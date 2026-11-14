// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The [`Channel`] on Tokio: the goroutines of Go's transport as one task
//! and a lock. The task runs the writer every frame interval (a ticker that
//! skips missed ticks, as Go's `time.Ticker` drops them) and the KCP timers;
//! the track reader hands frames in with [`Transport::handle_incoming_frame`];
//! the upper layer sends and reads through the async calls, which wait as
//! kcp-go's `Write` and `readLoop` do: a full send window holds a send, an
//! unread message holds the KCP receive window shut.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::channel::{Channel, Config, ConfirmError, DatagramError, DatagramSink, Inbound};
use crate::conn::SendError;
use crate::log::info;

/// The provider under the transport: the published track and the room's
/// state (`videoSession`). Calls are made under the transport's lock and
/// must not block.
pub trait Stream: Send + Sync + 'static {
    /// `track.WriteSample`: one sample, `true` when taken.
    fn write_sample(&self, sample: &[u8]) -> bool;
    /// `CanSend`: the publisher takes writes.
    fn can_send(&self) -> bool {
        true
    }
    /// `SubscriberCanSend`: control may go (before the publisher is up).
    fn subscriber_can_send(&self) -> bool {
        true
    }
    /// `Reconnect`: rebuild the provider (asked by the peer-restart
    /// watchdog); must return at once.
    fn reconnect(&self, _reason: &str) {}
}

/// What the transport tells its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The provider reconnected and the planes restarted on a new epoch:
    /// the session over them is gone (`SetReconnectCallback`).
    Reconnected,
}

/// [`Event`]s held for the owner.
pub const EVENT_QUEUE: usize = 16;

struct Inner {
    core: Mutex<Channel>,
    stream: Arc<dyn Stream>,
    frame_interval: Duration,
    /// The data plane may take a send, or a message is ready.
    data: Notify,
    /// The same for control.
    control: Notify,
    /// The task's schedule changed (a restart, a close).
    wake: Notify,
    events: mpsc::Sender<Event>,
}

/// The vp8channel transport, client side.
#[derive(Clone)]
pub struct Transport {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport").finish_non_exhaustive()
    }
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

impl Transport {
    /// `New` + `Connect` past the provider: both planes up and the writer
    /// running. The task ends at [`Transport::close`].
    #[must_use]
    pub fn start(
        cfg: &Config,
        stream: Arc<dyn Stream>,
        on_datagram: Option<DatagramSink>,
    ) -> (Self, mpsc::Receiver<Event>, JoinHandle<()>) {
        let t = now();
        let mut ch = Channel::new(cfg, t);
        ch.set_datagram_sink(on_datagram);
        Self::start_with(ch, cfg, stream)
    }

    /// [`Transport::start`] around a channel the caller built (tests).
    #[must_use]
    pub fn start_with(
        mut ch: Channel,
        cfg: &Config,
        stream: Arc<dyn Stream>,
    ) -> (Self, mpsc::Receiver<Event>, JoinHandle<()>) {
        ch.connect(now());
        let (events, rx) = mpsc::channel(EVENT_QUEUE);
        let interval_ns = u64::try_from(cfg.options.frame_interval())
            .unwrap_or(1)
            .max(1);
        let inner = Arc::new(Inner {
            core: Mutex::new(ch),
            stream,
            frame_interval: Duration::from_nanos(interval_ns),
            data: Notify::new(),
            control: Notify::new(),
            wake: Notify::new(),
            events,
        });
        let task = tokio::spawn(run(Arc::clone(&inner)));
        (Self { inner }, rx, task)
    }

    fn core(&self) -> MutexGuard<'_, Channel> {
        self.inner
            .core
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` on the channel under the lock (tests, stats).
    pub fn with_channel<R>(&self, f: impl FnOnce(&mut Channel) -> R) -> R {
        f(&mut self.core())
    }

    /// `handleIncomingFrame`: a frame the track reader assembled.
    pub fn handle_incoming_frame(&self, frame: &[u8]) -> Inbound {
        let (verdict, reconnect) = {
            let mut c = self.core();
            let v = c.handle_incoming_frame(frame, now());
            (v, c.take_reconnect())
        };
        if matches!(verdict, Inbound::Data) {
            self.inner.data.notify_waiters();
        }
        if matches!(verdict, Inbound::Control) {
            self.inner.control.notify_waiters();
        }
        if let Some(reason) = reconnect {
            self.inner.stream.reconnect(reason);
        }
        verdict
    }

    /// `Send` on the data plane: waits while the send window is full.
    ///
    /// # Errors
    /// [`SendError::Closed`] or [`SendError::TooLarge`].
    pub async fn send(&self, msg: &[u8]) -> Result<(), SendError> {
        self.wait_send(&self.inner.data, |c| c.send(msg, now()))
            .await
    }

    /// `ControlSend`.
    ///
    /// # Errors
    /// [`SendError::Closed`] or [`SendError::TooLarge`].
    pub async fn control_send(&self, msg: &[u8]) -> Result<(), SendError> {
        self.wait_send(&self.inner.control, |c| c.control_send(msg, now()))
            .await
    }

    async fn wait_send(
        &self,
        notify: &Notify,
        mut f: impl FnMut(&mut Channel) -> Result<(), SendError>,
    ) -> Result<(), SendError> {
        loop {
            let mut n = pin!(notify.notified());
            n.as_mut().enable();
            match f(&mut self.core()) {
                Err(SendError::WouldBlock) => {}
                other => return other,
            }
            n.await;
        }
    }

    /// The next data message (Go's `OnData`); `None` once closed.
    pub async fn recv_data(&self) -> Option<Vec<u8>> {
        self.wait_read(&self.inner.data, Channel::read_data).await
    }

    /// The next control message (`SetControlOnData`'s callback).
    pub async fn recv_control(&self) -> Option<Vec<u8>> {
        self.wait_read(&self.inner.control, Channel::read_control)
            .await
    }

    async fn wait_read(
        &self,
        notify: &Notify,
        f: fn(&mut Channel) -> Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        loop {
            let mut n = pin!(notify.notified());
            n.as_mut().enable();
            {
                let mut c = self.core();
                if let Some(m) = f(&mut c) {
                    return Some(m);
                }
                if c.is_closed() {
                    return None;
                }
            }
            n.await;
        }
    }

    /// `SendDatagram`.
    ///
    /// # Errors
    /// [`DatagramError`].
    pub fn send_datagram(&self, data: &[u8]) -> Result<(), DatagramError> {
        self.core().send_datagram(data)
    }

    /// `CanSend`.
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.core().can_send(self.inner.stream.can_send())
    }

    /// `ControlCanSend`.
    #[must_use]
    pub fn control_can_send(&self) -> bool {
        self.core()
            .control_can_send(self.inner.stream.subscriber_can_send())
    }

    /// `DatagramCanSend`.
    #[must_use]
    pub fn datagram_can_send(&self) -> bool {
        self.core().datagram_can_send(self.inner.stream.can_send())
    }

    /// `LocalPeerID`.
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        self.core().local_peer_id()
    }

    /// `ConfirmPeer`.
    ///
    /// # Errors
    /// [`ConfirmError`].
    pub fn confirm_peer(&self, peer_id: &str) -> Result<(), ConfirmError> {
        self.core().confirm_peer(peer_id, now())
    }

    /// `PeerSeen`.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        self.core().peer_seen()
    }

    /// `NotifyLinkHealth`.
    pub fn notify_link_health(&self, unhealthy: bool) {
        self.core().notify_link_health(unhealthy);
    }

    /// The relay asked for a keyframe.
    pub fn request_keyframe(&self) {
        self.core().request_keyframe();
    }

    /// `ResetPeer`: a fresh epoch and fresh KCP state on the same provider.
    pub fn reset_peer(&self) {
        self.core().restart_planes(now());
        self.wake_all();
    }

    /// The provider reconnected (its reconnect callback): the planes
    /// restart, then the owner hears [`Event::Reconnected`].
    pub fn provider_reconnected(&self) {
        self.core().restart_planes(now());
        self.wake_all();
        if self.inner.events.try_send(Event::Reconnected).is_err() {
            info!("vp8channel: reconnect event dropped: the owner is not reading");
        }
    }

    /// `Close`: both planes, the queues and the writer.
    pub fn close(&self) {
        self.core().close(now());
        self.wake_all();
    }

    fn wake_all(&self) {
        self.inner.data.notify_waiters();
        self.inner.control.notify_waiters();
        self.inner.wake.notify_one();
    }
}

/// The writer and the KCP timers.
async fn run(inner: Arc<Inner>) {
    let mut ticker = tokio::time::interval(inner.frame_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let next = {
            let mut c = inner.core.lock().unwrap_or_else(PoisonError::into_inner);
            if c.is_closed() {
                return;
            }
            c.update(now())
        };
        inner.data.notify_waiters();
        inner.control.notify_waiters();
        let sleep = sleep_until(next);
        tokio::select! {
            _ = ticker.tick() => {
                let stream = Arc::clone(&inner.stream);
                let mut c = inner.core.lock().unwrap_or_else(PoisonError::into_inner);
                c.tick(now(), &mut |s| stream.write_sample(s));
            }
            () = sleep => {}
            () = inner.wake.notified() => {}
        }
    }
}

fn sleep_until(at: Option<Instant>) -> impl Future<Output = ()> {
    let deadline = at.map(tokio::time::Instant::from_std);
    async move {
        match deadline {
            Some(d) => tokio::time::sleep_until(d).await,
            None => std::future::pending().await,
        }
    }
}

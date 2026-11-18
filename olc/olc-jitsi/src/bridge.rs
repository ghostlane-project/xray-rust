// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The bridge as the session uses it (`internal/engine/jitsi/bridge.go`,
//! `epoch.go`, `keepalive.go`'s `bridgeKeepalive`): the queue of frames to
//! send, the sender that waits for the bridge's backlog and the relay window
//! before it puts a frame on the wire, the receiver that tells a mark from
//! data, the announce and the keepalive.
//!
//! The wire itself (the data channel to the JVB, the hello, the messages
//! before the hello) is the caller's: [`Wire`]. The reconnect is the
//! caller's too: [`BridgeConfig::on_reconnect`] says a rejoin is wanted.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{mpsc, watch, Notify};
use tokio::time::Instant;

use crate::epoch::{random_epoch, Epochs, PeerIdError};
use crate::frame::{
    decode_raw, encode_frame, endpoint_message, legacy_endpoint_message, FrameError, Message,
    WindowFrame, WindowKind, MAGIC,
};
use crate::relaywin::{window_frame_bytes, Action, RelayWindow, Room, Timing};
use crate::xmpp::conn::BoxFut;

/// What the sender holds in its queue: frames, not bytes
/// (`defaultSendQueueSize`).
pub const SEND_QUEUE: usize = 32;
/// The backlog below the sender above which it waits
/// (`bridgeBacklogHighWater`): 256 KiB, a congestion window's worth and then
/// some, under the relay window it sits on top of.
pub const BACKLOG_HIGH_WATER: usize = 256 * 1024;
/// How often the backlog is looked at while the sender waits.
pub const BACKLOG_POLL: Duration = Duration::from_millis(5);
/// The sender does not wait through a reconnect for a session: old-epoch
/// frames are stale anyway (`jSessionWaitTimeout`).
pub const WIRE_WAIT: Duration = Duration::from_secs(2);
/// The keepalive frame's period (`bridgeKeepalive`).
pub const KEEPALIVE: Duration = Duration::from_secs(10);
/// The epoch announce: every 200 ms, 25 times, or until a peer is heard.
pub const ANNOUNCE_EVERY: Duration = Duration::from_millis(200);
/// How many announces.
pub const ANNOUNCES: u32 = 25;
/// How often a waiter for a peer looks (`WaitForPeer`).
pub const PEER_POLL: Duration = Duration::from_millis(50);

/// Why a frame was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// The session is closed (`ErrSessionClosed`).
    #[error("jitsi: session closed")]
    Closed,
    /// The bridge is not open (`ErrBridgeNotReady`).
    #[error("jitsi: bridge not ready")]
    NotReady,
    /// The frame would pass the bridge's message size.
    #[error("jitsi: send too large")]
    TooLarge,
}

/// Why the wire refused a message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct WireError(pub String);

/// What puts a message on the bridge.
pub trait Wire: Send + Sync + 'static {
    /// One JSON text message; waits for the transport's room.
    fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), WireError>>;
    /// The same, never waiting: a message that does not fit is dropped (the
    /// relay window's marks and echoes).
    fn try_send(&self, text: &str) -> Result<(), WireError>;
    /// Bytes queued below the sender.
    fn backlog(&self) -> usize;
}

/// What receives the peer's data.
pub type OnData = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// What receives the peer's data and may wait.
pub type OnDataAsync = Arc<dyn Fn(Vec<u8>) -> BoxFut<'static, ()> + Send + Sync>;

/// Asks for a rejoin with a reason; true when it was queued.
pub type OnReconnect = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Callbacks and settings of one bridge.
pub struct BridgeConfig {
    /// Data from the peer.
    pub on_data: OnData,
    /// Data from the peer, for a receiver that waits ([`Bridge::deliver_async`]).
    pub on_data_async: Option<OnDataAsync>,
    /// A rejoin is wanted, with the reason; true when it was queued, which
    /// closes the bridge to senders until the next one is open
    /// (`requestReconnect`).
    pub on_reconnect: OnReconnect,
    /// Only frames addressed to this session, from the confirmed peer
    /// (`RequireTargetedPeer`).
    pub require_targeted_peer: bool,
    /// The relay window's timers.
    pub timing: Timing,
}

struct Core {
    epochs: Epochs,
    win: RelayWindow,
    wire: Option<Arc<dyn Wire>>,
}

struct Sh {
    cfg: BridgeConfig,
    core: Mutex<Core>,
    wire_set: Notify,
    ready: AtomicBool,
    generation: AtomicU64,
    closed: watch::Sender<bool>,
    queue: mpsc::Sender<Vec<u8>>,
    relay_wake: Notify,
}

/// One session's bridge. Clones share it.
#[derive(Clone)]
pub struct Bridge {
    sh: Arc<Sh>,
}

fn lock(m: &Mutex<Core>) -> MutexGuard<'_, Core> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn wait_closed(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

impl Bridge {
    /// A bridge with a fresh local epoch; its loops run until [`Bridge::close`].
    #[must_use]
    pub fn new(cfg: BridgeConfig) -> Self {
        let (queue, queue_rx) = mpsc::channel(SEND_QUEUE);
        let (closed, _) = watch::channel(false);
        let core = Core {
            epochs: Epochs::new(random_epoch(), cfg.require_targeted_peer),
            win: RelayWindow::new(cfg.timing),
            wire: None,
        };
        let sh = Arc::new(Sh {
            cfg,
            core: Mutex::new(core),
            wire_set: Notify::new(),
            ready: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            closed,
            queue,
            relay_wake: Notify::new(),
        });
        tokio::spawn(send_loop(sh.clone(), queue_rx));
        tokio::spawn(keepalive_loop(sh.clone()));
        Self { sh }
    }

    /// Installs the wire a new bridge opened, or removes it with `None`.
    pub fn set_wire(&self, wire: Option<Arc<dyn Wire>>) {
        lock(&self.sh.core).wire = wire;
        self.sh.wire_set.notify_waiters();
    }

    /// The bridge is open: senders may queue, receive loops of an older
    /// generation are stale (`markBridgeReady`). The new generation.
    pub fn mark_ready(&self) -> u64 {
        let g = self.sh.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.sh.ready.store(true, Ordering::Release);
        g
    }

    /// Whether senders may queue.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.sh.ready.load(Ordering::Acquire)
    }

    /// Closes the bridge to senders (a rejoin is under way).
    pub fn set_not_ready(&self) {
        self.sh.ready.store(false, Ordering::Release);
    }

    /// The generation receive loops are bound to.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.sh.generation.load(Ordering::Acquire)
    }

    /// Whether the bridge is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.sh.closed.borrow()
    }

    /// Closes the bridge: every wait ends.
    pub fn close(&self) {
        self.sh.closed.send_replace(true);
        self.sh.ready.store(false, Ordering::Release);
        self.sh.relay_wake.notify_waiters();
        self.sh.wire_set.notify_waiters();
    }

    /// Queues `data` as a frame to the peer (`Send`); `None` is the epoch
    /// announce. Waits while the queue is full: back-pressure for the layer
    /// above, not a failure.
    ///
    /// # Errors
    /// [`BridgeError`].
    pub async fn send(&self, data: Option<&[u8]>) -> Result<(), BridgeError> {
        if self.is_closed() {
            return Err(BridgeError::Closed);
        }
        if !self.is_ready() {
            return Err(BridgeError::NotReady);
        }
        let frame = {
            let c = lock(&self.sh.core);
            encode_frame(data.unwrap_or(&[]), c.epochs.local(), c.epochs.peer_epoch())
                .map_err(|FrameError::SendTooLarge| BridgeError::TooLarge)?
        };
        let mut closed = self.sh.closed.subscribe();
        tokio::select! {
            r = self.sh.queue.send(frame) => r.map_err(|_| BridgeError::Closed),
            () = wait_closed(&mut closed) => Err(BridgeError::Closed),
        }
    }

    /// What a receive loop of generation `gen` makes of the bridge's next
    /// message; false when it should stop. `None` is the bridge closing: a
    /// rejoin is asked for unless the loop is of an older bridge
    /// (`deliverBridgeMessageGen`). The data goes to [`BridgeConfig::on_data`].
    pub fn deliver(&self, gen: u64, msg: Option<&Message>) -> bool {
        let (go_on, data) = self.process(gen, msg);
        if let Some(d) = data {
            (self.sh.cfg.on_data)(&d);
        }
        go_on
    }

    /// [`Bridge::deliver`] for a receiver that may wait: the data goes to
    /// [`BridgeConfig::on_data_async`] when there is one, and the receive
    /// loop reads no further message until it returns (the inbound
    /// back-pressure of Go's blocking `OnData`).
    pub async fn deliver_async(&self, gen: u64, msg: Option<&Message>) -> bool {
        let (go_on, data) = self.process(gen, msg);
        if let Some(d) = data {
            match &self.sh.cfg.on_data_async {
                Some(f) => f(d).await,
                None => (self.sh.cfg.on_data)(&d),
            }
        }
        go_on
    }

    /// The decision of [`Bridge::deliver`] and the data it has to hand over.
    fn process(&self, gen: u64, msg: Option<&Message>) -> (bool, Option<Vec<u8>>) {
        let Some(m) = msg else {
            if !self.is_closed() {
                self.request_reconnect(gen, "jitsi bridge closed");
            }
            return (false, None);
        };
        let raw = decode_raw(m);
        if let Some(raw) = raw.as_deref() {
            if let Some(f) = WindowFrame::parse(raw) {
                self.window_frame(&m.from, &f);
                return (true, None);
            }
        }
        let Some(raw) = raw else { return (true, None) };
        let (body, reset) = {
            let mut c = lock(&self.sh.core);
            let got = c.epochs.receive(&m.from, &raw, Instant::now().into_std());
            if got.reset_windows {
                c.win.reset();
            }
            (got.body, got.reset_windows)
        };
        if reset {
            self.sh.relay_wake.notify_waiters();
        }
        (true, body.filter(|b| !b.is_empty()))
    }

    /// Asks for a rejoin whatever generation is live (`requestReconnect`): a
    /// queued one closes the bridge to senders.
    pub fn ask_reconnect(&self, reason: &str) {
        if !self.is_closed() && (self.sh.cfg.on_reconnect)(reason) {
            self.set_not_ready();
        }
    }

    fn request_reconnect(&self, gen: u64, reason: &str) {
        if self.sh.generation.load(Ordering::Acquire) != gen || self.is_closed() {
            return;
        }
        if (self.sh.cfg.on_reconnect)(reason) {
            self.set_not_ready();
        }
    }

    fn window_frame(&self, from: &str, f: &WindowFrame) {
        let (action, wire, local) = {
            let mut c = lock(&self.sh.core);
            let Core { epochs, win, wire } = &mut *c;
            let action = win.on_frame(from, f, epochs);
            (action, wire.clone(), epochs.local())
        };
        match action {
            Action::SendEcho {
                receiver_epoch,
                counter,
            } => {
                if let (Some(w), Some(b)) = (
                    wire,
                    window_frame_bytes(WindowKind::Echo, local, receiver_epoch, counter),
                ) {
                    let _ = w.try_send(&endpoint_message(from, &b));
                }
            }
            Action::Echoed { moved: true, .. } => self.sh.relay_wake.notify_waiters(),
            _ => {}
        }
    }

    /// The local epoch as the peer id the layers above exchange.
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        lock(&self.sh.core).epochs.local_peer_id()
    }

    /// Binds the session to an authenticated peer (`ConfirmPeer`).
    ///
    /// # Errors
    /// [`PeerIdError`].
    pub fn confirm_peer(&self, id: &str) -> Result<(), PeerIdError> {
        let mut c = lock(&self.sh.core);
        if c.epochs.confirm_peer(id)? {
            c.win.reset();
            drop(c);
            self.sh.relay_wake.notify_waiters();
        }
        Ok(())
    }

    /// Forgets the peer and the latch (`ResetPeer`).
    pub fn reset_peer(&self) {
        let mut c = lock(&self.sh.core);
        c.epochs.reset_peer();
        c.win.reset();
        drop(c);
        self.sh.relay_wake.notify_waiters();
    }

    /// A peer epoch is latched, or `occupants` others are in the room.
    #[must_use]
    pub fn peer_seen(&self, occupants: usize) -> bool {
        lock(&self.sh.core).epochs.peer_seen(occupants)
    }

    /// The peer's epoch, 0 before there is one.
    #[must_use]
    pub fn peer_epoch(&self) -> u32 {
        lock(&self.sh.core).epochs.peer_epoch()
    }

    /// The local epoch.
    #[must_use]
    pub fn local_epoch(&self) -> u32 {
        lock(&self.sh.core).epochs.local()
    }

    /// Waits until a peer epoch is confirmed or latched (`WaitForPeer`).
    pub async fn wait_for_peer(&self) -> bool {
        let mut closed = self.sh.closed.subscribe();
        loop {
            if self.peer_epoch() != 0 {
                return true;
            }
            tokio::select! {
                () = wait_closed(&mut closed) => return false,
                () = tokio::time::sleep(PEER_POLL) => {}
            }
        }
    }

    /// What a reconnect does to the session before it rejoins: a new local
    /// epoch, no peer, no windows. Frames made before are of the old epoch
    /// and the sender drops them as it reaches them (`reconnect`).
    pub fn reset_for_reconnect(&self) {
        self.set_not_ready();
        {
            let mut c = lock(&self.sh.core);
            c.epochs.set_local(random_epoch());
            c.epochs.reset_peer();
            c.win.reset();
            c.wire = None;
        }
        self.sh.relay_wake.notify_waiters();
    }

    /// Notes that a reconnect finished now (the grace period).
    pub fn note_reconnect(&self) {
        lock(&self.sh.core)
            .epochs
            .note_reconnect(Instant::now().into_std());
    }

    /// Announces the local epoch: every [`ANNOUNCE_EVERY`], [`ANNOUNCES`]
    /// times, until a peer is heard (`announceEpoch`).
    pub fn start_announce(&self) {
        let b = self.clone();
        tokio::spawn(async move {
            let mut closed = b.sh.closed.subscribe();
            for _ in 0..ANNOUNCES {
                if b.is_closed() || b.peer_epoch() != 0 {
                    return;
                }
                if let Err(e) = b.send(None).await {
                    olc_net::debug!("jitsi: epoch announce failed: {e}");
                }
                tokio::select! {
                    () = wait_closed(&mut closed) => return,
                    () = tokio::time::sleep(ANNOUNCE_EVERY) => {}
                }
            }
        });
    }
}

impl Sh {
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    fn wire(&self) -> Option<Arc<dyn Wire>> {
        lock(&self.core).wire.clone()
    }

    async fn wait_wire(&self) -> Option<Arc<dyn Wire>> {
        let deadline = Instant::now() + WIRE_WAIT;
        let mut closed = self.closed.subscribe();
        loop {
            let set = self.wire_set.notified();
            if let Some(w) = self.wire() {
                return Some(w);
            }
            tokio::select! {
                () = set => {}
                () = wait_closed(&mut closed) => return None,
                () = tokio::time::sleep_until(deadline) => return None,
            }
        }
    }

    /// The frame is still of the session's current epoch (`outboundFrameCurrent`).
    fn current(&self, frame: &[u8]) -> bool {
        let off = MAGIC.len();
        if frame.len() < off + 8 {
            return false;
        }
        let epoch =
            u32::from_be_bytes([frame[off], frame[off + 1], frame[off + 2], frame[off + 3]]);
        epoch == lock(&self.core).epochs.local()
    }

    async fn wait_bridge_room(&self, wire: &Arc<dyn Wire>) -> bool {
        let mut closed = self.closed.subscribe();
        loop {
            if wire.backlog() <= BACKLOG_HIGH_WATER {
                return true;
            }
            tokio::select! {
                () = wait_closed(&mut closed) => return false,
                () = tokio::time::sleep(BACKLOG_POLL) => {}
            }
        }
    }

    /// Whether a frame may go on now; a probe the window asks for is sent.
    fn relay_ready(&self, wire: &Arc<dyn Wire>) -> bool {
        let (room, local, peer) = {
            let mut c = lock(&self.core);
            let room = c.win.room(Instant::now().into_std());
            (room, c.epochs.local(), c.epochs.peer_epoch())
        };
        match room {
            Room::Open => true,
            Room::Held => false,
            Room::Probe(counter) => {
                if let Some(b) = window_frame_bytes(WindowKind::Mark, local, peer, counter) {
                    let to = lock(&self.core)
                        .epochs
                        .send_target(Instant::now().into_std())
                        .to_owned();
                    let _ = wire.try_send(&endpoint_message(&to, &b));
                }
                false
            }
        }
    }

    async fn wait_relay_room(&self, wire: &Arc<dyn Wire>, frame: &[u8]) -> bool {
        let retry = lock(&self.core).win.timing().retry;
        let mut closed = self.closed.subscribe();
        while !self.relay_ready(wire) {
            let woken = self.relay_wake.notified();
            tokio::select! {
                () = wait_closed(&mut closed) => return false,
                () = woken => {}
                () = tokio::time::sleep(retry) => {}
            }
            if !self.current(frame) {
                return false;
            }
        }
        true
    }

    async fn send_frame(&self, frame: Vec<u8>) {
        let to = lock(&self.core)
            .epochs
            .send_target(Instant::now().into_std())
            .to_owned();
        if !self.current(&frame) {
            return;
        }
        let Some(wire) = self.wait_wire().await else {
            return;
        };
        if !self.wait_bridge_room(&wire).await
            || !self.wait_relay_room(&wire, &frame).await
            || !self.current(&frame)
        {
            return;
        }
        if let Err(e) = wire.send(&endpoint_message(&to, &frame)).await {
            if !self.is_closed() {
                olc_net::debug!("jitsi bridge send: {e}");
            }
            return;
        }
        let (mark, local, peer) = {
            let mut c = lock(&self.core);
            let mark = c.win.sent(frame.len(), Instant::now().into_std());
            (mark, c.epochs.local(), c.epochs.peer_epoch())
        };
        if let Some(counter) = mark {
            if let Some(b) = window_frame_bytes(WindowKind::Mark, local, peer, counter) {
                let _ = wire.try_send(&endpoint_message(&to, &b));
            }
        }
    }
}

async fn send_loop(sh: Arc<Sh>, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut closed = sh.closed.subscribe();
    loop {
        let frame = tokio::select! {
            () = wait_closed(&mut closed) => return,
            f = rx.recv() => match f {
                Some(f) => f,
                None => return,
            },
        };
        sh.send_frame(frame).await;
    }
}

/// `bridgeKeepalive`: an empty frame every 10 s in the library's own shape.
async fn keepalive_loop(sh: Arc<Sh>) {
    let mut closed = sh.closed.subscribe();
    loop {
        tokio::select! {
            () = wait_closed(&mut closed) => return,
            () = tokio::time::sleep(KEEPALIVE) => {}
        }
        if !sh.ready.load(Ordering::Acquire) {
            continue;
        }
        let Some(wire) = sh.wire() else { continue };
        let frame = {
            let c = lock(&sh.core);
            encode_frame(&[], c.epochs.local(), c.epochs.peer_epoch())
        };
        let Ok(frame) = frame else { continue };
        if let Err(e) = wire.send(&legacy_endpoint_message("", &frame)).await {
            olc_net::debug!("jitsi: bridge keepalive send: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[derive(Default)]
    struct FakeWire {
        sent: Mutex<Vec<String>>,
        try_sent: Mutex<Vec<String>>,
        backlog: AtomicUsize,
    }

    impl FakeWire {
        fn texts(&self) -> Vec<String> {
            self.sent.lock().unwrap().clone()
        }
        fn marks(&self) -> Vec<WindowFrame> {
            let m = |t: &String| {
                let msg = Message::parse(t)?;
                WindowFrame::parse(&decode_raw(&msg)?)
            };
            self.try_sent.lock().unwrap().iter().filter_map(m).collect()
        }
    }

    impl Wire for FakeWire {
        fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), WireError>> {
            Box::pin(async move {
                self.sent.lock().unwrap().push(text.to_owned());
                Ok(())
            })
        }
        fn try_send(&self, text: &str) -> Result<(), WireError> {
            self.try_sent.lock().unwrap().push(text.to_owned());
            Ok(())
        }
        fn backlog(&self) -> usize {
            self.backlog.load(Ordering::Relaxed)
        }
    }

    struct Rig {
        bridge: Bridge,
        wire: Arc<FakeWire>,
        data: Arc<Mutex<Vec<Vec<u8>>>>,
        reconnects: Arc<Mutex<Vec<String>>>,
    }

    fn rig(targeted: bool) -> Rig {
        let data = Arc::new(Mutex::new(Vec::new()));
        let reconnects = Arc::new(Mutex::new(Vec::new()));
        let (d, r) = (data.clone(), reconnects.clone());
        let bridge = Bridge::new(BridgeConfig {
            on_data: Arc::new(move |b| d.lock().unwrap().push(b.to_vec())),
            on_data_async: None,
            on_reconnect: Arc::new(move |why| {
                r.lock().unwrap().push(why.to_owned());
                true
            }),
            require_targeted_peer: targeted,
            timing: Timing::default(),
        });
        let wire = Arc::new(FakeWire::default());
        bridge.set_wire(Some(wire.clone()));
        Rig {
            bridge,
            wire,
            data,
            reconnects,
        }
    }

    async fn settle() {
        for _ in 0..30 {
            tokio::task::yield_now().await;
        }
    }

    fn from_peer(epoch: u32, to: u32, data: &[u8], from: &str) -> Message {
        let f = encode_frame(data, epoch, to).unwrap();
        let json = endpoint_message("", &f)
            .replace("\"to\":\"\"", &format!("\"to\":\"\",\"from\":\"{from}\""));
        Message::parse(&json).unwrap()
    }

    fn window_from(f: &WindowFrame, from: &str) -> Message {
        let json = endpoint_message("", &f.encode())
            .replace("\"to\":\"\"", &format!("\"to\":\"\",\"from\":\"{from}\""));
        Message::parse(&json).unwrap()
    }

    /// `TestSendBeforeConnect`, `TestSendAfterClose` (`jitsi_test.go:214,229`).
    #[tokio::test(start_paused = true)]
    async fn a_send_needs_an_open_bridge() {
        let r = rig(false);
        assert_eq!(r.bridge.send(Some(b"x")).await, Err(BridgeError::NotReady));
        r.bridge.mark_ready();
        assert_eq!(r.bridge.send(Some(b"x")).await, Ok(()));
        r.bridge.close();
        assert_eq!(r.bridge.send(Some(b"x")).await, Err(BridgeError::Closed));
        let big = vec![0u8; 16 * 1024];
        let r = rig(false);
        r.bridge.mark_ready();
        assert_eq!(r.bridge.send(Some(&big)).await, Err(BridgeError::TooLarge));
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_goes_to_the_room_or_to_the_latched_endpoint() {
        let r = rig(false);
        r.bridge.mark_ready();
        r.bridge.send(Some(b"first")).await.unwrap();
        settle().await;
        let local = r.bridge.local_epoch();
        let want = |to: &str, peer: u32| {
            endpoint_message(to, &encode_frame(b"first", local, peer).unwrap())
        };
        assert_eq!(r.wire.texts(), [want("", 0)]);
        // The peer speaks; its endpoint is latched and uploads go to it.
        let gen = r.bridge.generation();
        assert!(r
            .bridge
            .deliver(gen, Some(&from_peer(0x1111, 0, b"hello", "ep-b"))));
        assert_eq!(r.data.lock().unwrap().as_slice(), [b"hello".to_vec()]);
        r.bridge.send(Some(b"second")).await.unwrap();
        settle().await;
        let second = endpoint_message("ep-b", &encode_frame(b"second", local, 0x1111).unwrap());
        assert_eq!(r.wire.texts().last(), Some(&second));
    }

    /// `TestSendWaitsForRoomInsteadOfFailingWhenTheQueueIsFull`,
    /// `TestAWaitingSendReturnsWhenTheSessionCloses` (`sendqueue_test.go:32,52`).
    #[tokio::test(start_paused = true)]
    async fn a_full_queue_makes_the_sender_wait_and_a_close_frees_it() {
        let r = rig(false);
        r.bridge.mark_ready();
        // The wire is behind: the loop holds one frame and the queue 32.
        r.wire
            .backlog
            .store(BACKLOG_HIGH_WATER + 1, Ordering::Relaxed);
        for i in 0..=SEND_QUEUE {
            r.bridge.send(Some(&[i as u8])).await.unwrap();
        }
        settle().await;
        let b2 = r.bridge.clone();
        let waiting = tokio::spawn(async move { b2.send(Some(b"one more")).await });
        settle().await;
        assert!(!waiting.is_finished(), "the send must wait, not fail");
        assert!(r.wire.texts().is_empty());
        // The wire drains: the loop goes on and the waiting send completes.
        r.wire.backlog.store(0, Ordering::Relaxed);
        tokio::time::advance(S(1)).await;
        settle().await;
        assert_eq!(waiting.await.unwrap(), Ok(()));
        assert_eq!(r.wire.texts().len(), SEND_QUEUE + 2);
        // And a send waiting when the bridge closes returns.
        let r = rig(false);
        r.bridge.mark_ready();
        r.wire
            .backlog
            .store(BACKLOG_HIGH_WATER + 1, Ordering::Relaxed);
        for i in 0..=SEND_QUEUE {
            r.bridge.send(Some(&[i as u8])).await.unwrap();
        }
        settle().await;
        let b2 = r.bridge.clone();
        let waiting = tokio::spawn(async move { b2.send(Some(b"x")).await });
        settle().await;
        r.bridge.close();
        assert_eq!(waiting.await.unwrap(), Err(BridgeError::Closed));
    }

    /// The backlog gate (`backlog_test.go`): nothing goes above the mark.
    #[tokio::test(start_paused = true)]
    async fn the_sender_waits_behind_the_backlog() {
        let r = rig(false);
        r.bridge.mark_ready();
        r.wire
            .backlog
            .store(BACKLOG_HIGH_WATER + 1, Ordering::Relaxed);
        r.bridge.send(Some(b"x")).await.unwrap();
        tokio::time::advance(S(5)).await;
        settle().await;
        assert!(
            r.wire.texts().is_empty(),
            "sent behind a backlog over the mark"
        );
        r.wire.backlog.store(BACKLOG_HIGH_WATER, Ordering::Relaxed);
        tokio::time::advance(BACKLOG_POLL * 2).await;
        settle().await;
        assert_eq!(r.wire.texts().len(), 1, "at the mark it goes");
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_of_an_old_epoch_is_dropped() {
        let r = rig(false);
        r.bridge.mark_ready();
        r.wire
            .backlog
            .store(BACKLOG_HIGH_WATER + 1, Ordering::Relaxed);
        r.bridge.send(Some(b"old")).await.unwrap();
        settle().await;
        // A reconnect: a new epoch, nothing queued, and the held frame stale.
        r.bridge.reset_for_reconnect();
        r.bridge.set_wire(Some(r.wire.clone()));
        r.bridge.mark_ready();
        r.wire.backlog.store(0, Ordering::Relaxed);
        tokio::time::advance(S(1)).await;
        settle().await;
        assert!(r.wire.texts().is_empty(), "{:?}", r.wire.texts());
        r.bridge.send(Some(b"new")).await.unwrap();
        settle().await;
        assert_eq!(r.wire.texts().len(), 1);
    }

    /// `TestStaleRecvLoopDoesNotClearFreshBridge`,
    /// `TestLiveRecvLoopStillRequestsReconnect` (`regression_test.go:22,51`).
    #[tokio::test(start_paused = true)]
    async fn only_the_live_receive_loop_asks_for_a_rejoin() {
        let r = rig(false);
        let old = r.bridge.mark_ready();
        let fresh = r.bridge.mark_ready();
        assert!(!r.bridge.deliver(old, None));
        assert!(r.reconnects.lock().unwrap().is_empty());
        assert!(
            r.bridge.is_ready(),
            "a stale loop leaves the fresh bridge open"
        );
        assert!(!r.bridge.deliver(fresh, None));
        assert_eq!(
            r.reconnects.lock().unwrap().as_slice(),
            ["jitsi bridge closed"]
        );
        assert!(
            !r.bridge.is_ready(),
            "a queued rejoin closes the bridge to senders"
        );
        // Closed for good: no request.
        r.bridge.close();
        let g = r.bridge.generation();
        r.bridge.deliver(g, None);
        assert_eq!(r.reconnects.lock().unwrap().len(), 1);
    }

    /// Window frames never reach the data callback; a mark is echoed to its
    /// sender, an echo turns the window on.
    #[tokio::test(start_paused = true)]
    async fn marks_are_echoed_and_never_delivered_as_data() {
        let r = rig(true);
        r.bridge.mark_ready();
        r.bridge.confirm_peer("0000b0b0").unwrap();
        let local = r.bridge.local_epoch();
        let gen = r.bridge.generation();
        // A data frame latches the endpoint.
        r.bridge
            .deliver(gen, Some(&from_peer(0xb0b0, local, b"hi", "ep-b")));
        let mark = WindowFrame {
            kind: WindowKind::Mark,
            sender_epoch: 0xb0b0,
            receiver_epoch: local,
            counter: 4242,
        };
        assert!(r.bridge.deliver(gen, Some(&window_from(&mark, "ep-b"))));
        assert_eq!(
            r.data.lock().unwrap().len(),
            1,
            "only the data frame was delivered"
        );
        let echoes = r.wire.marks();
        assert_eq!(echoes.len(), 1);
        assert_eq!(
            (
                echoes[0].kind,
                echoes[0].sender_epoch,
                echoes[0].receiver_epoch,
                echoes[0].counter
            ),
            (WindowKind::Echo, local, 0xb0b0, 4242)
        );
        // The echo goes to the endpoint the mark came from.
        let sent = r.wire.try_sent.lock().unwrap()[0].clone();
        assert!(sent.contains("\"to\":\"ep-b\""), "{sent}");
    }

    /// The window holds a sender once the peer has echoed; a probe goes after
    /// a second; an echo lets it go on (`TestAnEchoWakesAHeldSender`).
    #[tokio::test(start_paused = true)]
    async fn the_relay_window_holds_the_sender_and_an_echo_wakes_it() {
        let r = rig(true);
        r.bridge.mark_ready();
        r.bridge.confirm_peer("0000b0b0").unwrap();
        let local = r.bridge.local_epoch();
        let gen = r.bridge.generation();
        r.bridge
            .deliver(gen, Some(&from_peer(0xb0b0, local, b"hi", "ep-b")));
        let chunk = vec![7u8; 8000];
        // The first frame is marked; its echo turns the window on.
        r.bridge.send(Some(&chunk)).await.unwrap();
        settle().await;
        let first = r
            .wire
            .marks()
            .iter()
            .find(|m| m.kind == WindowKind::Mark)
            .copied()
            .expect("a mark");
        let echo = |counter| WindowFrame {
            kind: WindowKind::Echo,
            sender_epoch: 0xb0b0,
            receiver_epoch: local,
            counter,
        };
        r.bridge
            .deliver(gen, Some(&window_from(&echo(first.counter), "ep-b")));
        // Now send past the window: it holds.
        let n = crate::relaywin::WINDOW / 8012 + 8;
        for _ in 0..n {
            r.bridge.send(Some(&chunk)).await.unwrap();
        }
        settle().await;
        let held_at = r.wire.texts().len();
        assert!(held_at < n, "the window did not hold: {held_at} of {n}");
        // A second later a probe goes (a mark with the count so far).
        let before = r.wire.marks().len();
        tokio::time::advance(S(2)).await;
        settle().await;
        assert!(r.wire.marks().len() > before, "no probe");
        let probe = r.wire.marks().last().copied().unwrap();
        assert_eq!(probe.kind, WindowKind::Mark);
        // Its echo frees the sender: the rest goes.
        r.bridge
            .deliver(gen, Some(&window_from(&echo(probe.counter), "ep-b")));
        settle().await;
        assert_eq!(
            r.wire.texts().len(),
            n + 1,
            "the held frames did not go after the echo"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_keepalive_is_an_empty_frame_in_the_legacy_shape_every_ten_seconds() {
        let r = rig(false);
        r.bridge.mark_ready();
        // The loop starts its first wait before time moves.
        settle().await;
        tokio::time::advance(KEEPALIVE).await;
        settle().await;
        let local = r.bridge.local_epoch();
        let want = legacy_endpoint_message("", &encode_frame(&[], local, 0).unwrap());
        assert_eq!(r.wire.texts(), std::slice::from_ref(&want));
        tokio::time::advance(KEEPALIVE).await;
        settle().await;
        assert_eq!(r.wire.texts(), [want.clone(), want]);
        // Not while the bridge is not open.
        r.bridge.set_not_ready();
        tokio::time::advance(KEEPALIVE).await;
        settle().await;
        assert_eq!(r.wire.texts().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_epoch_is_announced_until_a_peer_answers() {
        let r = rig(false);
        r.bridge.mark_ready();
        r.bridge.start_announce();
        settle().await;
        for _ in 0..3 {
            tokio::time::advance(ANNOUNCE_EVERY).await;
            settle().await;
        }
        assert_eq!(r.wire.texts().len(), 4);
        let gen = r.bridge.generation();
        r.bridge
            .deliver(gen, Some(&from_peer(0x1111, 0, b"", "ep-b")));
        for _ in 0..5 {
            tokio::time::advance(ANNOUNCE_EVERY).await;
            settle().await;
        }
        assert_eq!(
            r.wire.texts().len(),
            4,
            "announces stop once a peer is known"
        );
        // Without a peer: 25 and no more.
        let r = rig(false);
        r.bridge.mark_ready();
        r.bridge.start_announce();
        for _ in 0..40 {
            tokio::time::advance(ANNOUNCE_EVERY).await;
            settle().await;
        }
        assert_eq!(r.wire.texts().len(), ANNOUNCES as usize);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_peer_and_peer_ids() {
        let r = rig(false);
        assert_eq!(r.bridge.local_peer_id().len(), 8);
        assert!(!r.bridge.peer_seen(0) && r.bridge.peer_seen(1));
        let b = r.bridge.clone();
        let t = tokio::spawn(async move { b.wait_for_peer().await });
        tokio::time::advance(S(1)).await;
        settle().await;
        assert!(!t.is_finished());
        r.bridge.confirm_peer("00000009").unwrap();
        tokio::time::advance(PEER_POLL * 2).await;
        assert!(t.await.unwrap());
        assert_eq!(r.bridge.confirm_peer("0"), Err(PeerIdError::Invalid));
        r.bridge.reset_peer();
        assert_eq!(r.bridge.peer_epoch(), 0);
        let b = r.bridge.clone();
        let t = tokio::spawn(async move { b.wait_for_peer().await });
        settle().await;
        r.bridge.close();
        assert!(!t.await.unwrap());
    }
}

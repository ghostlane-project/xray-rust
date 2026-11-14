// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The vp8channel transport over an engine that carries video
//! (`vp8channel.New` over `common.NewEngineVideoSession`): the payloads ride
//! the engine's video track as VP8 frames ([`olc_vp8channel`]), in two KCP
//! planes, data and control, plus datagrams.
//!
//! The client sees the link's one surface plus the control plane Go's
//! `transport.ControlPlane` adds: a vp8channel client runs its data smux
//! session on the data plane and its control session (the hello, the
//! pings) on the control plane, each record its own KCP message (the
//! transport batches nothing: `Features` names no write interval).
//!
//! The engine under it is interop-p2p ([`crate::p2p`]), the one with a
//! video track the port has.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_net::link::{DataSink, DatagramSink, LinkEvent};
use olc_vp8channel::channel::{Carrier, Config as ChannelConfig, Options, DEFAULT_BATCH_SIZE};
use olc_vp8channel::transport::{Event, Stream, Transport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::p2p::{P2pEvent, P2pLink};

/// The FPS when the config names none: the app's (60, `appVP8FPS`), which
/// the gate gives both ends.
pub const DEFAULT_FPS: u32 = 60;

/// The largest message the transport takes (`defaultMaxPayloadSize`):
/// what smux's frames are clamped to.
pub const MAX_PAYLOAD_SIZE: usize = olc_vp8channel::wire::MAX_PAYLOAD_SIZE;

/// How often a wait for a plane that cannot send looks again (Go's
/// `WaitForPeer` polls every 50 ms; the planes' readiness has no event).
const READY_POLL: Duration = Duration::from_millis(10);

/// `WaitForPeer`'s poll interval.
const PEER_POLL: Duration = Duration::from_millis(50);

/// The engine as the transport's provider.
struct EngineStream(Arc<P2pLink>);

impl Stream for EngineStream {
    fn write_sample(&self, sample: &[u8]) -> bool {
        self.0.write_sample(sample)
    }

    fn can_send(&self) -> bool {
        self.0.can_send()
    }

    fn subscriber_can_send(&self) -> bool {
        self.0.can_send()
    }

    fn reconnect(&self, reason: &str) {
        self.0.reconnect(reason);
    }
}

#[derive(Default)]
struct Sinks {
    data: Option<Arc<dyn DataSink>>,
    control: Option<Arc<dyn DataSink>>,
    datagram: Option<DatagramSink>,
}

/// One vp8channel link.
pub struct Vp8Link {
    transport: Transport,
    engine: Arc<P2pLink>,
    sinks: Arc<Mutex<Sinks>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Vp8Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vp8Link")
            .field("engine", &self.engine)
            .finish_non_exhaustive()
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The channel's settings from the client's: the room's channel (or its
/// URL) for the binding token, the FPS and batch (the app's when unset),
/// the phone's buffer profile.
#[must_use]
pub fn channel_config(cfg: &Config) -> ChannelConfig {
    let fps = if cfg.vp8_fps == 0 {
        DEFAULT_FPS
    } else {
        cfg.vp8_fps
    };
    let batch = if cfg.vp8_batch == 0 {
        DEFAULT_BATCH_SIZE
    } else {
        cfg.vp8_batch
    };
    ChannelConfig {
        channel_id: cfg.channel.clone(),
        room_url: cfg.url.clone(),
        options: Options::with_defaults(fps, batch),
        constrained: true,
        carrier: Carrier::Vp8,
    }
}

impl Vp8Link {
    /// Joins the engine's room and starts the transport over it.
    ///
    /// # Errors
    /// The engine's.
    pub async fn connect(
        cfg: &Config,
        host_ip: std::net::IpAddr,
        events: mpsc::Sender<LinkEvent>,
    ) -> Result<Arc<Self>, crate::p2p::P2pError> {
        let ccfg = channel_config(cfg);
        let interval_ns = u64::try_from(ccfg.options.frame_interval())
            .unwrap_or(1)
            .max(1);
        let (p2p_tx, mut p2p_rx) = mpsc::channel(16);
        let engine =
            P2pLink::connect(&cfg.url, host_ip, Duration::from_nanos(interval_ns), p2p_tx).await?;
        let sinks = Arc::new(Mutex::new(Sinks::default()));
        let dsinks = sinks.clone();
        let on_datagram: olc_vp8channel::channel::DatagramSink = Box::new(move |d: &[u8]| {
            let sink = locked(&dsinks).datagram.clone();
            if let Some(sink) = sink {
                let mut owned = d.to_vec();
                sink(&mut owned);
            }
        });
        let (transport, mut t_rx, task) = Transport::start(
            &ccfg,
            Arc::new(EngineStream(engine.clone())),
            Some(on_datagram),
        );
        {
            let t = transport.clone();
            engine.set_frame_handler(Some(Arc::new(move |frame: &[u8]| {
                let _ = t.handle_incoming_frame(frame);
            })));
        }
        let link = Arc::new(Self {
            transport: transport.clone(),
            engine: engine.clone(),
            sinks: sinks.clone(),
            tasks: Mutex::new(vec![task]),
        });
        let mut tasks = Vec::new();
        // The engine's news: a rejoin restarts the planes on a new epoch.
        {
            let t = transport.clone();
            let ev = events.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(e) = p2p_rx.recv().await {
                    match e {
                        P2pEvent::Reconnected => t.provider_reconnected(),
                        P2pEvent::Ended(why) => {
                            let _ = ev.send(LinkEvent::Ended(why)).await;
                        }
                    }
                }
            }));
        }
        // The transport's: its planes restarted, so the sessions over them
        // are gone (`SetReconnectCallback`).
        tasks.push(tokio::spawn(async move {
            while let Some(e) = t_rx.recv().await {
                match e {
                    Event::Reconnected => {
                        let _ = events.send(LinkEvent::Reconnected).await;
                    }
                }
            }
        }));
        // The planes' messages to the lanes above.
        for control in [false, true] {
            let t = transport.clone();
            let s = sinks.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let msg = if control {
                        t.recv_control().await
                    } else {
                        t.recv_data().await
                    };
                    let Some(mut msg) = msg else { return };
                    let sink = {
                        let s = locked(&s);
                        if control {
                            s.control.clone()
                        } else {
                            s.data.clone()
                        }
                    };
                    if let Some(sink) = sink {
                        sink.push(&mut msg).await;
                    }
                }
            }));
        }
        locked(&link.tasks).extend(tasks);
        Ok(link)
    }

    /// Where data-plane records go.
    pub fn set_data(&self, sink: Option<Arc<dyn DataSink>>) {
        locked(&self.sinks).data = sink;
    }

    /// Where control-plane records go (`SetControlOnData`).
    pub fn set_control(&self, sink: Option<Arc<dyn DataSink>>) {
        locked(&self.sinks).control = sink;
    }

    /// Where datagrams go.
    pub fn set_datagram(&self, sink: Option<DatagramSink>) {
        locked(&self.sinks).datagram = sink;
    }

    /// `PeerSeen`: frames from a peer of the room arrived.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        self.transport.peer_seen()
    }

    /// `CanSend`: the data plane takes a message.
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.transport.can_send()
    }

    /// `ControlCanSend`.
    #[must_use]
    pub fn control_can_send(&self) -> bool {
        self.transport.control_can_send()
    }

    /// Waits up to `limit` for the data plane (or the control plane).
    pub async fn wait_ready(&self, limit: Duration, control: bool) -> bool {
        let ready = || {
            if control {
                self.control_can_send()
            } else {
                self.can_send()
            }
        };
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if ready() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(READY_POLL).await;
        }
    }

    /// `Send` on the data plane: waits while the KCP window is full.
    ///
    /// # Errors
    /// A closed transport.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.transport
            .send(payload)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e:?}")))
    }

    /// `ControlSend`.
    ///
    /// # Errors
    /// A closed transport.
    pub async fn control_send(&self, payload: &[u8]) -> io::Result<()> {
        self.transport
            .control_send(payload)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e:?}")))
    }

    /// `SendDatagram`.
    ///
    /// # Errors
    /// Too large, or no peer yet.
    pub fn send_datagram(&self, payload: &[u8]) -> io::Result<()> {
        self.transport
            .send_datagram(payload)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// `ConfirmPeer`.
    ///
    /// # Errors
    /// The id does not parse.
    pub fn confirm_peer(&self, peer_id: &str) -> io::Result<()> {
        self.transport
            .confirm_peer(peer_id)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// `ResetPeer`.
    pub fn reset_peer(&self) {
        self.transport.reset_peer();
    }

    /// `WaitForPeer`: until the handshake's peer is confirmed.
    ///
    /// # Errors
    /// Not within `limit`.
    pub async fn wait_for_peer(&self, limit: Duration) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if self.transport.with_channel(|c| c.peer_confirmed()) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "context deadline exceeded",
                ));
            }
            tokio::time::sleep(PEER_POLL).await;
        }
    }

    /// `Reconnect`: the engine joins again; the planes restart after.
    pub fn reconnect(&self, reason: &str) {
        self.engine.reconnect(reason);
    }

    /// Closes the transport and leaves the room.
    pub async fn close(&self) {
        self.transport.close();
        self.engine.close().await;
        for t in locked(&self.tasks).drain(..) {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_channel_takes_the_rooms_channel_and_the_apps_numbers_when_unset() {
        let cfg = Config::from_json(
            br#"{"url":"tcp://127.0.0.1:9/r?ice=udp","key":"k","transport":"vp8channel","engine":"interop-p2p","channel":"c1"}"#,
        )
        .unwrap();
        let ch = channel_config(&cfg);
        assert_eq!(ch.channel_id, "c1");
        assert_eq!(ch.room_url, "tcp://127.0.0.1:9/r?ice=udp");
        assert_eq!(ch.options, Options::with_defaults(60, 64));
        assert!(ch.constrained);
        assert_eq!(ch.carrier, Carrier::Vp8);
        let tuned = Config::from_json(
            br#"{"url":"u","key":"k","transport":"vp8channel","vp8_fps":30,"vp8_batch":8}"#,
        )
        .unwrap();
        assert_eq!(
            channel_config(&tuned).options,
            Options::with_defaults(30, 8)
        );
    }
}

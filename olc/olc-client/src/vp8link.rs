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
//! The engine under it is any that carries video
//! ([`olc_vp8channel::engine::VideoEngine`]): interop-p2p
//! ([`crate::p2p_engine`]) or a carrier's session. The engine names the
//! codec its relay forwards, and the channel dresses its frames for it;
//! the relay's keyframe requests go to the channel's writer.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_net::link::{DataSink, DatagramSink, LinkEvent};
use olc_vp8channel::channel::{Carrier, Config as ChannelConfig, Options, DEFAULT_BATCH_SIZE};
use olc_vp8channel::engine::{EngineEvent, Joined, VideoEngine};
use olc_vp8channel::transport::{Event, Stream, Transport};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

/// The FPS when the config names none: the app's (60, `appVP8FPS`), which
/// the gate gives both ends.
pub const DEFAULT_FPS: u32 = 60;

/// The largest message the transport takes (`defaultMaxPayloadSize`):
/// what smux's frames are clamped to.
pub const MAX_PAYLOAD_SIZE: usize = olc_vp8channel::wire::MAX_PAYLOAD_SIZE;

/// How often a wait for a plane that cannot send looks again (Go's
/// `WaitForPeer` polls every 50 ms; the planes' readiness has no event).
const READY_POLL: Duration = Duration::from_millis(10);

/// `WaitForPeer`'s poll interval, and the carrier settle wait's.
const PEER_POLL: Duration = Duration::from_millis(50);

#[derive(Default)]
struct Sinks {
    data: Option<Arc<dyn DataSink>>,
    control: Option<Arc<dyn DataSink>>,
    datagram: Option<DatagramSink>,
}

/// One vp8channel link.
pub struct Vp8Link {
    transport: Transport,
    engine: Arc<dyn VideoEngine>,
    carrier: Carrier,
    sinks: Arc<Mutex<Sinks>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Vp8Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vp8Link")
            .field("carrier", &self.carrier)
            .finish_non_exhaustive()
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a link holds, bytes, for the memory line: the channel beside its
/// KCP sessions (`vp8`), the KCP sessions (`kcp`), and the engine's readers
/// of the room's RTP (`rtp`; zero for an engine that counts none).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkHeld {
    /// The channel's planes, queues and buffers, KCP apart.
    pub vp8: usize,
    /// The planes' KCP sessions.
    pub kcp: usize,
    /// The engine's track readers.
    pub rtp: usize,
}

/// The channel's settings from the client's: the room's channel (or its
/// URL) for the binding token, the FPS and batch (the app's when unset),
/// the phone's buffer profile; and the engine's codec.
#[must_use]
pub fn channel_config(cfg: &Config, carrier: Carrier) -> ChannelConfig {
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
        carrier,
    }
}

/// The transport's frame interval for `cfg`: the duration each sample an
/// engine is given stands for.
#[must_use]
pub fn frame_interval(cfg: &Config) -> Duration {
    let ns = channel_config(cfg, Carrier::Vp8).options.frame_interval();
    Duration::from_nanos(u64::try_from(ns).unwrap_or(1).max(1))
}

impl Vp8Link {
    /// Starts the transport over an engine that has joined its room. The
    /// link owns the engine from here: [`Vp8Link::close`] leaves the room.
    #[must_use]
    pub fn start(cfg: &Config, joined: Joined, events: mpsc::Sender<LinkEvent>) -> Arc<Self> {
        let Joined {
            engine,
            events: mut engine_rx,
        } = joined;
        let carrier = engine.carrier();
        let ccfg = channel_config(cfg, carrier);
        let sinks = Arc::new(Mutex::new(Sinks::default()));
        let dsinks = sinks.clone();
        let on_datagram: olc_vp8channel::channel::DatagramSink = Box::new(move |d: &[u8]| {
            let sink = locked(&dsinks).datagram.clone();
            if let Some(sink) = sink {
                let mut owned = d.to_vec();
                sink(&mut owned);
            }
        });
        let stream: Arc<dyn Stream> = engine.clone();
        let (transport, mut t_rx, task) = Transport::start(&ccfg, stream, Some(on_datagram));
        {
            let t = transport.clone();
            engine.set_frame_handler(Some(Arc::new(move |frame: &[u8]| {
                let _ = t.handle_incoming_frame(frame);
            })));
        }
        // The relay's PLI or FIR: the writer answers with a keyframe (the
        // channel acts on it for the VP9 carrier alone).
        {
            let t = transport.clone();
            engine.set_keyframe_handler(Some(Arc::new(move || t.request_keyframe())));
        }
        let link = Arc::new(Self {
            transport: transport.clone(),
            engine,
            carrier,
            sinks: sinks.clone(),
            tasks: Mutex::new(vec![task]),
        });
        let mut tasks = Vec::new();
        // The engine's news: a rejoin restarts the planes on a new epoch.
        {
            let t = transport.clone();
            let ev = events.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(e) = engine_rx.recv().await {
                    match e {
                        EngineEvent::Reconnected => t.provider_reconnected(),
                        EngineEvent::Ended(why) => {
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
        link
    }

    /// What the link holds now ([`LinkHeld`]).
    #[must_use]
    pub fn held(&self) -> LinkHeld {
        let (all, kcp) = self
            .transport
            .with_channel(|c| (c.held_bytes(), c.kcp_held_bytes()));
        LinkHeld {
            vp8: all.saturating_sub(kcp),
            kcp,
            rtp: self.engine.rtp_held_bytes().unwrap_or(0),
        }
    }

    /// The codec the frames ride as: the engine's.
    #[must_use]
    pub fn carrier(&self) -> Carrier {
        self.carrier
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

    /// Waits until the peer's data path is open and settled; the caller
    /// bounds it. An engine with a wait of its own decides (interop-p2p:
    /// [`crate::p2p::P2pLink::wait_peer_settled`]); under a carrier it is
    /// the transport's `PeerSeen`, frames of a peer of the room arrived.
    pub async fn wait_peer_settled(&self) {
        if let Some(settled) = self.engine.wait_peer_settled() {
            settled.await;
            return;
        }
        while !self.transport.peer_seen() {
            tokio::time::sleep(PEER_POLL).await;
        }
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

    /// Closes the transport and leaves the room. The engine's handlers
    /// hold the transport, which holds the engine: they are taken back, so
    /// neither keeps the other alive.
    pub async fn close(&self) {
        self.transport.close();
        self.engine.set_frame_handler(None);
        self.engine.set_keyframe_handler(None);
        self.engine.close().await;
        for t in locked(&self.tasks).drain(..) {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Weak;

    use olc_vp8channel::engine::{EngineFuture, FrameHandler, KeyframeHandler, EVENT_QUEUE};
    use olc_vp8channel::vp9;
    use olc_vp8channel::wire::VP8_KEEPALIVE;

    use super::*;
    use crate::testing::bounded;

    /// What the fake engine says its readers hold.
    const FAKE_RTP_HELD: usize = 4321;

    #[test]
    fn the_channel_takes_the_rooms_channel_and_the_apps_numbers_when_unset() {
        let cfg = Config::from_json(
            br#"{"url":"tcp://127.0.0.1:9/r?ice=udp","key":"k","transport":"vp8channel","engine":"interop-p2p","channel":"c1"}"#,
        )
        .unwrap();
        let ch = channel_config(&cfg, Carrier::Vp8);
        assert_eq!(ch.channel_id, "c1");
        assert_eq!(ch.room_url, "tcp://127.0.0.1:9/r?ice=udp");
        assert_eq!(ch.options, Options::with_defaults(60, 64));
        assert!(ch.constrained);
        assert_eq!(ch.carrier, Carrier::Vp8);
        assert_eq!(channel_config(&cfg, Carrier::Vp9).carrier, Carrier::Vp9);
        assert_eq!(frame_interval(&cfg), Duration::from_nanos(16_666_666));
        let tuned = Config::from_json(
            br#"{"url":"u","key":"k","transport":"vp8channel","vp8_fps":30,"vp8_batch":8}"#,
        )
        .unwrap();
        assert_eq!(
            channel_config(&tuned, Carrier::Vp8).options,
            Options::with_defaults(30, 8)
        );
        assert_eq!(frame_interval(&tuned), Duration::from_nanos(33_333_333));
    }

    /// An engine in memory: it keeps the samples it is given and, wired to
    /// another, hands each to the other's frame handler as a track reader
    /// would (a VP9 sample undressed).
    struct FakeEngine {
        carrier: Carrier,
        /// The engine has a settle wait of its own, one that never ends.
        own_wait: bool,
        samples: Mutex<Vec<Vec<u8>>>,
        on_frame: Mutex<Option<FrameHandler>>,
        on_keyframe: Mutex<Option<KeyframeHandler>>,
        peer: Mutex<Weak<FakeEngine>>,
        reasons: Mutex<Vec<String>>,
        closed: AtomicBool,
    }

    impl FakeEngine {
        fn new(carrier: Carrier, own_wait: bool) -> Arc<Self> {
            Arc::new(Self {
                carrier,
                own_wait,
                samples: Mutex::new(Vec::new()),
                on_frame: Mutex::new(None),
                on_keyframe: Mutex::new(None),
                peer: Mutex::new(Weak::new()),
                reasons: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            })
        }

        fn samples(&self) -> Vec<Vec<u8>> {
            locked(&self.samples).clone()
        }

        /// The relay asks for a keyframe.
        fn ask_keyframe(&self) -> bool {
            let h = locked(&self.on_keyframe).clone();
            h.is_some_and(|h| {
                h();
                true
            })
        }
    }

    impl Stream for FakeEngine {
        fn write_sample(&self, sample: &[u8]) -> bool {
            locked(&self.samples).push(sample.to_vec());
            let Some(peer) = locked(&self.peer).upgrade() else {
                return true;
            };
            let frame = match self.carrier {
                Carrier::Vp8 => Some(sample),
                Carrier::Vp9 => vp9::undress(sample),
            };
            let handler = locked(&peer.on_frame).clone();
            if let (Some(frame), Some(handler)) = (frame, handler) {
                handler(frame);
            }
            true
        }

        fn reconnect(&self, reason: &str) {
            locked(&self.reasons).push(reason.to_owned());
        }
    }

    impl VideoEngine for FakeEngine {
        fn carrier(&self) -> Carrier {
            self.carrier
        }

        fn set_frame_handler(&self, handler: Option<FrameHandler>) {
            *locked(&self.on_frame) = handler;
        }

        fn set_keyframe_handler(&self, handler: Option<KeyframeHandler>) {
            *locked(&self.on_keyframe) = handler;
        }

        fn wait_peer_settled(&self) -> Option<EngineFuture<'_>> {
            self.own_wait
                .then(|| Box::pin(std::future::pending()) as EngineFuture<'_>)
        }

        fn rtp_held_bytes(&self) -> Option<usize> {
            Some(FAKE_RTP_HELD)
        }

        fn close(&self) -> EngineFuture<'_> {
            Box::pin(async move { self.closed.store(true, Ordering::Release) })
        }
    }

    /// What the link holds is its channel's, split at KCP, and its
    /// engine's readers' (the memory line's `vp8`, `kcp` and `rtp`).
    #[tokio::test(start_paused = true)]
    async fn the_link_says_what_its_channel_and_readers_hold() {
        bounded(async {
            let (a, b) = pair(Carrier::Vp8, false);
            tokio::time::sleep(Duration::from_secs(1)).await;
            let held = a.link.held();
            let (all, kcp) = a
                .link
                .transport
                .with_channel(|c| (c.held_bytes(), c.kcp_held_bytes()));
            assert_eq!((held.vp8 + held.kcp, held.kcp), (all, kcp));
            assert_eq!(held.rtp, FAKE_RTP_HELD);
            a.link.close().await;
            b.link.close().await;
        })
        .await;
    }

    struct Run {
        link: Arc<Vp8Link>,
        engine: Arc<FakeEngine>,
        engine_tx: mpsc::Sender<EngineEvent>,
        events: mpsc::Receiver<LinkEvent>,
    }

    fn run(carrier: Carrier, own_wait: bool) -> Run {
        let cfg = Config::from_json(
            br#"{"url":"https://carrier.example/room","key":"k","transport":"vp8channel","channel":"c1"}"#,
        )
        .unwrap();
        let engine = FakeEngine::new(carrier, own_wait);
        let (engine_tx, engine_rx) = mpsc::channel(EVENT_QUEUE);
        let (tx, events) = mpsc::channel(8);
        let link = Vp8Link::start(
            &cfg,
            Joined {
                engine: engine.clone(),
                events: engine_rx,
            },
            tx,
        );
        Run {
            link,
            engine,
            engine_tx,
            events,
        }
    }

    /// What a vp8channel session holds unread counts in the client's
    /// gauge (`lane_rx`): both planes' queues, as the one lane's does on a
    /// datachannel.
    #[tokio::test(start_paused = true)]
    async fn both_planes_queues_count_as_the_lanes_unread_bytes() {
        use olc_wire::record::{KeySet, Lane as RecordLane, Role};
        bounded(async {
            let r = run(Carrier::Vp8, false);
            let client = Arc::new(KeySet::new(&[7; 32], Role::Client).unwrap());
            let server = Arc::new(KeySet::new(&[7; 32], Role::Server).unwrap());
            let features = olc_muxconn::Features {
                max_payload_size: MAX_PAYLOAD_SIZE,
                write_interval: Duration::ZERO,
            };
            let (data, _dio) = crate::plane::PlaneLane::new(
                r.link.clone(),
                client.clone(),
                &features,
                RecordLane::Data,
            );
            let (control, _cio) = crate::plane::PlaneLane::new(
                r.link.clone(),
                client,
                &features,
                RecordLane::Control,
            );
            for (lane, kind, len) in [
                (&data, RecordLane::Data, 300),
                (&control, RecordLane::Control, 40),
            ] {
                let mut tx =
                    olc_muxconn::conn::Sender::new(server.clone(), kind, features.max_frame());
                let mut record = tx.seal(&vec![0x5a; len]).unwrap().to_vec();
                lane.push(&mut record).await;
            }
            let lane = crate::plane::SessLane::Planes { data, control };
            assert_eq!(lane.rx_buffered(), 340);
            lane.close();
            r.link.close().await;
        })
        .await;
    }

    /// Two links in one room: each engine's samples are the other's frames.
    fn pair(carrier: Carrier, own_wait: bool) -> (Run, Run) {
        let (a, b) = (run(carrier, own_wait), run(carrier, own_wait));
        *locked(&a.engine.peer) = Arc::downgrade(&b.engine);
        *locked(&b.engine.peer) = Arc::downgrade(&a.engine);
        (a, b)
    }

    /// The codec is the engine's: over a VP9 engine (MTS Link) every sample
    /// leaves dressed as VP9, over a VP8 one as the transport's own frame.
    #[tokio::test(start_paused = true)]
    async fn the_frames_are_dressed_for_the_engines_codec() {
        bounded(async {
            for carrier in [Carrier::Vp9, Carrier::Vp8] {
                let r = run(carrier, false);
                assert_eq!(r.link.carrier(), carrier);
                tokio::time::sleep(Duration::from_millis(300)).await;
                let samples = r.engine.samples();
                assert!(!samples.is_empty(), "{carrier:?}: nothing written");
                for s in &samples {
                    let vp9 = s.starts_with(&vp9::VP9_HEAD) && vp9::undress(s).is_some();
                    assert_eq!(vp9, carrier == Carrier::Vp9, "{carrier:?}: {s:02x?}");
                    assert_eq!(
                        s.starts_with(&VP8_KEEPALIVE),
                        carrier == Carrier::Vp8,
                        "{carrier:?}: {s:02x?}"
                    );
                }
                r.link.close().await;
            }
        })
        .await;
    }

    /// A relay's keyframe request reaches the writer: the next sample but
    /// a few is a keyframe, long before the two-second one is due.
    #[tokio::test(start_paused = true)]
    async fn a_keyframe_request_reaches_the_writer() {
        bounded(async {
            let r = run(Carrier::Vp9, false);
            let keyframes = || {
                r.engine
                    .samples()
                    .iter()
                    .filter(|s| s.len() == vp9::KEYFRAME_SPAN)
                    .count()
            };
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(!r.engine.samples().is_empty());
            assert_eq!(keyframes(), 0, "no keyframe is due in the first 2 s");
            assert!(
                r.engine.ask_keyframe(),
                "the engine has no keyframe handler"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(keyframes(), 1);
            r.link.close().await;
        })
        .await;
    }

    /// Under a carrier the peer has settled once its frames arrive
    /// (`PeerSeen`); alone in the room the wait goes on.
    #[tokio::test(start_paused = true)]
    async fn a_carriers_peer_has_settled_once_its_frames_arrive() {
        bounded(async {
            let alone = run(Carrier::Vp9, false);
            let waited =
                tokio::time::timeout(Duration::from_secs(1), alone.link.wait_peer_settled()).await;
            assert!(waited.is_err() && !alone.link.peer_seen());
            alone.link.close().await;

            let (a, b) = pair(Carrier::Vp9, false);
            for r in [&a, &b] {
                tokio::time::timeout(Duration::from_secs(1), r.link.wait_peer_settled())
                    .await
                    .expect("frames of the peer arrived");
                assert!(r.link.peer_seen());
            }
            a.link.close().await;
            b.link.close().await;
        })
        .await;
    }

    /// An engine with a settle wait of its own decides (interop-p2p's
    /// settle time), whatever the transport has seen.
    #[tokio::test(start_paused = true)]
    async fn an_engines_own_settle_wait_decides() {
        bounded(async {
            let (a, b) = pair(Carrier::Vp8, true);
            let waited =
                tokio::time::timeout(Duration::from_secs(1), a.link.wait_peer_settled()).await;
            assert!(a.link.peer_seen(), "the pair exchanged frames");
            assert!(waited.is_err(), "the engine's own wait was not asked");
            a.link.close().await;
            b.link.close().await;
        })
        .await;
    }

    /// The engine's news: a rejoin restarts the planes and the owner hears
    /// it; an end is passed on with its reason. The transport's own
    /// reconnect request goes down to the engine.
    #[tokio::test(start_paused = true)]
    async fn the_engines_news_reach_the_owner() {
        bounded(async {
            let mut r = run(Carrier::Vp9, false);
            let epoch = r.link.transport.with_channel(|c| c.local_epoch());
            r.engine_tx.send(EngineEvent::Reconnected).await.unwrap();
            assert!(matches!(
                r.events.recv().await,
                Some(LinkEvent::Reconnected)
            ));
            assert_ne!(r.link.transport.with_channel(|c| c.local_epoch()), epoch);
            r.engine_tx
                .send(EngineEvent::Ended("conference closed".to_owned()))
                .await
                .unwrap();
            match r.events.recv().await {
                Some(LinkEvent::Ended(why)) => assert_eq!(why, "conference closed"),
                other => panic!("{other:?}"),
            }
            r.link.reconnect("liveness");
            assert_eq!(*locked(&r.engine.reasons), ["liveness"]);
            r.link.close().await;
        })
        .await;
    }

    /// Closing leaves the room and takes the handlers back: the engine
    /// holds the transport through them, and the transport the engine.
    #[tokio::test(start_paused = true)]
    async fn close_leaves_the_room_and_takes_the_handlers_back() {
        bounded(async {
            let r = run(Carrier::Vp9, false);
            assert!(locked(&r.engine.on_frame).is_some());
            assert!(locked(&r.engine.on_keyframe).is_some());
            r.link.close().await;
            assert!(r.engine.closed.load(Ordering::Acquire));
            assert!(locked(&r.engine.on_frame).is_none());
            assert!(locked(&r.engine.on_keyframe).is_none());
            let written = r.engine.samples().len();
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(r.engine.samples().len(), written, "the writer stopped");
        })
        .await;
    }
}

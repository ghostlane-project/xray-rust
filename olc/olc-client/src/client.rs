// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's run (`client.RunWithAddress`, client.go) and its session's
//! life (link.go, health.go, recovery.go): bring-up, the session every
//! request waits for, its death and its reconnects.
//!
//! # Reconnect
//!
//! As in Go, three things rebuild a session, all serialised by one lock
//! (`reconnectMu`) and one recovery generation (`recovery`):
//!
//! - the engine rejoined (`LinkEvent::Reconnected`, `onProviderReconnect`):
//!   the session is dropped and the handshake retried, at most 5 attempts;
//! - the control loop declared the session dead (`onSessionDeath`, reason
//!   `liveness` or `peer-close`): the session is dropped, a fallback armed
//!   and the engine asked to reconnect, which comes back as the first;
//! - a fallback found no session after its pause (`armFallback`): it asks
//!   the engine again, or handshakes again itself (3 attempts), and the
//!   pause doubles after each failed round (30 s << rounds, at most 5 min).
//!
//! The lines `client reconnect reason=…` and `client reconnect attempt=…`
//! are Go's, which the gate's S4 and the apps read.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_muxconn::DatagramLane;
use olc_smux::Session;
use olc_wire::record::{KeySet, Role};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ConfigError, TRANSPORT_DATACHANNEL, TRANSPORT_VP8CHANNEL};
use crate::control::{self, End, Hooks};
use crate::direct::Rules;
use crate::hello::{self, HelloError, DEFAULT_TIMEOUT, HELLO_RESEND_INTERVAL};
use crate::lane::{Lane, DATACHANNEL};
use crate::link::Link;
use crate::pipe::{LinkEvent, EVENT_QUEUE};
use crate::plane::{PlaneLane, SessLane};
use crate::udp::Flows;

/// `reconnectProvider`: the engine rejoined.
pub const REASON_PROVIDER: &str = "provider";
/// `reconnectLiveness`: the control loop gave up.
pub const REASON_LIVENESS: &str = "liveness";
/// `reconnectFallback`: a fallback found no session.
pub const REASON_FALLBACK: &str = "liveness-fallback";
/// `reconnectHandshake`: a fallback asked the engine again.
pub const REASON_HANDSHAKE: &str = "handshake";
/// `reconnectPeerClose`: the server said `CONTROL_CLOSE`.
pub const REASON_PEER_CLOSE: &str = "peer-close";

/// The reconnect reason for how a control loop that was not stopped ended
/// (health.go's `OnDeath`): a close the peer sent is peer-close, anything
/// else liveness.
fn death_reason(end: &End) -> &'static str {
    if *end == End::ClosedByPeer {
        REASON_PEER_CLOSE
    } else {
        REASON_LIVENESS
    }
}

/// `maxRecoveryPause`: the longest pause between recovery rounds.
pub const MAX_RECOVERY_PAUSE: Duration = Duration::from_secs(300);
/// `maxRecoveryBackoff`: the pause doubles at most this many times.
pub const MAX_RECOVERY_BACKOFF: u32 = 8;
/// The first pause of `retryHandshake`, doubled up to [`RETRY_MAX_DELAY`].
pub const RETRY_INITIAL_DELAY: Duration = Duration::from_millis(300);
/// The longest pause between handshake attempts.
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
/// How long a request waits for a session (`defaultSessionReadyTimeout`).
pub const SESSION_READY_TIMEOUT: Duration = Duration::from_secs(60);
/// A control-plane transport's pong timeout, ms (`runtime.LivenessTimeout`
/// for vp8channel: 45 s, the KCP control plane's retransmits included).
pub const CONTROL_PLANE_LIVENESS_TIMEOUT_MS: u64 = 45_000;
/// Requests that may wait for a session at once (`maxParkedRequests`).
pub const MAX_PARKED: usize = 64;
/// How long shutdown waits for the control loop's goodbye.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Told each session id as a session opens (`Config.OnSessionOpen`).
pub type SessionListener = Arc<dyn Fn(&str) + Send + Sync>;

/// Why a run ended before or instead of serving.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The settings cannot run.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The engine did not join (`failed to connect link`).
    #[error("failed to connect link: {0}")]
    Link(#[from] crate::link::LinkError),
    /// The server the welcome named could not be bound, or the room
    /// held no peer (`confirmPeer`, `waitForPeer`).
    #[error("{0}")]
    Peer(std::io::Error),
    /// The first handshake failed, classified.
    #[error("handshake: {0}")]
    Handshake(Classified),
    /// smux would not start.
    #[error("create smux sessions: {0}")]
    Smux(String),
    /// The SOCKS port would not open.
    #[error("failed to listen on {addr}: {err}")]
    Listen {
        /// The address asked for.
        addr: String,
        /// Why.
        err: std::io::Error,
    },
}

/// A failed handshake as `classifyHandshakeFailure` names it.
#[derive(Debug)]
pub struct Classified {
    /// What it was.
    pub kind: FailureKind,
    /// The race's error.
    pub err: HelloError,
}

/// The classes (classify.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// `ErrPeerProtocolMismatch`.
    ProtocolMismatch,
    /// `ErrKeyMismatch`.
    KeyMismatch,
    /// `ErrPeerSilent`.
    PeerSilent,
    /// `ErrNoPeer`.
    NoPeer,
    /// Left as it was: a reject for another reason, a stop.
    Other,
}

impl std::fmt::Display for Classified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.kind {
            FailureKind::ProtocolMismatch => "peer speaks an incompatible olcrtc protocol: ",
            FailureKind::KeyMismatch => "key does not match the peer: ",
            FailureKind::PeerSilent => "peer did not answer the handshake: ",
            FailureKind::NoPeer => "no peer in room: ",
            FailureKind::Other => "",
        };
        f.write_str(prefix)?;
        match &self.err {
            HelloError::Open(_) => write!(f, "{}", self.err),
            e => write!(f, "handshake client: {e}"),
        }
    }
}

/// How a reconnect round ended (`roundResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Round {
    /// The run ended.
    Stopped,
    /// A session is open.
    Opened,
    /// No answer.
    Silent,
    /// The server refused.
    Refused,
    /// Nobody in the room.
    Empty,
}

/// The run's client.
#[derive(Debug, Clone, Copy)]
pub struct Client;

impl Client {
    /// Runs until `stop` is cancelled or the conference ends; `on_ready` is
    /// told the SOCKS address once it listens, which is after the first
    /// handshake.
    ///
    /// # Errors
    /// [`RunError`] for a run that never served.
    pub async fn run(
        cfg: Config,
        stop: CancellationToken,
        on_ready: impl FnOnce(SocketAddr) + Send,
    ) -> Result<(), RunError> {
        Self::run_with(cfg, stop, on_ready, None).await
    }

    /// [`Client::run`] with a session listener (`OnSessionOpen`): told each
    /// session id as a session opens or reopens.
    ///
    /// # Errors
    /// [`RunError`] for a run that never served.
    pub async fn run_with(
        cfg: Config,
        stop: CancellationToken,
        on_ready: impl FnOnce(SocketAddr) + Send,
        on_session_open: Option<SessionListener>,
    ) -> Result<(), RunError> {
        Self::run_inner(cfg, stop, on_ready, on_session_open, |_| {}).await
    }

    /// [`Client::run_with`]; `inspect` sees the run's state once it is
    /// built (the tests hold a `Weak` of it).
    async fn run_inner(
        cfg: Config,
        stop: CancellationToken,
        on_ready: impl FnOnce(SocketAddr) + Send,
        on_session_open: Option<SessionListener>,
        inspect: impl FnOnce(&Arc<Inner>) + Send,
    ) -> Result<(), RunError> {
        if cfg.transport != TRANSPORT_DATACHANNEL && cfg.transport != TRANSPORT_VP8CHANNEL {
            return Err(ConfigError::Transport(cfg.transport.clone()).into());
        }
        let keys = Arc::new(
            KeySet::from_hex(&cfg.key, Role::Client)
                .map_err(|e| ConfigError::Key(e.to_string()))?,
        );
        let rules = Rules::parse(&cfg.direct).map_err(ConfigError::Rule)?;
        // Checked before anything connects: an open relay never starts.
        let socks = cfg.socks_listen_addr()?;
        crate::log::set_verbose(cfg.debug);
        // The ring the engine's own names and the direct DNS ask (the mobile
        // runtime's `protect.NewResolver(dns)`).
        crate::resolver::set_servers(&cfg.dns);
        let (ev_tx, mut ev_rx) = mpsc::channel(EVENT_QUEUE);
        let link = Link::connect(&cfg, ev_tx).await?;
        let run = stop.child_token();
        let device_id = if cfg.device_id.is_empty() {
            random_device_id()
        } else {
            cfg.device_id.clone()
        };
        let inner = Arc::new(Inner {
            datagram: Mutex::new(DatagramLane::new(keys.clone())),
            keys,
            device_id,
            link,
            run: run.clone(),
            sess: Mutex::new(Sess::default()),
            ready: watch::channel(0).0,
            reconnect_mu: tokio::sync::Mutex::new(()),
            recovery: Mutex::new(Recovery::default()),
            failed_rounds: AtomicU32::new(0),
            parked: AtomicUsize::new(0),
            parked_saturated: AtomicBool::new(false),
            socks_conns: AtomicUsize::new(0),
            ipv6: Mutex::new(Ipv6Latch::default()),
            flows: Flows::new(cfg.udp_max_flows),
            dns_in_flight: AtomicUsize::new(0),
            dns_announced: Mutex::new(String::new()),
            dns_direct_announced: AtomicBool::new(false),
            next_control: AtomicU64::new(0),
            on_session_open,
            rules,
            cfg,
        });
        inner.install_datagram_sink();
        crate::gauges::register(&inner);
        inspect(&inner);
        {
            // The run's state is held only while an event is handled: the
            // task ends with the run, and the link's close ends the queue.
            let me = Arc::downgrade(&inner);
            let run = inner.run.clone();
            tokio::spawn(async move {
                loop {
                    let ev = tokio::select! {
                        () = run.cancelled() => break,
                        ev = ev_rx.recv() => match ev { Some(ev) => ev, None => break },
                    };
                    let Some(inner) = me.upgrade() else { break };
                    match ev {
                        LinkEvent::Reconnected => inner.on_provider_reconnect(),
                        LinkEvent::Ended(reason) => {
                            crate::info!("Client link reported conference end: {reason}");
                            inner.run.cancel();
                        }
                    }
                }
            });
        }
        if let Err(e) = inner.bring_up().await {
            inner.shutdown().await;
            return Err(e);
        }
        let listener = match TcpListener::bind(socks).await {
            Ok(l) => l,
            Err(err) => {
                inner.shutdown().await;
                return Err(RunError::Listen {
                    addr: inner.cfg.socks.clone(),
                    err,
                });
            }
        };
        let addr = listener.local_addr().map_err(|err| RunError::Listen {
            addr: inner.cfg.socks.clone(),
            err,
        })?;
        crate::info!("SOCKS5 server listening on {addr}");
        if let Some(rules) = &inner.rules {
            crate::info!("direct rules: {}", rules.summary());
        }
        on_ready(addr);
        tokio::spawn(inner.clone().accept_loop(listener));
        inner.run.cancelled().await;
        inner.shutdown().await;
        Ok(())
    }
}

/// A fresh device id, a version-4 UUID (`uuid.NewString`).
pub fn random_device_id() -> String {
    let b: [u8; 16] = rand::random();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]) & 0x0fff,
        (u16::from_be_bytes([b[8], b[9]]) & 0x3fff) | 0x8000,
        u64::from_be_bytes([0, 0, b[10], b[11], b[12], b[13], b[14], b[15]])
    )
}

/// The run's state, shared by every task of the run.
pub(crate) struct Inner {
    pub(crate) cfg: Config,
    pub(crate) keys: Arc<KeySet>,
    pub(crate) device_id: String,
    pub(crate) link: Link,
    /// The run: cancelled when it ends.
    pub(crate) run: CancellationToken,
    pub(crate) sess: Mutex<Sess>,
    /// Bumped each time a session becomes ready (`signalSessionReady`).
    pub(crate) ready: watch::Sender<u64>,
    reconnect_mu: tokio::sync::Mutex<()>,
    recovery: Mutex<Recovery>,
    failed_rounds: AtomicU32,
    pub(crate) parked: AtomicUsize,
    pub(crate) parked_saturated: AtomicBool,
    pub(crate) socks_conns: AtomicUsize,
    pub(crate) ipv6: Mutex<Ipv6Latch>,
    pub(crate) datagram: Mutex<DatagramLane>,
    pub(crate) flows: Flows,
    pub(crate) dns_in_flight: AtomicUsize,
    pub(crate) dns_announced: Mutex<String>,
    pub(crate) dns_direct_announced: AtomicBool,
    next_control: AtomicU64,
    on_session_open: Option<SessionListener>,
    pub(crate) rules: Option<Rules>,
}

/// The session every request waits for.
#[derive(Default)]
pub(crate) struct Sess {
    pub(crate) session: Option<Session>,
    /// The control session, on a link with a control plane (the data
    /// session is the control session otherwise).
    pub(crate) control_session: Option<Session>,
    pub(crate) session_id: String,
    pub(crate) lane: Option<SessLane>,
    control_stop: Option<CancellationToken>,
    control_done: Option<tokio::task::JoinHandle<()>>,
    /// Which control loop is current; a dead one names itself by it.
    control_id: u64,
}

/// `recovery` (recovery.go): one recovery runs at a time; a newer one
/// stops the older.
#[derive(Default)]
struct Recovery {
    gen: u64,
    stop: Option<CancellationToken>,
}

/// The IPv6 latch (tunnel.go): after [`IPV6_FAILURES_BEFORE_LATCH`] exits
/// refused IPv6 literals as unreachable, they are refused here for
/// [`IPV6_LATCH_WINDOW`].
#[derive(Default)]
pub(crate) struct Ipv6Latch {
    pub(crate) failures: u32,
    pub(crate) until: Option<Instant>,
}

/// `ipv6FailuresBeforeLatch`.
pub const IPV6_FAILURES_BEFORE_LATCH: u32 = 3;
/// `ipv6LatchWindow`.
pub const IPV6_LATCH_WINDOW: Duration = Duration::from_secs(120);

impl Inner {
    pub(crate) fn sess(&self) -> MutexGuard<'_, Sess> {
        self.sess.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn recovery(&self) -> MutexGuard<'_, Recovery> {
        self.recovery.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session when one is established (`sessionSnapshot`).
    pub(crate) fn session(&self) -> Option<(Session, String)> {
        let s = self.sess();
        match &s.session {
            Some(sess) if !sess.is_closed() && !s.session_id.is_empty() => {
                Some((sess.clone(), s.session_id.clone()))
            }
            _ => None,
        }
    }

    /// `sessionEstablished`.
    pub(crate) fn session_established(&self) -> bool {
        self.session().is_some()
    }

    /// `waitSessionReady` with the parking rules of `prepareTunnel`: waits
    /// for a session at most [`SESSION_READY_TIMEOUT`], as one of at most
    /// [`MAX_PARKED`] waiting requests.
    pub(crate) async fn wait_session(&self) -> Result<(Session, String), WaitRefused> {
        let deadline = Instant::now() + SESSION_READY_TIMEOUT;
        let mut ready = self.ready.subscribe();
        // The slot goes back however the wait ends, an abort included (a
        // sniffed direct name drops the tunnel's preparation).
        let mut parked: Option<Parked<'_>> = None;
        loop {
            if let Some(s) = self.session() {
                return Ok(s);
            }
            if parked.is_none() {
                if !self.park() {
                    return Err(WaitRefused::Saturated);
                }
                parked = Some(Parked(self));
            }
            tokio::select! {
                () = self.run.cancelled() => return Err(WaitRefused::Timeout),
                () = tokio::time::sleep_until(deadline) => return Err(WaitRefused::Timeout),
                r = ready.changed() => if r.is_err() { return Err(WaitRefused::Timeout) },
            }
        }
    }

    fn park(&self) -> bool {
        let mut n = self.parked.load(Ordering::Relaxed);
        loop {
            if n >= MAX_PARKED {
                if !self.parked_saturated.swap(true, Ordering::Relaxed) {
                    crate::info!("socks: {n} requests parked on a missing session; refusing more until it is back");
                }
                return false;
            }
            match self
                .parked
                .compare_exchange(n, n + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(now) => n = now,
            }
        }
    }

    fn unpark(&self) {
        if self.parked.fetch_sub(1, Ordering::Relaxed) - 1 < MAX_PARKED / 2 {
            self.parked_saturated.store(false, Ordering::Relaxed);
        }
    }

    /// The datagram lane's inbound side goes to the flows.
    fn install_datagram_sink(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        self.link
            .set_datagram(Some(Arc::new(move |record: &mut [u8]| {
                if let Some(inner) = weak.upgrade() {
                    inner.on_datagram(record);
                }
            })));
    }

    /// A fresh lane and smux session over the link; the link hands its
    /// records to the new lane from now on. A link with a control plane
    /// (vp8channel) gets a lane on each plane and a control session on the
    /// control one (`NewSessionPairWithConns`), returned second.
    fn new_session(&self) -> Result<(SessLane, Session, Option<Session>), RunError> {
        let smux_err = |e: olc_smux::Error| RunError::Smux(e.to_string());
        if let Some(vp8) = self.link.vp8() {
            let features = olc_muxconn::Features {
                max_payload_size: crate::vp8link::MAX_PAYLOAD_SIZE,
                write_interval: Duration::ZERO,
            };
            let (data, dio) = PlaneLane::new(
                vp8.clone(),
                self.keys.clone(),
                &features,
                olc_wire::record::Lane::Data,
            );
            let (control, cio) = PlaneLane::new(
                vp8.clone(),
                self.keys.clone(),
                &features,
                olc_wire::record::Lane::Control,
            );
            let lane = SessLane::Planes {
                data: data.clone(),
                control: control.clone(),
            };
            if let Some(old) = self.sess().lane.replace(lane.clone()) {
                old.close();
            }
            self.link.set_planes(Some(data), Some(control));
            let max = features.max_payload_size;
            let (session, driver) =
                Session::client(dio, olc_smux::Config::client_data(max, true)).map_err(smux_err)?;
            tokio::spawn(async move {
                let _ = driver.await;
            });
            let (csession, cdriver) =
                Session::client(cio, olc_smux::Config::control(max)).map_err(smux_err)?;
            tokio::spawn(async move {
                let _ = cdriver.await;
            });
            return Ok((lane, session, Some(csession)));
        }
        let (lane, io) = Lane::new(self.link.clone(), self.keys.clone(), &DATACHANNEL)
            .map_err(|e| RunError::Smux(e.to_string()))?;
        let old = self.sess().lane.replace(SessLane::Batched(lane.clone()));
        if let Some(old) = old {
            old.close();
        }
        self.link.set_data(Some(lane.clone()));
        let cfg = olc_smux::Config::client_data(DATACHANNEL.max_payload_size, false);
        let (session, driver) = Session::client(io, cfg).map_err(smux_err)?;
        tokio::spawn(async move {
            let _ = driver.await;
        });
        Ok((SessLane::Batched(lane), session, None))
    }

    /// The wait before a handshake's first hello: until the peer has settled
    /// in the room ([`Link::wait_peer_settled`]), for one resend
    /// interval at most, or until `stop`; what is left of `timeout`. Go sends
    /// the hello at once, and one that reaches an empty room, or a server
    /// between its rejoin and its new session, is lost to the first resend
    /// 2 s later: the e2e reconnects lost it in most rounds, the Go client as
    /// often as this one. The wait comes out of the handshake's budget, so a
    /// peer that never answers is given up when Go gives it up.
    async fn hello_budget(&self, timeout: Duration, stop: &CancellationToken) -> Duration {
        let started = Instant::now();
        tokio::select! {
            () = stop.cancelled() => {}
            () = self.link.wait_peer_settled() => {}
            () = tokio::time::sleep(HELLO_RESEND_INTERVAL.min(timeout)) => {}
        }
        timeout.saturating_sub(started.elapsed())
    }

    /// `bringUpLink` after the link joined: the first session and its
    /// handshake.
    async fn bring_up(self: &Arc<Self>) -> Result<(), RunError> {
        let _g = self.reconnect_mu.lock().await;
        let (lane, session, control) = self.new_session()?;
        let close = |session: &Session, control: &Option<Session>| {
            let _ = session.close();
            if let Some(c) = control {
                let _ = c.close();
            }
        };
        let hello_on = control.as_ref().unwrap_or(&session);
        let hello_remaining = self.hello_budget(DEFAULT_TIMEOUT, &self.run).await;
        let opened =
            match hello::open_control_stream(hello_on, &self.device_id, hello_remaining, &self.run)
                .await
            {
                Ok(o) => o,
                Err(err) => {
                    let classified = self.classify(err, &lane);
                    close(&session, &control);
                    lane.close();
                    return Err(RunError::Handshake(classified));
                }
            };
        if let Err(e) = self.bind_peer(&opened.welcome.peer_id).await {
            close(&session, &control);
            lane.close();
            return Err(RunError::Peer(e));
        }
        let sid = opened.welcome.session_id.clone();
        crate::info!("session {sid} opened (device={})", self.device_id);
        self.install(session, control, sid.clone(), opened.stream);
        self.notify_session_open(&sid);
        Ok(())
    }

    /// `confirmPeer` then `waitForPeer`, as the bring-up runs them.
    async fn bind_peer(&self, peer_id: &str) -> std::io::Result<()> {
        self.link.confirm_peer(peer_id).await?;
        self.link.wait_for_peer().await
    }

    /// `notifySessionOpen`.
    fn notify_session_open(&self, sid: &str) {
        if let Some(listen) = &self.on_session_open {
            listen(sid);
        }
    }

    /// `classifyHandshakeFailure`.
    fn classify(&self, err: HelloError, lane: &SessLane) -> Classified {
        let stats = lane.decrypt_stats();
        let kind = match &err {
            HelloError::Reply(olc_wire::handshake::HandshakeError::ProtocolVersion(_)) => {
                FailureKind::ProtocolMismatch
            }
            HelloError::Reply(olc_wire::handshake::HandshakeError::Rejected(reason)) => {
                if reason.contains("protocol version mismatch") {
                    FailureKind::ProtocolMismatch
                } else {
                    FailureKind::Other
                }
            }
            _ if stats.bad_magic > 0 => FailureKind::ProtocolMismatch,
            _ if stats.auth_failed > 0 => FailureKind::KeyMismatch,
            _ if self.link.peer_seen() => FailureKind::PeerSilent,
            _ => FailureKind::NoPeer,
        };
        Classified { kind, err }
    }

    /// Makes the session current, wakes the parked requests and starts its
    /// control loop.
    fn install(
        self: &Arc<Self>,
        session: Session,
        control_session: Option<Session>,
        sid: String,
        control: olc_smux::Stream,
    ) {
        let id = self.next_control.fetch_add(1, Ordering::Relaxed) + 1;
        let stop = self.run.child_token();
        {
            let mut s = self.sess();
            s.session = Some(session);
            s.control_session = control_session;
            s.session_id.clone_from(&sid);
            s.control_stop = Some(stop.clone());
            s.control_id = id;
        }
        *self.ipv6.lock().unwrap_or_else(PoisonError::into_inner) = Ipv6Latch::default();
        self.ready.send_modify(|g| *g += 1);
        let me = Arc::downgrade(self);
        let progress = {
            let me = me.clone();
            move || {
                me.upgrade()
                    .and_then(|i| i.sess().lane.as_ref().map(|l| l.payload_bytes()))
                    .unwrap_or(0)
            }
        };
        let stalled = {
            let me = me.clone();
            move || {
                me.upgrade()
                    .and_then(|i| i.sess().lane.as_ref().map(|l| l.send_stalled()))
                    .unwrap_or(false)
            }
        };
        let hooks = Hooks {
            fields: format!("role=client session={sid}"),
            progress: Box::new(progress),
            send_stalled: Box::new(stalled),
            on_pong: Box::new(|_| {}),
        };
        let mut liveness = self.cfg.liveness;
        // `tunedConfig`: a control-plane transport's pongs get 45 s
        // (`runtime.LivenessTimeout`) unless the config asks for more.
        if self.link.vp8().is_some() && liveness.timeout() <= olc_wire::control::DEFAULT_TIMEOUT {
            liveness.timeout_ms = CONTROL_PLANE_LIVENESS_TIMEOUT_MS;
        }
        let handle = tokio::spawn(async move {
            let end = control::run(control, liveness, hooks, stop.clone()).await;
            if stop.is_cancelled() {
                return;
            }
            let reason = death_reason(&end);
            if let Some(inner) = me.upgrade() {
                inner.on_session_death(id, reason).await;
            }
        });
        self.sess().control_done = Some(handle);
    }

    /// `dropSessionLocked`: tears the session down, unless `dead` names a
    /// control loop that is no longer current. Call with the reconnect lock.
    fn drop_session_locked(&self, reason: &str, dead: Option<u64>) -> bool {
        let (lane, session, stop) = {
            let mut s = self.sess();
            if let Some(dead) = dead {
                if s.control_id != dead || s.control_stop.is_none() {
                    return false;
                }
            }
            crate::info!("client reconnect reason={reason} - tearing down smux session");
            self.link.reset_peer();
            s.session_id.clear();
            s.control_done = None;
            if let Some(c) = s.control_session.take() {
                let _ = c.close();
            }
            (s.lane.take(), s.session.take(), s.control_stop.take())
        };
        if let Some(lane) = lane {
            lane.close();
        }
        if let Some(stop) = stop {
            stop.cancel();
        }
        if let Some(session) = session {
            let _ = session.close();
        }
        true
    }

    /// `recovery.take`: stops the recovery running and starts the next.
    fn recovery_take(&self) -> (CancellationToken, u64) {
        let mut r = self.recovery();
        self.take_locked(&mut r)
    }

    fn take_locked(&self, r: &mut Recovery) -> (CancellationToken, u64) {
        if let Some(old) = r.stop.take() {
            old.cancel();
        }
        r.gen += 1;
        let run = self.run.child_token();
        r.stop = Some(run.clone());
        (run, r.gen)
    }

    /// `recovery.takeIf`: only when no other recovery began since `expect`
    /// was read, and, unless `owned`, none runs.
    fn recovery_take_if(&self, expect: u64, owned: bool) -> Option<(CancellationToken, u64)> {
        let mut r = self.recovery();
        if r.gen != expect || (r.stop.is_some() && !owned) {
            return None;
        }
        Some(self.take_locked(&mut r))
    }

    fn recovery_release(&self, gen: u64) {
        let mut r = self.recovery();
        if r.gen == gen {
            if let Some(stop) = r.stop.take() {
                stop.cancel();
            }
        }
    }

    fn recovery_gen(&self) -> u64 {
        self.recovery().gen
    }

    /// `onProviderReconnect`.
    fn on_provider_reconnect(self: &Arc<Self>) {
        let (run, gen) = self.recovery_take();
        let me = self.clone();
        tokio::spawn(async move {
            me.handle_reconnect(&run, REASON_PROVIDER).await;
            me.recovery_release(gen);
        });
    }

    /// `handleReconnect`.
    async fn handle_reconnect(self: &Arc<Self>, run: &CancellationToken, reason: &str) {
        let expect = self.recovery_gen();
        let _g = self.reconnect_mu.lock().await;
        if run.is_cancelled() {
            return;
        }
        self.drop_session_locked(reason, None);
        let result = self.retry_handshake(run, reason).await;
        if result != Round::Opened && !run.is_cancelled() {
            self.after_failed_round(result, expect);
        }
    }

    /// `onSessionDeath`.
    async fn on_session_death(self: &Arc<Self>, dead: u64, reason: &str) {
        let expect = self.recovery_gen();
        let _g = self.reconnect_mu.lock().await;
        if !self.drop_session_locked(reason, Some(dead)) {
            return;
        }
        self.rebuild_provider(reason, expect, false);
    }

    /// `rebuildProvider`.
    fn rebuild_provider(self: &Arc<Self>, reason: &str, expect: u64, owned: bool) {
        if !self.arm_fallback(expect, owned, false) {
            return;
        }
        self.link.reconnect(reason);
    }

    /// `afterFailedRound`.
    fn after_failed_round(self: &Arc<Self>, result: Round, expect: u64) {
        if result == Round::Empty && self.cfg.end_on_empty_room {
            crate::info!("client reconnect: the room is empty and there are other rooms to try - ending the session");
            self.run.cancel();
            return;
        }
        if !self.arm_fallback(expect, true, result != Round::Refused) {
            return;
        }
        self.failed_rounds.fetch_add(1, Ordering::Relaxed);
    }

    /// `recoveryPause`.
    fn recovery_pause(&self) -> Duration {
        let base = self.cfg.liveness_fallback();
        let n = self.failed_rounds.load(Ordering::Relaxed);
        base.saturating_mul(1 << n.min(MAX_RECOVERY_BACKOFF))
            .min(MAX_RECOVERY_PAUSE)
    }

    /// `armFallback`.
    fn arm_fallback(self: &Arc<Self>, expect: u64, owned: bool, ask: bool) -> bool {
        let Some((run, gen)) = self.recovery_take_if(expect, owned) else {
            return false;
        };
        let delay = self.recovery_pause();
        let me = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = run.cancelled() => { me.recovery_release(gen); return; }
                () = tokio::time::sleep(delay) => {}
            }
            if me.session_established() {
                me.recovery_release(gen);
                return;
            }
            let after = crate::socks::go_duration(delay);
            if ask {
                crate::info!("client reconnect: no session after {after} - asking the provider for a new connection");
                me.rebuild_provider(REASON_HANDSHAKE, gen, true);
                me.recovery_release(gen);
                return;
            }
            crate::info!("client reconnect: no session after {after} - handshaking again");
            {
                let _g = me.reconnect_mu.lock().await;
                if !run.is_cancelled() && !me.session_established() {
                    let result = me.retry_handshake(&run, REASON_FALLBACK).await;
                    if result != Round::Opened && !run.is_cancelled() {
                        me.after_failed_round(result, gen);
                    }
                }
            }
            me.recovery_release(gen);
        });
        true
    }

    /// `retryHandshake`.
    async fn retry_handshake(self: &Arc<Self>, run: &CancellationToken, reason: &str) -> Round {
        let max_attempts = match reason {
            REASON_PROVIDER => 5,
            REASON_FALLBACK => 3,
            _ => 0,
        };
        let mut delay = RETRY_INITIAL_DELAY;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if run.is_cancelled() {
                return Round::Stopped;
            }
            crate::info!("client reconnect attempt={attempt} reason={reason}");
            match self.try_reopen_session(run, attempt).await {
                r @ (Round::Opened | Round::Stopped) => return r,
                Round::Refused => {
                    crate::info!("client reconnect: the peer refused the handshake (reason={reason}) - waiting before another try");
                    return Round::Refused;
                }
                Round::Empty => {
                    crate::info!("client reconnect: nobody in the room answered or sent a frame (reason={reason})");
                    return Round::Empty;
                }
                Round::Silent => {}
            }
            if max_attempts > 0 && attempt >= max_attempts {
                crate::info!("client reconnect: exhausted {attempt} handshake attempts (reason={reason}) - pausing before the next try");
                return Round::Silent;
            }
            tokio::select! {
                () = run.cancelled() => return Round::Stopped,
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(RETRY_MAX_DELAY);
        }
    }

    /// `tryReopenSession`.
    async fn try_reopen_session(self: &Arc<Self>, run: &CancellationToken, attempt: u32) -> Round {
        let (lane, session, control) = match self.new_session() {
            Ok(x) => x,
            Err(e) => {
                crate::info!("smux re-init failed (attempt {attempt}): {e}");
                return Round::Silent;
            }
        };
        let close = |session: &Session| {
            let _ = session.close();
            if let Some(c) = &control {
                let _ = c.close();
            }
        };
        let hello_on = control.as_ref().unwrap_or(&session);
        let hello_remaining = self.hello_budget(DEFAULT_TIMEOUT, run).await;
        let opened =
            match hello::open_control_stream(hello_on, &self.device_id, hello_remaining, run).await
            {
                Ok(o) => o,
                Err(err) => {
                    let refused = err.refused();
                    let classified = self.classify(err, &lane);
                    if !run.is_cancelled() {
                        crate::info!(
                            "handshake on reconnect failed (attempt {attempt}): {classified}"
                        );
                    }
                    close(&session);
                    return if run.is_cancelled() {
                        Round::Stopped
                    } else if refused {
                        Round::Refused
                    } else if classified.kind == FailureKind::NoPeer {
                        Round::Empty
                    } else {
                        Round::Silent
                    };
                }
            };
        if let Err(e) = self.link.confirm_peer(&opened.welcome.peer_id).await {
            crate::info!("peer confirmation on reconnect failed (attempt {attempt}): {e}");
            close(&session);
            return Round::Silent;
        }
        if let Err(e) = self.link.wait_for_peer().await {
            crate::info!("wait for peer on reconnect failed (attempt {attempt}): {e}");
            close(&session);
            return Round::Silent;
        }
        if run.is_cancelled() {
            close(&session);
            return Round::Stopped;
        }
        let sid = opened.welcome.session_id.clone();
        crate::info!("session {sid} reopened (device={})", self.device_id);
        self.install(session, control, sid.clone(), opened.stream);
        self.notify_session_open(&sid);
        self.failed_rounds.store(0, Ordering::Relaxed);
        Round::Opened
    }

    /// `shutdown`: the control loop says goodbye, then everything closes.
    async fn shutdown(&self) {
        self.run.cancel();
        let done = {
            let mut s = self.sess();
            if let Some(stop) = s.control_stop.take() {
                stop.cancel();
            }
            s.control_done.take()
        };
        if let Some(done) = done {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, done).await;
        }
        let (lane, session) = {
            let mut s = self.sess();
            s.session_id.clear();
            if let Some(c) = s.control_session.take() {
                let _ = c.close();
            }
            (s.lane.take(), s.session.take())
        };
        if let Some(session) = session {
            let _ = session.close();
        }
        if let Some(lane) = lane {
            lane.close();
        }
        self.link.close().await;
    }

    /// Whether the IPv6 latch refuses IPv6 literals now (`noIPv6Route`).
    pub(crate) fn no_ipv6_route(&self) -> bool {
        let mut l = self.ipv6.lock().unwrap_or_else(PoisonError::into_inner);
        match l.until {
            None => false,
            Some(t) if Instant::now() < t => true,
            Some(_) => {
                *l = Ipv6Latch::default();
                false
            }
        }
    }

    /// `noteConnectFailure` for a host-unreachable ack.
    pub(crate) fn note_ipv6_unreachable(&self, target: &str) {
        let mut l = self.ipv6.lock().unwrap_or_else(PoisonError::into_inner);
        l.failures += 1;
        if l.failures < IPV6_FAILURES_BEFORE_LATCH {
            return;
        }
        if l.until.is_none() {
            crate::info!(
                "exit reports no IPv6 route ({IPV6_FAILURES_BEFORE_LATCH} unreachable literals, last {target}) - refusing IPv6 targets locally for {}m0s",
                IPV6_LATCH_WINDOW.as_secs() / 60
            );
        }
        l.until = Some(Instant::now() + IPV6_LATCH_WINDOW);
    }

    /// `noteConnectSuccess` for an IPv6 literal.
    pub(crate) fn note_ipv6_ok(&self) {
        *self.ipv6.lock().unwrap_or_else(PoisonError::into_inner) = Ipv6Latch::default();
    }
}

/// One parked request's slot, given back on drop.
struct Parked<'a>(&'a Inner);

impl Drop for Parked<'_> {
    fn drop(&mut self) {
        self.0.unpark();
    }
}

/// Why a request got no session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitRefused {
    /// Too many requests already wait: network unreachable.
    Saturated,
    /// None came in time: host unreachable.
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::{PipeLink, KIND_END};
    use crate::testhub::{self, TestHub};
    use crate::testing::bounded;
    use std::sync::Weak;

    /// Waits up to 2 s for every strong reference to go.
    async fn gone<T>(what: &str, weak: &Weak<T>) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while weak.strong_count() > 0 {
            assert!(
                Instant::now() < deadline,
                "{what} still held {} times after the run",
                weak.strong_count()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Starts a run on `url`; its state's and its link's `Weak`s.
    async fn start(
        url: &str,
        stop: &CancellationToken,
    ) -> (
        tokio::task::JoinHandle<Result<(), RunError>>,
        Weak<Inner>,
        Weak<PipeLink>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(Client::run_inner(
            testhub::config(url),
            stop.clone(),
            |_| {},
            None,
            move |inner| {
                let Link::Pipe(link) = &inner.link else {
                    panic!("the test hub's run is on the interop pipe");
                };
                let _ = tx.send((Arc::downgrade(inner), Arc::downgrade(link)));
            },
        ));
        let (inner, link) = rx.await.unwrap();
        (run, inner, link)
    }

    #[tokio::test]
    async fn a_run_the_conference_ended_leaves_nothing_behind() {
        bounded(async {
            let (hub, url) = TestHub::start("leak-end").await;
            let stop = CancellationToken::new();
            let (run, inner, link) = start(&url, &stop).await;
            let mut m = hub.accept().await;
            m.send(KIND_END, b"over").await.unwrap();
            assert!(run.await.unwrap().is_err(), "the hello cannot win");
            gone("the run's state", &inner).await;
            gone("the link", &link).await;
        })
        .await;
    }

    #[tokio::test]
    async fn a_stopped_run_leaves_nothing_behind() {
        bounded(async {
            let (hub, url) = TestHub::start("leak-stop").await;
            let stop = CancellationToken::new();
            let (run, inner, link) = start(&url, &stop).await;
            let _m = hub.accept().await;
            stop.cancel();
            assert!(run.await.unwrap().is_err());
            gone("the run's state", &inner).await;
            gone("the link", &link).await;
        })
        .await;
    }

    #[tokio::test]
    async fn an_abandoned_wait_gives_its_park_slot_back() {
        bounded(async {
            let (hub, url) = TestHub::start("park").await;
            let stop = CancellationToken::new();
            let (run, inner, _) = start(&url, &stop).await;
            let _m = hub.accept().await;
            let me = inner.upgrade().unwrap();
            // A sniffed direct name aborts the tunnel's preparation while it
            // waits for a session (direct.rs sniff_then_route).
            let waiter = {
                let me = me.clone();
                tokio::spawn(async move {
                    let _ = me.wait_session().await;
                })
            };
            while me.parked.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            waiter.abort();
            let _ = waiter.await;
            assert_eq!(me.parked.load(Ordering::Relaxed), 0);
            drop(me);
            stop.cancel();
            let _ = run.await;
        })
        .await;
    }

    #[tokio::test]
    async fn the_first_hello_waits_for_the_peer_to_settle_in_the_room() {
        bounded(async {
            let (hub, url) = TestHub::start("settle").await;
            let stop = CancellationToken::new();
            let (run, _, _) = start(&url, &stop).await;
            let mut m = hub.accept().await;
            // Nobody else is in the room: a hello now reaches nobody, and
            // Go's is lost to its first resend, 2 s on.
            let early = tokio::time::timeout(Duration::from_millis(300), m.read()).await;
            assert!(early.is_err(), "a frame went into an empty room: {early:?}");
            let came = Instant::now();
            m.send(crate::pipe::KIND_PEERS, &1u16.to_be_bytes())
                .await
                .unwrap();
            let (kind, _) = m.read().await.unwrap();
            let after = came.elapsed();
            assert_eq!(kind, crate::pipe::KIND_DATA);
            assert!(
                after >= Duration::from_millis(5) && after < Duration::from_secs(1),
                "the first hello went {after:?} after the peer came"
            );
            stop.cancel();
            let _ = run.await;
        })
        .await;
    }

    #[test]
    fn a_close_from_the_peer_is_peer_close_and_any_other_end_liveness() {
        assert_eq!(death_reason(&End::ClosedByPeer), "peer-close");
        assert_eq!(
            death_reason(&End::Failed("control: EOF".into())),
            "liveness"
        );
        assert_eq!(
            death_reason(&End::Unhealthy("control stream unhealthy".into())),
            "liveness"
        );
    }

    #[test]
    fn a_device_id_is_a_v4_uuid() {
        let id = random_device_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"), "{id}");
    }

    #[test]
    fn the_classified_texts_are_gos() {
        let c = Classified {
            kind: FailureKind::NoPeer,
            err: HelloError::Timeout,
        };
        assert_eq!(
            c.to_string(),
            "no peer in room: handshake client: read welcome: read hdr: timeout"
        );
        let open = Classified {
            kind: FailureKind::Other,
            err: HelloError::Open("timeout".into()),
        };
        assert_eq!(open.to_string(), "open control stream: timeout");
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SaluteJazz session (salutejazz.go, signaling.go, media.go, data.go,
//! window.go at 2d4266af): one [`Link`] over a sequence of generations,
//! each a connector WebSocket, a subscriber peer connection the SFU offers
//! and a publisher peer connection this side offers. A reconnect tears the
//! generation down and joins again.
//!
//! # Tasks per generation
//!
//! - the signalling reader (`readLoop`), the keepalive (`pingLoop`) and the
//!   publisher's negotiation (`negotiate`);
//! - one event loop per peer connection: the subscriber's delivers each
//!   message to the client in channel order and answers relay-window marks
//!   behind them, so a mark is echoed only once what came before it has been
//!   taken (Go's blocking `OnMessage`).
//!
//! # Memory
//!
//! Beyond each peer's own ([`olc_rtc::peer`]): the publisher's SCTP send
//! buffer [`PUB_SCTP_BUFFERED`], the WebSocket's message buffer
//! ([`WS_READ_LIMIT`] at most, grown as messages need), the candidates
//! queued before a remote description ([`MAX_PENDING_ICE`] per peer), the
//! roster's departed set ([`LEFT_KEPT`]) and the relay window's per-peer
//! state ([`crate::relaywin`]).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use olc_net::link::{DataSink, DatagramSink, LinkEvent};
use olc_net::stream::BoxStream;
use olc_net::ws;
use olc_rtc::peer::{IceConnectionState, Peer, PeerConfig, PeerEvent};
use olc_rtc::str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use olc_rtc::str0m::channel::{ChannelConfig, ChannelId, Reliability};
use olc_rtc::str0m::Candidate;
use olc_rtc::{CryptoProvider, DtlsVersion};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

use crate::lk;
use crate::relaywin::{Timing, Windows};
use crate::wire::{self, event, method, TARGET_PUBLISHER, TARGET_SUBSCRIBER};

/// `labelReliable`.
pub const LABEL_RELIABLE: &str = "_reliable";
/// `labelLossy`.
pub const LABEL_LOSSY: &str = "_lossy";

/// `webOrigin`.
pub const WEB_ORIGIN: &str = "https://salutejazz.ru";
/// `webUserAgent`.
pub const WEB_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

/// `wsHandshakeTimeout`.
pub const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// `wsWriteTimeout`.
pub const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// `wsReadTimeout`: the connector pongs every 5 s ping, so 25 s of silence
/// is a dead socket.
pub const WS_READ_TIMEOUT: Duration = Duration::from_secs(25);
/// `wsReadLimit`: the largest connector message (an SDP with every
/// candidate, a roster), 8 MiB; the buffer grows to what a message needs.
pub const WS_READ_LIMIT: usize = 8 << 20;
/// `pingInterval`.
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
/// `pongTimeout`.
pub const PONG_TIMEOUT: Duration = Duration::from_secs(15);
/// `answerTimeout`.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);
/// `joinTimeout`.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
/// `maxReconnects` within [`RECONNECT_WINDOW`].
pub const MAX_RECONNECTS: u32 = 10;
/// `reconnectFailureWindow`: the reconnect count starts again after this
/// long without a request.
pub const RECONNECT_WINDOW: Duration = Duration::from_secs(5 * 60);
/// `reconnectBackoffStep`: the n-th attempt in a window waits n × this.
pub const RECONNECT_STEP: Duration = Duration::from_secs(2);
/// `reconnectBackoffMax`.
pub const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// `peerPollInterval`.
pub const PEER_POLL: Duration = Duration::from_millis(50);
/// How long an ICE path may stay disconnected before the peer connection
/// counts as failed: pion's `ICEFailedTimeout` (25 s), the state change that
/// makes the engine reconnect (`onPeerConnectionState`).
pub const ICE_FAILED_AFTER: Duration = Duration::from_secs(25);

/// `bufferHighWaterMark`: what a publisher lane may hold unacknowledged
/// before a reliable send waits and a lossy one is dropped, 512 KiB.
pub const HIGH_WATER: usize = 512 * 1024;
/// The publisher's SCTP send buffer, both lanes together (str0m counts one
/// budget for all channels): each lane at [`HIGH_WATER`] plus one message
/// over it (a record of at most 12 KiB with its DataPacket, under 16 KiB),
/// so a send the high-water check let through always fits.
pub const PUB_SCTP_BUFFERED: usize = 2 * (HIGH_WATER + (16 << 10));
/// The subscriber's: it sends nothing but SCTP's own control, so str0m's
/// default (128 KiB, allocated only as used).
pub const SUB_SCTP_BUFFERED: usize = 128 << 10;
/// `datagramSlack`: how far over its relay window a destination may be
/// before datagrams to it are dropped.
pub const DATAGRAM_SLACK: u64 = 64 << 10;
/// `lossyDropLogEvery`.
const LOSSY_DROP_LOG_EVERY: u64 = 100;
/// Candidates kept per peer connection before its remote description: an
/// SFU trickles one per address family and transport (LiveKit: a handful);
/// beyond this they are dropped (Go keeps every one).
pub const MAX_PENDING_ICE: usize = 32;
/// Departed identities remembered per generation (Go keeps every one): a
/// room's churn in one generation's life; the oldest goes first.
pub const LEFT_KEPT: usize = 256;
/// `windowMarksKept`.
const WINDOW_MARKS_KEPT: usize = 64;
/// `windowReportEvery`.
const WINDOW_REPORT_EVERY: Duration = Duration::from_secs(5);

/// The relay window's frame (`windowFrame`): version, kind, counter, the
/// window the sender runs: `[1][kind][u64 BE][u32 BE]`, 14 bytes.
const WINDOW_VERSION: u8 = 1;
const WINDOW_MARK: u8 = 1;
const WINDOW_ECHO: u8 = 2;
const WINDOW_FRAME_LEN: usize = 1 + 1 + 8 + 4;
/// `relayWindow`, the window this side announces: 192 KiB.
pub const RELAY_WINDOW: u64 = 192 << 10;
/// `relayMarkEvery`.
pub const RELAY_MARK_EVERY: u64 = RELAY_WINDOW / 8;
/// `relayHorizon`.
pub const RELAY_HORIZON: Duration = Duration::from_secs(3);
/// `relayProbeAfter`.
pub const RELAY_PROBE_AFTER: Duration = Duration::from_secs(1);
/// `relayRetry`.
pub const RELAY_RETRY: Duration = Duration::from_millis(250);
/// `relayDeadAfter`.
pub const RELAY_DEAD_AFTER: Duration = Duration::from_secs(120);

/// `defaultRelayTiming`.
#[must_use]
pub fn relay_timing() -> Timing {
    Timing {
        window: RELAY_WINDOW,
        mark_every: RELAY_MARK_EVERY,
        probe_after: RELAY_PROBE_AFTER,
        dead_after: RELAY_DEAD_AFTER,
        retry: RELAY_RETRY,
        horizon: RELAY_HORIZON,
        min_window: crate::relaywin::DEFAULT_MIN_WINDOW,
    }
}

fn window_frame(kind: u8, counter: u64) -> [u8; WINDOW_FRAME_LEN] {
    let mut f = [0u8; WINDOW_FRAME_LEN];
    f[0] = WINDOW_VERSION;
    f[1] = kind;
    f[2..10].copy_from_slice(&counter.to_be_bytes());
    f[10..].copy_from_slice(
        &u32::try_from(RELAY_WINDOW)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    f
}

fn parse_window_frame(f: &[u8]) -> Option<(u8, u64)> {
    if f.len() != WINDOW_FRAME_LEN
        || f[0] != WINDOW_VERSION
        || !matches!(f[1], WINDOW_MARK | WINDOW_ECHO)
    {
        return None;
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(&f[2..10]);
    Some((f[1], u64::from_be_bytes(c)))
}

/// The engine's errors, with Go's words.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `ErrURLRequired`.
    #[error("salutejazz connector URL required")]
    UrlRequired,
    /// `ErrRoomIDRequired`.
    #[error("salutejazz room code required")]
    RoomIdRequired,
    /// `ErrPasswordRequired`.
    #[error("salutejazz room password required")]
    PasswordRequired,
    /// `ErrWebSocketClosed`.
    #[error("salutejazz signaling websocket closed")]
    WebSocketClosed,
    /// `ErrSessionClosed`.
    #[error("salutejazz session closed")]
    SessionClosed,
    /// `ErrJoinTimeout`.
    #[error("salutejazz join timeout")]
    JoinTimeout,
    /// `ErrPongTimeout`.
    #[error("salutejazz ping was not answered")]
    PongTimeout,
    /// `ErrNoAnswer`.
    #[error("salutejazz publisher offer was not answered")]
    NoAnswer,
    /// `ErrNoDescription`.
    #[error("salutejazz description missing")]
    NoDescription,
    /// `ErrNoDataChannel`.
    #[error("salutejazz data channel not ready")]
    NoDataChannel,
    /// `ErrDestinationEnded`.
    #[error("salutejazz destination's session ended while the send was held")]
    DestinationEnded,
    /// `engine.ErrInvalidPeerID`.
    #[error("invalid peer id: empty identity")]
    InvalidPeerId,
    /// The dial (`salutejazz dial connector: ...`).
    #[error("salutejazz dial connector: {0}")]
    Dial(String),
    /// A malformed room reference (`auth.ErrRoomIDRequired: ...`); it never
    /// carries the reference.
    #[error("room ID required: {0}")]
    RoomRef(String),
    /// The auth provider's preconnect.
    #[error("{0}")]
    Auth(String),
    /// Anything else, worded.
    #[error("{0}")]
    Other(String),
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match e {
            Error::SessionClosed | Error::WebSocketClosed => io::ErrorKind::BrokenPipe,
            Error::NoDataChannel => io::ErrorKind::NotConnected,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e.to_string())
    }
}

/// What the engine joins with (`engine.Config` after the auth provider):
/// the connector, the room's code and password, the display name. Its
/// `Debug` leaves the password out.
#[derive(Clone)]
pub struct Config {
    /// The connector's WebSocket URL (`cfg.URL`).
    pub url: String,
    /// The room code (`Extra["roomID"]`).
    pub room_id: String,
    /// The room's password (`cfg.Token`).
    pub password: String,
    /// The display name (`cfg.Name`, `names.Generate()` in Go).
    pub name: String,
    /// The host candidates' address; the default route's when `None`.
    pub host_ip: Option<IpAddr>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("url", &self.url)
            .field("room_id", &self.room_id)
            .field("name", &self.name)
            .field("host_ip", &self.host_ip)
            .finish_non_exhaustive()
    }
}

/// A SaluteJazz link: the engine session the client's lanes run over.
pub struct Link {
    sh: Arc<Shared>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("room", &self.sh.cfg.room_id.len())
            .finish_non_exhaustive()
    }
}

struct Shared {
    cfg: Config,
    host_ip: IpAddr,
    crypto: Arc<CryptoProvider>,
    events: mpsc::Sender<LinkEvent>,
    data: RwLock<Option<Arc<dyn DataSink>>>,
    datagram: RwLock<Option<DatagramSink>>,
    cur: Mutex<Option<Arc<Gen>>>,
    /// `s.server`: the identity confirmed last, across generations.
    server: Mutex<String>,
    closed: AtomicBool,
    terminated: AtomicBool,
    ended: AtomicBool,
    reconnecting: AtomicBool,
    requests: mpsc::Sender<()>,
    stop: CancellationToken,
    /// A generation's lanes opened or went (for [`Link::wait_ready`]).
    lanes: Notify,
}

#[derive(Default)]
struct Roster {
    peers: HashMap<String, String>,
    left: VecDeque<String>,
}

impl Roster {
    fn has_left(&self, id: &str) -> bool {
        self.left.iter().any(|l| l == id)
    }

    fn depart(&mut self, id: &str) {
        self.peers.remove(id);
        if !self.has_left(id) {
            if self.left.len() >= LEFT_KEPT {
                self.left.pop_front();
            }
            self.left.push_back(id.to_owned());
        }
    }
}

struct Publisher {
    peer: Peer,
    rel: ChannelId,
    lossy: ChannelId,
}

struct RelayPeer {
    ordinal: u32,
    speaks: bool,
    marks: VecDeque<(u64, Instant)>,
    rtt: Duration,
    since: Option<Instant>,
    echoed: u64,
    delivered: u64,
}

struct Gen {
    done: CancellationToken,
    ws: Mutex<Option<ws::Writer<BoxStream>>>,
    group: Mutex<String>,
    join_req: Mutex<String>,
    identity: Mutex<String>,
    sub: Mutex<Option<Peer>>,
    publ: Mutex<Option<Publisher>>,
    pending_pub: Mutex<Option<SdpPendingOffer>>,
    answer: Mutex<Option<oneshot::Sender<String>>>,
    rel_open: AtomicBool,
    lossy_open: AtomicBool,
    sub_ready: Notify,
    sub_open: AtomicBool,
    pub_ready: Notify,
    ice: Mutex<HashMap<&'static str, Vec<Candidate>>>,
    ice_servers: Mutex<Vec<wire::IceServer>>,
    roster: Mutex<Roster>,
    confirmed: Mutex<String>,
    win: Mutex<Windows>,
    relay_peers: Mutex<(u32, HashMap<String, RelayPeer>)>,
    pongs: Mutex<HashMap<i64, oneshot::Sender<()>>>,
    rtt: AtomicI64,
    lossy_drops: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Gen {
    fn new() -> Gen {
        Gen {
            done: CancellationToken::new(),
            ws: Mutex::new(None),
            group: Mutex::default(),
            join_req: Mutex::default(),
            identity: Mutex::default(),
            sub: Mutex::new(None),
            publ: Mutex::new(None),
            pending_pub: Mutex::new(None),
            answer: Mutex::new(None),
            rel_open: AtomicBool::new(false),
            lossy_open: AtomicBool::new(false),
            sub_ready: Notify::new(),
            sub_open: AtomicBool::new(false),
            pub_ready: Notify::new(),
            ice: Mutex::default(),
            ice_servers: Mutex::default(),
            roster: Mutex::default(),
            confirmed: Mutex::default(),
            win: Mutex::new(Windows::new(relay_timing())),
            relay_peers: Mutex::new((0, HashMap::new())),
            pongs: Mutex::default(),
            rtt: AtomicI64::new(0),
            lossy_drops: AtomicU64::new(0),
        }
    }

    fn is_done(&self) -> bool {
        self.done.is_cancelled()
    }

    fn local_identity(&self) -> String {
        lock(&self.identity).clone()
    }

    fn in_room(&self, id: &str) -> bool {
        lock(&self.roster).peers.contains_key(id)
    }

    fn has_left(&self, id: &str) -> bool {
        lock(&self.roster).has_left(id)
    }

    fn has_remote(&self) -> bool {
        !lock(&self.roster).peers.is_empty()
    }

    fn note_peer(&self, id: &str) {
        if id.is_empty() || *lock(&self.identity) == id {
            return;
        }
        let mut r = lock(&self.roster);
        if !r.peers.contains_key(id) && !r.has_left(id) {
            r.peers.insert(id.to_owned(), String::new());
        }
    }

    fn apply_participants(&self, list: &[wire::Participant]) {
        let local = self.local_identity();
        let mut gone = Vec::new();
        {
            let mut r = lock(&self.roster);
            for p in list {
                if p.identity.is_empty() || p.identity == local {
                    continue;
                }
                if p.state == "DISCONNECTED" {
                    r.depart(&p.identity);
                    gone.push(p.identity.clone());
                    continue;
                }
                if r.has_left(&p.identity) {
                    continue;
                }
                r.peers.insert(p.identity.clone(), p.sid.clone());
            }
        }
        for id in gone {
            self.forget_relay_peer(&id);
        }
    }

    fn forget_relay_peer(&self, id: &str) {
        lock(&self.win).reset(id);
        lock(&self.relay_peers).1.remove(id);
    }

    /// `roomDest`.
    fn room_dest(&self, dest: Vec<String>) -> Vec<String> {
        if !dest.is_empty() {
            return dest;
        }
        let bound = lock(&self.confirmed).clone();
        if bound.is_empty() || !self.in_room(&bound) {
            return Vec::new();
        }
        vec![bound]
    }

    /// `windowKey`.
    fn window_key(&self, dest: &[String]) -> String {
        match dest {
            [one] if !self.has_left(one) => one.clone(),
            _ => String::new(),
        }
    }

    fn relay_peer<'a>(
        state: &'a mut (u32, HashMap<String, RelayPeer>),
        id: &str,
    ) -> &'a mut RelayPeer {
        let (seq, peers) = state;
        peers.entry(id.to_owned()).or_insert_with(|| {
            *seq += 1;
            RelayPeer {
                ordinal: *seq,
                speaks: false,
                marks: VecDeque::new(),
                rtt: Duration::ZERO,
                since: None,
                echoed: 0,
                delivered: 0,
            }
        })
    }

    /// `noteSpeaker`.
    fn note_speaker(&self, id: &str) -> bool {
        let mut st = lock(&self.relay_peers);
        let p = Self::relay_peer(&mut st, id);
        if p.speaks {
            return false;
        }
        p.speaks = true;
        olc_net::debug!("salutejazz: peer {} speaks the relay window", p.ordinal);
        true
    }

    /// `marks`.
    fn marks(&self, key: &str) -> bool {
        if *lock(&self.confirmed) == key {
            return true;
        }
        lock(&self.relay_peers).1.get(key).is_some_and(|p| p.speaks)
    }

    /// `noteMark`.
    fn note_mark(&self, key: &str, counter: u64, now: Instant) {
        let mut st = lock(&self.relay_peers);
        let p = Self::relay_peer(&mut st, key);
        if p.marks.len() >= WINDOW_MARKS_KEPT {
            p.marks.pop_front();
        }
        p.marks.push_back((counter, now));
    }

    /// `noteEcho`.
    fn note_echo(&self, key: &str, counter: u64, turned_on: bool, now: Instant) {
        let size = lock(&self.win).size(key);
        let mut st = lock(&self.relay_peers);
        let p = Self::relay_peer(&mut st, key);
        if turned_on {
            olc_net::debug!(
                "salutejazz: peer {} echoes marks - relay window on",
                p.ordinal
            );
        }
        while let Some(&(c, at)) = p.marks.front() {
            if c > counter {
                break;
            }
            if c == counter {
                p.rtt = now.saturating_duration_since(at);
            }
            p.marks.pop_front();
        }
        let Some(since) = p.since else {
            p.since = Some(now);
            p.echoed = counter;
            return;
        };
        p.delivered = p.delivered.wrapping_add(counter.wrapping_sub(p.echoed));
        p.echoed = counter;
        let elapsed = now.saturating_duration_since(since);
        if elapsed >= WINDOW_REPORT_EVERY {
            #[allow(clippy::cast_precision_loss)]
            let rate = p.delivered as f64 / elapsed.as_secs_f64() / 1000.0;
            olc_net::debug!(
                "salutejazz: relay window to peer {}: {rate:.1} kB/s delivered, echo rtt {}ms, window {} KiB",
                p.ordinal,
                p.rtt.as_millis(),
                size >> 10
            );
            p.since = Some(now);
            p.delivered = 0;
        }
    }

    fn drop_lossy(&self) {
        let n = self.lossy_drops.fetch_add(1, Ordering::Relaxed) + 1;
        if n % LOSSY_DROP_LOG_EVERY == 1 {
            olc_net::debug!("salutejazz: the lossy lane or a relay window is over its budget, {n} datagrams dropped");
        }
    }

    fn publisher(&self) -> Option<(Peer, ChannelId, ChannelId)> {
        lock(&self.publ)
            .as_ref()
            .map(|p| (p.peer.clone(), p.rel, p.lossy))
    }
}

fn uuid4() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl Link {
    /// `New` and `Connect`: joins the room and returns once the publisher's
    /// reliable lane is open; the reconnect watcher runs from then on and
    /// reports to `events`.
    ///
    /// # Errors
    /// A missing setting, the dial, the join's refusal or its timeout.
    pub async fn connect(cfg: Config, events: mpsc::Sender<LinkEvent>) -> Result<Arc<Link>, Error> {
        if cfg.url.is_empty() {
            return Err(Error::UrlRequired);
        }
        if cfg.password.is_empty() {
            return Err(Error::PasswordRequired);
        }
        if cfg.room_id.is_empty() {
            return Err(Error::RoomIdRequired);
        }
        olc_rtc::init();
        let host_ip = match cfg.host_ip {
            Some(ip) => ip,
            None => olc_rtc::ice::default_ipv4()
                .map_err(|e| Error::Other(format!("salutejazz local address: {e}")))?,
        };
        let (req_tx, req_rx) = mpsc::channel(1);
        let sh = Arc::new(Shared {
            cfg,
            host_ip,
            crypto: olc_rtc::crypto(),
            events,
            data: RwLock::new(None),
            datagram: RwLock::new(None),
            cur: Mutex::new(None),
            server: Mutex::default(),
            closed: AtomicBool::new(false),
            terminated: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            reconnecting: AtomicBool::new(false),
            requests: req_tx,
            stop: CancellationToken::new(),
            lanes: Notify::new(),
        });
        if let Err(e) = sh.connect_gen().await {
            sh.terminate();
            return Err(e);
        }
        tokio::spawn(watch(sh.clone(), req_rx));
        Ok(Arc::new(Link { sh }))
    }

    /// Where reliable messages go (`OnData`).
    pub fn set_data(&self, sink: Option<Arc<dyn DataSink>>) {
        *self.sh.data.write().unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// Where datagrams go (`OnDatagram`).
    pub fn set_datagram(&self, sink: Option<DatagramSink>) {
        *self
            .sh
            .datagram
            .write()
            .unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// This side's identity in the room (`LocalPeerID`).
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        self.sh
            .current()
            .map(|g| g.local_identity())
            .unwrap_or_default()
    }

    /// `PeerSeen`: the confirmed server is in the room.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        let server = lock(&self.sh.server).clone();
        match self.sh.current() {
            Some(g) if !server.is_empty() && !g.is_done() => g.in_room(&server),
            _ => false,
        }
    }

    /// `CanSend`: the reliable lane is open and under its high water.
    #[must_use]
    pub fn can_send(&self) -> bool {
        !self.sh.closed.load(Ordering::Acquire) && self.sh.lane_ready(true)
    }

    /// Waits up to `timeout` for [`Link::can_send`].
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        let until = tokio::time::Instant::now() + timeout;
        loop {
            let lanes = self.sh.lanes.notified();
            if self.can_send() {
                return true;
            }
            if self.sh.closed.load(Ordering::Acquire) {
                return false;
            }
            let pubr = self
                .sh
                .current()
                .filter(|g| !g.is_done())
                .and_then(|g| g.publisher());
            tokio::select! {
                () = lanes => {}
                () = async {
                    match pubr {
                        Some((peer, rel, _)) => { let _ = peer.wait_buffered(rel, HIGH_WATER).await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
                () = tokio::time::sleep_until(until) => return self.can_send(),
                () = self.sh.stop.cancelled() => return false,
            }
        }
    }

    /// `Send`: one message on the reliable lane to the confirmed server.
    ///
    /// # Errors
    /// No open lane, a closed session, the destination gone while held.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        self.sh
            .publish(data, None, Vec::new(), true)
            .await
            .map_err(io::Error::from)
    }

    /// `SendDatagram`: one message on the lossy lane; dropped, not failed,
    /// over budget.
    ///
    /// # Errors
    /// No open lane, a closed session.
    pub async fn send_datagram(&self, data: &[u8]) -> io::Result<()> {
        self.sh
            .publish(data, Some(lk::DATAGRAM_TOPIC), Vec::new(), false)
            .await
            .map_err(io::Error::from)
    }

    /// `ConfirmPeer`: sends go to `peer_id` from now on, and it gets a first
    /// window mark.
    ///
    /// # Errors
    /// An empty id or a closed session.
    pub async fn confirm_peer(&self, peer_id: &str) -> Result<(), Error> {
        if peer_id.is_empty() {
            return Err(Error::InvalidPeerId);
        }
        let gen = self
            .sh
            .current()
            .filter(|g| !g.is_done())
            .ok_or(Error::SessionClosed)?;
        let old = std::mem::replace(&mut *lock(&gen.confirmed), peer_id.to_owned());
        if !old.is_empty() && old != peer_id {
            gen.forget_relay_peer(&old);
        }
        peer_id.clone_into(&mut lock(&self.sh.server));
        send_window_frame(&gen, peer_id, WINDOW_MARK, 0);
        Ok(())
    }

    /// `ResetPeer`.
    pub fn reset_peer(&self) {
        if let Some(gen) = self.sh.current() {
            let old = std::mem::take(&mut *lock(&gen.confirmed));
            if !old.is_empty() {
                gen.forget_relay_peer(&old);
            }
        }
    }

    /// `WaitForPeer`: until a peer is confirmed or anyone else is in the
    /// room, polled every [`PEER_POLL`].
    ///
    /// # Errors
    /// The timeout (`salutejazz wait for peer: ...`) or a closed session.
    pub async fn wait_for_peer(&self, timeout: Duration) -> Result<(), Error> {
        let until = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(g) = self.sh.current() {
                if !lock(&g.confirmed).is_empty() || g.has_remote() {
                    return Ok(());
                }
            }
            if self.sh.closed.load(Ordering::Acquire) && self.sh.terminated.load(Ordering::Acquire)
            {
                return Err(Error::SessionClosed);
            }
            if tokio::time::Instant::now() >= until {
                return Err(Error::Other(
                    "salutejazz wait for peer: context deadline exceeded".into(),
                ));
            }
            tokio::select! {
                () = tokio::time::sleep(PEER_POLL) => {}
                () = self.sh.stop.cancelled() => return Err(Error::SessionClosed),
            }
        }
    }

    /// `Reconnect`: asks the watcher for a fresh generation.
    pub fn reconnect(&self, reason: &str) {
        if self.sh.closed.load(Ordering::Acquire) {
            return;
        }
        olc_net::info!("salutejazz: reconnect requested: {reason}");
        self.sh.queue_reconnect();
    }

    /// `Close`: leaves the room and stops everything.
    pub async fn close(&self) {
        let gen = self.sh.terminate();
        if let Some(gen) = gen {
            teardown(&gen).await;
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        if let Some(gen) = self.sh.terminate() {
            gen.done.cancel();
        }
    }
}

impl Shared {
    fn current(&self) -> Option<Arc<Gen>> {
        lock(&self.cur).clone()
    }

    fn lane_ready(&self, reliable: bool) -> bool {
        let Some(gen) = self.current().filter(|g| !g.is_done()) else {
            return false;
        };
        let open = if reliable {
            &gen.rel_open
        } else {
            &gen.lossy_open
        };
        if !open.load(Ordering::Acquire) {
            return false;
        }
        let Some((peer, rel, lossy)) = gen.publisher() else {
            return false;
        };
        peer.buffered_amount(if reliable { rel } else { lossy })
            .is_some_and(|n| n <= HIGH_WATER)
    }

    fn terminate(&self) -> Option<Arc<Gen>> {
        self.terminated.store(true, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        self.stop.cancel();
        self.lanes.notify_waiters();
        lock(&self.cur).take()
    }

    /// `queueReconnect`: coalesced into one pending request.
    fn queue_reconnect(&self) {
        if self.closed.load(Ordering::Acquire) || self.reconnecting.load(Ordering::Acquire) {
            return;
        }
        let _ = self.requests.try_send(());
    }

    fn reconnect_attempt(&self, gen: &Gen) {
        if self.closed.load(Ordering::Acquire) || gen.is_done() {
            return;
        }
        self.queue_reconnect();
    }

    fn signal_ended(&self, reason: &str) {
        if self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        self.closed.store(true, Ordering::Release);
        self.stop.cancel();
        olc_net::info!("salutejazz: session ended: {reason}");
        let _ = self.events.try_send(LinkEvent::Ended(reason.to_owned()));
    }

    async fn send_envelope<P: Serialize>(
        &self,
        gen: &Gen,
        ev: &str,
        payload: &P,
        request_id: &str,
    ) -> Result<(), Error> {
        let group = lock(&gen.group).clone();
        let env = wire::EnvOut {
            room_id: &self.cfg.room_id,
            payload,
            event: ev,
            group_id: &group,
            request_id,
        };
        let text = serde_json::to_string(&env)
            .map_err(|e| Error::Other(format!("salutejazz marshal {ev} payload: {e}")))?;
        let writer = lock(&gen.ws).clone().ok_or(Error::WebSocketClosed)?;
        match tokio::time::timeout(WS_WRITE_TIMEOUT, writer.send_text(&text)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::Other(format!("salutejazz ws write: {e}"))),
            Err(_) => Err(Error::Other("salutejazz ws write: i/o timeout".into())),
        }
    }

    async fn send_media(&self, gen: &Gen, m: &wire::MediaIn<'_>) -> Result<(), Error> {
        self.send_envelope(gen, event::MEDIA_IN, m, &uuid4()).await
    }

    /// `Connect` for one generation.
    async fn connect_gen(self: &Arc<Self>) -> Result<(), Error> {
        let gen = Arc::new(Gen::new());
        {
            if self.terminated.load(Ordering::Acquire) || self.ended.load(Ordering::Acquire) {
                return Err(Error::SessionClosed);
            }
            self.closed.store(false, Ordering::Release);
            let old = lock(&self.cur).replace(gen.clone());
            if let Some(old) = old {
                teardown(&old).await;
            }
        }
        let reader = match dial(&self.cfg.url).await {
            Ok((reader, writer)) => {
                *lock(&gen.ws) = Some(writer);
                reader
            }
            Err(e) => {
                self.abandon(&gen).await;
                return Err(e);
            }
        };
        tokio::spawn(read_loop(self.clone(), gen.clone(), reader));
        tokio::spawn(ping_loop(self.clone(), gen.clone()));
        tokio::spawn(negotiate(self.clone(), gen.clone()));
        let join_id = uuid4();
        join_id.clone_into(&mut lock(&gen.join_req));
        let join = wire::JoinRequest {
            password: &self.cfg.password,
            participant_name: &self.cfg.name,
            supported_features: wire::SupportedFeatures {
                attached_rooms: true,
                session_groups: true,
                transcription: true,
                interpretation: true,
            },
            is_silent: false,
        };
        if let Err(e) = self.send_envelope(&gen, event::JOIN, &join, &join_id).await {
            self.abandon(&gen).await;
            return Err(e);
        }
        let ready = gen.pub_ready.notified();
        let waited = if gen.rel_open.load(Ordering::Acquire) {
            Ok(())
        } else {
            tokio::select! {
                () = ready => Ok(()),
                () = gen.done.cancelled() => Err(Error::SessionClosed),
                () = tokio::time::sleep(JOIN_TIMEOUT) => Err(Error::JoinTimeout),
                () = self.stop.cancelled() => Err(Error::SessionClosed),
            }
        };
        if let Err(e) = waited {
            self.abandon(&gen).await;
            return Err(e);
        }
        if self.terminated.load(Ordering::Acquire) {
            self.abandon(&gen).await;
            return Err(Error::SessionClosed);
        }
        Ok(())
    }

    async fn abandon(&self, gen: &Arc<Gen>) {
        teardown(gen).await;
        let mut cur = lock(&self.cur);
        if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, gen)) {
            *cur = None;
        }
    }

    /// `publish`.
    async fn publish(
        &self,
        payload: &[u8],
        topic: Option<&str>,
        dest: Vec<String>,
        reliable: bool,
    ) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::SessionClosed);
        }
        let gen = self
            .current()
            .filter(|g| !g.is_done())
            .ok_or(Error::NoDataChannel)?;
        let open = if reliable {
            &gen.rel_open
        } else {
            &gen.lossy_open
        };
        let (peer, rel, lossy) = gen.publisher().ok_or(Error::NoDataChannel)?;
        if !open.load(Ordering::Acquire) {
            return Err(Error::NoDataChannel);
        }
        let chan = if reliable { rel } else { lossy };
        let dest = gen.room_dest(dest);
        let key = gen.window_key(&dest);
        if reliable {
            let epoch = if key.is_empty() {
                0
            } else {
                lock(&gen.win).epoch(&key)
            };
            // awaitSendWindow
            loop {
                match peer.buffered_amount(chan) {
                    Some(n) if n <= HIGH_WATER => break,
                    Some(_) => {}
                    None => return Err(Error::NoDataChannel),
                }
                tokio::select! {
                    r = peer.wait_buffered(chan, HIGH_WATER) => if r.is_err() { return Err(Error::SessionClosed) },
                    () = gen.done.cancelled() => return Err(Error::SessionClosed),
                    () = self.stop.cancelled() => return Err(Error::SessionClosed),
                }
            }
            self.await_relay_window(&gen, &key, epoch).await?;
        } else {
            let over = peer.buffered_amount(chan).is_none_or(|n| n > HIGH_WATER)
                || (!key.is_empty() && lock(&gen.win).over(&key, DATAGRAM_SLACK, Instant::now()));
            if over {
                gen.drop_lossy();
                return Ok(());
            }
        }
        let frame = lk::encode(payload, topic, &dest, reliable);
        loop {
            match peer.write(chan, true, &frame) {
                Ok(true) => break,
                Ok(false) if !reliable => {
                    gen.drop_lossy();
                    return Ok(());
                }
                Ok(false) => tokio::select! {
                    () = peer.progressed() => {}
                    () = gen.done.cancelled() => return Err(Error::SessionClosed),
                },
                Err(e) => return Err(Error::Other(format!("salutejazz data channel send: {e}"))),
            }
        }
        if !key.is_empty() {
            let (due, counter) = lock(&gen.win).sent(&key, frame.len(), Instant::now());
            if due {
                mark_relay(&gen, &key, counter);
            }
        }
        Ok(())
    }

    /// `awaitRelayWindow`.
    async fn await_relay_window(&self, gen: &Gen, key: &str, epoch: u64) -> Result<(), Error> {
        if key.is_empty() {
            return Ok(());
        }
        loop {
            if gen.is_done() || self.closed.load(Ordering::Acquire) {
                return Err(Error::SessionClosed);
            }
            if gen.has_left(key) {
                return Err(self.closed_or(gen, Error::DestinationEnded));
            }
            let (wake, answer) = {
                let mut win = lock(&gen.win);
                let wake = win.wake(key);
                if win.epoch(key) != epoch {
                    drop(win);
                    return Err(self.closed_or(gen, Error::DestinationEnded));
                }
                (wake, win.room(key, Instant::now()))
            };
            if let Some(g) = answer.let_go {
                olc_net::info!(
                    "relaywin: no echo for {}s with {} bytes in flight - window off",
                    g.held.as_secs_f64().round(),
                    g.in_flight
                );
            }
            if answer.probe {
                mark_relay(gen, key, answer.counter);
            }
            if answer.ok {
                return if gen.is_done() || self.closed.load(Ordering::Acquire) {
                    Err(Error::SessionClosed)
                } else {
                    Ok(())
                };
            }
            tokio::select! {
                () = wake.closed() => {}
                () = tokio::time::sleep(RELAY_RETRY) => {}
                () = gen.done.cancelled() => {}
                () = self.stop.cancelled() => {}
            }
        }
    }

    fn closed_or(&self, gen: &Gen, e: Error) -> Error {
        if gen.is_done() || self.closed.load(Ordering::Acquire) {
            Error::SessionClosed
        } else {
            e
        }
    }

    fn peer_config(&self, name: &'static str, buffered: usize) -> PeerConfig {
        PeerConfig {
            name,
            crypto: self.crypto.clone(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: self.host_ip,
            sctp_max_buffered: buffered,
        }
    }
}

/// `markRelay`.
fn mark_relay(gen: &Gen, key: &str, counter: u64) {
    if !gen.marks(key) {
        return;
    }
    gen.note_mark(key, counter, Instant::now());
    send_window_frame(gen, key, WINDOW_MARK, counter);
}

/// `sendWindowFrame`: on the publisher's reliable lane, best effort.
fn send_window_frame(gen: &Gen, to: &str, kind: u8, counter: u64) {
    if !gen.rel_open.load(Ordering::Acquire) {
        return;
    }
    let Some((peer, rel, _)) = gen.publisher() else {
        return;
    };
    let frame = lk::encode(
        &window_frame(kind, counter),
        Some(lk::WINDOW_TOPIC),
        &[to.to_owned()],
        true,
    );
    if !matches!(peer.write(rel, true, &frame), Ok(true)) {
        olc_net::debug!("salutejazz: a relay window frame did not fit the lane");
    }
}

/// The connector's WebSocket, with the web client's Origin and User-Agent.
async fn dial(url: &str) -> Result<(ws::Reader<BoxStream>, ws::Writer<BoxStream>), Error> {
    let target = olc_net::stream::parse_url(url).map_err(|e| Error::Dial(e.to_string()))?;
    let fut = async {
        let stream = olc_net::stream::dial(&target)
            .await
            .map_err(|e| Error::Dial(e.to_string()))?;
        let req = ws::Request {
            host: &target.authority,
            path: &target.path,
            headers: &[("User-Agent", WEB_USER_AGENT), ("Origin", WEB_ORIGIN)],
            read_limit: WS_READ_LIMIT,
            timeout: WS_HANDSHAKE_TIMEOUT,
        };
        ws::handshake(stream, &req)
            .await
            .map_err(|e| Error::Dial(e.to_string()))
    };
    tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| Error::Dial("i/o timeout".into()))?
}

/// `teardown`: wakes held senders, says goodbye on the socket, closes the
/// peer connections (each drains for at most `pcCloseTimeout`).
async fn teardown(gen: &Gen) {
    if gen.done.is_cancelled() {
        return;
    }
    gen.done.cancel();
    lock(&gen.win).reset_all();
    let ws = lock(&gen.ws).take();
    if let Some(ws) = ws {
        let _ = tokio::time::timeout(Duration::from_secs(1), ws.close()).await;
    }
    if let Some(p) = lock(&gen.sub).take() {
        p.close();
    }
    if let Some(p) = lock(&gen.publ).take() {
        p.peer.close();
    }
    gen.rel_open.store(false, Ordering::Release);
    gen.lossy_open.store(false, Ordering::Release);
}

/// The reconnect watcher (`Reconnector.Watch`, request mode).
async fn watch(sh: Arc<Shared>, mut requests: mpsc::Receiver<()>) {
    let mut count = 0u32;
    let mut last: Option<Instant> = None;
    loop {
        tokio::select! {
            got = requests.recv() => if got.is_none() { return },
            () = sh.stop.cancelled() => return,
        }
        loop {
            let now = Instant::now();
            if last.is_none_or(|l| now.duration_since(l) > RECONNECT_WINDOW) {
                count = 0;
            }
            count += 1;
            last = Some(now);
            if count > MAX_RECONNECTS {
                sh.signal_ended("reconnect limit reached");
                let cur = lock(&sh.cur).take();
                if let Some(g) = cur {
                    teardown(&g).await;
                }
                return;
            }
            sh.reconnecting.store(true, Ordering::Release);
            let cur = lock(&sh.cur).take();
            if let Some(g) = cur {
                teardown(&g).await;
            }
            sh.lanes.notify_waiters();
            let result = if sh.terminated.load(Ordering::Acquire) {
                Err(Error::SessionClosed)
            } else {
                sh.connect_gen().await
            };
            sh.reconnecting.store(false, Ordering::Release);
            match result {
                Ok(()) => {
                    // dropRequestsOlderThan: what was asked during the attempt is answered by it.
                    while requests.try_recv().is_ok() {}
                    let _ = sh.events.try_send(LinkEvent::Reconnected);
                    break;
                }
                Err(Error::SessionClosed) if sh.terminated.load(Ordering::Acquire) => return,
                Err(e) => {
                    olc_net::debug!("salutejazz: reconnect failed: {e}");
                    let backoff = (RECONNECT_STEP * count).min(RECONNECT_MAX);
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = sh.stop.cancelled() => return,
                    }
                }
            }
        }
    }
}

/// `readLoop`.
async fn read_loop(sh: Arc<Shared>, gen: Arc<Gen>, mut reader: ws::Reader<BoxStream>) {
    loop {
        let msg = tokio::select! {
            m = tokio::time::timeout(WS_READ_TIMEOUT, reader.next()) => m,
            () = gen.done.cancelled() => return,
        };
        let text = match msg {
            Ok(Ok(ws::Message::Text(t))) => t,
            Ok(Ok(ws::Message::Binary(_))) => continue,
            Ok(Err(e)) => {
                if !sh.closed.load(Ordering::Acquire) && !gen.is_done() {
                    olc_net::debug!("salutejazz: signaling read: {e}");
                    sh.queue_reconnect();
                }
                return;
            }
            Err(_) => {
                if !sh.closed.load(Ordering::Acquire) && !gen.is_done() {
                    olc_net::debug!("salutejazz: signaling read: i/o timeout");
                    sh.queue_reconnect();
                }
                return;
            }
        };
        match serde_json::from_str::<wire::EnvIn>(&text) {
            Ok(frame) => handle_envelope(&sh, &gen, frame).await,
            Err(e) => {
                if !sh.closed.load(Ordering::Acquire) && !gen.is_done() {
                    olc_net::debug!("salutejazz: signaling read: {e}");
                    sh.queue_reconnect();
                }
                return;
            }
        }
    }
}

async fn handle_envelope(sh: &Arc<Shared>, gen: &Arc<Gen>, frame: wire::EnvIn) {
    if !frame.group_id.is_empty() {
        let mut g = lock(&gen.group);
        if g.is_empty() {
            g.clone_from(&frame.group_id);
        }
    }
    match frame.event.as_str() {
        event::JOIN_RESPONSE => match serde_json::from_value::<wire::JoinResponse>(frame.payload) {
            Ok(r) => {
                if !r.participant.participant_id.is_empty() {
                    r.participant
                        .participant_id
                        .clone_into(&mut lock(&gen.identity));
                }
                if !r.participant_group.group_id.is_empty() {
                    r.participant_group
                        .group_id
                        .clone_into(&mut lock(&gen.group));
                }
                olc_net::debug!(
                    "salutejazz: joined, participant id {} chars, meeting id {} chars",
                    r.participant.participant_id.len(),
                    r.meeting_id.len()
                );
            }
            Err(e) => olc_net::debug!("salutejazz: join-response: {e}"),
        },
        event::MEDIA_OUT => match serde_json::from_value::<wire::MediaPayload>(frame.payload) {
            Ok(m) => handle_media_out(sh, gen, m).await,
            Err(e) => olc_net::debug!("salutejazz: media-out: {e}"),
        },
        event::PARTICIPANT_LEFT => {
            let mut id = frame.participant_id;
            if id.is_empty() {
                match serde_json::from_value::<wire::ParticipantLeft>(frame.payload) {
                    Ok(p) if !p.participant_id.is_empty() => id = p.participant_id,
                    Ok(p) => id = p.participant.participant_id,
                    Err(e) => {
                        olc_net::debug!("salutejazz: participant-left: {e}");
                        return;
                    }
                }
            }
            if id.is_empty() {
                olc_net::debug!("salutejazz: participant-left named nobody");
                return;
            }
            lock(&gen.roster).depart(&id);
            gen.forget_relay_peer(&id);
            olc_net::debug!(
                "salutejazz: participant-left, {} others still in the room",
                lock(&gen.roster).peers.len()
            );
        }
        event::ERROR => {
            let failure: wire::ServerError = match serde_json::from_value(frame.payload) {
                Ok(f) => f,
                Err(e) => {
                    olc_net::info!("salutejazz: server error frame: {e}");
                    return;
                }
            };
            let code = failure.code.trim().to_ascii_uppercase();
            if !frame.request_id.is_empty() && frame.request_id == *lock(&gen.join_req) {
                olc_net::info!("salutejazz: the connector refused the join: {code}");
                end_attempt(
                    sh,
                    gen,
                    &wire::ended_reason("the connector refused the join", &code),
                )
                .await;
            } else if wire::room_is_gone(&code) {
                olc_net::info!("salutejazz: the connector says the room is gone: {code}");
                end_attempt(sh, gen, &wire::ended_reason("the room is gone", &code)).await;
            } else {
                olc_net::info!("salutejazz: server error {code}");
            }
        }
        other => olc_net::debug!("salutejazz: event {other}"),
    }
}

/// `endAttempt`.
async fn end_attempt(sh: &Arc<Shared>, gen: &Arc<Gen>, reason: &str) {
    let current = sh.current().is_some_and(|c| Arc::ptr_eq(&c, gen));
    if !current {
        teardown(gen).await;
        return;
    }
    sh.signal_ended(reason);
    sh.abandon(gen).await;
}

async fn handle_media_out(sh: &Arc<Shared>, gen: &Arc<Gen>, m: wire::MediaPayload) {
    match m.method.as_str() {
        method::CONFIG => {
            if let Some(c) = m.configuration {
                *lock(&gen.ice_servers) = c.ice_servers;
            }
        }
        method::JOIN => {
            if let Some(j) = m.join {
                gen.apply_participants(&j.other_participants);
            }
        }
        method::OFFER => {
            if let Err(e) = handle_offer(sh, gen, m.description).await {
                olc_net::info!("salutejazz: subscriber offer: {e}");
                sh.reconnect_attempt(gen);
            }
        }
        method::ANSWER => {
            if let Some(d) = m.description {
                match lock(&gen.answer).take() {
                    Some(tx) => {
                        let _ = tx.send(d.sdp);
                    }
                    None => olc_net::debug!("salutejazz: unexpected rtc:answer"),
                }
            }
        }
        method::ICE => {
            for c in m.candidates {
                let target = if c.target.is_empty() {
                    TARGET_SUBSCRIBER
                } else {
                    c.target.as_str()
                };
                if let Err(e) = add_ice(gen, target, &c.candidate) {
                    olc_net::debug!("salutejazz: {target} candidate: {e}");
                }
            }
        }
        method::PARTICIPANTS => {
            if let Some(u) = m.update {
                gen.apply_participants(&u.participants);
            }
        }
        method::PONG => {
            let sent = m
                .pong_resp
                .map_or(0, |p| wire::parse_millis(&p.last_ping_timestamp));
            let mut pongs = lock(&gen.pongs);
            if let Some(tx) = pongs.remove(&sent) {
                let _ = tx.send(());
            } else {
                for (_, tx) in pongs.drain() {
                    let _ = tx.send(());
                }
            }
        }
        other => olc_net::debug!("salutejazz: media-out {other}"),
    }
}

/// `addICE`: to the peer when its remote description is in, else queued.
fn add_ice(gen: &Gen, target: &str, line: &str) -> Result<(), String> {
    let c =
        Candidate::from_sdp_string(line).map_err(|e| format!("salutejazz add candidate: {e}"))?;
    let (key, peer) = if target == TARGET_PUBLISHER {
        let answered = lock(&gen.pending_pub).is_none();
        (
            TARGET_PUBLISHER,
            gen.publisher().filter(|_| answered).map(|p| p.0),
        )
    } else {
        (TARGET_SUBSCRIBER, lock(&gen.sub).clone())
    };
    match peer {
        Some(p) => p.add_remote_candidate(c),
        None => {
            let mut ice = lock(&gen.ice);
            let q = ice.entry(key).or_default();
            if q.len() < MAX_PENDING_ICE {
                q.push(c);
            }
        }
    }
    Ok(())
}

/// `drainICE`.
fn drain_ice(gen: &Gen, target: &'static str, peer: &Peer) {
    let queued = lock(&gen.ice).remove(target).unwrap_or_default();
    for c in queued {
        peer.add_remote_candidate(c);
    }
}

/// `sendICE`: one candidate a frame, with the local ufrag.
async fn send_ice(sh: &Shared, gen: &Gen, target: &str, peer: &Peer) -> Result<(), Error> {
    let line = peer
        .add_host_candidate()
        .map_err(|e| Error::Other(e.to_string()))?;
    let ufrag = peer.creds().ufrag.clone();
    let m = wire::MediaIn {
        method: method::ICE,
        candidates: vec![wire::IceOut {
            candidate: &line,
            sdp_mid: "0",
            sdp_mline_index: 0,
            username_fragment: &ufrag,
            target,
        }],
        ..wire::MediaIn::default()
    };
    sh.send_media(gen, &m).await
}

/// `handleOffer`: the SFU's offer of the subscriber connection (again on a
/// renegotiation), answered as Chrome answers: as the DTLS client
/// (`a=setup:active`; str0m answers an `actpass` offer as the server, so the
/// offer is read as `passive`).
async fn handle_offer(
    sh: &Arc<Shared>,
    gen: &Arc<Gen>,
    desc: Option<wire::SdpIn>,
) -> Result<(), Error> {
    let desc = desc.ok_or(Error::NoDescription)?;
    let sdp = desc.sdp.replace("a=setup:actpass", "a=setup:passive");
    let offer = SdpOffer::from_sdp_string(&sdp)
        .map_err(|e| Error::Other(format!("salutejazz subscriber remote description: {e}")))?;
    let existing = lock(&gen.sub).clone();
    let (peer, fresh) = match existing {
        Some(p) => (p, false),
        None => {
            let (p, rx) =
                Peer::start(&sh.peer_config("subscriber", SUB_SCTP_BUFFERED)).map_err(|e| {
                    Error::Other(format!(
                        "salutejazz new {TARGET_SUBSCRIBER} peer connection: {e}"
                    ))
                })?;
            if gen.is_done() {
                p.close();
                return Err(Error::SessionClosed);
            }
            *lock(&gen.sub) = Some(p.clone());
            tokio::spawn(run_peer(sh.clone(), gen.clone(), rx, false));
            (p, true)
        }
    };
    let answer = peer
        .with_rtc(|rtc| rtc.sdp_api().accept_offer(offer))
        .map_err(|e| Error::Other(format!("salutejazz create answer: {e}")))?;
    drain_ice(gen, TARGET_SUBSCRIBER, &peer);
    let sdp = answer.to_sdp_string();
    let m = wire::MediaIn {
        method: method::ANSWER,
        description: Some(wire::SdpOut {
            sdp: &sdp,
            kind: "answer",
        }),
        ..wire::MediaIn::default()
    };
    sh.send_media(gen, &m).await?;
    if fresh {
        if let Err(e) = send_ice(sh, gen, TARGET_SUBSCRIBER, &peer).await {
            olc_net::debug!("salutejazz: {TARGET_SUBSCRIBER} candidate: {e}");
        }
    }
    Ok(())
}

/// `negotiate`: once the subscriber's `_reliable` is open, the publisher.
async fn negotiate(sh: Arc<Shared>, gen: Arc<Gen>) {
    let ready = gen.sub_ready.notified();
    if !gen.sub_open.load(Ordering::Acquire) {
        tokio::select! {
            () = ready => {}
            () = gen.done.cancelled() => return,
            () = sh.stop.cancelled() => return,
        }
    }
    if let Err(e) = start_publisher(&sh, &gen).await {
        if !gen.is_done() {
            olc_net::info!("salutejazz: publisher negotiation: {e}");
            sh.reconnect_attempt(&gen);
        }
    }
}

/// `startPublisher` and `awaitPublisherAnswer`.
async fn start_publisher(sh: &Arc<Shared>, gen: &Arc<Gen>) -> Result<(), Error> {
    let (peer, rx) = Peer::start(&sh.peer_config("publisher", PUB_SCTP_BUFFERED)).map_err(|e| {
        Error::Other(format!(
            "salutejazz new {TARGET_PUBLISHER} peer connection: {e}"
        ))
    })?;
    if gen.is_done() {
        peer.close();
        return Err(Error::SessionClosed);
    }
    let (offer, pending, rel, lossy) = peer
        .with_rtc(|rtc| {
            let mut api = rtc.sdp_api();
            let rel = api.add_channel_with_config(ChannelConfig {
                label: LABEL_RELIABLE.into(),
                ordered: true,
                reliability: Reliability::Reliable,
                negotiated: None,
                protocol: String::new(),
            });
            let lossy = api.add_channel_with_config(ChannelConfig {
                label: LABEL_LOSSY.into(),
                ordered: true,
                reliability: Reliability::MaxRetransmits { retransmits: 0 },
                negotiated: None,
                protocol: String::new(),
            });
            api.apply().map(|(o, p)| (o, p, rel, lossy))
        })
        .ok_or_else(|| Error::Other("salutejazz create offer: no offer".into()))?;
    *lock(&gen.publ) = Some(Publisher {
        peer: peer.clone(),
        rel,
        lossy,
    });
    *lock(&gen.pending_pub) = Some(pending);
    tokio::spawn(run_peer(sh.clone(), gen.clone(), rx, true));
    let (tx, answer_rx) = oneshot::channel();
    *lock(&gen.answer) = Some(tx);
    let sdp = offer.to_sdp_string();
    let m = wire::MediaIn {
        method: method::OFFER,
        description: Some(wire::SdpOut {
            sdp: &sdp,
            kind: "offer",
        }),
        ..wire::MediaIn::default()
    };
    sh.send_media(gen, &m).await?;
    if let Err(e) = send_ice(sh, gen, TARGET_PUBLISHER, &peer).await {
        olc_net::debug!("salutejazz: {TARGET_PUBLISHER} candidate: {e}");
    }
    let answer = tokio::select! {
        a = answer_rx => a.map_err(|_| Error::SessionClosed)?,
        () = gen.done.cancelled() => return Err(Error::SessionClosed),
        () = tokio::time::sleep(ANSWER_TIMEOUT) => return Err(Error::NoAnswer),
    };
    let answer = SdpAnswer::from_sdp_string(&answer)
        .map_err(|e| Error::Other(format!("salutejazz publisher remote description: {e}")))?;
    let pending = lock(&gen.pending_pub).take().ok_or(Error::SessionClosed)?;
    peer.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer))
        .map_err(|e| Error::Other(format!("salutejazz publisher remote description: {e}")))?;
    drain_ice(gen, TARGET_PUBLISHER, &peer);
    Ok(())
}

/// pion's words for an ICE state (`ICEConnectionState.String`).
fn pion_ice(s: IceConnectionState) -> &'static str {
    match s {
        IceConnectionState::New => "new",
        IceConnectionState::Checking => "checking",
        IceConnectionState::Connected => "connected",
        IceConnectionState::Completed => "completed",
        IceConnectionState::Disconnected => "disconnected",
    }
}

/// The apps' log contract (critique G1, W45): Android's `handleRtcLine`
/// and iOS's `IosVpnManager` restart the tunnel on pion's state lines, which
/// the Go engine logs at info through `PionLoggerFactory` under the `pc`
/// scope. The Rust engine says the same lines at the same events.
fn pion_ice_line(state: &str) {
    olc_net::info!("[pc] INFO: ICE connection state changed: {state}");
}

/// See [`pion_ice_line`]: `peer connection state changed: <state>`.
fn pion_pc_line(state: &str) {
    olc_net::info!("[pc] INFO: peer connection state changed: {state}");
}

fn state_name(s: IceConnectionState) -> &'static str {
    match s {
        IceConnectionState::New => "new",
        IceConnectionState::Checking => "connecting",
        IceConnectionState::Connected | IceConnectionState::Completed => "connected",
        IceConnectionState::Disconnected => "disconnected",
    }
}

/// One peer connection's events: its state (`onPeerConnectionState`), its
/// channels (`wireChannel`) and, on the subscriber, what the room sends
/// (`receiveOn`).
async fn run_peer(
    sh: Arc<Shared>,
    gen: Arc<Gen>,
    mut rx: mpsc::Receiver<PeerEvent>,
    publisher: bool,
) {
    let target = if publisher {
        TARGET_PUBLISHER
    } else {
        TARGET_SUBSCRIBER
    };
    let mut failing: Option<tokio::time::Instant> = None;
    loop {
        let ev = tokio::select! {
            ev = rx.recv() => ev,
            () = async {
                match failing {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                failing = None;
                pion_ice_line("failed");
                pion_pc_line("failed");
                failed(&sh, &gen, target);
                continue;
            }
        };
        let Some(ev) = ev else { return };
        match ev {
            PeerEvent::IceState(s) => {
                olc_net::debug!("salutejazz: {target} peer connection {}", state_name(s));
                pion_ice_line(pion_ice(s));
                match s {
                    IceConnectionState::Checking => pion_pc_line("connecting"),
                    IceConnectionState::Disconnected => pion_pc_line("disconnected"),
                    _ => {}
                }
                if s == IceConnectionState::Disconnected {
                    failing.get_or_insert(tokio::time::Instant::now() + ICE_FAILED_AFTER);
                } else if matches!(
                    s,
                    IceConnectionState::Connected | IceConnectionState::Completed
                ) {
                    failing = None;
                }
            }
            PeerEvent::Connected => {
                olc_net::debug!("salutejazz: {target} peer connection connected");
                pion_pc_line("connected");
            }
            PeerEvent::ChannelOpen(_, label) => {
                olc_net::debug!("salutejazz: channel {label:?} open (publisher={publisher})");
                match (publisher, label.as_str()) {
                    (true, LABEL_RELIABLE) => {
                        gen.rel_open.store(true, Ordering::Release);
                        gen.pub_ready.notify_waiters();
                        sh.lanes.notify_waiters();
                    }
                    (true, LABEL_LOSSY) => gen.lossy_open.store(true, Ordering::Release),
                    (false, LABEL_RELIABLE) => {
                        gen.sub_open.store(true, Ordering::Release);
                        gen.sub_ready.notify_waiters();
                    }
                    (false, LABEL_LOSSY) => {}
                    _ => olc_net::debug!("salutejazz: unexpected channel {label:?}"),
                }
            }
            PeerEvent::Data(mut m) => {
                if !publisher {
                    handle_data_packet(&sh, &gen, &mut m.data).await;
                }
            }
            PeerEvent::ChannelClose(_) => {}
            PeerEvent::Closed(reason) => {
                olc_net::debug!("salutejazz: {target} peer connection closed: {reason}");
                pion_ice_line("closed");
                pion_pc_line("closed");
                if !gen.is_done() {
                    failed(&sh, &gen, target);
                }
                return;
            }
        }
    }
}

fn failed(sh: &Shared, gen: &Gen, target: &str) {
    let current = sh
        .current()
        .is_some_and(|c| std::ptr::eq(Arc::as_ptr(&c), gen));
    if !sh.closed.load(Ordering::Acquire) && current {
        olc_net::info!("salutejazz: {target} peer connection failed");
        sh.queue_reconnect();
    }
}

/// `handleDataPacket`.
async fn handle_data_packet(sh: &Shared, gen: &Gen, frame: &mut [u8]) {
    if sh.closed.load(Ordering::Acquire) || gen.is_done() {
        return;
    }
    let Some(p) = lk::decode(frame) else {
        olc_net::debug!("salutejazz: data packet: malformed");
        return;
    };
    if !p.sender.is_empty() && p.sender == gen.local_identity() {
        return;
    }
    if p.by_identity {
        gen.note_peer(&p.sender);
    }
    let payload = &mut frame[p.payload.clone()];
    match p.topic.as_deref() {
        Some(lk::WINDOW_TOPIC) => handle_window_frame(gen, &p.sender, p.by_identity, payload),
        Some(lk::DATAGRAM_TOPIC) => {
            let sink = sh
                .datagram
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(sink) = sink {
                sink(payload);
            }
        }
        _ => {
            let sink = sh
                .data
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(sink) = sink {
                sink.push(payload).await;
            }
        }
    }
}

/// `handleWindowFrame`.
fn handle_window_frame(gen: &Gen, from: &str, by_identity: bool, payload: &[u8]) {
    if !by_identity || gen.has_left(from) {
        return;
    }
    let Some((kind, counter)) = parse_window_frame(payload) else {
        return;
    };
    if gen.note_speaker(from) {
        lock(&gen.win).arm(from);
    }
    match kind {
        WINDOW_MARK => send_window_frame(gen, from, WINDOW_ECHO, counter),
        _ => {
            let now = Instant::now();
            let (moved, turned_on) = lock(&gen.win).apply_echo_at(from, counter, Some(now));
            if moved {
                gen.note_echo(from, counter, turned_on, now);
            }
        }
    }
}

/// `pingLoop` and `ping`.
async fn ping_loop(sh: Arc<Shared>, gen: Arc<Gen>) {
    let mut tick =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    // Go's Ticker drops the ticks a slow receiver missed.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = gen.done.cancelled() => return,
            () = sh.stop.cancelled() => return,
        }
        if lock(&gen.group).is_empty() {
            continue;
        }
        if let Err(e) = ping(&sh, &gen).await {
            olc_net::debug!("salutejazz: ping: {e}");
            sh.reconnect_attempt(&gen);
            return;
        }
    }
}

async fn ping(sh: &Shared, gen: &Gen) -> Result<(), Error> {
    let (sent, rx) = {
        let mut pongs = lock(&gen.pongs);
        let mut sent = unix_ms();
        while pongs.contains_key(&sent) {
            sent += 1;
        }
        let (tx, rx) = oneshot::channel();
        pongs.insert(sent, tx);
        (sent, rx)
    };
    let m = wire::MediaIn {
        method: method::PING,
        ping_req: Some(wire::PingReq {
            timestamp: sent,
            rtt: gen.rtt.load(Ordering::Relaxed),
        }),
        ..wire::MediaIn::default()
    };
    let result = match sh.send_media(gen, &m).await {
        Err(e) => Err(e),
        Ok(()) => tokio::select! {
            r = rx => r.map_err(|_| Error::SessionClosed).map(|()| {
                gen.rtt.store(unix_ms() - sent, Ordering::Relaxed);
            }),
            () = tokio::time::sleep(PONG_TIMEOUT) => Err(Error::PongTimeout),
            () = gen.done.cancelled() => Err(Error::SessionClosed),
        },
    };
    lock(&gen.pongs).remove(&sent);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ice_states_take_pions_words() {
        assert_eq!(pion_ice(IceConnectionState::New), "new");
        assert_eq!(pion_ice(IceConnectionState::Checking), "checking");
        assert_eq!(pion_ice(IceConnectionState::Connected), "connected");
        assert_eq!(pion_ice(IceConnectionState::Completed), "completed");
        assert_eq!(pion_ice(IceConnectionState::Disconnected), "disconnected");
    }

    /// One per participant that has spoken in the room; its marks are
    /// bounded by `WINDOW_MARKS_KEPT`.
    #[test]
    fn a_relay_peer_stays_small() {
        assert!(
            size_of::<RelayPeer>() <= 96,
            "RelayPeer is {} bytes",
            size_of::<RelayPeer>()
        );
    }

    #[test]
    fn the_window_frame_is_gos_fourteen_bytes() {
        let f = window_frame(WINDOW_MARK, 0x0102_0304_0506_0708);
        assert_eq!(f, [1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 3, 0, 0]);
        assert_eq!(
            parse_window_frame(&f),
            Some((WINDOW_MARK, 0x0102_0304_0506_0708))
        );
        assert_eq!(
            parse_window_frame(&window_frame(WINDOW_ECHO, 5)),
            Some((WINDOW_ECHO, 5))
        );
        assert_eq!(parse_window_frame(&f[..13]), None);
        let mut bad = f;
        bad[1] = 3;
        assert_eq!(parse_window_frame(&bad), None);
        bad = f;
        bad[0] = 2;
        assert_eq!(parse_window_frame(&bad), None);
    }

    #[test]
    fn the_budget_numbers_hold_their_formulas() {
        assert_eq!(RELAY_MARK_EVERY, 24 << 10);
        assert_eq!(PUB_SCTP_BUFFERED, 1_081_344);
        // One record with its DataPacket fits the per-lane slack.
        assert!(olc_rtc_record_max() + lk::OVERHEAD <= 16 << 10);
    }

    fn olc_rtc_record_max() -> usize {
        // The datachannel transport's message cap (12 KiB) with its record
        // header and tag: what the client's lane sends at most.
        12 << 10
    }

    #[test]
    fn the_roster_forgets_the_oldest_departure_first() {
        let mut r = Roster::default();
        for i in 0..=LEFT_KEPT {
            r.depart(&format!("p{i}"));
        }
        assert_eq!(r.left.len(), LEFT_KEPT);
        assert!(!r.has_left("p0"));
        assert!(r.has_left(&format!("p{LEFT_KEPT}")));
    }

    #[test]
    fn a_send_goes_to_the_confirmed_peer_only_while_it_is_in_the_room() {
        let g = Gen::new();
        assert!(g.room_dest(Vec::new()).is_empty());
        "srv".clone_into(&mut lock(&g.confirmed));
        assert!(g.room_dest(Vec::new()).is_empty(), "not in the room yet");
        g.note_peer("srv");
        assert_eq!(g.room_dest(Vec::new()), vec!["srv".to_owned()]);
        assert_eq!(g.window_key(&["srv".to_owned()]), "srv");
        lock(&g.roster).depart("srv");
        assert!(g.room_dest(Vec::new()).is_empty());
        assert_eq!(g.window_key(&["srv".to_owned()]), "");
        g.note_peer("srv");
        assert!(
            !g.in_room("srv"),
            "a departed identity does not come back from a packet"
        );
    }
}

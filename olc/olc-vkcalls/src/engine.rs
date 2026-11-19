// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The VK Calls session (`Session` of `vkcalls.go`) as the video
//! transport's engine ([`VideoEngine`]): one guest in one SERVER
//! conversation, publishing the transport's VP8 track into the SFU's
//! publish slot and reading the cameras the SFU forwards.
//!
//! One join ([`Session::connect`], Go's `Connect`): the signalling socket,
//! the wait for SERVER topology (with the guests that flip a fresh room,
//! [`crate::recruit`]), `allocate-consumer`, `update-media-modifiers`, the
//! first offer, `change-media-settings`, the peer connection and the shaped
//! answer ([`crate::session::Negotiation`]), `accept-producer`, and the
//! wait for the peer connection. Then three tasks own the attempt:
//!
//! - the peer's events: its state as pion tells it ([`PcWatcher`]); when
//!   `producerCommand` opens, `change-simulcast` and the layout; the
//!   stream registry that arrives on `producerNotification`;
//! - the signalling notifications: participants, a later offer
//!   (`reanswer`), a hangup, the socket's end;
//! - the perf report, every five seconds, from the peer's count of video
//!   packets: without it the SFU stalls the forward within a minute.
//!
//! Everything one attempt owns is a `Generation`; nothing crosses to the
//! next. A rejoin ([`Reconnector`], ten requests within five minutes of one
//! another) tears the attempt down whole, the hangup included, takes a
//! fresh guest's credentials and joins from scratch.
//!
//! What differs from Go, none of it on the wire: a peer connection that
//! fails before it connected ends the join at once and asks for no rejoin
//! of its own (plan D5); a reader is kept per SSRC, [`READERS_MAX`] at
//! most (D8); every command has a bound over its write and its wait; a
//! rejoin's wait for SERVER topology has the first join's bound
//! ([`CONNECT_BOUND`]: Go's has none, and a room found in DIRECT would
//! hold its supervisor for good); a close ends a join under way and waits
//! for its hangup; a task of the session that panics ends the session
//! ([`TASK_FAILED`]), where Go's process would be gone.
//!
//! # Memory
//!
//! A session holds, per attempt: the signalling socket
//! ([`crate::signaling::READ_PEAK`] while a frame is decoded,
//! [`crate::signaling::NOTIFICATION_BYTES`] waiting at most), the peer
//! (olc-rtc's bounds), the resend cache of what it publishes
//! ([`RESEND_HELD`]), at most [`READERS_MAX`] readers ([`READER_HELD`]
//! each, full), and the control route's state ([`CONTROL_HELD`]). While an
//! offer is answered four texts of its size are alive
//! ([`OFFER_TEXTS`]); while a fresh room is flipped, the guests' sockets.
//! No room link, endpoint, token or TURN credential is in any log line,
//! error or `Debug` of this module.

use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use olc_net::reconnect::{Reconnector, Rejoin, Request as Asked};
use olc_rtc::media::{ResendCache, RtpOut};
use olc_rtc::pcstate::{Change, PcState, PcWatcher};
use olc_rtc::peer::{IceMode, Peer, PeerConfig, PeerEvent};
use olc_rtc::str0m::channel::ChannelId;
use olc_rtc::str0m::rtp::RtpPacket;
use olc_rtc::DtlsVersion;
use olc_vp8channel::channel::Carrier;
use olc_vp8channel::engine::{
    EngineEvent, EngineFuture, FrameHandler, Joined, KeyframeHandler, VideoEngine, EVENT_QUEUE,
};
use olc_vp8channel::rtp::{Packetizer, Payloader, Vp8Payloader, RTP_OUTBOUND_MTU};
use olc_vp8channel::rtp_reader::{
    HeldGauge, TrackReader, MAX_RETAINED_PAYLOAD, MIME_RED, MIME_VP8, REORDER_HOLD, REORDER_WINDOW,
};
use olc_vp8channel::transport::Stream;
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use zeroize::{Zeroize, Zeroizing};

use crate::answer::{breached, ShapeError};
use crate::auth::{self, Credentials};
use crate::control::{ControlState, RegistryError, PARTICIPANTS_MAX, REGISTRY_MAX};
use crate::negotiate::ViewError;
use crate::recruit::{wait_connected, Delays, Headers, Issue, MAX_RECRUITS};
use crate::session::{ice_servers_of, turn_servers, NegotiateError, Negotiation, Opened, TrackIds};
use crate::signaling::{
    accept_producer, allocate_consumer, change_media_settings, decimal_id, participant_ids,
    update_media_modifiers, Json, Notification, Notifications, Signaling, SignalingError,
    COMMAND_TIMEOUT, HANGUP_TIMEOUT, READ_LIMIT, REFERENCE_CAPABILITIES,
};

/// How long the first offer may take (`offerWait`).
pub const OFFER_WAIT: Duration = Duration::from_secs(30);
/// How long the peer connection may take to connect (`connectWait`).
pub const CONNECT_WAIT: Duration = Duration::from_secs(30);
/// How long a first join may take as a whole: the video transport's
/// `defaultConnectTimeout`, the deadline of the context Go's first
/// `Connect` runs under (`vp8channel/transport.go`). It is what ends the
/// wait for SERVER topology, which has no timer of its own. A rejoin runs
/// under the supervisor's context in Go, with no deadline: here its steps
/// keep their own timers, as Go's, and the topology wait alone has this
/// bound, counted from the rejoin's dial.
pub const CONNECT_BOUND: Duration = Duration::from_secs(60);
/// The rejoin requests served before the session ends (`maxReconnects`).
pub const MAX_RECONNECTS: u32 = 10;
/// Why a session that ran out of rejoins ended (`LimitReason`).
pub const LIMIT_REASON: &str = "reconnect limit reached";
/// How often the consumer's progress is reported (`perfStatInterval`, the
/// SDK's `statisticsInterval`).
pub const PERF_STAT_INTERVAL: Duration = Duration::from_secs(5);
/// What a close allows a peer connection beyond its own bound on its
/// goodbyes ([`olc_rtc::peer::CLOSE_DRAIN`]) to end and say so.
const CLOSE_MARGIN: Duration = Duration::from_millis(500);
/// What a close allows a join or a rejoin under way to notice it, hang up
/// and end: the hangups of the attempt it tore down, of its own socket and
/// of the guests it recruited, each [`HANGUP_TIMEOUT`] at most.
#[allow(clippy::cast_possible_truncation)]
const LEAVE_WAIT: Duration =
    Duration::from_millis((MAX_RECRUITS as u64 + 2) * HANGUP_TIMEOUT.as_millis() as u64 + 500);
/// Why a session ended whose rejoin supervisor or notification loop
/// panicked. Not in Go, where the process would be gone: here the task
/// alone would be, and the session would look alive for good.
pub const TASK_FAILED: &str = "vkcalls: a session task failed";
/// Not in Go: a command's write and its wait together. Go's write has no
/// deadline; a socket that takes no bytes would hold the frame for good.
pub const COMMAND_BOUND: Duration = Duration::from_secs(2 * COMMAND_TIMEOUT.as_secs());

/// The readers kept, one per SSRC the SFU forwards a read codec on (plan
/// D8). The offer declares up to 36 video tracks; a call the tunnel runs in
/// has the server's camera and little else. Past the cap the reader fed
/// longest ago goes.
pub const READERS_MAX: usize = 9;
/// The longest RTP payload a reader is given; a longer one is dropped
/// before any reader is made for it or copies it, which is what makes
/// [`READER_HELD`] a bound (the reorder buffer copies what it is given).
/// The SFU's packets carry 1,200 bytes at most.
pub const MAX_PACKET_PAYLOAD: usize = MAX_RETAINED_PAYLOAD;
/// The most one reader holds: olc-vp8channel's own bound, on its buffers'
/// capacities (the reorder buffer at the packet that makes it give a gap
/// up, the two lists it keeps, and the one frame buffer). The same bound
/// as MTS Link's reader.
pub use olc_vp8channel::rtp_reader::READER_HELD;

/// The newest packets of what we publish kept for a resend: what the far
/// reader can still take back behind a gap (its `reorderWindow`), and one.
/// The Go engine's phone profile keeps 256.
pub const RESEND_PACKETS: usize = REORDER_WINDOW + 1;
/// How long a sent packet is kept for a resend: the far reader's
/// `reorderHold`. Go's history has no age.
pub const RESEND_AGE: Duration = REORDER_HOLD;
/// The share of resends in what is sent past which str0m drops the queued
/// ones (its default).
const RESEND_RATIO_CAP: Option<f32> = Some(0.15);
/// What the resend cache holds, full.
pub const RESEND_HELD: usize = RESEND_PACKETS * RTP_OUTBOUND_MTU;

/// What the control route keeps: the registry and the participants (a key
/// or an id of at most 31 bytes and its node, each), and one layout frame
/// while it is written (a blob under 256 bytes per entry).
pub const CONTROL_HELD: usize = (REGISTRY_MAX + PARTICIPANTS_MAX) * (64 + 256);
/// The texts alive while an offer is answered: the offer, its view, what
/// the stack is given and the answer, each at most
/// [`crate::signaling::READ_LIMIT`].
pub const OFFER_TEXTS: usize = 4 * READ_LIMIT;
/// The offer of a live call as it was seen at most: 41 sections, 70 KB
/// (`signaling.go:44-45` gives its answer about 50 KB). What the budget's
/// burst is counted with; no bound hangs on it.
pub const LIVE_OFFER: usize = 72 << 10;

/// What the service channels may hold unacknowledged: commands of a few
/// dozen bytes, so str0m's floor.
pub const SCTP_BUFFERED: usize = 64 << 10;

/// What a TURN relay over TCP reads of a message that is not whole yet
/// (olc-rtc's own figure for it, `turn.rs`: a STUN message's largest size
/// and its header).
const TURN_PARTIAL: usize = 65_556;
/// What the peer connection's own queues hold beside str0m (K9: the peer
/// allocates on the service's `turn:` servers): every relay with its
/// queue of wrapped datagrams full, one read and one message not whole
/// yet; the chunks read from the relays that wait for the driver; what the
/// service channels hold unacknowledged; and the events that wait for the
/// session (one data message at its largest, and the queue's other
/// places).
pub const PEER_HELD: usize = olc_rtc::turn::MAX_ALLOCATIONS
    * (olc_rtc::turn::STREAM_QUEUE * olc_rtc::turn::SEND_BUF
        + olc_rtc::turn::STREAM_READ
        + TURN_PARTIAL)
    + olc_rtc::turn::STREAM_INBOUND * olc_rtc::turn::STREAM_READ
    + SCTP_BUFFERED
    + olc_rtc::peer::INBOUND_BYTES
    + olc_rtc::peer::EVENT_QUEUE * 128;

/// The longest session id an offer may name. Not in Go, which keeps
/// whatever the notification holds: the id is kept for the attempt, and
/// the socket's bound alone would let it be [`READ_LIMIT`] long. The
/// service's are a few dozen bytes. An offer with a longer one is not
/// answered: a first offer fails the join, a later one asks a rejoin.
pub const MAX_SESSION_ID: usize = 256;
/// The longest join link a session is made with (as MTS Link's): the link
/// is kept for the session, to ask the provider again with.
pub const MAX_ROOM_LINK: usize = 2048;
/// The longest guest name (as MTS Link's), kept beside the link.
pub const MAX_NAME: usize = 256;
/// What a session keeps for its life to join again with: the endpoint and
/// the ICE servers of the next join (the provider's bounds on them, which
/// direct credentials are held to as well), and what the provider is asked
/// again with (the link, the name, an account token and a test's base,
/// each bounded before it is kept), and the handshake's three headers.
/// While a join dials, the endpoint and the ICE servers are alive once
/// more.
pub const KEPT_HELD: usize =
    auth::TOKEN_MAX + auth::ICE_JSON_MAX + 3 * MAX_ROOM_LINK + MAX_NAME + 512;

/// What the log says when a bound of ours is what refused an offer: an
/// offer that is not answered fails the join or asks a rejoin, the SFU
/// offers the same again, and the run that meets it must be told which
/// bound it was. `bound` names the constant; no room data is in the line.
fn offer_bound_line(bound: &str) -> String {
    format!("vkcalls: bound {bound} refused the offer")
}

/// Says in the log which bound refused `offer`, when `error` is a bound's
/// refusal ([`ShapeError::SdpTooLarge`] stands for three of them).
fn note_refused(error: &NegotiateError, offer: &str) {
    let too_large = matches!(
        error,
        NegotiateError::Shape(ShapeError::SdpTooLarge)
            | NegotiateError::View(ViewError::Shape(ShapeError::SdpTooLarge))
    );
    if !too_large || !olc_net::log::verbose() {
        return;
    }
    let line = match breached(offer) {
        Some(bound) => offer_bound_line(&bound.to_string()),
        // The offer itself is within the bounds: a text made of it (its
        // view, the stack's answer) is what was past one.
        None => {
            offer_bound_line("MAX_SDP_SIZE, MAX_SDP_SECTIONS or MAX_SDP_LINES (a text made of it)")
        }
    };
    olc_net::debug!("{line}");
}

/// The line for an offer whose session id is past [`MAX_SESSION_ID`].
fn session_id_line() -> String {
    offer_bound_line(&format!("MAX_SESSION_ID ({MAX_SESSION_ID} bytes)"))
}

/// Why a session did not join. The texts are Go's as far as they go; none
/// names the room, the endpoint or a token.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `ErrSessionClosed`.
    #[error("vkcalls: session closed")]
    Closed,
    /// `ErrNoEndpoint`.
    #[error("vkcalls: signaling endpoint missing")]
    NoEndpoint,
    /// `ErrOfferTimeout`.
    #[error("vkcalls: no producer offer arrived")]
    OfferTimeout,
    /// `ErrConnectTimeout`.
    #[error("vkcalls: peer connection did not connect")]
    ConnectTimeout,
    /// The signalling socket's.
    #[error(transparent)]
    Signaling(#[from] SignalingError),
    /// The negotiation's.
    #[error(transparent)]
    Negotiate(#[from] NegotiateError),
    /// The provider refused the first guest (`builtin.ErrAuthFailed`).
    #[error("auth provider rejected the request: {0}")]
    Auth(auth::Error),
    /// The provider refused a rejoin's guest.
    #[error("refresh credentials: auth provider rejected the request: {0}")]
    Refresh(auth::Error),
    /// The join's time ran out in a step that has no timer of its own, or
    /// before the step's own: Go's context deadline, behind the words Go
    /// puts in front of it for that step.
    #[error("{0}: context deadline exceeded")]
    Deadline(String),
    /// Not in Go: the run's join budget is spent (the gate's `max_joins`).
    #[error("vkcalls join budget spent: {0} joins")]
    JoinBudget(u32),
    /// Not in Go: what the session would have to keep is longer than its
    /// bound ([`MAX_ROOM_LINK`], [`MAX_NAME`], the provider's bounds on an
    /// endpoint and on the ICE servers, [`MAX_SESSION_ID`]). The text
    /// names which, never the value.
    #[error("vkcalls: {0} is past its bound")]
    Bound(&'static str),
}

/// The waits of a join and the perf report's interval. The defaults are
/// Go's; a test names its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waits {
    /// [`OFFER_WAIT`].
    pub offer: Duration,
    /// [`CONNECT_WAIT`].
    pub connect: Duration,
    /// [`PERF_STAT_INTERVAL`].
    pub perf: Duration,
    /// [`CONNECT_BOUND`].
    pub join: Duration,
}

impl Default for Waits {
    fn default() -> Self {
        Waits {
            offer: OFFER_WAIT,
            connect: CONNECT_WAIT,
            perf: PERF_STAT_INTERVAL,
            join: CONNECT_BOUND,
        }
    }
}

/// The time one join has (Go's context under `Connect`).
#[derive(Debug, Clone, Copy)]
struct Bound {
    at: tokio::time::Instant,
    /// A first join: every step ends at `at`. A rejoin: the wait for
    /// SERVER topology alone.
    whole: bool,
}

impl Bound {
    fn first(wait: Duration) -> Self {
        Bound {
            at: tokio::time::Instant::now() + wait,
            whole: true,
        }
    }

    fn rejoin(wait: Duration) -> Self {
        Bound {
            at: tokio::time::Instant::now() + wait,
            whole: false,
        }
    }

    /// Resolves when a step with a timer of its own is out of the join's
    /// time: never in a rejoin.
    async fn step(self) {
        if self.whole {
            tokio::time::sleep_until(self.at).await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    /// Resolves when the wait for SERVER topology is out of time.
    async fn topology(self) {
        tokio::time::sleep_until(self.at).await;
    }

    fn spent(self) -> bool {
        tokio::time::Instant::now() >= self.at
    }
}

/// What a session is made of.
#[derive(Clone)]
pub struct Settings {
    /// What the provider issued for the first join (`engine.Credentials`).
    pub credentials: Credentials,
    /// Issues a fresh guest's credentials (`cfg.Refresh`): asked before
    /// every rejoin and for every recruited guest. Without one a rejoin
    /// uses the endpoint it has and a fresh room is not flipped.
    pub issue: Option<Issue>,
    /// The address the peer's socket binds and its host candidate names.
    pub host_ip: IpAddr,
    /// Relayed candidates only.
    pub relay_only: bool,
    /// The duration each sample the transport writes stands for.
    pub frame_interval: Duration,
    /// The most joins the process may start, rejoins included; 0 is no
    /// limit.
    pub max_joins: u32,
    /// The handshake headers of the signalling sockets.
    pub headers: Headers,
    /// The recruiter's pauses.
    pub delays: Delays,
    /// The join's waits.
    pub waits: Waits,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("credentials", &self.credentials)
            .field("issue", &self.issue.is_some())
            .field("host_ip", &self.host_ip)
            .field("relay_only", &self.relay_only)
            .field("frame_interval", &self.frame_interval)
            .field("max_joins", &self.max_joins)
            .field("waits", &self.waits)
            .finish_non_exhaustive()
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// The readers.

struct Slot {
    ssrc: u32,
    /// The readers' clock when a packet last came for this one.
    fed: u64,
    reader: TrackReader,
}

/// The remote tracks' readers (`handleRemoteTrack`, `readVP8Track`): one
/// per SSRC, made on the first packet whose payload type is VP8's or
/// video `red`'s (pion makes a track of the first packet's codec, and the
/// transport reads `video/VP8` and `video/red` and drains the rest), kept
/// for the attempt, [`READERS_MAX`] at most.
pub(crate) struct Readers {
    vp8: u8,
    red: Option<u8>,
    slots: Vec<Slot>,
    clock: u64,
}

impl Readers {
    /// Readers for an attempt whose stack names VP8 `vp8` and video `red`
    /// `red`.
    pub(crate) fn new(vp8: u8, red: Option<u8>) -> Self {
        Readers {
            vp8,
            red,
            slots: Vec::new(),
            clock: 0,
        }
    }

    /// How many readers there are.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// The bytes the readers hold, in capacities ([`READER_HELD`] each at
    /// most).
    pub(crate) fn held_bytes(&self) -> usize {
        self.slots.iter().map(|s| s.reader.held_bytes()).sum()
    }

    /// One RTP packet the SFU sent; `on_frame` takes each frame it
    /// completes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push(
        &mut self,
        ssrc: u32,
        seq: u16,
        marker: bool,
        payload_type: u8,
        payload: &[u8],
        now: Instant,
        on_frame: &mut dyn FnMut(&[u8]),
    ) {
        if payload.len() > MAX_PACKET_PAYLOAD {
            return;
        }
        self.clock += 1;
        let at = match self.slots.iter().position(|slot| slot.ssrc == ssrc) {
            Some(at) => at,
            None => {
                let mime = if payload_type == self.vp8 {
                    MIME_VP8
                } else if Some(payload_type) == self.red {
                    MIME_RED
                } else {
                    // A track of another codec is drained.
                    return;
                };
                let Some(reader) = TrackReader::new(Carrier::Vp8, mime) else {
                    return;
                };
                let slot = Slot {
                    ssrc,
                    fed: self.clock,
                    reader,
                };
                if self.slots.len() < READERS_MAX {
                    self.slots.push(slot);
                    self.slots.len() - 1
                } else {
                    let oldest = self
                        .slots
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, slot)| slot.fed)
                        .map_or(0, |(at, _)| at);
                    self.slots[oldest] = slot;
                    oldest
                }
            }
        };
        let slot = &mut self.slots[at];
        slot.fed = self.clock;
        slot.reader
            .push(seq, marker, payload_type, payload, now, on_frame);
    }
}

// ---------------------------------------------------------------------------
// One attempt.

/// What a peer connection's state means to the attempt it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing to do.
    Nothing,
    /// The peer connection is up.
    Up,
    /// It failed or closed before it ever connected: the join ends with
    /// [`Error::ConnectTimeout`], and no rejoin is asked for (plan D5).
    JoinFailed,
    /// It failed or closed after it had connected: a rejoin is asked for.
    Rejoin,
}

/// The verdict for a peer connection that moved to `pc`, having been
/// connected before or not.
pub(crate) fn verdict(pc: PcState, was_connected: bool) -> Verdict {
    match pc {
        PcState::Connected => Verdict::Up,
        PcState::Failed | PcState::Closed if was_connected => Verdict::Rejoin,
        PcState::Failed | PcState::Closed => Verdict::JoinFailed,
        PcState::New | PcState::Connecting | PcState::Disconnected => Verdict::Nothing,
    }
}

/// Everything one connection attempt owns (`generation`): tearing it down
/// leaves nothing of the attempt (spec 7.3: state never crosses
/// generations).
struct Generation {
    id: u64,
    signal: Signaling,
    peer: Peer,
    notification: ChannelId,
    command: ChannelId,
    /// The registry, the participants and the command counter.
    control: Mutex<ControlState>,
    /// `producerCommand` is open.
    command_open: AtomicBool,
    /// The session the last answered offer belonged to.
    session_id: Mutex<String>,
    /// The attempt was torn down (`done`): what it says after that says
    /// nothing about the session.
    done: AtomicBool,
    /// The peer connection is `connected` now.
    connected: AtomicBool,
    /// `Some(true)` once the peer connection connected, `Some(false)` when
    /// it failed first.
    first: watch::Sender<Option<bool>>,
    tasks: Mutex<Vec<AbortHandle>>,
    /// The watch of the peer's events, which says the peer connection's
    /// states: a teardown waits for it to have said the last one.
    watching: Mutex<Option<JoinHandle<()>>>,
    /// The perf report's task: the one that is stopped, not left to end.
    perf: Mutex<Option<AbortHandle>>,
}

impl Generation {
    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Writes one command on `producerCommand`, fire and forget as Go's
    /// `Send`.
    fn send(&self, what: &str, frame: &[u8]) {
        match self.peer.write(self.command, true, frame) {
            Ok(true) => {}
            Ok(false) => olc_net::debug!("vkcalls: {what}: the command channel is full"),
            Err(e) => olc_net::debug!("vkcalls: {what}: {e}"),
        }
    }

    /// `producerCommand` opened (`command.OnOpen`): the layer we publish is
    /// configured first (without it the SFU accepts the stream and forwards
    /// nothing, and the command is fire and forget, so the mistake is
    /// silent), then everything known is asked for.
    fn command_opened(&self) {
        self.command_open.store(true, Ordering::Release);
        let frame = locked(&self.control).change_simulcast();
        self.send("change-simulcast", &frame);
        self.subscribe_all();
    }

    /// `subscribeAll`: the layout for every registry stream and every
    /// participant's camera. The counter advances whether or not anything
    /// goes out.
    fn subscribe_all(&self) {
        let (frame, known, people) = {
            let mut control = locked(&self.control);
            let frame = control.layout();
            (
                frame,
                control.registry().iter().count(),
                control.participants().count(),
            )
        };
        match frame {
            Ok(None) => olc_net::debug!(
                "vkcalls: layout: nothing to ask for ({known} streams, {people} participants known)"
            ),
            Ok(Some(frame)) => {
                olc_net::debug!(
                    "vkcalls: layout of {} bytes ({known} streams, {people} participants known), channel {}",
                    frame.len(),
                    if self.command_open.load(Ordering::Acquire) { "open" } else { "not open" }
                );
                if self.command_open.load(Ordering::Acquire) {
                    self.send("layout", &frame);
                }
            }
            Err(e) => olc_net::debug!("vkcalls: layout encode: {e}"),
        }
    }

    /// `onServiceFrame`: a registry frame is folded in and the layout sent
    /// again.
    fn service_frame(&self, frame: &[u8]) {
        let read = locked(&self.control).on_service_frame(frame);
        match read {
            Ok(0) | Err(RegistryError::NotRegistry) => {}
            Ok(_) => self.subscribe_all(),
            Err(e) => olc_net::debug!("vkcalls: registry frame: {e}"),
        }
    }

    /// One perf report (`perfStatLoop`'s body): nothing in the stack
    /// decodes, so both values are the video packets received.
    fn report_perf(&self) {
        if !self.command_open.load(Ordering::Acquire) {
            return;
        }
        // Go adds up `uint32` counters: the sum wraps the same way.
        #[allow(clippy::cast_possible_truncation)]
        let received = self.peer.video_packets_in() as u32;
        let frame = locked(&self.control).perf_stat(received);
        self.send("perf stat", &frame);
    }

    /// Stops the attempt's tasks at once (a session dropped unclosed).
    fn abort(&self) {
        self.done.store(true, Ordering::Release);
        for task in locked(&self.tasks).drain(..) {
            task.abort();
        }
        if let Some(task) = locked(&self.perf).take() {
            task.abort();
        }
    }
}

/// The media of the current attempt.
struct Media {
    /// The attempt the rest belongs to.
    gen: u64,
    negotiation: Option<Negotiation>,
    /// The peer connection came up: packets can go.
    up: bool,
    /// The track's packetizer (`TrackLocalStaticSample`), the session's.
    packetizer: Packetizer,
}

/// The endpoint and the ICE servers of the next join; wiped when replaced
/// or dropped.
struct Creds {
    endpoint: String,
    ice_servers: String,
}

impl Creds {
    fn of(credentials: &Credentials) -> Self {
        Creds {
            endpoint: credentials.url.clone(),
            ice_servers: credentials.ice_servers.clone(),
        }
    }
}

impl Drop for Creds {
    fn drop(&mut self) {
        self.endpoint.zeroize();
        self.ice_servers.zeroize();
    }
}

/// Joins this process started under a budget ([`Settings::max_joins`]), as
/// SaluteJazz counts them: a join counts at its dial.
static BUDGETED_JOINS: AtomicU32 = AtomicU32::new(0);

fn take_join(max: u32) -> Result<(), Error> {
    if max == 0 {
        return Ok(());
    }
    if BUDGETED_JOINS.fetch_add(1, Ordering::AcqRel) >= max {
        return Err(Error::JoinBudget(max));
    }
    Ok(())
}

/// A VK Calls session: `engine.Session` over one SERVER conversation.
pub struct Session {
    creds: Mutex<Creds>,
    issue: Option<Issue>,
    host_ip: IpAddr,
    relay_only: bool,
    frame_ns: i64,
    max_joins: u32,
    headers: Headers,
    delays: Delays,
    waits: Waits,
    /// The published track's ids (`common.NewVideoTrack`), the session's.
    track: TrackIds,
    closed: AtomicBool,
    ended: AtomicBool,
    reconnecting: AtomicBool,
    /// The supervisor runs ([`Session::supervise`]).
    supervised: AtomicBool,
    /// `closeCh`: true once the session is closed or has ended.
    stop: watch::Sender<bool>,
    /// The joins and rejoins under way: a close waits for them to have
    /// left.
    joining: watch::Sender<usize>,
    gen_no: AtomicU64,
    gen: Mutex<Option<Arc<Generation>>>,
    media: Mutex<Media>,
    on_frame: Arc<Mutex<Option<FrameHandler>>>,
    /// What the readers of the attempt's sink hold (the memory line).
    rtp_held: HeldGauge,
    events: mpsc::Sender<EngineEvent>,
    reconnector: Arc<Reconnector>,
    /// Rejoin requests that took the supervisor's slot.
    rejoins_queued: AtomicU64,
    /// RTP packets written.
    rtp_out: AtomicU64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("generation", &self.gen_no.load(Ordering::Relaxed))
            .field("can_send", &self.can_send())
            .finish_non_exhaustive()
    }
}

/// The session as the supervisor rejoins it. It holds the session weakly:
/// a session nobody holds any more is not rejoined.
struct Rejoiner(Weak<Session>);

impl Rejoin for Rejoiner {
    type Error = Error;

    async fn rejoin(&self) -> Result<(), Error> {
        let Some(session) = self.0.upgrade() else {
            return Err(Error::Closed);
        };
        session.rejoin().await
    }

    fn failed(&self, err: &Error) {
        olc_net::info!("vkcalls: reconnect failed: {err}");
    }

    fn limit_reached(&self, reason: &str) {
        if let Some(session) = self.0.upgrade() {
            session.signal_ended(reason);
        }
    }
}

/// Ends the session when the task that holds it panics: a supervisor or a
/// notification loop that unwound would otherwise leave a session that
/// serves no request and says no `Ended`. A task that returns, or is
/// aborted by a teardown, says nothing here.
struct Fallen {
    session: Weak<Session>,
    task: &'static str,
}

impl Drop for Fallen {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        if let Some(session) = self.session.upgrade() {
            olc_net::debug!("vkcalls: {} panicked: the session ends", self.task);
            session.signal_ended(TASK_FAILED);
        }
    }
}

/// One join or rejoin under way, counted for the close.
struct Joining<'a>(&'a watch::Sender<usize>);

impl<'a> Joining<'a> {
    fn begin(count: &'a watch::Sender<usize>) -> Self {
        count.send_modify(|n| *n += 1);
        Joining(count)
    }
}

impl Drop for Joining<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// The first `producer-updated` that carries a description (`waitOffer`).
/// Whatever else is read on the way is let go, as Go does (plan D6).
async fn wait_offer(
    notes: &mut Notifications,
    wait: Duration,
    stop: impl Future<Output = ()>,
) -> Option<Notification> {
    let deadline = tokio::time::sleep(wait);
    tokio::pin!(deadline, stop);
    loop {
        tokio::select! {
            biased;
            note = notes.recv() => match note {
                Some(note)
                    if note.notification == "producer-updated" && !note.description.is_empty() =>
                {
                    return Some(note);
                }
                Some(_) => {}
                None => return None,
            },
            () = &mut deadline => return None,
            () = &mut stop => return None,
        }
    }
}

/// One command and its response, bounded over the write and the wait.
async fn command(signal: &Signaling, name: &str, payload: &Json<'_>) -> Result<(), Error> {
    match tokio::time::timeout(COMMAND_BOUND, signal.command(name, payload)).await {
        Ok(answered) => answered.map(|_| ()).map_err(Error::from),
        Err(_) => Err(SignalingError::Timeout(name.to_owned()).into()),
    }
}

impl Session {
    /// A session for `settings`, not joined yet, with its news. Its rejoin
    /// requests are served once [`Session::supervise`] is called, after the
    /// first join.
    ///
    /// # Errors
    ///
    /// [`Error::NoEndpoint`].
    pub fn new(settings: Settings) -> Result<(Arc<Self>, mpsc::Receiver<EngineEvent>), Error> {
        if settings.credentials.url.is_empty() {
            return Err(Error::NoEndpoint);
        }
        // The provider's own bounds on what it issues; direct credentials
        // are held to them as well, since both are kept ([`KEPT_HELD`]).
        if settings.credentials.url.len() > auth::TOKEN_MAX {
            return Err(Error::Bound("the endpoint"));
        }
        if settings.credentials.ice_servers.len() > auth::ICE_JSON_MAX {
            return Err(Error::Bound("the ICE servers' text"));
        }
        let (events, news) = mpsc::channel(EVENT_QUEUE);
        let reconnector = Arc::new(Reconnector::new(MAX_RECONNECTS, LIMIT_REASON));
        let frame_ns = i64::try_from(settings.frame_interval.as_nanos()).unwrap_or(i64::MAX);
        let session = Arc::new(Session {
            creds: Mutex::new(Creds::of(&settings.credentials)),
            issue: settings.issue,
            host_ip: settings.host_ip,
            relay_only: settings.relay_only,
            frame_ns,
            max_joins: settings.max_joins,
            headers: settings.headers,
            delays: settings.delays,
            waits: settings.waits,
            track: TrackIds::random(),
            closed: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            reconnecting: AtomicBool::new(false),
            supervised: AtomicBool::new(false),
            stop: watch::Sender::new(false),
            joining: watch::Sender::new(0),
            gen_no: AtomicU64::new(0),
            gen: Mutex::new(None),
            media: Mutex::new(Media {
                gen: 0,
                negotiation: None,
                up: false,
                packetizer: Packetizer::random(Payloader::Vp8(Vp8Payloader::with_picture_id(0))),
            }),
            on_frame: Arc::new(Mutex::new(None)),
            rtp_held: HeldGauge::default(),
            events,
            reconnector,
            rejoins_queued: AtomicU64::new(0),
            rtp_out: AtomicU64::new(0),
        });
        Ok((session, news))
    }

    /// `WatchConnection`: serves the session's rejoin requests on a task
    /// of its own until the session is closed, ends or is dropped. Called
    /// after the first join, as Go's caller does: a request raised while
    /// that join ran (its peer connection came up and went) waits in the
    /// supervisor's slot until then, so no rejoin runs beside the join. A
    /// second call does nothing. Call it on a tokio runtime.
    pub fn supervise(self: &Arc<Self>) {
        if self.supervised.swap(true, Ordering::AcqRel) {
            return;
        }
        let reconnector = Arc::clone(&self.reconnector);
        let rejoiner = Rejoiner(Arc::downgrade(self));
        let stopped = self.stopped();
        let fallen = Fallen {
            session: Arc::downgrade(self),
            task: "the rejoin supervisor",
        };
        tokio::spawn(async move {
            let _fallen = fallen;
            reconnector.watch(&rejoiner, stopped).await;
        });
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Resolves once the session is closed, has ended or is gone.
    fn stopped(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut stop = self.stop.subscribe();
        async move {
            let _ = stop.wait_for(|stopped| *stopped).await;
        }
    }

    /// The peer connection's settings for an attempt whose provider named
    /// the ICE servers `ice_servers`: the service's `turn:` servers (plan
    /// K9), IPv4 over UDP as Go's engine.
    fn peer_config(&self, ice_servers: &str) -> PeerConfig {
        PeerConfig {
            name: "vkcalls",
            crypto: olc_rtc::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: self.host_ip,
            sctp_max_buffered: SCTP_BUFFERED,
            turn: turn_servers(&ice_servers_of(ice_servers)),
            relay_only: self.relay_only,
            ice_mode: IceMode::Udp,
        }
    }

    /// Joins the conversation and brings the peer connection up with an
    /// active subscription (`Connect`), within [`CONNECT_BOUND`] as a
    /// whole. Whatever fails, the signalling socket hangs up before the
    /// error is returned.
    ///
    /// # Errors
    ///
    /// [`Error`].
    pub async fn connect(self: &Arc<Self>) -> Result<(), Error> {
        self.join_room(Bound::first(self.waits.join)).await
    }

    /// One step of a join that has a timer of its own, cut short by the
    /// session's stop or by the join's time; `step` names it as Go does in
    /// front of its context's error.
    async fn stepped<T>(
        &self,
        bound: Bound,
        step: impl FnOnce() -> String,
        doing: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        tokio::select! {
            biased;
            done = doing => done,
            () = self.stopped() => Err(Error::Closed),
            () = bound.step() => Err(Error::Deadline(step())),
        }
    }

    /// One command of a join ([`command`]) as a step of it.
    async fn ask(
        &self,
        bound: Bound,
        signal: &Signaling,
        name: &str,
        payload: &Json<'_>,
    ) -> Result<(), Error> {
        self.stepped(
            bound,
            || format!("vkcalls: signaling {name}"),
            command(signal, name, payload),
        )
        .await
    }

    /// `Connect` under `bound`: [`Session::connect`]'s and
    /// [`Session::rejoin`]'s.
    async fn join_room(self: &Arc<Self>, bound: Bound) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        take_join(self.max_joins)?;
        let _joining = Joining::begin(&self.joining);
        let (endpoint, ice_servers) = {
            let creds = locked(&self.creds);
            (
                Zeroizing::new(creds.endpoint.clone()),
                Zeroizing::new(creds.ice_servers.clone()),
            )
        };
        let dialed = self
            .stepped(bound, || "vkcalls: signaling dial".to_owned(), async {
                Signaling::dial(&endpoint, self.headers.options())
                    .await
                    .map_err(Error::from)
            })
            .await;
        drop(endpoint);
        let (signal, mut notes) = dialed?;

        let entered = self.enter(bound, &signal, &mut notes).await;
        let (connection, offer) = match entered {
            Ok(entered) => entered,
            Err(e) => {
                signal.close().await;
                return Err(e);
            }
        };
        if offer.session_id.len() > MAX_SESSION_ID {
            olc_net::debug!("{}", session_id_line());
            signal.close().await;
            return Err(Error::Bound("the offer's session id"));
        }
        let config = self.peer_config(&ice_servers);
        drop(ice_servers);
        let opened = match Negotiation::open(&offer.description, &config, &self.track) {
            Ok(opened) => opened,
            Err(e) => {
                note_refused(&e, &offer.description);
                signal.close().await;
                return Err(e.into());
            }
        };
        drop(config);
        let Opened {
            negotiation,
            events,
            answer,
        } = opened;
        if !negotiation.size_resends(ResendCache {
            packets: RESEND_PACKETS,
            age: RESEND_AGE,
            ratio_cap: RESEND_RATIO_CAP,
        }) {
            olc_net::debug!("vkcalls: no publish stream to size the resends of");
        }

        let gen = Arc::new(Generation {
            id: self.gen_no.fetch_add(1, Ordering::AcqRel) + 1,
            signal,
            peer: negotiation.peer().clone(),
            notification: negotiation.notification_channel(),
            command: negotiation.command_channel(),
            control: Mutex::new(ControlState::new()),
            command_open: AtomicBool::new(false),
            session_id: Mutex::new(offer.session_id.clone()),
            done: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            first: watch::Sender::new(None),
            tasks: Mutex::new(Vec::new()),
            watching: Mutex::new(None),
            perf: Mutex::new(None),
        });
        self.read_tracks(&negotiation);
        let replaced = {
            let mut media = locked(&self.media);
            media.gen = gen.id;
            media.up = false;
            media.negotiation.replace(negotiation)
        };
        drop(replaced);
        let watching = tokio::spawn(watch_peer(Arc::downgrade(self), Arc::clone(&gen), events));
        locked(&gen.tasks).push(watching.abort_handle());
        *locked(&gen.watching) = Some(watching);

        let accepted = self
            .ask(
                bound,
                &gen.signal,
                "accept-producer",
                &accept_producer(&offer.description, &answer, &offer.session_id),
            )
            .await;
        // Neither text is kept while the peer connection is waited for.
        drop(answer);
        drop(offer);
        let joined = match accepted {
            Ok(()) => self.await_connected(&gen, bound).await,
            Err(e) => Err(e),
        };
        if let Err(e) = joined {
            self.teardown(&gen).await;
            return Err(e);
        }

        *locked(&self.gen) = Some(Arc::clone(&gen));
        let perf = tokio::spawn(perf_loop(Arc::clone(&gen), self.waits.perf));
        *locked(&gen.perf) = Some(perf.abort_handle());
        let running = tokio::spawn(run(
            Arc::downgrade(self),
            Arc::clone(&gen),
            notes,
            connection,
        ));
        locked(&gen.tasks).push(running.abort_handle());
        if self.is_closed() {
            // Closed while the join ran: nothing of it stays.
            let mine = {
                let mut current = locked(&self.gen);
                if current.as_ref().is_some_and(|g| g.id == gen.id) {
                    current.take()
                } else {
                    None
                }
            };
            if let Some(gen) = mine {
                self.teardown(&gen).await;
            }
            return Err(Error::Closed);
        }
        Ok(())
    }

    /// The signalling half of a join, up to the offer: the `connection`
    /// notification and the offer it ends with.
    async fn enter(
        &self,
        bound: Bound,
        signal: &Signaling,
        notes: &mut Notifications,
    ) -> Result<(Notification, Notification), Error> {
        // The guests the wait recruited have hung up when it returns, so
        // it is told to stop and never dropped in the middle.
        let stop = async {
            tokio::select! {
                biased;
                () = self.stopped() => {}
                () = bound.topology() => {}
            }
        };
        let connection =
            wait_connected(notes, self.issue.clone(), &self.headers, self.delays, stop)
                .await
                .map_err(|e| self.stopped_wait(bound, e))?;
        self.ask(
            bound,
            signal,
            "allocate-consumer",
            &allocate_consumer(&REFERENCE_CAPABILITIES),
        )
        .await?;
        self.ask(
            bound,
            signal,
            "update-media-modifiers",
            &update_media_modifiers(),
        )
        .await?;
        // Go's `waitOffer` returns nothing when its context ends: the
        // same error as its own timer's.
        let stop = async {
            tokio::select! {
                biased;
                () = self.stopped() => {}
                () = bound.step() => {}
            }
        };
        let offer = wait_offer(notes, self.waits.offer, stop)
            .await
            .ok_or(Error::OfferTimeout)?;
        self.ask(
            bound,
            signal,
            "change-media-settings",
            &change_media_settings(),
        )
        .await?;
        Ok((connection, offer))
    }

    /// Why [`wait_connected`] ended when it was told to stop: the
    /// session's close, or the join's time, said as Go says its context's
    /// deadline in that wait.
    fn stopped_wait(&self, bound: Bound, error: SignalingError) -> Error {
        let step = match error {
            SignalingError::NotServer => "vkcalls: conversation is not in SERVER topology",
            SignalingError::JoinStopped => "vkcalls: connection wait",
            other => return other.into(),
        };
        if self.is_closed() {
            Error::Closed
        } else if bound.spent() {
            Error::Deadline(step.to_owned())
        } else {
            error.into()
        }
    }

    /// The remote tracks of `negotiation`'s peer go to their readers, and
    /// the frames they complete to the transport.
    fn read_tracks(&self, negotiation: &Negotiation) {
        let mut readers = Readers::new(negotiation.publish_pt(), negotiation.red_pt());
        let held = self.rtp_held.guard();
        let on_frame = Arc::clone(&self.on_frame);
        let mut first = true;
        let mut seen_pts: Vec<u8> = Vec::new();
        olc_net::debug!(
            "vkcalls: reading the call's media: video pt {:?}, red pt {:?}",
            negotiation.publish_pt(),
            negotiation.red_pt()
        );
        let mut frames = 0u32;
        negotiation
            .peer()
            .set_rtp_sink(Some(Box::new(move |packet: &RtpPacket| {
                let pt = *packet.header.payload_type;
                if !seen_pts.contains(&pt) && seen_pts.len() < 8 {
                    seen_pts.push(pt);
                    olc_net::debug!(
                        "vkcalls: first media from the call with pt {pt}: ssrc {}{}",
                        *packet.header.ssrc,
                        if first { " (the first packet)" } else { "" }
                    );
                }
                first = false;
                let handler = locked(&on_frame).clone();
                let Some(handler) = handler else { return };
                readers.push(
                    *packet.header.ssrc,
                    packet.header.sequence_number,
                    packet.header.marker,
                    *packet.header.payload_type,
                    &packet.payload,
                    Instant::now(),
                    &mut |frame| {
                        frames += 1;
                        if frames == 1 || frames == 50 {
                            olc_net::debug!(
                                "vkcalls: video frame {frames} off the call, {} bytes",
                                frame.len()
                            );
                        }
                        handler(frame);
                    },
                );
                held.set(readers.held_bytes());
            })));
    }

    /// Waits for the attempt's peer connection: connected within the
    /// wait, or the join has failed. A peer connection that fails before
    /// it connected ends the wait at once (plan D5).
    async fn await_connected(&self, gen: &Generation, bound: Bound) -> Result<(), Error> {
        let mut first = gen.first.subscribe();
        let settled = first.wait_for(Option::is_some);
        tokio::select! {
            biased;
            outcome = settled => match outcome.map(|outcome| *outcome) {
                Ok(Some(true)) => Ok(()),
                _ => Err(Error::ConnectTimeout),
            },
            () = tokio::time::sleep(self.waits.connect) => Err(Error::ConnectTimeout),
            () = self.stopped() => Err(Error::Closed),
            () = bound.step() => Err(Error::Deadline("vkcalls: connect wait".to_owned())),
        }
    }

    /// Tears one attempt down whole (`teardown`): its loops, its peer
    /// connection, and its signalling socket after the hangup.
    async fn teardown(&self, gen: &Generation) {
        gen.done.store(true, Ordering::Release);
        gen.connected.store(false, Ordering::Release);
        if let Some(perf) = locked(&gen.perf).take() {
            perf.abort();
        }
        let negotiation = {
            let mut media = locked(&self.media);
            if media.gen == gen.id {
                media.up = false;
                media.negotiation.take()
            } else {
                None
            }
        };
        gen.peer.set_rtp_sink(None);
        drop(negotiation);
        gen.peer.close();
        // The notification loop ends with the socket, the peer's with its
        // driver: neither is cut off in the middle of a frame.
        gen.signal.close().await;
    }

    /// The peer connection of `gen` moved (`OnConnectionStateChange`).
    fn moved(&self, gen: &Generation, pc: PcState, was_connected: bool) {
        gen.connected
            .store(pc == PcState::Connected, Ordering::Release);
        match verdict(pc, was_connected) {
            Verdict::Nothing => {}
            Verdict::Up => {
                {
                    let mut media = locked(&self.media);
                    if media.gen == gen.id {
                        media.up = true;
                    }
                }
                gen.first.send_if_modified(|first| {
                    let unset = first.is_none();
                    if unset {
                        *first = Some(true);
                    }
                    unset
                });
            }
            Verdict::JoinFailed => {
                gen.first.send_if_modified(|first| {
                    let unset = first.is_none();
                    if unset {
                        *first = Some(false);
                    }
                    unset
                });
            }
            Verdict::Rejoin => self.reconnect_attempt(gen),
        }
    }

    /// Asks the supervisor for a rejoin on behalf of one attempt
    /// (`reconnectAttempt`). A failure raised by an attempt already torn
    /// down says nothing about the session, so it asks nothing.
    fn reconnect_attempt(&self, gen: &Generation) {
        if self.is_closed() || gen.is_done() {
            return;
        }
        self.request();
    }

    fn request(&self) {
        let asked = self
            .reconnector
            .request(self.is_closed(), self.reconnecting.load(Ordering::Acquire));
        if asked == Asked::Queued {
            self.rejoins_queued.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One rejoin (`reconnect`): the old attempt goes whole, so the SFU
    /// never carries two guests of ours; then a fresh guest's credentials;
    /// then a join from scratch; then the transport is told.
    async fn rejoin(self: &Arc<Self>) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        self.reconnecting.store(true, Ordering::Release);
        let _reconnecting = Reset(&self.reconnecting);
        let _joining = Joining::begin(&self.joining);
        let old = locked(&self.gen).take();
        if let Some(old) = old {
            self.teardown(&old).await;
        }
        if let Some(issue) = &self.issue {
            // Nothing of the new guest is in the call yet: a close gives
            // the chain up where it is.
            let credentials = tokio::select! {
                biased;
                issued = issue() => issued.map_err(Error::Refresh)?,
                () = self.stopped() => return Err(Error::Closed),
            };
            *locked(&self.creds) = Creds::of(&credentials);
        }
        self.join_room(Bound::rejoin(self.waits.join)).await?;
        // The transport restarts its planes over the rebuilt carrier when
        // it hears this.
        let _ = self.events.try_send(EngineEvent::Reconnected);
        Ok(())
    }

    /// Ends the session for good (`signalEnded`): the verdict is about the
    /// room, so no rejoin follows, and the supervisor stops with it.
    fn signal_ended(&self, reason: &str) {
        // Closed first: whoever reads `Ended` finds the session closed.
        let first = !self.ended.swap(true, Ordering::AcqRel);
        self.closed.store(true, Ordering::Release);
        self.stop.send_replace(true);
        if first {
            let _ = self.events.try_send(EngineEvent::Ended(reason.to_owned()));
        }
    }

    /// Leaves the conversation and frees the peer connection (`Close`). A
    /// closed session refuses every later rejoin request.
    ///
    /// A join or a rejoin under way is told to stop and waited for
    /// (a few seconds at most): its guest has hung up when this returns,
    /// so a process that exits after the close leaves nobody in the call.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.stop.send_replace(true);
        let mut joining = self.joining.subscribe();
        let _ = tokio::time::timeout(LEAVE_WAIT, joining.wait_for(|n| *n == 0)).await;
        let gen = locked(&self.gen).take();
        if let Some(gen) = gen {
            self.teardown(&gen).await;
            // pion's Close returns once the peer connection is closed and
            // has said so: a stopping client's log ends with `peer
            // connection state changed: closed`, which the apps read. The
            // peer bounds its own goodbyes ([`olc_rtc::peer::CLOSE_DRAIN`]);
            // the margin here only keeps a stuck driver from holding the
            // close. A rejoin's teardown does not wait: the next join
            // starts at once, as Go's does.
            let watching = locked(&gen.watching).take();
            let _ = tokio::time::timeout(olc_rtc::peer::CLOSE_DRAIN + CLOSE_MARGIN, async {
                gen.peer.ended().await;
                if let Some(watching) = watching {
                    let _ = watching.await;
                }
            })
            .await;
        }
        *locked(&self.on_frame) = None;
    }

    /// Rejoin requests that took the supervisor's slot so far.
    #[must_use]
    pub fn rejoins_queued(&self) -> u64 {
        self.rejoins_queued.load(Ordering::Relaxed)
    }

    /// RTP packets written so far.
    #[must_use]
    pub fn rtp_out(&self) -> u64 {
        self.rtp_out.load(Ordering::Relaxed)
    }
}

/// Clears a flag when it goes.
struct Reset<'a>(&'a AtomicBool);

impl Drop for Reset<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Drop for Session {
    /// A session dropped unclosed still leaves: its tasks stop, its peer
    /// closes and its socket hangs up on its own way out.
    fn drop(&mut self) {
        if let Some(gen) = locked(&self.gen).take() {
            gen.abort();
            gen.peer.set_rtp_sink(None);
            gen.peer.close();
        }
    }
}

/// What the peer's watch waits for.
enum Step {
    Event(Option<PeerEvent>),
    Failed(Change),
}

/// The peer's events of one attempt, to their end.
async fn watch_peer(
    session: Weak<Session>,
    gen: Arc<Generation>,
    mut events: mpsc::Receiver<PeerEvent>,
) {
    let mut watcher = PcWatcher::new();
    let mut keyframe_asked = false;
    let mut notified = false;
    let mut notes = 0u32;
    loop {
        let step = tokio::select! {
            event = events.recv() => Step::Event(event),
            change = watcher.failed() => Step::Failed(change),
        };
        // Read before the event is taken in: a `closed` that follows
        // `connected` is a rejoin, one that comes first is the join's end.
        let was_connected = watcher.was_connected();
        let (change, last) = match step {
            Step::Failed(change) => (change, false),
            Step::Event(None) => return,
            Step::Event(Some(event)) => {
                let change = watcher.observe(&event);
                let last = matches!(event, PeerEvent::Closed(_));
                match &event {
                    PeerEvent::ChannelOpen(id, label) => {
                        olc_net::info!("vkcalls: data channel {label:?} open");
                        let _ = id;
                    }
                    PeerEvent::ChannelClose(_) => olc_net::debug!("vkcalls: a data channel closed"),
                    PeerEvent::KeyframeRequest(_) if !keyframe_asked => {
                        keyframe_asked = true;
                        olc_net::debug!("vkcalls: the call asked for a keyframe");
                    }
                    PeerEvent::Data(message)
                        if message.channel == gen.notification && !notified =>
                    {
                        notified = true;
                        olc_net::debug!(
                            "vkcalls: first notification, {} bytes",
                            message.data.len()
                        );
                    }
                    _ => {}
                }
                match event {
                    PeerEvent::ChannelOpen(id, _) if id == gen.command => gen.command_opened(),
                    PeerEvent::ChannelClose(id) if id == gen.command => {
                        gen.command_open.store(false, Ordering::Release);
                    }
                    PeerEvent::Data(message) if message.channel == gen.notification => {
                        if notes < 6 {
                            notes += 1;
                            let head: String = message.data[..message.data.len().min(48)]
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect();
                            olc_net::debug!(
                                "vkcalls: notification {notes}, {} bytes: {head}",
                                message.data.len()
                            );
                        }
                        gen.service_frame(&message.data);
                    }
                    PeerEvent::Data(message) if message.channel == gen.command => {
                        olc_net::debug!(
                            "vkcalls: command reply, {} bytes: {}",
                            message.data.len(),
                            String::from_utf8_lossy(&message.data[..message.data.len().min(160)])
                        );
                    }
                    _ => {}
                }
                (change, last)
            }
        };
        if let Some(pc) = change.pc {
            olc_net::info!("vkcalls: peer connection {pc}");
            match session.upgrade() {
                Some(session) => session.moved(&gen, pc, was_connected),
                None => return,
            }
        }
        if last {
            return;
        }
    }
}

/// Reports the consumer's progress every `every` (`perfStatLoop`).
async fn perf_loop(gen: Arc<Generation>, every: Duration) {
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if gen.is_done() {
            return;
        }
        gen.report_perf();
    }
}

/// Owns the session after a successful join (`run`): the participants, the
/// later offers and the signalling socket's lifetime.
async fn run(
    session: Weak<Session>,
    gen: Arc<Generation>,
    mut notes: Notifications,
    connection: Notification,
) {
    let _fallen = Fallen {
        session: session.clone(),
        task: "the notification loop",
    };
    {
        let others = participant_ids(&connection, gen.signal.self_id());
        olc_net::info!("vkcalls: connected, {} other participants", others.len());
        let mut control = locked(&gen.control);
        for id in &others {
            control.note_participant(id);
        }
    }
    drop(connection);
    gen.subscribe_all();
    while let Some(note) = notes.recv().await {
        match note.notification.as_str() {
            // A camera may appear with either: ask for it by key.
            "participant-joined" | "media-settings-changed" => {
                let Ok(id) = decimal_id(&note.participant_id) else {
                    continue;
                };
                let new = id != gen.signal.self_id() && locked(&gen.control).note_participant(&id);
                if new {
                    gen.subscribe_all();
                }
            }
            "producer-updated" => {
                let known = note.session_id == *locked(&gen.session_id);
                if note.description.is_empty() || known {
                    continue;
                }
                let Some(session) = session.upgrade() else {
                    return;
                };
                if note.session_id.len() > MAX_SESSION_ID {
                    // Not answered and not kept: as an offer that cannot
                    // be answered, the attempt is given up.
                    olc_net::info!("{}", session_id_line());
                    session.reconnect_attempt(&gen);
                    continue;
                }
                locked(&gen.session_id).clone_from(&note.session_id);
                if let Err(e) = session.reanswer(&gen, &note).await {
                    if let Error::Negotiate(refused) = &e {
                        note_refused(refused, &note.description);
                    }
                    olc_net::info!("vkcalls: renegotiation: {e}");
                    session.reconnect_attempt(&gen);
                }
            }
            "hungup" => {
                if let Ok(id) = decimal_id(&note.participant_id) {
                    locked(&gen.control).remove_stream(&id);
                }
            }
            // No input is known to make this loop panic; a test names one.
            #[cfg(test)]
            "olc-test-panic" => panic!("a test asked the notification loop to panic"),
            _ => {}
        }
    }
    // The socket is gone. The supervisor owns the verdict: a rejoin is
    // asked for, and the session only ends through its limit.
    if let Some(session) = session.upgrade() {
        session.reconnect_attempt(&gen);
    }
}

impl Session {
    /// Answers a later offer on the established transport (`reanswer`):
    /// the same shaping and `accept-producer`, no second connect wait.
    async fn reanswer(&self, gen: &Generation, note: &Notification) -> Result<(), Error> {
        let shaped = {
            let mut media = locked(&self.media);
            let media = &mut *media;
            match media.negotiation.as_mut() {
                Some(negotiation) if media.gen == gen.id => {
                    negotiation.reanswer(&note.description)?
                }
                _ => return Err(Error::Closed),
            }
        };
        command(
            &gen.signal,
            "accept-producer",
            &accept_producer(&note.description, &shaped, &note.session_id),
        )
        .await
    }
}

impl Stream for Session {
    /// `track.WriteSample`: one sample, packetized and written on the
    /// publish slot's layer `l` at the slot's VP8 payload type; taken and
    /// dropped while no peer connection is up, as pion's unbound track
    /// does.
    fn write_sample(&self, sample: &[u8]) -> bool {
        let mut media = locked(&self.media);
        let media = &mut *media;
        let Some(negotiation) = media.negotiation.as_mut() else {
            return true;
        };
        if !media.up {
            return true;
        }
        let packets = media.packetizer.packetize(sample, self.frame_ns);
        let written = negotiation.publish(
            Instant::now(),
            packets.into_iter().map(|p| RtpOut {
                seq: p.seq,
                timestamp: p.timestamp,
                marker: p.marker,
                payload: p.payload,
            }),
        );
        if let Some(n) = written {
            let before = self
                .rtp_out
                .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
            if before == 0 && n > 0 {
                olc_net::debug!("vkcalls: first video sent to the call, {n} packets");
            }
        } else if self.rtp_out.load(Ordering::Relaxed) == 0 {
            static ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !ONCE.swap(true, Ordering::Relaxed) {
                olc_net::debug!("vkcalls: the call took no video: no publish line");
            }
        }
        true
    }

    /// `CanSend`: the peer connection is connected.
    fn can_send(&self) -> bool {
        locked(&self.gen)
            .as_ref()
            .is_some_and(|gen| gen.connected.load(Ordering::Acquire))
    }

    /// `SubscriberCanSend`: one bundled peer connection.
    fn subscriber_can_send(&self) -> bool {
        self.can_send()
    }

    /// `Reconnect`: the layer above declared the path dead before the
    /// engine noticed; the supervisor serializes it with the engine's own
    /// requests.
    fn reconnect(&self, reason: &str) {
        if self.is_closed() {
            return;
        }
        olc_net::debug!("vkcalls: reconnect requested: {reason}");
        self.request();
    }
}

impl VideoEngine for Session {
    /// The engine names no codec: vp8channel's default.
    fn carrier(&self) -> Carrier {
        Carrier::Vp8
    }

    fn set_frame_handler(&self, handler: Option<FrameHandler>) {
        *locked(&self.on_frame) = handler;
    }

    /// The Go engine installs no keyframe-request handler: a VP8 channel
    /// answers none.
    fn set_keyframe_handler(&self, _handler: Option<KeyframeHandler>) {}

    fn rtp_held_bytes(&self) -> Option<usize> {
        Some(self.rtp_held.get())
    }

    fn close(&self) -> EngineFuture<'_> {
        Box::pin(self.shutdown())
    }
}

// ---------------------------------------------------------------------------
// The join the client asks for.

/// What the client asks of the carrier (`builtin.Config` as far as VK
/// Calls reads it).
#[derive(Clone)]
pub struct Join<'a> {
    /// The room goes through the provider ([`auth::issue`], again before
    /// each rejoin and for each recruited guest): `room` is the call's
    /// join link. Otherwise `room` is the signalling endpoint itself and
    /// there is no refresh.
    pub via_provider: bool,
    /// The join link, or the signalling endpoint.
    pub room: &'a str,
    /// `cfg.Token`: the provider refuses one; a direct engine reads none.
    pub token: &'a str,
    /// `Extra["ice_servers"]` of direct credentials. Go's direct
    /// credentials carry none: the tests' fakes alone.
    pub ice_servers: &'a str,
    /// The provider's two services at one base instead of their own (the
    /// API's paths start with `/method/`, the SDK API's is `/fb.do`), for
    /// the tests' fakes; `None` is the provider's defaults.
    pub provider_base: Option<&'a str>,
    /// The guest's name; empty takes a `guest-` name.
    pub name: &'a str,
    /// The address ICE host candidates name; `None` is the default
    /// route's.
    pub host_ip: Option<IpAddr>,
    /// Relayed candidates only.
    pub relay_only: bool,
    /// The most joins the process may start; 0 is no limit.
    pub max_joins: u32,
    /// The duration each sample the transport writes stands for.
    pub frame_interval: Duration,
}

impl std::fmt::Debug for Join<'_> {
    /// The link is the room's whole secret and the endpoint carries the
    /// join token: neither is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Join")
            .field("via_provider", &self.via_provider)
            .field("provider_base", &self.provider_base)
            .field("host_ip", &self.host_ip)
            .field("relay_only", &self.relay_only)
            .field("max_joins", &self.max_joins)
            .field("frame_interval", &self.frame_interval)
            .finish_non_exhaustive()
    }
}

/// What the provider is asked for every guest; wiped when it goes.
struct Asking {
    room: String,
    name: String,
    token: String,
    base: String,
}

impl Drop for Asking {
    fn drop(&mut self) {
        self.room.zeroize();
        self.token.zeroize();
    }
}

/// The issuer of `join`'s guests: the provider's whole chain, a new guest
/// each time (`resolveCredentials`' `issue`).
fn issuer(join: &Join<'_>) -> Issue {
    let asking = Arc::new(Asking {
        room: join.room.to_owned(),
        name: join.name.to_owned(),
        token: join.token.to_owned(),
        base: join.provider_base.unwrap_or_default().to_owned(),
    });
    Arc::new(move || {
        let asking = Arc::clone(&asking);
        Box::pin(async move {
            auth::issue(&auth::Request {
                room_url: &asking.room,
                name: &asking.name,
                token: &asking.token,
                api_base: &asking.base,
                fb_base: &asking.base,
                ..auth::Request::default()
            })
            .await
        })
    })
}

/// The credentials of an engine joined without its provider
/// (`engine.Credentials{URL, Token}`, and the tests' `ice_servers`).
fn direct(join: &Join<'_>) -> Credentials {
    Credentials {
        url: join.room.to_owned(),
        token: join.token.to_owned(),
        room_url: String::new(),
        ice_servers: join.ice_servers.to_owned(),
        participant_id: String::new(),
        peer_id_hint: None,
        device_idx: String::new(),
        client_type: String::new(),
        p2p_forbidden: true,
    }
}

/// Joins the room `join` names and hands the session back as the
/// transport's engine, with its news and its rejoins served from then on
/// ([`Session::supervise`]). A join that fails leaves nothing behind: the
/// guest has hung up.
///
/// # Errors
///
/// [`Error::Auth`] for the provider's refusal, else as
/// [`Session::connect`]; a host with no IPv4 route to name in a candidate
/// is [`NegotiateError::NewPeer`].
pub async fn join(join: Join<'_>) -> Result<Joined, Error> {
    // What the issuer keeps to ask the provider again with. A direct
    // join's room is its endpoint, which the session bounds.
    if join.via_provider && join.room.len() > MAX_ROOM_LINK {
        return Err(Error::Bound("the room link"));
    }
    if join.name.len() > MAX_NAME {
        return Err(Error::Bound("the name"));
    }
    if join.token.len() > MAX_ROOM_LINK {
        return Err(Error::Bound("the account token"));
    }
    if join
        .provider_base
        .is_some_and(|base| base.len() > MAX_ROOM_LINK)
    {
        return Err(Error::Bound("the provider's base"));
    }
    let (credentials, issue) = if join.via_provider {
        let issue = issuer(&join);
        (issue().await.map_err(Error::Auth)?, Some(issue))
    } else {
        (direct(&join), None)
    };
    let host_ip = match join.host_ip {
        Some(ip) => ip,
        None => olc_rtc::ice::default_ipv4().map_err(|e| NegotiateError::NewPeer(e.to_string()))?,
    };
    let (session, events) = Session::new(Settings {
        credentials,
        issue,
        host_ip,
        relay_only: join.relay_only,
        frame_interval: join.frame_interval,
        max_joins: join.max_joins,
        headers: Headers::default(),
        delays: Delays::default(),
        waits: Waits::default(),
    })?;
    if let Err(e) = session.connect().await {
        session.shutdown().await;
        return Err(e);
    }
    session.supervise();
    Ok(Joined {
        engine: session,
        events,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicUsize;

    use olc_rtc::media::{with_codecs, CodecLine};
    use olc_rtc::str0m::change::SdpOffer;
    use olc_rtc::str0m::format::{Codec, FormatParams};
    use olc_rtc::str0m::media::Mid;
    use olc_rtc::str0m::rtp::{RtpWrite, SeqNo, Ssrc};
    use olc_vp8channel::wire::epoch_header;
    use serde_json::{json, Value};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use super::*;
    use crate::control::{encode_layout, encode_perf_stat_report, layout_entries};
    use crate::negotiate::tests::live_shape_offer;
    use crate::negotiate::{offer_view, remote_ssrcs};
    use crate::recruit::Issuing;
    use crate::session::tests::{config, offered_by, sfu_side, watch, Seen};
    use crate::session::PUBLISH_CODECS;
    use crate::signaling::tests::{
        accept, bounded, bounded_for, connection, read_frame, write_text, Write,
    };
    use crate::testing::{Reply, Stub};

    /// The SSRCs the live shape's two receive slots name.
    const MID_5_SSRC: u32 = 2_463_708_139;
    const MID_6_SSRC: u32 = 2_463_708_140;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| (b as char).to_digit(16).unwrap() as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    /// A frame the transport would write: the epoch header and `n` bytes.
    fn frame(tag: u8, n: usize) -> Vec<u8> {
        let mut frame = epoch_header(1, 2, 3).to_vec();
        frame.extend((0..n).map(|i| tag ^ (i as u8)));
        frame
    }

    // ----- The readers.

    /// The packets of `frame`, numbered from `seq`.
    fn packets(frame: &[u8], seq: u16) -> Vec<olc_vp8channel::rtp::RtpPacket> {
        Packetizer::new(Payloader::Vp8(Vp8Payloader::with_picture_id(0)), seq, 7)
            .packetize(frame, 16_666_666)
    }

    /// Plan D8, the reason for a reader per SSRC: two cameras' packets come
    /// interleaved with sequence numbers of their own, and both frames
    /// arrive whole; a camera wrapped in `red` is unwrapped; a track of a
    /// codec the transport does not read gets no reader.
    #[test]
    fn each_ssrc_has_a_reader_of_its_own() {
        let (first, second) = (frame(0x11, 2600), frame(0x22, 2600));
        let (a, b) = (packets(&first, 100), packets(&second, 40_000));
        assert!(a.len() >= 3 && a.len() == b.len());
        let mut readers = Readers::new(100, Some(104));
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let now = Instant::now();
        for (bare, wrapped) in a.iter().zip(&b) {
            readers.push(
                1,
                bare.seq,
                bare.marker,
                100,
                &bare.payload,
                now,
                &mut |f| {
                    frames.push(f.to_vec());
                },
            );
            // RFC 2198, the primary block alone: VP8's payload type, then
            // the VP8 payload.
            let mut red = vec![100u8];
            red.extend_from_slice(&wrapped.payload);
            readers.push(2, wrapped.seq, wrapped.marker, 104, &red, now, &mut |f| {
                frames.push(f.to_vec());
            });
        }
        assert_eq!(frames, [first.clone(), second]);
        assert_eq!(readers.len(), 2);
        let held = readers.held_bytes();
        assert!(held > 0 && held <= 2 * READER_HELD, "{held}");

        // Opus, VP9, an RTX number: a track the transport drains.
        for pt in [111u8, 102, 101, 105] {
            readers.push(3, 1, true, pt, &a[0].payload, now, &mut |_| {
                panic!("a frame from payload type {pt}");
            });
        }
        assert_eq!(readers.len(), 2);

        // A stack that names no `red` reads VP8 alone.
        let mut plain = Readers::new(100, None);
        plain.push(9, 1, true, 104, &[100, 0x90, 0x80, 0], now, &mut |_| {
            panic!("a frame from a payload type nobody named");
        });
        assert_eq!(plain.len(), 0);
    }

    /// A payload longer than a reader's packet bound makes no reader and
    /// reaches none: the reorder buffer copies what it is given, so
    /// [`READER_HELD`] is a bound only with this one in front of it.
    #[test]
    fn an_oversize_payload_makes_and_feeds_no_reader() {
        let mut readers = Readers::new(100, None);
        let now = Instant::now();
        let mut frames = 0usize;
        let long = vec![0x10u8; MAX_PACKET_PAYLOAD + 1];
        readers.push(7, 1, true, 100, &long, now, &mut |_| frames += 1);
        assert_eq!(readers.len(), 0, "an oversize payload made a reader");
        let fits = vec![0x10u8; MAX_PACKET_PAYLOAD];
        readers.push(7, 2, true, 100, &fits, now, &mut |_| frames += 1);
        assert_eq!(readers.len(), 1);
        readers.push(7, 3, true, 100, &long, now, &mut |_| frames += 1);
        assert_eq!(readers.len(), 1);
    }

    /// Plan D8, the cap: [`READERS_MAX`] readers at most; one more SSRC
    /// takes the place of the reader fed longest ago, and the others go on
    /// where they were.
    #[test]
    fn a_tenth_ssrc_replaces_the_reader_fed_longest_ago() {
        assert_eq!(READERS_MAX, 9);
        let whole = frame(0x33, 2600);
        let parts = packets(&whole, 500);
        assert!(parts.len() >= 3);
        let mut readers = Readers::new(100, None);
        let now = Instant::now();
        let mut done: Vec<u32> = Vec::new();
        // Nine cameras each send the first packet of a frame.
        for ssrc in 1..=9u32 {
            let p = &parts[0];
            readers.push(ssrc, p.seq, p.marker, 100, &p.payload, now, &mut |_| {
                done.push(ssrc);
            });
        }
        assert_eq!(readers.len(), 9);
        // The first is fed again, so the second is now the one fed longest
        // ago; a tenth camera takes its place.
        let p = &parts[1];
        readers.push(1, p.seq, p.marker, 100, &p.payload, now, &mut |_| {
            done.push(1)
        });
        let p = &parts[0];
        readers.push(10, p.seq, p.marker, 100, &p.payload, now, &mut |_| {
            done.push(10)
        });
        assert_eq!(readers.len(), 9);
        let held: Vec<u32> = readers.slots.iter().map(|slot| slot.ssrc).collect();
        assert_eq!(held, [1, 10, 3, 4, 5, 6, 7, 8, 9]);
        // The kept readers finish their frames; the replaced camera, back
        // with the rest of its frame, starts a new reader that has no head
        // of it.
        for ssrc in [1u32, 3, 10] {
            for p in &parts[1..] {
                if ssrc == 1 && p.seq == parts[1].seq {
                    continue;
                }
                readers.push(ssrc, p.seq, p.marker, 100, &p.payload, now, &mut |f| {
                    assert_eq!(f, &whole[..]);
                    done.push(ssrc);
                });
            }
        }
        assert_eq!(done, [1, 3, 10]);
        for p in &parts[1..] {
            readers.push(2, p.seq, p.marker, 100, &p.payload, now, &mut |_| {
                done.push(2)
            });
        }
        assert_eq!(done, [1, 3, 10], "the replaced reader's frame came back");
        assert_eq!(readers.len(), 9);
    }

    /// What a peer connection's state means to its attempt: a failure
    /// before the first `connected` ends the join and asks nothing (plan
    /// D5), one after it asks for a rejoin.
    #[test]
    fn a_failure_before_the_connection_ends_the_join_and_one_after_it_rejoins() {
        assert_eq!(verdict(PcState::Connected, false), Verdict::Up);
        assert_eq!(verdict(PcState::Connected, true), Verdict::Up);
        for gone in [PcState::Failed, PcState::Closed] {
            assert_eq!(verdict(gone, false), Verdict::JoinFailed);
            assert_eq!(verdict(gone, true), Verdict::Rejoin);
        }
        for other in [PcState::New, PcState::Connecting, PcState::Disconnected] {
            assert_eq!(verdict(other, false), Verdict::Nothing);
            assert_eq!(verdict(other, true), Verdict::Nothing);
        }
        // Go's numbers.
        assert_eq!(
            (OFFER_WAIT, CONNECT_WAIT, PERF_STAT_INTERVAL),
            (
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(5)
            )
        );
        assert_eq!(
            (MAX_RECONNECTS, LIMIT_REASON),
            (10, "reconnect limit reached")
        );
        assert_eq!(Waits::default().perf, PERF_STAT_INTERVAL);
        // The video transport's `defaultConnectTimeout`.
        assert_eq!(CONNECT_BOUND, Duration::from_secs(60));
        assert_eq!(Waits::default().join, CONNECT_BOUND);
    }

    // ----- A fake room: the signalling socket and the SFU behind it.

    /// What the room does beside the happy path.
    #[derive(Default)]
    struct Script {
        /// The command answered with an error frame.
        reject: Mutex<Option<&'static str>>,
        /// No offer is sent.
        silent: AtomicBool,
        /// The SFU never takes the answer: no peer connection comes up.
        deaf: AtomicBool,
        /// Notifications sent before the offer.
        early: Mutex<Vec<Value>>,
        /// The description sent in place of the SFU's offer.
        offer: Mutex<Option<String>>,
        /// The room is fresh: a guest is told DIRECT, and nothing flips it.
        direct: AtomicBool,
        /// The SFU takes the answer and `accept-producer` gets no response
        /// (a test sends it when it wants the join to go on).
        hold_accept: AtomicBool,
        /// The session id of the SFU's offer in place of `sess-1`.
        session_id: Mutex<Option<String>>,
    }

    /// One guest as the room sees it.
    struct Conn {
        /// The handshake's request head.
        head: String,
        /// The text frames the guest sent.
        frames: Mutex<Vec<String>>,
        /// The socket ended.
        gone: AtomicBool,
        write: Write,
        /// The SFU's peer for this guest, and the offer it made.
        sfu: Peer,
        offer: String,
        /// The channels the guest opened, as the SFU names them.
        channels: Mutex<Vec<(ChannelId, String)>>,
        /// What arrived on `producerCommand`.
        commands: Mutex<Vec<Vec<u8>>>,
        /// The RTP the guest published.
        rtp: Mutex<Vec<Seen>>,
        sfu_up: AtomicBool,
        /// What the SFU's peer said, in order, with when it said it.
        events: Mutex<Vec<(Duration, String)>>,
        born: Instant,
    }

    impl Conn {
        fn frames(&self) -> Vec<String> {
            self.frames.lock().unwrap().clone()
        }

        /// The commands the guest sent on the socket: name, sequence, frame.
        fn sent(&self) -> Vec<(String, i64, Value)> {
            self.frames()
                .iter()
                .filter_map(|text| serde_json::from_str::<Value>(text).ok())
                .filter_map(|v| {
                    let name = v["command"].as_str()?.to_owned();
                    let sequence = v["sequence"].as_i64()?;
                    Some((name, sequence, v))
                })
                .collect()
        }

        fn names(&self) -> Vec<String> {
            self.sent().into_iter().map(|(name, _, _)| name).collect()
        }

        fn hangups(&self) -> Vec<String> {
            self.frames()
                .into_iter()
                .filter(|text| text.contains(r#""command":"hangup""#))
                .collect()
        }

        fn commands(&self) -> Vec<Vec<u8>> {
            self.commands.lock().unwrap().clone()
        }

        fn rtp(&self) -> Vec<Seen> {
            self.rtp.lock().unwrap().clone()
        }

        fn channel(&self, label: &str) -> ChannelId {
            self.channels
                .lock()
                .unwrap()
                .iter()
                .find(|(_, l)| l == label)
                .map(|(id, _)| *id)
                .unwrap_or_else(|| panic!("the SFU has no channel {label}"))
        }

        async fn notify(&self, note: Value) {
            write_text(&self.write, &note.to_string()).await;
        }

        /// The SFU forwards `packets` on the receive slot `mid`, whose
        /// SSRC is `ssrc`, at `pt`; `red` wraps each in RFC 2198 with VP8's
        /// payload type as the primary's.
        fn forward(
            &self,
            mid: &str,
            ssrc: u32,
            pt: u8,
            red: bool,
            packets: &[olc_vp8channel::rtp::RtpPacket],
        ) {
            self.sfu.with_rtc(|rtc| {
                let mut api = rtc.direct_api();
                let ssrc = Ssrc::from(ssrc);
                let mid = Mid::from(mid);
                if api.stream_tx(&ssrc).is_none() {
                    // str0m made a stream of its own for the line, and
                    // sends from the first stream a line has: ours takes
                    // its place.
                    let made = api.stream_tx_by_mid(mid, None).map(|tx| tx.ssrc());
                    if let Some(made) = made {
                        api.remove_stream_tx(made);
                    }
                    api.declare_stream_tx(ssrc, None, mid, None);
                }
                let tx = api.stream_tx(&ssrc).expect("the stream just declared");
                for p in packets {
                    let payload = if red {
                        let mut wrapped = vec![100u8];
                        wrapped.extend_from_slice(&p.payload);
                        wrapped
                    } else {
                        p.payload.clone()
                    };
                    tx.write_rtp(
                        RtpWrite::new(
                            pt.into(),
                            SeqNo::from(u64::from(p.seq)),
                            p.timestamp,
                            Instant::now(),
                            payload,
                        )
                        .marker(p.marker),
                    );
                }
            });
        }
    }

    /// The SFU's side of the session as the fake's stack reads it: the
    /// mirror of the view with the payload types the fake has, and the
    /// receive slots' `red` number under the name VP9 (str0m forwards a
    /// video codec's packets; the bytes at 104 are what the test wrote).
    fn as_the_fake_reads(mirror: &str) -> String {
        const KEPT: [&str; 5] = ["100", "101", "104", "105", "111"];
        let mut out = String::new();
        for line in mirror.split("\r\n").filter(|line| !line.is_empty()) {
            let codec_line = ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"]
                .iter()
                .find_map(|head| line.strip_prefix(head))
                .map(|rest| rest.split(' ').next().unwrap_or(""));
            let line = if let Some(rest) = line.strip_prefix("m=video ") {
                let mut parts = rest.split(' ');
                let head: Vec<&str> = parts.by_ref().take(2).collect();
                let kept: Vec<&str> = parts.filter(|pt| KEPT.contains(pt)).collect();
                format!("m=video {} {}", head.join(" "), kept.join(" "))
            } else if let Some(pt) = codec_line {
                if !KEPT.contains(&pt) {
                    continue;
                }
                line.replace("a=rtpmap:104 red/90000", "a=rtpmap:104 VP9/90000")
            } else {
                line.to_owned()
            };
            out.push_str(&line);
            out.push_str("\r\n");
        }
        out
    }

    struct FakeRoom {
        addr: SocketAddr,
        script: Script,
        conns: Mutex<Vec<Arc<Conn>>>,
        serve: Mutex<Option<JoinHandle<()>>>,
    }

    impl FakeRoom {
        async fn start() -> Arc<Self> {
            olc_rtc::init();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let room = Arc::new(FakeRoom {
                addr: listener.local_addr().unwrap(),
                script: Script::default(),
                conns: Mutex::new(Vec::new()),
                serve: Mutex::new(None),
            });
            let serve = tokio::spawn(Self::serve(Arc::clone(&room), listener));
            *room.serve.lock().unwrap() = Some(serve);
            room
        }

        /// The endpoint a guest `user` with the join token `token` dials.
        fn endpoint(&self, user: u64, token: &str) -> String {
            format!("ws://{}/fb?token={token}&userId={user}", self.addr)
        }

        async fn serve(room: Arc<Self>, listener: TcpListener) {
            loop {
                let (head, mut read, write) = accept(&listener).await;
                let codecs = [
                    CodecLine::video(100, Some(101), Codec::Vp8, FormatParams::default()),
                    CodecLine::video(104, Some(105), Codec::Vp9, FormatParams::default()),
                    CodecLine::opus(111, FormatParams::default()),
                ];
                let (sfu, mut events) = Peer::start_tuned(&config("sfu"), |c| {
                    with_codecs(c.set_ice_lite(true), &codecs)
                })
                .unwrap();
                let offer = offered_by(&sfu, &live_shape_offer());
                let mut rtp = watch(&sfu);
                let conn = Arc::new(Conn {
                    head,
                    frames: Mutex::new(Vec::new()),
                    gone: AtomicBool::new(false),
                    write,
                    sfu,
                    offer,
                    channels: Mutex::new(Vec::new()),
                    commands: Mutex::new(Vec::new()),
                    rtp: Mutex::new(Vec::new()),
                    sfu_up: AtomicBool::new(false),
                    events: Mutex::new(Vec::new()),
                    born: Instant::now(),
                });
                room.conns.lock().unwrap().push(Arc::clone(&conn));
                let topology = if room.script.direct.load(Ordering::SeqCst) {
                    "DIRECT"
                } else {
                    "SERVER"
                };
                conn.notify(connection(
                    topology,
                    json!([{"id": 42, "state": "ACCEPTED"}]),
                ))
                .await;
                // VK's keepalive: a text "ping" every 5 s (signaling's
                // SIGNALING_SILENCE ends a socket that stays quiet).
                tokio::spawn({
                    let conn = Arc::clone(&conn);
                    async move {
                        while !conn.gone.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            write_text(&conn.write, "ping").await;
                        }
                    }
                });

                // The SFU's peer.
                tokio::spawn({
                    let conn = Arc::clone(&conn);
                    async move {
                        while let Some(event) = events.recv().await {
                            let said = match &event {
                                PeerEvent::Connected => "connected".to_owned(),
                                PeerEvent::IceState(state) => format!("ice {state:?}"),
                                PeerEvent::ChannelOpen(_, label) => format!("open {label}"),
                                PeerEvent::ChannelClose(_) => "channel close".to_owned(),
                                PeerEvent::Data(message) => format!("data {}", message.data.len()),
                                PeerEvent::Failed(why) => format!("failed: {why}"),
                                PeerEvent::Closed(why) => format!("closed: {why}"),
                                _ => "other".to_owned(),
                            };
                            conn.events
                                .lock()
                                .unwrap()
                                .push((conn.born.elapsed(), said));
                            match event {
                                PeerEvent::Connected => conn.sfu_up.store(true, Ordering::SeqCst),
                                PeerEvent::ChannelOpen(id, label) => {
                                    conn.channels.lock().unwrap().push((id, label));
                                }
                                PeerEvent::Data(message) => {
                                    let command =
                                        conn.channels.lock().unwrap().iter().any(|(id, label)| {
                                            *id == message.channel && label == "producerCommand"
                                        });
                                    if command {
                                        conn.commands.lock().unwrap().push(message.data.clone());
                                    }
                                }
                                PeerEvent::Closed(_) => break,
                                _ => {}
                            }
                        }
                    }
                });
                tokio::spawn({
                    let conn = Arc::clone(&conn);
                    async move {
                        while let Some(seen) = rtp.recv().await {
                            conn.rtp.lock().unwrap().push(seen);
                        }
                    }
                });

                // The guest's socket.
                let room = Arc::clone(&room);
                tokio::spawn(async move {
                    let mut answered = false;
                    while let Some(frame) = read_frame(&mut read).await {
                        let text = frame.text().to_owned();
                        if text == "pong" {
                            continue; // the keepalive's answer is no frame of the test's
                        }
                        conn.frames.lock().unwrap().push(text.clone());
                        let Ok(v) = serde_json::from_str::<Value>(&text) else {
                            continue;
                        };
                        let Some(name) = v["command"].as_str() else {
                            continue;
                        };
                        if name == "hangup" {
                            continue;
                        }
                        let rejected = *room.script.reject.lock().unwrap() == Some(name);
                        if rejected {
                            conn.notify(json!({"sequence": v["sequence"], "type": "error"}))
                                .await;
                            continue;
                        }
                        let held = name == "accept-producer"
                            && room.script.hold_accept.load(Ordering::SeqCst);
                        if !held {
                            conn.notify(json!({
                                "sequence": v["sequence"], "response": name, "type": "response",
                            }))
                            .await;
                        }
                        match name {
                            "update-media-modifiers" => {
                                let early = room.script.early.lock().unwrap().clone();
                                for note in early {
                                    conn.notify(note).await;
                                }
                                if room.script.silent.load(Ordering::SeqCst) {
                                    continue;
                                }
                                let description = room
                                    .script
                                    .offer
                                    .lock()
                                    .unwrap()
                                    .clone()
                                    .unwrap_or_else(|| conn.offer.clone());
                                let session_id = room
                                    .script
                                    .session_id
                                    .lock()
                                    .unwrap()
                                    .clone()
                                    .unwrap_or_else(|| "sess-1".to_owned());
                                conn.notify(json!({
                                    "type": "notification",
                                    "notification": "producer-updated",
                                    "sessionId": session_id,
                                    "description": description,
                                }))
                                .await;
                            }
                            "accept-producer"
                                if !answered && !room.script.deaf.load(Ordering::SeqCst) =>
                            {
                                answered = true;
                                let shaped = v["description"].as_str().unwrap();
                                let view = offer_view(&conn.offer, &PUBLISH_CODECS, None).unwrap();
                                let mirror = as_the_fake_reads(&sfu_side(&view, shaped));
                                let mirror = SdpOffer::from_sdp_string(&mirror).unwrap();
                                conn.sfu
                                    .with_rtc(|rtc| rtc.sdp_api().accept_offer(mirror))
                                    .unwrap_or_else(|e| panic!("the fake SFU: {e}"));
                            }
                            _ => {}
                        }
                    }
                    conn.gone.store(true, Ordering::SeqCst);
                });
            }
        }

        fn conns(&self) -> Vec<Arc<Conn>> {
            self.conns.lock().unwrap().clone()
        }

        fn conn(&self, index: usize) -> Arc<Conn> {
            self.conns()
                .get(index)
                .cloned()
                .unwrap_or_else(|| panic!("the room has no guest {index}"))
        }
    }

    impl Drop for FakeRoom {
        fn drop(&mut self) {
            if let Some(serve) = self.serve.lock().unwrap().take() {
                serve.abort();
            }
            for conn in self.conns.lock().unwrap().iter() {
                conn.sfu.set_rtp_sink(None);
                conn.sfu.close();
            }
        }
    }

    /// Waits until `settled` holds.
    async fn until(what: &str, settled: impl Fn() -> bool) {
        for _ in 0..1500 {
            if settled() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{what}: not within 15 s");
    }

    fn credentials(endpoint: &str) -> Credentials {
        Credentials {
            url: endpoint.to_owned(),
            token: "SECRETTOKEN".to_owned(),
            room_url: String::new(),
            ice_servers: String::new(),
            participant_id: String::new(),
            peer_id_hint: None,
            device_idx: String::new(),
            client_type: "VK".to_owned(),
            p2p_forbidden: true,
        }
    }

    fn settings(endpoint: &str, issue: Option<Issue>) -> Settings {
        Settings {
            credentials: credentials(endpoint),
            issue,
            host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            relay_only: false,
            frame_interval: Duration::from_millis(16),
            max_joins: 0,
            headers: Headers::default(),
            delays: Delays::default(),
            waits: Waits::default(),
        }
    }

    /// A session joined to a fresh room as guest 42, its rejoins served.
    async fn joined(
        room: &Arc<FakeRoom>,
        waits: Waits,
    ) -> (Arc<Session>, mpsc::Receiver<EngineEvent>, Arc<Conn>) {
        let mut settings = settings(&room.endpoint(42, "SECRETTOKEN"), None);
        settings.waits = waits;
        let (session, news) = Session::new(settings).unwrap();
        session
            .connect()
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        session.supervise();
        let conn = room.conn(0);
        (session, news, conn)
    }

    /// The peer connection of the session's current attempt.
    fn current_peer(session: &Session) -> Peer {
        locked(&session.media)
            .negotiation
            .as_ref()
            .expect("the session has no peer connection")
            .peer()
            .clone()
    }

    /// An issuer whose `n`-th guest (from 1) is user `50 + n` with the
    /// token `TOKEN<n>`; the calls numbered in `failing` are refused.
    fn guests(room: &Arc<FakeRoom>, failing: &'static [usize]) -> (Issue, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let issue: Issue = Arc::new({
            let (calls, room) = (Arc::clone(&calls), Arc::clone(room));
            move || -> Issuing {
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                let endpoint = room.endpoint(50 + call as u64, &format!("TOKEN{call}"));
                Box::pin(async move {
                    if failing.contains(&call) {
                        return Err(auth::Error::InvalidRoomUrl);
                    }
                    Ok(credentials(&endpoint))
                })
            }
        });
        (issue, calls)
    }

    /// The hangup a guest sends under the sequence `n`.
    fn hangup_at(n: usize) -> String {
        format!(r#"{{"command":"hangup","reason":"HUNGUP","sequence":{n}}}"#)
    }

    /// Go's bound on a first join: the video transport's
    /// `defaultConnectTimeout` ([`CONNECT_BOUND`], held to it above).
    const SIXTY: Duration = Duration::from_secs(60);

    /// `change-simulcast` for the layer `l` under the number 1
    /// (`stamp.go`'s example bytes).
    const CHANGE_SIMULCAST_FIRST: &str = "07 00 01 01 01 A1 6C D1 01 40 D1 00 B4 0F D1 00 B4";

    /// `frame` is the `change-simulcast` of a fresh attempt: Go's bytes
    /// under the raw counter, which stands at 1 when the channel opens
    /// before the run's first layout took its number and at 2 after (the
    /// same two race in Go: `OnOpen` and `run`).
    fn assert_simulcast(frame: &[u8]) {
        let golden = hex(CHANGE_SIMULCAST_FIRST);
        assert_eq!(frame.len(), golden.len(), "{frame:x?}");
        assert_eq!(
            (&frame[..2], &frame[3..]),
            (&golden[..2], &golden[3..]),
            "{frame:x?}"
        );
        assert!(matches!(frame[2], 1 | 2), "{frame:x?}");
        assert_eq!(
            frame,
            crate::control::encode_change_simulcast(
                i64::from(frame[2]),
                "l",
                320,
                180,
                15,
                180_000
            )
        );
    }

    // ----- The join.

    /// `Connect`: the four commands in Go's order on one socket, each
    /// under the next sequence, the answer for the offer's session with the
    /// offer's SSRCs as strings; the session can send once the peer
    /// connection is up and not before; `Close` hangs up once, under the
    /// next sequence, and closes the peer connection; a closed session
    /// refuses to connect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_joins_and_leaves_as_gos() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (session, _news) =
                Session::new(settings(&room.endpoint(42, "SECRETTOKEN"), None)).unwrap();
            assert_eq!(session.carrier(), Carrier::Vp8);
            assert!(!session.can_send() && !session.subscriber_can_send());
            // A sample before the join is taken and dropped.
            assert!(session.write_sample(&frame(1, 100)));
            assert_eq!(session.rtp_out(), 0);

            session.connect().await.unwrap_or_else(|e| panic!("{e}"));
            assert!(session.can_send() && session.subscriber_can_send());
            let conn = room.conn(0);
            for part in [
                "tgt=join",
                "userId=42",
                "token=SECRETTOKEN",
                "capabilities=2F7F",
            ] {
                assert!(conn.head.contains(part), "{part}: {}", conn.head);
            }
            let sent = conn.sent();
            let order: Vec<(&str, i64)> = sent
                .iter()
                .map(|(name, seq, _)| (name.as_str(), *seq))
                .collect();
            assert_eq!(
                order,
                [
                    ("allocate-consumer", 1),
                    ("update-media-modifiers", 2),
                    ("change-media-settings", 3),
                    ("accept-producer", 4),
                ]
            );
            assert_eq!(sent[0].2["capabilities"]["videoTracksCount"], 36);
            assert_eq!(sent[1].2["mediaModifiers"]["denoise"], true);
            assert_eq!(sent[2].2["mediaSettings"]["isVideoEnabled"], false);
            let accept = &sent[3].2;
            assert_eq!(accept["sessionId"], "sess-1");
            let ssrcs: Vec<&str> = accept["ssrcs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect();
            assert_eq!(ssrcs, remote_ssrcs(&conn.offer));
            assert!(ssrcs.contains(&"2463708139") && ssrcs.contains(&"2463708140"));
            let shaped = accept["description"].as_str().unwrap();
            assert!(shaped.starts_with("v=0\r\no=- "), "{shaped}");
            assert!(shaped.contains(" 2 IN IP4 127.0.0.1\r\n"));
            assert!(shaped.contains("a=setup:active\r\n"));
            assert!(shaped.contains("a=simulcast:send l;m;h"));
            assert!(shaped.contains(&format!(
                "a=msid:{} {}\r\n",
                session.track.stream, session.track.track
            )));
            assert!(conn.hangups().is_empty());
            assert_eq!(session.rejoins_queued(), 0);

            let peer = current_peer(&session);
            assert!(!peer.is_ended());
            session.close().await;
            // As pion's Close: the peer connection has ended, and said so,
            // before the close returns (a stopping client's log ends with
            // `peer connection state changed: closed`, which the apps read).
            assert!(peer.is_ended(), "the close returned before the peer ended");
            assert!(!session.can_send());
            until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            assert_eq!(
                conn.hangups(),
                [r#"{"command":"hangup","reason":"HUNGUP","sequence":5}"#]
            );
            assert_eq!(conn.frames().len(), 5, "{:?}", conn.frames());
            // The peer connection is closed: its driver ends.
            peer.ended().await;
            assert!(matches!(session.connect().await, Err(Error::Closed)));
            // Nothing asks for a rejoin once it is closed.
            session.reconnect("after the close");
            assert_eq!(session.rejoins_queued(), 0);
            assert_eq!(room.conns().len(), 1);

            let none = Session::new(settings("", None)).unwrap_err();
            assert!(matches!(none, Error::NoEndpoint));
            assert_eq!(none.to_string(), "vkcalls: signaling endpoint missing");
        })
        .await;
    }

    /// Fidelity S4: whatever ends a join, the guest hangs up once before
    /// the error is returned, the error is Go's, and nothing asks for a
    /// rejoin: a refused command, no offer, an offer that cannot be
    /// answered, a peer connection that never comes up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_that_fails_hangs_up_and_says_why() {
        bounded_for(Duration::from_secs(40), async {
            let quick = Waits {
                offer: Duration::from_millis(300),
                connect: Duration::from_millis(600),
                perf: PERF_STAT_INTERVAL,
                join: CONNECT_BOUND,
            };
            let attempt = |room: &Arc<FakeRoom>| {
                let mut settings = settings(&room.endpoint(42, "SECRETTOKEN"), None);
                settings.waits = quick;
                let (session, _news) = Session::new(settings).unwrap();
                let room = Arc::clone(room);
                async move {
                    let error = session.connect().await.unwrap_err();
                    let conn = room.conn(0);
                    until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
                    assert!(!session.can_send());
                    assert_eq!(session.rejoins_queued(), 0);
                    assert_eq!(room.conns().len(), 1);
                    // The session can still be asked to leave.
                    session.close().await;
                    (error, conn)
                }
            };
            let hangup =
                |n: usize| format!(r#"{{"command":"hangup","reason":"HUNGUP","sequence":{n}}}"#);

            // A refused command.
            let room = FakeRoom::start().await;
            *room.script.reject.lock().unwrap() = Some("allocate-consumer");
            let (error, conn) = attempt(&room).await;
            assert_eq!(
                error.to_string(),
                "vkcalls: signaling command rejected: allocate-consumer"
            );
            assert_eq!(conn.names(), ["allocate-consumer", "hangup"]);
            assert_eq!(conn.hangups(), [hangup(2)]);

            // No offer.
            let room = FakeRoom::start().await;
            room.script.silent.store(true, Ordering::SeqCst);
            let (error, conn) = attempt(&room).await;
            assert!(matches!(error, Error::OfferTimeout), "{error}");
            assert_eq!(error.to_string(), "vkcalls: no producer offer arrived");
            assert_eq!(conn.hangups(), [hangup(3)]);

            // An offer with no slot to publish into.
            let room = FakeRoom::start().await;
            *room.script.offer.lock().unwrap() =
                Some(live_shape_offer().replace("a=recvonly", "a=sendonly"));
            let (error, conn) = attempt(&room).await;
            assert_eq!(
                error.to_string(),
                "vkcalls: native answer declares no video publish section"
            );
            assert_eq!(
                conn.names(),
                [
                    "allocate-consumer",
                    "update-media-modifiers",
                    "change-media-settings",
                    "hangup"
                ]
            );
            assert_eq!(conn.hangups(), [hangup(4)]);

            // A peer connection that never comes up (review note N4: the
            // watcher never fails a peer that never left `new`).
            let room = FakeRoom::start().await;
            room.script.deaf.store(true, Ordering::SeqCst);
            let (error, conn) = attempt(&room).await;
            assert!(matches!(error, Error::ConnectTimeout), "{error}");
            assert_eq!(
                error.to_string(),
                "vkcalls: peer connection did not connect"
            );
            assert_eq!(conn.hangups(), [hangup(5)]);
            assert!(conn.rtp().is_empty());
        })
        .await;
    }

    // ----- The join's bound.

    /// Fidelity M1: a first join runs under the video transport's 60 s, as
    /// Go's `Connect` runs under its context. A fresh room that stays in
    /// DIRECT (no issuer, so nobody to flip it) holds the guest in the
    /// wait for SERVER topology, which has no timer of its own: at 60 s
    /// the join ends with Go's words, and the guest has hung up, once.
    #[tokio::test]
    async fn a_first_join_in_a_room_that_stays_direct_ends_at_sixty_seconds() {
        // The clock is stopped below and jumps from timer to timer: this
        // bound lies past the 60 s the test waits out.
        bounded_for(Duration::from_secs(300), async {
            let room = FakeRoom::start().await;
            room.script.direct.store(true, Ordering::SeqCst);
            let (session, _news) =
                Session::new(settings(&room.endpoint(42, "SECRETTOKEN"), None)).unwrap();
            let before = tokio::time::Instant::now();
            let joining = tokio::spawn({
                let session = Arc::clone(&session);
                async move { session.connect().await }
            });
            until("the guest's socket", || !room.conns().is_empty()).await;
            let conn = room.conn(0);
            // The `connection` note is read before the clock stops.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!joining.is_finished(), "the join ended in DIRECT");
            assert!(conn.frames().is_empty(), "{:?}", conn.frames());

            tokio::time::pause();
            let error = joining.await.unwrap().unwrap_err();
            let waited = before.elapsed();
            tokio::time::resume();
            assert_eq!(
                error.to_string(),
                "vkcalls: conversation is not in SERVER topology: context deadline exceeded"
            );
            assert!(
                waited >= SIXTY && waited < SIXTY + Duration::from_millis(250),
                "{waited:?}"
            );
            until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            // One hangup, under the socket's first sequence, and nothing
            // else was ever sent.
            assert_eq!(conn.frames(), [hangup_at(1)]);
            assert!(!session.can_send());
            assert_eq!(session.rejoins_queued(), 0);
            session.close().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(conn.frames(), [hangup_at(1)]);
            assert_eq!(room.conns().len(), 1);
        })
        .await;
    }

    /// The same wait inside a rejoin: Go's rejoin runs under the
    /// supervisor's context, which has no deadline, so a room found in
    /// DIRECT would hold the supervisor for good with `reconnecting` set
    /// (every request refused, no `Ended`). Here that one wait has the
    /// first join's 60 s: the attempt fails, its guest hangs up, and the
    /// supervisor tries again after its backoff.
    #[tokio::test]
    async fn a_rejoin_into_a_room_that_stays_direct_gives_up_at_sixty_seconds() {
        bounded_for(Duration::from_secs(600), async {
            let room = FakeRoom::start().await;
            let (session, mut news, _first) = joined(&room, Waits::default()).await;
            room.script.direct.store(true, Ordering::SeqCst);
            let asked = tokio::time::Instant::now();
            session.reconnect("peer restart");
            until("the rejoin's guest", || room.conns().len() == 2).await;
            let second = room.conn(1);
            // Its `connection` note is read before the clock stops.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(second.frames().is_empty(), "{:?}", second.frames());

            tokio::time::pause();
            let mut steps = 0;
            while second.hangups().is_empty() {
                steps += 1;
                assert!(
                    steps < 1500,
                    "the rejoin still waits for SERVER topology after 150 s"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let waited = asked.elapsed();
            // The room is in SERVER topology for whoever comes next.
            room.script.direct.store(false, Ordering::SeqCst);
            tokio::time::resume();
            assert!(
                waited >= SIXTY && waited < SIXTY + Duration::from_secs(5),
                "{waited:?}"
            );
            assert_eq!(second.frames(), [hangup_at(1)]);

            // The supervisor is not wedged: the request is tried again.
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert_eq!(room.conns().len(), 3);
            assert!(session.can_send());
            assert_eq!(session.rejoins_queued(), 1);
            assert_eq!(second.frames(), [hangup_at(1)]);
            session.close().await;
        })
        .await;
    }

    // ----- The supervisor and the first join.

    /// Correctness S2: the supervisor serves requests only once the first
    /// join has returned (Go's `WatchConnection` follows `Connect`). The
    /// SFU's peer connection comes up and closes while the join still
    /// waits for the response to `accept-producer`: the request that
    /// raises is kept, and served after the join, by tearing the first
    /// attempt down. Served beside the join it left two guests in the
    /// call, one of them owned by nobody.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_peer_that_closes_inside_the_first_join_leaves_one_generation() {
        bounded(async {
            let room = FakeRoom::start().await;
            room.script.hold_accept.store(true, Ordering::SeqCst);
            let (session, mut news) =
                Session::new(settings(&room.endpoint(42, "SECRETTOKEN"), None)).unwrap();
            let joining = tokio::spawn({
                let session = Arc::clone(&session);
                async move { session.connect().await }
            });
            until("the peer connection inside the join", || {
                locked(&session.media).up
            })
            .await;
            let first = room.conn(0);
            room.script.hold_accept.store(false, Ordering::SeqCst);
            // pion's `closed`, whatever ended the peer connection.
            current_peer(&session).close();
            until("the rejoin request", || session.rejoins_queued() == 1).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(room.conns().len(), 1, "a rejoin ran beside the first join");
            assert!(!joining.is_finished());
            first
                .notify(json!({
                    "sequence": 4, "response": "accept-producer", "type": "response",
                }))
                .await;
            joining
                .await
                .unwrap()
                .unwrap_or_else(|e| panic!("connect: {e}"));
            session.supervise();

            // The kept request is served now: the first attempt goes whole.
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            until("the first guest leaves", || {
                first.gone.load(Ordering::SeqCst)
            })
            .await;
            assert_eq!(first.hangups().len(), 1, "{:?}", first.frames());
            assert_eq!(room.conns().len(), 2);
            let second = room.conn(1);
            assert!(session.can_send());
            assert!(!second.gone.load(Ordering::SeqCst));
            assert!(second.hangups().is_empty());
            assert_eq!(session.rejoins_queued(), 1);

            // Nothing is left behind by the close: every guest has gone,
            // each with its one hangup.
            session.close().await;
            until("the second guest leaves", || {
                second.gone.load(Ordering::SeqCst)
            })
            .await;
            assert_eq!(second.hangups().len(), 1);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(room.conns().len(), 2);
        })
        .await;
    }

    // ----- A task that panics.

    /// Correctness S3: a panic under a rejoin unwinds the supervisor's
    /// task. Without a word the session would look alive for good: every
    /// later request takes the slot and nobody serves it. The session ends
    /// instead, and says so once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_that_panics_ends_the_session() {
        rejoin_that_panics().await;
    }

    /// The same, repeated: the race it once had (the `Ended` event
    /// reached the test before the session was marked closed) showed one
    /// run in a few hundred.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_that_panics_ends_the_session_every_time() {
        for _ in 0..STRESS_ROUNDS {
            rejoin_that_panics().await;
        }
    }

    const STRESS_ROUNDS: usize = 200;

    async fn rejoin_that_panics() {
        bounded(async {
            let room = FakeRoom::start().await;
            let issue: Issue = Arc::new(|| -> Issuing { panic!("a test's issuer panics") });
            let (session, mut news) =
                Session::new(settings(&room.endpoint(42, "FIRST"), Some(issue))).unwrap();
            session.connect().await.unwrap_or_else(|e| panic!("{e}"));
            session.supervise();
            session.reconnect("peer restart");
            let said = tokio::time::timeout(Duration::from_secs(5), news.recv())
                .await
                .expect("the supervisor is gone and the session said nothing");
            assert_eq!(said, Some(EngineEvent::Ended(TASK_FAILED.to_owned())));
            assert_eq!(TASK_FAILED, "vkcalls: a session task failed");
            // The session is closed to everything that follows.
            session.reconnect("after the end");
            assert_eq!(session.rejoins_queued(), 1);
            assert!(matches!(session.connect().await, Err(Error::Closed)));
            // The old attempt went before the issuer was asked.
            let old = room.conn(0);
            until("the old guest leaves", || old.gone.load(Ordering::SeqCst)).await;
            assert_eq!(old.hangups().len(), 1);
            session.close().await;
            assert!(news.try_recv().is_err());
            assert_eq!(room.conns().len(), 1);
        })
        .await;
    }

    /// The same for the notification loop: it is the one that answers
    /// later offers and notices the socket's end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_notification_loop_that_panics_ends_the_session() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (session, mut news, conn) = joined(&room, Waits::default()).await;
            conn.notify(json!({
                "type": "notification", "notification": "olc-test-panic",
            }))
            .await;
            let said = tokio::time::timeout(Duration::from_secs(5), news.recv())
                .await
                .expect("the notification loop is gone and the session said nothing");
            assert_eq!(said, Some(EngineEvent::Ended(TASK_FAILED.to_owned())));
            session.reconnect("after the end");
            assert_eq!(session.rejoins_queued(), 0);
            // The owner's close still leaves the call.
            session.close().await;
            until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            assert_eq!(conn.hangups().len(), 1);
            assert_eq!(room.conns().len(), 1);
        })
        .await;
    }

    // ----- The close.

    /// Correctness S5: a close while a rejoin runs returns only once the
    /// rejoin's guest has hung up. The client's runtime ends right after
    /// the close, as a process that exits does: a hangup still on its way
    /// then is never sent, and the guest stays listed in the call.
    #[test]
    fn a_close_during_a_rejoin_has_hung_up_when_it_returns() {
        let room_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let client_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let room = room_rt.block_on(FakeRoom::start());
        let (session, _news) = client_rt.block_on(bounded(async {
            let (session, news) =
                Session::new(settings(&room.endpoint(42, "SECRETTOKEN"), None)).unwrap();
            session
                .connect()
                .await
                .unwrap_or_else(|e| panic!("connect: {e}"));
            session.supervise();
            (session, news)
        }));
        // The rejoin's guest gets no offer: the rejoin waits for it.
        room.script.silent.store(true, Ordering::SeqCst);
        session.reconnect("peer restart");
        client_rt.block_on(bounded(until("the rejoin waits for its offer", || {
            room.conns().len() == 2
                && room
                    .conn(1)
                    .names()
                    .iter()
                    .any(|name| name == "update-media-modifiers")
        })));
        client_rt.block_on(bounded(session.close()));
        drop(client_rt);

        let (old, new) = (room.conn(0), room.conn(1));
        room_rt.block_on(bounded(until("the guests' sockets end", || {
            old.gone.load(Ordering::SeqCst) && new.gone.load(Ordering::SeqCst)
        })));
        assert_eq!(old.hangups(), [hangup_at(5)]);
        assert_eq!(new.hangups(), [hangup_at(3)], "{:?}", new.frames());
        assert_eq!(room.conns().len(), 2);
    }

    // ----- The command channel.

    /// `producerCommand`: `change-simulcast` under the raw counter the
    /// moment the channel opens, then a layout for everything known, again
    /// on every registry frame and for every new participant; one counter
    /// for all of them, advanced whether or not a layout went out. What was
    /// read while the offer was waited for is not noted (plan D6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_command_channel_carries_the_simulcast_and_the_layout() {
        bounded(async {
            let room = FakeRoom::start().await;
            room.script.early.lock().unwrap().push(json!({
                "type": "notification", "notification": "participant-joined",
                "participantId": 99,
            }));
            // No perf report takes a number while the layouts are counted.
            let waits = Waits {
                perf: Duration::from_secs(3600),
                ..Waits::default()
            };
            let (session, _news, conn) = joined(&room, waits).await;
            until("change-simulcast", || !conn.commands().is_empty()).await;
            assert_simulcast(&conn.commands()[0]);
            until("the notification channel", || {
                conn.channels.lock().unwrap().len() == 2
            })
            .await;
            // Nothing is known yet: the two layouts so far (at the open and
            // at the run's start) took a number each and sent nothing, so
            // three numbers are gone.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(conn.commands().len(), 1, "{:x?}", conn.commands());

            // The registry names a camera: asked for by its compact id.
            let mut registry = vec![0x01, 0x81, 0xAB];
            registry.extend_from_slice(b"u77:sCAMERA");
            registry.push(0x05);
            let notification = conn.channel("producerNotification");
            assert!(conn.sfu.write(notification, true, &registry).unwrap());
            until("the first layout", || conn.commands().len() == 2).await;
            assert_eq!(
                conn.commands()[1],
                hex("000004c091c40a050001d10280d1016800c0")
            );
            // A frame of another kind changes nothing.
            assert!(conn.sfu.write(notification, true, &[0x06, 0x00]).unwrap());

            // A participant joins: its camera is asked for by key until the
            // registry names it. The same one again, and ourselves, ask
            // nothing.
            let mut known = ControlState::new();
            known.on_service_frame(&registry).unwrap();
            let expect = |known: &ControlState, sequence: i64| {
                encode_layout(
                    sequence,
                    &layout_entries(known.registry(), known.participants()),
                )
                .unwrap()
            };
            let joins = |id: Value| {
                json!({
                    "type": "notification", "notification": "participant-joined",
                    "participantId": id,
                })
            };
            conn.notify(joins(json!(88))).await;
            until("the second layout", || conn.commands().len() == 3).await;
            known.note_participant("88");
            let second = conn.commands()[2].clone();
            assert_eq!(second, expect(&known, 5));
            assert_eq!(&second[..5], &hex("0000 05 c0 92")[..]);
            assert!(second.windows(11).any(|window| window == b"u88:sCAMERA"));
            conn.notify(joins(json!(88))).await;
            conn.notify(joins(json!(42))).await;
            conn.notify(json!({
                "type": "notification", "notification": "media-settings-changed",
                "participantId": "89",
            }))
            .await;
            until("the third layout", || conn.commands().len() == 4).await;
            known.note_participant("89");
            assert_eq!(conn.commands()[3], expect(&known, 6));

            // One hangs up: nothing is sent for it, and the next layout
            // asks for it no more. The early participant never was asked
            // for.
            conn.notify(json!({
                "type": "notification", "notification": "hungup", "participantId": 88,
            }))
            .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(conn.sfu.write(notification, true, &registry).unwrap());
            until("the fourth layout", || conn.commands().len() == 5).await;
            known.remove_stream("88");
            let fourth = conn.commands()[4].clone();
            assert_eq!(fourth, expect(&known, 7));
            for frame in conn.commands() {
                assert!(!frame.windows(3).any(|w| w == b"u99"), "{frame:x?}");
            }
            assert!(!fourth.windows(3).any(|w| w == b"u88"));
            session.close().await;
        })
        .await;
    }

    /// The perf report: every interval while the channel is open, both
    /// values the video packets received so far, under the counter the
    /// other commands share.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_perf_report_counts_the_video_received() {
        bounded(async {
            let room = FakeRoom::start().await;
            let waits = Waits {
                perf: Duration::from_millis(150),
                ..Waits::default()
            };
            let (session, _news, conn) = joined(&room, waits).await;
            let reports = || -> Vec<Vec<u8>> {
                conn.commands()
                    .into_iter()
                    .filter(|frame| frame.starts_with(&[0x01, 0x00]))
                    .collect()
            };
            until("two reports", || reports().len() >= 2).await;
            // Nothing received yet; the numbers follow the three taken by
            // the open and the run's start, one apart.
            let first = reports();
            assert_eq!(first[0], encode_perf_stat_report(4, 0, 0));
            assert_eq!(first[1], encode_perf_stat_report(5, 0, 0));

            until("the SFU's side", || conn.sfu_up.load(Ordering::SeqCst)).await;
            let sent = packets(&frame(0x44, 5000), 300);
            assert!(sent.len() >= 5);
            conn.forward("6", MID_6_SSRC, 100, false, &sent);
            let n = u32::try_from(sent.len()).unwrap();
            until("a report of what was received", || {
                reports()
                    .iter()
                    .any(|frame| (1..400).any(|seq| *frame == encode_perf_stat_report(seq, n, n)))
            })
            .await;
            session.close().await;
            // No report follows the close.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let after = reports().len();
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert_eq!(reports().len(), after);
        })
        .await;
    }

    // ----- RTP.

    /// RTP out: every sample goes out on the publish slot at the slot's
    /// VP8 payload type, with the slot's mid and the rid `l` on every
    /// packet, the transport-wide sequence number, and no abs-send-time
    /// (plan D9).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn samples_go_out_on_the_publish_slots_layer() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (session, _news, conn) = joined(&room, Waits::default()).await;
            // Long enough for the SFU's first receiver reports.
            for i in 0..60u8 {
                assert!(session.write_sample(&frame(i, 200)));
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            // A sample of three packets.
            assert!(session.write_sample(&frame(0x77, 3000)));
            until("the packets", || conn.rtp().len() >= 63).await;
            assert_eq!(session.rtp_out(), 63);
            let got = conn.rtp();
            assert_eq!(got.len(), 63);
            for (i, p) in got.iter().enumerate() {
                assert_eq!(p.pt, 100, "{p:?}");
                assert_eq!(p.mid.as_deref(), Some("3"), "packet {i}: {p:?}");
                assert_eq!(p.rid.as_deref(), Some("l"), "packet {i}: {p:?}");
                assert!(!p.abs_send_time, "{p:?}");
                assert!(p.twcc, "{p:?}");
                assert_eq!(p.seq, got[0].seq.wrapping_add(u16::try_from(i).unwrap()));
            }
            session.close().await;
            // Nothing goes out after the close.
            assert!(session.write_sample(&frame(9, 200)));
            assert_eq!(session.rtp_out(), 63);
        })
        .await;
    }

    /// RTP in: a camera forwarded as VP8 and one forwarded wrapped in
    /// `red`, each on its own SSRC, both reach the transport as whole
    /// frames; without a handler nothing is read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarded_cameras_reach_the_transport_as_frames() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (session, _news, conn) = joined(&room, Waits::default()).await;
            until("the SFU's side", || conn.sfu_up.load(Ordering::SeqCst)).await;
            let frames: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
            session.set_frame_handler(Some(Arc::new({
                let frames = Arc::clone(&frames);
                move |frame: &[u8]| frames.lock().unwrap().push(frame.to_vec())
            })));
            let (bare, wrapped) = (frame(0x51, 2600), frame(0x62, 2600));
            conn.forward("6", MID_6_SSRC, 100, false, &packets(&bare, 700));
            until("the bare frame", || frames.lock().unwrap().len() == 1).await;
            conn.forward("5", MID_5_SSRC, 104, true, &packets(&wrapped, 9000));
            until("the wrapped frame", || frames.lock().unwrap().len() == 2).await;
            assert_eq!(*frames.lock().unwrap(), [bare.clone(), wrapped]);

            session.set_frame_handler(None);
            conn.forward("6", MID_6_SSRC, 100, false, &packets(&bare, 710));
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(frames.lock().unwrap().len(), 2);
            session.close().await;
        })
        .await;
    }

    // ----- A bound that refuses.

    /// A `producer-updated` notification as the SFU sends one.
    fn producer_updated(session_id: &str, description: &str) -> Value {
        json!({
            "type": "notification", "notification": "producer-updated",
            "sessionId": session_id, "description": description,
        })
    }

    /// Fidelity S3 of the wave-2 review: the bounds on an offer are ours,
    /// not Go's, and an offer that is not answered fails the join or asks
    /// a rejoin, where the SFU offers the same again. The run that meets
    /// one is told which bound it was, in one line with no room data: for a
    /// first offer and for a later one. An offer refused for any other
    /// reason names none, and neither does one that is answered.
    #[tokio::test]
    async fn a_bound_that_refuses_an_offer_is_named_in_the_log() {
        bounded_for(Duration::from_secs(90), async {
            let log = crate::testing::log_lines();
            let section = "m=video 9 UDP/TLS/RTP/SAVPF 100\r\na=mid:x\r\n";
            let too_many = live_shape_offer() + &section.repeat(crate::answer::MAX_SDP_SECTIONS);
            let too_long = live_shape_offer() + &"a=x\r\n".repeat(crate::answer::MAX_SDP_LINES);
            let no_slot = live_shape_offer().replace("a=recvonly", "a=sendonly");
            for (offer, text) in [
                (&too_many, "vkcalls: SDP exceeds size bound"),
                (&too_long, "vkcalls: SDP exceeds size bound"),
                (
                    &no_slot,
                    "vkcalls: native answer declares no video publish section",
                ),
            ] {
                let room = FakeRoom::start().await;
                *room.script.offer.lock().unwrap() = Some(offer.clone());
                let (session, _news) =
                    Session::new(settings(&room.endpoint(42, "SECRETTOKEN"), None)).unwrap();
                let error = session.connect().await.unwrap_err();
                assert_eq!(error.to_string(), text);
                let conn = room.conn(0);
                until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
                assert_eq!(conn.hangups().len(), 1);
                session.close().await;
            }
            assert_eq!(
                log.starting("vkcalls: bound "),
                [
                    "vkcalls: bound MAX_SDP_SECTIONS (128) refused the offer",
                    "vkcalls: bound MAX_SDP_LINES (16384) refused the offer",
                ]
            );
            for line in log.read() {
                assert!(
                    !line.contains("SECRETTOKEN") && !line.contains("a=mid"),
                    "{line}"
                );
            }

            // A later offer: the line once, then the rejoin Go's failed
            // renegotiation asks for.
            let log = crate::testing::log_lines();
            let room = FakeRoom::start().await;
            let (session, mut news, conn) = joined(&room, Waits::default()).await;
            assert_eq!(log.starting("vkcalls: bound "), [""; 0]);
            conn.notify(producer_updated("sess-2", &too_many)).await;
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert_eq!(
                log.starting("vkcalls: bound "),
                ["vkcalls: bound MAX_SDP_SECTIONS (128) refused the offer"]
            );
            assert_eq!(session.rejoins_queued(), 1);
            session.close().await;
        })
        .await;
    }

    /// Memory 5 of the wave-2 review: the session id of the last answered
    /// offer is kept for the attempt, and the socket's bound alone would
    /// let it be half a megabyte. An offer whose id is longer than
    /// [`MAX_SESSION_ID`] is not answered and its id is not kept: a first
    /// offer fails the join (the guest hangs up), a later one asks a
    /// rejoin; the log names the bound. An id at the bound is answered.
    #[tokio::test]
    async fn an_offers_session_id_has_a_bound() {
        bounded_for(Duration::from_secs(90), async {
            let line = "vkcalls: bound MAX_SESSION_ID (256 bytes) refused the offer";
            let log = crate::testing::log_lines();
            let room = FakeRoom::start().await;
            *room.script.session_id.lock().unwrap() = Some("s".repeat(MAX_SESSION_ID + 1));
            let (session, _news) =
                Session::new(settings(&room.endpoint(42, "SECRETTOKEN"), None)).unwrap();
            let error = session.connect().await.unwrap_err();
            assert!(matches!(error, Error::Bound(_)), "{error}");
            assert_eq!(
                error.to_string(),
                "vkcalls: the offer's session id is past its bound"
            );
            let conn = room.conn(0);
            until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            assert_eq!(
                conn.names(),
                [
                    "allocate-consumer",
                    "update-media-modifiers",
                    "change-media-settings",
                    "hangup"
                ]
            );
            assert_eq!(log.starting("vkcalls: bound "), [line]);
            session.close().await;

            // At the bound the offer is answered under its id.
            let log = crate::testing::log_lines();
            let room = FakeRoom::start().await;
            let at = "s".repeat(MAX_SESSION_ID);
            *room.script.session_id.lock().unwrap() = Some(at.clone());
            let (session, mut news, conn) = joined(&room, Waits::default()).await;
            assert_eq!(conn.sent()[3].2["sessionId"], at.as_str());
            assert_eq!(log.starting("vkcalls: bound "), [""; 0]);
            // A later offer past it: not answered, not kept, a rejoin.
            let past = "t".repeat(MAX_SESSION_ID + 1);
            conn.notify(producer_updated(&past, &conn.offer)).await;
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            until("the old guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            assert_eq!(
                conn.names(),
                [
                    "allocate-consumer",
                    "update-media-modifiers",
                    "change-media-settings",
                    "accept-producer",
                    "hangup"
                ]
            );
            assert_eq!(log.starting("vkcalls: bound "), [line]);
            assert_eq!(MAX_SESSION_ID, 256);
            session.close().await;
        })
        .await;
    }

    /// A join through the provider, as the client asks for one.
    fn through_provider<'a>(
        room: &'a str,
        name: &'a str,
        token: &'a str,
        base: &'a str,
    ) -> Join<'a> {
        Join {
            via_provider: true,
            room,
            token,
            ice_servers: "",
            provider_base: Some(base),
            name,
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            relay_only: false,
            max_joins: 0,
            frame_interval: Duration::from_millis(16),
        }
    }

    /// Memory 5 of the wave-2 review: what a session keeps for its life to
    /// join again with has a bound, as MTS Link's has. A link, a name or
    /// an account token past its bound is refused before the provider is
    /// asked anything, and credentials whose endpoint or ICE servers are
    /// longer than the provider's own bounds make no session, direct ones
    /// included. The error names which, never the value.
    #[tokio::test]
    async fn what_a_session_keeps_has_a_bound() {
        crate::testing::bounded(async {
            const ROOM: &str = crate::auth::tests::TEST_ROOM;
            let stub = Stub::start(|_| Reply::new(500, "")).await;
            let long_link = format!("{ROOM}{}", "x".repeat(MAX_ROOM_LINK));
            let long_name = "n".repeat(MAX_NAME + 1);
            let long_token = "t".repeat(MAX_ROOM_LINK + 1);
            for (asked, what) in [
                (
                    through_provider(&long_link, "Anna", "", &stub.base),
                    "the room link",
                ),
                (
                    through_provider(ROOM, &long_name, "", &stub.base),
                    "the name",
                ),
                (
                    through_provider(ROOM, "Anna", &long_token, &stub.base),
                    "the account token",
                ),
            ] {
                let error = join(asked).await.unwrap_err();
                assert!(matches!(error, Error::Bound(_)), "{what}: {error}");
                assert_eq!(
                    error.to_string(),
                    format!("vkcalls: {what} is past its bound")
                );
            }
            assert!(stub.seen().is_empty(), "the provider was asked");
            // At the bounds the provider is asked.
            let at_name = "n".repeat(MAX_NAME);
            let at = join(through_provider(ROOM, &at_name, "", &stub.base))
                .await
                .unwrap_err();
            assert!(matches!(at, Error::Auth(_)), "{at}");
            assert_eq!(stub.seen().len(), 1);

            // Credentials, however they came.
            let long_endpoint =
                format!("ws://127.0.0.1:9/fb?token={}", "t".repeat(auth::TOKEN_MAX));
            let error = Session::new(settings(&long_endpoint, None)).unwrap_err();
            assert_eq!(error.to_string(), "vkcalls: the endpoint is past its bound");
            assert!(!error.to_string().contains("ttt"));
            let with_ice = |len: usize| {
                let mut settings = settings("ws://127.0.0.1:9/fb", None);
                settings.credentials.ice_servers = "x".repeat(len);
                Session::new(settings)
            };
            let error = with_ice(auth::ICE_JSON_MAX + 1).unwrap_err();
            assert_eq!(
                error.to_string(),
                "vkcalls: the ICE servers' text is past its bound"
            );
            assert!(with_ice(auth::ICE_JSON_MAX).is_ok());
            assert_eq!((MAX_ROOM_LINK, MAX_NAME), (2048, 256));
            const { assert!(KEPT_HELD <= 114 << 10) };
        })
        .await;
    }

    // ----- What the far end hears when a peer connection goes.

    /// How long the fake SFU's driver took to end, or a panic that says
    /// which way of going it did not hear.
    async fn heard(what: &str, round: usize, conn: &Conn, ours: Option<&Peer>) -> Duration {
        let began = Instant::now();
        let ended = tokio::time::timeout(Duration::from_secs(8), conn.sfu.ended()).await;
        assert!(
            ended.is_ok(),
            "{what}, round {round}: the SFU's peer connection had not ended 8 s after ours \
             went (ours ended: {:?}, the guest's socket gone: {}); the SFU's peer said {:?}",
            ours.map(Peer::is_ended),
            conn.gone.load(Ordering::SeqCst),
            conn.events.lock().unwrap()
        );
        began.elapsed()
    }

    /// Waits until the service channels carry data both ways: the SFU has
    /// the `change-simulcast` the client sends when `producerCommand`
    /// opens, so SCTP's handshake is over.
    async fn channels_up(conn: &Conn) {
        until("the command channel", || !conn.commands().is_empty()).await;
    }

    /// Merge item 4 of wave 2 (seen once in a run of M7.8: the fake SFU's
    /// driver had not ended 15 s after the client's peer closed). Every way
    /// a session lets a peer connection go says goodbye on it (SCTP's
    /// shutdown and DTLS's close_notify), so the far end ends at once
    /// instead of at its ICE timeout: a close, a rejoin's teardown of the
    /// old attempt, and a session dropped unclosed. Many rounds of each.
    /// Each waits for the service channels first: what a close inside
    /// SCTP's handshake says is the test below.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sfu_hears_every_way_a_peer_connection_goes() {
        const ROUNDS: usize = 12;
        bounded_for(Duration::from_secs(300), async {
            let mut slowest = [Duration::ZERO; 3];
            for round in 0..ROUNDS {
                // A close.
                let room = FakeRoom::start().await;
                let (session, _news, conn) = joined(&room, Waits::default()).await;
                channels_up(&conn).await;
                assert!(session.write_sample(&frame(1, 3000)));
                let ours = current_peer(&session);
                session.close().await;
                let took = heard("a close", round, &conn, Some(&ours)).await;
                slowest[0] = slowest[0].max(took);

                // A rejoin: the old attempt's teardown, then the close of
                // the new one.
                let room = FakeRoom::start().await;
                let (session, mut news, conn) = joined(&room, Waits::default()).await;
                channels_up(&conn).await;
                let ours = current_peer(&session);
                session.reconnect("the test asks");
                assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
                let took = heard("a rejoin's teardown", round, &conn, Some(&ours)).await;
                slowest[1] = slowest[1].max(took);
                channels_up(&room.conn(1)).await;
                let ours = current_peer(&session);
                session.close().await;
                heard("a close after a rejoin", round, &room.conn(1), Some(&ours)).await;

                // A session dropped unclosed.
                let room = FakeRoom::start().await;
                let (session, news, conn) = joined(&room, Waits::default()).await;
                channels_up(&conn).await;
                assert!(session.write_sample(&frame(2, 3000)));
                let ours = current_peer(&session);
                drop(news);
                drop(session);
                let took = heard("a session dropped unclosed", round, &conn, Some(&ours)).await;
                slowest[2] = slowest[2].max(took);
            }
            eprintln!(
                "the SFU heard, slowest of {ROUNDS}: a close {:?}, a rejoin's teardown {:?}, \
                 a session dropped unclosed {:?}",
                slowest[0], slowest[1], slowest[2]
            );
            // Our driver bounds its goodbyes at CLOSE_DRAIN; the far end
            // hears them long before that.
            for took in slowest {
                assert!(took < olc_rtc::peer::CLOSE_DRAIN, "{slowest:?}");
            }
        })
        .await;
    }

    /// What merge item 4 was: a peer connection closed inside SCTP's
    /// handshake (the first milliseconds after it connected, before the
    /// SFU's COOKIE-ACK came back: the SFU has seen the channels open, the
    /// client's association is not established yet) said no goodbye.
    /// Upstream str0m's `Rtc::close` asks sctp-proto to shut the
    /// association down first, which refuses one that is not established
    /// (`ErrShutdownNonEstablished`), and returned before DTLS's
    /// close_notify was queued; olc-rtc's driver dropped that error, waited
    /// out [`olc_rtc::peer::CLOSE_DRAIN`] and ended, and the far end learnt
    /// nothing until its ICE gave up. Fixed in the vendored str0m (patch 5,
    /// `olc/vendor/str0m-0.25.0/XRAY-PATCH.md`; its own test is
    /// `tests/dtls-close.rs`). VK's SFU is told by the hangup on the socket
    /// all the same; this is what a peer that only speaks WebRTC hears.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_close_inside_the_sctp_handshake_is_heard() {
        bounded_for(Duration::from_secs(120), async {
            for round in 0..6 {
                let room = FakeRoom::start().await;
                let (session, _news, conn) = joined(&room, Waits::default()).await;
                let ours = current_peer(&session);
                // Connected a moment ago: no service channel has carried
                // anything yet.
                let inside = conn.commands().is_empty();
                let began = Instant::now();
                session.close().await;
                let closing = began.elapsed();
                let took =
                    heard("a close inside SCTP's handshake", round, &conn, Some(&ours)).await;
                eprintln!(
                    "round {round}: inside the handshake {inside}, the close took {closing:?}, \
                     the SFU heard after {took:?}"
                );
                assert!(
                    closing < olc_rtc::peer::CLOSE_DRAIN,
                    "the close waited out its drain: {closing:?}"
                );
            }
        })
        .await;
    }

    // ----- Later offers.

    /// `run`: an offer of the session already answered is passed over; one
    /// of a new session is answered on the same peer connection with the
    /// attempt's state (the version two further) and no second wait; one
    /// that cannot be answered asks for a rejoin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_later_offer_is_answered_or_the_session_rejoins() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (session, mut news, conn) = joined(&room, Waits::default()).await;
            let updated = |session_id: &str, description: &str| {
                json!({
                    "type": "notification", "notification": "producer-updated",
                    "sessionId": session_id, "description": description,
                })
            };
            let more = {
                let lines: Vec<&str> = conn.offer.split("\r\n").collect();
                let at = lines
                    .iter()
                    .rposition(|line| line.starts_with("m=video"))
                    .unwrap();
                lines[at..]
                    .join("\r\n")
                    .replace("a=mid:6", "a=mid:7")
                    .replace("2463708140", "2463708141")
            };
            assert!(more.contains("a=mid:7"), "{more}");
            let later = conn
                .offer
                .replace("a=group:BUNDLE 0 1 3 5 6", "a=group:BUNDLE 0 1 3 5 6 7")
                .replace("1790552100511", "1790552100512")
                + &more;

            conn.notify(updated("sess-1", &later)).await;
            conn.notify(updated("sess-2", "")).await;
            conn.notify(updated("sess-2", &later)).await;
            until("the second answer", || conn.sent().len() == 5).await;
            let sent = conn.sent();
            let (name, sequence, accept) = &sent[4];
            assert_eq!((name.as_str(), *sequence), ("accept-producer", 5));
            assert_eq!(accept["sessionId"], "sess-2");
            let shaped = accept["description"].as_str().unwrap();
            assert!(shaped.contains(" 4 IN IP4 127.0.0.1\r\n"), "{shaped}");
            assert!(shaped.contains("a=mid:7\r\n"));
            assert!(accept["ssrcs"]
                .as_array()
                .unwrap()
                .contains(&json!("2463708141")));
            assert!(session.can_send());
            assert_eq!(session.rejoins_queued(), 0);
            // The same session again: nothing.
            conn.notify(updated("sess-2", &later)).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(conn.sent().len(), 5);

            // An offer the stack refuses: the attempt is given up and the
            // session joins again (with the endpoint it has: no issuer).
            conn.notify(updated("sess-3", "v=0\r\nm=video x y\r\n"))
                .await;
            let event = news.recv().await;
            assert_eq!(event, Some(EngineEvent::Reconnected));
            assert_eq!(session.rejoins_queued(), 1);
            assert_eq!(room.conns().len(), 2);
            until("the old guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            assert_eq!(conn.hangups().len(), 1);
            assert!(room.conn(1).head.contains("userId=42"));
            session.close().await;
        })
        .await;
    }

    // ----- The rejoin.

    /// A rejoin is a fresh guest: the old attempt goes whole (one hangup
    /// on its socket, its peer connection closed), the provider is asked
    /// for a new guest, the new guest joins from scratch on a new socket
    /// (the sequences and the command counter start again), and the
    /// transport is told. Asked for by the layer above, by the socket's
    /// end and by the peer connection's close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_is_a_fresh_guest() {
        bounded_for(Duration::from_secs(60), async {
            let room = FakeRoom::start().await;
            let (issue, calls) = guests(&room, &[]);
            let (session, mut news) =
                Session::new(settings(&room.endpoint(42, "FIRST"), Some(issue))).unwrap();
            session.connect().await.unwrap_or_else(|e| panic!("{e}"));
            session.supervise();
            // The room was in SERVER topology: no guest was recruited.
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(room.conns().len(), 1);

            // `was`: the old attempt's peer connection. `hung_up`: the old
            // guest's socket was there to hang up on.
            let fresh = |index: usize, user: &str, token: &str, was: Peer, hung_up: bool| {
                let (old, new) = (room.conn(index - 1), room.conn(index));
                let (user, token) = (user.to_owned(), token.to_owned());
                let now = current_peer(&session);
                async move {
                    // The old peer connection is closed, the new one runs.
                    was.ended().await;
                    assert!(!now.is_ended());
                    until("the old guest leaves", || old.gone.load(Ordering::SeqCst)).await;
                    assert_eq!(
                        old.hangups().len(),
                        usize::from(hung_up),
                        "{:?}",
                        old.frames()
                    );
                    assert_eq!(
                        old.names().last().map(String::as_str) == Some("hangup"),
                        hung_up
                    );
                    assert!(new.head.contains(&user), "{}", new.head);
                    assert!(new.head.contains(&token), "{}", new.head);
                    assert!(new.head.contains("tgt=join"));
                    let order: Vec<(String, i64)> = new
                        .sent()
                        .into_iter()
                        .map(|(name, sequence, _)| (name, sequence))
                        .collect();
                    assert_eq!(
                        order,
                        [
                            ("allocate-consumer".to_owned(), 1),
                            ("update-media-modifiers".to_owned(), 2),
                            ("change-media-settings".to_owned(), 3),
                            ("accept-producer".to_owned(), 4),
                        ]
                    );
                    until("change-simulcast", || !new.commands().is_empty()).await;
                    assert_simulcast(&new.commands()[0]);
                    assert!(new.hangups().is_empty());
                }
            };

            // The layer above says the path is dead.
            let was = current_peer(&session);
            session.reconnect("peer restart");
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(room.conns().len(), 2);
            assert_eq!(session.rejoins_queued(), 1);
            assert!(session.can_send());
            fresh(1, "userId=51", "token=TOKEN1", was, true).await;
            // The old guest's hangup named its own socket's next number.
            assert_eq!(
                room.conn(0).hangups(),
                [r#"{"command":"hangup","reason":"HUNGUP","sequence":5}"#]
            );

            // The socket goes: there is nothing left to hang up on (Go's
            // `close` writes into the dead socket and lets the error go).
            let was = current_peer(&session);
            let _ = room.conn(1).write.lock().await.shutdown().await;
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(room.conns().len(), 3);
            fresh(2, "userId=52", "token=TOKEN2", was, false).await;

            // The peer connection closes under the session (pion's
            // `closed`, whatever ended it).
            let was = current_peer(&session);
            was.close();
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert_eq!(room.conns().len(), 4);
            fresh(3, "userId=53", "token=TOKEN3", was, true).await;
            assert_eq!(session.rejoins_queued(), 3);

            // What is written now goes out on the new peer connection.
            let last = room.conn(3);
            assert!(session.write_sample(&frame(3, 200)));
            until("a packet on the new peer", || !last.rtp().is_empty()).await;
            assert_eq!(last.rtp()[0].mid.as_deref(), Some("3"));

            session.close().await;
            until("the last guest leaves", || last.gone.load(Ordering::SeqCst)).await;
            assert_eq!(last.hangups().len(), 1);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(room.conns().len(), 4);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert!(news.try_recv().is_err());
        })
        .await;
    }

    /// A rejoin whose guest the provider refuses: the old attempt is gone
    /// already (it hung up), the error is Go's, the transport is told
    /// nothing; the next one joins. And the limit ends the session for
    /// good.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_guest_fails_the_rejoin_and_the_limit_ends_the_session() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (issue, calls) = guests(&room, &[1]);
            let (session, mut news) =
                Session::new(settings(&room.endpoint(42, "FIRST"), Some(issue))).unwrap();
            session.connect().await.unwrap_or_else(|e| panic!("{e}"));

            let refused = session.rejoin().await.unwrap_err();
            assert_eq!(
                refused.to_string(),
                "refresh credentials: auth provider rejected the request: vkcalls: invalid room url"
            );
            let old = room.conn(0);
            until("the old guest leaves", || old.gone.load(Ordering::SeqCst)).await;
            assert_eq!(old.hangups().len(), 1);
            assert!(!session.can_send());
            assert!(news.try_recv().is_err());
            assert_eq!(room.conns().len(), 1);
            // While a rejoin runs no other is asked for.
            assert!(!session.reconnecting.load(Ordering::SeqCst));

            session.rejoin().await.unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(news.try_recv().ok(), Some(EngineEvent::Reconnected));
            assert!(room.conn(1).head.contains("userId=52"));
            assert!(session.can_send());

            // The supervisor's limit (`OnLimit`).
            Rejoiner(Arc::downgrade(&session)).limit_reached(LIMIT_REASON);
            assert_eq!(
                news.recv().await,
                Some(EngineEvent::Ended("reconnect limit reached".to_owned()))
            );
            session.reconnect("after the end");
            assert_eq!(session.rejoins_queued(), 0);
            assert!(matches!(session.rejoin().await, Err(Error::Closed)));
            assert!(matches!(session.connect().await, Err(Error::Closed)));
            session.close().await;
            until("the guest leaves", || {
                room.conn(1).gone.load(Ordering::SeqCst)
            })
            .await;
            assert_eq!(room.conn(1).hangups().len(), 1);
        })
        .await;
    }

    /// The supervisor's part of a rejoin that fails: the request is tried
    /// again after the backoff (two seconds times the count), with a new
    /// guest, and one request is still one request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_rejoin_is_tried_again_after_the_backoff() {
        bounded(async {
            let room = FakeRoom::start().await;
            let (issue, calls) = guests(&room, &[1]);
            let (session, mut news) =
                Session::new(settings(&room.endpoint(42, "FIRST"), Some(issue))).unwrap();
            session.connect().await.unwrap_or_else(|e| panic!("{e}"));
            session.supervise();
            let asked = Instant::now();
            session.reconnect("peer restart");
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            let took = asked.elapsed();
            assert!(took >= olc_net::reconnect::BACKOFF_STEP, "{took:?}");
            assert!(took < Duration::from_secs(10), "{took:?}");
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(session.rejoins_queued(), 1);
            assert_eq!(room.conns().len(), 2);
            assert!(room.conn(1).head.contains("userId=52"));
            assert!(session.can_send());
            session.close().await;
        })
        .await;
    }

    // ----- What a session is given.

    /// Plan K9: the service's `turn:` servers go to the peer connection,
    /// over UDP and TCP; `stun:` ones are not asked, and `turns:` ones
    /// only where the build has Chrome's TLS.
    #[tokio::test]
    async fn the_services_turn_servers_go_to_the_peer_connection() {
        let (session, _news) = Session::new(Settings {
            relay_only: true,
            ..settings("ws://127.0.0.1:9/fb", None)
        })
        .unwrap();
        let config = session.peer_config(
            r#"[{"urls":["stun:stun.example:3478"]},{"credential":"turn-secret","urls":["turn:203.0.113.5:19302","turn:203.0.113.6:19302?transport=tcp","turns:203.0.113.7:5349"],"username":"turn-user"}]"#,
        );
        let plain: Vec<(&str, u16)> = config
            .turn
            .iter()
            .filter(|server| server.port == 19302)
            .map(|server| (server.host.as_str(), server.port))
            .collect();
        assert_eq!(plain, [("203.0.113.5", 19302), ("203.0.113.6", 19302)]);
        // The `turns:` one is olc-rtc's to take or leave, by its build.
        assert!(matches!(config.turn.len(), 2 | 3), "{:?}", config.turn);
        for server in &config.turn {
            assert_eq!(
                (server.username.as_str(), server.password.as_str()),
                ("turn-user", "turn-secret")
            );
            assert!(!server.host.contains("stun"));
        }
        assert!(config.relay_only);
        assert_eq!(config.ice_mode, IceMode::Udp);
        assert_eq!(config.host_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        // No list, or one that does not read: the SFU's own candidates.
        assert!(session.peer_config("").turn.is_empty());
        assert!(session.peer_config("{").turn.is_empty());
        let shown = format!("{config:?}");
        assert!(!shown.contains("turn-secret"), "{shown}");
    }

    /// Nothing a session shows names the room: not its `Debug`, not its
    /// settings', not a join's, not an error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_shows_nothing_of_the_room() {
        bounded(async {
            let room = FakeRoom::start().await;
            *room.script.reject.lock().unwrap() = Some("update-media-modifiers");
            let endpoint = room.endpoint(42, "SECRETTOKEN");
            let given = settings(&endpoint, None);
            let port = room.addr.port().to_string();
            let mut shown = vec![format!("{given:?}")];
            let (session, _news) = Session::new(given).unwrap();
            shown.push(format!("{session:?}"));
            let error = session.connect().await.unwrap_err();
            shown.push(format!("{error:?} {error}"));
            let asked = Join {
                via_provider: true,
                room: "https://vk.com/call/join/ROOMSECRET",
                token: "SECRETTOKEN",
                ice_servers: r#"[{"urls":["turn:203.0.113.5"],"credential":"SECRETTOKEN"}]"#,
                provider_base: None,
                name: "Anna",
                host_ip: None,
                relay_only: false,
                max_joins: 0,
                frame_interval: Duration::from_millis(16),
            };
            shown.push(format!("{asked:?}"));
            for text in &shown {
                let secrets = ["SECRETTOKEN", "ROOMSECRET", "userId", &port, "203.0.113.5"];
                for secret in secrets {
                    assert!(!text.contains(secret), "{secret} in {text}");
                }
            }
            session.close().await;
        })
        .await;
    }

    /// `join`: an engine joined without its provider takes its endpoint as
    /// given and comes back as the transport's engine; a join that fails
    /// leaves no guest behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_hands_the_session_back_as_the_transports_engine() {
        bounded(async {
            let room = FakeRoom::start().await;
            let endpoint = room.endpoint(42, "SECRETTOKEN");
            fn asked(endpoint: &str) -> Join<'_> {
                Join {
                    via_provider: false,
                    room: endpoint,
                    token: "",
                    ice_servers: "",
                    provider_base: None,
                    name: "Anna",
                    host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    relay_only: false,
                    max_joins: 0,
                    frame_interval: Duration::from_millis(16),
                }
            }
            let Joined { engine, mut events } = join(asked(&endpoint)).await.unwrap();
            assert_eq!(engine.carrier(), Carrier::Vp8);
            assert!(engine.can_send());
            assert!(engine.wait_peer_settled().is_none());
            let conn = room.conn(0);
            assert!(engine.write_sample(&frame(5, 300)));
            until("a packet", || !conn.rtp().is_empty()).await;
            // The transport asks for a rejoin: with no provider the guest
            // joins again on the endpoint it has.
            engine.reconnect("peer restart");
            assert_eq!(events.recv().await, Some(EngineEvent::Reconnected));
            assert!(room.conn(1).head.contains("userId=42"));
            engine.close().await;
            until("the guests leave", || {
                room.conns().iter().all(|c| c.gone.load(Ordering::SeqCst))
            })
            .await;
            assert_eq!(conn.hangups().len(), 1);
            assert_eq!(room.conn(1).hangups().len(), 1);

            // A join that fails.
            let room = FakeRoom::start().await;
            *room.script.reject.lock().unwrap() = Some("change-media-settings");
            let endpoint = room.endpoint(42, "SECRETTOKEN");
            let error = join(asked(&endpoint)).await.unwrap_err();
            assert_eq!(
                error.to_string(),
                "vkcalls: signaling command rejected: change-media-settings"
            );
            let conn = room.conn(0);
            until("the guest leaves", || conn.gone.load(Ordering::SeqCst)).await;
            assert_eq!(conn.hangups().len(), 1);
            assert!(matches!(
                join(asked("")).await.unwrap_err(),
                Error::NoEndpoint
            ));
        })
        .await;
    }

    /// The issuer of a join through the provider: the whole chain for
    /// every guest, each a new guest (its own device ids), the provider's
    /// two services at the one base a test names.
    #[tokio::test]
    async fn every_guest_of_a_join_walks_the_providers_chain() {
        crate::testing::bounded(async {
            let stub = Stub::start(|seen| {
                let method = match seen.target.strip_prefix("/method/") {
                    Some(method) => method.to_owned(),
                    None => {
                        assert_eq!(seen.target, "/fb.do");
                        crate::auth::tests::form_value(&seen.body, "method")
                            .unwrap_or("")
                            .to_owned()
                    }
                };
                Reply::new(200, crate::auth::tests::default_answer(&method))
                    .header("Content-Type", "application/json")
            })
            .await;
            let issue = issuer(&Join {
                via_provider: true,
                room: crate::auth::tests::TEST_ROOM,
                token: "",
                ice_servers: "",
                provider_base: Some(&stub.base),
                name: "Anna",
                host_ip: None,
                relay_only: false,
                max_joins: 0,
                frame_interval: Duration::from_millis(16),
            });
            let first = issue().await.unwrap();
            let second = issue().await.unwrap();
            assert_eq!(first.url, crate::auth::tests::ENDPOINT);
            assert_eq!(first.url, second.url);
            assert!(first.ice_servers.contains("turn:91.231.135.155:19302"));
            let seen = stub.seen();
            let targets: Vec<&str> = seen.iter().map(|s| s.target.as_str()).collect();
            let chain = [
                "/method/auth.getAnonymToken",
                "/method/messages.getCallPreview",
                "/method/messages.getAnonymCallToken",
                "/fb.do",
                "/fb.do",
            ];
            assert_eq!(targets, [chain, chain].concat());
            let value = |index: usize, name: &str| {
                crate::auth::tests::form_value(&seen[index].body, name)
                    .unwrap_or_else(|| panic!("request {index} has no {name}"))
                    .to_owned()
            };
            assert_eq!(value(0, "anonymName"), "Anna");
            assert_eq!(value(0, "device_id"), value(2, "device_id"));
            assert_ne!(value(0, "device_id"), value(5, "device_id"));
            assert!(value(0, "device_id").starts_with("olcrtc-"));
        })
        .await;
    }

    /// A budget of joins is the process's, as SaluteJazz's: a join past it
    /// is refused before any dial.
    #[tokio::test]
    async fn a_join_past_the_budget_is_refused() {
        assert!(take_join(0).is_ok());
        let (session, _news) = Session::new(Settings {
            max_joins: 1,
            ..settings("ws://127.0.0.1:9/fb", None)
        })
        .unwrap();
        // The first is taken by its dial, which nothing answers.
        let first = session.connect().await.unwrap_err();
        assert!(
            matches!(first, Error::Signaling(SignalingError::Dial(_))),
            "{first}"
        );
        let second = session.connect().await.unwrap_err();
        assert!(matches!(second, Error::JoinBudget(1)), "{second}");
        assert_eq!(second.to_string(), "vkcalls join budget spent: 1 joins");
    }
}

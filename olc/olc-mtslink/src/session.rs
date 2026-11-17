// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The MTS Link engine (`internal/engine/mtslink/mtslink.go` at 2d4266af):
//! one peer connection to the service's SFU, negotiated with a single SDP
//! exchange over HTTP ([`crate::signal`]), the payload riding the published
//! VP9 track and coming back on the slots the SFU fills with the room's
//! other publishers. It is the video transport's engine
//! ([`olc_vp8channel::engine::VideoEngine`]).
//!
//! # A join
//!
//! [`Session::connect`], in Go's order: a new peer connection (a new
//! certificate, new ICE credentials, a new generation); the offer, twelve
//! lines in the web client's order less what the SFU does not ask for
//! ([`lay_out`], [`as_posted`]); the join POST with the offer as it was
//! made, before any candidate; the peer the answer names; the answer applied; the pin, whose
//! failure is a note; then the wait for the peer connection
//! ([`CONNECT_WAIT`]). A join that fails anywhere after the peer exists
//! tears its generation down and takes the guest's conference back
//! ([`crate::signal::take_back_detached`], waited for as Go waits), and so
//! does one whose future is dropped. A first join has [`CONNECT_BOUND`]
//! for all of it. `close` sends nothing for a session that is joined: the
//! service drops the conference of a publisher that reached the SFU and
//! left. A join that a close finds running is given up where it stands and
//! taken back, and the close waits for that call ([`crate::LEAVE_WAIT`] at
//! most); nothing of that join is sent after the close.
//!
//! An answer that names one payload type for two codecs is refused before
//! str0m is given it (`payload_clash`): str0m's own check is an
//! `assert!`.
//!
//! # A rejoin
//!
//! A peer connection that failed or closed after it was up, the transport's
//! peer-restart watchdog and the client's liveness ([`Stream::reconnect`])
//! each ask for a rejoin. The requests go to the shared supervisor
//! ([`olc_net::reconnect::Reconnector`], Go's `engine.Reconnector` in
//! request mode, [`MAX_RECONNECTS`] attempts), which serves them one at a
//! time on a task of its own ([`Session::supervise`]) through
//! [`Session::rejoin`], Go's `reconnect`:
//!
//! 1. the old generation is torn down first and its peer connection waited
//!    for, so the room never holds two of ours;
//! 2. the provider is asked again ([`Refresh`]: a whole [`auth::issue`], a
//!    new guest, a new conference, a new device id) and its credentials are
//!    adopted. A session on direct credentials has no refresh and joins
//!    with the ones it has;
//! 3. a join from scratch ([`Session::connect`]'s own steps, the take-back
//!    after a failure included: a rejoin that works takes nothing back);
//! 4. the transport is told ([`EngineEvent::Reconnected`]), and starts its
//!    planes again on a new epoch.
//!
//! When the attempts run out the session is closed for good and says so
//! once ([`EngineEvent::Ended`], `reconnect limit reached`). It says so as
//! well when the supervisor's task, or the task that reads a peer
//! connection's events, ends by a panic ([`SUPERVISOR_LOST`],
//! [`WATCH_LOST`]): a session nobody serves is not left looking alive.
//!
//! # Memory
//!
//! A session holds, per generation: the peer connection (`olc_rtc`'s own
//! bounds), the published stream's resend cache ([`RESEND_HELD`] at most),
//! and a track reader per publisher it hears, nine at most
//! ([`crate::readers`], [`READERS_HELD`] at most). A rejoin holds one
//! generation at a time (the old one is gone before the new one is made),
//! the supervisor holds a flag and two counters, and what the provider is
//! asked again with is the room link and the name ([`REFRESH_HELD`] at
//! most). The credentials are kept for the session's life
//! ([`crate::auth::CREDENTIALS_HELD`] at most, whoever issued them). A join
//! holds its offer (about 6 KiB), its copies of the credentials
//! ([`JOIN_HELD`]) and the SFU's answer ([`crate::REPLY_LIMIT`]) while it
//! runs; a take-back holds [`crate::signal::TAKE_BACK_HELD`] for
//! [`crate::LEAVE_WAIT`] at most, and a join starts only once the one
//! before it, its take-back included, is over. Nothing is queued between
//! the transport and the peer: a sample is
//! packetized and written under one lock, a packet that arrives is pushed
//! into its track's reader on the peer's own task.
//!
//! # ICE
//!
//! The mode is the credentials' (`Extra["ice"]`: the room link's hint, or
//! the default of the side that joins, which is TCP on the client):
//! [`ice_mode`]. Over TCP alone the peer gathers nothing and binds no
//! candidate: it dials the passive candidates the SFU's answer names
//! ([`olc_rtc::peer::Peer::remote_described`]) and sends no UDP datagram.
//!
//! # Logs
//!
//! pion's two state lines, which the apps read, come from
//! [`olc_rtc::pcstate::PcWatcher`], once per change per generation. No log
//! line, error or `Debug` here carries the join URL, the cookies or an id
//! of the room: what the SFU says when it refuses a join, which can repeat
//! the request, is cleared of them first ([`crate::signal::Held`]).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use olc_net::reconnect::{Reconnector, Rejoin, Request};
use olc_rtc::media::{with_codecs, with_extensions, CodecLine, ResendCache, RtpOut, SendLine};
use olc_rtc::pcstate::{PcState, PcWatcher};
use olc_rtc::peer::{IceMode, Peer, PeerConfig, PeerEvent, CLOSE_DRAIN};
use olc_rtc::str0m::change::{SdpAnswer, SdpPendingOffer};
use olc_rtc::str0m::format::{Codec, FormatParams};
use olc_rtc::str0m::media::{Direction, MediaKind, Mid};
use olc_rtc::str0m::rtp::{Extension, RtpPacket};
use olc_rtc::str0m::{Rtc, RtcConfig};
use olc_rtc::DtlsVersion;
use olc_vp8channel::channel::Carrier;
use olc_vp8channel::engine::{
    EngineEvent, EngineFuture, FrameHandler, Joined, KeyframeHandler, VideoEngine, EVENT_QUEUE,
};
use olc_vp8channel::rtp::{Packetizer, Payloader, RTP_OUTBOUND_MTU};
use olc_vp8channel::rtp_reader::{HeldGauge, MIME_VP9, REORDER_HOLD, REORDER_WINDOW};
use olc_vp8channel::transport::Stream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::auth::{self, Credentials, CREDENTIALS_HELD, MAX_COOKIES, MAX_ID, MAX_JOIN_URL};
use crate::readers::{Fed, Readers, MAX_READERS, READERS_HELD};
use crate::signal::{self, Agent, Held, Sfu, MAX_REFUSAL_TEXT};
use crate::{Error, Ice, LEAVE_WAIT};

/// How long a join waits for its peer connection (`connectWait`).
pub const CONNECT_WAIT: Duration = Duration::from_secs(30);
/// How long a whole first join may take: Go's video transport gives
/// `Connect` this long (`vp8channel/transport.go:58,339`). A rejoin has no
/// bound of its own, as in Go (`reconnect` calls `Connect` under the
/// supervisor's context, `mtslink.go:561`): each of its steps has one (the
/// join and the pin [`crate::HTTP_TIMEOUT`] each, the wait
/// [`CONNECT_WAIT`]), ninety seconds together.
pub const CONNECT_BOUND: Duration = Duration::from_secs(60);
/// The rejoin attempts within five minutes of one another before the
/// session ends (`maxReconnects`).
pub const MAX_RECONNECTS: u32 = 10;
/// Why a session whose attempts ran out ended (`LimitReason`).
pub const LIMIT_REASON: &str = "reconnect limit reached";
/// Why a session ended whose supervisor's task died (the Rust client's
/// own: a Go panic ends the process).
pub const SUPERVISOR_LOST: &str = "reconnect supervisor stopped";
/// Why a session ended when the task that reads its peer connection's
/// events died (the Rust client's own).
pub const WATCH_LOST: &str = "peer connection watch stopped";
/// The longest room link a refresh keeps: a link is under two hundred
/// bytes, and one that is not a link is refused by the provider anyway.
pub const MAX_ROOM_LINK: usize = 2048;
/// The longest guest name a refresh keeps.
pub const MAX_NAME: usize = 256;
/// The most a session keeps for its refresh, in bytes.
pub const REFRESH_HELD: usize = MAX_ROOM_LINK + MAX_NAME + 64;
/// The most a join's offer is, in bytes: twelve lines of about 500 bytes.
const OFFER_HELD: usize = 8 << 10;
/// The most a join holds of the credentials while it runs, in bytes,
/// beside the session's own ([`CREDENTIALS_HELD`]): its copy of them, the
/// join URL twice more (with what describes the offer, and as the request
/// is sent to), and what the SFU's words are cleared of (every part of
/// the URL as written and unescaped, the cookies' values, the ids).
pub const JOIN_HELD: usize =
    OFFER_HELD + CREDENTIALS_HELD + 4 * MAX_JOIN_URL + MAX_COOKIES + 3 * MAX_ID;
/// The video lines the offer receives on (`receiveSlots`): the web client's
/// nine, each of which the SFU fills with one publisher.
pub const RECEIVE_SLOTS: usize = 9;
/// VP9's payload type (`videoPayloadType`).
pub const VIDEO_PAYLOAD_TYPE: u8 = 98;
/// Its retransmission stream's (`rtxPayloadType`).
pub const RTX_PAYLOAD_TYPE: u8 = 99;
/// Opus's (`audioPayloadType`).
pub const AUDIO_PAYLOAD_TYPE: u8 = 111;

/// How long the published stream keeps a sent packet for a resend: as long
/// as the far reader can still take it back (its `reorderHold`).
pub const RESEND_AGE: Duration = REORDER_HOLD;
/// The newest packets the published stream keeps for a resend, at most:
/// what the far reader holds behind a gap, and the one that fills it. pion's
/// responder under the Go engine keeps 1024, 256 on the phone profile
/// (`internal/engine/interceptors.go:19`), for no set time.
pub const RESEND_PACKETS: usize = REORDER_WINDOW + 1;
/// The share of resends in what is sent past which str0m drops the queued
/// ones: its default.
const RESEND_RATIO_CAP: Option<f32> = Some(0.15);
/// The most the resend cache holds, in bytes.
pub const RESEND_HELD: usize = RESEND_PACKETS * RTP_OUTBOUND_MTU;
/// The most a generation holds, in bytes: the resend cache and the room's
/// readers.
pub const GENERATION_HELD: usize = RESEND_HELD + READERS_HELD;
/// The `remote track` lines one generation says, at most: a room whose
/// publishers keep changing does not fill the log.
const TRACK_LINES: usize = 2 * MAX_READERS;

/// What the peer's channels may hold unacknowledged: it has none (media
/// only), so str0m's floor.
const SCTP_BUFFERED: usize = 64 << 10;

/// The peer connection's settings as the SFU expects them (`newAPI`): VP9
/// with its retransmission stream and opus at Go's payload types, and the
/// four header extensions pion's defaults register, under pion's ids.
/// str0m gives VP9 `nack`, `nack pli`, `ccm fir`, `goog-remb` and
/// `transport-cc`, and opus `transport-cc`, as the Go offer has them.
#[must_use]
pub fn tune(config: RtcConfig) -> RtcConfig {
    let codecs = [
        CodecLine::video(
            VIDEO_PAYLOAD_TYPE,
            Some(RTX_PAYLOAD_TYPE),
            Codec::Vp9,
            FormatParams {
                profile_id: Some(0),
                ..FormatParams::default()
            },
        ),
        CodecLine::opus(
            AUDIO_PAYLOAD_TYPE,
            FormatParams {
                min_p_time: Some(10),
                use_inband_fec: Some(true),
                ..FormatParams::default()
            },
        ),
    ];
    let extensions = [
        (1, Extension::RtpMid),
        (2, Extension::RtpStreamId),
        (3, Extension::RepairedRtpStreamId),
        (4, Extension::TransportSequenceNumber),
    ];
    with_extensions(with_codecs(config, &codecs), &extensions)
}

/// The offer of one join, and what the join needs of it.
pub struct Offer {
    /// The offer as it is posted: no candidate in it.
    pub sdp: String,
    /// str0m's half of the exchange, which takes the answer.
    pending: SdpPendingOffer,
    /// The published line.
    pub publish: Mid,
    /// The line the SFU plays the room's audio on: the join names it
    /// (`originMid`).
    pub player: Mid,
}

impl std::fmt::Debug for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The text holds the ICE password.
        f.debug_struct("Offer")
            .field("publish", &self.publish)
            .field("player", &self.player)
            .finish_non_exhaustive()
    }
}

/// `buildPeerConnection` and `CreateOffer`: the lines in the web client's
/// order, less what the SFU does not ask for: the published camera, a
/// microphone line that stays silent, the one line the SFU plays the
/// room's audio on (it refuses an offer with two), and the receive slots.
/// `stream` and `track` name the published track (its msid). `None` when
/// str0m makes no offer.
pub fn lay_out(rtc: &mut Rtc, stream: &str, track: &str) -> Option<Offer> {
    let mut api = rtc.sdp_api();
    let publish = api.add_media(
        MediaKind::Video,
        Direction::SendRecv,
        Some(stream.to_owned()),
        Some(track.to_owned()),
        None,
    );
    api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let player = api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    for _ in 0..RECEIVE_SLOTS {
        api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
    }
    let (offer, pending) = api.apply()?;
    Some(Offer {
        sdp: as_posted(&offer.to_sdp_string()),
        pending,
        publish,
        player,
    })
}

/// The offer as it goes to the SFU: str0m's text, brought to what the Go
/// engine's offer says in three places where str0m says something else
/// about the guest (`mtslink/offer.sdp`):
///
/// - the origin names no user (`o=- …`; str0m writes its own name and
///   version there);
/// - a line that only receives (the audio player, the nine slots) declares
///   no stream: str0m gives every line an `a=msid`, SSRCs and an RTX group,
///   and the SFU counts what a guest publishes;
/// - the session names no stream (`a=msid-semantic:WMS *`), where str0m
///   lists every line's, the ones just taken out included.
///
/// Only the posted text changes; str0m keeps its own offer for the answer.
#[must_use]
pub fn as_posted(sdp: &str) -> String {
    const DECLARES: [&str; 3] = ["a=ssrc:", "a=ssrc-group:", "a=msid:"];
    let mut out = String::with_capacity(sdp.len());
    let mut lines = sdp.split_inclusive("\r\n").peekable();
    let mut section: Vec<&str> = Vec::new();
    let flush = |section: &mut Vec<&str>, out: &mut String| {
        let media = section.first().is_some_and(|l| l.starts_with("m="));
        let receives = media && section.iter().any(|l| l.trim_end() == "a=recvonly");
        for line in section.drain(..) {
            if receives && DECLARES.iter().any(|d| line.starts_with(d)) {
                continue;
            }
            if !media && line.starts_with("o=") {
                let rest = line.split_once(' ').map_or("\r\n", |(_, rest)| rest);
                out.push_str("o=- ");
                out.push_str(rest);
            } else if !media && line.starts_with("a=msid-semantic:") {
                out.push_str("a=msid-semantic:WMS *\r\n");
            } else {
                out.push_str(line);
            }
        }
    };
    while let Some(line) = lines.next() {
        section.push(line);
        if lines.peek().is_none_or(|next| next.starts_with("m=")) {
            flush(&mut section, &mut out);
        }
    }
    out
}

/// What an SDP says about its payload types, as far as str0m acts on it:
/// the codec each one names and, for a retransmission type, the type it
/// repeats. Read from every section together, as str0m keeps one table for
/// all of them.
struct PayloadTypes<'a> {
    /// The codec's name of each `a=rtpmap`, by payload type.
    codec: [Option<&'a str>; 128],
    /// The `apt` of each `a=fmtp`, by payload type.
    repeats: [Option<u8>; 128],
}

impl<'a> PayloadTypes<'a> {
    /// The table of `sdp`, or what in it names one payload type twice.
    /// A line str0m's parser would not take as an `a=rtpmap` or an
    /// `a=fmtp` is read here all the same: the check errs on that side.
    fn read(sdp: &'a str) -> Result<Self, String> {
        let mut table = Self {
            codec: [None; 128],
            repeats: [None; 128],
        };
        for line in sdp.split('\n').map(str::trim) {
            if let Some(map) = line.strip_prefix("a=rtpmap:") {
                let (pt, encoding) = map.split_once(' ').unwrap_or((map, ""));
                let Some(slot) = pt.parse::<usize>().ok().filter(|&pt| pt < 128) else {
                    continue;
                };
                let name = encoding.trim().split('/').next().unwrap_or("");
                match table.codec[slot] {
                    Some(known) if !known.eq_ignore_ascii_case(name) => {
                        return Err(format!("payload type {slot} names two codecs"));
                    }
                    _ => table.codec[slot] = Some(name),
                }
            } else if let Some(fmtp) = line.strip_prefix("a=fmtp:") {
                let (pt, params) = fmtp.split_once(' ').unwrap_or((fmtp, ""));
                let Some(slot) = pt.parse::<usize>().ok().filter(|&pt| pt < 128) else {
                    continue;
                };
                let repeated = params
                    .split([';', ' ', '\t'])
                    .filter_map(|param| param.split_once('='))
                    .filter(|(key, _)| key.trim().eq_ignore_ascii_case("apt"))
                    .filter_map(|(_, value)| value.trim().parse::<u8>().ok());
                for apt in repeated {
                    match table.repeats[slot] {
                        Some(known) if known != apt => {
                            return Err(format!("payload type {slot} repeats two others"));
                        }
                        _ => table.repeats[slot] = Some(apt),
                    }
                }
            }
        }
        Ok(table)
    }
}

/// Why `answer` must not be given to str0m after `offer`, if it must not:
/// it names one payload type for two codecs, or one retransmission type
/// for two others, or gives a payload type of the offer another codec.
///
/// str0m keeps one table of payload types for the whole peer connection
/// and holds "one claim per payload type" with an `assert!`
/// (`format/payload_params.rs:39-43`, reached from `accept_answer` through
/// `CodecConfig::update_params`), not with an error (K2). The session's
/// table has VP9, its retransmission type and opus, each locked to what
/// the first section that names it says. With one codec per payload type
/// the three sets of numbers an answer can lock them to are apart, and
/// with one repeated type per retransmission type VP9's and opus's are
/// apart too: no number is claimed twice. pion refuses such an answer
/// with an error; so does this.
///
/// Only the numbers are said: the text is the SFU's.
fn payload_clash(offer: &str, answer: &str) -> Option<String> {
    let theirs = match PayloadTypes::read(answer) {
        Ok(table) => table,
        Err(clash) => return Some(clash),
    };
    // An offer of ours that clashes with itself names nothing to hold the
    // answer to: str0m made it from one table.
    let ours = PayloadTypes::read(offer).ok()?;
    (0..128).find_map(|pt| match (ours.codec[pt], theirs.codec[pt]) {
        (Some(offered), Some(answered)) if !offered.eq_ignore_ascii_case(answered) => Some(
            format!("payload type {pt} is not the codec it was offered as"),
        ),
        _ => None,
    })
}

/// `iceNetworkTypes`: what an ICE mode of the room link asks of the peer;
/// none is UDP, the shared setting.
#[must_use]
pub const fn ice_mode(ice: Option<Ice>) -> IceMode {
    match ice {
        None | Some(Ice::Udp) => IceMode::Udp,
        Some(Ice::Tcp) => IceMode::Tcp,
        Some(Ice::Both) => IceMode::Both,
    }
}

/// What the provider is asked again with before each rejoin (Go's
/// `cfg.Refresh`, a closure over `auth.Config`): the room as the link names
/// it, the guest's name, and the side's default ICE mode. The link is wiped
/// when it goes.
#[derive(Clone, PartialEq, Eq)]
pub struct Refresh {
    room_url: Zeroizing<String>,
    name: String,
    default_ice: String,
    gateway: String,
}

impl Refresh {
    /// A refresh for the room at `room_url`, joined as `name`;
    /// `default_ice` is the mode a link without a hint takes, `gateway`
    /// the provider's service when it is not its own (the tests' fakes).
    ///
    /// # Errors
    /// [`Error::RoomRef`] for a link longer than [`MAX_ROOM_LINK`], which
    /// is no event join link, or a name longer than [`MAX_NAME`].
    pub fn new(
        room_url: &str,
        name: &str,
        default_ice: &str,
        gateway: Option<&str>,
    ) -> Result<Self, Error> {
        let gateway = gateway.unwrap_or("");
        if room_url.len() > MAX_ROOM_LINK
            || name.len() > MAX_NAME
            || gateway.len() > MAX_ROOM_LINK
            || default_ice.len() > 8
        {
            return Err(Error::RoomRef);
        }
        Ok(Self {
            room_url: Zeroizing::new(room_url.to_owned()),
            name: name.to_owned(),
            default_ice: default_ice.to_owned(),
            gateway: gateway.to_owned(),
        })
    }

    /// `Provider.Issue` as the engine is handed it (`resolveCredentials`'
    /// `issue`): a new guest and a new conference in the room, or the
    /// provider's error under Go's words ([`Error::Auth`]).
    async fn issue(&self) -> Result<Credentials, Error> {
        auth::issue(&auth::Request {
            room_url: &self.room_url,
            name: &self.name,
            default_ice: &self.default_ice,
            gateway: &self.gateway,
            ..auth::Request::default()
        })
        .await
        .map_err(|e| Error::Auth(Box::new(e)))
    }
}

impl std::fmt::Debug for Refresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The link names the room's owner and its event (K6).
        f.debug_struct("Refresh")
            .field("name", &self.name)
            .field("default_ice", &self.default_ice)
            .finish_non_exhaustive()
    }
}

/// Joins this process started under a budget ([`Settings::max_joins`]):
/// process-wide, so a run the room supervisor starts again spends from the
/// same budget. A join counts when it is started, whether or not it works.
static BUDGETED_JOINS: AtomicU32 = AtomicU32::new(0);

/// Takes one join from a budget of `max` (0: no budget, nothing counted).
fn take_join(max: u32) -> Result<(), Error> {
    if max == 0 {
        return Ok(());
    }
    if BUDGETED_JOINS.fetch_add(1, Ordering::AcqRel) >= max {
        return Err(Error::JoinBudget(max));
    }
    Ok(())
}

/// What a session is made of.
#[derive(Debug, Clone)]
pub struct Settings {
    /// What the provider issued (`engine.Credentials`): the room join, the
    /// guest's cookies, and what takes the guest's conference back.
    pub credentials: Credentials,
    /// The address the peer's socket binds and its host candidate names.
    pub host_ip: IpAddr,
    /// The duration each sample the transport writes stands for.
    pub frame_interval: Duration,
    /// What the join, the pin and the take-back say about their sender;
    /// `None` is what the Go client at the pin sends ([`Agent::Go`]).
    pub user_agent: Option<String>,
    /// What the provider is asked again with before each rejoin; `None`
    /// for a session on direct credentials, which rejoins with the ones it
    /// has (Go: `cfg.Refresh == nil`).
    pub refresh: Option<Refresh>,
    /// The most joins the run may start on the service, rejoins included
    /// (the live step's budget, the Rust client's own: Go has none); 0 is
    /// no limit.
    pub max_joins: u32,
}

/// The current generation's place: which join it is and where its peer
/// connection stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Life {
    gen: u64,
    pc: PcState,
}

/// What one join owns of the media.
struct Media {
    /// The generation the rest belongs to.
    gen: u64,
    peer: Option<Peer>,
    /// The task that reads the peer's events to their end.
    watch: Option<JoinHandle<()>>,
    /// The published line's send stream, once the answer is applied.
    line: Option<SendLine>,
    /// DTLS is up: packets can go.
    up: bool,
    /// The track's packetizer (`TrackLocalStaticSample`), the session's.
    packetizer: Packetizer,
}

/// An MTS Link session: `engine.Session` over one endless room.
pub struct Session {
    creds: Mutex<Credentials>,
    host_ip: IpAddr,
    frame_ns: i64,
    user_agent: Option<String>,
    connect_wait: Duration,
    /// How long a first join may take ([`CONNECT_BOUND`]).
    connect_bound: Duration,
    /// Joins past their peer's start that have not ended, the take-back
    /// of a failed one included: what a close waits for.
    joins: watch::Sender<usize>,
    /// The tests' failpoint: a rejoin panics.
    #[cfg(test)]
    trip: AtomicBool,
    /// The published track's ids (`common.NewVideoTrack`).
    stream_id: String,
    track_id: String,
    /// `AddVideoTrack` was called.
    published: AtomicBool,
    closed: AtomicBool,
    gen_no: AtomicU64,
    life: watch::Sender<Life>,
    media: Mutex<Media>,
    on_frame: Arc<Mutex<Option<FrameHandler>>>,
    /// What the readers of the generation's sink hold (the memory line).
    rtp_held: HeldGauge,
    on_keyframe: Mutex<Option<KeyframeHandler>>,
    /// Rejoins asked for so far, whatever the supervisor made of each.
    rejoins: AtomicU64,
    /// Rejoins that came up.
    rejoined: AtomicU64,
    /// The engine's news: `Reconnected` after a rejoin, `Ended` at the
    /// rejoin limit.
    news: mpsc::Sender<EngineEvent>,
    refresh: Option<Refresh>,
    max_joins: u32,
    /// Serialises and coalesces the rejoin requests (`engine.Reconnector`).
    supervisor: Arc<Reconnector>,
    /// A rejoin is running (`reconnecting`): requests are refused.
    reconnecting: AtomicBool,
    /// [`Session::supervise`] was called.
    supervised: AtomicBool,
    /// The session's end was said (`endOnce`).
    ended: AtomicBool,
    /// True once the session is closed (`closeCh`): the supervisor stops.
    /// It stops as well when the session is dropped.
    stopped: watch::Sender<bool>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("life", &*self.life.borrow())
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The first line of what the peer connection said, bounded: its words
/// can quote the text they are about.
fn first_line(e: &dyn std::fmt::Display) -> String {
    let text = e.to_string();
    let line = text.lines().next().unwrap_or("");
    let mut end = line.len().min(MAX_REFUSAL_TEXT);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].to_owned()
}

/// What the service's words about a join are cleared of: the cookies'
/// values and the ids of `creds`, and every part of `target`, the join's
/// URL as it is posted to.
fn held_of(creds: &Credentials, target: Option<&str>) -> Held {
    let mut held = target.map_or_else(Held::none, Held::of_join);
    held.add_cookies(&creds.token);
    for id in [&creds.session_id, &creds.user_id, &creds.conference_id] {
        held.add(id.as_bytes());
    }
    held
}

/// `e` with the words of a call that got no reply cleared of `held`: they
/// can quote a line of what the service sent.
fn cleared(held: &Held, e: Error) -> Error {
    match e {
        Error::Transport { call, cause } => Error::Transport {
            call,
            cause: held.line(&cause),
        },
        other => other,
    }
}

/// Eight random hex digits (`common.RandomID`).
fn random_id() -> String {
    format!("{:08x}", rand::random::<u32>())
}

impl Session {
    /// `New`: a session from the provider's credentials, and its news.
    /// Nothing is asked of the service yet.
    ///
    /// # Errors
    /// [`Error::NoEndpoint`] without the room join;
    /// [`Error::CredentialsTooLarge`] for credentials past their bounds.
    pub fn new(settings: Settings) -> Result<(Arc<Self>, mpsc::Receiver<EngineEvent>), Error> {
        if settings.credentials.url.is_empty() {
            return Err(Error::NoEndpoint);
        }
        if !settings.credentials.fits() {
            return Err(Error::CredentialsTooLarge);
        }
        let (news, events) = mpsc::channel(EVENT_QUEUE);
        let (life, _) = watch::channel(Life {
            gen: 0,
            pc: PcState::New,
        });
        let session = Arc::new(Self {
            creds: Mutex::new(settings.credentials),
            host_ip: settings.host_ip,
            frame_ns: i64::try_from(settings.frame_interval.as_nanos()).unwrap_or(i64::MAX),
            user_agent: settings.user_agent,
            connect_wait: CONNECT_WAIT,
            connect_bound: CONNECT_BOUND,
            joins: watch::channel(0).0,
            #[cfg(test)]
            trip: AtomicBool::new(false),
            // The transport's track: `vp8channel-<hex>` on stream
            // `olcrtc-<hex>` (`vp8channel/transport.go:273`).
            stream_id: format!("olcrtc-{}", random_id()),
            track_id: format!("vp8channel-{}", random_id()),
            published: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            gen_no: AtomicU64::new(0),
            life,
            media: Mutex::new(Media {
                gen: 0,
                peer: None,
                watch: None,
                line: None,
                up: false,
                packetizer: Packetizer::random(Payloader::Vp9(
                    olc_vp8channel::vp9::Payloader::new(),
                )),
            }),
            on_frame: Arc::new(Mutex::new(None)),
            rtp_held: HeldGauge::default(),
            on_keyframe: Mutex::new(None),
            rejoins: AtomicU64::new(0),
            rejoined: AtomicU64::new(0),
            news,
            refresh: settings.refresh,
            max_joins: settings.max_joins,
            supervisor: Arc::new(Reconnector::new(MAX_RECONNECTS, LIMIT_REASON)),
            reconnecting: AtomicBool::new(false),
            supervised: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            stopped: watch::channel(false).0,
        });
        Ok((session, events))
    }

    /// `AddVideoTrack`: the next join publishes the transport's track.
    pub fn add_video_track(&self) {
        self.published.store(true, Ordering::Release);
    }

    /// Rejoins asked for so far: by [`Stream::reconnect`], or by a peer
    /// connection that failed or closed after it was up.
    #[must_use]
    pub fn rejoins_asked(&self) -> u64 {
        self.rejoins.load(Ordering::Acquire)
    }

    /// Rejoins that came up so far.
    #[must_use]
    pub fn rejoined(&self) -> u64 {
        self.rejoined.load(Ordering::Acquire)
    }

    /// `WatchConnection`: serves the session's rejoin requests on a task
    /// of its own until the session is closed, ends or is dropped. The
    /// task keeps the session alive only while a rejoin runs. A second
    /// call does nothing.
    ///
    /// A task that ends any other way (a panic under a rejoin) ends the
    /// session ([`SUPERVISOR_LOST`]): no later request would be served.
    pub fn supervise(self: &Arc<Self>) {
        if self.supervised.swap(true, Ordering::AcqRel) {
            return;
        }
        let supervisor = self.supervisor.clone();
        let session = Rejoiner(Arc::downgrade(self));
        let mut stopped = self.stopped.subscribe();
        let mut lost = EndOnDrop::new(Arc::downgrade(self), SUPERVISOR_LOST);
        tokio::spawn(async move {
            // An error is the sender gone: the session was dropped.
            let stop = async move {
                let _ = stopped.wait_for(|stopped| *stopped).await;
            };
            supervisor.watch(&session, stop).await;
            lost.returned();
        });
    }

    fn sfu(&self) -> Sfu<'_> {
        Sfu {
            user_agent: self.user_agent.as_deref().map_or(Agent::Go, Agent::Named),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// `Connect`: joins the room: the offer, the SFU's answer, the pin, and
    /// the wait for the peer connection to settle, [`CONNECT_BOUND`] at
    /// most together.
    ///
    /// The join's end is not left to its future: a join that is dropped
    /// (a caller's own timeout, a stop) tears its generation down and
    /// takes the conference back all the same, as Go's `Connect` does
    /// under a cancelled context (`leave` on `context.WithoutCancel`).
    ///
    /// # Errors
    /// [`Error::SessionClosed`] and [`Error::NoVideoTrack`] before anything
    /// is asked; the join's, the peer connection's or the wait's otherwise,
    /// after the generation is torn down and the conference taken back;
    /// [`Error::SessionClosed`] at once for a session closed under it.
    pub async fn connect(self: &Arc<Self>) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::SessionClosed);
        }
        if !self.published.load(Ordering::Acquire) {
            return Err(Error::NoVideoTrack);
        }
        take_join(self.max_joins)?;
        self.join_room(Some(self.connect_bound)).await
    }

    /// `Connect` past the join budget: [`Session::connect`]'s, bounded, and
    /// [`Session::rejoin`]'s, which has no bound but its steps'.
    async fn join_room(self: &Arc<Self>, bound: Option<Duration>) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::SessionClosed);
        }
        if !self.published.load(Ordering::Acquire) {
            return Err(Error::NoVideoTrack);
        }
        // One join at a time, and one take-back: a join starts once the one
        // before it is over, the take-back of a dropped or closed one
        // included (Go's `leave` runs inside `Connect`). That call ends
        // within its own wait.
        {
            let mut running = self.joins.subscribe();
            let over = running.wait_for(|running| *running == 0);
            let _ = tokio::time::timeout(LEAVE_WAIT + Duration::from_secs(1), over).await;
        }
        let creds = locked(&self.creds).clone();
        // Counted before the session is looked at again: a close either
        // finds this join and waits for its end, or is seen here.
        let busy = Busy::new(&self.joins);
        if self.is_closed() {
            return Err(Error::SessionClosed);
        }
        let (peer, gen, offer) = self.start_peer(ice_mode(creds.ice))?;
        let joining = Joining {
            session: self,
            gen,
            creds,
            busy: Some(busy),
        };
        let joined = {
            let join = async {
                self.negotiate(&peer, gen, offer, &joining.creds).await?;
                self.await_connected(gen).await
            };
            let join = async {
                match bound {
                    Some(bound) => tokio::time::timeout(bound, join)
                        .await
                        .unwrap_or(Err(Error::ConnectBound)),
                    None => join.await,
                }
            };
            // A close does not wait for the SFU: the join is given up
            // where it stands, so nothing of it is sent after the close.
            tokio::select! {
                biased;
                () = self.torn_down(gen) => Err(Error::SessionClosed),
                joined = join => joined,
            }
        };
        match joined {
            Ok(()) => {
                joining.came_up();
                Ok(())
            }
            Err(e) => {
                joining.failed().await;
                Err(e)
            }
        }
    }

    /// Resolves once generation `gen` is no longer the session's join: the
    /// session was closed or ended, or the generation torn down.
    async fn torn_down(&self, gen: u64) {
        let mut life = self.life.subscribe();
        let mut stopped = self.stopped.subscribe();
        // An error is the sender gone, which the session holds.
        let replaced = async {
            let _ = life.wait_for(|l| l.gen != gen).await;
        };
        let closed = async {
            let _ = stopped.wait_for(|stopped| *stopped).await;
        };
        tokio::select! {
            () = replaced => {}
            () = closed => {}
        }
    }

    /// `buildPeerConnection` and the offer: a new generation with its peer
    /// connection and its watch, the one before it torn down.
    fn start_peer(self: &Arc<Self>, ice: IceMode) -> Result<(Peer, u64, Offer), Error> {
        if ice != IceMode::Udp {
            olc_net::info!(
                "mtslink: ICE over {}, as the room link or this side asks",
                ice.as_str()
            );
        }
        let cfg = PeerConfig {
            name: "mtslink",
            crypto: olc_rtc::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: self.host_ip,
            sctp_max_buffered: SCTP_BUFFERED,
            // `webrtc.Configuration{}`: no STUN, no TURN.
            turn: Vec::new(),
            relay_only: false,
            ice_mode: ice,
        };
        let (peer, rx) = Peer::start_tuned(&cfg, tune).map_err(|e| Error::Peer {
            step: "new peer connection",
            cause: first_line(&e),
        })?;
        let made = peer.with_rtc(|rtc| lay_out(rtc, &self.stream_id, &self.track_id));
        let Some(offer) = made else {
            peer.close();
            return Err(Error::Peer {
                step: "offer",
                cause: "no offer was made".to_owned(),
            });
        };
        // `SetLocalDescription` starts the gathering, after the offer was
        // taken: the answer carries the SFU's candidates and ours reach it
        // as peer-reflexive ones. Over TCP alone nothing is gathered.
        if let Err(e) = peer.gather() {
            peer.close();
            return Err(Error::Peer {
                step: "local description",
                cause: first_line(&e),
            });
        }
        let (gen, old) = {
            let mut m = locked(&self.media);
            let gen = self.gen_no.fetch_add(1, Ordering::AcqRel) + 1;
            m.gen = gen;
            m.line = None;
            m.up = false;
            self.life.send_replace(Life {
                gen,
                pc: PcState::New,
            });
            (gen, m.peer.replace(peer.clone()))
        };
        if let Some(old) = old {
            old.close();
        }
        let watching = tokio::spawn(watch(Arc::downgrade(self), rx, gen));
        let mut m = locked(&self.media);
        if m.gen == gen {
            m.watch = Some(watching);
        }
        drop(m);
        Ok((peer, gen, offer))
    }

    /// `negotiate`: the SDP exchange. The offer goes out as it was made,
    /// without waiting for candidates, as the web client's does.
    async fn negotiate(
        &self,
        peer: &Peer,
        gen: u64,
        offer: Offer,
        creds: &Credentials,
    ) -> Result<(), Error> {
        let sfu = self.sfu();
        let target = Zeroizing::new(signal::offer_url(&creds.url, &offer.player)?);
        // What the SFU's words, and the words about its answer, are
        // cleared of before they are an error: the join's ids and tickets.
        let held = held_of(creds, Some(target.as_str()));
        let answer = signal::join_offer_holding(&target, &offer.sdp, &sfu, &held)
            .await
            .map_err(|e| cleared(&held, e))?;
        // The answer of a join that was closed under it is acted on no
        // further: no pin follows a close.
        self.still_joining(gen)?;
        let peer_id = signal::peer_of(&answer).ok_or(Error::NoPeerId)?;
        let remote = |e: &dyn std::fmt::Display| Error::Peer {
            step: "remote description",
            cause: first_line(&held.line(&e.to_string())),
        };
        let parsed = SdpAnswer::from_sdp_string(&answer).map_err(|e| remote(&e))?;
        // Before str0m sees it: its own check of this is an `assert!`.
        if let Some(clash) = payload_clash(&offer.sdp, &answer) {
            return Err(remote(&clash));
        }
        let (publish, pending) = (offer.publish, offer.pending);
        peer.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, parsed))
            .map_err(|e| remote(&e))?;
        // ICE over TCP: the answer's passive candidates are dialled.
        peer.remote_described(&answer);
        self.media_ready(peer, gen, publish);
        self.still_joining(gen)?;
        if let Err(e) = signal::pin_peer(&target, peer_id, &sfu).await {
            olc_net::debug!("mtslink: {}", cleared(&held, e));
        }
        Ok(())
    }

    /// Whether generation `gen` is still the session's join.
    fn still_joining(&self, gen: u64) -> Result<(), Error> {
        if self.is_closed() || self.life.borrow().gen != gen {
            return Err(Error::SessionClosed);
        }
        Ok(())
    }

    /// The answer is applied: the published line's send stream with its
    /// resend cache sized before anything is written, and the room's video
    /// into its readers, one per SSRC (pion's track per SSRC).
    fn media_ready(&self, peer: &Peer, gen: u64, publish: Mid) {
        let pt = peer.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Vp9)
                .map(|p| p.pt())
        });
        let Some(pt) = pt else {
            olc_net::debug!("mtslink: the answer left no VP9 on the published line");
            return;
        };
        let line = SendLine::new(publish, None, pt);
        let sized = line.size_resends(
            peer,
            ResendCache {
                packets: RESEND_PACKETS,
                age: RESEND_AGE,
                ratio_cap: RESEND_RATIO_CAP,
            },
        );
        if !sized {
            olc_net::debug!("mtslink: no send stream on the published line");
        }
        // The sink owns the readers: they go with the generation.
        let mut readers = Readers::new();
        let held = self.rtp_held.guard();
        let on_frame = self.on_frame.clone();
        let mut said = 0usize;
        peer.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
            // Anything but the room's video is drained (`drain`).
            if p.header.payload_type != pt {
                return;
            }
            let handler = locked(&on_frame).clone();
            let Some(handler) = handler else { return };
            let fed = readers.push(
                *p.header.ssrc,
                p.header.sequence_number,
                p.header.marker,
                *p.header.payload_type,
                &p.payload,
                Instant::now(),
                &mut |frame| handler(frame),
            );
            held.set(readers.held_bytes());
            if matches!(fed, Fed::New | Fed::Replaced(_)) && said < TRACK_LINES {
                said += 1;
                olc_net::debug!("mtslink: remote track kind=video codec={MIME_VP9}");
            }
        })));
        let mut m = locked(&self.media);
        if m.gen == gen {
            m.line = Some(line);
        }
    }

    /// `awaitConnected`: waits for generation `gen`'s peer connection to
    /// settle.
    async fn await_connected(&self, gen: u64) -> Result<(), Error> {
        let mut rx = self.life.subscribe();
        let settled = rx.wait_for(|l| {
            l.gen != gen || matches!(l.pc, PcState::Connected | PcState::Failed | PcState::Closed)
        });
        let life = match tokio::time::timeout(self.connect_wait, settled).await {
            Err(_) => return Err(Error::ConnectTimeout),
            Ok(Err(_)) => return Err(Error::SessionClosed),
            Ok(Ok(l)) => *l,
        };
        if life.gen != gen || self.is_closed() {
            return Err(Error::SessionClosed);
        }
        match life.pc {
            PcState::Connected => Ok(()),
            // A join that never connected is `connect`'s to report.
            _ => Err(Error::ConnectFailed),
        }
    }

    /// `leave`: takes back the conference of a join that came to nothing,
    /// on tasks of their own ([`crate::signal::take_back_detached`],
    /// [`crate::LEAVE_WAIT`] at most): the call, and one that waits for it,
    /// says its failure and lets go of `busy`, which a close waits for.
    /// The handle is for a join that waits as Go's does; dropping it stops
    /// nothing. None, with nothing sent, outside a runtime.
    fn leave(&self, creds: &Credentials, busy: Busy) -> Option<JoinHandle<()>> {
        tokio::runtime::Handle::try_current().ok()?;
        let asked = signal::take_back_detached(
            &creds.gateway,
            &creds.conference_id,
            &creds.token,
            &self.sfu(),
        );
        let held = held_of(creds, None);
        Some(tokio::spawn(async move {
            if let Ok(Err(e)) = asked.await {
                olc_net::debug!("mtslink: {}", cleared(&held, e));
            }
            drop(busy);
        }))
    }

    /// `generation.teardown`: the generation is done and its peer
    /// connection closes; `gen` names the one meant, `None` whichever is
    /// current. Returns the peer, closing, and the task that reads its
    /// events to their end.
    fn teardown(&self, gen: Option<u64>) -> Option<(Peer, Option<JoinHandle<()>>)> {
        let (peer, watching) = {
            let mut m = locked(&self.media);
            if gen.is_some_and(|g| g != m.gen) {
                return None;
            }
            // A generation of its own, with no peer: what the old one's
            // watch says from here on is about nothing.
            m.gen = self.gen_no.fetch_add(1, Ordering::AcqRel) + 1;
            m.line = None;
            m.up = false;
            self.life.send_replace(Life {
                gen: m.gen,
                pc: PcState::Closed,
            });
            (m.peer.take(), m.watch.take())
        };
        let peer = peer?;
        peer.set_rtp_sink(None);
        peer.close();
        Some((peer, watching))
    }

    /// The watch's: DTLS is up on generation `gen`.
    fn dtls_up(&self, gen: u64) {
        let mut m = locked(&self.media);
        if m.gen == gen {
            m.up = true;
        }
    }

    /// The watch's: the SFU asked for a keyframe on the published line
    /// (`readRTCP`: a PLI or a FIR, no rate limit of the engine's own).
    fn keyframe_asked(&self, gen: u64) {
        if self.life.borrow().gen != gen {
            return;
        }
        let handler = locked(&self.on_keyframe).clone();
        if let Some(handler) = handler {
            handler();
        }
    }

    /// The watch's: generation `gen`'s peer connection moved to `pc`
    /// (`OnConnectionStateChange`). A failure or a close before it ever
    /// connected is the join's to report; after, it asks for a rejoin,
    /// unless the generation was torn down on purpose.
    fn moved(&self, gen: u64, pc: PcState, was_connected: bool) {
        olc_net::debug!("mtslink: peer connection {pc}");
        let current = self.life.send_if_modified(|l| {
            if l.gen != gen {
                return false;
            }
            l.pc = pc;
            true
        });
        if current && was_connected && matches!(pc, PcState::Failed | PcState::Closed) {
            let _ = self.ask_rejoin();
        }
    }

    /// `reconnectAttempt` / `Reconnector.Request`: asks the supervisor for
    /// a rejoin. It refuses one while the session is closed or a rejoin
    /// runs, and makes one of any number between two attempts.
    fn ask_rejoin(&self) -> Request {
        if self.is_closed() {
            return Request::Rejected;
        }
        self.rejoins.fetch_add(1, Ordering::AcqRel);
        self.supervisor
            .request(self.is_closed(), self.reconnecting.load(Ordering::Acquire))
    }

    /// `reconnect`: tears the current join down and joins again as a new
    /// guest: the old peer goes first, so the room never holds two of
    /// ours, then the provider's fresh credentials (none on direct
    /// credentials), then a join from scratch, and the transport is told.
    ///
    /// # Errors
    /// [`Error::SessionClosed`]; [`Error::Refresh`] around the provider's
    /// [`Error::Auth`];
    /// the join's, after its conference was taken back.
    pub async fn rejoin(self: &Arc<Self>) -> Result<(), Error> {
        if self.is_closed() {
            return Err(Error::SessionClosed);
        }
        self.reconnecting.store(true, Ordering::Release);
        let _running = Running(&self.reconnecting);
        #[cfg(test)]
        assert!(
            !self.trip.load(Ordering::Acquire),
            "the tests' failpoint in a rejoin"
        );
        // pion's `Close` returns once the peer connection is closed; the
        // old one's last lines are said before the new one's first.
        if let Some((peer, watching)) = self.teardown(None) {
            Self::gone(peer, watching).await;
        }
        take_join(self.max_joins)?;
        if let Some(refresh) = &self.refresh {
            let fresh = refresh
                .issue()
                .await
                .map_err(|e| Error::Refresh(Box::new(e)))?;
            // What a provider issues fits; the bound holds all the same.
            if !fresh.fits() {
                return Err(Error::CredentialsTooLarge);
            }
            // `adopt`.
            *locked(&self.creds) = fresh;
        }
        // No bound of the join's own: Go's `reconnect` has none.
        self.join_room(None).await?;
        self.rejoined.fetch_add(1, Ordering::AcqRel);
        // `NotifyReconnect`: the transport shakes hands again over the
        // rebuilt carrier. A full queue has a `Reconnected` in it already.
        let _ = self.news.try_send(EngineEvent::Reconnected);
        Ok(())
    }

    /// Waits for a torn-down generation's peer connection to be gone and
    /// its last state to be said, [`CLOSE_DRAIN`] and a second at most.
    async fn gone(peer: Peer, watching: Option<JoinHandle<()>>) {
        let gone = async {
            peer.ended().await;
            if let Some(watching) = watching {
                let _ = watching.await;
            }
        };
        let _ = tokio::time::timeout(CLOSE_DRAIN + Duration::from_secs(1), gone).await;
    }

    /// `signalEnded`: the session is over for good; said once.
    fn end(&self, reason: &str) {
        if !self.ended.swap(true, Ordering::AcqRel) {
            let _ = self.news.try_send(EngineEvent::Ended(reason.to_owned()));
        }
        self.closed.store(true, Ordering::Release);
        self.stopped.send_replace(true);
        // Go leaves the last generation to `Close`; nothing can use it
        // once the session is closed, so it goes now.
        self.teardown(None);
    }

    /// `Close`: leaves the room and frees the peer connection, its
    /// goodbyes given [`CLOSE_DRAIN`]; it returns once the peer's last
    /// state has been said (pion's `closed` lines, which the apps read:
    /// pion's `Close` returns after them too). No HTTP call: the service
    /// drops the conference of a publisher that was on the SFU and left.
    ///
    /// A join that runs (a rejoin, on the supervisor's task) is given up
    /// where it stands, and its conference, which no publisher reached, is
    /// taken back: the close returns once that call was answered,
    /// [`crate::LEAVE_WAIT`] at most, so a process that exits after it has
    /// sent the call.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.stopped.send_replace(true);
        let closing = self.teardown(None);
        let peer_gone = async {
            if let Some((peer, watching)) = closing {
                Self::gone(peer, watching).await;
            }
        };
        let joins_done = async {
            let mut joins = self.joins.subscribe();
            let done = joins.wait_for(|running| *running == 0);
            let _ = tokio::time::timeout(crate::LEAVE_WAIT, done).await;
        };
        tokio::join!(peer_gone, joins_done);
    }
}

/// One join in [`Session::joins`], from before its peer connection is made
/// until it came up or its take-back was answered.
struct Busy(watch::Sender<usize>);

impl Busy {
    fn new(joins: &watch::Sender<usize>) -> Self {
        joins.send_modify(|running| *running += 1);
        Self(joins.clone())
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0
            .send_modify(|running| *running = running.saturating_sub(1));
    }
}

/// A join from its peer connection's start: what `Connect`'s error path
/// does (the generation torn down, the conference taken back) is done when
/// this goes, unless the join came up. So it is done for a join whose
/// future is dropped, and for one that panics.
///
/// It holds the join's own copy of the credentials: a refresh may adopt
/// others before the take-back is sent.
struct Joining<'a> {
    session: &'a Session,
    gen: u64,
    creds: Credentials,
    /// None once the join ended, either way.
    busy: Option<Busy>,
}

impl Joining<'_> {
    /// The join came up: nothing is torn down or taken back.
    fn came_up(mut self) {
        self.busy = None;
    }

    /// The join failed: its end, waited for as Go's `Connect` waits for
    /// `leave`. A caller that stops waiting stops nothing.
    async fn failed(mut self) {
        if let Some(asked) = self.give_up() {
            let _ = asked.await;
        }
    }

    fn give_up(&mut self) -> Option<JoinHandle<()>> {
        let busy = self.busy.take()?;
        self.session.teardown(Some(self.gen));
        self.session.leave(&self.creds, busy)
    }
}

impl Drop for Joining<'_> {
    fn drop(&mut self) {
        drop(self.give_up());
    }
}

/// Ends the session when the task that holds it ends any other way than
/// by returning: a panic under it, which tokio would swallow with the
/// task, leaving a session that takes requests and serves none.
struct EndOnDrop {
    session: Weak<Session>,
    reason: &'static str,
    armed: bool,
}

impl EndOnDrop {
    const fn new(session: Weak<Session>, reason: &'static str) -> Self {
        Self {
            session,
            reason,
            armed: true,
        }
    }

    /// The task is returning: nothing to say.
    const fn returned(&mut self) {
        self.armed = false;
    }
}

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // A session its owner closed has nothing left to end.
        if let Some(session) = self.session.upgrade().filter(|s| !s.is_closed()) {
            olc_net::debug!("mtslink: {}", self.reason);
            session.end(self.reason);
        }
    }
}

/// Resets the `reconnecting` flag when a rejoin ends, however it ends.
struct Running<'a>(&'a AtomicBool);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The session as its supervisor holds it: not kept alive between two
/// rejoins.
struct Rejoiner(Weak<Session>);

impl Rejoin for Rejoiner {
    type Error = Error;

    async fn rejoin(&self) -> Result<(), Error> {
        match self.0.upgrade() {
            Some(session) => session.rejoin().await,
            None => Err(Error::SessionClosed),
        }
    }

    /// `OnError`.
    fn failed(&self, err: &Error) {
        olc_net::debug!("mtslink: reconnect failed: {err}");
    }

    /// `OnLimit`.
    fn limit_reached(&self, reason: &str) {
        if let Some(session) = self.0.upgrade() {
            session.end(reason);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A session dropped without `close` leaves no driver behind; its
        // supervisor stops when `stopped` goes with it.
        self.closed.store(true, Ordering::Release);
        self.teardown(None);
    }
}

/// One generation's peer events ([`watch_events`]) on a task of their own.
/// A task that ends any other way than by returning (a panic in a handler
/// of the transport's) ends the session ([`WATCH_LOST`]): nothing else
/// would see that peer connection fail.
async fn watch(session: Weak<Session>, rx: mpsc::Receiver<PeerEvent>, gen: u64) {
    let mut lost = EndOnDrop::new(session.clone(), WATCH_LOST);
    watch_events(session, rx, gen).await;
    lost.returned();
}

/// One generation's peer events: pion's state lines, the join's wait, the
/// keyframe requests, until the driver ends or the session is gone.
async fn watch_events(session: Weak<Session>, mut rx: mpsc::Receiver<PeerEvent>, gen: u64) {
    let mut state = PcWatcher::new();
    loop {
        let ev = tokio::select! {
            ev = rx.recv() => ev,
            change = state.failed() => {
                let Some(s) = session.upgrade() else { return };
                if let Some(pc) = change.pc {
                    s.moved(gen, pc, state.was_connected());
                }
                continue;
            }
        };
        let Some(ev) = ev else { return };
        let Some(s) = session.upgrade() else { return };
        match &ev {
            PeerEvent::Connected => s.dtls_up(gen),
            PeerEvent::KeyframeRequest(_) => s.keyframe_asked(gen),
            _ => {}
        }
        if let Some(pc) = state.observe(&ev).pc {
            s.moved(gen, pc, state.was_connected());
        }
        if matches!(ev, PeerEvent::Closed(_)) {
            return;
        }
    }
}

impl Stream for Session {
    /// `track.WriteSample`: packetized as VP9 and written; taken and
    /// dropped while no line is up, as pion's unbound track does.
    fn write_sample(&self, sample: &[u8]) -> bool {
        let mut m = locked(&self.media);
        let m = &mut *m;
        let (Some(peer), Some(line)) = (m.peer.as_ref(), m.line.as_mut()) else {
            return true;
        };
        if !m.up {
            return true;
        }
        let packets = m.packetizer.packetize(sample, self.frame_ns);
        let _ = line.write(
            peer,
            Instant::now(),
            packets.into_iter().map(|p| RtpOut {
                seq: p.seq,
                timestamp: p.timestamp,
                marker: p.marker,
                payload: p.payload,
            }),
        );
        true
    }

    /// `CanSend`: the peer connection is connected.
    fn can_send(&self) -> bool {
        !self.is_closed() && self.life.borrow().pc == PcState::Connected
    }

    /// `SubscriberCanSend`: one peer connection carries both ways.
    fn subscriber_can_send(&self) -> bool {
        self.can_send()
    }

    /// `Reconnect`.
    fn reconnect(&self, reason: &str) {
        if self.is_closed() {
            return;
        }
        olc_net::debug!("mtslink: reconnect requested: {reason}");
        let _ = self.ask_rejoin();
    }
}

impl VideoEngine for Session {
    /// `VideoCodec`: the SFU answers a published track with VP9 and H264
    /// only.
    fn carrier(&self) -> Carrier {
        Carrier::Vp9
    }

    fn set_frame_handler(&self, handler: Option<FrameHandler>) {
        *locked(&self.on_frame) = handler;
    }

    fn set_keyframe_handler(&self, handler: Option<KeyframeHandler>) {
        *locked(&self.on_keyframe) = handler;
    }

    fn rtp_held_bytes(&self) -> Option<usize> {
        Some(self.rtp_held.get())
    }

    fn close(&self) -> EngineFuture<'_> {
        Box::pin(self.shutdown())
    }
}

/// What the link asks a join with (`builtin.Config` as far as
/// `resolveCredentials` and `engineConfig` read it).
#[derive(Clone, Copy)]
pub struct Join<'a> {
    /// The room goes through the provider ([`auth::issue`]): `room` is the
    /// event join link, its `?ice=` hint included. Otherwise the engine
    /// joins with `room`, `token` and `extra` as its credentials.
    pub via_provider: bool,
    /// The event join link, or the SFU room join.
    pub room: &'a str,
    /// The engine's token (the guest's cookies) without the provider.
    pub token: &'a str,
    /// `engine.Credentials.Extra` without the provider: `gateway`,
    /// `conferenceId`, `ice`. Go's direct credentials carry none; the
    /// tests' fakes set them.
    pub extra: &'a BTreeMap<String, String>,
    /// The gateway instead of the service's own, for the tests' fakes.
    pub provider_base: Option<&'a str>,
    /// The guest's name.
    pub name: &'a str,
    /// The ICE mode a link without a hint takes (`auth.Config.DefaultICE`).
    pub default_ice: &'a str,
    /// The address ICE host candidates name; none takes the default
    /// route's.
    pub host_ip: Option<IpAddr>,
    /// The duration each sample the transport writes stands for.
    pub frame_interval: Duration,
    /// The most joins the run may start, rejoins included; 0 is no limit.
    pub max_joins: u32,
}

impl std::fmt::Debug for Join<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The room, the token and the extra name the room and the guest.
        f.debug_struct("Join")
            .field("via_provider", &self.via_provider)
            .field("name", &self.name)
            .field("default_ice", &self.default_ice)
            .field("host_ip", &self.host_ip)
            .field("frame_interval", &self.frame_interval)
            .field("max_joins", &self.max_joins)
            .finish_non_exhaustive()
    }
}

/// The credentials of an engine joined without its provider
/// (`engine.Credentials` as given).
fn direct(j: &Join<'_>) -> Credentials {
    let extra = |key: &str| j.extra.get(key).cloned().unwrap_or_default();
    Credentials {
        url: Zeroizing::new(j.room.to_owned()),
        token: Zeroizing::new(j.token.to_owned()),
        gateway: extra("gateway"),
        session_id: extra("sessionId"),
        user_id: extra("userId"),
        conference_id: extra("conferenceId"),
        ice: Ice::from_word(&extra("ice")),
    }
}

/// Joins the room and hands the session back as the transport's engine:
/// the provider's credentials when asked ([`auth::issue`], and again
/// before each rejoin), a session, the transport's track on it, the join,
/// and the session's rejoins served from then on ([`Session::supervise`]).
///
/// # Errors
/// The provider's under [`Error::Auth`], or [`Session::connect`]'s;
/// [`Error::JoinBudget`] when the run's joins are spent, before anything
/// is asked.
pub async fn join(j: Join<'_>) -> Result<Joined, Error> {
    let refresh = if j.via_provider {
        // A link the provider would refuse is refused under its words.
        let refresh = Refresh::new(j.room, j.name, j.default_ice, j.provider_base)
            .map_err(|e| Error::Auth(Box::new(e)))?;
        Some(refresh)
    } else {
        None
    };
    take_join(j.max_joins)?;
    let credentials = match &refresh {
        Some(refresh) => refresh.issue().await?,
        None => direct(&j),
    };
    let host_ip = match j.host_ip {
        Some(ip) => ip,
        None => olc_rtc::ice::default_ipv4().map_err(|e| Error::Peer {
            step: "new peer connection",
            cause: first_line(&e),
        })?,
    };
    olc_rtc::init();
    let (session, events) = Session::new(Settings {
        credentials,
        host_ip,
        frame_interval: j.frame_interval,
        user_agent: None,
        refresh,
        max_joins: j.max_joins,
    })?;
    session.add_video_track();
    session.join_room(Some(session.connect_bound)).await?;
    session.supervise();
    Ok(Joined {
        engine: session,
        events,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use olc_interop::load;
    use olc_rtc::str0m::change::SdpOffer;
    use olc_rtc::str0m::media::{KeyframeRequest, KeyframeRequestKind};
    use olc_vp8channel::vp9;
    use olc_vp8channel::wire::{epoch_header, TOKEN_OFF};

    use super::*;
    use crate::auth::tests::{Gateway, LINK, SESSION};
    use crate::signal::tests::{join_url, CONFERENCE, COOKIES, PEER};
    use crate::testing::{bounded, closed_port, Hung, Proto, Reply, Seen, Stub};

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// One packet the fake's peer received: payload type, marker, payload.
    type Got = (u8, bool, Vec<u8>);
    /// What the fake does to its answer before it sends it.
    type Rewrite = Arc<dyn Fn(&str) -> String + Send + Sync>;

    #[derive(Default)]
    struct FakeState {
        /// Answers the join with this instead.
        refuse: Option<(u16, String)>,
        /// The pin's status; 0 is 200.
        pin_status: u16,
        /// The answer names no peer.
        nameless: bool,
        /// The answer carries no candidate: nothing ever connects.
        deaf: bool,
        /// The answer names this passive TCP candidate too, as the SFU
        /// names each of its candidates twice (UDP and passive TCP).
        tcp: Option<std::net::SocketAddr>,
        /// Called as each join arrives, before it is answered.
        on_join: Option<Arc<dyn Fn() + Send + Sync>>,
        /// The join's reply is held back until this says true.
        hold_join: Option<watch::Receiver<bool>>,
        /// Changes the answer before it goes.
        mangle: Option<Rewrite>,
        /// Answers the join with a 404 that quotes the request's target
        /// behind this many letters, as a front end does.
        echo: Option<usize>,
        offers: Vec<String>,
        peers: Vec<Peer>,
        got: Vec<Got>,
    }

    /// MTS Link's SFU and, on the same server, the one gateway call the
    /// engine makes (`fakeSFU`, `mtslink_test.go:45-198`): it answers a
    /// join with a real peer connection of `olc_rtc`'s.
    struct Fake {
        stub: Stub,
        st: Arc<Mutex<FakeState>>,
    }

    fn fake_config() -> PeerConfig {
        PeerConfig {
            name: "sfu",
            crypto: olc_rtc::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: LOOPBACK,
            sctp_max_buffered: SCTP_BUFFERED,
            turn: Vec::new(),
            relay_only: false,
            ice_mode: IceMode::Udp,
        }
    }

    fn answer_join(st: &Arc<Mutex<FakeState>>, req: &Seen) -> Reply {
        let offer = String::from_utf8(req.body.clone()).unwrap();
        let mut s = st.lock().unwrap();
        s.offers.push(offer.clone());
        if let Some(hook) = s.on_join.clone() {
            hook();
        }
        if let Some((status, body)) = s.refuse.clone() {
            return Reply::new(status, body);
        }
        if let Some(letters) = s.echo {
            let body = format!(
                "{}The requested URL {} was not found on this server.\n<hr>",
                "x".repeat(letters),
                req.target
            );
            return Reply::new(404, body);
        }
        let (peer, mut rx) = Peer::start_tuned(&fake_config(), tune).unwrap();
        if !s.deaf {
            peer.gather().unwrap();
        }
        let parsed = match SdpOffer::from_sdp_string(&offer) {
            Ok(o) => o,
            Err(e) => return Reply::new(400, format!("SDP validation error: {e}")),
        };
        let answer = match peer.with_rtc(|rtc| rtc.sdp_api().accept_offer(parsed)) {
            Ok(a) => a.to_sdp_string(),
            Err(e) => return Reply::new(400, format!("SDP validation error: {e}")),
        };
        let answer = match s.tcp {
            Some(addr) => with_passive(&answer, addr),
            None => answer,
        };
        let answer = match &s.mangle {
            Some(mangle) => mangle(&answer),
            None => answer,
        };
        let got = st.clone();
        peer.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
            got.lock().unwrap().got.push((
                *p.header.payload_type,
                p.header.marker,
                p.payload.to_vec(),
            ));
        })));
        // The driver ends when its queue's receiver goes: keep it.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        s.peers.push(peer);
        let sdp = if s.nameless {
            answer
        } else {
            // The SFU names the peer in the answer's s= line.
            answer.replacen("\r\ns=-\r\n", &format!("\r\ns={PEER}\r\n"), 1)
        };
        Reply::new(200, sdp).header("Content-Type", "application/sdp")
    }

    /// `sdp` with a passive TCP host candidate at `addr` as the first
    /// attribute of its first line, written as pion writes one.
    fn with_passive(sdp: &str, addr: std::net::SocketAddr) -> String {
        let media = sdp.find("\r\nm=").expect("an m-line") + 2;
        let at = media + sdp[media..].find("\r\na=").expect("an attribute") + 2;
        format!(
            "{}a=candidate:375738803 1 tcp 1671430143 {} {} typ host tcptype passive\r\n{}",
            &sdp[..at],
            addr.ip(),
            addr.port(),
            &sdp[at..]
        )
    }

    impl Fake {
        async fn start() -> Self {
            Self::start_as(Proto::Plain).await
        }

        async fn start_as(proto: Proto) -> Self {
            olc_rtc::init();
            let st = Arc::new(Mutex::new(FakeState::default()));
            let theirs = st.clone();
            let stub = Stub::start_as(proto, move |req: &Seen| {
                let path = req.target.split('?').next().unwrap_or("");
                if req.method == "POST" && path == format!("/rtc/room/{SESSION}/join") {
                    let reply = answer_join(&theirs, req);
                    match theirs.lock().unwrap().hold_join.clone() {
                        Some(gate) => reply.held_until(gate),
                        None => reply,
                    }
                } else if req.method == "POST" && path.starts_with("/rtc/peer/") {
                    match theirs.lock().unwrap().pin_status {
                        0 => Reply::new(200, ""),
                        status => Reply::new(status, ""),
                    }
                } else if req.method == "DELETE" && path.starts_with("/api/conferences/") {
                    Reply::new(204, "")
                } else {
                    Reply::new(404, "")
                }
            })
            .await;
            Self { stub, st }
        }

        fn set(&self, change: impl FnOnce(&mut FakeState)) {
            change(&mut self.st.lock().unwrap());
        }

        /// `METHOD path` of every request so far, the query left out.
        fn calls(&self) -> Vec<String> {
            self.stub
                .seen()
                .iter()
                .map(|s| format!("{} {}", s.method, s.target.split('?').next().unwrap()))
                .collect()
        }

        fn peer(&self) -> Peer {
            self.st.lock().unwrap().peers.last().unwrap().clone()
        }

        fn got(&self) -> Vec<Got> {
            self.st.lock().unwrap().got.clone()
        }

        /// The mid of the offer's section `i`.
        fn mid(&self, i: usize) -> Mid {
            let offers = self.st.lock().unwrap();
            let mids = olc_rtc::sdp::section_mids(offers.offers.last().unwrap());
            Mid::from(mids[i].as_str())
        }

        /// The credentials a provider would hand the engine for this fake
        /// (`fakeSFU.config`).
        fn credentials(&self) -> Credentials {
            Credentials {
                url: Zeroizing::new(join_url(&self.stub.base)),
                token: Zeroizing::new(COOKIES.to_owned()),
                gateway: self.stub.base.clone(),
                session_id: SESSION.to_owned(),
                user_id: "100200999".to_owned(),
                conference_id: CONFERENCE.to_owned(),
                ice: None,
            }
        }

        /// A session with the transport's track on it
        /// (`newPublishingSession`).
        fn session(&self) -> Arc<Session> {
            let s = session_of(self.credentials());
            s.add_video_track();
            s
        }
    }

    fn settings(credentials: Credentials) -> Settings {
        Settings {
            credentials,
            host_ip: LOOPBACK,
            frame_interval: Duration::from_nanos(16_666_666),
            user_agent: None,
            refresh: None,
            max_joins: 0,
        }
    }

    /// The targets of the joins the fake saw, in order.
    fn join_targets(fake: &Fake) -> Vec<String> {
        fake.stub
            .seen()
            .iter()
            .filter(|s| s.method == "POST" && s.target.contains("/join?"))
            .map(|s| s.target.clone())
            .collect()
    }

    /// The value of `key` in a join's query.
    fn query_of<'a>(target: &'a str, key: &str) -> &'a str {
        target
            .split(['?', '&'])
            .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no {key} in the join"))
    }

    /// Makes the fake note, as each join arrives, whether `old` (a peer
    /// connection of the session's) was gone by then.
    fn note_old_peer(fake: &Fake, old: Peer) -> Arc<Mutex<Vec<bool>>> {
        let gone = Arc::new(Mutex::new(Vec::new()));
        let theirs = gone.clone();
        fake.set(|f| {
            f.on_join = Some(Arc::new(move || {
                theirs.lock().unwrap().push(old.is_ended());
            }));
        });
        gone
    }

    fn current_peer(s: &Session) -> Peer {
        locked(&s.media).peer.clone().expect("a peer connection")
    }

    /// A session whose news nobody reads.
    fn session_of(credentials: Credentials) -> Arc<Session> {
        Session::new(settings(credentials)).unwrap().0
    }

    async fn until(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..1500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("not within 15 s: {what}");
    }

    /// The kind and direction of every m-line of an SDP, in order
    /// (`mediaSections`).
    fn media_sections(sdp: &str) -> Vec<String> {
        sdp.split("\r\nm=")
            .skip(1)
            .map(|section| {
                let kind = section.split(' ').next().unwrap();
                let direction = ["sendrecv", "sendonly", "recvonly", "inactive"]
                    .into_iter()
                    .rfind(|d| section.contains(&format!("\r\na={d}")))
                    .unwrap_or("?");
                format!("{kind} {direction}")
            })
            .collect()
    }

    // TestNewNeedsTheRoomJoin.
    #[test]
    fn a_session_needs_the_room_join() {
        let none = Credentials {
            url: Zeroizing::new(String::new()),
            token: Zeroizing::new(String::new()),
            gateway: String::new(),
            session_id: String::new(),
            user_id: String::new(),
            conference_id: String::new(),
            ice: None,
        };
        let err = Session::new(settings(none)).unwrap_err();
        assert_eq!(err, Error::NoEndpoint);
        assert_eq!(err.to_string(), "mtslink: room join URL missing");
    }

    // TestTheEngineNamesItsCodecAndReportsKeyframeRequests, TestICENetworkTypes.
    #[tokio::test]
    async fn the_engine_names_vp9_and_reads_the_ice_mode() {
        let fake = Fake::start().await;
        let s = fake.session();
        assert_eq!(s.carrier(), Carrier::Vp9);
        assert!(!s.can_send() && !s.subscriber_can_send());
        assert_eq!(ice_mode(None), IceMode::Udp);
        assert_eq!(ice_mode(Some(Ice::Udp)), IceMode::Udp);
        assert_eq!(ice_mode(Some(Ice::Tcp)), IceMode::Tcp);
        assert_eq!(ice_mode(Some(Ice::Both)), IceMode::Both);
    }

    /// The offer the session posts, held to what the Go engine's is
    /// (`mtslink/offer.json`, `offer.sdp`): the lines and their order, the
    /// codecs at Go's payload types, the feedback, the header extensions
    /// under pion's ids, the published track's ids, and no candidate.
    #[tokio::test]
    async fn the_offer_lays_the_lines_out_as_the_go_engines() {
        bounded(async {
            olc_rtc::init();
            let (peer, _rx) = Peer::start_tuned(&fake_config(), tune).unwrap();
            let offer = peer
                .with_rtc(|rtc| lay_out(rtc, "olcrtc-0a1b2c3d", "vp8channel-4e5f6a7b"))
                .unwrap();
            let sdp = &offer.sdp;

            let legend = load("mtslink/offer.json");
            let want: Vec<String> = legend["sections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(want.len(), 3 + RECEIVE_SLOTS);
            assert_eq!(media_sections(sdp), want, "{sdp}");

            // The join names the audio player's line: the third.
            let mids = olc_rtc::sdp::section_mids(sdp);
            assert_eq!(mids.len(), 12);
            assert_eq!(&*offer.player, mids[2].as_str());
            assert_eq!(&*offer.publish, mids[0].as_str());

            let has = |section: &str, line: &str| section.lines().any(|l| l == line);
            let sections: Vec<&str> = sdp.split("\r\nm=").skip(1).collect();
            for (i, section) in sections.iter().enumerate() {
                let video = section.starts_with("video ");
                let first = section.lines().next().unwrap();
                if video {
                    assert!(first.ends_with(" UDP/TLS/RTP/SAVPF 98 99"), "{first}");
                    for line in [
                        "a=rtpmap:98 VP9/90000",
                        "a=fmtp:98 profile-id=0",
                        "a=rtpmap:99 rtx/90000",
                        "a=fmtp:99 apt=98",
                        "a=rtcp-fb:98 nack",
                        "a=rtcp-fb:98 nack pli",
                        "a=rtcp-fb:98 ccm fir",
                        "a=rtcp-fb:98 goog-remb",
                        "a=rtcp-fb:98 transport-cc",
                        "a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid",
                        "a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
                        "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
                        "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
                    ] {
                        assert!(
                            has(section, line),
                            "section {i}: no {line:?} in\n{section}"
                        );
                    }
                } else {
                    assert!(first.ends_with(" UDP/TLS/RTP/SAVPF 111"), "{first}");
                    assert!(has(section, "a=rtpmap:111 opus/48000/2"), "{section}");
                    let fmtp = section
                        .lines()
                        .find(|l| l.starts_with("a=fmtp:111 "))
                        .unwrap_or_else(|| panic!("no opus fmtp in\n{section}"));
                    assert!(
                        fmtp.contains("minptime=10") && fmtp.contains("useinbandfec=1"),
                        "{fmtp}"
                    );
                    assert!(has(section, "a=rtcp-fb:111 transport-cc"), "{section}");
                }
                assert!(has(section, "a=setup:actpass"), "{section}");
                assert!(has(section, "a=rtcp-mux"), "{section}");
            }
            // The published track goes by the transport's ids, the
            // microphone line has its stream; the audio player and the
            // slots send nothing and declare nothing.
            assert!(
                has(sections[0], "a=msid:olcrtc-0a1b2c3d vp8channel-4e5f6a7b"),
                "{}",
                sections[0]
            );
            assert!(sections[0].contains("\r\na=ssrc-group:FID "), "{}", sections[0]);
            assert!(sections[1].contains("\r\na=ssrc:"), "{}", sections[1]);
            for receives in &sections[2..] {
                for declares in ["a=ssrc", "a=msid:"] {
                    assert!(!receives.contains(declares), "{declares} in\n{receives}");
                }
            }
            // The session names neither a library nor a stream.
            assert!(sdp.starts_with("v=0\r\no=- "), "{sdp}");
            assert!(sdp.contains("\r\na=msid-semantic:WMS *\r\n"), "{sdp}");
            assert!(!sdp.contains("str0m"), "{sdp}");
            assert!(sdp.ends_with("\r\n"), "{sdp}");
            // What str0m keeps is its own: the posted text is a copy.
            assert_eq!(as_posted(sdp), *sdp, "posting twice changes the text");
            // The offer is posted as it was made: before any candidate.
            for word in [
                "a=candidate",
                "end-of-candidates",
                "VP8",
                "H264",
                "abs-send-time",
                "ssrc-audio-level",
            ] {
                assert!(!sdp.contains(word), "{word:?} in\n{sdp}");
            }
            assert!(sdp.contains("\r\na=group:BUNDLE "), "{sdp}");
            let debug = format!("{offer:?}");
            assert!(!debug.contains("ice-pwd") && !debug.contains("v=0"), "{debug}");
            peer.close();
        })
        .await;
    }

    // TestSessionJoinsPublishesAndHearsTheRelay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_joins_publishes_and_hears_the_relay() {
        bounded(async {
            let fake = Fake::start().await;
            let s = fake.session();
            let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let asked = Arc::new(AtomicU64::new(0));
            {
                let heard = heard.clone();
                s.set_frame_handler(Some(Arc::new(move |f: &[u8]| {
                    heard.lock().unwrap().push(f.to_vec());
                })));
                let asked = asked.clone();
                s.set_keyframe_handler(Some(Arc::new(move || {
                    asked.fetch_add(1, Ordering::AcqRel);
                })));
            }

            s.connect().await.expect("Connect");
            assert!(
                s.can_send() && s.subscriber_can_send(),
                "a joined session cannot send"
            );

            // The join: the offer as the body, nothing of the guest's
            // cookies, and the three things that describe the offer added
            // to what the provider gave.
            let seen = fake.stub.seen();
            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("POST /rtc/peer/{PEER}/pin"),
                ]
            );
            let join = &seen[0];
            assert_eq!(join.header("Content-Type"), Some("application/sdp"));
            assert_eq!(
                join.header("Cookie"),
                None,
                "the guest's cookies went to the SFU"
            );
            assert_eq!(join.header("User-Agent"), Some("Go-http-client/1.1"));
            let player = fake.mid(2);
            assert_eq!(
                join.target,
                format!(
                    "/rtc/room/{SESSION}/join?did=33d131e5f5194d28&disableRecording=true\
                     &joinToken=vcJOIN&originMid={}&pid=3d131e5f5194d283\
                     &preferredPublishCodec=vp9&publishToken=vcPRIVATE&twcc=true\
                     &userId=100200999&userName=guest",
                    &*player
                )
            );
            let offer = String::from_utf8(join.body.clone()).unwrap();
            assert_eq!(media_sections(&offer).len(), 3 + RECEIVE_SLOTS);
            assert!(!offer.contains("a=candidate"), "{offer}");
            // The pin the web client sends after every join: nothing pinned.
            let pin = &seen[1];
            assert_eq!(pin.target, format!("/rtc/peer/{PEER}/pin"));
            assert_eq!(pin.body, br#"{"streams":[""]}"#);
            assert_eq!(pin.header("Content-Type"), Some("application/json"));
            assert_eq!(pin.header("Cookie"), None);

            // What is written to the track reaches the relay as VP9.
            let mut frame = epoch_header(1, 2, 3).to_vec();
            frame.extend_from_slice(b"kcp bytes");
            let mut sample = Vec::new();
            vp9::dress(&mut sample, &frame, false);
            let relay = fake.peer();
            for _ in 0..1500 {
                assert!(s.write_sample(&sample));
                if !fake.got().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let (pt, marker, payload) = fake
                .got()
                .first()
                .cloned()
                .expect("no packet reached the relay");
            assert_eq!((pt, marker), (VIDEO_PAYLOAD_TYPE, true));
            // The VP9 payloader's descriptor (flexible mode, a picture id,
            // begin and end of a one-packet frame) and the sample behind it.
            assert_eq!(payload[0] & 0x9c, 0x9c, "{:02x}", payload[0]);
            assert!(
                payload.ends_with(&sample),
                "the sample is not in the packet"
            );

            // The relay asks for a keyframe; the handler hears it.
            let publish = fake.mid(0);
            for kind in [KeyframeRequestKind::Pli, KeyframeRequestKind::Fir] {
                let before = asked.load(Ordering::Acquire);
                relay.with_rtc(|rtc| {
                    rtc.direct_api()
                        .stream_rx_by_mid(publish, None)
                        .expect("the relay holds the published stream")
                        .request_keyframe(kind);
                });
                until("a keyframe request reaching the handler", || {
                    asked.load(Ordering::Acquire) > before
                })
                .await;
            }

            // What the relay sends into a slot reaches the frame handler,
            // assembled and undressed.
            let slot = fake.mid(3);
            let mut line = SendLine::declare(&relay, slot, None, VIDEO_PAYLOAD_TYPE.into(), true)
                .expect("the relay has the slot's line");
            let mut packetizer = Packetizer::random(Payloader::Vp9(vp9::Payloader::new()));
            for _ in 0..1500 {
                let packets = packetizer.packetize(&sample, 16_666_666);
                line.write(
                    &relay,
                    Instant::now(),
                    packets.into_iter().map(|p| RtpOut {
                        seq: p.seq,
                        timestamp: p.timestamp,
                        marker: p.marker,
                        payload: p.payload,
                    }),
                )
                .expect("the slot takes a write");
                if !heard.lock().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let got = heard
                .lock()
                .unwrap()
                .first()
                .cloned()
                .expect("the relay's video never reached the handler");
            assert_eq!(&got[TOKEN_OFF..], &frame[TOKEN_OFF..]);
            assert_eq!(s.rejoins_asked(), 0);

            // A guest that joined leaves nothing to take back, and its
            // close returns once the peer's last state has been said.
            s.close().await;
            assert_eq!(
                Arc::weak_count(&s),
                0,
                "the peer's watch outlived the close"
            );
            assert!(!s.can_send(), "a closed session can send");
            assert!(
                s.write_sample(&sample),
                "a closed session's track still takes a sample"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(fake.calls().len(), 2, "{:?}", fake.calls());
            assert_eq!(s.rejoins_asked(), 0, "a close asked for a rejoin");
        })
        .await;
    }

    /// A reader per publisher (M6.5, D8): the relay fills two slots, each
    /// publisher numbering its packets from the same place; both are
    /// heard. One reader for the room takes the second for the first's
    /// repeats.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_publishers_in_two_slots_are_both_heard() {
        bounded(async {
            let fake = Fake::start().await;
            let s = fake.session();
            let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            {
                let heard = heard.clone();
                s.set_frame_handler(Some(Arc::new(move |f: &[u8]| {
                    heard.lock().unwrap().push(f.to_vec());
                })));
            }
            s.connect().await.expect("Connect");
            let relay = fake.peer();
            let mut publishers = Vec::new();
            let mut frames = Vec::new();
            for (i, words) in [&b"the first publisher"[..], b"the second one"]
                .into_iter()
                .enumerate()
            {
                let mut frame = epoch_header(1, 2, 3).to_vec();
                frame.extend_from_slice(words);
                let mut sample = Vec::new();
                vp9::dress(&mut sample, &frame, false);
                let line = SendLine::declare(
                    &relay,
                    fake.mid(3 + i),
                    None,
                    VIDEO_PAYLOAD_TYPE.into(),
                    true,
                )
                .expect("the relay has the slot's line");
                let packetizer = Packetizer::new(Payloader::Vp9(vp9::Payloader::new()), 5000, 1);
                publishers.push((line, packetizer, sample));
                frames.push(frame);
            }
            let both = |heard: &[Vec<u8>]| {
                frames
                    .iter()
                    .map(|frame| heard.iter().any(|h| h[TOKEN_OFF..] == frame[TOKEN_OFF..]))
                    .collect::<Vec<bool>>()
            };
            for _ in 0..500 {
                for (line, packetizer, sample) in &mut publishers {
                    let packets = packetizer.packetize(sample, 16_666_666);
                    line.write(
                        &relay,
                        Instant::now(),
                        packets.into_iter().map(|p| RtpOut {
                            seq: p.seq,
                            timestamp: p.timestamp,
                            marker: p.marker,
                            payload: p.payload,
                        }),
                    )
                    .expect("the slot takes a write");
                }
                if both(&heard.lock().unwrap()) == [true, true] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                both(&heard.lock().unwrap()),
                [true, true],
                "which of the two publishers the session heard"
            );
            s.close().await;
        })
        .await;
    }

    /// The ICE mode is the credentials' (M6.6; `iceNetworkTypes`,
    /// `buildPeerConnection`). The SFU names a UDP candidate and a passive
    /// TCP one. Over TCP the session dials the passive one, speaks ICE on
    /// it framed as RFC 4571, sends no UDP datagram, and so does not reach
    /// the UDP candidate it could have connected to. With both it dials
    /// and uses UDP too; over UDP it dials nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_credentials_ice_mode_decides_what_the_peer_dials_and_sends() {
        use tokio::io::AsyncReadExt;
        bounded(async {
            // Nothing answers ICE on this one: a TCP-only join cannot connect.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let fake = Fake::start().await;
            fake.set(|s| s.tcp = Some(addr));
            let session = |ice: Option<Ice>| {
                let (mut s, _events) = Session::new(settings(Credentials {
                    ice,
                    ..fake.credentials()
                }))
                .unwrap();
                Arc::get_mut(&mut s).unwrap().connect_wait = Duration::from_millis(1500);
                s.add_video_track();
                s
            };
            let dialled = || tokio::time::timeout(Duration::from_secs(10), listener.accept());

            let s = session(Some(Ice::Tcp));
            let joining = {
                let s = s.clone();
                tokio::spawn(async move { s.connect().await })
            };
            let (mut conn, _) = dialled()
                .await
                .expect("over TCP the passive candidate was not dialled")
                .unwrap();
            // RFC 4571's length, then a STUN binding request.
            let mut head = [0u8; 10];
            tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut head))
                .await
                .expect("nothing was said on the connection")
                .unwrap();
            assert!(u16::from_be_bytes([head[0], head[1]]) >= 20, "{head:02x?}");
            assert_eq!(head[2..4], [0x00, 0x01], "{head:02x?}");
            assert_eq!(head[6..10], [0x21, 0x12, 0xa4, 0x42], "{head:02x?}");
            let peer = locked(&s.media).peer.clone().expect("the join's peer");
            assert_eq!(peer.ice_mode(), IceMode::Tcp);
            let err = joining.await.unwrap().unwrap_err();
            assert_eq!(err, Error::ConnectTimeout, "the UDP candidate was used");
            assert_eq!(peer.udp_out(), 0, "UDP datagrams sent over TCP alone");
            drop(conn);

            let s = session(Some(Ice::Both));
            s.connect()
                .await
                .expect("with both the UDP candidate connects");
            let (conn, _) = dialled()
                .await
                .expect("with both the passive candidate was not dialled")
                .unwrap();
            let peer = locked(&s.media).peer.clone().expect("the join's peer");
            assert_eq!(peer.ice_mode(), IceMode::Both);
            assert!(peer.udp_out() > 0);
            s.close().await;
            drop(conn);

            let s = session(None);
            s.connect().await.expect("over UDP");
            let peer = locked(&s.media).peer.clone().expect("the join's peer");
            assert_eq!(peer.ice_mode(), IceMode::Udp);
            assert!(peer.udp_out() > 0);
            assert!(
                tokio::time::timeout(Duration::from_millis(300), listener.accept())
                    .await
                    .is_err(),
                "over UDP a TCP candidate was dialled"
            );
            s.close().await;
        })
        .await;
    }

    /// Over TCP alone, a join whose only passive candidate refuses the dial
    /// has no path and none coming: the peer says so at once (olc-rtc's
    /// rule for ICE over TCP, plan D7) and the join ends there, not after
    /// the wait; the conference is taken back as after any failed join.
    /// Go's pion stays `checking` until `Connect`'s 30 s are over.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tcp_join_whose_dial_is_refused_fails_without_the_wait() {
        bounded(async {
            let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = closed.local_addr().unwrap();
            drop(closed);
            let fake = Fake::start().await;
            fake.set(|s| s.tcp = Some(addr));
            let (mut s, _events) = Session::new(settings(Credentials {
                ice: Some(Ice::Tcp),
                ..fake.credentials()
            }))
            .unwrap();
            Arc::get_mut(&mut s).unwrap().connect_wait = Duration::from_secs(12);
            s.add_video_track();
            let began = Instant::now();
            let err = s.connect().await.unwrap_err();
            let took = began.elapsed();
            assert_eq!(err, Error::ConnectFailed, "after {took:?}");
            assert!(took < Duration::from_secs(8), "the join waited {took:?}");
            assert!(
                locked(&s.media).peer.is_none(),
                "the generation outlived its join"
            );
            assert_eq!(
                fake.calls().last().map(String::as_str),
                Some(format!("DELETE /api/conferences/{CONFERENCE}").as_str())
            );
            assert_eq!(s.rejoins_asked(), 0);
        })
        .await;
    }

    // TestARefusedJoinSaysWhyAndTakesTheConferenceBack.
    #[tokio::test]
    async fn a_refused_join_says_why_and_takes_the_conference_back() {
        bounded(async {
            let fake = Fake::start().await;
            fake.set(|s| {
                s.refuse = Some((
                    400,
                    "SDP validation error: exceeded maximal audio players value 1".to_owned(),
                ));
            });
            let s = fake.session();
            let err = s.connect().await.unwrap_err();
            assert_eq!(
                err.to_string(),
                "mtslink: the SFU refused the join: status 400: \
                 SDP validation error: exceeded maximal audio players value 1"
            );
            assert!(!s.can_send(), "a session whose join was refused can send");
            let seen = fake.stub.seen();
            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                ]
            );
            assert_eq!(seen[1].header("Cookie"), Some(COOKIES));
            // The generation is gone with the join.
            assert!(locked(&s.media).peer.is_none());
        })
        .await;
    }

    // TestAnAnswerThatIsNotSDPIsRefused, and an answer that names no peer.
    #[tokio::test]
    async fn an_answer_without_an_sdp_or_a_peer_fails_the_join() {
        bounded(async {
            let fake = Fake::start().await;
            fake.set(|s| s.refuse = Some((200, r#"{"error":"no room"}"#.to_owned())));
            let s = fake.session();
            assert_eq!(s.connect().await, Err(Error::NoAnswer));
            fake.set(|s| {
                s.refuse = None;
                s.nameless = true;
            });
            assert_eq!(s.connect().await, Err(Error::NoPeerId));
            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                ],
                "no pin for an answer without a peer, and the conference taken back"
            );
            assert!(locked(&s.media).peer.is_none());
        })
        .await;
    }

    // TestARefusedPinDoesNotFailTheJoin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_pin_does_not_fail_the_join() {
        bounded(async {
            let fake = Fake::start().await;
            fake.set(|s| s.pin_status = 403);
            let s = fake.session();
            s.connect().await.expect("Connect with a refused pin");
            assert!(s.can_send());
            assert_eq!(fake.calls().len(), 2, "{:?}", fake.calls());
            s.close().await;
        })
        .await;
    }

    // TestASessionWithNothingToPublishDoesNotJoin.
    #[tokio::test]
    async fn a_session_with_nothing_to_publish_does_not_join() {
        bounded(async {
            let fake = Fake::start().await;
            let s = session_of(fake.credentials());
            let err = s.connect().await.unwrap_err();
            assert_eq!(err, Error::NoVideoTrack);
            assert_eq!(
                err.to_string(),
                "mtslink: nothing to publish: the engine carries a video transport only"
            );
            assert!(
                fake.calls().is_empty(),
                "a session with no track asked the SFU for a join"
            );
        })
        .await;
    }

    // TestACloseSessionRefusesToConnect.
    #[tokio::test]
    async fn a_closed_session_refuses_to_connect() {
        bounded(async {
            let fake = Fake::start().await;
            let s = fake.session();
            s.close().await;
            let err = s.connect().await.unwrap_err();
            assert_eq!(err, Error::SessionClosed);
            assert_eq!(err.to_string(), "mtslink: session closed");
            assert!(fake.calls().is_empty(), "{:?}", fake.calls());
            s.reconnect("after the close");
            assert_eq!(s.rejoins_asked(), 0, "a closed session asked for a rejoin");
        })
        .await;
    }

    /// A join whose peer connection never comes up ends after the wait,
    /// with Go's words, its generation torn down and the conference taken
    /// back (`awaitConnected`, `Connect`'s error path).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_that_never_connects_times_out_and_takes_the_conference_back() {
        bounded(async {
            let fake = Fake::start().await;
            fake.set(|s| s.deaf = true);
            let (mut s, _events) = Session::new(settings(fake.credentials())).unwrap();
            Arc::get_mut(&mut s).unwrap().connect_wait = Duration::from_millis(400);
            s.add_video_track();
            let began = Instant::now();
            let err = s.connect().await.unwrap_err();
            assert_eq!(err, Error::ConnectTimeout);
            assert_eq!(err.to_string(), "mtslink: peer connection did not connect");
            assert!(began.elapsed() >= Duration::from_millis(400));
            assert!(!s.can_send());
            assert!(
                locked(&s.media).peer.is_none(),
                "the generation outlived its join"
            );
            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("POST /rtc/peer/{PEER}/pin"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                ]
            );
            assert_eq!(s.rejoins_asked(), 0);
        })
        .await;
    }

    /// `watch`'s rule (`OnConnectionStateChange`): a failure or a close
    /// before the first connect is the join's error and asks nothing; one
    /// after it asks for a rejoin; a generation torn down asks nothing.
    #[tokio::test]
    async fn a_lost_peer_is_the_joins_error_before_it_connected_and_a_rejoin_after() {
        bounded(async {
            let fake = Fake::start().await;
            let s = fake.session();
            let generation = |gen| {
                locked(&s.media).gen = gen;
                s.life.send_replace(Life {
                    gen,
                    pc: PcState::New,
                });
            };
            for pc in [PcState::Failed, PcState::Closed] {
                generation(7);
                let waiting = {
                    let s = s.clone();
                    tokio::spawn(async move { s.await_connected(7).await })
                };
                s.moved(7, PcState::Connecting, false);
                s.moved(7, pc, false);
                assert_eq!(waiting.await.unwrap(), Err(Error::ConnectFailed), "{pc}");
                assert_eq!(
                    Error::ConnectFailed.to_string(),
                    "mtslink: peer connection failed"
                );
                assert_eq!(s.rejoins_asked(), 0, "{pc}");
            }

            generation(8);
            s.moved(8, PcState::Connected, true);
            assert_eq!(s.await_connected(8).await, Ok(()));
            assert!(s.can_send());
            s.moved(8, PcState::Disconnected, true);
            assert!(!s.can_send(), "a disconnected peer connection can send");
            assert_eq!(s.rejoins_asked(), 0, "disconnected does nothing");
            s.moved(8, PcState::Failed, true);
            assert_eq!(s.rejoins_asked(), 1);
            // Another generation's news say nothing about this one.
            s.moved(7, PcState::Closed, true);
            assert_eq!(s.rejoins_asked(), 1);

            // A wait whose generation is torn down ends as closed, and the
            // old watch's close asks nothing.
            generation(9);
            let waiting = {
                let s = s.clone();
                tokio::spawn(async move { s.await_connected(9).await })
            };
            tokio::task::yield_now().await;
            s.teardown(Some(9));
            assert_eq!(waiting.await.unwrap(), Err(Error::SessionClosed));
            s.moved(9, PcState::Closed, true);
            assert_eq!(s.rejoins_asked(), 1);

            // `Reconnect` asks too, until the session is closed.
            s.reconnect("peer restart");
            assert_eq!(s.rejoins_asked(), 2);
            s.close().await;
            s.reconnect("peer restart");
            assert_eq!(s.rejoins_asked(), 2);
        })
        .await;
    }

    /// An engine named without its provider joins with the credentials as
    /// given: no ICE word is UDP (`resolveCredentials` with no provider
    /// hands the engine no `Extra`).
    #[test]
    fn direct_credentials_are_taken_as_given() {
        fn j(extra: &BTreeMap<String, String>) -> Join<'_> {
            Join {
                via_provider: false,
                room: "http://127.0.0.1:9/rtc/room/1/join?userId=2&joinToken=jt",
                token: "sessionId=abc",
                extra,
                provider_base: None,
                name: "guest",
                default_ice: "tcp",
                host_ip: Some(LOOPBACK),
                frame_interval: Duration::from_millis(16),
                max_joins: 0,
            }
        }
        let mut extra = BTreeMap::new();
        let c = direct(&j(&extra));
        assert_eq!(
            &*c.url,
            "http://127.0.0.1:9/rtc/room/1/join?userId=2&joinToken=jt"
        );
        assert_eq!(&*c.token, "sessionId=abc");
        assert_eq!((c.gateway.as_str(), c.conference_id.as_str()), ("", ""));
        assert_eq!(
            c.ice, None,
            "the client's default is the provider's to apply"
        );
        assert_eq!(ice_mode(c.ice), IceMode::Udp);
        extra.insert("gateway".to_owned(), "http://127.0.0.1:2".to_owned());
        extra.insert("conferenceId".to_owned(), "77".to_owned());
        extra.insert("ice".to_owned(), "both".to_owned());
        let c = direct(&j(&extra));
        assert_eq!(
            (c.gateway.as_str(), c.conference_id.as_str(), c.ice),
            ("http://127.0.0.1:2", "77", Some(Ice::Both))
        );
        // Nothing of the room in what a join shows of itself.
        let shown = format!("{:?}", j(&extra));
        for secret in ["127.0.0.1:9", "joinToken", "jt", "sessionId=abc", "77"] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
    }

    /// `join` without the provider: the engine in its room, as the link
    /// gets it; and a join the SFU is not there for is the carrier's error,
    /// with no URL in it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_hands_the_session_back_as_the_transports_engine() {
        bounded(async {
            let fake = Fake::start().await;
            let room = join_url(&fake.stub.base);
            let mut extra = BTreeMap::new();
            extra.insert("gateway".to_owned(), fake.stub.base.clone());
            extra.insert("conferenceId".to_owned(), CONFERENCE.to_owned());
            let asked = Join {
                via_provider: false,
                room: &room,
                token: COOKIES,
                extra: &extra,
                provider_base: None,
                name: "guest",
                default_ice: "tcp",
                host_ip: Some(LOOPBACK),
                frame_interval: Duration::from_nanos(16_666_666),
                max_joins: 0,
            };
            let joined = join(asked).await.expect("join");
            assert_eq!(joined.engine.carrier(), Carrier::Vp9);
            assert!(joined.engine.can_send());
            assert_eq!(format!("{joined:?}"), "Joined { carrier: Vp9, .. }");
            joined.engine.close().await;
            assert!(!joined.engine.can_send());

            let nowhere = format!(
                "http://127.0.0.1:{}/rtc/room/1/join?userId=2&joinToken=vcJOIN",
                closed_port().await
            );
            let err = join(Join {
                room: &nowhere,
                ..asked
            })
            .await
            .unwrap_err();
            let text = err.to_string();
            assert!(text.starts_with("mtslink: join: Post: "), "{text}");
            for secret in ["vcJOIN", "rtc/room", "userId"] {
                assert!(!text.contains(secret), "{secret} in {text}");
            }
            // The conference of the join that came to nothing is taken back.
            assert_eq!(
                fake.calls().last().map(String::as_str),
                Some(format!("DELETE /api/conferences/{CONFERENCE}").as_str())
            );
        })
        .await;
    }

    /// `join` through the provider: the gateway's five calls, then the
    /// SFU the configuration names, joined with what the provider issued.
    /// The link has no hint and the side says `udp`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_through_the_provider_walks_the_gateway_then_the_sfu() {
        bounded(async {
            let gateway = Gateway::start().await;
            // The provider's join is always https.
            let fake = Fake::start_as(Proto::TlsHttp1).await;
            gateway.names_sfu(&fake.stub.host);
            let extra = BTreeMap::new();
            let joined = join(Join {
                via_provider: true,
                room: LINK,
                token: "",
                extra: &extra,
                provider_base: Some(&gateway.stub.base),
                name: "guest",
                default_ice: "udp",
                host_ip: Some(LOOPBACK),
                frame_interval: Duration::from_nanos(16_666_666),
                max_joins: 0,
            })
            .await
            .expect("join");
            assert!(joined.engine.can_send());
            assert_eq!(gateway.calls().len(), 5, "{:?}", gateway.calls());
            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    "POST /rtc/peer/".to_owned() + PEER + "/pin",
                ]
            );
            let target = &fake.stub.seen()[0].target;
            for pair in [
                "joinToken=vcJOIN000000000000000000000000000",
                "publishToken=vcPRIVATE0000000000000000000000000",
                "userId=100200999",
                "userName=guest",
                "twcc=true",
            ] {
                assert!(target.contains(pair), "no {pair} in the join");
            }
            joined.engine.close().await;
        })
        .await;
    }

    // TestReconnectJoinsAgainWithFreshCredentials.
    /// A rejoin is a new guest: the old peer connection gone first, the
    /// provider asked again, a join from scratch with what it issued, and
    /// the transport told so it can shake hands again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_joins_again_with_fresh_credentials() {
        bounded(async {
            let gateway = Gateway::start().await;
            // The provider's join is always https.
            let fake = Fake::start_as(Proto::TlsHttp1).await;
            gateway.names_sfu(&fake.stub.host);
            let refresh = Refresh::new(LINK, "guest", "udp", Some(&gateway.stub.base)).unwrap();
            let (s, mut news) = Session::new(Settings {
                refresh: Some(refresh.clone()),
                ..settings(refresh.issue().await.expect("issue"))
            })
            .unwrap();
            s.add_video_track();
            s.connect().await.expect("Connect");
            assert_eq!(gateway.calls().len(), 5, "{:?}", gateway.calls());
            assert!(news.try_recv().is_err(), "a first join is no rejoin");

            gateway.answer(
                &format!("/api/eventsessions/{SESSION}/join-token"),
                Reply::new(
                    200,
                    r#"{"data":{"joinToken":"vcSECOND0000000000000000000000000"}}"#,
                ),
            );
            let gone = note_old_peer(&fake, current_peer(&s));
            s.rejoin().await.expect("rejoin");

            // The provider was walked again, whole, and took nothing back.
            let calls = gateway.calls();
            assert_eq!(calls.len(), 10, "{calls:?}");
            assert_eq!(calls[5..], calls[..5], "the refresh is not a whole issue");
            assert!(calls.iter().all(|c| !c.starts_with("DELETE")), "{calls:?}");
            // A second join, with the fresh token and a new device.
            let joins = join_targets(&fake);
            assert_eq!(joins.len(), 2, "{joins:?}");
            assert_eq!(
                query_of(&joins[0], "joinToken"),
                "vcJOIN000000000000000000000000000"
            );
            assert_eq!(
                query_of(&joins[1], "joinToken"),
                "vcSECOND0000000000000000000000000"
            );
            assert_ne!(query_of(&joins[0], "did"), query_of(&joins[1], "did"));
            // The room never held two of ours.
            assert_eq!(
                *gone.lock().unwrap(),
                [true],
                "the old peer at the second join"
            );
            // The transport is told, once, and the session carries again.
            assert_eq!(news.try_recv(), Ok(EngineEvent::Reconnected));
            assert!(news.try_recv().is_err());
            assert!(s.can_send());
            assert_eq!(s.rejoined(), 1);
            assert_eq!(
                fake.calls().iter().filter(|c| c.ends_with("/pin")).count(),
                2,
                "every join is pinned"
            );
            s.close().await;
        })
        .await;
    }

    /// A provider that gives no fresh credentials fails the rejoin under
    /// Go's words, after the old join is gone and before the SFU is asked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_the_provider_refuses_asks_nothing_of_the_sfu() {
        bounded(async {
            let gateway = Gateway::start().await;
            let fake = Fake::start_as(Proto::TlsHttp1).await;
            gateway.names_sfu(&fake.stub.host);
            let refresh = Refresh::new(LINK, "guest", "udp", Some(&gateway.stub.base)).unwrap();
            let (s, mut news) = Session::new(Settings {
                refresh: Some(refresh.clone()),
                ..settings(refresh.issue().await.expect("issue"))
            })
            .unwrap();
            s.add_video_track();
            s.connect().await.expect("Connect");

            // Go reads `null` as a reply that names nothing: not accepted.
            gateway.status(
                &format!("/api/eventsessions/{SESSION}/guestlogin"),
                200,
                "null",
            );
            let err = s.rejoin().await.unwrap_err();
            assert!(matches!(err, Error::Refresh(_)), "{err:?}");
            // `reconnect` wraps what the provider's `issue` returns, and
            // that is already wrapped (`builtin.go:216-220`).
            assert_eq!(
                err.to_string(),
                "refresh credentials: auth provider rejected the request: \
                 mtslink: the service did not accept the guest"
            );
            assert!(!s.can_send(), "the old join outlived a rejoin");
            assert!(locked(&s.media).peer.is_none());
            assert_eq!(
                join_targets(&fake).len(),
                1,
                "the SFU was asked without credentials"
            );
            assert!(
                news.try_recv().is_err(),
                "a failed rejoin told the transport"
            );
            assert_eq!(s.rejoined(), 0);
            // The session is not over: the next attempt is the supervisor's.
            assert!(!s.is_closed());
            s.close().await;
        })
        .await;
    }

    /// A session on direct credentials has no provider to ask (K11, Go's
    /// `cfg.Refresh == nil`): it joins again with the credentials it has.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_on_direct_credentials_joins_with_the_ones_it_has() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, mut news) = Session::new(settings(fake.credentials())).unwrap();
            s.add_video_track();
            s.connect().await.expect("Connect");
            let gone = note_old_peer(&fake, current_peer(&s));
            s.rejoin().await.expect("rejoin");

            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("POST /rtc/peer/{PEER}/pin"),
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("POST /rtc/peer/{PEER}/pin"),
                ],
                "a rejoin that works asks for a join and a pin, and takes nothing back"
            );
            let joins = join_targets(&fake);
            for key in ["joinToken", "publishToken", "did", "pid", "userId"] {
                assert_eq!(query_of(&joins[0], key), query_of(&joins[1], key), "{key}");
            }
            // A join from scratch: a new offer, so a new audio player line.
            assert_ne!(
                query_of(&joins[0], "originMid"),
                query_of(&joins[1], "originMid")
            );
            assert_eq!(
                *gone.lock().unwrap(),
                [true],
                "the old peer at the second join"
            );
            assert_eq!(news.try_recv(), Ok(EngineEvent::Reconnected));
            assert!(s.can_send());
            s.close().await;
            // A closed session rejoins nothing.
            assert_eq!(s.rejoin().await, Err(Error::SessionClosed));
            assert_eq!(join_targets(&fake).len(), 2);
        })
        .await;
    }

    /// The conference is taken back only after a join that failed: a
    /// rejoin the SFU refuses takes it back, the one that works after it
    /// takes nothing back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_rejoin_takes_its_conference_back_and_a_good_one_does_not() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, mut news) = Session::new(settings(fake.credentials())).unwrap();
            s.add_video_track();
            s.connect().await.expect("Connect");
            fake.set(|f| f.refuse = Some((503, "busy".to_owned())));
            let err = s.rejoin().await.unwrap_err();
            assert_eq!(
                err.to_string(),
                "mtslink: the SFU refused the join: status 503: busy"
            );
            assert_eq!(
                fake.calls()[2..],
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                ]
            );
            assert!(!s.can_send() && locked(&s.media).peer.is_none());
            assert!(news.try_recv().is_err());

            fake.set(|f| f.refuse = None);
            s.rejoin().await.expect("the rejoin after the refused one");
            assert_eq!(
                fake.calls()[4..],
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("POST /rtc/peer/{PEER}/pin"),
                ]
            );
            assert_eq!(news.try_recv(), Ok(EngineEvent::Reconnected));
            assert!(s.can_send());
            s.close().await;
            assert_eq!(fake.calls().len(), 6, "a close asked for something");
        })
        .await;
    }

    /// The supervisor serves what asks for a rejoin: a peer connection the
    /// SFU closed after it was up, and the transport's own request; a
    /// request while a rejoin runs is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_peer_and_a_request_are_each_served_with_a_rejoin() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, mut news) = Session::new(settings(fake.credentials())).unwrap();
            s.add_video_track();
            s.connect().await.expect("Connect");
            s.supervise();
            s.supervise();
            assert_eq!(s.rejoins_asked(), 0);

            // The SFU drops the guest's peer connection.
            fake.peer().close();
            until("the rejoin after the SFU closed the peer", || {
                s.rejoined() == 1
            })
            .await;
            assert!(s.rejoins_asked() >= 1);
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert!(s.can_send());
            assert_eq!(join_targets(&fake).len(), 2);

            // The transport's watchdog or the client's liveness asks.
            s.reconnect("peer restart");
            until("the rejoin the transport asked for", || s.rejoined() == 2).await;
            assert_eq!(news.recv().await, Some(EngineEvent::Reconnected));
            assert_eq!(join_targets(&fake).len(), 3, "one request, one join");
            assert!(s.can_send());
            assert!(
                fake.calls().iter().all(|c| !c.starts_with("DELETE")),
                "a rejoin that worked took a conference back"
            );

            // While a rejoin runs, a request is refused (`reconnecting`).
            s.reconnecting.store(true, Ordering::Release);
            assert_eq!(s.ask_rejoin(), Request::Rejected);
            s.reconnecting.store(false, Ordering::Release);

            s.close().await;
            assert_eq!(s.ask_rejoin(), Request::Rejected);
            s.reconnect("peer restart");
            assert_eq!(join_targets(&fake).len(), 3);
            assert!(news.try_recv().is_err());
        })
        .await;
    }

    /// Ten attempts that fail end the session for good, with Go's reason,
    /// said once; nothing is joined after it. The SFU here is a closed
    /// port, so every attempt fails at its dial.
    #[tokio::test(start_paused = true)]
    async fn rejoins_that_keep_failing_end_the_session_at_the_limit() {
        olc_rtc::init();
        let nowhere = format!("http://127.0.0.1:{}", closed_port().await);
        let creds = Credentials {
            url: Zeroizing::new(join_url(&nowhere)),
            token: Zeroizing::new(COOKIES.to_owned()),
            gateway: nowhere,
            session_id: SESSION.to_owned(),
            user_id: "100200999".to_owned(),
            conference_id: CONFERENCE.to_owned(),
            ice: None,
        };
        let (s, mut news) = Session::new(settings(creds)).unwrap();
        s.add_video_track();
        s.supervise();
        s.reconnect("liveness");
        // 2 + 4 + … + 20 s of backoff between the ten attempts.
        let ended = tokio::time::timeout(Duration::from_secs(600), news.recv())
            .await
            .expect("the session did not end");
        assert_eq!(ended, Some(EngineEvent::Ended(LIMIT_REASON.to_owned())));
        assert_eq!(LIMIT_REASON, "reconnect limit reached");
        assert_eq!(MAX_RECONNECTS, 10);
        assert!(s.is_closed() && !s.can_send());
        assert_eq!(s.rejoined(), 0);
        assert_eq!(s.connect().await, Err(Error::SessionClosed));
        assert_eq!(s.ask_rejoin(), Request::Rejected);
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(news.try_recv().is_err(), "the end was said twice");
    }

    /// The supervisor's task keeps no session alive: a session dropped
    /// without a close takes its supervisor with it.
    #[tokio::test]
    async fn a_dropped_session_stops_its_supervisor() {
        bounded(async {
            let fake = Fake::start().await;
            let s = fake.session();
            let supervisor = s.supervisor.clone();
            s.supervise();
            tokio::task::yield_now().await;
            assert_eq!(Arc::strong_count(&supervisor), 3, "no supervisor task");
            assert_eq!(Arc::strong_count(&s), 1, "the supervisor holds the session");
            drop(s);
            until("the supervisor's task ending", || {
                Arc::strong_count(&supervisor) == 1
            })
            .await;
        })
        .await;
    }

    /// The run's join budget counts rejoins: past it nothing is asked of
    /// the service, and the old join is gone all the same. (The one test
    /// that sets a budget: the count is the process's.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_join_budget_counts_rejoins() {
        bounded(async {
            let fake = Fake::start().await;
            let s = Session::new(Settings {
                max_joins: 2,
                ..settings(fake.credentials())
            })
            .unwrap()
            .0;
            s.add_video_track();
            s.connect().await.expect("the first join");
            s.rejoin().await.expect("the second join");
            let err = s.rejoin().await.unwrap_err();
            assert_eq!(err, Error::JoinBudget(2));
            assert_eq!(err.to_string(), "mtslink: join budget spent: 2 joins");
            assert_eq!(
                join_targets(&fake).len(),
                2,
                "a join past the budget was sent"
            );
            assert_eq!(s.connect().await, Err(Error::JoinBudget(2)));
            assert_eq!(join_targets(&fake).len(), 2);
            assert!(!s.can_send());
            s.close().await;
        })
        .await;
    }

    /// What a session keeps for its refresh is bounded, and shows nothing
    /// of the room.
    #[test]
    fn a_refresh_is_bounded_and_shows_no_room() {
        let refresh = Refresh::new(LINK, "guest", "tcp", None).unwrap();
        let shown = format!("{refresh:?}");
        assert_eq!(
            shown,
            r#"Refresh { name: "guest", default_ice: "tcp", .. }"#
        );
        let long = format!("{LINK}?{}", "x".repeat(MAX_ROOM_LINK));
        assert_eq!(
            Refresh::new(&long, "guest", "tcp", None),
            Err(Error::RoomRef)
        );
        assert_eq!(
            Refresh::new(LINK, &"n".repeat(MAX_NAME + 1), "tcp", None),
            Err(Error::RoomRef)
        );
        assert!(Refresh::new(LINK, &"n".repeat(MAX_NAME), "tcp", None).is_ok());
        const { assert!(REFRESH_HELD <= 4 << 10) };
        // The link is wiped when the refresh goes.
        fn wiped<T: 'static>(_: &T) -> bool {
            std::any::TypeId::of::<T>() == std::any::TypeId::of::<Zeroizing<String>>()
        }
        assert!(wiped(&refresh.room_url));
    }

    /// Nothing a session, its settings or its errors show names the room,
    /// the guest or a token.
    #[tokio::test]
    async fn a_session_shows_nothing_of_the_room() {
        let fake = Fake::start().await;
        let s = fake.session();
        let shown = format!("{s:?} {:?}", settings(fake.credentials()));
        for secret in [
            "vcJOIN",
            "vcPRIVATE",
            "eyJguest",
            "100200999",
            CONFERENCE,
            SESSION,
        ] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        let long = "x".repeat(500) + "\nice-pwd:secret";
        let cut = first_line(&long);
        assert_eq!(cut.len(), MAX_REFUSAL_TEXT);
        assert!(!cut.contains("secret"));
        assert_eq!(first_line(&"я".repeat(150)).len(), MAX_REFUSAL_TEXT);
    }

    /// `as_posted` on a text of its own: the origin, the session's streams
    /// and the lines that only receive change; nothing else does.
    #[test]
    fn the_posted_offer_declares_only_what_is_sent() {
        let sdp = "v=0\r\no=str0m-0.25.0 77 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
                   a=group:BUNDLE a b\r\na=msid-semantic: WMS s1 s2\r\n\
                   m=video 9 UDP/TLS/RTP/SAVPF 98 99\r\na=mid:a\r\na=sendrecv\r\n\
                   a=msid:s1 t1\r\na=ssrc:1 cname:t1\r\na=ssrc-group:FID 1 2\r\n\
                   m=video 9 UDP/TLS/RTP/SAVPF 98 99\r\na=mid:b\r\na=recvonly\r\n\
                   a=msid:s2 t2\r\na=rtcp-mux\r\na=ssrc:3 cname:t2\r\na=ssrc:3 msid:s2 t2\r\n\
                   a=ssrc-group:FID 3 4\r\n";
        assert_eq!(
            as_posted(sdp),
            "v=0\r\no=- 77 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n\
             a=group:BUNDLE a b\r\na=msid-semantic:WMS *\r\n\
             m=video 9 UDP/TLS/RTP/SAVPF 98 99\r\na=mid:a\r\na=sendrecv\r\n\
             a=msid:s1 t1\r\na=ssrc:1 cname:t1\r\na=ssrc-group:FID 1 2\r\n\
             m=video 9 UDP/TLS/RTP/SAVPF 98 99\r\na=mid:b\r\na=recvonly\r\na=rtcp-mux\r\n"
        );
        // A text that is no SDP comes back as it was.
        assert_eq!(as_posted("o=x"), "o=- \r\n");
        assert_eq!(as_posted(""), "");
        assert_eq!(
            as_posted("m=audio 9 X 0\r\na=sendonly\r\na=ssrc:9 cname:c"),
            "m=audio 9 X 0\r\na=sendonly\r\na=ssrc:9 cname:c"
        );
    }

    /// The first issue the provider refuses is the join's error under Go's
    /// words (`resolveCredentials`: `ErrAuthFailed` around the provider's
    /// own), and nothing is asked of the SFU.
    #[tokio::test]
    async fn a_first_issue_the_provider_refuses_says_so_in_gos_words() {
        bounded(async {
            let gateway = Gateway::start().await;
            let fake = Fake::start_as(Proto::TlsHttp1).await;
            gateway.names_sfu(&fake.stub.host);
            gateway.status(
                &format!("/api/eventsessions/{SESSION}/guestlogin"),
                200,
                "null",
            );
            let extra = BTreeMap::new();
            let refused = join(Join {
                via_provider: true,
                room: LINK,
                token: "",
                extra: &extra,
                provider_base: Some(&gateway.stub.base),
                name: "guest",
                default_ice: "udp",
                host_ip: Some(LOOPBACK),
                frame_interval: Duration::from_nanos(16_666_666),
                max_joins: 0,
            })
            .await;
            let Err(err) = refused else {
                panic!("a join the provider refused came up")
            };
            assert_eq!(
                err.to_string(),
                "auth provider rejected the request: mtslink: the service did not accept the guest"
            );
            assert!(fake.calls().is_empty(), "{:?}", fake.calls());
        })
        .await;
    }

    /// The answer with opus moved to VP9's payload type.
    fn opus_at_vp9s_number(answer: &str) -> String {
        answer
            .replace("SAVPF 111\r\n", "SAVPF 98\r\n")
            .replace(":111 ", ":98 ")
    }

    /// The answer with VP9's retransmission type named as opus's too.
    fn one_rtx_for_two(answer: &str) -> String {
        answer.replace(
            "a=rtpmap:111 opus/48000/2\r\n",
            "a=rtpmap:111 opus/48000/2\r\na=rtpmap:99 rtx/90000\r\na=fmtp:99 apt=111\r\n",
        )
    }

    /// An answer that names one payload type for two codecs, or one
    /// retransmission type for two, is refused as the remote description
    /// it is, with the conference taken back: str0m's own check of it is
    /// an `assert!` (K2), which would end the task the join runs on. The
    /// session joins again afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answer_whose_payload_types_clash_is_refused_without_a_panic() {
        bounded(async {
            type Mangle = fn(&str) -> String;
            let cases: [(&str, Mangle); 2] = [
                ("opus at VP9's number", opus_at_vp9s_number),
                ("one rtx for two codecs", one_rtx_for_two),
            ];
            for (what, mangle) in cases {
                let fake = Fake::start().await;
                fake.set(|f| f.mangle = Some(Arc::new(mangle)));
                let s = fake.session();
                let err = s.connect().await.unwrap_err();
                assert!(
                    matches!(
                        err,
                        Error::Peer {
                            step: "remote description",
                            ..
                        }
                    ),
                    "{what}: {err:?}"
                );
                assert!(
                    err.to_string().starts_with("mtslink: remote description: "),
                    "{what}: {err}"
                );
                assert_eq!(
                    fake.calls(),
                    [
                        format!("POST /rtc/room/{SESSION}/join"),
                        format!("DELETE /api/conferences/{CONFERENCE}"),
                    ],
                    "{what}"
                );
                assert!(locked(&s.media).peer.is_none(), "{what}");
                // The mangling does change what str0m is given.
                let offer = fake.st.lock().unwrap().offers[0].clone();
                assert_ne!(mangle(&offer), offer, "{what}");
                fake.set(|f| f.mangle = None);
                s.connect()
                    .await
                    .expect("the join after the refused answer");
                assert!(s.can_send(), "{what}");
                s.close().await;
            }
        })
        .await;
    }

    /// What `payload_clash` refuses, and what it lets through.
    #[test]
    fn a_payload_type_means_one_thing_in_an_answer() {
        // The Go engine's offer: what the session's is held to.
        let offer = std::fs::read_to_string(olc_interop::vectors_dir().join("mtslink/offer.sdp"))
            .expect("offer.sdp");
        let offer = offer.as_str();
        // An answer that says what the offer said.
        assert_eq!(payload_clash(offer, offer), None);
        let answer = "v=0\r\ns=-\r\n\
                      m=video 9 UDP/TLS/RTP/SAVPF 98 99\r\na=mid:0\r\n\
                      a=rtpmap:98 VP9/90000\r\na=rtpmap:99 rtx/90000\r\na=fmtp:99 apt=98\r\n\
                      m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:1\r\n\
                      a=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\n\
                      m=video 9 UDP/TLS/RTP/SAVPF 98 99\r\na=mid:2\r\n\
                      a=rtpmap:98 vp9/90000\r\na=rtpmap:99 RTX/90000\r\na=fmtp:99 apt=98\r\n";
        assert_eq!(
            payload_clash(offer, answer),
            None,
            "the same in another case"
        );
        assert_eq!(
            payload_clash(offer, &answer.replace("opus/48000/2", "opus/48000")),
            None,
            "the codec is its name, as for str0m"
        );
        // A codec the offer did not name, at a number of its own, clashes
        // with nothing.
        assert_eq!(
            payload_clash(offer, &answer.replace("98", "100")),
            None,
            "VP9 at another number"
        );
        let clashes: [(&str, String, &str); 6] = [
            (
                "opus at VP9's number",
                opus_at_vp9s_number(answer),
                "payload type 98 names two codecs",
            ),
            (
                "one rtx for two codecs",
                one_rtx_for_two(answer),
                "payload type 99 repeats two others",
            ),
            (
                "two apts on one line",
                answer.replacen("apt=98", "apt=98; apt=111", 1),
                "payload type 99 repeats two others",
            ),
            (
                "VP9 at opus's number, with no opus beside it",
                "v=0\r\nm=video 9 X 111\r\na=rtpmap:111 VP9/90000\r\n".to_owned(),
                "payload type 111 is not the codec it was offered as",
            ),
            (
                "a retransmission type that is a codec",
                answer.replacen("a=rtpmap:99 rtx/90000", "a=rtpmap:99 H264/90000", 1),
                "payload type 99 names two codecs",
            ),
            (
                "lines str0m would not read",
                "v=0\nm=audio 9 X 98\n  a=rtpmap:98 opus/48000/2\n".to_owned(),
                "payload type 98 is not the codec it was offered as",
            ),
        ];
        for (what, answer, why) in clashes {
            assert_eq!(
                payload_clash(offer, &answer).as_deref(),
                Some(why),
                "{what}"
            );
        }
        // Numbers past the seven bits are nobody's.
        assert_eq!(
            payload_clash(
                offer,
                "a=rtpmap:200 opus/48000/2\r\na=rtpmap:200 VP9/90000\r\n"
            ),
            None
        );
    }

    /// A rejoin that panics takes the supervisor's task with it: the
    /// session says its end, once, and is closed, where it would otherwise
    /// take requests for ever and serve none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_supervisor_that_dies_ends_the_session() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, mut news) = Session::new(settings(fake.credentials())).unwrap();
            s.add_video_track();
            s.connect().await.expect("Connect");
            s.supervise();
            s.trip.store(true, Ordering::Release);
            s.reconnect("liveness");
            let ended = tokio::time::timeout(Duration::from_secs(5), news.recv())
                .await
                .expect("a session whose supervisor died said nothing");
            assert_eq!(
                ended,
                Some(EngineEvent::Ended(
                    "reconnect supervisor stopped".to_owned()
                ))
            );
            assert!(s.is_closed() && !s.can_send());
            assert!(locked(&s.media).peer.is_none(), "the peer outlived the end");
            assert_eq!(s.ask_rejoin(), Request::Rejected);
            assert!(!s.reconnecting.load(Ordering::Acquire));
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(news.try_recv().is_err(), "the end was said twice");
        })
        .await;
    }

    /// The task that reads a generation's peer events ends the session
    /// when it dies (a handler of the transport's that panics): nothing
    /// else would ever see that peer connection fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_watch_that_dies_ends_the_session() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, mut news) = Session::new(settings(fake.credentials())).unwrap();
            locked(&s.media).gen = 7;
            s.life.send_replace(Life {
                gen: 7,
                pc: PcState::New,
            });
            s.set_keyframe_handler(Some(Arc::new(|| panic!("the test's handler"))));
            let (tx, rx) = mpsc::channel(4);
            let watching = tokio::spawn(watch(Arc::downgrade(&s), rx, 7));
            tx.send(PeerEvent::KeyframeRequest(KeyframeRequest {
                mid: Mid::from("0"),
                rid: None,
                kind: KeyframeRequestKind::Pli,
            }))
            .await
            .unwrap();
            assert!(watching.await.unwrap_err().is_panic());
            let ended = tokio::time::timeout(Duration::from_secs(5), news.recv())
                .await
                .expect("a session whose watch died said nothing");
            assert_eq!(
                ended,
                Some(EngineEvent::Ended(
                    "peer connection watch stopped".to_owned()
                ))
            );
            assert!(s.is_closed());

            // A watch that ends as it should ends nothing.
            let (s, mut news) = Session::new(settings(fake.credentials())).unwrap();
            let (tx, rx) = mpsc::channel(4);
            let watching = tokio::spawn(watch(Arc::downgrade(&s), rx, 7));
            tx.send(PeerEvent::Closed("done".to_owned())).await.unwrap();
            watching.await.unwrap();
            let (tx, rx) = mpsc::channel(4);
            let watching = tokio::spawn(watch(Arc::downgrade(&s), rx, 8));
            drop(tx);
            watching.await.unwrap();
            assert!(news.try_recv().is_err());
            assert!(!s.is_closed());
        })
        .await;
    }

    /// A joined, supervised session whose next join the fake holds, with
    /// that rejoin asked for and at the SFU.
    async fn rejoining_at_the_sfu(
        fake: &Fake,
        credentials: Credentials,
    ) -> (
        Arc<Session>,
        mpsc::Receiver<EngineEvent>,
        watch::Sender<bool>,
    ) {
        let (s, news) = Session::new(settings(credentials)).unwrap();
        s.add_video_track();
        s.connect().await.expect("Connect");
        s.supervise();
        let (open, gate) = watch::channel(false);
        fake.set(|f| f.hold_join = Some(gate));
        s.reconnect("liveness");
        until("the rejoin's join reaching the SFU", || {
            join_targets(fake).len() == 2
        })
        .await;
        (s, news, open)
    }

    /// A close while a rejoin's join is at the SFU: the join is given up,
    /// its conference is taken back, and the close returns only once that
    /// call was answered, so a process that exits after `close` has sent
    /// it. No peer connection is left.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_close_during_a_rejoin_waits_for_the_take_back() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, mut news, _open) = rejoining_at_the_sfu(&fake, fake.credentials()).await;
            let began = Instant::now();
            s.close().await;
            let took = began.elapsed();
            assert_eq!(
                fake.calls()[2..],
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                ],
                "what the SFU and the gateway had seen when the close returned"
            );
            assert!(took < crate::LEAVE_WAIT, "{took:?}");
            assert!(locked(&s.media).peer.is_none(), "a peer was left");
            until("the rejoin ending", || {
                !s.reconnecting.load(Ordering::Acquire)
            })
            .await;
            assert_eq!(s.rejoined(), 0);
            assert!(news.try_recv().is_err(), "a closed session had news");
            assert!(locked(&s.media).peer.is_none(), "a peer was left");
            assert_eq!(*s.joins.borrow(), 0, "a join or a take-back still runs");
        })
        .await;
    }

    /// The answer of a join that was closed under it is not acted on: no
    /// pin goes out after the close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_answered_after_the_close_sends_no_pin() {
        bounded(async {
            let fake = Fake::start().await;
            let (s, _news, open) = rejoining_at_the_sfu(&fake, fake.credentials()).await;
            s.close().await;
            // The held answer goes now.
            open.send(true).unwrap();
            until("the rejoin ending", || {
                !s.reconnecting.load(Ordering::Acquire)
            })
            .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let after: Vec<String> = fake.calls()[2..].to_vec();
            assert!(
                after.iter().all(|c| !c.ends_with("/pin")),
                "a pin after the close: {after:?}"
            );
            assert_eq!(
                after.iter().filter(|c| c.starts_with("DELETE")).count(),
                1,
                "{after:?}"
            );
            assert!(locked(&s.media).peer.is_none(), "a peer was left");
        })
        .await;
    }

    /// A take-back nobody answers holds a close for the leave wait and no
    /// longer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_close_waits_for_a_take_back_no_longer_than_the_leave_wait() {
        bounded(async {
            let fake = Fake::start().await;
            let gateway = Hung::start().await;
            let credentials = Credentials {
                gateway: gateway.base.clone(),
                ..fake.credentials()
            };
            let (s, _news, _open) = rejoining_at_the_sfu(&fake, credentials).await;
            let began = Instant::now();
            s.close().await;
            let took = began.elapsed();
            assert!(
                took >= crate::LEAVE_WAIT - Duration::from_millis(500),
                "the close did not wait for the take-back: {took:?}"
            );
            assert!(
                took <= crate::LEAVE_WAIT + Duration::from_secs(3),
                "{took:?}"
            );
            assert!(locked(&s.media).peer.is_none());
        })
        .await;
    }

    async fn within(limit: Duration, what: &str, cond: impl Fn() -> bool) {
        let began = Instant::now();
        while !cond() {
            assert!(began.elapsed() < limit, "not within {limit:?}: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A join whose future is dropped (Go: a `Connect` whose context is
    /// cancelled, `leave` on `context.WithoutCancel`) still tears its
    /// generation down and takes the conference back: while the join is at
    /// the SFU, and while it waits for the peer connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_join_that_is_dropped_takes_its_conference_back() {
        bounded(async {
            // Dropped while the SFU holds the join.
            let fake = Fake::start().await;
            let (_open, gate) = watch::channel(false);
            fake.set(|f| f.hold_join = Some(gate));
            let s = fake.session();
            {
                let joining = s.connect();
                tokio::pin!(joining);
                let dropped = tokio::time::timeout(Duration::from_millis(400), &mut joining).await;
                assert!(dropped.is_err(), "a held join ended: {dropped:?}");
                assert_eq!(fake.calls(), [format!("POST /rtc/room/{SESSION}/join")]);
            }
            within(
                Duration::from_secs(4),
                "the take-back of a dropped join",
                || fake.calls().len() == 2,
            )
            .await;
            assert_eq!(
                fake.calls()[1],
                format!("DELETE /api/conferences/{CONFERENCE}")
            );
            assert_eq!(fake.stub.seen()[1].header("Cookie"), Some(COOKIES));
            assert!(locked(&s.media).peer.is_none(), "the generation was left");
            assert!(!s.can_send());
            within(Duration::from_secs(4), "the take-back ending", || {
                *s.joins.borrow() == 0
            })
            .await;

            // Dropped in the wait for a peer connection that never comes.
            let fake = Fake::start().await;
            fake.set(|f| f.deaf = true);
            let s = fake.session();
            {
                let joining = s.connect();
                tokio::pin!(joining);
                let dropped = tokio::time::timeout(Duration::from_millis(1500), &mut joining).await;
                assert!(dropped.is_err(), "a deaf join ended: {dropped:?}");
                assert_eq!(fake.calls().len(), 2, "{:?}", fake.calls());
            }
            within(
                Duration::from_secs(4),
                "the take-back of a dropped wait",
                || fake.calls().len() == 3,
            )
            .await;
            assert_eq!(
                fake.calls()[2],
                format!("DELETE /api/conferences/{CONFERENCE}")
            );
            assert!(locked(&s.media).peer.is_none(), "the generation was left");

            // A join that came up takes nothing back when it goes.
            let fake = Fake::start().await;
            let s = fake.session();
            s.connect().await.expect("Connect");
            s.close().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(fake.calls().len(), 2, "{:?}", fake.calls());
        })
        .await;
    }

    /// What the SFU says when it refuses can repeat the request, as a
    /// front end's 404 does: the error, which is logged on every failed
    /// rejoin, shows no id and no ticket of the join, whole or cut.
    #[tokio::test]
    async fn a_refusal_that_repeats_the_request_shows_none_of_it() {
        bounded(async {
            // With 166 letters before it the session id lies across the
            // 200-byte cut.
            for letters in [0, 166] {
                let fake = Fake::start().await;
                fake.set(|f| f.echo = Some(letters));
                let s = fake.session();
                let text = s.connect().await.unwrap_err().to_string();
                let said = format!(
                    "mtslink: the SFU refused the join: status 404: {}",
                    "x".repeat(letters)
                );
                assert!(text.starts_with(&said), "{text}");
                for secret in [
                    SESSION,
                    &SESSION[..6],
                    "vcJOIN",
                    "vcPRIVATE",
                    "100200999",
                    "33d131e5f5194d28",
                    "3d131e5f5194d283",
                ] {
                    assert!(!text.contains(secret), "{letters}: {secret} in {text}");
                }
                if letters == 0 {
                    // What is no value of the join stays as the SFU said it.
                    assert!(
                        text.contains(
                            "The requested URL /rtc/room/…/join?did=…&disableRecording=true\
                             &joinToken=…&originMid="
                        ),
                        "{text}"
                    );
                }
            }
        })
        .await;
    }

    /// Credentials past what a provider can issue make no session: what a
    /// session keeps for its life is bounded whoever hands it over.
    #[tokio::test]
    async fn credentials_past_their_bounds_make_no_session() {
        let fake = Fake::start().await;
        let too_large = |change: &dyn Fn(&mut Credentials)| {
            let mut credentials = fake.credentials();
            change(&mut credentials);
            Session::new(settings(credentials))
                .map(|_| ())
                .expect_err("a session on credentials past their bound")
                .to_string()
        };
        let cases: [&dyn Fn(&mut Credentials); 6] = [
            &|c| c.url = Zeroizing::new(format!("{}&x={}", *c.url, "u".repeat(64 << 10))),
            &|c| c.token = Zeroizing::new("c".repeat(8193)),
            &|c| c.gateway = format!("http://{}", "g".repeat(2048)),
            &|c| c.session_id = "1".repeat(65),
            &|c| c.user_id = "1".repeat(65),
            &|c| c.conference_id = "1".repeat(65),
        ];
        for (i, case) in cases.into_iter().enumerate() {
            assert_eq!(too_large(case), "mtslink: credentials too large", "{i}");
        }
        // What the fake's provider hands over fits.
        assert!(Session::new(settings(fake.credentials())).is_ok());
    }

    /// Go bounds the first join (the transport gives `Connect` 60 s) and
    /// no rejoin (`reconnect` calls `Connect` under the supervisor's
    /// context): a rejoin whose steps take longer than the first join's
    /// bound still comes up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rejoin_is_not_held_to_the_first_joins_bound() {
        bounded(async {
            let fake = Fake::start().await;
            let (mut s, _news) = Session::new(settings(fake.credentials())).unwrap();
            Arc::get_mut(&mut s).unwrap().connect_bound = Duration::from_millis(600);
            s.add_video_track();
            s.connect().await.expect("Connect");
            let (open, gate) = watch::channel(false);
            fake.set(|f| f.hold_join = Some(gate));
            let opening = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let _ = open.send(true);
            });
            let began = Instant::now();
            s.rejoin()
                .await
                .expect("a rejoin slower than the first join's bound");
            assert!(began.elapsed() >= Duration::from_millis(1500));
            assert!(s.can_send());
            opening.await.unwrap();
            s.close().await;
        })
        .await;
    }

    /// A first join is held to its bound, under Go's words, and its
    /// conference is taken back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_first_join_is_held_to_its_bound() {
        bounded(async {
            let fake = Fake::start().await;
            let (_open, gate) = watch::channel(false);
            fake.set(|f| f.hold_join = Some(gate));
            let (mut s, _news) = Session::new(settings(fake.credentials())).unwrap();
            Arc::get_mut(&mut s).unwrap().connect_bound = Duration::from_millis(600);
            s.add_video_track();
            let began = Instant::now();
            let err = s.connect().await.unwrap_err();
            assert_eq!(err, Error::ConnectBound);
            assert_eq!(
                err.to_string(),
                "mtslink: connect wait: context deadline exceeded"
            );
            assert!(began.elapsed() >= Duration::from_millis(600));
            assert_eq!(
                fake.calls(),
                [
                    format!("POST /rtc/room/{SESSION}/join"),
                    format!("DELETE /api/conferences/{CONFERENCE}"),
                ]
            );
            assert_eq!(CONNECT_BOUND, Duration::from_secs(60));
        })
        .await;
    }

    /// What a session holds per generation is what the budget says.
    #[test]
    fn what_a_generation_holds_is_bounded() {
        assert_eq!(RESEND_PACKETS, 257);
        assert_eq!(RESEND_HELD, 257 * 1200);
        assert_eq!(
            GENERATION_HELD,
            RESEND_HELD + 9 * crate::readers::READER_HELD
        );
        // 7.06 MiB: the readers at olc-vp8channel's bound (was 9.06 MiB
        // with two frame buffers counted per reader).
        const { assert!(GENERATION_HELD <= 7300 << 10) };
        assert_eq!(TRACK_LINES, 18);
        assert!(std::mem::size_of::<Life>() <= 16);
    }
}

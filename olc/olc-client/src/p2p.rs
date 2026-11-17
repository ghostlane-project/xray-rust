// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The interop-p2p engine, client side: a room of the interop hub for the
//! signalling and one WebRTC peer connection ([`olc_rtc::peer::Peer`], str0m
//! in RTP mode) with one VP8 video line both ways, the line vp8channel
//! rides. The Go side is the overlay's `internal/engine/interopp2p` on
//! pion; both keep the same contract:
//!
//! - the URL is the hub's, `tcp://host:port/room`, with an optional query
//!   (`turn=` once per URL of one ICE server, `turn_user=`, `turn_pass=`,
//!   `policy=relay|all`) read as Go's `url.Query` reads it
//!   ([`parse_settings`]): the `turn:` URLs over UDP become the peer
//!   connection's TURN servers (olc-rtc's client; `turns:` and TCP ones are
//!   left out until it has them), and `policy=relay` gathers relayed
//!   candidates only; `ice=udp|tcp|both` is the peer connection's ICE mode
//!   ([`olc_rtc::peer::IceMode`]; UDP when absent): with `tcp`
//!   the client gathers nothing and dials the passive TCP candidates the
//!   server's SDP names;
//! - signalling is JSON text in the hub's DATA frames: `hello` (broadcast
//!   right after the join, then directed as a reply), `offer`, `answer`,
//!   `bye`; every participant names itself by 16 random hex characters at
//!   each join;
//! - the newcomer offers: a directed hello from X makes the offer to X; an
//!   offer from X is answered (a server that rejoined), unless it crosses
//!   our own unanswered offer to X (both hellos crossed, so each took the
//!   other for the newcomer): then the greater id's offer stands and the
//!   lower id answers it;
//! - no trickle: the offer and the answer wait for the relayed candidates
//!   (at most [`GATHER_BUDGET`], the Go side's `gatherBudget`) and carry
//!   every candidate;
//! - one video line, `sendrecv`, VP8: what the remote sends goes to the
//!   frame handler through [`olc_vp8channel::rtp_reader::TrackReader`];
//!   what the transport writes goes out packetized as pion would
//!   ([`olc_vp8channel::rtp::Packetizer`]).
//!
//! This side keeps one peer connection: the server's. A participant that
//! is not the one it offered to (or answered) is ignored, as vp8channel's
//! binding token would ignore its frames anyway.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use olc_rtc::media::{with_codecs, CodecLine, ResendCache, RtpOut, SendLine};
use olc_rtc::peer::{IceMode, Peer, PeerConfig, PeerEvent};
use olc_rtc::str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use olc_rtc::str0m::format::{Codec, FormatParams};
use olc_rtc::str0m::media::{Direction, MediaKind, Mid};
use olc_rtc::str0m::rtp::RtpPacket;
use olc_rtc::str0m::RtcConfig;
use olc_rtc::turn::{servers_with, TurnServer, TurnTransport, MAX_ALLOCATIONS};
use olc_rtc::DtlsVersion;
use olc_vp8channel::channel::Carrier;
use olc_vp8channel::rtp::{Packetizer, Payloader, Vp8Payloader};
use olc_vp8channel::rtp_reader::{TrackReader, MIME_VP8, REORDER_HOLD, REORDER_WINDOW};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

use crate::pipe::{
    frame_into, parse_url, read_frame, KIND_DATA, KIND_END, KIND_JOIN, MAX_PAYLOAD, PEER_SETTLE,
    REJOIN_BACKOFF, REJOIN_MAX,
};

/// The id's length in hex characters.
pub const ID_LEN: usize = 16;

/// What its channels may hold unacknowledged: the peer has none (media
/// only), so str0m's floor.
const SCTP_BUFFERED: usize = 64 << 10;

/// How long the resend cache keeps a sent packet (str0m's `set_rtx_cache`):
/// as long as the far end's vp8channel reader can still take it back. That
/// reader (Go's `reorderHold`, [`REORDER_HOLD`]) gives a gap up 300 ms after
/// the first packet behind it arrived, so a NACK reaching this end later
/// than 300 ms after the packet went asks for what will never be read.
pub const RESEND_AGE: Duration = REORDER_HOLD;

/// The newest packets the resend cache keeps, at most: packets a second at
/// the carriers' fastest rate times [`RESEND_AGE`], but never more than
/// the far reader holds behind a gap. MTS Link's SFU forwarded 19 Mbit/s
/// (vp8channel's `carrier.go`, measured 2026-10-11): 1979 packets a second
/// of 1200 bytes, 594 in 300 ms. The reader (Go's `reorderWindow`,
/// [`REORDER_WINDOW`]) gives a gap up once 256 packets wait behind it, so
/// the 257th newest is the oldest a resend can still fill in. pion's
/// responder keeps 1024 by default, the Go engine's phone profile 256
/// (`interceptors.go:19`), str0m 1000 for 3 s.
pub const RESEND_PACKETS: usize = REORDER_WINDOW + 1;

/// The share of resends in what is sent past which str0m drops the queued
/// ones: its default (`DEFAULT_RTX_RATIO_CAP`, not exported).
const RESEND_RATIO_CAP: Option<f32> = Some(0.15);

/// How long an offer or an answer waits for its relayed candidates before
/// it goes with what it has (the Go side's `gatherBudget`).
pub const GATHER_BUDGET: Duration = Duration::from_secs(10);

/// The one codec's payload type, as the Go side registers it
/// (`VP8PayloadType`).
pub const VP8_PAYLOAD_TYPE: u8 = 96;

/// The peer's codecs are the Go side's: VP8 at [`VP8_PAYLOAD_TYPE`] with
/// NACK, PLI and FIR feedback, and no RTX (the engine's `newAPI` registers
/// VP8 with that feedback and nothing else). So an SDP from this end names
/// what one from the Go end names, and a lost packet comes back on its own
/// SSRC (the vendored str0m's `ResendPlain`).
fn lab_codecs(config: RtcConfig) -> RtcConfig {
    with_codecs(
        config,
        &[CodecLine::video(
            VP8_PAYLOAD_TYPE,
            None,
            Codec::Vp8,
            FormatParams::default(),
        )],
    )
}

/// The engine's news for the transport above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pEvent {
    /// The engine joined again (a lost hub, a dead peer connection, a
    /// `Reconnect`): the planes over it restart on a new epoch.
    Reconnected,
    /// The hub ended the conference.
    Ended(String),
}

/// Why the engine did not come up.
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    /// The URL is not `tcp://host:port/room[?query]`.
    #[error("interop-p2p: url must be tcp://host:port/room")]
    BadUrl,
    /// The hub.
    #[error("interop-p2p: {0}")]
    Io(#[from] io::Error),
}

/// One signalling message (the contract's JSON); unknown fields are
/// ignored, an unknown `t` too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// `hello`, `offer`, `answer` or `bye`.
    pub t: String,
    /// The sender's id.
    pub from: String,
    /// The addressee's id; empty for everyone.
    #[serde(default)]
    pub to: String,
    /// The SDP of an offer or an answer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sdp: String,
}

/// The engine's URL as the Go side reads it (`ParseSettings`): the hub,
/// the room, one ICE server's `turn=` URLs and credential, and the policy.
/// Its `Debug` shows no password.
#[derive(Clone, PartialEq, Eq)]
pub struct Settings {
    /// The hub's `host:port`.
    pub addr: String,
    /// The room.
    pub room: String,
    /// The `turn=` values, in order (one ICE server's URLs).
    pub turn: Vec<String>,
    /// `turn_user=`.
    pub turn_user: String,
    /// `turn_pass=`.
    pub turn_pass: String,
    /// `policy=relay` (`all` or none is every candidate).
    pub relay_only: bool,
    /// `ice=udp|tcp|both`; `None` when the URL has none.
    pub ice: Option<IceMode>,
}

impl Settings {
    /// The peer connection's ICE mode: the URL's `ice=`, else UDP. Nothing
    /// else names it; the gate writes `ice=` into both ends' URLs
    /// (`-olcrtc.gate-ice`, `olc/interop/p2p.sh --ice`).
    #[must_use]
    pub fn ice_mode(&self) -> IceMode {
        self.ice.unwrap_or_default()
    }
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("addr", &self.addr)
            .field("room", &self.room)
            .field("turn", &self.turn)
            .field("turn_user", &self.turn_user)
            .field("turn_pass_len", &self.turn_pass.len())
            .field("relay_only", &self.relay_only)
            .field("ice", &self.ice)
            .finish()
    }
}

/// Reads the engine's URL, `tcp://host:port/room[?turn=..&turn_user=..&
/// turn_pass=..&policy=relay|all]`, as Go's `url.Query` does: pairs split
/// on `&`, each part unescaped (`+` is a space); a pair that does not
/// unescape, or holds a `;`, is dropped.
///
/// # Errors
/// [`P2pError::BadUrl`]: not a hub URL, or a policy neither `relay` nor
/// `all`.
pub fn parse_settings(raw: &str) -> Result<Settings, P2pError> {
    let (base, query) = raw.split_once('?').unwrap_or((raw, ""));
    let (addr, room) = parse_url(base).map_err(|_| P2pError::BadUrl)?;
    let mut s = Settings {
        addr,
        room,
        turn: Vec::new(),
        turn_user: String::new(),
        turn_pass: String::new(),
        relay_only: false,
        ice: None,
    };
    let mut policy = None;
    let mut ice = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        if pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (query_unescape(k), query_unescape(v)) else {
            continue;
        };
        match k.as_str() {
            "turn" => s.turn.push(v),
            // url.Values.Get: the first value.
            "turn_user" if s.turn_user.is_empty() => s.turn_user = v,
            "turn_pass" if s.turn_pass.is_empty() => s.turn_pass = v,
            "policy" if policy.is_none() => policy = Some(v),
            "ice" if ice.is_none() => ice = Some(v),
            _ => {}
        }
    }
    s.ice = match ice.as_deref() {
        None | Some("") => None,
        Some(word) => Some(IceMode::parse(word).ok_or(P2pError::BadUrl)?),
    };
    s.relay_only = match policy.as_deref() {
        None | Some("" | "all") => false,
        Some("relay") => true,
        Some(_) => return Err(P2pError::BadUrl),
    };
    Ok(s)
}

/// Go's `url.QueryUnescape`: `+` is a space, `%XX` a byte; `None` on a bad
/// escape or bytes that are not UTF-8.
fn query_unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = b.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// A fresh id: 16 lowercase hex characters.
#[must_use]
pub fn new_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// The `a=mid:` of the first `m=video` section of `sdp`.
#[must_use]
pub fn video_mid(sdp: &str) -> Option<&str> {
    let mut in_video = false;
    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(m) = line.strip_prefix("m=") {
            in_video = m.starts_with("video ");
        } else if in_video {
            if let Some(mid) = line.strip_prefix("a=mid:") {
                return Some(mid.trim());
            }
        }
    }
    None
}

/// Whether our unanswered offer (to `pending`) stands against an offer from
/// `remote`: only when the two cross and our id is the greater (the
/// overlay's `answer` keeps the same rule).
#[must_use]
pub fn crossed_offer_stands(pending: Option<&str>, me: &str, remote: &str) -> bool {
    pending == Some(remote) && me > remote
}

/// What a frame the track reader completes is handed to.
pub type FrameHandler = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// The media both ways on the current peer connection.
struct Media {
    peer: Option<Peer>,
    /// The video line, once offered or answered.
    mid: Option<Mid>,
    /// The line's send stream, once negotiated with VP8 on it: the payload
    /// type to write with and where the sequence stands on this peer.
    line: Option<SendLine>,
    packetizer: Packetizer,
}

struct State {
    id: String,
    /// The participant the peer connection is with, and the connection's
    /// generation (a dead driver names itself by it).
    remote: Option<(String, u64)>,
    /// An offer we sent and the str0m state that takes its answer.
    pending: Option<(String, SdpPendingOffer)>,
    writer: Option<OwnedWriteHalf>,
    closed: bool,
}

/// One participant in a hub room with a peer connection to the server.
pub struct P2pLink {
    addr: String,
    room: String,
    /// The URL's TURN servers over UDP.
    turn: Vec<TurnServer>,
    /// The URL's `policy=relay`.
    relay_only: bool,
    /// The URL's `ice=`, else UDP.
    ice: IceMode,
    host_ip: IpAddr,
    frame_ns: i64,
    st: tokio::sync::Mutex<State>,
    media: Mutex<Media>,
    on_frame: Mutex<Option<FrameHandler>>,
    events: mpsc::Sender<P2pEvent>,
    joined: AtomicBool,
    connected: AtomicBool,
    gen: AtomicU64,
    /// When the current peer connection came up (its DTLS and SRTP in
    /// place, so samples go out); `None` while there is none.
    up_since: watch::Sender<Option<tokio::time::Instant>>,
    /// The current peer connection's generation and the relayed candidates
    /// it has gathered.
    gathered: watch::Sender<(u64, usize)>,
    rejoining: AtomicBool,
    /// RTP packets the remote sent.
    pub rtp_in: AtomicU64,
    /// RTP packets written.
    pub rtp_out: AtomicU64,
}

impl std::fmt::Debug for P2pLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pLink")
            .field("addr", &self.addr)
            .field("room", &self.room)
            .finish_non_exhaustive()
    }
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl P2pLink {
    /// Joins the room `url` names and says hello. `frame_interval` is the
    /// transport's, the duration each written sample stands for.
    ///
    /// # Errors
    /// The URL or the hub.
    pub async fn connect(
        url: &str,
        host_ip: IpAddr,
        frame_interval: Duration,
        events: mpsc::Sender<P2pEvent>,
    ) -> Result<Arc<Self>, P2pError> {
        let set = parse_settings(url)?;
        // The hub's TURN servers over UDP alone, as this lane was built and
        // measured (olc-rtc's `udp_servers`, which became `servers` with TCP
        // and TLS): taking the room's TCP and TLS servers here is a change
        // of its own, with its own relay-only run.
        let mut turn = servers_with(&set.turn, &set.turn_user, &set.turn_pass, false);
        turn.retain(|s| s.transport == TurnTransport::Udp);
        let ice = set.ice_mode();
        if ice != IceMode::Udp {
            crate::info!("interop-p2p: ICE over {}", ice.as_str());
        }
        if !ice.udp() {
            // A TCP-only peer allocates nothing (relayed candidates are
            // UDP ones), so no SDP waits for them.
            turn.clear();
        }
        if set.relay_only && turn.is_empty() {
            crate::info!(
                "interop-p2p: relay-only with no TURN server over UDP in the URL: no candidate to offer"
            );
        }
        olc_rtc::init();
        let link = Arc::new(Self {
            addr: set.addr,
            room: set.room,
            turn,
            relay_only: set.relay_only,
            ice,
            host_ip,
            frame_ns: i64::try_from(frame_interval.as_nanos()).unwrap_or(i64::MAX),
            st: tokio::sync::Mutex::new(State {
                id: new_id(),
                remote: None,
                pending: None,
                writer: None,
                closed: false,
            }),
            media: Mutex::new(Media {
                peer: None,
                mid: None,
                line: None,
                // pion's VP8 payloader starts its picture ids at 0.
                packetizer: Packetizer::random(Payloader::Vp8(Vp8Payloader::with_picture_id(0))),
            }),
            on_frame: Mutex::new(None),
            events,
            joined: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            gen: AtomicU64::new(0),
            up_since: watch::Sender::new(None),
            gathered: watch::Sender::new((0, 0)),
            rejoining: AtomicBool::new(false),
            rtp_in: AtomicU64::new(0),
            rtp_out: AtomicU64::new(0),
        });
        link.join().await?;
        Ok(link)
    }

    /// Dials the hub, joins, starts the reader and says hello.
    async fn join(self: &Arc<Self>) -> Result<(), P2pError> {
        let conn = TcpStream::connect(&self.addr).await?;
        conn.set_nodelay(true)?;
        let (read, mut write) = conn.into_split();
        let mut buf = Vec::new();
        frame_into(&mut buf, KIND_JOIN, self.room.as_bytes())?;
        write.write_all(&buf).await?;
        let id = {
            let mut st = self.st.lock().await;
            if st.closed {
                return Err(io::Error::from(io::ErrorKind::NotConnected).into());
            }
            st.writer = Some(write);
            st.remote = None;
            st.pending = None;
            st.id = new_id();
            st.id.clone()
        };
        self.joined.store(true, Ordering::Release);
        crate::debug!("interop-p2p: joined {} as {id}", self.room);
        tokio::spawn(self.clone().read_loop(read));
        self.signal(&Signal {
            t: "hello".into(),
            from: id,
            ..Signal::default()
        })
        .await;
        Ok(())
    }

    /// Sends one signalling message; a failed write is the reader's to see.
    async fn signal(&self, msg: &Signal) {
        let Ok(text) = serde_json::to_vec(msg) else {
            return;
        };
        let mut buf = Vec::with_capacity(text.len() + 5);
        if frame_into(&mut buf, KIND_DATA, &text).is_err() {
            return;
        }
        let mut st = self.st.lock().await;
        if let Some(w) = st.writer.as_mut() {
            if let Err(e) = w.write_all(&buf).await {
                crate::debug!("interop-p2p: signal: {e}");
            }
        }
    }

    async fn read_loop(self: Arc<Self>, mut read: tokio::net::tcp::OwnedReadHalf) {
        let mut buf = vec![0u8; MAX_PAYLOAD];
        let reason = loop {
            let (kind, n) = match read_frame(&mut read, &mut buf).await {
                Ok(f) => f,
                Err(e) => break format!("hub: {e}"),
            };
            match kind {
                KIND_DATA => {
                    if let Ok(msg) = serde_json::from_slice::<Signal>(&buf[..n]) {
                        self.on_signal(msg).await;
                    }
                }
                KIND_END => {
                    let why = String::from_utf8_lossy(&buf[..n]).into_owned();
                    self.st.lock().await.writer = None;
                    self.joined.store(false, Ordering::Release);
                    let _ = self.events.send(P2pEvent::Ended(why)).await;
                    return;
                }
                _ => {}
            }
        };
        if self.st.lock().await.closed {
            return;
        }
        crate::info!("interop-p2p: {reason}, rejoining the room");
        self.rejoin().await;
    }

    async fn on_signal(self: &Arc<Self>, msg: Signal) {
        let (me, ours) = {
            let st = self.st.lock().await;
            let ours = st.remote.as_ref().map(|(r, _)| r.clone());
            (st.id.clone(), ours)
        };
        if msg.from == me || msg.from.is_empty() || !(msg.to.is_empty() || msg.to == me) {
            return;
        }
        match msg.t.as_str() {
            // A broadcast hello: an older participant answers with its own
            // and waits for the newcomer's offer.
            "hello" if msg.to.is_empty() => {
                if ours.is_none() {
                    self.signal(&Signal {
                        t: "hello".into(),
                        from: me,
                        to: msg.from,
                        ..Signal::default()
                    })
                    .await;
                }
            }
            // A directed hello: we are the newcomer, so we offer.
            "hello" => {
                if ours.is_none() {
                    self.offer(&me, &msg.from).await;
                }
            }
            "offer" => self.answer(&me, &msg.from, &msg.sdp).await,
            "answer" => self.accept(&msg.from, &msg.sdp).await,
            "bye" if ours.as_deref() == Some(msg.from.as_str()) => {
                self.drop_peer().await;
            }
            _ => {}
        }
    }

    fn peer_config(&self) -> PeerConfig {
        PeerConfig {
            name: "p2p",
            crypto: olc_rtc::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: self.host_ip,
            sctp_max_buffered: SCTP_BUFFERED,
            turn: self.turn.clone(),
            relay_only: self.relay_only,
            ice_mode: self.ice,
        }
    }

    /// A fresh peer connection for `remote`, gathering (its host candidate
    /// added, its TURN allocations started) and its driver's events watched;
    /// the old one closed. Returns it with its generation.
    fn start_peer(self: &Arc<Self>, st: &mut State, remote: &str) -> Option<(Peer, u64)> {
        let (peer, rx) = match Peer::start_tuned(&self.peer_config(), lab_codecs) {
            Ok(p) => p,
            Err(e) => {
                crate::info!("interop-p2p: peer connection: {e}");
                return None;
            }
        };
        if let Err(e) = peer.gather() {
            crate::info!("interop-p2p: host candidate: {e}");
            peer.close();
            return None;
        }
        let gen = self.gen.fetch_add(1, Ordering::AcqRel) + 1;
        st.remote = Some((remote.to_owned(), gen));
        self.line_down();
        self.gathered.send_replace((gen, 0));
        let old = {
            let mut m = locked(&self.media);
            m.mid = None;
            m.line = None;
            m.peer.replace(peer.clone())
        };
        if let Some(old) = old {
            old.close();
        }
        tokio::spawn(self.clone().watch(rx, gen));
        Some((peer, gen))
    }

    /// Waits until connection `gen` has a relayed candidate from each TURN
    /// server, or [`GATHER_BUDGET`] (the Go side's `GatheringCompletePromise`
    /// under its budget: no trickle, so the SDP carries what is there then);
    /// whether `gen` is still the current connection.
    async fn wait_gathered(&self, gen: u64) -> bool {
        let want = self.turn.len().min(MAX_ALLOCATIONS);
        if want > 0 {
            let mut rx = self.gathered.subscribe();
            let gathered = rx.wait_for(|&(g, n)| g != gen || n >= want);
            if tokio::time::timeout(GATHER_BUDGET, gathered).await.is_err() {
                crate::info!(
                    "interop-p2p: gathering still running after {GATHER_BUDGET:?}; sending what it has"
                );
            }
        }
        self.gen.load(Ordering::Acquire) == gen
    }

    async fn offer(self: &Arc<Self>, me: &str, remote: &str) {
        let started = {
            let mut st = self.st.lock().await;
            self.start_peer(&mut st, remote)
        };
        let Some((peer, gen)) = started else {
            return;
        };
        if !self.wait_gathered(gen).await {
            return;
        }
        let mut st = self.st.lock().await;
        if self.gen.load(Ordering::Acquire) != gen {
            return;
        }
        let made = peer.with_rtc(|rtc| {
            let mut api = rtc.sdp_api();
            let mid = api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
            api.apply().map(|(offer, pending)| (offer, pending, mid))
        });
        let Some((offer, pending, mid)) = made else {
            crate::info!("interop-p2p: str0m made no offer");
            return;
        };
        locked(&self.media).mid = Some(mid);
        st.pending = Some((remote.to_owned(), pending));
        drop(st);
        crate::debug!("interop-p2p: offer to {remote}");
        self.signal(&Signal {
            t: "offer".into(),
            from: me.to_owned(),
            to: remote.to_owned(),
            sdp: offer.to_sdp_string(),
        })
        .await;
    }

    async fn accept(self: &Arc<Self>, remote: &str, sdp: &str) {
        let mut st = self.st.lock().await;
        let Some((to, pending)) = st.pending.take() else {
            return;
        };
        if to != remote {
            st.pending = Some((to, pending));
            return;
        }
        drop(st);
        let answer = match SdpAnswer::from_sdp_string(sdp) {
            Ok(a) => a,
            Err(e) => {
                crate::info!("interop-p2p: answer from {remote}: {e}");
                return;
            }
        };
        let peer = locked(&self.media).peer.clone();
        let Some(peer) = peer else { return };
        if let Err(e) = peer.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer)) {
            crate::info!("interop-p2p: answer from {remote}: {e}");
            return;
        }
        // ICE over TCP: the answer's passive candidates are dialled.
        peer.remote_described(sdp);
        self.media_ready(&peer);
    }

    async fn answer(self: &Arc<Self>, me: &str, remote: &str, sdp: &str) {
        let offer = match SdpOffer::from_sdp_string(sdp) {
            Ok(o) => o,
            Err(e) => {
                crate::info!("interop-p2p: offer from {remote}: {e}");
                return;
            }
        };
        let Some(mid) = video_mid(sdp).map(Mid::from) else {
            crate::info!("interop-p2p: offer from {remote} has no video line");
            return;
        };
        let started = {
            let mut st = self.st.lock().await;
            if crossed_offer_stands(st.pending.as_ref().map(|(to, _)| to.as_str()), me, remote) {
                crate::debug!("interop-p2p: the offer from {remote} crossed ours; ours stands");
                return;
            }
            st.pending = None;
            self.start_peer(&mut st, remote)
        };
        let Some((peer, gen)) = started else {
            return;
        };
        if !self.wait_gathered(gen).await {
            return;
        }
        let answer = match peer.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer)) {
            Ok(a) => a,
            Err(e) => {
                crate::info!("interop-p2p: offer from {remote}: {e}");
                return;
            }
        };
        locked(&self.media).mid = Some(mid);
        peer.remote_described(sdp);
        self.media_ready(&peer);
        crate::debug!("interop-p2p: answer to {remote}");
        self.signal(&Signal {
            t: "answer".into(),
            from: me.to_owned(),
            to: remote.to_owned(),
            sdp: answer.to_sdp_string(),
        })
        .await;
    }

    /// The line is negotiated: the VP8 payload type to write with, the send
    /// stream's resend cache sized ([`RESEND_PACKETS`], [`RESEND_AGE`]) before
    /// anything is written, and the remote's RTP into the track reader.
    fn media_ready(self: &Arc<Self>, peer: &Peer) {
        let pt = peer.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Vp8)
                .map(|p| p.pt())
        });
        let Some(pt) = pt else {
            locked(&self.media).line = None;
            crate::info!("interop-p2p: no VP8 on the line");
            return;
        };
        let line = locked(&self.media)
            .mid
            .map(|mid| SendLine::new(mid, None, pt));
        let sized = line.as_ref().is_some_and(|line| {
            line.size_resends(
                peer,
                ResendCache {
                    packets: RESEND_PACKETS,
                    age: RESEND_AGE,
                    ratio_cap: RESEND_RATIO_CAP,
                },
            )
        });
        if !sized {
            crate::info!("interop-p2p: no send stream on the line to size the resends of");
        }
        locked(&self.media).line = line;
        let mut reader = TrackReader::new(Carrier::Vp8, MIME_VP8).expect("vp8channel reads VP8");
        let me = Arc::downgrade(self);
        peer.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
            let Some(me) = me.upgrade() else { return };
            me.rtp_in.fetch_add(1, Ordering::Relaxed);
            if p.header.payload_type != pt {
                return;
            }
            let handler = locked(&me.on_frame).clone();
            let Some(handler) = handler else { return };
            reader.push(
                p.header.sequence_number,
                p.header.marker,
                *p.header.payload_type,
                &p.payload,
                Instant::now(),
                &mut |frame| handler(frame),
            );
        })));
    }

    /// The driver's events: up, or gone (the engine then joins again).
    async fn watch(self: Arc<Self>, mut rx: mpsc::Receiver<PeerEvent>, gen: u64) {
        while let Some(ev) = rx.recv().await {
            match ev {
                PeerEvent::Connected => {
                    let now = tokio::time::Instant::now();
                    // Under the watch's lock, as `line_down`: a connection
                    // replaced meanwhile does not mark its successor up.
                    let current = self.up_since.send_if_modified(|v| {
                        if self.gen.load(Ordering::Acquire) != gen {
                            return false;
                        }
                        *v = Some(now);
                        self.connected.store(true, Ordering::Release);
                        true
                    });
                    if current {
                        crate::info!("interop-p2p: peer connection up");
                        self.say_udp_out("up");
                    }
                }
                PeerEvent::LocalCandidate(_) => {
                    self.gathered.send_if_modified(|(g, n)| {
                        if *g != gen {
                            return false;
                        }
                        *n += 1;
                        true
                    });
                }
                // ICE over TCP has nothing left (a connection that broke, a
                // dial that failed) and no other path is alive: the driver
                // runs on, the engine joins again now.
                PeerEvent::Failed(why) => {
                    if self.gen.load(Ordering::Acquire) == gen && !self.st.lock().await.closed {
                        crate::info!("interop-p2p: peer connection failed: {why}");
                        self.say_udp_out("failed");
                        self.rejoin().await;
                    }
                }
                PeerEvent::Closed(why) => {
                    if self.gen.load(Ordering::Acquire) == gen && !self.st.lock().await.closed {
                        crate::info!("interop-p2p: peer connection ended: {why}");
                        self.say_udp_out("ended");
                        self.rejoin().await;
                    }
                    return;
                }
                _ => {}
            }
        }
    }

    /// With ICE over TCP, says how many datagrams the current peer
    /// connection gave its UDP socket (none, in `tcp` mode): the lab's
    /// `p2p.sh --ice=tcp` reads the line.
    fn say_udp_out(&self, when: &str) {
        if self.ice == IceMode::Udp {
            return;
        }
        let peer = locked(&self.media).peer.clone();
        if let Some(peer) = peer {
            crate::info!(
                "interop-p2p: ICE over {}: {} UDP datagrams sent ({when})",
                self.ice.as_str(),
                peer.udp_out()
            );
        }
    }

    /// No line up (a new peer connection, or none): samples are dropped and
    /// no peer is settled. Called after the generation moved, and under the
    /// watch's lock, so the old connection's late `Connected` cannot undo it.
    fn line_down(&self) {
        self.up_since.send_modify(|v| {
            *v = None;
            self.connected.store(false, Ordering::Release);
        });
    }

    /// Closes the peer connection (a `bye`).
    async fn drop_peer(&self) {
        self.st.lock().await.remote = None;
        self.gen.fetch_add(1, Ordering::AcqRel);
        self.line_down();
        let old = {
            let mut m = locked(&self.media);
            m.mid = None;
            m.line = None;
            m.peer.take()
        };
        if let Some(p) = old {
            p.close();
        }
    }

    /// Leaves and joins again with a new id (`Reconnect`, a lost hub, a dead
    /// peer connection), then tells the transport. Boxed: the join it awaits
    /// spawns the reader that may call it again, a cycle the compiler cannot
    /// see `Send` through.
    fn rejoin(self: &Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if self.rejoining.swap(true, Ordering::AcqRel) {
                return;
            }
            self.leave().await;
            let mut delay = REJOIN_BACKOFF;
            loop {
                if self.st.lock().await.closed {
                    self.rejoining.store(false, Ordering::Release);
                    return;
                }
                match self.join().await {
                    Ok(()) => break,
                    Err(e) => crate::debug!("interop-p2p: rejoin: {e}"),
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(REJOIN_MAX);
            }
            self.rejoining.store(false, Ordering::Release);
            let _ = self.events.send(P2pEvent::Reconnected).await;
        })
    }

    /// Says bye, closes the peer connection and the hub connection.
    async fn leave(&self) {
        let me = self.st.lock().await.id.clone();
        self.signal(&Signal {
            t: "bye".into(),
            from: me,
            ..Signal::default()
        })
        .await;
        self.drop_peer().await;
        self.joined.store(false, Ordering::Release);
        if let Some(mut w) = self.st.lock().await.writer.take() {
            let _ = w.shutdown().await;
        }
    }

    /// Where frames the remote's track completes go.
    pub fn set_frame_handler(&self, handler: Option<FrameHandler>) {
        *locked(&self.on_frame) = handler;
    }

    /// `track.WriteSample`: one sample as the transport's frame interval,
    /// packetized and written; dropped (and taken) while no line is up, as
    /// pion's track without a binding does.
    pub fn write_sample(&self, sample: &[u8]) -> bool {
        let mut m = locked(&self.media);
        let m = &mut *m;
        let (Some(peer), Some(line)) = (m.peer.as_ref(), m.line.as_mut()) else {
            return true;
        };
        if !self.connected.load(Ordering::Acquire) {
            return true;
        }
        let packets = m.packetizer.packetize(sample, self.frame_ns);
        let written = line.write(
            peer,
            Instant::now(),
            packets.into_iter().map(|p| RtpOut {
                seq: p.seq,
                timestamp: p.timestamp,
                marker: p.marker,
                payload: p.payload,
            }),
        );
        if let Some(n) = written {
            self.rtp_out
                .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        true
    }

    /// `CanSend`: in the room.
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.joined.load(Ordering::Acquire)
    }

    /// `PeerSeen`: a peer connection came up.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Waits until the peer's data path is open (the peer connection up, so
    /// samples go out) and [`PEER_SETTLE`] old: a hello written sooner is
    /// taken and dropped ([`Self::write_sample`], as pion's unbound track
    /// does), or reaches a server whose own side of the line is not up yet.
    /// It waits on across a new peer connection and a rejoin, and for as
    /// long as there is none; the caller bounds it.
    pub async fn wait_peer_settled(&self) {
        let mut rx = self.up_since.subscribe();
        loop {
            let since = *rx.borrow_and_update();
            match since {
                Some(at) => {
                    tokio::select! {
                        () = tokio::time::sleep_until(at + PEER_SETTLE) => {
                            if *rx.borrow() == Some(at) {
                                return;
                            }
                        }
                        r = rx.changed() => if r.is_err() { return },
                    }
                }
                None => {
                    if rx.changed().await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// `Reconnect`: leave and join again, at once in the background.
    pub fn reconnect(self: &Arc<Self>, reason: &str) {
        crate::info!("interop-p2p: reconnect: {reason}");
        let me = self.clone();
        tokio::spawn(async move { me.rejoin().await });
    }

    /// Leaves the room for good.
    pub async fn close(&self) {
        self.leave().await;
        self.st.lock().await.closed = true;
        self.set_frame_handler(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_reads_as_the_go_side_reads_it() {
        let set = parse_settings(
            "tcp://127.0.0.1:9/gate-x?turn=turn%3A127.0.0.1%3A3478&turn=turns%3Alocalhost%3A5349%3Ftransport%3Dtcp\
             &turn_user=1763100000%3Aolc&turn_pass=p%2Bq+r&policy=relay&x=%zz&turn=a;b",
        )
        .unwrap();
        assert_eq!(set.addr, "127.0.0.1:9");
        assert_eq!(set.room, "gate-x");
        assert_eq!(
            set.turn,
            ["turn:127.0.0.1:3478", "turns:localhost:5349?transport=tcp"]
        );
        assert_eq!(set.turn_user, "1763100000:olc");
        assert_eq!(set.turn_pass, "p+q r");
        assert!(set.relay_only);
        assert!(!format!("{set:?}").contains("p+q r"), "{set:?}");
        let plain = parse_settings("tcp://127.0.0.1:9/gate-x").unwrap();
        assert_eq!((plain.room.as_str(), plain.turn.len()), ("gate-x", 0));
        assert!(!plain.relay_only);
        assert!(!parse_settings("tcp://h:1/r?policy=all").unwrap().relay_only);
        assert!(matches!(
            parse_settings("tcp://h:1/r?policy=none"),
            Err(P2pError::BadUrl)
        ));
        assert!(parse_settings("ws://x/y").is_err());
        // The ICE mode, in Go's three words; the first value counts.
        assert_eq!(plain.ice, None);
        assert_eq!(set.ice, None);
        for (q, want) in [
            ("ice=udp", Some(IceMode::Udp)),
            ("ice=tcp", Some(IceMode::Tcp)),
            ("policy=all&ice=both", Some(IceMode::Both)),
            ("ice=tcp&ice=udp", Some(IceMode::Tcp)),
            ("ice=", None),
        ] {
            let got = parse_settings(&format!("tcp://h:1/r?{q}")).unwrap();
            assert_eq!(got.ice, want, "{q}");
        }
        assert!(matches!(
            parse_settings("tcp://h:1/r?ice=TCP"),
            Err(P2pError::BadUrl)
        ));
    }

    // The lab's environment switch is gone: the gate writes `ice=` into
    // both ends' URLs (-olcrtc.gate-ice), and a client's ICE mode must not
    // depend on what its process inherited.
    #[test]
    fn nothing_but_the_url_names_the_ice_mode() {
        let plain = parse_settings("tcp://h:1/r").unwrap();
        assert_eq!(plain.ice_mode(), IceMode::Udp);
        let tcp = parse_settings("tcp://h:1/r?ice=tcp").unwrap();
        assert_eq!(tcp.ice_mode(), IceMode::Tcp);
        let src = include_str!("p2p.rs");
        for gone in [concat!("OLCRTC_P2P", "_ICE"), concat!("env::", "var")] {
            assert!(!src.contains(gone), "p2p.rs still reads {gone}");
        }
    }

    #[test]
    fn a_signal_reads_with_unknown_fields_and_writes_without_an_empty_sdp() {
        let s: Signal = serde_json::from_str(r#"{"t":"hello","from":"ab","to":"","x":1}"#).unwrap();
        assert_eq!(
            (s.t.as_str(), s.from.as_str(), s.to.as_str()),
            ("hello", "ab", "")
        );
        let out = serde_json::to_string(&Signal {
            t: "bye".into(),
            from: "ab".into(),
            ..Signal::default()
        })
        .unwrap();
        assert_eq!(out, r#"{"t":"bye","from":"ab","to":""}"#);
        assert!(serde_json::from_str::<Signal>(r#"{"from":"ab"}"#).is_err());
    }

    #[test]
    fn of_two_crossed_offers_the_greater_ids_stands() {
        assert!(crossed_offer_stands(Some("b"), "c", "b"));
        assert!(!crossed_offer_stands(Some("c"), "b", "c"));
        assert!(!crossed_offer_stands(None, "c", "b"));
        assert!(!crossed_offer_stands(Some("a"), "c", "b"));
    }

    #[test]
    fn an_id_is_sixteen_hex() {
        let id = new_id();
        assert_eq!(id.len(), ID_LEN);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    /// One relayed room: its members and the frames held for them.
    #[derive(Default)]
    struct Room {
        members: Vec<(usize, OwnedWriteHalf)>,
        held: Vec<(usize, Vec<u8>)>,
        hold_until: usize,
    }

    impl Room {
        /// Writes the held frames, in order, to every member but each
        /// frame's sender.
        async fn flush(&mut self) {
            for (from, frame) in std::mem::take(&mut self.held) {
                for (other, w) in &mut self.members {
                    if *other != from {
                        let _ = w.write_all(&frame).await;
                    }
                }
            }
        }
    }

    /// What [`relay_hub`] read: how many DATA frames, and their bodies.
    type Relayed = (Arc<AtomicU64>, Arc<Mutex<Vec<Vec<u8>>>>);

    /// A hub room that relays DATA frames to the other members, as the
    /// overlay's interoppipe hub does (no PEERS, no END), and counts and
    /// keeps the frames it read. With `hold_until` members it holds every
    /// frame until that many have joined, so each one's broadcast hello
    /// reaches the others (participants that joined at once).
    async fn relay_hub(hold_until: usize) -> (String, tokio::task::JoinHandle<()>, Relayed) {
        use tokio::io::AsyncReadExt;
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let room = Arc::new(tokio::sync::Mutex::new(Room {
            hold_until,
            ..Room::default()
        }));
        let read_frames = Arc::new(AtomicU64::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let counted = read_frames.clone();
        let kept = bodies.clone();
        let task = tokio::spawn(async move {
            let mut next = 0usize;
            loop {
                let Ok((conn, _)) = ln.accept().await else {
                    return;
                };
                let (mut read, write) = conn.into_split();
                let id = next;
                next += 1;
                {
                    let mut r = room.lock().await;
                    r.members.push((id, write));
                    if r.members.len() >= r.hold_until {
                        r.flush().await;
                    }
                }
                let room = room.clone();
                let counted = counted.clone();
                let kept = kept.clone();
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    loop {
                        if read.read_exact(&mut hdr).await.is_err() {
                            return;
                        }
                        let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                        let mut body = vec![0u8; len - 1];
                        if read.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        if hdr[4] != KIND_DATA {
                            continue;
                        }
                        locked(&kept).push(body.clone());
                        let mut frame = hdr.to_vec();
                        frame.extend_from_slice(&body);
                        let mut r = room.lock().await;
                        r.held.push((id, frame));
                        if r.members.len() >= r.hold_until {
                            r.flush().await;
                        }
                        counted.fetch_add(1, Ordering::Release);
                    }
                });
            }
        });
        (format!("tcp://{addr}/room"), task, (read_frames, bodies))
    }

    /// Two participants meet in a room of `hub` (both joined first when
    /// `at_once`), the URL carrying `query` when it is not empty, and a
    /// sample written on either side arrives whole on the other. Returns the
    /// signalling the hub relayed.
    async fn meet_and_move_samples(at_once: bool, query: &str) -> Vec<Vec<u8>> {
        let (url, hub, (read_frames, bodies)) = relay_hub(if at_once { 2 } else { 0 }).await;
        let url = if query.is_empty() {
            url
        } else {
            format!("{url}?{query}")
        };
        let lo = IpAddr::from([127, 0, 0, 1]);
        let tick = Duration::from_millis(16);
        let (a_tx, _a_rx) = mpsc::channel(4);
        let (b_tx, _b_rx) = mpsc::channel(4);
        let (got_a, mut at_a) = mpsc::unbounded_channel::<Vec<u8>>();
        let (got_b, mut at_b) = mpsc::unbounded_channel::<Vec<u8>>();
        let a = P2pLink::connect(&url, lo, tick, a_tx).await.unwrap();
        a.set_frame_handler(Some(Arc::new(move |f: &[u8]| {
            let _ = got_a.send(f.to_vec());
        })));
        if !at_once {
            // The first one's hello went to an empty room: the second is
            // the newcomer.
            while read_frames.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        let b = P2pLink::connect(&url, lo, tick, b_tx).await.unwrap();
        b.set_frame_handler(Some(Arc::new(move |f: &[u8]| {
            let _ = got_b.send(f.to_vec());
        })));
        // Larger than one packet's payload, so the frame spans several
        // packets and the marker closes it.
        let sample = |tag: u8| -> Vec<u8> {
            (0..3000u32)
                .map(|i| tag ^ u8::try_from(i % 251).unwrap())
                .collect()
        };
        let (to_b, to_a) = (sample(0x11), sample(0x22));
        let (mut b_has, mut a_has) = (false, false);
        while !(a_has && b_has) {
            assert!(a.write_sample(&to_b) && b.write_sample(&to_a));
            tokio::select! {
                Some(f) = at_b.recv() => { assert_eq!(f, to_b); b_has = true; }
                Some(f) = at_a.recv() => { assert_eq!(f, to_a); a_has = true; }
                () = tokio::time::sleep(tick) => {}
            }
        }
        assert!(a.peer_seen() && b.peer_seen());
        assert!(a.rtp_out.load(Ordering::Relaxed) > 0 && b.rtp_in.load(Ordering::Relaxed) > 0);
        a.close().await;
        b.close().await;
        hub.abort();
        let relayed = locked(&bodies).clone();
        relayed
    }

    /// The wait before the first hello: not while the room holds nobody,
    /// then once the peer connection has been up for the settle time, and
    /// not again after the peer said bye.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_peer_settles_once_its_line_has_been_up_for_the_settle_time() {
        crate::testing::bounded_for(Duration::from_secs(20), async {
            let (url, hub, (read_frames, _)) = relay_hub(0).await;
            let lo = IpAddr::from([127, 0, 0, 1]);
            let tick = Duration::from_millis(16);
            let (a_tx, _a_rx) = mpsc::channel(4);
            let (b_tx, _b_rx) = mpsc::channel(4);
            let a = P2pLink::connect(&url, lo, tick, a_tx).await.unwrap();
            let waiting = a.clone();
            let wait = tokio::spawn(async move { waiting.wait_peer_settled().await });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!wait.is_finished(), "settled alone in the room");
            while read_frames.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let b = P2pLink::connect(&url, lo, tick, b_tx).await.unwrap();
            wait.await.unwrap();
            let settled = tokio::time::Instant::now();
            let up = (*a.up_since.borrow()).expect("settled with no line up");
            assert!(a.peer_seen());
            assert!(
                settled >= up + PEER_SETTLE,
                "settled {:?} after the line came up",
                settled - up
            );
            // The peer leaves: its line is gone, and so is the settled peer.
            b.close().await;
            while a.peer_seen() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let waiting = a.clone();
            let wait = tokio::spawn(async move { waiting.wait_peer_settled().await });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!wait.is_finished(), "settled on a peer that left");
            wait.abort();
            a.close().await;
            hub.abort();
        })
        .await;
    }

    /// The second is the newcomer and offers, the first answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_participants_meet_and_move_samples_both_ways() {
        crate::testing::bounded_for(Duration::from_secs(20), meet_and_move_samples(false, ""))
            .await;
    }

    /// Both hellos cross, so each takes the other for the newcomer and both
    /// offer: the greater id's offer stands and the lower id answers it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn participants_that_join_at_once_still_meet() {
        crate::testing::bounded_for(Duration::from_secs(20), meet_and_move_samples(true, "")).await;
    }

    const TURN_USER: &str = "1763100000:olc";
    const TURN_PASS: &str = "turn-test-password";

    /// A TURN server on loopback relaying from 127.0.0.1 (webrtc-rs's,
    /// tests only, as olc-rtc's relay tests run it), and its `turn:` URL.
    async fn turn_server() -> (turn::server::Server, String) {
        use turn::relay::relay_static::RelayAddressGeneratorStatic;
        use turn::server::config::{ConnConfig, ServerConfig};
        let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = conn.local_addr().unwrap();
        let server = turn::server::Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::from([127, 0, 0, 1]),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(webrtc_util::vnet::net::Net::new(None)),
                }),
            }],
            realm: "olc.test".to_owned(),
            auth_handler: Arc::new(
                turn::auth::StaticAuthHandler::new(
                    [(TURN_USER.to_owned(), TURN_PASS.to_owned())].into(),
                )
                .unwrap(),
            ),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .unwrap();
        (server, format!("turn:{addr}"))
    }

    /// The `a=candidate` lines of the offers and answers the hub relayed.
    fn signalled_candidates(signals: &[Vec<u8>]) -> Vec<String> {
        signals
            .iter()
            .filter_map(|raw| serde_json::from_slice::<Signal>(raw).ok())
            .filter(|s| s.t == "offer" || s.t == "answer")
            .flat_map(|s| {
                s.sdp
                    .lines()
                    .filter(|l| l.starts_with("a=candidate:"))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Both participants read the URL's TURN server and relay-only policy,
    /// as the Go side does: every candidate either one signals is a relayed
    /// one, and samples still move both ways.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_only_participants_meet_through_the_urls_turn_server() {
        crate::testing::bounded_for(Duration::from_secs(20), async {
            let (server, turn) = turn_server().await;
            let query = format!(
                "turn={}&turn_user={}&turn_pass={TURN_PASS}&policy=relay",
                turn.replace(':', "%3A"),
                TURN_USER.replace(':', "%3A"),
            );
            let signals = meet_and_move_samples(false, &query).await;
            let candidates = signalled_candidates(&signals);
            assert!(
                !candidates.is_empty() && candidates.iter().all(|c| c.contains(" typ relay")),
                "{candidates:?}"
            );
            server.close().await.unwrap();
        })
        .await;
    }

    /// A UDP hop in front of the TURN server at `server`: each client's
    /// datagrams go up through a socket of the hop's own (one 5-tuple per
    /// client, as the server wants), and every `nth` ChannelData carrying
    /// VP8 RTP (payload type 96 in SRTP's clear header) is dropped on its
    /// way up. Returns the hop's address and how many it dropped.
    async fn lossy_hop(
        server: std::net::SocketAddr,
        nth: u64,
    ) -> (std::net::SocketAddr, Arc<AtomicU64>) {
        use std::collections::HashMap;
        use tokio::net::UdpSocket;
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let dropped = Arc::new(AtomicU64::new(0));
        let counted = dropped.clone();
        tokio::spawn(async move {
            let mut ups: HashMap<std::net::SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut seen = 0u64;
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let Ok((n, from)) = front.recv_from(&mut buf).await else {
                    return;
                };
                let up = if let Some(u) = ups.get(&from) {
                    u.clone()
                } else {
                    let u = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    u.connect(server).await.unwrap();
                    let (down, back) = (u.clone(), front.clone());
                    tokio::spawn(async move {
                        let mut b = vec![0u8; 1 << 16];
                        while let Ok(n) = down.recv(&mut b).await {
                            let _ = back.send_to(&b[..n], from).await;
                        }
                    });
                    ups.insert(from, u.clone());
                    u
                };
                let d = &buf[..n];
                let vp8 = n > 6
                    && (0x40..=0x7f).contains(&d[0])
                    && (0x80..=0xbf).contains(&d[4])
                    && d[5] & 0x7f == 96;
                if vp8 {
                    seen += 1;
                    if seen.is_multiple_of(nth) {
                        counted.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                let _ = up.send(d).await;
            }
        });
        (addr, dropped)
    }

    /// What [`nack_hop`] did and saw, and what it is told to do next.
    #[derive(Default)]
    struct NackHop {
        /// Drop the next VP8 packet (and take the flag down).
        drop_next: AtomicBool,
        /// The dropped packet's SSRC and sequence number.
        dropped: Mutex<Option<(u32, u16)>>,
        /// VP8 packets that came again with the dropped one's SSRC and number.
        resent: AtomicU64,
        /// How long each RTCP packet is held before it goes on, ms.
        rtcp_delay_ms: AtomicU64,
        /// RTCP packets passed on.
        rtcp: AtomicU64,
    }

    /// A UDP hop in front of the TURN server that drops one VP8 packet when
    /// told to, counts the packet coming again, and holds RTCP (the NACKs
    /// with it) for a while when told to: the TURN ChannelData each client
    /// sends up carries RTP and SRTCP whose headers are in the clear.
    async fn nack_hop(server: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<NackHop>) {
        use std::collections::HashMap;
        use tokio::net::UdpSocket;
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let hop = Arc::new(NackHop::default());
        let st = hop.clone();
        tokio::spawn(async move {
            let mut ups: HashMap<std::net::SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let Ok((n, from)) = front.recv_from(&mut buf).await else {
                    return;
                };
                let up = if let Some(u) = ups.get(&from) {
                    u.clone()
                } else {
                    let u = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    u.connect(server).await.unwrap();
                    let (down, back) = (u.clone(), front.clone());
                    tokio::spawn(async move {
                        let mut b = vec![0u8; 1 << 16];
                        while let Ok(n) = down.recv(&mut b).await {
                            let _ = back.send_to(&b[..n], from).await;
                        }
                    });
                    ups.insert(from, u.clone());
                    u
                };
                let d = buf[..n].to_vec();
                let channel =
                    n > 16 && (0x40..=0x7f).contains(&d[0]) && (0x80..=0xbf).contains(&d[4]);
                if channel && d[5] & 0x7f == VP8_PAYLOAD_TYPE {
                    let id = (
                        u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
                        u16::from_be_bytes([d[6], d[7]]),
                    );
                    if st.drop_next.swap(false, Ordering::AcqRel) {
                        *st.dropped.lock().unwrap() = Some(id);
                        continue;
                    }
                    if *st.dropped.lock().unwrap() == Some(id) {
                        st.resent.fetch_add(1, Ordering::Relaxed);
                    }
                } else if channel && (200..=207).contains(&d[5]) {
                    let delay = st.rtcp_delay_ms.load(Ordering::Relaxed);
                    let counted = st.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        counted.rtcp.fetch_add(1, Ordering::Relaxed);
                        let _ = up.send(&d).await;
                    });
                    continue;
                }
                let _ = up.send(&d).await;
            }
        });
        (addr, hop)
    }

    /// Writes `sample` from `a` a tick apart for `run`, or until `done`.
    async fn write_for(a: &P2pLink, sample: &[u8], run: Duration, done: impl Fn() -> bool) {
        let until = tokio::time::Instant::now() + run;
        while tokio::time::Instant::now() < until && !done() {
            assert!(a.write_sample(sample));
            tokio::time::sleep(Duration::from_millis(16)).await;
        }
    }

    /// The resend cache keeps a packet as long as the far reader can still
    /// take it ([`RESEND_AGE`], vp8channel's `reorderHold`) and no longer:
    /// both ends relay-only through [`nack_hop`], a packet dropped while
    /// RTCP goes straight through comes again, and one dropped while every
    /// RTCP packet is held for twice that does not, though its NACKs arrive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_nack_later_than_the_far_readers_hold_finds_nothing() {
        crate::testing::bounded_for(Duration::from_secs(30), async {
            let (server, turn) = turn_server().await;
            let at: std::net::SocketAddr = turn.trim_start_matches("turn:").parse().unwrap();
            let (via, hop) = nack_hop(at).await;
            let query = format!(
                "turn=turn%3A{}&turn_user={}&turn_pass={TURN_PASS}&policy=relay",
                via.to_string().replace(':', "%3A"),
                TURN_USER.replace(':', "%3A"),
            );
            let (url, hub, (read_frames, _)) = relay_hub(0).await;
            let url = format!("{url}?{query}");
            let lo = IpAddr::from([127, 0, 0, 1]);
            let tick = Duration::from_millis(16);
            let (a_tx, _a_rx) = mpsc::channel(4);
            let (b_tx, _b_rx) = mpsc::channel(4);
            let (got_b, mut at_b) = mpsc::unbounded_channel::<Vec<u8>>();
            let a = P2pLink::connect(&url, lo, tick, a_tx).await.unwrap();
            while read_frames.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let b = P2pLink::connect(&url, lo, tick, b_tx).await.unwrap();
            b.set_frame_handler(Some(Arc::new(move |f: &[u8]| {
                let _ = got_b.send(f.to_vec());
            })));
            while !a.peer_seen() || !b.peer_seen() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let sample = vec![7u8; 3000];
            loop {
                assert!(a.write_sample(&sample));
                tokio::select! {
                    Some(_) = at_b.recv() => break,
                    () = tokio::time::sleep(tick) => {}
                }
            }
            hop.drop_next.store(true, Ordering::Release);
            let resent = || hop.resent.load(Ordering::Relaxed) > 0;
            write_for(&a, &sample, Duration::from_secs(3), resent).await;
            assert!(
                hop.dropped.lock().unwrap().is_some(),
                "the hop dropped nothing"
            );
            assert!(resent(), "a packet NACKed in time was not resent");

            let late = 2 * RESEND_AGE;
            let late_ms = u64::try_from(late.as_millis()).unwrap();
            hop.rtcp_delay_ms.store(late_ms, Ordering::Relaxed);
            write_for(&a, &sample, Duration::from_millis(100), || false).await;
            hop.resent.store(0, Ordering::Relaxed);
            let rtcp_before = hop.rtcp.load(Ordering::Relaxed);
            hop.drop_next.store(true, Ordering::Release);
            write_for(&a, &sample, late + Duration::from_secs(1), || false).await;
            assert!(
                hop.rtcp.load(Ordering::Relaxed) > rtcp_before,
                "no RTCP came through the late hop"
            );
            assert!(!resent(), "a packet NACKed {late:?} late was resent");
            a.close().await;
            b.close().await;
            hub.abort();
            server.close().await.unwrap();
        })
        .await;
    }

    /// A lost packet is resent: both ends relay-only through a hop that
    /// drops every tenth VP8 packet on its way to the TURN server, and every
    /// sample `a` writes still arrives whole at `b`. No RTX is negotiated
    /// (the lab codecs), so `b` NACKs on the main SSRC and `a` answers with
    /// the packet itself (the vendored str0m's `ResendPlain`); without
    /// resends a sample that lost one is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_packet_lost_on_the_way_is_resent() {
        crate::testing::bounded_for(Duration::from_secs(20), async {
            let (server, turn) = turn_server().await;
            let at: std::net::SocketAddr = turn.trim_start_matches("turn:").parse().unwrap();
            let (hop, dropped) = lossy_hop(at, 10).await;
            let query = format!(
                "turn=turn%3A{}&turn_user={}&turn_pass={TURN_PASS}&policy=relay",
                hop.to_string().replace(':', "%3A"),
                TURN_USER.replace(':', "%3A"),
            );
            let (url, hub, (read_frames, _)) = relay_hub(0).await;
            let url = format!("{url}?{query}");
            let lo = IpAddr::from([127, 0, 0, 1]);
            let tick = Duration::from_millis(16);
            let (a_tx, _a_rx) = mpsc::channel(4);
            let (b_tx, _b_rx) = mpsc::channel(4);
            let (got_b, mut at_b) = mpsc::unbounded_channel::<Vec<u8>>();
            let a = P2pLink::connect(&url, lo, tick, a_tx).await.unwrap();
            while read_frames.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let b = P2pLink::connect(&url, lo, tick, b_tx).await.unwrap();
            b.set_frame_handler(Some(Arc::new(move |f: &[u8]| {
                let _ = got_b.send(f.to_vec());
            })));
            // Three packets a sample; its first byte numbers it.
            let sample = |i: u8| -> Vec<u8> {
                let mut s: Vec<u8> = (0..3000u32)
                    .map(|j| u8::try_from(j % 251).unwrap())
                    .collect();
                s[0] = i;
                s
            };
            while !a.peer_seen() || !b.peer_seen() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // A sample through first, so the line is up both ways.
            loop {
                assert!(a.write_sample(&sample(0)));
                tokio::select! {
                    Some(_) = at_b.recv() => break,
                    () = tokio::time::sleep(tick) => {}
                }
            }
            while at_b.try_recv().is_ok() {}
            const SAMPLES: u8 = 60;
            for i in 1..=SAMPLES {
                assert!(a.write_sample(&sample(i)));
                tokio::time::sleep(tick).await;
            }
            let mut have = std::collections::BTreeSet::new();
            let until = tokio::time::Instant::now() + Duration::from_secs(3);
            while have.len() < usize::from(SAMPLES) {
                tokio::select! {
                    Some(f) = at_b.recv() => {
                        assert_eq!(f, sample(f[0]), "sample {} arrived changed", f[0]);
                        if f[0] > 0 {
                            have.insert(f[0]);
                        }
                    }
                    () = tokio::time::sleep_until(until) => break,
                }
            }
            let lost: Vec<u8> = (1..=SAMPLES).filter(|i| !have.contains(i)).collect();
            assert!(
                dropped.load(Ordering::Relaxed) > 0,
                "the hop dropped nothing"
            );
            assert!(lost.is_empty(), "samples lost: {lost:?}");
            a.close().await;
            b.close().await;
            hub.abort();
            server.close().await.unwrap();
        })
        .await;
    }

    #[test]
    fn the_video_mid_is_the_first_video_sections() {
        let sdp = "v=0\r\nm=audio 9 UDP 0\r\na=mid:a0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=rtcp-mux\r\na=mid:v1\r\nm=video 9 X 97\r\na=mid:v2\r\n";
        assert_eq!(video_mid(sdp), Some("v1"));
        assert_eq!(video_mid("v=0\r\nm=audio 9 X 0\r\na=mid:0\r\n"), None);
    }
}

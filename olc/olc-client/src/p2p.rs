// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The interop-p2p engine, client side: a room of the interop hub for the
//! signalling and one WebRTC peer connection ([`olc_rtc::peer::Peer`], str0m
//! in RTP mode) with one VP8 video line both ways, the line vp8channel
//! rides. The Go side is the overlay's `internal/engine/interopp2p` on
//! pion; both keep the same contract:
//!
//! - the URL is the hub's, `tcp://host:port/room`, with an optional query
//!   (`turn=`, `turn_user=`, `turn_pass=`, `policy=`) this side does not
//!   read yet: it gathers host candidates only, and the server's side relays
//!   (T2(a) runs the server relay-only through coturn);
//! - signalling is JSON text in the hub's DATA frames: `hello` (broadcast
//!   right after the join, then directed as a reply), `offer`, `answer`,
//!   `bye`; every participant names itself by 16 random hex characters at
//!   each join;
//! - the newcomer offers: a directed hello from X makes the offer to X; an
//!   offer from X is always answered (a server that rejoined);
//! - no trickle: the offer and the answer carry every candidate;
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

use olc_rtc::peer::{Peer, PeerConfig, PeerEvent};
use olc_rtc::str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use olc_rtc::str0m::format::Codec;
use olc_rtc::str0m::media::{Direction, MediaKind, Mid, Pt};
use olc_rtc::str0m::rtp::{RtpPacket, RtpWrite, SeqNo};
use olc_rtc::DtlsVersion;
use olc_vp8channel::channel::Carrier;
use olc_vp8channel::rtp::{Packetizer, Payloader, Vp8Payloader};
use olc_vp8channel::rtp_reader::{TrackReader, MIME_VP8};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::pipe::{
    frame_into, parse_url, read_frame, KIND_DATA, KIND_END, KIND_JOIN, MAX_PAYLOAD, REJOIN_BACKOFF,
    REJOIN_MAX,
};

/// The id's length in hex characters.
pub const ID_LEN: usize = 16;

/// What its channels may hold unacknowledged: the peer has none (media
/// only), so str0m's floor.
const SCTP_BUFFERED: usize = 64 << 10;

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

/// Splits the engine's URL into the hub's address and the room, the query
/// dropped (this side reads none of it).
///
/// # Errors
/// [`P2pError::BadUrl`].
pub fn split_url(raw: &str) -> Result<(String, String), P2pError> {
    let base = raw.split_once('?').map_or(raw, |(b, _)| b);
    parse_url(base).map_err(|_| P2pError::BadUrl)
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

/// What a frame the track reader completes is handed to.
pub type FrameHandler = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// The media both ways on the current peer connection.
struct Media {
    peer: Option<Peer>,
    mid: Option<Mid>,
    pt: Option<Pt>,
    packetizer: Packetizer,
    /// The extended sequence number of the last packet written on this
    /// peer (str0m wants the rollover counter in it).
    ext: Option<u64>,
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
    host_ip: IpAddr,
    frame_ns: i64,
    st: tokio::sync::Mutex<State>,
    media: Mutex<Media>,
    on_frame: Mutex<Option<FrameHandler>>,
    events: mpsc::Sender<P2pEvent>,
    joined: AtomicBool,
    connected: AtomicBool,
    gen: AtomicU64,
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
        let (addr, room) = split_url(url)?;
        olc_rtc::init();
        let link = Arc::new(Self {
            addr,
            room,
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
                pt: None,
                // pion's VP8 payloader starts its picture ids at 0.
                packetizer: Packetizer::random(Payloader::Vp8(Vp8Payloader::with_picture_id(0))),
                ext: None,
            }),
            on_frame: Mutex::new(None),
            events,
            joined: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            gen: AtomicU64::new(0),
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
        }
    }

    /// A fresh peer connection for `remote`, its host candidate added and
    /// its driver's events watched; the old one closed.
    fn start_peer(self: &Arc<Self>, st: &mut State, remote: &str) -> Option<Peer> {
        let (peer, rx) = match Peer::start(&self.peer_config()) {
            Ok(p) => p,
            Err(e) => {
                crate::info!("interop-p2p: peer connection: {e}");
                return None;
            }
        };
        if let Err(e) = peer.add_host_candidate() {
            crate::info!("interop-p2p: host candidate: {e}");
            peer.close();
            return None;
        }
        let gen = self.gen.fetch_add(1, Ordering::AcqRel) + 1;
        st.remote = Some((remote.to_owned(), gen));
        self.connected.store(false, Ordering::Release);
        let old = {
            let mut m = locked(&self.media);
            m.mid = None;
            m.pt = None;
            m.ext = None;
            m.peer.replace(peer.clone())
        };
        if let Some(old) = old {
            old.close();
        }
        tokio::spawn(self.clone().watch(rx, gen));
        Some(peer)
    }

    async fn offer(self: &Arc<Self>, me: &str, remote: &str) {
        let mut st = self.st.lock().await;
        let Some(peer) = self.start_peer(&mut st, remote) else {
            return;
        };
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
        let mut st = self.st.lock().await;
        st.pending = None;
        let Some(peer) = self.start_peer(&mut st, remote) else {
            return;
        };
        drop(st);
        let answer = match peer.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer)) {
            Ok(a) => a,
            Err(e) => {
                crate::info!("interop-p2p: offer from {remote}: {e}");
                return;
            }
        };
        locked(&self.media).mid = Some(mid);
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

    /// The line is negotiated: the VP8 payload type to write with, and the
    /// remote's RTP into the track reader.
    fn media_ready(self: &Arc<Self>, peer: &Peer) {
        let pt = peer.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Vp8)
                .map(|p| p.pt())
        });
        locked(&self.media).pt = pt;
        let Some(pt) = pt else {
            crate::info!("interop-p2p: no VP8 on the line");
            return;
        };
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
                    if self.gen.load(Ordering::Acquire) == gen {
                        crate::info!("interop-p2p: peer connection up");
                        self.connected.store(true, Ordering::Release);
                    }
                }
                PeerEvent::Closed(why) => {
                    if self.gen.load(Ordering::Acquire) == gen && !self.st.lock().await.closed {
                        crate::info!("interop-p2p: peer connection ended: {why}");
                        self.rejoin().await;
                    }
                    return;
                }
                _ => {}
            }
        }
    }

    /// Closes the peer connection (a `bye`).
    async fn drop_peer(&self) {
        self.st.lock().await.remote = None;
        self.gen.fetch_add(1, Ordering::AcqRel);
        self.connected.store(false, Ordering::Release);
        let old = {
            let mut m = locked(&self.media);
            m.mid = None;
            m.pt = None;
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
        let (Some(peer), Some(mid), Some(pt)) = (m.peer.clone(), m.mid, m.pt) else {
            return true;
        };
        if !self.connected.load(Ordering::Acquire) {
            return true;
        }
        let packets = m.packetizer.packetize(sample, self.frame_ns);
        let mut ext = m.ext;
        let wallclock = Instant::now();
        peer.with_rtc(|rtc| {
            let mut api = rtc.direct_api();
            let Some(tx) = api.stream_tx_by_mid(mid, None) else {
                return;
            };
            for p in packets {
                let seq = match ext {
                    None => u64::from(p.seq),
                    Some(e) => e + 1,
                };
                ext = Some(seq);
                tx.write_rtp(
                    RtpWrite::new(pt, SeqNo::from(seq), p.timestamp, wallclock, p.payload)
                        .marker(p.marker),
                );
                self.rtp_out.fetch_add(1, Ordering::Relaxed);
            }
        });
        m.ext = ext;
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
    fn the_url_drops_its_query_and_keeps_the_room() {
        assert_eq!(
            split_url("tcp://127.0.0.1:9/gate-x?turn=turn%3A127.0.0.1%3A3478&policy=relay")
                .unwrap(),
            ("127.0.0.1:9".to_owned(), "gate-x".to_owned())
        );
        assert_eq!(split_url("tcp://127.0.0.1:9/gate-x").unwrap().1, "gate-x");
        assert!(split_url("ws://x/y").is_err());
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
    fn an_id_is_sixteen_hex() {
        let id = new_id();
        assert_eq!(id.len(), ID_LEN);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    /// A hub room that relays DATA frames to the other members, as the
    /// overlay's interoppipe hub does (no PEERS, no END).
    async fn relay_hub() -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncReadExt;
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let members: Arc<tokio::sync::Mutex<Vec<(usize, OwnedWriteHalf)>>> = Arc::default();
        let task = tokio::spawn(async move {
            let mut next = 0usize;
            loop {
                let Ok((conn, _)) = ln.accept().await else {
                    return;
                };
                let (mut read, write) = conn.into_split();
                let id = next;
                next += 1;
                members.lock().await.push((id, write));
                let members = members.clone();
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
                        let mut frame = hdr.to_vec();
                        frame.extend_from_slice(&body);
                        for (other, w) in members.lock().await.iter_mut() {
                            if *other != id {
                                let _ = w.write_all(&frame).await;
                            }
                        }
                    }
                });
            }
        });
        (format!("tcp://{addr}/room?turn=ignored&policy=relay"), task)
    }

    /// Two participants: the second is the newcomer and offers, the first
    /// answers; a sample written on either side arrives whole on the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_participants_meet_and_move_samples_both_ways() {
        crate::testing::bounded_for(Duration::from_secs(20), async {
            let (url, hub) = relay_hub().await;
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

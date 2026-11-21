// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The session (`internal/engine/jitsi/jitsi.go`, `negotiate.go`,
//! `keepalive.go`): joins the room, waits for the focus's offer, answers it
//! with a peer connection that has an audio line it only receives, a video
//! line that carries one frame a second so the bridge keeps the endpoint
//! alive, and the data channel the bridge relays between endpoints; opens the
//! bridge on the hello exchange and hands the peer's data up.
//!
//! The answer is str0m's, completed with what pion writes and str0m does not
//! (plan D5): the keepalive source's `mslabel` and `label`, the track ids Go
//! gives it, the audio line's direction, and the candidates.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_net::reconnect::{Reconnector, Rejoin, Request};
use olc_rtc::media::{RtpOut, SendLine};
use olc_rtc::peer::{IceMode, Peer, PeerConfig, PeerEvent};
use olc_rtc::str0m::change::SdpOffer;
use olc_rtc::str0m::channel::{ChannelConfig, ChannelId, Reliability};
use olc_rtc::str0m::format::Codec;
use olc_rtc::str0m::media::Mid;
use olc_rtc::str0m::Candidate;
use olc_rtc::DtlsVersion;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::bridge::{Bridge, BridgeConfig, BridgeError, OnData, Wire, WireError};
use crate::epoch::PeerIdError;
use crate::frame::{Message, CLIENT_HELLO, SERVER_HELLO_CLASS};
use crate::ice::turn_servers;
use crate::jingle::build::{accept_body, media_name_for_mid, transport_info_content};
use crate::jingle::parse::{candidate_line, parse_transport_info, Parsed};
use crate::jingle::sdp::stack_view;
use crate::join::{join_muc, JoinConfig, JoinError, Joined};
use crate::nick::xmpp_domain;
use crate::relaywin::Timing;
use crate::stanza;
use crate::xmpp::conn::{BoxFut, Conn, Incoming};

/// The data channel's label and protocol (`J/j.go`).
pub const CHANNEL_LABEL: &str = "JVB data channel";
/// The data channel's protocol.
pub const CHANNEL_PROTOCOL: &str = "http://jitsi.org/protocols/colibri";
/// How long the bridge has to open once the answer is sent
/// (`bridgeOpenTimeout`).
pub const BRIDGE_OPEN: Duration = Duration::from_secs(30);
/// How long the answer waits for the peer's gathering (`peer.go`).
pub const GATHER_WAIT: Duration = Duration::from_secs(3);
/// The XMPP ping's period and its wait (`xmppKeepaliveInterval/Timeout`).
pub const XMPP_PING: Duration = Duration::from_secs(25);
/// How long a ping's answer is waited for.
pub const XMPP_PING_WAIT: Duration = Duration::from_secs(15);
/// The keepalive video's period.
pub const RTP_KEEPALIVE: Duration = Duration::from_secs(1);
/// What the bridge may be told before its hello is answered, at most.
pub const HELLO_BUFFER: usize = 64;
/// What the data channel may hold unacknowledged: the backlog gate's mark and
/// one message above it.
pub const SCTP_BUFFERED: usize = crate::bridge::BACKLOG_HIGH_WATER + 16 * 1024;

/// A minimal valid VP8 keyframe: it refreshes the bridge's
/// `lastRtpReceived` for the endpoint (`vp8Keepalive`).
pub const VP8_KEEPALIVE: [u8; 20] = [
    0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00, 0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
    0x99, 0x84, 0x88, 0xfc,
];

/// The waits of a rejoin (`reconnect.go`).
#[derive(Debug, Clone, Copy)]
pub struct RejoinTimes {
    /// The join (`reconnectJoinTimeout`).
    pub join: Duration,
    /// The offer after a rejoin (`reinitiateTimeout`).
    pub reinitiate: Duration,
    /// The offer after a full reconnect (`fullReconnectTimeout`).
    pub full: Duration,
}

impl Default for RejoinTimes {
    fn default() -> Self {
        Self {
            join: Duration::from_secs(30),
            reinitiate: Duration::from_secs(30),
            full: Duration::from_secs(60),
        }
    }
}

/// Failed attempts in a row that end the session (`maxReconnects`).
pub const MAX_RECONNECTS: u32 = 5;

/// What a session needs.
pub struct SessionConfig {
    /// The room and how it is joined.
    pub join: JoinConfig,
    /// The address the peer's host candidate names.
    pub host_ip: IpAddr,
    /// Only relayed candidates.
    pub relay_only: bool,
    /// Only frames addressed to this session, from the confirmed peer.
    pub require_targeted_peer: bool,
    /// Data from the peer.
    pub on_data: OnData,
    /// Data from the peer, for a receiver that waits.
    pub on_data_async: Option<crate::bridge::OnDataAsync>,
    /// The session ended for good, with why (the supervisor's limit, or a
    /// request its policy refused).
    pub on_ended: Arc<dyn Fn(&str) + Send + Sync>,
    /// A rejoin finished: the layers above start their handshake again
    /// (`NotifyReconnect`).
    pub on_reconnected: Arc<dyn Fn() + Send + Sync>,
    /// How long a rejoin's steps may take.
    pub times: RejoinTimes,
    /// The relay window's timers.
    pub timing: Timing,
}

/// The ids of the keepalive track: stream `olcrtc-ka-<8>`, track
/// `jitsi-ka-<8>` (`newKeepaliveTrack`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepaliveIds {
    /// The stream.
    pub stream: String,
    /// The track.
    pub track: String,
}

impl KeepaliveIds {
    /// Fresh ids: six random bytes each, URL-safe base64.
    #[must_use]
    pub fn random() -> Self {
        use base64::Engine as _;
        let suffix = || {
            let b: [u8; 6] = rand::random();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        };
        Self {
            stream: format!("olcrtc-ka-{}", suffix()),
            track: format!("jitsi-ka-{}", suffix()),
        }
    }
}

/// str0m's answer as the focus is given it (plan D5): the audio line is
/// receive-only and names no source; the video line's source is named by our
/// ids, with the `mslabel` and `label` pion writes; `candidates` (SDP lines
/// without `a=`) are in the first section.
#[must_use]
pub fn complete_answer(answer: &str, ids: &KeepaliveIds, candidates: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut kind = "";
    let mut first_section = true;
    let mut first_end: Option<usize> = None;
    for line in answer.split("\r\n") {
        if let Some(m) = line.strip_prefix("m=") {
            if !first_section && first_end.is_none() {
                first_end = Some(out.len());
            }
            first_section = false;
            kind = m.split(' ').next().unwrap_or("");
            out.push(line.to_owned());
            continue;
        }
        match kind {
            "audio" => {
                if line.starts_with("a=ssrc") || line.starts_with("a=msid:") {
                    continue;
                }
                if line == "a=sendrecv" {
                    out.push("a=recvonly".to_owned());
                    continue;
                }
            }
            "video" => {
                if line.starts_with("a=msid:") {
                    out.push(format!("a=msid:{} {}", ids.stream, ids.track));
                    continue;
                }
                if let Some(rest) = line.strip_prefix("a=ssrc:") {
                    if let Some((ssrc, attr)) = rest.split_once(' ') {
                        if attr.starts_with("msid:") {
                            out.push(format!("a=ssrc:{ssrc} msid:{} {}", ids.stream, ids.track));
                            out.push(format!("a=ssrc:{ssrc} mslabel:{}", ids.stream));
                            out.push(format!("a=ssrc:{ssrc} label:{}", ids.track));
                            continue;
                        }
                        if attr.starts_with("mslabel:") || attr.starts_with("label:") {
                            continue;
                        }
                    }
                }
            }
            _ => {}
        }
        out.push(line.to_owned());
    }
    // The candidates close the first media section.
    if !candidates.is_empty() {
        let at = first_end.unwrap_or(out.len());
        // Before a section's trailing empty line, when it is the last.
        let at = if first_end.is_none() && out.last().is_some_and(String::is_empty) {
            at - 1
        } else {
            at
        };
        for (i, c) in candidates.iter().enumerate() {
            out.insert(at + i, format!("a={c}"));
        }
    }
    out.join("\r\n")
}

/// The `mid` of the first media section of `kind` in `sdp`.
fn mid_of(sdp: &str, kind: &str) -> Option<String> {
    let mut in_kind = false;
    for line in sdp.split("\r\n") {
        if let Some(m) = line.strip_prefix("m=") {
            in_kind = m.split(' ').next() == Some(kind);
        } else if in_kind {
            if let Some(mid) = line.strip_prefix("a=mid:") {
                return Some(mid.trim().to_owned());
            }
        }
    }
    None
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The data channel as the bridge's wire.
struct PeerWire {
    peer: Peer,
    channel: ChannelId,
}

impl Wire for PeerWire {
    fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), WireError>> {
        Box::pin(async move {
            loop {
                match self.peer.write(self.channel, false, text.as_bytes()) {
                    Ok(true) => return Ok(()),
                    Ok(false) => self
                        .peer
                        .wait_buffered(self.channel, SCTP_BUFFERED / 2)
                        .await
                        .map_err(|e| WireError(e.to_string()))?,
                    Err(e) => return Err(WireError(e.to_string())),
                }
            }
        })
    }

    fn try_send(&self, text: &str) -> Result<(), WireError> {
        match self.peer.write(self.channel, false, text.as_bytes()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(WireError("the channel's buffer is full".into())),
            Err(e) => Err(WireError(e.to_string())),
        }
    }

    fn backlog(&self) -> usize {
        self.peer.buffered_amount(self.channel).unwrap_or(0)
    }
}

struct Live {
    conn: Option<Conn>,
    peer: Option<Peer>,
    /// What belongs to the connection: the ping, the trickle, the wait.
    conn_tasks: Vec<JoinHandle<()>>,
    /// What belongs to the peer connection.
    peer_tasks: Vec<JoinHandle<()>>,
    /// What lives as long as the session: the supervisor.
    fixed_tasks: Vec<JoinHandle<()>>,
}

struct Sh {
    cfg: SessionConfig,
    bridge: Bridge,
    live: Mutex<Live>,
    closed: watch::Sender<bool>,
    closing: AtomicBool,
    reconnecting: Arc<AtomicBool>,
    reconnector: Arc<Reconnector>,
}

/// A Jitsi session: the client end of a tunnel's link.
#[derive(Clone)]
pub struct Session {
    sh: Arc<Sh>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
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

impl Session {
    /// Joins the room and waits, in the background, for the focus's offer:
    /// it comes once another participant is there (`Connect`).
    ///
    /// # Errors
    /// The join's.
    pub async fn connect(cfg: SessionConfig) -> Result<Self, JoinError> {
        olc_rtc::init();
        let joined = join_muc(&cfg.join).await?;
        let reconnector = Arc::new(
            Reconnector::new(MAX_RECONNECTS, "jitsi reconnect limit reached")
                .with_count_failures(true),
        );
        let reconnecting = Arc::new(AtomicBool::new(false));
        // `requestReconnect`: not while one runs; a refusal ends the session.
        let on_reconnect: crate::bridge::OnReconnect = {
            let (rc, busy, ended) = (
                reconnector.clone(),
                reconnecting.clone(),
                cfg.on_ended.clone(),
            );
            Arc::new(move |why: &str| {
                if busy.load(Ordering::Acquire) {
                    return false;
                }
                match rc.request(false, false) {
                    Request::Rejected => {
                        ended(why);
                        false
                    }
                    Request::Queued => {
                        olc_net::info!("jitsi reconnect requested: {why}");
                        true
                    }
                    Request::Coalesced => false,
                }
            })
        };
        let bridge = Bridge::new(BridgeConfig {
            on_data: cfg.on_data.clone(),
            on_data_async: cfg.on_data_async.clone(),
            on_reconnect,
            require_targeted_peer: cfg.require_targeted_peer,
            timing: cfg.timing,
        });
        let (closed, _) = watch::channel(false);
        let sh = Arc::new(Sh {
            cfg,
            bridge,
            live: Mutex::new(Live {
                conn: None,
                peer: None,
                conn_tasks: Vec::new(),
                peer_tasks: Vec::new(),
                fixed_tasks: Vec::new(),
            }),
            closed,
            closing: AtomicBool::new(false),
            reconnecting,
            reconnector,
        });
        let (conn, ice) = install_conn(&sh, joined);
        let wait = tokio::spawn(wait_for_offer(sh.clone(), conn, ice));
        let watch = tokio::spawn(watch_reconnects(sh.clone()));
        {
            let mut live = lock(&sh.live);
            live.conn_tasks.push(wait);
            live.fixed_tasks.push(watch);
        }
        Ok(Self { sh })
    }

    /// Asks for a rejoin, as the layers above do when their path is dead
    /// (`Reconnect`).
    pub fn reconnect(&self, reason: &str) {
        self.sh.bridge.ask_reconnect(reason);
    }

    /// The bridge, for the layers above and the tests.
    #[must_use]
    pub fn bridge(&self) -> &Bridge {
        &self.sh.bridge
    }

    /// Sends `data` to the peer (`Send`).
    ///
    /// # Errors
    /// [`BridgeError`].
    pub async fn send(&self, data: &[u8]) -> Result<(), BridgeError> {
        self.sh.bridge.send(Some(data)).await
    }

    /// The local epoch as eight hex digits (`LocalPeerID`).
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        self.sh.bridge.local_peer_id()
    }

    /// Binds the session to an authenticated peer (`ConfirmPeer`).
    ///
    /// # Errors
    /// [`PeerIdError`].
    pub fn confirm_peer(&self, id: &str) -> Result<(), PeerIdError> {
        self.sh.bridge.confirm_peer(id)
    }

    /// Forgets the peer (`ResetPeer`).
    pub fn reset_peer(&self) {
        self.sh.bridge.reset_peer();
    }

    /// A peer's epoch is latched, or others are in the room (`PeerSeen`).
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        let n = lock(&self.sh.live)
            .conn
            .as_ref()
            .map_or(0, |c| c.occupants().len());
        self.sh.bridge.peer_seen(n)
    }

    /// The bridge is open: a send is queued (`CanSend`).
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.sh.bridge.is_ready()
    }

    /// Waits until a peer epoch is confirmed (`WaitForPeer`).
    pub async fn wait_for_peer(&self) -> bool {
        self.sh.bridge.wait_for_peer().await
    }

    /// Closes the session in Jitsi's order: the peer connection, the room
    /// (its leave confirmed for up to 5 s), the connection, then the tasks.
    pub async fn close(&self) {
        if self.sh.closing.swap(true, Ordering::AcqRel) {
            return;
        }
        let (conn, peer) = {
            let mut live = lock(&self.sh.live);
            (live.conn.take(), live.peer.take())
        };
        if let Some(p) = &peer {
            p.close();
        }
        self.sh.bridge.close();
        if let Some(c) = &conn {
            if c.leave_muc_wait(Duration::from_secs(5)).await.is_err() {
                let _ = c.send(&stanza::leave(&c.room_jid())).await;
            }
            c.close().await;
        }
        self.sh.closed.send_replace(true);
        let tasks = {
            let mut live = lock(&self.sh.live);
            let mut all = std::mem::take(&mut live.conn_tasks);
            all.append(&mut live.peer_tasks);
            all.append(&mut live.fixed_tasks);
            all
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            for t in tasks {
                t.abort();
                let _ = t.await;
            }
        })
        .await;
    }
}

/// Takes a joined room: the ping and the trickle start; the offer is the
/// caller's to wait for.
fn install_conn(sh: &Arc<Sh>, joined: Joined) -> (Conn, Vec<crate::ice::IceServer>) {
    let Joined {
        conn,
        incoming,
        ice,
        ..
    } = joined;
    let tasks = [
        tokio::spawn(ping_loop(sh.clone(), conn.clone())),
        tokio::spawn(trickle_in(sh.clone(), incoming)),
    ];
    let mut live = lock(&sh.live);
    live.conn = Some(conn.clone());
    live.conn_tasks.extend(tasks);
    drop(live);
    if sh.closing.load(Ordering::Acquire) {
        // A join that finished while the session was closing: nothing will
        // close it later.
        let c = conn.clone();
        tokio::spawn(async move { c.close().await });
    }
    (conn, ice)
}

/// Why a rejoin attempt did not end in a session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RejoinError {
    /// The session was closed meanwhile (`ErrSessionClosed`).
    #[error("jitsi: session closed")]
    Closed,
    /// The room was joined and nobody else is in it: not a failure
    /// (`errNoPeer`); the session waits for the offer.
    #[error("no peer in room")]
    NoPeer,
    /// The attempt failed.
    #[error("{0}")]
    Failed(String),
}

/// Leaves the room (its echo awaited for up to 5 s) and closes the
/// connection, as `Close` does.
async fn leave_and_close(conn: Conn) {
    if conn.leave_muc_wait(Duration::from_secs(5)).await.is_err() {
        let _ = conn.send(&stanza::leave(&conn.room_jid())).await;
    }
    conn.close().await;
}

/// What a rejoin tears down before it joins again: the peer connection, the
/// connection and what runs for them.
async fn teardown(sh: &Arc<Sh>) {
    let (conn, peer, tasks) = {
        let mut live = lock(&sh.live);
        let mut tasks = std::mem::take(&mut live.peer_tasks);
        tasks.append(&mut live.conn_tasks);
        (live.conn.take(), live.peer.take(), tasks)
    };
    if let Some(p) = peer {
        p.close();
    }
    for t in tasks {
        t.abort();
    }
    if let Some(c) = conn {
        leave_and_close(c).await;
    }
}

fn join_settings(sh: &Sh) -> JoinConfig {
    let mut j = sh.cfg.join.clone();
    j.budget = sh.cfg.times.join;
    j
}

/// One attempt (`reconnect`): a new epoch, the room joined again and the
/// offer waited for; when any of that fails, the full reconnect.
async fn rejoin(sh: &Arc<Sh>) -> Result<(), RejoinError> {
    if sh.closing.load(Ordering::Acquire) {
        return Err(RejoinError::Closed);
    }
    if sh.reconnecting.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let r = rejoin_steps(sh).await;
    sh.reconnecting.store(false, Ordering::Release);
    r
}

async fn rejoin_steps(sh: &Arc<Sh>) -> Result<(), RejoinError> {
    sh.bridge.reset_for_reconnect();
    teardown(sh).await;
    olc_net::info!("jitsi: rejoin (non-blocking) ...");
    let joined = match join_muc(&join_settings(sh)).await {
        Ok(j) => j,
        Err(e) => {
            olc_net::info!("jitsi: rejoin failed: {e} - full reconnect");
            return full_reconnect(sh).await;
        }
    };
    let (conn, ice) = install_conn(sh, joined);
    let parsed = match conn.wait_session_initiate(sh.cfg.times.reinitiate).await {
        Ok(p) => p,
        Err(e) => {
            olc_net::info!("jitsi: wait reinitiate failed: {e} - full reconnect");
            return full_reconnect(sh).await;
        }
    };
    if let Err(e) = complete_setup(sh, &conn, &parsed, &ice).await {
        olc_net::info!("jitsi: negotiate after reinitiate failed: {e} - full reconnect");
        return full_reconnect(sh).await;
    }
    finish_reconnect(sh, "reinitiate");
    Ok(())
}

/// `reconnectFull`: the session is dropped and made again; alone in the room
/// it parks and says so with [`RejoinError::NoPeer`].
async fn full_reconnect(sh: &Arc<Sh>) -> Result<(), RejoinError> {
    teardown(sh).await;
    sh.bridge.reset_for_reconnect();
    olc_net::info!("jitsi: full reconnect ...");
    let joined = join_muc(&join_settings(sh))
        .await
        .map_err(|e| RejoinError::Failed(e.to_string()))?;
    if sh.closing.load(Ordering::Acquire) {
        let (c, _) = install_conn(sh, joined);
        c.close().await;
        return Err(RejoinError::Closed);
    }
    let (conn, ice) = install_conn(sh, joined);
    match conn.wait_session_initiate(sh.cfg.times.full).await {
        Err(_) => {
            // Parked: the offer, when it comes, is set up in the background.
            let t = tokio::spawn(wait_for_offer(sh.clone(), conn, ice));
            lock(&sh.live).conn_tasks.push(t);
            Err(RejoinError::NoPeer)
        }
        Ok(parsed) => {
            if let Err(e) = complete_setup(sh, &conn, &parsed, &ice).await {
                teardown(sh).await;
                return Err(RejoinError::Failed(format!(
                    "jitsi setup after full reconnect: {e}"
                )));
            }
            finish_reconnect(sh, "full");
            Ok(())
        }
    }
}

/// `finishReconnect`: the layers above are told, the epoch is announced.
fn finish_reconnect(sh: &Arc<Sh>, mode: &str) {
    sh.bridge.note_reconnect();
    let b = sh.bridge.clone();
    tokio::spawn(async move {
        let _ = b.send(None).await;
    });
    (sh.cfg.on_reconnected)();
    olc_net::info!("jitsi: reconnected ({mode})");
}

/// The supervisor's session: its attempts, and what ends it.
struct Rejoiner(Arc<Sh>);

impl Rejoin for Rejoiner {
    type Error = RejoinError;

    async fn rejoin(&self) -> Result<(), RejoinError> {
        rejoin(&self.0).await
    }

    fn failed(&self, err: &RejoinError) {
        olc_net::info!("jitsi reconnect failed: {err}");
    }

    fn limit_reached(&self, reason: &str) {
        self.0.bridge.set_not_ready();
        (self.0.cfg.on_ended)(reason);
    }

    fn is_non_failure(&self, err: &RejoinError) -> bool {
        *err == RejoinError::NoPeer
    }
}

async fn watch_reconnects(sh: Arc<Sh>) {
    let mut closed = sh.closed.subscribe();
    let rejoiner = Rejoiner(sh.clone());
    let rc = sh.reconnector.clone();
    rc.watch(&rejoiner, wait_closed(&mut closed)).await;
}

/// `waitForJingle`, then `completeJingleSetup`.
async fn wait_for_offer(sh: Arc<Sh>, conn: Conn, ice: Vec<crate::ice::IceServer>) {
    let mut closed = sh.closed.subscribe();
    let parsed = tokio::select! {
        () = wait_closed(&mut closed) => return,
        p = conn.wait_session_initiate(Duration::from_secs(365 * 24 * 3600)) => match p {
            Ok(p) => p,
            Err(e) => {
                if !sh.closing.load(Ordering::Acquire) {
                    olc_net::info!("jitsi: wait jingle failed: {e}");
                    sh.bridge.ask_reconnect("wait jingle failed");
                }
                return;
            }
        },
    };
    if let Err(e) = complete_setup(&sh, &conn, &parsed, &ice).await {
        if !sh.closing.load(Ordering::Acquire) {
            olc_net::info!("jitsi: jingle setup failed: {e}");
            sh.bridge.ask_reconnect("jingle setup failed");
        }
    }
}

async fn complete_setup(
    sh: &Arc<Sh>,
    conn: &Conn,
    parsed: &Parsed,
    ice: &[crate::ice::IceServer],
) -> Result<(), String> {
    olc_net::info!("jitsi: session-initiate received");
    let pcfg = PeerConfig {
        name: "jitsi",
        crypto: olc_rtc::crypto(),
        dtls_version: DtlsVersion::Dtls12,
        host_ip: sh.cfg.host_ip,
        sctp_max_buffered: SCTP_BUFFERED,
        turn: turn_servers(ice),
        relay_only: sh.cfg.relay_only,
        ice_mode: IceMode::Udp,
    };
    let expected_relays = pcfg.turn.len().min(olc_rtc::turn::MAX_ALLOCATIONS);
    let (peer, mut events) = Peer::start(&pcfg).map_err(|e| format!("new pc: {e}"))?;
    let offer = SdpOffer::from_sdp_string(&stack_view(&parsed.sdp))
        .map_err(|e| format!("set remote desc: {e}"))?;
    let answer = peer
        .with_rtc(|rtc| rtc.sdp_api().accept_offer(offer))
        .map_err(|e| format!("set remote desc: {e}"))?
        .to_sdp_string();
    peer.remote_described(&parsed.sdp);
    for c in &parsed.candidates {
        if let Some(line) = candidate_line(c) {
            if let Ok(c) = Candidate::from_sdp_string(&line) {
                peer.add_remote_candidate(c);
            }
        }
    }
    let channel = peer.with_rtc(|rtc| {
        let mut api = rtc.sdp_api();
        let id = api.add_channel_with_config(ChannelConfig {
            label: CHANNEL_LABEL.into(),
            ordered: true,
            reliability: Reliability::Reliable,
            negotiated: None,
            protocol: CHANNEL_PROTOCOL.into(),
        });
        let _ = api.apply();
        id
    });
    // Gathering: the host candidate now, the relayed ones as their
    // allocations come up, for at most three seconds.
    let mut candidates: Vec<String> = Vec::new();
    if let Some(host) = peer.gather().map_err(|e| format!("gather: {e}"))? {
        candidates.push(host);
    }
    let mut early: Vec<PeerEvent> = Vec::new();
    if expected_relays > 0 {
        let deadline = tokio::time::Instant::now() + GATHER_WAIT;
        let mut relays = 0;
        while relays < expected_relays {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Some(PeerEvent::LocalCandidate(c))) => {
                    candidates.push(c);
                    relays += 1;
                }
                Ok(Some(other)) => early.push(other),
                Ok(None) | Err(_) => break,
            }
        }
    }
    let ids = KeepaliveIds::random();
    let completed = complete_answer(&answer, &ids, &candidates);
    let body = accept_body(&completed);
    let to = format!("{}/focus", conn.room_bare_jid());
    conn.send(&stanza::session_accept(
        &to,
        &parsed.sid,
        &parsed.initiator,
        conn.jid(),
        &body,
    ))
    .await
    .map_err(|e| format!("session-accept: {e}"))?;
    let video = mid_of(&completed, "video");
    let pt = peer.with_rtc(|rtc| {
        rtc.codec_config()
            .find(|p| p.spec().codec == Codec::Vp8)
            .map(|p| p.pt())
    });
    {
        let mut live = lock(&sh.live);
        if let Some(old) = live.peer.replace(peer.clone()) {
            old.close();
        }
    }
    let (opened_tx, opened_rx) = oneshot::channel();
    let task = tokio::spawn(peer_task(
        sh.clone(),
        conn.clone(),
        peer.clone(),
        channel,
        events,
        early,
        parsed.clone(),
        opened_tx,
    ));
    let keepalive = match (video, pt) {
        (Some(mid), Some(pt)) => Some(tokio::spawn(rtp_keepalive(
            sh.clone(),
            peer.clone(),
            SendLine::new(Mid::from(mid.as_str()), None, pt),
        ))),
        _ => None,
    };
    {
        let mut live = lock(&sh.live);
        live.peer_tasks.push(task);
        live.peer_tasks.extend(keepalive);
    }
    match tokio::time::timeout(BRIDGE_OPEN, opened_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(format!("open bridge sctp: {e}")),
        Ok(Err(_)) => return Err("open bridge sctp: the peer ended".into()),
        Err(_) => return Err("open bridge sctp: context deadline exceeded".into()),
    }
    olc_net::info!("jitsi: bridge open sctp");
    sh.bridge.start_announce();
    Ok(())
}

/// The peer's events: the channel's open and the hello, then the bridge's
/// messages; the end of the connection.
#[allow(clippy::too_many_arguments)]
async fn peer_task(
    sh: Arc<Sh>,
    conn: Conn,
    peer: Peer,
    channel: ChannelId,
    mut events: mpsc::Receiver<PeerEvent>,
    early: Vec<PeerEvent>,
    parsed: Parsed,
    opened: oneshot::Sender<Result<(), String>>,
) {
    let mut opened = Some(opened);
    let mut gen: Option<u64> = None;
    let mut waiting: Vec<Message> = Vec::new();
    let mut backlog = early.into_iter();
    let trickle_to = format!("{}/focus", conn.room_bare_jid());
    loop {
        let ev = match backlog.next() {
            Some(e) => e,
            None => match events.recv().await {
                Some(e) => e,
                None => break,
            },
        };
        match ev {
            PeerEvent::ChannelOpen(id, label) if id == channel && label == CHANNEL_LABEL => {
                if let Err(e) = peer.write(channel, false, CLIENT_HELLO.as_bytes()) {
                    if let Some(o) = opened.take() {
                        let _ = o.send(Err(format!("client hello: {e}")));
                    }
                }
            }
            PeerEvent::Data(inb) if inb.channel == channel => {
                let Ok(text) = std::str::from_utf8(&inb.data) else {
                    continue;
                };
                let Some(msg) = Message::parse(text) else {
                    continue;
                };
                match gen {
                    Some(g) => {
                        sh.bridge.deliver_async(g, Some(&msg)).await;
                    }
                    None if msg.class == SERVER_HELLO_CLASS => {
                        let wire = Arc::new(PeerWire {
                            peer: peer.clone(),
                            channel,
                        });
                        sh.bridge.set_wire(Some(wire));
                        let g = sh.bridge.mark_ready();
                        gen = Some(g);
                        if let Some(o) = opened.take() {
                            let _ = o.send(Ok(()));
                        }
                        for m in waiting.drain(..) {
                            sh.bridge.deliver_async(g, Some(&m)).await;
                        }
                    }
                    None => {
                        if waiting.len() < HELLO_BUFFER {
                            waiting.push(msg);
                        }
                    }
                }
            }
            PeerEvent::ChannelClose(id) if id == channel => {
                if let Some(g) = gen {
                    sh.bridge.deliver_async(g, None).await;
                }
            }
            PeerEvent::LocalCandidate(line) => {
                let inner = transport_info_content(media_name_for_mid("0"), &line);
                let iq = stanza::jingle(
                    &trickle_to,
                    &conn.next_id(),
                    "transport-info",
                    &parsed.sid,
                    &parsed.initiator,
                    conn.jid(),
                    &inner,
                );
                let _ = conn.send(&iq).await;
            }
            PeerEvent::Failed(why) => {
                olc_net::debug!("jitsi pc state: failed ({why})");
                if !sh.closing.load(Ordering::Acquire) {
                    sh.bridge.ask_reconnect("jitsi peer connection failed");
                }
            }
            PeerEvent::Closed(why) => {
                if let Some(o) = opened.take() {
                    let _ = o.send(Err(why));
                }
                if let Some(g) = gen {
                    sh.bridge.deliver_async(g, None).await;
                }
                return;
            }
            _ => {}
        }
    }
    if let Some(o) = opened.take() {
        let _ = o.send(Err("the peer's events ended".into()));
    }
}

/// One VP8 frame a second on the offered video line (`rtpKeepalive`).
async fn rtp_keepalive(sh: Arc<Sh>, peer: Peer, mut line: SendLine) {
    let mut closed = sh.closed.subscribe();
    let mut seq: u16 = rand::random();
    let mut ts: u32 = rand::random();
    let mut payload = vec![0x10u8];
    payload.extend_from_slice(&VP8_KEEPALIVE);
    loop {
        tokio::select! {
            () = wait_closed(&mut closed) => return,
            () = tokio::time::sleep(RTP_KEEPALIVE) => {}
        }
        if peer.is_ended() {
            return;
        }
        let n = line.write(
            &peer,
            std::time::Instant::now(),
            vec![RtpOut {
                seq,
                timestamp: ts,
                marker: true,
                payload: payload.clone(),
            }],
        );
        if n == Some(1) {
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(90_000);
        }
    }
}

/// `xmppKeepalive`: an XMPP ping every 25 s; each distinct failure asks for a
/// rejoin once.
async fn ping_loop(sh: Arc<Sh>, conn: Conn) {
    let mut closed = sh.closed.subscribe();
    let mut last = String::new();
    loop {
        tokio::select! {
            () = wait_closed(&mut closed) => return,
            () = tokio::time::sleep(XMPP_PING) => {}
        }
        let id = conn.next_id();
        let to = xmpp_domain(conn.jid(), &conn.config().host).to_owned();
        match conn
            .send_iq_wait(&stanza::ping(&to, &id), &id, XMPP_PING_WAIT)
            .await
        {
            Ok(_) => last.clear(),
            Err(e) => {
                if sh.closing.load(Ordering::Acquire) {
                    return;
                }
                olc_net::debug!("jitsi: xmpp keepalive: {e}");
                let reason = e.to_string();
                if reason != last {
                    sh.bridge
                        .ask_reconnect(&format!("xmpp keepalive: {reason}"));
                    last = reason;
                }
            }
        }
    }
}

/// `trickleDrainLoop`: the focus's candidates go to the peer, when there is
/// one (decision D4: none are kept).
async fn trickle_in(sh: Arc<Sh>, mut incoming: mpsc::Receiver<Incoming>) {
    let mut closed = sh.closed.subscribe();
    loop {
        let item = tokio::select! {
            () = wait_closed(&mut closed) => return,
            i = incoming.recv() => match i {
                Some(i) => i,
                None => return,
            },
        };
        let Incoming::TransportInfo(raw) = item;
        let peer = lock(&sh.live).peer.clone();
        let Some(peer) = peer else { continue };
        match parse_transport_info(&raw) {
            Ok(ti) => {
                for c in ti.contents.iter().flat_map(|c| c.candidates.iter()) {
                    if let Some(line) = candidate_line(c) {
                        match Candidate::from_sdp_string(&line) {
                            Ok(c) => peer.add_remote_candidate(c),
                            Err(e) => olc_net::debug!("jitsi add ICE candidate: {e}"),
                        }
                    }
                }
            }
            Err(e) => olc_net::debug!("jitsi trickle ICE: parse transport-info: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE audio video data\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:uf\r\na=ice-pwd:pw\r\na=setup:active\r\na=mid:audio\r\na=sendrecv\r\na=msid:A1 A2\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\na=ssrc:11 cname:c1\r\na=ssrc:11 msid:A1 A2\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 100 96\r\nc=IN IP4 0.0.0.0\r\na=mid:video\r\na=sendrecv\r\na=msid:V1 V2\r\na=rtcp-mux\r\na=rtpmap:100 VP8/90000\r\na=ssrc-group:FID 22 33\r\na=ssrc:22 cname:c2\r\na=ssrc:22 msid:V1 V2\r\na=ssrc:33 cname:c2\r\na=ssrc:33 msid:V1 V2\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:data\r\na=sctp-port:5000\r\n";

    fn ids() -> KeepaliveIds {
        KeepaliveIds {
            stream: "olcrtc-ka-WMutBdYz".into(),
            track: "jitsi-ka-4x861OUH".into(),
        }
    }

    #[test]
    fn the_answer_is_completed_as_pion_writes_it() {
        let out = complete_answer(
            ANSWER,
            &ids(),
            &["candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host".into()],
        );
        // The audio line receives only and names no source.
        assert!(out.contains("a=mid:audio\r\na=recvonly\r\n"), "{out}");
        assert!(!out.contains("a=ssrc:11"), "{out}");
        assert!(!out.contains("A1"), "{out}");
        // The video source is named by our ids, with mslabel and label.
        for l in [
            "a=msid:olcrtc-ka-WMutBdYz jitsi-ka-4x861OUH",
            "a=ssrc:22 cname:c2",
            "a=ssrc:22 msid:olcrtc-ka-WMutBdYz jitsi-ka-4x861OUH",
            "a=ssrc:22 mslabel:olcrtc-ka-WMutBdYz",
            "a=ssrc:22 label:jitsi-ka-4x861OUH",
            "a=ssrc:33 label:jitsi-ka-4x861OUH",
            "a=ssrc-group:FID 22 33",
        ] {
            assert!(out.contains(&format!("{l}\r\n")), "{l} missing in {out}");
        }
        assert!(!out.contains("V1"), "{out}");
        // The candidate stands in the first section.
        let audio_end = out.find("m=video").unwrap();
        assert!(
            out[..audio_end].contains("a=candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host\r\n"),
            "{out}"
        );
        // The accept body that comes of it has the four parameters of a source.
        let body = accept_body(&out);
        assert!(
            body.contains(r#"<parameter name="mslabel" value="olcrtc-ka-WMutBdYz"/>"#),
            "{body}"
        );
        assert!(
            body.contains(r#"<parameter name="label" value="jitsi-ka-4x861OUH"/>"#),
            "{body}"
        );
        assert!(
            body.contains(r#"name="audio" senders="initiator""#),
            "{body}"
        );
        assert!(
            body.contains(r#"<source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="33">"#),
            "{body}"
        );
    }

    #[test]
    fn without_candidates_the_answer_is_unchanged_but_for_its_lines() {
        let out = complete_answer(ANSWER, &ids(), &[]);
        assert!(!out.contains("a=candidate"));
        assert!(out.ends_with("a=sctp-port:5000\r\n"));
    }

    #[test]
    fn keepalive_ids_are_go_s_shape() {
        let k = KeepaliveIds::random();
        assert!(k.stream.starts_with("olcrtc-ka-") && k.track.starts_with("jitsi-ka-"));
        assert_eq!(k.stream.len(), "olcrtc-ka-".len() + 8);
        assert_eq!(k.track.len(), "jitsi-ka-".len() + 8);
        assert_ne!(KeepaliveIds::random(), k);
    }

    #[test]
    fn the_keepalive_frame_and_the_constants() {
        assert_eq!(VP8_KEEPALIVE.len(), 20);
        assert_eq!(VP8_KEEPALIVE[0], 0x30);
        assert_eq!(BRIDGE_OPEN, Duration::from_secs(30));
        assert_eq!(XMPP_PING, Duration::from_secs(25));
        assert_eq!(XMPP_PING_WAIT, Duration::from_secs(15));
        assert_eq!(mid_of(ANSWER, "video").as_deref(), Some("video"));
        assert_eq!(mid_of(ANSWER, "text"), None);
    }
}

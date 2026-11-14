// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! One peer connection: a str0m `Rtc` on one protected UDP socket, driven by
//! a task of its own (pion's `PeerConnection` with its agent and SCTP
//! goroutines, in one place).
//!
//! The owner talks to it through [`Peer`] (SDP, candidates, channel writes;
//! each call takes the `Rtc` under a short lock and kicks the driver) and
//! hears from it through the [`PeerEvent`] queue the driver fills.
//!
//! # Backpressure
//!
//! - out: a channel write str0m cannot buffer returns `false`
//!   ([`Peer::write`]); [`Peer::wait_buffered`] waits until a channel's
//!   unacknowledged bytes fall under a mark, as the carriers wait on
//!   `BufferedAmount` (salutejazz/data.go `awaitSendWindow`);
//! - in: a data event holds permits of [`INBOUND_BYTES`] until the owner
//!   drops it. With none left the driver stops reading its socket, so a
//!   slow owner slows the sender through SCTP's own flow control, as a
//!   blocking `OnMessage` does under pion.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};

pub use str0m::IceConnectionState;

use crate::turn::{Arrival, RelayEvent, Relays, Resolved, StreamChunk, TurnServer, TurnTransport};
use crate::{CryptoProvider, DtlsVersion};

/// The driver's one receive buffer: the largest datagram it reads. An SFU
/// sends at most an Ethernet MTU (1500); DTLS records here are at most the
/// 1200-byte MTU str0m and Chrome use; 2048 leaves room for an IPv6 path's
/// larger packets without a second size class.
pub const RECV_BUF: usize = 2048;

/// What the data events waiting for the owner may hold at once, in bytes:
/// one message at str0m's largest receivable size (`max-message-size`
/// 262144, Chrome's value, which str0m advertises unchanged), so any
/// message SCTP accepted can pass, and no more. A message larger than this
/// takes all of it.
pub const INBOUND_BYTES: usize = 256 * 1024;

/// The event queue's length. Only the non-data events need it (data events
/// are bounded by [`INBOUND_BYTES`]); a peer's life has a handful of those.
pub const EVENT_QUEUE: usize = 64;

/// How long a closing peer drains its goodbyes (SCTP shutdown, DTLS
/// close_notify) before the socket goes: Go's `pcCloseTimeout`.
pub const CLOSE_DRAIN: Duration = Duration::from_secs(2);

/// A peer connection's settings.
#[derive(Clone)]
pub struct PeerConfig {
    /// Its name in the logs (`subscriber`, `publisher`).
    pub name: &'static str,
    /// DTLS, SRTP and the hashes ([`crate::crypto`]).
    pub crypto: Arc<CryptoProvider>,
    /// The DTLS versions offered.
    pub dtls_version: DtlsVersion,
    /// The address the socket binds and the host candidate names
    /// ([`crate::ice::default_ipv4`]).
    pub host_ip: IpAddr,
    /// What its channels may hold unacknowledged, in bytes, all channels
    /// together (str0m's `sctp_max_buffered_amount`; 128 KiB by default).
    pub sctp_max_buffered: usize,
    /// The TURN servers it allocates on once it gathers ([`Peer::gather`]),
    /// over UDP from its own socket or over a TCP connection of each
    /// server's own; at most [`crate::turn::MAX_ALLOCATIONS`] are used. Each allocation's relayed
    /// candidate comes as [`PeerEvent::LocalCandidate`].
    pub turn: Vec<TurnServer>,
    /// Only relayed candidates (WebRTC's `iceTransportPolicy: "relay"`):
    /// [`Peer::gather`] adds no host candidate.
    pub relay_only: bool,
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("name", &self.name)
            .field("dtls_version", &self.dtls_version)
            .field("host_ip", &self.host_ip)
            .field("sctp_max_buffered", &self.sctp_max_buffered)
            .field("turn", &self.turn)
            .field("relay_only", &self.relay_only)
            .finish_non_exhaustive()
    }
}

/// What the driver tells the owner.
#[derive(Debug)]
pub enum PeerEvent {
    /// ICE moved to this state.
    IceState(IceConnectionState),
    /// A local candidate gathered after the start (a TURN allocation's
    /// relayed address), as its SDP attribute (`candidate:...`), for
    /// trickling.
    LocalCandidate(String),
    /// ICE and DTLS are up.
    Connected,
    /// A data channel opened, with its label.
    ChannelOpen(ChannelId, String),
    /// A message arrived.
    Data(Inbound),
    /// A data channel closed.
    ChannelClose(ChannelId),
    /// The driver ended (the remote closed, the owner closed, an error):
    /// the last event.
    Closed(String),
}

/// One message from a data channel. Its bytes count against
/// [`INBOUND_BYTES`] until it is dropped.
#[derive(Debug)]
pub struct Inbound {
    /// The channel it came on.
    pub channel: ChannelId,
    /// Binary or text.
    pub binary: bool,
    /// The message.
    pub data: Vec<u8>,
    _held: OwnedSemaphorePermit,
}

/// A peer connection that cannot do what it was asked.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// The socket.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// str0m refused.
    #[error("{0}")]
    Rtc(String),
    /// No such channel (yet, or any more). Worded as pion's
    /// `io.ErrClosedPipe`, which `DataChannel.Send` returns for a channel
    /// that is not open: the apps read `read/write on closed pipe` in the
    /// engine's log as a lost transport.
    #[error("io: read/write on closed pipe")]
    NoChannel,
    /// The driver has ended (pion's `io.ErrClosedPipe` too).
    #[error("io: read/write on closed pipe")]
    Closed,
}

/// A handle on one peer connection; clones share it.
#[derive(Clone)]
pub struct Peer {
    sh: Arc<Shared>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("name", &self.sh.name)
            .field("local", &self.sh.local)
            .finish_non_exhaustive()
    }
}

struct Shared {
    name: &'static str,
    rtc: Mutex<Rtc>,
    /// Something changed under the lock: the driver polls str0m again.
    kick: Notify,
    /// The driver took input: acknowledgements may have lowered a channel's
    /// buffered amount ([`Peer::wait_buffered`]).
    progressed: Notify,
    closing: AtomicBool,
    ended: AtomicBool,
    local: SocketAddr,
    creds: IceCreds,
    /// Datagrams the host refused to send (a path the firewall drops):
    /// counted, as ICE fails such a pair on its own.
    send_refused: AtomicU64,
    /// [`PeerConfig::relay_only`].
    relay_only: bool,
    /// [`PeerConfig::turn`], until [`Peer::gather`] takes it.
    turn: Mutex<Vec<TurnServer>>,
    /// The resolved servers, waiting for the driver to allocate on them.
    turn_ready: Mutex<Option<Vec<Resolved>>>,
    /// Datagrams that could not go through a relay ([`Relays::dropped`]).
    relay_dropped: AtomicU64,
    /// When pion's refused-send line was written last ([`note_refused`]).
    refused_said: Mutex<Option<Instant>>,
}

/// The str0m settings every peer uses: RTP mode (media would pass through
/// untouched, as the carriers' video lanes will need), the given ICE
/// credentials, DTLS and SCTP send buffer.
#[must_use]
pub fn rtc_config(cfg: &PeerConfig, creds: &IceCreds) -> RtcConfig {
    RtcConfig::new()
        .set_crypto_provider(cfg.crypto.clone())
        .set_dtls_version(cfg.dtls_version)
        .set_rtp_mode(true)
        .set_local_ice_credentials(creds.clone())
        .set_sctp_max_buffered_amount(cfg.sctp_max_buffered)
}

impl Peer {
    /// A peer on a fresh protected socket at `cfg.host_ip`, with fresh
    /// Chrome-sized credentials, and its event queue. The driver starts now
    /// (on the current tokio runtime) and ends with [`Peer::close`], the
    /// remote's close, or the queue's receiver dropped.
    ///
    /// # Errors
    /// The bind, or the protector's refusal.
    pub fn start(cfg: &PeerConfig) -> Result<(Peer, mpsc::Receiver<PeerEvent>), PeerError> {
        let std_sock = std::net::UdpSocket::bind(SocketAddr::new(cfg.host_ip, 0))?;
        olc_net::net::protect(std_sock.as_raw_fd())?;
        std_sock.set_nonblocking(true)?;
        let local = std_sock.local_addr()?;
        let sock = UdpSocket::from_std(std_sock)?;
        let creds = crate::ice::chrome_creds();
        let rtc = rtc_config(cfg, &creds).build(Instant::now());
        let sh = Arc::new(Shared {
            name: cfg.name,
            rtc: Mutex::new(rtc),
            kick: Notify::new(),
            progressed: Notify::new(),
            closing: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            local,
            creds,
            send_refused: AtomicU64::new(0),
            relay_only: cfg.relay_only,
            turn: Mutex::new(cfg.turn.clone()),
            turn_ready: Mutex::new(None),
            relay_dropped: AtomicU64::new(0),
            refused_said: Mutex::new(None),
        });
        let (tx, rx) = mpsc::channel(EVENT_QUEUE);
        tokio::spawn(drive(sh.clone(), sock, tx));
        Ok((Peer { sh }, rx))
    }

    fn lock(&self) -> MutexGuard<'_, Rtc> {
        self.sh.rtc.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` on the `Rtc` (the SDP API, the direct API) and has the
    /// driver poll after it.
    pub fn with_rtc<R>(&self, f: impl FnOnce(&mut Rtc) -> R) -> R {
        let out = f(&mut self.lock());
        self.sh.kick.notify_one();
        out
    }

    /// The local ICE credentials.
    #[must_use]
    pub fn creds(&self) -> &IceCreds {
        &self.sh.creds
    }

    /// The socket's address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.sh.local
    }

    /// Adds the socket's host candidate and returns its SDP attribute
    /// (`candidate:...`), for trickling.
    ///
    /// # Errors
    /// str0m refused the candidate.
    pub fn add_host_candidate(&self) -> Result<String, PeerError> {
        let c = Candidate::host(self.sh.local, "udp").map_err(|e| PeerError::Rtc(e.to_string()))?;
        self.with_rtc(|rtc| {
            rtc.add_local_candidate(c)
                .map(Candidate::to_sdp_string)
                .ok_or_else(|| PeerError::Rtc("str0m refused the host candidate".into()))
        })
    }

    /// Starts gathering, as `setLocalDescription` does: the host candidate
    /// now, returned for trickling (none when relay-only), and an
    /// allocation on each TURN server once its host resolves, whose relayed
    /// candidate comes as [`PeerEvent::LocalCandidate`]. A second call adds
    /// only the host candidate again.
    ///
    /// # Errors
    /// str0m refused the host candidate.
    pub fn gather(&self) -> Result<Option<String>, PeerError> {
        let turn = std::mem::take(&mut *lock(&self.sh.turn));
        if !turn.is_empty() {
            let sh = Arc::downgrade(&self.sh);
            let v4 = self.sh.local.is_ipv4();
            tokio::spawn(async move {
                let resolved = crate::turn::resolve(&turn, v4).await;
                if let Some(sh) = sh.upgrade() {
                    *lock(&sh.turn_ready) = Some(resolved);
                    sh.kick.notify_one();
                }
            });
        }
        if self.sh.relay_only {
            return Ok(None);
        }
        self.add_host_candidate().map(Some)
    }

    /// Adds a candidate the remote trickled.
    pub fn add_remote_candidate(&self, c: Candidate) {
        self.with_rtc(|rtc| rtc.add_remote_candidate(c));
    }

    /// Writes one message on `channel`: `Ok(false)` when str0m's send buffer
    /// cannot take it now.
    ///
    /// # Errors
    /// No such channel, a closed peer, or str0m's refusal.
    pub fn write(&self, channel: ChannelId, binary: bool, data: &[u8]) -> Result<bool, PeerError> {
        if self.is_ended() {
            return Err(PeerError::Closed);
        }
        self.with_rtc(|rtc| {
            let mut ch = rtc.channel(channel).ok_or(PeerError::NoChannel)?;
            ch.write(binary, data)
                .map_err(|e| PeerError::Rtc(e.to_string()))
        })
    }

    /// What `channel` holds unacknowledged; `None` without the channel.
    #[must_use]
    pub fn buffered_amount(&self, channel: ChannelId) -> Option<usize> {
        self.lock()
            .channel(channel)
            .map(|mut ch| ch.buffered_amount())
    }

    /// Waits until `channel` holds at most `at_most` bytes unacknowledged.
    ///
    /// # Errors
    /// The channel went or the peer closed.
    pub async fn wait_buffered(&self, channel: ChannelId, at_most: usize) -> Result<(), PeerError> {
        loop {
            let progressed = self.sh.progressed.notified();
            tokio::pin!(progressed);
            progressed.as_mut().enable();
            if self.is_ended() {
                return Err(PeerError::Closed);
            }
            match self.buffered_amount(channel) {
                None => return Err(PeerError::NoChannel),
                Some(n) if n <= at_most => return Ok(()),
                Some(_) => {}
            }
            progressed.await;
        }
    }

    /// Waits for the driver's next input (a datagram, a timer): what an
    /// acknowledgement that frees send buffer comes with.
    pub async fn progressed(&self) {
        let next = self.sh.progressed.notified();
        if self.is_ended() {
            return;
        }
        next.await;
    }

    /// Whether ICE and DTLS are up.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.lock().is_connected()
    }

    /// Waits for the driver to end, its goodbyes sent and its relays'
    /// close lines written: what pion's `PeerConnection.Close` returns
    /// after. The caller bounds it (Go's `pcCloseTimeout`).
    pub async fn ended(&self) {
        loop {
            let next = self.sh.progressed.notified();
            tokio::pin!(next);
            next.as_mut().enable();
            if self.is_ended() {
                return;
            }
            next.await;
        }
    }

    /// Whether the driver has ended.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.sh.ended.load(Ordering::Acquire)
    }

    /// Datagrams the host refused to send so far.
    #[must_use]
    pub fn send_refused(&self) -> u64 {
        self.sh.send_refused.load(Ordering::Relaxed)
    }

    /// Datagrams that could not go through a TURN relay so far (no
    /// permission yet, which ICE's retransmit covers, or refused).
    #[must_use]
    pub fn relay_dropped(&self) -> u64 {
        self.sh.relay_dropped.load(Ordering::Relaxed)
    }

    /// Starts closing: the goodbyes go out for at most [`CLOSE_DRAIN`], then
    /// the driver ends with [`PeerEvent::Closed`].
    pub fn close(&self) {
        self.sh.closing.store(true, Ordering::Release);
        self.sh.kick.notify_one();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The most often pion's refused-send line is written for one peer
/// connection. pion writes one for every datagram the host refuses
/// (`candidateBase.writeTo`); a path that is down refuses hundreds a second,
/// and the apps need three lines in six seconds (Android's
/// `RTC_IO_ERROR_RECOVERY_THRESHOLD`, `RTC_FAILURE_WINDOW_MS`).
pub const REFUSED_LINE_EVERY: Duration = Duration::from_millis(100);

/// pion's words for a datagram the host refused: `Failed to send packet:`
/// and Go's `net.OpError` for a UDP write, whose error is the syscall's in
/// Go's words (lower case, no `os error` suffix). The apps read `network is
/// unreachable` in it as a path that went away.
#[must_use]
pub fn refused_line(local: SocketAddr, to: SocketAddr, e: &io::Error) -> String {
    let net = if local.is_ipv4() { "udp4" } else { "udp6" };
    format!(
        "Failed to send packet: write {net} {local}->{to}: sendto: {}",
        go_errno_text(e)
    )
}

/// An OS error as Go's `syscall.Errno` says it: the C library's message,
/// first letter in lower case, without Rust's ` (os error N)`.
fn go_errno_text(e: &io::Error) -> String {
    let Some(code) = e.raw_os_error() else {
        return e.to_string();
    };
    let text = io::Error::from_raw_os_error(code).to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// pion's line for a relayed candidate whose peer connection closed: its
/// read loop ends on the TURN client's closed socket and says so, once per
/// relay candidate (`candidateBase.recvLoop`, `Failed to read from
/// candidate %s: %v`; seen at every close of the Go server's peer
/// connections in `t3-live-2`). The apps read `use of closed network
/// connection` in it as a lost transport. The related address is the one
/// our candidate's SDP gives (`0.0.0.0:0`); pion's gives the mapped address.
#[must_use]
pub fn closed_relay_line(relayed: SocketAddr) -> String {
    let net = if relayed.is_ipv4() { "udp4" } else { "udp6" };
    let unspecified = if relayed.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    format!(
        "Failed to read from candidate {net} relay {relayed} related {unspecified} \
         (resolved: {relayed}): read udp {relayed}: use of closed network connection"
    )
}

/// Counts a datagram the host refused and, for a refusal pion would have
/// seen (not a full socket buffer: Go's write blocks there), writes pion's
/// line at most once per [`REFUSED_LINE_EVERY`].
fn note_refused(sh: &Shared, local: SocketAddr, to: SocketAddr, e: &io::Error) {
    sh.send_refused.fetch_add(1, Ordering::Relaxed);
    if e.kind() == io::ErrorKind::WouldBlock {
        return;
    }
    let now = Instant::now();
    let mut last = lock(&sh.refused_said);
    if last.is_some_and(|t| now.duration_since(t) < REFUSED_LINE_EVERY) {
        return;
    }
    *last = Some(now);
    drop(last);
    olc_net::info!("[ice] INFO: {}", refused_line(local, to, e));
}

/// Polls str0m until it asks to be woken: sends what it transmits (from a
/// relayed address, through its relay), keeps its events. Returns when to
/// wake it.
fn pump(
    sh: &Shared,
    sock: &UdpSocket,
    relays: &mut Relays,
    events: &mut Vec<Event>,
) -> Result<Instant, String> {
    let mut rtc = lock(&sh.rtc);
    let now = Instant::now();
    loop {
        match rtc.poll_output().map_err(|e| format!("poll: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                if relays.send(sock, t.source, t.destination, &t.contents, now) {
                    if let Some((server, e)) = relays.take_refused() {
                        note_refused(sh, sh.local, server, &e);
                    }
                } else if let Err(e) = sock.try_send_to(&t.contents, t.destination) {
                    note_refused(sh, sh.local, t.destination, &e);
                }
            }
            Output::Event(e) => events.push(e),
        }
    }
}

/// Runs the relays: their timers, what they send, and the allocations that
/// came up, whose relayed candidates go to str0m and, as SDP lines, into
/// `lines`. Returns when to run them again.
fn run_relays(
    sh: &Shared,
    sock: &UdpSocket,
    relays: &mut Relays,
    lines: &mut Vec<String>,
) -> Option<Instant> {
    let mut up = Vec::new();
    let wake = relays.poll(sock, sh.name, Instant::now(), &mut up);
    sh.relay_dropped.store(relays.dropped(), Ordering::Relaxed);
    if up.is_empty() {
        return wake;
    }
    let mut rtc = lock(&sh.rtc);
    for RelayEvent::Allocated(relayed, via) in up {
        match relayed_candidate(relayed, sh.local, via) {
            Ok(c) => {
                if let Some(c) = rtc.add_local_candidate(c) {
                    lines.push(c.to_sdp_string());
                }
            }
            Err(e) => olc_net::debug!("webrtc: {} relayed candidate {relayed}: {e}", sh.name),
        }
    }
    wake
}

/// A relayed candidate as libwebrtc makes one: its address is UDP either way,
/// its type preference follows how the allocation reaches its server (2 over
/// UDP, 1 over TCP), so ICE prefers a relay over UDP, as Chrome does.
fn relayed_candidate(
    relayed: SocketAddr,
    base: SocketAddr,
    via: TurnTransport,
) -> Result<Candidate, String> {
    let via = match via {
        TurnTransport::Udp => "udp",
        TurnTransport::Tcp => "tcp",
    };
    Candidate::relayed_via(relayed, base, "udp", via).map_err(|e| e.to_string())
}

async fn drive(sh: Arc<Shared>, sock: UdpSocket, tx: mpsc::Sender<PeerEvent>) {
    let inbound = Arc::new(Semaphore::new(INBOUND_BYTES));
    let mut buf = vec![0u8; RECV_BUF];
    let mut events = Vec::new();
    let mut lines = Vec::new();
    // What the relays' TCP connections read; the driver keeps a sender, so
    // the queue stays open while it runs.
    let (stream_tx, mut stream_rx) = mpsc::channel::<StreamChunk>(crate::turn::STREAM_INBOUND);
    let mut relays = Relays::new(&[], sh.local, Instant::now(), &stream_tx);
    let mut drain_until: Option<Instant> = None;
    let reason: String = 'run: loop {
        if let Some(servers) = lock(&sh.turn_ready).take() {
            relays = Relays::new(&servers, sh.local, Instant::now(), &stream_tx);
        }
        // New relayed candidates reach str0m before it polls, so its checks
        // from them start now.
        run_relays(&sh, &sock, &mut relays, &mut lines);
        let wake = match pump(&sh, &sock, &mut relays, &mut events) {
            Ok(t) => t,
            Err(e) => break 'run e,
        };
        // A transmit through a relay may have queued a request (a
        // permission, a channel): out with it now, not at the next wake.
        let relay_wake = run_relays(&sh, &sock, &mut relays, &mut lines);
        let wake = relay_wake.map_or(wake, |r| r.min(wake));
        for line in lines.drain(..) {
            if tx.send(PeerEvent::LocalCandidate(line)).await.is_err() {
                break 'run "the owner went".into();
            }
        }
        sh.progressed.notify_waiters();
        let mut remote_closed = false;
        for e in events.drain(..) {
            let ev = match e {
                Event::IceConnectionStateChange(s) => PeerEvent::IceState(s),
                Event::Connected => PeerEvent::Connected,
                Event::ChannelOpen(id, label) => PeerEvent::ChannelOpen(id, label),
                Event::ChannelClose(id) => PeerEvent::ChannelClose(id),
                Event::ChannelData(d) => {
                    let want = d.data.len().clamp(1, INBOUND_BYTES);
                    let want = u32::try_from(want).unwrap_or(u32::MAX);
                    let Ok(held) = inbound.clone().acquire_many_owned(want).await else {
                        break 'run "inbound closed".into();
                    };
                    PeerEvent::Data(Inbound {
                        channel: d.id,
                        binary: d.binary,
                        data: d.data,
                        _held: held,
                    })
                }
                Event::Closed => {
                    remote_closed = true;
                    continue;
                }
                _ => continue,
            };
            if tx.send(ev).await.is_err() {
                break 'run "the owner went".into();
            }
        }
        if remote_closed {
            break 'run "the remote closed the connection".into();
        }
        let now = Instant::now();
        if sh.closing.load(Ordering::Acquire) && drain_until.is_none() {
            let _ = lock(&sh.rtc).close();
            drain_until = Some(now + CLOSE_DRAIN);
            continue;
        }
        if let Some(until) = drain_until {
            let alive = sh
                .rtc
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_alive();
            if !alive || now >= until {
                break 'run "closed".into();
            }
        }
        let wake = drain_until.map_or(wake, |u| u.min(wake));
        tokio::select! {
            got = sock.recv_from(&mut buf) => match got {
                Ok((n, src)) => {
                    let now = Instant::now();
                    let fed = match relays.recv(src, &buf[..n], now) {
                        Arrival::Direct => feed(&sh, now, Receive::new(Protocol::Udp, src, sh.local, &buf[..n])),
                        Arrival::Handled => Ok(()),
                        Arrival::Relayed { relayed, data } => feed(
                            &sh,
                            now,
                            Receive::new(Protocol::Udp, data.peer, relayed, data.data()),
                        ),
                    };
                    if let Err(e) = fed {
                        break 'run e;
                    }
                }
                Err(e) if matches!(e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {}
                Err(e) => break 'run format!("recv: {e}"),
            },
            Some(chunk) = stream_rx.recv() => {
                let now = Instant::now();
                let mut fed = Ok(());
                relays.recv_stream(&chunk, now, |relayed, peer, data| {
                    if fed.is_ok() {
                        fed = feed(&sh, now, Receive::new(Protocol::Udp, peer, relayed, data));
                    }
                });
                if let Err(e) = fed {
                    break 'run e;
                }
            }
            () = tokio::time::sleep_until(wake.into()) => {
                let mut rtc = sh.rtc.lock().unwrap_or_else(PoisonError::into_inner);
                if let Err(e) = rtc.handle_input(Input::Timeout(Instant::now())) {
                    break 'run format!("timeout: {e}");
                }
            }
            () = sh.kick.notified() => {}
        }
    };
    for relayed in relays.close(&sock, Instant::now()) {
        olc_net::info!("[ice] WARN: {}", closed_relay_line(relayed));
    }
    sh.ended.store(true, Ordering::Release);
    sh.progressed.notify_waiters();
    olc_net::debug!("webrtc: {} peer connection ended: {reason}", sh.name);
    let _ = tx.send(PeerEvent::Closed(reason)).await;
}

/// Hands str0m one datagram (one it cannot parse is dropped, as before).
fn feed<E>(sh: &Shared, now: Instant, r: Result<Receive<'_>, E>) -> Result<(), String> {
    let Ok(r) = r else { return Ok(()) };
    lock(&sh.rtc)
        .handle_input(Input::Receive(now, r))
        .map_err(|e| format!("input: {e}"))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use str0m::change::SdpOffer;
    use str0m::channel::{ChannelConfig, Reliability};

    use super::*;

    /// A relayed candidate ranks by its path to the TURN server, as
    /// libwebrtc's do (`ICE_TYPE_PREFERENCE_RELAY_UDP` 2, `_TCP` 1): with a
    /// relay over UDP and one over TCP both up, ICE nominates the UDP one.
    /// Both are UDP candidates in the SDP.
    #[test]
    fn a_relayed_candidate_ranks_by_its_path_to_the_turn_server() {
        let relayed: SocketAddr = "192.0.2.7:40000".parse().unwrap();
        let base: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let udp = relayed_candidate(relayed, base, TurnTransport::Udp).unwrap();
        let tcp = relayed_candidate(relayed, base, TurnTransport::Tcp).unwrap();
        assert_eq!(udp.prio() >> 24, 2, "{}", udp.to_sdp_string());
        assert_eq!(tcp.prio() >> 24, 1, "{}", tcp.to_sdp_string());
        for c in [&udp, &tcp] {
            let line = c.to_sdp_string();
            assert!(
                line.contains(" udp ") && line.contains(" typ relay"),
                "{line}"
            );
        }
    }

    /// A send on a channel that is not open says pion's `io.ErrClosedPipe`
    /// (`DataChannel.Send`'s `ensureOpen`), so the session's
    /// `salutejazz data channel send: ...` reads as Go's, which the apps
    /// take for a lost transport.
    #[test]
    fn a_send_without_a_channel_says_pions_closed_pipe() {
        assert_eq!(
            PeerError::NoChannel.to_string(),
            "io: read/write on closed pipe"
        );
        assert_eq!(
            PeerError::Closed.to_string(),
            "io: read/write on closed pipe"
        );
    }
    /// pion's line for a refused datagram, in Go's words, as the apps
    /// match it (lower case `network is unreachable`).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_send_reads_as_pions_line() {
        let local: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let to: SocketAddr = "198.51.100.2:3478".parse().unwrap();
        assert_eq!(
            refused_line(local, to, &io::Error::from_raw_os_error(101)),
            "Failed to send packet: write udp4 192.0.2.1:5000->198.51.100.2:3478: sendto: network is unreachable"
        );
        let v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        let to6: SocketAddr = "[2001:db8::2]:3478".parse().unwrap();
        assert_eq!(
            refused_line(v6, to6, &io::Error::from_raw_os_error(113)),
            "Failed to send packet: write udp6 [2001:db8::1]:5000->[2001:db8::2]:3478: sendto: no route to host"
        );
    }

    /// The line a closed relay candidate writes, in pion's words (the Go
    /// server's at the end of `t3-live-2`, addresses aside).
    #[test]
    fn a_closed_relay_reads_as_pions_line() {
        let relayed: SocketAddr = "192.0.2.7:44444".parse().unwrap();
        assert_eq!(
            closed_relay_line(relayed),
            "Failed to read from candidate udp4 relay 192.0.2.7:44444 related 0.0.0.0:0 \
             (resolved: 192.0.2.7:44444): read udp 192.0.2.7:44444: use of closed network connection"
        );
        let v6: SocketAddr = "[2001:db8::7]:44444".parse().unwrap();
        assert!(closed_relay_line(v6).starts_with(
            "Failed to read from candidate udp6 relay [2001:db8::7]:44444 related [::]:0 "
        ));
    }

    /// A refusal is counted every time; the line is written at most once
    /// per [`REFUSED_LINE_EVERY`], and never for a full socket buffer.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refused_sends_are_counted_and_said_sparingly() {
        crate::testing::bounded(async {
            let (a, _rx) = Peer::start(&config("a", 1 << 20)).unwrap();
            let to: SocketAddr = "198.51.100.2:3478".parse().unwrap();
            let local = a.sh.local;
            let unreachable = io::Error::from_raw_os_error(101);
            note_refused(
                &a.sh,
                local,
                to,
                &io::Error::from(io::ErrorKind::WouldBlock),
            );
            assert!(
                lock(&a.sh.refused_said).is_none(),
                "a full buffer is not pion's refusal"
            );
            note_refused(&a.sh, local, to, &unreachable);
            let first = lock(&a.sh.refused_said).expect("said once");
            note_refused(&a.sh, local, to, &unreachable);
            assert_eq!(
                *lock(&a.sh.refused_said),
                Some(first),
                "not again within the interval"
            );
            assert_eq!(a.send_refused(), 3);
            a.close();
        })
        .await;
    }
    use crate::testing::bounded;

    /// The event queue holds [`EVENT_QUEUE`] of these per peer connection,
    /// so its bound in bytes is the slot's size times the queue.
    #[test]
    fn an_event_slot_stays_small() {
        assert!(
            size_of::<Inbound>() <= 56,
            "Inbound is {} bytes",
            size_of::<Inbound>()
        );
        assert!(
            size_of::<PeerEvent>() <= 64,
            "PeerEvent is {} bytes",
            size_of::<PeerEvent>()
        );
    }

    fn config(name: &'static str, buffered: usize) -> PeerConfig {
        PeerConfig {
            name,
            crypto: crate::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            sctp_max_buffered: buffered,
            turn: Vec::new(),
            relay_only: false,
        }
    }

    /// `a` offers one reliable channel and `b` answers; returns its id.
    fn negotiate(a: &Peer, b: &Peer) -> ChannelId {
        let (offer, pending, id) = a.with_rtc(|rtc| {
            let mut api = rtc.sdp_api();
            let id = api.add_channel_with_config(ChannelConfig {
                label: "_reliable".into(),
                ordered: true,
                reliability: Reliability::Reliable,
                negotiated: None,
                protocol: String::new(),
            });
            let (offer, pending) = api.apply().unwrap();
            (offer, pending, id)
        });
        let offer = SdpOffer::from_sdp_string(&offer.to_sdp_string()).unwrap();
        let answer = b.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer)).unwrap();
        a.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer))
            .unwrap();
        id
    }

    /// Waits until the channel is open at both ends.
    async fn both_open(a_rx: &mut mpsc::Receiver<PeerEvent>, b_rx: &mut mpsc::Receiver<PeerEvent>) {
        let mut open = (false, false);
        while !(open.0 && open.1) {
            tokio::select! {
                Some(e) = a_rx.recv() => match e {
                    PeerEvent::ChannelOpen(..) => open.0 = true,
                    PeerEvent::Closed(r) => panic!("a closed: {r}"),
                    _ => {}
                },
                Some(e) = b_rx.recv() => match e {
                    PeerEvent::ChannelOpen(..) => open.1 = true,
                    PeerEvent::Closed(r) => panic!("b closed: {r}"),
                    _ => {}
                },
            }
        }
    }

    /// Two peers on loopback, `a` offering one reliable channel; returns
    /// both with their queues once the channel is open at both ends.
    async fn pair(
        buffered: usize,
    ) -> (
        Peer,
        mpsc::Receiver<PeerEvent>,
        Peer,
        mpsc::Receiver<PeerEvent>,
        ChannelId,
    ) {
        crate::init();
        let (a, mut a_rx) = Peer::start(&config("a", buffered)).unwrap();
        let (b, mut b_rx) = Peer::start(&config("b", buffered)).unwrap();
        let id = negotiate(&a, &b);
        let ca = Candidate::from_sdp_string(&a.add_host_candidate().unwrap()).unwrap();
        let cb = Candidate::from_sdp_string(&b.add_host_candidate().unwrap()).unwrap();
        a.add_remote_candidate(cb);
        b.add_remote_candidate(ca);
        both_open(&mut a_rx, &mut b_rx).await;
        (a, a_rx, b, b_rx, id)
    }

    /// Moves `n` messages of `len` bytes from `from` to `to` on `id`, and
    /// checks each arrives whole and in order.
    async fn send_through(
        from: &Peer,
        to_rx: &mut mpsc::Receiver<PeerEvent>,
        id: ChannelId,
        n: usize,
        len: usize,
    ) {
        for i in 0..n {
            let msg = vec![u8::try_from(i % 251).unwrap(); len];
            while !from.write(id, true, &msg).unwrap() {
                from.wait_buffered(id, 128 << 10).await.unwrap();
            }
        }
        let mut got = 0usize;
        while got < n {
            match to_rx.recv().await.unwrap() {
                PeerEvent::Data(m) => {
                    assert_eq!(m.data.len(), len);
                    assert!(m.data.iter().all(|&x| usize::from(x) == got % 251));
                    got += 1;
                }
                PeerEvent::Closed(r) => panic!("closed: {r}"),
                _ => {}
            }
        }
    }

    /// `a` uses only its relayed candidate (relay-only, no host candidate
    /// added) and `b` knows only that one: whatever connects them goes
    /// through the TURN server, both ways.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_only_peer_connects_through_turn() {
        bounded(async {
            crate::init();
            let (server, entry) = crate::testing::turn_server().await;
            let mut ca = config("a", 1 << 20);
            ca.turn = vec![entry];
            ca.relay_only = true;
            let (a, mut a_rx) = Peer::start(&ca).unwrap();
            let (b, mut b_rx) = Peer::start(&config("b", 1 << 20)).unwrap();
            let id = negotiate(&a, &b);
            assert_eq!(
                a.gather().unwrap(),
                None,
                "a relay-only peer has no host candidate"
            );
            let cb = Candidate::from_sdp_string(&b.add_host_candidate().unwrap()).unwrap();
            a.add_remote_candidate(cb);
            let line = loop {
                match a_rx.recv().await {
                    Some(PeerEvent::LocalCandidate(line)) => break line,
                    Some(PeerEvent::Closed(r)) => panic!("a closed: {r}"),
                    None => panic!("a's queue ended"),
                    Some(_) => {}
                }
            };
            assert!(line.contains(" typ relay"), "{line}");
            let relayed = Candidate::from_sdp_string(&line).unwrap();
            assert_ne!(relayed.addr(), a.local_addr(), "{line}");
            b.add_remote_candidate(relayed);
            both_open(&mut a_rx, &mut b_rx).await;
            send_through(&a, &mut b_rx, id, 40, 12_000).await;
            send_through(&b, &mut a_rx, id, 40, 12_000).await;
            // Nothing went around the relay: a has no other candidate.
            assert_eq!(a.send_refused(), 0);
            a.close();
            b.close();
            server.close().await.unwrap();
        })
        .await;
    }

    /// A TURN server that refuses the credential costs the peer nothing
    /// else: no relayed candidate, and its host candidate still connects.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_turn_credential_leaves_the_host_path() {
        bounded(async {
            crate::init();
            let (server, mut entry) = crate::testing::turn_server().await;
            entry.password = "not-the-password".into();
            let mut ca = config("a", 1 << 20);
            ca.turn = vec![entry];
            let (a, mut a_rx) = Peer::start(&ca).unwrap();
            let (b, mut b_rx) = Peer::start(&config("b", 1 << 20)).unwrap();
            let id = negotiate(&a, &b);
            let host = a.gather().unwrap().expect("a host candidate");
            let ca = Candidate::from_sdp_string(&host).unwrap();
            let cb = Candidate::from_sdp_string(&b.add_host_candidate().unwrap()).unwrap();
            a.add_remote_candidate(cb);
            b.add_remote_candidate(ca);
            let mut open = (false, false);
            while !(open.0 && open.1) {
                tokio::select! {
                    Some(e) = a_rx.recv() => match e {
                        PeerEvent::ChannelOpen(..) => open.0 = true,
                        PeerEvent::LocalCandidate(l) => panic!("a relayed candidate on a refused credential: {l}"),
                        PeerEvent::Closed(r) => panic!("a closed: {r}"),
                        _ => {}
                    },
                    Some(e) = b_rx.recv() => if let PeerEvent::ChannelOpen(..) = e { open.1 = true },
                }
            }
            send_through(&a, &mut b_rx, id, 5, 1_000).await;
            a.close();
            b.close();
            server.close().await.unwrap();
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_peers_move_ordered_messages_whole() {
        bounded(async {
            let (a, _a_rx, b, mut b_rx, id) = pair(1 << 20).await;
            assert!(a.is_connected() && b.is_connected());
            let total = 200usize;
            let sender = tokio::spawn(async move {
                for i in 0..total {
                    let msg = vec![u8::try_from(i % 251).unwrap(); 12_000];
                    loop {
                        if a.write(id, true, &msg).unwrap() {
                            break;
                        }
                        a.wait_buffered(id, 256 << 10).await.unwrap();
                    }
                }
                a
            });
            let mut got = 0usize;
            while got < total {
                match b_rx.recv().await.unwrap() {
                    PeerEvent::Data(m) => {
                        assert_eq!(m.data.len(), 12_000);
                        assert!(m.data.iter().all(|&x| usize::from(x) == got % 251));
                        got += 1;
                    }
                    PeerEvent::Closed(r) => panic!("closed: {r}"),
                    _ => {}
                }
            }
            let a = sender.await.unwrap();
            a.close();
            b.close();
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_send_buffer_refuses_and_drains() {
        bounded(async {
            let (a, _a_rx, _b, mut b_rx, id) = pair(64 << 10).await;
            let msg = vec![7u8; 16 << 10];
            let mut accepted = 0usize;
            while a.write(id, true, &msg).unwrap() {
                accepted += 1;
                assert!(accepted <= 8, "str0m took more than its 64 KiB buffer");
            }
            assert!(accepted >= 3, "only {accepted} messages fit in 64 KiB");
            // The peer reads them; the buffer empties as they are acked.
            let reader = tokio::spawn(async move {
                let mut n = 0;
                while n < accepted {
                    if let Some(PeerEvent::Data(_)) = b_rx.recv().await {
                        n += 1;
                    }
                }
                b_rx
            });
            a.wait_buffered(id, 0).await.unwrap();
            assert_eq!(a.buffered_amount(id), Some(0));
            drop(reader.await.unwrap());
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unread_queue_holds_its_byte_bound_and_no_more() {
        bounded(async {
            let (a, _a_rx, _b, mut b_rx, id) = pair(1 << 20).await;
            let msg = vec![1u8; 12_000];
            for _ in 0..60 {
                while !a.write(id, true, &msg).unwrap() {
                    a.wait_buffered(id, 512 << 10).await.unwrap();
                }
            }
            // Nobody reads: the driver stops once the events hold
            // INBOUND_BYTES; let it get there.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut held = Vec::new();
            while let Ok(PeerEvent::Data(m)) = b_rx.try_recv() {
                held.push(m);
            }
            let bytes: usize = held.iter().map(|m| m.data.len()).sum();
            assert!(bytes <= INBOUND_BYTES, "{bytes} bytes queued");
            assert!(bytes + 12_000 > INBOUND_BYTES, "only {bytes} bytes queued");
            // Dropping them lets the rest through.
            let before = held.len();
            drop(held);
            let mut rest = 0;
            while before + rest < 60 {
                if let Some(PeerEvent::Data(_)) = b_rx.recv().await {
                    rest += 1;
                }
            }
        })
        .await;
    }

    /// `ended` returns once the driver has ended, and at once after.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ended_waits_for_the_driver() {
        bounded(async {
            let (a, _a_rx, _b, _b_rx, _id) = pair(1 << 20).await;
            assert!(!a.is_ended());
            a.close();
            a.ended().await;
            assert!(a.is_ended());
            a.ended().await;
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_ends_both_drivers() {
        bounded(async {
            let (a, mut a_rx, _b, mut b_rx, _id) = pair(1 << 20).await;
            a.close();
            loop {
                if let Some(PeerEvent::Closed(_)) = a_rx.recv().await {
                    break;
                }
            }
            assert!(a.is_ended());
            // The remote hears the goodbye (or its ICE goes); either way its
            // driver reports it and no write is taken after.
            loop {
                match b_rx.recv().await {
                    Some(PeerEvent::Closed(_) | PeerEvent::ChannelClose(_)) | None => break,
                    Some(PeerEvent::IceState(IceConnectionState::Disconnected)) => break,
                    _ => {}
                }
            }
        })
        .await;
    }
}

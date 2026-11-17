// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! One peer connection: a str0m `Rtc` on one protected UDP socket, driven by
//! a task of its own (pion's `PeerConnection` with its agent and SCTP
//! goroutines, in one place).
//!
//! # ICE over TCP
//!
//! [`PeerConfig::ice_mode`] says which transports its ICE uses. With `tcp`
//! or `both` the peer dials each `tcptype passive` candidate the remote
//! names ([`Peer::add_remote_candidate`], [`Peer::remote_described`]) on a
//! protected socket and makes a local `tcp` / `tcptype active` candidate of
//! the connection, as pion does; packets go framed on it
//! ([`crate::icetcp`]). In `tcp` mode the peer gathers nothing else and
//! sends no UDP datagram ([`Peer::udp_out`] stays 0), and takes none. A
//! connection that breaks is not dialled again. When a connection ends or
//! a dial fails and no connection is left and no dial is on its way, the
//! owner is told at once ([`PeerEvent::Failed`]): always for a peer whose
//! ICE is TCP alone, and with both transports when a connection had
//! carried packets and the UDP path has been silent.
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
//!
//! # Media
//!
//! The `Rtc` runs in RTP mode: an owner that negotiated a media line writes
//! whole RTP packets through the direct API ([`Peer::with_rtc`]) and hears
//! each one that arrives through its [`RtpSink`], called on the driver's
//! task as the packet is decrypted (pion's `TrackRemote.ReadRTP` loop, with
//! no queue between). [`crate::media`] has the helpers: the codecs and
//! extensions a peer is built with, a send stream's sequence and resend
//! cache, the count of video packets received.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use str0m::channel::ChannelId;
use str0m::media::KeyframeRequest;
use str0m::net::{Protocol, Receive, TcpType};
use str0m::rtp::RtpPacket;
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};

pub use str0m::IceConnectionState;

pub use crate::icetcp::IceMode;
use crate::icetcp::{Conns, MAX_DIALS};
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

/// Takes each RTP packet the remote sends, on the driver's task; it must
/// not block (the driver reads nothing else meanwhile).
pub type RtpSink = Box<dyn FnMut(&RtpPacket) + Send>;

/// The event queue's length. Only the non-data events need it (data events
/// are bounded by [`INBOUND_BYTES`]); a peer's life has a handful of those.
pub const EVENT_QUEUE: usize = 64;

/// How long a closing peer drains its goodbyes (SCTP shutdown, DTLS
/// close_notify) before the socket goes: Go's `pcCloseTimeout`.
pub const CLOSE_DRAIN: Duration = Duration::from_secs(2);

/// How long ago the UDP path may have been heard on and still count as
/// alive when the last ICE-TCP connection breaks (a peer with both
/// transports): pion's `ICEDisconnectedTimeout` (5 s). Heard on means a
/// datagram str0m took for this peer's: from the nominated address, a STUN
/// message with the peer's credentials, or from a remote candidate.
pub const PATH_HEARD_WITHIN: Duration = Duration::from_secs(5);

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
    /// Which transports ICE uses (Go's `iceNetworkTypes`): UDP alone, TCP
    /// alone (no host candidate, no TURN allocation, no UDP datagram; a
    /// connection to each passive TCP candidate the remote names), or
    /// both.
    pub ice_mode: IceMode,
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
            .field("ice_mode", &self.ice_mode)
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
    /// The remote asked for a keyframe on a line this peer sends on (RTCP
    /// PLI or FIR): which line, which layer and which of the two. str0m
    /// keeps one pending request per sending stream, so a burst of them in
    /// one RTCP packet comes as one event.
    KeyframeRequest(KeyframeRequest),
    /// ICE over TCP has no connection left and no dial on its way, after a
    /// connection ended or a dial failed, and no other path is alive: the
    /// peer connection has failed, now (pion would say so up to 30 s
    /// later, the checks going unanswered). For a peer whose ICE is TCP
    /// alone that is every such moment, whether or not a packet ever came
    /// on a connection; with both transports, only when a connection had
    /// been heard on and the UDP path has not within
    /// [`PATH_HEARD_WITHIN`]. Said once; the driver runs on until it is
    /// closed. [`crate::pcstate::PcWatcher`] takes it as `failed`.
    Failed(String),
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
    /// Where arriving RTP goes; dropped without one.
    rtp: Mutex<Option<RtpSink>>,
    /// Video RTP packets received ([`Peer::video_packets_in`]).
    video_in: AtomicU64,
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
    /// [`PeerConfig::ice_mode`].
    ice_mode: IceMode,
    /// Datagrams given to the UDP socket ([`Peer::udp_out`]).
    udp_out: AtomicU64,
    /// Datagrams read off the UDP socket ([`Peer::udp_in`]).
    udp_in: AtomicU64,
    /// Packets ICE-TCP dropped ([`Peer::tcp_dropped`]).
    tcp_dropped: AtomicU64,
    /// Times an ICE-TCP socket held the peer back ([`Peer::tcp_stalls`]).
    tcp_stalls: AtomicU64,
    /// RTP packets a send line refused ([`Peer::rtp_refused`]).
    rtp_refused: AtomicU64,
    /// The remote passive candidates dialled so far, [`MAX_DIALS`] at most.
    tcp_asked: Mutex<Vec<SocketAddr>>,
    /// Dials on their way. A dial that connected queues its stream in
    /// `tcp_ready` and leaves this count in one step, under the queue's
    /// lock; the driver takes the queue, and [`tcp_left`] reads both, under
    /// the same lock. So the driver never holds a stream whose dial still
    /// counts (were it to refuse that stream, "a dial is on its way" would
    /// be the answer to its own end), and a reader that finds the count at
    /// nothing and the queue empty has missed no connection.
    tcp_dialing: AtomicUsize,
    /// Why the last dial that failed did (or that its connection could not
    /// be kept), until the driver takes it. A dial leaves `tcp_dialing`
    /// before it writes here: the driver asks what is left once per reason,
    /// and the dial that failed must not be part of the answer.
    tcp_dial_failed: Mutex<Option<String>>,
    /// Connected streams waiting for the driver; `true` for one accepted
    /// (tests), whose local candidate exists already.
    tcp_ready: Mutex<Vec<(TcpStream, bool)>>,
    /// Tests: the driver closes its ICE-TCP connections.
    #[cfg(test)]
    tcp_cut: AtomicBool,
    /// Tests: the ICE-TCP connections the driver holds, and how many of
    /// them were heard on, as of its last turn.
    #[cfg(test)]
    tcp_counts: Mutex<(usize, usize)>,
    /// Tests: run by a dial's task between its two steps (its stream
    /// queued and the count left; the count left and its failure told).
    #[cfg(test)]
    tcp_dial_mid: Mutex<Option<DialHook>>,
    /// Tests: the driver refuses the next stream it takes, as it refuses
    /// one that was reset as it came.
    #[cfg(test)]
    tcp_refuse: AtomicBool,
    /// Tests: the driver's turns so far.
    #[cfg(test)]
    turns: AtomicU64,
    /// Tests: datagrams off the UDP socket or a relay handed to str0m.
    #[cfg(test)]
    udp_fed: AtomicU64,
}

/// Tests: what [`Shared::tcp_dial_mid`] runs.
#[cfg(test)]
type DialHook = Box<dyn Fn(&Shared) + Send + Sync>;

/// Tests: a dial's task is between its two steps.
#[cfg(test)]
fn dial_mid(sh: &Shared) {
    if let Some(hook) = lock(&sh.tcp_dial_mid).as_ref() {
        hook(sh);
    }
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
        Peer::start_tuned(cfg, |c| c)
    }

    /// [`Peer::start`] with the str0m settings passed through `tune` before
    /// the peer is built: a link whose SDP must say what its Go engine's says
    /// sets its codecs there (`RtcConfig::clear_codecs`, `codec_config`).
    ///
    /// # Errors
    /// The bind, or the protector's refusal.
    pub fn start_tuned(
        cfg: &PeerConfig,
        tune: impl FnOnce(RtcConfig) -> RtcConfig,
    ) -> Result<(Peer, mpsc::Receiver<PeerEvent>), PeerError> {
        let std_sock = std::net::UdpSocket::bind(SocketAddr::new(cfg.host_ip, 0))?;
        olc_net::net::protect(std_sock.as_raw_fd())?;
        std_sock.set_nonblocking(true)?;
        let local = std_sock.local_addr()?;
        let sock = UdpSocket::from_std(std_sock)?;
        let creds = crate::ice::chrome_creds();
        let rtc = tune(rtc_config(cfg, &creds)).build(Instant::now());
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
            rtp: Mutex::new(None),
            video_in: AtomicU64::new(0),
            relay_only: cfg.relay_only,
            turn: Mutex::new(cfg.turn.clone()),
            turn_ready: Mutex::new(None),
            relay_dropped: AtomicU64::new(0),
            refused_said: Mutex::new(None),
            ice_mode: cfg.ice_mode,
            udp_out: AtomicU64::new(0),
            udp_in: AtomicU64::new(0),
            tcp_dropped: AtomicU64::new(0),
            tcp_stalls: AtomicU64::new(0),
            rtp_refused: AtomicU64::new(0),
            tcp_asked: Mutex::new(Vec::new()),
            tcp_dialing: AtomicUsize::new(0),
            tcp_dial_failed: Mutex::new(None),
            tcp_ready: Mutex::new(Vec::new()),
            #[cfg(test)]
            tcp_cut: AtomicBool::new(false),
            #[cfg(test)]
            tcp_counts: Mutex::new((0, 0)),
            #[cfg(test)]
            tcp_dial_mid: Mutex::new(None),
            #[cfg(test)]
            tcp_refuse: AtomicBool::new(false),
            #[cfg(test)]
            turns: AtomicU64::new(0),
            #[cfg(test)]
            udp_fed: AtomicU64::new(0),
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
    /// str0m refused the candidate, or the peer's ICE is TCP alone.
    pub fn add_host_candidate(&self) -> Result<String, PeerError> {
        if !self.sh.ice_mode.udp() {
            return Err(PeerError::Rtc(
                "no host candidate: this peer's ICE is TCP alone".into(),
            ));
        }
        let c = Candidate::host(self.sh.local, "udp").map_err(|e| PeerError::Rtc(e.to_string()))?;
        self.with_rtc(|rtc| {
            rtc.add_local_candidate(c)
                .map(Candidate::to_sdp_string)
                .ok_or_else(|| PeerError::Rtc("str0m refused the host candidate".into()))
        })
    }

    /// Where the RTP the remote sends goes from now on; `None` drops it.
    pub fn set_rtp_sink(&self, sink: Option<RtpSink>) {
        *self.sh.rtp.lock().unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// Video RTP packets the remote sent so far, with or without a sink:
    /// every packet str0m handed up (decrypted, a resend unwrapped) whose
    /// payload type is a video codec's, its RTX or its RED. What pion's
    /// `InboundRTPStreamStats.PacketsReceived` adds up to over the streams
    /// of kind video (VK Calls reports it, Go `vkcalls.go:578-589`).
    #[must_use]
    pub fn video_packets_in(&self) -> u64 {
        self.sh.video_in.load(Ordering::Relaxed)
    }

    /// Starts gathering, as `setLocalDescription` does: the host candidate
    /// now, returned for trickling (none when relay-only), and an
    /// allocation on each TURN server once its host resolves, whose relayed
    /// candidate comes as [`PeerEvent::LocalCandidate`]. A second call adds
    /// only the host candidate again.
    ///
    /// With ICE over TCP alone nothing is gathered (`Ok(None)`), as pion
    /// gathers nothing in a TCP network mode without a TCP mux: the TURN
    /// servers are left alone (their relayed candidates are UDP ones), and
    /// the local candidates come with the connections to the remote's.
    ///
    /// # Errors
    /// str0m refused the host candidate.
    pub fn gather(&self) -> Result<Option<String>, PeerError> {
        let turn = std::mem::take(&mut *lock(&self.sh.turn));
        if !self.sh.ice_mode.udp() {
            return Ok(None);
        }
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

    /// Adds a candidate the remote trickled; a `tcptype passive` one is
    /// dialled when the peer's ICE takes TCP.
    pub fn add_remote_candidate(&self, c: Candidate) {
        self.dial_if_passive(&c);
        self.with_rtc(|rtc| rtc.add_remote_candidate(c));
    }

    /// The remote's description was applied (`accept_offer`,
    /// `accept_answer`): dials every `tcptype passive` candidate `sdp`
    /// names, when the peer's ICE takes TCP, and returns how many dials it
    /// started. str0m keeps the description's candidates to itself, so the
    /// owner passes the text; without this call a TCP-only peer never
    /// connects to an SFU that names its candidates in the SDP.
    pub fn remote_described(&self, sdp: &str) -> usize {
        if !self.sh.ice_mode.tcp() {
            return 0;
        }
        sdp.lines()
            .filter_map(|l| l.trim_end().strip_prefix("a="))
            .filter(|l| l.starts_with("candidate:"))
            .filter_map(|l| Candidate::from_sdp_string(l).ok())
            .filter(|c| self.dial_if_passive(c))
            .count()
    }

    /// Dials `c` when it is a passive TCP candidate of the socket's family
    /// not dialled before, the peer's ICE takes TCP and fewer than
    /// [`MAX_DIALS`] were dialled; whether a dial started. Remote `active`
    /// and `so` candidates are left alone, as pion leaves them.
    fn dial_if_passive(&self, c: &Candidate) -> bool {
        let addr = c.addr();
        if !self.sh.ice_mode.tcp()
            || c.proto() != Protocol::Tcp
            || c.tcptype() != Some(TcpType::Passive)
            || addr.is_ipv4() != self.sh.local.is_ipv4()
            || self.is_ended()
        {
            return false;
        }
        {
            let mut asked = lock(&self.sh.tcp_asked);
            if asked.contains(&addr) {
                return false;
            }
            if asked.len() >= MAX_DIALS {
                olc_net::debug!(
                    "webrtc: {} ice tcp: {addr} not dialled, {MAX_DIALS} dialled already",
                    self.sh.name
                );
                return false;
            }
            asked.push(addr);
            // Counted before the task exists, under the list's lock: the
            // driver never sees a dialled address with no dial counted.
            self.sh.tcp_dialing.fetch_add(1, Ordering::AcqRel);
        }
        let sh = Arc::downgrade(&self.sh);
        let name = self.sh.name;
        tokio::spawn(async move {
            // A protected socket, where pion's dialer is a plain one bound
            // to the interface: the connection must not enter the tunnel.
            let dialled = olc_net::net::dial_tcp_with(addr, Some(crate::icetcp::SNDBUF)).await;
            // A peer that went meanwhile takes nothing: the stream closes
            // here.
            let Some(sh) = sh.upgrade() else { return };
            match dialled {
                Ok(stream) => {
                    // Go's default for a TCP connection: packets go as
                    // they are written.
                    let _ = stream.set_nodelay(true);
                    // Queued and out of the count in one step: see
                    // `Shared::tcp_dialing`.
                    let mut ready = lock(&sh.tcp_ready);
                    if !sh.ended.load(Ordering::Acquire) {
                        ready.push((stream, false));
                    }
                    #[cfg(test)]
                    dial_mid(&sh);
                    sh.tcp_dialing.fetch_sub(1, Ordering::AcqRel);
                }
                Err(e) => {
                    olc_net::debug!("webrtc: {name} ice tcp: dial {addr}: {e}");
                    // Out of the count, then the failure: see
                    // `Shared::tcp_dial_failed`.
                    sh.tcp_dialing.fetch_sub(1, Ordering::AcqRel);
                    #[cfg(test)]
                    dial_mid(&sh);
                    *lock(&sh.tcp_dial_failed) = Some(format!("ice tcp {addr}: dial: {e}"));
                }
            }
            sh.kick.notify_one();
        });
        true
    }

    /// The transports this peer's ICE uses.
    #[must_use]
    pub fn ice_mode(&self) -> IceMode {
        self.sh.ice_mode
    }

    /// Datagrams given to the UDP socket so far, to the remote or to a TURN
    /// server, sent or refused. It stays 0 for a peer whose ICE is TCP
    /// alone.
    #[must_use]
    pub fn udp_out(&self) -> u64 {
        self.sh.udp_out.load(Ordering::Relaxed)
    }

    /// Datagrams read off the UDP socket so far, whoever sent them. A peer
    /// whose ICE is TCP alone reads them and drops them.
    #[must_use]
    pub fn udp_in(&self) -> u64 {
        self.sh.udp_in.load(Ordering::Relaxed)
    }

    /// Packets ICE-TCP dropped so far: for a pair of candidates no
    /// connection joins (ICE tries every local one with every remote one),
    /// or on a connection whose socket took nothing for longer than
    /// [`crate::icetcp::STALL_MAX`].
    #[must_use]
    pub fn tcp_dropped(&self) -> u64 {
        self.sh.tcp_dropped.load(Ordering::Relaxed)
    }

    /// RTP packets a send line refused so far, its stream holding
    /// [`crate::media::SEND_BACKLOG_PACKETS`] already or the packet longer
    /// than [`crate::media::SEND_PACKET_MAX`]: dropped as a full UDP socket
    /// drops them.
    #[must_use]
    pub fn rtp_refused(&self) -> u64 {
        self.sh.rtp_refused.load(Ordering::Relaxed)
    }

    /// Counts RTP packets a send line refused ([`Peer::rtp_refused`]).
    pub(crate) fn note_rtp_refused(&self, packets: usize) {
        let n = u64::try_from(packets).unwrap_or(u64::MAX);
        self.sh.rtp_refused.fetch_add(n, Ordering::Relaxed);
    }

    /// Times so far an ICE-TCP socket took only part of a packet and the
    /// peer waited for it to take the rest (where pion's write blocks).
    #[must_use]
    pub fn tcp_stalls(&self) -> u64 {
        self.sh.tcp_stalls.load(Ordering::Relaxed)
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

/// Tests: the passive end of ICE-TCP, which no carrier's client is.
#[cfg(test)]
impl Peer {
    /// Listens on the peer's address and returns the local `tcp` /
    /// `tcptype passive` host candidate of the listener; every connection
    /// accepted becomes one of the driver's. With `recv_buffer` the
    /// accepted sockets' kernel receive buffer is that small (a far end
    /// that takes little at a time).
    pub(crate) fn listen_tcp(&self, recv_buffer: Option<u32>) -> Candidate {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        if let Some(n) = recv_buffer {
            socket.set_recv_buffer_size(n).unwrap();
        }
        socket.bind(SocketAddr::new(self.sh.local.ip(), 0)).unwrap();
        let ln = socket.listen(8).unwrap();
        let c = Candidate::builder()
            .tcp()
            .host(ln.local_addr().unwrap())
            .tcptype(TcpType::Passive)
            .build()
            .unwrap();
        let c = self
            .with_rtc(|rtc| rtc.add_local_candidate(c).cloned())
            .unwrap();
        let sh = Arc::downgrade(&self.sh);
        tokio::spawn(async move {
            while let Ok((stream, _)) = ln.accept().await {
                let _ = stream.set_nodelay(true);
                let Some(sh) = sh.upgrade() else { return };
                lock(&sh.tcp_ready).push((stream, true));
                sh.kick.notify_one();
            }
        });
        c
    }

    /// Closes the driver's ICE-TCP connections under the live peer: the
    /// far end sees its connection end with no DTLS goodbye.
    pub(crate) fn cut_tcp(&self) {
        self.sh.tcp_cut.store(true, Ordering::Release);
        self.sh.kick.notify_one();
    }

    /// The ICE-TCP connections the driver held at its last turn, and how
    /// many of them a packet had arrived on.
    pub(crate) fn tcp_conns(&self) -> (usize, usize) {
        *lock(&self.sh.tcp_counts)
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
    conns: &mut Conns,
    events: &mut Vec<Event>,
) -> Result<Instant, String> {
    let mut rtc = lock(&sh.rtc);
    let now = Instant::now();
    loop {
        // An ICE-TCP socket that took only part of a packet: nothing more
        // comes out of str0m until the rest has gone (pion's write blocks
        // its caller), so str0m keeps what it has and nothing is dropped.
        if conns.held_back(now) {
            sh.tcp_dropped.store(conns.dropped(), Ordering::Relaxed);
            return Ok(now + crate::icetcp::STALL_POLL);
        }
        match rtc.poll_output().map_err(|e| format!("poll: {e}"))? {
            Output::Timeout(t) => {
                sh.tcp_dropped.store(conns.dropped(), Ordering::Relaxed);
                return Ok(t);
            }
            // From a TCP candidate: on the connection of its two addresses,
            // never on the UDP socket.
            Output::Transmit(t) if t.proto != Protocol::Udp => {
                conns.send(t.source, t.destination, &t.contents, now);
            }
            Output::Transmit(t) => {
                sh.udp_out.fetch_add(1, Ordering::Relaxed);
                if relays.send(sock, t.source, t.destination, &t.contents, now) {
                    if let Some((server, e)) = relays.take_refused() {
                        note_refused(sh, sh.local, server, &e);
                    }
                } else if let Err(e) = sock.try_send_to(&t.contents, t.destination) {
                    note_refused(sh, sh.local, t.destination, &e);
                }
            }
            Output::Event(e) => {
                if let Event::RtpPacket(p) = &e {
                    if crate::media::is_video(rtc.codec_config(), p.header.payload_type) {
                        sh.video_in.fetch_add(1, Ordering::Relaxed);
                    }
                }
                events.push(e);
            }
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
/// UDP, 1 over TCP, 0 over TLS: libwebrtc's `ICE_TYPE_PREFERENCE_RELAY_*`), so
/// ICE prefers a relay over UDP, then TCP, then TLS, as Chrome does.
fn relayed_candidate(
    relayed: SocketAddr,
    base: SocketAddr,
    via: TurnTransport,
) -> Result<Candidate, String> {
    let via = match via {
        TurnTransport::Udp => is::Protocol::Udp,
        TurnTransport::Tcp => is::Protocol::Tcp,
        TurnTransport::Tls => is::Protocol::Tls,
    };
    Candidate::relayed_via(relayed, base, "udp", via).map_err(|e| e.to_string())
}

/// Takes the streams that connected since the last turn: each becomes one
/// of the driver's connections and, unless it was accepted (tests), a local
/// `tcp` / `tcptype active` host candidate at its own address, which ICE
/// pairs with the remote's TCP candidates. It is not trickled: pion's
/// remote ignores an active candidate and learns the address from the first
/// check (a peer reflexive one).
fn tcp_joined(sh: &Shared, conns: &mut Conns) {
    let ready = std::mem::take(&mut *lock(&sh.tcp_ready));
    for (stream, accepted) in ready {
        #[cfg(test)]
        let stream = (!sh.tcp_refuse.swap(false, Ordering::AcqRel)).then_some(stream);
        #[cfg(not(test))]
        let stream = Some(stream);
        let Some((local, remote)) = stream.and_then(|s| conns.add(s)) else {
            olc_net::debug!("webrtc: {} ice tcp: a connection too many, closed", sh.name);
            // One too many, a second between the same two addresses, or
            // one that was reset as it came (it has no addresses left). The
            // last may have been the only one: the driver asks what is left.
            if !accepted {
                *lock(&sh.tcp_dial_failed) =
                    Some("ice tcp: a connection ended as it was made".into());
            }
            continue;
        };
        olc_net::debug!("webrtc: {} ice tcp: {local} -> {remote} connected", sh.name);
        if accepted {
            continue;
        }
        let made = Candidate::builder()
            .tcp()
            .host(local)
            .tcptype(TcpType::Active)
            .build();
        match made {
            Ok(c) => {
                if lock(&sh.rtc).add_local_candidate(c).is_none() {
                    olc_net::debug!("webrtc: {} ice tcp: str0m refused {local}", sh.name);
                }
            }
            Err(e) => olc_net::debug!("webrtc: {} ice tcp: candidate {local}: {e}", sh.name),
        }
    }
}

/// Removes the ICE-TCP connections that ended; `heard` turns true when one
/// of them had a packet arrive on it. Returns the last one's end, in the
/// words [`PeerEvent::Failed`] carries.
fn tcp_lost(sh: &Shared, conns: &mut Conns, heard: &mut bool) -> Option<String> {
    let mut last = None;
    while let Some(lost) = conns.take_lost() {
        olc_net::debug!(
            "webrtc: {} ice tcp: {} -> {} ended: {}",
            sh.name,
            lost.local,
            lost.remote,
            lost.why
        );
        *heard |= lost.heard;
        last = Some(format!("ice tcp {}: {}", lost.remote, lost.why));
    }
    last
}

/// Whether ICE over TCP still has something: a connection held, a stream
/// waiting for the driver, or a dial on its way.
fn tcp_left(sh: &Shared, conns: &Conns) -> bool {
    // The count and the queue under the queue's lock: see
    // `Shared::tcp_dialing`.
    let ready = lock(&sh.tcp_ready);
    sh.tcp_dialing.load(Ordering::Acquire) > 0 || !ready.is_empty() || conns.len() > 0
}

/// The rule of [`PeerEvent::Failed`], asked when an ICE-TCP connection
/// ended or a dial failed (plan D7: at once, where pion waits out its
/// unanswered checks; same wire, the rejoin sooner). `tcp_left`: a
/// connection, or a dial on its way, remains. `tcp_heard`: a connection
/// that ended had carried packets. `udp_quiet_for`: how long ago the UDP
/// path was heard on, `None` for never.
///
/// - Something of TCP's left: not failed, heard on or not (a second
///   passive candidate may still answer).
/// - TCP alone: failed, whether or not a packet ever came (a refused dial,
///   a connection reset before its first answer: the ICE agent would stay
///   `checking` for good).
/// - Both: failed when a connection had been heard on and the UDP path
///   has not within [`PATH_HEARD_WITHIN`]. A TCP path that never worked
///   leaves the UDP candidates to ICE.
fn path_failed(
    mode: IceMode,
    tcp_left: bool,
    tcp_heard: bool,
    udp_quiet_for: Option<Duration>,
) -> bool {
    if tcp_left || !mode.tcp() {
        return false;
    }
    if !mode.udp() {
        return true;
    }
    tcp_heard && udp_quiet_for.is_none_or(|quiet| quiet >= PATH_HEARD_WITHIN)
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
    let mut conns = Conns::default();
    // When the UDP socket (or a relay's stream) last brought something
    // str0m took for this peer's; never stamped by a peer whose ICE is TCP
    // alone.
    let mut udp_heard: Option<Instant> = None;
    // Whether an ICE-TCP connection that ended had carried packets.
    let mut tcp_heard = false;
    let mut failed_said = false;
    let mut held = false;
    let mut drain_until: Option<Instant> = None;
    let reason: String = 'run: loop {
        #[cfg(test)]
        sh.turns.fetch_add(1, Ordering::Relaxed);
        if let Some(servers) = lock(&sh.turn_ready).take() {
            relays = Relays::new(&servers, sh.local, Instant::now(), &stream_tx);
        }
        // New TCP candidates reach str0m before it polls, too.
        tcp_joined(&sh, &mut conns);
        #[cfg(test)]
        if sh.tcp_cut.swap(false, Ordering::AcqRel) {
            conns.cut();
        }
        // New relayed candidates reach str0m before it polls, so its checks
        // from them start now.
        run_relays(&sh, &sock, &mut relays, &mut lines);
        let wake = match pump(&sh, &sock, &mut relays, &mut conns, &mut events) {
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
                // PLI and FIR alike, as Go's carriers take them; no rate
                // limit here (the owner's writer has its own).
                Event::KeyframeRequest(r) => PeerEvent::KeyframeRequest(r),
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
                Event::RtpPacket(p) => {
                    if let Some(sink) = sh
                        .rtp
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .as_mut()
                    {
                        sink(&p);
                    }
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
        // A connection that ended, or a dial that failed: is anything left?
        let ended = tcp_lost(&sh, &mut conns, &mut tcp_heard);
        let undialled = lock(&sh.tcp_dial_failed).take();
        if let Some(why) = ended.or(undialled) {
            // A closing peer's connections end with it: no failure then.
            if !failed_said
                && !sh.closing.load(Ordering::Acquire)
                && path_failed(
                    sh.ice_mode,
                    tcp_left(&sh, &conns),
                    tcp_heard,
                    udp_heard.map(|t| t.elapsed()),
                )
            {
                failed_said = true;
                olc_net::debug!("webrtc: {} peer connection failed: {why}", sh.name);
                if tx.send(PeerEvent::Failed(why)).await.is_err() {
                    break 'run "the owner went".into();
                }
            }
        }
        #[cfg(test)]
        {
            *lock(&sh.tcp_counts) = (conns.len(), conns.heard());
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
        // Held back by an ICE-TCP socket: str0m was not polled to its end,
        // so it is given nothing either (its DTLS queues only a few records
        // between two polls) until the socket takes the rest, or the hold
        // runs out ([`crate::icetcp::STALL_MAX`]).
        if conns.held_back(now) {
            if !held {
                held = true;
                sh.tcp_stalls.fetch_add(1, Ordering::Relaxed);
            }
            tokio::select! {
                (i, what) = conns.ready(false) => {
                    let _ = conns.turn(i, what, |_, _, _| Ok::<(), String>(()));
                }
                () = tokio::time::sleep(crate::icetcp::STALL_POLL) => {}
            }
            continue;
        }
        held = false;
        tokio::select! {
            got = recv(&sh, &sock, &mut buf) => match got {
                // A peer whose ICE is TCP alone has no UDP candidate:
                // whatever reaches its socket is nobody's, and is dropped
                // before str0m sees it.
                Ok(_) if !sh.ice_mode.udp() => {}
                Ok((n, src)) => {
                    let now = Instant::now();
                    let fed = match relays.recv(src, &buf[..n], now) {
                        Arrival::Direct => feed_udp(&sh, now, Receive::new(Protocol::Udp, src, sh.local, &buf[..n])),
                        // The TURN server's own words are no packet of the
                        // peer's.
                        Arrival::Handled => Ok(false),
                        Arrival::Relayed { relayed, data } => feed_udp(
                            &sh,
                            now,
                            Receive::new(Protocol::Udp, data.peer, relayed, data.data()),
                        ),
                    };
                    match fed {
                        Ok(true) => udp_heard = Some(now),
                        Ok(false) => {}
                        Err(e) => break 'run e,
                    }
                }
                Err(e) if matches!(e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) => {}
                Err(e) => break 'run format!("recv: {e}"),
            },
            Some(chunk) = stream_rx.recv() => {
                let now = Instant::now();
                let mut fed = Ok(false);
                relays.recv_stream(&chunk, now, |relayed, peer, data| {
                    if let Ok(heard) = fed {
                        fed = feed_udp(&sh, now, Receive::new(Protocol::Udp, peer, relayed, data))
                            .map(|took| took || heard);
                    }
                });
                match fed {
                    Ok(true) => udp_heard = Some(now),
                    Ok(false) => {}
                    Err(e) => break 'run e,
                }
            }
            (i, what) = conns.ready(true) => {
                let now = Instant::now();
                let fed = conns.turn(i, what, |from, to, packet| {
                    feed(&sh, now, Receive::new(Protocol::Tcp, from, to, packet)).map(|_| ())
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
    if sh.ice_mode.tcp() {
        olc_net::debug!(
            "webrtc: {} ice over {}: {} UDP datagrams out, {} TCP packets dropped, \
             {} RTP packets refused at a full send line",
            sh.name,
            sh.ice_mode.as_str(),
            sh.udp_out.load(Ordering::Relaxed),
            conns.dropped(),
            sh.rtp_refused.load(Ordering::Relaxed)
        );
    }
    let _ = tx.send(PeerEvent::Closed(reason)).await;
}

/// One datagram off the peer's UDP socket, counted ([`Peer::udp_in`]).
async fn recv(sh: &Shared, sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    let got = sock.recv_from(buf).await;
    if got.is_ok() {
        sh.udp_in.fetch_add(1, Ordering::Relaxed);
    }
    got
}

/// [`feed`] for a datagram that came over UDP, off the peer's socket or
/// through a relay.
fn feed_udp<E>(sh: &Shared, now: Instant, r: Result<Receive<'_>, E>) -> Result<bool, String> {
    #[cfg(test)]
    sh.udp_fed.fetch_add(1, Ordering::Relaxed);
    feed(sh, now, r)
}

/// Hands str0m one datagram (one it cannot parse is dropped, as before).
/// `Ok(true)` for one str0m takes for this peer's (`Rtc::accepts`: from the
/// nominated address, a STUN message with the peer's credentials, or from
/// a remote candidate): what counts as a path heard on. The others are
/// handed over all the same, as before.
fn feed<E>(sh: &Shared, now: Instant, r: Result<Receive<'_>, E>) -> Result<bool, String> {
    let Ok(r) = r else { return Ok(false) };
    let input = Input::Receive(now, r);
    let mut rtc = lock(&sh.rtc);
    let ours = rtc.accepts(&input);
    rtc.handle_input(input).map_err(|e| format!("input: {e}"))?;
    Ok(ours)
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
        let tls = relayed_candidate(relayed, base, TurnTransport::Tls).unwrap();
        assert_eq!(udp.prio() >> 24, 2, "{}", udp.to_sdp_string());
        assert_eq!(tcp.prio() >> 24, 1, "{}", tcp.to_sdp_string());
        assert_eq!(tls.prio() >> 24, 0, "{}", tls.to_sdp_string());
        for c in [&udp, &tcp, &tls] {
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
            ice_mode: IceMode::Udp,
        }
    }

    /// `a` offers one reliable channel and `b` answers; returns its id.
    fn negotiate(a: &Peer, b: &Peer) -> ChannelId {
        negotiate_lines(a, b, false).0
    }

    /// `a` offers one reliable channel and, with `video`, a video line both
    /// ways; `b` answers. Returns the channel's id and the line's mid.
    fn negotiate_lines(a: &Peer, b: &Peer, video: bool) -> (ChannelId, Option<str0m::media::Mid>) {
        use str0m::media::{Direction, MediaKind};
        let (offer, pending, id) = a.with_rtc(|rtc| {
            let mut api = rtc.sdp_api();
            let id = api.add_channel_with_config(ChannelConfig {
                label: "_reliable".into(),
                ordered: true,
                reliability: Reliability::Reliable,
                negotiated: None,
                protocol: String::new(),
            });
            let mid = video
                .then(|| api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None));
            let (offer, pending) = api.apply().unwrap();
            (offer, pending, (id, mid))
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
            entry.password = String::from("not-the-password").into();
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

    /// Two peers whose ICE is `mode_a` and `mode_b`, `b` listening for
    /// ICE-TCP (the passive end, as an SFU is) and `a` told of it; with UDP
    /// in both modes the host candidates are exchanged too. Returns both
    /// once the channel `a` offered is open at both ends.
    async fn tcp_pair(
        mode_a: IceMode,
        mode_b: IceMode,
        recv_buffer: Option<u32>,
    ) -> (
        Peer,
        mpsc::Receiver<PeerEvent>,
        Peer,
        mpsc::Receiver<PeerEvent>,
        ChannelId,
    ) {
        let (a, a_rx, b, b_rx, id, _) = tcp_pair_with(mode_a, mode_b, recv_buffer, false).await;
        (a, a_rx, b, b_rx, id)
    }

    /// [`tcp_pair`], with a video line both ways beside the channel when
    /// `video`; returns its mid too.
    async fn tcp_pair_with(
        mode_a: IceMode,
        mode_b: IceMode,
        recv_buffer: Option<u32>,
        video: bool,
    ) -> (
        Peer,
        mpsc::Receiver<PeerEvent>,
        Peer,
        mpsc::Receiver<PeerEvent>,
        ChannelId,
        Option<str0m::media::Mid>,
    ) {
        crate::init();
        let cfg = |name, ice_mode| PeerConfig {
            ice_mode,
            ..config(name, 1 << 20)
        };
        let (a, mut a_rx) = Peer::start(&cfg("a", mode_a)).unwrap();
        let (b, mut b_rx) = Peer::start(&cfg("b", mode_b)).unwrap();
        let (id, mid) = negotiate_lines(&a, &b, video);
        if let (Some(ca), Some(cb)) = (a.gather().unwrap(), b.gather().unwrap()) {
            a.add_remote_candidate(Candidate::from_sdp_string(&cb).unwrap());
            b.add_remote_candidate(Candidate::from_sdp_string(&ca).unwrap());
        }
        let passive = b.listen_tcp(recv_buffer);
        assert!(passive.to_sdp_string().contains(" tcptype passive"));
        // As an SFU's answer names it; the UDP line beside it is not dialled.
        let sdp = format!(
            "v=0\r\na=candidate:1 1 udp 2130706431 127.0.0.1 9 typ host\r\na={}\r\n",
            passive.to_sdp_string()
        );
        assert_eq!(a.remote_described(&sdp), 1);
        assert_eq!(a.remote_described(&sdp), 0, "a candidate is dialled once");
        a.add_remote_candidate(passive);
        both_open(&mut a_rx, &mut b_rx).await;
        (a, a_rx, b, b_rx, id, mid)
    }

    /// Runs one step of a two-peer test under a bound of its own, and says
    /// where both peers stood when it ran out.
    async fn step<F: std::future::Future>(what: &str, a: &Peer, b: &Peer, f: F) -> F::Output {
        let state = |p: &Peer| {
            format!(
                "connected {}, ended {}, udp out {}, tcp dropped {}, refused {}",
                p.is_connected(),
                p.is_ended(),
                p.udp_out(),
                p.tcp_dropped(),
                p.send_refused()
            )
        };
        match tokio::time::timeout(Duration::from_secs(8), f).await {
            Ok(out) => out,
            Err(_) => panic!("{what}: not within 8 s; a: {}; b: {}", state(a), state(b)),
        }
    }

    /// Waits for the driver's end on `rx` and returns its reason.
    async fn ended(rx: &mut mpsc::Receiver<PeerEvent>) -> String {
        loop {
            match rx.recv().await {
                Some(PeerEvent::Closed(why)) => return why,
                Some(PeerEvent::Failed(why)) => return format!("failed: {why}"),
                Some(_) => {}
                None => return "the queue closed".into(),
            }
        }
    }

    /// Whether `rx` brings [`PeerEvent::Failed`] within `within`.
    async fn fails_within(rx: &mut mpsc::Receiver<PeerEvent>, within: Duration) -> Option<String> {
        tokio::time::timeout(within, async {
            loop {
                match rx.recv().await {
                    Some(PeerEvent::Failed(why)) => return why,
                    Some(PeerEvent::Closed(r)) => panic!("closed: {r}"),
                    Some(_) => {}
                    None => panic!("the queue closed"),
                }
            }
        })
        .await
        .ok()
    }

    /// ICE over TCP alone (the MTS Link client's default): the peer
    /// gathers nothing, dials the remote's passive candidate, and the
    /// vendored `is` agent nominates the active-to-passive pair. Messages
    /// pass whole both ways, and neither end gives its UDP socket one
    /// datagram.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ice_over_tcp_alone_connects_and_sends_no_udp() {
        bounded(async {
            let (a, mut a_rx, b, mut b_rx, id) = tcp_pair(IceMode::Tcp, IceMode::Tcp, None).await;
            assert!(a.is_connected() && b.is_connected());
            assert_eq!(a.ice_mode(), IceMode::Tcp);
            assert!(a.gather().unwrap().is_none());
            assert!(a.add_host_candidate().is_err());
            // The sender's own end is told too (its queue is not read by
            // `send_through`).
            tokio::select! {
                () = step("a to b", &a, &b, send_through(&a, &mut b_rx, id, 60, 12_000)) => {}
                why = ended(&mut a_rx) => panic!("a ended while it sent: {why}"),
            }
            tokio::select! {
                () = step("b to a", &a, &b, send_through(&b, &mut a_rx, id, 60, 12_000)) => {}
                why = ended(&mut b_rx) => panic!("b ended while it sent: {why}"),
            }
            assert_eq!(a.udp_out(), 0, "the active end sent UDP");
            assert_eq!(b.udp_out(), 0, "the passive end sent UDP");
            assert_eq!((a.send_refused(), b.send_refused()), (0, 0));
            assert_eq!(a.tcp_dropped(), 0);
            a.close();
            b.close();
            // A closing peer's connections end with it: no failure is told.
            step("a's end", &a, &b, async {
                loop {
                    match a_rx.recv().await.unwrap() {
                        PeerEvent::Failed(why) => panic!("a closing peer failed: {why}"),
                        PeerEvent::Closed(_) => break,
                        _ => {}
                    }
                }
            })
            .await;
        })
        .await;
    }

    /// A far end that takes little at a time (a small receive buffer, and
    /// every packet decrypted before the next is read), and nothing at all
    /// from its first packet until the sender's socket has refused one,
    /// while the sender writes 600 RTP packets at once: the sender's socket
    /// refuses packets again and again, and each time the peer waits for it
    /// to take the rest, as pion's write blocks, instead of dropping. Every
    /// packet arrives, in order; none was dropped.
    ///
    /// The stall is made, not hoped for: the 600 packets (660 KB) are several
    /// times what the two kernel buffers hold (128 KiB to send, 4 KiB to
    /// receive), and the far driver stops in its sink at the first packet
    /// until [`Peer::tcp_stalls`] says the socket refused one. No clock
    /// decides it. (At first nothing held the far end, and whether the
    /// socket filled was a race between the two drivers over about 55 ms:
    /// measured on the build box, it filled in 4 runs of 6, and in 2 of 6
    /// beside three busy threads. Then a 300 ms hold of the far peer's lock
    /// decided it, against the clock of [`crate::icetcp::STALL_MAX`].)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_tcp_socket_holds_the_peer_back_and_loses_nothing() {
        use str0m::format::Codec;
        use str0m::rtp::{RtpWrite, SeqNo};
        const PACKETS: u64 = 600;

        bounded(async {
            let (a, mut a_rx, b, _b_rx, _id, mid) =
                tcp_pair_with(IceMode::Tcp, IceMode::Tcp, Some(4096), true).await;
            let mid = mid.unwrap();
            // What arrived, and how many of them out of their order.
            let seen = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
            let sink = seen.clone();
            let sender = a.clone();
            b.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
                let at = sink.0.fetch_add(1, Ordering::Relaxed);
                if at == 0 {
                    // The far driver reads nothing more until the sender's
                    // socket is full. The bound only ends a run in which it
                    // never fills, which the last assertion then reports.
                    let give_up = Instant::now() + Duration::from_secs(5);
                    while sender.tcp_stalls() == 0 && Instant::now() < give_up {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                let want = u16::try_from(1000 + at).unwrap();
                if p.header.sequence_number != want || p.payload.len() != 1100 {
                    sink.1.fetch_add(1, Ordering::Relaxed);
                }
            })));
            let pt = a.with_rtc(|rtc| {
                rtc.codec_config()
                    .find(|p| p.spec().codec == Codec::Vp8)
                    .unwrap()
                    .pt()
            });
            a.with_rtc(|rtc| {
                let mut api = rtc.direct_api();
                let tx = api.stream_tx_by_mid(mid, None).unwrap();
                for i in 0..PACKETS {
                    tx.write_rtp(RtpWrite::new(
                        pt,
                        SeqNo::from(1000 + i),
                        3000 * u32::try_from(i).unwrap(),
                        Instant::now(),
                        vec![0x90; 1100],
                    ));
                }
            });
            let all = async {
                while seen.0.load(Ordering::Relaxed) < PACKETS {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            tokio::select! {
                () = step("600 packets", &a, &b, all) => {}
                why = ended(&mut a_rx) => panic!("a ended while it sent: {why}"),
            }
            assert_eq!(seen.1.load(Ordering::Relaxed), 0, "packets out of order");
            assert_eq!(
                a.tcp_dropped(),
                0,
                "packets were dropped at a stalled socket"
            );
            assert!(
                a.tcp_stalls() > 0,
                "the socket never stalled: the test did not see what it is for"
            );
            b.set_rtp_sink(None);
            a.close();
            b.close();
        })
        .await;
    }

    /// Review finding 1 (memory): a far end that takes about a thousand
    /// packets a second and a writer that offers ten times that, for three
    /// seconds, over ICE-TCP. The socket holds the driver back again and
    /// again, so what is written waits in str0m, whose queue has no bound:
    /// the send line refuses the batches that would pass
    /// [`crate::media::SEND_BACKLOG_PACKETS`], counts them, and what it
    /// took arrives whole and in order once the writer stops.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_slow_far_end_leaves_no_more_than_the_bound_in_the_send_line() {
        use crate::media::{RtpOut, SendLine, SEND_BACKLOG_PACKETS};
        use str0m::format::Codec;
        const BATCH: u16 = 40;

        bounded(async {
            let (a, mut a_rx, b, _b_rx, _id, mid) =
                tcp_pair_with(IceMode::Tcp, IceMode::Tcp, Some(4096), true).await;
            let mid = mid.unwrap();
            // How many arrived, how many behind their predecessor, the last
            // sequence number.
            let seen = Arc::new((AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)));
            let sink = seen.clone();
            b.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
                // A slow reader: the far driver takes a millisecond a packet.
                std::thread::sleep(Duration::from_millis(1));
                let seq = u64::from(p.header.sequence_number);
                let last = sink.2.swap(seq, Ordering::Relaxed);
                if sink.0.fetch_add(1, Ordering::Relaxed) > 0 && seq <= last {
                    sink.1.fetch_add(1, Ordering::Relaxed);
                }
            })));
            let pt = a.with_rtc(|rtc| {
                rtc.codec_config()
                    .find(|p| p.spec().codec == Codec::Vp8)
                    .unwrap()
                    .pt()
            });
            let mut line = SendLine::new(mid, None, pt);
            let (mut seq, mut offered, mut taken, mut worst) = (1000u16, 0usize, 0usize, 0usize);
            let writer = async {
                let until = Instant::now() + Duration::from_secs(3);
                while Instant::now() < until {
                    let batch: Vec<RtpOut> = (0..BATCH)
                        .map(|i| RtpOut {
                            seq: seq + i,
                            timestamp: 3000 * u32::from(seq + i),
                            marker: i + 1 == BATCH,
                            payload: vec![0x90; 1100],
                        })
                        .collect();
                    seq += BATCH;
                    offered += usize::from(BATCH);
                    taken += line.write(&a, Instant::now(), batch).unwrap();
                    worst = worst.max(line.backlog(&a).unwrap());
                    tokio::time::sleep(Duration::from_millis(4)).await;
                }
            };
            tokio::select! {
                () = writer => {}
                why = ended(&mut a_rx) => panic!("a ended while it sent: {why}"),
            }
            assert!(
                worst <= SEND_BACKLOG_PACKETS,
                "the send line held {worst} packets ({taken} of {offered} taken, {} refused, \
                 {} stalls): more than its bound of {SEND_BACKLOG_PACKETS}",
                a.rtp_refused(),
                a.tcp_stalls()
            );
            assert!(a.tcp_stalls() > 0, "the socket never stalled");
            assert!(taken < offered, "nothing was refused: the far end kept up");
            assert_eq!(
                a.rtp_refused(),
                u64::try_from(offered - taken).unwrap(),
                "the refused packets are counted"
            );
            assert_eq!(taken % usize::from(BATCH), 0, "a batch goes whole or not");
            let want = u64::try_from(taken).unwrap();
            let drained = async {
                while seen.0.load(Ordering::Relaxed) < want || line.backlog(&a) != Some(0) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            tokio::select! {
                () = step("what was taken arrives", &a, &b, drained) => {}
                why = ended(&mut a_rx) => panic!("a ended while it drained: {why}"),
            }
            assert_eq!(seen.0.load(Ordering::Relaxed), want);
            assert_eq!(seen.1.load(Ordering::Relaxed), 0, "packets out of order");
            assert_eq!(a.tcp_dropped(), 0, "ICE-TCP dropped what the line took");
            b.set_rtp_sink(None);
            a.close();
            b.close();
        })
        .await;
    }

    /// The remote's SDP as pion writes it (the overlay's engine over a TCP
    /// mux, 2026-11-15): each candidate once per component, the passive
    /// ones with a trailing `ufrag`, pion's own active one beside them. One
    /// dial: the passive IPv4 address, once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_remote_sdp_is_read_as_pion_writes_it() {
        bounded(async {
            crate::init();
            // A port nothing listens on: the dial is refused.
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let sdp = format!(
                "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=sendrecv\r\n\
                 a=candidate:375738803 1 tcp 1675624447 127.0.0.1 17413 typ host tcptype active\r\n\
                 a=candidate:375738803 2 tcp 1675624447 127.0.0.1 17413 typ host tcptype active\r\n\
                 a=candidate:375738803 1 tcp 1671430143 127.0.0.1 {port} typ host tcptype passive ufrag kGWfCJDnmfYiehkm\r\n\
                 a=candidate:375738803 2 tcp 1671430143 127.0.0.1 {port} typ host tcptype passive ufrag kGWfCJDnmfYiehkm\r\n\
                 a=candidate:1 1 udp 2130706431 127.0.0.1 {port} typ host\r\n\
                 a=candidate:2 1 tcp 1671430143 ::1 {port} typ host tcptype passive\r\n\
                 a=candidate:3 1 tcp 1671430143 127.0.0.1 {port} typ host tcptype so\r\n\
                 a=end-of-candidates\r\n"
            );
            let want: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            for mode in [IceMode::Tcp, IceMode::Both] {
                let (p, _rx) = Peer::start(&PeerConfig {
                    ice_mode: mode,
                    ..config("p", 1 << 20)
                })
                .unwrap();
                assert_eq!(p.remote_described(&sdp), 1, "{mode:?}");
                assert_eq!(*lock(&p.sh.tcp_asked), [want]);
                p.close();
            }
            let (p, _rx) = Peer::start(&config("p", 1 << 20)).unwrap();
            assert_eq!(p.remote_described(&sdp), 0, "a UDP peer dials nothing");
            p.close();
        })
        .await;
    }

    /// A UDP-only peer dials nothing, whatever the remote names.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_udp_peer_dials_no_tcp_candidate() {
        bounded(async {
            let (a, _a_rx, b, _b_rx, _id) = pair(1 << 20).await;
            let passive = b.listen_tcp(None);
            let sdp = format!("a={}\r\n", passive.to_sdp_string());
            assert_eq!(a.remote_described(&sdp), 0);
            a.add_remote_candidate(passive);
            assert!(lock(&a.sh.tcp_asked).is_empty());
            assert!(a.udp_out() > 0, "the UDP path was not counted");
            a.close();
            b.close();
        })
        .await;
    }

    /// Plan D7: the one ICE-TCP connection breaks with no DTLS goodbye, and
    /// the owner hears `Failed` at once, long before ICE would notice
    /// (str0m's disconnect takes seconds; pion's failed 30 s).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_broken_tcp_connection_fails_the_peer_at_once() {
        bounded(async {
            let (a, mut a_rx, b, _b_rx, _id) = tcp_pair(IceMode::Tcp, IceMode::Tcp, None).await;
            assert_eq!(
                fails_within(&mut a_rx, Duration::from_millis(300)).await,
                None
            );
            b.cut_tcp();
            let why = fails_within(&mut a_rx, Duration::from_secs(2))
                .await
                .expect("the lost connection was not told within 2 s");
            assert!(why.starts_with("ice tcp 127.0.0.1:"), "{why}");
            assert!(why.ends_with("read: EOF"), "{why}");
            // Said once, and the watcher takes it as failed without a wait.
            let mut w = crate::pcstate::PcWatcher::new();
            w.observe(&PeerEvent::Failed(why));
            let said = tokio::time::timeout(Duration::from_millis(100), w.failed()).await;
            assert_eq!(
                said.map(|c| c.pc),
                Ok(Some(crate::pcstate::PcState::Failed))
            );
            assert_eq!(
                fails_within(&mut a_rx, Duration::from_millis(500)).await,
                None
            );
            assert!(!a.is_ended(), "the driver runs on until it is closed");
            a.close();
            b.close();
        })
        .await;
    }

    /// The rule of `Failed`, case by case (reviews S1, S2, S4's mirror with
    /// the UDP path silent for longer than [`PATH_HEARD_WITHIN`]).
    #[test]
    fn the_last_path_rule() {
        let (fresh, stale) = (
            Some(PATH_HEARD_WITHIN - Duration::from_millis(1)),
            Some(PATH_HEARD_WITHIN),
        );
        // TCP alone: failed once nothing of TCP's is left, heard or not.
        assert!(path_failed(IceMode::Tcp, false, false, None));
        assert!(path_failed(IceMode::Tcp, false, true, None));
        // A connection or a dial that remains keeps every mode waiting.
        for mode in [IceMode::Tcp, IceMode::Both] {
            for heard in [false, true] {
                assert!(!path_failed(mode, true, heard, None), "{mode:?} {heard}");
                assert!(!path_failed(mode, true, heard, stale), "{mode:?} {heard}");
            }
        }
        // Both: a TCP path that worked, and a UDP path that is silent.
        assert!(path_failed(IceMode::Both, false, true, None));
        assert!(path_failed(IceMode::Both, false, true, stale));
        assert!(path_failed(
            IceMode::Both,
            false,
            true,
            Some(Duration::from_secs(60))
        ));
        assert!(!path_failed(IceMode::Both, false, true, fresh));
        assert!(!path_failed(
            IceMode::Both,
            false,
            true,
            Some(Duration::ZERO)
        ));
        // Both: a TCP path that never worked leaves the UDP candidates.
        assert!(!path_failed(IceMode::Both, false, false, None));
        assert!(!path_failed(IceMode::Both, false, false, stale));
        // A UDP peer has no ICE-TCP to lose.
        assert!(!path_failed(IceMode::Udp, false, true, None));
    }

    /// Waits (5 s at most) until `p`'s driver holds `conns` ICE-TCP
    /// connections, `heard` of them heard on.
    async fn holds(what: &str, p: &Peer, conns: usize, heard: usize) {
        let wait = async {
            while p.tcp_conns() != (conns, heard) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        if tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .is_err()
        {
            panic!(
                "{what}: the driver holds {:?} (connections, heard), not ({conns}, {heard})",
                p.tcp_conns()
            );
        }
    }

    /// A passive TCP candidate at `addr`, as an SFU's SDP names one.
    fn passive_sdp(addr: SocketAddr) -> String {
        format!(
            "v=0\r\na=candidate:1 1 tcp 1671430143 {} {} typ host tcptype passive\r\n",
            addr.ip(),
            addr.port()
        )
    }

    /// Sends a datagram no peer of `to` wrote, every 20 ms until dropped.
    fn strays(to: SocketAddr) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            loop {
                let _ = sock.send_to(&[0xff; 24], to).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }

    /// With both transports the UDP pair carries the peer (ICE's
    /// priorities), the TCP connection is checked beside it, and its loss
    /// fails nothing: the messages go on. The connection is seen heard on
    /// before it is cut, so the loss is one the rule judges: with the UDP
    /// path not counted, `Failed` comes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn with_both_a_lost_tcp_connection_leaves_the_udp_path() {
        bounded(async {
            let (a, mut a_rx, b, mut b_rx, id) = tcp_pair(IceMode::Both, IceMode::Both, None).await;
            assert!(a.udp_out() > 0);
            holds("before the cut", &a, 1, 1).await;
            send_through(&b, &mut a_rx, id, 5, 1000).await;
            b.cut_tcp();
            assert_eq!(
                fails_within(&mut a_rx, Duration::from_millis(700)).await,
                None
            );
            holds("after the cut", &a, 0, 0).await;
            send_through(&a, &mut b_rx, id, 20, 12_000).await;
            a.close();
            b.close();
        })
        .await;
    }

    /// The mirror: both transports asked for, but the far end has TCP
    /// alone, so nothing a peer of ours wrote ever comes on the UDP socket.
    /// The one connection's loss fails the peer at once, and datagrams from
    /// a stranger on the UDP socket do not pass for a path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn with_both_and_no_udp_path_a_lost_tcp_connection_fails_the_peer() {
        bounded(async {
            let (a, mut a_rx, b, _b_rx, _id) = tcp_pair(IceMode::Both, IceMode::Tcp, None).await;
            holds("before the cut", &a, 1, 1).await;
            let noise = strays(a.local_addr());
            assert_eq!(
                fails_within(&mut a_rx, Duration::from_millis(300)).await,
                None
            );
            b.cut_tcp();
            let why = fails_within(&mut a_rx, Duration::from_secs(2))
                .await
                .expect("the last path was lost and nobody was told within 2 s");
            assert!(why.ends_with("read: EOF"), "{why}");
            noise.abort();
            a.close();
            b.close();
        })
        .await;
    }

    /// Review S5: a TCP-only peer's UDP socket is no path. Datagrams that
    /// reach it from anyone do not keep the peer alive when its connection
    /// breaks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stray_datagram_is_no_path_for_a_tcp_only_peer() {
        bounded(async {
            let (a, mut a_rx, b, _b_rx, _id) = tcp_pair(IceMode::Tcp, IceMode::Tcp, None).await;
            holds("before the cut", &a, 1, 1).await;
            let noise = strays(a.local_addr());
            assert_eq!(
                fails_within(&mut a_rx, Duration::from_millis(300)).await,
                None
            );
            b.cut_tcp();
            let why = fails_within(&mut a_rx, Duration::from_secs(2))
                .await
                .expect("stray datagrams kept a TCP-only peer from failing");
            assert!(why.ends_with("read: EOF"), "{why}");
            noise.abort();
            assert_eq!(a.udp_out(), 0);
            a.close();
            b.close();
        })
        .await;
    }

    /// Wave 2 review S4: a TCP-only peer hands str0m nothing that came on
    /// its UDP socket. The datagrams are seen to arrive (the peer counts
    /// what it reads) and none of them is fed; the same datagrams at a peer
    /// whose ICE takes UDP are fed, every one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tcp_only_peer_hands_str0m_no_udp_datagram() {
        async fn reads(p: &Peer, datagrams: u64) {
            let wait = async {
                while p.udp_in() < datagrams {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            if tokio::time::timeout(Duration::from_secs(5), wait)
                .await
                .is_err()
            {
                panic!("{} of {datagrams} datagrams read in 5 s", p.udp_in());
            }
        }
        bounded(async {
            let (a, _a_rx, b, _b_rx, _id) = tcp_pair(IceMode::Tcp, IceMode::Tcp, None).await;
            holds("connected", &a, 1, 1).await;
            let noise = strays(a.local_addr());
            reads(&a, 10).await;
            noise.abort();
            assert_eq!(
                a.sh.udp_fed.load(Ordering::Relaxed),
                0,
                "a TCP-only peer handed str0m a datagram of its UDP socket"
            );
            a.close();
            b.close();

            let (u, _u_rx) = Peer::start(&config("u", 1 << 20)).unwrap();
            let noise = strays(u.local_addr());
            reads(&u, 10).await;
            noise.abort();
            let fed = u.sh.udp_fed.load(Ordering::Relaxed);
            assert!(fed >= 10, "a UDP peer was fed {fed} of 10");
            u.close();
        })
        .await;
    }

    /// A dial's task between its two steps: the driver is woken (from a
    /// thread that is no worker's, so the wake is another worker's to
    /// take) and has turned twice more before the task goes on.
    fn turn_the_driver(sh: &Shared) {
        let before = sh.turns.load(Ordering::Relaxed);
        let until = Instant::now() + Duration::from_secs(3);
        while sh.turns.load(Ordering::Relaxed) < before + 2 {
            assert!(Instant::now() < until, "the driver did not turn");
            std::thread::scope(|s| {
                s.spawn(|| sh.kick.notify_one());
            });
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wave 2 review S1: a dial's failure is left for the driver only once
    /// the dial is out of the count. Here the driver turns between the
    /// task's two steps: told of the failure while the dial still counted,
    /// it found "something of TCP's left", dropped the reason and was never
    /// asked again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_dial_is_told_once_it_left_the_count() {
        bounded(async {
            crate::init();
            let closed = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let (p, mut rx) = Peer::start(&PeerConfig {
                ice_mode: IceMode::Tcp,
                ..config("p", 1 << 20)
            })
            .unwrap();
            *lock(&p.sh.tcp_dial_mid) = Some(Box::new(turn_the_driver));
            assert_eq!(p.remote_described(&passive_sdp(closed)), 1);
            let why = fails_within(&mut rx, Duration::from_secs(5))
                .await
                .expect("the driver turned between a failed dial's two steps and nobody was told");
            assert!(
                why.starts_with(&format!("ice tcp {closed}: dial: ")),
                "{why}"
            );
            p.close();
        })
        .await;
    }

    /// Wave 2 review S1, the other window: the driver takes a dial's
    /// stream and cannot keep it (reset as it came). The stream and the
    /// dial's leaving the count are one step to the driver, so what it asks
    /// then finds no dial left: `Failed`. The task stays between its two
    /// steps for 300 ms with the driver woken; were they two steps to the
    /// driver, it would refuse the stream with the dial still counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stream_the_driver_cannot_keep_fails_a_tcp_only_peer() {
        bounded(async {
            crate::init();
            let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = ln.local_addr().unwrap();
            let (p, mut rx) = Peer::start(&PeerConfig {
                ice_mode: IceMode::Tcp,
                ..config("p", 1 << 20)
            })
            .unwrap();
            p.sh.tcp_refuse.store(true, Ordering::Release);
            *lock(&p.sh.tcp_dial_mid) = Some(Box::new(|sh: &Shared| {
                std::thread::scope(|s| {
                    s.spawn(|| sh.kick.notify_one());
                });
                std::thread::sleep(Duration::from_millis(300));
            }));
            assert_eq!(p.remote_described(&passive_sdp(at)), 1);
            let why = fails_within(&mut rx, Duration::from_secs(3))
                .await
                .expect("a stream refused while its dial still counted was never told");
            assert_eq!(why, "ice tcp: a connection ended as it was made");
            assert!(!p.sh.tcp_refuse.load(Ordering::Acquire), "refused once");
            drop(ln);
            p.close();
        })
        .await;
    }

    /// Review S1, first scenario: the one passive candidate refuses the
    /// dial (MTS Link's 443/tcp closed to this network). A TCP-only peer
    /// has no path and none coming: the owner hears `Failed`, where the
    /// ICE agent would stay `checking` for good. With both transports the
    /// UDP candidates may still connect: nothing is said.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_dial_fails_a_tcp_only_peer() {
        bounded(async {
            crate::init();
            // A port nothing listens on.
            let closed = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let sdp = passive_sdp(closed);
            let start = |ice_mode| {
                Peer::start(&PeerConfig {
                    ice_mode,
                    ..config("p", 1 << 20)
                })
                .unwrap()
            };
            let (p, mut rx) = start(IceMode::Tcp);
            assert_eq!(p.remote_described(&sdp), 1);
            let why = fails_within(&mut rx, Duration::from_secs(2))
                .await
                .expect("a TCP-only peer whose only dial was refused was not failed");
            assert!(
                why.starts_with(&format!("ice tcp {closed}: dial: ")),
                "{why}"
            );
            assert_eq!(
                fails_within(&mut rx, Duration::from_millis(300)).await,
                None,
                "said once"
            );
            assert!(!p.is_ended(), "the driver runs on until it is closed");
            p.close();

            let (p, mut rx) = start(IceMode::Both);
            assert_eq!(p.remote_described(&sdp), 1);
            assert_eq!(
                fails_within(&mut rx, Duration::from_millis(700)).await,
                None,
                "with both transports a refused dial leaves the UDP candidates"
            );
            p.close();
        })
        .await;
    }

    /// Review S1, second scenario: the connection is accepted and closed
    /// before one packet came back on it (a middlebox's reset). It was
    /// never heard on, and it was the only one: `Failed`, at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_closed_before_any_packet_fails_a_tcp_only_peer() {
        bounded(async {
            crate::init();
            let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = ln.local_addr().unwrap();
            let door = tokio::spawn(async move {
                // Accepted, and gone.
                drop(ln.accept().await.unwrap());
                ln
            });
            let (p, mut rx) = Peer::start(&PeerConfig {
                ice_mode: IceMode::Tcp,
                ..config("p", 1 << 20)
            })
            .unwrap();
            assert_eq!(p.remote_described(&passive_sdp(at)), 1);
            let why = fails_within(&mut rx, Duration::from_secs(2))
                .await
                .expect("a TCP-only peer whose only connection closed unheard was not failed");
            assert!(why.starts_with(&format!("ice tcp {at}: ")), "{why}");
            assert!(!why.contains("dial"), "{why}");
            drop(door.await.unwrap());
            p.close();
        })
        .await;
    }

    /// Review S2: the connection that carried the peer ends while a second
    /// one is open and has not answered yet (an SFU that names two passive
    /// candidates). The second may still come up: nothing is said until it
    /// ends too, and then `Failed` is, though that one was never heard on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_connection_waits_for_one_still_being_checked() {
        bounded(async {
            let (a, mut a_rx, b, _b_rx, _id) = tcp_pair(IceMode::Tcp, IceMode::Tcp, None).await;
            holds("the first connection", &a, 1, 1).await;
            // A second passive address that accepts and answers nothing.
            let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = ln.local_addr().unwrap();
            let mute = tokio::spawn(async move { ln.accept().await.unwrap().0 });
            assert_eq!(a.remote_described(&passive_sdp(at)), 1);
            let mute = mute.await.unwrap();
            holds("the second connection", &a, 2, 1).await;
            b.cut_tcp();
            assert_eq!(
                fails_within(&mut a_rx, Duration::from_millis(700)).await,
                None,
                "failed while another connection was still being checked"
            );
            holds("after the first is lost", &a, 1, 0).await;
            drop(mute);
            let why = fails_within(&mut a_rx, Duration::from_secs(2))
                .await
                .expect("the last connection ended and nobody was told within 2 s");
            assert!(why.starts_with(&format!("ice tcp {at}: ")), "{why}");
            a.close();
            b.close();
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

    /// A tuned peer's settings are its own: VP8 alone, no RTX, and the offer
    /// says so (what a Go engine that registers VP8 alone offers).
    #[tokio::test]
    async fn a_tuned_peer_offers_the_codecs_it_was_given() {
        use str0m::format::{Codec, FormatParams};
        use str0m::media::{Direction, Frequency, MediaKind};

        bounded(async {
            crate::init();
            let (a, _rx) = Peer::start_tuned(&config("a", 1 << 20), |c| {
                let mut c = c.clear_codecs();
                c.codec_config().add_config(
                    96.into(),
                    None,
                    Codec::Vp8,
                    Frequency::NINETY_KHZ,
                    None,
                    FormatParams::default(),
                );
                c
            })
            .unwrap();
            let offer = a.with_rtc(|rtc| {
                let mut api = rtc.sdp_api();
                api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
                api.apply().unwrap().0.to_sdp_string()
            });
            assert!(offer.contains("a=rtpmap:96 VP8/90000"), "{offer}");
            assert!(offer.contains("a=rtcp-fb:96 nack\r\n"), "{offer}");
            assert!(!offer.contains("rtx/90000"), "{offer}");
            assert!(
                !offer.contains("VP9/90000") && !offer.contains("H264/90000"),
                "{offer}"
            );
            a.close();
        })
        .await;
    }

    /// RTP written on a negotiated video line reaches the remote's sink
    /// whole: sequence numbers, markers and payloads (the vp8channel lane).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtp_on_a_video_line_reaches_the_sink() {
        use str0m::format::Codec;
        use str0m::media::{Direction, MediaKind};
        use str0m::rtp::{RtpWrite, SeqNo};

        bounded(async {
            crate::init();
            let (a, mut a_rx) = Peer::start(&config("a", 1 << 20)).unwrap();
            let (b, mut b_rx) = Peer::start(&config("b", 1 << 20)).unwrap();
            let (got_tx, mut got) = mpsc::unbounded_channel();
            b.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
                let _ = got_tx.send((
                    p.header.sequence_number,
                    p.header.marker,
                    p.payload.to_vec(),
                ));
            })));
            let (offer, pending, mid) = a.with_rtc(|rtc| {
                let mut api = rtc.sdp_api();
                let mid = api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
                let (offer, pending) = api.apply().unwrap();
                (offer, pending, mid)
            });
            let offer = SdpOffer::from_sdp_string(&offer.to_sdp_string()).unwrap();
            let answer = b.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer)).unwrap();
            a.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer))
                .unwrap();
            let ca = Candidate::from_sdp_string(&a.add_host_candidate().unwrap()).unwrap();
            let cb = Candidate::from_sdp_string(&b.add_host_candidate().unwrap()).unwrap();
            a.add_remote_candidate(cb);
            b.add_remote_candidate(ca);
            let mut up = (false, false);
            while !(up.0 && up.1) {
                tokio::select! {
                    Some(e) = a_rx.recv() => if let PeerEvent::Connected = e { up.0 = true },
                    Some(e) = b_rx.recv() => if let PeerEvent::Connected = e { up.1 = true },
                }
            }
            let pt = a.with_rtc(|rtc| {
                rtc.codec_config()
                    .find(|p| p.spec().codec == Codec::Vp8)
                    .unwrap()
                    .pt()
            });
            let sent: Vec<(u16, bool, Vec<u8>)> = (0..20u16)
                .map(|i| {
                    (
                        65_530u16.wrapping_add(i),
                        i % 4 == 3,
                        vec![0x90, 0x80, u8::try_from(i).unwrap(), 7, 7],
                    )
                })
                .collect();
            for (i, (seq, marker, payload)) in sent.iter().enumerate() {
                let ext = 65_530u64 + u64::try_from(i).unwrap();
                a.with_rtc(|rtc| {
                    let mut api = rtc.direct_api();
                    let tx = api.stream_tx_by_mid(mid, None).unwrap();
                    tx.write_rtp(
                        RtpWrite::new(
                            pt,
                            SeqNo::from(ext),
                            3000 * u32::from(*seq),
                            Instant::now(),
                            payload.clone(),
                        )
                        .marker(*marker),
                    );
                });
            }
            let mut seen = Vec::new();
            while seen.len() < sent.len() {
                seen.push(got.recv().await.unwrap());
            }
            seen.sort_by_key(|(seq, ..)| u32::from(seq.wrapping_sub(65_530)));
            assert_eq!(seen, sent);
            b.set_rtp_sink(None);
            a.close();
            b.close();
        })
        .await;
    }

    /// A keyframe request from the remote (PLI, then FIR) reaches the owner
    /// of the peer that sends on the line, naming the line and the kind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_keyframe_request_reaches_the_senders_owner() {
        use str0m::format::Codec;
        use str0m::media::{Direction, KeyframeRequestKind, MediaKind};
        use str0m::rtp::{RtpWrite, SeqNo};

        bounded(async {
            crate::init();
            let (a, mut a_rx) = Peer::start(&config("a", 1 << 20)).unwrap();
            let (b, mut b_rx) = Peer::start(&config("b", 1 << 20)).unwrap();
            let (got_tx, mut got) = mpsc::unbounded_channel();
            b.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
                let _ = got_tx.send(p.header.sequence_number);
            })));
            let (offer, pending, mid) = a.with_rtc(|rtc| {
                let mut api = rtc.sdp_api();
                let mid = api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
                let (offer, pending) = api.apply().unwrap();
                (offer, pending, mid)
            });
            let offer = SdpOffer::from_sdp_string(&offer.to_sdp_string()).unwrap();
            let answer = b.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer)).unwrap();
            a.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer))
                .unwrap();
            let ca = Candidate::from_sdp_string(&a.add_host_candidate().unwrap()).unwrap();
            let cb = Candidate::from_sdp_string(&b.add_host_candidate().unwrap()).unwrap();
            a.add_remote_candidate(cb);
            b.add_remote_candidate(ca);
            let mut up = (false, false);
            while !(up.0 && up.1) {
                tokio::select! {
                    Some(e) = a_rx.recv() => match e {
                        PeerEvent::Connected => up.0 = true,
                        PeerEvent::KeyframeRequest(r) => panic!("asked before anything was sent: {r:?}"),
                        _ => {}
                    },
                    Some(e) = b_rx.recv() => if let PeerEvent::Connected = e { up.1 = true },
                }
            }
            // The receiver learns the sender's stream from its first packet.
            let pt = a.with_rtc(|rtc| {
                rtc.codec_config()
                    .find(|p| p.spec().codec == Codec::Vp8)
                    .unwrap()
                    .pt()
            });
            a.with_rtc(|rtc| {
                let mut api = rtc.direct_api();
                let tx = api.stream_tx_by_mid(mid, None).unwrap();
                tx.write_rtp(RtpWrite::new(
                    pt,
                    SeqNo::from(100u64),
                    3000,
                    Instant::now(),
                    vec![0x90, 0x80, 1, 7, 7],
                ));
            });
            assert_eq!(got.recv().await, Some(100));
            for kind in [KeyframeRequestKind::Pli, KeyframeRequestKind::Fir] {
                b.with_rtc(|rtc| {
                    rtc.direct_api()
                        .stream_rx_by_mid(mid, None)
                        .expect("the receiver holds the sender's stream")
                        .request_keyframe(kind);
                });
                let asked = loop {
                    match a_rx.recv().await {
                        Some(PeerEvent::KeyframeRequest(r)) => break r,
                        Some(PeerEvent::Closed(r)) => panic!("a closed: {r}"),
                        None => panic!("a's driver went"),
                        Some(_) => {}
                    }
                };
                assert_eq!(
                    asked,
                    KeyframeRequest {
                        mid,
                        rid: None,
                        kind
                    }
                );
            }
            // The receiver's own owner hears nothing of it.
            while let Ok(e) = b_rx.try_recv() {
                assert!(!matches!(e, PeerEvent::KeyframeRequest(_)), "{e:?}");
            }
            b.set_rtp_sink(None);
            a.close();
            b.close();
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

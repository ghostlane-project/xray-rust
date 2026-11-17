// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! TURN relays for one peer connection: turn-client-proto's UDP client on the
//! peer's own socket, as Chrome shares one UDP socket between its host
//! candidate and its TURN allocations, and its TCP client on a TCP
//! connection of its own per server.
//!
//! SaluteJazz's SFU offers only private host candidates, so a client reaches
//! it through Sber's TURN or not at all. The Go engine at 2d4266af hands
//! every `rtc:config` server to pion, which allocates on each: over UDP (the
//! valid pairs of `t3-live-1` are `relay` at local preference 3, pion's
//! UDP), over TCP, and over TLS (`turns:`). This module allocates over all
//! three, so a network that drops UDP still leaves the TCP path and one that
//! also inspects TCP leaves TLS. TLS is `crate::turns` (the `boring`
//! feature): the same framing as TCP inside a TLS connection whose hello is
//! Chrome 157's (`crate::tls_boring`), as a TURN server's TLS hello from a
//! client of any other shape would be the one hello on the wire that is no
//! browser's. Without the feature `turns:` URLs are left out.
//!
//! Over TCP (RFC 8656 section 3.1) a task per server (`stream`) dials it
//! through the engine's protected dial and moves bytes both ways: what the
//! client sends waits in a queue of [`STREAM_QUEUE`] datagrams, what the
//! server sends comes to the driver in chunks of at most [`STREAM_READ`]
//! bytes, [`STREAM_INBOUND`] of them in flight for the whole peer. The
//! client frames STUN and ChannelData on the stream (padding a ChannelData
//! to four bytes) and reassembles what arrives; it holds at most one
//! partial message, whose length field bounds it to 64 KiB.
//!
//! The driver ([`crate::peer`]) owns a `Relays`: datagrams from a TURN
//! server go to its client, and what the client unwraps goes to str0m as
//! arriving at the relayed address; str0m's transmits from a relayed address
//! go out through the client. Permissions and channels are ours (str0m only
//! sees the relayed candidate): a permission is asked for when ICE first
//! sends to an address, a channel is bound when the first non-STUN payload
//! goes to it, as Chrome's `TurnEntry` does. turn-client-proto refreshes the
//! allocation, the permissions and the channels itself.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use turn_client_proto::api::{
    TurnClientApi, TurnConfig, TurnEvent, TurnPeerData, TurnPollRet, TurnRecvRet,
};
use turn_client_proto::client::TurnClient;
use turn_client_proto::prelude::DelayedTransmitBuild;
use turn_client_proto::stun::agent::Transmit;
use turn_client_proto::stun::Instant as TurnInstant;
use turn_client_proto::tcp::TurnClientTcp;
use turn_client_proto::types::{AddressFamily, TransportType, TurnCredentials};
use turn_client_proto::udp::TurnClientUdp;
use zeroize::Zeroizing;

/// How a client reaches a TURN server: the URL's `transport` (RFC 7065).
/// The relayed address is UDP either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnTransport {
    /// Datagrams from the peer's own socket.
    Udp,
    /// A TCP connection of its own, STUN and ChannelData framed on it.
    Tcp,
    /// The same framing inside a TLS connection of its own (`turns:`,
    /// RFC 7350's TURN over TLS), the hello Chrome's (`tls_boring`).
    Tls,
}

/// A TURN server from the carrier's ICE servers (WebRTC's `RTCIceServer`,
/// one `turn:` URL over UDP or TCP), its host not yet resolved. The
/// credential is wiped when the entry is dropped, and so is every clone's.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// The server's host name or address literal (without brackets).
    pub host: String,
    /// Its port (3478 when the URL names none).
    pub port: u16,
    /// How it is reached.
    pub transport: TurnTransport,
    /// The long-term credential's user name.
    pub username: Zeroizing<String>,
    /// The long-term credential's password.
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnServer")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("transport", &self.transport)
            .field("username_len", &self.username.len())
            .field("password_len", &self.password.len())
            .finish()
    }
}

/// TURN's default port (RFC 8656 §3.1, pion's `DefaultPort` for `turn:`).
pub const DEFAULT_PORT: u16 = 3478;
/// TURN over TLS's default port (pion's `DefaultTLSPort` for `turns:`).
pub const DEFAULT_TLS_PORT: u16 = 5349;

/// The TURN servers of one ICE server entry this client allocates on: each
/// `turn:` URL over UDP (named or by default) or TCP, as pion's `ParseURL`
/// reads `turn:host[:port][?transport=udp|tcp]`, in the list's order; and
/// each `turns:` URL (TLS over TCP, port 5349 by default) when this build
/// has Chrome's TLS (the `boring` feature: without it the one TLS hello
/// this client would send is no browser's, so `turns:` stays skipped).
/// `stun:` and a URL that does not parse are left out.
#[must_use]
pub fn servers(urls: &[String], username: &str, password: &str) -> Vec<TurnServer> {
    servers_with(urls, username, password, cfg!(feature = "boring"))
}

/// [`servers`], with `tls` saying whether `turns:` URLs are taken.
#[must_use]
pub fn servers_with(urls: &[String], username: &str, password: &str, tls: bool) -> Vec<TurnServer> {
    let mut out = Vec::new();
    for url in urls {
        let (secure, rest) = match (url.strip_prefix("turn:"), url.strip_prefix("turns:")) {
            (Some(rest), _) => (false, rest),
            (None, Some(rest)) if tls => (true, rest),
            _ => continue,
        };
        let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut transport = if secure { "tcp" } else { "udp" };
        for kv in query.split('&').filter(|kv| !kv.is_empty()) {
            match kv.split_once('=') {
                Some(("transport", t)) => transport = t,
                _ => transport = "",
            }
        }
        let transport = match (transport.to_ascii_lowercase().as_str(), secure) {
            ("udp", false) => TurnTransport::Udp,
            ("tcp", false) => TurnTransport::Tcp,
            // TURN over TLS runs on TCP; `turns:` over UDP would be DTLS.
            ("tcp", true) => TurnTransport::Tls,
            _ => continue,
        };
        let Some((host, port)) = split_host_port(addr, secure) else {
            continue;
        };
        let s = TurnServer {
            host: host.to_owned(),
            port,
            transport,
            username: Zeroizing::new(username.to_owned()),
            password: Zeroizing::new(password.to_owned()),
        };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// `host`, `host:port`, `[v6]` and `[v6]:port`.
fn split_host_port(s: &str, secure: bool) -> Option<(&str, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':')?)),
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return None,
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        None if secure => DEFAULT_TLS_PORT,
        None => DEFAULT_PORT,
        Some(p) => p.parse().ok().filter(|p| *p != 0)?,
    };
    Some((host, port))
}

/// A [`TurnServer`] whose host resolved.
#[derive(Clone)]
pub(crate) struct Resolved {
    /// The URL's host as written: a TLS server's name (or address literal),
    /// which its certificate is checked for ([`sni_name`]).
    pub(crate) host: String,
    pub(crate) addr: SocketAddr,
    pub(crate) transport: TurnTransport,
    /// Wiped when dropped, as [`TurnServer`]'s. The TURN client the
    /// driver makes from them keeps its own copy for the allocation's life
    /// (`turn-client-proto`'s `TurnCredentials`), which is not ours to wipe.
    pub(crate) username: Zeroizing<String>,
    pub(crate) password: Zeroizing<String>,
}

/// Resolves the first [`MAX_ALLOCATIONS`] servers through the engine's
/// resolver ([`olc_net::resolver`]), keeping one address of `family`'s
/// kind each (IPv4 for an IPv4 socket); a host that does not resolve is
/// left out, as pion gathers nothing from it.
pub(crate) async fn resolve(servers: &[TurnServer], v4: bool) -> Vec<Resolved> {
    let mut out = Vec::new();
    for s in servers.iter().take(MAX_ALLOCATIONS) {
        let ips = match olc_net::resolver::lookup(&s.host).await {
            Ok(ips) => ips,
            Err(e) => {
                olc_net::debug!("webrtc: TURN host {}: {e}", s.host);
                continue;
            }
        };
        let Some(ip) = ips.into_iter().find(|ip| ip.is_ipv4() == v4) else {
            continue;
        };
        let addr = SocketAddr::new(ip, s.port);
        if out
            .iter()
            .any(|r: &Resolved| r.addr == addr && r.transport == s.transport)
        {
            continue;
        }
        out.push(Resolved {
            host: s.host.clone(),
            addr,
            transport: s.transport,
            username: s.username.clone(),
            password: s.password.clone(),
        });
    }
    out
}

/// The name a TLS hello to `host` sends as its server name: the URL's host
/// when it is a name, nothing when it is an address literal (Chrome's TLS
/// never sends an IP in SNI, RFC 6066 section 3).
#[must_use]
pub fn sni_name(host: &str) -> Option<&str> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() || bare.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host)
    }
}

/// The allocations one peer connection holds at most: SaluteJazz's
/// `rtc:config` names two TURN hosts (`a-t`, `s-t`), each over UDP, TCP and
/// TLS, and Chrome allocates on all six; so does this client, and a longer
/// list does not open more sockets' worth of state.
pub const MAX_ALLOCATIONS: usize = 6;

/// The remote addresses one allocation keeps permissions and channels for:
/// the remote candidates of one peer connection (an SFU trickles one or two
/// per transport and family; a browser peer a handful), with room to spare.
/// A remote past it gets no permission, so ICE fails that pair on its own.
pub const MAX_PEERS: usize = 16;

/// What wrapping one datagram for the TURN server adds, at most: a Send
/// indication's 20-byte header, XOR-PEER-ADDRESS for IPv6 (4 + 20), DATA's
/// 4-byte header and up to 3 bytes of padding, FINGERPRINT (8): 59, rounded
/// up. A ChannelData message adds 4 (and up to 3 of padding).
pub const TURN_OVERHEAD: usize = 64;

/// The shortest wait the relays ask the driver for: a millisecond, under
/// any TURN timer (the first retransmit is 500 ms, RFC 8489 §6.2.1).
const MIN_WAKE: Duration = Duration::from_millis(1);

/// The one buffer a wrapped datagram is written into: the largest datagram
/// str0m sends (its MTU, under [`crate::peer::RECV_BUF`]) plus the wrapping.
pub const SEND_BUF: usize = crate::peer::RECV_BUF + TURN_OVERHEAD;

// Wrapping fits, checked when this builds: str0m's datagrams are at most its
// 1200-byte MTU, and the largest wrapping (a Send indication to an IPv6
// peer) adds 59.
const _: () = assert!(TURN_OVERHEAD >= 59 && 1200 + 59 <= SEND_BUF);

/// One read from a TURN server's TCP connection, at most: a few of the
/// ChannelData messages a peer's 1200-byte datagrams become.
pub const STREAM_READ: usize = 4096;

/// The datagrams waiting for one TCP connection, at most (each at most
/// [`SEND_BUF`]): a burst of ICE checks or SCTP's window in 1200-byte
/// datagrams. Past it a datagram is dropped, as a full UDP socket buffer
/// drops one, and SCTP sends it again.
pub const STREAM_QUEUE: usize = 16;

/// The chunks read from a peer's TCP connections waiting for its driver
/// (each at most [`STREAM_READ`]): a reader with none left waits, so a slow
/// driver slows the server through TCP.
pub const STREAM_INBOUND: usize = 8;

/// The kernel's send buffer for a TURN TCP connection (`SO_SNDBUF`, set
/// before the dial so autotuning never grows it): the queue's worth twice.
pub const STREAM_SNDBUF: u32 = 64 * 1024;

/// A write to a TURN server over TCP that has not finished in this long
/// ends the connection: a server that reads nothing for this long has gone
/// (ICE's consent checks give up on its pairs after 30 s).
pub const STREAM_WRITE_STALL: Duration = Duration::from_secs(10);

// What one TCP connection holds at most stays far under the 12 MiB gauge:
// its queue, a read, and the client's partial message.
const _: () = assert!(STREAM_QUEUE * SEND_BUF + STREAM_READ + 65_556 <= 128 * 1024);

/// libwebrtc's pause between its gathering phases (Chrome's
/// `kMinimumStepDelay`): the UDP phase's Binding to each UDP TURN server
/// first, every Allocate this much later. The lab's capture of Chrome 157
/// (lab-olc-rtc.yml, turn-capture) shows 53-56 ms.
pub const ALLOCATE_STEP: Duration = Duration::from_millis(50);
/// A Binding's first retransmission timeout (libwebrtc's
/// `STUN_INITIAL_RTO`); each pause doubles, up to [`BINDING_MAX_RTO`].
pub const BINDING_RTO: Duration = Duration::from_millis(250);
/// The longest pause between two sends of a Binding (`STUN_MAX_RTO`).
pub const BINDING_MAX_RTO: Duration = Duration::from_secs(8);
/// The most times one Binding is sent: the capture's eight, at 0, 258,
/// 774, 1789, 3805, 7821, 15836 and 23852 ms.
pub const BINDING_SENDS: u8 = 8;

/// What a TCP connection's task read from its server, for the driver
/// ([`Relays::recv_stream`]); empty when the connection ended.
pub(crate) struct StreamChunk {
    /// The relay's place in [`Relays`].
    pub(crate) slot: usize,
    pub(crate) data: Vec<u8>,
}

/// What the relays tell the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayEvent {
    /// An allocation is up: its relayed address, the local candidate's, and
    /// how it reaches its server.
    Allocated(SocketAddr, TurnTransport),
}

/// What one datagram from the socket turned out to be.
pub(crate) enum Arrival<'a> {
    /// Not from a TURN server (or not TURN): str0m's, as it came.
    Direct,
    /// A TURN server's own answer, taken by its client.
    Handled,
    /// A remote's datagram through a relay: str0m's, from `data.peer` to
    /// `relayed`.
    Relayed {
        /// The allocation's relayed address.
        relayed: SocketAddr,
        /// The remote's datagram.
        data: TurnPeerData<&'a [u8]>,
    },
}

/// The relays of one peer connection: at most [`MAX_ALLOCATIONS`], each
/// with at most [`MAX_PEERS`] permissions and channels, and one
/// [`SEND_BUF`] for wrapping. Their memory is that, turn-client-proto's
/// state per allocation (its transactions, one per request in flight, and
/// the permission and channel lists our caps bound) and, for one over TCP,
/// its connection's queues ([`STREAM_QUEUE`], [`STREAM_READ`]).
pub(crate) struct Relays {
    base: Instant,
    local: SocketAddr,
    list: Vec<Relay>,
    out: Box<[u8]>,
    dropped: u64,
    /// The last datagram to a TURN server the host refused (not for a full
    /// buffer), for the driver's pion line ([`Relays::take_refused`]).
    refused: Option<(SocketAddr, io::Error)>,
    /// The first poll: the Bindings' clock, and every Allocate one
    /// [`ALLOCATE_STEP`] after it.
    started: Option<Instant>,
}

struct Relay {
    client: TurnClient,
    server: SocketAddr,
    /// How what the client sends reaches the server.
    path: Path,
    /// How the allocation reaches its server (the relayed candidate's rank).
    via: TurnTransport,
    /// The server's nonce was looked at for RFC 8489's cookie (logged once;
    /// the client ignores the cookie, as Chrome does).
    cookie_seen: bool,
    relayed: Option<SocketAddr>,
    /// The remote addresses a permission was asked for.
    permitted: Vec<IpAddr>,
    /// The remotes a channel was asked for.
    bound: Vec<SocketAddr>,
    /// The allocation failed or closed: nothing more goes through it.
    done: bool,
    /// A UDP server's Binding (Chrome's UDP port's); none over TCP.
    binding: Option<Binding>,
}

/// The Binding request Chrome's UDP port sends each UDP TURN server, which
/// libwebrtc also takes as a STUN server: no attribute, a transaction id
/// of libwebrtc's base64 alphabet (`rtc::CreateRandomString`), sent again
/// unanswered at [`BINDING_RTO`]'s pauses, [`BINDING_SENDS`] times at
/// most, whatever becomes of the allocation (it is another port's). Its
/// answer (a mapped address) is taken and not used: the client gathers no
/// server-reflexive candidate.
struct Binding {
    msg: [u8; 20],
    /// Times sent.
    sends: u8,
    /// When it goes next, after the relays' first poll.
    next: Duration,
    /// The pause after that.
    rto: Duration,
    answered: bool,
}

impl Binding {
    fn new() -> Binding {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut msg = [0u8; 20];
        msg[..8].copy_from_slice(&[0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        for b in &mut msg[8..] {
            *b = ALPHABET[usize::from(rand::random::<u8>() & 63)];
        }
        Binding {
            msg,
            sends: 0,
            next: Duration::ZERO,
            rto: BINDING_RTO,
            answered: false,
        }
    }

    /// Whether `data` answers it: a Binding success or error response with
    /// its transaction id.
    fn answered_by(&self, data: &[u8]) -> bool {
        data.len() >= 20
            && matches!(data[..2], [0x01, 0x01] | [0x01, 0x11])
            && data[4..20] == self.msg[4..20]
    }
}

/// How a relay's client reaches its server.
enum Path {
    /// From the peer's socket.
    Udp,
    /// Through its TCP connection's task ([`stream`]), whose queue this is.
    Stream(mpsc::Sender<Vec<u8>>),
}

/// What became of one datagram for a TURN server.
enum Sent {
    Ok,
    /// A full socket buffer or queue: dropped, as UDP drops it.
    Full,
    /// The host refused it (a path the firewall drops).
    Refused(io::Error),
    /// The TCP connection has ended.
    Closed,
}

impl Path {
    fn send(&self, sock: &UdpSocket, to: SocketAddr, data: &[u8]) -> Sent {
        match self {
            Path::Udp => match sock.try_send_to(data, to) {
                Ok(_) => Sent::Ok,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Sent::Full,
                Err(e) => Sent::Refused(e),
            },
            Path::Stream(tx) => match tx.try_send(data.to_vec()) {
                Ok(()) => Sent::Ok,
                Err(TrySendError::Full(_)) => Sent::Full,
                Err(TrySendError::Closed(_)) => Sent::Closed,
            },
        }
    }
}

impl Relay {
    /// Logs, once, whether the server's first challenge carries RFC 8489's
    /// nonce cookie (the client answers it as Chrome does, classic: the
    /// vendored stun-proto's `CLIENT_READS_NONCE_SECURITY`).
    fn note_cookie(&mut self, data: &[u8]) {
        if self.cookie_seen || data.len() <= 20 || data[0] != 0x01 || data[1] != 0x13 {
            return;
        }
        self.cookie_seen = true;
        let cookie = data
            .windows(RFC8489_COOKIE.len())
            .any(|w| w == RFC8489_COOKIE);
        olc_net::debug!(
            "webrtc: TURN server {} challenge, RFC 8489 nonce cookie: {}",
            self.server,
            if cookie { "yes" } else { "no" }
        );
    }
}

impl Relays {
    /// An allocation request on each of `servers` (the first
    /// [`MAX_ALLOCATIONS`] of `local`'s family), from `local`; a server
    /// over TCP gets its connection's task, which sends what `inbound`
    /// reads. Nothing is sent until [`Relays::poll`].
    pub(crate) fn new(
        servers: &[Resolved],
        local: SocketAddr,
        base: Instant,
        inbound: &mpsc::Sender<StreamChunk>,
    ) -> Relays {
        let list = servers
            .iter()
            .filter(|s| s.addr.is_ipv4() == local.is_ipv4())
            .take(MAX_ALLOCATIONS)
            .enumerate()
            .map(|(slot, s)| {
                let mut cfg = TurnConfig::new(TurnCredentials::new(&s.username, &s.password));
                // Every challenge is read as Chrome reads it, classic
                // whatever its nonce says (the vendored stun-proto,
                // `CLIENT_READS_NONCE_SECURITY`): MESSAGE-INTEGRITY with the
                // MD5 key, nothing echoed, so SHA-256 is never chosen.
                if local.is_ipv6() {
                    cfg.set_address_family(AddressFamily::IPV6);
                }
                // Over TCP the client's local address only names the
                // connection to itself (its buffers are keyed by it): the
                // peer's socket address, as the relayed candidate's base.
                let (client, path) = match s.transport {
                    TurnTransport::Udp => (
                        TurnClient::Udp(TurnClientUdp::allocate(local, s.addr, cfg)),
                        Path::Udp,
                    ),
                    TurnTransport::Tcp | TurnTransport::Tls => {
                        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
                        if s.transport == TurnTransport::Tls {
                            tokio::spawn(stream_tls(
                                slot,
                                s.host.clone(),
                                s.addr,
                                rx,
                                inbound.clone(),
                            ));
                        } else {
                            tokio::spawn(stream(slot, s.addr, rx, inbound.clone()));
                        }
                        (
                            TurnClient::Tcp(TurnClientTcp::allocate(local, s.addr, cfg)),
                            Path::Stream(tx),
                        )
                    }
                };
                Relay {
                    client,
                    server: s.addr,
                    path,
                    via: s.transport,
                    cookie_seen: false,
                    relayed: None,
                    permitted: Vec::with_capacity(MAX_PEERS),
                    bound: Vec::with_capacity(MAX_PEERS),
                    done: false,
                    binding: matches!(s.transport, TurnTransport::Udp).then(Binding::new),
                }
            })
            .collect::<Vec<_>>();
        let out = if list.is_empty() {
            Box::default()
        } else {
            vec![0u8; SEND_BUF].into_boxed_slice()
        };
        Relays {
            base,
            local,
            list,
            out,
            dropped: 0,
            refused: None,
            started: None,
        }
    }

    /// Datagrams that could not go through a relay so far: no permission
    /// yet (ICE retransmits), too long, or the host refused.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    fn at(&self, now: Instant) -> TurnInstant {
        let nanos = now.saturating_duration_since(self.base).as_nanos();
        TurnInstant::from_nanos(i64::try_from(nanos).unwrap_or(i64::MAX))
    }

    /// Hands a datagram from `from` to the UDP relay whose server sent it.
    pub(crate) fn recv<'a>(
        &mut self,
        from: SocketAddr,
        data: &'a [u8],
        now: Instant,
    ) -> Arrival<'a> {
        let at = self.at(now);
        let local = self.local;
        let Some(r) = self
            .list
            .iter_mut()
            .find(|r| r.server == from && matches!(r.path, Path::Udp))
        else {
            return Arrival::Direct;
        };
        if r.binding.as_ref().is_some_and(|b| b.answered_by(data)) {
            if let Some(b) = r.binding.as_mut() {
                b.answered = true;
            }
            return Arrival::Handled;
        }
        r.note_cookie(data);
        match r
            .client
            .recv(Transmit::new(data, TransportType::Udp, from, local), at)
        {
            TurnRecvRet::Ignored(_) => Arrival::Direct,
            TurnRecvRet::PeerData(data) => match r.relayed {
                Some(relayed) if !r.done => Arrival::Relayed { relayed, data },
                _ => Arrival::Handled,
            },
            TurnRecvRet::Handled | TurnRecvRet::PeerIcmp { .. } => Arrival::Handled,
        }
    }

    /// Hands what a TCP connection's task read to its relay's client: each
    /// remote's datagram the client unwraps goes to `deliver` (the relayed
    /// address it arrived at, the remote, the datagram). An empty chunk: the
    /// connection ended, and the relay with it.
    pub(crate) fn recv_stream(
        &mut self,
        chunk: &StreamChunk,
        now: Instant,
        mut deliver: impl FnMut(SocketAddr, SocketAddr, &[u8]),
    ) {
        let at = self.at(now);
        let local = self.local;
        let Some(r) = self.list.get_mut(chunk.slot) else {
            return;
        };
        if r.done || !matches!(r.path, Path::Stream(_)) {
            return;
        }
        let from = r.server;
        let arrived = Transmit::new(&chunk.data[..], TransportType::Tcp, from, local);
        if chunk.data.is_empty() {
            let how = if r.via == TurnTransport::Tls {
                "TLS"
            } else {
                "TCP"
            };
            olc_net::debug!("webrtc: TURN server {from} over {how}: the connection ended");
            let _ = r.client.recv(arrived, at);
            r.done = true;
            return;
        }
        r.note_cookie(&chunk.data);
        let relayed = r.relayed;
        if let (TurnRecvRet::PeerData(d), Some(relayed)) = (r.client.recv(arrived, at), relayed) {
            deliver(relayed, d.peer, d.data());
        }
        while let Some(d) = r.client.poll_recv(at) {
            if let Some(relayed) = relayed {
                deliver(relayed, d.peer, d.data());
            }
        }
    }

    /// Sends str0m's datagram `from` a relayed address to `to` through
    /// that relay; `false` when `from` is no relayed address of these (the
    /// caller sends it from the socket itself).
    ///
    /// A remote without a permission gets one asked for and this datagram
    /// dropped (ICE sends its check again); a channel is bound at the first
    /// payload that is not STUN, as Chrome's `TurnEntry` binds one once
    /// data flows.
    pub(crate) fn send(
        &mut self,
        sock: &UdpSocket,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        let at = self.at(now);
        let Some(r) = self.list.iter_mut().find(|r| r.relayed == Some(from)) else {
            return false;
        };
        if r.done {
            self.dropped += 1;
            return true;
        }
        let ip = to.ip();
        if !r.client.have_permission(TransportType::Udp, ip) {
            if !r.permitted.contains(&ip)
                && r.permitted.len() < MAX_PEERS
                && r.client
                    .create_permission(TransportType::Udp, ip, at)
                    .is_ok()
            {
                r.permitted.push(ip);
            }
            self.dropped += 1;
            return true;
        }
        if !is_stun(data)
            && !r.bound.contains(&to)
            && r.bound.len() < MAX_PEERS
            && r.client.bind_channel(TransportType::Udp, to, at).is_ok()
        {
            r.bound.push(to);
        }
        match r.client.send_to(TransportType::Udp, to, data, at) {
            Ok(Some(wrapped)) if wrapped.data.len() <= self.out.len() => {
                let server = wrapped.to;
                let len = wrapped.data.len();
                let w = wrapped.write_into(&mut self.out[..len]);
                match r.path.send(sock, server, w.data) {
                    Sent::Ok => {}
                    Sent::Full => self.dropped += 1,
                    Sent::Refused(e) => {
                        self.dropped += 1;
                        self.refused = Some((server, e));
                    }
                    Sent::Closed => {
                        self.dropped += 1;
                        r.done = true;
                    }
                }
            }
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => self.dropped += 1,
        }
        true
    }

    /// The TURN server and the error of the last datagram the host refused
    /// to send to it since the last call.
    pub(crate) fn take_refused(&mut self) -> Option<(SocketAddr, io::Error)> {
        self.refused.take()
    }

    /// Runs the relays' timers, sends what their clients queued and
    /// collects their events. Returns when to run them again.
    pub(crate) fn poll(
        &mut self,
        sock: &UdpSocket,
        name: &str,
        now: Instant,
        events: &mut Vec<RelayEvent>,
    ) -> Option<Instant> {
        let at = self.at(now);
        let base = self.base;
        let started = *self.started.get_or_insert(now);
        let since = now.saturating_duration_since(started);
        let mut wake: Option<Instant> = None;
        let mut soon = |w: Instant| wake = Some(wake.map_or(w, |x: Instant| x.min(w)));
        for r in &mut self.list {
            if let Some(b) = r.binding.as_mut().filter(|b| !b.answered) {
                if b.sends < BINDING_SENDS && since >= b.next {
                    // Unanswered or not sent, it is resent on its schedule,
                    // as a datagram would be.
                    let _ = r.path.send(sock, r.server, &b.msg);
                    b.sends += 1;
                    b.next += b.rto;
                    b.rto = (b.rto * 2).min(BINDING_MAX_RTO);
                }
                if b.sends < BINDING_SENDS {
                    soon(started + b.next);
                }
            }
            if r.done {
                continue;
            }
            if since < ALLOCATE_STEP {
                soon(started + ALLOCATE_STEP);
                continue;
            }
            match r.client.poll(at) {
                TurnPollRet::WaitUntil(w) => {
                    // Never in the past: a client that asks for "now" again
                    // right after its poll would spin the driver.
                    let w = (base + Duration::from_nanos(u64::try_from(w.as_nanos()).unwrap_or(0)))
                        .max(now + MIN_WAKE);
                    soon(w);
                }
                TurnPollRet::Closed => r.done = true,
                TurnPollRet::AllocateTcpSocket { .. } | TurnPollRet::TcpClose { .. } => {}
            }
            while let Some(t) = r.client.poll_transmit(at) {
                match r.path.send(sock, t.to, t.data.as_ref()) {
                    Sent::Ok => {}
                    Sent::Full | Sent::Refused(_) => self.dropped += 1,
                    Sent::Closed => {
                        self.dropped += 1;
                        r.done = true;
                    }
                }
            }
            while let Some(e) = r.client.poll_event() {
                match e {
                    TurnEvent::AllocationCreated(TransportType::Udp, relayed) => {
                        olc_net::debug!("webrtc: {name} TURN allocation {relayed} on {}", r.server);
                        r.relayed = Some(relayed);
                        events.push(RelayEvent::Allocated(relayed, r.via));
                    }
                    TurnEvent::AllocationCreateFailed(family) => {
                        olc_net::debug!(
                            "webrtc: {name} TURN allocation ({family}) on {} failed",
                            r.server
                        );
                        if r.relayed.is_none() {
                            r.done = true;
                        }
                    }
                    TurnEvent::PermissionCreateFailed(_, ip) => r.permitted.retain(|p| *p != ip),
                    TurnEvent::ChannelCreateFailed(_, peer) => r.bound.retain(|p| *p != peer),
                    _ => {}
                }
            }
        }
        wake
    }

    /// Releases every allocation (a Refresh with a zero lifetime, as Chrome
    /// sends on close) and sends those requests once; a TCP connection's
    /// task sends its queue and ends once the relays are dropped. Returns
    /// the relayed addresses that were still up (for pion's close lines,
    /// [`crate::peer::closed_relay_line`]).
    pub(crate) fn close(&mut self, sock: &UdpSocket, now: Instant) -> Vec<SocketAddr> {
        let at = self.at(now);
        let mut up = Vec::new();
        for r in &mut self.list {
            if let (false, Some(relayed)) = (r.done, r.relayed) {
                let _ = r.client.delete(at);
                up.push(relayed);
            }
            while let Some(t) = r.client.poll_transmit(at) {
                let _ = r.path.send(sock, t.to, t.data.as_ref());
            }
            r.done = true;
            r.binding = None;
        }
        up
    }
}

/// One TURN server's TCP connection: dials it from a protected socket,
/// writes what `out` holds, reads into chunks for the driver. It ends when
/// the server closes the connection or a write stalls for
/// [`STREAM_WRITE_STALL`] (the driver hears an empty chunk), or when the
/// relays are dropped: then it writes what is queued (a closing Refresh)
/// and shuts the connection down, within [`crate::peer::CLOSE_DRAIN`].
pub(crate) async fn stream(
    slot: usize,
    server: SocketAddr,
    mut out: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<StreamChunk>,
) {
    let ended = || StreamChunk {
        slot,
        data: Vec::new(),
    };
    let tcp = match olc_net::net::dial_tcp_with(server, Some(STREAM_SNDBUF)).await {
        Ok(tcp) => tcp,
        Err(e) => {
            olc_net::debug!("webrtc: TURN server {server} over TCP: {e}");
            let _ = inbound.send(ended()).await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    let (mut rd, mut wr) = tcp.into_split();
    let reader = async {
        let mut buf = vec![0u8; STREAM_READ];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = StreamChunk {
                        slot,
                        data: buf[..n].to_vec(),
                    };
                    if inbound.send(chunk).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = inbound.send(ended()).await;
    };
    let writer = async {
        while let Some(b) = out.recv().await {
            match tokio::time::timeout(STREAM_WRITE_STALL, wr.write_all(&b)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    olc_net::debug!("webrtc: TURN server {server} over TCP: write: {e}");
                    let _ = inbound.try_send(ended());
                    return;
                }
                Err(_) => {
                    olc_net::debug!("webrtc: TURN server {server} over TCP: write stalled");
                    let _ = inbound.try_send(ended());
                    return;
                }
            }
        }
        let _ = tokio::time::timeout(crate::peer::CLOSE_DRAIN, wr.shutdown()).await;
    };
    tokio::select! {
        () = reader => {}
        () = writer => {}
    }
}

/// One TURN server's TLS connection ([`crate::turns`]): the same framing as
/// [`stream`] inside Chrome's TLS. A build without the `boring` feature never
/// lists a `turns:` server, so this only ends the relay.
#[cfg(feature = "boring")]
async fn stream_tls(
    slot: usize,
    host: String,
    server: SocketAddr,
    out: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<StreamChunk>,
) {
    crate::turns::stream(slot, host, server, out, inbound).await;
}

#[cfg(not(feature = "boring"))]
async fn stream_tls(
    slot: usize,
    _host: String,
    server: SocketAddr,
    _out: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<StreamChunk>,
) {
    olc_net::debug!("webrtc: TURN server {server} over TLS: this build has no Chrome TLS");
    let _ = inbound
        .send(StreamChunk {
            slot,
            data: Vec::new(),
        })
        .await;
}

/// RFC 8489's nonce cookie (§9.2): a server that sends it offers the
/// security features its nonce encodes.
const RFC8489_COOKIE: &[u8] = b"obMatJos2";

/// Whether a datagram is STUN (RFC 7983: a first byte of 0 to 3), not DTLS
/// or media.
fn is_stun(data: &[u8]) -> bool {
    data.first().is_some_and(|b| *b < 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_turn_server_never_prints_its_credential() {
        let s = TurnServer {
            host: "a-t.example".into(),
            port: 3478,
            transport: TurnTransport::Udp,
            username: String::from("1700000000:user").into(),
            password: String::from("s3cr3t-credential").into(),
        };
        let shown = format!("{s:?}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(!shown.contains("1700000000:user"), "{shown}");
        assert!(shown.contains("a-t.example"), "{shown}");
    }

    /// Wave 2's memory note n1: a TURN user name and password are wiped
    /// when the entry that holds them is dropped, the resolved copy the
    /// driver allocates with as well: both keep them in `Zeroizing`.
    #[tokio::test]
    async fn a_turn_credential_is_wiped_when_its_entry_is_dropped() {
        fn wiped<T>(_: &T) -> bool {
            std::any::type_name::<T>().starts_with("zeroize::Zeroizing<")
        }
        let list = servers_with(&urls(&["turn:127.0.0.1:3478"]), "u", "p", false);
        let s = &list[0];
        assert!(wiped(&s.username), "a server's user name");
        assert!(wiped(&s.password), "a server's password");
        assert!(!wiped(&s.host));
        let resolved = crate::testing::bounded(resolve(&list, true)).await;
        let r = &resolved[0];
        assert!(wiped(&r.username), "a resolved server's user name");
        assert!(wiped(&r.password), "a resolved server's password");
        assert_eq!((r.username.as_str(), r.password.as_str()), ("u", "p"));
    }

    /// SaluteJazz's `rtc:config` as the spike's probe (e) logged it: of six
    /// URLs, the four `turn:` ones, over UDP and TCP, in the list's order
    /// (`turns:` waits for libwebrtc's TLS hello).
    #[test]
    fn the_udp_and_tcp_turn_urls_are_taken() {
        let got = servers_with(
            &urls(&[
                "turn:a-t.salutejazz.ru:3478?transport=udp",
                "turn:s-t.salutejazz.ru:3478?transport=udp",
                "turn:a-t.salutejazz.ru:3478?transport=tcp",
                "turn:s-t.salutejazz.ru:3478?transport=tcp",
                "turns:a-t.salutejazz.ru:443?transport=tcp",
                "turns:s-t.salutejazz.ru:443?transport=tcp",
            ]),
            "u",
            "p",
            false,
        );
        let hosts: Vec<_> = got
            .iter()
            .map(|s| (s.host.as_str(), s.port, s.transport))
            .collect();
        assert_eq!(
            hosts,
            [
                ("a-t.salutejazz.ru", 3478, TurnTransport::Udp),
                ("s-t.salutejazz.ru", 3478, TurnTransport::Udp),
                ("a-t.salutejazz.ru", 3478, TurnTransport::Tcp),
                ("s-t.salutejazz.ru", 3478, TurnTransport::Tcp),
            ]
        );
        for s in &got {
            assert_eq!((s.username.as_str(), s.password.as_str()), ("u", "p"));
        }
    }

    #[test]
    fn a_turn_url_reads_as_pion_reads_it() {
        let one = |u: &str| servers_with(&urls(&[u]), "u", "p", false);
        assert_eq!(one("turn:192.0.2.1")[0].port, DEFAULT_PORT);
        assert_eq!(one("turn:192.0.2.1")[0].transport, TurnTransport::Udp);
        assert_eq!(one("turn:[2001:db8::1]:5000")[0].host, "2001:db8::1");
        assert_eq!(one("turn:[2001:db8::1]")[0].port, DEFAULT_PORT);
        assert_eq!(one("turn:h:3479?transport=UDP")[0].port, 3479);
        assert_eq!(one("turn:h?transport=tcp")[0].transport, TurnTransport::Tcp);
        assert_eq!(one("turn:h:443?transport=TCP")[0].port, 443);
        for bad in [
            "stun:stun.l.google.com:19302",
            "turn:",
            "turn::3478",
            "turn:h:0",
            "turn:h:x",
            "turn:2001:db8::1",
            "turn:h?transport=sctp",
            "turn:h?foo=bar",
            "turns:h:443?transport=tcp",
            "turns:h",
        ] {
            assert!(one(bad).is_empty(), "{bad}");
        }
        // The same server twice is allocated on once; over UDP and over TCP
        // it is two.
        assert_eq!(
            servers_with(
                &urls(&["turn:h", "turn:h:3478?transport=udp"]),
                "u",
                "p",
                false
            )
            .len(),
            1
        );
        assert_eq!(
            servers_with(&urls(&["turn:h", "turn:h?transport=tcp"]), "u", "p", false).len(),
            2
        );
    }

    /// `turns:` URLs, as SaluteJazz's `rtc:config` lists them (TLS on 443,
    /// `transport=tcp`), are TLS servers when the build has Chrome's TLS and
    /// nothing when it has not; the port is 5349 when the URL names none; a
    /// `turns:` over UDP (DTLS) is not ours.
    #[test]
    fn a_turns_url_is_a_tls_server_only_where_the_build_has_chromes_tls() {
        let list = urls(&[
            "turn:a-t.salutejazz.ru:3478?transport=udp",
            "turns:a-t.salutejazz.ru:443?transport=tcp",
            "turns:s-t.salutejazz.ru:443?transport=tcp",
        ]);
        let with = servers_with(&list, "u", "p", true);
        let got: Vec<_> = with
            .iter()
            .map(|s| (s.host.as_str(), s.port, s.transport))
            .collect();
        assert_eq!(
            got,
            [
                ("a-t.salutejazz.ru", 3478, TurnTransport::Udp),
                ("a-t.salutejazz.ru", 443, TurnTransport::Tls),
                ("s-t.salutejazz.ru", 443, TurnTransport::Tls),
            ]
        );
        let without = servers_with(&list, "u", "p", false);
        assert_eq!(without.len(), 1, "{without:?}");
        assert_eq!(without[0].transport, TurnTransport::Udp);
        // The shipped entry point follows the feature.
        assert_eq!(
            servers(&list, "u", "p").len(),
            if cfg!(feature = "boring") { 3 } else { 1 }
        );
        let one = |u: &str| servers_with(&urls(&[u]), "u", "p", true);
        assert_eq!(one("turns:h")[0].port, DEFAULT_TLS_PORT);
        assert_eq!(one("turns:h")[0].transport, TurnTransport::Tls);
        assert_eq!(
            one("turns:[2001:db8::1]:5000?transport=TCP")[0].host,
            "2001:db8::1"
        );
        assert!(one("turns:h?transport=udp").is_empty());
        assert!(one("turns:h?transport=sctp").is_empty());
        assert!(one("turns:").is_empty());
        // TLS and TCP to one address are two servers.
        assert_eq!(
            servers_with(
                &urls(&["turn:h:443?transport=tcp", "turns:h:443"]),
                "u",
                "p",
                true
            )
            .len(),
            2
        );
    }

    /// A name is the hello's server name; an address literal never is.
    #[test]
    fn an_address_literal_is_no_server_name() {
        assert_eq!(sni_name("a-t.salutejazz.ru"), Some("a-t.salutejazz.ru"));
        assert_eq!(sni_name("localhost"), Some("localhost"));
        assert_eq!(sni_name("192.0.2.1"), None);
        assert_eq!(sni_name("2001:db8::1"), None);
        assert_eq!(sni_name("[2001:db8::1]"), None);
        assert_eq!(sni_name("1.2.3.4.example"), Some("1.2.3.4.example"));
        assert_eq!(sni_name(""), None);
    }

    /// The host of a `turns:` URL is kept through resolution, for the TLS
    /// name and the certificate's check.
    #[tokio::test]
    async fn a_resolved_tls_server_keeps_its_host() {
        let list = servers_with(
            &urls(&[
                "turns:192.0.2.9:443?transport=tcp",
                "turn:192.0.2.9:443?transport=tcp",
            ]),
            "u",
            "p",
            true,
        );
        let got = crate::testing::bounded(resolve(&list, true)).await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].transport, TurnTransport::Tls);
        assert_eq!(got[0].host, "192.0.2.9");
        assert_eq!(got[1].transport, TurnTransport::Tcp);
    }

    #[tokio::test]
    async fn literals_resolve_to_their_family_at_most_max_allocations() {
        let entry = |host: String, transport| TurnServer {
            host,
            port: 3478,
            transport,
            username: String::from("u").into(),
            password: String::from("p").into(),
        };
        let list: Vec<TurnServer> = (1..=MAX_ALLOCATIONS + 2)
            .map(|i| entry(format!("192.0.2.{i}"), TurnTransport::Udp))
            .chain(std::iter::once(entry(
                "2001:db8::1".into(),
                TurnTransport::Udp,
            )))
            .collect();
        let got = crate::testing::bounded(resolve(&list, true)).await;
        assert_eq!(got.len(), MAX_ALLOCATIONS);
        assert!(got.iter().all(|r| r.addr.is_ipv4()));
        let v6 = crate::testing::bounded(resolve(&list[MAX_ALLOCATIONS + 2..], false)).await;
        assert_eq!(v6.len(), 1);
        // One address over UDP and over TCP is two allocations.
        let both = [
            entry("192.0.2.1".into(), TurnTransport::Udp),
            entry("192.0.2.1".into(), TurnTransport::Tcp),
        ];
        let got = crate::testing::bounded(resolve(&both, true)).await;
        let kinds: Vec<_> = got.iter().map(|r| r.transport).collect();
        assert_eq!(kinds, [TurnTransport::Udp, TurnTransport::Tcp]);
    }

    /// The per-allocation state the caps bound, before turn-client-proto's
    /// own lists: one of these per allocation, at most [`MAX_ALLOCATIONS`].
    #[test]
    fn a_relay_stays_small() {
        let n = size_of::<Relay>();
        eprintln!("Relay is {n} bytes, Relays {} bytes", size_of::<Relays>());
        assert!(n <= 4096, "Relay is {n} bytes");
    }

    /// However many remotes ICE sends to, one allocation asks for at most
    /// [`MAX_PEERS`] permissions; a datagram to a remote without one is
    /// dropped, not queued.
    /// The attribute types of a STUN message, in order.
    fn attribute_types(msg: &[u8]) -> Vec<u16> {
        let end = (20 + usize::from(u16::from_be_bytes([msg[2], msg[3]]))).min(msg.len());
        let mut at = 20;
        let mut out = Vec::new();
        while at + 4 <= end {
            out.push(u16::from_be_bytes([msg[at], msg[at + 1]]));
            let len = usize::from(u16::from_be_bytes([msg[at + 2], msg[at + 3]]));
            at += 4 + len.next_multiple_of(4);
        }
        out
    }

    /// Polls `relays` until `server` reads a request (at most 5 s): its
    /// length.
    async fn next_request(
        relays: &mut Relays,
        sock: &UdpSocket,
        server: &UdpSocket,
        buf: &mut [u8],
        what: &str,
    ) -> usize {
        let mut up = Vec::new();
        for _ in 0..50 {
            relays.poll(sock, "t", Instant::now(), &mut up);
            let got = tokio::time::timeout(Duration::from_millis(100), server.recv_from(buf)).await;
            if let Ok(Ok((n, _))) = got {
                return n;
            }
        }
        panic!("no {what} in 5 s");
    }

    /// A challenge with RFC 8489's nonce cookie (the password algorithms
    /// bit set, PASSWORD-ALGORITHMS listing SHA-256 then MD5) gets Chrome's
    /// retry, as Chrome 157 sent it to the lab's capture server
    /// (lab-olc-rtc.yml's turn-capture): USERNAME, REALM, NONCE, then
    /// MESSAGE-INTEGRITY with the MD5 key; neither PASSWORD-ALGORITHMS nor
    /// PASSWORD-ALGORITHM, no MESSAGE-INTEGRITY-SHA256. The same as its
    /// answer to a classic challenge.
    #[tokio::test]
    async fn an_rfc8489_challenge_is_answered_as_chrome_answers_it() {
        crate::testing::bounded(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = sock.local_addr().unwrap();
            let resolved = [Resolved {
                host: String::new(),
                addr: server.local_addr().unwrap(),
                transport: TurnTransport::Udp,
                username: String::from("u").into(),
                password: String::from("p").into(),
            }];
            let (inbound, _chunks) = mpsc::channel(STREAM_INBOUND);
            let mut relays = Relays::new(&resolved, local, Instant::now(), &inbound);
            let mut buf = [0u8; 1500];
            let n = loop {
                let n = next_request(&mut relays, &sock, &server, &mut buf, "Allocate").await;
                if buf[..2] != [0x00, 0x01] {
                    break n;
                }
            };
            assert_eq!(&buf[..2], &[0x00, 0x03], "not an Allocate");
            let first = attribute_types(&buf[..n]);
            // Chrome's first Allocate: REQUESTED-TRANSPORT alone (no
            // LIFETIME, no DONT-FRAGMENT).
            assert_eq!(first, [0x0019], "{first:04x?}");
            let mut challenge = vec![0x01, 0x13, 0, 0, 0x21, 0x12, 0xa4, 0x42];
            challenge.extend_from_slice(&buf[8..20]);
            for (t, v) in [
                (0x0009_u16, b"\0\0\x04\x01Unauthorized".to_vec()),
                (0x0014, b"olc.test".to_vec()),
                (0x0015, b"obMatJos2gAAA0123456789abcdef".to_vec()),
                (0x8002, vec![0, 2, 0, 0, 0, 1, 0, 0]),
            ] {
                challenge.extend_from_slice(&t.to_be_bytes());
                challenge.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
                challenge.extend_from_slice(&v);
                challenge.resize(challenge.len().next_multiple_of(4), 0);
            }
            let len = u16::try_from(challenge.len() - 20).unwrap();
            challenge[2..4].copy_from_slice(&len.to_be_bytes());
            let handled = relays.recv(resolved[0].addr, &challenge, Instant::now());
            assert!(
                matches!(handled, Arrival::Handled),
                "the challenge was not taken"
            );
            let n = loop {
                let n = next_request(&mut relays, &sock, &server, &mut buf, "retry").await;
                if buf[..2] != [0x00, 0x01] {
                    break n;
                }
            };
            assert_eq!(&buf[..2], &[0x00, 0x03], "the retry is not an Allocate");
            let retry = attribute_types(&buf[..n]);
            // Chrome's retry, exactly: no LIFETIME.
            assert_eq!(
                retry,
                [0x0019, 0x0006, 0x0014, 0x0015, 0x0008],
                "{retry:04x?}"
            );
            assert!(first.contains(&0x0019), "{first:04x?}");
            // USERNAME, REALM, NONCE, MESSAGE-INTEGRITY, in that order, after
            // REQUESTED-TRANSPORT.
            let at: Vec<Option<usize>> = [0x0019_u16, 0x0006, 0x0014, 0x0015, 0x0008]
                .iter()
                .map(|t| retry.iter().position(|x| x == t))
                .collect();
            assert!(
                at.iter().all(Option::is_some) && at.windows(2).all(|w| w[0] < w[1]),
                "Chrome's order is 0019 0006 0014 0015 0008: {retry:04x?}"
            );
            // MESSAGE-INTEGRITY-SHA256, PASSWORD-ALGORITHM, PASSWORD-ALGORITHMS.
            for t in [0x001c_u16, 0x001d, 0x8002] {
                assert!(!retry.contains(&t), "{t:#06x} in {retry:04x?}");
            }
        })
        .await;
    }

    /// What `server` has read so far, every datagram.
    fn drain(server: &UdpSocket) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1500];
        while let Ok((n, _)) = server.try_recv_from(&mut buf) {
            out.push(buf[..n].to_vec());
        }
        out
    }

    /// The Bindings among `got`.
    fn bindings(got: &[Vec<u8>]) -> Vec<&Vec<u8>> {
        got.iter().filter(|m| m[..2] == [0x00, 0x01]).collect()
    }

    /// A UDP TURN server is first sent a Binding, as Chrome's UDP port takes
    /// it for a STUN server: no attribute, a transaction id of libwebrtc's
    /// base64 alphabet. Every Allocate goes one [`ALLOCATE_STEP`] later. An
    /// unanswered Binding is sent again, the same id, at Chrome's pauses
    /// ([`BINDING_RTO`] doubling to [`BINDING_MAX_RTO`]), [`BINDING_SENDS`]
    /// times in all, the allocation's own fate aside; an answer is taken
    /// (never handed to str0m) and ends the resends.
    #[tokio::test]
    async fn a_udp_turn_server_is_bound_first_as_chrome_binds_it() {
        crate::testing::bounded(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = sock.local_addr().unwrap();
            let resolved = [Resolved {
                host: String::new(),
                addr: server.local_addr().unwrap(),
                transport: TurnTransport::Udp,
                username: String::from("u").into(),
                password: String::from("p").into(),
            }];
            let settle = || tokio::time::sleep(Duration::from_millis(20));
            // As the driver's socket is by the time its relays start (after
            // the connector's rtc:config): tokio knows it can write.
            sock.writable().await.unwrap();
            let (inbound, _chunks) = mpsc::channel(STREAM_INBOUND);
            let t0 = Instant::now();
            let mut relays = Relays::new(&resolved, local, t0, &inbound);
            let mut up = Vec::new();
            let wake = relays.poll(&sock, "t", t0, &mut up);
            settle().await;
            let got = drain(&server);
            assert_eq!(got.len(), 1, "{got:02x?}");
            let binding = got[0].clone();
            assert_eq!(binding.len(), 20, "{binding:02x?}");
            assert_eq!(&binding[..8], &[0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
            assert!(
                binding[8..20]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'),
                "{:?}",
                String::from_utf8_lossy(&binding[8..20])
            );
            assert!(wake.is_some_and(|w| w <= t0 + ALLOCATE_STEP), "{wake:?}");
            relays.poll(
                &sock,
                "t",
                t0 + ALLOCATE_STEP - Duration::from_millis(1),
                &mut up,
            );
            settle().await;
            assert!(drain(&server).is_empty(), "something before the step");
            relays.poll(&sock, "t", t0 + ALLOCATE_STEP, &mut up);
            settle().await;
            let got = drain(&server);
            assert!(got.len() == 1 && got[0][..2] == [0x00, 0x03], "{got:02x?}");
            let (mut at, mut rto, mut sends) = (Duration::ZERO, BINDING_RTO, 1);
            for _ in 1..BINDING_SENDS {
                at += rto;
                rto = (rto * 2).min(BINDING_MAX_RTO);
                relays.poll(&sock, "t", t0 + at - Duration::from_millis(1), &mut up);
                settle().await;
                assert!(bindings(&drain(&server)).is_empty(), "early at {at:?}");
                relays.poll(&sock, "t", t0 + at, &mut up);
                settle().await;
                let got = drain(&server);
                let b = bindings(&got);
                assert_eq!(b.len(), 1, "at {at:?}: {got:02x?}");
                assert_eq!(b[0], &binding, "at {at:?}: another id");
                sends += 1;
            }
            assert_eq!(sends, BINDING_SENDS);
            assert_eq!(at, Duration::from_millis(23_750));
            relays.poll(&sock, "t", t0 + Duration::from_secs(60), &mut up);
            settle().await;
            assert!(bindings(&drain(&server)).is_empty(), "a ninth Binding");

            // A second relay, answered: the answer is taken and the resends end.
            let t0 = Instant::now();
            let mut relays = Relays::new(&resolved, local, t0, &inbound);
            relays.poll(&sock, "t", t0, &mut up);
            settle().await;
            let got = drain(&server);
            let mut answer = got[0].clone();
            answer[..2].copy_from_slice(&[0x01, 0x01]);
            assert!(matches!(
                relays.recv(resolved[0].addr, &answer, t0),
                Arrival::Handled
            ));
            relays.poll(&sock, "t", t0 + BINDING_RTO, &mut up);
            settle().await;
            assert!(bindings(&drain(&server)).is_empty(), "resent once answered");
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_allocation_asks_at_most_max_peers_permissions() {
        crate::testing::bounded(async {
            let (server, entry) = crate::testing::turn_server().await;
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = sock.local_addr().unwrap();
            let resolved = resolve(&[entry], true).await;
            let (inbound, _chunks) = mpsc::channel(STREAM_INBOUND);
            let mut relays = Relays::new(&resolved, local, Instant::now(), &inbound);
            let mut up = Vec::new();
            let mut buf = vec![0u8; crate::peer::RECV_BUF];
            let relayed = loop {
                relays.poll(&sock, "t", Instant::now(), &mut up);
                if let Some(RelayEvent::Allocated(a, _)) = up.first() {
                    break *a;
                }
                let got =
                    tokio::time::timeout(Duration::from_millis(100), sock.recv_from(&mut buf))
                        .await;
                if let Ok(Ok((n, from))) = got {
                    let _ = relays.recv(from, &buf[..n], Instant::now());
                }
            };
            let before = relays.dropped();
            for i in 0..40u8 {
                let to = SocketAddr::from(([127, 0, 1, i + 1], 9));
                assert!(relays.send(&sock, relayed, to, &[0, 1, 0, 0], Instant::now()));
            }
            assert_eq!(relays.list[0].permitted.len(), MAX_PEERS);
            assert_eq!(relays.dropped() - before, 40);
            // A datagram from no relayed address is the caller's to send.
            assert!(!relays.send(&sock, local, relayed, &[0, 1, 0, 0], Instant::now()));
            // Closing names the allocation that was up, once.
            assert_eq!(relays.close(&sock, Instant::now()), [relayed]);
            assert!(relays.close(&sock, Instant::now()).is_empty());
            server.close().await.unwrap();
        })
        .await;
    }

    /// A server over TCP gets its Allocate request on a TCP connection of
    /// its own, nothing on UDP at the same address; when the server closes
    /// the connection, the relay ends and its task with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tcp_relay_allocates_on_its_own_connection() {
        use tokio::io::AsyncReadExt as _;
        crate::testing::bounded(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = listener.local_addr().unwrap();
            // A UDP socket at the server's address: the request must not
            // come here.
            let same_port_udp = UdpSocket::bind(server).await.unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local = sock.local_addr().unwrap();
            let resolved = [Resolved {
                host: String::new(),
                addr: server,
                transport: TurnTransport::Tcp,
                username: String::from("u").into(),
                password: String::from("p").into(),
            }];
            let (inbound, mut chunks) = mpsc::channel(STREAM_INBOUND);
            let t0 = Instant::now();
            let mut relays = Relays::new(&resolved, local, t0, &inbound);
            let mut up = Vec::new();
            relays.poll(&sock, "t", t0, &mut up);
            // The relay phase: every Allocate one step after the start.
            relays.poll(&sock, "t", t0 + ALLOCATE_STEP, &mut up);
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 20];
            conn.read_exact(&mut head).await.unwrap();
            // An Allocate request (0x0003) with STUN's magic cookie.
            assert_eq!(&head[..2], &[0x00, 0x03], "{head:02x?}");
            assert_eq!(&head[4..8], &[0x21, 0x12, 0xa4, 0x42], "{head:02x?}");
            let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
            let mut body = vec![0u8; len];
            conn.read_exact(&mut body).await.unwrap();
            let whole = [&head[..], &body[..]].concat();
            // Chrome's: REQUESTED-TRANSPORT alone, and over TCP no Binding
            // first (nor on UDP: below).
            assert_eq!(attribute_types(&whole), [0x0019], "{whole:02x?}");
            // REQUESTED-TRANSPORT (0x0019): UDP (17), the relayed address's.
            assert!(
                body.windows(5).any(|w| w == [0x00, 0x19, 0x00, 0x04, 17]),
                "{body:02x?}"
            );
            let mut probe = [0u8; 64];
            let udp = tokio::time::timeout(
                Duration::from_millis(200),
                same_port_udp.recv_from(&mut probe),
            )
            .await;
            assert!(udp.is_err(), "the request came over UDP too");
            drop(conn);
            let chunk = chunks.recv().await.unwrap();
            assert!(chunk.data.is_empty(), "{} bytes", chunk.data.len());
            relays.recv_stream(&chunk, Instant::now(), |_, _, _| {
                panic!("no remote's data came")
            });
            assert!(relays.list[0].done);
            relays.close(&sock, Instant::now());
            drop(relays);
            // With the relays gone the task ends: the queue's last sender
            // is the test's own.
            drop(inbound);
            assert!(chunks.recv().await.is_none());
        })
        .await;
    }

    /// A build without Chrome's TLS never lists a `turns:` server; a TLS
    /// server handed to it anyway ends its relay at once and says so (no
    /// plain TCP, which would put a TURN request where a TLS hello belongs).
    #[cfg(not(feature = "boring"))]
    #[tokio::test]
    async fn a_tls_relay_without_chromes_tls_ends_at_once() {
        crate::testing::bounded(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = listener.local_addr().unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let resolved = [Resolved {
                host: "turn.olc.test".into(),
                addr: server,
                transport: TurnTransport::Tls,
                username: String::from("u").into(),
                password: String::from("p").into(),
            }];
            let (inbound, mut chunks) = mpsc::channel(STREAM_INBOUND);
            let mut relays = Relays::new(
                &resolved,
                sock.local_addr().unwrap(),
                Instant::now(),
                &inbound,
            );
            let chunk = chunks.recv().await.unwrap();
            assert!(chunk.data.is_empty());
            relays.recv_stream(&chunk, Instant::now(), |_, _, _| panic!("no data"));
            assert!(relays.list[0].done);
            // Nothing was dialled.
            let none = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(none.is_err(), "a connection was opened");
        })
        .await;
    }
}

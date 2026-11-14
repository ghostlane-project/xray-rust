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
//! UDP), over TCP, and over TLS (`turns:`). This module allocates over UDP
//! and TCP, so a network that drops UDP still leaves the TCP path; TLS waits
//! for a ClientHello that is libwebrtc's (port plan section 8, M8), as a
//! TURN server's TLS hello from this client would otherwise be the one
//! hello on the wire that is no browser's.
//!
//! Over TCP (RFC 8656 section 3.1) a task per server ([`stream`]) dials it
//! through the engine's protected dial and moves bytes both ways: what the
//! client sends waits in a queue of [`STREAM_QUEUE`] datagrams, what the
//! server sends comes to the driver in chunks of at most [`STREAM_READ`]
//! bytes, [`STREAM_INBOUND`] of them in flight for the whole peer. The
//! client frames STUN and ChannelData on the stream (padding a ChannelData
//! to four bytes) and reassembles what arrives; it holds at most one
//! partial message, whose length field bounds it to 64 KiB.
//!
//! The driver ([`crate::peer`]) owns a [`Relays`]: datagrams from a TURN
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
use turn_client_proto::types::stun::message::IntegrityAlgorithm;
use turn_client_proto::types::{AddressFamily, TransportType, TurnCredentials};
use turn_client_proto::udp::TurnClientUdp;

/// How a client reaches a TURN server: the URL's `transport` (RFC 7065).
/// The relayed address is UDP either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnTransport {
    /// Datagrams from the peer's own socket.
    Udp,
    /// A TCP connection of its own, STUN and ChannelData framed on it.
    Tcp,
}

/// A TURN server from the carrier's ICE servers (WebRTC's `RTCIceServer`,
/// one `turn:` URL over UDP or TCP), its host not yet resolved.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// The server's host name or address literal (without brackets).
    pub host: String,
    /// Its port (3478 when the URL names none).
    pub port: u16,
    /// How it is reached.
    pub transport: TurnTransport,
    /// The long-term credential's user name.
    pub username: String,
    /// The long-term credential's password.
    pub password: String,
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

/// The TURN servers of one ICE server entry this client allocates on: each
/// `turn:` URL over UDP (named or by default) or TCP, as pion's `ParseURL`
/// reads `turn:host[:port][?transport=udp|tcp]`, in the list's order.
/// `turns:` (TLS) is left out until its ClientHello is libwebrtc's (M8);
/// so are `stun:` and a URL that does not parse.
#[must_use]
pub fn servers(urls: &[String], username: &str, password: &str) -> Vec<TurnServer> {
    let mut out = Vec::new();
    for url in urls {
        let Some(rest) = url.strip_prefix("turn:") else {
            continue;
        };
        let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut transport = "udp";
        for kv in query.split('&').filter(|kv| !kv.is_empty()) {
            match kv.split_once('=') {
                Some(("transport", t)) => transport = t,
                _ => transport = "",
            }
        }
        let transport = match transport.to_ascii_lowercase().as_str() {
            "udp" => TurnTransport::Udp,
            "tcp" => TurnTransport::Tcp,
            _ => continue,
        };
        let Some((host, port)) = split_host_port(addr) else {
            continue;
        };
        let s = TurnServer {
            host: host.to_owned(),
            port,
            transport,
            username: username.to_owned(),
            password: password.to_owned(),
        };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// `host`, `host:port`, `[v6]` and `[v6]:port`.
fn split_host_port(s: &str) -> Option<(&str, u16)> {
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
        None => DEFAULT_PORT,
        Some(p) => p.parse().ok().filter(|p| *p != 0)?,
    };
    Some((host, port))
}

/// A [`TurnServer`] whose host resolved.
#[derive(Clone)]
pub(crate) struct Resolved {
    pub(crate) addr: SocketAddr,
    pub(crate) transport: TurnTransport,
    pub(crate) username: String,
    pub(crate) password: String,
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
            addr,
            transport: s.transport,
            username: s.username.clone(),
            password: s.password.clone(),
        });
    }
    out
}

/// The allocations one peer connection holds at most: SaluteJazz's
/// `rtc:config` names two TURN hosts (`a-t`, `s-t`), each over UDP, TCP and
/// TLS, and Chrome allocates on all six. This client takes the UDP and TCP
/// four; six leaves room for TLS without letting a long list open sockets'
/// worth of state.
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
    /// An allocation is up: its relayed address, the local candidate's.
    Allocated(SocketAddr),
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
}

struct Relay {
    client: TurnClient,
    server: SocketAddr,
    /// How what the client sends reaches the server.
    path: Path,
    /// The server's nonce was looked at for RFC 8489's cookie (logged once:
    /// Chrome ignores the cookie, turn-client-proto follows it, M8's X6).
    cookie_seen: bool,
    relayed: Option<SocketAddr>,
    /// The remote addresses a permission was asked for.
    permitted: Vec<IpAddr>,
    /// The remotes a channel was asked for.
    bound: Vec<SocketAddr>,
    /// The allocation failed or closed: nothing more goes through it.
    done: bool,
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
    /// nonce cookie (Chrome ignores the cookie, turn-client-proto follows
    /// it, M8's X6).
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
                // SHA-1 stays first: a classic server's challenge (no RFC
                // 8489 nonce cookie: pion's, coturn's by default) gets
                // MESSAGE-INTEGRITY with the MD5 key, as Chrome sends. A
                // server with the cookie lists its password algorithms;
                // turn-client-proto takes its first one we know and echoes
                // the list, which Chrome never does (M8's X6). webrtc-rs's
                // server answers every such request with
                // MESSAGE-INTEGRITY-SHA256, which only SHA-256 here accepts.
                cfg.add_supported_integrity(IntegrityAlgorithm::Sha256);
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
                    TurnTransport::Tcp => {
                        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
                        tokio::spawn(stream(slot, s.addr, rx, inbound.clone()));
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
                    cookie_seen: false,
                    relayed: None,
                    permitted: Vec::with_capacity(MAX_PEERS),
                    bound: Vec::with_capacity(MAX_PEERS),
                    done: false,
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
            olc_net::debug!("webrtc: TURN server {from} over TCP: the connection ended");
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
        let mut wake: Option<Instant> = None;
        for r in &mut self.list {
            if r.done {
                continue;
            }
            match r.client.poll(at) {
                TurnPollRet::WaitUntil(w) => {
                    // Never in the past: a client that asks for "now" again
                    // right after its poll would spin the driver.
                    let w = (base + Duration::from_nanos(u64::try_from(w.as_nanos()).unwrap_or(0)))
                        .max(now + MIN_WAKE);
                    wake = Some(wake.map_or(w, |x| x.min(w)));
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
                        events.push(RelayEvent::Allocated(relayed));
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
    /// task sends its queue and ends once the relays are dropped.
    pub(crate) fn close(&mut self, sock: &UdpSocket, now: Instant) {
        let at = self.at(now);
        for r in &mut self.list {
            if !r.done && r.relayed.is_some() {
                let _ = r.client.delete(at);
            }
            while let Some(t) = r.client.poll_transmit(at) {
                let _ = r.path.send(sock, t.to, t.data.as_ref());
            }
            r.done = true;
        }
    }
}

/// One TURN server's TCP connection: dials it from a protected socket,
/// writes what `out` holds, reads into chunks for the driver. It ends when
/// the server closes the connection or a write stalls for
/// [`STREAM_WRITE_STALL`] (the driver hears an empty chunk), or when the
/// relays are dropped: then it writes what is queued (a closing Refresh)
/// and shuts the connection down, within [`crate::peer::CLOSE_DRAIN`].
async fn stream(
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
            username: "1700000000:user".into(),
            password: "s3cr3t-credential".into(),
        };
        let shown = format!("{s:?}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(!shown.contains("1700000000:user"), "{shown}");
        assert!(shown.contains("a-t.example"), "{shown}");
    }

    /// SaluteJazz's `rtc:config` as the spike's probe (e) logged it: of six
    /// URLs, the four `turn:` ones, over UDP and TCP, in the list's order
    /// (`turns:` waits for libwebrtc's TLS hello).
    #[test]
    fn the_udp_and_tcp_turn_urls_are_taken() {
        let got = servers(
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
        assert!(got.iter().all(|s| s.username == "u" && s.password == "p"));
    }

    #[test]
    fn a_turn_url_reads_as_pion_reads_it() {
        let one = |u: &str| servers(&urls(&[u]), "u", "p");
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
            servers(&urls(&["turn:h", "turn:h:3478?transport=udp"]), "u", "p").len(),
            1
        );
        assert_eq!(
            servers(&urls(&["turn:h", "turn:h?transport=tcp"]), "u", "p").len(),
            2
        );
    }

    #[tokio::test]
    async fn literals_resolve_to_their_family_at_most_max_allocations() {
        let entry = |host: String, transport| TurnServer {
            host,
            port: 3478,
            transport,
            username: "u".into(),
            password: "p".into(),
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
                if let Some(RelayEvent::Allocated(a)) = up.first() {
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
            relays.close(&sock, Instant::now());
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
                addr: server,
                transport: TurnTransport::Tcp,
                username: "u".into(),
                password: "p".into(),
            }];
            let (inbound, mut chunks) = mpsc::channel(STREAM_INBOUND);
            let mut relays = Relays::new(&resolved, local, Instant::now(), &inbound);
            let mut up = Vec::new();
            relays.poll(&sock, "t", Instant::now(), &mut up);
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 20];
            conn.read_exact(&mut head).await.unwrap();
            // An Allocate request (0x0003) with STUN's magic cookie.
            assert_eq!(&head[..2], &[0x00, 0x03], "{head:02x?}");
            assert_eq!(&head[4..8], &[0x21, 0x12, 0xa4, 0x42], "{head:02x?}");
            let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
            let mut body = vec![0u8; len];
            conn.read_exact(&mut body).await.unwrap();
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
}

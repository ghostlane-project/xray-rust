// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! TURN relays for one peer connection: turn-client-proto's UDP client on the
//! peer's own socket, as Chrome shares one UDP socket between its host
//! candidate and its TURN allocations.
//!
//! SaluteJazz's SFU offers only private host candidates, so a client reaches
//! it through Sber's TURN or not at all. The Go engine at 2d4266af hands the
//! `rtc:config` servers to pion, which allocated over UDP there (the valid
//! pairs of `t3-live-1` are `relay` at local preference 3, pion's UDP); this
//! module does the same. TURN over TCP and TLS, which `rtc:config` lists too,
//! were not used by pion and come later.
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

use tokio::net::UdpSocket;
use turn_client_proto::api::{
    TurnClientApi, TurnConfig, TurnEvent, TurnPeerData, TurnPollRet, TurnRecvRet,
};
use turn_client_proto::prelude::DelayedTransmitBuild;
use turn_client_proto::stun::agent::Transmit;
use turn_client_proto::stun::Instant as TurnInstant;
use turn_client_proto::types::stun::message::IntegrityAlgorithm;
use turn_client_proto::types::{AddressFamily, TransportType, TurnCredentials};
use turn_client_proto::udp::TurnClientUdp;

/// A TURN server from the carrier's ICE servers (WebRTC's `RTCIceServer`,
/// one `turn:` URL over UDP), its host not yet resolved.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// The server's host name or address literal (without brackets).
    pub host: String,
    /// Its port (3478 when the URL names none).
    pub port: u16,
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
            .field("username_len", &self.username.len())
            .field("password_len", &self.password.len())
            .finish()
    }
}

/// TURN's default port (RFC 8656 §3.1, pion's `DefaultPort` for `turn:`).
pub const DEFAULT_PORT: u16 = 3478;

/// The UDP TURN servers of one ICE server entry: each `turn:` URL whose
/// transport is UDP (named or by default), as pion's `ParseURL` reads
/// `turn:host[:port][?transport=udp|tcp]`. `turns:`, `stun:` and TCP are
/// left out (pion allocated over UDP on SaluteJazz; TCP and TLS come
/// later); so is a URL that does not parse.
#[must_use]
pub fn udp_servers(urls: &[String], username: &str, password: &str) -> Vec<TurnServer> {
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
        if !transport.eq_ignore_ascii_case("udp") {
            continue;
        }
        let Some((host, port)) = split_host_port(addr) else {
            continue;
        };
        let s = TurnServer {
            host: host.to_owned(),
            port,
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
        if out.iter().any(|r: &Resolved| r.addr == addr) {
            continue;
        }
        out.push(Resolved {
            addr,
            username: s.username.clone(),
            password: s.password.clone(),
        });
    }
    out
}

/// The allocations one peer connection holds at most: SaluteJazz's
/// `rtc:config` names two TURN hosts over UDP (`a-t`, `s-t`), and Chrome
/// allocates on each; twice that leaves room for a carrier listing more
/// without letting a long list open sockets' worth of state.
pub const MAX_ALLOCATIONS: usize = 4;

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
/// [`SEND_BUF`] for wrapping. Their memory is that and turn-client-proto's
/// state per allocation (its transactions, one per request in flight, and
/// the permission and channel lists our caps bound).
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
    client: TurnClientUdp,
    server: SocketAddr,
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

impl Relays {
    /// An allocation request on each of `servers` (the first
    /// [`MAX_ALLOCATIONS`] of `local`'s family), from `local`. Nothing is
    /// sent until [`Relays::poll`].
    pub(crate) fn new(servers: &[Resolved], local: SocketAddr, base: Instant) -> Relays {
        let list = servers
            .iter()
            .filter(|s| s.addr.is_ipv4() == local.is_ipv4())
            .take(MAX_ALLOCATIONS)
            .map(|s| {
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
                Relay {
                    client: TurnClientUdp::allocate(local, s.addr, cfg),
                    server: s.addr,
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

    /// Hands a datagram from `from` to the relay whose server sent it.
    pub(crate) fn recv<'a>(
        &mut self,
        from: SocketAddr,
        data: &'a [u8],
        now: Instant,
    ) -> Arrival<'a> {
        let at = self.at(now);
        let local = self.local;
        let Some(r) = self.list.iter_mut().find(|r| r.server == from) else {
            return Arrival::Direct;
        };
        if !r.cookie_seen && data.len() > 20 && data[0] == 0x01 && data[1] == 0x13 {
            r.cookie_seen = true;
            let cookie = data
                .windows(RFC8489_COOKIE.len())
                .any(|w| w == RFC8489_COOKIE);
            olc_net::debug!(
                "webrtc: TURN server {from} challenge, RFC 8489 nonce cookie: {}",
                if cookie { "yes" } else { "no" }
            );
        }
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
                let w = wrapped.write_into(&mut self.out);
                if let Err(e) = sock.try_send_to(w.data, server) {
                    self.dropped += 1;
                    if e.kind() != io::ErrorKind::WouldBlock {
                        self.refused = Some((server, e));
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
                if sock.try_send_to(t.data.as_ref(), t.to).is_err() {
                    self.dropped += 1;
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
    /// sends on close) and sends those requests once.
    pub(crate) fn close(&mut self, sock: &UdpSocket, now: Instant) {
        let at = self.at(now);
        for r in &mut self.list {
            if !r.done && r.relayed.is_some() {
                let _ = r.client.delete(at);
            }
            while let Some(t) = r.client.poll_transmit(at) {
                let _ = sock.try_send_to(t.data.as_ref(), t.to);
            }
            r.done = true;
        }
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
            username: "1700000000:user".into(),
            password: "s3cr3t-credential".into(),
        };
        let shown = format!("{s:?}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(!shown.contains("1700000000:user"), "{shown}");
        assert!(shown.contains("a-t.example"), "{shown}");
    }

    /// SaluteJazz's `rtc:config` as the spike's probe (e) logged it: of six
    /// URLs, the two `turn:` ones over UDP are used.
    #[test]
    fn only_the_udp_turn_urls_are_taken() {
        let got = udp_servers(
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
        let hosts: Vec<_> = got.iter().map(|s| (s.host.as_str(), s.port)).collect();
        assert_eq!(
            hosts,
            [("a-t.salutejazz.ru", 3478), ("s-t.salutejazz.ru", 3478)]
        );
        assert!(got.iter().all(|s| s.username == "u" && s.password == "p"));
    }

    #[test]
    fn a_turn_url_reads_as_pion_reads_it() {
        let one = |u: &str| udp_servers(&urls(&[u]), "u", "p");
        assert_eq!(one("turn:192.0.2.1")[0].port, DEFAULT_PORT);
        assert_eq!(one("turn:[2001:db8::1]:5000")[0].host, "2001:db8::1");
        assert_eq!(one("turn:[2001:db8::1]")[0].port, DEFAULT_PORT);
        assert_eq!(one("turn:h:3479?transport=UDP")[0].port, 3479);
        for bad in [
            "stun:stun.l.google.com:19302",
            "turn:",
            "turn::3478",
            "turn:h:0",
            "turn:h:x",
            "turn:2001:db8::1",
            "turn:h?transport=tcp",
            "turn:h?foo=bar",
        ] {
            assert!(one(bad).is_empty(), "{bad}");
        }
        // The same server twice is allocated on once.
        assert_eq!(
            udp_servers(&urls(&["turn:h", "turn:h:3478?transport=udp"]), "u", "p").len(),
            1
        );
    }

    #[tokio::test]
    async fn literals_resolve_to_their_family_at_most_max_allocations() {
        let servers: Vec<TurnServer> = (1..=6)
            .map(|i| TurnServer {
                host: format!("192.0.2.{i}"),
                port: 3478,
                username: "u".into(),
                password: "p".into(),
            })
            .chain(std::iter::once(TurnServer {
                host: "2001:db8::1".into(),
                port: 3478,
                username: "u".into(),
                password: "p".into(),
            }))
            .collect();
        let got = crate::testing::bounded(resolve(&servers, true)).await;
        assert_eq!(got.len(), MAX_ALLOCATIONS);
        assert!(got.iter().all(|r| r.addr.is_ipv4()));
        let v6 = crate::testing::bounded(resolve(&servers[6..], false)).await;
        assert_eq!(v6.len(), 1);
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
            let mut relays = Relays::new(&resolved, local, Instant::now());
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
}

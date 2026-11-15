// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The resolver ring (`protect.Resolver`, protect/resolver.go): the names
//! the engine itself dials (a direct rule's target, a carrier's host) are
//! looked up on the configured DNS servers over protected sockets, and the
//! host's resolver answers when they give nothing.
//!
//! As in Go:
//!
//! - the list is what a platform hands over (commas, semicolons, spaces;
//!   [`split_dns_servers`]); each entry is normalised (`host` → `host:53`)
//!   and a public operator's IPv4 address brings its IPv6 twin, then, when a
//!   configured server is a public operator, the other operators follow at
//!   its port ([`expand_dns_servers`]): an IPv6-only network still reaches
//!   one;
//! - it is not a rotation: every query goes to the preferred server, which
//!   moves on only when a query to it goes unanswered; any answer, NXDOMAIN
//!   included, is an answer;
//! - after [`RING_DARK_AFTER`] unanswered queries with no answer between
//!   them the ring is dark for [`RING_DARK_WINDOW`]: a lookup asks the host
//!   first then, and the ring after it; an exchange (the direct DNS path)
//!   asks the ring all the same;
//! - each attempt is bounded: [`QUERY_TIMEOUT`] a query,
//!   [`CONFIGURED_LOOKUP_BUDGET`] the configured servers,
//!   [`SYSTEM_LOOKUP_BUDGET`] the host's resolver.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::net;

/// Unanswered queries in a row after which the ring is dark
/// (`ringDarkAfter`).
pub const RING_DARK_AFTER: u32 = 3;
/// How long a dark ring is asked after the host (`ringDarkWindow`).
pub const RING_DARK_WINDOW: Duration = Duration::from_secs(30);
/// One query's wait (`dnsQueryTimeout`).
pub const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// The configured servers' whole attempt (`configuredLookupBudget`).
pub const CONFIGURED_LOOKUP_BUDGET: Duration = Duration::from_secs(4);
/// The host resolver's attempt (`systemLookupBudget`).
pub const SYSTEM_LOOKUP_BUDGET: Duration = Duration::from_secs(5);
/// Resolving a server given by name (`defaultDNSTimeout`).
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// Attempts per family, as Go's resolver (`attempts: 2`).
pub const ATTEMPTS: usize = 2;
/// The largest answer read (`exchangeBufferSize`).
pub const ANSWER_BUFFER: usize = 4096;

/// `dnsIPv6Peer`: a public IPv4 resolver's IPv6 twin.
const IPV6_PEER: [(&str, &str); 6] = [
    ("1.1.1.1", "2606:4700:4700::1111"),
    ("1.0.0.1", "2606:4700:4700::1001"),
    ("8.8.8.8", "2001:4860:4860::8888"),
    ("8.8.4.4", "2001:4860:4860::8844"),
    ("9.9.9.9", "2620:fe::fe"),
    ("149.112.112.112", "2620:fe::9"),
];

/// `publicOperators`: the fallback order behind a public operator.
const PUBLIC_OPERATORS: [(&str, &str); 3] = [
    ("1.1.1.1", "2606:4700:4700::1111"),
    ("8.8.8.8", "2001:4860:4860::8888"),
    ("9.9.9.9", "2620:fe::fe"),
];

/// `SplitDNSServers`: the entries of a list separated by commas,
/// semicolons or white space.
#[must_use]
pub fn split_dns_servers(list: &str) -> Vec<&str> {
    list.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `net.SplitHostPort`'s split, enough for the forms a list holds.
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        return Some((host, port));
    }
    let (host, port) = s.rsplit_once(':')?;
    (!host.contains(':')).then_some((host, port))
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `normalizeDNSServer`: `host`, `host:port` and `[v6]:port`.
fn normalize(server: &str) -> Option<String> {
    let t = server.trim();
    if t.is_empty() {
        return None;
    }
    if split_host_port(t).is_some() {
        return Some(t.to_owned());
    }
    Some(join_host_port(
        t.trim_matches(|c| c == '[' || c == ']'),
        "53",
    ))
}

fn ipv6_peer(host: &str) -> Option<&'static str> {
    IPV6_PEER
        .iter()
        .find(|(v4, _)| *v4 == host)
        .map(|(_, v6)| *v6)
}

/// `expandDNSServers`: each server normalised and followed by its IPv6
/// twin, duplicates dropped, order kept; the other public operators behind
/// them when one of them is a public operator.
#[must_use]
pub fn expand_dns_servers(servers: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(servers.len() * 2);
    let mut add = |addr: String| {
        if !out.contains(&addr) {
            out.push(addr);
        }
    };
    let mut public_port: Option<String> = None;
    for entry in servers {
        for server in split_dns_servers(entry) {
            let Some(addr) = normalize(server) else {
                continue;
            };
            if let Some((host, port)) = split_host_port(&addr) {
                if let Some(peer) = ipv6_peer(host) {
                    if public_port.is_none() {
                        public_port = Some(port.to_owned());
                    }
                    let twin = join_host_port(peer, port);
                    add(addr);
                    add(twin);
                    continue;
                }
            }
            add(addr);
        }
    }
    if let Some(port) = public_port {
        for (v4, v6) in PUBLIC_OPERATORS {
            add(join_host_port(v4, &port));
            add(join_host_port(v6, &port));
        }
    }
    out
}

/// The configured servers in preference order (`serverRing`).
#[derive(Debug)]
pub(crate) struct Ring {
    servers: Vec<String>,
    preferred: AtomicUsize,
    /// Unanswered queries since the last answer.
    silences: AtomicU32,
    /// When `silences` reached [`RING_DARK_AFTER`].
    dark_at: Mutex<Option<Instant>>,
}

impl Ring {
    fn new(servers: Vec<String>) -> Option<Self> {
        (!servers.is_empty()).then(|| Self {
            servers,
            preferred: AtomicUsize::new(0),
            silences: AtomicU32::new(0),
            dark_at: Mutex::new(None),
        })
    }

    fn dark_at(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.dark_at.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the servers went unanswered recently enough for that to
    /// still be the expectation; past the window the count starts over.
    pub(crate) fn dark(&self, now: Instant) -> bool {
        let mut at = self.dark_at();
        match *at {
            None => false,
            Some(t) if now.saturating_duration_since(t) <= RING_DARK_WINDOW => true,
            Some(_) => {
                *at = None;
                self.silences.store(0, Ordering::Relaxed);
                false
            }
        }
    }

    fn note_answer(&self) {
        self.silences.store(0, Ordering::Relaxed);
        *self.dark_at() = None;
    }

    pub(crate) fn note_silence(&self, idx: usize) {
        // Past a silent server once: two queries timing out on it together
        // must not skip the one after it.
        let _ = self.preferred.compare_exchange(
            idx,
            (idx + 1) % self.servers.len(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        if self.silences.fetch_add(1, Ordering::Relaxed) + 1 >= RING_DARK_AFTER {
            self.dark_at().get_or_insert_with(Instant::now);
        }
    }

    /// A query socket to the preferred server, or the next one that can be
    /// reached (on an IPv6-only network the IPv4 ones cannot).
    async fn dial(&self) -> io::Result<(UdpSocket, usize)> {
        let count = self.servers.len();
        let start = self.preferred.load(Ordering::Relaxed) % count;
        let mut first: Option<io::Error> = None;
        for i in 0..count {
            let idx = (start + i) % count;
            match connect_udp(&self.servers[idx]).await {
                Ok(sock) => return Ok((sock, idx)),
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        Err(unreachable(first))
    }

    /// Sends `query` and reads one answer into `buf`, telling the ring how
    /// it went: any answer is one; silence moves the ring on.
    async fn ask(&self, query: &[u8], buf: &mut [u8]) -> io::Result<usize> {
        let (sock, idx) = self.dial().await?;
        sock.send(query).await?;
        // A query still waiting when its lookup's budget ends it went
        // unanswered too.
        let mut waiting = Waiting {
            ring: self,
            idx,
            done: false,
        };
        let got = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(buf)).await;
        waiting.done = true;
        match got {
            Ok(Ok(n)) => {
                if n > 0 {
                    self.note_answer();
                }
                Ok(n)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.note_silence(idx);
                Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))
            }
        }
    }
}

struct Waiting<'a> {
    ring: &'a Ring,
    idx: usize,
    done: bool,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.ring.note_silence(self.idx);
        }
    }
}

fn unreachable(first: Option<io::Error>) -> io::Error {
    let what = "no configured dns server could be reached";
    match first {
        Some(e) => io::Error::new(e.kind(), format!("{what}: {e}")),
        None => io::Error::new(io::ErrorKind::NotConnected, what),
    }
}

/// A connected, protected UDP socket to `server`; a scoped link-local
/// address (`fe80::1%pdp_ip0`) by its interface, a name by the host's
/// resolver.
async fn connect_udp(server: &str) -> io::Result<UdpSocket> {
    let addr = server_addr(server).await?;
    let sock = net::udp_socket(addr.ip()).await?;
    sock.connect(addr).await?;
    Ok(sock)
}

async fn server_addr(server: &str) -> io::Result<SocketAddr> {
    if let Ok(a) = server.parse::<SocketAddr>() {
        return Ok(a);
    }
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bad dns server {server:?}"),
        )
    };
    let (host, port) = split_host_port(server).ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    if let Some((ip, zone)) = host.split_once('%') {
        let ip: Ipv6Addr = ip.parse().map_err(|_| bad())?;
        let scope = zone
            .parse::<u32>()
            .ok()
            .or_else(|| crate::sys::if_index(zone))
            .ok_or_else(bad)?;
        return Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)));
    }
    match tokio::time::timeout(DEFAULT_DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(mut addrs)) => addrs.next().ok_or_else(bad),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")),
    }
}

/// A resolver over a ring (`protect.Resolver`). The process has one,
/// behind [`set_servers`], [`lookup`], [`has_servers`] and [`exchange`].
#[derive(Debug)]
pub struct Resolver {
    ring: Mutex<Option<Arc<Ring>>>,
    /// Whether the host's resolver is asked (Go's `system`; the tests turn
    /// it off).
    system: bool,
}

static DEFAULT: Resolver = Resolver::new();

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    /// A resolver with no servers, which asks only the host.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ring: Mutex::new(None),
            system: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn without_system(servers: &str) -> Self {
        let r = Self {
            ring: Mutex::new(None),
            system: false,
        };
        r.set_servers(servers);
        r
    }

    /// Replaces the servers (`SetServers`): lookups in flight finish on the
    /// old ring.
    pub fn set_servers(&self, servers: &str) {
        let ring = Ring::new(expand_dns_servers(&split_dns_servers(servers))).map(Arc::new);
        *self.ring.lock().unwrap_or_else(PoisonError::into_inner) = ring;
    }

    pub(crate) fn ring(&self) -> Option<Arc<Ring>> {
        self.ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The expanded servers in the order they are asked (`Servers`).
    pub fn servers(&self) -> Vec<String> {
        self.ring().map(|r| r.servers.clone()).unwrap_or_default()
    }

    /// Whether any server is configured (`HasServers`).
    pub fn has_servers(&self) -> bool {
        self.ring().is_some()
    }

    /// Sends `query` as it is to the preferred server and returns the
    /// answer as sent (`Exchange`). A dark ring is asked all the same;
    /// silence moves it on, and the query is not retried here, since the
    /// resolver that sent it will.
    ///
    /// # Errors
    /// No servers, none reachable, the socket's error, or silence.
    pub async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let ring = self.ring().ok_or_else(|| unreachable(None))?;
        let mut buf = vec![0u8; ANSWER_BUFFER];
        let n = ring
            .ask(query, &mut buf)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("read answer: {e}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The addresses of `host`, IPv4 first (`LookupFamilies`): a literal is
    /// itself; a name is asked of the servers, then of the host, each on a
    /// budget; servers that just went dark are asked after the host.
    ///
    /// # Errors
    /// No address from either, with what each said.
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let bare = host.split_once('%').map_or(host, |(ip, _)| ip);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let Some(ring) = self.ring() else {
            if !self.system {
                return Err(lookup_error(host, Some(&unreachable(None)), None));
            }
            return match system_lookup(host).await {
                Ok(ips) => Ok(ips),
                Err(e) => Err(lookup_error(host, None, Some(&e))),
            };
        };
        let dark = self.system && ring.dark(Instant::now());
        let mut configured = None;
        if !dark {
            match configured_lookup(&ring, host).await {
                Ok(ips) => return Ok(ips),
                Err(e) => configured = Some(e),
            }
            if !self.system {
                return Err(lookup_error(host, configured.as_ref(), None));
            }
        }
        let system = match system_lookup(host).await {
            Ok(ips) => return Ok(ips),
            Err(e) => e,
        };
        if dark {
            // The host had nothing either: the servers get their turn.
            match configured_lookup(&ring, host).await {
                Ok(ips) => return Ok(ips),
                Err(e) => configured = Some(e),
            }
        }
        Err(lookup_error(host, configured.as_ref(), Some(&system)))
    }
}

/// `lookupError`: which resolver was asked and what each said.
fn lookup_error(
    host: &str,
    configured: Option<&io::Error>,
    system: Option<&io::Error>,
) -> io::Error {
    let mut parts = Vec::with_capacity(2);
    if let Some(e) = configured {
        parts.push(format!("configured servers: {e}"));
    }
    if let Some(e) = system {
        parts.push(format!("host resolver: {e}"));
    }
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("lookup {host}: {}", parts.join("; ")),
    )
}

fn no_addresses() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no such host")
}

/// Both families on the servers, concurrently, within
/// [`CONFIGURED_LOOKUP_BUDGET`]; an error unless some address came.
async fn configured_lookup(ring: &Ring, host: &str) -> io::Result<Vec<IpAddr>> {
    let both = async {
        let (v4, v6) = tokio::join!(
            lookup_family(ring, host, TYPE_A),
            lookup_family(ring, host, TYPE_AAAA)
        );
        match (v4, v6) {
            (Ok(mut a), Ok(b)) => {
                a.extend(b);
                Ok(a)
            }
            (Ok(a), Err(e)) | (Err(e), Ok(a)) if a.is_empty() => Err(e),
            (Ok(a), Err(_)) | (Err(_), Ok(a)) => Ok(a),
            (Err(e), Err(_)) => Err(e),
        }
    };
    match tokio::time::timeout(CONFIGURED_LOOKUP_BUDGET, both).await {
        Ok(Ok(ips)) if !ips.is_empty() => Ok(ips),
        Ok(Ok(_)) => Err(no_addresses()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")),
    }
}

/// One family, up to [`ATTEMPTS`] queries: an answer ends it, an empty or
/// NXDOMAIN one too; a server failure or refusal tries again.
async fn lookup_family(ring: &Ring, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    // On the heap for the lookup's life, not in the future: both families
    // run at once, and an array here put 8 KiB into every future that may
    // look a name up, every SOCKS connection's task among them (gap 18).
    let mut buf = vec![0u8; ANSWER_BUFFER];
    let mut last = no_addresses();
    for _ in 0..ATTEMPTS {
        let id: u16 = rand::random();
        let q = build_query(id, host, qtype)?;
        match ring.ask(&q, &mut buf).await {
            Ok(n) => {
                let msg = &buf[..n];
                match msg.get(3).map(|b| b & 0x0f) {
                    Some(RCODE_SERVFAIL | RCODE_REFUSED) => {
                        last = io::Error::other("server misbehaving");
                        continue;
                    }
                    Some(RCODE_NXDOMAIN) if parse_answer(msg, id, qtype).is_some() => {
                        return Err(no_addresses());
                    }
                    _ => {}
                }
                match parse_answer(msg, id, qtype) {
                    Some(ips) => return Ok(ips),
                    None => {
                        last = io::Error::new(io::ErrorKind::InvalidData, "dns: malformed answer")
                    }
                }
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

/// The host's resolver within [`SYSTEM_LOOKUP_BUDGET`]: inside an iOS
/// packet tunnel it points into the tunnel itself.
async fn system_lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    match tokio::time::timeout(SYSTEM_LOOKUP_BUDGET, tokio::net::lookup_host((host, 0))).await {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            ips.sort_by_key(IpAddr::is_ipv6);
            if ips.is_empty() {
                Err(no_addresses())
            } else {
                Ok(ips)
            }
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")),
    }
}

/// Sets the process resolver's servers ([`Resolver::set_servers`]).
pub fn set_servers(servers: &str) {
    DEFAULT.set_servers(servers);
}

/// [`Resolver::lookup`] on the process resolver.
///
/// # Errors
/// As [`Resolver::lookup`].
pub async fn lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    DEFAULT.lookup(host).await
}

/// [`Resolver::has_servers`] on the process resolver.
pub fn has_servers() -> bool {
    DEFAULT.has_servers()
}

/// [`Resolver::exchange`] on the process resolver.
///
/// # Errors
/// As [`Resolver::exchange`].
pub async fn exchange(query: &[u8]) -> io::Result<Vec<u8>> {
    DEFAULT.exchange(query).await
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// A recursive query for `name`, type `qtype`.
///
/// # Errors
/// `InvalidInput` for a name DNS cannot carry.
pub fn build_query(id: u16, name: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|&l| (1..64).contains(&l))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dns: bad name"))?;
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    Ok(q)
}

/// The addresses of type `qtype` in an answer to query `id`.
pub fn parse_answer(msg: &[u8], id: u16, qtype: u16) -> Option<Vec<IpAddr>> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id || msg[2] & 0x80 == 0 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut at = 12;
    for _ in 0..qd {
        at = skip_name(msg, at)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        at = skip_name(msg, at)?;
        let head = msg.get(at..at + 10)?;
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let rdlen = usize::from(u16::from_be_bytes([head[8], head[9]]));
        let data = msg.get(at + 10..at + 10 + rdlen)?;
        match (rtype, qtype, rdlen) {
            (TYPE_A, TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (TYPE_AAAA, TYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(data);
                out.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            _ => {}
        }
        at += 10 + rdlen;
    }
    Some(out)
}

fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)?;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        if len == 0 {
            return Some(at + 1);
        }
        at += 1 + usize::from(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_and_its_answer() {
        let q = build_query(0x1234, "a.example", TYPE_A).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..], b"\x01a\x07example\x00\x00\x01\x00\x01");
        let mut ans = q.clone();
        ans[2] |= 0x80;
        ans[7] = 1;
        ans.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        assert_eq!(
            parse_answer(&ans, 0x1234, TYPE_A).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
        );
        assert!(parse_answer(&ans, 0x9999, TYPE_A).is_none());
        assert!(build_query(1, &"x".repeat(64), TYPE_A).is_err());
    }

    #[test]
    fn the_list_expands_as_go_expands_it() {
        // resolver_test.go's vectors at 2d4266af.
        let cf = "1.1.1.1:53";
        let cases: &[(&[&str], &[&str])] = &[
            (
                &[cf],
                &[
                    cf,
                    "[2606:4700:4700::1111]:53",
                    "8.8.8.8:53",
                    "[2001:4860:4860::8888]:53",
                    "9.9.9.9:53",
                    "[2620:fe::fe]:53",
                ],
            ),
            (
                &["8.8.8.8"],
                &[
                    "8.8.8.8:53",
                    "[2001:4860:4860::8888]:53",
                    "1.1.1.1:53",
                    "[2606:4700:4700::1111]:53",
                    "9.9.9.9:53",
                    "[2620:fe::fe]:53",
                ],
            ),
            (&["2620:fe::fe"], &["[2620:fe::fe]:53"]),
            (&["resolver.example:5353"], &["resolver.example:5353"]),
            (
                &["1.1.1.1", cf, "9.9.9.9"],
                &[
                    cf,
                    "[2606:4700:4700::1111]:53",
                    "9.9.9.9:53",
                    "[2620:fe::fe]:53",
                    "8.8.8.8:53",
                    "[2001:4860:4860::8888]:53",
                ],
            ),
            (
                &["", "   ", "1.0.0.1:53"],
                &[
                    "1.0.0.1:53",
                    "[2606:4700:4700::1001]:53",
                    "1.1.1.1:53",
                    "[2606:4700:4700::1111]:53",
                    "8.8.8.8:53",
                    "[2001:4860:4860::8888]:53",
                    "9.9.9.9:53",
                    "[2620:fe::fe]:53",
                ],
            ),
            (&["10.0.0.1:53"], &["10.0.0.1:53"]),
            (
                &["10.0.0.1:53, fe80::1%pdp_ip0 1.1.1.1:53"],
                &[
                    "10.0.0.1:53",
                    "[fe80::1%pdp_ip0]:53",
                    "1.1.1.1:53",
                    "[2606:4700:4700::1111]:53",
                    "8.8.8.8:53",
                    "[2001:4860:4860::8888]:53",
                    "9.9.9.9:53",
                    "[2620:fe::fe]:53",
                ],
            ),
        ];
        for (input, want) in cases {
            let got = expand_dns_servers(input);
            assert_eq!(got, *want, "{input:?}");
            for addr in &got {
                assert!(split_host_port(addr).is_some(), "{addr} is not dialable");
            }
        }
        assert_eq!(
            split_dns_servers(" 10.0.0.1:53, fe80::1%pdp_ip0 ;1.1.1.1 "),
            ["10.0.0.1:53", "fe80::1%pdp_ip0", "1.1.1.1"]
        );
        assert!(split_dns_servers(" , ; ").is_empty());
    }

    /// A DNS server on loopback: it answers A queries with `Answer`, says
    /// NXDOMAIN, or keeps quiet, and counts what it was asked.
    #[derive(Clone, Copy)]
    enum Fake {
        Answer([u8; 4]),
        NxDomain,
        Silent,
    }

    struct FakeDns {
        addr: String,
        asked: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl FakeDns {
        async fn start(mode: Fake) -> Self {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap().to_string();
            let asked = Arc::new(AtomicUsize::new(0));
            let count = asked.clone();
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 512];
                while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                    count.fetch_add(1, Ordering::SeqCst);
                    let q = &buf[..n];
                    let mut r = q.to_vec();
                    r[2] |= 0x80;
                    match mode {
                        Fake::Silent => continue,
                        Fake::NxDomain => r[3] = (r[3] & 0xf0) | RCODE_NXDOMAIN,
                        Fake::Answer(ip) => {
                            if u16::from_be_bytes([q[n - 4], q[n - 3]]) == TYPE_A {
                                r[7] = 1;
                                r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                                r.extend_from_slice(&ip);
                            }
                        }
                    }
                    let _ = sock.send_to(&r, from).await;
                }
            });
            Self { addr, asked, task }
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    impl Drop for FakeDns {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn nxdomain_is_an_answer_not_a_silence() {
        crate::testing::bounded(async {
            let srv = FakeDns::start(Fake::NxDomain).await;
            let r = Resolver::without_system(&srv.addr);
            for _ in 0..RING_DARK_AFTER + 1 {
                let e = r.lookup("gone.test").await.unwrap_err();
                assert!(e.to_string().ends_with("no such host"), "{e}");
            }
            let ring = r.ring().unwrap();
            assert!(
                !ring.dark(Instant::now()),
                "a name that does not exist darkens nothing"
            );
            assert_eq!(ring.silences.load(Ordering::Relaxed), 0);
            // A query a family, each answered once: NXDOMAIN is not asked again.
            assert_eq!(srv.asked(), 2 * (RING_DARK_AFTER as usize + 1));
        })
        .await;
    }

    #[tokio::test]
    async fn an_exchange_asks_the_ring_while_it_is_dark() {
        crate::testing::bounded(async {
            let srv = FakeDns::start(Fake::Answer([10, 0, 0, 1])).await;
            let r = Resolver::without_system(&srv.addr);
            let ring = r.ring().unwrap();
            for _ in 0..RING_DARK_AFTER {
                ring.note_silence(0);
            }
            assert!(ring.dark(Instant::now()));
            let q = build_query(0x1234, "a.ru", TYPE_A).unwrap();
            let resp = r.exchange(&q).await.unwrap();
            assert_eq!(
                parse_answer(&resp, 0x1234, TYPE_A).unwrap(),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
            );
            assert_eq!(srv.asked(), 1);
            assert!(!ring.dark(Instant::now()), "an answer ends the darkness");
        })
        .await;
    }

    #[tokio::test]
    async fn a_silent_server_hands_the_next_query_to_the_one_after_it() {
        crate::testing::bounded(async {
            let silent = FakeDns::start(Fake::Silent).await;
            let answering = FakeDns::start(Fake::Answer([10, 0, 0, 1])).await;
            let r = Resolver::without_system(&format!("{},{}", silent.addr, answering.addr));
            let q = build_query(0x1234, "a.ru", TYPE_A).unwrap();
            let e = r.exchange(&q).await.unwrap_err();
            assert!(e.to_string().starts_with("read answer: "), "{e}");
            assert_eq!((silent.asked(), answering.asked()), (1, 0));
            r.exchange(&q).await.unwrap();
            assert_eq!((silent.asked(), answering.asked()), (1, 1));
        })
        .await;
    }

    #[tokio::test]
    async fn a_literal_needs_no_lookup() {
        crate::testing::bounded(a_literal_needs_no_lookup_body()).await;
    }

    async fn a_literal_needs_no_lookup_body() {
        assert_eq!(
            lookup("127.0.0.1").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }
}

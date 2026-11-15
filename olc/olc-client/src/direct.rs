// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Direct connections (olcbox#28; `internal/route`, `internal/sniff`,
//! `client/direct.go`).
//!
//! With rules configured, a CONNECT whose target they name is dialed from
//! this process over a protected socket instead of a tunnel stream. A target
//! given as an address the rules do not list may still be a name they do (a
//! tun2socks in front hands over addresses only), so the SOCKS reply goes
//! out first and the client's first bytes are read, at most [`MAX_HEAD`]
//! within [`SNIFF_TIMEOUT`], for a TLS server name or an HTTP Host, while the
//! tunnel is made ready in parallel; the bytes are replayed into whichever
//! outbound wins.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::client::Inner;
use crate::copy::{copy_bidirectional, CopyEnd, HALF_OPEN_GRACE};
use crate::socks::{host_text, Job};
use crate::tunnel::rep;

/// How long a client is given to send something worth reading
/// (`sniffTimeout`).
pub const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

/// The most read before giving up on a name (`sniff.MaxHead`): the largest
/// TLS record, plus its header. The buffer lives only while one connection
/// is sniffed.
pub const MAX_HEAD: usize = 16 * 1024 + TLS_RECORD_HEADER;

const TLS_RECORD_HEADER: usize = 5;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_MAJOR: u8 = 3;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_MAX_RECORD: usize = 16 * 1024;
const TLS_RANDOM_LEN: usize = 32;
const EXT_SERVER_NAME: usize = 0;
const SNI_HOST_NAME: usize = 0;

/// The rules (`route.Rules`): exact names, name suffixes and merged address
/// ranges.
#[derive(Debug, Default, Clone)]
pub struct Rules {
    full: HashSet<String>,
    suffix: HashSet<String>,
    /// Disjoint, sorted by `(family, lo)`.
    ranges: Vec<Range>,
    names: usize,
    prefixes: usize,
}

/// A closed interval of addresses of one family (4 or 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Range {
    family: u8,
    lo: u128,
    hi: u128,
}

fn key(ip: IpAddr) -> (u8, u128) {
    match unmap(ip) {
        IpAddr::V4(a) => (4, u128::from(u32::from(a))),
        IpAddr::V6(a) => (6, u128::from(a)),
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Parses an address as `netip.ParseAddr` does, a zone dropped.
fn parse_addr(s: &str) -> Option<IpAddr> {
    let bare = s.split_once('%').map_or(s, |(a, _)| a);
    if bare.contains(':') {
        bare.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
    } else {
        bare.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
    }
}

fn normalize(name: &str) -> String {
    let t = name.trim();
    t.strip_suffix('.').unwrap_or(t).to_ascii_lowercase()
}

impl Rules {
    /// Reads one rule per line (`route.Parse`): `domain:<name>`,
    /// `full:<name>`, an address or a CIDR prefix; blank lines and `#`
    /// comments are skipped. No rules is `None`.
    ///
    /// # Errors
    /// The line that is not a rule, as Go words it.
    pub fn parse<S: AsRef<str>>(lines: &[S]) -> Result<Option<Self>, String> {
        let mut r = Self::default();
        let text = lines
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join("\n");
        for (n, raw) in text.split('\n').enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            r.add(line)
                .map_err(|e| format!("route: bad rule: line {}: {line:?}: {e}", n + 1))?;
        }
        if r.names == 0 && r.prefixes == 0 {
            return Ok(None);
        }
        r.merge();
        Ok(Some(r))
    }

    fn add(&mut self, line: &str) -> Result<(), &'static str> {
        if let Some(name) = line.strip_prefix("domain:") {
            return Self::add_name(&mut self.suffix, &mut self.names, name);
        }
        if let Some(name) = line.strip_prefix("full:") {
            return Self::add_name(&mut self.full, &mut self.names, name);
        }
        if let Some((addr, bits)) = line.split_once('/') {
            if addr.contains('%') {
                return Err("not a name rule, an address or a prefix");
            }
            let (Some(ip), Ok(bits)) = (parse_addr(addr), bits.parse::<u32>()) else {
                return Err("not a name rule, an address or a prefix");
            };
            let (family, width) = match ip {
                IpAddr::V4(_) => (4, 32),
                IpAddr::V6(_) => (6, 128),
            };
            if bits > width {
                return Err("not a name rule, an address or a prefix");
            }
            let raw = match ip {
                IpAddr::V4(a) => u128::from(u32::from(a)),
                IpAddr::V6(a) => u128::from(a),
            };
            let host_bits = width - bits;
            let mask = if host_bits >= 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            self.ranges.push(Range {
                family,
                lo: raw & !mask,
                hi: raw | mask,
            });
            self.prefixes += 1;
            return Ok(());
        }
        if let Some(ip) = parse_addr(line) {
            // Kept as written: a mapped literal never matches, as in Go,
            // since `MatchIP` unmaps what it is asked.
            let (family, v) = match ip {
                IpAddr::V4(a) => (4, u128::from(u32::from(a))),
                IpAddr::V6(a) => (6, u128::from(a)),
            };
            self.ranges.push(Range {
                family,
                lo: v,
                hi: v,
            });
            self.prefixes += 1;
            return Ok(());
        }
        Err("not a name rule, an address or a prefix")
    }

    fn add_name(
        set: &mut HashSet<String>,
        count: &mut usize,
        raw: &str,
    ) -> Result<(), &'static str> {
        let name = normalize(raw);
        if name.is_empty() {
            return Err("empty name");
        }
        if name.contains([' ', '\t']) {
            return Err("name contains whitespace");
        }
        set.insert(name);
        *count += 1;
        Ok(())
    }

    fn merge(&mut self) {
        self.ranges.sort();
        let mut out: Vec<Range> = Vec::with_capacity(self.ranges.len());
        for cur in self.ranges.drain(..) {
            if let Some(last) = out.last_mut() {
                if last.family == cur.family
                    && (cur.lo <= last.hi || last.hi.checked_add(1) == Some(cur.lo))
                {
                    last.hi = last.hi.max(cur.hi);
                    continue;
                }
            }
            out.push(cur);
        }
        out.shrink_to_fit();
        self.ranges = out;
    }

    /// One of the exact names, or under one of the suffixes
    /// (`MatchDomain`).
    pub fn match_domain(&self, name: &str) -> bool {
        let name = normalize(name);
        if name.is_empty() {
            return false;
        }
        if self.full.contains(&name) {
            return true;
        }
        let mut rest = name.as_str();
        loop {
            if self.suffix.contains(rest) {
                return true;
            }
            match rest.find('.') {
                Some(dot) => rest = &rest[dot + 1..],
                None => return false,
            }
        }
    }

    /// In one of the prefixes; an IPv4-mapped address as its IPv4
    /// (`MatchIP`).
    pub fn match_ip(&self, ip: IpAddr) -> bool {
        let (family, v) = key(ip);
        let idx = self
            .ranges
            .partition_point(|r| (r.family, r.lo) <= (family, v));
        idx > 0 && {
            let r = self.ranges[idx - 1];
            r.family == family && r.hi >= v
        }
    }

    /// A literal by prefix, anything else by name (`MatchHost`).
    pub fn match_host(&self, host: &str) -> bool {
        let bare = host.strip_prefix('[').unwrap_or(host);
        let bare = bare.strip_suffix(']').unwrap_or(bare);
        match parse_addr(bare) {
            Some(ip) => self.match_ip(ip),
            None => self.match_domain(host),
        }
    }

    /// The one line a log prints about the rules (`Summary`).
    pub fn summary(&self) -> String {
        format!("{} names, {} prefixes", self.names, self.prefixes)
    }
}

/// Where a CONNECT goes, decided from its target alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Through the tunnel.
    Tunnel,
    /// Dialed here; the rule that matched.
    Direct(&'static str),
    /// Reply first and read a name off the first bytes.
    Sniff,
}

/// `classifyConnect`.
pub fn classify(rules: Option<&Rules>, host: &str) -> Route {
    let Some(rules) = rules else {
        return Route::Tunnel;
    };
    if let Some(ip) = parse_addr(host) {
        return if rules.match_ip(ip) {
            Route::Direct("prefix")
        } else {
            Route::Sniff
        };
    }
    if rules.match_domain(host) {
        Route::Direct("name")
    } else {
        Route::Tunnel
    }
}

/// The server name in `head` (`sniff.Host`), and whether more bytes could
/// still change the answer.
pub fn sniff_host(head: &[u8]) -> (String, bool) {
    if head.is_empty() {
        return (String::new(), true);
    }
    if head[0] == TLS_HANDSHAKE {
        return tls_server_name(head);
    }
    let (partial, complete) = http_method(head);
    if complete || partial {
        return http_host(head, complete);
    }
    (String::new(), false)
}

fn tls_server_name(head: &[u8]) -> (String, bool) {
    if head.len() < TLS_RECORD_HEADER {
        return (String::new(), true);
    }
    if head[1] != TLS_VERSION_MAJOR {
        return (String::new(), false);
    }
    let record = usize::from(head[3]) << 8 | usize::from(head[4]);
    if record == 0 || record > TLS_MAX_RECORD {
        return (String::new(), false);
    }
    if head.len() < TLS_RECORD_HEADER + record {
        return (String::new(), true);
    }
    let body = &head[TLS_RECORD_HEADER..TLS_RECORD_HEADER + record];
    if body.len() < 4 || body[0] != TLS_CLIENT_HELLO {
        return (String::new(), false);
    }
    let hello = usize::from(body[1]) << 16 | usize::from(body[2]) << 8 | usize::from(body[3]);
    if hello > body.len() - 4 {
        return (String::new(), false);
    }
    (client_hello_server_name(&body[4..4 + hello]), false)
}

/// Go's `cursor`: big-endian reads that remember the first short one.
struct Cursor<'a> {
    b: &'a [u8],
    off: usize,
    bad: bool,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self {
            b,
            off: 0,
            bad: false,
        }
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        if self.bad || self.off + n > self.b.len() {
            self.bad = true;
            return &[];
        }
        let v = &self.b[self.off..self.off + n];
        self.off += n;
        v
    }
    fn u8(&mut self) -> usize {
        self.take(1).first().map_or(0, |&v| usize::from(v))
    }
    fn u16(&mut self) -> usize {
        match self.take(2) {
            [a, b] => usize::from(*a) << 8 | usize::from(*b),
            _ => 0,
        }
    }
    fn done(&self) -> bool {
        self.bad || self.off >= self.b.len()
    }
}

fn client_hello_server_name(hello: &[u8]) -> String {
    let mut c = Cursor::new(hello);
    c.take(2 + TLS_RANDOM_LEN);
    let n = c.u8();
    c.take(n);
    let n = c.u16();
    c.take(n);
    let n = c.u8();
    c.take(n);
    let n = c.u16();
    let mut exts = Cursor::new(c.take(n));
    while !exts.done() {
        let typ = exts.u16();
        let n = exts.u16();
        let data = exts.take(n);
        if exts.bad {
            return String::new();
        }
        if typ == EXT_SERVER_NAME {
            return server_name_list(data);
        }
    }
    String::new()
}

fn server_name_list(data: &[u8]) -> String {
    let mut list = Cursor::new(data);
    let n = list.u16();
    let mut names = Cursor::new(list.take(n));
    while !names.done() {
        let typ = names.u8();
        let n = names.u16();
        let name = names.take(n);
        if names.bad {
            return String::new();
        }
        if typ == SNI_HOST_NAME && !name.is_empty() {
            return String::from_utf8_lossy(name).to_lowercase();
        }
    }
    String::new()
}

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

fn http_method(head: &[u8]) -> (bool, bool) {
    let mut partial = false;
    for m in HTTP_METHODS {
        if head.starts_with(m) {
            return (false, true);
        }
        if head.len() < m.len() && m.starts_with(head) {
            partial = true;
        }
    }
    (partial, false)
}

fn http_host(head: &[u8], complete: bool) -> (String, bool) {
    if !complete {
        return (String::new(), true);
    }
    let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
        return (String::new(), head.len() < MAX_HEAD);
    };
    // Lines end at CRLF alone, as Go's `bytes.SplitSeq(headers, "\r\n")`.
    let lines = crlf_lines(&head[..end]);
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&line[..colon]);
        if !is_host_header(name.trim()) {
            continue;
        }
        let value = String::from_utf8_lossy(&line[colon + 1..]);
        return (host_without_port(value.trim()), false);
    }
    (String::new(), false)
}

fn crlf_lines(mut rest: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (line, next) = match rest.windows(2).position(|w| w == b"\r\n") {
            Some(i) => (&rest[..i], &rest[i + 2..]),
            None => (rest, &rest[rest.len()..]),
        };
        rest = next;
        Some(line)
    })
}

/// `bytes.EqualFold(name, "Host")`: Go's simple folding, under which the
/// long s (U+017F) is an s.
fn is_host_header(name: &str) -> bool {
    let mut chars = name.chars();
    let folds = |c: Option<char>, lower: char| {
        c.is_some_and(|c| c.to_ascii_lowercase() == lower || (lower == 's' && c == '\u{17f}'))
    };
    folds(chars.next(), 'h')
        && folds(chars.next(), 'o')
        && folds(chars.next(), 's')
        && folds(chars.next(), 't')
        && chars.next().is_none()
}

fn host_without_port(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) if end > 0 => rest[..end].to_lowercase(),
            _ => String::new(),
        };
    }
    let host = if host.matches(':').count() == 1 {
        &host[..host.find(':').unwrap_or(host.len())]
    } else {
        host
    };
    host.to_lowercase()
}

/// `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl Inner {
    /// `dialDirect`: serves a CONNECT from this process; `fallback`, when
    /// set, is the address the SOCKS client gave for a target sniffed as a
    /// name, dialed when the name does not resolve here.
    pub(crate) async fn dial_direct(
        &self,
        mut conn: TcpStream,
        job: Job,
        reason: &str,
        fallback: Option<Vec<u8>>,
    ) {
        let name = host_text(&job.host).into_owned();
        crate::info!("direct to {name}:{} ({reason})", job.port);
        let mut remote = crate::net::dial_tcp_host(&join_host_port(&name, job.port)).await;
        if let (Err(e), Some(fb)) = (&remote, &fallback) {
            let fb = host_text(fb);
            crate::debug!("direct to {name}: {e}; dialing {fb} instead");
            remote = crate::net::dial_tcp_host(&join_host_port(&fb, job.port)).await;
        }
        let mut remote = match remote {
            Ok(r) => r,
            Err(e) => {
                crate::info!("direct to {name}:{} failed: {e}", job.port);
                job.fail(&mut conn, rep::HOST_UNREACHABLE).await;
                return;
            }
        };
        if !job.open(&mut conn, &mut remote).await {
            return;
        }
        let port = job.port;
        drop(job);
        let (_, end) = copy_bidirectional(conn, remote, false, HALF_OPEN_GRACE, &self.run).await;
        if matches!(end, CopyEnd::HalfOpenIdle) {
            crate::debug!("direct to {name}:{port} closed: half-open and silent for 1m0s");
        }
    }

    /// `sniffThenRoute`: answers the CONNECT, reads what the client sends
    /// first while the tunnel is made ready, and routes by the name in it
    /// when the rules cover that name.
    pub(crate) async fn sniff_then_route(self: &Arc<Self>, mut conn: TcpStream, mut job: Job) {
        use tokio::io::AsyncWriteExt;
        if conn
            .write_all(&crate::tunnel::reply(rep::SUCCESS, &job.host))
            .await
            .is_err()
        {
            return;
        }
        job.replied = true;
        let prep = {
            let me = self.clone();
            let (host, port) = (job.host.clone(), job.port);
            tokio::spawn(async move { me.prepare_tunnel(&host, port).await })
        };
        let (host, head) = sniff_head(&mut conn).await;
        job.head = head;
        if !host.is_empty() && self.rules.as_ref().is_some_and(|r| r.match_domain(&host)) {
            // The direct path won: whatever the tunnel has by now is closed.
            prep.abort();
            let given = std::mem::replace(&mut job.host, host.into_bytes());
            // Boxed: a sniffed connection mostly goes through the tunnel,
            // and its task holds the direct path's state only when taken.
            Box::pin(self.dial_direct(conn, job, "sniffed name", Some(given))).await;
            return;
        }
        if !host.is_empty() {
            crate::debug!(
                "sniffed {host} for {}:{}: not a direct name",
                host_text(&job.host),
                job.port
            );
        }
        match prep.await {
            Ok(Ok(stream)) => self.pump_tunnel(conn, stream, job).await,
            Ok(Err(code)) => job.fail(&mut conn, code).await,
            Err(_) => {}
        }
    }
}

/// `sniffHead`: the client's first bytes for up to [`SNIFF_TIMEOUT`], or
/// until the sniffer has an answer; the name found and what was read.
async fn sniff_head(conn: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = vec![0u8; MAX_HEAD];
    let mut filled = 0;
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut host;
    loop {
        let r = tokio::time::timeout_at(deadline, conn.read(&mut buf[filled..])).await;
        let (n, stop) = match r {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => (0, true),
            Ok(Ok(n)) => (n, false),
        };
        filled += n;
        let need;
        (host, need) = sniff_host(&buf[..filled]);
        if stop || !need || filled == buf.len() {
            break;
        }
    }
    buf.truncate(filled);
    buf.shrink_to_fit();
    (host, buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(lines: &[&str]) -> Rules {
        Rules::parse(lines).unwrap().unwrap()
    }

    #[test]
    fn the_host_header_is_found_as_go_finds_it() {
        let host = |h: &[u8]| http_host(h, true).0;
        assert_eq!(
            host(b"GET / HTTP/1.1\r\nHost: A.example:80\r\n\r\n"),
            "a.example"
        );
        assert_eq!(
            host(b"GET / HTTP/1.1\r\nX: a\nHost: b.example\r\n\r\n"),
            "",
            "a bare LF ends no line"
        );
        assert_eq!(
            host("GET / HTTP/1.1\r\nHo\u{17f}t: c.example\r\n\r\n".as_bytes()),
            "c.example",
            "EqualFold folds the long s"
        );
        assert_eq!(host(b"GET / HTTP/1.1\r\nHosts: d.example\r\n\r\n"), "");
    }

    #[test]
    fn names_and_prefixes_match_as_gos() {
        let r = rules(&[
            "domain:Example.RU.",
            "full:only.test",
            "10.0.0.0/8",
            "192.168.1.1",
            "2001:db8::/32",
            "# c",
            "",
        ]);
        assert_eq!(r.summary(), "2 names, 3 prefixes");
        assert!(r.match_domain("example.ru") && r.match_domain("a.b.EXAMPLE.ru."));
        assert!(!r.match_domain("notexample.ru"));
        assert!(r.match_domain("only.test") && !r.match_domain("a.only.test"));
        assert!(r.match_ip("10.255.0.1".parse().unwrap()));
        assert!(
            r.match_ip("::ffff:10.1.2.3".parse().unwrap()),
            "mapped is matched as IPv4"
        );
        assert!(
            r.match_ip("192.168.1.1".parse().unwrap())
                && !r.match_ip("192.168.1.2".parse().unwrap())
        );
        assert!(
            r.match_ip("2001:db8:ffff::1".parse().unwrap())
                && !r.match_ip("2001:db9::".parse().unwrap())
        );
        assert!(r.match_host("[2001:db8::1]") && r.match_host("x.example.ru"));
        assert_eq!(classify(Some(&r), "10.1.1.1"), Route::Direct("prefix"));
        assert_eq!(classify(Some(&r), "8.8.8.8"), Route::Sniff);
        assert_eq!(classify(Some(&r), "ya.example.ru"), Route::Direct("name"));
        assert_eq!(classify(Some(&r), "google.com"), Route::Tunnel);
        assert_eq!(classify(None, "10.1.1.1"), Route::Tunnel);
    }

    #[test]
    fn ranges_merge_and_bad_lines_name_their_number() {
        let r = rules(&["10.0.0.0/24", "10.0.1.0/24", "10.0.0.5"]);
        assert_eq!(r.ranges.len(), 1, "adjacent and overlapping ranges fold");
        assert!(r.match_ip("10.0.1.255".parse().unwrap()));
        assert!(Rules::parse(&["# only a comment"]).unwrap().is_none());
        let err = Rules::parse(&["domain:a", "nonsense here"]).unwrap_err();
        assert_eq!(
            err,
            "route: bad rule: line 2: \"nonsense here\": not a name rule, an address or a prefix"
        );
        assert!(Rules::parse(&["domain:"])
            .unwrap_err()
            .ends_with("empty name"));
    }

    #[test]
    fn a_client_hello_and_an_http_request_name_their_host() {
        // A ClientHello with server_name "Sni.Example".
        let name = b"Sni.Example";
        let mut sni = vec![0u8];
        sni.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = (u16::try_from(sni.len()).unwrap()).to_be_bytes().to_vec();
        ext.extend_from_slice(&sni);
        let mut exts = vec![0, 0];
        exts.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&ext);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        hello.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        hello.extend_from_slice(&exts);
        let mut body = vec![1, 0];
        body.extend_from_slice(&u16::try_from(hello.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&hello);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        rec.extend_from_slice(&body);
        assert_eq!(sniff_host(&rec), ("sni.example".to_owned(), false));
        assert_eq!(
            sniff_host(&rec[..10]),
            (String::new(), true),
            "a partial record asks for more"
        );
        assert_eq!(
            sniff_host(b"GET / HTTP/1.1\r\nHost: Web.Example:8080\r\n\r\n"),
            ("web.example".to_owned(), false)
        );
        assert_eq!(sniff_host(b"GE"), (String::new(), true));
        assert_eq!(sniff_host(b"GET / HTTP/1.1\r\nHo"), (String::new(), true));
        assert_eq!(sniff_host(b"SSH-2.0-x\r\n"), (String::new(), false));
        assert_eq!(host_without_port("[::1]:80"), "::1");
        assert_eq!(join_host_port("::1", 80), "[::1]:80");
    }
}

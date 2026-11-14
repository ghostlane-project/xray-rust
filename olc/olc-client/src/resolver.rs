// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The resolver ring (`protect.Resolver`, resolver.go): the names the engine
//! itself dials (a direct rule's target, a carrier's host) are looked up on
//! the configured DNS servers, over protected sockets, the next server after
//! a failure; after [`RING_DARK_AFTER`] failures in a row the ring is dark
//! for [`RING_DARK_WINDOW`] and the system resolver answers instead. With no
//! ring set, the system resolver answers everything.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::net;

/// Failures in a row after which the ring is dark (`ringDarkAfter`).
pub const RING_DARK_AFTER: u32 = 3;
/// How long a dark ring stays dark (`ringDarkWindow`).
pub const RING_DARK_WINDOW: Duration = Duration::from_secs(30);
/// One query's wait (`dnsQueryTimeout`).
pub const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// The largest answer read (`exchangeBufferSize`).
pub const ANSWER_BUFFER: usize = 4096;

struct Ring {
    servers: Vec<SocketAddr>,
    next: usize,
    failures: u32,
    dark_until: Option<Instant>,
}

static RING: Mutex<Option<Ring>> = Mutex::new(None);

/// Sets the ring from `servers`, comma- or space-separated `ip[:port]`
/// (`SetServers`); an empty list removes it.
pub fn set_servers(servers: &str) {
    let list: Vec<SocketAddr> = servers
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .filter_map(parse_server)
        .collect();
    *RING.lock().unwrap_or_else(PoisonError::into_inner) = (!list.is_empty()).then_some(Ring {
        servers: list,
        next: 0,
        failures: 0,
        dark_until: None,
    });
}

fn parse_server(s: &str) -> Option<SocketAddr> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    s.parse().ok()
}

/// The server to ask next, or `None` when there is no ring or it is dark.
fn pick() -> Option<SocketAddr> {
    let mut g = RING.lock().unwrap_or_else(PoisonError::into_inner);
    let ring = g.as_mut()?;
    if ring.dark_until.is_some_and(|t| Instant::now() < t) {
        return None;
    }
    Some(ring.servers[ring.next % ring.servers.len()])
}

fn note(ok: bool) {
    let mut g = RING.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(ring) = g.as_mut() else { return };
    if ok {
        ring.failures = 0;
        ring.dark_until = None;
        return;
    }
    ring.next = (ring.next + 1) % ring.servers.len();
    ring.failures += 1;
    if ring.failures >= RING_DARK_AFTER {
        ring.failures = 0;
        ring.dark_until = Some(Instant::now() + RING_DARK_WINDOW);
    }
}

/// The addresses of `host`: a literal is itself; a name is asked of the
/// ring (IPv4 first), else of the system.
///
/// # Errors
/// No address from either.
pub async fn lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    for _ in 0..2 {
        let Some(server) = pick() else { break };
        match query_both(server, host).await {
            Ok(ips) if !ips.is_empty() => {
                note(true);
                return Ok(ips);
            }
            _ => note(false),
        }
    }
    let addrs = tokio::net::lookup_host((host, 0)).await?;
    let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("lookup {host}: no such host"),
        ));
    }
    Ok(ips)
}

/// Whether a ring is set (`HasServers`).
pub fn has_servers() -> bool {
    RING.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

/// Sends `query` as it is to the ring's preferred server over a protected
/// socket and returns the answer as the server sent it (`Exchange`).
/// Silence moves the ring on; the query is not retried here, since the
/// resolver that sent it will.
///
/// # Errors
/// No ring, the socket's error, or [`QUERY_TIMEOUT`] of silence.
pub async fn exchange(query: &[u8]) -> io::Result<Vec<u8>> {
    let server = pick().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "protect: no dns server reachable")
    })?;
    let sock = net::udp_socket(server.ip()).await?;
    sock.connect(server).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; ANSWER_BUFFER];
    match tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            note(true);
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(e)) => {
            note(false);
            Err(e)
        }
        Err(_) => {
            note(false);
            Err(io::Error::new(io::ErrorKind::TimedOut, "read answer: i/o timeout"))
        }
    }
}

async fn query_both(server: SocketAddr, host: &str) -> io::Result<Vec<IpAddr>> {
    let mut out = query(server, host, TYPE_A).await.unwrap_or_default();
    out.extend(query(server, host, TYPE_AAAA).await.unwrap_or_default());
    Ok(out)
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

async fn query(server: SocketAddr, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let id: u16 = rand::random();
    let q = build_query(id, host, qtype)?;
    let sock = net::udp_socket(server.ip()).await?;
    sock.connect(server).await?;
    sock.send(&q).await?;
    let mut buf = vec![0u8; ANSWER_BUFFER];
    let n = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns query: i/o timeout"))??;
    parse_answer(&buf[..n], id, qtype)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "dns: malformed answer"))
}

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

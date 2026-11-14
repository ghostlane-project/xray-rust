// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! DNS over the stream, and direct DNS (dns.go).
//!
//! Behind a tun2socks every resolver query arrives as a SOCKS UDP datagram
//! to port 53. The datagram lane is lossy, and a lost query is a resolver
//! retry seconds later, so a port-53 datagram is answered over a smux
//! stream instead: the CONNECT the TCP path sends, to the resolver's port
//! 53, then one RFC 7766 query and response (a two-byte length first). A
//! query for a name the direct rules cover goes, as it is, to the resolver
//! ring over a protected socket instead.
//!
//! Bounded: at most [`MAX_IN_FLIGHT`] queries, each ending within
//! [`QUERY_DEADLINE`]; past the cap a query takes the lane.

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use olc_smux::{Session, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::client::Inner;
use crate::socks::host_text;
use crate::tunnel::send_connect;
use crate::udp::{Addr, Datagram, Reply};

/// The resolver port.
pub const DNS_PORT: u16 = 53;
/// The largest message RFC 7766 frames (`dnsMaxMessageSize`).
pub const MAX_MESSAGE: usize = 65535;
/// One query end to end (`dnsQueryDeadline`).
pub const QUERY_DEADLINE: Duration = Duration::from_secs(5);
/// Queries at once (`dnsMaxInFlight`).
pub const MAX_IN_FLIGHT: usize = 64;

/// Why a stream exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The stream failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// `errDNSResponseEmpty`.
    #[error("empty dns response")]
    Empty,
}

/// `exchangeTCPDNS`: one framed query, one framed response.
///
/// # Errors
/// [`ExchangeError`].
pub async fn exchange_tcp<S>(stream: &mut S, query: &[u8]) -> Result<Vec<u8>, ExchangeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let len = u16::try_from(query.len()).map_err(|_| std::io::Error::other("query too large"))?;
    let mut msg = Vec::with_capacity(2 + query.len());
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(query);
    stream.write_all(&msg).await?;
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    let n = usize::from(u16::from_be_bytes(hdr));
    if n == 0 {
        return Err(ExchangeError::Empty);
    }
    let mut response = vec![0u8; n];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// The name in a query's first question, without the trailing dot
/// (`dnsQuestionName`); `None` for a response or a message that does not
/// parse. As strict as `dnsmessage` (x/net v0.55.0, `Name.unpack` and
/// `Parser.Question`): no dot inside a label, at most 10 pointers, a name
/// under 254 bytes with its dots, and the type and class after it.
pub fn question_name(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 || msg[2] & 0x80 != 0 || u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    // A dot after every label, as dnsmessage holds it.
    let mut name: Vec<u8> = Vec::new();
    let mut at = 12;
    let mut after = None;
    let mut pointers = 0;
    loop {
        let c = *msg.get(at)?;
        at += 1;
        match c & 0xc0 {
            0x00 if c == 0 => break,
            0x00 => {
                let label = msg.get(at..at + usize::from(c))?;
                if label.contains(&b'.') || name.len() + label.len() >= 254 {
                    return None;
                }
                name.extend_from_slice(label);
                name.push(b'.');
                at += usize::from(c);
            }
            0xc0 => {
                let low = *msg.get(at)?;
                at += 1;
                after.get_or_insert(at);
                pointers += 1;
                if pointers > 10 {
                    return None;
                }
                at = usize::from(c & 0x3f) << 8 | usize::from(low);
            }
            _ => return None,
        }
    }
    let after = after.unwrap_or(at);
    msg.get(after..after + 4)?;
    name.pop();
    Some(String::from_utf8_lossy(&name).into_owned())
}

/// Truncates a response a `FWD_UDP` client cannot read whole to its header
/// and question with TC set, so the resolver asks again over TCP; `None`
/// when even that does not fit.
pub fn truncate_response(resp: &[u8], cap: usize) -> Option<Vec<u8>> {
    if resp.len() <= cap {
        return Some(resp.to_vec());
    }
    if resp.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    let mut at = 12;
    for _ in 0..qd {
        loop {
            let len = *resp.get(at)?;
            if len & 0xc0 == 0xc0 {
                at += 2;
                break;
            }
            at += 1 + usize::from(len);
            if len == 0 {
                break;
            }
        }
        at += 4;
    }
    if at > resp.len() || at > cap {
        return None;
    }
    let mut out = resp[..at].to_vec();
    out[2] |= 0x02;
    out[6..12].fill(0);
    Some(out)
}

/// Gives a slot back when the query ends.
struct Slot(Arc<Inner>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.dns_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Inner {
    fn take_dns_slot(self: &Arc<Self>) -> Option<Slot> {
        if self.dns_in_flight.fetch_add(1, Ordering::Relaxed) >= MAX_IN_FLIGHT {
            self.dns_in_flight.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Slot(self.clone()))
    }

    /// `tryDNSOverStream`: false sends the query on to the lane.
    pub(crate) fn try_dns_over_stream(
        self: &Arc<Self>,
        reply: &Reply,
        dg: &Datagram<'_>,
        assoc: &CancellationToken,
    ) -> bool {
        if dg.port != DNS_PORT || dg.payload.is_empty() || dg.payload.len() > MAX_MESSAGE {
            return false;
        }
        let Some((session, sid)) = self.session() else {
            return false;
        };
        let Some(slot) = self.take_dns_slot() else {
            return false;
        };
        self.announce_dns_over_stream(&sid, &host_text(&dg.host));
        let query = dg.payload.to_vec();
        let host = dg.host.clone();
        let reply = reply.clone();
        let assoc = assoc.clone();
        tokio::spawn(async move {
            let _slot = slot;
            tokio::select! {
                () = assoc.cancelled() => {}
                _ = tokio::time::timeout(QUERY_DEADLINE, query_over_stream(&session, &host, &query, &reply)) => {}
            }
        });
        true
    }

    /// `announceDNSOverStream`: once per session.
    fn announce_dns_over_stream(&self, sid: &str, resolver: &str) {
        let mut last = self
            .dns_announced
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *last != sid {
            sid.clone_into(&mut last);
            drop(last);
            crate::info!("dns over the stream: session={sid} resolver={resolver}:{DNS_PORT}");
        }
    }

    /// `tryDNSDirect`: a query for a direct name to the resolver ring.
    pub(crate) fn try_dns_direct(
        self: &Arc<Self>,
        reply: &Reply,
        dg: &Datagram<'_>,
        assoc: &CancellationToken,
    ) -> bool {
        let Some(rules) = &self.rules else {
            return false;
        };
        if dg.port != DNS_PORT || !crate::resolver::has_servers() {
            return false;
        }
        let Some(name) = question_name(dg.payload) else {
            return false;
        };
        if !rules.match_domain(&name) {
            return false;
        }
        let Some(slot) = self.take_dns_slot() else {
            return false;
        };
        if !self.dns_direct_announced.swap(true, Ordering::Relaxed) {
            crate::info!("dns direct: queries for direct names go to the resolver ring");
        }
        let query = dg.payload.to_vec();
        let from = Addr::parse(&dg.host);
        let reply = reply.clone();
        let assoc = assoc.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let answer = tokio::select! {
                () = assoc.cancelled() => return,
                r = tokio::time::timeout(QUERY_DEADLINE, crate::resolver::exchange(&query)) => r,
            };
            match answer {
                Ok(Ok(resp)) => deliver_dns(&reply, &from, &resp),
                Ok(Err(e)) => crate::debug!("dns direct: {e}"),
                Err(_) => crate::debug!("dns direct: context deadline exceeded"),
            }
        });
        true
    }
}

/// `dnsQueryOverStream`: every failure is a silent drop; the resolver
/// retries.
async fn query_over_stream(session: &Session, host: &[u8], query: &[u8], reply: &Reply) {
    let mut stream: Stream = match session.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            crate::debug!("dns over the stream: open failed: {e}");
            return;
        }
    };
    if let Err(e) = send_connect(&mut stream, host, DNS_PORT).await {
        crate::debug!("dns over the stream: {e}");
        return;
    }
    match exchange_tcp(&mut stream, query).await {
        Ok(resp) => deliver_dns(reply, &Addr::parse(host), &resp),
        Err(e) => crate::debug!("dns over the stream: sid={} {e}", stream.id()),
    }
}

/// An answer back as if it came down the lane; cut to what a `FWD_UDP`
/// client reads.
fn deliver_dns(reply: &Reply, from: &Addr, resp: &[u8]) {
    match reply {
        Reply::Assoc { .. } => reply.deliver(from, DNS_PORT, resp),
        Reply::Fwd { to, .. } => {
            let named = if matches!(from, Addr::Domain(_)) {
                to
            } else {
                from
            };
            if let Some(cut) = truncate_response(resp, crate::udp::fwd_max_reply(named)) {
                reply.deliver(from, DNS_PORT, &cut);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        crate::resolver::build_query(7, name, 1).unwrap()
    }

    #[test]
    fn a_question_names_its_name() {
        assert_eq!(
            question_name(&query("Ya.Example.RU")).as_deref(),
            Some("Ya.Example.RU")
        );
        let mut resp = query("a.b");
        resp[2] |= 0x80;
        assert_eq!(question_name(&resp), None, "a response is not a query");
        assert_eq!(question_name(&[0; 5]), None);
    }

    #[test]
    fn a_question_parses_only_as_dnsmessage_parses_it() {
        let head = |rest: &[u8]| {
            let mut m = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            m.extend_from_slice(rest);
            m
        };
        assert_eq!(
            question_name(&head(b"\x03a.b\x00\x00\x01\x00\x01")),
            None,
            "a dot in a label"
        );
        let mut cut = query("a.b");
        cut.pop();
        assert_eq!(question_name(&cut), None, "no class after the name");
        assert_eq!(
            question_name(&head(b"\x00\x00\x01\x00\x01")).as_deref(),
            Some("")
        );
        // Labels of 63, 63, 63 and 61 make 253 bytes: the last that parses.
        let long = |last: usize| {
            let l = |c: char, n: usize| c.to_string().repeat(n);
            format!(
                "{}.{}.{}.{}",
                l('a', 63),
                l('b', 63),
                l('c', 63),
                l('d', last)
            )
        };
        assert_eq!(question_name(&query(&long(61))).map(|n| n.len()), Some(253));
        assert_eq!(question_name(&query(&long(62))), None);
        // A chain of pointers ending at "a": ten are followed, not eleven.
        let chain = |n: usize| {
            let mut rest = Vec::new();
            for k in 0..n {
                let to = u8::try_from(12 + 2 * (k + 1)).unwrap();
                rest.extend_from_slice(&[0xc0, to]);
            }
            rest.extend_from_slice(b"\x01a\x00\x00\x01\x00\x01");
            head(&rest)
        };
        assert_eq!(question_name(&chain(10)).as_deref(), Some("a"));
        assert_eq!(question_name(&chain(11)), None);
        assert_eq!(
            question_name(&head(b"\x40a\x00\x00\x01\x00\x01")),
            None,
            "a reserved prefix"
        );
    }

    #[test]
    fn a_large_answer_is_cut_to_its_question_with_tc() {
        let q = query("many.example");
        let mut resp = q.clone();
        resp[2] |= 0x80;
        resp[7] = 100;
        resp.extend(std::iter::repeat_n(0u8, 1600));
        let cut = truncate_response(&resp, 1493).unwrap();
        assert_eq!(cut.len(), q.len());
        assert_eq!(cut[2] & 0x02, 0x02);
        assert_eq!(&cut[6..12], &[0; 6]);
        assert_eq!(
            truncate_response(&q, 1493).unwrap(),
            q,
            "a small one is untouched"
        );
    }

    #[tokio::test]
    async fn a_tcp_exchange_is_length_prefixed() {
        crate::testing::bounded(async {
            let (mut a, mut b) = tokio::io::duplex(256);
            let srv = tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                b.read_exact(&mut hdr).await.unwrap();
                let mut q = vec![0u8; usize::from(u16::from_be_bytes(hdr))];
                b.read_exact(&mut q).await.unwrap();
                b.write_all(&[0, 3, b'a', b'n', b's']).await.unwrap();
                let mut second = [0u8; 3];
                b.read_exact(&mut second).await.unwrap();
                b.write_all(&[0, 0]).await.unwrap();
                q
            });
            assert_eq!(exchange_tcp(&mut a, b"qq").await.unwrap(), b"ans");
            // The second query goes out before the server task is awaited:
            // the server answers it only once it has read it.
            assert!(matches!(
                exchange_tcp(&mut a, b"q").await,
                Err(ExchangeError::Empty)
            ));
            assert_eq!(srv.await.unwrap(), b"qq");
        })
        .await;
    }
}

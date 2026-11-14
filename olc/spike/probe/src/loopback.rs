//! Two str0m `Rtc`s joined in-process, no sockets: ICE, the DTLS handshake (with whatever
//! provider is given), SCTP, and an echo over a data channel. Runs anywhere, the iOS
//! simulator included, because nothing leaves the process.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::config::{CryptoProvider, DtlsVersion};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

use crate::peer::rtc_config;
use crate::util::chrome_ice_creds;
use crate::wire::Taps;

/// What one loopback run did.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub connected_ms: u128,
    pub open_ms: u128,
    pub echo_ms: u128,
    pub bytes: usize,
    pub messages: usize,
    pub offerer_hello: Vec<Vec<u8>>,
}

struct Side {
    rtc: Rtc,
    addr: SocketAddr,
    timeout: Instant,
    taps: Taps,
    /// What this side transmitted and the other has not read yet: one datagram is handed
    /// over at a time and the reader polled after it, as a socket would (a DTLS stack's
    /// receive queue is bounded: dimpl refuses a flight pushed in unpolled).
    outq: VecDeque<(SocketAddr, SocketAddr, Vec<u8>)>,
}

/// Runs offerer and answerer to an echo of `bytes` bytes in messages of `chunk`, or fails
/// after `limit`.
pub fn run(provider: &Arc<CryptoProvider>, version: DtlsVersion, bytes: usize, chunk: usize, limit: Duration) -> Result<Report, String> {
    let start = Instant::now();
    let mut a = Side {
        rtc: rtc_config(provider, version, &chrome_ice_creds()).build(start),
        addr: "192.0.2.10:5000".parse().map_err(|_| "addr")?,
        timeout: start,
        taps: Taps::default(),
        outq: VecDeque::new(),
    };
    let mut b = Side {
        rtc: rtc_config(provider, version, &chrome_ice_creds()).build(start),
        addr: "192.0.2.20:6000".parse().map_err(|_| "addr")?,
        timeout: start,
        taps: Taps::default(),
        outq: VecDeque::new(),
    };
    a.rtc.add_local_candidate(Candidate::host(a.addr, "udp").map_err(|e| e.to_string())?);
    b.rtc.add_local_candidate(Candidate::host(b.addr, "udp").map_err(|e| e.to_string())?);

    let mut api = a.rtc.sdp_api();
    let cid = api.add_channel_with_config(ChannelConfig {
        label: "_reliable".into(),
        ordered: true,
        reliability: Reliability::Reliable,
        negotiated: None,
        protocol: String::new(),
    });
    let (offer, pending) = api.apply().ok_or("no offer")?;
    let answer = b.rtc.sdp_api().accept_offer(offer).map_err(|e| format!("accept offer: {e}"))?;
    a.rtc.sdp_api().accept_answer(pending, answer).map_err(|e| format!("accept answer: {e}"))?;

    let mut st = State { start: Some(start), cid: Some(cid), ..State::default() };
    loop {
        if start.elapsed() > limit {
            return Err(format!(
                "loopback: no echo after {limit:?} (connected {:?}, open {}, sent {}, echoed {})",
                st.connected, st.a_open, st.sent, st.echoed
            ));
        }
        let mut progressed = poll_side(&mut a, true, &mut st)?;
        progressed |= poll_side(&mut b, false, &mut st)?;
        while !a.outq.is_empty() || !b.outq.is_empty() {
            progressed = true;
            if let Some(d) = a.outq.pop_front() {
                deliver(&mut b, d)?;
                poll_side(&mut b, false, &mut st)?;
            }
            if let Some(d) = b.outq.pop_front() {
                deliver(&mut a, d)?;
                poll_side(&mut a, true, &mut st)?;
            }
        }
        // The offerer writes while its channel takes more and less than a megabyte waits.
        if st.a_open && st.b_open {
            while st.sent < bytes && st.sent - st.echoed < 1 << 20 {
                let n = chunk.min(bytes - st.sent);
                let mut msg = vec![0u8; n];
                msg[..4.min(n)].copy_from_slice(&st.seq.to_be_bytes()[..4.min(n)]);
                let Some(mut ch) = a.rtc.channel(cid) else { break };
                if !ch.write(true, &msg).map_err(|e| format!("write: {e}"))? {
                    break;
                }
                st.seq += 1;
                st.sent += n;
                progressed = true;
            }
        }
        if st.echoed >= bytes && bytes > 0 {
            let mut report = st.report;
            report.echo_ms = start.elapsed().as_millis();
            report.bytes = st.echoed;
            report.offerer_hello = a.taps.hello_tx.clone();
            report.offerer_hello.extend(b.taps.hello_tx.iter().cloned());
            return Ok(report);
        }
        let now = Instant::now();
        for s in [&mut a, &mut b] {
            if now >= s.timeout {
                s.rtc.handle_input(Input::Timeout(now)).map_err(|e| format!("timeout: {e}"))?;
                progressed = true;
            }
        }
        if !progressed {
            let next = a.timeout.min(b.timeout);
            let wait = next.saturating_duration_since(Instant::now()).min(Duration::from_millis(5));
            std::thread::sleep(wait);
        }
    }
}

#[derive(Default)]
struct State {
    start: Option<Instant>,
    cid: Option<ChannelId>,
    report: Report,
    connected: (bool, bool),
    a_open: bool,
    b_open: bool,
    sent: usize,
    echoed: usize,
    seq: u32,
}

/// Hands one datagram to `to`.
fn deliver(to: &mut Side, (src, dst, data): (SocketAddr, SocketAddr, Vec<u8>)) -> Result<(), String> {
    to.taps.received(&data);
    let r = Receive::new(Protocol::Udp, src, dst, &data).map_err(|e| e.to_string())?;
    to.rtc.handle_input(Input::Receive(Instant::now(), r)).map_err(|e| format!("input: {e}"))
}

/// Polls `from` until it waits, queueing what it transmits; true if anything moved.
fn poll_side(from: &mut Side, is_a: bool, st: &mut State) -> Result<bool, String> {
    let start = st.start.unwrap_or_else(Instant::now);
    let mut progressed = false;
    loop {
        match from.rtc.poll_output().map_err(|e| format!("poll: {e}"))? {
            Output::Timeout(t) => {
                from.timeout = t;
                return Ok(progressed);
            }
            Output::Transmit(t) => {
                progressed = true;
                from.taps.sent(&t.contents);
                from.outq.push_back((t.source, t.destination, t.contents.to_vec()));
            }
            Output::Event(e) => {
                progressed = true;
                match e {
                    Event::Connected => {
                        if is_a {
                            st.connected.0 = true;
                        } else {
                            st.connected.1 = true;
                        }
                        if st.connected.0 && st.connected.1 && st.report.connected_ms == 0 {
                            st.report.connected_ms = start.elapsed().as_millis();
                        }
                    }
                    Event::ChannelOpen(id, _) => {
                        if is_a && Some(id) == st.cid {
                            st.a_open = true;
                            st.report.open_ms = start.elapsed().as_millis();
                        } else if !is_a {
                            st.b_open = true;
                        }
                    }
                    Event::ChannelData(d) => {
                        if is_a {
                            st.echoed += d.data.len();
                            st.report.messages += 1;
                        } else if let Some(mut ch) = from.rtc.channel(d.id) {
                            // The echo: the answerer writes back what it read.
                            if !ch.write(true, &d.data).map_err(|e| format!("echo: {e}"))? {
                                return Err("echo: the answerer's channel was full".into());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

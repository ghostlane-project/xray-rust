// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Unit tests on a virtual clock: two sessions joined by a simulated path.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::kcp::{
    itimediff, Segment, IKCP_CMD_ACK, IKCP_CMD_PUSH, IKCP_CMD_WASK, IKCP_CMD_WINS, IKCP_OVERHEAD,
};
use crate::message::{self, Reader, SendError, MAX_MESSAGE};
use crate::pool::BUF_CAP;
use crate::session::{Config, Session};
use crate::{FlushType, Kcp};

/// SplitMix64, seeded.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64 <= p && p > 0.0
    }
}

/// One segment of a packet, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seg {
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    len: usize,
}

fn segments(mut p: &[u8]) -> Vec<Seg> {
    let mut v = Vec::new();
    while p.len() >= IKCP_OVERHEAD {
        let len = u32::from_le_bytes(p[20..24].try_into().unwrap()) as usize;
        v.push(Seg {
            cmd: p[4],
            frg: p[5],
            wnd: u16::from_le_bytes(p[6..8].try_into().unwrap()),
            ts: u32::from_le_bytes(p[8..12].try_into().unwrap()),
            sn: u32::from_le_bytes(p[12..16].try_into().unwrap()),
            una: u32::from_le_bytes(p[16..20].try_into().unwrap()),
            len,
        });
        p = &p[IKCP_OVERHEAD + len..];
    }
    v
}

fn drain(s: &mut Session) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    while let Some(p) = s.peek_output() {
        v.push(p.to_vec());
        s.pop_output();
    }
    v
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 31 + usize::from(seed)) % 251) as u8)
        .collect()
}

/// A path in one direction: loss, a fixed delay, some packets held longer.
struct Path {
    q: VecDeque<(u64, Vec<u8>)>,
    held: Vec<(u64, Vec<u8>)>,
    loss: f64,
    reorder: f64,
    delay: u64,
    hold: u64,
    blackout: Option<(u64, u64)>,
    dropped: u64,
}

impl Path {
    fn new(loss: f64, reorder: f64, delay: u64) -> Self {
        Self {
            q: VecDeque::new(),
            held: Vec::new(),
            loss,
            reorder,
            delay,
            hold: 30,
            blackout: None,
            dropped: 0,
        }
    }
    fn send(&mut self, t: u64, p: Vec<u8>, rng: &mut Rng) {
        if let Some((a, b)) = self.blackout {
            if t >= a && t < b {
                self.dropped += 1;
                return;
            }
        }
        if rng.chance(self.loss) {
            self.dropped += 1;
            return;
        }
        if rng.chance(self.reorder) {
            self.held.push((t + self.delay + self.hold, p));
        } else {
            self.q.push_back((t + self.delay, p));
        }
    }
    fn due(&mut self, t: u64) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while self.q.front().is_some_and(|(at, _)| *at <= t) {
            v.push(self.q.pop_front().unwrap().1);
        }
        let mut i = 0;
        while i < self.held.len() {
            if self.held[i].0 <= t {
                v.push(self.held.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        v
    }
}

/// Moves `data` from a to b, both with `cfg`, on a 1 ms virtual clock;
/// returns (bytes delivered in order, ms taken).
fn transfer(
    cfg: Config,
    data: &[u8],
    ab: Path,
    ba: Path,
    seed: u64,
    limit_ms: u64,
) -> (Vec<u8>, u64, Session, Session) {
    let base = Instant::now();
    let at = |t: u64| base + Duration::from_millis(t);
    let mut a = Session::new(cfg, base);
    let mut b = Session::new(cfg, base);
    let (mut ab, mut ba) = (ab, ba);
    let mut rng = Rng(seed);
    let mut reader = Reader::new();
    let mut got = Vec::new();
    let mut sent = 0;
    let (mut next_a, mut next_b) = (0u64, 0u64);
    let chunk = 8000;
    for t in 0..limit_ms {
        for p in ab.due(t) {
            b.input(&p, at(t));
        }
        for p in ba.due(t) {
            a.input(&p, at(t));
        }
        while sent < data.len() {
            let end = (sent + chunk).min(data.len());
            match message::send(&mut a, &data[sent..end], at(t)) {
                Ok(()) => sent = end,
                Err(SendError::WouldBlock) => break,
                Err(e) => panic!("{e}"),
            }
        }
        if t >= next_a {
            next_a = t + u64::from(a.update(at(t)));
        }
        if t >= next_b {
            next_b = t + u64::from(b.update(at(t)));
        }
        while let Some(m) = reader.next(&mut b).unwrap() {
            got.extend_from_slice(&m);
        }
        for p in drain(&mut a) {
            ab.send(t, p, &mut rng);
        }
        for p in drain(&mut b) {
            ba.send(t, p, &mut rng);
        }
        if got.len() == data.len() {
            return (got, t, a, b);
        }
    }
    (got, limit_ms, a, b)
}

#[test]
fn sizes_stay_small() {
    assert_eq!(std::mem::size_of::<Segment>(), 64);
    assert!(
        std::mem::size_of::<Kcp>() <= 512,
        "Kcp is {} bytes",
        std::mem::size_of::<Kcp>()
    );
    assert!(
        std::mem::size_of::<Session>() <= 768,
        "Session is {} bytes",
        std::mem::size_of::<Session>()
    );
}

#[test]
fn vp8channel_settings_are_kcp_gos_after_its_clamps() {
    let s = Session::new(Config::vp8channel_constrained(), Instant::now());
    let k = s.kcp();
    assert_eq!(k.interval, 10, "kcp-go clamps the engine's 5 ms to 10");
    assert_eq!(k.rx_minrto, 30);
    assert_eq!(k.rx_rto, 200);
    assert_eq!(k.nodelay, 1);
    assert_eq!(k.fastresend, 2);
    assert_eq!(k.nocwnd, 1);
    assert_eq!(k.stream, 1);
    assert_eq!(
        (k.snd_wnd, k.rcv_wnd, k.rmt_wnd),
        (512, 512, 32),
        "rmt_wnd starts at IKCP_WND_RCV"
    );
    assert_eq!((k.mtu, k.mss), (1400, 1376));
    assert_eq!(k.conv, 0xC0FF_EE01);
    let mut big = Config::vp8channel(4096, 4096);
    big.mtu = 9000;
    assert_eq!(
        Session::new(big, Instant::now()).kcp().mtu,
        1500,
        "SetMtu clamps to mtuLimit"
    );
}

#[test]
fn a_write_is_cut_at_mss_and_flushed_at_once() {
    let now = Instant::now();
    let mut s = Session::new(Config::vp8channel_constrained(), now);
    s.write(&[&pattern(3000, 1)], now).unwrap();
    let pkts = drain(&mut s);
    let segs: Vec<Seg> = pkts.iter().flat_map(|p| segments(p)).collect();
    assert_eq!(
        segs.iter().map(|s| s.len).collect::<Vec<_>>(),
        vec![1376, 1376, 248]
    );
    assert!(segs
        .iter()
        .all(|s| s.cmd == IKCP_CMD_PUSH && s.frg == 0 && s.wnd == 512 && s.una == 0));
    assert_eq!(segs.iter().map(|s| s.sn).collect::<Vec<_>>(), vec![0, 1, 2]);
    // 1400-byte segments fill a packet each; the last one has its own.
    assert_eq!(
        pkts.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![1400, 1400, 272]
    );
}

#[test]
fn stream_mode_appends_to_the_last_queued_segment() {
    let now = Instant::now();
    let mut cfg = Config::vp8channel_constrained();
    cfg.snd_wnd = 1; // keep segments in snd_queue
    let mut s = Session::new(cfg, now);
    s.write(&[b"abc"], now).unwrap();
    // One segment is in flight (window 1); a write now waits.
    assert!(s.write(&[b"x"], now).is_err());
    // A second write appended while one is queued: use the state machine.
    let mut k = Kcp::new(1);
    k.set_stream(true);
    k.send(&[1; 1000]);
    k.send(&[2; 1000]);
    let (q, _, _, _) = k.queue_lens();
    assert_eq!(q, 2, "1000 + 1000 at mss 1376 is two segments");
    let mut out = Vec::new();
    k.wnd_size(64, 64);
    k.nodelay(1, 10, 2, 1);
    k.flush(FlushType::Full, 0, &mut |p: &[u8]| out.push(p.to_vec()));
    let segs: Vec<Seg> = out.iter().flat_map(|p| segments(p)).collect();
    assert_eq!(
        segs.iter().map(|s| s.len).collect::<Vec<_>>(),
        vec![1376, 624]
    );
}

#[test]
fn a_push_is_acked_at_once_with_its_ts_and_the_window() {
    let now = Instant::now();
    let mut a = Session::new(Config::vp8channel_constrained(), now);
    let mut b = Session::new(Config::vp8channel_constrained(), now);
    a.write(&[b"hello"], now + Duration::from_millis(7))
        .unwrap();
    let p = drain(&mut a).remove(0);
    let push = &segments(&p)[0];
    assert_eq!(push.ts, 7);
    b.input(&p, now + Duration::from_millis(20));
    let acks = drain(&mut b);
    assert_eq!(acks.len(), 1);
    let ack = &segments(&acks[0])[0];
    assert_eq!(
        (ack.cmd, ack.sn, ack.ts, ack.una, ack.wnd, ack.len),
        (IKCP_CMD_ACK, 0, 7, 1, 511, 0)
    );
    // a takes the ACK: rtt 13 ms; srtt 13, rttvar 6, rto = 13 + max(10, 24) = 37.
    a.input(&acks[0], now + Duration::from_millis(20));
    assert_eq!(a.kcp().srtt(), 13);
    assert_eq!(a.kcp().rto(), 37);
    assert_eq!(a.kcp().queue_lens().1, 0);
}

#[test]
fn acks_for_old_segments_are_filtered_but_the_last_is_kept() {
    // kcp.go:795-803: an ack with sn < rcv_nxt goes out only if it is the
    // last of the list.
    let mut k = Kcp::new(1);
    k.nodelay(1, 10, 2, 1);
    k.wnd_size(32, 32);
    let mut out = Vec::new();
    let push = |sn: u32, ts: u32| {
        let mut p = vec![0u8; IKCP_OVERHEAD + 1];
        p[0..4].copy_from_slice(&1u32.to_le_bytes());
        p[4] = IKCP_CMD_PUSH;
        p[6..8].copy_from_slice(&32u16.to_le_bytes());
        p[8..12].copy_from_slice(&ts.to_le_bytes());
        p[12..16].copy_from_slice(&sn.to_le_bytes());
        p[20..24].copy_from_slice(&1u32.to_le_bytes());
        p
    };
    // sn 0, 0 (a repeat), 1 in one packet: three acks queued.
    let mut pkt = push(0, 100);
    pkt.extend(push(0, 101));
    pkt.extend(push(1, 102));
    k.input(&pkt, true, false, 200, &mut |p: &[u8]| out.push(p.to_vec()));
    assert!(out.is_empty(), "no ack-no-delay: acks wait for a flush");
    k.flush(FlushType::AckOnly, 200, &mut |p: &[u8]| {
        out.push(p.to_vec())
    });
    let segs = segments(&out[0]);
    // rcv_nxt is 2 now: the first two (sn 0 < 2) are dropped, sn 1 < 2 is
    // the last and goes.
    assert_eq!(segs.len(), 1);
    assert_eq!(
        (segs[0].cmd, segs[0].sn, segs[0].ts, segs[0].una),
        (IKCP_CMD_ACK, 1, 102, 2)
    );
}

#[test]
fn rto_backs_off_by_half_the_rto_in_nodelay_mode() {
    let base = Instant::now();
    let mut a = Session::new(Config::vp8channel_constrained(), base);
    a.write(&[b"x"], base).unwrap();
    drain(&mut a);
    // Nothing comes back: retransmits at 200, then +300, +400, +500 (rto
    // grows by rx_rto/2 = 100 each time), on the 10 ms update clock.
    let mut sends = Vec::new();
    let mut next = 0u64;
    for t in 0..2000u64 {
        if t >= next {
            next = t + u64::from(a.update(base + Duration::from_millis(t)));
        }
        if !drain(&mut a).is_empty() {
            sends.push(t);
        }
    }
    assert_eq!(&sends[..4], &[200, 500, 900, 1400]);
}

#[test]
fn a_hole_is_fast_resent_after_two_later_acks() {
    let base = Instant::now();
    let at = |t: u64| base + Duration::from_millis(t);
    let mut a = Session::new(Config::vp8channel_constrained(), base);
    let mut b = Session::new(Config::vp8channel_constrained(), base);
    a.write(&[&pattern(1376 * 4, 3)], at(0)).unwrap();
    let pkts = drain(&mut a);
    assert_eq!(pkts.len(), 4);
    // Lose sn 0; deliver 1, 2, 3 at t=5: b acks each at once.
    for p in &pkts[1..] {
        b.input(p, at(5));
    }
    let acks = drain(&mut b);
    assert_eq!(acks.len(), 3);
    // The first ack (sn 1) counts one skip; the second (sn 2) a second:
    // fastack >= 2 flushes at once and resends sn 0.
    a.input(&acks[0], at(10));
    assert!(drain(&mut a).is_empty());
    a.input(&acks[1], at(10));
    let resent = drain(&mut a);
    assert_eq!(resent.len(), 1);
    let s = &segments(&resent[0])[0];
    assert_eq!((s.cmd, s.sn), (IKCP_CMD_PUSH, 0));
    assert_eq!(a.kcp().counters().fast_retrans_segs, 1);
}

#[test]
fn a_full_receiver_is_probed_after_500_ms_then_by_half_again() {
    let base = Instant::now();
    let at = |t: u64| base + Duration::from_millis(t);
    let mut cfg = Config::vp8channel_constrained();
    cfg.rcv_wnd = 4;
    let mut b = Session::new(cfg, base);
    let mut a = Session::new(Config::vp8channel_constrained(), base);
    // a fills b's window of 4; b never reads.
    a.write(&[&pattern(1376 * 6, 1)], at(0)).unwrap();
    let mut wask = Vec::new();
    let (mut na, mut nb) = (0, 0);
    for t in 0..3000u64 {
        if t >= na {
            na = t + u64::from(a.update(at(t)));
        }
        if t >= nb {
            nb = t + u64::from(b.update(at(t)));
        }
        for p in drain(&mut a) {
            if segments(&p).iter().any(|s| s.cmd == IKCP_CMD_WASK) {
                wask.push(t);
            }
            b.input(&p, at(t));
        }
        for p in drain(&mut b) {
            a.input(&p, at(t));
        }
    }
    assert!(wask.len() >= 3, "probes: {wask:?}");
    let gaps: Vec<u64> = wask.windows(2).map(|w| w[1] - w[0]).collect();
    // 500 to the first probe, then 750, 1125, ... (probe_wait += probe_wait/2),
    // each on the 10 ms clock.
    assert!((750..=760).contains(&gaps[0]), "gaps {gaps:?}");
    assert!((1120..=1135).contains(&gaps[1]), "gaps {gaps:?}");
    // b's answers are WINS segments.
    let mut b2 = Session::new(cfg, base);
    let mut p = vec![0u8; IKCP_OVERHEAD];
    p[0..4].copy_from_slice(&Config::VP8CHANNEL_CONV.to_le_bytes());
    p[4] = IKCP_CMD_WASK;
    b2.input(&p, at(0));
    b2.update(at(1));
    let out = drain(&mut b2);
    assert_eq!(segments(&out[0])[0].cmd, IKCP_CMD_WINS);
}

#[test]
fn a_clean_path_moves_a_mebibyte_in_order() {
    let data = pattern(1 << 20, 9);
    let (got, ms, a, _) = transfer(
        Config::vp8channel_constrained(),
        &data,
        Path::new(0.0, 0.0, 10),
        Path::new(0.0, 0.0, 10),
        1,
        30_000,
    );
    assert_eq!(got.len(), data.len());
    assert!(got == data);
    assert!(ms < 2_000, "took {ms} ms");
    assert_eq!(a.kcp().counters().retrans_segs, 0);
}

#[test]
fn loss_reorder_and_a_blackout_are_survived() {
    let data = pattern(512 * 1024, 2);
    let mut ab = Path::new(0.10, 0.05, 20);
    ab.blackout = Some((300, 700));
    let ba = Path::new(0.10, 0.05, 20);
    let (got, ms, a, b) = transfer(
        Config::vp8channel_constrained(),
        &data,
        ab,
        ba,
        0xC0FFEE,
        60_000,
    );
    assert_eq!(got.len(), data.len(), "after {ms} ms");
    assert!(got == data);
    assert!(a.kcp().counters().retrans_segs > 0);
    assert!(b.kcp().counters().repeat_segs > 0 || a.kcp().counters().retrans_segs > 0);
}

#[test]
fn buffers_stay_within_the_windows() {
    let data = pattern(4 << 20, 4);
    let (got, _, a, b) = transfer(
        Config::vp8channel_constrained(),
        &data,
        Path::new(0.05, 0.05, 25),
        Path::new(0.05, 0.05, 25),
        7,
        120_000,
    );
    assert_eq!(got.len(), data.len());
    // send side: snd_wnd - 1 + one write of 8004 bytes (6 segments).
    let send_bound = 512 - 1 + 6;
    // receive side: rcv_queue <= 512 and rcv_buf < 512.
    let recv_bound = 512 + 511;
    assert!(
        a.stats().peak_buffers <= send_bound,
        "sender peak {} buffers",
        a.stats().peak_buffers
    );
    assert!(
        b.stats().peak_buffers <= recv_bound,
        "receiver peak {} buffers",
        b.stats().peak_buffers
    );
    assert!(a.held_bytes() <= (send_bound + 64) * BUF_CAP + 2048 * 1400 + 1500);
}

#[test]
fn the_output_backlog_drops_what_does_not_fit() {
    let now = Instant::now();
    let mut cfg = Config::vp8channel_constrained();
    cfg.output_backlog = 2;
    let mut s = Session::new(cfg, now);
    s.write(&[&pattern(1376 * 5, 0)], now).unwrap();
    assert_eq!(s.output_len(), 2);
    assert_eq!(s.stats().output_dropped, 3);
    assert_eq!(s.stats().output_peak, 2);
}

#[test]
fn oversized_packets_are_cut_short_and_fec_tags_go_nowhere() {
    let now = Instant::now();
    let mut s = Session::new(Config::vp8channel_constrained(), now);
    s.input(&[0u8; 11], now);
    assert_eq!(s.stats().input_errors, 1);
    let mut big = vec![0u8; 1600];
    big[0..4].copy_from_slice(&Config::VP8CHANNEL_CONV.to_le_bytes());
    big[4] = IKCP_CMD_PUSH;
    big[20..24].copy_from_slice(&1576u32.to_le_bytes());
    s.input(&big, now);
    assert_eq!(s.stats().input_truncated, 1);
    assert_eq!(
        s.stats().input_errors,
        2,
        "its length now runs past the packet: Input returns -2"
    );
    let mut parity = vec![0u8; 40];
    parity[4] = 0xf2;
    s.input(&parity, now);
    assert_eq!(s.stats().fec_ignored, 1);
}

#[test]
fn messages_frame_as_vp8channel_does() {
    let now = Instant::now();
    let mut a = Session::new(Config::vp8channel_constrained(), now);
    let mut b = Session::new(Config::vp8channel_constrained(), now);
    // An empty length is skipped by the reader.
    a.write(&[&0u32.to_be_bytes()], now).unwrap();
    message::send(&mut a, b"first", now).unwrap();
    message::send(&mut a, &pattern(5000, 5), now).unwrap();
    assert_eq!(
        message::send(&mut a, &vec![0; MAX_MESSAGE + 1], now),
        Err(SendError::TooLarge)
    );
    for p in drain(&mut a) {
        b.input(&p, now);
    }
    let mut r = Reader::new();
    assert_eq!(r.next(&mut b).unwrap().as_deref(), Some(&b"first"[..]));
    assert_eq!(r.next(&mut b).unwrap(), Some(pattern(5000, 5)));
    assert_eq!(r.next(&mut b).unwrap(), None);
    // The prefix and the message share segments: "first" is 4 + 5 bytes
    // right after the empty prefix, all in segment 0.
    let mut c = Session::new(Config::vp8channel_constrained(), now);
    message::send(&mut c, b"first", now).unwrap();
    let segs = segments(&drain(&mut c)[0]);
    assert_eq!(segs[0].len, 9);
    // A length over 8 MiB ends the reader.
    let mut d = Session::new(Config::vp8channel_constrained(), now);
    let mut e = Session::new(Config::vp8channel_constrained(), now);
    d.write(&[&(MAX_MESSAGE as u32 + 1).to_be_bytes()], now)
        .unwrap();
    for p in drain(&mut d) {
        e.input(&p, now);
    }
    let mut r = Reader::new();
    assert!(r.next(&mut e).is_err());
    assert!(r.next(&mut e).is_err());
}

#[test]
fn itimediff_wraps_as_go() {
    assert_eq!(itimediff(5, 3), 2);
    assert_eq!(itimediff(3, 5), -2);
    assert_eq!(itimediff(1, u32::MAX), 2);
    assert_eq!(itimediff(u32::MAX, 1), -2);
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A port of kcp-go v5.6.72 kcp.go (https://github.com/xtaci/kcp-go),
// Copyright (c) 2015 xtaci, MIT License. See NOTICE.

//! The KCP state machine: kcp-go v5.6.72 `kcp.go`, function for function.
//!
//! Every function here is the Go function of the same name, in the same order
//! of statements, with kcp-go's constants. Where Go reads the clock
//! (`currentMs()`), the caller passes `current`, milliseconds on its own
//! clock (any origin; only differences matter, modulo 2^32, as in Go).
//!
//! Paths below are `kcp-go/kcp.go` at v5.6.72 unless named.

use std::collections::VecDeque;

use crate::pool::Pool;

/// No-delay mode: minimum RTO (ms) (`kcp.go:35`).
pub const IKCP_RTO_NDL: u32 = 30;
/// Normal mode: minimum RTO (ms).
pub const IKCP_RTO_MIN: u32 = 100;
/// Default RTO (ms).
pub const IKCP_RTO_DEF: u32 = 200;
/// Maximum RTO (ms).
pub const IKCP_RTO_MAX: u32 = 60000;
/// cmd: push data (`kcp.go:41`).
pub const IKCP_CMD_PUSH: u8 = 81;
/// cmd: acknowledge.
pub const IKCP_CMD_ACK: u8 = 82;
/// cmd: window probe request (ask).
pub const IKCP_CMD_WASK: u8 = 83;
/// cmd: window size response (tell).
pub const IKCP_CMD_WINS: u8 = 84;
/// Probe flag: schedule a WASK.
pub const IKCP_ASK_SEND: u32 = 1;
/// Probe flag: schedule a WINS.
pub const IKCP_ASK_TELL: u32 = 2;
/// Default send window (segments) (`kcp.go:51`).
pub const IKCP_WND_SND: u32 = 32;
/// Default receive window (segments). kcp-go's, not ikcp's 128.
pub const IKCP_WND_RCV: u32 = 32;
/// Default MTU (bytes, without the UDP/IP header).
pub const IKCP_MTU_DEF: u32 = 1400;
/// Fast retransmit threshold (unused by the state machine, as in Go).
pub const IKCP_ACK_FAST: u32 = 3;
/// Default flush interval (ms).
pub const IKCP_INTERVAL: u32 = 100;
/// Segment header: conv 4, cmd 1, frg 1, wnd 2, ts 4, sn 4, una 4, len 4.
pub const IKCP_OVERHEAD: usize = 24;
/// Retransmissions before the link is marked dead (`state`).
pub const IKCP_DEADLINK: u32 = 20;
/// Initial slow-start threshold (segments).
pub const IKCP_THRESH_INIT: u32 = 2;
/// Minimum slow-start threshold (segments).
pub const IKCP_THRESH_MIN: u32 = 2;
/// Initial window probe timeout (ms). kcp-go's 500, not ikcp's 7000 (`kcp.go:62`).
pub const IKCP_PROBE_INIT: u32 = 500;
/// Maximum window probe timeout (ms).
pub const IKCP_PROBE_LIMIT: u32 = 120_000;
/// Offset of `sn` in the segment header.
pub const IKCP_SN_OFFSET: usize = 12;

/// `IKCP_FLUSH_ACKONLY` / `IKCP_FLUSH_FULL` (`kcp.go:74-79`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushType {
    /// Phase 1 only: pending ACKs (and the probes, which every flush sends).
    AckOnly,
    /// Every phase, including (re)transmission of data.
    Full,
}

/// `_itimediff` (`kcp.go:116-118`).
#[inline]
#[must_use]
pub fn itimediff(later: u32, earlier: u32) -> i32 {
    // Go: (int32)(later - earlier), wrapping.
    later.wrapping_sub(earlier) as i32
}

/// One KCP segment (`kcp.go:121-135`).
///
/// 64 bytes (asserted in the tests); `data` is a pooled buffer of
/// [`crate::pool::BUF_CAP`] bytes capacity, or empty once acknowledged
/// (`parse_ack` gives it back early, as Go's `recycleSegment` does).
#[derive(Debug, Default)]
pub struct Segment {
    pub(crate) conv: u32,
    pub(crate) cmd: u8,
    pub(crate) frg: u8,
    pub(crate) wnd: u16,
    pub(crate) acked: bool,
    pub(crate) ts: u32,
    pub(crate) sn: u32,
    pub(crate) una: u32,
    pub(crate) rto: u32,
    pub(crate) xmit: u32,
    pub(crate) resendts: u32,
    pub(crate) fastack: u32,
    pub(crate) data: Vec<u8>,
}

impl Segment {
    /// `encode` (`kcp.go:138-150`): the 24-byte header, `len` from `data`.
    fn encode_header(&self, ptr: &mut [u8], len: usize) {
        ptr[0..4].copy_from_slice(&self.conv.to_le_bytes());
        ptr[4] = self.cmd;
        ptr[5] = self.frg;
        ptr[6..8].copy_from_slice(&self.wnd.to_le_bytes());
        ptr[8..12].copy_from_slice(&self.ts.to_le_bytes());
        ptr[12..16].copy_from_slice(&self.sn.to_le_bytes());
        ptr[16..20].copy_from_slice(&self.una.to_le_bytes());
        // Go: uint32(len(seg.data)); a segment's data is at most a packet.
        ptr[20..24].copy_from_slice(&(len as u32).to_le_bytes());
    }
}

/// The receive buffer: Go's `segmentHeap` (`kcp.go:152-190`), a min-heap of
/// out-of-order segments by `sn` with a set against duplicates.
///
/// Every segment it holds has `rcv_nxt <= sn < rcv_nxt + rcv_wnd`
/// (`parse_data` admits nothing else, and `rcv_nxt` only moves past a
/// segment it hands on), so a deque of slots indexed by `sn - rcv_nxt` keeps
/// the same order: the heap's minimum is `rcv_nxt` exactly when slot 0 is
/// full, which is the only question Go's loops ask of it. Bounded by
/// `rcv_wnd` slots of 64 bytes plus the segments' buffers.
#[derive(Debug, Default)]
struct RecvBuf {
    slots: VecDeque<Option<Segment>>,
    len: usize,
}

impl RecvBuf {
    fn len(&self) -> usize {
        self.len
    }

    /// `Has(sn)` for `sn` at `offset = sn - rcv_nxt`.
    fn has(&self, offset: usize) -> bool {
        matches!(self.slots.get(offset), Some(Some(_)))
    }

    fn insert(&mut self, offset: usize, seg: Segment) {
        if self.slots.len() <= offset {
            self.slots.resize_with(offset + 1, || None);
        }
        debug_assert!(self.slots[offset].is_none());
        self.slots[offset] = Some(seg);
        self.len += 1;
    }

    /// The segment with `sn == rcv_nxt`, if held; the caller then moves
    /// `rcv_nxt` on by one, so every slot moves down by one.
    fn pop_front_if_ready(&mut self) -> Option<Segment> {
        match self.slots.front() {
            Some(Some(_)) => {
                self.len -= 1;
                self.slots.pop_front().flatten()
            }
            _ => None,
        }
    }

    /// Gives every held segment's buffer back.
    fn drain(&mut self, pool: &mut Pool) {
        for seg in self.slots.drain(..).flatten() {
            pool.put(seg.data);
        }
        self.len = 0;
    }
}

/// A KCP connection's protocol state machine (`kcp.go:194-248`). No I/O:
/// output goes through the callback handed to [`Kcp::flush`] and
/// [`Kcp::input`].
#[derive(Debug)]
pub struct Kcp {
    pub(crate) conv: u32,
    pub(crate) mtu: u32,
    pub(crate) mss: u32,
    pub(crate) state: u32,

    pub(crate) snd_una: u32,
    pub(crate) snd_nxt: u32,
    pub(crate) rcv_nxt: u32,

    pub(crate) ssthresh: u32,
    pub(crate) rx_rttvar: i32,
    pub(crate) rx_srtt: i32,
    pub(crate) rx_rto: u32,
    pub(crate) rx_minrto: u32,
    pub(crate) snd_wnd: u32,
    pub(crate) rcv_wnd: u32,
    pub(crate) rmt_wnd: u32,
    pub(crate) cwnd: u32,
    pub(crate) incr: u32,

    pub(crate) probe: u32,
    pub(crate) ts_probe: u32,
    pub(crate) probe_wait: u32,

    pub(crate) interval: u32,
    pub(crate) ts_flush: u32,
    pub(crate) nodelay: u32,
    pub(crate) updated: u32,

    pub(crate) dead_link: u32,
    pub(crate) fastresend: i32,
    pub(crate) nocwnd: i32,
    pub(crate) stream: i32,

    snd_queue: VecDeque<Segment>,
    rcv_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    rcv_buf: RecvBuf,

    acklist: Vec<(u32, u32)>,

    /// Go's `buffer`: `(mtu + IKCP_OVERHEAD) * 3` bytes, the encoding
    /// buffer of `flush`.
    buffer: Vec<u8>,
    pub(crate) pool: Pool,
    pub(crate) counters: Counters,
}

/// The parts of Go's `DefaultSnmp` that the state machine moves, per
/// connection here (Go keeps one global set).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Segments encoded (`OutSegs`).
    pub out_segs: u64,
    /// Segments read by `input` (`InSegs`).
    pub in_segs: u64,
    /// PUSH segments already held or outside the window (`RepeatSegs`).
    pub repeat_segs: u64,
    /// RTO retransmissions (`LostSegs`).
    pub lost_segs: u64,
    /// Fast retransmissions (`FastRetransSegs`).
    pub fast_retrans_segs: u64,
    /// Early retransmissions (`EarlyRetransSegs`).
    pub early_retrans_segs: u64,
    /// All retransmissions (`RetransSegs`).
    pub retrans_segs: u64,
}

impl Kcp {
    /// `NewKCP` (`kcp.go:260-281`).
    #[must_use]
    pub fn new(conv: u32) -> Self {
        let mtu = IKCP_MTU_DEF;
        Self {
            conv,
            mtu,
            mss: mtu - IKCP_OVERHEAD as u32,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: IKCP_THRESH_INIT,
            rx_rttvar: 0,
            rx_srtt: 0,
            rx_rto: IKCP_RTO_DEF,
            rx_minrto: IKCP_RTO_MIN,
            snd_wnd: IKCP_WND_SND,
            rcv_wnd: IKCP_WND_RCV,
            rmt_wnd: IKCP_WND_RCV,
            cwnd: 0,
            incr: 0,
            probe: 0,
            ts_probe: 0,
            probe_wait: 0,
            interval: IKCP_INTERVAL,
            ts_flush: IKCP_INTERVAL,
            nodelay: 0,
            updated: 0,
            dead_link: IKCP_DEADLINK,
            fastresend: 0,
            nocwnd: 0,
            stream: 0,
            snd_queue: VecDeque::with_capacity((IKCP_WND_SND * 2) as usize),
            rcv_queue: VecDeque::with_capacity((IKCP_WND_RCV * 2) as usize),
            snd_buf: VecDeque::with_capacity((IKCP_WND_SND * 2) as usize),
            rcv_buf: RecvBuf::default(),
            acklist: Vec::new(),
            buffer: vec![0; ((mtu as usize) + IKCP_OVERHEAD) * 3],
            pool: Pool::default(),
            counters: Counters::default(),
        }
    }

    /// `newSegment` (`kcp.go:284-287`).
    fn new_segment(&mut self, size: usize) -> Segment {
        let mut data = self.pool.get();
        data.resize(size, 0);
        Segment {
            data,
            ..Segment::default()
        }
    }

    /// `PeekSize` (`kcp.go:298-319`).
    #[must_use]
    pub fn peek_size(&self) -> i32 {
        let Some(seg) = self.rcv_queue.front() else {
            return -1;
        };
        if seg.frg == 0 {
            return seg.data.len() as i32;
        }
        if self.rcv_queue.len() < usize::from(seg.frg) + 1 {
            return -1;
        }
        let mut length = 0usize;
        for seg in &self.rcv_queue {
            length += seg.data.len();
            if seg.frg == 0 {
                break;
            }
        }
        length as i32
    }

    /// `Recv` (`kcp.go:328-380`): the next message into `buffer`; -1 when
    /// there is none, -2 when `buffer` is smaller than it.
    pub fn recv(&mut self, buffer: &mut [u8]) -> i32 {
        let peeksize = self.peek_size();
        if peeksize < 0 {
            return -1;
        }
        if peeksize as usize > buffer.len() {
            return -2;
        }

        let fast_recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        // merge fragment
        let mut n = 0usize;
        while let Some(seg) = self.rcv_queue.pop_front() {
            buffer[n..n + seg.data.len()].copy_from_slice(&seg.data);
            n += seg.data.len();
            let frg = seg.frg;
            self.pool.put(seg.data);
            if frg == 0 {
                break;
            }
        }

        self.move_rcv_buf();

        // fast recover
        if self.rcv_queue.len() < self.rcv_wnd as usize && fast_recover {
            self.probe |= IKCP_ASK_TELL;
        }
        n as i32
    }

    /// The loop that `Recv` and `parse_data` share: rcv_buf -> rcv_queue
    /// while the next segment is in order and the queue has room.
    fn move_rcv_buf(&mut self) {
        while self.rcv_buf.len() > 0 && self.rcv_queue.len() < self.rcv_wnd as usize {
            match self.rcv_buf.pop_front_if_ready() {
                Some(seg) => {
                    self.rcv_queue.push_back(seg);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                }
                None => break,
            }
        }
    }

    /// `Send` (`kcp.go:383-444`): 0, or -1 for an empty buffer, -2 for more
    /// than 255 fragments.
    pub fn send(&mut self, mut buffer: &[u8]) -> i32 {
        if buffer.is_empty() {
            return -1;
        }
        let mss = self.mss as usize;

        // append to previous segment in streaming mode (if possible)
        if self.stream != 0 {
            if let Some(seg) = self.snd_queue.back_mut() {
                if seg.data.len() < mss {
                    let capacity = mss - seg.data.len();
                    let extend = buffer.len().min(capacity);
                    seg.data.extend_from_slice(&buffer[..extend]);
                    buffer = &buffer[extend..];
                }
            }
            if buffer.is_empty() {
                return 0;
            }
        }

        let mut count = if buffer.len() <= mss {
            1
        } else {
            buffer.len().div_ceil(mss)
        };
        if count > 255 {
            return -2;
        }
        if count == 0 {
            count = 1;
        }

        for i in 0..count {
            let size = buffer.len().min(mss);
            let mut seg = self.new_segment(0);
            seg.data.extend_from_slice(&buffer[..size]);
            seg.frg = if self.stream == 0 {
                (count - i - 1) as u8
            } else {
                0
            };
            self.snd_queue.push_back(seg);
            buffer = &buffer[size..];
        }
        0
    }

    /// `update_ack` (`kcp.go:448-470`), RFC 6298.
    fn update_ack(&mut self, rtt: i32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttvar = rtt >> 1;
        } else {
            let mut delta = rtt.wrapping_sub(self.rx_srtt);
            self.rx_srtt = self.rx_srtt.wrapping_add(delta >> 3);
            if delta < 0 {
                delta = delta.wrapping_neg();
            }
            if rtt < self.rx_srtt.wrapping_sub(self.rx_rttvar) {
                self.rx_rttvar = self
                    .rx_rttvar
                    .wrapping_add((delta.wrapping_sub(self.rx_rttvar)) >> 5);
            } else {
                self.rx_rttvar = self
                    .rx_rttvar
                    .wrapping_add((delta.wrapping_sub(self.rx_rttvar)) >> 2);
            }
        }
        let rto =
            (self.rx_srtt as u32).wrapping_add(self.interval.max((self.rx_rttvar as u32) << 2));
        self.rx_rto = self.rx_minrto.max(rto).min(IKCP_RTO_MAX);
    }

    /// `shrink_buf` (`kcp.go:473-479`).
    fn shrink_buf(&mut self) {
        self.snd_una = match self.snd_buf.front() {
            Some(seg) => seg.sn,
            None => self.snd_nxt,
        };
    }

    /// `parse_ack` (`kcp.go:484-503`): mark, give the buffer back, keep the
    /// slot until `una` passes it.
    fn parse_ack(&mut self, sn: u32) {
        if itimediff(sn, self.snd_una) < 0 || itimediff(sn, self.snd_nxt) >= 0 {
            return;
        }
        for seg in &mut self.snd_buf {
            if sn == seg.sn {
                seg.acked = true;
                let data = std::mem::take(&mut seg.data);
                self.pool.put(data);
                break;
            }
            if itimediff(sn, seg.sn) < 0 {
                break;
            }
        }
    }

    /// `parse_fastack` (`kcp.go:507-527`).
    fn parse_fastack(&mut self, sn: u32, ts: u32) -> i32 {
        let mut should_fast_ack = 0;
        if itimediff(sn, self.snd_una) < 0 || itimediff(sn, self.snd_nxt) >= 0 {
            return 0;
        }
        let fastresend = self.fastresend as u32;
        for seg in &mut self.snd_buf {
            if itimediff(sn, seg.sn) < 0 {
                break;
            } else if sn != seg.sn && itimediff(seg.ts, ts) <= 0 && seg.fastack != 0xFFFF_FFFF {
                seg.fastack = seg.fastack.wrapping_add(1);
                if seg.fastack >= fastresend {
                    should_fast_ack = 1;
                }
            }
        }
        should_fast_ack
    }

    /// `parse_una` (`kcp.go:531-543`).
    fn parse_una(&mut self, una: u32) -> usize {
        let mut count = 0;
        while let Some(seg) = self.snd_buf.front() {
            if itimediff(una, seg.sn) > 0 {
                let seg = self.snd_buf.pop_front().expect("front exists");
                self.pool.put(seg.data);
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// `ack_push` (`kcp.go:546-548`).
    fn ack_push(&mut self, sn: u32, ts: u32) {
        self.acklist.push((sn, ts));
    }

    /// `parse_data` (`kcp.go:551-585`): true when the segment repeats one
    /// already held or falls outside the window.
    fn parse_data(&mut self, sn: u32, frg: u8, data: &[u8]) -> bool {
        if itimediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) >= 0
            || itimediff(sn, self.rcv_nxt) < 0
        {
            return true;
        }

        let offset = sn.wrapping_sub(self.rcv_nxt) as usize;
        let mut repeat = false;
        if self.rcv_buf.has(offset) {
            repeat = true;
        } else {
            // replicate the content if it's new
            let mut seg = self.new_segment(0);
            seg.data.extend_from_slice(data);
            seg.conv = self.conv;
            seg.cmd = IKCP_CMD_PUSH;
            seg.frg = frg;
            seg.sn = sn;
            self.rcv_buf.insert(offset, seg);
        }

        self.move_rcv_buf();
        repeat
    }

    /// `Input` (`kcp.go:593-739`): one packet from the peer. `regular` is
    /// Go's `pktType == IKCP_PACKET_REGULAR`. Returns 0, or -1 (short or a
    /// foreign conv), -2 (a length beyond the packet), -3 (an unknown cmd):
    /// as in Go, segments before the bad one have been taken and nothing
    /// after it runs (no RTT sample, no flush).
    pub fn input<F: FnMut(&[u8])>(
        &mut self,
        mut data: &[u8],
        regular: bool,
        ack_no_delay: bool,
        current: u32,
        output: &mut F,
    ) -> i32 {
        let snd_una = self.snd_una;
        if data.len() < IKCP_OVERHEAD {
            return -1;
        }

        let mut latest: u32 = 0;
        let mut update_rtt = 0;
        let mut in_segs: u64 = 0;
        let mut flush_segments = 0;

        loop {
            if data.len() < IKCP_OVERHEAD {
                break;
            }
            let conv = u32::from_le_bytes(data[0..4].try_into().expect("4"));
            let cmd = data[4];
            let frg = data[5];
            let wnd = u16::from_le_bytes(data[6..8].try_into().expect("2"));
            let ts = u32::from_le_bytes(data[8..12].try_into().expect("4"));
            let sn = u32::from_le_bytes(data[12..16].try_into().expect("4"));
            let una = u32::from_le_bytes(data[16..20].try_into().expect("4"));
            let length = u32::from_le_bytes(data[20..24].try_into().expect("4"));
            data = &data[IKCP_OVERHEAD..];

            if conv != self.conv {
                return -1;
            }
            if (data.len() as u64) < u64::from(length) {
                return -2;
            }
            if cmd != IKCP_CMD_PUSH
                && cmd != IKCP_CMD_ACK
                && cmd != IKCP_CMD_WASK
                && cmd != IKCP_CMD_WINS
            {
                return -3;
            }

            // only trust window updates from regular packets. i.e: latest update
            if regular {
                self.rmt_wnd = u32::from(wnd);
            }
            if self.parse_una(una) > 0 {
                flush_segments |= 1;
            }
            self.shrink_buf();

            let length = length as usize;
            match cmd {
                IKCP_CMD_ACK => {
                    self.parse_ack(sn);
                    flush_segments |= self.parse_fastack(sn, ts);
                    update_rtt |= 1;
                    latest = ts;
                }
                IKCP_CMD_PUSH => {
                    let mut repeat = true;
                    if itimediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) < 0 {
                        self.ack_push(sn, ts);
                        if itimediff(sn, self.rcv_nxt) >= 0 {
                            repeat = self.parse_data(sn, frg, &data[..length]);
                        }
                    }
                    if regular && repeat {
                        self.counters.repeat_segs += 1;
                    }
                }
                IKCP_CMD_WASK => {
                    // ready to send back IKCP_CMD_WINS in flush
                    self.probe |= IKCP_ASK_TELL;
                }
                _ => {} // IKCP_CMD_WINS
            }

            in_segs += 1;
            data = &data[length..];
        }
        self.counters.in_segs += in_segs;

        // update rtt with the latest ts; ignore the FEC packet
        if update_rtt != 0 && regular && itimediff(current, latest) >= 0 {
            self.update_ack(itimediff(current, latest));
        }

        // cwnd update on ACK arrival (Reno); off with nc = 1
        if self.nocwnd == 0 && itimediff(self.snd_una, snd_una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr = self.incr.wrapping_add(mss);
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr = self
                    .incr
                    .wrapping_add((mss.wrapping_mul(mss)) / self.incr + (mss / 16));
                if (self.cwnd + 1).wrapping_mul(mss) <= self.incr {
                    // Go: (incr + mss - 1) / mss in uint32, so it wraps.
                    let up = self.incr.wrapping_add(mss).wrapping_sub(1);
                    self.cwnd = up.checked_div(mss).unwrap_or(up);
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd.wrapping_mul(mss);
            }
        }

        if flush_segments != 0 {
            self.flush(FlushType::Full, current, output);
        } else if self.acklist.len() >= (self.mtu as usize) / IKCP_OVERHEAD {
            // clocking
            self.flush(FlushType::AckOnly, current, output);
        } else if ack_no_delay && !self.acklist.is_empty() {
            self.flush(FlushType::AckOnly, current, output);
        }
        0
    }

    /// `wnd_unused` (`kcp.go:741-746`).
    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            return (self.rcv_wnd as usize - self.rcv_queue.len()) as u16;
        }
        0
    }

    /// `flush` (`kcp.go:759-996`): writes what is due through `output`, one
    /// call per packet of at most `mtu` bytes, and returns the suggested
    /// interval (ms) until the next flush.
    pub fn flush<F: FnMut(&[u8])>(
        &mut self,
        flush_type: FlushType,
        current: u32,
        output: &mut F,
    ) -> u32 {
        let mut seg = Segment {
            conv: self.conv,
            cmd: IKCP_CMD_ACK,
            wnd: self.wnd_unused(),
            una: self.rcv_nxt,
            ..Segment::default()
        };

        let mtu = self.mtu as usize;
        // `ptr` of Go: the write offset into `buffer`.
        let mut buffer = std::mem::take(&mut self.buffer);
        let mut pos = 0usize;

        // makeSpace makes room for writing
        macro_rules! make_space {
            ($space:expr) => {
                if pos + $space > mtu {
                    output(&buffer[..pos]);
                    pos = 0;
                }
            };
        }

        // --- Phase 1: Flush pending ACKs ---
        // Both flush types flush the ACKs.
        let acks = std::mem::take(&mut self.acklist);
        let last = acks.len().wrapping_sub(1);
        for (i, &(sn, ts)) in acks.iter().enumerate() {
            make_space!(IKCP_OVERHEAD);
            // filter jitters caused by bufferbloat
            if itimediff(sn, self.rcv_nxt) >= 0 || last == i {
                seg.sn = sn;
                seg.ts = ts;
                seg.encode_header(&mut buffer[pos..pos + IKCP_OVERHEAD], 0);
                self.counters.out_segs += 1;
                pos += IKCP_OVERHEAD;
            }
        }
        self.acklist = acks;
        self.acklist.clear();

        // --- Phase 2: Window probing (when remote window is zero) ---
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = IKCP_PROBE_INIT;
                self.ts_probe = current.wrapping_add(self.probe_wait);
            } else if itimediff(current, self.ts_probe) >= 0 {
                if self.probe_wait < IKCP_PROBE_INIT {
                    self.probe_wait = IKCP_PROBE_INIT;
                }
                self.probe_wait += self.probe_wait / 2;
                if self.probe_wait > IKCP_PROBE_LIMIT {
                    self.probe_wait = IKCP_PROBE_LIMIT;
                }
                self.ts_probe = current.wrapping_add(self.probe_wait);
                self.probe |= IKCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }

        // --- Phase 3: Flush window probing commands ---
        // They carry whatever sn and ts the last ACK written left in `seg`.
        if self.probe & IKCP_ASK_SEND != 0 {
            seg.cmd = IKCP_CMD_WASK;
            make_space!(IKCP_OVERHEAD);
            seg.encode_header(&mut buffer[pos..pos + IKCP_OVERHEAD], 0);
            self.counters.out_segs += 1;
            pos += IKCP_OVERHEAD;
        }
        if self.probe & IKCP_ASK_TELL != 0 {
            seg.cmd = IKCP_CMD_WINS;
            make_space!(IKCP_OVERHEAD);
            seg.encode_header(&mut buffer[pos..pos + IKCP_OVERHEAD], 0);
            self.counters.out_segs += 1;
            pos += IKCP_OVERHEAD;
        }
        self.probe = 0;

        // --- Phase 4: snd_queue -> snd_buf (sliding window) ---
        let mut cwnd = self.snd_wnd.min(self.rmt_wnd);
        if self.nocwnd == 0 {
            cwnd = self.cwnd.min(cwnd);
        }
        let mut new_segs_count = 0;
        loop {
            if itimediff(self.snd_nxt, self.snd_una.wrapping_add(cwnd)) >= 0 {
                break;
            }
            let Some(mut newseg) = self.snd_queue.pop_front() else {
                break;
            };
            newseg.conv = self.conv;
            newseg.cmd = IKCP_CMD_PUSH;
            newseg.sn = self.snd_nxt;
            self.snd_buf.push_back(newseg);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            new_segs_count += 1;
        }

        // calculate resent
        let resent: u32 = if self.fastresend <= 0 {
            0xffff_ffff
        } else {
            self.fastresend as u32
        };

        // --- Phase 5: Retransmit segments from snd_buf ---
        let mut change: u64 = 0;
        let mut lost_segs: u64 = 0;
        let mut fast_retrans_segs: u64 = 0;
        let mut early_retrans_segs: u64 = 0;
        let mut next_update = self.interval;

        if flush_type == FlushType::Full {
            let rx_rto = self.rx_rto;
            let nodelay = self.nodelay;
            let dead_link = self.dead_link;
            let mut dead = false;
            for segment in &mut self.snd_buf {
                let mut needsend = false;
                if segment.acked {
                    continue;
                }
                if segment.xmit == 0 {
                    // initial transmit
                    needsend = true;
                    segment.rto = rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                } else if segment.fastack >= resent && segment.fastack != 0xFFFF_FFFF {
                    // fast retransmit
                    needsend = true;
                    segment.fastack = 0xFFFF_FFFF;
                    segment.rto = rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                    change += 1;
                    fast_retrans_segs += 1;
                } else if segment.fastack > 0
                    && segment.fastack != 0xFFFF_FFFF
                    && new_segs_count == 0
                {
                    // early retransmit
                    needsend = true;
                    segment.fastack = 0xFFFF_FFFF;
                    segment.rto = rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                    change += 1;
                    early_retrans_segs += 1;
                } else if itimediff(current, segment.resendts) >= 0 {
                    // RTO
                    needsend = true;
                    if nodelay == 0 {
                        segment.rto = segment.rto.wrapping_add(rx_rto);
                    } else {
                        segment.rto = segment.rto.wrapping_add(rx_rto / 2);
                    }
                    segment.fastack = 0;
                    segment.resendts = current.wrapping_add(segment.rto);
                    lost_segs += 1;
                }

                if needsend {
                    segment.xmit = segment.xmit.wrapping_add(1);
                    segment.ts = current;
                    segment.wnd = seg.wnd;
                    segment.una = seg.una;

                    let len = segment.data.len();
                    let need = IKCP_OVERHEAD + len;
                    make_space!(need);
                    segment.encode_header(&mut buffer[pos..pos + IKCP_OVERHEAD], len);
                    self.counters.out_segs += 1;
                    pos += IKCP_OVERHEAD;
                    buffer[pos..pos + len].copy_from_slice(&segment.data);
                    pos += len;

                    if segment.xmit >= dead_link {
                        dead = true;
                    }
                }

                // get the nearest rto
                let rto = itimediff(segment.resendts, current);
                if rto > 0 && (rto as u32) < next_update {
                    next_update = rto as u32;
                }
            }
            if dead {
                self.state = 0xFFFF_FFFF;
            }
        }

        // flushBuffer (Go's deferred call)
        if pos > 0 {
            output(&buffer[..pos]);
        }
        self.buffer = buffer;

        // --- Phase 6: counters and congestion window ---
        let mut sum = lost_segs;
        self.counters.lost_segs += lost_segs;
        self.counters.fast_retrans_segs += fast_retrans_segs;
        sum += fast_retrans_segs;
        self.counters.early_retrans_segs += early_retrans_segs;
        sum += early_retrans_segs;
        self.counters.retrans_segs += sum;

        if self.nocwnd == 0 {
            // rate halving per RFC 6937: ssthresh = inflight / 2
            if change > 0 {
                let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.ssthresh = (inflight / 2).max(IKCP_THRESH_MIN);
                self.cwnd = self.ssthresh.wrapping_add(resent);
                self.incr = self.cwnd.wrapping_mul(self.mss);
            }
            // after RTO: reset cwnd per RFC 5681
            if lost_segs > 0 {
                self.ssthresh = (cwnd / 2).max(IKCP_THRESH_MIN);
                self.cwnd = 1;
                self.incr = self.mss;
            }
            if self.cwnd < 1 {
                self.cwnd = 1;
                self.incr = self.mss;
            }
        }

        next_update
    }

    /// `Update` (`kcp.go:1003-1026`, deprecated in Go; kcp-go's own session
    /// calls `flush` instead, as [`crate::Session`] does).
    pub fn update<F: FnMut(&[u8])>(&mut self, current: u32, output: &mut F) {
        if self.updated == 0 {
            self.updated = 1;
            self.ts_flush = current;
        }
        let mut slap = itimediff(current, self.ts_flush);
        if !(-10000..10000).contains(&slap) {
            self.ts_flush = current;
            slap = 0;
        }
        if slap >= 0 {
            self.ts_flush = self.ts_flush.wrapping_add(self.interval);
            if itimediff(current, self.ts_flush) >= 0 {
                self.ts_flush = current.wrapping_add(self.interval);
            }
            self.flush(FlushType::Full, current, output);
        }
    }

    /// `Check` (`kcp.go:1037-1077`, deprecated in Go).
    #[must_use]
    pub fn check(&self, current: u32) -> u32 {
        let mut ts_flush = self.ts_flush;
        let mut tm_packet: i32 = 0x7fff_ffff;
        if self.updated == 0 {
            return current;
        }
        if itimediff(current, ts_flush) >= 10000 || itimediff(current, ts_flush) < -10000 {
            ts_flush = current;
        }
        if itimediff(current, ts_flush) >= 0 {
            return current;
        }
        let tm_flush = itimediff(ts_flush, current);
        for seg in &self.snd_buf {
            let diff = itimediff(seg.resendts, current);
            if diff <= 0 {
                return current;
            }
            if diff < tm_packet {
                tm_packet = diff;
            }
        }
        let mut minimal = tm_packet as u32;
        if tm_packet >= tm_flush {
            minimal = tm_flush as u32;
        }
        if minimal >= self.interval {
            minimal = self.interval;
        }
        current.wrapping_add(minimal)
    }

    /// `SetMtu` (`kcp.go:1080-1089`): -1 when `mtu` is not above the header.
    pub fn set_mtu(&mut self, mtu: i32) -> i32 {
        if mtu <= IKCP_OVERHEAD as i32 {
            return -1;
        }
        self.mtu = mtu as u32;
        self.mss = self.mtu - IKCP_OVERHEAD as u32;
        self.buffer = vec![0; (mtu as usize + IKCP_OVERHEAD) * 3];
        0
    }

    /// `NoDelay` (`kcp.go:1097-1121`): the interval is clamped to 10..=5000
    /// ms, so the engine's 5 becomes 10.
    pub fn nodelay(&mut self, nodelay: i32, interval: i32, resend: i32, nc: i32) -> i32 {
        if nodelay >= 0 {
            self.nodelay = nodelay as u32;
            self.rx_minrto = if nodelay != 0 {
                IKCP_RTO_NDL
            } else {
                IKCP_RTO_MIN
            };
        }
        if interval >= 0 {
            self.interval = interval.clamp(10, 5000) as u32;
        }
        if resend >= 0 {
            self.fastresend = resend;
        }
        if nc >= 0 {
            self.nocwnd = nc;
        }
        0
    }

    /// `WndSize` (`kcp.go:1124-1132`).
    pub fn wnd_size(&mut self, sndwnd: i32, rcvwnd: i32) -> i32 {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd as u32;
        }
        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd as u32;
        }
        0
    }

    /// `WaitSnd` (`kcp.go:1135-1137`).
    #[must_use]
    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Stream mode on or off (Go sets the field from `UDPSession.SetStreamMode`).
    pub fn set_stream(&mut self, stream: bool) {
        self.stream = i32::from(stream);
    }

    /// The send window (segments).
    #[must_use]
    pub fn snd_wnd(&self) -> u32 {
        self.snd_wnd
    }

    /// The receive window (segments).
    #[must_use]
    pub fn rcv_wnd(&self) -> u32 {
        self.rcv_wnd
    }

    /// The window the peer last advertised (segments).
    #[must_use]
    pub fn rmt_wnd(&self) -> u32 {
        self.rmt_wnd
    }

    /// The maximum segment size (`mtu - 24`).
    #[must_use]
    pub fn mss(&self) -> u32 {
        self.mss
    }

    /// The current retransmission timeout (ms) (`GetRTO`).
    #[must_use]
    pub fn rto(&self) -> u32 {
        self.rx_rto
    }

    /// The smoothed round trip (ms) (`GetSRTT`).
    #[must_use]
    pub fn srtt(&self) -> i32 {
        self.rx_srtt
    }

    /// `state == 0xFFFFFFFF`: a segment was sent `dead_link` times. kcp-go's
    /// session never reads it, and neither does [`crate::Session`].
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.state == 0xFFFF_FFFF
    }

    /// The counters this connection moved.
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// Segments held per queue: (snd_queue, snd_buf, rcv_buf, rcv_queue).
    #[must_use]
    pub fn queue_lens(&self) -> (usize, usize, usize, usize) {
        (
            self.snd_queue.len(),
            self.snd_buf.len(),
            self.rcv_buf.len(),
            self.rcv_queue.len(),
        )
    }

    /// Payload bytes held in segment buffers, at their capacity (what the
    /// memory budget counts), plus the buffers the pool keeps free.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.pool.in_use() * crate::pool::BUF_CAP + self.pool.free_bytes()
    }

    /// Gives every buffer back: the queues, the receive buffer and the pool.
    pub fn clear(&mut self) {
        for seg in self
            .snd_queue
            .drain(..)
            .chain(self.snd_buf.drain(..))
            .chain(self.rcv_queue.drain(..))
        {
            self.pool.put(seg.data);
        }
        self.rcv_buf.drain(&mut self.pool);
        self.acklist = Vec::new();
        self.pool.trim();
    }
}

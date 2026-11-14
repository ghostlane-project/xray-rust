// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A port of the parts of kcp-go v5.6.72 sess.go (https://github.com/xtaci/kcp-go)
// that decide what goes on the wire, Copyright (c) 2015 xtaci, MIT License.
// See NOTICE.

//! kcp-go's `UDPSession`, without the socket: when it flushes, how it splits
//! writes, how it reads a stream, what it drops.
//!
//! The olcRTC engine drives kcp-go through a fake `net.PacketConn`
//! (`vp8channel/kcpconn.go`) with no FEC and no cipher, so of `sess.go` only
//! these parts shape the wire, and they are what this type keeps:
//!
//! - `WriteBuffers` (`sess.go:366-451`): a write is taken whole while
//!   `WaitSnd() < snd_wnd`, cut into `mss` pieces for `kcp.Send`, then
//!   flushed at once unless write delay is on. Otherwise it waits
//!   ([`WouldBlock`]).
//! - `Read` (`sess.go:275-360`): one segment (stream mode) at a time, the
//!   rest of a segment kept for the next read.
//! - the output callback (`sess.go:227-245`): a copy of each packet of at
//!   least 24 bytes into a queue of `devBacklog` = 2048 (`sess.go:86`), and
//!   a packet that finds it full is dropped (KCP resends it).
//! - `packetInput`/`kcpInput` (`sess.go:970-1121`) with no cipher: packets
//!   under 12 bytes are dropped, FEC-tagged ones go their own way, the rest
//!   to `kcp.Input` as regular packets with the session's ACK-no-delay.
//! - `update` (`sess.go:802-816`): a full flush, next one after the interval
//!   it returns.
//! - the read side's buffer of `mtuLimit` bytes (`readloop.go:44`,
//!   `kcpconn.go:249-258`): a packet larger than 1500 bytes reaches KCP cut
//!   to 1500.
//!
//! # Memory
//!
//! With `W` = snd_wnd, `R` = rcv_wnd, `M` = the largest single write in
//! segments (`ceil(len / mss)`), `B` = the output backlog, `C` =
//! [`crate::pool::BUF_CAP`] (1476):
//!
//! - send side: `WaitSnd() <= W − 1 + M` segments (a write is taken while
//!   fewer than `W` wait), each one buffer of `C` until acknowledged;
//! - receive side: `rcv_queue <= R` and `rcv_buf < R` segments, `C` each;
//! - output queue: `<= B` packets of at most `mtu` bytes;
//! - the read buffer: `max(1500, largest segment)`.
//!
//! vp8channel's phone profile (W = R = 512, writes of at most 4 + 61,440
//! bytes, M = 45, B = 2048, mtu 1400): `(556 + 1023) × 1476` = 2.33 MB of
//! segments and 2.87 MB of output queue at the worst. Go's are the same
//! counts (its buffers are 1500 bytes). The windows are what the peer reads
//! (`wnd` in every segment), so they stay Go's; see [`Session::stats`] for
//! what a run actually held.

use std::collections::VecDeque;
use std::time::Instant;

use crate::kcp::{FlushType, Kcp, IKCP_OVERHEAD};
use crate::pool::MTU_LIMIT;

/// kcp-go's `devBacklog` (`sess.go:86`): the queue between KCP's output
/// callback and the packet writer.
pub const DEV_BACKLOG: usize = 2048;

/// FEC type marks at offset 4 (`kcp-go/fec.go:55-57`).
const TYPE_DATA: u16 = 0xf1;
const TYPE_PARITY: u16 = 0xf2;
const TYPE_OOB: u16 = 0xf3;
/// `fecHeaderSizePlus2` (`kcp-go/fec.go:54`).
const FEC_HEADER_SIZE_PLUS2: usize = 8;
/// `convSize` (`sess.go:80`).
const CONV_SIZE: usize = 4;

/// The settings `startKCP` gives a session, as fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Conversation id (`kcpConvID`).
    pub conv: u32,
    /// `SetNoDelay(nodelay, interval, resend, nc)`.
    pub nodelay: i32,
    /// The interval asked for (kcp-go clamps it to at least 10 ms).
    pub interval: i32,
    /// Fast resend after this many skipping ACKs.
    pub resend: i32,
    /// 1: congestion control off.
    pub nc: i32,
    /// `SetWindowSize(snd, rcv)` (segments).
    pub snd_wnd: i32,
    /// See `snd_wnd`.
    pub rcv_wnd: i32,
    /// `SetMtu` (clamped to 1500).
    pub mtu: i32,
    /// `SetStreamMode`.
    pub stream: bool,
    /// `SetACKNoDelay`.
    pub ack_no_delay: bool,
    /// `SetWriteDelay`.
    pub write_delay: bool,
    /// The output queue's length in packets (Go: `devBacklog`).
    pub output_backlog: usize,
}

impl Config {
    /// vp8channel's `kcpConvID` (`vp8channel/kcp.go:59`).
    pub const VP8CHANNEL_CONV: u32 = 0xC0FF_EE01;
    /// vp8channel's `kcpMTU` (`vp8channel/kcp.go:66`): mss 1376.
    pub const VP8CHANNEL_MTU: i32 = 1400;

    /// What `startKCPAcks` sets (`vp8channel/kcp.go:155-179`):
    /// `SetNoDelay(1, 5, 2, 1)` (the 5 ms becomes 10), the windows given,
    /// MTU 1400, stream mode, ACK no-delay, no write delay.
    ///
    /// The windows are the host profile's (`vp8channel/kcp.go:17-36,76-106`):
    /// the phone (constrained) profile is 512/512, a server's 4096/4096,
    /// and a paced writer's send window 512.
    #[must_use]
    pub fn vp8channel(snd_wnd: i32, rcv_wnd: i32) -> Self {
        Self {
            conv: Self::VP8CHANNEL_CONV,
            nodelay: 1,
            interval: 5,
            resend: 2,
            nc: 1,
            snd_wnd,
            rcv_wnd,
            mtu: Self::VP8CHANNEL_MTU,
            stream: true,
            ack_no_delay: true,
            write_delay: false,
            output_backlog: DEV_BACKLOG,
        }
    }

    /// The phone profile (`kcpConstrainedSndWnd`, `kcpConstrainedRcvWnd`).
    #[must_use]
    pub fn vp8channel_constrained() -> Self {
        Self::vp8channel(512, 512)
    }
}

/// A write found the send window full; retry after the next update or input
/// (Go's `Write` blocks on `chWriteEvent` instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WouldBlock;

/// What a session counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Packets KCP made while the output queue was full (dropped, resent later).
    pub output_dropped: u64,
    /// The most packets the output queue ever held.
    pub output_peak: usize,
    /// Packets cut to 1500 bytes on the way in.
    pub input_truncated: u64,
    /// Packets refused: under 12 bytes, or `kcp.Input` returned an error.
    pub input_errors: u64,
    /// FEC parity and OOB packets, which have nowhere to go without FEC.
    pub fec_ignored: u64,
    /// Zero-length segments read past (see [`Session::read`]).
    pub empty_segments: u64,
    /// The most segment buffers in use at once.
    pub peak_buffers: usize,
}

/// One KCP session: [`Kcp`] with kcp-go's session around it.
#[derive(Debug)]
pub struct Session {
    kcp: Kcp,
    ack_no_delay: bool,
    write_delay: bool,
    origin: Instant,

    /// Go's `recvbuf` and `bufptr`: the rest of a segment a short read left.
    recvbuf: Vec<u8>,
    bufptr: usize,

    output: VecDeque<Vec<u8>>,
    output_cap: usize,
    output_free: Vec<Vec<u8>>,

    stats: Stats,
}

/// Output packet buffers kept for reuse: one OLKB batch.
const OUTPUT_RETAIN: usize = 64;

impl Session {
    /// A session with `cfg`, its clock starting at `origin` (Go's `refTime`;
    /// the `ts` it stamps are milliseconds since then).
    #[must_use]
    pub fn new(cfg: Config, origin: Instant) -> Self {
        let mut kcp = Kcp::new(cfg.conv);
        // newUDPSession: SetMtu(IKCP_MTU_DEF), then startKCP's settings in
        // its order.
        kcp.nodelay(cfg.nodelay, cfg.interval, cfg.resend, cfg.nc);
        kcp.wnd_size(cfg.snd_wnd, cfg.rcv_wnd);
        // SetMtu: min(mtuLimit, mtu) - headerSize (0: no cipher, no FEC).
        let _ = kcp.set_mtu(cfg.mtu.min(MTU_LIMIT as i32));
        kcp.set_stream(cfg.stream);
        Self {
            kcp,
            ack_no_delay: cfg.ack_no_delay,
            write_delay: cfg.write_delay,
            origin,
            recvbuf: Vec::new(),
            bufptr: 0,
            output: VecDeque::new(),
            output_cap: cfg.output_backlog,
            output_free: Vec::new(),
            stats: Stats::default(),
        }
    }

    /// Milliseconds since the origin, as Go's `currentMs` (wrapping u32).
    #[must_use]
    pub fn ms(&self, now: Instant) -> u32 {
        now.saturating_duration_since(self.origin).as_millis() as u32
    }

    /// The state machine.
    #[must_use]
    pub fn kcp(&self) -> &Kcp {
        &self.kcp
    }

    /// `WriteBuffers` (`sess.go:366-451`): takes all of `bufs` while fewer
    /// than `snd_wnd` segments wait, else [`WouldBlock`].
    pub fn write(&mut self, bufs: &[&[u8]], now: Instant) -> Result<usize, WouldBlock> {
        let snd_wnd = self.kcp.snd_wnd() as usize;
        if self.kcp.wait_snd() >= snd_wnd {
            return Err(WouldBlock);
        }
        let mss = self.kcp.mss() as usize;
        let mut n = 0;
        for b in bufs {
            n += b.len();
            let mut b: &[u8] = b;
            loop {
                if b.len() <= mss {
                    self.kcp.send(b);
                    break;
                }
                self.kcp.send(&b[..mss]);
                b = &b[mss..];
            }
        }
        if self.kcp.wait_snd() >= snd_wnd || !self.write_delay {
            let current = self.ms(now);
            self.flush(FlushType::Full, current);
        }
        self.note_buffers();
        Ok(n)
    }

    /// Whether a write would be taken now.
    #[must_use]
    pub fn writable(&self) -> bool {
        self.kcp.wait_snd() < self.kcp.snd_wnd() as usize
    }

    /// `Read` (`sess.go:275-360`): `Some(n)` bytes of the stream, or `None`
    /// when nothing is ready.
    ///
    /// One departure: a zero-length segment at the head of the queue is read
    /// past. kcp-go's `Read` only takes `PeekSize() > 0`, so such a segment
    /// (a peer's empty PUSH; kcp-go never sends one) wedges its reader for
    /// good.
    pub fn read(&mut self, b: &mut [u8]) -> Option<usize> {
        if self.bufptr < self.recvbuf.len() {
            let rest = &self.recvbuf[self.bufptr..];
            let n = rest.len().min(b.len());
            b[..n].copy_from_slice(&rest[..n]);
            self.bufptr += n;
            return Some(n);
        }
        loop {
            let size = self.kcp.peek_size();
            if size == 0 {
                self.kcp.recv(&mut []);
                self.stats.empty_segments += 1;
                continue;
            }
            if size < 0 {
                return None;
            }
            let size = size as usize;
            if b.len() >= size {
                self.kcp.recv(b);
                return Some(size);
            }
            self.recvbuf.clear();
            self.recvbuf.resize(size, 0);
            self.kcp.recv(&mut self.recvbuf);
            let n = b.len();
            b.copy_from_slice(&self.recvbuf[..n]);
            self.bufptr = n;
            return Some(n);
        }
    }

    /// Whether [`Session::read`] would return bytes.
    #[must_use]
    pub fn readable(&self) -> bool {
        self.bufptr < self.recvbuf.len() || self.kcp.peek_size() >= 0
    }

    /// One packet from the peer: `packetInput` and `kcpInput` with no
    /// cipher (`sess.go:970-1121`), after the 1500-byte read buffer.
    pub fn input(&mut self, packet: &[u8], now: Instant) {
        let data = if packet.len() > MTU_LIMIT {
            self.stats.input_truncated += 1;
            &packet[..MTU_LIMIT]
        } else {
            packet
        };
        // basic check for minimum packet size: min(IKCP_OVERHEAD, fecHeaderSizePlus2 + convSize)
        if data.len() < IKCP_OVERHEAD.min(FEC_HEADER_SIZE_PLUS2 + CONV_SIZE) {
            self.stats.input_errors += 1;
            return;
        }
        let current = self.ms(now);
        let fec_flag = u16::from_le_bytes([data[4], data[5]]);
        let ack_no_delay = self.ack_no_delay;
        let ret = match fec_flag {
            // A data shard: its KCP packet goes in as a regular one. With no
            // parity on this transport FEC can recover nothing, so the
            // decoder Go creates lazily here is not ported.
            TYPE_DATA => {
                let mut out = OutputSink::new(
                    &mut self.output,
                    self.output_cap,
                    &mut self.output_free,
                    &mut self.stats,
                );
                self.kcp.input(
                    &data[FEC_HEADER_SIZE_PLUS2..],
                    true,
                    ack_no_delay,
                    current,
                    &mut |p: &[u8]| out.push(p),
                )
            }
            TYPE_PARITY | TYPE_OOB => {
                self.stats.fec_ignored += 1;
                0
            }
            _ => {
                let mut out = OutputSink::new(
                    &mut self.output,
                    self.output_cap,
                    &mut self.output_free,
                    &mut self.stats,
                );
                self.kcp
                    .input(data, true, ack_no_delay, current, &mut |p: &[u8]| {
                        out.push(p)
                    })
            }
        };
        if ret != 0 {
            self.stats.input_errors += 1;
        }
        self.note_buffers();
    }

    /// `update` (`sess.go:802-816`): a full flush; returns the milliseconds
    /// until the next one is due.
    pub fn update(&mut self, now: Instant) -> u32 {
        let current = self.ms(now);
        let interval = self.flush(FlushType::Full, current);
        self.note_buffers();
        interval
    }

    /// `Close` sends what it can first (`sess.go:476-479`).
    pub fn close(&mut self, now: Instant) {
        let current = self.ms(now);
        self.flush(FlushType::Full, current);
    }

    fn flush(&mut self, flush_type: FlushType, current: u32) -> u32 {
        let mut out = OutputSink::new(
            &mut self.output,
            self.output_cap,
            &mut self.output_free,
            &mut self.stats,
        );
        self.kcp
            .flush(flush_type, current, &mut |p: &[u8]| out.push(p))
    }

    fn note_buffers(&mut self) {
        self.stats.peak_buffers = self.stats.peak_buffers.max(self.kcp.pool.in_use());
    }

    /// The oldest packet waiting to go out.
    #[must_use]
    pub fn peek_output(&self) -> Option<&[u8]> {
        self.output.front().map(Vec::as_slice)
    }

    /// Drops the oldest packet waiting (after it was written).
    pub fn pop_output(&mut self) {
        if let Some(mut b) = self.output.pop_front() {
            if self.output_free.len() < OUTPUT_RETAIN {
                b.clear();
                self.output_free.push(b);
            }
        }
    }

    /// Packets waiting to go out.
    #[must_use]
    pub fn output_len(&self) -> usize {
        self.output.len()
    }

    /// Drops every packet waiting to go out.
    pub fn clear_output(&mut self) {
        while !self.output.is_empty() {
            self.pop_output();
        }
    }

    /// What this session counted.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Bytes this session holds: segment buffers (at capacity), the free
    /// pool, the output queue and the read buffer.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.kcp.buffered_bytes()
            + self.output.iter().map(Vec::capacity).sum::<usize>()
            + self.output_free.iter().map(Vec::capacity).sum::<usize>()
            + self.recvbuf.capacity()
    }

    /// Gives the free buffers back (the queues keep what they hold).
    pub fn trim(&mut self) {
        self.kcp.pool.trim();
        self.output_free = Vec::new();
        if self.bufptr >= self.recvbuf.len() {
            self.recvbuf = Vec::new();
            self.bufptr = 0;
        }
    }
}

/// The output callback of `newUDPSession` (`sess.go:227-245`).
struct OutputSink<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    cap: usize,
    free: &'a mut Vec<Vec<u8>>,
    stats: &'a mut Stats,
}

impl<'a> OutputSink<'a> {
    fn new(
        queue: &'a mut VecDeque<Vec<u8>>,
        cap: usize,
        free: &'a mut Vec<Vec<u8>>,
        stats: &'a mut Stats,
    ) -> Self {
        Self {
            queue,
            cap,
            free,
            stats,
        }
    }

    fn push(&mut self, packet: &[u8]) {
        // A basic check for the minimum packet size.
        if packet.len() < IKCP_OVERHEAD {
            return;
        }
        if self.queue.len() >= self.cap {
            // drop and recycle to avoid blocking; KCP will retransmit if needed
            self.stats.output_dropped += 1;
            return;
        }
        let mut b = self.free.pop().unwrap_or_default();
        b.clear();
        b.extend_from_slice(packet);
        self.queue.push_back(b);
        self.stats.output_peak = self.stats.output_peak.max(self.queue.len());
    }
}

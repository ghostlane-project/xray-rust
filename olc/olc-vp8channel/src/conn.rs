// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! One KCP plane: `kcpPlane`, `kcpRuntime` and `kcpConn`
//! (`vp8channel/kcp.go`, `kcpconn.go` at 2d4266af), sans-IO.
//!
//! Go runs a plane as goroutines around a `net.PacketConn`: kcp-go's update
//! loop and output goroutine write each KCP packet to `kcpConn.WriteTo`,
//! which wraps it (`[epoch header][packet][CRC-32C]`) into the plane's
//! outbound queue for the paced writer, and blocks while that queue is full;
//! the track reader hands each inbound packet to `deliver`, which checks the
//! CRC and queues it for kcp-go's reader. Here the plane owns the session:
//!
//! - KCP's output queue ([`olc_kcp::session::DEV_BACKLOG`], kcp-go's
//!   `chPostProcessing`) is moved into [`Plane::out`] while it has room
//!   ([`Plane::pump`]); a packet that does not fit stays in KCP's queue, as
//!   Go's blocked `WriteTo` holds it;
//! - an inbound packet goes into KCP at once ([`Plane::deliver`]): Go's
//!   inbound queue (4096, or 1024 on the phone) only ever drops, so there is
//!   none;
//! - messages are read out by the caller ([`Plane::read`]), so a slow reader
//!   leaves them in KCP and its window closes, as Go's `readLoop` blocked in
//!   `onData` does.
//!
//! The data lane's state on the conn (issue #12) is kept here too: when the
//! peer last answered, the hold that drops resent pushes while the lane is
//! dark and the probe it lets through, and the delivery count.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use olc_kcp::{link, message, Config as KcpConfig, Session};

use crate::frames::{stamps_of, DeliveryTrack};
use crate::segment::{answers, pushes};
use crate::wire::{EpochHeader, EPOCH_HDR_LEN, WIRE_CRC_LEN};

/// `outboundQueueSize`: data packets waiting for the writer (server profile).
pub const OUTBOUND_QUEUE: usize = 1536;
/// `constrainedOutboundQueueSize`: the same on the phone.
pub const CONSTRAINED_OUTBOUND_QUEUE: usize = 1024;
/// `controlOutboundQueueSize`.
pub const CONTROL_OUTBOUND_QUEUE: usize = 2048;
/// `ackQueueSize`: packets that only acknowledge the peer, written ahead of
/// the data.
pub const ACK_QUEUE: usize = 256;
/// `canSendHighWatermark`, percent.
pub const CAN_SEND_HIGH_WATERMARK: usize = 90;

/// Packet buffers kept for reuse per plane: what one full batch takes.
const FREE_RETAIN: usize = 64;
/// The capacity of a packet buffer: Go's largest pooled class.
const PACKET_CAP: usize = 1536;

/// A wrapped packet on its way to the writer (`packetBuffer`).
#[derive(Debug)]
pub struct Packet {
    /// `[epoch header][KCP packet][CRC-32C BE]`.
    pub data: Vec<u8>,
    /// When it was queued, on the channel's clock (`queued`).
    pub queued: i64,
}

/// Why a message was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The plane is down (Go: `ErrTransportClosed`, `rt == nil`).
    Closed,
    /// Over 8 MiB (`ErrKCPMessageTooLarge`).
    TooLarge,
    /// The send window is full; Go's `Write` blocks here.
    WouldBlock,
}

/// One KCP session and what rides on it (`kcpRuntime` + `kcpConn`).
#[derive(Debug)]
pub struct Conn {
    /// Tells a restarted plane's session from the one before.
    pub id: u64,
    /// The session.
    pub sess: Session,
    hdr: EpochHeader,
    reader: message::Reader,
    /// A message over the cap ended Go's `readLoop`: nothing more is read.
    read_dead: bool,
    /// When the peer last answered (`lastAck`), channel clock; 0 never.
    pub last_ack: i64,
    hold_every: i64,
    probe_at: i64,
    probe_buf: Vec<u8>,
    /// Pushes written and acknowledgements back (`delivery`).
    pub delivery: DeliveryTrack,
    /// Packets refused by the CRC (`corrupt`).
    pub corrupt: u64,
    /// When the session's timer next flushes.
    pub next_update: Instant,
}

impl Conn {
    /// `hold`: drop pushes but one per `every` (ns); 0 lets them through.
    pub fn hold(&mut self, every: i64) {
        self.probe_at = 0;
        self.hold_every = every;
    }

    /// Whether pushes are held back.
    #[must_use]
    pub fn holding(&self) -> bool {
        self.hold_every != 0
    }

    /// `keepProbe`: the newest push held back.
    pub fn keep_probe(&mut self, p: &[u8]) {
        self.probe_buf.clear();
        self.probe_buf.extend_from_slice(p);
    }

    /// `withheld`: whether `WriteTo` drops `p` ([`Plane::pump`] inlines it).
    #[cfg(test)]
    fn withheld(&mut self, p: &[u8]) -> bool {
        if self.hold_every == 0 || answers(p) || !pushes(p) {
            return false;
        }
        self.keep_probe(p);
        true
    }

    /// The frame header the packets carry now.
    #[must_use]
    pub fn header(&self) -> &EpochHeader {
        &self.hdr
    }
}

/// `kcpPlane`: a queue to the writer and the session that fills it, which
/// a restart replaces while the queue stays.
#[derive(Debug)]
pub struct Plane {
    /// Wrapped packets for the writer.
    pub out: VecDeque<Packet>,
    /// [`Plane::out`]'s bound.
    pub out_cap: usize,
    /// What only acknowledges the peer, on a data plane (`acks`).
    pub acks: Option<VecDeque<Packet>>,
    /// The live session, `None` before the start and after the close.
    pub rt: Option<Conn>,
    kcp: KcpConfig,
    origin: Instant,
    free: Vec<Vec<u8>>,
    next_id: u64,
    started: bool,
    closed: bool,
}

impl Plane {
    /// `newKCPPlane` (`with_acks` false) or `newDataPlane`. `origin` is the
    /// sessions' clock origin (kcp-go's `refTime`).
    #[must_use]
    pub fn new(out_cap: usize, with_acks: bool, kcp: KcpConfig, origin: Instant) -> Self {
        Self {
            out: VecDeque::new(),
            out_cap,
            acks: with_acks.then(VecDeque::new),
            rt: None,
            kcp,
            origin,
            free: Vec::new(),
            next_id: 1,
            started: false,
            closed: false,
        }
    }

    /// `start`: brings the plane up once; whether this call did.
    pub fn start(&mut self, hdr: EpochHeader, now: Instant) -> bool {
        if self.started || self.closed {
            return false;
        }
        self.started = true;
        self.rt = Some(self.new_conn(hdr, now));
        true
    }

    fn new_conn(&mut self, hdr: EpochHeader, now: Instant) -> Conn {
        let id = self.next_id;
        self.next_id += 1;
        Conn {
            id,
            sess: Session::new(self.kcp, self.origin),
            hdr,
            reader: message::Reader::new(),
            read_dead: false,
            last_ack: 0,
            hold_every: 0,
            probe_at: 0,
            probe_buf: Vec::new(),
            delivery: DeliveryTrack::default(),
            corrupt: 0,
            next_update: now,
        }
    }

    /// `restart`: drops what is queued and replaces the session with a
    /// fresh one stamped with `hdr`.
    pub fn restart(&mut self, hdr: EpochHeader, now: Instant) {
        if self.closed {
            return;
        }
        self.drain();
        self.started = true;
        self.rt = Some(self.new_conn(hdr, now));
    }

    /// `drain`: discards everything queued for the writer.
    pub fn drain(&mut self) {
        while let Some(p) = self.out.pop_front() {
            self.release(p.data);
        }
        if let Some(acks) = self.acks.as_mut() {
            while let Some(p) = acks.pop_front() {
                if self.free.len() < FREE_RETAIN {
                    let mut b = p.data;
                    b.clear();
                    self.free.push(b);
                }
            }
        }
    }

    /// `close`: the session sends what it can, then is gone.
    pub fn close(&mut self, now: Instant) {
        self.closed = true;
        if let Some(rt) = self.rt.as_mut() {
            rt.sess.close(now);
        }
        self.rt = None;
    }

    /// Whether the plane was closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// `setHeader`: re-points the header of the packets from now on.
    pub fn set_header(&mut self, hdr: EpochHeader) {
        if let Some(rt) = self.rt.as_mut() {
            rt.hdr = hdr;
        }
    }

    /// `SetWindowSize(segments, 0)` on the live session (`dataWindow`).
    pub fn set_window(&mut self, segments: usize) {
        if let Some(rt) = self.rt.as_mut() {
            rt.sess
                .set_window_size(i32::try_from(segments).unwrap_or(i32::MAX), 0);
        }
    }

    /// Returns a packet buffer to the free list.
    pub fn release(&mut self, mut b: Vec<u8>) {
        if self.free.len() < FREE_RETAIN && b.capacity() <= PACKET_CAP * 2 {
            b.clear();
            self.free.push(b);
        }
    }

    /// `wrap`: `[header][p][CRC-32C(p)]`, queued at `now_ns`.
    fn wrap(free: &mut Vec<Vec<u8>>, hdr: &EpochHeader, p: &[u8], now_ns: i64) -> Packet {
        let mut data = free.pop().unwrap_or_else(|| Vec::with_capacity(PACKET_CAP));
        link::wrap_into(&mut data, hdr, p);
        Packet {
            data,
            queued: now_ns,
        }
    }

    /// kcp-go's output goroutine writing to `WriteTo`: moves KCP's output
    /// into the queues while they have room. A push the hold withholds is
    /// dropped (and kept as the probe); what only acknowledges goes to
    /// [`Plane::acks`] while it has room, else with the data.
    pub fn pump(&mut self, now_ns: i64) {
        let Some(rt) = self.rt.as_mut() else {
            return;
        };
        while let Some(p) = rt.sess.peek_output() {
            let push = pushes(p);
            let answer = answers(p);
            if rt.hold_every != 0 && !answer && push {
                rt.probe_buf.clear();
                rt.probe_buf.extend_from_slice(p);
                rt.sess.pop_output();
                continue;
            }
            if let (Some(acks), true) = (self.acks.as_mut(), answer && !push) {
                if acks.len() < ACK_QUEUE {
                    let packet = Self::wrap(&mut self.free, &rt.hdr, p, now_ns);
                    acks.push_back(packet);
                    rt.sess.pop_output();
                    continue;
                }
            }
            if self.out.len() >= self.out_cap {
                return;
            }
            let packet = Self::wrap(&mut self.free, &rt.hdr, p, now_ns);
            self.out.push_back(packet);
            rt.sess.pop_output();
        }
    }

    /// `deliver`: a KCP packet off the wire (its CRC-32C trailer still on).
    /// A bad CRC is counted and dropped; KCP resends.
    pub fn deliver(&mut self, payload: &[u8], now: Instant, now_ns: i64) {
        let Some(rt) = self.rt.as_mut() else {
            return;
        };
        let Ok(body) = link::unwrap(payload) else {
            rt.corrupt += 1;
            return;
        };
        if answers(body) {
            rt.last_ack = now_ns;
        }
        let st = stamps_of(body);
        if st.acked {
            rt.delivery.count(st.ack, 0, 1, 0);
        }
        rt.sess.input(body, now);
        self.pump(now_ns);
    }

    /// The session's timer: flushes when due; the next time it is due.
    pub fn update(&mut self, now: Instant, now_ns: i64) -> Option<Instant> {
        let rt = self.rt.as_mut()?;
        if now >= rt.next_update {
            let ms = rt.sess.update(now);
            rt.next_update = now + Duration::from_millis(u64::from(ms.max(1)));
        }
        let next = rt.next_update;
        self.pump(now_ns);
        Some(next)
    }

    /// `kcpRuntime.send`: one message, its length in front, one write.
    ///
    /// # Errors
    /// [`SendError`].
    pub fn send(&mut self, msg: &[u8], now: Instant, now_ns: i64) -> Result<(), SendError> {
        let rt = self.rt.as_mut().ok_or(SendError::Closed)?;
        match message::send(&mut rt.sess, msg, now) {
            Ok(()) => {}
            Err(message::SendError::TooLarge) => return Err(SendError::TooLarge),
            Err(message::SendError::WouldBlock) => return Err(SendError::WouldBlock),
        }
        self.pump(now_ns);
        Ok(())
    }

    /// Whether a send would be taken now.
    #[must_use]
    pub fn writable(&self) -> bool {
        self.rt.as_ref().is_some_and(|rt| rt.sess.writable())
    }

    /// The next whole message, as `readLoop` reads it.
    pub fn read(&mut self) -> Option<Vec<u8>> {
        let rt = self.rt.as_mut()?;
        if rt.read_dead {
            return None;
        }
        match rt.reader.next(&mut rt.sess) {
            Ok(m) => m,
            Err(_) => {
                rt.read_dead = true;
                None
            }
        }
    }

    /// `probe`: the newest push held back, once per hold interval, so the
    /// peer has something to answer while the lane is dark. It waits for no
    /// room.
    pub fn probe(&mut self, now_ns: i64) {
        let Some(rt) = self.rt.as_mut() else {
            return;
        };
        if rt.hold_every == 0 || now_ns < rt.probe_at {
            return;
        }
        rt.probe_at = now_ns + rt.hold_every;
        if rt.probe_buf.is_empty() {
            return;
        }
        let packet = Self::wrap(&mut self.free, &rt.hdr, &rt.probe_buf, now_ns);
        if self.out.len() < self.out_cap {
            self.out.push_back(packet);
        } else {
            self.release(packet.data);
        }
    }

    /// Bytes this plane holds: the queues, the free list and the session.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        let q = |q: &VecDeque<Packet>| q.iter().map(|p| p.data.capacity()).sum::<usize>();
        q(&self.out)
            + self.acks.as_ref().map_or(0, q)
            + self.free.iter().map(Vec::capacity).sum::<usize>()
            + self.rt.as_ref().map_or(0, |rt| {
                rt.sess.held_bytes() + rt.reader.held_bytes() + rt.probe_buf.capacity()
            })
    }

    /// Gives the free buffers back.
    pub fn trim(&mut self) {
        self.free = Vec::new();
        if let Some(rt) = self.rt.as_mut() {
            rt.sess.trim();
        }
    }
}

/// Whether a wrapped packet is longer than a header and its trailer.
#[must_use]
pub fn carries_packet(data: &[u8]) -> bool {
    data.len() > EPOCH_HDR_LEN + WIRE_CRC_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::tests::seg;
    use crate::segment::{CMD_ACK, CMD_PUSH};
    use crate::wire::epoch_header;

    fn plane(with_acks: bool) -> (Plane, Instant) {
        let now = Instant::now();
        let mut p = Plane::new(8, with_acks, KcpConfig::vp8channel_constrained(), now);
        assert!(p.start(epoch_header(7, 1, 2), now));
        assert!(!p.start(epoch_header(7, 1, 2), now), "once");
        (p, now)
    }

    #[test]
    fn a_message_goes_out_wrapped_and_crc_checked() {
        let (mut a, now) = plane(false);
        a.send(b"hello", now, 1).unwrap();
        assert_eq!(a.out.len(), 1);
        let pk = &a.out[0].data;
        assert_eq!(&pk[..EPOCH_HDR_LEN], &epoch_header(7, 1, 2));
        assert_eq!(a.out[0].queued, 1);
        let body = link::unwrap(&pk[EPOCH_HDR_LEN..]).unwrap();
        assert_eq!(body[4], CMD_PUSH);

        let (mut b, _) = plane(false);
        let wire = pk[EPOCH_HDR_LEN..].to_vec();
        let mut bad = wire.clone();
        bad[30] ^= 1;
        b.deliver(&bad, now, 2);
        assert_eq!(b.rt.as_ref().unwrap().corrupt, 1);
        assert_eq!(b.read(), None);
        b.deliver(&wire, now, 3);
        assert_eq!(b.read().as_deref(), Some(&b"hello"[..]));
        // ACK no-delay: the answer is queued at once.
        assert_eq!(b.out.len(), 1);
    }

    #[test]
    fn acknowledgements_take_their_own_queue_on_a_data_plane() {
        let (mut a, now) = plane(true);
        let (mut b, _) = plane(true);
        a.send(b"x", now, 1).unwrap();
        let wire = a.out[0].data[EPOCH_HDR_LEN..].to_vec();
        b.deliver(&wire, now, 2);
        assert_eq!(b.out.len(), 0);
        assert_eq!(b.acks.as_ref().unwrap().len(), 1);
        let ack = &b.acks.as_ref().unwrap()[0].data;
        a.deliver(&ack[EPOCH_HDR_LEN..], now, 9);
        assert_eq!(
            a.rt.as_ref().unwrap().last_ack,
            9,
            "an answer stamps last_ack"
        );
    }

    #[test]
    fn a_full_queue_leaves_the_packet_in_kcp() {
        let (mut a, now) = plane(false);
        for i in 0..20u8 {
            a.send(&[i; 1300], now, 1).unwrap();
        }
        assert_eq!(a.out.len(), 8);
        assert!(a.rt.as_ref().unwrap().sess.output_len() > 0);
        a.out.clear();
        a.pump(2);
        assert_eq!(a.out.len(), 8, "refilled as the writer drains");
    }

    #[test]
    fn a_hold_drops_pushes_keeps_answers_and_probes_once_per_interval() {
        // lane_test.go:256
        let (mut a, now) = plane(true);
        a.rt.as_mut().unwrap().hold(100);
        a.send(b"held", now, 1).unwrap();
        assert!(a.out.is_empty(), "a push is held back");
        a.probe(5);
        assert_eq!(a.out.len(), 1, "the probe is the push held back");
        a.probe(50);
        assert_eq!(a.out.len(), 1, "one per interval");
        a.probe(105);
        assert_eq!(a.out.len(), 2);
        // An acknowledgement is never held.
        let mut ack = seg(CMD_ACK, 1, 0);
        ack[0..4].copy_from_slice(&0xC0FF_EE01u32.to_le_bytes());
        a.rt.as_mut().unwrap().hold(0);
        assert!(!a.rt.as_mut().unwrap().withheld(&ack));
        a.rt.as_mut().unwrap().hold(100);
        assert!(!a.rt.as_mut().unwrap().withheld(&ack));
        assert!(a.rt.as_mut().unwrap().withheld(&seg(CMD_PUSH, 1, 2)));
    }

    #[test]
    fn a_restart_drains_the_queue_and_starts_a_new_session() {
        let (mut a, now) = plane(false);
        a.send(b"old", now, 1).unwrap();
        let id = a.rt.as_ref().unwrap().id;
        a.restart(epoch_header(7, 3, 0), now);
        assert!(a.out.is_empty());
        assert_ne!(a.rt.as_ref().unwrap().id, id);
        a.close(now);
        assert!(a.rt.is_none());
        a.restart(epoch_header(7, 3, 0), now);
        assert!(a.rt.is_none(), "a closed plane stays closed");
        assert_eq!(a.send(b"x", now, 1), Err(SendError::Closed));
    }
}

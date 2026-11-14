// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57 session.go, stream.go and shaper.go,
// Copyright (c) 2016-2017 xtaci, MIT.

//! The session's state, behind one mutex: the streams, the token bucket,
//! the accept queue, the send order and the chunk pool.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Waker};

use crate::arena::{Arena, FrameQueue};
use crate::frame::{encode_upd, Cmd, Header, HEADER_SIZE, INITIAL_PEER_WINDOW, UPD_SIZE};
use crate::{Config, Error};

pub(crate) const NIL: u32 = u32::MAX;

/// Slot 0 is the session's own entry in the send order: sid 0, NOP only
/// (`smux/session.go:528`).
pub(crate) const NOP_SLOT: u32 = 0;

/// Slot flags.
pub(crate) mod flag {
    /// In the sid map: frames from the peer reach it.
    pub const REGISTERED: u16 = 1 << 0;
    /// A `Stream`, an open in progress or the accept queue refers to it.
    pub const HANDLE: u16 = 1 << 1;
    /// The peer's FIN arrived (`chFinEvent`, `smux/stream.go:58,808-813`).
    pub const PEER_FIN: u16 = 1 << 2;
    /// This side sent or queued FIN (`chWriteClosed`, `smux/stream.go:62`).
    pub const WRITE_CLOSED: u16 = 1 << 3;
    /// The stream is dead (`die`, `smux/stream.go:54`).
    pub const DIED: u16 = 1 << 4;
    /// In the send order.
    pub const IN_RR: u16 = 1 << 5;
    pub const SYN_QUEUED: u16 = 1 << 6;
    pub const SYN_FLIGHT: u16 = 1 << 7;
    pub const UPD_QUEUED: u16 = 1 << 8;
    pub const UPD_FLIGHT: u16 = 1 << 9;
    /// Waiting for session send room.
    pub const ROOM_WAIT: u16 = 1 << 10;
    /// Slot 0 only: a NOP is queued.
    pub const NOP_QUEUED: u16 = 1 << 11;

    pub const PENDING: u16 = SYN_QUEUED | UPD_QUEUED | NOP_QUEUED;
    pub const KEEP: u16 =
        REGISTERED | HANDLE | IN_RR | SYN_QUEUED | SYN_FLIGHT | UPD_QUEUED | UPD_FLIGHT;
}

/// What one side of a session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Opens odd stream ids from 3 (`smux/session.go:153-154,189`).
    Client,
    /// Opens even stream ids from 2 (`smux/session.go:155-156,189`).
    Server,
}

/// One stream's state. Go's `stream` (`smux/stream.go:40-79`) less the
/// channels: wakers stand in for them.
#[derive(Debug)]
pub(crate) struct Slot {
    pub sid: u32,
    pub flags: u16,
    /// Received frames not yet read.
    pub rx: FrameQueue,
    /// PSH frames and FIN markers (length 0) not yet handed to the driver.
    pub tx: FrameQueue,
    /// Unread payload bytes in `rx`; their tokens are out of the bucket.
    pub rx_payload: u32,
    pub peak_rx: u32,
    /// Payload queued or being written.
    pub tx_payload: u32,
    /// PSH and FIN frames queued or being written.
    pub tx_frames: u32,
    /// `numRead`, `incr`, `numWritten`, `peerConsumed`, `peerWindow`
    /// (`smux/stream.go:70-76`), all modulo 2^32 as in Go.
    pub num_read: u32,
    pub incr: u32,
    pub num_written: u32,
    pub peer_consumed: u32,
    pub peer_window: u32,
    /// The consumed count of the queued UPD.
    pub upd_consumed: u32,
    pub rr_prev: u32,
    pub rr_next: u32,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
}

impl Slot {
    fn new(sid: u32, flags: u16) -> Slot {
        Slot {
            sid,
            flags,
            rx: FrameQueue::default(),
            tx: FrameQueue::default(),
            rx_payload: 0,
            peak_rx: 0,
            tx_payload: 0,
            tx_frames: 0,
            num_read: 0,
            incr: 0,
            num_written: 0,
            peer_consumed: 0,
            // smux/stream.go:190
            peer_window: INITIAL_PEER_WINDOW,
            upd_consumed: 0,
            rr_prev: NIL,
            rr_next: NIL,
            read_waker: None,
            write_waker: None,
        }
    }

    pub fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }

    pub fn set(&mut self, f: u16) {
        self.flags |= f;
    }

    pub fn clear(&mut self, f: u16) {
        self.flags &= !f;
    }

    fn has_pending(&self) -> bool {
        self.has(flag::PENDING) || !self.tx.is_empty()
    }

    pub fn wake_read(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
    }

    pub fn wake_write(&mut self) {
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

pub(crate) fn set_waker(slot: &mut Option<Waker>, cx: &Context<'_>) {
    match slot {
        Some(w) if w.will_wake(cx.waker()) => {}
        _ => *slot = Some(cx.waker().clone()),
    }
}

fn add_waker(list: &mut Vec<Waker>, cx: &Context<'_>) {
    if !list.iter().any(|w| w.will_wake(cx.waker())) {
        list.push(cx.waker().clone());
    }
}

/// What the driver is writing.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Nop,
    Syn,
    Upd,
    Psh(u32),
    Fin,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct InFlight {
    pub slot: u32,
    pub kind: Kind,
    pub wire_len: usize,
}

/// Counters for [`Stats`](crate::Stats).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counters {
    pub peak_rx: usize,
    pub peak_tx: usize,
    pub frames_in: u64,
    pub frames_out: u64,
    pub nop_in: u64,
    pub nop_out: u64,
    pub upd_in: u64,
    pub upd_out: u64,
    pub read_buffer: usize,
    pub write_buffer: usize,
}

#[derive(Debug)]
pub(crate) struct State {
    /// `die` (`smux/session.go:107`).
    pub closed: bool,
    /// Why the session closed: `None` for `Session::close` or the last
    /// handle, `Timeout` for the keepalive.
    pub close_reason: Option<Error>,
    /// `socketReadError`, `socketWriteError`, `protoError`
    /// (`smux/session.go:112-122`).
    pub read_err: Option<Error>,
    pub write_err: Option<Error>,
    pub proto_err: bool,
    pub go_away: bool,
    pub next_sid: u32,
    /// The token bucket (`smux/session.go:101,143`), in payload bytes.
    pub bucket: i64,
    pub slots: Vec<Option<Slot>>,
    free_slots: Vec<u32>,
    pub sids: HashMap<u32, u32>,
    pub accept_q: VecDeque<u32>,
    accept_wakers: Vec<Waker>,
    closed_wakers: Vec<Waker>,
    pub driver_waker: Option<Waker>,
    rr_head: u32,
    rr_tail: u32,
    rr_next: u32,
    pub arena: Arena,
    /// Payload queued to send, all streams.
    pub tx_total: usize,
    /// Payload received and unread, all streams; `max_receive_buffer - bucket`.
    pub rx_total: usize,
    room_q: VecDeque<u32>,
    pub session_handles: usize,
    pub stream_handles: usize,
    /// `sessionIsActive` (`smux/session.go:126,410`).
    pub active: bool,
    /// The driver stopped reading for tokens or accept room.
    pub read_paused: bool,
    pub counters: Counters,
}

impl State {
    pub(crate) fn new(cfg: &Config, role: Role) -> State {
        let mut slots = Vec::with_capacity(8);
        slots.push(Some(Slot::new(0, 0)));
        State {
            closed: false,
            close_reason: None,
            read_err: None,
            write_err: None,
            proto_err: false,
            go_away: false,
            next_sid: match role {
                Role::Client => 1,
                Role::Server => 0,
            },
            bucket: cfg.max_receive_buffer as i64,
            slots,
            free_slots: Vec::new(),
            sids: HashMap::new(),
            accept_q: VecDeque::new(),
            accept_wakers: Vec::new(),
            closed_wakers: Vec::new(),
            driver_waker: None,
            rr_head: NIL,
            rr_tail: NIL,
            rr_next: NIL,
            arena: Arena::new(cfg.pool_retain_bytes),
            tx_total: 0,
            rx_total: 0,
            room_q: VecDeque::new(),
            session_handles: 1,
            stream_handles: 0,
            active: false,
            read_paused: false,
            counters: Counters::default(),
        }
    }

    pub(crate) fn slot(&self, idx: u32) -> &Slot {
        self.slots[idx as usize].as_ref().expect("live slot")
    }

    pub(crate) fn slot_mut(&mut self, idx: u32) -> &mut Slot {
        self.slots[idx as usize].as_mut().expect("live slot")
    }

    pub(crate) fn wake_driver(&self) {
        if let Some(w) = &self.driver_waker {
            w.wake_by_ref();
        }
    }

    pub(crate) fn add_accept_waker(&mut self, cx: &Context<'_>) {
        add_waker(&mut self.accept_wakers, cx);
    }

    pub(crate) fn add_closed_waker(&mut self, cx: &Context<'_>) {
        add_waker(&mut self.closed_wakers, cx);
    }

    fn wake_acceptors(&mut self) {
        for w in self.accept_wakers.drain(..) {
            w.wake();
        }
    }

    pub(crate) fn alloc_slot(&mut self, sid: u32, flags: u16) -> u32 {
        let slot = Slot::new(sid, flags);
        if let Some(idx) = self.free_slots.pop() {
            self.slots[idx as usize] = Some(slot);
            idx
        } else {
            self.slots.push(Some(slot));
            (self.slots.len() - 1) as u32
        }
    }

    /// Puts a slot in the sid map. A sid already there is replaced, as Go's
    /// map assignment does (`smux/session.go:209`).
    pub(crate) fn register(&mut self, idx: u32) {
        let sid = self.slot(idx).sid;
        if let Some(old) = self.sids.insert(sid, idx) {
            if old != idx {
                self.slot_mut(old).clear(flag::REGISTERED);
            }
        }
        self.slot_mut(idx).set(flag::REGISTERED);
    }

    /// Takes a slot out of the sid map: later frames for its sid are
    /// dropped (`smux/session.go:373`).
    pub(crate) fn unregister(&mut self, idx: u32) {
        let s = self.slot_mut(idx);
        if !s.has(flag::REGISTERED) {
            return;
        }
        s.clear(flag::REGISTERED);
        let sid = s.sid;
        if self.sids.get(&sid) == Some(&idx) {
            self.sids.remove(&sid);
        }
    }

    /// Frees a slot nothing refers to any more, giving back its tokens.
    pub(crate) fn free_if_done(&mut self, idx: u32) {
        if idx == NOP_SLOT {
            return;
        }
        let Some(s) = self.slots[idx as usize].as_ref() else {
            return;
        };
        if s.has(flag::KEEP) || s.tx_frames != 0 {
            return;
        }
        self.drop_rx(idx);
        let Some(mut s) = self.slots[idx as usize].take() else {
            return;
        };
        s.tx.clear(&mut self.arena);
        self.free_slots.push(idx);
    }

    /// Drops a stream's unread data and returns its tokens: Go's
    /// `recycleTokens` (`smux/session.go:367-372`, `smux/stream.go:767-776`).
    pub(crate) fn drop_rx(&mut self, idx: u32) {
        let State { slots, arena, .. } = self;
        let s = slots[idx as usize].as_mut().expect("live slot");
        let n = s.rx_payload as usize;
        s.rx.clear(arena);
        s.rx_payload = 0;
        if n > 0 {
            self.return_tokens(n);
        }
    }

    /// `returnTokens` (`smux/session.go:377-381`): when the bucket is
    /// positive again, the driver reads again.
    pub(crate) fn return_tokens(&mut self, n: usize) {
        self.bucket += n as i64;
        self.rx_total -= n;
        if self.bucket > 0 && self.read_paused {
            self.read_paused = false;
            self.wake_driver();
        }
    }

    // --- The send order: shaperQueue (smux/shaper.go:66-172). ---------

    /// Adds a slot to the send order: at the back of the list, and the next
    /// to serve if the list was empty (`smux/shaper.go:95-106`).
    pub(crate) fn push_rr(&mut self, idx: u32) {
        let tail = self.rr_tail;
        let s = self.slot_mut(idx);
        if s.has(flag::IN_RR) {
            return;
        }
        s.set(flag::IN_RR);
        s.rr_prev = tail;
        s.rr_next = NIL;
        if tail == NIL {
            self.rr_head = idx;
        } else {
            self.slot_mut(tail).rr_next = idx;
        }
        self.rr_tail = idx;
        if self.rr_next == NIL {
            self.rr_next = idx;
            self.wake_driver();
        }
    }

    fn unlink_rr(&mut self, idx: u32) {
        let s = self.slot_mut(idx);
        if !s.has(flag::IN_RR) {
            return;
        }
        s.clear(flag::IN_RR);
        let (p, n) = (s.rr_prev, s.rr_next);
        s.rr_prev = NIL;
        s.rr_next = NIL;
        if p == NIL {
            self.rr_head = n;
        } else {
            self.slot_mut(p).rr_next = n;
        }
        if n == NIL {
            self.rr_tail = p;
        } else {
            self.slot_mut(n).rr_prev = p;
        }
        if self.rr_next == idx {
            self.rr_next = if n == NIL { self.rr_head } else { n };
        }
    }

    pub(crate) fn rr_is_empty(&self) -> bool {
        self.rr_next == NIL
    }

    /// The next frame to write, into `out` (at least `HEADER_SIZE +
    /// max_frame_size` bytes): `shaperQueue.Pop` (`smux/shaper.go:115-172`).
    /// Each stream's own frames go control first (SYN, then UPD), then data
    /// in order, as its heap orders them (`smux/shaper.go:47-52`); streams
    /// take turns, one frame each.
    pub(crate) fn pop_frame(&mut self, cfg: &Config, out: &mut [u8]) -> Option<InFlight> {
        if self.rr_next == NIL {
            return None;
        }
        let cur = self.rr_next;
        let State { slots, arena, .. } = self;
        let s = slots[cur as usize].as_mut().expect("live slot");
        let (kind, wire_len) = if cur == NOP_SLOT {
            s.clear(flag::NOP_QUEUED);
            out[..HEADER_SIZE].copy_from_slice(&Header::new(Cmd::Nop, 0, 0).encode());
            (Kind::Nop, HEADER_SIZE)
        } else if s.has(flag::SYN_QUEUED) {
            s.clear(flag::SYN_QUEUED);
            s.set(flag::SYN_FLIGHT);
            out[..HEADER_SIZE].copy_from_slice(&Header::new(Cmd::Syn, 0, s.sid).encode());
            (Kind::Syn, HEADER_SIZE)
        } else if s.has(flag::UPD_QUEUED) {
            s.clear(flag::UPD_QUEUED);
            s.set(flag::UPD_FLIGHT);
            out[..HEADER_SIZE]
                .copy_from_slice(&Header::new(Cmd::Upd, UPD_SIZE as u16, s.sid).encode());
            // smux/stream.go:421-425: consumed, then this side's MaxStreamBuffer.
            out[HEADER_SIZE..HEADER_SIZE + UPD_SIZE]
                .copy_from_slice(&encode_upd(s.upd_consumed, cfg.max_stream_buffer as u32));
            (Kind::Upd, HEADER_SIZE + UPD_SIZE)
        } else {
            let n =
                s.tx.pop_frame(arena, &mut out[HEADER_SIZE..])
                    .expect("a slot in the send order has a frame");
            if n == 0 {
                out[..HEADER_SIZE].copy_from_slice(&Header::new(Cmd::Fin, 0, s.sid).encode());
                (Kind::Fin, HEADER_SIZE)
            } else {
                out[..HEADER_SIZE]
                    .copy_from_slice(&Header::new(Cmd::Psh, n as u16, s.sid).encode());
                (Kind::Psh(n as u32), HEADER_SIZE + n)
            }
        };
        let pending = s.has_pending();
        let next = s.rr_next;
        self.rr_next = if next == NIL { self.rr_head } else { next };
        if !pending {
            self.unlink_rr(cur);
        }
        Some(InFlight {
            slot: cur,
            kind,
            wire_len,
        })
    }

    /// The driver wrote a frame: `sendLoop`'s result (`smux/session.go:647-652`)
    /// reaches whoever waits for it.
    pub(crate) fn frame_written(&mut self, f: InFlight) {
        if self.closed {
            return;
        }
        self.counters.frames_out += 1;
        let s = self.slot_mut(f.slot);
        match f.kind {
            Kind::Nop => self.counters.nop_out += 1,
            Kind::Syn => {
                s.clear(flag::SYN_FLIGHT);
                s.wake_write();
            }
            Kind::Upd => {
                s.clear(flag::UPD_FLIGHT);
                s.wake_read();
                self.counters.upd_out += 1;
            }
            Kind::Psh(n) => {
                s.tx_frames -= 1;
                s.tx_payload -= n;
                s.wake_write();
                self.tx_total -= n as usize;
                self.wake_room();
            }
            Kind::Fin => {
                s.tx_frames -= 1;
                s.wake_write();
            }
        }
        self.free_if_done(f.slot);
        if self.session_handles == 0 && self.stream_handles == 0 {
            self.wake_driver();
        }
    }

    pub(crate) fn queue_nop(&mut self) {
        let s = self.slot_mut(NOP_SLOT);
        if s.has(flag::NOP_QUEUED) {
            return;
        }
        s.set(flag::NOP_QUEUED);
        self.push_rr(NOP_SLOT);
    }

    pub(crate) fn queue_upd(&mut self, idx: u32, consumed: u32) {
        let s = self.slot_mut(idx);
        s.upd_consumed = consumed;
        s.set(flag::UPD_QUEUED);
        self.push_rr(idx);
    }

    /// Queues one PSH frame, or a FIN marker for an empty `data`.
    pub(crate) fn queue_data(&mut self, idx: u32, data: &[u8]) {
        let State { slots, arena, .. } = self;
        let s = slots[idx as usize].as_mut().expect("live slot");
        s.tx.push(arena, data);
        s.tx_frames += 1;
        s.tx_payload += data.len() as u32;
        self.tx_total += data.len();
        self.counters.peak_tx = self.counters.peak_tx.max(self.tx_total);
        self.push_rr(idx);
    }

    pub(crate) fn wait_room(&mut self, idx: u32, cx: &Context<'_>) {
        let s = self.slot_mut(idx);
        set_waker(&mut s.write_waker, cx);
        if !s.has(flag::ROOM_WAIT) {
            s.set(flag::ROOM_WAIT);
            self.room_q.push_back(idx);
        }
    }

    /// Wakes every writer waiting for session send room, oldest first.
    fn wake_room(&mut self) {
        while let Some(idx) = self.room_q.pop_front() {
            if let Some(Some(s)) = self.slots.get_mut(idx as usize) {
                if s.has(flag::ROOM_WAIT) {
                    s.clear(flag::ROOM_WAIT);
                    s.wake_write();
                }
            }
        }
    }

    // --- Frames from the peer: recvLoop (smux/session.go:418-515). -----

    /// Whether the driver may take the next frame off the connection: Go
    /// reads a header only while the bucket is positive
    /// (`smux/session.go:390-399`), and its reader blocks while one stream
    /// more than the accept backlog waits (`smux/session.go:142,440-445`: the
    /// stream is registered, then the push to the full channel blocks).
    pub(crate) fn may_read(&mut self, cfg: &Config) -> bool {
        if self.bucket <= 0 || self.accept_q.len() > cfg.accept_backlog {
            self.read_paused = true;
            false
        } else {
            true
        }
    }

    /// Acts on one validated frame.
    pub(crate) fn on_frame(&mut self, cmd: Cmd, sid: u32, payload: &[u8]) {
        self.counters.frames_in += 1;
        match cmd {
            Cmd::Nop => self.counters.nop_in += 1,
            // smux/session.go:426-445: a SYN for a sid in use is ignored.
            Cmd::Syn => {
                if !self.sids.contains_key(&sid) {
                    let idx = self.alloc_slot(sid, flag::HANDLE);
                    self.register(idx);
                    self.accept_q.push_back(idx);
                    self.wake_acceptors();
                }
            }
            // smux/session.go:447-457, smux/stream.go:808-813.
            Cmd::Fin => {
                if let Some(&idx) = self.sids.get(&sid) {
                    let s = self.slot_mut(idx);
                    s.set(flag::PEER_FIN);
                    s.wake_read();
                    self.try_half_close_cleanup(idx);
                }
            }
            // smux/session.go:459-486: data for a stream that is gone is
            // dropped and takes no tokens.
            Cmd::Psh => {
                if let Some(&idx) = self.sids.get(&sid) {
                    let n = payload.len();
                    let State {
                        slots,
                        arena,
                        counters,
                        bucket,
                        rx_total,
                        ..
                    } = self;
                    let s = slots[idx as usize].as_mut().expect("live slot");
                    s.rx.push(arena, payload);
                    s.rx_payload += n as u32;
                    s.peak_rx = s.peak_rx.max(s.rx_payload);
                    s.wake_read();
                    *bucket -= n as i64;
                    *rx_total += n;
                    counters.peak_rx = counters.peak_rx.max(*rx_total);
                }
            }
            // smux/session.go:488-510, smux/stream.go:795-805.
            Cmd::Upd => {
                self.counters.upd_in += 1;
                if let Some(&idx) = self.sids.get(&sid) {
                    let (consumed, window) = crate::frame::decode_upd(
                        payload.try_into().expect("UPD payload is 8 bytes"),
                    );
                    let s = self.slot_mut(idx);
                    s.peer_consumed = consumed;
                    s.peer_window = window;
                    s.wake_write();
                }
            }
        }
    }

    // --- Stream closing (smux/stream.go:644-697,808-833). --------------

    /// `tryHalfCloseCleanup`: once both FINs are out the stream dies and
    /// leaves the sid map. Go also drops its unread data here
    /// (`smux/session.go:367-373`); this port keeps it for the reader.
    pub(crate) fn try_half_close_cleanup(&mut self, idx: u32) {
        let s = self.slot_mut(idx);
        if s.has(flag::PEER_FIN) && s.has(flag::WRITE_CLOSED) {
            s.set(flag::DIED);
            s.wake_read();
            s.wake_write();
            self.unregister(idx);
        }
    }

    /// Go's `Close` up to the FIN: `ErrClosedPipe` if the stream is already
    /// dead; otherwise it dies, its unread data goes, and a FIN is queued
    /// after whatever data it has queued, even after `CloseWrite` sent one.
    pub(crate) fn close_stream(&mut self, idx: u32) -> Result<(), Error> {
        let s = self.slot_mut(idx);
        if s.has(flag::DIED) {
            return Err(Error::ClosedPipe);
        }
        s.set(flag::DIED | flag::WRITE_CLOSED);
        s.wake_read();
        s.wake_write();
        self.unregister(idx);
        self.drop_rx(idx);
        if self.closed {
            return Err(Error::ClosedPipe);
        }
        if let Some(e) = &self.write_err {
            return Err(e.clone());
        }
        self.queue_data(idx, &[]);
        Ok(())
    }

    /// Go's `CloseWrite` up to the FIN.
    pub(crate) fn close_write(&mut self, idx: u32) -> Result<(), Error> {
        let s = self.slot_mut(idx);
        if s.has(flag::WRITE_CLOSED) {
            return Err(Error::ClosedPipe);
        }
        s.set(flag::WRITE_CLOSED);
        s.wake_write();
        if self.closed {
            return Err(Error::ClosedPipe);
        }
        if let Some(e) = &self.write_err {
            return Err(e.clone());
        }
        self.queue_data(idx, &[]);
        self.try_half_close_cleanup(idx);
        Ok(())
    }

    /// A `Stream` handle went away: Go's finalizer `Close`
    /// (`smux/session.go:239-241`) without the wait.
    pub(crate) fn drop_handle(&mut self, idx: u32) {
        if !self.slot(idx).has(flag::DIED) {
            let _ = self.close_stream(idx);
        }
        let s = self.slot_mut(idx);
        s.clear(flag::HANDLE);
        s.read_waker = None;
        s.write_waker = None;
        self.drop_rx(idx);
        self.stream_handles -= 1;
        self.free_if_done(idx);
        if self.stream_handles == 0 && self.session_handles == 0 {
            self.wake_driver();
        }
    }

    /// An open gave up before its stream was handed out.
    pub(crate) fn cancel_open(&mut self, idx: u32) {
        let s = self.slot_mut(idx);
        if s.has(flag::SYN_QUEUED) {
            // The SYN never left: forget the stream.
            s.clear(flag::SYN_QUEUED | flag::HANDLE);
            s.flags |= flag::DIED | flag::WRITE_CLOSED;
            if !s.has_pending() {
                self.unlink_rr(idx);
            }
            self.unregister(idx);
            self.free_if_done(idx);
        } else {
            // The peer has the stream (or will): close it.
            if !self.slot(idx).has(flag::DIED) {
                let _ = self.close_stream(idx);
            }
            self.slot_mut(idx).clear(flag::HANDLE);
            self.free_if_done(idx);
        }
    }

    // --- Session end. ---------------------------------------------------

    /// Go's `Session.Close` (`smux/session.go:260-278`): every stream dies,
    /// nothing more is written, the connection goes.
    pub(crate) fn close_session(&mut self, reason: Option<Error>) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        self.close_reason = reason;
        self.sids.clear();
        self.rr_head = NIL;
        self.rr_tail = NIL;
        self.rr_next = NIL;
        self.tx_total = 0;
        let State { slots, arena, .. } = self;
        for (i, s) in slots.iter_mut().enumerate() {
            let Some(s) = s.as_mut() else {
                continue;
            };
            if i as u32 != NOP_SLOT {
                s.set(flag::DIED);
            }
            s.clear(
                flag::REGISTERED
                    | flag::IN_RR
                    | flag::SYN_QUEUED
                    | flag::SYN_FLIGHT
                    | flag::UPD_QUEUED
                    | flag::UPD_FLIGHT
                    | flag::NOP_QUEUED
                    | flag::ROOM_WAIT,
            );
            s.rr_prev = NIL;
            s.rr_next = NIL;
            s.tx.clear(arena);
            s.tx_payload = 0;
            s.tx_frames = 0;
            s.wake_read();
            s.wake_write();
        }
        self.room_q.clear();
        while let Some(idx) = self.accept_q.pop_front() {
            self.slot_mut(idx).clear(flag::HANDLE);
            self.free_if_done(idx);
        }
        for i in 1..self.slots.len() {
            self.free_if_done(i as u32);
        }
        self.wake_acceptors();
        for w in self.closed_wakers.drain(..) {
            w.wake();
        }
        self.wake_driver();
        true
    }

    /// `notifyWriteError` (`smux/session.go:301-306`): the send side is
    /// gone; everyone waiting for a frame to be written gets the error.
    pub(crate) fn fail_write(&mut self, err: Error) {
        if self.write_err.is_none() {
            self.write_err = Some(err);
        }
        self.rr_head = NIL;
        self.rr_tail = NIL;
        self.rr_next = NIL;
        self.tx_total = 0;
        let State { slots, arena, .. } = self;
        for s in slots.iter_mut().flatten() {
            s.clear(
                flag::IN_RR
                    | flag::SYN_QUEUED
                    | flag::SYN_FLIGHT
                    | flag::UPD_QUEUED
                    | flag::UPD_FLIGHT
                    | flag::NOP_QUEUED
                    | flag::ROOM_WAIT,
            );
            s.rr_prev = NIL;
            s.rr_next = NIL;
            s.tx.clear(arena);
            s.tx_payload = 0;
            s.tx_frames = 0;
            s.wake_read();
            s.wake_write();
        }
        self.room_q.clear();
        for i in 1..self.slots.len() {
            self.free_if_done(i as u32);
        }
    }

    /// `notifyReadError` and `notifyProtoError` (`smux/session.go:294-313`):
    /// readers and acceptors get the error.
    pub(crate) fn fail_read(&mut self, err: Option<Error>) {
        match err {
            Some(e) => {
                if self.read_err.is_none() {
                    self.read_err = Some(e);
                }
            }
            None => self.proto_err = true,
        }
        for s in self.slots.iter_mut().flatten() {
            s.wake_read();
        }
        self.wake_acceptors();
    }

    /// Releases the pool's spare chunks once nothing is buffered.
    pub(crate) fn trim_pool(&mut self) {
        if self.arena.in_use() == 0 {
            self.arena.release_pool();
        }
    }
}

/// What every handle shares.
#[derive(Debug)]
pub(crate) struct Shared {
    pub cfg: Config,
    pub role: Role,
    state: Mutex<State>,
}

impl Shared {
    pub(crate) fn new(cfg: Config, role: Role) -> Shared {
        let state = State::new(&cfg, role);
        Shared {
            cfg,
            role,
            state: Mutex::new(state),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock leaves the state as it was at the
        // panic; keep going rather than poison every handle.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

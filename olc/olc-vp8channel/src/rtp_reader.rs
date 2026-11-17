// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The remote track's reader (W36, W37): `rtp_reader.go`, the VP9
//! assembler of `carrier.go` and `common/red.go` at 2d4266af, with pion's
//! payload descriptor parsers (`rtp@v1.10.2/codecs/vp8_packet.go:121-219`,
//! `vp9_packet.go:253-504`) where the assemblers lean on them.
//!
//! The WebRTC stack hands each RTP packet's sequence number, marker, payload
//! type and payload to [`TrackReader::push`]; RED is unwrapped first, a
//! reorder buffer restores sequence order (a gap is given up after 256
//! packets behind it or 300 ms), and the carrier's assembler turns the
//! ordered packets into frames in the transport's layout for
//! [`crate::Channel::handle_incoming_frame`].
//!
//! Memory, where Go has a collector: every buffer here is allocated at a
//! size that is its bound, never by a vector's doubling, so what a reader
//! holds is at most [`READER_HELD`] **in capacities** (while its owner
//! gives it no payload over [`MAX_RETAINED_PAYLOAD`]); a frame buffer over
//! [`FRAME_KEPT`] is released when its frame was read or dropped, and the
//! packet buffers a gap needed are released when it is over
//! ([`READER_IDLE`] is what stays).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::channel::Carrier;
use crate::vp9;
use crate::wire::{EPOCH_HDR_LEN, MAX_PAYLOAD_SIZE};

/// `reorderWindow`: packets held behind a gap before it is given up.
pub const REORDER_WINDOW: usize = 256;
/// `reorderHold`: how long a gap may hold packets back.
pub const REORDER_HOLD: Duration = Duration::from_millis(300);
/// `maxRetainedRTPPayloadCap`: a payload buffer larger than this is not
/// kept for reuse.
pub const MAX_RETAINED_PAYLOAD: usize = 2 * 1024;
/// `maxAssembledFrameSize`: a frame that grows past this is dropped.
pub const MAX_ASSEMBLED_FRAME: usize = 4 * MAX_PAYLOAD_SIZE;
/// Packet buffers the reorder buffer's free list keeps once nothing waits
/// behind a gap; the others are released (Go leaves them to its collector).
pub const FREE_KEPT: usize = 8;
/// The largest frame buffer an assembler keeps between two frames. The
/// transport's own frame fits (a sample of [`MAX_PAYLOAD_SIZE`] at most,
/// and its VP9 dress), so its reader allocates nothing per frame; a larger
/// one (another publisher's video) is released once the frame is handed
/// out or dropped.
pub const FRAME_KEPT: usize = MAX_PAYLOAD_SIZE + 4 * 1024;
/// An assembler's first allocation for a frame; it doubles from there, up
/// to [`MAX_ASSEMBLED_FRAME`] and no further.
const FRAME_FIRST: usize = 4 * 1024;
/// What a reorder buffer's allocations hold at most, **in capacities**,
/// while no payload it is given is longer than [`MAX_RETAINED_PAYLOAD`]
/// (the carriers drop a longer one before their readers): the buffer of
/// every packet of a full window and of the one that gives its gap up,
/// held or free, and the two lists (held, free) at that many slots each.
pub const REORDER_HELD: usize =
    (REORDER_WINDOW + 1) * (MAX_RETAINED_PAYLOAD + 2 * size_of::<Received>());
/// What a reorder buffer keeps once nothing waits behind a gap:
/// [`FREE_KEPT`] buffers, and the lists at that many slots.
pub const REORDER_IDLE: usize = FREE_KEPT * (MAX_RETAINED_PAYLOAD + 2 * size_of::<Received>());
/// What one [`TrackReader`] holds at most, in capacities, under the same
/// condition: its reorder buffer full and a frame at the bound being built.
pub const READER_HELD: usize = REORDER_HELD + MAX_ASSEMBLED_FRAME;
/// What a [`TrackReader`] keeps between frames with nothing behind a gap.
pub const READER_IDLE: usize = REORDER_IDLE + FRAME_KEPT;
/// `rtpBufSize`: pion's receive MTU, the largest packet the reader reads.
pub const RTP_BUF_SIZE: usize = 8192;
/// `mimeTypeRED`.
pub const MIME_RED: &str = "video/red";
/// `webrtc.MimeTypeVP8`.
pub const MIME_VP8: &str = "video/VP8";
/// `webrtc.MimeTypeVP9`.
pub const MIME_VP9: &str = "video/VP9";

/// `seqLess`: `a` precedes `b` in RFC 1982 serial order.
#[must_use]
pub fn seq_less(a: u16, b: u16) -> bool {
    a.wrapping_sub(b) & 0x8000 != 0
}

/// `ErrREDHeader`: a RED payload whose block headers do not fit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("common: malformed RED header")]
pub struct RedHeaderError;

/// `common.REDPrimary`: the payload type and data of a RED (RFC 2198)
/// payload's primary block. Block headers come first, four bytes while F is
/// set and one for the primary, then the redundant blocks' data, then the
/// primary's.
///
/// # Errors
/// [`RedHeaderError`] when the headers run past the payload.
pub fn red_primary(payload: &[u8]) -> Result<(u8, &[u8]), RedHeaderError> {
    let (mut offset, mut skip) = (0usize, 0usize);
    loop {
        let Some(&b) = payload.get(offset) else {
            return Err(RedHeaderError);
        };
        if b & 0x80 == 0 {
            offset += 1;
            break;
        }
        if offset + 4 > payload.len() {
            return Err(RedHeaderError);
        }
        let high = usize::from(payload[offset + 2] & 0x03);
        skip += high << 8 | usize::from(payload[offset + 3]);
        offset += 4;
    }
    let primary_type = payload[offset - 1] & 0x7f;
    let start = offset + skip;
    if start > payload.len() {
        return Err(RedHeaderError);
    }
    Ok((primary_type, &payload[start..]))
}

/// How many more slots a list of `len` whose capacity is spent reserves:
/// the lists of a reorder buffer have two sizes, [`FREE_KEPT`] and the
/// window and one, and never a vector's doubling.
fn more_slots(len: usize) -> usize {
    if len < FREE_KEPT {
        FREE_KEPT - len
    } else {
        (REORDER_WINDOW + 1).saturating_sub(len).max(1)
    }
}

/// One received RTP packet as the reorder buffer holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Received {
    /// Sequence number.
    pub seq: u16,
    /// The marker bit.
    pub marker: bool,
    /// Payload type (the RED primary's, once unwrapped).
    pub payload_type: u8,
    /// The payload, descriptor first.
    pub payload: Vec<u8>,
}

/// `reorderBuffer`: restores sequence order before assembly, so an SFU's
/// reordering is not taken for loss (olcrtc#95).
#[derive(Debug, Default)]
pub struct ReorderBuffer {
    /// The packets behind a gap, in sequence order. Go keeps a map by
    /// sequence number; a hash table's size follows its history of removals
    /// (it may double with half its slots free), so here they are a list:
    /// each is ahead of `next_seq` by less than half the number space (an
    /// older one is dropped on arrival), so their order is their distance
    /// from it, and stays when it moves up to the oldest of them.
    pkts: VecDeque<Received>,
    free: Vec<Received>,
    next_seq: u16,
    started: bool,
    gap_since: Option<Instant>,
}

impl ReorderBuffer {
    /// `newReorderBuffer`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next sequence number it delivers.
    #[must_use]
    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// Packets held behind a gap.
    #[must_use]
    pub fn held(&self) -> usize {
        self.pkts.len()
    }

    /// The bytes its allocations hold, in capacities: the payload buffers
    /// (held and free) and the two lists.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        let payloads: usize = self
            .pkts
            .iter()
            .chain(&self.free)
            .map(|p| p.payload.capacity())
            .sum();
        payloads + (self.pkts.capacity() + self.free.capacity()) * size_of::<Received>()
    }

    /// `push`: holds the packet (a copy) and delivers, in order, every packet
    /// that is now next. One older than the position is dropped; a full
    /// window or a gap older than [`REORDER_HOLD`] skips to the oldest held.
    pub fn push(
        &mut self,
        seq: u16,
        marker: bool,
        payload_type: u8,
        payload: &[u8],
        now: Instant,
        deliver: &mut dyn FnMut(&Received),
    ) {
        if !self.started {
            self.started = true;
            self.next_seq = seq;
        }
        if seq_less(seq, self.next_seq) {
            return;
        }
        let mut pkt = self.free.pop().unwrap_or_default();
        pkt.seq = seq;
        pkt.marker = marker;
        pkt.payload_type = payload_type;
        pkt.payload.clear();
        if pkt.payload.capacity() < payload.len() {
            // A buffer of the size every kept one has, whatever this
            // payload's length: one that grew to fit would have twice the
            // capacity of the last (a vector's rule) and be kept. A longer
            // payload gets its own length and is not kept.
            pkt.payload = Vec::with_capacity(payload.len().max(MAX_RETAINED_PAYLOAD));
        }
        pkt.payload.extend_from_slice(payload);
        let next = self.next_seq;
        let ahead = |s: u16| s.wrapping_sub(next);
        let place = self
            .pkts
            .binary_search_by_key(&ahead(seq), |p| ahead(p.seq));
        match place {
            // The same number again: the later copy takes its place.
            Ok(i) => {
                let old = std::mem::replace(&mut self.pkts[i], pkt);
                self.recycle(old);
            }
            Err(i) => {
                if self.pkts.len() == self.pkts.capacity() {
                    self.pkts.reserve_exact(more_slots(self.pkts.len()));
                }
                self.pkts.insert(i, pkt);
            }
        }
        let aged = self
            .gap_since
            .is_some_and(|since| now.saturating_duration_since(since) > REORDER_HOLD);
        if self.pkts.len() > REORDER_WINDOW || aged {
            self.skip_to_oldest();
            self.gap_since = None;
        }
        self.drain(deliver);
        if self.pkts.is_empty() {
            self.gap_since = None;
            self.trim();
        } else if self.gap_since.is_none() {
            self.gap_since = Some(now);
        }
    }

    fn drain(&mut self, deliver: &mut dyn FnMut(&Received)) {
        while self.pkts.front().is_some_and(|p| p.seq == self.next_seq) {
            let Some(pkt) = self.pkts.pop_front() else {
                break;
            };
            self.next_seq = self.next_seq.wrapping_add(1);
            deliver(&pkt);
            self.recycle(pkt);
        }
    }

    fn recycle(&mut self, mut pkt: Received) {
        if pkt.payload.capacity() > MAX_RETAINED_PAYLOAD {
            pkt.payload = Vec::new();
        } else {
            pkt.payload.clear();
        }
        // Go's free list grows to the window at most (every packet it holds
        // came from it or was made new while it was empty).
        if self.free.len() <= REORDER_WINDOW {
            if self.free.len() == self.free.capacity() {
                self.free.reserve_exact(more_slots(self.free.len()));
            }
            self.free.push(pkt);
        }
    }

    /// Nothing waits behind a gap: the buffers the gap needed go, all but
    /// [`FREE_KEPT`], and both lists go back to that many slots.
    fn trim(&mut self) {
        if self.free.len() > FREE_KEPT {
            self.free.truncate(FREE_KEPT);
        }
        if self.free.capacity() > FREE_KEPT {
            self.free.shrink_to(FREE_KEPT);
        }
        if self.pkts.capacity() > FREE_KEPT {
            self.pkts.shrink_to(FREE_KEPT);
        }
    }

    /// `skipToOldest`. Every held packet is within 32,767 ahead of the
    /// position (an older one is dropped on arrival), so the serial order
    /// among them is the forward distance from it, whatever order Go's map
    /// gives them in: the list's first.
    fn skip_to_oldest(&mut self) {
        if let Some(oldest) = self.pkts.front() {
            self.next_seq = oldest.seq;
        }
    }
}

/// `codecs.VP8Packet.Unmarshal`'s reading of a payload descriptor: the S
/// bit and the descriptor's length, or `None` (`errShortPacket`,
/// `errNilPacket`).
#[must_use]
pub fn vp8_descriptor(payload: &[u8]) -> Option<(bool, usize)> {
    let first = *payload.first()?;
    let s = first & 0x10 != 0;
    let mut i = 1;
    let (mut pic, mut tl0, mut tk) = (false, false, false);
    if first & 0x80 != 0 {
        let x = *payload.get(i)?;
        pic = x & 0x80 != 0;
        tl0 = x & 0x40 != 0;
        tk = x & 0x20 != 0 || x & 0x10 != 0;
        i += 1;
    }
    if pic {
        let m = *payload.get(i)?;
        if m & 0x80 != 0 {
            if i + 1 >= payload.len() {
                return None;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    if tl0 {
        payload.get(i)?;
        i += 1;
    }
    if tk {
        payload.get(i)?;
        i += 1;
    }
    Some((s, i))
}

/// The one buffer an assembler builds a frame in and hands it out from.
/// Its capacity is [`MAX_ASSEMBLED_FRAME`] at most (it is grown to sizes
/// chosen here), and [`FRAME_KEPT`] at most once it is cleared.
#[derive(Debug, Default)]
struct FrameBuf(Vec<u8>);

impl FrameBuf {
    /// Whether `more` bytes still make a frame within the bound.
    fn takes(&self, more: usize) -> bool {
        self.0.len() + more <= MAX_ASSEMBLED_FRAME
    }

    /// Appends `body`; the caller asked [`Self::takes`].
    fn extend(&mut self, body: &[u8]) {
        let need = self.0.len() + body.len();
        if need > self.0.capacity() {
            let to = need
                .max(2 * self.0.capacity())
                .max(FRAME_FIRST)
                .min(MAX_ASSEMBLED_FRAME.max(need));
            self.0.reserve_exact(to - self.0.len());
        }
        self.0.extend_from_slice(body);
    }

    /// Empties it; a buffer larger than [`FRAME_KEPT`] is released.
    fn clear(&mut self) {
        if self.0.capacity() > FRAME_KEPT {
            self.0 = Vec::new();
        } else {
            self.0.clear();
        }
    }
}

/// `vp8FrameState`: the packets of one VP8 track into frames. A sequence
/// gap or a bad descriptor drops the frame being built; S starts one; the
/// marker ends it; a frame shorter than an epoch header is not one.
#[derive(Debug, Default)]
pub struct Vp8Assembler {
    /// The frame being built while `valid`; otherwise the last one handed
    /// out, until [`Self::release`] or the next packet.
    buf: FrameBuf,
    last_seq: u16,
    have_last: bool,
    valid: bool,
}

impl Vp8Assembler {
    /// The bytes its frame buffer holds, in capacity.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.buf.0.capacity()
    }

    /// The frame [`Self::process`] handed out was read: its buffer is
    /// cleared, and released when it is larger than [`FRAME_KEPT`]. A
    /// frame being built is left alone.
    pub fn release(&mut self) {
        if !self.valid {
            self.buf.clear();
        }
    }

    fn drop_frame(&mut self) {
        self.valid = false;
        self.buf.clear();
    }

    /// `processRTPPacket`: a whole frame when `pkt` ends one. Go swaps the
    /// frame into a second buffer to hand it out; here it stays in the one
    /// buffer until it is released or the next packet comes.
    pub fn process(&mut self, pkt: &Received) -> Option<&[u8]> {
        self.release();
        if self.have_last && pkt.seq != self.last_seq.wrapping_add(1) {
            self.drop_frame();
        }
        self.last_seq = pkt.seq;
        self.have_last = true;
        let Some((start, hdr)) = vp8_descriptor(&pkt.payload) else {
            self.drop_frame();
            return None;
        };
        if start {
            self.buf.clear();
            self.valid = true;
        }
        if !self.valid {
            return None;
        }
        let body = &pkt.payload[hdr..];
        if !self.buf.takes(body.len()) {
            self.drop_frame();
            return None;
        }
        self.buf.extend(body);
        if !pkt.marker {
            return None;
        }
        self.valid = false;
        (self.buf.0.len() >= EPOCH_HDR_LEN).then_some(self.buf.0.as_slice())
    }
}

/// The parts of `codecs.VP9Packet.Unmarshal` the VP9 assembler reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp9Descriptor {
    /// B: the frame's first packet.
    pub begin: bool,
    /// E: its last.
    pub end: bool,
    /// The descriptor's length.
    pub len: usize,
}

/// `maxSpatialLayers`.
const MAX_SPATIAL_LAYERS: u8 = 5;
/// `maxVP9RefPics`.
const MAX_VP9_REF_PICS: usize = 3;

/// `codecs.VP9Packet.Unmarshal`. `pdiffs` is the packet struct's `PDiff`
/// length, which pion never resets: every reference index of every packet
/// the assembler has read counts, and once three are counted a packet with
/// an N bit is refused (`errTooManyPDiff`), as in Go.
fn vp9_descriptor(p: &[u8], pdiffs: &mut usize) -> Option<Vp9Descriptor> {
    let first = *p.first()?;
    let (i_bit, p_bit, l_bit, f_bit) = (
        first & 0x80 != 0,
        first & 0x40 != 0,
        first & 0x20 != 0,
        first & 0x10 != 0,
    );
    let (begin, end, v_bit) = (first & 0x08 != 0, first & 0x04 != 0, first & 0x02 != 0);
    let mut pos = 1;
    if i_bit {
        let b = *p.get(pos)?;
        if b & 0x80 != 0 {
            pos += 1;
            p.get(pos)?;
        }
        pos += 1;
    }
    if l_bit {
        let b = *p.get(pos)?;
        if (b >> 1) & 0x7 >= MAX_SPATIAL_LAYERS {
            return None;
        }
        pos += 1;
        if !f_bit {
            p.get(pos)?;
            pos += 1;
        }
    }
    if f_bit && p_bit {
        loop {
            let b = *p.get(pos)?;
            *pdiffs = pdiffs.saturating_add(1);
            if b & 0x01 == 0 {
                break;
            }
            if *pdiffs >= MAX_VP9_REF_PICS {
                return None;
            }
            pos += 1;
        }
        pos += 1;
    }
    if v_bit {
        let b = *p.get(pos)?;
        let ns = usize::from(b >> 5) + 1;
        let (y, g) = (b & 0x10 != 0, b & 0x08 != 0);
        pos += 1;
        if y {
            for _ in 0..ns {
                if p.len() <= pos + 3 {
                    return None;
                }
                pos += 4;
            }
        }
        let mut ng = 0;
        if g {
            ng = *p.get(pos)?;
            pos += 1;
        }
        for _ in 0..ng {
            let b = *p.get(pos)?;
            let r = usize::from((b >> 2) & 0x3);
            pos += 1;
            // Go: len(packet) <= pos+R-1, never true for R = 0.
            if p.len() < pos + r {
                return None;
            }
            pos += r;
        }
    }
    Some(Vp9Descriptor {
        begin,
        end,
        len: pos,
    })
}

/// `vp9FrameState`: as [`Vp8Assembler`], with B starting a frame, E or the
/// marker ending it, and the frame undressed ([`vp9::undress`]).
#[derive(Debug, Default)]
pub struct Vp9Assembler {
    /// As [`Vp8Assembler`]'s.
    buf: FrameBuf,
    last_seq: u16,
    have_last: bool,
    valid: bool,
    pdiffs: usize,
}

impl Vp9Assembler {
    /// The bytes its frame buffer holds, in capacity.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.buf.0.capacity()
    }

    /// As [`Vp8Assembler::release`].
    pub fn release(&mut self) {
        if !self.valid {
            self.buf.clear();
        }
    }

    fn drop_frame(&mut self) {
        self.valid = false;
        self.buf.clear();
    }

    /// `processRTPPacket`.
    pub fn process(&mut self, pkt: &Received) -> Option<&[u8]> {
        self.release();
        if self.have_last && pkt.seq != self.last_seq.wrapping_add(1) {
            self.drop_frame();
        }
        self.last_seq = pkt.seq;
        self.have_last = true;
        let Some(d) = vp9_descriptor(&pkt.payload, &mut self.pdiffs) else {
            self.drop_frame();
            return None;
        };
        if d.begin {
            self.buf.clear();
            self.valid = true;
        }
        if !self.valid {
            return None;
        }
        let body = &pkt.payload[d.len..];
        if !self.buf.takes(body.len()) {
            self.drop_frame();
            return None;
        }
        self.buf.extend(body);
        if !d.end && !pkt.marker {
            return None;
        }
        self.valid = false;
        vp9::undress(&self.buf.0)
    }
}

/// A carrier's assembler (`frameAssembler`).
#[derive(Debug)]
pub enum Assembler {
    /// The transport's own VP8.
    Vp8(Vp8Assembler),
    /// MTS Link's VP9.
    Vp9(Vp9Assembler),
}

impl Assembler {
    /// `carrier.assembler()`.
    #[must_use]
    pub fn for_carrier(carrier: Carrier) -> Self {
        match carrier {
            Carrier::Vp8 => Self::Vp8(Vp8Assembler::default()),
            Carrier::Vp9 => Self::Vp9(Vp9Assembler::default()),
        }
    }

    /// `processRTPPacket`.
    pub fn process(&mut self, pkt: &Received) -> Option<&[u8]> {
        match self {
            Self::Vp8(a) => a.process(pkt),
            Self::Vp9(a) => a.process(pkt),
        }
    }

    /// The bytes its frame buffer holds, in capacity.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        match self {
            Self::Vp8(a) => a.held_bytes(),
            Self::Vp9(a) => a.held_bytes(),
        }
    }

    /// The frame [`Self::process`] handed out was read
    /// ([`Vp8Assembler::release`]).
    pub fn release(&mut self) {
        match self {
            Self::Vp8(a) => a.release(),
            Self::Vp9(a) => a.release(),
        }
    }
}

/// `carrier.accepts`: whether a remote track of this MIME type carries
/// frames (VP8 takes its RED wrapper too); the others are drained.
#[must_use]
pub fn accepts(carrier: Carrier, mime: &str) -> bool {
    match carrier {
        Carrier::Vp8 => mime.eq_ignore_ascii_case(MIME_VP8) || mime.eq_ignore_ascii_case(MIME_RED),
        Carrier::Vp9 => mime.eq_ignore_ascii_case(MIME_VP9),
    }
}

/// `readVP8Track`'s loop body: one remote track, RED unwrapped when its
/// codec is RED, reordered, assembled.
#[derive(Debug)]
pub struct TrackReader {
    red: bool,
    reorder: ReorderBuffer,
    assembler: Assembler,
    /// RTP packets read (`rtpCount`).
    pub packets: u64,
    /// Frames assembled (`frameCount`).
    pub frames: u64,
}

impl TrackReader {
    /// The reader of a remote track of `mime` on `carrier`, or `None` when
    /// the carrier drains such a track (`handleRemoteTrack`).
    #[must_use]
    pub fn new(carrier: Carrier, mime: &str) -> Option<Self> {
        accepts(carrier, mime).then(|| Self {
            red: mime.eq_ignore_ascii_case(MIME_RED),
            reorder: ReorderBuffer::new(),
            assembler: Assembler::for_carrier(carrier),
            packets: 0,
            frames: 0,
        })
    }

    /// The reorder buffer (tests, stats).
    #[must_use]
    pub fn reorder(&self) -> &ReorderBuffer {
        &self.reorder
    }

    /// The bytes the reader's allocations hold, in capacities
    /// ([`READER_HELD`] at most, [`READER_IDLE`] between frames).
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.reorder.held_bytes() + self.assembler.held_bytes()
    }

    /// One RTP packet off the track; `on_frame` takes each frame it
    /// completes (the slice is the reader's buffer: it is gone when
    /// `on_frame` returns). A RED packet without a readable primary is skipped
    /// before the reorder buffer sees it.
    pub fn push(
        &mut self,
        seq: u16,
        marker: bool,
        payload_type: u8,
        payload: &[u8],
        now: Instant,
        on_frame: &mut dyn FnMut(&[u8]),
    ) {
        self.packets += 1;
        let (pt, data) = if self.red {
            match red_primary(payload) {
                Ok(p) => p,
                Err(RedHeaderError) => return,
            }
        } else {
            (payload_type, payload)
        };
        let (assembler, frames) = (&mut self.assembler, &mut self.frames);
        self.reorder.push(seq, marker, pt, data, now, &mut |pkt| {
            if let Some(frame) = assembler.process(pkt) {
                *frames += 1;
                on_frame(frame);
            }
            // Read, or none: a reader left idle keeps no large frame.
            assembler.release();
        });
    }
}

/// What a carrier's track readers hold, for the client's gauges: the RTP
/// sink owns the readers and sets it ([`HeldGuard::set`]) after each
/// packet; the engine reads it ([`HeldGauge::get`]). The guard sets it to
/// zero as the readers go with their sink.
#[derive(Debug, Clone, Default)]
pub struct HeldGauge(Arc<AtomicUsize>);

impl HeldGauge {
    /// The bytes last set; zero once the readers are gone.
    #[must_use]
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    /// The setter a sink owns with its readers.
    #[must_use]
    pub fn guard(&self) -> HeldGuard {
        HeldGuard(self.0.clone())
    }
}

/// [`HeldGauge`]'s setter: zero again when dropped.
#[derive(Debug)]
pub struct HeldGuard(Arc<AtomicUsize>);

impl HeldGuard {
    /// What the readers hold now.
    pub fn set(&self, bytes: usize) {
        self.0.store(bytes, Ordering::Relaxed);
    }
}

impl Drop for HeldGuard {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_held_gauge_reads_what_the_sink_set_and_zero_once_it_goes() {
        let gauge = HeldGauge::default();
        let guard = gauge.guard();
        guard.set(READER_HELD);
        assert_eq!(gauge.clone().get(), READER_HELD);
        drop(guard);
        assert_eq!(gauge.get(), 0);
    }
    use crate::rtp::{Packetizer, Payloader, Vp8Payloader};
    use crate::wire::epoch_header;

    fn frame(n: usize) -> Vec<u8> {
        let mut f = epoch_header(1, 2, 3).to_vec();
        f.extend((0..n).map(|i| i as u8));
        f
    }

    #[test]
    fn red_primary_finds_the_primary_and_refuses_bad_headers() {
        assert_eq!(red_primary(&[100, 1, 2, 3]), Ok((100, &[1u8, 2, 3][..])));
        let mut p = vec![0x80 | 100, 0, 0, 3, 0x80 | 100, 0, 1, 44, 100];
        p.extend_from_slice(&[1, 2, 3]);
        p.extend(std::iter::repeat_n(9, 300));
        p.extend_from_slice(&[7, 7]);
        assert_eq!(red_primary(&p), Ok((100, &[7u8, 7][..])));
        let bads: [&[u8]; 4] = [
            &[],
            &[0x80 | 100, 0],
            &[0x80 | 100, 0, 0, 5, 100, 1, 2],
            &[0x80 | 100, 0, 0, 0],
        ];
        for bad in bads {
            assert_eq!(red_primary(bad), Err(RedHeaderError), "{bad:?}");
        }
    }

    #[test]
    fn the_reorder_buffer_waits_for_a_gap_then_gives_it_up() {
        let t0 = Instant::now();
        let mut b = ReorderBuffer::new();
        let mut got = Vec::new();
        let push = |b: &mut ReorderBuffer, seq: u16, at: Instant| {
            let mut out = Vec::new();
            b.push(seq, false, 96, &[], at, &mut |p| out.push(p.seq));
            out
        };
        got.extend(push(&mut b, 65534, t0));
        got.extend(push(&mut b, 0, t0));
        assert_eq!(got, [65534], "65535 is missing");
        assert_eq!(push(&mut b, 65535, t0), [65535, 0], "across the wrap");
        assert!(push(&mut b, 65535, t0).is_empty(), "already delivered");
        assert!(push(&mut b, 3, t0).is_empty());
        assert!(
            push(&mut b, 4, t0 + Duration::from_millis(300)).is_empty(),
            "held 300 ms, not more"
        );
        assert_eq!(
            push(&mut b, 6, t0 + Duration::from_millis(301)),
            [3, 4],
            "the gap at 1 and 2 given up"
        );
        assert_eq!(b.held(), 1);
        for s in 7..7 + 255 {
            assert!(push(&mut b, s, t0 + Duration::from_millis(302)).is_empty());
        }
        assert_eq!(b.held(), REORDER_WINDOW);
        let out = push(&mut b, 262, t0 + Duration::from_millis(302));
        assert_eq!(out.len(), 257, "a full window behind the hole at 5");
        assert_eq!(out[0], 6);
        assert_eq!(b.next_seq(), 263);
    }

    #[test]
    fn vp8_frames_assemble_across_packets_and_a_gap_drops_one() {
        let t0 = Instant::now();
        let mut k = Packetizer::new(Payloader::Vp8(Vp8Payloader::with_picture_id(200)), 10, 0);
        let mut r = TrackReader::new(Carrier::Vp8, "video/vp8").unwrap();
        let a = k.packetize(&frame(3000), 1);
        let b = k.packetize(&frame(10), 1);
        let c = k.packetize(&frame(5), 1);
        let d = k.packetize(&frame(7), 1);
        assert_eq!((a.len(), b.len(), c.len(), d.len()), (3, 1, 1, 1));
        let mut frames = Vec::new();
        let mut on = |f: &[u8]| frames.push(f.to_vec());
        for i in [0, 2, 1] {
            let p = &a[i];
            r.push(p.seq, p.marker, 96, &p.payload, t0, &mut on);
        }
        // b's only packet is lost: c waits behind the gap until a packet
        // comes after the hold.
        r.push(
            c[0].seq,
            c[0].marker,
            96,
            &c[0].payload,
            t0 + Duration::from_secs(1),
            &mut on,
        );
        assert_eq!(r.reorder().held(), 1);
        r.push(
            d[0].seq,
            d[0].marker,
            96,
            &d[0].payload,
            t0 + Duration::from_secs(2),
            &mut on,
        );
        assert_eq!(frames, [frame(3000), frame(5), frame(7)]);
        assert_eq!((r.packets, r.frames), (5, 3));
        assert!(TrackReader::new(Carrier::Vp8, "video/VP9").is_none());
        assert!(TrackReader::new(Carrier::Vp9, "video/red").is_none());
    }

    /// A packet of a hand-made frame: a one-byte descriptor of `carrier`
    /// (the frame's first packet starts it, its last ends it), then `body`
    /// bytes.
    fn part(carrier: Carrier, seq: u16, first: bool, last: bool, body: usize) -> Received {
        let descriptor = match carrier {
            Carrier::Vp8 => u8::from(first) << 4,
            Carrier::Vp9 => u8::from(first) << 3 | u8::from(last) << 2,
        };
        let mut payload = vec![descriptor];
        payload.resize(1 + body, 0x5a);
        Received {
            seq,
            marker: last,
            payload_type: 96,
            payload,
        }
    }

    /// The largest body a carrier's reader is given (it drops a payload
    /// over [`MAX_RETAINED_PAYLOAD`]), and how many of them a frame at the
    /// bound has.
    const BODY: usize = MAX_RETAINED_PAYLOAD - 1;
    const PARTS: usize = MAX_ASSEMBLED_FRAME / BODY;

    /// Wave 2's memory review, finding 1: the bound is on capacities. A
    /// payload that is longer than the recycled buffer it lands in must not
    /// double it, and neither list has more slots than the window and one.
    #[test]
    fn the_reorder_buffer_holds_capacities_within_its_bound() {
        let t0 = Instant::now();
        let mut b = ReorderBuffer::new();
        let mut peak = 0;
        let mut push = |b: &mut ReorderBuffer, seq: u16, len: usize| {
            b.push(seq, false, 96, &vec![7u8; len], t0, &mut |_| {});
            peak = peak.max(b.held_bytes());
        };
        push(&mut b, 0, 100);
        // A gap at 1 with a full window of 2,047-byte packets behind it,
        // then the gap filled: every buffer goes back to the free list.
        for seq in 2..=257 {
            push(&mut b, seq, MAX_RETAINED_PAYLOAD - 1);
        }
        assert_eq!(b.held(), REORDER_WINDOW);
        push(&mut b, 1, MAX_RETAINED_PAYLOAD - 1);
        assert_eq!((b.held(), b.next_seq()), (0, 258));
        // A second gap, the packets one byte longer than those buffers.
        for seq in 259..=514 {
            push(&mut b, seq, MAX_RETAINED_PAYLOAD);
        }
        assert_eq!(b.held(), REORDER_WINDOW);
        let largest = b
            .pkts
            .iter()
            .chain(&b.free)
            .map(|p| p.payload.capacity())
            .max();
        assert_eq!(largest, Some(MAX_RETAINED_PAYLOAD), "a payload buffer");
        assert!(
            peak <= REORDER_HELD,
            "held {peak}, the bound {REORDER_HELD}"
        );
        assert!(peak >= REORDER_WINDOW * MAX_RETAINED_PAYLOAD, "{peak}");
        assert!(b.pkts.capacity() <= REORDER_WINDOW + 1, "the held list");
        assert!(b.free.capacity() <= REORDER_WINDOW + 1, "the free list");
    }

    /// The held packets are a list in sequence order, however they came:
    /// one far ahead, one across the wrap, the same number twice. What is
    /// delivered and what is skipped is as with Go's map.
    #[test]
    fn held_packets_stay_in_sequence_order_however_they_came() {
        let t0 = Instant::now();
        let mut b = ReorderBuffer::new();
        let push = |b: &mut ReorderBuffer, seq: u16, marker: bool, at: Instant| {
            let mut out = Vec::new();
            b.push(seq, marker, 96, &[1], at, &mut |p| {
                out.push((p.seq, p.marker));
            });
            out
        };
        assert_eq!(push(&mut b, 65530, false, t0), [(65530, false)]);
        for seq in [700, 65533, 2, 30_000, 65535, 2] {
            assert!(push(&mut b, seq, false, t0).is_empty(), "{seq}");
        }
        assert!(push(&mut b, 65533, true, t0).is_empty(), "the later copy");
        let order: Vec<u16> = b.pkts.iter().map(|p| p.seq).collect();
        assert_eq!(order, [65533, 65535, 2, 700, 30_000]);
        // 65531 comes: it alone is next. Then the gap at 65532 ages, and
        // the oldest held is the place to go on from.
        assert_eq!(push(&mut b, 65531, false, t0), [(65531, false)]);
        let late = t0 + REORDER_HOLD + Duration::from_millis(1);
        assert_eq!(
            push(&mut b, 65534, false, late),
            [(65533, true), (65534, false), (65535, false)]
        );
        assert_eq!((b.next_seq(), b.held()), (0, 3));
        // Each skip goes to the oldest left, across the wrap first.
        let later = late + REORDER_HOLD + Duration::from_millis(1);
        assert_eq!(push(&mut b, 3, false, later), [(2, false), (3, false)]);
        assert_eq!((b.next_seq(), b.held()), (4, 2));
        assert!(push(&mut b, 1, false, later).is_empty(), "behind it");
        assert_eq!(b.held(), 2);
    }

    /// The free list is the gap's, not the reader's: once nothing waits it
    /// keeps [`FREE_KEPT`] buffers.
    #[test]
    fn the_reorder_buffer_releases_its_free_list_when_nothing_waits() {
        let t0 = Instant::now();
        let mut b = ReorderBuffer::new();
        let push = |b: &mut ReorderBuffer, seq: u16| {
            b.push(seq, false, 96, &[7u8; 1200], t0, &mut |_| {});
        };
        push(&mut b, 0);
        for seq in 2..=257 {
            push(&mut b, seq);
        }
        assert_eq!(b.held(), REORDER_WINDOW);
        assert!(b.held_bytes() > REORDER_IDLE);
        push(&mut b, 1);
        assert_eq!(b.held(), 0);
        assert_eq!(b.free.len(), FREE_KEPT);
        assert!(
            b.held_bytes() <= REORDER_IDLE,
            "idle it holds {}, not {REORDER_IDLE} at most",
            b.held_bytes()
        );
        // And a gap after it is held as the first was.
        for seq in 259..=514 {
            push(&mut b, seq);
        }
        assert_eq!(b.held(), REORDER_WINDOW);
        assert!(b.held_bytes() <= REORDER_HELD);
    }

    /// An assembler has one frame buffer, never larger than the frame
    /// bound (a vector that doubles would be), and gives a large one back
    /// once its frame was read. The transport's own frames stay in one
    /// buffer that is kept.
    #[test]
    fn an_assembler_holds_one_frame_at_most_and_releases_a_large_one() {
        for carrier in [Carrier::Vp8, Carrier::Vp9] {
            let mut a = Assembler::for_carrier(carrier);
            let mut seq = 0u16;
            let mut frame = |a: &mut Assembler, parts: usize| {
                let mut out = None;
                for i in 0..parts {
                    let pkt = part(carrier, seq, i == 0, i + 1 == parts, BODY);
                    seq = seq.wrapping_add(1);
                    out = a.process(&pkt).map(<[u8]>::len);
                    assert!(
                        a.held_bytes() <= MAX_ASSEMBLED_FRAME,
                        "{carrier:?}: {} held at packet {i}",
                        a.held_bytes()
                    );
                }
                a.release();
                out
            };
            for _ in 0..3 {
                let out = frame(&mut a, PARTS);
                if carrier == Carrier::Vp8 {
                    assert_eq!(out, Some(PARTS * BODY));
                }
                assert!(out.is_some(), "{carrier:?}");
                assert!(
                    a.held_bytes() <= FRAME_KEPT,
                    "{carrier:?}: {} kept after a frame at the bound",
                    a.held_bytes()
                );
            }
            // A frame the transport itself may send: its buffer is kept
            // and taken again.
            let own = MAX_PAYLOAD_SIZE / BODY + 1;
            assert!(frame(&mut a, own).is_some());
            let kept = a.held_bytes();
            assert!((own * BODY..=FRAME_KEPT).contains(&kept), "{kept}");
            assert!(frame(&mut a, own).is_some());
            assert_eq!(a.held_bytes(), kept);
        }
    }

    /// A reader as its owner drives it: within [`READER_HELD`] at every
    /// packet with a window of the largest packets behind a gap and frames
    /// at the bound, and [`READER_IDLE`] at most once the gap is filled and
    /// the frame handed out.
    #[test]
    fn a_reader_holds_its_bound_in_capacities_and_little_between_frames() {
        const { assert!(READER_HELD < 772 << 10) };
        const { assert!(READER_IDLE < 81 << 10) };
        for (carrier, mime) in [(Carrier::Vp8, MIME_VP8), (Carrier::Vp9, MIME_VP9)] {
            let t0 = Instant::now();
            let mut r = TrackReader::new(carrier, mime).unwrap();
            let (mut peak, mut frames) = (0, 0);
            let mut push = |r: &mut TrackReader, n: usize| {
                let at = n % PARTS;
                let (first, last) = (at == 0, at == PARTS - 1);
                let pkt = part(carrier, u16::try_from(n).unwrap(), first, last, BODY);
                r.push(pkt.seq, pkt.marker, 96, &pkt.payload, t0, &mut |_| {
                    frames += 1;
                });
                peak = peak.max(r.held_bytes());
            };
            // One frame at the bound, in order.
            for n in 0..PARTS {
                push(&mut r, n);
            }
            assert!(
                r.held_bytes() <= READER_IDLE,
                "{carrier:?}: {} held after a frame at the bound",
                r.held_bytes()
            );
            // The next frames behind a gap at their first packet.
            for n in PARTS + 1..=PARTS + REORDER_WINDOW {
                push(&mut r, n);
            }
            assert_eq!(r.reorder().held(), REORDER_WINDOW);
            push(&mut r, PARTS);
            assert_eq!(r.reorder().held(), 0);
            for n in PARTS + REORDER_WINDOW + 1..4 * PARTS {
                push(&mut r, n);
            }
            assert_eq!(frames, 4, "{carrier:?}");
            assert!(peak <= READER_HELD, "{carrier:?}: {peak} held");
            assert!(peak > REORDER_WINDOW * MAX_RETAINED_PAYLOAD, "{peak}");
            assert!(
                r.held_bytes() <= READER_IDLE,
                "{carrier:?}: {} held at the end",
                r.held_bytes()
            );
        }
    }

    #[test]
    fn descriptors_read_as_pion_reads_them() {
        assert_eq!(vp8_descriptor(&[0x10, 1]), Some((true, 1)));
        assert_eq!(
            vp8_descriptor(&[0x90, 0x80, 0x92, 0x34, 9]),
            Some((true, 4))
        );
        assert_eq!(vp8_descriptor(&[0x80, 0x80, 0x12, 9]), Some((false, 3)));
        assert_eq!(
            vp8_descriptor(&[0x80, 0x70, 1, 2]),
            Some((false, 4)),
            "L and T/K"
        );
        assert_eq!(vp8_descriptor(&[0x80, 0x80, 0x92]), None);
        assert_eq!(vp8_descriptor(&[]), None);
        let mut n = 0;
        assert_eq!(
            vp9_descriptor(&[0x9b, 0x80, 0, 0x10, 1, 0x40, 0, 0xb4, 7], &mut n),
            Some(Vp9Descriptor {
                begin: true,
                end: false,
                len: 8
            })
        );
        assert_eq!(vp9_descriptor(&[0x9b, 0x80], &mut n), None);
        // F and P: reference indices, counted for good as pion counts them.
        assert!(vp9_descriptor(&[0x50, 0x03, 0x02, 9], &mut n).is_some());
        assert_eq!(n, 2);
        assert!(
            vp9_descriptor(&[0x50, 0x03, 0x02], &mut n).is_none(),
            "a third with N set"
        );
        assert!(
            vp9_descriptor(&[0x50, 0x02], &mut n).is_some(),
            "without N it passes"
        );
    }
}

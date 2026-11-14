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

use std::collections::HashMap;
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
    pkts: HashMap<u16, Received>,
    free: Vec<Received>,
    next_seq: u16,
    started: bool,
    gap_since: Option<Instant>,
}

impl ReorderBuffer {
    /// `newReorderBuffer`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pkts: HashMap::with_capacity(REORDER_WINDOW + 1),
            ..Self::default()
        }
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
        pkt.payload.extend_from_slice(payload);
        if let Some(old) = self.pkts.insert(seq, pkt) {
            self.recycle(old);
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
        } else if self.gap_since.is_none() {
            self.gap_since = Some(now);
        }
    }

    fn drain(&mut self, deliver: &mut dyn FnMut(&Received)) {
        while let Some(pkt) = self.pkts.remove(&self.next_seq) {
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
            self.free.push(pkt);
        }
    }

    /// `skipToOldest`. Every held packet is within 32,767 ahead of the
    /// position (an older one is dropped on arrival), so the serial order
    /// among them is the forward distance from it, whatever order Go's map
    /// gives them in.
    fn skip_to_oldest(&mut self) {
        let next = self.next_seq;
        if let Some(&oldest) = self.pkts.keys().min_by_key(|&&s| s.wrapping_sub(next)) {
            self.next_seq = oldest;
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

/// `vp8FrameState`: the packets of one VP8 track into frames. A sequence
/// gap or a bad descriptor drops the frame being built; S starts one; the
/// marker ends it; a frame shorter than an epoch header is not one.
#[derive(Debug, Default)]
pub struct Vp8Assembler {
    buf: Vec<u8>,
    out: Vec<u8>,
    last_seq: u16,
    have_last: bool,
    valid: bool,
}

impl Vp8Assembler {
    fn drop_frame(&mut self) {
        self.valid = false;
        self.buf.clear();
    }

    /// `processRTPPacket`: a whole frame when `pkt` ends one.
    pub fn process(&mut self, pkt: &Received) -> Option<&[u8]> {
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
        if self.buf.len() + body.len() > MAX_ASSEMBLED_FRAME {
            self.drop_frame();
            return None;
        }
        self.buf.extend_from_slice(body);
        if !pkt.marker {
            return None;
        }
        std::mem::swap(&mut self.buf, &mut self.out);
        self.buf.clear();
        self.valid = false;
        (self.out.len() >= EPOCH_HDR_LEN).then_some(self.out.as_slice())
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
    buf: Vec<u8>,
    out: Vec<u8>,
    last_seq: u16,
    have_last: bool,
    valid: bool,
    pdiffs: usize,
}

impl Vp9Assembler {
    fn drop_frame(&mut self) {
        self.valid = false;
        self.buf.clear();
    }

    /// `processRTPPacket`.
    pub fn process(&mut self, pkt: &Received) -> Option<&[u8]> {
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
        if self.buf.len() + body.len() > MAX_ASSEMBLED_FRAME {
            self.drop_frame();
            return None;
        }
        self.buf.extend_from_slice(body);
        if !d.end && !pkt.marker {
            return None;
        }
        std::mem::swap(&mut self.buf, &mut self.out);
        self.buf.clear();
        self.valid = false;
        vp9::undress(&self.out)
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

    /// One RTP packet off the track; `on_frame` takes each frame it
    /// completes. A RED packet without a readable primary is skipped
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
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The room's video, one reader per remote track.
//!
//! pion raises a track per SSRC and the Go transport reads each with a
//! reorder buffer and an assembler of its own
//! (`vp8channel/rtp_reader.go:264-303`). The SFU fills each of the nine
//! receive slots with one publisher, and every publisher numbers its
//! packets by itself: one reader for all of them would take one
//! publisher's sequence numbers for another's late or lost packets.
//!
//! [`Readers`] keeps a [`TrackReader`] per SSRC, made on the first packet
//! of that SSRC and dropped with the generation (it lives in the peer's
//! RTP sink).
//!
//! # Memory
//!
//! At most [`MAX_READERS`] readers live at once: the slots the offer
//! receives on. A packet of one more SSRC takes the place of the reader fed
//! longest ago, whose half-built frame goes with it. A packet whose payload
//! is longer than [`MAX_PACKET_PAYLOAD`] is dropped before any reader
//! copies it, which is what makes [`READER_HELD`] a bound: pion reads up to
//! 8,192 bytes, the writers of this transport send 1,200 at most.

use std::time::Instant;

use olc_vp8channel::channel::Carrier;
use olc_vp8channel::rtp_reader::{TrackReader, MAX_RETAINED_PAYLOAD, MIME_VP9};

/// The readers alive at once, at most: one per receive slot of the offer
/// (`receiveSlots`).
pub const MAX_READERS: usize = 9;
/// The longest RTP payload a reader is given.
pub const MAX_PACKET_PAYLOAD: usize = MAX_RETAINED_PAYLOAD;
/// The most one track reader holds, in bytes: olc-vp8channel's own bound,
/// on its buffers' capacities (the reorder buffer at the packet that makes
/// it give a gap up, the two lists it keeps, and the one frame buffer).
/// It is a bound here because [`MAX_PACKET_PAYLOAD`] is the reader's
/// retained payload.
pub use olc_vp8channel::rtp_reader::READER_HELD;
/// The most all of a generation's readers hold.
pub const READERS_HELD: usize = MAX_READERS * READER_HELD;

/// What became of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fed {
    /// It went to the reader its SSRC already had.
    Known,
    /// It is the first of its SSRC and a reader was made for it.
    New,
    /// It is the first of its SSRC, and its reader took the place of this
    /// SSRC's, the one fed longest ago.
    Replaced(u32),
    /// Its payload is longer than [`MAX_PACKET_PAYLOAD`]: dropped.
    Oversize,
}

/// One remote track's reader.
#[derive(Debug)]
struct Live {
    ssrc: u32,
    /// The count of the packet that fed it last.
    fed: u64,
    reader: TrackReader,
}

/// A generation's track readers, VP9 only.
#[derive(Debug, Default)]
pub struct Readers {
    live: Vec<Live>,
    /// Packets taken so far.
    count: u64,
    /// Readers that gave their place to a new SSRC's so far.
    pub replaced: u64,
    /// Packets dropped for their length so far.
    pub oversize: u64,
}

impl Readers {
    /// No reader yet: the first is made by the first packet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The readers alive.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// No reader is alive.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// The bytes the readers hold, in capacities ([`READERS_HELD`] at
    /// most).
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.live.iter().map(|l| l.reader.held_bytes()).sum()
    }

    /// The SSRCs that have a reader, the one fed longest ago first.
    #[must_use]
    pub fn ssrcs(&self) -> Vec<u32> {
        let mut by_age: Vec<&Live> = self.live.iter().collect();
        by_age.sort_by_key(|l| l.fed);
        by_age.into_iter().map(|l| l.ssrc).collect()
    }

    /// One RTP packet of the room's video; `on_frame` takes each frame its
    /// track completes.
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        ssrc: u32,
        seq: u16,
        marker: bool,
        payload_type: u8,
        payload: &[u8],
        now: Instant,
        on_frame: &mut dyn FnMut(&[u8]),
    ) -> Fed {
        // Before a reader is made for it, or copies it.
        if payload.len() > MAX_PACKET_PAYLOAD {
            self.oversize += 1;
            return Fed::Oversize;
        }
        self.count += 1;
        let (at, fed) = match self.live.iter().position(|l| l.ssrc == ssrc) {
            Some(at) => (at, Fed::Known),
            None => {
                let mut fed = Fed::New;
                if self.live.len() >= MAX_READERS {
                    // The place of the one fed longest ago; it is dropped,
                    // with what it held, before the new one is made.
                    let oldest = self
                        .live
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, l)| l.fed)
                        .map_or(0, |(i, _)| i);
                    fed = Fed::Replaced(self.live.swap_remove(oldest).ssrc);
                    self.replaced += 1;
                }
                self.live.push(Live {
                    ssrc,
                    fed: 0,
                    reader: TrackReader::new(Carrier::Vp9, MIME_VP9)
                        .expect("the VP9 carrier reads VP9"),
                });
                (self.live.len() - 1, fed)
            }
        };
        let live = &mut self.live[at];
        live.fed = self.count;
        live.reader
            .push(seq, marker, payload_type, payload, now, on_frame);
        fed
    }
}

#[cfg(test)]
mod tests {
    use olc_vp8channel::rtp::{Packetizer, Payloader, RtpPacket};
    use olc_vp8channel::vp9;
    use olc_vp8channel::wire::{epoch_header, TOKEN_OFF};

    use super::*;

    const PT: u8 = 98;

    /// A transport frame whose body is `fill`, `n` bytes long.
    fn frame(fill: u8, n: usize) -> Vec<u8> {
        let mut f = epoch_header(1, 2, 3).to_vec();
        f.extend(std::iter::repeat_n(fill, n));
        f
    }

    /// `frame` as its publisher sends it: dressed as VP9 and packetized
    /// from sequence number `seq` on.
    fn packets(frame: &[u8], seq: u16) -> Vec<RtpPacket> {
        let mut sample = Vec::new();
        vp9::dress(&mut sample, frame, false);
        Packetizer::new(Payloader::Vp9(vp9::Payloader::new()), seq, 1)
            .packetize(&sample, 16_666_666)
    }

    fn feed(r: &mut Readers, ssrc: u32, p: &RtpPacket, got: &mut Vec<Vec<u8>>) -> Fed {
        r.push(
            ssrc,
            p.seq,
            p.marker,
            PT,
            &p.payload,
            Instant::now(),
            &mut |f| got.push(f.to_vec()),
        )
    }

    /// What the readers hold is their readers' bytes: none before the
    /// first packet, a reader's part of a frame after it, within the bound.
    #[test]
    fn the_readers_say_what_they_hold() {
        let mut r = Readers::new();
        assert_eq!(r.held_bytes(), 0);
        let mut got = Vec::new();
        let ps = packets(&frame(0x11, 4000), 7);
        assert!(ps.len() >= 2);
        feed(&mut r, 1, &ps[0], &mut got);
        let held = r.held_bytes();
        assert!(held > 0 && held <= READERS_HELD, "{held}");
        feed(&mut r, 2, &ps[0], &mut got);
        assert!(r.held_bytes() > held, "a second reader adds its own");
    }

    /// Two publishers in two slots, each numbering its packets from the
    /// same place, their packets arriving in turn: each one's frame comes
    /// out whole. One reader for both takes the second publisher's packets
    /// for repeats of the first's and drops them.
    #[test]
    fn two_tracks_with_interleaved_sequence_numbers_both_deliver() {
        let (a, b) = (frame(0xaa, 3000), frame(0xbb, 3000));
        let (pa, pb) = (packets(&a, 7), packets(&b, 7));
        assert!(pa.len() >= 3 && pa.len() == pb.len(), "{}", pa.len());
        let mut r = Readers::new();
        let mut got = Vec::new();
        for (i, (x, y)) in pa.iter().zip(&pb).enumerate() {
            let first = i == 0;
            assert_eq!(
                feed(&mut r, 0x1111, x, &mut got),
                if first { Fed::New } else { Fed::Known }
            );
            assert_eq!(
                feed(&mut r, 0x2222, y, &mut got),
                if first { Fed::New } else { Fed::Known }
            );
        }
        assert_eq!(got.len(), 2, "frames delivered");
        assert_eq!(&got[0][TOKEN_OFF..], &a[TOKEN_OFF..], "the first track's");
        assert_eq!(&got[1][TOKEN_OFF..], &b[TOKEN_OFF..], "the second track's");
        assert_eq!(r.len(), 2);
        assert_eq!(r.ssrcs(), [0x1111, 0x2222]);

        // The same two a wrap later, the second a packet ahead of the first.
        let (pa, pb) = (packets(&a, 65_534), packets(&b, 65_534));
        let mut r = Readers::new();
        let mut got = Vec::new();
        feed(&mut r, 2, &pb[0], &mut got);
        for (x, y) in pa.iter().zip(pb.iter().skip(1)) {
            feed(&mut r, 1, x, &mut got);
            feed(&mut r, 2, y, &mut got);
        }
        feed(&mut r, 1, pa.last().unwrap(), &mut got);
        assert_eq!(got.len(), 2, "frames delivered across the wrap");
        assert_eq!(&got[0][TOKEN_OFF..], &b[TOKEN_OFF..]);
        assert_eq!(&got[1][TOKEN_OFF..], &a[TOKEN_OFF..]);
    }

    /// Nine readers at most (D8): the tenth SSRC takes the place of the
    /// one fed longest ago, and what that one had half built is gone.
    #[test]
    fn the_tenth_track_replaces_the_one_fed_longest_ago() {
        let f = frame(0xcc, 3000);
        let p = packets(&f, 100);
        assert!(p.len() >= 3);
        let mut r = Readers::new();
        let mut got = Vec::new();
        // Nine tracks, each with the first packet of a frame.
        for ssrc in 1..=9 {
            assert_eq!(feed(&mut r, ssrc, &p[0], &mut got), Fed::New);
        }
        assert_eq!(r.len(), MAX_READERS);
        assert_eq!(r.ssrcs(), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        // The first is fed again: the second is now the one fed longest ago.
        assert_eq!(feed(&mut r, 1, &p[1], &mut got), Fed::Known);
        assert_eq!(r.ssrcs(), [2, 3, 4, 5, 6, 7, 8, 9, 1]);
        assert_eq!(feed(&mut r, 10, &p[0], &mut got), Fed::Replaced(2));
        assert_eq!(r.len(), MAX_READERS, "a tenth reader was kept");
        assert_eq!(r.ssrcs(), [3, 4, 5, 6, 7, 8, 9, 1, 10]);
        // The first track's frame, begun before the tenth came, completes.
        for x in &p[2..] {
            feed(&mut r, 1, x, &mut got);
        }
        assert_eq!(got.len(), 1, "the kept track's frame");
        assert_eq!(&got[0][TOKEN_OFF..], &f[TOKEN_OFF..]);
        // The second track comes back as a new one (the third goes): the
        // rest of the frame it had begun is the rest of nothing.
        assert_eq!(feed(&mut r, 2, &p[1], &mut got), Fed::Replaced(3));
        for x in &p[2..] {
            assert_eq!(feed(&mut r, 2, x, &mut got), Fed::Known);
        }
        assert_eq!(got.len(), 1, "a replaced reader's half frame came out");
        assert_eq!(r.len(), MAX_READERS);
        // A flood of new tracks never holds more than nine.
        for ssrc in 1000..2000 {
            feed(&mut r, ssrc, &p[0], &mut got);
            assert!(r.len() <= MAX_READERS);
        }
        assert_eq!(r.ssrcs(), (1991..2000).collect::<Vec<u32>>());
        assert_eq!(r.replaced, 1002);
    }

    /// A payload longer than a reader keeps is dropped before a reader is
    /// made for it or copies it.
    #[test]
    fn an_oversize_payload_reaches_no_reader() {
        let mut r = Readers::new();
        let mut got = Vec::new();
        let long = RtpPacket {
            seq: 1,
            timestamp: 1,
            marker: true,
            payload: vec![0x9c; MAX_PACKET_PAYLOAD + 1],
        };
        assert_eq!(feed(&mut r, 5, &long, &mut got), Fed::Oversize);
        assert!(
            r.is_empty(),
            "a reader was made for a packet it cannot take"
        );
        let fits = RtpPacket {
            payload: vec![0x9c; MAX_PACKET_PAYLOAD],
            ..long.clone()
        };
        assert_eq!(feed(&mut r, 5, &fits, &mut got), Fed::New);
        assert_eq!(feed(&mut r, 5, &long, &mut got), Fed::Oversize);
        assert_eq!(r.len(), 1);
        assert!(got.is_empty());
        assert_eq!(r.oversize, 2);
    }

    /// The bound the budget carries.
    #[test]
    fn what_the_readers_hold_is_bounded() {
        assert_eq!(MAX_READERS, crate::session::RECEIVE_SLOTS);
        assert_eq!(MAX_PACKET_PAYLOAD, 2048);
        assert_eq!(READER_HELD, olc_vp8channel::rtp_reader::READER_HELD);
        assert_eq!(READERS_HELD, 9 * READER_HELD);
        const { assert!(READER_HELD <= 1 << 20) };
        const { assert!(READERS_HELD <= 9 << 20) };
    }
}

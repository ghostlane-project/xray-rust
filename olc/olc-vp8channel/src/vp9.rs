// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The VP9 carrier (W34, W35): `vp8channel/carrier.go` at 2d4266af. A relay
//! that forwards no VP8 (MTS Link's SFU answers H264 and VP9 only) gets the
//! same frames re-headed as VP9 keyframes where they reach the track
//! ([`dress`]) and un-headed where they leave it ([`undress`]); nothing in
//! between knows the difference.
//!
//! ```text
//! vp9Head (68) ‖ zero padding (keyframes, to 1400) ‖ token, src, dst, crc ‖ KCP bytes ‖ u16 BE len(head + padding)
//! ```

use crate::wire::{EPOCH_HDR_LEN, TOKEN_OFF, VP8_KEEPALIVE};

/// `vp9Head`: a libvpx keyframe of a black 320x180 picture.
pub const VP9_HEAD: [u8; 68] = [
    0x82, 0x49, 0x83, 0x42, 0x60, 0x13, 0xf0, 0x0b, 0x36, 0x66, 0x38, 0x24, 0x1c, 0x19, 0x92, 0x00,
    0x00, 0x50, 0x43, 0xe8, 0xbf, 0x40, 0x00, 0x67, 0x3f, 0xfe, 0x2f, 0x20, 0x00, 0x04, 0xee, 0x66,
    0xa7, 0x89, 0xd3, 0xfb, 0x17, 0xd3, 0x70, 0x4c, 0xc4, 0xe7, 0xd9, 0x1b, 0x5b, 0xe5, 0xac, 0x4c,
    0x31, 0x1d, 0x90, 0x67, 0xac, 0xb3, 0x74, 0x35, 0x3e, 0x92, 0xab, 0xc1, 0xec, 0x2d, 0xe8, 0x00,
    0x85, 0x59, 0x2c, 0xf0,
];
/// `vp9HeadWidth`.
pub const HEAD_WIDTH: u16 = 320;
/// `vp9HeadHeight`.
pub const HEAD_HEIGHT: u16 = 180;
/// `vp9TrailerLen`.
pub const TRAILER_LEN: usize = 2;
/// `vp9KeyframeSpan`: a keyframe sample is padded past one RTP packet.
pub const KEYFRAME_SPAN: usize = 1400;
/// `vp9DescriptorLen`: flags and a 15-bit picture id.
pub const DESCRIPTOR_LEN: usize = 3;
/// `vp9StructureLen`: the scalability structure of a keyframe's first packet.
pub const STRUCTURE_LEN: usize = 5;

const FLAG_PICTURE_ID: u8 = 0x80;
const FLAG_FLEXIBLE: u8 = 0x10;
const FLAG_BEGIN: u8 = 0x08;
const FLAG_END: u8 = 0x04;
const FLAG_STRUCTURE: u8 = 0x02;
const FLAG_NOT_REF: u8 = 0x01;
const LONG_PICTURE_ID: u16 = 0x8000;
const ONE_LAYER_SIZED: u8 = 0x10;

/// `vp9Dress`: the frame (VP8 keepalive dropped) behind the VP9 head into
/// `dst`; a keyframe is padded to [`KEYFRAME_SPAN`], ahead of the header.
pub fn dress(dst: &mut Vec<u8>, frame: &[u8], keyframe: bool) {
    let body = &frame[VP8_KEEPALIVE.len().min(frame.len())..];
    let pad = if keyframe {
        KEYFRAME_SPAN.saturating_sub(VP9_HEAD.len() + body.len() + TRAILER_LEN)
    } else {
        0
    };
    dst.clear();
    dst.reserve(VP9_HEAD.len() + pad + body.len() + TRAILER_LEN);
    dst.extend_from_slice(&VP9_HEAD);
    dst.resize(VP9_HEAD.len() + pad, 0);
    dst.extend_from_slice(body);
    #[allow(clippy::cast_possible_truncation)]
    let head = (VP9_HEAD.len() + pad) as u16;
    dst.extend_from_slice(&head.to_be_bytes());
}

/// `vp9Undress`: the transport's view of a VP9 sample (the epoch header
/// at [`TOKEN_OFF`] as in a VP8 frame), or `None` for a sample that is
/// not one of ours.
#[must_use]
pub fn undress(sample: &[u8]) -> Option<&[u8]> {
    let n = sample.len();
    if n < TRAILER_LEN {
        return None;
    }
    let head = usize::from(u16::from_be_bytes([sample[n - 2], sample[n - 1]]));
    if head < TOKEN_OFF || head + EPOCH_HDR_LEN - TOKEN_OFF + TRAILER_LEN > n {
        return None;
    }
    Some(&sample[head - TOKEN_OFF..n - TRAILER_LEN])
}

/// `vp9Payloader`: libwebrtc's single-layer VP9 keyframe packetization:
/// flexible mode, a 15-bit picture id, the scalability structure on the
/// first packet.
#[derive(Debug, Clone)]
pub struct Payloader {
    picture_id: u16,
}

impl Payloader {
    /// `newVP9Payloader`: a random first picture id.
    #[must_use]
    pub fn new() -> Self {
        Self::with_picture_id(rand::random::<u16>())
    }

    /// A payloader whose next picture id is `id` (masked to 15 bits).
    #[must_use]
    pub fn with_picture_id(id: u16) -> Self {
        Self {
            picture_id: id & 0x7fff,
        }
    }

    /// The picture id the next sample gets.
    #[must_use]
    pub fn picture_id(&self) -> u16 {
        self.picture_id
    }

    /// `Payload`: the packets' payloads for one sample at payload MTU `mtu`.
    pub fn payload(&mut self, mtu: usize, sample: &[u8]) -> Vec<Vec<u8>> {
        if sample.is_empty() || mtu <= DESCRIPTOR_LEN + STRUCTURE_LEN {
            return Vec::new();
        }
        let id = self.picture_id;
        self.picture_id = (self.picture_id + 1) & 0x7fff;
        let mut packets = Vec::with_capacity(sample.len() / mtu + 1);
        let mut rest = sample;
        let mut first = true;
        while !rest.is_empty() {
            let hdr_len = DESCRIPTOR_LEN + if first { STRUCTURE_LEN } else { 0 };
            let n = rest.len().min(mtu - hdr_len);
            let mut pkt = vec![0u8; hdr_len];
            pkt.reserve(n);
            pkt[0] = FLAG_PICTURE_ID | FLAG_FLEXIBLE | FLAG_NOT_REF;
            pkt[1..3].copy_from_slice(&(LONG_PICTURE_ID | id).to_be_bytes());
            if first {
                pkt[0] |= FLAG_BEGIN | FLAG_STRUCTURE;
                pkt[3] = ONE_LAYER_SIZED;
                pkt[4..6].copy_from_slice(&HEAD_WIDTH.to_be_bytes());
                pkt[6..8].copy_from_slice(&HEAD_HEIGHT.to_be_bytes());
            }
            if n == rest.len() {
                pkt[0] |= FLAG_END;
            }
            pkt.extend_from_slice(&rest[..n]);
            packets.push(pkt);
            rest = &rest[n..];
            first = false;
        }
        packets
    }
}

impl Default for Payloader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{epoch_header, parse_epoch_header};

    #[test]
    fn dress_and_undress_round_trip() {
        let mut frame = epoch_header(1, 2, 3).to_vec();
        frame.extend_from_slice(b"kcp bytes");
        let mut d = Vec::new();
        dress(&mut d, &frame, false);
        assert_eq!(&d[..68], &VP9_HEAD);
        assert_eq!(d.len(), 68 + 16 + 9 + 2);
        let u = undress(&d).unwrap();
        assert_eq!(&u[TOKEN_OFF..], &frame[TOKEN_OFF..]);
        assert!(parse_epoch_header(u).is_some());

        dress(&mut d, &frame, true);
        assert_eq!(
            d.len(),
            KEYFRAME_SPAN,
            "a keyframe spans more than a packet"
        );
        assert!(d[68..68 + 100].iter().all(|&b| b == 0));
        assert_eq!(&undress(&d).unwrap()[TOKEN_OFF..], &frame[TOKEN_OFF..]);

        assert_eq!(undress(&[0]), None);
        assert_eq!(
            undress(&[0, 5]),
            None,
            "a head shorter than the token offset"
        );
        assert_eq!(undress(&[0, 30, 0, 0]), None, "a head past the sample");
    }

    #[test]
    fn the_payloader_announces_one_sized_layer_and_wraps_the_id() {
        let mut p = Payloader::with_picture_id(0x7fff);
        let sample = vec![7u8; 2500];
        let pkts = p.payload(1188, &sample);
        assert_eq!(pkts.len(), 3);
        assert_eq!(
            &pkts[0][..8],
            &[
                0x80 | 0x10 | 0x01 | 0x08 | 0x02,
                0xff,
                0xff,
                0x10,
                0x01,
                0x40,
                0x00,
                0xb4
            ]
        );
        assert_eq!(pkts[0].len(), 1188);
        assert_eq!(&pkts[1][..3], &[0x91, 0xff, 0xff]);
        assert_eq!(pkts[2][0], 0x91 | 0x04);
        let total: usize = pkts
            .iter()
            .enumerate()
            .map(|(i, k)| k.len() - if i == 0 { 8 } else { 3 })
            .sum();
        assert_eq!(total, 2500);
        let next = p.payload(1188, b"x");
        assert_eq!(
            &next[0][..3],
            &[0x80 | 0x10 | 0x01 | 0x08 | 0x02 | 0x04, 0x80, 0x00]
        );
        assert!(p.payload(8, b"x").is_empty());
        assert!(p.payload(1188, b"").is_empty());
    }
}

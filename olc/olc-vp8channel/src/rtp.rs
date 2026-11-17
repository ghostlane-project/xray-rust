// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What pion makes of a sample the transport writes (W36): the track's
//! `WriteSample` (`webrtc/v4@v4.2.15/track_local_static.go:343-383`), its
//! packetizer (`rtp@v1.10.2/packetizer.go`) and the VP8 payloader with
//! picture ids on (`codecs/vp8_packet.go`, `mediaengine.go:826`), so the RTP
//! packets the Rust client hands its WebRTC stack are the ones a Go client
//! sends: the same descriptors, sizes, markers and timestamps.

/// `rtpOutboundMTU` (`webrtc/v4 constants.go:41`).
pub const RTP_OUTBOUND_MTU: usize = 1200;
/// The fixed RTP header pion takes off the MTU before the payloader.
pub const RTP_HEADER_LEN: usize = 12;
/// The payload MTU the payloader is given: 1188.
pub const PAYLOAD_MTU: usize = RTP_OUTBOUND_MTU - RTP_HEADER_LEN;
/// The video clock.
pub const CLOCK_RATE: f64 = 90_000.0;

/// `codecs.VP8Payloader{EnablePictureID: true}`.
#[derive(Debug, Clone, Default)]
pub struct Vp8Payloader {
    picture_id: u16,
}

impl Vp8Payloader {
    /// A payloader whose next picture id is `id` (pion starts at 0).
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

    /// `Payload`: picture id 0 has no id at all (a 1-byte descriptor), 1-127
    /// a 7-bit one (3 bytes), from 128 a 15-bit one (4 bytes); S on the
    /// first packet. The id moves on after every sample.
    pub fn payload(&mut self, mtu: usize, payload: &[u8]) -> Vec<Vec<u8>> {
        let header = match self.picture_id {
            0 => 1,
            1..=127 => 3,
            _ => 4,
        };
        let max_fragment = mtu.saturating_sub(header);
        let mut out = Vec::new();
        if max_fragment.min(payload.len()) == 0 {
            // Go returns before moving the picture id on.
            return out;
        }
        let mut rest = payload;
        let mut first = true;
        while !rest.is_empty() {
            let n = max_fragment.min(rest.len());
            let mut pkt = vec![0u8; header + n];
            if first {
                pkt[0] = 0x10;
                first = false;
            }
            match header {
                3 => {
                    pkt[0] |= 0x80;
                    pkt[1] |= 0x80;
                    #[allow(clippy::cast_possible_truncation)]
                    let id = (self.picture_id & 0x7f) as u8;
                    pkt[2] |= id;
                }
                4 => {
                    pkt[0] |= 0x80;
                    pkt[1] |= 0x80;
                    #[allow(clippy::cast_possible_truncation)]
                    let hi = ((self.picture_id >> 8) & 0x7f) as u8;
                    pkt[2] |= 0x80 | hi;
                    #[allow(clippy::cast_possible_truncation)]
                    let lo = (self.picture_id & 0xff) as u8;
                    pkt[3] |= lo;
                }
                _ => {}
            }
            pkt[header..].copy_from_slice(&rest[..n]);
            out.push(pkt);
            rest = &rest[n..];
        }
        self.picture_id = (self.picture_id + 1) & 0x7fff;
        out
    }
}

/// One RTP packet to write: the header fields pion sets and the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    /// Sequence number.
    pub seq: u16,
    /// RTP timestamp.
    pub timestamp: u32,
    /// Set on the last packet of a sample.
    pub marker: bool,
    /// Descriptor and bytes.
    pub payload: Vec<u8>,
}

/// The payloaders the track can run.
#[derive(Debug, Clone)]
pub enum Payloader {
    /// The transport's own VP8.
    Vp8(Vp8Payloader),
    /// The VP9 carrier's (`carrier.go`).
    Vp9(crate::vp9::Payloader),
}

impl Payloader {
    fn payload(&mut self, mtu: usize, sample: &[u8]) -> Vec<Vec<u8>> {
        match self {
            Self::Vp8(p) => p.payload(mtu, sample),
            Self::Vp9(p) => p.payload(mtu, sample),
        }
    }
}

/// `TrackLocalStaticSample` with its packetizer: sequence numbers from a
/// random start, the timestamp moved on by each sample's duration in 90 kHz
/// ticks with the fraction carried (`remainder`).
#[derive(Debug, Clone)]
pub struct Packetizer {
    payloader: Payloader,
    seq: u16,
    timestamp: u32,
    remainder: f64,
}

impl Packetizer {
    /// A packetizer starting at `seq` and `timestamp` (pion picks both at
    /// random).
    #[must_use]
    pub fn new(payloader: Payloader, seq: u16, timestamp: u32) -> Self {
        Self {
            payloader,
            seq,
            timestamp,
            remainder: 0.0,
        }
    }

    /// [`Packetizer::new`] with pion's random starts.
    #[must_use]
    pub fn random(payloader: Payloader) -> Self {
        Self::new(payloader, rand::random(), rand::random())
    }

    /// `WriteSample(Sample{Data, Duration})`: the packets of one sample.
    /// An empty sample only moves the timestamp on (`SkipSamples`).
    pub fn packetize(&mut self, sample: &[u8], duration_ns: i64) -> Vec<RtpPacket> {
        #[allow(clippy::cast_precision_loss)]
        let tick = duration_ns as f64 / 1e9 * CLOCK_RATE;
        let total = tick + self.remainder;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ticks = total as u32;
        self.remainder = total - f64::from(ticks);
        if sample.is_empty() {
            self.timestamp = self.timestamp.wrapping_add(ticks);
            return Vec::new();
        }
        let payloads = self.payloader.payload(PAYLOAD_MTU, sample);
        let last = payloads.len().saturating_sub(1);
        let out = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                let seq = self.seq;
                self.seq = self.seq.wrapping_add(1);
                RtpPacket {
                    seq,
                    timestamp: self.timestamp,
                    marker: i == last,
                    payload,
                }
            })
            .collect();
        self.timestamp = self.timestamp.wrapping_add(ticks);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picture_ids_grow_their_descriptor() {
        let mut p = Vp8Payloader::default();
        let a = p.payload(PAYLOAD_MTU, &[1, 2, 3]);
        assert_eq!(a, [vec![0x10, 1, 2, 3]], "id 0: no id");
        let b = p.payload(PAYLOAD_MTU, &[9]);
        assert_eq!(b, [vec![0x90, 0x80, 0x01, 9]]);
        let mut p = Vp8Payloader::with_picture_id(0x1234);
        let c = p.payload(PAYLOAD_MTU, &vec![5u8; 2400]);
        assert_eq!(c.len(), 3);
        assert_eq!(&c[0][..4], &[0x90, 0x80, 0x92, 0x34]);
        assert_eq!(&c[1][..4], &[0x80, 0x80, 0x92, 0x34], "S only on the first");
        assert_eq!(c[0].len(), PAYLOAD_MTU);
        assert_eq!(c[2].len(), 4 + 2400 - 2 * (PAYLOAD_MTU - 4));
        let mut p = Vp8Payloader::with_picture_id(0x7fff);
        p.payload(PAYLOAD_MTU, &[0]);
        assert_eq!(
            p.payload(PAYLOAD_MTU, &[0])[0][0],
            0x10,
            "wrapped back to 0"
        );
        assert!(p.payload(PAYLOAD_MTU, &[]).is_empty());
    }

    #[test]
    fn timestamps_carry_the_fraction_and_markers_end_samples() {
        let mut k = Packetizer::new(Payloader::Vp8(Vp8Payloader::default()), 65535, 100);
        let fi = 1_000_000_000 / 60;
        let a = k.packetize(&vec![0u8; 3000], fi);
        assert_eq!(
            a.iter().map(|p| (p.seq, p.marker)).collect::<Vec<_>>(),
            [(65535, false), (0, false), (1, true)]
        );
        assert!(a.iter().all(|p| p.timestamp == 100));
        let b = k.packetize(b"x", fi);
        // 16 666 666 ns is 1499.99994 ticks: 1499 now, the fraction carried.
        assert_eq!(b[0].timestamp, 100 + 1499);
        let mut ts = b[0].timestamp;
        for _ in 0..20_000 {
            ts = k.packetize(b"x", fi)[0].timestamp;
        }
        assert!(ts > 100 + 1499 * 20_001, "the carried fraction adds up");
        let before = k.timestamp;
        assert!(k.packetize(b"", fi).is_empty());
        assert!(
            k.timestamp > before,
            "an empty sample still moves the clock"
        );
    }
}

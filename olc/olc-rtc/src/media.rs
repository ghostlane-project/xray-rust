// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Media on a [`Peer`]: what an engine with a video line does around
//! str0m's RTP mode, in one place (the P2P lab lane, MTS Link, VK Calls).
//!
//! - before the peer is built, its codecs and header extensions
//!   ([`with_codecs`], [`with_extensions`], for [`Peer::start_tuned`]): an
//!   SDP from this end then names the payload types and extension ids the
//!   Go engine's names;
//! - out, a [`SendLine`]: whole RTP packets written on one stream (a mid,
//!   and a rid when the stream is one layer of several), each with the
//!   extended sequence number str0m wants, each kept for a resend
//!   ([`ResendCache`]);
//! - in, the packets go to the peer's [`crate::peer::RtpSink`]; the video
//!   ones are counted on the way ([`Peer::video_packets_in`]).
//!
//! # Memory
//!
//! A [`SendLine`] is a few words and holds no packet. What a line keeps is
//! in str0m:
//!
//! - the resend cache: at most [`ResendCache::packets`] packets for
//!   [`ResendCache::age`], so its bound is the caller's, set before the first
//!   write ([`SendLine::size_resends`]);
//! - the packets written and not yet handed to the transport, at most
//!   [`SEND_BACKLOG_PACKETS`] of [`SEND_PACKET_MAX`] bytes
//!   ([`SEND_BACKLOG_MAX`] in all). str0m's own queue has no bound, and
//!   over ICE-TCP a slow socket keeps the driver from emptying it
//!   ([`crate::icetcp`]), so [`SendLine::write`] reads its length (the
//!   vendored str0m's `queued_packets`) and refuses, before anything is
//!   queued, the batch that would pass the bound. A refused packet is
//!   counted ([`Peer::rtp_refused`]) and gone, as one a full UDP socket
//!   drops; pion's track over a TCP candidate blocks its writer instead.
//!
//! A written packet's payload moves into str0m without a copy.

use std::time::{Duration, Instant};

use str0m::format::{Codec, CodecConfig, FormatParams};
use str0m::media::{Frequency, Mid, Pt, Rid};
use str0m::rtp::{Extension, RtpWrite, SeqNo, Ssrc};
use str0m::RtcConfig;

use crate::peer::Peer;

/// The packets one send stream holds at most, written and not yet handed to
/// the transport ([`SendLine::write`] refuses a batch that would pass it).
/// Over UDP the driver hands every packet out at once and the count stays
/// near nothing; over ICE-TCP a socket that takes less than is written
/// holds the driver back ([`crate::icetcp`]) and the packets wait in str0m,
/// whose queue has no bound of its own. 256 packets are five of the largest
/// samples vp8channel writes (60 KiB each), a quarter of a second at
/// 10 Mbit/s.
pub const SEND_BACKLOG_PACKETS: usize = 256;

/// The longest payload a send line takes: the Go engine's tracks packetize
/// at pion's outbound MTU of 1200 bytes, header included
/// (`vp8channel/rtp.go` `rtpOutboundMTU`), so no packet it writes is longer.
pub const SEND_PACKET_MAX: usize = 1200;

/// What a waiting packet costs beside its payload: str0m's own record of
/// it (header, extension values, times; 408 bytes on a 64-bit target). A
/// test holds its `size_of` under this.
pub const SEND_PACKET_SLOT: usize = 416;

/// What one send stream's waiting packets hold at most, in bytes (the
/// budget's row). A payload's capacity beyond its length is its writer's.
pub const SEND_BACKLOG_MAX: usize = SEND_BACKLOG_PACKETS * (SEND_PACKET_MAX + SEND_PACKET_SLOT);

// The budget's row for one send stream stays under half a mebibyte.
const _: () = assert!(SEND_BACKLOG_MAX <= 512 << 10);

/// One payload type a peer is built with.
#[derive(Debug, Clone)]
pub struct CodecLine {
    /// The payload type.
    pub pt: u8,
    /// Its resend (RTX) payload type; `None` names no RTX, and a lost
    /// packet is resent on its own SSRC (the vendored str0m's plain resend).
    pub resend: Option<u8>,
    /// The codec.
    pub codec: Codec,
    /// The RTP clock.
    pub clock_rate: Frequency,
    /// The channels (audio).
    pub channels: Option<u8>,
    /// The `a=fmtp` values.
    pub format: FormatParams,
}

impl CodecLine {
    /// A video codec on the 90 kHz clock.
    #[must_use]
    pub fn video(pt: u8, resend: Option<u8>, codec: Codec, format: FormatParams) -> Self {
        Self {
            pt,
            resend,
            codec,
            clock_rate: Frequency::NINETY_KHZ,
            channels: None,
            format,
        }
    }

    /// `red` on a video line (RFC 2198 around a video codec, as VK's SFU
    /// forwards a camera): a payload type of its own with its RTX, which the
    /// vendored str0m negotiates and, in RTP mode, hands up as it came, the
    /// RED header still on it (`olc/vendor/str0m-0.25.0/XRAY-PATCH.md`). It
    /// is only read: nothing here writes RED.
    #[must_use]
    pub fn video_red(pt: u8, resend: Option<u8>) -> Self {
        Self::video(pt, resend, Codec::Red, FormatParams::default())
    }

    /// Opus: 48 kHz, two channels (`opus/48000/2`).
    #[must_use]
    pub fn opus(pt: u8, format: FormatParams) -> Self {
        Self {
            pt,
            resend: None,
            codec: Codec::Opus,
            clock_rate: Frequency::FORTY_EIGHT_KHZ,
            channels: Some(2),
            format,
        }
    }
}

/// `config` with `codecs` as its only payload types, in that order (str0m's
/// own set is dropped). str0m gives every video codec `nack`, `nack pli`,
/// `ccm fir`, `goog-remb` and `transport-cc` feedback, and audio
/// `transport-cc`.
#[must_use]
pub fn with_codecs(config: RtcConfig, codecs: &[CodecLine]) -> RtcConfig {
    let mut config = config.clear_codecs();
    let table = config.codec_config();
    for c in codecs {
        table.add_config(
            c.pt.into(),
            c.resend.map(Pt::from),
            c.codec,
            c.clock_rate,
            c.channels,
            c.format,
        );
    }
    config
}

/// `config` with `extensions` (id, extension) as its only RTP header
/// extensions (str0m's standard set, Chrome's ids, is dropped). An extension
/// left out is neither offered nor written on a packet. An id outside 1-14
/// is ignored by str0m.
#[must_use]
pub fn with_extensions(config: RtcConfig, extensions: &[(u8, Extension)]) -> RtcConfig {
    extensions
        .iter()
        .fold(config.clear_extension_map(), |config, (id, ext)| {
            config.set_extension(*id, ext.clone())
        })
}

/// Whether RTP at `pt` is video by the peer's payload table: its own
/// payload type, its RTX one or its RED one, as str0m finds a packet's
/// parameters (`main_payload_params`). `red` with parameters of its own is
/// video's ([`CodecLine::video_red`]); audio's RED hangs on its codec.
pub(crate) fn is_video(table: &CodecConfig, pt: Pt) -> bool {
    table
        .params()
        .iter()
        .find(|p| p.pt() == pt || p.resend() == Some(pt) || p.red() == Some(pt))
        .is_some_and(|p| {
            let codec = p.spec().codec;
            codec.is_video() || codec == Codec::Red
        })
}

/// What a send stream keeps for resends (str0m's `set_rtx_cache`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResendCache {
    /// The newest packets kept, at most.
    pub packets: usize,
    /// How long a packet is kept.
    pub age: Duration,
    /// The share of resends in what is sent past which str0m drops the
    /// queued ones; `None` sends every one.
    pub ratio_cap: Option<f32>,
}

/// One RTP packet to write: what a packetizer makes of a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpOut {
    /// The 16-bit sequence number.
    pub seq: u16,
    /// The RTP timestamp.
    pub timestamp: u32,
    /// The marker bit.
    pub marker: bool,
    /// The payload (no header).
    pub payload: Vec<u8>,
}

/// The extended sequence number of a packet numbered `seq` written after the
/// one extended to `last`: the first is its own number, a later one is as
/// far ahead of `last` as `seq` is ahead of `last`'s low 16 bits, so the
/// rollover counter moves when `seq` wraps. Packets go in order: one behind
/// `last` would read as almost a whole cycle ahead.
#[must_use]
pub fn extend_seq(last: Option<u64>, seq: u16) -> u64 {
    match last {
        None => u64::from(seq),
        #[allow(clippy::cast_possible_truncation)]
        Some(last) => last + u64::from(seq.wrapping_sub(last as u16)),
    }
}

/// The send side of one stream of a peer: the line (mid), the layer (rid)
/// when there are several, the payload type its packets go with, and where
/// the sequence stands. One per peer connection: a new peer starts a new one.
#[derive(Debug, Clone)]
pub struct SendLine {
    mid: Mid,
    rid: Option<Rid>,
    pt: Pt,
    /// The extended sequence number of the last packet written.
    last: Option<u64>,
}

impl SendLine {
    /// The stream `(mid, rid)` of a negotiated line, written at `pt`. The
    /// stream itself is str0m's: made by the negotiation for a line without
    /// rids, by [`SendLine::declare`] otherwise. Without a rid str0m takes
    /// any stream of the line, so a line that has layers is named with one.
    #[must_use]
    pub fn new(mid: Mid, rid: Option<Rid>, pt: Pt) -> Self {
        Self {
            mid,
            rid,
            pt,
            last: None,
        }
    }

    /// [`SendLine::new`] for a stream the negotiation did not make (a layer
    /// named by a rid, a line whose answer is not str0m's): declares it on
    /// `peer` with a fresh SSRC, and a fresh RTX SSRC with `rtx`, unless it
    /// is there already. `None` when the peer has no line `mid`.
    #[must_use]
    pub fn declare(peer: &Peer, mid: Mid, rid: Option<Rid>, pt: Pt, rtx: bool) -> Option<Self> {
        peer.with_rtc(|rtc| {
            rtc.media(mid)?;
            let mut api = rtc.direct_api();
            if api.stream_tx_by_mid(mid, rid).is_none() {
                let ssrc = api.new_ssrc();
                let rtx = rtx.then(|| loop {
                    let other = api.new_ssrc();
                    if other != ssrc {
                        break other;
                    }
                });
                api.declare_stream_tx(ssrc, rtx, mid, rid);
            }
            Some(())
        })?;
        Some(Self::new(mid, rid, pt))
    }

    /// The line.
    #[must_use]
    pub fn mid(&self) -> Mid {
        self.mid
    }

    /// The layer.
    #[must_use]
    pub fn rid(&self) -> Option<Rid> {
        self.rid
    }

    /// The payload type written.
    #[must_use]
    pub fn pt(&self) -> Pt {
        self.pt
    }

    /// The stream's SSRC and RTX SSRC on `peer`; `None` without the stream.
    #[must_use]
    pub fn ssrcs(&self, peer: &Peer) -> Option<(Ssrc, Option<Ssrc>)> {
        peer.with_rtc(|rtc| {
            rtc.direct_api()
                .stream_tx_by_mid(self.mid, self.rid)
                .map(|tx| (tx.ssrc(), tx.rtx()))
        })
    }

    /// Sizes the stream's resend cache; call it before the first write (it
    /// empties what the cache holds). `false` without the stream.
    pub fn size_resends(&self, peer: &Peer, cache: ResendCache) -> bool {
        peer.with_rtc(|rtc| {
            let mut api = rtc.direct_api();
            let Some(tx) = api.stream_tx_by_mid(self.mid, self.rid) else {
                return false;
            };
            tx.set_rtx_cache(cache.packets, cache.age, cache.ratio_cap);
            true
        })
    }

    /// Has every packet of the stream carry its mid and rid, where str0m
    /// leaves both out once the receiver has reported on the SSRC (the
    /// vendored str0m's `set_mid_rid_on_every_packet`). For a far end that
    /// binds the stream by its rid and is never told an SSRC: VK's SFU, to
    /// which the Go engine's stamper writes both on every packet
    /// (`vkcalls/stamp.go`). `false` without the stream.
    pub fn keep_mid_rid(&self, peer: &Peer) -> bool {
        peer.with_rtc(|rtc| {
            let mut api = rtc.direct_api();
            let Some(tx) = api.stream_tx_by_mid(self.mid, self.rid) else {
                return false;
            };
            tx.set_mid_rid_on_every_packet(true);
            true
        })
    }

    /// The packets written on the stream that str0m still holds, not yet
    /// handed to the transport; `None` without the stream.
    #[must_use]
    pub fn backlog(&self, peer: &Peer) -> Option<usize> {
        peer.with_rtc(|rtc| {
            rtc.direct_api()
                .stream_tx_by_mid(self.mid, self.rid)
                .map(|tx| tx.queued_packets())
        })
    }

    /// Writes `packets` in order, each kept for a resend (`nackable`), all
    /// stamped `wallclock`, under one lock of the peer. Returns how many
    /// went to str0m; `None`, and nothing taken off the sequence, when the
    /// peer has no such stream.
    ///
    /// The batch (one sample's packets) goes whole or not at all: when the
    /// stream would hold more than [`SEND_BACKLOG_PACKETS`] with it, none
    /// of it is written (`Some(0)`), so a transport slower than its writer
    /// loses whole samples and never the middle of one. A packet longer
    /// than [`SEND_PACKET_MAX`] is left out by itself. What was not written
    /// is counted in [`Peer::rtp_refused`] and takes no sequence number
    /// here: the receiver sees the gap the caller's numbering leaves.
    pub fn write<I>(&mut self, peer: &Peer, wallclock: Instant, packets: I) -> Option<usize>
    where
        I: IntoIterator<Item = RtpOut>,
        I::IntoIter: ExactSizeIterator,
    {
        let packets = packets.into_iter();
        let offered = packets.len();
        let (pt, mut last) = (self.pt, self.last);
        let written = peer.with_rtc(|rtc| {
            let mut api = rtc.direct_api();
            let tx = api.stream_tx_by_mid(self.mid, self.rid)?;
            // Before anything is queued: what the stream holds already.
            if tx.queued_packets() + offered > SEND_BACKLOG_PACKETS {
                return Some(0);
            }
            let mut n = 0;
            for p in packets {
                if p.payload.len() > SEND_PACKET_MAX {
                    continue;
                }
                let seq = extend_seq(last, p.seq);
                last = Some(seq);
                tx.write_rtp(
                    RtpWrite::new(pt, SeqNo::from(seq), p.timestamp, wallclock, p.payload)
                        .marker(p.marker)
                        .nackable(true),
                );
                n += 1;
            }
            Some(n)
        })?;
        self.last = last;
        if written < offered {
            peer.note_rtp_refused(offered - written);
        }
        Some(written)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use str0m::change::SdpOffer;
    use str0m::media::{Direction, MediaKind};
    use str0m::rtp::RtpPacket;
    use str0m::Candidate;
    use tokio::sync::mpsc;

    use super::*;
    use crate::peer::{PeerConfig, PeerEvent};
    use crate::testing::bounded;
    use crate::DtlsVersion;

    fn config(name: &'static str) -> PeerConfig {
        PeerConfig {
            name,
            crypto: crate::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            sctp_max_buffered: 64 << 10,
            turn: Vec::new(),
            relay_only: false,
            ice_mode: crate::peer::IceMode::Udp,
        }
    }

    /// What a sink saw of one packet.
    type Seen = (u8, u16, bool, Vec<u8>);

    /// Two peers on loopback, connected, `a` having offered the lines of
    /// `kinds`; returns both, the lines' mids and what reaches `b`'s sink.
    async fn lines(kinds: &[MediaKind]) -> (Peer, Peer, Vec<Mid>, mpsc::UnboundedReceiver<Seen>) {
        crate::init();
        let (a, mut a_rx) = Peer::start(&config("a")).unwrap();
        let (b, mut b_rx) = Peer::start(&config("b")).unwrap();
        let (got_tx, got) = mpsc::unbounded_channel();
        b.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
            let _ = got_tx.send((
                *p.header.payload_type,
                p.header.sequence_number,
                p.header.marker,
                p.payload.to_vec(),
            ));
        })));
        let (offer, pending, mids) = a.with_rtc(|rtc| {
            let mut api = rtc.sdp_api();
            let mids: Vec<Mid> = kinds
                .iter()
                .map(|k| api.add_media(*k, Direction::SendRecv, None, None, None))
                .collect();
            let (offer, pending) = api.apply().unwrap();
            (offer, pending, mids)
        });
        let offer = SdpOffer::from_sdp_string(&offer.to_sdp_string()).unwrap();
        let answer = b.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer)).unwrap();
        a.with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer))
            .unwrap();
        let ca = Candidate::from_sdp_string(&a.add_host_candidate().unwrap()).unwrap();
        let cb = Candidate::from_sdp_string(&b.add_host_candidate().unwrap()).unwrap();
        a.add_remote_candidate(cb);
        b.add_remote_candidate(ca);
        let mut up = (false, false);
        while !(up.0 && up.1) {
            tokio::select! {
                Some(e) = a_rx.recv() => match e {
                    PeerEvent::Connected => up.0 = true,
                    PeerEvent::Closed(r) => panic!("a closed: {r}"),
                    _ => {}
                },
                Some(e) = b_rx.recv() => match e {
                    PeerEvent::Connected => up.1 = true,
                    PeerEvent::Closed(r) => panic!("b closed: {r}"),
                    _ => {}
                },
            }
        }
        // The drivers end when their queues' receivers go: keep them.
        tokio::spawn(async move { while a_rx.recv().await.is_some() {} });
        tokio::spawn(async move { while b_rx.recv().await.is_some() {} });
        (a, b, mids, got)
    }

    fn pt_of(peer: &Peer, codec: Codec) -> Pt {
        peer.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == codec)
                .unwrap()
                .pt()
        })
    }

    fn packets(first: u16, n: u16) -> Vec<RtpOut> {
        (0..n)
            .map(|i| RtpOut {
                seq: first.wrapping_add(i),
                timestamp: 3000 * u32::from(i),
                marker: i % 4 == 3,
                payload: vec![0x90, 0x80, u8::try_from(i).unwrap(), 7, 7],
            })
            .collect()
    }

    /// The extended number follows the 16-bit one across its wrap, twice.
    #[test]
    fn the_extended_sequence_follows_the_wrap() {
        assert_eq!(extend_seq(None, 65_534), 65_534);
        assert_eq!(extend_seq(Some(65_534), 65_535), 65_535);
        assert_eq!(extend_seq(Some(65_535), 0), 65_536);
        assert_eq!(extend_seq(Some(65_536), 1), 65_537);
        assert_eq!(extend_seq(Some(131_071), 0), 131_072);
        // A gap the caller left stays a gap.
        assert_eq!(extend_seq(Some(65_535), 4), 65_540);
        assert_eq!(extend_seq(None, 0), 0);
    }

    /// The budget's figure for a waiting packet covers str0m's record of
    /// one.
    #[test]
    fn a_waiting_packets_slot_covers_str0ms_record() {
        assert!(
            size_of::<str0m::rtp::RtpPacket>() <= SEND_PACKET_SLOT,
            "str0m's RtpPacket is {} bytes",
            size_of::<str0m::rtp::RtpPacket>()
        );
    }

    /// A stream holds [`SEND_BACKLOG_PACKETS`] and no more: the batch that
    /// would pass it is refused whole, a packet too long is left out by
    /// itself, both are counted, and the sequence goes on from what was
    /// taken. (The peer is not connected, so nothing leaves the stream.)
    #[tokio::test]
    async fn a_full_send_line_refuses_the_batch_whole() {
        bounded(async {
            crate::init();
            let (a, _rx) = Peer::start(&config("a")).unwrap();
            let (mid, mid2): (Mid, Mid) = ("v1".into(), "v2".into());
            a.with_rtc(|rtc| {
                let mut api = rtc.direct_api();
                api.declare_media(mid, MediaKind::Video);
                api.declare_media(mid2, MediaKind::Video);
            });
            let pt = pt_of(&a, Codec::Vp8);
            let mut line = SendLine::declare(&a, mid, None, pt, false).unwrap();
            assert_eq!(line.backlog(&a), Some(0));
            let many = |first: u16, n: usize| -> Vec<RtpOut> {
                (0..n)
                    .map(|i| RtpOut {
                        seq: first.wrapping_add(u16::try_from(i).unwrap()),
                        timestamp: 0,
                        marker: false,
                        payload: vec![0x90; 1100],
                    })
                    .collect()
            };
            // Up to the bound, in three batches.
            assert_eq!(line.write(&a, Instant::now(), many(0, 200)), Some(200));
            assert_eq!(line.write(&a, Instant::now(), many(200, 50)), Some(50));
            // Seven would pass it: none of them goes.
            assert_eq!(line.write(&a, Instant::now(), many(250, 7)), Some(0));
            assert_eq!((line.backlog(&a), a.rtp_refused()), (Some(250), 7));
            // Six fit, to the packet.
            assert_eq!(line.write(&a, Instant::now(), many(257, 6)), Some(6));
            assert_eq!(line.backlog(&a), Some(SEND_BACKLOG_PACKETS));
            assert_eq!(line.write(&a, Instant::now(), many(263, 1)), Some(0));
            // A batch larger than the bound never fits, on an empty stream
            // either; a packet too long is left out by itself.
            let mut other = SendLine::declare(&a, mid2, None, pt, false).unwrap();
            assert_eq!(
                other.write(&a, Instant::now(), many(0, SEND_BACKLOG_PACKETS + 1)),
                Some(0)
            );
            let mut mixed = many(0, 3);
            mixed[1].payload = vec![0x90; SEND_PACKET_MAX + 1];
            assert_eq!(other.write(&a, Instant::now(), mixed), Some(2));
            assert_eq!(other.backlog(&a), Some(2));
            let refused = 7 + 1 + u64::try_from(SEND_BACKLOG_PACKETS).unwrap() + 1 + 1;
            assert_eq!(a.rtp_refused(), refused);
            // The line that was full is still at its bound.
            assert_eq!(line.backlog(&a), Some(SEND_BACKLOG_PACKETS));
            a.close();
        })
        .await;
    }

    /// A send line is a few words: an engine keeps one per peer connection.
    #[test]
    fn a_send_line_stays_small() {
        assert!(
            size_of::<SendLine>() <= 48,
            "SendLine is {} bytes",
            size_of::<SendLine>()
        );
    }

    /// The payload table says what is video: a video codec's own payload
    /// type and its RTX one, not audio's, not one nobody named.
    #[test]
    fn video_is_told_by_the_payload_table() {
        let mut config = with_codecs(
            RtcConfig::new(),
            &[
                CodecLine::opus(111, FormatParams::default()),
                CodecLine::video(98, Some(99), Codec::Vp9, FormatParams::default()),
                CodecLine::video_red(104, Some(105)),
            ],
        );
        let table = config.codec_config();
        assert!(is_video(table, 98.into()));
        assert!(is_video(table, 99.into()));
        // Video wrapped in RED, and that stream's RTX.
        assert!(is_video(table, 104.into()));
        assert!(is_video(table, 105.into()));
        assert!(!is_video(table, 111.into()));
        assert!(!is_video(table, 96.into()));
    }

    /// A peer built with MTS Link's codecs and pion's extension ids offers
    /// those and no others (Go `mtslink.go:210-242`, pion's default header
    /// extensions): VP9 98 `profile-id=0` resent at 99, opus 111, mid 1,
    /// rid 2, repaired rid 3, transport-cc 4, no abs-send-time.
    #[tokio::test]
    async fn a_peer_offers_the_codecs_and_extensions_it_was_given() {
        bounded(async {
            crate::init();
            let codecs = [
                CodecLine::opus(
                    111,
                    FormatParams {
                        min_p_time: Some(10),
                        use_inband_fec: Some(true),
                        ..FormatParams::default()
                    },
                ),
                CodecLine::video(
                    98,
                    Some(99),
                    Codec::Vp9,
                    FormatParams {
                        profile_id: Some(0),
                        ..FormatParams::default()
                    },
                ),
            ];
            let extensions = [
                (1, Extension::RtpMid),
                (2, Extension::RtpStreamId),
                (3, Extension::RepairedRtpStreamId),
                (4, Extension::TransportSequenceNumber),
            ];
            let (a, _rx) = Peer::start_tuned(&config("a"), |c| {
                with_extensions(with_codecs(c, &codecs), &extensions)
            })
            .unwrap();
            let offer = a.with_rtc(|rtc| {
                let mut api = rtc.sdp_api();
                api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
                api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
                api.apply().unwrap().0.to_sdp_string()
            });
            for line in [
                "a=rtpmap:111 opus/48000/2\r\n",
                "a=rtpmap:98 VP9/90000\r\n",
                "a=fmtp:98 profile-id=0\r\n",
                "a=rtpmap:99 rtx/90000\r\n",
                "a=fmtp:99 apt=98\r\n",
                "a=rtcp-fb:98 nack\r\n",
                "a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
                "a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n",
                "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n",
                "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
            ] {
                assert!(offer.contains(line), "no {line:?} in\n{offer}");
            }
            let fmtp = offer
                .lines()
                .find(|l| l.starts_with("a=fmtp:111 "))
                .unwrap_or_else(|| panic!("no opus fmtp in\n{offer}"));
            assert!(
                fmtp.contains("minptime=10") && fmtp.contains("useinbandfec=1"),
                "{fmtp}"
            );
            for word in ["VP8/90000", "H264/90000", "abs-send-time", "ssrc-audio-level", "a=extmap:10 "] {
                assert!(!offer.contains(word), "{word:?} in\n{offer}");
            }
            a.close();
        })
        .await;
    }

    /// Packets written through a send line reach the remote's sink whole and
    /// in their numbers across the 16-bit wrap, in two writes; the line
    /// names its stream, and its resend cache takes a size.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_send_line_writes_across_the_sequence_wrap() {
        bounded(async {
            let (a, b, mids, mut got) = lines(&[MediaKind::Video]).await;
            let pt = pt_of(&a, Codec::Vp8);
            let mut line = SendLine::new(mids[0], None, pt);
            assert!(line.ssrcs(&a).is_some());
            assert!(line.size_resends(
                &a,
                ResendCache {
                    packets: 257,
                    age: Duration::from_millis(300),
                    ratio_cap: Some(0.15),
                }
            ));
            let sent = packets(65_530, 20);
            assert_eq!(line.write(&a, Instant::now(), sent[..7].to_vec()), Some(7));
            assert_eq!(line.write(&a, Instant::now(), sent[7..].to_vec()), Some(13));
            assert_eq!(line.last, Some(65_530 + 19));
            let mut seen = Vec::new();
            while seen.len() < sent.len() {
                seen.push(got.recv().await.unwrap());
            }
            seen.sort_by_key(|(_, seq, ..)| seq.wrapping_sub(65_530));
            let want: Vec<Seen> = sent
                .into_iter()
                .map(|p| (*pt, p.seq, p.marker, p.payload))
                .collect();
            assert_eq!(seen, want);
            b.set_rtp_sink(None);
            a.close();
            b.close();
        })
        .await;
    }

    /// A line the peer does not have takes nothing and keeps its place; a
    /// layer declared on a line that is there is found, once, with an RTX
    /// SSRC of its own when asked, and takes packets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_line_without_a_stream_writes_nothing_and_a_declared_layer_does() {
        bounded(async {
            let (a, b, mids, _got) = lines(&[MediaKind::Video]).await;
            let pt = pt_of(&a, Codec::Vp8);
            let low = Rid::from("l");
            let mut absent = SendLine::new(mids[0], Some(low), pt);
            assert_eq!(absent.write(&a, Instant::now(), packets(10, 3)), None);
            assert_eq!(absent.last, None);
            assert!(absent.ssrcs(&a).is_none());
            assert!(!absent.size_resends(
                &a,
                ResendCache {
                    packets: 8,
                    age: Duration::from_millis(300),
                    ratio_cap: None,
                }
            ));
            assert!(SendLine::declare(&a, Mid::from("nope"), Some(low), pt, false).is_none());

            // The negotiation's own stream, asked for before the line has
            // two: a lookup without a rid takes any stream of the line.
            let (main, _) = SendLine::new(mids[0], None, pt).ssrcs(&a).unwrap();
            let mut layer = SendLine::declare(&a, mids[0], Some(low), pt, true).unwrap();
            let (ssrc, rtx) = layer.ssrcs(&a).unwrap();
            assert!(rtx.is_some_and(|r| r != ssrc));
            assert_ne!(ssrc, main);
            // Declared again, it is the same stream.
            let again = SendLine::declare(&a, mids[0], Some(low), pt, true).unwrap();
            assert_eq!(again.ssrcs(&a), Some((ssrc, rtx)));
            assert_eq!(layer.write(&a, Instant::now(), packets(10, 3)), Some(3));
            assert_eq!(layer.last, Some(12));
            a.close();
            b.close();
        })
        .await;
    }

    /// The peer counts the video packets it received and no others: the
    /// number VK Calls' performance report carries (Go `vkcalls.go:578-589`,
    /// pion's `InboundRTPStreamStats.PacketsReceived` of kind video).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_peer_counts_the_video_packets_it_received() {
        bounded(async {
            let (a, b, mids, mut got) = lines(&[MediaKind::Audio, MediaKind::Video]).await;
            assert_eq!(b.video_packets_in(), 0);
            let (opus, vp8) = (pt_of(&a, Codec::Opus), pt_of(&a, Codec::Vp8));
            let mut audio = SendLine::new(mids[0], None, opus);
            let mut video = SendLine::new(mids[1], None, vp8);
            assert_eq!(audio.write(&a, Instant::now(), packets(500, 5)), Some(5));
            assert_eq!(video.write(&a, Instant::now(), packets(900, 12)), Some(12));
            assert_eq!(audio.write(&a, Instant::now(), packets(505, 4)), Some(4));
            let (mut heard, mut watched) = (0, 0);
            while heard + watched < 21 {
                let (pt, ..) = got.recv().await.unwrap();
                if pt == *opus {
                    heard += 1;
                } else {
                    assert_eq!(pt, *vp8);
                    watched += 1;
                }
            }
            assert_eq!((heard, watched), (9, 12));
            // The count is taken before the sink is called.
            assert_eq!(b.video_packets_in(), 12);
            // Without a sink the packets are dropped, and still counted.
            b.set_rtp_sink(None);
            assert_eq!(video.write(&a, Instant::now(), packets(912, 3)), Some(3));
            tokio::time::timeout(Duration::from_secs(10), async {
                while b.video_packets_in() < 15 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the packets written without a sink were not counted");
            assert_eq!(b.video_packets_in(), 15);
            assert_eq!(a.video_packets_in(), 0);
            a.close();
            b.close();
        })
        .await;
    }
}

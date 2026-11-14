// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! vp8channel's frame layout (W24-W26, W29, W30): `vp8channel/wire.go`,
//! `epoch.go` and `datagram.go` at 2d4266af.
//!
//! ```text
//! [0..20]   a minimal valid VP8 keyframe (an SFU that checks the bitstream
//!           forwards the track)
//! [20..24]  binding token (BE)
//! [24..28]  sender's epoch (src, BE); the high bit marks the control plane
//! [28..32]  destination epoch (dst, BE; 0 = broadcast)
//! [32..36]  CRC-32/IEEE of token ‖ src ‖ dst (BE)
//! [36..]    one KCP packet ‖ its CRC-32C, or OLKB (u16 BE len ‖ packet)*,
//!           or OLUD ‖ datagram, or OLUB (u16 BE len ‖ OLUD ‖ datagram)*
//! ```

/// `vp8Keepalive` (`wire.go:10-14`): heads every frame.
pub const VP8_KEEPALIVE: [u8; 20] = [
    0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00, 0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
    0x99, 0x84, 0x88, 0xfc,
];

/// `tokenOff`.
pub const TOKEN_OFF: usize = 20;
/// `srcOff`.
pub const SRC_OFF: usize = 24;
/// `dstOff`.
pub const DST_OFF: usize = 28;
/// `crcOff`.
pub const CRC_OFF: usize = 32;
/// `epochHdrLen`.
pub const EPOCH_HDR_LEN: usize = 36;
/// `controlEpochFlag`: the high bit of a control plane's epoch.
pub const CONTROL_EPOCH_FLAG: u32 = 0x8000_0000;

/// `kcpBatchMagic`.
pub const KCP_BATCH_MAGIC: [u8; 4] = *b"OLKB";
/// `datagramMagic`.
pub const DATAGRAM_MAGIC: [u8; 4] = *b"OLUD";
/// `datagramBatchMagic`.
pub const DATAGRAM_BATCH_MAGIC: [u8; 4] = *b"OLUB";
/// `batchLenLen`: the length in front of each packet of a batch.
pub const BATCH_LEN_LEN: usize = 2;
/// `defaultMaxPayloadSize` (`transport.go:56`): the largest sample.
pub const MAX_PAYLOAD_SIZE: usize = 60 * 1024;

/// `kcpMTU` (`kcp.go:66`): the KCP packet size, mss 1376.
pub const KCP_MTU: usize = 1400;
/// `wireCRCLen` (`kcpconn.go:23`): the CRC-32C trailer of a KCP packet.
pub const WIRE_CRC_LEN: usize = 4;

/// A frame header.
pub type EpochHeader = [u8; EPOCH_HDR_LEN];

/// `epochCRC` (`epoch.go:33-39`).
#[must_use]
pub fn epoch_crc(token: u32, src: u32, dst: u32) -> u32 {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&token.to_be_bytes());
    buf[4..8].copy_from_slice(&src.to_be_bytes());
    buf[8..12].copy_from_slice(&dst.to_be_bytes());
    crc32fast::hash(&buf)
}

/// `buildEpochHeaderTo` (`epoch.go:21-31`); `dst` 0 is a broadcast.
#[must_use]
pub fn epoch_header(token: u32, src: u32, dst: u32) -> EpochHeader {
    let mut hdr = [0u8; EPOCH_HDR_LEN];
    hdr[..TOKEN_OFF].copy_from_slice(&VP8_KEEPALIVE);
    hdr[TOKEN_OFF..SRC_OFF].copy_from_slice(&token.to_be_bytes());
    hdr[SRC_OFF..DST_OFF].copy_from_slice(&src.to_be_bytes());
    hdr[DST_OFF..CRC_OFF].copy_from_slice(&dst.to_be_bytes());
    hdr[CRC_OFF..].copy_from_slice(&epoch_crc(token, src, dst).to_be_bytes());
    hdr
}

/// A header's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Binding token.
    pub token: u32,
    /// Sender's epoch.
    pub src: u32,
    /// Destination epoch, 0 for everyone.
    pub dst: u32,
}

/// `parseEpochHeader` (`epoch.go:43-53`): `None` when the frame is shorter
/// than a header or its CRC does not match. The VP8 bytes are not checked.
#[must_use]
pub fn parse_epoch_header(frame: &[u8]) -> Option<Header> {
    if frame.len() < EPOCH_HDR_LEN {
        return None;
    }
    let be = |off: usize| u32::from_be_bytes(frame[off..off + 4].try_into().expect("four bytes"));
    let h = Header {
        token: be(TOKEN_OFF),
        src: be(SRC_OFF),
        dst: be(DST_OFF),
    };
    (be(CRC_OFF) == epoch_crc(h.token, h.src, h.dst)).then_some(h)
}

/// `splitKCPPayload` (`wire.go:56-77`): each KCP packet of an OLKB batch, or
/// the payload itself when it is not one (a legacy single packet). A batch
/// is read up to its first malformed entry (a zero or overlong length, or a
/// stray byte): what came before it is delivered.
pub fn split_kcp_payload<'a>(payload: &'a [u8], mut deliver: impl FnMut(&'a [u8])) {
    let Some(mut rest) = payload.strip_prefix(&KCP_BATCH_MAGIC) else {
        deliver(payload);
        return;
    };
    while !rest.is_empty() {
        if rest.len() < BATCH_LEN_LEN {
            return;
        }
        let size = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[BATCH_LEN_LEN..];
        if size == 0 || rest.len() < size {
            return;
        }
        deliver(&rest[..size]);
        rest = &rest[size..];
    }
}

/// `appendBatchPacket` (`writer.go:434-441`): a packet over 65,535 bytes is
/// left out, silently.
pub fn append_batch_packet(dst: &mut Vec<u8>, packet: &[u8]) {
    let Ok(len) = u16::try_from(packet.len()) else {
        return;
    };
    dst.extend_from_slice(&len.to_be_bytes());
    dst.extend_from_slice(packet);
}

/// `splitDatagramPayload` (`datagram.go:84-89`).
#[must_use]
pub fn split_datagram_payload(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&DATAGRAM_MAGIC)
}

/// `splitDatagramBatchPayload` (`datagram.go:91-110`): unlike OLKB, one
/// malformed entry refuses the whole batch.
#[must_use]
pub fn split_datagram_batch_payload(payload: &[u8]) -> Option<Vec<&[u8]>> {
    let mut rest = payload.strip_prefix(&DATAGRAM_BATCH_MAGIC)?;
    let mut packets = Vec::with_capacity(4);
    while !rest.is_empty() {
        if rest.len() < BATCH_LEN_LEN {
            return None;
        }
        let size = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[BATCH_LEN_LEN..];
        if size == 0 || rest.len() < size {
            return None;
        }
        packets.push(&rest[..size]);
        rest = &rest[size..];
    }
    Some(packets)
}

/// A datagram too large for one sample (`ErrTrafficPayloadTooLarge`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge;

/// `enqueueDatagram`'s frame (`datagram.go:52-71`): `header ‖ OLUD ‖ data`,
/// refused when `len + 36 + 4 > 60 KiB`.
pub fn datagram_frame(hdr: &EpochHeader, data: &[u8]) -> Result<Vec<u8>, TooLarge> {
    if data.len() + EPOCH_HDR_LEN + DATAGRAM_MAGIC.len() > MAX_PAYLOAD_SIZE {
        return Err(TooLarge);
    }
    let mut frame = Vec::with_capacity(EPOCH_HDR_LEN + DATAGRAM_MAGIC.len() + data.len());
    frame.extend_from_slice(hdr);
    frame.extend_from_slice(&DATAGRAM_MAGIC);
    frame.extend_from_slice(data);
    Ok(frame)
}

/// `sameEpochHeader` (`datagram.go:139-141`).
#[must_use]
pub fn same_epoch_header(a: &[u8], b: &[u8]) -> bool {
    a.len() >= EPOCH_HDR_LEN && b.len() >= EPOCH_HDR_LEN && a[..EPOCH_HDR_LEN] == b[..EPOCH_HDR_LEN]
}

/// `randomEpoch` (`epoch.go:66-84`): a data epoch, the high bit clear,
/// never 0.
#[must_use]
pub fn random_epoch() -> u32 {
    let e = rand::random::<u32>() & !CONTROL_EPOCH_FLAG;
    if e == 0 {
        1
    } else {
        e
    }
}

/// `formatPeerID` (`peers.go:330-332`): eight lowercase hex digits.
#[must_use]
pub fn format_peer_id(epoch: u32) -> String {
    format!("{epoch:08x}")
}

/// `parsePeerID` (`peers.go:334-341`): `strconv.ParseUint(s, 16, 32)`, so
/// hex digits of either case and nothing else (no sign, no `0x`).
#[must_use]
pub fn parse_peer_id(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// `roomhint.Split` (`internal/roomhint/roomhint.go:40-53`): the room link
/// without a trailing `?ice=` or `&ice=` hint that names a known mode
/// (`udp`, `tcp`, `both`), and the mode. Otherwise the link comes back as it
/// was and the mode is empty. With a hint, the link is cut out of its
/// whitespace-trimmed form.
#[must_use]
pub fn split_room_hint(room: &str) -> (&str, &str) {
    const KEY: &str = "ice=";
    let trimmed = room.trim_matches(|c: char| c.is_whitespace());
    for sep in ["?", "&"] {
        let needle = format!("{sep}{KEY}");
        let Some(at) = trimmed.rfind(&needle) else {
            continue;
        };
        let mode = &trimmed[at + needle.len()..];
        if matches!(mode, "udp" | "tcp" | "both") {
            return (&trimmed[..at], mode);
        }
    }
    (room, "")
}

/// `common.BindingToken` (`transport/common/binding.go:20-35`): FNV-1a 32 of
/// the channel id, or of the room link without its hint when there is no
/// channel id; 0 becomes 1.
#[must_use]
pub fn binding_token(channel_id: &str, room_url: &str) -> u32 {
    let source = if channel_id.is_empty() {
        split_room_hint(room_url).0
    } else {
        channel_id
    };
    let mut h: u32 = 0x811c_9dc5;
    for b in source.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    if h == 0 {
        1
    } else {
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips_and_a_flipped_bit_fails_it() {
        let h = epoch_header(0x1234_5678, 0x0abc_def0, 0x8000_0001);
        assert_eq!(&h[..20], &VP8_KEEPALIVE);
        assert_eq!(
            parse_epoch_header(&h),
            Some(Header {
                token: 0x1234_5678,
                src: 0x0abc_def0,
                dst: 0x8000_0001
            })
        );
        for i in TOKEN_OFF..EPOCH_HDR_LEN {
            let mut bad = h;
            bad[i] ^= 1;
            assert_eq!(parse_epoch_header(&bad), None, "byte {i}");
        }
        assert_eq!(parse_epoch_header(&h[..35]), None);
        // The VP8 bytes are not part of the check.
        let mut vp8 = h;
        vp8[0] ^= 0xff;
        assert!(parse_epoch_header(&vp8).is_some());
    }

    #[test]
    fn olkb_stops_at_the_first_bad_entry_olub_refuses_the_batch() {
        let mut b = KCP_BATCH_MAGIC.to_vec();
        append_batch_packet(&mut b, b"one");
        append_batch_packet(&mut b, b"two");
        b.extend_from_slice(&[0, 9, 1]);
        let mut got = Vec::new();
        split_kcp_payload(&b, |p| got.push(p.to_vec()));
        assert_eq!(got, [b"one".to_vec(), b"two".to_vec()]);

        let mut got = Vec::new();
        split_kcp_payload(b"plain", |p| got.push(p.to_vec()));
        assert_eq!(got, [b"plain".to_vec()]);

        let mut d = DATAGRAM_BATCH_MAGIC.to_vec();
        append_batch_packet(&mut d, b"OLUDa");
        assert_eq!(split_datagram_batch_payload(&d), Some(vec![&b"OLUDa"[..]]));
        d.push(0);
        assert_eq!(split_datagram_batch_payload(&d), None);
        assert_eq!(
            split_datagram_batch_payload(&DATAGRAM_BATCH_MAGIC),
            Some(vec![])
        );
    }

    #[test]
    fn a_datagram_fills_a_sample_at_most() {
        let hdr = epoch_header(1, 2, 0);
        let max = MAX_PAYLOAD_SIZE - EPOCH_HDR_LEN - 4;
        assert_eq!(
            datagram_frame(&hdr, &vec![0; max]).unwrap().len(),
            MAX_PAYLOAD_SIZE
        );
        assert_eq!(datagram_frame(&hdr, &vec![0; max + 1]), Err(TooLarge));
    }

    #[test]
    fn peer_ids_are_go_hex() {
        assert_eq!(format_peer_id(0xab), "000000ab");
        assert_eq!(parse_peer_id("000000AB"), Some(0xab));
        assert_eq!(parse_peer_id("ffffffff"), Some(u32::MAX));
        for bad in ["", "+1", "0x1", "100000000", "not-hex", " 1"] {
            assert_eq!(parse_peer_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn random_epochs_are_data_epochs() {
        for _ in 0..1000 {
            let e = random_epoch();
            assert!(e != 0 && e & CONTROL_EPOCH_FLAG == 0);
        }
    }

    #[test]
    fn the_hint_is_no_part_of_the_room() {
        assert_eq!(
            split_room_hint("https://x/r?ice=tcp"),
            ("https://x/r", "tcp")
        );
        assert_eq!(
            split_room_hint("https://x/r?a=1&ice=both"),
            ("https://x/r?a=1", "both")
        );
        assert_eq!(
            split_room_hint("https://x/r?ice=quic"),
            ("https://x/r?ice=quic", "")
        );
        assert_eq!(
            split_room_hint(" https://x/r?ice=udp "),
            ("https://x/r", "udp")
        );
        assert_eq!(
            binding_token("", "https://x/r?ice=tcp"),
            binding_token("", "https://x/r")
        );
        // FNV-1a 32 of the empty string.
        assert_eq!(binding_token("", ""), 0x811c_9dc5);
        assert_eq!(binding_token("chan", "ignored"), binding_token("chan", ""));
    }
}

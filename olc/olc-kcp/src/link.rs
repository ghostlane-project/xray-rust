// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What vp8channel puts around every KCP packet (W28): the trailer
//! `CRC32C-Castagnoli(packet)` big-endian, and the frame header in front.
//!
//! Go: olcRTC `internal/transport/vp8channel/kcpconn.go:14-30,186-214,
//! 339-352` at 2d4266af. kcp-go runs with no FEC and no block cipher there,
//! so this trailer is the packet's only integrity check: a packet whose CRC
//! does not match is dropped and KCP resends it (issue #109).

/// Bytes of the trailer (`wireCRCLen`).
pub const CRC_LEN: usize = 4;

const POLY: u32 = 0x82F6_3B78; // Castagnoli, reflected

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut s = 1;
        while s < 8 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            s += 1;
        }
        i += 1;
    }
    t
}

static TABLES: [[u32; 256]; 8] = make_tables();

/// CRC-32C (Castagnoli) of `data`: Go's `crc32.Checksum(data,
/// crc32.MakeTable(crc32.Castagnoli))`. Slicing by 8; 8 KiB of tables.
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let t = &TABLES;
    let mut crc = !0u32;
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let lo = crc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        crc = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][c[4] as usize]
            ^ t[2][c[5] as usize]
            ^ t[1][c[6] as usize]
            ^ t[0][c[7] as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ t[0][((crc ^ u32::from(b)) & 0xff) as usize];
    }
    !crc
}

/// `kcpConn.wrap` (`kcpconn.go:342-352`): `header ‖ packet ‖ crc32c(packet)`
/// big-endian, appended to `out`.
pub fn wrap_into(out: &mut Vec<u8>, header: &[u8], packet: &[u8]) {
    out.reserve(header.len() + packet.len() + CRC_LEN);
    out.extend_from_slice(header);
    out.extend_from_slice(packet);
    out.extend_from_slice(&crc32c(packet).to_be_bytes());
}

/// Why [`unwrap`] refused a payload (Go counts both as `corrupt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corrupt {
    /// Shorter than the trailer.
    Short,
    /// The trailer does not match.
    Mismatch,
}

/// `kcpConn.deliver`'s check (`kcpconn.go:186-196`): the KCP packet of a
/// payload whose trailer matches.
pub fn unwrap(payload: &[u8]) -> Result<&[u8], Corrupt> {
    if payload.len() < CRC_LEN {
        return Err(Corrupt::Short);
    }
    let (body, tail) = payload.split_at(payload.len() - CRC_LEN);
    let want = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
    if crc32c(body) == want {
        Ok(body)
    } else {
        Err(Corrupt::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_answers() {
        // RFC 3720 B.4 and the usual check value.
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62A8_AB43);
        let inc: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&inc), 0x46DD_794E);
    }

    #[test]
    fn slicing_agrees_with_bytewise() {
        fn bytewise(data: &[u8]) -> u32 {
            let mut crc = !0u32;
            for &b in data {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ POLY
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        let data: Vec<u8> = (0..3000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for n in [0, 1, 7, 8, 9, 15, 16, 17, 100, 1399, 1400, 3000] {
            assert_eq!(crc32c(&data[..n]), bytewise(&data[..n]), "n={n}");
        }
    }

    #[test]
    fn wrap_then_unwrap() {
        let mut out = Vec::new();
        wrap_into(&mut out, &[9u8; 36], b"kcp packet");
        assert_eq!(out.len(), 36 + 10 + 4);
        assert_eq!(unwrap(&out[36..]), Ok(&b"kcp packet"[..]));
        let mut bad = out[36..].to_vec();
        bad[0] ^= 1;
        assert_eq!(unwrap(&bad), Err(Corrupt::Mismatch));
        assert_eq!(unwrap(&[1, 2, 3]), Err(Corrupt::Short));
        assert_eq!(unwrap(&crc32c(b"").to_be_bytes()), Ok(&b""[..]));
    }
}

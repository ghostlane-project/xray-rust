// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the lane reads off a KCP packet without decoding it (`lane.go`
//! `pushes`, `answers`): the segment header as kcp-go lays it out, `conv,
//! cmd, frg, wnd, ts, sn, una, len`, little-endian.

/// `IKCP_OVERHEAD`.
pub const OVERHEAD: usize = 24;
/// `kcpCmdOff`.
pub const CMD_OFF: usize = 4;
/// `kcpTSOff`.
pub const TS_OFF: usize = 8;
/// `kcpLenOff`.
pub const LEN_OFF: usize = 20;
/// `IKCP_CMD_PUSH`.
pub const CMD_PUSH: u8 = 81;
/// `IKCP_CMD_ACK`.
pub const CMD_ACK: u8 = 82;
/// `IKCP_CMD_WASK`.
pub const CMD_WASK: u8 = 83;
/// `IKCP_CMD_WINS`.
pub const CMD_WINS: u8 = 84;

/// A little-endian u32 at `off` (the caller checked the length).
#[must_use]
pub fn read_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// `pushes`: whether a KCP packet holds a push segment. kcp-go packs
/// acknowledgements first, so a packet of them alone is walked to its end;
/// a length past what is left ends the walk.
#[must_use]
pub fn pushes(mut segs: &[u8]) -> bool {
    while segs.len() >= OVERHEAD {
        if segs[CMD_OFF] == CMD_PUSH {
            return true;
        }
        let size = read_u32_le(segs, LEN_OFF) as usize;
        let rest = &segs[OVERHEAD..];
        if size > rest.len() {
            return false;
        }
        segs = &rest[size..];
    }
    false
}

/// `answers`: whether a KCP packet answers the other side, opening with an
/// acknowledgement or the window size a probe asked for.
#[must_use]
pub fn answers(packet: &[u8]) -> bool {
    packet.len() >= OVERHEAD && matches!(packet[CMD_OFF], CMD_ACK | CMD_WINS)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One segment: conv 0xC0FFEE01, `cmd`, `ts`, `len` zero bytes.
    pub(crate) fn seg(cmd: u8, ts: u32, len: u32) -> Vec<u8> {
        let mut s = vec![0u8; OVERHEAD];
        s[0..4].copy_from_slice(&0xC0FF_EE01u32.to_le_bytes());
        s[CMD_OFF] = cmd;
        s[TS_OFF..TS_OFF + 4].copy_from_slice(&ts.to_le_bytes());
        s[LEN_OFF..LEN_OFF + 4].copy_from_slice(&len.to_le_bytes());
        s.resize(OVERHEAD + len as usize, 0xab);
        s
    }

    #[test]
    fn pushes_walks_the_segments_and_stops_at_a_hostile_length() {
        // lane_test.go:237
        let mut p = seg(CMD_ACK, 1, 0);
        p.extend(seg(CMD_ACK, 2, 0));
        assert!(!pushes(&p), "acknowledgements alone");
        p.extend(seg(CMD_PUSH, 3, 10));
        assert!(pushes(&p));
        let mut bad = seg(CMD_ACK, 1, 0);
        bad[LEN_OFF] = 200;
        bad.extend(seg(CMD_PUSH, 3, 10));
        assert!(!pushes(&bad), "a length past the packet ends the walk");
        assert!(!pushes(&[0u8; 23]));
    }

    #[test]
    fn answers_reads_the_first_segment() {
        assert!(answers(&seg(CMD_ACK, 0, 0)));
        assert!(answers(&seg(CMD_WINS, 0, 0)));
        assert!(!answers(&seg(CMD_PUSH, 0, 4)));
        assert!(!answers(&seg(CMD_WASK, 0, 0)));
        let mut p = seg(CMD_PUSH, 0, 0);
        p.extend(seg(CMD_ACK, 0, 0));
        assert!(!answers(&p), "only the first segment tells");
    }
}

//! What a plaintext record says about smux streams, without parsing smux
//! (conn.go:103-117, 557-593).
//!
//! A record holds whole smux frames, one or several, each
//! `version | cmd | length u16 LE | stream id u32 LE | body`. The walk stops at
//! the first header whose version is neither 1 nor 2, and a length past the
//! record's end takes what is left.

/// The smux frame header (conn.go:103-110).
pub const SMUX_HEADER_SIZE: usize = 8;
/// smux's SYN command (conn.go:111).
pub const SMUX_CMD_SYN: u8 = 0;
/// smux's PSH command (conn.go:112).
pub const SMUX_CMD_PSH: u8 = 2;
/// The first stream a client's smux session opens (conn.go:114-117).
pub const SMUX_FIRST_STREAM: u32 = 3;

/// Calls `f(cmd, stream_id, body_len)` for each frame header of `record`.
fn walk(mut record: &[u8], mut f: impl FnMut(u8, u32, usize)) {
    while record.len() >= SMUX_HEADER_SIZE {
        let (version, cmd) = (record[0], record[1]);
        if version != 1 && version != 2 {
            return;
        }
        let len = usize::from(u16::from_le_bytes([record[2], record[3]]));
        let body = len.min(record.len() - SMUX_HEADER_SIZE);
        let sid = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);
        f(cmd, sid, body);
        record = &record[SMUX_HEADER_SIZE + body..];
    }
}

/// The stream payload of a record: the bodies of its PSH frames on streams
/// other than 0 (`streamPayloadLen`, conn.go:557-574). The control stream's
/// liveness check counts this, not every byte (olcbox#25).
#[must_use]
pub fn stream_payload_len(record: &[u8]) -> u64 {
    let mut total = 0u64;
    walk(record, |cmd, sid, body| {
        if cmd == SMUX_CMD_PSH && sid != 0 {
            total += body as u64;
        }
    });
    total
}

/// Whether a record's SYN frames open a session's first stream, and whether
/// they open any stream (`openedStreams`, conn.go:576-593).
#[must_use]
pub fn opened_streams(record: &[u8]) -> (bool, bool) {
    let (mut first, mut opens) = (false, false);
    walk(record, |cmd, sid, _| {
        if cmd == SMUX_CMD_SYN && sid != 0 {
            first |= sid == SMUX_FIRST_STREAM;
            opens = true;
        }
    });
    (first, opens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_is_walked_frame_by_frame() {
        let mut record = vec![2, SMUX_CMD_SYN, 0, 0, 3, 0, 0, 0];
        record.extend_from_slice(&[2, SMUX_CMD_PSH, 2, 0, 3, 0, 0, 0, b'h', b'i']);
        assert_eq!(stream_payload_len(&record), 2);
        assert_eq!(opened_streams(&record), (true, true));
        assert_eq!(
            stream_payload_len(&record[..17]),
            1,
            "a short body counts what is there"
        );
    }
}

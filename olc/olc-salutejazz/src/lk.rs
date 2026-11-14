// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The LiveKit messages the SaluteJazz SFU (LiveKit 1.5.3) relays,
//! hand-encoded (the engine's `dataPacket`, data.go, through protobuf-go).
//!
//! livekit_models.proto: `DataPacket { kind = 1; user = 2 (oneof);
//! participant_identity = 4; destination_identities = 5 }` and
//! `UserPacket { participant_sid = 1; payload = 2; destination_sids = 3;
//! topic = 4; participant_identity = 5; destination_identities = 6 }`.
//! Fields go in field-number order, as protobuf-go writes them, and the
//! destinations go on both messages, as the engine fills both for 1.5.3.

use std::ops::Range;

/// The lossy lane's topic (`datagramPublishTopic`).
pub const DATAGRAM_TOPIC: &str = "olcrtc.udp";
/// The relay window's topic (`windowTopic`).
pub const WINDOW_TOPIC: &str = "olcrtc.win";

/// What [`encode`] adds to a payload at most for one destination and a
/// topic: two tags and lengths per field (≤ 1 + 3 bytes each for the sizes
/// here), the kind, the topic and the destination twice. 128 covers a
/// 40-byte identity and the longer topic.
pub const OVERHEAD: usize = 128;

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

fn bytes_field(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    varint(out, u64::from(field << 3 | 2));
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// One DataPacket carrying one UserPacket, as `dataPacket` builds it:
/// `kind` LOSSY (1) written only for the lossy lane (RELIABLE is 0, the
/// default, which protobuf-go omits).
#[must_use]
pub fn encode(payload: &[u8], topic: Option<&str>, dest: &[String], reliable: bool) -> Vec<u8> {
    let mut user_len = 1 + varint_len(payload.len() as u64) + payload.len();
    if let Some(t) = topic {
        user_len += 1 + varint_len(t.len() as u64) + t.len();
    }
    for d in dest {
        user_len += 1 + varint_len(d.len() as u64) + d.len();
    }
    let dest_len: usize = dest
        .iter()
        .map(|d| 1 + varint_len(d.len() as u64) + d.len())
        .sum();
    let mut out = Vec::with_capacity(2 + 1 + varint_len(user_len as u64) + user_len + dest_len);
    if !reliable {
        varint(&mut out, 1 << 3);
        varint(&mut out, 1);
    }
    varint(&mut out, 2 << 3 | 2);
    varint(&mut out, user_len as u64);
    bytes_field(&mut out, 2, payload);
    if let Some(t) = topic {
        bytes_field(&mut out, 4, t.as_bytes());
    }
    for d in dest {
        bytes_field(&mut out, 6, d.as_bytes());
    }
    for d in dest {
        bytes_field(&mut out, 5, d.as_bytes());
    }
    out
}

/// A relayed user packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserPacket {
    /// Who sent it (`senderIdentity`): the user packet's identity, its sid,
    /// else the outer identity.
    pub sender: String,
    /// Whether `sender` is an identity (not a sid).
    pub by_identity: bool,
    /// Its topic, if any.
    pub topic: Option<String>,
    /// Where the payload lies in the frame (decrypted there in place).
    pub payload: Range<usize>,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.b.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let byte = self.byte()?;
            v |= u64::from(byte & 0x7f) << (7 * i);
            if byte < 0x80 {
                return Some(v);
            }
        }
        None
    }

    fn skip(&mut self, n: usize) -> Option<Range<usize>> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len())?;
        let r = self.at..end;
        self.at = end;
        Some(r)
    }

    /// The next field: number, wire type, and its bytes for wire type 2.
    fn field(&mut self) -> Option<(u64, u8, Range<usize>)> {
        let tag = self.varint()?;
        let (num, wt) = (tag >> 3, (tag & 7) as u8);
        let r = match wt {
            0 => {
                self.varint()?;
                self.at..self.at
            }
            1 => self.skip(8)?,
            2 => {
                let n = usize::try_from(self.varint()?).ok()?;
                self.skip(n)?
            }
            5 => self.skip(4)?,
            _ => return None,
        };
        Some((num, wt, r))
    }

    fn done(&self) -> bool {
        self.at >= self.b.len()
    }
}

fn text(frame: &[u8], r: Range<usize>) -> String {
    String::from_utf8_lossy(&frame[r]).into_owned()
}

/// Decodes a relayed DataPacket; `None` for a malformed one or one that is
/// not a user packet.
#[must_use]
pub fn decode(frame: &[u8]) -> Option<UserPacket> {
    let mut r = Reader { b: frame, at: 0 };
    let mut user = None;
    let mut outer = String::new();
    while !r.done() {
        let (num, wt, v) = r.field()?;
        match (num, wt) {
            (2, 2) => user = Some(v),
            (4, 2) => outer = text(frame, v),
            _ => {}
        }
    }
    let user = user?;
    let mut r = Reader {
        b: &frame[..user.end],
        at: user.start,
    };
    let (mut sid, mut identity) = (String::new(), String::new());
    let mut out = UserPacket {
        payload: user.start..user.start,
        ..UserPacket::default()
    };
    while !r.done() {
        let (num, wt, v) = r.field()?;
        match (num, wt) {
            (1, 2) => sid = text(frame, v),
            (2, 2) => out.payload = v,
            (4, 2) => out.topic = Some(text(frame, v)),
            (5, 2) => identity = text(frame, v),
            _ => {}
        }
    }
    (out.sender, out.by_identity) = if !identity.is_empty() {
        (identity, true)
    } else if !sid.is_empty() {
        (sid, false)
    } else {
        let by = !outer.is_empty();
        (outer, by)
    };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn a_lossy_packet_is_protobuf_gos_bytes() {
        // proto.Marshal of the engine's dataPacket(b"hello", "olcrtc.udp",
        // ["peer-1"], false), the spike's vector.
        let f = encode(b"hello", Some(DATAGRAM_TOPIC), &["peer-1".into()], false);
        assert_eq!(
            hex(&f),
            "0801121b120568656c6c6f220a6f6c637274632e7564703206706565722d312a06706565722d31"
        );
    }

    #[test]
    fn a_reliable_packet_has_no_kind_and_round_trips() {
        let f = encode(&[9; 300], None, &["srv".into()], true);
        assert_eq!(f[0], 0x12, "the kind field is omitted on the reliable lane");
        let p = decode(&f).unwrap();
        assert_eq!(&f[p.payload.clone()], &[9; 300][..]);
        assert_eq!(p.topic, None);
        assert!(encode(b"x", None, &[], true).len() <= 1 + OVERHEAD);
    }

    #[test]
    fn the_sender_is_the_identity_then_the_sid_then_the_outer_identity() {
        // UserPacket{participant_sid: "PA_1", payload: "p", participant_identity: "id-1"}
        let user = [
            &[0x0a, 4][..],
            b"PA_1",
            &[0x12, 1, b'p'],
            &[0x2a, 4],
            b"id-1",
        ]
        .concat();
        let frame = [&[0x12, u8::try_from(user.len()).unwrap()][..], &user].concat();
        let p = decode(&frame).unwrap();
        assert_eq!((p.sender.as_str(), p.by_identity), ("id-1", true));
        let user = [&[0x0a, 4][..], b"PA_1", &[0x12, 1, b'p']].concat();
        let frame = [
            &[0x12, u8::try_from(user.len()).unwrap()][..],
            &user,
            &[0x22, 2],
            b"zz",
        ]
        .concat();
        let p = decode(&frame).unwrap();
        assert_eq!((p.sender.as_str(), p.by_identity), ("PA_1", false));
        let frame = [&[0x12, 3, 0x12, 1, b'p', 0x22, 2][..], b"zz"].concat();
        let p = decode(&frame).unwrap();
        assert_eq!((p.sender.as_str(), p.by_identity), ("zz", true));
    }

    #[test]
    fn malformed_frames_are_refused_not_panicked_on() {
        assert_eq!(decode(&[0x12, 0x7f, 1]), None);
        assert_eq!(decode(&[0x12]), None);
        assert_eq!(decode(&[0x0f]), None);
        assert_eq!(decode(&[0x08, 0x01]), None, "no user packet");
        assert_eq!(decode(&[0xff; 12]), None);
    }
}

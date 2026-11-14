//! The LiveKit messages the SaluteJazz SFU (LiveKit 1.5.3) relays, hand-encoded.
//!
//! livekit_models.proto: DataPacket { kind = 1; user = 2 (oneof); participant_identity = 4;
//! destination_identities = 5 } and UserPacket { participant_sid = 1; payload = 2;
//! destination_sids = 3; topic = 4; participant_identity = 5; destination_identities = 6 }.
//! Fields are written in field-number order, as protobuf-go writes them (the engine's own
//! frames), and the destinations go on both messages, as the engine fills both for 1.5.3.

/// The lossy lane's topic (the engine's `datagramPublishTopic`).
pub const DATAGRAM_TOPIC: &str = "olcrtc.udp";

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn bytes_field(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    varint(out, ((field << 3) | 2) as u64);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// One DataPacket carrying one UserPacket, as the engine's `dataPacket` builds it.
pub fn encode(payload: &[u8], topic: Option<&str>, dest: &[&str], reliable: bool) -> Vec<u8> {
    let mut user = Vec::with_capacity(payload.len() + 64);
    bytes_field(&mut user, 2, payload);
    if let Some(t) = topic {
        bytes_field(&mut user, 4, t.as_bytes());
    }
    for d in dest {
        bytes_field(&mut user, 6, d.as_bytes());
    }
    let mut out = Vec::with_capacity(user.len() + 64);
    if !reliable {
        varint(&mut out, 1 << 3); // kind: LOSSY = 1 (RELIABLE = 0 is the default, not written)
        varint(&mut out, 1);
    }
    bytes_field(&mut out, 2, &user);
    for d in dest {
        bytes_field(&mut out, 5, d.as_bytes());
    }
    out
}

/// A relayed user packet: who sent it (as the SFU stamped it), its topic and its payload.
#[derive(Debug, Clone, Default)]
pub struct UserPacket {
    pub sender: String,
    pub topic: Option<String>,
    pub payload: Vec<u8>,
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let (&byte, rest) = self.b.split_first()?;
            self.b = rest;
            v |= ((byte & 0x7f) as u64) << (7 * i);
            if byte < 0x80 {
                return Some(v);
            }
        }
        None
    }

    /// The next field: number, wire type, and its bytes for wire type 2.
    fn field(&mut self) -> Option<(u32, u8, &'a [u8], u64)> {
        let tag = self.varint()?;
        let (num, wt) = ((tag >> 3) as u32, (tag & 7) as u8);
        match wt {
            0 => Some((num, wt, &[][..], self.varint()?)),
            1 => {
                let (_, rest) = self.b.split_at_checked(8)?;
                self.b = rest;
                Some((num, wt, &[][..], 0))
            }
            2 => {
                let n = self.varint()? as usize;
                let (v, rest) = self.b.split_at_checked(n)?;
                self.b = rest;
                Some((num, wt, v, 0))
            }
            5 => {
                let (_, rest) = self.b.split_at_checked(4)?;
                self.b = rest;
                Some((num, wt, &[][..], 0))
            }
            _ => None,
        }
    }
}

/// Decodes a relayed DataPacket; `None` for anything that is not a user packet.
pub fn decode(frame: &[u8]) -> Option<UserPacket> {
    let mut r = Reader { b: frame };
    let mut user = None;
    let mut outer_identity = String::new();
    while !r.b.is_empty() {
        let (num, wt, v, _) = r.field()?;
        match (num, wt) {
            (2, 2) => user = Some(v),
            (4, 2) => outer_identity = String::from_utf8_lossy(v).into_owned(),
            _ => {}
        }
    }
    let mut r = Reader { b: user? };
    let (mut sid, mut identity, mut out) = (String::new(), String::new(), UserPacket::default());
    while !r.b.is_empty() {
        let (num, wt, v, _) = r.field()?;
        match (num, wt) {
            (1, 2) => sid = String::from_utf8_lossy(v).into_owned(),
            (2, 2) => out.payload = v.to_vec(),
            (4, 2) => out.topic = Some(String::from_utf8_lossy(v).into_owned()),
            (5, 2) => identity = String::from_utf8_lossy(v).into_owned(),
            _ => {}
        }
    }
    // The engine's senderIdentity: the user packet's identity, its sid, then the outer one.
    out.sender = [identity, sid, outer_identity].into_iter().find(|s| !s.is_empty()).unwrap_or_default();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let f = encode(b"hello", Some(DATAGRAM_TOPIC), &["peer-1"], false);
        let p = decode(&f).unwrap();
        assert_eq!(p.payload, b"hello");
        assert_eq!(p.topic.as_deref(), Some(DATAGRAM_TOPIC));
        // kind LOSSY, user{payload, topic, dest}, dest: field-number order, as protobuf-go writes.
        assert_eq!(
            hex(&f),
            "0801121b120568656c6c6f220a6f6c637274632e7564703206706565722d312a06706565722d31"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

//! Taps on what goes over the wire: the first STUN binding request each way and the first
//! DTLS ClientHello, kept as bytes so the shape comparisons (scripts/wire.py) read exactly
//! what was sent.

use crate::util::hex;

const MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// A STUN Binding request (type 0x0001).
pub fn is_binding_request(b: &[u8]) -> bool {
    b.len() >= 20 && b[0] == 0x00 && b[1] == 0x01 && b[4..8] == MAGIC
}

/// A DTLS record carrying a ClientHello's first message (handshake type 1, message_seq 0).
pub fn is_client_hello(b: &[u8]) -> bool {
    b.len() > 25 && b[0] == 22 && b[13] == 1 && b[17] == 0 && b[18] == 0
}

/// The attribute types of a STUN message, in order, with their lengths.
pub fn stun_attrs(b: &[u8]) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    let mut i = 20;
    while i + 4 <= b.len() {
        let t = u16::from_be_bytes([b[i], b[i + 1]]);
        let l = u16::from_be_bytes([b[i + 2], b[i + 3]]);
        out.push((t, l));
        i += 4 + ((l as usize + 3) & !3);
    }
    out
}

pub fn stun_attr_name(t: u16) -> String {
    match t {
        0x0006 => "USERNAME".into(),
        0x0008 => "MESSAGE-INTEGRITY".into(),
        0x0020 => "XOR-MAPPED-ADDRESS".into(),
        0x0024 => "PRIORITY".into(),
        0x0025 => "USE-CANDIDATE".into(),
        0x8028 => "FINGERPRINT".into(),
        0x8029 => "ICE-CONTROLLED".into(),
        0x802a => "ICE-CONTROLLING".into(),
        0xc057 => "GOOG-NETWORK-INFO".into(),
        0xc058 => "GOOG-LAST-ICE-CHECK-RECEIVED".into(),
        0xc059 => "GOOG-NOMINATION".into(),
        0xc05a => "GOOG-DELTA".into(),
        0xc05b => "GOOG-DELTA-ACK".into(),
        0xc060 => "GOOG-MISC-INFO".into(),
        0xc070 => "META-DTLS-IN-STUN".into(),
        0xc071 => "META-DTLS-IN-STUN-ACK".into(),
        t => format!("0x{t:04x}"),
    }
}

/// `USERNAME(9) ICE-CONTROLLING(8) ...` for a log line.
pub fn stun_shape(b: &[u8]) -> String {
    stun_attrs(b).iter().map(|(t, l)| format!("{}({l})", stun_attr_name(*t))).collect::<Vec<_>>().join(" ")
}

/// What one connection's taps caught.
#[derive(Debug, Default, Clone)]
pub struct Taps {
    pub stun_tx: Vec<Vec<u8>>,
    pub stun_rx: Vec<Vec<u8>>,
    pub hello_tx: Vec<Vec<u8>>,
    pub hello_rx: Vec<Vec<u8>>,
}

/// How many requests of each direction are kept: enough to see both a plain check and a
/// nominating one.
const KEEP: usize = 4;

impl Taps {
    pub fn sent(&mut self, b: &[u8]) {
        if is_binding_request(b) && self.stun_tx.len() < KEEP {
            self.stun_tx.push(b.to_vec());
        } else if is_client_hello(b) && self.hello_tx.len() < 4 {
            self.hello_tx.push(b.to_vec());
        }
    }

    pub fn received(&mut self, b: &[u8]) {
        if is_binding_request(b) && self.stun_rx.len() < KEEP {
            self.stun_rx.push(b.to_vec());
        } else if is_client_hello(b) && self.hello_rx.len() < 4 {
            self.hello_rx.push(b.to_vec());
        }
    }

    /// Prints every catch as `STUN_TX <conn> <shape> <hex>` / `DTLS_CH_TX <conn> <hex>` lines.
    pub fn print(&self, conn: &str) {
        for b in &self.stun_tx {
            eprintln!("STUN_TX {conn} [{}] {}", stun_shape(b), hex(b));
        }
        for b in &self.stun_rx {
            eprintln!("STUN_RX {conn} [{}] {}", stun_shape(b), hex(b));
        }
        for b in &self.hello_tx {
            eprintln!("DTLS_CH_TX {conn} {}", hex(b));
        }
        for b in &self.hello_rx {
            eprintln!("DTLS_CH_RX {conn} {}", hex(b));
        }
    }
}

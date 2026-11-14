//! Small helpers: randomness for ids, hex, arguments.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use str0m::IceCreds;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 64 unpredictable-enough bits for request ids and ICE credentials (SipHash with a
/// per-process random key over a counter; not key material).
pub fn rand_u64() -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    h.finish()
}

/// `n` characters of the ICE alphabet ([A-Za-z0-9+/]), as Chrome draws its credentials.
pub fn ice_chars(n: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(n);
    let mut bits = 0u64;
    let mut left = 0;
    for _ in 0..n {
        if left < 6 {
            bits = rand_u64();
            left = 64;
        }
        out.push(A[(bits & 63) as usize] as char);
        bits >>= 6;
        left -= 6;
    }
    out
}

/// Chrome-sized ICE credentials: a 4-character ufrag, a 24-character password.
pub fn chrome_ice_creds() -> IceCreds {
    IceCreds { ufrag: ice_chars(4), pass: ice_chars(24) }
}

/// A random (version 4) UUID string, as the engine's `uuid.NewString()`.
pub fn uuid4() -> String {
    let (a, b) = (rand_u64(), rand_u64());
    let mut x = [0u8; 16];
    x[..8].copy_from_slice(&a.to_be_bytes());
    x[8..].copy_from_slice(&b.to_be_bytes());
    x[6] = (x[6] & 0x0f) | 0x40;
    x[8] = (x[8] & 0x3f) | 0x80;
    let h = hex(&x);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The address of the interface the default route leaves by (a connected UDP socket sends
/// nothing; it only asks the kernel for a route).
pub fn default_ipv4() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// `--name value` pairs and `--flag`s.
pub struct Args(Vec<String>);

impl Args {
    pub fn from_env() -> Self {
        Args(std::env::args().skip(1).collect())
    }

    pub fn get(&self, name: &str) -> Option<String> {
        let key = format!("--{name}");
        self.0.iter().position(|a| *a == key).and_then(|i| self.0.get(i + 1).cloned())
    }

    pub fn or(&self, name: &str, default: &str) -> String {
        self.get(name).unwrap_or_else(|| default.to_string())
    }

    pub fn num(&self, name: &str, default: usize) -> Result<usize, String> {
        match self.get(name) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("--{name}: not a number: {v}")),
        }
    }

    pub fn flag(&self, name: &str) -> bool {
        let key = format!("--{name}");
        self.0.iter().any(|a| *a == key)
    }
}

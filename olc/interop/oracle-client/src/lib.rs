//! Test support for the olcRTC port (`olc-wire`, `olc-muxconn`, and the crates
//! after them). Not shipped: only dev-dependencies name it.
//!
//! Two things the Rust tests check themselves against, both made by the Go
//! engine at [`PIN`]:
//!
//! - the golden vectors under `olc/interop/vectors/<pin8>/`, written by
//!   `olc/interop/regen.sh` (see [`load`]);
//! - the decode oracle, `cmd/zz-olcrtc-oracle` built by
//!   `olc/interop/build-oracle.sh`: a process that hands the bytes a Rust test
//!   made to the engine's own code and says what that code made of them (see
//!   [`Oracle`]). A test that needs it skips, saying why, when [`ORACLE_ENV`]
//!   is not set.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The engine commit the vectors and the oracle are made from.
pub const PIN: &str = "2d4266af3947f4d9940efafb0d5aabb6207f6659";

/// The variable that names the built oracle binary.
pub const ORACLE_ENV: &str = "OLC_GO_ORACLE";

/// The directory of the vectors for [`PIN`].
#[must_use]
pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("vectors")
        .join(&PIN[..8])
}

/// Reads one vector file (`name` relative to [`vectors_dir`]) and returns its
/// `cases`, after checking it was made at [`PIN`].
///
/// # Panics
/// When the file is missing, is not JSON, or names another pin.
#[must_use]
pub fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let file: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    assert_eq!(file["pin"], PIN, "{name} was generated at another pin");
    file["cases"].clone()
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decodes hex (either case).
///
/// # Panics
/// On an odd length or a character that is not a hex digit.
#[must_use]
pub fn unhex(text: &str) -> Vec<u8> {
    fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not a hex digit: {:?}", char::from(c)),
        }
    }
    let text = text.as_bytes();
    assert!(
        text.len().is_multiple_of(2),
        "odd hex length {}",
        text.len()
    );
    text.chunks_exact(2)
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect()
}

/// A field of a vector case as bytes: its hex string decoded.
///
/// # Panics
/// When the field is not a hex string.
#[must_use]
pub fn bytes(case: &Value, field: &str) -> Vec<u8> {
    unhex(
        case[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is not a string in {case}")),
    )
}

/// `n` deterministic bytes, as the generators' `zzvectors.Pattern` makes them:
/// byte `i` is `(i * 31 + seed) mod 251`.
#[must_use]
pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 31 + usize::from(seed)) % 251).expect("below 251"))
        .collect()
}

/// The lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A small deterministic generator (SplitMix64) for seeded differential tests:
/// the same seed makes the same inputs on every machine.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator seeded with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..n` (`n` > 0).
    pub fn below(&mut self, n: usize) -> usize {
        let n64 = u64::try_from(n).expect("usize fits u64");
        usize::try_from(self.next_u64() % n64).expect("below n")
    }

    /// `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64().to_le_bytes()[0]).collect()
    }

    /// Fewer than `n` bytes, how many drawn first.
    pub fn bytes_below(&mut self, n: usize) -> Vec<u8> {
        let len = self.below(n);
        self.bytes(len)
    }
}

/// The decode oracle: the Go engine at [`PIN`] behind a JSON-lines pipe.
///
/// Every request is one JSON object with an `"op"`; byte strings are hex. A
/// reply with `"error"` means the request itself was wrong, and [`call`]
/// panics on it; what the engine's code decided is in the reply's other
/// fields (usually `"verdict"`). The protocol is defined in
/// `olc/interop/go-overlay/cmd/zz-olcrtc-oracle/main.go`.
///
/// [`call`]: Oracle::call
#[derive(Debug)]
pub struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Oracle {
    /// The oracle [`ORACLE_ENV`] names, or `None` after telling stderr why
    /// `test` is skipped.
    ///
    /// # Panics
    /// When the variable is set but the oracle cannot be started.
    #[must_use]
    pub fn from_env(test: &str) -> Option<Self> {
        let Some(path) = std::env::var_os(ORACLE_ENV) else {
            eprintln!(
                "skipping {test}: {ORACLE_ENV} is not set; build the Go oracle with \
                 olc/interop/build-oracle.sh <path> and set {ORACLE_ENV}=<path>"
            );
            return None;
        };
        Some(Self::spawn(&path))
    }

    /// Starts the oracle at `path` and checks it was built at [`PIN`].
    ///
    /// # Panics
    /// When it cannot be started or answers for another pin.
    #[must_use]
    pub fn spawn(path: &OsString) -> Self {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("start the oracle {}: {e}", path.to_string_lossy()));
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut oracle = Self {
            child,
            stdin,
            stdout,
            line: String::new(),
        };
        let pong = oracle.call(&serde_json::json!({"op": "ping"}));
        assert_eq!(pong["pin"], PIN, "the oracle was built at another pin");
        oracle
    }

    /// Sends one request and returns the reply.
    ///
    /// # Panics
    /// When the oracle has gone away or says the request was malformed.
    pub fn call(&mut self, request: &Value) -> Value {
        let mut text = serde_json::to_string(request).expect("a request serializes");
        text.push('\n');
        self.stdin
            .write_all(text.as_bytes())
            .and_then(|()| self.stdin.flush())
            .expect("write to the oracle");
        self.line.clear();
        let n = self
            .stdout
            .read_line(&mut self.line)
            .expect("read from the oracle");
        assert!(n > 0, "the oracle closed its output");
        let reply: Value = serde_json::from_str(&self.line).expect("the oracle answers JSON");
        if let Some(error) = reply.get("error") {
            panic!("the oracle refused {request}: {error}");
        }
        reply
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&all)), all);
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("ABcd"), vec![0xab, 0xcd]);
    }

    #[test]
    fn pattern_matches_the_generators() {
        // zzvectors.Pattern(5, 7): (i*31+7) % 251.
        assert_eq!(pattern(5, 7), vec![7, 38, 69, 100, 131]);
        assert_eq!(
            pattern(10, 250)[9],
            u8::try_from((9 * 31 + 250) % 251).unwrap()
        );
    }

    #[test]
    fn the_vectors_are_at_the_pin() {
        let keys = load("crypto/keys.json");
        assert!(keys["keys"].as_array().is_some_and(|k| !k.is_empty()));
    }
}

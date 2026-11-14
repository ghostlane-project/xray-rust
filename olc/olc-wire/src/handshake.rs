//! The session handshake, v3 (`internal/handshake/handshake.go`).
//!
//! The client opens the session's first stream and writes one framed
//! `CLIENT_HELLO` carrying a fresh 128-bit challenge; the server answers on
//! that stream with `SERVER_WELCOME` (a session id, maybe a peer id) or
//! `SERVER_REJECT` (a reason), each echoing the challenge. A reply that echoes
//! another challenge belongs to another client sharing the room and key, and
//! is skipped (handshake.go:128-152).
//!
//! The hello is written byte for byte as Go's `json.Marshal` writes the
//! `Hello` struct with no claims: `{"version":3,"type":"CLIENT_HELLO",
//! "device_id":…,"challenge":…}` (handshake.go:62-69, 117-124). Ghostlane
//! never sets claims; only `pkg/olcrtc/client` passes them.
//!
//! Replies are read with `serde_json`. It reads what a Go server writes exactly
//! as Go does (vectors `handshake/client.json`, `handshake/server.json`). On
//! input no Go server produces, the two decoders differ: Go matches object
//! keys in any case, serde_json only as written (a key in another case reads
//! as absent); Go takes the last of a key given twice, serde_json refuses the
//! reply; Go reads invalid UTF-8 and lone surrogate escapes as U+FFFD,
//! serde_json refuses the reply; Go refuses `-0` for an unsigned field,
//! serde_json reads it as 0.

use std::io::Read;
use std::time::Duration;

use rand::RngCore;
use serde::Deserialize;

use crate::framing::{self, FrameTooLarge, ReadError};
use crate::gojson;

/// The handshake's wire version (handshake.go:32-34).
pub const PROTO_VERSION: i64 = 3;
/// Bytes of challenge, sent as 32 lowercase hex digits (handshake.go:36-39).
pub const CHALLENGE_SIZE: usize = 16;
/// The largest handshake frame body (handshake.go:41-44).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;
/// How long either side waits for the other's reply (handshake.go:46-48).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
/// The client's message (handshake.go:55).
pub const TYPE_HELLO: &str = "CLIENT_HELLO";
/// The server's success reply (handshake.go:57).
pub const TYPE_WELCOME: &str = "SERVER_WELCOME";
/// The server's failure reply (handshake.go:59).
pub const TYPE_REJECT: &str = "SERVER_REJECT";

/// A client that has had no welcome sends another hello, on a new stream with
/// a new challenge, this often (client/link.go:38).
pub const HELLO_RESEND_INTERVAL: Duration = Duration::from_secs(2);
/// The most hello streams one handshake opens (client/link.go:40-43).
pub const MAX_HELLO_ATTEMPTS: u32 = 8;

/// The server's reject reasons of its own (handshake.go:214-235); an auth
/// hook's refusal is its error's text (handshake.go:237-243).
pub mod reject_reason {
    /// The hello was not JSON of the right shape.
    pub const MALFORMED_HELLO: &str = "malformed hello";
    /// The first frame was not a `CLIENT_HELLO`.
    pub const EXPECTED_CLIENT_HELLO: &str = "expected CLIENT_HELLO";
    /// The hello's version is not 3.
    pub const PROTOCOL_VERSION_MISMATCH: &str = "protocol version mismatch";
    /// The challenge is not 16 bytes of hex.
    pub const INVALID_CHALLENGE: &str = "invalid handshake challenge";
}

/// One handshake's identity: 16 random bytes (handshake.go:194-201).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Challenge([u8; CHALLENGE_SIZE]);

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.to_hex();
        f.debug_tuple("Challenge")
            .field(&std::str::from_utf8(&hex).expect("hex is ASCII"))
            .finish()
    }
}

impl Challenge {
    /// A fresh challenge from the operating system's generator.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; CHALLENGE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The challenge made of `bytes`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHALLENGE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Its bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHALLENGE_SIZE] {
        &self.0
    }

    /// The 32 lowercase hex digits it is sent as (`hex.EncodeToString`).
    #[must_use]
    pub fn to_hex(&self) -> [u8; 2 * CHALLENGE_SIZE] {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 2 * CHALLENGE_SIZE];
        for (i, b) in self.0.iter().enumerate() {
            out[2 * i] = DIGITS[usize::from(b >> 4)];
            out[2 * i + 1] = DIGITS[usize::from(b & 0x0f)];
        }
        out
    }

    fn matches(&self, echoed: &str) -> bool {
        echoed.as_bytes() == self.to_hex()
    }
}

/// Appends the framed `CLIENT_HELLO` for `device_id` and `challenge` to `out`
/// (handshake.go:117-124, 263-268).
///
/// # Errors
/// [`FrameTooLarge`] when the hello's JSON is over [`MAX_MESSAGE_SIZE`]; `out`
/// is then unchanged.
pub fn encode_hello(
    device_id: &[u8],
    challenge: &Challenge,
    out: &mut Vec<u8>,
) -> Result<(), FrameTooLarge> {
    let frame = framing::Frame::begin(out);
    out.extend_from_slice(b"{\"version\":");
    gojson::write_i64(out, PROTO_VERSION);
    out.extend_from_slice(b",\"type\":\"");
    out.extend_from_slice(TYPE_HELLO.as_bytes());
    out.extend_from_slice(b"\",\"device_id\":");
    gojson::write_string(out, device_id);
    out.extend_from_slice(b",\"challenge\":\"");
    out.extend_from_slice(&challenge.to_hex());
    out.extend_from_slice(b"\"}");
    frame.finish(out, MAX_MESSAGE_SIZE)
}

/// What the server granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// The session id the server's auth hook gave.
    pub session_id: String,
    /// The routing peer id; empty when the server sent none.
    pub peer_id: String,
}

/// A reply read with [`parse_reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// It echoes another challenge: another client's, or none. Wait for the
    /// next one (handshake.go:151-153).
    NotOurs,
    /// The server took this hello.
    Welcome(Welcome),
}

/// The handshake failed. The variants are the Go errors (handshake.go:88-102),
/// and [`HandshakeError::verdict`] their names in the vectors.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// The server refused, for this reason.
    #[error("handshake rejected: {0}")]
    Rejected(String),
    /// The server speaks another version.
    #[error("incompatible protocol version: server v{0}, client v3")]
    ProtocolVersion(i64),
    /// A reply that is neither a welcome nor a reject.
    #[error("unexpected handshake message: got {0:?}")]
    UnexpectedMessage(String),
    /// A reply's own challenge is not ours.
    #[error("handshake challenge mismatch")]
    ChallengeMismatch,
    /// A reply that is not JSON of the right shape.
    #[error("{0}")]
    Parse(String),
    /// The stream failed or ended, or a frame was over the limit.
    #[error("read welcome: handshake: {0}")]
    Read(#[from] ReadError),
}

impl HandshakeError {
    /// The verdict's name in the vectors.
    #[must_use]
    pub const fn verdict(&self) -> &'static str {
        match self {
            Self::Rejected(_) => "rejected",
            Self::ProtocolVersion(_) => "protocol_version",
            Self::UnexpectedMessage(_) => "unexpected_message",
            Self::ChallengeMismatch => "challenge_mismatch",
            Self::Parse(_) => "parse",
            Self::Read(ReadError::TooLarge(_)) => "frame_too_large",
            Self::Read(_) => "read",
        }
    }
}

/// The two fields every reply is first read for (handshake.go:144-147).
#[derive(Deserialize, Default)]
struct Probe {
    #[serde(rename = "type")]
    kind: Option<String>,
    challenge: Option<String>,
}

/// `Welcome` (handshake.go:71-78).
#[derive(Deserialize, Default)]
struct WelcomeMsg {
    version: Option<i64>,
    session_id: Option<String>,
    peer_id: Option<String>,
    challenge: Option<String>,
}

/// `Reject` (handshake.go:80-86).
#[derive(Deserialize, Default)]
struct RejectMsg {
    // Read and type-checked as Go does, though a reject's version is not
    // compared (handshake.go:183-192).
    #[allow(dead_code)]
    version: Option<i64>,
    reason: Option<String>,
    challenge: Option<String>,
}

/// Go's `json.Unmarshal` into a struct: a top-level `null` leaves it as it
/// was, and absent or `null` fields read as empty.
fn unmarshal<'a, T: Deserialize<'a> + Default>(body: &'a [u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice::<Option<T>>(body).map(Option::unwrap_or_default)
}

/// Reads one reply body against our `challenge` (`readReply`,
/// handshake.go:138-192).
///
/// # Errors
/// [`HandshakeError::Rejected`] for our reject, and the other variants for a
/// reply that ends the handshake.
pub fn parse_reply(body: &[u8], challenge: &Challenge) -> Result<Reply, HandshakeError> {
    let probe: Probe =
        unmarshal(body).map_err(|e| HandshakeError::Parse(format!("parse reply: {e}")))?;
    if !challenge.matches(probe.challenge.as_deref().unwrap_or("")) {
        return Ok(Reply::NotOurs);
    }
    match probe.kind.as_deref().unwrap_or("") {
        TYPE_WELCOME => {
            let w: WelcomeMsg = unmarshal(body)
                .map_err(|e| HandshakeError::Parse(format!("parse welcome: {e}")))?;
            let version = w.version.unwrap_or(0);
            if version != PROTO_VERSION {
                return Err(HandshakeError::ProtocolVersion(version));
            }
            if !challenge.matches(w.challenge.as_deref().unwrap_or("")) {
                return Err(HandshakeError::ChallengeMismatch);
            }
            Ok(Reply::Welcome(Welcome {
                session_id: w.session_id.unwrap_or_default(),
                peer_id: w.peer_id.unwrap_or_default(),
            }))
        }
        TYPE_REJECT => {
            let r: RejectMsg =
                unmarshal(body).map_err(|e| HandshakeError::Parse(format!("parse reject: {e}")))?;
            if !challenge.matches(r.challenge.as_deref().unwrap_or("")) {
                return Err(HandshakeError::ChallengeMismatch);
            }
            Err(HandshakeError::Rejected(r.reason.unwrap_or_default()))
        }
        other => Err(HandshakeError::UnexpectedMessage(other.to_owned())),
    }
}

/// Reads replies from `r` until ours (`Client`'s loop, handshake.go:128-135),
/// and returns the welcome and how many replies to other challenges it
/// skipped. `buf` holds each frame; it never grows past [`MAX_MESSAGE_SIZE`].
///
/// # Errors
/// The [`HandshakeError`] that ends the handshake.
pub fn read_welcome<R: Read + ?Sized>(
    r: &mut R,
    challenge: &Challenge,
    buf: &mut Vec<u8>,
) -> Result<(Welcome, usize), HandshakeError> {
    let mut skipped = 0;
    loop {
        framing::read(r, MAX_MESSAGE_SIZE, buf)?;
        match parse_reply(buf, challenge)? {
            Reply::NotOurs => skipped += 1,
            Reply::Welcome(welcome) => return Ok((welcome, skipped)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_lowercase_hex() {
        let c = Challenge::from_bytes([0xab; 16]);
        assert_eq!(&c.to_hex(), b"abababababababababababababababab");
        assert!(c.matches("abababababababababababababababab"));
        assert!(!c.matches("ABABABABABABABABABABABABABABABAB"));
        assert_ne!(Challenge::random(), Challenge::random());
    }

    #[test]
    fn a_top_level_null_is_not_ours() {
        let c = Challenge::from_bytes([1; 16]);
        assert_eq!(parse_reply(b"null", &c).unwrap(), Reply::NotOurs);
        assert_eq!(parse_reply(b"[]", &c).unwrap_err().verdict(), "parse");
    }
}

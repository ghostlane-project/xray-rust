//! The control stream, v1 (`internal/control/control.go`): framed JSON pings,
//! pongs and a close, on the stream the handshake ran on.
//!
//! Each side pings every [`DEFAULT_INTERVAL`] from `seq` 1 with its clock in
//! `sent_unix_nano`, answers each ping with a pong that echoes both, and calls
//! the stream unhealthy after [`DEFAULT_FAILURES`] pongs in a row miss their
//! timeout ([`DEFAULT_TIMEOUT`], or [`CONTROL_PLANE_TIMEOUT`] on a transport
//! with a control plane). A message of another version or type ends the
//! stream (control.go:470-484). This module is the messages and the numbers;
//! the loop belongs to the client.
//!
//! Zero `seq` and `sent_unix_nano` are left out, as Go's `omitempty` does
//! (control.go:107-113). Reading uses `serde_json`, with the differences from
//! Go's decoder listed in [`crate::handshake`].

use std::io::Read;
use std::time::Duration;

use serde::Deserialize;

use crate::framing::{self, FrameTooLarge, ReadError};
use crate::gojson;

/// The control stream's wire version (control.go:24-25).
pub const PROTO_VERSION: i64 = 1;
/// The largest control frame body (control.go:26-27).
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024;
/// Time between two pings (control.go:28-29).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
/// How long a pong may take (control.go:30-41).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a pong may take on a transport with a control plane
/// (`runtime.LivenessTimeout`, runtime.go:154-163).
pub const CONTROL_PLANE_TIMEOUT: Duration = Duration::from_secs(45);
/// Missed pongs in a row that make the stream unhealthy (control.go:42-44).
pub const DEFAULT_FAILURES: u32 = 4;
/// Probes in a row that payload still arriving may excuse (control.go:45-78).
pub const MAX_STALLED_PROBES: u32 = 3;
/// A side that leaves sends `CONTROL_CLOSE` under this write deadline
/// (`NotifyControlClose`, tunnelcore/core.go:59-70)...
pub const CLOSE_WRITE_DEADLINE: Duration = Duration::from_secs(2);
/// ...waits this long once it went out, then half-closes the stream.
pub const CLOSE_LINGER: Duration = Duration::from_millis(200);

/// The three messages (control.go:83-92).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// `CONTROL_PING`.
    Ping,
    /// `CONTROL_PONG`.
    Pong,
    /// `CONTROL_CLOSE`: the peer is leaving on purpose.
    Close,
}

impl MsgType {
    /// The name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ping => "CONTROL_PING",
            Self::Pong => "CONTROL_PONG",
            Self::Close => "CONTROL_CLOSE",
        }
    }

    fn from_wire(name: &str) -> Option<Self> {
        match name {
            "CONTROL_PING" => Some(Self::Ping),
            "CONTROL_PONG" => Some(Self::Pong),
            "CONTROL_CLOSE" => Some(Self::Close),
            _ => None,
        }
    }
}

/// One control message (control.go:107-113).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    /// Which message.
    pub kind: MsgType,
    /// The ping's number, echoed by its pong; 0 means absent.
    pub seq: u64,
    /// The pinger's clock, echoed by the pong; 0 means absent.
    pub sent_unix_nano: i64,
}

impl Message {
    /// A ping.
    #[must_use]
    pub const fn ping(seq: u64, sent_unix_nano: i64) -> Self {
        Self {
            kind: MsgType::Ping,
            seq,
            sent_unix_nano,
        }
    }

    /// The pong that answers `ping` (control.go:309-320).
    #[must_use]
    pub const fn pong_for(ping: &Self) -> Self {
        Self {
            kind: MsgType::Pong,
            seq: ping.seq,
            sent_unix_nano: ping.sent_unix_nano,
        }
    }

    /// `CONTROL_CLOSE` (`SendClose`, control.go:485-488).
    #[must_use]
    pub const fn close() -> Self {
        Self {
            kind: MsgType::Close,
            seq: 0,
            sent_unix_nano: 0,
        }
    }
}

/// Appends the framed message to `out` (`writeFrame`, control.go:490-495).
///
/// # Errors
/// Never in practice: a message is far below [`MAX_MESSAGE_SIZE`].
pub fn encode(msg: &Message, out: &mut Vec<u8>) -> Result<(), FrameTooLarge> {
    let frame = framing::Frame::begin(out);
    out.extend_from_slice(b"{\"version\":");
    gojson::write_i64(out, PROTO_VERSION);
    out.extend_from_slice(b",\"type\":\"");
    out.extend_from_slice(msg.kind.as_str().as_bytes());
    out.push(b'"');
    if msg.seq != 0 {
        out.extend_from_slice(b",\"seq\":");
        gojson::write_u64(out, msg.seq);
    }
    if msg.sent_unix_nano != 0 {
        out.extend_from_slice(b",\"sent_unix_nano\":");
        gojson::write_i64(out, msg.sent_unix_nano);
    }
    out.push(b'}');
    frame.finish(out, MAX_MESSAGE_SIZE)
}

/// A control message was refused. [`ControlError::verdict`] names it as the
/// vectors do.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Another version (control.go:475-478).
    #[error("incompatible control protocol version: peer v{0}, local v1")]
    ProtocolVersion(i64),
    /// Another type (control.go:479-481).
    #[error("unexpected control message: got {0:?}")]
    UnexpectedMessage(String),
    /// Not JSON of the right shape (control.go:471-474).
    #[error("parse control message: {0}")]
    Parse(String),
    /// The stream failed or ended, or a frame was over the limit.
    #[error("control: {0}")]
    Read(#[from] ReadError),
}

impl ControlError {
    /// The verdict's name in the vectors.
    #[must_use]
    pub const fn verdict(&self) -> &'static str {
        match self {
            Self::ProtocolVersion(_) => "protocol_version",
            Self::UnexpectedMessage(_) => "unexpected_message",
            Self::Parse(_) => "parse",
            Self::Read(ReadError::TooLarge(_)) => "frame_too_large",
            Self::Read(_) => "read",
        }
    }
}

#[derive(Deserialize, Default)]
struct Wire {
    version: Option<i64>,
    #[serde(rename = "type")]
    kind: Option<String>,
    seq: Option<u64>,
    sent_unix_nano: Option<i64>,
}

/// Reads one message body (`parseMessage`, control.go:470-484).
///
/// # Errors
/// The [`ControlError`] the Go code gives.
pub fn parse(body: &[u8]) -> Result<Message, ControlError> {
    let wire: Wire = serde_json::from_slice::<Option<Wire>>(body)
        .map(Option::unwrap_or_default)
        .map_err(|e| ControlError::Parse(e.to_string()))?;
    let version = wire.version.unwrap_or(0);
    if version != PROTO_VERSION {
        return Err(ControlError::ProtocolVersion(version));
    }
    let kind = wire.kind.unwrap_or_default();
    let Some(parsed) = MsgType::from_wire(&kind) else {
        return Err(ControlError::UnexpectedMessage(kind));
    };
    Ok(Message {
        kind: parsed,
        seq: wire.seq.unwrap_or(0),
        sent_unix_nano: wire.sent_unix_nano.unwrap_or(0),
    })
}

/// Reads one framed message from `r` (control.go:497-504, then [`parse`]).
/// `buf` holds the frame; it never grows past [`MAX_MESSAGE_SIZE`].
///
/// # Errors
/// The [`ControlError`] the Go code gives.
pub fn read<R: Read + ?Sized>(r: &mut R, buf: &mut Vec<u8>) -> Result<Message, ControlError> {
    framing::read(r, MAX_MESSAGE_SIZE, buf)?;
    parse(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pong_echoes_its_ping() {
        let ping = Message::ping(7, -3);
        let pong = Message::pong_for(&ping);
        assert_eq!(pong.kind, MsgType::Pong);
        assert_eq!((pong.seq, pong.sent_unix_nano), (7, -3));
        let mut out = Vec::new();
        encode(&pong, &mut out).unwrap();
        assert_eq!(parse(&out[4..]).unwrap(), pong);
    }
}

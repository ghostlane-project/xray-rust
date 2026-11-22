//! The one-shot questions: `probe` (one request for a URL through the
//! session's line), `olc-check` (one join of the session's room) and
//! `olc-ping` (a join, then the best of three requests through the room).
//! Each is a process of its own that prints one line and ends; none of them
//! serves a port for the parent.
//!
//! Not built yet: each is refused.

use crate::args::Flags;
use crate::session::Session;
use crate::Failure;

/// The flags `probe` takes besides `--session`.
pub const PROBE_FLAGS: &[&str] = &["url", "timeout-ms", "outbound"];
/// The flags `olc-check` takes besides `--session`.
pub const OLC_CHECK_FLAGS: &[&str] = &["timeout-ms"];
/// The flags `olc-ping` takes besides `--session`.
pub const OLC_PING_FLAGS: &[&str] = &["url", "timeout-ms"];

/// A question's answer, printed as the one line of its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The line or the room answered.
    pub ok: bool,
    /// How long the answer took, milliseconds.
    pub millis: Option<u64>,
    /// Why there was none.
    pub error: Option<String>,
}

/// `probe`: starts the session's core half with no listener of its own
/// needed, asks for `--url` through `--outbound` (the default outbound when
/// not given) within `--timeout-ms`, and stops.
///
/// # Errors
/// A session or flags the question cannot be asked with; an answer that did
/// not come is an [`Outcome`], not an error.
pub fn probe(session: &Session, flags: &Flags) -> Result<Outcome, Failure> {
    let _ = (session, flags);
    Err(Failure::unsupported("`probe` is not built yet"))
}

/// `olc-check`: joins the session's room alone and waits for its SOCKS
/// port, within `--timeout-ms`.
///
/// # Errors
/// As [`probe`].
pub fn olc_check(session: &Session, flags: &Flags) -> Result<Outcome, Failure> {
    let _ = (session, flags);
    Err(Failure::unsupported("`olc-check` is not built yet"))
}

/// `olc-ping`: [`olc_check`], then the best of three requests for `--url`
/// through the room.
///
/// # Errors
/// As [`probe`].
pub fn olc_ping(session: &Session, flags: &Flags) -> Result<Outcome, Failure> {
    let _ = (session, flags);
    Err(Failure::unsupported("`olc-ping` is not built yet"))
}

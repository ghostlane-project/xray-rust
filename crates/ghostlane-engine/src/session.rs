//! The session file: what one run of the engine is to carry. It holds the
//! line's or the room's secrets, so it is a file of mode 0600 that the
//! parent writes and names on the command line; nothing secret is ever an
//! argument.
//!
//! ```json
//! {
//!   "version": 1,
//!   "core": { "inbounds": [], "outbounds": [] },
//!   "room": { },
//!   "bind": { "interface": "eth0" },
//!   "geodata_dir": "/path/to/lists"
//! }
//! ```
//!
//! - `version`: the contract's version, [`PROTOCOL`].
//! - `core`: the core half, an Xray JSON config as the apps' builder writes
//!   it. Alone, the session is a core line.
//! - `room`: the room half, read by `room.rs`. Alone, the session is a room
//!   whose SOCKS port the parent uses directly; with `core`, the core stands
//!   in front of the room (`front.rs`).
//! - `bind`: the interface every socket but loopback's leaves by, when a
//!   tunnel holds the default route. The escape of the system reads it and
//!   may read more fields than `interface`.
//! - `geodata_dir`: the one directory `ext:` and `geosite:` lists are read
//!   from; without it, the core's own search (the working directory, then
//!   the program's).
//!
//! `core` or `room` must be there; a half that is `null` is absent. A field
//! this file does not name is refused, so a typing error does not pass for
//! a setting.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::events::{FailureCode, PROTOCOL};
use crate::Failure;

/// A session, read and checked.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// The contract's version; [`load`] accepts [`PROTOCOL`] only.
    pub version: u32,
    /// The core half: an Xray JSON config, a JSON object.
    #[serde(default)]
    pub core: Option<Value>,
    /// The room half, a JSON object that `room.rs` reads.
    #[serde(default)]
    pub room: Option<Value>,
    /// The way out past a tunnel.
    #[serde(default)]
    pub bind: Option<Bind>,
    /// The one directory lists are read from.
    #[serde(default)]
    pub geodata_dir: Option<PathBuf>,
}

/// The way out past a tunnel: the interface the session's sockets are bound
/// to.
#[derive(Clone, Deserialize)]
pub struct Bind {
    /// The interface's name.
    pub interface: String,
    /// What else the system's escape reads.
    #[serde(flatten)]
    pub more: Map<String, Value>,
}

// The halves hold keys and passwords: a debug line says only which are there.
impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("version", &self.version)
            .field("core", &self.core.is_some())
            .field("room", &self.room.is_some())
            .field("bind", &self.bind.as_ref().map(|bind| &bind.interface))
            .field("geodata_dir", &self.geodata_dir)
            .finish()
    }
}

fn refused(message: impl Into<String>) -> Failure {
    Failure::new(FailureCode::Session, message)
}

/// Reads the session file at `path`.
///
/// # Errors
/// [`FailureCode::Session`]: the file cannot be read, other users can read
/// or write it (Unix), or it is not a session of this protocol. The message
/// never quotes the file.
pub fn load(path: &Path) -> Result<Session, Failure> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| refused(format!("the session file cannot be read: {error}")))?;
    if !metadata.is_file() {
        return Err(refused("the session file is not a regular file"));
    }
    check_mode(&metadata)?;
    let text = std::fs::read_to_string(path)
        .map_err(|error| refused(format!("the session file cannot be read: {error}")))?;
    parse(&text)
}

#[cfg(unix)]
fn check_mode(metadata: &std::fs::Metadata) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(refused(
            "the session file is open to other users: its mode must be 0600",
        ));
    }
    Ok(())
}

// Elsewhere the file's protection is its place: the parent writes it under
// the user's own profile.
#[cfg(not(unix))]
fn check_mode(_metadata: &std::fs::Metadata) -> Result<(), Failure> {
    Ok(())
}

fn object_or_absent(name: &str, half: Option<Value>) -> Result<Option<Value>, Failure> {
    match half {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(fields)) => Ok(Some(Value::Object(fields))),
        Some(_) => Err(refused(format!(
            "the session's `{name}` must be a JSON object"
        ))),
    }
}

/// Reads a session from its text.
///
/// # Errors
/// [`FailureCode::Session`], as [`load`].
pub fn parse(text: &str) -> Result<Session, Failure> {
    // serde_json's error names a line, a column and a field, never a value.
    let mut session: Session = serde_json::from_str(text)
        .map_err(|error| refused(format!("the session file is not a session: {error}")))?;
    if session.version != PROTOCOL {
        return Err(refused(format!(
            "the session file names protocol {}; this engine reads protocol {PROTOCOL}",
            session.version
        )));
    }
    session.core = object_or_absent("core", session.core.take())?;
    session.room = object_or_absent("room", session.room.take())?;
    if session.core.is_none() && session.room.is_none() {
        return Err(refused("the session has neither a `core` nor a `room`"));
    }
    if let Some(bind) = &session.bind {
        if bind.interface.is_empty() {
            return Err(refused("the session's `bind.interface` is empty"));
        }
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(text: &str) -> String {
        let failure = parse(text).unwrap_err();
        assert_eq!(failure.code, FailureCode::Session);
        failure.message
    }

    #[test]
    fn a_core_line_a_room_and_both_are_sessions() {
        let line = parse(r#"{"version":1,"core":{"outbounds":[]}}"#).unwrap();
        assert!(line.core.is_some() && line.room.is_none() && line.bind.is_none());
        let room = parse(r#"{"version":1,"core":null,"room":{"rooms":["a"]}}"#).unwrap();
        assert!(room.core.is_none() && room.room.is_some());
        let both = parse(
            r#"{"version":1,"core":{},"room":{},"bind":{"interface":"eth0","index":2},
                "geodata_dir":"/lists"}"#,
        )
        .unwrap();
        assert!(both.core.is_some() && both.room.is_some());
        let bind = both.bind.unwrap();
        assert_eq!(bind.interface, "eth0");
        assert_eq!(bind.more["index"], 2);
        assert_eq!(both.geodata_dir.unwrap(), Path::new("/lists"));
    }

    #[test]
    fn what_is_not_a_session_is_refused_with_a_sentence() {
        assert!(message("{").contains("is not a session"));
        assert!(message(r#"{"version":2,"core":{}}"#).contains("protocol 2"));
        assert!(message(r#"{"core":{}}"#).contains("version"));
        assert!(message(r#"{"version":1}"#).contains("neither"));
        assert!(message(r#"{"version":1,"core":null,"room":null}"#).contains("neither"));
        assert!(message(r#"{"version":1,"core":[]}"#).contains("`core` must be a JSON object"));
        assert!(message(r#"{"version":1,"room":"r"}"#).contains("`room` must be a JSON object"));
        assert!(message(r#"{"version":1,"core":{},"bind":{"interface":""}}"#).contains("empty"));
        assert!(message(r#"{"version":1,"core":{},"bind":{}}"#).contains("interface"));
        assert!(message(r#"{"version":1,"core":{},"sesion":1}"#).contains("sesion"));
    }

    #[test]
    fn a_refusal_and_a_debug_line_never_quote_a_secret() {
        let secret = "0f0e0d0c-0b0a-0908-0706-050403020100";
        let text = format!(r#"{{"version":1,"core":{{"id":"{secret}"}},"room":7}}"#);
        assert!(!message(&text).contains(secret));
        let text = format!(r#"{{"version":1,"core":{{"id":"{secret}"}}}}"#);
        let session = parse(&text).unwrap();
        assert!(!format!("{session:?}").contains(secret));
    }
}

//! The room half of a session: the olcRTC client, joined to a room of the
//! session's list, serving a SOCKS port on loopback. It is behind the
//! `rooms` feature: a build without it carries no olc crate and refuses a
//! session that has a room half.
//!
//! Not built yet: with the feature on, a room half is refused as well.

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::Value;

use crate::events::{Diagnostic, Severity, Source};
use crate::{Ctx, Failure};

#[cfg(feature = "rooms")]
const NOT_CARRIED: &str = "rooms are not built into the engine yet";
#[cfg(not(feature = "rooms"))]
const NOT_CARRIED: &str = "this build carries no rooms";

/// A running room.
pub struct Room {
    socks: SocketAddr,
}

impl Room {
    /// Where the room's SOCKS port listens, on loopback.
    #[must_use]
    pub fn socks(&self) -> SocketAddr {
        self.socks
    }

    /// Resolves when the room ends on its own, with why. It does not
    /// resolve for a hop to another room or a reconnect.
    pub async fn ended(&mut self) -> Failure {
        std::future::pending().await
    }

    /// Stops the room, waiting at most `grace` for it to leave.
    pub async fn stop(self, grace: Duration) {
        let _ = grace;
    }
}

/// Joins the room half `spec` describes and returns once its SOCKS port
/// serves. Each session it opens is printed as `session_opened`, its log
/// lines as `log` events, and its sockets go through `ctx.escape`.
///
/// # Errors
/// `room` when the room cannot be joined, `unsupported` when this build does
/// not carry rooms.
pub async fn start(spec: &Value, ctx: &Ctx) -> Result<Room, Failure> {
    let _ = (spec, ctx);
    Err(Failure::unsupported(NOT_CARRIED))
}

/// What this build says of a room half, starting nothing.
#[must_use]
pub fn check(spec: &Value) -> Vec<Diagnostic> {
    let _ = spec;
    vec![Diagnostic {
        severity: Severity::Error,
        source: Source::Room,
        path: None,
        message: NOT_CARRIED.to_owned(),
    }]
}

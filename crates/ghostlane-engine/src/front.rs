//! The front: a session with both halves runs the core in front of the
//! room, in this one process. The core half's rules decide what goes to the
//! room and what goes direct, and what goes to the room reaches it through a
//! `socks` outbound on loopback, TCP and UDP.
//!
//! Not built yet: a session with both halves is refused.

use serde_json::Value;

use crate::room::Room;
use crate::{Ctx, Failure};

/// Joins the halves: called once the room serves and before the core is
/// built, it may change the core half (where its `socks` outbound to the
/// room points, for one).
///
/// # Errors
/// `config` when the core half has no way to the room, `unsupported` when
/// this build has no front.
pub fn join(core: &mut Value, room: &Room, ctx: &Ctx) -> Result<(), Failure> {
    let _ = (core, room, ctx);
    Err(Failure::unsupported(
        "a core in front of a room is not built yet",
    ))
}

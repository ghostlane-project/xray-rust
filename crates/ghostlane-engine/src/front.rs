//! The front: a session with both halves runs the core in front of the
//! room, in this one process. The core half's rules decide what goes to the
//! room and what goes direct, and what goes to the room reaches it through a
//! `socks` outbound on loopback, TCP and UDP.
//!
//! Not built yet: a session with both halves is refused.

use std::net::SocketAddr;

use serde_json::Value;

use crate::room::Room;
use crate::{Ctx, Failure};

/// The tag of the core half's outbound that is its way to the room.
pub const ROOM_OUTBOUND: &str = "room";

/// Joins the halves: called once the room serves and before the core is
/// built, it may change the core half (where its `socks` outbound to the
/// room points, for one).
///
/// # Errors
/// `config` when the core half has no way to the room, `unsupported` when
/// this build has no front.
pub fn join(core: &mut Value, room: &Room, ctx: &Ctx) -> Result<(), Failure> {
    let _ = (room, ctx);
    point(core, SocketAddr::from(([127, 0, 0, 1], 0)))
}

/// Points the core half's way to the room at `socks`, where the room's
/// SOCKS port listens.
///
/// # Errors
/// `unsupported`: not built yet.
pub fn point(core: &mut Value, socks: SocketAddr) -> Result<(), Failure> {
    let _ = (core, socks);
    Err(Failure::unsupported(
        "a core in front of a room is not built yet",
    ))
}

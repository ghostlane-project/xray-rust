//! The front: a session with both halves runs the core in front of the
//! room, in this one process. The core half's rules decide what goes to the
//! room and what goes direct, and what goes to the room reaches it through a
//! `socks` outbound on loopback, TCP and UDP.
//!
//! The way to the room is the core half's outbound tagged
//! [`ROOM_OUTBOUND`], `room`: a `socks` outbound, with one server written
//! flat in its `settings` or as its one `servers` entry, as the config
//! parser takes either. Once the room serves, [`join`] points that server at
//! the room's SOCKS port: its `address` and `port` become where the room
//! listens on loopback, whatever the core half said there. The core half is
//! a config the parser takes as it is written (`check-config` reads it so),
//! so a parent that leaves the room's port to the system writes any port
//! there; one that names the port in the room half writes the same.
//!
//! Its login is the room half's: the room's port asks for the `socks.user`
//! and `socks.password` of the room half, or for none, and the `room`
//! outbound gives the same `user` and `pass`, or none.
//!
//! The way to the room takes no `streamSettings` and no `proxySettings`: it
//! is plain SOCKS to a port on loopback, which the session's way out leaves
//! unbound (`escape.rs`), and a transport, a socket option or a chain would
//! keep it from the room. Everything else in the core half is the parent's:
//! its inbounds (a LAN inbound with accounts among them), its rules, its DNS
//! and its other outbounds, whose sockets leave by the session's way out as
//! a line's do.

use std::net::SocketAddr;

use serde_json::{Map, Value};

use crate::events::FailureCode;
use crate::room::Room;
use crate::{Ctx, Failure};

/// The tag of the core half's outbound that is its way to the room.
pub const ROOM_OUTBOUND: &str = "room";

/// Joins the halves: called once the room serves and before the core is
/// built, it points the core half's way to the room at the room's SOCKS
/// port ([`point`]).
///
/// # Errors
/// `config` when the core half has no way to the room, or one that cannot
/// reach it.
pub fn join(core: &mut Value, room: &Room, ctx: &Ctx) -> Result<(), Failure> {
    let _ = ctx;
    point(core, room.socks())
}

/// How the `room` outbound writes its one server.
enum Form {
    /// In `settings` itself, or with no `settings` yet.
    Flat,
    /// As `settings.servers[0]`.
    Listed,
}

fn refused(message: impl Into<String>) -> Failure {
    Failure::new(FailureCode::Config, message)
}

fn no_way() -> Failure {
    refused(format!(
        "the core half has no way to the room: no outbound is tagged `{ROOM_OUTBOUND}`"
    ))
}

/// Where in `core` the way to the room is, and how it writes its server; or
/// why the core half has no way to the room that can reach it. Nothing is
/// changed.
fn find(core: &Value) -> Result<(usize, Form), Failure> {
    let outbounds = core
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(no_way)?;
    let mut tagged = outbounds
        .iter()
        .enumerate()
        .filter(|(_, outbound)| outbound.get("tag").and_then(Value::as_str) == Some(ROOM_OUTBOUND));
    let (index, way) = tagged.next().ok_or_else(no_way)?;
    if let Some((again, _)) = tagged.next() {
        return Err(refused(format!(
            "$.outbounds[{again}]: a second outbound is tagged `{ROOM_OUTBOUND}`; one is the way to the room"
        )));
    }
    let at = format!("$.outbounds[{index}]");
    if way.get("protocol").and_then(Value::as_str) != Some("socks") {
        return Err(refused(format!(
            "{at}: the way to the room is a `socks` outbound, as the room's port serves SOCKS5"
        )));
    }
    for field in ["streamSettings", "proxySettings"] {
        if way.get(field).is_some_and(|value| !value.is_null()) {
            return Err(refused(format!(
                "{at}.{field}: the way to the room is plain SOCKS to a port on loopback, with no `{field}`"
            )));
        }
    }
    match way.get("settings") {
        None | Some(Value::Null) => Ok((index, Form::Flat)),
        Some(Value::Object(settings)) => match settings.get("servers") {
            None | Some(Value::Null) => Ok((index, Form::Flat)),
            Some(Value::Array(servers)) if servers.len() == 1 && servers[0].is_object() => {
                Ok((index, Form::Listed))
            }
            Some(_) => Err(refused(format!(
                "{at}.settings.servers: the way to the room names one server, an object"
            ))),
        },
        Some(_) => Err(refused(format!("{at}.settings: must be an object"))),
    }
}

/// Points the core half's way to the room, its outbound tagged
/// [`ROOM_OUTBOUND`], at `socks`, where the room's SOCKS port listens: the
/// server's `address` and `port` are set, and everything else of the
/// outbound (its login, its level) is kept. A core half that is refused is
/// left as it was.
///
/// # Errors
/// `config`, with a sentence that names the field: the core half has no
/// outbound tagged `room`, or two; it is not a `socks` outbound; it carries
/// `streamSettings` or `proxySettings`; its `settings` or `servers` are not
/// the parser's forms of one server.
pub fn point(core: &mut Value, socks: SocketAddr) -> Result<(), Failure> {
    let (index, form) = find(core)?;
    let way = &mut core["outbounds"][index];
    let server = match form {
        Form::Flat => {
            if !way.get("settings").is_some_and(Value::is_object) {
                way["settings"] = Value::Object(Map::new());
            }
            &mut way["settings"]
        }
        Form::Listed => &mut way["settings"]["servers"][0],
    };
    server["address"] = Value::String(socks.ip().to_string());
    server["port"] = Value::from(socks.port());
    Ok(())
}

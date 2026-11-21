// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The room link (`internal/auth/jitsi`): host and room out of
//! `https://host/room`.

/// The engine this provider's credentials are for.
pub const ENGINE: &str = "jitsi";

/// The credentials' key for the room name.
pub const CREDENTIAL_KEY_ROOM: &str = "room";

/// The server used where none is named (`defaultServiceURL`).
pub const DEFAULT_SERVICE_URL: &str = "https://meet.handyweb.org";

/// A room link that does not give a host and a room. The link is not in the
/// text: a Jitsi room's name is the room's whole secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoomError {
    /// Nothing was given (`auth.ErrRoomIDRequired`).
    #[error("room ID required")]
    Required,
    /// No host, or no room (`ErrInvalidRoomURL`).
    #[error("jitsi: invalid room URL (expected host/room or https://host/room)")]
    Invalid,
}

/// Splits a room link into (host, room): with or without a scheme; the host
/// is what stands before the first `/`, the room is the rest with its outer
/// slashes trimmed (`parseRoomURL`).
///
/// # Errors
/// [`RoomError`].
pub fn parse_room_url(raw: &str) -> Result<(String, String), RoomError> {
    let mut raw = raw.trim();
    if raw.is_empty() {
        return Err(RoomError::Required);
    }
    if let Some(i) = raw.find("://") {
        raw = &raw[i + 3..];
    }
    raw = raw.strip_prefix("//").unwrap_or(raw);
    raw = raw.strip_prefix('/').unwrap_or(raw);
    let slash = match raw.find('/') {
        Some(i) if i > 0 => i,
        _ => return Err(RoomError::Invalid),
    };
    let host = raw[..slash].trim();
    let room = raw[slash + 1..].trim_matches('/');
    if host.is_empty() || room.is_empty() {
        return Err(RoomError::Invalid);
    }
    Ok((host.to_owned(), room.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "myroom";
    const HOST: &str = "meet.example";

    /// `TestParseRoomURL` (`internal/auth/jitsi/jitsi_test.go`).
    #[test]
    fn the_room_link_table() {
        type Case = (
            &'static str,
            &'static str,
            Option<(&'static str, &'static str)>,
        );
        let cases: [Case; 10] = [
            (
                "https url",
                "https://meet.one.example/myroom",
                Some(("meet.one.example", ROOM)),
            ),
            ("http url", "http://meet.example/myroom", Some((HOST, ROOM))),
            (
                "scheme-less",
                "meet.example.com/myroom",
                Some(("meet.example.com", ROOM)),
            ),
            (
                "trailing slash",
                "https://meet.example/myroom/",
                Some((HOST, ROOM)),
            ),
            (
                "double slash leader",
                "//meet.example/myroom",
                Some((HOST, ROOM)),
            ),
            (
                "uppercase room",
                "https://meet.example/MyRoom",
                Some((HOST, "MyRoom")),
            ),
            ("empty", "", None),
            ("host only", "meet.example.com", None),
            ("no room", "https://meet.example/", None),
            ("scheme only", "https://", None),
        ];
        for (name, raw, want) in cases {
            let got = parse_room_url(raw);
            match want {
                Some((h, r)) => assert_eq!(got, Ok((h.to_owned(), r.to_owned())), "{name}"),
                None => assert!(got.is_err(), "{name}: {got:?}"),
            }
        }
    }

    #[test]
    fn odd_inputs() {
        // The room keeps inner slashes, loses outer ones; the host is
        // trimmed, a path prefix stays out of it.
        assert_eq!(
            parse_room_url("  https://meet.example/a/b//  ").unwrap(),
            (HOST.into(), "a/b".into())
        );
        assert_eq!(
            parse_room_url("/meet.example/room").unwrap(),
            (HOST.into(), "room".into())
        );
        assert!(parse_room_url("https:///room").is_err(), "an empty host");
        assert!(
            parse_room_url("https://meet.example//").is_err(),
            "an empty room"
        );
        assert!(parse_room_url("https://meet.example/ / ").is_ok());
        assert!(parse_room_url("   ").is_err());
    }

    /// `ErrRoomIDRequired` for nothing, the invalid-link error for the rest;
    /// neither shows the link (D12: the room's name is its secret).
    #[test]
    fn errors_do_not_show_the_link() {
        assert_eq!(parse_room_url(""), Err(RoomError::Required));
        let e = parse_room_url("https://secret-host-name/").unwrap_err();
        assert_eq!(e, RoomError::Invalid);
        assert!(!e.to_string().contains("secret"), "{e}");
        assert_eq!(RoomError::Required.to_string(), "room ID required");
        assert!(RoomError::Invalid
            .to_string()
            .starts_with("jitsi: invalid room URL (expected host/room or https://host/room)"));
    }

    #[test]
    fn the_providers_constants() {
        assert_eq!(DEFAULT_SERVICE_URL, "https://meet.handyweb.org");
        assert_eq!(CREDENTIAL_KEY_ROOM, "room");
        assert_eq!(ENGINE, "jitsi");
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SaluteJazz auth provider's client half (`internal/auth/salutejazz`
//! at 2d4266af, `Issue`): a room reference `<code>:<password>` becomes the
//! engine's credentials after the `preconnect` call the official web client
//! makes before every join, which checks the password and names the
//! connector to join on. `CreateRoom` is the server's and is not ported.
//!
//! The password is a credential: no error here carries it or the reference.

use std::time::Duration;

use olc_net::http::{self, HttpRequest};
use serde::Serialize;

use crate::session::{Error, WEB_ORIGIN, WEB_USER_AGENT};

/// The REST base (`defaultAPIBase`).
pub const API_BASE: &str = "https://bk.salutejazz.ru";
/// The connector when a preconnect reply names none
/// (`defaultConnectorURL`).
pub const DEFAULT_CONNECTOR: &str = "wss://ws.salutejazz.ru/connector";
/// One preconnect, dial to the last body byte (Go's `protect.NewHTTPClient`
/// timeout).
pub const PRECONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The most of a preconnect reply read: the reply is a few hundred bytes of
/// JSON; 64 KiB holds any the service has sent with room to spare.
pub const PRECONNECT_MAX_BODY: usize = 64 << 10;

/// What the engine joins with.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The connector's `wss://` URL.
    pub url: String,
    /// The room's password (`Token`).
    pub token: String,
    /// The room's code (`Extra["roomID"]`).
    pub room_id: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("url", &self.url)
            .field("room_id", &self.room_id)
            .finish_non_exhaustive()
    }
}

/// `roomPartRE`: `^[a-z0-9]{4,16}$`.
fn room_part(s: &str) -> bool {
    (4..=16).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `splitRoomRef`: the code and the password of `<code>:<password>`, split
/// at the first colon.
///
/// # Errors
/// [`Error::RoomRef`], which names neither half.
pub fn split_room_ref(room_ref: &str) -> Result<(&str, &str), Error> {
    let (code, password) = room_ref
        .split_once(':')
        .ok_or_else(|| Error::RoomRef("expected \"<code>:<password>\"".into()))?;
    if !room_part(code) || !room_part(password) {
        return Err(Error::RoomRef("malformed room reference".into()));
    }
    Ok((code, password))
}

/// The preconnect body, in the order Go's `json.Marshal` of a map writes it
/// (sorted keys, at both levels).
#[derive(Serialize)]
struct Preconnect<'a> {
    #[serde(rename = "jazzNextMigration")]
    migration: Migration,
    password: &'a str,
}

/// The feature flags the web client sends beside the password.
#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)] // the service's own object
struct Migration {
    #[serde(rename = "b2bBaseRoomSupport")]
    b2b_base_room: bool,
    #[serde(rename = "demoRoomBaseSupport")]
    demo_room_base: bool,
    #[serde(rename = "demoRoomVersionSupport")]
    demo_room_version: u32,
    #[serde(rename = "mediaWithoutAutoSubscribeSupport")]
    media_without_auto_subscribe: bool,
    #[serde(rename = "sberclassRoomSupport")]
    sberclass_room: bool,
    #[serde(rename = "sdkRoomSupport")]
    sdk_room: bool,
    #[serde(rename = "webinarSpeakerSupport")]
    webinar_speaker: bool,
    #[serde(rename = "webinarViewerSupport")]
    webinar_viewer: bool,
}

/// The body of `POST /room/<code>/preconnect` for `password`.
fn preconnect_body(password: &str) -> Vec<u8> {
    let body = Preconnect {
        migration: Migration {
            b2b_base_room: true,
            demo_room_base: true,
            demo_room_version: 2,
            media_without_auto_subscribe: true,
            sberclass_room: true,
            sdk_room: true,
            webinar_speaker: true,
            webinar_viewer: true,
        },
        password,
    };
    serde_json::to_vec(&body).unwrap_or_default()
}

/// The reply's `connectorUrl`, or the default for none.
fn connector_of(body: &[u8]) -> Result<String, Error> {
    #[derive(serde::Deserialize)]
    struct Reply {
        #[serde(rename = "connectorUrl", default)]
        connector_url: String,
    }
    let reply: Reply = serde_json::from_slice(body)
        .map_err(|e| Error::Auth(format!("preconnect: decode response: {e}")))?;
    Ok(if reply.connector_url.is_empty() {
        DEFAULT_CONNECTOR.to_owned()
    } else {
        reply.connector_url
    })
}

/// `Provider.Issue` against `api_base` ([`API_BASE`] in use).
///
/// # Errors
/// [`Error::RoomRef`] for a malformed reference, [`Error::Auth`] when the
/// call fails or the service refuses it (`preconnect failed: status N`).
pub async fn issue(api_base: &str, room_ref: &str) -> Result<Credentials, Error> {
    let (code, password) = split_room_ref(room_ref)?;
    let url = format!("{api_base}/room/{code}/preconnect");
    let target =
        olc_net::stream::parse_url(&url).map_err(|e| Error::Auth(format!("preconnect: {e}")))?;
    let body = preconnect_body(password);
    let call = async {
        let mut stream = olc_net::stream::dial(&target)
            .await
            .map_err(|e| Error::Auth(format!("preconnect: {e}")))?;
        let req = HttpRequest {
            method: "POST",
            host: &target.authority,
            path: &target.path,
            headers: &[
                ("User-Agent", WEB_USER_AGENT),
                ("Content-Type", "application/json"),
                ("Origin", WEB_ORIGIN),
            ],
            body: &body,
            max_body: PRECONNECT_MAX_BODY,
            timeout: PRECONNECT_TIMEOUT,
        };
        http::request(&mut stream, &req)
            .await
            .map_err(|e| Error::Auth(format!("preconnect: {e}")))
    };
    let resp = tokio::time::timeout(PRECONNECT_TIMEOUT, call)
        .await
        .map_err(|_| Error::Auth("preconnect: i/o timeout".into()))??;
    if !(200..300).contains(&resp.status) {
        return Err(Error::Auth(format!(
            "preconnect: preconnect failed: status {}",
            resp.status
        )));
    }
    Ok(Credentials {
        url: connector_of(&resp.body)?,
        token: password.to_owned(),
        room_id: code.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn a_room_reference_splits_as_gos_does() {
        assert_eq!(
            split_room_ref("abc123:passw0rd").unwrap(),
            ("abc123", "passw0rd")
        );
        for bad in [
            "abc123",
            ":passw0rd",
            "abc123:",
            "ABC123:passw0rd",
            "abc:passw0rd",
            "abc123:pass:w0rd",
            "abc123:pass w0rd",
        ] {
            let err = split_room_ref(bad).unwrap_err().to_string();
            assert!(
                !err.contains("passw0rd") && !err.contains("w0rd"),
                "{bad:?} leaked into {err:?}"
            );
        }
    }

    #[test]
    fn the_preconnect_body_is_gos_map_in_sorted_order() {
        assert_eq!(
            String::from_utf8(preconnect_body("passw0rd")).unwrap(),
            r#"{"jazzNextMigration":{"b2bBaseRoomSupport":true,"demoRoomBaseSupport":true,"demoRoomVersionSupport":2,"mediaWithoutAutoSubscribeSupport":true,"sberclassRoomSupport":true,"sdkRoomSupport":true,"webinarSpeakerSupport":true,"webinarViewerSupport":true},"password":"passw0rd"}"#
        );
    }

    #[test]
    fn a_reply_without_a_connector_takes_the_default() {
        assert_eq!(
            connector_of(br#"{"connectorUrl":"wss://x.test/connector"}"#).unwrap(),
            "wss://x.test/connector"
        );
        assert_eq!(connector_of(br"{}").unwrap(), DEFAULT_CONNECTOR);
        assert!(connector_of(b"<html>").is_err());
    }

    /// One preconnect against a loopback server: the request line, the
    /// headers the web client sends, the body; the reply's connector.
    #[tokio::test]
    async fn issue_preconnects_and_returns_the_connector() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", ln.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if got.len() >= head_end + 4 + len {
                        break;
                    }
                }
            }
            let reply = br#"{"connectorUrl":"ws://127.0.0.1:9/connector","other":1}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                reply.len()
            );
            s.write_all(head.as_bytes()).await.unwrap();
            s.write_all(reply).await.unwrap();
            String::from_utf8(got).unwrap()
        });
        let creds = tokio::time::timeout(Duration::from_secs(10), issue(&base, "abc123:passw0rd"))
            .await
            .expect("bounded")
            .unwrap();
        assert_eq!(creds.url, "ws://127.0.0.1:9/connector");
        assert_eq!(
            (creds.token.as_str(), creds.room_id.as_str()),
            ("passw0rd", "abc123")
        );
        assert!(!format!("{creds:?}").contains("passw0rd"));
        let req = server.await.unwrap();
        assert!(
            req.starts_with("POST /room/abc123/preconnect HTTP/1.1\r\n"),
            "{req}"
        );
        for h in [
            format!("User-Agent: {WEB_USER_AGENT}\r\n"),
            "Content-Type: application/json\r\n".to_owned(),
            format!("Origin: {WEB_ORIGIN}\r\n"),
        ] {
            assert!(req.contains(&h), "no {h:?} in {req}");
        }
        assert!(req.ends_with(r#""password":"passw0rd"}"#), "{req}");
    }

    #[tokio::test]
    async fn a_refused_preconnect_names_its_status_and_not_the_password() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", ln.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
                .await;
        });
        let err = tokio::time::timeout(Duration::from_secs(10), issue(&base, "abc123:passw0rd"))
            .await
            .expect("bounded")
            .unwrap_err()
            .to_string();
        assert!(err.contains("status 403"), "{err}");
        assert!(!err.contains("passw0rd"), "{err}");
    }
}

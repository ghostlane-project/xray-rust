// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The signalling WebSocket (`signaling.go`): the endpoint's URL, command
//! frames in the order the SDK writes them, responses matched by sequence,
//! the text keepalive, and the notifications the engine acts on.
//!
//! One reader task per socket. A command is one text frame, never split: the
//! SFU parses every frame on its own and answers a continuation-split
//! message with `invalid-request`.
//!
//! Nothing here logs or formats a frame, an endpoint or a description: they
//! carry the join token and the ICE credentials.
//!
//! Memory: a command frame is built once, bounded by [`FRAME_MAX`] while it
//! is built, and dropped before the wait for its response. An incoming frame
//! is bounded by [`READ_LIMIT`] before it is read; while it is decoded the
//! frame, the decoder's scratch and the decoded description are alive
//! together ([`READ_PEAK`]). At most [`NOTIFICATION_QUEUE`] notifications of
//! at most [`NOTIFICATION_BYTES`] together wait for the engine, and a
//! notification the queue has no room for is dropped.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_net::stream::BoxStream;
use olc_net::ws;
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::AbortHandle;

use crate::answer;

/// The dial, the TLS and the WebSocket handshake together
/// (`wsHandshakeTimeout`).
pub const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// The wait for a command's response (`commandTimeout`).
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
/// The wait for the `connection` notification (`connectionTimeout`).
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// The bound on one command frame (`signalingWriteBuffer`): an
/// accept-producer answer is about 50 KB for the 41-section offer.
pub const FRAME_MAX: usize = 256 << 10;

/// The notifications that wait for the engine; a full queue drops.
pub const NOTIFICATION_QUEUE: usize = 16;

/// The bytes of the notifications that wait for the engine
/// ([`Notification::held`]); a notification that would take the queue past
/// them is dropped as one that finds the queue full is.
///
/// Not Go's, whose queue drops by count alone, so it is sized by what
/// Go's sixteen places hold of a call as it is: the largest frame the
/// socket reads ([`READ_LIMIT`]) always fits an empty queue, sixteen offers
/// of the usual size (50 KB) all wait, and of the largest seen (70 KB)
/// fourteen do. Go's consumer has no claim on more: a notification it
/// cannot place is dropped for good there too, and what waits unread is
/// read in order and passed over unless it is a later session's offer.
pub const NOTIFICATION_BYTES: usize = 1 << 20;

/// The largest frame read: 512 KiB. Go's socket has no bound. The largest
/// frame the engine uses is the offer: about 50 KB for the live 41-section
/// one, 70 KB at most seen, each line end two more bytes as JSON. The bound
/// is seven times that; the shaper's own bound ([`answer::MAX_SDP_SIZE`],
/// 1 MiB) is not reached through the socket. A larger frame ends the
/// socket, which the engine answers with a rejoin.
pub const READ_LIMIT: usize = 512 << 10;

/// What the log says when a frame past [`READ_LIMIT`] ended the socket:
/// the engine answers the socket's end with a rejoin, and an SFU that sends
/// the frame again ends every one of them, so a run that hits the bound is
/// told which bound it was. No room data is in it.
#[must_use]
pub fn read_limit_line() -> String {
    format!("vkcalls: bound READ_LIMIT ({READ_LIMIT} bytes) ended the signaling socket")
}

/// What reading one frame at [`READ_LIMIT`] can hold at once: the message
/// (its buffer grows by doubling, so up to twice the frame), the decoder's
/// scratch for an escaped description and the description itself (each at
/// most the frame). Transient: all but the description is gone when the
/// frame is decoded.
pub const READ_PEAK: usize = 4 * READ_LIMIT;

// A frame the socket read always fits an empty queue: what it holds is at
// most its own bytes and its participants' entries (256 of 56 bytes).
const _: () = assert!(READ_LIMIT + (64 << 10) <= NOTIFICATION_BYTES);

/// The participants kept of one `connection` notification; the rest are
/// read and left out. Go keeps every one.
pub const PARTICIPANTS_MAX: usize = 256;

/// The bound on the hangup's write at close. Go's write has none (it blocks
/// while the socket does).
pub const HANGUP_TIMEOUT: Duration = Duration::from_secs(1);

const FIELD_CONNECTION: &str = "connection";
const FIELD_TOPOLOGY: &str = "topology-changed";
const FRAME_TYPE_ERROR: &str = "error";
const REASON_HUNGUP: &str = "HUNGUP";
pub(crate) const TOPOLOGY_SERVER: &str = "SERVER";

/// The capabilities bitmask of the URL (`capabilitiesBitmask`).
pub const CAPABILITIES_BITMASK: &str = "2F7F";

/// Signalling errors; the texts are Go's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignalingError {
    /// `ErrSignalingEndpoint`. The endpoint is never in the text.
    #[error("vkcalls: invalid signaling endpoint")]
    Endpoint,
    /// `ErrParticipantID`, with which rule it broke.
    #[error("vkcalls: invalid participant id: {0}")]
    ParticipantId(&'static str),
    /// `ErrSignalingClosed`, with what was waited for.
    #[error("vkcalls: signaling socket closed: {0}")]
    Closed(String),
    /// `ErrSignalingRejected`, with the command.
    #[error("vkcalls: signaling command rejected: {0}")]
    Rejected(String),
    /// `ErrSignalingTimeout`, with what was waited for.
    #[error("vkcalls: signaling response timeout: {0}")]
    Timeout(String),
    /// `ErrSignalingNotServer`.
    #[error("vkcalls: conversation is not in SERVER topology")]
    NotServer,
    /// The caller's stop came while the `connection` notification was
    /// waited for (Go: `vkcalls: connection wait:` and its context's
    /// error; the caller knows why it stopped).
    #[error("vkcalls: connection wait: stopped")]
    JoinStopped,
    /// `ErrSignalingPayload`, with the command.
    #[error("vkcalls: signaling command payload: {0} payload is not an object")]
    Payload(String),
    /// `ErrSignalingFrameTooLarge`.
    #[error("vkcalls: signaling command exceeds one frame")]
    FrameTooLarge,
    /// The dial or the handshake failed.
    #[error("vkcalls: signaling dial: {0}")]
    Dial(String),
    /// A command's write failed.
    #[error("vkcalls: signaling write {name}: {why}")]
    Write {
        /// The command.
        name: String,
        /// The transport's error.
        why: String,
    },
}

// ---------------------------------------------------------------------------
// The URL.

/// A query as Go's `url.Values` holds it: keys in byte order, each with its
/// values in their order. Keys and values are bytes: an escape may decode to
/// anything.
#[derive(Default)]
struct Query(BTreeMap<Vec<u8>, Vec<Vec<u8>>>);

impl Query {
    /// `url.ParseQuery`, its error dropped as `URL.Query` drops it: a pair
    /// with a `;` or a bad escape is left out.
    fn parse(raw: &str) -> Self {
        let mut out = Query::default();
        for pair in raw.split('&') {
            if pair.is_empty() || pair.contains(';') {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let (Some(key), Some(value)) = (query_unescape(key), query_unescape(value)) else {
                continue;
            };
            out.0.entry(key).or_default().push(value);
        }
        out
    }

    fn set(&mut self, key: &str, value: &str) {
        self.0
            .insert(key.as_bytes().to_vec(), vec![value.as_bytes().to_vec()]);
    }

    fn get(&self, key: &str) -> Option<&[u8]> {
        self.0
            .get(key.as_bytes())
            .and_then(|values| values.first())
            .map(Vec::as_slice)
    }

    /// `url.Values.Encode`: `key=value` pairs, the keys sorted.
    fn encode(&self) -> String {
        let mut out = String::new();
        for (key, values) in &self.0 {
            for value in values {
                if !out.is_empty() {
                    out.push('&');
                }
                query_escape(&mut out, key);
                out.push('=');
                query_escape(&mut out, value);
            }
        }
        out
    }
}

/// `url.QueryUnescape`.
fn query_unescape(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex_value(*bytes.get(i + 1)?)?;
                let lo = hex_value(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `url.QueryEscape`.
fn query_escape(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
    }
}

/// The scheme and what follows its colon, as `url.Parse` finds them
/// (`getScheme`): letters, then letters, digits, `+`, `-` and `.` up to a
/// colon. Text that has no such start has no scheme and is all rest; a colon
/// in front is the one text refused ("missing protocol scheme").
fn split_scheme(text: &str) -> Option<(&str, &str)> {
    for (i, byte) in text.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i > 0 => return Some((&text[..i], &text[i + 1..])),
            b':' => return None,
            _ => break,
        }
    }
    Some(("", text))
}

/// An endpoint split as `url.Parse` splits it, as far as the signalling
/// needs: the scheme (lower case), what follows its colon up to the query,
/// the query and the fragment.
struct Endpoint<'a> {
    scheme: String,
    /// `//host/path`, as written.
    rest: &'a str,
    query: Query,
    fragment: Option<&'a str>,
}

impl<'a> Endpoint<'a> {
    /// The cases `url.Parse` refuses that an endpoint could show: a control
    /// byte, a colon with no scheme before it, a bad escape in the path, a
    /// port that is not a number. An endpoint with no scheme is one Go
    /// parses (and [`signaling_url`] then refuses for its scheme):
    /// [`self_participant`] reads its query, as `selfParticipant` does.
    fn parse(endpoint: &'a str) -> Option<Self> {
        if endpoint.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return None;
        }
        let (text, fragment) = match endpoint.split_once('#') {
            Some((text, fragment)) => (text, Some(fragment)),
            None => (endpoint, None),
        };
        let (scheme, after) = split_scheme(text)?;
        let (rest, query) = after.split_once('?').unwrap_or((after, ""));
        // With a scheme and no slash behind it the rest is opaque to Go.
        if scheme.is_empty() || rest.starts_with('/') {
            // No scheme, and a colon before the first slash: "first path
            // segment in URL cannot contain colon".
            if scheme.is_empty()
                && !rest.starts_with('/')
                && rest
                    .split('/')
                    .next()
                    .is_some_and(|first| first.contains(':'))
            {
                return None;
            }
            let mut path = rest;
            if let Some(authority) = rest
                .strip_prefix("//")
                .filter(|_| !scheme.is_empty() || !rest.starts_with("///"))
            {
                let (host, behind) = match authority.find('/') {
                    Some(i) => authority.split_at(i),
                    None => (authority, ""),
                };
                let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
                let port = match host.rfind(']') {
                    Some(i) => host[i + 1..].strip_prefix(':'),
                    None => host.rsplit_once(':').map(|(_, port)| port),
                };
                if port.is_some_and(|port| !port.bytes().all(|b| b.is_ascii_digit())) {
                    return None;
                }
                path = behind;
            }
            let path = path.as_bytes();
            for (i, byte) in path.iter().enumerate() {
                if *byte == b'%'
                    && !(path.get(i + 1).copied().and_then(hex_value).is_some()
                        && path.get(i + 2).copied().and_then(hex_value).is_some())
                {
                    return None;
                }
            }
        }
        Some(Endpoint {
            scheme: scheme.to_ascii_lowercase(),
            rest,
            query: Query::parse(query),
            fragment,
        })
    }

    /// `URL.String` with the query encoded anew.
    fn text(&self) -> String {
        let mut out = format!("{}:{}", self.scheme, self.rest);
        let query = self.query.encode();
        if !query.is_empty() {
            out.push('?');
            out.push_str(&query);
        }
        if let Some(fragment) = self.fragment {
            out.push('#');
            out.push_str(fragment);
        }
        out
    }
}

/// The join endpoint with the client parameters the SDK sends on a fresh
/// join (`signalingURL`): the parameters are set over what the endpoint
/// carries and the whole query is encoded again, its keys sorted. `ws://` is
/// the local-test transport.
///
/// The values are what Go at the pin sends.
///
/// # Errors
///
/// [`SignalingError::Endpoint`].
pub fn signaling_url(endpoint: &str) -> Result<String, SignalingError> {
    let mut url = Endpoint::parse(endpoint)
        .filter(|url| url.scheme == "wss" || url.scheme == "ws")
        .ok_or(SignalingError::Endpoint)?;
    url.query.set("platform", "WEB");
    url.query.set("appVersion", "1.1");
    url.query.set("version", "5");
    url.query.set("device", "browser");
    url.query.set("capabilities", CAPABILITIES_BITMASK);
    url.query.set("clientType", "VK");
    url.query.set("tgt", "join");
    Ok(url.text())
}

/// This session's participant id: the endpoint's `userId`
/// (`selfParticipant`). Empty when there is none.
#[must_use]
pub fn self_participant(endpoint: &str) -> String {
    Endpoint::parse(endpoint)
        .and_then(|url| {
            url.query
                .get("userId")
                .map(|id| String::from_utf8_lossy(id).into_owned())
        })
        .unwrap_or_default()
}

/// The debug line's form of a target: the path and the query, with the
/// values that identify the join replaced.
fn redacted(target: &str) -> String {
    let Some(mut url) = Endpoint::parse(target) else {
        return String::new();
    };
    for key in ["token", "userId", "conversationId", "peerId"] {
        if url.query.get(key).is_some() {
            url.query.set(key, "<r>");
        }
    }
    let path = url.rest.strip_prefix("//").map_or(url.rest, |authority| {
        authority.find('/').map_or("", |i| &authority[i..])
    });
    format!("{path}?{}", url.query.encode())
}

// ---------------------------------------------------------------------------
// Command frames.

/// A JSON value of a command's payload, as Go's `map[string]any` holds one.
/// An object's members are written with their keys in byte order, whatever
/// order they are given in (`encoding/json` sorts a map's keys); of two
/// members with one key the later is written.
#[derive(Clone, PartialEq, Eq)]
pub enum Json<'a> {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A string.
    Str(&'a str),
    /// An array.
    Array(Vec<Json<'a>>),
    /// An object.
    Object(Vec<(&'a str, Json<'a>)>),
}

/// Strings are shown by their length: a description holds ICE credentials.
impl std::fmt::Debug for Json<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Json::Null => f.write_str("null"),
            Json::Bool(b) => write!(f, "{b}"),
            Json::Int(n) => write!(f, "{n}"),
            Json::Str(s) => write!(f, "<{} bytes>", s.len()),
            Json::Array(items) => f.debug_list().entries(items).finish(),
            Json::Object(members) => f
                .debug_map()
                .entries(members.iter().map(|(k, v)| (k, v)))
                .finish(),
        }
    }
}

/// `s` as `encoding/json` writes a string (HTML escaping on): what Go's
/// `json.Marshal` puts between the quotes, and the quotes.
pub(crate) fn go_json_string(s: &str) -> String {
    let mut out = FrameText {
        text: String::with_capacity(s.len() + 2),
        limit: usize::MAX,
        over: false,
    };
    out.string(s);
    out.text
}

/// A frame under construction: text up to a bound, and whether more was
/// asked of it.
struct FrameText {
    text: String,
    limit: usize,
    over: bool,
}

impl FrameText {
    fn push_str(&mut self, s: &str) {
        let len = self.text.len() + s.len();
        if self.over || len > self.limit {
            self.over = true;
            return;
        }
        if len > self.text.capacity() {
            // Doubled, as a string grows, but never past the bound.
            let wanted = len.max(2 * self.text.capacity()).min(self.limit);
            self.text.reserve_exact(wanted - self.text.len());
        }
        self.text.push_str(s);
    }

    /// A string as `encoding/json` writes it with HTML escaping on: `"` and
    /// `\` behind a backslash, the short forms of BS, FF, LF, CR and TAB,
    /// `\u00xx` for the other control bytes and for `<`, `>` and `&`, and
    /// `\u2028` / `\u2029`.
    fn string(&mut self, s: &str) {
        self.push_str("\"");
        let bytes = s.as_bytes();
        let mut start = 0;
        let mut i = 0;
        while i < bytes.len() && !self.over {
            let byte = bytes[i];
            let (escape, width): (Option<&str>, usize) = match byte {
                b'"' => (Some("\\\""), 1),
                b'\\' => (Some("\\\\"), 1),
                0x08 => (Some("\\b"), 1),
                0x0C => (Some("\\f"), 1),
                b'\n' => (Some("\\n"), 1),
                b'\r' => (Some("\\r"), 1),
                b'\t' => (Some("\\t"), 1),
                b'<' => (Some("\\u003c"), 1),
                b'>' => (Some("\\u003e"), 1),
                b'&' => (Some("\\u0026"), 1),
                0x00..=0x1F => (None, 1),
                0xE2 if bytes[i..].starts_with(&[0xE2, 0x80, 0xA8]) => (Some("\\u2028"), 3),
                0xE2 if bytes[i..].starts_with(&[0xE2, 0x80, 0xA9]) => (Some("\\u2029"), 3),
                _ => {
                    i += 1;
                    continue;
                }
            };
            self.push_str(&s[start..i]);
            match escape {
                Some(escape) => self.push_str(escape),
                None => {
                    let mut code = String::with_capacity(6);
                    let _ = write!(code, "\\u{byte:04x}");
                    self.push_str(&code);
                }
            }
            i += width;
            start = i;
        }
        if !self.over {
            self.push_str(&s[start..]);
        }
        self.push_str("\"");
    }

    fn value(&mut self, value: &Json<'_>) {
        if self.over {
            return;
        }
        match value {
            Json::Null => self.push_str("null"),
            Json::Bool(true) => self.push_str("true"),
            Json::Bool(false) => self.push_str("false"),
            Json::Int(n) => {
                let mut digits = String::with_capacity(20);
                let _ = write!(digits, "{n}");
                self.push_str(&digits);
            }
            Json::Str(s) => self.string(s),
            Json::Array(items) => {
                self.push_str("[");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.push_str(",");
                    }
                    self.value(item);
                }
                self.push_str("]");
            }
            Json::Object(members) => {
                self.push_str("{");
                self.members(members);
                self.push_str("}");
            }
        }
    }

    /// An object's members without its braces, the keys in byte order.
    fn members(&mut self, members: &[(&str, Json<'_>)]) {
        let mut sorted: Vec<&(&str, Json<'_>)> = members.iter().collect();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mut first = true;
        for (i, (key, value)) in sorted.iter().enumerate() {
            if sorted.get(i + 1).is_some_and(|next| next.0 == *key) {
                continue;
            }
            if !first {
                self.push_str(",");
            }
            first = false;
            self.string(key);
            self.push_str(":");
            self.value(value);
        }
    }
}

/// What a value's text takes at least: the capacity a frame starts with.
fn size_hint(value: &Json<'_>) -> usize {
    match value {
        Json::Null | Json::Bool(_) => 5,
        Json::Int(_) => 8,
        Json::Str(s) => s.len() + 2,
        Json::Array(items) => 2 + items.iter().map(|item| size_hint(item) + 1).sum::<usize>(),
        Json::Object(members) => {
            2 + members
                .iter()
                .map(|(key, value)| key.len() + 4 + size_hint(value))
                .sum::<usize>()
        }
    }
}

/// A command frame (`orderedCommandFrame`): `command` and `sequence` first,
/// then the payload's own members, the order the SDK writes. No payload
/// ([`Json::Null`]) or one without members closes the frame after the
/// sequence.
///
/// # Errors
///
/// [`SignalingError::Payload`] for a payload that is not an object;
/// [`SignalingError::FrameTooLarge`] past [`FRAME_MAX`] bytes (the frame is
/// given up as soon as it passes the bound).
pub fn ordered_command_frame(
    name: &str,
    sequence: i64,
    payload: &Json<'_>,
) -> Result<String, SignalingError> {
    let members: &[(&str, Json<'_>)] = match payload {
        Json::Null => &[],
        Json::Object(members) => members,
        _ => return Err(SignalingError::Payload(name.to_owned())),
    };
    let hint = (size_hint(payload) + name.len() + 48).min(FRAME_MAX);
    let mut frame = FrameText {
        text: String::with_capacity(hint),
        limit: FRAME_MAX,
        over: false,
    };
    frame.push_str("{\"command\":");
    frame.string(name);
    frame.push_str(",\"sequence\":");
    frame.value(&Json::Int(sequence));
    // Go compares the marshalled payload with `{}`: an object whose members
    // all yield to a later one of their key is never empty.
    if !members.is_empty() {
        frame.push_str(",");
        frame.members(members);
    }
    frame.push_str("}");
    if frame.over {
        return Err(SignalingError::FrameTooLarge);
    }
    Ok(frame.text)
}

/// The hangup frame (`hangup`): a plain map's marshal, so its keys sorted.
pub(crate) fn hangup_frame(sequence: i64) -> String {
    format!("{{\"command\":\"hangup\",\"reason\":\"{REASON_HUNGUP}\",\"sequence\":{sequence}}}")
}

/// One value of the capabilities report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// A feature we have or have not.
    Flag(bool),
    /// A version or a count.
    Number(i64),
}

/// The `allocate-consumer` feature report Go at the pin sends
/// (`referenceCapabilities`): only what the engine implements.
pub const REFERENCE_CAPABILITIES: [(&str, Capability); 23] = [
    ("estimatedPerformanceIndex", Capability::Number(0)),
    ("audioMix", Capability::Flag(true)),
    ("consumerUpdate", Capability::Flag(true)),
    (
        "producerNotificationDataChannelVersion",
        Capability::Number(8),
    ),
    ("producerCommandDataChannelVersion", Capability::Number(3)),
    ("consumerScreenDataChannelVersion", Capability::Number(1)),
    ("producerScreenDataChannelVersion", Capability::Number(1)),
    ("asrDataChannelVersion", Capability::Number(1)),
    ("animojiDataChannelVersion", Capability::Number(2)),
    ("animojiBackendRender", Capability::Flag(true)),
    ("onDemandTracks", Capability::Flag(true)),
    ("unifiedPlan", Capability::Flag(true)),
    ("singleSession", Capability::Flag(true)),
    ("videoTracksCount", Capability::Number(36)),
    ("red", Capability::Flag(true)),
    ("audioShare", Capability::Flag(true)),
    ("fastScreenShare", Capability::Flag(true)),
    ("videoSuspend", Capability::Flag(false)),
    ("simulcast", Capability::Flag(true)),
    ("simulcastNativeOrder", Capability::Flag(true)),
    ("consumerFastScreenShare", Capability::Flag(false)),
    (
        "consumerFastScreenShareQualityOnDemand",
        Capability::Flag(false),
    ),
    ("transparentAudio", Capability::Flag(false)),
];

/// The `allocate-consumer` payload: `{"capabilities":{…}}`
/// ([`REFERENCE_CAPABILITIES`] is what Go sends).
#[must_use]
pub fn allocate_consumer<'a>(capabilities: &[(&'a str, Capability)]) -> Json<'a> {
    let members = capabilities
        .iter()
        .map(|(key, value)| {
            let value = match value {
                Capability::Flag(flag) => Json::Bool(*flag),
                Capability::Number(n) => Json::Int(*n),
            };
            (*key, value)
        })
        .collect();
    Json::Object(vec![("capabilities", Json::Object(members))])
}

/// The `update-media-modifiers` payload.
#[must_use]
pub fn update_media_modifiers() -> Json<'static> {
    Json::Object(vec![(
        "mediaModifiers",
        Json::Object(vec![
            ("denoise", Json::Bool(true)),
            ("denoiseAnn", Json::Bool(true)),
        ]),
    )])
}

/// The `change-media-settings` payload.
#[must_use]
pub fn change_media_settings() -> Json<'static> {
    Json::Object(vec![(
        "mediaSettings",
        Json::Object(vec![
            ("isAudioEnabled", Json::Bool(false)),
            ("isVideoEnabled", Json::Bool(false)),
            ("isScreenSharingEnabled", Json::Bool(false)),
            ("isFastScreenSharingEnabled", Json::Bool(false)),
            ("isAudioSharingEnabled", Json::Bool(false)),
            ("isAnimojiEnabled", Json::Bool(true)),
        ]),
    )])
}

/// The `accept-producer` payload (`acceptPayload`): the shaped answer, the
/// session the offer belonged to and the offer's SSRC attributions, as
/// strings.
#[must_use]
pub fn accept_producer<'a>(offer: &'a str, shaped: &'a str, session_id: &'a str) -> Json<'a> {
    let ssrcs = answer::remote_ssrcs(offer)
        .into_iter()
        .map(Json::Str)
        .collect();
    Json::Object(vec![
        ("description", Json::Str(shaped)),
        ("sessionId", Json::Str(session_id)),
        ("ssrcs", Json::Array(ssrcs)),
    ])
}

// ---------------------------------------------------------------------------
// Frames from the server.

/// A participant id as the connector writes one: a number or a string
/// (Go's `any`).
#[derive(Debug, Clone, Default, PartialEq)]
pub enum AnyId {
    /// No value, or `null`.
    #[default]
    Absent,
    /// A JSON number, as Go's `float64` holds it.
    Number(f64),
    /// A JSON string.
    Text(String),
    /// Anything else.
    Other,
}

impl<'de> Deserialize<'de> for AnyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = AnyId;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any value")
            }
            fn visit_unit<E>(self) -> Result<AnyId, E> {
                Ok(AnyId::Absent)
            }
            fn visit_bool<E>(self, _: bool) -> Result<AnyId, E> {
                Ok(AnyId::Other)
            }
            #[allow(clippy::cast_precision_loss)] // Go's float64 loses it as well.
            fn visit_i64<E>(self, n: i64) -> Result<AnyId, E> {
                Ok(AnyId::Number(n as f64))
            }
            #[allow(clippy::cast_precision_loss)]
            fn visit_u64<E>(self, n: u64) -> Result<AnyId, E> {
                Ok(AnyId::Number(n as f64))
            }
            fn visit_f64<E>(self, n: f64) -> Result<AnyId, E> {
                Ok(AnyId::Number(n))
            }
            fn visit_str<E>(self, s: &str) -> Result<AnyId, E> {
                Ok(AnyId::Text(s.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<AnyId, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(AnyId::Other)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<AnyId, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(AnyId::Other)
            }
        }
        deserializer.deserialize_any(Any)
    }
}

/// `null` leaves a field at its zero value, as `encoding/json` does.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// The first [`PARTICIPANTS_MAX`] entries of a participant list; `null` is
/// an empty one.
fn participants<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Participant>, D::Error> {
    struct List;
    impl<'de> Visitor<'de> for List {
        type Value = Vec<Participant>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a participant list")
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while out.len() < PARTICIPANTS_MAX {
                match seq.next_element::<Option<Participant>>()? {
                    Some(entry) => out.push(entry.unwrap_or_default()),
                    None => return Ok(out),
                }
            }
            // Still checked for its form, as Go checks the whole frame.
            while seq.next_element::<Option<Participant>>()?.is_some() {}
            Ok(out)
        }
    }
    deserializer.deserialize_any(List)
}

/// `peerId` of a frame.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct PeerId {
    /// The peer's number.
    #[serde(deserialize_with = "nullable")]
    pub id: i64,
}

/// One participant of a `connection` notification.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Participant {
    /// The participant's id.
    pub id: AnyId,
    /// Its state (`ACCEPTED`, `HUNGUP`, `REJECTED`).
    #[serde(deserialize_with = "nullable")]
    pub state: String,
}

/// `conversation` of a `connection` notification.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Conversation {
    /// `DIRECT` or `SERVER`.
    #[serde(deserialize_with = "nullable")]
    pub topology: String,
    /// The participants, [`PARTICIPANTS_MAX`] at most.
    #[serde(deserialize_with = "participants")]
    pub participants: Vec<Participant>,
}

/// One server frame (`notification`): only the fields the engine acts on.
#[derive(Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Notification {
    /// `type`: `response`, `error`, `notification`.
    #[serde(rename = "type", deserialize_with = "nullable")]
    pub kind: String,
    /// The command's sequence a response answers; 0 on a notification.
    #[serde(deserialize_with = "nullable")]
    pub sequence: i64,
    /// The command a response answers.
    #[serde(deserialize_with = "nullable")]
    pub response: String,
    /// The notification's name.
    #[serde(deserialize_with = "nullable")]
    pub notification: String,
    /// The server's stamp (read, never used).
    #[serde(deserialize_with = "nullable")]
    pub stamp: i64,
    /// `peerId`.
    #[serde(rename = "peerId")]
    pub peer_id: Option<PeerId>,
    /// `sessionId`: the session an offer belongs to.
    #[serde(rename = "sessionId", deserialize_with = "nullable")]
    pub session_id: String,
    /// `description`: the offer of a `producer-updated`.
    #[serde(deserialize_with = "nullable")]
    pub description: String,
    /// The value of a `topology-changed`; a `connection` carries it inside
    /// its conversation.
    #[serde(deserialize_with = "nullable")]
    pub topology: String,
    /// `conversation`.
    pub conversation: Option<Conversation>,
    /// `participantId`.
    #[serde(rename = "participantId")]
    pub participant_id: AnyId,
}

impl Notification {
    /// The bytes this frame holds while it waits: its own size and every
    /// text and list it owns. A text decoded from a frame has no spare
    /// capacity, so the lengths are what is held.
    #[must_use]
    pub fn held(&self) -> usize {
        let id = |id: &AnyId| match id {
            AnyId::Text(text) => text.len(),
            _ => 0,
        };
        let conversation = self.conversation.as_ref().map_or(0, |c| {
            c.topology.len()
                + c.participants.len() * std::mem::size_of::<Participant>()
                + c.participants
                    .iter()
                    .map(|p| id(&p.id) + p.state.len())
                    .sum::<usize>()
        });
        std::mem::size_of::<Self>()
            + self.kind.len()
            + self.response.len()
            + self.notification.len()
            + self.session_id.len()
            + self.description.len()
            + self.topology.len()
            + id(&self.participant_id)
            + conversation
    }
}

/// The description and the session are shown by their length only.
impl std::fmt::Debug for Notification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notification")
            .field("type", &self.kind)
            .field("sequence", &self.sequence)
            .field("response", &self.response)
            .field("notification", &self.notification)
            .field("topology", &self.topology)
            .field("description_len", &self.description.len())
            .field(
                "participants",
                &self.conversation.as_ref().map(|c| c.participants.len()),
            )
            .finish_non_exhaustive()
    }
}

/// One text frame decoded as Go decodes it into `notification`: `null` is an
/// empty frame; a field of another type refuses the whole frame.
fn decode(text: &str) -> Result<Notification, serde_json::Error> {
    Ok(serde_json::from_str::<Option<Notification>>(text)?.unwrap_or_default())
}

/// What the debug line says of a frame that did not decode: its size and the
/// error's class and place. Never the error's own text, which quotes the
/// value it met, and never the frame: both can hold the join token.
fn invalid_frame_text(len: usize, error: &serde_json::Error) -> String {
    format!(
        "vkcalls: invalid signaling frame: {len} bytes: {:?} error at column {}",
        error.classify(),
        error.column()
    )
}

/// A participant id as a decimal string (`decimalID`).
///
/// # Errors
///
/// [`SignalingError::ParticipantId`].
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
pub fn decimal_id(id: &AnyId) -> Result<String, SignalingError> {
    match id {
        AnyId::Number(n) => {
            // Go: `t != float64(int64(t))`.
            let whole = *n >= -9_223_372_036_854_775_808.0
                && *n < 9_223_372_036_854_775_808.0
                && (*n as i64) as f64 == *n;
            if !whole {
                return Err(SignalingError::ParticipantId("non-integer"));
            }
            Ok((*n as i64).to_string())
        }
        AnyId::Text(text) => {
            // `strconv.ParseInt(text, 10, 64)`: a sign, then digits.
            let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
            if digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || text.parse::<i64>().is_err()
            {
                return Err(SignalingError::ParticipantId("non-numeric"));
            }
            Ok(text.clone())
        }
        AnyId::Absent | AnyId::Other => Err(SignalingError::ParticipantId("unsupported type")),
    }
}

/// The ids of the participants still in the conversation, ours left out
/// (`participantIDs`).
#[must_use]
pub fn participant_ids(note: &Notification, self_id: &str) -> Vec<String> {
    let Some(conversation) = &note.conversation else {
        return Vec::new();
    };
    conversation
        .participants
        .iter()
        .filter(|p| p.state != REASON_HUNGUP && p.state != "REJECTED")
        .filter_map(|p| decimal_id(&p.id).ok())
        .filter(|id| id != self_id)
        .collect()
}

// ---------------------------------------------------------------------------
// The socket.

/// The headers of the handshake that the code sets. The defaults are what Go
/// at the pin sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialOptions<'a> {
    /// `Origin`.
    pub origin: &'a str,
    /// `Referer`.
    pub referer: &'a str,
    /// `User-Agent`: Go's HTTP client names itself when the caller sets
    /// none. Empty sends no such header.
    pub user_agent: &'a str,
}

impl Default for DialOptions<'_> {
    fn default() -> Self {
        DialOptions {
            origin: "https://vk.com",
            referer: "https://vk.com/",
            user_agent: "Go-http-client/1.1",
        }
    }
}

struct State {
    /// The write half; gone once the socket is shut down.
    writer: Option<ws::Writer<BoxStream>>,
    /// The commands that wait for their response, by sequence.
    waiters: BTreeMap<i64, oneshot::Sender<Notification>>,
    reader: Option<AbortHandle>,
}

/// The reader's end of the notification queue: the channel and the bytes
/// of what waits in it, counted up here and down by [`Notifications`].
struct Queue {
    sender: mpsc::Sender<Notification>,
    held: Arc<AtomicUsize>,
}

impl Queue {
    /// Queues `note`; false when the queue has no room for it.
    fn offer(&self, note: Notification) -> bool {
        let bytes = note.held();
        // Counted before the send: the reader's side may take the frame,
        // and count it down, the moment it is in the channel.
        let before = self.held.fetch_add(bytes, Ordering::AcqRel);
        if before.saturating_add(bytes) <= NOTIFICATION_BYTES && self.sender.try_send(note).is_ok()
        {
            return true;
        }
        self.held.fetch_sub(bytes, Ordering::AcqRel);
        false
    }
}

struct Shared {
    /// Go's `writeMu` for commands: a sequence is taken and its frame
    /// written in one piece.
    order: tokio::sync::Mutex<()>,
    sequence: AtomicI64,
    state: Mutex<State>,
    closed: watch::Sender<bool>,
    self_id: String,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn writer(&self) -> Option<ws::Writer<BoxStream>> {
        self.state().writer.clone()
    }

    /// `shutdown`: once. The socket's halves are let go, the reader is
    /// stopped and every waiting command is told (its sender is dropped).
    fn shutdown(&self) {
        let (writer, waiters, reader) = {
            let mut state = self.state();
            (
                state.writer.take(),
                std::mem::take(&mut state.waiters),
                state.reader.take(),
            )
        };
        drop(writer);
        drop(waiters);
        if let Some(reader) = reader {
            reader.abort();
        }
        self.closed.send_replace(true);
    }

    /// `deliver`: a frame whose sequence a command waits for goes to that
    /// command and nowhere else; anything else is a notification.
    fn deliver(&self, note: Notification, queue: &Queue) {
        if note.sequence != 0 {
            let waiter = self.state().waiters.remove(&note.sequence);
            if let Some(waiter) = waiter {
                let _ = waiter.send(note);
                return;
            }
        }
        if !queue.offer(note) {
            olc_net::debug!("vkcalls: notification dropped, queue full");
        }
    }
}

/// Takes a command's waiter away when the command ends, however it ends.
struct Waiter<'a> {
    shared: &'a Shared,
    sequence: i64,
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.shared.state().waiters.remove(&self.sequence);
    }
}

/// Shuts the socket down when a frame's write did not finish: a command
/// dropped in the middle of its write leaves half a frame on the wire, and
/// nothing after it could be read.
struct Unfinished<'a>(Option<&'a Shared>);

impl Drop for Unfinished<'_> {
    fn drop(&mut self) {
        if let Some(shared) = self.0 {
            shared.shutdown();
        }
    }
}

/// How long the socket may stay quiet before it is taken for dead
/// (`signalingSilence`). VK's signalling sends a text "ping" every 5 s
/// (measured live, 2026-11-19), so six missed pings is no lull. Without it a
/// socket whose peer vanished without a FIN reads forever, deaf to the call.
pub const SIGNALING_SILENCE: Duration = Duration::from_secs(30);

/// The socket's only reader (`readLoop`). Nothing read for
/// [`SIGNALING_SILENCE`] ends the socket like a read error: the reader is
/// dropped mid-read, which is safe because nothing reads it again.
async fn read_loop(reader: ws::Reader<BoxStream>, shared: Arc<Shared>, queue: Queue) {
    read_loop_within(reader, shared, queue, SIGNALING_SILENCE).await;
}

async fn read_loop_within(
    mut reader: ws::Reader<BoxStream>,
    shared: Arc<Shared>,
    queue: Queue,
    silence: Duration,
) {
    loop {
        let Ok(next) = tokio::time::timeout(silence, reader.next()).await else {
            olc_net::debug!("vkcalls: signalling silent for {silence:?}, ending the socket");
            break;
        };
        let text = match next {
            Ok(ws::Message::Text(text)) => text,
            Ok(ws::Message::Binary(_)) => continue,
            Err(ws::WsError::TooLarge) => {
                olc_net::debug!("{}", read_limit_line());
                break;
            }
            Err(_) => break,
        };
        if text == "ping" {
            if let Some(writer) = shared.writer() {
                let _ = writer.send_text("pong").await;
            }
            continue;
        }
        match decode(&text) {
            Ok(note) => {
                drop(text);
                shared.deliver(note, &queue);
            }
            Err(error) => olc_net::debug!("{}", invalid_frame_text(text.len(), &error)),
        }
    }
    shared.shutdown();
}

/// One signalling WebSocket (`signalingClient`): commands and the close.
/// Its notifications are read through the [`Notifications`] it came with.
///
/// Every way out of a join ends in [`Signaling::close`], which hangs up
/// before it shuts the socket: a guest that only went away stays listed in
/// the call until the SFU times it out, beside the next attempt's guest.
pub struct Signaling {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Signaling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signaling")
            .field("sequence", &self.shared.sequence.load(Ordering::Relaxed))
            .field("closed", &*self.shared.closed.borrow())
            .finish_non_exhaustive()
    }
}

impl Signaling {
    /// Opens the signalling socket (`dialSignaling`). The endpoint comes
    /// from the join response and already carries the token and `userId`.
    ///
    /// # Errors
    ///
    /// [`SignalingError::Endpoint`]; [`SignalingError::Dial`] for the dial,
    /// the TLS, the handshake, or [`WS_HANDSHAKE_TIMEOUT`] over all three.
    pub async fn dial(
        endpoint: &str,
        options: DialOptions<'_>,
    ) -> Result<(Signaling, Notifications), SignalingError> {
        let target_url = signaling_url(endpoint)?;
        olc_net::debug!("vkcalls: signaling url {}", redacted(&target_url));
        let dialed = target_url
            .split_once('#')
            .map_or(&*target_url, |(url, _)| url);
        // The parse error would quote the URL.
        let target = olc_net::stream::parse_url(dialed).map_err(|_| SignalingError::Endpoint)?;
        let mut headers: Vec<(&str, &str)> =
            vec![("Origin", options.origin), ("Referer", options.referer)];
        if !options.user_agent.is_empty() {
            headers.push(("User-Agent", options.user_agent));
        }
        let handshake = async {
            let stream = olc_net::stream::dial(&target)
                .await
                .map_err(|e| SignalingError::Dial(e.to_string()))?;
            let request = ws::Request {
                host: &target.authority,
                path: &target.path,
                headers: &headers,
                read_limit: READ_LIMIT,
                timeout: WS_HANDSHAKE_TIMEOUT,
            };
            ws::handshake(stream, &request)
                .await
                .map_err(|e| SignalingError::Dial(e.to_string()))
        };
        let (reader, writer) = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| SignalingError::Dial("i/o timeout".to_owned()))??;

        let (sender, notifications) = mpsc::channel(NOTIFICATION_QUEUE);
        let held = Arc::new(AtomicUsize::new(0));
        let queue = Queue {
            sender,
            held: Arc::clone(&held),
        };
        let shared = Arc::new(Shared {
            order: tokio::sync::Mutex::new(()),
            sequence: AtomicI64::new(0),
            state: Mutex::new(State {
                writer: Some(writer),
                waiters: BTreeMap::new(),
                reader: None,
            }),
            closed: watch::Sender::new(false),
            self_id: self_participant(endpoint),
        });
        let task = tokio::spawn(read_loop(reader, Arc::clone(&shared), queue));
        {
            let mut state = shared.state();
            if state.writer.is_some() {
                state.reader = Some(task.abort_handle());
            }
        }
        Ok((
            Signaling { shared },
            Notifications {
                queue: notifications,
                held,
            },
        ))
    }

    /// This session's participant id (`Self`).
    #[must_use]
    pub fn self_id(&self) -> &str {
        &self.shared.self_id
    }

    /// Whether the socket is gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.shared.closed.borrow()
    }

    /// Returns once the socket is gone (`Closed`).
    pub async fn closed(&self) {
        let mut closed = self.shared.closed.subscribe();
        // The sender lives in `shared`, which `self` holds.
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Sends one command frame and waits for its response or error frame
    /// (`command`). The sequence is taken, and the waiter is in place,
    /// before the first byte goes out; a frame that would not fit one frame
    /// is refused before any byte goes out and still takes its sequence, as
    /// in Go.
    ///
    /// Dropped while its frame is being written, it shuts the socket down
    /// (half a frame is on the wire); dropped while it waits, it only gives
    /// up its response.
    ///
    /// # Errors
    ///
    /// [`SignalingError::Payload`], [`SignalingError::FrameTooLarge`],
    /// [`SignalingError::Write`]; [`SignalingError::Rejected`] for an error
    /// frame; [`SignalingError::Timeout`] after [`COMMAND_TIMEOUT`];
    /// [`SignalingError::Closed`] for a socket that is gone or goes while
    /// the command waits.
    pub async fn command(
        &self,
        name: &str,
        payload: &Json<'_>,
    ) -> Result<Notification, SignalingError> {
        let shared = &*self.shared;
        let order = shared.order.lock().await;
        let sequence = shared.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let (waiter, response) = oneshot::channel();
        let writer = {
            let mut state = shared.state();
            let writer = state.writer.clone();
            if writer.is_some() {
                state.waiters.insert(sequence, waiter);
            }
            writer
        };
        let _waiter = Waiter { shared, sequence };
        let Some(writer) = writer else {
            return Err(SignalingError::Closed(name.to_owned()));
        };
        let frame = ordered_command_frame(name, sequence, payload)?;
        let mut unfinished = Unfinished(Some(shared));
        let sent = writer.send_text(&frame).await;
        // The frame is not kept while its response is waited for.
        drop(frame);
        drop(writer);
        match sent {
            Ok(()) => unfinished.0 = None,
            Err(error) => {
                drop(unfinished);
                return Err(SignalingError::Write {
                    name: name.to_owned(),
                    why: error.to_string(),
                });
            }
        }
        drop(order);

        tokio::select! {
            biased;
            note = response => match note {
                Ok(note) if note.kind == FRAME_TYPE_ERROR => {
                    Err(SignalingError::Rejected(name.to_owned()))
                }
                Ok(note) => Ok(note),
                Err(_) => Err(SignalingError::Closed(name.to_owned())),
            },
            () = tokio::time::sleep(COMMAND_TIMEOUT) => {
                Err(SignalingError::Timeout(name.to_owned()))
            }
        }
    }

    /// Leaves the conversation, best effort, and tears the socket down
    /// (`close`): the hangup names the next sequence without taking it, and
    /// nothing is waited for but its write, [`HANGUP_TIMEOUT`] at most.
    pub async fn close(&self) {
        if let Some(writer) = self.shared.writer() {
            let frame = hangup_frame(self.shared.sequence.load(Ordering::Relaxed) + 1);
            let _ = tokio::time::timeout(HANGUP_TIMEOUT, writer.send_text(&frame)).await;
        }
        self.shared.shutdown();
    }
}

impl Drop for Signaling {
    /// A socket dropped unclosed (a join given up in the middle of a wait)
    /// still leaves the conversation: the hangup goes out from a task of
    /// its own, [`HANGUP_TIMEOUT`] at most, and the socket is shut after
    /// it. Go has one way out, `close`; a dropped future is Rust's second.
    /// Outside a runtime the socket is only shut.
    fn drop(&mut self) {
        let Some(writer) = self.shared.writer() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.shared.shutdown();
            return;
        };
        let shared = Arc::clone(&self.shared);
        let frame = hangup_frame(shared.sequence.load(Ordering::Relaxed) + 1);
        runtime.spawn(async move {
            let _ = tokio::time::timeout(HANGUP_TIMEOUT, writer.send_text(&frame)).await;
            drop(writer);
            shared.shutdown();
        });
    }
}

/// The server frames that answer no command, in their order
/// (`Notifications`): 16 at most wait here, and [`NOTIFICATION_BYTES`] at
/// most.
#[derive(Debug)]
pub struct Notifications {
    queue: mpsc::Receiver<Notification>,
    /// The bytes of what waits in the queue ([`Notification::held`]).
    held: Arc<AtomicUsize>,
}

impl Notifications {
    /// The next notification; `None` once the socket is gone and what it
    /// had queued is read.
    pub async fn recv(&mut self) -> Option<Notification> {
        let note = self.queue.recv().await?;
        self.held.fetch_sub(note.held(), Ordering::AcqRel);
        Some(note)
    }

    /// The bytes of the notifications that wait here.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    /// Waits for this socket's `connection` notification, the moment the
    /// participant counts in the conversation, whatever its topology
    /// (`awaitJoin`). Other notifications read on the way are let go.
    ///
    /// # Errors
    ///
    /// [`SignalingError::Timeout`] after [`CONNECTION_TIMEOUT`];
    /// [`SignalingError::Closed`].
    pub async fn await_join(&mut self) -> Result<Notification, SignalingError> {
        let deadline = tokio::time::sleep(CONNECTION_TIMEOUT);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                biased;
                note = self.recv() => match note {
                    Some(note) if note.notification == FIELD_CONNECTION => return Ok(note),
                    Some(_) => {}
                    None => return Err(SignalingError::Closed(FIELD_CONNECTION.to_owned())),
                },
                () = &mut deadline => {
                    return Err(SignalingError::Timeout(FIELD_CONNECTION.to_owned()));
                }
            }
        }
    }

    /// Returns when the conversation stands in SERVER topology
    /// (`waitServerTopology`): at once for a room that opened there, and on
    /// the `topology-changed` a third simultaneous participant triggers for
    /// a fresh room's DIRECT. There is no timer here; `stop` is the caller's
    /// (Go's context): when it ends first the topology is named as the
    /// reason.
    ///
    /// # Errors
    ///
    /// [`SignalingError::NotServer`] when `stop` ends first;
    /// [`SignalingError::Closed`].
    pub async fn wait_server_topology(
        &mut self,
        mut connection: Notification,
        stop: impl Future<Output = ()>,
    ) -> Result<(), SignalingError> {
        let in_server = |note: &Notification| {
            note.conversation
                .as_ref()
                .is_some_and(|c| c.topology == TOPOLOGY_SERVER)
        };
        if in_server(&connection) {
            return Ok(());
        }
        olc_net::debug!(
            "vkcalls: conversation opened outside SERVER topology; \
             waiting for the switch a second participant triggers"
        );
        tokio::pin!(stop);
        while !in_server(&connection) {
            tokio::select! {
                biased;
                note = self.recv() => match note {
                    // The connection note's participant list is stale now;
                    // the engine learns every join as its own notification.
                    Some(note)
                        if note.notification == FIELD_TOPOLOGY
                            && note.topology == TOPOLOGY_SERVER =>
                    {
                        return Ok(());
                    }
                    Some(note) if note.notification == FIELD_CONNECTION => connection = note,
                    Some(_) => {}
                    None => {
                        return Err(SignalingError::Closed(
                            "waiting for SERVER topology".to_owned(),
                        ));
                    }
                },
                () = &mut stop => return Err(SignalingError::NotServer),
            }
        }
        Ok(())
    }

    /// Reads the notifications until the socket is gone, so a
    /// signalling-only guest's queue never fills (`drainNotifications`).
    pub async fn drain(mut self) {
        while self.recv().await.is_some() {}
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::AtomicBool;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use sha1::{Digest, Sha1};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::answer::tests::FIXTURE_OFFER;

    /// One async test's bound: a stuck test fails instead of holding the
    /// shared build box.
    pub(crate) async fn bounded<F: Future>(f: F) -> F::Output {
        bounded_for(Duration::from_secs(20), f).await
    }

    pub(crate) async fn bounded_for<F: Future>(bound: Duration, f: F) -> F::Output {
        match tokio::time::timeout(bound, f).await {
            Ok(out) => out,
            Err(_) => panic!("the test did not finish in time"),
        }
    }

    // ----- The fake SFU's socket: the server side of RFC 6455, as far as
    // the tests need it (olc_net::ws is the client under test).

    pub(crate) type Write = Arc<tokio::sync::Mutex<OwnedWriteHalf>>;

    /// A client frame as it arrived on the wire.
    #[derive(Debug)]
    pub(crate) struct Frame {
        pub(crate) fin: bool,
        pub(crate) opcode: u8,
        pub(crate) payload: Vec<u8>,
    }

    impl Frame {
        pub(crate) fn text(&self) -> &str {
            std::str::from_utf8(&self.payload).unwrap()
        }
    }

    /// Reads one raw frame (RFC 6455 5.2): a reader that joined
    /// continuation frames would hide a split. `None` at the end of the
    /// stream.
    pub(crate) async fn read_frame(read: &mut OwnedReadHalf) -> Option<Frame> {
        let mut head = [0u8; 2];
        read.read_exact(&mut head).await.ok()?;
        assert!(head[1] & 0x80 != 0, "a client frame is masked");
        let len = match head[1] & 0x7f {
            126 => {
                let mut ext = [0u8; 2];
                read.read_exact(&mut ext).await.ok()?;
                u64::from(u16::from_be_bytes(ext))
            }
            127 => {
                let mut ext = [0u8; 8];
                read.read_exact(&mut ext).await.ok()?;
                u64::from_be_bytes(ext)
            }
            n => u64::from(n),
        };
        let mut mask = [0u8; 4];
        read.read_exact(&mut mask).await.ok()?;
        let mut payload = vec![0u8; usize::try_from(len).unwrap()];
        read.read_exact(&mut payload).await.ok()?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }
        Some(Frame {
            fin: head[0] & 0x80 != 0,
            opcode: head[0] & 0x0f,
            payload,
        })
    }

    async fn write_frame(write: &Write, opcode: u8, payload: &[u8]) {
        let mut frame = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            frame.push(u8::try_from(len).unwrap());
        } else if len <= 0xffff {
            frame.push(126);
            frame.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        let _ = write.lock().await.write_all(&frame).await;
    }

    pub(crate) async fn write_text(write: &Write, text: &str) {
        write_frame(write, 1, text.as_bytes()).await;
    }

    /// A listener on loopback and the endpoint that reaches it.
    pub(crate) async fn listen() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "ws://{}/fb?token=SECRETTOKEN&userId=42",
            listener.local_addr().unwrap()
        );
        (listener, endpoint)
    }

    /// Accepts one connection and answers its handshake with `status`.
    /// Returns the request's head and the socket's halves.
    async fn accept_with(listener: &TcpListener, status: &str) -> (String, OwnedReadHalf, Write) {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            read.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap();
        let mut hash = Sha1::new();
        hash.update(key.as_bytes());
        hash.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = STANDARD.encode(hash.finalize());
        let response = format!(
            "HTTP/1.1 {status}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        write.write_all(response.as_bytes()).await.unwrap();
        (head, read, Arc::new(tokio::sync::Mutex::new(write)))
    }

    pub(crate) async fn accept(listener: &TcpListener) -> (String, OwnedReadHalf, Write) {
        accept_with(listener, "101 Switching Protocols").await
    }

    /// `fakeSFU`: answers every command with a response frame naming it, or
    /// with an error frame once `reject` is set; notes a `pong`; keeps the
    /// text frames it read.
    struct FakeSfu {
        write: Write,
        seen_pong: Arc<AtomicBool>,
        reject: Arc<AtomicBool>,
        frames: Arc<Mutex<Vec<String>>>,
        serve: JoinHandle<()>,
    }

    impl FakeSfu {
        fn serve(mut read: OwnedReadHalf, write: Write) -> Self {
            let seen_pong = Arc::new(AtomicBool::new(false));
            let reject = Arc::new(AtomicBool::new(false));
            let frames = Arc::new(Mutex::new(Vec::new()));
            let serve = tokio::spawn({
                let (write, seen_pong, reject, frames) = (
                    Arc::clone(&write),
                    Arc::clone(&seen_pong),
                    Arc::clone(&reject),
                    Arc::clone(&frames),
                );
                async move {
                    while let Some(frame) = read_frame(&mut read).await {
                        assert!(frame.fin && frame.opcode == 1, "{frame:?}");
                        let text = frame.text().to_owned();
                        frames.lock().unwrap().push(text.clone());
                        if text == "pong" {
                            seen_pong.store(true, Ordering::SeqCst);
                            continue;
                        }
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let Some(command) = value["command"].as_str() else {
                            continue;
                        };
                        let reply = if reject.load(Ordering::SeqCst) {
                            serde_json::json!({"sequence": value["sequence"], "type": "error"})
                        } else {
                            serde_json::json!({"sequence": value["sequence"], "response": command, "type": "response"})
                        };
                        write_text(&write, &reply.to_string()).await;
                    }
                }
            });
            FakeSfu {
                write,
                seen_pong,
                reject,
                frames,
                serve,
            }
        }

        async fn send(&self, frame: serde_json::Value) {
            write_text(&self.write, &frame.to_string()).await;
        }

        fn frames(&self) -> Vec<String> {
            self.frames.lock().unwrap().clone()
        }

        /// Closes the socket from the server's side, with no close frame.
        async fn close(&self) {
            self.serve.abort();
            let _ = self.write.lock().await.shutdown().await;
        }
    }

    /// Dials the listener and serves the connection with a [`FakeSfu`].
    async fn connect(
        listener: &TcpListener,
        endpoint: &str,
    ) -> (Signaling, Notifications, FakeSfu, String) {
        let (dialed, accepted) = tokio::join!(
            Signaling::dial(endpoint, DialOptions::default()),
            accept(listener)
        );
        let (signaling, notifications) = dialed.unwrap();
        let (head, read, write) = accepted;
        (signaling, notifications, FakeSfu::serve(read, write), head)
    }

    pub(crate) fn connection(topology: &str, participants: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "type": "notification", "notification": "connection",
            "peerId": {"id": 111},
            "conversation": {"topology": topology, "participants": participants},
        })
    }

    // ----- The Go tests.

    // TestSignalingCommandFlow: the connection notification, command
    // response correlation, the ping/pong keepalive, rejection and the
    // closed-session failure.
    #[tokio::test]
    async fn signaling_command_flow() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (signaling, mut notifications, sfu, _) = connect(&listener, &endpoint).await;
            sfu.send(connection(
                "SERVER",
                serde_json::json!([
                    {"id": 42, "state": "ACCEPTED"},
                    {"id": 43, "state": "HUNGUP"},
                ]),
            ))
            .await;

            let note = notifications.await_join().await.unwrap();
            assert_eq!(
                note.conversation.as_ref().map(|c| c.topology.as_str()),
                Some("SERVER")
            );
            assert_eq!(note.peer_id, Some(PeerId { id: 111 }));
            assert_eq!(signaling.self_id(), "42");
            assert_eq!(participant_ids(&note, "42"), Vec::<String>::new());
            assert_eq!(participant_ids(&note, "7"), ["42"]);

            let response = signaling
                .command(
                    "allocate-consumer",
                    &allocate_consumer(&REFERENCE_CAPABILITIES),
                )
                .await
                .unwrap();
            assert_eq!(response.response, "allocate-consumer");
            assert_eq!(response.sequence, 1);

            // The keepalive: a text "ping" from the server is answered
            // "pong".
            write_text(&sfu.write, "ping").await;
            while !sfu.seen_pong.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            // A command with no payload is still one JSON object, so the
            // fake parses it and its error frame is a rejection.
            sfu.reject.store(true, Ordering::SeqCst);
            assert_eq!(
                signaling
                    .command("update-media-modifiers", &Json::Null)
                    .await,
                Err(SignalingError::Rejected("update-media-modifiers".into()))
            );
            assert_eq!(
                sfu.frames().last().map(String::as_str),
                Some(r#"{"command":"update-media-modifiers","sequence":2}"#)
            );

            // Closing the socket fails pending and future commands.
            assert!(!signaling.is_closed());
            sfu.close().await;
            signaling.closed().await;
            assert!(signaling.is_closed());
            assert_eq!(
                signaling.command("hangup", &Json::Null).await,
                Err(SignalingError::Closed("hangup".into()))
            );
            assert_eq!(notifications.recv().await, None);
            assert_eq!(
                notifications.await_join().await,
                Err(SignalingError::Closed("connection".into()))
            );
        })
        .await;
    }

    // TestSignalingURL, and the whole text.
    #[test]
    fn the_signaling_url() {
        let got = signaling_url("wss://calls.example.okcdn.ru/fb?token=t&userId=1").unwrap();
        for want in [
            "platform=WEB",
            "appVersion=1.1",
            "version=5",
            "capabilities=2F7F",
            "tgt=join",
        ] {
            assert!(got.contains(want), "url {got:?} missing {want:?}");
        }
        assert_eq!(
            got,
            "wss://calls.example.okcdn.ru/fb?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&token=t&userId=1&version=5"
        );
        assert_eq!(
            signaling_url("https://calls.example/"),
            Err(SignalingError::Endpoint)
        );
    }

    /// What Go's `signalingURL` and `selfParticipant` return for these
    /// endpoints (run at the pin, 2026-11-15).
    #[test]
    fn the_signaling_url_as_go_writes_it() {
        // Of note: the peer id is kept; a pair with a bad escape or a
        // semicolon is left out; a key with no value and an empty key stay;
        // a plus is a space and is written as a plus again; the scheme is
        // lower-cased, the host and the path are not touched; a parameter
        // the endpoint carries is replaced; a key's values keep their order
        // and the first userId is ours; an opaque URL passes.
        let cases: &[(&str, Option<&str>, &str)] = &[
            (
                "",
                None,
                "",
            ),
            (
                "WSS://H:8443/p",
                Some("wss://H:8443/p?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&version=5"),
                "",
            ),
            (
                "calls.example/x",
                None,
                "",
            ),
            (
                "https://calls.example/",
                None,
                "",
            ),
            (
                "ws://127.0.0.1:1/?a=1&a=2&platform=X&userId=7&userId=8",
                Some("ws://127.0.0.1:1/?a=1&a=2&appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&userId=7&userId=8&version=5"),
                "7",
            ),
            (
                "wss://calls.example.okcdn.ru/fb?token=t&userId=1",
                Some("wss://calls.example.okcdn.ru/fb?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&token=t&userId=1&version=5"),
                "1",
            ),
            (
                "wss://h/%zz",
                None,
                "",
            ),
            (
                "wss://h/a%20b/c?q=%7E~-_.%21",
                Some("wss://h/a%20b/c?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&q=~~-_.%21&tgt=join&version=5"),
                "",
            ),
            (
                "wss://h/p\u{1}",
                None,
                "",
            ),
            (
                "wss://h/p?",
                Some("wss://h/p?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&version=5"),
                "",
            ),
            (
                "wss://h/p?k=\u{e9}&%C3%A9=1",
                Some("wss://h/p?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&k=%C3%A9&platform=WEB&tgt=join&version=5&%C3%A9=1"),
                "",
            ),
            (
                "wss://h/p?userId=42&token=a%2Bb+c&conversationId=x&peerId=9&entityType=CHAT&z=%zz&bad;semi=1&=v&k&e=",
                Some("wss://h/p?=v&appVersion=1.1&capabilities=2F7F&clientType=VK&conversationId=x&device=browser&e=&entityType=CHAT&k=&peerId=9&platform=WEB&tgt=join&token=a%2Bb+c&userId=42&version=5"),
                "42",
            ),
            (
                "wss://h:port/",
                None,
                "",
            ),
            (
                "wss://h?x=1#frag",
                Some("wss://h?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&version=5&x=1#frag"),
                "",
            ),
            (
                "wss:opaque?x=1",
                Some("wss:opaque?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&version=5&x=1"),
                "",
            ),
        ];
        for (endpoint, want, self_id) in cases {
            assert_eq!(
                signaling_url(endpoint).ok().as_deref(),
                *want,
                "signaling_url({endpoint:?})"
            );
            assert_eq!(&self_participant(endpoint), self_id, "self of {endpoint:?}");
        }
    }

    #[test]
    fn the_debug_line_names_no_join() {
        let target = signaling_url(
            "wss://h/fb/x?token=SECRETTOKEN&userId=4242&conversationId=CONV&peerId=PEER&entityType=CHAT",
        )
        .unwrap();
        let line = redacted(&target);
        assert_eq!(
            line,
            "/fb/x?appVersion=1.1&capabilities=2F7F&clientType=VK&conversationId=%3Cr%3E&device=browser&entityType=CHAT&peerId=%3Cr%3E&platform=WEB&tgt=join&token=%3Cr%3E&userId=%3Cr%3E&version=5"
        );
        for secret in ["SECRETTOKEN", "4242", "CONV", "PEER"] {
            assert!(!line.contains(secret), "{line}");
        }
    }

    // TestSignalingLargeCommandIsOneFrame: a large command leaves as one
    // text frame; one larger than the bound is refused before any byte goes
    // out, never split.
    #[tokio::test]
    async fn a_large_command_is_one_frame() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (dialed, accepted) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept(&listener)
            );
            let (signaling, _notifications) = dialed.unwrap();
            let (_, mut read, write) = accepted;
            let (headers, mut seen) = mpsc::channel(4);
            let server = tokio::spawn(async move {
                while let Some(frame) = read_frame(&mut read).await {
                    let sequence = serde_json::from_slice::<serde_json::Value>(&frame.payload)
                        .unwrap()["sequence"]
                        .clone();
                    headers
                        .send((frame.fin, frame.opcode, frame.payload.len(), sequence.clone()))
                        .await
                        .unwrap();
                    let reply = serde_json::json!({"stamp": 0, "sequence": sequence, "response": "accept-producer", "type": "response"});
                    write_text(&write, &reply.to_string()).await;
                }
            });

            let description = "a=rtcp-fb:96 nack pli\r\n".repeat(3000);
            let payload = Json::Object(vec![("description", Json::Str(&description))]);
            let want = ordered_command_frame("accept-producer", 1, &payload).unwrap();
            assert!(want.len() > 70_000, "{}", want.len());
            signaling.command("accept-producer", &payload).await.unwrap();
            assert_eq!(
                seen.recv().await,
                Some((true, 1, want.len(), serde_json::json!(1)))
            );

            let huge = "x".repeat(FRAME_MAX);
            let payload = Json::Object(vec![("description", Json::Str(&huge))]);
            assert_eq!(
                signaling.command("accept-producer", &payload).await,
                Err(SignalingError::FrameTooLarge)
            );
            // Nothing of it went out: the next frame the server reads is the
            // next command, whole. The refused one took its sequence.
            signaling.command("accept-producer", &Json::Null).await.unwrap();
            assert_eq!(
                seen.recv().await,
                Some((
                    true,
                    1,
                    r#"{"command":"accept-producer","sequence":3}"#.len(),
                    serde_json::json!(3)
                ))
            );
            assert!(!signaling.is_closed());
            server.abort();
        })
        .await;
    }

    // TestOrderedCommandFrameIsJSON: one JSON object whatever the payload
    // holds: none, no fields, or fields.
    #[test]
    fn an_ordered_command_frame_is_json() {
        let one = Json::Object(vec![("a", Json::Int(1))]);
        for (payload, want) in [
            (&Json::Null, r#"{"command":"x","sequence":2}"#),
            (&Json::Object(vec![]), r#"{"command":"x","sequence":2}"#),
            (&one, r#"{"command":"x","sequence":2,"a":1}"#),
        ] {
            let raw = ordered_command_frame("x", 2, payload).unwrap();
            assert_eq!(raw, want);
            assert!(serde_json::from_str::<serde_json::Value>(&raw)
                .unwrap()
                .is_object());
        }
        assert_eq!(
            ordered_command_frame("x", 2, &Json::Array(vec![Json::Int(1)])),
            Err(SignalingError::Payload("x".into()))
        );
        for scalar in [Json::Bool(true), Json::Int(0), Json::Str("{}")] {
            assert_eq!(
                ordered_command_frame("x", 2, &scalar),
                Err(SignalingError::Payload("x".into()))
            );
        }
    }

    /// The frames of the four commands with the payloads the engine sends,
    /// byte for byte as Go's `orderedCommandFrame` writes them (run at the
    /// pin, 2026-11-15).
    #[test]
    fn the_command_frames_as_go_writes_them() {
        assert_eq!(
            ordered_command_frame(
                "allocate-consumer",
                1,
                &allocate_consumer(&REFERENCE_CAPABILITIES)
            )
            .unwrap(),
            concat!(
                r#"{"command":"allocate-consumer","sequence":1,"capabilities":{"#,
                r#""animojiBackendRender":true,"animojiDataChannelVersion":2,"asrDataChannelVersion":1,"#,
                r#""audioMix":true,"audioShare":true,"consumerFastScreenShare":false,"#,
                r#""consumerFastScreenShareQualityOnDemand":false,"consumerScreenDataChannelVersion":1,"#,
                r#""consumerUpdate":true,"estimatedPerformanceIndex":0,"fastScreenShare":true,"#,
                r#""onDemandTracks":true,"producerCommandDataChannelVersion":3,"#,
                r#""producerNotificationDataChannelVersion":8,"producerScreenDataChannelVersion":1,"#,
                r#""red":true,"simulcast":true,"simulcastNativeOrder":true,"singleSession":true,"#,
                r#""transparentAudio":false,"unifiedPlan":true,"videoSuspend":false,"videoTracksCount":36}}"#,
            )
        );
        assert_eq!(
            ordered_command_frame("update-media-modifiers", 2, &update_media_modifiers()).unwrap(),
            r#"{"command":"update-media-modifiers","sequence":2,"mediaModifiers":{"denoise":true,"denoiseAnn":true}}"#
        );
        assert_eq!(
            ordered_command_frame("change-media-settings", 3, &change_media_settings()).unwrap(),
            concat!(
                r#"{"command":"change-media-settings","sequence":3,"mediaSettings":{"isAnimojiEnabled":true,"#,
                r#""isAudioEnabled":false,"isAudioSharingEnabled":false,"isFastScreenSharingEnabled":false,"#,
                r#""isScreenSharingEnabled":false,"isVideoEnabled":false}}"#,
            )
        );
        // A description with CRLF, the HTML characters, the two line
        // separators, a quote, a backslash, a tab, a control byte, DEL and a
        // letter outside ASCII; the fixture offer's SSRCs as strings.
        let shaped = "v=0\r\na=x:<>&\u{2028}\u{2029}\"\\\t\u{1}\u{7f} \u{e9}\r\n";
        assert_eq!(
            ordered_command_frame(
                "accept-producer",
                4,
                &accept_producer(FIXTURE_OFFER, shaped, "sess-1")
            )
            .unwrap(),
            concat!(
                r#"{"command":"accept-producer","sequence":4,"description":"#,
                r#""v=0\r\na=x:\u003c\u003e\u0026\u2028\u2029\"\\\t\u0001"#,
                "\u{7f} \u{e9}",
                r#"\r\n","sessionId":"sess-1","ssrcs":["2463708138","2463708139"]}"#,
            )
        );
        // Keys in byte order at every level (upper case first), the later of
        // two members with one key, every kind of value, a name that needs
        // its own escapes.
        let payload = Json::Object(vec![
            ("a", Json::Array(vec![])),
            ("Z", Json::Null),
            ("n", Json::Int(i64::MIN + 1)),
            ("a", Json::Array(vec![])),
            (
                "B",
                Json::Array(vec![
                    Json::Str("s"),
                    Json::Int(1),
                    Json::Bool(false),
                    Json::Null,
                    Json::Object(vec![]),
                ]),
            ),
        ]);
        assert_eq!(
            ordered_command_frame("a\"b<c", -3, &payload).unwrap(),
            r#"{"command":"a\"b\u003cc","sequence":-3,"B":["s",1,false,null,{}],"Z":null,"a":[],"n":-9223372036854775807}"#
        );
        // Every ASCII byte.
        let all: String = (0u8..0x80).map(char::from).collect();
        let payload = Json::Object(vec![("s", Json::Str(&all))]);
        assert_eq!(
            ordered_command_frame("x", 1, &payload).unwrap(),
            concat!(
                r#"{"command":"x","sequence":1,"s":""#,
                r#"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f"#,
                r#"\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"#,
                r##" !\"#$%\u0026'()*+,-./0123456789:;\u003c=\u003e?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"##,
                "\u{7f}\"}",
            )
        );
        assert_eq!(
            hangup_frame(5),
            r#"{"command":"hangup","reason":"HUNGUP","sequence":5}"#
        );
    }

    /// The bound is on the frame's bytes: 262,144 pass, one more is refused.
    #[test]
    fn the_frame_bound() {
        let overhead = ordered_command_frame("x", 1, &Json::Object(vec![("d", Json::Str(""))]))
            .unwrap()
            .len();
        let fits = "x".repeat(FRAME_MAX - overhead);
        let frame =
            ordered_command_frame("x", 1, &Json::Object(vec![("d", Json::Str(&fits))])).unwrap();
        assert_eq!(frame.len(), 262_144);
        let over = "x".repeat(FRAME_MAX - overhead + 1);
        assert_eq!(
            ordered_command_frame("x", 1, &Json::Object(vec![("d", Json::Str(&over))])),
            Err(SignalingError::FrameTooLarge)
        );
        // The escapes count: a string of the bound's size in `<` is three
        // frames' worth.
        let escaped = "<".repeat(FRAME_MAX / 6);
        assert_eq!(
            ordered_command_frame("x", 1, &Json::Object(vec![("d", Json::Str(&escaped))])),
            Err(SignalingError::FrameTooLarge)
        );
        // Whatever is asked, no more than the bound is ever held.
        let big = "x".repeat(4 * FRAME_MAX);
        let payload = Json::Object(vec![("a", Json::Str(&big)), ("b", Json::Str(&big))]);
        let mut frame = FrameText {
            text: String::new(),
            limit: FRAME_MAX,
            over: false,
        };
        frame.value(&payload);
        assert!(frame.over);
        assert!(
            frame.text.capacity() <= FRAME_MAX,
            "{}",
            frame.text.capacity()
        );
    }

    // TestSignalingWaitsForServerTopology: a lone guest is handed DIRECT,
    // and the wait ends only on the topology-changed a later participant
    // triggers, or with the caller's stop, naming the topology.
    #[tokio::test]
    async fn the_wait_for_server_topology() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (signaling, mut notifications, sfu, _) = connect(&listener, &endpoint).await;
            sfu.send(connection("DIRECT", serde_json::json!([]))).await;

            let wait = tokio::spawn(async move {
                let note = notifications.await_join().await?;
                let waited = notifications
                    .wait_server_topology(note, std::future::pending())
                    .await;
                waited.map(|()| notifications)
            });
            // Still waiting while the room is DIRECT.
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(!wait.is_finished(), "the wait ended early");
            sfu.send(serde_json::json!({"type": "notification", "notification": "topology-changed", "topology": "DIRECT"}))
                .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!wait.is_finished(), "a change to DIRECT ended the wait");
            sfu.send(serde_json::json!({"type": "notification", "notification": "topology-changed", "topology": "SERVER"}))
                .await;
            let mut notifications = wait.await.unwrap().unwrap();

            // A stop that comes in DIRECT names the topology. The first wait
            // consumed the connection notification, so the fake sends it
            // again.
            sfu.send(connection("DIRECT", serde_json::json!([]))).await;
            let note = notifications.await_join().await.unwrap();
            assert_eq!(
                notifications
                    .wait_server_topology(note, tokio::time::sleep(Duration::from_millis(50)))
                    .await,
                Err(SignalingError::NotServer)
            );

            // A room that opened in SERVER is not waited for; a second
            // connection notification in SERVER ends the wait too; a socket
            // that goes while waiting says so.
            sfu.send(connection("SERVER", serde_json::json!([]))).await;
            let note = notifications.await_join().await.unwrap();
            notifications
                .wait_server_topology(note, std::future::ready(()))
                .await
                .unwrap();
            sfu.send(connection("SERVER", serde_json::json!([]))).await;
            notifications
                .wait_server_topology(Notification::default(), std::future::pending())
                .await
                .unwrap();
            sfu.close().await;
            assert_eq!(
                notifications
                    .wait_server_topology(Notification::default(), std::future::pending())
                    .await,
                Err(SignalingError::Closed("waiting for SERVER topology".into()))
            );
            drop(signaling);
        })
        .await;
    }

    // ----- Beyond the Go tests.

    /// The handshake's request: the target with its query sorted, and the
    /// three headers Go sends.
    #[tokio::test]
    async fn the_handshake_request() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (signaling, _notifications, _sfu, head) = connect(&listener, &endpoint).await;
            let port = listener.local_addr().unwrap().port();
            assert!(
                head.starts_with(
                    "GET /fb?appVersion=1.1&capabilities=2F7F&clientType=VK&device=browser&platform=WEB&tgt=join&token=SECRETTOKEN&userId=42&version=5 HTTP/1.1\r\n"
                ),
                "{head}"
            );
            for line in [
                format!("Host: 127.0.0.1:{port}\r\n"),
                "Origin: https://vk.com\r\n".to_owned(),
                "Referer: https://vk.com/\r\n".to_owned(),
                "User-Agent: Go-http-client/1.1\r\n".to_owned(),
            ] {
                assert!(head.contains(&line), "{head:?} lacks {line:?}");
            }
            assert!(!head.contains("Sec-WebSocket-Protocol"), "{head}");
            assert!(!head.contains("Sec-WebSocket-Extensions"), "{head}");
            drop(signaling);

            // The headers are the caller's to change; an empty User-Agent
            // sends none.
            let options = DialOptions {
                origin: "https://example.test",
                referer: "https://example.test/x",
                user_agent: "",
            };
            let (dialed, accepted) =
                tokio::join!(Signaling::dial(&endpoint, options), accept(&listener));
            dialed.unwrap();
            let head = accepted.0;
            assert!(head.contains("Origin: https://example.test\r\n"), "{head}");
            assert!(head.contains("Referer: https://example.test/x\r\n"), "{head}");
            assert!(!head.contains("User-Agent"), "{head}");
        })
        .await;
    }

    /// A refused handshake and a bad endpoint: neither error names the
    /// endpoint.
    #[tokio::test]
    async fn a_failed_dial_names_no_endpoint() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (dialed, _) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept_with(&listener, "403 Forbidden")
            );
            let error = dialed.unwrap_err();
            assert!(matches!(error, SignalingError::Dial(_)), "{error:?}");
            assert!(error.to_string().contains("403"), "{error}");
            for bad in [
                "https://h/fb?token=SECRETTOKEN".to_owned(),
                "wss://h:99999/fb?token=SECRETTOKEN".to_owned(),
                "wss://u:p@h/fb?token=SECRETTOKEN".to_owned(),
                "wss:///fb?token=SECRETTOKEN".to_owned(),
            ] {
                let error = Signaling::dial(&bad, DialOptions::default())
                    .await
                    .unwrap_err();
                assert_eq!(error, SignalingError::Endpoint, "{bad}");
            }
            // Nobody listens: the dial's own error, without the query.
            drop(listener);
            let error = Signaling::dial(&endpoint, DialOptions::default())
                .await
                .unwrap_err();
            assert!(matches!(error, SignalingError::Dial(_)), "{error:?}");
            assert!(
                !format!("{error} {error:?}").contains("SECRETTOKEN"),
                "{error:?}"
            );
        })
        .await;
    }

    /// Responses go to their commands by sequence, whatever order they come
    /// in; a response nobody waits for is a notification.
    #[tokio::test]
    async fn responses_are_matched_by_sequence() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (dialed, accepted) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept(&listener)
            );
            let (signaling, mut notifications) = dialed.unwrap();
            let (_, mut read, write) = accepted;
            let server = tokio::spawn(async move {
                let first = read_frame(&mut read).await.unwrap();
                let second = read_frame(&mut read).await.unwrap();
                assert_eq!(first.text(), r#"{"command":"one","sequence":1}"#);
                assert_eq!(second.text(), r#"{"command":"two","sequence":2,"k":true}"#);
                write_text(
                    &write,
                    r#"{"sequence":9,"response":"nobody","type":"response"}"#,
                )
                .await;
                write_text(
                    &write,
                    r#"{"sequence":2,"response":"for-two","type":"response"}"#,
                )
                .await;
                write_text(
                    &write,
                    r#"{"sequence":1,"response":"for-one","type":"response"}"#,
                )
                .await;
                // Held open until the test ends.
                let _ = read_frame(&mut read).await;
            });
            let two = Json::Object(vec![("k", Json::Bool(true))]);
            let (one, two) = tokio::join!(
                signaling.command("one", &Json::Null),
                signaling.command("two", &two)
            );
            assert_eq!(one.unwrap().response, "for-one");
            assert_eq!(two.unwrap().response, "for-two");
            let stray = notifications.recv().await.unwrap();
            assert_eq!((stray.sequence, stray.response.as_str()), (9, "nobody"));
            assert!(signaling.shared.state().waiters.is_empty());
            server.abort();
        })
        .await;
    }

    /// The queue holds 16 notifications; the seventeenth and after are
    /// dropped, and the socket goes on.
    #[tokio::test]
    async fn a_full_queue_drops() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (signaling, mut notifications, sfu, _) = connect(&listener, &endpoint).await;
            for stamp in 1..=20 {
                sfu.send(serde_json::json!({"notification": "n", "stamp": stamp}))
                    .await;
            }
            // Binary frames and frames that do not decode are passed over.
            write_frame(&sfu.write, 2, b"binary").await;
            write_text(&sfu.write, "not json").await;
            write_text(&sfu.write, r#"{"sequence":"SECRETTOKEN"}"#).await;
            // The reader has seen all of it once it answers a command.
            signaling.command("mark", &Json::Null).await.unwrap();
            for stamp in 1..=16 {
                assert_eq!(notifications.recv().await.unwrap().stamp, stamp);
            }
            sfu.send(serde_json::json!({"notification": "n", "stamp": 21}))
                .await;
            assert_eq!(notifications.recv().await.unwrap().stamp, 21);
            assert_eq!(NOTIFICATION_QUEUE, 16);
            // The drain reads to the end.
            let drained = tokio::spawn(notifications.drain());
            sfu.send(serde_json::json!({"notification": "n"})).await;
            sfu.close().await;
            drained.await.unwrap();
        })
        .await;
    }

    /// The queue is bounded in bytes too: an offer that would take what
    /// waits past [`NOTIFICATION_BYTES`] is dropped, as the seventeenth
    /// notification is, and room comes back as the engine reads.
    #[tokio::test]
    async fn a_queue_past_its_bytes_drops() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (signaling, mut notifications, sfu, _) = connect(&listener, &endpoint).await;
            let offer = "x".repeat(400 << 10);
            let note = |stamp: i64| {
                serde_json::json!({
                    "notification": "producer-updated", "stamp": stamp, "description": offer,
                })
            };
            // Two offers of 400 KiB are under 1 MiB; the third is past it.
            for stamp in 1..=3 {
                sfu.send(note(stamp)).await;
            }
            // A small one still fits behind the two.
            sfu.send(serde_json::json!({"notification": "n", "stamp": 7}))
                .await;
            signaling.command("mark", &Json::Null).await.unwrap();
            assert_eq!(
                notifications.held(),
                2 * Notification::held(&decode(&note(1).to_string()).unwrap()) + small_held()
            );
            for stamp in 1..=2 {
                let got = notifications.recv().await.unwrap();
                assert_eq!((got.stamp, got.description.len()), (stamp, 400 << 10));
            }
            assert_eq!(notifications.recv().await.unwrap().stamp, 7);
            assert_eq!(notifications.held(), 0);
            // What was read is room again.
            sfu.send(note(8)).await;
            signaling.command("mark", &Json::Null).await.unwrap();
            assert_eq!(notifications.recv().await.unwrap().stamp, 8);
            assert_eq!(NOTIFICATION_BYTES, 1 << 20);
            // The largest frame the socket reads always fits an empty
            // queue. Sixteen offers of a live call's usual size (50 KB)
            // all wait, as in Go's sixteen places; of the largest seen
            // (70 KB) fourteen do, and the fifteenth is dropped where Go
            // drops the seventeenth.
            const { assert!(READ_LIMIT + (64 << 10) <= NOTIFICATION_BYTES) };
            const { assert!(NOTIFICATION_QUEUE * 50_000 <= NOTIFICATION_BYTES - (64 << 10)) };
            const { assert!(14 * crate::engine::LIVE_OFFER <= NOTIFICATION_BYTES - (8 << 10)) };
        })
        .await;
    }

    fn small_held() -> usize {
        decode(r#"{"notification":"n","stamp":7}"#).unwrap().held()
    }

    /// What a notification holds is its own size and every text and list it
    /// owns.
    #[test]
    fn a_notification_counts_what_it_owns() {
        let empty = Notification::default().held();
        assert_eq!(empty, std::mem::size_of::<Notification>());
        let note = decode(
            r#"{"type":"notification","notification":"connection","sessionId":"abc","description":"0123456789",
                "conversation":{"topology":"SERVER","participants":[{"id":"12345","state":"ACCEPTED"},{"id":7}]}}"#,
        )
        .unwrap();
        assert_eq!(
            note.held(),
            empty
                + "notification".len()
                + "connection".len()
                + "abc".len()
                + "0123456789".len()
                + "SERVER".len()
                + 2 * std::mem::size_of::<Participant>()
                + "12345".len()
                + "ACCEPTED".len()
        );
    }

    /// A frame of the read limit is read; one byte more ends the socket
    /// before the frame is taken in, and one log line names the bound
    /// (fidelity S3 of the wave-2 review: the engine answers the socket's
    /// end with a rejoin, which meets the same frame, so the run that hits
    /// the bound must say so). A socket that ends otherwise names none.
    #[tokio::test]
    async fn a_frame_past_the_read_limit_ends_the_socket() {
        const LIMIT: usize = 512 << 10;
        bounded(async {
            let log = crate::testing::log_lines();
            let (listener, endpoint) = listen().await;
            let (signaling, mut notifications, sfu, _) = connect(&listener, &endpoint).await;
            let frame = |len: usize| {
                let head = r#"{"notification":"producer-updated","description":""#;
                let fill = len - head.len() - 2;
                format!("{head}{}\"}}", "x".repeat(fill))
            };
            assert_eq!(frame(LIMIT).len(), LIMIT);
            write_text(&sfu.write, &frame(LIMIT)).await;
            let got = notifications.recv().await.unwrap();
            assert_eq!(got.description.len(), LIMIT - 52);
            assert_eq!(log.starting("vkcalls: bound "), [""; 0]);
            write_text(&sfu.write, &frame(LIMIT + 1)).await;
            assert_eq!(notifications.recv().await, None);
            signaling.closed().await;
            assert!(signaling.is_closed());
            assert_eq!(READ_LIMIT, LIMIT);
            assert_eq!(
                log.starting("vkcalls: bound "),
                ["vkcalls: bound READ_LIMIT (524288 bytes) ended the signaling socket"]
            );
            assert_eq!(log.starting("vkcalls: bound "), [read_limit_line()]);

            // The far end going away is no bound's doing.
            let log = crate::testing::log_lines();
            let (signaling, mut notifications, sfu, _) = connect(&listener, &endpoint).await;
            sfu.close().await;
            assert_eq!(notifications.recv().await, None);
            signaling.closed().await;
            assert_eq!(log.starting("vkcalls: bound "), [""; 0]);
        })
        .await;
    }

    /// A socket that stays open but says nothing ends after
    /// SIGNALING_SILENCE, like a read error, so the session rejoins instead of
    /// staying deaf to the call (the FI servers, 2026-11-19).
    #[tokio::test(start_paused = true)]
    async fn a_silent_socket_ends() {
        bounded_for(Duration::from_secs(120), async {
            let (listener, endpoint) = listen().await;
            let (signaling, mut notifications, _sfu, _) = connect(&listener, &endpoint).await;
            let start = tokio::time::Instant::now();
            assert_eq!(notifications.recv().await, None);
            signaling.closed().await;
            assert!(start.elapsed() >= SIGNALING_SILENCE);
            assert_eq!(SIGNALING_SILENCE, Duration::from_secs(30));
        })
        .await;
    }

    /// VK's ping every 5 s keeps the socket open well past the deadline.
    #[tokio::test(start_paused = true)]
    async fn pings_keep_the_socket() {
        bounded_for(Duration::from_secs(120), async {
            let (listener, endpoint) = listen().await;
            let (signaling, _notifications, sfu, _) = connect(&listener, &endpoint).await;
            for _ in 0..16 {
                tokio::time::sleep(Duration::from_secs(5)).await;
                write_text(&sfu.write, "ping").await;
                tokio::task::yield_now().await;
                assert!(!signaling.is_closed());
            }
        })
        .await;
    }

    /// A command nobody answers ends after 15 s; the join wait after 30 s.
    #[tokio::test]
    async fn the_waits_end_on_their_timers() {
        // The clock is stopped below and jumps to the next timer: this
        // bound must lie past the 15 s and the 30 s the test waits out.
        bounded_for(Duration::from_secs(120), async {
            let (listener, endpoint) = listen().await;
            let (dialed, accepted) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept(&listener)
            );
            let (signaling, mut notifications) = dialed.unwrap();
            let (_, mut read, write) = accepted;
            // The server reads and never answers.
            let server =
                tokio::spawn(async move { while read_frame(&mut read).await.is_some() {} });
            write_text(
                &write,
                r#"{"notification":"participant-joined","participantId":7}"#,
            )
            .await;
            // Read before the clock stops: the wait must pass over it.
            tokio::time::sleep(Duration::from_millis(50)).await;
            // VK's keepalive, so SIGNALING_SILENCE does not end the socket
            // under the waits.
            let pinger = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    write_text(&write, "ping").await;
                }
            });

            tokio::time::pause();
            let before = tokio::time::Instant::now();
            assert_eq!(
                signaling.command("allocate-consumer", &Json::Null).await,
                Err(SignalingError::Timeout("allocate-consumer".into()))
            );
            // A timer fires on its millisecond.
            let exact = |waited: Duration, want: Duration| {
                waited >= want && waited < want + Duration::from_millis(5)
            };
            assert!(
                exact(before.elapsed(), COMMAND_TIMEOUT),
                "{:?}",
                before.elapsed()
            );
            assert_eq!(COMMAND_TIMEOUT, Duration::from_secs(15));
            assert!(signaling.shared.state().waiters.is_empty());

            let before = tokio::time::Instant::now();
            assert_eq!(
                notifications.await_join().await,
                Err(SignalingError::Timeout("connection".into()))
            );
            assert!(
                exact(before.elapsed(), CONNECTION_TIMEOUT),
                "{:?}",
                before.elapsed()
            );
            assert_eq!(CONNECTION_TIMEOUT, Duration::from_secs(30));
            assert_eq!(WS_HANDSHAKE_TIMEOUT, Duration::from_secs(20));
            tokio::time::resume();
            assert!(!signaling.is_closed());
            pinger.abort();
            server.abort();
        })
        .await;
    }

    /// A command that waits when the socket goes is told so; the close
    /// leaves a hangup naming the next sequence, and no close frame.
    #[tokio::test]
    async fn the_close() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (dialed, accepted) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept(&listener)
            );
            let (signaling, mut notifications) = dialed.unwrap();
            let (_, mut read, _write) = accepted;
            let server = tokio::spawn(async move {
                let mut frames = Vec::new();
                while let Some(frame) = read_frame(&mut read).await {
                    frames.push((frame.fin, frame.opcode, frame.text().to_owned()));
                }
                frames
            });
            let (answer, ()) = tokio::join!(signaling.command("wait", &Json::Null), async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                signaling.close().await;
            });
            assert_eq!(answer, Err(SignalingError::Closed("wait".into())));
            assert!(signaling.is_closed());
            signaling.closed().await;
            assert_eq!(notifications.recv().await, None);
            // The server reads to the end of the stream: the socket is
            // closed though `signaling` still lives.
            assert_eq!(
                server.await.unwrap(),
                [
                    (true, 1, r#"{"command":"wait","sequence":1}"#.to_owned()),
                    (
                        true,
                        1,
                        r#"{"command":"hangup","reason":"HUNGUP","sequence":2}"#.to_owned()
                    ),
                ]
            );
            // Closing again does nothing.
            signaling.close().await;
        })
        .await;
    }

    /// A socket dropped without `close` (a join's future dropped in a
    /// wait) still hangs up, once, and is then shut; one closed first says
    /// nothing more when it is dropped.
    #[tokio::test]
    async fn a_socket_dropped_unclosed_hangs_up() {
        bounded(async {
            for close_first in [false, true] {
                let (listener, endpoint) = listen().await;
                let (dialed, accepted) = tokio::join!(
                    Signaling::dial(&endpoint, DialOptions::default()),
                    accept(&listener)
                );
                let (signaling, notifications) = dialed.unwrap();
                let (_, mut read, _write) = accepted;
                let server = tokio::spawn(async move {
                    let mut frames = Vec::new();
                    while let Some(frame) = read_frame(&mut read).await {
                        frames.push(frame.text().to_owned());
                    }
                    frames
                });
                if close_first {
                    signaling.close().await;
                }
                drop(signaling);
                drop(notifications);
                assert_eq!(
                    server.await.unwrap(),
                    [r#"{"command":"hangup","reason":"HUNGUP","sequence":1}"#],
                    "closed first: {close_first}"
                );
            }
        })
        .await;
    }

    /// A command dropped while it waits gives up its response and no more;
    /// one dropped in the middle of its write shuts the socket down.
    #[tokio::test]
    async fn a_command_dropped_in_its_write_shuts_the_socket() {
        bounded(async {
            let (listener, endpoint) = listen().await;
            let (dialed, accepted) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept(&listener)
            );
            let (signaling, _notifications) = dialed.unwrap();
            // The server never reads: the socket's buffers fill.
            let (_head, _read, _write) = accepted;
            let description = "x".repeat(32 << 10);
            let payload = Json::Object(vec![("description", Json::Str(&description))]);
            let mut written = 0;
            while !signaling.is_closed() {
                assert!(written < 1000, "the socket took 32 MiB unread");
                let dropped = tokio::time::timeout(
                    Duration::from_millis(10),
                    signaling.command("accept-producer", &payload),
                )
                .await;
                assert!(dropped.is_err(), "{dropped:?}");
                written += 1;
            }
            // The first ones were written whole and dropped in their wait.
            assert!(written > 1, "the first command did not fit the socket");
            assert!(signaling.shared.state().waiters.is_empty());
            assert_eq!(
                signaling.command("x", &Json::Null).await,
                Err(SignalingError::Closed("x".into()))
            );
        })
        .await;
    }

    /// Frames as Go decodes them into `notification` (run at the pin,
    /// 2026-11-15): what is an error, and what the fields hold.
    #[test]
    fn frames_decode_as_go_decodes_them() {
        // (frame, decodes, type, sequence)
        let cases: &[(&str, bool, &str, i64)] = &[
            ("null", true, "", 0),
            (r#"{"sequence":"x"}"#, false, "", 0),
            (r#"{"sequence":1.0}"#, false, "", 0),
            (r#"{"sequence":1e2}"#, false, "", 0),
            (
                r#"{"type":null,"sequence":null,"description":null}"#,
                true,
                "",
                0,
            ),
            (r#"{"participantId":true}"#, true, "", 0),
            (r#"{"peerId":5}"#, false, "", 0),
            (r#"{"peerId":{"id":111}}"#, true, "", 0),
            ("[1]", false, "", 0),
            (r#""s""#, false, "", 0),
            (r#"{"conversation":null,"peerId":null}"#, true, "", 0),
            (r#" {"sequence":7} "#, true, "", 7),
            (r#"{"sequence":7} x"#, false, "", 0),
            (r#"{"conversation":{"participants":null}}"#, true, "", 0),
            (r#"{"conversation":{"participants":{}}}"#, false, "", 0),
            (r#"{"stamp":"x"}"#, false, "", 0),
            (r#"{"sequence":9223372036854775808}"#, false, "", 0),
            (r#"{"type":"error","sequence":-1}"#, true, "error", -1),
            (
                r#"{"unknown":{"deep":[1,2,{"x":null}]},"sequence":4}"#,
                true,
                "",
                4,
            ),
        ];
        for (frame, decodes, kind, sequence) in cases {
            match decode(frame) {
                Ok(note) => {
                    assert!(decodes, "{frame} decoded");
                    assert_eq!(
                        (note.kind.as_str(), note.sequence),
                        (*kind, *sequence),
                        "{frame}"
                    );
                }
                Err(error) => assert!(!decodes, "{frame}: {error}"),
            }
        }
        let note = decode(r#"{"peerId":{"id":111},"sessionId":"s","description":"d","topology":"SERVER","response":"r","notification":"n","stamp":5}"#).unwrap();
        assert_eq!(
            note,
            Notification {
                response: "r".into(),
                notification: "n".into(),
                stamp: 5,
                peer_id: Some(PeerId { id: 111 }),
                session_id: "s".into(),
                description: "d".into(),
                topology: "SERVER".into(),
                ..Notification::default()
            }
        );
        // The participants: `null` entries and states, ids of every kind.
        let note = decode(concat!(
            r#"{"conversation":{"topology":"SERVER","participants":[null,{"id":"7","state":null},"#,
            r#"{"id":8,"state":"HUNGUP"},{"id":9,"state":"ACCEPTED"},{"id":"42"},{"id":1.5},{"id":[1]},"#,
            r#"{"id":10,"state":"REJECTED"},{"id":{"a":1}},{"id":false}]}}"#
        ))
        .unwrap();
        assert_eq!(participant_ids(&note, "42"), ["7", "9"]);
        assert_eq!(
            participant_ids(&Notification::default(), "42"),
            Vec::<String>::new()
        );
        assert_eq!(
            decode(r#"{"participantId":"12"}"#).unwrap().participant_id,
            AnyId::Text("12".into())
        );
        assert_eq!(
            decode(r#"{"participantId":12}"#).unwrap().participant_id,
            AnyId::Number(12.0)
        );
        assert_eq!(
            decode(r#"{"participantId":null}"#).unwrap().participant_id,
            AnyId::Absent
        );
        assert_eq!(
            decode(r#"{"participantId":true}"#).unwrap().participant_id,
            AnyId::Other
        );
    }

    /// `decimalID` (Go's answers, run at the pin).
    #[test]
    fn decimal_ids() {
        let ok = |id: AnyId| decimal_id(&id).unwrap();
        let err = |id: AnyId| match decimal_id(&id).unwrap_err() {
            SignalingError::ParticipantId(why) => why,
            other => panic!("{other:?}"),
        };
        assert_eq!(ok(AnyId::Number(42.0)), "42");
        assert_eq!(ok(AnyId::Number(-7.0)), "-7");
        assert_eq!(
            ok(AnyId::Number(9_007_199_254_740_993.0)),
            "9007199254740992"
        );
        assert_eq!(err(AnyId::Number(1.5)), "non-integer");
        assert_eq!(err(AnyId::Number(1e30)), "non-integer");
        assert_eq!(
            err(AnyId::Number(9_223_372_036_854_775_808.0)),
            "non-integer"
        );
        assert_eq!(ok(AnyId::Text("43".into())), "43");
        assert_eq!(ok(AnyId::Text("+5".into())), "+5");
        assert_eq!(ok(AnyId::Text("-5".into())), "-5");
        assert_eq!(ok(AnyId::Text("007".into())), "007");
        assert_eq!(err(AnyId::Text(String::new())), "non-numeric");
        assert_eq!(err(AnyId::Text("4x".into())), "non-numeric");
        assert_eq!(err(AnyId::Text("+".into())), "non-numeric");
        assert_eq!(err(AnyId::Text("+-5".into())), "non-numeric");
        assert_eq!(
            err(AnyId::Text("9223372036854775808".into())),
            "non-numeric"
        );
        assert_eq!(err(AnyId::Other), "unsupported type");
        assert_eq!(err(AnyId::Absent), "unsupported type");
    }

    /// A participant list past the bound keeps its first entries; a frame
    /// whose later entries are malformed is still refused whole.
    #[test]
    fn the_participant_bound() {
        let entries: Vec<String> = (0..PARTICIPANTS_MAX + 50)
            .map(|i| format!(r#"{{"id":{i},"state":"ACCEPTED"}}"#))
            .collect();
        let frame = format!(
            r#"{{"notification":"connection","conversation":{{"participants":[{}]}}}}"#,
            entries.join(",")
        );
        let note = decode(&frame).unwrap();
        let ids = participant_ids(&note, "");
        assert_eq!(ids.len(), PARTICIPANTS_MAX);
        assert_eq!(ids.last().map(String::as_str), Some("255"));
        let bad = frame.replace(
            r#"{"id":300,"state":"ACCEPTED"}"#,
            r#"{"id":300,"state":7}"#,
        );
        assert!(decode(&bad).is_err());
    }

    /// Neither a frame's debug form nor the line for a frame that did not
    /// decode shows what the frame held.
    #[test]
    fn nothing_shows_a_frame() {
        let note = decode(r#"{"type":"notification","notification":"producer-updated","description":"a=ice-pwd:SECRETPWD","sessionId":"SECRETSESSION"}"#).unwrap();
        let shown = format!("{note:?}");
        assert!(
            shown.contains("producer-updated") && shown.contains("description_len: 19"),
            "{shown}"
        );
        assert!(!shown.contains("SECRET"), "{shown}");

        let frame = r#"{"sequence":"SECRETTOKEN"}"#;
        let error = decode(frame).unwrap_err();
        // The error's own text is why the line is not made of it.
        assert!(error.to_string().contains("SECRETTOKEN"));
        let line = invalid_frame_text(frame.len(), &error);
        assert!(
            line.starts_with("vkcalls: invalid signaling frame: 26 bytes: Data error at column "),
            "{line}"
        );
        assert!(!line.contains("SECRET"), "{line}");
        let error = decode("SECRETTOKEN").unwrap_err();
        assert!(!invalid_frame_text(11, &error).contains("SECRET"));

        let payload = accept_producer("a=ssrc:1 cname:x\r\n", "a=ice-pwd:SECRETPWD", "sess");
        let shown = format!("{payload:?}");
        assert!(
            !shown.contains("SECRET") && shown.contains("<19 bytes>"),
            "{shown}"
        );
    }

    #[test]
    fn sizes() {
        // 16 of them wait in the queue at most.
        assert!(
            std::mem::size_of::<Notification>() <= 256,
            "Notification is {} bytes",
            std::mem::size_of::<Notification>()
        );
        assert!(
            std::mem::size_of::<Participant>() <= 56,
            "Participant is {} bytes",
            std::mem::size_of::<Participant>()
        );
        assert!(std::mem::size_of::<Json<'_>>() <= 32);
        assert_eq!(FRAME_MAX, 262_144);
        assert_eq!(READ_LIMIT, 524_288);
        assert_eq!(READ_PEAK, 2 << 20);
    }
}

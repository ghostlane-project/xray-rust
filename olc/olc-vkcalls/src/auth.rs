// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The VK Calls auth provider (`internal/auth/vkcalls`): a guest's way from
//! a join link to the signalling endpoint, with no account.
//!
//! [`issue`] walks the five anonymous steps the Go engine walks: a bootstrap
//! anonymous token, the call's preview (the guest's user id and a secret),
//! the call's own anonymous token, the SDK's anonymous login, and the join
//! by link. Three calls go to the API (`api.vk.me`), two to the SDK's
//! (`calls.okcdn.ru`). The join's answer becomes the [`Credentials`] the
//! engine connects with.
//!
//! Every call is one `POST` of a form on its own connection
//! (`olc_net::retry::fetch`); nothing is kept between calls but the three
//! tokens, the secret and the session key the next call presents, and those
//! are wiped when the chain ends. A reply is bounded by [`REPLY_LIMIT`]
//! before it is read and dropped once decoded; every text taken out of one
//! is bounded before it is copied.
//!
//! What a request says about its sender (the User-Agent, the device ids,
//! the guest's name, the client and SDK versions) is a parameter:
//! [`Client`], [`Request::device_id`], [`Request::sdk_device_id`]. Each
//! default is what the Go client at the pin sends; the User-Agent's is
//! `net/http`'s own name for the protocol the call is spoken in
//! ([`Agent::Go`]), chosen once the connection says which.
//!
//! Nothing here logs. No error carries the room link, a token, the
//! endpoint, a request or a reply's body: a status that is not 200 is told
//! by its number (Go adds 200 bytes of the body), and a link Go's parser
//! refuses is told without the link (Go quotes it).

use std::marker::PhantomData;
use std::time::Duration;

pub use olc_net::agent::{Agent, GO_USER_AGENT_H2, GO_USER_AGENT_HTTP1};
use olc_net::http::{self, HttpError, HttpRequest};
use olc_net::stream::Offer;
use olc_net::{fetch, form, retry, stream};
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use crate::gourl;
use crate::signaling::go_json_string;

/// The API's base (`New`: `APIBase`).
pub const API_BASE: &str = "https://api.vk.me";
/// The SDK API's base (`fbProdBase`).
pub const FB_BASE: &str = "https://calls.okcdn.ru";
/// The time the five steps may take together (`requestWait`).
pub const REQUEST_WAIT: Duration = Duration::from_secs(20);
/// The most of a reply read. Go reads 8 MiB (`requestLimit`) and cuts a
/// longer reply short; the replies of the chain are a few kilobytes, and a
/// longer one is an error of the call here.
pub const REPLY_LIMIT: usize = 256 << 10;
/// The longest token, secret, session key or endpoint taken out of a reply.
/// Not in Go, which takes whatever the reply holds; a longer one refuses the
/// step ([`Error::FieldTooLong`]).
pub const TOKEN_MAX: usize = 4096;
/// The longest client type, device index or user id taken out of a reply
/// (not in Go).
pub const WORD_MAX: usize = 64;
/// The most URLs kept of one ICE server of the join's answer (not in Go).
pub const ICE_URLS_MAX: usize = 16;
/// The longest URL, user name or credential kept of an ICE server (not in
/// Go).
pub const ICE_TEXT_MAX: usize = 512;
/// The longest `ice_servers` text of [`Credentials`]: the STUN and the
/// TURN server, [`ICE_URLS_MAX`] URLs each and the TURN server's user name
/// and credential, every text at [`ICE_TEXT_MAX`] and every byte of it one
/// that JSON writes as six (`\u003c`), and the punctuation.
pub const ICE_JSON_MAX: usize = 6 * (2 * ICE_URLS_MAX + 2) * ICE_TEXT_MAX + 256;
/// How much of the service's own error message an error carries, in bytes.
/// Go carries all of it.
pub const KIND_MAX: usize = 200;
/// What stands in the service's error message where it repeated a value of
/// the request. Not in Go, which prints the message as it came: the error
/// is logged on every failed rejoin and recruit, and a message that quotes
/// a parameter would put the call's link or a token of the chain there.
pub const SCRUBBED: &str = "…";
/// The shortest value taken out of a message, in bytes. The chain's fixed
/// words (`ru`, `JSON`, `false`) are shorter; a link's id, a device id and
/// a token are longer.
pub const SCRUB_MIN: usize = 6;
/// The shortest end of a message that is taken out for being the start of
/// a longer value: a message that ends inside a token shows none of it.
const SCRUB_TAIL_MIN: usize = 4;
/// How much of the service's error message is read before it is cleaned
/// and cut: what the error carries and the longest value the chain holds,
/// so a value the cut would split is still seen whole.
const FAULT_READ: usize = KIND_MAX + TOKEN_MAX;

/// `schemaVersion`: the credentials' `vkcalls_schema`.
pub const SCHEMA_VERSION: &str = "1";
/// `KeySchema`.
pub const KEY_SCHEMA: &str = "vkcalls_schema";
/// `KeyRoomURL`.
pub const KEY_ROOM_URL: &str = "room_url";
/// `KeyICEServers`.
pub const KEY_ICE_SERVERS: &str = "ice_servers";
/// `KeyParticipantID`.
pub const KEY_PARTICIPANT_ID: &str = "participant_id";
/// `KeyPeerIDHint`.
pub const KEY_PEER_ID_HINT: &str = "peer_id_hint";
/// `KeyDeviceIdx`.
pub const KEY_DEVICE_IDX: &str = "device_idx";
/// `KeyClientType`.
pub const KEY_CLIENT_TYPE: &str = "client_type";
/// `KeyP2PForbidden`.
pub const KEY_P2P_FORBIDDEN: &str = "p2p_forbidden";

/// `stageAnonToken`.
pub const STAGE_ANON_TOKEN: &str = "auth.getAnonymToken";
/// `stagePreview`.
pub const STAGE_PREVIEW: &str = "messages.getCallPreview";
/// `stageCallToken`.
pub const STAGE_CALL_TOKEN: &str = "messages.getAnonymCallToken";
/// `stageLogin`.
pub const STAGE_LOGIN: &str = "auth.anonymLogin";
/// `stageJoin`.
pub const STAGE_JOIN: &str = "vchat.joinConversationByLink";

const FORM_TYPE: &str = "application/x-www-form-urlencoded";
/// The profile fields the preview asks for.
const PREVIEW_FIELDS: &str = "first_name,last_name,photo_200";

/// A VK-side answer that is not what the chain needs (`GuestAPIError`):
/// the service's own error, or a reply the step cannot use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestApiError {
    /// The step.
    pub stage: &'static str,
    /// The service's `error_code` (14 captcha, 10 internal, 5 auth); 0 for
    /// an answer the chain itself found wanting.
    pub code: i64,
    /// The service's `error_msg`, cleared of what the chain holds
    /// ([`SCRUBBED`]) and then at most [`KIND_MAX`] bytes of it, or the
    /// chain's own word: `invalid_json`, `invalid_response`,
    /// `missing_token`, `missing_secret`, `invalid_user_id`,
    /// `missing_session_key`, `missing_endpoint_or_token`.
    pub kind: String,
}

impl std::fmt::Display for GuestApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code == 0 {
            write!(f, "vkcalls: {}: {}", self.stage, self.kind)
        } else {
            write!(
                f,
                "vkcalls: {}: api error {} ({})",
                self.stage, self.code, self.kind
            )
        }
    }
}

/// The provider's errors; the texts are Go's as far as they name no link
/// and no reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `ErrRoomURLRequired`.
    #[error("vkcalls: room url required")]
    RoomUrlRequired,
    /// `ErrTokenUnsupported`.
    #[error("vkcalls: account token is not supported for guest issue")]
    TokenUnsupported,
    /// `ErrInvalidEndpoint`.
    #[error("vkcalls: invalid signaling endpoint")]
    InvalidEndpoint,
    /// `ErrEndpointUserInfo`.
    #[error("vkcalls: signaling endpoint must not carry userinfo or port")]
    EndpointUserInfo,
    /// `ErrEndpointToken`.
    #[error("vkcalls: endpoint token mismatch")]
    EndpointToken,
    /// `ErrMissingClientType`.
    #[error("vkcalls: missing client_type")]
    MissingClientType,
    /// `ErrInvalidDeviceIdx`.
    #[error("vkcalls: invalid device_idx")]
    InvalidDeviceIdx,
    /// `ErrInvalidRoomURL`: a link `url.Parse` refuses. Go's text goes on
    /// with the link and the parser's words; the link stays out here.
    #[error("vkcalls: invalid room url")]
    InvalidRoomUrl,
    /// `ErrRoomURLShape`.
    #[error("vkcalls: room url must be https://vk.ru/call/join/<id>")]
    RoomUrlShape,
    /// `ErrRoomURLExtra`.
    #[error("vkcalls: room url must not carry userinfo, port, query or fragment")]
    RoomUrlExtra,
    /// `ErrICEServers`. In Go only a JSON encoder's failure, which cannot
    /// happen; here an ICE server of more URLs than [`ICE_URLS_MAX`] or a
    /// text past [`ICE_TEXT_MAX`].
    #[error("vkcalls: ice servers")]
    IceServers,
    /// `GuestAPIError`.
    #[error("{0}")]
    Api(GuestApiError),
    /// A status that is not 200. Go's text goes on with 200 bytes of the
    /// body; the body stays out here.
    #[error("vkcalls: http {status}")]
    Http {
        /// The step.
        stage: &'static str,
        /// The status.
        status: u16,
    },
    /// A call that got no reply (Go: `vkcalls: do: …`): the reason, without
    /// the URL.
    #[error("vkcalls: do: {cause}")]
    Transport {
        /// The step.
        stage: &'static str,
        /// What failed.
        cause: String,
    },
    /// Not in Go: a text of the step's reply is longer than its bound
    /// ([`TOKEN_MAX`], [`WORD_MAX`]).
    #[error("vkcalls: {0}: a field of the reply is past its bound")]
    FieldTooLong(&'static str),
}

impl Error {
    fn api(stage: &'static str, kind: &str) -> Self {
        Error::Api(GuestApiError {
            stage,
            code: 0,
            kind: kind.to_owned(),
        })
    }
}

/// What the five calls say about their sender. The default is what Go at
/// the pin sends; nothing else is added (no `Origin`, no `Accept`, no
/// client hints, and no `Accept-Encoding`, which Go's client adds:
/// `olc_net` reads no coded body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client<'a> {
    /// The `User-Agent`. Go's code names none on the five calls, so
    /// `net/http` names itself, by the protocol ([`Agent::Go`]).
    pub user_agent: Agent<'a>,
    /// `client_id` of the bootstrap token.
    pub client_id: &'a str,
    /// `v` of the three API calls (`apiVersion`).
    pub api_version: &'a str,
    /// `lang` of the three API calls.
    pub lang: &'a str,
    /// `application_key` of the two SDK calls (`sdkAppKey`).
    pub application_key: &'a str,
    /// `client_version` inside the login's `session_data`
    /// (`sdkClientVer`).
    pub sdk_client_version: &'a str,
    /// `version` inside the login's `session_data`.
    pub sdk_version: u32,
    /// What the API calls' `device_id` starts with; 32 hex digits follow,
    /// new on every [`issue`] and one for its three calls.
    pub device_prefix: &'a str,
    /// What the `device_id` inside `session_data` starts with; 32 hex
    /// digits follow, new on every [`issue`].
    pub sdk_device_prefix: &'a str,
    /// What a guest with no name is called; 8 hex digits follow, new on
    /// every [`issue`].
    pub guest_prefix: &'a str,
}

impl Default for Client<'_> {
    fn default() -> Self {
        Self {
            user_agent: Agent::Go,
            client_id: "8093730",
            api_version: "5.276",
            lang: "ru",
            application_key: "CGMMEJLGDIHBABABA",
            sdk_client_version: "1.0.1",
            sdk_version: 2,
            device_prefix: "olcrtc-",
            sdk_device_prefix: "olcrtc-sdk-",
            guest_prefix: "guest-",
        }
    }
}

/// What [`issue`] is asked (`auth.Config` and the provider's two bases).
#[derive(Clone, Copy, Default)]
pub struct Request<'a> {
    /// The call's join link (`RoomURL`).
    pub room_url: &'a str,
    /// The guest's name (`Name`); empty takes [`Client::guest_prefix`] and
    /// 8 hex digits.
    pub name: &'a str,
    /// An account token (`Token`): a guest has none, and one that is given
    /// refuses the issue.
    pub token: &'a str,
    /// The API's base; empty is [`API_BASE`]. Only tests set it.
    pub api_base: &'a str,
    /// The SDK API's base; empty is [`FB_BASE`]. Only tests set it.
    pub fb_base: &'a str,
    /// What the calls say about their sender.
    pub client: Client<'a>,
    /// The whole `device_id` of the three API calls; none makes one as Go
    /// does.
    pub device_id: Option<&'a str>,
    /// The whole `device_id` inside `session_data`; none makes one as Go
    /// does.
    pub sdk_device_id: Option<&'a str>,
}

impl std::fmt::Debug for Request<'_> {
    /// The link is the room's whole secret and the device ids name the
    /// guest: none of them is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("named", &!self.name.is_empty())
            .field("api_base", &self.api_base)
            .field("fb_base", &self.fb_base)
            .finish_non_exhaustive()
    }
}

/// What the engine joins with (`auth.Credentials` under the provider's v1
/// contract). The secrets of the chain (the anonymous tokens, the preview's
/// secret, the session key, the device ids) are not in it.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The signalling endpoint (`URL`). It carries the join token.
    pub url: String,
    /// The join token (`Token`).
    pub token: String,
    /// `Extra["room_url"]`: the join link as the chain used it.
    pub room_url: String,
    /// `Extra["ice_servers"]`: the service's STUN and TURN servers as the
    /// JSON text Go writes (keys in byte order; `<`, `>` and `&` escaped).
    /// It carries the TURN credential.
    pub ice_servers: String,
    /// `Extra["participant_id"]`: the guest's user id (step 2).
    pub participant_id: String,
    /// `Extra["peer_id_hint"]`: the endpoint's `peerId`, when it has one.
    pub peer_id_hint: Option<String>,
    /// `Extra["device_idx"]`; empty when the answer had none.
    pub device_idx: String,
    /// `Extra["client_type"]`.
    pub client_type: String,
    /// `Extra["p2p_forbidden"]`: true unless the answer says false.
    pub p2p_forbidden: bool,
}

impl Credentials {
    /// Go's `Extra`: the fields by their keys, in the keys' byte order.
    #[must_use]
    pub fn extra(&self) -> Vec<(&'static str, &str)> {
        let mut out = vec![
            (KEY_CLIENT_TYPE, self.client_type.as_str()),
            (KEY_DEVICE_IDX, self.device_idx.as_str()),
            (KEY_ICE_SERVERS, self.ice_servers.as_str()),
            (
                KEY_P2P_FORBIDDEN,
                if self.p2p_forbidden { "true" } else { "false" },
            ),
            (KEY_PARTICIPANT_ID, self.participant_id.as_str()),
        ];
        if let Some(hint) = &self.peer_id_hint {
            out.push((KEY_PEER_ID_HINT, hint.as_str()));
        }
        out.push((KEY_ROOM_URL, self.room_url.as_str()));
        out.push((KEY_SCHEMA, SCHEMA_VERSION));
        out
    }
}

impl std::fmt::Debug for Credentials {
    /// The endpoint and the token are the join, the ICE servers hold the
    /// TURN credential, the link is the room and the ids name the guest.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("client_type", &self.client_type)
            .field("p2p_forbidden", &self.p2p_forbidden)
            .finish_non_exhaustive()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.url.zeroize();
        self.token.zeroize();
        self.room_url.zeroize();
        self.ice_servers.zeroize();
        self.participant_id.zeroize();
        if let Some(hint) = &mut self.peer_id_hint {
            hint.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// The link.

/// A join link as the chain uses it (`canonicalLink`).
#[derive(Clone, PartialEq, Eq)]
pub struct Link {
    text: String,
    /// Where the call's id starts in `text`.
    id: usize,
}

impl Link {
    /// The link: `https://<vk.ru or vk.com>/call/join/<id>`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The call's id, what the join step is given (`linkID`).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.text[self.id..]
    }
}

impl std::fmt::Debug for Link {
    /// The link is the room's whole secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

/// `canonicalLink`: the join link in the one form the chain sends: scheme
/// `https`, host `vk.ru` or `vk.com` exactly, the path `/call/join/<id>`
/// once the slashes around it are dropped, and no user, port, query or
/// fragment. The id comes back with its escapes undone.
///
/// One difference from Go: an id whose escapes decode to bytes that are not
/// UTF-8 is refused as a link of another shape (Go sends the bytes).
///
/// # Errors
/// [`Error::InvalidRoomUrl`] for a link `url.Parse` refuses, then
/// [`Error::RoomUrlShape`] and [`Error::RoomUrlExtra`] in Go's order.
pub fn canonical_link(raw: &str) -> Result<Link, Error> {
    let url = gourl::parse(raw.trim()).ok_or(Error::InvalidRoomUrl)?;
    let host = match url.host.as_slice() {
        b"vk.ru" => "vk.ru",
        b"vk.com" => "vk.com",
        _ => return Err(Error::RoomUrlShape),
    };
    if url.scheme != "https" {
        return Err(Error::RoomUrlShape);
    }
    // A port is part of the host, so it was refused above.
    if url.user || !url.raw_query.is_empty() || !url.fragment.is_empty() {
        return Err(Error::RoomUrlExtra);
    }
    let path = url.path.as_slice();
    let first = path.iter().position(|&b| b != b'/').unwrap_or(path.len());
    let last = path
        .iter()
        .rposition(|&b| b != b'/')
        .map_or(first, |i| i + 1);
    let mut parts = path[first..last].split(|&b| b == b'/');
    let (call, join, id) = (parts.next(), parts.next(), parts.next());
    if parts.next().is_some() || call != Some(b"call") || join != Some(b"join") {
        return Err(Error::RoomUrlShape);
    }
    let id = id
        .filter(|id| !id.is_empty())
        .and_then(|id| std::str::from_utf8(id).ok())
        .ok_or(Error::RoomUrlShape)?;
    let head = format!("https://{host}/call/join/");
    let at = head.len();
    Ok(Link {
        text: head + id,
        id: at,
    })
}

// ---------------------------------------------------------------------------
// Replies, read as `encoding/json` reads them into the provider's structs.

/// A JSON object read into a struct as Go reads one: a field is found by
/// its name whatever the case of its letters, a field named twice keeps the
/// last value, an unknown field is passed over, and `null` leaves a field
/// (or the whole struct) as it was. A value of another type than its field
/// refuses the reply.
///
/// Two differences from Go, neither seen on the wire: a nested object named
/// twice is replaced where Go merges the two, and names are folded as ASCII
/// (Go also folds the Kelvin sign into `k`).
trait Reply<'de>: Default {
    /// Reads the value of `key` when the struct has such a field; false
    /// leaves the value unread.
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error>;

    /// Whether a text was longer than its bound.
    fn over(&self) -> bool {
        false
    }
}

struct Object<T>(T);

impl<'de, T: Reply<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields<T>(PhantomData<T>);
        impl<'de, T: Reply<'de>> Visitor<'de> for Fields<T> {
            type Value = Object<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_unit<E>(self) -> Result<Object<T>, E> {
                Ok(Object(T::default()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Object<T>, A::Error> {
                let mut out = T::default();
                while let Some(key) = map.next_key::<String>()? {
                    if !out.field(&key, &mut map)? {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(Object(out))
            }
        }
        deserializer.deserialize_any(Fields(PhantomData))
    }
}

fn named(key: &str, field: &str) -> bool {
    key.eq_ignore_ascii_case(field)
}

/// A string field: a string of at most the seed's bytes, or `null`.
struct TextSeed(usize);

enum Text {
    Null,
    Value(String),
    TooLong,
}

impl<'de> DeserializeSeed<'de> for TextSeed {
    type Value = Text;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Text, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl Visitor<'_> for TextSeed {
    type Value = Text;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string")
    }
    fn visit_unit<E>(self) -> Result<Text, E> {
        Ok(Text::Null)
    }
    fn visit_str<E>(self, s: &str) -> Result<Text, E> {
        // Before the copy.
        Ok(if s.len() > self.0 {
            Text::TooLong
        } else {
            Text::Value(s.to_owned())
        })
    }
}

/// Reads a string field into `into`; a longer one than `max` sets `over`
/// and is not copied.
fn text<'de, A: MapAccess<'de>>(
    map: &mut A,
    max: usize,
    into: &mut String,
    over: &mut bool,
) -> Result<(), A::Error> {
    match map.next_value_seed(TextSeed(max))? {
        Text::Null => {}
        Text::Value(value) => {
            into.zeroize();
            *into = value;
        }
        Text::TooLong => *over = true,
    }
    Ok(())
}

/// A string field the chain decodes and never reads: held to its type,
/// not copied.
struct Unread;

impl<'de> Deserialize<'de> for Unread {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Check;
        impl Visitor<'_> for Check {
            type Value = Unread;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_unit<E>(self) -> Result<Unread, E> {
                Ok(Unread)
            }
            fn visit_str<E>(self, _: &str) -> Result<Unread, E> {
                Ok(Unread)
            }
        }
        deserializer.deserialize_any(Check)
    }
}

/// An integer field (Go's `int`, `int64`): a number written as an integer
/// that fits 64 bits, or `null`.
struct Int(Option<i64>);

impl<'de> Deserialize<'de> for Int {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Whole;
        impl Visitor<'_> for Whole {
            type Value = Int;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an integer")
            }
            fn visit_unit<E>(self) -> Result<Int, E> {
                Ok(Int(None))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Int, E> {
                Ok(Int(Some(n)))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Int, E> {
                i64::try_from(n)
                    .map(|n| Int(Some(n)))
                    .map_err(|_| E::custom("an integer past 64 bits"))
            }
            fn visit_f64<E: serde::de::Error>(self, n: f64) -> Result<Int, E> {
                // `-0` is an integer to Go; the parser here hands it over
                // as a float. Any other float is no integer.
                if n == 0.0 && n.is_sign_negative() {
                    Ok(Int(Some(0)))
                } else {
                    Err(E::custom("a number that is no integer"))
                }
            }
        }
        deserializer.deserialize_any(Whole)
    }
}

/// `json.Number` as the preview's `user_id` is read: a number, or a string
/// that spells one.
#[derive(Default)]
enum UserId {
    /// Absent or `null`.
    #[default]
    Absent,
    /// An integer as written: digits behind an optional minus.
    Whole(String),
    /// A number that is no integer (Go: `invalid_user_id`), or one this
    /// parser cannot give back as written: past 64 bits.
    Other,
    /// Longer than [`WORD_MAX`].
    TooLong,
}

/// `isValidNumber`: whether `s` is a JSON number.
fn is_json_number(s: &str) -> bool {
    let digits = |s: &[u8]| s.iter().take_while(|b| b.is_ascii_digit()).count();
    let mut s = s.as_bytes();
    if let [b'-', rest @ ..] = s {
        s = rest;
    }
    match s {
        [b'0', rest @ ..] => s = rest,
        [b'1'..=b'9', ..] => s = &s[digits(s)..],
        _ => return false,
    }
    if let [b'.', rest @ ..] = s {
        let n = digits(rest);
        if n == 0 {
            return false;
        }
        s = &rest[n..];
    }
    if let [b'e' | b'E', rest @ ..] = s {
        let rest = match rest {
            [b'+' | b'-', rest @ ..] => rest,
            rest => rest,
        };
        let n = digits(rest);
        if n == 0 {
            return false;
        }
        s = &rest[n..];
    }
    s.is_empty()
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Number;
        impl Visitor<'_> for Number {
            type Value = UserId;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a number")
            }
            fn visit_unit<E>(self) -> Result<UserId, E> {
                Ok(UserId::Absent)
            }
            fn visit_i64<E>(self, n: i64) -> Result<UserId, E> {
                Ok(UserId::Whole(n.to_string()))
            }
            fn visit_u64<E>(self, n: u64) -> Result<UserId, E> {
                Ok(UserId::Whole(n.to_string()))
            }
            fn visit_f64<E>(self, _: f64) -> Result<UserId, E> {
                Ok(UserId::Other)
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<UserId, E> {
                if s.len() > WORD_MAX {
                    return Ok(UserId::TooLong);
                }
                if !is_json_number(s) {
                    return Err(E::custom("a string that is no number"));
                }
                Ok(if s.bytes().all(|b| b == b'-' || b.is_ascii_digit()) {
                    UserId::Whole(s.to_owned())
                } else {
                    UserId::Other
                })
            }
        }
        deserializer.deserialize_any(Number)
    }
}

/// The join's `device_idx` (Go's `any`, read by `decimalOf`).
#[derive(Default)]
enum DeviceIdx {
    /// Absent or `null`: the credentials' field stays empty.
    #[default]
    Absent,
    /// A number of digits alone, or a string of digits alone (an empty one
    /// too), as written.
    Digits(String),
    /// Anything else, and digits past [`WORD_MAX`].
    Invalid,
}

impl<'de> Deserialize<'de> for DeviceIdx {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = DeviceIdx;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any value")
            }
            fn visit_unit<E>(self) -> Result<DeviceIdx, E> {
                Ok(DeviceIdx::Absent)
            }
            fn visit_bool<E>(self, _: bool) -> Result<DeviceIdx, E> {
                Ok(DeviceIdx::Invalid)
            }
            fn visit_i64<E>(self, _: i64) -> Result<DeviceIdx, E> {
                // Only a negative number comes here.
                Ok(DeviceIdx::Invalid)
            }
            fn visit_u64<E>(self, n: u64) -> Result<DeviceIdx, E> {
                Ok(DeviceIdx::Digits(n.to_string()))
            }
            fn visit_f64<E>(self, _: f64) -> Result<DeviceIdx, E> {
                Ok(DeviceIdx::Invalid)
            }
            fn visit_str<E>(self, s: &str) -> Result<DeviceIdx, E> {
                Ok(
                    if s.len() <= WORD_MAX && s.bytes().all(|b| b.is_ascii_digit()) {
                        DeviceIdx::Digits(s.to_owned())
                    } else {
                        DeviceIdx::Invalid
                    },
                )
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<DeviceIdx, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(DeviceIdx::Invalid)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<DeviceIdx, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(DeviceIdx::Invalid)
            }
        }
        deserializer.deserialize_any(Any)
    }
}

/// A value that is kept when it is a string (Go's `v.(string)`): a string
/// of at most [`ICE_TEXT_MAX`] bytes, a longer one as [`Word::TooLong`],
/// and anything else as none.
enum Word {
    None,
    Value(String),
    TooLong,
}

impl<'de> Deserialize<'de> for Word {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = Word;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any value")
            }
            fn visit_unit<E>(self) -> Result<Word, E> {
                Ok(Word::None)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Word, E> {
                Ok(Word::None)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Word, E> {
                Ok(Word::None)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Word, E> {
                Ok(Word::None)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Word, E> {
                Ok(Word::None)
            }
            fn visit_str<E>(self, s: &str) -> Result<Word, E> {
                Ok(if s.len() > ICE_TEXT_MAX {
                    Word::TooLong
                } else {
                    Word::Value(s.to_owned())
                })
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Word, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Word::None)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Word, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Word::None)
            }
        }
        deserializer.deserialize_any(Any)
    }
}

/// `urlsOf`: the `urls` of an ICE server: one string as it is (an empty one
/// too), or the strings of a list that are not empty.
#[derive(Default)]
struct Urls {
    list: Vec<String>,
    /// More URLs than [`ICE_URLS_MAX`], or one past [`ICE_TEXT_MAX`].
    over: bool,
}

impl<'de> Deserialize<'de> for Urls {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = Urls;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any value")
            }
            fn visit_unit<E>(self) -> Result<Urls, E> {
                Ok(Urls::default())
            }
            fn visit_bool<E>(self, _: bool) -> Result<Urls, E> {
                Ok(Urls::default())
            }
            fn visit_i64<E>(self, _: i64) -> Result<Urls, E> {
                Ok(Urls::default())
            }
            fn visit_u64<E>(self, _: u64) -> Result<Urls, E> {
                Ok(Urls::default())
            }
            fn visit_f64<E>(self, _: f64) -> Result<Urls, E> {
                Ok(Urls::default())
            }
            fn visit_str<E>(self, s: &str) -> Result<Urls, E> {
                Ok(if s.len() > ICE_TEXT_MAX {
                    Urls {
                        list: Vec::new(),
                        over: true,
                    }
                } else {
                    Urls {
                        list: vec![s.to_owned()],
                        over: false,
                    }
                })
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Urls, A::Error> {
                let mut out = Urls::default();
                while let Some(entry) = seq.next_element::<Word>()? {
                    match entry {
                        Word::None => {}
                        Word::Value(url) if url.is_empty() => {}
                        Word::Value(url) if out.list.len() < ICE_URLS_MAX => out.list.push(url),
                        Word::Value(_) | Word::TooLong => out.over = true,
                    }
                }
                Ok(out)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Urls, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Urls::default())
            }
        }
        deserializer.deserialize_any(Any)
    }
}

/// An ICE server of the join's answer (Go's `any`, read by `urlsOf` and
/// `credsOf`): an object's `urls`, `username` and `credential`, the names
/// matched as written and the last of a repeated name kept. Anything that
/// is no object is no server.
#[derive(Default)]
struct Server {
    urls: Vec<String>,
    username: String,
    credential: String,
    over: bool,
}

impl<'de> Deserialize<'de> for Server {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = Server;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any value")
            }
            fn visit_unit<E>(self) -> Result<Server, E> {
                Ok(Server::default())
            }
            fn visit_bool<E>(self, _: bool) -> Result<Server, E> {
                Ok(Server::default())
            }
            fn visit_i64<E>(self, _: i64) -> Result<Server, E> {
                Ok(Server::default())
            }
            fn visit_u64<E>(self, _: u64) -> Result<Server, E> {
                Ok(Server::default())
            }
            fn visit_f64<E>(self, _: f64) -> Result<Server, E> {
                Ok(Server::default())
            }
            fn visit_str<E>(self, _: &str) -> Result<Server, E> {
                Ok(Server::default())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Server, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Server::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Server, A::Error> {
                let mut out = Server::default();
                // What each name's last value said of the bound.
                let (mut urls_over, mut name_over, mut credential_over) = (false, false, false);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "urls" => {
                            let urls = map.next_value::<Urls>()?;
                            out.urls = urls.list;
                            urls_over = urls.over;
                        }
                        "username" | "credential" => {
                            let (into, over) = if key == "username" {
                                (&mut out.username, &mut name_over)
                            } else {
                                (&mut out.credential, &mut credential_over)
                            };
                            into.zeroize();
                            into.clear();
                            *over = false;
                            match map.next_value::<Word>()? {
                                Word::None => {}
                                Word::Value(value) => *into = value,
                                Word::TooLong => *over = true,
                            }
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                out.over = urls_over || name_over || credential_over;
                Ok(out)
            }
        }
        deserializer.deserialize_any(Any)
    }
}

/// The service's own error (`envelope.Error`).
#[derive(Default)]
struct ApiFault {
    code: i64,
    msg: String,
}

impl<'de> Reply<'de> for ApiFault {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if named(key, "error_code") {
            if let Int(Some(code)) = map.next_value()? {
                self.code = code;
            }
        } else if named(key, "error_msg") {
            // The message is cut, not refused: its length says nothing of
            // the reply. Here only to what the cleaning needs to see
            // ([`Held::clean`] cuts it to what the error carries).
            if let Text::Value(mut msg) = map.next_value_seed(TextSeed(REPLY_LIMIT))? {
                let mut cut = msg.len().min(FAULT_READ);
                while !msg.is_char_boundary(cut) {
                    cut -= 1;
                }
                msg.truncate(cut);
                self.msg.zeroize();
                self.msg = msg;
            }
        } else {
            return Ok(false);
        }
        Ok(true)
    }
}

/// What every reply is read as first (`decodeAPI`'s `envelope`).
#[derive(Default)]
struct Envelope {
    error: Option<ApiFault>,
}

impl<'de> Reply<'de> for Envelope {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if !named(key, "error") {
            return Ok(false);
        }
        // A pointer: `null` takes an earlier error away.
        self.error = map
            .next_value::<Option<Object<ApiFault>>>()?
            .map(|fault| fault.0);
        Ok(true)
    }
}

/// `{"response": …}` of the three API calls.
#[derive(Default)]
struct Response<T>(T);

impl<'de, T: Reply<'de>> Reply<'de> for Response<T> {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if !named(key, "response") {
            return Ok(false);
        }
        if let Some(inner) = map.next_value::<Option<Object<T>>>()? {
            self.0 = inner.0;
        }
        Ok(true)
    }

    fn over(&self) -> bool {
        self.0.over()
    }
}

/// Step 1's `response`.
#[derive(Default)]
struct Bootstrap {
    token: String,
    over: bool,
}

impl<'de> Reply<'de> for Bootstrap {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if named(key, "token") {
            text(map, TOKEN_MAX, &mut self.token, &mut self.over)?;
        } else if named(key, "expired_at") {
            // Decoded by Go and never read: held to its type.
            map.next_value::<Int>()?;
        } else if named(key, "is_verified") {
            map.next_value::<Option<bool>>()?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn over(&self) -> bool {
        self.over
    }
}

/// Step 2's `response`.
#[derive(Default)]
struct Preview {
    user_id: UserId,
    secret: String,
    over: bool,
}

impl<'de> Reply<'de> for Preview {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if named(key, "user_id") {
            // `null` leaves an earlier id as it was.
            match map.next_value::<UserId>()? {
                UserId::Absent => {}
                id => self.user_id = id,
            }
        } else if named(key, "secret") {
            text(map, TOKEN_MAX, &mut self.secret, &mut self.over)?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn over(&self) -> bool {
        self.over || matches!(self.user_id, UserId::TooLong)
    }
}

/// Step 3's `response`.
#[derive(Default)]
struct Issued {
    token: String,
    over: bool,
}

impl<'de> Reply<'de> for Issued {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if !named(key, "token") {
            return Ok(false);
        }
        text(map, TOKEN_MAX, &mut self.token, &mut self.over)?;
        Ok(true)
    }

    fn over(&self) -> bool {
        self.over
    }
}

/// Step 4's reply (`sdkSession`).
#[derive(Default)]
struct Session {
    session_key: String,
    over: bool,
}

impl<'de> Reply<'de> for Session {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if !named(key, "session_key") {
            return Ok(false);
        }
        text(map, TOKEN_MAX, &mut self.session_key, &mut self.over)?;
        Ok(true)
    }

    fn over(&self) -> bool {
        self.over
    }
}

/// Step 5's reply.
#[derive(Default)]
struct Join {
    endpoint: String,
    token: String,
    device_idx: DeviceIdx,
    client_type: String,
    p2p_forbidden: Option<bool>,
    stun: Server,
    turn: Server,
    over: bool,
}

impl<'de> Reply<'de> for Join {
    fn field<A: MapAccess<'de>>(&mut self, key: &str, map: &mut A) -> Result<bool, A::Error> {
        if named(key, "endpoint") {
            text(map, TOKEN_MAX, &mut self.endpoint, &mut self.over)?;
        } else if named(key, "token") {
            text(map, TOKEN_MAX, &mut self.token, &mut self.over)?;
        } else if named(key, "wt_endpoint") || named(key, "id") {
            // Decoded by Go and never read: held to their type.
            map.next_value::<Unread>()?;
        } else if named(key, "device_idx") {
            self.device_idx = map.next_value()?;
        } else if named(key, "client_type") {
            text(map, WORD_MAX, &mut self.client_type, &mut self.over)?;
        } else if named(key, "p2p_forbidden") {
            // A pointer: `null` is "not said".
            self.p2p_forbidden = map.next_value()?;
        } else if named(key, "stun_server") {
            self.stun = map.next_value()?;
        } else if named(key, "turn_server") {
            self.turn = map.next_value()?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn over(&self) -> bool {
        self.over
    }
}

impl Drop for Join {
    fn drop(&mut self) {
        self.endpoint.zeroize();
        self.token.zeroize();
        self.turn.credential.zeroize();
    }
}

/// `decodeAPI`: a reply that is no JSON object is `invalid_json`, one that
/// carries the service's `error` is that error, and one whose fields are
/// not of their types is `invalid_response`.
///
/// The service's own message is cleared of `held` before it is cut.
fn decode<'de, T: Reply<'de>>(
    body: &'de [u8],
    stage: &'static str,
    held: &Held,
) -> Result<T, Error> {
    let envelope = serde_json::from_slice::<Object<Envelope>>(body)
        .map_err(|_| Error::api(stage, "invalid_json"))?
        .0;
    if let Some(mut fault) = envelope.error {
        let kind = held.clean(&fault.msg);
        fault.msg.zeroize();
        return Err(Error::Api(GuestApiError {
            stage,
            code: fault.code,
            kind,
        }));
    }
    let reply = serde_json::from_slice::<Object<T>>(body)
        .map_err(|_| Error::api(stage, "invalid_response"))?
        .0;
    if reply.over() {
        return Err(Error::FieldTooLong(stage));
    }
    Ok(reply)
}

// ---------------------------------------------------------------------------
// The credentials.

/// `iceServersJSON`: the STUN server when it has URLs, then the TURN server
/// with its URLs and, when it names a user, the user name and the
/// credential; as Go's `json.Marshal` writes a list of maps.
fn ice_servers_json(stun: &Server, turn: &Server) -> Result<String, Error> {
    if stun.over || turn.over {
        return Err(Error::IceServers);
    }
    let urls = |out: &mut String, urls: &[String]| {
        out.push_str("\"urls\":[");
        for (i, url) in urls.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&go_json_string(url));
        }
        out.push(']');
    };
    let mut out = String::from("[");
    if !stun.urls.is_empty() {
        out.push('{');
        urls(&mut out, &stun.urls);
        out.push('}');
    }
    if !turn.urls.is_empty() || !turn.username.is_empty() {
        if out.len() > 1 {
            out.push(',');
        }
        out.push('{');
        // Go writes a map's keys in byte order: credential, urls, username.
        if !turn.username.is_empty() {
            out.push_str("\"credential\":");
            out.push_str(&go_json_string(&turn.credential));
        }
        if !turn.urls.is_empty() {
            if !turn.username.is_empty() {
                out.push(',');
            }
            urls(&mut out, &turn.urls);
        }
        if !turn.username.is_empty() {
            out.push_str(",\"username\":");
            out.push_str(&go_json_string(&turn.username));
        }
        out.push('}');
    }
    out.push(']');
    Ok(out)
}

/// `credentialsFromJoin`: the v1 checks of a join's answer, in Go's order.
fn credentials_from_join(link: &Link, user_id: &str, join: &Join) -> Result<Credentials, Error> {
    if join.endpoint.is_empty() || join.token.is_empty() {
        return Err(Error::api(STAGE_JOIN, "missing_endpoint_or_token"));
    }
    let url = gourl::parse(&join.endpoint)
        .filter(|url| url.scheme == "wss" && url.host.ends_with(b".okcdn.ru"))
        .ok_or(Error::InvalidEndpoint)?;
    // A port is part of the host, so it was refused above.
    if url.user {
        return Err(Error::EndpointUserInfo);
    }
    let own_token = gourl::query_get(url.raw_query, "token");
    if !own_token.is_empty() && own_token != join.token.as_bytes() {
        return Err(Error::EndpointToken);
    }
    if join.client_type.is_empty() {
        return Err(Error::MissingClientType);
    }
    let device_idx = match &join.device_idx {
        DeviceIdx::Absent => String::new(),
        DeviceIdx::Digits(digits) => digits.clone(),
        DeviceIdx::Invalid => return Err(Error::InvalidDeviceIdx),
    };
    let ice_servers = ice_servers_json(&join.stun, &join.turn)?;
    let hint = gourl::query_get(url.raw_query, "peerId");
    Ok(Credentials {
        url: join.endpoint.clone(),
        token: join.token.clone(),
        room_url: link.as_str().to_owned(),
        ice_servers,
        participant_id: user_id.to_owned(),
        // An escape may decode to anything; the hint is told, never used.
        peer_id_hint: (!hint.is_empty()).then(|| String::from_utf8_lossy(&hint).into_owned()),
        device_idx,
        client_type: join.client_type.clone(),
        // Absent forbids DIRECT.
        p2p_forbidden: join.p2p_forbidden.unwrap_or(true),
    })
}

// ---------------------------------------------------------------------------
// What the service's words are cleared of.

/// The values of one run of the chain that the service's own error message
/// must not carry into an error or a log: the link's id, the device ids,
/// the guest's name and id, and the tokens, the secret and the session key
/// of the steps so far, each as it is and as a form spells it. Each is a
/// copy, wiped when this goes.
#[derive(Default)]
struct Held {
    /// Longest first: where two start at one place the longer one goes.
    values: Vec<Zeroizing<String>>,
}

impl Held {
    /// Holds `value` too, unless it is shorter than [`SCRUB_MIN`].
    fn add(&mut self, value: &str) {
        // As the form spells it too: a message that quotes the request's
        // body quotes that.
        let escaped = Zeroizing::new(form::query_escape(value));
        for spelling in [value, escaped.as_str()] {
            if spelling.len() < SCRUB_MIN || self.values.iter().any(|v| v.as_str() == spelling) {
                continue;
            }
            let at = self
                .values
                .iter()
                .position(|v| v.len() < spelling.len())
                .unwrap_or(self.values.len());
            self.values.insert(at, Zeroizing::new(spelling.to_owned()));
        }
    }

    /// `msg` with every held value replaced by [`SCRUBBED`], then cut to
    /// [`KIND_MAX`] bytes on a character. A message that ends inside a held
    /// value (the service's own cut, or [`FAULT_READ`]'s) loses that end
    /// too, from [`SCRUB_TAIL_MIN`] bytes of it.
    fn clean(&self, msg: &str) -> String {
        let mut out = String::with_capacity(msg.len().min(KIND_MAX + 4));
        let mut rest = msg;
        while out.len() < KIND_MAX {
            let Some(c) = rest.chars().next() else { break };
            if let Some(value) = self.values.iter().find(|v| rest.starts_with(v.as_str())) {
                out.push_str(SCRUBBED);
                rest = &rest[value.len()..];
                continue;
            }
            let ends_inside = rest.len() >= SCRUB_TAIL_MIN
                && self
                    .values
                    .iter()
                    .any(|v| v.len() > rest.len() && v.starts_with(rest));
            if ends_inside {
                out.push_str(SCRUBBED);
                break;
            }
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
        let mut cut = out.len().min(KIND_MAX);
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out
    }
}

// ---------------------------------------------------------------------------
// The chain.

/// `randomToken`'s spelling: the bytes in lower-case hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The calls of one [`issue`]: where they go, what they say of their
/// sender and when the chain's time is up.
struct Chain<'a> {
    api_base: &'a str,
    fb_base: &'a str,
    client: &'a Client<'a>,
    deadline: Instant,
}

impl Chain<'_> {
    /// `raw`: one form posted, the reply's body when its status is 200.
    async fn post(
        &self,
        stage: &'static str,
        url: &str,
        form: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let transport = |cause: String| Error::Transport { stage, cause };
        // The parse error would quote the URL.
        let target = stream::parse_url(url)
            .map_err(|_| transport("the service's URL does not parse".to_owned()))?;
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(transport("timed out".to_owned()));
        }
        // `olc_net::retry::fetch` taken apart, for the one thing it cannot
        // be told: what to send once the protocol is known. Only the TCP
        // dial is tried again (D4); the request is written at most once,
        // and the whole call ends within what is left of the chain's time.
        let exchange = async {
            let dialed = retry::dial_for(&target, Offer::Fetch).await?;
            // Go's order on the wire: the User-Agent, then the form's type.
            let mut headers: Vec<(&str, &str)> = Vec::with_capacity(2);
            let agent = self.client.user_agent.on(dialed.h2);
            if !agent.is_empty() {
                headers.push(("User-Agent", agent));
            }
            headers.push(("Content-Type", FORM_TYPE));
            let req = HttpRequest {
                method: "POST",
                host: &target.authority,
                path: &target.path,
                headers: &headers,
                body: form.as_bytes(),
                max_body: REPLY_LIMIT,
                timeout: left,
            };
            if dialed.h2 {
                fetch::request_h2(dialed.stream, &req).await
            } else {
                let mut stream = dialed.stream;
                http::request(&mut stream, &req).await
            }
        };
        let mut resp = tokio::time::timeout(left, exchange)
            .await
            .unwrap_or(Err(HttpError::Timeout))
            .map_err(|e| transport(e.to_string()))?;
        let body = Zeroizing::new(std::mem::take(&mut resp.body));
        if resp.status != 200 {
            return Err(Error::Http {
                stage,
                status: resp.status,
            });
        }
        Ok(body)
    }

    /// `vkCall`: an API method with the API's version added.
    async fn vk_call(
        &self,
        method: &'static str,
        fields: &[(&str, &str)],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut pairs = fields.to_vec();
        pairs.push(("v", self.client.api_version));
        let form = Zeroizing::new(form::encode(&pairs));
        let url = format!("{}/method/{method}", self.api_base);
        self.post(method, &url, &form).await
    }

    /// `fbCall`: an SDK method with what every SDK call carries.
    async fn fb_call(
        &self,
        method: &'static str,
        fields: &[(&str, &str)],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut pairs = fields.to_vec();
        pairs.push(("method", method));
        pairs.push(("format", "JSON"));
        pairs.push(("application_key", self.client.application_key));
        let form = Zeroizing::new(form::encode(&pairs));
        let url = format!("{}/fb.do", self.fb_base);
        self.post(method, &url, &form).await
    }
}

/// `Provider.Issue`: runs the guest chain for `req.room_url`.
///
/// # Errors
/// Before any request: [`Error::RoomUrlRequired`], [`Error::TokenUnsupported`]
/// and the link's ([`canonical_link`]). Then the first step that fails, by
/// its name; the join's answer is held to the checks of the credentials.
pub async fn issue(req: &Request<'_>) -> Result<Credentials, Error> {
    issue_within(req, REQUEST_WAIT).await
}

/// [`issue`] with the chain's time given.
pub(crate) async fn issue_within(req: &Request<'_>, wait: Duration) -> Result<Credentials, Error> {
    if req.room_url.is_empty() {
        return Err(Error::RoomUrlRequired);
    }
    if !req.token.is_empty() {
        return Err(Error::TokenUnsupported);
    }
    let link = canonical_link(req.room_url)?;
    let client = &req.client;
    let chain = Chain {
        api_base: if req.api_base.is_empty() {
            API_BASE
        } else {
            req.api_base
        },
        fb_base: if req.fb_base.is_empty() {
            FB_BASE
        } else {
            req.fb_base
        },
        client,
        deadline: Instant::now() + wait,
    };
    let device_id = req.device_id.map_or_else(
        || {
            format!(
                "{}{}",
                client.device_prefix,
                hex(&rand::random::<[u8; 16]>())
            )
        },
        str::to_owned,
    );
    let name = if req.name.is_empty() {
        format!("{}{}", client.guest_prefix, hex(&rand::random::<[u8; 4]>()))
    } else {
        req.name.to_owned()
    };
    // What the service's own words about a refused step are cleared of.
    let mut held = Held::default();
    held.add(link.id());
    held.add(&device_id);
    held.add(&name);

    // Step 1: the bootstrap anonymous token.
    let body = chain
        .vk_call(
            STAGE_ANON_TOKEN,
            &[
                ("client_id", client.client_id),
                ("link", link.as_str()),
                ("device_id", device_id.as_str()),
                ("anonymName", name.as_str()),
                ("lang", client.lang),
            ],
        )
        .await?;
    let bootstrap = Zeroizing::new(
        decode::<Response<Bootstrap>>(&body, STAGE_ANON_TOKEN, &held)?
            .0
            .token,
    );
    drop(body);
    if bootstrap.is_empty() {
        return Err(Error::api(STAGE_ANON_TOKEN, "missing_token"));
    }
    held.add(&bootstrap);

    // Step 2: the call's preview: the guest's user id and a secret.
    let body = chain
        .vk_call(
            STAGE_PREVIEW,
            &[
                ("anonymous_token", bootstrap.as_str()),
                ("device_id", device_id.as_str()),
                ("link", link.as_str()),
                ("lang", client.lang),
                ("extended", "1"),
                ("fields", PREVIEW_FIELDS),
            ],
        )
        .await?;
    let mut preview = decode::<Response<Preview>>(&body, STAGE_PREVIEW, &held)?.0;
    drop(body);
    let secret = Zeroizing::new(std::mem::take(&mut preview.secret));
    if secret.is_empty() {
        return Err(Error::api(STAGE_PREVIEW, "missing_secret"));
    }
    let UserId::Whole(user_id) = preview.user_id else {
        return Err(Error::api(STAGE_PREVIEW, "invalid_user_id"));
    };
    held.add(&secret);
    held.add(&user_id);

    // Step 3: the call's own anonymous token.
    let body = chain
        .vk_call(
            STAGE_CALL_TOKEN,
            &[
                ("anonymous_token", bootstrap.as_str()),
                ("device_id", device_id.as_str()),
                ("link", link.as_str()),
                ("lang", client.lang),
                ("name", name.as_str()),
                ("user_id", user_id.as_str()),
                ("secret", secret.as_str()),
            ],
        )
        .await?;
    let call_token = Zeroizing::new(
        decode::<Response<Issued>>(&body, STAGE_CALL_TOKEN, &held)?
            .0
            .token,
    );
    drop(body);
    if call_token.is_empty() {
        return Err(Error::api(STAGE_CALL_TOKEN, "missing_token"));
    }
    held.add(&call_token);

    // Step 4: the SDK's anonymous login.
    let sdk_device_id = req.sdk_device_id.map_or_else(
        || {
            format!(
                "{}{}",
                client.sdk_device_prefix,
                hex(&rand::random::<[u8; 16]>())
            )
        },
        str::to_owned,
    );
    held.add(&sdk_device_id);
    // Go's `json.Marshal` of a map: the keys in byte order.
    let session_data = format!(
        "{{\"client_version\":{},\"device_id\":{},\"version\":{}}}",
        go_json_string(client.sdk_client_version),
        go_json_string(&sdk_device_id),
        client.sdk_version
    );
    let body = chain
        .fb_call(STAGE_LOGIN, &[("session_data", session_data.as_str())])
        .await?;
    let session_key = Zeroizing::new(decode::<Session>(&body, STAGE_LOGIN, &held)?.session_key);
    drop(body);
    if session_key.is_empty() {
        return Err(Error::api(STAGE_LOGIN, "missing_session_key"));
    }
    held.add(&session_key);

    // Step 5: the join by link.
    let body = chain
        .fb_call(
            STAGE_JOIN,
            &[
                ("joinLink", link.id()),
                ("isVideo", "false"),
                ("protocolVersion", "5"),
                ("anonymToken", call_token.as_str()),
                ("session_key", session_key.as_str()),
            ],
        )
        .await?;
    let join = decode::<Join>(&body, STAGE_JOIN, &held)?;
    drop(body);
    credentials_from_join(&link, &user_id, &join)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::testing::{bounded, Proto, Reply as Answer, Seen, Stub};

    pub(crate) const TEST_ROOM: &str = "https://vk.ru/call/join/0FakeCallLinkForVectors012";
    pub(crate) const ENDPOINT: &str = "wss://videowebrtc.okcdn.ru/ws2?conversationId=c&peerId=10020030040&token=join-token&userId=100200300400&entityType=USER";

    /// `defaultAPIAnswer` and `defaultFBAnswer` of the provider's tests.
    pub(crate) fn default_answer(method: &str) -> String {
        match method {
            STAGE_ANON_TOKEN => {
                r#"{"response":{"token":"anon-token","expired_at":1790619997}}"#.to_owned()
            }
            STAGE_PREVIEW => r#"{"response":{"user_id":100200300400,"secret":"s3cret"}}"#.to_owned(),
            STAGE_CALL_TOKEN => r#"{"response":{"token":"sdk-anon-token"}}"#.to_owned(),
            STAGE_LOGIN => {
                r#"{"session_key":"sk","session_secret_key":"ssk","api_server":"https://calls.okcdn.ru"}"#
                    .to_owned()
            }
            STAGE_JOIN => join_answer(&[]),
            _ => r#"{"error":{"error_code":10,"error_msg":"internal"}}"#.to_owned(),
        }
    }

    /// The test's join answer with the fields of `set` replaced; a `None`
    /// takes the field out. The values are JSON as written.
    pub(crate) fn join_answer(set: &[(&str, Option<&str>)]) -> String {
        let endpoint = format!("\"{ENDPOINT}\"");
        let mut fields: Vec<(&str, &str)> = vec![
            ("endpoint", &endpoint),
            ("wt_endpoint", r#""wss://videowebrtc.okcdn.ru/wt""#),
            ("token", r#""join-token""#),
            ("id", r#""call-id""#),
            ("device_idx", "7"),
            ("client_type", r#""VK""#),
            ("p2p_forbidden", "false"),
            ("stun_server", r#"{"urls":"stun:stun.example:3478"}"#),
            (
                "turn_server",
                r#"{"urls":["turn:91.231.135.155:19302","turn:91.231.135.179:19302"],"username":"u","credential":"c"}"#,
            ),
        ];
        for (name, value) in set {
            fields.retain(|(field, _)| field != name);
            if let Some(value) = value {
                fields.push((name, value));
            }
        }
        let body: Vec<String> = fields
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect();
        format!("{{{}}}", body.join(","))
    }

    /// The two servers of the chain (`fakeVK`): the methods asked, in
    /// order, and for a method named in `replies` that status and body in
    /// place of the test's own answer.
    pub(crate) struct FakeVk {
        pub(crate) api: Stub,
        pub(crate) fb: Stub,
        steps: Arc<Mutex<Vec<String>>>,
        replies: Arc<Mutex<HashMap<String, (u16, String)>>>,
    }

    /// The value of `name` in a form body, as written.
    pub(crate) fn form_value<'a>(body: &'a [u8], name: &str) -> Option<&'a str> {
        std::str::from_utf8(body).ok()?.split('&').find_map(|pair| {
            pair.split_once('=')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value)
        })
    }

    impl FakeVk {
        pub(crate) async fn start() -> Self {
            Self::start_as(Proto::Plain).await
        }

        /// The two servers reached in `proto`.
        pub(crate) async fn start_as(proto: Proto) -> Self {
            let steps = Arc::new(Mutex::new(Vec::new()));
            let replies: Arc<Mutex<HashMap<String, (u16, String)>>> = Arc::default();
            let answer = |steps: &Arc<Mutex<Vec<String>>>,
                          replies: &Arc<Mutex<HashMap<String, (u16, String)>>>,
                          method: &str| {
                steps.lock().unwrap().push(method.to_owned());
                let (status, body) = replies
                    .lock()
                    .unwrap()
                    .get(method)
                    .cloned()
                    .unwrap_or_else(|| (200, default_answer(method)));
                Answer::new(status, body).header("Content-Type", "application/json")
            };
            let api = Stub::start_as(proto, {
                let (steps, replies) = (steps.clone(), replies.clone());
                move |seen: &Seen| {
                    let method = seen.target.strip_prefix("/method/").unwrap_or(&seen.target);
                    answer(&steps, &replies, method)
                }
            })
            .await;
            let fb = Stub::start_as(proto, {
                let (steps, replies) = (steps.clone(), replies.clone());
                move |seen: &Seen| {
                    let method = form_value(&seen.body, "method").unwrap_or("");
                    answer(&steps, &replies, method)
                }
            })
            .await;
            Self {
                api,
                fb,
                steps,
                replies,
            }
        }

        /// Answers `method` with `status` and `body` from now on.
        pub(crate) fn reply(&self, method: &str, status: u16, body: &str) {
            self.replies
                .lock()
                .unwrap()
                .insert(method.to_owned(), (status, body.to_owned()));
        }

        /// Back to the test's own answers.
        pub(crate) fn reset(&self) {
            self.replies.lock().unwrap().clear();
        }

        /// The methods asked so far, taken.
        pub(crate) fn taken(&self) -> Vec<String> {
            std::mem::take(&mut *self.steps.lock().unwrap())
        }

        pub(crate) fn request<'a>(&'a self, room_url: &'a str, name: &'a str) -> Request<'a> {
            Request {
                room_url,
                name,
                api_base: &self.api.base,
                fb_base: &self.fb.base,
                ..Request::default()
            }
        }

        pub(crate) async fn issue(&self, room_url: &str, name: &str) -> Result<Credentials, Error> {
            bounded(issue(&self.request(room_url, name))).await
        }
    }

    const CHAIN: [&str; 5] = [
        STAGE_ANON_TOKEN,
        STAGE_PREVIEW,
        STAGE_CALL_TOKEN,
        STAGE_LOGIN,
        STAGE_JOIN,
    ];

    // TestIssueHappyPath.
    #[tokio::test]
    async fn issue_happy_path() {
        let vk = FakeVk::start().await;
        let creds = vk.issue(TEST_ROOM, "Test").await.unwrap();
        assert_eq!(vk.taken(), CHAIN, "chain order");
        assert_eq!(creds.url, ENDPOINT);
        assert_eq!(creds.token, "join-token");
        let extra: HashMap<&str, &str> = creds.extra().into_iter().collect();
        for (key, want) in [
            (KEY_SCHEMA, "1"),
            (KEY_ROOM_URL, TEST_ROOM),
            (KEY_PARTICIPANT_ID, "100200300400"),
            (KEY_PEER_ID_HINT, "10020030040"),
            (KEY_DEVICE_IDX, "7"),
            (KEY_CLIENT_TYPE, "VK"),
            (KEY_P2P_FORBIDDEN, "false"),
        ] {
            assert_eq!(extra.get(key).copied(), Some(want), "{key}");
        }
        assert_eq!(extra.len(), 8);
        let ice: serde_json::Value = serde_json::from_str(extra[KEY_ICE_SERVERS]).unwrap();
        let ice = ice.as_array().unwrap();
        assert_eq!(ice.len(), 2, "ice servers");
        let urls = ice[1]["urls"].as_array().unwrap();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "turn:91.231.135.155:19302");
        assert_eq!(ice[1]["username"], "u");
        assert_eq!(ice[1]["credential"], "c");
        // Bootstrap secrets must not leak into the credentials.
        for (_, value) in creds.extra() {
            for secret in ["anon-token", "s3cret", "ssk"] {
                assert!(!value.contains(secret), "a bootstrap secret in Extra");
            }
        }
        for field in [&creds.url, &creds.token] {
            for secret in ["anon-token", "s3cret", "ssk"] {
                assert!(!field.contains(secret));
            }
        }
    }

    // TestIssueValidations.
    #[tokio::test]
    async fn issue_validations() {
        let vk = FakeVk::start().await;
        assert_eq!(vk.issue("", "").await, Err(Error::RoomUrlRequired));
        let with_token = Request {
            token: "acc",
            ..vk.request(TEST_ROOM, "")
        };
        assert_eq!(
            bounded(issue(&with_token)).await,
            Err(Error::TokenUnsupported)
        );
        for bad in [
            "https://evil.example/call/join/x",
            "https://vk.ru/call/join/x/extra",
            "https://user@vk.ru/call/join/x",
            "https://vk.ru:8443/call/join/x",
            "https://vk.ru/call/join/x?token=1",
            "https://vk.ru/other/path",
        ] {
            let got = vk.issue(bad, "").await;
            assert!(
                matches!(got, Err(Error::RoomUrlShape | Error::RoomUrlExtra)),
                "bad room url accepted: {bad}"
            );
        }
        // Nothing was asked of the service for any of them.
        assert_eq!(vk.taken(), [""; 0]);
        // Endpoint token mismatch.
        vk.reply(
            STAGE_JOIN,
            200,
            &join_answer(&[("token", Some(r#""different-token""#))]),
        );
        assert_eq!(vk.issue(TEST_ROOM, "").await, Err(Error::EndpointToken));
        // p2p_forbidden absent -> conservative true.
        vk.reply(STAGE_JOIN, 200, &join_answer(&[("p2p_forbidden", None)]));
        let creds = vk.issue(TEST_ROOM, "").await.unwrap();
        assert!(creds.p2p_forbidden, "absent p2p_forbidden");
        assert!(creds.extra().contains(&(KEY_P2P_FORBIDDEN, "true")));
    }

    // TestIssueAPIErrors.
    #[tokio::test]
    async fn issue_api_errors() {
        let vk = FakeVk::start().await;
        vk.reply(
            STAGE_PREVIEW,
            200,
            r#"{"error":{"error_code":14,"error_msg":"Captcha needed"}}"#,
        );
        let got = vk.issue(TEST_ROOM, "").await;
        let Err(Error::Api(api)) = &got else {
            panic!("captcha error: {got:?}");
        };
        assert_eq!((api.stage, api.code), (STAGE_PREVIEW, 14));
        assert_eq!(
            got.unwrap_err().to_string(),
            "vkcalls: messages.getCallPreview: api error 14 (Captcha needed)"
        );
        assert_eq!(vk.taken(), CHAIN[..2]);
        // Every method answers a JSON string.
        vk.reset();
        for method in CHAIN {
            vk.reply(method, 200, r#""<html>""#);
        }
        assert_eq!(
            vk.issue(TEST_ROOM, "").await,
            Err(Error::api(STAGE_ANON_TOKEN, "invalid_json"))
        );
    }

    /// The values the chain makes up are Go's forms, new on every issue,
    /// and a caller's own are sent as given.
    #[tokio::test]
    async fn the_made_up_values_are_gos_forms_and_parameters() {
        let hex = |s: &str, n: usize| {
            s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        let vk = FakeVk::start().await;
        let mut devices = Vec::new();
        for _ in 0..2 {
            vk.issue(TEST_ROOM, "").await.unwrap();
        }
        let api = vk.api.seen();
        assert_eq!(api.len(), 6);
        for seen in &api {
            assert_eq!(seen.header("User-Agent"), Some("Go-http-client/1.1"));
            let device = form_value(&seen.body, "device_id").unwrap();
            assert!(
                device
                    .strip_prefix("olcrtc-")
                    .is_some_and(|rest| hex(rest, 32)),
                "the device id's form"
            );
            devices.push(device.to_owned());
            assert_eq!(form_value(&seen.body, "v"), Some("5.276"));
            assert_eq!(form_value(&seen.body, "lang"), Some("ru"));
        }
        // One for the three calls of an issue, another for the next issue.
        assert!(devices[0] == devices[1] && devices[1] == devices[2]);
        assert!(devices[3] == devices[4] && devices[4] == devices[5]);
        assert_ne!(devices[0], devices[3]);
        let guest = form_value(&api[0].body, "anonymName").unwrap();
        assert!(guest
            .strip_prefix("guest-")
            .is_some_and(|rest| hex(rest, 8)));
        assert_eq!(form_value(&api[2].body, "name"), Some(guest));
        assert_ne!(form_value(&api[3].body, "anonymName"), Some(guest));
        assert_eq!(form_value(&api[0].body, "client_id"), Some("8093730"));
        let fb = vk.fb.seen();
        assert_eq!(fb.len(), 4);
        let session = form_value(&fb[0].body, "session_data").unwrap();
        let (head, rest) = session
            .split_once("olcrtc-sdk-")
            .expect("the SDK device id's form");
        assert_eq!(
            head,
            "%7B%22client_version%22%3A%221.0.1%22%2C%22device_id%22%3A%22"
        );
        assert!(hex(&rest[..32], 32));
        assert_eq!(&rest[32..], "%22%2C%22version%22%3A2%7D");
        assert_ne!(form_value(&fb[2].body, "session_data"), Some(session));
        assert_eq!(
            form_value(&fb[1].body, "application_key"),
            Some("CGMMEJLGDIHBABABA")
        );

        // A caller's own values.
        let vk = FakeVk::start().await;
        let req = Request {
            client: Client {
                user_agent: Agent::Named(""),
                client_id: "1",
                api_version: "9.9",
                lang: "en",
                application_key: "KEY",
                sdk_client_version: "2.\"0",
                sdk_version: 3,
                ..Client::default()
            },
            device_id: Some("device one"),
            sdk_device_id: Some("sdk<two>"),
            ..vk.request(TEST_ROOM, "Name")
        };
        bounded(issue(&req)).await.unwrap();
        let api = vk.api.seen();
        for seen in &api {
            assert_eq!(seen.header("User-Agent"), None);
            assert_eq!(form_value(&seen.body, "device_id"), Some("device+one"));
            assert_eq!(form_value(&seen.body, "v"), Some("9.9"));
            assert_eq!(form_value(&seen.body, "lang"), Some("en"));
        }
        assert_eq!(form_value(&api[0].body, "client_id"), Some("1"));
        let fb = vk.fb.seen();
        // {"client_version":"2.\"0","device_id":"sdk<two>","version":3}
        assert_eq!(
            form_value(&fb[0].body, "session_data"),
            Some(
                "%7B%22client_version%22%3A%222.%5C%220%22%2C%22device_id%22%3A%22sdk%5Cu003ctwo%5Cu003e%22%2C%22version%22%3A3%7D"
            )
        );
        assert_eq!(form_value(&fb[1].body, "application_key"), Some("KEY"));
    }

    /// Fidelity S1 of the wave-2 review. Go's code names no sender on the
    /// five calls, so `net/http` names itself, and by the protocol the call
    /// is spoken in: its client asks for HTTP/2 (`ForceAttemptHTTP2`,
    /// `protect.go:98`) and says `Go-http-client/2.0` where the server
    /// picks it (`api.vk.me` and `calls.okcdn.ru` do), `/1.1` on HTTP/1.1.
    /// The other pairings no Go client sends. A caller's own words go out
    /// as given in either protocol.
    #[tokio::test]
    async fn go_names_itself_by_the_protocol_the_chain_is_spoken_in() {
        for (proto, want) in [
            (Proto::Plain, "Go-http-client/1.1"),
            (Proto::TlsHttp1, "Go-http-client/1.1"),
            (Proto::TlsH2, "Go-http-client/2.0"),
        ] {
            let vk = FakeVk::start_as(proto).await;
            let issued = vk.issue(TEST_ROOM, "Name").await;
            assert!(issued.is_ok(), "{proto:?}: {issued:?}");
            assert_eq!(vk.taken(), CHAIN, "{proto:?}");
            let (api, fb) = (vk.api.seen(), vk.fb.seen());
            assert_eq!((api.len(), fb.len()), (3, 2), "{proto:?}");
            for seen in api.iter().chain(&fb) {
                assert_eq!(seen.header("User-Agent"), Some(want), "{proto:?}");
                // The calls are the same calls in either protocol.
                assert_eq!(seen.method, "POST", "{proto:?}");
                assert_eq!(seen.header("Content-Type"), Some(FORM_TYPE), "{proto:?}");
            }
            assert_eq!(api[0].target, format!("/method/{STAGE_ANON_TOKEN}"));
            assert_eq!(form_value(&api[0].body, "client_id"), Some("8093730"));
            assert_eq!(fb[1].target, "/fb.do");
            assert_eq!(
                form_value(&fb[1].body, "joinLink"),
                Some("0FakeCallLinkForVectors012"),
                "{proto:?}"
            );

            for (named, want) in [("agent/1", Some("agent/1")), ("", None)] {
                let vk = FakeVk::start_as(proto).await;
                let req = Request {
                    client: Client {
                        user_agent: Agent::Named(named),
                        ..Client::default()
                    },
                    ..vk.request(TEST_ROOM, "Name")
                };
                bounded(issue(&req)).await.unwrap();
                for seen in vk.api.seen().iter().chain(&vk.fb.seen()) {
                    assert_eq!(seen.header("User-Agent"), want, "{proto:?}");
                }
            }
        }
        assert_eq!(Client::default().user_agent, Agent::Go);
    }

    /// Memory and secrets 3 of the wave-2 review: the service's own error
    /// message goes into an error that is logged on every failed rejoin
    /// and recruit. A message that repeats what the request carried (the
    /// call's link, a device id, a token of the chain so far, the guest's
    /// id) is cleared of it before the cut, so a value the cut would split
    /// is gone whole and so is the start of one the message ends in.
    #[tokio::test]
    async fn the_services_words_are_cleared_of_what_the_chain_holds() {
        let vk = FakeVk::start().await;
        let issue_with = |sdk: Option<&'static str>| {
            let vk = &vk;
            async move {
                let req = Request {
                    device_id: Some("device-0123456789"),
                    sdk_device_id: sdk,
                    ..vk.request(TEST_ROOM, "Guest Name")
                };
                bounded(issue(&req)).await
            }
        };
        let fault = |msg: &str| format!(r#"{{"error":{{"error_code":100,"error_msg":"{msg}"}}}}"#);
        let told = |stage: &'static str, kind: &str| -> Result<Credentials, Error> {
            Err(Error::Api(GuestApiError {
                stage,
                code: 100,
                kind: kind.to_owned(),
            }))
        };

        // The third step repeats its whole form: the link (its id, also as
        // a form spells the name), the device id, the bootstrap token, the
        // guest's id and the preview's secret.
        vk.reply(
            STAGE_CALL_TOKEN,
            200,
            &fault(
                "One of the parameters specified was missing or invalid: \
                 link=https://vk.ru/call/join/0FakeCallLinkForVectors012 \
                 device_id=device-0123456789 anonymous_token=anon-token \
                 name=Guest+Name user_id=100200300400 secret=s3cret v=5.276",
            ),
        );
        assert_eq!(
            issue_with(None).await,
            told(
                STAGE_CALL_TOKEN,
                "One of the parameters specified was missing or invalid: \
                 link=https://vk.ru/call/join/… device_id=… anonymous_token=… \
                 name=… user_id=… secret=… v=5.276"
            )
        );

        // The join's refusal, with what the fourth and fifth steps hold: the
        // SDK's device id, the call's token and the link's id. Nothing that
        // is not held is touched, and a value shorter than six bytes (the
        // test's two-letter session key) is not looked for.
        vk.reset();
        vk.reply(
            STAGE_JOIN,
            200,
            &fault(
                "joinLink 0FakeCallLinkForVectors012 anonymToken sdk-anon-token \
                 device sdk-device-0123 session sk: not found",
            ),
        );
        assert_eq!(
            issue_with(Some("sdk-device-0123")).await,
            told(
                STAGE_JOIN,
                "joinLink … anonymToken … device … session sk: not found"
            )
        );

        // The cut is after the cleaning: a token the 200 bytes would split
        // leaves no part of itself.
        let lead = "x".repeat(KIND_MAX - 4);
        vk.reply(
            STAGE_JOIN,
            200,
            &fault(&format!("{lead} sdk-anon-token tail")),
        );
        assert_eq!(
            issue_with(None).await,
            told(STAGE_JOIN, &format!("{lead} …"))
        );
        // A message that itself ends inside a token shows none of it; three
        // bytes of one are nobody's.
        vk.reply(STAGE_JOIN, 200, &fault("no such token: sdk-anon"));
        assert_eq!(issue_with(None).await, told(STAGE_JOIN, "no such token: …"));
        vk.reply(STAGE_JOIN, 200, &fault("no such token: sdk"));
        assert_eq!(
            issue_with(None).await,
            told(STAGE_JOIN, "no such token: sdk")
        );
        // A step is cleared of what the chain holds by then, no more: the
        // first step holds no token yet.
        vk.reset();
        vk.reply(
            STAGE_ANON_TOKEN,
            200,
            &fault("anon-token for 0FakeCallLinkForVectors012"),
        );
        assert_eq!(
            issue_with(None).await,
            told(STAGE_ANON_TOKEN, "anon-token for …")
        );
        const { assert!(SCRUB_MIN == 6 && SCRUB_TAIL_MIN == 4) };
        assert_eq!(FAULT_READ, KIND_MAX + TOKEN_MAX);
    }

    /// Not Go's: what a reply may hold is bounded before it is kept.
    #[tokio::test]
    async fn a_reply_past_its_bounds_refuses_the_step() {
        let vk = FakeVk::start().await;
        let long = |n: usize| "x".repeat(n);
        // A reply longer than the limit is the call's error, at the limit
        // it is read.
        let pad = |len: usize| {
            let head = r#"{"response":{"token":"t"},"pad":""#;
            format!("{head}{}\"}}", long(len - head.len() - 2))
        };
        vk.reply(STAGE_ANON_TOKEN, 200, &pad(REPLY_LIMIT + 1));
        assert_eq!(
            vk.issue(TEST_ROOM, "").await,
            Err(Error::Transport {
                stage: STAGE_ANON_TOKEN,
                cause: "response body too large".to_owned()
            })
        );
        vk.reply(STAGE_ANON_TOKEN, 200, &pad(REPLY_LIMIT));
        vk.issue(TEST_ROOM, "").await.unwrap();
        vk.taken();

        // A token at its bound is taken, one byte more refuses the step.
        let token = |n: usize| format!(r#"{{"response":{{"token":"{}"}}}}"#, long(n));
        vk.reply(STAGE_ANON_TOKEN, 200, &token(TOKEN_MAX));
        vk.issue(TEST_ROOM, "").await.unwrap();
        assert_eq!(vk.taken(), CHAIN);
        vk.reply(STAGE_ANON_TOKEN, 200, &token(TOKEN_MAX + 1));
        assert_eq!(
            vk.issue(TEST_ROOM, "").await,
            Err(Error::FieldTooLong(STAGE_ANON_TOKEN))
        );
        assert_eq!(vk.taken(), CHAIN[..1]);
        vk.reset();

        // The other secrets and the join's texts.
        let cases: [(&str, String); 6] = [
            (
                STAGE_PREVIEW,
                format!(
                    r#"{{"response":{{"user_id":1,"secret":"{}"}}}}"#,
                    long(TOKEN_MAX + 1)
                ),
            ),
            (
                STAGE_PREVIEW,
                format!(
                    r#"{{"response":{{"user_id":"{}","secret":"s"}}}}"#,
                    "1".repeat(WORD_MAX + 1)
                ),
            ),
            (STAGE_CALL_TOKEN, token(TOKEN_MAX + 1)),
            (
                STAGE_LOGIN,
                format!(r#"{{"session_key":"{}"}}"#, long(TOKEN_MAX + 1)),
            ),
            (
                STAGE_JOIN,
                join_answer(&[("token", Some(&format!("\"{}\"", long(TOKEN_MAX + 1))))]),
            ),
            (
                STAGE_JOIN,
                join_answer(&[("client_type", Some(&format!("\"{}\"", long(WORD_MAX + 1))))]),
            ),
        ];
        for (stage, body) in cases {
            vk.reply(stage, 200, &body);
            assert_eq!(
                vk.issue(TEST_ROOM, "").await,
                Err(Error::FieldTooLong(stage)),
                "{stage}"
            );
            vk.reset();
        }
        // A user id at the bound is taken as written.
        vk.reply(
            STAGE_PREVIEW,
            200,
            &format!(
                r#"{{"response":{{"user_id":"{}","secret":"s"}}}}"#,
                "1".repeat(WORD_MAX)
            ),
        );
        assert_eq!(
            vk.issue(TEST_ROOM, "").await.unwrap().participant_id,
            "1".repeat(WORD_MAX)
        );

        // The ICE servers: 16 URLs of 512 bytes are kept, a 17th or a
        // longer one refuses the join, as does a long credential.
        vk.reset();
        let url = long(ICE_TEXT_MAX);
        let urls = |count: usize, url: &str| {
            let list: Vec<String> = (0..count).map(|_| format!("\"{url}\"")).collect();
            format!(
                r#"{{"urls":[{}],"username":"u","credential":"c"}}"#,
                list.join(",")
            )
        };
        vk.reply(
            STAGE_JOIN,
            200,
            &join_answer(&[("turn_server", Some(&urls(ICE_URLS_MAX, &url)))]),
        );
        let creds = vk.issue(TEST_ROOM, "").await.unwrap();
        assert_eq!(creds.ice_servers.matches(&url).count(), ICE_URLS_MAX);
        for server in [
            urls(ICE_URLS_MAX + 1, &url),
            urls(1, &long(ICE_TEXT_MAX + 1)),
            format!(
                r#"{{"urls":"turn:t","username":"u","credential":"{}"}}"#,
                long(ICE_TEXT_MAX + 1)
            ),
            format!(r#"{{"urls":"{}"}}"#, long(ICE_TEXT_MAX + 1)),
        ] {
            vk.reply(
                STAGE_JOIN,
                200,
                &join_answer(&[("turn_server", Some(&server))]),
            );
            assert_eq!(vk.issue(TEST_ROOM, "").await, Err(Error::IceServers));
        }
        // The service's own message is cut at 200 bytes, on a letter.
        vk.reply(
            STAGE_JOIN,
            200,
            &format!(
                r#"{{"error":{{"error_code":7,"error_msg":"{}é tail"}}}}"#,
                long(KIND_MAX - 1)
            ),
        );
        assert_eq!(
            vk.issue(TEST_ROOM, "").await,
            Err(Error::Api(GuestApiError {
                stage: STAGE_JOIN,
                code: 7,
                kind: long(KIND_MAX - 1)
            }))
        );
    }

    /// The chain has one time for its five steps.
    #[tokio::test]
    async fn the_chain_ends_when_its_time_is_up() {
        // A server that takes the request and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let held = tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                open.push(stream);
            }
        });
        let req = Request {
            room_url: TEST_ROOM,
            api_base: &base,
            fb_base: &base,
            ..Request::default()
        };
        let began = std::time::Instant::now();
        let got = bounded(issue_within(&req, Duration::from_millis(300))).await;
        assert_eq!(
            got,
            Err(Error::Transport {
                stage: STAGE_ANON_TOKEN,
                cause: "timed out".to_owned()
            })
        );
        assert!(began.elapsed() >= Duration::from_millis(300));
        // With no time at all nothing is dialed.
        assert_eq!(
            bounded(issue_within(&req, Duration::ZERO)).await,
            Err(Error::Transport {
                stage: STAGE_ANON_TOKEN,
                cause: "timed out".to_owned()
            })
        );
        held.abort();
        assert_eq!(REQUEST_WAIT, Duration::from_secs(20));
    }

    /// No link, token, endpoint or reply in an error or in `Debug`.
    #[tokio::test]
    async fn nothing_secret_is_told() {
        let vk = FakeVk::start().await;
        let secrets = [
            "0FakeCallLinkForVectors012",
            "join-token",
            "anon-token",
            "s3cret",
            "videowebrtc",
            "10020030040",
            "100200300400",
            "SECRETBODY",
            "127.0.0.1",
        ];
        let clean = |text: &str| {
            for secret in secrets {
                assert!(!text.contains(secret), "{secret} in {text:?}");
            }
        };
        let creds = vk.issue(TEST_ROOM, "Test").await.unwrap();
        clean(&format!("{creds:?}"));
        let req = Request {
            device_id: Some("SECRETBODY"),
            ..vk.request(TEST_ROOM, "SECRETBODY")
        };
        let shown = format!("{req:?}");
        assert!(!shown.contains("0FakeCallLinkForVectors012") && !shown.contains("SECRETBODY"));
        clean(&format!("{:?}", canonical_link(TEST_ROOM).unwrap()));

        let mut errors = vec![
            canonical_link("https://vk.ru/call/join/0FakeCallLinkForVectors012%zz").unwrap_err(),
            canonical_link("https://vk.ru/call/0FakeCallLinkForVectors012").unwrap_err(),
            canonical_link("https://vk.ru/call/join/0FakeCallLinkForVectors012?x").unwrap_err(),
        ];
        for (stage, status, body) in [
            (STAGE_ANON_TOKEN, 500, "SECRETBODY anon-token"),
            (STAGE_PREVIEW, 200, "SECRETBODY not json"),
            (
                STAGE_CALL_TOKEN,
                200,
                r#"{"response":{"token":5,"x":"SECRETBODY"}}"#,
            ),
            (STAGE_LOGIN, 200, r#"{"session_secret_key":"SECRETBODY"}"#),
            (
                STAGE_JOIN,
                200,
                r#"{"endpoint":"wss://videowebrtc.example/?token=join-token","token":"join-token"}"#,
            ),
        ] {
            vk.reset();
            vk.reply(stage, status, body);
            errors.push(vk.issue(TEST_ROOM, "Test").await.unwrap_err());
        }
        // A service that is not there: the dial's error names no address.
        let port = crate::testing::closed_port().await;
        let gone = format!("http://127.0.0.1:{port}");
        let req = Request {
            api_base: &gone,
            ..vk.request(TEST_ROOM, "")
        };
        let refused = bounded(issue(&req)).await.unwrap_err();
        assert!(matches!(
            refused,
            Error::Transport {
                stage: STAGE_ANON_TOKEN,
                ..
            }
        ));
        errors.push(refused);
        let req = Request {
            api_base: "https://user:join-token@127.0.0.1/",
            ..vk.request(TEST_ROOM, "")
        };
        errors.push(bounded(issue(&req)).await.unwrap_err());
        assert_eq!(errors.len(), 10);
        for error in &errors {
            clean(&error.to_string());
            clean(&format!("{error:?}"));
        }
    }

    /// The longest `ice_servers` text the chain can issue is the bound the
    /// session's kept credentials are counted with.
    #[test]
    fn the_ice_servers_text_has_a_bound() {
        let worst = "<".repeat(ICE_TEXT_MAX);
        let server = |named: bool| Server {
            urls: vec![worst.clone(); ICE_URLS_MAX],
            username: if named { worst.clone() } else { String::new() },
            credential: if named { worst.clone() } else { String::new() },
            over: false,
        };
        let text = ice_servers_json(&server(false), &server(true)).unwrap();
        assert!(text.len() <= ICE_JSON_MAX, "{}", text.len());
        assert!(text.len() > ICE_JSON_MAX - 256, "{}", text.len());
        const { assert!(ICE_JSON_MAX <= 103 << 10) };
    }

    /// Go's decoder as the provider's structs meet it, where the vectors
    /// say nothing.
    #[test]
    fn a_reply_is_read_as_go_reads_one() {
        let api = |kind: &str| Error::api(STAGE_JOIN, kind);
        let join = |body: &str| decode::<Join>(body.as_bytes(), STAGE_JOIN, &Held::default());
        // A field's name in any case; the last of two wins; null leaves a
        // string as it was and takes a pointer away.
        let read = join(
            r#"{"ENDPOINT":"a","Token":"t","token":"u","endpoint":null,
                "p2p_forbidden":false,"P2P_FORBIDDEN":null,"client_type":"x","client_type":"VK"}"#,
        )
        .unwrap();
        assert_eq!(
            (
                read.endpoint.as_str(),
                read.token.as_str(),
                read.p2p_forbidden
            ),
            ("a", "u", None)
        );
        assert_eq!(read.client_type, "VK");
        // `null` for the whole reply is an empty one.
        assert!(join("null").unwrap().endpoint.is_empty());
        // Fields the chain never reads are held to their types all the same.
        assert_eq!(
            join(r#"{"wt_endpoint":5}"#).err(),
            Some(api("invalid_response"))
        );
        assert_eq!(join(r#"{"id":[]}"#).err(), Some(api("invalid_response")));
        assert!(join(r#"{"id":null,"wt_endpoint":"w","more":{"a":[1,2]}}"#).is_ok());
        // The envelope: an error that is no object, a code that is no
        // integer, text behind the value.
        assert_eq!(join(r#"{"error":"x"}"#).err(), Some(api("invalid_json")));
        assert_eq!(
            join(r#"{"error":{"error_code":"14"}}"#).err(),
            Some(api("invalid_json"))
        );
        assert_eq!(
            join(r#"{"error":{"error_code":1.5}}"#).err(),
            Some(api("invalid_json"))
        );
        assert_eq!(join(r#"{} x"#).err(), Some(api("invalid_json")));
        assert_eq!(join("").err(), Some(api("invalid_json")));
        assert_eq!(join("5").err(), Some(api("invalid_json")));
        // An error taken away by a later null is no error; an empty error
        // object is one.
        assert!(join(r#"{"error":{"error_code":1},"error":null}"#).is_ok());
        assert_eq!(
            join(r#"{"Error":{}}"#).err(),
            Some(Error::Api(GuestApiError {
                stage: STAGE_JOIN,
                code: 0,
                kind: String::new()
            }))
        );
        assert_eq!(
            join(r#"{"error":{"ERROR_CODE":-0,"error_msg":null}}"#).err(),
            Some(Error::Api(GuestApiError {
                stage: STAGE_JOIN,
                code: 0,
                kind: String::new()
            }))
        );
        // Step 1's unread fields.
        let boot = |body: &str| {
            decode::<Response<Bootstrap>>(body.as_bytes(), STAGE_ANON_TOKEN, &Held::default())
                .map(|r| r.0.token.clone())
        };
        assert_eq!(
            boot(r#"{"response":{"token":"t","expired_at":1,"is_verified":true}}"#),
            Ok("t".to_owned())
        );
        for bad in [
            r#"{"response":{"token":"t","expired_at":"1"}}"#,
            r#"{"response":{"token":"t","expired_at":1.5}}"#,
            r#"{"response":{"token":"t","is_verified":1}}"#,
            r#"{"response":"t"}"#,
            r#"{"response":[]}"#,
        ] {
            assert_eq!(
                boot(bad),
                Err(Error::api(STAGE_ANON_TOKEN, "invalid_response")),
                "{bad}"
            );
        }
        assert_eq!(boot(r#"{"response":null}"#), Ok(String::new()));

        // `isValidNumber`.
        for (text, valid) in [
            ("0", true),
            ("-0", true),
            ("77", true),
            ("-5", true),
            ("1.5", true),
            ("1e3", true),
            ("1E+3", true),
            ("0.0e-0", true),
            ("", false),
            ("-", false),
            ("007", false),
            ("+1", false),
            ("1.", false),
            (".5", false),
            ("1e", false),
            ("1e+", false),
            ("abc", false),
            ("1 ", false),
            ("0x1", false),
        ] {
            assert_eq!(is_json_number(text), valid, "{text:?}");
        }
    }

    #[test]
    fn the_link_and_its_id() {
        let link = canonical_link(" https://vk.com//call/join/a%41b/ \n").unwrap();
        assert_eq!(
            (link.as_str(), link.id()),
            ("https://vk.com/call/join/aAb", "aAb")
        );
        // An id that is not UTF-8 once its escapes are undone (Go sends
        // the bytes).
        assert_eq!(
            canonical_link("https://vk.ru/call/join/%FF"),
            Err(Error::RoomUrlShape)
        );
        // The defaults are the service's.
        assert_eq!(
            (API_BASE, FB_BASE),
            ("https://api.vk.me", "https://calls.okcdn.ru")
        );
    }
}

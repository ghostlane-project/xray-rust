// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The MTS Link auth provider (`internal/auth/mtslink`): the guest's way
//! into an endless meeting, as the Go engine measured it against the live
//! service on 2026-10-11.
//!
//! The gateway is `gw.mts-link.ru/api`. A guest needs no account: a login
//! with a nickname sets the cookies every later call presents. [`issue`]
//! does what the web client does between a link and the media: look the
//! event's session up, log the guest in, read the session's configuration
//! for the SFU it lives on, make a conference (the record of one
//! participant's published media, whose private key is the publish
//! ticket) and take a join token. The join itself is [`crate::signal`]'s.
//!
//! There is no cookie jar: the login's cookies are kept as one `Cookie`
//! value and later replies' `Set-Cookie` are not read. The cookies are a
//! live credential and reach no log and no error.

use olc_net::http::{HttpRequest, HttpResponse};
use olc_net::{cookies, form, retry, stream};
use olc_vp8channel::wire::split_room_hint;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::gourl::Url;
use crate::{Error, Ice, HTTP_TIMEOUT, REPLY_LIMIT};

/// The API the web client talks to (`defaultGateway`).
pub const DEFAULT_GATEWAY: &str = "https://gw.mts-link.ru";
/// The page the web client's calls come from (`webOrigin`).
pub const WEB_ORIGIN: &str = "https://my.mts-link.ru";
/// The User-Agent of the gateway calls in Go at the pin (`userAgent`,
/// `api.go:35`).
pub const WEB_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";
/// What a guest is called when the caller names none (`defaultNickname`);
/// the service refuses an empty one with 400.
pub const DEFAULT_NICKNAME: &str = "Гость";

/// The most bytes of a ticket taken from a reply: the conference's private
/// key and the join token. The service's are a few dozen; both go into the
/// join URL, which is kept for the session's life. Go has no bound but the
/// reply's megabyte.
pub const MAX_TICKET: usize = 4096;
/// The most bytes of the `Cookie` value a login's cookies make: the
/// service's are a few hundred, sent back on every gateway call and kept
/// for the session's life. Go has no bound but the reply's head.
pub const MAX_COOKIES: usize = 8192;
/// The longest room join a session keeps. The provider's own is under
/// 26 KiB at its worst: an SFU's name (253), the session and the guest's
/// ids, a nickname of 256 bytes and two tickets of [`MAX_TICKET`], each
/// escaped at three bytes a byte. The service's is about 600 bytes.
pub const MAX_JOIN_URL: usize = 32 << 10;
/// The longest gateway base a session keeps: a room link's bound.
pub const MAX_GATEWAY: usize = 2048;
/// The longest session, guest or conference id a session keeps: the
/// service's are numbers of twenty digits at most ([`is_id`]).
pub const MAX_ID: usize = 64;
/// The most the credentials of a session hold, in bytes
/// ([`Credentials::fits`]).
pub const CREDENTIALS_HELD: usize = MAX_JOIN_URL + MAX_COOKIES + MAX_GATEWAY + 3 * MAX_ID;

const FORM_TYPE: &str = "application/x-www-form-urlencoded";

/// What a gateway call says about its sender. The default is what Go at
/// the pin sends; nothing else is added (no `Accept`, no client hints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Web<'a> {
    /// The `User-Agent`.
    pub user_agent: &'a str,
    /// The `Origin`; the `Referer` is this and a slash.
    pub origin: &'a str,
}

impl Default for Web<'_> {
    fn default() -> Self {
        Self {
            user_agent: WEB_USER_AGENT,
            origin: WEB_ORIGIN,
        }
    }
}

/// What [`issue`] is asked (`auth.Config` and the provider's gateway).
#[derive(Clone, Copy, Default)]
pub struct Request<'a> {
    /// The event join link the platform stores, with or without its
    /// `?ice=` hint.
    pub room_url: &'a str,
    /// The guest's nickname; empty takes [`DEFAULT_NICKNAME`].
    pub name: &'a str,
    /// The ICE mode of a link without a hint (`auth.Config.DefaultICE`):
    /// the client side says `tcp`, a server nothing. A word that names no
    /// mode is no default.
    pub default_ice: &'a str,
    /// The gateway's base URL; empty is [`DEFAULT_GATEWAY`]. Only tests
    /// set it.
    pub gateway: &'a str,
    /// The sender's headers on the gateway calls.
    pub web: Web<'a>,
    /// The join's device id (`did`); none makes a new one on every call
    /// as Go does: eight random bytes in lower-case hex.
    pub did: Option<&'a str>,
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The link names the room's owner and its event, and the device id
        // is the guest's in the join: neither is for a log (K6). The
        // gateway and the sender's headers say nothing a reader needs.
        f.debug_struct("Request")
            .field("name", &self.name)
            .field("default_ice", &self.default_ice)
            .finish_non_exhaustive()
    }
}

/// What the engine joins with (`auth.Credentials`). The join URL and the
/// cookies are zeroed when it goes, and so is each copy of it.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The SFU room join (`URL`): the offer goes in, the answer comes out.
    /// It names the guest and holds both tokens.
    pub url: Zeroizing<String>,
    /// The guest's cookies (`Token`), for the gateway only: the SFU reads
    /// none. At most [`MAX_COOKIES`] bytes.
    pub token: Zeroizing<String>,
    /// `Extra["gateway"]`: where a conference is taken back.
    pub gateway: String,
    /// `Extra["sessionId"]`.
    pub session_id: String,
    /// `Extra["userId"]`.
    pub user_id: String,
    /// `Extra["conferenceId"]`: the conference to take back after a join
    /// that failed.
    pub conference_id: String,
    /// `Extra["ice"]`: the link's hint or the caller's default; none when
    /// neither names a mode.
    pub ice: Option<Ice>,
}

impl Credentials {
    /// Whether every part is within its bound ([`MAX_JOIN_URL`],
    /// [`MAX_COOKIES`], [`MAX_GATEWAY`], [`MAX_ID`]): what a session keeps
    /// for its life, and copies for each join, is [`CREDENTIALS_HELD`] at
    /// most whoever hands it over. What [`issue`] returns fits; an
    /// engine's direct credentials are the caller's.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.url.len() <= MAX_JOIN_URL
            && self.token.len() <= MAX_COOKIES
            && self.gateway.len() <= MAX_GATEWAY
            && [&self.session_id, &self.user_id, &self.conference_id]
                .iter()
                .all(|id| id.len() <= MAX_ID)
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URL holds two tokens, the token is the cookies, and the ids
        // name the room and the guest.
        f.debug_struct("Credentials")
            .field("ice", &self.ice)
            .finish_non_exhaustive()
    }
}

/// `isID`: a service id, 1 to 20 ASCII digits.
#[must_use]
pub fn is_id(s: impl AsRef<[u8]>) -> bool {
    let s = s.as_ref();
    (1..=20).contains(&s.len()) && s.iter().all(u8::is_ascii_digit)
}

/// `isHost`: whether `s` can be the host of a URL and nothing more: the
/// SFU's name comes out of a reply and goes into a URL.
#[must_use]
pub fn is_host(s: impl AsRef<[u8]>) -> bool {
    let s = s.as_ref();
    (1..=253).contains(&s.len())
        && s.iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// `parseEventLink`: the event, and the session when the link names one,
/// of the join link the platform stores
/// (`https://my.mts-link.ru/j/{ownerId}/{eventId}`, or the same with
/// `/session/{sessionId}` behind it).
///
/// # Errors
/// [`Error::RoomRef`] for anything else.
pub fn parse_event_link(room: &str) -> Result<(String, Option<String>), Error> {
    let url = Url::parse(room.trim()).ok_or(Error::RoomRef)?;
    let path = url.path();
    let first = path.iter().position(|&b| b != b'/').unwrap_or(path.len());
    let last = path
        .iter()
        .rposition(|&b| b != b'/')
        .map_or(first, |i| i + 1);
    let parts: Vec<&[u8]> = path[first..last].split(|&b| b == b'/').collect();
    let at = parts
        .iter()
        .position(|&part| part == b"j")
        .ok_or(Error::RoomRef)?;
    if parts.len() < at + 3 || !is_id(parts[at + 1]) || !is_id(parts[at + 2]) {
        return Err(Error::RoomRef);
    }
    // An id is ASCII digits.
    let text = |id: &[u8]| String::from_utf8_lossy(id).into_owned();
    let session = (parts.len() >= at + 5 && parts[at + 3] == b"session" && is_id(parts[at + 4]))
        .then(|| text(parts[at + 4]));
    Ok((text(parts[at + 2]), session))
}

/// The session a login made (`guest`).
struct Guest {
    /// The cookies the gateway set, as the `Cookie` value that presents
    /// them.
    cookies: Zeroizing<String>,
    user_id: String,
}

/// One gateway request (`call`): what it is called in an error, how it is
/// made, and which status is an answer.
struct Call<'a> {
    name: &'static str,
    method: &'static str,
    url: String,
    form: Option<String>,
    want: u16,
    web: &'a Web<'a>,
}

impl Call<'_> {
    /// `call.do`: the reply when its status is the one wanted.
    /// [`Error::RoomGone`] for a room the service does not know (404, 406,
    /// 410) and [`Error::BadStatus`] for the rest; the body is in neither.
    async fn run(&self, cookies: &str) -> Result<HttpResponse, Error> {
        let transport = |cause: String| Error::Transport {
            call: self.name,
            cause,
        };
        let target = stream::parse_url(&self.url)
            .map_err(|_| transport("the gateway's URL does not parse".into()))?;
        let referer = format!("{}/", self.web.origin);
        // Go's order on the wire: the User-Agent, then the rest by name.
        let mut headers: Vec<(&str, &str)> = Vec::with_capacity(5);
        headers.push(("User-Agent", self.web.user_agent));
        if self.form.is_some() {
            headers.push(("Content-Type", FORM_TYPE));
        }
        if !cookies.is_empty() {
            headers.push(("Cookie", cookies));
        }
        headers.push(("Origin", self.web.origin));
        headers.push(("Referer", referer.as_str()));
        let req = HttpRequest {
            method: self.method,
            host: &target.authority,
            path: &target.path,
            headers: &headers,
            body: self.form.as_deref().unwrap_or("").as_bytes(),
            max_body: REPLY_LIMIT,
            timeout: HTTP_TIMEOUT,
        };
        let resp = retry::fetch(&target, &req)
            .await
            .map_err(|e| transport(e.to_string()))?;
        match resp.status {
            status if status == self.want => Ok(resp),
            404 | 406 | 410 => Err(Error::RoomGone(self.name)),
            status => Err(Error::BadStatus {
                call: self.name,
                status,
            }),
        }
    }
}

/// `json.Unmarshal` into a struct: a field that is absent or `null` is
/// left at its zero value, and so is the whole reply when it is `null`;
/// any other mismatch is none.
fn decode<'de, T: Deserialize<'de> + Default>(raw: &'de [u8]) -> Option<T> {
    serde_json::from_slice::<Option<T>>(raw)
        .ok()
        .map(Option::unwrap_or_default)
}

#[derive(Deserialize, Default)]
struct Id {
    #[serde(default)]
    id: Option<i64>,
}

impl Id {
    /// The id as the service's paths spell it; none unless positive.
    fn text(&self) -> Option<String> {
        self.id.filter(|&id| id > 0).map(|id| id.to_string())
    }
}

/// A ticket out of a reply: a JSON string of at most [`MAX_TICKET`]
/// bytes, counted as the string's own bytes, not as the reply spelled
/// them. A longer one fails the reply's decoding before it is copied, and
/// what is copied is zeroed when it goes.
struct Ticket(Zeroizing<String>);

impl<'de> Deserialize<'de> for Ticket {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Bounded;
        impl serde::de::Visitor<'_> for Bounded {
            type Value = Ticket;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a string of at most {MAX_TICKET} bytes")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Ticket, E> {
                if text.len() > MAX_TICKET {
                    // The length alone: the text is the ticket.
                    return Err(E::invalid_length(text.len(), &self));
                }
                Ok(Ticket(Zeroizing::new(text.to_owned())))
            }
        }
        d.deserialize_str(Bounded)
    }
}

impl Ticket {
    /// The ticket; none for an empty one.
    fn text(self) -> Option<Zeroizing<String>> {
        (!self.0.is_empty()).then_some(self.0)
    }
}

/// The first element of a JSON list of ids. The others are read, held to
/// the same type as Go's decoder holds them, and dropped one by one: a
/// reply's megabyte of list never becomes a megabyte of ids.
#[derive(Default)]
struct First(Option<Id>);

impl<'de> Deserialize<'de> for First {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Elements;
        impl<'de> serde::de::Visitor<'de> for Elements {
            type Value = First;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a list of objects")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<First, A::Error> {
                let first = seq.next_element::<Option<Id>>()?.flatten();
                while seq.next_element::<Option<Id>>()?.is_some() {}
                Ok(First(first))
            }
        }
        d.deserialize_seq(Elements)
    }
}

/// `eventSession`: the event's public record names its session. An
/// endless meeting has one, started when the room was made.
async fn event_session(web: &Web<'_>, gateway: &str, event: &str) -> Result<String, Error> {
    #[derive(Deserialize, Default)]
    struct Reply {
        #[serde(rename = "eventSessions", default)]
        event_sessions: Option<First>,
    }
    let resp = Call {
        name: "event",
        method: "GET",
        url: format!("{gateway}/api/event/{event}"),
        form: None,
        want: 200,
        web,
    }
    .run("")
    .await?;
    decode::<Reply>(&resp.body)
        .and_then(|reply| reply.event_sessions)
        .and_then(|sessions| sessions.0)
        .and_then(|first| first.text())
        .ok_or(Error::NoSession)
}

/// `guestLogin`: registers a guest on the session. The reply's own `user`
/// carries no id (the guest's user sits under `participation`), and the
/// cookies are every one the reply set: the web client presents them all.
async fn guest_login(
    web: &Web<'_>,
    gateway: &str,
    session: &str,
    nickname: &str,
) -> Result<Guest, Error> {
    #[derive(Deserialize, Default)]
    struct Participation {
        #[serde(default)]
        user: Option<Id>,
    }
    #[derive(Deserialize, Default)]
    struct Reply {
        #[serde(rename = "isAccepted", default)]
        is_accepted: Option<bool>,
        #[serde(default)]
        participation: Option<Participation>,
    }
    const INCOMPLETE: Error = Error::IncompleteReply("guestlogin");
    let resp = Call {
        name: "guestlogin",
        method: "POST",
        url: format!("{gateway}/api/eventsessions/{session}/guestlogin"),
        form: Some(form::encode(&[
            ("nickname", nickname),
            ("name", ""),
            ("secondName", ""),
            ("phone", ""),
        ])),
        want: 200,
        web,
    }
    .run("")
    .await?;
    let reply = decode::<Reply>(&resp.body).ok_or(INCOMPLETE)?;
    if reply.is_accepted != Some(true) {
        return Err(Error::NotAccepted);
    }
    let user_id = reply
        .participation
        .and_then(|p| p.user)
        .and_then(|user| user.text())
        .ok_or(INCOMPLETE)?;
    let set = cookies::from_set_cookie(&resp.headers);
    // The `Cookie` value's size, before it is made: the pairs and a "; "
    // between each two.
    let size = set.iter().map(String::len).sum::<usize>() + 2 * set.len().saturating_sub(1);
    if set.is_empty() || size > MAX_COOKIES {
        return Err(INCOMPLETE);
    }
    Ok(Guest {
        cookies: Zeroizing::new(cookies::header(&set)),
        user_id,
    })
}

/// `mediaServer`: the SFU the session lives on, out of its configuration.
async fn media_server(
    web: &Web<'_>,
    gateway: &str,
    session: &str,
    guest: &Guest,
) -> Result<String, Error> {
    #[derive(Deserialize, Default)]
    struct Reply {
        #[serde(rename = "rtcServer", default)]
        rtc_server: Option<String>,
    }
    let resp = Call {
        name: "configuration",
        method: "GET",
        url: format!("{gateway}/api/eventsession/{session}/configuration"),
        form: None,
        want: 200,
        web,
    }
    .run(&guest.cookies)
    .await?;
    decode::<Reply>(&resp.body)
        .and_then(|reply| reply.rtc_server)
        .filter(|name| is_host(name))
        .ok_or(Error::IncompleteReply("configuration"))
}

/// The record of one participant's published media (`conference`).
struct Conference {
    id: String,
    /// The record's private key: what lets its owner publish.
    publish_token: Zeroizing<String>,
}

/// `newConference`: the guest's conference, a camera and no microphone,
/// which is all the engine publishes.
async fn new_conference(
    web: &Web<'_>,
    gateway: &str,
    session: &str,
    guest: &Guest,
) -> Result<Conference, Error> {
    #[derive(Deserialize, Default)]
    struct Reply {
        #[serde(default)]
        id: Option<i64>,
        #[serde(rename = "privateKey", default)]
        private_key: Option<Ticket>,
    }
    const INCOMPLETE: Error = Error::IncompleteReply("conferences");
    let resp = Call {
        name: "conferences",
        method: "POST",
        url: format!("{gateway}/api/eventsessions/{session}/conferences"),
        form: Some(form::encode(&[("hasAudio", "false"), ("hasVideo", "true")])),
        want: 201,
        web,
    }
    .run(&guest.cookies)
    .await?;
    let reply = decode::<Reply>(&resp.body).ok_or(INCOMPLETE)?;
    let id = Id { id: reply.id }.text().ok_or(INCOMPLETE)?;
    let publish_token = reply.private_key.and_then(Ticket::text).ok_or(INCOMPLETE)?;
    Ok(Conference { id, publish_token })
}

/// `joinToken`: the ticket the room join presents.
async fn join_token(
    web: &Web<'_>,
    gateway: &str,
    session: &str,
    guest: &Guest,
) -> Result<Zeroizing<String>, Error> {
    #[derive(Deserialize, Default)]
    struct Data {
        #[serde(rename = "joinToken", default)]
        join_token: Option<Ticket>,
    }
    #[derive(Deserialize, Default)]
    struct Reply {
        #[serde(default)]
        data: Option<Data>,
    }
    let resp = Call {
        name: "join-token",
        method: "GET",
        url: format!("{gateway}/api/eventsessions/{session}/join-token"),
        form: None,
        want: 200,
        web,
    }
    .run(&guest.cookies)
    .await?;
    decode::<Reply>(&resp.body)
        .and_then(|reply| reply.data)
        .and_then(|data| data.join_token)
        .and_then(Ticket::text)
        .ok_or(Error::IncompleteReply("join-token"))
}

/// `leave`: takes a conference back, `DELETE /api/conferences/{id}` with
/// the cookies of the guest that made it (204, measured). The service
/// drops the record by itself once its publisher has been on the SFU and
/// left; one whose join never reached the SFU stays in the room's list
/// until its guest takes it back.
///
/// # Errors
/// [`Error::ConferenceId`] before any request for an id that is not a
/// number; the call's own otherwise.
pub async fn leave(
    web: &Web<'_>,
    gateway: &str,
    conference_id: &str,
    cookies: &str,
) -> Result<(), Error> {
    if !is_id(conference_id) {
        return Err(Error::ConferenceId);
    }
    Call {
        name: "leave",
        method: "DELETE",
        url: format!("{gateway}/api/conferences/{conference_id}"),
        form: None,
        want: 204,
        web,
    }
    .run(cookies)
    .await
    .map(|_| ())
}

/// A join's device id as Go makes one: eight random bytes in lower-case
/// hex.
fn new_did() -> String {
    rand::random::<[u8; 8]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `roomJoinURL`: the SFU join the web client issues for a meeting, as far
/// as it names the guest (measured 2026-10-11):
///
/// ```text
/// POST https://{rtcServer}/rtc/room/{sessionId}/join
///      ?userId=&joinToken=&disableRecording=true&userName=&publishToken=&did=&pid=
/// ```
///
/// `did` and `pid` are the web client's device and page ids, the second
/// the first turned left by one character. What describes the offer
/// (`twcc`, `originMid`, `preferredPublishCodec`) is
/// [`crate::signal::offer_url`]'s to add. The query is `url.Values.Encode`'s:
/// sorted by key.
#[must_use]
pub fn room_join_url(
    server: &str,
    session: &str,
    user_id: &str,
    nickname: &str,
    join_token: &str,
    publish_token: &str,
    did: &str,
) -> String {
    let turn = did.chars().next().map_or(0, char::len_utf8);
    let pid = format!("{}{}", &did[turn..], &did[..turn]);
    // The query holds both tickets: it is zeroed once it is in the URL.
    let query = Zeroizing::new(form::encode(&[
        ("userId", user_id),
        ("joinToken", join_token),
        ("disableRecording", "true"),
        ("userName", nickname),
        ("publishToken", publish_token),
        ("did", did),
        ("pid", &pid),
    ]));
    format!("https://{server}/rtc/room/{session}/join?{}", *query)
}

/// `Provider.Issue`: walks a guest into the room and returns what the
/// engine joins with. Every call makes a new guest and a new conference:
/// the cookies of one are of no use to the next process, and a guest that
/// is gone leaves nothing behind in the room.
///
/// The calls are the web client's, in its order: the event (skipped when
/// the link names its session), the login, the configuration, the
/// conference, the join token; and the conference taken back when the
/// join token fails, since nothing will join it.
///
/// # Errors
/// [`Error::RoomRef`] for a link that is not the event join link, before
/// any request; the failing call's error otherwise.
pub async fn issue(req: &Request<'_>) -> Result<Credentials, Error> {
    let (room, hint) = split_room_hint(req.room_url);
    // A link that says nothing takes what its side asks for.
    let ice = Ice::from_word(hint).or_else(|| Ice::from_word(req.default_ice));
    let (event, session) = parse_event_link(room)?;
    let gateway = if req.gateway.is_empty() {
        DEFAULT_GATEWAY
    } else {
        req.gateway
    };
    let web = &req.web;

    let session = match session {
        Some(session) => session,
        None => event_session(web, gateway, &event).await?,
    };
    let nickname = if req.name.is_empty() {
        DEFAULT_NICKNAME
    } else {
        req.name
    };
    let mut guest = guest_login(web, gateway, &session, nickname).await?;
    let server = media_server(web, gateway, &session, &guest).await?;
    let conference = new_conference(web, gateway, &session, &guest).await?;
    let token = match join_token(web, gateway, &session, &guest).await {
        Ok(token) => token,
        Err(e) => {
            // The conference is made and nothing will join it: take it
            // back rather than leave it in the room's list for good.
            let _ = leave(web, gateway, &conference.id, &guest.cookies).await;
            return Err(e);
        }
    };

    let fresh;
    let did = match req.did {
        Some(did) => did,
        None => {
            fresh = new_did();
            fresh.as_str()
        }
    };
    Ok(Credentials {
        url: Zeroizing::new(room_join_url(
            &server,
            &session,
            &guest.user_id,
            nickname,
            &token,
            &conference.publish_token,
            did,
        )),
        token: std::mem::take(&mut guest.cookies),
        gateway: gateway.to_owned(),
        session_id: session,
        user_id: guest.user_id,
        conference_id: conference.id,
        ice,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::testing::{bounded, Reply, Seen, Stub};

    pub(crate) const EVENT: &str = "20300400500";
    pub(crate) const SESSION: &str = "20300400600";
    const OWNER: &str = "100200300";
    pub(crate) const LINK: &str = "https://my.mts-link.ru/j/100200300/20300400500";

    // The gateway's own answers, as it gave them on 2026-10-11 (ids kept,
    // tokens replaced): `mtslink_test.go:26-44`, verbatim.
    const REPLY_EVENT: &str = concat!(
        r#"{"id":20300400500,"access":1,"type":"meeting","status":"ACTIVE","isEndless":true,"#,
        r#""eventSessions":[{"id":20300400600,"access":1,"type":"meeting","status":"START"}]}"#
    );
    pub(crate) const REPLY_GUEST_LOGIN: &str = concat!(
        r#"{"isAccepted":true,"participationId":1485424883,"user":{"sessionId":"529e1f7db49244b035d47e8c4eca75f4"},"#,
        r#""participation":{"id":1485424883,"name":"","nickname":"cap-a","isOnline":false,"isAccepted":true,"role":"GUEST","#,
        r#""event":{"id":20300400500},"user":{"id":100200999,"type":"GUEST","isDeleted":false,"nickname":"cap-a"},"#,
        r#""eventSession":{"id":20300400600},"registerStatus":"INVITED"}}"#
    );
    const REPLY_CONFIGURATION: &str = concat!(
        r#"{"hlsServer":"events-delivery-files.webinar.ru","rtcServer":"sfu.mts-link.ru","#,
        r#""mediaServer":"live-sd.webinar.ru","rtcUrl":"\/\/sfu.mts-link.ru\/event\/20300400600\/rtc","#,
        r#""cometServer":"msg-edge-5.webinar.ru","rtcActiveSpeakerServer":"sfu.mts-link.ru"}"#
    );
    const REPLY_CONFERENCE: &str = concat!(
        r#"{"id":395296501,"isDeleted":false,"createAt":"2026-10-11T15:46:04+03:00","#,
        r#""privateKey":"vcPRIVATE0000000000000000000000000","publicKey":"vcPUBLIC00000000000000000000000000","#,
        r#""userId":100200999,"user":{"id":100200999,"nickname":"cap-a"},"status":"PUBLISH","size":"SMALL","#,
        r#""hasStream":false,"hasVideo":true,"hasAudio":false,"typeMedia":"conference","participationId":1485424883}"#
    );
    const REPLY_JOIN_TOKEN: &str = r#"{"data":{"joinToken":"vcJOIN000000000000000000000000000"}}"#;
    const REPLY_GONE: &str = r#"{"error":{"code":406,"message":"Not Acceptable"}}"#;
    pub(crate) const REPLY_NO_TOKEN: &str =
        r#"{"error":{"code":401,"message":"A Token was not found in the TokenStorage."}}"#;
    const REPLY_ACCESS_DENIED: &str = r#"{"error":{"code":403,"message":"Access denied"}}"#;

    /// The cookies the service sets at the login.
    pub(crate) const LOGIN_COOKIES: [&str; 3] = [
        "access=eyJguest.access",
        "refresh=6074c7a91c56476840728cab1c1b42f5",
        "sessionId=529e1f7db49244b0",
    ];

    /// What the fake answers differently from the service.
    #[derive(Default)]
    struct Changes {
        /// A path's reply, in place of the measured one.
        answer: HashMap<String, Reply>,
        /// What the configuration names; none keeps the measured SFU.
        rtc_server: Option<String>,
        /// Requests the web client never makes.
        strays: Vec<String>,
    }

    /// The service behind one test server (`gateway`,
    /// `mtslink_test.go:49-146`): it answers the measured shapes, sets the
    /// guest's cookies at the login and expects them back on every call
    /// that needs them.
    pub(crate) struct Gateway {
        pub(crate) stub: Stub,
        changes: Arc<Mutex<Changes>>,
    }

    fn cookie<'a>(seen: &'a Seen, name: &str) -> Option<&'a str> {
        seen.header("Cookie")?
            .split("; ")
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
    }

    fn measured(seen: &Seen, changes: &mut Changes) -> Reply {
        let guest = cookie(seen, "access") == Some("eyJguest.access")
            && cookie(seen, "sessionId") == Some("529e1f7db49244b0");
        let call = format!("{} {}", seen.method, seen.target);
        if call == format!("GET /api/event/{EVENT}") {
            Reply::new(200, REPLY_EVENT)
        } else if call == format!("POST /api/eventsessions/{SESSION}/guestlogin") {
            // As the service sets them: Secure, HttpOnly, SameSite=None.
            LOGIN_COOKIES
                .iter()
                .fold(Reply::new(200, REPLY_GUEST_LOGIN), |reply, pair| {
                    reply.header(
                        "Set-Cookie",
                        &format!(
                            "{pair}; Path=/; Domain=.mts-link.ru; Secure; HttpOnly; SameSite=None"
                        ),
                    )
                })
        } else if call == format!("GET /api/eventsession/{SESSION}/configuration") {
            if !guest {
                return Reply::new(403, REPLY_ACCESS_DENIED);
            }
            match &changes.rtc_server {
                Some(name) => Reply::new(
                    200,
                    REPLY_CONFIGURATION.replace(
                        r#""rtcServer":"sfu.mts-link.ru""#,
                        &format!(r#""rtcServer":"{name}""#),
                    ),
                ),
                None => Reply::new(200, REPLY_CONFIGURATION),
            }
        } else if call == format!("POST /api/eventsessions/{SESSION}/conferences") {
            if !guest {
                return Reply::new(401, REPLY_NO_TOKEN);
            }
            Reply::new(201, REPLY_CONFERENCE)
        } else if call == format!("GET /api/eventsessions/{SESSION}/join-token") {
            if !guest {
                return Reply::new(401, REPLY_NO_TOKEN);
            }
            Reply::new(200, REPLY_JOIN_TOKEN)
        } else if call == "DELETE /api/conferences/395296501" {
            if !guest {
                return Reply::new(401, REPLY_NO_TOKEN);
            }
            Reply::new(204, "")
        } else {
            changes.strays.push(call);
            Reply::new(406, REPLY_GONE)
        }
    }

    impl Gateway {
        pub(crate) async fn start() -> Self {
            let changes = Arc::new(Mutex::new(Changes::default()));
            let theirs = changes.clone();
            let stub = Stub::start(move |seen| {
                let mut changes = theirs.lock().unwrap();
                match changes.answer.get(&seen.target) {
                    Some(reply) => reply.clone(),
                    None => measured(seen, &mut changes),
                }
            })
            .await;
            Self { stub, changes }
        }

        /// Answers `path` with `status` and `body` from now on.
        pub(crate) fn status(&self, path: &str, status: u16, body: &str) {
            self.answer(path, Reply::new(status, body));
        }

        pub(crate) fn answer(&self, path: &str, reply: Reply) {
            self.changes
                .lock()
                .unwrap()
                .answer
                .insert(path.to_owned(), reply);
        }

        pub(crate) fn names_sfu(&self, name: &str) {
            self.changes.lock().unwrap().rtc_server = Some(name.to_owned());
        }

        /// `METHOD path` of every request, in order. Fails on a request
        /// the web client never makes.
        pub(crate) fn calls(&self) -> Vec<String> {
            let strays = &self.changes.lock().unwrap().strays;
            assert!(
                strays.is_empty(),
                "the provider asked for {strays:?}, which the web client never does"
            );
            self.stub
                .seen()
                .iter()
                .map(|s| format!("{} {}", s.method, s.target))
                .collect()
        }

        /// The decoded body of the last POST to `path`.
        fn form(&self, path: &str) -> HashMap<String, String> {
            let seen = self.stub.seen();
            let post = seen
                .iter()
                .rev()
                .find(|s| s.method == "POST" && s.target == path)
                .unwrap_or_else(|| panic!("no POST to {path}"));
            let body = String::from_utf8(post.body.clone()).unwrap();
            let url = format!("http://form/?{body}");
            Url::parse(&url)
                .unwrap()
                .query()
                .into_iter()
                .map(|(k, v)| (String::from_utf8(k).unwrap(), String::from_utf8(v).unwrap()))
                .collect()
        }

        pub(crate) async fn issue(&self, link: &str, name: &str) -> Result<Credentials, Error> {
            self.issue_with(link, name, "").await
        }

        pub(crate) async fn issue_with(
            &self,
            link: &str,
            name: &str,
            default_ice: &str,
        ) -> Result<Credentials, Error> {
            bounded(issue(&Request {
                room_url: link,
                name,
                default_ice,
                gateway: &self.stub.base,
                ..Request::default()
            }))
            .await
        }
    }

    fn login_path() -> String {
        format!("/api/eventsessions/{SESSION}/guestlogin")
    }

    fn join_token_path() -> String {
        format!("/api/eventsessions/{SESSION}/join-token")
    }

    /// The join URL's query, decoded.
    fn query_of(url: &str) -> HashMap<String, String> {
        Url::parse(url)
            .unwrap()
            .query()
            .into_iter()
            .map(|(k, v)| (String::from_utf8(k).unwrap(), String::from_utf8(v).unwrap()))
            .collect()
    }

    // TestParseEventLink.
    #[test]
    fn an_event_link_names_its_event_and_maybe_its_session() {
        let session_link = format!("{LINK}/session/{SESSION}");
        let stream_link = format!("{LINK}/stream-new/{SESSION}");
        let padded = format!("  {LINK}\n");
        let no_owner = format!("https://my.mts-link.ru/j/abc/{EVENT}");
        let no_event = format!("https://my.mts-link.ru/j/{OWNER}");
        for (link, want) in [
            (LINK, Some((EVENT, None))),
            (session_link.as_str(), Some((EVENT, Some(SESSION)))),
            (stream_link.as_str(), Some((EVENT, None))),
            (padded.as_str(), Some((EVENT, None))),
            (no_owner.as_str(), None),
            (no_event.as_str(), None),
            ("not a url", None),
            ("https://my.mts-link.ru/events", None),
            ("", None),
        ] {
            let got = parse_event_link(link);
            match want {
                Some((event, session)) => assert_eq!(
                    got,
                    Ok((event.to_owned(), session.map(str::to_owned))),
                    "{link:?}"
                ),
                None => assert_eq!(got, Err(Error::RoomRef), "{link:?}"),
            }
        }
    }

    // TestIssueWalksTheGuestFlowAndBuildsTheRoomJoin: the whole guest
    // flow, in the web client's order, with the web client's bodies.
    #[tokio::test]
    async fn issue_walks_the_guest_flow_and_builds_the_room_join() {
        let gw = Gateway::start().await;
        let creds = gw.issue(LINK, "Мария Ковалёва").await.unwrap();

        assert_eq!(
            gw.calls(),
            [
                format!("GET /api/event/{EVENT}"),
                format!("POST /api/eventsessions/{SESSION}/guestlogin"),
                format!("GET /api/eventsession/{SESSION}/configuration"),
                format!("POST /api/eventsessions/{SESSION}/conferences"),
                format!("GET /api/eventsessions/{SESSION}/join-token"),
            ]
        );
        assert_eq!(gw.form(&login_path())["nickname"], "Мария Ковалёва");
        let conf = gw.form(&format!("/api/eventsessions/{SESSION}/conferences"));
        assert_eq!(
            (conf["hasVideo"].as_str(), conf["hasAudio"].as_str()),
            ("true", "false"),
            "a camera and no microphone"
        );

        let prefix = format!("https://sfu.mts-link.ru/rtc/room/{SESSION}/join?");
        assert!(
            creds.url.starts_with(&prefix),
            "the configuration's SFU and the session's room"
        );
        let q = query_of(&creds.url);
        for (key, want) in [
            // participation.user.id: the login reply's top-level user has no id
            ("userId", "100200999"),
            ("joinToken", "vcJOIN000000000000000000000000000"),
            ("publishToken", "vcPRIVATE0000000000000000000000000"),
            ("userName", "Мария Ковалёва"),
            ("disableRecording", "true"),
        ] {
            assert_eq!(q[key], want, "join URL {key}");
        }
        let (did, pid) = (&q["did"], &q["pid"]);
        assert!(
            did.len() == 16 && pid.len() == 16 && did != pid,
            "two 16-hex ids"
        );
        assert_eq!(q.len(), 7);

        assert_eq!(
            (
                creds.session_id.as_str(),
                creds.user_id.as_str(),
                creds.conference_id.as_str(),
                creds.gateway.as_str()
            ),
            (SESSION, "100200999", "395296501", gw.stub.base.as_str())
        );
        // The cookies are for the gateway; every one the login set
        // travels, not a pair picked by name.
        assert_eq!(*creds.token, LOGIN_COOKIES.join("; "));
        // And none of it is printed.
        let shown = format!("{creds:?}");
        for secret in ["vcJOIN", "vcPRIVATE", "eyJguest", SESSION, "100200999"] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
    }

    // What Go's client leaves to its defaults is said here: the device id
    // is new on every issue, sixteen lower-case hex digits, and the page
    // id is the device id turned left by one.
    #[tokio::test]
    async fn every_issue_has_a_new_device_id_unless_one_is_given() {
        let gw = Gateway::start().await;
        let mut seen = Vec::new();
        for _ in 0..2 {
            let q = query_of(&gw.issue(LINK, "a").await.unwrap().url);
            let (did, pid) = (q["did"].clone(), q["pid"].clone());
            assert!(
                did.len() == 16 && did.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{did:?}"
            );
            assert_eq!(pid, format!("{}{}", &did[1..], &did[..1]));
            seen.push(did);
        }
        assert_ne!(seen[0], seen[1], "one device id for two guests");

        let given = bounded(issue(&Request {
            room_url: LINK,
            gateway: &gw.stub.base,
            did: Some("0123456789abcdef"),
            ..Request::default()
        }))
        .await
        .unwrap();
        let q = query_of(&given.url);
        assert_eq!(
            (q["did"].as_str(), q["pid"].as_str()),
            ("0123456789abcdef", "123456789abcdef0")
        );
    }

    // The gateway calls go out under the sender's headers: Go's by
    // default, the caller's when it names others.
    #[tokio::test]
    async fn the_gateway_calls_carry_the_senders_headers() {
        let gw = Gateway::start().await;
        gw.issue(LINK, "a").await.unwrap();
        for seen in gw.stub.seen() {
            assert_eq!(seen.header("User-Agent"), Some(WEB_USER_AGENT));
            assert_eq!(seen.header("Origin"), Some("https://my.mts-link.ru"));
            assert_eq!(seen.header("Referer"), Some("https://my.mts-link.ru/"));
            assert_eq!(
                seen.header("Content-Type"),
                (seen.method == "POST").then_some(FORM_TYPE),
                "{} {}",
                seen.method,
                seen.target
            );
            assert_eq!(seen.header("Accept"), None);
        }

        let other = Gateway::start().await;
        bounded(issue(&Request {
            room_url: LINK,
            gateway: &other.stub.base,
            web: Web {
                user_agent: "agent/1",
                origin: "https://page.example",
            },
            ..Request::default()
        }))
        .await
        .unwrap();
        for seen in other.stub.seen() {
            assert_eq!(seen.header("User-Agent"), Some("agent/1"));
            assert_eq!(seen.header("Origin"), Some("https://page.example"));
            assert_eq!(seen.header("Referer"), Some("https://page.example/"));
        }
    }

    // TestIssueTakesTheSessionALinkNames.
    #[tokio::test]
    async fn issue_takes_the_session_a_link_names() {
        let gw = Gateway::start().await;
        gw.issue(&format!("{LINK}/session/{SESSION}"), "a")
            .await
            .unwrap();
        assert_eq!(
            gw.calls()[0],
            format!("POST /api/eventsessions/{SESSION}/guestlogin"),
            "a link that names its session needs no event lookup"
        );
    }

    // TestIssueJoinsUnderADefaultNameWhenNoneIsGiven.
    #[tokio::test]
    async fn issue_joins_under_a_default_name_when_none_is_given() {
        let gw = Gateway::start().await;
        let creds = gw.issue(LINK, "").await.unwrap();
        let nick = gw.form(&login_path())["nickname"].clone();
        assert_eq!(
            nick, DEFAULT_NICKNAME,
            "an empty nickname is refused by the service (400 ERROR_BAD_REQUEST)"
        );
        assert_eq!(
            query_of(&creds.url)["userName"],
            nick,
            "the join names another user than the login"
        );
    }

    // TestIssueJoinsTheSFUTheConfigurationNames: webinar rooms answered
    // on live-webrtc-ixcN-*.webinar.ru, meetings on sfu.mts-link.ru.
    #[tokio::test]
    async fn issue_joins_the_sfu_the_configuration_names() {
        let gw = Gateway::start().await;
        gw.names_sfu("live-webrtc-ixc1-13.webinar.ru");
        let creds = gw.issue(LINK, "a").await.unwrap();
        let prefix = format!("https://live-webrtc-ixc1-13.webinar.ru/rtc/room/{SESSION}/join?");
        assert!(creds.url.starts_with(&prefix));
    }

    // TestIssueRefusesAnSFUNameThatIsNotAHost.
    #[tokio::test]
    async fn issue_refuses_an_sfu_name_that_is_not_a_host() {
        for name in ["", "evil.example/path?x=", "user@host", "a b"] {
            let gw = Gateway::start().await;
            gw.names_sfu(name);
            assert_eq!(
                gw.issue(LINK, "a").await,
                Err(Error::IncompleteReply("configuration")),
                "rtcServer {name:?}"
            );
        }
    }

    // TestARoomTheServiceNoLongerHasIsGone: 406 at the event lookup and
    // at the login alike (measured). That is the room, not the guest.
    #[tokio::test]
    async fn a_room_the_service_no_longer_has_is_gone() {
        let gw = Gateway::start().await;
        gw.status(&format!("/api/event/{EVENT}"), 406, REPLY_GONE);
        assert_eq!(gw.issue(LINK, "a").await, Err(Error::RoomGone("event")));

        let gw = Gateway::start().await;
        gw.status(&login_path(), 406, REPLY_GONE);
        assert_eq!(
            gw.issue(LINK, "a").await,
            Err(Error::RoomGone("guestlogin"))
        );
        // 404 and 410 say the same; nothing else does.
        for (status, gone) in [(404, true), (410, true), (400, false), (409, false)] {
            let gw = Gateway::start().await;
            gw.status(&login_path(), status, REPLY_GONE);
            let err = gw.issue(LINK, "a").await.unwrap_err();
            assert_eq!(err == Error::RoomGone("guestlogin"), gone, "{status}");
        }
    }

    // TestAnEventWithoutASessionIsNotARoom.
    #[tokio::test]
    async fn an_event_without_a_session_is_not_a_room() {
        for body in [
            r#"{"id":20300400500,"eventSessions":[]}"#,
            r#"{"id":20300400500}"#,
            r#"{"eventSessions":[{"id":0}]}"#,
            r#"{"eventSessions":[{"id":"20300400600"}]}"#,
            r#"{"eventSessions":null}"#,
            r#"{"eventSessions":{"id":20300400600}}"#,
            // The first session is the one; and every element is held to
            // its type, as Go's decoder holds it.
            r#"{"eventSessions":[null,{"id":20300400600}]}"#,
            r#"{"eventSessions":[{"id":20300400600},7]}"#,
            "null",
            "<html>",
        ] {
            let gw = Gateway::start().await;
            gw.status(&format!("/api/event/{EVENT}"), 200, body);
            assert_eq!(gw.issue(LINK, "a").await, Err(Error::NoSession), "{body}");
        }
    }

    // The event's first session is the room, whatever follows it.
    #[tokio::test]
    async fn the_first_session_of_an_event_is_joined() {
        let gw = Gateway::start().await;
        gw.status(
            &format!("/api/event/{EVENT}"),
            200,
            r#"{"eventSessions":[{"id":20300400600},{"id":1},null,{}]}"#,
        );
        assert_eq!(gw.issue(LINK, "a").await.unwrap().session_id, SESSION);
    }

    // TestAGuestTheServiceTurnsAwayIsNotAccepted.
    #[tokio::test]
    async fn a_guest_the_service_turns_away_is_not_accepted() {
        let gw = Gateway::start().await;
        gw.status(
            &login_path(),
            200,
            &REPLY_GUEST_LOGIN.replacen(r#""isAccepted":true"#, r#""isAccepted":false"#, 1),
        );
        assert_eq!(gw.issue(LINK, "a").await, Err(Error::NotAccepted));
        // Go reads `null` as a reply that names nothing: not accepted.
        let gw = Gateway::start().await;
        gw.status(&login_path(), 200, "null");
        assert_eq!(gw.issue(LINK, "a").await, Err(Error::NotAccepted));
    }

    // TestRepliesThatNameNothingAreIncomplete.
    #[tokio::test]
    async fn replies_that_name_nothing_are_incomplete() {
        let conferences = format!("/api/eventsessions/{SESSION}/conferences");
        for (path, status, body, call) in [
            (
                login_path(),
                200,
                r#"{"isAccepted":true,"user":{"sessionId":"x"}}"#,
                "guestlogin",
            ),
            (login_path(), 200, "not json", "guestlogin"),
            (
                conferences.clone(),
                201,
                r#"{"id":395296501,"publicKey":"vcPUBLIC"}"#,
                "conferences",
            ),
            (
                conferences.clone(),
                201,
                r#"{"id":0,"privateKey":"vcPRIVATE"}"#,
                "conferences",
            ),
            (
                conferences,
                201,
                r#"{"id":395296501,"privateKey":""}"#,
                "conferences",
            ),
            (join_token_path(), 200, r#"{"data":{}}"#, "join-token"),
            (
                join_token_path(),
                200,
                r#"{"data":{"joinToken":""}}"#,
                "join-token",
            ),
        ] {
            let gw = Gateway::start().await;
            gw.status(&path, status, body);
            assert_eq!(
                gw.issue(LINK, "a").await,
                Err(Error::IncompleteReply(call)),
                "{path}: {body}"
            );
        }
        // A login that sets no cookie made no guest.
        let gw = Gateway::start().await;
        gw.status(&login_path(), 200, REPLY_GUEST_LOGIN);
        assert_eq!(
            gw.issue(LINK, "a").await,
            Err(Error::IncompleteReply("guestlogin"))
        );
    }

    // TestAnUnexpectedStatusNamesTheCallAndTheNumberOnly: what the
    // service answers is never in an error: a body can carry a token.
    #[tokio::test]
    async fn an_unexpected_status_names_the_call_and_the_number_only() {
        let gw = Gateway::start().await;
        gw.status(
            &join_token_path(),
            500,
            r#"{"error":"boom","token":"vcSECRET00000000"}"#,
        );
        let err = gw.issue(LINK, "a").await.unwrap_err();
        assert_eq!(
            err,
            Error::BadStatus {
                call: "join-token",
                status: 500
            }
        );
        assert_eq!(
            err.to_string(),
            "join-token: mtslink: unexpected status 500"
        );
    }

    // TestAConferenceNothingWillJoinIsTakenBack: a conference stays in
    // the room's list until its publisher has been on the SFU and left,
    // or its guest takes it back. A flow that stops after making one
    // takes it back.
    #[tokio::test]
    async fn a_conference_nothing_will_join_is_taken_back() {
        let gw = Gateway::start().await;
        gw.status(&join_token_path(), 500, "{}");
        assert!(matches!(
            gw.issue(LINK, "a").await,
            Err(Error::BadStatus { .. })
        ));
        let calls = gw.calls();
        assert_eq!(
            calls.last().map(String::as_str),
            Some("DELETE /api/conferences/395296501"),
            "{calls:?}"
        );
        let seen = gw.stub.seen();
        assert_eq!(
            seen.last().unwrap().header("Cookie"),
            Some(LOGIN_COOKIES.join("; ").as_str())
        );
        // A flow that stops before the conference takes nothing back.
        let gw = Gateway::start().await;
        gw.status(
            &format!("/api/eventsessions/{SESSION}/conferences"),
            500,
            "{}",
        );
        gw.issue(LINK, "a").await.unwrap_err();
        assert_eq!(gw.calls().len(), 4);
    }

    // TestLeaveTakesTheConferenceBack.
    #[tokio::test]
    async fn leave_takes_the_conference_back() {
        let stub = Stub::start(|_| Reply::new(204, "")).await;
        let web = Web::default();
        bounded(leave(
            &web,
            &stub.base,
            "395296501",
            "access=a; sessionId=s",
        ))
        .await
        .unwrap();
        let seen = stub.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (
                seen[0].method.as_str(),
                seen[0].target.as_str(),
                seen[0].header("Cookie")
            ),
            (
                "DELETE",
                "/api/conferences/395296501",
                Some("access=a; sessionId=s")
            )
        );
        assert_eq!(
            bounded(leave(&web, &stub.base, "39/../5", "c")).await,
            Err(Error::ConferenceId),
            "a conference id that is not a number went into a path"
        );
        assert_eq!(stub.seen().len(), 1);
        // Another status than 204 is the call's error.
        let stub = Stub::start(|_| Reply::new(200, "{}")).await;
        assert_eq!(
            bounded(leave(&web, &stub.base, "1", "c")).await,
            Err(Error::BadStatus {
                call: "leave",
                status: 200
            })
        );
    }

    // TestIssuePassesTheLinksICEHintToTheEngine.
    #[tokio::test]
    async fn issue_passes_the_links_ice_hint_to_the_engine() {
        let gw = Gateway::start().await;
        let hinted = gw.issue(&format!("{LINK}?ice=tcp"), "a").await.unwrap();
        assert_eq!(hinted.ice, Some(Ice::Tcp));
        let plain = gw.issue(LINK, "a").await.unwrap();
        assert_eq!(plain.ice, None, "a plain link asks for no ICE mode");
        // The hint is no part of the room: the same calls either way.
        let calls = gw.calls();
        assert_eq!(calls[..5], calls[5..]);
    }

    // TestALinkWithoutAHintTakesTheCallersDefaultICE: the client side
    // asks for TCP, a server for nothing. A hint on the link wins, and a
    // default that names no mode is no default.
    #[tokio::test]
    async fn a_link_without_a_hint_takes_the_callers_default_ice() {
        let gw = Gateway::start().await;
        let udp_link = format!("{LINK}?ice=udp");
        let both_link = format!("{LINK}?ice=both");
        for (link, default, want) in [
            (LINK, "tcp", Some(Ice::Tcp)),
            (udp_link.as_str(), "tcp", Some(Ice::Udp)),
            (both_link.as_str(), "", Some(Ice::Both)),
            (LINK, "", None),
            (LINK, "sideways", None),
        ] {
            let creds = gw.issue_with(link, "a", default).await.unwrap();
            assert_eq!(creds.ice, want, "{link} with default {default:?}");
        }
    }

    // A link that is no event link is refused before anything is asked.
    #[tokio::test]
    async fn a_bad_link_asks_the_gateway_nothing() {
        let gw = Gateway::start().await;
        assert_eq!(
            gw.issue("https://my.mts-link.ru/events", "a").await,
            Err(Error::RoomRef)
        );
        assert!(gw.calls().is_empty());
    }

    // A gateway that cannot be reached is the call's error, and says
    // nothing of where it went.
    #[tokio::test]
    async fn a_gateway_that_is_not_there_names_the_call() {
        let closed = crate::testing::closed_port().await;
        let base = format!("http://127.0.0.1:{closed}");
        let err = bounded(issue(&Request {
            room_url: LINK,
            gateway: &base,
            ..Request::default()
        }))
        .await
        .unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, Error::Transport { call: "event", .. })
                && text.starts_with("mtslink: event: "),
            "{text}"
        );
        assert!(
            !text.contains(&closed.to_string()) && !text.contains(EVENT),
            "{text}"
        );
    }

    // What `issue` is handed is the room's link and the device's id:
    // neither is in what a log line would print of it (K6).
    #[test]
    fn a_request_shows_neither_the_room_nor_the_device() {
        let session_link = format!("{LINK}/session/{SESSION}?ice=udp");
        let req = Request {
            room_url: &session_link,
            name: "cap-a",
            default_ice: "tcp",
            gateway: "http://127.0.0.1:1",
            did: Some("33d131e5f5194d28"),
            ..Request::default()
        };
        let shown = format!("{req:?} {req:#?}");
        for secret in [
            OWNER,
            EVENT,
            SESSION,
            "my.mts-link.ru/j",
            "33d131e5f5194d28",
            "3d131e5f5194d283",
        ] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        // What a reader of the log needs is there.
        for told in ["Request", "cap-a", "tcp"] {
            assert!(shown.contains(told), "{told} not in {shown}");
        }
        // The empty request too.
        let shown = format!("{:?}", Request::default());
        assert!(shown.contains("Request"), "{shown}");
    }

    /// The conference's reply with `key` as its private key.
    fn conference_with(key: &str) -> String {
        REPLY_CONFERENCE.replace("vcPRIVATE0000000000000000000000000", key)
    }

    /// The join token's reply with `token`.
    fn join_token_with(token: &str) -> String {
        REPLY_JOIN_TOKEN.replace("vcJOIN000000000000000000000000000", token)
    }

    // A ticket is a few dozen bytes. One past 4 KiB is not a ticket: it
    // would go into the join URL three bytes a byte and stay for the
    // session's life.
    #[tokio::test]
    async fn a_ticket_over_four_kibibytes_is_no_reply() {
        let conferences = format!("/api/eventsessions/{SESSION}/conferences");
        assert_eq!(MAX_TICKET, 4096);
        let most = "k".repeat(4096);
        let over = "k".repeat(4097);

        // The longest one taken, both at once.
        let gw = Gateway::start().await;
        gw.status(&conferences, 201, &conference_with(&most));
        gw.status(&join_token_path(), 200, &join_token_with(&most));
        let creds = gw.issue(LINK, "a").await.unwrap();
        let q = query_of(&creds.url);
        assert_eq!(q["publishToken"], most);
        assert_eq!(q["joinToken"], most);

        let gw = Gateway::start().await;
        gw.status(&conferences, 201, &conference_with(&over));
        assert_eq!(
            gw.issue(LINK, "a").await,
            Err(Error::IncompleteReply("conferences"))
        );
        assert_eq!(gw.calls().len(), 4, "the flow went on after the conference");

        // A join token that is none ends as any failed join token does:
        // the conference is taken back.
        let gw = Gateway::start().await;
        gw.status(&join_token_path(), 200, &join_token_with(&over));
        assert_eq!(
            gw.issue(LINK, "a").await,
            Err(Error::IncompleteReply("join-token"))
        );
        let calls = gw.calls();
        assert_eq!(
            calls.last().map(String::as_str),
            Some("DELETE /api/conferences/395296501"),
            "{calls:?}"
        );

        // The bound is on the ticket's bytes, not on how the reply
        // spelled them: 4096 letters written as escapes are taken.
        let escaped = "\\u006b".repeat(4096);
        let gw = Gateway::start().await;
        gw.status(&join_token_path(), 200, &join_token_with(&escaped));
        let creds = gw.issue(LINK, "a").await.unwrap();
        assert_eq!(query_of(&creds.url)["joinToken"], most);
    }

    /// The login's reply setting the guest's cookies and one more, `pad`,
    /// that brings the `Cookie` value they make to `total` bytes.
    fn login_with_cookies_of(total: usize) -> Reply {
        let kept = LOGIN_COOKIES.join("; ");
        let pad = "p".repeat(total - kept.len() - "; pad=".len());
        LOGIN_COOKIES
            .iter()
            .map(|pair| (*pair).to_owned())
            .chain([format!("pad={pad}")])
            .fold(Reply::new(200, REPLY_GUEST_LOGIN), |reply, pair| {
                reply.header("Set-Cookie", &format!("{pair}; Path=/; Secure; HttpOnly"))
            })
    }

    // The guest's cookies are a few hundred bytes, sent back on every
    // call and held for the session's life. More than 8 KiB of them is
    // not a login.
    /// The worst the provider can issue is within what a session keeps.
    #[test]
    fn what_the_provider_issues_fits_what_a_session_keeps() {
        // Every byte of the nickname (256 at most in a refresh) and of the
        // two tickets escaped at three bytes.
        let url = room_join_url(
            &"s".repeat(253),
            &"9".repeat(20),
            &"9".repeat(20),
            &"%".repeat(256),
            &"%".repeat(MAX_TICKET),
            &"%".repeat(MAX_TICKET),
            "33d131e5f5194d28",
        );
        assert!(url.len() > 25 << 10, "{}", url.len());
        assert!(url.len() <= MAX_JOIN_URL, "{}", url.len());
        assert_eq!(MAX_JOIN_URL, 32 << 10);
        assert_eq!(CREDENTIALS_HELD, (32 << 10) + 8192 + 2048 + 3 * 64);
        let most = Credentials {
            url: Zeroizing::new(url),
            token: Zeroizing::new("c".repeat(MAX_COOKIES)),
            gateway: "g".repeat(MAX_GATEWAY),
            session_id: "9".repeat(MAX_ID),
            user_id: "9".repeat(MAX_ID),
            conference_id: "9".repeat(MAX_ID),
            ice: None,
        };
        assert!(most.fits());
        let over = Credentials {
            conference_id: "9".repeat(MAX_ID + 1),
            ..most
        };
        assert!(!over.fits());
    }

    #[tokio::test]
    async fn cookies_over_eight_kibibytes_are_no_login() {
        assert_eq!(MAX_COOKIES, 8192);
        let gw = Gateway::start().await;
        gw.answer(&login_path(), login_with_cookies_of(8192));
        let creds = gw.issue(LINK, "a").await.unwrap();
        assert_eq!(creds.token.len(), 8192);

        let gw = Gateway::start().await;
        gw.answer(&login_path(), login_with_cookies_of(8193));
        assert_eq!(
            gw.issue(LINK, "a").await,
            Err(Error::IncompleteReply("guestlogin"))
        );
        assert_eq!(
            gw.calls().len(),
            2,
            "the cookies were sent on to the next call"
        );
    }

    /// Whether `field` is of the type that zeroes its buffer when dropped.
    fn wiped_when_dropped<T: 'static>(_field: &T) -> bool {
        std::any::TypeId::of::<T>() == std::any::TypeId::of::<zeroize::Zeroizing<String>>()
    }

    // The join URL holds both tickets and the token is the cookies:
    // their bytes are zeroed when the credentials go, as `Config`'s and
    // `CarrierJoin`'s are.
    #[tokio::test]
    async fn the_join_url_and_the_cookies_are_wiped_when_dropped() {
        let gw = Gateway::start().await;
        let creds = gw.issue(LINK, "a").await.unwrap();
        assert!(wiped_when_dropped(&creds.url), "the join URL");
        assert!(wiped_when_dropped(&creds.token), "the cookies");
        // A copy is wiped by itself.
        let copy = creds.clone();
        assert!(wiped_when_dropped(&copy.url) && wiped_when_dropped(&copy.token));
        assert_eq!(copy, creds);
    }
}

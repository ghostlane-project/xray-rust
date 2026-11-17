// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SFU's signalling (`internal/engine/mtslink/signal.go`). MTS Link's
//! SFU ("odin" in its answers) speaks SDP over plain HTTP, measured by the
//! Go engine against the live service on 2026-10-11:
//!
//! ```text
//! POST {join}                      the offer in, the answer out
//! POST {origin}/rtc/peer/{id}/pin  {"streams":[""]}, the web client's call
//!                                  after every join; the peer is the
//!                                  answer's s= line
//! ```
//!
//! No WebSocket and no trickle: the answer carries the SFU's candidates
//! and the guest's reach it as peer-reflexive ones. The SFU authenticates
//! by the join's own tokens and reads no cookie, so the join and the pin
//! send none.
//!
//! The join URL holds both of the guest's tokens. It reaches no error and
//! no log: a call that fails says its name and the reason only.

use std::time::Duration;

use olc_net::http::{self, HttpError, HttpRequest, HttpResponse};
use olc_net::stream::{self, Offer};
use olc_net::{fetch, form, retry};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::gourl::Url;
use crate::{Error, HTTP_TIMEOUT, LEAVE_WAIT, REPLY_LIMIT};

/// How much of a refusal's body an error carries (`maxRefusalText`), in
/// bytes.
pub const MAX_REFUSAL_TEXT: usize = 200;
/// The body of the pin the web client sends after a join (`pinNothing`):
/// no stream held in a slot, the SFU fills them as it sees fit.
pub const PIN_NOTHING: &str = r#"{"streams":[""]}"#;
/// What the join asks the SFU to take from the published track, in the
/// service's own spelling (`publishCodec`).
pub const PUBLISH_CODEC: &str = "vp9";
/// What Go's `net/http` calls itself on HTTP/1.1 (`defaultUserAgent`).
pub const GO_USER_AGENT_HTTP1: &str = "Go-http-client/1.1";
/// What Go's `net/http` calls itself on HTTP/2 (`http2defaultUserAgent`).
pub const GO_USER_AGENT_H2: &str = "Go-http-client/2.0";

/// The `User-Agent` of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Agent<'a> {
    /// What the Go client at the pin sends. Its code names no sender on the
    /// join, the pin and the take-back, so `net/http` names itself, and by
    /// the protocol the call is spoken in: the client asks for HTTP/2
    /// (`ForceAttemptHTTP2`, `internal/protect/protect.go:98`), and says
    /// [`GO_USER_AGENT_H2`] where the server picks it and
    /// [`GO_USER_AGENT_HTTP1`] where it does not. The value is chosen once
    /// the connection says which, never before.
    #[default]
    Go,
    /// These words in either protocol; empty sends no `User-Agent`.
    Named(&'a str),
}

impl<'a> Agent<'a> {
    /// The `User-Agent` on a connection that speaks HTTP/2 (`h2`) or
    /// HTTP/1.1; empty for none.
    #[must_use]
    pub const fn on(self, h2: bool) -> &'a str {
        match self {
            Self::Go if h2 => GO_USER_AGENT_H2,
            Self::Go => GO_USER_AGENT_HTTP1,
            Self::Named(words) => words,
        }
    }
}

/// What a call to the SFU, and the engine's take-back at the gateway, say
/// about their sender. Go sends its own User-Agent, no `Origin` and no
/// `Referer`, and so does this by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sfu<'a> {
    /// The `User-Agent`.
    pub user_agent: Agent<'a>,
}

/// The three values that describe the offer.
const OFFER_KEYS: [&[u8]; 3] = [b"twcc", b"originMid", b"preferredPublishCodec"];

/// `offerURL`: the provider's room join with what describes the offer
/// added: the transport-wide congestion feedback the offer carries, the
/// m-line the SFU sends the room's audio on, and the codec of the
/// published track. The query comes back as `url.Values.Encode` writes it:
/// sorted by key, the three values replacing any the join had.
///
/// # Errors
/// [`Error::JoinUrl`] for a join without a scheme or a host.
pub fn offer_url(join: &str, audio_player_mid: &str) -> Result<String, Error> {
    let url = Url::parse(join).ok_or(Error::JoinUrl)?;
    let mut pairs = url.query();
    pairs.retain(|(key, _)| !OFFER_KEYS.contains(&key.as_slice()));
    pairs.push((b"twcc".to_vec(), b"true".to_vec()));
    pairs.push((b"originMid".to_vec(), audio_player_mid.into()));
    pairs.push((b"preferredPublishCodec".to_vec(), PUBLISH_CODEC.into()));
    Ok(url.string_with_query(&form::encode(&pairs)))
}

/// One request to `url`, written at most once, in the protocol the
/// connection speaks: the sender's User-Agent for that protocol, then
/// `rest`. The whole call, dials and waits included, ends within `limit`.
async fn send(
    call: &'static str,
    method: &'static str,
    url: &str,
    sfu: &Sfu<'_>,
    rest: &[(&str, &str)],
    body: &[u8],
    limit: Duration,
) -> Result<HttpResponse, Error> {
    // Go's `url.Error` says the method as `Post` or `Delete`; the URL is
    // left out (`redactURL`).
    let op = if method == "DELETE" { "Delete" } else { "Post" };
    let failed = |cause: &dyn std::fmt::Display| Error::Transport {
        call,
        cause: format!("{op}: {cause}"),
    };
    // `parse_url`'s error quotes the URL.
    let target = stream::parse_url(url).map_err(|_| failed(&"the URL names no http(s) host"))?;
    // `olc_net::retry::fetch` taken apart, for the one thing it cannot be
    // told: what to send once the protocol is known. Only the TCP dial is
    // tried again (D4).
    let exchange = async {
        let dialed = retry::dial_for(&target, Offer::Fetch).await?;
        let headers = headers(sfu, dialed.h2, rest);
        let req = HttpRequest {
            method,
            host: &target.authority,
            path: &target.path,
            headers: &headers,
            body,
            max_body: REPLY_LIMIT,
            timeout: limit,
        };
        if dialed.h2 {
            fetch::request_h2(dialed.stream, &req).await
        } else {
            let mut stream = dialed.stream;
            http::request(&mut stream, &req).await
        }
    };
    tokio::time::timeout(limit, exchange)
        .await
        .unwrap_or(Err(HttpError::Timeout))
        .map_err(|e| failed(&e))
}

/// The headers of a call on a connection that speaks HTTP/2 (`h2`) or
/// HTTP/1.1: the sender's User-Agent, then `rest`.
fn headers<'a>(sfu: &Sfu<'a>, h2: bool, rest: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let agent = sfu.user_agent.on(h2);
    let mut out = Vec::with_capacity(rest.len() + 1);
    if !agent.is_empty() {
        out.push(("User-Agent", agent));
    }
    out.extend_from_slice(rest);
    out
}

/// Where a request to the join URL goes: none for a URL that does not
/// parse or that names a user (a join carries no credentials of that
/// kind, and `olc_net` sends none).
fn request_url(join: &Url<'_>) -> Option<String> {
    if join.has_userinfo() {
        return None;
    }
    let mut out = join.origin_and_path();
    if !join.raw_query().is_empty() {
        out.push('?');
        out.push_str(join.raw_query());
    }
    Some(out)
}

/// `joinOffer`: POSTs the offer to `join_url` ([`offer_url`]'s result) and
/// returns the answer's SDP. What the SFU says when it refuses is cleared
/// of what the join URL holds ([`Held::of_join`]).
///
/// # Errors
/// [`Error::JoinRefused`] with the status and the first line of the SFU's
/// words for anything but 200; [`Error::NoAnswer`] for a 200 whose body is
/// no SDP; [`Error::Transport`] (`mtslink: join: Post: …`, without the
/// URL) when no reply came.
pub async fn join_offer(join_url: &str, offer: &str, sfu: &Sfu<'_>) -> Result<String, Error> {
    join_offer_holding(join_url, offer, sfu, &Held::of_join(join_url)).await
}

/// [`join_offer`] for a caller that holds more than the join URL: the
/// SFU's words are cleared of `held` (the URL's own values are the
/// caller's to put in it).
///
/// # Errors
/// As [`join_offer`].
pub async fn join_offer_holding(
    join_url: &str,
    offer: &str,
    sfu: &Sfu<'_>,
    held: &Held,
) -> Result<String, Error> {
    // The copy holds both tickets, as the URL does.
    let url = Url::parse(join_url)
        .and_then(|u| request_url(&u))
        .map(Zeroizing::new)
        .ok_or(Error::JoinUrl)?;
    let resp = send(
        "join",
        "POST",
        &url,
        sfu,
        &[("Content-Type", "application/sdp")],
        offer.as_bytes(),
        HTTP_TIMEOUT,
    )
    .await?;
    if resp.status != 200 {
        return Err(Error::JoinRefused {
            status: resp.status,
            text: String::from_utf8_lossy(&held.refusal(&resp.body)).into_owned(),
        });
    }
    match String::from_utf8(resp.body) {
        Ok(answer) if answer.starts_with("v=0") => Ok(answer),
        _ => Err(Error::NoAnswer),
    }
}

/// One character of `s` as Go's `utf8.DecodeRune` reads it: a byte that
/// starts no character is U+FFFD and one byte long.
fn decode_rune(s: &[u8]) -> (char, usize) {
    let head = &s[..s.len().min(4)];
    let valid = match std::str::from_utf8(head) {
        Ok(text) => text,
        // The longest valid prefix is valid.
        Err(e) => std::str::from_utf8(&head[..e.valid_up_to()]).unwrap_or(""),
    };
    valid
        .chars()
        .next()
        .map_or((char::REPLACEMENT_CHARACTER, 1), |c| (c, c.len_utf8()))
}

/// The character `s` ends with, as `utf8.DecodeLastRune` reads it.
fn decode_last_rune(s: &[u8]) -> (char, usize) {
    for len in 1..=s.len().min(4) {
        let tail = &s[s.len() - len..];
        if let Some(c) = std::str::from_utf8(tail)
            .ok()
            .and_then(|t| t.chars().next())
        {
            if c.len_utf8() == len {
                return (c, len);
            }
        }
    }
    (char::REPLACEMENT_CHARACTER, 1)
}

/// `strings.TrimSpace` on bytes that need not be UTF-8.
fn trim_space(mut s: &[u8]) -> &[u8] {
    while !s.is_empty() {
        let (c, len) = decode_rune(s);
        if !c.is_whitespace() {
            break;
        }
        s = &s[len..];
    }
    while !s.is_empty() {
        let (c, len) = decode_last_rune(s);
        if !c.is_whitespace() {
            break;
        }
        s = &s[..s.len() - len];
    }
    s
}

/// The first line of a refusal as [`refusal_text`] cleans it, made as it is
/// asked for: the body is trimmed and cut at its first line feed here, the
/// rest is walked only as far as the text needs.
struct Cleaner<'a> {
    rest: &'a [u8],
}

impl<'a> Cleaner<'a> {
    fn new(body: &'a [u8]) -> Self {
        let trimmed = trim_space(body);
        let line = trimmed
            .iter()
            .position(|&b| b == b'\n')
            .map_or(trimmed, |at| &trimmed[..at]);
        Self { rest: line }
    }

    /// Whether the line is walked to its end.
    const fn is_done(&self) -> bool {
        self.rest.is_empty()
    }

    /// Cleans on into `out` until it holds `upto` bytes or the line ends.
    /// A character is four bytes at most, so `out` ends under `upto + 4`.
    fn fill(&mut self, out: &mut Vec<u8>, upto: usize) {
        while !self.rest.is_empty() && out.len() < upto {
            let (c, len) = decode_rune(self.rest);
            self.rest = &self.rest[len..];
            if c >= ' ' && c != '\u{7f}' {
                out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
            }
        }
    }
}

/// `refusalText`: the first line of a refusal, bounded and printable. The
/// body is trimmed, cut at its first line feed, its control characters
/// (below U+0020, and U+007F) are removed, a byte that is no UTF-8 becomes
/// U+FFFD, and the result is cut at [`MAX_REFUSAL_TEXT`] bytes, which can
/// split a character: the bytes are Go's, and [`Error::JoinRefused`]
/// prints them lossily.
///
/// Only the first line is walked, and no more of it than the text holds.
///
/// The text can repeat what the request carried: an error is made from
/// [`Held::refusal`], never from this.
#[must_use]
pub fn refusal_text(body: &[u8]) -> Vec<u8> {
    let mut line = Cleaner::new(body);
    // A character is four bytes at most.
    let mut out = Vec::with_capacity(line.rest.len().min(MAX_REFUSAL_TEXT + 4));
    line.fill(&mut out, MAX_REFUSAL_TEXT);
    out.truncate(MAX_REFUSAL_TEXT);
    out
}

/// What stands in a refusal where the service repeated a value of the
/// request.
pub const SCRUBBED: &str = "…";
/// The shortest value taken out of a refusal, in bytes. The join's fixed
/// words (`true`, `rtc`, `room`, `join`) are shorter; an id, a ticket and a
/// cookie's value are longer.
pub const SCRUB_MIN: usize = 6;
/// The shortest end of a refusal that is taken out for being the start of
/// a longer value: a line that ends inside a ticket shows none of it.
const SCRUB_TAIL_MIN: usize = 4;
/// The most values a refusal is searched for: a join has seven in its
/// query and one in its path, a guest three cookies and three ids. Past
/// this the SFU's words are dropped whole ([`Held::refusal`]).
pub const MAX_HELD: usize = 64;

/// The values of a join that the service's words about it must not carry
/// into an error or a log (the Rust client's own rule: Go prints the
/// words as they came): the ids and tickets in the join URL's path and
/// query, and what the caller adds (the guest's cookies, the ids of the
/// session). A reply that quotes its request line, as a front end's 404
/// does, would otherwise put the guest's tickets into the debug log on
/// every failed attempt.
///
/// Each value is a copy, zeroed when this goes.
#[derive(Default)]
pub struct Held {
    /// Longest first: where two start at one place the longer one goes.
    values: Vec<Zeroizing<Vec<u8>>>,
    /// More values than [`MAX_HELD`] were offered.
    over: bool,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held")
            .field("values", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl Held {
    /// Nothing held: a refusal's text is [`refusal_text`]'s.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// What `join_url` holds: every part of its path and every value of
    /// its query, as written and with the escapes undone, less the three
    /// values that describe the offer ([`offer_url`]). Nothing for a URL
    /// that does not parse.
    #[must_use]
    pub fn of_join(join_url: &str) -> Self {
        let mut held = Self::default();
        let Some(url) = Url::parse(join_url) else {
            return held;
        };
        for part in url.raw_path().split('/') {
            held.add(part.as_bytes());
        }
        for part in url.path().split(|&b| b == b'/') {
            held.add(part);
        }
        for pair in url.raw_query().split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if !OFFER_KEYS.contains(&key.as_bytes()) {
                held.add(value.as_bytes());
            }
        }
        for (key, value) in url.query() {
            if !OFFER_KEYS.contains(&key.as_slice()) {
                held.add(&value);
            }
        }
        held
    }

    /// Holds `value` too, unless it is shorter than [`SCRUB_MIN`] or held
    /// already.
    pub fn add(&mut self, value: &[u8]) {
        if value.len() < SCRUB_MIN || self.values.iter().any(|v| v.as_slice() == value) {
            return;
        }
        if self.values.len() >= MAX_HELD {
            self.over = true;
            return;
        }
        let at = self.values.partition_point(|v| v.len() >= value.len());
        self.values.insert(at, Zeroizing::new(value.to_vec()));
    }

    /// Holds the value of every cookie of a `Cookie` header's value.
    pub fn add_cookies(&mut self, cookies: &str) {
        for pair in cookies.split(';') {
            let pair = pair.trim();
            self.add(
                pair.split_once('=')
                    .map_or(pair, |(_, value)| value)
                    .as_bytes(),
            );
        }
    }

    /// [`refusal_text`] of `body` with every held value in it replaced by
    /// [`SCRUBBED`], before the cut: a value the cut would have split is
    /// gone whole, and so is the start of one the line ends in. With
    /// nothing held in the line the bytes are [`refusal_text`]'s. When
    /// more values were offered than are searched for, the text is
    /// [`SCRUBBED`] alone.
    ///
    /// It holds the text, and of the line no more than twice the longest
    /// value at a time.
    #[must_use]
    pub fn refusal(&self, body: &[u8]) -> Vec<u8> {
        if self.over {
            return SCRUBBED.as_bytes().to_vec();
        }
        let Some(longest) = self.values.first().map(|v| v.len()) else {
            return refusal_text(body);
        };
        let mut line = Cleaner::new(body);
        // The line's cleaned bytes from `at` on: what the search looks at.
        let mut ahead: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        let mut at = 0;
        let mut out = Vec::with_capacity(MAX_REFUSAL_TEXT + 4);
        while out.len() < MAX_REFUSAL_TEXT {
            if ahead.len() - at < longest && !line.is_done() {
                ahead.drain(..at);
                at = 0;
                line.fill(&mut ahead, 2 * longest + 64);
            }
            let rest = &ahead[at..];
            let Some(&byte) = rest.first() else { break };
            if let Some(value) = self.values.iter().find(|v| rest.starts_with(v.as_slice())) {
                out.extend_from_slice(SCRUBBED.as_bytes());
                at += value.len();
                continue;
            }
            let cut_short = line.is_done()
                && rest.len() >= SCRUB_TAIL_MIN
                && self
                    .values
                    .iter()
                    .any(|v| v.len() > rest.len() && v.starts_with(rest));
            if cut_short {
                out.extend_from_slice(SCRUBBED.as_bytes());
                break;
            }
            out.push(byte);
            at += 1;
        }
        out.truncate(MAX_REFUSAL_TEXT);
        out
    }

    /// One line of `text` (a peer connection's or a transport's words,
    /// which can quote what they are about) with every held value
    /// replaced, bounded like a refusal.
    #[must_use]
    pub fn line(&self, text: &str) -> String {
        String::from_utf8_lossy(&self.refusal(text.as_bytes())).into_owned()
    }
}

/// `peerOf`: the peer an answer names, its session name (the `s=` line).
/// The id goes into a path, so one that could not be a path segment is
/// none. The first `s=` line decides.
#[must_use]
pub fn peer_of(answer: &str) -> Option<&str> {
    let id = answer
        .split('\n')
        .find_map(|line| line.trim().strip_prefix("s="))?;
    let unfit = id.is_empty() || id == "-" || id.contains(['/', '?', '#', '%', ' ', '\t']);
    (!unfit).then_some(id)
}

/// `pinPeer`: the pin the web client sends after a join, to the join's
/// own scheme and host and with no query. The media flows without it
/// (measured), so the caller treats a failure as a note, not as a join
/// that failed.
///
/// # Errors
/// [`Error::PinStatus`] for another status than 200; [`Error::Transport`]
/// (`mtslink: pin: Post: …`) when no reply came.
pub async fn pin_peer(join_url: &str, peer_id: &str, sfu: &Sfu<'_>) -> Result<(), Error> {
    let join = Url::parse(join_url)
        .filter(|u| !u.has_userinfo())
        .ok_or(Error::JoinUrl)?;
    let url = format!("{}://{}/rtc/peer/{peer_id}/pin", join.scheme, join.host);
    let resp = send(
        "pin",
        "POST",
        &url,
        sfu,
        &[("Content-Type", "application/json")],
        PIN_NOTHING.as_bytes(),
        HTTP_TIMEOUT,
    )
    .await?;
    if resp.status != 200 {
        return Err(Error::PinStatus(resp.status));
    }
    Ok(())
}

/// `takeBack`: removes the guest's conference from the room's list,
/// `DELETE {gateway}/api/conferences/{id}` with the guest's cookies (204,
/// measured). The service does it by itself for a publisher that was on
/// the SFU and left; a conference whose join never got there stays until
/// this is called. Any status is taken.
///
/// Nothing is sent, and nothing is wrong, without a gateway or with a
/// conference id that is not digits.
///
/// The call is given [`LEAVE_WAIT`], not a call's [`HTTP_TIMEOUT`]. Like
/// any future it ends when it is dropped: a join that may itself be
/// dropped asks through [`take_back_detached`].
///
/// # Errors
/// [`Error::Transport`] (`mtslink: leave: Delete: …`) when no reply came.
pub async fn take_back(
    gateway: &str,
    conference_id: &str,
    cookies: &str,
    sfu: &Sfu<'_>,
) -> Result<(), Error> {
    if !takes_back(gateway, conference_id) {
        return Ok(());
    }
    let url = format!("{gateway}/api/conferences/{conference_id}");
    let cookie = [("Cookie", cookies)];
    let sent = usize::from(!cookies.is_empty());
    send(
        "leave",
        "DELETE",
        &url,
        sfu,
        &cookie[..sent],
        b"",
        LEAVE_WAIT,
    )
    .await
    .map(|_| ())
}

/// The most one take-back holds while it runs, in bytes: its reply, and
/// the guest's cookies three times over (the task's copy, the request as
/// written, the values its failure's words are cleared of) with the
/// gateway and the conference id beside each.
pub const TAKE_BACK_HELD: usize =
    REPLY_LIMIT + 3 * (crate::auth::MAX_COOKIES + crate::auth::MAX_GATEWAY + crate::auth::MAX_ID);

/// Whether there is a conference to take back, and where.
fn takes_back(gateway: &str, conference_id: &str) -> bool {
    !gateway.is_empty()
        && !conference_id.is_empty()
        && conference_id.bytes().all(|b| b.is_ascii_digit())
}

/// `Session.leave` (`mtslink.go:499-516`): [`take_back`] on a task of its
/// own, so that it outlives the join that asks for it. The join's own end
/// may be the reason the conference is taken back (`context.WithoutCancel`
/// in Go): dropping the join's future, or the handle this returns, does
/// not stop the call. [`LEAVE_WAIT`] does.
///
/// Go's join waits for the call before it returns its error; awaiting the
/// handle does the same. The result is a note for the log.
///
/// The task holds its own copies of the three values and one exchange,
/// for [`LEAVE_WAIT`] at most; the cookies' copy is zeroed when it ends.
/// Nothing is copied or sent where [`take_back`] sends nothing.
///
/// # Panics
/// Outside a Tokio runtime.
pub fn take_back_detached(
    gateway: &str,
    conference_id: &str,
    cookies: &str,
    sfu: &Sfu<'_>,
) -> JoinHandle<Result<(), Error>> {
    if !takes_back(gateway, conference_id) {
        return tokio::spawn(async { Ok(()) });
    }
    let (gateway, conference_id) = (gateway.to_owned(), conference_id.to_owned());
    let cookies = Zeroizing::new(cookies.to_owned());
    let named = match sfu.user_agent {
        Agent::Go => None,
        Agent::Named(words) => Some(words.to_owned()),
    };
    tokio::spawn(async move {
        let sfu = Sfu {
            user_agent: named.as_deref().map_or(Agent::Go, Agent::Named),
        };
        take_back(&gateway, &conference_id, &cookies, &sfu).await
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use super::*;
    use crate::testing::{bounded, closed_port, Hung, Proto, Reply, Stub};

    pub(crate) const PEER: &str = "31djU82nnvUp1kyQjpDpPhyWx6eeoD1xs1SrH6HGSrPpwQyR8IgX3REL7";
    pub(crate) const COOKIES: &str =
        "access=eyJguest.access; refresh=6074c7a91c56; sessionId=529e1f7d";
    pub(crate) const CONFERENCE: &str = "395296501";
    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";

    /// The room join as the auth provider hands it over
    /// (`fakeSFU.joinURL`).
    pub(crate) fn join_url(base: &str) -> String {
        format!(
            "{base}/rtc/room/20300400600/join?userId=100200999&joinToken=vcJOIN&disableRecording=true\
             &userName=guest&publishToken=vcPRIVATE&did=33d131e5f5194d28&pid=3d131e5f5194d283"
        )
    }

    pub(crate) fn answer() -> String {
        format!("v=0\r\no=odin 0 0 IN IP4 127.0.0.1\r\ns={PEER}\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n")
    }

    // TestOfferURLAddsWhatDescribesTheOffer.
    #[test]
    fn the_offer_url_adds_what_describes_the_offer() {
        let got = offer_url(
            "https://sfu.mts-link.ru/rtc/room/20300400600/join?userId=1&joinToken=vcJ&userName=%D0%9C",
            "2",
        )
        .unwrap();
        assert_eq!(
            got,
            "https://sfu.mts-link.ru/rtc/room/20300400600/join?joinToken=vcJ&originMid=2\
             &preferredPublishCodec=vp9&twcc=true&userId=1&userName=%D0%9C"
        );
        assert_eq!(
            offer_url("://nothing", "2"),
            Err(Error::JoinUrl),
            "a join URL that does not parse was taken"
        );
        assert_eq!(
            Error::JoinUrl.to_string(),
            "mtslink: room join URL missing: the join URL does not parse"
        );
    }

    // TestPeerOfReadsTheSessionNameOfAnAnswer.
    #[test]
    fn the_peer_is_the_session_name_of_an_answer() {
        assert_eq!(peer_of(&answer()), Some(PEER));
        for sdp in [
            "v=0\r\no=odin 0 0\r\n",
            "v=0\r\ns=-\r\n",
            "v=0\r\ns=a/b\r\n",
            "v=0\r\ns=a b\r\n",
            "",
        ] {
            assert_eq!(peer_of(sdp), None, "{sdp:?}: a peer id goes into a path");
        }
    }

    // The join as the SFU sees it: the offer as the body, its type, the
    // sender Go's default, and nothing the gateway's calls carry.
    #[tokio::test]
    async fn the_join_posts_the_offer_and_returns_the_answer() {
        let sdp = answer();
        let stub = Stub::start(move |_| Reply::new(200, &sdp)).await;
        let url = offer_url(&join_url(&stub.base), "2").unwrap();
        let got = bounded(join_offer(&url, OFFER, &Sfu::default()))
            .await
            .unwrap();
        assert_eq!(got, answer());
        let seen = stub.seen();
        assert_eq!(seen.len(), 1, "a join is sent once");
        let join = &seen[0];
        assert_eq!(join.method, "POST");
        assert_eq!(
            join.target,
            "/rtc/room/20300400600/join?did=33d131e5f5194d28&disableRecording=true&joinToken=vcJOIN\
             &originMid=2&pid=3d131e5f5194d283&preferredPublishCodec=vp9&publishToken=vcPRIVATE\
             &twcc=true&userId=100200999&userName=guest"
        );
        assert_eq!(join.body, OFFER.as_bytes());
        assert_eq!(join.header("Content-Type"), Some("application/sdp"));
        assert_eq!(join.header("User-Agent"), Some(GO_USER_AGENT_HTTP1));
        for absent in ["Cookie", "Origin", "Referer", "Accept-Encoding"] {
            assert_eq!(join.header(absent), None, "{absent}: the SFU reads none");
        }
    }

    // The sender's name is the caller's to change, and to leave out: a
    // name given is sent as given in either protocol.
    #[tokio::test]
    async fn the_sfu_calls_carry_the_senders_user_agent() {
        for proto in [Proto::Plain, Proto::TlsH2] {
            let sdp = answer();
            let stub = Stub::start_as(proto, move |_| Reply::new(200, &sdp)).await;
            let url = offer_url(&join_url(&stub.base), "2").unwrap();
            let named = Sfu {
                user_agent: Agent::Named("agent/1"),
            };
            let silent = Sfu {
                user_agent: Agent::Named(""),
            };
            bounded(join_offer(&url, OFFER, &named)).await.unwrap();
            bounded(pin_peer(&url, PEER, &named)).await.unwrap();
            bounded(take_back(&stub.base, CONFERENCE, COOKIES, &named))
                .await
                .unwrap();
            bounded(take_back_detached(&stub.base, CONFERENCE, COOKIES, &named))
                .await
                .unwrap()
                .unwrap();
            bounded(join_offer(&url, OFFER, &silent)).await.unwrap();
            let agents: Vec<Option<String>> = stub
                .seen()
                .iter()
                .map(|s| s.header("User-Agent").map(str::to_owned))
                .collect();
            let named = Some("agent/1".to_owned());
            assert_eq!(
                agents,
                [named.clone(), named.clone(), named.clone(), named, None],
                "{proto:?}"
            );
        }
        // The default is Go's own name, whichever the protocol makes it.
        assert_eq!(Sfu::default().user_agent, Agent::Go);
        assert_eq!(Agent::Go.on(false), "Go-http-client/1.1");
        assert_eq!(Agent::Go.on(true), "Go-http-client/2.0");
    }

    // TestARefusedJoinSaysWhyAndTakesTheConferenceBack: the SFU's own
    // words, which name the rule the offer broke; and the conference
    // nothing will publish into is taken back with the guest's cookies.
    #[tokio::test]
    async fn a_refused_join_says_why_and_the_conference_is_taken_back() {
        let stub = Stub::start(|seen| {
            if seen.method == "DELETE" {
                Reply::new(204, "")
            } else {
                Reply::new(
                    400,
                    "SDP validation error: exceeded maximal audio players value 1",
                )
            }
        })
        .await;
        let url = offer_url(&join_url(&stub.base), "2").unwrap();
        let err = bounded(join_offer(&url, OFFER, &Sfu::default()))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "mtslink: the SFU refused the join: status 400: \
             SDP validation error: exceeded maximal audio players value 1"
        );
        assert!(matches!(err, Error::JoinRefused { status: 400, .. }));

        bounded(take_back(&stub.base, CONFERENCE, COOKIES, &Sfu::default()))
            .await
            .unwrap();
        let seen = stub.seen();
        let leaves: Vec<String> = seen
            .iter()
            .filter(|s| s.method == "DELETE")
            .map(|s| format!("DELETE {} | {}", s.target, s.header("Cookie").unwrap_or("")))
            .collect();
        assert_eq!(
            leaves,
            [format!("DELETE /api/conferences/{CONFERENCE} | {COOKIES}")],
            "the conference taken back with the guest's cookies"
        );
        let leave = seen.last().unwrap();
        for absent in ["Origin", "Referer", "Content-Type"] {
            assert_eq!(leave.header(absent), None, "{absent}");
        }
        assert_eq!(leave.header("User-Agent"), Some(GO_USER_AGENT_HTTP1));
    }

    // TestAnAnswerThatIsNotSDPIsRefused.
    #[tokio::test]
    async fn an_answer_that_is_not_sdp_is_refused() {
        let bodies: [&[u8]; 4] = [br#"{"error":"no room"}"#, b"", b"\xffv=0", b" v=0"];
        for body in bodies {
            let reply = body.to_vec();
            let stub = Stub::start(move |_| Reply::new(200, &reply)).await;
            let url = offer_url(&join_url(&stub.base), "2").unwrap();
            assert_eq!(
                bounded(join_offer(&url, OFFER, &Sfu::default())).await,
                Err(Error::NoAnswer),
                "{body:?}"
            );
        }
    }

    // The pin: the join's own host, the peer in the path, no query, the
    // web client's body, no cookie. (`TestSessionJoinsPublishesAndHears
    // TheRelay` holds the pin to this line; `TestARefusedPinDoesNotFail
    // TheJoin` needs a refusal to be an error the caller can drop.)
    #[tokio::test]
    async fn the_pin_goes_to_the_peer_without_the_joins_query() {
        let stub = Stub::start(|seen| {
            Reply::new(
                if seen.target.contains("refused") {
                    403
                } else {
                    200
                },
                "{}",
            )
        })
        .await;
        let url = offer_url(&join_url(&stub.base), "2").unwrap();
        bounded(pin_peer(&url, PEER, &Sfu::default()))
            .await
            .unwrap();
        let seen = stub.seen();
        let pins: Vec<String> = seen
            .iter()
            .map(|s| {
                format!(
                    "{} {} | {} | {} | {}",
                    s.method,
                    s.target,
                    String::from_utf8_lossy(&s.body),
                    s.header("Content-Type").unwrap_or(""),
                    s.header("Cookie").unwrap_or("")
                )
            })
            .collect();
        assert_eq!(
            pins,
            [format!(
                "POST /rtc/peer/{PEER}/pin | {{\"streams\":[\"\"]}} | application/json | "
            )]
        );
        let err = bounded(pin_peer(&url, "refused", &Sfu::default()))
            .await
            .unwrap_err();
        assert_eq!(err, Error::PinStatus(403));
        assert_eq!(err.to_string(), "mtslink: pin: status 403");
    }

    // The take-back needs a gateway and a conference that is a number,
    // and takes whatever the gateway answers.
    #[tokio::test]
    async fn the_take_back_is_sent_only_for_a_conference_and_takes_any_status() {
        let stub = Stub::start(|_| Reply::new(500, "boom")).await;
        let sfu = Sfu::default();
        for (gateway, conference) in [
            ("", CONFERENCE),
            (stub.base.as_str(), ""),
            (stub.base.as_str(), "39/../5"),
            (stub.base.as_str(), "12a"),
        ] {
            assert_eq!(
                bounded(take_back(gateway, conference, COOKIES, &sfu)).await,
                Ok(()),
                "{gateway:?} {conference:?}"
            );
        }
        assert!(stub.seen().is_empty(), "something was sent");
        assert_eq!(
            bounded(take_back(&stub.base, CONFERENCE, "", &sfu)).await,
            Ok(()),
            "a 500 failed the take-back"
        );
        let seen = stub.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].header("Cookie"), None, "an empty cookie was sent");
    }

    // The join URL holds both tokens: no error of a call says it.
    #[tokio::test]
    async fn the_join_url_is_in_no_error() {
        let port = closed_port().await;
        let base = format!("http://127.0.0.1:{port}");
        let url = offer_url(&join_url(&base), "2").unwrap();
        let sfu = Sfu::default();
        let join = bounded(join_offer(&url, OFFER, &sfu)).await.unwrap_err();
        let pin = bounded(pin_peer(&url, PEER, &sfu)).await.unwrap_err();
        let leave = bounded(take_back(&base, CONFERENCE, COOKIES, &sfu))
            .await
            .unwrap_err();
        let texts = [join.to_string(), pin.to_string(), leave.to_string()];
        for (text, start) in texts.iter().zip([
            "mtslink: join: Post: ",
            "mtslink: pin: Post: ",
            "mtslink: leave: Delete: ",
        ]) {
            assert!(text.starts_with(start), "{text}");
        }
        // Joins that cannot be sent at all: another scheme, a user in the
        // URL, no host.
        let odd = [
            bounded(join_offer(
                "ftp://sfu.example/join?joinToken=vcJOIN",
                OFFER,
                &sfu,
            ))
            .await
            .unwrap_err(),
            bounded(join_offer(
                "https://u:vcPRIVATE@sfu.example/join?joinToken=vcJOIN",
                OFFER,
                &sfu,
            ))
            .await
            .unwrap_err(),
            bounded(join_offer("/join?joinToken=vcJOIN", OFFER, &sfu))
                .await
                .unwrap_err(),
            bounded(pin_peer(
                "https://u:vcPRIVATE@sfu.example/join?joinToken=vcJOIN",
                PEER,
                &sfu,
            ))
            .await
            .unwrap_err(),
        ];
        let port = port.to_string();
        for text in texts
            .iter()
            .cloned()
            .chain(odd.iter().map(Error::to_string))
        {
            for secret in [
                "vcJOIN",
                "vcPRIVATE",
                "100200999",
                "33d131e5",
                "/rtc/room",
                "eyJguest",
                port.as_str(),
            ] {
                assert!(!text.contains(secret), "{secret} in {text:?}");
            }
        }
    }

    // A refusal's text is one line, printable and bounded, with Go's
    // reading of bytes that are no UTF-8 (K11).
    #[test]
    fn a_refusal_is_one_bounded_printable_line() {
        let long = "я".repeat(150);
        let cases: &[(&[u8], &[u8])] = &[
            (b"  first line\r\nsecond\n", b"first line"),
            (b"\n\n  first\nsecond", b"first"),
            (b"a\tb\x00c\x7fd\x1b[0m", b"abcd[0m"),
            (b"", b""),
            (b" \r\n\t ", b""),
            // Each byte that starts no character is one U+FFFD.
            (b"bad \xff byte", b"bad \xef\xbf\xbd byte"),
            (b"bad \xe4\xb8", b"bad \xef\xbf\xbd\xef\xbf\xbd"),
            // A no-break space is white space; a line separator is not a
            // line end.
            (b"\xc2\xa0first\xc2\xa0", b"first"),
            (b"a\xe2\x80\xa8b\nc", b"a\xe2\x80\xa8b"),
            // 300 bytes of two-byte letters: cut at 200 bytes.
            (long.as_bytes(), &long.as_bytes()[..200]),
        ];
        for &(body, want) in cases {
            assert_eq!(
                refusal_text(body),
                want,
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
        // The cut is in bytes and may split a character.
        let split = format!("a{long}");
        let got = refusal_text(split.as_bytes());
        assert_eq!(got.len(), 200);
        assert!(std::str::from_utf8(&got).is_err());
        // A megabyte of one line costs the text's size, not the body's.
        let huge = vec![b'x'; 1 << 20];
        let got = refusal_text(&huge);
        assert_eq!(got.len(), 200);
        assert!(got.capacity() <= 204, "{}", got.capacity());
    }

    /// What a refusal repeats of the request is taken out before the cut;
    /// with nothing of it in the line the bytes are Go's.
    #[test]
    fn a_refusal_is_cleared_of_what_the_join_holds() {
        let join = "https://sfu.example/rtc/room/20300400600/join?userId=100200999\
                    &joinToken=vcJOIN%2Fabc&disableRecording=true&userName=guest&twcc=true\
                    &originMid=abcdefgh";
        let mut held = Held::of_join(join);
        held.add_cookies(COOKIES);
        held.add(CONFERENCE.as_bytes());
        let long = "я".repeat(150);
        let untouched: [&[u8]; 6] = [
            b"SDP validation error: exceeded maximal audio players value 1",
            b"",
            b"  busy\r\nmore 100200999",
            b"bad \xff byte\x00",
            long.as_bytes(),
            // Not values of the join: its fixed words, the guest's name,
            // what describes the offer, the SFU's own name.
            b"twcc=true userName=guest originMid=abcdefgh at sfu.example /rtc/room/ /join",
        ];
        for body in untouched {
            assert_eq!(
                held.refusal(body),
                refusal_text(body),
                "{:?}",
                String::from_utf8_lossy(body)
            );
        }
        let said =
            |body: &str| String::from_utf8_lossy(&held.refusal(body.as_bytes())).into_owned();
        assert_eq!(
            said("no /rtc/room/20300400600/join for 100200999"),
            "no /rtc/room/…/join for …"
        );
        // As written and with the escape undone.
        assert_eq!(said("token vcJOIN%2Fabc or vcJOIN/abc"), "token … or …");
        assert_eq!(
            said("cookie eyJguest.access; refresh=6074c7a91c56; 529e1f7d of 395296501"),
            "cookie …; refresh=…; … of …"
        );
        // A value the cut would split is gone whole.
        let across = format!("{}100200999 and more", "x".repeat(195));
        assert_eq!(said(&across), format!("{}… a", "x".repeat(195)));
        assert_eq!(refusal_text(across.as_bytes())[195..], *b"10020");
        // A line that ends inside a value shows none of it; three bytes
        // are no value.
        assert_eq!(said("cut short: 10020"), "cut short: …");
        assert_eq!(said("cut short: 100"), "cut short: 100");
        // A text of nothing but values.
        let many = said(&"100200999".repeat(300));
        assert!(!many.contains('1') && many.starts_with("………"), "{many}");
        // A megabyte of one line costs the text and the search's window.
        let huge = vec![b'x'; 1 << 20];
        let got = held.refusal(&huge);
        assert_eq!(got.len(), 200);
        assert!(got.capacity() <= 204, "{}", got.capacity());
        let mut huge = b"100200999".repeat(100_000);
        huge.extend_from_slice(b" tail");
        assert_eq!(held.refusal(&huge).len(), 200);

        // Nothing held, and a URL that does not parse, change nothing.
        assert_eq!(Held::none().refusal(b"a 100200999\nb"), b"a 100200999");
        assert_eq!(Held::of_join("://nothing").refusal(b"x"), b"x");
        // It shows how many values it holds, never one of them.
        assert_eq!(format!("{held:?}"), "Held { values: 8, .. }");
        // More values than are searched for: the words are dropped whole.
        let mut over = Held::none();
        for i in 0..=MAX_HELD {
            over.add(format!("value-{i:04}").as_bytes());
        }
        assert_eq!(over.refusal(b"anything at all"), SCRUBBED.as_bytes());
        assert_eq!(over.line("value-0001"), SCRUBBED);
        // A value added twice is held once; a short one is not held.
        let mut once = Held::none();
        once.add(b"abcdef");
        once.add(b"abcdef");
        once.add(b"abcde");
        assert_eq!(format!("{once:?}"), "Held { values: 1, .. }");
    }

    /// The join's refusal is cleared of the join URL's values by
    /// `join_offer` itself.
    #[tokio::test]
    async fn a_refused_join_does_not_repeat_its_url() {
        let stub = Stub::start(|seen| {
            Reply::new(
                404,
                format!("The requested URL {} was not found", seen.target),
            )
        })
        .await;
        let url = offer_url(&join_url(&stub.base), "2").unwrap();
        let err = bounded(join_offer(&url, OFFER, &Sfu::default()))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "mtslink: the SFU refused the join: status 404: The requested URL /rtc/room/…/join\
             ?did=…&disableRecording=true&joinToken=…&originMid=2&pid=…\
             &preferredPublishCodec=vp9&publishToken=…&twcc=true&userId=…&userName=guest \
             was not found"
        );
    }

    // Go's code names no sender on these calls, so `net/http` names
    // itself, and by the protocol the call is spoken in: its client asks
    // for HTTP/2 (`ForceAttemptHTTP2`, `protect.go:98`) and says
    // `Go-http-client/2.0` there (`http2defaultUserAgent`), `/1.1` on
    // HTTP/1.1 (`defaultUserAgent`). The other pairings no Go client sends.
    #[tokio::test]
    async fn go_names_itself_by_the_protocol_a_call_is_spoken_in() {
        for (proto, want) in [
            (Proto::Plain, "Go-http-client/1.1"),
            (Proto::TlsHttp1, "Go-http-client/1.1"),
            (Proto::TlsH2, "Go-http-client/2.0"),
        ] {
            let sdp = answer();
            let stub = Stub::start_as(proto, move |seen| {
                if seen.method == "DELETE" {
                    Reply::new(204, "")
                } else {
                    Reply::new(200, &sdp)
                }
            })
            .await;
            let url = offer_url(&join_url(&stub.base), "2").unwrap();
            let sfu = Sfu::default();
            assert_eq!(
                bounded(join_offer(&url, OFFER, &sfu)).await,
                Ok(answer()),
                "{proto:?}"
            );
            assert_eq!(
                bounded(pin_peer(&url, PEER, &sfu)).await,
                Ok(()),
                "{proto:?}"
            );
            assert_eq!(
                bounded(take_back(&stub.base, CONFERENCE, COOKIES, &sfu)).await,
                Ok(()),
                "{proto:?}"
            );
            let seen = stub.seen();
            let calls: Vec<String> = seen
                .iter()
                .map(|s| {
                    format!(
                        "{} {} | {}",
                        s.method,
                        s.target.split('?').next().unwrap_or(""),
                        s.header("User-Agent").unwrap_or("<none>")
                    )
                })
                .collect();
            assert_eq!(
                calls,
                [
                    format!("POST /rtc/room/20300400600/join | {want}"),
                    format!("POST /rtc/peer/{PEER}/pin | {want}"),
                    format!("DELETE /api/conferences/{CONFERENCE} | {want}"),
                ],
                "{proto:?}"
            );
            // The calls are the same calls in either protocol.
            assert_eq!(seen[0].body, OFFER.as_bytes(), "{proto:?}");
            assert_eq!(
                seen[0].header("Content-Type"),
                Some("application/sdp"),
                "{proto:?}"
            );
            assert_eq!(seen[1].body, PIN_NOTHING.as_bytes(), "{proto:?}");
            assert_eq!(seen[2].header("Cookie"), Some(COOKIES), "{proto:?}");
        }
    }

    /// Whether `took` is `want`, give or take the timer's grain.
    fn about(took: Duration, want: Duration) -> bool {
        took >= want && took < want + Duration::from_millis(50)
    }

    // `leaveWait`: the take-back of a conference is given five seconds,
    // not the thirty of a call; the join and the pin keep theirs.
    #[tokio::test(start_paused = true)]
    async fn a_take_back_nobody_answers_is_given_five_seconds() {
        let hung = Hung::start().await;
        let sfu = Sfu::default();
        let began = tokio::time::Instant::now();
        let err = take_back(&hung.base, CONFERENCE, COOKIES, &sfu)
            .await
            .unwrap_err();
        let took = began.elapsed();
        assert!(about(took, Duration::from_secs(5)), "{took:?}: {err}");
        assert_eq!(err.to_string(), "mtslink: leave: Delete: timed out");
        assert_eq!(LEAVE_WAIT, Duration::from_secs(5));
        assert_eq!(HTTP_TIMEOUT, Duration::from_secs(30));

        let began = tokio::time::Instant::now();
        let handle = take_back_detached(&hung.base, CONFERENCE, COOKIES, &sfu);
        let err = handle.await.unwrap().unwrap_err();
        let took = began.elapsed();
        assert!(about(took, Duration::from_secs(5)), "{took:?}: {err}");
        assert_eq!(err.to_string(), "mtslink: leave: Delete: timed out");

        let url = offer_url(&join_url(&hung.base), "2").unwrap();
        let began = tokio::time::Instant::now();
        let err = join_offer(&url, OFFER, &sfu).await.unwrap_err();
        let took = began.elapsed();
        assert!(about(took, Duration::from_secs(30)), "{took:?}: {err}");
        assert_eq!(err.to_string(), "mtslink: join: Post: timed out");
    }

    // `Session.leave`: the join's own end may be why the conference is
    // taken back, so the call outlives the join that asked for it.
    #[tokio::test]
    async fn a_take_back_outlives_the_join_that_asked_for_it() {
        let stub = Stub::start(|_| Reply::new(204, "")).await;
        let base = stub.base.clone();
        // A join that asks for the take-back and is dropped at once, with
        // everything it borrowed.
        let join = async move {
            let (gateway, conference, cookies) = (base, CONFERENCE.to_owned(), COOKIES.to_owned());
            drop(take_back_detached(
                &gateway,
                &conference,
                &cookies,
                &Sfu::default(),
            ));
            std::future::pending::<()>().await;
        };
        assert!(
            tokio::time::timeout(Duration::ZERO, join).await.is_err(),
            "the join ended"
        );
        bounded(async {
            while stub.seen().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let seen = stub.seen();
        assert_eq!(
            format!(
                "{} {} | {}",
                seen[0].method,
                seen[0].target,
                seen[0].header("Cookie").unwrap_or("")
            ),
            format!("DELETE /api/conferences/{CONFERENCE} | {COOKIES}")
        );

        // What `take_back` does not send, this does not send either.
        let nothing = bounded(take_back_detached("", CONFERENCE, COOKIES, &Sfu::default()))
            .await
            .unwrap();
        assert_eq!(nothing, Ok(()));
        let ended = bounded(take_back_detached(
            &stub.base,
            CONFERENCE,
            "",
            &Sfu::default(),
        ))
        .await
        .unwrap();
        assert_eq!(ended, Ok(()));
        let seen = stub.seen();
        assert_eq!(seen.len(), 2, "one take-back for each one asked");
        assert_eq!(seen[1].header("Cookie"), None, "an empty cookie was sent");
    }
}

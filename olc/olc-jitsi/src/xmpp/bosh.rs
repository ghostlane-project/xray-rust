// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! BOSH (XEP-0124, XEP-0206) as the j library speaks it
//! (`J/internal/xmpp/conn.go:1168-1495`): the transport a join falls to when
//! the WebSocket does not dial and config.js names a BOSH URL.
//!
//! The requests are the library's, byte for byte (`jitsi/bosh.json` holds
//! the Go client's): a session request, then polls back to back, each
//! stanza in a request of its own, the stream's restart after the SASL
//! exchange, a terminate at the close. The request ids start below a
//! million and go up by one. Two requests are open at most: the poll, and
//! one other, which is answered before the next goes.
//!
//! Each request is a connection of its own ([`olc_net::fetch`], plan W3).
//!
//! Where this differs from the library, and why:
//!
//! - A poll's answer is waited for as long as the session's wait and
//!   [`POLL_MARGIN`]. The Go engine's HTTP client gives an answer's headers
//!   10 s, so it hangs up on a poll that a manager holds for the 60 s the
//!   session request asks for, and its transport closes
//!   (`TestGoJitsiFakeBOSHHeldPoll`).
//! - An answer is read as XML. The session ends on the body's own
//!   `type='terminate'` (the library looks for those words anywhere in the
//!   answer), and the stanzas are the body's child elements (the library
//!   counts `<` and `>`, and takes nothing out of an answer with a raw `>`
//!   inside an attribute value). An answer that is not a `<body>` ends the
//!   transport: what it held is lost, and nothing here can ask for it again.
//! - A request that fails ends the transport at once. The library leaves it
//!   open, and the hole in the request ids ends the session at the manager.
//! - Bounds the library does not have: an answer of [`REPLY_LIMIT`] at most;
//!   stanzas not yet read of [`INBOX_BYTES`] at most, past which the
//!   transport ends (the library stops its poll at 64 unread stanzas, and a
//!   stanza being sent then waits for that poll); and after a poll that came
//!   back empty at once the next waits for [`POLL_FLOOR`], unless another
//!   request went out since (the manager lets a poll go for it).
//! - The requests name the `User-Agent` this client names on config.js and
//!   on the WebSocket, where the library leaves Go's own; and no
//!   `Accept-Encoding`, because `olc-net` reads no coded answer.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_net::fetch::fetch;
use olc_net::http::HttpRequest;
use olc_net::stream::{parse_url, Target};
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

use super::conn::{wait_closed, BoxFut, ConnError, Framing, Rx, Tx};
use crate::configjs::BROWSER_USER_AGENT;
use crate::xml::{self, escape, XmlError};

/// The most of one answer that is read: the WebSocket's limit for a stanza.
pub const REPLY_LIMIT: usize = 1 << 20;
/// The most the stanzas taken out of answers and not yet read may hold.
pub const INBOX_BYTES: usize = 1 << 20;
/// The wait the session request asks for (`wait="60"`).
pub const WAIT: Duration = Duration::from_secs(60);
/// How much longer than the session's wait a poll's answer is waited for.
pub const POLL_MARGIN: Duration = Duration::from_secs(10);
/// How long any other request's answer is waited for (the Go HTTP client's
/// whole-request timeout).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the terminate's answer is waited for.
pub const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);
/// The least time between two polls when the first came back empty and no
/// other request went out since.
pub const POLL_FLOOR: Duration = Duration::from_secs(1);
/// The most of a server's answer that an error text quotes.
pub const QUOTE_MAX: usize = 512;
/// What a closed transport says (`conn.go:1298,1320`).
pub const CLOSED: &str = "bosh connection closed";
/// The requests' `Content-Type` (`conn.go:1229`).
pub const CONTENT_TYPE: &str = "text/xml; charset=utf-8";

const NS: &str = "http://jabber.org/protocol/httpbind";

// An answer's stanzas always fit an empty inbox.
const _: () = assert!(REPLY_LIMIT <= INBOX_BYTES);

/// The session request (`boshTransport.init`).
#[must_use]
pub fn create_body(rid: u64, xmpp_domain: &str) -> String {
    format!(
        r#"<body rid="{rid}" to="{}" xml:lang="en" wait="{}" hold="1" content="text/xml; charset=utf-8" ver="1.6" xmpp:version="1.0" xmlns="{NS}" xmlns:xmpp="urn:xmpp:xbosh"/>"#,
        escape(xmpp_domain),
        WAIT.as_secs()
    )
}

/// The poll (`pollLoop`).
#[must_use]
pub fn poll_body(rid: u64, sid: &str) -> String {
    format!(r#"<body rid="{rid}" sid="{}" xmlns="{NS}"/>"#, escape(sid))
}

/// One stanza (`Send`).
#[must_use]
pub fn send_body(rid: u64, sid: &str, stanza: &str) -> String {
    format!(
        r#"<body rid="{rid}" sid="{}" xmlns="{NS}">{stanza}</body>"#,
        escape(sid)
    )
}

/// The stream's restart after the SASL exchange (`authBOSH`).
#[must_use]
pub fn restart_body(rid: u64, sid: &str, xmpp_domain: &str) -> String {
    format!(
        r#"<body rid="{rid}" sid="{}" to="{}" xml:lang="en" xmpp:restart="true" xmlns="{NS}" xmlns:xmpp="urn:xmpp:xbosh"/>"#,
        escape(sid),
        escape(xmpp_domain)
    )
}

/// The end of the session (`Close`).
#[must_use]
pub fn terminate_body(rid: u64, sid: &str) -> String {
    format!(
        r#"<body rid="{rid}" sid="{}" type="terminate" xmlns="{NS}"/>"#,
        escape(sid)
    )
}

/// One answer, read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reply<'a> {
    /// The body's `sid`; empty when it has none.
    pub sid: String,
    /// The body's `wait`, in seconds.
    pub wait: Option<u64>,
    /// The body's own `type` is `terminate`: the manager ended the session.
    pub terminate: bool,
    /// The stanzas inside, each whole as it was written.
    pub stanzas: Vec<&'a str>,
}

/// Reads an answer by its `<body>` element.
///
/// # Errors
/// The text is not one well-formed `<body>` element.
pub fn parse_reply(text: &str) -> Result<Reply<'_>, XmlError> {
    let root = xml::root(text)?;
    if root.name != "body" {
        return Err(XmlError::Syntax("not a BOSH body"));
    }
    let attr = |n: &str| root.attr(n).ok().flatten();
    Ok(Reply {
        sid: attr("sid").map(Cow::into_owned).unwrap_or_default(),
        wait: attr("wait").and_then(|w| w.parse().ok()),
        terminate: attr("type").as_deref() == Some("terminate"),
        stanzas: xml::children(text)?,
    })
}

/// The first [`QUOTE_MAX`] bytes of a server's answer, for an error's text.
fn quote(text: &str) -> &str {
    if text.len() <= QUOTE_MAX {
        return text;
    }
    let mut end = QUOTE_MAX;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// One HTTP POST of a request body, answered with the answer's body.
pub trait Post: Send + Sync + 'static {
    /// Posts `body`; the whole exchange within `timeout`.
    ///
    /// The error is the request's failure, in the library's words where it
    /// has them (`bosh: HTTP <status>: <body>`).
    fn post(&self, body: String, timeout: Duration) -> BoxFut<'_, Result<String, String>>;
}

/// The POST over HTTP: a connection for each request, the answer read up to
/// [`REPLY_LIMIT`].
pub struct Http {
    target: Target,
}

impl Http {
    /// A poster to the BOSH URL config.js names.
    ///
    /// # Errors
    /// The URL is not one this client can dial.
    pub fn new(url: &str) -> Result<Self, String> {
        parse_url(url)
            .map(|target| Self { target })
            .map_err(|e| e.to_string())
    }
}

impl Post for Http {
    fn post(&self, body: String, timeout: Duration) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async move {
            let headers = [
                ("User-Agent", BROWSER_USER_AGENT),
                ("Content-Type", CONTENT_TYPE),
            ];
            let req = HttpRequest {
                method: "POST",
                host: &self.target.authority,
                path: &self.target.path,
                headers: &headers,
                body: body.as_bytes(),
                max_body: REPLY_LIMIT,
                timeout,
            };
            let resp = fetch(&self.target, &req).await.map_err(|e| e.to_string())?;
            if resp.status != 200 {
                let said = String::from_utf8_lossy(&resp.body);
                return Err(format!("bosh: HTTP {}: {}", resp.status, quote(&said)));
            }
            String::from_utf8(resp.body).map_err(|_| "bosh: an answer that is not UTF-8".to_owned())
        })
    }
}

#[derive(Default)]
struct Inbox {
    stanzas: VecDeque<String>,
    bytes: usize,
}

struct Inner {
    post: Arc<dyn Post>,
    domain: String,
    sid: String,
    /// How long a poll's answer is waited for.
    poll_wait: Duration,
    /// The last request id given out.
    rid: AtomicU64,
    /// One request besides the poll at a time (the library's mutex).
    turn: tokio::sync::Mutex<()>,
    /// How many requests besides the poll were ever started.
    started: AtomicU64,
    /// Wakes the poll loop out of its floor when a request starts.
    kick: Notify,
    inbox: Mutex<Inbox>,
    arrived: Notify,
    closed: watch::Sender<bool>,
    /// The manager ended the session: there is nothing left to terminate.
    ended: AtomicBool,
    /// The terminate was said.
    terminated: AtomicBool,
}

fn closed_error() -> ConnError {
    ConnError::Transport(CLOSED.into())
}

impl Inner {
    fn inbox(&self) -> MutexGuard<'_, Inbox> {
        self.inbox.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn next_rid(&self) -> u64 {
        self.rid.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Ends the transport: no request goes out after this but the terminate.
    fn shut(&self) {
        self.closed.send_replace(true);
        self.arrived.notify_one();
        self.kick.notify_one();
    }

    /// Takes an answer: its stanzas go to the inbox, and their number is the
    /// result. `None` when the answer ended the transport, or came after its
    /// end.
    fn take(&self, text: &str) -> Option<usize> {
        if self.is_closed() {
            return None;
        }
        let reply = match parse_reply(text) {
            Ok(r) => r,
            Err(e) => {
                olc_net::debug!("jitsi: bosh: {} bytes that are no answer ({e})", text.len());
                self.shut();
                return None;
            }
        };
        if reply.terminate {
            olc_net::debug!("jitsi: bosh: the server ended the session");
            self.ended.store(true, Ordering::Release);
            self.shut();
            return None;
        }
        let bytes: usize = reply.stanzas.iter().map(|s| s.len()).sum();
        {
            let mut inbox = self.inbox();
            if inbox.bytes + bytes > INBOX_BYTES {
                drop(inbox);
                olc_net::debug!("jitsi: bosh: more than {INBOX_BYTES} bytes of stanzas unread");
                self.shut();
                return None;
            }
            inbox.bytes += bytes;
            inbox
                .stanzas
                .extend(reply.stanzas.iter().map(|s| (*s).to_owned()));
        }
        if !reply.stanzas.is_empty() {
            self.arrived.notify_one();
        }
        Some(reply.stanzas.len())
    }

    /// One request besides the poll (`Send`, and the restart): alone among
    /// its kind, and answered before the next goes. Its id is taken when its
    /// turn comes.
    async fn request(&self, body: impl FnOnce(u64) -> String) -> Result<(), ConnError> {
        if self.is_closed() {
            return Err(closed_error());
        }
        self.started.fetch_add(1, Ordering::AcqRel);
        self.kick.notify_one();
        let mut closed = self.closed.subscribe();
        let exchange = async {
            let _turn = self.turn.lock().await;
            if self.is_closed() {
                return Err(closed_error());
            }
            let body = body(self.next_rid());
            match self.post.post(body, REQUEST_TIMEOUT).await {
                Ok(text) => self.take(&text).map(|_| ()).ok_or_else(closed_error),
                Err(e) => {
                    self.shut();
                    Err(ConnError::Transport(e))
                }
            }
        };
        tokio::select! {
            biased;
            r = exchange => r,
            () = wait_closed(&mut closed) => Err(closed_error()),
        }
    }

    /// `Close`: the transport ends, and the manager is told so once, unless
    /// it was the manager that ended the session.
    async fn close(&self) {
        self.shut();
        if self.ended.load(Ordering::Acquire) || self.terminated.swap(true, Ordering::AcqRel) {
            return;
        }
        // After the request that is out, as the library's lock orders it;
        // the transport's end has let that one go.
        let _turn = self.turn.lock().await;
        let body = terminate_body(self.next_rid(), &self.sid);
        if let Err(e) = self.post.post(body, TERMINATE_TIMEOUT).await {
            olc_net::debug!("jitsi: bosh: terminate: {e}");
        }
    }
}

/// `pollLoop`: a poll is out whenever the transport lives, the next as soon
/// as the last is answered.
async fn poll_loop(inner: Arc<Inner>) {
    let mut closed = inner.closed.subscribe();
    // The requests besides the poll that an empty answer was already put
    // down to.
    let mut seen = 0;
    loop {
        if inner.is_closed() {
            return;
        }
        let started = Instant::now();
        let body = poll_body(inner.next_rid(), &inner.sid);
        let answer = tokio::select! {
            biased;
            () = wait_closed(&mut closed) => return,
            a = inner.post.post(body, inner.poll_wait) => a,
        };
        let taken = match answer {
            Ok(text) => match inner.take(&text) {
                Some(n) => n,
                None => return,
            },
            Err(e) => {
                olc_net::debug!("jitsi: bosh: poll: {e}");
                inner.shut();
                return;
            }
        };
        if taken > 0 {
            continue;
        }
        // An empty answer before the floor: a manager that holds nothing, or
        // one that let this poll go for another request. Only the second is
        // a reason to ask again at once (XEP-0124, section 12), and it is
        // one whether or not that request is still out: its answer may have
        // been read before this poll's, and with no poll out what the
        // manager says next would wait for the floor. A request is that
        // reason once: while it stays out, a manager that holds nothing is
        // still asked once a floor.
        let floor = started + POLL_FLOOR;
        loop {
            let others = inner.started.load(Ordering::Acquire);
            if others != seen {
                seen = others;
                break;
            }
            if Instant::now() >= floor {
                break;
            }
            tokio::select! {
                () = wait_closed(&mut closed) => return,
                () = tokio::time::sleep_until(floor) => {}
                () = inner.kick.notified() => {}
            }
        }
    }
}

/// The sending half of a BOSH session.
pub struct BoshTx(Arc<Inner>);

/// The receiving half: the stanzas taken out of the answers, in order.
pub struct BoshRx(Arc<Inner>);

impl std::fmt::Debug for BoshTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshTx")
            .field("closed", &self.0.is_closed())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for BoshRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoshRx")
            .field("closed", &self.0.is_closed())
            .finish_non_exhaustive()
    }
}

/// Opens a session (`dialBOSH` up to the login): the session request, whose
/// answer gives the session id and the stream's features, and the poll loop.
///
/// # Errors
/// The library's: `bosh init: <the request's failure>`, or
/// `bosh init: no sid in response: <the answer>` (its first [`QUOTE_MAX`]
/// bytes).
pub async fn open(post: Arc<dyn Post>, xmpp_domain: &str) -> Result<(BoshTx, BoshRx), ConnError> {
    // The library starts from `UnixNano() % 1000000`.
    let rid = u64::from(rand::random::<u32>() % 1_000_000) + 1;
    let text = post
        .post(create_body(rid, xmpp_domain), REQUEST_TIMEOUT)
        .await
        .map_err(|e| ConnError::Transport(format!("bosh init: {e}")))?;
    let no_sid =
        || ConnError::Transport(format!("bosh init: no sid in response: {}", quote(&text)));
    let reply = parse_reply(&text).map_err(|_| no_sid())?;
    if reply.sid.is_empty() {
        return Err(no_sid());
    }
    if reply.terminate {
        return Err(ConnError::Transport(format!(
            "bosh init: session ended: {}",
            quote(&text)
        )));
    }
    // The manager may hold a poll for less than was asked, never for more.
    let wait = reply
        .wait
        .filter(|w| (1..=WAIT.as_secs()).contains(w))
        .map_or(WAIT, Duration::from_secs);
    let inner = Arc::new(Inner {
        post,
        domain: xmpp_domain.to_owned(),
        sid: reply.sid,
        poll_wait: wait + POLL_MARGIN,
        rid: AtomicU64::new(rid),
        turn: tokio::sync::Mutex::new(()),
        started: AtomicU64::new(0),
        kick: Notify::new(),
        inbox: Mutex::new(Inbox::default()),
        arrived: Notify::new(),
        closed: watch::channel(false).0,
        ended: AtomicBool::new(false),
        terminated: AtomicBool::new(false),
    });
    inner.take(&text);
    tokio::spawn(poll_loop(inner.clone()));
    Ok((BoshTx(inner.clone()), BoshRx(inner)))
}

impl Tx for BoshTx {
    fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), ConnError>> {
        Box::pin(self.0.request(move |rid| send_body(rid, &self.0.sid, text)))
    }

    fn close(&self) -> BoxFut<'_, ()> {
        Box::pin(self.0.close())
    }

    fn framing(&self) -> Framing {
        Framing::Bosh
    }

    fn restart(&self) -> BoxFut<'_, Result<(), ConnError>> {
        Box::pin(
            self.0
                .request(|rid| restart_body(rid, &self.0.sid, &self.0.domain)),
        )
    }
}

impl Rx for BoshRx {
    fn recv(&mut self) -> BoxFut<'_, Result<String, ConnError>> {
        Box::pin(async move {
            loop {
                {
                    let mut inbox = self.0.inbox();
                    if let Some(s) = inbox.stanzas.pop_front() {
                        inbox.bytes -= s.len();
                        return Ok(s);
                    }
                }
                if self.0.is_closed() {
                    return Err(closed_error());
                }
                self.0.arrived.notified().await;
            }
        })
    }
}

impl Drop for BoshRx {
    /// Nobody reads any more: nothing more is asked for.
    fn drop(&mut self) {
        self.0.shut();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stanza;
    use crate::xml;
    use crate::xmpp::conn::{Conn, ConnConfig, Incoming};
    use crate::xmpp::testing::{BoshServer, BOSH_SID, BOSH_SPIN};
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    const S: fn(u64) -> Duration = Duration::from_secs;
    const NS: &str = "http://jabber.org/protocol/httpbind";

    fn cfg() -> ConnConfig {
        ConnConfig {
            host: "web.example".into(),
            room: "secret-room".into(),
            xmpp_domain: "meet.jitsi".into(),
            muc_domain: "muc.meet.jitsi".into(),
        }
    }

    /// A connection logged in over BOSH on `server`.
    async fn up(server: &BoshServer) -> (Conn, mpsc::Receiver<Incoming>, Arc<BoshTx>) {
        let (tx, rx) = open(Arc::new(server.clone()), "meet.jitsi").await.unwrap();
        let tx = Arc::new(tx);
        let (conn, incoming) = Conn::login(tx.clone(), rx, cfg(), S(30)).await.unwrap();
        (conn, incoming, tx)
    }

    /// Lets the tasks run.
    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
    }

    /// Waits, five seconds of the test's clock at most, for `cond`.
    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("waited five seconds for {what}");
    }

    /// An IQ set from the focus, which a client acknowledges.
    fn set(id: &str) -> String {
        format!("<iq type='set' id='{id}' from='f@auth.meet.jitsi/focus' xmlns='jabber:client'><q xmlns='urn:x'/></iq>")
    }

    /// The `(id, to)` of every IQ result among `said`, but `end`'s.
    fn acks(said: &[String], end: &str) -> Vec<(String, String)> {
        said.iter()
            .filter_map(|s| {
                let r = xml::root(s).ok()?;
                let a = |n: &str| r.attr(n).ok().flatten().unwrap_or_default().into_owned();
                (r.name == "iq" && a("type") == "result" && a("id") != end)
                    .then(|| (a("id"), a("to")))
            })
            .collect()
    }

    fn acked(server: &BoshServer, id: &str) -> bool {
        let want = format!("id=\"{id}\"");
        server.state().said.iter().any(|s| s.contains(&want))
    }

    fn strings(v: &serde_json::Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    }

    /// Every body the Go client posts, byte for byte, with the request id
    /// and the session id put in (`jitsi/bosh.json`).
    #[test]
    fn the_bodies_are_the_go_client_s() {
        let v = olc_interop::load("jitsi/bosh.json");
        let put = |s: &serde_json::Value| {
            s.as_str()
                .unwrap()
                .replacen("rid=\"RID\"", "rid=\"4242\"", 1)
                .replacen("sid=\"SID\"", "sid=\"s-1\"", 1)
        };
        assert_eq!(create_body(4242, "meet.jitsi"), put(&v["create"]));
        assert_eq!(poll_body(4242, "s-1"), put(&v["poll"]));
        assert_eq!(restart_body(4242, "s-1", "meet.jitsi"), put(&v["restart"]));
        assert_eq!(terminate_body(4242, "s-1"), put(&v["terminate"]));
        let (login, stanzas) = (strings(&v["login"]), strings(&v["stanzas"]));
        assert_eq!(login.len(), 7);
        assert_eq!(stanzas.len(), 7);
        for (body, stanza) in v["login"].as_array().unwrap().iter().zip(&stanzas) {
            assert_eq!(send_body(4242, "s-1", stanza), put(body));
        }
        // What stands in them is what this crate writes for the WebSocket.
        assert_eq!(stanzas[0], stanza::AUTH_ANONYMOUS);
        assert_eq!(stanzas[1], stanza::BIND);
        assert_eq!(stanzas[2], stanza::SESSION);
        assert_eq!(
            send_body(
                4242,
                "s-1",
                &stanza::leave("secret-room@muc.meet.jitsi/fedcba98")
            ),
            put(&v["leave"])
        );
        assert_eq!(
            send_body(
                4242,
                "s-1",
                &stanza::disco_result("secret-room@muc.meet.jitsi/focus", "disco-1")
            ),
            put(&v["disco_reply"])
        );
        assert_eq!(v["header"]["Content-Type"][0], CONTENT_TYPE);
    }

    /// An answer is read by its `<body>`: the session id, the wait, and the
    /// end of the session, which is the body's own `type` and not those
    /// words anywhere in the answer (decision D3; `conn.go:1287` looks for
    /// the text).
    #[test]
    fn an_answer_is_read_by_its_body() {
        let r = parse_reply(&format!(
            "<body xmlns='{NS}' sid='abc' wait='45' authid='zzz'><a/><b>t</b></body>"
        ))
        .map(|r| (r.sid, r.wait, r.terminate, r.stanzas.concat()));
        assert_eq!(
            r,
            Ok(("abc".into(), Some(45), false, "<a/><b>t</b>".into()))
        );
        let text = format!("<body xmlns='{NS}' sid='abc'/>");
        let r = parse_reply(&text).unwrap();
        assert_eq!((r.sid.as_str(), r.wait, r.stanzas.len()), ("abc", None, 0));
        assert!(
            parse_reply("<body type='terminate' condition='item-not-found'/>")
                .unwrap()
                .terminate
        );
        assert!(
            parse_reply(r#"<body type="terminate"/>"#)
                .unwrap()
                .terminate
        );
        let text = r#"<body><iq type="terminate"/><x>type='terminate'</x></body>"#;
        let r = parse_reply(text).unwrap();
        assert!(!r.terminate, "the words inside a stanza end nothing");
        assert_eq!(r.stanzas.len(), 2);
        // What is not a BOSH body is not read as one.
        assert!(parse_reply("<html><body>busy</body></html>").is_err());
        assert!(parse_reply("<body><iq></body>").is_err());
        assert!(parse_reply("busy").is_err());
        assert!(parse_reply("").is_err());
    }

    /// The stanzas the Go client took out of each answer of the vector (its
    /// acknowledgements say which), and the one answer it loses whole.
    #[test]
    fn an_answer_is_split_as_go_splits_it_but_where_go_loses_it() {
        let v = olc_interop::load("jitsi/bosh.json");
        let rows = v["split"].as_array().unwrap();
        assert_eq!(rows.len(), 11);
        let mut lost = 0;
        for row in rows {
            let reply = row["reply"].as_str().unwrap();
            let parsed = parse_reply(reply).unwrap();
            let ids: Vec<String> = parsed
                .stanzas
                .iter()
                .filter_map(|s| {
                    let r = xml::root(s).unwrap();
                    (r.name == "iq").then(|| r.attr("id").unwrap().unwrap().into_owned())
                })
                .collect();
            let go = strings(&row["acked"]);
            if row["name"] == "a tag end written raw in a value" {
                assert!(go.is_empty(), "Go takes nothing out of {reply}");
                assert_eq!(ids, ["g1", "g2"]);
                lost += 1;
            } else {
                assert_eq!(ids, go, "{}", row["name"]);
            }
        }
        assert_eq!(lost, 1);
    }

    /// The whole join over BOSH: every request but the polls is the Go
    /// client's, in its order; the ids go up by one; no stream is opened and
    /// no stream management asked for; never more than two requests open;
    /// and no step waits for a clock.
    #[tokio::test(start_paused = true)]
    async fn the_join_s_requests_are_the_go_client_s_in_their_order() {
        let v = olc_interop::load("jitsi/bosh.json");
        let server = BoshServer::new();
        let started = Instant::now();
        let (conn, _incoming, _tx) = up(&server).await;
        conn.allocate_focus(S(10)).await.unwrap();
        conn.discover_services(S(10)).await.unwrap();
        conn.join_muc("olcrtc", S(10)).await.unwrap();
        assert!(started.elapsed() < POLL_FLOOR, "{:?}", started.elapsed());
        assert_eq!(conn.nick(), v["nick"].as_str().unwrap());
        let poll = v["poll"].as_str().unwrap();
        let (bodies, consecutive) = server.normalised();
        let ours: Vec<&str> = bodies
            .iter()
            .map(String::as_str)
            .filter(|b| *b != poll)
            .collect();
        assert_eq!(ours, strings(&v["sequence"]));
        assert!(consecutive, "the request ids go up by one");
        assert!(bodies.iter().any(|b| b == poll), "a poll is out");
        for never in ["<open ", "<enable ", "<r "] {
            assert!(!bodies.iter().any(|b| b.contains(never)), "{never}");
        }
        assert!(v["max_in_flight"].as_u64().unwrap() <= 2);
        assert!(server.state().max_open <= 2, "{}", server.state().max_open);
        let first: u64 = xml::root(&server.state().bodies[0])
            .unwrap()
            .attr("rid")
            .unwrap()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=1_000_000).contains(&first), "{first}");

        conn.leave_muc_wait(S(10)).await.unwrap();
        conn.close().await;
        let (bodies, consecutive) = server.normalised();
        assert!(consecutive);
        assert_eq!(bodies[bodies.len() - 1], v["terminate"].as_str().unwrap());
        assert!(bodies.iter().any(|b| b == v["leave"].as_str().unwrap()));
        assert!(server.state().terminated);
        assert!(server.state().max_open <= 2);
    }

    /// The vector's answers, given to a live connection as they were given
    /// to the Go client: it acknowledges the IQ sets Go acknowledged, to
    /// whom Go did; and both of the answer Go loses.
    #[tokio::test(start_paused = true)]
    async fn an_answer_s_stanzas_reach_the_connection_as_they_reach_go_s() {
        let v = olc_interop::load("jitsi/bosh.json");
        let server = BoshServer::new();
        let (_conn, _incoming, _tx) = up(&server).await;
        for (i, row) in v["split"].as_array().unwrap().iter().enumerate() {
            let from = server.state().said.len();
            let end = format!("end-{i}");
            server.say_whole(&row["reply"].as_str().unwrap().replace("SID", BOSH_SID));
            server.say(&set(&end));
            wait_for("the acknowledgement that closes the row", || {
                acked(&server, &end)
            })
            .await;
            let got = acks(&server.state().said[from..], &end);
            let ids: Vec<&str> = got.iter().map(|(id, _)| id.as_str()).collect();
            let go = strings(&row["acked"]);
            if row["name"] == "a tag end written raw in a value" {
                assert!(go.is_empty());
                assert_eq!(ids, ["g1", "g2"]);
            } else {
                assert_eq!(ids, go, "{}", row["name"]);
                let to: Vec<&str> = got.iter().map(|(_, to)| to.as_str()).collect();
                assert_eq!(to, strings(&row["acked_to"]), "{}", row["name"]);
            }
        }
    }

    /// A manager that holds a poll for the whole wait the session request
    /// asked for, as Prosody does: the session lives, one poll a minute. The
    /// Go client hangs up on such a poll after 10 s
    /// (`TestGoJitsiFakeBOSHHeldPoll`).
    #[tokio::test(start_paused = true)]
    async fn a_poll_held_for_the_whole_wait_keeps_the_session() {
        let server = BoshServer::new();
        assert_eq!(server.state().hold, WAIT);
        let (conn, _incoming, _tx) = up(&server).await;
        // The first poll goes out once the login's task lets the loop run.
        settle().await;
        let before = server.state().bodies.len();
        assert_eq!(
            server.normalised().0[before - 1],
            format!(r#"<body rid="RID" sid="SID" xmlns="{NS}"/>"#),
            "a poll is out"
        );
        tokio::time::sleep(S(185)).await;
        assert!(!conn.is_closed());
        assert_eq!(server.state().bodies.len() - before, 3, "a poll a minute");
        assert!(server.normalised().1);
        server.say(&set("late"));
        wait_for("the acknowledgement of a late stanza", || {
            acked(&server, "late")
        })
        .await;
    }

    /// A poll nobody answers ends the transport once the wait and its margin
    /// are over, and the connection with it.
    #[tokio::test(start_paused = true)]
    async fn a_poll_never_answered_ends_the_transport_after_the_wait_and_its_margin() {
        let server = BoshServer::new();
        server.state().mute = true;
        let (conn, _incoming, tx) = up(&server).await;
        tokio::time::sleep(WAIT + POLL_MARGIN - S(1)).await;
        assert!(!conn.is_closed());
        tokio::time::sleep(S(2)).await;
        settle().await;
        assert!(conn.is_closed());
        assert_eq!(
            tx.send("<message/>").await,
            Err(ConnError::Transport(CLOSED.into()))
        );
    }

    /// A manager that answers every poll at once with nothing is asked once
    /// a floor, not in a spin (Go's loop has no such bound); and a stanza
    /// sent meanwhile does not wait for the floor.
    #[tokio::test(start_paused = true)]
    async fn empty_answers_at_once_are_paced_and_a_send_is_not() {
        let server = BoshServer::new();
        let (conn, _incoming, _tx) = up(&server).await;
        // The first poll is out and held before the manager changes.
        settle().await;
        server.state().at_once = true;
        let before = server.state().bodies.len();
        // The poll that is out comes back at the wait; from there on every
        // poll is answered at once.
        tokio::time::sleep(WAIT + S(30) + Duration::from_millis(500)).await;
        let polls = server.state().bodies.len() - before;
        assert!(polls < BOSH_SPIN, "the client spins");
        assert!((29..=32).contains(&polls), "{polls} polls in 30 s");
        assert!(!conn.is_closed());
        // The poll loop is waiting for its floor now. A manager that holds
        // again answers a stanza only when the next poll arrives.
        server.state().at_once = false;
        let t = Instant::now();
        conn.send("<message to='x'/>").await.unwrap();
        assert!(
            t.elapsed() < Duration::from_millis(100),
            "{:?}",
            t.elapsed()
        );
    }

    /// The manager lets a poll go, empty, for a stanza's request, and what it
    /// says next comes back on that request. Whichever of the two answers the
    /// client reads first, the next poll is out at once: with none out, what
    /// the manager says after that would wait for the floor (the gate's S0
    /// over BOSH: a tunnel ready in 0.2 s in one run and in 2.2 s in the next).
    #[tokio::test(start_paused = true)]
    async fn a_poll_let_go_for_a_stanza_is_followed_by_the_next_at_once() {
        let server = BoshServer::new();
        let (conn, _incoming, _tx) = up(&server).await;
        // The first poll is out and held, and young: its floor is ahead.
        settle().await;
        let before = server.state().bodies.len();
        let t = Instant::now();
        server.state().late = Some(
            "<presence from='secret-room@muc.meet.jitsi/other' xmlns='jabber:client'/>".into(),
        );
        // The stanza's request is answered, with what the manager said late,
        // before the poll loop has seen its own poll come back.
        conn.send("<message to='x'/>").await.unwrap();
        settle().await;
        assert_eq!(conn.occupants(), ["other"], "what the request brought");
        let (polls, last) = {
            let st = server.state();
            (
                st.bodies.len() - before - 1,
                st.bodies.last().cloned().unwrap_or_default(),
            )
        };
        assert_eq!(
            polls, 1,
            "the polls since the stanza, no time having passed"
        );
        assert!(!last.contains("<message"), "{last}");
        assert_eq!(t.elapsed(), Duration::ZERO);
        assert!(!conn.is_closed());
    }

    /// A request is a reason to ask again at once one time, not for as long
    /// as it is out: a manager that holds nothing and is slow with a stanza
    /// is still asked once a floor.
    #[tokio::test(start_paused = true)]
    async fn a_stanza_that_stays_out_does_not_lift_the_floor_for_good() {
        let server = BoshServer::new();
        let (conn, _incoming, tx) = up(&server).await;
        settle().await;
        {
            let mut st = server.state();
            st.at_once = true;
            st.stall = true;
        }
        let before = server.state().bodies.len();
        let stuck = tokio::spawn(async move { tx.send("<message to='x'/>").await });
        settle().await;
        // The poll that was held comes back, empty, and from here on every
        // poll does, at once; the stanza's request stays out.
        server.say_whole(&format!("<body xmlns='{NS}' sid='{BOSH_SID}'/>"));
        tokio::time::sleep(S(20)).await;
        let polls = server.state().bodies.len() - before - 1;
        assert!(polls < BOSH_SPIN, "the client spins");
        assert!((20..=23).contains(&polls), "{polls} polls in 20 s");
        assert!(!conn.is_closed());
        assert!(!stuck.is_finished());
        stuck.abort();
    }

    /// The server ends the session with the body's `type`; the same words
    /// inside a stanza end nothing (they would end the Go client's).
    #[tokio::test(start_paused = true)]
    async fn a_terminate_on_the_body_ends_it_and_the_words_inside_a_stanza_do_not() {
        let server = BoshServer::new();
        let (conn, _incoming, tx) = up(&server).await;
        server.say(
            r#"<iq type='set' id='t1' from='f@auth.meet.jitsi/focus'><x type="terminate"/></iq>"#,
        );
        wait_for("the acknowledgement", || acked(&server, "t1")).await;
        assert!(!conn.is_closed());
        server.say_whole(&format!(
            "<body type='terminate' condition='remote-stream-error' xmlns='{NS}'><iq type='set' id='t2' from='f@auth.meet.jitsi/focus'/></body>"
        ));
        wait_for("the connection's end", || conn.is_closed()).await;
        settle().await;
        assert!(!acked(&server, "t2"), "nothing of a terminate is read");
        assert_eq!(
            tx.send("<message/>").await,
            Err(ConnError::Transport(CLOSED.into()))
        );
        // The session is the server's to end: nothing more is asked of it.
        let n = server.state().bodies.len();
        conn.close().await;
        tokio::time::sleep(S(120)).await;
        assert_eq!(server.state().bodies.len(), n);
        assert!(!server.state().terminated);
    }

    #[tokio::test(start_paused = true)]
    async fn close_says_terminate_once_and_asks_no_more() {
        let server = BoshServer::new();
        let (conn, _incoming, tx) = up(&server).await;
        conn.close().await;
        assert!(server.state().terminated);
        let (bodies, consecutive) = server.normalised();
        assert!(consecutive);
        assert_eq!(
            bodies[bodies.len() - 1],
            format!(r#"<body rid="RID" sid="SID" type="terminate" xmlns="{NS}"/>"#)
        );
        let n = bodies.len();
        conn.close().await;
        tx.close().await;
        tokio::time::sleep(S(120)).await;
        assert_eq!(server.state().bodies.len(), n, "one terminate, no poll");
        assert_eq!(
            tx.send("<message/>").await,
            Err(ConnError::Transport(CLOSED.into()))
        );
    }

    /// A request that fails ends the transport: its id is spent, and the
    /// manager would end a session with a hole in its ids anyway.
    #[tokio::test(start_paused = true)]
    async fn a_request_that_fails_ends_the_transport() {
        // A stanza's.
        let server = BoshServer::new();
        let (conn, _incoming, tx) = up(&server).await;
        server.state().fail = Some("io error: connection reset".into());
        assert_eq!(
            tx.send("<message/>").await,
            Err(ConnError::Transport("io error: connection reset".into()))
        );
        wait_for("the connection's end", || conn.is_closed()).await;
        let n = server.state().bodies.len();
        tokio::time::sleep(S(120)).await;
        assert_eq!(server.state().bodies.len(), n, "no poll after the end");

        // A poll's.
        let server = BoshServer::new();
        let (conn, _incoming, _tx) = up(&server).await;
        server.state().fail = Some("io error: connection reset".into());
        server.say("<presence from='secret-room@muc.meet.jitsi/zz'/>");
        wait_for("the connection's end", || conn.is_closed()).await;
    }

    /// Stanzas nobody reads are kept up to a megabyte; past it the transport
    /// ends, and what was kept is still read.
    #[tokio::test(start_paused = true)]
    async fn the_inbox_holds_a_megabyte_and_then_the_transport_ends() {
        let server = BoshServer::new();
        let (tx, mut rx) = open(Arc::new(server.clone()), "meet.jitsi").await.unwrap();
        let big = format!("<message><b>{}</b></message>", "x".repeat(300 << 10));
        for _ in 0..5 {
            server.say(&big);
            settle().await;
        }
        assert_eq!(
            tx.send("<message/>").await,
            Err(ConnError::Transport(CLOSED.into()))
        );
        let mut got = Vec::new();
        let end = loop {
            match rx.recv().await {
                Ok(s) => got.push(s.len()),
                Err(e) => break e,
            }
        };
        assert_eq!(end, ConnError::Transport(CLOSED.into()));
        // The features of the session request, then three of the five.
        assert_eq!(got.len(), 4, "{got:?}");
        assert!(got[1..].iter().all(|n| *n == big.len()));
        assert!(got.iter().sum::<usize>() <= INBOX_BYTES);
    }

    /// The restart is a request of its own after the SASL exchange; when it
    /// fails the login says so in Go's words (`conn.go:1404`).
    #[tokio::test(start_paused = true)]
    async fn a_restart_that_fails_is_the_login_s_failure_in_go_s_words() {
        let server = BoshServer::new();
        {
            let mut st = server.state();
            st.fail = Some("io error: connection reset".into());
            st.fail_when = Some("xmpp:restart");
        }
        let (tx, rx) = open(Arc::new(server.clone()), "meet.jitsi").await.unwrap();
        let e = Conn::login(Arc::new(tx), rx, cfg(), S(30)).await.err();
        assert_eq!(
            e.unwrap().to_string(),
            "bosh restart: io error: connection reset"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_is_not_a_body_ends_the_transport() {
        for answer in ["<body><iq></body>", "<html><body>busy</body></html>"] {
            let server = BoshServer::new();
            let (conn, _incoming, _tx) = up(&server).await;
            server.say_whole(answer);
            wait_for("the connection's end", || conn.is_closed()).await;
        }
    }

    /// A session request that gets no session fails in Go's words, with the
    /// server's answer quoted (`conn.go:1205-1213`), in part when it is long;
    /// and nothing else is asked.
    #[tokio::test(start_paused = true)]
    async fn a_session_request_that_gets_no_session_fails_in_go_s_words() {
        let refusal = format!("<body type='terminate' condition='host-unknown' xmlns='{NS}'/>");
        let server = BoshServer::new();
        server.state().create = Some(refusal.clone());
        let e = open(Arc::new(server.clone()), "meet.jitsi").await.err();
        assert_eq!(
            e.unwrap().to_string(),
            format!("bosh init: no sid in response: {refusal}")
        );
        tokio::time::sleep(S(120)).await;
        assert_eq!(server.state().bodies.len(), 1, "no poll, no terminate");

        let server = BoshServer::new();
        server.state().fail = Some("bosh: HTTP 404: not here".into());
        let e = open(Arc::new(server.clone()), "meet.jitsi").await.err();
        assert_eq!(
            e.unwrap().to_string(),
            "bosh init: bosh: HTTP 404: not here"
        );

        let server = BoshServer::new();
        server.state().create = Some(format!("<body x='{}'/>", "y".repeat(4000)));
        let e = open(Arc::new(server.clone()), "meet.jitsi")
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(e.starts_with("bosh init: no sid in response: <body x='yyy"));
        assert!(e.len() <= 40 + QUOTE_MAX, "{}", e.len());

        let server = BoshServer::new();
        server.state().create = Some("busy".into());
        let e = open(Arc::new(server.clone()), "meet.jitsi").await.err();
        assert_eq!(
            e.unwrap().to_string(),
            "bosh init: no sid in response: busy"
        );
    }
}

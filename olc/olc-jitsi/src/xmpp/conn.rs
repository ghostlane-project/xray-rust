// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The XMPP connection (`J/internal/xmpp/conn.go`): the anonymous login, the
//! read loop that answers what the server asks and routes what it answers,
//! the stream-management keepalive, the MUC occupants and the waiters for an
//! IQ's reply, the room's leave echo and the focus's offer.
//!
//! Decisions of the plan (D3, D4): the read loop decides on the parsed root
//! of each stanza (its name and its `type` and `id`), not on text anywhere in
//! it; and it keeps no queue of raw stanzas. A `transport-info` goes to the
//! session's channel (and is dropped when that is full, or nobody reads),
//! the one `session-initiate` waits parsed to be taken, and every other
//! stanza that nobody waits for is dropped, so a room full of presences can
//! never stall the reader.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, Notify};

use crate::ice::{parse_services, Service};
use crate::jingle::parse::{parse_stanza, Parsed};
use crate::stanza;
use crate::xml::{self, Event, Reader, Start};

/// A boxed future, for the transport traits.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How a transport carries the XMPP stream, which shapes the login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// RFC 7395: the stream is opened and reopened with `<open/>` frames,
    /// and stream management keeps it alive.
    WebSocket,
    /// XEP-0206: the session request opened the stream, its restart is a
    /// request of the transport's own, and there is no stream management
    /// (`authBOSH`; `keepaliveLoop` returns at once on BOSH).
    Bosh,
}

/// The sending half of a transport: one text message at a time.
pub trait Tx: Send + Sync + 'static {
    /// Sends `text` as one message.
    fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), ConnError>>;
    /// Closes the transport.
    fn close(&self) -> BoxFut<'_, ()>;
    /// How the transport carries the stream.
    fn framing(&self) -> Framing {
        Framing::WebSocket
    }
    /// Restarts the stream after the SASL exchange, where that is the
    /// transport's to do ([`Framing::Bosh`]).
    fn restart(&self) -> BoxFut<'_, Result<(), ConnError>> {
        Box::pin(async { Ok(()) })
    }
}

/// The receiving half: one text message at a time.
pub trait Rx: Send + 'static {
    /// The next message; an error ends the connection.
    fn recv(&mut self) -> BoxFut<'_, Result<String, ConnError>>;
}

/// Why a connection call failed. The texts are the library's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnError {
    /// The transport failed.
    #[error("{0}")]
    Transport(String),
    /// The login or the focus said no, with the text of the step.
    #[error("{0}")]
    Login(String),
    /// The connection is closed.
    #[error("xmpp connection closed")]
    Closed,
    /// The connection closed while an IQ's reply was awaited.
    #[error("connection closed before IQ {0} reply")]
    ClosedBeforeReply(String),
    /// No reply in time.
    #[error("timeout waiting for IQ {0} reply")]
    Timeout(String),
    /// An IQ wait without an id.
    #[error("SendIQWait requires non-empty id")]
    NoId,
    /// More IQs await a reply than this connection holds.
    #[error("too many IQ waiters")]
    TooManyWaiters,
    /// The server refused the focus request.
    #[error("focus allocation failed: {0}")]
    Focus(String),
    /// The connection closed before the leave was confirmed.
    #[error("connection closed before MUC leave confirmed")]
    LeaveClosed,
    /// No echo of the leave in time.
    #[error("timeout waiting for MUC leave confirmation")]
    LeaveTimeout,
    /// The connection closed while the room was being joined.
    #[error("connection closed")]
    JoinClosed,
    /// The room was not joined in time.
    #[error("context deadline exceeded")]
    JoinTimeout,
}

/// What the connection serves.
#[derive(Debug, Clone)]
pub struct ConnConfig {
    /// The web host (the name the user gave).
    pub host: String,
    /// The room.
    pub room: String,
    /// The XMPP domain: `hosts.domain` of config.js, the web host without it.
    pub xmpp_domain: String,
    /// The MUC domain.
    pub muc_domain: String,
}

/// What the focus said of the conference (`FocusInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FocusInfo {
    /// The `ready` attribute is `true` (`strings.EqualFold`).
    pub ready: bool,
    /// The `authentication` property.
    pub authentication_required: bool,
    /// The `externalAuth` property.
    pub external_auth: bool,
    /// The `visitors-supported` property.
    pub visitors_supported: bool,
    /// Every named property.
    pub properties: HashMap<String, String>,
}

/// What the read loop hands the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A `transport-info` stanza, whole.
    TransportInfo(String),
}

/// The stream-management keepalive's period (`keepaliveLoop`).
pub const SM_INTERVAL: Duration = Duration::from_secs(30);
/// How long an acknowledgement is waited for.
pub const SM_ACK_WAIT: Duration = Duration::from_secs(10);
/// The most nicks held as occupants; Go has no bound (decision D11).
pub const MAX_OCCUPANTS: usize = 256;
/// The longest nick held as an occupant, in bytes; Go has no bound. A nick
/// of Jitsi's is eight (the head of the JID's local part, as this client's
/// is), `focus` is five; a longer one is left out of the table.
pub const MAX_NICK: usize = 64;
/// The most IQs awaiting a reply at once; Go has no bound.
pub const MAX_IQ_WAITERS: usize = 16;
/// How many stanzas the session's channel holds.
pub const INCOMING_QUEUE: usize = 64;
/// How long the transport's goodbye (the WebSocket's close frame, BOSH's
/// terminate) may take where a close must not outlast its caller's own
/// bound: after a join that failed, and for a connection nobody holds any
/// more.
pub const CLOSE_WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct State {
    iq_waiters: HashMap<String, oneshot::Sender<String>>,
    sm_waiter: Option<Arc<Notify>>,
    leave_waiter: Option<Arc<Notify>>,
    join_waiter: Option<Arc<Notify>>,
    occupants: HashSet<String>,
    session_initiate: Option<Arc<Parsed>>,
    focus: FocusInfo,
}

struct Shared {
    tx: Arc<dyn Tx>,
    cfg: ConnConfig,
    jid: String,
    nick: String,
    closed: watch::Sender<bool>,
    ack_h: AtomicU32,
    id_seq: AtomicU64,
    st: Mutex<State>,
    jingle: Notify,
    events: mpsc::Sender<Incoming>,
}

/// What the handles of a connection share and its own tasks do not. The
/// read loop and the keepalive hold the connection up by themselves, so a
/// handle that is dropped unclosed (a join whose future was dropped after
/// the login, a rejoin aborted between the old connection's leave and its
/// close) would leave it logged in for the life of the process: the last
/// handle to go closes it. Go has no such case, a goroutine is not dropped.
struct Held(Arc<Shared>);

impl Drop for Held {
    fn drop(&mut self) {
        // Closed already (by `close`, by the transport, by the keepalive):
        // nothing is left to do. Else the flag ends the read loop and the
        // keepalive, and the transport goes with them.
        if self.0.closed.send_replace(true) {
            return;
        }
        // The goodbye is the transport's to say, and takes a task.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let sh = self.0.clone();
        runtime.spawn(async move {
            let _ = tokio::time::timeout(CLOSE_WAIT, sh.tx.close()).await;
        });
    }
}

/// A logged-in connection. Clones share it; when the last of them is dropped
/// the connection is closed, if [`Conn::close`] did not close it before.
#[derive(Clone)]
pub struct Conn {
    sh: Arc<Shared>,
    _held: Arc<Held>,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

/// Resolves once the flag is true (or its sender is gone). Not `wait_for`,
/// whose future holds a lock guard and so cannot be sent between threads.
pub(super) async fn wait_closed(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn attr(s: &Start<'_>, n: &str) -> String {
    s.attr(n)
        .ok()
        .flatten()
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

/// Reads until `pred` takes a message; a `stream:error` or `failure` first is
/// the server's refusal, with its text.
async fn read_until<R: Rx>(
    rx: &mut R,
    mut pred: impl FnMut(&str, &Start<'_>) -> bool,
) -> Result<String, ConnError> {
    loop {
        let msg = rx.recv().await?;
        let Ok(root) = xml::root(&msg) else { continue };
        if pred(&msg, &root) {
            return Ok(msg);
        }
        if root.name == "stream:error" || root.name == "failure" {
            return Err(ConnError::Login(format!("server error: {msg}")));
        }
    }
}

fn step(name: &str, e: &ConnError) -> ConnError {
    ConnError::Login(format!("{name}: {e}"))
}

impl Conn {
    /// Logs in anonymously (`auth`): the stream opened, SASL ANONYMOUS, the
    /// stream opened again, the resource bound, the session, stream
    /// management enabled; then the read loop and the keepalive run.
    ///
    /// Over BOSH (`authBOSH`, [`Framing::Bosh`]) the session request has
    /// opened the stream, the transport restarts it, and there is no stream
    /// management: neither enabled nor kept alive.
    ///
    /// # Errors
    /// The server's refusal at a step, with that step's name and the text it
    /// sent; or the transport's.
    pub async fn login<R: Rx>(
        tx: Arc<dyn Tx>,
        mut rx: R,
        cfg: ConnConfig,
        budget: Duration,
    ) -> Result<(Self, mpsc::Receiver<Incoming>), ConnError> {
        let framing = tx.framing();
        let steps = Self::login_steps(&tx, &mut rx, &cfg);
        let (jid, nick) = match tokio::time::timeout(budget, steps).await {
            Ok(r) => r?,
            Err(_) => return Err(ConnError::JoinTimeout),
        };
        let (events, incoming) = mpsc::channel(INCOMING_QUEUE);
        let (closed, _) = watch::channel(false);
        let sh = Arc::new(Shared {
            tx,
            cfg,
            jid,
            nick,
            closed,
            ack_h: AtomicU32::new(0),
            id_seq: AtomicU64::new(0),
            st: Mutex::new(State::default()),
            jingle: Notify::new(),
            events,
        });
        tokio::spawn(read_loop(sh.clone(), rx));
        if framing == Framing::WebSocket {
            tokio::spawn(keepalive(sh.clone()));
        }
        let held = Arc::new(Held(sh.clone()));
        Ok((Self { sh, _held: held }, incoming))
    }

    async fn login_steps<R: Rx>(
        tx: &Arc<dyn Tx>,
        rx: &mut R,
        cfg: &ConnConfig,
    ) -> Result<(String, String), ConnError> {
        let bosh = tx.framing() == Framing::Bosh;
        let open = stanza::open(&cfg.xmpp_domain);
        if !bosh {
            tx.send(&open).await?;
        }
        let features = read_until(rx, |_, r| local(r.name) == "features")
            .await
            .map_err(|e| step("initial features", &e))?;
        if !has_anonymous(&features) {
            return Err(ConnError::Login(
                "server does not advertise anonymous XMPP login".into(),
            ));
        }
        tx.send(stanza::AUTH_ANONYMOUS).await?;
        read_until(rx, |_, r| r.name == "success")
            .await
            .map_err(|e| step("sasl", &e))?;
        if bosh {
            tx.restart().await.map_err(|e| step("bosh restart", &e))?;
        } else {
            tx.send(&open).await?;
        }
        read_until(rx, |_, r| local(r.name) == "features")
            .await
            .map_err(|e| step("post-auth features", &e))?;
        tx.send(stanza::BIND).await?;
        let bind = read_until(rx, |m, _| matches!(xml::text_of(m, "jid"), Ok(Some(_))))
            .await
            .map_err(|e| step("bind", &e))?;
        let jid = xml::text_of(&bind, "jid")
            .ok()
            .flatten()
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default();
        if jid.is_empty() {
            return Err(ConnError::Login(format!("bind failed: {bind}")));
        }
        // The first eight bytes of the JID's local part; none when shorter.
        let nick = jid
            .split('@')
            .next()
            .and_then(|l| l.get(..8))
            .unwrap_or("")
            .to_owned();
        tx.send(stanza::SESSION).await?;
        read_until(rx, |_, r| r.name == "iq" && attr(r, "id") == "sess_1")
            .await
            .map_err(|e| step("session", &e))?;
        if bosh {
            return Ok((jid, nick));
        }
        tx.send(stanza::ENABLE_SM).await?;
        read_until(rx, |_, r| r.name == "enabled")
            .await
            .map_err(|e| step("sm enable", &e))?;
        Ok((jid, nick))
    }

    /// The bound JID.
    #[must_use]
    pub fn jid(&self) -> &str {
        &self.sh.jid
    }

    /// The nick: the first eight bytes of the JID's local part, empty when
    /// it is shorter.
    #[must_use]
    pub fn nick(&self) -> &str {
        &self.sh.nick
    }

    /// What the connection was made for.
    #[must_use]
    pub fn config(&self) -> &ConnConfig {
        &self.sh.cfg
    }

    /// The room's JID as this connection is in it: `room@muc/nick`.
    #[must_use]
    pub fn room_jid(&self) -> String {
        format!(
            "{}@{}/{}",
            self.sh.cfg.room, self.sh.cfg.muc_domain, self.sh.nick
        )
    }

    /// The room's bare JID.
    #[must_use]
    pub fn room_bare_jid(&self) -> String {
        format!("{}@{}", self.sh.cfg.room, self.sh.cfg.muc_domain)
    }

    /// A fresh stanza id: `j-<n>` (`NextID`).
    #[must_use]
    pub fn next_id(&self) -> String {
        format!("j-{}", self.sh.id_seq.fetch_add(1, Ordering::AcqRel) + 1)
    }

    /// Whether the connection is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.sh.closed.borrow()
    }

    /// Resolves when the connection is closed.
    pub async fn closed(&self) {
        let mut rx = self.sh.closed.subscribe();
        wait_closed(&mut rx).await;
    }

    fn mark_closed(&self) {
        self.sh.closed.send_replace(true);
    }

    /// Closes the connection and its transport.
    pub async fn close(&self) {
        self.mark_closed();
        self.sh.tx.close().await;
    }

    /// Sends a stanza as it is (`Send`).
    ///
    /// # Errors
    /// [`ConnError::Closed`] after the close; the transport's, which closes
    /// the connection.
    pub async fn send(&self, text: &str) -> Result<(), ConnError> {
        self.sh.send(text).await
    }

    /// Sends an IQ and waits for the `result` or `error` with its id
    /// (`SendIQWait`).
    ///
    /// # Errors
    /// [`ConnError`]: no id, too many waiters, a failed send, the close, the
    /// timeout.
    pub async fn send_iq_wait(
        &self,
        iq: &str,
        id: &str,
        timeout: Duration,
    ) -> Result<String, ConnError> {
        if id.is_empty() {
            return Err(ConnError::NoId);
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut st = lock(&self.sh.st);
            if st.iq_waiters.len() >= MAX_IQ_WAITERS && !st.iq_waiters.contains_key(id) {
                return Err(ConnError::TooManyWaiters);
            }
            st.iq_waiters.insert(id.to_owned(), tx);
        }
        let forget = || {
            lock(&self.sh.st).iq_waiters.remove(id);
        };
        if let Err(e) = self.sh.send(iq).await {
            forget();
            return Err(e);
        }
        let mut closed = self.sh.closed.subscribe();
        tokio::select! {
            reply = rx => match reply {
                Ok(msg) => Ok(msg),
                Err(_) => {
                    forget();
                    Err(ConnError::ClosedBeforeReply(id.to_owned()))
                }
            },
            () = wait_closed(&mut closed) => {
                forget();
                Err(ConnError::ClosedBeforeReply(id.to_owned()))
            }
            () = tokio::time::sleep(timeout) => {
                forget();
                Err(ConnError::Timeout(id.to_owned()))
            }
        }
    }

    /// Asks the focus for the conference (`AllocateFocus`) and waits for its
    /// answer. A `ready='false'` answer passes, as it does in Go.
    ///
    /// # Errors
    /// The focus's `error`, or the wait's.
    pub async fn allocate_focus(&self, timeout: Duration) -> Result<FocusInfo, ConnError> {
        let iq = stanza::focus(
            &self.sh.cfg.xmpp_domain,
            &self.room_bare_jid(),
            &self.sh.nick,
        );
        let reply = self.send_iq_wait(&iq, "focus_1", timeout).await?;
        let root = xml::root(&reply).map_err(|e| ConnError::Focus(e.to_string()))?;
        if attr(&root, "type") == "error" {
            return Err(ConnError::Focus(reply));
        }
        let info = parse_focus_info(&reply);
        lock(&self.sh.st).focus = info.clone();
        Ok(info)
    }

    /// The focus's answer.
    #[must_use]
    pub fn focus_info(&self) -> FocusInfo {
        lock(&self.sh.st).focus.clone()
    }

    /// Asks for the external services (`DiscoverServices`); a server without
    /// them answers `error` and gives none.
    ///
    /// # Errors
    /// The wait's.
    pub async fn discover_services(&self, timeout: Duration) -> Result<Vec<Service>, ConnError> {
        let iq = stanza::extdisco(&self.sh.cfg.xmpp_domain);
        let reply = self.send_iq_wait(&iq, "disco_1", timeout).await?;
        match xml::root(&reply) {
            Ok(r) if attr(&r, "type") == "error" => Ok(Vec::new()),
            _ => Ok(parse_services(&reply)),
        }
    }

    /// Joins the room (`JoinMUC`): the presence, and the wait for the server's
    /// echo of it with status 110; then the room's disco#info is asked for.
    ///
    /// # Errors
    /// The close or the timeout.
    pub async fn join_muc(&self, display_name: &str, timeout: Duration) -> Result<(), ConnError> {
        let waiter = Arc::new(Notify::new());
        lock(&self.sh.st).join_waiter = Some(waiter.clone());
        let presence = stanza::join_presence(&self.room_jid(), display_name, &self.sh.nick);
        self.sh.send(&presence).await?;
        let mut closed = self.sh.closed.subscribe();
        tokio::select! {
            () = waiter.notified() => {}
            () = wait_closed(&mut closed) => return Err(ConnError::JoinClosed),
            () = tokio::time::sleep(timeout) => return Err(ConnError::JoinTimeout),
        }
        let _ = self
            .sh
            .send(&stanza::room_info(&self.room_bare_jid(), &self.next_id()))
            .await;
        Ok(())
    }

    /// Leaves the room and waits for the server to echo it (`LeaveMUCWait`),
    /// as lib-jitsi-meet does: the bridge slot can be reclaimed once it is.
    ///
    /// # Errors
    /// The close, the timeout, or a failed send.
    pub async fn leave_muc_wait(&self, timeout: Duration) -> Result<(), ConnError> {
        let waiter = Arc::new(Notify::new());
        // A second concurrent leave inherits the first's waiter.
        let w = {
            let mut st = lock(&self.sh.st);
            st.leave_waiter
                .get_or_insert_with(|| waiter.clone())
                .clone()
        };
        let forget = || {
            let mut st = lock(&self.sh.st);
            if st.leave_waiter.as_ref().is_some_and(|x| Arc::ptr_eq(x, &w)) {
                st.leave_waiter = None;
            }
        };
        if let Err(e) = self.sh.send(&stanza::leave(&self.room_jid())).await {
            forget();
            return Err(e);
        }
        let mut closed = self.sh.closed.subscribe();
        tokio::select! {
            () = w.notified() => Ok(()),
            () = wait_closed(&mut closed) => Err(ConnError::LeaveClosed),
            () = tokio::time::sleep(timeout) => {
                forget();
                Err(ConnError::LeaveTimeout)
            }
        }
    }

    /// The other nicks in the room: not ours, not `focus` (`Occupants`).
    #[must_use]
    pub fn occupants(&self) -> Vec<String> {
        lock(&self.sh.st).occupants.iter().cloned().collect()
    }

    /// Waits for a `session-initiate` and takes it: the parsed offer, one at
    /// a time, the newest.
    ///
    /// # Errors
    /// The close or the timeout.
    pub async fn wait_session_initiate(&self, timeout: Duration) -> Result<Arc<Parsed>, ConnError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut closed = self.sh.closed.subscribe();
        loop {
            let notified = self.sh.jingle.notified();
            if let Some(p) = lock(&self.sh.st).session_initiate.take() {
                return Ok(p);
            }
            tokio::select! {
                () = notified => {}
                () = wait_closed(&mut closed) => return Err(ConnError::JoinClosed),
                () = tokio::time::sleep_until(deadline) => return Err(ConnError::JoinTimeout),
            }
        }
    }
}

fn has_anonymous(features: &str) -> bool {
    let mut r = Reader::new(features);
    while let Ok(Some(e)) = r.next_event() {
        if let Event::Start(s) = e {
            if s.name == "mechanism" {
                if let Ok(Some(Event::Text(t))) = r.next_event() {
                    if t == "ANONYMOUS" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// `parseFocusInfo`.
fn parse_focus_info(reply: &str) -> FocusInfo {
    let mut info = FocusInfo::default();
    let mut r = Reader::new(reply);
    let mut in_conference = false;
    while let Ok(Some(e)) = r.next_event() {
        match e {
            Event::Start(s) if s.name == "conference" => {
                info.ready = attr(&s, "ready").eq_ignore_ascii_case("true");
                in_conference = !s.self_closing;
            }
            Event::Start(s) if in_conference && s.name == "property" => {
                let name = attr(&s, "name");
                if !name.is_empty() {
                    info.properties.insert(name, attr(&s, "value"));
                }
            }
            Event::End("conference") => in_conference = false,
            _ => {}
        }
    }
    let flag = |k: &str| {
        info.properties
            .get(k)
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    };
    info.authentication_required = flag("authentication");
    info.external_auth = flag("externalAuth");
    info.visitors_supported = flag("visitors-supported");
    info
}

impl Shared {
    async fn send(&self, text: &str) -> Result<(), ConnError> {
        if *self.closed.borrow() {
            return Err(ConnError::Closed);
        }
        if let Err(e) = self.tx.send(text).await {
            self.closed.send_replace(true);
            return Err(e);
        }
        Ok(())
    }

    /// What the server sent, by its root (decision D3).
    async fn dispatch(&self, msg: String) {
        let Ok(root) = xml::root(&msg) else {
            self.ack_h.fetch_add(1, Ordering::AcqRel);
            return;
        };
        match root.name {
            "r" => {
                let h = self.ack_h.load(Ordering::Acquire);
                let _ = self.send(&stanza::sm_ack(h)).await;
                return;
            }
            "a" => {
                if let Some(w) = lock(&self.st).sm_waiter.take() {
                    w.notify_one();
                }
                return;
            }
            _ => {}
        }
        self.ack_h.fetch_add(1, Ordering::AcqRel);
        match root.name {
            "iq" => self.dispatch_iq(&msg, &root).await,
            "presence" => self.dispatch_presence(&msg, &root),
            _ => {}
        }
    }

    async fn dispatch_iq(&self, msg: &str, root: &Start<'_>) {
        let (kind, id, from) = (attr(root, "type"), attr(root, "id"), attr(root, "from"));
        if (kind == "result" || kind == "error") && !id.is_empty() {
            let waiter = lock(&self.st).iq_waiters.remove(&id);
            if let Some(w) = waiter {
                let _ = w.send(msg.to_owned());
                return;
            }
        }
        if kind == "get" && is_disco_info(msg) {
            if !from.is_empty() && !id.is_empty() {
                let _ = self.send(&stanza::disco_result(&from, &id)).await;
            }
            return;
        }
        if kind != "set" {
            return;
        }
        let action = parse_stanza(msg).map(|j| j.action).unwrap_or_default();
        if !from.is_empty() && !id.is_empty() {
            let _ = self.send(&stanza::iq_result(&from, &id)).await;
        }
        match action.as_str() {
            "session-initiate" => {
                let parsed = Parsed::of(msg);
                lock(&self.st).session_initiate = Some(Arc::new(parsed));
                self.jingle.notify_one();
            }
            "transport-info" => {
                let _ = self
                    .events
                    .try_send(Incoming::TransportInfo(msg.to_owned()));
            }
            _ => {}
        }
    }

    fn dispatch_presence(&self, msg: &str, root: &Start<'_>) {
        let from = attr(root, "from");
        let unavailable = attr(root, "type") == "unavailable";
        self.track_presence(&from, unavailable);
        let mut st = lock(&self.st);
        if unavailable
            && !self.nick.is_empty()
            && from == format!("{}@{}/{}", self.cfg.room, self.cfg.muc_domain, self.nick)
        {
            if let Some(w) = st.leave_waiter.take() {
                w.notify_one();
            }
        }
        if has_status_110(msg) {
            if let Some(w) = st.join_waiter.take() {
                w.notify_one();
            }
        }
    }

    /// `trackPresence`: available adds, `unavailable` removes; self, `focus`
    /// and anyone outside this room are left out, and so is a nick longer
    /// than [`MAX_NICK`], which the table's size is counted on.
    fn track_presence(&self, from: &str, unavailable: bool) {
        let Some(slash) = from.rfind('/') else { return };
        let nick = &from[slash + 1..];
        if nick.is_empty() || nick.len() > MAX_NICK || nick == "focus" || nick == self.nick {
            return;
        }
        if !from.starts_with(&format!("{}@", self.cfg.room)) {
            return;
        }
        let mut st = lock(&self.st);
        if unavailable {
            st.occupants.remove(nick);
        } else if st.occupants.len() < MAX_OCCUPANTS || st.occupants.contains(nick) {
            st.occupants.insert(nick.to_owned());
        }
    }
}

fn is_disco_info(msg: &str) -> bool {
    let mut r = Reader::new(msg);
    while let Ok(Some(e)) = r.next_event() {
        if let Event::Start(s) = e {
            if s.name == "query" && attr(&s, "xmlns").contains("disco#info") {
                return true;
            }
        }
    }
    false
}

fn has_status_110(msg: &str) -> bool {
    let mut r = Reader::new(msg);
    while let Ok(Some(e)) = r.next_event() {
        if let Event::Start(s) = e {
            if s.name == "status" && attr(&s, "code") == "110" {
                return true;
            }
        }
    }
    false
}

async fn read_loop<R: Rx>(sh: Arc<Shared>, mut rx: R) {
    let mut closed = sh.closed.subscribe();
    loop {
        let msg = tokio::select! {
            biased;
            () = wait_closed(&mut closed) => break,
            m = rx.recv() => match m {
                Ok(m) => m,
                Err(_) => break,
            },
        };
        sh.dispatch(msg).await;
    }
    sh.closed.send_replace(true);
}

/// `keepaliveLoop`: every 30 s a stream-management request; no
/// acknowledgement within 10 s closes the connection, so the server sees the
/// transport go and clears the room's ghost instead of waiting for its own
/// idle timeout.
async fn keepalive(sh: Arc<Shared>) {
    let mut closed = sh.closed.subscribe();
    loop {
        tokio::select! {
            () = wait_closed(&mut closed) => return,
            () = tokio::time::sleep(SM_INTERVAL) => {}
        }
        // Armed before the request, so a fast answer cannot race it.
        let waiter = lock(&sh.st)
            .sm_waiter
            .get_or_insert_with(|| Arc::new(Notify::new()))
            .clone();
        if sh.send(stanza::SM_REQUEST).await.is_err() {
            return;
        }
        tokio::select! {
            () = waiter.notified() => {}
            () = wait_closed(&mut closed) => return,
            () = tokio::time::sleep(SM_ACK_WAIT) => {
                {
                    let mut st = lock(&sh.st);
                    if st.sm_waiter.as_ref().is_some_and(|w| Arc::ptr_eq(w, &waiter)) {
                        st.sm_waiter = None;
                    }
                }
                sh.closed.send_replace(true);
                sh.tx.close().await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmpp::testing::{pipe, pipe_bosh, serve_login, Server, RESTART};

    const S: fn(u64) -> Duration = Duration::from_secs;

    fn cfg() -> ConnConfig {
        ConnConfig {
            host: "meet.example".into(),
            room: "testroom".into(),
            xmpp_domain: "meet.example".into(),
            muc_domain: "conference.test.example.com".into(),
        }
    }

    /// A connection logged in as `abcdef0123456789@meet.example/res`.
    async fn up() -> (Conn, mpsc::Receiver<Incoming>, Server) {
        let (tx, rx, mut server) = pipe();
        let tx: Arc<dyn Tx> = Arc::new(tx);
        let login = tokio::spawn(Conn::login(tx, rx, cfg(), S(30)));
        serve_login(&mut server, "abcdef0123456789@meet.example/res").await;
        let (conn, incoming) = login.await.unwrap().unwrap();
        (conn, incoming, server)
    }

    async fn login_refused(
        script: impl FnOnce(&mut Server) -> BoxFut<'_, ()> + Send + 'static,
    ) -> ConnError {
        let (tx, rx, mut server) = pipe();
        let tx: Arc<dyn Tx> = Arc::new(tx);
        let task = tokio::spawn(async move { Conn::login(tx, rx, cfg(), S(30)).await.map(|_| ()) });
        script(&mut server).await;
        task.await.unwrap().unwrap_err()
    }

    /// Lets the tasks run.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    /// `authBOSH` (`conn.go:1375-1437`): the session request has opened the
    /// stream, so the login starts at the features; the restart after the
    /// SASL exchange is the transport's own request; and stream management
    /// is neither asked for nor run (`keepaliveLoop` returns at once).
    #[tokio::test(start_paused = true)]
    async fn over_bosh_the_login_opens_no_stream_and_runs_no_stream_management() {
        let (tx, rx, mut server) = pipe_bosh();
        let tx: Arc<dyn Tx> = Arc::new(tx);
        let login = tokio::spawn(Conn::login(tx, rx, cfg(), S(30)));
        server.say("<stream:features xmlns='jabber:client'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>");
        assert_eq!(server.next().await, stanza::AUTH_ANONYMOUS);
        server.say("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
        assert_eq!(server.next().await, RESTART);
        server.say("<stream:features xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>");
        assert_eq!(server.next().await, stanza::BIND);
        server.say("<iq type='result' id='bind_1' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>abcdef0123456789@meet.example/res</jid></bind></iq>");
        assert_eq!(server.next().await, stanza::SESSION);
        server.say("<iq type='result' id='sess_1' xmlns='jabber:client'/>");
        let (conn, _incoming) = login.await.unwrap().unwrap();
        assert_eq!(conn.nick(), "abcdef01");
        settle().await;
        assert!(server.drain().is_empty(), "no <enable>");
        // Over a WebSocket a request goes out at SM_INTERVAL and the
        // connection closes SM_ACK_WAIT later for want of an answer.
        tokio::time::sleep(SM_INTERVAL + SM_ACK_WAIT + S(5)).await;
        settle().await;
        assert!(server.drain().is_empty(), "no <r>");
        assert!(!conn.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn the_login_goes_as_go_s_does_and_binds_the_nick() {
        let (conn, _incoming, mut server) = up().await;
        assert_eq!(conn.jid(), "abcdef0123456789@meet.example/res");
        assert_eq!(conn.nick(), "abcdef01");
        assert_eq!(
            conn.room_jid(),
            "testroom@conference.test.example.com/abcdef01"
        );
        assert!(server.drain().is_empty(), "nothing more was written");
        assert_eq!(conn.next_id(), "j-1");
        assert_eq!(conn.next_id(), "j-2");
    }

    #[tokio::test(start_paused = true)]
    async fn a_short_local_part_gives_no_nick() {
        let (tx, rx, mut server) = pipe();
        let tx: Arc<dyn Tx> = Arc::new(tx);
        let login = tokio::spawn(Conn::login(tx, rx, cfg(), S(30)));
        serve_login(&mut server, "abc@meet.example/res").await;
        let (conn, _) = login.await.unwrap().unwrap();
        assert_eq!(conn.nick(), "");
    }

    #[tokio::test(start_paused = true)]
    async fn host_unknown_aborts_the_login_with_the_servers_text() {
        let e = login_refused(|s| {
            Box::pin(async move {
                let _ = s.next().await;
                s.say("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text>This server does not serve meet.example</text></stream:error>");
            })
        })
        .await;
        let text = e.to_string();
        assert!(
            text.starts_with("initial features: server error: <stream:error"),
            "{text}"
        );
        assert!(text.contains("<host-unknown"), "{text}");
        assert!(crate::configjs::should_retry_with_fallback(
            Some(&text),
            true
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_in_sasl_and_a_server_without_anonymous() {
        let e = login_refused(|s| {
            Box::pin(async move {
                let _ = s.next().await;
                s.say("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>");
                let _ = s.next().await;
                s.say("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>");
            })
        })
        .await;
        assert!(
            e.to_string().starts_with("sasl: server error: <failure"),
            "{e}"
        );
        let e = login_refused(|s| {
            Box::pin(async move {
                let _ = s.next().await;
                s.say("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>");
            })
        })
        .await;
        assert_eq!(
            e.to_string(),
            "server does not advertise anonymous XMPP login"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_login_that_hangs_ends_at_its_budget_and_a_hangup_is_an_error() {
        let (tx, rx, _server) = pipe();
        let tx: Arc<dyn Tx> = Arc::new(tx);
        let e = Conn::login(tx, rx, cfg(), S(5)).await.unwrap_err();
        assert_eq!(e, ConnError::JoinTimeout);
        let (tx, rx, mut server) = pipe();
        let tx: Arc<dyn Tx> = Arc::new(tx);
        server.hang_up();
        let e = Conn::login(tx, rx, cfg(), S(5)).await.unwrap_err();
        assert!(e.to_string().starts_with("initial features: "), "{e}");
    }

    /// `TestReadLoop_StreamManagement` (`conn_test.go:455`): a request is
    /// answered with the count of the stanzas received since the enable.
    #[tokio::test(start_paused = true)]
    async fn an_sm_request_is_answered_with_the_stanza_count() {
        let (_conn, _inc, mut server) = up().await;
        server.say("<r xmlns='urn:xmpp:sm:3'/>");
        assert_eq!(server.next().await, r#"<a h="0" xmlns="urn:xmpp:sm:3"/>"#);
        for _ in 0..3 {
            server.say("<message xmlns='jabber:client'/>");
        }
        server.say("<r xmlns='urn:xmpp:sm:3'/>");
        assert_eq!(server.next().await, r#"<a h="3" xmlns="urn:xmpp:sm:3"/>"#);
    }

    #[tokio::test(start_paused = true)]
    async fn the_keepalive_asks_every_30_seconds_and_an_answer_keeps_it_going() {
        let (conn, _inc, mut server) = up().await;
        for round in 0..3 {
            tokio::time::advance(SM_INTERVAL).await;
            settle().await;
            assert_eq!(server.next().await, stanza::SM_REQUEST, "round {round}");
            server.say("<a xmlns='urn:xmpp:sm:3' h='5'/>");
            tokio::time::advance(S(1)).await;
            settle().await;
        }
        assert!(!conn.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn no_answer_in_ten_seconds_closes_the_connection() {
        let (conn, _inc, mut server) = up().await;
        tokio::time::advance(SM_INTERVAL).await;
        settle().await;
        assert_eq!(server.next().await, stanza::SM_REQUEST);
        tokio::time::advance(SM_ACK_WAIT - Duration::from_millis(1)).await;
        settle().await;
        assert!(
            !conn.is_closed(),
            "one miss closes, but not before the window"
        );
        tokio::time::advance(S(1)).await;
        settle().await;
        assert!(conn.is_closed());
        assert!(conn.send("<presence/>").await.is_err());
    }

    /// `TestAckIQ_SessionInitiate`, `TestAckIQ_SourceAdd` (`conn_test.go:171,201`).
    #[tokio::test(start_paused = true)]
    async fn an_iq_set_is_acknowledged_and_a_session_initiate_is_kept() {
        let (conn, _inc, mut server) = up().await;
        server.say(crate::jingle::fixtures::INITIATE);
        assert_eq!(
            server.next().await,
            r#"<iq to="room@muc.meet.jitsi/focus" id="si1" type="result" xmlns="jabber:client"/>"#
        );
        let p = conn.wait_session_initiate(S(1)).await.unwrap();
        assert_eq!(p.sid, "sid123");
        // Taken: the next wait is for another.
        assert_eq!(
            conn.wait_session_initiate(S(1)).await,
            Err(ConnError::JoinTimeout)
        );
        server.say("<iq from='room@conference.test.example.com/focus' id='sa_456' type='set' xmlns='jabber:client'><jingle xmlns='urn:xmpp:jingle:1' action='source-add' sid='abc'><content name='video'/></jingle></iq>");
        assert_eq!(
            server.next().await,
            r#"<iq to="room@conference.test.example.com/focus" id="sa_456" type="result" xmlns="jabber:client"/>"#
        );
        // An iq get that is not a disco is not acknowledged; neither is a result.
        server.say("<iq from='x' id='1' type='get' xmlns='jabber:client'><ping xmlns='urn:xmpp:ping'/></iq>");
        server.say("<iq from='x' id='2' type='result' xmlns='jabber:client'/>");
        settle().await;
        assert!(server.drain().is_empty());
    }

    /// A newer offer replaces one not yet taken.
    #[tokio::test(start_paused = true)]
    async fn the_newest_session_initiate_is_the_one_taken() {
        let (conn, _inc, server) = up().await;
        let second = crate::jingle::fixtures::INITIATE.replace("sid123", "sid456");
        server.say(crate::jingle::fixtures::INITIATE);
        server.say(&second);
        settle().await;
        assert_eq!(
            conn.wait_session_initiate(S(1)).await.unwrap().sid,
            "sid456"
        );
    }

    /// `TestDiscoInfoResponse` (`conn_test.go:223`).
    #[tokio::test(start_paused = true)]
    async fn a_disco_query_is_answered_with_the_features() {
        let (_conn, _inc, mut server) = up().await;
        server.say("<iq from='focus@auth.test.example.com' id='disco_99' type='get' xmlns='jabber:client'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>");
        let reply = server.next().await;
        assert_eq!(
            reply,
            stanza::disco_result("focus@auth.test.example.com", "disco_99")
        );
        assert_eq!(reply.matches("<feature ").count(), 16);
    }

    /// `TestStress_OccupantTracking` (`conn_test.go:298`).
    #[tokio::test(start_paused = true)]
    async fn occupants_come_and_go_and_self_and_focus_are_not_among_them() {
        let (conn, _inc, server) = up().await;
        let room = "testroom@conference.test.example.com";
        for n in ["u1", "u2", "focus", "abcdef01"] {
            server.say(&format!("<presence from='{room}/{n}' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'><item role='participant'/></x></presence>"));
        }
        // Another room's, and one with no resource.
        server.say("<presence from='other@conference.test.example.com/zz' xmlns='jabber:client'/>");
        server.say(&format!("<presence from='{room}' xmlns='jabber:client'/>"));
        settle().await;
        let mut occ = conn.occupants();
        occ.sort();
        assert_eq!(occ, ["u1", "u2"]);
        server.say(&format!(
            "<presence from='{room}/u1' type='unavailable' xmlns='jabber:client'/>"
        ));
        settle().await;
        assert_eq!(conn.occupants(), ["u2"]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_occupant_table_is_capped() {
        let (conn, _inc, server) = up().await;
        for i in 0..400 {
            server.say(&format!("<presence from='testroom@conference.test.example.com/n{i}' xmlns='jabber:client'/>"));
        }
        settle().await;
        assert_eq!(conn.occupants().len(), MAX_OCCUPANTS);
    }

    /// The table is priced at `MAX_OCCUPANTS` nicks of `MAX_NICK` bytes
    /// (olc-client's sizes table): a nick of that length is kept, a longer
    /// one is left out, however many of them the server names and however
    /// long they are.
    #[tokio::test(start_paused = true)]
    async fn a_nick_longer_than_the_bound_is_not_kept() {
        let (conn, _inc, server) = up().await;
        let room = "testroom@conference.test.example.com";
        let longest = "n".repeat(MAX_NICK);
        for nick in [longest.clone(), format!("{longest}x"), "short".to_owned()] {
            server.say(&format!(
                "<presence from='{room}/{nick}' xmlns='jabber:client'/>"
            ));
        }
        for i in 0..400 {
            server.say(&format!(
                "<presence from='{room}/{}{i}' xmlns='jabber:client'/>",
                "w".repeat(2000)
            ));
        }
        settle().await;
        let mut occ = conn.occupants();
        let long = occ.iter().filter(|n| n.len() > MAX_NICK).count();
        assert_eq!(long, 0, "nicks longer than MAX_NICK that are held");
        occ.sort();
        assert_eq!(occ, [longest.as_str(), "short"]);
        // One that was never kept leaves as any does.
        server.say(&format!(
            "<presence from='{room}/{longest}x' type='unavailable' xmlns='jabber:client'/>"
        ));
        settle().await;
        assert_eq!(conn.occupants().len(), 2);
        // Filled with the longest nicks there are, the table holds what the
        // sizes table says and no more.
        for i in 0..400 {
            server.say(&format!(
                "<presence from='{room}/{i:0>width$}' xmlns='jabber:client'/>",
                width = MAX_NICK
            ));
        }
        settle().await;
        let held = conn.occupants();
        assert_eq!(held.len(), MAX_OCCUPANTS);
        assert_eq!(
            held.iter().map(String::len).sum::<usize>(),
            MAX_OCCUPANTS * MAX_NICK - (MAX_NICK - "short".len())
        );
    }

    /// `TestStress_IQWaiters`, `TestStress_IQWaiterTimeout` (`conn_test.go`).
    #[tokio::test(start_paused = true)]
    async fn an_iq_waiter_gets_its_reply_or_times_out() {
        let (conn, _inc, mut server) = up().await;
        let c2 = conn.clone();
        let t = tokio::spawn(async move {
            c2.send_iq_wait(
                "<iq to='t' type='set' id='w1' xmlns='jabber:client'><body/></iq>",
                "w1",
                S(5),
            )
            .await
        });
        assert!(server.next().await.contains("id='w1'"));
        // A child's id is not the root's: this is not the reply.
        server.say("<iq from='t' id='other' type='result' xmlns='jabber:client'><x id='w1'/></iq>");
        server.say("<iq from='t' id='w1' type='result' xmlns='jabber:client'/>");
        let reply = t.await.unwrap().unwrap();
        assert!(reply.contains("id='w1'") && reply.contains("type='result'"));
        let e = conn
            .send_iq_wait("<iq id='x'/>", "x", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), "timeout waiting for IQ x reply");
        assert_eq!(
            conn.send_iq_wait("<iq/>", "", S(1)).await,
            Err(ConnError::NoId)
        );
        // The wait is forgotten: a late reply goes nowhere.
        server.say("<iq from='t' id='x' type='result' xmlns='jabber:client'/>");
        settle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_close_ends_a_wait_and_waiters_are_bounded() {
        let (conn, _inc, _server) = up().await;
        let c2 = conn.clone();
        let t = tokio::spawn(async move { c2.send_iq_wait("<iq id='z'/>", "z", S(60)).await });
        settle().await;
        conn.close().await;
        assert_eq!(
            t.await.unwrap(),
            Err(ConnError::ClosedBeforeReply("z".into()))
        );

        let (conn, _inc, _server) = up().await;
        let mut tasks = Vec::new();
        for i in 0..MAX_IQ_WAITERS {
            let c = conn.clone();
            tasks.push(tokio::spawn(async move {
                c.send_iq_wait("<iq/>", &format!("id{i}"), S(60)).await
            }));
        }
        settle().await;
        assert_eq!(
            conn.send_iq_wait("<iq/>", "more", S(1)).await,
            Err(ConnError::TooManyWaiters)
        );
        conn.close().await;
        for t in tasks {
            assert!(t.await.unwrap().is_err());
        }
    }

    /// `TestLeaveMUCWait_Success`, `…_Timeout` (`conn_test.go:422,441`).
    #[tokio::test(start_paused = true)]
    async fn the_leave_waits_for_its_own_unavailable_echo() {
        let (conn, _inc, mut server) = up().await;
        let c2 = conn.clone();
        let t = tokio::spawn(async move { c2.leave_muc_wait(S(5)).await });
        assert_eq!(
            server.next().await,
            r#"<presence to="testroom@conference.test.example.com/abcdef01" type="unavailable" xmlns="jabber:client"/>"#
        );
        // Another occupant leaving is not the echo.
        server.say("<presence from='testroom@conference.test.example.com/other' type='unavailable' xmlns='jabber:client'/>");
        settle().await;
        assert!(!t.is_finished());
        server.say("<presence from='testroom@conference.test.example.com/abcdef01' type='unavailable' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'><item role='none'/><status code='110'/></x></presence>");
        assert_eq!(t.await.unwrap(), Ok(()));
        assert_eq!(
            conn.leave_muc_wait(S(5)).await,
            Err(ConnError::LeaveTimeout)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_focus_the_services_and_the_join() {
        let (conn, _inc, mut server) = up().await;
        // Focus.
        let c = conn.clone();
        let t = tokio::spawn(async move { c.allocate_focus(S(5)).await });
        let sent = server.next().await;
        assert_eq!(
            sent,
            stanza::focus(
                "meet.example",
                "testroom@conference.test.example.com",
                "abcdef01"
            )
        );
        server.say("<iq from='focus.meet.example' id='focus_1' type='result' xmlns='jabber:client'><conference xmlns='http://jitsi.org/protocol/focus' room='r' ready='true'><property name='authentication' value='true'/><property name='externalAuth' value='false'/><property name='x' value='y'/></conference></iq>");
        let info = t.await.unwrap().unwrap();
        assert!(
            info.ready
                && info.authentication_required
                && !info.external_auth
                && !info.visitors_supported
        );
        assert_eq!(info.properties.get("x").map(String::as_str), Some("y"));
        assert_eq!(conn.focus_info(), info);
        // ready='false' passes, as in Go; an error does not.
        let c = conn.clone();
        let t = tokio::spawn(async move { c.allocate_focus(S(5)).await });
        server.next().await;
        server.say("<iq id='focus_1' type='result'><conference ready='false'/></iq>");
        assert!(!t.await.unwrap().unwrap().ready);
        let c = conn.clone();
        let t = tokio::spawn(async move { c.allocate_focus(S(5)).await });
        server.next().await;
        server.say("<iq id='focus_1' type='error'><error type='cancel'/></iq>");
        assert!(t
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .starts_with("focus allocation failed: <iq"));
        // Services.
        let c = conn.clone();
        let t = tokio::spawn(async move { c.discover_services(S(5)).await });
        assert_eq!(server.next().await, stanza::extdisco("meet.example"));
        server.say("<iq id='disco_1' type='result'><services xmlns='urn:xmpp:extdisco:2'><service type='stun' host='s.example' port='3478'/></services></iq>");
        assert_eq!(t.await.unwrap().unwrap().len(), 1);
        let c = conn.clone();
        let t = tokio::spawn(async move { c.discover_services(S(5)).await });
        server.next().await;
        server.say("<iq id='disco_1' type='error'/>");
        assert!(t.await.unwrap().unwrap().is_empty());
        // Join: the presence, the echo with status 110, then the room's disco.
        let c = conn.clone();
        let t = tokio::spawn(async move { c.join_muc("olcrtc", S(5)).await });
        let p = server.next().await;
        assert_eq!(
            p,
            stanza::join_presence(
                "testroom@conference.test.example.com/abcdef01",
                "olcrtc",
                "abcdef01"
            )
        );
        server.say("<presence from='testroom@conference.test.example.com/abcdef01' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'><status code='110'/></x></presence>");
        assert_eq!(t.await.unwrap(), Ok(()));
        let info = server.next().await;
        assert!(
            info.contains("disco#info")
                && info.contains("to=\"testroom@conference.test.example.com\""),
            "{info}"
        );
        // No echo: the join times out.
        assert_eq!(
            conn.join_muc("olcrtc", S(2)).await,
            Err(ConnError::JoinTimeout)
        );
    }

    /// D4: a room's presences before a peer arrives do not stall the reader
    /// (Go's queue of 64 does), a `transport-info` reaches the session, and a
    /// full channel drops instead of blocking.
    #[tokio::test(start_paused = true)]
    async fn the_reader_never_waits_for_the_session() {
        let (conn, mut incoming, mut server) = up().await;
        for i in 0..200 {
            server.say(&format!(
                "<presence from='testroom@conference.test.example.com/n{}' xmlns='jabber:client'/>",
                i % 20
            ));
        }
        let ti = "<iq from='room@c/focus' id='t1' type='set' xmlns='jabber:client'><jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='s'><content name='audio'><transport><candidate ip='1.2.3.4' port='1'/></transport></content></jingle></iq>";
        server.say(ti);
        settle().await;
        assert_eq!(
            incoming.try_recv().unwrap(),
            Incoming::TransportInfo(ti.to_owned())
        );
        // Acked all the same, and the reader is alive.
        assert!(server.next().await.contains("id=\"t1\""));
        for i in 0..(INCOMING_QUEUE + 40) {
            server.say(&ti.replace("t1", &format!("t{i}")));
        }
        server.say("<r xmlns='urn:xmpp:sm:3'/>");
        settle().await;
        let mut acks = server.drain();
        assert!(
            acks.pop().unwrap().starts_with("<a h="),
            "the reader answered after a full channel"
        );
        assert!(incoming.try_recv().is_ok());
        assert!(!conn.is_closed());
    }

    /// A connection is its handles': when the last of them is dropped
    /// without a close (a join whose future was dropped after the login, a
    /// rejoin aborted between the old connection's leave and its close) the
    /// transport is closed, once, and the keepalive asks no more. Go has no
    /// such case: a goroutine is not dropped. A clone keeps the connection.
    #[tokio::test(start_paused = true)]
    async fn a_connection_nobody_holds_any_more_is_closed() {
        let (conn, _inc, mut server) = up().await;
        let second = conn.clone();
        drop(conn);
        settle().await;
        assert_eq!(server.closes(), 0, "a clone still holds it");
        assert!(!second.is_closed());
        drop(second);
        settle().await;
        assert_eq!(server.closes(), 1, "the transport was not closed");
        // Left open, it would ask at SM_INTERVAL.
        tokio::time::sleep(SM_INTERVAL + SM_ACK_WAIT + S(5)).await;
        settle().await;
        assert!(
            server.drain().is_empty(),
            "a connection nobody holds still asks <r/>"
        );
        assert_eq!(server.closes(), 1);
    }

    /// A connection that was closed is not closed again when its handles go,
    /// and one the server hung up on has nothing left to close.
    #[tokio::test(start_paused = true)]
    async fn the_last_handle_of_a_closed_connection_closes_nothing_more() {
        let (conn, _inc, server) = up().await;
        let second = conn.clone();
        conn.close().await;
        assert_eq!(server.closes(), 1);
        drop(conn);
        drop(second);
        settle().await;
        assert_eq!(server.closes(), 1);

        let (conn, _inc, mut server) = up().await;
        server.hang_up();
        conn.closed().await;
        drop(conn);
        settle().await;
        assert_eq!(server.closes(), 0);
    }

    /// `TestStress_ReadLoopCloseRace`: the server hanging up closes the
    /// connection and every wait.
    #[tokio::test(start_paused = true)]
    async fn a_hangup_closes_the_connection() {
        let (conn, _inc, mut server) = up().await;
        let c2 = conn.clone();
        let t = tokio::spawn(async move { c2.wait_session_initiate(S(60)).await });
        settle().await;
        server.hang_up();
        assert_eq!(t.await.unwrap(), Err(ConnError::JoinClosed));
        conn.closed().await;
        assert!(conn.is_closed());
        assert_eq!(conn.send("x").await, Err(ConnError::Closed));
    }
}

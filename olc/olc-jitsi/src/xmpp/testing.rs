// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! An in-memory XMPP server for the connection's tests: the transport is a
//! pair of channels (Go's `mockTransport`, `conn_test.go:27-75`), and the
//! test plays the server. And [`BoshServer`], a BOSH connection manager with
//! a Prosody and a Jicofo behind it, for the tests of [`super::bosh`].

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::bosh::Post;
use super::conn::{BoxFut, ConnError, Framing, Rx, Tx};
use crate::xml;

/// The client's half of the pipe.
pub struct MemTx {
    out: mpsc::UnboundedSender<String>,
    closed: Mutex<bool>,
    bosh: bool,
}

/// What a BOSH pipe's `sent` shows where the client asked for the stream's
/// restart: a request of the transport's own, not a stanza.
pub const RESTART: &str = "(restart)";

/// The client's receiving half.
pub struct MemRx {
    inbound: mpsc::UnboundedReceiver<String>,
}

/// The test's half: what the client sent, and a way to say something to it.
pub struct Server {
    /// What the client wrote, in order.
    pub sent: mpsc::UnboundedReceiver<String>,
    to_client: Option<mpsc::UnboundedSender<String>>,
}

impl Server {
    /// Says `stanza` to the client.
    pub fn say(&self, stanza: &str) {
        if let Some(tx) = &self.to_client {
            let _ = tx.send(stanza.to_owned());
        }
    }

    /// The server goes away: the client's reads fail.
    pub fn hang_up(&mut self) {
        self.to_client = None;
    }

    /// The next stanza the client wrote; waits for it.
    pub async fn next(&mut self) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(60), self.sent.recv())
            .await
            .expect("the client wrote nothing in a minute")
            .expect("the client's writer is gone")
    }

    /// Everything the client wrote so far, without waiting.
    pub fn drain(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(s) = self.sent.try_recv() {
            out.push(s);
        }
        out
    }
}

/// A transport and the server's end of it.
#[must_use]
pub fn pipe() -> (MemTx, MemRx, Server) {
    let (out, sent) = mpsc::unbounded_channel();
    let (to_client, inbound) = mpsc::unbounded_channel();
    (
        MemTx {
            out,
            closed: Mutex::new(false),
            bosh: false,
        },
        MemRx { inbound },
        Server {
            sent,
            to_client: Some(to_client),
        },
    )
}

/// A transport that says it is BOSH: the login opens no stream and asks the
/// transport for the restart, which shows in `sent` as [`RESTART`].
#[must_use]
pub fn pipe_bosh() -> (MemTx, MemRx, Server) {
    let (mut tx, rx, server) = pipe();
    tx.bosh = true;
    (tx, rx, server)
}

impl Tx for MemTx {
    fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), ConnError>> {
        Box::pin(async move {
            if *self.closed.lock().unwrap() {
                return Err(ConnError::Transport("closed".into()));
            }
            self.out
                .send(text.to_owned())
                .map_err(|_| ConnError::Transport("the server is gone".into()))
        })
    }

    fn close(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            *self.closed.lock().unwrap() = true;
        })
    }

    fn framing(&self) -> Framing {
        if self.bosh {
            Framing::Bosh
        } else {
            Framing::WebSocket
        }
    }

    fn restart(&self) -> BoxFut<'_, Result<(), ConnError>> {
        Box::pin(async move {
            self.out
                .send(RESTART.to_owned())
                .map_err(|_| ConnError::Transport("the server is gone".into()))
        })
    }
}

impl Rx for MemRx {
    fn recv(&mut self) -> BoxFut<'_, Result<String, ConnError>> {
        Box::pin(async move {
            self.inbound
                .recv()
                .await
                .ok_or_else(|| ConnError::Transport("the server hung up".into()))
        })
    }
}

/// The server's side of a login that succeeds: reads the client's six
/// stanzas and answers each as Prosody does, binding `jid`.
pub async fn serve_login(server: &mut Server, jid: &str) {
    let open = server.next().await;
    assert!(open.starts_with("<open "), "{open}");
    server.say("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='meet.example' version='1.0' id='s1'/>");
    server.say("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>");
    let auth = server.next().await;
    assert!(auth.starts_with("<auth "), "{auth}");
    server.say("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
    let open = server.next().await;
    assert!(open.starts_with("<open "), "{open}");
    server.say("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='meet.example' version='1.0' id='s2'/>");
    server.say("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>");
    let bind = server.next().await;
    assert!(bind.contains("bind_1"), "{bind}");
    server.say(&format!(
        "<iq type='result' id='bind_1' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>{jid}</jid></bind></iq>"
    ));
    let sess = server.next().await;
    assert!(sess.contains("sess_1"), "{sess}");
    server.say("<iq type='result' id='sess_1' xmlns='jabber:client'/>");
    let enable = server.next().await;
    assert!(enable.starts_with("<enable "), "{enable}");
    server.say("<enabled xmlns='urn:xmpp:sm:3' id='sm1' resume='true'/>");
}

/// The session id [`BoshServer`] gives.
pub const BOSH_SID: &str = "sid-0001";
/// After this many requests a [`BoshServer`] fails every one: a client that
/// spins ends the test instead of hanging it.
pub const BOSH_SPIN: usize = 2_000;

const BOSH_NS: &str = "http://jabber.org/protocol/httpbind";
const BOSH_TERMINATE: &str = "<body type='terminate' xmlns='http://jabber.org/protocol/httpbind'/>";

/// A BOSH connection manager as Prosody's is (XEP-0124), with the fake
/// room's Prosody and Jicofo behind it: one request is held, a second
/// releases the older, what the server says goes out on the oldest held
/// request, and a held request is answered empty after `hold`.
#[derive(Clone)]
pub struct BoshServer(Arc<Mutex<BoshState>>);

/// What a [`BoshServer`] saw and how it behaves.
pub struct BoshState {
    /// Every request body, as they arrived.
    pub bodies: Vec<String>,
    /// Every stanza the client sent.
    pub said: Vec<String>,
    /// The most requests open at once.
    pub max_open: usize,
    /// How long a request is held before it is answered empty.
    pub hold: Duration,
    /// Every request is answered at once, with what there is to say or
    /// empty: a manager that holds nothing.
    pub at_once: bool,
    /// A held request is never answered empty.
    pub mute: bool,
    /// The next request fails with this text; with `fail_when`, the next
    /// one whose body holds those words.
    pub fail: Option<String>,
    /// Which request `fail` is for.
    pub fail_when: Option<&'static str>,
    /// What the session request is answered with, instead of a session.
    pub create: Option<String>,
    /// The JID the bind gives.
    pub jid: String,
    /// The client said terminate.
    pub terminated: bool,
    /// Said as soon as the next request that carries a stanza is on hold: it
    /// goes back on that request, the poll before it having gone back empty.
    pub late: Option<String>,
    /// A request that carries a stanza is never answered.
    pub stall: bool,
    open: usize,
    seq: u64,
    held: VecDeque<(u64, oneshot::Sender<String>)>,
    out: VecDeque<(String, bool)>,
}

struct BoshOpen(Arc<Mutex<BoshState>>);

impl Drop for BoshOpen {
    fn drop(&mut self) {
        self.0.lock().unwrap().open -= 1;
    }
}

fn bosh_wrap(stanzas: &str) -> String {
    if stanzas.is_empty() {
        format!("<body xmlns='{BOSH_NS}' xmlns:stream='http://etherx.jabber.org/streams' sid='{BOSH_SID}'/>")
    } else {
        format!("<body xmlns='{BOSH_NS}' xmlns:stream='http://etherx.jabber.org/streams' sid='{BOSH_SID}'>{stanzas}</body>")
    }
}

impl BoshState {
    /// Answers the oldest held request while there is something to say or
    /// more than one is held.
    fn flush(&mut self) {
        // A request its client hung up on holds nothing.
        self.held.retain(|(_, tx)| !tx.is_closed());
        while !self.held.is_empty() && (!self.out.is_empty() || self.held.len() > 1) {
            let (_, tx) = self.held.pop_front().unwrap();
            let _ = tx.send(self.next_body());
        }
    }

    /// What there is to say, as one answer; an empty one when nothing.
    fn next_body(&mut self) -> String {
        if matches!(self.out.front(), Some((_, true))) {
            return self.out.pop_front().unwrap().0;
        }
        let mut stanzas = String::new();
        while matches!(self.out.front(), Some((_, false))) {
            stanzas.push_str(&self.out.pop_front().unwrap().0);
        }
        bosh_wrap(&stanzas)
    }

    /// Prosody and Jicofo: what one stanza of the client is answered with.
    fn answer(&mut self, t: &str) {
        let mut say = |s: String| self.out.push_back((s, false));
        if t.starts_with("<auth ") {
            say("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".into());
        } else if t.contains("bind_1") {
            say(format!("<iq type='result' id='bind_1' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>{}</jid></bind></iq>", self.jid));
        } else if t.contains("sess_1") {
            say("<iq type='result' id='sess_1' xmlns='jabber:client'/>".into());
        } else if t.contains("focus_1") {
            say("<iq id='focus_1' type='result' xmlns='jabber:client'><conference xmlns='http://jitsi.org/protocol/focus' ready='true'/></iq>".into());
        } else if t.contains("disco_1") {
            say("<iq id='disco_1' type='result' xmlns='jabber:client'><services xmlns='urn:xmpp:extdisco:2'><service type='stun' host='stun.example'/></services></iq>".into());
        } else if t.starts_with("<presence ") {
            let to = t
                .split("to=\"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .unwrap_or("");
            let kind = if t.contains("type=\"unavailable\"") {
                " type='unavailable'"
            } else {
                ""
            };
            say(format!("<presence from='{to}'{kind} xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'><status code='110'/></x></presence>"));
        }
    }
}

impl Default for BoshServer {
    fn default() -> Self {
        Self::new()
    }
}

impl BoshServer {
    /// A manager that holds a request for a minute and binds
    /// `fedcba9876543210@meet.jitsi/res`.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(BoshState {
            bodies: Vec::new(),
            said: Vec::new(),
            max_open: 0,
            hold: Duration::from_secs(60),
            at_once: false,
            mute: false,
            fail: None,
            fail_when: None,
            create: None,
            jid: "fedcba9876543210@meet.jitsi/res".into(),
            terminated: false,
            late: None,
            stall: false,
            open: 0,
            seq: 0,
            held: VecDeque::new(),
            out: VecDeque::new(),
        })))
    }

    /// What it saw, and its switches.
    pub fn state(&self) -> std::sync::MutexGuard<'_, BoshState> {
        self.0.lock().unwrap()
    }

    /// Says `stanza` to the client on its next answer.
    pub fn say(&self, stanza: &str) {
        let mut st = self.state();
        st.out.push_back((stanza.to_owned(), false));
        st.flush();
    }

    /// Answers the client's next request with `body`, whole.
    pub fn say_whole(&self, body: &str) {
        let mut st = self.state();
        st.out.push_back((body.to_owned(), true));
        st.flush();
    }

    /// The request bodies in the order of their request ids, with the id as
    /// `RID` and the session id as `SID`, and whether the ids go up by one
    /// from the first (`BOSHBodies` of the Go fake).
    #[must_use]
    pub fn normalised(&self) -> (Vec<String>, bool) {
        let st = self.state();
        let mut reqs: Vec<(u64, &String)> = st
            .bodies
            .iter()
            .map(|b| {
                let rid = xml::root(b)
                    .ok()
                    .and_then(|r| r.attr("rid").ok().flatten().and_then(|v| v.parse().ok()))
                    .expect("a request has a rid");
                (rid, b)
            })
            .collect();
        reqs.sort_by_key(|(rid, _)| *rid);
        let consecutive = reqs.windows(2).all(|w| w[1].0 == w[0].0 + 1);
        let bodies = reqs
            .iter()
            .map(|(rid, b)| {
                b.replacen(&format!("rid=\"{rid}\""), "rid=\"RID\"", 1)
                    .replacen(&format!("sid=\"{BOSH_SID}\""), "sid=\"SID\"", 1)
            })
            .collect();
        (bodies, consecutive)
    }

    async fn serve(&self, body: String) -> Result<String, String> {
        let stalled = {
            let st = self.state();
            st.stall && !body.ends_with("/>")
        };
        if stalled {
            self.state().bodies.push(body);
            return std::future::pending().await;
        }
        let (id, mut rx, hold, mute) = {
            let mut st = self.state();
            st.bodies.push(body.clone());
            if st.bodies.len() > BOSH_SPIN {
                return Err("the client spins".into());
            }
            if st.fail_when.is_none_or(|w| body.contains(w)) {
                if let Some(e) = st.fail.take() {
                    return Err(e);
                }
            }
            let root = xml::root(&body).map_err(|e| format!("a request that is not XML: {e}"))?;
            let attr = |n: &str| root.attr(n).ok().flatten().unwrap_or_default().into_owned();
            if attr("sid").is_empty() {
                return Ok(st.create.clone().unwrap_or_else(|| format!(
                    "<body xmlns='{BOSH_NS}' xmlns:stream='http://etherx.jabber.org/streams' xmlns:xmpp='urn:xmpp:xbosh' sid='{BOSH_SID}' wait='60' requests='2' inactivity='60' hold='1' polling='5' ver='1.6' xmpp:version='1.0' authid='{BOSH_SID}' from='meet.jitsi' secure='true'><stream:features xmlns='jabber:client'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features></body>"
                )));
            }
            if st.terminated {
                return Ok(BOSH_TERMINATE.into());
            }
            if attr("type") == "terminate" {
                st.terminated = true;
                for (_, tx) in st.held.drain(..) {
                    let _ = tx.send(BOSH_TERMINATE.into());
                }
                return Ok(BOSH_TERMINATE.into());
            }
            let mut carried = false;
            if attr("xmpp:restart") == "true" {
                st.out.push_back(("<stream:features xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></stream:features>".into(), false));
            } else {
                let stanzas: Vec<String> = xml::children(&body)
                    .map_err(|e| format!("a request that is not XML: {e}"))?
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                carried = !stanzas.is_empty();
                for t in stanzas {
                    st.answer(&t);
                    st.said.push(t);
                }
            }
            if st.at_once {
                return Ok(st.next_body());
            }
            let (tx, rx) = oneshot::channel();
            st.seq += 1;
            let id = st.seq;
            st.held.push_back((id, tx));
            st.flush();
            if carried {
                if let Some(late) = st.late.take() {
                    st.out.push_back((late, false));
                    st.flush();
                }
            }
            (id, rx, st.hold, st.mute)
        };
        tokio::select! {
            biased;
            r = &mut rx => return r.map_err(|_| "the server is gone".to_owned()),
            () = tokio::time::sleep(hold), if !mute => {}
        }
        let mine = {
            let mut st = self.state();
            let at = st.held.iter().position(|(i, _)| *i == id);
            at.map(|i| st.held.remove(i)).is_some()
        };
        if mine {
            Ok(bosh_wrap(""))
        } else {
            rx.await.map_err(|_| "the server is gone".to_owned())
        }
    }
}

impl Post for BoshServer {
    fn post(&self, body: String, timeout: Duration) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async move {
            let _open = {
                let mut st = self.state();
                st.open += 1;
                st.max_open = st.max_open.max(st.open);
                BoshOpen(self.0.clone())
            };
            match tokio::time::timeout(timeout, self.serve(body)).await {
                Ok(r) => r,
                Err(_) => Err("timed out".into()),
            }
        })
    }
}

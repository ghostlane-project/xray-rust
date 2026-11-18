// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! An in-memory XMPP server for the connection's tests: the transport is a
//! pair of channels (Go's `mockTransport`, `conn_test.go:27-75`), and the
//! test plays the server.

use std::sync::Mutex;

use tokio::sync::mpsc;

use super::conn::{BoxFut, ConnError, Rx, Tx};

/// The client's half of the pipe.
pub struct MemTx {
    out: mpsc::UnboundedSender<String>,
    closed: Mutex<bool>,
}

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
        },
        MemRx { inbound },
        Server {
            sent,
            to_client: Some(to_client),
        },
    )
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

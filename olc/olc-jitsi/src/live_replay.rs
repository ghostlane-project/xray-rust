// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A real deployment's connection, played back (plan W5; `jitsi/live.json`,
//! its `room`): everything the pinned Go engine and a real Prosody and Jicofo
//! said to each other on one WebSocket, from the first `<open>` to the third
//! stream-management answer, as the engine's log had it (docker-jitsi-meet
//! stable-11248-3, the fork's `olc-jitsi-live` workflow).
//!
//! The server's half is said again to this crate's connection, and what the
//! connection says must be what Go said, byte for byte: the login against a
//! real Prosody's features, the focus, the services query a deployment
//! refuses, the room, the answer to a Jicofo's disco#info query by node (what
//! Jicofo reads a client's features from, and decides the offer by), the
//! acknowledgements, the stream-management counts.
//!
//! The Go fake sends none of this server's extras; before the capture the
//! port had met them only in a run, never in a test.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::xmpp::conn::{Conn, ConnConfig, Tx};
use crate::xmpp::testing::pipe;

/// The room of the capture, and the name the Go engine gave itself there.
const ROOM: &str = "gate-92e942cec9a0";
const NAME: &str = "Maksim-Rodionov";
const BUDGET: Duration = Duration::from_secs(30);

/// The capture: who said each stanza (`true`: the client), and its text.
fn capture() -> Vec<(bool, String)> {
    let v = olc_interop::load("jitsi/live.json");
    v["room"]
        .as_array()
        .expect("room is a list")
        .iter()
        .map(|l: &Value| {
            (
                l["client"].as_bool().expect("client"),
                l["stanza"].as_str().expect("stanza").to_owned(),
            )
        })
        .collect()
}

/// What the read loop writes on its own (an answer to a stream-management
/// request, an IQ result); the rest is the join's sequence.
fn is_answer(stanza: &str) -> bool {
    stanza.starts_with("<a ") || stanza.contains(r#" type="result""#)
}

fn split(said: &[String]) -> (Vec<&str>, Vec<&str>) {
    let (a, j): (Vec<&str>, Vec<&str>) =
        said.iter().map(String::as_str).partition(|s| is_answer(s));
    (j, a)
}

#[tokio::test(start_paused = true)]
async fn what_go_said_to_a_real_prosody_and_jicofo_is_what_this_client_says() {
    let lines = capture();
    // The session's own stanza (the session-accept, the stack's answer inside
    // it) is not the connection's to say: `the_accept_of_a_real_offer…` in
    // vectors.rs holds its body.
    let expected: Vec<String> = lines
        .iter()
        .filter(|(client, s)| *client && !s.contains(r#"id="accept_1""#))
        .map(|(_, s)| s.clone())
        .collect();
    assert_eq!(lines.len(), 47);
    assert_eq!(expected.len(), 17);

    let (tx, rx, mut server) = pipe();
    let tx: Arc<dyn Tx> = Arc::new(tx);
    let cfg = ConnConfig {
        host: "meet.jitsi-live.test".into(),
        room: ROOM.into(),
        xmpp_domain: "meet.jitsi".into(),
        muc_domain: "muc.meet.jitsi".into(),
    };
    // The steps of `join::join_once` once the socket is up.
    let join = tokio::spawn(async move {
        let (conn, incoming) = Conn::login(tx, rx, cfg, BUDGET).await?;
        let focus = conn.allocate_focus(BUDGET).await?;
        let services = conn.discover_services(BUDGET).await?;
        conn.join_muc(NAME, BUDGET).await?;
        Ok::<_, crate::xmpp::conn::ConnError>((conn, incoming, focus, services))
    });

    // The playback. The server's stanzas are said in the capture's order.
    // Where the capture has the client speak, the playback waits until this
    // client has said that very stanza: the read loop and the join write on
    // their own, so one may be ahead of the other, and what came early is
    // kept for its turn. A client that never says it stops the playback;
    // the comparison below then shows what it said instead.
    let mut said: Vec<String> = Vec::new();
    let mut early: Vec<String> = Vec::new();
    let mut peers_mid_way = None;
    let mut conn_parts = None;
    let mut join = Some(join);
    'play: for (i, (client, stanza)) in lines.iter().enumerate() {
        if !*client {
            server.say(stanza);
            continue;
        }
        if stanza.contains(r#"id="accept_1""#) {
            // The offer is in, and the first peer with it.
            let parts = join.take().expect("one accept").await.unwrap().unwrap();
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
            peers_mid_way = Some(parts.0.occupants());
            conn_parts = Some(parts);
            continue;
        }
        if let Some(at) = early.iter().position(|s| s == stanza) {
            early.remove(at);
            continue;
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(2), server.sent.recv()).await {
                Ok(Some(s)) => {
                    said.push(s.clone());
                    if &s == stanza {
                        break;
                    }
                    early.push(s);
                }
                _ => {
                    eprintln!("the playback stops at line {i}: the client did not say {stanza}");
                    break 'play;
                }
            }
        }
    }
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    said.extend(server.drain());

    let (want_join, want_answers) = split(&expected);
    let (got_join, got_answers) = split(&said);
    assert_eq!(got_join, want_join, "the join's stanzas");
    assert_eq!(got_answers, want_answers, "the read loop's answers");
    // The answer Jicofo reads this client's features from is among them.
    assert_eq!(
        got_answers
            .iter()
            .filter(|s| s.contains("disco#info") && s.matches("<feature ").count() == 16)
            .count(),
        1
    );

    let (conn, _incoming, focus, services) =
        conn_parts.expect("the join returned before the offer was answered");
    assert_eq!(
        conn.jid(),
        "041fd969-b171-40bd-ae32-0a93edb24906@meet.jitsi/_DOJWIKxS4JB"
    );
    assert_eq!(conn.nick(), "041fd969");
    assert!(focus.ready);
    // This deployment has no XEP-0215 services: the query's error is "none".
    assert!(services.is_empty());
    // The peer that had joined when the offer came, and nobody at the end:
    // both peers of the capture left. The focus is never an occupant.
    assert_eq!(peers_mid_way.unwrap(), ["279a5104"]);
    assert!(conn.occupants().is_empty());
    assert!(!conn.is_closed());
    let offer = conn
        .wait_session_initiate(Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(offer.sid, "8k1vkqbdjoecd");
    assert_eq!(offer.initiator, "focus@auth.meet.jitsi/focus");
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The session end to end, in one process: a fake Prosody and Jicofo over a
//! real WebSocket (the join's fake), whose offer is a str0m peer's put through
//! the converter (its SDP written as a `session-initiate`); and that peer as
//! the JVB, which takes the data channel's open, answers the hello and relays
//! frames between the client and a made-up other endpoint.
//!
//! What it proves is the pipeline's own: the offer as Jingle, as SDP, as the
//! stack's answer, as the `session-accept`, back as an SDP the bridge peer
//! takes, DTLS and SCTP up, the channel opened with its label and protocol,
//! the hello exchange, frames both ways, the keepalive video. What it cannot
//! prove is that a real Jicofo and a real JVB accept the same bytes: that is
//! plan W5.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use olc_rtc::peer::{IceMode, Peer, PeerConfig, PeerEvent};
use olc_rtc::str0m::change::{SdpAnswer, SdpPendingOffer};
use olc_rtc::str0m::channel::{ChannelConfig, ChannelId, Reliability};
use olc_rtc::str0m::media::{Direction, MediaKind};
use olc_rtc::str0m::rtp::RtpPacket;
use olc_rtc::str0m::Candidate;
use olc_rtc::DtlsVersion;
use tokio::sync::mpsc;

use crate::frame::{decode_raw, encode_frame, endpoint_message, Message, CLIENT_HELLO};
use crate::jingle::build::accept_body;
use crate::jingle::parse::parse_stanza;
use crate::jingle::sdp::to_sdp;
use crate::join::tests::{fake_with, AfterJoin, Fake, Opts};
use crate::join::{JoinConfig, Limits};
use crate::relaywin::Timing;
use crate::session::{Session, SessionConfig, CHANNEL_LABEL, CHANNEL_PROTOCOL};

const MIDS: [&str; 3] = ["audio", "video", "data"];

/// `sdp` with its sections' mids renamed to `to` in order, its group rewritten;
/// the old mids come back.
fn remid(sdp: &str, to: &[&str]) -> (String, Vec<String>) {
    let mut old = Vec::new();
    let mut out = String::new();
    for line in sdp.lines() {
        if let Some(m) = line.strip_prefix("a=mid:") {
            old.push(m.to_owned());
            out.push_str(&format!("a=mid:{}\r\n", to[old.len() - 1]));
        } else if line.starts_with("a=group:BUNDLE") {
            out.push_str(&format!("a=group:BUNDLE {}\r\n", to.join(" ")));
        } else {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    (out, old)
}

fn config(name: &'static str) -> PeerConfig {
    PeerConfig {
        name,
        crypto: olc_rtc::crypto(),
        dtls_version: DtlsVersion::Dtls12,
        host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        sctp_max_buffered: 1 << 20,
        turn: Vec::new(),
        relay_only: false,
        ice_mode: IceMode::Udp,
    }
}

async fn until<F: FnMut() -> bool>(what: &str, mut f: F) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what}: not within 10 s");
}

/// The JVB: a peer that offers audio, video and data, and the loop that plays
/// the bridge's part on the client's channel.
struct Jvb {
    peer: Peer,
    pending: Option<SdpPendingOffer>,
    old_mids: Vec<String>,
    offer: String,
    events: Option<mpsc::Receiver<PeerEvent>>,
}

fn jvb() -> Jvb {
    olc_rtc::init();
    let (peer, events) = Peer::start(&config("jvb")).unwrap();
    let (offer, pending) = peer.with_rtc(|rtc| {
        let mut api = rtc.sdp_api();
        api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        api.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
        api.add_channel_with_config(ChannelConfig {
            label: "bridge-side".into(),
            ordered: true,
            reliability: Reliability::Reliable,
            negotiated: Some(1001),
            protocol: String::new(),
        });
        api.apply().unwrap()
    });
    let host = peer.gather().unwrap().expect("a host candidate");
    let (mut named, old) = remid(&offer.to_sdp_string(), &MIDS);
    // The host candidate stands in the first section, as a bridge's do.
    let at = named.find("m=video").unwrap();
    named.insert_str(at, &format!("a={host}\r\n"));
    Jvb {
        peer,
        pending: Some(pending),
        old_mids: old,
        offer: named,
        events: Some(events),
    }
}

/// The offer as the focus's `session-initiate`.
fn initiate(offer: &str) -> String {
    format!(
        "<iq from='secret-room@muc.meet.jitsi/focus' to='x@meet.jitsi/res' id='si1' type='set' xmlns='jabber:client'>\
         <jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' initiator='secret-room@muc.meet.jitsi/focus' sid='sid-e2e'>{}</jingle></iq>",
        accept_body(offer)
    )
}

/// The bridge side of one peer connection, once the client has answered.
struct Side {
    peer: Peer,
    frames: mpsc::UnboundedReceiver<Message>,
    chan: Arc<Mutex<Option<ChannelId>>>,
    seen_cfg: Arc<Mutex<Option<(String, String)>>>,
    video_in: Arc<AtomicU64>,
}

/// Takes the client's `session-accept` as the answer of `jvb` and plays the
/// bridge: the hello is answered, the client's frames are handed to the test.
async fn serve_bridge(mut jvb: Jvb, accept: &str) -> Side {
    let j = parse_stanza(accept).unwrap();
    let candidates: Vec<String> = j
        .contents
        .iter()
        .filter_map(|c| c.transport.as_ref())
        .flat_map(|t| t.candidates.iter())
        .filter_map(crate::jingle::parse::candidate_line)
        .collect();
    assert!(
        !candidates.is_empty(),
        "the accept carries a host candidate: {accept}"
    );
    let old: Vec<&str> = jvb.old_mids.iter().map(String::as_str).collect();
    let (answer, _) = remid(&to_sdp(&j), &old);
    let answer = SdpAnswer::from_sdp_string(&answer)
        .unwrap_or_else(|e| panic!("the bridge refuses the answer: {e}\n{answer}"));
    let pending = jvb.pending.take().unwrap();
    jvb.peer
        .with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, answer))
        .expect("accept_answer");
    for c in &candidates {
        jvb.peer
            .add_remote_candidate(Candidate::from_sdp_string(c).unwrap());
    }
    let video_in = Arc::new(AtomicU64::new(0));
    let v2 = video_in.clone();
    jvb.peer.set_rtp_sink(Some(Box::new(move |_p: &RtpPacket| {
        v2.fetch_add(1, Ordering::Relaxed);
    })));
    let mut events = jvb.events.take().unwrap();
    let (frames_tx, frames) = mpsc::unbounded_channel::<Message>();
    let seen_cfg: Arc<Mutex<Option<(String, String)>>> = Arc::default();
    let chan: Arc<Mutex<Option<ChannelId>>> = Arc::default();
    let (cc, ci, bp) = (seen_cfg.clone(), chan.clone(), jvb.peer.clone());
    tokio::spawn(async move {
        let mut hello = false;
        while let Some(ev) = events.recv().await {
            match ev {
                PeerEvent::ChannelOpen(id, label) if label == CHANNEL_LABEL => {
                    let cfg = bp.with_rtc(|rtc| rtc.channel(id).and_then(|c| c.config().cloned()));
                    *cc.lock().unwrap() = cfg.map(|c| (c.label, c.protocol));
                    *ci.lock().unwrap() = Some(id);
                }
                PeerEvent::Data(inb) => {
                    let Ok(text) = std::str::from_utf8(&inb.data) else {
                        continue;
                    };
                    if text == CLIENT_HELLO && !hello {
                        hello = true;
                        let _ = bp.write(inb.channel, false, br#"{"colibriClass":"ServerHello"}"#);
                    } else if let Some(m) = Message::parse(text) {
                        let _ = frames_tx.send(m);
                    }
                }
                _ => {}
            }
        }
    });
    Side {
        peer: jvb.peer,
        frames,
        chan,
        seen_cfg,
        video_in,
    }
}

impl Side {
    /// Reads the client's frames until one carries `want`.
    async fn expect_frame(&mut self, want: &[u8]) -> Vec<u8> {
        for _ in 0..100 {
            let m = tokio::time::timeout(Duration::from_secs(5), self.frames.recv())
                .await
                .expect("no frame from the client in 5 s")
                .expect("the bridge's queue ended");
            assert_eq!(m.class, "EndpointMessage");
            let raw = decode_raw(&m).expect("a raw payload");
            assert_eq!(&raw[..4], b"OLR1");
            if &raw[12..] == want {
                return raw;
            }
        }
        panic!("the client's frame {want:?} did not reach the bridge");
    }

    /// Says `data` as if another endpoint sent it.
    fn say_from_other(&self, data: &[u8]) {
        let frame = encode_frame(data, 0xb0b0_b0b0, 0).unwrap();
        let json = endpoint_message("", &frame)
            .replace("\"to\":\"\"", "\"to\":\"\",\"from\":\"ep-other\"");
        let id = self.chan.lock().unwrap().expect("the channel's id");
        assert!(self.peer.write(id, false, json.as_bytes()).unwrap());
    }
}

const DOCKER: &str = "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nconfig.hosts.muc = 'muc.meet.jitsi';\n";

type Pool = Arc<Mutex<Vec<Option<Jvb>>>>;

/// A Jicofo that offers a new bridge peer's offer each time a client joins.
async fn fake_jicofo(pool: &Pool, offers: bool) -> Fake {
    let after: Option<AfterJoin> = offers.then(|| {
        let pool = pool.clone();
        Arc::new(move || {
            let j = jvb();
            let st = initiate(&j.offer);
            pool.lock().unwrap().push(Some(j));
            vec![st]
        }) as AfterJoin
    });
    fake_with(
        vec![(200, "application/javascript", DOCKER.into()); 20],
        "meet.jitsi",
        Opts {
            after_join: after,
            turn: false,
            deflate: false,
            ..Opts::default()
        },
    )
    .await
}

struct Seen2 {
    data: Arc<Mutex<Vec<Vec<u8>>>>,
    ended: Arc<Mutex<Vec<String>>>,
    reconnected: Arc<AtomicU64>,
}

async fn connect(f: &Fake, times: crate::session::RejoinTimes) -> (Session, Seen2) {
    let mut join = JoinConfig::new(
        "web.example",
        "secret-room",
        "olcrtc",
        Duration::from_secs(20),
    );
    join.config_base = Some(format!("http://{}", f.addr));
    join.ws_url = Some(format!("ws://{}/xmpp-websocket", f.addr));
    join.limits = Limits::default();
    let seen = Seen2 {
        data: Arc::default(),
        ended: Arc::default(),
        reconnected: Arc::default(),
    };
    let (d, e, r) = (
        seen.data.clone(),
        seen.ended.clone(),
        seen.reconnected.clone(),
    );
    let session = Session::connect(SessionConfig {
        join,
        host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        relay_only: false,
        require_targeted_peer: false,
        on_data: Arc::new(move |b| d.lock().unwrap().push(b.to_vec())),
        on_data_async: None,
        on_ended: Arc::new(move |why| e.lock().unwrap().push(why.to_owned())),
        on_reconnected: Arc::new(move || {
            r.fetch_add(1, Ordering::Relaxed);
        }),
        times,
        timing: Timing::default(),
    })
    .await
    .expect("the join");
    (session, seen)
}

/// Waits for connection `index`'s `session-accept` and returns it.
async fn accept_of(f: &Fake, index: usize) -> String {
    for _ in 0..500 {
        {
            let s = f.seen.lock().unwrap();
            if let Some(v) = s.said.get(index) {
                if let Some(x) = v.iter().find(|x| x.contains("action=\"session-accept\"")) {
                    return x.clone();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let s = f.seen.lock().unwrap();
    let shown: Vec<String> = s
        .said
        .iter()
        .enumerate()
        .map(|(i, v)| {
            format!(
                "#{i}[{}]",
                v.iter()
                    .map(|x| x.chars().skip(1).take(14).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect();
    panic!("NOACCEPT on connection {index}: {}", shown.join(" "));
}

fn take_jvb(pool: &Pool, index: usize) -> Jvb {
    pool.lock().unwrap()[index]
        .take()
        .expect("the connection's bridge peer")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_joins_answers_opens_the_bridge_and_moves_frames_both_ways() {
    let pool: Pool = Arc::default();
    let f = fake_jicofo(&pool, true).await;
    let (session, seen) = connect(&f, crate::session::RejoinTimes::default()).await;
    let accept = accept_of(&f, 0).await;
    assert!(
        accept.contains("to=\"secret-room@muc.meet.jitsi/focus\""),
        "{accept}"
    );
    assert!(accept.contains("id=\"accept_1\""), "{accept}");
    assert!(accept.contains("sid=\"sid-e2e\""), "{accept}");
    assert!(
        accept.contains("name=\"audio\" senders=\"initiator\""),
        "{accept}"
    );
    assert!(accept.contains("setup=\"active\""), "{accept}");
    assert!(
        accept.contains("mslabel") && accept.contains("jitsi-ka-"),
        "{accept}"
    );
    let mut side = serve_bridge(take_jvb(&pool, 0), &accept).await;
    until("the bridge to open", || session.can_send()).await;
    assert_eq!(
        side.seen_cfg.lock().unwrap().clone(),
        Some((CHANNEL_LABEL.to_owned(), CHANNEL_PROTOCOL.to_owned())),
        "the bridge saw the channel's open with its label and protocol"
    );
    session.send(b"world").await.unwrap();
    side.expect_frame(b"world").await;
    side.say_from_other(b"hello from the peer");
    until("the peer's data", || {
        seen.data
            .lock()
            .unwrap()
            .iter()
            .any(|d| d == b"hello from the peer")
    })
    .await;
    assert!(session.peer_seen());
    until("the keepalive video", || {
        side.video_in.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert!(seen.ended.lock().unwrap().is_empty());
    session.close().await;
    until("the leave", || {
        f.seen.lock().unwrap().said[0]
            .iter()
            .any(|s| s.contains("type=\"unavailable\""))
    })
    .await;
}

/// J17: the bridge closes; the session joins again, answers the new offer
/// under a new epoch and traffic goes both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_bridge_is_rejoined_under_a_new_epoch() {
    let pool: Pool = Arc::default();
    let f = fake_jicofo(&pool, true).await;
    let (session, seen) = connect(&f, crate::session::RejoinTimes::default()).await;
    let accept = accept_of(&f, 0).await;
    let side1 = serve_bridge(take_jvb(&pool, 0), &accept).await;
    until("the bridge to open", || session.can_send()).await;
    let first_epoch = session.local_peer_id();
    // The bridge closes the client's channel, as a JVB that lost it does.
    let id = side1.chan.lock().unwrap().expect("the channel's id");
    side1
        .peer
        .with_rtc(|rtc| rtc.direct_api().close_data_channel(id));
    until("a second connection", || {
        f.seen.lock().unwrap().upgrades.len() >= 2
    })
    .await;
    until("the second offer", || pool.lock().unwrap().len() >= 2).await;
    let accept2 = accept_of(&f, 1).await;
    let mut side2 = serve_bridge(take_jvb(&pool, 1), &accept2).await;
    until("the reconnect", || {
        seen.reconnected.load(Ordering::Relaxed) >= 1
    })
    .await;
    until("the bridge to open again", || session.can_send()).await;
    assert_ne!(session.local_peer_id(), first_epoch, "a new local epoch");
    session.send(b"again").await.unwrap();
    side2.expect_frame(b"again").await;
    side2.say_from_other(b"after the rejoin");
    until("data after the rejoin", || {
        seen.data
            .lock()
            .unwrap()
            .iter()
            .any(|d| d == b"after the rejoin")
    })
    .await;
    // The old connection left the room before the new one joined.
    assert!(f.seen.lock().unwrap().said[0]
        .iter()
        .any(|s| s.contains("type=\"unavailable\"")));
    assert!(seen.ended.lock().unwrap().is_empty());
    session.close().await;
}

/// Alone in the room a rejoin parks and fails nothing: the count stays at
/// nothing however often it is asked for (`errNoPeer`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alone_in_the_room_a_rejoin_parks_and_counts_no_failure() {
    let pool: Pool = Arc::default();
    let f = fake_jicofo(&pool, false).await;
    let times = crate::session::RejoinTimes {
        join: Duration::from_secs(10),
        reinitiate: Duration::from_millis(200),
        full: Duration::from_millis(200),
    };
    let (session, seen) = connect(&f, times).await;
    for round in 1..=(crate::session::MAX_RECONNECTS as usize + 1) {
        session.reconnect("test");
        until("both joins of the round", || {
            f.seen.lock().unwrap().upgrades.len() > 2 * round
        })
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        seen.ended.lock().unwrap().is_empty(),
        "ended: {:?}",
        seen.ended.lock().unwrap()
    );
    assert_eq!(seen.reconnected.load(Ordering::Relaxed), 0);
    session.close().await;
}

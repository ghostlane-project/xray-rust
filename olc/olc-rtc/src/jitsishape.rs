// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! J0 of the Jitsi port (plan `m10-jitsi-plan.md` section 6): what str0m does
//! with the shape of a Jitsi offer, observed on two loopback peers. The
//! "bridge" is a str0m peer whose offer is turned into the text the Jingle to
//! SDP converter will write (audio, video and data sections with the mids
//! `audio`, `video`, `data`; session-level `msid-semantic`; `a=rtcp:9`;
//! `max-message-size`; `a=setup:actpass`, read as `passive`). The "client" is
//! the peer the Jitsi engine will run. Nothing here is engine code: each test
//! is one line of the plan's list, and a red one names a patch or a
//! workaround.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::rtp::RtpPacket;
use str0m::Candidate;
use tokio::sync::mpsc;

use crate::media::{RtpOut, SendLine};
use crate::peer::{IceMode, Peer, PeerConfig, PeerEvent};
use crate::testing::bounded;
use crate::DtlsVersion;

const LABEL: &str = "JVB data channel";
const PROTOCOL: &str = "http://jitsi.org/protocols/colibri";
const MIDS: [&str; 3] = ["audio", "video", "data"];

fn config(name: &'static str) -> PeerConfig {
    PeerConfig {
        name,
        crypto: crate::crypto(),
        dtls_version: DtlsVersion::Dtls12,
        host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        sctp_max_buffered: 256 << 10,
        turn: Vec::new(),
        relay_only: false,
        ice_mode: IceMode::Udp,
    }
}

/// `sdp` with its sections' mids renamed to `to`, in order of appearance, and
/// its bundle group rewritten; the old mids come back.
fn remid(sdp: &str, to: &[&str]) -> (String, Vec<String>) {
    let mut old = Vec::new();
    let mut out = String::new();
    for line in sdp.lines() {
        if let Some(m) = line.strip_prefix("a=mid:") {
            old.push(m.to_owned());
            out.push_str(&format!("a=mid:{}\r\n", to[old.len() - 1]));
        } else {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    let group_from: Vec<String> = out
        .lines()
        .filter(|l| l.starts_with("a=group:BUNDLE"))
        .map(str::to_owned)
        .collect();
    for g in group_from {
        out = out.replace(&g, &format!("a=group:BUNDLE {}", to.join(" ")));
    }
    (out, old)
}

/// A str0m offer written the way the converter will write Jitsi's: named
/// mids, `msid-semantic`, `a=rtcp:9`, `max-message-size`, no `a=ssrc*`,
/// `actpass` read as `passive`; the mid header extension left out on request.
fn converter_shape(raw: &str, mid_ext: bool) -> (String, Vec<String>) {
    let (named, old) = remid(raw, &MIDS);
    let mut out = String::new();
    let mut in_app = false;
    for line in named.lines() {
        if line.starts_with("a=ssrc") || line.starts_with("a=msid-semantic") {
            continue;
        }
        if !mid_ext && line.starts_with("a=extmap:") && line.contains("sdes:mid") {
            continue;
        }
        if line.starts_with("m=") {
            in_app = line.starts_with("m=application");
        }
        out.push_str(&line.replace("a=setup:actpass", "a=setup:passive"));
        out.push_str("\r\n");
        if line.starts_with("t=") {
            out.push_str("a=msid-semantic: WMS *\r\n");
        }
        if line.starts_with("c=") {
            out.push_str("a=rtcp:9 IN IP4 0.0.0.0\r\n");
        }
        if in_app && line.starts_with("a=sctp-port") && !named.contains("a=max-message-size") {
            out.push_str("a=max-message-size:262144\r\n");
        }
    }
    (out, old)
}

struct Rig {
    bridge: Peer,
    b_rx: mpsc::Receiver<PeerEvent>,
    client: Peer,
    c_rx: mpsc::Receiver<PeerEvent>,
    offer: String,
    answer: String,
    /// The bridge's own mids, in section order.
    bridge_mids: Vec<str0m::media::Mid>,
}

async fn connected(rx: &mut mpsc::Receiver<PeerEvent>, who: &str) {
    loop {
        match rx.recv().await {
            Some(PeerEvent::Connected) => return,
            Some(PeerEvent::Closed(r)) => panic!("{who} closed: {r}"),
            Some(PeerEvent::Failed(r)) => panic!("{who} failed: {r}"),
            Some(_) => {}
            None => panic!("{who}'s queue ended"),
        }
    }
}

/// The bridge offers audio, video and data (the data section carries an
/// out-of-band channel, which opens no DCEP); the client answers; both are
/// connected when this returns.
async fn rig(mid_ext: bool) -> Rig {
    crate::init();
    let (bridge, mut b_rx) = Peer::start(&config("bridge")).unwrap();
    let (client, mut c_rx) = Peer::start(&config("client")).unwrap();
    let (offer, pending): (_, SdpPendingOffer) = bridge.with_rtc(|rtc| {
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
    let (offer_text, old) = converter_shape(&offer.to_sdp_string(), mid_ext);
    let parsed = SdpOffer::from_sdp_string(&offer_text)
        .unwrap_or_else(|e| panic!("str0m refuses the converter-shaped offer: {e}\n{offer_text}"));
    let answer = client
        .with_rtc(|rtc| rtc.sdp_api().accept_offer(parsed))
        .unwrap_or_else(|e| panic!("accept_offer: {e}\n{offer_text}"));
    let answer_text = answer.to_sdp_string();
    let bridge_mids: Vec<str0m::media::Mid> = old
        .iter()
        .map(|m| str0m::media::Mid::from(m.as_str()))
        .collect();
    let old: Vec<&str> = old.iter().map(String::as_str).collect();
    let (back, _) = remid(&answer_text, &old);
    let back = SdpAnswer::from_sdp_string(&back).unwrap();
    bridge
        .with_rtc(|rtc| rtc.sdp_api().accept_answer(pending, back))
        .unwrap();
    let cb = Candidate::from_sdp_string(&bridge.add_host_candidate().unwrap()).unwrap();
    let cc = Candidate::from_sdp_string(&client.add_host_candidate().unwrap()).unwrap();
    client.add_remote_candidate(cb);
    bridge.add_remote_candidate(cc);
    let up = async {
        connected(&mut b_rx, "bridge").await;
        connected(&mut c_rx, "client").await;
    };
    tokio::time::timeout(Duration::from_secs(10), up)
        .await
        .unwrap_or_else(|_| panic!("not connected in 10 s\n{offer_text}\n{answer_text}"));
    Rig {
        bridge,
        b_rx,
        client,
        c_rx,
        offer: offer_text,
        answer: answer_text,
        bridge_mids,
    }
}

fn jvb_channel() -> ChannelConfig {
    ChannelConfig {
        label: LABEL.into(),
        ordered: true,
        reliability: Reliability::Reliable,
        negotiated: None,
        protocol: PROTOCOL.into(),
    }
}

/// The client opens the channel; returns its id there and the bridge's id
/// once the bridge saw the open.
async fn open_channel(r: &mut Rig) -> (ChannelId, ChannelId) {
    let (id, offer) = r.client.with_rtc(|rtc| {
        let mut api = rtc.sdp_api();
        let id = api.add_channel_with_config(jvb_channel());
        (id, api.apply())
    });
    assert!(
        offer.is_none(),
        "adding a channel after the negotiation must not make an offer"
    );
    let seen = async {
        loop {
            match r.b_rx.recv().await {
                Some(PeerEvent::ChannelOpen(cid, label)) if label == LABEL => return cid,
                Some(PeerEvent::Closed(why)) => panic!("bridge closed: {why}"),
                Some(_) => {}
                None => panic!("bridge queue ended"),
            }
        }
    };
    let theirs = tokio::time::timeout(Duration::from_secs(10), seen)
        .await
        .expect("the bridge saw no open of the channel");
    // And the client's side is open too.
    let ours = async {
        loop {
            match r.c_rx.recv().await {
                Some(PeerEvent::ChannelOpen(cid, _)) if cid == id => return,
                Some(PeerEvent::Closed(why)) => panic!("client closed: {why}"),
                Some(_) => {}
                None => panic!("client queue ended"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), ours)
        .await
        .expect("the client's channel never opened");
    (id, theirs)
}

fn section<'a>(sdp: &'a str, kind: &str) -> &'a str {
    let start = sdp.find(&format!("m={kind}")).unwrap();
    let rest = &sdp[start + 2..];
    let end = rest.find("\r\nm=").map_or(rest.len(), |i| i + 2);
    &sdp[start..start + 2 + end]
}

/// Line 1: the converter-shaped offer is taken; the answer keeps three
/// sections, their order and their mids.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_1_the_converter_shaped_offer_is_answered_in_kind() {
    bounded(async {
        let r = rig(true).await;
        assert!(r.offer.contains("a=msid-semantic: WMS *"), "{}", r.offer);
        assert!(r.offer.contains("a=rtcp:9 IN IP4 0.0.0.0"));
        assert!(r
            .offer
            .contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(r.offer.contains("a=max-message-size:262144"));
        assert_eq!(crate::sdp::section_mids(&r.answer), MIDS, "{}", r.answer);
        assert!(
            r.answer.contains("a=group:BUNDLE audio video data"),
            "{}",
            r.answer
        );
        r.client.close();
        r.bridge.close();
    })
    .await;
}

/// Line 1, second half: a hand-written offer in Jitsi's shape (named mids,
/// opus + telephone-event, VP8 with RTX, data) is taken too, and `actpass` as
/// it stands is answered `passive`: the reason for the rewrite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_1_a_written_jitsi_offer_is_taken_and_actpass_makes_us_passive() {
    bounded(async {
        crate::init();
        let text = include_str!("testdata/jitsi/offer-fixture.sdp");
        let (client, _rx) = Peer::start(&config("client")).unwrap();
        let answer = client
            .with_rtc(|rtc| {
                rtc.sdp_api()
                    .accept_offer(SdpOffer::from_sdp_string(text).unwrap())
            })
            .unwrap_or_else(|e| panic!("accept_offer of the fixture: {e}"))
            .to_sdp_string();
        assert_eq!(crate::sdp::section_mids(&answer), MIDS, "{answer}");
        assert!(
            answer.contains("a=setup:passive"),
            "actpass is answered passive:\n{answer}"
        );
        assert!(!answer.contains("a=setup:active"));
        client.close();

        let (client, _rx) = Peer::start(&config("client")).unwrap();
        let passive = text.replace("a=setup:actpass", "a=setup:passive");
        let answer = client
            .with_rtc(|rtc| {
                rtc.sdp_api()
                    .accept_offer(SdpOffer::from_sdp_string(&passive).unwrap())
            })
            .unwrap()
            .to_sdp_string();
        assert!(answer.contains("a=setup:active"), "{answer}");
        assert!(!answer.contains("a=setup:passive"), "{answer}");
        client.close();
    })
    .await;
}

/// Line 2: with the offer's `actpass` read as `passive` the answer says
/// `a=setup:active`, and the DTLS handshake completes with the client as its
/// client (the `rig` is connected).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_2_the_answer_is_active_and_the_handshake_completes() {
    bounded(async {
        let r = rig(true).await;
        for kind in ["audio", "video", "application"] {
            assert!(
                section(&r.answer, kind).contains("a=setup:active"),
                "{kind}:\n{}",
                r.answer
            );
        }
        assert!(r.client.is_connected() && r.bridge.is_connected());
        r.client.close();
        r.bridge.close();
    })
    .await;
}

/// Line 3: a channel with label and protocol, created by the answerer after
/// the negotiation: the far side's open carries both strings. (Before the
/// negotiation there is no way to create it: str0m makes an offer of it; see
/// `j0_3_before_the_negotiation_a_channel_is_an_offer_of_its_own`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_3_the_dcep_open_carries_label_and_protocol() {
    bounded(async {
        let mut r = rig(true).await;
        let (_ours, theirs) = open_channel(&mut r).await;
        let got = r
            .bridge
            .with_rtc(|rtc| rtc.channel(theirs).and_then(|c| c.config().cloned()))
            .expect("the bridge knows the channel's config");
        assert_eq!(got.label, LABEL);
        assert_eq!(got.protocol, PROTOCOL);
        assert!(got.ordered);
        assert_eq!(got.reliability, Reliability::Reliable);
        assert_eq!(got.negotiated, None, "in-band");
        r.client.close();
        r.bridge.close();
    })
    .await;
}

/// Line 3, the other order: asked before the offer is accepted, the channel
/// is the first change of an offer of the client's own; accept_offer does not
/// carry it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_3_before_the_negotiation_a_channel_is_an_offer_of_its_own() {
    bounded(async {
        crate::init();
        let (client, _rx) = Peer::start(&config("client")).unwrap();
        let made = client.with_rtc(|rtc| {
            let mut api = rtc.sdp_api();
            api.add_channel_with_config(jvb_channel());
            api.apply().is_some()
        });
        assert!(made, "str0m makes an offer for a channel on a fresh peer");
        client.close();
    })
    .await;
}

/// Line 4: a text message of 21 900 bytes passes whole both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_4_a_21900_byte_text_message_passes_whole_both_ways() {
    bounded(async {
        let mut r = rig(true).await;
        let (ours, theirs) = open_channel(&mut r).await;
        let text: Vec<u8> = (0..21_900u32)
            .map(|i| b'a' + u8::try_from(i % 26).unwrap())
            .collect();
        assert!(r.client.write(ours, false, &text).unwrap());
        assert!(r.bridge.write(theirs, false, &text).unwrap());
        for (rx, who) in [(&mut r.b_rx, "bridge"), (&mut r.c_rx, "client")] {
            let got = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match rx.recv().await {
                        Some(PeerEvent::Data(m)) => return m,
                        Some(PeerEvent::Closed(why)) => panic!("{who} closed: {why}"),
                        Some(_) => {}
                        None => panic!("{who}'s queue ended"),
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{who} got nothing"));
            assert!(!got.binary, "{who}: a text message");
            assert_eq!(got.data, text, "{who}");
        }
        r.client.close();
        r.bridge.close();
    })
    .await;
}

/// Line 5: a send line on the offered video section writes VP8 frames; the
/// far side receives RTP at the offered VP8 payload type. The answer's
/// video section is printed: it is plan D5's input.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_5_a_send_line_on_the_offered_video_section_reaches_the_bridge() {
    bounded(async {
        let r = rig(true).await;
        eprintln!(
            "J0-5 answer video section:\n{}",
            section(&r.answer, "video")
        );
        eprintln!(
            "J0-5 answer audio section:\n{}",
            section(&r.answer, "audio")
        );
        let seen = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let sink = seen.clone();
        let want_pt = r.client.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Vp8)
                .map(|p| *p.pt())
        });
        let want_pt = want_pt.expect("the client negotiated VP8");
        r.bridge.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
            sink.0.fetch_add(1, Ordering::Relaxed);
            if *p.header.payload_type == want_pt {
                sink.1.fetch_add(1, Ordering::Relaxed);
            }
        })));
        let video = r
            .client
            .with_rtc(|rtc| rtc.media(str0m::media::Mid::from("video")).map(|m| m.mid()));
        let video = video.expect("the client has the video line");
        let pt = r.client.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Vp8)
                .unwrap()
                .pt()
        });
        let mut line = SendLine::new(video, None, pt);
        let t0 = Instant::now();
        for i in 0..3u16 {
            let n = line
                .write(
                    &r.client,
                    Instant::now(),
                    vec![RtpOut {
                        seq: 100 + i,
                        timestamp: 90_000 * u32::from(i),
                        marker: true,
                        payload: vec![0x10; 20],
                    }],
                )
                .expect("the client has the stream");
            assert_eq!(n, 1);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let _ = t0;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            seen.1.load(Ordering::Relaxed),
            3,
            "{} packets in all",
            seen.0.load(Ordering::Relaxed)
        );
        assert!(r.client.is_connected() && r.bridge.is_connected());
        r.client.close();
        r.bridge.close();
    })
    .await;
}

/// Line 6: RTP for an SSRC no section declares and with no `mid` header
/// extension (the offer names none) is dropped quietly: the peer stays
/// connected and says nothing per packet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_6_unmapped_rtp_is_dropped_quietly() {
    bounded(async {
        let mut r = rig(false).await;
        assert!(!r.answer.contains("sdes:mid"), "{}", r.answer);
        let video = r.bridge_mids[1];
        let pt = r.bridge.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Vp8)
                .unwrap()
                .pt()
        });
        let mut line = SendLine::new(video, None, pt);
        let before = r.bridge.udp_out();
        for i in 0..30u16 {
            line.write(
                &r.bridge,
                Instant::now(),
                vec![RtpOut {
                    seq: 500 + i,
                    timestamp: 3000 * u32::from(i),
                    marker: true,
                    payload: vec![0x10; 20],
                }],
            )
            .expect("the bridge has the stream");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            r.bridge.udp_out() - before >= 30,
            "the bridge did send the packets ({} datagrams)",
            r.bridge.udp_out() - before
        );
        assert!(
            r.client.is_connected() && r.bridge.is_connected(),
            "the peer stayed up"
        );
        assert!(r.client.udp_in() > 0);
        // No event but the quiet kind: nothing that ends or fails the peer.
        while let Ok(e) = r.c_rx.try_recv() {
            assert!(
                !matches!(e, PeerEvent::Closed(_) | PeerEvent::Failed(_)),
                "unmapped RTP ended the peer: {e:?}"
            );
        }
        assert_eq!(
            r.client.video_packets_in(),
            0,
            "nothing was delivered for an unmapped SSRC"
        );
        r.client.close();
        r.bridge.close();
    })
    .await;
}

/// Line 7: `buffered_amount` and `wait_buffered` on that channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn j0_7_the_buffered_amount_gates_and_drains() {
    bounded(async {
        let mut r = rig(true).await;
        let (ours, _theirs) = open_channel(&mut r).await;
        let msg = vec![b'x'; 16 << 10];
        let mut taken = 0usize;
        while r.client.write(ours, false, &msg).unwrap() {
            taken += 1;
            assert!(taken <= 40, "str0m took more than its 256 KiB");
        }
        assert!(taken >= 8, "only {taken} messages of 16 KiB fit in 256 KiB");
        let held = r.client.buffered_amount(ours).unwrap();
        assert!(held > 0 && held <= (256 << 10) + (16 << 10), "{held}");
        let mut got = 0;
        let drain = async {
            while got < taken {
                if let Some(PeerEvent::Data(_)) = r.b_rx.recv().await {
                    got += 1;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .expect("the bridge got everything the client had taken");
        tokio::time::timeout(Duration::from_secs(5), r.client.wait_buffered(ours, 0))
            .await
            .expect("the buffer drained")
            .unwrap();
        assert_eq!(r.client.buffered_amount(ours), Some(0));
        r.client.close();
        r.bridge.close();
    })
    .await;
}

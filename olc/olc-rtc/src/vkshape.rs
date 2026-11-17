// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! VK Calls on str0m: what that carrier needs of a [`Peer`], tried on the Go
//! engine's own test offers before any of the carrier is written (M7.0).
//! Tests only.
//!
//! VK's SFU offers; the client answers and is the DTLS client. One offer
//! holds a slot the client publishes into (video, receive-only, one layer
//! named by the rid `l`) and a slot per participant the SFU forwards
//! (send-only, bound by the `a=ssrc` it names, video wrapped in RED).
//!
//! # The fixtures (`testdata/vk/`)
//!
//! `offer-*.sdp` are the offers of the Go engine's tests at 2d4266af
//! (`internal/engine/vkcalls/negotiate_test.go`: `pionOffer`,
//! `offerWithPeer` behind and ahead of the publish slot, `liveShapeOffer`),
//! and `view-*.sdp` what `pionView(offer, ["vp8"], nil)` makes of each: the
//! text the Go engine hands its WebRTC stack. Both are the Go functions'
//! output (the interop vectors' `vkcalls/view.json`, tables `offers` and
//! `views`), kept with bare line feeds and read back with CRLF.
//!
//! # The far end
//!
//! The SFU of the connected tests is a second [`Peer`], ICE-lite as VK's.
//! The client is given the Go fixture's view with that peer's credentials,
//! fingerprint and candidate put in; the SFU peer is given the mirror of it
//! ([`sfu_side`]: the same sections with the directions turned, the form of
//! the answer the Go engine shapes for VK), so each end holds the session
//! the other describes. The SFU's own payload table calls the RED payload
//! type VP9: it only has to send at that number, and so it sends whether
//! or not str0m knows video RED; what the test asks is what the client
//! does with the packet.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use str0m::change::SdpOffer;
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::format::{Codec, FormatParams};
use str0m::media::{Mid, Rid};
use str0m::rtp::{RtpPacket, RtpWrite, SeqNo, Ssrc};
use str0m::Candidate;
use tokio::sync::mpsc;

use crate::media::{with_codecs, CodecLine, RtpOut, SendLine};
use crate::peer::{IceMode, Peer, PeerConfig, PeerEvent};
use crate::sdp::{in_order, section_mids};
use crate::testing::bounded;
use crate::DtlsVersion;

const OFFER_PION: &str = include_str!("testdata/vk/offer-pion.sdp");
const OFFER_PEER_AFTER: &str = include_str!("testdata/vk/offer-peer-after.sdp");
const OFFER_PEER_AHEAD: &str = include_str!("testdata/vk/offer-peer-ahead.sdp");
const OFFER_LIVE: &str = include_str!("testdata/vk/offer-live.sdp");
const VIEW_PION: &str = include_str!("testdata/vk/view-pion.sdp");
const VIEW_PEER_AFTER: &str = include_str!("testdata/vk/view-peer-after.sdp");
const VIEW_PEER_AHEAD: &str = include_str!("testdata/vk/view-peer-ahead.sdp");
const VIEW_LIVE: &str = include_str!("testdata/vk/view-live.sdp");

/// The fixtures' session version, which a later offer raises
/// (`TestPayloadClashRenegotiates`).
const O_LINE: &str = "o=- 1790552099500 1790552100511 IN IP4 127.0.0.1";
const O_LINE_LATER: &str = "o=- 1790552099500 1790552100512 IN IP4 127.0.0.1";

const EXT_TWCC: &str =
    "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n";
const EXT_ABS_SEND_TIME: &str =
    "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n";
const EXT_MID: &str = "a=extmap:14 urn:ietf:params:rtp-hdrext:sdes:mid\r\n";
const EXT_RID: &str = "a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n";

/// The live shape's slots: the one we publish into and the two forwarded
/// participants, with the SSRCs the offer names for them.
const PUBLISH_MID: &str = "3";
const FIRST_MID: &str = "5";
const FIRST_SSRC: u32 = 2_463_708_139;
const SECOND_MID: &str = "6";
const SECOND_SSRC: u32 = 2_463_708_140;

/// A fixture as the Go test holds it: every line ended by CRLF.
fn crlf(fixture: &str) -> String {
    assert!(!fixture.contains('\r'), "a fixture is kept with bare LFs");
    fixture.replace('\n', "\r\n")
}

/// The fixtures are Go's own texts: each offer is the interop vectors'
/// (`vkcalls/view.json`, the table `offers`) and each view the one Go's
/// `pionView(offer, ["vp8"], nil)` gave for it there. A fixture edited by
/// hand, or vectors regenerated to another text, fail here.
#[test]
fn the_fixtures_are_the_vectors_texts() {
    let file = olc_interop::load("vkcalls/view.json");
    let views = file["views"].as_array().expect("the views");
    for (base, offer, view) in [
        ("pion", OFFER_PION, VIEW_PION),
        ("peer_after", OFFER_PEER_AFTER, VIEW_PEER_AFTER),
        ("peer_ahead", OFFER_PEER_AHEAD, VIEW_PEER_AHEAD),
        ("live", OFFER_LIVE, VIEW_LIVE),
    ] {
        assert!(
            file["offers"][base].as_str() == Some(crlf(offer).as_str()),
            "the offer {base} is not the vectors'"
        );
        let name = format!("{base}, publishing VP8");
        let case = views
            .iter()
            .find(|case| case["name"].as_str() == Some(name.as_str()))
            .unwrap_or_else(|| panic!("no view named {name:?}"));
        assert!(
            case["view"].as_str() == Some(crlf(view).as_str()),
            "the view of {base} is not the vectors'"
        );
    }
}

/// What the engine does to an offer before str0m sees it, so that str0m
/// takes the DTLS client's part as pion does on `actpass` (str0m would take
/// the server's).
fn as_dtls_client(offer: &str) -> String {
    assert!(offer.contains("a=setup:actpass"));
    offer.replace("a=setup:actpass", "a=setup:passive")
}

/// `text` with its one `from` made `to`.
fn swap(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from:?} is not there once");
    text.replacen(from, to, 1)
}

/// The media section of `sdp` whose mid is `mid`.
fn section<'a>(sdp: &'a str, mid: &str) -> &'a str {
    let name = format!("a=mid:{mid}\r\n");
    let mut starts: Vec<usize> = sdp.match_indices("\r\nm=").map(|(i, _)| i + 2).collect();
    starts.push(sdp.len());
    starts
        .windows(2)
        .map(|w| &sdp[w[0]..w[1]])
        .find(|s| s.contains(&name))
        .unwrap_or_else(|| panic!("no section with mid {mid} in:\n{sdp}"))
}

/// The mids of `sdp`'s sections, in order.
fn mids(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=mid:"))
        .collect()
}

fn config(name: &'static str) -> PeerConfig {
    PeerConfig {
        name,
        crypto: crate::crypto(),
        dtls_version: DtlsVersion::Dtls12,
        host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        sctp_max_buffered: 64 << 10,
        turn: Vec::new(),
        relay_only: false,
        ice_mode: IceMode::Udp,
    }
}

/// The client's payload table before any offer: VP8 and video RED, each
/// with its RTX, and Opus, at numbers no fixture uses, so every number it
/// ends with is one an offer gave it.
fn client_codecs() -> Vec<CodecLine> {
    vec![
        CodecLine::video(120, Some(121), Codec::Vp8, FormatParams::default()),
        CodecLine::video_red(122, Some(123)),
        CodecLine::opus(124, FormatParams::default()),
    ]
}

/// The fake SFU's payload table: VP8 as the offer numbers it, and the RED
/// payload type under the name VP9 (see the module's words on the far end).
fn sfu_codecs() -> Vec<CodecLine> {
    vec![
        CodecLine::video(100, Some(101), Codec::Vp8, FormatParams::default()),
        CodecLine::video(104, Some(105), Codec::Vp9, FormatParams::default()),
        CodecLine::opus(111, FormatParams::default()),
    ]
}

fn client() -> (Peer, mpsc::Receiver<PeerEvent>) {
    crate::init();
    Peer::start_tuned(&config("client"), |c| with_codecs(c, &client_codecs())).unwrap()
}

/// Gives `peer` the offer `sdp`; its answer, or what str0m said.
fn accept(peer: &Peer, sdp: &str) -> Result<String, String> {
    let offer = SdpOffer::from_sdp_string(sdp).map_err(|e| format!("parse: {e}"))?;
    peer.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer))
        .map(|answer| answer.to_sdp_string())
        .map_err(|e| format!("accept: {e}"))
}

/// The payload type and RTX payload type `peer` holds for `codec`.
fn numbers(peer: &Peer, codec: Codec) -> (u8, Option<u8>) {
    peer.with_rtc(|rtc| {
        let p = rtc
            .codec_config()
            .find(|p| p.spec().codec == codec)
            .unwrap_or_else(|| panic!("no {codec:?} in the payload table"));
        (*p.pt(), p.resend().map(|pt| *pt))
    })
}

fn has_line(peer: &Peer, mid: &str) -> bool {
    peer.with_rtc(|rtc| rtc.media(Mid::from(mid)).is_some())
}

/// (a) The views of the Go fixtures are accepted, each mid answered, and
/// VP8 goes out at the publish slot's payload type whatever a participant's
/// own section calls it (#72, `TestPayloadClashNegotiates`). One of the
/// four needs its group line put in the order of its sections first
/// ([`in_order`]): pion takes it as it is, str0m does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_views_of_gos_offers_are_accepted() {
    bounded(async {
        for (name, view) in [
            ("pion", VIEW_PION),
            ("peer after the publish slot", VIEW_PEER_AFTER),
            ("peer ahead of the publish slot", VIEW_PEER_AHEAD),
            ("live shape", VIEW_LIVE),
        ] {
            let view = as_dtls_client(&crlf(view));
            let offer = in_order(&view, &[]);
            assert_eq!(
                offer != view,
                view == as_dtls_client(&crlf(VIEW_PEER_AHEAD))
            );
            let (peer, _rx) = client();
            let answer = accept(&peer, &offer).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(mids(&answer), mids(&offer), "{name}");
            assert_eq!(numbers(&peer, Codec::Vp8), (100, Some(101)), "{name}");
            let publish = section(&answer, PUBLISH_MID);
            assert!(publish.contains("a=sendonly\r\n"), "{name}:\n{publish}");
            assert!(
                publish.contains("a=rtpmap:100 VP8/90000\r\n"),
                "{name}:\n{publish}"
            );
            assert!(answer.contains("a=setup:active\r\n"), "{name}:\n{answer}");
            assert!(
                !answer.contains("a=setup:passive") && !answer.contains("a=setup:actpass"),
                "{name}:\n{answer}"
            );
            // Every section is taken: none answered with port 0.
            for mid in mids(&offer) {
                let s = section(&answer, mid);
                assert!(!s.starts_with("m=audio 0 "), "{name} mid {mid}:\n{s}");
                assert!(!s.starts_with("m=video 0 "), "{name} mid {mid}:\n{s}");
                assert!(!s.starts_with("m=application 0 "), "{name} mid {mid}:\n{s}");
                assert!(has_line(&peer, mid) || s.starts_with("m=application"));
            }
            peer.close();
        }

        // As the Go test holds it, the view with the participant ahead is
        // refused: its group names the mids in another order than its
        // sections come in.
        let (peer, _rx) = client();
        let refused = accept(&peer, &as_dtls_client(&crlf(VIEW_PEER_AHEAD))).unwrap_err();
        assert!(
            refused.contains("Mid order not matching a=group"),
            "{refused}"
        );
        peer.close();
    })
    .await;
}

/// (a) A later offer that adds a participant's section is accepted on the
/// same peer and moves no payload type (`TestPayloadClashRenegotiates`);
/// so is the live shape's with one more receive slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_offer_with_one_more_section_is_accepted() {
    bounded(async {
        let (peer, _rx) = client();
        accept(&peer, &as_dtls_client(&crlf(VIEW_PION))).unwrap();
        assert!(!has_line(&peer, "6"));
        let later = swap(
            &as_dtls_client(&crlf(VIEW_PEER_AFTER)),
            O_LINE,
            O_LINE_LATER,
        );
        let answer = accept(&peer, &later).unwrap();
        assert_eq!(mids(&answer), mids(&later));
        assert!(has_line(&peer, "6"));
        assert!(
            section(&answer, "6").contains("a=recvonly\r\n"),
            "{}",
            section(&answer, "6")
        );
        assert_eq!(numbers(&peer, Codec::Vp8), (100, Some(101)));
        assert!(section(&answer, PUBLISH_MID).contains("a=rtpmap:100 VP8/90000\r\n"));
        peer.close();

        // The participant's section placed among the old ones: str0m wants
        // each section where it was, so the later offer goes in with the
        // sections it knows first.
        let first = as_dtls_client(&crlf(VIEW_PION));
        let later = swap(
            &as_dtls_client(&crlf(VIEW_PEER_AHEAD)),
            O_LINE,
            O_LINE_LATER,
        );
        let (peer, _rx) = client();
        accept(&peer, &first).unwrap();
        let refused = accept(&peer, &in_order(&later, &[])).unwrap_err();
        assert!(refused.contains("Changed order for m-line"), "{refused}");
        peer.close();
        let (peer, _rx) = client();
        accept(&peer, &first).unwrap();
        let later = in_order(&later, &section_mids(&first));
        assert_eq!(mids(&later), ["0", "1", "2", "3", "5", "6"]);
        let answer = accept(&peer, &later).unwrap();
        assert_eq!(mids(&answer), mids(&later));
        assert!(has_line(&peer, "6"));
        assert_eq!(numbers(&peer, Codec::Vp8), (100, Some(101)));
        peer.close();

        let (peer, _rx) = client();
        let first = as_dtls_client(&crlf(VIEW_LIVE));
        accept(&peer, &first).unwrap();
        let third = section(&first, SECOND_MID)
            .replace("a=mid:6\r\n", "a=mid:7\r\n")
            .replace("2463708140", "2463708141")
            .replace("pat-6", "pat-7");
        let later = swap(&first, O_LINE, O_LINE_LATER);
        let later = swap(
            &later,
            "a=group:BUNDLE 0 1 3 5 6",
            "a=group:BUNDLE 0 1 3 5 6 7",
        ) + &third;
        let answer = accept(&peer, &later).unwrap();
        assert_eq!(mids(&answer), mids(&later));
        assert!(has_line(&peer, "7"));
        assert_eq!(numbers(&peer, Codec::Vp8), (100, Some(101)));
        peer.close();
    })
    .await;
}

/// (b, the table) With the live numbering RED is 102 in the publish slot and
/// 104 in the receive slots. The view leaves the publish slot only what we
/// publish, so RED takes the receive slots' number, with its RTX
/// (`TestLiveShapeKeepsReceiveNumbering`), and the answer says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn red_takes_the_receive_slots_number() {
    bounded(async {
        let (peer, _rx) = client();
        let answer = accept(&peer, &as_dtls_client(&crlf(VIEW_LIVE))).unwrap();
        assert_eq!(numbers(&peer, Codec::Red), (104, Some(105)));
        for mid in [FIRST_MID, SECOND_MID] {
            let s = section(&answer, mid);
            assert!(s.contains("a=rtpmap:104 red/90000\r\n"), "{s}");
            assert!(s.contains("a=fmtp:105 apt=104\r\n"), "{s}");
            assert!(s.contains("a=rtpmap:100 VP8/90000\r\n"), "{s}");
        }
        let publish = section(&answer, PUBLISH_MID);
        assert!(!publish.contains("red/90000"), "{publish}");
        peer.close();
    })
    .await;
}

/// What a peer's sink saw of one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    pt: u8,
    seq: u16,
    ssrc: u32,
    mid: Option<Mid>,
    rid: Option<Rid>,
    abs_send_time: bool,
    twcc: bool,
    payload: Vec<u8>,
}

fn watch(peer: &Peer) -> mpsc::UnboundedReceiver<Seen> {
    let (tx, rx) = mpsc::unbounded_channel();
    peer.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
        let _ = tx.send(Seen {
            pt: *p.header.payload_type,
            seq: p.header.sequence_number,
            ssrc: *p.header.ssrc,
            mid: p.header.ext_vals.mid,
            rid: p.header.ext_vals.rid,
            abs_send_time: p.header.ext_vals.abs_send_time.is_some(),
            twcc: p.header.ext_vals.transport_cc.is_some(),
            payload: p.payload.to_vec(),
        });
    })));
    rx
}

/// A peer's events, those read while waiting for something else kept.
struct Events {
    kept: VecDeque<PeerEvent>,
    rx: mpsc::Receiver<PeerEvent>,
}

impl Events {
    async fn next(&mut self) -> PeerEvent {
        if let Some(e) = self.kept.pop_front() {
            return e;
        }
        self.rx.recv().await.expect("the peer's driver went")
    }
}

/// How the live shape's offer is varied.
#[derive(Debug, Clone, Copy)]
struct Shape {
    /// The publish slot names an RTX for VP8 (the live shape does).
    publish_rtx: bool,
    /// The publish slot as str0m is given it keeps the offer's
    /// abs-send-time line (D9 takes it out).
    publish_abs_send_time: bool,
}

impl Shape {
    const LIVE: Shape = Shape {
        publish_rtx: true,
        publish_abs_send_time: true,
    };
}

struct Room {
    client: Peer,
    client_events: Events,
    sfu: Peer,
    sfu_events: Events,
}

impl Room {
    fn close(&self) {
        self.client.set_rtp_sink(None);
        self.sfu.set_rtp_sink(None);
        self.client.close();
        self.sfu.close();
    }
}

fn fingerprint(peer: &Peer) -> String {
    peer.with_rtc(|rtc| rtc.direct_api().local_dtls_fingerprint().to_string())
}

/// The live shape's view as the client is given it: the fixture with the
/// SFU peer's credentials, fingerprint and candidate, and `shape`'s changes
/// to the publish slot.
fn offer_from(sfu: &Peer, shape: Shape) -> String {
    let mut sdp = as_dtls_client(&crlf(VIEW_LIVE));
    sdp = swap(
        &sdp,
        "a=candidate:1 1 udp 1 192.0.2.1 43210 typ host",
        &format!("a={}", sfu.add_host_candidate().unwrap()),
    );
    sdp = swap(
        &sdp,
        "a=ice-ufrag:QcK1avCrgDjn21p",
        &format!("a=ice-ufrag:{}", sfu.creds().ufrag),
    );
    sdp = swap(
        &sdp,
        "a=ice-pwd:GZU7Kw3Sq1YSJxrABCtRTGhms",
        &format!("a=ice-pwd:{}", sfu.creds().pass),
    );
    sdp = swap(
        &sdp,
        "a=fingerprint:sha-256 32:16:0D:10:FC:A1:F1:04:43:F5:22:01:9B:2E:53:38",
        &format!("a=fingerprint:{}", fingerprint(sfu)),
    );
    if !shape.publish_rtx {
        sdp = swap(
            &sdp,
            "m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\nc=IN IP4 0.0.0.0\r\na=mid:3\r\n",
            "m=video 9 UDP/TLS/RTP/SAVPF 100\r\nc=IN IP4 0.0.0.0\r\na=mid:3\r\n",
        );
        sdp = swap(
            &sdp,
            "a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\na=rid:l recv\r\n",
            "a=rid:l recv\r\n",
        );
    }
    if !shape.publish_abs_send_time {
        let with = format!("a=mid:3\r\n{EXT_TWCC}{EXT_ABS_SEND_TIME}");
        sdp = swap(&sdp, &with, &format!("a=mid:3\r\n{EXT_TWCC}"));
    }
    sdp
}

/// The session as the SFU holds it, written as an offer for the SFU peer:
/// the live shape's sections with the directions turned and the client's
/// credentials and fingerprint, the client being the DTLS client. It is the
/// form of the answer the Go engine shapes for VK (`answer.go`): the
/// offer's extmap lines echoed, the publish slot naming the rid and no
/// SSRC. The SFU did offer abs-send-time on the publish slot, so its side
/// reads one if the client writes one.
fn sfu_side(client: &Peer, shape: Shape) -> String {
    let vp8 = "a=rtpmap:100 VP8/90000\r\na=rtcp-fb:100 nack\r\na=rtcp-fb:100 nack pli\r\n";
    let vp8_rtx = "a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\n";
    let mut sdp = String::from(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1 3 5 6\r\n",
    );
    sdp += "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\n";
    sdp += &format!("a=ice-ufrag:{}\r\n", client.creds().ufrag);
    sdp += &format!("a=ice-pwd:{}\r\n", client.creds().pass);
    sdp += &format!("a=fingerprint:{}\r\n", fingerprint(client));
    sdp += "a=setup:active\r\na=mid:0\r\na=recvonly\r\na=rtcp-mux\r\n";
    sdp += "a=rtpmap:111 opus/48000/2\r\n";
    sdp += "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n";
    sdp += "a=mid:1\r\na=sctp-port:5000\r\n";
    if shape.publish_rtx {
        sdp += "m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\n";
    } else {
        sdp += "m=video 9 UDP/TLS/RTP/SAVPF 100\r\n";
    }
    sdp += "c=IN IP4 0.0.0.0\r\na=mid:3\r\n";
    sdp += EXT_TWCC;
    sdp += EXT_ABS_SEND_TIME;
    sdp += EXT_MID;
    sdp += EXT_RID;
    sdp += "a=sendonly\r\na=rtcp-mux\r\n";
    sdp += vp8;
    if shape.publish_rtx {
        sdp += vp8_rtx;
    }
    sdp += "a=rid:l send\r\na=simulcast:send l\r\n";
    for mid in [FIRST_MID, SECOND_MID] {
        sdp += "m=video 9 UDP/TLS/RTP/SAVPF 100 101 104 105\r\nc=IN IP4 0.0.0.0\r\n";
        sdp += &format!("a=mid:{mid}\r\n");
        sdp += EXT_TWCC;
        sdp += EXT_ABS_SEND_TIME;
        sdp += "a=recvonly\r\na=rtcp-mux\r\n";
        sdp += vp8;
        sdp += vp8_rtx;
        sdp += "a=rtpmap:104 VP9/90000\r\na=rtpmap:105 rtx/90000\r\na=fmtp:105 apt=104\r\n";
    }
    sdp
}

/// A client joined to a fake SFU over the live shape; `after_accept` runs
/// on the client between its answer and the connection (where the engine
/// makes its channels).
async fn join(shape: Shape, after_accept: impl FnOnce(&Peer)) -> Room {
    crate::init();
    let (sfu, mut sfu_rx) = Peer::start_tuned(&config("sfu"), |c| {
        with_codecs(c.set_ice_lite(true), &sfu_codecs())
    })
    .unwrap();
    let (client, mut client_rx) = client();
    let offer = offer_from(&sfu, shape);
    accept(&client, &offer).unwrap();
    after_accept(&client);
    let candidate = Candidate::from_sdp_string(&client.add_host_candidate().unwrap()).unwrap();
    accept(&sfu, &sfu_side(&client, shape)).unwrap();
    sfu.add_remote_candidate(candidate);
    let mut up = (false, false);
    let mut kept = (VecDeque::new(), VecDeque::new());
    while !(up.0 && up.1) {
        tokio::select! {
            e = client_rx.recv() => match e.expect("the client's driver went") {
                PeerEvent::Connected => up.0 = true,
                PeerEvent::Closed(r) => panic!("the client closed: {r}"),
                e => kept.0.push_back(e),
            },
            e = sfu_rx.recv() => match e.expect("the SFU's driver went") {
                PeerEvent::Connected => up.1 = true,
                PeerEvent::Closed(r) => panic!("the SFU closed: {r}"),
                e => kept.1.push_back(e),
            },
        }
    }
    Room {
        client,
        client_events: Events {
            kept: kept.0,
            rx: client_rx,
        },
        sfu,
        sfu_events: Events {
            kept: kept.1,
            rx: sfu_rx,
        },
    }
}

/// The SFU forwards `payloads` on the slot whose SSRC is `ssrc`, at `pt`,
/// numbered from `first`.
fn forward(sfu: &Peer, mid: &str, ssrc: u32, pt: u8, first: u16, payloads: &[Vec<u8>]) {
    sfu.with_rtc(|rtc| {
        let mut api = rtc.direct_api();
        let ssrc = Ssrc::from(ssrc);
        let mid = Mid::from(mid);
        // str0m made a stream of its own for the line, and sends from the
        // first stream a line has: ours takes its place.
        let made = api.stream_tx_by_mid(mid, None).map(|tx| tx.ssrc());
        if let Some(made) = made.filter(|made| *made != ssrc) {
            api.remove_stream_tx(made);
        }
        api.declare_stream_tx(ssrc, None, mid, None);
        let tx = api.stream_tx(&ssrc).expect("the stream just declared");
        for (i, payload) in payloads.iter().enumerate() {
            let seq = u64::from(first) + u64::try_from(i).unwrap();
            tx.write_rtp(RtpWrite::new(
                pt.into(),
                SeqNo::from(seq),
                u32::try_from(seq).unwrap() * 3000,
                Instant::now(),
                payload.clone(),
            ));
        }
    });
}

/// The next `n` packets a sink sees, or those seen within `within`.
async fn take(rx: &mut mpsc::UnboundedReceiver<Seen>, n: usize, within: Duration) -> Vec<Seen> {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(within, async {
        while got.len() < n {
            match rx.recv().await {
                Some(seen) => got.push(seen),
                None => break,
            }
        }
    })
    .await;
    got
}

/// (b) Video the SFU forwards wrapped in RED, at the receive slots' RED
/// payload type and on the SSRC the offer names, reaches the packet event
/// as it came (the RED header still on it, for `olc-vp8channel`'s reader)
/// and is counted as video. VP8 sent bare on the other slot is the control:
/// it reaches the sink with or without the patch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn video_wrapped_in_red_reaches_the_packet_event() {
    bounded(async {
        let room = join(Shape::LIVE, |_| {}).await;
        let mut seen = watch(&room.client);

        let bare: Vec<Vec<u8>> = (0..5u8).map(|i| vec![0x90, 0x80, i, 1, 2, 3]).collect();
        forward(&room.sfu, SECOND_MID, SECOND_SSRC, 100, 500, &bare);
        let got = take(&mut seen, bare.len(), Duration::from_secs(5)).await;
        assert_eq!(got.len(), bare.len(), "bare VP8 at 100: {got:?}");
        for (i, p) in got.iter().enumerate() {
            assert_eq!((p.pt, p.ssrc), (100, SECOND_SSRC));
            assert_eq!(p.payload, bare[usize::from(p.seq - 500)], "packet {i}");
        }

        // RFC 2198 with the primary block alone: one byte naming VP8's
        // payload type, then the VP8 payload.
        let wrapped: Vec<Vec<u8>> = (0..8u8)
            .map(|i| vec![100, 0x90, 0x80, i, 4, 5, 6])
            .collect();
        forward(&room.sfu, FIRST_MID, FIRST_SSRC, 104, 900, &wrapped);
        let got = take(&mut seen, wrapped.len(), Duration::from_secs(5)).await;
        assert_eq!(
            got.len(),
            wrapped.len(),
            "video wrapped in RED at 104 did not reach the packet event: {got:?}"
        );
        for p in &got {
            assert_eq!((p.pt, p.ssrc), (104, FIRST_SSRC));
            assert_eq!(p.payload, wrapped[usize::from(p.seq - 900)]);
        }
        assert_eq!(room.client.video_packets_in(), 13);
        room.close();
    })
    .await;
}

/// Publishes `n` packets on the publish slot's layer `l`, one every 25 ms,
/// numbered from `first`.
async fn publish(room: &Room, line: &mut SendLine, first: u16, n: u16) {
    for i in 0..n {
        let seq = first.wrapping_add(i);
        let wrote = line.write(
            &room.client,
            Instant::now(),
            [RtpOut {
                seq,
                timestamp: 3000 * u32::from(seq),
                marker: true,
                payload: vec![0x90, 0x80, 0, 9, 9],
            }],
        );
        assert_eq!(wrote, Some(1));
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The publish slot's layer `l` on `room`'s client, at VP8's payload type.
fn layer(room: &Room) -> SendLine {
    let (vp8, _) = numbers(&room.client, Codec::Vp8);
    SendLine::declare(
        &room.client,
        Mid::from(PUBLISH_MID),
        Some(Rid::from("l")),
        vp8.into(),
        false,
    )
    .expect("the publish slot")
}

/// (c) What we publish carries the slot's mid and the rid `l` on every
/// packet, receiver reports or not: VK's SFU is told no SSRC and binds the
/// stream by its rid, and the Go engine's stamper writes both on each
/// packet. Tried where the publish slot names no RTX (the Go tests' first
/// fixture) and where it does (the live shape). Without
/// [`SendLine::keep_mid_rid`] the first loses both from its second packet
/// on (the far end's first report comes that soon); the second keeps them
/// only because str0m never records the report for a stream that has an
/// RTX SSRC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_and_rid_stay_on_every_packet() {
    bounded(async {
        for publish_rtx in [false, true] {
            let shape = Shape {
                publish_rtx,
                ..Shape::LIVE
            };
            let room = join(shape, |_| {}).await;
            let mut seen = watch(&room.sfu);
            let mut line = layer(&room);
            let (_, rtx) = line.ssrcs(&room.client).expect("the layer's stream");
            assert_eq!(rtx.is_some(), publish_rtx, "an RTX SSRC only with an RTX");
            assert!(line.keep_mid_rid(&room.client));
            // 3.5 s: the far end reports on a video stream every second.
            publish(&room, &mut line, 1000, 140).await;
            let got = take(&mut seen, 140, Duration::from_secs(3)).await;
            assert_eq!(got.len(), 140, "rtx {publish_rtx}: packets at the SFU");
            let bare: Vec<u16> = got
                .iter()
                .filter(|p| p.mid != Some(Mid::from(PUBLISH_MID)) || p.rid != Some(Rid::from("l")))
                .map(|p| p.seq)
                .collect();
            assert!(
                bare.is_empty(),
                "rtx {publish_rtx}: {} of 140 packets without their mid or rid, the first numbered {} (sent from 1000)",
                bare.len(),
                bare[0]
            );
            assert!(got.iter().all(|p| p.pt == 100), "VP8 at the slot's number");
            room.close();
        }
    })
    .await;
}

fn service_channel(label: &str) -> ChannelConfig {
    ChannelConfig {
        label: label.into(),
        ordered: true,
        reliability: Reliability::Reliable,
        negotiated: None,
        protocol: String::new(),
    }
}

/// The next two channels a peer's events open, with their labels.
async fn two_open(events: &mut Events) -> Vec<(ChannelId, String)> {
    let mut open = Vec::new();
    while open.len() < 2 {
        match events.next().await {
            PeerEvent::ChannelOpen(id, label) => open.push((id, label)),
            PeerEvent::Closed(r) => panic!("closed: {r}"),
            _ => {}
        }
    }
    open
}

fn stream_id(peer: &Peer, id: ChannelId) -> Option<u16> {
    peer.with_rtc(|rtc| rtc.direct_api().sctp_stream_id_by_channel_id(id))
}

/// (d) The engine's two service channels, made by the answering DTLS client
/// after the offer is applied, in the Go engine's order: they open at the
/// SFU under their labels on SCTP streams 0 and 2 (pion's numbers for the
/// DTLS client: even, in the order made), and carry a message each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_channels_made_after_the_offer_take_streams_0_and_2() {
    bounded(async {
        let mut made = None;
        let mut room = join(Shape::LIVE, |client| {
            made = Some(client.with_rtc(|rtc| {
                let mut api = rtc.direct_api();
                let notify = api.create_data_channel(service_channel("producerNotification"));
                let command = api.create_data_channel(service_channel("producerCommand"));
                (notify, command)
            }));
        })
        .await;
        let (notify, command) = made.unwrap();

        let ours = two_open(&mut room.client_events).await;
        assert_eq!(
            ours,
            vec![
                (notify, "producerNotification".to_owned()),
                (command, "producerCommand".to_owned())
            ]
        );
        assert_eq!(stream_id(&room.client, notify), Some(0));
        assert_eq!(stream_id(&room.client, command), Some(2));

        let theirs = two_open(&mut room.sfu_events).await;
        let labels: Vec<(Option<u16>, &str)> = theirs
            .iter()
            .map(|(id, label)| (stream_id(&room.sfu, *id), label.as_str()))
            .collect();
        assert_eq!(
            labels,
            vec![
                (Some(0), "producerNotification"),
                (Some(2), "producerCommand")
            ]
        );

        // change-simulcast for sequence 1, as the engine sends it at open.
        let frame = [
            0x07, 0x00, 0x01, 0x01, 0x01, 0xA1, 0x6C, 0xD1, 0x01, 0x40, 0xD1, 0x00, 0xB4, 0x0F,
            0xD1, 0x00, 0xB4,
        ];
        assert!(room.client.write(command, true, &frame).unwrap());
        loop {
            match room.sfu_events.next().await {
                PeerEvent::Data(m) => {
                    assert_eq!(stream_id(&room.sfu, m.channel), Some(2));
                    assert!(m.binary);
                    assert_eq!(m.data, frame);
                    break;
                }
                PeerEvent::Closed(r) => panic!("the SFU closed: {r}"),
                _ => {}
            }
        }
        let registry = theirs[0].0;
        assert!(room.sfu.write(registry, true, b"registry").unwrap());
        loop {
            match room.client_events.next().await {
                PeerEvent::Data(m) => {
                    assert_eq!(m.channel, notify);
                    assert_eq!(m.data, b"registry");
                    break;
                }
                PeerEvent::Closed(r) => panic!("the client closed: {r}"),
                _ => {}
            }
        }
        room.close();
    })
    .await;
}

/// (e) D9: the Go engine writes no abs-send-time on what it publishes (its
/// stamper writes the mid and the rid alone), and str0m writes one on every
/// packet of a slot that names the extension. With the line taken out of
/// the publish slot str0m is given, none goes out, while the mid, the rid
/// and the transport-wide sequence number still do. The first half shows
/// the line left in does put one on the packets, so the second half can
/// fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_abs_send_time_on_what_we_publish() {
    bounded(async {
        for publish_abs_send_time in [true, false] {
            let shape = Shape {
                publish_abs_send_time,
                ..Shape::LIVE
            };
            let room = join(shape, |_| {}).await;
            let mut seen = watch(&room.sfu);
            let mut line = layer(&room);
            assert!(line.keep_mid_rid(&room.client));
            publish(&room, &mut line, 2000, 12).await;
            let got = take(&mut seen, 12, Duration::from_secs(3)).await;
            assert_eq!(got.len(), 12);
            for p in &got {
                assert_eq!(
                    p.abs_send_time, publish_abs_send_time,
                    "the slot names abs-send-time: {publish_abs_send_time}; packet {p:?}"
                );
                assert_eq!(p.mid, Some(Mid::from(PUBLISH_MID)), "{p:?}");
                assert_eq!(p.rid, Some(Rid::from("l")), "{p:?}");
                assert!(p.twcc, "{p:?}");
            }
            room.close();
        }
    })
    .await;
}

/// #72 on str0m: why it is given the view and never the offer itself. The
/// raw offers are taken, and nothing panics with this client's table of
/// one entry a codec (the claim assert of K2 was read in str0m, not
/// reached here), but the first section to name a codec gives it its
/// number. With a participant
/// ahead of the publish slot VP8 would go out at the participant's 96, not
/// the slot's 100; with the live numbering RED would sit at the publish
/// slot's 102 and the camera video forwarded at 104 would have no
/// parameters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_view_the_numbers_are_the_wrong_slots() {
    bounded(async {
        let (peer, _rx) = client();
        let raw = in_order(&as_dtls_client(&crlf(OFFER_PEER_AHEAD)), &[]);
        accept(&peer, &raw).unwrap();
        assert_eq!(numbers(&peer, Codec::Vp8), (96, Some(97)));
        peer.close();

        let (peer, _rx) = client();
        accept(&peer, &as_dtls_client(&crlf(OFFER_LIVE))).unwrap();
        assert_eq!(numbers(&peer, Codec::Vp8), (100, Some(101)));
        assert_eq!(numbers(&peer, Codec::Red), (102, Some(103)));
        peer.close();

        for raw in [OFFER_PION, OFFER_PEER_AFTER] {
            let (peer, _rx) = client();
            accept(&peer, &as_dtls_client(&crlf(raw))).unwrap();
            assert_eq!(numbers(&peer, Codec::Vp8), (100, Some(101)));
            peer.close();
        }
    })
    .await;
}

/// The fixtures are the Go tests' offers: the lengths the Go strings have.
#[test]
fn the_fixtures_are_the_go_tests_offers() {
    for (text, len) in [
        (OFFER_PION, 2190),
        (OFFER_PEER_AFTER, 2729),
        (OFFER_PEER_AHEAD, 2729),
        (OFFER_LIVE, 2857),
        (VIEW_PION, 1974),
        (VIEW_PEER_AFTER, 2513),
        (VIEW_PEER_AHEAD, 2513),
        (VIEW_LIVE, 2597),
    ] {
        assert_eq!(crlf(text).len(), len);
    }
}

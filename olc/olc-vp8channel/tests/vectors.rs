// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The Go engine's vp8channel wire at the pin, as golden vectors
//! (olc/interop/vectors, made by `zz_vectors_wire_test.go`):
//!
//! - `vp8/epoch.json` (W24, W26): headers, their parse, peer ids, `ConfirmPeer`;
//! - `vp8/token.json` (W25): the binding token and the room hint;
//! - `vp8/kcp-crc.json` (W28): the CRC-32C trailer, out and in;
//! - `vp8/olkb.json` (W29), `vp8/datagram.json` (W30): batches built and split;
//! - `vp8/inbound-verdicts.json` (W27): what a client does with each frame;
//! - `vp9/carrier.json` (W34, W35): the VP9 dress and payloader;
//! - `vp8/rtp.json` (W36): pion's VP8 payloader and packetizer;
//! - `vp8/rtp-reader.json` (W36, W37): RED, the reorder buffer and the
//!   assemblers, over scripts of packets.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use olc_interop::{bytes, hex, load, pattern, sha256_hex};
use olc_kcp::link;
use olc_vp8channel::conn::Packet;
use olc_vp8channel::lane::{batch_sample_up_to, LaneParams};
use olc_vp8channel::rtp::{Packetizer, Payloader, RtpPacket, Vp8Payloader, PAYLOAD_MTU};
use olc_vp8channel::rtp_reader::{accepts, red_primary, TrackReader};
use olc_vp8channel::wire::{
    binding_token, datagram_frame, epoch_crc, epoch_header, format_peer_id, parse_epoch_header,
    parse_peer_id, split_datagram_batch_payload, split_datagram_payload, split_kcp_payload,
    split_room_hint, EPOCH_HDR_LEN, VP8_KEEPALIVE,
};
use olc_vp8channel::writer::Writer;
use olc_vp8channel::{vp9, Carrier, Channel, Config, Inbound, Options};
use serde_json::Value;

fn u32_of(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap_or_else(|| panic!("not a number: {v}"))).expect("a u32")
}

fn usize_of(v: &Value) -> usize {
    usize::try_from(v.as_u64().unwrap_or_else(|| panic!("not a number: {v}"))).expect("a usize")
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap_or_else(|| panic!("not an array: {v}"))
}

/// A `PatternSpec`'s bytes.
fn spec(v: &Value) -> Vec<u8> {
    pattern(
        usize_of(&v["len"]),
        u8::try_from(v["seed"].as_u64().unwrap()).unwrap(),
    )
}

/// `zzBytes`: hex, or length and SHA-256 when large.
fn assert_bytes(want: &Value, got: &[u8], what: &str) {
    assert_eq!(usize_of(&want["len"]), got.len(), "{what}: length");
    match want["hex"].as_str() {
        Some(h) => assert_eq!(hex(got), h, "{what}"),
        None => assert_eq!(sha256_hex(got), str_of(&want["sha256"]), "{what}"),
    }
}

/// `zzPacketsDigest`.
fn assert_digest(want: &Value, pkts: &[Vec<u8>], what: &str) {
    let lens: Vec<usize> = arr(&want["lens"]).iter().map(usize_of).collect();
    assert_eq!(
        pkts.iter().map(Vec::len).collect::<Vec<_>>(),
        lens,
        "{what}: lengths"
    );
    let heads: Vec<&str> = arr(&want["heads"]).iter().map(str_of).collect();
    let got: Vec<String> = pkts.iter().map(|k| hex(&k[..k.len().min(4)])).collect();
    assert_eq!(got, heads, "{what}: descriptors");
    let mut all = Vec::new();
    for k in pkts {
        all.extend_from_slice(&u16::try_from(k.len()).unwrap().to_be_bytes());
        all.extend_from_slice(k);
    }
    assert_eq!(sha256_hex(&all), str_of(&want["sha256"]), "{what}");
}

const CHANNEL: &str = "vectors";

fn token() -> u32 {
    binding_token(CHANNEL, "")
}

#[test]
fn w24_w26_headers_peer_ids_and_confirmation() {
    let v = load("vp8/epoch.json");
    assert_eq!(hex(&VP8_KEEPALIVE), str_of(&v["keepalive"]));
    assert_eq!(token(), u32_of(&v["binding"]["token"]));
    for h in arr(&v["headers"]) {
        let (t, s, d) = (u32_of(&h["token"]), u32_of(&h["src"]), u32_of(&h["dst"]));
        assert_eq!(epoch_crc(t, s, d), u32_of(&h["crc"]));
        assert_eq!(hex(&epoch_header(t, s, d)), str_of(&h["hex"]), "{h}");
    }
    for p in arr(&v["parse"]) {
        let got = parse_epoch_header(&bytes(p, "hex"));
        assert_eq!(got.is_some(), p["ok"].as_bool().unwrap(), "{}", p["name"]);
        if let Some(h) = got {
            assert_eq!(
                (h.token, h.src, h.dst),
                (u32_of(&p["token"]), u32_of(&p["src"]), u32_of(&p["dst"])),
                "{}",
                p["name"]
            );
        }
    }
    for f in arr(&v["format_peer"]) {
        assert_eq!(format_peer_id(u32_of(&f["epoch"])), str_of(&f["id"]));
    }
    for p in arr(&v["parse_peer"]) {
        let got = parse_peer_id(str_of(&p["id"]));
        let want = p["ok"].as_bool().unwrap().then(|| u32_of(&p["epoch"]));
        assert_eq!(got, want, "{:?}", p["id"]);
    }
    let local = u32_of(&v["local_epoch"]);
    for c in arr(&v["confirm_peer"]) {
        let t0 = Instant::now();
        let mut ch = Channel::with_epoch(&config(), t0, local);
        ch.connect(t0);
        let got = ch.confirm_peer(str_of(&c["id"]), t0);
        assert_eq!(
            got.is_ok(),
            c["ok"].as_bool().unwrap(),
            "{:?}: {got:?}",
            c["id"]
        );
        assert_eq!(ch.peer_confirmed(), c["confirmed"].as_bool().unwrap());
        if let (Err(e), Some(want)) = (&got, c["error"].as_str()) {
            assert_eq!(e.to_string(), want);
        }
        if got.is_ok() {
            let hdr = ch.data.rt.as_ref().unwrap().header();
            assert_eq!(hex(hdr), str_of(&c["data_header"]), "{:?}", c["id"]);
        }
    }
}

#[test]
fn w25_the_binding_token_leaves_the_hint_out() {
    for c in arr(&load("vp8/token.json")) {
        let (channel, room) = (str_of(&c["channel"]), str_of(&c["room"]));
        if channel.is_empty() {
            assert_eq!(
                split_room_hint(room),
                (str_of(&c["room_without_hint"]), str_of(&c["hint"])),
                "{room:?}"
            );
        }
        assert_eq!(
            binding_token(channel, room),
            u32_of(&c["token"]),
            "{channel:?} {room:?}"
        );
    }
}

#[test]
fn w28_the_crc32c_trailer_out_and_in() {
    let v = load("vp8/kcp-crc.json");
    let hdr = bytes(&v, "header");
    for w in arr(&v["wrap"]) {
        let p = spec(&w["packet"]);
        let mut out = Vec::new();
        link::wrap_into(&mut out, &hdr, &p);
        assert_bytes(&w["wire"], &out, "wrap");
        assert_eq!(
            u32::from_be_bytes(out[out.len() - 4..].try_into().unwrap()),
            u32_of(&w["crc"])
        );
    }
    for d in arr(&v["deliver"]) {
        let input = bytes(d, "hex");
        let got = link::unwrap(&input);
        assert_eq!(
            got.is_ok(),
            d["accepted"].as_bool().unwrap(),
            "{}",
            d["name"]
        );
        assert_eq!(u64::from(got.is_err()), d["corrupt"].as_u64().unwrap());
        if let Ok(body) = got {
            assert_eq!(hex(body), str_of(&d["body"]), "{}", d["name"]);
        }
    }
}

fn lane_params(batch: usize) -> LaneParams {
    LaneParams::new(
        Options::with_defaults(30, batch).frame_interval(),
        batch,
        4096,
    )
}

#[test]
fn w29_olkb_batches_built_and_split() {
    let v = load("vp8/olkb.json");
    for s in arr(&v["split"]) {
        let mut got = Vec::new();
        split_kcp_payload(&bytes(s, "hex"), |p| got.push(hex(p)));
        let want: Vec<&str> = s["delivered"]
            .as_array()
            .map(|a| a.iter().map(str_of).collect())
            .unwrap_or_default();
        assert_eq!(got, want, "{}", s["name"]);
    }
    let hdr = bytes(&v, "header");
    for b in arr(&v["batch"]) {
        let name = &b["name"];
        let frame = |q: &Value| {
            let mut data = hdr.clone();
            if q["len"].as_i64().unwrap() >= 0 {
                data.extend_from_slice(&spec(q));
            }
            Packet { data, queued: 0 }
        };
        let frames = arr(&b["frames"]);
        let first = frame(&frames[0]);
        let mut src: VecDeque<Packet> = frames[1..].iter().map(frame).collect();
        let p = lane_params(usize_of(&b["batch_size"]));
        let (sample, left, _) =
            batch_sample_up_to(&mut src, first, Vec::new(), &p, usize_of(&b["limit"]));
        assert_bytes(&b["sample"], &sample, &format!("{name} sample"));
        assert_eq!(src.len(), usize_of(&b["queue_left"]), "{name}");
        match (&left, b.get("left_over")) {
            (Some(l), Some(want)) => assert_bytes(want, &l.data, &format!("{name} left over")),
            (None, None) => {}
            _ => panic!("{name}: left over {:?}", left.map(|l| l.data.len())),
        }
    }
}

#[test]
fn w30_datagrams_their_batches_and_the_bound() {
    let v = load("vp8/datagram.json");
    let (tok, local) = (u32_of(&v["token"]), u32_of(&v["local_epoch"]));
    assert_eq!(tok, token());
    for f in arr(&v["frames"]) {
        let got = datagram_frame(
            &epoch_header(tok, local, u32_of(&f["dst"])),
            &spec(&f["data"]),
        );
        assert_eq!(got.is_ok(), f["ok"].as_bool().unwrap(), "{f:?}");
        match got {
            Ok(frame) => assert_bytes(&f["frame"], &frame, "frame"),
            Err(_) => assert_eq!(
                olc_vp8channel::channel::DatagramError::TooLarge.to_string(),
                str_of(&f["error"])
            ),
        }
    }
    for b in arr(&v["batch"]) {
        let name = &b["name"];
        let mut src: VecDeque<Vec<u8>> = arr(&b["queue"])
            .iter()
            .map(|d| {
                datagram_frame(&epoch_header(tok, local, u32_of(&d["dst"])), &spec(d)).unwrap()
            })
            .collect();
        let batch = usize_of(&b["batch_size"]);
        let mut w = Writer::new(Options::with_defaults(30, batch).frame_interval());
        let first = src.pop_front().unwrap();
        let sample = w.batch_datagram_sample_from(&mut src, first, batch);
        assert_bytes(&b["sample"], &sample, &format!("{name} sample"));
        assert_eq!(src.len(), usize_of(&b["queue_left"]), "{name}");
        match (w.pending_datagram(), b.get("pending")) {
            (Some(p), Some(want)) => assert_bytes(want, p, &format!("{name} pending")),
            (None, None) => {}
            (got, _) => panic!("{name}: pending {:?}", got.map(<[u8]>::len)),
        }
    }
    for s in arr(&v["split"]) {
        let input = bytes(s, "hex");
        let name = &s["name"];
        assert_eq!(
            split_datagram_payload(&input).map(hex),
            s["olud"].as_str().map(str::to_owned),
            "{name}"
        );
        let want: Option<Vec<&str>> = s["olub"].as_array().map(|a| a.iter().map(str_of).collect());
        let got: Option<Vec<String>> =
            split_datagram_batch_payload(&input).map(|ps| ps.iter().map(|p| hex(p)).collect());
        assert_eq!(
            got,
            want.map(|w| w.into_iter().map(str::to_owned).collect()),
            "{name}"
        );
    }
}

fn config() -> Config {
    Config {
        channel_id: CHANNEL.into(),
        room_url: String::new(),
        options: Options::with_defaults(30, 1),
        constrained: false,
        carrier: Carrier::Vp8,
    }
}

/// What Go reads off its transport after a frame, from the Rust verdict
/// and the channel's own state.
#[derive(Debug, PartialEq, Eq)]
struct Effects {
    peer_seen: bool,
    data: usize,
    control: usize,
    datagrams: usize,
    touched: bool,
    restart: bool,
}

fn packets_in(payload: &[u8]) -> usize {
    let mut n = 0;
    split_kcp_payload(payload, |_| n += 1);
    n
}

#[test]
fn w27_what_a_client_does_with_each_frame() {
    let v = load("vp8/inbound-verdicts.json");
    let (local, peer) = (u32_of(&v["local_epoch"]), u32_of(&v["peer_epoch"]));
    for c in arr(&v["cases"]) {
        let name = &c["name"];
        let t0 = Instant::now();
        let mut ch = Channel::with_epoch(&config(), t0, local);
        ch.connect(t0);
        let got = Arc::new(AtomicUsize::new(0));
        let sink = Arc::clone(&got);
        ch.set_datagram_sink(Some(Box::new(move |_| {
            sink.fetch_add(1, Ordering::Relaxed);
        })));
        // "confirmed" and "unhealthy": the peer's last frame an hour before
        // this one; "unhealthy_recent": just now.
        let at = match str_of(&c["scenario"]) {
            "fresh" => t0,
            s @ ("confirmed" | "unhealthy" | "unhealthy_recent") => {
                ch.confirm_peer(&format_peer_id(peer), t0).unwrap();
                ch.notify_link_health(s != "confirmed");
                if s == "unhealthy_recent" {
                    t0
                } else {
                    t0 + Duration::from_secs(3600)
                }
            }
            s => panic!("scenario {s}"),
        };
        let frame = bytes(c, "frame");
        let verdict = ch.handle_incoming_frame(&frame, at);
        let payload = frame.get(EPOCH_HDR_LEN..).unwrap_or_default();
        let e = Effects {
            peer_seen: ch.peer_seen(),
            data: if matches!(verdict, Inbound::Data) {
                packets_in(payload)
            } else {
                0
            },
            control: if matches!(verdict, Inbound::Control) {
                packets_in(payload)
            } else {
                0
            },
            datagrams: got.load(Ordering::Relaxed),
            touched: matches!(
                verdict,
                Inbound::Data | Inbound::DataKeepalive | Inbound::Datagram(true)
            ) || matches!(verdict, Inbound::DatagramBatch(n) if n > 0),
            restart: ch.take_reconnect().is_some(),
        };
        let w = &c["effects"];
        let want = Effects {
            peer_seen: w["peer_seen"].as_bool().unwrap(),
            data: usize_of(&w["data"]),
            control: usize_of(&w["control"]),
            datagrams: usize_of(&w["datagrams"]),
            touched: w["touched"].as_bool().unwrap(),
            restart: w["restart"].as_bool().unwrap(),
        };
        assert_eq!(e, want, "{name}: the Rust verdict is {verdict:?}");
    }
}

#[test]
fn w34_w35_the_vp9_dress_and_payloader() {
    let v = load("vp9/carrier.json");
    assert_eq!(hex(&vp9::VP9_HEAD), str_of(&v["head"]));
    let (tok, local, peer) = (
        u32_of(&v["token"]),
        u32_of(&v["local_epoch"]),
        u32_of(&v["peer_epoch"]),
    );
    for d in arr(&v["dress"]) {
        let mut frame = epoch_header(tok, local, peer).to_vec();
        frame.extend_from_slice(&spec(&d["payload"]));
        let mut out = vec![0xee; 7];
        vp9::dress(&mut out, &frame, d["keyframe"].as_bool().unwrap());
        assert_bytes(&d["dressed"], &out, &format!("dress {d}"));
    }
    for u in arr(&v["undress"]) {
        let input = bytes(u, "hex");
        let got = vp9::undress(&input);
        assert_eq!(got.is_some(), u["ok"].as_bool().unwrap(), "{}", u["name"]);
        if let Some(view) = got {
            assert_eq!(hex(view), str_of(&u["view"]), "{}", u["name"]);
        }
    }
    for p in arr(&v["payload"]) {
        let mut pl = vp9::Payloader::with_picture_id(
            u16::try_from(p["picture_id"].as_u64().unwrap()).unwrap(),
        );
        let mtu = usize_of(&p["mtu"]);
        for s in arr(&p["samples"]) {
            let pkts = pl.payload(mtu, &spec(&s["sample"]));
            let want = arr(&s["packets"]);
            assert_eq!(pkts.len(), want.len(), "{s}");
            for (k, w) in pkts.iter().zip(want) {
                assert_bytes(w, k, "vp9 packet");
            }
            assert_eq!(
                u64::from(pl.picture_id()),
                s["next_picture_id"].as_u64().unwrap()
            );
        }
    }
}

fn assert_rtp(want: &[Value], got: &[RtpPacket], what: &str) {
    assert_eq!(got.len(), want.len(), "{what}: packets");
    for (k, w) in got.iter().zip(want) {
        assert_eq!(u64::from(k.seq), w["seq"].as_u64().unwrap(), "{what}: seq");
        assert_eq!(k.timestamp, u32_of(&w["timestamp"]), "{what}: timestamp");
        assert_eq!(k.marker, w["marker"].as_bool().unwrap(), "{what}: marker");
        assert_bytes(&w["payload"], &k.payload, what);
    }
}

#[test]
fn w36_what_pion_makes_of_a_sample() {
    let v = load("vp8/rtp.json");
    assert_eq!(usize_of(&v["payload_mtu"]), PAYLOAD_MTU);

    let heads: std::collections::HashMap<usize, &str> = arr(&v["heads"])
        .iter()
        .map(|h| (usize_of(&h["call"]), str_of(&h["hex"])))
        .collect();
    let boundary: std::collections::HashMap<usize, &Value> = arr(&v["boundary"])
        .iter()
        .map(|b| (usize_of(&b["call"]), b))
        .collect();
    let mut p = Vp8Payloader::default();
    for k in 0..=0x8000 + 2 {
        let full = boundary.get(&k);
        let sample = full.map_or_else(|| vec![0xab], |b| spec(&b["sample"]));
        let out = p.payload(PAYLOAD_MTU, &sample);
        if let Some(h) = heads.get(&k) {
            assert_eq!(hex(&out[0][..out[0].len().min(5)]), *h, "call {k}");
        }
        if let Some(b) = full {
            assert_digest(&b["packets"], &out, &format!("call {k}"));
        }
    }
    assert!(p.payload(PAYLOAD_MTU, &[]).is_empty());

    for s in arr(&v["sizes"]) {
        let mut q = Vp8Payloader::default();
        for _ in 0..usize_of(&s["calls_before"]) {
            q.payload(PAYLOAD_MTU, &[0]);
        }
        let out = q.payload(PAYLOAD_MTU, &spec(&s["sample"]));
        assert_digest(&s["packets"], &out, &format!("{s}"));
    }

    for t in arr(&v["tracks"]) {
        let name = str_of(&t["name"]);
        let d = t["frame_interval_ns"].as_i64().unwrap();
        let seq = u16::try_from(t["seq"].as_u64().unwrap()).unwrap();
        let mut k = Packetizer::new(
            Payloader::Vp8(Vp8Payloader::default()),
            seq,
            u32_of(&t["timestamp"]),
        );
        for s in arr(&t["samples"]) {
            let got = k.packetize(&spec(&s["sample"]), d);
            assert_rtp(arr(&s["packets"]), &got, name);
        }
        let mut last = 0;
        for _ in 0..20_000 {
            last = k.packetize(&[1], d)[0].timestamp;
        }
        assert_eq!(
            last,
            u32_of(&t["after_20000_more"]),
            "{name}: the carried fraction"
        );
    }

    let vk = &v["vp9_keyframe"];
    let pl =
        vp9::Payloader::with_picture_id(u16::try_from(vk["picture_id"].as_u64().unwrap()).unwrap());
    let mut k = Packetizer::new(
        Payloader::Vp9(pl),
        u16::try_from(vk["seq"].as_u64().unwrap()).unwrap(),
        u32_of(&vk["timestamp"]),
    );
    let mut frame = epoch_header(token(), 0x100, 0x200).to_vec();
    frame.extend_from_slice(b"kcp");
    let mut sample = Vec::new();
    vp9::dress(&mut sample, &frame, true);
    let got = k.packetize(&sample, 1_000_000_000 / 60);
    assert_rtp(arr(&vk["packets"]), &got, "vp9 keyframe");
}

/// `zzREDPayload`.
fn red_payload(pt: u8, primary: &[u8], redundant: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in redundant {
        let n = u16::try_from(b.len()).unwrap();
        out.extend_from_slice(&[0x80 | pt, 0, (n >> 8) as u8 & 0x03, n as u8]);
    }
    out.push(pt);
    for b in redundant {
        out.extend_from_slice(b);
    }
    out.extend_from_slice(primary);
    out
}

/// `zzGenerate`: the frames, peer to us, through our packetizer at 60 fps.
fn generate(payloader: Payloader, seq: u16, frames: &[Value], dress: bool) -> Vec<RtpPacket> {
    let mut k = Packetizer::new(payloader, seq, 0);
    let mut out = Vec::new();
    for f in frames {
        let mut frame = epoch_header(token(), 0x200, 0x100).to_vec();
        frame.extend_from_slice(&spec(f));
        let sample = if dress {
            let mut d = Vec::new();
            vp9::dress(&mut d, &frame, f["keyframe"].as_bool().unwrap_or(false));
            d
        } else {
            frame
        };
        out.extend(k.packetize(&sample, 1_000_000_000 / 60));
    }
    out
}

/// `zzListDigest`.
fn assert_list(want: &Value, pkts: &[RtpPacket]) {
    assert_eq!(pkts.len(), usize_of(&want["packets"]), "generated packets");
    let mut all = Vec::new();
    for p in pkts {
        all.extend_from_slice(&p.seq.to_be_bytes());
        all.push(u8::from(p.marker));
        all.extend_from_slice(&u32::try_from(p.payload.len()).unwrap().to_be_bytes());
        all.extend_from_slice(&p.payload);
    }
    assert_eq!(
        sha256_hex(&all),
        str_of(&want["sha256"]),
        "generated packets"
    );
}

/// `zzRunReader`'s script on a [`TrackReader`]: a microsecond a step, and a
/// second more on an aged one (the Go side ages the gap it holds).
fn run_reader(v: &Value, carrier: Carrier, mime: &str, gen: &[RtpPacket]) {
    let mut r = TrackReader::new(carrier, mime).unwrap();
    let steps = arr(&v["steps"]);
    let outs = arr(&v["out"]);
    assert_eq!(steps.len(), outs.len());
    let mut now = Instant::now();
    for (n, (s, want)) in steps.iter().zip(outs).enumerate() {
        now += Duration::from_micros(1);
        if s["aged"].as_bool().unwrap_or(false) {
            now += Duration::from_secs(1);
        }
        let (seq, mut marker, mut payload) = if let Some(i) = s["i"].as_u64() {
            let g = &gen[usize::try_from(i).unwrap()];
            (g.seq, g.marker, g.payload.clone())
        } else {
            (
                u16::try_from(s["seq"].as_u64().unwrap()).unwrap(),
                false,
                bytes(s, "raw"),
            )
        };
        if let Some(m) = s["marker"].as_bool() {
            marker = m;
        }
        payload = match s["red"].as_str().unwrap_or("") {
            "" => payload,
            "plain" => red_payload(96, &payload, &[]),
            "one" => red_payload(96, &payload, &[&payload[..payload.len().min(10)]]),
            "fec" => red_payload(106, &payload, &[]),
            other => panic!("red {other}"),
        };
        let before = (r.reorder().next_seq(), r.reorder().held());
        let mut frames = Vec::new();
        r.push(seq, marker, 96, &payload, now, &mut |f| {
            frames.push(f.to_vec())
        });
        if want["skipped"].as_bool().unwrap_or(false) {
            assert!(frames.is_empty(), "step {n}: a skipped packet made a frame");
            assert_eq!(
                (r.reorder().next_seq(), r.reorder().held()),
                before,
                "step {n}: skipped"
            );
            continue;
        }
        let wf = arr(&want["frames"]);
        assert_eq!(frames.len(), wf.len(), "step {n} ({s}): frames");
        for (f, w) in frames.iter().zip(wf) {
            assert_bytes(w, f, &format!("step {n} frame"));
        }
        assert_eq!(
            u64::from(r.reorder().next_seq()),
            want["next_seq"].as_u64().unwrap(),
            "step {n}: next seq"
        );
        assert_eq!(
            r.reorder().held(),
            usize_of(&want["held"]),
            "step {n}: held"
        );
    }
}

#[test]
fn w36_w37_the_track_reader() {
    let v = load("vp8/rtp-reader.json");
    for c in arr(&v["red"]) {
        let input = bytes(c, "hex");
        let got = red_primary(&input);
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{}", c["name"]);
        if let Ok((pt, data)) = got {
            assert_eq!(u64::from(pt), c["pt"].as_u64().unwrap(), "{}", c["name"]);
            assert_eq!(hex(data), str_of(&c["data"]), "{}", c["name"]);
        }
    }
    for c in arr(&v["accepts"]) {
        let m = str_of(&c["mime"]);
        assert_eq!(accepts(Carrier::Vp8, m), c["vp8"].as_bool().unwrap(), "{m}");
        assert_eq!(accepts(Carrier::Vp8, m), c["own"].as_bool().unwrap(), "{m}");
        assert_eq!(accepts(Carrier::Vp9, m), c["vp9"].as_bool().unwrap(), "{m}");
    }

    let s = &v["vp8"];
    let gen = generate(
        Payloader::Vp8(Vp8Payloader::default()),
        65534,
        arr(&s["frames"]),
        false,
    );
    assert_list(&s["generated"], &gen);
    run_reader(s, Carrier::Vp8, "video/VP8", &gen);

    let s = &v["vp8_red"];
    let gen = generate(
        Payloader::Vp8(Vp8Payloader::default()),
        1000,
        arr(&s["frames"]),
        false,
    );
    assert_list(&s["generated"], &gen);
    run_reader(s, Carrier::Vp8, "video/red", &gen);

    let s = &v["vp9"];
    let id = u16::try_from(s["picture_id"].as_u64().unwrap()).unwrap();
    let gen = generate(
        Payloader::Vp9(vp9::Payloader::with_picture_id(id)),
        200,
        arr(&s["frames"]),
        true,
    );
    assert_list(&s["generated"], &gen);
    run_reader(s, Carrier::Vp9, "video/VP9", &gen);
}

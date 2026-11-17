//! Differential tests against the Go decode oracle: bytes Rust makes are read
//! by the engine's own code at the pin, Go's bytes are read by Rust, and both
//! sides' verdicts are compared on the same seeded inputs. Each test skips,
//! saying so, when `OLC_GO_ORACLE` does not name a built oracle.

use std::io::Cursor;

use olc_interop::{hex, unhex, Oracle, Rng};
use olc_wire::handshake::{self, Challenge, Reply};
use olc_wire::record::{KeySet, Lane, Role};
use olc_wire::{connect, control, framing, gojson, udpwire};
use serde_json::{json, Value};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a u64: {v}"))
}

/// Bytes that exercise an encoder: printable ASCII, the escaped ones,
/// controls, DEL, valid multi-byte UTF-8, U+2028, and broken sequences.
fn tricky_bytes(rng: &mut Rng, max_len: usize) -> Vec<u8> {
    const PIECES: &[&[u8]] = &[
        b"a",
        b"Z",
        b"0",
        b".",
        b"-",
        b"\"",
        b"\\",
        b"/",
        b"<",
        b">",
        b"&",
        b" ",
        b"\x00",
        b"\x01",
        b"\x08",
        b"\t",
        b"\n",
        b"\x0c",
        b"\r",
        b"\x1f",
        b"\x7f",
        "é".as_bytes(),
        "😀".as_bytes(),
        "\u{2028}".as_bytes(),
        "\u{2029}".as_bytes(),
        "\u{fffd}".as_bytes(),
        b"\xff",
        b"\xfe",
        b"\xc3",
        b"\xe2\x82",
        b"\xed\xa0\x80",
        b"\xf0\x9f\x98",
        b"\xc0\x80",
        b"\xf4\x90\x80\x80",
        b"\x80",
    ];
    let n = rng.below(max_len + 1);
    let mut out = Vec::new();
    for _ in 0..n {
        out.extend_from_slice(PIECES[rng.below(PIECES.len())]);
    }
    out
}

fn keyset(o: &mut Oracle, id: &str, psk: &[u8], role: &str) {
    let r = o.call(&json!({"op": "keyset", "id": id, "key_hex": hex(psk), "role": role}));
    assert_eq!(r["verdict"], "ok");
}

#[test]
fn records_cross_both_ways_on_every_lane() {
    let Some(mut o) = Oracle::from_env("records_cross_both_ways_on_every_lane") else {
        return;
    };
    let mut rng = Rng::new(1);
    let psk = rng.bytes(32);
    keyset(&mut o, "c", &psk, "client");
    keyset(&mut o, "s", &psk, "server");
    let client = KeySet::new(&psk, Role::Client).unwrap();
    let server = KeySet::new(&psk, Role::Server).unwrap();
    for lane in Lane::ALL {
        for i in 0..40 {
            let len = match i {
                0 => 0,
                1 => 12244,
                2 => 32776,
                _ => rng.below(2000),
            };
            let plain = rng.bytes(len);
            // Rust seals, Go opens.
            let mut record = Vec::new();
            client.seal_into(lane, &plain, &mut record).unwrap();
            let r = o
                .call(&json!({"op": "open", "id": "s", "lane": lane.name(), "data": hex(&record)}));
            assert_eq!(r["verdict"], "ok", "{} #{i}", lane.name());
            assert_eq!(s(&r["plaintext"]), hex(&plain));
            // Go seals, Rust opens.
            let r =
                o.call(&json!({"op": "seal", "id": "c", "lane": lane.name(), "data": hex(&plain)}));
            assert_eq!(r["verdict"], "ok");
            let mut out = Vec::new();
            server
                .open_into(lane, &unhex(s(&r["record"])), &mut out)
                .unwrap();
            assert_eq!(out, plain, "{} #{i}", lane.name());
        }
    }
}

#[test]
fn the_replay_window_judges_every_record_as_go_does() {
    let Some(mut o) = Oracle::from_env("the_replay_window_judges_every_record_as_go_does") else {
        return;
    };
    let mut rng = Rng::new(2);
    let psk = rng.bytes(32);
    keyset(&mut o, "rx", &psk, "server");
    let rust_rx = KeySet::new(&psk, Role::Server).unwrap();
    // Four senders: four key sets of the same key, each with its own
    // prefixes, as four runs of a client would be.
    let senders: Vec<KeySet> = (0..4)
        .map(|_| KeySet::new(&psk, Role::Client).unwrap())
        .collect();
    let mut sealed: Vec<(Lane, Vec<u8>)> = Vec::new();
    for _ in 0..400 {
        let lane = Lane::ALL[rng.below(3)];
        let sender = &senders[rng.below(senders.len())];
        let mut record = Vec::new();
        sender
            .seal_into(lane, &rng.bytes_below(40), &mut record)
            .unwrap();
        sealed.push((lane, record));
    }
    let mut checked = 0;
    for step in 0..2500 {
        // Mostly records near the newest, so the window moves forward, falls
        // behind, and sees duplicates; some damaged on the way.
        let newest = (step * sealed.len() / 2500).max(1);
        let back = rng.below(100.min(newest));
        let (lane, mut record) = sealed[newest - 1 - back].clone();
        let lane = if rng.below(20) == 0 {
            Lane::ALL[rng.below(3)]
        } else {
            lane
        };
        match rng.below(16) {
            0 => {
                let at = rng.below(record.len());
                record[at] ^= 1 << rng.below(8);
            }
            1 => record.truncate(rng.below(record.len())),
            2 => record[4..12].fill(0),
            3 => record[0] = b'X',
            _ => {}
        }
        let mut out = Vec::new();
        let rust = rust_rx.open_into(lane, &record, &mut out);
        let go =
            o.call(&json!({"op": "open", "id": "rx", "lane": lane.name(), "data": hex(&record)}));
        let verdict = rust.map_or_else(|e| e.verdict(), |_| "ok");
        assert_eq!(verdict, s(&go["verdict"]), "step {step}");
        if verdict == "ok" {
            assert_eq!(hex(&out), s(&go["plaintext"]), "step {step}");
        }
        let stats = rust_rx.reorder_stats(lane);
        assert_eq!(
            (stats.skipped, stats.late),
            (u(&go["skipped"]), u(&go["late"])),
            "step {step}"
        );
        checked += 1;
    }
    assert_eq!(checked, 2500);
}

#[test]
fn frames_read_as_go_reads_them() {
    let Some(mut o) = Oracle::from_env("frames_read_as_go_reads_them") else {
        return;
    };
    let mut rng = Rng::new(3);
    for i in 0..600 {
        let max = [0usize, 1, 4, 16, 64][rng.below(5)];
        let declared = match rng.below(4) {
            0 => rng.below(8),
            1 => max.saturating_sub(1) + rng.below(3),
            2 => rng.below(80),
            // Go allocates the declared length before it reads
            // (framing.go:64), so a length far past the input is only tried
            // under a limit, which refuses it first.
            _ if max > 0 => rng.next_u64() as u32 as usize,
            _ => 100 + rng.below(100),
        };
        let mut input = u32::try_from(declared)
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        input.extend(rng.bytes_below(90));
        input.truncate(rng.below(input.len() + 1).max(if rng.below(4) == 0 {
            0
        } else {
            input.len()
        }));
        let mut r = Cursor::new(&input[..]);
        let mut body = Vec::new();
        let verdict = framing::read(&mut r, max, &mut body).map_or_else(|e| e.verdict(), |()| "ok");
        let go = o.call(&json!({"op": "frame_read", "data": hex(&input), "max": max}));
        assert_eq!(verdict, s(&go["verdict"]), "#{i}");
        assert_eq!(r.position(), u(&go["consumed"]), "#{i}");
        if verdict == "ok" {
            assert_eq!(hex(&body), s(&go["body"]), "#{i}");
        }
    }
}

#[test]
fn strings_are_written_as_go_writes_them() {
    let Some(mut o) = Oracle::from_env("strings_are_written_as_go_writes_them") else {
        return;
    };
    let mut rng = Rng::new(4);
    for i in 0..3000 {
        let input = tricky_bytes(&mut rng, 12);
        let mut ours = Vec::new();
        gojson::write_string(&mut ours, &input);
        let go = o.call(&json!({"op": "json_string", "data": hex(&input)}));
        assert_eq!(hex(&ours), s(&go["json"]), "#{i}: input {}", hex(&input));
    }
}

#[test]
fn hellos_are_go_hellos_and_the_go_server_takes_them() {
    let Some(mut o) = Oracle::from_env("hellos_are_go_hellos_and_the_go_server_takes_them") else {
        return;
    };
    let mut rng = Rng::new(5);
    for i in 0..400 {
        let device_id = tricky_bytes(&mut rng, 16);
        let challenge = Challenge::from_bytes(rng.bytes(16).try_into().unwrap());
        let challenge_hex = String::from_utf8(challenge.to_hex().to_vec()).unwrap();
        let mut frame = Vec::new();
        handshake::encode_hello(&device_id, &challenge, &mut frame).unwrap();
        let go = o.call(
            &json!({"op": "hello_frame", "data": hex(&device_id), "challenge": challenge_hex}),
        );
        assert_eq!(hex(&frame), s(&go["frame"]), "#{i}");
        let session = format!("sess-{i}");
        let peer = if i % 3 == 0 {
            String::new()
        } else {
            format!("peer-{i}")
        };
        let go = o.call(&json!({"op": "hello_server", "data": hex(&frame), "session_id": session, "peer_id": peer}));
        assert_eq!(go["verdict"], "ok", "#{i}");
        assert_eq!(go["version"], 3);
        assert_eq!(go["type"], handshake::TYPE_HELLO);
        assert_eq!(s(&go["challenge"]), challenge_hex);
        if std::str::from_utf8(&device_id).is_ok() {
            assert_eq!(s(&go["device_id"]), hex(&device_id), "#{i}");
        }
        let reply = unhex(s(&go["reply"]));
        let mut buf = Vec::new();
        let (welcome, skipped) =
            handshake::read_welcome(&mut Cursor::new(&reply[..]), &challenge, &mut buf).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(
            (welcome.session_id, welcome.peer_id),
            (session, peer),
            "#{i}"
        );
    }
    // A refusal reads as one.
    let challenge = Challenge::from_bytes([7; 16]);
    let mut frame = Vec::new();
    handshake::encode_hello(b"dev", &challenge, &mut frame).unwrap();
    let go =
        o.call(&json!({"op": "hello_server", "data": hex(&frame), "auth_error": "no such key"}));
    assert_eq!(go["verdict"], "auth");
    let reply = unhex(s(&go["reply"]));
    let (body, _) = framing::try_decode(&reply, handshake::MAX_MESSAGE_SIZE)
        .unwrap()
        .unwrap();
    match handshake::parse_reply(body, &challenge) {
        Err(handshake::HandshakeError::Rejected(reason)) => assert_eq!(reason, "no such key"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        handshake::parse_reply(body, &Challenge::from_bytes([8; 16])).unwrap(),
        Reply::NotOurs
    );
}

#[test]
fn control_messages_read_back_in_go() {
    let Some(mut o) = Oracle::from_env("control_messages_read_back_in_go") else {
        return;
    };
    let mut rng = Rng::new(6);
    for i in 0..400 {
        let kind = [
            control::MsgType::Ping,
            control::MsgType::Pong,
            control::MsgType::Close,
        ][rng.below(3)];
        let seq = if rng.below(4) == 0 {
            0
        } else {
            rng.next_u64() >> rng.below(64)
        };
        let sent = if rng.below(4) == 0 {
            0
        } else {
            rng.next_u64() as i64 >> rng.below(63)
        };
        let msg = control::Message {
            kind,
            seq,
            sent_unix_nano: sent,
        };
        let mut frame = Vec::new();
        control::encode(&msg, &mut frame).unwrap();
        let go = o.call(&json!({"op": "control_read", "data": hex(&frame)}));
        assert_eq!(go["verdict"], "ok", "#{i}");
        assert_eq!(s(&go["type"]), kind.as_str());
        assert_eq!(u(&go["seq"]), seq, "#{i}");
        assert_eq!(go["sent_unix_nano"].as_i64().unwrap(), sent, "#{i}");
        assert_eq!(
            control::read(&mut Cursor::new(&frame[..]), &mut Vec::new()).unwrap(),
            msg
        );
    }
}

#[test]
fn connect_requests_are_go_requests_and_the_go_server_reads_them() {
    let Some(mut o) =
        Oracle::from_env("connect_requests_are_go_requests_and_the_go_server_reads_them")
    else {
        return;
    };
    let mut rng = Rng::new(7);
    for i in 0..600 {
        let host = tricky_bytes(&mut rng, 20);
        let port = match rng.below(5) {
            0 => 0,
            1 => 65535,
            _ => u16::try_from(rng.below(65536)).unwrap(),
        };
        let mut ours = Vec::new();
        connect::encode_request(&host, port, &mut ours);
        assert!(ours.len() <= connect::MAX_REQUEST_SIZE);
        let go = o.call(&json!({"op": "connect_frame", "data": hex(&host), "port": port}));
        assert_eq!(hex(&ours), s(&go["request"]), "#{i}: host {}", hex(&host));
        let go = o.call(&json!({"op": "connect_parse", "data": hex(&ours)}));
        assert_eq!(go["parsed"], true, "#{i}");
        assert_eq!(go["cmd"], connect::COMMAND);
        assert_eq!(u(&go["port"]), u64::from(port), "#{i}");
        if std::str::from_utf8(&host).is_ok() {
            assert_eq!(s(&go["addr"]), hex(&host), "#{i}");
        }
    }
}

/// A host for the UDP encoder: pieces of addresses, names and junk, so that
/// what `netip.ParseAddr` accepts and refuses is crossed often.
fn udp_host(rng: &mut Rng) -> Vec<u8> {
    const PIECES: &[&[u8]] = &[
        b"0",
        b"1",
        b"9",
        b"01",
        b"255",
        b"256",
        b"1234",
        b"12345",
        b"ffff",
        b"FFFF",
        b"a",
        b"g",
        b".",
        b".",
        b":",
        b":",
        b"::",
        b"%",
        b"%eth0",
        b"[",
        b"]",
        b" ",
        b"\t",
        b"x",
        b"-",
        "é".as_bytes(),
        b"\xff",
        b"~",
        b"!",
    ];
    if rng.below(8) == 0 {
        return vec![b'a'; 250 + rng.below(10)];
    }
    let n = rng.below(10);
    let mut out = Vec::new();
    for _ in 0..n {
        out.extend_from_slice(PIECES[rng.below(PIECES.len())]);
    }
    out
}

#[test]
fn udp_frames_encode_and_decode_as_go_does() {
    let Some(mut o) = Oracle::from_env("udp_frames_encode_and_decode_as_go_does") else {
        return;
    };
    let mut rng = Rng::new(8);
    let mut wires = Vec::new();
    for i in 0..3000 {
        let type_byte = [1u8, 1, 1, 2, 2, 0, 3][rng.below(7)];
        let host = if type_byte == 2 && rng.below(3) != 0 {
            Vec::new()
        } else {
            udp_host(&mut rng)
        };
        let flow = if rng.below(10) == 0 {
            0
        } else {
            rng.next_u64() | 1
        };
        let port = match rng.below(6) {
            0 => 0,
            _ if type_byte == 2 && rng.below(2) == 0 => 0,
            _ => u16::try_from(rng.below(65535) + 1).unwrap(),
        };
        let payload = match rng.below(8) {
            0 => rng.bytes(1200),
            1 => rng.bytes(1201),
            _ if type_byte == 2 => Vec::new(),
            _ => rng.bytes_below(30),
        };
        let go = o.call(
            &json!({"op": "udpwire_encode", "data": hex(&host), "type": type_byte, "flow_id": flow,
            "port": port, "payload": hex(&payload)}),
        );
        let mut ours = Vec::new();
        let verdict = match udpwire::FrameType::from_byte(type_byte) {
            None => "unknown_type",
            Some(kind) => udpwire::encode(kind, flow, &host, port, &payload, &mut ours)
                .map_or_else(|e| e.verdict(), |()| "ok"),
        };
        assert_eq!(
            verdict,
            s(&go["verdict"]),
            "#{i}: host {:?}",
            String::from_utf8_lossy(&host)
        );
        if verdict == "ok" {
            assert_eq!(
                hex(&ours),
                s(&go["wire"]),
                "#{i}: host {:?}",
                String::from_utf8_lossy(&host)
            );
            wires.push(ours);
        }
    }
    assert!(
        wires.len() > 500,
        "enough frames to decode: {}",
        wires.len()
    );
    for i in 0..3000 {
        let mut wire = wires[rng.below(wires.len())].clone();
        match rng.below(6) {
            0 => {
                let at = rng.below(wire.len().min(20));
                wire[at] = rng.bytes(1)[0];
            }
            1 => wire.truncate(rng.below(wire.len() + 1)),
            2 => wire[12] = [0u8, 1, 2, 3, 4, 5][rng.below(6)],
            3 => wire[15] = rng.bytes(1)[0],
            4 => {
                let at = 16 + rng.below(wire.len().saturating_sub(16).max(1));
                if at < wire.len() {
                    wire[at] = [b' ', 0x7f, 0x80, b'a'][rng.below(4)];
                }
            }
            _ => {}
        }
        let go = o.call(&json!({"op": "udpwire_decode", "data": hex(&wire)}));
        match udpwire::decode(&wire) {
            Ok(f) => {
                assert_eq!(go["verdict"], "ok", "#{i}: {}", hex(&wire));
                assert_eq!(u(&go["type"]), u64::from(f.kind as u8));
                assert_eq!(u(&go["flow_id"]), f.flow_id);
                assert_eq!(s(&go["host"]), f.host.to_string(), "#{i}: {}", hex(&wire));
                assert_eq!(u(&go["port"]), u64::from(f.port));
                assert_eq!(s(&go["payload"]), hex(f.payload));
            }
            Err(e) => assert_eq!(e.verdict(), s(&go["verdict"]), "#{i}: {}", hex(&wire)),
        }
    }
}

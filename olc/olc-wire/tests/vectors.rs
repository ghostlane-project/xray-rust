//! The golden vectors of the Go engine at the pin
//! (`olc/interop/vectors/2d4266af/`), checked against olc-wire: every byte
//! the Go code wrote, Rust writes; every verdict it gave, Rust gives.

use std::io::Cursor;
use std::time::Duration;

use olc_interop::{bytes, hex, load, pattern, sha256_hex, unhex};
use olc_wire::handshake::{self, Challenge, HandshakeError, Reply};
use olc_wire::record::{self, derive_keys, KeySet, Lane, OpenError, Role, SealError};
use olc_wire::sizes::{self, BufferProfile, SmuxSession};
use olc_wire::{connect, control, framing, udpwire};
use serde_json::Value;

fn u64_of(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a u64: {v}"))
}

fn i64_of(v: &Value) -> i64 {
    v.as_i64().unwrap_or_else(|| panic!("not an i64: {v}"))
}

fn usize_of(v: &Value) -> usize {
    usize::try_from(u64_of(v)).expect("fits usize")
}

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn ms(v: &Value) -> Duration {
    Duration::from_millis(u64_of(v))
}

fn lane(name: &str) -> Lane {
    Lane::ALL
        .into_iter()
        .find(|l| l.name() == name)
        .unwrap_or_else(|| panic!("unknown lane {name}"))
}

fn role(name: &str) -> Option<Role> {
    match name {
        "client" => Some(Role::Client),
        "server" => Some(Role::Server),
        _ => None,
    }
}

fn prefix(case: &Value) -> [u8; 16] {
    bytes(case, "prefix").try_into().expect("16 bytes")
}

/// A case's plaintext: hex, or a `zzvectors.Pattern` spec.
fn plaintext(case: &Value) -> Vec<u8> {
    if let Some(spec) = case.get("plaintext_pattern") {
        let seed = u8::try_from(u64_of(&spec["seed"])).expect("a byte");
        return pattern(usize_of(&spec["len"]), seed);
    }
    bytes(case, "plaintext")
}

// W01 ----------------------------------------------------------------------

#[test]
fn w01_directional_keys() {
    let c = load("crypto/keys.json");
    assert_eq!(c["client_to_server_label"], record::CLIENT_TO_SERVER_LABEL);
    assert_eq!(c["server_to_client_label"], record::SERVER_TO_CLIENT_LABEL);
    assert_eq!(
        c["record_magic"].as_str().unwrap().as_bytes(),
        record::RECORD_MAGIC
    );
    assert_eq!(usize_of(&c["nonce_prefix_size"]), record::NONCE_PREFIX_SIZE);
    assert_eq!(
        usize_of(&c["record_header_size"]),
        record::RECORD_HEADER_SIZE
    );
    assert_eq!(usize_of(&c["wire_overhead"]), record::WIRE_OVERHEAD);
    assert_eq!(u64_of(&c["replay_window_size"]), record::REPLAY_WINDOW_SIZE);
    assert_eq!(
        usize_of(&c["max_replay_senders"]),
        record::MAX_REPLAY_SENDERS
    );
    for case in c["keys"].as_array().unwrap() {
        let psk: [u8; 32] = bytes(case, "psk").try_into().unwrap();
        let keys = derive_keys(&psk);
        assert_eq!(
            hex(&keys.client_to_server),
            str_of(&case["client_to_server"])
        );
        assert_eq!(
            hex(&keys.server_to_client),
            str_of(&case["server_to_client"])
        );
    }
    for case in c["invalid_psk_lengths"].as_array().unwrap() {
        let len = usize_of(&case["len"]);
        assert_eq!(case["verdict"], "invalid_key_size");
        assert_eq!(
            KeySet::new(&vec![0; len], Role::Client).unwrap_err(),
            record::KeyError::Size(len)
        );
    }
}

#[test]
fn w01_setup_key_set() {
    let c = load("runtime.json");
    for case in c["setup_key_set"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let Some(role) = role(str_of(&case["role"])) else {
            // Go's role is an int and can be 0 or 3; Rust's cannot.
            assert!(str_of(&case["verdict"]).starts_with("other: "), "{name}");
            continue;
        };
        match KeySet::from_hex(str_of(&case["key_hex"]), role) {
            Ok(keys) => {
                assert_eq!(case["verdict"], "ok", "{name}");
                assert_eq!(keys.role(), role);
            }
            Err(e) => {
                assert_eq!(e.verdict(), case["verdict"], "{name}");
                assert_eq!(e.to_string(), str_of(&case["error_text"]), "{name}");
            }
        }
    }
}

// W02, W03, W05 ------------------------------------------------------------

#[test]
fn w02_w03_w05_seal() {
    let c = load("crypto/seal.json");
    let psk = bytes(&c, "psk");
    for case in c["cases"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let lane = lane(str_of(&case["lane"]));
        assert_eq!(lane.aad(), str_of(&case["aad"]).as_bytes());
        let keys = KeySet::with_prefixes(
            &psk,
            role(str_of(&case["role"])).unwrap(),
            [prefix(case); 3],
        )
        .unwrap();
        keys.set_last_counter(lane, u64_of(&case["counter_before"]));
        let mut out = vec![0xee];
        let result = keys.seal_into(lane, &plaintext(case), &mut out);
        match str_of(&case["verdict"]) {
            "ok" => {
                result.unwrap();
                let record = &out[1..];
                assert_eq!(record.len(), usize_of(&case["record_len"]), "{name}");
                match case.get("record") {
                    Some(want) => assert_eq!(hex(record), str_of(want), "{name}"),
                    None => {
                        assert_eq!(sha256_hex(record), str_of(&case["record_sha256"]), "{name}")
                    }
                }
            }
            "counter_exhausted" => {
                assert_eq!(result, Err(SealError::CounterExhausted), "{name}");
                assert_eq!(
                    out,
                    [0xee],
                    "{name}: a refused seal leaves the buffer alone"
                );
            }
            other => panic!("{name}: unknown verdict {other}"),
        }
    }
    for seq in c["sequences"].as_array().unwrap() {
        let lane = lane(str_of(&seq["lane"]));
        let keys =
            KeySet::with_prefixes(&psk, role(str_of(&seq["role"])).unwrap(), [prefix(seq); 3])
                .unwrap();
        for (plain, want) in seq["plaintexts"]
            .as_array()
            .unwrap()
            .iter()
            .zip(seq["records"].as_array().unwrap())
        {
            let mut out = Vec::new();
            keys.seal_into(lane, &unhex(str_of(plain)), &mut out)
                .unwrap();
            assert_eq!(hex(&out), str_of(want), "{}", seq["name"]);
        }
    }
}

// W04 ----------------------------------------------------------------------

#[test]
fn w04_open_verdicts_and_the_replay_window() {
    let c = load("crypto/open.json");
    let psk = bytes(&c, "psk");
    for seq in c["sequences"].as_array().unwrap() {
        let name = str_of(&seq["name"]);
        let keys = KeySet::new(&psk, role(str_of(&seq["receiver"])).unwrap()).unwrap();
        for (i, step) in seq["steps"].as_array().unwrap().iter().enumerate() {
            let lane = lane(str_of(&step["lane"]));
            let record = bytes(step, "record");
            let mut out = vec![0xee];
            let verdict = match keys.open_into(lane, &record, &mut out) {
                Ok(n) => {
                    assert_eq!(n, out.len() - 1);
                    if let Some(plain) = step.get("plain") {
                        assert_eq!(hex(&out[1..]), str_of(plain), "{name} step {i}");
                    }
                    "ok"
                }
                Err(e) => {
                    assert_eq!(
                        out,
                        [0xee],
                        "{name} step {i}: a failed open leaves the buffer alone"
                    );
                    e.verdict()
                }
            };
            assert_eq!(
                verdict,
                str_of(&step["verdict"]),
                "{name} step {i} ({})",
                step["note"]
            );
        }
        for lane in Lane::ALL {
            let want = &seq["reorder"][lane.name()];
            let stats = keys.reorder_stats(lane);
            assert_eq!(
                stats.skipped,
                u64_of(&want["skipped"]),
                "{name} {}",
                lane.name()
            );
            assert_eq!(stats.late, u64_of(&want["late"]), "{name} {}", lane.name());
        }
    }
}

#[test]
fn w04_open_in_place_agrees_with_open_into() {
    let c = load("crypto/open.json");
    let psk = bytes(&c, "psk");
    let seq = &c["sequences"][0];
    let keys = KeySet::new(&psk, Role::Server).unwrap();
    let step = &seq["steps"][0];
    let mut record = bytes(step, "record");
    let plain = keys
        .open_in_place(lane(str_of(&step["lane"])), &mut record)
        .unwrap();
    assert_eq!(hex(plain), str_of(&step["plain"]));
    let mut record = bytes(step, "record");
    assert_eq!(
        keys.open_in_place(Lane::Data, &mut record).unwrap_err(),
        OpenError::Duplicate
    );
}

// W07 ----------------------------------------------------------------------

#[test]
fn w07_framing() {
    let c = load("framing.json");
    assert_eq!(usize_of(&c["header_size"]), framing::HEADER_SIZE);
    for case in c["write"].as_array().unwrap() {
        let body = bytes(case, "body");
        let max = usize_of(&case["max"]);
        let mut out = vec![0xee];
        let result = framing::encode(&body, max, &mut out);
        match str_of(&case["verdict"]) {
            "ok" => {
                result.unwrap();
                assert_eq!(hex(&out[1..]), str_of(&case["frame"]));
                assert_eq!(case["writes"], 1, "Go writes a frame with one Write");
                let mut built = Vec::new();
                let frame = framing::Frame::begin(&mut built);
                built.extend_from_slice(&body);
                frame.finish(&mut built, max).unwrap();
                assert_eq!(built, out[1..]);
            }
            "too_large" => {
                assert!(result.is_err());
                assert_eq!(out, [0xee]);
                assert_eq!(case["writes"], 0);
            }
            other => panic!("unknown verdict {other}"),
        }
    }
    for case in c["read"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let input = bytes(case, "input");
        let max = usize_of(&case["max"]);
        let mut r = Cursor::new(&input[..]);
        let mut body = Vec::new();
        let verdict = match framing::read(&mut r, max, &mut body) {
            Ok(()) => {
                assert_eq!(hex(&body), case.get("body").map_or("", str_of), "{name}");
                "ok"
            }
            Err(e) => e.verdict(),
        };
        assert_eq!(verdict, str_of(&case["verdict"]), "{name}");
        assert_eq!(r.position(), u64_of(&case["consumed"]), "{name}");
        match framing::try_decode(&input, max) {
            Ok(Some((b, used))) => {
                assert_eq!(verdict, "ok", "{name}");
                assert_eq!(
                    (b, used as u64),
                    (&body[..], u64_of(&case["consumed"])),
                    "{name}"
                );
            }
            Ok(None) => assert!(
                verdict.starts_with("eof") || verdict.starts_with("truncated"),
                "{name}"
            ),
            Err(_) => assert_eq!(verdict, "too_large", "{name}"),
        }
    }
}

// W08 ----------------------------------------------------------------------

#[test]
fn w08_hello() {
    let c = load("handshake/hello.json");
    let k = &c["constants"];
    assert_eq!(i64_of(&k["proto_version"]), handshake::PROTO_VERSION);
    assert_eq!(usize_of(&k["challenge_size"]), handshake::CHALLENGE_SIZE);
    assert_eq!(
        usize_of(&k["max_message_size"]),
        handshake::MAX_MESSAGE_SIZE
    );
    assert_eq!(ms(&k["default_timeout_ms"]), handshake::DEFAULT_TIMEOUT);
    assert_eq!(k["type_hello"], handshake::TYPE_HELLO);
    assert_eq!(k["type_welcome"], handshake::TYPE_WELCOME);
    assert_eq!(k["type_reject"], handshake::TYPE_REJECT);
    for case in c["cases"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let device_id = match case.get("device_id_fill") {
            Some(fill) => str_of(fill)
                .as_bytes()
                .repeat(usize_of(&case["device_id_len"])),
            None if case.get("device_id_hex").is_some() => bytes(case, "device_id_hex"),
            None => Vec::new(),
        };
        assert_eq!(device_id.len(), usize_of(&case["device_id_len"]), "{name}");
        let challenge = Challenge::from_bytes(bytes(case, "challenge").try_into().unwrap());
        assert_eq!(
            &challenge.to_hex()[..],
            str_of(&case["challenge"]).as_bytes()
        );
        let mut out = Vec::new();
        let result = handshake::encode_hello(&device_id, &challenge, &mut out);
        match str_of(&case["verdict"]) {
            "ok" => {
                result.unwrap();
                assert_eq!(out.len(), usize_of(&case["frame_len"]), "{name}");
                match case.get("frame") {
                    Some(want) => assert_eq!(hex(&out), str_of(want), "{name}"),
                    None => assert_eq!(sha256_hex(&out), str_of(&case["frame_sha256"]), "{name}"),
                }
            }
            "frame_too_large" => {
                assert!(result.is_err(), "{name}");
                assert!(out.is_empty(), "{name}");
            }
            other => panic!("{name}: unknown verdict {other}"),
        }
    }
}

// W09 ----------------------------------------------------------------------

/// The client's loop over replies, counting the ones it skips also when the
/// handshake then fails.
fn read_replies(
    input: &[u8],
    challenge: &Challenge,
) -> (Result<handshake::Welcome, HandshakeError>, u64) {
    let mut r = Cursor::new(input);
    let mut buf = Vec::new();
    let mut skipped = 0;
    loop {
        if let Err(e) = framing::read(&mut r, handshake::MAX_MESSAGE_SIZE, &mut buf) {
            return (Err(e.into()), skipped);
        }
        match handshake::parse_reply(&buf, challenge) {
            Ok(Reply::NotOurs) => skipped += 1,
            Ok(Reply::Welcome(w)) => return (Ok(w), skipped),
            Err(e) => return (Err(e), skipped),
        }
    }
}

#[test]
fn w09_replies() {
    for case in load("handshake/client.json").as_array().unwrap() {
        let name = str_of(&case["name"]);
        let challenge = Challenge::from_bytes(bytes(case, "challenge").try_into().unwrap());
        let input = bytes(case, "input");
        let (result, skipped) = read_replies(&input, &challenge);
        assert_eq!(skipped, u64_of(&case["skipped"]), "{name}");
        match result {
            Ok(w) => {
                assert_eq!(case["verdict"], "ok", "{name}");
                assert_eq!(
                    w.session_id,
                    case.get("session_id").map_or("", str_of),
                    "{name}"
                );
                assert_eq!(w.peer_id, case.get("peer_id").map_or("", str_of), "{name}");
                let mut buf = Vec::new();
                let (again, n) =
                    handshake::read_welcome(&mut Cursor::new(&input[..]), &challenge, &mut buf)
                        .unwrap();
                assert_eq!((again, n as u64), (w, skipped), "{name}");
            }
            Err(e) => {
                assert_eq!(e.verdict(), str_of(&case["verdict"]), "{name}: {e}");
                let want = str_of(&case["error_text"]);
                if e.verdict() == "parse" {
                    // The JSON library's own words differ; the step that
                    // failed does not.
                    let step = |s: &str| s.split(": ").next().unwrap().to_owned();
                    assert_eq!(step(&e.to_string()), step(want), "{name}");
                } else {
                    assert_eq!(e.to_string(), want, "{name}");
                }
            }
        }
    }
}

#[test]
fn w09_the_go_servers_replies_read_as_the_go_client_reads_them() {
    for case in load("handshake/server.json").as_array().unwrap() {
        let name = str_of(&case["name"]);
        // A hello over the limit gets no reply at all.
        let reply = case
            .get("reply")
            .map_or_else(Vec::new, |_| bytes(case, "reply"));
        let Some(wire) = case["challenge"].as_str() else {
            // No challenge in the hello: the server's reject echoes none, and
            // a client skips it as another client's.
            if !reply.is_empty() {
                let (body, _) = framing::try_decode(&reply, handshake::MAX_MESSAGE_SIZE)
                    .unwrap()
                    .unwrap();
                let any = Challenge::from_bytes([0; 16]);
                assert_eq!(
                    handshake::parse_reply(body, &any).unwrap(),
                    Reply::NotOurs,
                    "{name}"
                );
            }
            continue;
        };
        let Ok(raw) = <[u8; 16]>::try_from(unhex_lenient(wire).as_slice()) else {
            continue;
        };
        let ours = Challenge::from_bytes(raw);
        let (body, used) = framing::try_decode(&reply, handshake::MAX_MESSAGE_SIZE)
            .unwrap()
            .unwrap();
        assert_eq!(used, reply.len(), "{name}");
        let got = handshake::parse_reply(body, &ours);
        let echoes = str_of(&case["reply_text"]).contains("\"challenge\"");
        let lowercase = wire.bytes().all(|b| !b.is_ascii_uppercase());
        match (str_of(&case["verdict"]), got) {
            // A reply that echoes no challenge (the server refused the
            // hello's type) is another client's to Go's client as well.
            // A Rust client sends lowercase hex and so never sees an echo
            // in upper case; Go's client compares strings and skips it too.
            (_, Ok(Reply::NotOurs)) if !echoes || !lowercase => {}
            ("ok", Ok(Reply::Welcome(w))) => {
                assert_eq!(w.session_id, str_of(&case["session_id"]), "{name}");
                assert_eq!(w.peer_id, str_of(&case["peer_id"]), "{name}");
            }
            ("auth", Err(HandshakeError::Rejected(reason))) => {
                assert!(reason.starts_with("access denied"), "{name}: {reason}");
            }
            ("protocol_version", Err(HandshakeError::Rejected(reason))) => {
                assert_eq!(
                    reason,
                    handshake::reject_reason::PROTOCOL_VERSION_MISMATCH,
                    "{name}"
                );
            }
            (verdict, got) => panic!("{name}: the server said {verdict}, the client read {got:?}"),
        }
    }
}

fn unhex_lenient(text: &str) -> Vec<u8> {
    if text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        unhex(&text.to_ascii_lowercase())
    } else {
        Vec::new()
    }
}

// W11, W12 -----------------------------------------------------------------

#[test]
fn w11_w12_control() {
    let c = load("control.json");
    let k = &c["constants"];
    assert_eq!(i64_of(&k["proto_version"]), control::PROTO_VERSION);
    assert_eq!(usize_of(&k["max_message_size"]), control::MAX_MESSAGE_SIZE);
    assert_eq!(ms(&k["default_interval_ms"]), control::DEFAULT_INTERVAL);
    assert_eq!(ms(&k["default_timeout_ms"]), control::DEFAULT_TIMEOUT);
    assert_eq!(
        u64_of(&k["default_failures"]),
        u64::from(control::DEFAULT_FAILURES)
    );
    assert_eq!(
        u64_of(&k["max_stalled_probes"]),
        u64::from(control::MAX_STALLED_PROBES)
    );
    assert_eq!(k["type_ping"], control::MsgType::Ping.as_str());
    assert_eq!(k["type_pong"], control::MsgType::Pong.as_str());
    assert_eq!(k["type_close"], control::MsgType::Close.as_str());
    let kind = |name: &str| match name {
        "CONTROL_PING" => control::MsgType::Ping,
        "CONTROL_PONG" => control::MsgType::Pong,
        "CONTROL_CLOSE" => control::MsgType::Close,
        other => panic!("unknown type {other}"),
    };
    for case in c["encode"].as_array().unwrap() {
        let msg = control::Message {
            kind: kind(str_of(&case["type"])),
            seq: u64_of(&case["seq"]),
            sent_unix_nano: i64_of(&case["sent_unix_nano"]),
        };
        let mut out = Vec::new();
        control::encode(&msg, &mut out).unwrap();
        assert_eq!(hex(&out), str_of(&case["frame"]), "{}", case["name"]);
        assert_eq!(&out[4..], str_of(&case["body"]).as_bytes());
    }
    for case in c["parse"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let mut buf = Vec::new();
        match control::read(&mut Cursor::new(bytes(case, "input")), &mut buf) {
            Ok(msg) => {
                assert_eq!(case["verdict"], "ok", "{name}");
                assert_eq!(control::PROTO_VERSION, i64_of(&case["version"]), "{name}");
                assert_eq!(msg.kind, kind(str_of(&case["type"])), "{name}");
                assert_eq!(msg.seq, u64_of(&case["seq"]), "{name}");
                assert_eq!(
                    msg.sent_unix_nano,
                    i64_of(&case["sent_unix_nano"]),
                    "{name}"
                );
            }
            Err(e) => assert_eq!(e.verdict(), str_of(&case["verdict"]), "{name}: {e}"),
        }
    }
    assert_eq!(control::CLOSE_WRITE_DEADLINE, Duration::from_secs(2));
    assert_eq!(control::CLOSE_LINGER, Duration::from_millis(200));
}

// W18 ----------------------------------------------------------------------

#[test]
fn w18_smux_settings_and_frame_sizes() {
    let c = load("runtime.json");
    let k = &c["constants"];
    assert_eq!(
        usize_of(&k["smux_frame_overhead"]),
        sizes::SMUX_FRAME_OVERHEAD
    );
    assert_eq!(
        usize_of(&k["smux_wire_overhead"]),
        sizes::SMUX_WIRE_OVERHEAD
    );
    assert_eq!(
        usize_of(&k["min_smux_wire_payload"]),
        sizes::MIN_SMUX_WIRE_PAYLOAD
    );
    assert_eq!(ms(&k["connect_ack_timeout_ms"]), connect::ACK_TIMEOUT);
    assert_eq!(
        ms(&k["connect_request_timeout_ms"]),
        connect::REQUEST_TIMEOUT
    );
    assert_eq!(ms(&k["liveness_timeout_ms"]), control::DEFAULT_TIMEOUT);
    for case in c["smux"].as_array().unwrap() {
        let max = i64_of(&case["max_wire_payload"]);
        let profile = match str_of(&case["profile"]) {
            "server" => BufferProfile::Server,
            "constrained" => BufferProfile::Constrained,
            other => panic!("unknown profile {other}"),
        };
        for (field, session) in [
            ("data", SmuxSession::Data),
            ("long", SmuxSession::DataLong),
            ("control", SmuxSession::Control),
        ] {
            let want = &case[field];
            let got = sizes::smux_settings(session, max, profile);
            let what = format!("{max} {profile:?} {field}");
            assert_eq!(u64::from(got.version), u64_of(&want["version"]), "{what}");
            assert_eq!(
                got.keepalive_disabled,
                want["keepalive_disabled"].as_bool().unwrap(),
                "{what}"
            );
            assert_eq!(
                got.keepalive_interval,
                ms(&want["keepalive_interval_ms"]),
                "{what}"
            );
            assert_eq!(
                got.keepalive_timeout,
                ms(&want["keepalive_timeout_ms"]),
                "{what}"
            );
            assert_eq!(
                got.max_frame_size,
                usize_of(&want["max_frame_size"]),
                "{what}"
            );
            assert_eq!(
                got.max_receive_buffer,
                usize_of(&want["max_receive_buffer"]),
                "{what}"
            );
            assert_eq!(
                got.max_stream_buffer,
                usize_of(&want["max_stream_buffer"]),
                "{what}"
            );
        }
    }
    let dc = load("transport/datachannel.json");
    assert_eq!(
        usize_of(&dc["max_payload_size"]),
        sizes::datachannel::MAX_PAYLOAD_SIZE
    );
    assert_eq!(
        Duration::from_micros(u64_of(&dc["write_interval_us"])),
        sizes::datachannel::WRITE_INTERVAL
    );
    let vp8 = load("transport/vp8channel.json");
    assert_eq!(
        usize_of(&vp8["max_payload_size"]),
        sizes::vp8channel::MAX_PAYLOAD_SIZE
    );
}

// W20 ----------------------------------------------------------------------

#[test]
fn w20_connect() {
    let c = load("connect.json");
    assert_eq!(u64_of(&c["ack_ok"]), u64::from(connect::ACK_OK));
    assert_eq!(
        u64_of(&c["ack_host_unreachable"]),
        u64::from(connect::ACK_HOST_UNREACHABLE)
    );
    for case in c["cases"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let port = u16::try_from(u64_of(&case["port"])).unwrap();
        let mut out = Vec::new();
        connect::encode_request(&bytes(case, "host_hex"), port, &mut out);
        assert_eq!(hex(&out), str_of(&case["request"]), "{name}");
        let ack = u8::try_from(u64_of(&case["ack"])).unwrap();
        match connect::check_ack(ack, 3) {
            Ok(()) => assert_eq!(case["verdict"], "ok", "{name}"),
            Err(e) => {
                assert_eq!(case["verdict"], "ack_error", "{name}");
                assert_eq!(e.to_string(), str_of(&case["error_text"]), "{name}");
            }
        }
    }
    let t = load("tunnelcore.json");
    assert_eq!(u64_of(&t["connect_ack_ok"]), u64::from(connect::ACK_OK));
    assert_eq!(
        u64_of(&t["connect_ack_host_unreachable"]),
        u64::from(connect::ACK_HOST_UNREACHABLE)
    );
    assert_eq!(
        t["udp_record_aad"].as_str().unwrap().as_bytes(),
        Lane::Udp.aad()
    );
}

// W22 ----------------------------------------------------------------------

#[test]
fn w22_udpwire() {
    let c = load("udpwire.json");
    let k = &c["constants"];
    assert_eq!(u64_of(&k["version"]), u64::from(udpwire::VERSION));
    assert_eq!(usize_of(&k["max_payload_size"]), udpwire::MAX_PAYLOAD_SIZE);
    assert_eq!(usize_of(&k["max_host_len"]), udpwire::MAX_HOST_LEN);
    assert_eq!(usize_of(&k["header_len"]), udpwire::HEADER_LEN);
    assert_eq!(k["magic"].as_str().unwrap().as_bytes(), udpwire::MAGIC);
    for case in c["encode"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let type_byte = u8::try_from(u64_of(&case["type"])).unwrap();
        let Some(kind) = udpwire::FrameType::from_byte(type_byte) else {
            assert_eq!(case["verdict"], "unknown_type", "{name}");
            continue;
        };
        let port = u16::try_from(u64_of(&case["port"])).unwrap();
        let mut out = vec![0xee];
        let result = udpwire::encode(
            kind,
            u64_of(&case["flow_id"]),
            str_of(&case["host"]).as_bytes(),
            port,
            &bytes(case, "payload"),
            &mut out,
        );
        match result {
            Ok(()) => {
                assert_eq!(case["verdict"], "ok", "{name}");
                assert_eq!(hex(&out[1..]), str_of(&case["wire"]), "{name}");
            }
            Err(e) => {
                assert_eq!(e.verdict(), str_of(&case["verdict"]), "{name}");
                assert_eq!(out, [0xee], "{name}");
            }
        }
    }
    for case in c["decode"].as_array().unwrap() {
        let name = str_of(&case["name"]);
        let wire = bytes(case, "wire");
        match udpwire::decode(&wire) {
            Ok(frame) => {
                assert_eq!(case["verdict"], "ok", "{name}");
                assert_eq!(u64::from(frame.kind as u8), u64_of(&case["type"]), "{name}");
                assert_eq!(frame.flow_id, u64_of(&case["flow_id"]), "{name}");
                assert_eq!(frame.host.to_string(), str_of(&case["host"]), "{name}");
                assert_eq!(u64::from(frame.port), u64_of(&case["port"]), "{name}");
                assert_eq!(hex(frame.payload), str_of(&case["payload"]), "{name}");
                let mut again = Vec::new();
                frame.encode(&mut again).unwrap();
                let back = udpwire::decode(&again).unwrap();
                assert_eq!(back.host.to_string(), frame.host.to_string(), "{name}");
            }
            Err(e) => assert_eq!(e.verdict(), str_of(&case["verdict"]), "{name}: {e}"),
        }
    }
}

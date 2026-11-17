// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The golden vectors of Go at the pin
//! (`olc/interop/vectors/2d4266af/vkcalls/`, made by the overlay's
//! `zz_vectors_test.go` and `zz_vectors_wire_test.go` in
//! `internal/engine/vkcalls`): what the control channel, the answer shaper,
//! the offer view and the signalling build and read is what Go's do.
//!
//! Read here: `msgpack.json`, `shape.json`, `view.json`, `frames.json`, the
//! `signaling_url` half of `url.json`, and the provider's `url_auth.json`
//! and `requests_auth.json` (made by `internal/auth/vkcalls`' generator).
//! Not read yet: `stamp.json` and `url.json`'s `ice_servers_of` (the
//! session's, M7.8).
//!
//! Of an auth request `requests_auth.json` records, the method, the target,
//! the form and the headers the code names are compared. `Host`,
//! `Content-Length` and `Connection` are `olc_net`'s own, and Go's
//! `Accept-Encoding: gzip` is not sent (`olc_net` reads no coded body).
//!
//! Of the handshake `frames.json` records, only the target and the three
//! headers the code names are compared: the rest of the request is
//! `olc_net::ws`'s own (its header order is not Go's).

use olc_interop::{hex, load, sha256_hex, unhex};
use serde_json::Value;

use crate::answer::{self, ShapeState};
use crate::auth::tests::{form_value, FakeVk, TEST_ROOM};
use crate::auth::{self, Client};
use crate::control::{self, LayoutEntry, Registry};
use crate::negotiate::{self, MediaKind, ViewError, ViewMemo};
use crate::signaling::{self, DialOptions, Json, SignalingError};

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn i64_of(v: &Value) -> i64 {
    v.as_i64().unwrap_or_else(|| panic!("not an integer: {v}"))
}

fn usize_of(v: &Value) -> usize {
    usize::try_from(v.as_u64().unwrap_or_else(|| panic!("not a count: {v}"))).expect("fits")
}

fn u32_of(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap_or_else(|| panic!("not a count: {v}"))).expect("fits")
}

/// A list; a field Go left out (`omitempty`) or wrote as `null` is empty.
fn list(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// The cases of `file[name]`, at least `least` of them.
fn cases<'a>(file: &'a Value, name: &str, least: usize) -> &'a [Value] {
    let cases = list(&file[name]);
    assert!(cases.len() >= least, "{name}: {} cases", cases.len());
    cases
}

/// A case's text, by the rule the files state: the table's text named by
/// `base`, or the text `sdp`; then with `lf` every CRLF made a bare LF; then
/// each edit replacing the first `old` by `new`; then with `tail` one more
/// line, `a=` and `tail` times the letter x and CRLF.
pub(crate) fn text_of(spec: &Value, table: &Value, name: &Value) -> String {
    let mut text = match spec.get("sdp").filter(|sdp| !sdp.is_null()) {
        Some(sdp) => str_of(sdp).to_owned(),
        None => str_of(&table[str_of(&spec["base"])]).to_owned(),
    };
    if spec["lf"] == true {
        text = text.replace("\r\n", "\n");
    }
    for edit in list(&spec["edits"]) {
        let old = str_of(&edit["old"]);
        assert!(text.contains(old), "{name}: the text does not hold {old:?}");
        text = text.replacen(old, str_of(&edit["new"]), 1);
    }
    if let Some(tail) = spec.get("tail").filter(|tail| !tail.is_null()) {
        text.push_str("a=");
        text.extend(std::iter::repeat_n('x', usize_of(tail)));
        text.push_str("\r\n");
    }
    text
}

fn entry_of(v: &Value) -> LayoutEntry {
    LayoutEntry {
        key: unhex(str_of(&v["key_hex"])),
        compact: u8::try_from(usize_of(&v["compact"])).expect("a byte"),
        by_compact: v["by_compact"] == true,
        priority: i64_of(&v["priority"]),
        width: i64_of(&v["width"]),
        height: i64_of(&v["height"]),
    }
}

/// A registry as the files list one: `(key, id)` in the keys' byte order.
fn registry_list(registry: &Registry) -> Vec<(String, u8)> {
    registry.iter().map(|(key, id)| (hex(key), id)).collect()
}

fn registry_want(v: &Value) -> Vec<(String, u8)> {
    list(v)
        .iter()
        .map(|e| {
            (
                str_of(&e["key_hex"]).to_owned(),
                u8::try_from(usize_of(&e["id"])).expect("a byte"),
            )
        })
        .collect()
}

#[test]
fn the_command_channels_integers_and_commands_are_gos() {
    let file = load("vkcalls/msgpack.json");
    assert_eq!(
        usize_of(&file["sequence_modulus"]),
        usize::try_from(control::COMMAND_SEQ_MOD).unwrap()
    );
    let layer = &file["layer"];
    assert_eq!(
        (
            i64_of(&layer["width"]),
            i64_of(&layer["height"]),
            i64_of(&layer["fps"]),
            i64_of(&layer["kbps"])
        ),
        (
            control::LAYER_WIDTH,
            control::LAYER_HEIGHT,
            control::LAYER_FPS,
            control::LAYER_KBPS
        )
    );

    for case in cases(&file, "append_mp_int", 25) {
        let mut out = Vec::new();
        control::append_mp_int(&mut out, i64_of(&case["value"]));
        assert_eq!(hex(&out), str_of(&case["hex"]), "{}", case["value"]);
    }
    for case in cases(&file, "change_simulcast", 5) {
        let frame = control::encode_change_simulcast(
            i64_of(&case["sequence"]),
            str_of(&case["rid"]),
            i64_of(&case["width"]),
            i64_of(&case["height"]),
            i64_of(&case["fps"]),
            i64_of(&case["bitrate"]),
        );
        assert_eq!(hex(&frame), str_of(&case["hex"]), "{}", case["name"]);
    }
    for case in cases(&file, "perf_stat_report", 8) {
        let frame = control::encode_perf_stat_report(
            i64_of(&case["sequence"]),
            u32_of(&case["frames_decoded"]),
            u32_of(&case["frames_received"]),
        );
        assert_eq!(hex(&frame), str_of(&case["hex"]), "{case}");
    }
}

#[test]
fn a_layout_is_encoded_as_go_encodes_it() {
    let file = load("vkcalls/msgpack.json");
    let (mut refused, mut long) = (0, 0);
    for case in cases(&file, "encode_layout", 17) {
        let name = &case["name"];
        let entries: Vec<LayoutEntry> = match case.get("repeat") {
            // Entry i by compact id i mod 256, priority 1, 640x360.
            Some(n) => (0..usize_of(n))
                .map(|i| LayoutEntry {
                    key: Vec::new(),
                    compact: u8::try_from(i % 256).unwrap(),
                    by_compact: true,
                    priority: 1,
                    width: 640,
                    height: 360,
                })
                .collect(),
            None => list(&case["entries"]).iter().map(entry_of).collect(),
        };
        let got = control::encode_layout(i64_of(&case["sequence"]), &entries);
        if let Some(error) = case.get("error") {
            refused += 1;
            assert_eq!(
                got.map(|f| f.len()).map_err(|e| e.to_string()),
                Err(str_of(error).to_owned()),
                "{name}"
            );
            continue;
        }
        let frame = got.unwrap_or_else(|e| panic!("{name}: {e}"));
        if let Some(sum) = case.get("sha256") {
            long += 1;
            assert_eq!(frame.len(), usize_of(&case["len"]), "{name}");
            assert_eq!(sha256_hex(&frame), str_of(sum), "{name}");
        } else {
            assert_eq!(hex(&frame), str_of(&case["hex"]), "{name}");
        }
    }
    assert!(refused >= 5 && long >= 1, "{refused} refused, {long} long");

    for case in cases(&file, "layout_entries", 7) {
        let mut registry = Registry::default();
        for (key, id) in registry_want(&case["registry"]) {
            registry.insert(unhex(&key), id);
        }
        let participants = list(&case["participants"]).iter().map(str_of);
        let want: Vec<LayoutEntry> = list(&case["entries"]).iter().map(entry_of).collect();
        assert_eq!(
            control::layout_entries(&registry, participants),
            want,
            "{}",
            case["name"]
        );
    }
}

#[test]
fn a_registry_frame_is_read_as_go_reads_it() {
    let file = load("vkcalls/msgpack.json");
    let (mut refused, mut not_utf8) = (0, 0);
    for case in cases(&file, "parse_registry", 33) {
        let got = Registry::parse(&unhex(str_of(&case["frame_hex"])));
        let want = match case.get("error") {
            Some(error) => {
                refused += 1;
                Err(str_of(error).to_owned())
            }
            None => Ok(registry_want(&case["registry"])),
        };
        not_utf8 += list(&case["registry"])
            .iter()
            .filter(|e| e["key"].is_null())
            .count();
        assert_eq!(
            got.as_ref().map(registry_list).map_err(ToString::to_string),
            want,
            "{}",
            case["name"]
        );
    }
    assert!(
        refused >= 5 && not_utf8 >= 1,
        "{refused} refused, {not_utf8} keys that are not UTF-8"
    );
}

#[test]
fn the_shaped_answer_is_gos_byte_for_byte() {
    let file = load("vkcalls/shape.json");
    assert_eq!(usize_of(&file["bound"]), answer::MAX_SDP_SIZE);
    let session_id = file["session_id"].as_u64().expect("the session id");
    let slots = file["audio_ssrc"].as_object().expect("the audio SSRCs");
    assert_eq!(slots.len(), 1, "one audio publish slot in every case");
    let audio_ssrc = slots.values().next().and_then(Value::as_u64).unwrap();
    // The two draws a state makes, turned back into what the generator set.
    let state = move || {
        ShapeState::with_rng(move |n| {
            if n > 1_000_000_000 {
                session_id - 1_000_000_000_000_000_000
            } else {
                audio_ssrc - 1_000_000_000
            }
        })
    };
    assert_eq!(state().session_id(), session_id);

    let (mut answered, mut refused) = (0, 0);
    for case in cases(&file, "cases", 40) {
        let name = &case["name"];
        let offer = text_of(&case["offer"], &file["offers"], name);
        let native = text_of(&case["native"], &file["natives"], name);
        let mut state = state();
        let first = answer::shape_answer_sdp(&offer, &native, &mut state);
        let version = i64_of(&case["version_after"]);
        if let Some(error) = case.get("error") {
            refused += 1;
            assert_eq!(
                first.map(|a| a.len()).map_err(|e| e.to_string()),
                Err(str_of(error).to_owned()),
                "{name}"
            );
            assert_eq!(i64::try_from(state.version()).unwrap(), version, "{name}");
            continue;
        }
        answered += 1;
        let first = first.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(first, str_of(&case["answer"]), "{name}");
        let second = answer::shape_answer_sdp(&offer, &native, &mut state)
            .unwrap_or_else(|e| panic!("{name}, the second answer: {e}"));
        assert_eq!(
            second.split("\r\n").nth(1),
            Some(str_of(&case["second_o"])),
            "{name}"
        );
        assert_eq!(second.len(), usize_of(&case["second_len"]), "{name}");
        assert_eq!(
            sha256_hex(second.as_bytes()),
            str_of(&case["second_sha256"]),
            "{name}"
        );
        assert_eq!(i64::try_from(state.version()).unwrap(), version, "{name}");
    }
    assert!(
        answered >= 19 && refused >= 21,
        "{answered} answers, {refused} refusals"
    );
}

/// A case's publish list; `null` is none.
fn publish_of(case: &Value) -> Vec<&str> {
    list(&case["publish"]).iter().map(str_of).collect()
}

/// What a memo has settled, as the files list it: `(kind, payload type,
/// identity)`, audio first, by payload type.
fn claims_of(memo: &ViewMemo) -> Vec<(&'static str, u8, String)> {
    let mut out = Vec::new();
    for kind in [MediaKind::Audio, MediaKind::Video] {
        for pt in 0..=u8::MAX {
            if let Some(name) = memo.claim(kind, pt) {
                out.push((kind.as_str(), pt, name.to_owned()));
            }
        }
    }
    out
}

#[test]
fn the_offer_view_is_gos_byte_for_byte() {
    let file = load("vkcalls/view.json");
    assert_eq!(usize_of(&file["bound"]), answer::MAX_SDP_SIZE);
    let offers = &file["offers"];
    let (mut same, mut refused) = (0, 0);
    for case in cases(&file, "views", 32) {
        let name = &case["name"];
        let offer = text_of(&case["offer"], offers, name);
        let got = negotiate::offer_view(&offer, &publish_of(case), None);
        if let Some(error) = case.get("error") {
            refused += 1;
            assert_eq!(
                got.map(|v| v.len()).map_err(|e| e.to_string()),
                Err(str_of(error).to_owned()),
                "{name}"
            );
            continue;
        }
        let view = got.unwrap_or_else(|e| panic!("{name}: {e}"));
        if case["same"] == true {
            same += 1;
            assert!(view == offer, "{name}: the view is not the offer itself");
        } else {
            assert!(view != offer, "{name}: the view is the offer itself");
        }
        // A view left out is the offer.
        let want = match str_of(&case["view"]) {
            "" if case["same"] == true => offer.as_str(),
            view => view,
        };
        assert!(
            view == want,
            "{name}: the view differs\n--- got\n{view}\n--- want\n{want}"
        );
    }
    assert!(same >= 4 && refused >= 1, "{same} same, {refused} refused");

    for chain in cases(&file, "chains", 6) {
        let name = &chain["name"];
        let mut memo = ViewMemo::new();
        for (i, step) in list(&chain["steps"]).iter().enumerate() {
            let offer = text_of(&step["offer"], offers, name);
            let view = negotiate::offer_view(&offer, &publish_of(step), Some(&mut memo))
                .unwrap_or_else(|e| panic!("{name}, step {i}: {e}"));
            let want = str_of(&step["view"]);
            assert!(
                view == want,
                "{name}, step {i}: the view differs\n--- got\n{view}\n--- want\n{want}"
            );
            let claims: Vec<(&str, u8, String)> = list(&step["claims"])
                .iter()
                .map(|c| {
                    (
                        str_of(&c["kind"]),
                        u8::try_from(usize_of(&c["pt"])).expect("a byte"),
                        str_of(&c["name"]).to_owned(),
                    )
                })
                .collect();
            assert_eq!(claims_of(&memo), claims, "{name}, step {i}: the memo");
        }
    }
}

#[test]
fn the_offers_facts_are_gos() {
    let file = load("vkcalls/view.json");
    for fact in cases(&file, "offer_facts", 5) {
        let name = &fact["offer"];
        let offer = str_of(&file["offers"][str_of(name)]);
        assert_eq!(
            negotiate::publish_mid(offer).unwrap_or(""),
            str_of(&fact["publish_mid"]),
            "{name}"
        );
        let ssrcs: Vec<&str> = list(&fact["remote_ssrcs"]).iter().map(str_of).collect();
        assert_eq!(negotiate::remote_ssrcs(offer), ssrcs, "{name}");
    }
    for case in cases(&file, "publish_mid", 8) {
        assert_eq!(
            negotiate::publish_mid(str_of(&case["sdp"])).unwrap_or(""),
            str_of(&case["mid"]),
            "{}",
            case["name"]
        );
    }
    for case in cases(&file, "remote_ssrcs", 10) {
        let ssrcs: Vec<&str> = list(&case["ssrcs"]).iter().map(str_of).collect();
        assert_eq!(
            negotiate::remote_ssrcs(str_of(&case["sdp"])),
            ssrcs,
            "{}",
            case["name"]
        );
    }
}

/// One codec as both sides are compared: kind, payload type, `kind/name`,
/// clock rate, channels, fmtp, rtcp-fb pairs.
type CodecRow = (String, u8, String, u32, u16, String, Vec<(String, String)>);

/// Go's table lists what each section registers, one section after the
/// other; ours lists a payload type once per kind. The first of each is
/// what both name; `clash` is a payload type whose later codec is another
/// (name without regard to case, rate, channels), which Go's stack refuses
/// at registration and ours as [`ViewError::Clash`].
fn table_want(sections: &Value) -> (Vec<CodecRow>, Option<(String, u8)>) {
    let mut rows: Vec<CodecRow> = Vec::new();
    let mut clash = None;
    for section in list(sections) {
        let kind = str_of(&section["kind"]);
        for codec in list(&section["codecs"]) {
            let row: CodecRow = (
                kind.to_owned(),
                u8::try_from(usize_of(&codec["pt"])).expect("a byte"),
                str_of(&codec["mime"]).to_owned(),
                u32_of(&codec["clock_rate"]),
                u16::try_from(usize_of(&codec["channels"])).expect("fits"),
                str_of(&codec["fmtp"]).to_owned(),
                list(&codec["rtcp_fb"])
                    .iter()
                    .map(|fb| (str_of(&fb[0]).to_owned(), str_of(&fb[1]).to_owned()))
                    .collect(),
            );
            match rows.iter().find(|r| r.0 == row.0 && r.1 == row.1) {
                None => rows.push(row),
                Some(first) => {
                    let same = first.2.eq_ignore_ascii_case(&row.2)
                        && first.3 == row.3
                        && first.4 == row.4;
                    if !same && clash.is_none() {
                        clash = Some((row.0, row.1));
                    }
                }
            }
        }
    }
    (rows, clash)
}

#[test]
fn the_codec_table_is_what_go_registers() {
    let file = load("vkcalls/view.json");
    let mut viewed = 0;
    for case in cases(&file, "codec_tables", 5) {
        let name = &case["name"];
        let mut text = text_of(&case["offer"], &file["offers"], name);
        if case["viewed"] == true {
            viewed += 1;
            text = negotiate::offer_view(&text, &publish_of(case), None)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let (want, clash) = table_want(&case["sections"]);
        let got = negotiate::codec_table(&text);
        if let Some((kind, pt)) = clash {
            assert!(case["viewed"] != true, "{name}: a view with a clash");
            match got {
                Err(ViewError::Clash {
                    kind: k,
                    payload_type,
                    ..
                }) => assert_eq!((k.as_str(), payload_type), (kind.as_str(), pt), "{name}"),
                other => panic!("{name}: wanted the clash at {kind} {pt}, got {other:?}"),
            }
            continue;
        }
        let got: Vec<CodecRow> = got
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .iter()
            .map(|c| {
                (
                    c.kind.as_str().to_owned(),
                    c.payload_type,
                    format!("{}/{}", c.kind, c.name),
                    c.clock_rate,
                    c.channels,
                    c.fmtp.to_owned(),
                    c.feedback
                        .iter()
                        .map(|fb| (fb.kind.to_owned(), fb.parameter.to_owned()))
                        .collect(),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
    }
    assert!(viewed >= 3, "{viewed} tables of a view");
}

#[test]
fn the_signalling_url_is_gos() {
    let file = load("vkcalls/url.json");
    let mut refused = 0;
    for case in cases(&file, "signaling_url", 26) {
        let name = &case["name"];
        let endpoint = str_of(&case["endpoint"]);
        let got = signaling::signaling_url(endpoint);
        match case.get("error") {
            Some(error) => {
                refused += 1;
                assert_eq!(got, Err(SignalingError::Endpoint), "{name}");
                // Go's text goes on with the error it wraps (a nil one for a
                // wrong scheme); ours is the part before it.
                assert!(
                    str_of(error).starts_with(&SignalingError::Endpoint.to_string()),
                    "{name}: {error}"
                );
            }
            None => assert_eq!(got.as_deref(), Ok(str_of(&case["url"])), "{name}"),
        }
        assert_eq!(
            signaling::self_participant(endpoint),
            str_of(&case["self"]),
            "{name}: the session's own participant"
        );
    }
    assert!(refused >= 7, "{refused} refused");
}

/// A payload as the frame builder takes one. `None` for a value it has no
/// form for (a number that is not an integer).
fn json_of(v: &Value) -> Option<Json<'_>> {
    Some(match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => Json::Int(n.as_i64()?),
        Value::String(s) => Json::Str(s),
        Value::Array(items) => Json::Array(items.iter().map(json_of).collect::<Option<_>>()?),
        Value::Object(members) => Json::Object(
            members
                .iter()
                .map(|(k, v)| Some((k.as_str(), json_of(v)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

/// A case's payload and frame. A member of the payload the builder has no
/// form for is left out of both: Go writes it `,"<key>":<value>`.
fn payload_and_frame(case: &Value) -> (Json<'_>, String) {
    let mut frame = str_of(&case["frame"]).to_owned();
    let Value::Object(members) = &case["payload"] else {
        let payload = json_of(&case["payload"]);
        return (payload.expect("a payload the builder takes"), frame);
    };
    let mut kept = Vec::new();
    for (key, value) in members {
        match json_of(value) {
            Some(value) => kept.push((key.as_str(), value)),
            None => {
                let written = format!(",\"{key}\":{value}");
                assert!(
                    frame.contains(&written),
                    "{}: {written} is not in the frame",
                    case["name"]
                );
                frame = frame.replacen(&written, "", 1);
            }
        }
    }
    (Json::Object(kept), frame)
}

#[test]
fn a_command_frame_is_gos_json() {
    let file = load("vkcalls/frames.json");
    assert_eq!(usize_of(&file["frame_bound"]), signaling::FRAME_MAX);
    let (mut refused, mut left_out) = (0, 0);
    for case in cases(&file, "ordered", 17) {
        let name = &case["name"];
        let (payload, frame) = payload_and_frame(case);
        left_out += usize::from(frame != str_of(&case["frame"]));
        let got = signaling::ordered_command_frame(
            str_of(&case["command"]),
            i64_of(&case["sequence"]),
            &payload,
        );
        match case.get("error") {
            Some(error) => {
                refused += 1;
                assert_eq!(
                    got.map_err(|e| e.to_string()),
                    Err(str_of(error).to_owned()),
                    "{name}"
                );
            }
            None => assert_eq!(got.as_deref(), Ok(frame.as_str()), "{name}"),
        }
    }
    assert!(refused >= 3, "{refused} refused");
    // One float in the whole file: every other member is compared.
    assert!(left_out <= 1, "{left_out} cases with a member left out");
}

#[test]
fn a_connections_commands_are_the_frames_go_wrote() {
    let file = load("vkcalls/frames.json");
    let commands = cases(&file, "commands", 6);
    let texts: Vec<&Value> = list(&file["frames"])
        .iter()
        .filter(|f| f["opcode"] == 1 && f.get("text").is_none_or(|t| t != "pong"))
        .collect();
    let mut on_the_wire = texts.iter();
    let (mut at_the_bound, mut past_it) = (0, 0);
    for case in commands {
        let (command, sequence) = (str_of(&case["command"]), i64_of(&case["sequence"]));
        let who = format!("{command} #{sequence}");
        let written;
        let description;
        let payload = match (command, case.get("description_len")) {
            // A long one: that many letters x, the session "session-1", no
            // SSRC.
            (_, Some(n)) => {
                description = "x".repeat(usize_of(n));
                Json::Object(vec![
                    ("description", Json::Str(&description)),
                    ("sessionId", Json::Str("session-1")),
                    ("ssrcs", Json::Array(Vec::new())),
                ])
            }
            ("allocate-consumer", None) => {
                signaling::allocate_consumer(&signaling::REFERENCE_CAPABILITIES)
            }
            ("update-media-modifiers", None) => signaling::update_media_modifiers(),
            ("change-media-settings", None) => signaling::change_media_settings(),
            // The answer's: what the frame itself holds, written again.
            (_, None) => {
                written = serde_json::from_str::<Value>(str_of(&case["frame"])).unwrap();
                let Some(Json::Object(mut members)) = json_of(&written) else {
                    panic!("{who}: not an object");
                };
                members.retain(|(key, _)| !matches!(*key, "command" | "sequence"));
                Json::Object(members)
            }
        };
        let got = signaling::ordered_command_frame(command, sequence, &payload);
        let len = usize_of(&case["len"]);
        if let Some(error) = case.get("error") {
            // Go builds the frame and refuses it at the write; the builder
            // here gives it up at the bound.
            past_it += 1;
            assert_eq!(len, signaling::FRAME_MAX + 1, "{who}");
            assert_eq!(got, Err(SignalingError::FrameTooLarge), "{who}");
            assert!(
                str_of(error).contains(&SignalingError::FrameTooLarge.to_string()),
                "{who}: {error}"
            );
            continue;
        }
        let frame = got.unwrap_or_else(|e| panic!("{who}: {e}"));
        at_the_bound += usize::from(frame.len() == signaling::FRAME_MAX);
        assert_eq!(frame.len(), len, "{who}");
        assert_eq!(
            sha256_hex(frame.as_bytes()),
            str_of(&case["sha256"]),
            "{who}"
        );
        if let Some(text) = case.get("frame") {
            assert_eq!(frame, str_of(text), "{who}");
        }
        // And it is the next text frame the listener read, whole.
        let wire = on_the_wire
            .next()
            .unwrap_or_else(|| panic!("{who}: no frame"));
        assert!(wire["fin"] == true && wire["masked"] == true, "{who}");
        assert_eq!(usize_of(&wire["length"]), frame.len(), "{who}");
        match wire.get("text") {
            Some(text) => assert_eq!(frame, str_of(text), "{who}"),
            None => assert_eq!(
                sha256_hex(frame.as_bytes()),
                str_of(&wire["sha256"]),
                "{who}"
            ),
        }
    }
    assert_eq!((at_the_bound, past_it), (1, 1));

    // The refused command took a sequence number: the hangup has the next.
    let hangup = signaling::hangup_frame(i64::try_from(commands.len()).unwrap() + 1);
    assert_eq!(hangup, str_of(&file["hangup"]));
    let last = on_the_wire.next().expect("the hangup's frame");
    assert_eq!(str_of(&last["text"]), hangup);
    assert!(on_the_wire.next().is_none(), "a frame nothing accounts for");

    // The handshake: the target is the signalling URL's, and the headers
    // the code names carry Go's values.
    let handshake = &file["handshake"];
    let endpoint = str_of(&file["endpoint"]).replace("<sfu>", "127.0.0.1:9");
    assert_eq!(
        signaling::signaling_url(&endpoint).unwrap(),
        format!("ws://127.0.0.1:9{}", str_of(&handshake["target"]))
    );
    let headers: Vec<&str> = list(&handshake["headers"]).iter().map(str_of).collect();
    let options = DialOptions::default();
    for (name, value) in [
        ("Origin", options.origin),
        ("Referer", options.referer),
        ("User-Agent", options.user_agent),
    ] {
        assert!(
            headers.contains(&format!("{name}: {value}").as_str()),
            "{name}: {value} is not among {headers:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The provider (`internal/auth/vkcalls`).

/// The provider's error by the name of Go's sentinel error; empty for a
/// `GuestAPIError` and for an error that is only a text.
fn go_name(error: &auth::Error) -> &'static str {
    use auth::Error as E;
    match error {
        E::RoomUrlRequired => "ErrRoomURLRequired",
        E::TokenUnsupported => "ErrTokenUnsupported",
        E::InvalidEndpoint => "ErrInvalidEndpoint",
        E::EndpointUserInfo => "ErrEndpointUserInfo",
        E::EndpointToken => "ErrEndpointToken",
        E::MissingClientType => "ErrMissingClientType",
        E::InvalidDeviceIdx => "ErrInvalidDeviceIdx",
        E::InvalidRoomUrl => "ErrInvalidRoomURL",
        E::RoomUrlShape => "ErrRoomURLShape",
        E::RoomUrlExtra => "ErrRoomURLExtra",
        E::IceServers => "ErrICEServers",
        E::Api(_) | E::Http { .. } | E::Transport { .. } | E::FieldTooLong(_) => "",
    }
}

/// A field Go left out (`omitempty`) or wrote as `null` is none.
fn present<'a>(v: &'a Value, field: &str) -> Option<&'a Value> {
    v.get(field).filter(|value| !value.is_null())
}

/// Holds an error to the failure a vector records: the sentinel's name, a
/// `GuestAPIError`'s fields, and the text. Two texts are Go's only up to
/// where Go goes on with what must not be told: a status that is not 200
/// (Go adds 200 bytes of the body) and a link its parser refuses (Go quotes
/// the link).
fn same_failure(got: &auth::Error, want: &Value, name: &str) {
    assert_eq!(
        go_name(got),
        present(want, "is").map_or("", str_of),
        "{name}"
    );
    let text = match present(want, "text") {
        Some(text) => str_of(text).as_bytes().to_vec(),
        None => unhex(str_of(&want["text_hex"])),
    };
    let ours = got.to_string();
    match (got, present(want, "api")) {
        (auth::Error::Api(api), Some(go)) => {
            assert_eq!(
                (api.stage, api.code, api.kind.as_str()),
                (
                    str_of(&go["stage"]),
                    i64_of(&go["code"]),
                    str_of(&go["kind"])
                ),
                "{name}"
            );
            assert_eq!(ours.as_bytes(), text, "{name}");
        }
        (auth::Error::Api(_), None) | (_, Some(_)) => {
            panic!("{name}: {got:?} against {want}")
        }
        (auth::Error::Http { .. }, None) => {
            assert!(
                text.starts_with(format!("{ours}: ").as_bytes()),
                "{name}: {ours}"
            );
        }
        (auth::Error::InvalidRoomUrl, None) => {
            assert!(
                text.starts_with(format!("{ours}: parse ").as_bytes()),
                "{name}: {ours}"
            );
        }
        (_, None) => assert_eq!(ours.as_bytes(), text, "{name}"),
    }
}

/// Holds credentials to a vector's: the URL, the token and every field of
/// Go's `Extra`.
fn same_credentials(got: &auth::Credentials, want: &Value, name: &str) {
    assert_eq!(got.url, str_of(&want["url"]), "{name}");
    assert_eq!(got.token, str_of(&want["token"]), "{name}");
    let extra: Vec<(&str, &str)> = want["extra"]
        .as_object()
        .unwrap_or_else(|| panic!("{name}: no extra"))
        .iter()
        .map(|(key, value)| (key.as_str(), str_of(value)))
        .collect();
    // Both in the keys' byte order.
    assert_eq!(got.extra(), extra, "{name}");
}

#[test]
fn the_room_link_is_canonical_as_gos() {
    let file = load("vkcalls/url_auth.json");
    assert_eq!(str_of(&file["room"]), TEST_ROOM);
    let (mut taken, mut refused) = (0, 0);
    for case in cases(&file, "canonical_link", 41) {
        let name = str_of(&case["name"]);
        match (
            auth::canonical_link(str_of(&case["link"])),
            present(case, "error"),
        ) {
            (Ok(link), None) => {
                taken += 1;
                assert_eq!(
                    (link.as_str(), link.id()),
                    (str_of(&case["canonical"]), str_of(&case["join_link"])),
                    "{name}"
                );
            }
            (Err(error), Some(want)) => {
                refused += 1;
                same_failure(&error, want, name);
            }
            (got, want) => panic!("{name}: {got:?} against {want:?}"),
        }
    }
    assert!(
        taken >= 12 && refused >= 29,
        "{taken} taken, {refused} refused"
    );
}

#[tokio::test]
async fn the_credentials_of_a_join_are_gos() {
    let file = load("vkcalls/url_auth.json");
    let vk = FakeVk::start().await;
    let (mut issued, mut refused) = (0, 0);
    for case in cases(&file, "credentials_from_join", 61) {
        let name = str_of(&case["name"]);
        vk.reply(auth::STAGE_JOIN, 200, str_of(&case["join"]));
        let got = vk.issue(TEST_ROOM, "Test").await;
        assert_eq!(vk.taken().len(), 5, "{name}");
        match (got, present(case, "error")) {
            (Ok(creds), None) => {
                issued += 1;
                same_credentials(&creds, &case["credentials"], name);
            }
            (Err(error), Some(want)) => {
                refused += 1;
                same_failure(&error, want, name);
            }
            (got, want) => panic!("{name}: {got:?} against {want:?}"),
        }
    }
    assert!(
        issued >= 30 && refused >= 30,
        "{issued} issued, {refused} refused"
    );
}

#[tokio::test]
async fn the_chain_refuses_step_by_step_as_gos() {
    let file = load("vkcalls/url_auth.json");
    let (mut issued, mut refused) = (0, 0);
    for case in cases(&file, "issue", 28) {
        let name = str_of(&case["name"]);
        let vk = FakeVk::start().await;
        for (method, reply) in case["replies"].as_object().into_iter().flatten() {
            let status = u16::try_from(usize_of(&reply["status"])).expect("a status");
            vk.reply(method, status, str_of(&reply["body"]));
        }
        let req = auth::Request {
            token: str_of(&case["token"]),
            ..vk.request(str_of(&case["link"]), str_of(&case["nickname"]))
        };
        let got = auth::issue(&req).await;
        let steps: Vec<&str> = list(&case["steps"]).iter().map(str_of).collect();
        assert_eq!(vk.taken(), steps, "{name}");
        match (got, present(case, "error")) {
            (Ok(creds), None) => {
                issued += 1;
                same_credentials(&creds, &case["credentials"], name);
            }
            (Err(error), Some(want)) => {
                refused += 1;
                same_failure(&error, want, name);
            }
            (got, want) => panic!("{name}: {got:?} against {want:?}"),
        }
    }
    assert!(
        issued >= 5 && refused >= 23,
        "{issued} issued, {refused} refused"
    );
}

/// `text` with every `prefix` that `digits` lower-case hex digits follow
/// replaced by `label`, as the generator masks what is random.
fn masked(text: &str, prefix: &str, digits: usize, label: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(prefix) {
        let after = &rest[at + prefix.len()..];
        let random = after.len() >= digits
            && after.as_bytes()[..digits]
                .iter()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        out.push_str(&rest[..at]);
        if random {
            out.push_str(label);
            rest = &after[digits..];
        } else {
            out.push_str(prefix);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

#[tokio::test]
async fn the_service_sees_the_requests_go_sends() {
    let file = load("vkcalls/requests_auth.json");
    let flows = list(&file["flows"]);
    assert_eq!(flows.len(), 2);
    for flow in flows {
        let name = str_of(&flow["flow"]);
        let vk = FakeVk::start().await;
        let creds = vk
            .issue(str_of(&flow["link"]), str_of(&flow["nickname"]))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        same_credentials(&creds, &flow["credentials"], name);
        let steps: Vec<&str> = list(&flow["steps"]).iter().map(str_of).collect();
        assert_eq!(vk.taken(), steps, "{name}");

        let mut devices = Vec::new();
        for (server, stub) in [("api", &vk.api), ("fb", &vk.fb)] {
            let want: Vec<&Value> = list(&flow["requests"])
                .iter()
                .filter(|request| request["server"] == server)
                .collect();
            let seen = stub.seen();
            assert_eq!(seen.len(), want.len(), "{name}: requests at {server}");
            for (request, seen) in want.iter().zip(&seen) {
                let what = format!("{name} #{}", request["seq"]);
                assert_eq!(seen.method, str_of(&request["method"]), "{what}");
                assert_eq!(seen.target, str_of(&request["target"]), "{what}");
                let body = String::from_utf8(seen.body.clone()).expect("a form");
                let body = masked(&body, "olcrtc-sdk-", 32, "olcrtc-sdk-<hex32>");
                let body = masked(&body, "olcrtc-", 32, "olcrtc-<hex32>");
                let body = masked(&body, "guest-", 8, "guest-<hex8>");
                assert_eq!(body, str_of(&request["body"]), "{what}");
                if let Some(device) = form_value(&seen.body, "device_id") {
                    devices.push(device.to_owned());
                }
                // The headers the code names, in Go's order; the rest of
                // Go's request is its client's own.
                let ours: Vec<String> = seen
                    .headers
                    .iter()
                    .filter(|(n, _)| {
                        !["Host", "Content-Length", "Connection"].contains(&n.as_str())
                    })
                    .map(|(n, v)| format!("{n}: {v}"))
                    .collect();
                let gos: Vec<&str> = list(&request["headers"])
                    .iter()
                    .map(str_of)
                    .filter(|line| {
                        !["Host: ", "Content-Length: ", "Accept-Encoding: "]
                            .iter()
                            .any(|own| line.starts_with(own))
                    })
                    .collect();
                assert_eq!(ours, gos, "{what}");
                assert_eq!(seen.header("Host"), Some(stub.host.as_str()), "{what}");
                assert_eq!(
                    seen.header("Content-Length"),
                    Some(seen.body.len().to_string().as_str()),
                    "{what}"
                );
                assert_eq!(seen.header("Accept-Encoding"), None, "{what}");
            }
        }
        // One device id for the three API calls.
        assert_eq!(devices.len(), 3, "{name}");
        assert!(devices.iter().all(|device| *device == devices[0]), "{name}");
    }
    // What is masked is what the file says is random, and the default
    // sender is Go's.
    let masks: Vec<&str> = file["masked"]
        .as_object()
        .expect("the masks")
        .keys()
        .map(String::as_str)
        .collect();
    for mask in ["olcrtc-<hex32>", "olcrtc-sdk-<hex32>", "guest-<hex8>"] {
        assert!(masks.contains(&mask), "{mask}");
    }
    // The vector was taken behind a plain listener, where Go speaks
    // HTTP/1.1 and names itself so.
    assert_eq!(Client::default().user_agent, auth::Agent::Go);
    assert_eq!(auth::Agent::Go.on(false), "Go-http-client/1.1");
    assert_eq!(
        masked(
            "a olcrtc-0123 olcrtc-0123456789abcdef0123456789abcdefX",
            "olcrtc-",
            32,
            "<d>"
        ),
        "a olcrtc-0123 <d>X"
    );
}

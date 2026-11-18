// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The golden vectors of Go at the pin
//! (`olc/interop/vectors/2d4266af/jitsi/`, made by the overlay's
//! `zz_vectors_test.go` in `internal/auth/jitsi` and `internal/engine/jitsi`):
//! what this crate reads, tidies, frames and accepts is what Go's code does
//! with the same input.

use std::time::Instant;

use olc_interop::{load, unhex};
use serde_json::Value;

use crate::configjs::{
    library_domain, media_type, should_retry_with_fallback, whole_lines, StatusError,
    FALLBACK_CONFIG,
};
use crate::epoch::{Epochs, PeerIdError};
use crate::frame::{
    decode_raw, encode_frame, endpoint_message, FrameError, Message, WindowFrame, WindowKind, MAGIC,
};
use crate::nick::{normalise_host, sanitise_nick, xmpp_domain};
use crate::room::{parse_room_url, RoomError};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn list(v: &Value) -> &[Value] {
    v.as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("not a list: {v}"))
}

fn n(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a number: {v}"))
}

fn hex_of(b: &[u8]) -> String {
    olc_interop::hex(b)
}

#[test]
fn a_room_link_is_read_as_go_reads_it() {
    let cases = load("jitsi/room.json");
    assert!(list(&cases).len() >= 30, "{} cases", list(&cases).len());
    for c in list(&cases) {
        let raw = s(&c["raw"]);
        let got = parse_room_url(raw);
        let want = match s(&c["error"]) {
            "" => Ok((s(&c["host"]).to_owned(), s(&c["room"]).to_owned())),
            "required" => Err(RoomError::Required),
            "invalid" => Err(RoomError::Invalid),
            other => panic!("{other}"),
        };
        assert_eq!(got, want, "{raw:?}");
    }
}

#[test]
fn nicks_hosts_and_domains_are_tidied_as_go_tidies_them() {
    let c = load("jitsi/nick.json");
    let nicks = list(&c["sanitise_nick"]);
    assert!(nicks.len() >= 25, "{}", nicks.len());
    for r in nicks {
        assert_eq!(sanitise_nick(s(&r["raw"])), s(&r["want"]), "{:?}", r["raw"]);
    }
    for r in list(&c["normalise_host"]) {
        assert_eq!(
            normalise_host(s(&r["raw"])),
            s(&r["want"]),
            "{:?}",
            r["raw"]
        );
    }
    let domains = list(&c["xmpp_domain"]);
    assert!(domains.len() >= 10);
    for r in domains {
        assert_eq!(
            xmpp_domain(s(&r["jid"]), s(&r["fallback"])),
            s(&r["want"]),
            "{:?}",
            r["jid"]
        );
    }
}

#[test]
fn config_js_is_judged_as_go_judges_it() {
    let c = load("jitsi/configjs.json");
    let rows = list(&c["library_domain"]);
    assert!(rows.len() >= 25, "{}", rows.len());
    for r in rows {
        assert_eq!(
            library_domain(s(&r["body"]).as_bytes()),
            s(&r["want"]),
            "{}",
            s(&r["name"])
        );
    }
    for r in list(&c["whole_lines"]) {
        assert_eq!(
            whole_lines(s(&r["body"]).as_bytes()),
            s(&r["want"]).as_bytes(),
            "{:?}",
            r["body"]
        );
    }
    for r in list(&c["status"]) {
        let e = StatusError {
            code: u16::try_from(n(&r["code"])).unwrap(),
            media_type: s(&r["media_type"]).to_owned(),
        };
        assert_eq!(e.is_final(), r["final"] == true, "{}", e.code);
        assert_eq!(e.to_string(), s(&r["text"]));
    }
    for r in list(&c["media_type"]) {
        let header = (r["set"] == true).then(|| s(&r["header"]));
        assert_eq!(media_type(header), s(&r["want"]), "{:?}", r["header"]);
    }
    for r in list(&c["retry"]) {
        let err = (r["has_err"] == true).then(|| s(&r["err"]));
        assert_eq!(
            should_retry_with_fallback(err, r["failed"] == true),
            r["want"] == true,
            "{err:?}"
        );
    }
    assert_eq!(s(&c["fallback_config"]), FALLBACK_CONFIG);
}

#[test]
fn bridge_frames_and_json_are_go_s() {
    let c = load("jitsi/frames.json");
    let encodes = list(&c["encode"]);
    assert!(encodes.len() >= 7);
    for r in encodes {
        let data = match r["zeros"].as_u64() {
            Some(z) => vec![0u8; usize::try_from(z).unwrap()],
            None => unhex(s(&r["data_hex"])),
        };
        let got = encode_frame(&data, n(&r["local"]) as u32, n(&r["peer"]) as u32);
        if r["too_big"] == true {
            assert_eq!(got, Err(FrameError::SendTooLarge), "{} bytes", data.len());
            continue;
        }
        let got = got.unwrap();
        match r["frame_len"].as_u64() {
            Some(len) => {
                assert_eq!(got.len() as u64, len);
                assert_eq!(hex_of(&got[..12]), s(&r["frame_head_hex"]));
                assert!(got[12..].iter().all(|b| *b == 0));
            }
            None => assert_eq!(hex_of(&got), s(&r["frame_hex"])),
        }
    }

    let decodes = list(&c["decode_raw"]);
    assert!(decodes.len() >= 20);
    for r in decodes {
        let mut fields: Value = serde_json::from_str(s(&r["fields"])).unwrap();
        fields["colibriClass"] = r["class"].clone();
        let m = Message::parse(&fields.to_string()).unwrap();
        let got = decode_raw(&m);
        let want = (r["some"] == true).then(|| unhex(s(&r["want_hex"])));
        assert_eq!(got, want, "{}", s(&r["name"]));
    }

    for r in list(&c["endpoint_message"]) {
        let data = unhex(s(&r["data_hex"]));
        assert_eq!(
            endpoint_message(s(&r["to"]), &data),
            s(&r["json"]),
            "{:?}",
            r["to"]
        );
    }

    for r in list(&c["window"]) {
        let bytes = unhex(s(&r["hex"]));
        let got = WindowFrame::parse(&bytes);
        if r["parsed"] != true {
            assert_eq!(got, None, "{}", s(&r["hex"]));
            continue;
        }
        let f = got.unwrap_or_else(|| panic!("{} was not parsed", s(&r["hex"])));
        let kind = match n(&r["kind"]) {
            1 => WindowKind::Mark,
            2 => WindowKind::Echo,
            k => WindowKind::Other(u8::try_from(k).unwrap()),
        };
        assert_eq!(
            (
                f.kind,
                u64::from(f.sender_epoch),
                u64::from(f.receiver_epoch),
                f.counter
            ),
            (kind, n(&r["sender"]), n(&r["receiver"]), n(&r["counter"]))
        );
        assert_eq!(hex_of(&f.encode()), s(&r["hex"]), "it writes what it read");
    }
}

#[test]
fn the_epoch_rules_are_go_s() {
    let runs = load("jitsi/epoch.json");
    assert!(list(&runs).len() >= 6);
    for run in list(&runs) {
        let mut e = Epochs::new(n(&run["local"]) as u32, run["targeted"] == true);
        for (i, st) in list(&run["steps"]).iter().enumerate() {
            let name = format!("{} step {i}", s(&run["name"]));
            let mut delivered: Option<Vec<u8>> = None;
            let mut error = "";
            match s(&st["op"]) {
                "recv" => {
                    let raw = unhex(st["raw_hex"].as_str().unwrap_or(""));
                    let got = e.receive(st["from"].as_str().unwrap_or(""), &raw, Instant::now());
                    // Go hands data up when there is any: an announce has none.
                    delivered = got.body.filter(|b| !b.is_empty());
                    assert!(MAGIC.len() == 4);
                }
                "confirm" => {
                    error = match e.confirm_peer(st["peer_id"].as_str().unwrap_or("")) {
                        Ok(_) => "",
                        Err(PeerIdError::Parse) => "parse",
                        Err(PeerIdError::Invalid) => "invalid",
                    };
                }
                "reset" => e.reset_peer(),
                other => panic!("{other}"),
            }
            assert_eq!(
                delivered.is_some(),
                st["delivered"] == true,
                "{name}: delivered"
            );
            if let Some(d) = delivered {
                assert_eq!(hex_of(&d), s(&st["delivered_hex"]), "{name}");
            }
            assert_eq!(error, st["error"].as_str().unwrap_or(""), "{name}: error");
            assert_eq!(
                u64::from(e.peer_epoch()),
                n(&st["peer_epoch"]),
                "{name}: peer epoch"
            );
            assert_eq!(
                e.endpoint().unwrap_or(""),
                s(&st["endpoint"]),
                "{name}: endpoint"
            );
        }
    }
}

/// `o=- <id> <version> IN ...` lines carry a session id the generator
/// replaced; both sides say the same one here.
fn same_origin(sdp: &str) -> String {
    sdp.split("\r\n")
        .map(|l| {
            if l.starts_with("o=- ") {
                "o=- 1 2 IN IP4 0.0.0.0"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// J6's `V offer.json`: the session-initiate the Go fake sent, read and
/// written as SDP, is the SDP the Go engine's pion was given from it.
#[test]
fn the_offer_is_the_sdp_go_gives_its_stack() {
    use crate::jingle::parse::parse_stanza;
    use crate::jingle::sdp::{strip_remote_sources, to_sdp};
    let c = load("jitsi/offer.json");
    let j = parse_stanza(s(&c["initiate_xml"])).unwrap();
    let got = same_origin(&strip_remote_sources(&to_sdp(&j)));
    let want = same_origin(s(&c["offer_sdp"]));
    assert_eq!(
        got.split("\r\n").collect::<Vec<_>>(),
        want.split("\r\n").collect::<Vec<_>>()
    );
}

/// J6's `V accept.json`: the SDP the Go engine's pion answered with, written
/// as the session-accept's body, is the body Go's library wrote from it.
#[test]
fn the_accept_is_the_body_go_writes_from_the_answer() {
    use crate::jingle::build::accept_body;
    let c = load("jitsi/accept.json");
    let got = accept_body(s(&c["local_sdp"]));
    let want = s(&c["accept_inner"]);
    assert_eq!(
        got.replace("><", ">\n<").lines().collect::<Vec<_>>(),
        want.replace("><", ">\n<").lines().collect::<Vec<_>>()
    );
}

/// J10's `V relaywin.json`: the window driven by Go's scripts answers as
/// Go's does at every step: what a room check says, the marks that went out,
/// whether the window is on and full.
#[test]
fn the_relay_window_answers_go_s_scripts_as_go_does() {
    use crate::relaywin::{RelayWindow, Room, Timing};
    use std::time::{Duration, Instant};
    let scripts = load("jitsi/relaywin.json");
    assert_eq!(list(&scripts).len(), 4);
    for sc in list(&scripts) {
        let name = s(&sc["name"]);
        let base = Instant::now();
        let mut w = RelayWindow::new(Timing {
            probe: Duration::from_secs(3600),
            dead: Duration::from_secs(30),
            retry: Duration::from_millis(250),
        });
        for (i, step) in list(&sc["steps"]).iter().enumerate() {
            let op = &step["op"];
            let at = base + Duration::from_millis(n(&op["at_ms"]));
            let mut marks: Vec<u64> = Vec::new();
            let mut room = "";
            let mut probe = 0;
            match s(&op["op"]) {
                "sent" => marks.extend(w.sent(n(&op["n"]) as usize, at)),
                "echo" => {
                    w.echo(op["counter"].as_u64().unwrap_or(0));
                }
                "room" => match w.room(at) {
                    Room::Open => room = "open",
                    Room::Held => room = "held",
                    Room::Probe(c) => {
                        room = "probe";
                        probe = c;
                        marks.push(c);
                    }
                },
                "timing" => w.set_probe(Duration::from_millis(n(&op["n"]))),
                "reset" => w.reset(),
                other => panic!("{other}"),
            }
            let want_marks: Vec<u64> = list(&step["marks"]).iter().map(n).collect();
            let at_step = format!("{name} step {i} ({})", op["op"]);
            assert_eq!(marks, want_marks, "{at_step}: marks");
            assert_eq!(room, step["room"].as_str().unwrap_or(""), "{at_step}: room");
            assert_eq!(
                probe,
                step["probe"].as_u64().unwrap_or(0),
                "{at_step}: probe"
            );
            assert_eq!(
                w.is_active(),
                step["on"].as_bool().unwrap(),
                "{at_step}: on"
            );
            assert_eq!(
                w.is_held(),
                step["full"].as_bool().unwrap(),
                "{at_step}: full"
            );
        }
    }
}

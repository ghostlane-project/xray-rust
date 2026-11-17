// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The golden vectors of Go at the pin
//! (`olc/interop/vectors/2d4266af/mtslink/`, made by the overlay's
//! `zz_vectors_test.go` in `internal/auth/mtslink` and
//! `internal/engine/mtslink`): what the provider and the signalling parse,
//! build and put on the wire is what Go's do.
//!
//! `requests_*.json` hold Go's requests as `net/http` wrote them. Compared
//! are the method, the target, the body and the headers the Go code names,
//! in their wire order. Not compared: `Host` (the listener's), the
//! `Content-Length` line's place, `Accept-Encoding: gzip` (not sent here:
//! `olc_net` reads no coded body) and `Connection: close` (one request per
//! connection here, where Go keeps one alive).

use olc_interop::{load, unhex};
use serde_json::Value;

use crate::auth::tests::{Gateway, LOGIN_COOKIES, REPLY_GUEST_LOGIN, REPLY_NO_TOKEN, SESSION};
use crate::auth::{self, Web};
use crate::signal::tests::{CONFERENCE, COOKIES};
use crate::signal::{self, Sfu};
use crate::testing::{bounded, Reply, Seen, Stub};
use crate::Error;

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn list(v: &Value) -> &[Value] {
    v.as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("not a list: {v}"))
}

#[test]
fn an_event_link_is_read_as_go_reads_it() {
    let file = load("mtslink/parse_event_link.json");
    assert_eq!(str_of(&file["error"]), Error::RoomRef.to_string());
    let cases = list(&file["cases"]);
    assert!(cases.len() >= 41, "{} cases", cases.len());
    for case in cases {
        let got = auth::parse_event_link(str_of(&case["link"]));
        let want = if case["ok"] == true {
            let session = str_of(&case["session"]);
            Ok((
                str_of(&case["event"]).to_owned(),
                (!session.is_empty()).then(|| session.to_owned()),
            ))
        } else {
            Err(Error::RoomRef)
        };
        assert_eq!(got, want, "{}", case["name"]);
    }
}

#[test]
fn an_id_and_a_host_are_what_go_takes_for_one() {
    type Check = fn(&[u8]) -> bool;
    let checks: [(&str, Check, usize); 2] = [
        ("mtslink/is_id.json", |s| auth::is_id(s), 15),
        ("mtslink/is_host.json", |s| auth::is_host(s), 22),
    ];
    for (file, check, least) in checks {
        let cases = load(file);
        let cases = list(&cases);
        assert!(cases.len() >= least, "{file}: {} cases", cases.len());
        for case in cases {
            assert_eq!(
                check(&unhex(str_of(&case["input_hex"]))),
                case["ok"] == true,
                "{file}: {}",
                case["name"]
            );
        }
    }
}

#[test]
fn the_room_join_is_gos_but_for_the_device_id() {
    let file = load("mtslink/room_join_url.json");
    let cases = list(&file["cases"]);
    assert!(cases.len() >= 8, "{} cases", cases.len());
    for case in cases {
        let got = auth::room_join_url(
            str_of(&case["server"]),
            str_of(&case["session"]),
            str_of(&case["user_id"]),
            str_of(&case["nickname"]),
            str_of(&case["join_token"]),
            str_of(&case["publish_token"]),
            "0123456789abcdef",
        );
        let want = str_of(&case["url"])
            .replace("<did>", "0123456789abcdef")
            .replace("<pid>", "123456789abcdef0");
        assert_eq!(got, want, "{}", case["name"]);
    }
}

#[test]
fn the_offer_url_is_gos() {
    let cases = load("mtslink/offer_url.json");
    let cases = list(&cases);
    assert!(cases.len() >= 34, "{} cases", cases.len());
    for case in cases {
        let got = signal::offer_url(str_of(&case["join"]), str_of(&case["mid"]));
        match case.get("error") {
            Some(error) => assert_eq!(
                got.as_ref().map_err(Error::to_string),
                Err(str_of(error).to_owned()),
                "{}",
                case["name"]
            ),
            None => assert_eq!(got.as_deref(), Ok(str_of(&case["url"])), "{}", case["name"]),
        }
    }
}

#[test]
fn the_peer_of_an_answer_is_gos() {
    let cases = load("mtslink/peer_of.json");
    let cases = list(&cases);
    assert!(cases.len() >= 30, "{} cases", cases.len());
    for case in cases {
        assert_eq!(
            signal::peer_of(str_of(&case["answer"])).unwrap_or(""),
            str_of(&case["peer"]),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn a_refusals_text_is_gos() {
    let file = load("mtslink/refusal_text.json");
    assert_eq!(file["max_bytes"], signal::MAX_REFUSAL_TEXT);
    let cases = list(&file["cases"]);
    assert!(cases.len() >= 30, "{} cases", cases.len());
    for case in cases {
        let text = signal::refusal_text(&unhex(str_of(&case["body_hex"])));
        assert_eq!(text, unhex(str_of(&case["text_hex"])), "{}", case["name"]);
        // The whole error of a 400 with that body, as Go prints it with
        // what is no UTF-8 shown as U+FFFD.
        let error = Error::JoinRefused {
            status: 400,
            text: String::from_utf8_lossy(&text).into_owned(),
        };
        assert_eq!(
            error.to_string(),
            str_of(&case["error"]),
            "{}",
            case["name"]
        );
    }
}

fn login_path() -> String {
    format!("/api/eventsessions/{SESSION}/guestlogin")
}

#[tokio::test]
async fn the_forms_are_gos_on_the_wire() {
    let cases = load("mtslink/forms.json");
    let cases = list(&cases);
    assert!(cases.len() >= 10, "{} cases", cases.len());
    let gw = Gateway::start().await;
    for case in cases {
        gw.issue(auth::tests::LINK, str_of(&case["nickname"]))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let seen = gw.stub.seen();
        let posts: Vec<&Seen> = seen.iter().rev().filter(|s| s.method == "POST").collect();
        // The newest first: the conference, then the login.
        assert_eq!(
            String::from_utf8_lossy(&posts[0].body),
            str_of(&case["conferences_body"]),
            "{}",
            case["name"]
        );
        assert_eq!(
            String::from_utf8_lossy(&posts[1].body),
            str_of(&case["guestlogin_body"]),
            "{}",
            case["name"]
        );
    }
}

/// The cookies the login keeps, through a login whose reply sets the
/// case's `Set-Cookie` lines: the `Cookie` value of the next call, or the
/// login's error.
#[tokio::test]
async fn the_cookies_a_login_keeps_are_the_ones_go_keeps() {
    let cases = load("mtslink/cookies.json");
    let cases = list(&cases);
    assert!(cases.len() >= 22, "{} cases", cases.len());
    for case in cases {
        let gw = Gateway::start().await;
        let reply = list(&case["set_cookie"])
            .iter()
            .fold(Reply::new(200, REPLY_GUEST_LOGIN), |reply, line| {
                reply.header("Set-Cookie", str_of(line))
            });
        gw.answer(&login_path(), reply);
        // Whatever the cookies, the next call shows them.
        gw.status(
            &format!("/api/eventsession/{SESSION}/configuration"),
            500,
            "{}",
        );
        let err = gw.issue(auth::tests::LINK, "a").await.unwrap_err();
        let seen = gw.stub.seen();
        match case.get("error") {
            Some(error) => {
                assert_eq!(err.to_string(), str_of(error), "{}", case["name"]);
                assert_eq!(seen.len(), 2, "{}", case["name"]);
            }
            None => {
                assert_eq!(seen.len(), 3, "{}: {err}", case["name"]);
                assert_eq!(
                    seen[2].header("Cookie"),
                    Some(str_of(&case["cookie"])),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}

/// The header lines the Go code names, in wire order: Go's own `Host`,
/// `Content-Length` and `Accept-Encoding` left out.
fn named_in_go(request: &Value, host: &str) -> Vec<String> {
    let headers: Vec<&str> = list(&request["headers"]).iter().map(str_of).collect();
    assert_eq!(headers[0], format!("Host: {host}"));
    assert_eq!(headers.last(), Some(&"Accept-Encoding: gzip"));
    headers
        .iter()
        .filter(|h| {
            !["Host: ", "Content-Length: ", "Accept-Encoding: "]
                .iter()
                .any(|own| h.starts_with(own))
        })
        .map(|h| (*h).to_owned())
        .collect()
}

/// The header lines sent here, in wire order, without the transport's
/// own.
fn named_here(seen: &Seen, host: &str) -> Vec<String> {
    assert_eq!(seen.header("Host"), Some(host));
    assert_eq!(seen.header("Connection"), Some("close"));
    assert_eq!(seen.header("Accept-Encoding"), None);
    seen.headers
        .iter()
        .filter(|(n, _)| !["Host", "Content-Length", "Connection"].contains(&n.as_str()))
        .map(|(n, v)| format!("{n}: {v}"))
        .collect()
}

/// Holds what the stub saw to the flow's requests at `server`.
fn same_requests(
    flow: &Value,
    server: &str,
    mask: &str,
    stub: &Stub,
    body_of: &dyn Fn(&str) -> String,
) {
    let name = str_of(&flow["flow"]);
    let want: Vec<&Value> = list(&flow["requests"])
        .iter()
        .filter(|r| r["server"] == server)
        .collect();
    let seen = stub.seen();
    assert_eq!(seen.len(), want.len(), "{name}: requests at the {server}");
    for (request, seen) in want.iter().zip(&seen) {
        let what = format!("{name} #{}", request["seq"]);
        assert_eq!(seen.method, str_of(&request["method"]), "{what}");
        assert_eq!(seen.target, str_of(&request["target"]), "{what}");
        assert_eq!(
            String::from_utf8_lossy(&seen.body),
            body_of(str_of(&request["body"])),
            "{what}"
        );
        assert_eq!(
            named_here(seen, &stub.host),
            named_in_go(request, mask),
            "{what}"
        );
        let length = seen.header("Content-Length").map(str::to_owned);
        let has_length = list(&request["headers"])
            .iter()
            .any(|h| str_of(h).starts_with("Content-Length: "));
        assert_eq!(
            length,
            has_length.then(|| seen.body.len().to_string()),
            "{what}"
        );
    }
}

#[tokio::test]
async fn the_gateway_sees_the_requests_go_sends() {
    let file = load("mtslink/requests_gateway.json");
    let flows = list(&file["flows"]);
    assert_eq!(flows.len(), 3);
    for flow in flows {
        let name = str_of(&flow["flow"]);
        let gw = Gateway::start().await;
        if name == "issue_join_token_refused" {
            gw.status(
                &format!("/api/eventsessions/{SESSION}/join-token"),
                401,
                REPLY_NO_TOKEN,
            );
        }
        let got = gw
            .issue_with(
                str_of(&flow["link"]),
                str_of(&flow["nickname"]),
                str_of(&flow["default_ice"]),
            )
            .await;
        let calls = gw.calls();
        same_requests(flow, "gateway", "<gateway>", &gw.stub, &str::to_owned);
        match got {
            Err(e) => {
                assert_eq!(e.to_string(), str_of(&flow["error"]), "{name}");
                assert!(flow["credentials"].is_null(), "{name}");
                assert_eq!(calls.last().unwrap(), "DELETE /api/conferences/395296501");
            }
            Ok(creds) => {
                assert_eq!(str_of(&flow["error"]), "", "{name}");
                let want = &flow["credentials"];
                let did = creds
                    .url
                    .split_once("did=")
                    .and_then(|(_, rest)| rest.get(..16))
                    .unwrap_or_else(|| panic!("{name}: no device id"));
                let pid = format!("{}{}", &did[1..], &did[..1]);
                assert_eq!(
                    *creds.url,
                    str_of(&want["url"])
                        .replace("<did>", did)
                        .replace("<pid>", &pid),
                    "{name}"
                );
                assert_eq!(*creds.token, str_of(&want["token"]), "{name}");
                assert_eq!(*creds.token, LOGIN_COOKIES.join("; "), "{name}");
                let extra = &want["extra"];
                assert_eq!(
                    creds.gateway,
                    str_of(&extra["gateway"]).replace("<gateway>", &gw.stub.host),
                    "{name}"
                );
                assert_eq!(creds.session_id, str_of(&extra["sessionId"]), "{name}");
                assert_eq!(creds.user_id, str_of(&extra["userId"]), "{name}");
                assert_eq!(
                    creds.conference_id,
                    str_of(&extra["conferenceId"]),
                    "{name}"
                );
                assert_eq!(
                    creds.ice.map(crate::Ice::as_str),
                    extra.get("ice").map(str_of),
                    "{name}"
                );
                assert_eq!(
                    extra.as_object().map(|fields| fields.len()),
                    Some(4 + usize::from(creds.ice.is_some())),
                    "{name}"
                );
            }
        }
    }
    // The default sender is Go's.
    assert_eq!(Web::default().user_agent, auth::WEB_USER_AGENT);
}

/// The fake SFU's HTTP side: the join answers an SDP that names the peer,
/// or the refusal; the pin answers 200.
async fn sfu(refusal: Option<&'static str>) -> Stub {
    Stub::start(move |seen| match (refusal, seen.target.ends_with("/pin")) {
        (_, true) => Reply::new(200, "{}"),
        (Some(text), false) => Reply::new(400, text),
        (None, false) => Reply::new(200, signal::tests::answer()),
    })
    .await
}

#[tokio::test]
async fn the_sfu_sees_the_requests_go_sends() {
    let file = load("mtslink/requests_sfu.json");
    let flows = list(&file["flows"]);
    assert_eq!(flows.len(), 2);
    // The offer Go posted, its names left in: the body is ours to choose,
    // and it must arrive as it was given.
    let offer = std::fs::read_to_string(olc_interop::vectors_dir().join("mtslink/offer.sdp"))
        .expect("offer.sdp");
    let dress = Sfu::default();
    for flow in flows {
        let name = str_of(&flow["flow"]);
        let refused = name == "join_refused";
        let relay =
            sfu(refused.then_some("SDP validation error: exceeded maximal audio players value 1"))
                .await;
        let gateway = Stub::start(|_| Reply::new(204, "")).await;
        let url = signal::offer_url(&signal::tests::join_url(&relay.base), "2").unwrap();
        match bounded(signal::join_offer(&url, &offer, &dress)).await {
            Ok(answer) => {
                assert!(!refused, "{name}");
                let peer = signal::peer_of(&answer).expect("the answer names its peer");
                bounded(signal::pin_peer(&url, peer, &dress)).await.unwrap();
            }
            Err(e) => {
                assert_eq!(e.to_string(), str_of(&flow["error"]), "{name}");
                // What the session does after a join that failed.
                bounded(signal::take_back(
                    &gateway.base,
                    CONFERENCE,
                    COOKIES,
                    &dress,
                ))
                .await
                .unwrap();
            }
        }
        let body_of = |body: &str| body.replace("<offer.sdp>", &offer);
        same_requests(flow, "sfu", "<sfu>", &relay, &body_of);
        same_requests(flow, "gateway", "<gateway>", &gateway, &body_of);
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The golden vectors of Go at the pin (`olc/interop/vectors/2d4266af/net/`)
//! for the helpers a carrier's room provider needs: a form body is byte for
//! byte `url.Values.Encode`'s, and the cookies kept from a reply are the
//! ones `http.Response.Cookies` gives the Go provider.

use olc_interop::{load, sha256_hex, unhex};
use olc_net::{cookies, form};
use serde_json::Value;

fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn usize_of(v: &Value) -> usize {
    usize::try_from(v.as_u64().unwrap_or_else(|| panic!("not a number: {v}"))).expect("fits")
}

fn list(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

#[test]
fn a_form_is_encoded_as_gos_url_values() {
    let cases = load("net/forms.json");
    let cases = list(&cases);
    assert!(cases.len() >= 20, "{} cases", cases.len());
    for case in cases {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = list(&case["pairs"])
            .iter()
            .map(|p| (unhex(str_of(&p["key"])), unhex(str_of(&p["value"]))))
            .collect();
        assert_eq!(
            form::encode(&pairs),
            str_of(&case["encoded"]),
            "{}",
            case["name"]
        );
    }
}

/// A case's `Set-Cookie` values as the HTTP client hands headers over: a
/// name in any case, a value decoded as the h2 path decodes it.
fn headers_of(case: &Value) -> Vec<(String, String)> {
    let mut lines: Vec<String> = list(&case["set_cookie"])
        .iter()
        .map(|l| String::from_utf8_lossy(&unhex(str_of(l))).into_owned())
        .collect();
    if let Some(r) = case.get("repeat") {
        let prefix = str_of(&r["prefix"]);
        lines.extend((0..usize_of(&r["count"])).map(|i| format!("{prefix}{i}={i}")));
        lines.extend((0..usize_of(&r["blank"])).map(|_| String::new()));
    }
    let mut headers = vec![("Content-Type".to_string(), "a=b".to_string())];
    for (i, line) in lines.into_iter().enumerate() {
        let name = ["Set-Cookie", "set-cookie", "SET-COOKIE"][i % 3];
        headers.push((name.to_string(), line));
        headers.push(("Cookie".to_string(), "not=mine".to_string()));
    }
    headers
}

#[test]
fn the_cookies_kept_from_a_reply_are_the_ones_go_keeps() {
    let cases = load("net/cookies.json");
    let cases = list(&cases);
    assert!(cases.len() >= 40, "{} cases", cases.len());
    for case in cases {
        let name = &case["name"];
        let got = cookies::from_set_cookie(&headers_of(case));
        let header = cookies::header(&got);
        assert_eq!(got.len(), usize_of(&case["pair_count"]), "{name}");
        if let Some(sum) = case.get("pairs_sha256") {
            assert_eq!(sha256_hex(header.as_bytes()), str_of(sum), "{name}");
            continue;
        }
        let want: Vec<&str> = list(&case["pairs"]).iter().map(str_of).collect();
        assert_eq!(got, want, "{name}");
        assert_eq!(header, case.get("header").map_or("", str_of), "{name}");
    }
}

/// The MTS Link provider's vectors (`mtslink/cookies.json`: the `Set-Cookie`
/// lines of a login's reply and the `Cookie` value Go's provider sends on
/// its next call) hold for the helpers alone, with no provider around them.
#[test]
fn the_cookie_header_after_a_login_is_the_one_gos_provider_sends() {
    let cases = load("mtslink/cookies.json");
    let cases = list(&cases);
    assert!(cases.len() >= 22, "{} cases", cases.len());
    let mut none_kept = 0;
    for case in cases {
        let headers: Vec<(String, String)> = list(&case["set_cookie"])
            .iter()
            .map(|line| ("Set-Cookie".to_string(), str_of(line).to_string()))
            .collect();
        let header = cookies::header(&cookies::from_set_cookie(&headers));
        assert_eq!(header, str_of(&case["cookie"]), "{}", case["name"]);
        none_kept += usize::from(header.is_empty());
    }
    assert!(none_kept >= 1, "no case where nothing is kept");
}

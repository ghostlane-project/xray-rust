//! `network: "http"`, the HTTP/2 transport of v2fly and sing-box (`type=http`
//! in a share link). Xray-core deleted it; this core carries it as XHTTP in
//! `stream-one` mode, which is one HTTP/2 request whose body and answer are the
//! two directions. What the line looks like to a sing-box `http` server is
//! checked by xray-core-rs's `vless_http_sing_box_tests`.
use serde_json::Value;
use xray_config::profile_import::{import_profile, ProfileFormat};
use xray_config::{parse_xray_json, StreamSecurity, StreamTransport, XhttpMode};

const ID: &str = "6c027102-b0fb-4e85-a77c-9a0a8607101b";
const PBK: &str = "kZ4NDkIZkxCcdw0iPsMfsjun8jdTfh4ngEuPlJ4yUY8";

fn config(stream: &str) -> String {
    format!(
        r#"{{"inbounds": [], "outbounds": [{{"tag": "proxy", "protocol": "vless",
          "settings": {{"vnext": [{{"address": "server.example", "port": 443,
            "users": [{{"id": "{ID}"}}]}}]}},
          "streamSettings": {{ {stream} }}}}]}}"#
    )
}

#[test]
fn http_is_xhttp_in_stream_one_mode_with_its_host_and_path() {
    let parsed = parse_xray_json(&config(
        r#""network": "http", "security": "tls",
           "tlsSettings": {"serverName": "front.example"},
           "httpSettings": {"host": ["a.example", "b.example"], "path": "/h2"}"#,
    ))
    .expect("an http line parses");
    let stream = &parsed.config.outbounds[0].stream;
    let StreamTransport::Xhttp(xhttp) = &stream.transport else {
        panic!("http must become xhttp, got {:?}", stream.transport);
    };
    assert_eq!(xhttp.mode, XhttpMode::StreamOne);
    assert_eq!(xhttp.host.as_deref(), Some("a.example"));
    assert_eq!(xhttp.path, "/h2");
    let StreamSecurity::Tls(tls) = &stream.security else {
        panic!("expected tls");
    };
    assert_eq!(tls.alpn, ["h2"], "HTTP/2 is the point of the transport");
}

#[test]
fn http_takes_a_single_host_string_and_none() {
    for (settings, host) in [
        (
            r#"{"host": "one.example", "path": "/p"}"#,
            Some("one.example"),
        ),
        (r#"{"path": "/p"}"#, None),
        (r#"{"host": [], "path": "/p"}"#, None),
    ] {
        let parsed = parse_xray_json(&config(&format!(
            r#""network": "http", "security": "tls", "httpSettings": {settings}"#
        )))
        .unwrap();
        let StreamTransport::Xhttp(xhttp) = &parsed.config.outbounds[0].stream.transport else {
            panic!("expected xhttp");
        };
        assert_eq!(xhttp.host.as_deref(), host, "{settings}");
        assert_eq!(xhttp.mode, XhttpMode::StreamOne);
    }
}

#[test]
fn http_runs_under_reality_and_says_what_it_became() {
    let parsed = parse_xray_json(&config(&format!(
        r#""network": "http", "security": "reality",
           "realitySettings": {{"serverName": "site.example", "publicKey": "{PBK}", "shortId": "ab12cd34"}},
           "httpSettings": {{"path": "/h2"}}"#
    )))
    .expect("http under REALITY parses");
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Xhttp(_)
    ));
    assert!(
        parsed
            .diagnostics
            .iter()
            .any(|d| d.message.contains("xhttp") && d.message.contains("stream-one")),
        "a warning must say the line runs as xhttp stream-one: {:?}",
        parsed.diagnostics
    );
}

#[test]
fn h2_is_the_old_name_of_http() {
    let parsed = parse_xray_json(&config(
        r#""network": "h2", "security": "tls", "httpSettings": {"path": "/p"}"#,
    ))
    .unwrap();
    assert!(matches!(
        parsed.config.outbounds[0].stream.transport,
        StreamTransport::Xhttp(_)
    ));
}

#[test]
fn http_refuses_what_it_cannot_carry() {
    for stream in [
        // Another transport's block beside it.
        r#""network": "http", "security": "tls", "xhttpSettings": {"mode": "packet-up"}"#,
        // A key the transport has no meaning for.
        r#""network": "http", "security": "tls", "httpSettings": {"nonsense": 1}"#,
        r#""network": "http", "security": "tls", "httpSettings": {"path": 5}"#,
        r#""network": "http", "security": "tls", "httpSettings": {"host": [1]}"#,
    ] {
        assert!(
            parse_xray_json(&config(stream)).is_err(),
            "must be refused: {stream}"
        );
    }
}

#[test]
fn h3_and_quic_stay_removed() {
    for network in ["h3", "quic"] {
        let error = parse_xray_json(&config(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .expect_err("removed");
        assert!(error
            .diagnostics
            .iter()
            .any(|d| d.message.contains("removed")));
    }
}

fn import(link: &str) -> Value {
    let profile = import_profile(ProfileFormat::Vless, link, None, &[]).unwrap();
    assert!(parse_xray_json(&profile.config_json).is_ok());
    serde_json::from_str(&profile.config_json).unwrap()
}

#[test]
fn a_type_http_link_imports_with_its_host_and_path() {
    for scheme_type in ["http", "h2"] {
        let link = format!(
            "vless://{ID}@192.0.2.10:443?type={scheme_type}&security=tls&sni=front.example\
             &host=a.example%2Cb.example&path=%2Fh2"
        );
        let config = import(&link);
        let stream = &config["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "http");
        assert_eq!(stream["httpSettings"]["path"], "/h2");
        assert_eq!(stream["httpSettings"]["host"][0], "a.example");
        assert_eq!(stream["httpSettings"]["host"][1], "b.example");
    }
}

#[test]
fn a_type_http_reality_link_imports() {
    let link = format!(
        "vless://{ID}@192.0.2.10:443?type=http&security=reality&pbk={PBK}&fp=chrome\
         &sni=site.example&sid=ab12cd34&path=%2Fh2"
    );
    let config = import(&link);
    assert_eq!(config["outbounds"][0]["streamSettings"]["network"], "http");
}

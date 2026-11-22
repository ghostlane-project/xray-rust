//! `tlsSettings.allowInsecure: true` on an outbound's own TLS: the parser
//! takes it where the core honours it, warns naming the outbound and its
//! server, and refuses it where the core does not. A pin or a verification
//! name verifies instead, REALITY never reads it, and a config without it
//! parses exactly as before.
use serde_json::{json, Value};
use xray_config::{parse_xray_json, Diagnostic, DiagnosticSeverity, StreamSecurity, TlsSettings};

const FLAG: &str = "$.outbounds[0].streamSettings.tlsSettings.allowInsecure";
const UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn vless(address: &str, tls: Value) -> Value {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":address,"port":8443,
            "users":[{"id":UUID,"encryption":"none"}]}]},
        "streamSettings":{"network":"raw","security":"tls","tlsSettings":tls}}]})
}

fn hysteria(tls: Value) -> Value {
    let mut config: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/configs/hysteria2.json"
    ))
    .unwrap();
    config["outbounds"][0]["streamSettings"]["tlsSettings"] = tls;
    config
}

fn parsed_tls(config: &Value) -> (TlsSettings, Vec<Diagnostic>) {
    let parsed = parse_xray_json(&config.to_string())
        .unwrap_or_else(|error| panic!("{config} must parse: {:?}", error.diagnostics));
    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected TLS security");
    };
    (tls.clone(), parsed.diagnostics)
}

fn at<'a>(diagnostics: &'a [Diagnostic], path: &str) -> Vec<&'a Diagnostic> {
    diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.path.as_deref() == Some(path))
        .collect()
}

fn the_warning<'a>(diagnostics: &'a [Diagnostic], path: &str) -> &'a str {
    let found = at(diagnostics, path);
    assert_eq!(found.len(), 1, "one diagnostic at {path}: {diagnostics:?}");
    assert_eq!(found[0].severity, DiagnosticSeverity::Warning, "{found:?}");
    &found[0].message
}

fn refused_at(config: &Value, path: &str) -> String {
    let error = parse_xray_json(&config.to_string()).expect_err("must be refused");
    let found: Vec<_> = error
        .diagnostics
        .iter()
        .filter(|d| d.path.as_deref() == Some(path) && d.severity == DiagnosticSeverity::Error)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "one error at {path}: {:?}",
        error.diagnostics
    );
    found[0].message.clone()
}

#[test]
fn the_flag_waives_the_check_and_the_warning_names_the_outbound_and_its_server() {
    for (address, server) in [
        ("203.0.113.7", "203.0.113.7:8443"),
        ("2001:db8::7", "[2001:db8::7]:8443"),
        ("vless.example", "vless.example:8443"),
    ] {
        let (tls, diagnostics) = parsed_tls(&vless(
            address,
            json!({"serverName":"vless.example","allowInsecure":true}),
        ));
        assert!(tls.allow_insecure, "{address}");
        let message = the_warning(&diagnostics, FLAG);
        assert!(message.contains("`proxy`"), "{message}");
        assert!(message.contains(server), "{server}: {message}");
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    }

    // Hysteria 2 with no pin: its QUIC TLS takes the flag the same way.
    let (tls, diagnostics) = parsed_tls(&hysteria(
        json!({"serverName":"server.example","alpn":["h3"],"allowInsecure":true}),
    ));
    assert!(tls.allow_insecure);
    let message = the_warning(&diagnostics, FLAG);
    assert!(
        message.contains("`proxy`") && message.contains("server.example:443"),
        "{message}"
    );

    // An outbound with no tag is named by its place.
    let mut untagged = vless("203.0.113.7", json!({"allowInsecure":true}));
    untagged["outbounds"][0]
        .as_object_mut()
        .unwrap()
        .remove("tag");
    let (_, diagnostics) = parsed_tls(&untagged);
    let message = the_warning(&diagnostics, FLAG);
    assert!(message.contains("outbound 0 "), "{message}");
    assert!(message.contains("203.0.113.7:8443"), "{message}");
}

#[test]
fn without_the_flag_the_parse_is_what_it_was() {
    for tls in [
        json!({"serverName":"vless.example"}),
        json!({"serverName":"vless.example","allowInsecure":false}),
        json!({"serverName":"vless.example","allowInsecure":null}),
    ] {
        let (parsed, diagnostics) = parsed_tls(&vless("203.0.113.7", tls.clone()));
        assert!(!parsed.allow_insecure, "{tls}");
        assert!(diagnostics.is_empty(), "{tls}: {diagnostics:?}");
        let (parsed, diagnostics) = parsed_tls(&hysteria(tls.clone()));
        assert!(!parsed.allow_insecure, "{tls}");
        assert!(diagnostics.is_empty(), "{tls}: {diagnostics:?}");
    }
    // Anything but a boolean or null is still refused at its path.
    refused_at(&vless("203.0.113.7", json!({"allowInsecure":"yes"})), FLAG);
    refused_at(&vless("203.0.113.7", json!({"allowInsecure":1})), FLAG);
}

#[test]
fn a_pin_or_a_verification_name_verifies_instead_of_the_flag() {
    for config in [
        vless(
            "203.0.113.7",
            json!({"allowInsecure":true,"pinnedPeerCertSha256":PIN}),
        ),
        hysteria(
            json!({"serverName":"server.example","allowInsecure":true,"pinnedPeerCertSha256":PIN}),
        ),
    ] {
        let (tls, diagnostics) = parsed_tls(&config);
        assert!(!tls.allow_insecure, "the pin verifies: {config}");
        assert_eq!(tls.pinned_peer_cert_sha256, vec![[0xaa; 32]]);
        assert!(diagnostics.is_empty(), "nothing is waived: {diagnostics:?}");
    }
    let (tls, diagnostics) = parsed_tls(&vless(
        "203.0.113.7",
        json!({"allowInsecure":true,"verifyPeerCertByName":"cert.example"}),
    ));
    assert!(!tls.allow_insecure, "the name verifies");
    assert_eq!(tls.verify_peer_cert_by_name, ["cert.example"]);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn refused_where_the_core_would_not_honour_it() {
    let insecure = json!({"serverName":"server.example","allowInsecure":true});
    let tls_stream = json!({"network":"raw","security":"tls","tlsSettings":insecure});
    let mut trojan: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/configs/trojan.json")).unwrap();
    trojan["outbounds"][0]["streamSettings"] = tls_stream.clone();
    let mut vmess: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/configs/vmess.json")).unwrap();
    vmess["outbounds"][0]["streamSettings"] = tls_stream.clone();
    let socks = json!({"outbounds":[{"tag":"proxy","protocol":"socks",
        "settings":{"address":"socks.example","port":1080},"streamSettings":tls_stream}]});
    let http = json!({"outbounds":[{"tag":"proxy","protocol":"http",
        "settings":{"address":"proxy.example","port":3128},"streamSettings":tls_stream}]});
    for (name, config) in [
        ("trojan", trojan),
        ("vmess", vmess),
        ("socks", socks),
        ("http", http),
    ] {
        let message = refused_at(&config, FLAG);
        assert!(message.contains(name), "{name}: {message}");
    }

    // An XHTTP download leg always verifies, as the core requires.
    let download = json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"203.0.113.7","port":443,
            "users":[{"id":UUID,"encryption":"none"}]}]},
        "streamSettings":{"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"up.example"},
            "xhttpSettings":{"path":"/up","mode":"packet-up","downloadSettings":{
                "address":"203.0.113.8","port":443,"network":"xhttp","security":"tls",
                "tlsSettings":{"serverName":"down.example","allowInsecure":true},
                "xhttpSettings":{"path":"/down"}}}}}]});
    refused_at(
        &download,
        "$.outbounds[0].streamSettings.xhttpSettings.downloadSettings.tlsSettings.allowInsecure",
    );

    // A realm mask's rendezvous TLS is not a link's server.
    let realm = json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":UUID,"encryption":"none"}]}]},
        "streamSettings":{"network":"kcp","finalmask":{"udp":[{"type":"realm","settings":{
            "url":"realm://t@rendezvous.example/name","stunServers":["stun.example.net:3478"],
            "tlsConfig":{"serverName":"front.example","allowInsecure":true}}}]}}}]});
    refused_at(
        &realm,
        "$.outbounds[0].streamSettings.finalmask.udp[0].settings.tlsConfig.allowInsecure",
    );
}

#[test]
fn reality_does_not_read_the_flag() {
    let config = json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"203.0.113.7","port":443,
            "users":[{"id":UUID,"encryption":"none"}]}]},
        "streamSettings":{"network":"raw","security":"reality",
            "realitySettings":{"serverName":"reality.example","fingerprint":"chrome",
                "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405",
                "allowInsecure":true}}}]});
    let parsed = parse_xray_json(&config.to_string()).expect("REALITY parses");
    assert!(matches!(
        parsed.config.outbounds[0].stream.security,
        StreamSecurity::Reality(_)
    ));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}

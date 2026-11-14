//! The DNS outbound's `forward` rule: a query of the types and names the
//! rule matches is sent, unchanged, to a DNS server of the rule's own,
//! through an outbound the rule names. This core adds it; Xray-core has no
//! such action and refuses the config, so a profile that relies on it never
//! falls back to sending those queries out directly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json, DiagnosticSeverity, DnsForwardTarget, DnsOutboundRuleAction,
    DnsOutboundSettings, OutboundSettings,
};

/// The line `out`, a direct outbound, a blackhole and a loopback, and the
/// DNS outbound last, with `rules`.
fn config(rules: Value) -> String {
    json!({
        "inbounds": [],
        "outbounds": [
            {"tag": "out", "protocol": "vless", "settings": {"vnext": [{
                "address": "10.0.0.10", "port": 443,
                "users": [{"id": "11111111-1111-1111-1111-111111111111", "encryption": "none"}]
            }]}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "again", "protocol": "loopback", "settings": {"inboundTag": "in"}},
            {"tag": "dns-out", "protocol": "dns", "settings": {"rules": rules}}
        ]
    })
    .to_string()
}

fn dns_settings(raw: &str) -> DnsOutboundSettings {
    let parsed = parse_xray_json(raw).unwrap_or_else(|error| panic!("{raw}: {error:?}"));
    assert!(
        parsed.diagnostics.is_empty(),
        "no diagnostics: {:?}",
        parsed.diagnostics
    );
    let dns = parsed
        .config
        .outbounds
        .iter()
        .find_map(|outbound| match &outbound.settings {
            OutboundSettings::Dns(settings) => Some(settings.clone()),
            _ => None,
        });
    dns.expect("a dns outbound")
}

fn first_error(raw: &str) -> (String, String) {
    let error = parse_xray_json(raw).expect_err(&format!("{raw} should be refused"));
    error
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| {
            (
                diagnostic.path.clone().unwrap_or_default(),
                diagnostic.message.clone(),
            )
        })
        .expect("an error")
}

fn forward(address: IpAddr, port: u16, outbound_tag: &str) -> DnsOutboundRuleAction {
    DnsOutboundRuleAction::Forward(DnsForwardTarget {
        address,
        port,
        outbound_tag: outbound_tag.to_owned(),
    })
}

const CLOUDFLARE: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const RULE: &str = "$.outbounds[4].settings.rules[0]";

#[test]
fn a_forward_rule_names_its_server_and_the_outbound_it_goes_through() {
    let settings = dns_settings(&config(json!([{
        "action": "forward",
        "qType": "2-27,29-65535",
        "address": "1.1.1.1",
        "port": 53,
        "outboundTag": "out"
    }])));

    assert_eq!(settings.rules.len(), 1);
    assert_eq!(settings.rules[0].action, forward(CLOUDFLARE, 53, "out"));
    // The rule's types go through the line; A and AAAA keep the default,
    // the fake address.
    assert_eq!(
        settings.action_for(16, "example.com"),
        forward(CLOUDFLARE, 53, "out")
    );
    assert_eq!(
        settings.action_for(33, "_xmpp-client._tcp.example.com"),
        forward(CLOUDFLARE, 53, "out")
    );
    assert_eq!(
        settings.action_for(1, "example.com"),
        DnsOutboundRuleAction::Hijack
    );
    assert_eq!(
        settings.action_for(28, "example.com"),
        DnsOutboundRuleAction::Hijack
    );
}

#[test]
fn each_forward_rule_has_its_own_server_and_outbound() {
    let settings = dns_settings(&config(json!([
        {"action": "Forward", "domain": ["domain:ru"], "address": "10.0.0.1", "outboundTag": "direct"},
        {"action": "FORWARD", "address": "2606:4700:4700::1111", "port": 5353, "outboundTag": "out"}
    ])));

    assert_eq!(
        settings.action_for(16, "example.ru"),
        forward(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53, "direct")
    );
    assert_eq!(
        settings.action_for(16, "example.com"),
        forward(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            5353,
            "out"
        )
    );
}

#[test]
fn a_forward_rule_asks_port_53_unless_it_says_otherwise() {
    for (port, expected) in [
        (None, 53),
        (Some(json!(null)), 53),
        (Some(json!(5353)), 5353),
    ] {
        let mut rule = json!({"action": "forward", "address": "1.1.1.1", "outboundTag": "out"});
        if let Some(port) = port {
            rule["port"] = port;
        }
        let settings = dns_settings(&config(json!([rule])));
        assert_eq!(
            settings.rules[0].action,
            forward(CLOUDFLARE, expected, "out")
        );
    }

    let (path, _) = first_error(&config(json!([
        {"action": "forward", "address": "1.1.1.1", "port": 0, "outboundTag": "out"}
    ])));
    assert_eq!(path, format!("{RULE}.port"));
    let (path, _) = first_error(&config(json!([
        {"action": "forward", "address": "1.1.1.1", "port": 65536, "outboundTag": "out"}
    ])));
    assert_eq!(path, format!("{RULE}.port"));
}

#[test]
fn a_forward_rule_needs_an_ip_address() {
    for address in [
        None,
        Some(json!("")),
        Some(json!("dns.google")),
        Some(json!("1.1.1.1:53")),
        Some(json!("fe80::1%en0")),
        Some(json!(53)),
    ] {
        let mut rule = json!({"action": "forward", "outboundTag": "out"});
        if let Some(address) = address.clone() {
            rule["address"] = address;
        }
        let (path, _) = first_error(&config(json!([rule])));
        assert_eq!(path, format!("{RULE}.address"), "address {address:?}");
    }
}

#[test]
fn a_forward_rule_may_not_point_into_the_tun() {
    // The core's TUN resolver and client addresses: a query sent there would
    // come straight back into the core.
    for address in ["198.18.0.1", "198.18.0.2", "::ffff:198.18.0.1"] {
        let (path, message) = first_error(&config(json!([
            {"action": "forward", "address": address, "outboundTag": "direct"}
        ])));
        assert_eq!(path, format!("{RULE}.address"), "{address}: {message}");
    }
}

#[test]
fn a_forward_rule_needs_an_outbound_that_carries_traffic() {
    for (tag, why) in [
        (json!(null), "absent"),
        (json!(""), "empty"),
        (json!(7), "not a string"),
        (json!("missing"), "no such outbound"),
        (
            json!("dns-out"),
            "a DNS outbound answers queries, it does not carry them",
        ),
        (json!("block"), "a blackhole carries nothing"),
        (json!("again"), "a loopback has no single path"),
    ] {
        let mut rule = json!({"action": "forward", "address": "1.1.1.1"});
        if !tag.is_null() {
            rule["outboundTag"] = tag.clone();
        }
        let (path, message) = first_error(&config(json!([rule])));
        assert_eq!(path, format!("{RULE}.outboundTag"), "{why}: {message}");
    }
}

#[test]
fn only_a_forward_rule_takes_a_server() {
    for (field, value) in [
        ("address", json!("1.1.1.1")),
        ("port", json!(53)),
        ("outboundTag", json!("out")),
    ] {
        for action in ["direct", "drop", "return", "hijack"] {
            let mut rule = json!({"action": action});
            rule[field] = value.clone();
            let (path, message) = first_error(&config(json!([rule])));
            assert_eq!(path, format!("{RULE}.{field}"), "{action}: {message}");
        }
    }
}

#[test]
fn rules_without_forward_parse_as_before() {
    let settings = dns_settings(&config(json!([
        {"action": "direct", "domain": ["domain:ru"]},
        {"action": "return", "qType": 65, "rCode": 5}
    ])));

    assert_eq!(
        settings.action_for(16, "example.ru"),
        DnsOutboundRuleAction::Direct
    );
    assert_eq!(
        settings.action_for(65, "example.com"),
        DnsOutboundRuleAction::Return
    );
    assert_eq!(
        settings.action_for(16, "example.com"),
        DnsOutboundRuleAction::Return
    );
    assert_eq!(
        settings.action_for(1, "example.com"),
        DnsOutboundRuleAction::Hijack
    );
}

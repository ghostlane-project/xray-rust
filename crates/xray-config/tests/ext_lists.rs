//! Lists named through `ext:file.dat:tag`: a routing rule's `domain` and
//! `ip`, the DNS outbound's rules and a DNS server's `domains` read a v2fly
//! `.dat` from the geodata directory and match what the tag holds and
//! nothing else.
//!
//! The `.dat` files are written by the test itself, as the protobuf wire
//! format v2fly's tools write (`GeoSiteList` and `GeoIPList`), from made-up
//! names and documentation prefixes. Nothing is downloaded.

use std::{
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};
use xray_config::{
    parse_xray_json_with_exclusive_geodata_dirs, DiagnosticSeverity, DnsServerConfig,
    OutboundSettings, ParsedConfig,
};

// v2fly's Domain.Type.
const PLAIN: u64 = 0;
const REGEX: u64 = 1;
const ROOT_DOMAIN: u64 = 2;
const FULL: u64 = 3;

const A: u16 = 1;
const AAAA: u16 = 28;

/// Names the `blocked` tag holds and names it does not.
const BLOCKED_NAMES: &[&str] = &[
    // `ROOT_DOMAIN blocked.example`: the name and everything under it.
    "blocked.example",
    "a.blocked.example",
    "deep.er.blocked.example",
    // `FULL exact.example.org`: that name only.
    "exact.example.org",
    // `PLAIN keyword-xyz`: a substring.
    "cdn.keyword-xyz.example.com",
    // `REGEX ^re[0-9]+\.example\.net$`.
    "re42.example.net",
];
const OTHER_NAMES: &[&str] = &[
    // A suffix matches on a label boundary only.
    "notblocked.example",
    "blocked.example.com",
    "sub.exact.example.org",
    "rex.example.net",
    "example",
    // The `.dat` holds this one under another tag.
    "other.example",
    "a.other.example",
];

const BLOCKED_IPS: &[&str] = &[
    "198.51.100.0",
    "198.51.100.77",
    "198.51.100.255",
    "2001:db8:1::",
    "2001:db8:1:ffff::1",
];
const OTHER_IPS: &[&str] = &[
    "198.51.99.255",
    "198.51.101.0",
    "2001:db8:2::1",
    "2001:db8::1",
    // The `.dat` holds this one under another tag.
    "203.0.113.5",
];

#[test]
fn a_routing_rule_reads_names_through_ext() {
    let fixture = Fixture::new();
    // The three spellings Xray-core reads for a list of names in a file.
    for spelling in ["ext", "ext-domain", "ext-site"] {
        let parsed = fixture.parse(&routing_config(json!({
            "domain": [format!("{spelling}:names.dat:blocked")]
        })));
        let rule = &parsed.config.routing.rules[0];
        for name in BLOCKED_NAMES {
            assert!(rule.matches_domain(Some(name)), "{spelling}: {name}");
            assert!(rule.matches(None, Some(name), None), "{spelling}: {name}");
        }
        for name in OTHER_NAMES {
            assert!(!rule.matches_domain(Some(name)), "{spelling}: {name}");
            assert!(!rule.matches(None, Some(name), None), "{spelling}: {name}");
        }
    }
}

#[test]
fn a_routing_rule_reads_prefixes_through_ext() {
    let fixture = Fixture::new();
    for spelling in ["ext", "ext-ip"] {
        let parsed = fixture.parse(&routing_config(json!({
            "ip": [format!("{spelling}:prefixes.dat:blocked")]
        })));
        let rule = &parsed.config.routing.rules[0];
        for ip in BLOCKED_IPS {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(rule.matches_ip(Some(&ip)), "{spelling}: {ip}");
            assert!(rule.matches(None, None, Some(&ip)), "{spelling}: {ip}");
        }
        for ip in OTHER_IPS {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!rule.matches_ip(Some(&ip)), "{spelling}: {ip}");
            assert!(!rule.matches(None, None, Some(&ip)), "{spelling}: {ip}");
        }
    }
}

/// The tag is found whatever its case in the config, as in Xray-core, and a
/// second tag of the same file is a list of its own.
#[test]
fn the_tag_selects_one_list_of_the_file() {
    let fixture = Fixture::new();
    let parsed = fixture.parse(&routing_config(json!({
        "domain": ["ext:names.dat:OTHER"]
    })));
    let rule = &parsed.config.routing.rules[0];
    assert!(rule.matches_domain(Some("a.other.example")));
    for name in BLOCKED_NAMES {
        assert!(!rule.matches_domain(Some(name)), "{name}");
    }

    let parsed = fixture.parse(&routing_config(json!({
        "ip": ["ext:prefixes.dat:Other"]
    })));
    let rule = &parsed.config.routing.rules[0];
    assert!(rule.matches_ip(Some(&"203.0.113.5".parse().unwrap())));
    for ip in BLOCKED_IPS {
        assert!(!rule.matches_ip(Some(&ip.parse().unwrap())), "{ip}");
    }
}

#[test]
fn the_dns_outbound_reads_names_through_ext() {
    let fixture = Fixture::new();
    for spelling in ["ext", "ext-domain", "ext-site"] {
        let parsed = fixture.parse(&dns_outbound_config(json!([
            {"action": "drop", "domain": [format!("{spelling}:names.dat:blocked")]}
        ])));
        let OutboundSettings::Dns(settings) = &parsed.config.outbounds[1].settings else {
            panic!("expected a DNS outbound");
        };
        let rule = &settings.rules[0];
        for name in BLOCKED_NAMES {
            assert!(rule.matches(A, name), "{spelling}: {name}");
            assert!(rule.matches(AAAA, name), "{spelling}: {name}");
            // A query name as it is on the wire, with its root label.
            assert!(rule.matches(A, &format!("{name}.")), "{spelling}: {name}.");
        }
        for name in OTHER_NAMES {
            assert!(!rule.matches(A, name), "{spelling}: {name}");
            assert!(!rule.matches(AAAA, name), "{spelling}: {name}");
        }
    }
}

#[test]
fn a_dns_server_reads_names_through_ext() {
    let fixture = Fixture::new();
    let parsed = fixture.parse(
        &json!({
            "dns": {"servers": [{"address": "192.0.2.53", "domains": ["ext:names.dat:blocked"]}]},
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        })
        .to_string(),
    );
    let DnsServerConfig::Policy(server) = &parsed.config.dns.servers[0] else {
        panic!("expected a server with domains");
    };
    for name in BLOCKED_NAMES {
        assert!(server.domains.matches(name), "{name}");
    }
    for name in OTHER_NAMES {
        assert!(!server.domains.matches(name), "{name}");
    }
}

/// A file or a tag that is not there refuses the config, at the entry that
/// names it: a rule never silently matches nothing.
#[test]
fn a_missing_file_or_tag_is_refused_where_it_is_named() {
    let fixture = Fixture::new();
    for (entry, what) in [
        ("ext:absent.dat:blocked", "a missing file"),
        ("ext:names.dat:absent", "a missing tag"),
    ] {
        assert_eq!(
            fixture.first_error_path(&routing_config(json!({"domain": [entry]}))),
            "$.routing.rules[0].domain[0]",
            "{what} in a routing rule's names"
        );
        assert_eq!(
            fixture.first_error_path(&dns_outbound_config(
                json!([{"action": "drop", "domain": [entry]}])
            )),
            "$.outbounds[1].settings.rules[0].domain[0]",
            "{what} in the DNS outbound's rule"
        );
    }
    for (entry, what) in [
        ("ext:absent.dat:blocked", "a missing file"),
        ("ext:prefixes.dat:absent", "a missing tag"),
    ] {
        assert_eq!(
            fixture.first_error_path(&routing_config(json!({"ip": [entry]}))),
            "$.routing.rules[0].ip[0]",
            "{what} in a routing rule's prefixes"
        );
    }
}

fn routing_config(condition: Value) -> String {
    let mut rule = json!({"type": "field", "outboundTag": "blocked-out"});
    for (key, value) in condition.as_object().unwrap() {
        rule[key] = value.clone();
    }
    json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked-out", "protocol": "freedom"}
        ],
        "routing": {"rules": [rule]}
    })
    .to_string()
}

fn dns_outbound_config(rules: Value) -> String {
    json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns", "settings": {"rules": rules}}
        ]
    })
    .to_string()
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "xray-ext-lists-{}-{stamp}-{id}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let fixture = Self { dir };

        let names = geo_list(&[
            geo_site(
                "BLOCKED",
                &[
                    (ROOT_DOMAIN, "blocked.example"),
                    (FULL, "exact.example.org"),
                    (PLAIN, "keyword-xyz"),
                    (REGEX, r"^re[0-9]+\.example\.net$"),
                ],
            ),
            geo_site("OTHER", &[(ROOT_DOMAIN, "other.example")]),
        ]);
        fs::write(fixture.dir.join("names.dat"), names).unwrap();

        let prefixes = geo_list(&[
            geo_ip("BLOCKED", &["198.51.100.0/24", "2001:db8:1::/48"]),
            geo_ip("OTHER", &["203.0.113.0/24"]),
        ]);
        fs::write(fixture.dir.join("prefixes.dat"), prefixes).unwrap();
        fixture
    }

    /// Parses with this directory as the only place geodata is looked for.
    fn parse(&self, raw: &str) -> ParsedConfig {
        parse_xray_json_with_exclusive_geodata_dirs(raw, std::slice::from_ref(&self.dir))
            .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
    }

    fn first_error_path(&self, raw: &str) -> String {
        let error =
            parse_xray_json_with_exclusive_geodata_dirs(raw, std::slice::from_ref(&self.dir))
                .expect_err(&format!("{raw} should be refused"));
        error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
            .and_then(|diagnostic| diagnostic.path.clone())
            .unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// The protobuf wire format, written by hand so the test shares no code with
// the reader it checks.

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn bytes_field(out: &mut Vec<u8>, tag: u64, body: &[u8]) {
    varint(out, tag << 3 | 2);
    varint(out, body.len() as u64);
    out.extend_from_slice(body);
}

fn varint_field(out: &mut Vec<u8>, tag: u64, value: u64) {
    varint(out, tag << 3);
    varint(out, value);
}

/// `GeoSite { country_code = 1; repeated Domain domain = 2 }` with
/// `Domain { Type type = 1; string value = 2 }`.
fn geo_site(code: &str, domains: &[(u64, &str)]) -> Vec<u8> {
    let mut site = Vec::new();
    bytes_field(&mut site, 1, code.as_bytes());
    for (kind, value) in domains {
        let mut domain = Vec::new();
        varint_field(&mut domain, 1, *kind);
        bytes_field(&mut domain, 2, value.as_bytes());
        bytes_field(&mut site, 2, &domain);
    }
    site
}

/// `GeoIP { country_code = 1; repeated CIDR cidr = 2 }` with
/// `CIDR { bytes ip = 1; uint32 prefix = 2 }`.
fn geo_ip(code: &str, cidrs: &[&str]) -> Vec<u8> {
    let mut entry = Vec::new();
    bytes_field(&mut entry, 1, code.as_bytes());
    for cidr in cidrs {
        let (ip, prefix) = cidr.split_once('/').unwrap();
        let ip = match ip.parse::<IpAddr>().unwrap() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mut body = Vec::new();
        bytes_field(&mut body, 1, &ip);
        varint_field(&mut body, 2, prefix.parse().unwrap());
        bytes_field(&mut entry, 2, &body);
    }
    entry
}

/// `GeoSiteList` and `GeoIPList`: `repeated entry = 1`.
fn geo_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for entry in entries {
        bytes_field(&mut list, 1, entry);
    }
    list
}

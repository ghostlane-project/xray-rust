// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The ICE servers the focus advertises (XEP-0215 `extdisco`): the services
//! as the library reads them and renders them as STUN/TURN URLs
//! (`J/internal/xmpp/conn.go:1092`, `J/j.go:614-699`).
//!
//! `NormaliseICEServers` of the engine (`internal/engine/iceservers.go`) is
//! not ported: it makes pion accept URLs, and what [`convert_ice`] writes is
//! already the form it ends in. The peer asks no STUN server (plan D9), so
//! `stun:` entries are read and not used.

use std::net::Ipv6Addr;

use olc_rtc::turn::TurnServer;

use crate::xml::{Event, Reader};

/// One `<service/>` of the focus's answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Service {
    /// `stun`, `stuns`, `turn`, `turns`, or something that is not ICE.
    pub kind: String,
    /// The host.
    pub host: String,
    /// The port, as written.
    pub port: String,
    /// `udp`, `tcp`, or what the server wrote.
    pub transport: String,
    /// The TURN user name.
    pub username: String,
    /// The TURN password.
    pub password: String,
}

/// An ICE server in WebRTC's shape (`ICEServer`).
#[derive(Clone, PartialEq, Eq)]
pub struct IceServer {
    /// Its URLs; one per service here.
    pub urls: Vec<String>,
    /// The TURN user name.
    pub username: String,
    /// The TURN password.
    pub credential: String,
}

impl std::fmt::Debug for IceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceServer")
            .field("urls", &self.urls)
            .field("username_len", &self.username.len())
            .field("credential_len", &self.credential.len())
            .finish()
    }
}

/// The most services read from one answer; Go has no bound.
pub const MAX_SERVICES: usize = 64;

/// The services of an extdisco answer (`parseServices`): the `service`
/// children of the root's `services` child. What cannot be read gives what
/// was read before it, as Go's `xml.Unmarshal` leaves the struct.
#[must_use]
pub fn parse_services(xml: &str) -> Vec<Service> {
    let mut out = Vec::new();
    let mut r = Reader::new(xml);
    // 1 inside the root, 2 inside its `services`.
    let mut depth = 0usize;
    let mut in_services = false;
    loop {
        let Ok(Some(ev)) = r.next_event() else {
            return out;
        };
        match ev {
            Event::Start(s) => {
                depth += 1;
                if depth == 2 && s.name == "services" && !in_services {
                    in_services = !s.self_closing;
                    if s.self_closing {
                        depth -= 1;
                    }
                } else if depth == 3 && in_services && s.name == "service" {
                    if out.len() < MAX_SERVICES {
                        let a = |n: &str| {
                            s.attr(n)
                                .ok()
                                .flatten()
                                .map(|v| v.into_owned())
                                .unwrap_or_default()
                        };
                        out.push(Service {
                            kind: a("type"),
                            host: a("host"),
                            port: a("port"),
                            transport: a("transport"),
                            username: a("username"),
                            password: a("password"),
                        });
                    }
                    if s.self_closing {
                        depth -= 1;
                    }
                } else if s.self_closing {
                    depth -= 1;
                }
            }
            Event::End(_) => {
                if depth == 2 {
                    in_services = false;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Text(_) => {}
        }
    }
}

/// One service as an RFC 7064/7065 URI (`iceServiceURL`): the default port
/// of the scheme for a missing one, an IPv6 host in brackets, the transport
/// only for turn and only when it is `udp` or `tcp`. `None` for anything
/// that is no usable ICE service.
#[must_use]
pub fn service_url(s: &Service) -> Option<String> {
    let scheme = s.kind.trim().to_lowercase();
    let default_port = match scheme.as_str() {
        "stun" | "turn" => "3478",
        "stuns" | "turns" => "5349",
        _ => return None,
    };
    let mut host = s.host.trim();
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        host = inner;
    }
    if host.is_empty() || host.contains(['[', ']', '?', '#', '/', '@', '%', ' ', '\t', '\r', '\n'])
    {
        return None;
    }
    let colon = host.contains(':');
    if colon && host.parse::<Ipv6Addr>().is_err() {
        return None;
    }
    let port = match s.port.trim() {
        "" => default_port.to_owned(),
        p => p.to_owned(),
    };
    match port.parse::<i64>() {
        Ok(n) if (1..=65535).contains(&n) => {}
        _ => return None,
    }
    let hostport = if colon {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut url = format!("{scheme}:{hostport}");
    if scheme == "turn" || scheme == "turns" {
        let t = s.transport.trim().to_lowercase();
        if t == "udp" || t == "tcp" {
            url.push_str("?transport=");
            url.push_str(&t);
        }
    }
    Some(url)
}

/// The servers of a list of services (`convertICE`): one server per usable
/// service, in order; a `turn` or `turns` one only with a user name and a
/// password.
#[must_use]
pub fn convert_ice(services: &[Service]) -> Vec<IceServer> {
    services
        .iter()
        .filter_map(|s| {
            let url = service_url(s)?;
            let turn = url.starts_with("turn:") || url.starts_with("turns:");
            if turn && (s.username.is_empty() || s.password.is_empty()) {
                return None;
            }
            Some(IceServer {
                urls: vec![url],
                username: s.username.clone(),
                credential: s.password.clone(),
            })
        })
        .collect()
}

/// The TURN servers the peer allocates on: every `turn:` URL over UDP or
/// TCP, and `turns:` ones when the build has Chrome's TLS; `stun:` ones are
/// left out (plan D9).
#[must_use]
pub fn turn_servers(servers: &[IceServer]) -> Vec<TurnServer> {
    let mut out: Vec<TurnServer> = Vec::new();
    for s in servers {
        for t in olc_rtc::turn::servers(&s.urls, &s.username, &s.credential) {
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(kind: &str, host: &str, port: &str, transport: &str, user: &str, pass: &str) -> Service {
        Service {
            kind: kind.into(),
            host: host.into(),
            port: port.into(),
            transport: transport.into(),
            username: user.into(),
            password: pass.into(),
        }
    }

    /// `TestConvertICEURLFormation` (`J/ice_test.go:15`), every row.
    #[test]
    fn the_url_table() {
        let c = |s: &Service| convert_ice(std::slice::from_ref(s));
        let rows: Vec<(&str, Service, &str)> = vec![
            (
                "stun explicit port",
                svc("stun", "stun.example.com", "3478", "", "", ""),
                "stun:stun.example.com:3478",
            ),
            (
                "stun empty port",
                svc("stun", "stun.example.com", "", "", "", ""),
                "stun:stun.example.com:3478",
            ),
            (
                "stuns empty port",
                svc("stuns", "stun.example.com", "", "", "", ""),
                "stuns:stun.example.com:5349",
            ),
            (
                "turn empty port",
                svc("turn", "turn.example.com", "", "udp", "user", "pass"),
                "turn:turn.example.com:3478?transport=udp",
            ),
            (
                "turns empty port",
                svc("turns", "turn.example.com", "", "tcp", "user", "pass"),
                "turns:turn.example.com:5349?transport=tcp",
            ),
            (
                "turn empty transport",
                svc("turn", "turn.example.com", "3478", "", "user", "pass"),
                "turn:turn.example.com:3478",
            ),
            (
                "turn unknown transport",
                svc("turn", "turn.example.com", "443", "ssltcp", "user", "pass"),
                "turn:turn.example.com:443",
            ),
            (
                "turn uppercase transport",
                svc("turn", "turn.example.com", "3478", "UDP", "user", "pass"),
                "turn:turn.example.com:3478?transport=udp",
            ),
            (
                "stun ignores transport",
                svc("stun", "stun.example.com", "3478", "udp", "", ""),
                "stun:stun.example.com:3478",
            ),
            (
                "uppercase type",
                svc("STUN", "stun.example.com", "3478", "", "", ""),
                "stun:stun.example.com:3478",
            ),
            (
                "whitespace",
                svc(" stun ", " stun.example.com ", " 3478 ", "", "", ""),
                "stun:stun.example.com:3478",
            ),
            (
                "ipv6 default port",
                svc("stun", "2001:db8::1", "", "", "", ""),
                "stun:[2001:db8::1]:3478",
            ),
            (
                "ipv6 explicit port",
                svc("turn", "2001:db8::1", "3478", "tcp", "user", "pass"),
                "turn:[2001:db8::1]:3478?transport=tcp",
            ),
            (
                "ipv6 bracketed",
                svc("stun", "[2001:db8::1]", "3478", "", "", ""),
                "stun:[2001:db8::1]:3478",
            ),
            (
                "turn with credentials",
                svc("turn", "turn.example.com", "3478", "udp", "user", "pass"),
                "turn:turn.example.com:3478?transport=udp",
            ),
            (
                "stuns without credentials",
                svc("stuns", "stun.example.com", "5349", "", "", ""),
                "stuns:stun.example.com:5349",
            ),
        ];
        for (name, s, want) in rows {
            let got = c(&s);
            assert_eq!(got.len(), 1, "{name}");
            assert_eq!(got[0].urls, [want], "{name}");
        }
        let skipped: Vec<(&str, Service)> = vec![
            ("missing host", svc("stun", "", "3478", "", "", "")),
            (
                "missing type",
                svc("", "stun.example.com", "3478", "", "", ""),
            ),
            (
                "non ice type",
                svc("speech-to-text", "stt.example.com", "443", "", "", ""),
            ),
            (
                "non numeric port",
                svc("stun", "stun.example.com", "notaport", "", "", ""),
            ),
            (
                "out of range port",
                svc("stun", "stun.example.com", "70000", "", "", ""),
            ),
            (
                "zero port",
                svc("stun", "stun.example.com", "0", "", "", ""),
            ),
            (
                "negative port",
                svc("stun", "stun.example.com", "-1", "", "", ""),
            ),
            (
                "url metacharacters",
                svc("stun", "stun.example.com?x", "3478", "", "", ""),
            ),
            (
                "colon host that is no ipv6",
                svc("stun", "evil:host", "3478", "", "", ""),
            ),
            (
                "embedded port",
                svc("stun", "stun.example.com:3478", "3478", "", "", ""),
            ),
            (
                "bracketed non-ipv6",
                svc("stun", "[evil:host]", "3478", "", "", ""),
            ),
            (
                "malformed ipv6",
                svc("stun", "2001:db8::zz", "3478", "", "", ""),
            ),
            (
                "turn without credentials",
                svc("turn", "turn.example.com", "3478", "udp", "", ""),
            ),
            (
                "turns without credentials",
                svc("turns", "turn.example.com", "5349", "tcp", "", ""),
            ),
            (
                "turn username only",
                svc("turn", "turn.example.com", "3478", "udp", "user", ""),
            ),
            (
                "turn password only",
                svc("turn", "turn.example.com", "3478", "udp", "", "pass"),
            ),
        ];
        for (name, s) in skipped {
            assert!(c(&s).is_empty(), "{name}: {:?}", c(&s));
        }
    }

    /// `TestConvertICEMixedServices` (`J/ice_test.go:211`) and the empty case.
    #[test]
    fn one_bad_service_does_not_poison_the_rest() {
        let services = [
            svc("stun", "stun.example.com", "", "", "", ""),
            svc("turn", "", "3478", "udp", "", ""),
            svc("turn", "anon.example.com", "3478", "udp", "", ""),
            svc("turn", "turn.example.com", "", "udp", "user1", "pass1"),
            svc("speech-to-text", "stt.example.com", "443", "", "", ""),
            svc("turns", "turn.example.com", "443", "tcp", "user2", "pass2"),
            svc("turns", "partial.example.com", "443", "tcp", "user3", ""),
            svc("stun", "broken.example.com", "notaport", "", "", ""),
        ];
        let got = convert_ice(&services);
        let want = [
            ("stun:stun.example.com:3478", "", ""),
            ("turn:turn.example.com:3478?transport=udp", "user1", "pass1"),
            ("turns:turn.example.com:443?transport=tcp", "user2", "pass2"),
        ];
        assert_eq!(got.len(), want.len());
        for (g, (url, u, p)) in got.iter().zip(want) {
            assert_eq!(
                (
                    g.urls.as_slice(),
                    g.username.as_str(),
                    g.credential.as_str()
                ),
                (&[url.to_owned()][..], u, p)
            );
        }
        assert!(convert_ice(&[]).is_empty());
    }

    #[test]
    fn the_extdisco_answer_is_read() {
        let xml = "<iq type='result' id='disco_1' from='meet.example' xmlns='jabber:client'><services xmlns='urn:xmpp:extdisco:2'>\
            <service type='stun' host='stun.example.com' port='3478' transport='udp'/>\
            <service type='turn' host='turn.example.com' port='443' transport='tcp' username='u1' password='p1' restricted='1'/>\
            <service type='turns' host='turn.example.com'></service>\
            </services></iq>";
        let s = parse_services(xml);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], svc("stun", "stun.example.com", "3478", "udp", "", ""));
        assert_eq!(
            s[1],
            svc("turn", "turn.example.com", "443", "tcp", "u1", "p1")
        );
        assert_eq!(s[2].kind, "turns");
        // No services, services elsewhere, an answer that is cut.
        assert!(parse_services("<iq type='result'/>").is_empty());
        assert!(parse_services(
            "<iq><x><services><service type='stun' host='h'/></services></x></iq>"
        )
        .is_empty());
        let cut = parse_services(
            "<iq><services><service type='stun' host='a'/><service type='stun' host='b'/><serv",
        );
        assert_eq!(cut.len(), 2);
        assert!(parse_services("").is_empty());
        // Entities in an attribute.
        let e = parse_services("<iq><services><service type='turn' host='h' username='a&amp;b' password='p'/></services></iq>");
        assert_eq!(e[0].username, "a&b");
    }

    #[test]
    fn at_most_so_many_services_are_read() {
        let mut xml = String::from("<iq><services>");
        for i in 0..200 {
            xml.push_str(&format!("<service type='stun' host='h{i}'/>"));
        }
        xml.push_str("</services></iq>");
        assert_eq!(parse_services(&xml).len(), MAX_SERVICES);
    }

    #[test]
    fn turn_entries_go_to_the_peer_and_stun_does_not() {
        let servers = convert_ice(&[
            svc("stun", "stun.example.com", "", "", "", ""),
            svc("turn", "turn.example.com", "3478", "udp", "user", "pass"),
            svc("turn", "turn.example.com", "3478", "udp", "user", "pass"),
            svc("turn", "turn2.example.com", "443", "tcp", "user", "pass"),
        ]);
        let t = turn_servers(&servers);
        assert_eq!(t.len(), 2, "{t:?}");
        assert_eq!((t[0].host.as_str(), t[0].port), ("turn.example.com", 3478));
        assert_eq!((t[1].host.as_str(), t[1].port), ("turn2.example.com", 443));
        assert!(
            !format!("{:?}", servers[1]).contains("pass"),
            "a credential in a Debug"
        );
    }
}

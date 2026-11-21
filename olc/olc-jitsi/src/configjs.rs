// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! config.js discovery, the pure half: what the j library reads out of the
//! file, and the engine's judgement of it (`internal/engine/jitsi/configjs.go`,
//! `J/internal/xmpp/conn.go:217-338`).

use std::time::Duration;

/// How many times config.js is asked for.
pub const ATTEMPTS: u32 = 3;
/// All of config.js the library looks at: one read into a 64 KiB buffer.
pub const MAX_BODY: usize = 64 << 10;
/// The pause before the second attempt; the third waits twice as long.
pub const PAUSE: Duration = Duration::from_secs(1);
/// One attempt, from the request to the end of the body.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the rest of the body gets once the lines read declare the domain.
pub const GRACE: Duration = Duration::from_secs(1);
/// Discovery as a whole, attempts and pauses together.
pub const BUDGET: Duration = Duration::from_secs(10);

/// The XMPP domain of a docker-jitsi-meet server whatever its public name.
pub const FALLBACK_XMPP_DOMAIN: &str = "meet.jitsi";
/// Its MUC domain.
pub const FALLBACK_MUC_DOMAIN: &str = "muc.meet.jitsi";
/// What a docker-jitsi-meet config.js says about its XMPP hosts.
pub const FALLBACK_CONFIG: &str = "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nconfig.hosts.muc = 'muc.meet.jitsi';\n";

/// The User-Agent the library's WebSocket dial sends, and config.js is asked
/// with.
pub const BROWSER_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0";

/// A config.js answer other than 200: `HTTP 403 text/html`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("HTTP {code} {media_type}")]
pub struct StatusError {
    /// The status.
    pub code: u16,
    /// The Content-Type without parameters ([`media_type`]).
    pub media_type: String,
}

impl StatusError {
    /// The same request gets this answer again, so another attempt only
    /// waits for it: a redirect, or 404 or 410 from a host with no config.js.
    #[must_use]
    pub fn is_final(&self) -> bool {
        (300..400).contains(&self.code) || self.code == 404 || self.code == 410
    }
}

/// The Content-Type of an answer without its parameters.
#[must_use]
pub fn media_type(content_type: Option<&str>) -> String {
    let mt = content_type
        .map(|c| c.split(';').next().unwrap_or("").trim())
        .unwrap_or("");
    if mt.is_empty() {
        "no content-type".to_owned()
    } else {
        mt.to_owned()
    }
}

/// `b` up to its last newline: a line cut mid-value would hand the library
/// half a domain.
#[must_use]
pub fn whole_lines(b: &[u8]) -> &[u8] {
    match b.iter().rposition(|c| *c == b'\n') {
        Some(i) => &b[..=i],
        None => &b[..0],
    }
}

/// The XMPP domain the library takes from a config.js body (`libraryDomain`);
/// empty means it opens the stream to the web host.
#[must_use]
pub fn library_domain(body: &[u8]) -> String {
    extract_string_field(&String::from_utf8_lossy(body), "domain")
}

/// The first line that, less a leading `config.hosts.` or `config.`, starts
/// with `key` and then `:`, `=` or a blank, and whose value, cut at the first
/// `;` or `,` and then at a `//` comment, holds string literals: those
/// literals joined (`extractStringField`).
#[must_use]
pub fn extract_string_field(body: &str, key: &str) -> String {
    for line in body.split('\n') {
        let t = line.trim();
        let t = t.strip_prefix("config.hosts.").unwrap_or(t);
        let t = t.strip_prefix("config.").unwrap_or(t);
        let Some(rest) = t.strip_prefix(key) else {
            continue;
        };
        if !matches!(rest.as_bytes().first(), Some(b':' | b'=' | b' ' | b'\t')) {
            continue;
        }
        let mut expr = rest.trim_start_matches([' ', '\t', ':', '=']);
        if let Some(i) = expr.find([';', ',']) {
            expr = &expr[..i];
        }
        if let Some(i) = comment_start(expr) {
            expr = &expr[..i];
        }
        let v = join_literals(expr);
        if !v.is_empty() {
            return v;
        }
    }
    String::new()
}

/// Where a `//` comment starts outside string literals.
fn comment_start(expr: &str) -> Option<usize> {
    let b = expr.as_bytes();
    let mut quote = 0u8;
    for (i, &c) in b.iter().enumerate() {
        if quote != 0 {
            if c == quote {
                quote = 0;
            }
        } else if c == b'\'' || c == b'"' {
            quote = c;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            return Some(i);
        }
    }
    None
}

/// The string literals of a JS expression, joined, up to one left open.
fn join_literals(expr: &str) -> String {
    let mut out = String::new();
    let mut rest = expr;
    while let Some(start) = rest.find(['\'', '"']) {
        let q = rest.as_bytes()[start] as char;
        let after = &rest[start + 1..];
        let Some(end) = after.find(q) else {
            break;
        };
        out.push_str(&after[..end]);
        rest = &after[end + 1..];
    }
    out
}

/// What the library reads out of config.js (`fetchConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitsiConfig {
    /// `hosts.domain`, the web host when none.
    pub xmpp_domain: String,
    /// `hosts.muc`, `conference.<host>` when none.
    pub muc_domain: String,
    /// `websocket`, with `//` given `wss:`; empty when none.
    pub websocket: String,
    /// `bosh`, with `//` given `https:`; empty when none.
    pub bosh: String,
}

impl JitsiConfig {
    /// The reading of `body` for the web host `host`.
    #[must_use]
    pub fn from_body(host: &str, body: &str) -> Self {
        let mut c = Self {
            xmpp_domain: host.to_owned(),
            muc_domain: format!("conference.{host}"),
            websocket: String::new(),
            bosh: String::new(),
        };
        let v = extract_string_field(body, "domain");
        if !v.is_empty() {
            c.xmpp_domain = v;
        }
        let v = extract_string_field(body, "muc");
        if !v.is_empty() {
            c.muc_domain = v;
        }
        let v = extract_string_field(body, "websocket");
        if !v.is_empty() {
            c.websocket = match v.strip_prefix("//") {
                Some(_) => format!("wss:{v}"),
                None => v,
            };
        }
        let v = extract_string_field(body, "bosh");
        if !v.is_empty() {
            c.bosh = match v.strip_prefix("//") {
                Some(_) => format!("https:{v}"),
                None => v,
            };
        }
        c
    }

    /// The WebSocket URL the library dials, with the room appended as it is
    /// (not escaped).
    #[must_use]
    pub fn websocket_url(&self, host: &str, room: &str) -> String {
        let base = if self.websocket.is_empty() {
            format!("wss://{host}/xmpp-websocket")
        } else {
            self.websocket.clone()
        };
        let sep = if base.contains('?') { '&' } else { '?' };
        format!("{base}{sep}room={room}")
    }
}

/// Whether a failed join gets one more try on the docker-jitsi-meet
/// defaults: the server refused the XMPP domain with a `<host-unknown/>`
/// stream error, and that domain was the library's guess because config.js
/// could not be read (`shouldRetryWithFallback`).
#[must_use]
pub fn should_retry_with_fallback(join_err: Option<&str>, discovery_failed: bool) -> bool {
    discovery_failed && join_err.is_some_and(|e| e.contains("<host-unknown"))
}

/// The headers a browser sends for the script, for a request that has none
/// of its own (`browserRequest`).
#[must_use]
pub fn browser_headers(scheme: &str, host: &str) -> [(&'static str, String); 4] {
    [
        ("User-Agent", BROWSER_USER_AGENT.to_owned()),
        ("Accept", "*/*".to_owned()),
        ("Accept-Language", "en-US,en;q=0.9".to_owned()),
        ("Referer", format!("{scheme}://{host}/")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCKER: &str = "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nvar subdomain = '';\nconfig.hosts.muc = 'muc.' + subdomain + 'meet.jitsi';\n";

    /// `domainCases` (`configjs_test.go:549`).
    #[test]
    fn the_domain_the_library_takes() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "jitsi-meet config",
                "var config = {\n    // Connection\n    //\n\n    hosts: {\n        // XMPP domain.\n        domain: 'jitsi-meet.example.com',\n\n        muc: 'conference.' + subdomain + 'jitsi-meet.example.com',\n    },\n\n    bosh: 'https://jitsi-meet.example.com/' + subdir + 'http-bind',\n};\n",
                "jitsi-meet.example.com",
            ),
            ("docker-jitsi-meet config", DOCKER, "meet.jitsi"),
            (
                "double quotes and a trailing comment",
                "config.hosts.domain = \"meet.example.org\"; // XMPP\n",
                "meet.example.org",
            ),
            (
                "concatenated literals",
                "var config = {\n    hosts: {\n        domain: 'meet.' + subdomain + 'example.org',\n    },\n};\n",
                "meet.example.org",
            ),
            (
                "hosts opened on the config line",
                "var config = { hosts: {\n        domain: 'xmpp.custom.example',\n    },\n};\n",
                "xmpp.custom.example",
            ),
            (
                "hosts brace on a line of its own",
                "var config = {\n    hosts:\n    {\n        domain: 'xmpp.custom.example',\n    },\n};\n",
                "xmpp.custom.example",
            ),
            (
                "the first domain key wins, in hosts or not",
                "var other = {\n    domain: 'other.example',\n};\nvar config = {\n    hosts: {\n        domain: 'meet.example.org',\n    },\n};\n",
                "other.example",
            ),
            (
                "a key without a literal gives way to the next",
                "config.hosts.domain = someVariable;\nconfig.hosts.domain = 'meet.example.org';\n",
                "meet.example.org",
            ),
            ("a semicolon in the literal cuts it", "config.hosts.domain = 'meet;example.org';\n", ""),
            ("html error page", "<html><body>Attention Required!</body></html>", ""),
            ("file cut before hosts", "var config = {\n    // Connection\n", ""),
            (
                "commented out",
                "var config = {\n    hosts: {\n        // domain: 'x.example',\n    },\n};\n",
                "",
            ),
            (
                "only anonymousdomain",
                "var config = {\n    hosts: {\n        anonymousdomain: 'guest.example',\n    },\n};\n",
                "",
            ),
            ("longer key", "config.hosts.domainAlias = 'x.example';\n", ""),
            ("not a string", "config.hosts.domain = someVariable;\n", ""),
            ("a literal left open", "config.hosts.domain = 'meet.' + 'exam", "meet."),
            ("a // inside a literal", "config.hosts.domain = 'http://x';\n", "http://x"),
        ];
        for (name, body, want) in cases {
            assert_eq!(library_domain(body.as_bytes()), *want, "{name}");
            // The library's own function agrees with the engine's.
            assert_eq!(extract_string_field(body, "domain"), *want, "{name}");
        }
    }

    #[test]
    fn what_the_library_reads_of_a_config() {
        let c = JitsiConfig::from_body("web.example", DOCKER);
        assert_eq!(c.xmpp_domain, "meet.jitsi");
        assert_eq!(c.muc_domain, "muc.meet.jitsi");
        assert_eq!(c.websocket, "");
        assert_eq!(c.bosh, "");
        // Nothing declared: the web host, and "conference." before it.
        let c = JitsiConfig::from_body("web.example", "<html></html>");
        assert_eq!(c.xmpp_domain, "web.example");
        assert_eq!(c.muc_domain, "conference.web.example");
        // Protocol-relative URLs get their scheme.
        let c = JitsiConfig::from_body(
            "web.example",
            "config.websocket = '//web.example/xmpp-websocket';\nconfig.bosh = '//web.example/http-bind';\n",
        );
        assert_eq!(c.websocket, "wss://web.example/xmpp-websocket");
        assert_eq!(c.bosh, "https://web.example/http-bind");
        let c = JitsiConfig::from_body(
            "web.example",
            "    websocket: 'wss://other.example/xmpp-websocket',\n    bosh: 'https://other.example/http-bind',\n",
        );
        assert_eq!(c.websocket, "wss://other.example/xmpp-websocket");
        assert_eq!(c.bosh, "https://other.example/http-bind");
    }

    #[test]
    fn the_websocket_url_gets_the_room() {
        let mut c = JitsiConfig::from_body("web.example", "");
        assert_eq!(
            c.websocket_url("web.example", "r"),
            "wss://web.example/xmpp-websocket?room=r"
        );
        c.websocket = "wss://x.example/xmpp-websocket?token=1".into();
        assert_eq!(
            c.websocket_url("web.example", "r"),
            "wss://x.example/xmpp-websocket?token=1&room=r"
        );
    }

    #[test]
    fn whole_lines_cuts_at_the_last_newline() {
        assert_eq!(whole_lines(b"a\nb\nc"), b"a\nb\n");
        assert_eq!(whole_lines(b"abc"), b"");
        assert_eq!(whole_lines(b"a\n"), b"a\n");
        assert_eq!(whole_lines(b""), b"");
    }

    /// `TestShouldRetryWithFallback` (`configjs_test.go:636`).
    #[test]
    fn the_fallback_is_for_host_unknown_after_a_failed_discovery() {
        let host_unknown = "xmpp dial: initial features: server error: <stream:error xmlns='jabber:client'><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text>This server does not serve meet.example.com</text></stream:error>";
        let other = "xmpp dial: failed to WebSocket dial: expected handshake response status code 101 but got 502";
        let outside = "dial tcp: lookup host-unknown.example: no such host";
        for (err, failed, want) in [
            (Some(host_unknown), true, true),
            (Some(host_unknown), false, false),
            (Some(other), true, false),
            (Some(other), false, false),
            (Some(outside), true, false),
            (None, true, false),
        ] {
            assert_eq!(
                should_retry_with_fallback(err, failed),
                want,
                "{err:?} {failed}"
            );
        }
    }

    #[test]
    fn answers_that_another_try_would_not_change() {
        let s = |code| StatusError {
            code,
            media_type: "text/html".into(),
        };
        for code in [301, 302, 307, 399, 404, 410] {
            assert!(s(code).is_final(), "{code}");
        }
        for code in [200, 400, 403, 429, 500, 502, 503] {
            assert!(!s(code).is_final(), "{code}");
        }
        assert_eq!(s(403).to_string(), "HTTP 403 text/html");
        assert_eq!(media_type(Some("text/html; charset=utf-8")), "text/html");
        assert_eq!(media_type(Some("  ; x")), "no content-type");
        assert_eq!(media_type(None), "no content-type");
    }

    #[test]
    fn the_fallback_body_is_dockers() {
        assert_eq!(FALLBACK_CONFIG, "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nconfig.hosts.muc = 'muc.meet.jitsi';\n");
        assert_eq!(library_domain(FALLBACK_CONFIG.as_bytes()), "meet.jitsi");
        assert_eq!(
            JitsiConfig::from_body("x", FALLBACK_CONFIG).muc_domain,
            "muc.meet.jitsi"
        );
    }

    /// The headers a browser sends for the script, where the request has
    /// none of its own.
    #[test]
    fn the_scripts_headers() {
        let h = browser_headers("https", "meet.example:8443");
        assert_eq!(
            h,
            [
                (
                    "User-Agent",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
                        .to_owned()
                ),
                ("Accept", "*/*".to_owned()),
                ("Accept-Language", "en-US,en;q=0.9".to_owned()),
                ("Referer", "https://meet.example:8443/".to_owned()),
            ]
        );
    }

    #[test]
    fn limits() {
        use std::time::Duration;
        assert_eq!(ATTEMPTS, 3);
        assert_eq!(MAX_BODY, 64 << 10);
        assert_eq!(PAUSE, Duration::from_secs(1));
        assert_eq!(ATTEMPT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(GRACE, Duration::from_secs(1));
        assert_eq!(BUDGET, Duration::from_secs(10));
    }
}

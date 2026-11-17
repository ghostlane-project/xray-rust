// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Go's `net/url` as far as the carrier leans on it: `url.Parse` of a room
//! link and of a join URL, `URL.Query` with `Values.Set`, and `URL.String`.
//!
//! The Go engine reads a link's path after `url.Parse` has undone its
//! escapes, and rebuilds the join URL through `URL.String`, so which links
//! name a room and which bytes the join goes out with are that package's
//! rules. They are copied here, not replaced by a general URL crate, and
//! held to the vectors `mtslink/parse_event_link.json` and
//! `mtslink/offer_url.json`.
//!
//! Only an absolute URL with a host is a URL here: the callers refuse
//! everything else. One known gap: an IPv6 zone (`[fe80::1%25eth0]`) is
//! held to the host's bytes, where Go lets a zone hold more.

/// The part of a URL an escape rule belongs to (`net/url`'s `encoding`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Host,
    UserPassword,
    Path,
    Query,
    Fragment,
}

/// An absolute URL, its parts as written.
pub(crate) struct Url<'a> {
    /// The scheme, lower-cased as Go does.
    pub scheme: String,
    /// What stands before the host's `@`.
    userinfo: Option<&'a str>,
    /// The host with its port, never empty.
    pub host: &'a str,
    /// The path: empty, or from its first `/`.
    path: &'a str,
    /// What follows the `?`.
    query: Option<&'a str>,
    /// What follows the `#`.
    fragment: &'a str,
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `shouldEscape`: whether `b` is written as `%XX` in `part`.
const fn should_escape(b: u8, part: Part) -> bool {
    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
        return false;
    }
    let reserved = matches!(
        b,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@'
    );
    match part {
        Part::Host => !matches!(
            b,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        ),
        Part::UserPassword => !reserved || matches!(b, b'@' | b'/' | b'?' | b':'),
        Part::Path => !reserved || b == b'?',
        Part::Query => true,
        Part::Fragment => !reserved && !matches!(b, b'!' | b'(' | b')' | b'*'),
    }
}

/// `unescape`: `s` with its `%XX` undone (and `+` as a space in a query);
/// none for a broken escape, or for a byte a host cannot hold.
fn unescape(s: &[u8], part: Part) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                let hi = hex_digit(*s.get(i + 1)?)?;
                let lo = hex_digit(*s.get(i + 2)?)?;
                // A host escapes only bytes that are not ASCII, and `%25`.
                if part == Part::Host && hi < 8 && (hi, lo) != (2, 5) {
                    return None;
                }
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' if part == Part::Query => {
                out.push(b' ');
                i += 1;
            }
            b => {
                if part == Part::Host && b < 0x80 && should_escape(b, Part::Host) {
                    return None;
                }
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// `escape` for every part but a query (whose space is a `+`:
/// `olc_net::form`).
fn escape(s: &[u8], part: Part) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s {
        if should_escape(b, part) {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

/// `validEncoded`: whether `s` can stand in a URL as it is written.
fn valid_encoded(s: &str, part: Part) -> bool {
    s.bytes().all(|b| {
        matches!(
            b,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'['
                | b']'
                | b'%'
        ) || !should_escape(b, part)
    })
}

/// `EscapedPath` / `EscapedFragment`: `raw` as written when that is a
/// valid spelling, else its bytes escaped anew.
fn respelled(raw: &str, part: Part) -> String {
    if valid_encoded(raw, part) {
        return raw.to_owned();
    }
    // `parse` checked the escapes.
    escape(&unescape(raw.as_bytes(), part).unwrap_or_default(), part)
}

/// `getScheme`: the lower-cased scheme and what follows its colon.
fn scheme_of(s: &str) -> Option<(String, &str)> {
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i > 0 => return Some((s[..i].to_ascii_lowercase(), &s[i + 1..])),
            _ => return None,
        }
    }
    None
}

/// `validOptionalPort`: nothing, or a colon and digits.
fn valid_port(s: &str) -> bool {
    s.is_empty()
        || s.strip_prefix(':')
            .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
}

/// `parseHost`'s checks.
fn valid_host(host: &str) -> bool {
    let port = if host.starts_with('[') {
        match host.rfind(']') {
            Some(i) => &host[i + 1..],
            None => return false,
        }
    } else {
        host.rfind(':').map_or("", |i| &host[i..])
    };
    valid_port(port) && unescape(host.as_bytes(), Part::Host).is_some()
}

/// `validUserinfo` and the escapes of its two halves.
fn valid_userinfo(s: &str) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    }) && unescape(s.as_bytes(), Part::UserPassword).is_some()
}

impl<'a> Url<'a> {
    /// `url.Parse`, for a URL with a scheme and a host; none for any other
    /// and for one Go refuses.
    pub(crate) fn parse(raw: &'a str) -> Option<Self> {
        // Go cuts the fragment off first and looks for control bytes in
        // what is left (`url.Parse`, `stringContainsCTLByte`).
        let (rest, fragment) = raw.split_once('#').unwrap_or((raw, ""));
        if rest.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return None;
        }
        unescape(fragment.as_bytes(), Part::Fragment)?;
        let (scheme, rest) = scheme_of(rest)?;
        let (rest, query) = if rest.ends_with('?') && rest.matches('?').count() == 1 {
            (&rest[..rest.len() - 1], Some(""))
        } else {
            match rest.split_once('?') {
                Some((rest, query)) => (rest, Some(query)),
                None => (rest, None),
            }
        };
        // Without the two slashes Go reads an opaque URL or a path alone:
        // neither has a host.
        let rest = rest.strip_prefix("//")?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (userinfo, host) = match authority.rfind('@') {
            Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
            None => (None, authority),
        };
        if host.is_empty() || !valid_host(host) || !userinfo.is_none_or(valid_userinfo) {
            return None;
        }
        unescape(path.as_bytes(), Part::Path)?;
        Some(Self {
            scheme,
            userinfo,
            host,
            path,
            query,
            fragment,
        })
    }

    /// `URL.Path`: the path with its escapes undone.
    pub(crate) fn path(&self) -> Vec<u8> {
        // `parse` checked the escapes.
        unescape(self.path.as_bytes(), Part::Path).unwrap_or_default()
    }

    /// Whether the URL names a user before its host.
    pub(crate) const fn has_userinfo(&self) -> bool {
        self.userinfo.is_some()
    }

    /// `URL.Query`: the pairs of the query in their order, escapes undone.
    /// A pair with a semicolon or a broken escape is left out, as
    /// `ParseQuery` leaves it out and `Query` drops the error.
    pub(crate) fn query(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut pairs = Vec::new();
        for pair in self.query.unwrap_or("").split('&') {
            if pair.is_empty() || pair.contains(';') {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let (Some(key), Some(value)) = (
                unescape(key.as_bytes(), Part::Query),
                unescape(value.as_bytes(), Part::Query),
            ) else {
                continue;
            };
            pairs.push((key, value));
        }
        pairs
    }

    /// The scheme, the host and the path: what a request to this URL is
    /// sent to, less its query.
    pub(crate) fn origin_and_path(&self) -> String {
        let mut out =
            String::with_capacity(self.scheme.len() + self.host.len() + self.path.len() + 4);
        out.push_str(&self.scheme);
        out.push_str("://");
        out.push_str(self.host);
        if self.path.is_empty() {
            out.push('/');
        } else {
            out.push_str(&respelled(self.path, Part::Path));
        }
        out
    }

    /// The path as written, its escapes kept: empty, or from its first
    /// `/`.
    pub(crate) const fn raw_path(&self) -> &'a str {
        self.path
    }

    /// The raw query, empty for none.
    pub(crate) fn raw_query(&self) -> &'a str {
        self.query.unwrap_or("")
    }

    /// `URL.String` with `RawQuery` set to `query`.
    pub(crate) fn string_with_query(&self, query: &str) -> String {
        let mut out = String::with_capacity(
            self.scheme.len() + self.host.len() + self.path.len() + query.len() + 8,
        );
        out.push_str(&self.scheme);
        out.push_str("://");
        if let Some(userinfo) = self.userinfo {
            let (user, password) = match userinfo.split_once(':') {
                Some((user, password)) => (user, Some(password)),
                None => (userinfo, None),
            };
            out.push_str(&respelled_userinfo(user));
            if let Some(password) = password {
                out.push(':');
                out.push_str(&respelled_userinfo(password));
            }
            out.push('@');
        }
        if self.host.is_ascii() && !self.host.contains('%') {
            out.push_str(self.host);
        } else {
            let host = unescape(self.host.as_bytes(), Part::Host).unwrap_or_default();
            out.push_str(&escape(&host, Part::Host));
        }
        out.push_str(&respelled(self.path, Part::Path));
        if self.query.is_some() || !query.is_empty() {
            out.push('?');
            out.push_str(query);
        }
        if !self.fragment.is_empty() {
            out.push('#');
            out.push_str(&respelled(self.fragment, Part::Fragment));
        }
        out
    }
}

/// `Userinfo.String` for one half: always escaped anew.
fn respelled_userinfo(raw: &str) -> String {
    escape(
        &unescape(raw.as_bytes(), Part::UserPassword).unwrap_or_default(),
        Part::UserPassword,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(raw: &str) -> Option<(String, String, String)> {
        Url::parse(raw).map(|u| {
            (
                u.scheme.clone(),
                u.host.to_owned(),
                String::from_utf8_lossy(&u.path()).into_owned(),
            )
        })
    }

    #[test]
    fn a_url_needs_a_scheme_and_a_host() {
        assert_eq!(
            parts("HTTPS://Host.Example:8443/a%20b/%6A?x#y"),
            Some((
                "https".to_owned(),
                "Host.Example:8443".to_owned(),
                "/a b/j".to_owned()
            ))
        );
        for bad in [
            "",
            "host/path",
            "//host/path",
            "/path",
            "https:///path",
            "https:host",
            "://nothing",
            "1https://host/",
            "https://ho st/",
            "https://host:port/",
            "https://[::1/",
            "https://host/%zz",
            "https://host/a\tb",
            "https://host/\u{7f}",
            "https://us er@host/",
            "https://ho%41st/",
        ] {
            assert!(parts(bad).is_none(), "{bad:?} was taken");
        }
        // A host may hold what Go lets it hold.
        for good in [
            "https://[::1]:443/",
            "https://user:pw@host/",
            "https://:443/",
            "a+b-c.d://h",
        ] {
            assert!(parts(good).is_some(), "{good:?} was refused");
        }
    }

    /// Go's `url.Parse` cuts the fragment off before it looks for control
    /// bytes, so one in the fragment is no refusal; before the `#` it is.
    #[test]
    fn a_control_byte_is_refused_only_before_the_fragment() {
        for good in ["https://host/p#\u{7f}", "https://host/p?x=1#a\tb"] {
            assert_eq!(
                parts(good),
                Some(("https".to_owned(), "host".to_owned(), "/p".to_owned())),
                "{good:?}"
            );
        }
        for bad in ["https://host/p\u{1}#f", "https://host/p?x=\u{7f}#f"] {
            assert!(parts(bad).is_none(), "{bad:?} was taken");
        }
    }

    #[test]
    fn a_query_is_read_as_gos_parse_query_reads_it() {
        let u = Url::parse("https://h/p?a=1&&b&c=%zz&d=1;e=2&f=x+y%20z&a=2").unwrap();
        let got: Vec<(String, String)> = u
            .query()
            .into_iter()
            .map(|(k, v)| (String::from_utf8(k).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        let want = [("a", "1"), ("b", ""), ("f", "x y z"), ("a", "2")];
        assert_eq!(
            got.iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            want
        );
    }

    #[test]
    fn a_url_is_written_back_as_go_writes_it() {
        for (raw, query, want) in [
            ("https://h/p?old=1#f", "q=1", "https://h/p?q=1#f"),
            ("https://h?old", "q=1", "https://h?q=1"),
            ("https://h/p?", "", "https://h/p?"),
            ("https://h/p", "", "https://h/p"),
            // A path that cannot stand as written is escaped anew, and
            // then all of it is.
            ("https://h/a b/(c)", "q", "https://h/a%20b/%28c%29?q"),
            ("https://h/a%20b/(c)", "q", "https://h/a%20b/(c)?q"),
            ("https://u:p@h/", "q", "https://u:p@h/?q"),
            ("https://u%41!:@h/", "q", "https://uA%21:@h/?q"),
            ("https://h\u{e9}/", "q", "https://h%C3%A9/?q"),
            ("https://h/p#a b", "q", "https://h/p?q#a%20b"),
        ] {
            let u = Url::parse(raw).unwrap();
            assert_eq!(u.string_with_query(query), want, "{raw:?}");
        }
        let u = Url::parse("HTTP://h:8080?x=1#f").unwrap();
        assert_eq!(u.origin_and_path(), "http://h:8080/");
        assert_eq!(u.raw_query(), "x=1");
        assert!(!u.has_userinfo());
    }
}

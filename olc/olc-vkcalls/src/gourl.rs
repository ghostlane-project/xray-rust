// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Go's `url.Parse` as far as the provider leans on it
//! (`internal/auth/vkcalls`): which room links name a call, and which
//! endpoints of a join answer are VK's, are that package's rules. The
//! provider reads a URL's scheme, whether it names a user, its host and its
//! path with their escapes undone, its raw query and its fragment.
//!
//! The rules are copied, not replaced by a general URL crate, and held to
//! `vkcalls/url_auth.json`. One known gap: a host in brackets is held to a
//! host's bytes all through, where Go lets an IPv6 zone hold more and
//! checks the address; no caller here accepts a host in brackets, so the
//! gap can only change which refusal is told.
//!
//! Nothing here keeps or prints a URL.

/// The part of a URL an escape rule belongs to (`net/url`'s `encoding`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Host,
    UserPassword,
    Path,
    Query,
    Fragment,
}

/// A URL as `url.Parse` splits it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Url<'a> {
    /// `Scheme`, lower-cased.
    pub scheme: String,
    /// Whether `User` is set: an `@` in the authority, even with nothing
    /// before it.
    pub user: bool,
    /// `Host`: the host and its port, escapes undone.
    pub host: Vec<u8>,
    /// `Path`, escapes undone.
    pub path: Vec<u8>,
    /// `RawQuery`.
    pub raw_query: &'a str,
    /// `Fragment`, escapes undone.
    pub fragment: Vec<u8>,
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `shouldEscape(b, encodeHost)`: the ASCII bytes a host cannot hold.
const fn host_refuses(b: u8) -> bool {
    !(b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_'
                | b'.'
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
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        ))
}

/// `unescape`: `s` with its `%XX` undone (and `+` as a space in a query);
/// none for a broken escape, or for a byte a host cannot hold.
fn unescape(s: &str, part: Part) -> Option<Vec<u8>> {
    let s = s.as_bytes();
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
                if part == Part::Host && b < 0x80 && host_refuses(b) {
                    return None;
                }
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// `getScheme`: the scheme as written and what follows its colon. Text
/// with no such start has no scheme and is all rest; a colon in front is
/// the one text refused ("missing protocol scheme").
fn split_scheme(text: &str) -> Option<(&str, &str)> {
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i > 0 => return Some((&text[..i], &text[i + 1..])),
            b':' => return None,
            _ => break,
        }
    }
    Some(("", text))
}

/// `validOptionalPort`: nothing, or a colon and digits.
fn valid_port(s: &str) -> bool {
    s.is_empty()
        || s.strip_prefix(':')
            .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()))
}

/// `parseHost`.
fn parse_host(host: &str) -> Option<Vec<u8>> {
    let port = if host.starts_with('[') {
        &host[host.rfind(']')? + 1..]
    } else {
        host.rfind(':').map_or("", |i| &host[i..])
    };
    if !valid_port(port) {
        return None;
    }
    unescape(host, Part::Host)
}

/// `validUserinfo`, and the escapes of the name and the password.
fn valid_userinfo(s: &str) -> bool {
    let allowed = s.bytes().all(|b| {
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
    });
    let (name, password) = s.split_once(':').unwrap_or((s, ""));
    allowed
        && unescape(name, Part::UserPassword).is_some()
        && unescape(password, Part::UserPassword).is_some()
}

/// `url.Parse`; none where Go returns an error.
pub(crate) fn parse(raw: &str) -> Option<Url<'_>> {
    let (text, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    // The fragment is not looked at for control bytes.
    if text.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let mut url = Url::default();
    if text == "*" {
        url.path = b"*".to_vec();
    } else {
        let (scheme, rest) = split_scheme(text)?;
        url.scheme = scheme.to_ascii_lowercase();
        let (rest, raw_query) = if rest.ends_with('?') && rest.matches('?').count() == 1 {
            (&rest[..rest.len() - 1], "")
        } else {
            rest.split_once('?').unwrap_or((rest, ""))
        };
        url.raw_query = raw_query;
        // With a scheme and no slash behind it the rest is opaque: no
        // host, no path.
        if rest.starts_with('/') || scheme.is_empty() {
            // No scheme, and a colon before the first slash: "first path
            // segment in URL cannot contain colon".
            if !rest.starts_with('/')
                && rest
                    .split('/')
                    .next()
                    .is_some_and(|first| first.contains(':'))
            {
                return None;
            }
            let mut path = rest;
            if let Some(authority) = rest
                .strip_prefix("//")
                .filter(|_| !scheme.is_empty() || !rest.starts_with("///"))
            {
                let (authority, behind) =
                    authority.split_at(authority.find('/').unwrap_or(authority.len()));
                let host = match authority.rfind('@') {
                    Some(i) => {
                        if !valid_userinfo(&authority[..i]) {
                            return None;
                        }
                        url.user = true;
                        &authority[i + 1..]
                    }
                    None => authority,
                };
                url.host = parse_host(host)?;
                path = behind;
            }
            url.path = unescape(path, Part::Path)?;
        }
    }
    url.fragment = unescape(fragment, Part::Fragment)?;
    Some(url)
}

/// `URL.Query().Get(key)`: the first value `key` has in `raw_query`, empty
/// when it has none. A pair with a semicolon or a broken escape is left
/// out, as `ParseQuery` leaves it out and `Query` drops the error.
pub(crate) fn query_get(raw_query: &str, key: &str) -> Vec<u8> {
    for pair in raw_query.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(name), Some(value)) = (unescape(name, Part::Query), unescape(value, Part::Query))
        else {
            continue;
        };
        if name == key.as_bytes() {
            return value;
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(raw: &str) -> Option<(String, bool, String, String, String, String)> {
        let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
        parse(raw).map(|url| {
            (
                url.scheme,
                url.user,
                text(url.host),
                text(url.path),
                url.raw_query.to_owned(),
                text(url.fragment),
            )
        })
    }

    fn url(
        scheme: &str,
        user: bool,
        host: &str,
        path: &str,
        query: &str,
        fragment: &str,
    ) -> Option<(String, bool, String, String, String, String)> {
        Some((
            scheme.to_owned(),
            user,
            host.to_owned(),
            path.to_owned(),
            query.to_owned(),
            fragment.to_owned(),
        ))
    }

    /// Worked out from `net/url` (`url.go`: `Parse`, `parse`, `getScheme`,
    /// `parseAuthority`, `parseHost`, `unescape`); the provider's vectors
    /// hold the same through `canonical_link` and the join's endpoint.
    #[test]
    fn a_url_splits_as_go_splits_it() {
        assert_eq!(
            parts("HTTPS://u:p@Vk.ru:8443/a%41b/c%2Fd?x=1&y#fr%41g"),
            url("https", true, "Vk.ru:8443", "/aAb/c/d", "x=1&y", "frAg")
        );
        assert_eq!(
            parts("wss://a.okcdn.ru/ws2?"),
            url("wss", false, "a.okcdn.ru", "/ws2", "", "")
        );
        // A question mark that is not the only one opens the query.
        assert_eq!(parts("wss://h/p??"), url("wss", false, "h", "/p", "?", ""));
        // An `@` with nothing before it is a user all the same.
        assert_eq!(parts("https://@h/"), url("https", true, "h", "/", "", ""));
        // The last `@` ends the userinfo.
        assert_eq!(parts("https://a@b@h"), url("https", true, "h", "", "", ""));
        // No scheme: a path alone, or a host behind two slashes.
        assert_eq!(
            parts("vk.ru/call"),
            url("", false, "", "vk.ru/call", "", "")
        );
        assert_eq!(parts("//h/p"), url("", false, "h", "/p", "", ""));
        assert_eq!(parts("///p"), url("", false, "", "///p", "", ""));
        assert_eq!(parts(""), url("", false, "", "", "", ""));
        assert_eq!(parts("*"), url("", false, "", "*", "", ""));
        // A digit first is no scheme, so the colon is in a first segment.
        assert_eq!(parts("1a:b"), None);
        assert_eq!(parts("a/b:c"), url("", false, "", "a/b:c", "", ""));
        // A scheme and no slash: opaque, no host and no path.
        assert_eq!(
            parts("https:vk.ru/x?q"),
            url("https", false, "", "", "q", "")
        );
        // An empty authority.
        assert_eq!(parts("https:///p"), url("https", false, "", "/p", "", ""));
        // A host escapes only what is not ASCII.
        assert_eq!(
            parts("https://h%C3%A9/"),
            url("https", false, "h\u{e9}", "/", "", "")
        );
        assert_eq!(
            parts("https://[::1]:443/"),
            url("https", false, "[::1]:443", "/", "", "")
        );

        for refused in [
            ":x",
            "https://h/%zz",
            "https://h/%4",
            "https://h/p#%zz",
            "https://h:port/",
            "https://h:80:x/",
            "https://[::1/",
            "https://[::1]x/",
            "https://vk%2Eru/",
            "https://h h/",
            "https://h\\h/",
            "https://u ser@h/",
            "https://u%zz@h/",
            "https://h/\x7f",
            "https://h/\n",
        ] {
            assert_eq!(parts(refused), None, "{refused:?}");
        }
        // A control byte behind the `#` is not looked at.
        assert_eq!(
            parts("https://h/#\x7f"),
            url("https", false, "h", "/", "", "\x7f")
        );
    }

    #[test]
    fn a_query_gives_the_first_value_of_a_key() {
        let get =
            |query: &str, key: &str| String::from_utf8_lossy(&query_get(query, key)).into_owned();
        assert_eq!(get("token=a&token=b", "token"), "a");
        assert_eq!(get("a=1&peerId=4+6%2F", "peerId"), "4 6/");
        assert_eq!(get("t%6Fken=x", "token"), "x");
        assert_eq!(get("token", "token"), "");
        assert_eq!(get("", "token"), "");
        // Left out: a pair with a semicolon, a pair with a broken escape.
        assert_eq!(get("token=a;b&token=c", "token"), "c");
        assert_eq!(get("token=%zz&token=d", "token"), "d");
        assert_eq!(get("x=1&&=2", "token"), "");
    }
}

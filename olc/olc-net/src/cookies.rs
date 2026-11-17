// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The cookies of one reply, as a Go room provider keeps them
//! (`internal/auth/mtslink/api.go:175-180`): `name=value` of every
//! `Set-Cookie` that Go's `http.Response.Cookies` reads and whose value is
//! not empty, in header order. There is no jar: a provider keeps the pairs
//! of the reply it wants and sends them back as one `Cookie` header
//! ([`header`], `api.go:235`).
//!
//! Go's reading (`net/http`, `ParseSetCookie`), held to its results by
//! `interop/vectors/2d4266af/net/cookies.json`:
//!
//! - the line and its first `;`-part are trimmed of spaces, tabs, CR and LF;
//!   everything after the first `;` (the attributes) is dropped unread;
//! - the part is cut at its first `=`; without one the cookie is skipped;
//! - the name, trimmed, must be an HTTP token;
//! - a value in a pair of double quotes loses them; what is left must be
//!   printable ASCII without `"`, `;` and `\`, else the cookie is skipped;
//! - a reply with more than [`MAX_SET_COOKIE_LINES`] `Set-Cookie` lines
//!   gives no cookie at all.

/// Go's `httpcookiemaxnum`: past this many `Set-Cookie` lines, read or not,
/// a reply's cookies are all dropped.
pub const MAX_SET_COOKIE_LINES: usize = 3000;

/// `textproto.TrimString`'s set.
fn trim(s: &str) -> &str {
    s.trim_matches([' ', '\t', '\n', '\r'])
}

/// An HTTP token character (`httpguts.IsTokenRune`).
const fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// `validCookieValueByte`.
const fn value_byte(b: u8) -> bool {
    0x20 <= b && b < 0x7f && b != b'"' && b != b';' && b != b'\\'
}

/// One `Set-Cookie` value's name and value, when Go reads it and the value
/// is not empty.
fn pair(line: &str) -> Option<(&str, &str)> {
    let first = trim(trim(line).split(';').next()?);
    let (name, value) = first.split_once('=')?;
    let name = trim(name);
    if name.is_empty() || !name.bytes().all(token) {
        return None;
    }
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    if value.is_empty() || !value.bytes().all(value_byte) {
        return None;
    }
    Some((name, value))
}

/// The cookies a provider keeps from a reply's `headers` (as
/// [`crate::http::HttpResponse::headers`] holds them): one `name=value` per
/// `Set-Cookie` Go reads with a value, in header order, duplicates kept.
///
/// What comes back is no larger than the reply's head, which the HTTP
/// client bounds (16 KiB over HTTP/1.1, 256 KiB over h2).
#[must_use]
pub fn from_set_cookie(headers: &[(String, String)]) -> Vec<String> {
    let lines = || {
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value.as_str())
    };
    if lines().count() > MAX_SET_COOKIE_LINES {
        return Vec::new();
    }
    lines()
        .filter_map(pair)
        .map(|(name, value)| format!("{name}={value}"))
        .collect()
}

/// The `Cookie` header's value for `pairs`: joined with `"; "`.
#[must_use]
pub fn header(pairs: &[String]) -> String {
    pairs.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(lines: &[&str]) -> Vec<String> {
        let headers: Vec<(String, String)> = lines
            .iter()
            .map(|l| ("Set-Cookie".to_string(), (*l).to_string()))
            .collect();
        from_set_cookie(&headers)
    }

    #[test]
    fn a_logins_cookies_become_one_header() {
        let got = kept(&[
            "sessionId=s-1; Path=/; HttpOnly",
            "empty=",
            "userId=\"42\"; Path=/",
            "bad name=1",
            "route=b; Secure; SameSite=None",
        ]);
        assert_eq!(got, ["sessionId=s-1", "userId=42", "route=b"]);
        assert_eq!(header(&got), "sessionId=s-1; userId=42; route=b");
        assert_eq!(header(&[]), "");
    }

    #[test]
    fn other_headers_are_not_cookies() {
        let headers = [
            ("Cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
            ("Set-Cookie2".to_string(), "c=3".to_string()),
        ];
        assert_eq!(from_set_cookie(&headers), ["b=2"]);
    }
}

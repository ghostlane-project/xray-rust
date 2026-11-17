// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A form body as Go writes it (`url.Values.Encode`): what the carriers'
//! room providers POST (`internal/auth/mtslink/api.go:144-146`,
//! `internal/auth/vkcalls/vkcalls.go:341-345`).
//!
//! Fields go out sorted by key, the keys compared as bytes before they are
//! escaped; a key's values keep the order they were given in. Keys and
//! values are escaped as `url.QueryEscape` does: `A-Z a-z 0-9 - _ . ~` stay,
//! a space is `+`, every other byte is `%XX` in upper-case hex. The
//! `form_urlencoded` crate differs on `*` and `~`, so this is written out
//! and held to Go's bytes by `interop/vectors/2d4266af/net/forms.json`.

/// Whether `url.QueryEscape` leaves `b` as it is.
const fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// The length of `s` once escaped.
fn escaped_len(s: &[u8]) -> usize {
    s.iter()
        .map(|&b| if unreserved(b) || b == b' ' { 1 } else { 3 })
        .sum()
}

fn escape_into(out: &mut String, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in s {
        if unreserved(b) {
            out.push(char::from(b));
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
}

/// `s` as Go's `url.QueryEscape` writes it.
#[must_use]
pub fn query_escape(s: impl AsRef<[u8]>) -> String {
    let s = s.as_ref();
    let mut out = String::with_capacity(escaped_len(s));
    escape_into(&mut out, s);
    out
}

/// The fields as an `application/x-www-form-urlencoded` body, byte for byte
/// Go's `url.Values.Encode` of the same fields added in this order.
///
/// The body is built once, at its final size; nothing else is allocated but
/// one index per field for the sort.
#[must_use]
pub fn encode<K: AsRef<[u8]>, V: AsRef<[u8]>>(pairs: &[(K, V)]) -> String {
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    // Stable: a repeated key keeps its values in the caller's order.
    order.sort_by(|&a, &b| pairs[a].0.as_ref().cmp(pairs[b].0.as_ref()));
    let len: usize = pairs
        .iter()
        .map(|(k, v)| escaped_len(k.as_ref()) + escaped_len(v.as_ref()) + 2)
        .sum();
    let mut out = String::with_capacity(len.saturating_sub(1));
    for i in order {
        if !out.is_empty() {
            out.push('&');
        }
        escape_into(&mut out, pairs[i].0.as_ref());
        out.push('=');
        escape_into(&mut out, pairs[i].1.as_ref());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_is_sorted_and_escaped() {
        assert_eq!(
            encode(&[
                ("nickname", "a+b &c=d~*"),
                ("name", ""),
                ("secondName", ""),
                ("phone", "")
            ]),
            "name=&nickname=a%2Bb+%26c%3Dd~%2A&phone=&secondName="
        );
        assert_eq!(encode::<&str, &str>(&[]), "");
        assert_eq!(
            query_escape("Иван Петров"),
            "%D0%98%D0%B2%D0%B0%D0%BD+%D0%9F%D0%B5%D1%82%D1%80%D0%BE%D0%B2"
        );
    }

    #[test]
    fn the_body_is_allocated_once() {
        let pairs = [("b", "x y"), ("a", "~/"), ("", "")];
        let body = encode(&pairs);
        assert_eq!(body, "=&a=~%2F&b=x+y");
        assert_eq!(body.capacity(), body.len());
    }
}

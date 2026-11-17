//! The parts of Go's `encoding/json` encoder the wire messages need, byte for
//! byte: strings as `json.Marshal` writes them, and integers.
//!
//! Go's encoder escapes HTML (`<`, `>`, `&` as `\u003c`, `\u003e`,
//! `\u0026`), writes `\b \f \n \r \t` in their short forms and every other
//! byte below 0x20 as `\u00xx` (lowercase hex), passes DEL (0x7f) and valid
//! non-ASCII as they are except U+2028 and U+2029 (`\u2028`, `\u2029`), and
//! replaces each byte that does not start a valid UTF-8 sequence with
//! `\ufffd`, one per byte (`appendString` in Go 1.26's
//! `encoding/json/encode.go`). Rust's `serde_json` does none of the HTML or
//! separator escapes and refuses invalid UTF-8, so its output would differ
//! from the Go server's input expectations only in harmless ways, but would
//! differ from the vectors; this module is what makes the hello and the
//! CONNECT request the Go client's bytes exactly.

use std::io::Write as _;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` as a JSON string, quotes included, as Go's `json.Marshal`
/// writes a `string` holding these bytes.
pub fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    out.reserve(s.len() + 2);
    out.push(b'"');
    let mut rest = s;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                write_valid(out, valid);
                break;
            }
            Err(e) => {
                let (valid, bad) = rest.split_at(e.valid_up_to());
                write_valid(out, std::str::from_utf8(valid).expect("checked"));
                // Go decodes one rune at a time and an invalid one is one
                // byte wide: every byte of a broken sequence is a U+FFFD.
                out.extend_from_slice(b"\\ufffd");
                rest = &bad[1..];
            }
        }
    }
    out.push(b'"');
}

fn write_valid(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let escape: Option<&[u8]> = match b {
            b'"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            0x08 => Some(b"\\b"),
            0x0c => Some(b"\\f"),
            b'\n' => Some(b"\\n"),
            b'\r' => Some(b"\\r"),
            b'\t' => Some(b"\\t"),
            // U+2028 and U+2029 are E2 80 A8 and E2 80 A9.
            0xe2 if bytes.get(i + 1) == Some(&0x80)
                && matches!(bytes.get(i + 2), Some(0xa8 | 0xa9)) =>
            {
                out.extend_from_slice(&bytes[start..i]);
                out.extend_from_slice(if bytes[i + 2] == 0xa8 {
                    b"\\u2028"
                } else {
                    b"\\u2029"
                });
                i += 3;
                start = i;
                continue;
            }
            b'<' | b'>' | b'&' | 0x00..=0x1f => {
                out.extend_from_slice(&bytes[start..i]);
                out.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 0x0f)],
                ]);
                i += 1;
                start = i;
                continue;
            }
            _ => None,
        };
        if let Some(escape) = escape {
            out.extend_from_slice(&bytes[start..i]);
            out.extend_from_slice(escape);
            start = i + 1;
        }
        i += 1;
    }
    out.extend_from_slice(&bytes[start..]);
}

/// Appends an unsigned integer as Go writes it.
pub fn write_u64(out: &mut Vec<u8>, n: u64) {
    write!(out, "{n}").expect("writing to a Vec cannot fail");
}

/// Appends a signed integer as Go writes it.
pub fn write_i64(out: &mut Vec<u8>, n: i64) {
    write!(out, "{n}").expect("writing to a Vec cannot fail");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted(s: &[u8]) -> String {
        let mut out = Vec::new();
        write_string(&mut out, s);
        String::from_utf8(out).expect("the output is UTF-8")
    }

    #[test]
    fn escapes_as_go_does() {
        assert_eq!(quoted(b""), r#""""#);
        assert_eq!(quoted(br#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quoted(b"<a&b>"), r#""\u003ca\u0026b\u003e""#);
        assert_eq!(quoted(b"\x08\x0c\n\r\t"), r#""\b\f\n\r\t""#);
        assert_eq!(quoted(b"\x00\x01\x1f\x7f"), "\"\\u0000\\u0001\\u001f\x7f\"");
        assert_eq!(
            quoted("x\u{2028}y\u{2029}z".as_bytes()),
            r#""x\u2028y\u2029z""#
        );
        assert_eq!(quoted("é🙂\u{fffd}".as_bytes()), "\"é🙂\u{fffd}\"");
    }

    #[test]
    fn each_invalid_byte_is_one_replacement() {
        // A truncated three-byte sequence is two bytes, so two U+FFFD; Rust's
        // own lossy decoding would make it one.
        assert_eq!(quoted(b"a\xe2\x82b"), r#""a\ufffd\ufffdb""#);
        // An encoded surrogate is three invalid bytes.
        assert_eq!(quoted(b"\xed\xa0\x80"), r#""\ufffd\ufffd\ufffd""#);
        assert_eq!(quoted(b"\xff"), r#""\ufffd""#);
        assert_eq!(quoted(b"\xf0\x9f\x98"), r#""\ufffd\ufffd\ufffd""#);
    }
}

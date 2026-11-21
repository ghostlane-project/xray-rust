// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What crosses the bridge: `OLR1` data frames with their epoch header, `OLW1`
//! relay-window frames, and the JSON the bridge's data channel carries them
//! in (`internal/engine/jitsi/epoch.go`, `relaywindow.go`, `bridge.go`).

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use serde_json::Value;

/// A data frame starts with this (`bridgeMagic`).
pub const MAGIC: [u8; 4] = *b"OLR1";
/// The most a bridge message may hold: JVB's practical limit
/// (`bridgeMaxMessageSize`).
pub const MAX_MESSAGE: usize = 16 * 1024;
/// Sender epoch and receiver epoch.
pub const EPOCH_HEADER: usize = 8;
/// The class of the bridge's data messages.
pub const CLASS_ENDPOINT_MESSAGE: &str = "EndpointMessage";
/// The class of the bridge's answer to the hello.
pub const SERVER_HELLO_CLASS: &str = "ServerHello";
/// What the client says first on the channel.
pub const CLIENT_HELLO: &str = r#"{"colibriClass":"ClientHello"}"#;

/// A relay-window frame starts with this (`bridgeWindowMagic`).
pub const WINDOW_MAGIC: [u8; 4] = *b"OLW1";
/// Magic, kind, sender epoch, receiver epoch, counter.
pub const WINDOW_FRAME_LEN: usize = 4 + 1 + 4 + 4 + 8;

/// Why a frame was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The frame would pass [`MAX_MESSAGE`] (`ErrSendTooLarge`).
    #[error("send too large")]
    SendTooLarge,
}

/// `data` as a data frame from epoch `local` to epoch `peer`
/// (`encodeBridgeFrame`).
///
/// # Errors
/// [`FrameError::SendTooLarge`].
pub fn encode_frame(data: &[u8], local: u32, peer: u32) -> Result<Vec<u8>, FrameError> {
    if data.len() + MAGIC.len() + EPOCH_HEADER > MAX_MESSAGE {
        return Err(FrameError::SendTooLarge);
    }
    let mut f = Vec::with_capacity(MAGIC.len() + EPOCH_HEADER + data.len());
    f.extend_from_slice(&MAGIC);
    f.extend_from_slice(&local.to_be_bytes());
    f.extend_from_slice(&peer.to_be_bytes());
    f.extend_from_slice(data);
    Ok(f)
}

/// What a relay-window frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    /// How many bytes the sender has handed the bridge for the receiver.
    Mark,
    /// The receiver's answer to a mark.
    Echo,
    /// Parsed, and ignored by everyone.
    Other(u8),
}

/// A mark or an echo (`windowFrame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowFrame {
    /// Which.
    pub kind: WindowKind,
    /// The sender's epoch.
    pub sender_epoch: u32,
    /// The epoch it is for.
    pub receiver_epoch: u32,
    /// The sender's byte count at the mark, which an echo returns.
    pub counter: u64,
}

impl WindowFrame {
    /// The 21 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; WINDOW_FRAME_LEN] {
        let mut b = [0u8; WINDOW_FRAME_LEN];
        b[..4].copy_from_slice(&WINDOW_MAGIC);
        b[4] = match self.kind {
            WindowKind::Mark => 1,
            WindowKind::Echo => 2,
            WindowKind::Other(k) => k,
        };
        b[5..9].copy_from_slice(&self.sender_epoch.to_be_bytes());
        b[9..13].copy_from_slice(&self.receiver_epoch.to_be_bytes());
        b[13..].copy_from_slice(&self.counter.to_be_bytes());
        b
    }

    /// The frame `payload` is, if it is one (`parseWindowFrame`).
    #[must_use]
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() != WINDOW_FRAME_LEN || payload[..4] != WINDOW_MAGIC {
            return None;
        }
        Some(Self {
            kind: match payload[4] {
                1 => WindowKind::Mark,
                2 => WindowKind::Echo,
                k => WindowKind::Other(k),
            },
            sender_epoch: u32::from_be_bytes(payload[5..9].try_into().ok()?),
            receiver_epoch: u32::from_be_bytes(payload[9..13].try_into().ok()?),
            counter: u64::from_be_bytes(payload[13..].try_into().ok()?),
        })
    }
}

/// A bridge message as the library hands it up (`colibri.Message`).
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// `colibriClass`, empty when absent or not a string.
    pub class: String,
    /// `from`, likewise.
    pub from: String,
    /// `to`, likewise.
    pub to: String,
    fields: Value,
}

impl Message {
    /// The message `text` is; `None` for anything but a JSON object.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let fields: Value = serde_json::from_str(text).ok()?;
        let obj = fields.as_object()?;
        let s = |k: &str| obj.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        Some(Self {
            class: s("colibriClass"),
            from: s("from"),
            to: s("to"),
            fields,
        })
    }
}

/// Go's `base64.StdEncoding.DecodeString`: padding required, trailing bits
/// not checked, carriage returns and newlines skipped.
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    if s.contains(['\r', '\n']) {
        let clean: String = s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
        return ENGINE.decode(clean).ok();
    }
    ENGINE.decode(s).ok()
}

/// The bytes an `EndpointMessage` carries: `msgPayload.raw`, or the legacy
/// top-level `raw` (`decodeRaw`).
#[must_use]
pub fn decode_raw(m: &Message) -> Option<Vec<u8>> {
    if m.class != CLASS_ENDPOINT_MESSAGE {
        return None;
    }
    let raw = m
        .fields
        .get("msgPayload")
        .and_then(|p| p.get("raw"))
        .and_then(Value::as_str)
        .or_else(|| m.fields.get("raw").and_then(Value::as_str))?;
    decode_b64(raw)
}

/// A JSON string as Go's `encoding/json` writes it: `<`, `>`, `&`, U+2028
/// and U+2029 escaped too.
fn go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// The JSON that sends `data` to endpoint `to` (empty: everyone), the payload
/// under `msgPayload.raw`, the fields in the order JVB's Jackson wants them
/// (`newEndpointMessage`).
#[must_use]
pub fn endpoint_message(to: &str, data: &[u8]) -> String {
    format!(
        r#"{{"colibriClass":"EndpointMessage","to":{},"msgPayload":{{"raw":"{}"}}}}"#,
        go_json_string(to),
        b64(data)
    )
}

/// The library's own `SendRaw`: the payload in a top-level `raw`, the keys in
/// Go's map order. The bridge keepalive goes out in this shape.
#[must_use]
pub fn legacy_endpoint_message(to: &str, data: &[u8]) -> String {
    format!(
        r#"{{"colibriClass":"EndpointMessage","raw":"{}","to":{}}}"#,
        b64(data),
        go_json_string(to)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(class: &str, fields: serde_json::Value) -> Message {
        let mut m = serde_json::json!({ "colibriClass": class });
        m.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        Message::parse(&m.to_string()).unwrap()
    }

    fn b64(data: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// `TestDecodeRaw` (`jitsi_test.go:43`).
    #[test]
    fn decode_raw_reads_the_legacy_field() {
        let enc = b64(b"hello world");
        let m = message("EndpointMessage", serde_json::json!({ "raw": enc }));
        assert_eq!(decode_raw(&m).as_deref(), Some(&b"hello world"[..]));
        let other = message("OtherClass", serde_json::json!({ "raw": enc }));
        assert_eq!(decode_raw(&other), None);
        let none = message("EndpointMessage", serde_json::json!({}));
        assert_eq!(decode_raw(&none), None);
        let bad = message(
            "EndpointMessage",
            serde_json::json!({ "raw": "not-base64!!!" }),
        );
        assert_eq!(decode_raw(&bad), None);
    }

    /// `TestDecodeRawAcceptsMsgPayload` (`jitsi_test.go:67`).
    #[test]
    fn decode_raw_reads_msg_payload() {
        let enc = b64(b"hello msgPayload");
        let m = message(
            "EndpointMessage",
            serde_json::json!({ "msgPayload": { "raw": enc } }),
        );
        assert_eq!(decode_raw(&m).as_deref(), Some(&b"hello msgPayload"[..]));
        let no_raw = message(
            "EndpointMessage",
            serde_json::json!({ "msgPayload": { "other": "field" } }),
        );
        assert_eq!(decode_raw(&no_raw), None);
        // A payload without raw gives way to the top-level field.
        let both = message(
            "EndpointMessage",
            serde_json::json!({ "msgPayload": { "other": 1 }, "raw": enc }),
        );
        assert_eq!(decode_raw(&both).as_deref(), Some(&b"hello msgPayload"[..]));
        // A raw that is not a string is no raw.
        let num = message("EndpointMessage", serde_json::json!({ "raw": 5 }));
        assert_eq!(decode_raw(&num), None);
    }

    #[test]
    fn base64_is_gos_standard_encoding() {
        // Trailing bits are not checked, line ends are skipped.
        assert_eq!(decode_b64("YQ==").as_deref(), Some(&b"a"[..]));
        assert_eq!(decode_b64("YR==").as_deref(), Some(&b"a"[..]));
        assert_eq!(decode_b64("Y\r\nQ==").as_deref(), Some(&b"a"[..]));
        assert_eq!(decode_b64("YQ"), None, "padding is required");
        assert_eq!(decode_b64("YQ=="), decode_b64("YQ=="));
        assert_eq!(decode_b64("Y Q=="), None);
        assert_eq!(decode_b64(""), Some(Vec::new()));
    }

    #[test]
    fn a_message_is_its_class_sender_and_fields() {
        let m =
            Message::parse(r#"{"colibriClass":"EndpointMessage","from":"abc","to":"def","x":1}"#)
                .unwrap();
        assert_eq!(
            (m.class.as_str(), m.from.as_str(), m.to.as_str()),
            ("EndpointMessage", "abc", "def")
        );
        // A field of another type is an empty string, as Go's assertion gives.
        let m = Message::parse(r#"{"colibriClass":5,"from":null}"#).unwrap();
        assert_eq!((m.class.as_str(), m.from.as_str()), ("", ""));
        // Not an object: not a message.
        assert!(Message::parse("[1]").is_none());
        assert!(Message::parse("nope").is_none());
        assert!(Message::parse("").is_none());
    }

    /// `TestSendEndpointRawFieldOrderAndShape` (`jitsi_test.go:94`).
    #[test]
    fn the_endpoint_message_has_its_fields_in_the_bridges_order() {
        assert_eq!(
            endpoint_message("abc123", b"payload"),
            r#"{"colibriClass":"EndpointMessage","to":"abc123","msgPayload":{"raw":"cGF5bG9hZA=="}}"#
        );
        assert_eq!(
            endpoint_message("", b""),
            r#"{"colibriClass":"EndpointMessage","to":"","msgPayload":{"raw":""}}"#
        );
    }

    /// The library's `SendRaw`: a map, so Go sorts the keys.
    #[test]
    fn the_legacy_shape_and_the_hello() {
        assert_eq!(
            legacy_endpoint_message("abc123", b"payload"),
            r#"{"colibriClass":"EndpointMessage","raw":"cGF5bG9hZA==","to":"abc123"}"#
        );
        assert_eq!(CLIENT_HELLO, r#"{"colibriClass":"ClientHello"}"#);
        assert_eq!(SERVER_HELLO_CLASS, "ServerHello");
    }

    #[test]
    fn what_goes_in_the_to_field_is_escaped_as_go_does() {
        assert_eq!(
            endpoint_message("a\"b<c>&", b""),
            r#"{"colibriClass":"EndpointMessage","to":"a\"b\u003cc\u003e\u0026","msgPayload":{"raw":""}}"#
        );
    }

    #[test]
    fn the_data_frame_layout() {
        let f = encode_frame(b"hi", 0x0102_0304, 0x0a0b_0c0d).unwrap();
        assert_eq!(
            f,
            [b'O', b'L', b'R', b'1', 1, 2, 3, 4, 0xa, 0xb, 0xc, 0xd, b'h', b'i']
        );
        assert_eq!(MAGIC, *b"OLR1");
        assert_eq!(MAX_MESSAGE, 16 * 1024);
    }

    /// A frame is 12 bytes of header and the data, at most 16 384 together.
    #[test]
    fn the_data_frame_is_bounded() {
        let room = MAX_MESSAGE - 12;
        assert!(encode_frame(&vec![0; room], 1, 2).is_ok());
        assert_eq!(
            encode_frame(&vec![0; room + 1], 1, 2),
            Err(FrameError::SendTooLarge)
        );
        assert_eq!(FrameError::SendTooLarge.to_string(), "send too large");
    }

    #[test]
    fn the_window_frame_is_21_bytes() {
        let f = WindowFrame {
            kind: WindowKind::Mark,
            sender_epoch: 1,
            receiver_epoch: 2,
            counter: 0x0102_0304_0506_0708,
        };
        let b = f.encode();
        assert_eq!(b.len(), 21);
        assert_eq!(
            b,
            [b'O', b'L', b'W', b'1', 1, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(WindowFrame::parse(&b), Some(f));
        let echo = WindowFrame {
            kind: WindowKind::Echo,
            ..f
        };
        assert_eq!(echo.encode()[4], 2);
        assert_eq!(WindowFrame::parse(&echo.encode()), Some(echo));
        // Wrong length, wrong magic.
        assert_eq!(WindowFrame::parse(&b[..20]), None);
        let mut long = b.to_vec();
        long.push(0);
        assert_eq!(WindowFrame::parse(&long), None);
        let mut other = b;
        other[3] = b'2';
        assert_eq!(WindowFrame::parse(&other), None);
        // A kind that is neither is still a frame (Go parses it and ignores it).
        let mut odd = b;
        odd[4] = 9;
        assert_eq!(
            WindowFrame::parse(&odd).map(|f| f.kind),
            Some(WindowKind::Other(9))
        );
    }
}

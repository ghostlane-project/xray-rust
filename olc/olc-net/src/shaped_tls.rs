// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The fork's TLS as the signalling's (port plan section 8: the
//! signalling's ClientHello is a browser's): `xray-transport`'s connector,
//! shaped-rustls with a uTLS ClientHello profile, the server checked against
//! the webpki roots. The TCP under it is [`crate::net`]'s, protected.
//!
//! ALPN is what Chrome offers for the dial's use ([`Offer`]): `http/1.1`
//! alone on a WebSocket's own connection, `h2` and `http/1.1` on a
//! `fetch`'s, which [`crate::fetch`] then speaks in the protocol the server
//! picked. For any list but `http/1.1` alone the shaped hello carries the
//! profile's own ALPN extension (Chrome's: `h2`, `http/1.1`); the list here
//! is also what the handshake accepts back.
//!
//! The profile's ALPS (application_settings) is offered only for a protocol
//! of the hello's ALPN list, as Chrome offers it: for `h2` on a `fetch`'s
//! connection, none on a WebSocket's. A server that accepts it gets the
//! client's own, empty as Chrome's, before the client's Finished
//! (`tests/alps_fetch.rs`).
//!
//! Trust for tests only: a lab's deployment has a certificate of the lab's
//! own CA, which the webpki roots do not hold. The cargo feature
//! `tls-test-pin` makes every dial trust the one certificate whose SHA-256
//! the environment variable [`TEST_PIN_ENV`] names, by the connector's own
//! pin (Xray's `pinnedPeerCertSha256`). A lab names its CA: a CA with that
//! hash in the chain the server presents becomes the only trust anchor, and
//! the chain, the dates and the name are checked as ever. (A leaf with that
//! hash is taken as it is, which is the connector's rule and the reason a
//! lab pins its CA.) `tests/test_pin.rs` holds each of these. No app build
//! has the feature, and no setting reaches it.

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use xray_transport::{TlsClientConfig, TlsConnector};

use crate::stream::{set_tls_connector, BoxStream, Dialed, Offer, TlsFuture};

/// The profile [`install`] shapes by default.
pub const FINGERPRINT: &str = "chrome";

/// The environment variable the `tls-test-pin` feature reads: the SHA-256 of
/// one certificate's DER, 64 hex digits (`openssl x509 -outform der | sha256sum`).
/// The shipped features never read it.
pub const TEST_PIN_ENV: &str = "OLC_TLS_TEST_PIN";

/// Whether this build reads [`TEST_PIN_ENV`]: a test build's `tls-test-pin`.
pub const TEST_PIN_BUILD: bool = cfg!(feature = "tls-test-pin");

/// A pin as [`TEST_PIN_ENV`] gives it: 64 hex digits, blanks around them
/// dropped.
#[must_use]
pub fn parse_pin(text: &str) -> Option<[u8; 32]> {
    let text = text.trim().as_bytes();
    if text.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut pin = [0u8; 32];
    for (i, pair) in text.chunks_exact(2).enumerate() {
        pin[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(pin)
}

/// The pins the variable's value stands for: its one pin, or none.
#[cfg(any(test, feature = "tls-test-pin"))]
fn pins_of(value: Option<&str>) -> Vec<[u8; 32]> {
    value.and_then(parse_pin).into_iter().collect()
}

/// The certificates every dial is pinned to: none in the shipped client,
/// whatever the environment says.
#[cfg(not(feature = "tls-test-pin"))]
fn test_pins() -> Vec<[u8; 32]> {
    Vec::new()
}

/// The certificates every dial is pinned to: the one [`TEST_PIN_ENV`]
/// names, read once.
#[cfg(feature = "tls-test-pin")]
fn test_pins() -> Vec<[u8; 32]> {
    static PINS: std::sync::OnceLock<Vec<[u8; 32]>> = std::sync::OnceLock::new();
    PINS.get_or_init(|| {
        let value = std::env::var(TEST_PIN_ENV).ok();
        let pins = pins_of(value.as_deref());
        match (&value, pins.is_empty()) {
            (Some(v), true) if !v.trim().is_empty() => {
                crate::info!("tls: {TEST_PIN_ENV} is not a certificate's SHA-256: ignored");
            }
            (_, false) => {
                crate::info!(
                    "tls: a test build: every TLS dial trusts the one certificate {TEST_PIN_ENV} names"
                );
            }
            _ => {}
        }
        pins
    })
    .clone()
}

/// The ALPN protocols a dial for `offer` names.
#[must_use]
pub fn alpn(offer: Offer) -> Vec<String> {
    match offer {
        Offer::WebSocket => vec!["http/1.1".to_owned()],
        Offer::Fetch => vec!["h2".to_owned(), "http/1.1".to_owned()],
    }
}

/// The connector's settings for a dial to `host` for `offer`, shaped as the
/// (normalized) uTLS profile `fingerprint`.
#[must_use]
pub fn client_config(host: String, offer: Offer, fingerprint: &str) -> TlsClientConfig {
    TlsClientConfig {
        server_name: host,
        allow_insecure: false,
        pinned_peer_cert_sha256: test_pins(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: alpn(offer),
        fingerprint: Some(fingerprint.to_owned()),
    }
}

/// Installs the shaped connector for `fingerprint` (a uTLS profile name,
/// [`FINGERPRINT`] for Chrome's) as the TLS of every `wss://` and
/// `https://` dial.
///
/// # Errors
/// The connector's, for a fingerprint it does not know.
pub fn install(fingerprint: &str) -> io::Result<()> {
    let tls = TlsConnector::system().map_err(|e| io::Error::other(e.to_string()))?;
    let normalized = xray_utls_name(fingerprint)?;
    set_tls_connector(Some(Arc::new(
        move |tcp: TcpStream, host: String, offer: Offer| -> TlsFuture {
            let tls = tls.clone();
            let cfg = client_config(host.clone(), offer, &normalized);
            Box::pin(async move {
                let (stream, picked) = tls
                    .connect_stream_with_alpn(Box::new(tcp), &cfg)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                crate::debug!("{}", alpn_line(&host, offer, picked.as_deref()));
                Ok(Dialed {
                    stream: Box::new(stream) as BoxStream,
                    h2: offer == Offer::Fetch && picked.as_deref() == Some(b"h2".as_slice()),
                })
            })
        },
    )));
    Ok(())
}

/// The debug line a dial writes: the protocol the server picked of the
/// ones offered.
fn alpn_line(host: &str, offer: Offer, picked: Option<&[u8]>) -> String {
    let offered = alpn(offer).join(",");
    match picked {
        Some(p) => format!(
            "tls: {host}: ALPN {} picked of {offered}",
            String::from_utf8_lossy(p)
        ),
        None => format!("tls: {host}: no ALPN picked of {offered}"),
    }
}

/// The profile's normalized name, as the connector takes it; `unsafe` (no
/// shaping) is refused here, since the point is the shape.
fn xray_utls_name(fingerprint: &str) -> io::Result<String> {
    xray_utls::normalize_tls_fingerprint(fingerprint)
        .filter(|n| !n.eq_ignore_ascii_case("unsafe"))
        .map(str::to_owned)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown TLS fingerprint {fingerprint:?}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dial_says_the_protocol_the_server_picked() {
        assert_eq!(
            alpn_line("bk.example", Offer::Fetch, Some(b"h2")),
            "tls: bk.example: ALPN h2 picked of h2,http/1.1"
        );
        assert_eq!(
            alpn_line("ws.example", Offer::WebSocket, Some(b"http/1.1")),
            "tls: ws.example: ALPN http/1.1 picked of http/1.1"
        );
        assert_eq!(
            alpn_line("x.example", Offer::Fetch, None),
            "tls: x.example: no ALPN picked of h2,http/1.1"
        );
    }

    /// The body of a ClientHello record's extension `kind`.
    fn extension(hello: &[u8], kind: u16) -> Option<&[u8]> {
        // record (5) + handshake header (4) + version (2) + random (32)
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + usize::from(hello[at]); // session id
        at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]])); // suites
        at += 1 + usize::from(hello[at]); // compression
        let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 2;
        while at + 4 <= end {
            let this = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            if this == kind {
                return Some(&hello[at + 4..at + 4 + len]);
            }
            at += 4 + len;
        }
        None
    }

    /// The protocols of an ALPN or ALPS extension's body.
    fn protocols(body: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 2;
        while i < body.len() {
            let n = usize::from(body[i]);
            out.push(body[i + 1..i + 1 + n].to_vec());
            i += 1 + n;
        }
        out
    }

    const ALPN: u16 = 0x0010;
    /// application_settings (ALPS) at the codepoint Chrome 157 uses.
    const ALPS: u16 = 0x44cd;
    const ALPS_OLD: u16 = 0x4469;

    /// Chrome's hellos (157, ghostlane lab/olc-alps): a `fetch` offers `h2`
    /// then `http/1.1`, and ALPS for `h2`; a WebSocket's own connection
    /// offers `http/1.1` alone and no ALPS.
    #[test]
    fn a_fetch_offers_h2_and_a_websocket_does_not() {
        let hello = |offer| {
            xray_transport::browser_tls_client_hello_bytes(&client_config(
                "bk.salutejazz.ru".to_owned(),
                offer,
                FINGERPRINT,
            ))
            .unwrap()
        };
        let fetch = hello(Offer::Fetch);
        assert_eq!(
            protocols(extension(&fetch, ALPN).unwrap()),
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            protocols(extension(&fetch, ALPS).expect("a fetch's hello offers ALPS")),
            [b"h2".to_vec()]
        );
        assert_eq!(extension(&fetch, ALPS_OLD), None);

        let websocket = hello(Offer::WebSocket);
        assert_eq!(
            protocols(extension(&websocket, ALPN).unwrap()),
            [b"http/1.1".to_vec()]
        );
        assert_eq!(extension(&websocket, ALPS), None, "Chrome's has none");
        assert_eq!(extension(&websocket, ALPS_OLD), None);
    }

    const PIN_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn pin_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, v) in b.iter_mut().enumerate() {
            *v = u8::try_from(i).unwrap();
        }
        b
    }

    /// A pin is the SHA-256 of a certificate's DER as `sha256sum` prints
    /// it: 64 hex digits, either case, blanks around it dropped; anything
    /// else is no pin.
    #[test]
    fn a_pin_is_64_hex_digits() {
        assert_eq!(parse_pin(PIN_HEX), Some(pin_bytes()));
        assert_eq!(parse_pin(&PIN_HEX.to_uppercase()), Some(pin_bytes()));
        assert_eq!(parse_pin(&format!("  {PIN_HEX}\n")), Some(pin_bytes()));
        for bad in [
            "",
            "00",
            &PIN_HEX[..63],
            &format!("{PIN_HEX}0"),
            &format!("{}g", &PIN_HEX[..63]),
            &format!("{} {}", &PIN_HEX[..32], &PIN_HEX[32..]),
            &format!("+{}", &PIN_HEX[..63]),
        ] {
            assert_eq!(parse_pin(bad), None, "{bad:?}");
        }
    }

    /// What the variable gives a test build: its one pin, or none when it is
    /// unset, empty or not a pin (such a build then trusts as a shipped one).
    #[test]
    fn the_variable_names_one_pin_or_none() {
        assert_eq!(pins_of(Some(PIN_HEX)), vec![pin_bytes()]);
        assert_eq!(pins_of(None), Vec::<[u8; 32]>::new());
        assert_eq!(pins_of(Some("")), Vec::<[u8; 32]>::new());
        assert_eq!(pins_of(Some("not a pin")), Vec::<[u8; 32]>::new());
    }

    /// The shipped client pins nothing whatever the environment says: the
    /// `tls-test-pin` feature is the only way in, and a dial's settings carry
    /// no pin and no name but the host's without it.
    #[test]
    fn the_shipped_client_pins_no_certificate() {
        assert_eq!(TEST_PIN_ENV, "OLC_TLS_TEST_PIN");
        assert_eq!(TEST_PIN_BUILD, cfg!(feature = "tls-test-pin"));
        if !TEST_PIN_BUILD {
            let cfg = client_config("meet.example".to_owned(), Offer::Fetch, FINGERPRINT);
            assert!(cfg.pinned_peer_cert_sha256.is_empty());
            assert!(cfg.verify_peer_cert_by_name.is_empty());
            assert!(!cfg.allow_insecure);
        }
    }

    /// The pin cannot be turned on from an app: the libraries the apps link
    /// (olc-ffi, and ghostlane-core over it) name no feature that reaches
    /// `tls-test-pin`, and the client's settings (olc-client's `Config`, the
    /// FFI's JSON) have no field for it: it is a cargo feature of a test
    /// build and a variable of that process, nothing else.
    #[test]
    fn the_apps_libraries_cannot_turn_the_pin_on() {
        for (name, manifest) in [
            ("olc-ffi", include_str!("../../olc-ffi/Cargo.toml")),
            (
                "ghostlane-core",
                include_str!("../../../crates/ghostlane-core/Cargo.toml"),
            ),
        ] {
            assert!(
                !manifest.contains("tls-test-pin"),
                "{name}'s manifest names the test pin"
            );
        }
        for (name, source) in [
            (
                "olc-client's config",
                include_str!("../../olc-client/src/config.rs"),
            ),
            (
                "olc-ffi's config",
                include_str!("../../olc-ffi/src/config.rs"),
            ),
        ] {
            assert!(
                !source.contains("TEST_PIN") && !source.contains("test_pin"),
                "{name} reaches for the test pin"
            );
        }
        let own = include_str!("../Cargo.toml");
        assert!(own.contains("tls-test-pin = [\"shaped-tls\"]"));
    }

    #[test]
    fn a_profile_is_named_as_xray_names_it() {
        assert_eq!(xray_utls_name("Chrome").unwrap(), "chrome");
        assert_eq!(xray_utls_name("").unwrap(), "chrome");
        assert!(xray_utls_name("unsafe").is_err());
        assert!(xray_utls_name("netscape").is_err());
    }
}

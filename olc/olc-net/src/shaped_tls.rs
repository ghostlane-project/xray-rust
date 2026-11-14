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

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use xray_transport::{TlsClientConfig, TlsConnector};

use crate::stream::{set_tls_connector, BoxStream, Dialed, Offer, TlsFuture};

/// The profile [`install`] shapes by default.
pub const FINGERPRINT: &str = "chrome";

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
        pinned_peer_cert_sha256: Vec::new(),
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
            let cfg = client_config(host, offer, &normalized);
            Box::pin(async move {
                let (stream, picked) = tls
                    .connect_stream_with_alpn(Box::new(tcp), &cfg)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(Dialed {
                    stream: Box::new(stream) as BoxStream,
                    h2: offer == Offer::Fetch && picked.as_deref() == Some(b"h2".as_slice()),
                })
            })
        },
    )));
    Ok(())
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

    /// The ALPN extension's protocols in a ClientHello record.
    fn alpn_of(hello: &[u8]) -> Vec<Vec<u8>> {
        // record (5) + handshake header (4) + version (2) + random (32)
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + usize::from(hello[at]); // session id
        at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]])); // suites
        at += 1 + usize::from(hello[at]); // compression
        let end = at + 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 2;
        while at + 4 <= end {
            let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
            let len = usize::from(u16::from_be_bytes([hello[at + 2], hello[at + 3]]));
            let body = &hello[at + 4..at + 4 + len];
            if kind == 0x0010 {
                let mut out = Vec::new();
                let mut i = 2;
                while i < body.len() {
                    let n = usize::from(body[i]);
                    out.push(body[i + 1..i + 1 + n].to_vec());
                    i += 1 + n;
                }
                return out;
            }
            at += 4 + len;
        }
        Vec::new()
    }

    /// Chrome's hellos: a `fetch` offers `h2` then `http/1.1`, a
    /// WebSocket's own connection `http/1.1` alone.
    #[test]
    fn a_fetch_offers_h2_and_a_websocket_does_not() {
        let hello = |offer| {
            xray_transport::plain_tls_client_hello_bytes(&client_config(
                "bk.salutejazz.ru".to_owned(),
                offer,
                FINGERPRINT,
            ))
            .unwrap()
        };
        assert_eq!(
            alpn_of(&hello(Offer::Fetch)),
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(alpn_of(&hello(Offer::WebSocket)), [b"http/1.1".to_vec()]);
    }

    #[test]
    fn a_profile_is_named_as_xray_names_it() {
        assert_eq!(xray_utls_name("Chrome").unwrap(), "chrome");
        assert_eq!(xray_utls_name("").unwrap(), "chrome");
        assert!(xray_utls_name("unsafe").is_err());
        assert!(xray_utls_name("netscape").is_err());
    }
}

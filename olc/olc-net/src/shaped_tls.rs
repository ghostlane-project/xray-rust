// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The fork's TLS as the signalling's (port plan section 8: the
//! signalling's ClientHello is a browser's): `xray-transport`'s connector,
//! shaped-rustls with a uTLS ClientHello profile, the server checked against
//! the webpki roots. The TCP under it is [`crate::net`]'s, protected.
//!
//! ALPN is `http/1.1` alone: what a browser offers on a WebSocket's own
//! connection, and all the one-request [`crate::http`] client speaks. A
//! browser's `fetch` would offer `h2` too, so the auth call's hello differs
//! from Chrome's there.

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use xray_transport::{TlsClientConfig, TlsConnector};

use crate::stream::{set_tls_connector, BoxStream, TlsFuture};

/// The profile [`install`] shapes by default.
pub const FINGERPRINT: &str = "chrome";

/// The one ALPN offered.
pub const ALPN: &str = "http/1.1";

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
        move |tcp: TcpStream, host: String| -> TlsFuture {
            let tls = tls.clone();
            let cfg = TlsClientConfig {
                server_name: host,
                allow_insecure: false,
                pinned_peer_cert_sha256: Vec::new(),
                verify_peer_cert_by_name: Vec::new(),
                alpn: vec![ALPN.to_owned()],
                fingerprint: Some(normalized.clone()),
            };
            Box::pin(async move {
                let stream = tls
                    .connect_stream(Box::new(tcp), &cfg)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(Box::new(stream) as BoxStream)
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

    #[test]
    fn a_profile_is_named_as_xray_names_it() {
        assert_eq!(xray_utls_name("Chrome").unwrap(), "chrome");
        assert_eq!(xray_utls_name("").unwrap(), "chrome");
        assert!(xray_utls_name("unsafe").is_err());
        assert!(xray_utls_name("netscape").is_err());
    }
}

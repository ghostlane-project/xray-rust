// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! WebRTC for the olcRTC engines, on str0m (port plan section 11, M4).
//!
//! The Go engine at 2d4266af runs pion; a carrier there opens peer
//! connections, trickles ICE and moves LiveKit DataPackets over SCTP data
//! channels. Here each peer connection is one [`peer::Peer`]: a str0m `Rtc`
//! in RTP mode on one protected UDP socket ([`olc_net::net`]), driven by a
//! task of its own.
//!
//! # Looking like a browser (port plan section 8)
//!
//! - ICE credentials are Chrome's sizes: a 4-character ufrag, a
//!   24-character password ([`ice::chrome_creds`]);
//! - STUN attributes go in Chrome's order: the vendored `is` fork
//!   (`olc/vendor/is-0.12.0`), switched on by [`init`];
//! - DTLS is BoringSSL configured as libwebrtc configures it under the
//!   `boring` feature ([`dtls_boring`]): Chrome's ClientHello and
//!   certificate. Without it, str0m's own (dimpl), whose hello looks like no
//!   browser's: a development build only.
//!
//! # Memory
//!
//! Per peer connection: one receive buffer ([`peer::RECV_BUF`]), the event
//! queue's bytes ([`peer::INBOUND_BYTES`]), str0m's SCTP send buffer
//! (the caller's `sctp_max_buffered`) and its receive storage (at least
//! 1 MiB per association, str0m's floor, allocated as data arrives).

#![warn(missing_docs)]
#![cfg_attr(not(feature = "boring"), forbid(unsafe_code))]
#![cfg_attr(feature = "boring", deny(unsafe_code))]

#[cfg(feature = "boring")]
#[allow(unsafe_code)]
pub mod dtls_boring;
pub mod ice;
pub mod peer;
pub mod turn;

use std::sync::Arc;

pub use str0m;
pub use str0m::config::{CryptoProvider, DtlsVersion};

/// Switches the process to Chrome's STUN attribute order (the `is` fork's
/// `StunProfile::Chrome`). Idempotent; call it before the first peer.
pub fn init() {
    is::stun::set_stun_profile(is::stun::StunProfile::Chrome);
}

/// The DTLS this build has: BoringSSL shaped as Chrome's under the `boring`
/// feature, else str0m's own (dimpl). SRTP, SHA-1 HMAC and the rest come
/// from aws-lc-rs either way.
#[must_use]
pub fn crypto() -> Arc<CryptoProvider> {
    #[cfg(feature = "boring")]
    let provider = dtls_boring::provider();
    #[cfg(not(feature = "boring"))]
    let provider = str0m_aws_lc_rs::default_provider();
    Arc::new(provider)
}

/// The name of [`crypto`]'s DTLS, for the logs and the reports.
#[must_use]
pub fn dtls_name() -> &'static str {
    if cfg!(feature = "boring") {
        "boringssl"
    } else {
        "dimpl"
    }
}

/// Bounds for this crate's tests: a stuck test fails instead of holding the
/// shared build box.
#[cfg(test)]
pub(crate) mod testing {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::UdpSocket;

    /// One async test's bound.
    pub(crate) const TEST_BOUND: Duration = Duration::from_secs(20);

    /// Runs `f` under [`TEST_BOUND`].
    pub(crate) async fn bounded<F: Future>(f: F) -> F::Output {
        match tokio::time::timeout(TEST_BOUND, f).await {
            Ok(out) => out,
            Err(_) => panic!("the test did not finish within {TEST_BOUND:?}"),
        }
    }

    const TURN_USER: &str = "1763100000:olc";
    const TURN_PASS: &str = "turn-test-password";
    const TURN_REALM: &str = "olc.test";

    /// A TURN server on loopback (webrtc-rs's, tests only) relaying from
    /// 127.0.0.1, and the entry a peer's config names it by. It speaks RFC
    /// 8489's nonce cookie and SHA-256; the classic path (no cookie, as
    /// coturn and pion answer) is the interop harness's, against pion's
    /// server (zz_rust_relay_test.go).
    pub(crate) async fn turn_server() -> (turn::server::Server, crate::turn::TurnServer) {
        use turn::relay::relay_static::RelayAddressGeneratorStatic;
        use turn::server::config::{ConnConfig, ServerConfig};
        let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = conn.local_addr().unwrap();
        let server = turn::server::Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(webrtc_util::vnet::net::Net::new(None)),
                }),
            }],
            realm: TURN_REALM.to_owned(),
            // RFC 8489's handler: the nonce cookie, SHA-256 and MD5 offered.
            auth_handler: Arc::new(
                turn::auth::StaticAuthHandler::new(
                    [(TURN_USER.to_owned(), TURN_PASS.to_owned())].into(),
                )
                .unwrap(),
            ),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .unwrap();
        let entry = crate::turn::TurnServer {
            host: addr.ip().to_string(),
            port: addr.port(),
            transport: crate::turn::TurnTransport::Udp,
            username: TURN_USER.into(),
            password: TURN_PASS.into(),
        };
        (server, entry)
    }
}

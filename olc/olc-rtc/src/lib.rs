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
//! - DTLS is str0m's own (dimpl) for now, whose hello does not look like
//!   Chrome's; the BoringSSL provider shaped as Chrome's (the spike's, M2)
//!   comes next, behind a `boring` feature: a build for a censored network
//!   needs it.
//!
//! # Memory
//!
//! Per peer connection: one receive buffer ([`peer::RECV_BUF`]), the event
//! queue's bytes ([`peer::INBOUND_BYTES`]), str0m's SCTP send buffer
//! (the caller's `sctp_max_buffered`) and its receive storage (at least
//! 1 MiB per association, str0m's floor, allocated as data arrives).

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod ice;
pub mod peer;

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
    Arc::new(str0m_aws_lc_rs::default_provider())
}

/// The name of [`crypto`]'s DTLS, for the logs and the reports.
#[must_use]
pub fn dtls_name() -> &'static str {
    "dimpl"
}

/// Bounds for this crate's tests: a stuck test fails instead of holding the
/// shared build box.
#[cfg(test)]
pub(crate) mod testing {
    use std::future::Future;
    use std::time::Duration;

    /// One async test's bound.
    pub(crate) const TEST_BOUND: Duration = Duration::from_secs(20);

    /// Runs `f` under [`TEST_BOUND`].
    pub(crate) async fn bounded<F: Future>(f: F) -> F::Output {
        match tokio::time::timeout(TEST_BOUND, f).await {
            Ok(out) => out,
            Err(_) => panic!("the test did not finish within {TEST_BOUND:?}"),
        }
    }
}

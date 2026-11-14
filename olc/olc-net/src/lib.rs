// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The network layer under the olcRTC client and its engines, as the Go
//! engine at 2d4266af has it:
//!
//! - [`log`]: the engine log (`internal/logger`), whose lines are a contract
//!   with the apps and the gate;
//! - [`net`]: every socket the engine opens goes through the host's
//!   protector first (`internal/protect`);
//! - [`resolver`]: the DNS ring the engine's own names are asked of;
//! - [`ws`] and [`http`]: the clients a carrier's signalling speaks (the
//!   SaluteJazz connector's WebSocket, its auth's HTTPS calls), over any
//!   byte stream: plain TCP from [`net`], or TLS the host shapes (with the
//!   `shaped-tls` feature, `shaped_tls::install` puts the fork's own in).
//!
//! Moved out of `olc-client` so the engines (`olc-rtc`, the carriers) share
//! one protector and one log with the client.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod http;
pub mod link;
pub mod log;
pub mod net;
pub mod resolver;
#[cfg(feature = "shaped-tls")]
pub mod shaped_tls;
pub mod stream;
pub mod ws;

/// Bounds for this crate's tests: a stuck test fails instead of holding the
/// shared build box.
#[cfg(test)]
pub(crate) mod testing {
    use std::future::Future;
    use std::time::Duration;

    /// One async test's bound.
    pub(crate) const TEST_BOUND: Duration = Duration::from_secs(10);

    /// Runs `f` under [`TEST_BOUND`].
    pub(crate) async fn bounded<F: Future>(f: F) -> F::Output {
        match tokio::time::timeout(TEST_BOUND, f).await {
            Ok(out) => out,
            Err(_) => panic!("the test did not finish within {TEST_BOUND:?}"),
        }
    }
}

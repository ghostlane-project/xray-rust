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
//!   `shaped-tls` feature, `shaped_tls::install` puts the fork's own in);
//!   [`fetch`] is a browser's `fetch` on top: `h2` or `http/1.1`, as the
//!   server picks.
//! - [`form`], [`cookies`] and [`retry`]: what a carrier's room provider
//!   takes from Go's standard library and HTTP client: a form body as
//!   `url.Values.Encode` writes it, a reply's cookies as
//!   `http.Response.Cookies` reads them, and a dial that is tried again.
//! - [`reconnect`]: the supervisor that rejoins a carrier's room
//!   (`internal/engine/reconnect.go`): coalesced requests, the wait for a
//!   route, the attempt limit and the backoff.
//! - [`agent`]: the `User-Agent` of a call Go's code names no sender on,
//!   which follows the protocol the connection speaks.
//!
//! Moved out of `olc-client` so the engines (`olc-rtc`, the carriers) share
//! one protector and one log with the client.

// Only `sys` may use `unsafe`, for its call into the C library.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod agent;
pub mod cookies;
pub mod fetch;
pub mod form;
pub mod http;
pub mod link;
pub mod log;
pub mod net;
pub mod reconnect;
pub mod resolver;
pub mod retry;
#[cfg(feature = "shaped-tls")]
pub mod shaped_tls;
pub mod stream;
mod sys;
pub mod ws;
mod ws_deflate;

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

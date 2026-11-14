// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The olcRTC client: what `internal/client` does in the Go engine at
//! 2d4266af, over the Rust record layer ([`olc_wire`]), lanes
//! ([`olc_muxconn`]) and smux ([`olc_smux`]).
//!
//! # Shape
//!
//! [`Client::run`] joins the room through the engine ([`pipe`], the
//! interop hub's, until the WebRTC carriers come), builds the data lane
//! ([`lane`]) and the smux session over it, wins the hello race
//! ([`hello`]), starts the control loop ([`control`]) and only then opens
//! the SOCKS5 front ([`socks`]): `SOCKS5 server listening on <addr>` is the
//! line the apps wait for. A CONNECT becomes a smux stream with a CONNECT
//! request ([`tunnel`]); UDP (`UDP ASSOCIATE` and hev's `FWD_UDP`) becomes
//! DNS over a stream ([`dns`]) or a flow on the datagram lane ([`udp`]).
//! A session that dies is rebuilt ([`client`]'s reconnect, as `link.go`
//! does it).
//!
//! # Memory
//!
//! Every queue is bounded and every buffer is sized from a formula written
//! next to its constant; [`sizes`] holds the per-layer budget and the
//! `size_of` assertions on the per-session and per-stream state.

// Only `sys` may use `unsafe`, for its calls into the C library.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod control;
pub mod copy;
pub mod direct;
pub mod dns;
pub mod frames;
pub mod gauges;
pub mod hello;
pub mod lane;
pub mod log;
pub mod net;
pub mod pipe;
pub mod resolver;
pub mod sizes;
pub mod socks;
pub mod supervisor;
pub mod sys;
#[cfg(test)]
mod testhub;
pub mod tunnel;
pub mod udp;

pub use client::{Client, RunError};
pub use config::Config;

/// Bounds for this crate's tests: a stuck test fails instead of holding the
/// shared build box.
#[cfg(test)]
pub(crate) mod testing {
    use std::future::Future;
    use std::time::Duration;

    /// One async test's bound (wall time; virtual time under `start_paused`,
    /// where an idle runtime jumps straight to it).
    pub(crate) const TEST_BOUND: Duration = Duration::from_secs(10);
    /// The whole test binary's wall-clock bound: it catches a test blocked
    /// outside the runtime, where no timer fires.
    const PROCESS_BOUND: Duration = Duration::from_secs(120);

    /// Runs `f` under [`TEST_BOUND`] and arms the process watchdog.
    pub(crate) async fn bounded<F: Future>(f: F) -> F::Output {
        bounded_for(TEST_BOUND, f).await
    }

    /// Runs `f` under `limit` (a paused test whose scenario needs more
    /// virtual time than [`TEST_BOUND`]) and arms the process watchdog.
    pub(crate) async fn bounded_for<F: Future>(limit: Duration, f: F) -> F::Output {
        watchdog();
        match tokio::time::timeout(limit, f).await {
            Ok(out) => out,
            Err(_) => panic!("the test did not finish within {limit:?}"),
        }
    }

    /// Ends the process once it has run [`PROCESS_BOUND`].
    pub(crate) fn watchdog() {
        static ARMED: std::sync::Once = std::sync::Once::new();
        ARMED.call_once(|| {
            std::thread::spawn(|| {
                std::thread::sleep(PROCESS_BOUND);
                eprintln!("olc-client tests still running after {PROCESS_BOUND:?}: aborting");
                std::process::exit(101);
            });
        });
    }
}

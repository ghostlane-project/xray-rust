// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The Jitsi carrier (`internal/auth/jitsi` and `internal/engine/jitsi` of
//! the Go engine at 2d4266af, and `github.com/zarazaex69/j` v0.0.1, the
//! library it joins with), ported in the order of the plan
//! `m10-jitsi-plan.md`: what Go sends is what Rust sends.
//!
//! [`xml`] is the crate's own small XML (decision D2); [`stanza`] is every
//! stanza the client writes, as exact text.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bridge;
pub mod configjs;
pub mod epoch;
pub mod frame;
pub mod ice;
pub mod jingle;
pub mod join;
pub mod link;
pub mod nick;
pub mod relaywin;
pub mod room;
pub mod session;
#[cfg(test)]
mod session_e2e;
pub mod stanza;
#[cfg(test)]
mod vectors;
pub mod xml;
pub mod xmpp;

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SaluteJazz carrier (`internal/engine/salutejazz` at 2d4266af) and
//! the client half of its auth provider (`internal/auth/salutejazz`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod lk;
pub mod relaywin;
pub mod session;
pub mod wire;

pub use session::{Config, Error, Link, Refresh, RefreshFuture};

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The XMPP connection of the j library (`J/internal/xmpp/conn.go`):
//! [`conn`] logs in anonymously, keeps the stream alive with stream
//! management and serves what the server sends; [`bosh`] carries the same
//! stream over HTTP when the WebSocket does not dial; `testing` (test builds
//! only) is an in-memory server for their tests.

pub mod bosh;
pub mod conn;

#[cfg(test)]
pub(crate) mod testing;

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The XMPP connection of the j library (`J/internal/xmpp/conn.go`):
//! [`conn`] logs in anonymously, keeps the stream alive with stream
//! management and serves what the server sends; [`testing`] is an in-memory
//! server for its tests.

pub mod conn;

#[cfg(test)]
pub(crate) mod testing;

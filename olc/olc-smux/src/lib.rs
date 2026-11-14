// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A port of smux v1.5.57 (https://github.com/xtaci/smux), Copyright (c)
// 2016-2017 xtaci, MIT License. See NOTICE.

//! smux protocol version 2, ported from xtaci/smux v1.5.57 for the olcRTC
//! client.
//!
//! The olcRTC servers on the exits run smux v1.5.57 with `Version = 2`
//! (olcRTC `internal/runtime/runtime.go:109-119,206-217` at 2d4266af). This
//! crate speaks to them byte for byte: the same frames, the same window
//! updates at the same points, the same keepalive, the same stream ids and
//! the same close and half-close sequences. Every behaviour cites the Go
//! file and line it reproduces; `smux/` means the module at
//! `github.com/xtaci/smux@v1.5.57`.
//!
//! # Shape
//!
//! [`Session::client`] (or [`Session::server`], which exists for tests) runs
//! a session over any `AsyncRead + AsyncWrite` connection. One task, the
//! [`Driver`], owns the connection: it reads and dispatches frames (Go's
//! `recvLoop`), writes queued frames in the shaper's order (`shaperLoop` and
//! `sendLoop`) and runs the keepalive. [`Stream`]s are `AsyncRead +
//! AsyncWrite` handles; `poll_shutdown` is Go's `CloseWrite` and
//! [`Stream::close`] (or dropping the handle) is Go's `Close`.
//!
//! # Memory
//!
//! Every buffer is bounded in bytes:
//!
//! - received data is limited by the session token bucket,
//!   `MaxReceiveBuffer` (`smux/session.go:101,143,377-399`), exactly as in Go;
//! - queued outgoing data is limited per stream and per session
//!   ([`Config::max_stream_send_buffer`], [`Config::max_send_buffer`]);
//! - both live in one pool of 4 KiB chunks per session (see
//!   [`Stats::pool_held`]), so a frame costs no allocation once the pool is
//!   warm, and a stream with nothing buffered holds no payload memory.
//!
//! The crate's own module docs give the bounds as formulas.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod arena;
mod config;
mod driver;
mod error;
pub mod frame;
mod session;
mod state;
mod stream;

pub use config::{
    clamp_max_frame_size, Config, HostClass, KeepAlive, DATACHANNEL_MAX_PAYLOAD,
    MIN_SMUX_WIRE_PAYLOAD, OLC_RECORD_OVERHEAD, SMUX_WIRE_OVERHEAD, VP8CHANNEL_MAX_PAYLOAD,
};
pub use driver::Driver;
pub use error::Error;
pub use session::{Role, Session, Stats};
pub use stream::{Stream, StreamStats};

/// The size of one chunk of the session's buffer pool, in bytes.
pub const POOL_CHUNK_SIZE: usize = arena::CHUNK;

#[cfg(test)]
mod size_tests;

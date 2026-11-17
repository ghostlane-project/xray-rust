// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
//
// A port of kcp-go v5.6.72 (https://github.com/xtaci/kcp-go), Copyright (c)
// 2015 xtaci, MIT License. See NOTICE.

//! KCP for the olcRTC client: kcp-go v5.6.72, sans-IO.
//!
//! The olcRTC servers on the exits run kcp-go v5.6.72 inside the vp8channel
//! transport (olcRTC `internal/transport/vp8channel/kcp.go` at 2d4266af).
//! The wire is ikcp's, but what the server depends on is kcp-go's behaviour:
//! its constants (receive window 32 by default, window probe 500 ms, the
//! 10 ms floor on the interval), its flush order, its stream-mode cutting and
//! its session's drop points. This crate keeps all of it:
//!
//! - [`kcp`]: the state machine, `kcp.go` function for function;
//! - [`session`]: what kcp-go's `UDPSession` adds that reaches the wire
//!   (write splitting and flushing, the read side, the output backlog);
//! - [`message`]: vp8channel's `u32` length framing on the stream (W33);
//! - [`link`]: vp8channel's CRC-32C trailer on every packet (W28);
//! - [`pool`]: segment buffers.
//!
//! Nothing here does I/O or reads a clock: the caller passes `Instant`s
//! (or, to [`Kcp`], milliseconds) and moves packets. The vp8channel crate
//! drives it on kcp-go's schedule: [`Session::update`] after the interval it
//! returns (at most 10 ms), [`Session::input`] for each packet, and the
//! output queue drained by its writer.
//!
//! Settings: [`Config::vp8channel`] is `startKCP`'s (`nodelay 1`, interval
//! 5 → 10 ms, resend 2, `nc 1`, MTU 1400 so mss 1376, stream mode, ACK no
//! delay, no write delay, conv `0xC0FFEE01`), with the windows of the host
//! profile: 512/512 on a phone.

#![forbid(unsafe_code)]

pub mod kcp;
pub mod link;
pub mod message;
pub mod pool;
pub mod session;

pub use kcp::{Counters, FlushType, Kcp};
pub use session::{Config, Session, Stats, WouldBlock};

#[cfg(test)]
mod tests;

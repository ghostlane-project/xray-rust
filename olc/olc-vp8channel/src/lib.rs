// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The olcRTC vp8channel transport, client side, as the Go engine runs it
//! at 2d4266af (`internal/transport/vp8channel`): a KCP byte transport whose
//! packets ride a video track as valid VP8 keyframes, so SFUs that check the
//! bitstream forward them.
//!
//! # Layers
//!
//! - [`wire`]: the 36-byte epoch header, the OLKB/OLUD/OLUB batches, the
//!   binding token (W24-W26, W29, W30);
//! - [`conn`]: a KCP plane ([`olc_kcp`]) with its CRC-32C trailer (W28) and
//!   its queue to the writer;
//! - [`lane`], [`pace`], [`frames`]: the data lane that goes quiet on a dark
//!   path and keeps under what the path carries (issue #12);
//! - [`writer`]: the paced writer, a sample a frame interval;
//! - [`channel`]: the client transport, sans-IO: epochs, both planes,
//!   datagrams, the inbound dispatch (W27);
//! - [`transport`]: the channel on Tokio;
//! - [`rtp`]: what pion makes of a written sample (W36), [`vp9`]: the VP9
//!   carrier (W34, W35).
//!
//! # What is not ported
//!
//! The server side (one session per remote epoch, `peers.go`), the traffic
//! shaper (`cfg.Traffic`, unset on clients) and the publish limiter
//! (olcrtc#26: only the generic LiveKit engine declares a ceiling, and no
//! Rust carrier is that engine).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod channel;
pub mod conn;
pub mod frames;
pub mod lane;
pub mod log;
pub mod pace;
pub mod rtp;
pub mod segment;
pub mod transport;
pub mod vp9;
pub mod wire;
pub mod writer;

pub use channel::{Carrier, Channel, Config, Inbound, Options};
pub use transport::{Event, Stream, Transport};

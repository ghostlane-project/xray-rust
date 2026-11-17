// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The olcRTC client's API for the apps: [`OlcrtcRuntime`], call for call
//! the gomobile `mobile.Runtime` of the Go engine at 2d4266af, so the Swift
//! and Kotlin call sites change only in names (plan §3.3).
//!
//! # Shape
//!
//! - UniFFI (proc-macro, no UDL): Swift and Kotlin bindings are generated
//!   from the library that links this crate (`ghostlane-core`, library
//!   mode); the callbacks ([`SocketProtector`], [`SessionListener`],
//!   [`LogWriter`]) are foreign traits; the errors ([`OlcrtcError`]) carry
//!   Go's texts.
//! - The calls are synchronous, as gomobile's. A generation runs on the
//!   process's one Tokio runtime (`ghostlane_runtime`), shared with the xray
//!   core in the same library.
//! - The room list is the runtime's and the supervisor reads it at every
//!   hop (`set_room`, `clear_failover_rooms`, `add_failover_room` while
//!   running), as Go's `Reload` does.
//! - [`memory_stats`] and [`trim`] are MemoryWatch's (plan §9), and
//!   [`set_byte_budget`] sets the byte budget both cores share (D11's relief).

#![warn(missing_docs)]

uniffi::setup_scaffolding!();

pub mod callbacks;
pub mod config;
pub mod error;
pub mod memory;
mod probe;
pub mod runtime;

pub use callbacks::{set_log_writer, LogWriter, SessionListener, SocketProtector};
pub use error::OlcrtcError;
pub use memory::{memory_stats, set_byte_budget, trim};
pub use runtime::{OlcrtcRuntime, RoomRun, Runner};

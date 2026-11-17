// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The VK Calls carrier (`internal/auth/vkcalls` and
//! `internal/engine/vkcalls` of the Go engine at 2d4266af).
//!
//! [`auth`] walks a guest from a join link to the signalling endpoint;
//! [`signaling`] is that endpoint's WebSocket and [`recruit`] the wait for
//! SERVER topology with the guests that end it; [`negotiate`] and [`answer`]
//! are the offer as our stack is given it and the answer VK's SFU accepts;
//! [`session`] is one attempt's peer connection, answered through both;
//! [`control`] is the producer command channel; [`engine`] is the session
//! over all of them, the video transport's engine.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod answer;
pub mod auth;
pub mod control;
pub mod engine;
mod gourl;
pub mod negotiate;
pub mod recruit;
pub mod session;
pub mod signaling;

#[cfg(test)]
mod testing;
#[cfg(test)]
mod vectors;

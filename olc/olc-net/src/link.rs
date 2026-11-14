// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What an engine's link and the client above it share: the events a link
//! reports (Go's reconnect and ended callbacks) and the sinks it hands the
//! peer's messages to (`OnData`, `OnDatagram`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// What a link tells the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// The engine joined its room again: the session over it is gone and
    /// must be built again (the engine's reconnect callback).
    Reconnected,
    /// The conference ended for good (the ended callback), with why.
    Ended(String),
}

/// A future a sink returns.
pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Where a link hands each reliable message (`OnData`): the client's data
/// lane. The push may wait (the lane's queue is full); the link reads no
/// further message of that channel until it returns, which is the inbound
/// backpressure (Go's `OnMessage` blocking pion's SCTP reader).
pub trait DataSink: Send + Sync {
    /// Takes one message; it may decrypt it in place.
    fn push<'a>(&'a self, record: &'a mut [u8]) -> SinkFuture<'a>;
}

/// Where a link hands each lossy message (`OnDatagram`): never waits.
pub type DatagramSink = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

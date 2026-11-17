// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the transport needs of an engine that carries video (Go's
//! `videoSession` over `common.NewEngineVideoSession`): the published track
//! as a [`Stream`], the codec its relay forwards, the remote track's frames
//! and the relay's keyframe requests back, and its news.
//!
//! An engine is a carrier's session (MTS Link, VK Calls) or the interop
//! lab's peer-to-peer one. It packetizes the samples it is given and hands
//! back **assembled frames** ([`crate::rtp_reader::TrackReader`]), never
//! RTP. Its news come on a channel it is given when it joins: the owner
//! reads [`Joined::events`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::channel::Carrier;
use crate::transport::Stream;

/// What a frame the remote track completes is handed to
/// ([`crate::Transport::handle_incoming_frame`]). Called on the engine's
/// receive path: it must not block.
pub type FrameHandler = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// What a keyframe request from the relay (a PLI or a FIR) is handed to
/// ([`crate::Transport::request_keyframe`]). It must not block.
pub type KeyframeHandler = Arc<dyn Fn() + Send + Sync>;

/// A wait or a teardown the engine runs.
pub type EngineFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// What an engine tells its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// It joined again: the transport restarts its planes on a new epoch
    /// ([`crate::Transport::provider_reconnected`]).
    Reconnected,
    /// It is gone for good, and why.
    Ended(String),
}

/// [`EngineEvent`]s held for the owner. An engine sends without waiting
/// for room it may never get (`try_send`, or a send it can abandon).
pub const EVENT_QUEUE: usize = 16;

/// An engine that carries video.
pub trait VideoEngine: Stream {
    /// The codec the engine's track carries: what the transport dresses
    /// its frames as.
    fn carrier(&self) -> Carrier;

    /// Where the remote track's frames go; `None` drops them.
    fn set_frame_handler(&self, handler: Option<FrameHandler>);

    /// Where the relay's keyframe requests go; `None` drops them. An
    /// engine whose relay asks for none keeps nothing.
    fn set_keyframe_handler(&self, handler: Option<KeyframeHandler>);

    /// A wait of the engine's own for its peer to have settled, for an
    /// engine that knows more than "frames arrived" (interop-p2p: its peer
    /// connection up for a settle time). `None`, the default, leaves the
    /// wait to the transport: until [`crate::Transport::peer_seen`].
    fn wait_peer_settled(&self) -> Option<EngineFuture<'_>> {
        None
    }

    /// Bytes the engine's readers of the room's RTP hold now (the memory
    /// line's `rtp`); `None`, the default, for an engine that has none to
    /// count (its frames come whole).
    fn rtp_held_bytes(&self) -> Option<usize> {
        None
    }

    /// Leaves the room for good.
    fn close(&self) -> EngineFuture<'_>;
}

/// An engine in its room, and its news.
pub struct Joined {
    /// The engine.
    pub engine: Arc<dyn VideoEngine>,
    /// Its events, at most [`EVENT_QUEUE`] held.
    pub events: mpsc::Receiver<EngineEvent>,
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Joined")
            .field("carrier", &self.engine.carrier())
            .finish_non_exhaustive()
    }
}

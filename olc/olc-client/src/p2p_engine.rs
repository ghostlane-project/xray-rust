// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! interop-p2p ([`crate::p2p`]) as a video engine
//! ([`olc_vp8channel::engine::VideoEngine`]): what the vp8channel link
//! runs over, the same surface a carrier's session gives.
//!
//! The engine is a handle around the link, since [`P2pLink::reconnect`]
//! needs the link's `Arc`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use olc_vp8channel::channel::Carrier;
use olc_vp8channel::engine::{
    EngineEvent, EngineFuture, FrameHandler, Joined, KeyframeHandler, VideoEngine, EVENT_QUEUE,
};
use olc_vp8channel::transport::Stream;
use tokio::sync::mpsc;

use crate::p2p::{P2pError, P2pEvent, P2pLink};

/// interop-p2p's link as the transport's engine.
#[derive(Debug)]
pub struct P2pEngine(Arc<P2pLink>);

impl P2pEngine {
    /// The link under the engine.
    #[must_use]
    pub fn link(&self) -> &Arc<P2pLink> {
        &self.0
    }
}

impl Stream for P2pEngine {
    fn write_sample(&self, sample: &[u8]) -> bool {
        self.0.write_sample(sample)
    }

    fn can_send(&self) -> bool {
        self.0.can_send()
    }

    fn subscriber_can_send(&self) -> bool {
        self.0.can_send()
    }

    fn reconnect(&self, reason: &str) {
        self.0.reconnect(reason);
    }
}

impl VideoEngine for P2pEngine {
    fn carrier(&self) -> Carrier {
        Carrier::Vp8
    }

    fn set_frame_handler(&self, handler: Option<FrameHandler>) {
        self.0.set_frame_handler(handler);
    }

    /// The lab's pair is two peers and no relay: nothing asks for a
    /// keyframe, and a VP8 channel answers none.
    fn set_keyframe_handler(&self, _handler: Option<KeyframeHandler>) {}

    fn wait_peer_settled(&self) -> Option<EngineFuture<'_>> {
        Some(Box::pin(self.0.wait_peer_settled()))
    }

    fn close(&self) -> EngineFuture<'_> {
        Box::pin(self.0.close())
    }
}

/// The link's news as the engine's.
fn engine_event(e: P2pEvent) -> EngineEvent {
    match e {
        P2pEvent::Reconnected => EngineEvent::Reconnected,
        P2pEvent::Ended(why) => EngineEvent::Ended(why),
    }
}

/// Joins the hub room `url` names ([`P2pLink::connect`]) and hands the link
/// back as an engine. Its events are passed on by a task that ends with
/// the link or with the reader.
///
/// # Errors
/// The URL or the hub.
pub async fn connect(
    url: &str,
    host_ip: IpAddr,
    frame_interval: Duration,
) -> Result<Joined, P2pError> {
    let (p2p_tx, mut p2p_rx) = mpsc::channel(EVENT_QUEUE);
    let link = P2pLink::connect(url, host_ip, frame_interval, p2p_tx).await?;
    let (tx, events) = mpsc::channel(EVENT_QUEUE);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tx.closed() => return,
                e = p2p_rx.recv() => {
                    let Some(e) = e else { return };
                    if tx.send(engine_event(e)).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Ok(Joined {
        engine: Arc::new(P2pEngine(link)),
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_links_news_are_the_engines() {
        assert_eq!(
            engine_event(P2pEvent::Reconnected),
            EngineEvent::Reconnected
        );
        assert_eq!(
            engine_event(P2pEvent::Ended("hub closed".to_owned())),
            EngineEvent::Ended("hub closed".to_owned())
        );
    }
}

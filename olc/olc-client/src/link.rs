// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The engine the client runs over (`transport.Transport` over an
//! `engine.Session`): the interop hub's pipe, or a carrier. The client sees
//! one surface, Go's: send and receive on the data and datagram lanes,
//! readiness, reconnect, and the peer binding (`PeerIdentity`,
//! `PeerReadyTransport`) a carrier has and the pipe does not.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use olc_net::link::{DataSink, DatagramSink, LinkEvent, SinkFuture};
use tokio::sync::mpsc;

use crate::config::{
    Config, ConfigError, ENGINE_INTEROP_PIPE, ENGINE_SALUTEJAZZ, PROVIDER_SALUTEJAZZ,
};
use crate::lane::Lane;
use crate::pipe::PipeLink;

/// How long the bring-up waits for the room to hold a peer
/// (`peerWaitTimeout`, link.go).
pub const PEER_WAIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Why the link did not come up.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The interop pipe's.
    #[error(transparent)]
    Pipe(#[from] crate::pipe::LinkError),
    /// SaluteJazz's.
    #[error(transparent)]
    SaluteJazz(#[from] olc_salutejazz::Error),
    /// The settings.
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// One engine link.
#[derive(Debug, Clone)]
pub enum Link {
    /// The interop hub.
    Pipe(Arc<PipeLink>),
    /// The SaluteJazz carrier.
    SaluteJazz(Arc<olc_salutejazz::Link>),
}

impl DataSink for Lane {
    fn push<'a>(&'a self, record: &'a mut [u8]) -> SinkFuture<'a> {
        Box::pin(Lane::push(self, record))
    }
}

impl Link {
    /// Joins the room `cfg` names with the engine it names.
    ///
    /// # Errors
    /// The engine's.
    pub async fn connect(cfg: &Config, events: mpsc::Sender<LinkEvent>) -> Result<Link, LinkError> {
        match cfg.engine_name()? {
            ENGINE_INTEROP_PIPE => Ok(Link::Pipe(PipeLink::connect(&cfg.url, events).await?)),
            ENGINE_SALUTEJAZZ => {
                let (url, password, room_id) = if cfg.provider == PROVIDER_SALUTEJAZZ {
                    let c = olc_salutejazz::auth::issue(olc_salutejazz::auth::API_BASE, &cfg.url)
                        .await?;
                    (c.url, c.token, c.room_id)
                } else {
                    (cfg.url.clone(), cfg.token.clone(), cfg.room_id.clone())
                };
                let jazz = olc_salutejazz::Config {
                    url,
                    room_id,
                    password,
                    name: cfg.participant_name(),
                    host_ip: cfg.host_ip()?,
                    relay_only: cfg.relay_only()?,
                    max_joins: cfg.max_joins,
                };
                Ok(Link::SaluteJazz(
                    olc_salutejazz::Link::connect(jazz, events).await?,
                ))
            }
            other => Err(ConfigError::Engine(other.to_owned()).into()),
        }
    }

    /// Where reliable messages go.
    pub fn set_data(&self, lane: Option<Arc<Lane>>) {
        match self {
            Link::Pipe(p) => p.set_data(lane),
            Link::SaluteJazz(j) => j.set_data(lane.map(|l| l as Arc<dyn DataSink>)),
        }
    }

    /// Where datagrams go.
    pub fn set_datagram(&self, sink: Option<DatagramSink>) {
        match self {
            Link::Pipe(p) => p.set_datagram(sink),
            Link::SaluteJazz(j) => j.set_datagram(sink),
        }
    }

    /// `PeerSeen`.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        match self {
            Link::Pipe(p) => p.peer_seen(),
            Link::SaluteJazz(j) => j.peer_seen(),
        }
    }

    /// `CanSend`.
    #[must_use]
    pub fn can_send(&self) -> bool {
        match self {
            Link::Pipe(p) => p.can_send(),
            Link::SaluteJazz(j) => j.can_send(),
        }
    }

    /// Waits up to `limit` for [`Link::can_send`].
    pub async fn wait_ready(&self, limit: Duration) -> bool {
        match self {
            Link::Pipe(p) => p.wait_ready(limit).await,
            Link::SaluteJazz(j) => j.wait_ready(limit).await,
        }
    }

    /// `Send`.
    ///
    /// # Errors
    /// The engine's.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        match self {
            Link::Pipe(p) => p.send(payload).await,
            Link::SaluteJazz(j) => j.send(payload).await,
        }
    }

    /// `SendDatagram`.
    ///
    /// # Errors
    /// The engine's.
    pub async fn send_datagram(&self, payload: &[u8]) -> io::Result<()> {
        match self {
            Link::Pipe(p) => p.send_datagram(payload).await,
            Link::SaluteJazz(j) => j.send_datagram(payload).await,
        }
    }

    /// `confirmPeer`: binds sends to the server the welcome named. The pipe
    /// has no binding (its hub has one peer per room), so it takes none.
    ///
    /// # Errors
    /// `confirm peer: ...`.
    pub async fn confirm_peer(&self, peer_id: &str) -> io::Result<()> {
        if peer_id.is_empty() {
            return Ok(());
        }
        match self {
            Link::Pipe(_) => Ok(()),
            Link::SaluteJazz(j) => j
                .confirm_peer(peer_id)
                .await
                .map_err(|e| io::Error::other(format!("confirm peer: {e}"))),
        }
    }

    /// `tunnelcore.ResetPeer`: forgets the binding.
    pub fn reset_peer(&self) {
        if let Link::SaluteJazz(j) = self {
            j.reset_peer();
        }
    }

    /// `waitForPeer`.
    ///
    /// # Errors
    /// `wait for peer: ...`.
    pub async fn wait_for_peer(&self) -> io::Result<()> {
        match self {
            Link::Pipe(_) => Ok(()),
            Link::SaluteJazz(j) => j
                .wait_for_peer(PEER_WAIT_TIMEOUT)
                .await
                .map_err(|e| io::Error::other(format!("wait for peer: {e}"))),
        }
    }

    /// Asks the engine to join again.
    pub fn reconnect(&self, reason: &str) {
        match self {
            Link::Pipe(p) => p.reconnect(reason),
            Link::SaluteJazz(j) => j.reconnect(reason),
        }
    }

    /// Leaves the room.
    pub async fn close(&self) {
        match self {
            Link::Pipe(p) => p.close().await,
            Link::SaluteJazz(j) => j.close().await,
        }
    }
}

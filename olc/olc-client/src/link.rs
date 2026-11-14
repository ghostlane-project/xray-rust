// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The engine the client runs over (`transport.Transport` over an
//! `engine.Session`): the interop hub's pipe, or a carrier. The client sees
//! one surface, Go's: send and receive on the data and datagram lanes,
//! readiness, reconnect, and the peer binding (`PeerIdentity`,
//! `PeerReadyTransport`) a carrier has and the pipe does not.
//!
//! A vp8channel link ([`Vp8Link`], over the interop-p2p engine) adds a
//! control plane of its own (`transport.ControlPlane`): the client runs a
//! lane on each plane ([`Link::set_planes`]).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use olc_net::link::{DataSink, DatagramSink, LinkEvent, SinkFuture};
use tokio::sync::mpsc;

use crate::config::{
    Config, ConfigError, ENGINE_INTEROP_P2P, ENGINE_INTEROP_PIPE, ENGINE_SALUTEJAZZ,
    PROVIDER_SALUTEJAZZ, TRANSPORT_VP8CHANNEL,
};
use crate::lane::Lane;
use crate::pipe::PipeLink;
use crate::plane::PlaneLane;
use crate::vp8link::Vp8Link;

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
    /// interop-p2p's.
    #[error(transparent)]
    P2p(#[from] crate::p2p::P2pError),
    /// The host's address for ICE.
    #[error("ice host address: {0}")]
    HostIp(io::Error),
}

/// One engine link.
#[derive(Debug, Clone)]
pub enum Link {
    /// The interop hub.
    Pipe(Arc<PipeLink>),
    /// The SaluteJazz carrier.
    SaluteJazz(Arc<olc_salutejazz::Link>),
    /// vp8channel over interop-p2p.
    Vp8(Arc<Vp8Link>),
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
        let engine = cfg.engine_name()?;
        let vp8 = cfg.transport == TRANSPORT_VP8CHANNEL;
        if vp8 != (engine == ENGINE_INTEROP_P2P) {
            return Err(ConfigError::Engine(engine.to_owned()).into());
        }
        match engine {
            ENGINE_INTEROP_P2P => {
                let host = match cfg.host_ip()? {
                    Some(ip) => ip,
                    None => olc_rtc::ice::default_ipv4().map_err(LinkError::HostIp)?,
                };
                Ok(Link::Vp8(Vp8Link::connect(cfg, host, events).await?))
            }
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
                };
                Ok(Link::SaluteJazz(
                    olc_salutejazz::Link::connect(jazz, events).await?,
                ))
            }
            other => Err(ConfigError::Engine(other.to_owned()).into()),
        }
    }

    /// Waits until the peer has settled in the room, so the first hello
    /// reaches a peer whose session is in place; the caller bounds it. The
    /// pipe: [`PipeLink::wait_peer_settled`]. SaluteJazz and vp8channel
    /// have nothing of the kind yet and return at once (Go sends the hello
    /// at once).
    pub async fn wait_peer_settled(&self) {
        match self {
            Link::Pipe(p) => p.wait_peer_settled().await,
            Link::SaluteJazz(_) | Link::Vp8(_) => {}
        }
    }

    /// Where reliable messages go (a link without a control plane).
    pub fn set_data(&self, lane: Option<Arc<Lane>>) {
        match self {
            Link::Pipe(p) => p.set_data(lane),
            Link::SaluteJazz(j) => j.set_data(lane.map(|l| l as Arc<dyn DataSink>)),
            Link::Vp8(_) => {}
        }
    }

    /// The vp8channel link, which has a control plane
    /// (`runtime.IsControlPlane`).
    #[must_use]
    pub fn vp8(&self) -> Option<&Arc<Vp8Link>> {
        match self {
            Link::Vp8(v) => Some(v),
            _ => None,
        }
    }

    /// Where each plane's records go (a link with a control plane).
    pub fn set_planes(&self, data: Option<Arc<PlaneLane>>, control: Option<Arc<PlaneLane>>) {
        if let Link::Vp8(v) = self {
            v.set_data(data.map(|l| l as Arc<dyn DataSink>));
            v.set_control(control.map(|l| l as Arc<dyn DataSink>));
        }
    }

    /// Where datagrams go.
    pub fn set_datagram(&self, sink: Option<DatagramSink>) {
        match self {
            Link::Pipe(p) => p.set_datagram(sink),
            Link::SaluteJazz(j) => j.set_datagram(sink),
            Link::Vp8(v) => v.set_datagram(sink),
        }
    }

    /// `PeerSeen`.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        match self {
            Link::Pipe(p) => p.peer_seen(),
            Link::SaluteJazz(j) => j.peer_seen(),
            Link::Vp8(v) => v.peer_seen(),
        }
    }

    /// `CanSend`.
    #[must_use]
    pub fn can_send(&self) -> bool {
        match self {
            Link::Pipe(p) => p.can_send(),
            Link::SaluteJazz(j) => j.can_send(),
            Link::Vp8(v) => v.can_send(),
        }
    }

    /// Waits up to `limit` for [`Link::can_send`].
    pub async fn wait_ready(&self, limit: Duration) -> bool {
        match self {
            Link::Pipe(p) => p.wait_ready(limit).await,
            Link::SaluteJazz(j) => j.wait_ready(limit).await,
            Link::Vp8(v) => v.wait_ready(limit, false).await,
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
            Link::Vp8(v) => v.send(payload).await,
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
            Link::Vp8(v) => v.send_datagram(payload),
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
            Link::Vp8(v) => v
                .confirm_peer(peer_id)
                .map_err(|e| io::Error::other(format!("confirm peer: {e}"))),
        }
    }

    /// `tunnelcore.ResetPeer`: forgets the binding.
    pub fn reset_peer(&self) {
        match self {
            Link::SaluteJazz(j) => j.reset_peer(),
            Link::Vp8(v) => v.reset_peer(),
            Link::Pipe(_) => {}
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
            Link::Vp8(v) => v
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
            Link::Vp8(v) => v.reconnect(reason),
        }
    }

    /// Leaves the room.
    pub async fn close(&self) {
        match self {
            Link::Pipe(p) => p.close().await,
            Link::SaluteJazz(j) => j.close().await,
            Link::Vp8(v) => v.close().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pick(json: &str) -> Result<Link, LinkError> {
        let cfg = Config::from_json(json.as_bytes()).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        Link::connect(&cfg, tx).await
    }

    /// vp8channel rides a video track: only interop-p2p has one, and
    /// interop-p2p carries nothing else; a mismatch is refused before any
    /// dial.
    #[tokio::test]
    async fn the_transport_and_the_engine_go_together() {
        crate::testing::bounded_for(Duration::from_secs(5), async {
            for json in [
                r#"{"url":"tcp://127.0.0.1:9/r","key":"k","transport":"vp8channel"}"#,
                r#"{"url":"tcp://127.0.0.1:9/r","key":"k","transport":"vp8channel","engine":"salutejazz"}"#,
                r#"{"url":"tcp://127.0.0.1:9/r","key":"k","engine":"interop-p2p"}"#,
            ] {
                let Err(err) = pick(json).await else {
                    panic!("{json} connected");
                };
                assert!(
                    matches!(err, LinkError::Config(ConfigError::Engine(_))),
                    "{json}: {err}"
                );
            }
        })
        .await;
    }

    /// The pair that goes together reaches the engine: a hub that is not
    /// there is the engine's error, not the settings'.
    #[tokio::test]
    async fn vp8channel_over_interop_p2p_dials_the_hub() {
        crate::testing::bounded_for(Duration::from_secs(5), async {
            let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = ln.local_addr().unwrap().port();
            drop(ln);
            let json = format!(
                r#"{{"url":"tcp://127.0.0.1:{port}/r","key":"k","transport":"vp8channel","engine":"interop-p2p","ice_local_ip":"127.0.0.1"}}"#
            );
            let Err(err) = pick(&json).await else {
                panic!("no hub, no link");
            };
            assert!(matches!(err, LinkError::P2p(_)), "{err}");
        })
        .await;
    }
}

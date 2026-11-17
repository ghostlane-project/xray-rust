// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The engine the client runs over (`transport.Transport` over an
//! `engine.Session`): the interop hub's pipe, or a carrier. The client sees
//! one surface, Go's: send and receive on the data and datagram lanes,
//! readiness, reconnect, and the peer binding (`PeerIdentity`,
//! `PeerReadyTransport`) a carrier has and the pipe does not.
//!
//! A vp8channel link ([`Vp8Link`], over an engine that carries video:
//! interop-p2p, MTS Link, VK Calls) adds a control plane of its own
//! (`transport.ControlPlane`): the client runs a lane on each plane
//! ([`Link::set_planes`]).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use olc_net::link::{DataSink, DatagramSink, LinkEvent, SinkFuture};
use tokio::sync::mpsc;

use crate::carrier::{BuiltIn, CarrierError, CarrierJoin, JoinError, VideoCarriers};
use crate::config::{
    Config, ConfigError, ENGINE_INTEROP_P2P, ENGINE_INTEROP_PIPE, ENGINE_MTSLINK,
    ENGINE_SALUTEJAZZ, ENGINE_VKCALLS, PROVIDER_SALUTEJAZZ, TRANSPORT_VP8CHANNEL,
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
    /// A carrier's engine that is not part of this build.
    #[error("engine {0:?} is not built into this client")]
    NotBuilt(String),
    /// A carrier's engine (MTS Link, VK Calls) did not come up.
    #[error("{engine}: {source}")]
    Carrier {
        /// The engine.
        engine: String,
        /// The carrier crate's error.
        #[source]
        source: CarrierError,
    },
}

/// One engine link.
#[derive(Debug, Clone)]
pub enum Link {
    /// The interop hub.
    Pipe(Arc<PipeLink>),
    /// The SaluteJazz carrier.
    SaluteJazz(Arc<olc_salutejazz::Link>),
    /// vp8channel over an engine that carries video.
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
        Self::connect_with(cfg, events, &BuiltIn).await
    }

    /// [`Link::connect`] with the video carriers' engines made by
    /// `carriers` (a test's fakes).
    ///
    /// # Errors
    /// The engine's.
    pub async fn connect_with(
        cfg: &Config,
        events: mpsc::Sender<LinkEvent>,
        carriers: &dyn VideoCarriers,
    ) -> Result<Link, LinkError> {
        let engine = cfg.engine_name()?;
        let vp8 = cfg.transport == TRANSPORT_VP8CHANNEL;
        // An engine with a video track runs vp8channel and nothing else,
        // and vp8channel needs one: refused before any dial.
        if vp8 != Config::engine_carries_video(engine) {
            return Err(ConfigError::Engine(engine.to_owned()).into());
        }
        match engine {
            ENGINE_INTEROP_P2P => {
                let host = match cfg.host_ip()? {
                    Some(ip) => ip,
                    None => olc_rtc::ice::default_ipv4().map_err(LinkError::HostIp)?,
                };
                let joined =
                    crate::p2p_engine::connect(&cfg.url, host, crate::vp8link::frame_interval(cfg))
                        .await?;
                Ok(Link::Vp8(Vp8Link::start(cfg, joined, events)))
            }
            ENGINE_MTSLINK | ENGINE_VKCALLS => {
                let join = CarrierJoin::from_config(cfg, engine)?;
                let joined = carriers.join(join).await.map_err(|e| match e {
                    JoinError::NotBuilt(engine) => LinkError::NotBuilt(engine),
                    JoinError::Carrier(source) => LinkError::Carrier {
                        engine: engine.to_owned(),
                        source,
                    },
                })?;
                Ok(Link::Vp8(Vp8Link::start(cfg, joined, events)))
            }
            ENGINE_INTEROP_PIPE => Ok(Link::Pipe(PipeLink::connect(&cfg.url, events).await?)),
            ENGINE_SALUTEJAZZ => {
                let (url, password, room_id, refresh) = if cfg.provider == PROVIDER_SALUTEJAZZ {
                    let base = cfg
                        .preconnect_base
                        .clone()
                        .unwrap_or_else(|| olc_salutejazz::auth::API_BASE.to_owned());
                    let c = olc_salutejazz::auth::issue(&base, &cfg.url).await?;
                    // Go's provider hook: the preconnect again before each rejoin.
                    let room_ref = cfg.url.clone();
                    let refresh: olc_salutejazz::Refresh =
                        Arc::new(move || -> olc_salutejazz::RefreshFuture {
                            let room_ref = room_ref.clone();
                            let base = base.clone();
                            Box::pin(async move {
                                olc_salutejazz::auth::issue(&base, &room_ref)
                                    .await
                                    .map_err(|e| {
                                        olc_salutejazz::Error::Other(format!(
                                            "engineconn: provider refresh: {e}"
                                        ))
                                    })
                            })
                        });
                    (c.url, c.token, c.room_id, Some(refresh))
                } else {
                    (
                        cfg.url.clone(),
                        cfg.token.clone(),
                        cfg.room_id.clone(),
                        None,
                    )
                };
                let jazz = olc_salutejazz::Config {
                    url,
                    room_id,
                    password,
                    name: cfg.participant_name(),
                    host_ip: cfg.host_ip()?,
                    relay_only: cfg.relay_only()?,
                    max_joins: cfg.max_joins,
                    refresh,
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
    /// pipe: [`PipeLink::wait_peer_settled`]; SaluteJazz:
    /// `olc_salutejazz::Link`'s, from the room's roster and its own data
    /// path, with no fixed delay; vp8channel: over interop-p2p the peer
    /// connection up for the pipe's settle time, over a carrier the peer's
    /// frames seen ([`Vp8Link::wait_peer_settled`]).
    pub async fn wait_peer_settled(&self) {
        match self {
            Link::Pipe(p) => p.wait_peer_settled().await,
            Link::SaluteJazz(j) => j.wait_peer_settled().await,
            Link::Vp8(v) => v.wait_peer_settled().await,
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
    use olc_vp8channel::channel::Carrier;
    use olc_vp8channel::engine::{
        EngineEvent, EngineFuture, FrameHandler, Joined, KeyframeHandler, VideoEngine, EVENT_QUEUE,
    };
    use olc_vp8channel::transport::Stream;

    use super::*;
    use crate::carrier::JoinFuture;

    async fn pick(json: &str) -> Result<Link, LinkError> {
        let cfg = Config::from_json(json.as_bytes()).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        Link::connect(&cfg, tx).await
    }

    /// vp8channel rides a video track: interop-p2p, MTS Link and VK Calls
    /// have one and carry nothing else
    /// (`TestMTSLinkCarriesVP8ChannelAlone`, `gate/mtslink_test.go:15`); a
    /// mismatch is refused before any dial, and before any carrier is
    /// asked.
    #[tokio::test]
    async fn the_transport_and_the_engine_go_together() {
        crate::testing::bounded_for(Duration::from_secs(5), async {
            let carriers = Fakes::default();
            for json in [
                r#"{"url":"tcp://127.0.0.1:9/r","key":"k","transport":"vp8channel"}"#,
                r#"{"url":"tcp://127.0.0.1:9/r","key":"k","transport":"vp8channel","engine":"salutejazz"}"#,
                r#"{"url":"tcp://127.0.0.1:9/r","key":"k","engine":"interop-p2p"}"#,
                r#"{"url":"https://my.mts-link.ru/j/1/2","key":"k","provider":"mtslink"}"#,
                r#"{"url":"https://my.mts-link.ru/j/1/2","key":"k","transport":"datachannel","engine":"mtslink"}"#,
                r#"{"url":"https://vk.com/call/join/x","key":"k","provider":"vkcalls"}"#,
                r#"{"url":"https://vk.com/call/join/x","key":"k","transport":"datachannel","engine":"vkcalls"}"#,
            ] {
                let cfg = Config::from_json(json.as_bytes()).unwrap();
                let (tx, _rx) = mpsc::channel(4);
                let Err(err) = Link::connect_with(&cfg, tx, &carriers).await else {
                    panic!("{json} connected");
                };
                assert!(
                    matches!(err, LinkError::Config(ConfigError::Engine(_))),
                    "{json}: {err}"
                );
            }
            assert!(carriers.asked().is_empty(), "a refused pair reached a carrier");
        })
        .await;
    }

    /// A carrier's engine in memory: VP9 for MTS Link, VP8 for VK Calls.
    struct FakeEngine(Carrier);

    impl Stream for FakeEngine {
        fn write_sample(&self, _sample: &[u8]) -> bool {
            true
        }
    }

    impl VideoEngine for FakeEngine {
        fn carrier(&self) -> Carrier {
            self.0
        }
        fn set_frame_handler(&self, _handler: Option<FrameHandler>) {}
        fn set_keyframe_handler(&self, _handler: Option<KeyframeHandler>) {}
        fn close(&self) -> EngineFuture<'_> {
            Box::pin(async {})
        }
    }

    /// The carriers as a test has them: each join is kept and answered
    /// with a fake engine, or refused.
    #[derive(Default)]
    struct Fakes {
        asked: std::sync::Mutex<Vec<CarrierJoin>>,
        refuse: bool,
        /// The engines' event senders, kept so the channels stay open.
        news: std::sync::Mutex<Vec<mpsc::Sender<EngineEvent>>>,
    }

    impl Fakes {
        fn asked(&self) -> Vec<CarrierJoin> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl VideoCarriers for Fakes {
        fn join(&self, join: CarrierJoin) -> JoinFuture<'_> {
            Box::pin(async move {
                let carrier = if join.engine == ENGINE_MTSLINK {
                    Carrier::Vp9
                } else {
                    Carrier::Vp8
                };
                self.asked.lock().unwrap().push(join);
                if self.refuse {
                    return Err(JoinError::Carrier("the room refused the guest".into()));
                }
                let (tx, events) = mpsc::channel(EVENT_QUEUE);
                self.news.lock().unwrap().push(tx);
                Ok(Joined {
                    engine: Arc::new(FakeEngine(carrier)),
                    events,
                })
            })
        }
    }

    /// vp8channel over a carrier reaches the carrier's join with what the
    /// client side asks (the room as given, `tcp` where the link names no
    /// ICE mode), and the link over its engine rides the engine's codec.
    #[tokio::test]
    async fn vp8channel_over_a_carrier_joins_through_its_crate() {
        crate::testing::bounded_for(Duration::from_secs(5), async {
            for (json, engine, via_provider, carrier) in [
                (
                    r#"{"url":"https://my.mts-link.ru/j/100200300/400500600700","key":"k","transport":"vp8channel","provider":"mtslink"}"#,
                    ENGINE_MTSLINK,
                    true,
                    Carrier::Vp9,
                ),
                (
                    r#"{"url":"https://sfu.example/rtc/room/1/join?joinToken=jt","key":"k","transport":"vp8channel","engine":"mtslink","token":"c=1"}"#,
                    ENGINE_MTSLINK,
                    false,
                    Carrier::Vp9,
                ),
                (
                    r#"{"url":"https://vk.com/call/join/AbCdEf","key":"k","transport":"vp8channel","provider":"vkcalls"}"#,
                    ENGINE_VKCALLS,
                    true,
                    Carrier::Vp8,
                ),
                (
                    r#"{"url":"wss://signal.example/ws?token=t","key":"k","transport":"vp8channel","engine":"vkcalls"}"#,
                    ENGINE_VKCALLS,
                    false,
                    Carrier::Vp8,
                ),
            ] {
                let cfg = Config::from_json(json.as_bytes()).unwrap();
                let carriers = Fakes::default();
                let (tx, _rx) = mpsc::channel(4);
                let link = match Link::connect_with(&cfg, tx, &carriers).await {
                    Ok(link) => link,
                    Err(err) => panic!("{json}: {err}"),
                };
                let asked = carriers.asked();
                assert_eq!(asked.len(), 1, "{json}");
                assert_eq!(asked[0].engine, engine);
                assert_eq!(asked[0].via_provider, via_provider, "{json}");
                assert_eq!(asked[0].room, cfg.url);
                assert_eq!(asked[0].default_ice, "tcp");
                let vp8 = link.vp8().expect("a vp8channel link");
                assert_eq!(vp8.carrier(), carrier, "{json}");
                link.close().await;
            }
        })
        .await;
    }

    /// A carrier's refusal is the link's error under the engine's name: a
    /// fake's, and the built-in VK Calls carrier's own (a guest has no
    /// account token, so its provider refuses before any request).
    #[tokio::test]
    async fn a_carriers_refusal_is_the_links_error() {
        crate::testing::bounded_for(Duration::from_secs(5), async {
            let json = r#"{"url":"https://vk.com/call/join/AbCdEf","key":"k","transport":"vp8channel","provider":"vkcalls"}"#;
            let cfg = Config::from_json(json.as_bytes()).unwrap();
            let carriers = Fakes {
                refuse: true,
                ..Fakes::default()
            };
            let (tx, _rx) = mpsc::channel(4);
            let Err(err) = Link::connect_with(&cfg, tx, &carriers).await else {
                panic!("a refused join connected");
            };
            assert_eq!(err.to_string(), "vkcalls: the room refused the guest");
            assert!(!err.to_string().contains("AbCdEf"));
            let json = r#"{"url":"https://vk.com/call/join/AbCdEf","key":"k","transport":"vp8channel","provider":"vkcalls","token":"account"}"#;
            let Err(err) = pick(json).await else {
                panic!("a refused join connected");
            };
            assert!(
                matches!(&err, LinkError::Carrier { engine, .. } if engine == ENGINE_VKCALLS),
                "{err}"
            );
            assert_eq!(
                err.to_string(),
                "vkcalls: auth provider rejected the request: \
                 vkcalls: account token is not supported for guest issue"
            );
            assert!(!err.to_string().contains("AbCdEf"));
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

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The carriers whose engines carry video (MTS Link, VK Calls), as the
//! link reaches them: what a join is given ([`CarrierJoin`], Go's
//! `builtin.Config` as far as `resolveCredentials` and `engineConfig` read
//! it) and who makes the engine ([`VideoCarriers`]).
//!
//! No carrier code lives in this crate. [`BuiltIn`] is where each carrier's
//! crate is connected (MTS Link's is); a test connects a fake instead
//! ([`crate::link::Link::connect_with`]).

use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use olc_vp8channel::engine::Joined;

use crate::config::{Config, ConfigError, DEFAULT_ICE, ENGINE_MTSLINK, PROVIDER_NONE};

/// Why a carrier's engine did not come up: the carrier crate's own error.
pub type CarrierError = Box<dyn std::error::Error + Send + Sync>;

/// A join in flight.
pub type JoinFuture<'a> = Pin<Box<dyn Future<Output = Result<Joined, JoinError>> + Send + 'a>>;

/// Why [`VideoCarriers::join`] gave no engine.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    /// The engine's crate is not part of this build.
    #[error("engine {0:?} is not built into this client")]
    NotBuilt(String),
    /// The carrier's.
    #[error(transparent)]
    Carrier(CarrierError),
}

/// What a carrier's join is given. Its `Debug` shows neither the room, the
/// token nor the credentials' values, and they are wiped when it goes.
#[derive(Clone, PartialEq, Eq)]
pub struct CarrierJoin {
    /// The engine: [`crate::config::ENGINE_MTSLINK`] or
    /// [`crate::config::ENGINE_VKCALLS`].
    pub engine: String,
    /// The room goes through the carrier's auth provider (`Provider.Issue`,
    /// again before each rejoin): `room` is the room's join link as given,
    /// its `?ice=` hint included. Otherwise the engine joins with `room`,
    /// `token` and `extra` as its credentials and has no refresh.
    pub via_provider: bool,
    /// The join link (`auth.Config.RoomURL`), or the engine's URL
    /// (`engine.Credentials.URL`).
    pub room: String,
    /// `cfg.Token`: the provider's token (VK Calls refuses one), or the
    /// engine's (`engine.Credentials.Token`).
    pub token: String,
    /// `engine.Credentials.Extra` for an engine joined without its
    /// provider. Go's direct credentials carry none
    /// (`builtin.go:197-203`): this is for the tests' fakes alone.
    pub extra: BTreeMap<String, String>,
    /// The provider's service instead of its own, for the tests' fakes;
    /// `None` is the provider's default.
    pub provider_base: Option<String>,
    /// The name shown in the room (`cfg.Name`).
    pub name: String,
    /// `auth.Config.DefaultICE`: the ICE mode a link without a hint takes.
    /// The client side's is `tcp` (`internal/client/link.go:846-852`).
    pub default_ice: &'static str,
    /// The address ICE host candidates name (`ICELocalIP`), if one is set.
    pub host_ip: Option<IpAddr>,
    /// Relayed candidates only.
    pub relay_only: bool,
    /// The most joins the run may start, rejoins included; 0 is no limit.
    pub max_joins: u32,
    /// The duration each sample the transport writes stands for.
    pub frame_interval: Duration,
}

impl CarrierJoin {
    /// The join `cfg` asks of `engine`.
    ///
    /// # Errors
    /// `ice_local_ip` or `ice_transport_policy` do not read.
    pub fn from_config(cfg: &Config, engine: &str) -> Result<Self, ConfigError> {
        let via_provider = !(cfg.provider.is_empty() || cfg.provider == PROVIDER_NONE);
        Ok(Self {
            engine: engine.to_owned(),
            via_provider,
            room: cfg.url.clone(),
            token: cfg.token.clone(),
            extra: if via_provider {
                BTreeMap::new()
            } else {
                cfg.engine_extra.clone()
            },
            provider_base: (!cfg.provider_base.is_empty()).then(|| cfg.provider_base.clone()),
            name: cfg.participant_name(),
            default_ice: DEFAULT_ICE,
            host_ip: cfg.host_ip()?,
            relay_only: cfg.relay_only()?,
            max_joins: cfg.max_joins,
            frame_interval: crate::vp8link::frame_interval(cfg),
        })
    }
}

impl std::fmt::Debug for CarrierJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |set: &str| if set.is_empty() { "" } else { "<hidden>" };
        f.debug_struct("CarrierJoin")
            .field("engine", &self.engine)
            .field("via_provider", &self.via_provider)
            .field("room", &hidden(&self.room))
            .field("token", &hidden(&self.token))
            .field("extra", &self.extra.keys().collect::<Vec<_>>())
            .field("provider_base", &self.provider_base)
            .field("name", &self.name)
            .field("default_ice", &self.default_ice)
            .field("host_ip", &self.host_ip)
            .field("relay_only", &self.relay_only)
            .field("max_joins", &self.max_joins)
            .field("frame_interval", &self.frame_interval)
            .finish()
    }
}

impl Drop for CarrierJoin {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.room);
        zeroize::Zeroize::zeroize(&mut self.token);
        for v in self.extra.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

/// Who makes a carrier's engine.
pub trait VideoCarriers: Send + Sync {
    /// Joins the room and hands back the engine in it, with its events.
    fn join(&self, join: CarrierJoin) -> JoinFuture<'_>;
}

/// The carriers this build has: MTS Link and VK Calls.
///
/// MTS Link's session is [`olc_mtslink::session`] (M6.4), VK Calls' is
/// [`olc_vkcalls::engine`] (M7.8). A carrier adds its crate to this one's
/// dependencies and one arm here, mapping the [`CarrierJoin`] to its crate's
/// settings and returning the crate's engine as a [`Joined`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BuiltIn;

impl VideoCarriers for BuiltIn {
    fn join(&self, join: CarrierJoin) -> JoinFuture<'_> {
        Box::pin(async move {
            match join.engine.as_str() {
                ENGINE_MTSLINK => olc_mtslink::session::join(olc_mtslink::session::Join {
                    via_provider: join.via_provider,
                    room: &join.room,
                    token: &join.token,
                    extra: &join.extra,
                    provider_base: join.provider_base.as_deref(),
                    name: &join.name,
                    default_ice: join.default_ice,
                    host_ip: join.host_ip,
                    frame_interval: join.frame_interval,
                    max_joins: join.max_joins,
                })
                .await
                .map_err(|e| JoinError::Carrier(Box::new(e))),
                crate::config::ENGINE_VKCALLS => vkcalls(&join).await,
                _ => Err(JoinError::NotBuilt(join.engine.clone())),
            }
        })
    }
}

/// VK Calls: the guest's chain when the room goes through the provider
/// (and again for every rejoin and every guest that flips a fresh room),
/// else the signalling endpoint as given; then the session.
async fn vkcalls(join: &CarrierJoin) -> Result<Joined, JoinError> {
    olc_vkcalls::engine::join(olc_vkcalls::engine::Join {
        via_provider: join.via_provider,
        room: &join.room,
        token: &join.token,
        ice_servers: join
            .extra
            .get(olc_vkcalls::auth::KEY_ICE_SERVERS)
            .map_or("", String::as_str),
        provider_base: join.provider_base.as_deref(),
        name: &join.name,
        host_ip: join.host_ip,
        relay_only: join.relay_only,
        max_joins: join.max_joins,
        frame_interval: join.frame_interval,
    })
    .await
    .map_err(|e| JoinError::Carrier(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ENGINE_VKCALLS;

    const MTS_ROOM: &str = "https://my.mts-link.ru/j/100200300/400500600700";

    fn join(json: &str) -> CarrierJoin {
        let cfg = Config::from_json(json.as_bytes()).unwrap();
        CarrierJoin::from_config(&cfg, cfg.engine_name().unwrap()).unwrap()
    }

    /// `TestResolveCredentialsHandsTheProviderTheDefaultICE`
    /// (`builtin/credentials_test.go:22`) with the client role's default
    /// (`TestTheClientSideAsksForTCPWhereTheLinkSaysNothing`,
    /// `client/linkrole_test.go:16`): the provider is handed the room as
    /// given and `tcp`, and a hint on the link is left for it to read.
    #[test]
    fn the_provider_is_handed_the_room_and_the_clients_default_ice() {
        for hint in ["", "?ice=udp", "?ice=both"] {
            let room = format!("{MTS_ROOM}{hint}");
            let j = join(&format!(
                r#"{{"url":"{room}","key":"k","transport":"vp8channel","provider":"mtslink","name":"Anna K","max_joins":3}}"#
            ));
            assert_eq!(j.engine, ENGINE_MTSLINK);
            assert!(j.via_provider);
            assert_eq!(j.room, room);
            assert_eq!(j.default_ice, "tcp");
            assert_eq!((j.name.as_str(), j.max_joins), ("Anna K", 3));
            assert_eq!(j.frame_interval, Duration::from_nanos(16_666_666));
            assert!(j.extra.is_empty() && j.provider_base.is_none());
        }
        let vk = join(
            r#"{"url":"https://vk.com/call/join/AbCdEf123","key":"k","transport":"vp8channel","provider":"vkcalls","ice_local_ip":"192.0.2.7","ice_transport_policy":"relay","provider_base":"http://127.0.0.1:9"}"#,
        );
        assert_eq!(vk.engine, ENGINE_VKCALLS);
        assert_eq!(vk.default_ice, "tcp");
        assert_eq!(vk.host_ip, Some("192.0.2.7".parse().unwrap()));
        assert!(vk.relay_only);
        assert_eq!(vk.provider_base.as_deref(), Some("http://127.0.0.1:9"));
    }

    /// An engine named without its provider joins with the credentials as
    /// given (`resolveCredentials` with no provider); the extra is the
    /// tests' and never goes to a provider.
    #[test]
    fn a_direct_engine_gets_its_credentials_as_given() {
        let j = join(
            r#"{"url":"https://sfu.example/rtc/room/1/join?userId=2&joinToken=jt","key":"k","transport":"vp8channel","engine":"mtslink","token":"sessionId=abc","engine_extra":{"gateway":"http://127.0.0.1:9","conferenceId":"77","ice":"udp"}}"#,
        );
        assert!(!j.via_provider);
        assert_eq!(j.token, "sessionId=abc");
        assert_eq!(j.extra.get("ice").map(String::as_str), Some("udp"));
        assert_eq!(j.extra.len(), 3);
        let p = join(&format!(
            r#"{{"url":"{MTS_ROOM}","key":"k","transport":"vp8channel","provider":"mtslink","engine_extra":{{"ice":"udp"}}}}"#
        ));
        assert!(p.via_provider && p.extra.is_empty());
        let bad =
            Config::from_json(br#"{"url":"u","key":"k","engine":"vkcalls","ice_local_ip":"nope"}"#)
                .unwrap();
        assert!(matches!(
            CarrierJoin::from_config(&bad, ENGINE_VKCALLS),
            Err(ConfigError::IceLocalIp(_))
        ));
    }

    #[test]
    fn debug_shows_neither_the_room_nor_the_credentials() {
        let j = join(
            r#"{"url":"https://sfu.example/rtc/room/1/join?joinToken=jt-secret","key":"k","transport":"vp8channel","engine":"mtslink","token":"cookie-secret","engine_extra":{"conferenceId":"conf-secret"}}"#,
        );
        let shown = format!("{j:?}");
        for secret in ["sfu.example", "jt-secret", "cookie-secret", "conf-secret"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("conferenceId"), "{shown}");
    }

    /// MTS Link's session is built in (M6.4): a join reaches the carrier's
    /// crate, which makes a peer connection and posts its offer. With no
    /// SFU there, what comes back is the carrier's own error, and nothing
    /// of the room is in it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtslink_joins_through_its_crate() {
        crate::testing::bounded_for(Duration::from_secs(20), async {
            let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = ln.local_addr().unwrap().port();
            drop(ln);
            let j = join(&format!(
                r#"{{"url":"http://127.0.0.1:{port}/rtc/room/1/join?userId=2&joinToken=jt-secret","key":"k","transport":"vp8channel","engine":"mtslink","token":"cookie-secret","ice_local_ip":"127.0.0.1"}}"#
            ));
            assert_eq!(j.engine, ENGINE_MTSLINK);
            match BuiltIn.join(j).await {
                Err(JoinError::Carrier(e)) => {
                    let text = e.to_string();
                    assert!(text.starts_with("mtslink: join: Post: "), "{text}");
                    for secret in ["jt-secret", "cookie-secret", "rtc/room", "userId"] {
                        assert!(!text.contains(secret), "{secret} in {text}");
                    }
                }
                other => panic!("{other:?}"),
            }
            // An engine joined without its provider needs the room join.
            let j = join(r#"{"url":"","key":"k","transport":"vp8channel","engine":"mtslink","ice_local_ip":"127.0.0.1"}"#);
            match BuiltIn.join(j).await {
                Err(JoinError::Carrier(e)) => {
                    assert_eq!(e.to_string(), "mtslink: room join URL missing");
                }
                other => panic!("{other:?}"),
            }
        })
        .await;
    }

    /// A VK Calls join reaches `olc-vkcalls`: the engine's own refusal for
    /// an endpoint that is none, the provider's for a token (a guest has
    /// none) and for a link that is no call's; each before any dial, and
    /// none naming the room.
    #[tokio::test]
    async fn a_vk_calls_join_reaches_its_crate() {
        let refusal = |json: &str| {
            let j = join(json);
            async move {
                match BuiltIn.join(j).await {
                    Err(JoinError::Carrier(e)) => e.to_string(),
                    other => panic!("{other:?}"),
                }
            }
        };
        assert_eq!(
            refusal(
                r#"{"url":"sfu-secret","key":"k","transport":"vp8channel","engine":"vkcalls","ice_local_ip":"127.0.0.1"}"#
            )
            .await,
            "vkcalls: invalid signaling endpoint"
        );
        assert_eq!(
            refusal(
                r#"{"url":"https://vk.com/call/join/AbCdEf123","key":"k","transport":"vp8channel","provider":"vkcalls","token":"account-secret"}"#
            )
            .await,
            "auth provider rejected the request: vkcalls: account token is not supported for guest issue"
        );
        assert_eq!(
            refusal(
                r#"{"url":"https://vk.com/call/AbCdEf123","key":"k","transport":"vp8channel","provider":"vkcalls"}"#
            )
            .await,
            "auth provider rejected the request: vkcalls: room url must be https://vk.ru/call/join/<id>"
        );
    }
}

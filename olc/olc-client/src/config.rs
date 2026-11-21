// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's settings: the parts of Go's `client.Config` the port
//! carries, read from JSON (the gate's rust flavour writes it; the FFI will
//! build it in place).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use serde::Deserialize;

/// The transport the client runs by default: messages on the engine's
/// data channel.
pub const TRANSPORT_DATACHANNEL: &str = "datachannel";
/// The transport that rides the engine's video track as VP8 frames
/// ([`crate::vp8link`]); it needs an engine with a video track, and such an
/// engine carries nothing else.
pub const TRANSPORT_VP8CHANNEL: &str = "vp8channel";

/// The interop hub's engine (`interop-pipe`, the default).
pub const ENGINE_INTEROP_PIPE: &str = "interop-pipe";
/// The SaluteJazz carrier's engine.
pub const ENGINE_SALUTEJAZZ: &str = "salutejazz";
/// The interop hub's peer-to-peer engine: signalling in a hub room, one
/// WebRTC peer connection with a video line ([`crate::p2p`]).
pub const ENGINE_INTEROP_P2P: &str = "interop-p2p";
/// The MTS Link carrier's engine: a video track its SFU forwards as VP9.
pub const ENGINE_MTSLINK: &str = "mtslink";
/// The VK Calls carrier's engine: a video track its SFU forwards as VP8.
pub const ENGINE_VKCALLS: &str = "vkcalls";
/// The Jitsi engine: XMPP signalling, the bridge's data channel; datachannel
/// transport alone (no video track, no vp8channel).
pub const ENGINE_JITSI: &str = "jitsi";

/// No auth provider: the engine joins `url` with `token` and `room_id` as
/// given (Go's `none`, the default).
pub const PROVIDER_NONE: &str = "none";
/// SaluteJazz's auth provider: `url` is the room reference
/// `<code>:<password>`, and the connector comes from its preconnect.
pub const PROVIDER_SALUTEJAZZ: &str = "salutejazz";
/// MTS Link's auth provider: `url` is the event's join link
/// (`https://my.mts-link.ru/j/<owner>/<event>`, with an optional `?ice=`
/// hint), and a guest's SFU join comes from its gateway.
pub const PROVIDER_MTSLINK: &str = "mtslink";
/// VK Calls' auth provider: `url` is the call's join link
/// (`https://vk.com/call/join/<id>`).
pub const PROVIDER_VKCALLS: &str = "vkcalls";
/// Jitsi's auth provider: `url` is the room link (`https://host/room`).
pub const PROVIDER_JITSI: &str = "jitsi";

/// The ICE mode the client side asks of a carrier whose room link names
/// none (`linkRole`'s `DefaultICE`, `internal/client/link.go:846-852`,
/// `roomhint.ICETCP`): TCP to the relay holds on mobile networks where UDP
/// goes dark. A link's own `?ice=` hint wins.
pub const DEFAULT_ICE: &str = "tcp";

/// `iceTransportPolicy: "all"`: host and relayed candidates.
pub const ICE_POLICY_ALL: &str = "all";
/// `iceTransportPolicy: "relay"`: relayed candidates only.
pub const ICE_POLICY_RELAY: &str = "relay";

/// One run of the client. Its `Debug` shows neither the key, the room's
/// password nor the SOCKS password.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The engine's URL: `tcp://host:port/room` for the interop hub, the
    /// connector's `ws://` or `wss://` URL for SaluteJazz; with a provider,
    /// the room as the provider reads it (a carrier's join link).
    pub url: String,
    /// The engine (`engine.name`): [`ENGINE_INTEROP_PIPE`] when empty, or
    /// [`ENGINE_SALUTEJAZZ`], [`ENGINE_INTEROP_P2P`], [`ENGINE_MTSLINK`],
    /// [`ENGINE_VKCALLS`], [`ENGINE_JITSI`]; a provider's own engine when it
    /// names one.
    #[serde(default)]
    pub engine: String,
    /// The auth provider (`auth.provider`): [`PROVIDER_NONE`] when empty, or
    /// [`PROVIDER_SALUTEJAZZ`], [`PROVIDER_MTSLINK`], [`PROVIDER_VKCALLS`],
    /// [`PROVIDER_JITSI`].
    #[serde(default)]
    pub provider: String,
    /// `engine.Credentials.Extra` for a carrier's engine joined without its
    /// provider. Go's direct credentials carry none
    /// (`builtin.go:197-203`), so this is for the tests' fakes alone: what
    /// a provider would have issued (MTS Link: `gateway`, `sessionId`,
    /// `userId`, `conferenceId`, `ice`; VK Calls: `ice_servers`, ...). A
    /// provider is never handed it.
    #[serde(default)]
    pub engine_extra: BTreeMap<String, String>,
    /// A carrier provider's service instead of its own (Go's tests set
    /// `Provider.gateway`), for the tests' fakes; empty is the provider's.
    #[serde(default)]
    pub provider_base: String,
    /// The room's secret the engine joins with (`cfg.Token`): the
    /// SaluteJazz room's password.
    #[serde(default)]
    pub token: String,
    /// The room's code (`Extra["roomID"]`).
    #[serde(default)]
    pub room_id: String,
    /// The name the engine shows in the room; a fresh
    /// [`crate::names::generate`] when empty, as Go's client and server
    /// always take one (`tunnelcore/transport.go:55`).
    #[serde(default)]
    pub name: String,
    /// The address the engine's ICE host candidates name (Go's
    /// `net.ice_local_ip`); the default route's when empty.
    #[serde(default)]
    pub ice_local_ip: String,
    /// WebRTC's `iceTransportPolicy`: [`ICE_POLICY_ALL`] when empty (pion's
    /// and Go's only behaviour), or [`ICE_POLICY_RELAY`], every path through
    /// the carrier's TURN servers (the interop tests' relay-only runs).
    #[serde(default)]
    pub ice_transport_policy: String,
    /// The most joins this run may start on the carrier, rejoins included;
    /// 0 is no limit (Go has none). A live test against the real service
    /// sets it, so a run spends a fixed number of joins and no more.
    #[serde(default)]
    pub max_joins: u32,
    /// More rooms to fail over to, in order (the supervisor's profiles).
    #[serde(default)]
    pub rooms: Vec<String>,
    /// The 32-byte key, hex.
    pub key: String,
    /// The transport: `datachannel` (the default) or `vp8channel`.
    #[serde(default = "datachannel")]
    pub transport: String,
    /// The room's peer-routing channel both ends set (Go's `ChannelID`,
    /// `room.channel`): vp8channel's binding token comes from it, or from
    /// the URL when it is empty.
    #[serde(default)]
    pub channel: String,
    /// vp8channel's frames a second; 0 for the app's 60.
    #[serde(default)]
    pub vp8_fps: u32,
    /// vp8channel's KCP packets a frame; 0 for 64.
    #[serde(default)]
    pub vp8_batch: usize,
    /// The resolver the server is asked to use for names, `host:port`
    /// (Go's `DNSServer`; the client sends DNS over the stream to whatever
    /// address a query names).
    #[serde(default)]
    pub dns: String,
    /// Where the SOCKS5 front listens, IPv4 (`127.0.0.1:0` for any port).
    #[serde(default = "loopback_any")]
    pub socks: String,
    /// The device id the hello carries; a fresh one when empty.
    #[serde(default)]
    pub device_id: String,
    /// The SOCKS5 login; none when the user is empty.
    #[serde(default)]
    pub socks_user: String,
    /// The SOCKS5 password.
    #[serde(default)]
    pub socks_pass: String,
    /// Refuse UDP ASSOCIATE and FWD_UDP.
    #[serde(default)]
    pub udp_disabled: bool,
    /// The most UDP flows at once; 0 for the default.
    #[serde(default)]
    pub udp_max_flows: usize,
    /// Liveness of the control stream; zero fields take Go's defaults.
    #[serde(default)]
    pub liveness: Liveness,
    /// Names and prefixes dialed directly instead of through the tunnel.
    #[serde(default)]
    pub direct: Vec<String>,
    /// Debug lines on.
    #[serde(default)]
    pub debug: bool,
    /// The liveness fallback's first pause, ms (Go's `LivenessFallback`,
    /// 30 s); 0 for the default.
    #[serde(default)]
    pub liveness_fallback_ms: u64,
    /// End the run when a reconnect finds the room empty and there are other
    /// rooms to try (set by the supervisor).
    #[serde(default)]
    pub end_on_empty_room: bool,
    /// Where the SaluteJazz preconnect goes: [`olc_salutejazz::auth::API_BASE`]
    /// when unset. No config file can set it; a test points it at a loopback
    /// port, so no test reaches the service.
    #[serde(skip)]
    pub(crate) preconnect_base: Option<String>,
}

/// `control.Config`'s three numbers.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Liveness {
    /// Between pings, ms; 0 for 10 s.
    #[serde(default)]
    pub interval_ms: u64,
    /// For a pong, ms; 0 for 15 s.
    #[serde(default)]
    pub timeout_ms: u64,
    /// Missed pongs that end the session; 0 for 4.
    #[serde(default)]
    pub failures: u32,
}

impl Liveness {
    /// The interval, defaulted.
    #[must_use]
    pub fn interval(&self) -> Duration {
        nonzero_ms(self.interval_ms, olc_wire::control::DEFAULT_INTERVAL)
    }

    /// The pong timeout, defaulted.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        nonzero_ms(self.timeout_ms, olc_wire::control::DEFAULT_TIMEOUT)
    }

    /// The failures, defaulted.
    #[must_use]
    pub fn failures(&self) -> u32 {
        if self.failures == 0 {
            olc_wire::control::DEFAULT_FAILURES
        } else {
            self.failures
        }
    }
}

fn nonzero_ms(ms: u64, default: Duration) -> Duration {
    if ms == 0 {
        default
    } else {
        Duration::from_millis(ms)
    }
}

fn datachannel() -> String {
    TRANSPORT_DATACHANNEL.to_owned()
}

fn loopback_any() -> String {
    "127.0.0.1:0".to_owned()
}

/// A config that cannot run.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Not JSON of the right shape.
    #[error("parse config: {0}")]
    Parse(String),
    /// The key is not 64 hex digits.
    #[error("setup key set: {0}")]
    Key(String),
    /// A transport the port does not carry yet.
    #[error("unsupported transport {0:?}: the Rust client carries datachannel and vp8channel")]
    Transport(String),
    /// A direct rule that does not parse (`route.ErrRule`).
    #[error("{0}")]
    Rule(String),
    /// An engine the port does not carry.
    #[error(
        "unsupported engine {0:?} for the transport: the Rust client carries interop-pipe, salutejazz and jitsi (datachannel) and interop-p2p, mtslink and vkcalls (vp8channel)"
    )]
    Engine(String),
    /// A provider the port does not carry, or one whose engine is not the
    /// one named.
    #[error(
        "unsupported auth provider {0:?}: the Rust client carries none, salutejazz, mtslink, vkcalls and jitsi"
    )]
    Provider(String),
    /// `ice_local_ip` is not an address.
    #[error("ice_local_ip {0:?} is not an IP address")]
    IceLocalIp(String),
    /// `ice_transport_policy` is neither `all` nor `relay`.
    #[error("ice_transport_policy {0:?}: all or relay")]
    IcePolicy(String),
    /// The SOCKS listen address cannot be used (`ErrInvalidConfig`).
    #[error("invalid config: {0}")]
    Socks(&'static str),
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |set: &str| if set.is_empty() { "" } else { "<hidden>" };
        f.debug_struct("Config")
            .field("url", &self.room_label(&self.url))
            .field("engine", &self.engine)
            .field("provider", &self.provider)
            .field(
                "engine_extra",
                &self.engine_extra.keys().collect::<Vec<_>>(),
            )
            .field("provider_base", &self.provider_base)
            .field("token", &hidden(&self.token))
            .field("room_id", &self.room_id)
            .field("name", &self.name)
            .field("ice_local_ip", &self.ice_local_ip)
            .field("ice_transport_policy", &self.ice_transport_policy)
            .field("max_joins", &self.max_joins)
            .field(
                "rooms",
                &self
                    .rooms
                    .iter()
                    .map(|r| self.room_label(r))
                    .collect::<Vec<_>>(),
            )
            .field("key", &hidden(&self.key))
            .field("transport", &self.transport)
            .field("channel", &self.channel)
            .field("vp8_fps", &self.vp8_fps)
            .field("vp8_batch", &self.vp8_batch)
            .field("dns", &self.dns)
            .field("socks", &self.socks)
            .field("device_id", &self.device_id)
            .field("socks_user", &self.socks_user)
            .field("socks_pass", &hidden(&self.socks_pass))
            .field("udp_disabled", &self.udp_disabled)
            .field("udp_max_flows", &self.udp_max_flows)
            .field("liveness", &self.liveness)
            .field("direct", &self.direct)
            .field("debug", &self.debug)
            .field("liveness_fallback_ms", &self.liveness_fallback_ms)
            .field("end_on_empty_room", &self.end_on_empty_room)
            .finish()
    }
}

/// The key's hex, the room's password, the SOCKS password, the rooms (a
/// SaluteJazz room carries its password, a carrier's join link is its
/// secret) and a direct engine's credentials are wiped when the settings go.
impl Drop for Config {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.token);
        wipe(&mut self.socks_pass);
        wipe(&mut self.url);
        for r in &mut self.rooms {
            wipe(r);
        }
        for v in self.engine_extra.values_mut() {
            wipe(v);
        }
    }
}

/// Zeroes the string's whole buffer; `zeroize`'s volatile writes keep the
/// wipe from being optimised away.
fn wipe(s: &mut String) {
    zeroize::Zeroize::zeroize(s);
}

impl Config {
    /// How a log line names `room`. A SaluteJazz room (`<code>:<password>`)
    /// by its code alone, never its password (Go's mobile runtime prints the
    /// whole reference); a reference that does not split as one by none of
    /// it, since it may be the password alone. An MTS Link or VK Calls
    /// room by its host alone: an MTS join link names the owner's account
    /// and the event (Go's gate withholds both ids), a VK join link is the
    /// call's whole secret, and an engine's own URL carries the guest's
    /// tokens. Another engine's room is an address and is named as it is.
    #[must_use]
    pub fn room_label(&self, room: &str) -> String {
        if self.is_video_carrier() {
            return match link_host(room) {
                Some(host) => format!("{host}/<hidden>"),
                None => "<malformed room link>".to_owned(),
            };
        }
        if self.provider != PROVIDER_SALUTEJAZZ {
            return room.to_owned();
        }
        match olc_salutejazz::auth::split_room_ref(room) {
            Ok((code, _)) => code.to_owned(),
            Err(_) => "<malformed room reference>".to_owned(),
        }
    }

    /// Whether the settings name MTS Link, VK Calls or Jitsi, by provider or
    /// by engine (it reads both, so settings that would be refused still
    /// hide their room). A Jitsi room's name is its whole secret.
    fn is_video_carrier(&self) -> bool {
        [self.provider.as_str(), self.engine.as_str()]
            .iter()
            .any(|n| matches!(*n, ENGINE_MTSLINK | ENGINE_VKCALLS | ENGINE_JITSI))
    }

    /// Reads the JSON form.
    ///
    /// # Errors
    /// [`ConfigError::Parse`].
    pub fn from_json(raw: &[u8]) -> Result<Self, ConfigError> {
        serde_json::from_slice(raw).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// The engine the link runs: the provider's for a provider that has one
    /// (`Provider.Engine()`), else `engine`, else the interop pipe.
    ///
    /// # Errors
    /// [`ConfigError::Provider`] for an unknown provider, or an `engine`
    /// that is not the provider's.
    pub fn engine_name(&self) -> Result<&str, ConfigError> {
        match self.provider.as_str() {
            "" | PROVIDER_NONE if self.engine.is_empty() => Ok(ENGINE_INTEROP_PIPE),
            "" | PROVIDER_NONE => Ok(&self.engine),
            PROVIDER_SALUTEJAZZ if self.engine.is_empty() || self.engine == ENGINE_SALUTEJAZZ => {
                Ok(ENGINE_SALUTEJAZZ)
            }
            PROVIDER_MTSLINK if self.engine.is_empty() || self.engine == ENGINE_MTSLINK => {
                Ok(ENGINE_MTSLINK)
            }
            PROVIDER_VKCALLS if self.engine.is_empty() || self.engine == ENGINE_VKCALLS => {
                Ok(ENGINE_VKCALLS)
            }
            PROVIDER_JITSI if self.engine.is_empty() || self.engine == ENGINE_JITSI => {
                Ok(ENGINE_JITSI)
            }
            other => Err(ConfigError::Provider(other.to_owned())),
        }
    }

    /// Whether `engine` carries video and so runs vp8channel and nothing
    /// else: MTS Link's SFU relays no data between guests
    /// (`TestMTSLinkCarriesVP8ChannelAlone`), VK Calls' other transport
    /// (videochannel) is not ported, interop-p2p has a video line alone.
    #[must_use]
    pub fn engine_carries_video(engine: &str) -> bool {
        matches!(engine, ENGINE_INTEROP_P2P | ENGINE_MTSLINK | ENGINE_VKCALLS)
    }

    /// The display name the engine joins with.
    #[must_use]
    pub fn participant_name(&self) -> String {
        if self.name.is_empty() {
            crate::names::generate()
        } else {
            self.name.clone()
        }
    }

    /// The ICE host address, if one is set.
    ///
    /// # Errors
    /// [`ConfigError::IceLocalIp`].
    pub fn host_ip(&self) -> Result<Option<std::net::IpAddr>, ConfigError> {
        if self.ice_local_ip.is_empty() {
            return Ok(None);
        }
        self.ice_local_ip
            .parse()
            .map(Some)
            .map_err(|_| ConfigError::IceLocalIp(self.ice_local_ip.clone()))
    }

    /// Whether only relayed candidates are used.
    ///
    /// # Errors
    /// [`ConfigError::IcePolicy`].
    pub fn relay_only(&self) -> Result<bool, ConfigError> {
        match self.ice_transport_policy.as_str() {
            "" | ICE_POLICY_ALL => Ok(false),
            ICE_POLICY_RELAY => Ok(true),
            other => Err(ConfigError::IcePolicy(other.to_owned())),
        }
    }

    /// Where the SOCKS front listens: IPv4 only, as Go listens `tcp4`
    /// (client.go:318), `localhost` being 127.0.0.1. Outside loopback a
    /// login is required (mobile/config.go:488-492): without one, anyone who
    /// reaches the port could relay CONNECT and UDP through the exit.
    ///
    /// # Errors
    /// [`ConfigError::Socks`].
    pub fn socks_listen_addr(&self) -> Result<SocketAddrV4, ConfigError> {
        let bad = ConfigError::Socks("invalid SOCKS listen address");
        let (host, port) = self.socks.rsplit_once(':').ok_or(bad.clone())?;
        let port: u16 = port.parse().map_err(|_| bad.clone())?;
        let ip = match host {
            "localhost" => Ipv4Addr::LOCALHOST,
            "" => Ipv4Addr::UNSPECIFIED,
            h => h.parse::<Ipv4Addr>().map_err(|_| bad)?,
        };
        if !ip.is_loopback() && (self.socks_user.is_empty() || self.socks_pass.is_empty()) {
            return Err(ConfigError::Socks(
                "SOCKS credentials are required outside loopback",
            ));
        }
        Ok(SocketAddrV4::new(ip, port))
    }

    /// The liveness fallback's first pause.
    #[must_use]
    pub fn liveness_fallback(&self) -> Duration {
        nonzero_ms(self.liveness_fallback_ms, DEFAULT_LIVENESS_FALLBACK)
    }
}

/// The host (and port) of a room link, for a label: what stands between
/// `scheme://` and the path, when it is a host and nothing more (letters,
/// digits, `.`, `-`, `:`; Go's `isHost`). A link with user info, or one
/// that is no URL, gives none: nothing of it is safe to show.
fn link_host(room: &str) -> Option<&str> {
    let (scheme, rest) = room.trim().split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let host = rest.split(['/', '?', '#']).next()?;
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':');
    (!host.is_empty() && host.len() <= 253 && host.bytes().all(plain)).then_some(host)
}

/// Go's `defaultLivenessFallback` (client.go): how long a recovery waits for
/// a session before it asks again.
pub const DEFAULT_LIVENESS_FALLBACK: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gates_config_reads_with_its_defaults() {
        let cfg = Config::from_json(
            br#"{"url":"tcp://127.0.0.1:9/r","key":"00","transport":"datachannel","dns":"8.8.8.8:53","socks":"127.0.0.1:0","device_id":"gate-rust"}"#,
        )
        .unwrap();
        assert_eq!(cfg.url, "tcp://127.0.0.1:9/r");
        assert_eq!(cfg.liveness.interval(), Duration::from_secs(10));
        assert_eq!(cfg.liveness.timeout(), Duration::from_secs(15));
        assert_eq!(cfg.liveness.failures(), 4);
        assert_eq!(cfg.liveness_fallback(), Duration::from_secs(30));
        assert!(cfg.rooms.is_empty() && cfg.socks_user.is_empty());
        let min = Config::from_json(br#"{"url":"u","key":"k"}"#).unwrap();
        assert_eq!(min.transport, "datachannel");
        assert_eq!(min.socks, "127.0.0.1:0");
        assert_eq!(
            (min.channel.as_str(), min.vp8_fps, min.vp8_batch),
            ("", 0, 0)
        );
    }

    #[test]
    fn the_p2p_gates_config_names_its_channel_and_numbers() {
        let cfg = Config::from_json(
            br#"{"url":"tcp://127.0.0.1:9/gate-r","key":"00","transport":"vp8channel","engine":"interop-p2p","channel":"c0ffee","vp8_fps":60,"vp8_batch":64,"ice_local_ip":"127.0.0.1"}"#,
        )
        .unwrap();
        assert_eq!(cfg.transport, TRANSPORT_VP8CHANNEL);
        assert_eq!(cfg.engine_name().unwrap(), ENGINE_INTEROP_P2P);
        assert_eq!(
            (cfg.channel.as_str(), cfg.vp8_fps, cfg.vp8_batch),
            ("c0ffee", 60, 64)
        );
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("c0ffee") && dbg.contains("vp8_batch: 64"),
            "{dbg}"
        );
    }

    #[test]
    fn a_salutejazz_config_names_its_room() {
        let cfg = Config::from_json(
            br#"{"url":"ws://127.0.0.1:9/connector","key":"k","engine":"salutejazz","token":"passw0rd","room_id":"abc123","ice_local_ip":"192.0.2.7"}"#,
        )
        .unwrap();
        assert_eq!(
            (
                cfg.engine.as_str(),
                cfg.token.as_str(),
                cfg.room_id.as_str()
            ),
            ("salutejazz", "passw0rd", "abc123")
        );
        // No name: a generated one, as Go's (never the fallback a room
        // would see on every tunnel).
        let name = cfg.participant_name();
        assert_ne!(name, crate::names::FALLBACK);
        assert!(name.split(' ').count() >= 2, "{name:?}");
        let named = Config::from_json(br#"{"url":"u","key":"k","name":"Anna K"}"#).unwrap();
        assert_eq!(named.participant_name(), "Anna K");
        assert_eq!(cfg.host_ip().unwrap(), Some("192.0.2.7".parse().unwrap()));
        let bad = Config::from_json(br#"{"url":"u","key":"k","ice_local_ip":"nope"}"#).unwrap();
        assert!(matches!(bad.host_ip(), Err(ConfigError::IceLocalIp(_))));
        let policy = |p: &str| {
            Config::from_json(
                format!(r#"{{"url":"u","key":"k","ice_transport_policy":"{p}"}}"#).as_bytes(),
            )
            .unwrap()
            .relay_only()
        };
        assert_eq!(cfg.relay_only(), Ok(false));
        assert_eq!(policy("all"), Ok(false));
        assert_eq!(policy("relay"), Ok(true));
        assert!(matches!(policy("public"), Err(ConfigError::IcePolicy(_))));
        assert_eq!(cfg.max_joins, 0);
        let capped = Config::from_json(br#"{"url":"u","key":"k","max_joins":2}"#).unwrap();
        assert_eq!(capped.max_joins, 2);
    }

    #[test]
    fn a_provider_picks_its_engine() {
        let cfg = |raw: &[u8]| Config::from_json(raw).unwrap();
        assert_eq!(
            cfg(br#"{"url":"u","key":"k"}"#).engine_name().unwrap(),
            ENGINE_INTEROP_PIPE
        );
        assert_eq!(
            cfg(br#"{"url":"u","key":"k","engine":"salutejazz"}"#)
                .engine_name()
                .unwrap(),
            ENGINE_SALUTEJAZZ
        );
        assert_eq!(
            cfg(br#"{"url":"abc123:passw0rd","key":"k","provider":"salutejazz"}"#)
                .engine_name()
                .unwrap(),
            ENGINE_SALUTEJAZZ
        );
        assert!(matches!(
            cfg(br#"{"url":"u","key":"k","provider":"salutejazz","engine":"interop-pipe"}"#)
                .engine_name(),
            Err(ConfigError::Provider(_))
        ));
        assert!(matches!(
            cfg(br#"{"url":"u","key":"k","provider":"telemost"}"#).engine_name(),
            Err(ConfigError::Provider(_))
        ));
    }

    /// `TestMtsLinkRegistered` (`builtin/registry_test.go:51`) and its VK
    /// twin, as far as the settings go: each carrier's provider and engine
    /// are known, by either name, and a provider runs its own engine alone.
    #[test]
    fn the_carriers_providers_and_engines_are_known() {
        let cfg = |raw: &str| Config::from_json(raw.as_bytes()).unwrap();
        for (provider, engine) in [
            (PROVIDER_MTSLINK, ENGINE_MTSLINK),
            (PROVIDER_VKCALLS, ENGINE_VKCALLS),
        ] {
            let by_provider = cfg(&format!(
                r#"{{"url":"u","key":"k","provider":"{provider}"}}"#
            ));
            assert_eq!(by_provider.engine_name(), Ok(engine));
            let both = cfg(&format!(
                r#"{{"url":"u","key":"k","provider":"{provider}","engine":"{engine}"}}"#
            ));
            assert_eq!(both.engine_name(), Ok(engine));
            let direct = cfg(&format!(r#"{{"url":"u","key":"k","engine":"{engine}"}}"#));
            assert_eq!(direct.engine_name(), Ok(engine));
            let none = cfg(&format!(
                r#"{{"url":"u","key":"k","provider":"none","engine":"{engine}"}}"#
            ));
            assert_eq!(none.engine_name(), Ok(engine));
            let other = cfg(&format!(
                r#"{{"url":"u","key":"k","provider":"{provider}","engine":"salutejazz"}}"#
            ));
            assert_eq!(
                other.engine_name(),
                Err(ConfigError::Provider(provider.to_owned()))
            );
            assert!(Config::engine_carries_video(engine));
        }
        assert!(Config::engine_carries_video(ENGINE_INTEROP_P2P));
        for data in [ENGINE_INTEROP_PIPE, ENGINE_SALUTEJAZZ, "jitsi", ""] {
            assert!(!Config::engine_carries_video(data), "{data}");
        }
        // The client side's default (`TestTheClientSideAsksForTCPWhereTheLinkSaysNothing`).
        assert_eq!(DEFAULT_ICE, "tcp");
    }

    /// PJ5: Jitsi's provider and engine are known by either name, and a
    /// provider runs its own engine alone; the engine carries no video.
    #[test]
    fn the_jitsi_provider_and_engine_are_known() {
        let cfg = |raw: &str| Config::from_json(raw.as_bytes()).unwrap();
        for json in [
            r#"{"url":"https://meet.example/room","key":"k","provider":"jitsi"}"#,
            r#"{"url":"https://meet.example/room","key":"k","provider":"jitsi","engine":"jitsi"}"#,
            r#"{"url":"https://meet.example/room","key":"k","engine":"jitsi"}"#,
            r#"{"url":"https://meet.example/room","key":"k","provider":"none","engine":"jitsi"}"#,
        ] {
            assert_eq!(cfg(json).engine_name(), Ok(ENGINE_JITSI), "{json}");
        }
        assert_eq!(
            cfg(r#"{"url":"u","key":"k","provider":"jitsi","engine":"salutejazz"}"#).engine_name(),
            Err(ConfigError::Provider(PROVIDER_JITSI.to_owned()))
        );
        assert!(!Config::engine_carries_video(ENGINE_JITSI));
    }

    /// D12: a Jitsi room's name is the room's whole secret, so a label shows
    /// the host alone, for the provider's link and for a direct engine's.
    #[test]
    fn a_jitsi_room_is_named_by_its_host_alone() {
        for who in [r#""provider":"jitsi""#, r#""engine":"jitsi""#] {
            let room = "https://meet.example.org/secret-room-name";
            let cfg = Config::from_json(
                format!(
                    r#"{{"url":"{room}","rooms":["{room}"],"key":"k",{who},"engine_extra":{{"room":"secret-room-name"}}}}"#
                )
                .as_bytes(),
            )
            .unwrap();
            assert_eq!(cfg.room_label(room), "meet.example.org/<hidden>", "{who}");
            let shown = format!("{cfg:?}");
            assert!(!shown.contains("secret-room-name"), "{who}: {shown}");
            // A bare name is not a link: nothing of it is shown.
            assert_eq!(cfg.room_label("secret-room-name"), "<malformed room link>");
        }
    }

    /// K6 (`TestEndpointSecretsWithholdBothIDsOfAnMTSLink`,
    /// `gate/mtslink_test.go:105`): an MTS join link names the owner and
    /// the event, a VK join link is the call's secret, and an engine's own
    /// URL carries the guest's tokens. No label and no `Debug` shows them.
    #[test]
    fn a_carriers_room_is_named_by_its_host_alone() {
        let mts = "https://my.mts-link.ru/j/100200300/400500600700";
        let vk = "https://vk.com/call/join/AbCdEfGh1234567";
        let sfu = "https://sfu7.mts-link.example/rtc/room/555666777/join?userId=888999&joinToken=jt0secret&publishToken=pt0secret";
        let cases: [(&str, &str, &str, &[&str]); 6] = [
            (
                r#""provider":"mtslink""#,
                mts,
                "my.mts-link.ru/<hidden>",
                &["100200300", "400500600700", "/j/"],
            ),
            (
                r#""provider":"mtslink""#,
                "https://my.mts-link.ru/j/100200300/400500600700/session/123456?ice=tcp",
                "my.mts-link.ru/<hidden>",
                &["100200300", "400500600700", "123456", "ice=tcp"],
            ),
            (
                r#""provider":"vkcalls""#,
                vk,
                "vk.com/<hidden>",
                &["AbCdEfGh1234567", "call/join"],
            ),
            (
                r#""engine":"mtslink""#,
                sfu,
                "sfu7.mts-link.example/<hidden>",
                &["555666777", "888999", "jt0secret", "pt0secret"],
            ),
            (
                r#""engine":"vkcalls""#,
                "wss://user:pw0secret@signal.example/ws?token=tk0secret",
                "<malformed room link>",
                &["pw0secret", "tk0secret", "signal.example"],
            ),
            (
                r#""provider":"vkcalls""#,
                "AbCdEfGh1234567",
                "<malformed room link>",
                &["AbCdEfGh1234567"],
            ),
        ];
        for (who, room, label, secrets) in cases {
            let cfg = Config::from_json(
                format!(
                    r#"{{"url":"{room}","rooms":["{room}"],"key":"k","transport":"vp8channel",{who}}}"#
                )
                .as_bytes(),
            )
            .unwrap();
            assert_eq!(cfg.room_label(room), label, "{who}");
            let shown = format!("{cfg:?}");
            for secret in secrets {
                assert!(!cfg.room_label(room).contains(secret), "{who}: {secret}");
                assert!(!shown.contains(secret), "{who}: {secret} in {shown}");
            }
        }
        // Another engine's room is an address, shown as it is.
        let hub = Config::from_json(br#"{"url":"tcp://127.0.0.1:9/r","key":"k"}"#).unwrap();
        assert_eq!(hub.room_label("tcp://127.0.0.1:9/r"), "tcp://127.0.0.1:9/r");
        // A direct engine's credentials are named by their keys alone.
        let direct = Config::from_json(
            br#"{"url":"https://sfu.example/x","key":"k","engine":"mtslink","engine_extra":{"conferenceId":"conf0secret"},"provider_base":"http://127.0.0.1:9"}"#,
        )
        .unwrap();
        let shown = format!("{direct:?}");
        assert!(
            shown.contains("conferenceId") && !shown.contains("conf0secret"),
            "{shown}"
        );
        assert_eq!(direct.provider_base, "http://127.0.0.1:9");
    }

    /// The config the Go gate writes for a carrier's fake (the overlay's
    /// `rustConfig`, `zz_rust_carriers_test.go`) is one this client reads:
    /// the file is what Go's `TestRustConfigCarriesTheCarriersTestFields`
    /// holds its own output to. The client refuses a key it does not know,
    /// so a name that differs between the two sides fails here or there.
    #[test]
    fn the_gates_carrier_config_reads() {
        let cfg = Config::from_json(include_bytes!(
            "../../interop/go-overlay/internal/gate/zz_rust_carrier_config.json"
        ))
        .unwrap();
        assert_eq!(cfg.engine_name().unwrap(), ENGINE_MTSLINK);
        assert_eq!(cfg.provider_base, "http://127.0.0.1:1");
        let extra: Vec<(&str, &str)> = cfg
            .engine_extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            extra,
            [
                ("conferenceId", "20300400600"),
                ("gateway", "http://127.0.0.1:2"),
                ("ice", "both"),
                (
                    "ice_servers",
                    r#"[{"urls":["stun:127.0.0.1:3478"]},{"credential":"p","urls":["turn:127.0.0.1:3478"],"username":"u"}]"#
                ),
            ]
        );
    }

    #[test]
    fn debug_prints_neither_the_key_nor_the_socks_password() {
        let key = "ab".repeat(32);
        let cfg = Config::from_json(
            format!(r#"{{"url":"u","key":"{key}","token":"room-pass-9","socks_user":"me","socks_pass":"hunter22"}}"#)
                .as_bytes(),
        )
        .unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains(&key), "{shown}");
        assert!(!shown.contains("room-pass-9"), "{shown}");
        assert!(!shown.contains("hunter22"), "{shown}");
        assert!(shown.contains("socks_user: \"me\""), "{shown}");
    }

    #[test]
    fn the_socks_front_listens_on_ipv4_and_outside_loopback_only_with_a_login() {
        let at = |socks: &str, user: &str, pass: &str| {
            Config::from_json(
                format!(
                    r#"{{"url":"u","key":"k","socks":"{socks}","socks_user":"{user}","socks_pass":"{pass}"}}"#
                )
                .as_bytes(),
            )
            .unwrap()
            .socks_listen_addr()
        };
        assert_eq!(
            at("127.0.0.1:0", "", ""),
            Ok("127.0.0.1:0".parse().unwrap())
        );
        assert_eq!(
            at("localhost:1080", "", ""),
            Ok("127.0.0.1:1080".parse().unwrap())
        );
        let refused = Err(ConfigError::Socks(
            "SOCKS credentials are required outside loopback",
        ));
        assert_eq!(at("0.0.0.0:1080", "", ""), refused);
        assert_eq!(at(":1080", "", ""), refused);
        assert_eq!(at("192.168.1.2:1080", "me", ""), refused);
        assert_eq!(
            at("0.0.0.0:1080", "me", "pw"),
            Ok("0.0.0.0:1080".parse().unwrap())
        );
        let invalid = Err(ConfigError::Socks("invalid SOCKS listen address"));
        assert_eq!(at("[::1]:1080", "", ""), invalid);
        assert_eq!(at("127.0.0.1", "", ""), invalid);
        assert_eq!(at("host.example:1080", "me", "pw"), invalid);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        assert!(matches!(
            Config::from_json(br#"{"url":"u","key":"k","sock":"x"}"#),
            Err(ConfigError::Parse(_))
        ));
    }
}

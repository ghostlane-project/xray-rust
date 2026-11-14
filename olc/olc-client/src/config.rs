// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's settings: the parts of Go's `client.Config` the port
//! carries, read from JSON (the gate's rust flavour writes it; the FFI will
//! build it in place).

use std::time::Duration;

use serde::Deserialize;

/// The transport the client runs: the only one the port has so far.
pub const TRANSPORT_DATACHANNEL: &str = "datachannel";

/// The interop hub's engine (`interop-pipe`, the default).
pub const ENGINE_INTEROP_PIPE: &str = "interop-pipe";
/// The SaluteJazz carrier's engine.
pub const ENGINE_SALUTEJAZZ: &str = "salutejazz";

/// No auth provider: the engine joins `url` with `token` and `room_id` as
/// given (Go's `none`, the default).
pub const PROVIDER_NONE: &str = "none";
/// SaluteJazz's auth provider: `url` is the room reference
/// `<code>:<password>`, and the connector comes from its preconnect.
pub const PROVIDER_SALUTEJAZZ: &str = "salutejazz";

/// One run of the client.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The engine's URL: `tcp://host:port/room` for the interop hub, the
    /// connector's `ws://` or `wss://` URL for SaluteJazz.
    pub url: String,
    /// The engine (`engine.name`): [`ENGINE_INTEROP_PIPE`] when empty, or
    /// [`ENGINE_SALUTEJAZZ`]; a provider's own engine when it names one.
    #[serde(default)]
    pub engine: String,
    /// The auth provider (`auth.provider`): [`PROVIDER_NONE`] when empty, or
    /// [`PROVIDER_SALUTEJAZZ`].
    #[serde(default)]
    pub provider: String,
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
    /// More rooms to fail over to, in order (the supervisor's profiles).
    #[serde(default)]
    pub rooms: Vec<String>,
    /// The 32-byte key, hex.
    pub key: String,
    /// The transport; `datachannel`.
    #[serde(default = "datachannel")]
    pub transport: String,
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
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Not JSON of the right shape.
    #[error("parse config: {0}")]
    Parse(String),
    /// The key is not 64 hex digits.
    #[error("setup key set: {0}")]
    Key(String),
    /// A transport the port does not carry yet.
    #[error("unsupported transport {0:?}: the Rust client carries datachannel")]
    Transport(String),
    /// A direct rule that does not parse (`route.ErrRule`).
    #[error("{0}")]
    Rule(String),
    /// An engine the port does not carry.
    #[error("unsupported engine {0:?}: the Rust client carries interop-pipe and salutejazz")]
    Engine(String),
    /// A provider the port does not carry, or one whose engine is not the
    /// one named.
    #[error("unsupported auth provider {0:?}: the Rust client carries none and salutejazz")]
    Provider(String),
    /// `ice_local_ip` is not an address.
    #[error("ice_local_ip {0:?} is not an IP address")]
    IceLocalIp(String),
}

impl Config {
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
            other => Err(ConfigError::Provider(other.to_owned())),
        }
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

    /// The liveness fallback's first pause.
    #[must_use]
    pub fn liveness_fallback(&self) -> Duration {
        nonzero_ms(self.liveness_fallback_ms, DEFAULT_LIVENESS_FALLBACK)
    }
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

    #[test]
    fn an_unknown_field_is_refused() {
        assert!(matches!(
            Config::from_json(br#"{"url":"u","key":"k","sock":"x"}"#),
            Err(ConfigError::Parse(_))
        ));
    }
}

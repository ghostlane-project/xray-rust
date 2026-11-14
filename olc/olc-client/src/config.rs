// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's settings: the parts of Go's `client.Config` the port
//! carries, read from JSON (the gate's rust flavour writes it; the FFI will
//! build it in place).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use serde::Deserialize;

/// The transport the client runs: the only one the port has so far.
pub const TRANSPORT_DATACHANNEL: &str = "datachannel";

/// One run of the client. Its `Debug` shows neither the key nor the SOCKS
/// password.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The engine's URL: `tcp://host:port/room` for the interop hub.
    pub url: String,
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
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
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
    /// The SOCKS listen address cannot be used (`ErrInvalidConfig`).
    #[error("invalid config: {0}")]
    Socks(&'static str),
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |set: &str| if set.is_empty() { "" } else { "<hidden>" };
        f.debug_struct("Config")
            .field("url", &self.url)
            .field("rooms", &self.rooms)
            .field("key", &hidden(&self.key))
            .field("transport", &self.transport)
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

/// The key's hex and the SOCKS password are wiped when the settings go.
impl Drop for Config {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.socks_pass);
    }
}

/// Zeroes the string's whole buffer; `zeroize`'s volatile writes keep the
/// wipe from being optimised away.
fn wipe(s: &mut String) {
    zeroize::Zeroize::zeroize(s);
}

impl Config {
    /// Reads the JSON form.
    ///
    /// # Errors
    /// [`ConfigError::Parse`].
    pub fn from_json(raw: &[u8]) -> Result<Self, ConfigError> {
        serde_json::from_slice(raw).map_err(|e| ConfigError::Parse(e.to_string()))
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
    fn debug_prints_neither_the_key_nor_the_socks_password() {
        let key = "ab".repeat(32);
        let cfg = Config::from_json(
            format!(r#"{{"url":"u","key":"{key}","socks_user":"me","socks_pass":"hunter22"}}"#)
                .as_bytes(),
        )
        .unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains(&key), "{shown}");
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
        assert_eq!(at("127.0.0.1:0", "", ""), Ok("127.0.0.1:0".parse().unwrap()));
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

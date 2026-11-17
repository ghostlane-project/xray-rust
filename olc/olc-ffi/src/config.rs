// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The runtime's settings (`mobile/config.go`): what the setters store, the
//! defaults, the checks, and the client config a start snapshots. Settings
//! persist across starts (the Android service relies on it for the rules,
//! UDP and DTLS); only the room list is read again at each hop.

use crate::error::{invalid, OlcrtcError};

/// `transportData`.
pub const TRANSPORT_DATACHANNEL: &str = "datachannel";
/// `transportVP8`: Go's default transport, the one MTS Link and VK Calls
/// carry (the interop pipe and SaluteJazz carry datachannel alone).
pub const TRANSPORT_VP8: &str = "vp8channel";

/// The transports the setters accept: Go's list
/// (`supportedTransport`, config.go:578-585) narrowed to the two the Rust
/// client is planned to carry (plan §3.3); [`CARRIED_TRANSPORTS`] are the
/// ones this build runs.
pub const TRANSPORTS: &[&str] = &[TRANSPORT_DATACHANNEL, TRANSPORT_VP8];
/// The transports this build runs.
pub const CARRIED_TRANSPORTS: &[&str] = &[TRANSPORT_DATACHANNEL, TRANSPORT_VP8];

/// `providerNone`: the room is an engine's URL, dialed directly.
pub const PROVIDER_NONE: &str = "none";
/// The providers this build carries: the client's (SaluteJazz, MTS Link,
/// VK Calls) and `none`; `set_provider` refuses any other, as Go refuses
/// one it was built without (jitsi, telemost, wbstream, max are not ported).
pub const PROVIDERS: &[&str] = &[
    PROVIDER_NONE,
    olc_client::config::PROVIDER_SALUTEJAZZ,
    olc_client::config::PROVIDER_MTSLINK,
    olc_client::config::PROVIDER_VKCALLS,
];
/// The engine `none` reaches: the interop hub's pipe (`interop-pipe`),
/// whose rooms are `tcp://host:port/name`.
pub const ENGINE_INTEROP_PIPE: &str = "interop-pipe";

/// `defaultDNSServer`.
pub const DEFAULT_DNS: &str = "8.8.8.8:53";
/// `defaultSOCKSHost`.
pub const DEFAULT_SOCKS_HOST: &str = "127.0.0.1";
/// `defaultSOCKSPort`.
pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// `defaultVP8FPS`, `defaultVP8BatchSize`.
pub const DEFAULT_VP8: (i64, i64) = (30, 64);
/// `minTrafficPayloadSize`.
pub const MIN_TRAFFIC_PAYLOAD: i64 = 53;
/// The DTLS profiles accepted (`engine.ValidateDTLSProfile`): empty or
/// `off` (the stock handshake), Go's Chrome 138 profile, and `chrome`, the
/// Rust client's BoringSSL profile (plan §8.5).
pub const DTLS_PROFILES: &[&str] = &["", "off", "chrome-linux-138-compat-v1", "chrome"];

/// `runtimeConfig`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RuntimeConfig {
    pub provider: String,
    pub transport: String,
    pub room: String,
    pub failover_rooms: Vec<String>,
    pub channel: String,
    pub key_hex: String,
    pub dns: String,
    pub dtls_profile: String,
    pub socks_host: String,
    pub socks_port: u16,
    pub socks_user: String,
    pub socks_pass: String,
    pub provider_token: String,
    pub device_id: String,
    pub device_id_path: String,
    pub engine: String,
    pub service_url: String,
    pub engine_token: String,
    pub liveness: olc_client::config::Liveness,
    pub traffic: (i64, i64, i64),
    pub vp8: (i64, i64),
    pub udp_disabled: bool,
    pub direct_rules: String,
    /// The liveness fallback's first pause, ms; 0 is the client's 30 s (no
    /// mobile setter: the gate's e2e shortens it through the driver).
    pub liveness_fallback_ms: u64,
}

impl Default for RuntimeConfig {
    /// `defaultRuntimeConfig`.
    fn default() -> Self {
        Self {
            provider: String::new(),
            transport: TRANSPORT_VP8.to_owned(),
            room: String::new(),
            failover_rooms: Vec::new(),
            channel: String::new(),
            key_hex: String::new(),
            dns: DEFAULT_DNS.to_owned(),
            dtls_profile: "off".to_owned(),
            socks_host: DEFAULT_SOCKS_HOST.to_owned(),
            socks_port: DEFAULT_SOCKS_PORT,
            socks_user: String::new(),
            socks_pass: String::new(),
            provider_token: String::new(),
            device_id: String::new(),
            device_id_path: String::new(),
            engine: String::new(),
            service_url: String::new(),
            engine_token: String::new(),
            liveness: olc_client::config::Liveness {
                interval_ms: 10_000,
                timeout_ms: 15_000,
                failures: 4,
            },
            traffic: (0, 0, 0),
            vp8: DEFAULT_VP8,
            udp_disabled: false,
            direct_rules: String::new(),
            liveness_fallback_ms: 0,
        }
    }
}

/// The key, the SOCKS password and the tokens never reach a log line.
impl std::fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hidden = |s: &str| if s.is_empty() { "" } else { "<hidden>" };
        f.debug_struct("RuntimeConfig")
            .field("provider", &self.provider)
            .field("transport", &self.transport)
            .field("room", &self.room)
            .field("failover_rooms", &self.failover_rooms)
            .field("channel", &self.channel)
            .field("key_hex", &hidden(&self.key_hex))
            .field("dns", &self.dns)
            .field("dtls_profile", &self.dtls_profile)
            .field("socks", &(&self.socks_host, self.socks_port))
            .field("socks_user", &self.socks_user)
            .field("socks_pass", &hidden(&self.socks_pass))
            .field("provider_token", &hidden(&self.provider_token))
            .field("device_id", &self.device_id)
            .field("device_id_path", &self.device_id_path)
            .field("engine", &(&self.engine, &self.service_url))
            .field("engine_token", &hidden(&self.engine_token))
            .field("liveness", &self.liveness)
            .field("traffic", &self.traffic)
            .field("vp8", &self.vp8)
            .field("udp_disabled", &self.udp_disabled)
            .field("direct_rules", &self.direct_rules.lines().count())
            .field("liveness_fallback_ms", &self.liveness_fallback_ms)
            .finish()
    }
}

impl Drop for RuntimeConfig {
    fn drop(&mut self) {
        zero(&mut self.key_hex);
        zero(&mut self.socks_pass);
        zero(&mut self.provider_token);
        zero(&mut self.engine_token);
    }
}

fn zero(s: &mut String) {
    zeroize::Zeroize::zeroize(s);
}

impl RuntimeConfig {
    /// `rooms`: the primary first (always, even empty: the `none`
    /// provider's one room), then the extras, without repeats.
    pub fn rooms(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(1 + self.failover_rooms.len());
        out.push(self.room.clone());
        for r in &self.failover_rooms {
            if !r.is_empty() && !out.contains(r) {
                out.push(r.clone());
            }
        }
        out
    }

    /// `validateRuntimeConfig`, with this build's narrower lists.
    pub fn validate(&self) -> Result<(), OlcrtcError> {
        if !PROVIDERS.contains(&self.provider.as_str()) {
            return Err(invalid(format!("provider {:?}", self.provider)));
        }
        if !CARRIED_TRANSPORTS.contains(&self.transport.as_str()) {
            return Err(invalid(format!("transport {:?}", self.transport)));
        }
        if self.provider != PROVIDER_NONE && self.room.is_empty() {
            return Err(invalid("room is required"));
        }
        if self.provider == PROVIDER_NONE
            && !(self.engine.is_empty() || self.engine == ENGINE_INTEROP_PIPE)
        {
            return Err(invalid(format!("engine {:?}", self.engine)));
        }
        self.check_engine_transport()?;
        validate_key(&self.key_hex)?;
        if self.dns.is_empty() {
            return Err(invalid("DNS server or resolver is required"));
        }
        if self.socks_host.is_empty() || self.socks_port == 0 {
            return Err(invalid("invalid SOCKS listen address"));
        }
        if !is_loopback_host(&self.socks_host)
            && (self.socks_user.is_empty() || self.socks_pass.is_empty())
        {
            return Err(invalid("SOCKS credentials are required outside loopback"));
        }
        Ok(())
    }

    /// The engine the provider (or `engine`) runs, and whether it carries
    /// the transport: the client's rule (`Config::engine_name`,
    /// `Config::engine_carries_video`), checked here so a start the client
    /// would refuse at every room is refused before it begins.
    fn check_engine_transport(&self) -> Result<(), OlcrtcError> {
        let mut probe = olc_client::Config::from_json(br#"{"url":"","key":""}"#)
            .expect("the minimal config parses");
        probe.provider.clone_from(&self.provider);
        probe.engine.clone_from(&self.engine);
        let engine = probe
            .engine_name()
            .map_err(|_| invalid(format!("engine {:?}", self.engine)))?;
        if olc_client::Config::engine_carries_video(engine) != (self.transport == TRANSPORT_VP8) {
            return Err(invalid(format!(
                "transport {:?} for engine {engine:?}",
                self.transport
            )));
        }
        Ok(())
    }

    /// `clientConfig`: the snapshot a start runs; the supervisor sets the
    /// room of each run. The client has one token: through a provider it is
    /// the provider's account token (`ProviderToken`; VK Calls refuses one
    /// for a guest, as Go's provider does), without one the engine's
    /// (`Token`). The DTLS profile is not handed on: the client has no
    /// setting for it.
    pub fn client_config(&self, device_id: String, debug: bool) -> olc_client::Config {
        let mut cfg = olc_client::Config::from_json(br#"{"url":"","key":""}"#)
            .expect("the minimal config parses");
        cfg.key.clone_from(&self.key_hex);
        cfg.transport.clone_from(&self.transport);
        cfg.provider.clone_from(&self.provider);
        cfg.engine.clone_from(&self.engine);
        cfg.token.clone_from(if self.provider == PROVIDER_NONE {
            &self.engine_token
        } else {
            &self.provider_token
        });
        cfg.channel.clone_from(&self.channel);
        let (fps, batch) = self.vp8;
        cfg.vp8_fps = u32::try_from(fps).unwrap_or(0);
        cfg.vp8_batch = usize::try_from(batch).unwrap_or(0);
        cfg.dns.clone_from(&self.dns);
        cfg.socks = join_host_port(&self.socks_host, self.socks_port);
        cfg.device_id = device_id;
        cfg.socks_user.clone_from(&self.socks_user);
        cfg.socks_pass.clone_from(&self.socks_pass);
        cfg.udp_disabled = self.udp_disabled;
        cfg.liveness = self.liveness;
        cfg.direct = direct_lines(&self.direct_rules);
        cfg.liveness_fallback_ms = self.liveness_fallback_ms;
        cfg.debug = debug;
        cfg
    }
}

/// `net.JoinHostPort`.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The rule text as the client's lines.
pub(crate) fn direct_lines(text: &str) -> Vec<String> {
    text.lines().map(str::to_owned).collect()
}

/// `validateKey`: 32 bytes of hex, worded as Go's `encoding/hex`.
pub(crate) fn validate_key(key_hex: &str) -> Result<(), OlcrtcError> {
    let bytes = key_hex.as_bytes();
    if let Some(&b) = bytes.iter().find(|b| !b.is_ascii_hexdigit()) {
        let c = char::from(b);
        return Err(invalid(format!(
            "decode key: encoding/hex: invalid byte: U+{:04X} {c:?}",
            u32::from(b)
        )));
    }
    if bytes.len() % 2 == 1 {
        return Err(invalid("decode key: encoding/hex: odd length hex string"));
    }
    if bytes.len() != 64 {
        return Err(invalid("key must be 32 bytes"));
    }
    Ok(())
}

/// `validateDNSServers`: the list `SetDNS` documents (separated by commas,
/// semicolons or spaces), each `host[:port]`, a bare host meaning port 53.
pub(crate) fn validate_dns(list: &str) -> Result<(), OlcrtcError> {
    let entries = olc_client::resolver::split_dns_servers(list);
    if entries.is_empty() {
        return Err(invalid("DNS server is required"));
    }
    for entry in entries {
        let (host, port) = split_dns_entry(entry);
        if host.trim().is_empty() {
            return Err(invalid(format!("DNS server {entry:?} has no host")));
        }
        if !matches!(port.parse::<u32>(), Ok(1..=65535)) {
            return Err(invalid(format!("DNS server {entry:?} has a bad port")));
        }
    }
    Ok(())
}

/// `net.SplitHostPort`, falling back to the whole entry and port 53.
fn split_dns_entry(entry: &str) -> (&str, &str) {
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            if let Some(port) = tail.strip_prefix(':') {
                return (host, port);
            }
            if tail.is_empty() {
                return (host, "53");
            }
        }
        return (entry.trim_matches(['[', ']']), "53");
    }
    match entry.rsplit_once(':') {
        // One colon: host:port. More: a bare IPv6 address, port 53.
        Some((host, port)) if !host.contains(':') => (host, port),
        _ => (entry, "53"),
    }
}

/// `cleanHost`: trimmed, brackets off.
pub(crate) fn clean_host(host: &str) -> String {
    let host = host.trim();
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned()
}

/// `isLoopbackHost`: `localhost` or a loopback address.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `resolveDeviceID`: the id set, else the one in the file (created with a
/// fresh id when missing), else a fresh one.
pub(crate) fn resolve_device_id(device_id: &str, path: &str) -> Result<String, String> {
    if !device_id.is_empty() {
        return Ok(device_id.to_owned());
    }
    if path.is_empty() {
        return Ok(olc_client::client::random_device_id());
    }
    match std::fs::read_to_string(path) {
        Ok(data) if !data.trim().is_empty() => return Ok(data.trim().to_owned()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("read device id {path}: {e}")),
    }
    let id = olc_client::client::random_device_id();
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir device id dir: {e}"))?;
    }
    write_private(path, format!("{id}\n").as_bytes())
        .map_err(|e| format!("write device id {path}: {e}"))?;
    Ok(id)
}

fn write_private(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_dns_and_hosts_are_checked_as_go_checks_them() {
        assert_eq!(validate_key(&"ab".repeat(32)), Ok(()));
        assert_eq!(
            validate_key("zz").unwrap_err().to_string(),
            "invalid mobile runtime configuration: decode key: encoding/hex: invalid byte: U+007A 'z'"
        );
        assert_eq!(
            validate_key("abc").unwrap_err().to_string(),
            "invalid mobile runtime configuration: decode key: encoding/hex: odd length hex string"
        );
        assert_eq!(
            validate_key("abcd").unwrap_err().to_string(),
            "invalid mobile runtime configuration: key must be 32 bytes"
        );
        // Android's list: bare IPv4, bare IPv6 with a zone, a public one with its port.
        assert_eq!(validate_dns("10.0.0.1,fe80::1%rmnet0,1.1.1.1:53"), Ok(()));
        assert_eq!(validate_dns("[2001:db8::1]:5353 8.8.8.8;9.9.9.9"), Ok(()));
        assert!(validate_dns("").is_err());
        assert!(validate_dns(":53").is_err());
        assert!(validate_dns("1.1.1.1:0").is_err());
        assert!(validate_dns("1.1.1.1:x").is_err());
        assert_eq!(clean_host(" [::1] "), "::1");
        assert!(is_loopback_host("localhost") && is_loopback_host("127.0.0.2"));
        assert!(!is_loopback_host("0.0.0.0") && !is_loopback_host("10.0.0.1"));
    }

    #[test]
    fn the_room_list_is_the_primary_then_the_extras_once_each() {
        let mut cfg = RuntimeConfig::default();
        cfg.room = "a".to_owned();
        cfg.failover_rooms = vec![
            "b".into(),
            "a".into(),
            String::new(),
            "b".into(),
            "c".into(),
        ];
        assert_eq!(cfg.rooms(), ["a", "b", "c"]);
        // The `none` provider's one room is there even empty.
        assert_eq!(RuntimeConfig::default().rooms(), [""]);
    }

    #[test]
    fn the_defaults_are_gos_and_a_start_needs_what_go_needs() {
        let d = RuntimeConfig::default();
        assert_eq!(
            (
                d.transport.as_str(),
                d.dns.as_str(),
                d.socks_host.as_str(),
                d.socks_port
            ),
            ("vp8channel", "8.8.8.8:53", "127.0.0.1", 1080)
        );
        assert_eq!(
            d.validate().unwrap_err().to_string(),
            "invalid mobile runtime configuration: provider \"\""
        );
        let mut c = RuntimeConfig::default();
        c.provider = "none".into();
        assert_eq!(
            c.validate().unwrap_err().to_string(),
            "invalid mobile runtime configuration: transport \"vp8channel\" for engine \"interop-pipe\"",
            "Go's default transport, but the interop pipe carries no video"
        );
        c.transport = "datachannel".into();
        // Go's hex.DecodeString("") is no error: the length is.
        assert_eq!(
            c.validate().unwrap_err().to_string(),
            "invalid mobile runtime configuration: key must be 32 bytes"
        );
        c.key_hex = "00".repeat(32);
        assert_eq!(c.validate(), Ok(()));
        c.socks_host = "0.0.0.0".into();
        assert_eq!(
            c.validate().unwrap_err().to_string(),
            "invalid mobile runtime configuration: SOCKS credentials are required outside loopback"
        );
        c.socks_user = "u".into();
        c.socks_pass = "p".into();
        assert_eq!(c.validate(), Ok(()));
        let client = c.client_config("dev".into(), false);
        assert_eq!(client.socks, "0.0.0.0:1080");
        assert_eq!(client.device_id, "dev");
        assert!(!format!("{c:?}").contains(&"00".repeat(32)));
    }

    /// SaluteJazz, MTS Link and VK Calls start through the runtime, each on
    /// the transport its engine carries (the client's rule: MTS Link and VK
    /// Calls run vp8channel alone, SaluteJazz datachannel), refused at the
    /// check otherwise, as an engine not the provider's is.
    #[test]
    fn the_carriers_start_on_the_transports_their_engines_carry() {
        for p in ["salutejazz", "mtslink", "vkcalls", "none"] {
            assert!(PROVIDERS.contains(&p), "{p}");
        }
        assert_eq!(CARRIED_TRANSPORTS, ["datachannel", "vp8channel"]);
        let cfg = |provider: &str, transport: &str, room: &str| {
            let mut c = RuntimeConfig::default();
            c.key_hex = "00".repeat(32);
            c.provider = provider.into();
            c.transport = transport.into();
            c.room = room.into();
            c
        };
        let link = "https://carrier.example/j/1/2";
        for provider in ["mtslink", "vkcalls"] {
            let mut c = cfg(provider, "vp8channel", link);
            assert_eq!(c.validate(), Ok(()), "{provider}");
            c.transport = "datachannel".into();
            assert_eq!(
                c.validate().unwrap_err().to_string(),
                format!(
                    "invalid mobile runtime configuration: transport \"datachannel\" for engine \"{provider}\""
                )
            );
        }
        let mut c = cfg("salutejazz", "datachannel", "code:password");
        assert_eq!(c.validate(), Ok(()));
        c.transport = "vp8channel".into();
        assert!(c.validate().is_err());
        let mut c = cfg("mtslink", "vp8channel", link);
        c.engine = "vkcalls".into();
        assert!(c.validate().is_err(), "an engine not the provider's");
        assert!(
            cfg("vkcalls", "vp8channel", "").validate().is_err(),
            "a room"
        );
    }

    /// What a start hands the client: the provider, the engine, the token
    /// (a provider's account token through a provider, the engine's own
    /// without one, as Go's `ProviderToken` and `Token`), the channel and
    /// the VP8 numbers (Go's `clientConfig`).
    #[test]
    fn a_start_hands_the_client_the_provider_channel_and_vp8_numbers() {
        let mut c = RuntimeConfig::default();
        c.key_hex = "00".repeat(32);
        c.provider = "vkcalls".into();
        c.transport = "vp8channel".into();
        c.channel = "c1".into();
        c.vp8 = (25, 32);
        c.engine_token = "eng".into();
        c.provider_token = "t0k".into();
        let client = c.client_config("dev".into(), false);
        assert_eq!(
            (
                client.provider.as_str(),
                client.transport.as_str(),
                client.channel.as_str(),
                client.vp8_fps,
                client.vp8_batch,
                client.token.as_str()
            ),
            ("vkcalls", "vp8channel", "c1", 25, 32, "t0k")
        );
        assert_eq!(client.engine_name(), Ok("vkcalls"));
        assert!(!format!("{client:?}").contains("t0k"));
        c.provider = "none".into();
        c.engine = "interop-pipe".into();
        let client = c.client_config(String::new(), false);
        assert_eq!(client.engine_name(), Ok("interop-pipe"));
        assert_eq!(client.token, "eng");
    }

    #[test]
    fn a_device_id_path_keeps_one_id_across_runs() {
        let dir = std::env::temp_dir().join(format!("olc-ffi-devid-{}", std::process::id()));
        let path = dir.join("sub").join("device-id");
        let path = path.to_str().unwrap();
        let first = resolve_device_id("", path).unwrap();
        assert_eq!(resolve_device_id("", path).unwrap(), first);
        assert_eq!(resolve_device_id("set", path).unwrap(), "set");
        assert_eq!(std::fs::read_to_string(path).unwrap(), format!("{first}\n"));
        let _ = std::fs::remove_dir_all(dir);
    }
}

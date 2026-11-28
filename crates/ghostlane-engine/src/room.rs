//! The room half of a session: the olcRTC client, joined to a room of the
//! session's list, serving a SOCKS port on loopback. It is behind the
//! `rooms` feature: a build without it carries no olc crate and refuses a
//! session that has a room half.
//!
//! The half is the phones' settings, as `OlcrtcRuntime` (olc-ffi) takes them:
//!
//! ```json
//! {
//!   "provider": "none",
//!   "transport": "datachannel",
//!   "rooms": ["tcp://hub.example:7000/name"],
//!   "key": "<64 hex digits>",
//!   "device_id": "...",
//!   "dns": "192.0.2.53:53",
//!   "socks": {"port": 0, "user": "...", "password": "..."},
//!   "udp": true,
//!   "direct_rules": "...",
//!   "dtls_profile": "chrome",
//!   "channel": "...",
//!   "vp8": {"fps": 30, "batch": 64},
//!   "debug": false
//! }
//! ```
//!
//! `provider`, `rooms` (at least one; the first is joined first, the others
//! are the failover list) and `key` are required. `transport` is the
//! carrier's own when absent (`vp8channel` for MTS Link and VK Calls,
//! `datachannel` for the others) and must be that one when given. The SOCKS
//! port is on loopback; 0 or no `socks` lets the system pick a free port,
//! which `ready` prints. Every other field is the setter of the same name and
//! keeps the runtime's default when absent. A field not listed is refused.
//!
//! The room's sockets go through the session's way out (`bind`): olc-net's
//! protector is the escape's [`Escape::bind`](crate::escape::Escape::bind),
//! told the address a TCP socket dials, so a dial to loopback is not bound.
//! Its log lines are `log` events of the room, its sessions
//! `session_opened`.

use std::net::SocketAddr;
#[cfg(not(feature = "rooms"))]
use std::time::Duration;

#[cfg(not(feature = "rooms"))]
use serde_json::Value;

#[cfg(not(feature = "rooms"))]
use crate::events::{Diagnostic, Severity, Source};
#[cfg(not(feature = "rooms"))]
use crate::session::Bind;
#[cfg(not(feature = "rooms"))]
use crate::{Ctx, Failure};

#[cfg(feature = "rooms")]
pub(crate) use carried::ask;
#[cfg(feature = "rooms")]
pub use carried::{check, start};

#[cfg(not(feature = "rooms"))]
const NOT_CARRIED: &str = "this build carries no rooms";

/// A running room.
pub struct Room {
    socks: SocketAddr,
    #[cfg(feature = "rooms")]
    runtime: std::sync::Arc<olc_ffi::OlcrtcRuntime>,
}

impl Room {
    /// Where the room's SOCKS port listens, on loopback.
    #[must_use]
    pub fn socks(&self) -> SocketAddr {
        self.socks
    }
}

#[cfg(not(feature = "rooms"))]
impl Room {
    /// Resolves when the room ends on its own, with why. It does not
    /// resolve for a hop to another room or a reconnect.
    pub async fn ended(&mut self) -> Failure {
        std::future::pending().await
    }

    /// Stops the room, waiting at most `grace` for it to leave.
    pub async fn stop(self, grace: Duration) {
        let _ = grace;
    }
}

/// Joins the room half `spec` describes and returns once its SOCKS port
/// serves. Each session it opens is printed as `session_opened`, its log
/// lines as `log` events, and its sockets go through `ctx.escape`.
///
/// # Errors
/// `room` when the room cannot be joined, `unsupported` when this build does
/// not carry rooms.
#[cfg(not(feature = "rooms"))]
pub async fn start(spec: &Value, ctx: &Ctx) -> Result<Room, Failure> {
    let _ = (spec, ctx);
    Err(Failure::unsupported(NOT_CARRIED))
}

/// What this build says of a room half, starting nothing.
#[cfg(not(feature = "rooms"))]
#[must_use]
pub fn check(spec: &Value) -> Vec<Diagnostic> {
    let _ = spec;
    vec![Diagnostic {
        severity: Severity::Error,
        source: Source::Room,
        path: None,
        message: NOT_CARRIED.to_owned(),
    }]
}

/// One join of the room half `spec` describes, alone: its first room, timed
/// to its SOCKS port, then, with `ping_url`, the best of three requests
/// through it. `Ok(Ok(millis))` is a yes, `Ok(Err(why))` a no.
///
/// # Errors
/// `room` when the half is refused, `bind` when its way out cannot be used,
/// `unsupported` when this build does not carry rooms.
#[cfg(not(feature = "rooms"))]
pub(crate) fn ask(
    spec: &Value,
    bind: Option<&Bind>,
    timeout: Duration,
    ping_url: Option<&str>,
) -> Result<Result<u64, String>, Failure> {
    let _ = (spec, bind, timeout, ping_url);
    Err(Failure::unsupported(NOT_CARRIED))
}

#[cfg(feature = "rooms")]
mod carried {
    use olc_net::net::RawFd;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;

    use olc_ffi::{LogWriter, OlcrtcError, OlcrtcRuntime, SessionListener};
    use olc_net::net::{set_peer_protector, PeerProtector};
    use serde_json::{Map, Value};

    use super::Room;
    use crate::escape::Escape;
    use crate::events::{Diagnostic, Event, Events, FailureCode, Level, Severity, Source};
    use crate::session::Bind;
    use crate::{Ctx, Failure};

    /// How often a starting room is looked at, and a running one.
    const STARTING_POLL: Duration = Duration::from_millis(50);
    const RUNNING_POLL: Duration = Duration::from_millis(250);

    const FIELDS: &[&str] = &[
        "provider",
        "transport",
        "rooms",
        "key",
        "device_id",
        "dns",
        "socks",
        "udp",
        "direct_rules",
        "dtls_profile",
        "channel",
        "vp8",
        "debug",
    ];

    /// The room half, read.
    struct Half {
        provider: String,
        transport: String,
        rooms: Vec<String>,
        key: String,
        device_id: Option<String>,
        dns: Option<String>,
        socks_port: u16,
        socks_user: String,
        socks_password: String,
        udp: Option<bool>,
        direct_rules: Option<String>,
        dtls_profile: Option<String>,
        channel: Option<String>,
        vp8: Option<(i64, i64)>,
        debug: bool,
    }

    /// What reading a half found: the errors refuse it, the warnings are
    /// remarks.
    #[derive(Default)]
    struct Findings(Vec<Diagnostic>);

    impl Findings {
        fn error(&mut self, path: &str, message: impl Into<String>) {
            self.push(Severity::Error, path, message);
        }

        fn warning(&mut self, path: &str, message: impl Into<String>) {
            self.push(Severity::Warning, path, message);
        }

        fn push(&mut self, severity: Severity, path: &str, message: impl Into<String>) {
            self.0.push(Diagnostic {
                severity,
                source: Source::Room,
                path: Some(path.to_owned()),
                message: message.into(),
            });
        }

        fn refused(&self) -> bool {
            self.0.iter().any(|found| found.severity == Severity::Error)
        }

        /// The errors as one sentence: `path: message`, joined.
        fn sentence(&self) -> String {
            self.0
                .iter()
                .filter(|found| found.severity == Severity::Error)
                .map(|found| match &found.path {
                    Some(path) => format!("{path}: {}", found.message),
                    None => found.message.clone(),
                })
                .collect::<Vec<_>>()
                .join("; ")
        }
    }

    /// The transport a carrier runs: the client carries one per engine.
    fn carrier_transport(provider: &str) -> &'static str {
        match provider {
            "mtslink" | "vkcalls" => "vp8channel",
            _ => "datachannel",
        }
    }

    fn text(half: &Map<String, Value>, name: &str, found: &mut Findings) -> Option<String> {
        match half.get(name)? {
            Value::String(text) => Some(text.clone()),
            Value::Null => None,
            _ => {
                found.error(&format!("$.{name}"), "must be a string");
                None
            }
        }
    }

    fn flag(half: &Map<String, Value>, name: &str, found: &mut Findings) -> Option<bool> {
        match half.get(name)? {
            Value::Bool(on) => Some(*on),
            Value::Null => None,
            _ => {
                found.error(&format!("$.{name}"), "must be true or false");
                None
            }
        }
    }

    fn whole(value: &Value, path: &str, range: (i64, i64), found: &mut Findings) -> Option<i64> {
        let (low, high) = range;
        match value.as_i64().filter(|n| (low..=high).contains(n)) {
            Some(n) => Some(n),
            None => {
                found.error(path, format!("must be a whole number from {low} to {high}"));
                None
            }
        }
    }

    /// An object field: its members, after refusing the ones not in `known`.
    fn object<'a>(
        half: &'a Map<String, Value>,
        name: &str,
        known: &[&str],
        found: &mut Findings,
    ) -> Option<&'a Map<String, Value>> {
        let path = format!("$.{name}");
        match half.get(name)? {
            Value::Object(members) => {
                for member in members.keys() {
                    if !known.contains(&member.as_str()) {
                        found.error(
                            &format!("{path}.{member}"),
                            "is not a field of the room half",
                        );
                    }
                }
                Some(members)
            }
            Value::Null => None,
            _ => {
                found.error(&path, "must be an object");
                None
            }
        }
    }

    /// Reads a half by hand, so that no message quotes a value of it: a key
    /// or a password is never in a finding.
    fn read(spec: &Value) -> (Option<Half>, Findings) {
        let mut found = Findings::default();
        let Value::Object(half) = spec else {
            found.0.push(Diagnostic {
                severity: Severity::Error,
                source: Source::Room,
                path: None,
                message: "the room half must be an object".to_owned(),
            });
            return (None, found);
        };
        for name in half.keys() {
            if !FIELDS.contains(&name.as_str()) {
                found.error(&format!("$.{name}"), "is not a field of the room half");
            }
        }

        let absent = |name: &str| matches!(half.get(name), None | Some(Value::Null));
        let provider = text(half, "provider", &mut found);
        if absent("provider") {
            found.error("$.provider", "is required");
        }
        let transport = text(half, "transport", &mut found);

        let mut rooms = Vec::new();
        match half.get("rooms") {
            None | Some(Value::Null) => found.error("$.rooms", "is required"),
            Some(Value::Array(list)) => {
                for (index, room) in list.iter().enumerate() {
                    match room.as_str().map(str::trim) {
                        Some(room) if !room.is_empty() => rooms.push(room.to_owned()),
                        _ => found.error(&format!("$.rooms[{index}]"), "must be a room, a string"),
                    }
                }
                if list.is_empty() {
                    found.error("$.rooms", "must name at least one room");
                }
                let mut seen = HashSet::new();
                if rooms.iter().any(|room| !seen.insert(room)) {
                    found.warning("$.rooms", "the room list holds one room twice");
                }
            }
            Some(_) => found.error("$.rooms", "must be a list of rooms"),
        }

        let key = text(half, "key", &mut found);
        if absent("key") {
            found.error("$.key", "is required");
        }
        if key
            .as_ref()
            .is_some_and(|key| key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            found.error("$.key", "must be 64 hex digits (32 bytes)");
        }

        let (mut socks_port, mut socks_user, mut socks_password) =
            (0, String::new(), String::new());
        if let Some(socks) = object(half, "socks", &["port", "user", "password"], &mut found) {
            if let Some(port) = socks.get("port").filter(|port| !port.is_null()) {
                socks_port = whole(port, "$.socks.port", (0, 65_535), &mut found)
                    .and_then(|port| u16::try_from(port).ok())
                    .unwrap_or(0);
            }
            for (name, into) in [("user", &mut socks_user), ("password", &mut socks_password)] {
                match socks.get(name) {
                    None | Some(Value::Null) => {}
                    Some(Value::String(text)) => text.clone_into(into),
                    Some(_) => found.error(&format!("$.socks.{name}"), "must be a string"),
                }
            }
        }

        let mut vp8 = None;
        if let Some(options) = object(half, "vp8", &["fps", "batch"], &mut found) {
            let fps = options
                .get("fps")
                .map_or(Some(0), |fps| whole(fps, "$.vp8.fps", (1, 120), &mut found));
            let batch = options.get("batch").map_or(Some(0), |batch| {
                whole(batch, "$.vp8.batch", (1, i64::from(u16::MAX)), &mut found)
            });
            if let (Some(fps), Some(batch)) = (fps, batch) {
                vp8 = Some((fps, batch));
            }
        }

        let device_id = text(half, "device_id", &mut found);
        let dns = text(half, "dns", &mut found);
        let direct_rules = text(half, "direct_rules", &mut found);
        let dtls_profile = text(half, "dtls_profile", &mut found);
        let channel = text(half, "channel", &mut found);
        let udp = flag(half, "udp", &mut found);
        let debug = flag(half, "debug", &mut found).unwrap_or(false);

        if found.refused() {
            return (None, found);
        }
        let (Some(provider), Some(key)) = (provider, key) else {
            return (None, found);
        };
        let own = carrier_transport(&provider);
        let transport = transport.unwrap_or_else(|| own.to_owned());
        let half = Half {
            provider,
            transport,
            rooms,
            key,
            device_id,
            dns,
            socks_port,
            socks_user,
            socks_password,
            udp,
            direct_rules,
            dtls_profile,
            channel,
            vp8,
            debug,
        };
        (Some(half), found)
    }

    /// A setter's refusal in its own words, without the runtime's prefix.
    fn said(error: &OlcrtcError) -> String {
        match error {
            OlcrtcError::InvalidConfig(detail) => detail.clone(),
            other => other.to_string(),
        }
    }

    /// Hands the half to `runtime` through its setters; `port` is the SOCKS
    /// port of a run (a one-shot asks with its own). The first refusal, at
    /// its field.
    fn apply(
        half: &Half,
        runtime: &OlcrtcRuntime,
        port: Option<u16>,
    ) -> Result<(), (String, String)> {
        let at = |path: &str| {
            let path = path.to_owned();
            move |error: OlcrtcError| (path, said(&error))
        };
        runtime
            .set_provider(half.provider.clone())
            .map_err(at("$.provider"))?;
        runtime
            .set_transport(half.transport.clone())
            .map_err(at("$.transport"))?;
        let own = carrier_transport(&half.provider);
        if half.transport != own {
            return Err((
                "$.transport".to_owned(),
                format!("the `{}` carrier runs `{own}` alone", half.provider),
            ));
        }
        let (first, others) = half.rooms.split_first().ok_or_else(|| {
            (
                "$.rooms".to_owned(),
                "must name at least one room".to_owned(),
            )
        })?;
        runtime.set_room(first.clone()).map_err(at("$.rooms[0]"))?;
        runtime.clear_failover_rooms();
        for (index, room) in others.iter().enumerate() {
            runtime
                .add_failover_room(room.clone())
                .map_err(at(&format!("$.rooms[{}]", index + 1)))?;
        }
        runtime.set_key(half.key.clone()).map_err(|_| {
            (
                "$.key".to_owned(),
                "must be 64 hex digits (32 bytes)".to_owned(),
            )
        })?;
        if let Some(dns) = &half.dns {
            runtime.set_dns(dns.clone()).map_err(at("$.dns"))?;
        }
        if let Some(profile) = &half.dtls_profile {
            runtime
                .set_dtls_profile(profile.clone())
                .map_err(at("$.dtls_profile"))?;
        }
        if let Some(rules) = &half.direct_rules {
            runtime
                .set_direct_rules(rules.clone())
                .map_err(at("$.direct_rules"))?;
        }
        if let Some((fps, batch)) = half.vp8 {
            let (default_fps, default_batch) = (30, 64);
            let fps = if fps == 0 { default_fps } else { fps };
            let batch = if batch == 0 { default_batch } else { batch };
            runtime.set_vp8_options(fps, batch).map_err(at("$.vp8"))?;
        }
        if let Some(port) = port {
            runtime
                .set_socks_listen_host(Ipv4Addr::LOCALHOST.to_string())
                .map_err(at("$.socks"))?;
            runtime
                .set_socks_port(i64::from(port))
                .map_err(at("$.socks.port"))?;
            runtime
                .set_socks_credentials(half.socks_user.clone(), half.socks_password.clone())
                .map_err(at("$.socks"))?;
        }
        if let Some(channel) = &half.channel {
            runtime.set_channel(channel.clone());
        }
        if let Some(device) = &half.device_id {
            runtime.set_device_id(device.clone());
        }
        if let Some(udp) = half.udp {
            runtime.set_udp(udp);
        }
        runtime.set_debug(half.debug);
        Ok(())
    }

    /// A half that was read, handed to a fresh runtime.
    struct Prepared {
        half: Half,
        remarks: Vec<Diagnostic>,
        runtime: Arc<OlcrtcRuntime>,
        /// The SOCKS port of a run; 0 for a one-shot, which asks with its
        /// own.
        port: u16,
    }

    /// The half read and handed to a fresh runtime, or why not. `serves`:
    /// for a run, whose SOCKS port is the session's or a free one.
    fn prepare(spec: &Value, serves: bool) -> Result<Prepared, Failure> {
        let refused = |sentence: String| Failure::new(FailureCode::Room, sentence);
        let (half, found) = read(spec);
        let Some(half) = half else {
            return Err(refused(found.sentence()));
        };
        let port = match (serves, half.socks_port) {
            (false, _) => 0,
            (true, 0) => free_port()?,
            (true, port) => port,
        };
        let runtime = OlcrtcRuntime::new();
        apply(&half, &runtime, serves.then_some(port))
            .map_err(|(path, message)| refused(format!("{path}: {message}")))?;
        Ok(Prepared {
            half,
            remarks: found.0,
            runtime,
            port,
        })
    }

    /// Room sockets leave by the session's way out, through olc-net's
    /// protector, which is told the address a TCP socket dials: the escape
    /// leaves a dial to loopback (a hub on this machine) unbound, as the
    /// core's protector does, and binds every other socket, a UDP socket
    /// (whose peers are not known when it is opened) among them. It is the
    /// process's one protector, as olc-ffi's setter would install it; a
    /// session without a way out removes it.
    fn protect_through(escape: Option<Escape>, events: &Events) {
        let protector = escape.map(|escape| -> PeerProtector {
            let events = events.clone();
            Arc::new(move |fd: RawFd, peer: Option<SocketAddr>| {
                match escape.bind(i64::from(fd), peer) {
                    Ok(()) => true,
                    Err(error) => {
                        events.log(
                            Level::Warning,
                            format!(
                                "a socket of the room could not be bound to `{}`: {error}",
                                escape.interface()
                            ),
                        );
                        false
                    }
                }
            })
        });
        set_peer_protector(protector);
    }

    /// The room's log lines, as `log` events: one per line, without the
    /// newline the client ends each with.
    struct RoomLog(Events);

    impl LogWriter for RoomLog {
        fn write_log(&self, msg: String) {
            for line in msg.lines().filter(|line| !line.trim().is_empty()) {
                self.0.emit(&Event::Log {
                    source: Source::Room,
                    level: Level::Info,
                    line: line.to_owned(),
                });
            }
        }
    }

    struct Opened(Events);

    impl SessionListener for Opened {
        fn on_session_opened(&self, room: String, session_id: String) {
            self.0.emit(&Event::SessionOpened { room, session_id });
        }
    }

    /// A free port on loopback, for a room whose session leaves it to the
    /// system: the runtime takes a port, not 0.
    fn free_port() -> Result<u16, Failure> {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .map(|address| address.port())
            .map_err(|error| {
                Failure::new(
                    FailureCode::Room,
                    format!("no port on loopback for the room's SOCKS: {error}"),
                )
            })
    }

    /// Why a generation that is no longer active ended.
    fn end_of(runtime: &OlcrtcRuntime) -> Failure {
        let why = match runtime.wait_ready(1) {
            Err(error) => error.to_string(),
            Ok(()) => "it stopped".to_owned(),
        };
        Failure::new(FailureCode::Room, format!("the room ended: {why}"))
    }

    /// Stops a room whose start was given up (a stop asked for while it
    /// joined), so it leaves its room; its lines go to stderr from then on.
    struct Abandon(Option<Arc<OlcrtcRuntime>>);

    impl Drop for Abandon {
        fn drop(&mut self) {
            if let Some(runtime) = self.0.take() {
                olc_ffi::set_log_writer(None);
                let _ = runtime.stop(1);
            }
        }
    }

    /// Joins the room half `spec` describes and returns once its SOCKS port
    /// serves. Each session it opens is printed as `session_opened`, its log
    /// lines as `log` events, and its sockets go through `ctx.escape`.
    ///
    /// # Errors
    /// `room` when the half is refused, or the room ends before it serves.
    pub async fn start(spec: &Value, ctx: &Ctx) -> Result<Room, Failure> {
        let Prepared {
            remarks,
            runtime,
            port,
            ..
        } = prepare(spec, true)?;
        for remark in remarks {
            ctx.events.emit(&Event::Warning {
                source: remark.source,
                path: remark.path,
                message: remark.message,
            });
        }
        protect_through(ctx.escape.clone(), &ctx.events);
        olc_ffi::set_log_writer(Some(Arc::new(RoomLog(ctx.events.clone()))));
        runtime.set_session_listener(Some(Arc::new(Opened(ctx.events.clone()))));
        runtime.start().map_err(|error| {
            Failure::new(
                FailureCode::Room,
                format!("the room could not start: {error}"),
            )
        })?;
        let mut abandon = Abandon(Some(Arc::clone(&runtime)));
        loop {
            match runtime.state().as_str() {
                "running" => break,
                "starting" => tokio::time::sleep(STARTING_POLL).await,
                _ => {
                    abandon.0 = None;
                    return Err(end_of(&runtime));
                }
            }
        }
        abandon.0 = None;
        Ok(Room {
            socks: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            runtime,
        })
    }

    impl Room {
        /// Resolves when the room ends on its own, with why: every room of
        /// its list was tried. It does not resolve for a hop to another room
        /// or a reconnect.
        pub async fn ended(&mut self) -> Failure {
            while self.runtime.is_running() {
                tokio::time::sleep(RUNNING_POLL).await;
            }
            end_of(&self.runtime)
        }

        /// Stops the room, waiting at most `grace` for it to leave.
        pub async fn stop(self, grace: Duration) {
            let runtime = Arc::clone(&self.runtime);
            let millis = i64::try_from(grace.as_millis()).unwrap_or(i64::MAX).max(1);
            let _ = tokio::task::spawn_blocking(move || runtime.stop(millis)).await;
            olc_ffi::set_log_writer(None);
        }
    }

    /// What this build says of a room half, starting nothing: every field is
    /// read and handed to a runtime that is never started.
    #[must_use]
    pub fn check(spec: &Value) -> Vec<Diagnostic> {
        let (half, mut found) = read(spec);
        if let Some(half) = half {
            let runtime = OlcrtcRuntime::new();
            // A port of 0 is the system's pick at the start: any port passes.
            let port = if half.socks_port == 0 {
                1
            } else {
                half.socks_port
            };
            if let Err((path, message)) = apply(&half, &runtime, Some(port)) {
                found.error(&path, message);
            }
        }
        found.0
    }

    /// A one-shot's refusal of the half or the runtime, as against an answer
    /// that is a no.
    fn is_refusal(error: &OlcrtcError) -> bool {
        matches!(
            error,
            OlcrtcError::InvalidConfig(_)
                | OlcrtcError::UnsupportedProvider(_)
                | OlcrtcError::UnsupportedTransport(_)
                | OlcrtcError::Setting(_)
        )
    }

    /// One join of the room half `spec` describes, alone: its first room,
    /// timed to its SOCKS port, then, with `ping_url`, the best of three
    /// requests through it. `Ok(Ok(millis))` is a yes, `Ok(Err(why))` a no.
    /// Nothing is printed: the way out is opened quietly, and the room's log
    /// lines go to stderr.
    ///
    /// # Errors
    /// `room` when the half is refused, `bind` when its way out cannot be
    /// used.
    pub(crate) fn ask(
        spec: &Value,
        bind: Option<&Bind>,
        timeout: Duration,
        ping_url: Option<&str>,
    ) -> Result<Result<u64, String>, Failure> {
        let Prepared { half, runtime, .. } = prepare(spec, false)?;
        let quiet = Events::to(Box::new(std::io::sink()));
        let escape = bind.map(|bind| Escape::open(bind, &quiet)).transpose()?;
        protect_through(escape, &quiet);
        let millis = i64::try_from(timeout.as_millis()).unwrap_or(i64::MAX);
        let (fps, batch) = half.vp8.unwrap_or((0, 0));
        let first = half.rooms[0].clone();
        let device = half.device_id.clone().unwrap_or_default();
        let asked = match ping_url {
            None => runtime.check(
                half.provider.clone(),
                half.transport.clone(),
                first,
                device,
                half.key.clone(),
                0,
                millis,
                fps,
                batch,
            ),
            Some(url) => runtime.ping(
                half.provider.clone(),
                half.transport.clone(),
                first,
                device,
                half.key.clone(),
                0,
                millis,
                url.to_owned(),
                fps,
                batch,
            ),
        };
        match asked {
            Ok(millis) => Ok(Ok(u64::try_from(millis).unwrap_or(0))),
            Err(error) if is_refusal(&error) => {
                Err(Failure::new(FailureCode::Room, error.to_string()))
            }
            Err(error) => Ok(Err(error.to_string())),
        }
    }
}

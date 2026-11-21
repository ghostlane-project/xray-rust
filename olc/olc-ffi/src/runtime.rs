// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `OlcrtcRuntime`: gomobile's `mobile.Runtime` (`mobile/runtime.go`,
//! `config.go`, `listener.go`, `protector.go`), call for call.
//!
//! A start snapshots the settings into a generation that runs on the
//! process's one runtime (`ghostlane_runtime`), under the room supervisor:
//! the rooms are the runtime's, read again at every hop, so a room the app
//! adds while a session is live is used when that session ends
//! (`AddFailoverRoom`, the iOS RoomKeeper's "live, no restart"). Every call
//! is synchronous, as gomobile's are; the waits block the caller's thread,
//! never a runtime worker (a call from a worker moves the worker's other
//! tasks off first).

use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use olc_client::supervisor::{self, Reload};
use tokio_util::sync::CancellationToken;

use crate::callbacks::{SessionListener, SocketProtector};
use crate::config::{self, RuntimeConfig, PROVIDERS, TRANSPORTS};
use crate::error::{invalid, OlcrtcError};

/// `defaultReadyTimeout`.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(8);
/// `defaultStopTimeout`.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// `runtimeState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Starting,
    Running,
    Stopping,
    Stopped,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Starting => "starting",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
            Phase::Stopped => "stopped",
        }
    }

    /// `isActiveLocked`.
    fn active(self) -> bool {
        matches!(self, Phase::Starting | Phase::Running | Phase::Stopping)
    }
}

/// One room's run, as the supervisor starts it.
pub struct RoomRun {
    /// The generation's settings with this room in `url`.
    pub cfg: olc_client::Config,
    /// Cancelled when the generation stops.
    pub stop: CancellationToken,
    /// To be told the SOCKS address once it listens.
    pub on_ready: Box<dyn FnOnce(SocketAddr) + Send>,
    /// To be told each session id as a session opens.
    pub on_session_open: olc_client::client::SessionListener,
}

/// What runs one room (`clientRunner`): the client, or a test's stand-in.
pub type Runner = Arc<dyn Fn(RoomRun) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

/// `runPublicClient`: the client, its error wrapped as the mobile runtime
/// and `pkg/olcrtc/client` wrap it.
fn client_runner() -> Runner {
    Arc::new(|run: RoomRun| {
        async move {
            let RoomRun {
                cfg,
                stop,
                on_ready,
                on_session_open,
            } = run;
            olc_client::Client::run_with(cfg, stop, on_ready, Some(on_session_open))
                .await
                .map_err(|e| format!("run public client: client: {e}"))
        }
        .boxed()
    })
}

/// `runGeneration`'s latches, guarded by its own lock (taken after the
/// runtime's when both are held).
#[derive(Debug, Default)]
struct Flags {
    ready: bool,
    done: bool,
    stop_requested: bool,
    err: Option<OlcrtcError>,
}

struct Generation {
    id: u64,
    cfg: olc_client::Config,
    device: (String, String),
    cancel: CancellationToken,
    flags: Mutex<Flags>,
    changed: Condvar,
}

impl Generation {
    fn flags(&self) -> MutexGuard<'_, Flags> {
        self.flags.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until `until` holds or `deadline` passes; the flags then.
    fn wait(&self, deadline: Instant, until: impl Fn(&Flags) -> bool) -> MutexGuard<'_, Flags> {
        off_worker(|| {
            let mut f = self.flags();
            while !until(&f) {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                f = self
                    .changed
                    .wait_timeout(f, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            f
        })
    }
}

/// A wait called from a runtime worker would hold the worker the run needs
/// (the iOS runtime has one): `block_in_place` hands its tasks to another
/// thread first.
pub(crate) fn off_worker<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// The signalling's TLS, before anything dials a carrier: the host's own
/// when it installed one (the carriers' tests do), else the shaped connector
/// the CLI installs. A start needs it, and so does a check or a ping made
/// before any start (the desktop's one-shots, a phone's check of a room it
/// has not joined yet): without it their first `https://` dial ended in `no
/// TLS connector installed for a TLS URL`. Whoever comes first installs it;
/// the next finds it there and leaves it alone.
///
/// # Errors
/// The connector could not be built.
pub(crate) fn ensure_signalling_tls() -> Result<(), String> {
    if !olc_net::stream::tls_connector_installed() {
        olc_net::shaped_tls::install(olc_net::shaped_tls::FINGERPRINT)
            .map_err(|e| format!("olcRTC runtime: tls: {e}"))?;
    }
    Ok(())
}

struct State {
    defaults: RuntimeConfig,
    phase: Phase,
    next_generation: u64,
    current: Option<Arc<Generation>>,
    listener: Option<Arc<dyn SessionListener>>,
}

struct Shared {
    st: Mutex<State>,
    runner: Runner,
    /// The pause between rooms (`failoverRetryDelay`).
    retry_delay: Duration,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_current(st: &State, gen: &Generation) -> bool {
        st.current.as_ref().is_some_and(|c| c.id == gen.id)
    }

    /// `profilesSnapshot`: the rooms now, under the lock.
    fn rooms(&self) -> Vec<String> {
        self.lock().defaults.rooms()
    }

    /// `markReady`.
    fn mark_ready(&self, gen: &Generation) {
        let mut st = self.lock();
        if !Self::is_current(&st, gen) || st.phase != Phase::Starting {
            return;
        }
        st.phase = Phase::Running;
        gen.flags().ready = true;
        gen.changed.notify_all();
    }

    /// `notifySessionOpened`: a stopping or replaced generation is not
    /// heard.
    fn notify_session_opened(&self, gen: &Generation, room: &str, session_id: &str) {
        let listener = {
            let st = self.lock();
            let live = Self::is_current(&st, gen) && !gen.flags().stop_requested;
            if !live {
                return;
            }
            st.listener.clone()
        };
        if let Some(l) = listener {
            l.on_session_opened(room.to_owned(), session_id.to_owned());
        }
    }

    /// `finish`.
    fn finish(&self, gen: &Generation, err: Option<OlcrtcError>) {
        let mut st = self.lock();
        if Self::is_current(&st, gen) {
            st.phase = Phase::Stopped;
        }
        let mut f = gen.flags();
        f.err = err;
        f.done = true;
        drop(f);
        drop(st);
        gen.changed.notify_all();
    }

    /// `abandon`: a generation that outran its stop deadline is let go, so
    /// the runtime can start again while it unwinds.
    fn abandon(&self, gen: &Generation) {
        let mut st = self.lock();
        if Self::is_current(&st, gen) {
            st.current = None;
            st.phase = Phase::Stopped;
        }
    }
}

/// The generation's task: the supervisor over the runtime's rooms.
async fn run_generation(shared: Arc<Shared>, gen: Arc<Generation>) {
    let walk = {
        let shared = shared.clone();
        let gen = gen.clone();
        async move {
            let device_id = config::resolve_device_id(&gen.device.0, &gen.device.1)
                .map_err(|e| format!("run public client: client: {e}"))?;
            let reload: Reload = {
                let shared = Arc::downgrade(&shared);
                Arc::new(move || shared.upgrade().map(|s| s.rooms()).unwrap_or_default())
            };
            let rooms = shared.rooms();
            let delay = shared.retry_delay;
            supervisor::walk_paced(
                rooms,
                Some(reload),
                &gen.cancel,
                delay,
                |room: &str| gen.cfg.room_label(room),
                |room, end_on_empty_room| {
                    let mut cfg = gen.cfg.clone();
                    cfg.url.clone_from(&room);
                    cfg.device_id.clone_from(&device_id);
                    cfg.end_on_empty_room = end_on_empty_room;
                    let on_ready: Box<dyn FnOnce(SocketAddr) + Send> = {
                        let (shared, gen) = (shared.clone(), gen.clone());
                        Box::new(move |_| shared.mark_ready(&gen))
                    };
                    let on_session_open: olc_client::client::SessionListener = {
                        let (shared, gen) = (shared.clone(), gen.clone());
                        Arc::new(move |sid: &str| shared.notify_session_opened(&gen, &room, sid))
                    };
                    (shared.runner)(RoomRun {
                        cfg,
                        stop: gen.cancel.child_token(),
                        on_ready,
                        on_session_open,
                    })
                },
            )
            .await
            .map_err(|e| e.to_string())
        }
    };
    let ended = std::panic::AssertUnwindSafe(walk).catch_unwind().await;
    gen.cancel.cancel();
    let err = match ended {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(OlcrtcError::Run(e)),
        Err(_) => Some(OlcrtcError::Run(
            "olcRTC runtime: the generation panicked".to_owned(),
        )),
    };
    shared.finish(&gen, err);
}

/// `timeoutFromMillis`: zero or less is the default.
fn timeout_from_millis(ms: i64, fallback: Duration) -> Duration {
    u64::try_from(ms)
        .ok()
        .filter(|&ms| ms > 0)
        .map_or(fallback, Duration::from_millis)
}

/// A deadline `d` from now, saturating far in the future.
fn deadline(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .unwrap_or_else(|| now + Duration::from_secs(100 * 365 * 24 * 3600))
}

/// One independently configured olcRTC client lifecycle (`Runtime`).
#[derive(uniffi::Object)]
pub struct OlcrtcRuntime {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for OlcrtcRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.shared.lock();
        f.debug_struct("OlcrtcRuntime")
            .field("state", &st.phase.name())
            .field("defaults", &st.defaults)
            .finish_non_exhaustive()
    }
}

/// A runtime closed while it runs (Kotlin's `close()`, Swift's last
/// reference: UniFFI frees the object either way) stops its run as
/// `stop(5_000)` does, so no run outlives the app's object: not its task,
/// its SOCKS port, nor its session in the room, where a later client's hello
/// would reach it. This is beyond Go: `mobile/` at 2d4266af sets no
/// finalizer, so a Go runtime the app let go of runs on. The session
/// listener goes first, so nothing calls the app after this. On one of the
/// runtime's own threads (the app letting go from a callback the run is
/// making) the run is told to stop and not waited for: it would be waiting
/// on itself. A close with nothing running waits for nothing.
impl Drop for OlcrtcRuntime {
    fn drop(&mut self) {
        // Dropped outside the lock: a foreign listener's release calls into
        // the app.
        let listener = self.shared.lock().listener.take();
        drop(listener);
        let Some(gen) = self.request_stop() else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            return;
        }
        let _ = self.wait_stopped(&gen, DEFAULT_STOP_TIMEOUT);
    }
}

impl OlcrtcRuntime {
    /// A runtime whose rooms are run by `runner` (`newRuntime(runner)`: the
    /// tests' stand-in for the client), pausing `retry_delay` between rooms
    /// (zero: the supervisor's 2 s).
    #[doc(hidden)]
    #[must_use]
    pub fn with_runner(runner: Runner, retry_delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            shared: Arc::new(Shared {
                st: Mutex::new(State {
                    defaults: RuntimeConfig::default(),
                    phase: Phase::Idle,
                    next_generation: 0,
                    current: None,
                    listener: None,
                }),
                runner,
                retry_delay,
            }),
        })
    }

    /// The client's liveness fallback, for the gate's driver only (Go's
    /// mobile API has no such setter; the e2e scenarios shorten it).
    #[doc(hidden)]
    pub fn set_liveness_fallback_millis(&self, ms: u64) {
        self.set(|d| d.liveness_fallback_ms = ms);
    }

    fn set(&self, f: impl FnOnce(&mut RuntimeConfig)) {
        f(&mut self.shared.lock().defaults);
    }
}

#[uniffi::export]
impl OlcrtcRuntime {
    /// `MobileNew()`: an idle runtime with the mobile defaults. Every host
    /// is a phone, so the client's buffers are always the constrained ones.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_runner(client_runner(), supervisor::RETRY_DELAY)
    }

    /// `SetProvider`: one this build carries.
    ///
    /// # Errors
    /// `unsupported provider: "<name>"`.
    pub fn set_provider(&self, provider: String) -> Result<(), OlcrtcError> {
        if !PROVIDERS.contains(&provider.as_str()) {
            return Err(OlcrtcError::UnsupportedProvider(provider));
        }
        self.set(|d| d.provider = provider);
        Ok(())
    }

    /// `SetTransport`.
    ///
    /// # Errors
    /// `unsupported transport: "<name>"`.
    pub fn set_transport(&self, transport: String) -> Result<(), OlcrtcError> {
        if !TRANSPORTS.contains(&transport.as_str()) {
            return Err(OlcrtcError::UnsupportedTransport(transport));
        }
        self.set(|d| d.transport = transport);
        Ok(())
    }

    /// `SetRoom`: the primary room, first in the list. While running it is
    /// the head of the list from the next hop on.
    ///
    /// # Errors
    /// An empty room.
    pub fn set_room(&self, room: String) -> Result<(), OlcrtcError> {
        let room = room.trim();
        if room.is_empty() {
            return Err(invalid("room is required"));
        }
        let room = room.to_owned();
        self.set(|d| d.room = room);
        Ok(())
    }

    /// `AddFailoverRoom`: a room after the primary, in the order added; the
    /// primary and repeats are ignored. Safe while running: the supervisor
    /// reads the list at every hop.
    ///
    /// # Errors
    /// An empty room.
    pub fn add_failover_room(&self, room: String) -> Result<(), OlcrtcError> {
        let room = room.trim();
        if room.is_empty() {
            return Err(invalid("failover room is required"));
        }
        let room = room.to_owned();
        self.set(|d| {
            if room != d.room && !d.failover_rooms.contains(&room) {
                d.failover_rooms.push(room);
            }
        });
        Ok(())
    }

    /// `ClearFailoverRooms`: every extra room goes; the primary stays.
    pub fn clear_failover_rooms(&self) {
        self.set(|d| d.failover_rooms.clear());
    }

    /// `SetChannel`.
    pub fn set_channel(&self, channel_id: String) {
        self.set(|d| d.channel = channel_id.trim().to_owned());
    }

    /// `SetKey`: 32 bytes of hex.
    ///
    /// # Errors
    /// A key that is not 64 hex digits.
    pub fn set_key(&self, key_hex: String) -> Result<(), OlcrtcError> {
        config::validate_key(&key_hex)?;
        self.set(|d| d.key_hex = key_hex);
        Ok(())
    }

    /// `SetDNS`: one `host:port`, or several separated by commas, semicolons
    /// or spaces, asked in that order. A running generation follows at once:
    /// the next lookup asks the new network's resolvers.
    ///
    /// # Errors
    /// An empty list, an entry without a host or with a bad port.
    pub fn set_dns(&self, dns_server: String) -> Result<(), OlcrtcError> {
        config::validate_dns(&dns_server)?;
        olc_client::resolver::set_servers(&dns_server);
        self.set(|d| d.dns = dns_server);
        Ok(())
    }

    /// `SetDTLSProfile`: for future runs.
    ///
    /// # Errors
    /// `dtls profile "<p>": dtls: unknown profile: "<p>"`.
    pub fn set_dtls_profile(&self, profile: String) -> Result<(), OlcrtcError> {
        if !config::DTLS_PROFILES.contains(&profile.as_str()) {
            return Err(OlcrtcError::Setting(format!(
                "dtls profile {profile:?}: dtls: unknown profile: {profile:?}"
            )));
        }
        self.set(|d| d.dtls_profile = profile);
        Ok(())
    }

    /// `SetSocksListenHost`.
    ///
    /// # Errors
    /// An empty host.
    pub fn set_socks_listen_host(&self, host: String) -> Result<(), OlcrtcError> {
        let host = config::clean_host(&host);
        if host.is_empty() {
            return Err(invalid("SOCKS host is required"));
        }
        self.set(|d| d.socks_host = host);
        Ok(())
    }

    /// `SetSocksPort`.
    ///
    /// # Errors
    /// A port outside 1..65535.
    pub fn set_socks_port(&self, port: i64) -> Result<(), OlcrtcError> {
        let port = u16::try_from(port)
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| invalid("SOCKS port must be between 1 and 65535"))?;
        self.set(|d| d.socks_port = port);
        Ok(())
    }

    /// `SetSocksCredentials`: the login hev sends; none when the user is
    /// empty.
    ///
    /// # Errors
    /// A user or password over 255 bytes.
    pub fn set_socks_credentials(&self, user: String, password: String) -> Result<(), OlcrtcError> {
        if user.len() > 255 || password.len() > 255 {
            return Err(invalid("SOCKS credentials exceed 255 bytes"));
        }
        self.set(|d| {
            d.socks_user = user;
            d.socks_pass = password;
        });
        Ok(())
    }

    /// `SetProviderToken`.
    pub fn set_provider_token(&self, token: String) {
        self.set(|d| d.provider_token = token.trim().to_owned());
    }

    /// `SetDeviceID`: the id the hello carries in future runs.
    pub fn set_device_id(&self, device_id: String) {
        self.set(|d| d.device_id = device_id.trim().to_owned());
    }

    /// `SetDeviceIDPath`: a file that keeps one id across runs.
    pub fn set_device_id_path(&self, path: String) {
        self.set(|d| d.device_id_path = path.trim().to_owned());
    }

    /// `SetEngine`: the engine the `none` provider dials.
    pub fn set_engine(&self, name: String, service_url: String, token: String) {
        self.set(|d| {
            d.engine = name.trim().to_owned();
            d.service_url = service_url.trim().to_owned();
            d.engine_token = token.trim().to_owned();
        });
    }

    /// `SetLivenessOptions`, in milliseconds.
    ///
    /// # Errors
    /// A value that is not positive.
    pub fn set_liveness_options(
        &self,
        interval_millis: i64,
        timeout_millis: i64,
        failures: i64,
    ) -> Result<(), OlcrtcError> {
        if interval_millis <= 0 || timeout_millis <= 0 || failures <= 0 {
            return Err(invalid("liveness values must be positive"));
        }
        let failures =
            u32::try_from(failures).map_err(|_| invalid("liveness duration is too large"))?;
        let ms = |v: i64| u64::try_from(v).map_err(|_| invalid("liveness duration is too large"));
        let liveness = olc_client::config::Liveness {
            interval_ms: ms(interval_millis)?,
            timeout_ms: ms(timeout_millis)?,
            failures,
        };
        self.set(|d| d.liveness = liveness);
        Ok(())
    }

    /// `SetTrafficOptions` (kept for the API; the datachannel client does
    /// not pace).
    ///
    /// # Errors
    /// Go's checks.
    pub fn set_traffic_options(
        &self,
        max_payload_size: i64,
        min_delay_millis: i64,
        max_delay_millis: i64,
    ) -> Result<(), OlcrtcError> {
        if max_payload_size < 0
            || (max_payload_size > 0 && max_payload_size < config::MIN_TRAFFIC_PAYLOAD)
        {
            return Err(invalid("traffic payload limit is too small"));
        }
        if min_delay_millis < 0
            || max_delay_millis < 0
            || (max_delay_millis > 0 && max_delay_millis < min_delay_millis)
        {
            return Err(invalid("invalid traffic delay range"));
        }
        self.set(|d| d.traffic = (max_payload_size, min_delay_millis, max_delay_millis));
        Ok(())
    }

    /// `SetVP8Options`.
    ///
    /// # Errors
    /// fps outside 1..120 or a batch under 1.
    pub fn set_vp8_options(&self, fps: i64, batch_size: i64) -> Result<(), OlcrtcError> {
        if !(1..=120).contains(&fps) || batch_size < 1 {
            return Err(invalid("invalid VP8 options"));
        }
        self.set(|d| d.vp8 = (fps, batch_size));
        Ok(())
    }

    /// `SetDebug`: the engine's debug lines, process-wide.
    pub fn set_debug(&self, enabled: bool) {
        olc_client::log::set_verbose(enabled);
    }

    /// `SetUDP`: the SOCKS5 UDP relay (UDP ASSOCIATE and `FWD_UDP`) on or
    /// off for the next start; on by default.
    pub fn set_udp(&self, enabled: bool) {
        self.set(|d| d.udp_disabled = !enabled);
    }

    /// `SetDirectRules`: what the next start dials directly; parsed now.
    ///
    /// # Errors
    /// The first line that is not a rule.
    pub fn set_direct_rules(&self, text: String) -> Result<(), OlcrtcError> {
        olc_client::direct::Rules::parse(&config::direct_lines(&text)).map_err(invalid)?;
        self.set(|d| d.direct_rules = text);
        Ok(())
    }

    /// `SetProtector` (process-wide, as Go's `protect.SetProtector`).
    pub fn set_protector(&self, protector: Option<Arc<dyn SocketProtector>>) {
        olc_client::net::set_protector(protector.map(|p| -> olc_client::net::Protector {
            Arc::new(move |fd| p.protect(i64::from(fd)))
        }));
    }

    /// `SetSessionListener`; `None` takes it back.
    pub fn set_session_listener(&self, listener: Option<Arc<dyn SessionListener>>) {
        self.shared.lock().listener = listener;
    }

    /// `Start`: a new generation from the settings as they are now.
    ///
    /// # Errors
    /// `olcRTC runtime is already active`, a setting [`Self::start`] cannot
    /// run, or no runtime threads.
    pub fn start(&self) -> Result<(), OlcrtcError> {
        let mut st = self.shared.lock();
        if st.phase.active() {
            return Err(OlcrtcError::AlreadyRunning);
        }
        st.defaults.validate()?;
        ensure_signalling_tls().map_err(OlcrtcError::Run)?;
        let rt = ghostlane_runtime::handle()
            .map_err(|e| OlcrtcError::Run(format!("olcRTC runtime: no threads: {e}")))?;
        let cfg = st
            .defaults
            .client_config(String::new(), olc_client::log::verbose());
        st.next_generation += 1;
        let gen = Arc::new(Generation {
            id: st.next_generation,
            cfg,
            device: (
                st.defaults.device_id.clone(),
                st.defaults.device_id_path.clone(),
            ),
            cancel: CancellationToken::new(),
            flags: Mutex::new(Flags::default()),
            changed: Condvar::new(),
        });
        st.current = Some(gen.clone());
        st.phase = Phase::Starting;
        drop(st);
        rt.spawn(run_generation(self.shared.clone(), gen));
        Ok(())
    }

    /// `WaitReady`: waits for the generation current when called.
    ///
    /// # Errors
    /// `has not been started`; the generation's own end; `stopped before
    /// becoming ready`; `readiness timed out`.
    pub fn wait_ready(&self, timeout_millis: i64) -> Result<(), OlcrtcError> {
        let Some(gen) = self.shared.lock().current.clone() else {
            return Err(OlcrtcError::NotRunning);
        };
        Self::wait_generation_ready(
            &gen,
            timeout_from_millis(timeout_millis, DEFAULT_READY_TIMEOUT),
        )
    }

    /// `Stop`: cancels the current generation and waits for it. It always
    /// leaves the runtime startable: a generation that outruns the deadline
    /// is let go (its SOCKS port is already closed) and the error says so.
    ///
    /// # Errors
    /// `olcRTC runtime stop timed out`.
    pub fn stop(&self, timeout_millis: i64) -> Result<(), OlcrtcError> {
        let Some(gen) = self.request_stop() else {
            return Ok(());
        };
        self.wait_stopped(
            &gen,
            timeout_from_millis(timeout_millis, DEFAULT_STOP_TIMEOUT),
        )
    }

    /// `IsRunning`: starting, running or stopping.
    pub fn is_running(&self) -> bool {
        self.shared.lock().phase.active()
    }

    /// `State`: idle, starting, running, stopping or stopped.
    pub fn state(&self) -> String {
        self.shared.lock().phase.name().to_owned()
    }

    /// `Check`: joins `room_id` alone (no supervisor), waits for the SOCKS
    /// port, and returns the milliseconds that took.
    ///
    /// # Errors
    /// The run's error, or `probe timed out`.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        provider_name: String,
        transport_name: String,
        room_id: String,
        device_id: String,
        key_hex: String,
        socks_port: i64,
        timeout_millis: i64,
        vp8_fps: i64,
        vp8_batch_size: i64,
    ) -> Result<i64, OlcrtcError> {
        let probe = crate::probe::Probe {
            provider: provider_name,
            transport: transport_name,
            room: room_id,
            device_id,
            key_hex,
            socks_port,
            timeout_millis,
            vp8: (vp8_fps, vp8_batch_size),
            ping_url: None,
        };
        let defaults = self.shared.lock().defaults.clone();
        crate::probe::run(&defaults, &self.shared.runner, probe)
    }

    /// `Ping`: [`Self::check`], then the best of three HTTP requests to
    /// `ping_url` through the probe's SOCKS port, in milliseconds.
    ///
    /// # Errors
    /// The run's error, the request's, or `probe timed out`.
    #[allow(clippy::too_many_arguments)]
    pub fn ping(
        &self,
        provider_name: String,
        transport_name: String,
        room_id: String,
        device_id: String,
        key_hex: String,
        socks_port: i64,
        timeout_millis: i64,
        ping_url: String,
        vp8_fps: i64,
        vp8_batch_size: i64,
    ) -> Result<i64, OlcrtcError> {
        let probe = crate::probe::Probe {
            provider: provider_name,
            transport: transport_name,
            room: room_id,
            device_id,
            key_hex,
            socks_port,
            timeout_millis,
            vp8: (vp8_fps, vp8_batch_size),
            ping_url: Some(ping_url),
        };
        let defaults = self.shared.lock().defaults.clone();
        crate::probe::run(&defaults, &self.shared.runner, probe)
    }
}

impl OlcrtcRuntime {
    /// `Stop`'s first half: the active generation, told to stop; `None`
    /// when nothing is active.
    fn request_stop(&self) -> Option<Arc<Generation>> {
        let mut st = self.shared.lock();
        let gen = st.current.clone()?;
        if matches!(st.phase, Phase::Idle | Phase::Stopped) {
            return None;
        }
        if st.phase != Phase::Stopping {
            st.phase = Phase::Stopping;
            gen.flags().stop_requested = true;
            gen.cancel.cancel();
        }
        Some(gen)
    }

    /// `Stop`'s second half: waits `timeout` for `gen` to end, else lets it
    /// go.
    fn wait_stopped(&self, gen: &Generation, timeout: Duration) -> Result<(), OlcrtcError> {
        if gen.wait(deadline(timeout), |f| f.done).done {
            return Ok(());
        }
        self.shared.abandon(gen);
        Err(OlcrtcError::StopTimeout)
    }

    /// `waitGenerationReady`: one generation, whatever is current by then.
    fn wait_generation_ready(gen: &Generation, timeout: Duration) -> Result<(), OlcrtcError> {
        let f = gen.wait(deadline(timeout), |f| f.done || f.ready);
        // A generation that has exited is never ready, whatever its latch.
        if f.done {
            return Err(Self::generation_error(&f));
        }
        if f.ready {
            return Ok(());
        }
        Err(OlcrtcError::ReadyTimeout)
    }

    /// `generationError`: its own failure, else whether it was ever ready.
    fn generation_error(f: &Flags) -> OlcrtcError {
        if let Some(e) = &f.err {
            return e.clone();
        }
        if f.ready {
            OlcrtcError::NotRunning
        } else {
            OlcrtcError::StoppedBeforeReady
        }
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;

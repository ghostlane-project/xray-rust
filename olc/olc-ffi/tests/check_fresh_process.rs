// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A room check or ping in a process where nothing was started before it
//! (the desktop's one-shot check, a phone's check before its first start).
//! The signalling's TLS used to be put in by `start` alone, so such a check
//! dialed its carrier, found no TLS and failed with `no TLS connector
//! installed for a TLS URL` before a byte of a hello left.
//!
//! The carrier here is a fake on loopback: a listener that keeps the first
//! bytes of every connection and closes it. The room is run by the client
//! itself, told to take that listener for the provider's service
//! (`provider_base`, the setting the carriers' own tests use), so nothing
//! leaves the machine and no join can get past its first request. What is
//! asked is only that the dial reaches the fake as TLS: a handshake record
//! (`0x16 0x03`), not a closed connection with nothing on it.
//!
//! The TLS connector is the process's, so each case runs in a process of
//! its own: the test binary starts itself again with the case's name in
//! `OLC_CHECK_FRESH_CASE`.

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use olc_ffi::{LogWriter, OlcrtcError, OlcrtcRuntime, RoomRun, Runner};

const CASE: &str = "OLC_CHECK_FRESH_CASE";
const PROVIDER: &str = "mtslink";
const TRANSPORT: &str = "vp8channel";
/// A room link of the provider's shape; its host is never dialed.
const ROOM: &str = "https://my.mts-link.ru/j/100200300/400500600700";
const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NO_TLS: &str = "no TLS connector installed";

/// A fake carrier: the first bytes (five at most) of each connection.
struct Carrier {
    addr: SocketAddr,
    seen: Receiver<Vec<u8>>,
}

impl Carrier {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, seen) = mpsc::channel();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));
                    let mut head = Vec::new();
                    let mut buf = [0u8; 5];
                    while head.len() < 5 {
                        match conn.read(&mut buf[..5 - head.len()]) {
                            Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                            _ => break,
                        }
                    }
                    let _ = tx.send(head);
                });
            }
        });
        Self { addr, seen }
    }

    fn base(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// Waits `within` for a connection that began as a TLS handshake;
    /// else what the connections began with.
    fn tls_hello(&self, within: Duration) -> Result<(), Vec<Vec<u8>>> {
        let until = Instant::now() + within;
        let mut others = Vec::new();
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.seen.recv_timeout(left) {
                Ok(head) if head.starts_with(&[0x16, 0x03]) => return Ok(()),
                Ok(head) => others.push(head),
                Err(_) => return Err(others),
            }
        }
    }
}

/// The engine's lines, kept for a failure's text.
#[derive(Default)]
struct Lines(Mutex<Vec<String>>);

impl LogWriter for Lines {
    fn write_log(&self, msg: String) {
        let mut l = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        l.push(msg.trim_end().to_owned());
    }
}

impl Lines {
    fn tail(&self) -> String {
        let l = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let from = l.len().saturating_sub(30);
        l[from..].join("\n  ")
    }
}

/// A runtime whose rooms the client itself runs, with the provider's
/// service at the address in `base`.
struct Bench {
    rt: Arc<OlcrtcRuntime>,
    base: Arc<Mutex<String>>,
    lines: Arc<Lines>,
}

impl Bench {
    fn new() -> Self {
        let base = Arc::new(Mutex::new(String::new()));
        let at = base.clone();
        let runner: Runner = Arc::new(move |run: RoomRun| {
            let base = at.lock().unwrap_or_else(PoisonError::into_inner).clone();
            async move {
                let RoomRun {
                    mut cfg,
                    stop,
                    on_ready,
                    on_session_open,
                } = run;
                cfg.provider_base = base;
                olc_client::Client::run_with(cfg, stop, on_ready, Some(on_session_open))
                    .await
                    .map_err(|e| format!("run public client: client: {e}"))
            }
            .boxed()
        });
        let lines = Arc::new(Lines::default());
        olc_ffi::set_log_writer(Some(lines.clone()));
        let rt = OlcrtcRuntime::with_runner(runner, Duration::from_millis(200));
        rt.set_debug(true);
        // No name is looked up here; were one, it would go nowhere.
        rt.set_dns("127.0.0.1:9".to_owned()).unwrap();
        Self { rt, base, lines }
    }

    fn point_at(&self, carrier: &Carrier) {
        *self.base.lock().unwrap_or_else(PoisonError::into_inner) = carrier.base();
    }

    /// A check (or, with `ping`, a ping) of the room at a new fake carrier;
    /// the carrier and how the call ended.
    fn probe(&self, ping: bool) -> (Carrier, Result<i64, OlcrtcError>) {
        let carrier = Carrier::new();
        self.point_at(&carrier);
        let s = str::to_owned;
        let r = if ping {
            self.rt.ping(
                s(PROVIDER),
                s(TRANSPORT),
                s(ROOM),
                s("device"),
                s(KEY),
                0,
                4_000,
                s("http://127.0.0.1:9/"),
                0,
                0,
            )
        } else {
            self.rt.check(
                s(PROVIDER),
                s(TRANSPORT),
                s(ROOM),
                s("device"),
                s(KEY),
                0,
                4_000,
                0,
                0,
            )
        };
        (carrier, r)
    }

    /// The probe's dial must have reached the fake carrier as TLS.
    fn probe_dials_tls(&self, what: &str, ping: bool) {
        let (carrier, r) = self.probe(ping);
        // The fake completes no handshake, so the probe itself fails; how
        // is in the text of a failure below.
        let ended = match &r {
            Ok(ms) => format!("ready in {ms} ms"),
            Err(e) => e.to_string(),
        };
        if let Err(others) = carrier.tls_hello(Duration::from_secs(3)) {
            panic!(
                "{what}: the signalling dial sent no TLS hello to the carrier \
                 (its connections began with {others:?}).\n the call ended with: {ended}\n \
                 the engine's lines:\n  {}",
                self.lines.tail()
            );
        }
        assert!(
            !ended.contains(NO_TLS),
            "{what}: a TLS hello was seen, yet the call ended with: {ended}"
        );
    }

    /// A start's dial must reach a new fake carrier as TLS; the runtime is
    /// stopped again.
    fn start_dials_tls(&self, what: &str) {
        let carrier = Carrier::new();
        self.point_at(&carrier);
        let free = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        self.rt.set_provider(PROVIDER.to_owned()).unwrap();
        self.rt.set_transport(TRANSPORT.to_owned()).unwrap();
        self.rt.set_room(ROOM.to_owned()).unwrap();
        self.rt.set_key(KEY.to_owned()).unwrap();
        self.rt.set_device_id("device".to_owned());
        self.rt.set_socks_port(i64::from(port)).unwrap();
        self.rt.start().unwrap();
        let seen = carrier.tls_hello(Duration::from_secs(10));
        let _ = self.rt.stop(5_000);
        if let Err(others) = seen {
            panic!(
                "{what}: the start's signalling dial sent no TLS hello to the carrier \
                 (its connections began with {others:?}).\n the engine's lines:\n  {}",
                self.lines.tail()
            );
        }
        assert!(!self.rt.is_running(), "{what}: the runtime did not stop");
    }
}

/// Nothing ran before the check.
fn case_check() {
    assert!(!olc_net::stream::tls_connector_installed());
    Bench::new().probe_dials_tls("a check in a fresh process", false);
}

/// Nothing ran before the ping.
fn case_ping() {
    assert!(!olc_net::stream::tls_connector_installed());
    Bench::new().probe_dials_tls("a ping in a fresh process", true);
}

/// A check, then a start and a second check on the same runtime, then a
/// start on another runtime of the process.
fn case_check_then_start() {
    let b = Bench::new();
    b.probe_dials_tls("a check in a fresh process", false);
    b.start_dials_tls("a start after a check");
    b.probe_dials_tls("a check after a check and a start", false);
    Bench::new().start_dials_tls("a second runtime's start after a check");
}

/// A start, then a check while it runs and one after it stopped.
fn case_start_then_check() {
    let b = Bench::new();
    let carrier = Carrier::new();
    b.point_at(&carrier);
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    b.rt.set_provider(PROVIDER.to_owned()).unwrap();
    b.rt.set_room(ROOM.to_owned()).unwrap();
    b.rt.set_key(KEY.to_owned()).unwrap();
    b.rt.set_device_id("device".to_owned());
    b.rt.set_socks_port(i64::from(port)).unwrap();
    b.rt.start().unwrap();
    carrier
        .tls_hello(Duration::from_secs(10))
        .unwrap_or_else(|o| panic!("the start sent no TLS hello (saw {o:?})"));
    // The running start keeps dialing whatever `base` names, so this check
    // is judged by its error alone.
    let (_carrier, r) = b.probe(false);
    let ended = r.map_or_else(|e| e.to_string(), |ms| format!("ready in {ms} ms"));
    assert!(
        !ended.contains(NO_TLS),
        "a check beside a running start ended with: {ended}"
    );
    b.rt.stop(5_000).unwrap();
    b.probe_dials_tls("a check after a start", false);
    b.start_dials_tls("a start after a start and a check");
}

/// The host's own connector (the carriers' tests install one) is the one a
/// check uses: a check does not put the shaped one over it.
fn case_host_connector_kept() {
    use olc_net::stream::{Offer, TlsFuture};
    let calls = Arc::new(AtomicUsize::new(0));
    let n = calls.clone();
    olc_net::stream::set_tls_connector(Some(Arc::new(
        move |_tcp: tokio::net::TcpStream, _host: String, _offer: Offer| -> TlsFuture {
            n.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(std::io::Error::other("the host's connector")) })
        },
    )));
    let b = Bench::new();
    let (carrier, r) = b.probe(false);
    assert!(r.is_err());
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "the check did not use the host's connector: {r:?}"
    );
    assert!(
        carrier.tls_hello(Duration::from_millis(500)).is_err(),
        "a TLS hello left though the host's connector sends none"
    );
}

/// The case named in the environment; nothing when the binary runs as the
/// suite.
#[test]
fn case() {
    let Ok(name) = std::env::var(CASE) else {
        return;
    };
    // An unoptimized build's frames do not fit the runtime's 512 KiB worker
    // stack once the client itself runs on it (the first poll of a join
    // overflowed it); an optimized build keeps the stack the apps ship.
    if cfg!(debug_assertions) {
        let mut profile = ghostlane_runtime::runtime::Profile::for_target();
        profile.stack = 8 * 1024 * 1024;
        ghostlane_runtime::runtime::configure(profile).unwrap();
    }
    match name.as_str() {
        "check" => case_check(),
        "ping" => case_ping(),
        "check-then-start" => case_check_then_start(),
        "start-then-check" => case_start_then_check(),
        "host-connector-kept" => case_host_connector_kept(),
        other => panic!("unknown case {other:?}"),
    }
}

/// Runs `name` in a process of its own (90 s at most) and fails with its
/// output.
fn in_fresh_process(name: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "case", "--nocapture", "--test-threads=1"])
        .env(CASE, name)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let other = std::thread::spawn(move || {
            let mut t = String::new();
            let _ = err.read_to_string(&mut t);
            t
        });
        let _ = out.read_to_string(&mut text);
        text.push_str(&other.join().unwrap_or_default());
        let _ = tx.send(text);
    });
    let until = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = reader.join();
    match status {
        Some(s) if s.success() => {}
        Some(s) => panic!("case {name:?} failed ({s}):\n{text}"),
        None => panic!("case {name:?} did not end in 90 s:\n{text}"),
    }
}

#[test]
fn a_check_in_a_fresh_process_dials_its_carrier_in_tls() {
    in_fresh_process("check");
}

#[test]
fn a_ping_in_a_fresh_process_dials_its_carrier_in_tls() {
    in_fresh_process("ping");
}

#[test]
fn a_start_after_a_check_and_a_check_after_it() {
    in_fresh_process("check-then-start");
}

#[test]
fn a_check_after_a_start_and_beside_one() {
    in_fresh_process("start-then-check");
}

#[test]
fn a_check_keeps_the_hosts_own_connector() {
    in_fresh_process("host-connector-kept");
}

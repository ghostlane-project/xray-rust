// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `olc-ffi-client <config.json>`: the gate's Rust client driven through the
//! app API instead of `Client::run`, so the gate (S0-S7) and the e2e
//! scenarios run the call sequence the iOS extension makes
//! (`OlcrtcEngine.launch`): the setters, `start`, `wait_ready(35 000)`,
//! then `stop(5000)` on SIGTERM or SIGINT. It reads olc-client's JSON, logs
//! through the FFI's log writer to stderr, and exits 1 with the
//! generation's error when the generation ends on its own.
//!
//! With `OLC_FFI_CYCLES=<n>` and `OLC_FFI_FETCH=<http url>` it instead makes
//! n start / fetch / stop cycles and prints one line per cycle with the
//! shared runtime's tasks and threads, the OS's thread count and the heap
//! (`ffi cycle=...`), for the stop/start leak test.
//!
//! With `OLC_FFI_CONTROL=1` it is the footprint harness's host on Linux
//! (Ghostlane `lab/olc-ffi/footprint/footprint.py`), fp-host's protocol
//! (`host/main.swift`), one command per line on stdin, one answer per line
//! on stdout, and a `TICK <unix ms> <footprint> <memory_stats json>` line
//! four times a second between them; `<footprint>` is `RssAnon` (the
//! anonymous resident bytes, Linux's nearest to `phys_footprint`):
//!
//! ```text
//! start        start, wait_ready(35000)   READY ms=<n> | ERR start <text>
//! stats        memory_stats()             STATS <json>
//! trim         trim()                     TRIM <bytes> <footprint before> <after>
//! mtrim        glibc's malloc_trim(0)     MTRIM <its result> <footprint before> <after>
//! budget <n>   set_byte_budget(n)         BUDGET cap=<B>
//! cycle <n>    n x (stop, start, ready)   CYCLED n=<n> ready_min=<ms> ready_max=<ms>
//! stop         stop(5000)                 STOPPED ms=<n>
//! quit         stop when running, exit    BYE releases=0
//! ```
//!
//! The first line is `LOADED pid=<pid>`; end of input is a quit. A command
//! it does not know goes to the build's own (`main`'s `extra`: the dhat
//! example's `profile` and `dump`), else it is `ERR unknown <command>`.
//!
//! This file is the driver; `main.rs` gives it the counting allocator, and
//! `examples/olc-ffi-dhat.rs` the same driver with dhat-rs's.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::atomic::{AtomicUsize, Ordering};

use olc_ffi::{LogWriter, OlcrtcError, OlcrtcRuntime, SessionListener, SocketProtector};

/// `OLCRTC_READY_TIMEOUT_MS`, as the apps pass it.
const READY_MS: i64 = 35_000;
/// `MOBILE_STOP_TIMEOUT_MS`.
const STOP_MS: i64 = 5_000;

struct Stderr;

impl LogWriter for Stderr {
    fn write_log(&self, msg: String) {
        // Go's lines end with their newline already.
        let _ = std::io::stderr().lock().write_all(msg.as_bytes());
    }
}

/// The iOS RoomKeeper's part, logged: the room and id of each session.
struct Keeper;

impl SessionListener for Keeper {
    fn on_session_opened(&self, room: String, session_id: String) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "ffi session opened room={room} id={session_id}"
        );
    }
}

/// `LibboxPlatform.pinToPhysicalInterface`'s place: nothing to pin on
/// this host, so each call is counted and logged once, the proof that the
/// engine's sockets reach the app's protector.
struct Pin(AtomicUsize);

impl SocketProtector for Pin {
    fn protect(&self, fd: i64) -> bool {
        if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
            let _ = writeln!(std::io::stderr().lock(), "ffi protect fd={fd} (first)");
        }
        true
    }
}

fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn configure(rt: &OlcrtcRuntime, cfg: &olc_client::Config) -> Result<SocketAddr, OlcrtcError> {
    rt.set_debug(cfg.debug);
    rt.set_session_listener(Some(Arc::new(Keeper)));
    rt.set_protector(Some(Arc::new(Pin(AtomicUsize::new(0)))));
    rt.set_provider("none".into())?;
    rt.set_engine("interop-pipe".into(), String::new(), String::new());
    rt.set_transport(cfg.transport.clone())?;
    if !cfg.dns.is_empty() {
        rt.set_dns(cfg.dns.clone())?;
    }
    rt.set_direct_rules(cfg.direct.join("\n"))?;
    rt.set_udp(!cfg.udp_disabled);
    // OlcrtcEngine.applyRooms.
    rt.set_room(cfg.url.clone())?;
    rt.clear_failover_rooms();
    for room in &cfg.rooms {
        rt.add_failover_room(room.clone())?;
    }
    rt.set_device_id(cfg.device_id.clone());
    rt.set_key(cfg.key.clone())?;
    let (host, port) = cfg
        .socks
        .rsplit_once(':')
        .ok_or_else(|| OlcrtcError::InvalidConfig("invalid SOCKS listen address".into()))?;
    let mut port: u16 = port
        .parse()
        .map_err(|_| OlcrtcError::InvalidConfig("invalid SOCKS listen address".into()))?;
    if port == 0 {
        // The app's allocateLocalPort().
        port = free_port().map_err(|e| OlcrtcError::InvalidConfig(e.to_string()))?;
    }
    rt.set_socks_listen_host(if host.is_empty() {
        "0.0.0.0".into()
    } else {
        host.into()
    })?;
    rt.set_socks_port(i64::from(port))?;
    rt.set_socks_credentials(cfg.socks_user.clone(), cfg.socks_pass.clone())?;
    let l = cfg.liveness;
    if l.interval_ms != 0 || l.timeout_ms != 0 || l.failures != 0 {
        let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        rt.set_liveness_options(ms(l.interval()), ms(l.timeout()), i64::from(l.failures()))?;
    }
    rt.set_liveness_fallback_millis(cfg.liveness_fallback_ms);
    let ip = if host.is_empty() || host == "localhost" {
        "127.0.0.1"
    } else {
        host
    };
    format!("{ip}:{port}")
        .parse()
        .map_err(|_| OlcrtcError::InvalidConfig("invalid SOCKS listen address".into()))
}

fn signals() -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    let rt = ghostlane_runtime::handle().expect("runtime");
    rt.spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        let _ = tx.send(());
    });
    rx
}

fn serve(rt: &OlcrtcRuntime) -> ExitCode {
    let stop = signals();
    if let Err(e) = rt.start().and_then(|()| rt.wait_ready(READY_MS)) {
        olc_client::info!("olcRTC start failed: {e}");
        let _ = rt.stop(STOP_MS);
        return ExitCode::FAILURE;
    }
    loop {
        match stop.recv_timeout(Duration::from_millis(100)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return match rt.stop(STOP_MS) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        olc_client::info!("olcRTC stop did not finish in time: {e}");
                        ExitCode::FAILURE
                    }
                };
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if !rt.is_running() {
            // The generation ended on its own: its error, as WaitReady says it.
            if let Err(e) = rt.wait_ready(1) {
                olc_client::info!("{e}");
            }
            return ExitCode::FAILURE;
        }
    }
}

/// GET `url` (plain HTTP) through the SOCKS5 front at `socks`, by name as
/// hev and Go's dialer ask; the body's length.
fn fetch(socks: SocketAddr, url: &str) -> std::io::Result<usize> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, m.to_owned());
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| bad("http only"))?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| bad("host:port"))?;
    let port: u16 = port.parse().map_err(|_| bad("port"))?;
    let mut s = TcpStream::connect_timeout(&socks, Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.write_all(&[5, 1, 0])?;
    let mut two = [0u8; 2];
    s.read_exact(&mut two)?;
    let len = u8::try_from(host.len()).map_err(|_| bad("host"))?;
    let mut req = vec![5, 1, 0, 3, len];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    if rep[1] != 0 {
        return Err(bad(&format!("socks reply {}", rep[1])));
    }
    write!(s, "GET {path} HTTP/1.0\r\nHost: {authority}\r\n\r\n")?;
    let mut all = Vec::new();
    s.read_to_end(&mut all)?;
    let body = all
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |i| all.len() - i - 4);
    Ok(body)
}

fn os_threads() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn cycles(rt: &OlcrtcRuntime, socks: SocketAddr, n: usize, url: &str) -> ExitCode {
    for i in 0..n {
        let t0 = Instant::now();
        if let Err(e) = rt.start().and_then(|()| rt.wait_ready(READY_MS)) {
            olc_client::info!("ffi cycle={i} start failed: {e}");
            return ExitCode::FAILURE;
        }
        let ready_ms = t0.elapsed().as_millis();
        let fetched = match fetch(socks, url) {
            Ok(n) => n,
            Err(e) => {
                olc_client::info!("ffi cycle={i} fetch failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if i + 1 == n {
            // MemoryWatch's reading with a session up, once.
            eprintln!("ffi memory running {}", olc_ffi::memory_stats());
        }
        let t1 = Instant::now();
        if let Err(e) = rt.stop(STOP_MS) {
            olc_client::info!("ffi cycle={i} stop failed: {e}");
            return ExitCode::FAILURE;
        }
        let stop_ms = t1.elapsed().as_millis();
        // What a stop leaves: tasks settle as the run's last ones end.
        let settle = Instant::now() + Duration::from_secs(2);
        let mut tasks = ghostlane_runtime::runtime::alive_tasks().unwrap_or(0);
        while tasks > 0 && Instant::now() < settle {
            std::thread::sleep(Duration::from_millis(10));
            tasks = ghostlane_runtime::runtime::alive_tasks().unwrap_or(0);
        }
        let live = ghostlane_runtime::alloc::heap().map_or(0, |h| h.live);
        eprintln!(
            "ffi cycle={i} ready_ms={ready_ms} fetched={fetched} stop_ms={stop_ms} tasks={tasks} rt_threads={} os_threads={} live={live} state={}",
            ghostlane_runtime::runtime::threads(),
            os_threads(),
            rt.state()
        );
    }
    eprintln!("ffi memory stopped {}", olc_ffi::memory_stats());
    eprintln!(
        "ffi cycles done n={n} workers={}",
        ghostlane_runtime::runtime::built().map_or(0, |p| p.workers)
    );
    ExitCode::SUCCESS
}

/// A field of `/proc/self/status` in bytes (its kB), 0 when absent.
fn status_bytes(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        })
        .map_or(0, |kib| kib * 1024)
}

/// The footprint the control mode reports: `RssAnon`.
fn footprint() -> u64 {
    status_bytes("RssAnon")
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
extern "C" {
    fn malloc_trim(pad: usize) -> std::ffi::c_int;
}

/// glibc's `malloc_trim(0)`: every arena's free pages back to the system.
fn glibc_trim() -> Option<i32> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: malloc_trim takes no pointer; it walks the arenas under
        // their own locks.
        Some(unsafe { malloc_trim(0) })
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        None
    }
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn millis(since: Instant) -> u128 {
    since.elapsed().as_millis()
}

/// An error on one line, as fp-host writes it.
fn one_line(e: &OlcrtcError) -> String {
    e.to_string().replace('\n', " ")
}

/// A build's own control commands: `(command, the rest of its line)` to the
/// answer line, `None` for a command it does not know either.
pub type Extra<'a> = &'a mut dyn FnMut(&str, &str) -> Option<String>;

fn control(rt: &OlcrtcRuntime, extra: Extra<'_>) -> ExitCode {
    std::thread::spawn(|| loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        say(&format!(
            "TICK {now} {} {}",
            footprint(),
            olc_ffi::memory_stats()
        ));
        std::thread::sleep(Duration::from_millis(250));
    });
    let start_ready = || -> Result<u128, OlcrtcError> {
        let t0 = Instant::now();
        rt.start()?;
        rt.wait_ready(READY_MS)?;
        Ok(millis(t0))
    };
    say(&format!("LOADED pid={}", std::process::id()));
    let mut line = String::new();
    loop {
        line.clear();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        let (command, rest) = text.split_once(' ').unwrap_or((text, ""));
        let rest = rest.trim();
        let n = rest.parse::<u64>().ok();
        match command {
            "start" => match start_ready() {
                Ok(ms) => say(&format!("READY ms={ms}")),
                Err(e) => say(&format!("ERR start {}", one_line(&e))),
            },
            "stats" => say(&format!("STATS {}", olc_ffi::memory_stats())),
            "trim" => {
                let before = footprint();
                let bytes = olc_ffi::trim();
                say(&format!("TRIM {bytes} {before} {}", footprint()));
            }
            "mtrim" => {
                let before = footprint();
                match glibc_trim() {
                    Some(r) => say(&format!("MTRIM {r} {before} {}", footprint())),
                    None => say("ERR mtrim not glibc"),
                }
            }
            "budget" => {
                olc_ffi::set_byte_budget(n.unwrap_or(0));
                say(&format!(
                    "BUDGET cap={}",
                    ghostlane_runtime::byte_budget().capacity
                ));
            }
            "cycle" => {
                let n = n.unwrap_or(1);
                let mut readies = Vec::new();
                let mut failed = None;
                for _ in 0..n {
                    if let Err(e) = rt.stop(STOP_MS) {
                        failed = Some(e);
                        break;
                    }
                    match start_ready() {
                        Ok(ms) => readies.push(ms),
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                match failed {
                    None => say(&format!(
                        "CYCLED n={n} ready_min={} ready_max={}",
                        readies.iter().min().unwrap_or(&0),
                        readies.iter().max().unwrap_or(&0)
                    )),
                    Some(e) => say(&format!("ERR cycle {} {}", readies.len(), one_line(&e))),
                }
            }
            "stop" => {
                let t0 = Instant::now();
                match rt.stop(STOP_MS) {
                    Ok(()) => say(&format!("STOPPED ms={}", millis(t0))),
                    Err(e) => say(&format!("ERR stop {}", one_line(&e))),
                }
            }
            "quit" => break,
            other => match extra(other, rest) {
                Some(answer) => say(&answer),
                None => say(&format!("ERR unknown {other}")),
            },
        }
    }
    if rt.is_running() {
        let _ = rt.stop(STOP_MS);
    }
    say("BYE releases=0");
    ExitCode::SUCCESS
}

/// The driver's `main`, with the build's own control commands.
pub fn main(extra: Extra<'_>) -> ExitCode {
    olc_ffi::set_log_writer(Some(Arc::new(Stderr)));
    match olc_client::sys::raise_nofile_limit() {
        Some(l) => olc_client::info!("file limit: {} (hard {})", l.soft, l.hard),
        None => olc_client::info!("file limit: unknown"),
    }
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: olc-ffi-client <config.json>");
        return ExitCode::from(2);
    };
    let cfg = match std::fs::read(&path)
        .map_err(|e| format!("read {path}: {e}"))
        .and_then(|raw| olc_client::Config::from_json(&raw).map_err(|e| e.to_string()))
    {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let rt = OlcrtcRuntime::new();
    let socks = match configure(&rt, &cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if std::env::var("OLC_FFI_CONTROL").is_ok_and(|v| v == "1") {
        return control(&rt, extra);
    }
    match (
        std::env::var("OLC_FFI_CYCLES")
            .ok()
            .and_then(|v| v.parse().ok()),
        std::env::var("OLC_FFI_FETCH"),
    ) {
        (Some(n), Ok(url)) => cycles(&rt, socks, n, &url),
        _ => serve(&rt),
    }
}

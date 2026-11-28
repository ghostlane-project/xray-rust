//! The engine as an app runs it: a child process with a session file, read
//! through its stdout. Everything is on loopback: an HTTP origin, the far
//! end of a VLESS line (the server side of the plain TCP line, as the core's
//! own tests stand it up) and a SOCKS5 client, all in this process.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghostlane_engine::events::{EndReason, Event, FailureCode, Level, Severity, Source};
use serde_json::{json, Value};

const ENGINE: &str = env!("CARGO_BIN_EXE_ghostlane-engine");
const USER: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const USER_BYTES: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// How long a step that should be immediate may take on a loaded runner.
const SOON: Duration = Duration::from_secs(20);
/// The contract: an engine told to stop is gone within two seconds.
const GONE_WITHIN: Duration = Duration::from_secs(2);

/// A directory of this test's own, removed at the end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ghostlane-engine-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Writes `session` as a session file of mode `mode` (Unix).
    fn session(&self, session: &Value, mode: u32) -> String {
        let path = self.0.join("session.json");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .unwrap()
            .write_all(session.to_string().as_bytes())
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path.into_os_string().into_string().unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The engine as a child: its stdin held open, its stdout read line by line,
/// its stderr kept for the message of a test that fails.
struct Engine {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    seen: Vec<String>,
    stderr: Arc<Mutex<String>>,
}

impl Engine {
    fn spawn(arguments: &[&str]) -> Self {
        let mut child = Command::new(ENGINE)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the engine");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = Arc::new(Mutex::new(String::new()));
        let mut from = child.stderr.take().unwrap();
        let into = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = from.read_to_string(&mut text);
            *into.lock().unwrap() = text;
        });
        let (tell, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tell.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
            seen: Vec::new(),
            stderr,
        }
    }

    fn so_far(&self) -> String {
        format!(
            "the engine's lines so far:\n{}\nits stderr, once it has ended:\n{}",
            self.seen.join("\n"),
            self.stderr.lock().unwrap()
        )
    }

    /// The next line; `None` once the engine has closed its stdout. Every
    /// line must be an event of the contract.
    fn next(&mut self, within: Duration) -> Option<Event> {
        match self.lines.recv_timeout(within) {
            Ok(line) => {
                let event = Event::from_line(&line)
                    .unwrap_or_else(|error| panic!("not an event ({error}): {line}"));
                self.seen.push(line);
                Some(event)
            }
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => {
                panic!("no line within {within:?}; {}", self.so_far())
            }
        }
    }

    /// Reads on until `wanted` picks a line.
    fn until<T>(&mut self, within: Duration, mut wanted: impl FnMut(&Event) -> Option<T>) -> T {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(event) = self.next(left) else {
                panic!("the engine ended first; {}", self.so_far());
            };
            if let Some(found) = wanted(&event) {
                return found;
            }
        }
    }

    /// The address of the `socks-in` listener, from `ready`.
    fn ready(&mut self) -> SocketAddr {
        self.until(SOON, |event| match event {
            Event::Ready { inbounds } => Some(
                inbounds
                    .iter()
                    .find(|inbound| inbound.tag.as_deref() == Some("socks-in"))
                    .expect("the session's inbound")
                    .address
                    .parse()
                    .unwrap(),
            ),
            _ => None,
        })
    }

    /// Every line from here to the end of the engine's stdout.
    fn rest(&mut self) -> Vec<Event> {
        let mut rest = Vec::new();
        while let Some(event) = self.next(SOON) {
            rest.push(event);
        }
        rest
    }

    fn exit(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the engine is still running after {within:?}; {}",
                self.so_far()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A one-shot command: its lines and its exit status.
    fn answer(arguments: &[&str]) -> (Vec<Event>, Option<i32>) {
        let mut engine = Self::spawn(arguments);
        let lines = engine.rest();
        (lines, engine.exit(SOON).code())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn body() -> Vec<u8> {
    (0..64 * 1024_u32)
        .map(|index| (index % 251) as u8)
        .collect()
}

/// An HTTP origin on loopback: every request is answered with [`body`].
fn origin() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    request.push(byte[0]);
                }
                let body = body();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
        }
    });
    address
}

/// The far end of the session's line: a VLESS server over plain TCP that
/// carries each request to its target and counts it.
struct LineServer {
    address: SocketAddr,
    carried: Arc<AtomicUsize>,
}

impl LineServer {
    fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let carried = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&carried);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(client) = stream else { continue };
                let count = Arc::clone(&count);
                std::thread::spawn(move || Self::carry(client, &count));
            }
        });
        Self { address, carried }
    }

    /// One request: the header (version 0, the user's id, no addons, a TCP
    /// command, the target), the answer `00 00`, then bytes both ways.
    fn carry(mut client: TcpStream, count: &AtomicUsize) {
        let mut head = [0_u8; 18];
        if client.read_exact(&mut head).is_err() {
            return;
        }
        assert_eq!(head[0], 0, "the VLESS version");
        assert_eq!(head[1..17], USER_BYTES, "the session's user");
        let mut addons = vec![0_u8; usize::from(head[17])];
        client.read_exact(&mut addons).unwrap();
        let mut request = [0_u8; 4];
        client.read_exact(&mut request).unwrap();
        assert_eq!(request[0], 1, "a TCP request");
        assert_eq!(request[3], 1, "an IPv4 target");
        let mut ip = [0_u8; 4];
        client.read_exact(&mut ip).unwrap();
        let port = u16::from_be_bytes([request[1], request[2]]);
        let mut target = TcpStream::connect((Ipv4Addr::from(ip), port)).unwrap();
        client.write_all(&[0, 0]).unwrap();
        count.fetch_add(1, Ordering::SeqCst);

        let mut from_client = client.try_clone().unwrap();
        let mut to_target = target.try_clone().unwrap();
        let up = std::thread::spawn(move || {
            let _ = std::io::copy(&mut from_client, &mut to_target);
            let _ = to_target.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut target, &mut client);
        let _ = client.shutdown(Shutdown::Write);
        let _ = up.join();
    }
}

/// A core line: a SOCKS5 listener on a port the system picks, and a VLESS
/// outbound to `line`.
fn core_line(line: SocketAddr, log: &Value) -> Value {
    json!({
        "version": 1,
        "core": {
            "log": log,
            "inbounds": [
                {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0}
            ],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": line.ip().to_string(),
                    "port": line.port(),
                    "users": [{"id": USER, "encryption": "none"}]
                }]},
                "streamSettings": {"network": "tcp"}
            }]
        }
    })
}

/// A SOCKS5 CONNECT to `target` through `proxy`.
fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let SocketAddr::V4(target) = target else {
        panic!("the test's targets are IPv4");
    };
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream.set_read_timeout(Some(SOON)).unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0], "SOCKS5 with no login");
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply[..2], [5, 0], "the CONNECT is accepted");
    stream
}

/// GET `/` of `target` through `proxy`: the body.
fn fetch(proxy: SocketAddr, target: SocketAddr) -> Vec<u8> {
    let mut stream = socks_connect(proxy, target);
    let request = format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "the origin's answer"
    );
    let head = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the end of the headers");
    response.split_off(head + 4)
}

fn ended(reason: EndReason, code: Option<FailureCode>) -> impl Fn(&Event) -> bool {
    move |event| matches!(event, Event::Ended { reason: r, code: c, .. } if *r == reason && *c == code)
}

/// The last line of a run, which must be `ended`.
fn last_ended(lines: &[Event]) -> (EndReason, Option<FailureCode>, Option<String>) {
    match lines.last() {
        Some(Event::Ended {
            reason,
            code,
            message,
        }) => (*reason, *code, message.clone()),
        other => panic!("the last line is not `ended`: {other:?}"),
    }
}

#[test]
fn a_fetch_goes_through_the_spawned_program_by_its_line() {
    let scratch = Scratch::new("fetch");
    let origin = origin();
    let line = LineServer::start();
    // An unknown level is a remark of the parser, and the access log is on.
    let session = core_line(
        line.address,
        &json!({"loglevel": "loud", "access": "events"}),
    );
    let mut engine = Engine::spawn(&["run", "--session", &scratch.session(&session, 0o600)]);

    let proxy = engine.ready();
    assert!(proxy.ip().is_loopback() && proxy.port() != 0, "{proxy}");
    assert!(
        engine.seen.iter().any(|line| {
            matches!(
                Event::from_line(line).unwrap(),
                Event::Warning { source: Source::Core, path: Some(path), .. } if path == "$.log.loglevel"
            )
        }),
        "the parser's remark comes before `ready`; {}",
        engine.so_far()
    );

    assert_eq!(fetch(proxy, origin), body(), "the origin's body, whole");
    assert_eq!(
        line.carried.load(Ordering::SeqCst),
        1,
        "the fetch went by the line's far end"
    );
    // The core's access line for the flow becomes a `log` event.
    engine.until(SOON, |event| {
        matches!(
            event,
            Event::Log { source: Source::Core, level: Level::Access, line } if line.contains("accepted")
        )
        .then_some(())
    });

    drop(engine.stdin.take());
    let status = engine.exit(GONE_WITHIN);
    assert!(status.success(), "{status}");
    let rest = engine.rest();
    assert_eq!(last_ended(&rest).0, EndReason::StdinClosed);
}

#[test]
fn closing_stdin_ends_it_within_two_seconds() {
    let scratch = Scratch::new("stdin");
    let origin = origin();
    let line = LineServer::start();
    let session = core_line(line.address, &Value::Null);
    let mut engine = Engine::spawn(&["run", "--session", &scratch.session(&session, 0o600)]);
    let proxy = engine.ready();
    // A flow that is open and idle when the stop comes.
    let mut idle = socks_connect(proxy, origin);

    let asked = Instant::now();
    drop(engine.stdin.take());
    let status = engine.exit(GONE_WITHIN);
    let took = asked.elapsed();
    assert!(took < GONE_WITHIN, "it took {took:?}");
    assert_eq!(status.code(), Some(0), "a stop that was asked for");

    let rest = engine.rest();
    assert_eq!(
        last_ended(&rest),
        (EndReason::StdinClosed, None, None),
        "{rest:?}"
    );
    assert_eq!(
        rest.iter()
            .filter(|event| matches!(event, Event::Ended { .. }))
            .count(),
        1,
        "`ended` is printed once"
    );
    // Its flows ended with it.
    let mut left = Vec::new();
    let _ = idle.read_to_end(&mut left);
    assert!(left.is_empty(), "nothing more comes through an ended flow");
}

#[cfg(unix)]
#[test]
fn sigterm_ends_it_as_well() {
    let scratch = Scratch::new("sigterm");
    let line = LineServer::start();
    let session = core_line(line.address, &Value::Null);
    let mut engine = Engine::spawn(&["run", "--session", &scratch.session(&session, 0o600)]);
    engine.ready();

    let pid = libc::pid_t::try_from(engine.child.id()).unwrap();
    // SAFETY: a signal to the child this test started and still holds.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = engine.exit(GONE_WITHIN);
    assert_eq!(status.code(), Some(0), "a stop that was asked for");
    let rest = engine.rest();
    assert!(
        rest.last().is_some_and(ended(EndReason::Signal, None)),
        "{rest:?}"
    );
}

/// The commit of this checkout, the way `build.rs` reads it.
fn checkout_commit() -> Option<String> {
    let git = |arguments: &[&str]| -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(env!("CARGO_MANIFEST_DIR"))
            .args(arguments)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    (git(&["rev-parse", "--show-prefix"])? == "crates/ghostlane-engine/")
        .then(|| git(&["rev-parse", "HEAD"]))
        .flatten()
}

#[test]
fn version_prints_the_pin_and_boringssl() {
    let (lines, code) = Engine::answer(&["version"]);
    assert_eq!(code, Some(0));
    let [Event::Version {
        engine,
        protocol,
        pin,
        boringssl,
        rooms,
        target,
    }] = lines.as_slice()
    else {
        panic!("`version` prints one line of its kind: {lines:?}");
    };
    assert_eq!(engine, env!("CARGO_PKG_VERSION"));
    assert_eq!(*protocol, 1);
    assert!(!target.is_empty());

    // The pin: the builder's word, else this checkout's commit, else unknown.
    let expected = option_env!("GHOSTLANE_ENGINE_PIN")
        .map(str::to_owned)
        .or_else(checkout_commit)
        .unwrap_or_else(|| "unknown".to_owned());
    assert_eq!(*pin, expected, "the pin");
    assert!(
        pin == "unknown"
            || (pin.len() == 40
                && pin
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
        "the pin is a commit: {pin}"
    );

    assert_eq!(*rooms, cfg!(feature = "rooms"), "the rooms");
    if cfg!(feature = "boring") {
        assert!(*boringssl, "built with BoringSSL, `version` says so");
    }
    if !cfg!(feature = "rooms") {
        assert!(!*boringssl, "no rooms, no DTLS of any make");
    }
}

#[cfg(unix)]
#[test]
fn a_session_file_open_to_other_users_is_refused() {
    let scratch = Scratch::new("mode");
    let line = LineServer::start();
    let session = core_line(line.address, &Value::Null);
    let (lines, code) = Engine::answer(&["run", "--session", &scratch.session(&session, 0o644)]);
    assert_eq!(code, Some(1));
    let (reason, failure, message) = last_ended(&lines);
    assert_eq!(
        (reason, failure),
        (EndReason::Failed, Some(FailureCode::Session))
    );
    assert!(message.unwrap().contains("0600"));
    assert_eq!(lines.len(), 1, "nothing was started: {lines:?}");
}

#[test]
fn a_core_the_parser_refuses_is_named_by_run_and_by_check_config() {
    let scratch = Scratch::new("refused");
    let mut session = core_line("127.0.0.1:9".parse().unwrap(), &Value::Null);
    session["core"]["outbounds"][0]["streamSettings"]["network"] = json!("h3");
    let path = scratch.session(&session, 0o600);

    let (lines, code) = Engine::answer(&["run", "--session", &path]);
    assert_eq!(code, Some(1));
    let (reason, failure, message) = last_ended(&lines);
    assert_eq!(
        (reason, failure),
        (EndReason::Failed, Some(FailureCode::Config))
    );
    let message = message.unwrap();
    assert!(message.contains("streamSettings"), "{message}");
    assert!(!message.contains(USER), "a refusal quotes no secret");

    let (lines, code) = Engine::answer(&["check-config", "--session", &path]);
    assert_eq!(code, Some(1));
    let [Event::CheckConfig { ok, diagnostics }] = lines.as_slice() else {
        panic!("`check-config` prints one line of its kind: {lines:?}");
    };
    assert!(!*ok);
    assert!(diagnostics
        .iter()
        .any(|found| found.severity == Severity::Error && found.source == Source::Core));
}

#[test]
fn check_config_accepts_a_core_line_and_starts_nothing() {
    let scratch = Scratch::new("accepted");
    let session = core_line("127.0.0.1:9".parse().unwrap(), &json!({"loglevel": "loud"}));
    let path = scratch.session(&session, 0o600);
    let (lines, code) = Engine::answer(&["check-config", "--session", &path]);
    assert_eq!(code, Some(0));
    let [Event::CheckConfig { ok, diagnostics }] = lines.as_slice() else {
        panic!("`check-config` prints one line of its kind: {lines:?}");
    };
    assert!(*ok);
    assert!(
        diagnostics
            .iter()
            .all(|found| found.severity == Severity::Warning),
        "{diagnostics:?}"
    );
    assert!(
        diagnostics
            .iter()
            .any(|found| found.path.as_deref() == Some("$.log.loglevel")),
        "the unknown log level is remarked on: {diagnostics:?}"
    );
}

#[test]
fn a_command_line_that_is_not_understood_is_one_error_line_and_status_two() {
    let cases: [&[&str]; 4] = [&[], &["start"], &["run"], &["run", "--session"]];
    for arguments in cases {
        let (lines, code) = Engine::answer(arguments);
        assert_eq!(code, Some(2), "{arguments:?}");
        assert!(
            matches!(
                lines.as_slice(),
                [Event::Error {
                    code: FailureCode::Usage,
                    ..
                }]
            ),
            "{arguments:?}: {lines:?}"
        );
    }
}

#[test]
fn a_session_that_is_not_there_ends_a_run_and_fails_an_answer() {
    let (lines, code) = Engine::answer(&["run", "--session", "/nonexistent/session.json"]);
    assert_eq!(code, Some(1));
    assert!(
        lines
            .last()
            .is_some_and(ended(EndReason::Failed, Some(FailureCode::Session))),
        "{lines:?}"
    );
    let (lines, code) = Engine::answer(&["check-config", "--session", "/nonexistent/session.json"]);
    assert_eq!(code, Some(1));
    assert!(
        matches!(
            lines.as_slice(),
            [Event::Error {
                code: FailureCode::Session,
                ..
            }]
        ),
        "{lines:?}"
    );
}

/// Without the `rooms` feature the build carries no room: a session with a
/// room half is refused, by `run` and by `check-config`.
#[cfg(not(feature = "rooms"))]
#[test]
fn a_build_without_rooms_refuses_a_room() {
    let scratch = Scratch::new("no-rooms");
    let path = scratch.session(&json!({"version": 1, "room": {}}), 0o600);
    let (lines, code) = Engine::answer(&["run", "--session", &path]);
    assert_eq!(code, Some(1));
    let (reason, failure, message) = last_ended(&lines);
    assert_eq!(
        (reason, failure),
        (EndReason::Failed, Some(FailureCode::Unsupported))
    );
    assert_eq!(message.as_deref(), Some("this build carries no rooms"));

    let (lines, code) = Engine::answer(&["check-config", "--session", &path]);
    assert_eq!(code, Some(1));
    let [Event::CheckConfig { ok, diagnostics }] = lines.as_slice() else {
        panic!("`check-config` prints one line of its kind: {lines:?}");
    };
    assert!(!*ok);
    assert_eq!(diagnostics[0].source, Source::Room);
}

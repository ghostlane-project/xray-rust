//! The room half and the one-shot questions, through the program as an app
//! runs it: a child process with a session file, read through its stdout.
//!
//! The rooms are on the `none` carrier, the interop pipe: a room is a hub's
//! `tcp://host:port/name`. The hub here is a stand-in on loopback that reads
//! each participant's JOIN and then holds the connection, or ends the
//! conference at once. No olcRTC server is in its rooms, so no session opens
//! and a join never gets past its hello; what is asked is what the engine
//! does with a room: it joins the room the session names, says so in its log,
//! leaves it when told to stop, ends with a `room` failure when the room ends,
//! and asks `olc-check` and `olc-ping` in one line each, in a process where
//! nothing ran before.
//!
//! `probe` asks through a core line: a VLESS line on loopback whose far end
//! is in this process, as in `e2e_loopback.rs`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghostlane_engine::events::{EndReason, Event, FailureCode};
use serde_json::{json, Value};

const ENGINE: &str = env!("CARGO_BIN_EXE_ghostlane-engine");
const USER: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const USER_BYTES: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// A room's key: 32 bytes of hex.
const KEY: &str = "4f6c635254432d74657374206b65792c206e6f7420612073656372657421212e";
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
            "ghostlane-engine-room-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Writes `session` as a session file of mode 0600 (Unix), under `name`.
    fn session(&self, name: &str, session: &Value) -> String {
        let path = self.0.join(format!("{name}.json"));
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

/// The last line of a run, which must be `ended`.
#[cfg(feature = "rooms")]
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

/// The one `error` line of a command that failed.
fn the_error(lines: &[Event]) -> (FailureCode, String) {
    match lines {
        [Event::Error { code, message }] => (*code, message.clone()),
        other => panic!("one `error` line was expected: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// A core line, for `probe`.

fn body() -> Vec<u8> {
    (0..16 * 1024_u32)
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

/// The far end of a VLESS line over plain TCP that carries each request to
/// its target and counts it.
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
    /// command, an IPv4 target), the answer `00 00`, then bytes both ways.
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

/// A core line: a SOCKS5 listener on `port` (0: the system picks), and a
/// VLESS outbound to `line`, tagged `proxy`.
fn core_line(line: SocketAddr, port: u16) -> Value {
    json!({
        "version": 1,
        "core": {
            "inbounds": [
                {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": port}
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

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---------------------------------------------------------------------------
// `probe`.

#[test]
fn probe_asks_for_a_url_through_the_line_in_one_line() {
    let scratch = Scratch::new("probe");
    let origin = origin();
    let line = LineServer::start();
    let path = scratch.session("line", &core_line(line.address, 0));
    let url = format!("http://{origin}/generate_204");

    let (lines, code) = Engine::answer(&["probe", "--session", &path, "--url", &url]);
    assert_eq!(code, Some(0), "{lines:?}");
    let [Event::Probe { ok, millis, error }] = lines.as_slice() else {
        panic!("`probe` prints one line of its kind: {lines:?}");
    };
    assert!(*ok && error.is_none(), "{lines:?}");
    assert!(
        millis.is_some(),
        "a probe that was answered says how long it took"
    );
    assert_eq!(
        line.carried.load(Ordering::SeqCst),
        1,
        "it went by the line"
    );

    // The line's own outbound, named.
    let (lines, code) = Engine::answer(&[
        "probe",
        "--session",
        &path,
        "--url",
        &url,
        "--outbound",
        "proxy",
        "--timeout-ms",
        "4000",
    ]);
    assert_eq!(code, Some(0), "{lines:?}");
    assert!(matches!(lines.as_slice(), [Event::Probe { ok: true, .. }]));
    assert_eq!(line.carried.load(Ordering::SeqCst), 2);
}

#[test]
fn probe_through_a_dead_line_is_a_no() {
    let scratch = Scratch::new("probe-dead");
    let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = dead.local_addr().unwrap();
    drop(dead);
    let path = scratch.session("line", &core_line(address, 0));
    let (lines, code) = Engine::answer(&[
        "probe",
        "--session",
        &path,
        "--url",
        "http://127.0.0.1:9/",
        "--timeout-ms",
        "3000",
    ]);
    assert_eq!(code, Some(1), "{lines:?}");
    let [Event::Probe { ok, millis, error }] = lines.as_slice() else {
        panic!("`probe` prints one line of its kind: {lines:?}");
    };
    assert!(!*ok && millis.is_none(), "{lines:?}");
    assert!(error.as_deref().is_some_and(|error| !error.is_empty()));
}

/// The session's own listeners are not the probe's: a probe of a session
/// whose port a running engine holds still asks its question.
#[test]
fn probe_binds_none_of_the_sessions_listeners() {
    let scratch = Scratch::new("probe-beside");
    let origin = origin();
    let line = LineServer::start();
    let session = core_line(line.address, free_port());
    let path = scratch.session("line", &session);
    let mut running = Engine::spawn(&["run", "--session", &path]);
    running.until(SOON, |event| {
        matches!(event, Event::Ready { .. }).then_some(())
    });

    let url = format!("http://{origin}/");
    let (lines, code) = Engine::answer(&["probe", "--session", &path, "--url", &url]);
    assert_eq!(code, Some(0), "{lines:?}");
    assert!(matches!(lines.as_slice(), [Event::Probe { ok: true, .. }]));

    drop(running.stdin.take());
    assert!(running.exit(GONE_WITHIN).success());
}

#[test]
fn probe_refuses_what_it_cannot_ask() {
    let scratch = Scratch::new("probe-refused");
    let line = core_line("127.0.0.1:9".parse().unwrap(), 0);
    let path = scratch.session("line", &line);

    let (lines, code) = Engine::answer(&["probe", "--session", &path]);
    assert_eq!(code, Some(2), "{lines:?}");
    assert_eq!(the_error(&lines).0, FailureCode::Usage, "no `--url`");

    let (lines, code) = Engine::answer(&[
        "probe",
        "--session",
        &path,
        "--url",
        "http://127.0.0.1:9/",
        "--outbound",
        "nowhere",
    ]);
    assert_eq!(code, Some(2), "{lines:?}");
    let (failure, message) = the_error(&lines);
    assert_eq!(failure, FailureCode::Usage, "{message}");
    assert!(message.contains("--outbound"), "{message}");

    let room = scratch.session(
        "room",
        &json!({"version": 1, "room": {"provider": "none", "rooms": ["tcp://127.0.0.1:9/r"], "key": KEY}}),
    );
    let (lines, code) =
        Engine::answer(&["probe", "--session", &room, "--url", "http://127.0.0.1:9/"]);
    assert_eq!(code, Some(1), "{lines:?}");
    assert_eq!(
        the_error(&lines).0,
        FailureCode::Session,
        "no core to ask through"
    );
}

// ---------------------------------------------------------------------------
// The room half.

#[cfg(feature = "rooms")]
mod room {
    use super::*;
    use ghostlane_engine::events::{Severity, Source};

    /// What the hub does with a participant once its JOIN is read.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Then {
        /// Keeps the connection and reads what comes, as a room with nobody
        /// else in it.
        Hold,
        /// Ends the conference: an END frame, then it reads on.
        End,
    }

    /// A participant the hub took.
    struct Joined {
        /// The room its JOIN named.
        room: String,
        /// Told once its connection has closed: it left the room.
        left: Receiver<()>,
    }

    /// An interop-pipe hub on loopback: frames of `u32 BE length | kind |
    /// payload`, the first of a participant's a JOIN (kind 1) naming its room.
    struct Hub {
        address: SocketAddr,
        joins: Receiver<Joined>,
    }

    const KIND_JOIN: u8 = 1;
    const KIND_END: u8 = 5;

    impl Hub {
        fn start(then: Then) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let (tell, joins) = mpsc::channel();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let tell = tell.clone();
                    std::thread::spawn(move || Self::take(stream, then, &tell));
                }
            });
            Self { address, joins }
        }

        fn take(mut stream: TcpStream, then: Then, tell: &mpsc::Sender<Joined>) {
            let Some((kind, room)) = read_frame(&mut stream) else {
                return;
            };
            assert_eq!(kind, KIND_JOIN, "a participant's first frame is its JOIN");
            let (gone, left) = mpsc::channel();
            let room = String::from_utf8(room).expect("a room's name is text");
            let _ = tell.send(Joined { room, left });
            if then == Then::End {
                let reason = b"the conference ended";
                let mut frame = u32::try_from(1 + reason.len())
                    .unwrap()
                    .to_be_bytes()
                    .to_vec();
                frame.push(KIND_END);
                frame.extend_from_slice(reason);
                let _ = stream.write_all(&frame);
            }
            while read_frame(&mut stream).is_some() {}
            let _ = gone.send(());
        }

        /// The URL of room `name` on this hub.
        fn url(&self, name: &str) -> String {
            format!("tcp://{}/{name}", self.address)
        }

        /// The next participant that joined.
        fn joined(&self, within: Duration) -> Joined {
            self.joins
                .recv_timeout(within)
                .unwrap_or_else(|_| panic!("nobody joined a room of the hub within {within:?}"))
        }

        /// Nobody else joined within `within`.
        fn no_more(&self, within: Duration) {
            if let Ok(joined) = self.joins.recv_timeout(within) {
                panic!("an unexpected join of room {:?}", joined.room);
            }
        }
    }

    fn read_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut head = [0_u8; 5];
        stream.read_exact(&mut head).ok()?;
        let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let mut payload = vec![0_u8; length.checked_sub(1)?];
        stream.read_exact(&mut payload).ok()?;
        Some((head[4], payload))
    }

    /// A session whose room half is the hub's room `name`.
    fn none_room(hub: &Hub, name: &str) -> Value {
        json!({
            "version": 1,
            "room": {
                "provider": "none",
                "rooms": [hub.url(name)],
                "key": KEY
            }
        })
    }

    #[test]
    fn a_none_room_is_joined_as_the_session_names_it_and_left_at_the_stop() {
        let scratch = Scratch::new("join");
        let hub = Hub::start(Then::Hold);
        let path = scratch.session("room", &none_room(&hub, "f4b-one"));
        let mut engine = Engine::spawn(&["run", "--session", &path]);

        let joined = hub.joined(SOON);
        assert_eq!(joined.room, "f4b-one", "the room the session names");
        // The room's own lines are the engine's `log` events.
        engine.until(SOON, |event| {
            matches!(event, Event::Log { source: Source::Room, line, .. } if !line.contains('\n'))
                .then_some(())
        });

        let asked = Instant::now();
        drop(engine.stdin.take());
        let status = engine.exit(GONE_WITHIN);
        assert_eq!(status.code(), Some(0), "a stop that was asked for");
        let rest = engine.rest();
        assert_eq!(last_ended(&rest), (EndReason::StdinClosed, None, None));
        // It left the room: the hub's connection closed.
        let left = GONE_WITHIN.saturating_sub(asked.elapsed()) + Duration::from_millis(500);
        joined
            .left
            .recv_timeout(left)
            .expect("the engine left the room when it stopped");
        hub.no_more(Duration::from_millis(200));
    }

    #[test]
    fn a_room_that_ends_ends_the_run_with_a_room_failure() {
        let scratch = Scratch::new("ended");
        let hub = Hub::start(Then::End);
        let path = scratch.session("room", &none_room(&hub, "f4b-ends"));
        let mut engine = Engine::spawn(&["run", "--session", &path]);
        assert_eq!(hub.joined(SOON).room, "f4b-ends");

        let status = engine.exit(SOON);
        assert_eq!(status.code(), Some(1), "{}", engine.so_far());
        let rest = engine.rest();
        let (reason, code, message) = last_ended(&rest);
        assert_eq!((reason, code), (EndReason::Failed, Some(FailureCode::Room)));
        let message = message.unwrap();
        assert!(message.starts_with("the room ended: "), "{message}");
        assert!(!message.contains(KEY), "a failure quotes no key");
        assert!(
            !rest
                .iter()
                .any(|event| matches!(event, Event::Ready { .. })),
            "a room that never served is never `ready`: {rest:?}"
        );
    }

    #[test]
    fn check_config_says_what_it_reads_in_a_room_half() {
        let scratch = Scratch::new("check");
        let room = |half: Value| json!({"version": 1, "room": half});
        let check =
            |name: &str, session: &Value| -> (bool, Vec<(Severity, Option<String>, String)>) {
                let path = scratch.session(name, session);
                let (lines, code) = Engine::answer(&["check-config", "--session", &path]);
                let [Event::CheckConfig { ok, diagnostics }] = lines.as_slice() else {
                    panic!("`check-config` prints one line of its kind: {lines:?}");
                };
                assert_eq!(code, Some(if *ok { 0 } else { 1 }), "{lines:?}");
                for found in diagnostics {
                    assert_eq!(found.source, Source::Room, "{found:?}");
                    assert!(!found.message.contains(KEY), "a finding quotes no key");
                }
                let found = diagnostics
                    .iter()
                    .map(|found| (found.severity, found.path.clone(), found.message.clone()))
                    .collect();
                (*ok, found)
            };
        let paths =
            |found: &[(Severity, Option<String>, String)], severity: Severity| -> Vec<String> {
                found
                    .iter()
                    .filter(|(level, _, _)| *level == severity)
                    .filter_map(|(_, path, _)| path.clone())
                    .collect()
            };

        // Every field the half takes.
        let whole = room(json!({
            "provider": "none",
            "transport": "datachannel",
            "rooms": ["tcp://127.0.0.1:9/a", "tcp://127.0.0.1:9/b"],
            "key": KEY,
            "device_id": "f4b-device",
            "dns": "192.0.2.53:53,198.51.100.53",
            "socks": {"port": 41090, "user": "u", "password": "p"},
            "udp": false,
            "direct_rules": "",
            "dtls_profile": "chrome",
            "channel": "c0ffee",
            "vp8": {"fps": 30, "batch": 64},
            "debug": true
        }));
        let (ok, found) = check("whole", &whole);
        assert!(ok && found.is_empty(), "{found:?}");

        // A room given twice is a remark, not a refusal.
        let twice = room(json!({
            "provider": "none",
            "rooms": ["tcp://127.0.0.1:9/a", "tcp://127.0.0.1:9/a"],
            "key": KEY
        }));
        let (ok, found) = check("twice", &twice);
        assert!(ok, "{found:?}");
        assert_eq!(paths(&found, Severity::Warning), ["$.rooms"], "{found:?}");

        // What is refused, each at its field.
        let cases = [
            (
                "no-key",
                json!({"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"]}),
                "$.key",
            ),
            (
                "bad-key",
                json!({"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"], "key": "zz"}),
                "$.key",
            ),
            (
                "no-rooms",
                json!({"provider": "none", "rooms": [], "key": KEY}),
                "$.rooms",
            ),
            (
                "rooms-text",
                json!({"provider": "none", "rooms": "tcp://127.0.0.1:9/a", "key": KEY}),
                "$.rooms",
            ),
            (
                "provider",
                json!({"provider": "telemost", "rooms": ["https://example.com/j/1"], "key": KEY}),
                "$.provider",
            ),
            (
                "transport",
                json!({"provider": "none", "transport": "smoke", "rooms": ["tcp://127.0.0.1:9/a"], "key": KEY}),
                "$.transport",
            ),
            (
                "unknown",
                json!({"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"], "key": KEY, "colour": "red"}),
                "$.colour",
            ),
            (
                "socks",
                json!({"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"], "key": KEY, "socks": {"port": "x"}}),
                "$.socks.port",
            ),
            (
                "dns",
                json!({"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"], "key": KEY, "dns": ":53"}),
                "$.dns",
            ),
        ];
        for (name, half, path) in cases {
            let (ok, found) = check(name, &room(half));
            assert!(!ok, "{name}: {found:?}");
            assert_eq!(paths(&found, Severity::Error), [path], "{name}: {found:?}");
        }
    }

    #[test]
    fn olc_check_asks_once_in_a_process_of_its_own() {
        let scratch = Scratch::new("olc-check");
        // Nobody answers in the room: a no, once the time is up.
        let quiet = Hub::start(Then::Hold);
        let path = scratch.session("quiet", &none_room(&quiet, "f4b-check"));
        let asked = Instant::now();
        let (lines, code) =
            Engine::answer(&["olc-check", "--session", &path, "--timeout-ms", "1500"]);
        assert_eq!(code, Some(1), "{lines:?}");
        let [Event::OlcCheck { ok, millis, error }] = lines.as_slice() else {
            panic!("`olc-check` prints one line of its kind: {lines:?}");
        };
        assert!(!*ok && millis.is_none(), "{lines:?}");
        assert!(
            error
                .as_deref()
                .is_some_and(|error| error.contains("timed out")),
            "{lines:?}"
        );
        assert!(asked.elapsed() < SOON);
        assert_eq!(quiet.joined(SOON).room, "f4b-check", "it joined the room");

        // The room ends at once: a no, at once.
        let ending = Hub::start(Then::End);
        let path = scratch.session("ending", &none_room(&ending, "f4b-check-ends"));
        let asked = Instant::now();
        let (lines, code) =
            Engine::answer(&["olc-check", "--session", &path, "--timeout-ms", "15000"]);
        assert_eq!(code, Some(1), "{lines:?}");
        assert!(
            matches!(
                lines.as_slice(),
                [Event::OlcCheck {
                    ok: false,
                    error: Some(_),
                    ..
                }]
            ),
            "{lines:?}"
        );
        assert!(
            asked.elapsed() < Duration::from_secs(10),
            "{:?}",
            asked.elapsed()
        );
        assert_eq!(ending.joined(SOON).room, "f4b-check-ends");
    }

    #[test]
    fn olc_ping_needs_a_url_and_answers_once() {
        let scratch = Scratch::new("olc-ping");
        let hub = Hub::start(Then::End);
        let path = scratch.session("room", &none_room(&hub, "f4b-ping"));

        let (lines, code) = Engine::answer(&["olc-ping", "--session", &path]);
        assert_eq!(code, Some(2), "{lines:?}");
        assert_eq!(the_error(&lines).0, FailureCode::Usage, "no `--url`");
        hub.no_more(Duration::from_millis(200));

        let (lines, code) = Engine::answer(&[
            "olc-ping",
            "--session",
            &path,
            "--url",
            "http://127.0.0.1:9/",
            "--timeout-ms",
            "15000",
        ]);
        assert_eq!(code, Some(1), "{lines:?}");
        assert!(
            matches!(
                lines.as_slice(),
                [Event::OlcPing {
                    ok: false,
                    millis: None,
                    error: Some(_)
                }]
            ),
            "{lines:?}"
        );
        assert_eq!(hub.joined(SOON).room, "f4b-ping");
    }

    /// A room question of a session that has no room, and a session whose room
    /// half is refused, are failures of the command, not answers.
    #[test]
    fn olc_check_refuses_what_it_cannot_ask() {
        let scratch = Scratch::new("olc-check-refused");
        let line = scratch.session("line", &core_line("127.0.0.1:9".parse().unwrap(), 0));
        let (lines, code) = Engine::answer(&["olc-check", "--session", &line]);
        assert_eq!(code, Some(1), "{lines:?}");
        assert_eq!(the_error(&lines).0, FailureCode::Session);

        let bad = scratch.session(
            "bad",
            &json!({"version": 1, "room": {"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"], "key": "zz"}}),
        );
        let (lines, code) = Engine::answer(&["olc-check", "--session", &bad]);
        assert_eq!(code, Some(1), "{lines:?}");
        let (failure, message) = the_error(&lines);
        assert_eq!(failure, FailureCode::Room, "{message}");
        assert!(message.starts_with("$.key: "), "{message}");
    }
}

#[cfg(not(feature = "rooms"))]
#[test]
fn without_rooms_the_room_questions_are_refused() {
    let scratch = Scratch::new("no-rooms");
    let path = scratch.session(
        "room",
        &json!({"version": 1, "room": {"provider": "none", "rooms": ["tcp://127.0.0.1:9/a"], "key": KEY}}),
    );
    let asks: [&[&str]; 2] = [
        &["olc-check", "--session", &path],
        &[
            "olc-ping",
            "--session",
            &path,
            "--url",
            "http://127.0.0.1:9/",
        ],
    ];
    for command in asks {
        let (lines, code) = Engine::answer(command);
        assert_eq!(code, Some(1), "{command:?}: {lines:?}");
        assert_eq!(
            the_error(&lines),
            (
                FailureCode::Unsupported,
                "this build carries no rooms".to_owned()
            ),
            "{command:?}"
        );
    }
}

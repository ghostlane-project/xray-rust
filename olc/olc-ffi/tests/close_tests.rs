// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A runtime closed while it runs (Kotlin's `close()`, Swift's last
//! reference: UniFFI frees the object either way) stops its run, bounded as
//! `stop(5_000)` is, and lets go of what it held: the run's tasks, its SOCKS
//! port and the app's session listener. A run left behind kept its session
//! in the room, and a later client's hello reached it (the Android lab's
//! "incompatible control protocol version: peer v3" from the Go server).
//!
//! A process of its own: [`alive_tasks`] counts every task on the process's
//! one runtime, so the tests here take turns.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use ghostlane_runtime::runtime::alive_tasks;
use olc_ffi::runtime::DEFAULT_STOP_TIMEOUT;
use olc_ffi::{OlcrtcRuntime, RoomRun, Runner, SessionListener};

const ROOM: &str = "https://meet.example.org/room";
const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static TURN: Mutex<()> = Mutex::new(());

fn turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs `f` on its own thread and fails if it takes longer than 30 s.
fn bounded(f: impl FnOnce() + Send + 'static) {
    let _turn = turn();
    let (tx, rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => h.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(h.join().unwrap_err());
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("the test did not finish in 30 s"),
    }
}

/// The tasks alive on the process's runtime (none before it is built).
fn tasks() -> usize {
    alive_tasks().unwrap_or(0)
}

/// The tasks alive once they settle to `base` (2 s at most). Each test
/// counts from what it found, so a run another test left behind fails that
/// test alone; on the fix every test finds 0.
fn tasks_left(base: usize) -> usize {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let n = tasks();
        if n <= base || Instant::now() >= until {
            return n;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A latch a run waits on.
#[derive(Clone)]
struct Gate(Arc<tokio::sync::watch::Sender<bool>>);

impl Gate {
    fn new() -> Self {
        Self(Arc::new(tokio::sync::watch::channel(false).0))
    }

    fn open(&self) {
        self.0.send_replace(true);
    }

    async fn wait(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|open| *open).await;
    }
}

/// How the stand-in's run ends.
#[derive(Clone)]
enum Ends {
    /// At the stop, as the client does.
    AtTheStop,
    /// When the gate opens, deaf to the stop (a transport that will not let
    /// go).
    AtTheGate(Gate),
    /// At the stop, once the gate opens and a session has opened.
    AtTheStopAfterASession(Gate),
}

/// The client's SOCKS front, stood in: it listens on a loopback port of its
/// own, tells the port, is ready, and holds the port until its run ends.
fn front(ends: Ends, ports: mpsc::Sender<u16>) -> Runner {
    Arc::new(move |run: RoomRun| {
        let (ends, ports) = (ends.clone(), ports.clone());
        async move {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("listen: {e}"))?;
            let at = l.local_addr().unwrap();
            let _ = ports.send(at.port());
            (run.on_ready)(at);
            match ends {
                Ends::AtTheStop => run.stop.cancelled().await,
                Ends::AtTheGate(g) => {
                    g.wait().await;
                    return Ok(());
                }
                Ends::AtTheStopAfterASession(g) => {
                    g.wait().await;
                    (run.on_session_open)("session-1");
                    run.stop.cancelled().await;
                }
            }
            drop(l);
            Err("context canceled".to_owned())
        }
        .boxed()
    })
}

fn configured(runner: Runner) -> Arc<OlcrtcRuntime> {
    let rt = OlcrtcRuntime::with_runner(runner, Duration::from_millis(10));
    rt.set_provider("none".into()).unwrap();
    rt.set_transport("datachannel".into()).unwrap();
    rt.set_room(ROOM.into()).unwrap();
    rt.set_key(KEY.into()).unwrap();
    rt.set_device_id("device".into());
    rt
}

#[derive(Default)]
struct Sessions(Mutex<Vec<String>>);

impl SessionListener for Sessions {
    fn on_session_opened(&self, room: String, session_id: String) {
        self.0.lock().unwrap().push(format!("{room} {session_id}"));
    }
}

/// Nothing listens on `port` any more, and it can be listened on again.
fn assert_port_free(port: u16) {
    let at = SocketAddr::from(([127, 0, 0, 1], port));
    let dial = TcpStream::connect_timeout(&at, Duration::from_secs(1));
    assert!(dial.is_err(), "the SOCKS port {port} still accepts");
    TcpListener::bind(at).unwrap_or_else(|e| panic!("the port {port} is still held: {e}"));
}

/// A started runtime, ready; its port.
fn running(rt: &OlcrtcRuntime, ports: &mpsc::Receiver<u16>, base: usize) -> u16 {
    rt.start().unwrap();
    rt.wait_ready(5_000).unwrap();
    let port = ports.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(tasks() > base, "the run has its task");
    port
}

#[test]
fn a_running_runtime_closed_stops_its_run() {
    bounded(|| {
        let base = tasks();
        eprintln!("tasks before the test: {base}");
        let (tx, ports) = mpsc::channel();
        let rt = configured(front(Ends::AtTheStop, tx));
        let sessions = Arc::new(Sessions::default());
        rt.set_session_listener(Some(sessions.clone()));
        let port = running(&rt, &ports, base);

        let t0 = Instant::now();
        drop(rt);
        let took = t0.elapsed();

        assert!(took < Duration::from_secs(2), "the close took {took:?}");
        assert_eq!(tasks_left(base), base, "tasks left after the close");
        assert_eq!(
            Arc::strong_count(&sessions),
            1,
            "the closed runtime still holds the session listener"
        );
        assert_port_free(port);
    });
}

#[test]
fn a_close_waits_for_a_run_deaf_to_the_stop_as_long_as_stop_does() {
    bounded(|| {
        let base = tasks();
        eprintln!("tasks before the test: {base}");
        let (tx, ports) = mpsc::channel();
        let gate = Gate::new();
        let rt = configured(front(Ends::AtTheGate(gate.clone()), tx));
        let sessions = Arc::new(Sessions::default());
        rt.set_session_listener(Some(sessions.clone()));
        let port = running(&rt, &ports, base);

        let t0 = Instant::now();
        drop(rt);
        let took = t0.elapsed();

        let early = DEFAULT_STOP_TIMEOUT - Duration::from_millis(50);
        let late = DEFAULT_STOP_TIMEOUT + Duration::from_secs(2);
        assert!(
            (early..late).contains(&took),
            "the close took {took:?}, stop's bound is {DEFAULT_STOP_TIMEOUT:?}"
        );
        assert_eq!(
            Arc::strong_count(&sessions),
            1,
            "a run that outlived the close still reaches the session listener"
        );
        gate.open();
        assert_eq!(tasks_left(base), base, "tasks left once the run let go");
        assert_port_free(port);
    });
}

/// The app's listener releasing the last reference: the close runs inside
/// the run's own task, so it must not wait for that task.
struct Closer {
    rt: Mutex<Option<Arc<OlcrtcRuntime>>>,
    took: Mutex<mpsc::Sender<Duration>>,
}

impl SessionListener for Closer {
    fn on_session_opened(&self, _room: String, _session_id: String) {
        let rt = self.rt.lock().unwrap().take();
        let t0 = Instant::now();
        drop(rt);
        let _ = self.took.lock().unwrap().send(t0.elapsed());
    }
}

#[test]
fn a_close_inside_the_runs_own_callback_does_not_wait_for_itself() {
    bounded(|| {
        let base = tasks();
        eprintln!("tasks before the test: {base}");
        let (tx, ports) = mpsc::channel();
        let gate = Gate::new();
        let rt = configured(front(Ends::AtTheStopAfterASession(gate.clone()), tx));
        let (took_tx, took) = mpsc::channel();
        let closer = Arc::new(Closer {
            rt: Mutex::new(None),
            took: Mutex::new(took_tx),
        });
        rt.set_session_listener(Some(closer.clone()));
        let port = running(&rt, &ports, base);
        *closer.rt.lock().unwrap() = Some(rt);
        gate.open();

        let took = took
            .recv_timeout(Duration::from_secs(10))
            .expect("the session callback never returned");
        assert!(took < Duration::from_secs(1), "the close took {took:?}");
        assert_eq!(tasks_left(base), base, "tasks left after the close");
        assert_eq!(
            Arc::strong_count(&closer),
            1,
            "the closed runtime still holds the session listener"
        );
        assert_port_free(port);
    });
}

/// Not RED: a close with nothing running waits for nothing.
#[test]
fn closing_an_idle_or_a_stopped_runtime_waits_for_nothing() {
    bounded(|| {
        let base = tasks();
        let (tx, ports) = mpsc::channel();
        let idle = configured(front(Ends::AtTheStop, tx.clone()));
        let t0 = Instant::now();
        drop(idle);
        assert!(t0.elapsed() < Duration::from_millis(200), "{:?}", t0.elapsed());

        let rt = configured(front(Ends::AtTheStop, tx));
        let port = running(&rt, &ports, base);
        rt.stop(5_000).unwrap();
        let t0 = Instant::now();
        drop(rt);
        assert!(t0.elapsed() < Duration::from_millis(200), "{:?}", t0.elapsed());
        assert_eq!(tasks_left(base), base, "tasks left after the stop and the close");
        assert_port_free(port);
    });
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The lifecycle, failover and listener tests of `mobile/` at 2d4266af
//! (`runtime_test.go`, `runtime_stop_timeout_test.go`, `failover_test.go`,
//! `failover_review_test.go`, `listener_test.go`, `probe_test.go`), each
//! with a stand-in runner, as Go's `newRuntime(runner)` gives them one.
//! Every test runs under [`bounded`]: a hang fails it instead of the run.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::FutureExt;

use super::*;

const ROOM: &str = "https://meet.example.org/room";
const STANDBY: &str = "https://meet.example.org/standby";
const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// `errTestRun`.
const BOOM: &str = "test runner failed";
/// `shortFailoverDelay`.
const SHORT: Duration = Duration::from_millis(10);

/// Runs `f` on its own thread and fails if it takes longer than 20 s.
fn bounded(f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    let h = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(()) => h.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(h.join().unwrap_err());
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("the test did not finish in 20 s"),
    }
}

/// A latch a stand-in runner waits on (Go's `chan struct{}` closed once).
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

fn runner<F, Fut>(f: F) -> Runner
where
    F: Fn(RoomRun) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    Arc::new(move |run| f(run).boxed())
}

fn addr() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

/// `blockingReadyRunner`.
fn blocking_ready() -> Runner {
    runner(|run: RoomRun| async move {
        (run.on_ready)(addr());
        run.stop.cancelled().await;
        Err("context canceled".to_owned())
    })
}

/// `configuredRuntime`, with Go's short failover delay.
fn configured(runner: Runner) -> Arc<OlcrtcRuntime> {
    let rt = OlcrtcRuntime::with_runner(runner, SHORT);
    rt.set_provider("none".into()).unwrap();
    rt.set_transport("datachannel".into()).unwrap();
    rt.set_room(ROOM.into()).unwrap();
    rt.set_key(KEY.into()).unwrap();
    rt.set_device_id("device".into());
    rt
}

/// `waitForState`.
fn wait_for_state(rt: &OlcrtcRuntime, want: &str) {
    let until = Instant::now() + Duration::from_secs(1);
    while Instant::now() < until {
        if rt.state() == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("state() = {:?}, want {want:?}", rt.state());
}

fn recv<T>(rx: &mpsc::Receiver<T>, what: &str) -> T {
    rx.recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("{what} never happened"))
}

/// `recordingListener`.
#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

impl SessionListener for Recording {
    fn on_session_opened(&self, room: String, session_id: String) {
        self.0.lock().unwrap().push(format!("{room} {session_id}"));
    }
}

impl Recording {
    fn events(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// One room the supervisor handed the runner (`roomRun`).
type Runs = Arc<Mutex<Vec<(String, bool)>>>;

fn record(runs: &Runs, run: &RoomRun) -> usize {
    let mut r = runs.lock().unwrap();
    r.push((run.cfg.url.clone(), run.cfg.end_on_empty_room));
    r.len()
}

fn pairs(list: &[(&str, bool)]) -> Vec<(String, bool)> {
    list.iter().map(|(r, e)| ((*r).to_owned(), *e)).collect()
}

#[test]
fn runtime_lifecycle() {
    bounded(|| {
        let rt = configured(blocking_ready());
        assert_eq!(rt.state(), "idle");
        rt.start().unwrap();
        assert_eq!(rt.start(), Err(OlcrtcError::AlreadyRunning));
        rt.wait_ready(100).unwrap();
        assert_eq!((rt.state().as_str(), rt.is_running()), ("running", true));
        rt.stop(100).unwrap();
        assert_eq!((rt.state().as_str(), rt.is_running()), ("stopped", false));
        rt.stop(1).unwrap();
    });
}

#[test]
fn wait_ready_returns_the_startup_error_in_gos_words() {
    bounded(|| {
        let rt = configured(runner(|_| async { Err(BOOM.to_owned()) }));
        rt.start().unwrap();
        let err = rt.wait_ready(1000).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "supervisor: max failover cycles exceeded after 1 cycle(s): profile {ROOM:?}: {BOOM}"
            )
        );
        assert!(matches!(err, OlcrtcError::Run(_)));
        wait_for_state(&rt, "stopped");
    });
}

#[test]
fn wait_ready_times_out() {
    bounded(|| {
        let rt = configured(runner(|run: RoomRun| async move {
            run.stop.cancelled().await;
            Err("context canceled".to_owned())
        }));
        rt.start().unwrap();
        assert_eq!(rt.wait_ready(1), Err(OlcrtcError::ReadyTimeout));
        rt.stop(100).unwrap();
    });
}

#[test]
fn a_timeout_never_overflows() {
    assert!(timeout_from_millis(i64::MAX, Duration::from_secs(1)) > Duration::ZERO);
    assert_eq!(
        timeout_from_millis(0, DEFAULT_READY_TIMEOUT),
        DEFAULT_READY_TIMEOUT
    );
    assert_eq!(
        timeout_from_millis(-5, DEFAULT_STOP_TIMEOUT),
        DEFAULT_STOP_TIMEOUT
    );
    assert!(deadline(Duration::MAX) > Instant::now());
}

#[test]
fn a_stop_that_misses_its_deadline_releases_the_runtime() {
    bounded(|| {
        let (release, (started_tx, started)) = (Gate::new(), mpsc::channel());
        let r = release.clone();
        let rt = configured(runner(move |_| {
            let (r, started_tx) = (r.clone(), started_tx.clone());
            async move {
                let _ = started_tx.send(());
                r.wait().await;
                Ok(())
            }
        }));
        rt.start().unwrap();
        recv(&started, "the run");
        assert_eq!(rt.stop(1), Err(OlcrtcError::StopTimeout));
        assert_eq!((rt.state().as_str(), rt.is_running()), ("stopped", false));
        release.open();
        wait_for_state(&rt, "stopped");
    });
}

#[test]
fn a_timed_out_stop_leaves_the_runtime_startable() {
    bounded(|| {
        let (stuck, (started_tx, started)) = (Gate::new(), mpsc::channel());
        let s = stuck.clone();
        let rt = configured(runner(move |run: RoomRun| {
            let (s, started_tx) = (s.clone(), started_tx.clone());
            async move {
                let _ = started_tx.send(());
                (run.on_ready)(addr());
                // Deaf to the stop on purpose: a transport that will not let go.
                s.wait().await;
                Ok(())
            }
        }));
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        assert_eq!(rt.stop(200), Err(OlcrtcError::StopTimeout));
        assert_eq!(rt.state(), "stopped");
        assert!(
            !rt.is_running(),
            "an abandoned generation keeps nothing active"
        );
        rt.start().unwrap();
        recv(&started, "generation 1");
        recv(&started, "generation 2");
        stuck.open();
        rt.stop(1000).unwrap();
    });
}

#[test]
fn an_abandoned_generation_does_not_clobber_its_successor() {
    bounded(|| {
        let (release, stay_up) = (Gate::new(), Gate::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (r, u, c) = (release.clone(), stay_up.clone(), calls.clone());
        let rt = configured(runner(move |run: RoomRun| {
            let first = c.fetch_add(1, Ordering::SeqCst) == 0;
            let gate = if first { r.clone() } else { u.clone() };
            async move {
                (run.on_ready)(addr());
                gate.wait().await;
                Ok(())
            }
        }));
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        assert_eq!(rt.stop(200), Err(OlcrtcError::StopTimeout));
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        // The abandoned one finishes first and must not write its end over
        // the live one's.
        release.open();
        let until = Instant::now() + Duration::from_secs(1);
        while Instant::now() < until {
            assert_eq!(
                rt.state(),
                "running",
                "the live generation stopped reading as running"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(rt.is_running());
        stay_up.open();
        let _ = rt.stop(1000);
    });
}

#[test]
fn a_rapid_restart_uses_new_generations() {
    bounded(|| {
        let rt = configured(blocking_ready());
        for generation in 0..25 {
            rt.start()
                .unwrap_or_else(|e| panic!("start {generation}: {e}"));
            rt.wait_ready(100)
                .unwrap_or_else(|e| panic!("ready {generation}: {e}"));
            rt.stop(100)
                .unwrap_or_else(|e| panic!("stop {generation}: {e}"));
        }
        assert_eq!(rt.shared.lock().next_generation, 25);
    });
}

#[test]
fn a_stale_waiter_cannot_observe_a_restart() {
    bounded(|| {
        let calls = Arc::new(AtomicUsize::new(0));
        let (first_tx, first_started) = mpsc::channel();
        let c = calls.clone();
        let rt = configured(runner(move |run: RoomRun| {
            let call = c.fetch_add(1, Ordering::SeqCst) + 1;
            let first_tx = first_tx.clone();
            async move {
                if call == 1 {
                    let _ = first_tx.send(());
                } else {
                    (run.on_ready)(addr());
                }
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.start().unwrap();
        recv(&first_started, "the first run");
        let first = rt.shared.lock().current.clone().unwrap();
        let stale = std::thread::spawn(move || {
            OlcrtcRuntime::wait_generation_ready(&first, Duration::from_secs(1))
        });
        rt.stop(100).unwrap();
        rt.start().unwrap();
        rt.wait_ready(100).unwrap();
        assert_eq!(stale.join().unwrap(), Err(OlcrtcError::StoppedBeforeReady));
        rt.stop(100).unwrap();
    });
}

#[test]
fn concurrent_start_stop_and_wait_ready() {
    bounded(|| {
        let rt = configured(blocking_ready());
        rt.start().unwrap();
        let mut threads = Vec::new();
        for _ in 0..16 {
            let r = rt.clone();
            threads.push(std::thread::spawn(move || {
                let e = r.start();
                assert!(
                    matches!(e, Ok(()) | Err(OlcrtcError::AlreadyRunning)),
                    "{e:?}"
                );
            }));
            let r = rt.clone();
            threads.push(std::thread::spawn(move || {
                let e = r.wait_ready(100);
                // A stopped generation is not running if it had been ready,
                // stopped-before-ready otherwise.
                assert!(
                    matches!(
                        e,
                        Ok(()) | Err(OlcrtcError::StoppedBeforeReady | OlcrtcError::NotRunning)
                    ),
                    "{e:?}"
                );
            }));
            let r = rt.clone();
            threads.push(std::thread::spawn(move || r.stop(100).unwrap()));
        }
        for t in threads {
            t.join().unwrap();
        }
        rt.stop(100).unwrap();
        wait_for_state(&rt, "stopped");
    });
}

#[test]
fn wait_ready_after_stop_is_not_ready() {
    bounded(|| {
        let rt = configured(blocking_ready());
        rt.start().unwrap();
        rt.wait_ready(1000).unwrap();
        rt.stop(1000).unwrap();
        assert_eq!(rt.wait_ready(100), Err(OlcrtcError::NotRunning));
        assert_eq!(rt.state(), "stopped");
    });
}

#[test]
fn failover_advances_to_the_next_room_when_the_first_ends() {
    bounded(|| {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let s = seen.clone();
        let rt = configured(runner(move |run: RoomRun| {
            s.lock().unwrap().push(run.cfg.url.clone());
            async move {
                if run.cfg.url == ROOM {
                    return Err(BOOM.to_owned());
                }
                (run.on_ready)(addr());
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        assert_eq!(*seen.lock().unwrap(), [ROOM, STANDBY]);
        rt.stop(100).unwrap();
    });
}

/// Item 2 through the API: the room the app adds while a session is live
/// is the next hop, without a restart.
#[test]
fn rooms_added_during_a_session_are_used_at_the_next_hop() {
    bounded(|| {
        let retire = Gate::new();
        let (standby_tx, standby_running) = mpsc::channel();
        let r = retire.clone();
        let rt = configured(runner(move |run: RoomRun| {
            let (r, standby_tx) = (r.clone(), standby_tx.clone());
            async move {
                (run.on_ready)(addr());
                if run.cfg.url == ROOM {
                    r.wait().await;
                    return Ok(());
                }
                let _ = standby_tx.send(run.cfg.url.clone());
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.start().unwrap();
        rt.wait_ready(100).unwrap();
        rt.add_failover_room(STANDBY.into()).unwrap();
        retire.open();
        assert_eq!(
            recv(&standby_running, "the room added mid-session"),
            STANDBY
        );
        assert_eq!(rt.state(), "running");
        rt.stop(100).unwrap();
    });
}

/// The primary the app replaces mid-session (`SetRoom` from a refreshed
/// subscription) heads the walk from the next hop.
#[test]
fn a_primary_replaced_during_a_session_is_the_next_hop() {
    bounded(|| {
        let retire = Gate::new();
        let (next_tx, next) = mpsc::channel();
        let r = retire.clone();
        let rt = configured(runner(move |run: RoomRun| {
            let (r, next_tx) = (r.clone(), next_tx.clone());
            async move {
                (run.on_ready)(addr());
                if run.cfg.url == ROOM {
                    r.wait().await;
                    return Ok(());
                }
                let _ = next_tx.send(run.cfg.url.clone());
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        rt.wait_ready(100).unwrap();
        rt.set_room("https://meet.example.org/new".into()).unwrap();
        rt.clear_failover_rooms();
        retire.open();
        assert_eq!(
            recv(&next, "the new primary"),
            "https://meet.example.org/new"
        );
        rt.stop(100).unwrap();
    });
}

#[test]
fn a_generation_ends_after_one_pass_over_dead_rooms() {
    bounded(|| {
        let tried = Arc::new(AtomicUsize::new(0));
        let t = tried.clone();
        let rt = configured(runner(move |_| {
            t.fetch_add(1, Ordering::SeqCst);
            async { Err(BOOM.to_owned()) }
        }));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        let err = rt.wait_ready(2000).unwrap_err().to_string();
        assert!(
            err.ends_with(&format!("profile {STANDBY:?}: {BOOM}")),
            "{err}"
        );
        wait_for_state(&rt, "stopped");
        assert_eq!(
            tried.load(Ordering::SeqCst),
            2,
            "primary and standby, once each"
        );
    });
}

#[test]
fn the_failover_list_is_ordered_and_deduplicated() {
    let rt = configured(blocking_ready());
    assert!(matches!(
        rt.add_failover_room("  ".into()),
        Err(OlcrtcError::InvalidConfig(_))
    ));
    for room in ["b", ROOM, "a", "b"] {
        rt.add_failover_room(room.into()).unwrap();
    }
    assert_eq!(rt.shared.rooms(), [ROOM, "b", "a"]);
    rt.clear_failover_rooms();
    assert_eq!(rt.shared.rooms(), [ROOM]);
}

#[test]
fn a_handover_never_runs_two_rooms_at_once() {
    bounded(|| {
        let live = Arc::new(Mutex::new((0usize, 0usize)));
        let retire = Gate::new();
        let (standby_tx, standby) = mpsc::channel();
        let (l, r) = (live.clone(), retire.clone());
        let rt = configured(runner(move |run: RoomRun| {
            let (l, r, standby_tx) = (l.clone(), r.clone(), standby_tx.clone());
            async move {
                {
                    let mut g = l.lock().unwrap();
                    g.0 += 1;
                    g.1 = g.1.max(g.0);
                }
                struct Out(Arc<Mutex<(usize, usize)>>);
                impl Drop for Out {
                    fn drop(&mut self) {
                        self.0.lock().unwrap().0 -= 1;
                    }
                }
                let _out = Out(l);
                (run.on_ready)(addr());
                if run.cfg.url == ROOM {
                    r.wait().await;
                    return Ok(());
                }
                let _ = standby_tx.send(());
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        retire.open();
        recv(&standby, "the standby");
        assert_eq!(live.lock().unwrap().1, 1, "rooms running at once");
        rt.stop(1000).unwrap();
    });
}

#[test]
fn rooms_cleared_during_a_session_are_gone_at_the_next_hop() {
    bounded(|| {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let retire = Gate::new();
        let (s, r) = (seen.clone(), retire.clone());
        let rt = configured(runner(move |run: RoomRun| {
            s.lock().unwrap().push(run.cfg.url.clone());
            let r = r.clone();
            async move {
                (run.on_ready)(addr());
                if run.cfg.url == ROOM {
                    r.wait().await;
                }
                Err(BOOM.to_owned())
            }
        }));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        rt.clear_failover_rooms();
        retire.open();
        wait_for_state(&rt, "stopped");
        assert_eq!(
            *seen.lock().unwrap(),
            [ROOM],
            "the withdrawn room was hopped to"
        );
    });
}

#[test]
fn a_single_room_generation_does_not_give_up_on_it() {
    bounded(|| {
        let runs: Runs = Arc::default();
        let release = Gate::new();
        let (rs, r) = (runs.clone(), release.clone());
        let rt = configured(runner(move |run: RoomRun| {
            record(&rs, &run);
            let r = r.clone();
            async move {
                (run.on_ready)(addr());
                r.wait().await;
                Ok(())
            }
        }));
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        let got = runs.lock().unwrap().clone();
        release.open();
        assert_eq!(got, pairs(&[(ROOM, false)]));
        rt.stop(1000).unwrap();
    });
}

#[test]
fn a_second_room_lets_the_next_start_give_up_on_an_empty_room() {
    bounded(|| {
        let runs: Runs = Arc::default();
        let retire = Gate::new();
        let (first_tx, first_started) = mpsc::channel();
        let (standby_tx, standby) = mpsc::channel();
        let (rs, r) = (runs.clone(), retire.clone());
        let rt = configured(runner(move |run: RoomRun| {
            let first = record(&rs, &run) == 1;
            let (r, first_tx, standby_tx) = (r.clone(), first_tx.clone(), standby_tx.clone());
            async move {
                (run.on_ready)(addr());
                if first {
                    let _ = first_tx.send(());
                    r.wait().await;
                    return Err(BOOM.to_owned());
                }
                let _ = standby_tx.send(());
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.start().unwrap();
        recv(&first_started, "the first room");
        rt.add_failover_room(STANDBY.into()).unwrap();
        retire.open();
        recv(&standby, "the room added mid-session");
        assert_eq!(
            *runs.lock().unwrap(),
            pairs(&[(ROOM, false), (STANDBY, true)])
        );
        rt.stop(1000).unwrap();
    });
}

#[test]
fn a_generation_started_with_two_rooms_gives_up_on_the_first() {
    bounded(|| {
        let runs: Runs = Arc::default();
        let release = Gate::new();
        let (rs, r) = (runs.clone(), release.clone());
        let rt = configured(runner(move |run: RoomRun| {
            record(&rs, &run);
            let r = r.clone();
            async move {
                (run.on_ready)(addr());
                r.wait().await;
                Ok(())
            }
        }));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        let got = runs.lock().unwrap().clone();
        release.open();
        assert_eq!(got, pairs(&[(ROOM, true)]));
        rt.stop(1000).unwrap();
    });
}

#[test]
fn the_session_listener_names_the_room_of_each_session() {
    bounded(|| {
        let rt = configured(runner(|run: RoomRun| async move {
            (run.on_session_open)(&format!("session-in-{}", run.cfg.url));
            if run.cfg.url == ROOM {
                return Err(BOOM.to_owned());
            }
            (run.on_ready)(addr());
            run.stop.cancelled().await;
            Err("context canceled".to_owned())
        }));
        let listener = Arc::new(Recording::default());
        rt.set_session_listener(Some(listener.clone()));
        rt.add_failover_room(STANDBY.into()).unwrap();
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        assert_eq!(
            listener.events(),
            [
                format!("{ROOM} session-in-{ROOM}"),
                format!("{STANDBY} session-in-{STANDBY}")
            ]
        );
        rt.stop(100).unwrap();
    });
}

#[test]
fn the_session_listener_is_optional_replaceable_and_can_be_taken_back() {
    bounded(|| {
        let (next, third) = (Gate::new(), Gate::new());
        let (n, t) = (next.clone(), third.clone());
        let rt = configured(runner(move |run: RoomRun| {
            let (n, t) = (n.clone(), t.clone());
            async move {
                (run.on_session_open)("first");
                (run.on_ready)(addr());
                n.wait().await;
                (run.on_session_open)("second");
                t.wait().await;
                (run.on_session_open)("after the listener was removed");
                run.stop.cancelled().await;
                Err("context canceled".to_owned())
            }
        }));
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        let listener = Arc::new(Recording::default());
        rt.set_session_listener(Some(listener.clone()));
        next.open();
        let until = Instant::now() + Duration::from_secs(2);
        while listener.events().is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(listener.events(), [format!("{ROOM} second")]);
        rt.set_session_listener(None);
        third.open();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(listener.events(), [format!("{ROOM} second")]);
        rt.stop(1000).unwrap();
    });
}

#[test]
fn the_session_listener_ignores_a_stopping_generation() {
    bounded(|| {
        let stopping = Gate::new();
        let s = stopping.clone();
        let rt = configured(runner(move |run: RoomRun| {
            let s = s.clone();
            async move {
                (run.on_ready)(addr());
                run.stop.cancelled().await;
                s.wait().await;
                (run.on_session_open)("late");
                Err("context canceled".to_owned())
            }
        }));
        let listener = Arc::new(Recording::default());
        rt.set_session_listener(Some(listener.clone()));
        rt.start().unwrap();
        rt.wait_ready(2000).unwrap();
        let gen = rt.shared.lock().current.clone().unwrap();
        assert_eq!(rt.stop(1), Err(OlcrtcError::StopTimeout));
        stopping.open();
        // The late session is called in before the generation is done.
        assert!(gen.wait(deadline(Duration::from_secs(2)), |f| f.done).done);
        wait_for_state(&rt, "stopped");
        assert!(listener.events().is_empty(), "{:?}", listener.events());
    });
}

/// `listeningProbeRunner`: listens where the probe asks, as the client's
/// SOCKS front does.
fn listening(cfg_tx: mpsc::Sender<String>) -> Runner {
    runner(move |run: RoomRun| {
        let _ = cfg_tx.send(run.cfg.socks.clone());
        async move {
            let l = tokio::net::TcpListener::bind(run.cfg.socks.as_str())
                .await
                .map_err(|e| format!("listen probe SOCKS: {e}"))?;
            (run.on_ready)(l.local_addr().unwrap());
            run.stop.cancelled().await;
            Err("context canceled".to_owned())
        }
    })
}

fn check(rt: &OlcrtcRuntime, port: i64, timeout_ms: i64) -> Result<i64, OlcrtcError> {
    rt.check(
        "none".into(),
        "datachannel".into(),
        ROOM.into(),
        "device".into(),
        KEY.into(),
        port,
        timeout_ms,
        0,
        0,
    )
}

#[test]
fn a_check_asks_for_any_loopback_port() {
    bounded(|| {
        let (cfg_tx, configs) = mpsc::channel();
        let rt = configured(listening(cfg_tx));
        assert!(check(&rt, 0, 1000).unwrap() >= 0);
        assert_eq!(recv(&configs, "the probe"), "127.0.0.1:0");
    });
}

#[test]
fn a_check_on_a_port_in_use_reports_the_bind_error() {
    bounded(|| {
        let (cfg_tx, _configs) = mpsc::channel();
        let rt = configured(listening(cfg_tx));
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = i64::from(busy.local_addr().unwrap().port());
        let err = check(&rt, port, 1000).unwrap_err();
        assert!(err.to_string().starts_with("listen probe SOCKS:"), "{err}");
    });
}

/// A run deaf to readiness. Its async block captures `run.stop` alone (the
/// 2021 edition's disjoint capture), so `on_ready` is dropped uncalled at
/// once: the probe must not take that for the run's end. It did, and then
/// waited on the run with no deadline (the first run of this test hung).
#[test]
fn a_check_that_never_listens_times_out() {
    bounded(|| {
        let rt = configured(runner(|run: RoomRun| async move {
            run.stop.cancelled().await;
            Err("context canceled".to_owned())
        }));
        let t0 = Instant::now();
        assert_eq!(check(&rt, 0, 50), Err(OlcrtcError::ReadyTimeout));
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    });
}

#[test]
fn a_check_reports_the_runs_error() {
    bounded(|| {
        let rt = configured(runner(|_| async { Err(BOOM.to_owned()) }));
        assert_eq!(
            check(&rt, 0, 1000),
            Err(OlcrtcError::Probe(BOOM.to_owned()))
        );
    });
}

#[test]
fn a_start_refuses_what_go_refuses() {
    let rt = OlcrtcRuntime::with_runner(blocking_ready(), SHORT);
    assert_eq!(
        rt.start().unwrap_err().to_string(),
        "invalid mobile runtime configuration: provider \"\""
    );
    assert_eq!(
        rt.set_provider("telemost".into()).unwrap_err().to_string(),
        "unsupported provider: \"telemost\""
    );
    assert_eq!(
        rt.set_transport("carrier-pigeon".into())
            .unwrap_err()
            .to_string(),
        "unsupported transport: \"carrier-pigeon\""
    );
    assert_eq!(
        rt.set_socks_port(0).unwrap_err().to_string(),
        "invalid mobile runtime configuration: SOCKS port must be between 1 and 65535"
    );
    assert_eq!(
        rt.set_dtls_profile("x".into()).unwrap_err().to_string(),
        "dtls profile \"x\": dtls: unknown profile: \"x\""
    );
    assert_eq!(rt.state(), "idle");
}

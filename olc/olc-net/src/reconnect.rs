// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The rejoin supervisor of a carrier's session: Go's `engine.Reconnector`
//! (`internal/engine/reconnect.go` at 2d4266af) in its request mode, the
//! one the MTS Link and VK Calls engines use.
//!
//! A session asks for a rejoin with [`Reconnector::request`] whenever its
//! peer connection, its signalling or the client above it says the path is
//! dead. The requests share one queue slot, so any number of them between
//! two attempts is one rejoin. [`Reconnector::watch`] serves the slot,
//! and looks at its stop before every request it takes from it:
//!
//! 1. while the host protector refuses sockets (a phone with no network)
//!    it waits, asking with one probe socket after 1, 2, 4, 8, 8, ...
//!    seconds for up to five minutes; that wait is not an attempt;
//! 2. it counts the attempt. The count starts again only when more than
//!    five minutes passed since the attempt before; a rejoin that worked
//!    does not reset it. Past the limit the session is told it ended;
//! 3. it runs the session's [`Rejoin::rejoin`]. When that works, the slot
//!    is emptied unless a request was raised *during* the attempt: such a
//!    request is about a room the attempt never saw, and is served next;
//! 4. when it fails, it waits 2 s times the count (30 s at most) and goes
//!    back to step 1.
//!
//! The count-failures mode (`CountFailures`, Jitsi's) is
//! [`Reconnector::with_count_failures`]: failures are counted, not requests;
//! the window runs from the first failure and a success, or an error the
//! session calls a non-failure ([`Rejoin::is_non_failure`], Go's
//! `IsNonFailure`: a room with nobody in it), empties the count; the wait
//! after a failure is taken from the count *before* the attempt, so the
//! first is 0. Go's reconnect and ended callbacks are the session's own
//! here ([`crate::link::LinkEvent`]); the supervisor only says when the
//! limit was reached.
//!
//! It holds no payload: one flag, two counters and, while it waits, one
//! timer.

use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::net;

/// The request count starts again once more than this passed since the
/// last attempt (`reconnectFailureWindow`).
pub const WINDOW: Duration = Duration::from_secs(5 * 60);
/// The wait after failed attempt `n` is `n` times this
/// (`reconnectBackoffStep`).
pub const BACKOFF_STEP: Duration = Duration::from_secs(2);
/// The longest wait after a failed attempt (`reconnectBackoffMax`).
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// The first wait before the route is probed again (`noRouteProbeInitial`).
pub const NO_ROUTE_PROBE_INITIAL: Duration = Duration::from_secs(1);
/// The longest wait between two route probes (`noRouteProbeMax`).
pub const NO_ROUTE_PROBE_MAX: Duration = Duration::from_secs(8);
/// How long an attempt is held back for a route at most (`noRouteMaxWait`):
/// a protector that refuses for some other reason still lets the attempts
/// run out and end the session.
pub const NO_ROUTE_MAX_WAIT: Duration = Duration::from_secs(5 * 60);

/// How a rejoin request was handled (`ReconnectRequest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// The session's state or its policy refused the request.
    Rejected,
    /// The request took the queue slot.
    Queued,
    /// Another request already holds the queue slot.
    Coalesced,
}

/// Says whether a socket can be opened right now (`RouteProbe`).
pub type RouteProbe = Arc<dyn Fn() -> bool + Send + Sync>;
/// The caller's own word on whether a rejoin may be asked for
/// (`SetShouldReconnect`).
pub type Policy = Arc<dyn Fn() -> bool + Send + Sync>;

/// The session a [`Reconnector`] rejoins for.
pub trait Rejoin: Sync {
    /// Why a rejoin failed.
    type Error: Display + Send;

    /// One attempt: tear the old join down, take fresh credentials, join
    /// again, and tell the layer above (Go's `Reconnect` callback). It is
    /// awaited to its end: a session that stops in the middle returns an
    /// error of its own, as Go's does on a cancelled context. No attempt
    /// begins once the watch has seen its stop.
    fn rejoin(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// A failed attempt, before the backoff (`OnError`).
    fn failed(&self, _err: &Self::Error) {}

    /// The attempts ran out: the session has ended, with why (`OnLimit`).
    fn limit_reached(&self, reason: &str);

    /// An error that is not a failure (count-failures mode): the attempt
    /// ends with no `failed` call and no wait, and the count starts again
    /// (`IsNonFailure`, Jitsi's "no peer in the room yet").
    fn is_non_failure(&self, _err: &Self::Error) -> bool {
        false
    }
}

/// The request counter (`count`, `lastRequest`).
#[derive(Debug, Default)]
struct Counter {
    count: u32,
    last: Option<Instant>,
    /// Count-failures mode: when the first failure of the run came.
    window_start: Option<Instant>,
}

/// Serialises and coalesces a session's rejoin requests (`Reconnector`).
pub struct Reconnector {
    max_attempts: u32,
    limit_reason: String,
    route_probe: Option<RouteProbe>,
    count_failures: bool,
    /// The queue of one: a request is waiting to be served.
    pending: AtomicBool,
    /// Every request that took the slot, so a success can tell one raised
    /// before the attempt from one raised during it.
    queued: AtomicU64,
    wake: Notify,
    policy: Mutex<Option<Policy>>,
    counter: Mutex<Counter>,
}

impl std::fmt::Debug for Reconnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reconnector")
            .field("max_attempts", &self.max_attempts)
            .field("limit_reason", &self.limit_reason)
            .field("route_probe", &self.route_probe.is_some())
            .field("pending", &self.pending.load(Ordering::Relaxed))
            .field("queued", &self.queued.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Reconnector {
    /// A supervisor that allows `max_attempts` attempts within [`WINDOW`]
    /// of one another and ends the session with `limit_reason` at the next.
    /// The route is asked of the host protector ([`net::probe_route`]).
    #[must_use]
    pub fn new(max_attempts: u32, limit_reason: impl Into<String>) -> Self {
        Self {
            max_attempts,
            limit_reason: limit_reason.into(),
            route_probe: Some(Arc::new(net::probe_route)),
            count_failures: false,
            pending: AtomicBool::new(false),
            queued: AtomicU64::new(0),
            wake: Notify::new(),
            policy: Mutex::new(None),
            counter: Mutex::new(Counter::default()),
        }
    }

    /// Replaces the route probe; `None` gates nothing.
    #[must_use]
    pub fn with_route_probe(mut self, probe: Option<RouteProbe>) -> Self {
        self.route_probe = probe;
        self
    }

    /// Counts failed attempts instead of requests (`CountFailures`).
    #[must_use]
    pub fn with_count_failures(mut self, on: bool) -> Self {
        self.count_failures = on;
        self
    }

    /// Sets, or with `None` removes, the caller's policy
    /// (`SetShouldReconnect`).
    pub fn set_should_reconnect(&self, policy: Option<Policy>) {
        *lock(&self.policy) = policy;
    }

    /// Whether the policy allows a rejoin (`ShouldReconnect`); with none
    /// set it does.
    #[must_use]
    pub fn should_reconnect(&self) -> bool {
        // The policy runs outside the lock: it is the caller's code.
        let policy = lock(&self.policy).clone();
        policy.is_none_or(|allows| allows())
    }

    /// Queues a rejoin unless the session's state or the policy refuses it
    /// (`Request`).
    pub fn request(&self, closed: bool, reconnecting: bool) -> Request {
        if closed || reconnecting || !self.should_reconnect() {
            return Request::Rejected;
        }
        if self
            .pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Request::Coalesced;
        }
        self.queued.fetch_add(1, Ordering::AcqRel);
        self.wake.notify_one();
        Request::Queued
    }

    /// Empties the queue slot and says whether a request was in it
    /// (`Drain`).
    pub fn drain(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    /// Serves the rejoin requests until `stop` resolves or the attempts
    /// run out (`Watch`). `stop` is what Go's context and `done` channel
    /// are together.
    ///
    /// `stop` is looked at before the queue, every time: a request that is
    /// waiting when the stop comes, or was raised during the rejoin the
    /// stop came in, is left in the slot and no join is made for it. Go's
    /// `select` may still pick the queue there, but its reconnect callback
    /// is handed the cancelled context and fails at once;
    /// [`Rejoin::rejoin`] is handed nothing.
    pub async fn watch<R: Rejoin>(&self, session: &R, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        loop {
            if stopped(stop.as_mut()).await {
                return;
            }
            if self.drain() {
                if self.handle_attempt(session, stop.as_mut()).await {
                    return;
                }
                continue;
            }
            tokio::select! {
                biased;
                () = stop.as_mut() => return,
                () = self.wake.notified() => {}
            }
        }
    }

    /// One served request (`handleRequestAttempt`): attempts until one
    /// works. True when the watch is over: `stop` resolved or the limit
    /// was reached.
    async fn handle_attempt<R: Rejoin, S: Future<Output = ()>>(
        &self,
        session: &R,
        mut stop: Pin<&mut S>,
    ) -> bool {
        if self.count_failures {
            return self.handle_failure_attempts(session, stop).await;
        }
        // The bound is checked before every attempt, not once: a room that
        // is gone for good must reach the limit, the only way the layer
        // above learns the session is over.
        loop {
            if self.await_route(stop.as_mut()).await {
                return true;
            }
            let count = self.next_request_count();
            if count > self.max_attempts {
                session.limit_reached(&self.limit_reason);
                return true;
            }
            let seen = self.queued.load(Ordering::Acquire);
            match session.rejoin().await {
                Ok(()) => {
                    // `dropRequestsOlderThan`: a request raised while the
                    // attempt ran is about a room it never saw (#31).
                    if self.queued.load(Ordering::Acquire) == seen {
                        self.drain();
                    }
                    return false;
                }
                Err(e) => {
                    session.failed(&e);
                    if wait(stop.as_mut(), backoff(count)).await {
                        return true;
                    }
                }
            }
        }
    }

    /// `handleFailureAttempts`.
    async fn handle_failure_attempts<R: Rejoin, S: Future<Output = ()>>(
        &self,
        session: &R,
        mut stop: Pin<&mut S>,
    ) -> bool {
        loop {
            if self.await_route(stop.as_mut()).await {
                return true;
            }
            let failures = self.failure_count();
            if failures > self.max_attempts {
                session.limit_reached(&self.limit_reason);
                return true;
            }
            let wait_after = backoff(failures);
            let seen = self.queued.load(Ordering::Acquire);
            match session.rejoin().await {
                Ok(()) => {
                    self.reset_failures();
                    if self.queued.load(Ordering::Acquire) == seen {
                        self.drain();
                    }
                    return false;
                }
                Err(e) if session.is_non_failure(&e) => {
                    self.reset_failures();
                    if self.queued.load(Ordering::Acquire) == seen {
                        self.drain();
                    }
                    return false;
                }
                Err(e) => {
                    session.failed(&e);
                    self.record_failure();
                    if wait(stop.as_mut(), wait_after).await {
                        return true;
                    }
                }
            }
        }
    }

    /// `failureCount`: the count, which starts again once the window from
    /// the first failure has passed.
    fn failure_count(&self) -> u32 {
        let mut c = lock(&self.counter);
        if c.window_start
            .is_some_and(|w| Instant::now().duration_since(w) > WINDOW)
        {
            c.count = 0;
            c.window_start = None;
        }
        c.count
    }

    fn record_failure(&self) {
        let mut c = lock(&self.counter);
        c.count = c.count.saturating_add(1);
        c.window_start.get_or_insert_with(Instant::now);
    }

    fn reset_failures(&self) {
        let mut c = lock(&self.counter);
        c.count = 0;
        c.window_start = None;
    }

    /// Holds the next attempt while the host protector refuses sockets
    /// (`awaitRoute`). A phone that lost its network has no interface to
    /// dial from: an attempt there learns nothing and counts towards the
    /// limit that ends the session for good (olcbox#37). True when `stop`
    /// ended the wait.
    async fn await_route<S: Future<Output = ()>>(&self, mut stop: Pin<&mut S>) -> bool {
        let Some(probe) = &self.route_probe else {
            return false;
        };
        if probe() {
            return false;
        }
        let started = Instant::now();
        let mut delay = NO_ROUTE_PROBE_INITIAL;
        crate::info!(
            "reconnect: no route out, the host refuses sockets; probing again in {}, for up to {}",
            go_seconds(delay),
            go_seconds(NO_ROUTE_MAX_WAIT)
        );
        loop {
            if wait(stop.as_mut(), delay).await {
                return true;
            }
            if probe() {
                crate::info!(
                    "reconnect: route is back after {}",
                    go_seconds(started.elapsed())
                );
                return false;
            }
            if started.elapsed() >= NO_ROUTE_MAX_WAIT {
                crate::info!(
                    "reconnect: still no route after {}; attempting anyway",
                    go_seconds(NO_ROUTE_MAX_WAIT)
                );
                return false;
            }
            delay = (delay * 2).min(NO_ROUTE_PROBE_MAX);
        }
    }

    /// `nextRequestCount`.
    fn next_request_count(&self) -> u32 {
        let mut c = lock(&self.counter);
        let now = Instant::now();
        if c.last.is_none_or(|last| now.duration_since(last) > WINDOW) {
            c.count = 0;
        }
        c.count = c.count.saturating_add(1);
        c.last = Some(now);
        c.count
    }
}

/// The wait after failed attempt `count` (`reconnectBackoff`).
#[must_use]
pub fn backoff(count: u32) -> Duration {
    BACKOFF_STEP.saturating_mul(count).min(BACKOFF_MAX)
}

/// Waits `delay`; true when `stop` resolved first (`waitReconnect`).
async fn wait<S: Future<Output = ()>>(stop: Pin<&mut S>, delay: Duration) -> bool {
    tokio::select! {
        biased;
        () = stop => true,
        () = tokio::time::sleep(delay) => false,
    }
}

/// Whether `stop` has resolved by now; it waits for nothing.
async fn stopped<S: Future<Output = ()>>(stop: Pin<&mut S>) -> bool {
    tokio::select! {
        biased;
        () = stop => true,
        () = std::future::ready(()) => false,
    }
}

/// A duration rounded to a second, as Go's `%s` prints one
/// (`d.Round(time.Second).String()`): `3s`, `1m5s`, `5m0s`, `1h0m0s`.
fn go_seconds(d: Duration) -> String {
    let total = d.as_secs() + u64::from(d.subsec_nanos() >= 500_000_000);
    let (h, m, s) = (total / 3600, total / 60 % 60, total % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::sync::atomic::AtomicU32;

    /// A stuck test fails instead of holding the shared build box. The
    /// clock is paused in every test here, so the bound is an hour of it:
    /// the waits under test run to minutes.
    async fn bounded<F: Future>(f: F) -> F::Output {
        tokio::time::timeout(S(3600), f)
            .await
            .expect("the test did not finish within an hour of the paused clock")
    }

    type Outcome = Box<dyn Fn(u32) -> Result<(), String> + Send + Sync>;

    /// A session whose rejoin `n` (from 1) ends as `outcome(n)` says, and
    /// which notes when each began, each failure and the end.
    struct Session {
        began: Instant,
        outcome: Outcome,
        calls: AtomicU32,
        at: Mutex<Vec<Duration>>,
        failures: Mutex<Vec<String>>,
        ended: Mutex<Vec<String>>,
    }

    impl Session {
        fn new(outcome: impl Fn(u32) -> Result<(), String> + Send + Sync + 'static) -> Self {
            Self {
                began: Instant::now(),
                outcome: Box::new(outcome),
                calls: AtomicU32::new(0),
                at: Mutex::new(Vec::new()),
                failures: Mutex::new(Vec::new()),
                ended: Mutex::new(Vec::new()),
            }
        }

        fn ok() -> Self {
            Self::new(|_| Ok(()))
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::Acquire)
        }

        fn at(&self) -> Vec<Duration> {
            lock(&self.at).clone()
        }

        fn ended(&self) -> Vec<String> {
            lock(&self.ended).clone()
        }

        fn failures_seen(&self) -> Vec<String> {
            lock(&self.failures).clone()
        }
    }

    impl Rejoin for Session {
        type Error = String;

        async fn rejoin(&self) -> Result<(), String> {
            let n = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
            lock(&self.at).push(self.began.elapsed());
            (self.outcome)(n)
        }

        fn failed(&self, err: &String) {
            lock(&self.failures).push(err.clone());
        }

        fn is_non_failure(&self, err: &String) -> bool {
            err.starts_with("nofail")
        }

        fn limit_reached(&self, reason: &str) {
            lock(&self.ended).push(reason.to_string());
        }
    }

    /// Without a route probe, as Go's own tests of the counter run (their
    /// process has no protector).
    fn ungated(max: u32) -> Reconnector {
        Reconnector::new(max, "limit").with_route_probe(None)
    }

    /// `newRouteGatedReconnector`, with the real pacing on a paused clock.
    fn gated(probe: impl Fn() -> bool + Send + Sync + 'static) -> Reconnector {
        Reconnector::new(3, "limit").with_route_probe(Some(Arc::new(probe)))
    }

    fn count(r: &Reconnector) -> u32 {
        lock(&r.counter).count
    }

    const S: fn(u64) -> Duration = Duration::from_secs;

    /// One served request with nothing to stop it.
    async fn attempt(r: &Reconnector, s: &Session) -> bool {
        let stop = pending::<()>();
        tokio::pin!(stop);
        bounded(r.handle_attempt(s, stop.as_mut())).await
    }

    // TestReconnectorRequestWindowReset
    #[tokio::test(start_paused = true)]
    async fn an_expired_request_window_starts_the_count_again() {
        let r = ungated(2);
        let s = Session::ok();
        *lock(&r.counter) = Counter {
            count: 2,
            last: Some(Instant::now()),
            ..Counter::default()
        };
        tokio::time::advance(WINDOW + S(1)).await;
        assert!(!attempt(&r, &s).await, "an expired window ended the loop");
        assert_eq!((s.calls(), count(&r)), (1, 1));
        assert!(s.ended().is_empty());
    }

    // TestReconnectorMaxAttempts
    #[tokio::test(start_paused = true)]
    async fn past_the_limit_no_attempt_is_made_and_the_session_is_told() {
        let r = ungated(2);
        let s = Session::ok();
        *lock(&r.counter) = Counter {
            count: 2,
            last: Some(Instant::now()),
            ..Counter::default()
        };
        assert!(attempt(&r, &s).await, "the loop went on past the limit");
        assert_eq!(s.calls(), 0, "rejoin called after the limit");
        assert_eq!(s.ended(), ["limit"]);
    }

    // TestReconnectorFailureWindowReset
    #[tokio::test(start_paused = true)]
    async fn an_expired_failure_window_starts_the_count_again() {
        let r = ungated(2).with_count_failures(true);
        let s = Session::ok();
        *lock(&r.counter) = Counter {
            count: 3,
            window_start: Some(Instant::now()),
            ..Counter::default()
        };
        tokio::time::advance(WINDOW + S(1)).await;
        assert!(!attempt(&r, &s).await, "an expired window ended the loop");
        let c = lock(&r.counter);
        assert_eq!((c.count, c.window_start), (0, None));
        assert_eq!(s.calls(), 1);
    }

    /// Failures are counted, not requests: six failed attempts wait 0, 2,
    /// 4, 6, 8 and 10 s (the wait is taken from the count before the
    /// attempt), and the seventh is the limit.
    #[tokio::test(start_paused = true)]
    async fn counted_failures_wait_from_zero_and_run_out_at_the_seventh() {
        let r = ungated(5).with_count_failures(true);
        let s = Session::new(|n| Err(format!("no {n}")));
        assert!(attempt(&r, &s).await, "the loop went on past the limit");
        assert_eq!(s.at(), [S(0), S(0), S(2), S(6), S(12), S(20)]);
        assert_eq!(s.began.elapsed(), S(30));
        assert_eq!(s.failures_seen().len(), 6);
        assert_eq!(s.ended(), ["limit"]);
    }

    /// A success empties the count, which request mode never does.
    #[tokio::test(start_paused = true)]
    async fn a_success_resets_the_failure_count() {
        let r = ungated(5).with_count_failures(true);
        let s = Session::new(|n| if n < 3 { Err("down".into()) } else { Ok(()) });
        assert!(!attempt(&r, &s).await);
        assert_eq!(s.calls(), 3);
        let c = lock(&r.counter);
        assert_eq!((c.count, c.window_start), (0, None));
    }

    /// An error the session calls a non-failure resets the count, is not
    /// reported through `failed`, and ends the served request.
    #[tokio::test(start_paused = true)]
    async fn a_non_failure_resets_the_count_and_reports_nothing() {
        let r = ungated(5).with_count_failures(true);
        let s = Session::new(|n| match n {
            1 | 2 => Err("down".into()),
            _ => Err("nofail: alone in the room".into()),
        });
        assert!(
            !attempt(&r, &s).await,
            "a non-failure ends the request, not the watch"
        );
        assert_eq!(s.calls(), 3);
        assert_eq!(s.failures_seen(), ["down", "down"]);
        let c = lock(&r.counter);
        assert_eq!((c.count, c.window_start), (0, None));
        assert!(s.ended().is_empty());
    }

    /// The window runs from the first failure, and a failure after it
    /// restarts the count.
    #[tokio::test(start_paused = true)]
    async fn the_failure_window_runs_from_the_first_failure() {
        let r = ungated(5).with_count_failures(true);
        let s = Session::new(|_| Err("down".into()));
        let t0 = Instant::now();
        *lock(&r.counter) = Counter {
            count: 6,
            window_start: Some(t0),
            ..Counter::default()
        };
        tokio::time::advance(WINDOW).await;
        // Exactly the window: the count stands, so the limit is met.
        assert!(attempt(&r, &s).await);
        assert_eq!(s.calls(), 0);
        assert_eq!(s.ended(), ["limit"]);
    }

    // TestReconnectorCoalescesAndGuardsRequests
    #[test]
    fn requests_are_guarded_and_coalesced() {
        let r = ungated(0);
        assert_eq!(r.request(true, false), Request::Rejected, "closed");
        assert_eq!(r.request(false, true), Request::Rejected, "reconnecting");
        r.set_should_reconnect(Some(Arc::new(|| false)));
        assert!(!r.should_reconnect());
        assert_eq!(r.request(false, false), Request::Rejected, "policy");

        r.set_should_reconnect(None);
        assert!(r.should_reconnect());
        assert_eq!(r.request(false, false), Request::Queued, "first");
        assert_eq!(r.request(false, false), Request::Coalesced, "second");
        assert!(r.drain(), "the queue held no request");
        assert!(!r.drain(), "the queue held more than one request");
    }

    // TestReconnectorCancellationStopsBackoff
    #[tokio::test(start_paused = true)]
    async fn a_stop_ends_the_backoff() {
        let r = ungated(1);
        let stopped = Arc::new(Notify::new());
        let s = Session::new({
            let stopped = stopped.clone();
            move |_| {
                stopped.notify_one();
                Err("failed".to_string())
            }
        });
        let began = Instant::now();
        let stop = stopped.notified();
        tokio::pin!(stop);
        assert!(
            bounded(r.handle_attempt(&s, stop.as_mut())).await,
            "a stopped loop went on"
        );
        assert_eq!(began.elapsed(), S(0), "the backoff was waited out");
        assert_eq!(s.calls(), 1);
        assert_eq!(*lock(&s.failures), ["failed"]);
        assert!(s.ended().is_empty());
    }

    // TestReconnectorCallbacksAreRaceSafe: every request that was told
    // `Queued` is found by exactly one drain, whatever the policy does
    // meanwhile.
    #[test]
    fn requests_from_many_threads_are_each_served_once() {
        fn shared<T: Send + Sync>(_: &T) {}
        let r = ungated(0);
        shared(&r);
        let (queued, drained) = (AtomicU64::new(0), AtomicU64::new(0));
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    start.wait();
                    for _ in 0..2_000 {
                        r.set_should_reconnect(Some(Arc::new(|| true)));
                        r.set_should_reconnect(None);
                    }
                });
                scope.spawn(|| {
                    start.wait();
                    for _ in 0..20_000 {
                        if r.request(false, false) == Request::Queued {
                            queued.fetch_add(1, Ordering::AcqRel);
                        }
                        if r.drain() {
                            drained.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                });
            }
        });
        let left = u64::from(r.drain());
        let queued = queued.into_inner();
        assert!(queued > 0, "no request was ever queued");
        assert_eq!(queued, drained.into_inner() + left);
        assert_eq!(r.queued.load(Ordering::Acquire), queued);
    }

    // TestARequestRaisedDuringAnAttemptIsKept (#31)
    #[tokio::test(start_paused = true)]
    async fn a_request_raised_during_an_attempt_is_kept() {
        let r = Arc::new(ungated(4));
        let during = Arc::new(Mutex::new(None));
        let s = Session::new({
            let (r, during) = (r.clone(), during.clone());
            move |_| {
                // The provider moves the room while we are still rejoining.
                *lock(&during) = Some(r.request(false, false));
                Ok(())
            }
        });
        assert!(
            !attempt(&r, &s).await,
            "a rejoin that worked ended the loop"
        );
        assert_eq!(*lock(&during), Some(Request::Queued));
        assert!(
            r.drain(),
            "the request raised during the attempt was thrown away"
        );
    }

    // TestARequestRaisedBeforeAnAttemptIsDropped
    #[tokio::test(start_paused = true)]
    async fn a_request_raised_before_an_attempt_is_dropped() {
        let r = ungated(4);
        let s = Session::ok();
        assert_eq!(r.request(false, false), Request::Queued);
        assert!(
            !attempt(&r, &s).await,
            "a rejoin that worked ended the loop"
        );
        assert!(!r.drain(), "a request from before the attempt outlived it");
    }

    // TestReconnectorWaitsForRouteBeforeAttempt
    #[tokio::test(start_paused = true)]
    async fn an_attempt_waits_for_the_route() {
        let probes = Arc::new(AtomicU32::new(0));
        let r = gated({
            let probes = probes.clone();
            move || probes.fetch_add(1, Ordering::AcqRel) + 1 >= 3
        });
        let s = Session::ok();
        assert!(
            !attempt(&r, &s).await,
            "a rejoin that worked ended the loop"
        );
        assert_eq!((probes.load(Ordering::Acquire), s.calls()), (3, 1));
        // Asked at once, after 1 s and after 2 s more.
        assert_eq!(s.at(), [S(3)]);
        assert_eq!(count(&r), 1, "waiting for a route is not an attempt");
    }

    // TestReconnectorRouteWaitEndsWithContext
    #[tokio::test(start_paused = true)]
    async fn the_route_wait_ends_with_the_stop() {
        let r = gated(|| false);
        let s = Session::ok();
        let began = Instant::now();
        let stop = tokio::time::sleep(Duration::from_millis(20_500));
        tokio::pin!(stop);
        assert!(
            bounded(r.handle_attempt(&s, stop.as_mut())).await,
            "a stopped route wait went on"
        );
        assert_eq!(began.elapsed(), Duration::from_millis(20_500));
        assert_eq!(s.calls(), 0, "an attempt was made with no route");
        assert_eq!(count(&r), 0);
    }

    // TestReconnectorRouteWaitGivesUpAfterMaxWait
    #[tokio::test(start_paused = true)]
    async fn the_route_wait_gives_up_after_the_max_wait() {
        let probes = Arc::new(AtomicU32::new(0));
        let r = gated({
            let probes = probes.clone();
            move || {
                probes.fetch_add(1, Ordering::AcqRel);
                false
            }
        });
        let s = Session::ok();
        assert!(
            !attempt(&r, &s).await,
            "a rejoin that worked ended the loop"
        );
        // Probes at 0, 1, 3, 7, 15 s and then every 8 s; the first one at
        // or past five minutes is at 303 s, the 41st.
        assert_eq!(s.at(), [S(303)], "the attempt once the wait is over");
        assert_eq!(probes.load(Ordering::Acquire), 41);
        assert_eq!(count(&r), 1);
    }

    // TestReconnectorWithoutRouteProbeAttemptsAtOnce
    #[tokio::test(start_paused = true)]
    async fn without_a_route_probe_the_attempt_is_made_at_once() {
        let r = ungated(1);
        let s = Session::ok();
        assert!(
            !attempt(&r, &s).await,
            "a rejoin that worked ended the loop"
        );
        assert_eq!(s.at(), [S(0)]);
    }

    // reconnect.go:183-208: the bound is checked before every attempt, and
    // the route before that.
    #[tokio::test(start_paused = true)]
    async fn failed_attempts_back_off_and_run_out() {
        let probes = Arc::new(AtomicU32::new(0));
        let r = gated({
            let probes = probes.clone();
            move || {
                probes.fetch_add(1, Ordering::AcqRel);
                true
            }
        });
        let s = Session::new(|n| Err(format!("no {n}")));
        assert!(attempt(&r, &s).await, "the loop went on past the limit");
        // 2 s after the first failure, 4 s after the second; the limit is
        // found 6 s after the third.
        assert_eq!(s.at(), [S(0), S(2), S(6)]);
        assert_eq!(s.began.elapsed(), S(12));
        assert_eq!(*lock(&s.failures), ["no 1", "no 2", "no 3"]);
        assert_eq!(s.ended(), ["limit"]);
        assert_eq!(probes.load(Ordering::Acquire), 4, "asked before each count");
    }

    /// A watch on its own task, and what stops it.
    fn watched(
        r: &Arc<Reconnector>,
        s: &Arc<Session>,
    ) -> (tokio::task::JoinHandle<()>, Arc<Notify>) {
        let stop = Arc::new(Notify::new());
        let task = tokio::spawn({
            let (r, s, stop) = (r.clone(), s.clone(), stop.clone());
            async move { r.watch(&*s, stop.notified()).await }
        });
        (task, stop)
    }

    /// Lets the watch run until every timer it could be waiting on is
    /// later than `d` from now.
    async fn settle(d: Duration) {
        tokio::time::sleep(d).await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_watch_serves_requests_until_it_is_stopped() {
        let r = Arc::new(ungated(10));
        let s = Arc::new(Session::ok());
        let (task, stop) = watched(&r, &s);
        settle(S(1)).await;
        assert_eq!(s.calls(), 0, "a rejoin nobody asked for");

        // Three requests before the watch runs are one rejoin.
        assert_eq!(r.request(false, false), Request::Queued);
        assert_eq!(r.request(false, false), Request::Coalesced);
        assert_eq!(r.request(false, false), Request::Coalesced);
        settle(S(1)).await;
        assert_eq!(s.calls(), 1);

        assert_eq!(r.request(false, false), Request::Queued);
        settle(S(1)).await;
        assert_eq!(s.calls(), 2);
        assert!(!task.is_finished());

        stop.notify_one();
        bounded(task).await.unwrap();
        // A request after the stop is queued and never served.
        assert_eq!(r.request(false, false), Request::Queued);
        settle(S(1)).await;
        assert_eq!(s.calls(), 2);
        assert!(s.ended().is_empty());
    }

    // reconnect.go:197-203: a rejoin that worked does not give the
    // attempts back; only five quiet minutes do.
    #[tokio::test(start_paused = true)]
    async fn a_rejoin_that_worked_does_not_reset_the_count() {
        let r = Arc::new(ungated(2));
        let s = Arc::new(Session::ok());
        let (task, _stop) = watched(&r, &s);
        for want in 1..=2 {
            r.request(false, false);
            settle(S(1)).await;
            assert_eq!(s.calls(), want);
        }
        r.request(false, false);
        bounded(task).await.unwrap();
        assert_eq!(s.calls(), 2, "a third attempt within the window");
        assert_eq!(s.ended(), ["limit"]);
    }

    // #31 through the watch: the request raised during a rejoin is served
    // by a second one, and that one's own request by a third.
    #[tokio::test(start_paused = true)]
    async fn the_watch_serves_a_request_raised_during_a_rejoin() {
        let r = Arc::new(ungated(10));
        let s = Arc::new(Session::new({
            let r = r.clone();
            move |n| {
                if n < 3 {
                    r.request(false, false);
                }
                Ok(())
            }
        }));
        let (task, stop) = watched(&r, &s);
        r.request(false, false);
        settle(S(1)).await;
        assert_eq!(s.calls(), 3);
        stop.notify_one();
        bounded(task).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_from_before_the_watch_is_served() {
        let r = ungated(10);
        let s = Session::ok();
        r.request(false, false);
        // Served: the request was there before the watch looked.
        bounded(r.watch(&s, tokio::time::sleep(S(1)))).await;
        assert_eq!(s.calls(), 1);
    }

    // Go's Watch may pick the queue over a context that is already done,
    // but its reconnect callback is then handed the cancelled context and
    // fails at once. `Rejoin::rejoin` is handed nothing, so the stop is
    // looked at first: a session that was closed with a request waiting
    // makes no join.
    #[tokio::test(start_paused = true)]
    async fn a_request_waiting_when_the_stop_came_is_not_served() {
        let r = ungated(10);
        let s = Session::new(|_| Err("down".to_string()));
        let stop = Arc::new(Notify::new());
        stop.notify_one();
        r.request(false, false);
        bounded(r.watch(&s, stop.notified())).await;
        assert_eq!(s.calls(), 0, "a rejoin for a session that had stopped");
        assert!(lock(&s.failures).is_empty());
        assert_eq!(count(&r), 0, "an attempt was counted after the stop");
    }

    // The same after a rejoin that worked: the request raised during it is
    // kept (#31), and the stop that came during it is seen before that
    // request is served.
    #[tokio::test(start_paused = true)]
    async fn a_stop_during_a_rejoin_leaves_the_request_raised_in_it_unserved() {
        let r = Arc::new(ungated(10));
        let stop = Arc::new(Notify::new());
        let s = Arc::new(Session::new({
            let (r, stop) = (r.clone(), stop.clone());
            move |_| {
                r.request(false, false);
                stop.notify_one();
                Ok(())
            }
        }));
        r.request(false, false);
        bounded(r.watch(&*s, stop.notified())).await;
        assert_eq!(s.calls(), 1, "a rejoin after the stop");
        assert!(s.ended().is_empty());
        assert!(
            r.drain(),
            "the request raised during the rejoin was dropped"
        );
    }

    fn cases() -> serde_json::Value {
        olc_interop::load("reconnect/backoff.json")
    }

    fn ms(v: &serde_json::Value) -> Duration {
        Duration::from_millis(v.as_u64().unwrap_or_else(|| panic!("not a number: {v}")))
    }

    fn list(v: &serde_json::Value) -> &[serde_json::Value] {
        v.as_array().map_or(&[], Vec::as_slice)
    }

    #[test]
    fn the_constants_and_the_backoff_are_gos() {
        let cases = cases();
        let c = &cases["constants"];
        assert_eq!(WINDOW, ms(&c["window_ms"]));
        assert_eq!(BACKOFF_STEP, ms(&c["backoff_step_ms"]));
        assert_eq!(BACKOFF_MAX, ms(&c["backoff_max_ms"]));
        assert_eq!(NO_ROUTE_PROBE_INITIAL, ms(&c["no_route_probe_initial_ms"]));
        assert_eq!(NO_ROUTE_PROBE_MAX, ms(&c["no_route_probe_max_ms"]));
        assert_eq!(NO_ROUTE_MAX_WAIT, ms(&c["no_route_max_wait_ms"]));

        let table = list(&cases["backoff"]);
        assert!(table.len() >= 40, "{} rows", table.len());
        for row in table {
            let count = u32::try_from(row["count"].as_u64().unwrap()).unwrap();
            assert_eq!(backoff(count), ms(&row["ms"]), "count {count}");
        }
        assert_eq!(backoff(u32::MAX), BACKOFF_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn the_request_count_is_gos() {
        let cases = cases();
        let runs = list(&cases["counter"]);
        assert!(runs.len() >= 8, "{} runs", runs.len());
        for run in runs {
            let r = ungated(10);
            let mut got = Vec::new();
            for gap in list(&run["gaps_ms"]) {
                tokio::time::advance(ms(gap)).await;
                got.push(u64::from(r.next_request_count()));
            }
            let want: Vec<u64> = list(&run["counts"])
                .iter()
                .map(|c| c.as_u64().unwrap())
                .collect();
            assert_eq!(got, want, "{}", run["name"]);
        }
    }

    /// The count-failures mode's counter, run as Go's runs it (PJ1).
    #[tokio::test(start_paused = true)]
    async fn the_failure_count_is_gos() {
        let cases = cases();
        let runs = list(&cases["failures"]);
        assert!(runs.len() >= 9, "{} runs", runs.len());
        for run in runs {
            let r = ungated(10).with_count_failures(true);
            let ops = list(&run["ops"]);
            let gaps = list(&run["gaps_ms"]);
            let mut got = Vec::new();
            for (op, gap) in ops.iter().zip(gaps) {
                tokio::time::advance(ms(gap)).await;
                got.push(match op.as_str().unwrap() {
                    "count" => u64::from(r.failure_count()),
                    "fail" => {
                        r.record_failure();
                        u64::from(count(&r))
                    }
                    "reset" => {
                        r.reset_failures();
                        u64::from(count(&r))
                    }
                    other => panic!("{other}"),
                });
            }
            let want: Vec<u64> = list(&run["counts"])
                .iter()
                .map(|c| c.as_u64().unwrap())
                .collect();
            assert_eq!(got, want, "{}", run["name"]);
        }
    }

    #[test]
    fn a_wait_is_printed_as_go_prints_it() {
        let cases = cases();
        let rows = list(&cases["durations"]);
        assert!(rows.len() >= 30, "{} rows", rows.len());
        for row in rows {
            let d = ms(&row["ms"]);
            assert_eq!(go_seconds(d), row["rounded"].as_str().unwrap(), "{d:?}");
            if d.subsec_nanos() == 0 {
                assert_eq!(go_seconds(d), row["plain"].as_str().unwrap(), "{d:?}");
            }
        }
    }

    #[test]
    fn the_supervisor_holds_no_buffer() {
        // One flag, two counters, the policy and the probe: nothing that
        // grows with traffic.
        assert!(
            size_of::<Reconnector>() <= 192,
            "{}",
            size_of::<Reconnector>()
        );
    }
}

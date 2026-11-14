// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A port of `internal/relaywin` at olcrtc engine commit 2d4266af.
//!
//! # Model
//!
//! A relay (an SFU) reads a sender's channel as fast as frames arrive and
//! queues them toward each receiver without pushing back. So the sender counts
//! the bytes it hands the relay for each destination and follows them, every
//! `mark_every` bytes, with a mark that carries the count. The destination
//! echoes a mark when its receive path reaches it; the relay delivers in order,
//! so an echo means every byte before the mark has left the relay. In flight is
//! `sent - echoed`, and a sender holds while that is a whole window.
//!
//! This module counts and decides; the carrier owns the wire (how a mark and an
//! echo are framed, whose echo counts for which destination).
//!
//! * A window holds a sender only once it is on: an echo came
//!   ([`Windows::apply_echo`]) or the destination said otherwise that it speaks
//!   the window ([`Windows::arm`]). Until then it is marked at least once a
//!   `probe_after`.
//! * An echo moves a window only past its last echo and within what was sent.
//!   Counts never start over: a window opened after a reset starts at the count
//!   of every byte counted here.
//! * A sender held for `probe_after` since the last mark marks again
//!   ([`Windows::room`] says so); held for `dead_after` without an echo, the
//!   window goes off.
//! * Every window has an epoch, replaced by [`Windows::reset`],
//!   [`Windows::reset_all`] and [`Windows::bump`]. Epochs are never reused (a
//!   `u64` counter; wrapping at 2^64 is not a case that happens).
//! * A datagram asks [`Windows::over`] instead of `room`; `over` only looks.
//! * With `Timing::horizon` set, each window is sized for its leg: once a
//!   second while a sender is held it measures the rate the destination took
//!   bytes at, keeps the best of the last [`RATE_SAMPLES`], and sizes itself to
//!   `best rate * horizon`, between `min_window` and `window`.
//!
//! # Mapping from Go
//!
//! * **Time is injected.** Every Go method that is handed or reads a
//!   `time.Time` takes a `std::time::Instant`. Go's zero `time.Time` ("never")
//!   is `Option<Instant>` `None`. `ApplyEcho` (no clock) is
//!   [`Windows::apply_echo`], which is [`Windows::apply_echo_at`] with `None`.
//! * **Locking.** Go's `Windows` has its own mutex. Here [`Windows`] is a plain
//!   struct with `&mut self` methods; the caller wraps it in a
//!   `std::sync::Mutex` (never held across an `.await`).
//! * **Wake channel.** Go's `Wake(key) <-chan struct{}` is closed when a
//!   sender may go on, and a closed channel stays closed. Here
//!   [`Windows::wake`] returns a cloneable [`Wake`] handle that owns a
//!   `tokio::sync::Notify` and a closed flag: [`Wake::closed`] is the
//!   `<-ch`, [`Wake::is_closed`] the non-blocking `select/default`. A sender
//!   clones it **before** asking `room` and waits on it (with its own `retry`
//!   timer, `Timing::retry`) after, exactly as in Go; the flag makes a wake
//!   between the question and the wait impossible to miss. Handles are
//!   `Arc`-backed and independent of the `Mutex`, so waiting does not hold it.
//!   One close releases every sender parked on that window and none parked on
//!   another.
//! * **Logging.** Go logs when a window is let go in `Room`. This module has no
//!   logger: [`RoomAnswer::let_go`] carries the held time and bytes in flight
//!   for the caller to log (never the key).
//! * **Bounds.** The window map is keyed by the carrier's destination key and is
//!   *not* bounded here, as in Go: a window stays open until `reset` or
//!   `reset_all`, and [`Windows::len`] is how a carrier sees a leak. Per
//!   destination the state is one fixed-size struct (plus one `Notify`, and a
//!   measurement block for a sized window); see the size assertions in the
//!   tests.
//! * `sent` takes `usize` (Go's `int`, negative clamped to 0, which cannot be
//!   expressed here). Counter arithmetic wraps exactly where Go's `uint64`
//!   arithmetic does; nothing on peer-controlled input can panic.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// `DefaultWindow` in Go: 192 KiB a destination (`192 << 10`).
///
/// A control ping waits behind up to a window one way and its pong behind up to
/// a window the other, so on the slowest SFU-to-receiver leg the gate has
/// measured, 34 kB/s, two windows and a round trip have to fit in the tunnel's
/// 15 s liveness timeout with a margin: 2 x 192 KiB / 34 kB/s = 11.6 s (256 KiB
/// would be 15.4 s). At a 0.35 s round trip it still carries about 3.9 Mbit/s
/// (7/8 of a window a round trip), over the gate's 1.4 and 1.6 Mbit/s floors.
pub const DEFAULT_WINDOW: u64 = 192 << 10;

/// `DefaultProbeAfter` in Go: a sender held this long since its last mark marks
/// again, and a destination that has not echoed yet is marked at least this
/// often. 1 s.
pub const DEFAULT_PROBE_AFTER: Duration = Duration::from_secs(1);

/// `DefaultDeadAfter` in Go: a destination that has held a sender this long
/// without an echo is let go. 120 s. A relay that never drops reliable data
/// makes a silent destination a slow leg or a hole being repaired far more
/// often than a dead one, and liveness closes a dead one long before this: a
/// backstop, not a verdict.
pub const DEFAULT_DEAD_AFTER: Duration = Duration::from_secs(120);

/// `DefaultRetry` in Go: how often a held sender looks again, for the probe and
/// the dead check. `DEFAULT_PROBE_AFTER / 4` = 250 ms (written in
/// milliseconds because `Duration` division is not `const`; a test pins the
/// formula).
pub const DEFAULT_RETRY: Duration = Duration::from_millis(250);

/// `markDivisor` in Go: a `mark_every` left zero is `window / MARK_DIVISOR`,
/// which keeps a sender's view within an eighth of the truth for one small
/// frame a mark.
pub const MARK_DIVISOR: u64 = 8;

/// `DefaultMinWindow` in Go: the least a window sized for its leg shrinks to
/// when the timing names no `min_window`: 16 KiB (`16 << 10`). At the 26 kB/s
/// the gate measured through Sber's relay it is 16384 / 26000 = 0.63 s of
/// queue, well under a second, and it still keeps a slower leg moving.
pub const DEFAULT_MIN_WINDOW: u64 = 16 << 10;

/// `minMarkEvery` in Go: a window sized down still marks at least this far
/// apart (2 KiB, `2 << 10`), so a small window does not spend its leg on
/// marks.
pub const MIN_MARK_EVERY: u64 = 2 << 10;

/// `rateInterval` in Go: how long a sized window measures the rate its
/// destination takes bytes at before it sizes itself again (1 s).
pub const RATE_INTERVAL: Duration = Duration::from_secs(1);

/// `rateSamples` in Go: how many rates a sized window keeps the best of (10).
/// With [`RATE_INTERVAL`] that is 10 s: a lull of a few seconds does not shrink
/// a window, a leg slower for ten does.
pub const RATE_SAMPLES: usize = 10;

/// `firstSizedWindow` in Go: where a sized window starts, before it has
/// measured its leg (64 KiB, `64 << 10`). What a new window hands the relay at
/// once is queued there however slow the leg: 65536 / 26000 = 2.5 s on a
/// 26 kB/s leg (7.6 s at the 192 KiB cap), and a pong behind it. A leg that
/// carries it in less than the horizon grows it within a `RATE_INTERVAL` or
/// two.
pub const FIRST_SIZED_WINDOW: u64 = 64 << 10;

/// `Timing` in Go: sizes a [`Windows`]. A field left zero takes its default:
/// the `DEFAULT_*` constants, and for `mark_every` an eighth of `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timing {
    /// `Window`: how many bytes may be in flight to one destination.
    pub window: u64,
    /// `MarkEvery`: how many bytes to a destination go between two marks.
    pub mark_every: u64,
    /// `ProbeAfter`: see [`DEFAULT_PROBE_AFTER`].
    pub probe_after: Duration,
    /// `DeadAfter`: see [`DEFAULT_DEAD_AFTER`].
    pub dead_after: Duration,
    /// `Retry`: see [`DEFAULT_RETRY`].
    pub retry: Duration,
    /// `Horizon`: when set, sizes each destination's window for its leg: how
    /// much of the leg's time a window lets be in flight, at the best rate the
    /// leg has shown lately. Zero keeps every window at `window`.
    pub horizon: Duration,
    /// `MinWindow`: the least a sized window shrinks to: [`DEFAULT_MIN_WINDOW`]
    /// when `horizon` is set and this is zero, and never more than `window`.
    pub min_window: u64,
}

impl Timing {
    /// `withDefaults` in Go: every zero field filled in.
    fn with_defaults(mut self) -> Self {
        if self.window == 0 {
            self.window = DEFAULT_WINDOW;
        }
        if self.mark_every == 0 {
            self.mark_every = (self.window / MARK_DIVISOR).max(1);
        }
        if self.probe_after.is_zero() {
            self.probe_after = DEFAULT_PROBE_AFTER;
        }
        if self.dead_after.is_zero() {
            self.dead_after = DEFAULT_DEAD_AFTER;
        }
        if self.retry.is_zero() {
            self.retry = DEFAULT_RETRY;
        }
        if !self.horizon.is_zero() {
            if self.min_window == 0 {
                self.min_window = DEFAULT_MIN_WINDOW;
            }
            self.min_window = self.min_window.min(self.window);
        }
        self
    }
}

/// What [`Windows::room`] answers: Go's `(ok, probe, counter)` plus the
/// let-go fact Go logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomAnswer {
    /// `ok`: the send may go now.
    pub ok: bool,
    /// `probe`: the caller sends a mark carrying `counter`, whether or not `ok`.
    pub probe: bool,
    /// `counter`: the count the probe's mark carries; zero when `probe` is false.
    pub counter: u64,
    /// Set when this call turned a silent window off (`ok` is then true). Go
    /// logs "no echo for %s with %d bytes in flight - window off" here.
    pub let_go: Option<LetGo>,
}

/// A window turned off by `dead_after`, for the caller's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LetGo {
    /// How long the window held a sender without an echo.
    pub held: Duration,
    /// Bytes in flight when it was let go.
    pub in_flight: u64,
}

impl RoomAnswer {
    /// Room, no probe, nothing let go.
    const GO: Self = Self {
        ok: true,
        probe: false,
        counter: 0,
        let_go: None,
    };
    /// Held, no probe.
    const HELD: Self = Self {
        ok: false,
        probe: false,
        counter: 0,
        let_go: None,
    };
}

#[derive(Debug)]
struct WakeInner {
    closed: AtomicBool,
    notify: Notify,
}

/// The `<-chan struct{}` of Go's `Wake`: closed (once, for good) the next time
/// a sender held on a window may go on. Cloning shares the same channel. A
/// window replaces its channel after a close that keeps the window, so take a
/// fresh one from [`Windows::wake`] before every `room` question.
#[derive(Debug, Clone)]
pub struct Wake(Arc<WakeInner>);

impl Wake {
    fn new() -> Self {
        Self(Arc::new(WakeInner {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        }))
    }

    fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }

    /// Whether the channel is closed (Go: `select { case <-ch: ... default: }`).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    /// Completes once the channel is closed (Go: `<-ch`). Cancel-safe.
    pub async fn closed(&self) {
        loop {
            // Created before the flag is read: a close between the two is seen
            // by the flag, one after the read completes the future.
            let notified = self.0.notify.notified();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }

    /// The `Notify` behind the handle, for a caller that wants to select on it
    /// directly. It is only notified by a close; check [`Wake::is_closed`]
    /// after it fires.
    #[must_use]
    pub fn notify(&self) -> &Notify {
        &self.0.notify
    }

    /// Whether both handles are the same channel.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// `state` in Go: the window toward one destination (the hot per-destination
/// struct). `Option<Instant>` is `None` where Go holds the zero time.
#[derive(Debug, Clone)]
struct State {
    /// Bytes handed to the relay for the destination.
    sent: u64,
    /// `sent`, as of the last mark.
    marked: u64,
    /// The highest count the destination has echoed.
    echoed: u64,
    /// The window holds: an echo came, or `arm`.
    active: bool,
    /// When the last mark went out.
    marked_at: Option<Instant>,
    /// When the window filled, cleared by every echo.
    held_since: Option<Instant>,
    /// When a sender was first held since `room` last let one go. Unlike
    /// `held_since` an echo leaves it. `room` letting a sender go clears it,
    /// and so does `bump`.
    waiting_since: Option<Instant>,
    /// Replaced by reset, reset_all and bump; never zero.
    epoch: u64,
    /// Closed when a sender held on the window may go on: replaced by an echo
    /// that moves it and by `bump`, left closed by `reset` and `reset_all`.
    wake: Wake,
    /// The window now: `window`, or what its leg sized it to.
    size: u64,
    /// Bytes between two marks at that size.
    mark_every: u64,
    /// What a sized window measures of its leg; `None` when not sized. Boxed
    /// so an unsized window does not carry it.
    leg: Option<Box<LegMeasure>>,
}

/// `legMeasure` in Go: what a sized window measures of its leg.
#[derive(Debug, Clone, Default)]
struct LegMeasure {
    /// Start of the interval the rate is measured over.
    rate_since: Option<Instant>,
    /// The count echoed then.
    rate_from: u64,
    /// A sender was held on the window during the interval.
    held: bool,
    /// The last [`RATE_SAMPLES`] rates measured with a sender held, bytes a
    /// second.
    rates: [f64; RATE_SAMPLES],
    /// The slot the next rate takes.
    next: usize,
}

/// `Windows` in Go: the window toward every destination of one sender, keyed by
/// whatever the carrier addresses a destination by. Not internally
/// synchronised: wrap in a `std::sync::Mutex`.
#[derive(Debug)]
pub struct Windows {
    timing: Timing,
    windows: HashMap<String, State>,
    /// Every byte counted against a window since `new`, where a new window's
    /// count starts.
    count: u64,
    /// The last epoch handed out.
    epochs: u64,
}

/// Elapsed since an optional instant is at least `d`; a `None` ("zero time") is
/// always long enough, as `now.Sub(time.Time{})` is in Go.
fn elapsed_ge(now: Instant, since: Option<Instant>, d: Duration) -> bool {
    since.is_none_or(|t| now.saturating_duration_since(t) >= d)
}

/// `resize` in Go: a window gets a new size and marks in proportion: at
/// `window` it marks every `mark_every`, as an unsized window does, and a
/// smaller one no closer than [`MIN_MARK_EVERY`]. Multiplication wraps as
/// Go's `uint64` does.
fn resize(t: &Timing, st: &mut State, size: u64) {
    st.size = size;
    st.mark_every =
        (size.wrapping_mul(t.mark_every) / t.window).max(MIN_MARK_EVERY.min(t.mark_every));
}

/// `measure` in Go: takes an echo of `counter`, come back at `now`, into a
/// sized window's rate and, once a [`RATE_INTERVAL`] has passed, sizes the
/// window again from the best rate its leg has shown in the last
/// [`RATE_SAMPLES`] intervals. An interval in which no sender was held says
/// nothing about the leg and is not kept.
fn measure(t: &Timing, st: &mut State, counter: u64, now: Instant) {
    let Some(leg) = st.leg.as_deref_mut() else {
        return;
    };
    let Some(since) = leg.rate_since else {
        leg.rate_since = Some(now);
        leg.rate_from = counter;
        leg.held = false;
        return;
    };
    let elapsed = now.saturating_duration_since(since);
    if elapsed < RATE_INTERVAL {
        return;
    }
    let mut new_size = None;
    if leg.held {
        leg.rates[leg.next] = counter.saturating_sub(leg.rate_from) as f64 / elapsed.as_secs_f64();
        leg.next = (leg.next + 1) % RATE_SAMPLES;
        let best = leg.rates.iter().copied().fold(0.0_f64, f64::max);
        // `as u64` saturates and maps NaN to 0.
        let want = (best * t.horizon.as_secs_f64()) as u64;
        new_size = Some(want.max(t.min_window).min(t.window));
    }
    leg.rate_since = Some(now);
    leg.rate_from = counter;
    leg.held = false;
    if let Some(size) = new_size {
        resize(t, st, size);
    }
}

impl State {
    /// `wakeSenders` in Go: releases every sender parked on the window and arms
    /// the next wait.
    fn wake_senders(&mut self) {
        self.wake.close();
        self.wake = Wake::new();
    }
}

impl Windows {
    /// `New` in Go: no window open, sized by `t`.
    #[must_use]
    pub fn new(t: Timing) -> Self {
        Self {
            timing: t.with_defaults(),
            windows: HashMap::new(),
            count: 0,
            epochs: 0,
        }
    }

    /// `Timing` in Go: the timing in force, its zero fields filled in; a held
    /// sender waits `retry` between looks.
    #[must_use]
    pub fn timing(&self) -> Timing {
        self.timing
    }

    /// `Room` in Go: whether a send to `key` may go now. `ok` is false only
    /// while the window is on and a whole size is in flight.
    ///
    /// A window that holds the sender and has not marked for `probe_after` asks
    /// for a probe: `probe` is true and `counter` is the count the mark
    /// carries, which the caller sends whether or not `ok`. A window that has
    /// held the sender for `dead_after` without an echo is turned off, and the
    /// send goes (`let_go` says so).
    pub fn room(&mut self, key: &str, now: Instant) -> RoomAnswer {
        let t = self.timing;
        let Some(st) = self.windows.get_mut(key) else {
            return RoomAnswer::GO;
        };
        if !st.active || st.sent.wrapping_sub(st.echoed) < st.size {
            st.held_since = None;
            st.waiting_since = None;
            return RoomAnswer::GO;
        }
        if let Some(leg) = st.leg.as_deref_mut() {
            leg.held = true;
        }
        let held_since = *st.held_since.get_or_insert(now);
        st.waiting_since.get_or_insert(now);
        let held = now.saturating_duration_since(held_since);
        if held >= t.dead_after {
            let in_flight = st.sent.wrapping_sub(st.echoed);
            st.active = false;
            st.held_since = None;
            st.waiting_since = None;
            return RoomAnswer {
                let_go: Some(LetGo { held, in_flight }),
                ..RoomAnswer::GO
            };
        }
        if elapsed_ge(now, st.marked_at, t.probe_after) {
            st.marked = st.sent;
            st.marked_at = Some(now);
            return RoomAnswer {
                ok: false,
                probe: true,
                counter: st.sent,
                let_go: None,
            };
        }
        RoomAnswer::HELD
    }

    /// `Sent` in Go: counts `n` bytes handed to the relay for `key`, opening its
    /// window if there is none, and reports whether a mark is due and the count
    /// it carries: every `mark_every` bytes, and while the destination has not
    /// echoed, once a `probe_after` as well, starting with the first bytes. The
    /// caller sends the mark after the bytes it counts, on the same ordered
    /// lane. `counter` is zero when no mark is due.
    pub fn sent(&mut self, key: &str, n: usize, now: Instant) -> (bool, u64) {
        let probe_after = self.timing.probe_after;
        let add = u64::try_from(n).unwrap_or(u64::MAX);
        // Opened first: a new window starts at the count before these bytes.
        let st = self.open(key);
        st.sent = st.sent.wrapping_add(add);
        let due = st.sent.wrapping_sub(st.marked) >= st.mark_every
            || (!st.active && elapsed_ge(now, st.marked_at, probe_after));
        let answer = if due {
            st.marked = st.sent;
            st.marked_at = Some(now);
            (true, st.sent)
        } else {
            (false, 0)
        };
        self.count = self.count.wrapping_add(add);
        answer
    }

    /// `ApplyEcho` in Go: takes the destination's echo of `counter` without a
    /// clock: moves the window as [`Windows::apply_echo_at`] does and gives a
    /// sized window no measurement. Returns `(moved, turned_on)`.
    pub fn apply_echo(&mut self, key: &str, counter: u64) -> (bool, bool) {
        self.apply_echo_at(key, counter, None)
    }

    /// `ApplyEchoAt` in Go: takes the destination's echo of `counter`, come
    /// back at `now` (`None` is Go's zero time: no measurement). It moves
    /// `key`'s window only past the last echo and within what was sent, and
    /// returns `(moved, turned_on)`. A window that moved wakes every sender
    /// parked on it. A sized window also counts the echo into its rate and,
    /// once a [`RATE_INTERVAL`] has passed, sizes itself again. The caller has
    /// checked that the echo came from the destination `key` names: anyone who
    /// can see a count can send it back.
    pub fn apply_echo_at(&mut self, key: &str, counter: u64, now: Option<Instant>) -> (bool, bool) {
        let t = self.timing;
        let Some(st) = self.windows.get_mut(key) else {
            return (false, false);
        };
        if counter <= st.echoed || counter > st.sent {
            return (false, false);
        }
        let turned_on = !st.active;
        st.active = true;
        st.echoed = counter;
        st.held_since = None;
        if let Some(now) = now {
            if st.leg.is_some() {
                measure(&t, st, counter, now);
            }
        }
        st.wake_senders();
        (true, turned_on)
    }

    /// `Size` in Go: the window toward `key` now: `window`, or for a sized
    /// window its first size until its leg has sized it; `window` for a key
    /// with no window open. It only looks.
    #[must_use]
    pub fn size(&self, key: &str) -> u64 {
        self.windows
            .get(key)
            .map_or(self.timing.window, |st| st.size)
    }

    /// `Arm` in Go: turns `key`'s window on without an echo, opening it if there
    /// is none: the destination has said some other way that it speaks the
    /// window, so a sender may be held before its first echo comes. What is in
    /// flight stays.
    pub fn arm(&mut self, key: &str) {
        let st = self.open(key);
        if !st.active {
            st.active = true;
            st.held_since = None;
        }
    }

    /// `Reset` in Go: forgets `key`'s window: the destination starts over, and
    /// what was counted toward it means nothing to what comes after. A window
    /// opened for `key` later starts off, at the count of every byte counted so
    /// far, under a new epoch. A sender parked on the window is woken.
    pub fn reset(&mut self, key: &str) {
        if let Some(st) = self.windows.remove(key) {
            st.wake.close();
        }
    }

    /// `ResetAll` in Go: forgets every window, as [`Windows::reset`] does one,
    /// and wakes every parked sender. The count of bytes and the epochs go on.
    pub fn reset_all(&mut self) {
        for st in self.windows.values() {
            st.wake.close();
        }
        self.windows.clear();
    }

    /// `Bump` in Go: gives `key`'s window a new epoch and keeps its counts: the
    /// session a parked sender's frame belongs to is over, but the bytes it
    /// handed the relay before are still queued there and their echoes still
    /// count. A sender parked on the window is woken, to find its epoch gone, so
    /// nobody is waiting on the window any more.
    pub fn bump(&mut self, key: &str) {
        let epoch = self.windows.contains_key(key).then(|| self.next_epoch());
        if let (Some(epoch), Some(st)) = (epoch, self.windows.get_mut(key)) {
            st.epoch = epoch;
            st.waiting_since = None;
            st.wake_senders();
        }
    }

    /// `Epoch` in Go: the epoch of `key`'s window, opening the window if there
    /// is none. It is never zero, and never one another window has had: a
    /// sender takes it before it waits and compares it with the one it wakes
    /// to.
    pub fn epoch(&mut self, key: &str) -> u64 {
        self.open(key).epoch
    }

    /// `Over` in Go: whether `key`'s window is on with more than a size and
    /// `slack` in flight, or has held a sender for `probe_after` by now. For a
    /// frame the carrier drops rather than holds, a datagram. A window that is
    /// off is never over, and neither is a destination with no window.
    ///
    /// `over` only looks: it opens no window, starts no hold, takes no probe,
    /// lets nothing go and wakes nobody.
    #[must_use]
    pub fn over(&self, key: &str, slack: u64, now: Instant) -> bool {
        let Some(st) = self.windows.get(key) else {
            return false;
        };
        if !st.active {
            return false;
        }
        if let Some(w) = st.waiting_since {
            if now.saturating_duration_since(w) >= self.timing.probe_after {
                return true;
            }
        }
        // Compared past the window, so no slack can wrap the sum.
        let in_flight = st.sent.wrapping_sub(st.echoed);
        in_flight > st.size && in_flight - st.size > slack
    }

    /// `Wake` in Go: the channel closed the next time a sender held on `key`'s
    /// window may go on: an echo moved the window, a reset or a bump changed it,
    /// or `reset_all` changed every window. A sender takes it before it asks
    /// [`Windows::room`], so a wake between the two is not missed. It opens the
    /// window if there is none, as [`Windows::epoch`] does.
    pub fn wake(&mut self, key: &str) -> Wake {
        self.open(key).wake.clone()
    }

    /// `Len` in Go: how many destinations have a window open. It only looks.
    /// Not bounded (see the module doc): a window stays open until reset.
    #[must_use]
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Whether no window is open (clippy's companion of [`Windows::len`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// `open` in Go: returns `key`'s window, opening one at the session's count
    /// if there is none: no mark sent before it is past that count, so no echo
    /// of one can move the new window.
    fn open(&mut self, key: &str) -> &mut State {
        if !self.windows.contains_key(key) {
            let t = self.timing;
            let count = self.count;
            let mut st = State {
                sent: count,
                marked: count,
                echoed: count,
                active: false,
                marked_at: None,
                held_since: None,
                waiting_since: None,
                epoch: self.next_epoch(),
                wake: Wake::new(),
                size: t.window,
                mark_every: t.mark_every,
                leg: None,
            };
            if !t.horizon.is_zero() {
                st.leg = Some(Box::default());
                let first = FIRST_SIZED_WINDOW.max(t.min_window).min(t.window);
                resize(&t, &mut st, first);
            }
            self.windows.insert(key.to_owned(), st);
        }
        self.windows.get_mut(key).expect("window opened just above")
    }

    /// `nextEpoch` in Go: an epoch no window has had.
    fn next_epoch(&mut self) -> u64 {
        self.epochs = self.epochs.wrapping_add(1);
        self.epochs
    }
}

#[cfg(test)]
mod tests {
    // Ports of relaywin_test.go and size_test.go (2d4266af). Time is a fake
    // clock: every call is handed its `now`. Tests that spawn goroutines in Go
    // (parkOn, heldSender, the slow receiver) are single-threaded steppers
    // here; a wake is checked with `Wake::is_closed`.
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::future::Future;
    use std::pin::pin;
    use std::sync::OnceLock;
    use std::task::{Context, Poll, Waker};

    /// One window per destination the sender has written to: its size is
    /// what a room of many participants costs.
    #[test]
    fn a_window_stays_small() {
        assert!(
            size_of::<State>() <= 128,
            "State is {} bytes",
            size_of::<State>()
        );
        assert!(
            size_of::<LegMeasure>() <= 128,
            "LegMeasure is {} bytes",
            size_of::<LegMeasure>()
        );
    }

    /// A full datachannel frame, a smux frame of 12 KiB.
    const FRAME: usize = 12 << 10;
    /// The default window, as a number the tests do sums on.
    const WINDOW: usize = DEFAULT_WINDOW as usize;
    /// The room past a window the SaluteJazz datagram rule leaves.
    const SLACK: u64 = 64 << 10;

    /// The fake clock's origin.
    fn t0() -> Instant {
        static T0: OnceLock<Instant> = OnceLock::new();
        *T0.get_or_init(Instant::now)
    }

    fn at(d: Duration) -> Instant {
        t0() + d
    }

    /// Comparable copy of a window's counts (Go's `snapshot` copies `state`).
    #[derive(Debug, Clone, PartialEq)]
    struct Snap {
        sent: u64,
        marked: u64,
        echoed: u64,
        active: bool,
        marked_at: Option<Instant>,
        held_since: Option<Instant>,
        waiting_since: Option<Instant>,
        epoch: u64,
        size: u64,
        mark_every: u64,
        wake: usize,
    }

    fn snapshot(w: &Windows, key: &str) -> Snap {
        let st = w
            .windows
            .get(key)
            .unwrap_or_else(|| panic!("no window for {key:?}"));
        Snap {
            sent: st.sent,
            marked: st.marked,
            echoed: st.echoed,
            active: st.active,
            marked_at: st.marked_at,
            held_since: st.held_since,
            waiting_since: st.waiting_since,
            epoch: st.epoch,
            size: st.size,
            mark_every: st.mark_every,
            wake: Arc::as_ptr(&st.wake.0) as usize,
        }
    }

    /// Whether a send to `key` would wait now, without Room's side effects.
    fn held(w: &Windows, key: &str) -> bool {
        w.windows
            .get(key)
            .is_some_and(|st| st.active && st.sent - st.echoed >= w.timing.window)
    }

    /// Turns `key`'s window on the way a destination that speaks the window
    /// does: the first `n` bytes are marked at once, and it echoes that mark.
    fn on(w: &mut Windows, key: &str, n: usize) {
        let (due, counter) = w.sent(key, n, t0());
        assert!(due, "the first bytes to a destination were not marked");
        let (moved, turned_on) = w.apply_echo(key, counter);
        assert!(
            moved && turned_on,
            "the echo of the first mark: moved {moved}, turned on {turned_on}"
        );
    }

    /// The counts a sender's marks carry.
    #[derive(Default)]
    struct Marks(Vec<u64>);

    impl Marks {
        fn sent(&mut self, w: &mut Windows, key: &str, n: usize, now: Instant) {
            let (due, counter) = w.sent(key, n, now);
            if due {
                self.0.push(counter);
            }
        }
        fn last(&self) -> u64 {
            *self.0.last().expect("no mark went out")
        }
    }

    fn ok(w: &mut Windows, key: &str, now: Instant) -> bool {
        w.room(key, now).ok
    }

    // TestAZeroTimingTakesTheDefaults
    #[test]
    fn a_zero_timing_takes_the_defaults() {
        let want = Timing {
            window: 192 << 10,
            mark_every: 24 << 10,
            probe_after: Duration::from_secs(1),
            dead_after: Duration::from_secs(120),
            retry: Duration::from_millis(250),
            ..Timing::default()
        };
        assert_eq!(Windows::new(Timing::default()).timing(), want);
        let want = Timing {
            window: 64 << 10,
            mark_every: 8 << 10,
            probe_after: Duration::from_secs(1),
            dead_after: Duration::from_secs(60),
            retry: Duration::from_millis(250),
            ..Timing::default()
        };
        let got = Windows::new(Timing {
            window: 64 << 10,
            dead_after: Duration::from_secs(60),
            ..Timing::default()
        })
        .timing();
        assert_eq!(got, want);
        // The formula written next to DEFAULT_RETRY.
        assert_eq!(DEFAULT_RETRY, DEFAULT_PROBE_AFTER / 4);
    }

    // TestADestinationThatNeverEchoesIsSentToAsBefore
    #[test]
    fn a_destination_that_never_echoes_is_sent_to_as_before() {
        let mut w = Windows::new(Timing::default());
        for i in 0..(4 * WINDOW / FRAME) {
            w.sent("peer", FRAME, at(Duration::from_millis(i as u64)));
        }
        for now in [t0(), at(DEFAULT_PROBE_AFTER), at(2 * DEFAULT_DEAD_AFTER)] {
            let a = w.room("peer", now);
            assert!(
                a.ok && !a.probe,
                "a destination that never echoed held the sender"
            );
        }
    }

    // TestAnEchoTurnsTheWindowOnAndItHoldsAtAWindow
    #[test]
    fn an_echo_turns_the_window_on_and_it_holds_at_a_window() {
        let mut w = Windows::new(Timing::default());
        on(&mut w, "peer", FRAME);
        let mut m = Marks::default();
        m.sent(&mut w, "peer", WINDOW - 1, t0());
        assert!(
            ok(&mut w, "peer", t0()),
            "held one byte short of a window in flight"
        );
        m.sent(&mut w, "peer", 1, t0());
        assert!(
            !ok(&mut w, "peer", t0()),
            "not held with a whole window in flight"
        );
        let (moved, turned_on) = w.apply_echo("peer", m.last());
        assert!(moved && !turned_on);
        assert!(
            ok(&mut w, "peer", t0()),
            "an echo of the last mark left no room"
        );
    }

    // TestAWindowHoldsAtItsOwnSize
    #[test]
    fn a_window_holds_at_its_own_size() {
        let mut w = Windows::new(Timing {
            window: 1000,
            ..Timing::default()
        });
        on(&mut w, "peer", 10);
        w.sent("peer", 999, t0());
        assert!(
            ok(&mut w, "peer", t0()),
            "held at 999 of a 1000-byte window"
        );
        w.sent("peer", 1, t0());
        assert!(
            !ok(&mut w, "peer", t0()),
            "not held at 1000 of a 1000-byte window"
        );
    }

    // TestAWindowOnIsMarkedEveryMarkEveryBytes
    #[test]
    fn a_window_on_is_marked_every_mark_every_bytes() {
        let mut w = Windows::new(Timing {
            window: 64 << 10,
            mark_every: 8000,
            probe_after: Duration::from_secs(3600),
            ..Timing::default()
        });
        on(&mut w, "peer", 100);
        let mut m = Marks::default();
        for i in 0..9 {
            m.sent(&mut w, "peer", 3000, at(Duration::from_secs(i)));
        }
        assert_eq!(m.0, vec![100 + 9000, 100 + 18000, 100 + 27000]);
    }

    // TestUntilItEchoesADestinationIsMarkedOnceAProbeInterval
    #[test]
    fn until_it_echoes_a_destination_is_marked_once_a_probe_interval() {
        let mut w = Windows::new(Timing {
            probe_after: Duration::from_secs(1),
            ..Timing::default()
        });
        let mut m = Marks::default();
        m.sent(&mut w, "peer", 100, t0());
        m.sent(&mut w, "peer", 100, at(Duration::from_millis(999)));
        m.sent(&mut w, "peer", 100, at(Duration::from_secs(1)));
        assert_eq!(m.0, vec![100, 300]);
        assert!(
            w.apply_echo("peer", m.last()).0,
            "the echo of a mark moved nothing"
        );
        let (due, _) = w.sent("peer", 100, at(Duration::from_secs(3600)));
        assert!(!due, "a window on was marked for time, not bytes");
    }

    // TestALostEchoIsRepairedByAProbe
    #[test]
    fn a_lost_echo_is_repaired_by_a_probe() {
        let mut w = Windows::new(Timing {
            probe_after: Duration::from_secs(1),
            dead_after: Duration::from_secs(3600),
            ..Timing::default()
        });
        on(&mut w, "peer", FRAME);
        let mut lost = Marks::default();
        for _ in 0..(WINDOW / FRAME) {
            lost.sent(&mut w, "peer", FRAME, t0());
        }
        let sent = snapshot(&w, "peer").sent;
        let a = w.room("peer", at(Duration::from_millis(999)));
        assert!(!a.ok && !a.probe, "want held without a probe");
        let a = w.room("peer", at(Duration::from_secs(1)));
        assert!(
            !a.ok && a.probe && a.counter == sent,
            "want held, a probe at {sent}"
        );
        assert!(
            !w.room("peer", at(Duration::from_millis(1500))).probe,
            "probed again within an interval"
        );
        let again = w.room("peer", at(Duration::from_secs(2)));
        assert!(
            again.probe && again.counter == sent,
            "want another probe at {sent}"
        );
        assert!(
            w.apply_echo("peer", a.counter).0,
            "the probe's echo moved nothing"
        );
        assert!(
            ok(&mut w, "peer", at(Duration::from_secs(2))),
            "still held after the probe's echo"
        );
    }

    // TestADestinationSilentForDeadAfterIsLetGo
    #[test]
    fn a_destination_silent_for_dead_after_is_let_go() {
        let minute = Duration::from_secs(60);
        let mut w = Windows::new(Timing {
            probe_after: Duration::from_secs(1),
            dead_after: minute,
            ..Timing::default()
        });
        on(&mut w, "peer", FRAME);
        w.sent("peer", WINDOW, t0());
        assert!(!ok(&mut w, "peer", t0()), "the window is not on and full");
        assert!(
            !ok(&mut w, "peer", at(minute - Duration::from_nanos(1))),
            "let go before DeadAfter"
        );
        let a = w.room("peer", at(minute));
        assert!(a.ok, "still held after DeadAfter without an echo");
        assert_eq!(
            a.let_go,
            Some(LetGo {
                held: minute,
                in_flight: WINDOW as u64
            })
        );
        assert!(
            ok(&mut w, "peer", at(Duration::from_secs(3600))),
            "a destination let go held the sender again"
        );
        let sent = snapshot(&w, "peer").sent;
        let (moved, turned_on) = w.apply_echo("peer", sent);
        assert!(moved && turned_on, "an echo after the let-go: want both");
        assert!(
            ok(&mut w, "peer", at(Duration::from_secs(3600))),
            "held with nothing in flight"
        );
    }

    // TestAnEchoStartsTheDeadClockOver
    #[test]
    fn an_echo_starts_the_dead_clock_over() {
        let mut w = Windows::new(Timing {
            probe_after: Duration::from_secs(3600),
            dead_after: Duration::from_secs(60),
            ..Timing::default()
        });
        let mut m = Marks::default();
        m.sent(&mut w, "peer", FRAME, t0());
        m.sent(&mut w, "peer", WINDOW / 8, t0()); // a mark_every left zero
        assert_eq!(m.0.len(), 2);
        w.sent("peer", 2 * WINDOW, t0());
        w.apply_echo("peer", m.0[0]);
        assert!(!ok(&mut w, "peer", t0()), "the window is not on and full");
        w.apply_echo("peer", m.0[1]);
        assert!(
            !ok(&mut w, "peer", at(Duration::from_secs(120))),
            "a destination that echoed was let go as dead"
        );
        assert!(
            ok(&mut w, "peer", at(Duration::from_secs(240))),
            "a destination silent for twice the dead period still holds"
        );
    }

    // TestAnEchoMovesAWindowOnlyForwardAndWithinWhatWasSent
    #[test]
    fn an_echo_moves_a_window_only_forward_and_within_what_was_sent() {
        let mut w = Windows::new(Timing::default());
        let mut m = Marks::default();
        m.sent(&mut w, "peer", FRAME, t0());
        m.sent(&mut w, "peer", 2 * WINDOW, t0());
        assert_eq!(m.0.len(), 2);
        let (first, second) = (m.0[0], m.0[1]);
        for (key, counter) in [("stranger", first), ("peer", second + 1), ("peer", 0)] {
            assert_eq!(
                w.apply_echo(key, counter),
                (false, false),
                "an echo of {counter} for {key:?} moved the window"
            );
        }
        assert!(
            ok(&mut w, "peer", t0()),
            "an echo past what was sent, or of nothing, turned the window on"
        );
        assert_eq!(w.apply_echo("peer", first), (true, true));
        for stale in [first, first - 1] {
            assert!(
                !w.apply_echo("peer", stale).0,
                "an echo of {stale} moved the window"
            );
        }
        let st = snapshot(&w, "peer");
        assert_eq!(st.sent - st.echoed, 2 * WINDOW as u64);
        assert_eq!(w.apply_echo("peer", second), (true, false));
    }

    // TestAnEchoFromBeforeAResetMovesNoWindow
    #[test]
    fn an_echo_from_before_a_reset_moves_no_window() {
        let mut w = Windows::new(Timing::default());
        let mut m = Marks::default();
        m.sent(&mut w, "peer", WINDOW / 2, t0());
        let stale = m.last();
        w.reset("peer");
        m.sent(&mut w, "peer", FRAME, t0());
        let fresh = m.last();
        w.sent("peer", 2 * WINDOW, t0());
        assert!(
            !w.apply_echo("peer", stale).0,
            "an echo from before the reset moved the new window"
        );
        assert!(!snapshot(&w, "peer").active);
        w.apply_echo("peer", fresh);
        let st = snapshot(&w, "peer");
        assert!(st.active && st.sent - st.echoed == 2 * WINDOW as u64);
    }

    // TestANewWindowStartsPastEveryCountBeforeIt
    #[test]
    fn a_new_window_starts_past_every_count_before_it() {
        let mut w = Windows::new(Timing::default());
        let (_, a) = w.sent("a", 1000, t0());
        let (_, b) = w.sent("b", 5000, t0());
        assert!(a == 1000 && b == 6000);
        w.reset_all();
        let (_, fresh_a) = w.sent("a", 10, t0());
        let (_, fresh_b) = w.sent("b", 10, t0());
        for (key, counter) in [("a", a), ("a", b), ("b", a), ("b", b)] {
            assert!(
                !w.apply_echo(key, counter).0,
                "an echo of {counter} from before reset_all moved {key:?}"
            );
        }
        assert!(w.apply_echo("a", fresh_a).0);
        assert!(w.apply_echo("b", fresh_b).0);
    }

    // TestAHeldDestinationDoesNotHoldAnother
    #[test]
    fn a_held_destination_does_not_hold_another() {
        let mut w = Windows::new(Timing::default());
        on(&mut w, "slow", FRAME);
        on(&mut w, "fast", FRAME);
        w.sent("slow", WINDOW, t0());
        assert!(!ok(&mut w, "slow", t0()));
        for _ in 0..(WINDOW / FRAME / 2) {
            assert!(
                ok(&mut w, "fast", t0()),
                "the stalled destination held another"
            );
            w.sent("fast", FRAME, t0());
        }
    }

    // TestResetStartsOneWindowOver
    #[test]
    fn reset_starts_one_window_over() {
        let mut w = Windows::new(Timing::default());
        for key in ["a", "b"] {
            on(&mut w, key, FRAME);
            w.sent(key, WINDOW, t0());
        }
        w.reset("a");
        assert!(
            ok(&mut w, "a", t0()),
            "a window reset forgot holds the sender"
        );
        w.sent("a", 4 * WINDOW, t0());
        assert!(
            ok(&mut w, "a", t0()),
            "a window started over is on before an echo"
        );
        assert!(held(&w, "b"), "reset of one window let another go");
    }

    // TestResetAllStartsEveryWindowOver
    #[test]
    fn reset_all_starts_every_window_over() {
        let mut w = Windows::new(Timing::default());
        for key in ["a", "b"] {
            on(&mut w, key, FRAME);
            w.sent(key, WINDOW, t0());
        }
        w.reset_all();
        for key in ["a", "b"] {
            assert!(ok(&mut w, key, t0()), "{key:?}'s window outlived reset_all");
        }
    }

    // TestLenCountsTheWindowsOpen
    #[test]
    fn len_counts_the_windows_open() {
        let mut w = Windows::new(Timing::default());
        assert_eq!(w.len(), 0);
        assert!(w.is_empty());
        w.epoch("a");
        w.wake("b");
        w.sent("c", FRAME, t0());
        w.arm("d");
        assert_eq!(w.len(), 4);
        w.room("e", t0());
        let _ = w.over("e", SLACK, t0());
        w.apply_echo("e", 1);
        w.bump("e");
        assert_eq!(w.len(), 4, "looking, echoing and bumping opened a window");
        w.reset("a");
        assert_eq!(w.len(), 3);
        w.reset_all();
        assert_eq!(w.len(), 0);
    }

    // TestArmTurnsTheWindowOnWithoutAnEcho
    #[test]
    fn arm_turns_the_window_on_without_an_echo() {
        let mut w = Windows::new(Timing::default());
        w.arm("peer");
        assert!(snapshot(&w, "peer").active);
        assert!(
            !w.sent("peer", 100, t0()).0,
            "an armed window's first bytes were marked for time"
        );
        assert!(
            !w.sent("peer", 100, at(Duration::from_secs(3600))).0,
            "an armed window was marked for time"
        );
        w.sent("peer", WINDOW - 201, t0());
        assert!(ok(&mut w, "peer", t0()), "held one byte short of a window");
        w.sent("peer", 1, t0());
        assert!(
            !ok(&mut w, "peer", t0()),
            "an armed window with a window in flight did not hold"
        );
    }

    // TestArmKeepsWhatIsInFlight
    #[test]
    fn arm_keeps_what_is_in_flight() {
        let mut w = Windows::new(Timing::default());
        let mut m = Marks::default();
        m.sent(&mut w, "peer", FRAME, t0());
        w.sent("peer", WINDOW, t0());
        assert!(ok(&mut w, "peer", t0()), "held before any echo or arm");
        w.arm("peer");
        assert!(!ok(&mut w, "peer", t0()), "arm forgot what was in flight");
        let before = snapshot(&w, "peer");
        w.arm("peer");
        assert_eq!(
            snapshot(&w, "peer"),
            before,
            "a second arm changed the window"
        );
        assert_eq!(w.apply_echo("peer", m.last()), (true, false));
    }

    // TestArmOpensAWindowAtTheSessionsCount
    #[test]
    fn arm_opens_a_window_at_the_sessions_count() {
        let mut w = Windows::new(Timing::default());
        let (_, a) = w.sent("a", 1000, t0());
        w.arm("b");
        assert!(
            !w.apply_echo("b", a).0,
            "an echo of another window's mark moved a window arm opened"
        );
        w.reset("a");
        w.arm("a");
        assert!(
            !w.apply_echo("a", a).0,
            "an echo from before the reset moved the window arm opened"
        );
        let (_, fresh) = w.sent("a", WINDOW / 2, t0());
        assert_eq!(fresh, 1000 + (WINDOW / 2) as u64);
        assert_eq!(w.apply_echo("a", fresh), (true, false));
    }

    // TestAnEpochLastsUntilAResetOrABump
    #[test]
    fn an_epoch_lasts_until_a_reset_or_a_bump() {
        let mut w = Windows::new(Timing::default());
        let e1 = w.epoch("a");
        let other = w.epoch("b");
        assert!(e1 != 0 && other != 0, "zero is no epoch");
        on(&mut w, "a", FRAME);
        w.arm("a");
        w.sent("a", WINDOW, t0());
        w.room("a", at(Duration::from_secs(3600)));
        assert_eq!(w.epoch("a"), e1, "the epoch changed with the window in use");

        w.reset("a");
        let e2 = w.epoch("a");
        w.bump("a");
        let e3 = w.epoch("a");
        assert!(e2 != e1 && e3 != e2 && e3 != e1, "want each epoch new");
        assert_eq!(
            w.epoch("b"),
            other,
            "reset and bump of one window changed another's epoch"
        );
        w.reset_all();
        let (e4, after) = (w.epoch("a"), w.epoch("b"));
        assert!(
            e4 != e1 && e4 != e2 && e4 != e3 && after != other,
            "reset_all left an epoch"
        );
    }

    // TestAnEpochNeverComesBack
    #[test]
    fn an_epoch_never_comes_back() {
        let mut w = Windows::new(Timing::default());
        let mut seen = HashSet::new();
        for i in 0..300 {
            let e = w.epoch("peer");
            assert!(seen.insert(e), "epoch {e} came back after {i} replacements");
            match i % 3 {
                0 => w.reset("peer"),
                1 => w.bump("peer"),
                _ => w.reset_all(),
            }
        }
    }

    // TestABumpKeepsTheCounts
    #[test]
    fn a_bump_keeps_the_counts() {
        let mut w = Windows::new(Timing::default());
        on(&mut w, "peer", FRAME);
        let mut m = Marks::default();
        m.sent(&mut w, "peer", WINDOW, t0());
        let before = snapshot(&w, "peer");
        w.bump("peer");
        let mut after = snapshot(&w, "peer");
        // The epoch and the wake channel are bump's to replace; the counts are not.
        assert!(after.epoch != before.epoch && after.wake != before.wake);
        after.epoch = before.epoch;
        after.wake = before.wake;
        assert_eq!(after, before, "bump changed the counts");
        assert!(
            !ok(&mut w, "peer", t0()),
            "bump let go of what is in flight"
        );
        assert_eq!(w.apply_echo("peer", m.last()), (true, false));
    }

    // TestAWindowOffIsNeverOver
    #[test]
    fn a_window_off_is_never_over() {
        let mut w = Windows::new(Timing::default());
        assert!(
            !w.over("peer", SLACK, t0()),
            "a destination with no window is over"
        );
        assert!(!w.windows.contains_key("peer"), "over opened a window");
        w.sent("peer", 16 * WINDOW, t0());
        assert!(
            !w.over("peer", SLACK, t0()),
            "a destination that never echoed is over"
        );
    }

    // TestAWindowOnIsOverPastAWindowAndItsSlack
    #[test]
    fn a_window_on_is_over_past_a_window_and_its_slack() {
        let mut w = Windows::new(Timing::default());
        on(&mut w, "peer", FRAME);
        w.sent("peer", WINDOW, t0());
        assert!(!ok(&mut w, "peer", t0()), "the window is not on and full");
        assert!(!w.over("peer", SLACK, t0()), "over at a window in flight");
        w.sent("peer", SLACK as usize, t0());
        assert!(
            !w.over("peer", SLACK, t0()),
            "over at exactly a window and the slack"
        );
        w.sent("peer", 1, t0());
        assert!(
            w.over("peer", SLACK, t0()),
            "not over a byte past a window and the slack"
        );
        let sent = snapshot(&w, "peer").sent;
        assert!(
            w.apply_echo("peer", sent).0 && !w.over("peer", SLACK, t0()),
            "still over after the echo of everything"
        );
    }

    // TestAWindowStartedOverIsNotOver
    #[test]
    fn a_window_started_over_is_not_over() {
        for (name, reset_all) in [("reset", false), ("reset_all", true)] {
            let mut w = Windows::new(Timing::default());
            w.arm("peer");
            w.sent("peer", WINDOW + SLACK as usize + 1, t0());
            assert!(
                w.over("peer", SLACK, t0()),
                "the window is not over to start with"
            );
            if reset_all {
                w.reset_all();
            } else {
                w.reset("peer");
            }
            assert!(!w.over("peer", SLACK, t0()), "over after {name}");
            w.arm("peer");
            w.sent("peer", WINDOW + SLACK as usize, t0());
            assert!(
                !w.over("peer", SLACK, t0()),
                "the window opened after {name} counts what was in flight before it"
            );
        }
    }

    // TestABumpKeepsAWindowOver
    #[test]
    fn a_bump_keeps_a_window_over() {
        let mut w = Windows::new(Timing::default());
        w.arm("peer");
        w.sent("peer", WINDOW + SLACK as usize + 1, t0());
        w.bump("peer");
        assert!(w.over("peer", SLACK, t0()), "bump forgot what is in flight");
    }

    // TestAWindowLetGoIsNeverOver
    #[test]
    fn a_window_let_go_is_never_over() {
        let minute = Duration::from_secs(60);
        let mut w = Windows::new(Timing {
            probe_after: Duration::from_secs(1),
            dead_after: minute,
            ..Timing::default()
        });
        on(&mut w, "peer", FRAME);
        w.sent("peer", WINDOW + SLACK as usize + 1, t0());
        w.room("peer", t0());
        assert!(ok(&mut w, "peer", at(minute)), "not let go after DeadAfter");
        w.sent("peer", 4 * WINDOW, t0());
        assert!(!w.over("peer", SLACK, t0()), "a destination let go is over");
    }

    // TestADatagramYieldsToASenderHeldAProbeInterval
    #[test]
    fn a_datagram_yields_to_a_sender_held_a_probe_interval() {
        let sec = Duration::from_secs(1);
        let ns = Duration::from_nanos(1);
        let mut w = Windows::new(Timing {
            probe_after: sec,
            dead_after: Duration::from_secs(60),
            ..Timing::default()
        });
        let mut m = Marks::default();
        on(&mut w, "peer", FRAME);
        for _ in 0..((WINDOW + SLACK as usize / 2) / FRAME) {
            m.sent(&mut w, "peer", FRAME, t0());
        }
        assert!(!ok(&mut w, "peer", t0()), "the window is not on and full");
        assert!(
            !w.over("peer", SLACK, at(sec - ns)),
            "yielded to a sender held for less than a probe interval"
        );
        assert!(
            w.over("peer", SLACK, at(sec)),
            "did not yield to a sender held for a probe interval"
        );

        assert!(
            w.apply_echo("peer", m.0[0]).0 && held(&w, "peer"),
            "the first echo did not move the window and leave it full"
        );
        assert!(
            w.over("peer", SLACK, at(sec)),
            "an echo that left the window full started the wait over"
        );
        assert!(
            w.apply_echo("peer", m.last()).0 && !held(&w, "peer"),
            "the echo of everything did not open the window"
        );
        assert!(
            w.over("peer", SLACK, at(sec)),
            "a datagram took the room an echo opened for the held sender"
        );
        assert!(
            ok(&mut w, "peer", at(sec)),
            "the sender was not let go on an open window"
        );
        assert!(
            !w.over("peer", SLACK, at(Duration::from_secs(3600))),
            "yielded after the sender was let go"
        );

        w.sent("peer", WINDOW, at(sec));
        assert!(!ok(&mut w, "peer", at(sec)), "the window is not full again");
        w.bump("peer");
        assert!(
            !w.over("peer", SLACK, at(Duration::from_secs(3600))),
            "yielded to senders a bump sent away"
        );
        w.room("peer", at(2 * sec));
        assert!(
            !w.over("peer", SLACK, at(3 * sec - ns)) && w.over("peer", SLACK, at(3 * sec)),
            "a sender held after a bump did not start a wait of its own"
        );
    }

    // TestOverOnlyLooks
    #[test]
    fn over_only_looks() {
        let minute = Duration::from_secs(60);
        let mut w = Windows::new(Timing {
            probe_after: Duration::from_secs(1),
            dead_after: minute,
            ..Timing::default()
        });
        on(&mut w, "peer", FRAME);
        w.sent("peer", WINDOW + SLACK as usize + 1, t0());
        let wake = w.wake("peer");
        let before = snapshot(&w, "peer");
        for _ in 0..3 {
            let _ = w.over("peer", SLACK, t0());
        }
        assert_eq!(snapshot(&w, "peer"), before, "over changed the window");
        assert!(!wake.is_closed(), "over woke the senders");
        w.room("peer", t0());
        let _ = w.over("peer", SLACK, t0());
        assert!(
            w.room("peer", at(Duration::from_secs(1))).probe,
            "over took the probe a held sender was due"
        );
        assert!(
            !ok(&mut w, "peer", at(minute - Duration::from_nanos(1))),
            "over moved the dead clock"
        );
    }

    // TestAnEchoThatMovesAWindowWakesThatWindow
    #[test]
    fn an_echo_that_moves_a_window_wakes_that_window() {
        let mut w = Windows::new(Timing::default());
        let (_, counter) = w.sent("peer", FRAME, t0());
        let (_, other_counter) = w.sent("other", FRAME, t0());
        let (wake, other) = (w.wake("peer"), w.wake("other"));
        w.apply_echo("peer", counter + 1);
        w.apply_echo("stranger", counter);
        assert!(
            !wake.is_closed() && !other.is_closed(),
            "an echo that moved nothing woke the senders"
        );
        w.apply_echo("peer", counter);
        assert!(
            wake.is_closed(),
            "an echo that moved the window woke nobody"
        );
        assert!(
            !other.is_closed(),
            "an echo that moved one window woke another's senders"
        );
        assert!(
            !w.wake("peer").is_closed(),
            "the next wake channel came closed"
        );
        w.apply_echo("other", other_counter);
        assert!(other.is_closed());
    }

    // TestResetsAndBumpsWake
    #[test]
    fn resets_and_bumps_wake() {
        for name in ["reset", "reset_all", "bump"] {
            let mut w = Windows::new(Timing::default());
            for key in ["peer", "other"] {
                on(&mut w, key, FRAME);
                w.sent(key, WINDOW, t0());
            }
            let wake = w.wake("peer");
            w.reset("other");
            w.bump("other");
            assert!(
                !wake.is_closed(),
                "a reset or bump of another window woke this one's senders"
            );
            match name {
                "reset" => w.reset("peer"),
                "reset_all" => w.reset_all(),
                _ => w.bump("peer"),
            }
            assert!(wake.is_closed(), "{name} woke nobody");
        }
    }

    // TestCountingArmingAndLookingDoNotWake
    #[test]
    fn counting_arming_and_looking_do_not_wake() {
        let mut w = Windows::new(Timing::default());
        let wake = w.wake("peer");
        w.sent("peer", WINDOW, t0());
        w.arm("peer");
        w.room("peer", at(Duration::from_secs(3600)));
        let _ = w.over("peer", SLACK, t0());
        w.epoch("other");
        w.wake("other");
        let _ = w.timing();
        assert!(
            !wake.is_closed(),
            "counting, arm or a look woke the senders"
        );
    }

    // TestOneWakeReleasesEverySenderParkedOnItsWindow (parked senders are
    // clones of the handle; each is released by the one close).
    #[test]
    fn one_wake_releases_every_sender_parked_on_its_window() {
        let mut w = Windows::new(Timing::default());
        let (_, counter) = w.sent("peer", FRAME, t0());
        let other = w.wake("other");
        let parked: Vec<Wake> = (0..3).map(|_| w.wake("peer")).collect();
        assert!(parked.iter().all(|p| p.same_as(&parked[0])));
        w.apply_echo("peer", counter);
        assert!(
            parked.iter().all(Wake::is_closed),
            "one wake did not release every sender"
        );
        assert!(
            !other.is_closed(),
            "the wake of one window released a sender parked on another"
        );
    }

    // TestResetAllReleasesEveryParkedSender
    #[test]
    fn reset_all_releases_every_parked_sender() {
        let mut w = Windows::new(Timing::default());
        let parked: Vec<Wake> = ["a", "b", "c"]
            .iter()
            .flat_map(|k| [w.wake(k), w.wake(k)])
            .collect();
        w.reset_all();
        assert!(
            parked.iter().all(Wake::is_closed),
            "reset_all did not release every parked sender"
        );
    }

    /// The async side of `Wake`: pending until closed, ready after, with a
    /// no-op waker and no runtime.
    #[test]
    fn wake_closed_future_completes_once_closed() {
        let mut w = Windows::new(Timing::default());
        let (_, counter) = w.sent("peer", FRAME, t0());
        let wake = w.wake("peer");
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = pin!(wake.closed());
        assert_eq!(fut.as_mut().poll(&mut cx), Poll::Pending);
        w.apply_echo("peer", counter);
        assert_eq!(fut.as_mut().poll(&mut cx), Poll::Ready(()));
        // A handle taken after the close is a fresh channel.
        assert!(!w.wake("peer").is_closed());
    }

    /// A carrier's send path in miniature (Go's `sender.waitRoom`, one step):
    /// takes the wake before it looks, marks when `room` asks for a probe, and
    /// either goes or parks on the wake it took. A window whose epoch changed
    /// meanwhile refuses the frame.
    #[derive(Debug, PartialEq)]
    enum Step {
        Go,
        StaleEpoch,
        Park(Wake),
    }

    impl PartialEq for Wake {
        fn eq(&self, other: &Self) -> bool {
            self.same_as(other)
        }
    }

    fn wait_room_step(
        w: &mut Windows,
        key: &str,
        now: Instant,
        epoch: u64,
        marks: &mut Vec<u64>,
    ) -> Step {
        let wake = w.wake(key);
        if w.epoch(key) != epoch {
            return Step::StaleEpoch;
        }
        let a = w.room(key, now);
        if a.probe {
            marks.push(a.counter);
        }
        if a.ok {
            Step::Go
        } else {
            Step::Park(wake)
        }
    }

    /// Go's `heldSender`: a sender parked on a full window toward "peer".
    fn held_sender() -> (Windows, u64, Wake) {
        let mut w = Windows::new(Timing {
            retry: Duration::from_secs(3600),
            ..Timing::default()
        });
        on(&mut w, "peer", FRAME);
        w.sent("peer", WINDOW, t0());
        let epoch = w.epoch("peer");
        let Step::Park(wake) = wait_room_step(&mut w, "peer", t0(), epoch, &mut Vec::new()) else {
            panic!("the sender was never held");
        };
        (w, epoch, wake)
    }

    // TestAnEchoWakesAHeldSender
    #[test]
    fn an_echo_wakes_a_held_sender() {
        let (mut w, epoch, wake) = held_sender();
        let sent = snapshot(&w, "peer").sent;
        w.apply_echo("peer", sent);
        assert!(wake.is_closed(), "the held sender slept through the echo");
        assert_eq!(
            wait_room_step(&mut w, "peer", t0(), epoch, &mut Vec::new()),
            Step::Go
        );
    }

    // TestAResetOrABumpReleasesAHeldSenderWithoutSending
    #[test]
    fn a_reset_or_a_bump_releases_a_held_sender_without_sending() {
        for name in ["reset", "reset_all", "bump"] {
            let (mut w, epoch, wake) = held_sender();
            match name {
                "reset" => w.reset("peer"),
                "reset_all" => w.reset_all(),
                _ => w.bump("peer"),
            }
            assert!(wake.is_closed(), "{name} did not release the held sender");
            let step = wait_room_step(&mut w, "peer", t0(), epoch, &mut Vec::new());
            assert_eq!(step, Step::StaleEpoch, "released by {name}");
        }
    }

    // TestASlowReceiverNeverHasMoreThanAWindowQueued: the relay in miniature,
    // single-threaded. The receiver stalls first, then reads one queue item at
    // a time; the sender runs only when its wake channel closed. Time does not
    // move, and the retry is an hour away: every step forward is a wake.
    #[test]
    fn a_slow_receiver_never_has_more_than_a_window_queued() {
        const FRAMES: usize = 6 * (512 << 10) / FRAME; // six phone windows of smux
        enum Item {
            Frame(usize),
            Mark(u64),
        }
        let mut w = Windows::new(Timing {
            retry: Duration::from_secs(3600),
            probe_after: Duration::from_secs(3600),
            dead_after: Duration::from_secs(3600),
            ..Timing::default()
        });
        w.arm("peer");
        let epoch = w.epoch("peer");
        let mut queue: VecDeque<Item> = VecDeque::new();
        let (mut queued, mut peak) = (0usize, 0usize);
        let mut next = 0usize;
        let mut got = Vec::new();
        let mut parked: Option<Wake> = None;

        // The sender: sends until held, then parks on the wake it took.
        let mut run_sender = |w: &mut Windows,
                              queue: &mut VecDeque<Item>,
                              queued: &mut usize,
                              peak: &mut usize,
                              parked: &mut Option<Wake>| {
            while next < FRAMES {
                let mut marks = Vec::new();
                let step = wait_room_step(w, "peer", t0(), epoch, &mut marks);
                queue.extend(marks.into_iter().map(Item::Mark));
                match step {
                    Step::Go => {}
                    Step::StaleEpoch => panic!("frame {next}: stale epoch"),
                    Step::Park(wake) => {
                        *parked = Some(wake);
                        return;
                    }
                }
                *queued += FRAME;
                *peak = (*peak).max(*queued);
                queue.push_back(Item::Frame(next));
                next += 1;
                let (due, counter) = w.sent("peer", FRAME, t0());
                if due {
                    queue.push_back(Item::Mark(counter));
                }
            }
            *parked = None;
        };

        run_sender(&mut w, &mut queue, &mut queued, &mut peak, &mut parked);
        assert!(
            parked.is_some(),
            "the sender was never held by a stalled receiver"
        );

        // The receiver resumes.
        while let Some(item) = queue.pop_front() {
            match item {
                // The receive path reaches a mark only once every frame before
                // it has been handed up, and echoes it.
                Item::Mark(c) => {
                    w.apply_echo("peer", c);
                }
                Item::Frame(seq) => {
                    queued -= FRAME;
                    got.push(seq);
                }
            }
            if parked.as_ref().is_some_and(Wake::is_closed) {
                run_sender(&mut w, &mut queue, &mut queued, &mut peak, &mut parked);
            }
        }
        assert_eq!(next, FRAMES, "the sender never finished: a wake was missed");
        assert_eq!(
            got,
            (0..FRAMES).collect::<Vec<_>>(),
            "the load did not arrive whole and in order"
        );
        assert!(
            peak <= WINDOW + FRAME,
            "{peak} bytes queued at the peak, over a window and a frame"
        );
    }

    // ---- size_test.go: a window sized for its leg ----

    /// The Timing SaluteJazz sizes its windows with.
    fn sized() -> Timing {
        Timing {
            horizon: Duration::from_secs(3),
            ..Timing::default()
        }
    }

    /// A relay and the destination behind it, on the fake clock (Go's `leg`):
    /// what a sender hands the relay queues, the leg drains it at `rate` bytes
    /// a second, and the destination's echo of a mark comes back `rtt` after
    /// the leg delivered the mark's last byte.
    struct Leg {
        w: Windows,
        key: &'static str,
        rate: f64,
        rtt: Duration,
        app_limit: f64,
        /// Echoes carry the clock (`apply_echo_at`) or not.
        timed: bool,
        jitter: Duration,
        seed: u64,
        now: Instant,
        last_echo: Instant,
        drained: f64,
        pending: VecDeque<u64>,
        echoes: VecDeque<(u64, Instant)>,
        app_budget: f64,
        /// The longest a byte waited in the relay.
        worst_queue: Duration,
    }

    impl Leg {
        fn new(timing: Timing, rate: f64, rtt: Duration) -> Self {
            let mut w = Windows::new(timing);
            on(&mut w, "peer", 1);
            let drained = snapshot(&w, "peer").sent as f64;
            Self {
                w,
                key: "peer",
                rate,
                rtt,
                app_limit: 0.0,
                timed: true,
                jitter: Duration::ZERO,
                seed: 0,
                now: t0(),
                last_echo: t0(),
                drained,
                pending: VecDeque::new(),
                echoes: VecDeque::new(),
                app_budget: 0.0,
                worst_queue: Duration::ZERO,
            }
        }

        /// Steps the clock by `tick` for `d`, sending, draining and echoing.
        fn run(&mut self, d: Duration, tick: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.send(tick);
                self.drain(tick);
                self.echo();
                self.now += tick;
            }
        }

        fn send(&mut self, tick: Duration) {
            if self.app_limit > 0.0 {
                self.app_budget += self.app_limit * tick.as_secs_f64();
            }
            loop {
                if self.app_limit > 0.0 && self.app_budget < FRAME as f64 {
                    return;
                }
                let a = self.w.room(self.key, self.now);
                if a.probe {
                    self.pending.push_back(a.counter);
                }
                if !a.ok {
                    return;
                }
                let (due, counter) = self.w.sent(self.key, FRAME, self.now);
                if due {
                    self.pending.push_back(counter);
                }
                if self.app_limit > 0.0 {
                    self.app_budget -= FRAME as f64;
                }
            }
        }

        fn drain(&mut self, tick: Duration) {
            let sent = snapshot(&self.w, self.key).sent as f64;
            let queued = sent - self.drained;
            if queued > 0.0 {
                let wait = Duration::from_secs_f64(queued / self.rate);
                self.worst_queue = self.worst_queue.max(wait);
            }
            self.drained = sent.min(self.drained + self.rate * tick.as_secs_f64());
            while self
                .pending
                .front()
                .is_some_and(|&c| c as f64 <= self.drained)
            {
                let mut at = self.now + self.rtt + self.next_jitter();
                if at < self.last_echo {
                    at = self.last_echo; // echoes come back in the order their marks went
                }
                self.last_echo = at;
                let counter = self.pending.pop_front().unwrap_or_default();
                self.echoes.push_back((counter, at));
            }
        }

        /// The next echo's extra delay, from a fixed sequence so a run is the
        /// same every time.
        fn next_jitter(&mut self) -> Duration {
            if self.jitter.is_zero() {
                return Duration::ZERO;
            }
            self.seed = self
                .seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let nanos = u64::try_from(self.jitter.as_nanos()).unwrap_or(u64::MAX);
            Duration::from_nanos((self.seed >> 33) % nanos)
        }

        fn echo(&mut self) {
            while let Some(&(counter, at)) = self.echoes.front() {
                if at > self.now {
                    break;
                }
                if self.timed {
                    self.w.apply_echo_at(self.key, counter, Some(self.now));
                } else {
                    self.w.apply_echo(self.key, counter);
                }
                self.echoes.pop_front();
            }
        }

        /// Runs the leg long enough for a window to find its size, then starts
        /// the queue record over.
        fn settle(&mut self) {
            self.run(Duration::from_secs(30), Duration::from_millis(10));
            self.worst_queue = Duration::ZERO;
        }
    }

    /// The leg the gate measured through Sber's relay: 26 kB/s from the SFU to
    /// the receiver, 0.3 s of round trip under the queue.
    const SLOW_LEG: f64 = 26_000.0;
    const SLOW_RTT: Duration = Duration::from_millis(300);
    const TEN_MS: Duration = Duration::from_millis(10);

    // TestASizedWindowShrinksToWhatASlowLegCarries
    #[test]
    fn a_sized_window_shrinks_to_what_a_slow_leg_carries() {
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.settle();
        l.run(Duration::from_secs(30), TEN_MS);
        let size = l.w.size(l.key);
        assert!(
            size < DEFAULT_WINDOW / 2,
            "on a slow leg the window stayed at {} KiB",
            size >> 10
        );
        assert!(
            size >= DEFAULT_MIN_WINDOW,
            "the window shrank to {size} bytes, under its floor"
        );
        // What a pong waits behind is the queue the window lets build: horizon
        // of the leg, and the frame that went just before the window filled.
        let limit = sized().horizon
            + Duration::from_secs_f64(FRAME as f64 / SLOW_LEG)
            + Duration::from_millis(500);
        assert!(
            l.worst_queue <= limit,
            "a byte waited {:?} in the relay on a settled leg, over {limit:?}",
            l.worst_queue
        );
    }

    // TestAFixedWindowQueuesSecondsOnTheSameLeg
    #[test]
    fn a_fixed_window_queues_seconds_on_the_same_leg() {
        // The control: the same leg with the fixed window queues a whole
        // window, several seconds of it.
        let mut l = Leg::new(Timing::default(), SLOW_LEG, SLOW_RTT);
        l.settle();
        l.run(Duration::from_secs(30), TEN_MS);
        assert_eq!(
            l.w.size(l.key),
            DEFAULT_WINDOW,
            "a fixed window changed size"
        );
        assert!(
            l.worst_queue >= Duration::from_secs(6),
            "the fixed window queued only {:?}: the control proves nothing",
            l.worst_queue
        );
    }

    // TestASizedWindowGrowsBackWhenTheLegSpeedsUp
    #[test]
    fn a_sized_window_grows_back_when_the_leg_speeds_up() {
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.settle();
        assert!(
            l.w.size(l.key) < DEFAULT_WINDOW,
            "the window did not shrink on the slow leg to begin with"
        );
        l.rate = 1_000_000.0;
        l.run(Duration::from_secs(20), TEN_MS);
        assert_eq!(
            l.w.size(l.key),
            DEFAULT_WINDOW,
            "on a 1 MB/s leg the window is not at its cap"
        );
    }

    // TestASenderThatIsNeverHeldLeavesTheSizeAlone
    #[test]
    fn a_sender_that_is_never_held_leaves_the_size_alone() {
        // A sender under what the leg carries says nothing about the leg.
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.app_limit = SLOW_LEG / 4.0;
        let first = l.w.size(l.key);
        l.run(Duration::from_secs(60), TEN_MS);
        assert_eq!(
            l.w.size(l.key),
            first,
            "a sender that never filled the window moved its size"
        );
    }

    // TestMarksFollowTheSize
    #[test]
    fn marks_follow_the_size() {
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.settle();
        let st = snapshot(&l.w, l.key);
        let want = (st.size * l.w.timing().mark_every / DEFAULT_WINDOW).max(MIN_MARK_EVERY);
        assert_eq!(
            st.mark_every,
            want,
            "a {} KiB window marks at the wrong spacing",
            st.size >> 10
        );
        assert!(
            st.mark_every < l.w.timing().mark_every,
            "a shrunk window still marks as the cap does"
        );
    }

    // TestASizedWindowHoldsAndOverflowsAtItsOwnSize
    #[test]
    fn a_sized_window_holds_and_overflows_at_its_own_size() {
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.settle();
        let st = snapshot(&l.w, l.key);
        let in_flight = st.sent - st.echoed;
        assert!(
            in_flight >= st.size,
            "a settled sender has {in_flight} bytes in flight under its {} byte window",
            st.size
        );
        assert!(
            !ok(&mut l.w, l.key, l.now),
            "room lets a send go with {in_flight} in flight on a {} byte window",
            st.size
        );
        assert!(
            l.w.over(l.key, 0, l.now) || in_flight <= st.size,
            "over does not see bytes past the window"
        );
    }

    // TestResetForgetsTheSize
    #[test]
    fn reset_forgets_the_size() {
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.settle();
        l.w.reset(l.key);
        l.w.epoch(l.key); // the next send opens it again
        assert_eq!(l.w.size(l.key), FIRST_SIZED_WINDOW);
        let st = l.w.windows.get(l.key).expect("window");
        let leg = st
            .leg
            .as_deref()
            .expect("a sized window opened again has nothing to measure its leg with");
        assert!(
            leg.rate_since.is_none() && leg.rates == [0.0; RATE_SAMPLES],
            "a reset window kept its measurements"
        );
    }

    // TestAnEchoWithoutAClockNeverResizes
    #[test]
    fn an_echo_without_a_clock_never_resizes() {
        let mut l = Leg::new(sized(), SLOW_LEG, SLOW_RTT);
        l.timed = false;
        let first = l.w.size(l.key);
        l.run(Duration::from_secs(60), TEN_MS);
        assert_eq!(
            l.w.size(l.key),
            first,
            "echoes with no clock resized the window"
        );
    }

    // TestWithoutAHorizonTheWindowIsFixed
    #[test]
    fn without_a_horizon_the_window_is_fixed() {
        let mut l = Leg::new(Timing::default(), SLOW_LEG, SLOW_RTT);
        l.run(Duration::from_secs(60), TEN_MS);
        assert_eq!(l.w.size(l.key), DEFAULT_WINDOW);
        assert_eq!(
            l.w.timing().min_window,
            0,
            "a timing with no horizon took a min_window"
        );
    }

    // TestSizeOfAWindowNotOpenIsTheCap
    #[test]
    fn size_of_a_window_not_open_is_the_cap() {
        let w = Windows::new(sized());
        assert_eq!(w.size("nobody"), DEFAULT_WINDOW);
        assert_eq!(w.len(), 0, "size opened a window");
    }

    // TestASizedWindowStartsSmallAndAFastLegGrowsItToTheCap
    #[test]
    fn a_sized_window_starts_small_and_a_fast_leg_grows_it_to_the_cap() {
        let mut l = Leg::new(sized(), 1_000_000.0, Duration::from_millis(50));
        assert_eq!(l.w.size(l.key), FIRST_SIZED_WINDOW);
        l.run(Duration::from_secs(3), Duration::from_millis(5));
        assert_eq!(
            l.w.size(l.key),
            DEFAULT_WINDOW,
            "3 s on a 1 MB/s leg left the window under its cap"
        );
    }

    // TestABurstyLegDoesNotCollapseASizedWindow
    #[test]
    fn a_bursty_leg_does_not_collapse_a_sized_window() {
        const BURSTY_LEG: f64 = 60_000.0;
        let mut l = Leg::new(sized(), BURSTY_LEG, Duration::from_millis(300));
        l.jitter = Duration::from_secs(3);
        l.seed = 49;
        l.settle();
        let (from, mut least) = (l.drained, l.w.size(l.key));
        for _ in 0..600 {
            l.run(Duration::from_millis(100), TEN_MS);
            least = least.min(l.w.size(l.key));
        }
        let rate = (l.drained - from) / 60.0;
        assert!(
            rate >= BURSTY_LEG * 0.8,
            "a bursty leg moved {:.1} kB/s under a sized window, under 80 % of it",
            rate / 1000.0
        );
        assert!(
            least >= DEFAULT_WINDOW / 3,
            "the window fell to {} KiB: it measured its own size, not the leg",
            least >> 10
        );
    }

    // ---- bounded state: size_of assertions on the hot per-destination structs ----

    /// `State`, the hot per-destination struct, on a 64-bit Linux target
    /// (`Instant` is a 16-byte `Timespec` with a niche, so `Option<Instant>` is
    /// 16 bytes too):
    ///
    /// * six `u64`: sent, marked, echoed, epoch, size, mark_every = 48
    /// * three `Option<Instant>`: marked_at, held_since, waiting_since = 48
    /// * `active: bool` = 1, padded to the 8-byte alignment = 8
    /// * `wake: Wake` (one `Arc`) = 8
    /// * `leg: Option<Box<LegMeasure>>` (niche on the box) = 8
    ///
    /// 48 + 48 + 8 + 8 + 8 = 120 bytes. Behind the `Arc` is one heap block per
    /// destination (the `Notify` and a flag), and a sized window adds one boxed
    /// `LegMeasure`.
    #[test]
    fn the_per_destination_state_is_one_small_struct() {
        assert_eq!(std::mem::size_of::<Option<Instant>>(), 16);
        assert_eq!(std::mem::size_of::<State>(), 120);
    }

    /// `LegMeasure`, boxed only for a sized window:
    /// `rate_since: Option<Instant>` 16 + `rate_from: u64` 8 +
    /// `rates: [f64; 10]` 80 + `next: usize` 8 + `held: bool` 1 padded to 8 =
    /// 16 + 8 + 80 + 8 + 8 = 120 bytes.
    #[test]
    fn the_leg_measurement_is_a_fixed_block() {
        assert_eq!(std::mem::size_of::<LegMeasure>(), 120);
    }
}

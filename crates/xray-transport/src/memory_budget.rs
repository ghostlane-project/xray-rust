//! The process's budget of payload bytes in flight.
//!
//! Every buffer that holds a flow's payload while it moves is sized by
//! something local: a relay read by its buffer, a TLS session by its record
//! queue, a flow-controlled stream by the window its peer was granted. Each
//! of those is reasonable for one flow and multiplies with the number of
//! flows, so what a process holds at its busiest grew with N, not with the
//! link: 32 uploading Reality flows held about 8.4 MB, 256 would hold 67.
//!
//! The budget is one number, `B`, for the whole process: the bytes the link
//! can have in flight. A holder takes bytes of `B` before it holds payload
//! beyond its floor and gives them back once the payload is written or
//! dropped. When `B` is spent a holder does not allocate: it reads less,
//! waits for its writer to drain, or holds back the credit its peer needs to
//! send more. That is backpressure, and it reaches the sender.
//!
//! # Sizing
//!
//! `B = rate × RTT` ([`bandwidth_delay_product`]): enough for one flow to
//! fill the link, shared by all of them when there are many. The default
//! rate is the host's memory class's ([`ByteBudgetSettings::for_class`]): a
//! constrained host (a phone) is sized for 200 Mbit/s over 120 ms, which is
//! 3,000,000 bytes; a standard host for 1 Gbit/s over the same 120 ms,
//! 15,000,000 bytes.
//!
//! Each flow keeps a floor outside `B` ([`DEFAULT_FLOW_FLOOR`], 4 KiB), so
//! that a flow always moves even when `B` is spent and no flow can wait on
//! another for good. The floor is the budget's overshoot: at hev's 256
//! sessions, two directions each, it is 256 × 2 × 4 KiB = 2 MiB beyond `B`.
//!
//! [`set_byte_budget`] changes both at any time. A smaller `B` takes effect as
//! held bytes come back; nothing held is revoked.
//!
//! # Who takes bytes
//!
//! - A relay direction, for a read beyond its floor and for what it wrote
//!   that its writer may still hold (a TLS session's records) until it
//!   flushes: [`BudgetPermits`].
//! - A flow-controlled receive window (an HTTP/2 stream), for the bytes it
//!   received and no reader has taken yet, beyond its floor: a
//!   [`ReceiveGate`]. Credit its peer has and has not used holds nothing, so
//!   an idle stream holds no bytes of `B` however large its window; when the
//!   windows' part of `B` is spent, a stream that queues more than its floor
//!   hands credit back only once that part covers its queue again, at the
//!   latest when its reader has taken the queue down to the floor.
//! - A QUIC connection's receive and send windows together, for the part of
//!   them above the floor while the connection moves data: a
//!   [`WindowLease`].
//!
//! Windows of both kinds share what `B` leaves after a reserve for the
//! relays (`B / 8`, [`RELAY_RESERVE_DIVISOR`]): queues beyond that part get
//! no more credit until they drain. Leases hold for as long as their
//! connections move data: a lone lease takes all the windows' part, and once
//! another is held below its fair share every lease is held to
//! `(B - B / 8) / leases`. Handshake values (HTTP/2 SETTINGS, the first
//! connection WINDOW_UPDATE, QUIC transport parameters) are not touched:
//! only when later credit goes out moves.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Waker};

use tokio::sync::futures::Notified;
use tokio::sync::Notify;

use crate::{memory_class, MemoryClass};

/// The link a constrained host's budget is sized for: a phone's 200 Mbit/s.
pub const CONSTRAINED_BUDGET_RATE_BITS_PER_SECOND: u64 = 200_000_000;
/// The link a standard host's budget is sized for: 1 Gbit/s.
pub const STANDARD_BUDGET_RATE_BITS_PER_SECOND: u64 = 1_000_000_000;
/// The round trip both are sized for: 120 ms, a phone in Russia to an exit
/// in western Europe.
pub const BUDGET_RTT_MILLIS: u64 = 120;

/// What each flow may hold outside the budget: one 4 KiB read, the relay's
/// first read size. 256 flows × 2 directions × 4 KiB = 2 MiB at most.
pub const DEFAULT_FLOW_FLOOR: usize = 4 * 1024;
/// The smallest floor: the relay's smallest read.
pub const MIN_FLOW_FLOOR: usize = 1024;
/// The largest floor: one HTTP/2 or QUIC flow's useful minimum window, past
/// which the floor rather than `B` would bound the process.
pub const MAX_FLOW_FLOOR: usize = 64 * 1024;

/// The part of `B` kept from the leases for the relays: an eighth. On a
/// phone that is 375,000 bytes, four relay directions at the phone's read cap
/// with a TLS writer's unflushed threshold each (4 × (32 + 64) KiB).
pub const RELAY_RESERVE_DIVISOR: usize = 8;

/// `rate × RTT` in bytes: what a path of `rate_bits_per_second` and
/// `rtt_millis` holds in flight.
pub const fn bandwidth_delay_product(rate_bits_per_second: u64, rtt_millis: u64) -> usize {
    // In 128 bits no product of two u64 overflows.
    let bytes = rate_bits_per_second as u128 / 8 * rtt_millis as u128 / 1000;
    if bytes > usize::MAX as u128 {
        usize::MAX
    } else {
        bytes as usize
    }
}

/// The budget's two numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudgetSettings {
    /// `B`: the bytes all holders together may take.
    pub capacity: usize,
    /// What each holder keeps outside `B`. Clamped to
    /// [`MIN_FLOW_FLOOR`]..=[`MAX_FLOW_FLOOR`].
    pub floor: usize,
}

impl ByteBudgetSettings {
    /// The formula's budget for a host of `class`.
    pub const fn for_class(class: MemoryClass) -> Self {
        let rate = match class {
            MemoryClass::Standard => STANDARD_BUDGET_RATE_BITS_PER_SECOND,
            MemoryClass::Constrained => CONSTRAINED_BUDGET_RATE_BITS_PER_SECOND,
        };
        Self {
            capacity: bandwidth_delay_product(rate, BUDGET_RTT_MILLIS),
            floor: DEFAULT_FLOW_FLOOR,
        }
    }
}

/// The budget's state at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteBudgetUsage {
    pub capacity: usize,
    pub floor: usize,
    /// Bytes taken now. Above `capacity` only after the capacity was lowered.
    pub in_use: usize,
    /// The most taken at once since the last [`reset_byte_budget_peak`].
    pub peak: usize,
    /// Leases whose connections move data now.
    pub windows: usize,
    /// Bytes the windows hold, leases and receive gates, part of `in_use`.
    pub window_bytes: usize,
}

static PROCESS: ByteBudget = ByteBudget::new();

/// Sets the process's budget; `None` returns it to the formula for the
/// memory class ([`ByteBudgetSettings::for_class`]). Takes effect at once:
/// a holder that asks for bytes next sees the new numbers.
pub fn set_byte_budget(settings: Option<ByteBudgetSettings>) {
    PROCESS.set(settings);
}

/// The process's budget now.
pub fn byte_budget() -> ByteBudgetSettings {
    PROCESS.settings()
}

/// The process's budget and what is taken of it.
pub fn byte_budget_usage() -> ByteBudgetUsage {
    PROCESS.usage()
}

/// Starts [`ByteBudgetUsage::peak`] again from what is taken now.
pub fn reset_byte_budget_peak() {
    PROCESS.reset_peak();
}

/// A budget of bytes: the process's ([`ByteBudget::process`]), or one of a
/// test's own.
#[derive(Debug)]
pub struct ByteBudget {
    /// The capacity set, plus one; zero follows the memory class.
    capacity: AtomicUsize,
    /// The floor set; zero follows the memory class.
    floor: AtomicUsize,
    in_use: AtomicUsize,
    peak: AtomicUsize,
    /// The queue's length; read before the lock is taken.
    waiting: AtomicUsize,
    /// Holders waiting for bytes, in the order they began to wait.
    queue: Mutex<VecDeque<Arc<Waiter>>>,
    /// Leases that want bytes.
    windows: AtomicUsize,
    window_bytes: AtomicUsize,
    /// Leases held below their fair share.
    short_windows: AtomicUsize,
    /// Moved on whenever leases should fit themselves again: the budget
    /// changed, a lease fell short, or one gave bytes back while another
    /// was short. [`Self::window_events`] wakes on each.
    window_generation: AtomicUsize,
    window_events: Notify,
}

impl Default for ByteBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteBudget {
    /// A budget that follows the memory class until it is set.
    pub const fn new() -> Self {
        Self {
            capacity: AtomicUsize::new(0),
            floor: AtomicUsize::new(0),
            in_use: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            queue: Mutex::new(VecDeque::new()),
            windows: AtomicUsize::new(0),
            window_bytes: AtomicUsize::new(0),
            short_windows: AtomicUsize::new(0),
            window_generation: AtomicUsize::new(0),
            window_events: Notify::const_new(),
        }
    }

    /// A budget with these numbers from the start.
    pub fn with_settings(settings: ByteBudgetSettings) -> Self {
        let budget = Self::new();
        budget.set(Some(settings));
        budget
    }

    /// The process's budget, which [`set_byte_budget`] sets.
    pub fn process() -> &'static ByteBudget {
        &PROCESS
    }

    pub fn set(&self, settings: Option<ByteBudgetSettings>) {
        match settings {
            None => {
                self.capacity.store(0, Ordering::SeqCst);
                self.floor.store(0, Ordering::SeqCst);
            }
            Some(settings) => {
                let floor = settings.floor.clamp(MIN_FLOW_FLOOR, MAX_FLOW_FLOOR);
                self.floor.store(floor, Ordering::SeqCst);
                self.capacity
                    .store(settings.capacity.saturating_add(1), Ordering::SeqCst);
            }
        }
        // A larger budget may have room for a waiter now, and the leases
        // fit themselves to the new numbers: a smaller budget takes back
        // what they hold above their new share.
        self.serve(&mut self.lock_queue());
        self.window_event();
    }

    pub fn settings(&self) -> ByteBudgetSettings {
        ByteBudgetSettings {
            capacity: self.capacity(),
            floor: self.floor(),
        }
    }

    pub fn capacity(&self) -> usize {
        match self.capacity.load(Ordering::SeqCst) {
            0 => ByteBudgetSettings::for_class(memory_class()).capacity,
            set => set - 1,
        }
    }

    pub fn floor(&self) -> usize {
        match self.floor.load(Ordering::SeqCst) {
            0 => ByteBudgetSettings::for_class(memory_class()).floor,
            set => set,
        }
    }

    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::SeqCst)
    }

    pub fn usage(&self) -> ByteBudgetUsage {
        ByteBudgetUsage {
            capacity: self.capacity(),
            floor: self.floor(),
            in_use: self.in_use(),
            peak: self.peak.load(Ordering::SeqCst),
            windows: self.windows.load(Ordering::SeqCst),
            window_bytes: self.window_bytes.load(Ordering::SeqCst),
        }
    }

    pub fn reset_peak(&self) {
        self.peak.store(self.in_use(), Ordering::SeqCst);
    }

    /// Takes up to `want` bytes without waiting; returns how many it took.
    fn take(&self, want: usize) -> usize {
        if want == 0 {
            return 0;
        }
        let capacity = self.capacity();
        let mut in_use = self.in_use.load(Ordering::SeqCst);
        loop {
            let taken = want.min(capacity.saturating_sub(in_use));
            if taken == 0 {
                return 0;
            }
            match self.in_use.compare_exchange_weak(
                in_use,
                in_use + taken,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.peak.fetch_max(in_use + taken, Ordering::SeqCst);
                    return taken;
                }
                Err(current) => in_use = current,
            }
        }
    }

    /// Gives `bytes` back: to the holders waiting, first come first served,
    /// as far as they cover what each is short of, and the rest to the
    /// budget. Only the waiters whose bytes are all there are woken.
    fn give(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        if self.waiting.load(Ordering::SeqCst) != 0 {
            let mut queue = self.lock_queue();
            let rest = self.hand_out(&mut queue, bytes);
            self.in_use.fetch_sub(rest, Ordering::SeqCst);
            return;
        }
        self.in_use.fetch_sub(bytes, Ordering::SeqCst);
        // A holder that began to wait after the check above has missed
        // these bytes, or else it found them free (`wait`).
        if self.waiting.load(Ordering::SeqCst) != 0 {
            self.serve(&mut self.lock_queue());
        }
    }

    /// The bytes no holder has taken.
    pub fn free(&self) -> usize {
        self.capacity().saturating_sub(self.in_use())
    }

    /// What the windows, leases and receive gates, may hold together: `B`
    /// less the relays' reserve.
    pub fn window_cap(&self) -> usize {
        let capacity = self.capacity();
        capacity - capacity / RELAY_RESERVE_DIVISOR
    }

    /// Moved on each time the leases should fit themselves again.
    pub fn window_generation(&self) -> usize {
        self.window_generation.load(Ordering::SeqCst)
    }

    /// Resolves at the next window event. Enable it (or poll it once) before
    /// reading [`Self::window_generation`] so that no event falls between.
    pub fn window_events(&self) -> Notified<'_> {
        self.window_events.notified()
    }

    fn window_event(&self) {
        self.window_generation.fetch_add(1, Ordering::SeqCst);
        self.window_events.notify_waiters();
    }

    fn lock_queue(&self) -> MutexGuard<'_, VecDeque<Arc<Waiter>>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands `bytes`, taken already, to the waiters at the front of the
    /// queue; returns what none of them is short of.
    fn hand_out(&self, queue: &mut VecDeque<Arc<Waiter>>, mut bytes: usize) -> usize {
        while bytes > 0 {
            let Some(front) = queue.front() else {
                break;
            };
            let mut state = front.lock();
            if front.queued.load(Ordering::SeqCst) {
                let handed = bytes.min(state.short);
                front.handed.fetch_add(handed, Ordering::SeqCst);
                state.short -= handed;
                bytes -= handed;
                if state.short > 0 {
                    break;
                }
                front.queued.store(false, Ordering::SeqCst);
                if let Some(waker) = state.waker.take() {
                    waker.wake();
                }
            }
            drop(state);
            queue.pop_front();
        }
        self.drop_stale(queue);
        bytes
    }

    /// Hands what is free to the waiters at the front of the queue.
    fn serve(&self, queue: &mut VecDeque<Arc<Waiter>>) {
        while let Some(front) = queue.front() {
            let mut state = front.lock();
            if front.queued.load(Ordering::SeqCst) {
                let handed = self.take(state.short);
                front.handed.fetch_add(handed, Ordering::SeqCst);
                state.short -= handed;
                if state.short > 0 {
                    break;
                }
                front.queued.store(false, Ordering::SeqCst);
                if let Some(waker) = state.waker.take() {
                    waker.wake();
                }
            }
            drop(state);
            queue.pop_front();
        }
        self.drop_stale(queue);
    }

    /// Pops the holders at the front that stopped waiting, and counts the
    /// rest.
    fn drop_stale(&self, queue: &mut VecDeque<Arc<Waiter>>) {
        while queue
            .front()
            .is_some_and(|front| !front.queued.load(Ordering::SeqCst))
        {
            queue.pop_front();
        }
        self.waiting.store(queue.len(), Ordering::SeqCst);
    }
}

/// A holder's place in its budget's queue.
#[derive(Debug, Default)]
struct Waiter {
    /// In the queue and short of bytes. Set only by the holder, cleared by
    /// whoever ends the wait, both under `state`.
    queued: AtomicBool,
    /// Bytes handed to the holder while it waited: taken of the budget for
    /// it, and its once it next holds.
    handed: AtomicUsize,
    state: Mutex<WaitState>,
}

#[derive(Debug, Default)]
struct WaitState {
    /// The holder's task, woken once its bytes are all handed to it.
    waker: Option<Waker>,
    /// What it still waits for.
    short: usize,
}

impl Waiter {
    fn lock(&self) -> MutexGuard<'_, WaitState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Bytes one holder has taken from a budget; dropped, they go back.
#[derive(Debug)]
pub struct BudgetPermits<'b> {
    budget: &'b ByteBudget,
    held: usize,
    /// Its place in the queue, from the first time it waited.
    waiter: Option<Arc<Waiter>>,
}

impl<'b> BudgetPermits<'b> {
    /// Bytes held for a moment: a read and its write.
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self {
            budget,
            held: 0,
            waiter: None,
        }
    }

    pub fn budget(&self) -> &'b ByteBudget {
        self.budget
    }

    pub fn held(&self) -> usize {
        self.held
    }

    /// Holds `bytes` if the budget has them: gives back what is held above
    /// `bytes` and takes what is missing as far as the budget allows. Never
    /// waits. Returns what is held.
    pub fn try_hold(&mut self, bytes: usize) -> usize {
        if let Some(waiter) = &self.waiter {
            self.held += waiter.handed.swap(0, Ordering::SeqCst);
        }
        if bytes > self.held {
            self.held += self.budget.take(bytes - self.held);
        } else if bytes < self.held {
            self.budget.give(self.held - bytes);
            self.held = bytes;
        }
        self.held
    }

    /// Has the task of `cx` woken once the budget can give this holder
    /// `bytes` in all, counting what it holds: the holders that wait are
    /// handed the bytes given back in the order they began to wait, and
    /// each is woken once it has all it waits for, so a give wakes no more
    /// tasks than it has bytes for. Waiting again keeps the holder's place.
    ///
    /// Returns whether the bytes are there already (free, or handed to it
    /// meanwhile); then the caller holds them now rather than wait.
    pub fn wake_when_free(&mut self, cx: &mut Context<'_>, bytes: usize) -> bool {
        let budget = self.budget;
        let held = self.held;
        // No holder waits for more than all of `B`: it would never be woken.
        let bytes = bytes.min(budget.capacity());
        let waiter = self.waiter.get_or_insert_with(Arc::default);
        let mut queue = budget.lock_queue();
        {
            let mut state = waiter.lock();
            let short = bytes.saturating_sub(held + waiter.handed.load(Ordering::SeqCst));
            if short == 0 {
                return true;
            }
            state.short = short;
            if !state
                .waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                state.waker = Some(cx.waker().clone());
            }
            if !waiter.queued.swap(true, Ordering::SeqCst) {
                queue.push_back(Arc::clone(waiter));
            }
            budget.waiting.store(queue.len(), Ordering::SeqCst);
        }
        // Bytes given back before the count above was stored went to the
        // budget, not to the queue: hand them out now.
        budget.serve(&mut queue);
        !waiter.queued.load(Ordering::SeqCst)
    }

    /// Ends a wait the holder no longer needs: its place goes, and bytes
    /// handed to it go to the next waiter.
    pub fn stop_waiting(&mut self) {
        let Some(waiter) = &self.waiter else {
            return;
        };
        if waiter.queued.load(Ordering::SeqCst) {
            let mut state = waiter.lock();
            waiter.queued.store(false, Ordering::SeqCst);
            state.short = 0;
            state.waker = None;
        }
        let late = waiter.handed.swap(0, Ordering::SeqCst);
        self.budget.give(late);
    }

    /// Gives back everything held, and stops waiting.
    pub fn release(&mut self) {
        self.stop_waiting();
        self.try_hold(0);
    }
}

impl Drop for BudgetPermits<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Paces the credit one flow-controlled receive window hands back by the
/// bytes it holds.
///
/// A receive window lets its peer send that much ahead of the reader, and
/// what arrives waits in the window's queue until a reader takes it. Those
/// bytes, beyond the floor, take bytes of the budget. As a reader takes
/// bytes, the credit they free is owed to the peer and handed back at once,
/// unless the budget is spent and the queue still holds more than the floor:
/// then the credit waits until the reader has taken the queue down to the
/// floor or the budget has room again, and a peer that outruns a pressed
/// process pauses on its window. The reader's next read decides again, so no
/// task waits on the budget and a stream's credit never depends on another
/// stream's.
///
/// Credit the peer has and has not used holds nothing: an idle stream holds
/// no bytes of `B`, whatever its window. What all streams can hold at once is
/// therefore bounded by their windows, as without a budget; the budget bounds
/// what they hold while readers keep up and the pace at which a pressed
/// process lets a queue refill.
#[derive(Debug)]
pub struct ReceiveGate<'b> {
    permits: BudgetPermits<'b>,
    owed: usize,
}

impl<'b> ReceiveGate<'b> {
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self {
            permits: BudgetPermits::new(budget),
            owed: 0,
        }
    }

    pub fn budget(&self) -> &'b ByteBudget {
        self.permits.budget()
    }

    /// A reader took `bytes`: the window owes the peer that much credit.
    pub fn consumed(&mut self, bytes: usize) {
        self.owed = self.owed.saturating_add(bytes);
    }

    /// Credit taken by readers and not handed back yet.
    pub fn owed(&self) -> usize {
        self.owed
    }

    /// Bytes of the budget the window holds.
    pub fn held(&self) -> usize {
        self.permits.held()
    }

    /// Holds the budget's bytes for `queued`, the bytes received and not
    /// taken by a reader, and returns how much of the credit owed to hand
    /// back now: all of it while the budget covers the queue beyond the
    /// floor, none while it does not, nor while the budget holds more than
    /// a lowered capacity: then queues beyond the floor drain before their
    /// peers may send more, and what they hold comes back.
    pub fn grant(&mut self, queued: usize) -> usize {
        let budget = self.permits.budget();
        let need = queued.saturating_sub(budget.floor());
        let before = self.permits.held();
        let held = self.permits.try_hold(need);
        if held > before {
            budget.window_bytes.fetch_add(held - before, Ordering::SeqCst);
        } else {
            budget.window_bytes.fetch_sub(before - held, Ordering::SeqCst);
        }
        let spent = budget.in_use() > budget.capacity()
            || budget.window_bytes.load(Ordering::SeqCst) > budget.window_cap();
        if held < need || (need > 0 && spent) {
            return 0;
        }
        std::mem::take(&mut self.owed)
    }

    /// Gives back the budget's bytes; the window is closed.
    pub fn close(&mut self) {
        self.owed = 0;
        let held = self.permits.held();
        self.permits.budget().window_bytes.fetch_sub(held, Ordering::SeqCst);
        self.permits.release();
    }
}

impl Drop for ReceiveGate<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

/// A QUIC connection's receive and send windows, sized from the budget as
/// one holder.
///
/// While the connection moves data each window wants the part of its size
/// above the floor; the lease takes what the leases' share allows and the
/// connection runs its windows at the floor plus their parts of it. A lone
/// lease takes up to all the leases may hold ([`ByteBudget::window_cap`]);
/// once another lease is held below its fair share, each is held to
/// `window_cap / leases` from its next fit, and gives the rest back. An idle
/// connection wants nothing and holds nothing.
#[derive(Debug)]
pub struct WindowLease<'b> {
    permits: BudgetPermits<'b>,
    /// Counted among the leases that want bytes.
    active: bool,
    /// Counted among the leases held below their fair share.
    short: bool,
}

impl<'b> WindowLease<'b> {
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self {
            permits: BudgetPermits::new(budget),
            active: false,
            short: false,
        }
    }

    pub fn budget(&self) -> &'b ByteBudget {
        self.permits.budget()
    }

    pub fn held(&self) -> usize {
        self.permits.held()
    }

    /// Whether the last fit held the lease below its fair share.
    pub fn is_short(&self) -> bool {
        self.short
    }

    /// Fits the lease to windows that want `want` bytes above their floors,
    /// and returns what it holds now: at most `want`, what the leases'
    /// share leaves it and what `B` has free.
    pub fn fit(&mut self, want: usize) -> usize {
        let budget = self.permits.budget();
        if (want > 0) != self.active {
            self.active = want > 0;
            if self.active {
                budget.windows.fetch_add(1, Ordering::SeqCst);
            } else {
                budget.windows.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let cap = budget.window_cap();
        let fair = cap / budget.windows.load(Ordering::SeqCst).max(1);
        let before = self.permits.held();
        let others_hold = budget
            .window_bytes
            .load(Ordering::SeqCst)
            .saturating_sub(before);
        let others_short =
            budget.short_windows.load(Ordering::SeqCst) > usize::from(self.short);
        let share = if others_short { fair } else { cap };
        let target = want.min(share).min(cap.saturating_sub(others_hold));
        let held = self.permits.try_hold(target);
        if held > before {
            budget.window_bytes.fetch_add(held - before, Ordering::SeqCst);
        } else {
            budget.window_bytes.fetch_sub(before - held, Ordering::SeqCst);
        }
        let short = held < want.min(fair);
        if short != self.short {
            self.short = short;
            if short {
                budget.short_windows.fetch_add(1, Ordering::SeqCst);
                // The others give back what they hold above their share.
                budget.window_event();
            } else {
                budget.short_windows.fetch_sub(1, Ordering::SeqCst);
            }
        }
        if held < before && others_short {
            // Bytes for the leases that are short.
            budget.window_event();
        }
        held
    }

    /// Gives back what the lease holds; the connection is closed.
    pub fn release(&mut self) {
        self.fit(0);
    }
}

impl Drop for WindowLease<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use std::task::Wake;

    use super::*;

    const KIB: usize = 1024;

    fn budget(capacity: usize, floor: usize) -> ByteBudget {
        ByteBudget::with_settings(ByteBudgetSettings { capacity, floor })
    }

    #[test]
    fn the_default_budget_is_the_bandwidth_delay_product_of_the_class() {
        // 200 Mbit/s × 120 ms and 1 Gbit/s × 120 ms.
        assert_eq!(
            ByteBudgetSettings::for_class(MemoryClass::Constrained),
            ByteBudgetSettings {
                capacity: 3_000_000,
                floor: 4 * KIB,
            }
        );
        assert_eq!(
            ByteBudgetSettings::for_class(MemoryClass::Standard).capacity,
            15_000_000
        );
        assert_eq!(bandwidth_delay_product(u64::MAX, u64::MAX), usize::MAX);
    }

    #[test]
    fn an_unset_budget_follows_the_memory_class_and_a_set_one_its_numbers() {
        let budget = ByteBudget::new();
        assert_eq!(
            budget.settings(),
            ByteBudgetSettings::for_class(memory_class())
        );
        budget.set(Some(ByteBudgetSettings {
            capacity: 0,
            floor: 1,
        }));
        assert_eq!(
            budget.settings(),
            ByteBudgetSettings {
                capacity: 0,
                floor: MIN_FLOW_FLOOR,
            },
            "a zero capacity is a budget of floors only, and the floor is clamped"
        );
        budget.set(None);
        assert_eq!(
            budget.settings(),
            ByteBudgetSettings::for_class(memory_class())
        );
    }

    #[test]
    fn holders_take_what_is_free_and_give_it_back_when_dropped() {
        let budget = budget(100 * KIB, 4 * KIB);
        let mut first = BudgetPermits::new(&budget);
        let mut second = BudgetPermits::new(&budget);
        assert_eq!(first.try_hold(60 * KIB), 60 * KIB);
        assert_eq!(second.try_hold(60 * KIB), 40 * KIB, "only what is free");
        assert_eq!(budget.in_use(), 100 * KIB);
        assert_eq!(
            first.try_hold(10 * KIB),
            10 * KIB,
            "holding less gives back"
        );
        assert_eq!(second.try_hold(60 * KIB), 60 * KIB);
        drop(second);
        assert_eq!(budget.in_use(), 10 * KIB);
        first.release();
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.usage().peak, 100 * KIB);
    }

    #[test]
    fn a_smaller_budget_takes_effect_as_bytes_come_back() {
        let budget = budget(100 * KIB, 4 * KIB);
        let mut held = BudgetPermits::new(&budget);
        assert_eq!(held.try_hold(80 * KIB), 80 * KIB);
        budget.set(Some(ByteBudgetSettings {
            capacity: 50 * KIB,
            floor: 4 * KIB,
        }));
        assert_eq!(held.held(), 80 * KIB, "nothing held is revoked");
        let mut late = BudgetPermits::new(&budget);
        assert_eq!(late.try_hold(KIB), 0);
        assert_eq!(held.try_hold(30 * KIB), 30 * KIB);
        assert_eq!(late.try_hold(30 * KIB), 20 * KIB);
    }

    /// A task's waker that counts its wakes.
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn task() -> (Arc<Wakes>, Waker) {
        let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        (wakes, waker)
    }

    fn wakes(task: &Wakes) -> usize {
        task.0.load(Ordering::SeqCst)
    }

    #[test]
    fn waiters_get_the_bytes_given_back_in_turn_and_only_those_covered_wake() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut all = BudgetPermits::new(&budget);
        all.try_hold(64 * KIB);
        let tasks: Vec<_> = (0..3).map(|_| task()).collect();
        let mut waiting: Vec<_> = (0..3).map(|_| BudgetPermits::new(&budget)).collect();
        for (permits, (_, waker)) in waiting.iter_mut().zip(&tasks) {
            assert_eq!(permits.try_hold(8 * KIB), 0);
            let mut cx = Context::from_waker(waker);
            assert!(!permits.wake_when_free(&mut cx, 8 * KIB));
        }
        // Waiting again keeps the place and does not queue twice.
        let mut cx = Context::from_waker(&tasks[0].1);
        assert!(!waiting[0].wake_when_free(&mut cx, 8 * KIB));
        assert_eq!(budget.waiting.load(Ordering::SeqCst), 3);

        all.try_hold(52 * KIB);
        assert_eq!(
            tasks
                .iter()
                .map(|(task, _)| wakes(task))
                .collect::<Vec<_>>(),
            [1, 0, 0],
            "12 KiB back: the first waiter has its 8 KiB, the second 4 of its 8"
        );
        assert_eq!(budget.in_use(), 64 * KIB, "handed bytes stay taken");
        assert_eq!(waiting[0].try_hold(8 * KIB), 8 * KIB);
        all.try_hold(48 * KIB);
        assert_eq!(
            tasks
                .iter()
                .map(|(task, _)| wakes(task))
                .collect::<Vec<_>>(),
            [1, 1, 0]
        );
        assert_eq!(waiting[1].try_hold(8 * KIB), 8 * KIB);
        assert_eq!(budget.waiting.load(Ordering::SeqCst), 1);
        assert_eq!(budget.free(), 0);
    }

    #[test]
    fn a_holder_that_stops_waiting_passes_its_bytes_on() {
        let budget = budget(16 * KIB, 4 * KIB);
        let mut all = BudgetPermits::new(&budget);
        all.try_hold(16 * KIB);
        let (first_task, first_waker) = task();
        let (second_task, second_waker) = task();
        let mut first = BudgetPermits::new(&budget);
        let mut second = BudgetPermits::new(&budget);
        assert!(!first.wake_when_free(&mut Context::from_waker(&first_waker), 8 * KIB));
        assert!(!second.wake_when_free(&mut Context::from_waker(&second_waker), 8 * KIB));

        all.try_hold(12 * KIB);
        assert_eq!(wakes(&first_task), 0, "4 of its 8 KiB are handed to it");
        drop(first);
        assert_eq!(wakes(&second_task), 0, "the 4 KiB pass on; 4 more to come");
        all.try_hold(8 * KIB);
        assert_eq!(wakes(&second_task), 1);
        second.stop_waiting();
        assert_eq!(
            budget.in_use(),
            8 * KIB,
            "an ended wait gives its bytes back"
        );
        assert_eq!(budget.waiting.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bytes_given_back_before_the_wait_began_are_not_missed() {
        let budget = budget(16 * KIB, 4 * KIB);
        let mut all = BudgetPermits::new(&budget);
        all.try_hold(16 * KIB);
        let mut late = BudgetPermits::new(&budget);
        assert_eq!(late.try_hold(4 * KIB), 0);
        // Given back between the failed hold and the wait: no one was
        // queued, so the bytes went to the budget.
        all.try_hold(10 * KIB);
        let (task, waker) = task();
        assert!(
            late.wake_when_free(&mut Context::from_waker(&waker), 4 * KIB),
            "the bytes are there: hold them rather than wait"
        );
        assert_eq!(late.try_hold(4 * KIB), 4 * KIB);
        assert_eq!(wakes(&task), 1, "served at once, so woken once");
        assert_eq!(budget.waiting.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_larger_budget_serves_its_waiters() {
        let budget = budget(10 * KIB, 4 * KIB);
        let mut all = BudgetPermits::new(&budget);
        all.try_hold(10 * KIB);
        let (task, waker) = task();
        let mut waiting = BudgetPermits::new(&budget);
        assert!(!waiting.wake_when_free(&mut Context::from_waker(&waker), 4 * KIB));
        budget.set(Some(ByteBudgetSettings {
            capacity: 20 * KIB,
            floor: 4 * KIB,
        }));
        assert_eq!(wakes(&task), 1, "woken when the budget grows");
        assert_eq!(waiting.try_hold(4 * KIB), 4 * KIB);
        waiting.release();
        // No holder waits for more than all of B.
        let mut greedy = BudgetPermits::new(&budget);
        assert!(!greedy.wake_when_free(&mut Context::from_waker(&waker), usize::MAX));
        drop(all);
        assert_eq!(wakes(&task), 2, "all of B came back to it");
        assert_eq!(greedy.try_hold(usize::MAX), 20 * KIB);
    }

    #[test]
    fn a_gate_holds_its_queue_beyond_the_floor_and_nothing_for_unused_credit() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut gate = ReceiveGate::new(&budget);
        // The peer has a 1 MiB window and has sent nothing: no bytes held.
        assert_eq!(gate.grant(0), 0);
        assert_eq!(gate.held(), 0);
        // 40 KiB arrived and a reader took 16 of them.
        gate.consumed(16 * KIB);
        assert_eq!(gate.grant(24 * KIB), 16 * KIB, "B covers the queue");
        assert_eq!(gate.held(), 20 * KIB, "the queue beyond the floor");
        // The reader caught up: the stream holds nothing, idle or not.
        gate.consumed(24 * KIB);
        assert_eq!(gate.grant(0), 24 * KIB);
        assert_eq!(gate.held(), 0);
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn a_pressed_gate_holds_back_credit_until_its_reader_drains_the_queue() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut other = BudgetPermits::new(&budget);
        other.try_hold(60 * KIB);
        let mut gate = ReceiveGate::new(&budget);
        gate.consumed(8 * KIB);
        assert_eq!(gate.grant(20 * KIB), 0, "16 KiB beyond the floor, 4 free");
        assert_eq!(gate.owed(), 8 * KIB);
        gate.consumed(12 * KIB);
        assert_eq!(gate.grant(8 * KIB), 20 * KIB, "4 KiB beyond the floor fit");
        gate.consumed(8 * KIB);
        assert_eq!(gate.grant(0), 8 * KIB, "within the floor it never waits");
        // Another holder's bytes coming back let a full queue refill too.
        gate.consumed(KIB);
        assert_eq!(gate.grant(40 * KIB), 0);
        drop(other);
        assert_eq!(gate.grant(40 * KIB), KIB);
        gate.close();
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn queues_beyond_the_windows_part_get_no_credit_and_leave_the_relays_reserve() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut gate = ReceiveGate::new(&budget);
        gate.consumed(8 * KIB);
        // 60 KiB beyond the floor: held, as they are in memory, but past the
        // windows' 56 KiB, so the peer gets no more until they drain.
        assert_eq!(gate.grant(64 * KIB), 0);
        assert_eq!(budget.usage().window_bytes, 60 * KIB);
        gate.consumed(8 * KIB);
        assert_eq!(gate.grant(56 * KIB), 16 * KIB, "52 KiB fit the windows' part");
        let mut relay = BudgetPermits::new(&budget);
        assert_eq!(relay.try_hold(16 * KIB), 12 * KIB);
        drop(gate);
        assert_eq!(budget.usage().window_bytes, 0, "a dropped gate gives back");
        assert_eq!(budget.in_use(), 12 * KIB);
    }

    #[test]
    fn a_lowered_budget_holds_back_credit_until_the_queues_drain() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut gate = ReceiveGate::new(&budget);
        gate.consumed(8 * KIB);
        assert_eq!(gate.grant(36 * KIB), 8 * KIB, "32 KiB beyond the floor fit");
        // A host under memory pressure lowers B below what the queue holds.
        budget.set(Some(ByteBudgetSettings {
            capacity: 16 * KIB,
            floor: 4 * KIB,
        }));
        gate.consumed(8 * KIB);
        assert_eq!(gate.grant(28 * KIB), 0, "B is spent: the queue drains first");
        assert_eq!(gate.held(), 24 * KIB, "what it holds follows the queue down");
        gate.consumed(16 * KIB);
        assert_eq!(gate.grant(12 * KIB), 24 * KIB, "within the new B again");
        assert_eq!(budget.in_use(), 8 * KIB);
        gate.close();
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn a_lone_lease_takes_all_but_the_relays_reserve() {
        let budget = budget(800 * KIB, 4 * KIB);
        let mut lease = WindowLease::new(&budget);
        assert_eq!(lease.fit(3 * 1024 * KIB), 700 * KIB, "B less an eighth");
        assert_eq!(budget.usage().windows, 1);
        assert_eq!(budget.usage().window_bytes, 700 * KIB);
        let mut relay = BudgetPermits::new(&budget);
        assert_eq!(relay.try_hold(200 * KIB), 100 * KIB, "the reserve is the relays'");
        assert_eq!(lease.fit(0), 0, "an idle connection holds nothing");
        assert_eq!(budget.usage().windows, 0);
        assert_eq!(budget.usage().window_bytes, 0);
    }

    #[test]
    fn leases_fall_to_a_fair_share_once_one_is_short() {
        let budget = budget(800 * KIB, 4 * KIB);
        let mut first = WindowLease::new(&budget);
        let mut second = WindowLease::new(&budget);
        assert_eq!(first.fit(1024 * KIB), 700 * KIB);
        let seen = budget.window_generation();
        assert_eq!(second.fit(1024 * KIB), 0, "the first holds the leases' share");
        assert!(second.is_short());
        assert_ne!(budget.window_generation(), seen, "the others are told");
        assert_eq!(first.fit(1024 * KIB), 350 * KIB, "half of the share each");
        assert_eq!(second.fit(1024 * KIB), 350 * KIB);
        assert!(!second.is_short());
        // A lease that wants less leaves the rest to the other at its next fit.
        assert_eq!(first.fit(100 * KIB), 100 * KIB);
        assert_eq!(second.fit(1024 * KIB), 600 * KIB);
        drop(first);
        drop(second);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.usage().windows, 0);
    }

    #[test]
    fn a_smaller_budget_takes_back_what_leases_hold_above_it() {
        let budget = budget(800 * KIB, 4 * KIB);
        let mut lease = WindowLease::new(&budget);
        assert_eq!(lease.fit(1024 * KIB), 700 * KIB);
        let seen = budget.window_generation();
        budget.set(Some(ByteBudgetSettings {
            capacity: 80 * KIB,
            floor: 4 * KIB,
        }));
        assert_ne!(budget.window_generation(), seen, "leases are told to fit again");
        assert_eq!(lease.fit(1024 * KIB), 70 * KIB);
        assert_eq!(budget.in_use(), 70 * KIB);
    }
}

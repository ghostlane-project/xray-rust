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
//! A relay direction, for a read beyond its floor and for what it wrote
//! that its writer may still hold (a TLS session's records) until it
//! flushes: [`BudgetPermits`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Waker};

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
        // A larger budget may have room for a waiter now.
        self.serve(&mut self.lock_queue());
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
            tasks.iter().map(|(task, _)| wakes(task)).collect::<Vec<_>>(),
            [1, 0, 0],
            "12 KiB back: the first waiter has its 8 KiB, the second 4 of its 8"
        );
        assert_eq!(budget.in_use(), 64 * KIB, "handed bytes stay taken");
        assert_eq!(waiting[0].try_hold(8 * KIB), 8 * KIB);
        all.try_hold(48 * KIB);
        assert_eq!(
            tasks.iter().map(|(task, _)| wakes(task)).collect::<Vec<_>>(),
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
        assert_eq!(budget.in_use(), 8 * KIB, "an ended wait gives its bytes back");
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
}

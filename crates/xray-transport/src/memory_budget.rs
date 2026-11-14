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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
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
    /// How many tasks wait for bytes; checked before taking the lock.
    waiting: AtomicUsize,
    wakers: Mutex<Vec<Waker>>,
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
            wakers: Mutex::new(Vec::new()),
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
        self.wake_all();
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

    fn give(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.in_use.fetch_sub(bytes, Ordering::SeqCst);
        if self.waiting.load(Ordering::SeqCst) != 0 {
            self.wake_all();
        }
    }

    /// The bytes no holder has taken.
    pub fn free(&self) -> usize {
        self.capacity().saturating_sub(self.in_use())
    }

    /// Wakes the task of `cx` once bytes come back or the budget grows.
    /// Returns whether the budget has free bytes already; the task is
    /// registered either way, so a caller that finds none can return
    /// `Pending`.
    pub fn wake_when_free(&self, cx: &mut Context<'_>) -> bool {
        {
            let mut wakers = self.wakers.lock().unwrap_or_else(PoisonError::into_inner);
            if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
            self.waiting.store(wakers.len(), Ordering::SeqCst);
        }
        self.free() > 0
    }

    fn wake_all(&self) {
        let wakers = {
            let mut wakers = self.wakers.lock().unwrap_or_else(PoisonError::into_inner);
            self.waiting.store(0, Ordering::SeqCst);
            std::mem::take(&mut *wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

/// Bytes one holder has taken from a budget; dropped, they go back.
#[derive(Debug)]
pub struct BudgetPermits<'b> {
    budget: &'b ByteBudget,
    held: usize,
}

impl<'b> BudgetPermits<'b> {
    /// Bytes held for a moment: a read and its write.
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self { budget, held: 0 }
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
        if bytes > self.held {
            self.held += self.budget.take(bytes - self.held);
        } else if bytes < self.held {
            self.budget.give(self.held - bytes);
            self.held = bytes;
        }
        self.held
    }

    /// Gives back everything held.
    pub fn release(&mut self) {
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
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
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

    struct Flag(AtomicBool);

    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_waiter_is_woken_when_bytes_come_back_or_the_budget_grows() {
        let budget = budget(10 * KIB, 4 * KIB);
        let mut all = BudgetPermits::new(&budget);
        all.try_hold(10 * KIB);

        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        assert!(!budget.wake_when_free(&mut cx));
        all.try_hold(9 * KIB);
        assert!(flag.0.swap(false, Ordering::SeqCst), "woken on give back");
        assert!(budget.wake_when_free(&mut cx), "one byte in KiB is free");
        all.try_hold(10 * KIB);
        budget.set(Some(ByteBudgetSettings {
            capacity: 20 * KIB,
            floor: 4 * KIB,
        }));
        assert!(flag.0.load(Ordering::SeqCst), "woken when the budget grows");
    }
}

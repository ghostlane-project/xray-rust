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
//!   flushes: [`BudgetPermits::new`].
//! - A flow-controlled receive window, for the credit it re-grants beyond its
//!   floor (HTTP/2 `release_capacity`, the WINDOW_UPDATEs it sends): a
//!   [`WindowGate`]. The credit a handshake grants (HTTP/2 SETTINGS, QUIC
//!   transport parameters) is the peer's as announced; only the timing of
//!   later credit moves.
//! - A QUIC connection's receive and send windows: a [`WindowLease`].
//!
//! Windows are held for as long as they are open, so their holders share `B`
//! between them ([`BudgetPermits::window`]): none takes more than
//! `B / (windows + 1)`, the windows holding bytes counted. The one share
//! over is left for what relays read and write, which moves through the
//! windows: a lone window takes half of `B`, and 32 windows take 32/33.

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
    /// Windows holding bytes now.
    pub windows: usize,
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
    windows: AtomicUsize,
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
            windows: AtomicUsize::new(0),
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
            windows: self.windows.load(Ordering::SeqCst),
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

    /// How much one window may hold: `B` shared by the windows holding
    /// bytes, this one counted, and one share more for the relays.
    fn window_share(&self, holding: bool) -> usize {
        let others = self.windows.load(Ordering::SeqCst);
        let windows = if holding { others } else { others + 1 };
        self.capacity() / (windows.max(1) + 1)
    }
}

/// Bytes one holder has taken from a budget; dropped, they go back.
#[derive(Debug)]
pub struct BudgetPermits<'b> {
    budget: &'b ByteBudget,
    held: usize,
    /// Held for as long as a window is open, and so counted among the
    /// windows that share `B`.
    window: bool,
}

impl<'b> BudgetPermits<'b> {
    /// Bytes held for a moment: a read and its write.
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self {
            budget,
            held: 0,
            window: false,
        }
    }

    /// Bytes held for as long as a window is open, which share `B` with the
    /// other windows: none grows past `B / (windows + 1)`, the windows
    /// holding bytes counted.
    pub fn window(budget: &'b ByteBudget) -> Self {
        Self {
            budget,
            held: 0,
            window: true,
        }
    }

    pub fn budget(&self) -> &'b ByteBudget {
        self.budget
    }

    pub fn held(&self) -> usize {
        self.held
    }

    /// Holds `bytes` if the budget has them: gives back what is held above
    /// `bytes` and takes what is missing as far as the budget (and, for a
    /// window, its share) allows. Never waits. Returns what is held.
    pub fn try_hold(&mut self, bytes: usize) -> usize {
        let target = if self.window && bytes > self.held {
            bytes.min(self.held.max(self.budget.window_share(self.held > 0)))
        } else {
            bytes
        };
        let before = self.held;
        if target > self.held {
            self.held += self.budget.take(target - self.held);
        } else if target < self.held {
            self.budget.give(self.held - target);
            self.held = target;
        }
        if self.window {
            match (before > 0, self.held > 0) {
                (false, true) => {
                    self.budget.windows.fetch_add(1, Ordering::SeqCst);
                }
                (true, false) => {
                    self.budget.windows.fetch_sub(1, Ordering::SeqCst);
                }
                _ => {}
            }
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

/// Paces the credit one flow-controlled receive window re-grants its peer.
///
/// A receive window's exposure is what the peer may still send plus what
/// was received and not yet taken by a reader: the bytes this window may
/// make the process hold. The credit a handshake granted is the peer's as
/// announced and outside the budget; as the reader takes bytes the window
/// owes the peer that much credit, and it hands credit back only while its
/// exposure stays within the floor and the bytes it holds of the budget. A
/// window that cannot hand back credit holds it until the budget has bytes
/// again ([`ByteBudget::wake_when_free`]): its peer pauses, which is the
/// backpressure.
#[derive(Debug)]
pub struct WindowGate<'b> {
    permits: BudgetPermits<'b>,
    owed: usize,
}

impl<'b> WindowGate<'b> {
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self {
            permits: BudgetPermits::window(budget),
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

    /// How much of the credit owed to hand back now, given the window's
    /// `exposure` (credit the peer still has, plus bytes received and not
    /// taken by a reader, not counting what is owed). The caller hands back
    /// exactly that much.
    ///
    /// The window holds bytes of the budget for the credit it granted, that
    /// is for its exposure beyond the floor once it has granted; credit the
    /// handshake granted is the peer's and holds none. Bytes taken for a
    /// grant that cannot be made go back at once.
    pub fn grant(&mut self, exposure: usize) -> usize {
        let floor = self.permits.budget().floor();
        let before = self.permits.held();
        let mut granted = 0;
        if self.owed > 0 {
            let wanted = exposure.saturating_add(self.owed).saturating_sub(floor);
            let held = self.permits.try_hold(wanted);
            granted = (floor + held).saturating_sub(exposure).min(self.owed);
        }
        let keep = if granted > 0 {
            exposure.saturating_add(granted).saturating_sub(floor)
        } else {
            before.min(exposure.saturating_sub(floor))
        };
        self.permits.try_hold(keep);
        self.owed -= granted;
        granted
    }

    /// Gives back the budget's bytes; the window is closed.
    pub fn close(&mut self) {
        self.owed = 0;
        self.permits.release();
    }
}

/// A QUIC connection's window, sized from the budget.
///
/// quinn keeps a connection's receive and send windows where they are set;
/// a lease holds bytes of the budget for the part of a window above the
/// floor while the connection moves data, and the window runs at the floor
/// plus what the lease holds, never above the window configured. An idle
/// connection gives its bytes back. The handshake's transport parameters
/// are unchanged: a smaller receive window only delays MAX_DATA.
#[derive(Debug)]
pub struct WindowLease<'b> {
    permits: BudgetPermits<'b>,
}

impl<'b> WindowLease<'b> {
    pub fn new(budget: &'b ByteBudget) -> Self {
        Self {
            permits: BudgetPermits::window(budget),
        }
    }

    pub fn held(&self) -> usize {
        self.permits.held()
    }

    /// The window to run for a connection whose configured window is
    /// `configured`, while it is `active` (moving data) or not.
    pub fn refresh(&mut self, configured: u64, active: bool) -> u64 {
        let floor = self.permits.budget().floor() as u64;
        let wanted = if active {
            usize::try_from(configured.saturating_sub(floor)).unwrap_or(usize::MAX)
        } else {
            0
        };
        let held = self.permits.try_hold(wanted) as u64;
        floor.saturating_add(held).min(configured)
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

    #[test]
    fn windows_share_the_budget() {
        let budget = budget(120 * KIB, 4 * KIB);
        let mut first = BudgetPermits::window(&budget);
        let mut second = BudgetPermits::window(&budget);
        let mut third = BudgetPermits::window(&budget);
        assert_eq!(
            first.try_hold(200 * KIB),
            60 * KIB,
            "alone it takes half: the other half is the relays'"
        );
        assert_eq!(second.try_hold(200 * KIB), 40 * KIB, "a third");
        assert_eq!(budget.usage().windows, 2);
        assert_eq!(third.try_hold(200 * KIB), 20 * KIB, "what is left of B");
        assert_eq!(budget.usage().windows, 3);
        // A window above its share keeps what it holds, but grows no more.
        assert_eq!(second.try_hold(70 * KIB), 40 * KIB);
        drop(third);
        second.release();
        assert_eq!(budget.usage().windows, 1);
        // A relay's bytes are not a window and are not shared out.
        let mut relay = BudgetPermits::new(&budget);
        assert_eq!(relay.try_hold(200 * KIB), 60 * KIB);
    }

    #[test]
    fn a_gate_hands_back_credit_only_within_the_floor_and_its_bytes() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut gate = WindowGate::new(&budget);
        // The handshake granted 1 MiB; a reader took 16 KiB of it. Handing
        // that back would expose 1 MiB again, all of it beyond the floor.
        gate.consumed(16 * KIB);
        let exposure = 1024 * KIB - 16 * KIB;
        assert_eq!(gate.grant(exposure), 0, "over B, so it waits");
        assert_eq!(gate.held(), 0, "the handshake's credit holds no bytes");
        assert_eq!(budget.in_use(), 0);
        // Most of the first window has been read: now it may grant again.
        gate.consumed(1000 * KIB);
        assert_eq!(gate.owed(), 1016 * KIB);
        let exposure = 8 * KIB;
        assert_eq!(
            gate.grant(exposure),
            28 * KIB,
            "the floor and its share of B, less what is out"
        );
        assert_eq!(gate.held(), 32 * KIB);
        assert_eq!(budget.in_use(), 32 * KIB);
        // The peer sent it and a reader took it: the exposure shrank, and
        // the bytes held for it go back as the credit is handed back again.
        gate.consumed(36 * KIB);
        assert_eq!(gate.grant(0), 36 * KIB);
        assert_eq!(gate.held(), 32 * KIB);
        gate.close();
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn a_gate_always_hands_back_its_floor() {
        // Another holder spent B: the gate still moves, a floor at a time.
        let budget = budget(64 * KIB, 4 * KIB);
        let mut other = BudgetPermits::new(&budget);
        other.try_hold(64 * KIB);
        let mut gate = WindowGate::new(&budget);
        gate.consumed(100 * KIB);
        assert_eq!(gate.grant(0), 4 * KIB);
        assert_eq!(gate.grant(4 * KIB), 0, "the floor is out");
        assert_eq!(gate.grant(KIB), 3 * KIB);
        assert_eq!(gate.held(), 0);
    }

    #[test]
    fn a_lease_runs_the_floor_plus_its_share_and_gives_it_back_when_idle() {
        let budget = budget(1200 * KIB, 4 * KIB);
        let mut lease = WindowLease::new(&budget);
        let configured = 3 * 1024 * 1024;
        assert_eq!(
            lease.refresh(configured, true),
            604 * KIB as u64,
            "the floor and half of B"
        );
        let mut other = WindowLease::new(&budget);
        assert_eq!(
            other.refresh(configured, true),
            404 * KIB as u64,
            "the floor and a third of B"
        );
        assert_eq!(lease.refresh(configured, false), 4 * KIB as u64);
        assert_eq!(lease.held(), 0);
        assert_eq!(other.refresh(configured, true), 604 * KIB as u64);
        assert_eq!(other.refresh(64 * KIB as u64, true), 64 * KIB as u64);
        assert_eq!(other.held(), 60 * KIB);
    }
}

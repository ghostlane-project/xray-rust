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
//! that a flow always moves even when `B` is spent and no relay can wait on
//! another for good. HTTP/2 streams are not held to that: they share their
//! connection's window, and a stream's credit can wait on other paused
//! streams' readers (below). The floor is the budget's overshoot: at hev's
//! 256 sessions, two directions each, it is 256 × 2 × 4 KiB = 2 MiB beyond
//! `B`.
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
//!   latest when its reader has taken the queue down to the floor. A gate
//!   that holds credit back is settled again by one task per budget whenever
//!   bytes come back while `B` has room, as they do when the gates' share of
//!   the windows' part falls, whether or not its reader reads again: its
//!   credit goes back at the first of those after that part, less what the
//!   other gates hold, covers its queue and `B` can hold it. Room in `B` is
//!   not enough. While other paused streams' queues hold the windows' part,
//!   a paused stream's credit waits on their readers, and a queue larger
//!   than the whole part waits on its own reader.
//!
//! The windows' part of `B` is what it leaves after a reserve for the relays
//! (`B / 8`, [`RELAY_RESERVE_DIVISOR`]): the gates together hold no more than
//! that part, so the reserve is always the relays', and queues beyond it get
//! no more credit until they drain. Handshake values (HTTP/2 SETTINGS, the first
//! connection WINDOW_UPDATE) are not touched: only when later credit goes
//! out moves. Hysteria2's QUIC windows are not counted: each connection keeps
//! the windows it announced (`HysteriaWindows`).

use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};

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

/// The part of `B` kept from the receive windows for the relays: an eighth. On a
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
    /// Bytes the receive gates hold, part of `in_use`.
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
    /// Bytes the receive gates hold, part of `in_use`.
    window_bytes: AtomicUsize,
    /// The gates listed in `withheld`; read before the lock is taken.
    withholding: AtomicUsize,
    /// Receive gates holding back credit their readers took, for the
    /// settler to settle again as bytes come back: each hands its credit
    /// back once it can hold its queue.
    withheld: Mutex<Withheld>,
    /// A settle round is due: set when bytes come back while gates are
    /// listed, cleared by the settler as a round begins.
    settle_due: AtomicBool,
    /// The settler's task while it waits for a round.
    settler: Mutex<Option<Waker>>,
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
            window_bytes: AtomicUsize::new(0),
            withholding: AtomicUsize::new(0),
            withheld: Mutex::new(Withheld {
                gates: Vec::new(),
                settling: false,
            }),
            settle_due: AtomicBool::new(false),
            settler: Mutex::new(None),
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
        // A larger budget may have room for a waiter now, or for a gate's
        // queue.
        self.serve(&mut self.lock_queue());
        if self.withholding.load(Ordering::SeqCst) != 0 {
            self.settle_soon();
        }
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
        } else {
            self.in_use.fetch_sub(bytes, Ordering::SeqCst);
            // A holder that began to wait after the check above has missed
            // these bytes, or else it found them free (`wait`).
            if self.waiting.load(Ordering::SeqCst) != 0 {
                self.serve(&mut self.lock_queue());
            }
        }
        self.settle_if_room();
    }

    /// Has the settler run a round if gates hold credit back and `B` holds no
    /// more than its capacity, as `grant` asks of a gate that holds its
    /// queue: after bytes come back, and after the gates' share of the
    /// windows' part falls. One load while no gate holds credit back, so
    /// the relays' path pays nothing more.
    fn settle_if_room(&self) {
        if self.withholding.load(Ordering::SeqCst) != 0 && self.in_use() <= self.capacity() {
            self.settle_soon();
        }
    }

    /// The bytes no holder has taken.
    pub fn free(&self) -> usize {
        self.capacity().saturating_sub(self.in_use())
    }

    /// The windows' part of `B`: what the receive gates may hold together,
    /// `B` less the relays' reserve.
    pub fn window_cap(&self) -> usize {
        let capacity = self.capacity();
        capacity - capacity / RELAY_RESERVE_DIVISOR
    }

    fn lock_queue(&self) -> MutexGuard<'_, VecDeque<Arc<Waiter>>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_withheld(&self) -> MutexGuard<'_, Withheld> {
        self.withheld.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_settler(&self) -> MutexGuard<'_, Option<Waker>> {
        self.settler.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lists `gate`, which holds back credit its reader took, for the settler
    /// to settle again whenever bytes come back while `B` has room, until it
    /// holds none back. Starts the settler, one task per budget, on the
    /// runtime of the caller; without a runtime the gate's own reader is
    /// left to settle it.
    pub fn list_withheld(&'static self, gate: Weak<dyn WithheldCredit>) {
        let start = {
            let mut withheld = self.lock_withheld();
            withheld.gates.push(gate);
            self.withholding
                .store(withheld.gates.len(), Ordering::SeqCst);
            !std::mem::replace(&mut withheld.settling, true)
        };
        // `B` may have had room again before the gate was listed, when no
        // give could see it: a round now.
        self.settle_soon();
        if start {
            // The guard goes with the task: dropped unpolled, or with its
            // runtime, it lets the next gate listed start a settler again.
            let running = Settling(self);
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => drop(runtime.spawn(settle_withheld(running))),
                Err(_) => drop(running),
            }
        }
    }

    /// Has the settler run a round.
    fn settle_soon(&self) {
        if self.settle_due.swap(true, Ordering::SeqCst) {
            return;
        }
        let waker = self.lock_settler().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Ready once a round is due, which it clears.
    fn poll_settle_due(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut settler = self.lock_settler();
        if self.settle_due.swap(false, Ordering::SeqCst) {
            return Poll::Ready(());
        }
        if !settler
            .as_ref()
            .is_some_and(|waker| waker.will_wake(cx.waker()))
        {
            *settler = Some(cx.waker().clone());
        }
        Poll::Pending
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

/// A receive gate that holds back credit its reader took: settled again from
/// outside its reader as bytes come back, so the credit goes back once the
/// gate can hold its queue whether or not the reader reads again
/// ([`ByteBudget::list_withheld`]). Public for xray-transport's HTTP/2
/// gates (`stream/h2_budget.rs`), which list themselves.
pub trait WithheldCredit: Send + Sync {
    /// Settles the gate against what its stream holds now, and hands back
    /// the credit that grants.
    fn settle(&self);
    /// Whether the gate still holds credit back. One that does not leaves
    /// the list, and is listed again when it next holds some back.
    fn still_withheld(&self) -> bool;
}

/// The gates a budget's settler settles.
struct Withheld {
    gates: Vec<Weak<dyn WithheldCredit>>,
    /// The settler's task is running.
    settling: bool,
}

impl std::fmt::Debug for Withheld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Withheld")
            .field("gates", &self.gates.len())
            .field("settling", &self.settling)
            .finish()
    }
}

/// A budget's settler is running; dropped, it is not.
struct Settling(&'static ByteBudget);

impl Drop for Settling {
    fn drop(&mut self) {
        self.0.lock_withheld().settling = false;
    }
}

/// The settler: one task per budget, on the runtime of the gate whose
/// listing started it, while gates are listed. Each round settles every
/// listed gate and keeps those that still hold credit back; it ends once
/// none does, and a gate listed later starts it again. A round runs when
/// bytes come back while `B` has room, so it never runs on the relays'
/// path; it waits for nothing and goes back to the scheduler between any
/// two rounds: one runtime worker serves it, and no chain of rounds holds
/// one.
async fn settle_withheld(running: Settling) {
    let budget = running.0;
    let mut settled = false;
    loop {
        // Waiting for a round gives the worker back. A round due already
        // when the last ends, as gives on other workers during it make one,
        // yields first: a chain of them never holds the worker, and a
        // settler with nothing due costs no extra poll.
        let mut first_poll = true;
        let waited = poll_fn(|cx| {
            let first = std::mem::take(&mut first_poll);
            budget.poll_settle_due(cx).map(|()| !first)
        })
        .await;
        if settled && !waited {
            tokio::task::yield_now().await;
        }
        settled = true;
        let gates: Vec<Arc<dyn WithheldCredit>> = budget
            .lock_withheld()
            .gates
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for gate in &gates {
            gate.settle();
        }
        drop(gates);
        let mut withheld = budget.lock_withheld();
        withheld
            .gates
            .retain(|gate| gate.upgrade().is_some_and(|gate| gate.still_withheld()));
        budget
            .withholding
            .store(withheld.gates.len(), Ordering::SeqCst);
        if withheld.gates.is_empty() {
            // Cleared here, under the lock that lists gates, not by the
            // guard after it: a gate listed meanwhile starts a settler.
            withheld.settling = false;
            drop(withheld);
            std::mem::forget(running);
            return;
        }
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
/// unless the queue holds more than the floor and the gate cannot hold it:
/// then the credit waits until the windows' part of `B`, less what the
/// other gates hold, covers the queue and `B` can hold it, at the latest
/// until the reader has taken the queue down to the floor, and a peer that
/// outruns a pressed process pauses on its window. The reader's next read
/// decides again, and so does the budget's settler, a task that settles
/// every gate holding credit back whenever bytes come back while `B` has
/// room, whether or not its reader reads; no gate and no reader waits in
/// the budget's queue. Until then, the credit a paused reader took and its
/// gate holds back still counts in the connection's window, so the
/// connection's other streams can wait on it, up to the stream's window.
/// Room in `B` is not enough: while other paused streams' queues hold the
/// windows' part, a paused stream's credit waits on their readers, and a
/// queue larger than the whole part waits on its own reader.
///
/// A gate holds at most the windows' part of `B`
/// ([`ByteBudget::window_cap`]) less what the other gates hold, so the
/// relays' reserve stays theirs whatever the queues hold; a queue beyond what
/// its gate may hold gets no credit until it drains.
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
    /// back now: all of it while the gate may hold the queue beyond the
    /// floor, none while it may not, nor while the budget holds more than a
    /// lowered capacity: then queues beyond the floor drain before their
    /// peers may send more, and what they hold comes back.
    ///
    /// The gate may hold what the windows' part of `B` leaves beside the
    /// other gates and what `B` has free; it holds that much of a queue
    /// beyond it, and no more.
    pub fn grant(&mut self, queued: usize) -> usize {
        let budget = self.permits.budget();
        let need = queued.saturating_sub(budget.floor());
        let before = self.permits.held();
        if need == 0 && before == 0 {
            // A stream that keeps up: nothing to hold, nothing to claim.
            return std::mem::take(&mut self.owed);
        }
        let cap = budget.window_cap();
        let mut windows = budget.window_bytes.load(Ordering::SeqCst);
        let held = loop {
            let others = windows.saturating_sub(before);
            let claim = need.min(cap.saturating_sub(others));
            if claim <= before {
                // Less to hold: the bytes go back to `B` before the gate's
                // share of the windows' part, so the gates never hold more
                // than that part, not even for a moment.
                if claim < before {
                    self.permits.try_hold(claim);
                    budget
                        .window_bytes
                        .fetch_sub(before - claim, Ordering::SeqCst);
                    budget.settle_if_room();
                }
                break claim;
            }
            // More to hold: the room is claimed among the gates before `B`
            // is asked, so two gates cannot both take the same part of it.
            match budget.window_bytes.compare_exchange_weak(
                windows,
                others + claim,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    let held = self.permits.try_hold(claim);
                    if held < claim {
                        // `B` had less free: the relays hold the rest.
                        budget
                            .window_bytes
                            .fetch_sub(claim - held, Ordering::SeqCst);
                    }
                    break held;
                }
                Err(current) => windows = current,
            }
        };
        if held < need || (need > 0 && budget.in_use() > budget.capacity()) {
            return 0;
        }
        std::mem::take(&mut self.owed)
    }

    /// Gives back the budget's bytes; the window is closed.
    pub fn close(&mut self) {
        self.owed = 0;
        let held = self.permits.held();
        // The bytes first, then the share, as in `grant`.
        self.permits.release();
        let budget = self.permits.budget();
        budget.window_bytes.fetch_sub(held, Ordering::SeqCst);
        budget.settle_if_room();
    }
}

impl Drop for ReceiveGate<'_> {
    fn drop(&mut self) {
        self.close();
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
    fn a_queue_beyond_the_windows_part_gets_no_credit_and_leaves_the_relays_reserve() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut gate = ReceiveGate::new(&budget);
        gate.consumed(8 * KIB);
        // 60 KiB beyond the floor, past the windows' 56 KiB: the gate holds
        // 56 of them and the peer gets no more until the queue drains.
        assert_eq!(gate.grant(64 * KIB), 0);
        assert_eq!(gate.held(), 56 * KIB);
        assert_eq!(budget.usage().window_bytes, 56 * KIB);
        // With the queue still above the windows' part, a relay takes the
        // reserve: 8 KiB of B beyond its floor.
        let mut relay = BudgetPermits::new(&budget);
        assert_eq!(relay.try_hold(16 * KIB), 8 * KIB, "B / 8 is the relays'");
        assert_eq!(gate.grant(64 * KIB), 0, "the queue still waits");
        assert_eq!(budget.in_use(), 64 * KIB);
        gate.consumed(8 * KIB);
        assert_eq!(
            gate.grant(56 * KIB),
            16 * KIB,
            "52 KiB fit the windows' part"
        );
        assert_eq!(relay.held(), 8 * KIB);
        drop(gate);
        assert_eq!(budget.usage().window_bytes, 0, "a dropped gate gives back");
        assert_eq!(budget.in_use(), 8 * KIB);
    }

    #[test]
    fn gates_share_the_windows_part_and_never_hold_the_reserve() {
        let budget = budget(64 * KIB, 4 * KIB);
        let mut first = ReceiveGate::new(&budget);
        let mut second = ReceiveGate::new(&budget);
        first.consumed(KIB);
        second.consumed(KIB);
        assert_eq!(first.grant(44 * KIB), KIB, "40 KiB of the windows' 56");
        assert_eq!(
            second.grant(24 * KIB),
            0,
            "20 KiB beyond the floor, 16 left"
        );
        assert_eq!(second.held(), 16 * KIB);
        assert_eq!(budget.usage().window_bytes, 56 * KIB);
        assert_eq!(budget.free(), 8 * KIB, "the relays' reserve is free");
        // The first's reader takes its queue down: the second's fits again.
        assert_eq!(first.grant(4 * KIB), 0, "nothing more owed");
        assert_eq!(first.held(), 0);
        assert_eq!(second.grant(24 * KIB), KIB);
        assert_eq!(second.held(), 20 * KIB);
        drop(first);
        drop(second);
        assert_eq!(budget.usage().window_bytes, 0);
        assert_eq!(budget.in_use(), 0);
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
        assert_eq!(
            gate.grant(28 * KIB),
            0,
            "B is spent: the queue drains first"
        );
        assert_eq!(
            gate.held(),
            14 * KIB,
            "it holds no more than the new windows' part"
        );
        gate.consumed(16 * KIB);
        assert_eq!(gate.grant(12 * KIB), 24 * KIB, "within the new B again");
        assert_eq!(budget.in_use(), 8 * KIB);
        gate.close();
        assert_eq!(budget.in_use(), 0);
    }

    /// A gate a test lists: counts its rounds, holds credit back while told.
    struct CountingGate {
        settled: AtomicUsize,
        withheld: AtomicBool,
    }

    impl WithheldCredit for CountingGate {
        fn settle(&self) {
            self.settled.fetch_add(1, Ordering::SeqCst);
        }

        fn still_withheld(&self) -> bool {
            self.withheld.load(Ordering::SeqCst)
        }
    }

    impl CountingGate {
        fn settled(&self) -> usize {
            self.settled.load(Ordering::SeqCst)
        }
    }

    /// Lets the settler, on this runtime's one thread, run what is due.
    async fn let_the_settler_run() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn the_settler_settles_listed_gates_once_bytes_come_back_and_never_on_the_givers_path() {
        let budget: &'static ByteBudget = Box::leak(Box::new(budget(64 * KIB, 4 * KIB)));
        let mut relay = BudgetPermits::new(budget);
        assert_eq!(relay.try_hold(64 * KIB), 64 * KIB);
        let gate = Arc::new(CountingGate {
            settled: AtomicUsize::new(0),
            withheld: AtomicBool::new(true),
        });
        let listed: Weak<CountingGate> = Arc::downgrade(&gate);
        budget.list_withheld(listed as Weak<dyn WithheldCredit>);
        assert_eq!(gate.settled(), 0, "a listing settles nothing itself");
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 1, "a listing has a round run");
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 1, "no round without bytes coming back");

        relay.try_hold(60 * KIB);
        assert_eq!(gate.settled(), 1, "a give settles nothing itself");
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 2, "bytes came back with room: a round");

        relay.try_hold(56 * KIB);
        relay.try_hold(52 * KIB);
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 3, "gives before a round make one round");

        // A gate that holds nothing back leaves the list; the settler ends.
        gate.withheld.store(false, Ordering::SeqCst);
        relay.try_hold(48 * KIB);
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 4);
        assert_eq!(budget.withholding.load(Ordering::SeqCst), 0);
        assert!(!budget.lock_withheld().settling, "the settler ended");
        relay.try_hold(44 * KIB);
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 4, "no round with no gate listed");

        // Listed again, it starts a settler again.
        gate.withheld.store(true, Ordering::SeqCst);
        let listed: Weak<CountingGate> = Arc::downgrade(&gate);
        budget.list_withheld(listed as Weak<dyn WithheldCredit>);
        let_the_settler_run().await;
        assert_eq!(gate.settled(), 5);

        // A gate dropped while listed leaves the list at the next round.
        drop(gate);
        relay.try_hold(40 * KIB);
        let_the_settler_run().await;
        assert_eq!(budget.withholding.load(Ordering::SeqCst), 0);
        assert!(!budget.lock_withheld().settling, "the settler ended");
    }

    /// A gate that holds all its queue withholds while `B` holds more than a
    /// lowered capacity, and grants once `B` holds no more than it: a give
    /// that brings `B` down to that capacity, not below it, has a round run.
    #[tokio::test]
    async fn a_give_down_to_a_lowered_capacity_has_the_settler_run_a_round() {
        let budget: &'static ByteBudget = Box::leak(Box::new(budget(64 * KIB, 4 * KIB)));
        let mut gate = ReceiveGate::new(budget);
        assert_eq!(
            gate.grant(4 * KIB + 16 * KIB),
            0,
            "nothing read, nothing owed"
        );
        assert_eq!(gate.held(), 16 * KIB, "the gate holds its queue");
        gate.consumed(8 * KIB);
        let mut relay = BudgetPermits::new(budget);
        assert_eq!(relay.try_hold(48 * KIB), 48 * KIB);
        budget.set(Some(ByteBudgetSettings {
            capacity: 48 * KIB,
            floor: 4 * KIB,
        }));
        assert_eq!(
            gate.grant(4 * KIB + 16 * KIB),
            0,
            "B holds more than its capacity"
        );
        let listed = Arc::new(CountingGate {
            settled: AtomicUsize::new(0),
            withheld: AtomicBool::new(true),
        });
        let weak: Weak<CountingGate> = Arc::downgrade(&listed);
        budget.list_withheld(weak as Weak<dyn WithheldCredit>);
        let_the_settler_run().await;
        assert_eq!(listed.settled(), 1, "a listing has a round run");

        relay.try_hold(32 * KIB);
        assert_eq!(budget.in_use(), budget.capacity(), "B holds its capacity");
        let_the_settler_run().await;
        assert_eq!(
            listed.settled(),
            2,
            "bytes came back down to the capacity: a round"
        );
        assert_eq!(
            gate.grant(4 * KIB + 16 * KIB),
            8 * KIB,
            "which hands the credit back"
        );
        gate.close();
    }

    /// A gate that has the next round made due while it is settled, as gives
    /// on other workers do while a round runs, for `rounds` rounds.
    struct RearmingGate {
        budget: &'static ByteBudget,
        settled: AtomicUsize,
        rounds: usize,
    }

    impl WithheldCredit for RearmingGate {
        fn settle(&self) {
            if self.settled.fetch_add(1, Ordering::SeqCst) + 1 < self.rounds {
                self.budget.settle_soon();
            }
        }

        fn still_withheld(&self) -> bool {
            self.settled.load(Ordering::SeqCst) < self.rounds
        }
    }

    /// Rounds due one after another give the worker back between them: on a
    /// runtime of one thread, a chain of them leaves the other tasks their
    /// turns rather than run to its end in one poll.
    #[tokio::test]
    async fn the_settler_gives_its_worker_back_after_every_round() {
        const ROUNDS: usize = 1000;
        let budget: &'static ByteBudget = Box::leak(Box::new(budget(64 * KIB, 4 * KIB)));
        let gate = Arc::new(RearmingGate {
            budget,
            settled: AtomicUsize::new(0),
            rounds: ROUNDS,
        });
        let weak: Weak<RearmingGate> = Arc::downgrade(&gate);
        budget.list_withheld(weak as Weak<dyn WithheldCredit>);
        tokio::task::yield_now().await;
        let settled = gate.settled.load(Ordering::SeqCst);
        assert!(
            (1..ROUNDS).contains(&settled),
            "the settler ran {settled} of the {ROUNDS} rounds due before this task's next turn"
        );
        // A guard, not a measure: a chain that never ends fails here.
        for _ in 0..4 * ROUNDS {
            let settling = budget.lock_withheld().settling;
            if !settling {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            gate.settled.load(Ordering::SeqCst),
            ROUNDS,
            "every round due ran"
        );
        assert!(!budget.lock_withheld().settling, "the settler ended");
    }

    #[test]
    fn concurrent_gates_and_relays_stay_within_the_budget_and_end_holding_nothing() {
        let budget = budget(64 * KIB, 4 * KIB);
        let cap = budget.window_cap();
        let done = AtomicUsize::new(0);
        let worst_windows = AtomicUsize::new(0);
        let worst_in_use = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for seed in 0..4u64 {
                let (budget, done) = (&budget, &done);
                scope.spawn(move || {
                    let mut x = seed.wrapping_mul(6_364_136_223_846_793_005) | 1;
                    let mut next = move || {
                        x = x
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        (x >> 33) as usize
                    };
                    for _ in 0..50 {
                        let mut gate = ReceiveGate::new(budget);
                        for _ in 0..200 {
                            gate.consumed(next() % (8 * KIB));
                            gate.grant(next() % (80 * KIB));
                            assert!(gate.held() <= cap);
                        }
                        if next() % 2 == 0 {
                            gate.close();
                        }
                    }
                    done.fetch_add(1, Ordering::SeqCst);
                });
            }
            for seed in 10..12u64 {
                let (budget, done) = (&budget, &done);
                scope.spawn(move || {
                    let mut x = seed;
                    let mut relay = BudgetPermits::new(budget);
                    for _ in 0..20_000 {
                        x = x
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        relay.try_hold(((x >> 33) as usize) % (32 * KIB));
                    }
                    done.fetch_add(1, Ordering::SeqCst);
                });
            }
            let (budget, done) = (&budget, &done);
            let (worst_windows, worst_in_use) = (&worst_windows, &worst_in_use);
            scope.spawn(move || {
                while done.load(Ordering::SeqCst) < 6 {
                    let usage = budget.usage();
                    worst_windows.fetch_max(usage.window_bytes, Ordering::SeqCst);
                    worst_in_use.fetch_max(usage.in_use, Ordering::SeqCst);
                    std::thread::yield_now();
                }
            });
        });
        let usage = budget.usage();
        assert!(worst_windows.load(Ordering::SeqCst) <= cap, "{usage:?}");
        assert!(worst_in_use.load(Ordering::SeqCst) <= 64 * KIB, "{usage:?}");
        assert_eq!(usage.window_bytes, 0);
        assert_eq!(usage.in_use, 0);
    }
}

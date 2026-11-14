//! What the core's relays hold, counted by this binary's allocator.
//!
//! The core runs on a runtime of its own whose threads are counted; the
//! far ends of its flows (SOCKS clients, a TLS VLESS Vision server, a sink)
//! run on another whose threads are not, and the two meet only through
//! loopback sockets. The tests take turns: there is one allocator and one
//! process-wide byte budget.
//!
//! Every test prints its numbers (`--nocapture`).

#[path = "relay_memory/support.rs"]
mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use support::KIB;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static COUNTED: Cell<bool> = const { Cell::new(false) };
}

fn counted() -> bool {
    COUNTED.try_with(Cell::get).unwrap_or(false)
}

fn count(delta: isize) {
    let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    if delta > 0 {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: every call goes to `System` unchanged; the counters only watch.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && counted() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() && counted() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        if counted() {
            count(-(layout.size() as isize));
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() && counted() {
            count(new_size as isize - layout.size() as isize);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn count_this_thread() {
    COUNTED.with(|counted| counted.set(true));
}

fn leave_this_thread() {}

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// Starts the peak again from what is live now.
fn reset_peak() -> isize {
    let now = live();
    PEAK.store(now, Ordering::Relaxed);
    now
}

fn peak() -> isize {
    PEAK.load(Ordering::Relaxed)
}

static TURN: Mutex<()> = Mutex::new(());

fn take_turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The byte budget a constrained (phone) core runs with: 200 Mbit/s over
/// 120 ms, `xray_transport::memory_budget`'s default for its class. Written
/// out so that the test reads the same against a core without a budget.
const CONSTRAINED_BUDGET: isize = 3_000_000;
/// What a flow may hold beside the budget: its relay floors, its TLS
/// session and its Vision state.
const PER_FLOW: isize = 16 * KIB as isize;
/// The free relay buffers a constrained process keeps.
const CONSTRAINED_POOL_KEEP: isize = 4 * 128 * KIB as isize;

/// T4: 32 Vision flows over TLS, a MiB down each and then a MiB up each,
/// all at once, the uploads to a server that takes them at a phone's pace:
/// the core holds no more than the budget and a little per flow above what
/// it holds idle.
#[test]
fn thirty_two_vision_flows_hold_the_budget_and_little_more() {
    const FLOWS: usize = 32;
    let _turn = take_turn();
    let far = support::runtime(2, leave_this_thread);
    let near = support::runtime(2, count_this_thread);
    let (server, client_config) = far.block_on(support::start_vision_server(support::Uplink::Slow));
    let mut core =
        near.block_on(async { support::vision_core(server, client_config, support::Uplink::Slow) });
    near.block_on(core.start()).unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    let mut flows = far.block_on(futures_join_all(
        (0..FLOWS).map(|_| support::open_vision_flow(socks)),
    ));
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    let idle = reset_peak();

    far.block_on(futures_join_all(flows.iter_mut().map(support::download)));
    let download_peak = peak() - idle;
    far.block_on(futures_join_all(flows.iter_mut().map(support::upload)));
    let peak_over_idle = peak() - idle;
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    let after = live() - idle;

    let bound = CONSTRAINED_BUDGET + FLOWS as isize * PER_FLOW;
    eprintln!(
        "T4 {FLOWS} Vision flows: idle {idle} B ({} B a flow), peak over idle {peak_over_idle} B \
         (download alone {download_peak} B), {after} B more than idle after, bound {bound} B",
        idle / FLOWS as isize
    );
    drop(flows);
    near.block_on(core.stop()).unwrap();
    assert!(
        peak_over_idle <= bound,
        "the flows held {peak_over_idle} B over idle; the bound is {bound} B"
    );
}

/// T5: 1,000 SOCKS flows, each sending 256 KiB, opened and closed 50 at a
/// time: once they are gone the core holds what it held before, give or
/// take the free buffers its relays keep.
#[test]
fn a_thousand_closed_flows_leave_the_core_where_it_was() {
    const FLOWS: usize = 1000;
    const AT_ONCE: usize = 50;
    let _turn = take_turn();
    let far = support::runtime(2, leave_this_thread);
    let near = support::runtime(2, count_this_thread);
    let sink = far.block_on(support::start_sink());
    let mut core = near.block_on(async { support::direct_core() });
    near.block_on(core.start()).unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    // As many flows at once, a byte each: the runtimes' and the core's
    // tables grow to them, the relay buffers do not.
    far.block_on(futures_join_all((0..AT_ONCE).map(|_| async move {
        let stream = support::socks_connect(socks, sink).await;
        support::send_and_close(stream, 1).await;
    })));
    settle(&far, &core);
    let baseline = live();

    for _ in 0..FLOWS / AT_ONCE {
        far.block_on(futures_join_all((0..AT_ONCE).map(|_| async move {
            let stream = support::socks_connect(socks, sink).await;
            support::send_and_close(stream, 256 * KIB).await;
        })));
    }
    settle(&far, &core);
    let retained = live() - baseline;
    eprintln!(
        "T5 {FLOWS} flows of 256 KiB: baseline {baseline} B, retained {retained} B, \
         bound {CONSTRAINED_POOL_KEEP} B"
    );
    near.block_on(core.stop()).unwrap();
    assert!(
        retained <= CONSTRAINED_POOL_KEEP,
        "closed flows left {retained} B behind; the pool keeps at most {CONSTRAINED_POOL_KEEP} B"
    );
}

/// T8: a task whose future holds nothing costs the runtime at most 128 bytes.
#[test]
fn a_task_with_no_state_costs_at_most_128_bytes() {
    const TASKS: usize = 1000;
    let _turn = take_turn();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut handles = Vec::with_capacity(TASKS);
    let per_task = runtime.block_on(async {
        // Once first, so the run queue has room for them all.
        for _ in 0..TASKS {
            handles.push(tokio::spawn(std::future::pending::<()>()));
        }
        tokio::task::yield_now().await;
        for handle in handles.drain(..) {
            handle.abort();
        }
        tokio::task::yield_now().await;

        count_this_thread();
        let before = live();
        for _ in 0..TASKS {
            handles.push(tokio::spawn(std::future::pending::<()>()));
        }
        tokio::task::yield_now().await;
        let per_task = (live() - before) / TASKS as isize;
        COUNTED.with(|counted| counted.set(false));
        for handle in handles.drain(..) {
            handle.abort();
        }
        per_task
    });
    eprintln!("T8 a task with no state: {per_task} B");
    assert!(per_task <= 128, "a task with no state took {per_task} B");
}

/// Waits for the core's flows to be gone and their tasks to end.
fn settle(far: &tokio::runtime::Runtime, core: &xray_core_rs::Core) {
    far.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !core.connection_snapshot().connections.is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "flows stayed open");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
}

/// Runs the futures together on the calling task.
async fn futures_join_all<F: std::future::Future>(
    futures: impl IntoIterator<Item = F>,
) -> Vec<F::Output> {
    let mut pending: Vec<_> = futures
        .into_iter()
        .map(|future| Some(Box::pin(future)))
        .collect();
    let mut outputs: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for (slot, output) in pending.iter_mut().zip(outputs.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => {
                        *output = Some(value);
                        *slot = None;
                    }
                    std::task::Poll::Pending => done = false,
                }
            }
        }
        if done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    outputs
        .into_iter()
        .map(|output| output.expect("every future finished"))
        .collect()
}

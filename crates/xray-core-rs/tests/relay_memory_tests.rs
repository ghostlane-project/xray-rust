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

/// T4's budget: a third of a phone's 3 MB, so that 64 flows want more of it
/// than it has (about 4 MB measured).
const T4_BUDGET: usize = 1_000_000;
/// What a flow may hold beside the budget: its two relay directions'
/// 4 KiB floors.
const PER_FLOW: isize = 8 * KIB as isize;
/// What a TLS 1.3 record carries beyond the plaintext the budget counts as
/// unflushed: a 5-byte header, the content type and a 16-byte tag.
const TLS_RECORD_FRAMING: isize = 22;
/// The smallest record T4's uploads write: a relay's smallest read, 1 KiB
/// (`MIN_COPY_BUFFER_SIZE`). The far client is always ahead of the slow
/// server, so each read fills its buffer, all but a flow's last.
const SMALLEST_RECORD: isize = KIB as isize;
/// What a TLS session's receive side holds while a download moves, beyond
/// what it holds idle, none of it the budget's: rustls's deframer grows from
/// its 4 KiB read size to a whole record on the wire (`MAX_WIRE_SIZE`,
/// 16,384 + 2,048 + 5 bytes), and the plaintext it decrypts waits up to its
/// 16 KiB limit and one record more.
const TLS_RECEIVE: isize = (18_437 - 4 * KIB as isize) + 2 * 16 * KIB as isize;
/// The packets of a flow Vision pads (`VisionStream`'s `packets_to_filter`).
/// While it pads, it copies each write with its padding, up to 64 KiB and
/// the padding, and the copy is not the budget's.
const VISION_PADDED_PACKETS: usize = 8;
/// The free relay buffers a constrained process keeps.
const CONSTRAINED_POOL_KEEP: isize = 4 * 128 * KIB as isize;

/// What one run of `flows` Vision flows held, in bytes.
#[derive(Debug, Clone, Copy)]
struct Run {
    idle: isize,
    /// The downloads' peak over idle.
    download: isize,
    /// What the flows held over idle once the downloads were done.
    moving: isize,
    /// The uploads' peak over `moving`.
    upload: isize,
    after: isize,
    /// The uploads' peak of permits.
    budget_peak: usize,
}

/// `flows` Vision flows over TLS, past Vision's padding, a MiB down each and
/// then a MiB up each, all at once, the uploads to a server that takes them
/// at a phone's pace, under the byte budget the process has now.
fn vision_flows(flows: usize) -> Run {
    let far = support::runtime(2, leave_this_thread);
    let near = support::runtime(2, count_this_thread);
    let (server, client_config) = far.block_on(support::start_vision_server(support::Uplink::Slow));
    let mut core =
        near.block_on(async { support::vision_core(server, client_config, support::Uplink::Slow) });
    near.block_on(core.start()).unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    let mut streams = far.block_on(futures_join_all(
        (0..flows).map(|_| support::open_vision_flow(socks)),
    ));
    far.block_on(futures_join_all(
        streams
            .iter_mut()
            .map(|stream| support::ping(stream, VISION_PADDED_PACKETS)),
    ));
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    let idle = reset_peak();

    far.block_on(futures_join_all(streams.iter_mut().map(support::download)));
    let download = peak() - idle;
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    let moving = reset_peak();
    xray_transport::reset_byte_budget_peak();
    far.block_on(futures_join_all(streams.iter_mut().map(support::upload)));
    let upload = peak() - moving;
    let budget_peak = xray_transport::byte_budget_usage().peak;
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    let after = live() - idle;
    drop(streams);
    near.block_on(core.stop()).unwrap();
    Run {
        idle,
        download,
        moving: moving - idle,
        upload,
        after,
        budget_peak,
    }
}

/// T4: 64 Vision flows over TLS, a MiB down each and then a MiB up each,
/// all at once, the uploads to a server that takes them at a phone's pace.
///
/// The uploads press the budget. Above what the flows held once the
/// downloads were done, the core holds no more than the budget, the flows'
/// floors and the TLS framing of the records those bytes wait in; their
/// relay buffers come from those the pool kept from the downloads. The same
/// uploads with no limit take more than that (2.5-3.1 MB here, and 4 MB of
/// permits), so the bound holds because of the budget, not beside it.
///
/// The downloads leave the budget little to do, since the far reader keeps
/// up. What they hold above idle is mostly each TLS session's receive side,
/// which the budget does not count, so they are held to the budget, the
/// floors and that.
///
/// The flows are measured past Vision's padding: pings take each of them
/// through the packets Vision pads, whose writes it copies outside the
/// budget.
#[test]
fn sixty_four_vision_flows_hold_the_budget_and_their_floors() {
    const FLOWS: usize = 64;
    let _turn = take_turn();
    let flows = FLOWS as isize;
    let held = T4_BUDGET as isize + flows * PER_FLOW;
    let upload_bound = held + TLS_RECORD_FRAMING * (held / SMALLEST_RECORD + flows);
    let download_bound = held + flows * TLS_RECEIVE;
    let budget = |capacity| {
        xray_transport::set_byte_budget(Some(xray_transport::ByteBudgetSettings {
            capacity,
            floor: xray_transport::memory_budget::DEFAULT_FLOW_FLOOR,
        }));
    };
    budget(usize::MAX / 2);
    let unlimited = vision_flows(FLOWS);
    budget(T4_BUDGET);
    let limited = vision_flows(FLOWS);
    xray_transport::set_byte_budget(None);
    for (arm, run) in [("no limit", unlimited), ("B = 1 MB", limited)] {
        eprintln!(
            "T4 {FLOWS} Vision flows, {arm}: idle {} B ({} B a flow); download {} B over \
             idle, bound {download_bound} B; upload {} B over the {} B the flows held after \
             the downloads, bound {upload_bound} B, {} B of permits at most; {} B more than \
             idle after",
            run.idle,
            run.idle / flows,
            run.download,
            run.upload,
            run.moving,
            run.budget_peak,
            run.after
        );
    }
    assert!(
        unlimited.budget_peak > 2 * T4_BUDGET && unlimited.upload > upload_bound,
        "without a limit the uploads took {} B and {} B of permits: the test no longer \
         presses the budget",
        unlimited.upload,
        unlimited.budget_peak
    );
    assert!(
        limited.upload <= upload_bound,
        "the uploads held {} B over what the flows held before them; the bound is \
         {upload_bound} B",
        limited.upload
    );
    assert!(
        limited.download <= download_bound,
        "the downloads held {} B over idle; the bound is {download_bound} B",
        limited.download
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

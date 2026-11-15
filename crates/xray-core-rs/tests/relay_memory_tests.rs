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
/// What a flow may hold beside the budget while it moves bytes one way: the
/// 4 KiB floor of the relay direction that moves them. The other direction
/// waits for a read and holds no buffer meanwhile.
const FLOOR: isize = xray_transport::memory_budget::DEFAULT_FLOW_FLOOR as isize;
/// What a TLS 1.3 record carries beyond the plaintext the budget counts as
/// unflushed: a 5-byte header, the content type and a 16-byte tag.
const TLS_RECORD_FRAMING: isize = 22;
/// The smallest record T4's uploads write: a relay's smallest read, 1 KiB
/// (`MIN_COPY_BUFFER_SIZE`). The far client is always ahead of the slow
/// server, so each read fills its buffer, all but a flow's last.
const SMALLEST_RECORD: isize = KIB as isize;
/// The most a record takes on the wire: rustls's `MAX_WIRE_SIZE`, 16,384 B
/// of plaintext, 2,048 B of expansion and a 5-byte header.
const MAX_WIRE_SIZE: isize = 16_384 + 2_048 + 5;
/// What rustls's deframer holds while a read is pending: its read size.
const DEFRAMER_READ: isize = 4_096;
/// What a TLS session's receive side may hold while a download moves, beyond
/// what it holds idle, none of it the budget's: 32,778 B. The deframer grows
/// from `DEFRAMER_READ` straight to `MAX_WIRE_SIZE` once part of a record
/// waits in it, 14,341 B more. tokio-rustls 0.26 reads TLS only while no
/// plaintext waits, so the plaintext that waits is what one fill of the
/// deframer decrypts, less than `MAX_WIRE_SIZE`: 18,437 B.
const TLS_RECEIVE: isize = (MAX_WIRE_SIZE - DEFRAMER_READ) + MAX_WIRE_SIZE;
/// A constrained host's largest relay read, which T4's core makes (it sets
/// no `bufferSize`).
const CONSTRAINED_READ: isize = 32 * KIB as isize;
/// The worker threads of the core's runtime (`near`).
const CORE_WORKERS: usize = 2;
/// What the core's `CORE_WORKERS` workers may keep once
/// `release_relay_buffers` has freed the pool's lists: each the buffer it
/// got back last, at most a `CONSTRAINED_READ`.
const THREAD_SPARES: isize = CORE_WORKERS as isize * CONSTRAINED_READ;
/// The flows `quiesce` pings, so that each worker relays and its spare from
/// before the release goes; the rest keep what the run left them.
const QUIESCE_FLOWS: usize = 8;
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
    /// The downloads' peak of permits.
    download_permits: usize,
    /// What the flows held over idle once the downloads were done.
    moving: isize,
    /// The uploads' peak over `moving`.
    upload: isize,
    /// The uploads' peak of permits.
    upload_permits: usize,
    /// What the flows held over idle 300 ms after the uploads.
    after: isize,
}

/// `flows` Vision flows over TLS, past Vision's padding, a MiB down each and
/// then a MiB up each, all at once, the downloads read and the uploads taken
/// at a phone's pace, under the byte budget the process has now. Idle and
/// the end are taken quiesced, so that the buffers kept for later reads
/// count at neither.
fn vision_flows(flows: usize) -> Run {
    let far = support::runtime(2, leave_this_thread);
    let near = support::runtime(CORE_WORKERS, count_this_thread);
    let (server, client_config) = far.block_on(support::start_vision_server(support::Uplink::Slow));
    let mut core =
        near.block_on(async { support::vision_core(server, client_config, support::Uplink::Slow) });
    near.block_on(core.start()).unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    let mut streams = far.block_on(futures_join_all(
        (0..flows).map(|_| support::open_vision_flow(socks, support::Downlink::Slow)),
    ));
    far.block_on(futures_join_all(
        streams
            .iter_mut()
            .map(|stream| support::ping(stream, VISION_PADDED_PACKETS)),
    ));
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    quiesce(&far, &near, &mut streams);
    let idle = reset_peak();
    xray_transport::reset_byte_budget_peak();

    far.block_on(futures_join_all(
        streams
            .iter_mut()
            .map(|stream| support::download(stream, support::Downlink::Slow)),
    ));
    let download = peak() - idle;
    let download_permits = xray_transport::byte_budget_usage().peak;
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    let moving = reset_peak();
    xray_transport::reset_byte_budget_peak();
    far.block_on(futures_join_all(streams.iter_mut().map(support::upload)));
    let upload = peak() - moving;
    let upload_permits = xray_transport::byte_budget_usage().peak;
    far.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });
    quiesce(&far, &near, &mut streams);
    let after = live() - idle;
    drop(streams);
    near.block_on(core.stop()).unwrap();
    Run {
        idle,
        download,
        download_permits,
        moving: moving - idle,
        upload,
        upload_permits,
        after,
    }
}

/// Frees the buffers the relay pool keeps for later reads, on one of the
/// core's workers: a buffer freed on a thread that is not counted would stay
/// in `live()`.
fn release_kept_buffers(near: &tokio::runtime::Runtime) {
    near.block_on(near.spawn(async { xray_core_rs::release_relay_buffers() }))
        .expect("the release ran");
}

/// Takes the core to a point the bytes are measured from: the pool's lists
/// empty, and each worker's spare at most one buffer the pool lent since
/// the last release. A spare outlives `release_relay_buffers` until its
/// thread next uses the pool, so `QUIESCE_FLOWS` of the flows ping twice
/// between two releases: a worker that relays them frees its spare from
/// before, and the relays of the other flows keep their sizes.
fn quiesce(
    far: &tokio::runtime::Runtime,
    near: &tokio::runtime::Runtime,
    streams: &mut [tokio::net::TcpStream],
) {
    release_kept_buffers(near);
    far.block_on(futures_join_all(
        streams[..QUIESCE_FLOWS]
            .iter_mut()
            .map(|stream| support::ping(stream, 2)),
    ));
    far.block_on(async { tokio::time::sleep(Duration::from_millis(100)).await });
    release_kept_buffers(near);
}

/// T4: 64 Vision flows over TLS, a MiB down each and then a MiB up each,
/// all at once, at a phone's pace: the far client reads 4 KiB a millisecond
/// and the server takes 4 KiB a millisecond, so both directions press the
/// budget. The same flows with no limit take more than twice its bytes in
/// permits each way; that arm is checked first, so that a bound below does
/// not hold only because the flows never asked for more.
///
/// The uploads: above what the flows held once the downloads were done, the
/// core holds no more than the budget, each flow's 4 KiB floor (the
/// download direction waits for a read and holds no buffer) and 22 B of
/// framing for each record those bytes may wait in, a record per KiB (the
/// smallest relay read, the far client being always ahead) and one more
/// per flow. Their relay buffers come from those the pool kept from the
/// downloads, which `moving` counts. A flow's TLS session holds to send
/// only bytes its relay wrote and counts as unflushed: it takes a write
/// once the records of the one before have gone to the socket
/// (xray-transport's `tls_send`). Before, rustls took writes up to 64 KiB
/// ahead of the socket and part of a write that then waited, which the
/// relay buffer held too: at their peak 64 flows on a GitHub runner had 90
/// to 261 KB in both places, and went up to 102 KB over this bound in CI.
/// The arm with no limit holds more than the bound.
///
/// The downloads are held in permits, to the budget, not in bytes. What
/// they hold beside the budget is each TLS session's receive side, up to
/// `TLS_RECEIVE` a flow, which a bound in bytes must allow; and a flow with
/// no budget holds its `CONSTRAINED_READ` and the deframer's growth,
/// 47,109 B, less than the 52,499 B that bound gives each of 64 flows. So
/// no broken budget could fail it: with no limit the downloads held about
/// 2.9 MB over idle against its 3,359,936 B, with B = 1 MB 2.3 to 2.6 MB.
/// The bytes are printed.
///
/// 300 ms after the uploads the flows hold no more than they held idle and
/// the workers' spares: a frame, a buffer or a queue a flow kept from either
/// phase would show many times over.
///
/// The flows are measured past Vision's padding: pings take each of them
/// through the packets Vision pads, whose writes it copies outside the
/// budget.
#[test]
fn sixty_four_vision_flows_hold_the_budget_and_their_floors() {
    const FLOWS: usize = 64;
    let _turn = take_turn();
    let flows = FLOWS as isize;
    let held = T4_BUDGET as isize + flows * FLOOR;
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
             idle ({download_bound} B with TLS's receive side, not asserted), {} B of \
             permits at most; upload {} B over the {} B the flows held after the \
             downloads, bound {upload_bound} B, {} B of permits at most; {} B more than \
             idle after, bound {THREAD_SPARES} B",
            run.idle,
            run.idle / flows,
            run.download,
            run.download_permits,
            run.upload,
            run.moving,
            run.upload_permits,
            run.after
        );
    }
    assert!(
        unlimited.download_permits > 2 * T4_BUDGET,
        "without a limit the downloads took {} B of permits: the test no longer presses \
         the budget",
        unlimited.download_permits
    );
    assert!(
        unlimited.upload_permits > 2 * T4_BUDGET && unlimited.upload > upload_bound,
        "without a limit the uploads took {} B and {} B of permits: the test no longer \
         presses the budget",
        unlimited.upload,
        unlimited.upload_permits
    );
    assert!(
        limited.download_permits <= T4_BUDGET,
        "the downloads took {} B of permits; the budget is {T4_BUDGET} B",
        limited.download_permits
    );
    assert!(
        limited.upload <= upload_bound,
        "the uploads held {} B over what the flows held before them; the bound is \
         {upload_bound} B",
        limited.upload
    );
    for (arm, run) in [("no limit", unlimited), ("B = 1 MB", limited)] {
        assert!(
            run.after <= THREAD_SPARES,
            "{arm}: the flows held {} B more than idle after the uploads; the workers' \
             spares are at most {THREAD_SPARES} B",
            run.after
        );
    }
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
    let near = support::runtime(CORE_WORKERS, count_this_thread);
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

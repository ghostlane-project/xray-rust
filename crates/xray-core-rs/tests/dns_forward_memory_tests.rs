//! Many forwarded queries at once, on the Mobile profile the iOS and Android
//! cores run: the DNS operation limit caps the flows to the line, the queries
//! over it get SERVFAIL at once, and the heap stays within a stated bound and
//! comes back when the flows end.
//!
//! A test binary of its own with one test: the counting allocator sees the
//! whole process (client, core and line server), so nothing else may run.
#[path = "dns_forward/support.rs"]
mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use support::*;
use xray_core_rs::TunRuntimeProfile;

/// The DNS operation limit of `TunRuntimeProfile::Mobile`.
const PERMITS: usize = 16;
const QUERIES: usize = 48;
/// The heap's growth while 48 are open, 16 of them held by the line: 48
/// SOCKS UDP flows (about 39 KB each, the flow task's own size, before any
/// forward) and 16 forwards. Measured 2.08 MB.
const PEAK_BOUND: usize = 3 << 20;
/// The same with 16 at once, all on the line. Measured 0.82 MB.
const PEAK_BOUND_ON_THE_LINE: usize = 1_280 << 10;
/// What one query on the line adds over a refused one: its VLESS flow and
/// the boxed exchange, with the line server's end of the connection, which
/// runs in this process. Measured about 12 KB.
const PER_FORWARD_BOUND: usize = 24 << 10;
/// What may stay after a round's flows have closed. Measured under 2 KB.
const LEFT_BOUND: isize = 64 << 10;
const WAIT: Duration = Duration::from_secs(3);

struct CountingAllocator;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrank(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` unchanged and only counts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug, PartialEq, Eq)]
struct Round {
    refused: usize,
    answered: usize,
    max_on_the_line: usize,
}

/// `queries` TXT queries, each to its own DNS address so each is a flow of
/// its own, while the line holds every query it gets; then the line answers.
async fn round(line: &LineServer, socks: SocketAddr, queries: usize) -> Round {
    line.set_mode(Mode::Stall);
    line.reset_max_active();
    let association = UdpAssociation::open(socks).await;
    for index in 0..queries {
        let target = SocketAddrV4::new(Ipv4Addr::new(10, 53, 0, index as u8 + 1), 53);
        let message = query(index as u16 + 1, "example.com", QTYPE_TXT);
        association.send(target, &message).await;
    }
    let mut refused = 0;
    while refused < queries.saturating_sub(PERMITS) {
        let Some(answer) = association.recv(WAIT).await else {
            break;
        };
        if Answer::parse(&answer).rcode == RCODE_SERVFAIL {
            refused += 1;
        }
    }
    assert!(
        eventually(WAIT, || line.active() == queries.min(PERMITS)).await,
        "the line holds {} flows",
        line.active()
    );
    line.release();
    let mut answered = 0;
    while answered < queries.min(PERMITS) {
        let Some(answer) = association.recv(WAIT).await else {
            break;
        };
        if Answer::parse(&answer).txt() == Some(VIA_LINE) {
            answered += 1;
        }
    }
    association.close().await;
    assert!(
        eventually(WAIT, || line.active() == 0).await,
        "the line's flows close"
    );
    Round {
        refused,
        answered,
        max_on_the_line: line.max_active(),
    }
}

/// A round measured against the heap the previous one left: the round,
/// its peak growth and what it left.
async fn measured(line: &LineServer, socks: SocketAddr, queries: usize) -> (Round, usize, isize) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let round = round(line, socks, queries).await;
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let left = LIVE.load(Ordering::Relaxed) as isize - baseline as isize;
    (round, peak, left)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_queries_at_once_stay_within_the_operation_limit_and_the_bound() {
    let line = LineServer::spawn(Mode::Stall).await;
    let (mut core, socks) = start(&global_config(line.addr), TunRuntimeProfile::Mobile).await;
    let all_on_the_line = Round {
        refused: 0,
        answered: PERMITS,
        max_on_the_line: PERMITS,
    };
    let over_the_limit = Round {
        refused: QUERIES - PERMITS,
        answered: PERMITS,
        max_on_the_line: PERMITS,
    };

    // The first round warms every lazy structure up; the others are
    // measured against what the one before left.
    assert_eq!(round(&line, socks, QUERIES).await, over_the_limit);
    let (round_16, peak_16, left_16) = measured(&line, socks, PERMITS).await;
    let (round_48, peak_48, left_48) = measured(&line, socks, QUERIES).await;
    core.stop().await.unwrap();

    // 32 more flows, all refused at once, are the difference.
    let per_refused = peak_48.saturating_sub(peak_16) / (QUERIES - PERMITS);
    let per_forward = (peak_16 / PERMITS).saturating_sub(per_refused);
    println!(
        "{PERMITS} queries at once, all on the line: heap peak +{peak_16} bytes \
         (bound {PEAK_BOUND_ON_THE_LINE}), {left_16:+} left; {QUERIES} at once, \
         {PERMITS} on the line: heap peak +{peak_48} bytes (bound {PEAK_BOUND}), \
         {left_48:+} left (bound {LEFT_BOUND}); about {per_refused} bytes per refused \
         flow, {per_forward} more per forwarded one (bound {PER_FORWARD_BOUND})"
    );
    assert_eq!(round_16, all_on_the_line);
    assert_eq!(round_48, over_the_limit);
    assert!(
        peak_16 <= PEAK_BOUND_ON_THE_LINE,
        "heap peak +{peak_16} bytes"
    );
    assert!(peak_48 <= PEAK_BOUND, "heap peak +{peak_48} bytes");
    assert!(
        per_forward <= PER_FORWARD_BOUND,
        "{per_forward} bytes per forward"
    );
    assert!(left_16 <= LEFT_BOUND, "{left_16} bytes left behind");
    assert!(left_48 <= LEFT_BOUND, "{left_48} bytes left behind");
}

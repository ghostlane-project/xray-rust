//! The system allocator, counted: live bytes, the peak, and allocations.
//!
//! `design.md` D11 keeps the system allocator as it is (on iOS, xzone
//! malloc); this only wraps it with relaxed atomics so the cores can report
//! their heap (`memory_stats`) and the memory tests can hold a ceiling.
//! `ghostlane-core` installs it:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: ghostlane_runtime::alloc::CountingAlloc = ghostlane_runtime::alloc::CountingAlloc;
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The counting allocator over [`System`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

fn grew(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrank(by: usize) {
    LIVE.fetch_sub(by, Ordering::Relaxed);
}

// SAFETY: every call goes to `System` with the caller's arguments; the
// counters never touch the memory.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, passed on.
        unsafe { System.dealloc(ptr, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract, passed on.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        p
    }
}

/// The heap as the allocator counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heap {
    /// Bytes allocated and not freed.
    pub live: usize,
    /// The most `live` was since the start or [`reset_peak`].
    pub peak: usize,
    /// Allocations made (not reallocations).
    pub allocs: u64,
}

/// The heap; `None` when [`CountingAlloc`] is not the global allocator
/// (nothing was ever counted).
#[must_use]
pub fn heap() -> Option<Heap> {
    let peak = PEAK.load(Ordering::Relaxed);
    (peak > 0).then(|| Heap {
        live: LIVE.load(Ordering::Relaxed),
        peak,
        allocs: ALLOCS.load(Ordering::Relaxed),
    })
}

/// Starts the peak again from the live bytes (a memory test's window).
pub fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[global_allocator]
    static ALLOC: CountingAlloc = CountingAlloc;

    #[test]
    fn live_bytes_follow_allocations_and_the_peak_holds_the_most() {
        let before = heap().expect("installed here");
        reset_peak();
        let block = vec![1u8; 1 << 20];
        let during = heap().unwrap();
        assert!(
            during.live >= before.live + (1 << 20),
            "{before:?} {during:?}"
        );
        assert!(during.allocs > before.allocs);
        drop(block);
        let after = heap().unwrap();
        assert!(after.live < during.live, "{during:?} {after:?}");
        assert!(after.peak >= during.live, "{after:?}");
        reset_peak();
        assert!(heap().unwrap().peak < during.live);
    }
}

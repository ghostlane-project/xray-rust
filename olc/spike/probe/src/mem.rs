//! Memory gauges: the Rust heap (a counting allocator), the C heap (malloc's own counters,
//! minus the Rust heap: what BoringSSL, aws-lc and anything else in C hold), and the
//! process (RSS and its peak on Linux; phys_footprint and its peak on Apple, the number
//! iOS's jetsam limit is checked against).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

fn grow(n: usize) {
    let live = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrink(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
}

// SAFETY: every call is forwarded to the system allocator unchanged; only counters move.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            grow(l.size());
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            grow(l.size());
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        shrink(l.size());
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new > l.size() {
                grow(new - l.size());
            } else {
                shrink(l.size() - new);
            }
        }
        q
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Starts a new peak window at the current live size.
pub fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// One reading of every gauge, in bytes (0 where the platform has no such number).
#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    pub rust_live: usize,
    pub rust_peak: usize,
    pub rust_allocs: usize,
    /// malloc's in-use bytes (glibc mallinfo2 uordblks+hblkhd; Apple malloc_zone_statistics).
    pub malloc_in_use: usize,
    /// malloc_in_use minus rust_live: what C code holds.
    pub c_heap: usize,
    pub rss: usize,
    pub rss_peak: usize,
    pub phys_footprint: usize,
    pub phys_footprint_peak: usize,
}

impl Snapshot {
    pub fn json(&self) -> String {
        format!(
            "{{\"rust_live\":{},\"rust_peak\":{},\"rust_allocs\":{},\"malloc_in_use\":{},\"c_heap\":{},\"rss\":{},\"rss_peak\":{},\"phys_footprint\":{},\"phys_footprint_peak\":{}}}",
            self.rust_live,
            self.rust_peak,
            self.rust_allocs,
            self.malloc_in_use,
            self.c_heap,
            self.rss,
            self.rss_peak,
            self.phys_footprint,
            self.phys_footprint_peak
        )
    }
}

/// Reads every gauge now.
pub fn snapshot() -> Snapshot {
    let mut s = Snapshot {
        rust_live: LIVE.load(Ordering::Relaxed),
        rust_peak: PEAK.load(Ordering::Relaxed),
        rust_allocs: ALLOCS.load(Ordering::Relaxed),
        ..Snapshot::default()
    };
    platform(&mut s);
    s.c_heap = s.malloc_in_use.saturating_sub(s.rust_live);
    s
}

/// Prints `MEM <phase> <json>` to stderr and returns the reading.
pub fn report(phase: &str) -> Snapshot {
    let s = snapshot();
    eprintln!("MEM {phase} {}", s.json());
    s
}

#[cfg(target_os = "linux")]
fn platform(s: &mut Snapshot) {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let kb = |l: &str| -> usize {
                l.split_whitespace().nth(1).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0) * 1024
            };
            if line.starts_with("VmRSS:") {
                s.rss = kb(line);
            } else if line.starts_with("VmHWM:") {
                s.rss_peak = kb(line);
            }
        }
    }
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: mallinfo2 takes no arguments and returns a plain struct.
        let mi = unsafe { libc::mallinfo2() };
        s.malloc_in_use = mi.uordblks + mi.hblkhd;
    }
}

#[cfg(target_vendor = "apple")]
fn platform(s: &mut Snapshot) {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Default)]
    struct MallocStatistics {
        blocks_in_use: u32,
        size_in_use: usize,
        max_size_in_use: usize,
        size_allocated: usize,
    }

    static PF_SAMPLED_MAX: AtomicUsize = AtomicUsize::new(0);

    // task_vm_info, through rev 3 (ledger_phys_footprint_peak); the kernel fills what the
    // count asks for.
    #[repr(C)]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
        min_address: u64,
        max_address: u64,
        ledger_phys_footprint_peak: i64,
    }

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
        fn malloc_zone_statistics(zone: *mut c_void, stats: *mut MallocStatistics);
    }
    const TASK_VM_INFO: u32 = 22;

    let mut info = TaskVmInfo::default();
    let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
    // SAFETY: the out-parameter is a properly sized, zeroed task_vm_info.
    let kr = unsafe { task_info(mach_task_self_, TASK_VM_INFO, &mut info as *mut _ as *mut i32, &mut count) };
    if kr == 0 {
        s.rss = info.resident_size as usize;
        s.rss_peak = info.resident_size_peak as usize;
        s.phys_footprint = info.phys_footprint as usize;
        // The ledger's peak reads 0 where the kernel keeps no interval maximum (seen on the
        // macos-15 runner); the sampled maximum over every snapshot stands in for it then.
        let sampled = PF_SAMPLED_MAX.fetch_max(s.phys_footprint, Ordering::Relaxed).max(s.phys_footprint);
        let ledger = info.ledger_phys_footprint_peak.max(0) as usize;
        s.phys_footprint_peak = if ledger > 0 { ledger } else { sampled };
    }
    let mut ms = MallocStatistics::default();
    // SAFETY: a null zone asks for the sum over every zone.
    unsafe { malloc_zone_statistics(std::ptr::null_mut(), &mut ms) };
    s.malloc_in_use = ms.size_in_use;
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn platform(_: &mut Snapshot) {}

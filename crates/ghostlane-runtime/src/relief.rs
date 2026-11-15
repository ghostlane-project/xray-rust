//! What a trim gives back to the system: the cores' pools, then the system
//! allocator's free pages, measured as the fall of the process's footprint.
//!
//! The extension's relief under memory pressure (`design.md` D11) is the
//! core's, not the app's: `olc_ffi::trim()` drops the olcRTC client's pools
//! (the spare buffers it keeps for reuse) and then, on Apple and Android
//! targets, asks the system allocator for its free pages back. On Apple
//! targets that is `malloc_zone_pressure_relief(NULL, 0)` (every zone, as
//! much as it can).
//! Freed buffers stay the allocator's until it is asked or it decides; on
//! iOS, xzone malloc has no deferred-reclaim ring to decide for it
//! (Ghostlane lab/core-footprint, 09-allocator-rows.md), so without the call
//! the pages a burst leaves stay in the footprint jetsam counts.
//!
//! On Android the system allocator is bionic's (Scudo since Android 11),
//! which keeps a burst's freed pages too until it is asked (no release
//! interval is set for the process): the relief is `mallopt(M_PURGE_ALL, 0)`
//! (API 34: Scudo drains its thread caches first), else `mallopt(M_PURGE,
//! 0)` (API 28). `mallopt` is in libc from API 26 and the app's minSdk is 23,
//! so it is looked up at run time; before API 28 nothing is purged. Ghostlane
//! lab/olc-ffi-android measured it on the emulator after a burst of 256
//! downloads: the core in a process of its own gave back 508-516 kB with
//! `M_PURGE` and 240-248 kB more with `M_PURGE_ALL` (of 2.1-2.3 MB private),
//! and inside the app's process 3.7-4.0 MB of Scudo's private pages, where
//! the pools alone had moved nothing.
//!
//! The bytes a trim reports are the larger of what the pools dropped and
//! the fall of the footprint across the pools and the relief
//! (`phys_footprint` on Apple targets, `RssAnon` on Android): the pools'
//! buffers are freed into the allocator and the relief hands those same
//! pages to the system, so a sum would count them twice.
//!
//! Elsewhere nothing more is asked of the allocator (the footprint is not
//! read, and a trim reports the pools' bytes): glibc's `malloc_trim` gave
//! back about 1.1 MiB on Linux, but desktop Linux has no memory limit to
//! defend.

/// The process's footprint as the system counts it against its limit:
/// `phys_footprint` from `task_info(TASK_VM_INFO)` on Apple targets (what
/// MemoryWatch reads and jetsam kills on), `RssAnon` from
/// `/proc/self/status` on Android (the anonymous resident pages, where the
/// heap is), `None` elsewhere.
#[must_use]
pub fn footprint() -> Option<u64> {
    #[cfg(target_vendor = "apple")]
    {
        apple::footprint()
    }
    #[cfg(target_os = "android")]
    {
        android::footprint()
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "android")))]
    {
        None
    }
}

/// Asks the system allocator for its free pages back; the bytes it says it
/// released. On Apple targets `malloc_zone_pressure_relief(NULL, 0)`; on
/// Android bionic's `mallopt(M_PURGE_ALL, 0)`, else `mallopt(M_PURGE, 0)`,
/// which say nothing of bytes (0); elsewhere nothing is asked and it is 0.
pub fn allocator_relief() -> usize {
    #[cfg(target_vendor = "apple")]
    {
        apple::pressure_relief()
    }
    #[cfg(target_os = "android")]
    {
        android::purge()
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "android")))]
    {
        0
    }
}

/// Drops the pools (`pools` drops them and returns their bytes), then asks
/// the allocator for its free pages back ([`allocator_relief`]). Returns the
/// bytes given back: the pools' bytes, or the footprint's fall across both
/// steps when that is more (see the module's note).
pub fn trim(pools: impl FnOnce() -> usize) -> usize {
    let before = footprint();
    let dropped = pools();
    allocator_relief();
    given_back(dropped, before, footprint())
}

/// The bytes a trim reports, from the pools' bytes and the footprint before
/// and after it.
fn given_back(dropped: usize, before: Option<u64>, after: Option<u64>) -> usize {
    let fell = match (before, after) {
        (Some(before), Some(after)) => before.saturating_sub(after),
        _ => 0,
    };
    dropped.max(usize::try_from(fell).unwrap_or(usize::MAX))
}

/// `RssAnon` of a `/proc/<pid>/status`, in bytes.
#[cfg(any(target_os = "android", test))]
fn rss_anon(status: &str) -> Option<u64> {
    let kb = status
        .lines()
        .find_map(|l| l.strip_prefix("RssAnon:"))?
        .trim()
        .strip_suffix("kB")?
        .trim_end()
        .parse::<u64>()
        .ok()?;
    kb.checked_mul(1024)
}

#[cfg(target_os = "android")]
mod android {
    use std::ffi::{c_char, c_int, c_void};

    /// `M_PURGE` (`<malloc.h>`, API 28): the allocator releases the free
    /// pages it can.
    const M_PURGE: c_int = -101;
    /// `M_PURGE_ALL` (API 34): the same after Scudo drains its thread
    /// caches into its free lists, so their blocks' pages can go too.
    const M_PURGE_ALL: c_int = -104;

    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }

    /// `RTLD_DEFAULT` (`<dlfcn.h>`): every loaded library, in load order.
    #[cfg(target_pointer_width = "64")]
    fn rtld_default() -> *mut c_void {
        std::ptr::null_mut()
    }
    #[cfg(not(target_pointer_width = "64"))]
    fn rtld_default() -> *mut c_void {
        std::ptr::without_provenance_mut(0xffff_ffff)
    }

    type Mallopt = unsafe extern "C" fn(c_int, c_int) -> c_int;

    /// libc's `mallopt`, looked up when it is asked for: it is in libc from
    /// API 26 and the app's minSdk is 23, so it cannot be linked.
    fn mallopt() -> Option<Mallopt> {
        // SAFETY: RTLD_DEFAULT and a C string, as dlsym takes them.
        let f = unsafe { dlsym(rtld_default(), c"mallopt".as_ptr()) };
        if f.is_null() {
            return None;
        }
        // SAFETY: the symbol is libc's `int mallopt(int, int)`.
        Some(unsafe { std::mem::transmute::<*mut c_void, Mallopt>(f) })
    }

    /// `mallopt(M_PURGE_ALL, 0)`, else (an API level or an allocator that
    /// does not know it answers 0) `mallopt(M_PURGE, 0)`. Neither says how
    /// many bytes it released: 0.
    pub(super) fn purge() -> usize {
        if let Some(mallopt) = mallopt() {
            // SAFETY: mallopt takes any parameter and answers 0 for one it
            // does not know; a purge touches only the allocator's free
            // memory.
            unsafe {
                if mallopt(M_PURGE_ALL, 0) == 0 {
                    mallopt(M_PURGE, 0);
                }
            }
        }
        0
    }

    pub(super) fn footprint() -> Option<u64> {
        super::rss_anon(&std::fs::read_to_string("/proc/self/status").ok()?)
    }
}

#[cfg(target_vendor = "apple")]
mod apple {
    use std::ffi::c_void;

    /// `TASK_VM_INFO` (`<mach/task_info.h>`).
    const TASK_VM_INFO: u32 = 22;
    /// `TASK_VM_INFO_REV1_COUNT`: the `natural_t`s of `task_vm_info` up to
    /// and with `phys_footprint` (152 bytes).
    const REV1_COUNT: u32 = 38;
    /// `phys_footprint`'s place in them: byte 144, the struct being
    /// `#pragma pack(4)`, so an array of `natural_t` has its layout.
    const PHYS_FOOTPRINT: usize = 36;
    const KERN_SUCCESS: i32 = 0;

    extern "C" {
        /// What `mach_task_self()` reads (`<mach/mach_init.h>`).
        static mach_task_self_: u32;
        fn task_info(target: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
        fn malloc_zone_pressure_relief(zone: *mut c_void, goal: usize) -> usize;
    }

    pub(super) fn footprint() -> Option<u64> {
        let mut info = [0u32; REV1_COUNT as usize];
        let mut count = REV1_COUNT;
        // SAFETY: `mach_task_self_` is the task's own port, set before main
        // and never written again; `info` holds `count` natural_t's, which
        // is all task_info writes, and it says in `count` how many it did.
        let kr = unsafe {
            task_info(
                mach_task_self_,
                TASK_VM_INFO,
                info.as_mut_ptr().cast::<i32>(),
                &mut count,
            )
        };
        if kr != KERN_SUCCESS || count < REV1_COUNT {
            return None;
        }
        let low = info[PHYS_FOOTPRINT].to_ne_bytes();
        let high = info[PHYS_FOOTPRINT + 1].to_ne_bytes();
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&low);
        bytes[4..].copy_from_slice(&high);
        Some(u64::from_ne_bytes(bytes))
    }

    pub(super) fn pressure_relief() -> usize {
        // SAFETY: a null zone is every zone and a goal of 0 is as much as
        // it can (`<malloc/malloc.h>`); it touches only the allocator's
        // free memory.
        unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn a_trim_reports_the_footprints_fall_when_it_is_more_than_the_pools() {
        let pools = 128 << 10;
        assert_eq!(
            given_back(pools, Some(10 * MIB), Some(7 * MIB)),
            3 << 20,
            "the relief gave back 3 MiB"
        );
        assert_eq!(
            given_back(pools, Some(10 * MIB), Some(10 * MIB - 4096)),
            pools,
            "less fell than the pools dropped: the pools' bytes"
        );
        assert_eq!(
            given_back(pools, Some(10 * MIB), Some(11 * MIB)),
            pools,
            "it rose meanwhile"
        );
        assert_eq!(given_back(pools, None, None), pools, "no footprint here");
        assert_eq!(given_back(pools, Some(10 * MIB), None), pools);
    }

    #[test]
    fn rss_anon_is_read_from_a_status_in_bytes() {
        let status =
            "Name:\tolc\nVmRSS:\t   6680 kB\nRssAnon:\t    2344 kB\nRssFile:\t    4336 kB\n";
        assert_eq!(rss_anon(status), Some(2344 * 1024));
        assert_eq!(rss_anon("VmRSS:\t 6680 kB\n"), None, "no RssAnon line");
        assert_eq!(rss_anon("RssAnon:\t 2344 MB\n"), None, "not kB");
        assert_eq!(rss_anon("RssAnon:\t lots kB\n"), None);
    }

    #[test]
    fn the_footprint_is_read_on_apple_and_android_targets_only() {
        let f = footprint();
        if cfg!(target_vendor = "apple") {
            // A test process's phys_footprint is more than a mebibyte.
            assert!(f.is_some_and(|b| b > MIB), "{f:?}");
        } else if cfg!(target_os = "android") {
            // Its anonymous resident pages (stacks, heap) are fewer: 0.6 to
            // 0.9 MB on the emulator (run 43682904814).
            assert!(f.is_some_and(|b| b > 64 << 10), "{f:?}");
        } else {
            assert_eq!(f, None);
        }
    }

    /// On Android a trim asks Scudo for its free pages back
    /// (`mallopt(M_PURGE_ALL)`, else `M_PURGE`) and reports the fall of
    /// the anonymous resident bytes. Scudo releases a size class's free
    /// pages on a free by itself only once its release interval has passed
    /// since the class's last release, so what a burst frees right after a
    /// release stays resident until a later free or a purge. Here the same
    /// 8 MiB of 2 KiB blocks is freed twice: the first time Scudo releases
    /// it (run 43682904814, a single round: 9.0 MB fell to 0.77 MB at the
    /// free and the trim had 156 KB left to give), the second time it keeps
    /// it, for the trim. Run on the emulator by Ghostlane's
    /// lab/olc-ffi-android.
    #[cfg(target_os = "android")]
    #[test]
    fn on_android_a_trim_gives_back_what_a_burst_left_free() {
        let burst = || -> Vec<Vec<u8>> {
            (0..4096u32)
                .map(|i| vec![u8::try_from(i % 251).unwrap_or(0); 2 << 10])
                .collect()
        };
        drop(burst());
        let released = footprint();
        let bufs = burst();
        let held = footprint();
        drop(bufs);
        let kept = footprint();
        let given = trim(|| 0);
        eprintln!(
            "trim after 8 MiB freed twice: {given} B given back (after the first free {released:?}, \
             held {held:?}, after the second free {kept:?}, now {:?})",
            footprint()
        );
        assert!(given >= 1 << 20, "{given} B");
    }

    #[test]
    fn a_trim_drops_the_pools_and_reports_at_least_their_bytes() {
        let mut dropped = false;
        let n = trim(|| {
            dropped = true;
            64 << 10
        });
        assert!(dropped);
        assert!(n >= 64 << 10, "{n}");
    }

    /// On Apple targets the relief is asked: pages a burst of 16 KiB
    /// buffers left free are what it can give back. What it gives is the
    /// allocator's to say, so this reports and asserts only that it runs.
    #[test]
    fn the_allocator_relief_runs() {
        let bufs: Vec<Vec<u8>> = (0u8..=255).map(|i| vec![i; 16 << 10]).collect();
        let before = footprint();
        drop(bufs);
        let relieved = allocator_relief();
        let after = footprint();
        eprintln!("relief: {relieved} B; footprint {before:?} -> {after:?}");
        if !cfg!(target_vendor = "apple") {
            assert_eq!(relieved, 0);
        }
    }
}

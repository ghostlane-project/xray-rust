//! What a trim gives back to the system: the cores' pools, then the system
//! allocator's free pages, measured as the fall of the process's footprint.
//!
//! The extension's relief under memory pressure (`design.md` D11) is the
//! core's, not the app's: `olc_ffi::trim()` drops the olcRTC client's pools
//! (the spare buffers it keeps for reuse) and then, on Apple targets, asks
//! the system allocator for its free pages back,
//! `malloc_zone_pressure_relief(NULL, 0)` (every zone, as much as it can).
//! Freed buffers stay the allocator's until it is asked or it decides; on
//! iOS, xzone malloc has no deferred-reclaim ring to decide for it
//! (Ghostlane lab/core-footprint, 09-allocator-rows.md), so without the call
//! the pages a burst leaves stay in the footprint jetsam counts.
//!
//! The bytes a trim reports are the larger of what the pools dropped and
//! the fall of `phys_footprint` across the pools and the relief: the pools'
//! buffers are freed into the allocator and the relief hands those same
//! pages to the system, so a sum would count them twice.
//!
//! Elsewhere nothing more is asked of the allocator (the footprint is not
//! read, and a trim reports the pools' bytes).

/// The process's footprint as the system counts it against its limit:
/// `phys_footprint` from `task_info(TASK_VM_INFO)` on Apple targets (what
/// MemoryWatch reads and jetsam kills on), `None` elsewhere.
#[must_use]
pub fn footprint() -> Option<u64> {
    #[cfg(target_vendor = "apple")]
    {
        apple::footprint()
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        None
    }
}

/// Asks the system allocator for its free pages back; the bytes it says it
/// released. On Apple targets `malloc_zone_pressure_relief(NULL, 0)`;
/// elsewhere nothing is asked and it is 0.
pub fn allocator_relief() -> usize {
    #[cfg(target_vendor = "apple")]
    {
        apple::pressure_relief()
    }
    #[cfg(not(target_vendor = "apple"))]
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
    fn the_footprint_is_read_on_apple_and_android_targets_only() {
        let f = footprint();
        if cfg!(any(target_vendor = "apple", target_os = "android")) {
            // A test process holds more than a mebibyte.
            assert!(f.is_some_and(|b| b > MIB), "{f:?}");
        } else {
            assert_eq!(f, None);
        }
    }

    /// On Android a trim asks Scudo for its free pages back
    /// (`mallopt(M_PURGE_ALL)`, else `M_PURGE`) and reports the fall of
    /// the anonymous resident bytes: 8 MiB of 16 KiB buffers freed leave
    /// whole pages free, which Scudo keeps until it is asked. Run on the
    /// emulator by Ghostlane's lab/olc-ffi-android.
    #[cfg(target_os = "android")]
    #[test]
    fn on_android_a_trim_gives_back_what_a_burst_left_free() {
        let bufs: Vec<Vec<u8>> = (0..512u32)
            .map(|i| vec![u8::try_from(i % 251).unwrap_or(0); 16 << 10])
            .collect();
        let held = footprint();
        drop(bufs);
        let given = trim(|| 0);
        eprintln!(
            "trim after 8 MiB freed: {given} B given back (held {held:?}, now {:?})",
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

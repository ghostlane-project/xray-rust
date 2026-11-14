//! Ghostlane's one native library (plan §3.4): the only crate with
//! `crate-type = ["staticlib", "cdylib"]`, so the extension links one copy
//! of the Rust standard library, one allocator and one runtime.
//!
//! - `xray_ffi`: the xray core's C ABI (`xray_ffi.h`), on the shared
//!   runtime (its `shared-runtime` feature).
//! - `olc_ffi`: the olcRTC client's UniFFI API (`OlcrtcRuntime`); its
//!   Swift and Kotlin bindings are generated from this library.
//! - [`ALLOC`]: the system allocator, counted (`ghostlane_runtime::alloc`),
//!   which `memory_stats()` reports.
//!
//! The runtime is `ghostlane_runtime`'s: one worker and four blocking
//! threads on iOS (`design.md` D11), xray-ffi's 2 to 6 workers elsewhere.

pub use olc_ffi;
pub use xray_ffi;

/// The process's allocator: the system's, counted.
#[global_allocator]
pub static ALLOC: ghostlane_runtime::alloc::CountingAlloc = ghostlane_runtime::alloc::CountingAlloc;

#[cfg(test)]
mod tests {
    #[test]
    fn both_cores_share_the_runtime_and_the_heap_is_counted() {
        let heap = ghostlane_runtime::alloc::heap().expect("the counting allocator is installed");
        assert!(heap.live > 0);
        let rt = ghostlane_runtime::handle().unwrap();
        let line = olc_ffi::memory_stats();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v["heap"]["live"].as_u64().unwrap() > 0, "{line}");
        assert_eq!(
            v["rt"]["workers"].as_u64(),
            u64::try_from(rt.metrics().num_workers()).ok(),
            "{line}"
        );
    }
}

//! What the two cores in `ghostlane-core` share in one process: one Tokio
//! runtime ([`runtime`]) and the allocator's gauges ([`alloc`]).
//!
//! The iOS packet-tunnel extension is killed at about 50 MB, so the library
//! it links carries the xray core (`xray-ffi`) and the olcRTC client
//! (`olc-ffi`) on one runtime with few threads (one worker and at most four
//! blocking threads on iOS, `design.md` D11) and counts its heap through one
//! allocator. Both cores take the runtime from here; `ghostlane-core`
//! installs [`alloc::CountingAlloc`] as the `#[global_allocator]`.

#![warn(missing_docs)]

pub mod alloc;
pub mod runtime;

pub use runtime::{handle, Profile};

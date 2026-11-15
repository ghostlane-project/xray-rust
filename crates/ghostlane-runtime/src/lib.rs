//! What the two cores in `ghostlane-core` share in one process: one Tokio
//! runtime ([`runtime`]), the allocator's gauges ([`alloc`]), one budget
//! of payload bytes in flight ([`memory_budget`], with the memory class it
//! is sized by, [`memory_class`]) and the relief a trim asks of the system
//! allocator ([`relief`]).
//!
//! The iOS packet-tunnel extension is killed at about 50 MB, so the library
//! it links carries the xray core (`xray-ffi`) and the olcRTC client
//! (`olc-ffi`) on one runtime with few threads (one worker and at most four
//! blocking threads on iOS, `design.md` D11) and counts its heap through one
//! allocator. Both cores take the runtime from here; `ghostlane-core`
//! installs [`alloc::CountingAlloc`] as the `#[global_allocator]`.

#![warn(missing_docs)]

pub mod alloc;
// The byte budget and the memory class came from xray-transport (Integration
// 3) as they were, so that the olcRTC client takes its buffers from the same
// budget as the xray core without depending on xray-transport; xray-transport
// re-exports both, so its paths are unchanged. Their items keep the docs they
// had there.
#[allow(missing_docs)]
pub mod memory_budget;
#[allow(missing_docs)]
pub mod memory_class;
pub mod relief;
pub mod runtime;

pub use memory_budget::{
    byte_budget, byte_budget_usage, reset_byte_budget_peak, set_byte_budget, ByteBudget,
    ByteBudgetSettings, ByteBudgetUsage,
};
pub use memory_class::{memory_class, set_memory_class, MemoryClass};
pub use runtime::{handle, Profile};

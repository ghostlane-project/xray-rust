//! Helpers for the size guards: the size of an async fn's future without
//! running it or building its arguments.
//!
//! The sizes asserted by the guards are release-profile sizes: rustc's MIR
//! optimisations (which decide how many locals a future keeps across an
//! `.await`, and so its size) differ between the dev and release profiles, and
//! the memory model measured the release ones. Each guard is therefore
//! `ignore`d under `debug_assertions` and runs with `cargo test --release`.

/// A value of any type, for a closure that is only measured and never called.
pub(crate) fn never<T>() -> T {
    unreachable!("size guards measure a closure's return type and never call it")
}

/// The size in bytes of the future `make` would return.
pub(crate) fn size_of_returned<F>(_make: impl FnOnce() -> F) -> usize {
    std::mem::size_of::<F>()
}

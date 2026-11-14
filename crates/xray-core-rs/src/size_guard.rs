//! Helpers for the size guards: the size of an async fn's future without
//! running it or building its arguments.
//!
//! The sizes asserted by the guards are release-mode sizes (the profile the
//! memory model measured, tokio boxes a future above 16,384 B only there), so
//! each guard is `ignore`d under `debug_assertions` and runs with
//! `cargo test --release`.

/// A value of any type, for a closure that is only measured and never called.
pub(crate) fn never<T>() -> T {
    unreachable!("size guards measure a closure's return type and never call it")
}

/// The size in bytes of the future `make` would return.
pub(crate) fn size_of_returned<F>(_make: impl FnOnce() -> F) -> usize {
    std::mem::size_of::<F>()
}

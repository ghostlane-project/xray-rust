//! Lab only (gl/tls-send-lab-*): allocation tags and relay counters for
//! T4's split. Never merged.
use std::cell::Cell;

thread_local! {
    static TAG: Cell<u8> = const { Cell::new(0) };
}

/// Allocations made while a Vision flow's transport (TLS) writes or flushes.
pub const TLS_SEND: u8 = 1;
/// Allocations made while a Vision flow's transport (TLS) reads.
pub const TLS_RECV: u8 = 2;
/// The relay pool's new buffers.
pub const POOL: u8 = 3;

pub fn current() -> u8 {
    TAG.try_with(Cell::get).unwrap_or(0)
}

pub fn with<T>(tag: u8, f: impl FnOnce() -> T) -> T {
    let old = TAG.try_with(|slot| slot.replace(tag)).unwrap_or(0);
    let out = f();
    let _ = TAG.try_with(|slot| slot.set(old));
    out
}

/// (pool kept bytes, relays' unflushed bytes, bytes the TLS writers took of
/// a relay write still in progress)
pub fn counters() -> (usize, isize, isize) {
    crate::policy::lab_counters()
}

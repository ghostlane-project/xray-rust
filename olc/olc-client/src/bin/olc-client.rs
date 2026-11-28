// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `olc-client <config.json>`: the client as a process, for the gate and
//! the desktops. The engine log goes to stderr; SIGTERM or SIGINT ends the
//! run, after the control loop says goodbye. A config with `rooms` runs the
//! room supervisor (the primary room first, then the others, as
//! `mobile/runtime.go` does); one with only `url` runs that room.
//!
//! Built with `shaped-tls`, its `wss://` and `https://` go over the fork's
//! shaped-rustls with Chrome's ClientHello. Built with the `heap-stats` feature, the process counts every byte it
//! takes from the allocator and says `heap now <n> KiB peak <n> KiB` every
//! [`heap::EVERY`] and at its end (plan section 9: the engine's gauge).

use std::process::ExitCode;
use std::sync::Arc;

use olc_client::{supervisor, Client, Config};
use tokio_util::sync::CancellationToken;

/// Workers: enough for the gate's 32 parallel transfers, few enough for a
/// phone (plan §9: 2-6 workers).
const MAX_WORKERS: usize = 4;
/// A worker's stack (plan §9: 512 KiB; futures live on the heap).
const WORKER_STACK: usize = 512 * 1024;

#[cfg(feature = "heap-stats")]
#[allow(unsafe_code)]
mod heap {
    //! The counting allocator: the system's, with the bytes it holds now and
    //! the most it held, two relaxed atomics per call.

    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use std::time::Duration;

    /// How often the gauge is said while the client runs.
    pub const EVERY: Duration = Duration::from_secs(10);

    static NOW: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    struct Counting;

    #[global_allocator]
    static COUNTING: Counting = Counting;

    fn grew(n: usize) {
        let now = NOW.fetch_add(n, Relaxed) + n;
        PEAK.fetch_max(now, Relaxed);
    }

    // SAFETY: every call goes straight to `System` with the caller's
    // arguments; the counters are only arithmetic on the sizes.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's contract, passed on.
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                grew(layout.size());
            }
            p
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's contract, passed on.
            let p = unsafe { System.alloc_zeroed(layout) };
            if !p.is_null() {
                grew(layout.size());
            }
            p
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: the caller's contract, passed on.
            unsafe { System.dealloc(ptr, layout) };
            NOW.fetch_sub(layout.size(), Relaxed);
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: the caller's contract, passed on.
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                if new_size >= layout.size() {
                    grew(new_size - layout.size());
                } else {
                    NOW.fetch_sub(layout.size() - new_size, Relaxed);
                }
            }
            p
        }
    }

    /// Says the gauge.
    pub fn say() {
        olc_client::info!(
            "heap now {} KiB peak {} KiB",
            NOW.load(Relaxed) >> 10,
            PEAK.load(Relaxed) >> 10
        );
    }
}

fn main() -> ExitCode {
    // First, as the Go runtime does: the soft file limit up to the hard one.
    match olc_client::sys::raise_nofile_limit() {
        Some(l) => olc_client::info!("file limit: {} (hard {})", l.soft, l.hard),
        None => olc_client::info!("file limit: unknown"),
    }
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: olc-client <config.json>");
        return ExitCode::from(2);
    };
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let cfg = match Config::from_json(&raw) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    #[cfg(feature = "shaped-tls")]
    if let Err(e) = olc_net::shaped_tls::install(olc_net::shaped_tls::FINGERPRINT) {
        eprintln!("tls: {e}");
        return ExitCode::FAILURE;
    }
    let workers = std::thread::available_parallelism()
        .map_or(2, std::num::NonZeroUsize::get)
        .clamp(2, MAX_WORKERS);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_stack_size(WORKER_STACK)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = rt.block_on(async move {
        #[cfg(feature = "heap-stats")]
        tokio::spawn(async {
            let mut tick = tokio::time::interval(heap::EVERY);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                heap::say();
            }
        });
        let stop = CancellationToken::new();
        {
            let stop = stop.clone();
            tokio::spawn(async move {
                // SIGTERM where there is one; Windows has Ctrl-C alone.
                let term = async {
                    #[cfg(unix)]
                    {
                        let mut term = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        )
                        .expect("SIGTERM handler");
                        term.recv().await;
                    }
                    #[cfg(not(unix))]
                    std::future::pending::<()>().await;
                };
                tokio::select! {
                    () = term => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
                stop.cancel();
            });
        }
        let ended = if cfg.rooms.is_empty() {
            Client::run(cfg, stop, |_| {})
                .await
                .map_err(|e| e.to_string())
        } else {
            supervisor::run(cfg, stop, Arc::new(|_| {}), None)
                .await
                .map_err(|e| e.to_string())
        };
        match ended {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                olc_client::info!("{e}");
                ExitCode::FAILURE
            }
        }
    });
    #[cfg(feature = "heap-stats")]
    heap::say();
    code
}

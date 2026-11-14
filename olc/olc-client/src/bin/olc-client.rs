// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `olc-client <config.json>`: the client as a process, for the gate and
//! the desktops. The engine log goes to stderr; SIGTERM or SIGINT ends the
//! run, after the control loop says goodbye. A config with `rooms` runs the
//! room supervisor (the primary room first, then the others, as
//! `mobile/runtime.go` does); one with only `url` runs that room.

use std::process::ExitCode;
use std::sync::Arc;

use olc_client::{supervisor, Client, Config};
use tokio_util::sync::CancellationToken;

/// Workers: enough for the gate's 32 parallel transfers, few enough for a
/// phone (plan §9: 2-6 workers).
const MAX_WORKERS: usize = 4;
/// A worker's stack (plan §9: 512 KiB; futures live on the heap).
const WORKER_STACK: usize = 512 * 1024;

fn main() -> ExitCode {
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
    rt.block_on(async move {
        let stop = CancellationToken::new();
        {
            let stop = stop.clone();
            tokio::spawn(async move {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! {
                    _ = term.recv() => {}
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
    })
}

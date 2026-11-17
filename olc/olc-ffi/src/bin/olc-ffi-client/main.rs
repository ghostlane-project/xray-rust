// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `olc-ffi-client <config.json>`: the gate's Rust client driven through the
//! app API (see `driver.rs`), on the counting allocator `memory_stats()`
//! reads its heap from.

use std::process::ExitCode;

mod driver;

#[global_allocator]
static ALLOC: ghostlane_runtime::alloc::CountingAlloc = ghostlane_runtime::alloc::CountingAlloc;

fn main() -> ExitCode {
    driver::main(&mut |_, _| None)
}

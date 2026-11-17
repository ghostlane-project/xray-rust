// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `olc-ffi-dhat <config.json>`: olc-ffi-client (the same driver) on
//! dhat-rs's allocator, for the heap by allocation site. Its control mode
//! (`OLC_FFI_CONTROL=1`) adds two commands:
//!
//! ```text
//! profile <file>   start a heap profile        PROFILING
//! dump             end it, written to <file>   DUMPED <file>
//! ```
//!
//! A profile counts the blocks allocated while it runs: `dump`'s `t-end`
//! is what of those is still live, so a profile started before 512
//! connections open and dumped while they are held is their state, site by
//! site. `memory_stats()`'s heap reads nothing here (its counting allocator
//! is not this build's). Built with debug line tables, not stripped:
//!
//! ```text
//! cargo build -p olc-ffi --example olc-ffi-dhat --profile dhat \
//!   --config 'profile.dhat.inherits="release"' \
//!   --config 'profile.dhat.debug="line-tables-only"' --config 'profile.dhat.strip="none"'
//! ```

use std::process::ExitCode;

#[path = "../src/bin/olc-ffi-client/driver.rs"]
mod driver;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> ExitCode {
    let mut profile: Option<(dhat::Profiler, String)> = None;
    driver::main(&mut |command, rest| match command {
        "profile" if profile.is_none() && !rest.is_empty() => {
            let p = dhat::Profiler::builder()
                .file_name(rest)
                .trim_backtraces(Some(40))
                .build();
            profile = Some((p, rest.to_owned()));
            Some("PROFILING".to_owned())
        }
        "dump" => Some(profile.take().map_or_else(
            || "ERR dump no profile".to_owned(),
            |(p, file)| {
                drop(p);
                format!("DUMPED {file}")
            },
        )),
        _ => None,
    })
}

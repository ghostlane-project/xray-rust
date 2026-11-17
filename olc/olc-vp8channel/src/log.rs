// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The transport's log lines (`logger.Infof`, `logger.Debugf` in Go), each
//! one line in Go's words. A host takes them with [`set_sink`] (olc-client
//! hands them to its own log); with none set they are dropped.

use std::fmt::Arguments;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

/// Where log lines go; `debug` says the line is a `Debugf` one.
pub type Sink = Arc<dyn Fn(&str, bool) + Send + Sync>;

static SINK: RwLock<Option<Sink>> = RwLock::new(None);
static HAS_SINK: AtomicBool = AtomicBool::new(false);

/// Sends the lines to `sink`, or nowhere.
pub fn set_sink(sink: Option<Sink>) {
    HAS_SINK.store(sink.is_some(), Ordering::Relaxed);
    *SINK.write().unwrap_or_else(PoisonError::into_inner) = sink;
}

fn emit(args: Arguments<'_>, debug: bool) {
    if !HAS_SINK.load(Ordering::Relaxed) {
        return;
    }
    let sink = SINK.read().unwrap_or_else(PoisonError::into_inner).clone();
    if let Some(sink) = sink {
        sink(&args.to_string(), debug);
    }
}

/// An `Infof` line.
pub fn write_info(args: Arguments<'_>) {
    emit(args, false);
}

/// A `Debugf` line.
pub fn write_debug(args: Arguments<'_>) {
    emit(args, true);
}

macro_rules! info {
    ($($t:tt)*) => { $crate::log::write_info(format_args!($($t)*)) };
}
macro_rules! debug {
    ($($t:tt)*) => { $crate::log::write_debug(format_args!($($t)*)) };
}
pub(crate) use {debug, info};

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The engine log (`internal/logger`): Go's `log.Printf`, one line each,
//! stamped `2006/01/02 15:04:05 ` in UTC.
//!
//! The lines are a contract: the apps restart the tunnel on some of them and
//! the gate judges S4 by others (critique G1), so their texts are Go's, word
//! for word. A host (the FFI, a test) can take the lines with [`set_sink`];
//! by default they go to stderr. Debug lines ([`debug!`]) are written only
//! when [`set_verbose`] is on, as `logger.Debugf`.

use std::fmt::Arguments;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where log lines go: each call is one line, without its newline.
pub type Sink = Arc<dyn Fn(&str) + Send + Sync>;

static SINK: RwLock<Option<Sink>> = RwLock::new(None);
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Sends every line to `sink`; `None` sends them to stderr again.
pub fn set_sink(sink: Option<Sink>) {
    *SINK
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = sink;
}

/// Turns the debug lines on or off (`logger.SetVerbose`).
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// Whether debug lines are written.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Writes one line, stamped.
pub fn write(args: Arguments<'_>) {
    let line = format!("{} {args}", stamp(SystemTime::now()));
    let sink = SINK
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    match sink {
        Some(sink) => sink(&line),
        None => {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "{line}");
        }
    }
}

/// `log.Printf`'s stamp, `2006/01/02 15:04:05`, in UTC.
pub fn stamp(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}/{month:02}/{day:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// `logger.Infof` (and `Warnf`, which writes the same way).
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write(format_args!($($arg)*)) };
}

/// `logger.Debugf`: only when verbose.
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::verbose() {
            $crate::log::write(format_args!($($arg)*))
        }
    };
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn the_stamp_is_gos_layout() {
        assert_eq!(stamp(UNIX_EPOCH), "1970/01/01 00:00:00");
        // 2026-11-14 12:34:56 UTC.
        let at = UNIX_EPOCH + Duration::from_secs(1_794_659_696);
        assert_eq!(stamp(at), "2026/11/14 12:34:56");
        // A leap day.
        let at = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(stamp(at), "2024/02/29 00:00:00");
    }
}

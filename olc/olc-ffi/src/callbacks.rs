// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the apps implement and hand in (`mobile/protector.go`,
//! `listener.go`, `log.go`). gomobile's `int` is a 64-bit integer on both
//! sides (Kotlin `Long`), so the descriptor is an `i64` here too.

use std::sync::Arc;

/// `SocketProtector`: called on every socket the engine opens, before it
/// connects or binds. Android's `VpnService.protect`; the iOS extension's
/// interface pin. `false` fails the dial (`socket protector rejected the
/// socket`).
#[uniffi::export(foreign)]
pub trait SocketProtector: Send + Sync {
    /// Protects `fd`; `false` refuses it.
    fn protect(&self, fd: i64) -> bool;
}

/// `SessionListener`: told the room and the id of each session as it opens
/// (the first, and every one after a hop or a reconnect). Not told by a
/// generation that is stopping or no longer current.
#[uniffi::export(foreign)]
pub trait SessionListener: Send + Sync {
    /// A session opened in `room`.
    fn on_session_opened(&self, room: String, session_id: String);
}

/// `LogWriter`: each engine line, as Go's `log` writes it: the
/// `2006/01/02 15:04:05 ` stamp, the text, and the newline (the Android
/// service `trimEnd`s it; the iOS extension stores it as given).
#[uniffi::export(foreign)]
pub trait LogWriter: Send + Sync {
    /// One line.
    fn write_log(&self, msg: String);
}

/// `SetLogWriter` (process-wide, as Go's `log.SetOutput`): every engine line
/// goes to `writer`; `None` sends them to stderr again.
#[uniffi::export]
pub fn set_log_writer(writer: Option<Arc<dyn LogWriter>>) {
    olc_client::log::set_sink(writer.map(|w| -> olc_client::log::Sink {
        Arc::new(move |line: &str| w.write_log(format!("{line}\n")))
    }));
}

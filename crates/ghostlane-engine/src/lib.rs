//! `ghostlane-engine`: Ghostlane's one program for the desktops and the
//! command line. An app starts it as an unprivileged child, hands it a
//! session file and reads its events; the README beside this crate is the
//! contract in full.
//!
//! - [`args`]: the command line. Nothing secret is ever in it.
//! - [`session`]: the session file, mode 0600, with a core half (an Xray
//!   JSON config), a room half, or both.
//! - [`events`]: the lines printed on stdout, one JSON object each, and the
//!   one writer of them.
//! - [`core_run`]: the core half, a line run by `xray-core-rs`.
//! - [`room`], [`front`], [`probe`], [`escape`]: the room half, the core in
//!   front of a room, the one-shot questions and the ways out past a tunnel.
//!   Each is a file of its own with the signatures the program calls.
//!
//! The program itself (`main.rs`) reads the command, starts the halves in
//! order, prints `ready`, and ends on SIGTERM or when its stdin closes.

#![warn(missing_docs)]

pub mod args;
pub mod core_run;
pub mod escape;
#[cfg(target_os = "linux")]
mod escape_linux;
#[cfg(target_os = "macos")]
mod escape_macos;
#[cfg(windows)]
mod escape_windows;
pub mod events;
pub mod front;
pub mod probe;
pub mod room;
pub mod session;

use events::{Events, FailureCode};

/// The commit this build was made from, 40 hex digits, or `unknown` when
/// the source tree had no git and the builder named none (`build.rs`).
pub const PIN: &str = env!("GHOSTLANE_ENGINE_PIN_BUILT");

/// The target this build is for, as rustc names it.
pub const TARGET: &str = env!("GHOSTLANE_ENGINE_TARGET");

/// Whether this build carries the rooms (the `rooms` feature).
#[must_use]
pub fn rooms() -> bool {
    cfg!(feature = "rooms")
}

/// Whether the rooms' DTLS is BoringSSL in this build: asked of the crate
/// that links it. A build without rooms has none.
#[must_use]
pub fn boringssl() -> bool {
    #[cfg(feature = "rooms")]
    {
        olc_rtc::dtls_name() == "boringssl"
    }
    #[cfg(not(feature = "rooms"))]
    {
        false
    }
}

/// Why a command could not do what it was asked: a code the parent can
/// act on and a sentence for a person. The engine's own sentences hold
/// nothing of the session file but the names of its fields; a refusal of the
/// core half is in the config parser's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// What kind of failure it is.
    pub code: FailureCode,
    /// One sentence, in English.
    pub message: String,
}

impl Failure {
    /// A failure of `code`.
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The build does not carry what the session or the command asks for.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(FailureCode::Unsupported, message)
    }

    /// The process's exit status for this failure: 2 for a command line
    /// that was not understood, 1 for everything else.
    #[must_use]
    pub fn exit_status(&self) -> u8 {
        if self.code == FailureCode::Usage {
            2
        } else {
            1
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// What every half of a running session is given.
#[derive(Clone)]
pub struct Ctx {
    /// Where events go.
    pub events: Events,
    /// The way out past a tunnel, when the session names an interface: every
    /// socket but loopback's is bound through it before it connects.
    pub escape: Option<escape::Escape>,
}

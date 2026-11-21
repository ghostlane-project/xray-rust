//! `ghostlane-engine`: Ghostlane's one program for the desktops and the
//! command line. An app starts it as an unprivileged child, hands it a
//! session file and reads its events.
//!
//! Not written yet: this is the events of a core line alone, and a program
//! that refuses every command.

#![warn(missing_docs)]

pub mod events;

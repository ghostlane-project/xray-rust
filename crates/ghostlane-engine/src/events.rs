//! The lines the engine prints on stdout: one JSON object per line, its kind
//! in the `event` field, every field of a kind always present (`null` when
//! it has no value). [`Events`] is the only writer: no other file of the
//! crate writes to stdout, which a test below holds.
//!
//! `tests/fixtures/events.jsonl` is the contract the apps read: every line
//! of it is a line the engine can print, byte for byte, and every kind and
//! every word below is in it. A kind added here without a line there, or a
//! line there the code cannot print, fails the tests of this file.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

/// The version of the contract: the session file read and the events
/// printed. `version` reports it and a session file names it.
pub const PROTOCOL: u32 = 1;

/// Defines an enum of words, each written in JSON as its literal, with the
/// list of all of them.
macro_rules! words {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $word:literal ),* $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $name {
            $( $(#[$vmeta])* #[serde(rename = $word)] $variant ),*
        }

        impl $name {
            /// Every word, as written in JSON.
            pub const ALL: &'static [&'static str] = &[ $( $word ),* ];

            /// The word as written in JSON.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $word ),* }
            }
        }
    };
}

words! {
    /// Which part of the engine a line is about.
    Source {
        /// The core half: the Xray-compatible core.
        Core = "core",
        /// The room half: the olcRTC client.
        Room = "room",
        /// The program itself.
        Engine = "engine",
    }
}

words! {
    /// A log line's level: the core's four severities, and its access log.
    Level {
        /// Debug.
        Debug = "debug",
        /// Info.
        Info = "info",
        /// Warning.
        Warning = "warning",
        /// Error.
        Error = "error",
        /// One accepted or rejected connection.
        Access = "access",
    }
}

words! {
    /// How bad a finding of `check-config` is.
    Severity {
        /// Accepted, with a remark.
        Warning = "warning",
        /// Refused.
        Error = "error",
    }
}

words! {
    /// What kind of failure ended a command.
    FailureCode {
        /// The command line was not understood. Exit status 2.
        Usage = "usage",
        /// The session file could not be read, is open to other users, or
        /// is not a session of this protocol.
        Session = "session",
        /// The core half was refused: by the config parser or by the core.
        Config = "config",
        /// The core could not start (a listener's port is taken, for one).
        Start = "start",
        /// The room half failed: it could not start, or it ended.
        Room = "room",
        /// The sockets could not be bound to the interface the session
        /// names.
        Bind = "bind",
        /// This build does not carry what was asked for.
        Unsupported = "unsupported",
        /// The engine itself failed (no threads, for one).
        Internal = "internal",
    }
}

words! {
    /// Why `run` ended.
    EndReason {
        /// The parent closed the engine's stdin, or died.
        StdinClosed = "stdin_closed",
        /// SIGTERM or SIGINT (Ctrl+C on Windows).
        Signal = "signal",
        /// The session failed: `code` and `message` say how.
        Failed = "failed",
    }
}

/// One listener of a running session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    /// The inbound's tag in the core half; `room` for the SOCKS port of a
    /// room that has no core in front of it; `null` for an untagged inbound.
    pub tag: Option<String>,
    /// Where it listens, `address:port`, the port the system gave when the
    /// session asked for port 0.
    pub address: String,
}

/// One finding about a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// Whether the session is refused for it.
    pub severity: Severity,
    /// The half it is about.
    pub source: Source,
    /// Where in that half, as a path into its JSON; `null` when it is about
    /// the whole.
    pub path: Option<String>,
    /// What is wrong, in English, in the words of the half's own parser.
    pub message: String,
}

/// Defines [`Event`] and the list of its kinds from one list, so that a kind
/// cannot be printed without being in [`Event::KINDS`].
macro_rules! events {
    ( $(
        $(#[$meta:meta])*
        $variant:ident = $kind:literal { $( $(#[$fmeta:meta])* $field:ident : $type:ty ),* $(,)? }
    )* ) => {
        /// One line on stdout.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "event", deny_unknown_fields)]
        pub enum Event {
            $(
                $(#[$meta])*
                #[serde(rename = $kind)]
                $variant { $( $(#[$fmeta])* $field : $type ),* }
            ),*
        }

        impl Event {
            /// Every kind the engine can print, as the `event` field names
            /// it.
            pub const KINDS: &'static [&'static str] = &[ $( $kind ),* ];

            /// This line's kind.
            #[must_use]
            pub fn kind(&self) -> &'static str {
                match self { $( Self::$variant { .. } => $kind ),* }
            }
        }
    };
}

events! {
    /// `version`: what this build is.
    Version = "version" {
        /// The engine's version.
        engine: String,
        /// The contract's version, [`PROTOCOL`].
        protocol: u32,
        /// The commit the build was made from, 40 hex digits, or `unknown`.
        pin: String,
        /// Whether the rooms' DTLS is BoringSSL.
        boringssl: bool,
        /// Whether the build carries the rooms.
        rooms: bool,
        /// The target the build is for.
        target: String,
    }

    /// `check-config`: whether this build accepts the session, and what it
    /// found. Nothing is started.
    CheckConfig = "check_config" {
        /// No finding is an error.
        ok: bool,
        /// The findings, in the order found.
        diagnostics: Vec<Diagnostic>,
    }

    /// The session's sockets leave by this interface from now on. Printed
    /// before `ready`, and again whenever the way out moves.
    Bound = "bound" {
        /// The interface's name.
        interface: String,
    }

    /// The session is accepted with a remark: a finding of the config parser
    /// that is not an error.
    Warning = "warning" {
        /// The half it is about.
        source: Source,
        /// Where in that half; `null` when it is about the whole.
        path: Option<String>,
        /// The remark, in English.
        message: String,
    }

    /// The session serves: every listener is bound, and a room is joined.
    /// Printed once.
    Ready = "ready" {
        /// The listeners.
        inbounds: Vec<Inbound>,
    }

    /// A room session opened: the first, and each one after a hop to
    /// another room or a reconnect.
    SessionOpened = "session_opened" {
        /// The room, as the session file names it.
        room: String,
        /// The session's id.
        session_id: String,
    }

    /// One log line. The core half's `log` object decides which of its lines
    /// are printed.
    Log = "log" {
        /// Whose line it is.
        source: Source,
        /// Its level.
        level: Level,
        /// The line, with no newline in it.
        line: String,
    }

    /// `probe`: one request for a URL through the session's line.
    Probe = "probe" {
        /// The line answered.
        ok: bool,
        /// How long the answer took, milliseconds; `null` when none came.
        millis: Option<u64>,
        /// Why none came; `null` when one did.
        error: Option<String>,
    }

    /// `olc-check`: one join of the session's room.
    OlcCheck = "olc_check" {
        /// The room was joined and its SOCKS port served.
        ok: bool,
        /// How long that took, milliseconds; `null` when it failed.
        millis: Option<u64>,
        /// Why it failed; `null` when it did not.
        error: Option<String>,
    }

    /// `olc-ping`: a join of the session's room, then the best of three
    /// requests through it.
    OlcPing = "olc_ping" {
        /// A request was answered.
        ok: bool,
        /// The best request's time, milliseconds; `null` when none was
        /// answered.
        millis: Option<u64>,
        /// Why none was; `null` when one was.
        error: Option<String>,
    }

    /// A command other than `run` failed, or no command was understood. The
    /// only line of that run.
    Error = "error" {
        /// What kind of failure.
        code: FailureCode,
        /// One sentence, in English.
        message: String,
    }

    /// `run` ended. Always its last line.
    Ended = "ended" {
        /// Why.
        reason: EndReason,
        /// What kind of failure, when the reason is `failed`; else `null`.
        code: Option<FailureCode>,
        /// The failure in one sentence; else `null`.
        message: Option<String>,
    }
}

impl Event {
    /// The line as printed, without its newline.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("an event is plain data")
    }

    /// Reads one printed line.
    ///
    /// # Errors
    /// The line is not an event of this protocol.
    pub fn from_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }
}

/// The writer of events: one line at a time, whole, flushed. After `ended`
/// it writes nothing more, so that line is the last of a run whoever asks
/// for it first.
#[derive(Clone)]
pub struct Events {
    inner: Arc<Inner>,
}

struct Inner {
    out: Mutex<Box<dyn Write + Send>>,
    ended: AtomicBool,
}

impl Events {
    /// Events to the parent: the process's stdout.
    #[must_use]
    pub fn parent() -> Self {
        Self::to(Box::new(std::io::stdout()))
    }

    /// Events to `out`.
    #[must_use]
    pub fn to(out: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(Inner {
                out: Mutex::new(out),
                ended: AtomicBool::new(false),
            }),
        }
    }

    /// Prints one event. A parent that no longer reads is not an error here:
    /// the engine ends when its stdin closes.
    pub fn emit(&self, event: &Event) {
        let mut line = event.to_line();
        line.push('\n');
        let mut out = self
            .inner
            .out
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.inner.ended.load(Ordering::Relaxed) {
            return;
        }
        if matches!(event, Event::Ended { .. }) {
            self.inner.ended.store(true, Ordering::Relaxed);
        }
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    /// A log line of the engine's own.
    pub fn log(&self, level: Level, line: impl Into<String>) {
        self.emit(&Event::Log {
            source: Source::Engine,
            level,
            line: line.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;

    const FIXTURE: &str = include_str!("../tests/fixtures/events.jsonl");

    fn fixture() -> Vec<(usize, &'static str, Event)> {
        FIXTURE
            .lines()
            .enumerate()
            .map(|(index, line)| {
                let event = Event::from_line(line).unwrap_or_else(|error| {
                    panic!(
                        "events.jsonl line {}: the engine cannot print this line: {error}\n{line}",
                        index + 1
                    )
                });
                (index + 1, line, event)
            })
            .collect()
    }

    #[test]
    fn every_fixture_line_is_a_line_the_engine_prints_byte_for_byte() {
        let lines = fixture();
        assert!(!lines.is_empty(), "the fixture is empty");
        for (number, line, event) in lines {
            assert_eq!(
                event.to_line(),
                line,
                "events.jsonl line {number}: the engine prints this event differently"
            );
            let named: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(named["event"], event.kind(), "events.jsonl line {number}");
        }
    }

    #[test]
    fn the_fixture_and_the_code_hold_the_same_kinds() {
        let code: BTreeSet<&str> = Event::KINDS.iter().copied().collect();
        assert_eq!(code.len(), Event::KINDS.len(), "a kind is listed twice");
        let fixture: BTreeSet<&str> = fixture().iter().map(|(_, _, event)| event.kind()).collect();
        let unlisted: Vec<_> = code.difference(&fixture).collect();
        assert!(
            unlisted.is_empty(),
            "the engine can print kinds the fixture lacks: {unlisted:?}"
        );
        // A kind the code cannot print does not parse (the test above), so
        // the two sets are equal here.
        assert_eq!(code, fixture);
    }

    #[test]
    fn a_kind_the_code_cannot_print_is_refused() {
        let error = Event::from_line(r#"{"event":"no_such_kind"}"#).unwrap_err();
        assert!(error.to_string().contains("no_such_kind"), "{error}");
        // A field the kind does not have, and a field left out.
        assert!(Event::from_line(r#"{"event":"bound","interface":"eth0","index":2}"#).is_err());
        assert!(Event::from_line(r#"{"event":"bound"}"#).is_err());
    }

    #[test]
    fn every_word_is_in_the_fixture() {
        let text: Vec<serde_json::Value> = FIXTURE
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let seen = |field: &str| -> BTreeSet<String> {
            let mut words = BTreeSet::new();
            for line in &text {
                let mut holders = vec![line];
                if let Some(list) = line.get("diagnostics").and_then(|list| list.as_array()) {
                    holders.extend(list);
                }
                for holder in holders {
                    if let Some(word) = holder.get(field).and_then(|word| word.as_str()) {
                        words.insert(word.to_owned());
                    }
                }
            }
            words
        };
        let all = |words: &[&str]| -> BTreeSet<String> {
            words.iter().map(|word| (*word).to_owned()).collect()
        };
        assert_eq!(seen("source"), all(Source::ALL), "source");
        assert_eq!(seen("level"), all(Level::ALL), "level");
        assert_eq!(seen("severity"), all(Severity::ALL), "severity");
        assert_eq!(seen("code"), all(FailureCode::ALL), "code");
        assert_eq!(seen("reason"), all(EndReason::ALL), "reason");
        assert_eq!(Source::Core.as_str(), "core");
    }

    #[test]
    fn nothing_is_printed_after_ended() {
        #[derive(Clone, Default)]
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let shared = Shared::default();
        let events = Events::to(Box::new(shared.clone()));
        let ended = |reason| Event::Ended {
            reason,
            code: None,
            message: None,
        };
        events.log(Level::Info, "one");
        events.emit(&ended(EndReason::StdinClosed));
        events.emit(&ended(EndReason::Signal));
        events.log(Level::Info, "two");
        let printed = String::from_utf8(shared.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            printed,
            "{\"event\":\"log\",\"source\":\"engine\",\"level\":\"info\",\"line\":\"one\"}\n\
             {\"event\":\"ended\",\"reason\":\"stdin_closed\",\"code\":null,\"message\":null}\n"
        );
    }

    /// Every file under `src/` but this one: no line of code writes to
    /// stdout, so a line the parent reads is always an [`Event`].
    #[test]
    fn this_file_is_the_only_writer_to_stdout() {
        fn walk(dir: &Path, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, found);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "rs")
                    || path.file_name().is_some_and(|name| name == "events.rs")
                {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for (index, line) in text.lines().enumerate() {
                    let code = line.trim_start();
                    if code.starts_with("//") {
                        continue;
                    }
                    let prints = ["print!(", "println!("].iter().any(|needle| {
                        code.match_indices(needle)
                            .any(|(at, _)| !code[..at].ends_with('e'))
                    });
                    if prints || code.contains("stdout") {
                        found.push(format!("{}:{}: {code}", path.display(), index + 1));
                    }
                }
            }
        }
        let mut found = Vec::new();
        walk(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );
        assert!(
            found.is_empty(),
            "only events.rs may write to stdout:\n{}",
            found.join("\n")
        );
    }
}

//! The command line: a command, the session file, and the command's own
//! flags, each `--name value`. Nothing secret is ever an argument: what is
//! secret is in the session file.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::events::FailureCode;
use crate::{probe, Failure};

/// What the program says on stderr when its arguments are not understood.
pub const USAGE: &str = "usage: ghostlane-engine run --session <file>
       ghostlane-engine check-config --session <file>
       ghostlane-engine probe --session <file> --url <url> [--timeout-ms <n>] [--outbound <tag>]
       ghostlane-engine olc-check --session <file> [--timeout-ms <n>]
       ghostlane-engine olc-ping --session <file> --url <url> [--timeout-ms <n>]
       ghostlane-engine version

run serves the session until SIGTERM or until its stdin closes; the other
commands answer once. Every answer is a JSON line on the standard output.";

/// The commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Serve a session until told to stop.
    Run,
    /// Say whether this build accepts a session, starting nothing.
    CheckConfig,
    /// One request for a URL through the session's line.
    Probe,
    /// One join of the session's room.
    OlcCheck,
    /// One join of the session's room and three requests through it.
    OlcPing,
    /// Say what this build is.
    Version,
}

impl Command {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "run" => Self::Run,
            "check-config" => Self::CheckConfig,
            "probe" => Self::Probe,
            "olc-check" => Self::OlcCheck,
            "olc-ping" => Self::OlcPing,
            "version" => Self::Version,
            _ => return None,
        })
    }

    /// The flags the command takes besides `--session`.
    fn flags(self) -> &'static [&'static str] {
        match self {
            Self::Run | Self::CheckConfig | Self::Version => &[],
            Self::Probe => probe::PROBE_FLAGS,
            Self::OlcCheck => probe::OLC_CHECK_FLAGS,
            Self::OlcPing => probe::OLC_PING_FLAGS,
        }
    }
}

/// A command's own flags, by name without the dashes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags(BTreeMap<String, String>);

impl Flags {
    /// The value given for `--name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// The value given for `--name`.
    ///
    /// # Errors
    /// [`FailureCode::Usage`] when the flag was not given.
    pub fn required(&self, name: &str) -> Result<&str, Failure> {
        self.get(name)
            .ok_or_else(|| usage(format!("`--{name}` is missing")))
    }

    /// The whole number given for `--name`, or `default` when it was not.
    ///
    /// # Errors
    /// [`FailureCode::Usage`] when the value is not a whole number.
    pub fn number(&self, name: &str, default: u64) -> Result<u64, Failure> {
        match self.get(name) {
            None => Ok(default),
            Some(text) => text
                .parse()
                .map_err(|_| usage(format!("`--{name}` takes a whole number"))),
        }
    }
}

/// One run of the program, as its arguments ask for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The command.
    pub command: Command,
    /// The session file: there for every command but `version`.
    pub session: Option<PathBuf>,
    /// The command's own flags.
    pub flags: Flags,
}

fn usage(message: impl Into<String>) -> Failure {
    Failure::new(FailureCode::Usage, message)
}

/// Reads the arguments after the program's name.
///
/// # Errors
/// [`FailureCode::Usage`]: no command or an unknown one, a flag the command
/// does not take or takes once, a flag with no value, or no session file.
pub fn parse(arguments: &[String]) -> Result<Invocation, Failure> {
    let Some((name, rest)) = arguments.split_first() else {
        return Err(usage("no command"));
    };
    let command = Command::named(name).ok_or_else(|| usage(format!("unknown command `{name}`")))?;
    let mut session = None;
    let mut flags = BTreeMap::new();
    let mut rest = rest.iter();
    while let Some(argument) = rest.next() {
        let Some(flag) = argument.strip_prefix("--") else {
            return Err(usage(format!(
                "`{name}` takes flags only, each `--name value`"
            )));
        };
        let known =
            (flag == "session" && command != Command::Version) || command.flags().contains(&flag);
        if !known {
            return Err(usage(format!("`{name}` takes no `--{flag}`")));
        }
        let Some(value) = rest.next() else {
            return Err(usage(format!("`--{flag}` has no value")));
        };
        let given_twice = if flag == "session" {
            session.replace(PathBuf::from(value)).is_some()
        } else {
            flags.insert(flag.to_owned(), value.clone()).is_some()
        };
        if given_twice {
            return Err(usage(format!("`--{flag}` is given twice")));
        }
    }
    if session.is_none() && command != Command::Version {
        return Err(usage(format!("`{name}` needs `--session <file>`")));
    }
    Ok(Invocation {
        command,
        session,
        flags: Flags(flags),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(line: &str) -> Result<Invocation, Failure> {
        let arguments: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        parse(&arguments)
    }

    fn refusal(line: &str) -> String {
        let failure = read(line).unwrap_err();
        assert_eq!(failure.code, FailureCode::Usage, "{line}");
        assert_eq!(failure.exit_status(), 2);
        failure.message
    }

    #[test]
    fn each_command_reads_its_session_and_its_own_flags() {
        let run = read("run --session /tmp/s.json").unwrap();
        assert_eq!(run.command, Command::Run);
        assert_eq!(run.session.unwrap(), PathBuf::from("/tmp/s.json"));
        assert_eq!(read("version").unwrap().session, None);
        assert_eq!(
            read("check-config --session s").unwrap().command,
            Command::CheckConfig
        );
        let probe = read("probe --url http://example.com/ --session s --timeout-ms 900").unwrap();
        assert_eq!(probe.command, Command::Probe);
        assert_eq!(probe.flags.get("url"), Some("http://example.com/"));
        assert_eq!(probe.flags.required("url").unwrap(), "http://example.com/");
        assert_eq!(probe.flags.number("timeout-ms", 5000).unwrap(), 900);
        assert_eq!(probe.flags.get("outbound"), None);
        let check = read("olc-check --session s").unwrap();
        assert_eq!(check.command, Command::OlcCheck);
        assert_eq!(check.flags.number("timeout-ms", 5000).unwrap(), 5000);
        assert_eq!(
            read("olc-ping --session s --url http://example.com/")
                .unwrap()
                .command,
            Command::OlcPing
        );
    }

    #[test]
    fn what_is_not_understood_is_a_usage_failure() {
        assert_eq!(refusal(""), "no command");
        assert_eq!(refusal("start"), "unknown command `start`");
        assert_eq!(refusal("run"), "`run` needs `--session <file>`");
        assert_eq!(refusal("run --session"), "`--session` has no value");
        assert_eq!(
            refusal("run s.json"),
            "`run` takes flags only, each `--name value`"
        );
        assert_eq!(
            refusal("run --session a --session b"),
            "`--session` is given twice"
        );
        assert_eq!(refusal("run --session a --url u"), "`run` takes no `--url`");
        assert_eq!(
            refusal("version --session a"),
            "`version` takes no `--session`"
        );
        assert_eq!(
            refusal("probe --session a --url u --url v"),
            "`--url` is given twice"
        );
        let probe = read("probe --session a --timeout-ms soon").unwrap();
        let failure = probe.flags.number("timeout-ms", 1).unwrap_err();
        assert_eq!(failure.message, "`--timeout-ms` takes a whole number");
        assert_eq!(
            probe.flags.required("url").unwrap_err().message,
            "`--url` is missing"
        );
    }
}

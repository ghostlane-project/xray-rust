# ghostlane-engine

Ghostlane's one program for macOS, Linux, Windows and the command-line
client. An app starts it as an unprivileged child process, gives it a session
file, and reads what it prints. On phones the same cores are a library inside
the app (`ghostlane-core`); this crate is that library's desktop form.

It is a member of this workspace so that it is built with the workspace's
lock file and its patched dependencies.

## The command line

```text
ghostlane-engine run --session <file>
ghostlane-engine check-config --session <file>
ghostlane-engine probe --session <file> --url <url> [--timeout-ms <n>] [--outbound <tag>]
ghostlane-engine olc-check --session <file> [--timeout-ms <n>]
ghostlane-engine olc-ping --session <file> --url <url> [--timeout-ms <n>]
ghostlane-engine version
```

- `run` serves a session until it is told to stop.
- `check-config` says whether this build accepts a session. It starts nothing.
- `probe`, `olc-check` and `olc-ping` each ask one question in a process of
  their own and print one line.
- `version` prints the commit the build was made from (the pin), whether the
  rooms are built in, and whether their DTLS is BoringSSL.

Nothing secret is ever an argument. Keys, passwords and room addresses are in
the session file.

Exit status: 0 after a stop that was asked for or an answer that is a yes,
1 after a failure or an answer that is a no, 2 when the command line was not
understood (the usage text is then on stderr).

## The session file

A JSON file that the parent writes with mode 0600 and names with `--session`.
On Unix the engine refuses a file that its group or other users can read or
write.

```json
{
  "version": 1,
  "core": { "inbounds": [], "outbounds": [] },
  "room": { },
  "bind": { "interface": "eth0" },
  "geodata_dir": "/path/to/lists"
}
```

| Field | Meaning |
|---|---|
| `version` | The contract's version. This engine reads 1, and `version` prints it as `protocol`. |
| `core` | The core half: an Xray JSON config. Alone, the session is a core line. |
| `room` | The room half. Alone, the session is a room whose SOCKS port the parent uses directly. With `core`, the core runs in front of the room in the same process, and its rules decide what goes to the room. |
| `bind` | The interface every socket but loopback's leaves by, for when a tunnel holds the default route. |
| `geodata_dir` | The one directory `ext:` and `geosite:` lists are read from. Without it the core searches the working directory, then the program's own. |

`core` or `room` must be present, and a half that is `null` is absent. A field
the engine does not know is refused.

## How it stops

`run` ends on SIGTERM or SIGINT (Ctrl+C on Windows), and when its stdin
closes. A parent that dies closes it, so an engine never outlives its parent.
There is no command channel: bytes read from stdin are ignored.

The parent must therefore hold the engine's stdin open as a pipe. Started with
stdin at end of file (`< /dev/null`, or a shell's background job), `run` ends
at once. From a shell script, hold a pipe open:

```sh
mkfifo hold
exec 9<>hold
ghostlane-engine run --session session.json <&9 &
# ...
exec 9>&-    # the engine ends
```

The process is gone within two seconds of being told to stop: it closes what
it holds, prints `ended`, and exits; if a half does not stop in time the
process ends anyway.

## Events

One JSON object per line on stdout. The `event` field names the kind, and
every field of a kind is always present, `null` when it has no value. stderr
is for people and is no part of the contract.

| `event` | Printed by | Fields |
|---|---|---|
| `version` | `version` | `engine`, `protocol`, `pin` (40 hex digits, or `unknown`), `boringssl`, `rooms`, `target` |
| `check_config` | `check-config` | `ok`, `diagnostics`: each `severity` (`warning`, `error`), `source`, `path`, `message` |
| `bound` | `run` | `interface`: the session's sockets leave by it. Before `ready`, and again whenever the way out moves |
| `warning` | `run` | `source`, `path`, `message`: the session is accepted with a remark |
| `ready` | `run` | `inbounds`: each `tag` and `address` as bound. Printed once, when every listener is bound and a room is joined |
| `session_opened` | `run` | `room`, `session_id`: a room session opened, the first and each one after a hop or a reconnect |
| `log` | `run` | `source`, `level` (`debug`, `info`, `warning`, `error`, `access`), `line` |
| `probe` | `probe` | `ok`, `millis`, `error` |
| `olc_check` | `olc-check` | `ok`, `millis`, `error` |
| `olc_ping` | `olc-ping` | `ok`, `millis`, `error` |
| `error` | every command but `run` | `code`, `message`: the command failed. The only line of that run |
| `ended` | `run` | `reason` (`stdin_closed`, `signal`, `failed`), `code`, `message`. Always the last line |

`source` is `core`, `room` or `engine`. A failure's `code` is one of `usage`,
`session`, `config`, `start`, `room`, `bind`, `unsupported`, `internal`.

The core half's own `log` object decides which of its lines are printed, as it
decides for a log file: `loglevel`, and `access` for one line per connection.

`tests/fixtures/events.jsonl` holds lines of every kind with every word above.
The crate's tests hold it to the code both ways: every line of the fixture is
a line the engine prints byte for byte, and no kind or word exists in the code
without a line there. An app's parser can be tested against the same file.

## Features

- `rooms` (on by default): the room half and the room one-shots. Without it
  no olc crate is built, and a session with a room half is refused.
- `boring`: the rooms' DTLS from BoringSSL. The shipped engine is built with
  it; it needs cmake and libclang.

The pin `version` prints is the `GHOSTLANE_ENGINE_PIN` environment variable of
the build when it is set (40 hex digits), else the commit of the checkout the
build was made in, else `unknown`.

## What is built

The core half is: `run` and `check-config` for a core line, and `version`.
The room half (`src/room.rs`), the core in front of a room (`src/front.rs`),
the one-shot questions (`src/probe.rs`) and the binding of sockets to an
interface (`src/escape_linux.rs`, `src/escape_macos.rs`,
`src/escape_windows.rs`) are files with their signatures in place that refuse
with `unsupported` until each is written.

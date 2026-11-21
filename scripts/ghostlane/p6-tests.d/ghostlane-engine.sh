#!/usr/bin/env bash
# ghostlane-engine.sh <host|windows-report>
#
# A drop-in of p6-ci.sh for crates/ghostlane-engine, the one program the
# desktops and the command line run.
#
#   host            1. the crate is formatted;
#                   2. as shipped, with the rooms and BoringSSL: its tests (the
#                      events fixture against the code, the session file, the
#                      command line, and the program as a child process on
#                      loopback: a fetch through its line, an end within two
#                      seconds of its stdin closing), and `version` prints
#                      this commit and BoringSSL;
#                   3. without the `rooms` feature: no olc crate and no
#                      BoringSSL is in the build (cargo tree), the same tests
#                      pass, and `version` says so.
#                   Every step runs; one that fails fails the script.
#   windows-report  `cargo check`s the engine without rooms, which is what a
#                   Windows build gets first, and says in the job summary
#                   whether it builds. It never fails: the crates under it do
#                   not all compile for Windows yet.
set -uo pipefail
mode="${1:?usage: ghostlane-engine.sh host|windows-report}"
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
export CARGO_TERM_COLOR=never

if [ "$mode" = windows-report ]; then
    out="$(mktemp)"
    status=0
    cargo check --locked -p ghostlane-engine --no-default-features --message-format=short > "$out" 2>&1 || status=$?
    tail -n 40 "$out"
    {
        echo "### ghostlane-engine without rooms on Windows"
        echo
        if [ "$status" = 0 ]; then
            echo "\`cargo check -p ghostlane-engine --no-default-features\` passes."
        else
            echo "\`cargo check -p ghostlane-engine --no-default-features\` fails (cargo status $status): $(grep -c '^error' "$out") error lines, the first:"
            echo
            echo '```'
            grep -m 5 '^error' "$out" | cut -c1-300
            echo '```'
        fi
    } >> "$summary"
    exit 0
fi
[ "$mode" = host ] || exit 0

bad=0
step() {
    local name="$1"
    shift
    echo "== ghostlane-engine: $name"
    if "$@"; then
        echo "ok: $name"
    else
        echo "FAILED: $name" >&2
        bad=1
    fi
}

engine="${CARGO_TARGET_DIR:-target}/debug/ghostlane-engine"

# version_says <rooms true|false> <boringssl true|false>: the binary the last
# cargo test built prints this commit as its pin, and these two answers.
version_says() {
    local line
    line="$("$engine" version < /dev/null)" || return 1
    echo "$line"
    python3 -I - "$line" "$(git rev-parse HEAD)" "$1" "$2" <<'PY'
import json, sys
line, head, rooms, boring = sys.argv[1:5]
said = json.loads(line)
want = {"event": "version", "pin": head, "rooms": rooms == "true", "boringssl": boring == "true"}
bad = {key: (said.get(key), value) for key, value in want.items() if said.get(key) != value}
if bad:
    sys.exit("version says otherwise, (said, wanted): %r" % bad)
PY
}

# Without rooms, nothing of olc and no BoringSSL is among the crates the
# engine is built from (its own and its build scripts', every platform); with
# them, the same listing shows olc-ffi, so the check can see what it rules out.
no_olc_without_rooms() {
    local without with
    without="$(cargo tree --locked -p ghostlane-engine --no-default-features --target all -e normal,build --prefix none | sed 's/ .*//' | sort -u)" || return 1
    if echo "$without" | grep -E '^(olc-|boring)'; then
        echo "without rooms the build still holds the crates above" >&2
        return 1
    fi
    echo "$without" | grep -qx 'xray-core-rs' || { echo "the listing does not show the core" >&2; return 1; }
    with="$(cargo tree --locked -p ghostlane-engine --features boring --target all -e normal,build --prefix none | sed 's/ .*//' | sort -u)" || return 1
    echo "$with" | grep -qx 'olc-ffi' || { echo "with rooms the listing does not show olc-ffi" >&2; return 1; }
    echo "$with" | grep -qx 'boring-sys' || { echo "with BoringSSL the listing does not show boring-sys" >&2; return 1; }
    echo "$(echo "$without" | wc -l | tr -d ' ') crates without rooms, $(echo "$with" | wc -l | tr -d ' ') with rooms and BoringSSL"
}

step "formatted" cargo fmt -p ghostlane-engine -- --check
step "tests, with rooms and BoringSSL" cargo test --locked --no-fail-fast -p ghostlane-engine --features boring
step "version, with rooms and BoringSSL" version_says true true
step "no olc crate without rooms" no_olc_without_rooms
step "tests, without rooms" cargo test --locked --no-fail-fast -p ghostlane-engine --no-default-features
step "version, without rooms" version_says false false

{
    echo "### ghostlane-engine ($(uname -s))"
    echo
    if [ "$bad" = 0 ]; then
        echo "Formatted; its tests pass with rooms and BoringSSL and without rooms; \`version\` prints the commit and BoringSSL; without rooms no olc crate is in the build."
    else
        echo "A step failed: see the log of this job."
    fi
} >> "$summary"
exit "$bad"

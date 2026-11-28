#!/usr/bin/env bash
# windows-engine.sh <host|windows-report>
#
# A drop-in of p6-ci.sh: the engine on Windows, the rooms built in.
#
#   windows-report  `cargo test -p ghostlane-engine` with its default features
#                   (the rooms, no BoringSSL: the shipped Windows engine's
#                   build). That builds the engine and the olc crates under it
#                   for the Windows target and runs the engine's unit tests
#                   (the escape: a socket leaves by IP_UNICAST_IF, read back
#                   with getsockopt; an interface that is not there is
#                   refused) and its loopback end-to-end tests (the program as
#                   a child process: a fetch through its line, an end within
#                   two seconds of its stdin closing).
#   host            nothing: the other systems run ghostlane-engine.sh.
set -uo pipefail
mode="${1:?usage: windows-engine.sh host|windows-report}"
[ "$mode" = windows-report ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

status=0
cargo test --locked --no-fail-fast -p ghostlane-engine || status=$?
{
    echo "### ghostlane-engine with rooms on Windows"
    echo
    if [ "$status" = 0 ]; then
        echo "\`cargo test -p ghostlane-engine\` passes: the engine and its rooms build, the loopback end-to-end tests pass, and a socket leaves by IP_UNICAST_IF."
    else
        echo "\`cargo test -p ghostlane-engine\` fails (cargo status $status): see the log of this job."
    fi
} >> "$summary"
exit "$status"

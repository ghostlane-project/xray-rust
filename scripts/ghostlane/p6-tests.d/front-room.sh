#!/usr/bin/env bash
# front-room.sh <host|windows-report>
#
# A drop-in of p6-ci.sh for ghostlane-engine's front: a session with both
# halves, the core in front of a room on the `none` carrier, in one process,
# with its sockets bound (crates/ghostlane-engine/tests/netns_front.sh).
#
#   host            on Linux only (the ubuntu leg; it needs passwordless sudo,
#                   which GitHub's ubuntu runners have):
#                   1. builds the engine as it ships (release, with the rooms
#                      and BoringSSL; netns-escape.sh builds the same);
#                   2. builds the room's far side, the olcRTC server: the Go
#                      engine at the interop pin (olc/interop/lib.sh) with
#                      the overlay, which gives it the interop pipe the
#                      `none` carrier's rooms run on, and the test hooks,
#                      which let it reach the test's private addresses. The
#                      runner's Go fetches the toolchain the engine's go.mod
#                      names (GOTOOLCHAIN=auto);
#                   3. runs netns_front.sh as root with both: in network
#                      namespaces whose default route is a tunnel, the
#                      core's rules send TCP and a datagram to the room
#                      through its `socks` outbound and one name direct, a
#                      LAN inbound refuses a client with no login, and no
#                      socket but loopback's leaves by another interface
#                      than the one the session names.
#                   A runner where no namespace can be made, or where the
#                   server does not build, fails the step: it is not
#                   skipped. Other systems have nothing to run.
#   windows-report  nothing: the engine binds no socket on Windows yet.
set -uo pipefail
mode="${1:?usage: front-room.sh host|windows-report}"
[ "$mode" = host ] || exit 0
[ "$(uname -s)" = Linux ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
export CARGO_TERM_COLOR=never

shipped="${CARGO_TARGET_DIR:-target}/release/ghostlane-engine"
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/front-room.XXXXXX")"
trap 'rm -rf "$work"' EXIT
server="$work/olcrtc"
bad=0
built="not built"
front="not run"

echo "== front-room: build the engine as it ships (release), with rooms and BoringSSL"
if ! cargo build --locked --release -p ghostlane-engine --features boring; then
    echo "FAILED: the release engine does not build" >&2
    built="the engine does not build"
    bad=1
fi

if [ "$bad" = 0 ]; then
    echo "== front-room: build the olcRTC server at the interop pin"
    go="$(command -v go || true)"
    if [ -z "$go" ]; then
        # The runner's newest Go when none is on the path.
        for root in $(env | sed -n 's/^GOROOT_[0-9_]*_X64=//p' | sort -V); do
            [ -x "$root/bin/go" ] && go="$root/bin/go"
        done
    fi
    if [ -z "$go" ]; then
        echo "FAILED: no Go on this runner" >&2
        built="no Go on this runner"
        bad=1
    else
        # Not in a condition: there `set -e` would not hold in the subshell.
        (
            set -e
            # shellcheck source=../../../olc/interop/lib.sh
            . olc/interop/lib.sh
            engine="$work/engine"
            olc_prepare "$engine"
            cd "$engine"
            GOTOOLCHAIN=auto GOFLAGS=-mod=readonly "$go" build -trimpath -buildvcs=false \
                -tags olcrtc_testhooks,"$OLC_GO_TAGS" -o "$server" ./cmd/olcrtc
            olc_guard "$engine"
            echo "built the olcRTC server at $OLC_PIN with $(GOTOOLCHAIN=auto "$go" version)"
        )
        if [ "$?" = 0 ] && [ -x "$server" ]; then
            built="the engine and the olcRTC server built"
        else
            echo "FAILED: the olcRTC server does not build" >&2
            built="the olcRTC server does not build"
            bad=1
        fi
    fi
fi

if [ "$bad" = 0 ]; then
    echo "== front-room: a core in front of a room, in one process, bound"
    if ! sudo -n true; then
        front="no passwordless sudo on this runner: no namespace can be made"
        echo "FAILED: $front" >&2
        bad=1
    elif sudo -n bash crates/ghostlane-engine/tests/netns_front.sh "$shipped" "$server"; then
        front="every case passed"
        echo "ok: the namespace test"
    else
        front="a case failed: see the log of this job"
        echo "FAILED: the namespace test" >&2
        bad=1
    fi
fi

{
    echo "### ghostlane-engine: a core in front of a room"
    echo
    echo "- Builds: $built."
    echo "- The namespace test, on the release build: $front."
} >> "$summary"
exit "$bad"

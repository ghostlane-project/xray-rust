#!/usr/bin/env bash
# escape-peer.sh <host|windows-report>
#
# A drop-in of p6-ci.sh. The socket protector is told the peer
# (SocketProtector::protect_to), so the engine's way out leaves loopback
# unbound:
#
#   host            1. xray-transport, xray-core-rs and olc-net are formatted;
#                   2. the peer reaches the protector: a TCP dial (IPv4, IPv6,
#                      a mapped address, Multipath TCP on Linux), the UDP
#                      helpers that know it, `sockopt` around the platform's
#                      protector, the SOCKS outbound's relay socket, olc-net's
#                      dial; and a protector that implements only `protect`
#                      (the phones') is handed every socket as before, once
#                      each and in the same order;
#                   3. on Linux, every test of those three crates, as
#                      upstream's CI runs them (all targets, no doc tests).
#                   The engine's own test (tests/escape_peer.rs: a front's
#                   dials to its room on loopback never reach the binder, its
#                   dials elsewhere do) runs in ghostlane-engine.sh.
#                   Every step runs; one that fails fails the script.
#   windows-report  nothing to add to the report.
#
# bash 3.2 safe (macOS).
set -uo pipefail
mode="${1:?usage: escape-peer.sh host|windows-report}"
[ "$mode" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never

bad=0
step() {
    local name="$1"
    shift
    echo "== escape-peer: $name"
    if "$@"; then
        echo "ok: $name"
    else
        echo "FAILED: $name" >&2
        bad=1
    fi
}

step "formatted" cargo fmt -p xray-transport -p xray-core-rs -p olc-net -- --check
step "the transport tells the peer" cargo test --locked --no-fail-fast -p xray-transport --test protect_to_tests
step "the SOCKS relay socket is told its server" cargo test --locked -p xray-core-rs --lib -- outbound::socks::tests
step "olc-net tells the peer" cargo test --locked --no-fail-fast -p olc-net --test peer_protector
if [ "$(uname -s)" = Linux ]; then
    step "every test of the three crates" cargo test --locked --no-fail-fast -p xray-transport -p xray-core-rs -p olc-net --all-targets
fi
exit "$bad"

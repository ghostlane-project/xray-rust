#!/usr/bin/env bash
# jitsi.sh --dry
# jitsi.sh <rust-client-bin|-> <gate|rust|go> [go test flags...]
#
# T2 for the Jitsi carrier: the Rust client against the Go fake of a Jitsi
# Meet room (Prosody and Jicofo over a WebSocket, one pion peer per
# participant as the JVB; internal/engine/jitsifake). No Jitsi deployment is
# contacted and no room is used. Run it on the build box, never on DATA:
#   go-remote.sh olc-w2-jitsi-go <repo>/olc/interop bash jitsi.sh <bin> gate
#
#   --dry the engine at the pin plus the overlay, gofmt, go vet with and
#         without olcrtc_lean over the carrier's packages and the gate, and
#         which of the sets below the overlay holds today; runs no test;
#   gate  TestGateRustJitsiFake (internal/gate/zz_rust_jitsifake_test.go):
#         S0-S7 over datachannel on the jitsifake target, the Go server
#         (engine jitsi) and the client in one room of the fake; it also
#         reads the client's log lines for the room name, the JID and
#         stanzas, and logs the client's heap peak and VmHWM beside the Go
#         client's. -olcrtc.gate-flavours=rust,cli adds the Go baseline (a
#         process of its own; p2p.sh says how, and its three flags);
#   rust  the TestRustJitsi* tests (internal/engine/jitsifake): the Rust
#         client against the fake with one Go engine in the room;
#   go    the engine's own tests of internal/auth/jitsi and
#         internal/engine/jitsi, the baseline the rust ones are read against,
#         and the fake's own tests (TestGoJitsiFakeJoin, TestGoJitsiFakePair:
#         the Go engine at the pin passing through it) ("-" for the binary).
# A set whose tests the overlay does not hold yet fails, it does not pass
# empty. Extra flags go to go test; -run=<re> replaces the set's own.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

OLC_CARRIER=jitsi
OLC_GATE_TARGET=jitsifake
OLC_GATE_RUN='^(TestGateRustJitsiFake|TestJitsiLogWatchReadsSecrets)$'
OLC_RUST_PKG=./internal/engine/jitsifake
OLC_RUST_RUN='^TestRustJitsi'
OLC_GO_PKGS=(./internal/auth/jitsi ./internal/engine/jitsi ./internal/engine/jitsifake)
olc_carrier_main "$@"

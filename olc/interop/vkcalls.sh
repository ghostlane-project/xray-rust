#!/usr/bin/env bash
# vkcalls.sh --dry
# vkcalls.sh <rust-client-bin|-> <gate|rust|go> [go test flags...]
#
# T2 for the VK Calls carrier: the Rust client against fakes of VK Calls (the
# engine's fake signalling at the pin and the overlay's media-capable fake
# SFU, pion as the offerer). No VK service is contacted and no room or
# account is used. Run it on the build box, never on DATA:
#   go-remote.sh olc-c-interop-go <repo>/olc/interop bash vkcalls.sh <bin> gate
#
#   --dry the engine at the pin plus the overlay, gofmt, go vet with and
#         without olcrtc_lean over the carrier's packages and the gate, and
#         which of the sets below the overlay holds today; runs no test and
#         needs no client;
#   gate  TestGateRustVKFake (internal/gate): S0-S5 over VP8 wrapped in RED
#         on the vkfake target, the Go server (engine vkcalls) and the client
#         at one fake SFU; -olcrtc.gate-flavours=rust,cli adds the Go
#         baseline, a process of its own (p2p.sh says how, and its three
#         flags);
#   rust  the TestRustVK* tests (internal/engine/vkcalls): the Rust client's
#         join, its three commands and its packets as the fake SFU sees them;
#   go    the engine's own tests of internal/auth/vkcalls and
#         internal/engine/vkcalls, the baseline the rust ones are read
#         against ("-" for the binary).
# A set whose tests the overlay does not hold yet fails, it does not pass
# empty. Extra flags go to go test; -run=<re> replaces the set's own.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

OLC_CARRIER=vkcalls
OLC_GATE_TARGET=vkfake
OLC_GATE_RUN='^TestGateRustVKFake$'
OLC_RUST_PKG=./internal/engine/vkcalls
OLC_RUST_RUN='^TestRustVK'
OLC_GO_PKGS=(./internal/auth/vkcalls ./internal/engine/vkcalls)
olc_carrier_main "$@"

#!/usr/bin/env bash
# mtslink.sh --dry
# mtslink.sh <rust-client-bin|-> <gate|rust|go> [go test flags...]
#
# T2 for the MTS Link carrier: the Rust client against the engine's fakes of
# MTS Link at the pin (a gateway and an SFU on loopback, pion as the SFU's
# peer). No MTS Link service is contacted and no room or account is used. Run
# it on the build box, never on DATA:
#   go-remote.sh olc-w2-mts-go <repo>/olc/interop bash mtslink.sh <bin> gate
#
#   --dry the engine at the pin plus the overlay, gofmt, go vet with and
#         without olcrtc_lean over the carrier's packages and the gate, and
#         which of the sets below the overlay holds today; runs no test and
#         needs no client;
#   gate  TestGateRustMTSFake (internal/gate/zz_rust_mtsfake_test.go): S0-S5
#         over VP9 on the mtsfake target, the Go server (engine mtslink on
#         direct credentials, over UDP) and the client in one room of the
#         forwarding fake SFU (internal/engine/mtslinkfake); it also holds
#         what the room saw, reads the client's log lines for the join's
#         secrets, and logs the client's heap peak (a build with the
#         heap-stats feature says it) and VmHWM. With it run the two tests
#         that hold those checks to what they name.
#         -olcrtc.gate-flavours=rust,cli adds the Go baseline, a process
#         of its own (p2p.sh says how, and its three flags);
#         -olcrtc.gate-mts-ice=tcp|udp|both is the Rust client's ICE mode
#         (tcp, its default for a link that says nothing);
#   rust  the TestRustMTS* tests (internal/engine/mtslink): the Rust client
#         against the engine's fake SFU, one guest: the join, the ICE modes,
#         and the rejoin after the SFU drops the guest's peer connection;
#   go    the engine's own tests of internal/auth/mtslink and
#         internal/engine/mtslink, the baseline the rust ones are read
#         against, and the forwarding fake's own test with two Go engines
#         in a room ("-" for the binary).
# A set whose tests the overlay does not hold yet fails, it does not pass
# empty. Extra flags go to go test; -run=<re> replaces the set's own.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

OLC_CARRIER=mtslink
OLC_GATE_TARGET=mtsfake
OLC_GATE_RUN='^(TestGateRustMTSFake|TestMTSLogWatchReadsSecretsAndTheHeapGauge|TestMTSRoomFailuresNameWhatARoomSawWrong)$'
OLC_RUST_PKG=./internal/engine/mtslink
OLC_RUST_RUN='^TestRustMTS'
OLC_GO_PKGS=(./internal/auth/mtslink ./internal/engine/mtslink ./internal/engine/mtslinkfake)
olc_carrier_main "$@"

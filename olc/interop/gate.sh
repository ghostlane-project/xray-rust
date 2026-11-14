#!/usr/bin/env bash
# gate.sh <rust-client-bin> [go test flags...]
#
# Runs the engine's gate on the interop target (TestGateRust, the overlay's
# internal/gate/zz_rust_flavour_test.go) against the Go engine at the pin,
# with the Rust client <rust-client-bin>. Run it on the build box, never on
# DATA:
#   go-remote.sh olc-client-go <repo>/olc/interop bash gate.sh <bin> [-olcrtc.gate-chaos=chaos]
# Extra flags go to go test; -run defaults to the gate itself.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

bin=${1:?usage: gate.sh <rust-client-bin> [go test flags...]}
shift
engine=$OLC_WORK/engine
olc_prepare "$engine"
run='^TestGateRust$'
args=()
for a in "$@"; do
	case "$a" in -run=*) run=${a#-run=} ;; *) args+=("$a") ;; esac
done
cd "$engine"
set +e
GOFLAGS=-mod=readonly go test -count=1 -timeout 60m -tags "$OLC_GO_TAGS" ./internal/gate -run "$run" -v \
	-olcrtc.gate-target=interop -olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts" "${args[@]}" 2>&1 \
	| grep -v '^=== \(RUN\|PAUSE\|CONT\)'
rc=${PIPESTATUS[0]}
set -e
olc_guard "$engine" || true
exit "$rc"

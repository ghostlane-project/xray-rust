#!/usr/bin/env bash
# fakeroom.sh <rust-client-bin> <gate|rust|go> [go test flags...]
#
# T2(b): the Rust client in the engine's SaluteJazz fake SFU (real WebRTC, no
# carrier), against the Go engine at the pin. Run it on the build box, never
# on DATA:
#   go-remote.sh olc-rtc-go <repo>/olc/interop bash fakeroom.sh <bin> gate
#
#   gate  TestGateRustFakeRoom (internal/gate/zz_rust_fakeroom_test.go): S0-S5
#         on the fakeroom target; -olcrtc.gate-flavours=rust,cli adds the Go
#         baseline;
#   rust  the TestRust* tests (internal/engine/salutejazz/zz_rust_test.go): the
#         join as the capture says, the two slow-leg tests, the rejoin;
#   go    the engine's own two slow-leg tests with the Go client, the
#         baseline the rust ones are read against.
# Extra flags go to go test; -run=<re> replaces the set's own.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

bin=${1:?usage: fakeroom.sh <rust-client-bin> <gate|rust|go> [go test flags...]}
what=${2:?usage: fakeroom.sh <rust-client-bin> <gate|rust|go> [go test flags...]}
shift 2
engine=$OLC_WORK/engine
olc_prepare "$engine"
extra=()
case "$what" in
gate)
	pkg=./internal/gate run='^TestGateRustFakeRoom$'
	extra=(-olcrtc.gate-target=fakeroom -olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts")
	;;
rust) pkg=./internal/engine/salutejazz run='^TestRust' ;;
go) pkg=./internal/engine/salutejazz run='^(TestATunnelOnASlowLegKeepsItsControlStreamUnderBulk|TestSixPullsOnTheSlowestLegKeepTheirPongs)$' ;;
*) olc_die "unknown set $what: gate, rust or go" ;;
esac
args=()
for a in "$@"; do
	case "$a" in -run=*) run=${a#-run=} ;; *) args+=("$a") ;; esac
done
cd "$engine"
set +e
OLCRTC_GATE_RUST_BIN="$bin" GOFLAGS=-mod=readonly go test -count=1 -timeout 40m -tags "$OLC_GO_TAGS" "$pkg" \
	-run "$run" -v "${extra[@]}" "${args[@]}" 2>&1 | grep -v '^=== \(RUN\|PAUSE\|CONT\)'
rc=${PIPESTATUS[0]}
set -e
olc_guard "$engine" || true
exit "$rc"

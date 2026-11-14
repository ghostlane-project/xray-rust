#!/usr/bin/env bash
# p2p.sh <rust-client-bin|-> [go test flags...]
# p2p.sh --engine [go test flags...]
#
# Runs the engine's gate on the p2p target (TestGateP2P, the overlay's
# internal/gate/zz_rust_p2p_test.go): the Go server at the pin in a room of
# the in-process hub, joined through the interop-p2p engine (pion, a VP8
# track, vp8channel and KCP end to end), with the Rust client
# <rust-client-bin> or, for "-", none (pass -olcrtc.gate-flavours=cli: the Go
# client alone, the baseline). --engine runs the engine's own tests instead
# (internal/engine/interopp2p), after gofmt and vet.
#
# TURN: -olcrtc.gate-turn=udp|tcp|tls makes the server relay-only through a
# coturn the test starts as its own child (-olcrtc.gate-turnserver, default
# turnserver on PATH). Never on the build box: no coturn is installed there
# and none may be; the lab workflow runs those on GitHub-hosted runners.
#
#   go-remote.sh olc-p2p <repo>/olc/interop bash p2p.sh - -olcrtc.gate-flavours=cli
#   go-remote.sh olc-p2p <repo>/olc/interop bash p2p.sh --engine
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

bin=${1:?usage: p2p.sh <rust-client-bin|-> [go test flags...] | p2p.sh --engine [go test flags...]}
shift
engine=$OLC_WORK/engine
olc_prepare "$engine"
cd "$engine"
unformatted=$(gofmt -l $(olc_overlay_files | grep '\.go$'))
[ -z "$unformatted" ] || olc_die "gofmt: $unformatted"
GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS" ./internal/engine/interopp2p ./internal/engine/builtin ./internal/gate

set +e
if [ "$bin" = --engine ]; then
	GOFLAGS=-mod=readonly go test -count=1 -timeout 5m -tags "$OLC_GO_TAGS" ./internal/engine/interopp2p -v "$@" 2>&1 \
		| grep -v '^=== \(RUN\|PAUSE\|CONT\)'
	rc=${PIPESTATUS[0]}
else
	[ "$bin" = - ] && bin=
	run='^TestGateP2P$'
	args=()
	for a in "$@"; do
		case "$a" in -run=*) run=${a#-run=} ;; *) args+=("$a") ;; esac
	done
	GOFLAGS=-mod=readonly go test -count=1 -timeout 60m -tags "$OLC_GO_TAGS" ./internal/gate -run "$run" -v \
		-olcrtc.gate-target=p2p -olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts" "${args[@]}" 2>&1 \
		| grep -v '^=== \(RUN\|PAUSE\|CONT\)'
	rc=${PIPESTATUS[0]}
fi
set -e
olc_guard "$engine" || true
exit "$rc"

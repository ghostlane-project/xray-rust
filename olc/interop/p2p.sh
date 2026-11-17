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
# The Go baseline (the cli flavour) is a process of its own: the public
# client as cmd/zz-olcrtc-goclient (internal/zzgoclient), with its VmHWM and
# sampled RSS logged as the Rust client's are (zz_go_child_test.go), in the
# phone buffer profile, the one the Rust client is a port of;
# -olcrtc.gate-go-profile=server gives it the engine's server profile (its
# CLI's). -olcrtc.gate-go-inproc runs it inside the test process instead, as
# the engine's own gate does: server profile, GOMAXPROCS shared with the
# harness, no memory figure of its own. -olcrtc.gate-go-gctrace also logs
# the largest heap the child's runtime said. The same three flags are
# mtslink.sh's and vkcalls.sh's gate sets'.
#
# ICE over TCP: --ice=tcp|both|udp (anywhere among the flags) is the gate's
# -olcrtc.gate-ice=<mode>, which may be passed as itself too: the gate writes
# ice=<mode> into the server's URL and the clients', and nothing else names
# the mode (no end reads it from the environment). With tcp the server
# gathers passive TCP candidates on a loopback TCP mux and no UDP, and the
# Rust client dials them (olc-rtc's icetcp.rs, the MTS Link client's default
# path); with both, either kind. After a tcp run with a Rust client the
# script also requires its lines "interop-p2p: ICE over tcp: 0 UDP datagrams
# sent" (in the gate's output or its rust-*.log artifacts) and none with
# another count. --engine takes no mode: the engine's tests name their own.
#
# TURN: -olcrtc.gate-turn=udp|tcp|tls makes the server relay-only through a
# coturn the test starts as its own child (-olcrtc.gate-turnserver, default
# turnserver on PATH). Never on the build box: no coturn is installed there
# and none may be; the lab workflow runs those on GitHub-hosted runners.
#
#   go-remote.sh olc-p2p <repo>/olc/interop bash p2p.sh - -olcrtc.gate-flavours=cli
#   go-remote.sh olc-p2p <repo>/olc/interop bash p2p.sh --engine
#   go-remote.sh olc-p2p <repo>/olc/interop bash p2p.sh <rust-client-bin> --ice=tcp
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

bin=${1:?usage: p2p.sh <rust-client-bin|-> [--ice=udp|tcp|both] [go test flags...] | p2p.sh --engine [go test flags...]}
shift
ice=
rest=()
for a in "$@"; do
	case "$a" in
	--ice=udp | --ice=tcp | --ice=both | -olcrtc.gate-ice=udp | -olcrtc.gate-ice=tcp | -olcrtc.gate-ice=both)
		[ -z "$ice" ] || olc_die "$a: the mode is already $ice"
		ice=${a##*=}
		;;
	--ice=* | -olcrtc.gate-ice=*) olc_die "$a: udp, tcp or both" ;;
	*) rest+=("$a") ;;
	esac
done
set -- "${rest[@]}"
if [ -n "$ice" ]; then
	[ "$bin" != --engine ] || olc_die "--ice with --engine: the engine's tests name their own modes"
	set -- "$@" "-olcrtc.gate-ice=$ice"
fi
engine=$OLC_WORK/engine
olc_prepare "$engine"
cd "$engine"
unformatted=$(gofmt -l $(olc_overlay_files | grep '\.go$'))
[ -z "$unformatted" ] || olc_die "gofmt: $unformatted"
GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS" ./internal/engine/interopp2p ./internal/engine/builtin ./internal/gate \
	"${OLC_GO_CHILD[@]}"

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
	out=$OLC_WORK/p2p-last.out
	rm -rf "$OLC_WORK"/gate-artifacts/p2p-*
	GOFLAGS=-mod=readonly go test -count=1 -timeout 60m -tags "$OLC_GO_TAGS" ./internal/gate -run "$run" -v \
		-olcrtc.gate-target=p2p -olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts" "${args[@]}" 2>&1 \
		| grep -v '^=== \(RUN\|PAUSE\|CONT\)' | tee "$out"
	rc=${PIPESTATUS[0]}
	# ICE over TCP alone: the Rust client says what its peer connections
	# gave their UDP sockets, and that must be nothing, every time. The
	# gate keeps the client's lines in its artifacts (rust-*.log), the
	# start of each run at least.
	if [ "$rc" = 0 ] && [ "$ice" = tcp ] && [ -n "$bin" ]; then
		lines=$OLC_WORK/p2p-last.rust
		{
			cat "$out"
			find "$OLC_WORK/gate-artifacts" -path '*/p2p-*' -name 'rust*.log' -exec cat {} +
		} >"$lines" 2>/dev/null || true
		said=$(grep -c 'interop-p2p: ICE over tcp: [0-9]* UDP datagrams sent' "$lines" || true)
		none=$(grep -c 'interop-p2p: ICE over tcp: 0 UDP datagrams sent' "$lines" || true)
		echo "p2p.sh: ICE over tcp: $said lines from the Rust client, $none of them with 0 UDP datagrams"
		if [ "$said" = 0 ] || [ "$said" != "$none" ]; then
			echo "p2p.sh: the Rust client did not show a UDP-free run" >&2
			rc=1
		fi
	fi
fi
set -e
olc_guard "$engine" || true
exit "$rc"

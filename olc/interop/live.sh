#!/usr/bin/env bash
# live.sh <rust-client-bin> [go test flags...]
#
# T3's SaluteJazz rust step from the build box (TestGateRustLive, the
# overlay's internal/gate/zz_rust_live_test.go): one fresh anonymous
# SaluteJazz room, made by the provider's own create call (no account), the
# pinned Go server in it, this build's Go client (the phones' build, so the
# mobile flavour) running S0-S5 there, then the Rust client running them in
# the same room. <rust-client-bin> is olc-client built with the shaped-tls
# feature. Run it on the build box, never on DATA:
#   go-remote.sh olc-rtc-go <repo>/olc/interop bash live.sh <bin>
#
# One run is one create call and three joins (the server, the Go client, the
# Rust client), plus one rejoin for every reconnect a cell reports: count
# them in the log before running it again. The gate's room and account
# variables (the CI's secrets) are cleared for the run: this step uses none.
# Extra flags go to go test.
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

bin=${1:?usage: live.sh <rust-client-bin> [go test flags...]}
shift
engine=$OLC_WORK/engine
olc_prepare "$engine"
cd "$engine"
set +e
env -u OLCRTC_GATE_LINK -u OLCRTC_GATE_TELEMOST_ROOMS -u OLCRTC_GATE_WBSTREAM_ROOMS \
	-u OLCRTC_GATE_VKCALLS_ROOMS -u OLCRTC_GATE_MTSLINK_ROOMS -u OLCRTC_GATE_MAX_ROOMS \
	-u OLCRTC_GATE_JITSI_HOSTS -u OLCRTC_GATE_WBSTREAM_TOKEN -u OLCRTC_GATE_MAX_KEYS \
	GOFLAGS=-mod=readonly go test -count=1 -timeout 30m -tags "$OLC_GO_TAGS,olcrtc_lean" ./internal/gate \
	-run '^TestGateRustLive$' -v -olcrtc.gate -olcrtc.gate-rust-live -olcrtc.gate-target=local \
	-olcrtc.gate-providers=salutejazz -olcrtc.gate-transports=datachannel \
	-olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts" "$@" 2>&1 \
	| grep -v '^=== \(RUN\|PAUSE\|CONT\)'
rc=${PIPESTATUS[0]}
set -e
olc_guard "$engine" || true
exit "$rc"

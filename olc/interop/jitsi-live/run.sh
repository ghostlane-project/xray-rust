#!/usr/bin/env bash
# run.sh <rust-client-bin> [go test flags...]
#
# The Jitsi carrier through a real deployment (plan W5): the gate's
# jitsilive target, TestGateRustJitsiLive (the overlay's
# internal/gate/zz_rust_jitsilive_test.go). The pinned Go server (the exit's
# side) joins a fresh room of the lab's own docker-jitsi-meet, and each
# client joins it as an app would, by the room's link over https and wss:
#
#   rows   the session up, a nonce echoed, 2 MiB down and 2 MiB up through
#          the client's SOCKS port (each checked by its SHA-256), the client
#          leaves, joins the same room again and does it all once more;
#   cells  the gate's S0-S7, as the jitsifake target runs them
#          (-olcrtc.gate-jitsi-live-plan=false leaves them out).
#
# -olcrtc.gate-flavours=cli,rust runs the Go client first: it is the control
# row. If it fails, the deployment is wrong, not the port.
#
# -olcrtc.gate-jitsi-live-first puts the Rust client alone in a room of its
# own before all of it, so that a real Jicofo asks it what it can do;
# deploy.sh first (first.sh) then reads what Jicofo made of the answer.
#
# What the run needs, all written by deploy.sh up into <dir>/lab.env:
#   OLCRTC_GATE_JITSI_LIVE_HOST  the deployment's host; it must resolve to
#                                this machine, the test refuses any other;
#   SSL_CERT_FILE                the roots the Go server and client trust:
#                                the system's and the lab's CA;
#   OLC_TLS_TEST_PIN             the SHA-256 of the lab CA's certificate,
#                                which the Rust client trusts in place of the
#                                webpki roots. <rust-client-bin> is olc-client
#                                built with the shaped-tls and tls-test-pin
#                                features (and boring, as the apps are).
#
# The deployment is a GitHub-hosted runner's (deploy.sh starts containers and
# edits /etc/hosts, so it refuses to run anywhere else). On the build box only
# the harness's own check runs, against the Go fake over its TLS listener:
#   go-remote.sh <topic> <repo>/olc/interop bash jitsi-live/run.sh <bin> \
#       -olcrtc.gate-jitsi-live-host=selftest -olcrtc.gate-flavours=cli,rust
# Extra flags go to go test.
set -euo pipefail
# shellcheck source=../lib.sh
. "$(dirname "$0")/../lib.sh"

bin=${1:?usage: run.sh <rust-client-bin> [go test flags...]}
shift
[ -x "$bin" ] || olc_die "$bin is not a program: the Rust client's binary"
engine=$OLC_WORK/engine
olc_prepare "$engine"
cd "$engine"
names=$(olc_tests ./internal/gate '^TestGateRustJitsiLive$')
[ -n "$names" ] || olc_die "the overlay holds no TestGateRustJitsiLive: nothing would run"
set +e
GOFLAGS=-mod=readonly go test -count=1 -timeout 45m -tags "$OLC_GO_TAGS" ./internal/gate \
	-run '^TestGateRustJitsiLive$' -v -olcrtc.gate-target=jitsilive \
	-olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts" "$@" 2>&1 |
	grep -v '^=== \(RUN\|PAUSE\|CONT\)'
rc=${PIPESTATUS[0]}
set -e
olc_guard "$engine" || true
exit "$rc"

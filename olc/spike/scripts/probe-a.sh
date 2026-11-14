#!/bin/bash
# Probe (a): str0m against the engine's fake SFU, echoing through the engine's own Session.
#
#   probe-a.sh <engine-checkout> <sfu-probe-binary> [sfu-probe flags...]
#
# <engine-checkout> is olcRTC at the servers' pin (ghostlane-project/olcrtc 2d4266af); it is
# copied, the harness (go/salutejazz/zz_spike_echo_test.go) is dropped into the copy's
# internal/engine/salutejazz, and `go test -run TestSpikeRustEcho` starts the fake SFU, joins
# the engine's Session as the echo and runs the probe against the same room. Needs Go and an
# up, non-loopback IPv4 interface. The probe's whole output goes to $OLC_SPIKE_OUT (default:
# ./probe-a.out); its RESULT line is printed at the end. Exit status: the test's.
#
# Examples (flags are sfu-probe's):
#   probe-a.sh ../olcrtc target/release/sfu-probe --dtls dimpl --version 12
#   probe-a.sh ../olcrtc target/release/sfu-probe --dtls boring --version auto --stun chrome
set -euo pipefail
engine=$(cd "${1:?engine checkout}" && pwd)
probe=$(cd "$(dirname "${2:?sfu-probe binary}")" && pwd)/$(basename "$2")
shift 2
spike=$(cd "$(dirname "$0")/.." && pwd)
out=${OLC_SPIKE_OUT:-$PWD/probe-a.out}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -C "$engine" --exclude=.git -cf - . | tar -C "$work" -xf -
cp "$spike/go/salutejazz/zz_spike_echo_test.go" "$work/internal/engine/salutejazz/"
set +e
(cd "$work" && OLC_SPIKE_PROBE="$probe" OLC_SPIKE_ARGS="$*" OLC_SPIKE_OUT="$out" \
  go test ./internal/engine/salutejazz -run '^TestSpikeRustEcho$' -count=1 -v -timeout 300s)
rc=$?
set -e
grep -h '^RESULT ' "$out" 2>/dev/null || echo "no RESULT line in $out"
exit $rc

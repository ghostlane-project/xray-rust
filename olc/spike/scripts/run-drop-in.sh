#!/bin/bash
# Runs one of go/<package>/zz_spike_bridge_test.go inside a copy of the engine.
#
#   run-drop-in.sh <package> <test> <out> <engine-checkout> <sdp-bridge-binary> [bridge flags...]
#
# The engine checkout is copied to a scratch directory (the checkout itself is never
# changed), the drop-in goes into the copy's internal/engine/<package>, and `go test -run`
# runs it with the bridge's path and flags in the environment. probe-b-mtslink.sh and
# probe-c-vkcalls.sh call this.
set -euo pipefail
pkg=${1:?package}; test=${2:?test}; out=${3:?out}
engine=$(cd "${4:?engine checkout}" && pwd)
bridge=$(cd "$(dirname "${5:?sdp-bridge binary}")" && pwd)/$(basename "$5")
shift 5
spike=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/olc-spike-$pkg.XXXXXX")
tar -C "$engine" --exclude=.git -cf - . | tar -C "$scratch" -xf -
cp "$spike/go/$pkg/zz_spike_bridge_test.go" "$scratch/internal/engine/$pkg/"
set +e
(cd "$scratch" && OLC_SPIKE_BRIDGE="$bridge" OLC_SPIKE_BRIDGE_ARGS="$*" OLC_SPIKE_OUT="$out" \
  go test "./internal/engine/$pkg" -run "^${test}\$" -count=1 -v -timeout 300s)
rc=$?
set -e
echo "scratch copy (delete when done): $scratch"
grep -h '^RESULT ' "$out" 2>/dev/null || true
exit $rc

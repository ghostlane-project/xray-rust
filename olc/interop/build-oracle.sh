#!/usr/bin/env bash
# build-oracle.sh <out>
#
# Builds the decode oracle (go-overlay/cmd/zz-olcrtc-oracle) against the Go
# engine at the pin, to <out>. The Rust interop tests run it when
# OLC_GO_ORACLE=<out>. Run it on the build box, never on DATA:
#   go-remote.sh olc-oracle <repo>/olc/interop bash build-oracle.sh <out>
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

out=${1:?usage: build-oracle.sh <out>}
engine=$OLC_WORK/engine
olc_prepare "$engine"
mkdir -p "$(dirname "$out")"
(cd "$engine" && GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false -tags "$OLC_GO_TAGS" -o "$out.tmp" ./cmd/zz-olcrtc-oracle)
olc_guard "$engine"
mv -f "$out.tmp" "$out"
echo '{"op":"ping"}' | "$out"
echo "built $out at $OLC_PIN"

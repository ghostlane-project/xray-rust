#!/usr/bin/env bash
# build-kcp-peer.sh <out>
#
# Builds the KCP conformance peer (go-overlay/cmd/zz-olcrtc-kcppeer: the
# engine's own startKCP on a UDP socket) against the Go engine at the pin, to
# <out>. olc-kcp's conformance tests run it when OLC_KCP_GO_PEER=<out>. Run it
# on the build box, never on DATA:
#   go-remote.sh olc-kcppeer <repo>/olc/interop bash build-kcp-peer.sh <out>
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

out=${1:?usage: build-kcp-peer.sh <out>}
engine=$OLC_WORK/engine
olc_prepare "$engine"
mkdir -p "$(dirname "$out")"
cd "$engine"
unformatted=$(gofmt -l $(olc_overlay_files | grep '\.go$'))
[ -z "$unformatted" ] || olc_die "gofmt: $unformatted"
GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS" ./internal/transport/vp8channel ./cmd/zz-olcrtc-kcppeer
GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false -tags "$OLC_GO_TAGS" -o "$out.tmp" ./cmd/zz-olcrtc-kcppeer
cd "$OLC_INTEROP"
olc_guard "$engine"
mv -f "$out.tmp" "$out"
"$out" -h 2>&1 | head -1 || true
echo "built $out at $OLC_PIN"

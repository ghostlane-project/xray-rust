#!/usr/bin/env bash
# regen.sh [--check]
#
# Regenerates the golden vectors under vectors/<pin8>/ from the Go engine at
# the pin: a clean checkout plus go-overlay/, each package's TestZZVectors run
# twice into two directories that must be byte for byte the same. --check
# compares against the committed vectors instead of replacing them.
#
# Needs git, network access to the engine's repository and Go (the go.mod's
# version); run it on the build box, never on DATA:
#   go-remote.sh olc-vectors <repo>/olc/interop bash regen.sh
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

mode=write
case "${1:-}" in
'') ;;
--check) mode=check ;;
*) olc_die "usage: regen.sh [--check]" ;;
esac

engine=$OLC_WORK/engine
olc_prepare "$engine"

pkgs=(
	./internal/crypto
	./internal/framing
	./internal/handshake
	./internal/control
	./internal/udpwire
	./internal/client
	./internal/muxconn
	./internal/runtime
	./internal/tunnelcore
	./internal/transport/datachannel
	./internal/transport/vp8channel
)
expected=(
	connect.json control.json framing.json muxconn.json runtime.json tunnelcore.json udpwire.json
	crypto/keys.json crypto/open.json crypto/seal.json
	handshake/client.json handshake/hello.json handshake/server.json
	transport/datachannel.json transport/vp8channel.json
	vp8/datagram.json vp8/epoch.json vp8/inbound-verdicts.json vp8/kcp-crc.json vp8/kcp-settings.json
	vp8/kcp.json vp8/olkb.json vp8/rtp-reader.json vp8/rtp.json vp8/token.json vp9/carrier.json
)

cd "$engine"
unformatted=$(gofmt -l $(olc_overlay_files | grep '\.go$'))
[ -z "$unformatted" ] || olc_die "gofmt: $unformatted"
GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS" "${pkgs[@]}" ./cmd/zz-olcrtc-oracle ./cmd/zz-olcrtc-kcppeer

for run in 1 2; do
	out=$OLC_WORK/run$run
	rm -rf "$out"
	mkdir -p "$out"
	OLC_VECTORS_OUT=$out GOFLAGS=-mod=readonly \
		go test -count=1 -tags "$OLC_GO_TAGS" -run '^TestZZVectors$' "${pkgs[@]}"
done
cd "$OLC_INTEROP"
olc_guard "$engine"

diff -r "$OLC_WORK/run1" "$OLC_WORK/run2" || olc_die "two runs wrote different vectors"
got=$(cd "$OLC_WORK/run1" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
want=$(printf '%s\n' "${expected[@]}" | LC_ALL=C sort)
[ "$got" = "$want" ] || olc_die "vector files: want $(echo $want), got $(echo $got)"

target=$OLC_INTEROP/vectors/${OLC_PIN:0:8}
if [ "$mode" = check ]; then
	diff -r "$OLC_WORK/run1" "$target" || olc_die "the committed vectors differ from the engine's"
	echo "vectors match the engine at $OLC_PIN"
else
	rm -rf "$target"
	mkdir -p "$target"
	cp -R "$OLC_WORK/run1/." "$target/"
	echo "wrote $(echo "$got" | wc -l) vector files to $target (two runs, no difference)"
fi

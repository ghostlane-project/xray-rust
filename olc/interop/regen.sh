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
	# The carriers (MTS Link, VK Calls), the rejoin supervisor's package and
	# the generators that belong to no engine package (olc-net's forms and
	# cookies). A package whose generator is not in the overlay yet runs no
	# test and writes nothing.
	./internal/auth/mtslink
	./internal/engine/mtslink
	./internal/auth/vkcalls
	./internal/engine/vkcalls
	# Jitsi: the room link, and the engine's pure parts.
	./internal/auth/jitsi
	./internal/engine/jitsi
	./internal/engine/jitsifake
	./internal/engine
	./internal/zzvectors
)
expected=(
	connect.json control.json framing.json muxconn.json runtime.json tunnelcore.json udpwire.json
	crypto/keys.json crypto/open.json crypto/seal.json
	handshake/client.json handshake/hello.json handshake/server.json
	transport/datachannel.json transport/vp8channel.json
	vp8/datagram.json vp8/epoch.json vp8/inbound-verdicts.json vp8/kcp-crc.json vp8/kcp-settings.json
	vp8/kcp.json vp8/olkb.json vp8/rtp-reader.json vp8/rtp.json vp8/token.json vp9/carrier.json
	# MTS Link: the auth provider's (internal/auth/mtslink) and the engine's
	# (internal/engine/mtslink). offer.sdp is a text of its own, not JSON.
	mtslink/cookies.json mtslink/forms.json mtslink/is_host.json mtslink/is_id.json
	mtslink/parse_event_link.json mtslink/requests_gateway.json mtslink/room_join_url.json
	mtslink/offer.json mtslink/offer.sdp mtslink/offer_url.json mtslink/peer_of.json
	mtslink/refusal_text.json mtslink/requests_sfu.json
	# VK Calls: the engine's (internal/engine/vkcalls) six, then the auth
	# provider's two (internal/auth/vkcalls: a generator writes from inside
	# its package, so the link and credential half of the URLs is url_auth).
	vkcalls/frames.json vkcalls/msgpack.json vkcalls/shape.json vkcalls/stamp.json
	vkcalls/url.json vkcalls/view.json
	vkcalls/requests_auth.json vkcalls/url_auth.json
	# Jitsi: the room link (internal/auth/jitsi), the engine's nicks, config.js
	# rules, bridge frames and epoch rules (internal/engine/jitsi).
	jitsi/room.json jitsi/nick.json jitsi/configjs.json jitsi/frames.json jitsi/epoch.json
	# The fake's half (internal/engine/jitsifake): what the engine says to a room.
	jitsi/transcript.json jitsi/handshake.json jitsi/offer.json jitsi/accept.json jitsi/relaywin.json
	# The same engine over BOSH, its WebSocket refused (zz_vectors_bosh_test.go).
	jitsi/bosh.json
	# A real deployment's session-initiate, kept as it arrived, through the
	# engine's own negotiation, and the engine's whole connection to that
	# deployment, both ways (internal/engine/jitsi, zz_vectors_live_test.go).
	jitsi/live.json
	# The rejoin supervisor's (internal/engine: olc-net's reconnect.rs).
	reconnect/backoff.json
)
# internal/zzvectors' own generator (olc-net: Go's form encoding and its
# Set-Cookie rules) writes net/; its files are expected once it is there.
if compgen -G "$OLC_OVERLAY/internal/zzvectors/*_test.go" >/dev/null; then
	expected+=(net/cookies.json net/forms.json)
fi

cd "$engine"
unformatted=$(gofmt -l $(olc_overlay_files | grep '\.go$'))
[ -z "$unformatted" ] || olc_die "gofmt: $unformatted"
GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS" "${pkgs[@]}" ./cmd/zz-olcrtc-oracle ./cmd/zz-olcrtc-kcppeer
# The phones' build (olcrtc_lean) compiles files the plain one leaves out: an
# overlay name must clash with none of them, in any package.
GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS,olcrtc_lean" ./...

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

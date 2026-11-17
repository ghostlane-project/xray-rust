#!/bin/sh
# peer.sh BIN [GOLDEN_DIR]
#
# Checks and builds the Go conformance peer for olc-smux, then (with
# GOLDEN_DIR) writes the golden captures twice and fails unless both runs
# are byte-identical. Run it where Go is installed, never on a production
# host, for example on the build box through go-remote.sh:
#
#   go-remote.sh olc-smux olc/interop/smux/go sh peer.sh /path/to/olc-smux-peer golden-out
#
# The Rust tests then take the binary from OLC_SMUX_GO_PEER, and the
# captures are committed under olc/interop/smux/golden/.
set -eu
bin=$1
golden=${2:-}

unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "gofmt: $unformatted" >&2
  exit 1
fi
go vet ./...
mkdir -p "$(dirname "$bin")"
go build -trimpath -o "$bin" .

if [ -n "$golden" ]; then
  rm -rf "$golden" "$golden.again"
  "$bin" golden -out "$golden"
  "$bin" golden -out "$golden.again"
  for f in "$golden"/*; do
    cmp "$f" "$golden.again/$(basename "$f")"
  done
  rm -rf "$golden.again"
  echo "golden: two runs identical"
fi

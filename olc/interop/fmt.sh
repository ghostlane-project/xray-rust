#!/usr/bin/env bash
# fmt.sh: gofmt the overlay in place. The overlay's packages only build inside
# the engine, so it is formatted there and copied back. Run it on the build
# box, then copy go-overlay/ back:
#   go-remote.sh olc-fmt <repo>/olc/interop bash fmt.sh
set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

engine=$OLC_WORK/engine
olc_prepare "$engine"
while read -r f; do
	case "$f" in *.go) ;; *) continue ;; esac
	gofmt -w "$engine/$f"
	cp "$engine/$f" "$OLC_OVERLAY/$f"
done < <(olc_overlay_files)
olc_guard "$engine"
echo "formatted the overlay"

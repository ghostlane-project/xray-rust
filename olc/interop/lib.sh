# shellcheck shell=bash
# Shared by regen.sh and build-oracle.sh: the engine pin, and a clean checkout
# of it with our overlay copied in.
#
# The overlay (go-overlay/) holds only files the engine does not have: Go's
# internal/ rule keeps code outside the module from importing the packages we
# test, so our generators and export shims have to live inside the module. They
# are built only with the olcrtc_interop tag. olc_guard proves after every step
# that no engine file was changed and that nothing but the overlay was added.

OLC_PIN=2d4266af3947f4d9940efafb0d5aabb6207f6659
OLC_REPO=https://github.com/ghostlane-project/olcrtc
OLC_MODULE=github.com/openlibrecommunity/olcrtc
OLC_GO_TAGS=olcrtc_interop
OLC_INTEROP=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OLC_OVERLAY=$OLC_INTEROP/go-overlay
OLC_WORK=$OLC_INTEROP/.work

olc_die() {
	echo "olc: $*" >&2
	exit 1
}

# The overlay's files, relative to its root, in byte order.
olc_overlay_files() {
	(cd "$OLC_OVERLAY" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
}

# olc_prepare <dir>: <dir> becomes the engine at OLC_PIN, clean, plus the overlay.
olc_prepare() {
	local dir=$1 f
	mkdir -p "$dir"
	if [ ! -d "$dir/.git" ]; then
		git -C "$dir" init -q
		git -C "$dir" remote add origin "$OLC_REPO"
	fi
	if ! git -C "$dir" cat-file -e "$OLC_PIN^{commit}" 2>/dev/null; then
		git -C "$dir" fetch -q --depth 1 origin "$OLC_PIN"
	fi
	git -C "$dir" -c advice.detachedHead=false checkout -q --force --detach "$OLC_PIN"
	git -C "$dir" reset -q --hard "$OLC_PIN"
	git -C "$dir" clean -q -fdx
	[ "$(git -C "$dir" rev-parse HEAD)" = "$OLC_PIN" ] || olc_die "checkout is not at $OLC_PIN"
	grep -qx "module $OLC_MODULE" "$dir/go.mod" || olc_die "go.mod does not name $OLC_MODULE"
	while read -r f; do
		[ ! -e "$dir/$f" ] || olc_die "overlay file $f would replace the engine's own"
		mkdir -p "$dir/$(dirname "$f")"
		cp "$OLC_OVERLAY/$f" "$dir/$f"
	done < <(olc_overlay_files)
	olc_guard "$dir"
}

# olc_guard <dir>: no tracked file changed, and the untracked files are
# exactly the overlay's.
olc_guard() {
	local dir=$1 want got
	git -C "$dir" diff --quiet --exit-code || olc_die "an engine file changed: $(git -C "$dir" diff --stat | tail -1)"
	want=$(olc_overlay_files | sed 's/^/?? /')
	got=$(git -C "$dir" status --porcelain --untracked-files=all | LC_ALL=C sort)
	if [ "$want" != "$got" ]; then
		diff <(echo "$want") <(echo "$got") >&2 || true
		olc_die "the checkout holds more than the engine and the overlay"
	fi
}

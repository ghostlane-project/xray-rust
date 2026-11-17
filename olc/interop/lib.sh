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
# The gate's Go baseline as a process of its own (go-overlay/internal/gate/
# zz_go_child_test.go): its package and its command, vetted with the gate.
OLC_GO_CHILD=(./internal/zzgoclient ./cmd/zz-olcrtc-goclient)

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

# olc_tests <package> <run>: the names of the tests -run <run> selects in
# <package>, one a line; the working directory is the prepared engine. go test
# passes ("no tests to run") when -run selects nothing, so a script that names
# a test asks here first.
olc_tests() {
	local out
	out=$(GOFLAGS=-mod=readonly go test -tags "$OLC_GO_TAGS" -list "$2" "$1") || olc_die "go test -list $2 $1 failed"
	grep '^Test' <<<"$out" || true
}

# olc_carrier_main "$@": the body of a carrier's script (mtslink.sh,
# vkcalls.sh), which sets, before calling:
#   OLC_CARRIER      the carrier's name, for messages;
#   OLC_GATE_TARGET  the gate target of its fake room, OLC_GATE_RUN its test;
#   OLC_RUST_PKG     the package of its TestRust* tests, OLC_RUST_RUN their -run;
#   OLC_GO_PKGS      the engine's packages of the carrier (an array): their own
#                    tests are the Go baseline, and --dry vets them.
# Arguments: --dry | <rust-client-bin|-> <gate|rust|go> [go test flags...].
olc_carrier_main() {
	local usage="usage: $OLC_CARRIER.sh --dry | $OLC_CARRIER.sh <rust-client-bin|-> <gate|rust|go> [go test flags...]"
	local bin what engine=$OLC_WORK/engine
	local -a pkgs extra=() args=()
	local run names a rc
	if [ "${1:-}" = --dry ]; then
		[ $# -eq 1 ] || olc_die "$usage"
		what=dry
	else
		bin=${1:?$usage}
		what=${2:?$usage}
		shift 2
		[ "$bin" = - ] && bin=
	fi
	case "$what" in
	dry) ;;
	gate)
		pkgs=(./internal/gate) run=$OLC_GATE_RUN
		extra=(-olcrtc.gate-target="$OLC_GATE_TARGET" -olcrtc.gate-rust-bin="$bin" -olcrtc.gate-dir="$OLC_WORK/gate-artifacts")
		;;
	rust) pkgs=("$OLC_RUST_PKG") run=$OLC_RUST_RUN ;;
	go) pkgs=("${OLC_GO_PKGS[@]}") run=. ;;
	*) olc_die "unknown set $what: gate, rust or go" ;;
	esac
	if [ "$what" != dry ] && [ "$what" != go ] && [ -z "$bin" ]; then
		olc_die "the $what set runs the Rust client: name its binary"
	fi
	olc_prepare "$engine"
	cd "$engine"

	if [ "$what" = dry ]; then
		names=$(gofmt -l $(olc_overlay_files | grep '\.go$'))
		[ -z "$names" ] || olc_die "gofmt: $names"
		GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS" "${OLC_GO_PKGS[@]}" ./internal/gate "${OLC_GO_CHILD[@]}"
		GOFLAGS=-mod=readonly go vet -tags "$OLC_GO_TAGS,olcrtc_lean" "${OLC_GO_PKGS[@]}" ./internal/gate "${OLC_GO_CHILD[@]}"
		grep -rqsF "\"$OLC_GATE_TARGET\"" "$OLC_OVERLAY/internal/gate" ||
			olc_die "the gate overlay names no target $OLC_GATE_TARGET"
		names=$(olc_tests ./internal/gate "$OLC_GATE_RUN")
		[ -n "$names" ] && a="$(wc -l <<<"$names") tests" || a="not in the overlay yet"
		echo "$OLC_CARRIER gate: $OLC_GATE_RUN in ./internal/gate, $a"
		names=$(olc_tests "$OLC_RUST_PKG" "$OLC_RUST_RUN")
		[ -n "$names" ] && a="$(wc -l <<<"$names") tests" || a="not in the overlay yet"
		echo "$OLC_CARRIER rust: $OLC_RUST_RUN in $OLC_RUST_PKG, $a"
		for a in "${OLC_GO_PKGS[@]}"; do
			names=$(olc_tests "$a" .)
			[ -n "$names" ] || olc_die "$a has no test at the pin"
			echo "$OLC_CARRIER go: $a, $(wc -l <<<"$names") tests"
		done
		cd "$OLC_INTEROP"
		olc_guard "$engine"
		echo "$OLC_CARRIER: dry run clean (the engine at $OLC_PIN plus the overlay, gofmt, vet in both tag sets)"
		return 0
	fi

	for a in "$@"; do
		case "$a" in -run=*) run=${a#-run=} ;; *) args+=("$a") ;; esac
	done
	for a in "${pkgs[@]}"; do
		names=$(olc_tests "$a" "$run")
		[ -n "$names" ] || olc_die "no test in $a matches $run: nothing would run"
	done
	set +e
	OLCRTC_GATE_RUST_BIN="$bin" GOFLAGS=-mod=readonly go test -count=1 -timeout 40m -tags "$OLC_GO_TAGS" "${pkgs[@]}" \
		-run "$run" -v "${extra[@]}" "${args[@]}" 2>&1 | grep -v '^=== \(RUN\|PAUSE\|CONT\)'
	rc=${PIPESTATUS[0]}
	set -e
	olc_guard "$engine" || true
	return "$rc"
}

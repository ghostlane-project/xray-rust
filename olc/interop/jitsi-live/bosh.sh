#!/usr/bin/env bash
# bosh.sh <web.log> <prosody.log> <rust|all>
#
# What a deployment's own logs say of BOSH (deploy.sh bosh runs this on the
# logs so far). It reads two logs and starts nothing.
#
# The gate holds the Rust client to BOSH by the client's own word (a start
# whose log does not say "BOSH instead" is a failed one). This is the other
# side's word: the sessions Prosody's mod_bosh made, and the /http-bind
# requests the front answered, by who sent them. The Go library names itself
# on its BOSH requests (Go-http-client); the Rust client sends what it asked
# config.js with, so a request that is not the Go library's is the Rust
# client's (nothing else posts to /http-bind in a run). It holds:
#
#   - Prosody made a BOSH session;
#   - the front answered requests of the Rust client, with 200 among them:
#     its XMPP did go over BOSH, through the front and mod_bosh;
#   - rust: no request is the Go library's. The deployment has its WebSocket
#     and the exit was to stay on it: a Go engine over BOSH there means the
#     run was not the one it says it was;
#   - all: requests of the Go library are there too. The deployment's
#     WebSocket is closed, and the control row went over BOSH as well.
set -euo pipefail

die() {
	echo "jitsi-live bosh: $*" >&2
	exit 1
}

usage="usage: bosh.sh <web.log> <prosody.log> <rust|all>"
web=${1:?$usage}
prosody=${2:?$usage}
who=${3:?$usage}
case "$who" in rust | all) ;; *) die "$usage" ;; esac
[ -s "$web" ] || die "$web is empty: no log of the front"
[ -s "$prosody" ] || die "$prosody is empty: no log of Prosody"

# lines <text>: how many lines it holds (none for the empty text).
lines() {
	grep -c . <<<"$1" || true
}

sessions=$(grep -a -c -F 'New BOSH session' "$prosody" || true)
posts=$(grep -a -E '"POST /http-bind[ ?][^"]*" [0-9]{3} ' "$web" || true)
go=$(grep -a -F '"Go-http-client/' <<<"$posts" || true)
rust=$(grep -a -v -F '"Go-http-client/' <<<"$posts" || true)
rust_ok=$(grep -a -E '"POST /http-bind[ ?][^"]*" 200 ' <<<"$rust" || true)
statuses=$(sed -n -E 's/.*"POST \/http-bind[ ?][^"]*" ([0-9]{3}) .*/\1/p' <<<"$rust" | sort | uniq -c |
	awk '{ printf "%s%s x %s", sep, $2, $1; sep = ", " }')

echo "jitsi-live bosh: Prosody made $sessions BOSH session(s); the front answered $(lines "$rust") request(s) of the Rust client (${statuses:-none}) and $(lines "$go") of the Go library."

[ "$sessions" -ge 1 ] || die "Prosody made no BOSH session: nobody's XMPP went over BOSH"
[ "$(lines "$rust")" -ge 1 ] || die "the front answered no /http-bind request other than the Go library's: the Rust client's XMPP did not go over BOSH"
[ "$(lines "$rust_ok")" -ge 1 ] || die "none of the Rust client's /http-bind requests was answered 200 ($statuses)"
case "$who" in
rust)
	[ "$(lines "$go")" -eq 0 ] ||
		die "$(lines "$go") /http-bind request(s) of the Go library on a deployment whose WebSocket is open: the exit was to keep its WebSocket"
	;;
all)
	[ "$(lines "$go")" -ge 1 ] ||
		die "no /http-bind request of the Go library: with the deployment's WebSocket closed the Go engines go over BOSH too"
	;;
esac

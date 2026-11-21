#!/usr/bin/env bash
# bosh.test.sh: bosh.sh held to what it names, on logs written here in the
# shape docker-jitsi-meet's front (nginx) and Prosody write them. It starts
# nothing and needs nothing but bash, grep, sed and awk:
#   bash olc/interop/jitsi-live/bosh.test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0
ran=0

go_agent='Go-http-client/2.0'
rust_agent='Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0'

# post <agent> <status> [path] [protocol]: one line of the front's log.
post() {
	printf 'web-1  | 10.0.0.9 - - [21/Nov/2026:18:32:04 +0000] "POST %s %s" %s 148 "" "%s"\n' \
		"${3:-/http-bind}" "${4:-HTTP/1.1}" "$2" "$1"
}

# session: one line of Prosody's log.
session() {
	printf "prosody-1  | 2026-11-21 18:32:04 mod_bosh                                         info\tNew BOSH session, assigned it sid 'f0f0'\n"
}

# check <name> <who> <want: ok|a word of the refusal>: bosh.sh on
# $tmp/web.log and $tmp/prosody.log.
check() {
	local name=$1 who=$2 want=$3 out rc=0
	ran=$((ran + 1))
	out=$(bash "$here/bosh.sh" "$tmp/web.log" "$tmp/prosody.log" "$who" 2>&1) || rc=$?
	if [ "$want" = ok ]; then
		[ "$rc" -eq 0 ] && return 0
		echo "FAIL $name: refused (rc $rc): $out"
	else
		[ "$rc" -ne 0 ] && grep -q -F -- "$want" <<<"$out" && return 0
		echo "FAIL $name: rc $rc, want a refusal with \"$want\": $out"
	fi
	failed=$((failed + 1))
}

# Something else the front logs, in every case: a page, a WebSocket upgrade
# it did not make (both senders dial one first), a GET of /http-bind (the
# deployment's own probe), a path that only starts like /http-bind.
noise() {
	printf 'web-1  | 10.0.0.9 - - [21/Nov/2026:18:31:11 +0000] "GET /xmpp-websocket?room=probe HTTP/1.1" 200 23207 "" "curl/8.5.0"\n'
	printf 'web-1  | 10.0.0.9 - - [21/Nov/2026:18:31:12 +0000] "GET /http-bind?room=probe HTTP/1.1" 200 23207 "" "curl/8.5.0"\n'
	printf 'web-1  | 10.0.0.9 - - [21/Nov/2026:18:32:04 +0000] "GET /xmpp-websocket-closed?room=r HTTP/1.1" 200 8817 "" "%s"\n' "$rust_agent"
	printf 'web-1  | 10.0.0.9 - - [21/Nov/2026:18:32:04 +0000] "POST /http-bindings HTTP/1.1" 200 8817 "" "%s"\n' "$rust_agent"
	printf 'web-1  | 10.0.0.9 - - [21/Nov/2026:18:32:04 +0000] "GET /config.js HTTP/1.1" 200 4845 "" "%s"\n' "$rust_agent"
}

# The Rust client over BOSH, the exit on its WebSocket.
{
	noise
	post "$rust_agent" 200
	post "$rust_agent" 200
	post "$rust_agent" 499
} >"$tmp/web.log"
{ session; } >"$tmp/prosody.log"
check "rust: the Rust client's requests alone" rust ok
check "all: no request of the Go library" all "no /http-bind request of the Go library"

# Everyone over BOSH.
{
	noise
	post "$go_agent" 200 /http-bind HTTP/2.0
	post "$rust_agent" 200
	post "$rust_agent" 200 '/http-bind?room=r'
} >"$tmp/web.log"
{
	session
	session
} >"$tmp/prosody.log"
check "all: both senders" all ok
check "rust: a Go engine over BOSH beside an open WebSocket" rust "the exit was to keep its WebSocket"

# The Go library alone: the lab run before the Rust client had BOSH.
{
	noise
	post "$go_agent" 200 /http-bind HTTP/2.0
	post "$go_agent" 200 /http-bind HTTP/2.0
} >"$tmp/web.log"
check "rust: the Go library alone" rust "did not go over BOSH"
check "all: the Go library alone" all "did not go over BOSH"

# Nothing posted to /http-bind at all (the noise is not a request of it).
{ noise; } >"$tmp/web.log"
check "rust: no BOSH request at all" rust "did not go over BOSH"

# The Rust client's requests, none answered 200.
{
	noise
	post "$rust_agent" 404
	post "$rust_agent" 502
} >"$tmp/web.log"
check "rust: no request answered 200" rust "was answered 200"

# The front's requests but no session of Prosody's.
{
	noise
	post "$rust_agent" 200
} >"$tmp/web.log"
printf "prosody-1  | 2026-11-21 18:32:04 mod_websocket info\tNew WebSocket session\n" >"$tmp/prosody.log"
check "rust: Prosody made no BOSH session" rust "made no BOSH session"

# An empty log is no log.
: >"$tmp/prosody.log"
check "rust: an empty Prosody log" rust "is empty"

[ "$failed" -eq 0 ] || {
	echo "bosh.test.sh: $failed of $ran failed"
	exit 1
}
echo "bosh.test.sh: $ran tests ok"

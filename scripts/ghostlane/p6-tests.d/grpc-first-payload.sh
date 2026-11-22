#!/usr/bin/env bash
# grpc-first-payload.sh <host|windows-report>
#
# A drop-in of p6-ci.sh. A request a client writes once and then waits on
# reaches the server over VLESS on gRPC: the request header held for the first
# payload (crates/xray-core-rs/src/outbound/first_payload.rs, HeldHeader) is
# reported written only once its carrier has taken it.
#
#   host            1. xray-core-rs is formatted;
#                   2. the held header's own tests: a first payload over a
#                      carrier that cannot take it yet waits with it and
#                      leaves behind the header when it opens, with no flush;
#                   3. a SOCKS inbound that sniffs (routeOnly) and a VLESS
#                      gRPC outbound, against a stand-in gRPC inbound that
#                      answers only a whole request: on a current-thread
#                      runtime, and sixty flows on three cores on a
#                      multi-threaded one (grpc_first_payload_tests);
#                   4. on Linux, the same flows with REALITY under gRPC, and
#                      under XHTTP in stream-one mode (an HTTP/2 uplink too),
#                      against the official Xray releases 26.4.25, 26.7.11 and
#                      26.11.9, fetched and checked against their sha256, a new
#                      core a round; the FIRST-PAYLOAD lines go to the job
#                      summary.
#                   Every step runs; one that fails fails the script.
#   windows-report  nothing to add to the report.
#
# bash 3.2 safe (macOS).
set -uo pipefail
mode="${1:?usage: grpc-first-payload.sh host|windows-report}"
[ "$mode" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

bad=0
step() {
    local name="$1"
    shift
    echo "== grpc-first-payload: $name"
    if "$@"; then
        echo "ok: $name"
    else
        echo "FAILED: $name" >&2
        bad=1
    fi
}

# fetch_xray <dir>: the official Xray-linux-64 builds, each checked against
# the sha256 its release's .dgst gives; prints "<version>=<path> ...".
fetch_xray() {
    local dir="$1" version sum out got servers=""
    while read -r version sum; do
        out="$dir/$version"
        mkdir -p "$out"
        curl -fsSL --retry 3 -o "$out/xray.zip" \
            "https://github.com/XTLS/Xray-core/releases/download/v$version/Xray-linux-64.zip" || return 1
        got="$(sha256sum "$out/xray.zip" | cut -d' ' -f1)"
        if [ "$got" != "$sum" ]; then
            echo "Xray v$version: the archive hashes to $got, pinned $sum" >&2
            return 1
        fi
        unzip -oq "$out/xray.zip" xray -d "$out" || return 1
        chmod +x "$out/xray"
        servers="${servers:+$servers }$version=$out/xray"
    done <<'PINS'
26.4.25 a4ec9c037933b6730fb29e4f7a6674647f40b0b9f40870411071dd6382ea87a8
26.7.11 aa11c3685c71da0ffc71e511db50404609e7e963bb914b048f59a6a00af8930e
26.11.9 b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
PINS
    echo "$servers"
}

official_xray() {
    local tmp servers out status=0
    tmp="$(mktemp -d)"
    servers="$(fetch_xray "$tmp")" || return 1
    out="$tmp/run.log"
    XRAY_SERVERS="$servers" GRPC_FIRST_PAYLOAD_ROUNDS=6 GRPC_FIRST_PAYLOAD_FLOWS=3 \
        cargo test --locked -p xray-core-rs --test grpc_first_payload_tests -- --ignored --nocapture \
        > "$out" 2>&1 || status=$?
    cat "$out"
    {
        echo "### A request written once, over REALITY under gRPC and XHTTP stream-one, against official Xray"
        echo
        echo '```'
        grep '^FIRST-PAYLOAD' "$out" || echo "no FIRST-PAYLOAD line was printed"
        echo '```'
    } >> "$summary"
    rm -rf "$tmp"
    return "$status"
}

step "formatted" cargo fmt -p xray-core-rs -- --check
step "the held header's own tests" cargo test --locked -p xray-core-rs --lib -- outbound::first_payload::tests
step "a sniffed request over gRPC, against a stand-in" cargo test --locked --no-fail-fast -p xray-core-rs --test grpc_first_payload_tests -- --nocapture
if [ "$(uname -s)" = Linux ]; then
    step "the same over REALITY, against official Xray" official_xray
fi
exit "$bad"

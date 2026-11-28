#!/usr/bin/env bash
# vless-http.sh <host|windows-report>
#
# A drop-in of p6-ci.sh. VLESS over the `http` transport (`type=http`, HTTP/2),
# which Xray-core deleted and sing-box and v2fly lists still use. The core
# runs it as XHTTP in stream-one mode (one HTTP/2 request, its body the uplink
# and its answer the downlink):
#
#   host            1. xray-config is formatted;
#                   2. the parser and the link importer: `network: "http"`
#                      (and the old name `h2`) becomes xhttp stream-one with
#                      the first host and the path, ALPN h2 by default, a
#                      warning saying so; a link's `type=http` imports;
#                   3. on Linux, against the official sing-box 1.13.20
#                      release (fetched, checked against its sha256) as the
#                      server, a VLESS inbound on `transport: http` over TLS
#                      and over REALITY: a 4 MiB download, a 4 MiB upload and a
#                      second download through the core, every byte checked
#                      (xray-core-rs's vless_http_sing_box_tests).
#                   Every step runs; one that fails fails the script.
#   windows-report  nothing to add to the report.
#
# bash 3.2 safe (macOS).
set -uo pipefail
mode="${1:?usage: vless-http.sh host|windows-report}"
[ "$mode" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never

bad=0
step() {
    local name="$1"
    shift
    echo "== vless-http: $name"
    if "$@"; then
        echo "ok: $name"
    else
        echo "FAILED: $name" >&2
        bad=1
    fi
}

SING_BOX_VERSION=1.13.20
SING_BOX_SHA256=646bc01bf128c32a12eb50d8690e387bba7504da7b1d65c704bd53916e38595a

against_sing_box() {
    local tmp got status=0
    tmp="$(mktemp -d)"
    curl -fsSL --retry 3 -o "$tmp/sing-box.tgz" \
        "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/sing-box-$SING_BOX_VERSION-linux-amd64.tar.gz" || { rm -rf "$tmp"; return 1; }
    got="$(sha256sum "$tmp/sing-box.tgz" | cut -d' ' -f1)"
    if [ "$got" != "$SING_BOX_SHA256" ]; then
        echo "sing-box $SING_BOX_VERSION: the archive hashes to $got, pinned $SING_BOX_SHA256" >&2
        rm -rf "$tmp"
        return 1
    fi
    tar -xzf "$tmp/sing-box.tgz" -C "$tmp" --strip-components=1 "sing-box-$SING_BOX_VERSION-linux-amd64/sing-box" || { rm -rf "$tmp"; return 1; }
    SING_BOX="$tmp/sing-box" cargo test --locked -p xray-core-rs --test vless_http_sing_box_tests \
        -- --ignored --nocapture --test-threads=1 || status=$?
    rm -rf "$tmp"
    return "$status"
}

step "formatted" cargo fmt -p xray-config -p xray-core-rs -- --check
step "the parser and the link importer" cargo test --locked --no-fail-fast -p xray-config --test http_transport_tests
if [ "$(uname -s)" = Linux ]; then
    step "a download and an upload through sing-box's http transport, over TLS and REALITY" against_sing_box
fi
exit "$bad"

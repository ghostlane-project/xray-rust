#!/usr/bin/env bash
# reality-hello-fallback.sh <host|windows-report>
#
# REALITY: the one retry with the short ClientHello when the configured one,
# with the X25519MLKEM768 share, is never answered
# (crates/xray-transport/src/reality_hello_fallback.rs).
#
#   host            the dial end to end, from the dialer through a path that
#                   cuts a long first flight to a REALITY server and back,
#                   with the REALITY runtime and connector tests that dial
#                   shares; the memory's own tests and the REALITY and
#                   TLS-carrier tests of the files the watch touches; the
#                   core's log line. Every group runs, so a red run names all
#                   that fails.
#   windows-report  nothing to add to the report.
#
# bash 3.2 safe (macOS).
set -euo pipefail

mode="${1:?usage: reality-hello-fallback.sh host|windows-report}"
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."

bad=0
run() {
    echo "== $*"
    "$@" || bad=1
}

case "$mode" in
host)
    run cargo test --locked --no-fail-fast -p xray-transport \
        --test reality_hello_fallback_tests \
        --test reality_runtime_tests \
        --test reality_connector_tests
    run cargo test --locked -p xray-transport --lib -- reality penetrating_tls
    run cargo test --locked -p xray-core-rs --lib -- reality_hello
    exit "$bad"
    ;;
windows-report)
    exit 0
    ;;
*)
    echo "unknown mode $mode" >&2
    exit 2
    ;;
esac

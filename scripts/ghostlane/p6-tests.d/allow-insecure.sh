#!/usr/bin/env bash
# allow-insecure.sh <host|windows-report>
#
# A drop-in of p6-ci.sh. `tlsSettings.allowInsecure: true` is honoured only
# when a config says so:
#
#   host            1. xray-config, xray-transport and xray-core-rs are
#                      formatted;
#                   2. against self-signed servers on loopback, over TCP TLS
#                      and over Hysteria 2's QUIC (no pin): refused without
#                      the flag, carried with it, the same server name and
#                      ALPN either way, a pin or a verification name beside it
#                      still verifying (xray-transport's allow_insecure_tests);
#                      the same from a parsed config through a running core
#                      (VLESS, Trojan and VMess over TCP TLS, Hysteria 2),
#                      the parse warning naming the outbound and its server,
#                      and a REALITY line that does not read the flag
#                      (xray-core-rs's allow_insecure_tests); the Hysteria
#                      outbound handing the flag to its QUIC client;
#                   3. the parser: where the flag is taken, warned about and
#                      refused (xray-config's allow_insecure_tests);
#                   4. on Linux, every xray-config test and the command line's
#                      config check fixtures, since the TLS parser changed
#                      under them, and clippy on the three crates.
#                   Every step runs; one that fails fails the script.
#   windows-report  nothing to add to the report.
#
# bash 3.2 safe (macOS).
set -uo pipefail
mode="${1:?usage: allow-insecure.sh host|windows-report}"
[ "$mode" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never

bad=0
step() {
    local name="$1"
    shift
    echo "== allow-insecure: $name"
    if "$@"; then
        echo "ok: $name"
    else
        echo "FAILED: $name" >&2
        bad=1
    fi
}

step "formatted" cargo fmt -p xray-config -p xray-transport -p xray-core-rs -- --check
step "the transport waives the check only when told" cargo test --locked --no-fail-fast -p xray-transport --test allow_insecure_tests
step "a config's flag through a running core" cargo test --locked --no-fail-fast -p xray-core-rs --test allow_insecure_tests
step "the Hysteria outbound hands the flag on" cargo test --locked -p xray-core-rs --lib -- outbound::hysteria::tests
step "the parser" cargo test --locked --no-fail-fast -p xray-config --test allow_insecure_tests
if [ "$(uname -s)" = Linux ]; then
    step "every xray-config test" cargo test --locked --no-fail-fast -p xray-config
    step "the command line's config check fixtures" cargo test --locked --no-fail-fast -p xray-cli --test config_tooling_tests
    step "clippy on the three crates" cargo clippy --locked -p xray-config -p xray-transport -p xray-core-rs --all-targets -- -D warnings
fi
exit "$bad"

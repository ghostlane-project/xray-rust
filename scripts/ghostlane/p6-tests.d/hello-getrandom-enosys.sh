#!/usr/bin/env bash
# hello-getrandom-enosys.sh <host|windows-report>
#
# A drop-in of p6-ci.sh. REALITY and uTLS-shaped TLS ClientHello generation
# and handshakes on kernels where SYS_getrandom returns ENOSYS and RNDGETENTCNT
# stays below 256 bits (Linux < 3.17, Android 6 and 7):
#
#   host            1. xray-transport is formatted;
#                   2. getrandom_enosys_tests: on Linux, child processes under
#                      a seccomp-BPF filter returning ENOSYS for SYS_getrandom
#                      and 160 bits for RNDGETENTCNT dial local REALITY and
#                      shaped-TLS servers within 4 s and match the normal
#                      ClientHello wire shape; on all host OSes, post-quantum
#                      REALITY and shaped-TLS hello layouts match their profiles;
#                   3. reality_rustls_tests and utls_tls_shaping_tests keep
#                      passing with ClientHello bytes unchanged.
#   windows-report  nothing to add to the report.
#
# bash 3.2 safe (macOS).
set -uo pipefail
mode="${1:?usage: hello-getrandom-enosys.sh host|windows-report}"
[ "$mode" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never

bad=0
step() {
    local name="$1"
    shift
    echo "== hello-getrandom-enosys: $name"
    if "$@"; then
        echo "ok: $name"
    else
        echo "FAILED: $name" >&2
        bad=1
    fi
}

step "formatted" cargo fmt -p xray-transport -- --check
step "hellos without getrandom" cargo test --locked --no-fail-fast -p xray-transport --test getrandom_enosys_tests -- --nocapture
step "REALITY and uTLS ClientHello oracle parity" cargo test --locked --no-fail-fast -p xray-transport --test reality_rustls_tests --test utls_tls_shaping_tests
exit "$bad"

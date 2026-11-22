#!/usr/bin/env bash
# two-cores.sh <host|windows-report>
#
# A drop-in of p6-ci.sh: two running xray-ffi handles in one process, each
# with its own inbound and protector, beside the one byte budget.
set -uo pipefail
[ "${1:?usage: two-cores.sh host|windows-report}" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
export CARGO_TERM_COLOR=never
echo "== two-cores"
cargo test --locked -p xray-ffi --test two_cores || exit 1
cargo test --locked -p xray-ffi --features shared-runtime --test two_cores

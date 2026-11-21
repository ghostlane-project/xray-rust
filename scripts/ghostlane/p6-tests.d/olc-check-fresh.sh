#!/usr/bin/env bash
# Drop-in of scripts/ghostlane/p6-ci.sh: a room check, a ping and a start in
# every order, each in a process of its own, against a fake carrier on
# loopback (olc/olc-ffi/tests/check_fresh_process.rs). The olc crates do not
# build for Windows yet, so that leg skips.
set -euo pipefail
[ "${1:-host}" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
cargo test --locked -p olc-ffi --features boring --test check_fresh_process

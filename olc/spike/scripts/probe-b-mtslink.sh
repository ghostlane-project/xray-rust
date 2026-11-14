#!/bin/bash
# Probe (b): str0m (the Rust sdp-bridge) joins a real MTS Link room, the engine's own Go
# code doing the service's part (go/mtslink/zz_spike_bridge_test.go says what each side does).
#
#   OLC_SPIKE_MTSLINK_ROOM=<link> probe-b-mtslink.sh <engine-checkout> <sdp-bridge-binary> [bridge flags...]
#
# The link is an MTS Link event join link of an endless meeting,
# https://my.mts-link.ru/j/<owner>/<event>, from the environment only: it is a secret of the
# engine's gate (GATE_MTSLINK_ROOMS / OLCRTC_GATE_MTSLINK_ROOMS); never put it on a command
# line. A guest needs no account. Runs from a build box or a CI runner, never from a
# production host. The bridge's stderr goes to $OLC_SPIKE_OUT (default ./probe-b.out); its
# RESULT line is printed at the end.
set -euo pipefail
: "${OLC_SPIKE_MTSLINK_ROOM:?set OLC_SPIKE_MTSLINK_ROOM in the environment}"
spike=$(cd "$(dirname "$0")/.." && pwd)
exec "$spike/scripts/run-drop-in.sh" mtslink TestSpikeBridgeMTSLink "${OLC_SPIKE_OUT:-$PWD/probe-b.out}" "$@"

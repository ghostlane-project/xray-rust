#!/bin/bash
# Probe (c): str0m (the Rust sdp-bridge) answers a real VK Calls SFU, the engine's own Go
# code doing the service's part (go/vkcalls/zz_spike_bridge_test.go says what each side does).
#
#   OLC_SPIKE_VKCALLS_ROOM=<link> probe-c-vkcalls.sh <engine-checkout> <sdp-bridge-binary> [bridge flags...]
#
# The link is a VK Calls join link, https://vk.ru/call/join/<id>, from the environment only:
# it is a secret of the engine's gate (GATE_VKCALLS_ROOMS / OLCRTC_GATE_VKCALLS_ROOMS); never
# put it on a command line. Guests are anonymous (the engine's five-step chain); the call
# itself is one an account started. Runs from a build box or a CI runner, never from a
# production host. The bridge's stderr goes to $OLC_SPIKE_OUT (default ./probe-c.out); its
# RESULT line is printed at the end.
set -euo pipefail
: "${OLC_SPIKE_VKCALLS_ROOM:?set OLC_SPIKE_VKCALLS_ROOM in the environment}"
spike=$(cd "$(dirname "$0")/.." && pwd)
exec "$spike/scripts/run-drop-in.sh" vkcalls TestSpikeBridgeVKCalls "${OLC_SPIKE_OUT:-$PWD/probe-c.out}" "$@"

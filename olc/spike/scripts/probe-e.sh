#!/bin/bash
# Probe (e): the TURN transports in SaluteJazz's rtc:config, from an anonymous room join.
#
#   probe-e.sh <engine-checkout>
#
# Joins a live SaluteJazz room (made anonymously, as the engine's carrier makes it), so it
# runs from a build box or a CI runner, never from a production host. Prints the RTC_CONFIG
# lines: every ICE URL, the transport a client opens for it, the credentials as lengths only.
set -euo pipefail
engine=$(cd "${1:?engine checkout}" && pwd)
spike=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -C "$engine" --exclude=.git -cf - . | tar -C "$work" -xf -
cp "$spike/go/salutejazz/zz_spike_rtcconfig_test.go" "$work/internal/engine/salutejazz/"
cd "$work"
OLC_SPIKE_LIVE=1 go test ./internal/engine/salutejazz -run '^TestSpikeRTCConfig$' -count=1 -v -timeout 180s

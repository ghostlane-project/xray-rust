#!/bin/bash
# Captures Chrome's own WebRTC wire shapes: STUN binding requests and the DTLS ClientHello.
#
#   chrome-capture.sh <outdir> [chrome-binary]
#
# Runs chrome-loop.html (two peer connections in one headless Chrome) with host candidates
# in the clear (the mDNS hiding feature off), and tcpdump on every interface meanwhile.
# Writes <outdir>/chrome.pcap and <outdir>/chrome.log (the page's OLC_SPIKE lines and the
# version). Needs sudo for tcpdump (a CI runner has it).
set -euo pipefail
out=${1:?outdir}
chrome=${2:-$(command -v google-chrome || command -v google-chrome-stable || command -v chromium)}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
"$chrome" --version | tee "$out/chrome.log"
sudo tcpdump -i any -U -s 0 -w "$out/chrome.pcap" udp >/dev/null 2>&1 &
dump=$!
sleep 2
profile=$(mktemp -d)
timeout 25 "$chrome" --headless=new --no-sandbox --disable-gpu --no-first-run \
  --user-data-dir="$profile" --disable-features=WebRtcHideLocalIpsWithMdns \
  --enable-logging=stderr --v=0 "file://$here/chrome-loop.html" 2>&1 \
  | grep -a 'OLC_SPIKE' | tee -a "$out/chrome.log" || true
sleep 1
sudo kill -INT "$dump" 2>/dev/null || true
wait "$dump" 2>/dev/null || true
sudo chmod a+r "$out/chrome.pcap"
rm -rf "$profile"
grep -q 'ECHO_OK' "$out/chrome.log"

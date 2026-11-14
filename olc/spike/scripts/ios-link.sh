#!/bin/bash
# Probe (d), the link half: links the Rust static library into a C program for an iOS
# target, once plainly and once with -all_load (every archive member forced in, so a
# duplicate symbol anywhere is a link error), then runs both in the booted simulator when
# the target is the simulator.
#
#   ios-link.sh <target-triple> <libolc_spike_ios_link.a> <outdir> [simulator-udid]
#
# Prints LINK_OK/LINK_FAIL per variant, the binaries' sizes, and the RESULT line of each run.
set -uo pipefail
target=${1:?triple}; lib=${2:?static library}; out=${3:?outdir}; udid=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
case "$target" in
  aarch64-apple-ios-sim) sdk=iphonesimulator; triple=arm64-apple-ios17.0-simulator ;;
  x86_64-apple-ios) sdk=iphonesimulator; triple=x86_64-apple-ios17.0-simulator ;;
  aarch64-apple-ios) sdk=iphoneos; triple=arm64-apple-ios17.0 ;;
  *) echo "unknown target $target"; exit 2 ;;
esac
mkdir -p "$out"
sysroot=$(xcrun --sdk "$sdk" --show-sdk-path)
rc=0
for variant in plain all_load; do
  extra=()
  [ "$variant" = all_load ] && extra=(-Wl,-all_load)
  bin="$out/c-$variant"
  if xcrun --sdk "$sdk" clang -target "$triple" -isysroot "$sysroot" "$here/../ios-link/c/main.c" \
      ${extra[@]+"${extra[@]}"} "$lib" -lc++ -framework Security -framework CoreFoundation -lresolv \
      -o "$bin" 2> "$out/link-$variant.err"; then
    echo "LINK_OK $variant $(stat -f %z "$bin") bytes"
  else
    echo "LINK_FAIL $variant"; grep -E 'duplicate symbol|error' "$out/link-$variant.err" | head -20
    rc=1; continue
  fi
  if [ -n "$udid" ] && [ "$sdk" = iphonesimulator ]; then
    if xcrun simctl spawn "$udid" "$bin" > "$out/run-$variant.out" 2> "$out/run-$variant.err"; then
      echo "RUN_OK $variant"
    else
      echo "RUN_FAIL $variant"; tail -20 "$out/run-$variant.err"; rc=1
    fi
    grep -h '^RESULT\|^HANDSHAKE\|^TLS_OK\|^MEM' "$out/run-$variant.out" "$out/run-$variant.err" | sed "s/^/[$variant] /"
  fi
done
exit $rc

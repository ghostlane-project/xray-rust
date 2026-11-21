#!/usr/bin/env bash
# p6-ci.sh <host|windows-report>
#
# What ghostlane-p6.yml runs on the program's branches (p6/**).
#
#   host            builds the host target of the crates Ghostlane ships
#                   (ghostlane-core with the `boring` feature, which brings
#                   xray-ffi and olc-ffi, exactly the feature set the apps'
#                   build scripts use) and runs the tests named below.
#   windows-report  `cargo check`s the same crates and the olc crates under
#                   them with --keep-going, and prints per crate how many
#                   errors the compiler reported (job summary and stdout).
#                   Today the olc crates use std::os::fd with no cfg, so
#                   Windows is expected to fail. The script exits 0 unless
#                   P6_WINDOWS_REQUIRED=1.
#
# bash 3.2 safe (macOS); needs rustup, cmake, a C/C++ compiler and clang
# (boring-sys's bindgen), python3.
set -euo pipefail

mode="${1:?usage: p6-ci.sh host|windows-report|selftest}"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0 CARGO_NET_RETRY=5
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
say() { echo "== $*"; }

# The crates, in dependency order. The first group is what the app links.
SHIPPED="ghostlane-core xray-ffi olc-ffi"
OLC_CRATES="olc-wire olc-kcp olc-vp8channel olc-muxconn olc-net olc-rtc olc-salutejazz olc-mtslink olc-vkcalls olc-client olc-ffi"

host_tests() {
    # ghostlane-core: both cores on one runtime and one byte budget.
    cargo test --locked -p ghostlane-core --features boring
    # olc-ffi: closing a client.
    cargo test --locked -p olc-ffi --features boring --test close_tests
    # xray-ffi: the C ABI.
    cargo test --locked -p xray-ffi --test ffi_tests
}

case "$mode" in
host)
    os="$(uname -s)"
    say "host target: $(rustc -vV | sed -n 's/^host: //p') on $os"
    cargo build --locked -p ghostlane-core --features boring
    echo "BUILD ghostlane-core --features boring: ok on $(rustc -vV | sed -n 's/^host: //p')"
    host_tests
    {
        echo "### Host build with BoringSSL: $(rustc -vV | sed -n 's/^host: //p')"
        echo
        echo "ghostlane-core with the \`boring\` feature builds, and the tests pass (ghostlane-core, olc-ffi close_tests, xray-ffi ffi_tests)."
    } >> "$summary"
    ;;
windows-report)
    tmp="$(mktemp -d)"
    total=0
    {
        echo "### Windows check, errors the compiler reported per crate"
        echo
    } >> "$summary"
    for feat in boring none; do
        out="$tmp/$feat.json"; err="$tmp/$feat.err"
        args=(check --locked --keep-going --message-format=json -p ghostlane-core)
        for c in $OLC_CRATES; do args+=(-p "$c"); done
        [ "$feat" = boring ] && args+=(--features ghostlane-core/boring)
        say "cargo ${args[*]}"
        status=0
        cargo "${args[@]}" > "$out" 2> "$err" || status=$?
        echo "cargo check exit status ($feat): $status"
        pyf="$tmp/count.py"
        cat > "$pyf" <<'PY'
import json, re, sys, collections
out, err, feat, status, summary = sys.argv[1:6]
counts = collections.Counter()
built = set()
codes = collections.defaultdict(collections.Counter)
def name(pid):
    # "registry+https://...#name@1.0", "path+file:///dir/name#1.0" or "name 1.0 (path+...)"
    m = re.search(r"#([A-Za-z0-9_-]+)@", pid)
    if m:
        return m.group(1)
    m = re.search(r"/([A-Za-z0-9_-]+)#[0-9]", pid)
    if m:
        return m.group(1)
    m = re.match(r"([A-Za-z0-9_-]+) ", pid)
    return m.group(1) if m else pid
for line in open(out, errors="replace"):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("reason") == "compiler-artifact":
        built.add(name(d.get("package_id", "?")))
        continue
    if d.get("reason") != "compiler-message":
        continue
    m = d["message"]
    if m.get("level") != "error":
        continue
    txt = m.get("message", "")
    if txt.startswith("aborting due to") or txt.startswith("could not compile"):
        continue
    c = name(d.get("package_id", "?"))
    counts[c] += 1
    codes[c][(m.get("code") or {}).get("code") or "-"] += 1
stderr = open(err, errors="replace").read()
scripts = sorted(set(re.findall(r"failed to run custom build command for `([^`]+)`", stderr)))
lines = []
lines.append("Features: %s. cargo check exit status %s." % ("ghostlane-core/boring" if feat == "boring" else "default (no boring)", status))
lines.append("")
lines.append("| crate | compiler errors | error codes |")
lines.append("|---|---|---|")
for c in sorted(counts):
    lines.append("| %s | %d | %s |" % (c, counts[c], ", ".join("%s x%d" % kv for kv in sorted(codes[c].items()))))
if not counts:
    lines.append("| (none) | 0 | |")
if scripts:
    lines.append("")
    lines.append("Build scripts that failed: " + ", ".join(scripts))
asked = sys.argv[6].split()
notdone = [c for c in asked if c not in built and c not in counts]
if notdone:
    lines.append("")
    lines.append("Not reached (a crate they need failed first, so their own errors are not counted yet): " + ", ".join(notdone))
lines.append("")
text = "\n".join(lines)
print(text, file=sys.stderr)
open(summary, "a").write(text + "\n")
print(sum(counts.values()) + len(scripts))
PY
        n=$(python3 -I "$pyf" "$out" "$err" "$feat" "$status" "$summary" "ghostlane-core $OLC_CRATES")
        total=$((total + n))
    done
    echo "windows-report: $total problems in total"
    if [ "$total" -gt 0 ] && [ "${P6_WINDOWS_REQUIRED:-0}" = 1 ]; then
        echo "P6_WINDOWS_REQUIRED=1 and the Windows check is not clean" >&2
        exit 1
    fi
    ;;
selftest)
    # Seconds-long checks of the script's own rules, run on every leg.
    st="$(mktemp -d)"; fail=0
    ok() { if [ "$1" = "$2" ]; then echo "ok: $3"; else echo "FAIL: $3 (got $1, want $2)"; fail=1; fi; }
    # 1. drop-in tests run sorted, with the mode, and one failing fails the lot.
    mkdir "$st/d"
    printf 'echo "$1" >> "%s/ran"\n' "$st" > "$st/d/20-b.sh"
    printf 'echo "$1" >> "%s/ran"\n' "$st" > "$st/d/10-a.sh"
    P6_TESTS_DIR="$st/d" run_dropins host && r=0 || r=$?
    ok "$r" 0 "drop-ins that pass pass"
    ok "$(tr '\n' ' ' < "$st/ran")" "host host " "both drop-ins ran with the mode"
    printf 'exit 3\n' > "$st/d/15-bad.sh"
    P6_TESTS_DIR="$st/d" run_dropins host >/dev/null 2>&1 && r=0 || r=$?
    ok "$r" 1 "a failing drop-in fails"
    P6_TESTS_DIR="$st/none" run_dropins host && r=0 || r=$?
    ok "$r" 0 "no drop-in directory is fine"
    # 2. the Windows verdict: required fails on errors, on a cargo failure with
    #    no compiler message, and on a failing drop-in; not required never fails.
    ok "$(windows_exit_code 1 0 0 0)" 0 "required, all clean"
    ok "$(windows_exit_code 1 3 0 0)" 1 "required, compiler errors"
    ok "$(windows_exit_code 1 0 101 0)" 1 "required, cargo failed with no message"
    ok "$(windows_exit_code 1 0 0 1)" 1 "required, a drop-in failed"
    ok "$(windows_exit_code 0 3 101 1)" 0 "not required never fails"
    # 3. the report names every crate: an error in xray-wireguard leaves xray-ffi unreached.
    printf '%s\n' '{"reason":"compiler-artifact","package_id":"path+file:///w/crates/olc-wire#0.1.0"}' \
        '{"reason":"compiler-message","package_id":"path+file:///w/crates/xray-wireguard#0.1.0","message":{"level":"error","message":"x","code":{"code":"E0433"}}}' > "$st/o.json"
    : > "$st/e.err"; : > "$st/sum"
    write_report_py "$st/count.py"
    n=$(python3 -I "$st/count.py" "$st/o.json" "$st/e.err" none 101 "$st/sum" "olc-wire xray-wireguard xray-ffi")
    ok "$n" 1 "one error counted"
    ok "$(grep -c 'olc-wire | clean' "$st/sum")" 1 "a clean crate is listed as clean"
    ok "$(grep -c 'xray-wireguard | 1 error' "$st/sum")" 1 "an erroring crate is listed with its count"
    ok "$(grep -c 'xray-ffi | not reached' "$st/sum")" 1 "an unreached crate is listed as not reached"
    exit "$fail"
    ;;
*)
    echo "unknown mode $mode" >&2; exit 2 ;;
esac

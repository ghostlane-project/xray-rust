#!/usr/bin/env bash
# ext-lists.sh <host|windows-report>
#
# A drop-in of p6-ci.sh. Lists named through `ext:file.dat:tag`:
#   - xray-config's ext_lists: a routing rule, the DNS outbound's rule and a
#     DNS server read a generated v2fly .dat and match what the tag holds and
#     nothing else;
#   - xray-core-rs's list_memory: 81,000 names and 25,000 prefixes load that
#     way; the heap they hold, the peak and the load time are printed (the
#     LIST-MEMORY lines, copied to the job summary) and the heap is held under
#     the test's ceilings.
# The Windows leg is a report of compiler errors and runs no test.
set -euo pipefail
mode="${1:?usage: ext-lists.sh host|windows-report}"
[ "$mode" = host ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

cargo test --locked -p xray-config --test ext_lists

out="$(mktemp)"
status=0
cargo test --locked -p xray-core-rs --test list_memory -- --nocapture > "$out" 2>&1 || status=$?
cat "$out"
{
    echo "### ext: lists, the heap of 81,000 names and 25,000 prefixes ($(uname -s))"
    echo
    echo '```'
    grep '^LIST-MEMORY' "$out" || echo "no LIST-MEMORY line was printed"
    echo '```'
} >> "$summary"
exit "$status"

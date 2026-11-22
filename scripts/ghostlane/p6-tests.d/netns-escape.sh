#!/usr/bin/env bash
# netns-escape.sh <host|windows-report>
#
# A drop-in of p6-ci.sh for ghostlane-engine's bound sockets on Linux.
#
#   host            on Linux only (the ubuntu leg; it needs passwordless sudo,
#                   which GitHub's ubuntu runners have):
#                   1. builds the engine as shipped, with the rooms and
#                      BoringSSL;
#                   2. reads the built program's symbol table: it must define
#                      BoringSSL's SSL_CTX_new and DTLS_method (AWS-LC, which
#                      the core links as well, prefixes its symbols and has
#                      no DTLS_method);
#                   3. runs crates/ghostlane-engine/tests/netns_escape.sh as
#                      root: in a network namespace whose default route is a
#                      tunnel, every socket of the engine but loopback's
#                      leaves by the interface the session names, for a line,
#                      a `none` room and a room on a fake carrier.
#                   A runner where no namespace can be made fails the step:
#                   it is not skipped. Other systems have nothing to run.
#   windows-report  nothing: the engine binds no socket on Windows yet.
set -uo pipefail
mode="${1:?usage: netns-escape.sh host|windows-report}"
[ "$mode" = host ] || exit 0
[ "$(uname -s)" = Linux ] || exit 0
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
export CARGO_TERM_COLOR=never

engine="${CARGO_TARGET_DIR:-target}/debug/ghostlane-engine"
bad=0
boring="not read"
escape="not run"

echo "== netns-escape: build the engine with rooms and BoringSSL"
if ! cargo build --locked -p ghostlane-engine --features boring; then
    echo "FAILED: the engine does not build" >&2
    bad=1
fi

# BoringSSL's own names among the program's defined functions.
if [ "$bad" = 0 ]; then
    echo "== netns-escape: BoringSSL in the built program"
    names="$(nm "$engine" 2>/dev/null | awk 'NF >= 3 && $(NF - 1) ~ /^[Tt]$/ { print $NF }' | sort -u)"
    missing=""
    for name in SSL_CTX_new DTLS_method; do
        grep -qx "$name" <<< "$names" || missing="$missing $name"
    done
    if [ -z "$missing" ]; then
        boring="the engine defines SSL_CTX_new and DTLS_method"
        echo "ok: $boring"
    else
        boring="the engine does not define${missing}"
        echo "FAILED: $boring ($(wc -l <<< "$names" | tr -d ' ') functions in its symbol table)" >&2
        bad=1
    fi
fi

if [ "$bad" = 0 ]; then
    echo "== netns-escape: every socket but loopback's leaves by the named interface"
    if ! sudo -n true; then
        escape="no passwordless sudo on this runner: no namespace can be made"
        echo "FAILED: $escape" >&2
        bad=1
    elif sudo -n bash crates/ghostlane-engine/tests/netns_escape.sh "$engine"; then
        escape="every case passed"
        echo "ok: the namespace test"
    else
        escape="a case failed: see the log of this job"
        echo "FAILED: the namespace test" >&2
        bad=1
    fi
fi

{
    echo "### ghostlane-engine: bound sockets on Linux"
    echo
    echo "- BoringSSL: $boring."
    echo "- The namespace test: $escape."
} >> "$summary"
exit "$bad"

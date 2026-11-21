#!/usr/bin/env bash
# first.sh <jicofo.log> <prosody.log>
#
# What a real Jicofo made of the Rust client's answer about itself (the
# gate's first step, -olcrtc.gate-jitsi-live-first; deploy.sh first runs this
# on the deployment's logs). It reads two logs and starts nothing.
#
# Jicofo learns what a participant can do by a disco#info query, and asks
# only the first participant that shows a caps hash it has not seen: the
# answer is checked against the hash and remembered for it. The Go engine
# and the Rust client show the same hash, and in every room of the gate the
# Go server joins first, so without the first step a deployment never asks
# the Rust client anything (run 44929668208: one query in the whole run, to
# the Go server). With it the Rust client is alone in a room named first-…
# before anyone else has joined, and this holds, from the logs:
#
#   1. every disco#info query by node that Jicofo sent went to an occupant of
#      a first-… room, and there is one. An answer that never came, or one
#      that does not hash to what the presence showed, is not remembered:
#      the next participant with the hash (a Go server, in a gate-… room)
#      would have been asked again;
#   2. the first participant whose features Jicofo logs as discovered is that
#      occupant, and no discovery failed;
#   3. every participant Jicofo then invited, the Go servers and clients of
#      the rows among them, was given the features below from that
#      remembered answer: the list Jicofo made of the Go engine's own answer
#      in run 44929668208, all 17 participants of that run alike.
set -euo pipefail

die() {
	echo "jitsi-live first: $*" >&2
	exit 1
}

jicofo=${1:?usage: first.sh <jicofo.log> <prosody.log>}
prosody=${2:?usage: first.sh <jicofo.log> <prosody.log>}
[ -s "$jicofo" ] || die "$jicofo is empty: no log of Jicofo"
[ -s "$prosody" ] || die "$prosody is empty: no log of Prosody"

want='[XMPP_CAPS, JSON_SOURCES, RECEIVE_MULTIPLE_STREAMS, REMB, SOURCE_NAMES, START_MUTED_RMD, TCC, VISITORS_V1, RTX, JINGLE, DTLS, JINGLE_RTP, AUDIO, VIDEO, SCTP, JINGLE_ICE]'
room='first-[0-9a-f]+@muc\.[^/ ]+/[^ ]+'

# 1. Whom Jicofo asked: the occupant each query by node was addressed to, as
# Prosody received it (mod_stanza_debug's RECV lines; attributes in any
# order).
asked=$(grep -a -F 'RECV: <iq ' "$prosody" |
	grep -a -F "disco#info' node='https://jitsi.org/jitsi-meet#" |
	grep -a -F "type='get'" |
	sed -n -E "s/.*RECV: <iq ([^>]* )?to='([^']*)'.*/\2/p" || true)
[ -n "$asked" ] || die "Jicofo asked no participant for its features: nothing joined before the caps hash was known?"
others=$(grep -v -E "^$room\$" <<<"$asked" || true)
[ -z "$others" ] || die "Jicofo asked someone other than the Rust client alone in its room; it did not keep that client's answer:
$others"

# 2. Whose features Jicofo discovered first, and that no discovery failed.
first=$(grep -a -o -m1 -E 'Discovered features for [^ ]+ in [0-9]+ ms' "$jicofo" || true)
[ -n "$first" ] || die "Jicofo's log has no discovered features"
grep -q -E "^Discovered features for $room in [0-9]+ ms\$" <<<"$first" ||
	die "the first participant Jicofo discovered was not the Rust client alone in its room: $first"
if failed=$(grep -a -i -E 'fail[a-z]* to discover|discover[a-z]* fail|disco[a-z#]* (timed out|timeout)' "$jicofo"); then
	die "a discovery failed:
$failed"
fi

# 3. What every invited participant was given.
given=$(grep -a -o -E 'Creating participant [^ ]+ with features=\[[^]]*\]' "$jicofo" | sed -E 's/^.* with features=//' || true)
count=$(grep -c . <<<"$given" || true)
[ "$count" -ge 2 ] || die "Jicofo invited $count participants: the rows did not run on this deployment"
differ=$(grep -v -x -F -- "$want" <<<"$given" | sort | uniq -c || true)
[ -z "$differ" ] || die "from the Rust client's answer Jicofo gave participants other features than from the Go engine's:
$differ
 want $want"

echo "jitsi-live first: Jicofo asked $(sort -u <<<"$asked" | wc -l) occupant(s), all of a first- room ($(wc -l <<<"$asked") queries);"
echo "jitsi-live first: $first;"
echo "jitsi-live first: $count invited participants, each with the 16 features the Go engine's answer gives."

#!/usr/bin/env bash
# first.test.sh: first.sh held to what it names, on logs written here in the
# shape docker-jitsi-meet's Jicofo and Prosody (mod_stanza_debug at debug
# level) write them. It starts nothing and needs nothing but bash, grep and
# sed:
#   bash olc/interop/jitsi-live/first.test.sh
#
# Prosody writes a stanza's attributes in the order of a Lua table, which is
# not the same from one start to the next: run 44951689810 logged Jicofo's
# query as <query node=... xmlns=...>, the runs before it as <query xmlns=...
# node=...>. Each order is read here, of the query and of its <iq>.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0
ran=0

room=first-0123456789ab@muc.meet.jitsi
gate=gate-ba5eba11cafe@muc.meet.jitsi
node='https://jitsi.org/jitsi-meet#AAAAbbbbCCCCddddEEEEffffGGGG='
info='http://jabber.org/protocol/disco#info'
features='[XMPP_CAPS, JSON_SOURCES, RECEIVE_MULTIPLE_STREAMS, REMB, SOURCE_NAMES, START_MUTED_RMD, TCC, VISITORS_V1, RTX, JINGLE, DTLS, JINGLE_RTP, AUDIO, VIDEO, SCTP, JINGLE_ICE]'

# p <text>: one line of Prosody's log, as `compose logs --no-color` gives it.
p() {
	printf 'prosody-1  | 2026-11-21 21:37:15 c2s55f414d5a1d0                                  debug\t%s\n' "$1"
}

# asked <occupant> <order>: Jicofo's query by node to <occupant>, as Prosody
# received it. <order>: xmlns-node, node-xmlns, or iq-reversed (node first in
# the query and the <iq>'s own attributes the other way round).
asked() {
	case $2 in
	xmlns-node) p "RECV: <iq id='E2I1G-7' to='$1' xml:lang='en-US' type='get'><query xmlns='$info' node='$node'/></iq>" ;;
	node-xmlns) p "RECV: <iq id='E2I1G-7' to='$1' xml:lang='en-US' type='get'><query node='$node' xmlns='$info'/></iq>" ;;
	iq-reversed) p "RECV: <iq type='get' xml:lang='en-US' to='$1' id='E2I1G-7'><query node='$node' xmlns='$info'/></iq>" ;;
	esac
}

# What Prosody logs in every case and is not a query by node that Jicofo
# sent: its queries without a node (the MUC service), the query as Prosody
# hands it on to the client (a SEND line), the client's own query of the room
# and its answer (a result), the client's request for services.
noise() {
	p "RECV: <iq id='E2I1G-6' to='muc.meet.jitsi' xml:lang='en-US' type='get'><query xmlns='$info'/></iq>"
	p "SEND: <iq from='$room/focus' id='Nm0x' to='c0ffee01-0000@meet.jitsi/res' xml:lang='en-US' type='get'><query node='$node' xmlns='$info'/></iq>"
	p "RECV: <iq id='j-1' to='$room' xml:lang='en' type='get'><query xmlns='$info'/></iq>"
	p "RECV: <iq id='Nm0x' to='$room/focus' xml:lang='en' type='result'><query xmlns='$info' node='$node'><feature var='http://jabber.org/protocol/caps'/></query></iq>"
	p "RECV: <iq id='disco_1' to='meet.jitsi' xml:lang='en' type='get'><services xmlns='urn:xmpp:extdisco:2'/></iq>"
}

# j <text>: one line of Jicofo's log.
j() {
	printf 'jicofo-1  | Jicofo 2026-11-21 21:37:15.324 INFO: [46] %s\n' "$1"
}

# discovered <occupant> [ms], invited <nick> [features]: Jicofo's two lines.
discovered() {
	j "[xmpp_connection=client] XmppProvider.discoverFeatures#286: Discovered features for $1 in ${2:-30} ms."
}
invited() {
	j "[room=$gate meeting_id=1987c233] JitsiMeetConferenceImpl.inviteChatMember#954: Creating participant $1 with features=${2:-$features}"
}

# A run that went as it should: the Rust client alone in the first room
# discovered first, the others from what Jicofo remembered, three invited.
good_jicofo() {
	discovered "$room/c0ffee01"
	discovered "$gate/1547c111" 1
	invited be94a8b9
	invited 1547c111
	invited 9473055c
}

# check <name> <want: ok|a word of the refusal>: first.sh on $tmp/jicofo.log
# and $tmp/prosody.log.
check() {
	local name=$1 want=$2 out rc=0
	ran=$((ran + 1))
	out=$(bash "$here/first.sh" "$tmp/jicofo.log" "$tmp/prosody.log" 2>&1) || rc=$?
	if [ "$want" = ok ]; then
		[ "$rc" -eq 0 ] && return 0
		echo "FAIL $name: refused (rc $rc): $out"
	else
		[ "$rc" -ne 0 ] && grep -q -F -- "$want" <<<"$out" && return 0
		echo "FAIL $name: rc $rc, want a refusal with \"$want\": $out"
	fi
	failed=$((failed + 1))
}

# The Rust client alone was asked, in each order Prosody writes it.
for order in xmlns-node node-xmlns iq-reversed; do
	good_jicofo >"$tmp/jicofo.log"
	{
		noise
		asked "$room/c0ffee01" "$order"
	} >"$tmp/prosody.log"
	check "the first room's occupant asked ($order)" ok
done

# Someone in a gate room was asked as well, in either order: Jicofo did not
# keep the Rust client's answer.
for order in xmlns-node node-xmlns; do
	good_jicofo >"$tmp/jicofo.log"
	{
		noise
		asked "$room/c0ffee01" xmlns-node
		asked "$gate/1547c111" "$order"
	} >"$tmp/prosody.log"
	check "a gate room's occupant asked too ($order)" "someone other than the Rust client"
done

# Nobody was asked: the query only as Prosody handed it on, and queries
# without a node.
good_jicofo >"$tmp/jicofo.log"
noise >"$tmp/prosody.log"
check "nobody asked" "asked no participant"

# The rest of first.sh, with the query as the runs before 44951689810 wrote
# it.
{
	noise
	asked "$room/c0ffee01" xmlns-node
} >"$tmp/prosody.log"
{
	discovered "$gate/1547c111"
	discovered "$room/c0ffee01"
	invited be94a8b9
	invited 1547c111
} >"$tmp/jicofo.log"
check "someone else discovered first" "was not the Rust client alone"
{
	good_jicofo
	j "[xmpp_connection=client] XmppProvider.discoverFeatures#290: Failed to discover features for $gate/9473055c"
} >"$tmp/jicofo.log"
check "a discovery failed" "a discovery failed"
{
	good_jicofo
	invited 0badf00d "[XMPP_CAPS, JINGLE, DTLS, AUDIO, VIDEO, SCTP, JINGLE_ICE]"
} >"$tmp/jicofo.log"
check "someone given other features" "other features than from the Go engine's"
{
	discovered "$room/c0ffee01"
	invited be94a8b9
} >"$tmp/jicofo.log"
check "one participant invited" "Jicofo invited 1 participants"
: >"$tmp/jicofo.log"
check "no log of Jicofo" "no log of Jicofo"
good_jicofo >"$tmp/jicofo.log"
: >"$tmp/prosody.log"
check "no log of Prosody" "no log of Prosody"

if [ "$failed" -ne 0 ]; then
	echo "first.test.sh: $failed of $ran tests failed"
	exit 1
fi
echo "first.test.sh: $ran tests ok"

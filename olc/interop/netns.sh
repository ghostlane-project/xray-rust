#!/usr/bin/env bash
# netns.sh <engine-client-shim> [set]
#
# K4's namespace leg: the engine, as the gate's Rust client, in a network
# namespace where only the named interface reaches anything. The fake carrier
# is SaluteJazz's fake SFU with every client relay-only through a pion TURN
# server (fakeroom.sh gate-relay), so a room's signalling, its ICE and its
# TURN sockets are all on the wire.
#
#   host   vh0 10.231.0.1/24: the gate, the fake SFU, the TURN server and the
#          Go server. DNAT sends vh0's TCP for 10.231.0.1 to the host's own
#          loopback, where the fake's relay and signalling listen;
#   olcc   out0 10.231.0.2/24, the way out (main table: default via vh0);
#          tun0, a dummy device standing for a tunnel: table 51820 is
#          `default dev tun0` and `ip rule pref 1000` sends every socket that
#          is not bound into it, where it is counted and lost.
#
# The engine runs in olcc with `bind: {interface: out0}` (the shim's
# OLC_ENGINE_NETNS, OLC_ENGINE_BIND). The sensors, read after the run:
#   tun0's tx_packets must not have grown        (nothing left unbound);
#   out0 carried UDP (the TURN allocation, the room's ICE) and TCP (the
#   signalling), counted by rules on olcc's OUTPUT chain.
# OLC_NETNS_SILENT names the interface that must stay silent (default tun0);
# naming out0 is the check pointed at the wrong leg, which must fail.
# A control first: an unbound ping must move tun0's counter, or the sensor is
# dead and the run says so.
#
# Needs root, iproute2, iptables and socat. Leaves 0 when the gate passed and
# every sensor read as said.
set -euo pipefail

shim=${1:?usage: netns.sh <engine-client-shim> [gate-relay]}
set_=${2:-gate-relay}
[ "$(id -u)" = 0 ] || { echo "netns.sh needs root" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ns=olcc
silent=${OLC_NETNS_SILENT:-tun0}

cleanup() {
	set +e
	iptables -t nat -D PREROUTING -i vh0 -d 10.231.0.1 -p tcp -j DNAT --to-destination 127.0.0.1 2>/dev/null
	ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
	ip netns del "$ns" 2>/dev/null
	ip link del vh0 2>/dev/null
}
trap cleanup EXIT
cleanup

ip netns add "$ns"
ip link add vh0 type veth peer name out0 netns "$ns"
ip addr add 10.231.0.1/24 dev vh0
ip link set vh0 up
sysctl -qw net.ipv4.conf.vh0.route_localnet=1 net.ipv4.conf.vh0.rp_filter=0 net.ipv4.conf.all.rp_filter=0
iptables -t nat -A PREROUTING -i vh0 -d 10.231.0.1 -p tcp -j DNAT --to-destination 127.0.0.1

in_ns() { ip netns exec "$ns" "$@"; }
in_ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
in_ns ip link set lo up
in_ns ip addr add 10.231.0.2/24 dev out0
in_ns ip link set out0 up
in_ns ip route add default via 10.231.0.1 dev out0
in_ns ip link add tun0 type dummy
in_ns ip link set tun0 up
in_ns ip route add default dev tun0 table 51820
in_ns ip rule add pref 1000 lookup 51820
in_ns iptables -A OUTPUT -o out0 -p udp -j ACCEPT
in_ns iptables -A OUTPUT -o out0 -p tcp -j ACCEPT

tx() { in_ns cat "/sys/class/net/$1/statistics/tx_packets"; }
rule_pkts() { in_ns iptables -nvxL OUTPUT | awk -v p="$1" '$4==p {n+=$1} END {print n+0}'; }

# The control: an unbound packet goes into tun0.
t0=$(tx tun0)
in_ns ping -c 1 -W 1 192.0.2.99 >/dev/null 2>&1 || true
[ "$(tx tun0)" -gt "$t0" ] || { echo "netns: the control failed: an unbound packet did not move tun0" >&2; exit 1; }

base_tun=$(tx tun0)
base_udp=$(rule_pkts udp)
base_tcp=$(rule_pkts tcp)

rc=0
OLC_ENGINE_NETNS=$ns OLC_ENGINE_BIND=out0 OLC_ENGINE_HOST=10.231.0.1 OLC_ENGINE_SOCKS_HOST=10.231.0.2 \
	bash "$here/fakeroom.sh" "$shim" "$set_" -olcrtc.gate-flavours=rust 2>&1 | tee netns-gate.log || rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then
	# S5 asks for a UDP relay, whose address the engine says is its own
	# loopback, inside the namespace: the gate dials it from the host and
	# cannot. S0-S4 carry the room's traffic and must all pass; nothing but
	# S5 (and the test that holds it) may fail.
	for cell in S0 S1 S2 S3 S4; do
		grep -q -- "--- PASS: TestGateRustFakeRoom/.*/$cell " netns-gate.log ||
			{ echo "netns: the gate failed: $cell did not pass (exit $rc)" >&2; exit "$rc"; }
	done
	if grep -- '--- FAIL' netns-gate.log | grep -v -e ': TestGateRustFakeRoom ' -e '/S5 ' | grep -q .; then
		echo "netns: the gate failed beyond S5 (exit $rc)" >&2
		exit "$rc"
	fi
	echo "netns: S5 (UDP associate, a relay on the namespace's loopback) is out of this leg"
fi

in_ns iptables -nvxL OUTPUT >&2
in_ns ip -s link show >&2
tun=$(($(tx tun0) - base_tun))
udp=$(($(rule_pkts udp) - base_udp))
tcp=$(($(rule_pkts tcp) - base_tcp))
echo "netns: tun0 +$tun packets, out0 udp +$udp, out0 tcp +$tcp"
fail=0
case "$silent" in
tun0) [ "$tun" -eq 0 ] || { echo "netns: $tun packets left unbound, into tun0" >&2; fail=1; } ;;
out0) { [ "$udp" -eq 0 ] && [ "$tcp" -eq 0 ]; } || { echo "netns: out0 carried the room, but was pointed at as the silent leg" >&2; fail=1; } ;;
*) echo "netns: OLC_NETNS_SILENT is tun0 or out0" >&2; exit 2 ;;
esac
[ "$udp" -gt 0 ] || { echo "netns: no UDP left by out0: no ICE or TURN socket was seen" >&2; fail=1; }
[ "$tcp" -gt 0 ] || { echo "netns: no TCP left by out0: no signalling was seen" >&2; fail=1; }
exit "$fail"

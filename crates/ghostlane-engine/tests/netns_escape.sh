#!/usr/bin/env bash
# netns_escape.sh <ghostlane-engine binary>
#
# Every socket of the engine but loopback's leaves by the interface the
# session names, on Linux, when a tunnel holds the default route. Needs root
# (it makes network namespaces); the engine itself runs as the user who
# called sudo (SUDO_UID), or as nobody.
#
# Two namespaces joined by a veth pair:
#
#   client  out0 10.231.0.2/24, the way out: main table `default via
#           10.231.0.1 dev out0`;
#           tun0, a dummy device standing for the tunnel: table 51820 is
#           `default dev tun0`, and `ip rule pref 1000 lookup 51820` sends
#           every socket that is not bound into it. tun0 counts what it is
#           given and drops it. No IPv6.
#   world   w0 10.231.0.1/24, and on its loopback the far side, all fakes
#           in this script: a DNS server (198.18.0.53) that answers
#           line.test, hub.test and origin.test, and every other name with
#           the fake carrier's address; a VLESS server over plain TCP
#           (198.18.0.10:443); an interop-pipe hub (198.18.0.20:7000); an
#           HTTP origin (198.18.0.30:80); and a fake carrier (198.18.0.40:443)
#           that records the TLS ClientHello it is sent and closes.
#
# A socket bound to out0 is routed by out0's routes alone, so it reaches the
# world; any other socket goes into tun0 and is lost there. Each case runs the
# engine in the client namespace with `bind: {interface: out0}` and asks that
# tun0 gave nothing while it ran (its tx_packets counter):
#
#   1. a line: the core's SOCKS inbound on loopback, a VLESS outbound to the
#      world; a fetch by address and one by name through it;
#   2. a room on the `none` carrier, its hub dialed by name: the name is
#      asked of the room's DNS server, and the hub sees the join;
#   3. a room on a fake carrier (`jitsi`, a room link on a name of the fake
#      DNS): the carrier's name is asked, and its signalling's TLS hello
#      reaches the fake carrier from out0;
#   4. the one-shots: `probe` through the line, `olc-check` of the `none`
#      room, each one line;
#   5. a session that names an interface that is not there ends with a
#      `bind` failure.
#
# And the control, without which the cases prove nothing: the line without
# `bind` cannot fetch, and tun0's counter grows.
#
# Not covered: TURN. A room's TURN relay is learned from the carrier's
# signalling, which a record-only fake does not complete.
#
# Leaves with 0 when every case passes, 1 otherwise; a namespace that cannot
# be made is a failure, not a skip. Needs bash, iproute2 and python3 (3.9 or
# later: the engine is started from Python with its user and group).
set -euo pipefail

engine_in="${1:?usage: netns_escape.sh <ghostlane-engine binary>}"
[ -x "$engine_in" ] || { echo "no engine at $engine_in" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "netns_escape.sh needs root: it makes network namespaces" >&2; exit 1; }

uid="${SUDO_UID:-65534}"
gid="${SUDO_GID:-65534}"
[ "$uid" != 0 ] || { uid=65534; gid=65534; }

client="gle-client-$$"
world="gle-world-$$"
scratch="$(mktemp -d /tmp/gle-netns.XXXXXX)"
chmod 0711 "$scratch"
pids=()

cleanup() {
    local pid
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    ip netns pids "$client" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns pids "$world" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    ip netns del "$client" 2>/dev/null || true
    ip netns del "$world" 2>/dev/null || true
    rm -rf "/etc/netns/$client"
    rm -rf "$scratch"
}
trap cleanup EXIT

in_client() { ip netns exec "$client" "$@"; }
in_world() { ip netns exec "$world" "$@"; }

# The namespaces. Any step that fails ends the script with a failure.
ip netns add "$client"
ip netns add "$world"
ip link add out0 netns "$client" type veth peer name w0 netns "$world"

in_client sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
in_client sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
in_client ip link set lo up
in_client ip addr add 10.231.0.2/24 dev out0
in_client sysctl -qw net.ipv4.conf.out0.rp_filter=0
in_client ip link set out0 up
in_client ip link add tun0 type dummy
in_client sysctl -qw net.ipv4.conf.tun0.rp_filter=0
in_client ip link set tun0 up
in_client ip route add default via 10.231.0.1 dev out0
in_client ip route add default dev tun0 table 51820
in_client ip rule add pref 1000 lookup 51820

in_world sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
in_world ip link set lo up
in_world ip addr add 10.231.0.1/24 dev w0
in_world ip link set w0 up
for host in 10 20 30 40 53; do
    in_world ip addr add "198.18.0.$host/32" dev lo
done

# The system resolver of the client namespace is the fake one too, so that a
# lookup the engine does not bind goes into tun0 and is counted, not lost.
mkdir -p "/etc/netns/$client"
echo "nameserver 198.18.0.53" > "/etc/netns/$client/resolv.conf"

# The engine, where its user can run it.
cp "$engine_in" "$scratch/ghostlane-engine"
chmod 0755 "$scratch/ghostlane-engine"

cat > "$scratch/world.py" <<'PY'
# The far side: one service per process, each line it logs is one fact.
import socket, struct, sys, threading

MODE, LOG = sys.argv[1], sys.argv[2]
NAMES = {"line.test": "198.18.0.10", "hub.test": "198.18.0.20", "origin.test": "198.18.0.30"}
CARRIER = "198.18.0.40"
USER = bytes(range(16))
lock = threading.Lock()


def log(*words):
    with lock, open(LOG, "a") as out:
        out.write(" ".join(str(word) for word in words) + "\n")


def exact(conn, n):
    data = b""
    while len(data) < n:
        more = conn.recv(n - len(data))
        if not more:
            raise EOFError
        data += more
    return data


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def tcp(address, handle):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address)
    server.listen(64)
    log("ready")
    while True:
        conn, peer = server.accept()
        threading.Thread(target=guarded, args=(handle, conn, peer), daemon=True).start()


def guarded(handle, conn, peer):
    try:
        handle(conn, peer)
    except (OSError, EOFError, ValueError) as error:
        log("broken", peer[0], type(error).__name__)
    finally:
        conn.close()


def dns():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("198.18.0.53", 53))
    log("ready")
    while True:
        query, peer = server.recvfrom(4096)
        if len(query) < 17:
            continue
        at, labels = 12, []
        while at < len(query) and query[at] != 0:
            size = query[at]
            labels.append(query[at + 1:at + 1 + size].decode("ascii", "replace"))
            at += 1 + size
        at += 1
        if at + 4 > len(query):
            continue
        kind = struct.unpack(">H", query[at:at + 2])[0]
        name = ".".join(labels).lower().rstrip(".")
        log("query", peer[0], name, kind)
        question = query[12:at + 4]
        answer = b""
        if kind == 1:
            address = NAMES.get(name, CARRIER)
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(address)
        head = struct.pack(">HHHHHH", struct.unpack(">H", query[:2])[0], 0x8180, 1, 1 if answer else 0, 0, 0)
        server.sendto(head + question + answer, peer)


def origin(conn, peer):
    request = b""
    while b"\r\n\r\n" not in request:
        more = conn.recv(4096)
        if not more:
            return
        request += more
    log("request", peer[0], request.split(b"\r\n", 1)[0].decode("ascii", "replace"))
    body = b"the world says hello\n"
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)


def vless(conn, peer):
    head = exact(conn, 18)
    if head[0] != 0 or head[1:17] != USER:
        log("refused", peer[0])
        return
    exact(conn, head[17])
    command, port_hi, port_lo, kind = exact(conn, 4)
    if kind == 1:
        host = socket.inet_ntoa(exact(conn, 4))
    elif kind == 2:
        host = exact(conn, exact(conn, 1)[0]).decode("ascii", "replace")
    else:
        log("refused", peer[0], "address kind", kind)
        return
    port = port_hi * 256 + port_lo
    log("carried", peer[0], command, host, port)
    target = socket.create_connection((NAMES.get(host, host), port), timeout=10)
    conn.sendall(b"\x00\x00")
    up = threading.Thread(target=pump, args=(conn, target), daemon=True)
    up.start()
    pump(target, conn)
    up.join(10)
    target.close()


def hub(conn, peer):
    head = exact(conn, 5)
    size = struct.unpack(">I", head[:4])[0]
    payload = exact(conn, size - 1)
    log("join" if head[4] == 1 else "frame", peer[0], payload.decode("utf-8", "replace"))
    while conn.recv(65536):
        pass
    log("left", peer[0])


def server_name(hello):
    try:
        at = 5 + 4 + 2 + 32
        at += 1 + hello[at]
        at += 2 + struct.unpack(">H", hello[at:at + 2])[0]
        at += 1 + hello[at]
        end = at + 2 + struct.unpack(">H", hello[at:at + 2])[0]
        at += 2
        while at + 4 <= end:
            kind, size = struct.unpack(">HH", hello[at:at + 4])
            if kind == 0:
                length = struct.unpack(">H", hello[at + 7:at + 9])[0]
                return hello[at + 9:at + 9 + length].decode("ascii", "replace")
            at += 4 + size
    except (IndexError, struct.error):
        pass
    return "-"


def carrier(conn, peer):
    conn.settimeout(10)
    hello = b""
    while len(hello) < 5 or len(hello) < 5 + struct.unpack(">H", hello[3:5])[0]:
        more = conn.recv(65536)
        if not more:
            break
        hello += more
    log("hello", peer[0], hello[:2].hex(), server_name(hello))


if MODE == "dns":
    dns()
else:
    address, handle = {
        "origin": (("198.18.0.30", 80), origin),
        "vless": (("198.18.0.10", 443), vless),
        "hub": (("198.18.0.20", 7000), hub),
        "carrier": (("198.18.0.40", 443), carrier),
    }[MODE]
    tcp(address, handle)
PY

for service in dns origin vless hub carrier; do
    : > "$scratch/$service.log"
    in_world python3 -I "$scratch/world.py" "$service" "$scratch/$service.log" \
        2>> "$scratch/world-errors.log" &
    pids+=("$!")
done
for service in dns origin vless hub carrier; do
    for _ in $(seq 1 100); do
        grep -qx ready "$scratch/$service.log" && break
        sleep 0.1
    done
    grep -qx ready "$scratch/$service.log" || {
        echo "the world's $service did not start" >&2
        cat "$scratch/world-errors.log" >&2 || true
        exit 1
    }
done

cat > "$scratch/cases.py" <<'PY'
# The cases, run in the client namespace as root; the engine runs as the user.
import json, os, queue, socket, struct, subprocess, sys, threading, time

ENGINE, SCRATCH, UID, GID = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
USER = "00010203-0405-0607-0809-0a0b0c0d0e0f"
KEY = "4f6c635254432d74657374206b65792c206e6f7420612073656372657421212e"
BIND = {"interface": "out0"}
failed = []
runs = 0


def check(ok, what):
    print(("ok: " if ok else "FAILED: ") + what, flush=True)
    if not ok:
        failed.append(what)
    return ok


def sent():
    with open("/sys/class/net/tun0/statistics/tx_packets") as counter:
        return int(counter.read())


def world(service):
    with open(os.path.join(SCRATCH, service + ".log")) as log:
        return [line.split() for line in log.read().splitlines() if line != "ready"]


def wait_for(what, within):
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        found = what()
        if found:
            return found
        time.sleep(0.1)
    return what()


def session(name, body):
    path = os.path.join(SCRATCH, name + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps(dict(version=1, **body)).encode())
    os.close(fd)
    os.chown(path, UID, GID)
    return path


class Engine:
    """The engine as an app runs it: stdin held open, one event a line."""

    def __init__(self, *arguments):
        global runs
        runs += 1
        self.name = "%s-%d" % (arguments[0], runs)
        self.stderr = open(os.path.join(SCRATCH, self.name + ".err"), "wb")
        self.process = subprocess.Popen(
            [ENGINE, *arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            user=UID,
            group=GID,
            extra_groups=[],
            env={"PATH": "/usr/bin:/bin", "RUST_BACKTRACE": "1"},
            cwd=SCRATCH,
        )
        self.lines, self.events = queue.Queue(), []
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.process.stdout:
            self.lines.put(json.loads(line))
        self.lines.put(None)

    def until(self, wanted, within):
        deadline = time.monotonic() + within
        while True:
            try:
                event = self.lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                return None
            if event is None:
                self.lines.put(None)
                return None
            self.events.append(event)
            if wanted(event):
                return event

    def stop(self):
        """Closes stdin; the exit status and the events to the end."""
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            status = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            status = self.process.wait()
        self.until(lambda event: False, 5)
        self.stderr.close()
        return status

    def show(self):
        print("  %s printed:" % self.name)
        for event in self.events:
            print("    " + json.dumps(event))
        with open(os.path.join(SCRATCH, self.name + ".err"), errors="replace") as err:
            tail = err.read()[-3000:]
        if tail.strip():
            print("  its stderr ends with:\n" + "\n".join("    " + line for line in tail.splitlines()))


def answer(*arguments):
    engine = Engine(*arguments)
    status = engine.stop()
    return engine, status


def socks_fetch(port, host, target_port, within):
    """GET / through a SOCKS5 port on loopback; the status line and body."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=within)
    conn.settimeout(within)
    try:
        conn.sendall(b"\x05\x01\x00")
        if conn.recv(2) != b"\x05\x00":
            return None
        try:
            address = b"\x01" + socket.inet_aton(host)
        except OSError:
            address = b"\x03" + bytes([len(host)]) + host.encode()
        conn.sendall(b"\x05\x01\x00" + address + struct.pack(">H", target_port))
        reply = conn.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            return None
        conn.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host.encode())
        data = b""
        while True:
            more = conn.recv(65536)
            if not more:
                break
            data += more
        return data
    except OSError:
        return None
    finally:
        conn.close()


def line(port, bound):
    body = {
        "core": {
            "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": port}],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "198.18.0.10",
                    "port": 443,
                    "users": [{"id": USER, "encryption": "none"}],
                }]},
                "streamSettings": {"network": "tcp"},
            }],
        },
    }
    if bound:
        body["bind"] = BIND
    return body


def room(provider, link, bound=True):
    body = {"room": {"provider": provider, "rooms": [link], "key": KEY, "dns": "198.18.0.53:53"}}
    if bound:
        body["bind"] = BIND
    return body


def from_out0(service, *words):
    """The lines of a world service from the client's out0 that hold `words`."""
    return [entry for entry in world(service)
            if len(entry) > 1 and entry[1] == "10.231.0.2" and all(word in entry for word in words)]


def quiet_tun(before, what):
    grew = sent() - before
    return check(grew == 0, "%s: nothing went into the tunnel (tun0 was given %d packets)" % (what, grew))


def ended_well(engine, status, what):
    last = engine.events[-1] if engine.events else None
    ok = status == 0 and last is not None and last.get("event") == "ended" and last.get("reason") == "stdin_closed"
    return check(ok, "%s: told to stop, it ended with status 0 (%s)" % (what, status))


def bound_first(engine, what):
    bound = [event for event in engine.events if event.get("event") == "bound"]
    return check(bool(bound) and bound[0].get("interface") == "out0", what + ": `bound` names out0")


# Nothing else in the namespace gives tun0 a packet.
before = sent()
time.sleep(1)
check(sent() == before, "tun0 is quiet with no engine running")

# The control: the line without `bind` is lost in the tunnel.
before = sent()
engine = Engine("run", "--session", session("line-unbound", line(21081, False)))
ready = engine.until(lambda event: event.get("event") == "ready", 20)
check(ready is not None, "control: the unbound line is ready")
got = socks_fetch(21081, "198.18.0.30", 80, 4) if ready else None
check(not got or not got.startswith(b"HTTP/1.1 200"), "control: without `bind` the line cannot fetch")
check(sent() > before, "control: without `bind` the line's sockets went into the tunnel")
status = engine.stop()
if failed:
    engine.show()

# 1. A line, bound.
before = sent()
engine = Engine("run", "--session", session("line", line(21080, True)))
ready = engine.until(lambda event: event.get("event") == "ready", 20)
check(ready is not None, "line: ready")
bound_first(engine, "line")
got = socks_fetch(21080, "198.18.0.30", 80, 10) if ready else None
check(bool(got) and got.startswith(b"HTTP/1.1 200") and got.endswith(b"the world says hello\n"),
      "line: a fetch by address through the line")
got = socks_fetch(21080, "origin.test", 80, 10) if ready else None
check(bool(got) and got.startswith(b"HTTP/1.1 200"), "line: a fetch by name through the line")
check(len(from_out0("vless", "carried")) >= 2, "line: the VLESS server carried both, from out0")
status = engine.stop()
quiet_tun(before, "line")
if not ended_well(engine, status, "line"):
    engine.show()

# 2. A room on the `none` carrier, its hub by name.
before = sent()
engine = Engine("run", "--session", session("none-room", room("none", "tcp://hub.test:7000/f4b-netns")))
joined = wait_for(lambda: from_out0("hub", "join", "f4b-netns"), 20)
check(bool(joined), "none room: the hub saw the join from out0")
check(bool(from_out0("dns", "query", "hub.test")), "none room: the hub's name was asked from out0")
engine.until(lambda event: False, 1)
bound_first(engine, "none room")
status = engine.stop()
quiet_tun(before, "none room")
if not ended_well(engine, status, "none room"):
    engine.show()

# 3. A room on a fake carrier: its name, then its signalling's TLS.
before = sent()
engine = Engine("run", "--session", session("carrier-room", room("jitsi", "https://meet.carrier.test/f4b-netns")))
hello = wait_for(lambda: from_out0("carrier", "hello", "meet.carrier.test"), 30)
check(bool(hello), "fake carrier: its signalling's TLS hello came from out0, for its name")
check(bool(hello) and hello[0][2].startswith("16"), "fake carrier: what came is a TLS handshake")
check(bool(from_out0("dns", "query", "meet.carrier.test")), "fake carrier: its name was asked from out0")
engine.until(lambda event: False, 1)
status = engine.stop()
quiet_tun(before, "fake carrier")
last = engine.events[-1] if engine.events else {}
if not check(last.get("event") == "ended", "fake carrier: the run ended with `ended`"):
    engine.show()
if not hello:
    engine.show()

# 4. The one-shots, bound: one line each, nothing in the tunnel.
before = sent()
engine, status = answer("probe", "--session", session("probe", line(21082, True)),
                        "--url", "http://198.18.0.30/", "--timeout-ms", "8000")
lines = engine.events
if not check(status == 0 and len(lines) == 1 and lines[0].get("event") == "probe" and lines[0].get("ok") is True,
             "probe: one line, a yes, through the bound line"):
    engine.show()
joins = len(from_out0("hub", "join", "f4b-check"))
engine, status = answer("olc-check", "--session", session("olc-check", room("none", "tcp://hub.test:7000/f4b-check")),
                        "--timeout-ms", "3000")
lines = engine.events
if not check(status == 1 and len(lines) == 1 and lines[0].get("event") == "olc_check" and lines[0].get("ok") is False,
             "olc-check: one line, a no (nobody serves the room)"):
    engine.show()
check(len(from_out0("hub", "join", "f4b-check")) > joins, "olc-check: it joined from out0")
quiet_tun(before, "one-shots")

# 5. An interface that is not there.
body = line(21083, True)
body["bind"] = {"interface": "eth9"}
engine, status = answer("run", "--session", session("no-interface", body))
last = engine.events[-1] if engine.events else {}
if not check(status == 1 and last.get("event") == "ended" and last.get("code") == "bind"
             and last.get("message") == "interface `eth9` does not exist",
             "a missing interface: `ended` failed with code bind"):
    engine.show()

# Every name was asked from out0.
asked = world("dns")
check(all(entry[1] == "10.231.0.2" for entry in asked), "every DNS query came from out0 (%d)" % len(asked))

print("%d failed" % len(failed))
sys.exit(1 if failed else 0)
PY

status=0
in_client python3 -I "$scratch/cases.py" "$scratch/ghostlane-engine" "$scratch" "$uid" "$gid" || status=$?
if [ "$status" != 0 ]; then
    echo "== what the world saw"
    for service in dns origin vless hub carrier; do
        echo "-- $service"
        cat "$scratch/$service.log"
    done
    cat "$scratch/world-errors.log" 2>/dev/null || true
fi
exit "$status"

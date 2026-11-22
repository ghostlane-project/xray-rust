#!/usr/bin/env bash
# netns_front.sh <ghostlane-engine binary> <olcRTC server binary>
#
# A session with both halves, on Linux, when a tunnel holds the default
# route: the core in front of a room on the `none` carrier, in one engine
# process, with every socket but loopback's bound to the interface the
# session names. The core's rules send one name direct and everything else
# to the room through its `socks` outbound, TCP and UDP; the room carries it
# to its far side, the olcRTC server; and a LAN inbound of the core asks for
# a login. Needs root (it makes network namespaces); the engine runs as the
# user who called sudo (SUDO_UID), or as nobody.
#
# The server is the olcRTC engine at the interop pin, built with the
# overlay that gives it the interop pipe (olc/interop: the `none` carrier's
# rooms are rooms of a TCP hub). front-room.sh, the drop-in, builds it.
#
# Two namespaces joined by a veth pair:
#
#   client  out0 10.231.0.2/24, the way out: main table `default via
#           10.231.0.1 dev out0`;
#           tun0, a dummy device standing for the tunnel: table 51820 is
#           `default dev tun0`, and `ip rule pref 1000 lookup 51820` sends
#           every socket that is not bound into it. tun0 counts what it is
#           given and drops it. `ip rule pref 999 lookup main
#           suppress_prefixlength 0` keeps the LAN (10.231.0.0/24) on the
#           LAN, as a tunnel's own rules do, so the LAN inbound can answer.
#           No IPv6.
#   world   w0 10.231.0.1/24, a device on the LAN; and on its loopback the
#           far side: a DNS server (10.232.0.53) for hub.test, room.test and
#           direct.test; an interop-pipe hub that relays between the
#           participants of a room (10.232.0.20:7000); an HTTP origin
#           (10.232.0.30:80) and a UDP echo (10.232.0.30:7), which log the
#           address each request came from; and the olcRTC server, in the
#           hub's room f4c-front, with the DNS server for its names.
#
# A socket bound to out0 is routed by out0's routes alone, so it reaches the
# world from 10.231.0.2; any other socket but a LAN one goes into tun0 and is
# lost there. What the room carries reaches the world from the server, on
# the world's own addresses. Each run asks that tun0 gave nothing while it
# ran (its tx_packets counter):
#
#   1. the far side: a room alone, bound, is ready and a fetch through its
#      SOCKS port reaches the origin from the server. Without it the cases
#      below would prove nothing about the front;
#   2. the control: the front without `bind` never serves (its room cannot
#      be reached), and tun0's counter grows;
#   3. the front, bound: ready with both halves, `bound` first, the room's
#      session opened, the room's join from out0. Through the core's SOCKS
#      inbound: a fetch by address and one by name ride the room (the origin
#      sees the server; the name is asked by the server, never from out0);
#      the name the rules send direct reaches the origin from out0, asked of
#      the DNS from out0; a datagram rides the room to the echo and comes
#      back. From the LAN (the world's w0): a client with no login is
#      refused and its request is not carried, a wrong login is refused,
#      and with the login a fetch and a datagram ride the room. Told to
#      stop, it ends with status 0 and leaves the room;
#   4. a front whose core half has no way to the room: `ended` fails with
#      code `config`, naming `room`, and it is never ready.
#
# Leaves with 0 when every case passes, 1 otherwise; a namespace that cannot
# be made or a server that does not join is a failure, not a skip. Needs
# bash, iproute2 and python3 (3.9 or later: the engine is started from
# Python with its user and group).
set -euo pipefail

engine_in="${1:?usage: netns_front.sh <ghostlane-engine binary> <olcRTC server binary>}"
server_in="${2:?usage: netns_front.sh <ghostlane-engine binary> <olcRTC server binary>}"
[ -x "$engine_in" ] || { echo "no engine at $engine_in" >&2; exit 1; }
[ -x "$server_in" ] || { echo "no olcRTC server at $server_in" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "netns_front.sh needs root: it makes network namespaces" >&2; exit 1; }

uid="${SUDO_UID:-65534}"
gid="${SUDO_GID:-65534}"
[ "$uid" != 0 ] || { uid=65534; gid=65534; }

client="glf-client-$$"
world="glf-world-$$"
scratch="$(mktemp -d /tmp/glf-netns.XXXXXX)"
chmod 0711 "$scratch"
pids=()
# A room key of the test's own: 32 bytes of hex.
key="4f6c635254432d74657374206b65792c206e6f7420612073656372657421212e"

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
in_client ip rule add pref 999 lookup main suppress_prefixlength 0
in_client ip rule add pref 1000 lookup 51820

in_world sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
in_world ip link set lo up
in_world ip addr add 10.231.0.1/24 dev w0
in_world ip link set w0 up
for host in 20 30 53; do
    in_world ip addr add "10.232.0.$host/32" dev lo
done

# The system resolver of the client namespace is the fake one too, so that a
# lookup the engine does not bind goes into tun0 and is counted, not lost.
mkdir -p "/etc/netns/$client"
echo "nameserver 10.232.0.53" > "/etc/netns/$client/resolv.conf"

# The engine, where its user can run it.
cp "$engine_in" "$scratch/ghostlane-engine"
chmod 0755 "$scratch/ghostlane-engine"

cat > "$scratch/world.py" <<'PY'
# The far side but the server: one service per process, each line it logs
# is one fact.
import queue, socket, struct, sys, threading

MODE, LOG = sys.argv[1], sys.argv[2]
NAMES = {"hub.test": "10.232.0.20", "room.test": "10.232.0.30", "direct.test": "10.232.0.30"}
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
    # A for the names above; for another type of theirs no answer; every
    # other name does not exist.
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("10.232.0.53", 53))
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
        answer, flags = b"", 0x8180
        if name not in NAMES:
            flags = 0x8183
        elif kind == 1:
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(NAMES[name])
        head = struct.pack(">HHHHHH", struct.unpack(">H", query[:2])[0], flags, 1, 1 if answer else 0, 0, 0)
        server.sendto(head + question + answer, peer)


def origin(conn, peer):
    request = b""
    while b"\r\n\r\n" not in request:
        more = conn.recv(4096)
        if not more:
            return
        request += more
    line = request.split(b"\r\n", 1)[0].decode("ascii", "replace").split()
    log("request", peer[0], line[1] if len(line) > 1 else "-")
    body = b"the world says hello\n"
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)


def echo():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("10.232.0.30", 7))
    log("ready")
    while True:
        data, peer = server.recvfrom(65536)
        log("datagram", peer[0], len(data))
        server.sendto(data, peer)


# The interop-pipe hub: frames of `u32 BE length | kind | payload`. A
# participant's first frame is its JOIN (kind 1) naming its room; DATA (2)
# and DGRAM (3) go to every other participant of the room, unchanged; each
# join and leave tells every participant how many others the room holds
# (PEERS, 4, a u16 BE), as the Go hub does (zz_hub.go).
rooms = {}


class Member:
    def __init__(self, conn, room):
        self.conn, self.room, self.out = conn, room, queue.Queue()

    def write(self):
        while True:
            frame = self.out.get()
            if frame is None:
                return
            try:
                self.conn.sendall(frame)
            except OSError:
                return


def frame(kind, payload):
    return struct.pack(">IB", 1 + len(payload), kind) + payload


def read_frame(conn):
    size = struct.unpack(">I", exact(conn, 4))[0]
    if size == 0 or size - 1 > 64 << 10:
        raise ValueError("frame of %d" % size)
    body = exact(conn, size)
    return body[0], body[1:]


def announce(room):
    with lock:
        members = list(rooms.get(room, ()))
    for member in members:
        member.out.put(frame(4, struct.pack(">H", max(len(members) - 1, 0))))


def hub(conn, peer):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    kind, payload = read_frame(conn)
    if kind != 1 or not payload:
        return
    room = payload.decode("utf-8", "replace").split("@", 1)[0]
    member = Member(conn, room)
    with lock:
        rooms.setdefault(room, set()).add(member)
    threading.Thread(target=member.write, daemon=True).start()
    log("join", peer[0], room)
    announce(room)
    try:
        while True:
            kind, payload = read_frame(conn)
            if kind not in (2, 3):
                continue
            with lock:
                others = [other for other in rooms.get(room, ()) if other is not member]
            for other in others:
                other.out.put(frame(kind, payload))
    finally:
        with lock:
            rooms[room].discard(member)
        member.out.put(None)
        log("left", peer[0], room)
        announce(room)


if MODE == "dns":
    dns()
elif MODE == "echo":
    echo()
else:
    address, handle = {
        "origin": (("10.232.0.30", 80), origin),
        "hub": (("10.232.0.20", 7000), hub),
    }[MODE]
    tcp(address, handle)
PY

services="dns origin echo hub"
for service in $services; do
    : > "$scratch/$service.log"
    in_world python3 -I "$scratch/world.py" "$service" "$scratch/$service.log" \
        2>> "$scratch/world-errors.log" &
    pids+=("$!")
done
for service in $services; do
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

# The olcRTC server, in the hub's room. A server built with the test hooks
# reads OLCRTC_TEST_ALLOW_PRIVATE_TARGETS: the world's addresses are private,
# which its egress policy refuses otherwise.
cp "$server_in" "$scratch/olcrtc"
chmod 0755 "$scratch/olcrtc"
(
    umask 077
    cat > "$scratch/srv.yaml" <<YAML
mode: srv
auth: { provider: none }
engine: { name: interop-pipe, url: "tcp://10.232.0.20:7000/f4c-front" }
crypto: { key: "$key" }
net: { transport: datachannel, dns: "10.232.0.53:53" }
udp: { enabled: true }
debug: true
YAML
)
: > "$scratch/srv.log"
(cd "$scratch" && exec ip netns exec "$world" env OLCRTC_TEST_ALLOW_PRIVATE_TARGETS=1 OLCRTC_TEST_BRIDGE_DELAY=0s \
    "$scratch/olcrtc" "$scratch/srv.yaml" >> "$scratch/srv.log" 2>&1) &
pids+=("$!")
for _ in $(seq 1 600); do
    grep -q "Link connected" "$scratch/srv.log" && break
    sleep 0.1
done
grep -q "Link connected" "$scratch/srv.log" || {
    echo "the olcRTC server did not join its room within 60 s; its log ends with:" >&2
    tail -n 60 "$scratch/srv.log" >&2
    exit 1
}
echo "the olcRTC server joined its room"

cat > "$scratch/drive.py" <<'PY'
# The cases, run in the client namespace as root; the engine runs as the
# user. `drive.py lan <mode> <host> <port>` is a device on the LAN, run in
# the world namespace: one question, one JSON line.
import json, os, queue, socket, struct, subprocess, sys, threading, time

KEY = "4f6c635254432d74657374206b65792c206e6f7420612073656372657421212e"
OUT0 = "10.231.0.2"
ORIGIN = "10.232.0.30"
ROOM = "tcp://hub.test:7000/f4c-front"
BIND = {"interface": "out0"}
LAN_LOGIN = (b"lan-user", b"lan-pass")
PAYLOAD = b"f4c: a datagram through the front"


class Refused(Exception):
    pass


def exact(conn, n):
    data = b""
    while len(data) < n:
        more = conn.recv(n - len(data))
        if not more:
            raise EOFError("closed after %d bytes" % len(data))
        data += more
    return data


def greet(proxy, login, within):
    """A SOCKS5 connection to proxy, past its method and its login."""
    conn = socket.create_connection(proxy, timeout=within)
    conn.settimeout(within)
    try:
        method = b"\x00" if login is None else b"\x02"
        conn.sendall(b"\x05\x01" + method)
        chosen = exact(conn, 2)
        if chosen != b"\x05" + method:
            raise Refused("the proxy chose " + chosen.hex())
        if login is not None:
            user, password = login
            conn.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
            status = exact(conn, 2)
            if status != b"\x01\x00":
                raise Refused("the login was refused: " + status.hex())
        return conn
    except BaseException:
        conn.close()
        raise


def address(host):
    try:
        return b"\x01" + socket.inet_aton(host)
    except OSError:
        return b"\x03" + bytes([len(host)]) + host.encode()


def reply(conn):
    """A SOCKS5 reply: its code and the address it names."""
    head = exact(conn, 4)
    if head[3] == 1:
        host = socket.inet_ntoa(exact(conn, 4))
    elif head[3] == 3:
        host = exact(conn, exact(conn, 1)[0]).decode("ascii", "replace")
    elif head[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(conn, 16))
    else:
        raise Refused("a reply of address kind %d" % head[3])
    return head[1], host, struct.unpack(">H", exact(conn, 2))[0]


def fetch(proxy, host, path, login=None, within=20):
    """GET path from host:80 through the SOCKS5 proxy: the response, or why not."""
    try:
        conn = greet(proxy, login, within)
        with conn:
            conn.sendall(b"\x05\x01\x00" + address(host) + struct.pack(">H", 80))
            code, _, _ = reply(conn)
            if code != 0:
                return "CONNECT answered %d" % code
            conn.sendall(b"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path.encode(), host.encode()))
            data = b""
            while True:
                more = conn.recv(65536)
                if not more:
                    return data
                data += more
    except (OSError, EOFError, Refused) as error:
        return "%s: %s" % (type(error).__name__, error)


def datagram(proxy, host, port, login=None, within=20):
    """PAYLOAD to host:port through the SOCKS5 proxy's UDP relay: what came back, or why nothing."""
    try:
        control = greet(proxy, login, within)
    except (OSError, EOFError, Refused) as error:
        return "%s: %s" % (type(error).__name__, error)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        code, relay, relay_port = reply(control)
        if code != 0:
            return "UDP ASSOCIATE answered %d" % code
        if relay in ("0.0.0.0", "::"):
            relay = proxy[0]
        udp.settimeout(3)
        head = b"\x00\x00\x00" + address(host) + struct.pack(">H", port)
        for _ in range(int(within / 3) + 1):
            udp.sendto(head + PAYLOAD, (relay, relay_port))
            try:
                data, _ = udp.recvfrom(65536)
            except socket.timeout:
                continue
            kind = data[3] if len(data) > 3 else 0
            skip = {1: 10, 4: 22}.get(kind, 7 + (data[4] if len(data) > 4 else 0))
            return data[skip:]
        return "no datagram came back"
    except (OSError, EOFError, Refused) as error:
        return "%s: %s" % (type(error).__name__, error)
    finally:
        udp.close()
        control.close()


def ok_page(got):
    return isinstance(got, bytes) and got.startswith(b"HTTP/1.1 200") and got.endswith(b"the world says hello\n")


def lan(mode, host, port):
    """One question of a device on the LAN, its answer as a dict."""
    proxy = (host, port)
    if mode == "no-login":
        conn = socket.create_connection(proxy, timeout=5)
        conn.settimeout(5)
        conn.sendall(b"\x05\x01\x00")
        try:
            chosen = exact(conn, 2).hex()
        except (OSError, EOFError):
            chosen = "closed"
        # The request anyway, as a client that does not wait for the answer.
        answered = False
        try:
            conn.sendall(b"\x05\x01\x00" + address(ORIGIN) + struct.pack(">H", 80))
            conn.sendall(b"GET /no-login HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
            conn.settimeout(3)
            rest = conn.recv(65536)
            answered = rest.startswith(b"\x05\x00")
        except (OSError, EOFError):
            pass
        conn.close()
        return {"chosen": chosen, "answered": answered}
    if mode == "wrong-login":
        try:
            greet(proxy, (LAN_LOGIN[0], b"not-the-pass"), 5).close()
            return {"refused": False}
        except (OSError, EOFError, Refused) as error:
            return {"refused": True, "why": str(error)}
    if mode == "fetch":
        got = fetch(proxy, ORIGIN, "/lan", LAN_LOGIN)
        return {"ok": ok_page(got), "got": repr(got)[:200]}
    if mode == "datagram":
        got = datagram(proxy, ORIGIN, 7, LAN_LOGIN)
        return {"echoed": got == PAYLOAD, "got": repr(got)[:200]}
    return {"unknown": mode}


if sys.argv[1] == "lan":
    print(json.dumps(lan(sys.argv[2], sys.argv[3], int(sys.argv[4]))), flush=True)
    sys.exit(0)

ENGINE, SCRATCH, UID, GID, WORLD = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
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


def served(event):
    return event.get("event") in ("ready", "ended")


def inbound(ready, tag):
    for listener in (ready or {}).get("inbounds") or []:
        if listener.get("tag") == tag:
            host, _, port = listener["address"].rpartition(":")
            return host, int(port)
    return None


def requests(path):
    """The addresses the origin was asked for `path` from."""
    return [entry[1] for entry in world("origin") if entry[0] == "request" and entry[2] == path]


def queries(name):
    return [entry[1] for entry in world("dns") if entry[0] == "query" and entry[2] == name]


def hub(what, room):
    return [entry[1] for entry in world("hub") if entry[0] == what and entry[2] == room]


def by_the_room(path, what):
    """`path` reached the origin, and only from the far side, the server."""
    seen = wait_for(lambda: requests(path), 5)
    return check(bool(seen) and OUT0 not in seen, "%s: the origin saw it from the far side (%s)" % (what, seen))


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


def room_half(device):
    return {"provider": "none", "rooms": [ROOM], "key": KEY, "dns": "10.232.0.53:53", "udp": True, "device_id": device}


def front_core():
    """The core half of a front as a parent writes it: the session's SOCKS
    inbound, a LAN inbound with a login on out0's address, the way to the
    room first (what no rule claims rides it), direct.test sent direct, and
    the DNS asked for what goes direct."""
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": [{"tag": "dns-direct", "address": "10.232.0.53", "port": 53}],
        },
        "inbounds": [
            {"tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
             "settings": {"auth": "noauth", "udp": True}},
            {"tag": "lan-in", "protocol": "socks", "listen": OUT0, "port": 0,
             "settings": {"auth": "password", "udp": True, "allowUnauthenticatedLan": True,
                          "accounts": [{"user": LAN_LOGIN[0].decode(), "pass": LAN_LOGIN[1].decode()}]}},
        ],
        "outbounds": [
            {"tag": "room", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 1080}},
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["dns-direct"], "outboundTag": "direct"},
                {"type": "field", "domain": ["domain:direct.test"], "outboundTag": "direct"},
            ],
        },
    }


def from_lan(mode, listener):
    done = subprocess.run(
        ["ip", "netns", "exec", WORLD, "python3", "-I", os.path.join(SCRATCH, "drive.py"), "lan", mode,
         listener[0], str(listener[1])],
        capture_output=True, text=True, timeout=60)
    try:
        return json.loads(done.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"broken": done.stdout[-500:] + done.stderr[-1500:]}


# Nothing else in the namespace gives tun0 a packet.
before = sent()
time.sleep(1)
check(sent() == before, "tun0 is quiet with no engine running")

# 1. The far side: a room alone, bound.
mark, before = len(failed), sent()
engine = Engine("run", "--session", session("room-alone", {"room": room_half("f4c-alone"), "bind": BIND}))
ready = engine.until(served, 60)
up = check(bool(ready) and ready.get("event") == "ready", "the room alone: ready, the server answers in its room")
socks = inbound(ready, "room") if up else None
got = fetch(socks, ORIGIN, "/alone") if socks else None
check(ok_page(got), "the room alone: a fetch through its SOCKS port (%r)" % (got if not ok_page(got) else "200",))
by_the_room("/alone", "the room alone")
status = engine.stop()
quiet_tun(before, "the room alone")
ended_well(engine, status, "the room alone")
if len(failed) > mark:
    engine.show()

# 2. The control: the front without `bind` cannot reach its room.
mark, before = len(failed), sent()
engine = Engine("run", "--session", session("front-unbound", {"core": front_core(), "room": room_half("f4c-unbound")}))
event = engine.until(served, 15)
check(not event or event.get("event") != "ready", "control: without `bind` the front never serves")
check(sent() > before, "control: without `bind` its sockets went into the tunnel")
engine.stop()
if len(failed) > mark:
    engine.show()

# 3. The front, bound.
mark, before = len(failed), sent()
joins, lefts = len(hub("join", "f4c-front")), len(hub("left", "f4c-front"))
engine = Engine("run", "--session", session("front", {"core": front_core(), "room": room_half("f4c-front"), "bind": BIND}))
ready = engine.until(served, 60)
up = check(bool(ready) and ready.get("event") == "ready", "front: ready, with both halves")
bound_first(engine, "front")
check(any(event.get("event") == "session_opened" for event in engine.events), "front: its room's session opened")
check(OUT0 in hub("join", "f4c-front")[joins:], "front: the room's join came from out0")
own = inbound(ready, "in") if up else None
lan_in = inbound(ready, "lan-in") if up else None
check(bool(lan_in) and lan_in[0] == OUT0, "front: the LAN inbound listens on out0's address (%s)" % (lan_in,))
if own:
    got = fetch(own, ORIGIN, "/room-address")
    check(ok_page(got), "front: TCP by address, by the room (%r)" % (got if not ok_page(got) else "200",))
    by_the_room("/room-address", "front: TCP by address")
    got = fetch(own, "room.test", "/room-name")
    check(ok_page(got), "front: TCP by name, by the room (%r)" % (got if not ok_page(got) else "200",))
    by_the_room("/room-name", "front: TCP by name")
    asked = queries("room.test")
    check(bool(asked) and OUT0 not in asked,
          "front: the room's name was asked by the far side, never from out0 (%s)" % (asked,))
    got = fetch(own, "direct.test", "/direct")
    check(ok_page(got), "front: TCP to the name the rules send direct (%r)" % (got if not ok_page(got) else "200",))
    seen = requests("/direct")
    check(seen == [OUT0], "front: the direct name reached the origin from out0 alone (%s)" % (seen,))
    asked = queries("direct.test")
    check(bool(asked) and set(asked) == {OUT0}, "front: the direct name was asked from out0 (%s)" % (asked,))
    echoed = len(world("echo"))
    got = datagram(own, ORIGIN, 7)
    check(got == PAYLOAD, "front: a datagram by the room came back (%r)" % (got,))
    seen = [entry[1] for entry in world("echo")[echoed:]]
    check(bool(seen) and OUT0 not in seen, "front: the echo saw the datagram from the far side (%s)" % (seen,))
if lan_in:
    answer = from_lan("no-login", lan_in)
    check(answer.get("chosen") in ("05ff", "closed") and answer.get("answered") is False,
          "LAN: a client with no login is refused (%s)" % (answer,))
    answer = from_lan("wrong-login", lan_in)
    check(answer.get("refused") is True, "LAN: a wrong login is refused (%s)" % (answer,))
    answer = from_lan("fetch", lan_in)
    check(answer.get("ok") is True, "LAN: with the login, a fetch (%s)" % (answer,))
    by_the_room("/lan", "LAN: the fetch")
    echoed = len(world("echo"))
    answer = from_lan("datagram", lan_in)
    check(answer.get("echoed") is True, "LAN: with the login, a datagram came back (%s)" % (answer,))
    seen = [entry[1] for entry in world("echo")[echoed:]]
    check(bool(seen) and OUT0 not in seen, "LAN: the echo saw the datagram from the far side (%s)" % (seen,))
    check(not requests("/no-login"), "LAN: the request with no login reached nothing")
status = engine.stop()
quiet_tun(before, "front")
ended_well(engine, status, "front")
check(bool(wait_for(lambda: OUT0 in hub("left", "f4c-front")[lefts:], 5)), "front: it left the room when it stopped")
if len(failed) > mark:
    engine.show()

# 4. A front with no way to the room.
mark = len(failed)
core = front_core()
core["outbounds"] = [outbound for outbound in core["outbounds"] if outbound["tag"] != "room"]
engine = Engine("run", "--session", session("front-no-way", {"core": core, "room": room_half("f4c-no-way"), "bind": BIND}))
last = engine.until(lambda event: event.get("event") == "ended", 60)
status = engine.stop()
check(status == 1 and bool(last) and last.get("reason") == "failed" and last.get("code") == "config"
      and "`room`" in (last.get("message") or ""),
      "a front with no way to the room: `ended` failed with code config, naming `room` (%s)" % (last,))
check(not any(event.get("event") == "ready" for event in engine.events), "a front with no way to the room: never ready")
if len(failed) > mark:
    engine.show()

print("%d failed" % len(failed))
sys.exit(1 if failed else 0)
PY

status=0
in_client python3 -I "$scratch/drive.py" cases "$scratch/ghostlane-engine" "$scratch" "$uid" "$gid" "$world" || status=$?
if [ "$status" != 0 ]; then
    echo "== what the world saw"
    for service in $services; do
        echo "-- $service"
        cat "$scratch/$service.log"
    done
    cat "$scratch/world-errors.log" 2>/dev/null || true
    echo "-- the olcRTC server's log, its end"
    tail -n 120 "$scratch/srv.log"
fi
exit "$status"

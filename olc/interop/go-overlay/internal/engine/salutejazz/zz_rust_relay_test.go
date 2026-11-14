// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T2(b) relay-only. The
// real SaluteJazz SFU offers only private host candidates, so a client
// reaches it through Sber's TURN or not at all (t3-live-1: the Rust client's
// host candidate never paired). Here the Rust client joins the fake SFU with
// iceTransportPolicy "relay", through a pion TURN server (pion/turn/v5, the
// engine's own dependency) on the host's address:
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test ./internal/engine/salutejazz -run '^TestRustRelayOnly' -v
//
// The fake advertises a STUN server in rtc:config (fakeconnector_test.go,
// fakeSTUNURL), so the client dials the fake through a WebSocket relay of
// this file that hands it the TURN server instead, and reads every candidate
// the client trickles. Nothing else changes: the Go server joins the fake
// directly, with the fake's own rtc:config.
//
// startTurnRelay is also what TestServeFakeRoom serves a relay-only room
// with (OLCRTC_GATE_RUST_RELAY=1), for the gate's fakeroom S0-S5.
//
// SaluteJazz's rtc:config lists each TURN host over UDP, over TCP (the same
// port, ?transport=tcp) and over TLS (turns:, 443); pion and Chrome allocate
// on all of them. TestRustRelayOnlyJoinsThroughTurnOverTCP hands the client
// only the TCP URL: a network that drops UDP leaves the client that path.

package salutejazz_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/turn/v5"

	"github.com/openlibrecommunity/olcrtc/internal/engine/salutejazz"
)

const (
	// fakeICEServers is the fake's rtc:config ICE server list as its frame
	// carries it (fakeconnector_test.go: one STUN URL, json.Marshal's form).
	fakeICEServers = `[{"urls":["stun:stun.l.google.com:19302"]}]`
	// relayRealm, relayUser and relayPass are the TURN server's.
	relayRealm = "olc.relay.test"
	relayUser  = "1763100000:rust"
	relayPass  = "relay-test-password"
	// rustRelayEnv makes TestServeFakeRoom serve relay-only rooms.
	rustRelayEnv = "OLCRTC_GATE_RUST_RELAY"
)

// candidateRe finds a candidate attribute in a client frame.
var candidateRe = regexp.MustCompile(`candidate:[^"]+`)

// turnRelay is a TURN server and the connector relay that hands it out.
type turnRelay struct {
	// url is the connector URL a client dials instead of the fake's.
	url string
	// allocations, relayedIn and relayedOut count what the TURN server
	// allocated and moved through its relayed sockets.
	allocations, relayedIn, relayedOut atomic.Int64

	// accepted counts the TCP connections the TURN server took (a TCP
	// relay only).
	accepted atomic.Int64

	mu         sync.Mutex
	rewrites   int
	candidates []string
	conns      []*websocket.Conn
}

// hostIPv4 is the address the default route leaves from: the one the fake's
// pion gathers a host candidate on (no packet is sent).
func hostIPv4(t testing.TB) net.IP {
	t.Helper()
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Skipf("no default IPv4 route: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP
}

// startTurnRelay starts a pion TURN server on the host's address, over UDP,
// and a WebSocket relay to upstream (a fake connector URL) whose rtc:config
// names that server. Both end with the test.
func startTurnRelay(t testing.TB, upstream string) *turnRelay {
	t.Helper()
	return startTurnRelayOver(t, upstream, "udp")
}

// startTurnRelayOver is startTurnRelay with the client reaching the TURN
// server over transport, "udp" or "tcp" (RFC 8656 section 3.1: STUN and
// ChannelData framed on one TCP connection); the relayed address is UDP
// either way.
func startTurnRelayOver(t testing.TB, upstream, transport string) *turnRelay {
	t.Helper()
	ip := hostIPv4(t)
	x := &turnRelay{}
	gen := countingRelay{
		RelayAddressGeneratorStatic: &turn.RelayAddressGeneratorStatic{RelayAddress: ip, Address: ip.String()},
		x:                           x,
	}
	key := turn.GenerateAuthKey(relayUser, relayRealm, relayPass)
	cfg := turn.ServerConfig{
		Realm: relayRealm,
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			return ra.Username, key, ra.Username == relayUser
		},
	}
	var port int
	switch transport {
	case "udp":
		udp, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		port = udp.LocalAddr().(*net.UDPAddr).Port
		cfg.PacketConnConfigs = []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: gen}}
	case "tcp":
		ln, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		port = ln.Addr().(*net.TCPAddr).Port
		cfg.ListenerConfigs = []turn.ListenerConfig{{Listener: countingListener{Listener: ln, x: x}, RelayAddressGenerator: gen}}
	default:
		t.Fatalf("no TURN transport %q", transport)
	}
	srv, err := turn.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	turnURL := "turn:" + ip.String() + ":" + strconv.Itoa(port) + "?transport=" + transport
	servers := `[{"credential":"` + relayPass + `","urls":["` + turnURL + `"],"username":"` + relayUser + `"}]`

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := upstream
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		up, _, err := websocket.DefaultDialer.Dial(target, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		down, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			_ = up.Close()
			return
		}
		x.mu.Lock()
		x.conns = append(x.conns, up, down)
		x.mu.Unlock()
		go x.pipe(up, down, func(msg []byte) []byte { // the fake to the client
			if !strings.Contains(string(msg), fakeICEServers) {
				return msg
			}
			x.mu.Lock()
			x.rewrites++
			x.mu.Unlock()
			return []byte(strings.Replace(string(msg), fakeICEServers, servers, 1))
		})
		go x.pipe(down, up, func(msg []byte) []byte { // the client to the fake
			if found := candidateRe.FindAllString(string(msg), -1); len(found) > 0 {
				x.mu.Lock()
				x.candidates = append(x.candidates, found...)
				x.mu.Unlock()
			}
			return msg
		})
	}))
	x.url = "ws" + strings.TrimPrefix(proxy.URL, "http") + "/connector"
	t.Cleanup(func() {
		x.mu.Lock()
		conns := append([]*websocket.Conn(nil), x.conns...)
		x.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		proxy.Close()
		_ = srv.Close()
	})
	return x
}

// pipe copies messages from src to dst through edit until either side
// ends, then closes both (a fake that drops the client drops it here too).
func (x *turnRelay) pipe(src, dst *websocket.Conn, edit func([]byte) []byte) {
	defer func() {
		_ = src.Close()
		_ = dst.Close()
	}()
	for {
		kind, msg, err := src.ReadMessage()
		if err != nil {
			return
		}
		if err := dst.WriteMessage(kind, edit(msg)); err != nil {
			return
		}
	}
}

// clientCandidates is every candidate the client trickled, and how many
// rtc:config frames were handed the TURN server.
func (x *turnRelay) clientCandidates() (lines []string, rewrites int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]string(nil), x.candidates...), x.rewrites
}

// useFor points cfg at the relay, relay-only.
func (x *turnRelay) useFor(cfg *rustConfig) {
	cfg.URL = x.url
	cfg.ICETransportPolicy = "relay"
}

// check fails t unless the client was handed the TURN server, trickled only
// relayed candidates, and the server relayed at least moved bytes each way.
func (x *turnRelay) check(t *testing.T, moved int64) {
	t.Helper()
	lines, rewrites := x.clientCandidates()
	if rewrites == 0 {
		t.Fatal("no rtc:config frame carried the fake's ICE servers: the client was never handed the TURN server")
	}
	if len(lines) == 0 {
		t.Fatal("the client trickled no candidate")
	}
	for _, l := range lines {
		if !strings.Contains(l, " typ relay") {
			t.Fatalf("a relay-only client trickled %q", l)
		}
	}
	t.Logf("candidates: %q", lines)
	in, out := x.relayedIn.Load(), x.relayedOut.Load()
	t.Logf("TURN: %d allocations, relayed %d bytes in and %d out", x.allocations.Load(), in, out)
	if x.allocations.Load() == 0 || in < moved || out < moved {
		t.Fatalf("the TURN server relayed %d in and %d out on %d allocations, want at least %d each way",
			in, out, x.allocations.Load(), moved)
	}
}

// countingRelay is RelayAddressGeneratorStatic whose relayed sockets count
// what they move.
type countingRelay struct {
	*turn.RelayAddressGeneratorStatic
	x *turnRelay
}

func (c countingRelay) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	pc, addr, err := c.RelayAddressGeneratorStatic.AllocatePacketConn(conf)
	if err != nil {
		return nil, nil, err
	}
	c.x.allocations.Add(1)
	return &countingConn{PacketConn: pc, x: c.x}, addr, nil
}

// countingListener counts the TCP connections the TURN server accepts.
type countingListener struct {
	net.Listener
	x *turnRelay
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.x.accepted.Add(1)
	}
	return c, err
}

type countingConn struct {
	net.PacketConn
	x *turnRelay
}

func (c *countingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	c.x.relayedIn.Add(int64(n))
	return n, a, err
}

func (c *countingConn) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, a)
	c.x.relayedOut.Add(int64(n))
	return n, err
}

// TestRustRelayOnlyJoinsThroughTurn is the join test relay-only: the client
// trickles only relayed candidates, both peer connections come up through
// the TURN server, and a download and an upload move through it at once.
func TestRustRelayOnlyJoinsThroughTurn(t *testing.T) {
	room := salutejazz.NewFakeRoom(t)
	relay := startTurnRelay(t, room.URL())
	tunnel := startRustTunnel(t, room, 0, 0, relay.useFor)
	down := startDownload(t, tunnel.socksAddr, startSource(t))
	up := startUpload(t, tunnel.socksAddr, startSink(t))
	const want = 4 << 20
	eventually(t, 60*time.Second, "4 MiB each way", func() bool { return down.moved() >= want && up.moved() >= want })
	for what, x := range map[string]*transfer{"download": down, "upload": up} {
		if bad := x.fault(); bad != nil {
			t.Fatalf("the %s: %v", what, bad)
		}
	}
	tunnel.checkStillUp(t)
	checkCapture(t, room)
	relay.check(t, want)
	for _, line := range []string{iceConnectedLine, pcConnectedLine} {
		if !tunnel.client.logHas(line) {
			t.Fatalf("the client never said %q", line)
		}
	}
}

// TestRustRelayOnlyJoinsThroughTurnOverTCP is the relay-only join with the
// TURN server reachable over TCP only: the client allocates over a TCP
// connection, trickles the relayed candidate, and a download and an upload
// move through it at once.
func TestRustRelayOnlyJoinsThroughTurnOverTCP(t *testing.T) {
	room := salutejazz.NewFakeRoom(t)
	relay := startTurnRelayOver(t, room.URL(), "tcp")
	tunnel := startRustTunnel(t, room, 0, 0, relay.useFor)
	down := startDownload(t, tunnel.socksAddr, startSource(t))
	up := startUpload(t, tunnel.socksAddr, startSink(t))
	const want = 4 << 20
	eventually(t, 60*time.Second, "4 MiB each way", func() bool { return down.moved() >= want && up.moved() >= want })
	for what, x := range map[string]*transfer{"download": down, "upload": up} {
		if bad := x.fault(); bad != nil {
			t.Fatalf("the %s: %v", what, bad)
		}
	}
	tunnel.checkStillUp(t)
	checkCapture(t, room)
	relay.check(t, want)
	if n := relay.accepted.Load(); n == 0 {
		t.Fatal("the TURN server accepted no TCP connection")
	} else {
		t.Logf("TURN over TCP: %d connections", n)
	}
	for _, line := range []string{iceConnectedLine, pcConnectedLine} {
		if !tunnel.client.logHas(line) {
			t.Fatalf("the client never said %q", line)
		}
	}
}

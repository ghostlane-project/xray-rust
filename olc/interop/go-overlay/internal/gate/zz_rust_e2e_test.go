// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the engine's e2e
// scenarios, ported to the Rust client on the interop target. Each runs the
// pinned Go server in a room of an in-process hub and the Rust client
// (olc-client) as a child process:
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestRustE2E$' \
//	    -olcrtc.gate-target=interop -olcrtc.gate-rust-bin=<olc-client>
//
//   - multi-key ring: a server holding two keys serves a client with the
//     second; a client whose key is outside the ring never pairs;
//   - reconnects: the hub drops every connection to the room, twice; the
//     client rejoins, reopens its session and carries a pull again;
//   - reconnects: as fast as Go: 20 such cuts under the Rust client and 20
//     under the Go client (zz_rust_reconnect_test.go), each with its own
//     server; the Rust client's reopens take at most 1.5 times as long;
//   - dead link: the room goes silent (the hub drops every frame); liveness
//     tears the session down and, once the room relays again, it reopens;
//   - egress refusal: a server without the private-target switch refuses a
//     loopback target; the client answers the SOCKS request host-unreachable;
//   - server restart (the peer close): the server process stops and another
//     starts in the room. The pinned server, with no peer ids on this
//     transport, says CONTROL_CLOSE only from closeSession at its shutdown,
//     and that notice races shutdown's own close of the transport
//     (server.go:231-246, link.go:366-424), so the client learns of the stop
//     from the notice or from liveness; either way it reopens on the new
//     server. The notice itself is held by olc-client's control tests;
//   - peer close: the server on the pipe in peer mode (interoppipe.PeersName)
//     runs its peer-routing path, which tells each peer CONTROL_CLOSE as a
//     rejoin rebuilds it (closePeerRouting, server/link.go:263-288). The hub
//     cuts the server alone; the client, still in the room, gives the session
//     up as peer-close, reopens and carries a pull. The Go client runs it
//     first, as the reference;
//   - supervisor failover: the client's config names two rooms; the first
//     fails (an address nothing listens on, then a room nobody is in), and
//     the room supervisor moves on to the second, which carries a pull;
//   - stalled far end: the hub stops reading the client's connection while
//     uploads fill every buffer in front of it, so the client's write to the
//     hub blocks for good. Liveness gives the session up and the client
//     rejoins and reopens with that write still stuck (reconnect), and a
//     SIGTERM ends the process within the stop budget (stop).

package gate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

// rustLiveness is olc-client's liveness block.
type rustLiveness struct {
	IntervalMS int `json:"interval_ms,omitempty"`
	TimeoutMS  int `json:"timeout_ms,omitempty"`
	Failures   int `json:"failures,omitempty"`
}

// e2eEnv is one run of the scenarios: the hub, the server binary, the origin.
type e2eEnv struct {
	t         *testing.T
	target    *InteropTarget
	capture   *Capture
	serverLog string // the log of the server started last
}

// room is a fresh room on the hub: its name and its endpoint.
func (e *e2eEnv) room(key string) (string, Endpoint) {
	ch, err := NewChannel()
	if err != nil {
		e.t.Fatal(err)
	}
	name := "e2e-" + ch
	return name, Endpoint{Provider: providerInterop, Transport: transportData, Room: e.target.hub.URL(name),
		Key: key, DNS: defaultDNS}
}

func (e *e2eEnv) key() string {
	k, err := NewKey()
	if err != nil {
		e.t.Fatal(err)
	}
	return k
}

// childLifetime bounds every process the scenarios start: longer than the
// whole of TestRustE2E, short enough that nothing outlives a stuck run.
const childLifetime = 10 * time.Minute

// server runs the pinned server in ep's room with ring; allowPrivate lifts
// its egress policy, as every gate cell does. The server is started here, not
// by the gate's startServer, so that its end is certain however the test
// ends:
//   - t.Cleanup kills its process group and waits for it, on a pass, a
//     failure or a t.Fatal before the scenario stops it itself;
//   - Pdeathsig kills it when the test process dies (a panic, -timeout, a
//     kill), where no cleanup runs;
//   - its context carries childLifetime.
//
// The returned stop is idempotent: SIGTERM to the group (the server says
// goodbye), SIGKILL to whatever is left after stopGrace, then the wait.
func (e *e2eEnv) server(ep Endpoint, ring []string, allowPrivate bool) func() {
	e.t.Helper()
	return e.serverOn(interoppipe.Name, ep, ring, allowPrivate)
}

// serverOn is server on the engine engineName: interoppipe.PeersName puts
// the server on its peer-routing path.
func (e *e2eEnv) serverOn(engineName string, ep Endpoint, ring []string, allowPrivate bool) func() {
	t := e.t
	t.Helper()
	binary, err := e.target.build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath, logPath := filepath.Join(dir, "srv.yaml"), filepath.Join(dir, serverLogName)
	logFile, err := createPrivate(cfgPath, serverConfigOn(t, engineName, ep, ring), logPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
	cmd := exec.CommandContext(ctx, binary, cfgPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	env := []string{bridgeDelayEnv + "=0s"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, privateTargetsEnv+"=") && !strings.HasPrefix(kv, bridgeDelayEnv+"=") {
			env = append(env, kv)
		}
	}
	if allowPrivate {
		env = append(env, privateTargetsEnv+"=1")
	}
	cmd.Env = env
	cmd.SysProcAttr = childProc(true)
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace
	err = cmd.Start()
	_ = logFile.Close()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-exited:
			case <-time.After(stopGrace + time.Second):
			}
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-exited
		})
	}
	t.Cleanup(stop)
	e.serverLog = logPath
	if err := waitForLine(logPath, linkedLine, linkBudget, exited); err != nil {
		t.Fatal(err)
	}
	return stop
}

// client starts the Rust client on ep and waits for its SOCKS address.
func (e *e2eEnv) client(ep Endpoint, extra func(*rustConfig)) (string, *rustChild) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
	e.t.Cleanup(cancel)
	child, err := startRust(ctx, *gateRustBin, ep, extra)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { child.halt(stopBudget, e.t.Logf) })
	select {
	case addr := <-child.ready:
		return addr, child
	case <-child.exited:
		e.t.Fatalf("rust client ended before it listened: %v", child.err)
	case <-time.After(startBudget):
		e.t.Fatalf("rust client not ready within %s", startBudget)
	}
	return "", nil
}

// serverConfigOn is interopServerConfig on the engine engineName.
func serverConfigOn(t *testing.T, engineName string, ep Endpoint, ring []string) string {
	t.Helper()
	cfg := interopServerConfig(ep, ring)
	if engineName == interoppipe.Name {
		return cfg
	}
	from := "name: " + interoppipe.Name + ","
	if strings.Count(cfg, from) != 1 {
		t.Fatalf("interopServerConfig does not name its engine as %q once:\n%s", from, cfg)
	}
	return strings.Replace(cfg, from, "name: "+engineName+",", 1)
}

// goPeersClient is the Go public client on the pipe in peer mode: it confirms
// the peer its welcome names and sends to that peer alone (client/link.go:111,
// :145-157), as on a carrier with peer ids.
type goPeersClient struct{ cli cliClient }

// Start runs the client on ep, as goInteropClient does.
func (g goPeersClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	cfg := client.Config{
		Transport: ep.Transport, Provider: "none", Engine: interoppipe.PeersName, URL: ep.Room,
		KeyHex: ep.Key, LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
	}
	c := g.cli
	c.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return c.Start(ctx, ep)
}

// peerClose runs the peer close under one client flavour: a server in peer
// mode, a pull, the hub cutting the server alone, and the client, which was
// not cut, hearing CONTROL_CLOSE as the server's rejoin rebuilds its peer
// routing (reinstallPeerRouting, server/link.go:238-244, closePeers through
// closePeerSession and notifyPeerClose, server/peer.go:691-767).
func (e *e2eEnv) peerClose(flavour string) {
	t := e.t
	t.Helper()
	hub := e.target.hub
	name, ep := e.room(e.key())
	srv, cli := ep, ep
	srv.Room, cli.Room = hub.URL(name+"@srv"), hub.URL(name+"@"+flavour)
	defer e.serverOn(interoppipe.PeersName, srv, []string{ep.Key}, true)()
	log := e.capture.Begin()
	var socks string
	switch flavour {
	case "rust":
		var child *rustChild
		socks, child = e.client(cli, nil)
		defer child.halt(stopBudget, t.Logf)
	case "cli":
		ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
		defer cancel()
		tun, err := goPeersClient{cli: cliClient{start: startBudget, stop: stopBudget}}.Start(ctx, cli)
		if err != nil {
			t.Fatal(err)
		}
		defer tun.Stop()
		socks = tun.SocksAddr
	default:
		t.Fatalf("no flavour %q", flavour)
	}
	e.pullSoon(socks, 10*time.Second)
	if n := log.Count("client reconnect reason="); n != 0 {
		t.Fatalf("%s: %d reconnects before the cut:\n%s", flavour, n, tail(log.Text(), 30))
	}
	hub.CutTag(name, "srv")
	waitLog(t, log, "client reconnect reason=peer-close", 1, 10*time.Second)
	// The death comes first and once; the engine's rejoin it asks for then
	// comes back as "reason=provider" (handleReconnect, client/link.go:361-372),
	// in both flavours, and is not a second death.
	deaths := func() (first string, peerClose, liveness int) {
		text := log.Text()
		if i := strings.Index(text, "client reconnect reason="); i >= 0 {
			first = text[i+len("client reconnect reason="):]
			if j := strings.IndexAny(first, " \n"); j >= 0 {
				first = first[:j]
			}
		}
		return first, log.Count("client reconnect reason=peer-close"), log.Count("client reconnect reason=liveness")
	}
	if first, pc, lv := deaths(); first != "peer-close" || pc != 1 || lv != 0 {
		t.Fatalf("%s: first death %q, %d peer-close, %d liveness; want the server's notice alone:\n%s",
			flavour, first, pc, lv, tail(log.Text(), 30))
	}
	waitLog(t, log, " reopened (device=", 1, 30*time.Second)
	e.pullSoon(socks, 20*time.Second)
	if first, pc, lv := deaths(); first != "peer-close" || pc != 1 || lv != 0 {
		t.Fatalf("%s: after the reopen: first death %q, %d peer-close, %d liveness:\n%s",
			flavour, first, pc, lv, tail(log.Text(), 30))
	}
	t.Logf("%s: the server's notice ended the session (peer-close); it reopened and carried a pull", flavour)
}

// pull fetches the origin's 1 KB through socks.
// failover is TestSupervisorFailoverProfilesReachWorkingSOCKS
// (e2e/tunnel_test.go:1481-1555) on the Rust client's room supervisor: its
// first room fails and the next, where the pinned server is, carries a pull.
// first is how the first room fails: "dead", an address nothing listens on
// (the Go test's failing provider: the run ends at its connect); "empty", a
// hub room nobody is in (the run ends when its handshake finds no peer).
// The rooms start in order, one cycle (mobile/runtime.go:150-161).
func (e *e2eEnv) failover(first string) {
	t := e.t
	t.Helper()
	name, ep := e.room(e.key())
	defer e.server(ep, []string{ep.Key}, true)()
	var bad, why string
	switch first {
	case "dead":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		bad, why = "tcp://"+ln.Addr().String()+"/"+name, "ended with error: "
		_ = ln.Close()
	case "empty":
		// The FFI's driver runs each room as Go's mobile runtime does, so its
		// error comes wrapped as runPublicClient (mobile/runtime.go:95) and
		// the client (pkg/olcrtc/client/client.go:166) wrap it.
		wrap := ""
		if filepath.Base(*gateRustBin) == "olc-ffi-client" {
			wrap = "run public client: client: "
		}
		bad, why = e.target.hub.URL(name+"-empty"), "ended with error: "+wrap+"handshake: no peer in room"
	default:
		t.Fatalf("no first room %q", first)
	}
	log := e.capture.Begin()
	socks, _ := e.client(ep, func(c *rustConfig) {
		c.URL, c.Rooms = bad, []string{ep.Room}
	})
	e.pullSoon(socks, 10*time.Second)
	text := log.Text()
	at := 0
	for _, want := range []string{
		"failover cycle=1 starting room=" + bad,
		"failover cycle=1 room=" + bad + " " + why,
		"failover cycle=1 starting room=" + ep.Room,
		"SOCKS5 server listening on ",
	} {
		i := strings.Index(text[at:], want)
		if i < 0 {
			t.Fatalf("%s first room: no %q after the lines before it:\n%s", first, want, tail(text, 30))
		}
		at += i + len(want)
	}
	if n := log.Count("failover cycle="); n != 3 {
		t.Fatalf("%s first room: %d supervisor lines, want 3 (two starts, one end):\n%s", first, n, tail(text, 30))
	}
	t.Logf("%s first room: the supervisor moved on to the next and it carried a pull", first)
}

func (e *e2eEnv) pull(socks string) error {
	dial, err := SocksDialer(socks)
	if err != nil {
		return err
	}
	resp, err := HTTPClient(dial, 20*time.Second).Get(e.target.origin.URLs.Small)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || n != 1024 {
		return fmt.Errorf("pull: status %d, %d bytes", resp.StatusCode, n)
	}
	return nil
}

// waitLog waits until log holds want n times.
func waitLog(t *testing.T, log *CellLog, want string, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for log.Count(want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%q seen %d times within %s, want %d; the client said:\n%s", want, log.Count(want), within, n,
				tail(log.Text(), 40))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func tail(text string, n int) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// pullSoon retries a pull for a while: a session that just reopened may
// still be settling.
func (e *e2eEnv) pullSoon(socks string, within time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := e.pull(socks)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("no pull within %s: %v", within, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// pushes is a set of uploads through the client that write until their
// connection fails.
type pushes struct {
	written atomic.Int64
	stop    func()
}

// push opens n uploads to the origin's sink through socks, each a POST that
// never ends: enough bytes to fill every buffer between the client and a far
// end that stopped reading (four of the server's 4 MiB stream windows against
// the pipe's 512 KiB send buffer and the hub's 512 KiB receive buffer).
func (e *e2eEnv) push(socks string, n int) *pushes {
	e.t.Helper()
	dial, err := SocksDialer(socks)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := url.Parse(e.target.origin.URLs.Sink)
	if err != nil {
		e.t.Fatal(err)
	}
	p := &pushes{}
	ctx, cancel := context.WithCancel(context.Background())
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
		once  sync.Once
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dial(ctx, "tcp", u.Host)
			if err != nil {
				return
			}
			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			conns = append(conns, conn)
			mu.Unlock()
			head := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", u.Path, u.Host,
				int64(1)<<40)
			if _, err := io.WriteString(conn, head); err != nil {
				return
			}
			chunk := make([]byte, 64<<10)
			for ctx.Err() == nil {
				wrote, err := conn.Write(chunk)
				p.written.Add(int64(wrote))
				if err != nil {
					return
				}
			}
		}()
	}
	p.stop = func() {
		once.Do(func() {
			cancel()
			mu.Lock()
			for _, c := range conns {
				_ = c.Close()
			}
			mu.Unlock()
			wg.Wait()
		})
	}
	e.t.Cleanup(p.stop)
	return p
}

// waitStuck waits until the uploads have moved some bytes and then none for a
// second: the path in front of them is full.
func (e *e2eEnv) waitStuck(p *pushes, within time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(within)
	last, since := p.written.Load(), time.Now()
	for {
		time.Sleep(100 * time.Millisecond)
		now := p.written.Load()
		switch {
		case now != last:
			last, since = now, time.Now()
		case now > 0 && time.Since(since) >= time.Second:
			e.t.Logf("the uploads stopped after %d bytes", now)
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("the uploads did not come to a stop within %s (%d bytes)", within, now)
		}
	}
}

// TestRustE2E runs the ported e2e scenarios.
func TestRustE2E(t *testing.T) {
	if *gateTargetName != targetInterop {
		t.Skip("the e2e scenarios run with -olcrtc.gate-target=interop")
	}
	if *gateRustBin == "" {
		t.Fatal("no Rust client: pass -olcrtc.gate-rust-bin")
	}
	interoppipe.Register()
	root := moduleRoot(t)
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	capture := StartCapture()
	t.Cleanup(capture.Stop)
	env := &e2eEnv{target: &InteropTarget{root: root, work: t.TempDir(), hub: hub, origin: startOrigin(t)},
		capture: capture}

	t.Run("multi-key ring", func(t *testing.T) {
		env.t = t
		k1, k2, outside := env.key(), env.key(), env.key()
		_, ep := env.room(k2)
		defer env.server(ep, []string{k1, k2}, true)()
		log := capture.Begin()
		socks, _ := env.client(ep, nil)
		if err := env.pull(socks); err != nil {
			t.Fatalf("the ring's second key: %v", err)
		}
		_, other := env.room(outside)
		defer env.server(other, []string{k1, k2}, true)()
		ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
		t.Cleanup(cancel)
		child, err := startRust(ctx, *gateRustBin, other, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { child.halt(stopBudget, nil) })
		select {
		case addr := <-child.ready:
			t.Fatalf("a key outside the ring paired and listens on %s", addr)
		case <-child.exited:
		case <-time.After(startBudget):
			t.Fatalf("a key outside the ring neither paired nor gave up within %s", startBudget)
		}
		waitLog(t, log, "handshake: ", 1, 5*time.Second)
		if log.Count("SOCKS5 server listening on ") != 1 {
			t.Fatalf("only the ring's key may listen:\n%s", tail(log.Text(), 20))
		}
	})

	t.Run("reconnects", func(t *testing.T) {
		env.t = t
		name, ep := env.room(env.key())
		defer env.server(ep, []string{ep.Key}, true)()
		log := capture.Begin()
		socks, _ := env.client(ep, nil)
		env.pullSoon(socks, 10*time.Second)
		for round := 1; round <= 2; round++ {
			hub.Cut(name)
			waitLog(t, log, "client reconnect reason=provider", round, 30*time.Second)
			waitLog(t, log, " reopened (device=", round, 60*time.Second)
			env.pullSoon(socks, 20*time.Second)
		}
	})

	// The hub cuts the room 20 times under each client, each with its own
	// server: the Rust client's reopens may take at most 1.5 times as long as
	// the Go client's in all. A round slower than a second (a first hello
	// lost to the 2 s resend) is logged with the hub's trace, the client's
	// log and the server's around it.
	t.Run("reconnects: as fast as Go", func(t *testing.T) {
		env.t = t
		const rounds = 20
		rust := env.reopenRounds("rust", rounds, time.Second)
		cli := env.reopenRounds("cli", rounds, time.Second)
		t.Logf("rust: %s", describeRounds(rust))
		t.Logf("cli:  %s", describeRounds(cli))
		if r, g := sumDurations(rust), sumDurations(cli); r*2 > g*3 {
			t.Fatalf("over %d rounds the Rust client took %s to reopen, the Go client %s: more than 1.5 times as long",
				rounds, r.Round(time.Millisecond), g.Round(time.Millisecond))
		}
	})

	t.Run("dead link", func(t *testing.T) {
		env.t = t
		name, ep := env.room(env.key())
		defer env.server(ep, []string{ep.Key}, true)()
		log := capture.Begin()
		socks, _ := env.client(ep, func(c *rustConfig) {
			c.Liveness = &rustLiveness{IntervalMS: 1000, TimeoutMS: 2000, Failures: 3}
			c.LivenessFallbackMS = 3000
		})
		env.pullSoon(socks, 10*time.Second)
		hub.Blackhole(name, true)
		waitLog(t, log, "control missed pong", 1, 30*time.Second)
		waitLog(t, log, "client reconnect reason=liveness", 1, 30*time.Second)
		hub.Blackhole(name, false)
		waitLog(t, log, " reopened (device=", 1, 90*time.Second)
		env.pullSoon(socks, 20*time.Second)
	})

	t.Run("egress refusal", func(t *testing.T) {
		env.t = t
		_, ep := env.room(env.key())
		defer env.server(ep, []string{ep.Key}, false)()
		log := capture.Begin()
		socks, _ := env.client(ep, nil)
		err := env.pull(socks)
		if err == nil {
			t.Fatal("a server without the private-target switch carried a loopback pull")
		}
		if !strings.Contains(err.Error(), "host unreachable") {
			t.Fatalf("pull: %v, want the SOCKS reply host unreachable", err)
		}
		waitLog(t, log, "remote not ready (connect ack=0x04)", 1, 5*time.Second)
	})

	t.Run("server restart", func(t *testing.T) {
		env.t = t
		_, ep := env.room(env.key())
		stop := env.server(ep, []string{ep.Key}, true)
		log := capture.Begin()
		socks, _ := env.client(ep, func(c *rustConfig) {
			c.Liveness = &rustLiveness{IntervalMS: 1000, TimeoutMS: 2000, Failures: 3}
			c.LivenessFallbackMS = 3000
		})
		env.pullSoon(socks, 10*time.Second)
		stop()
		deadline := time.Now().Add(30 * time.Second)
		for log.Count("client reconnect reason=peer-close")+log.Count("client reconnect reason=liveness") == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("the client did not give the stopped server's session up within 30s:\n%s",
					tail(log.Text(), 30))
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("the stopped server's session ended: peer-close %d, liveness %d",
			log.Count("client reconnect reason=peer-close"), log.Count("client reconnect reason=liveness"))
		defer env.server(ep, []string{ep.Key}, true)()
		waitLog(t, log, " reopened (device=", 1, 90*time.Second)
		env.pullSoon(socks, 20*time.Second)
	})

	t.Run("peer close", func(t *testing.T) {
		env.t = t
		for _, flavour := range []string{"cli", "rust"} {
			env.peerClose(flavour)
		}
	})

	t.Run("supervisor failover", func(t *testing.T) {
		env.t = t
		for _, first := range []string{"dead", "empty"} {
			env.failover(first)
		}
	})

	t.Run("stalled far end: reconnect", func(t *testing.T) {
		env.t = t
		name, ep := env.room(env.key())
		defer env.server(ep, []string{ep.Key}, true)()
		log := capture.Begin()
		socks, _ := env.client(ep, func(c *rustConfig) {
			c.Liveness = &rustLiveness{IntervalMS: 1000, TimeoutMS: 2000, Failures: 3}
			c.LivenessFallbackMS = 3000
		})
		env.pullSoon(socks, 10*time.Second)
		up := env.push(socks, 4)
		release := hub.StallNewest(name)
		defer release()
		env.waitStuck(up, 20*time.Second)
		waitLog(t, log, "client reconnect reason=liveness", 1, 30*time.Second)
		// The hub still reads nothing of the old connection: the rejoin must
		// not wait behind the write stuck on it.
		waitLog(t, log, " reopened (device=", 1, 30*time.Second)
		up.stop()
		env.pullSoon(socks, 20*time.Second)
	})

	t.Run("stalled far end: stop", func(t *testing.T) {
		env.t = t
		name, ep := env.room(env.key())
		defer env.server(ep, []string{ep.Key}, true)()
		log := capture.Begin()
		socks, child := env.client(ep, nil)
		env.pullSoon(socks, 10*time.Second)
		up := env.push(socks, 4)
		release := hub.StallNewest(name)
		defer release()
		env.waitStuck(up, 20*time.Second)
		started := time.Now()
		child.cancel()
		select {
		case <-child.exited:
		case <-time.After(stopBudget + 2*time.Second):
			t.Fatalf("SIGTERM with a write stuck on the far end: still running after %s", stopBudget+2*time.Second)
		}
		took := time.Since(started)
		state := child.cmd.ProcessState
		if !state.Success() || took >= stopBudget {
			t.Fatalf("SIGTERM with a write stuck on the far end: exit %v after %s, want a clean exit within %s; "+
				"the client said:\n%s", state, took.Round(time.Millisecond), stopBudget, tail(log.Text(), 20))
		}
		t.Logf("SIGTERM with a write stuck on the far end: a clean exit after %s", took.Round(time.Millisecond))
	})
}

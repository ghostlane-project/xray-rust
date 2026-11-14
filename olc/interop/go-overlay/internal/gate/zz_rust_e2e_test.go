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
//     server. The notice itself is held by olc-client's control tests.

package gate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
)

// rustLiveness is olc-client's liveness block.
type rustLiveness struct {
	IntervalMS int `json:"interval_ms,omitempty"`
	TimeoutMS  int `json:"timeout_ms,omitempty"`
	Failures   int `json:"failures,omitempty"`
}

// e2eEnv is one run of the scenarios: the hub, the server binary, the origin.
type e2eEnv struct {
	t       *testing.T
	target  *InteropTarget
	capture *Capture
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
	t := e.t
	t.Helper()
	binary, err := e.target.build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath, logPath := filepath.Join(dir, "srv.yaml"), filepath.Join(dir, serverLogName)
	logFile, err := createPrivate(cfgPath, interopServerConfig(ep, ring), logPath)
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
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

// pull fetches the origin's 1 KB through socks.
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
}

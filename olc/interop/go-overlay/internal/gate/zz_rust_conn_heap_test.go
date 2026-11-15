// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the heap an open
// connection costs the Rust client, plan §9's "per open connection" row
// (p3/m9-ffi.md, gap 18). The FFI's driver (olc-ffi-client in its control
// mode, OLC_FFI_CONTROL=1) runs the client through OlcrtcRuntime against the
// pinned Go server in a hub room; this test opens connConns SOCKS CONNECTs
// through it and reads memory_stats()' heap before and while they are open:
//
//   - idle: each CONNECT answered (the exit dialed a target that accepts and
//     never sends), no byte moving;
//   - moving: each to a target that sends dripBytes every dripEvery while the
//     test sends upBytes as often, every connection moving at once.
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestRustFFIConnHeap$' \
//	    -olcrtc.gate-target=interop -olcrtc.gate-rust-bin=<olc-ffi-client>
//
// It passes when every connection opened and moved, and the live heap per
// idle open connection is at most connIdleTarget bytes and per moving one at
// most connMovingTarget (the warm client's heap before the first connection
// is the base). After each phase the connections close and the heap must
// come back within connReturnSlack of the base.
//
// With -olcrtc.gate-rust-bin=<olc-ffi-dhat> (olc-ffi's dhat example) and
// OLC_CONN_HEAP_DHAT=idle|moving it instead profiles one phase by
// allocation site: a profile starts right before the phase's connections
// open and is written to OLC_CONN_HEAP_OUT while they are held. Nothing is
// asserted then (that build's heap is dhat's, memory_stats() reads none).

package gate

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
)

const (
	// connConns is the client's own bound (olc_client::socks::MAX_SOCKS_CONNS,
	// Go's maxSocksConns).
	connConns = 512
	// connOpeners open the connections this many at a time.
	connOpeners = 64
	// dripBytes every dripEvery down, upBytes as often up: 20 KiB/s down
	// and 10 KiB/s up per connection, 10 MiB/s down at 512.
	dripBytes = 2048
	upBytes   = 1024
	dripEvery = 100 * time.Millisecond
	// connIdleTarget and connMovingTarget are the guard's bounds, bytes of
	// live heap per open connection. Before the shrink (gap 18) an idle one
	// held 13,169-13,199 bytes and a moving one 13,334-13,422: the task's
	// 12,672-byte allocation, its socket's 256-byte registration and its
	// smux slot.
	connIdleTarget   = 3072
	connMovingTarget = 4096
	// connReturnSlack is how far above the base the heap may stay once the
	// connections closed: what their slots leave as capacity.
	connReturnSlack = 512 << 10
)

// connStats is the part of memory_stats() the test reads.
type connStats struct {
	Heap struct {
		Live   int64 `json:"live"`
		Allocs int64 `json:"allocs"`
	} `json:"heap"`
	Rt struct {
		Tasks int `json:"tasks"`
	} `json:"rt"`
	N struct {
		Conns   int `json:"conns"`
		Streams int `json:"streams"`
	} `json:"n"`
}

// controlChild is the driver in its control mode: one command per line on
// stdin, one answer per line on stdout, TICK lines skipped.
type controlChild struct {
	t       *testing.T
	stdin   io.WriteCloser
	answers chan string
}

func (c *controlChild) call(command, want string, within time.Duration) string {
	c.t.Helper()
	if _, err := io.WriteString(c.stdin, command+"\n"); err != nil {
		c.t.Fatalf("%s: %v", command, err)
	}
	return c.expect(command, want, within)
}

// expect waits for the answer that starts with want; command names it.
func (c *controlChild) expect(command, want string, within time.Duration) string {
	c.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case line, ok := <-c.answers:
			if !ok {
				c.t.Fatalf("%s: the driver ended", command)
			}
			if rest, ok := strings.CutPrefix(line, want); ok && (rest == "" || rest[0] == ' ') {
				return strings.TrimSpace(rest)
			}
			if strings.HasPrefix(line, "ERR ") {
				c.t.Fatalf("%s: %s", command, line)
			}
		case <-deadline:
			c.t.Fatalf("%s: no %s within %s", command, want, within)
		}
	}
}

func (c *controlChild) stats() connStats {
	c.t.Helper()
	raw := c.call("stats", "STATS", 30*time.Second)
	var s connStats
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		c.t.Fatalf("memory_stats(): %v in %q", err, raw)
	}
	return s
}

// waitConns waits until the client counts n open connections.
func (c *controlChild) waitConns(n int, within time.Duration) connStats {
	c.t.Helper()
	deadline := time.Now().Add(within)
	for {
		s := c.stats()
		if s.N.Conns == n {
			return s
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("%d connections open after %s; want %d", s.N.Conns, within, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// connTarget is what the exit dials for the test: it accepts and keeps every
// connection; with drip it sends dripBytes every dripEvery and reads what
// comes.
type connTarget struct {
	ln       net.Listener
	accepted atomic.Int64
	received atomic.Int64
	mu       sync.Mutex
	conns    []net.Conn
	wg       sync.WaitGroup
}

func startConnTarget(t *testing.T, drip bool) *connTarget {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ct := &connTarget{ln: ln}
	ct.wg.Add(1)
	go func() {
		defer ct.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			ct.mu.Lock()
			ct.conns = append(ct.conns, conn)
			ct.mu.Unlock()
			ct.accepted.Add(1)
			if !drip {
				continue
			}
			ct.wg.Add(2)
			go func() {
				defer ct.wg.Done()
				drain(conn, &ct.received)
			}()
			go func() {
				defer ct.wg.Done()
				chunk := make([]byte, dripBytes)
				for {
					if _, err := conn.Write(chunk); err != nil {
						return
					}
					time.Sleep(dripEvery)
				}
			}()
		}
	}()
	t.Cleanup(ct.close)
	return ct
}

func (ct *connTarget) close() {
	_ = ct.ln.Close()
	ct.mu.Lock()
	for _, c := range ct.conns {
		_ = c.Close()
	}
	ct.conns = nil
	ct.mu.Unlock()
	ct.wg.Wait()
}

// openConns opens n CONNECTs to addr through dial, connOpeners at a time;
// with up each sends upBytes every dripEvery and reads everything, and
// down counts what they read.
func openConns(t *testing.T, dial DialFunc, addr string, n int, up bool, down *atomic.Int64) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var (
		mu     sync.Mutex
		conns  []net.Conn
		failed []string
		wg     sync.WaitGroup
		pumps  sync.WaitGroup
	)
	var next atomic.Int64
	for range connOpeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for next.Add(1) <= int64(n) {
				dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
				conn, err := dial(dctx, "tcp", addr)
				dcancel()
				mu.Lock()
				if err != nil {
					failed = append(failed, err.Error())
					mu.Unlock()
					continue
				}
				conns = append(conns, conn)
				mu.Unlock()
				if !up {
					continue
				}
				pumps.Add(2)
				go func() {
					defer pumps.Done()
					drain(conn, down)
				}()
				go func() {
					defer pumps.Done()
					chunk := make([]byte, upBytes)
					for ctx.Err() == nil {
						if _, err := conn.Write(chunk); err != nil {
							return
						}
						time.Sleep(dripEvery)
					}
				}()
			}
		}()
	}
	wg.Wait()
	if len(failed) > 0 {
		cancel()
		for _, c := range conns {
			_ = c.Close()
		}
		t.Fatalf("%d of %d connections failed to open, first: %s", len(failed), n, failed[0])
	}
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			cancel()
			for _, c := range conns {
				_ = c.Close()
			}
			pumps.Wait()
		})
	}
	t.Cleanup(closeAll)
	return closeAll
}

// drain reads conn until it ends, counting into n as the bytes come.
func drain(conn net.Conn, n *atomic.Int64) {
	buf := make([]byte, 32<<10)
	for {
		got, err := conn.Read(buf)
		n.Add(int64(got))
		if err != nil {
			return
		}
	}
}

func waitCount(t *testing.T, what string, v *atomic.Int64, n int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for v.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d after %s; want %d", what, v.Load(), within, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// heapReadings takes n stats readings a quarter second apart: the median
// live heap and the last reading.
func heapReadings(c *controlChild, n int) (int64, connStats) {
	lives := make([]int64, 0, n)
	var last connStats
	for i := range n {
		if i > 0 {
			time.Sleep(250 * time.Millisecond)
		}
		last = c.stats()
		lives = append(lives, last.Heap.Live)
	}
	slices.Sort(lives)
	return lives[len(lives)/2], last
}

// TestRustFFIConnHeap measures the heap per open connection.
func TestRustFFIConnHeap(t *testing.T) {
	if *gateTargetName != targetInterop {
		t.Skip("the connection heap runs with -olcrtc.gate-target=interop")
	}
	bin := filepath.Base(*gateRustBin)
	if bin != "olc-ffi-client" && bin != "olc-ffi-dhat" {
		t.Skip("the connection heap runs with -olcrtc.gate-rust-bin=<olc-ffi-client>")
	}
	dhatPhase := os.Getenv("OLC_CONN_HEAP_DHAT")
	dhatOut := os.Getenv("OLC_CONN_HEAP_OUT")
	profiling := bin == "olc-ffi-dhat"
	if profiling != (dhatPhase == "idle" || dhatPhase == "moving") || (profiling && dhatOut == "") {
		t.Fatalf("olc-ffi-dhat runs with OLC_CONN_HEAP_DHAT=idle|moving and OLC_CONN_HEAP_OUT, and only it")
	}
	interoppipe.Register()
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	capture := StartCapture()
	t.Cleanup(capture.Stop)
	env := &e2eEnv{t: t, target: &InteropTarget{root: moduleRoot(t), work: t.TempDir(), hub: hub,
		origin: startOrigin(t)}, capture: capture}
	_, ep := env.room(env.key())
	defer env.server(ep, []string{ep.Key}, true)()

	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socks := probe.Addr().String()
	_ = probe.Close()
	cfg := rustConfig{URL: ep.Room, Key: ep.Key, Transport: ep.Transport, DNS: ep.DNS, Socks: socks,
		DeviceID: "gate-conn-heap"}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
	defer cancel()
	cmd := exec.CommandContext(ctx, *gateRustBin, path)
	cmd.Env = append(os.Environ(), "OLC_FFI_CONTROL=1")
	cmd.SysProcAttr = childProc(false)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopBudget
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "client.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &controlChild{t: t, stdin: stdin, answers: make(chan string, 64)}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if line := sc.Text(); !strings.HasPrefix(line, "TICK ") {
				c.answers <- line
			}
		}
		close(c.answers)
	}()
	defer func() {
		_, _ = io.WriteString(stdin, "quit\n")
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			text, _ := os.ReadFile(logPath)
			t.Logf("client log:\n%s", tail(string(text), 40))
		}
	}()
	c.expect("the driver's start", "LOADED", 30*time.Second)
	t.Logf("ready: %s", c.call("start", "READY", 60*time.Second))
	dial, err := SocksDialer(socks)
	if err != nil {
		t.Fatal(err)
	}

	hold := startConnTarget(t, false)
	drip := startConnTarget(t, true)
	// Warm: the first connections make what every later one reuses.
	warm := openConns(t, dial, hold.ln.Addr().String(), connOpeners, false, nil)
	warm()
	c.waitConns(0, 15*time.Second)
	time.Sleep(time.Second)
	baseLive, base := heapReadings(c, 3)

	profile := func(phase string) {
		if dhatPhase == phase {
			c.call("profile "+dhatOut, "PROFILING", 30*time.Second)
		}
	}
	dump := func(phase string) {
		if dhatPhase == phase {
			t.Logf("%s profile: %s", phase, c.call("dump", "DUMPED", 5*time.Minute))
		}
	}
	perConn := func(live int64) int64 { return (live - baseLive) / connConns }

	// Idle: every CONNECT answered, nothing moving.
	profile("idle")
	accepted := hold.accepted.Load()
	closeIdle := openConns(t, dial, hold.ln.Addr().String(), connConns, false, nil)
	waitCount(t, "idle connections at the target", &hold.accepted, accepted+connConns, 30*time.Second)
	time.Sleep(time.Second)
	idleLive, idle := heapReadings(c, 3)
	if idle.N.Conns != connConns {
		t.Fatalf("idle: the client counts %d connections; want %d", idle.N.Conns, connConns)
	}
	dump("idle")
	closeIdle()
	afterIdle := c.waitConns(0, 15*time.Second)

	// Moving: every connection receiving and sending at once.
	profile("moving")
	var down atomic.Int64
	closeMoving := openConns(t, dial, drip.ln.Addr().String(), connConns, true, &down)
	waitCount(t, "moving connections at the target", &drip.accepted, connConns, 30*time.Second)
	waitCount(t, "bytes down", &down, connConns*dripBytes*4, 60*time.Second)
	got := down.Load()
	movingLive, moving := heapReadings(c, 9)
	if moving.N.Conns != connConns {
		t.Fatalf("moving: the client counts %d connections; want %d", moving.N.Conns, connConns)
	}
	if down.Load() == got || drip.received.Load() == 0 {
		t.Fatalf("moving: %d bytes down and %d up, none in the last two seconds", got, drip.received.Load())
	}
	dump("moving")
	closeMoving()
	afterMoving := c.waitConns(0, 15*time.Second)
	time.Sleep(time.Second)
	endLive, _ := heapReadings(c, 3)

	t.Logf("conn heap: base live=%d allocs=%d tasks=%d", baseLive, base.Heap.Allocs, base.Rt.Tasks)
	t.Logf("conn heap: idle %d: live=%d (%d B per connection, %.1f allocations per connection) tasks=%d "+
		"streams=%d; after closing live=%d", connConns, idleLive, perConn(idleLive),
		float64(idle.Heap.Allocs-base.Heap.Allocs)/connConns, idle.Rt.Tasks, idle.N.Streams,
		afterIdle.Heap.Live)
	t.Logf("conn heap: moving %d: live=%d (%d B per connection, %.1f allocations per connection) tasks=%d "+
		"streams=%d, %d B down, %d B up; after closing live=%d, at the end %d", connConns, movingLive,
		perConn(movingLive), float64(moving.Heap.Allocs-base.Heap.Allocs)/connConns, moving.Rt.Tasks,
		moving.N.Streams, down.Load(), drip.received.Load(), afterMoving.Heap.Live, endLive)
	t.Logf("CONN_HEAP idle_per_conn=%d moving_per_conn=%d base=%d idle=%d moving=%d end=%d",
		perConn(idleLive), perConn(movingLive), baseLive, idleLive, movingLive, endLive)
	if profiling {
		return
	}
	if p := perConn(idleLive); p > connIdleTarget {
		t.Errorf("idle: %d B of heap per open connection; the target is %d", p, connIdleTarget)
	}
	if p := perConn(movingLive); p > connMovingTarget {
		t.Errorf("moving: %d B of heap per open connection; the target is %d", p, connMovingTarget)
	}
	if endLive-baseLive > connReturnSlack {
		t.Errorf("the heap stayed %d B above the base once every connection closed; at most %d",
			endLive-baseLive, connReturnSlack)
	}
}

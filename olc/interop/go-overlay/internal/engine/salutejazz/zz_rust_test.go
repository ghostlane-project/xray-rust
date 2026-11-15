// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T2(b), the SaluteJazz
// fake SFU with the Rust client (olc-client, engine salutejazz) in it. The
// pinned Go server joins the fake in-process, as startFakeTunnelLive does,
// and the Rust client joins it as a child process, over real WebRTC (str0m
// against the fake's pion) and the connector frames the fake holds to the
// capture of the official web client:
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test ./internal/engine/salutejazz -run '^TestRust' -v
//
//   - TestRustJoinsTheFakeRoomAsTheCaptureSays: the join, both peer
//     connections, a download and an upload, the relay window spoken; the
//     fake trips over no frame (an empty lastError);
//   - TestRustTunnelOnASlowLegKeepsItsControlStreamUnderBulk and
//     TestRustSixPullsOnTheSlowestLegKeepTheirPongs: tunnel_test.go's two
//     slow-leg tests, olcrtc#49, with the Rust client in the Go client's
//     place and the same bounds;
//   - TestRustRejoinsWhenTheConnectorDropsIt: every fake-side socket closes
//     without a close frame; the client joins again and carries a download.
//
// The join and the rejoin also hold the client to pion's state lines, which
// the apps restart the tunnel on (critique G1): "ICE connection state
// changed: connected", "peer connection state changed: connected" and
// "...: closed".
//
// TestServeFakeRoom serves fake rooms, each with a Go server in it, to the
// gate's fakeroom target (internal/gate/zz_rust_fakeroom_test.go), which runs
// this test binary as a child process and reads S0-S5 off the Rust client.
//
// What the Go client reports through its callbacks the Rust client says in
// its log, which the tests read: "session <id> opened", "reopened", "client
// reconnect", "control alive ... rtt=<d>", "control missed pong", "control
// unhealthy", and, from a build with the heap-stats feature, "heap now <n>
// KiB peak <n> KiB".

package salutejazz_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
	"github.com/openlibrecommunity/olcrtc/internal/engine"
	enginebuiltin "github.com/openlibrecommunity/olcrtc/internal/engine/builtin"
	"github.com/openlibrecommunity/olcrtc/internal/engine/salutejazz"
	"github.com/openlibrecommunity/olcrtc/internal/server"
	"github.com/openlibrecommunity/olcrtc/internal/zzmem"
)

const (
	// rustBinEnv names the Rust client binary.
	rustBinEnv = "OLCRTC_GATE_RUST_BIN"
	// rustLifetime bounds every client process a test starts.
	rustLifetime = 10 * time.Minute
	// rustStopGrace is how long a stopped client has to say goodbye.
	rustStopGrace = 5 * time.Second
	// rustListenMarker is the line the client prints once its SOCKS5 front
	// listens (client.go:324), after its session opened.
	rustListenMarker = "SOCKS5 server listening on "
	// windowTopic is the relay window's topic (window.go:75).
	windowTopic = "olcrtc.win"
	// rustTraceEnv, set, logs the start of every client's log (stamped to the
	// millisecond as it arrived) whether or not its test failed: where a
	// join spends its time.
	rustTraceEnv = "OLCRTC_GATE_RUST_TRACE"
	// rustTraceLines is how much of it: a join and its first exchanges.
	rustTraceLines = 120
)

func rustBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(rustBinEnv)
	if bin == "" {
		t.Skip(rustBinEnv + " (the olc-client binary) is not set")
	}
	return bin
}

// rustLiveness is olc-client's liveness block.
type rustLiveness struct {
	IntervalMS int `json:"interval_ms,omitempty"`
	TimeoutMS  int `json:"timeout_ms,omitempty"`
}

// rustConfig is what the Rust client reads (olc-client's config.rs).
type rustConfig struct {
	URL       string        `json:"url"`
	Engine    string        `json:"engine"`
	Token     string        `json:"token"`
	RoomID    string        `json:"room_id"`
	Name      string        `json:"name,omitempty"`
	Key       string        `json:"key"`
	Transport string        `json:"transport"`
	DNS       string        `json:"dns"`
	Socks     string        `json:"socks"`
	DeviceID  string        `json:"device_id"`
	Debug     bool          `json:"debug"`
	Liveness  *rustLiveness `json:"liveness,omitempty"`
	// ICETransportPolicy is "relay" for a relay-only client
	// (zz_rust_relay_test.go); empty is pion's and Go's "all".
	ICETransportPolicy string `json:"ice_transport_policy,omitempty"`
}

// rustRoomConfig joins room with key, liveness as given (zero: Go's).
func rustRoomConfig(room *salutejazz.FakeRoom, key string, probeEvery, pongTimeout time.Duration) rustConfig {
	cfg := rustConfig{
		URL: room.URL(), Engine: "salutejazz", Token: salutejazz.FakeRoomPassword, RoomID: salutejazz.FakeRoomCode,
		Key: key, Transport: "datachannel", DNS: "127.0.0.1:53", Socks: "127.0.0.1:0", DeviceID: "client-1",
		Debug: true,
	}
	if probeEvery > 0 || pongTimeout > 0 {
		cfg.Liveness = &rustLiveness{IntervalMS: int(probeEvery.Milliseconds()), TimeoutMS: int(pongTimeout.Milliseconds())}
	}
	return cfg
}

// rustProc is one run of the Rust client and what its log said.
type rustProc struct {
	cmd     *exec.Cmd
	logPath string
	listen  chan string
	exited  chan struct{}
	err     error

	opened, reopened, reconnects atomic.Int64
	// heapPeak is the last "heap ... peak N KiB" the client said, KiB.
	heapPeak atomic.Int64
	// rssPeak is the highest VmRSS sampled, KiB.
	rssPeak atomic.Int64
	// hwm is the VmHWM read just before the stop, KiB.
	hwm atomic.Int64
	// bin is the client's path; peakMem is the memory snapshot taken at the
	// sample with the highest VmRSS (under memMu).
	bin     string
	memMu   sync.Mutex
	peakMem zzmem.Peak
	// finalLog is the whole log once the client has exited (its directory
	// goes with the test's other cleanups).
	finalLog atomic.Pointer[string]
}

// startRust runs the client on cfg until the test ends; live, when given,
// gets its pongs, missed pongs and unhealthy reports. Its end is certain:
// the cleanup stops its process group and waits, Pdeathsig kills it with
// the test process, and its context carries rustLifetime.
func startRust(t *testing.T, cfg rustConfig, live *liveness) *rustProc {
	t.Helper()
	bin := rustBin(t)
	dir := t.TempDir()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "client.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), rustLifetime)
	cmd := exec.CommandContext(ctx, bin, cfgPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = rustStopGrace
	cmd.Stdout = io.Discard
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	p := &rustProc{bin: bin, cmd: cmd, logPath: logFile.Name(), listen: make(chan string, 1), exited: make(chan struct{})}
	lines := make(chan struct{})
	go func() {
		defer close(lines)
		defer func() { _ = logFile.Close() }()
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		said := false
		for sc.Scan() {
			line := sc.Text()
			_, _ = fmt.Fprintf(logFile, "%s %s\n", time.Now().Format("15:04:05.000"), line)
			if i := strings.Index(line, rustListenMarker); i >= 0 && !said {
				said = true
				p.listen <- strings.Fields(line[i+len(rustListenMarker):])[0]
			}
			p.note(line, live)
		}
	}()
	go func() {
		<-lines
		p.err = cmd.Wait()
		close(p.exited)
	}()
	go p.sample()
	t.Cleanup(func() {
		p.hwm.Store(procStatusKB(cmd.Process.Pid, "VmHWM:"))
		cancel()
		select {
		case <-p.exited:
		case <-time.After(rustStopGrace + 5*time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Errorf("the rust client was still running %s after its stop", rustStopGrace+5*time.Second)
		}
		if raw, err := os.ReadFile(p.logPath); err == nil {
			s := string(raw)
			p.finalLog.Store(&s)
		}
		t.Logf("rust client memory: VmHWM %d KiB, peak sampled VmRSS %d KiB, heap peak %d KiB",
			p.hwm.Load(), p.rssPeak.Load(), p.heapPeak.Load())
		p.memMu.Lock()
		t.Logf("rust client memory at peak RSS: %s", p.peakMem.Snap.Line(p.bin, memTopN))
		p.memMu.Unlock()
		switch {
		case os.Getenv(rustTraceEnv) != "":
			t.Logf("rust client log (%s), first lines:\n%s", p.logPath, headFile(p.logPath, rustTraceLines))
		case t.Failed():
			t.Logf("rust client log (%s), last lines:\n%s", p.logPath, tailFile(p.logPath, 60))
		}
	})
	return p
}

// note reads one log line for what the Go client's callbacks would have
// reported.
func (p *rustProc) note(line string, live *liveness) {
	switch {
	case strings.Contains(line, " reopened (device="):
		p.reopened.Add(1)
	case strings.Contains(line, "session ") && strings.Contains(line, " opened (device="):
		p.opened.Add(1)
	case strings.Contains(line, "client reconnect"):
		p.reconnects.Add(1)
	case strings.Contains(line, "heap now ") && strings.Contains(line, " peak "):
		if kib, ok := numberBefore(line, " peak ", " KiB"); ok {
			p.heapPeak.Store(kib)
		}
	}
	if live == nil {
		return
	}
	switch {
	case strings.Contains(line, "control alive "):
		_, rest, _ := strings.Cut(line, "rtt=")
		rtt, err := time.ParseDuration(strings.Fields(rest + " ")[0])
		if err != nil {
			return
		}
		live.mu.Lock()
		live.pongs = append(live.pongs, pong{at: time.Now(), rtt: rtt})
		live.mu.Unlock()
	case strings.Contains(line, "control missed pong"):
		live.mu.Lock()
		live.missed++
		live.mu.Unlock()
	case strings.Contains(line, "control unhealthy"):
		live.mu.Lock()
		live.unhealthy++
		live.mu.Unlock()
	}
}

// logHas says whether the client's log so far holds text.
func (p *rustProc) logHas(text string) bool {
	raw, err := os.ReadFile(p.logPath)
	return err == nil && strings.Contains(string(raw), text)
}

// The apps' log contract (critique G1): pion's state lines, which Android's
// handleRtcLine and iOS's IosVpnManager restart the tunnel on.
const (
	iceConnectedLine = "ICE connection state changed: connected"
	pcConnectedLine  = "peer connection state changed: connected"
	pcClosedLine     = "peer connection state changed: closed"
)

// numberBefore is the integer between after and before in line.
func numberBefore(line, after, before string) (int64, bool) {
	_, rest, ok := strings.Cut(line, after)
	if !ok {
		return 0, false
	}
	num, _, ok := strings.Cut(rest, before)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	return n, err == nil
}

// memTopN is how many mappings the peak-memory line names.
const memTopN = 12

// sample keeps the client's peak resident memory, twice a second.
func (p *rustProc) sample() {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if kb := procStatusKB(p.cmd.Process.Pid, "VmRSS:"); kb > p.rssPeak.Load() {
			p.rssPeak.Store(kb)
			p.memMu.Lock()
			p.peakMem.Observe(p.cmd.Process.Pid, kb)
			p.memMu.Unlock()
		}
		select {
		case <-p.exited:
			return
		case <-tick.C:
		}
	}
}

// procStatusKB reads one kB field of /proc/<pid>/status; 0 when it cannot.
func procStatusKB(pid int, field string) int64 {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, field); ok {
			n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			return n
		}
	}
	return 0
}

// tailFile is the last n lines of path.
func tailFile(path string, n int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// headFile is the first n lines of path.
func headFile(path string, n int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	return strings.Join(lines[:min(n, len(lines))], "\n")
}

// rustTunnel is fakeTunnel with the Rust client in the Go client's place.
type rustTunnel struct {
	room                *salutejazz.FakeRoom
	socksAddr           string
	serverID, clientID  string
	engines             *madeEngines
	serverLive          liveness
	clientLive          liveness
	client              *rustProc
	closedMu            sync.Mutex
	serverClosed        []string
	serverSessionsTotal atomic.Int64
}

// startRustTunnel is startFakeTunnelLive with the Rust client; tweaks change
// the client's config (a relay-only run points it at a TURN relay).
func startRustTunnel(t *testing.T, room *salutejazz.FakeRoom, probeEvery, pongTimeout time.Duration,
	tweaks ...func(*rustConfig),
) *rustTunnel {
	t.Helper()
	session.RegisterDefaults()
	provider, engines := registerFakeRoom(t, room)
	x := &rustTunnel{room: room, engines: engines}
	x.serverLive.interval, x.clientLive.interval = probeEvery, probeEvery
	x.serverLive.timeout, x.clientLive.timeout = pongTimeout, pongTimeout
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case <-serverDone:
		case <-time.After(10 * time.Second):
			t.Errorf("the server was still running 10 s after the test ended")
		}
	})
	go func() {
		serverDone <- server.Run(ctx, server.Config{
			Transport: "datachannel", Provider: provider, RoomURL: "room", KeyHex: tunnelKeyHex,
			DNSServer: "127.0.0.1:53", Liveness: x.serverLive.config(), UnsafeAllowPrivateTargets: true,
			OnSessionOpen: func(string, string, map[string]any) { x.serverSessionsTotal.Add(1) },
			OnSessionClose: func(_, reason string) {
				x.closedMu.Lock()
				defer x.closedMu.Unlock()
				x.serverClosed = append(x.serverClosed, reason)
			},
		})
	}()
	eventually(t, 10*time.Second, "the server in the room", func() bool {
		return engines.count() == 1 && engines.at(0).LocalPeerID() != ""
	})
	x.serverID = engines.at(0).LocalPeerID()

	cfg := rustRoomConfig(room, tunnelKeyHex, probeEvery, pongTimeout)
	for _, tweak := range tweaks {
		tweak(&cfg)
	}
	x.client = startRust(t, cfg, &x.clientLive)
	select {
	case x.socksAddr = <-x.client.listen:
	case <-x.client.exited:
		t.Fatalf("the rust client ended before it listened: %v", x.client.err)
	case <-time.After(30 * time.Second):
		t.Fatal("the rust client did not listen within 30 s")
	}
	eventually(t, 15*time.Second, "the client's session", func() bool { return x.client.opened.Load() == 1 })
	others := slices.DeleteFunc(room.Identities(), func(id string) bool { return id == x.serverID })
	if len(others) != 1 {
		t.Fatalf("the fake admitted %v beside the server %s, want the client alone", others, x.serverID)
	}
	x.clientID = others[0]
	return x
}

// checkStillUp is fakeTunnel.checkStillUp: the session the client opened
// has ended at neither end.
func (x *rustTunnel) checkStillUp(t *testing.T) {
	t.Helper()
	x.closedMu.Lock()
	closed := append([]string(nil), x.serverClosed...)
	x.closedMu.Unlock()
	if len(closed) > 0 {
		t.Fatalf("the server closed the client's session under bulk (reason %q)", closed[0])
	}
	c := x.client
	if c.reconnects.Load() > 0 || c.reopened.Load() > 0 || c.opened.Load() != 1 || x.engines.count() != 1 ||
		x.serverSessionsTotal.Load() != 1 || len(x.room.Identities()) != 2 {
		t.Fatalf("the client reconnected under bulk: %d reconnect lines, %d sessions opened and %d reopened, "+
			"%d server sessions, %d participants admitted", c.reconnects.Load(), c.opened.Load(), c.reopened.Load(),
			x.serverSessionsTotal.Load(), len(x.room.Identities()))
	}
}

// checkCapture fails the test if the fake tripped over a frame, or never saw
// the client answer the subscriber and offer the publisher.
func checkCapture(t *testing.T, room *salutejazz.FakeRoom) {
	t.Helper()
	if failure := room.LastError(); failure != "" {
		t.Fatalf("fake SFU error: %s", failure)
	}
	if !room.SawAnswer() || !room.SawPublisherOffer() {
		t.Fatalf("the fake saw answer=%v publisher offer=%v", room.SawAnswer(), room.SawPublisherOffer())
	}
}

// TestRustJoinsTheFakeRoomAsTheCaptureSays is the join and both lanes of a
// tunnel, with nothing slowed: the fake takes every frame the client sends
// (an empty lastError), both peer connections come up, a download and an
// upload move at once, both ends speak the relay window, and the client's
// candidates carry Chrome's 4-character ufrag.
func TestRustJoinsTheFakeRoomAsTheCaptureSays(t *testing.T) {
	room := salutejazz.NewFakeRoom(t)
	tunnel := startRustTunnel(t, room, 0, 0)
	down := startDownload(t, tunnel.socksAddr, startSource(t))
	up := startUpload(t, tunnel.socksAddr, startSink(t))
	const want = 4 << 20
	eventually(t, 30*time.Second, "4 MiB each way", func() bool { return down.moved() >= want && up.moved() >= want })
	for what, x := range map[string]*transfer{"download": down, "upload": up} {
		if bad := x.fault(); bad != nil {
			t.Fatalf("the %s: %v", what, bad)
		}
	}
	tunnel.checkStillUp(t)
	checkCapture(t, room)
	payloads, groups := room.Joins()
	for i, g := range groups {
		if g != "" {
			t.Fatalf("join %d carried group %q (payload %s)", i, g, payloads[i])
		}
	}
	t.Logf("joins: %v", payloads)
	targets, ufrags := room.ClientCandidates()
	chrome := 0
	for i, u := range ufrags {
		if len(u) == 4 {
			chrome++
		}
		t.Logf("candidate %d: target=%s ufrag=%q", i, targets[i], u)
	}
	if chrome == 0 {
		t.Fatalf("no candidate carried a 4-character ufrag: the rust client's are not Chrome's (%q)", ufrags)
	}
	if n := room.FramesFrom(tunnel.clientID, windowTopic); n == 0 {
		t.Fatalf("the client published no %s frame under bulk: it never spoke the relay window", windowTopic)
	}
	if n := room.FramesFrom(tunnel.serverID, windowTopic); n == 0 {
		t.Fatalf("the server published no %s frame: the client's window was never armed by its echo", windowTopic)
	}
	t.Logf("window frames: client %d, server %d", room.FramesFrom(tunnel.clientID, windowTopic),
		room.FramesFrom(tunnel.serverID, windowTopic))
	for _, line := range []string{iceConnectedLine, pcConnectedLine} {
		if !tunnel.client.logHas(line) {
			t.Fatalf("the client never said %q: the apps would not see the link come up", line)
		}
	}
}

// TestRustTunnelOnASlowLegKeepsItsControlStreamUnderBulk is
// TestATunnelOnASlowLegKeepsItsControlStreamUnderBulk with the Rust client.
func TestRustTunnelOnASlowLegKeepsItsControlStreamUnderBulk(t *testing.T) {
	room := salutejazz.NewFakeRoom(t)
	tunnel := startRustTunnel(t, room, tunnelProbeEvery, tunnelPongTimeout)
	room.SlowLeg(t, tunnel.serverID, tunnelLeg)
	room.SlowLeg(t, tunnel.clientID, tunnelLeg)

	down := startDownload(t, tunnel.socksAddr, startSource(t))
	up := startUpload(t, tunnel.socksAddr, startSink(t))
	eventually(t, 10*time.Second, "both transfers under way", func() bool {
		return down.moved() >= tunnelChunk && up.moved() >= tunnelChunk
	})
	watchFrom, downFrom, upFrom := time.Now(), down.moved(), up.moved()
	time.Sleep(tunnelWatch)
	watchTo, downTo, upTo := time.Now(), down.moved(), up.moved()

	tunnel.checkStillUp(t)
	pongBound := time.Duration(2*salutejazz.RelayWindowBound)*time.Second/tunnelLeg + time.Second
	tunnel.serverLive.check(t, "server", watchFrom, watchTo, pongBound)
	tunnel.clientLive.check(t, "client", watchFrom, watchTo, pongBound)

	watched := watchTo.Sub(watchFrom).Seconds()
	downRate, upRate := float64(downTo-downFrom)/watched, float64(upTo-upFrom)/watched
	t.Logf("in %s: download %.0f kB/s, upload %.0f kB/s on %d kB/s legs; the legs peaked at %d KiB to the client "+
		"and %d KiB to the server", tunnelWatch, downRate/1000, upRate/1000, tunnelLeg/1000,
		room.PeakQueuedTo(tunnel.clientID)>>10, room.PeakQueuedTo(tunnel.serverID)>>10)
	for _, moved := range []struct {
		what string
		rate float64
		bad  error
	}{{"download", downRate, down.fault()}, {"upload", upRate, up.fault()}} {
		if moved.bad != nil {
			t.Fatalf("the %s: %v", moved.what, moved.bad)
		}
		if moved.rate < tunnelLeg/4 {
			t.Fatalf("the %s moved %.0f kB/s, under a quarter of its %d kB/s leg",
				moved.what, moved.rate/1000, tunnelLeg/1000)
		}
	}
	for who, id := range map[string]string{"client": tunnel.clientID, "server": tunnel.serverID} {
		peak := room.PeakQueuedTo(id)
		if peak > salutejazz.RelayWindowBound {
			t.Fatalf("the leg to the %s held %d KiB, over the %d KiB a window allows",
				who, peak>>10, salutejazz.RelayWindowBound>>10)
		}
		if peak < salutejazz.RelayWindow/2 {
			t.Fatalf("the leg to the %s peaked at %d KiB, under half a %d KiB window: the bulk never queued "+
				"on it, so the tunnel did not run on a slow leg", who, peak>>10, salutejazz.RelayWindow>>10)
		}
	}
	checkCapture(t, room)
}

// TestRustSixPullsOnTheSlowestLegKeepTheirPongs is
// TestSixPullsOnTheSlowestLegKeepTheirPongs with the Rust client.
func TestRustSixPullsOnTheSlowestLegKeepTheirPongs(t *testing.T) {
	room := salutejazz.NewFakeRoom(t)
	tunnel := startRustTunnel(t, room, tunnelSlowProbeEvery, tunnelSlowPongTimeout)
	room.SlowLeg(t, tunnel.serverID, tunnelSlowestLeg)
	room.SlowLeg(t, tunnel.clientID, tunnelSlowestLeg)

	source := startSource(t)
	pulls := make([]*transfer, tunnelPulls)
	for i := range pulls {
		pulls[i] = startDownload(t, tunnel.socksAddr, source)
	}
	moved := func() int64 {
		var total int64
		for _, pull := range pulls {
			total += pull.moved()
		}
		return total
	}
	eventually(t, 20*time.Second, "the pulls under way", func() bool { return moved() >= tunnelChunk })
	time.Sleep(tunnelSettle)

	watchFrom, movedFrom := time.Now(), moved()
	peak := 0
	for end := watchFrom.Add(tunnelSlowWatch); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		peak = max(peak, room.QueuedTo(tunnel.clientID))
	}
	watchTo, movedTo := time.Now(), moved()

	tunnel.checkStillUp(t)
	record := time.Duration(salutejazz.SlowLegRecord) * time.Second / tunnelSlowestLeg
	pongBound := salutejazz.RelayHorizon + (2*tunnelPulls+1)*record + time.Second
	tunnel.serverLive.check(t, "server", watchFrom, watchTo, pongBound)
	tunnel.clientLive.check(t, "client", watchFrom, watchTo, pongBound)

	rate := float64(movedTo-movedFrom) / watchTo.Sub(watchFrom).Seconds()
	t.Logf("in %s: %d pulls moved %.1f kB/s on a %d kB/s leg; the leg to the client peaked at %d KiB",
		tunnelSlowWatch, tunnelPulls, rate/1000, tunnelSlowestLeg/1000, peak>>10)
	for i, pull := range pulls {
		if bad := pull.fault(); bad != nil {
			t.Fatalf("pull %d: %v", i, bad)
		}
	}
	if rate < tunnelSlowestLeg*3/4 {
		t.Fatalf("the pulls moved %.1f kB/s, under three quarters of their %d kB/s leg",
			rate/1000, tunnelSlowestLeg/1000)
	}
	if peak > salutejazz.RelayWindow*3/4 {
		t.Fatalf("the leg to the client held %d KiB under settled pulls, near the whole %d KiB window: "+
			"the window did not size itself for the leg", peak>>10, salutejazz.RelayWindow>>10)
	}
	checkCapture(t, room)
}

// TestRustRejoinsWhenTheConnectorDropsIt: the fake closes every socket
// without a close frame, as a dead link does. Both ends join again; the
// client's session comes back and carries a fresh download.
func TestRustRejoinsWhenTheConnectorDropsIt(t *testing.T) {
	room := salutejazz.NewFakeRoom(t)
	tunnel := startRustTunnel(t, room, time.Second, 4*time.Second)
	first := startDownload(t, tunnel.socksAddr, startSource(t))
	eventually(t, 10*time.Second, "the first download under way", func() bool { return first.moved() >= 1<<20 })
	room.DropAll()
	source := startSource(t)
	var again *transfer
	eventually(t, 60*time.Second, "a download after the drop", func() bool {
		if again == nil {
			conn, err := tryConnect(tunnel.socksAddr, source)
			if err != nil {
				time.Sleep(200 * time.Millisecond)
				return false
			}
			t.Cleanup(func() { _ = conn.Close() })
			again = &transfer{}
			go readPattern(conn, again)
		}
		return again.moved() >= 1<<20
	})
	if bad := again.fault(); bad != nil {
		t.Fatalf("the download after the drop: %v", bad)
	}
	if !tunnel.client.logHas(pcClosedLine) {
		t.Fatalf("the client never said %q when the connector dropped it: the apps would not restart", pcClosedLine)
	}
	t.Logf("after the drop: %d reconnect lines, %d sessions opened, %d reopened, %d participants admitted",
		tunnel.client.reconnects.Load(), tunnel.client.opened.Load(), tunnel.client.reopened.Load(),
		len(room.Identities()))
	if failure := room.LastError(); failure != "" {
		t.Fatalf("fake SFU error: %s", failure)
	}
}

// tryConnect is socksConnect that reports instead of failing the test.
func tryConnect(socksAddr, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp4", socksAddr)
	if err != nil {
		return nil, err
	}
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	request := append([]byte{5, 1, 0, 5, 1, 0, 1}, net.ParseIP(host).To4()...)
	request = append(request, byte(port>>8), byte(port))
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reply := make([]byte, 2+10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply[1] != 0 || reply[3] != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("refused: %v", reply)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// The fake-room server for the gate's fakeroom target.
const (
	// serveEnv switches TestServeFakeRoom on.
	serveEnv = "OLC_FAKE_ROOM_SERVE"
	// serveMarker opens the line that says where it listens, on stdout.
	serveMarker = "FAKE ROOM SERVER LISTENING ON "
	// serveLifetime bounds the server when the parent never closes stdin.
	serveLifetime = 70 * time.Minute
	// serveJoin is how long a room's Go server has to join.
	serveJoin = 15 * time.Second
)

// servedRoom is one fake room and the Go server in it.
type servedRoom struct {
	room     *salutejazz.FakeRoom
	engines  *madeEngines
	serverID string
	cancel   context.CancelFunc
	done     chan error

	mu     sync.Mutex
	closed []string
	opened int
}

// roomServer is TestServeFakeRoom's state.
type roomServer struct {
	t     *testing.T
	mu    sync.Mutex
	next  int
	rooms map[int]*servedRoom
}

// TestServeFakeRoom serves fake rooms over loopback HTTP until its stdin
// closes (the parent's end) or serveLifetime:
//
//	POST /open {"key","dns"}     a fresh fake room with a Go server holding
//	                             key in it: {"id","url","room","password","server"}
//	POST /close?id=N             the server stops, the room's participants end
//	GET  /state?id=N             {"last_error","identities","queued","peak",
//	                             "server_closed","server_opened"}
//	POST /slowleg?id=N&identity=X&rate=R, /dropall?id=N, /swallow?id=N&topic=T
//	                             the fake's hooks
func TestServeFakeRoom(t *testing.T) {
	if os.Getenv(serveEnv) != "1" {
		t.Skip(serveEnv + "=1 runs the fake-room server (the gate's fakeroom target starts it)")
	}
	// The fake skips without a host interface; let it do so here, on the
	// test's goroutine, not in a handler.
	salutejazz.NewFakeRoom(t).Shutdown()
	session.RegisterDefaults()
	s := &roomServer{t: t, rooms: make(map[int]*servedRoom)}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /open", s.open)
	mux.HandleFunc("POST /close", s.close)
	mux.HandleFunc("GET /state", s.state)
	mux.HandleFunc("POST /slowleg", s.hook(func(r *servedRoom, q map[string]string) error {
		rate, err := strconv.Atoi(q["rate"])
		if err != nil {
			return err
		}
		if !slices.Contains(r.room.Identities(), q["identity"]) {
			return fmt.Errorf("no participant %q", q["identity"])
		}
		r.room.SlowLeg(t, q["identity"], rate)
		return nil
	}))
	mux.HandleFunc("POST /dropall", s.hook(func(r *servedRoom, _ map[string]string) error {
		r.room.DropAll()
		return nil
	}))
	mux.HandleFunc("POST /swallow", s.hook(func(r *servedRoom, q map[string]string) error {
		r.room.Swallow(q["topic"])
		return nil
	}))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("%s%s\n", serveMarker, ln.Addr())
	stdin := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdin)
	}()
	select {
	case <-stdin:
	case <-time.After(serveLifetime):
		t.Errorf("served for %s without the parent closing stdin", serveLifetime)
	}
	_ = srv.Close()
	s.mu.Lock()
	rooms := make([]*servedRoom, 0, len(s.rooms))
	for _, r := range s.rooms {
		rooms = append(rooms, r)
	}
	s.mu.Unlock()
	for _, r := range rooms {
		r.stop()
	}
}

func (s *roomServer) open(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Key string `json:"key"`
		DNS string `json:"dns"`
	}
	if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.next++
	id := s.next
	s.mu.Unlock()
	room := salutejazz.NewFakeRoom(s.t)
	name := "salutejazz-fake-serve-" + strconv.Itoa(id)
	r := &servedRoom{room: room, engines: &madeEngines{}, done: make(chan error, 1)}
	enginebuiltin.Register(name, func(ctx context.Context, cfg enginebuiltin.Config) (engine.Session, error) {
		sess, err := salutejazz.New(ctx, room.Join(engine.Config{
			Name: cfg.Name, OnData: cfg.OnData, OnPeerData: cfg.OnPeerData,
			OnDatagram: cfg.OnDatagram, OnPeerDatagram: cfg.OnPeerDatagram,
			RequireTargetedPeer: cfg.RequireTargetedPeer,
		}))
		if err != nil {
			return nil, err
		}
		r.engines.add(sess.(*salutejazz.Session))
		return sess, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		r.done <- server.Run(ctx, server.Config{
			Transport: "datachannel", Provider: name, RoomURL: "room", KeyHex: body.Key,
			DNSServer: body.DNS, UnsafeAllowPrivateTargets: true,
			OnSessionOpen: func(string, string, map[string]any) {
				r.mu.Lock()
				defer r.mu.Unlock()
				r.opened++
			},
			OnSessionClose: func(_, reason string) {
				r.mu.Lock()
				defer r.mu.Unlock()
				r.closed = append(r.closed, reason)
			},
		})
	}()
	s.mu.Lock()
	s.rooms[id] = r
	s.mu.Unlock()
	deadline := time.Now().Add(serveJoin)
	for r.engines.count() == 0 || r.engines.at(0).LocalPeerID() == "" {
		if time.Now().After(deadline) {
			http.Error(w, "the server did not join within "+serveJoin.String(), http.StatusServiceUnavailable)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.serverID = r.engines.at(0).LocalPeerID()
	reply := map[string]any{
		"id": id, "url": room.URL(), "room": salutejazz.FakeRoomCode, "password": salutejazz.FakeRoomPassword,
		"server": r.serverID,
	}
	if os.Getenv(rustRelayEnv) == "1" {
		reply["relay_url"] = startTurnRelay(s.t, room.URL()).url
	}
	writeJSON(w, reply)
}

// stop ends the room's server and its participants, once.
func (r *servedRoom) stop() {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
	}
	r.room.Shutdown()
}

func (s *roomServer) find(req *http.Request) (*servedRoom, error) {
	id, err := strconv.Atoi(req.URL.Query().Get("id"))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[id]
	if r == nil {
		return nil, errors.New("no such room")
	}
	return r, nil
}

func (s *roomServer) close(w http.ResponseWriter, req *http.Request) {
	r, err := s.find(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	r.stop()
	writeJSON(w, r.snapshot())
}

func (s *roomServer) state(w http.ResponseWriter, req *http.Request) {
	r, err := s.find(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, r.snapshot())
}

func (r *servedRoom) snapshot() map[string]any {
	ids := r.room.Identities()
	queued, peak := map[string]int{}, map[string]int{}
	for _, id := range ids {
		queued[id], peak[id] = r.room.QueuedTo(id), r.room.PeakQueuedTo(id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"last_error": r.room.LastError(), "identities": ids, "server": r.serverID, "queued": queued, "peak": peak,
		"server_closed": append([]string{}, r.closed...), "server_opened": r.opened,
	}
}

func (s *roomServer) hook(apply func(*servedRoom, map[string]string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r, err := s.find(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		q := map[string]string{}
		for k, v := range req.URL.Query() {
			q[k] = v[0]
		}
		if err := apply(r, q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, r.snapshot())
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

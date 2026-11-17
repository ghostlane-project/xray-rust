//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T2 for the VK Calls
// carrier (M7.9). The fake VK Calls SFU (zz_fake_sfu_test.go) with the
// pinned Go server in a room of it (engine vkcalls on direct credentials,
// vp8channel, in this process) and the Rust client (olc-client, the same
// engine and transport) beside it as a child process:
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test -tags olcrtc_interop ./internal/engine/vkcalls -run '^TestRustVK' -v
//
//   - TestRustVKJoinsPublishesAndHearsTheServer: the join's frames, the
//     shaped answer, the two channels, the three producer commands and every
//     published packet are the engine's (the fake compares each with what
//     the engine's own functions write); the tunnel comes up over VP8 one
//     way and RED the other; a later offer is answered; the client leaves
//     with a hangup;
//   - TestRustVKKeepsItsMidAndRidAfterAReportWhereTheSlotNamesNoRTX: the
//     shape in which str0m alone would drop both after the first report;
//   - TestRustVKAsksForACameraThatCameLaterByItsKey: the client is alone
//     when it joins, so the server's camera is one it has to ask for;
//   - TestRustVKJoinsAgainWhenTheSFUDropsEveryone: every socket and media
//     leg goes; the client joins again from sequence 1 and the tunnel
//     reopens.
//
// No test reads a client's log for a room, a token or a participant: each
// holds the log to carrying none of them.

package vkcalls_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/openlibrecommunity/olcrtc/internal/engine/vkcalls"
	"github.com/openlibrecommunity/olcrtc/internal/server"
	"github.com/openlibrecommunity/olcrtc/internal/transport/vp8channel"
	"github.com/openlibrecommunity/olcrtc/internal/zzmem"
)

const (
	// rustBinEnv names the Rust client binary.
	rustBinEnv = "OLCRTC_GATE_RUST_BIN"
	// rustLifetime bounds every client process a test starts.
	rustLifetime = 5 * time.Minute
	// rustStopGrace is how long a stopped client has to say goodbye.
	rustStopGrace = 5 * time.Second
	// rustListenMarker is the line the client prints once its SOCKS5 front
	// listens, after its session opened: the tunnel is up.
	rustListenMarker = "SOCKS5 server listening on "
	// rustTraceEnv, set, logs every client's log whether or not its test
	// failed.
	rustTraceEnv = "OLCRTC_GATE_RUST_TRACE"
	// The app's vp8channel numbers.
	rustFPS   = 60
	rustBatch = 64
	// pion's state lines, which the apps read.
	pcConnectedLine = "peer connection state changed: connected"
	pcClosedLine    = "peer connection state changed: closed"
	memTopN         = 12
)

// rustKey is the tunnel's key: any 32 bytes, the server's and the client's.
var rustKey = strings.Repeat("6b", 32)

func rustBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(rustBinEnv)
	if bin == "" {
		t.Skip(rustBinEnv + " (the olc-client binary) is not set")
	}
	return bin
}

// rustConfig is what the Rust client reads (olc-client's config.rs), as far
// as a VK Calls join on direct credentials sets it.
type rustConfig struct {
	URL       string `json:"url"`
	Engine    string `json:"engine"`
	Key       string `json:"key"`
	Transport string `json:"transport"`
	Channel   string `json:"channel"`
	VP8FPS    int    `json:"vp8_fps"`
	VP8Batch  int    `json:"vp8_batch"`
	DNS       string `json:"dns"`
	Socks     string `json:"socks"`
	DeviceID  string `json:"device_id"`
	Debug     bool   `json:"debug"`
}

// rustVKConfig joins as the Go engine does on direct credentials: the
// signalling endpoint alone (no ICE servers: the SFU's candidates are in its
// offer).
func rustVKConfig(endpoint, channel string) rustConfig {
	return rustConfig{
		URL: endpoint, Engine: "vkcalls", Key: rustKey, Transport: "vp8channel", Channel: channel,
		VP8FPS: rustFPS, VP8Batch: rustBatch, DNS: "127.0.0.1:53", Socks: "127.0.0.1:0", DeviceID: "client-1",
		Debug: true,
	}
}

// rustProc is one run of the Rust client.
type rustProc struct {
	cmd     *exec.Cmd
	bin     string
	logPath string
	listen  chan string
	exited  chan struct{}
	cancel  context.CancelFunc

	reopened, reconnects atomic.Int64
	heapPeak, rssPeak    atomic.Int64
	hwm                  atomic.Int64
	memMu                sync.Mutex
	peakMem              zzmem.Peak
	stopOnce             sync.Once
}

// startRust runs the client on cfg until the test ends, and holds its log to
// carrying none of secrets. Its end is certain: the cleanup stops its
// process group and waits, Pdeathsig kills it with the test process, and its
// context carries rustLifetime.
func startRust(t *testing.T, cfg rustConfig, secrets func() []string) *rustProc {
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
	p := &rustProc{cmd: cmd, bin: bin, logPath: logFile.Name(), listen: make(chan string, 1),
		exited: make(chan struct{}), cancel: cancel}
	go func() {
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
			switch {
			case strings.Contains(line, " reopened (device="):
				p.reopened.Add(1)
			case strings.Contains(line, "client reconnect"):
				p.reconnects.Add(1)
			case strings.Contains(line, "heap now ") && strings.Contains(line, " peak "):
				if kib, ok := numberBefore(line, " peak ", " KiB"); ok {
					p.heapPeak.Store(kib)
				}
			}
		}
		_ = logFile.Close()
		_ = cmd.Wait()
		close(p.exited)
	}()
	go p.sample()
	t.Cleanup(func() {
		p.stop(t)
		log := p.log()
		if n := secretLines(log, append(secrets(), cfg.Key, cfg.URL)); n > 0 {
			t.Errorf("%d lines of the rust client's log carry the room, a token, a participant, the endpoint or the key", n)
		}
		t.Logf("rust client memory: VmHWM %d KiB, peak sampled VmRSS %d KiB, heap peak %d KiB",
			p.hwm.Load(), p.rssPeak.Load(), p.heapPeak.Load())
		p.memMu.Lock()
		t.Logf("rust client memory at peak RSS: %s", p.peakMem.Snap.Line(p.bin, memTopN))
		p.memMu.Unlock()
		if t.Failed() || os.Getenv(rustTraceEnv) != "" {
			t.Logf("rust client log, last lines:\n%s", scrubbed(tail(log, 80), append(secrets(), cfg.Key)))
		}
	})
	return p
}

// stop ends the client and waits for it, once.
func (p *rustProc) stop(t *testing.T) {
	t.Helper()
	p.stopOnce.Do(func() {
		p.hwm.Store(procStatusKB(p.cmd.Process.Pid, "VmHWM:"))
		p.cancel()
		select {
		case <-p.exited:
		case <-time.After(rustStopGrace + 5*time.Second):
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			t.Errorf("the rust client was still running %s after its stop", rustStopGrace+5*time.Second)
		}
	})
}

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

func (p *rustProc) log() string {
	raw, _ := os.ReadFile(p.logPath)
	return string(raw)
}

func (p *rustProc) logHas(text string) bool { return strings.Contains(p.log(), text) }

// up waits for the client's tunnel.
func (p *rustProc) up(t *testing.T, room *vkcalls.FakeVKRoom) {
	t.Helper()
	select {
	case <-p.listen:
	case <-p.exited:
		t.Fatalf("the rust client ended before its tunnel came up; the room: %+v", room.State())
	case <-time.After(60 * time.Second):
		t.Fatalf("the rust client's tunnel did not come up within 60 s; the room: %+v", room.State())
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

func tail(log string, n int) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// secretLines is how many lines of log hold one of secrets. It says how
// many, never which or what.
func secretLines(log string, secrets []string) int {
	n := 0
	for _, line := range strings.Split(log, "\n") {
		if slices.ContainsFunc(secrets, func(s string) bool { return s != "" && strings.Contains(line, s) }) {
			n++
		}
	}
	return n
}

// scrubbed is text with every secret taken out: what a failed test may show.
func scrubbed(text string, secrets []string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "<withheld>")
		}
	}
	return text
}

// TestRustVKLogSecretCheck holds secretLines and scrubbed to what they name;
// it needs no client binary.
func TestRustVKLogSecretCheck(t *testing.T) {
	secrets := []string{"0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef-aabbccddeeff0011",
		"123456789012", ""}
	for _, c := range []struct {
		log  string
		want int
	}{
		{"vkcalls: connected, 1 other participants\nvkcalls: peer connection connected\n", 0},
		{"vkcalls: signaling url /ws?conversationId=<r>&token=<r>&userId=<r>\n", 0},
		{"dial ws://127.0.0.1:1/ws?conversationId=0123456789abcdef0123456789abcdef\n", 1},
		{"a\ntoken=0123456789abcdef0123456789abcdef-aabbccddeeff0011\nb\nuserId=123456789012 joined\n", 2},
		{"participant 123456789012 and 123456789012 again\n", 1},
	} {
		if got := secretLines(c.log, secrets); got != c.want {
			t.Errorf("secretLines(%q) = %d, want %d", c.log, got, c.want)
		}
	}
	if got := scrubbed("userId=123456789012 in 0123456789abcdef0123456789abcdef", secrets); got != "userId=<withheld> in <withheld>" {
		t.Errorf("scrubbed = %q", got)
	}
}

var registerOnce sync.Once

// goServer runs the pinned Go server in the room at endpoint until the test
// ends: engine vkcalls on direct credentials, vp8channel at the app's
// numbers.
func goServer(t *testing.T, endpoint, channel string) {
	t.Helper()
	registerOnce.Do(session.RegisterDefaults)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Run(ctx, server.Config{
			Transport: "vp8channel", Provider: "none", Engine: "vkcalls", URL: endpoint, ChannelID: channel,
			KeyHex: rustKey, DNSServer: "127.0.0.1:53", UnsafeAllowPrivateTargets: true,
			TransportOptions: vp8channel.Options{FPS: rustFPS, BatchSize: rustBatch},
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("the Go server was still running 20 s after its stop")
		}
	})
}

// newRoom is a room of a fresh fake, with a channel for the two ends.
func newRoom(t *testing.T) (*vkcalls.FakeVKRoom, string) {
	t.Helper()
	return newRoomOf(t, (*vkcalls.FakeVK).Open)
}

// newRoomOf is newRoom with the room opened by open.
func newRoomOf(t *testing.T, open func(*vkcalls.FakeVK) *vkcalls.FakeVKRoom) (*vkcalls.FakeVKRoom, string) {
	t.Helper()
	sfu, err := vkcalls.NewFakeVK()
	if err != nil {
		t.Skipf("the fake needs a host interface and a loopback listener: %v", err)
	}
	t.Cleanup(sfu.Close)
	room := open(sfu)
	t.Cleanup(func() {
		// What a client said on its way out (its hangup) has been read.
		time.Sleep(200 * time.Millisecond)
		st := room.State()
		if len(st.Errors) != 0 {
			t.Errorf("the fake tripped:\n %s", strings.Join(st.Errors, "\n "))
		}
		if t.Failed() {
			raw, _ := json.MarshalIndent(st.Legs, " ", " ")
			t.Logf("the room's legs:\n %s", scrubbed(string(raw), room.Secrets()))
		}
	})
	return room, strings.Repeat("c0ffee", 2)
}

func within(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %s", limit, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// legs are the legs of role, in the order they came.
func legs(room *vkcalls.FakeVKRoom, role string) []vkcalls.FakeVKLeg {
	var out []vkcalls.FakeVKLeg
	for _, l := range room.State().Legs {
		if l.Role == role {
			out = append(out, l)
		}
	}
	return out
}

// last is the newest leg of role, or an empty one.
func last(room *vkcalls.FakeVKRoom, role string) vkcalls.FakeVKLeg {
	if all := legs(room, role); len(all) > 0 {
		return all[len(all)-1]
	}
	return vkcalls.FakeVKLeg{}
}

// serverJoined waits for the Go server's leg to publish.
func serverJoined(t *testing.T, room *vkcalls.FakeVKRoom) {
	t.Helper()
	within(t, 45*time.Second, "the Go server joining the fake and publishing", func() bool {
		leg := last(room, "server")
		return leg.Up && leg.Simulcast == 1 && leg.Packets > 0
	})
}

// The whole join beside the Go server.
func TestRustVKJoinsPublishesAndHearsTheServer(t *testing.T) {
	rustBin(t)
	room, channel := newRoom(t)
	goServer(t, room.Guest("server"), channel)
	serverJoined(t, room)
	p := startRust(t, rustVKConfig(room.Guest("rust"), channel), room.Secrets)

	// The tunnel is up: the handshake went out as VP8 on the publish slot
	// and came back wrapped in RED on a receive slot, through the fake.
	p.up(t, room)
	within(t, 20*time.Second, "a perf report, packets after a receiver report, a pong and media both ways", func() bool {
		rust, srv := last(room, "rust"), last(room, "server")
		return rust.Perf > 0 && rust.AfterReport > 0 && rust.Pongs > 0 && rust.Forwarded > 0 && srv.Forwarded > 0
	})
	if !p.logHas(pcConnectedLine) {
		t.Errorf("the client's log has no %q", pcConnectedLine)
	}

	// A later offer is answered on the same connection, and media goes on.
	if n := room.Reoffer(); n != 2 {
		t.Fatalf("%d legs were offered again, want the server's and the client's", n)
	}
	within(t, 15*time.Second, "the client answering the later offer", func() bool {
		return last(room, "rust").Answers == 2 && last(room, "server").Answers == 2
	})
	before := last(room, "rust")
	within(t, 10*time.Second, "media both ways after the later offer", func() bool {
		now := last(room, "rust")
		return now.Forwarded > before.Forwarded && now.Packets > before.Packets
	})

	// The client leaves: a hangup, then the socket.
	p.stop(t)
	within(t, 10*time.Second, "the client's hangup", func() bool { return last(room, "rust").Hangup })
	if !p.logHas(pcClosedLine) {
		t.Errorf("the client's log has no %q after its stop", pcClosedLine)
	}

	mine := legs(room, "rust")
	if len(mine) != 1 {
		t.Fatalf("%d legs of the client, want one join", len(mine))
	}
	leg := mine[0]
	want := []string{"allocate-consumer", "update-media-modifiers", "change-media-settings", "accept-producer",
		"accept-producer", "hangup"}
	if !slices.Equal(leg.Commands, want) {
		t.Errorf("commands %q, want %q", leg.Commands, want)
	}
	if leg.Channels["producerNotification"] != 0 || leg.Channels["producerCommand"] != 2 || len(leg.Channels) != 2 {
		t.Errorf("channels %v, want producerNotification on stream 0 and producerCommand on 2", leg.Channels)
	}
	if leg.Simulcast != 1 || leg.Layouts == 0 || leg.Perf == 0 {
		t.Errorf("the three producer commands: change-simulcast %d, layouts %d, perf reports %d",
			leg.Simulcast, leg.Layouts, leg.Perf)
	}
	if len(leg.LastLayout) != 1 || leg.LastLayout[0] != "#0" {
		t.Errorf("the last layout names %q, want the server's camera by its compact id", leg.LastLayout)
	}
	if leg.Packets == 0 || leg.AfterReport == 0 || leg.Sources != 1 {
		t.Errorf("published: %d packets, %d after a receiver report, %d SSRCs", leg.Packets, leg.AfterReport, leg.Sources)
	}
	t.Logf("the client's leg: %d published packets (%d after the first of %d receiver reports), %d resent, "+
		"%d forwarded to it, %d layouts, %d perf reports, %d pongs", leg.Packets, leg.AfterReport, leg.Reports,
		leg.RTX, leg.Forwarded, leg.Layouts, leg.Perf, leg.Pongs)
}

// A publish slot that names no RTX for VP8. str0m stops writing a stream's
// mid and rid once a receiver report names its SSRC (with RTX it waits for a
// report on the RTX SSRC, which this fake never sends), and the SFU binds
// the stream by them and is never told an SSRC: the client keeps both on
// every packet by the vendored patch (olc-rtc: keep_mid_rid). The fake
// reports every second and trips over a packet without them; the server
// goes on hearing the client long after the first report.
func TestRustVKKeepsItsMidAndRidAfterAReportWhereTheSlotNamesNoRTX(t *testing.T) {
	rustBin(t)
	room, channel := newRoomOf(t, (*vkcalls.FakeVK).OpenNoRTX)
	goServer(t, room.Guest("server"), channel)
	serverJoined(t, room)
	p := startRust(t, rustVKConfig(room.Guest("rust"), channel), room.Secrets)
	p.up(t, room)
	within(t, 20*time.Second, "three receiver reports and fifty packets after the first", func() bool {
		leg := last(room, "rust")
		return leg.Reports >= 3 && leg.AfterReport >= 50
	})
	before := last(room, "server").Forwarded
	within(t, 10*time.Second, "the server still hearing the client after the reports", func() bool {
		return last(room, "server").Forwarded > before+20
	})
	leg := last(room, "rust")
	if leg.RTX != 0 || leg.OtherPT != 0 {
		t.Errorf("%d packets at the RTX payload type the slot does not name, %d at another", leg.RTX, leg.OtherPT)
	}
	t.Logf("the client's leg: %d published packets, %d after the first of %d receiver reports", leg.Packets,
		leg.AfterReport, leg.Reports)
}

// The client is alone when it joins: no registry frame names the server's
// camera, which comes later, so the client asks for it by its string key and
// subscribes by the compact id the answer gives.
func TestRustVKAsksForACameraThatCameLaterByItsKey(t *testing.T) {
	rustBin(t)
	room, channel := newRoom(t)
	p := startRust(t, rustVKConfig(room.Guest("rust"), channel), room.Secrets)
	within(t, 45*time.Second, "the client joining an empty room and publishing", func() bool {
		leg := last(room, "rust")
		return leg.Up && leg.Simulcast == 1 && leg.Packets > 0
	})
	if leg := last(room, "rust"); leg.Layouts != 0 {
		t.Errorf("%d layouts in a room with nobody to subscribe to", leg.Layouts)
	}
	goServer(t, room.Guest("server"), channel)
	p.up(t, room)
	asks := 0
	for _, leg := range legs(room, "rust") {
		asks += leg.KeyAsks
	}
	if asks == 0 {
		t.Error("the client never asked for the later camera by its key")
	}
	within(t, 10*time.Second, "the client subscribed by the compact id", func() bool {
		leg := last(room, "rust")
		return len(leg.LastLayout) == 1 && leg.LastLayout[0] == "#0" && leg.Forwarded > 0
	})
}

// Every socket and media leg of the room goes at once, without a goodbye.
// The client joins again as the same guest, from sequence 1, and the tunnel
// reopens.
func TestRustVKJoinsAgainWhenTheSFUDropsEveryone(t *testing.T) {
	rustBin(t)
	room, channel := newRoom(t)
	goServer(t, room.Guest("server"), channel)
	serverJoined(t, room)
	p := startRust(t, rustVKConfig(room.Guest("rust"), channel), room.Secrets)
	p.up(t, room)
	within(t, 10*time.Second, "media both ways", func() bool {
		return last(room, "rust").Forwarded > 0 && last(room, "server").Forwarded > 0
	})

	room.Drop()
	within(t, 90*time.Second, "the client and the server joined again, media both ways", func() bool {
		rust, srv := legs(room, "rust"), legs(room, "server")
		if len(rust) < 2 || len(srv) < 2 {
			return false
		}
		r, s := rust[len(rust)-1], srv[len(srv)-1]
		return r.Up && s.Up && r.Forwarded > 0 && s.Forwarded > 0 && r.Simulcast == 1
	})
	within(t, 60*time.Second, "the tunnel reopening", func() bool { return p.reopened.Load() > 0 })
	first := legs(room, "rust")[0]
	if !first.Ended {
		t.Error("the client's first leg is still there")
	}
	t.Logf("the client joined %d times; reconnects said %d, reopened %d", len(legs(room, "rust")),
		p.reconnects.Load(), p.reopened.Load())
}

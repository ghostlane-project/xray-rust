// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's vkfake
// target, T2 for the VK Calls carrier (M7.9). Each cell's server is the
// pinned Go server (engine vkcalls on direct credentials, vp8channel) in a
// fresh room of the fake VK Calls SFU (internal/engine/vkcalls,
// zz_fake_sfu_test.go), which TestServeFakeVKSFU serves from a child process
// this test starts; the client joins the same room as another guest, so
// every byte of the tunnel goes out as VP8 on a publish slot and comes back
// wrapped in RED on a receive slot:
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestGateRustVKFake$' \
//	    -olcrtc.gate-target=vkfake -olcrtc.gate-rust-bin=<olc-client> \
//	    [-olcrtc.gate-flavours=rust,cli]
//
// The rust flavour is the Rust client with engine vkcalls; the cli flavour
// is the Go client in the same fake, the baseline, a child process of its
// own (zz_go_child_test.go). A run passes only
// if the fake tripped in none of its rooms (every frame, answer, producer
// command and published packet of every guest was the engine's), every
// client that connected sent its three producer commands, and no line a
// client logged carries a room, a guest's token or a participant.

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

const (
	platformVKFake = "vkfake-linux"
	// vkFakeServeMarker is TestServeFakeVKSFU's listening line, and
	// vkFakeServeEnv what switches it on.
	vkFakeServeMarker = "FAKE VK SFU HOOKS LISTENING ON "
	vkFakeServeEnv    = "OLC_FAKE_VK_SFU_SERVE"
	// vkFakeServeLifetime bounds the serving process.
	vkFakeServeLifetime = 70 * time.Minute
	// vkFakeEngine is the engine both ends join with.
	vkFakeEngine = "vkcalls"
)

// vkFakeLeg is one socket of a room as the fake saw it (FakeVKLeg).
type vkFakeLeg struct {
	Role        string   `json:"role"`
	Commands    []string `json:"commands"`
	Answers     int      `json:"answers"`
	Hangup      bool     `json:"hangup"`
	Up          bool     `json:"up"`
	Simulcast   int      `json:"simulcast"`
	Layouts     int      `json:"layouts"`
	KeyAsks     int      `json:"key_asks"`
	Perf        int      `json:"perf"`
	Packets     int      `json:"packets"`
	AfterReport int      `json:"after_report"`
	Reports     int      `json:"reports"`
	RTX         int      `json:"rtx"`
	Lost        int      `json:"lost"`
	Forwarded   int      `json:"forwarded"`
	Stalled     int      `json:"stalled"`
	Pongs       int      `json:"pongs"`
}

// vkFakeState is a room as the fake saw it.
type vkFakeState struct {
	Errors  []string    `json:"errors"`
	Legs    []vkFakeLeg `json:"legs"`
	Secrets []string    `json:"secrets"`
}

// vkFakeEnd is one room as it ended.
type vkFakeEnd struct {
	room   string
	state  vkFakeState
	err    error
	srvHWM int64 // the Go server's VmHWM, KiB
}

// VKFakeTarget is the Go server in a room of the fake SFU.
type VKFakeTarget struct {
	base    string // the serving process's http://addr
	builder *InteropTarget
	origin  *Origin

	mu      sync.Mutex
	rooms   map[string]string // room id by room URL
	secrets map[string]string // what no client line may carry, and what kind it is
	ended   []vkFakeEnd
}

// Name implements Target.
func (t *VKFakeTarget) Name() string { return targetVKFake }

// Platform implements Target.
func (t *VKFakeTarget) Platform() string { return platformVKFake }

// Pairs implements Target: VK Calls, vp8channel.
func (t *VKFakeTarget) Pairs() []Pair { return []Pair{{providerVKCalls, transportVP8}} }

// Load implements Target.
func (t *VKFakeTarget) Load() LoadURLs { return t.origin.URLs }

func (t *VKFakeTarget) call(ctx context.Context, method, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, t.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fake vk %s: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fake vk %s: %s", strings.SplitN(path, "?", 2)[0], resp.Status)
	}
	return json.Unmarshal(raw, out)
}

// keep notes what no client line may carry.
func (t *VKFakeTarget) keep(kind, secret string) {
	if secret == "" {
		return
	}
	t.mu.Lock()
	t.secrets[secret] = kind
	t.mu.Unlock()
}

// guest makes a participant of the room at roomURL and returns its
// signalling endpoint.
func (t *VKFakeTarget) guest(ctx context.Context, roomURL, role string) (string, error) {
	t.mu.Lock()
	id, ok := t.rooms[roomURL]
	t.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("fake vk: no served room at that URL")
	}
	var made struct {
		URL string `json:"url"`
	}
	if err := t.call(ctx, http.MethodPost, "/guest?room="+id+"&role="+role, &made); err != nil {
		return "", err
	}
	u, err := url.Parse(made.URL)
	if err != nil {
		return "", fmt.Errorf("fake vk: a guest's endpoint does not parse")
	}
	t.keep("a guest's endpoint", made.URL)
	t.keep("a guest's token", u.Query().Get("token"))
	t.keep("a participant", u.Query().Get("userId"))
	return made.URL, nil
}

// Open implements Target: a fresh room of the fake, the server joined to it
// as a guest of its own.
func (t *VKFakeTarget) Open(ctx context.Context, p Pair, dir string, opt OpenOptions) (Endpoint, func(), error) {
	key, err := NewKey()
	if err != nil {
		return Endpoint{}, nil, err
	}
	channel, err := NewChannel()
	if err != nil {
		return Endpoint{}, nil, err
	}
	var room struct {
		Room string `json:"room"`
		URL  string `json:"url"`
	}
	if err := t.call(ctx, http.MethodPost, "/open", &room); err != nil {
		return Endpoint{}, nil, err
	}
	t.mu.Lock()
	t.rooms[room.URL] = room.Room
	t.mu.Unlock()
	t.keep("a room", room.Room)
	closeRoom := func(srvHWM int64) {
		var st vkFakeState
		err := t.call(context.Background(), http.MethodPost, "/close?room="+room.Room, &st)
		t.mu.Lock()
		t.ended = append(t.ended, vkFakeEnd{room: room.Room, state: st, err: err, srvHWM: srvHWM})
		t.mu.Unlock()
	}
	ep := Endpoint{Provider: p.Provider, Transport: p.Transport, Room: room.URL, Channel: channel, Key: key,
		DNS: defaultDNS, VP8FPS: p2pFPS, VP8Batch: p2pBatch}
	endpoint, err := t.guest(ctx, room.URL, "server")
	if err != nil {
		closeRoom(0)
		return Endpoint{}, nil, err
	}
	binary, err := t.builder.build(ctx)
	if err != nil {
		closeRoom(0)
		return Endpoint{}, nil, err
	}
	srv, err := startServer(ctx, binary, t.builder.work, vkFakeServerConfig(ep, endpoint), opt)
	if err != nil {
		closeRoom(0)
		return Endpoint{}, nil, err
	}
	u, _ := url.Parse(endpoint)
	secrets := append(ep.Secrets(), endpoint, room.Room)
	if u != nil {
		secrets = append(secrets, u.Query().Get("token"), u.Query().Get("userId"))
	}
	config := filepath.Join(srv.dir, "srv.yaml")
	stop := sync.OnceFunc(func() {
		hwm := procStatusKB(vkFakePidOf(config), "VmHWM:")
		srv.stop(filepath.Join(dir, serverLogName), secrets)
		closeRoom(hwm)
	})
	if err := waitForLine(srv.log, linkedLine, linkBudget, srv.exited); err != nil {
		tail := clip(Scrub(lastLine(srv.log), secrets...))
		stop()
		return Endpoint{}, nil, fmt.Errorf("%w; last server line: %s", err, tail)
	}
	return ep, stop, nil
}

// vkFakePidOf is the process whose command line names path (the server,
// run on its config), or 0.
func vkFakePidOf(path string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && bytes.Contains(raw, []byte(path)) {
			return pid
		}
	}
	return 0
}

// vkFakeServerConfig is the mode: srv YAML of the pair: engine vkcalls on
// the guest's signalling endpoint as given (provider none), the room's
// channel, the app's vp8channel numbers.
func vkFakeServerConfig(ep Endpoint, endpoint string) string {
	return strings.Join([]string{
		"mode: srv", "auth: { provider: none }",
		"engine: { name: " + vkFakeEngine + ", url: " + strconv.Quote(endpoint) + " }",
		"room: { channel: " + strconv.Quote(ep.Channel) + " }",
		"crypto: { key: " + strconv.Quote(ep.Key) + " }",
		"net: { transport: " + ep.Transport + ", dns: " + strconv.Quote(ep.DNS) + " }",
		fmt.Sprintf("vp8: { fps: %d, batch_size: %d }", ep.VP8FPS, ep.VP8Batch),
		"udp: { enabled: true }", "debug: true",
	}, "\n") + "\n"
}

// goVKFakeClient is the Go public client in a served room, inside this
// process: the baseline as it was, kept behind -olcrtc.gate-go-inproc.
type goVKFakeClient struct {
	target *VKFakeTarget
	cli    cliClient
}

// Name implements Client.
func (goVKFakeClient) Name() string { return cliFlavour }

// Start implements Client.
func (g goVKFakeClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	endpoint, err := g.target.guest(ctx, ep.Room, cliFlavour)
	if err != nil {
		return nil, fmt.Errorf("go client: %w", err)
	}
	cfg := client.Config{
		Transport: ep.Transport, Provider: "none", Engine: vkFakeEngine, URL: endpoint, ChannelID: ep.Channel,
		KeyHex: ep.Key, LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
		TransportOptions: client.VP8Options{FPS: ep.VP8FPS, BatchSize: ep.VP8Batch},
	}
	cli := g.cli
	cli.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return cli.Start(ctx, ep)
}

// vkFakeWatch reads every line a client logs on its way to the cell's
// capture: how many carry something of a room that no log may, by kind, and
// the highest heap peak a Rust client said (a build with heap-stats says
// "heap now N KiB peak N KiB").
type vkFakeWatch struct {
	inner  io.Writer
	target *VKFakeTarget

	mu       sync.Mutex
	leaks    map[string]int
	lines    int
	heapPeak int64
}

// Write implements io.Writer.
func (w *vkFakeWatch) Write(p []byte) (int, error) {
	w.target.mu.Lock()
	secrets := make(map[string]string, len(w.target.secrets))
	for s, kind := range w.target.secrets {
		secrets[s] = kind
	}
	w.target.mu.Unlock()
	w.mu.Lock()
	for _, line := range strings.Split(string(p), "\n") {
		if line == "" {
			continue
		}
		w.lines++
		for s, kind := range secrets {
			if strings.Contains(line, s) {
				w.leaks[kind]++
			}
		}
		if _, rest, ok := strings.Cut(line, "heap now "); ok {
			if _, peak, ok := strings.Cut(rest, " peak "); ok {
				if n, err := strconv.ParseInt(strings.Fields(peak + " ")[0], 10, 64); err == nil && n > w.heapPeak {
					w.heapPeak = n
				}
			}
		}
	}
	w.mu.Unlock()
	return w.inner.Write(p)
}

// TestVKFakeWatchCountsWhatALogMustNotCarry holds the watch to what it
// names; it starts nothing.
func TestVKFakeWatchCountsWhatALogMustNotCarry(t *testing.T) {
	target := &VKFakeTarget{secrets: map[string]string{}}
	target.keep("a room", "0123456789abcdef0123456789abcdef")
	target.keep("a guest's token", "0123456789abcdef0123456789abcdef-aabbccddeeff0011")
	target.keep("a participant", "123456789012")
	target.keep("nothing", "")
	w := &vkFakeWatch{inner: io.Discard, target: target, leaks: map[string]int{}}
	for _, line := range []string{
		"vkcalls: connected, 1 other participants\n",
		"vkcalls: signaling url /ws?conversationId=<r>&token=<r>&userId=<r>\n",
		"heap now 1200 KiB peak 2345 KiB\nheap now 900 KiB peak 2100 KiB\n",
		"dial ws://127.0.0.1:1/ws?conversationId=0123456789abcdef0123456789abcdef\n",
		"guest 123456789012 joined\nguest 123456789012 left\n",
		"token=0123456789abcdef0123456789abcdef-aabbccddeeff0011\n",
	} {
		if n, err := w.Write([]byte(line)); err != nil || n != len(line) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	want := map[string]int{"a room": 2, "a guest's token": 1, "a participant": 2}
	if len(w.leaks) != len(want) {
		t.Errorf("leaks %v, want %v", w.leaks, want)
	}
	for kind, n := range want {
		if w.leaks[kind] != n {
			t.Errorf("%d lines with %s, want %d", w.leaks[kind], kind, n)
		}
	}
	if w.heapPeak != 2345 || w.lines != 8 {
		t.Errorf("heap peak %d of %d lines, want 2345 of 8", w.heapPeak, w.lines)
	}
}

// startVKFakeServer builds the vkcalls test binary and runs
// TestServeFakeVKSFU in it until the test ends: its stdin closes then (the
// server's signal to stop), its group is killed after a grace, Pdeathsig
// kills it with the test process, and its context carries the lifetime.
func startVKFakeServer(t *testing.T, root, dir string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "vkcalls.test")
	build := exec.Command("go", "test", "-c", "-tags", "olcrtc_interop", "-o", bin, "./internal/engine/vkcalls")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the fake VK SFU: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), vkFakeServeLifetime)
	cmd := exec.CommandContext(ctx, bin, "-test.run", "^TestServeFakeVKSFU$", "-test.v",
		"-test.timeout", (vkFakeServeLifetime + time.Minute).String())
	cmd.Env = append(os.Environ(), vkFakeServeEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = stopGrace
	logFile, err := os.OpenFile(filepath.Join(dir, "vkfake-sfu.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	cmd.Stderr = logFile
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	exited, lines := make(chan struct{}), make(chan struct{})
	addr := make(chan string, 1)
	go func() {
		defer close(lines)
		buf := make([]byte, 64<<10)
		said, pending := false, ""
		for {
			n, err := stdout.Read(buf)
			pending += string(buf[:n])
			for {
				line, rest, ok := strings.Cut(pending, "\n")
				if !ok {
					break
				}
				pending = rest
				if at, found := strings.CutPrefix(line, vkFakeServeMarker); found && !said {
					said = true
					addr <- strings.TrimSpace(at)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		<-lines
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			t.Errorf("the fake VK SFU was still running 30 s after its stdin closed")
		}
		cancel()
		<-exited
	})
	select {
	case a := <-addr:
		return "http://" + a
	case <-exited:
		t.Fatal("the fake VK SFU ended before it listened")
	case <-time.After(120 * time.Second):
		t.Fatal("the fake VK SFU did not listen within 120 s")
	}
	return ""
}

// TestGateRustVKFake is the gate on the vkfake target.
func TestGateRustVKFake(t *testing.T) {
	if *gateTargetName != targetVKFake {
		t.Skip("the fake VK Calls gate runs with -olcrtc.gate-target=vkfake")
	}
	root := moduleRoot(t)
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, targetVKFake)
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	target := &VKFakeTarget{
		base: startVKFakeServer(t, root, dir), builder: &InteropTarget{root: root, work: t.TempDir()},
		origin: startOrigin(t), rooms: map[string]string{}, secrets: map[string]string{},
	}

	registryMu.Lock()
	saved := registry
	registry = rtcScenarios(saved)
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})

	var clients []Client
	for _, name := range splitList(*gateFlavours) {
		switch name {
		case rustFlavour:
			clients = append(clients, rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
				extra: func(cfg *rustConfig) {
					endpoint, err := target.guest(context.Background(), cfg.URL, rustFlavour)
					if err != nil {
						t.Logf("rust client: %v", err)
						return
					}
					// Debug on: the secret check reads the client's debug
					// lines too (the socket's URL is said in one).
					cfg.URL, cfg.Engine, cfg.Debug = endpoint, vkFakeEngine, true
				}})
		case cliFlavour:
			inproc := goVKFakeClient{target: target, cli: cliClient{start: startBudget, stop: stopBudget}}
			clients = append(clients, goBaseline(t, root, inproc,
				func(ctx context.Context, ep Endpoint) (goJoin, error) {
					endpoint, err := target.guest(ctx, ep.Room, cliFlavour)
					return goJoin{Engine: vkFakeEngine, URL: endpoint}, err
				}))
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
	rec := NewRecorder(Report{Target: targetVKFake, Runner: runnerName()})
	capture := StartCapture()
	defer capture.Stop()
	watch := &vkFakeWatch{inner: log.Writer(), target: target, leaks: map[string]int{}}
	log.SetOutput(watch)
	defer log.SetOutput(watch.inner)
	secrets := []string{}
	opt := Options{
		Target: target, Clients: clients, Thresholds: Local, Dir: dir, Recorder: rec, Capture: capture,
		Secrets: &secrets, Logf: t.Logf, ReportPath: filepath.Join(dir, reportName),
	}
	RunPlan(runContext(t), opt, func(name string, cell func() error) {
		t.Run(name, func(t *testing.T) {
			if err := cell(); err != nil {
				t.Error(err)
			}
		})
	})
	rep := rec.Report()
	for _, c := range rep.Cells {
		raw, _ := json.Marshal(c.Metrics)
		t.Logf("cell %s: %s %s %q", c.ID, c.Status, raw, c.Failures)
	}
	for _, id := range unreported(rep) {
		t.Errorf("%s: %s", id, reasonDidNotRun)
	}
	if why := gateFailure(rep); why != "" {
		t.Errorf("gate: %s; the report goes to %s", why, opt.ReportPath)
	}

	// The rooms as the fake saw them.
	target.mu.Lock()
	ended := append([]vkFakeEnd(nil), target.ended...)
	target.mu.Unlock()
	if len(ended) == 0 {
		t.Error("no room was opened and closed")
	}
	total := map[string]*vkFakeLeg{}
	joined := map[string]int{}
	var srvHWM int64
	for i, e := range ended {
		if e.err != nil {
			t.Errorf("room %d: closing it: %v", i+1, e.err)
			continue
		}
		srvHWM = max(srvHWM, e.srvHWM)
		for _, why := range e.state.Errors {
			t.Errorf("room %d: the fake tripped: %s", i+1, Scrub(why, e.state.Secrets...))
		}
		for _, leg := range e.state.Legs {
			if !leg.Up {
				continue
			}
			joined[leg.Role]++
			sum := total[leg.Role]
			if sum == nil {
				sum = &vkFakeLeg{}
				total[leg.Role] = sum
			}
			sum.Simulcast += leg.Simulcast
			sum.Layouts += leg.Layouts
			sum.KeyAsks += leg.KeyAsks
			sum.Perf += leg.Perf
			sum.Packets += leg.Packets
			sum.AfterReport += leg.AfterReport
			sum.Reports += leg.Reports
			sum.RTX += leg.RTX
			sum.Lost += leg.Lost
			sum.Forwarded += leg.Forwarded
			sum.Stalled += leg.Stalled
			sum.Pongs += leg.Pongs
			sum.Answers += leg.Answers
			if leg.Hangup {
				sum.Commands = append(sum.Commands, "hangup")
			}
			if leg.Simulcast != 1 {
				t.Errorf("room %d: a %s leg that connected sent change-simulcast %d times", i+1, leg.Role, leg.Simulcast)
			}
		}
	}
	for role, sum := range total {
		t.Logf("%s in the fake: %d connected legs in %d rooms, %d hangups; change-simulcast %d, layouts %d (%d by key), "+
			"perf reports %d; published %d packets, every one with its mid and rid (%d after a receiver report, %d reports), "+
			"%d resent, %d lost on the way to the fake; forwarded to it %d as RED, %d withheld for want of a perf report; %d pongs",
			role, joined[role], len(ended), len(sum.Commands), sum.Simulcast, sum.Layouts, sum.KeyAsks, sum.Perf,
			sum.Packets, sum.AfterReport, sum.Reports, sum.RTX, sum.Lost, sum.Forwarded, sum.Stalled, sum.Pongs)
	}
	for _, name := range splitList(*gateFlavours) {
		sum := total[name]
		if sum == nil {
			t.Errorf("no %s client connected to the fake in any room", name)
			continue
		}
		if sum.Layouts == 0 || sum.Perf == 0 || sum.Packets == 0 || sum.AfterReport == 0 || sum.Forwarded == 0 {
			t.Errorf("%s: layouts %d, perf reports %d, published %d (%d after a receiver report), forwarded %d: "+
				"none may be zero over a whole run", name, sum.Layouts, sum.Perf, sum.Packets, sum.AfterReport, sum.Forwarded)
		}
	}

	// What the clients logged.
	watch.mu.Lock()
	defer watch.mu.Unlock()
	for kind, n := range watch.leaks {
		t.Errorf("%d lines the clients logged carry %s", n, kind)
	}
	if watch.lines == 0 && total[rustFlavour] != nil {
		t.Error("no client line was read: the secret check saw nothing")
	}
	t.Logf("secret check: %d client lines read, %d kinds of secret known, %d found", watch.lines,
		len(target.secrets), len(watch.leaks))
	t.Logf("rust client heap peak, the highest any client of the run said: %d KiB (0: no heap-stats build, or no rust flavour)",
		watch.heapPeak)
	t.Logf("go server memory, the highest VmHWM of the run's servers (the engine at the pin on the same call, in a process of its own): %d KiB",
		srvHWM)
	t.Logf("gate process memory (the harness, and the Go client only with -olcrtc.gate-go-inproc): VmHWM %d KiB",
		procStatusKB(os.Getpid(), "VmHWM:"))
}

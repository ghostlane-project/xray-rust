// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's interop
// target and its rust flavour. The target runs this module's server (built
// with the olcrtc_interop tag, which links the interop-pipe engine) in a room
// of an in-process hub (internal/engine/interoppipe) instead of a meeting
// service; the rust flavour runs the Rust client (olc-client) as a child
// process against it. TestGateRust runs S0-S5 on that pair:
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestGateRust$' \
//	    -olcrtc.gate-target=interop -olcrtc.gate-rust-bin=<olc-client> \
//	    [-olcrtc.gate-chaos=chaos] [-olcrtc.gate-flavours=rust,cli]
//
// The cli flavour here is the Go public client over the same hub, the
// baseline the rust one is compared with.

package gate

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

const (
	targetInterop    = "interop"
	platformInterop  = "interop-linux"
	providerInterop  = "interop"
	rustFlavour      = "rust"
	rustListenMarker = "SOCKS5 server listening on "
)

var (
	gateRustBin = flag.String("olcrtc.gate-rust-bin", os.Getenv("OLCRTC_GATE_RUST_BIN"),
		"the Rust client binary (olc-client) for the interop target")
	gateChaos    = flag.String("olcrtc.gate-chaos", "clean", "the interop hub's faults: clean or chaos")
	gateFlavours = flag.String("olcrtc.gate-flavours", rustFlavour,
		"the interop target's clients: rust, cli (the Go baseline) or both")
)

// InteropTarget is the server in a room of the hub.
type InteropTarget struct {
	root, work string
	hub        *interoppipe.Hub
	origin     *Origin

	buildMu sync.Mutex
	binary  string
}

// Name implements Target.
func (t *InteropTarget) Name() string { return targetInterop }

// Platform implements Target.
func (t *InteropTarget) Platform() string { return platformInterop }

// Pairs implements Target: the one pair, datachannel over the hub.
func (t *InteropTarget) Pairs() []Pair { return []Pair{{providerInterop, transportData}} }

// Load implements Target.
func (t *InteropTarget) Load() LoadURLs { return t.origin.URLs }

func (t *InteropTarget) build(ctx context.Context) (string, error) {
	t.buildMu.Lock()
	defer t.buildMu.Unlock()
	if t.binary != "" {
		return t.binary, nil
	}
	out := filepath.Join(t.work, "olcrtc")
	cmd := exec.CommandContext(ctx, "go", "build", "-tags", "olcrtc_testhooks,olcrtc_interop", "-o", out, "./cmd/olcrtc")
	cmd.Dir = t.root
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build server: %w\n%s", err, b)
	}
	t.binary = out
	return out, nil
}

// Open implements Target: a fresh room and key, the server joined to it.
func (t *InteropTarget) Open(ctx context.Context, p Pair, dir string, opt OpenOptions) (Endpoint, func(), error) {
	key, err := NewKey()
	if err != nil {
		return Endpoint{}, nil, err
	}
	room, err := NewChannel()
	if err != nil {
		return Endpoint{}, nil, err
	}
	ep := Endpoint{Provider: p.Provider, Transport: p.Transport, Room: t.hub.URL("gate-" + room), Key: key, DNS: defaultDNS}
	stop, err := t.startServer(ctx, ep, []string{key}, dir, opt)
	if err != nil {
		return Endpoint{}, nil, err
	}
	return ep, stop, nil
}

// startServer runs a server holding ring in ep's room and waits for its join.
func (t *InteropTarget) startServer(ctx context.Context, ep Endpoint, ring []string, dir string,
	opt OpenOptions,
) (func(), error) {
	binary, err := t.build(ctx)
	if err != nil {
		return nil, err
	}
	srv, err := startServer(ctx, binary, t.work, interopServerConfig(ep, ring), opt)
	if err != nil {
		return nil, err
	}
	secrets := append(ep.Secrets(), ring...)
	stop := func() { srv.stop(filepath.Join(dir, serverLogName), secrets) }
	if err := waitForLine(srv.log, linkedLine, linkBudget, srv.exited); err != nil {
		tail := clip(Scrub(lastLine(srv.log), secrets...))
		stop()
		return nil, fmt.Errorf("%w; last server line: %s", err, tail)
	}
	return stop, nil
}

// interopServerConfig is the mode: srv YAML of the interop pair.
func interopServerConfig(ep Endpoint, ring []string) string {
	keys := make([]string, 0, len(ring))
	for _, k := range ring {
		keys = append(keys, strconv.Quote(k))
	}
	crypto := "crypto: { keys: [" + strings.Join(keys, ", ") + "] }"
	if len(ring) == 1 {
		crypto = "crypto: { key: " + strconv.Quote(ring[0]) + " }"
	}
	return strings.Join([]string{
		"mode: srv", "auth: { provider: none }",
		"engine: { name: " + interoppipe.Name + ", url: " + strconv.Quote(ep.Room) + " }",
		crypto,
		"net: { transport: " + ep.Transport + ", dns: " + strconv.Quote(ep.DNS) + " }",
		"udp: { enabled: true }", "debug: true",
	}, "\n") + "\n"
}

// rustConfig is what the Rust client reads (olc-client's config.rs).
type rustConfig struct {
	URL       string `json:"url"`
	Key       string `json:"key"`
	Transport string `json:"transport"`
	DNS       string `json:"dns"`
	Socks     string `json:"socks"`
	DeviceID  string `json:"device_id"`
	SocksUser string `json:"socks_user,omitempty"`
	SocksPass string `json:"socks_pass,omitempty"`
	// Engine, Token and RoomID join a SaluteJazz room (the fakeroom target,
	// zz_rust_fakeroom_test.go): the engine, the room's password and code.
	Engine string `json:"engine,omitempty"`
	Token  string `json:"token,omitempty"`
	RoomID string `json:"room_id,omitempty"`
	// Provider is the auth provider: salutejazz reads URL as the room
	// reference "<code>:<password>" (zz_rust_live_test.go).
	Provider string `json:"provider,omitempty"`
	// Liveness and LivenessFallbackMS shorten the client's liveness for the
	// e2e scenarios (zz_rust_e2e_test.go).
	Liveness           *rustLiveness `json:"liveness,omitempty"`
	LivenessFallbackMS int           `json:"liveness_fallback_ms,omitempty"`
	// ICETransportPolicy is "relay" for a relay-only run (the fakeroom
	// target's relay rooms).
	ICETransportPolicy string `json:"ice_transport_policy,omitempty"`
	// MaxJoins caps the joins the client starts on the carrier, rejoins
	// included (the live step's budget); 0 is no cap.
	MaxJoins int `json:"max_joins,omitempty"`
}

// rustClient runs the Rust client as a child process; its stderr is the
// engine log and goes to the cell's capture line by line.
type rustClient struct {
	bin         string
	start, stop time.Duration
	extra       func(*rustConfig)
	logf        func(format string, args ...any)
}

// Name implements Client.
func (rustClient) Name() string { return rustFlavour }

// Start implements Client.
func (c rustClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	child, err := startRust(ctx, c.bin, ep, c.extra)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(c.start)
	defer timer.Stop()
	select {
	case addr := <-child.ready:
		return &Tunnel{SocksAddr: addr, Stop: sync.OnceFunc(func() { child.halt(c.stop, c.logf) })}, nil
	case <-child.exited:
		child.halt(c.stop, nil)
		return nil, fmt.Errorf("rust client: %w: %v", ErrClientEnded, child.err)
	case <-timer.C:
		child.halt(c.stop, nil)
		return nil, fmt.Errorf("rust client: %w within %s", ErrClientNotReady, c.start)
	}
}

// rustChild is one run of the Rust client.
type rustChild struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	dir    string
	ready  chan string
	exited chan struct{}
	err    error
	peak   int64 // the highest VmRSS sampled, KiB
	peakMu sync.Mutex
	once   sync.Once
}

func startRust(ctx context.Context, bin string, ep Endpoint, extra func(*rustConfig)) (*rustChild, error) {
	if bin == "" {
		return nil, errors.New("rust client: no binary: pass -olcrtc.gate-rust-bin or OLCRTC_GATE_RUST_BIN")
	}
	dir, err := os.MkdirTemp("", "olc-rust-")
	if err != nil {
		return nil, fmt.Errorf("rust client: %w", err)
	}
	cfg := rustConfig{URL: ep.Room, Key: ep.Key, Transport: ep.Transport, DNS: ep.DNS, Socks: "127.0.0.1:0",
		DeviceID: "gate-rust"}
	if extra != nil {
		extra(&cfg)
	}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("rust client: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(runCtx, bin, path)
	// The child dies with the test process (a panic or -timeout runs no
	// cleanup), not only when halt stops it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopBudget
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("rust client: %w", err)
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("rust client: %w", err)
	}
	c := &rustChild{cmd: cmd, cancel: cancel, dir: dir, ready: make(chan string, 1), exited: make(chan struct{})}
	lines := make(chan struct{})
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		said := false
		for sc.Scan() {
			line := sc.Text()
			_, _ = log.Writer().Write([]byte(line + "\n"))
			if i := strings.Index(line, rustListenMarker); i >= 0 && !said {
				said = true
				c.ready <- strings.Fields(line[i+len(rustListenMarker):])[0]
			}
		}
	}()
	go c.sample()
	go func() {
		<-lines
		c.err = cmd.Wait()
		close(c.exited)
	}()
	return c, nil
}

// sample keeps the child's peak resident memory, once a second.
func (c *rustChild) sample() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if kb := procStatusKB(c.cmd.Process.Pid, "VmRSS:"); kb > 0 {
			c.peakMu.Lock()
			c.peak = max(c.peak, kb)
			c.peakMu.Unlock()
		}
		select {
		case <-c.exited:
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

// halt stops the child (SIGTERM, then a kill after the budget) and, given a
// logf, says what its memory came to.
func (c *rustChild) halt(budget time.Duration, logf func(string, ...any)) {
	c.once.Do(func() {
		hwm := procStatusKB(c.cmd.Process.Pid, "VmHWM:")
		c.cancel()
		select {
		case <-c.exited:
		case <-time.After(budget + time.Second):
		}
		_ = os.RemoveAll(c.dir)
		if logf != nil {
			c.peakMu.Lock()
			logf("rust client memory: VmHWM %d KiB, peak sampled VmRSS %d KiB", hwm, c.peak)
			c.peakMu.Unlock()
		}
	})
}

// goInteropClient is the Go public client over the hub: the baseline.
type goInteropClient struct{ cli cliClient }

// Name implements Client.
func (goInteropClient) Name() string { return cliFlavour }

// Start implements Client.
func (g goInteropClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	cfg := client.Config{
		Transport: ep.Transport, Provider: "none", Engine: interoppipe.Name, URL: ep.Room,
		KeyHex: ep.Key, LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
	}
	c := g.cli
	c.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return c.Start(ctx, ep)
}

// interopScenarios is the registry the interop target runs: S0-S5 for every
// flavour. S6 needs a server whose bridge opens late, which a hub room does
// not model, and S7 weighs the test process, which the rust flavour is not
// part of (its memory is logged at its stop instead).
func interopScenarios(all []Scenario) []Scenario {
	var out []Scenario
	for _, s := range all {
		if !slices.Contains([]string{"S0", "S1", "S2", "S3", "S4", "S5"}, s.ID) {
			continue
		}
		s.Applies = always
		out = append(out, s)
	}
	return out
}

// TestGateRust is the gate on the interop target.
func TestGateRust(t *testing.T) {
	if *gateTargetName != targetInterop {
		t.Skip("the interop gate runs with -olcrtc.gate-target=interop")
	}
	interoppipe.Register()
	root := moduleRoot(t)
	chaos, err := interoppipe.Profile(*gateChaos)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := interoppipe.StartHub("127.0.0.1:0", chaos)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	target := &InteropTarget{root: root, work: t.TempDir(), hub: hub, origin: startOrigin(t)}

	registryMu.Lock()
	saved := registry
	registry = interopScenarios(saved)
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
			clients = append(clients, rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf})
		case cliFlavour:
			clients = append(clients, goInteropClient{cli: cliClient{start: startBudget, stop: stopBudget}})
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, "interop-"+cmpOr(*gateChaos, "clean"))
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(Report{Target: targetInterop, Runner: runnerName()})
	capture := StartCapture()
	defer capture.Stop()
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
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

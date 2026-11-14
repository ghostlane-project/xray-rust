// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's fakeroom
// target, T2(b). Each cell's server is the pinned Go server in a fresh room of
// the SaluteJazz fake SFU (internal/engine/salutejazz, fakeconnector_test.go),
// both run by TestServeFakeRoom (zz_rust_test.go there) in a child process
// this test starts; the client joins the fake over real WebRTC:
//
//	go test ./internal/gate -run '^TestGateRustFakeRoom$' -olcrtc.gate-target=fakeroom \
//	    -olcrtc.gate-rust-bin=<olc-client> [-olcrtc.gate-flavours=rust,cli]
//
// The rust flavour is the Rust client with engine salutejazz; the cli flavour
// is the Go public client over the same fake, the baseline. A cell passes
// only if the fake tripped over none of the frames of its room (an empty
// lastError): every client frame matched the capture.

package gate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/engine/salutejazz"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

const (
	targetFakeRoom   = "fakeroom"
	platformFakeRoom = "fakeroom-linux"
	providerJazz     = "salutejazz"
	// fakeRoomEngine is the engine the Go baseline joins with: SaluteJazz
	// with the room code the fake's server handed out.
	fakeRoomEngine = "zz-salutejazz-fake"
	// fakeRoomServeMarker is TestServeFakeRoom's listening line.
	fakeRoomServeMarker = "FAKE ROOM SERVER LISTENING ON "
	// fakeRoomServeLifetime bounds the serving process.
	fakeRoomServeLifetime = 70 * time.Minute
)

// fakeRoomCreds is what a client joins a served room with.
type fakeRoomCreds struct {
	ID       int    `json:"id"`
	URL      string `json:"url"`
	Room     string `json:"room"`
	Password string `json:"password"`
	Server   string `json:"server"`
	// RelayURL, served with OLCRTC_GATE_RUST_RELAY=1, is the room's
	// connector behind a relay that hands out a TURN server: the rust
	// flavour joins through it relay-only (zz_rust_relay_test.go).
	RelayURL string `json:"relay_url,omitempty"`
}

// fakeRoomState is a served room's state (TestServeFakeRoom's /state).
type fakeRoomState struct {
	LastError    string         `json:"last_error"`
	Identities   []string       `json:"identities"`
	Server       string         `json:"server"`
	Peak         map[string]int `json:"peak"`
	ServerClosed []string       `json:"server_closed"`
	ServerOpened int            `json:"server_opened"`
}

// FakeRoomTarget is the Go server in a room of the fake SFU.
type FakeRoomTarget struct {
	base   string // the serving process's http://addr
	origin *Origin

	mu    sync.Mutex
	creds map[string]fakeRoomCreds // by connector URL
	ended []fakeRoomEnd
}

// fakeRoomEnd is one room as it ended.
type fakeRoomEnd struct {
	creds fakeRoomCreds
	state fakeRoomState
	err   error
}

// Name implements Target.
func (t *FakeRoomTarget) Name() string { return targetFakeRoom }

// Platform implements Target.
func (t *FakeRoomTarget) Platform() string { return platformFakeRoom }

// Pairs implements Target: SaluteJazz, datachannel.
func (t *FakeRoomTarget) Pairs() []Pair { return []Pair{{providerJazz, transportData}} }

// Load implements Target.
func (t *FakeRoomTarget) Load() LoadURLs { return t.origin.URLs }

// Open implements Target: a fresh fake room, the server joined to it.
func (t *FakeRoomTarget) Open(ctx context.Context, p Pair, _ string, _ OpenOptions) (Endpoint, func(), error) {
	key, err := NewKey()
	if err != nil {
		return Endpoint{}, nil, err
	}
	var c fakeRoomCreds
	if err := t.call(ctx, http.MethodPost, "/open", map[string]string{"key": key, "dns": defaultDNS}, &c); err != nil {
		return Endpoint{}, nil, err
	}
	t.mu.Lock()
	t.creds[c.URL] = c
	t.mu.Unlock()
	ep := Endpoint{Provider: p.Provider, Transport: p.Transport, Room: c.URL, Key: key, DNS: defaultDNS}
	stop := sync.OnceFunc(func() {
		var st fakeRoomState
		err := t.call(context.Background(), http.MethodPost, fmt.Sprintf("/close?id=%d", c.ID), nil, &st)
		t.mu.Lock()
		t.ended = append(t.ended, fakeRoomEnd{creds: c, state: st, err: err})
		t.mu.Unlock()
	})
	return ep, stop, nil
}

// roomOf is the creds of the room at url.
func (t *FakeRoomTarget) roomOf(url string) (fakeRoomCreds, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.creds[url]
	return c, ok
}

func (t *FakeRoomTarget) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, t.base+path, rd)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fake room %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fake room %s: %s: %s", path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, out)
}

// startFakeRoomServer builds the salutejazz test binary and runs
// TestServeFakeRoom in it until the test ends: its stdin closes then (the
// server's signal to stop), its group is killed after a grace, Pdeathsig
// kills it with the test process, and its context carries the lifetime.
func startFakeRoomServer(t *testing.T, root, dir string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "salutejazz.test")
	build := exec.Command("go", "test", "-c", "-o", bin, "./internal/engine/salutejazz")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the fake room server: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), fakeRoomServeLifetime)
	cmd := exec.CommandContext(ctx, bin, "-test.run", "^TestServeFakeRoom$", "-test.v",
		"-test.timeout", (fakeRoomServeLifetime + time.Minute).String())
	cmd.Env = append(os.Environ(), "OLC_FAKE_ROOM_SERVE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = stopGrace
	// The Go servers' log: one file for every room the run opens.
	logFile, err := os.OpenFile(filepath.Join(dir, "fakeroom-server.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
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
		sc := bufio.NewScanner(stdout)
		said := false
		for sc.Scan() {
			line := sc.Text()
			if rest, ok := strings.CutPrefix(line, fakeRoomServeMarker); ok && !said {
				said = true
				addr <- strings.TrimSpace(rest)
				continue
			}
			t.Logf("fake room server: %s", line)
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
			t.Errorf("the fake room server was still running 30 s after its stdin closed")
		}
		cancel()
		<-exited
	})
	select {
	case a := <-addr:
		return "http://" + a
	case <-exited:
		t.Fatal("the fake room server ended before it listened")
	case <-time.After(60 * time.Second):
		t.Fatal("the fake room server did not listen within 60 s")
	}
	return ""
}

// goFakeRoomClient is the Go public client in a served room: the baseline.
type goFakeRoomClient struct {
	target *FakeRoomTarget
	cli    cliClient
}

// Name implements Client.
func (goFakeRoomClient) Name() string { return cliFlavour }

// Start implements Client.
func (g goFakeRoomClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	c, ok := g.target.roomOf(ep.Room)
	if !ok {
		return nil, fmt.Errorf("go client: no served room at %s", ep.Room)
	}
	cfg := client.Config{
		Transport: ep.Transport, Provider: "none", Engine: fakeRoomEngine, URL: c.URL, Token: c.Password,
		KeyHex: ep.Key, LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
	}
	cli := g.cli
	cli.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return cli.Start(ctx, ep)
}

// TestGateRustFakeRoom is the gate on the fakeroom target.
func TestGateRustFakeRoom(t *testing.T) {
	if *gateTargetName != targetFakeRoom {
		t.Skip("the fake-room gate runs with -olcrtc.gate-target=fakeroom")
	}
	root := moduleRoot(t)
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, targetFakeRoom)
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	target := &FakeRoomTarget{base: startFakeRoomServer(t, root, dir), origin: startOrigin(t),
		creds: make(map[string]fakeRoomCreds)}
	engine.Register(fakeRoomEngine, func(ctx context.Context, cfg engine.Config) (engine.Session, error) {
		c, ok := target.roomOf(cfg.URL)
		if !ok {
			return nil, fmt.Errorf("no served room at %s", cfg.URL)
		}
		cfg.Extra = map[string]string{"roomID": c.Room}
		return salutejazz.New(ctx, cfg)
	})

	registryMu.Lock()
	saved := registry
	registry = interopThroughS5(saved)
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
					c, ok := target.roomOf(cfg.URL)
					if !ok {
						return
					}
					cfg.Engine, cfg.Token, cfg.RoomID = providerJazz, c.Password, c.Room
					if c.RelayURL != "" {
						cfg.URL, cfg.ICETransportPolicy = c.RelayURL, "relay"
					}
				}})
		case cliFlavour:
			clients = append(clients, goFakeRoomClient{target: target, cli: cliClient{start: startBudget, stop: stopBudget}})
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
	rec := NewRecorder(Report{Target: targetFakeRoom, Runner: runnerName()})
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
	target.mu.Lock()
	ended := append([]fakeRoomEnd(nil), target.ended...)
	target.mu.Unlock()
	for _, e := range ended {
		if e.err != nil {
			t.Errorf("room %d: closing it: %v", e.creds.ID, e.err)
			continue
		}
		t.Logf("room %d: %d participants, server sessions opened %d, closed %q, leg peaks %v", e.creds.ID,
			len(e.state.Identities), e.state.ServerOpened, e.state.ServerClosed, e.state.Peak)
		if e.state.LastError != "" {
			t.Errorf("room %d: the fake tripped over a frame: %s", e.creds.ID, e.state.LastError)
		}
	}
	if len(ended) == 0 {
		t.Error("no room was opened and closed")
	}
}

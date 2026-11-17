// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the Go baseline as a
// process of its own, for the targets whose tunnel is vp8channel over WebRTC
// (p2p, mtsfake, vkfake). The engine's cli flavour runs the public client
// inside the test process: there it shares the process's Ps (GOMAXPROCS)
// with the load generators, the origin and, on mtsfake, the fake SFU's pion
// peers, its memory cannot be told from theirs, and it runs in the server
// buffer profile, where the Rust client is a port of the phone one. Here
// the cli flavour is cmd/zz-olcrtc-goclient (internal/zzgoclient): the same
// public client on the same config, started the way the rust flavour starts
// olc-client: its SOCKS address read from its log, its lines sent to the
// cell's capture, its VmHWM and sampled RSS logged when it stops.
//
//	-olcrtc.gate-go-profile=phone|server  the child's buffer profile; phone,
//	                                      the default, is the Rust client's
//	-olcrtc.gate-go-inproc                the engine's in-process client
//	                                      instead (server profile), to
//	                                      compare
//	-olcrtc.gate-go-gctrace               the child's runtime also says its
//	                                      heap sizes (GODEBUG=gctrace=1)

package gate

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/zzgoclient"
)

var (
	gateGoInproc = flag.Bool("olcrtc.gate-go-inproc", false,
		"the cli flavour of the p2p, mtsfake and vkfake targets inside the test process, as the engine's gate runs it "+
			"(server profile), instead of a child process")
	gateGoProfile = flag.String("olcrtc.gate-go-profile", zzgoclient.ProfilePhone,
		"the Go child client's buffer profile: phone (constrained, what the Rust client ports) or server")
	gateGoGCTrace = flag.Bool("olcrtc.gate-go-gctrace", false,
		"run the Go child client with GODEBUG=gctrace=1 and log the largest heap its runtime said")
)

// goJoin is what the Go client joins an endpoint with on direct credentials
// (provider none): the engine, its URL and, for the engines that take one,
// its token.
type goJoin struct {
	Engine, URL, Token string
}

// buildGoChild builds cmd/zz-olcrtc-goclient of the module at root. It is
// built before any cell runs: a build inside the first Start would be
// counted in that cell's handshake.
func buildGoChild(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "zz-olcrtc-goclient")
	cmd := exec.Command("go", "build", "-tags", "olcrtc_interop", "-o", out, "./cmd/zz-olcrtc-goclient")
	cmd.Dir = root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the go client: %v\n%s", err, raw)
	}
	return out
}

// goChildClient is the Go client in a process of its own: the baseline.
type goChildClient struct {
	bin, profile string
	start, stop  time.Duration
	logf         func(format string, args ...any)
	// join says what the client joins ep with; it may mint a guest.
	join func(ctx context.Context, ep Endpoint) (goJoin, error)
}

// Name implements Client.
func (goChildClient) Name() string { return cliFlavour }

// Start implements Client.
func (c goChildClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	j, err := c.join(ctx, ep)
	if err != nil {
		return nil, fmt.Errorf("go client: %w", err)
	}
	dir, err := os.MkdirTemp("", "olc-go-")
	if err != nil {
		return nil, fmt.Errorf("go client: %w", err)
	}
	raw, _ := json.Marshal(goChildConfig(ep, j, c.profile))
	var env []string
	if *gateGoGCTrace {
		env = []string{"GODEBUG=gctrace=1"}
	}
	child, err := startChild(ctx, "go client", c.bin, dir, "client.json", raw, env)
	if err != nil {
		return nil, err
	}
	addr, err := child.listening(c.start, c.stop)
	if err != nil {
		return nil, err
	}
	return &Tunnel{SocksAddr: addr, Stop: sync.OnceFunc(func() { child.halt(c.stop, c.logf) })}, nil
}

// goChildConfig is what the child is run on: the endpoint as the in-process
// baseline passes it to the public client, and the profile.
func goChildConfig(ep Endpoint, j goJoin, profile string) zzgoclient.Config {
	return zzgoclient.Config{
		Profile: profile, Transport: ep.Transport, Engine: j.Engine, URL: j.URL, Token: j.Token,
		Channel: ep.Channel, Key: ep.Key, DNS: ep.DNS, DeviceID: "gate-cli", VP8FPS: ep.VP8FPS, VP8Batch: ep.VP8Batch,
	}
}

// goBaseline is a target's cli flavour: the child in the profile
// -olcrtc.gate-go-profile names, or with -olcrtc.gate-go-inproc the
// in-process client the target had before.
func goBaseline(t *testing.T, root string, inproc Client,
	join func(ctx context.Context, ep Endpoint) (goJoin, error),
) Client {
	t.Helper()
	procs := cmpOr(os.Getenv("GOMAXPROCS"), "every CPU")
	if *gateGoInproc {
		t.Logf("go client: inside this process (-olcrtc.gate-go-inproc), server profile; "+
			"it shares GOMAXPROCS=%s with the harness", procs)
		return inproc
	}
	profile := *gateGoProfile
	if profile != zzgoclient.ProfilePhone && profile != zzgoclient.ProfileServer {
		t.Fatalf("-olcrtc.gate-go-profile=%q: %s or %s", profile, zzgoclient.ProfilePhone, zzgoclient.ProfileServer)
	}
	t.Logf("go client: a process of its own (cmd/zz-olcrtc-goclient), %s profile, GOMAXPROCS=%s as the server's",
		profile, procs)
	return goChildClient{bin: buildGoChild(t, root), profile: profile, start: startBudget, stop: stopBudget,
		logf: t.Logf, join: join}
}

// goGCLine reads a line of a Go runtime's gctrace,
//
//	gc 7 @1.234s 2%: 0.01+1.2+0.02 ms clock, ... ms cpu, 4->6->3 MB, 6 MB goal, 0 MB stacks, 0 MB globals, 3 P
//
// and returns the larger of the heap when the collection began and when it
// ended, in MB. Any other line is not one.
func goGCLine(line string) (int64, bool) {
	if !strings.HasPrefix(line, "gc ") || !strings.Contains(line, " MB goal") {
		return 0, false
	}
	for _, part := range strings.Split(line, ", ") {
		sizes, ok := strings.CutSuffix(part, " MB")
		if !ok || strings.Count(sizes, "->") != 2 {
			continue
		}
		var peak int64
		for _, f := range strings.Split(sizes, "->")[:2] {
			n, err := strconv.ParseInt(f, 10, 64)
			if err != nil {
				return 0, false
			}
			peak = max(peak, n)
		}
		return peak, true
	}
	return 0, false
}

// TestGoGCLineReadsTheHeapOfATraceLine holds goGCLine to what it names: a
// trace line is read (and so kept out of the cell's log), and no client
// line is taken for one.
func TestGoGCLineReadsTheHeapOfATraceLine(t *testing.T) {
	for _, c := range []struct {
		line string
		mb   int64
		ok   bool
	}{
		{"gc 7 @1.234s 2%: 0.01+1.2+0.02 ms clock, 0.03+0.1/1.0/0.5+0.06 ms cpu, 4->6->3 MB, 6 MB goal, " +
			"0 MB stacks, 0 MB globals, 3 P", 6, true},
		{"gc 1 @0.004s 1%: 0.1+0.2+0.3 ms clock, 0.1+0/0/0+0.1 ms cpu, 12->9->1 MB, 4 MB goal, 0 MB stacks, " +
			"0 MB globals, 3 P (forced)", 12, true},
		{"2026/11/15 10:00:00 [INFO] SOCKS5 server listening on 127.0.0.1:1080", 0, false},
		{"gc is not a trace line, 4->6->3 MB", 0, false},
		{"gc 3 @1s 0%: clock, cpu, x->6->3 MB, 6 MB goal", 0, false},
		{"", 0, false},
	} {
		if mb, ok := goGCLine(c.line); mb != c.mb || ok != c.ok {
			t.Errorf("goGCLine(%q) = %d, %v, want %d, %v", c.line, mb, ok, c.mb, c.ok)
		}
	}
}

// TestGoChildConfigCarriesTheEndpoint: what the child is run on is the
// endpoint and the join, whole, under the keys the command reads (it
// refuses one it does not know), in the profile asked for.
func TestGoChildConfigCarriesTheEndpoint(t *testing.T) {
	ep := Endpoint{Provider: providerInterop, Transport: transportVP8, Room: "tcp://127.0.0.1:9/room",
		Channel: "chan-1", Key: strings.Repeat("ab", 32), DNS: defaultDNS, VP8FPS: p2pFPS, VP8Batch: p2pBatch}
	j := goJoin{Engine: engineMTSLink, URL: "http://127.0.0.1:3/rtc/room/1", Token: `a=1; b="2"`}
	for _, profile := range []string{zzgoclient.ProfilePhone, zzgoclient.ProfileServer} {
		raw, err := json.Marshal(goChildConfig(ep, j, profile))
		if err != nil {
			t.Fatal(err)
		}
		got, err := zzgoclient.Parse(raw)
		if err != nil {
			t.Fatalf("%s: the command refuses the config: %v", profile, err)
		}
		want := zzgoclient.Config{
			Profile: profile, Transport: transportVP8, Engine: engineMTSLink, URL: j.URL, Token: j.Token,
			Channel: "chan-1", Key: ep.Key, DNS: defaultDNS, DeviceID: "gate-cli", VP8FPS: p2pFPS, VP8Batch: p2pBatch,
		}
		if got != want {
			t.Errorf("%s: the command reads\n%+v\nwant\n%+v", profile, got, want)
		}
	}
}

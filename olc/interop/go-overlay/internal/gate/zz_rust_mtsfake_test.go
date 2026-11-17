// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's mtsfake
// target, T2 for the MTS Link carrier. Each cell's server is the pinned Go
// server (this module's, built with the olcrtc_interop tag) with engine
// mtslink on direct credentials, in a fresh room of a fake SFU that forwards
// (internal/engine/mtslinkfake): real WebRTC against pion, every publisher's
// VP9 written into a slot of every other guest. The client joins the same
// room as another guest, and vp8channel and KCP run end to end over the
// carrier's own session code. No MTS Link service is contacted:
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestGateRustMTSFake$' \
//	    -olcrtc.gate-target=mtsfake -olcrtc.gate-rust-bin=<olc-client> \
//	    [-olcrtc.gate-flavours=rust,cli] [-olcrtc.gate-mts-ice=tcp|udp|both]
//
// The Go server joins as the engine does on direct credentials: over UDP,
// with no gateway to take a join back at (builtin.go:197-203). The rust
// flavour is the Rust client with engine mtslink, its ICE mode the flag's
// (tcp, the client's default for a link that says nothing); the cli flavour
// is the Go client on direct credentials, so over UDP: the baseline, a
// child process of its own (zz_go_child_test.go).
//
// Beyond S0-S5 the test holds:
//
//   - the room: no request the web client never makes, no cookie sent to
//     the SFU, no join refused, no conference taken back, a pin per join,
//     video forwarded both ways, and the rust client's pair on the protocol
//     the flag names;
//   - the logs: no line the rust client wrote carries a token, a cookie, a
//     device or user id, the conference, the room's session or the key
//     (mtsLogWatch, on the lines as written: the gate's own artifacts are
//     scrubbed, which would hide a leak);
//   - memory, logged: the rust client's heap peak (its heap-stats line) and
//     VmHWM, and with the cli flavour the Go client's VmHWM and this
//     process's own.

package gate

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/engine/mtslinkfake"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

const (
	platformMTSFake = "mtsfake-linux"
	engineMTSLink   = "mtslink"
	// mtsHeapLine opens the rust client's heap gauge (olc-client's
	// heap-stats feature): "heap now <n> KiB peak <n> KiB".
	mtsHeapLine = "heap now "
	// mtsLeakSamples is how many leaking lines the watch keeps to show.
	mtsLeakSamples = 5
)

var gateMTSICE = flag.String("olcrtc.gate-mts-ice", "tcp",
	"the mtsfake target's ICE mode for the rust client: tcp (the client's default), udp or both")

// mtsLogWatch reads every line of the process log as it is written, before
// the capture scrubs it: which flavour's client was running, whether the
// line carries one of the run's secrets, and the rust client's heap gauge.
type mtsLogWatch struct {
	next io.Writer

	mu      sync.Mutex
	secrets []string
	flavour string
	lines   map[string]int
	leaks   map[string]int
	samples []string
	// heapPeak is the highest "peak" the rust client's gauge said, KiB.
	heapPeak int64
}

func newMTSLogWatch(next io.Writer) *mtsLogWatch {
	return &mtsLogWatch{next: next, lines: map[string]int{}, leaks: map[string]int{}}
}

// know adds secrets no line may carry from here on.
func (w *mtsLogWatch) know(secrets ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range secrets {
		if s != "" {
			w.secrets = append(w.secrets, s)
		}
	}
}

// running names the flavour whose client the lines are from; empty between
// two clients.
func (w *mtsLogWatch) running(flavour string) {
	w.mu.Lock()
	w.flavour = flavour
	w.mu.Unlock()
}

// Write implements io.Writer: one or more whole lines.
func (w *mtsLogWatch) Write(p []byte) (int, error) {
	w.mu.Lock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.lines[w.flavour]++
		shown, leaked := line, false
		for _, s := range w.secrets {
			if strings.Contains(shown, s) {
				leaked = true
				shown = strings.ReplaceAll(shown, s, "<"+strconv.Itoa(len(s))+" bytes of a secret>")
			}
		}
		if leaked {
			w.leaks[w.flavour]++
			if len(w.samples) < mtsLeakSamples {
				w.samples = append(w.samples, w.flavour+": "+clip(shown))
			}
		}
		if _, rest, ok := strings.Cut(line, mtsHeapLine); ok && w.flavour == rustFlavour {
			if _, peak, ok := strings.Cut(rest, " KiB peak "); ok {
				if n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(peak), " KiB"), 10, 64); err == nil {
					w.heapPeak = max(w.heapPeak, n)
				}
			}
		}
	}
	next := w.next
	w.mu.Unlock()
	return next.Write(p)
}

// seen is what the watch read of one flavour's lines.
func (w *mtsLogWatch) seen(flavour string) (lines, leaks int, samples []string, heapPeak int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.samples {
		if strings.HasPrefix(s, flavour+": ") {
			samples = append(samples, s)
		}
	}
	return w.lines[flavour], w.leaks[flavour], samples, w.heapPeak
}

// TestMTSLogWatchReadsSecretsAndTheHeapGauge holds the watch to what it
// names; it needs no client binary. A check that reads no line, or that
// misses a secret in one, would pass every run.
func TestMTSLogWatchReadsSecretsAndTheHeapGauge(t *testing.T) {
	var out strings.Builder
	w := newMTSLogWatch(&out)
	w.know("vcJOINabc", "", "eyJguest.def")
	write := func(flavour, text string) {
		w.running(flavour)
		if n, err := w.Write([]byte(text)); err != nil || n != len(text) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	write(rustFlavour, "mtslink: ICE over tcp\n")
	write(rustFlavour, "heap now 1200 KiB peak 2900 KiB\n")
	write(rustFlavour, "heap now 900 KiB peak 2100 KiB\n")
	write(cliFlavour, "heap now 1 KiB peak 99999 KiB\n")
	if lines, leaks, _, heap := w.seen(rustFlavour); lines != 3 || leaks != 0 || heap != 2900 {
		t.Errorf("clean lines: %d lines, %d leaks, heap peak %d, want 3, 0, 2900", lines, leaks, heap)
	}
	write(rustFlavour, "joining ?joinToken=vcJOINabc&x=1\nall good\ncookie access=eyJguest.def; vcJOINabc\n")
	write(cliFlavour, "token vcJOINabc\n")
	write("", "between clients eyJguest.def\n")
	lines, leaks, samples, _ := w.seen(rustFlavour)
	if lines != 6 || leaks != 2 || len(samples) != 2 {
		t.Fatalf("rust: %d lines, %d leaks, %d samples, want 6, 2, 2", lines, leaks, len(samples))
	}
	for _, s := range samples {
		if strings.Contains(s, "vcJOINabc") || strings.Contains(s, "eyJguest.def") {
			t.Errorf("a sample shows the secret it was kept for: %q", s)
		}
	}
	if _, leaks, _, _ := w.seen(cliFlavour); leaks != 1 {
		t.Errorf("cli leaks = %d, want 1", leaks)
	}
	if _, leaks, _, _ := w.seen(""); leaks != 1 {
		t.Errorf("leaks between clients = %d, want 1", leaks)
	}
	// A secret learnt later is read from then on.
	w.know("did-0011")
	write(rustFlavour, "device did-0011\n")
	if _, leaks, _, _ := w.seen(rustFlavour); leaks != 3 {
		t.Errorf("rust leaks = %d after a later secret, want 3", leaks)
	}
	if !strings.Contains(out.String(), "all good\n") || strings.Count(out.String(), "\n") != 10 {
		t.Errorf("the watch did not pass every line on: %q", out.String())
	}
}

// mtsRoom is one cell's room and the guests minted in it.
type mtsRoom struct {
	room *mtslinkfake.Room
}

// mtsEnd is a room as it ended.
type mtsEnd struct {
	url   string
	state mtslinkfake.State
}

// MTSFakeTarget is the Go server in a room of the forwarding fake SFU.
type MTSFakeTarget struct {
	builder *InteropTarget // builds the server binary
	hub     *mtslinkfake.Hub
	origin  *Origin
	watch   *mtsLogWatch

	mu    sync.Mutex
	rooms map[string]*mtsRoom // by the endpoint's room
	ended []mtsEnd
}

// Name implements Target.
func (t *MTSFakeTarget) Name() string { return targetMTSFake }

// Platform implements Target.
func (t *MTSFakeTarget) Platform() string { return platformMTSFake }

// Pairs implements Target: MTS Link carries vp8channel alone.
func (t *MTSFakeTarget) Pairs() []Pair { return []Pair{{providerMTSLink, transportVP8}} }

// Load implements Target.
func (t *MTSFakeTarget) Load() LoadURLs { return t.origin.URLs }

// guest mints a guest of the room at url and tells the watch its secrets.
func (t *MTSFakeTarget) guest(url, name string) (mtslinkfake.Guest, bool) {
	t.mu.Lock()
	r, ok := t.rooms[url]
	t.mu.Unlock()
	if !ok {
		return mtslinkfake.Guest{}, false
	}
	g := r.room.Guest(name)
	t.watch.know(g.Secrets...)
	return g, true
}

// Open implements Target: a fresh room, channel and key, the server joined.
func (t *MTSFakeTarget) Open(ctx context.Context, p Pair, dir string, opt OpenOptions) (Endpoint, func(), error) {
	key, err := NewKey()
	if err != nil {
		return Endpoint{}, nil, err
	}
	channel, err := NewChannel()
	if err != nil {
		return Endpoint{}, nil, err
	}
	room := t.hub.Open()
	ep := Endpoint{Provider: p.Provider, Transport: p.Transport, Room: room.Link(), Channel: channel, Key: key,
		DNS: defaultDNS, VP8FPS: appVP8FPS, VP8Batch: appVP8Batch}
	t.mu.Lock()
	t.rooms[ep.Room] = &mtsRoom{room: room}
	t.mu.Unlock()
	t.watch.know(key)
	g, _ := t.guest(ep.Room, "server")
	end := func() {
		st := room.State()
		room.Close()
		t.mu.Lock()
		delete(t.rooms, ep.Room)
		t.ended = append(t.ended, mtsEnd{url: ep.Room, state: st})
		t.mu.Unlock()
	}
	binary, err := t.builder.build(ctx)
	if err != nil {
		end()
		return Endpoint{}, nil, err
	}
	srv, err := startServer(ctx, binary, t.builder.work, mtsServerConfig(ep, g), opt)
	if err != nil {
		end()
		return Endpoint{}, nil, err
	}
	secrets := append(ep.Secrets(), g.Secrets...)
	secrets = append(secrets, g.URL, g.Token)
	stop := sync.OnceFunc(func() {
		srv.stop(filepath.Join(dir, serverLogName), secrets)
		end()
	})
	if err := waitForLine(srv.log, linkedLine, linkBudget, srv.exited); err != nil {
		tail := clip(Scrub(lastLine(srv.log), secrets...))
		stop()
		return Endpoint{}, nil, fmt.Errorf("%w; last server line: %s", err, tail)
	}
	return ep, stop, nil
}

// mtsServerConfig is the mode: srv YAML of the pair: engine mtslink on
// direct credentials (the room join and the guest's cookies, nothing else:
// what Go's direct credentials carry), the app's vp8channel numbers.
func mtsServerConfig(ep Endpoint, g mtslinkfake.Guest) string {
	return strings.Join([]string{
		"mode: srv", "auth: { provider: none }",
		"engine: { name: " + engineMTSLink + ", url: " + strconv.Quote(g.URL) + ", token: " + strconv.Quote(g.Token) + " }",
		"room: { channel: " + strconv.Quote(ep.Channel) + " }",
		"crypto: { key: " + strconv.Quote(ep.Key) + " }",
		"net: { transport: " + ep.Transport + ", dns: " + strconv.Quote(ep.DNS) + " }",
		fmt.Sprintf("vp8: { fps: %d, batch_size: %d }", ep.VP8FPS, ep.VP8Batch),
		"udp: { enabled: true }", "debug: true",
	}, "\n") + "\n"
}

// mtsWatched tells the watch which flavour's client is running.
type mtsWatched struct {
	Client
	watch *mtsLogWatch
}

// Start implements Client.
func (c mtsWatched) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	c.watch.running(c.Name())
	tun, err := c.Client.Start(ctx, ep)
	if err != nil {
		c.watch.running("")
		return nil, err
	}
	stop := tun.Stop
	tun.Stop = func() {
		stop()
		c.watch.running("")
	}
	return tun, nil
}

// goMTSClient is the Go public client in the same room, on direct
// credentials as the server, inside this process: the baseline as it was,
// kept behind -olcrtc.gate-go-inproc.
type goMTSClient struct {
	target *MTSFakeTarget
	cli    cliClient
}

// Name implements Client.
func (goMTSClient) Name() string { return cliFlavour }

// Start implements Client.
func (g goMTSClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	guest, ok := g.target.guest(ep.Room, cliFlavour)
	if !ok {
		return nil, fmt.Errorf("go client: no room at the endpoint")
	}
	cfg := client.Config{
		Transport: ep.Transport, Provider: "none", Engine: engineMTSLink, URL: guest.URL, Token: guest.Token,
		ChannelID: ep.Channel, KeyHex: ep.Key, LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
		TransportOptions: client.VP8Options{FPS: ep.VP8FPS, BatchSize: ep.VP8Batch},
	}
	c := g.cli
	c.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return c.Start(ctx, ep)
}

// mtsRoomFailures is what a room that ended says against the run.
func mtsRoomFailures(st mtslinkfake.State, ice string) []string {
	var out []string
	if len(st.Strays) != 0 {
		out = append(out, fmt.Sprintf("requests the web client never makes: %q", st.Strays))
	}
	if st.CookiesAtSFU != 0 {
		out = append(out, fmt.Sprintf("%d calls to the SFU carried the guest's cookies", st.CookiesAtSFU))
	}
	if len(st.Refused) != 0 {
		out = append(out, fmt.Sprintf("joins the room refused: %q", st.Refused))
	}
	if len(st.Leaves) != 0 {
		out = append(out, fmt.Sprintf("%d conferences taken back, and no join failed", len(st.Leaves)))
	}
	if st.Pins != len(st.Joins) {
		out = append(out, fmt.Sprintf("%d pins for %d joins", st.Pins, len(st.Joins)))
	}
	clients := 0
	for _, j := range st.Joins {
		if j.Published == 0 || j.Heard == 0 {
			out = append(out, fmt.Sprintf("guest %s published %d packets and was sent %d", j.Guest, j.Published, j.Heard))
		}
		if j.Slots != mtslinkfake.Slots {
			out = append(out, fmt.Sprintf("guest %s offered %d video lines to receive on, want %d", j.Guest, j.Slots, mtslinkfake.Slots))
		}
		switch j.Guest {
		case "server", cliFlavour:
			// Go on direct credentials has no ICE word: UDP.
			if j.Pair != "udp" {
				out = append(out, fmt.Sprintf("guest %s is on a %q pair, want udp", j.Guest, j.Pair))
			}
		case rustFlavour:
			if ice != "both" && j.Pair != ice {
				out = append(out, fmt.Sprintf("the rust client is on a %q pair, asked for %s", j.Pair, ice))
			}
		}
		if j.Guest != "server" {
			clients++
		}
	}
	if clients == 0 {
		out = append(out, "no client joined the room")
	}
	return out
}

// TestMTSRoomFailuresNameWhatARoomSawWrong holds mtsRoomFailures to what it
// names; it needs no client binary.
func TestMTSRoomFailuresNameWhatARoomSawWrong(t *testing.T) {
	good := mtslinkfake.State{
		Joins: []mtslinkfake.Joined{{Guest: "server", Pair: "udp", Published: 9, Heard: 9, Slots: 9},
			{Guest: rustFlavour, Pair: "tcp", Published: 9, Heard: 9, Slots: 9}},
		Pins: 2,
	}
	if got := mtsRoomFailures(good, "tcp"); len(got) != 0 {
		t.Errorf("a good room fails: %q", got)
	}
	if got := mtsRoomFailures(good, "both"); len(got) != 0 {
		t.Errorf("a good room fails in both mode: %q", got)
	}
	bad := func(change func(*mtslinkfake.State), ice, want string) {
		t.Helper()
		st := good
		st.Joins = append([]mtslinkfake.Joined(nil), good.Joins...)
		change(&st)
		got := mtsRoomFailures(st, ice)
		if len(got) != 1 || !strings.Contains(got[0], want) {
			t.Errorf("failures = %q, want one about %q", got, want)
		}
	}
	bad(func(*mtslinkfake.State) {}, "udp", "asked for udp")
	bad(func(st *mtslinkfake.State) { st.Joins[0].Pair = "tcp" }, "tcp", "want udp")
	bad(func(st *mtslinkfake.State) { st.Joins[1].Heard = 0 }, "tcp", "was sent 0")
	bad(func(st *mtslinkfake.State) { st.Joins[1].Slots = 1 }, "tcp", "video lines")
	bad(func(st *mtslinkfake.State) { st.Strays = []string{"GET /x"} }, "tcp", "never makes")
	bad(func(st *mtslinkfake.State) { st.CookiesAtSFU = 1 }, "tcp", "cookies")
	bad(func(st *mtslinkfake.State) { st.Refused = []string{"no such guest"} }, "tcp", "refused")
	bad(func(st *mtslinkfake.State) { st.Leaves = []string{"1"} }, "tcp", "taken back")
	bad(func(st *mtslinkfake.State) { st.Pins = 1 }, "tcp", "pins")
	bad(func(st *mtslinkfake.State) { st.Joins = st.Joins[:1]; st.Pins = 1 }, "tcp", "no client")
}

// TestGateRustMTSFake is the gate on the mtsfake target.
func TestGateRustMTSFake(t *testing.T) {
	if *gateTargetName != targetMTSFake {
		t.Skip("the MTS Link fake-room gate runs with -olcrtc.gate-target=mtsfake")
	}
	ice := *gateMTSICE
	if ice != "tcp" && ice != "udp" && ice != "both" {
		t.Fatalf("-olcrtc.gate-mts-ice=%q: tcp, udp or both", ice)
	}
	root := moduleRoot(t)
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, targetMTSFake+"-"+ice)
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	hub, err := mtslinkfake.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	capture := StartCapture()
	defer capture.Stop()
	// The watch sits between the logger and the capture: it reads the
	// lines as they were written.
	watch := newMTSLogWatch(log.Writer())
	log.SetOutput(watch)
	target := &MTSFakeTarget{builder: &InteropTarget{root: root, work: t.TempDir()}, hub: hub, origin: startOrigin(t),
		watch: watch, rooms: make(map[string]*mtsRoom)}

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
	flavours := splitList(*gateFlavours)
	for _, name := range flavours {
		switch name {
		case rustFlavour:
			clients = append(clients, mtsWatched{watch: watch, Client: rustClient{
				bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
				extra: func(cfg *rustConfig) {
					g, ok := target.guest(cfg.URL, rustFlavour)
					if !ok {
						return
					}
					cfg.URL, cfg.Engine, cfg.Token = g.URL, engineMTSLink, g.Token
					cfg.IceLocalIP, cfg.Debug = "127.0.0.1", true
					cfg.EngineExtra = map[string]string{"gateway": g.Gateway, "conferenceId": g.Conference, "ice": ice}
				}}})
		case cliFlavour:
			inproc := goMTSClient{target: target, cli: cliClient{start: startBudget, stop: stopBudget}}
			clients = append(clients, mtsWatched{watch: watch, Client: goBaseline(t, root, inproc,
				func(_ context.Context, ep Endpoint) (goJoin, error) {
					guest, ok := target.guest(ep.Room, cliFlavour)
					if !ok {
						return goJoin{}, fmt.Errorf("no room at the endpoint")
					}
					return goJoin{Engine: engineMTSLink, URL: guest.URL, Token: guest.Token}, nil
				})})
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
	rec := NewRecorder(Report{Target: targetMTSFake, Runner: runnerName()})
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
	log.SetOutput(watch.next)
	rep := rec.Report()
	for _, c := range rep.Cells {
		t.Logf("cell %s: %s %v %q", c.ID, c.Status, c.Metrics, c.Failures)
	}
	for _, id := range unreported(rep) {
		t.Errorf("%s: %s", id, reasonDidNotRun)
	}
	if why := gateFailure(rep); why != "" {
		t.Errorf("gate: %s; the report goes to %s", why, opt.ReportPath)
	}

	// The rooms.
	target.mu.Lock()
	ended := append([]mtsEnd(nil), target.ended...)
	target.mu.Unlock()
	if len(ended) == 0 {
		t.Error("no room was opened and closed")
	}
	var forwarded, keyframes int64
	pairs := map[string]int{}
	for i, e := range ended {
		for _, why := range mtsRoomFailures(e.state, ice) {
			t.Errorf("room %d: %s", i+1, why)
		}
		keyframes += e.state.Keyframes
		for _, j := range e.state.Joins {
			forwarded += j.Heard
			pairs[j.Guest+" over "+j.Pair]++
		}
	}
	t.Logf("%d rooms: %d video packets forwarded, %d keyframe requests passed back, joins %v",
		len(ended), forwarded, keyframes, pairs)

	// The logs and the memory.
	for _, flavour := range flavours {
		lines, leaks, samples, heap := watch.seen(flavour)
		switch flavour {
		case rustFlavour:
			if lines == 0 {
				t.Error("the log watch read no line of the rust client: its secret check checked nothing")
			}
			if leaks != 0 {
				t.Errorf("%d of the rust client's %d log lines carry a secret of the join:\n%s", leaks, lines,
					strings.Join(samples, "\n"))
			}
			if heap == 0 {
				t.Logf("rust client: %d log lines, %d with a secret of the join; no heap gauge (a build without heap-stats)",
					lines, leaks)
			} else {
				t.Logf("rust client: %d log lines, %d with a secret of the join; heap peak %d KiB (VmHWM: the lines above)",
					lines, leaks, heap)
			}
		case cliFlavour:
			// The Go client is a process of its own (its memory: the "go
			// client memory" lines above) unless -olcrtc.gate-go-inproc put
			// it in this one, with the fake SFU's pion peers and the test
			// itself, where its own memory is below the process's.
			where := "a process of its own"
			if *gateGoInproc {
				where = "in this process, with the fake SFU"
			}
			t.Logf("go client (%s): %d log lines, %d with a secret of the join; this process's VmHWM %d KiB",
				where, lines, leaks, procStatusKB(os.Getpid(), "VmHWM:"))
			for _, s := range samples {
				t.Logf("go client log: %s", s)
			}
		}
	}
	if lines, leaks, samples, _ := watch.seen(""); leaks != 0 {
		t.Logf("between clients: %d of %d lines carry a secret (the gate's own, scrubbed in its artifacts): %q",
			leaks, lines, samples)
	}
}

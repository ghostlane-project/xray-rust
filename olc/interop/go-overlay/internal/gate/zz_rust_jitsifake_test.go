// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's jitsifake
// target, T2 for the Jitsi carrier. Each cell's server is the pinned Go server
// (cmd/olcrtc built with the test hooks, engine jitsi over datachannel) in a
// fresh room of the Go fake of a Jitsi Meet deployment
// (internal/engine/jitsifake: Prosody and Jicofo over a WebSocket, a pion peer
// per participant as the JVB). It is the pinned local target with the fake's
// host as its Jitsi host, so the plan, the thresholds and the server's start
// are the pinned ones; the client joins the same room:
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestGateRustJitsiFake$' \
//	    -olcrtc.gate-target=jitsifake -olcrtc.gate-rust-bin=<olc-client> \
//	    [-olcrtc.gate-flavours=rust,cli]
//
// With -olcrtc.gate-jitsi-bosh the rust client's WebSocket is refused and
// config.js names the fake's /http-bind: the same cells with its XMPP over
// BOSH (plan J19), the Go server beside it on its WebSocket. The fake then
// says the stream's features as a real Prosody does, and the answer with
// <success/> reaches the client after them (jitsifake's BOSHAsProsody).
//
// The rust flavour is the Rust client with provider jitsi, its plain HTTP
// origin and WebSocket the fake's (engine_extra config_base and ws_url); the
// cli flavour is the Go client, a process of its own (zz_go_child_test.go),
// over https and wss with the fake's certificate (SSL_CERT_FILE). S0-S7 run
// for both, S6 with the server's late bridge (OLCRTC_TEST_BRIDGE_DELAY).
// With -olcrtc.gate-jitsi-tls the rust flavour takes https and wss too, as
// an app does, the certificate trusted by its pin (a client built with the
// tls-test-pin feature); that run is S0-S6 (tlsScenarios says why).
//
// Beyond the cells the test holds:
//
//   - the room: a channel per join with Jitsi's own label and protocol,
//     the hello answered, the client's keepalive video read, no frame
//     dropped for a receiver that read;
//   - the logs: no line the rust client wrote carries the room's name, a
//     JID or a stanza (jitsiWatch, on the lines as written: the gate's own
//     artifacts are scrubbed, which would hide a leak);
//   - memory, logged: the rust client's heap peak and VmHWM beside the Go
//     client's VmHWM (the cli child's "go client memory" lines).

package gate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/jitsifake"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

var gateJitsiStall = flag.Bool("olcrtc.gate-jitsi-stall", false,
	"TestGateRustJitsiFake with a stopped reader: the fake's bridge stops handing frames to every client for 1.5 s in every 7")

var gateJitsiBOSH = flag.Bool("olcrtc.gate-jitsi-bosh", false,
	"TestGateRustJitsiFake with the rust client over BOSH: the fake refuses the WebSocket on the rust client's plain listener and its config.js names /http-bind; the Go server and the cli flavour stay on the WebSocket over TLS")

// targetJitsiFake is the gate target of the Go fake of a Jitsi room
// (jitsi.sh gate).
const targetJitsiFake = "jitsifake"

// gateGoPollLimit is how long the Go engine waits for a BOSH poll's answer
// (internal/protect/protect.go, the response header timeout).
const gateGoPollLimit = 10 * time.Second

// gateBOSHSuccessLag is how late the answer with <success/> reaches a client
// in the BOSH pass, the features' answer ahead of it.
const gateBOSHSuccessLag = 300 * time.Millisecond

// stanzaPattern is what an XMPP stanza of the join looks like in a log line:
// an element the client sends or hears (a BOSH body among them), or a JID of
// the fake's domain.
var stanzaPattern = regexp.MustCompile(`<(iq|presence|message|open|auth|stream:|jingle|success|enabled|bind|body)[ >/:]|@meet\.jitsi|muc\.meet\.jitsi`)

// jitsiWatch reads every line of the process log as it is written, in front
// of the MTS watch (which holds the secrets and the heap gauge): the stanzas a
// flavour's client wrote.
type jitsiWatch struct {
	*mtsLogWatch

	mu     sync.Mutex
	stanza map[string]int
	sample map[string][]string
}

func newJitsiWatch(next io.Writer) *jitsiWatch {
	return &jitsiWatch{mtsLogWatch: newMTSLogWatch(next), stanza: map[string]int{}, sample: map[string][]string{}}
}

// Write implements io.Writer.
func (w *jitsiWatch) Write(p []byte) (int, error) {
	w.mtsLogWatch.mu.Lock()
	flavour := w.mtsLogWatch.flavour
	w.mtsLogWatch.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if stanzaPattern.MatchString(line) {
			w.mu.Lock()
			w.stanza[flavour]++
			if len(w.sample[flavour]) < mtsLeakSamples {
				// Only the matching element's name: the line itself is the leak.
				w.sample[flavour] = append(w.sample[flavour], flavour+": "+stanzaPattern.FindString(line))
			}
			w.mu.Unlock()
		}
	}
	return w.mtsLogWatch.Write(p)
}

// stanzas is how many of one flavour's lines looked like a stanza.
func (w *jitsiWatch) stanzas(flavour string) (int, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stanza[flavour], append([]string(nil), w.sample[flavour]...)
}

// TestJitsiLogWatchReadsSecrets holds the watch to what it names; it needs no
// client binary. A check that reads no line, or that misses a stanza or a
// JID in one, would pass every run.
func TestJitsiLogWatchReadsSecrets(t *testing.T) {
	var out strings.Builder
	w := newJitsiWatch(&out)
	w.know("gate-0123456789ab", "0123456789abcdef")
	write := func(flavour, text string) {
		w.running(flavour)
		if n, err := w.Write([]byte(text)); err != nil || n != len(text) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	write(rustFlavour, "jitsi: joined\nheap now 1200 KiB peak 2900 KiB\n")
	if n, _ := w.stanzas(rustFlavour); n != 0 {
		t.Errorf("clean lines read as %d stanzas", n)
	}
	if lines, leaks, _, heap := w.seen(rustFlavour); lines != 2 || leaks != 0 || heap != 2900 {
		t.Errorf("clean lines: %d lines, %d leaks, heap %d, want 2, 0, 2900", lines, leaks, heap)
	}
	write(rustFlavour, "sent <presence to=\"x\"/>\nroom gate-0123456789ab\nuser 0123456789abcdef@meet.jitsi\nall good\n")
	n, samples := w.stanzas(rustFlavour)
	if n != 2 || len(samples) != 2 {
		t.Errorf("stanza lines %d (%q), want 2", n, samples)
	}
	for _, s := range samples {
		if strings.Contains(s, "0123456789abcdef") {
			t.Errorf("a sample shows what it was kept for: %q", s)
		}
	}
	if _, leaks, _, _ := w.seen(rustFlavour); leaks != 2 {
		t.Errorf("secret leaks = %d, want 2 (the room, the user part)", leaks)
	}
	write(cliFlavour, "<iq id=\"1\"/>\n")
	if n, _ := w.stanzas(cliFlavour); n != 1 {
		t.Errorf("cli stanza lines %d, want 1", n)
	}
	if n, _ := w.stanzas(rustFlavour); n != 2 {
		t.Errorf("the cli's line was counted for the rust client: %d", n)
	}
	if strings.Count(out.String(), "\n") != 7 {
		t.Errorf("the watch did not pass every line on: %q", out.String())
	}
	// The BOSH pass: a request's body in a line is a stanza in a line.
	write(rustFlavour, "posted <body rid=\"7\" sid=\"s\"/>\n")
	if n, _ := w.stanzas(rustFlavour); n != 3 {
		t.Errorf("a BOSH body in a line was not read as a stanza: %d stanza lines, want 3", n)
	}
}

// jitsiScenarios is the interop registry with S7 for the rust flavour alone.
// The cli flavour's S7 is the pinned one, which weighs the test process, and
// here that holds the fake itself (a pion peer per participant, every frame
// relayed through it): the Go client's memory is read from its own process
// instead, the "go client memory" lines (VmHWM), logged beside the rust
// client's.
func jitsiScenarios(all []Scenario, withhold func(...string)) []Scenario {
	out := interopScenarios(all, withhold)
	for i := range out {
		if out[i].ID == "S7" {
			out[i].Applies = func(_ Target, _ Pair, client string) bool { return client == rustFlavour }
		}
	}
	return out
}

// jitsiFakeTarget is the pinned local target with the fake's room: what it
// opens is told to the watch.
type jitsiFakeTarget struct {
	Target
	watch *jitsiWatch
	hub   *jitsifake.Hub
}

// Open implements Target.
func (t *jitsiFakeTarget) Open(ctx context.Context, p Pair, dir string, opt OpenOptions) (Endpoint, func(), error) {
	ep, stop, err := t.Target.Open(ctx, p, dir, opt)
	if err == nil {
		// The room's name is the link's last element: it is the secret.
		t.watch.know(ep.Room[strings.LastIndex(ep.Room, "/")+1:], ep.Key)
	}
	return ep, stop, err
}

// TestGateRustJitsiFake is the gate on the jitsifake target.
func TestGateRustJitsiFake(t *testing.T) {
	if *gateTargetName != targetJitsiFake {
		t.Skip("the Jitsi fake-room gate runs with -olcrtc.gate-target=jitsifake")
	}
	root := moduleRoot(t)
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, targetJitsiFake+map[bool]string{true: "-stalled", false: ""}[*gateJitsiStall]+
		map[bool]string{true: "-bosh", false: ""}[*gateJitsiBOSH])
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	hub, err := jitsifake.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	if *gateJitsiBOSH {
		// Only the plain listener refuses: the rust client's. A request is
		// held for the wait its client asked for, as Prosody holds it.
		hub.BOSH(true)
		hub.RefusePlainWebSocket(true)
		// And every login's answers cross, as a real Prosody's can.
		hub.BOSHAsProsody(true, gateBOSHSuccessLag)
	}
	if *gateJitsiStall {
		stop := make(chan struct{})
		t.Cleanup(func() { close(stop) })
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-time.After(5500 * time.Millisecond):
				}
				hub.StallAll(true)
				select {
				case <-stop:
					return
				case <-time.After(1500 * time.Millisecond):
				}
				hub.StallAll(false)
			}
		}()
	}
	if *gateJitsiTLS {
		// The rust flavour as the cli one: the room's link, https and wss,
		// the fake's certificate trusted by its pin (zz_rust_jitsilive_test.go).
		t.Setenv(rustTLSPinEnv, hub.Pin())
	}
	capture := StartCapture()
	defer capture.Stop()
	watch := newJitsiWatch(log.Writer())
	log.SetOutput(watch)
	// The JIDs the fake binds are ours to know: a log that carries one is a leak.
	for range 80 {
		var b [8]byte
		_, _ = rand.Read(b[:])
		user := hex.EncodeToString(b[:])
		hub.FixJID(user)
		watch.know(user)
	}
	local, err := NewLocalTarget(LocalOptions{
		ModuleRoot: root, WorkDir: t.TempDir(), JitsiHosts: []string{hub.Host()},
		Providers: []string{providerJitsi}, Transports: []string{transportData}, DNS: defaultDNS,
		Origin: startOrigin(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	target := &jitsiFakeTarget{Target: local, watch: watch, hub: hub}
	rec := NewRecorder(Report{Target: targetJitsiFake, Runner: runnerName()})

	registryMu.Lock()
	saved := registry
	registry = jitsiScenarios(saved, rec.Withhold)
	if *gateJitsiTLS {
		registry = tlsScenarios(saved, rec.Withhold)
	}
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
			clients = append(clients, mtsWatched{watch: watch.mtsLogWatch, Client: rustClient{
				bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
				extra: func(cfg *rustConfig) {
					cfg.Provider = providerJitsi
					cfg.IceLocalIP, cfg.Debug = "127.0.0.1", true
					if !*gateJitsiTLS {
						cfg.EngineExtra = map[string]string{"config_base": hub.Base(), "ws_url": hub.WSURL()}
					}
				}}})
		case cliFlavour:
			inproc := goJitsiClient{cli: cliClient{start: startBudget, stop: stopBudget}}
			clients = append(clients, mtsWatched{watch: watch.mtsLogWatch, Client: goBaseline(t, root, inproc,
				func(_ context.Context, ep Endpoint) (goJoin, error) {
					return goJoin{Provider: providerJitsi, RoomURL: ep.Room}, nil
				})})
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
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

	// The room, from the fake's side: every room the run opened.
	logins := map[string]int{}
	overBOSH := 0
	hub.EachRoom(func(name string, st jitsifake.State) {
		for _, said := range st.Transcripts {
			if *gateJitsiBOSH {
				// A client over BOSH opens no stream and enables no stream
				// management: the rest is compared.
				logins[jitsifake.JoinStanzas(said, name)]++
				if jitsifake.OverBOSH(said) {
					overBOSH++
				}
				continue
			}
			logins[jitsifake.Login(said, name)]++
		}
		t.Logf("room %d joins, %d initiates, %d accepts, %d hellos, %d relayed, %d dropped, video %v, classes %v",
			st.Joins, st.Initiates, st.Accepts, st.Hellos, st.Relayed, st.Dropped, st.Video, st.Classes)
		for _, c := range st.Channels {
			if c.Label != "JVB data channel" || c.Protocol != "http://jitsi.org/protocols/colibri" || !c.Ordered {
				t.Errorf("a channel %+v, want Jitsi's own label and protocol, ordered", c)
			}
		}
		if st.Hellos != len(st.Channels) {
			t.Errorf("%d hellos for %d channels", st.Hellos, len(st.Channels))
		}
		for k := range st.Classes {
			if strings.HasPrefix(k, "answer-refused") {
				t.Errorf("the bridge refused a client's answer: %s", k)
			}
		}
	})

	// What every client said to log in, Go's and Rust's, is one text.
	if len(logins) != 1 {
		for l, n := range logins {
			t.Errorf("%d clients logged in as:\n%s", n, l)
		}
	}

	// The BOSH pass: the rust client came over BOSH, and kept to it.
	if sessions := hub.BOSHSessions(); *gateJitsiBOSH {
		if overBOSH == 0 || len(sessions) == 0 {
			t.Errorf("%d clients joined over BOSH in %d sessions: the pass proved nothing", overBOSH, len(sessions))
		}
		var requests, ahead, crossed int
		var longest time.Duration
		for _, s := range sessions {
			requests += len(s.Requests)
			ahead += s.OutOfOrder
			if s.Crossed {
				crossed++
			}
			for _, d := range s.Held {
				longest = max(longest, d)
			}
			if _, consecutive := jitsifake.BOSHBodies(s); !consecutive {
				t.Errorf("a BOSH session's request ids do not go up by one (%d requests)", len(s.Requests))
			}
			if s.Refused != 0 || s.MaxInFlight > 2 {
				t.Errorf("a BOSH session: %d requests refused for their id, %d open at once (want 0 and at most 2)", s.Refused, s.MaxInFlight)
			}
			for _, r := range s.Requests {
				if ct := r.Header.Get("Content-Type"); ct != "text/xml; charset=utf-8" || r.Path != "/http-bind" {
					t.Errorf("a BOSH request to %q with Content-Type %q", r.Path, ct)
					break
				}
			}
		}
		t.Logf("bosh: %d clients over BOSH, %d sessions, %d requests, %d one ahead of their turn, the longest a request was held %s; in %d logins the features came ahead of <success/>",
			overBOSH, len(sessions), requests, ahead, longest.Round(100*time.Millisecond), crossed)
		if crossed == 0 && len(sessions) != 0 {
			t.Errorf("no login's features came ahead of its <success/> (%s late) in %d sessions: the pass did not try what a real Prosody's answers do",
				gateBOSHSuccessLag, len(sessions))
		}
		// S4 keeps the tunnel up for a minute with nothing to say over XMPP
		// but the client's ping: a poll is held far past the 10 s the Go
		// client waits for one (jitsifake's TestGoJitsiFakeBOSHHeldPoll).
		for _, c := range rep.Cells {
			if strings.HasSuffix(c.ID, "/"+rustFlavour+"/S4") && fmt.Sprint(c.Status) == "pass" && longest <= gateGoPollLimit {
				t.Errorf("S4 passed and no BOSH request was held longer than %s (the longest: %s): the fake did not hold a poll as a server does",
					gateGoPollLimit, longest.Round(100*time.Millisecond))
			}
		}
	} else if len(sessions) != 0 {
		t.Errorf("%d BOSH sessions in a run that is not the BOSH pass", len(sessions))
	}

	// The logs and the memory.
	for _, flavour := range flavours {
		lines, leaks, samples, heap := watch.seen(flavour)
		stanzas, shapes := watch.stanzas(flavour)
		switch flavour {
		case rustFlavour:
			if lines == 0 {
				t.Error("the log watch read no line of the rust client: its secret check checked nothing")
			}
			if leaks != 0 {
				t.Errorf("%d of the rust client's %d log lines carry the room's name or a JID:\n%s", leaks, lines,
					strings.Join(samples, "\n"))
			}
			if stanzas != 0 {
				t.Errorf("%d of the rust client's %d log lines carry a stanza:\n%s", stanzas, lines, strings.Join(shapes, "\n"))
			}
			t.Logf("rust client: %d log lines, %d with a secret, %d with a stanza; heap peak %d KiB (0: a build without heap-stats); VmHWM: the lines above",
				lines, leaks, stanzas, heap)
		case cliFlavour:
			t.Logf("go client: %d log lines, %d with the room or a JID, %d with a stanza (Go logs its room: not asserted); this process's VmHWM %d KiB; its own: the \"go client memory\" lines above",
				lines, leaks, stanzas, procStatusKB(os.Getpid(), "VmHWM:"))
		}
	}
}

// goJitsiClient is the Go public client in this process on the room's link:
// the baseline kept behind -olcrtc.gate-go-inproc.
type goJitsiClient struct{ cli cliClient }

// Name implements Client.
func (goJitsiClient) Name() string { return cliFlavour }

// Start implements Client.
func (g goJitsiClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	cfg := client.Config{
		Transport: ep.Transport, Provider: providerJitsi, RoomURL: ep.Room, ChannelID: ep.Channel, KeyHex: ep.Key,
		LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
	}
	c := g.cli
	c.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return c.Start(ctx, ep)
}

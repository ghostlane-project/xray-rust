// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the Jitsi carrier
// through a real deployment, and the certificate trust that run needs.
//
// TestGateRustJitsiLive is the gate's jitsilive target: the pinned local
// target (the Go server, cmd/olcrtc built with the test hooks, engine jitsi
// over datachannel) with the lab's own Jitsi Meet deployment as its Jitsi
// host: a docker-jitsi-meet (Prosody, Jicofo, JVB, web) started on this
// machine by olc/interop/jitsi-live/deploy.sh. Nothing here joins a public
// host: a host that does not resolve to this machine is refused before any
// request is made.
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestGateRustJitsiLive$' \
//	    -olcrtc.gate-target=jitsilive -olcrtc.gate-jitsi-live-host=<host> \
//	    -olcrtc.gate-rust-bin=<olc-client> -olcrtc.gate-flavours=cli,rust
//
// Both clients take the deployment as an app would: the room's link
// (https://host/room), its config.js over https, its XMPP over wss. The
// deployment's certificate is the lab's own CA's; the Go server and client
// trust it by SSL_CERT_FILE, the Rust client (built with the tls-test-pin
// feature, which no app build has) by OLC_TLS_TEST_PIN, the SHA-256 of the
// CA's certificate.
//
// The run is two parts, the cli flavour (the Go client, the control row: if
// it fails the deployment is wrong, not the port) and the rust flavour each:
//
//   - the rows: a fresh room with the server in it; the client joins (the
//     session is up), a nonce is echoed through its SOCKS port, 2 MiB come
//     down and 2 MiB go up, each checked by its SHA-256; the client leaves,
//     joins the same room again and does all of it once more; then the Rust
//     client, the pin taken away, gets no session in that room;
//   - the gate's cells S0-S6 on the same deployment, as the jitsifake target
//     runs them (-olcrtc.gate-jitsi-live-plan=false leaves them out). S7,
//     the memory cell, is the plain jitsifake run's: see tlsScenarios.
//
// -olcrtc.gate-jitsi-live-host=selftest runs the same code against the Go
// fake (jitsifake) over its TLS listener: the harness's own check on the
// build box, and the Rust client's https and wss path against the fake.
//
// TestGateRustJitsiTLSPin holds the Rust client's trust to the pin alone:
// against the fake's TLS listener it joins with the certificate's pin, and
// with none or another's it reaches neither config.js nor the WebSocket.

package gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/jitsifake"
)

var (
	gateJitsiTLS = flag.Bool("olcrtc.gate-jitsi-tls", false,
		"the jitsifake target's rust flavour over https and wss, the fake's certificate trusted by its pin "+
			"(a client built with the tls-test-pin feature); TestGateRustJitsiTLSPin runs only with it")
	gateJitsiLiveHost = flag.String("olcrtc.gate-jitsi-live-host", os.Getenv("OLCRTC_GATE_JITSI_LIVE_HOST"),
		"TestGateRustJitsiLive: the host of the lab's own Jitsi deployment on this machine; selftest is the Go fake")
	gateJitsiLivePlan = flag.Bool("olcrtc.gate-jitsi-live-plan", true,
		"TestGateRustJitsiLive: after the rows, the gate's cells S0-S7")
)

const (
	// targetJitsiLive is the gate target of the lab's own Jitsi deployment.
	targetJitsiLive = "jitsilive"
	// liveSelfTest is the host that stands for the Go fake.
	liveSelfTest = "selftest"
	// rustTLSPinEnv is what a Rust client built with tls-test-pin reads:
	// the SHA-256 (hex) of the one certificate its TLS dials trust.
	rustTLSPinEnv = "OLC_TLS_TEST_PIN"
	// liveRowBytes is a row's transfer, each way.
	liveRowBytes = 2 << 20
	// liveEchoBytes is the nonce a row echoes.
	liveEchoBytes = 48
	// liveRowsBudget bounds one flavour's rows: the server's join, two
	// client joins and the transfers.
	liveRowsBudget = 6 * time.Minute
	// liveStepBudget bounds one request of a row.
	liveStepBudget = 90 * time.Second
	// liveNoPinBudget is how long a Rust client without the pin gets to
	// show it has no session: several times what a join with it takes.
	liveNoPinBudget = 20 * time.Second
)

var (
	errNotThisMachine = errors.New("the host is not this machine's: the live target joins the lab's own deployment only")
	errLiveRow        = errors.New("live row")
)

// onThisMachine says whether every address host resolves to is loopback or
// one of this machine's own: the lab's deployment, never a public one.
func onThisMachine(host string, lookup func(string) ([]net.IP, error)) error {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	ips, err := lookup(name)
	if err != nil {
		return fmt.Errorf("%w: %w", errNotThisMachine, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: no address", errNotThisMachine)
	}
	own, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("%w: %w", errNotThisMachine, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			continue
		}
		mine := false
		for _, a := range own {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				mine = true
				break
			}
		}
		if !mine {
			return fmt.Errorf("%w: an address of it is on no interface here", errNotThisMachine)
		}
	}
	return nil
}

// TestOnThisMachineRefusesAHostElsewhere holds the live target's guard to
// what it names; it needs no network and no client binary.
func TestOnThisMachineRefusesAHostElsewhere(t *testing.T) {
	fixed := func(ips ...string) func(string) ([]net.IP, error) {
		return func(string) ([]net.IP, error) {
			out := make([]net.IP, 0, len(ips))
			for _, ip := range ips {
				out = append(out, net.ParseIP(ip))
			}
			return out, nil
		}
	}
	var mine string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
			mine = n.IP.String()
			break
		}
	}
	for _, c := range []struct {
		name, host string
		ips        []string
		ok         bool
	}{
		{"loopback", "meet.lab.test", []string{"127.0.0.1"}, true},
		{"loopback with a port", "meet.lab.test:8443", []string{"127.0.0.1"}, true},
		{"IPv6 loopback", "meet.lab.test", []string{"::1"}, true},
		{"a documentation address", "meet.lab.test", []string{"192.0.2.10"}, false},
		{"one address here and one elsewhere", "meet.lab.test", []string{"127.0.0.1", "192.0.2.10"}, false},
		{"no address", "meet.lab.test", nil, false},
	} {
		err := onThisMachine(c.host, fixed(c.ips...))
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && !errors.Is(err, errNotThisMachine) {
			t.Errorf("%s: %v is not errNotThisMachine", c.name, err)
		}
	}
	if mine != "" {
		if err := onThisMachine("meet.lab.test", fixed(mine)); err != nil {
			t.Errorf("this machine's own address %s refused: %v", mine, err)
		}
	}
	failing := func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
	if err := onThisMachine("meet.lab.test", failing); !errors.Is(err, errNotThisMachine) {
		t.Errorf("a name that does not resolve: %v", err)
	}
}

// liveOrigin is what the rows fetch through the tunnel: an echo, 2 MiB to
// pull and a sink that says what it swallowed. It listens on loopback, which
// the local target's server may reach (OLCRTC_TEST_ALLOW_PRIVATE_TARGETS).
type liveOrigin struct {
	base string
	srv  *http.Server
}

// liveStream is the bytes a row moves: ChaCha8 from a fixed seed, so each
// end knows what the other should have got without holding it.
func liveStream() io.Reader {
	var seed [32]byte
	copy(seed[:], "olc jitsi-live row transfer seed")
	return io.LimitReader(mrand.NewChaCha8(seed), liveRowBytes)
}

// liveStreamSum is the SHA-256 of liveStream.
func liveStreamSum() string {
	h := sha256.New()
	_, _ = io.Copy(h, liveStream())
	return hex.EncodeToString(h.Sum(nil))
}

func startLiveOrigin(t *testing.T) *liveOrigin {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET /down", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(liveRowBytes))
		_, _ = io.Copy(w, liveStream())
	})
	mux.HandleFunc("POST /up", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "%d %s", n, hex.EncodeToString(h.Sum(nil)))
	})
	o := &liveOrigin{base: "http://" + ln.Addr().String(), srv: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}}
	go func() { _ = o.srv.Serve(ln) }()
	t.Cleanup(func() { _ = o.srv.Close() })
	return o
}

// row is one join's work through the SOCKS port at socks: the echo, the
// pull and the push, each whole and each within liveStepBudget.
func (o *liveOrigin) row(ctx context.Context, socks string) error {
	dial, err := SocksDialer(socks)
	if err != nil {
		return fmt.Errorf("%w: socks: %w", errLiveRow, err)
	}
	hc := HTTPClient(dial, liveStepBudget)
	defer hc.CloseIdleConnections()
	do := func(method, path string, body io.Reader, size int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, o.base+path, body)
		if err != nil {
			return nil, err
		}
		if size > 0 {
			req.ContentLength = size
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%w: %s", ErrHTTPStatus, resp.Status)
		}
		if path == "/down" {
			h := sha256.New()
			n, err := io.Copy(h, resp.Body)
			if err != nil {
				return nil, fmt.Errorf("after %d bytes: %w", n, err)
			}
			return []byte(fmt.Sprintf("%d %s", n, hex.EncodeToString(h.Sum(nil)))), nil
		}
		return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	}
	nonce := make([]byte, liveEchoBytes)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("%w: %w", errLiveRow, err)
	}
	got, err := do(http.MethodPost, "/echo", bytes.NewReader(nonce), liveEchoBytes)
	if err != nil {
		return fmt.Errorf("%w: echo: %w", errLiveRow, err)
	}
	if !bytes.Equal(got, nonce) {
		return fmt.Errorf("%w: echo: %d bytes came back, not the %d sent", errLiveRow, len(got), len(nonce))
	}
	want := fmt.Sprintf("%d %s", liveRowBytes, liveStreamSum())
	if got, err = do(http.MethodGet, "/down", http.NoBody, 0); err != nil {
		return fmt.Errorf("%w: %d bytes down: %w", errLiveRow, liveRowBytes, err)
	}
	if string(got) != want {
		return fmt.Errorf("%w: down: the client read %q, the origin sent %q", errLiveRow, got, want)
	}
	if got, err = do(http.MethodPost, "/up", liveStream(), liveRowBytes); err != nil {
		return fmt.Errorf("%w: %d bytes up: %w", errLiveRow, liveRowBytes, err)
	}
	if string(got) != want {
		return fmt.Errorf("%w: up: the origin read %q, the client sent %q", errLiveRow, got, want)
	}
	return nil
}

// TestLiveOriginRowIsWholeOrFails holds the rows' check to what it names,
// through a SOCKS port that is this process's own (no tunnel, no client): a
// row over a straight path passes, and one whose bytes are cut short or
// altered on the way fails.
func TestLiveOriginRowIsWholeOrFails(t *testing.T) {
	o := startLiveOrigin(t)
	if len(liveStreamSum()) != 64 {
		t.Fatalf("the stream's sum %q", liveStreamSum())
	}
	n, err := io.Copy(io.Discard, liveStream())
	if err != nil || n != liveRowBytes {
		t.Fatalf("the stream is %d bytes (%v), want %d", n, err, liveRowBytes)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, c := range []struct {
		name string
		mode int
		want string
	}{
		{"straight", proxyStraight, ""},
		{"a byte of the pull flipped", proxyFlipDown, "down"},
		{"the push cut short", proxyCutUp, "up"},
	} {
		socks := startTestSocks(t, c.mode)
		err := o.row(ctx, socks)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !errors.Is(err, errLiveRow) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want a failed %s", c.name, err, c.want)
		}
	}
}

const (
	proxyStraight = iota
	proxyFlipDown
	proxyCutUp
)

// startTestSocks is a SOCKS5 CONNECT proxy on loopback for the row's own
// test: mode says what it does to the bytes it carries.
func startTestSocks(t *testing.T, mode int) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSocks(c, mode)
		}
	}()
	return ln.Addr().String()
}

func serveTestSocks(c net.Conn, mode int) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, head[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		a := make([]byte, 4)
		if _, err := io.ReadFull(c, a); err != nil {
			return
		}
		host = net.IP(a).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		a := make([]byte, l[0])
		if _, err := io.ReadFull(c, a); err != nil {
			return
		}
		host = string(a)
	default:
		return
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(c, p); err != nil {
		return
	}
	up, err := net.DialTimeout("tcp4", net.JoinHostPort(host, fmt.Sprint(int(p[0])<<8|int(p[1]))), 5*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { // the client's bytes, up
		defer func() { done <- struct{}{} }()
		if mode == proxyCutUp {
			_, _ = io.CopyN(up, c, liveRowBytes/2)
			_ = up.Close()
			return
		}
		_, _ = io.Copy(up, c)
	}()
	go func() { // the origin's bytes, down
		defer func() { done <- struct{}{} }()
		if mode != proxyFlipDown {
			_, _ = io.Copy(c, up)
			return
		}
		buf := make([]byte, 32<<10)
		var seen int64
		for {
			n, err := up.Read(buf)
			if n > 0 {
				// One byte, deep in a 2 MiB body: the echo's reply is far shorter.
				if at := int64(liveRowBytes / 2); seen <= at && at < seen+int64(n) {
					buf[at-seen] ^= 0x01
				}
				seen += int64(n)
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
}

// tlsScenarios is the jitsifake target's registry without S7, for a run whose
// Rust client is the test build with the signalling's TLS stack in it
// (shaped-tls and tls-test-pin). S7 on the rust flavour weighs the client's
// whole process from zero against a bound of 19 MiB, and it is judged in
// jitsi.sh's plain gate set with a client built without that stack: 18.8 MiB
// of VmHWM there (2026-11-21). The test build is 21.6 MiB on the fake
// (15.3 MiB of it the binary's own pages, 6.2 MiB anonymous, heap peak
// 3.4 MiB), so the cell would fail on every deployment and say nothing of
// any. The client's memory lines are logged by every run all the same.
func tlsScenarios(all []Scenario, withhold func(...string)) []Scenario {
	out := jitsiScenarios(all, withhold)
	for i := range out {
		if out[i].ID == "S7" {
			out[i].Applies = func(Target, Pair, string) bool { return false }
		}
	}
	return out
}

// liveRows runs one flavour's rows: the server in a fresh room of the
// deployment, the client joining it twice.
func liveRows(t *testing.T, target Target, client Client, origin *liveOrigin, capture *Capture, dir string, secrets *[]string) {
	t.Helper()
	pair := Pair{providerJitsi, transportData}
	ctx, cancel := context.WithTimeout(runContext(t), liveRowsBudget)
	defer cancel()
	rowDir := filepath.Join(dir, "rows-"+client.Name())
	if err := os.MkdirAll(rowDir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	cell := capture.Begin()
	defer func() {
		if err := cell.WriteScrubbed(filepath.Join(rowDir, "client.log"), *secrets...); err != nil {
			t.Logf("rows/%s: the client's log was not kept: %v", client.Name(), err)
		}
	}()
	began := time.Now()
	ep, stop, err := target.Open(ctx, pair, rowDir, OpenOptions{})
	if err != nil {
		t.Fatalf("the server did not join its room: %v", err)
	}
	defer stop()
	*secrets = append(*secrets, ep.Secrets()...)
	t.Logf("rows/%s: the server joined its room in %s", client.Name(), time.Since(began).Round(time.Millisecond))
	for join := 1; join <= 2; join++ {
		began = time.Now()
		tun, err := client.Start(ctx, ep)
		if err != nil {
			t.Fatalf("join %d: the session did not come up: %v", join, err)
		}
		up := time.Since(began)
		began = time.Now()
		err = origin.row(ctx, tun.SocksAddr)
		took := time.Since(began)
		tun.Stop()
		if err != nil {
			t.Fatalf("join %d: session up in %s, then: %v", join, up.Round(time.Millisecond), err)
		}
		t.Logf("rows/%s: join %d: session up in %s; the echo, %d bytes down and %d bytes up whole in %s; left",
			client.Name(), join, up.Round(time.Millisecond), liveRowBytes, liveRowBytes, took.Round(time.Millisecond))
	}
	// The Rust client's trust is the pin and nothing else: in the room it
	// has just joined twice, with the server still there, it gets no session
	// once the pin is taken away (the variable is this subtest's to change).
	if rc, ok := client.(rustClient); ok {
		t.Setenv(rustTLSPinEnv, "")
		rc.start = liveNoPinBudget
		began = time.Now()
		tun, err := rc.Start(ctx, ep)
		if err == nil {
			tun.Stop()
			t.Fatalf("without %s the session came up in %s: something else trusts the deployment's certificate",
				rustTLSPinEnv, time.Since(began).Round(time.Millisecond))
		}
		t.Logf("rows/%s: without %s, no session in %s (%v)", client.Name(), rustTLSPinEnv, liveNoPinBudget, err)
	}
}

// TestGateRustJitsiLive is the gate on the jitsilive target.
func TestGateRustJitsiLive(t *testing.T) {
	if *gateTargetName != targetJitsiLive {
		t.Skip("the live Jitsi gate runs with -olcrtc.gate-target=jitsilive")
	}
	root := moduleRoot(t)
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, targetJitsiLive)
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSpace(*gateJitsiLiveHost)
	iceLocal := ""
	var hub *jitsifake.Hub
	switch host {
	case "":
		t.Fatal("name the lab's host: -olcrtc.gate-jitsi-live-host (or selftest for the Go fake)")
	case liveSelfTest:
		if hub, err = jitsifake.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(hub.Close)
		host, iceLocal = hub.Host(), "127.0.0.1"
		t.Setenv(rustTLSPinEnv, hub.Pin())
	default:
		if err := onThisMachine(host, net.LookupIP); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"SSL_CERT_FILE", rustTLSPinEnv} {
			if os.Getenv(name) == "" {
				t.Fatalf("%s is not set: the deployment's certificate is the lab's own, and each client has to be told it", name)
			}
		}
	}
	capture := StartCapture()
	defer capture.Stop()
	local, err := NewLocalTarget(LocalOptions{
		ModuleRoot: root, WorkDir: t.TempDir(), JitsiHosts: []string{host},
		Providers: []string{providerJitsi}, Transports: []string{transportData}, DNS: defaultDNS,
		Origin: startOrigin(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	rust := rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
		extra: func(cfg *rustConfig) {
			cfg.Provider = providerJitsi
			cfg.IceLocalIP, cfg.Debug = iceLocal, true
		}}
	var clients []Client
	flavours := splitList(*gateFlavours)
	for _, name := range flavours {
		switch name {
		case rustFlavour:
			clients = append(clients, rust)
		case cliFlavour:
			inproc := goJitsiClient{cli: cliClient{start: startBudget, stop: stopBudget}}
			clients = append(clients, goBaseline(t, root, inproc,
				func(_ context.Context, ep Endpoint) (goJoin, error) {
					return goJoin{Provider: providerJitsi, RoomURL: ep.Room}, nil
				}))
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
	secrets := []string{}

	// The rows, a flavour at a time.
	origin := startLiveOrigin(t)
	for _, c := range clients {
		t.Run("rows/"+c.Name(), func(t *testing.T) {
			liveRows(t, local, c, origin, capture, dir, &secrets)
		})
	}
	if !*gateJitsiLivePlan {
		return
	}

	// The gate's cells, as the jitsifake target runs them over TLS.
	rec := NewRecorder(Report{Target: targetJitsiLive, Runner: runnerName()})
	registryMu.Lock()
	saved := registry
	registry = tlsScenarios(saved, rec.Withhold)
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
	opt := Options{
		Target: local, Clients: clients, Thresholds: Local, Dir: dir, Recorder: rec, Capture: capture,
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
		t.Logf("cell %s: %s %v %q", c.ID, c.Status, c.Metrics, c.Failures)
	}
	for _, id := range unreported(rep) {
		t.Errorf("%s: %s", id, reasonDidNotRun)
	}
	if why := gateFailure(rep); why != "" {
		t.Errorf("gate: %s; the report goes to %s", why, opt.ReportPath)
	}
}

// TestGateRustJitsiTLSPin is the Rust client's certificate trust on the
// fake's TLS listener: the pin, and nothing else.
func TestGateRustJitsiTLSPin(t *testing.T) {
	if *gateTargetName != targetJitsiFake || !*gateJitsiTLS {
		t.Skip("the pin test runs with -olcrtc.gate-target=jitsifake -olcrtc.gate-jitsi-tls")
	}
	hub, err := jitsifake.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	other := sha256.Sum256([]byte("another certificate"))
	for _, c := range []struct {
		name, pin string
		joins     bool
	}{
		{"no pin", "", false},
		{"another certificate's pin", hex.EncodeToString(other[:]), false},
		{"the certificate's pin", hub.Pin(), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(rustTLSPinEnv, c.pin)
			name, err := gateName()
			if err != nil {
				t.Fatal(err)
			}
			key, err := NewKey()
			if err != nil {
				t.Fatal(err)
			}
			room := hub.Named(name)
			ep := Endpoint{Provider: providerJitsi, Transport: transportData, Room: "https://" + hub.Host() + "/" + name,
				Key: key, DNS: defaultDNS}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			child, err := startRust(ctx, *gateRustBin, ep, func(cfg *rustConfig) {
				cfg.Provider = providerJitsi
				cfg.IceLocalIP, cfg.Debug = "127.0.0.1", true
			})
			if err != nil {
				t.Fatal(err)
			}
			defer child.halt(stopBudget, nil)
			// Alone in the room the client joins the conference and waits
			// for a peer: the join is what the fake counts. A client that
			// may not trust the listener gets 15 s to show it does not.
			wait := 15 * time.Second
			if c.joins {
				wait = 40 * time.Second
			}
			deadline := time.Now().Add(wait)
			var st jitsifake.State
			for time.Now().Before(deadline) {
				if st = room.State(); st.Joins > 0 {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			st = room.State()
			t.Logf("%s: %d joins, %d config.js requests, %d WebSocket upgrades", c.name, st.Joins, len(st.Config), len(st.Upgrades))
			switch {
			case c.joins && st.Joins == 0:
				t.Errorf("the client did not join over TLS with the certificate's pin")
			case c.joins && len(st.Upgrades) == 0:
				t.Errorf("a join with no WebSocket upgrade recorded")
			case !c.joins && (st.Joins != 0 || len(st.Config) != 0 || len(st.Upgrades) != 0):
				t.Errorf("a client without the certificate's pin got through TLS: %d joins, %d config.js requests, %d upgrades",
					st.Joins, len(st.Config), len(st.Upgrades))
			}
		})
	}
}

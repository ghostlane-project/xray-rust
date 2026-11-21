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
// -olcrtc.gate-jitsi-live-first puts one step before both: the Rust client
// alone in a room of its own, on a deployment nobody has joined yet (see
// liveFirst: it is how a real Jicofo comes to ask the Rust client, and not
// the Go server, what it can do).
//
// -olcrtc.gate-jitsi-live-bosh puts the Rust client's XMPP over BOSH, through
// the deployment's own front and Prosody's mod_bosh, in one of two ways:
//
//   - client: the deployment is as it started. The Rust client is told to
//     dial its WebSocket at a path the front does not upgrade
//     (liveClosedWebSocket), so it goes on to the BOSH URL config.js names,
//     as it would on a deployment with no WebSocket. The Go server keeps its
//     WebSocket, so the rows and the cells have a steady exit: this is the
//     mode the cells run in;
//   - deployment: deploy.sh bosh-only has closed the deployment's WebSocket
//     and nobody has one, the Go server and the Go client included. The Go
//     library's BOSH is not steady against a real Prosody: a login whose two
//     answers reach it out of their order fails (one in four in the lab run
//     44935236619, see goBOSHRace), and it hangs up on a poll held 10 s. So a
//     Go engine's start is tried again when it failed that way, and the mode
//     is for the rows alone. The Rust client's start is never tried again.
//
// In both a start of the Rust client whose log does not say it went over
// BOSH is a failed start (rustClient.overBOSH), and deploy.sh bosh reads the
// same from the deployment's own logs afterwards.
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
	"slices"
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
	gateJitsiLiveBOSH = flag.String("olcrtc.gate-jitsi-live-bosh", "",
		"TestGateRustJitsiLive with the Rust client's XMPP over BOSH: client (the deployment as it started; the Rust "+
			"client's WebSocket dial goes to a path the front does not upgrade, the exit keeps its WebSocket) or "+
			"deployment (deploy.sh bosh-only has closed the WebSocket for everyone; a Go engine's start is tried "+
			"again when its login failed the way the Go library's does, the Rust client's never)")
	gateJitsiLiveFirst = flag.Bool("olcrtc.gate-jitsi-live-first", false,
		"TestGateRustJitsiLive: before the rows, the Rust client joins a room of its own with no server in it; "+
			"on a deployment nobody has joined, Jicofo asks it for its features (deploy.sh first reads what came of it)")
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
	// liveFirstPrefix starts the name of the room the Rust client is alone
	// in; deploy.sh first finds the room in the deployment's logs by it.
	liveFirstPrefix = "first-"
	// liveFirstBudget is how long the Rust client stays there: Jicofo's
	// question comes with the join, within a second.
	liveFirstBudget = 12 * time.Second
	// liveBOSHClient and liveBOSHDeployment are -olcrtc.gate-jitsi-live-bosh.
	liveBOSHClient     = "client"
	liveBOSHDeployment = "deployment"
	// liveClosedWebSocket is where the Rust client dials its WebSocket in
	// the client mode: a path no front upgrades (docker-jitsi-meet's answers
	// it as a room's page, the Go fake with 404).
	liveClosedWebSocket = "/xmpp-websocket-closed"
	// liveGoBOSHTries is how many starts a Go engine gets in the deployment
	// mode. One login in four failed in the lab run, so five in a row fail
	// once in a thousand.
	liveGoBOSHTries = 5
	// liveSelfTestGoHold caps how long the Go fake holds a request in the
	// deployment mode's selftest: under the 10 s after which a Go engine
	// hangs up on a poll (gateGoPollLimit).
	liveSelfTestGoHold = 5 * time.Second
	// goBOSHRaceWords is in what a Go engine says when its BOSH login read
	// the stream's features before <success/> and then waited for them (the
	// library's own words; internal/xmpp/conn.go, authBOSH).
	goBOSHRaceWords = "post-auth features"
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

// goBOSHRace says whether a failed start is the Go library's own: its BOSH
// login against a real Prosody, the two answers after the SASL request read
// out of their order.
func goBOSHRace(err error) bool {
	return err != nil && strings.Contains(err.Error(), goBOSHRaceWords)
}

// tryAgain runs start until it passes, at most tries times. A failed start
// is tried again only when known says its failure is the one being allowed
// for; any other failure is the run's, at once.
func tryAgain(tries int, known func(error) bool, logf func(string, ...any), what string, start func() error) error {
	for n := 1; ; n++ {
		err := start()
		if err == nil || n >= tries || !known(err) {
			return err
		}
		logf("%s: start %d of %d failed the way the Go library's BOSH login does (%v): again", what, n, tries, err)
	}
}

// TestTryAgainIsForTheKnownFailureAlone holds the deployment mode's second
// tries to what they name; it needs no network and no client binary.
func TestTryAgainIsForTheKnownFailureAlone(t *testing.T) {
	race := errors.New("server exited before the link connected; last server line: server: failed to connect link: " +
		"session connect: jitsi join muc: xmpp dial: post-auth features: bosh connection closed")
	other := errors.New("server exited before the link connected; last server line: server: failed to connect link: " +
		"session connect: jitsi join muc: allocate focus: context deadline exceeded")
	if !goBOSHRace(race) || goBOSHRace(other) || goBOSHRace(nil) {
		t.Fatalf("goBOSHRace: the library's failure %v, another %v, none %v; want true, false, false",
			goBOSHRace(race), goBOSHRace(other), goBOSHRace(nil))
	}
	for _, c := range []struct {
		name  string
		tries int
		fails []error // what each start returns, in order; nil after them
		calls int
		want  error
	}{
		{"a start that passes is run once", 5, nil, 1, nil},
		{"another failure is not tried again", 5, []error{other}, 1, other},
		{"the known failure is tried again until a start passes", 5, []error{race, race}, 3, nil},
		{"the known failure and then another: the other ends it", 5, []error{race, other}, 2, other},
		{"the known failure every time ends at the last try", 3, []error{race, race, race, race}, 3, race},
		{"one try is one start", 1, []error{race}, 1, race},
	} {
		calls, said := 0, 0
		err := tryAgain(c.tries, goBOSHRace, func(string, ...any) { said++ }, c.name, func() error {
			calls++
			if calls <= len(c.fails) {
				return c.fails[calls-1]
			}
			return nil
		})
		if calls != c.calls || !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: %d starts and %v, want %d and %v", c.name, calls, err, c.calls, c.want)
		}
		if said != calls-1 {
			t.Errorf("%s: %d starts and %d of them said why they came again", c.name, calls, said)
		}
	}
}

// TestRustStartOverBOSHNeedsTheClientsWord holds rustClient.overBOSH to what
// it names, with a script in the client's place: a client that says its
// session is up without having said its XMPP went over BOSH has not started,
// and one that said so has. It needs no network and no client binary.
func TestRustStartOverBOSHNeedsTheClientsWord(t *testing.T) {
	said := "echo 'jitsi: the WebSocket did not dial (handshake failed); " + rustBOSHMarker + "' >&2\n"
	for _, c := range []struct {
		name, lines string
		over, ok    bool
	}{
		{"over BOSH asked, the client said so", said, true, true},
		{"over BOSH asked, the client did not say so", "", true, false},
		{"over BOSH not asked, the client did not say so", "", false, true},
		{"over BOSH not asked, the client said so", said, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "client.sh")
			script := "#!/bin/sh\n" + c.lines + "echo '" + rustListenMarker + "127.0.0.1:9' >&2\nexec sleep 30\n"
			if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // a test's own script
				t.Fatal(err)
			}
			rc := rustClient{bin: bin, start: 10 * time.Second, stop: 2 * time.Second, overBOSH: c.over}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			tun, err := rc.Start(ctx, Endpoint{Provider: providerJitsi, Transport: transportData,
				Room: "https://meet.lab.test/room", Key: strings.Repeat("00", 32), DNS: defaultDNS})
			if err == nil {
				tun.Stop()
			}
			switch {
			case c.ok && err != nil:
				t.Errorf("the start failed: %v", err)
			case !c.ok && err == nil:
				t.Error("the start passed though the client never said its XMPP went over BOSH")
			case !c.ok && !errors.Is(err, errNotOverBOSH):
				t.Errorf("the start failed with %v, want errNotOverBOSH", err)
			}
		})
	}
}

// liveRows runs one flavour's rows: the server in a fresh room of the
// deployment, the client joining it twice. goTries is how many starts a Go
// engine gets (the server, and the client of the cli flavour): one, or
// liveGoBOSHTries in the deployment mode, where a start is tried again when
// it failed by goBOSHRace. The Rust client always gets one.
func liveRows(t *testing.T, target Target, client Client, origin *liveOrigin, capture *Capture, dir string, secrets *[]string, goTries int) {
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
	_, isRust := client.(rustClient)
	clientTries := goTries
	if isRust {
		clientTries = 1
	}
	began := time.Now()
	var ep Endpoint
	var stop func()
	err := tryAgain(goTries, goBOSHRace, t.Logf, "rows/"+client.Name()+": the server's join", func() error {
		began = time.Now()
		var err error
		ep, stop, err = target.Open(ctx, pair, rowDir, OpenOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("the server did not join its room: %v", err)
	}
	defer stop()
	*secrets = append(*secrets, ep.Secrets()...)
	t.Logf("rows/%s: the server joined its room in %s", client.Name(), time.Since(began).Round(time.Millisecond))
	for join := 1; join <= 2; join++ {
		var tun *Tunnel
		// The Go client's reason is in its log, not in its start's error:
		// the failure is the known one when a new line of the log says so.
		seen := cell.Count(goBOSHRaceWords)
		err := tryAgain(clientTries, func(error) bool {
			n := cell.Count(goBOSHRaceWords)
			known := n > seen
			seen = n
			return known
		}, t.Logf, fmt.Sprintf("rows/%s: join %d", client.Name(), join), func() error {
			began = time.Now()
			var err error
			tun, err = client.Start(ctx, ep)
			return err
		})
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

// liveFirst is the Rust client alone in a room of its own, before any Go
// engine has joined the deployment. Jicofo reads what a client can do from
// its answer to a disco#info query, and asks only the first participant that
// shows a caps hash it has not seen; every later one gets the remembered
// answer. In the rows that first participant is always the Go server: it
// joins before the client and shows the same hash. Here it is the Rust
// client. Nothing serves the room and a lone participant gets no offer, so
// there is no session to wait for: the step is the join and the stay. What
// Jicofo made of the answer is in the deployment's logs, and deploy.sh first
// is the check: who was asked, and which features every participant of the
// rows was then given.
func liveFirst(t *testing.T, rc rustClient, host string, capture *Capture, dir string, secrets *[]string) {
	t.Helper()
	var name [6]byte
	var key [32]byte
	for _, b := range [][]byte{name[:], key[:]} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	room := liveFirstPrefix + hex.EncodeToString(name[:])
	ep := Endpoint{Provider: providerJitsi, Transport: transportData, Room: "https://" + host + "/" + room,
		Key: hex.EncodeToString(key[:]), DNS: defaultDNS}
	*secrets = append(*secrets, ep.Key)
	stepDir := filepath.Join(dir, "first-"+rc.Name())
	if err := os.MkdirAll(stepDir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	cell := capture.Begin()
	defer func() {
		if err := cell.WriteScrubbed(filepath.Join(stepDir, "client.log"), *secrets...); err != nil {
			t.Logf("first/%s: the client's log was not kept: %v", rc.Name(), err)
		}
	}()
	ctx, cancel := context.WithTimeout(runContext(t), 3*liveFirstBudget)
	defer cancel()
	rc.start = liveFirstBudget
	tun, err := rc.Start(ctx, ep)
	if err == nil {
		tun.Stop()
		t.Fatalf("alone in %s the client said its session was up: nothing serves that room", room)
	}
	t.Logf("first/%s: alone in %s for %s, no session as nothing serves it (%v)", rc.Name(), room, liveFirstBudget, err)
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
	bosh := strings.TrimSpace(*gateJitsiLiveBOSH)
	goTries := 1
	switch bosh {
	case "", liveBOSHClient:
	case liveBOSHDeployment:
		goTries = liveGoBOSHTries
		if *gateJitsiLivePlan {
			t.Fatal("-olcrtc.gate-jitsi-live-bosh=deployment is for the rows (-olcrtc.gate-jitsi-live-plan=false): " +
				"a Go server over BOSH hangs up on a poll held 10 s, and no cell would say anything of the Rust client")
		}
	default:
		t.Fatalf("-olcrtc.gate-jitsi-live-bosh=%q: %s or %s", bosh, liveBOSHClient, liveBOSHDeployment)
	}
	if bosh != "" {
		// Each mode's artifacts in a directory of its own: a job runs both.
		dir += "-bosh-" + bosh
		if err := os.MkdirAll(dir, artifactsPerm); err != nil {
			t.Fatal(err)
		}
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
		switch bosh {
		case liveBOSHClient:
			// The fake's WebSocket stays, for the Go server; the stream's
			// features and a login's answers as a real Prosody's.
			hub.BOSH(true)
			hub.BOSHAsProsody(true, gateBOSHSuccessLag)
		case liveBOSHDeployment:
			// Nobody has a WebSocket. The Go engines log in over BOSH too,
			// so the features come the way the Go library survives, and no
			// request is held as long as it would hang up on.
			hub.BOSH(true)
			hub.RefuseWebSocket(true)
			hub.BOSHHold(liveSelfTestGoHold, liveSelfTestGoHold)
		}
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
	rust := rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf, overBOSH: bosh != "",
		extra: func(cfg *rustConfig) {
			cfg.Provider = providerJitsi
			cfg.IceLocalIP, cfg.Debug = iceLocal, true
			if bosh == liveBOSHClient {
				cfg.EngineExtra = map[string]string{"ws_url": "wss://" + host + liveClosedWebSocket}
			}
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

	if *gateJitsiLiveFirst {
		if hub != nil {
			t.Fatal("-olcrtc.gate-jitsi-live-first is for a deployment: the Go fake asks no client for its features")
		}
		t.Run("first/"+rust.Name(), func(t *testing.T) {
			liveFirst(t, rust, host, capture, dir, &secrets)
		})
	}

	// The rows, a flavour at a time.
	origin := startLiveOrigin(t)
	for _, c := range clients {
		t.Run("rows/"+c.Name(), func(t *testing.T) {
			liveRows(t, local, c, origin, capture, dir, &secrets, goTries)
		})
	}
	if hub != nil && bosh != "" {
		liveSelfTestBOSH(t, hub, bosh)
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

// liveSelfTestBOSH reads from the Go fake what the rows did over BOSH: the
// selftest's stand-in for deploy.sh bosh on a deployment's logs.
func liveSelfTestBOSH(t *testing.T, hub *jitsifake.Hub, mode string) {
	t.Helper()
	sessions := hub.BOSHSessions()
	var rust, crossed int
	for _, s := range sessions {
		if len(s.Requests) != 0 && !strings.HasPrefix(s.Requests[0].Header.Get("User-Agent"), "Go-http-client/") {
			rust++
		}
		if s.Crossed {
			crossed++
		}
	}
	t.Logf("selftest, bosh=%s: %d BOSH sessions on the fake, %d of them the Rust client's; in %d logins the features came ahead of <success/>",
		mode, len(sessions), rust, crossed)
	if slices.Contains(splitList(*gateFlavours), rustFlavour) && rust < 2 {
		t.Errorf("%d BOSH sessions of the Rust client on the fake, want its two joins' at least", rust)
	}
	if mode == liveBOSHClient && rust != len(sessions) {
		t.Errorf("%d of %d BOSH sessions are not the Rust client's: the Go engines were to keep their WebSocket",
			len(sessions)-rust, len(sessions))
	}
	if mode == liveBOSHClient && rust != 0 && crossed == 0 {
		t.Errorf("no login's features came ahead of its <success/>: the fake was to cross them")
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

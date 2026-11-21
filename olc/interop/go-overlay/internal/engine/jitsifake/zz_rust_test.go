//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T2 for the Jitsi
// carrier, one client's join. The fake of a Jitsi Meet deployment with the
// Rust client (olc-client, provider jitsi over datachannel) in a room as a
// child process, read against the Go engine at the pin in the same fake:
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test -tags olcrtc_interop ./internal/engine/jitsifake -run '^TestRustJitsi' -v
//
//   - TestRustJitsiJoinIsTheGoClients: over the WebSocket, what the client
//     says from its stream open to its room disco is what the Go engine says;
//   - TestRustJitsiAWebSocketThatDialsIsTakenThoughBOSHIsNamed;
//   - TestRustJitsiOverBOSHJoinsAsTheGoClient: the WebSocket refused and
//     config.js naming /http-bind, the client's requests from the session
//     request to the room disco are the Go client's, body for body; no stream
//     open and no stream management; its own User-Agent, the one it asked
//     config.js with; ids up by one; the terminate at its stop;
//   - TestRustJitsiOverBOSHReachesTheBridgeBesideAGoEngine: the bridge's
//     offer comes down a poll and the client's answer goes up a request, with
//     a Go engine in the room on its WebSocket; a poll held past the 10 s the
//     Go client gives one (TestGoJitsiFakeBOSHHeldPoll) brings its stanza and
//     the client answers it in the next request;
//   - TestRustJitsiARefusedWebSocketWithNoBOSHNamedIsTheWebSocketsFailure.
//
// There is no olcRTC server in these rooms, so a client's handshake never
// ends: it gives up 15 s after its bridge opened and leaves. Each test reads
// what it needs before that. The tunnel itself over BOSH is the gate's BOSH
// pass (internal/gate/zz_rust_jitsifake_test.go, -olcrtc.gate-jitsi-bosh).

package jitsifake

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
)

const (
	// rustBinEnv names the Rust client binary.
	rustBinEnv = "OLCRTC_GATE_RUST_BIN"
	// rustLifetime bounds every client process a test starts.
	rustLifetime = 3 * time.Minute
	// rustStopGrace is how long a stopped client has to say goodbye.
	rustStopGrace = 5 * time.Second
	// rustTraceEnv, set, logs every client's log (stamped to the millisecond
	// as it arrived) whether or not its test failed.
	rustTraceEnv = "OLCRTC_GATE_RUST_TRACE"
	// rustGoUserAgent is what Go's net/http calls itself over HTTP/1.1: the
	// library names no sender on its BOSH requests (vectors: jitsi/bosh.json).
	rustGoUserAgent = "Go-http-client/1.1"
	// rustGoPollLimit is how long the Go engine waits for a poll's answer
	// (internal/protect/protect.go, the response header timeout).
	rustGoPollLimit = 10 * time.Second
	// rustTerminate is a session's last request, with its ids replaced as
	// BOSHBodies does.
	rustTerminate = `<body rid="RID" sid="SID" type="terminate" xmlns="` + boshNS + `"/>`
)

// stanzaInLog is what a stanza of the join, a BOSH body or a JID of the
// fake's domain looks like in a log (the gate's stanzaPattern, and the body).
var stanzaInLog = regexp.MustCompile(`<(iq|presence|message|open|auth|stream:|jingle|success|enabled|bind|body)[ >/:]|@meet\.jitsi|muc\.meet\.jitsi`)

// rustKey is the client's key: any 32 bytes, no server holds it.
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
// as a Jitsi join sets it.
type rustConfig struct {
	URL         string            `json:"url"`
	Provider    string            `json:"provider"`
	Key         string            `json:"key"`
	Transport   string            `json:"transport"`
	DNS         string            `json:"dns"`
	Socks       string            `json:"socks"`
	DeviceID    string            `json:"device_id"`
	Debug       bool              `json:"debug"`
	IceLocalIP  string            `json:"ice_local_ip"`
	EngineExtra map[string]string `json:"engine_extra"`
}

// rustRoomConfig joins room as the gate's rust flavour does: the room's link
// on the fake's host, config.js and the WebSocket on the fake's plain
// listener.
func rustRoomConfig(hub *Hub, room *Room) rustConfig {
	return rustConfig{
		URL: "https://" + hub.Host() + "/" + room.Name(), Provider: "jitsi", Key: rustKey, Transport: "datachannel",
		DNS: "127.0.0.1:53", Socks: "127.0.0.1:0", DeviceID: "client-1", Debug: true, IceLocalIP: "127.0.0.1",
		EngineExtra: map[string]string{"config_base": hub.Base(), "ws_url": hub.WSURL()},
	}
}

// rustProc is one run of the Rust client.
type rustProc struct {
	cmd     *exec.Cmd
	logPath string
	exited  chan struct{}
	cancel  context.CancelFunc
}

// startRust runs the client on cfg until the test ends. Its end is certain:
// the cleanup stops its process group and waits, Pdeathsig kills it with the
// test process, and its context carries rustLifetime. No line of its log may
// carry one of secrets.
func startRust(t *testing.T, cfg rustConfig, secrets ...string) *rustProc {
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
	cmd.SysProcAttr = rustChildProc()
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
	p := &rustProc{cmd: cmd, logPath: logFile.Name(), exited: make(chan struct{}), cancel: cancel}
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			_, _ = fmt.Fprintf(logFile, "%s %s\n", time.Now().Format("15:04:05.000"), sc.Text())
		}
		_ = logFile.Close()
		_ = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		p.stop(t)
		log := p.log()
		if log == "" {
			t.Error("the rust client wrote no log line: its secret check checked nothing")
		}
		for _, secret := range append([]string{rustKey}, secrets...) {
			if strings.Contains(log, secret) {
				t.Errorf("the rust client's log carries a secret of the join (%d bytes of it)", len(secret))
			}
		}
		if n := len(stanzaInLog.FindAllString(log, -1)); n != 0 {
			t.Errorf("%d places of the rust client's log look like a stanza or a JID", n)
		}
		if t.Failed() || os.Getenv(rustTraceEnv) != "" {
			t.Logf("rust client log, last lines:\n%s", rustTail(log, 80))
		}
	})
	return p
}

// stop ends the client and waits for it.
func (p *rustProc) stop(t *testing.T) {
	t.Helper()
	p.cancel()
	select {
	case <-p.exited:
	case <-time.After(rustStopGrace + 5*time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		t.Errorf("the rust client was still running %s after its stop", rustStopGrace+5*time.Second)
	}
}

// log is the client's log so far.
func (p *rustProc) log() string {
	raw, _ := os.ReadFile(p.logPath)
	return string(raw)
}

func rustTail(log string, n int) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// rustBOSHHub is a hub whose config.js names /http-bind and whose plain
// listener, the Rust client's, refuses the WebSocket. A request is held for
// the wait its client asked for, as Prosody holds it; a Go engine in the
// same hub keeps its WebSocket over TLS.
func rustBOSHHub(t *testing.T) *Hub {
	t.Helper()
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	hub.BOSH(true)
	hub.RefusePlainWebSocket(true)
	return hub
}

// rustSaid waits for the room's n-th client to have said at least stanzas
// and returns the room's state.
func rustSaid(t *testing.T, room *Room, n, stanzas int, what string) State {
	t.Helper()
	within(t, 30*time.Second, what, func() bool {
		st := room.State()
		return len(st.Transcripts) >= n && len(st.Transcripts[n-1]) >= stanzas
	})
	return room.State()
}

func TestRustJitsiJoinIsTheGoClients(t *testing.T) {
	rustBin(t)
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	room := hub.Open()
	const goUser, rustUser = "0123456789abcdef", "fedcba9876543210"
	hub.FixJID(goUser)
	_ = goEngine(t, hub, room, "olcrtc", engine.Config{})
	rustSaid(t, room, 1, 10, "the Go engine's login and room disco")
	hub.FixJID(rustUser)
	startRust(t, rustRoomConfig(hub, room), room.Name(), rustUser)
	st := rustSaid(t, room, 2, 10, "the rust client's login and room disco")

	want, got := Login(st.Transcripts[0], room.Name()), Login(st.Transcripts[1], room.Name())
	if !strings.HasPrefix(want, "<open ") || strings.Count(want, "\n") != 9 {
		t.Fatalf("the Go engine's login is not ten frames from its stream open:\n%s", want)
	}
	if got != want {
		t.Errorf("the rust client logged in as:\n%s\nthe Go engine as:\n%s", got, want)
	}
	if !strings.Contains(st.Transcripts[1][8], room.Name()+"@muc.meet.jitsi/"+rustUser[:8]) {
		t.Error("the rust client's presence does not name the occupant its bound JID gives")
	}
	if len(st.Upgrades) != 2 {
		t.Errorf("%d WebSocket upgrades in the room, want 2", len(st.Upgrades))
	}
	if n := len(hub.BOSHSessions()); n != 0 {
		t.Errorf("%d BOSH sessions on a hub whose config.js names none", n)
	}
}

func TestRustJitsiAWebSocketThatDialsIsTakenThoughBOSHIsNamed(t *testing.T) {
	rustBin(t)
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	hub.BOSH(true)
	room := hub.Open()
	const user = "fedcba9876543210"
	hub.FixJID(user)
	startRust(t, rustRoomConfig(hub, room), room.Name(), user)
	st := rustSaid(t, room, 1, 10, "the rust client's login and room disco")
	if !strings.HasPrefix(st.Transcripts[0][0], "<open ") || OverBOSH(st.Transcripts[0]) {
		t.Error("the client did not open a stream: not the WebSocket's login")
	}
	if len(st.Upgrades) != 1 {
		t.Errorf("%d WebSocket upgrades, want 1", len(st.Upgrades))
	}
	if n := len(hub.BOSHSessions()); n != 0 {
		t.Errorf("%d BOSH sessions beside a WebSocket that dialled", n)
	}
}

func TestRustJitsiOverBOSHJoinsAsTheGoClient(t *testing.T) {
	rustBin(t)
	// The Go client's join over BOSH, in a hub of its own: its requests are
	// held 5 s at most, or it hangs up (TestGoJitsiFakeBOSHHeldPoll).
	goHub := boshHub(t, boshGoHold)
	goRoom := goHub.Open()
	goHub.FixJID("0123456789abcdef")
	_ = goEngine(t, goHub, goRoom, "olcrtc", engine.Config{})
	rustSaid(t, goRoom, 1, 8, "the Go engine's login, room disco and caps answer over BOSH")
	goSession := goHub.BOSHSessions()[0]
	want := BOSHJoin(goSession, goRoom.Name())
	if strings.Count(want, "\n") != 8 || !strings.Contains(want, `xmpp:restart="true"`) {
		t.Fatalf("the Go client's join over BOSH is not nine requests with a restart:\n%s", want)
	}

	hub := rustBOSHHub(t)
	room := hub.Open()
	const user = "fedcba9876543210"
	hub.FixJID(user)
	p := startRust(t, rustRoomConfig(hub, room), room.Name(), user)
	st := rustSaid(t, room, 1, 8, "the rust client's login, room disco and caps answer over BOSH")
	sessions := hub.BOSHSessions()
	if len(sessions) != 1 {
		t.Fatalf("%d BOSH sessions, want 1", len(sessions))
	}
	if got := BOSHJoin(sessions[0], room.Name()); got != want {
		t.Errorf("the rust client joined over BOSH with:\n%s\nthe Go client with:\n%s", got, want)
	}
	said := st.Transcripts[0]
	if !OverBOSH(said) {
		t.Errorf("the first stanza is not the SASL request: %d bytes", len(said[0]))
	}
	for _, x := range said {
		for _, never := range []string{"<open ", "<enable ", "<r ", "<r/"} {
			if strings.HasPrefix(x, never) {
				t.Errorf("over BOSH the client said a stream's own frame, %q", never)
			}
		}
	}
	if st.Joins != 1 {
		t.Errorf("joins %d, want 1", st.Joins)
	}

	// Who it says it is: what it asked config.js with, on every request.
	if len(st.Config) != 1 {
		t.Fatalf("%d config.js requests for the room, want 1", len(st.Config))
	}
	agent := st.Config[0].Header.Get("User-Agent")
	if agent == "" || agent == rustGoUserAgent {
		t.Errorf("config.js was asked as %q", agent)
	}
	for _, r := range sessions[0].Requests {
		if got := r.Header.Get("User-Agent"); got != agent {
			t.Errorf("a BOSH request as %q, config.js as %q", got, agent)
			break
		}
	}
	for _, r := range sessions[0].Requests {
		if ct := r.Header.Get("Content-Type"); ct != "text/xml; charset=utf-8" || r.Path != boshPath {
			t.Errorf("a BOSH request to %q with Content-Type %q", r.Path, ct)
			break
		}
	}
	if goAgent := goSession.Requests[0].Header.Get("User-Agent"); goAgent != rustGoUserAgent {
		t.Errorf("the Go client's BOSH requests as %q: the comparison above reads something else", goAgent)
	}

	// Its stop: the leave, then the terminate, and nothing after.
	p.stop(t)
	within(t, 10*time.Second, "the leave and the terminate", func() bool {
		return room.State().Leaves == 1 && hub.BOSHSessions()[0].Terminated
	})
	b := hub.BOSHSessions()[0]
	bodies, consecutive := BOSHBodies(b)
	if !consecutive {
		t.Errorf("the request ids do not go up by one over %d requests", len(bodies))
	}
	if last := bodies[len(bodies)-1]; last != rustTerminate {
		t.Errorf("the last request is %d bytes, want the terminate", len(last))
	}
	if b.Refused != 0 || b.MaxInFlight > 2 || b.Expired {
		t.Errorf("%d requests refused for their id, %d open at once, expired %v", b.Refused, b.MaxInFlight, b.Expired)
	}
	t.Logf("rust over BOSH: %d requests, %d one ahead of their turn, %d open at once", len(b.Requests), b.OutOfOrder, b.MaxInFlight)
}

func TestRustJitsiOverBOSHReachesTheBridgeBesideAGoEngine(t *testing.T) {
	rustBin(t)
	hub := rustBOSHHub(t)
	room := hub.Open()
	_ = newPeer(t, hub, room, "olcsrv")
	const user = "fedcba9876543210"
	hub.FixJID(user)
	begun := time.Now()
	startRust(t, rustRoomConfig(hub, room), room.Name(), user)
	within(t, 40*time.Second, "a bridge channel for each of the two", func() bool {
		st := room.State()
		return st.Initiates == 2 && st.Accepts == 2 && st.Hellos == 2
	})
	// Over the WebSocket this takes a tenth of a second here. A second or
	// more is a poll that was not out when the bridge's offer was ready.
	t.Logf("the client's bridge channel is open %s after its start", time.Since(begun).Round(10*time.Millisecond))
	st := room.State()
	if len(st.Upgrades) != 1 {
		t.Errorf("%d WebSocket upgrades, want the Go engine's alone", len(st.Upgrades))
	}
	sessions := hub.BOSHSessions()
	if len(sessions) != 1 || sessions[0].Room != room.Name() {
		t.Fatalf("%d BOSH sessions, want the rust client's in this room", len(sessions))
	}
	accepted := false
	for _, r := range sessions[0].Requests {
		accepted = accepted || strings.Contains(r.Body, `action="session-accept"`) || strings.Contains(r.Body, `action='session-accept'`)
	}
	if !accepted {
		t.Error("no request of the session carries the session-accept")
	}
	mine := 0
	for _, c := range st.Channels {
		if c.Nick == user[:8] {
			mine++
			if c.Label != "JVB data channel" || c.Protocol != "http://jitsi.org/protocols/colibri" || !c.Ordered {
				t.Errorf("the rust client's channel %+v, want Jitsi's own label and protocol, ordered", c)
			}
		}
	}
	if mine != 1 {
		t.Errorf("%d bridge channels of the rust client, want 1", mine)
	}

	// A poll held longer than the Go engine waits for one: the room is quiet
	// until the fake has held the client's poll past that, then the focus
	// asks something. The poll's answer carries it, the client takes it out
	// and answers in a request of the next id: the session went on. (The
	// client leaves 15 s after its bridge opened, no olcRTC server being
	// here: the question is asked well before.)
	sid := sessions[0].SID
	quiet, asked := time.Now(), len(sessions[0].Requests)
	within(t, 14*time.Second, "the room quiet for longer than the Go engine waits for a poll", func() bool {
		if n := len(hub.BOSHSessions()[0].Requests); n != asked {
			quiet, asked = time.Now(), n
		}
		return time.Since(quiet) >= rustGoPollLimit+500*time.Millisecond
	})
	// The client's own transcript: the one that opened no stream.
	mineSaid := func() []string {
		for _, said := range room.State().Transcripts {
			if OverBOSH(said) {
				return said
			}
		}
		return nil
	}
	said := len(mineSaid())
	if !hub.BOSHInject(sid, "<iq type='set' id='late-1' from='f@auth.meet.jitsi/focus' xmlns='jabber:client'><q xmlns='urn:x'/></iq>", false) {
		t.Fatal("the session is gone before the question")
	}
	within(t, 3*time.Second, "the client's answer to what the held poll brought", func() bool {
		for _, x := range mineSaid()[said:] {
			if strings.HasPrefix(x, "<iq ") && attr(head(x), "id") == "late-1" && attr(head(x), "type") == "result" {
				return true
			}
		}
		return false
	})
	b := hub.BOSHSessions()[0]
	var held time.Duration
	for _, d := range b.Held {
		held = max(held, d)
	}
	if held < rustGoPollLimit {
		t.Errorf("the longest a request was held is %s: the poll was not held past the Go engine's %s", held.Round(100*time.Millisecond), rustGoPollLimit)
	}
	if _, consecutive := BOSHBodies(b); !consecutive || b.Refused != 0 || len(b.Dropped) != 0 || b.Expired || b.Terminated {
		t.Errorf("after a request held %s: ids up by one %v, %d refused, %d hung up on, expired %v, terminated %v",
			held.Round(100*time.Millisecond), consecutive, b.Refused, len(b.Dropped), b.Expired, b.Terminated)
	}
	t.Logf("rust over BOSH beside a Go engine: %d requests, the longest held %s and answered, %d open at once",
		len(b.Requests), held.Round(100*time.Millisecond), b.MaxInFlight)
}

func TestRustJitsiARefusedWebSocketWithNoBOSHNamedIsTheWebSocketsFailure(t *testing.T) {
	rustBin(t)
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	hub.RefusePlainWebSocket(true)
	room := hub.Open()
	p := startRust(t, rustRoomConfig(hub, room), room.Name())
	select {
	case <-p.exited:
	case <-time.After(90 * time.Second):
		t.Fatal("the rust client is still running 90 s after a join that cannot be made")
	}
	if !strings.Contains(p.log(), "failed to WebSocket dial") {
		t.Error("the client's log does not say the WebSocket did not dial")
	}
	if strings.Contains(p.log(), "bosh") {
		t.Error("the client's log speaks of BOSH where config.js names none")
	}
	if n := len(hub.BOSHSessions()); n != 0 {
		t.Errorf("%d BOSH sessions asked for where config.js names none", n)
	}
	if st := room.State(); st.Joins != 0 {
		t.Errorf("%d joins", st.Joins)
	}
}

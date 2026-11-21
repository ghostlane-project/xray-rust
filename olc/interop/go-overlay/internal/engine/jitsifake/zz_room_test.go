// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the fake Jitsi room
// held to the Go engine at the pin. A fake that the Go client cannot pass
// proves nothing about the Rust one.

package jitsifake

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/engine/jitsi"
)

func within(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not within %s: %s", d, what)
}

// goEngine is a Go jitsi engine on the pin, joined to the room.
func goEngine(t *testing.T, hub *Hub, room *Room, name string, cfg engine.Config) engine.Session {
	t.Helper()
	cfg.URL, cfg.Name = hub.Host(), name
	cfg.Extra = map[string]string{"room": room.Name()}
	s, err := jitsi.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Connect(ctx); err != nil {
		t.Fatalf("Connect as %s: %v", name, err)
	}
	return s
}

// writeVector writes a vector file when OLCRTC_JITSI_VECTORS names a directory.
func writeVector(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("OLCRTC_JITSI_VECTORS")
	if dir == "" {
		return
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGoJitsiFakeJoin(t *testing.T) {
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	hub.FixJID("0123456789abcdef")
	room := hub.Open()
	s := goEngine(t, hub, room, "olcrtc", engine.Config{})
	within(t, 10*time.Second, "the room's disco after the join", func() bool {
		st := room.State()
		return len(st.Transcripts) == 1 && len(st.Transcripts[0]) >= 10
	})
	st := room.State()
	said := st.Transcripts[0]
	for i, want := range []string{"<open ", "<auth ", "<open ", "bind_1", "sess_1", "<enable ", "focus_1", "disco_1", "<presence ", "disco#info"} {
		if !strings.Contains(said[i], want) {
			t.Errorf("stanza %d = %q, want it to hold %q", i, said[i], want)
		}
	}
	if !strings.Contains(said[8], room.Name()+"@muc.meet.jitsi/01234567") {
		t.Errorf("the join presence does not name the room occupant 01234567: %q", said[8])
	}
	if st.Joins != 1 || st.Initiates != 0 {
		t.Errorf("joins %d, initiates %d, want 1 and 0: alone in the room, no offer", st.Joins, st.Initiates)
	}
	if len(st.Config) != 1 || len(st.Upgrades) != 1 {
		t.Fatalf("handshakes: %d config.js, %d upgrades, want 1 and 1", len(st.Config), len(st.Upgrades))
	}
	if got := st.Upgrades[0].Header.Get("Sec-WebSocket-Protocol"); got != "xmpp" {
		t.Errorf("subprotocol %q, want xmpp", got)
	}
	// Still parked after a moment: no peer, no failure.
	time.Sleep(500 * time.Millisecond)
	if s.CanSend() {
		t.Error("an engine alone in the room can send")
	}
	_ = s.Close()
	within(t, 10*time.Second, "the leave echo", func() bool { return room.State().Leaves == 1 })
	st = room.State()
	last := st.Transcripts[0][len(st.Transcripts[0])-1]
	if !strings.Contains(last, `type="unavailable"`) {
		t.Errorf("the last stanza is %q, want the leave", last)
	}
	writeVector(t, "transcript.json", st.Transcripts[0])
	hs := map[string]any{"config_js": st.Config[0], "upgrade": st.Upgrades[0]}
	writeVector(t, "handshake.json", hs)
}

// peer is a Go engine in the room and what it was handed.
type peer struct {
	s         engine.Session
	mu        sync.Mutex
	got       [][]byte
	reconnect atomic.Int64
}

func (p *peer) heard(want string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.got {
		if string(b) == want {
			return true
		}
	}
	return false
}

func newPeer(t *testing.T, hub *Hub, room *Room, name string) *peer {
	t.Helper()
	p := &peer{}
	p.s = goEngine(t, hub, room, name, engine.Config{OnData: func(b []byte) {
		p.mu.Lock()
		p.got = append(p.got, append([]byte(nil), b...))
		p.mu.Unlock()
	}})
	p.s.SetReconnectCallback(func() { p.reconnect.Add(1) })
	// What the tunnel layer does with a session: watch it for a reconnect.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.s.WatchConnection(ctx)
	return p
}

// say sends until the other end has it: the first frames may meet no peer.
func say(t *testing.T, from, to *peer, text string) {
	t.Helper()
	within(t, 40*time.Second, "the frame "+text+" reaching the other engine", func() bool {
		_ = from.s.Send([]byte(text))
		time.Sleep(100 * time.Millisecond)
		return to.heard(text)
	})
}

func TestGoJitsiFakePair(t *testing.T) {
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	room := hub.Open()
	a := newPeer(t, hub, room, "olcsrv")
	b := newPeer(t, hub, room, "olccli")
	say(t, a, b, "from-a-1")
	say(t, b, a, "from-b-1")
	st := room.State()
	if st.Initiates != 2 || st.Accepts != 2 || st.Hellos != 2 {
		t.Errorf("initiates %d, accepts %d, hellos %d, want 2 each: one bridge peer per participant", st.Initiates, st.Accepts, st.Hellos)
	}
	for _, c := range st.Channels {
		if c.Label != "JVB data channel" || c.Protocol != "http://jitsi.org/protocols/colibri" || !c.Ordered {
			t.Errorf("channel %+v, want the engine's JVB data channel, colibri, ordered", c)
		}
	}
	if len(st.Channels) != 2 {
		t.Errorf("%d channels opened, want 2", len(st.Channels))
	}
	within(t, 20*time.Second, "the keepalive video of both reaching the bridge", func() bool {
		v := room.State().Video
		return len(v) == 2
	})

	// A bridge that goes away: both engines rejoin and the traffic resumes.
	before := a.reconnect.Load() + b.reconnect.Load()
	room.CloseBridges()
	within(t, 60*time.Second, "a rejoin after the bridge closed", func() bool {
		return a.reconnect.Load()+b.reconnect.Load() > before
	})
	say(t, a, b, "from-a-2")
	say(t, b, a, "from-b-2")
	if got := room.State().BridgesClosed; got != 2 {
		t.Errorf("bridges closed %d, want 2", got)
	}
	if room.State().Initiates < 4 {
		t.Errorf("initiates %d after the rejoin, want at least 4", room.State().Initiates)
	}
}

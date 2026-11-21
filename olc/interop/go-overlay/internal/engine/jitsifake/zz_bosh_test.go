// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the fake's BOSH half
// held to the Go engine at the pin, which takes BOSH when the WebSocket does
// not dial and config.js names one (j/internal/xmpp/conn.go:164-171). A fake
// the Go client cannot pass proves nothing about the Rust one.
//
// TestGoJitsiFakeBOSHHeldPoll is not a check of the fake: it writes down what
// the Go client does with a server that holds a poll as long as the client
// asked (wait="60", as Prosody does). The engine's HTTP client gives a
// response's headers 10 s (internal/protect/protect.go: defaultResponseHeader),
// so it hangs up on the held poll and its transport closes. The other tests
// here cap the fake's hold at 5 s for that reason.

package jitsifake

import (
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
)

// boshGoHold is how long the fake holds a Go client's request in the tests
// that need its session to live: under the client's 10 s.
const boshGoHold = 5 * time.Second

// boshHub is a hub whose WebSocket is refused and whose config.js names
// /http-bind; a request on the TLS listener (the Go engine's) is held for
// hold at most, zero for as long as the client asked.
func boshHub(t *testing.T, hold time.Duration) *Hub {
	t.Helper()
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	hub.BOSH(true)
	hub.RefuseWebSocket(true)
	hub.BOSHHold(0, hold)
	return hub
}

func TestGoJitsiFakeBOSHJoin(t *testing.T) {
	hub := boshHub(t, boshGoHold)
	hub.FixJID("0123456789abcdef")
	room := hub.Open()
	s := goEngine(t, hub, room, "olcrtc", engine.Config{})
	within(t, 10*time.Second, "the room's disco after the join", func() bool {
		st := room.State()
		return len(st.Transcripts) == 1 && len(st.Transcripts[0]) >= 7
	})
	st := room.State()
	said := st.Transcripts[0]
	// The WebSocket's login less the two stream opens and stream management.
	for i, want := range []string{"<auth ", "bind_1", "sess_1", "focus_1", "disco_1", "<presence ", "disco#info"} {
		if !strings.Contains(said[i], want) {
			t.Errorf("stanza %d = %q, want it to hold %q", i, said[i], want)
		}
	}
	for _, x := range said {
		for _, never := range []string{"<open ", "<enable ", "<r ", "<r/"} {
			if strings.HasPrefix(x, never) {
				t.Errorf("a BOSH client said %q", x)
			}
		}
	}
	if !strings.Contains(said[5], room.Name()+"@muc.meet.jitsi/01234567") {
		t.Errorf("the join presence does not name the room occupant 01234567: %q", said[5])
	}
	if st.Joins != 1 || len(st.Upgrades) != 0 {
		t.Errorf("joins %d, upgrades %d, want 1 and 0: over BOSH, no WebSocket", st.Joins, len(st.Upgrades))
	}
	sessions := hub.BOSHSessions()
	if len(sessions) != 1 {
		t.Fatalf("%d BOSH sessions, want 1", len(sessions))
	}
	b := sessions[0]
	if b.Room != room.Name() {
		t.Error("the session is not the room's")
	}
	create := b.Requests[0]
	for _, want := range []string{` to="meet.jitsi"`, ` wait="60"`, ` hold="1"`, ` ver="1.6"`, ` xmlns="http://jabber.org/protocol/httpbind"`} {
		if !strings.Contains(create.Body, want) {
			t.Errorf("the session request %q does not hold %q", create.Body, want)
		}
	}
	if create.Path != boshPath {
		t.Errorf("asked on %q, want %q: the library adds no room to the BOSH URL", create.Path, boshPath)
	}
	if got := create.Header.Get("Content-Type"); got != "text/xml; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}
	if got := create.Header.Get("User-Agent"); got != "Go-http-client/1.1" {
		t.Errorf("User-Agent %q, want Go's own: the library names none on BOSH", got)
	}
	if b.MaxInFlight > 2 {
		t.Errorf("%d requests open at once, want at most 2 (the poll and one send)", b.MaxInFlight)
	}
	if b.Refused != 0 {
		t.Errorf("%d requests refused for their id", b.Refused)
	}

	_ = s.Close()
	within(t, 10*time.Second, "the leave and the terminate", func() bool {
		ss := hub.BOSHSessions()
		return room.State().Leaves == 1 && ss[0].Terminated
	})
	b = hub.BOSHSessions()[0]
	bodies, consecutive := BOSHBodies(b)
	if !consecutive {
		t.Error("the request ids do not go up by one")
	}
	last := bodies[len(bodies)-1]
	if last != `<body rid="RID" sid="SID" type="terminate" xmlns="http://jabber.org/protocol/httpbind"/>` {
		t.Errorf("the last request is %q, want the terminate", last)
	}
}

func TestGoJitsiFakeBOSHPair(t *testing.T) {
	hub := boshHub(t, boshGoHold)
	room := hub.Open()
	a := newPeer(t, hub, room, "olcsrv")
	b := newPeer(t, hub, room, "olccli")
	say(t, a, b, "from-a-1")
	say(t, b, a, "from-b-1")
	st := room.State()
	if st.Initiates != 2 || st.Accepts != 2 || st.Hellos != 2 {
		t.Errorf("initiates %d, accepts %d, hellos %d, want 2 each: one bridge peer per participant", st.Initiates, st.Accepts, st.Hellos)
	}
	if len(st.Upgrades) != 0 {
		t.Errorf("%d WebSocket upgrades in a BOSH run", len(st.Upgrades))
	}
	sessions := hub.BOSHSessions()
	if len(sessions) != 2 {
		t.Fatalf("%d BOSH sessions, want 2", len(sessions))
	}
	for _, s := range sessions {
		if s.Refused != 0 || s.MaxInFlight > 2 {
			t.Errorf("session: %d refused, %d open at once", s.Refused, s.MaxInFlight)
		}
		t.Logf("session: %d requests, %d one ahead of their turn, %d open at once", len(s.Requests), s.OutOfOrder, s.MaxInFlight)
	}
}

// TestGoJitsiFakeBOSHHeldPoll writes down the Go client's behaviour with a
// server that holds a poll for the wait the client asked for.
func TestGoJitsiFakeBOSHHeldPoll(t *testing.T) {
	hub := boshHub(t, 0)
	room := hub.Open()
	_ = goEngine(t, hub, room, "olcrtc", engine.Config{})
	within(t, 10*time.Second, "the join", func() bool { return room.State().Joins == 1 })
	within(t, 20*time.Second, "the Go client hanging up on a held request", func() bool {
		return len(hub.BOSHSessions()[0].Dropped) > 0
	})
	b := hub.BOSHSessions()[0]
	held := b.Dropped[0]
	t.Logf("the Go client hung up on a request held for %s (wait=\"60\" asked); %d requests in the session", held.Round(100*time.Millisecond), len(b.Requests))
	if held < 9*time.Second || held > 12*time.Second {
		t.Errorf("held for %s when the client hung up, want about 10 s (ResponseHeaderTimeout)", held)
	}
	// Its poll loop ends with that: no poll and no stanza follows on the
	// session (a terminate may, when the engine takes the session down).
	n := len(b.Requests)
	time.Sleep(2 * time.Second)
	b = hub.BOSHSessions()[0]
	for _, r := range b.Requests[n:] {
		if !strings.Contains(r.Body, `type="terminate"`) {
			t.Errorf("a request after the hang-up: %d bytes, want none: the transport is closed", len(r.Body))
		}
	}
}

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the interop-p2p
// engine's tests, two sessions in a room of an in-process hub.

package interopp2p

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
)

const testBudget = 30 * time.Second

func TestParseURL(t *testing.T) {
	raw := "tcp://127.0.0.1:9/room-1?turn=" + "turn%3A127.0.0.1%3A3478%3Ftransport%3Dudp" +
		"&turn=turns%3Alocalhost%3A5349%3Ftransport%3Dtcp&turn_user=u&turn_pass=p&policy=relay&what=ever"
	got, err := ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "127.0.0.1:9" || got.Room != "room-1" || got.Policy != webrtc.ICETransportPolicyRelay {
		t.Fatalf("got %+v", got)
	}
	if len(got.ICEServers) != 1 {
		t.Fatalf("ice servers %+v", got.ICEServers)
	}
	s := got.ICEServers[0]
	if strings.Join(s.URLs, " ") != "turn:127.0.0.1:3478?transport=udp turns:localhost:5349?transport=tcp" ||
		s.Username != "u" || s.Credential != "p" {
		t.Fatalf("ice server %+v", s)
	}
	plain, err := ParseURL("tcp://127.0.0.1:9/room-1")
	if err != nil || plain.Policy != webrtc.ICETransportPolicyAll || len(plain.ICEServers) != 0 {
		t.Fatalf("plain %+v %v", plain, err)
	}
	for _, bad := range []string{
		"udp://127.0.0.1:9/r", "tcp:///r", "tcp://127.0.0.1:9/", "tcp://127.0.0.1:9/r?policy=nope",
	} {
		if _, err := ParseURL(bad); !errors.Is(err, ErrBadURL) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// party is one session with a local track and what it hears.
type party struct {
	s        *Session
	track    *webrtc.TrackLocalStaticSample
	tracks   atomic.Int32 // remote tracks handed over
	packets  atomic.Int64 // RTP packets read from them
	reconns  atomic.Int32
	stopping atomic.Bool
}

func newParty(t *testing.T, rawURL string) *party {
	t.Helper()
	sess, err := New(context.Background(), engine.Config{URL: rawURL})
	if err != nil {
		t.Fatal(err)
	}
	s, ok := sess.(*Session)
	if !ok {
		t.Fatalf("New returned %T", sess)
	}
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, "v-"+rawURL, "olcrtc-test")
	if err != nil {
		t.Fatal(err)
	}
	p := &party{s: s, track: track}
	if err := s.AddVideoTrack(track); err != nil {
		t.Fatal(err)
	}
	s.SetVideoTrackHandler(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if !strings.EqualFold(tr.Codec().MimeType, webrtc.MimeTypeVP8) {
			t.Errorf("remote track %s", tr.Codec().MimeType)
		}
		p.tracks.Add(1)
		go func() {
			for {
				pkt, _, err := tr.ReadRTP()
				if err != nil {
					return
				}
				if len(pkt.Payload) > 0 {
					p.packets.Add(1)
				}
			}
		}()
	})
	s.SetReconnectCallback(func() { p.reconns.Add(1) })
	t.Cleanup(func() { _ = s.Close() })
	return p
}

// observe joins room as a bare participant that says nothing, once the hub
// holds it.
func observe(t *testing.T, hub *interoppipe.Hub, room string) net.Conn {
	t.Helper()
	before := hub.Members(room)
	conn, err := net.Dial("tcp", strings.TrimPrefix(strings.TrimSuffix(hub.URL(room), "/"+room), "tcp://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := interoppipe.WriteFrame(conn, interoppipe.KindJoin, []byte(room)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the observer in the room", func() bool { return hub.Members(room) > before })
	return conn
}

// awaitHello reads conn until from's broadcast hello.
func awaitHello(t *testing.T, conn net.Conn, from string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(testBudget))
	for {
		kind, payload, err := interoppipe.ReadFrame(conn)
		if err != nil {
			t.Fatalf("waiting for %s's hello: %v", from, err)
		}
		var m map[string]string
		if kind == interoppipe.KindData && json.Unmarshal(payload, &m) == nil &&
			m["t"] == "hello" && m["from"] == from && m["to"] == "" {
			return
		}
	}
}

// pump writes a sample on every party's track until stop.
func pump(stop <-chan struct{}, parties ...*party) {
	sample := media.Sample{Data: make([]byte, 3000), Duration: time.Second / 60}
	tick := time.NewTicker(time.Second / 60)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		for _, p := range parties {
			_ = p.track.WriteSample(sample)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testBudget)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, testBudget)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTwoSessionsTradeVideoBothRoles: b joins after a, so b offers and a
// answers; then a reconnects, comes back as the newcomer and offers. Video
// flows both ways each time.
func TestTwoSessionsTradeVideoBothRoles(t *testing.T) {
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	ctx, cancel := context.WithTimeout(context.Background(), testBudget)
	defer cancel()

	// A bare observer in the room sees a's broadcast hello once the hub has
	// relayed it; only then does b join, so b is the newcomer and the two
	// hellos cannot cross.
	obs := observe(t, hub, "both-roles")
	a := newParty(t, hub.URL("both-roles"))
	if err := a.s.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.s.CanSend() || !a.s.SubscriberCanSend() {
		t.Fatal("a joined but cannot send")
	}
	awaitHello(t, obs, a.s.LocalID())
	go func() { // the rest of the room's talk
		_ = obs.SetReadDeadline(time.Time{})
		_, _ = io.Copy(io.Discard, obs)
	}()
	// An unknown query key is ignored; policy=all is the default.
	b := newParty(t, hub.URL("both-roles")+"?policy=all&unknown=1")
	if err := b.s.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); pump(stop, a, b) }()
	defer func() { close(stop); wg.Wait() }()

	waitFor(t, "both connected", func() bool { return a.s.PeerSeen() && b.s.PeerSeen() })
	waitFor(t, "video both ways", func() bool { return a.packets.Load() > 20 && b.packets.Load() > 20 })
	if a.s.offers.Load() != 0 || a.s.answers.Load() != 1 || b.s.offers.Load() != 1 || b.s.answers.Load() != 0 {
		t.Fatalf("first round: a offered %d answered %d, b offered %d answered %d",
			a.s.offers.Load(), a.s.answers.Load(), b.s.offers.Load(), b.s.answers.Load())
	}

	// a rejoins: it is the newcomer now.
	before := b.tracks.Load()
	a.s.Reconnect("test")
	waitFor(t, "a's reconnect callback", func() bool { return a.reconns.Load() == 1 })
	waitFor(t, "a new track at b", func() bool { return b.tracks.Load() > before })
	mark := b.packets.Load()
	markA := a.packets.Load()
	waitFor(t, "video both ways again", func() bool {
		return b.packets.Load() > mark+20 && a.packets.Load() > markA+20
	})
	if a.s.offers.Load() != 1 {
		t.Fatalf("after the rejoin a offered %d times", a.s.offers.Load())
	}
	if n := b.s.peerCount(); n != 1 {
		t.Fatalf("b holds %d peer connections, want 1 (the old one closed by bye)", n)
	}
}

// TestSignallingIgnoresOthers: frames for another id, from ourselves or not
// JSON are dropped without a peer connection made.
func TestSignallingIgnoresOthers(t *testing.T) {
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	ctx, cancel := context.WithTimeout(context.Background(), testBudget)
	defer cancel()
	a := newParty(t, hub.URL("ignore"))
	if err := a.s.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(strings.TrimSuffix(hub.URL("ignore"), "/ignore"), "tcp://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := interoppipe.WriteFrame(conn, interoppipe.KindJoin, []byte("ignore")); err != nil {
		t.Fatal(err)
	}
	send := func(m any) {
		raw, _ := json.Marshal(m)
		if err := interoppipe.WriteFrame(conn, interoppipe.KindData, raw); err != nil {
			t.Fatal(err)
		}
	}
	send(map[string]string{"t": "hello", "from": "aaaaaaaaaaaaaaaa", "to": "bbbbbbbbbbbbbbbb"})
	send(map[string]string{"t": "offer", "from": "aaaaaaaaaaaaaaaa", "to": "bbbbbbbbbbbbbbbb", "sdp": "x"})
	send(map[string]string{"t": "hello", "from": a.s.LocalID(), "to": a.s.LocalID()})
	if err := interoppipe.WriteFrame(conn, interoppipe.KindData, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	// A broadcast hello from a stranger is answered with a directed hello
	// and no offer (the stranger is the newcomer).
	send(map[string]string{"t": "hello", "from": "cccccccccccccccc", "to": ""})
	_ = conn.SetReadDeadline(time.Now().Add(testBudget))
	for {
		kind, payload, err := interoppipe.ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if kind != interoppipe.KindData {
			continue
		}
		var m map[string]string
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatalf("a sent %q", payload)
		}
		if m["t"] == "hello" && m["to"] == "" {
			continue // a's own broadcast, from before we joined or not
		}
		if m["t"] != "hello" || m["to"] != "cccccccccccccccc" || m["from"] != a.s.LocalID() {
			t.Fatalf("a answered with %v", m)
		}
		break
	}
	time.Sleep(200 * time.Millisecond)
	if n := a.s.peerCount(); n != 0 || a.s.offers.Load() != 0 || a.s.answers.Load() != 0 {
		t.Fatalf("a made %d peer connections, %d offers, %d answers", n, a.s.offers.Load(), a.s.answers.Load())
	}
}

// TestCrossedOffersTheGreaterIDStands: both ends took the other for the
// newcomer (their hellos crossed) and both offered. The lower id answers the
// other's offer and gives its own up; the greater id keeps its offer and
// ignores the other's, so exactly one connection is made either way.
func TestCrossedOffersTheGreaterIDStands(t *testing.T) {
	for _, tc := range []struct {
		name, stranger string
		answers        bool
	}{
		{"the stranger is lower, a's offer stands", "0000000000000000", false},
		{"the stranger is greater, a answers it", "ffffffffffffffff", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(hub.Close)
			ctx, cancel := context.WithTimeout(context.Background(), testBudget)
			defer cancel()
			a := newParty(t, hub.URL("crossed"))
			if err := a.s.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			conn, err := net.Dial("tcp", strings.TrimPrefix(strings.TrimSuffix(hub.URL("crossed"), "/crossed"), "tcp://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := interoppipe.WriteFrame(conn, interoppipe.KindJoin, []byte("crossed")); err != nil {
				t.Fatal(err)
			}
			send := func(m any) {
				raw, _ := json.Marshal(m)
				if err := interoppipe.WriteFrame(conn, interoppipe.KindData, raw); err != nil {
					t.Fatal(err)
				}
			}
			awaitFromA := func(kind string) {
				_ = conn.SetReadDeadline(time.Now().Add(testBudget))
				for {
					k, payload, err := interoppipe.ReadFrame(conn)
					if err != nil {
						t.Fatalf("waiting for a's %s: %v", kind, err)
					}
					var m map[string]string
					if k != interoppipe.KindData || json.Unmarshal(payload, &m) != nil {
						continue
					}
					if m["t"] == kind && m["from"] == a.s.LocalID() && m["to"] == tc.stranger {
						return
					}
				}
			}
			// The stranger's directed hello: a is the newcomer and offers.
			send(map[string]string{"t": "hello", "from": tc.stranger, "to": a.s.LocalID()})
			awaitFromA("offer")
			// The stranger's own offer crosses a's.
			pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = pc.Close() }()
			if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo,
				webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendrecv}); err != nil {
				t.Fatal(err)
			}
			offer, err := pc.CreateOffer(nil)
			if err != nil {
				t.Fatal(err)
			}
			gathered := webrtc.GatheringCompletePromise(pc)
			if err := pc.SetLocalDescription(offer); err != nil {
				t.Fatal(err)
			}
			select {
			case <-gathered:
			case <-ctx.Done():
				t.Fatal("the stranger's gathering did not end")
			}
			send(map[string]string{"t": "offer", "from": tc.stranger, "to": a.s.LocalID(), "sdp": pc.LocalDescription().SDP})
			if tc.answers {
				awaitFromA("answer")
				waitFor(t, "a's one answer", func() bool { return a.s.answers.Load() == 1 })
				return
			}
			time.Sleep(2 * time.Second)
			if a.s.answers.Load() != 0 || a.s.offers.Load() != 1 || a.s.peerCount() != 1 {
				t.Fatalf("a answered %d, offered %d, holds %d connections: its offer should stand alone",
					a.s.answers.Load(), a.s.offers.Load(), a.s.peerCount())
			}
		})
	}
}

//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): live.json, the Jingle
// vectors from a real deployment. offer.json and accept.json are made in a
// room of the Go fake, whose session-initiate was written from the shapes
// the library parses; this one starts from a session-initiate a real Jicofo
// sent, kept as it arrived on the wire:
//
//	testdata/zz-live/stable-11248-3-session-initiate.xml
//
// docker-jitsi-meet stable-11248-3 (Prosody 13.0.7, Jicofo 1.0.1205, JVB
// 2.3.318) on a GitHub-hosted runner of the fork, workflow olc-jitsi-live, run
// 44929668208: what the pinned Go server read from its WebSocket in the first
// room of that run. Nothing in it is replaced. The deployment lived for nine
// minutes; its room, addresses, ICE credentials and fingerprint name nothing
// that exists.
//
// The engine is given that stanza the way it is given any: its own
// conference PeerConnection (codecs, interceptors, Plan B), its own tracks
// for a datachannel run, the library's data channel, the library's
// Negotiator. No room and no bridge: the library's connection has a transport
// that records what is sent, so Accept runs to its end and the session-accept
// it would have sent is read back. The vector pairs
//
//	the stanza            -> the SDP the engine's pion was given from it,
//	the SDP pion answered -> the session-accept the library wrote from it.
//
// The second pair's random values are replaced as accept.json's are.
//
// The vector also carries that server's whole connection up to its third
// stream-management answer, both ways and in the order its log has them
// (the library's debug lines, which print what is written and read):
//
//	testdata/zz-live/stable-11248-3-room.txt   "> " the Go engine said,
//	                                           "< " Prosody or Jicofo said
//
// the login against a real Prosody's features, the focus, the services
// query a deployment without them refuses, the room with what a real one
// says around a join (the focus's presence, the room's metadata, an empty
// subject), a Jicofo's disco#info query by node and the engine's answer, the
// offer and its acknowledgement, a source-add in JSON form, two peers come
// and gone. The room's name is put back where the gate's log writer had cut
// it out; nothing else is changed. It is not made by this generator: what
// the engine said there is what it said to a real server.

package jitsi

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
	"github.com/zarazaex69/j"
)

const (
	zzLiveStanza  = "testdata/zz-live/stable-11248-3-session-initiate.xml"
	zzLiveRoomLog = "testdata/zz-live/stable-11248-3-room.txt"
	zzLiveFrom    = "docker-jitsi-meet stable-11248-3 (Prosody 13.0.7, Jicofo 1.0.1205, JVB 2.3.318), " +
		"workflow olc-jitsi-live run 44929668208: the session-initiate the Go server read from its WebSocket"
	// The room and the client's JID of the capture: the session-accept names
	// both.
	zzLiveRoom = "gate-92e942cec9a0@muc.meet.jitsi"
	zzLiveJID  = "041fd969-b171-40bd-ae32-0a93edb24906@meet.jitsi/_DOJWIKxS4JB"
)

type zzLive struct {
	From        string       `json:"from"`
	InitiateXML string       `json:"initiate_xml"`
	OfferSDP    string       `json:"offer_sdp"`
	LocalSDP    string       `json:"local_sdp"`
	AcceptXML   string       `json:"accept_xml"`
	AcceptInner string       `json:"accept_inner"`
	Room        []zzLiveLine `json:"room"`
}

// zzLiveLine is one stanza of the captured connection: who said it, and its
// text as it was on the wire.
type zzLiveLine struct {
	Client bool   `json:"client"`
	Stanza string `json:"stanza"`
}

// zzLiveCapture reads the captured connection. The offer in it is the stanza of
// zzLiveStanza: one capture, not two.
func zzLiveCapture(t *testing.T, offer string) []zzLiveLine {
	raw, err := os.ReadFile(zzLiveRoomLog)
	if err != nil {
		t.Fatal(err)
	}
	var out []zzLiveLine
	offers := 0
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if len(line) < 3 || (line[:2] != "> " && line[:2] != "< ") {
			t.Fatalf("%s line %d: neither \"> \" nor \"< \"", zzLiveRoomLog, i+1)
		}
		l := zzLiveLine{Client: line[0] == '>', Stanza: line[2:]}
		if !l.Client && l.Stanza == offer {
			offers++
		}
		out = append(out, l)
	}
	if offers != 1 {
		t.Fatalf("%s holds the offer of %s %d times, want once", zzLiveRoomLog, zzLiveStanza, offers)
	}
	return out
}

// zzLiveWire is the library connection's transport: what is sent is kept,
// nothing ever arrives.
type zzLiveWire struct {
	sent []string
}

func (w *zzLiveWire) Send(b []byte) error {
	w.sent = append(w.sent, string(b))
	return nil
}

func (w *zzLiveWire) Recv(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (w *zzLiveWire) Close() error { return nil }

// zzLiveSet stores v in the unexported field name of the struct at.
func zzLiveSet(at reflect.Value, name string, v any) {
	f := at.FieldByName(name)
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(v))
}

// zzLiveSession is a library session with no server behind it: its
// connection is the library's own type with wire as the transport and jid
// as the bound JID.
func zzLiveSession(wire *zzLiveWire, room, jid string) *j.Session {
	sess := &j.Session{RoomJID: room}
	field := reflect.ValueOf(sess).Elem().FieldByName("Conn")
	conn := reflect.New(field.Type().Elem())
	zzLiveSet(conn.Elem(), "tr", wire)
	zzLiveSet(conn.Elem(), "jid", jid)
	field.Set(conn)
	return sess
}

func zzLiveVectors(t *testing.T) {
	raw, err := os.ReadFile(zzLiveStanza)
	if err != nil {
		t.Fatal(err)
	}
	stanza := strings.TrimSpace(string(raw))

	made, err := New(context.Background(), engine.Config{
		URL: "https://meet.jitsi-live.test", Name: "olcsrv", OnData: func([]byte) {},
		Extra: map[string]string{credentialKeyRoom: "gate-92e942cec9a0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := made.(*Session)
	t.Cleanup(func() { _ = s.Close() })

	wire := &zzLiveWire{}
	jSess := zzLiveSession(wire, zzLiveRoom, zzLiveJID)
	pc, err := s.newConferencePeerConnection(jSess)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if _, _, err := s.configureConferenceTracks(pc); err != nil {
		t.Fatal(err)
	}
	if err := jSess.PrepareBridgeSCTP(pc); err != nil {
		t.Fatal(err)
	}
	neg := jSess.Negotiator()
	neg.PC = pc
	neg.JingleStanza = stanza
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := neg.Accept(ctx); err != nil {
		t.Fatalf("the engine's stack refused a real Jicofo's offer: %v", err)
	}
	if len(wire.sent) != 1 || !strings.Contains(wire.sent[0], `action="session-accept"`) {
		t.Fatalf("Accept sent %d stanzas, want the session-accept alone: %q", len(wire.sent), wire.sent)
	}
	accept := wire.sent[0]
	inner := accept[strings.Index(accept, "<jingle"):]
	inner = inner[strings.Index(inner, ">")+1 : strings.LastIndex(inner, "</jingle>")]
	remote := zzOrigin.ReplaceAllString(pc.RemoteDescription().SDP, "o=- 1 2 IN")
	r := zzScrub(pc.LocalDescription().SDP, accept, inner)
	zzvectors.Write(t, "jitsi/live.json", zzGenerator,
		[]string{
			"j/internal/jingle/sdp.go (JingleToSDP)", "j/internal/peer/peer.go (Accept)",
			"j/internal/jingle/build.go (SDPToJingleAccept)", "j/internal/xmpp/conn.go (SendSessionAccept)",
		},
		zzLive{
			From: zzLiveFrom, InitiateXML: stanza, OfferSDP: remote,
			LocalSDP: r[0], AcceptXML: r[1], AcceptInner: r[2],
			Room: zzLiveCapture(t, stanza),
		})
}

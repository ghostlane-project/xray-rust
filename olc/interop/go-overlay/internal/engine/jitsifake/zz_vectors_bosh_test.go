// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the golden vector of
// the Go client's BOSH (jitsi/bosh.json), written by TestZZVectors. The Go
// engine at the pin joins a room of the fake whose WebSocket is refused, so
// the library (j/internal/xmpp/conn.go:1168-1495) speaks BOSH:
//
//   - what it posts: the session request, the poll, the stream restart, each
//     stanza in a body of its own, the terminate, and the request's headers;
//   - how it splits an answer into stanzas (extractBOSHInner,
//     splitXMLElements; neither is exported, so they are read through the
//     client itself): the fake answers a poll with a body of its own writing,
//     full of IQ sets, and the client's acknowledgements say which stanzas it
//     took out of it.
//
// The Rust client's BOSH (olc/olc-jitsi, xmpp/bosh.rs) is held to it.

package jitsifake

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzBOSHGenerator = "internal/engine/jitsifake/zz_vectors_bosh_test.go"

type zzBOSHSplit struct {
	Name string `json:"name"`
	// Reply is the answer's whole body as the client got it.
	Reply string `json:"reply"`
	// Acked is the ids of the IQ results the Go client sent for it, in order.
	Acked []string `json:"acked"`
	// AckedTo is who each of those results was addressed to.
	AckedTo []string `json:"acked_to"`
}

type zzBOSH struct {
	Room string `json:"room"`
	User string `json:"user"`
	Nick string `json:"nick"`
	Name string `json:"name"`
	// Path and Header are a request's (Content-Length left out).
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
	// The bodies, with the request id as RID and the session id as SID.
	Create    string `json:"create"`
	Poll      string `json:"poll"`
	Restart   string `json:"restart"`
	Terminate string `json:"terminate"`
	// Login is every other body from the first to the room disco, in the
	// order of the request ids; Stanzas is what stands inside them.
	Login   []string `json:"login"`
	Stanzas []string `json:"stanzas"`
	// Sequence is the join whole, in the order of the request ids: the
	// session request, Login, and the restart where it was sent. The polls
	// and the caps answer, whose places differ from one run to the next,
	// are left out.
	Sequence []string `json:"sequence"`
	// DiscoReply and Leave are the bodies of the caps answer and the leave.
	DiscoReply string `json:"disco_reply"`
	Leave      string `json:"leave"`
	// Consecutive says the request ids went up by one from the first to the
	// terminate.
	Consecutive bool `json:"rids_consecutive"`
	// MaxInFlight is the most requests the client had open at once.
	MaxInFlight int           `json:"max_in_flight"`
	Split       []zzBOSHSplit `json:"split"`
}

const zzPollBody = `<body rid="RID" sid="SID" xmlns="http://jabber.org/protocol/httpbind"/>`

// zzSet is an IQ set from the focus, which a client acknowledges.
func zzSet(id string) string {
	return "<iq type='set' id='" + id + "' from='f@auth.meet.jitsi/focus' xmlns='jabber:client'><q xmlns='urn:x'/></iq>"
}

func zzBOSHVectors(t *testing.T) {
	hub := boshHub(t, boshGoHold)
	const user = "fedcba9876543210"
	hub.FixJID(user)
	room := hub.Named("secret-room")
	s := goEngine(t, hub, room, "olcrtc", engine.Config{})
	said := func() []string { return room.State().Transcripts[0] }
	within(t, 10*time.Second, "the login, the room disco and the caps answer", func() bool {
		st := room.State()
		return len(st.Transcripts) == 1 && len(st.Transcripts[0]) >= 8
	})
	sid := hub.BOSHSessions()[0].SID
	joined, _ := BOSHBodies(hub.BOSHSessions()[0])

	open := "<body xmlns='" + boshNS + "' sid='" + sid + "'>"
	rows := []struct{ name, reply string }{
		{"two stanzas back to back", open + zzSet("a1") + zzSet("a2") + "</body>"},
		{"elements of one name nested", open + "<iq type='set' id='n1' from='f@auth.meet.jitsi/focus' xmlns='jabber:client'><x><x><x/></x></x></iq>" + zzSet("n2") + "</body>"},
		{"white space between the stanzas", open + "\n  " + zzSet("w1") + "\n  " + zzSet("w2") + "\n</body>"},
		{"stanzas that close themselves", open + "<iq type='set' id='s1' from='f@auth.meet.jitsi/focus'/><presence from='secret-room@muc.meet.jitsi/zz' xmlns='jabber:client'/><iq type='set' id='s2' from='f@auth.meet.jitsi/focus'/></body>"},
		{"text with entities", open + "<iq type='set' id='t1' from='f@auth.meet.jitsi/focus'><q>1 &lt; 2 &gt; 0 &amp; so</q></iq>" + zzSet("t2") + "</body>"},
		{"attributes in double quotes", `<body xmlns="` + boshNS + `" sid="` + sid + `"><iq type="set" id="d1" from="f@auth.meet.jitsi/focus"><q a="1"/></iq></body>`},
		{"an entity for the tag end in a value", open + "<iq type='set' id='e1' from='f@auth.meet.jitsi/focus'><q a='1&gt;2'/></iq>" + zzSet("e2") + "</body>"},
		{"a body with nothing in it", "<body xmlns='" + boshNS + "' sid='" + sid + "'/>"},
		{"a body opened and closed", open + "</body>"},
		{"the stream's own attributes on the body", "<body xmlns='" + boshNS + "' xmlns:stream='http://etherx.jabber.org/streams' sid='" + sid + "' type='result'>" + zzSet("b1") + "</body>"},
		// Go's scanner ends a tag at the first '>', in a value too: it never
		// finds its way back to depth zero in this answer.
		{"a tag end written raw in a value", open + "<iq type='set' id='g1' from='f@auth.meet.jitsi/focus'><q a='1>2'/></iq>" + zzSet("g2") + "</body>"},
	}
	var split []zzBOSHSplit
	for i, row := range rows {
		from := len(said())
		end := fmt.Sprintf("end-%d", i)
		if !hub.BOSHInject(sid, row.reply, true) || !hub.BOSHInject(sid, zzSet(end), false) {
			t.Fatalf("row %q: the session is gone", row.name)
		}
		within(t, 10*time.Second, "the acknowledgement that closes row "+row.name, func() bool {
			for _, x := range said()[from:] {
				if attr(head(x), "id") == end {
					return true
				}
			}
			return false
		})
		out := zzBOSHSplit{Name: row.name, Reply: strings.ReplaceAll(row.reply, sid, "SID"), Acked: []string{}, AckedTo: []string{}}
		for _, x := range said()[from:] {
			h := head(x)
			if id := attr(h, "id"); strings.HasPrefix(x, "<iq ") && attr(h, "type") == "result" && id != end {
				out.Acked = append(out.Acked, id)
				out.AckedTo = append(out.AckedTo, attr(h, "to"))
			}
		}
		split = append(split, out)
	}

	_ = s.Close()
	within(t, 10*time.Second, "the leave and the terminate", func() bool {
		return room.State().Leaves == 1 && hub.BOSHSessions()[0].Terminated
	})
	b := hub.BOSHSessions()[0]
	all, consecutive := BOSHBodies(b)
	v := zzBOSH{
		Room: "secret-room", User: user, Nick: user[:8], Name: "olcrtc",
		Path: b.Requests[0].Path, Header: http.Header{}, Poll: zzPollBody,
		Consecutive: consecutive, MaxInFlight: b.MaxInFlight, Split: split,
	}
	for k, vals := range b.Requests[0].Header {
		if k != "Content-Length" {
			v.Header[k] = vals
		}
	}
	inner := func(body string) string {
		i := strings.Index(body, ">")
		return strings.TrimSuffix(body[i+1:], "</body>")
	}
	polls := 0
	for i, body := range joined {
		switch {
		case i == 0:
			v.Create = body
			v.Sequence = append(v.Sequence, body)
		case body == zzPollBody:
			polls++
		case strings.Contains(body, `xmpp:restart="true"`):
			v.Restart = body
			v.Sequence = append(v.Sequence, body)
		case strings.Contains(body, `type="result"`):
			v.DiscoReply = body
		default:
			v.Login = append(v.Login, body)
			v.Stanzas = append(v.Stanzas, inner(body))
			v.Sequence = append(v.Sequence, body)
		}
	}
	if polls == 0 {
		t.Error("the Go client sent no poll during the join")
	}
	v.Terminate = all[len(all)-1]
	for _, body := range all {
		if strings.Contains(body, `type="unavailable"`) {
			v.Leave = body
		}
	}
	zzvectors.Write(t, "jitsi/bosh.json", zzBOSHGenerator, []string{"j/internal/xmpp/conn.go", "internal/protect/protect.go"}, v)
}

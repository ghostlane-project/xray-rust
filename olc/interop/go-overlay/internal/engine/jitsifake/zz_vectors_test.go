// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the golden vectors of
// the fake's own half, what the Go engine at the pin says to a Jitsi room and
// asks of it: the login transcript, the leave, and the headers of the
// config.js request and of the WebSocket upgrade. The Rust client's join is
// held to them (olc/olc-jitsi, xmpp/muc.rs's test).

package jitsifake

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/engine/jitsifake/zz_vectors_test.go"

type zzTranscript struct {
	Room       string   `json:"room"`
	User       string   `json:"user"`
	Nick       string   `json:"nick"`
	Name       string   `json:"name"`
	Login      []string `json:"login"`
	DiscoReply string   `json:"disco_reply"`
	Leave      string   `json:"leave"`
}

type zzHeaders struct {
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
}

type zzHandshake struct {
	ConfigJS zzHeaders `json:"config_js"`
	Upgrade  zzHeaders `json:"upgrade"`
}

// zzHeader is a handshake with what differs run to run taken out: the
// WebSocket key, and the fake's host (port) wherever it stands.
func zzHeader(hub *Hub, h Handshake) zzHeaders {
	out := http.Header{}
	for k, v := range h.Header {
		if strings.EqualFold(k, "Sec-Websocket-Key") {
			continue
		}
		for _, one := range v {
			out.Add(k, strings.ReplaceAll(one, hub.Host(), "HOST"))
		}
	}
	return zzHeaders{Path: h.Path, Header: out}
}

func TestZZVectors(t *testing.T) {
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	const user = "0123456789abcdef"
	hub.FixJID(user)
	room := hub.Named("secret-room")
	s := goEngine(t, hub, room, "olcrtc", engine.Config{})
	within(t, 10*time.Second, "the login and the room disco", func() bool {
		st := room.State()
		return len(st.Transcripts) == 1 && len(st.Transcripts[0]) >= 11
	})
	_ = s.Close()
	within(t, 10*time.Second, "the leave echo", func() bool { return room.State().Leaves == 1 })
	st := room.State()
	said := st.Transcripts[0]
	zzvectors.Write(t, "jitsi/transcript.json", zzGenerator, []string{"internal/engine/jitsi/jitsi.go", "j/internal/xmpp/conn.go"},
		zzTranscript{Room: "secret-room", User: user, Nick: user[:8], Name: "olcrtc", Login: said[:10], DiscoReply: said[10], Leave: said[len(said)-1]})
	zzvectors.Write(t, "jitsi/handshake.json", zzGenerator, []string{"j/internal/xmpp/conn.go"},
		zzHandshake{ConfigJS: zzHeader(hub, st.Config[0]), Upgrade: zzHeader(hub, st.Upgrades[0])})
	// The same engine over BOSH: jitsi/bosh.json (zz_vectors_bosh_test.go).
	zzBOSHVectors(t)
}

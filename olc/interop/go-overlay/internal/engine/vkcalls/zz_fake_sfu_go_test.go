//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the fake VK Calls SFU
// (zz_fake_sfu_test.go) held to the engine at the pin, with no Rust client:
//
//   - TestFakeVKTakesTheGoEngine: two sessions of the engine in one room.
//     Each joins, publishes, is named to the other and hears it, wrapped in
//     RED; both answer a later offer; both leave. The fake trips over
//     nothing, which is what lets a trip under the Rust client mean
//     something;
//   - TestFakeVKTripsOnWhatTheEngineDoesNotSend: each check of the fake
//     fails for the change it names;
//   - TestPionHoldsNeitherTheVKOfferNorItsAnswer: why the fake is not a pion
//     PeerConnection;
//   - TestServeFakeVKSFU serves the fake to a process outside this package
//     (the gate's vkfake target).

package vkcalls

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
)

// fakeVKWithin waits for ok.
func fakeVKWithin(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %s", limit, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeVKJoined is one session of the engine in a room of the fake.
type fakeVKJoined struct {
	session *Session
	track   *webrtc.TrackLocalStaticSample
	heard   chan *webrtc.TrackRemote
}

// fakeVKJoin connects a session of the engine at endpoint, publishing a VP8
// track as the video transport does.
func fakeVKJoin(t *testing.T, endpoint string) *fakeVKJoined {
	t.Helper()
	made, err := New(context.Background(), engine.Config{URL: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := made.(*Session)
	if !ok {
		t.Fatalf("New made a %T", made)
	}
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000},
		"vp8channel-"+fakeVKHex(4), "olcrtc-"+fakeVKHex(4))
	if err != nil {
		t.Fatal(err)
	}
	if err := session.AddVideoTrack(track); err != nil {
		t.Fatal(err)
	}
	j := &fakeVKJoined{session: session, track: track, heard: make(chan *webrtc.TrackRemote, 8)}
	session.SetVideoTrackHandler(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		select {
		case j.heard <- remote:
		default:
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := session.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return j
}

// publish writes samples until done closes.
func (j *fakeVKJoined) publish(done <-chan struct{}) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	sample := media.Sample{Data: make([]byte, 300), Duration: 20 * time.Millisecond}
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			_ = j.track.WriteSample(sample)
		}
	}
}

// fakeVKLegOf is the last leg of role in st.
func fakeVKLegOf(st FakeVKState, role string) FakeVKLeg {
	for i := len(st.Legs) - 1; i >= 0; i-- {
		if st.Legs[i].Role == role {
			return st.Legs[i]
		}
	}
	return FakeVKLeg{}
}

// Two sessions of the engine at the pin in one room of the fake, in each of
// its two shapes: the live one, and a publish slot that names no RTX.
func TestFakeVKTakesTheGoEngine(t *testing.T) {
	sfu, err := NewFakeVK()
	if err != nil {
		t.Skipf("the fake needs a host interface and a loopback listener: %v", err)
	}
	defer sfu.Close()
	t.Run("the live shape", func(t *testing.T) { fakeVKTwoEngines(t, sfu.Open()) })
	t.Run("a publish slot without RTX", func(t *testing.T) {
		room := sfu.OpenNoRTX()
		fakeVKTwoEngines(t, room)
		for _, leg := range room.State().Legs {
			if leg.RTX != 0 {
				t.Errorf("%s: %d packets at the RTX payload type the slot does not name", leg.Role, leg.RTX)
			}
		}
	})
}

func fakeVKTwoEngines(t *testing.T, room *FakeVKRoom) {
	t.Helper()
	done := make(chan struct{})
	defer close(done)

	first := fakeVKJoin(t, room.Guest("first"))
	go first.publish(done)
	second := fakeVKJoin(t, room.Guest("second"))
	go second.publish(done)

	// Each hears the other's camera, as the SFU forwards it: red at the
	// receive slots' number, the primary block the publisher's VP8.
	for name, j := range map[string]*fakeVKJoined{"first": first, "second": second} {
		var remote *webrtc.TrackRemote
		select {
		case remote = <-j.heard:
		case <-time.After(20 * time.Second):
			t.Fatalf("%s heard no track; the room: %+v", name, room.State())
		}
		if got := remote.Codec().MimeType; !strings.EqualFold(got, "video/red") || remote.PayloadType() != fakeVKRed {
			t.Errorf("%s hears %s at %d, want video/red at %d", name, got, remote.PayloadType(), fakeVKRed)
		}
		pkt, _, err := remote.ReadRTP()
		if err != nil {
			t.Fatalf("%s: read: %v", name, err)
		}
		if len(pkt.Payload) < 2 || pkt.Payload[0] != fakeVKVP8 {
			t.Errorf("%s: the forwarded packet's primary block is not VP8 at %d", name, fakeVKVP8)
		}
	}

	// The perf report comes every five seconds, and both keep publishing
	// past a receiver report.
	fakeVKWithin(t, 15*time.Second, "a perf report and packets after a receiver report from both", func() bool {
		st := room.State()
		a, b := fakeVKLegOf(st, "first"), fakeVKLegOf(st, "second")
		return a.Perf > 0 && b.Perf > 0 && a.AfterReport > 0 && b.AfterReport > 0 && a.Pongs > 0 && b.Pongs > 0
	})

	// A later offer is answered on the same connection.
	if n := room.Reoffer(); n != 2 {
		t.Fatalf("%d legs were offered again, want 2", n)
	}
	fakeVKWithin(t, 15*time.Second, "both answering the later offer", func() bool {
		st := room.State()
		return fakeVKLegOf(st, "first").Answers == 2 && fakeVKLegOf(st, "second").Answers == 2
	})
	before := room.State()
	fakeVKWithin(t, 10*time.Second, "media both ways after the later offer", func() bool {
		st := room.State()
		return fakeVKLegOf(st, "first").Forwarded > fakeVKLegOf(before, "first").Forwarded &&
			fakeVKLegOf(st, "second").Forwarded > fakeVKLegOf(before, "second").Forwarded
	})

	_ = first.session.Close()
	_ = second.session.Close()
	fakeVKWithin(t, 10*time.Second, "both hanging up", func() bool {
		st := room.State()
		return fakeVKLegOf(st, "first").Hangup && fakeVKLegOf(st, "second").Hangup
	})

	st := room.State()
	if len(st.Errors) != 0 {
		t.Errorf("the fake tripped over the engine at the pin:\n %s", strings.Join(st.Errors, "\n "))
	}
	if len(st.Legs) != 2 {
		t.Fatalf("%d legs, want 2", len(st.Legs))
	}
	want := []string{"allocate-consumer", "update-media-modifiers", "change-media-settings", "accept-producer",
		"accept-producer", "hangup"}
	for _, role := range []string{"first", "second"} {
		leg := fakeVKLegOf(st, role)
		if !slices.Equal(leg.Commands, want) {
			t.Errorf("%s: commands %q, want %q", role, leg.Commands, want)
		}
		if leg.Channels["producerNotification"] != 0 || leg.Channels["producerCommand"] != 2 || len(leg.Channels) != 2 {
			t.Errorf("%s: channels %v", role, leg.Channels)
		}
		if leg.Simulcast != 1 || leg.Layouts == 0 || leg.Packets == 0 || leg.Reports == 0 || leg.Sources != 1 {
			t.Errorf("%s: %+v", role, leg)
		}
		if len(leg.LastLayout) != 1 || leg.LastLayout[0] != "#0" {
			t.Errorf("%s: the last layout names %q, want the other's camera by its compact id", role, leg.LastLayout)
		}
	}
	// The one who was alone had to ask for the later camera by its key: the
	// fake names a camera that came later only when asked. (The one who
	// came second is told of the first unasked, and may still have asked
	// before the registry frame reached it.)
	if a := fakeVKLegOf(st, "first"); a.KeyAsks == 0 {
		t.Errorf("the first never asked for the second's camera by its key: %+v", a)
	}
}

// fakeVKTestOffer is an offer of the fake with fixed values.
func fakeVKTestOffer() string {
	return fakeVKOffer(1, []string{"1 1 udp 1 192.0.2.1 43210 typ host"}, "QcK1avCrgDjn21p",
		"GZU7Kw3Sq1YSJxrABCtRTGhms", strings.TrimSuffix(strings.Repeat("3A:", 32), ":"), 2463708138,
		[]*fakeVKSlot{{mid: "5", ssrc: 2463708139}, {mid: "6", ssrc: 2463708140}}, true)
}

// fakeVKTestNative is what the shaper takes from a native answer.
const fakeVKTestNative = "v=0\n" +
	"m=video 9 UDP/TLS/RTP/SAVPF 100\n" +
	"a=ice-ufrag:KdfaZFqRLOnUhmUW\n" +
	"a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\n" +
	"a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\n" +
	"a=mid:3\na=sendonly\n" +
	"a=msid:olcrtc-0a1b2c3d vp8channel-4e5f6a7b\n" +
	"a=ssrc:3842537998 cname:proofkit\n"

// The fake's offer is the live shape (the engine's own view of it is one
// pion takes, as TestLiveShapeKeepsReceiveNumbering), and neither that
// offer nor the answer the engine shapes for it fits a pion media engine:
// one payload type names two codecs. So the fake cannot be a pion
// PeerConnection; it writes the offer and reads the answer itself.
func TestPionHoldsNeitherTheVKOfferNorItsAnswer(t *testing.T) {
	offer := fakeVKTestOffer()
	if _, err := offerMediaEngine(offer); err == nil {
		t.Error("a pion media engine holds the fake's offer: the fake no longer has VK's payload clash")
	} else {
		t.Logf("pion on the offer: %v", err)
	}
	shaped, err := ShapeAnswer(offer, fakeVKTestNative, NewShapeState())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offerMediaEngine(shaped); err == nil {
		t.Error("a pion media engine holds the shaped answer: a pion offerer could be given it whole")
	} else {
		t.Logf("pion on the shaped answer: %v", err)
	}
	view, err := pionView(offer, vp8Publish(), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertOneMeaning(t, view)
	if _, err := offerMediaEngine(view); err != nil {
		t.Errorf("the engine's view of the fake's offer: %v", err)
	}
	plain := fakeVKOffer(1, []string{"1 1 udp 1 192.0.2.1 43210 typ host"}, "QcK1avCrgDjn21p",
		"GZU7Kw3Sq1YSJxrABCtRTGhms", strings.TrimSuffix(strings.Repeat("3A:", 32), ":"), 2463708138,
		[]*fakeVKSlot{{mid: "5", ssrc: 2463708139}}, false)
	if !strings.Contains(offer, "m=video 9 UDP/TLS/RTP/SAVPF 100 101 98 99 102 103 104\r\n") ||
		!strings.Contains(plain, "m=video 9 UDP/TLS/RTP/SAVPF 100 98 99 102 103 104\r\n") ||
		strings.Count(plain, "a=fmtp:101 apt=100") != 1 || strings.Count(offer, "a=fmtp:101 apt=100") != 3 {
		t.Error("the two shapes differ in more or less than the publish slot's RTX for VP8")
	}
	plainView, err := pionView(plain, vp8Publish(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offerMediaEngine(plainView); err != nil {
		t.Errorf("the engine's view of the offer without RTX: %v", err)
	}
	if got := publishMid(offer); got != fakeVKPublishMid {
		t.Errorf("the offer's publish slot is mid %q, the fake reads %q", got, fakeVKPublishMid)
	}
	if got := remoteSSRCs(offer); !slices.Equal(got, []string{"2463708138", "2463708139", "2463708140"}) {
		t.Errorf("the offer's SSRCs: %q", got)
	}
}

// Each check of the fake fails for the change it names, and passes what the
// engine writes.
func TestFakeVKTripsOnWhatTheEngineDoesNotSend(t *testing.T) {
	// The producer commands.
	width, height, fps, kbps := layerProfile()
	layout := func(sequence int, entries ...LayoutEntry) []byte {
		frame, err := EncodeLayout(sequence, entries)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	tile := LayoutEntry{Compact: 3, ByCompact: true, Priority: 1, Width: 640, Height: 360}
	byKey := LayoutEntry{Key: "u100000000001:sCAMERA", Priority: 1, Width: 640, Height: 360}
	many := make([]LayoutEntry, 17)
	for i := range many {
		many[i] = tile
		many[i].Compact = uint8(i)
	}
	for _, c := range []struct {
		name  string
		frame []byte
		kind  string
		bad   string
	}{
		{"change-simulcast", encodeChangeSimulcast(1, "l", width, height, fps, kbps*1000), "change-simulcast", ""},
		{"change-simulcast under a large sequence", encodeChangeSimulcast(40000, "l", width, height, fps, kbps*1000), "change-simulcast", ""},
		{"another layer", encodeChangeSimulcast(1, "m", width, height, fps, kbps*1000), "", "not the engine's bytes"},
		{"another bitrate", encodeChangeSimulcast(1, "l", width, height, fps, 500000), "", "not the engine's bytes"},
		{"a bitrate in bit/s", encodeChangeSimulcast(1, "l", width, height, fps, kbps*1000*1000), "", "not the engine's bytes"},
		{"a layout by compact id", layout(2, tile), "layout", ""},
		{"a layout by key", layout(300, byKey, tile), "layout", ""},
		{"a layout of seventeen", layout(3, many...), "layout", ""},
		{"a layout at priority 2", layout(2, LayoutEntry{Compact: 3, ByCompact: true, Priority: 2, Width: 640, Height: 360}), "", "priority 2"},
		{"a layout with no size", layout(2, LayoutEntry{Key: "42:sCAMERA"}), "", "priority 0"},
		{"a layout cut short", layout(2, tile)[:9], "", "not the shape"},
		{"a perf report", encodePerfStatReport(7, 1234, 1234), "perf", ""},
		{"a perf report of two counts", encodePerfStatReport(7, 10, 11), "", "one count twice"},
		{"another command", []byte{0x05, 0x00, 0x01}, "", "kind 5"},
		{"no frame", nil, "", "not the shape"},
	} {
		got, err := fakeVKReadControl(c.frame)
		switch {
		case c.bad == "" && (err != nil || got.kind != c.kind):
			t.Errorf("%s: read as %q, %v", c.name, got.kind, err)
		case c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s: %v, want a refusal naming %q", c.name, err, c.bad)
		}
	}
	if got, err := fakeVKReadControl(layout(300, byKey, tile)); err != nil || len(got.entries) != 2 ||
		got.entries[0] != byKey || got.entries[1] != tile || got.sequence != 300 {
		t.Errorf("a layout read back: %+v, %v", got, err)
	}

	// The shaped answer.
	offer := fakeVKTestOffer()
	state := NewShapeState()
	shaped, err := ShapeAnswer(offer, fakeVKTestNative, state)
	if err != nil {
		t.Fatal(err)
	}
	id, err := fakeVKCheckAnswer(offer, shaped, 1, -1)
	if err != nil || id != state.SessionID {
		t.Fatalf("the engine's own answer: %v (session %d, want %d)", err, id, state.SessionID)
	}
	again, err := ShapeAnswer(offer, fakeVKTestNative, state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fakeVKCheckAnswer(offer, again, 2, id); err != nil {
		t.Errorf("the engine's second answer: %v", err)
	}
	for _, c := range []struct {
		name, from, to string
		n              int
		id             int64
		bad            string
	}{
		{"a passive answer", "a=setup:active", "a=setup:passive", 1, -1, "a=setup:passive"},
		{"no trickle", "a=ice-options:trickle\r\n", "", 1, -1, "the engine's shaper writes"},
		{"an a=ssrc in the publish slot", "a=rid:l send", "a=ssrc:1 cname:x\r\na=rid:l send", 1, -1, "a=ssrc:1 cname:x"},
		{"another layer", "a=simulcast:send l;m;h", "a=simulcast:send l", 1, -1, "a=simulcast:send l"},
		{"a codec left out", "a=rtpmap:106 ulpfec/90000\r\n", "", 1, -1, "the engine's shaper writes"},
		{"a second answer at the first's version", "", "", 2, -1, "o= version 2"},
		{"another session id", "", "", 1, 5, "session id changed"},
		{"no fingerprint", "a=fingerprint:", "a=fingerprint-", 1, -1, "no fingerprint"},
		{"no msid", "a=msid:", "a=msid-", 1, -1, "no a=msid"},
		{"another m= line", "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel", "\r\nm=application 0 UDP/DTLS/SCTP webrtc-datachannel", 1, -1, "m=application 0"},
	} {
		text := shaped
		if c.from != "" {
			text = strings.ReplaceAll(shaped, c.from, c.to)
			if text == shaped {
				t.Fatalf("%s: the answer has no %q", c.name, c.from)
			}
		}
		if _, err := fakeVKCheckAnswer(offer, text, c.n, c.id); err == nil || !strings.Contains(err.Error(), c.bad) {
			t.Errorf("%s: %v, want a refusal naming %q", c.name, err, c.bad)
		}
	}
	// A refusal at a credential's line says neither side of it.
	const pwdLine = "a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc"
	at := strings.LastIndex(shaped, pwdLine)
	if at < 0 {
		t.Fatal("the answer has no ICE password line")
	}
	other := shaped[:at] + "a=ice-pwd:AnotherPasswordOfTheSameLength01" + shaped[at+len(pwdLine):]
	if _, err := fakeVKCheckAnswer(offer, other, 1, -1); err == nil || !strings.Contains(err.Error(), "a=ice-pwd:<") ||
		strings.Contains(err.Error(), "WTugXt") || strings.Contains(err.Error(), "AnotherPassword") {
		t.Errorf("a refusal at the ICE password: %v, want one that says neither password", err)
	}

	// A published packet.
	stamped := func(mid, rid string, abs bool) *rtp.Header {
		h := &rtp.Header{Version: 2, PayloadType: fakeVKVP8}
		if mid != "" {
			_ = h.SetExtension(fakeVKExtMid, []byte(mid))
		}
		if rid != "" {
			_ = h.SetExtension(fakeVKExtRid, []byte(rid))
		}
		if abs {
			_ = h.SetExtension(fakeVKExtAbsSendTime, []byte{1, 2, 3})
		}
		return h
	}
	for _, c := range []struct {
		name string
		h    *rtp.Header
		bad  string
	}{
		{"the engine's", stamped("3", "l", false), ""},
		{"no mid", stamped("", "l", false), "whose mid is"},
		{"another mid", stamped("5", "l", false), "whose mid is"},
		{"no rid", stamped("3", "", false), "whose rid is"},
		{"another rid", stamped("3", "m", false), "whose rid is"},
		{"abs-send-time", stamped("3", "l", true), "abs-send-time"},
	} {
		if got := fakeVKPacketFault(c.h); (c.bad == "") != (got == "") || !strings.Contains(got, c.bad) {
			t.Errorf("%s: %q, want %q", c.name, got, c.bad)
		}
	}

	// A registry frame of the fake is one the engine reads.
	reg, err := ParseRegistry(fakeVKRegistry(map[string]uint8{"u100000000002:sCAMERA": 1, "u100000000001:sCAMERA": 0}))
	if err != nil || len(reg) != 2 || reg["u100000000001:sCAMERA"] != 0 || reg["u100000000002:sCAMERA"] != 1 {
		t.Errorf("the fake's registry frame read by the engine: %v, %v", reg, err)
	}

	// One counter for the producer commands: a number is used once, in
	// whatever order the frames come.
	room := &FakeVKRoom{guests: map[string]*fakeVKGuest{}}
	leg := &fakeVKLeg{room: room, guest: &fakeVKGuest{id: "1", role: "x"}, layout: map[uint8]bool{},
		registry: map[string]uint8{}, controlSeen: map[int]bool{}}
	leg.onControl(encodePerfStatReport(3, 1, 1))
	leg.onControl(encodePerfStatReport(2, 1, 1))
	if len(room.errs) != 0 || leg.perf != 2 {
		t.Errorf("two reports out of order: %d read, trips %q", leg.perf, room.errs)
	}
	leg.onControl(encodePerfStatReport(3, 2, 2))
	if len(room.errs) != 1 || !strings.Contains(room.errs[0], "sequence 3, which was used before") {
		t.Errorf("a sequence number used twice: trips %q", room.errs)
	}

	// The commands of a join.
	for i, name := range fakeVKCommands[:3] {
		frame, err := fakeVKWant(name, int64(i)+1)
		if err != nil || !strings.HasPrefix(string(frame), fmt.Sprintf(`{"command":%q,"sequence":%d,`, name, i+1)) {
			t.Errorf("%s: %s, %v", name, frame, err)
		}
	}
	if frame, err := fakeVKWant("accept-producer", 4); frame != nil || err != nil {
		t.Errorf("accept-producer has a fixed frame: %s, %v", frame, err)
	}
}

// The fake for a process outside this package.
const (
	// fakeVKServeEnv switches TestServeFakeVKSFU on.
	fakeVKServeEnv = "OLC_FAKE_VK_SFU_SERVE"
	// fakeVKServeMarker opens the line that says where the hooks listen, on
	// stdout.
	fakeVKServeMarker = "FAKE VK SFU HOOKS LISTENING ON "
	// fakeVKServeLifetime bounds the server when the parent never closes
	// stdin.
	fakeVKServeLifetime = 70 * time.Minute
)

// fakeVKHooks is the fake over loopback HTTP:
//
//	POST /open                   a room: {"room","url"}
//	POST /guest?room=R&role=W    a participant of it: {"url"}, its endpoint
//	GET  /state?room=R           FakeVKState and "secrets"
//	POST /reoffer?room=R         one more offer to every connected leg
//	POST /drop?room=R            every socket and media leg goes
//	POST /close?room=R           the room ends; its state
type fakeVKHooks struct{ sfu *FakeVK }

func (h fakeVKHooks) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	if req.Method+" "+req.URL.Path == "POST /open" {
		room := h.sfu.Open()
		reply(map[string]any{"room": room.ID(), "url": room.URL()})
		return
	}
	room := h.sfu.Room(req.URL.Query().Get("room"))
	if room == nil {
		http.Error(w, "no such room", http.StatusNotFound)
		return
	}
	switch req.Method + " " + req.URL.Path {
	case "POST /guest":
		reply(map[string]any{"url": room.Guest(req.URL.Query().Get("role"))})
		return
	case "GET /state":
	case "POST /reoffer":
		room.Reoffer()
	case "POST /drop":
		room.Drop()
	case "POST /close":
		room.Shutdown()
	default:
		http.NotFound(w, req)
		return
	}
	st := room.State()
	reply(map[string]any{"errors": st.Errors, "legs": st.Legs, "secrets": room.Secrets()})
}

// TestServeFakeVKSFU serves the fake and its hooks (fakeVKHooks) until its
// stdin closes (the parent's end) or fakeVKServeLifetime. The line
// fakeVKServeMarker opens, on stdout, says where the hooks listen.
func TestServeFakeVKSFU(t *testing.T) {
	if os.Getenv(fakeVKServeEnv) != "1" {
		t.Skip(fakeVKServeEnv + "=1 runs the fake SFU's server (the gate's vkfake target starts it)")
	}
	sfu, err := NewFakeVK()
	if err != nil {
		t.Fatal(err)
	}
	defer sfu.Close()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: fakeVKHooks{sfu: sfu}, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("%s%s\n", fakeVKServeMarker, ln.Addr())
	stdin := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdin)
	}()
	select {
	case <-stdin:
	case <-time.After(fakeVKServeLifetime):
		t.Errorf("served for %s without the parent closing stdin", fakeVKServeLifetime)
	}
	_ = srv.Close()
}

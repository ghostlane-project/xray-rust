// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the forwarding fake
// held to the Go engine at the pin, with no Rust client: two engines on
// direct credentials in one room hear each other, and the room turns away
// what the service would.

package mtslinkfake

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/engine/mtslink"
)

// blackKeyframe is a real VP9 keyframe (libvpx, a black 320x180 picture), the
// engine's own test sample (mtslink_test.go): pion's VP9 packetizer reads a
// frame's header and sends nothing for bytes that are no frame.
var blackKeyframe = []byte{
	0x82, 0x49, 0x83, 0x42, 0x60, 0x13, 0xf0, 0x0b, 0x36, 0x66, 0x38, 0x24, 0x1c, 0x19, 0x92, 0x00,
	0x00, 0x50, 0x43, 0xe8, 0xbf, 0x40, 0x00, 0x67, 0x3f, 0xfe, 0x2f, 0x20, 0x00, 0x04, 0xee, 0x66,
	0xa7, 0x89, 0xd3, 0xfb, 0x17, 0xd3, 0x70, 0x4c, 0xc4, 0xe7, 0xd9, 0x1b, 0x5b, 0xe5, 0xac, 0x4c,
	0x31, 0x1d, 0x90, 0x67, 0xac, 0xb3, 0x74, 0x35, 0x3e, 0x92, 0xab, 0xc1, 0xec, 0x2d, 0xe8, 0x00,
	0x85, 0x59, 0x2c, 0xf0,
}

// goGuest is a Go engine in the room, publishing, and what it heard.
type goGuest struct {
	session *mtslink.Session
	track   *webrtc.TrackLocalStaticSample
	heard   atomic.Int64
	asked   atomic.Int64
}

func joinGo(t *testing.T, room *Room, name string) *goGuest {
	t.Helper()
	g := room.Guest(name)
	// Direct credentials: the room join and the cookies, no Extra.
	sess, err := mtslink.New(context.Background(), engine.Config{URL: g.URL, Token: g.Token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s, ok := sess.(*mtslink.Session)
	if !ok {
		t.Fatalf("New returned %T", sess)
	}
	t.Cleanup(func() { _ = s.Close() })
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: s.VideoCodec(), ClockRate: 90000, SDPFmtpLine: "profile-id=0"}, "video", "olcrtc")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddVideoTrack(track); err != nil {
		t.Fatal(err)
	}
	out := &goGuest{session: s, track: track}
	s.SetVideoTrackHandler(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			if _, _, err := remote.ReadRTP(); err != nil {
				return
			}
			out.heard.Add(1)
		}
	})
	s.SetKeyframeRequestHandler(func() { out.asked.Add(1) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Connect(ctx); err != nil {
		t.Fatalf("Connect as %s: %v", name, err)
	}
	return out
}

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

func TestTwoGoEnginesHearEachOtherThroughTheRoom(t *testing.T) {
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	room := hub.Open()
	defer func() {
		if t.Failed() {
			t.Logf("the room: %+v", room.State())
		}
	}()
	a, b := joinGo(t, room, "a"), joinGo(t, room, "b")
	sample := media.Sample{Data: blackKeyframe, Duration: 20 * time.Millisecond}
	within(t, 15*time.Second, "each engine hearing the other's video", func() bool {
		_ = a.track.WriteSample(sample)
		_ = b.track.WriteSample(sample)
		return a.heard.Load() > 0 && b.heard.Load() > 0
	})
	// A guest that starts to hear a publisher makes the room ask that
	// publisher for a keyframe.
	within(t, 10*time.Second, "the room's keyframe requests reaching both publishers", func() bool {
		return a.asked.Load() > 0 && b.asked.Load() > 0
	})
	st := room.State()
	if len(st.Joins) != 2 || st.Pins != 2 || len(st.Refused)+len(st.Leaves)+len(st.Strays)+st.CookiesAtSFU != 0 {
		t.Errorf("state = %+v, want two joins, two pins and nothing else", st)
	}
	for _, j := range st.Joins {
		if j.Pair != "udp" || j.Published == 0 || j.Heard == 0 || j.Slots != Slots {
			t.Errorf("join %+v, want a UDP pair with video both ways", j)
		}
	}
	if st.Keyframes < 2 {
		t.Errorf("%d keyframe requests passed back, want one per publisher at least", st.Keyframes)
	}

	// A guest that leaves frees its slot: the one that stays is sent
	// nothing more, and a third hears the one that stays.
	_ = b.session.Close()
	within(t, 10*time.Second, "the room dropping the guest that left", func() bool {
		room.mu.Lock()
		defer room.mu.Unlock()
		return len(room.peers) == 1
	})
	c := joinGo(t, room, "c")
	within(t, 15*time.Second, "a third guest hearing the first", func() bool {
		_ = a.track.WriteSample(sample)
		return c.heard.Load() > 0
	})
}

func TestTheRoomTurnsAwayWhatTheServiceWould(t *testing.T) {
	hub, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	room := hub.Open()
	g := room.Guest("a")
	post := func(url, contentType, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	const player = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\na=recvonly\r\n"
	one := "v=0\r\n" + player
	two := one + strings.Replace(player, "a=mid:2", "a=mid:3", 1)
	described := g.URL + "&twcc=true&originMid=2&preferredPublishCodec=vp9"
	for _, c := range []struct {
		what, url, contentType, offer string
		status                        int
		words                         string
	}{
		{"a guest the room never minted", strings.Replace(described, "joinToken=vcJOIN", "joinToken=vcOTHER", 1),
			"application/sdp", one, http.StatusForbidden, "no such guest"},
		{"two audio players", described, "application/sdp", two, http.StatusBadRequest,
			"SDP validation error: exceeded maximal audio players value 1"},
		{"an originMid that is not the player's", strings.Replace(described, "originMid=2", "originMid=0", 1),
			"application/sdp", one, http.StatusBadRequest, "SDP validation error: originMid"},
		{"a join that does not describe its offer", g.URL + "&originMid=2", "application/sdp", one,
			http.StatusBadRequest, "SDP validation error: the join does not describe"},
		{"a body that is no SDP by its type", described, "application/json", one, http.StatusBadRequest, "not an SDP"},
		{"an offer pion refuses", described, "application/sdp", one, http.StatusBadRequest, "SDP validation error: "},
		{"another room", strings.Replace(described, "/rtc/room/", "/rtc/room/9", 1), "application/sdp", one,
			http.StatusNotFound, "no such room"},
	} {
		status, words := post(c.url, c.contentType, c.offer)
		if status != c.status || !strings.Contains(words, c.words) {
			t.Errorf("%s: %d %q, want %d and %q", c.what, status, words, c.status, c.words)
		}
	}
	if status, _ := post(hub.Base()+"/rtc/peer/nobody/pin", "application/json", `{"streams":[""]}`); status != http.StatusNotFound {
		t.Errorf("a pin of no peer: %d", status)
	}
	// The take-back: the guest's conference, with the guest's cookies.
	leave := func(conference, cookies string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
			hub.Base()+"/api/conferences/"+conference, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Cookie", cookies)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := leave(g.Conference, "access=other"); got != http.StatusUnauthorized {
		t.Errorf("a take-back without the guest's cookies: %d", got)
	}
	if got := leave(g.Conference, g.Token); got != http.StatusNoContent {
		t.Errorf("the guest's take-back: %d", got)
	}
	st := room.State()
	if len(st.Leaves) != 1 || st.Leaves[0] != g.Conference || len(st.Joins) != 0 || len(st.Refused) != 6 {
		t.Errorf("state = %+v, want one conference taken back, six refusals and no join", st)
	}
	// A room that closed answers no join, and its link names it apart
	// from every guest's join.
	if !strings.Contains(room.Link(), "/j/") || strings.Contains(g.URL, room.Link()) {
		t.Errorf("the room's link is not a name of its own")
	}
	for _, secret := range g.Secrets {
		if secret == "" || len(secret) < 8 {
			t.Errorf("a guest's secret is too short to look for: %d bytes", len(secret))
		}
	}
	room.Close()
	if status, _ := post(described, "application/sdp", one); status != http.StatusNotFound {
		t.Errorf("a join of a closed room: %d", status)
	}
}

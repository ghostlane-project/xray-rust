//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): a fake VK Calls SFU
// that carries media, for T2 of the VK Calls carrier (M7.9). No VK service is
// contacted and no call exists: a WebSocket and a UDP port on this host.
//
// What it is. The signalling socket of calls.okcdn.ru as the engine at the
// pin speaks it, and behind every socket one media leg: pion's ICE agent
// (lite, as VK's), pion's DTLS server, SRTP and SCTP with the two service
// channels. The fake is the offerer. Its offer is VK-shaped: the live
// shape of negotiate_test.go (liveShapeOffer), where the publish slot says
// 102 is red and 104 ulpfec and every receive slot says 102 is VP9 and 104
// red, with the leg's own candidates, credentials, fingerprint and SSRCs.
//
// Why not a pion PeerConnection as the offerer. A PeerConnection keeps one
// codec per payload type (the engine's #72), so it can neither write that
// offer nor take the shaped answer, which repeats the offer's numbering
// (TestPionHoldsNeitherTheVKOfferNorItsAnswer). The plan's fallback is
// taken: the fake writes the offer and reads the answer itself, and pion
// does the transport under it.
//
// What it holds a client to. The fake has the engine's own functions, so it
// makes the frame Go would have sent and compares bytes:
//
//   - the socket's query (signalingURL) and its Origin, Referer and
//     User-Agent;
//   - every signalling command, in Go's order, under Go's sequence numbers:
//     allocate-consumer, update-media-modifiers, change-media-settings,
//     accept-producer (the offer's SSRCs and session), hangup;
//   - the shaped answer: ShapeAnswer of the fake's offer and the answer's
//     own credentials, fingerprint, msid and o= line, byte for byte;
//   - the service channels: producerNotification on stream 0,
//     producerCommand on stream 2;
//   - the three producer commands: change-simulcast (the layer l), the
//     layout (EncodeLayout of what it names) and the perf report, each
//     under a sequence number of its own;
//   - every published packet: VP8 at the publish slot's payload type, the
//     slot's mid and the rid l in its header extensions, no abs-send-time.
//     The fake sends a receiver report every second, so "every packet"
//     includes the ones after a report.
//
// Anything else is recorded (FakeVKState.Errors); a room that tripped fails
// its test. What it does as the comments of vkcalls.go say the SFU does:
//
//   - a camera is forwarded only once its publisher sent change-simulcast,
//     only to a consumer whose layout names it by its compact id, and only
//     while that consumer's perf reports keep coming;
//   - the registry names, unasked, the cameras that were in the room when a
//     consumer's notification channel opened; a later camera is named when a
//     layout asks for it by its string key;
//   - what is forwarded is the publisher's VP8 wrapped in RED (RFC 2198, one
//     primary block) at the receive slot's red number and the slot's SSRC.

package vkcalls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/datachannel"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/fingerprint"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sctp"
	"github.com/pion/srtp/v3"
	"github.com/pion/transport/v4/packetio"
)

const (
	// The live shape's numbers (liveShapeOffer): the publish slot and what a
	// receive slot carries.
	fakeVKPublishMid = "3"
	fakeVKVP8        = 100
	fakeVKRTX        = 101
	fakeVKRed        = 104
	// The publish slot's header extensions, by the ids the offer gives them.
	fakeVKExtAbsSendTime = 3
	fakeVKExtRid         = 10
	fakeVKExtMid         = 14
	// fakeVKSlots is how many receive slots an offer opens with; a later
	// offer (Reoffer) adds one.
	fakeVKSlots = 2
	// fakeVKStall is how long a consumer is forwarded to without a perf
	// report (the SDK reports every 5 s; vkcalls.go: "without them the
	// forward is stalled within a minute").
	fakeVKStall = 15 * time.Second
	// fakeVKReport is how often a leg is sent a receiver report, and
	// fakeVKPing a text ping.
	fakeVKReport = time.Second
	fakeVKPing   = 3 * time.Second
	// fakeVKMediaWait bounds ICE and DTLS of one leg.
	fakeVKMediaWait = 30 * time.Second
	// fakeVKErrors bounds what a room remembers of its trips.
	fakeVKErrors = 24

	fakeVKGoUserAgent = "Go-http-client/1.1"
	fakeVKOrigin      = "https://vk.com"
	fakeVKReferer     = "https://vk.com/"
)

var errFakeVKShape = errors.New("not the shape the engine writes")

// FakeVK is the fake SFU: one signalling listener, any number of rooms.
type FakeVK struct {
	srv         *httptest.Server
	cert        tls.Certificate
	fingerprint string
	upgrader    websocket.Upgrader

	mu    sync.Mutex
	rooms map[string]*FakeVKRoom
}

// FakeVKRoom is one conversation.
type FakeVKRoom struct {
	sfu *FakeVK
	id  string

	mu     sync.Mutex
	guests map[string]*fakeVKGuest // by participant id
	legs   []*fakeVKLeg            // every socket, in the order they came
	errs   []string
	closed bool
	serial int
	// rtx: the publish slot names an RTX payload type for VP8.
	rtx bool
}

// fakeVKGuest is one participant's credentials: what a provider would hand
// out for it.
type fakeVKGuest struct {
	id, token, role, endpoint string
}

// fakeVKSlot is one receive slot of a leg's offer.
type fakeVKSlot struct {
	mid  string
	ssrc uint32
	// from is the publisher forwarded here; src its SSRC as last seen,
	// offset what its sequence numbers are moved by, next the slot's next.
	from    string
	src     uint32
	started bool
	offset  uint16
	next    uint16
}

// fakeVKLeg is one signalling socket and the media behind it.
type fakeVKLeg struct {
	room  *FakeVKRoom
	guest *fakeVKGuest
	conn  *websocket.Conn
	wsMu  sync.Mutex

	// Under room.mu.
	commands    []string
	answers     int
	hangup      bool
	ended       bool
	up          bool
	upAt        time.Time
	perfAt      time.Time
	channels    map[string]int
	simulcast   int
	layouts     int
	keyAsks     int
	perf        int
	controlSeen map[int]bool
	lastLayout  []string
	layout      map[uint8]bool
	registry    map[string]uint8
	slots       []*fakeVKSlot
	packets     int
	rtx         int
	otherPT     int
	afterRR     int
	reports     int
	forwarded   int
	stalled     int
	pongs       int
	sources     map[uint32]bool
	pubSSRC     uint32
	pubSeq      uint16
	lost        int
	offer       string
	sessionID   string
	offers      int
	shapeID     int64
	audioSSRC   uint32

	// The media leg.
	agent      *ice.Agent
	ufrag, pwd string
	candidates []string
	ice        *ice.Conn
	dtlsIn     *packetio.Buffer
	dtls       *dtls.Conn
	assoc      *sctp.Association
	mediaMu    sync.Mutex
	in, out    *srtp.Context
	dcMu       sync.Mutex
	notify     *datachannel.DataChannel
	done       chan struct{}
	doneOnce   sync.Once
}

// FakeVKLeg is what the fake saw of one socket.
type FakeVKLeg struct {
	Participant string `json:"participant"`
	Role        string `json:"role"`
	// Commands are the signalling commands, in order.
	Commands []string `json:"commands"`
	// Answers is how many offers were answered; Hangup whether the socket
	// said goodbye; Ended whether it is gone; Up whether DTLS came up.
	Answers int  `json:"answers"`
	Hangup  bool `json:"hangup"`
	Ended   bool `json:"ended"`
	Up      bool `json:"up"`
	// Channels are the service channels by label, with their SCTP stream.
	Channels map[string]int `json:"channels"`
	// The producer commands: change-simulcast, layouts (KeyAsks of them
	// asked for a camera by its string key), perf reports; LastLayout is
	// what the last layout named.
	Simulcast  int      `json:"simulcast"`
	Layouts    int      `json:"layouts"`
	KeyAsks    int      `json:"key_asks"`
	Perf       int      `json:"perf"`
	LastLayout []string `json:"last_layout"`
	// Packets are the published VP8 packets, every one with its mid and
	// rid (one without trips the room); AfterReport those that came after
	// the leg was sent its first receiver report; Sources the SSRCs.
	Packets     int `json:"packets"`
	AfterReport int `json:"after_report"`
	Reports     int `json:"reports"`
	Sources     int `json:"sources"`
	RTX         int `json:"rtx"`
	OtherPT     int `json:"other_pt"`
	// Lost is how many sequence numbers of the published stream never
	// reached the fake (what the path from the client dropped).
	Lost int `json:"lost"`
	// Forwarded is what was sent to this leg, wrapped in RED; Stalled what
	// was withheld for want of a perf report.
	Forwarded int `json:"forwarded"`
	Stalled   int `json:"stalled"`
	Pongs     int `json:"pongs"`
}

// FakeVKState is a room as the fake saw it.
type FakeVKState struct {
	// Errors is everything a client did that the engine at the pin does
	// not: empty for a room the fake did not trip in.
	Errors []string    `json:"errors"`
	Legs   []FakeVKLeg `json:"legs"`
}

// NewFakeVK starts the fake.
func NewFakeVK() (*FakeVK, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("fake vk: certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("fake vk: certificate: %w", err)
	}
	sum, err := fingerprint.Fingerprint(leaf, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("fake vk: fingerprint: %w", err)
	}
	f := &FakeVK{
		cert: cert, fingerprint: strings.ToUpper(sum), rooms: make(map[string]*FakeVKRoom),
		upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serveWS))
	return f, nil
}

// Close ends every room and the listener.
func (f *FakeVK) Close() {
	f.mu.Lock()
	rooms := make([]*FakeVKRoom, 0, len(f.rooms))
	for _, r := range f.rooms {
		rooms = append(rooms, r)
	}
	f.mu.Unlock()
	for _, r := range rooms {
		r.Shutdown()
	}
	f.srv.Close()
}

// Open makes a room.
func (f *FakeVK) Open() *FakeVKRoom {
	r := &FakeVKRoom{sfu: f, id: fakeVKHex(16), guests: make(map[string]*fakeVKGuest), rtx: true}
	f.mu.Lock()
	f.rooms[r.id] = r
	f.mu.Unlock()
	return r
}

// OpenNoRTX makes a room whose offers name no RTX for VP8 in the publish
// slot. The engine stamps its mid and rid on every packet either way; a
// str0m client does so only by the vendored patch where the stream has no
// RTX (str0m stops both once a receiver report names the stream's SSRC, and
// with RTX it waits for a report on the RTX SSRC instead, which this fake
// never sends). This shape is the one that holds the patch.
func (f *FakeVK) OpenNoRTX() *FakeVKRoom {
	r := f.Open()
	r.mu.Lock()
	r.rtx = false
	r.mu.Unlock()
	return r
}

// Room is the room with that id, or nil.
func (f *FakeVK) Room(id string) *FakeVKRoom {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rooms[id]
}

// ID names the room to the fake's hooks.
func (r *FakeVKRoom) ID() string { return r.id }

// URL is the room without a guest: what a gate cell knows its room by.
func (r *FakeVKRoom) URL() string {
	return "ws" + strings.TrimPrefix(r.sfu.srv.URL, "http") + "/ws?conversationId=" + r.id
}

// Guest makes a participant and returns its signalling endpoint, as the
// provider's join would: the socket's URL with the guest's token and id.
// role is a word for the state ("server", "rust", "cli").
func (r *FakeVKRoom) Guest(role string) string {
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	id := strconv.FormatUint(100000000000+binary.BigEndian.Uint64(raw[:])%900000000000, 10)
	g := &fakeVKGuest{id: id, token: r.id + "-" + fakeVKHex(8), role: role}
	g.endpoint = r.URL() + "&token=" + g.token + "&userId=" + g.id
	r.mu.Lock()
	r.guests[g.id] = g
	r.mu.Unlock()
	return g.endpoint
}

// Secrets is what no log of a client may carry: the room, and every guest's
// token and participant id.
func (r *FakeVKRoom) Secrets() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{r.id}
	for _, g := range r.guests {
		out = append(out, g.token, g.id)
	}
	sort.Strings(out)
	return out
}

// State is the room as the fake saw it so far.
func (r *FakeVKRoom) State() FakeVKState {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := FakeVKState{Errors: append([]string{}, r.errs...), Legs: make([]FakeVKLeg, 0, len(r.legs))}
	for _, l := range r.legs {
		channels := make(map[string]int, len(l.channels))
		for k, v := range l.channels {
			channels[k] = v
		}
		st.Legs = append(st.Legs, FakeVKLeg{
			Participant: l.guest.id, Role: l.guest.role, Commands: append([]string{}, l.commands...),
			Answers: l.answers, Hangup: l.hangup, Ended: l.ended, Up: l.up, Channels: channels,
			Simulcast: l.simulcast, Layouts: l.layouts, KeyAsks: l.keyAsks, Perf: l.perf,
			LastLayout: append([]string{}, l.lastLayout...), Packets: l.packets, AfterReport: l.afterRR,
			Reports: l.reports, Sources: len(l.sources), RTX: l.rtx, OtherPT: l.otherPT,
			Lost: l.lost, Forwarded: l.forwarded, Stalled: l.stalled, Pongs: l.pongs,
		})
	}
	return st
}

// Drop closes every socket without a close frame and every media leg, the
// way a dead SFU ends them. The guests stay: a client may join again.
func (r *FakeVKRoom) Drop() {
	for _, l := range r.live() {
		l.close()
	}
}

// Reoffer sends every connected leg one more offer: the same session with a
// receive slot added, under a new session id. It returns how many it sent.
func (r *FakeVKRoom) Reoffer() int {
	sent := 0
	for _, l := range r.live() {
		r.mu.Lock()
		ok := l.up && l.answers > 0
		var note map[string]any
		if ok {
			l.slots = append(l.slots, &fakeVKSlot{mid: strconv.Itoa(5 + len(l.slots)), ssrc: fakeVKSSRC()})
			note = l.offerLocked()
		}
		r.mu.Unlock()
		if ok {
			l.write(note)
			sent++
		}
	}
	return sent
}

// Shutdown ends the room: every leg goes and no socket is taken any more.
func (r *FakeVKRoom) Shutdown() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.Drop()
}

func (r *FakeVKRoom) live() []*fakeVKLeg {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*fakeVKLeg
	for _, l := range r.legs {
		if !l.ended {
			out = append(out, l)
		}
	}
	return out
}

// trip records something the engine at the pin does not do.
func (r *FakeVKRoom) trip(l *fakeVKLeg, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tripLocked(l, format, args...)
}

func (r *FakeVKRoom) tripLocked(l *fakeVKLeg, format string, args ...any) {
	who := "?"
	if l != nil {
		who = l.guest.role
	}
	msg := who + ": " + fmt.Sprintf(format, args...)
	for _, seen := range r.errs {
		if seen == msg {
			return
		}
	}
	if len(r.errs) < fakeVKErrors {
		r.errs = append(r.errs, msg)
	}
}

func fakeVKHex(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

func fakeVKSSRC() uint32 {
	var raw [4]byte
	_, _ = rand.Read(raw[:])
	return 1000000000 + binary.BigEndian.Uint32(raw[:])%1000000000
}

// serveWS takes a guest's socket.
func (f *FakeVK) serveWS(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	room := f.Room(q.Get("conversationId"))
	if room == nil || req.URL.Path != "/ws" {
		http.NotFound(w, req)
		return
	}
	room.mu.Lock()
	guest := room.guests[q.Get("userId")]
	refused := room.closed || guest == nil || guest.token != q.Get("token")
	room.mu.Unlock()
	if refused {
		http.Error(w, "no such guest", http.StatusForbidden)
		return
	}
	conn, err := f.upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(1 << 20)
	leg := &fakeVKLeg{
		room: room, guest: guest, conn: conn, channels: map[string]int{}, layout: map[uint8]bool{},
		registry: map[string]uint8{}, sources: map[uint32]bool{}, done: make(chan struct{}),
		controlSeen: map[int]bool{},
		shapeID:     -1, audioSSRC: fakeVKSSRC(),
	}
	for range fakeVKSlots {
		leg.slots = append(leg.slots, &fakeVKSlot{mid: strconv.Itoa(5 + len(leg.slots)), ssrc: fakeVKSSRC()})
	}

	// The socket as the engine dials it.
	if want, wantErr := signalingURL(guest.endpoint); wantErr != nil {
		room.trip(leg, "the endpoint: %v", wantErr)
	} else if _, query, _ := strings.Cut(want, "?"); query != req.URL.RawQuery {
		room.trip(leg, "the socket's query is not the engine's: %d bytes of %d values, the engine's has %d bytes",
			len(req.URL.RawQuery), len(q), len(query))
	}
	for name, want := range map[string]string{
		"Origin": fakeVKOrigin, "Referer": fakeVKReferer, "User-Agent": fakeVKGoUserAgent,
	} {
		if got := req.Header.Get(name); got != want {
			room.trip(leg, "the socket's %s is %q, the engine's is %q", name, got, want)
		}
	}

	// A guest has one socket: an older one of the same guest goes.
	room.mu.Lock()
	var old, others []*fakeVKLeg
	participants := []any{map[string]any{"id": fakeVKNumber(guest.id), "state": "ACCEPTED"}}
	for _, l := range room.legs {
		switch {
		case l.ended:
		case l.guest == guest:
			old = append(old, l)
		default:
			others = append(others, l)
			participants = append(participants, map[string]any{"id": fakeVKNumber(l.guest.id), "state": "ACCEPTED"})
		}
	}
	room.legs = append(room.legs, leg)
	room.mu.Unlock()
	for _, l := range old {
		l.close()
	}
	leg.write(map[string]any{
		"type": "notification", "notification": noteConnection,
		fieldPeerID:    map[string]any{"id": fakeVKNumber(guest.id)},
		"conversation": map[string]any{"topology": topologyServer, "participants": participants},
	})
	for _, l := range others {
		l.write(map[string]any{
			"type": "notification", "notification": "participant-joined", "participantId": fakeVKNumber(guest.id),
		})
	}
	go leg.pings()
	leg.serve()
}

// fakeVKNumber is a participant id as the connector writes it: a number.
func fakeVKNumber(id string) json.Number { return json.Number(id) }

func (l *fakeVKLeg) write(frame any) {
	l.wsMu.Lock()
	defer l.wsMu.Unlock()
	_ = l.conn.WriteJSON(frame)
}

func (l *fakeVKLeg) pings() {
	tick := time.NewTicker(fakeVKPing)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-tick.C:
			l.wsMu.Lock()
			_ = l.conn.WriteMessage(websocket.TextMessage, []byte("ping"))
			l.wsMu.Unlock()
		}
	}
}

// serve reads the socket until it ends.
func (l *fakeVKLeg) serve() {
	for {
		kind, data, err := l.conn.ReadMessage()
		if err != nil {
			break
		}
		if kind != websocket.TextMessage {
			l.room.trip(l, "a frame that is not text")
			continue
		}
		if string(data) == "pong" {
			l.room.mu.Lock()
			l.pongs++
			l.room.mu.Unlock()
			continue
		}
		l.onFrame(data)
	}
	l.close()
}

// close ends the leg once: the socket, the media, and the others are told.
func (l *fakeVKLeg) close() {
	l.doneOnce.Do(func() {
		close(l.done)
		_ = l.conn.UnderlyingConn().Close()
		l.mediaMu.Lock()
		agent, dconn, assoc, buf := l.agent, l.dtls, l.assoc, l.dtlsIn
		l.mediaMu.Unlock()
		if assoc != nil {
			assoc.Abort("the fake's leg ended")
		}
		if buf != nil {
			_ = buf.Close()
		}
		if dconn != nil {
			go func() { _ = dconn.Close() }()
		}
		if agent != nil {
			_ = agent.Close()
		}
		r := l.room
		r.mu.Lock()
		l.ended = true
		var others []*fakeVKLeg
		for _, o := range r.legs {
			if !o.ended && o.guest != l.guest {
				others = append(others, o)
			}
			// What was forwarded from this guest starts again with its next
			// stream.
			for _, s := range o.slots {
				if s.from == l.guest.id {
					s.started = false
				}
			}
		}
		r.mu.Unlock()
		for _, o := range others {
			o.write(map[string]any{
				"type": "notification", "notification": "hungup", "participantId": fakeVKNumber(l.guest.id),
			})
		}
	})
}

// fakeVKCommands is the engine's order of a join (vkcalls.go, Connect).
var fakeVKCommands = []string{"allocate-consumer", "update-media-modifiers", "change-media-settings", "accept-producer"}

// fakeVKWant is the frame the engine writes for a command of a join, or nil
// for one that depends on the frame itself (accept-producer, hangup).
func fakeVKWant(name string, sequence int64) ([]byte, error) {
	switch name {
	case "allocate-consumer":
		return orderedCommandFrame(name, sequence, map[string]any{"capabilities": referenceCapabilities()})
	case "update-media-modifiers":
		return orderedCommandFrame(name, sequence, map[string]any{
			"mediaModifiers": map[string]any{"denoise": true, "denoiseAnn": true},
		})
	case "change-media-settings":
		return orderedCommandFrame(name, sequence, map[string]any{
			"mediaSettings": map[string]any{"isAudioEnabled": false, "isVideoEnabled": false,
				"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
				"isAudioSharingEnabled": false, "isAnimojiEnabled": true},
		})
	}
	return nil, nil
}

// onFrame holds one signalling frame to the engine's.
func (l *fakeVKLeg) onFrame(data []byte) {
	var head struct {
		Command     string `json:"command"`
		Sequence    int64  `json:"sequence"`
		Description string `json:"description"`
		SessionID   string `json:"sessionId"` //nolint:tagliatelle // the connector's wire
	}
	if err := json.Unmarshal(data, &head); err != nil || head.Command == "" {
		l.room.trip(l, "a frame of %d bytes that is no command", len(data))
		return
	}
	r := l.room
	r.mu.Lock()
	position := len(l.commands)
	l.commands = append(l.commands, head.Command)
	offer, session, hungup := l.offer, l.sessionID, l.hangup
	if head.Sequence != int64(position)+1 {
		r.tripLocked(l, "%s under sequence %d, the engine's is %d", head.Command, head.Sequence, position+1)
	}
	if hungup {
		r.tripLocked(l, "%s after the hangup", head.Command)
	}
	r.mu.Unlock()

	if head.Command == "hangup" {
		want, _ := json.Marshal(map[string]any{"command": "hangup", fieldSequence: head.Sequence, "reason": reasonHungup})
		if !bytes.Equal(want, data) {
			r.trip(l, "the hangup is not the engine's frame")
		}
		r.mu.Lock()
		l.hangup = true
		r.mu.Unlock()
		return
	}
	switch {
	case position < len(fakeVKCommands) && head.Command != fakeVKCommands[position]:
		r.trip(l, "command %d is %s, the engine's is %s", position+1, head.Command, fakeVKCommands[position])
	case position >= len(fakeVKCommands) && head.Command != "accept-producer":
		r.trip(l, "%s after the join", head.Command)
	}
	if want, err := fakeVKWant(head.Command, head.Sequence); err != nil {
		r.trip(l, "%s: %v", head.Command, err)
	} else if want != nil && !bytes.Equal(want, data) {
		r.trip(l, "%s is not the engine's frame (%d bytes, the engine's %d)", head.Command, len(data), len(want))
	}

	first := false
	if head.Command == "accept-producer" {
		if offer == "" {
			r.trip(l, "accept-producer before any offer")
			return
		}
		want, err := orderedCommandFrame(head.Command, head.Sequence, acceptPayload(offer, head.Description, session))
		if err != nil || !bytes.Equal(want, data) {
			r.trip(l, "accept-producer is not the engine's frame for this offer (%d bytes, the engine's %d)",
				len(data), len(want))
		}
		r.mu.Lock()
		l.answers++
		answers := l.answers
		shapeID := l.shapeID
		r.mu.Unlock()
		id, err := fakeVKCheckAnswer(offer, head.Description, answers, shapeID)
		if err != nil {
			r.trip(l, "the answer to offer %d: %v", answers, err)
		}
		r.mu.Lock()
		l.shapeID = id
		r.mu.Unlock()
		first = answers == 1
	}
	l.write(map[string]any{"type": "response", "response": head.Command, fieldSequence: head.Sequence})

	switch {
	case head.Command == "allocate-consumer" && position == 0:
		if err := l.gather(); err != nil {
			r.trip(l, "the fake's own ICE: %v", err)
			return
		}
		r.mu.Lock()
		note := l.offerLocked()
		r.mu.Unlock()
		l.write(note)
	case first:
		normal := strings.ReplaceAll(head.Description, "\r\n", "\n")
		ufrag, pwd := iceUfragLine.FindStringSubmatch(normal), icePwdLine.FindStringSubmatch(normal)
		sum := fingerprintLin.FindStringSubmatch(normal)
		if ufrag == nil || pwd == nil || sum == nil {
			r.trip(l, "the answer carries no ICE credentials or no fingerprint")
			return
		}
		go l.media(ufrag[1], pwd[1], sum[1])
	}
}

// fakeVKCheckAnswer holds a shaped answer to ShapeAnswer: the engine's
// shaper, given this offer and what the answer itself says of its sender
// (credentials, fingerprint, msid, the o= line), writes these very bytes. n
// is which answer of the leg this is (the o= version is twice that), id the
// leg's o= session id so far (-1 before the first). It returns the id.
func fakeVKCheckAnswer(offer, shaped string, n int, id int64) (int64, error) {
	normal := strings.ReplaceAll(shaped, "\r\n", "\n")
	ufrag, pwd := iceUfragLine.FindStringSubmatch(normal), icePwdLine.FindStringSubmatch(normal)
	sum, msid := fingerprintLin.FindStringSubmatch(normal), msidLine.FindStringSubmatch(normal)
	if ufrag == nil || pwd == nil || sum == nil {
		return id, errors.New("no ICE credentials or no fingerprint")
	}
	if msid == nil {
		return id, errors.New("no a=msid in the publish slot")
	}
	var origin []string
	for _, line := range strings.Split(normal, "\n") {
		if strings.HasPrefix(line, "o=") {
			origin = strings.Fields(line)
			break
		}
	}
	if len(origin) != 6 {
		return id, errors.New("no o= line of six fields")
	}
	session, err := strconv.ParseInt(origin[1], 10, 64)
	if err != nil {
		return id, errors.New("the o= session id is no number")
	}
	version, err := strconv.Atoi(origin[2])
	if err != nil {
		return id, errors.New("the o= version is no number")
	}
	if version != 2*n {
		return session, fmt.Errorf("o= version %d, the engine's answer %d has %d", version, n, 2*n)
	}
	if id >= 0 && session != id {
		return session, errors.New("the o= session id changed between two answers of one connection")
	}
	native := strings.Join([]string{
		"v=0", "m=video 9 UDP/TLS/RTP/SAVPF 100", "a=ice-ufrag:" + ufrag[1], "a=ice-pwd:" + pwd[1], sum[1],
		"a=mid:" + fakeVKPublishMid, "a=sendonly", msid[1], "a=ssrc:1 cname:fake",
	}, "\n")
	want, err := ShapeAnswer(offer, native, &ShapeState{SessionID: session, Version: version - 2, AudioSSRC: map[string]uint32{}})
	if err != nil {
		return session, fmt.Errorf("the engine's shaper on this offer: %w", err)
	}
	if want == shaped {
		return session, nil
	}
	got, wanted := strings.Split(shaped, "\r\n"), strings.Split(want, "\r\n")
	for i := range wanted {
		if i >= len(got) {
			return session, fmt.Errorf("%d lines, the engine's shaper writes %d", len(got), len(wanted))
		}
		if got[i] != wanted[i] {
			return session, fmt.Errorf("line %d is %q, the engine's shaper writes %q",
				i+1, fakeVKMask(got[i]), fakeVKMask(wanted[i]))
		}
	}
	return session, fmt.Errorf("%d lines, the engine's shaper writes %d", len(got), len(wanted))
}

// fakeVKMask keeps a credential out of an error.
func fakeVKMask(line string) string {
	for _, head := range []string{"a=ice-pwd:", "a=ice-ufrag:"} {
		if strings.HasPrefix(line, head) {
			return head + "<" + strconv.Itoa(len(line)-len(head)) + " bytes>"
		}
	}
	return line
}

// gather makes the leg's ICE agent and its host candidates.
func (l *fakeVKLeg) gather() error {
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Lite:             true,
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost},
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
		LoggerFactory:    logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var found []string
	gathered := make(chan struct{})
	var once sync.Once
	if err := agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			once.Do(func() { close(gathered) })
			return
		}
		mu.Lock()
		found = append(found, c.Marshal())
		mu.Unlock()
	}); err != nil {
		_ = agent.Close()
		return err
	}
	if err := agent.GatherCandidates(); err != nil {
		_ = agent.Close()
		return err
	}
	select {
	case <-gathered:
	case <-time.After(10 * time.Second):
		_ = agent.Close()
		return errors.New("no end of gathering within 10 s")
	}
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		_ = agent.Close()
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if len(found) == 0 {
		_ = agent.Close()
		return errors.New("no host candidate: the fake needs a network interface")
	}
	l.mediaMu.Lock()
	l.agent = agent
	l.mediaMu.Unlock()
	l.room.mu.Lock()
	l.ufrag, l.pwd, l.candidates = ufrag, pwd, found
	l.room.mu.Unlock()
	select {
	case <-l.done: // the leg ended while it gathered
		_ = agent.Close()
	default:
	}
	return nil
}

// offerLocked writes the leg's next offer and returns its notification; the
// caller holds room.mu.
func (l *fakeVKLeg) offerLocked() map[string]any {
	l.offers++
	l.room.serial++
	l.sessionID = "fake-" + strconv.Itoa(l.room.serial) + "-" + fakeVKHex(4)
	l.offer = fakeVKOffer(l.offers, l.candidates, l.ufrag, l.pwd, l.room.sfu.fingerprint, l.audioSSRC, l.slots,
		l.room.rtx)
	return map[string]any{
		"type": "notification", "notification": "producer-updated",
		"sessionId": l.sessionID, fieldDescription: l.offer,
	}
}

// fakeVKOffer is liveShapeOffer (negotiate_test.go) with a leg's own
// values: the audio mix, the application section, the publish slot (102 red,
// 104 ulpfec, the layer l) and the receive slots (102 VP9, 104 red).
//
// Without rtx the publish slot names VP8 alone, with no payload type to
// resend it at (OpenNoRTX); the receive slots are the same.
func fakeVKOffer(version int, candidates []string, ufrag, pwd, sum string, audio uint32, slots []*fakeVKSlot,
	rtx bool,
) string {
	var b strings.Builder
	w := func(lines ...string) {
		for _, line := range lines {
			b.WriteString(line)
			b.WriteString("\r\n")
		}
	}
	mids := []string{"0", "1", fakeVKPublishMid}
	for _, s := range slots {
		mids = append(mids, s.mid)
	}
	w("v=0", fmt.Sprintf("o=- 1790552099500 %d IN IP4 127.0.0.1", 1790552100510+version), "s=-", "t=0 0",
		"a=group:BUNDLE "+strings.Join(mids, " "), "a=ice-lite", "a=msid-semantic: WMS *")
	w("m=audio 9 UDP/TLS/RTP/SAVPF 111", zeroAddrLn)
	for _, c := range candidates {
		w("a=candidate:" + c)
	}
	w("a=ice-ufrag:"+ufrag, "a=ice-pwd:"+pwd, "a=fingerprint:sha-256 "+sum, "a=setup:actpass", "a=mid:0",
		"a=sendonly", "a=rtcp-mux", "a=rtpmap:111 opus/48000/2", fmt.Sprintf("a=ssrc:%d cname:audio-mix", audio))
	w("m=application 9 UDP/DTLS/SCTP webrtc-datachannel", zeroAddrLn, "a=mid:1", "a=sendrecv")
	ext := []string{
		"a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
		fmt.Sprintf("a=extmap:%d http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time", fakeVKExtAbsSendTime),
	}
	vp8 := []string{
		"a=rtpmap:100 VP8/90000", "a=rtcp-fb:100 nack", "a=rtcp-fb:100 nack pli",
		"a=rtpmap:101 rtx/90000", "a=fmtp:101 apt=100",
	}
	h264 := []string{
		"a=rtpmap:98 H264/90000",
		"a=fmtp:98 packetization-mode=1;level-asymmetry-allowed=1;profile-level-id=42e034",
		"a=rtpmap:99 rtx/90000", "a=fmtp:99 apt=98",
	}
	publishLine, publishVP8 := "m=video 9 UDP/TLS/RTP/SAVPF 100 101 98 99 102 103 104", vp8
	if !rtx {
		publishLine, publishVP8 = "m=video 9 UDP/TLS/RTP/SAVPF 100 98 99 102 103 104", vp8[:3]
	}
	w(publishLine, zeroAddrLn, "a=mid:"+fakeVKPublishMid)
	w(ext...)
	w(fmt.Sprintf("a=extmap:%d urn:ietf:params:rtp-hdrext:sdes:mid", fakeVKExtMid),
		fmt.Sprintf("a=extmap:%d urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", fakeVKExtRid),
		"a=recvonly", "a=rtcp-mux")
	w(publishVP8...)
	w(h264...)
	w("a=rtpmap:102 red/90000", "a=rtpmap:103 rtx/90000", "a=fmtp:103 apt=102", "a=rtpmap:104 ulpfec/90000",
		"a=rid:l recv", "a=simulcast:recv l")
	for _, s := range slots {
		w("m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101 98 99 104 105 106", zeroAddrLn, "a=mid:"+s.mid)
		w(ext...)
		w("a=sendonly", "a=rtcp-mux", "a=rtpmap:102 VP9/90000", "a=rtpmap:103 rtx/90000", "a=fmtp:103 apt=102")
		w(vp8...)
		w(h264...)
		w("a=rtpmap:104 red/90000", "a=rtpmap:105 rtx/90000", "a=fmtp:105 apt=104", "a=rtpmap:106 ulpfec/90000",
			fmt.Sprintf("a=ssrc:%d cname:pat-%s", s.ssrc, s.mid),
			fmt.Sprintf("a=ssrc:%d msid:pat-%s video-pat-%s", s.ssrc, s.mid, s.mid))
	}
	return b.String()
}

// fakeVKEnd is the DTLS side of a leg's ICE connection: what the reader
// sorted out as DTLS comes in, everything written goes out.
type fakeVKEnd struct {
	in   *packetio.Buffer
	conn *ice.Conn
}

func (e *fakeVKEnd) Read(p []byte) (int, error)        { return e.in.Read(p) }
func (e *fakeVKEnd) Write(p []byte) (int, error)       { return e.conn.Write(p) }
func (e *fakeVKEnd) Close() error                      { return e.in.Close() }
func (e *fakeVKEnd) LocalAddr() net.Addr               { return e.conn.LocalAddr() }
func (e *fakeVKEnd) RemoteAddr() net.Addr              { return e.conn.RemoteAddr() }
func (e *fakeVKEnd) SetDeadline(t time.Time) error     { return e.in.SetReadDeadline(t) }
func (e *fakeVKEnd) SetReadDeadline(t time.Time) error { return e.in.SetReadDeadline(t) }
func (e *fakeVKEnd) SetWriteDeadline(time.Time) error  { return nil }

func (l *fakeVKLeg) gone() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// media brings a leg's transport up for the client the answer describes:
// ICE as the lite, controlled side; DTLS as the server (the answer is
// active), the client's certificate held to the answer's fingerprint; SRTP
// from the handshake; SCTP and the client's channels.
func (l *fakeVKLeg) media(ufrag, pwd, sum string) {
	r := l.room
	fail := func(format string, args ...any) {
		if !l.gone() {
			r.trip(l, format, args...)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), fakeVKMediaWait)
	defer cancel()
	go func() {
		select {
		case <-l.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	l.mediaMu.Lock()
	agent := l.agent
	l.mediaMu.Unlock()
	if agent == nil {
		fail("an answer before the fake had an agent")
		return
	}
	conn, err := agent.Accept(ctx, ufrag, pwd)
	if err != nil {
		fail("ICE did not connect: %v", err)
		return
	}
	end := &fakeVKEnd{in: packetio.NewBuffer(), conn: conn}
	l.mediaMu.Lock()
	l.ice, l.dtlsIn = conn, end.in
	l.mediaMu.Unlock()
	go l.read(conn, end.in)
	go l.reportLoop()

	dconn, err := dtls.Server(dtlsnet.PacketConnFromConn(end), conn.RemoteAddr(), &dtls.Config{
		Certificates: []tls.Certificate{r.sfu.cert},
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
		ClientAuth:           dtls.RequireAnyClientCert,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		InsecureSkipVerify:   true,
		LoggerFactory:        logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		fail("DTLS: %v", err)
		return
	}
	l.mediaMu.Lock()
	l.dtls = dconn
	l.mediaMu.Unlock()
	if l.gone() {
		_ = dconn.Close()
		return
	}
	if err := dconn.HandshakeContext(ctx); err != nil {
		fail("the DTLS handshake (the client is the one that starts it): %v", err)
		return
	}
	state, ok := dconn.ConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		fail("DTLS came up with no client certificate")
		return
	}
	leaf, err := x509.ParseCertificate(state.PeerCertificates[0])
	if err != nil {
		fail("the client's certificate: %v", err)
		return
	}
	algo, value, _ := strings.Cut(strings.TrimPrefix(sum, "a=fingerprint:"), " ")
	hash, err := fingerprint.HashFromString(algo)
	if err != nil {
		fail("the answer's fingerprint: %v", err)
		return
	}
	if got, sumErr := fingerprint.Fingerprint(leaf, hash); sumErr != nil || !strings.EqualFold(got, strings.TrimSpace(value)) {
		fail("the client's certificate is not the one the answer's fingerprint names")
		return
	}
	chosen, ok := dconn.SelectedSRTPProtectionProfile()
	if !ok {
		fail("DTLS chose no SRTP profile")
		return
	}
	profile := srtp.ProtectionProfileAes128CmHmacSha1_80
	if chosen == dtls.SRTP_AEAD_AES_128_GCM {
		profile = srtp.ProtectionProfileAeadAes128Gcm
	}
	keys := &srtp.Config{Profile: profile}
	if err := keys.ExtractSessionKeysFromDTLS(&state, false); err != nil {
		fail("SRTP keys: %v", err)
		return
	}
	in, err := srtp.CreateContext(keys.Keys.RemoteMasterKey, keys.Keys.RemoteMasterSalt, profile)
	if err != nil {
		fail("SRTP: %v", err)
		return
	}
	out, err := srtp.CreateContext(keys.Keys.LocalMasterKey, keys.Keys.LocalMasterSalt, profile)
	if err != nil {
		fail("SRTP: %v", err)
		return
	}
	l.mediaMu.Lock()
	l.in, l.out = in, out
	l.mediaMu.Unlock()
	r.mu.Lock()
	l.up, l.upAt = true, time.Now()
	r.mu.Unlock()

	assoc, err := sctp.Client(sctp.Config{NetConn: dconn, LoggerFactory: logging.NewDefaultLoggerFactory()})
	if err != nil {
		fail("SCTP: %v", err)
		return
	}
	l.mediaMu.Lock()
	l.assoc = assoc
	l.mediaMu.Unlock()
	if l.gone() {
		assoc.Abort("the fake's leg ended")
		return
	}
	for {
		dc, err := datachannel.Accept(assoc, &datachannel.Config{LoggerFactory: logging.NewDefaultLoggerFactory()})
		if err != nil {
			return
		}
		go l.channel(dc)
	}
}

// read sorts what arrives on the leg's ICE connection: DTLS to the
// handshake, RTP to the publish slot, RTCP nowhere.
func (l *fakeVKLeg) read(conn *ice.Conn, dtlsIn *packetio.Buffer) {
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		switch {
		case n < 2:
		case buf[0] >= 20 && buf[0] <= 63:
			_, _ = dtlsIn.Write(buf[:n])
		case buf[0] >= 128 && buf[0] <= 191 && (buf[1] < 192 || buf[1] > 223):
			l.onRTP(buf[:n])
		}
	}
}

// onRTP takes one packet the client published.
func (l *fakeVKLeg) onRTP(raw []byte) {
	l.mediaMu.Lock()
	in := l.in
	l.mediaMu.Unlock()
	if in == nil {
		return
	}
	var header rtp.Header
	plain, err := in.DecryptRTP(nil, raw, &header)
	if err != nil {
		return
	}
	n, err := (&rtp.Header{}).Unmarshal(plain)
	if err != nil || n > len(plain) {
		return
	}
	payload := plain[n:]
	if header.Padding && len(payload) > 0 {
		pad := int(payload[len(payload)-1])
		if pad == 0 || pad > len(payload) {
			return
		}
		payload = payload[:len(payload)-pad]
	}
	l.room.published(l, &header, payload)
}

// fakeVKPacketFault says what a published VP8 packet lacks of what the
// engine's stamper writes on every one (stamp.go): the publish slot's mid
// and the rid l, and no abs-send-time.
func fakeVKPacketFault(header *rtp.Header) string {
	switch {
	case string(header.GetExtension(fakeVKExtMid)) != fakeVKPublishMid:
		return fmt.Sprintf("a published packet whose mid is %q, the publish slot's is %q",
			header.GetExtension(fakeVKExtMid), fakeVKPublishMid)
	case string(header.GetExtension(fakeVKExtRid)) != "l":
		return fmt.Sprintf("a published packet whose rid is %q, the layer is l", header.GetExtension(fakeVKExtRid))
	case header.GetExtension(fakeVKExtAbsSendTime) != nil:
		return "a published packet with abs-send-time, which the engine never writes"
	}
	return ""
}

type fakeVKForward struct {
	to     *fakeVKLeg
	header rtp.Header
}

// published counts a packet of l's and forwards it to whoever asked for it.
func (r *FakeVKRoom) published(l *fakeVKLeg, header *rtp.Header, payload []byte) {
	var targets []fakeVKForward
	now := time.Now()
	r.mu.Lock()
	switch header.PayloadType {
	case fakeVKVP8:
	case fakeVKRTX:
		l.rtx++
		r.mu.Unlock()
		return
	default:
		l.otherPT++
		r.tripLocked(l, "a published packet at payload type %d, the publish slot's VP8 is %d",
			header.PayloadType, fakeVKVP8)
		r.mu.Unlock()
		return
	}
	l.packets++
	if l.reports > 0 {
		l.afterRR++
	}
	if l.pubSSRC == header.SSRC && l.sources[header.SSRC] {
		if ahead := int16(header.SequenceNumber - l.pubSeq); ahead > 0 { //nolint:gosec // the distance, wrapped
			l.lost += int(ahead) - 1
			l.pubSeq = header.SequenceNumber
		}
	} else {
		l.pubSSRC, l.pubSeq = header.SSRC, header.SequenceNumber
	}
	l.sources[header.SSRC] = true
	if fault := fakeVKPacketFault(header); fault != "" {
		if l.reports > 0 {
			fault += " (after a receiver report)"
		}
		r.tripLocked(l, "%s", fault)
	}
	if l.simulcast > 0 {
		key := cameraKey(l.guest.id)
		for _, c := range r.legs {
			if c.ended || !c.up || c.guest == l.guest {
				continue
			}
			id, named := c.registry[key]
			if !named || !c.layout[id] {
				continue
			}
			alive := c.upAt
			if c.perfAt.After(alive) {
				alive = c.perfAt
			}
			if now.Sub(alive) > fakeVKStall {
				c.stalled++
				continue
			}
			slot := c.slotLocked(l.guest.id)
			if slot == nil {
				continue
			}
			if !slot.started || slot.src != header.SSRC {
				slot.started, slot.src = true, header.SSRC
				slot.offset = slot.next - header.SequenceNumber
			}
			seq := header.SequenceNumber + slot.offset
			if int16(seq-slot.next) >= 0 {
				slot.next = seq + 1
			}
			c.forwarded++
			targets = append(targets, fakeVKForward{to: c, header: rtp.Header{
				Version: 2, Marker: header.Marker, PayloadType: fakeVKRed, SequenceNumber: seq,
				Timestamp: header.Timestamp, SSRC: slot.ssrc,
			}})
		}
	}
	r.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	// RFC 2198 with no redundancy: one header byte, the primary's payload
	// type, then the primary.
	red := append([]byte{fakeVKVP8}, payload...)
	for _, t := range targets {
		raw, err := (&rtp.Packet{Header: t.header, Payload: red}).Marshal()
		if err != nil {
			continue
		}
		t.to.send(func(out *srtp.Context) ([]byte, error) { return out.EncryptRTP(nil, raw, nil) })
	}
}

// slotLocked is the receive slot a publisher is forwarded in, or nil when
// the leg's offer has none left; the caller holds room.mu.
func (l *fakeVKLeg) slotLocked(publisher string) *fakeVKSlot {
	for _, s := range l.slots {
		if s.from == publisher {
			return s
		}
	}
	for _, s := range l.slots {
		if s.from == "" {
			s.from = publisher
			return s
		}
	}
	return nil
}

// send protects and writes one packet to the leg.
func (l *fakeVKLeg) send(protect func(*srtp.Context) ([]byte, error)) {
	l.mediaMu.Lock()
	defer l.mediaMu.Unlock()
	if l.out == nil || l.ice == nil {
		return
	}
	if raw, err := protect(l.out); err == nil {
		_, _ = l.ice.Write(raw)
	}
}

// reportLoop sends the leg a receiver report of what it publishes, every
// second: the engine's packets carry their mid and rid after it too.
func (l *fakeVKLeg) reportLoop() {
	tick := time.NewTicker(fakeVKReport)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-tick.C:
		}
		l.room.mu.Lock()
		ssrc, seq := l.pubSSRC, l.pubSeq
		l.room.mu.Unlock()
		if ssrc == 0 {
			continue
		}
		raw, err := (&rtcp.ReceiverReport{SSRC: 1, Reports: []rtcp.ReceptionReport{
			{SSRC: ssrc, LastSequenceNumber: uint32(seq)},
		}}).Marshal()
		if err != nil {
			continue
		}
		l.send(func(out *srtp.Context) ([]byte, error) { return out.EncryptRTCP(nil, raw, nil) })
		l.room.mu.Lock()
		l.reports++
		l.room.mu.Unlock()
	}
}

// channel serves one data channel the client opened.
func (l *fakeVKLeg) channel(dc *datachannel.DataChannel) {
	r := l.room
	label, stream := dc.Config.Label, int(dc.StreamIdentifier())
	want, known := map[string]int{"producerNotification": 0, "producerCommand": 2}[label]
	var first []byte
	r.mu.Lock()
	l.channels[label] = stream
	switch {
	case !known:
		r.tripLocked(l, "a data channel %q, which the engine does not open", label)
	case stream != want:
		r.tripLocked(l, "%s on SCTP stream %d, the engine's is %d", label, stream, want)
	}
	if label == "producerNotification" {
		// The cameras in the room now are named unasked.
		entries := map[string]uint8{}
		for _, o := range r.legs {
			if !o.ended && o.guest != l.guest {
				entries[cameraKey(o.guest.id)] = l.compactLocked(cameraKey(o.guest.id))
			}
		}
		if len(entries) > 0 {
			first = fakeVKRegistry(entries)
		}
	}
	r.mu.Unlock()
	if label == "producerNotification" {
		l.dcMu.Lock()
		l.notify = dc
		l.dcMu.Unlock()
		l.registryFrame(first)
	}
	buf := make([]byte, 64<<10)
	for {
		n, _, err := dc.ReadDataChannel(buf)
		if err != nil {
			return
		}
		if label != "producerCommand" {
			r.trip(l, "%d bytes on %s, where the engine writes nothing", n, label)
			continue
		}
		l.onControl(append([]byte(nil), buf[:n]...))
	}
}

// compactLocked is the compact id this consumer knows a stream by, given
// out on first use; the caller holds room.mu.
func (l *fakeVKLeg) compactLocked(key string) uint8 {
	if id, ok := l.registry[key]; ok {
		return id
	}
	id := uint8(len(l.registry)) //nolint:gosec // a handful of streams
	l.registry[key] = id
	return id
}

// fakeVKRegistry is a kind-1 producerNotification frame (ParseRegistry).
func fakeVKRegistry(entries map[string]uint8) []byte {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []byte{registryKind, 0x80 | byte(len(keys))} //nolint:gosec // under 16 entries
	for _, key := range keys {
		out = append(out, 0xA0|byte(len(key))) //nolint:gosec // a camera key is 21 bytes
		out = append(out, key...)
		out = append(out, entries[key])
	}
	return out
}

func (l *fakeVKLeg) registryFrame(frame []byte) {
	if frame == nil {
		return
	}
	l.dcMu.Lock()
	defer l.dcMu.Unlock()
	if l.notify != nil {
		_, _ = l.notify.WriteDataChannel(frame, false)
	}
}

// fakeVKInt reads one integer as appendMPInt writes it.
func fakeVKInt(b []byte, pos int) (int, int, error) {
	switch {
	case pos >= len(b):
	case b[pos] < 0x80:
		return int(b[pos]), pos + 1, nil
	case b[pos] == 0xD1 && pos+2 < len(b):
		return int(int16(binary.BigEndian.Uint16(b[pos+1:]))), pos + 3, nil //nolint:gosec // two's complement
	case b[pos] == 0xD2 && pos+4 < len(b):
		return int(int32(binary.BigEndian.Uint32(b[pos+1:]))), pos + 5, nil //nolint:gosec // two's complement
	}
	return 0, 0, errFakeVKShape
}

// fakeVKLayout reads the entries of an update-display-layout frame from its
// fourth element on (EncodeLayout).
func fakeVKLayout(b []byte, pos int) (entries []LayoutEntry, err error) {
	defer func() {
		if recover() != nil {
			entries, err = nil, errFakeVKShape
		}
	}()
	if b[pos] != 0xC0 {
		return nil, errFakeVKShape
	}
	pos++
	count := 0
	switch {
	case b[pos]&0xF0 == 0x90:
		count, pos = int(b[pos]&0x0F), pos+1
	case b[pos] == 0xDC:
		count, pos = int(binary.BigEndian.Uint16(b[pos+1:])), pos+3
	default:
		return nil, errFakeVKShape
	}
	for range count {
		if b[pos] != 0xC4 {
			return nil, errFakeVKShape
		}
		blob := b[pos+2 : pos+2+int(b[pos+1])]
		pos += 2 + len(blob)
		var e LayoutEntry
		p := 0
		switch {
		case blob[0] < 0x80:
			e.Compact, e.ByCompact, p = blob[0], true, 1
		case blob[0]&0xE0 == 0xA0:
			p = 1 + int(blob[0]&0x1F)
			e.Key = string(blob[1:p])
		default:
			return nil, errFakeVKShape
		}
		if blob[p] != 0x00 {
			return nil, errFakeVKShape
		}
		p++
		if e.Priority, p, err = fakeVKInt(blob, p); err != nil {
			return nil, err
		}
		if blob[p] == 0xC0 && blob[p+1] == 0xC0 {
			p += 2
		} else {
			if e.Width, p, err = fakeVKInt(blob, p); err != nil {
				return nil, err
			}
			if e.Height, p, err = fakeVKInt(blob, p); err != nil {
				return nil, err
			}
		}
		if blob[p] != 0x00 || p+1 != len(blob) {
			return nil, errFakeVKShape
		}
		entries = append(entries, e)
	}
	if b[pos] != 0xC0 || pos+1 != len(b) {
		return nil, errFakeVKShape
	}
	return entries, nil
}

// fakeVKControl is one producer command as the fake read it.
type fakeVKControl struct {
	kind     string // "change-simulcast", "layout", "perf"
	sequence int
	entries  []LayoutEntry
}

// fakeVKReadControl holds a producerCommand frame to the engine's three
// encoders: it is the bytes one of them writes for what the frame says.
func fakeVKReadControl(frame []byte) (fakeVKControl, error) {
	kind, pos, err := fakeVKInt(frame, 0)
	if err != nil {
		return fakeVKControl{}, err
	}
	zero, pos, err := fakeVKInt(frame, pos)
	if err != nil || zero != 0 {
		return fakeVKControl{}, errFakeVKShape
	}
	sequence, pos, err := fakeVKInt(frame, pos)
	if err != nil {
		return fakeVKControl{}, err
	}
	out := fakeVKControl{sequence: sequence}
	var want []byte
	switch kind {
	case 7:
		out.kind = "change-simulcast"
		width, height, fps, kbps := layerProfile()
		want = encodeChangeSimulcast(sequence, "l", width, height, fps, kbps*1000)
	case 1:
		out.kind = "perf"
		decoded, next, readErr := fakeVKInt(frame, pos)
		if readErr != nil {
			return out, readErr
		}
		received, _, readErr := fakeVKInt(frame, next)
		if readErr != nil {
			return out, readErr
		}
		if decoded != received || decoded < 0 {
			return out, fmt.Errorf("a perf report of %d decoded and %d received, the engine reports one count twice",
				decoded, received)
		}
		want = encodePerfStatReport(sequence, uint32(decoded), uint32(received)) //nolint:gosec // not negative
	case 0:
		out.kind = "layout"
		if out.entries, err = fakeVKLayout(frame, pos); err != nil {
			return out, err
		}
		if want, err = EncodeLayout(sequence, out.entries); err != nil {
			return out, err
		}
		for _, e := range out.entries {
			if e.Priority != 1 || e.Width != 640 || e.Height != 360 {
				return out, fmt.Errorf("a layout tile of priority %d at %dx%d, the engine asks priority 1 at 640x360",
					e.Priority, e.Width, e.Height)
			}
		}
	default:
		return out, fmt.Errorf("a producer command of kind %d, which the engine does not send", kind)
	}
	if !bytes.Equal(want, frame) {
		return out, fmt.Errorf("%s is not the engine's bytes: %x, the engine writes %x", out.kind, frame, want)
	}
	return out, nil
}

// onControl takes one producerCommand frame.
func (l *fakeVKLeg) onControl(frame []byte) {
	r := l.room
	cmd, err := fakeVKReadControl(frame)
	if err != nil {
		r.trip(l, "producerCommand: %v", err)
		return
	}
	var named map[string]uint8
	r.mu.Lock()
	// One counter for every producer command: a number is used once. They
	// need not arrive in order: the engine takes a number under its lock
	// and sends outside it, so two of its goroutines (the run loop's
	// layout and the channel's) can send theirs the other way round.
	if l.controlSeen[cmd.sequence] {
		r.tripLocked(l, "producerCommand %s under sequence %d, which was used before: one counter", cmd.kind,
			cmd.sequence)
	}
	l.controlSeen[cmd.sequence] = true
	switch cmd.kind {
	case "change-simulcast":
		l.simulcast++
		if l.simulcast > 1 {
			r.tripLocked(l, "change-simulcast %d times on one connection, the engine sends it once", l.simulcast)
		}
	case "perf":
		l.perf++
		l.perfAt = time.Now()
	case "layout":
		l.layouts++
		l.layout, l.lastLayout, named = map[uint8]bool{}, nil, map[string]uint8{}
		known := map[uint8]bool{}
		for _, id := range l.registry {
			known[id] = true
		}
		for _, e := range cmd.entries {
			if e.ByCompact {
				l.lastLayout = append(l.lastLayout, "#"+strconv.Itoa(int(e.Compact)))
				if !known[e.Compact] {
					r.tripLocked(l, "a layout names stream %d, which no registry frame gave", e.Compact)
					continue
				}
				l.layout[e.Compact] = true
				continue
			}
			l.keyAsks++
			who, isCamera := strings.CutSuffix(strings.TrimPrefix(e.Key, "u"), ":sCAMERA")
			l.lastLayout = append(l.lastLayout, "key")
			if !isCamera || !strings.HasPrefix(e.Key, "u") || r.guests[who] == nil || who == l.guest.id {
				r.tripLocked(l, "a layout asks for a stream key of %d bytes that is no camera of this room", len(e.Key))
				continue
			}
			// A camera asked for by its key is named.
			named[e.Key] = l.compactLocked(e.Key)
		}
	}
	r.mu.Unlock()
	if len(named) > 0 {
		l.registryFrame(fakeVKRegistry(named))
	}
}

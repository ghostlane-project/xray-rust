// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Package mtslinkfake is an overlay package (olc/interop in the xray-rust
// fork): a fake of MTS Link's SFU that forwards. The engine's own fake
// (internal/engine/mtslink, mtslink_test.go) answers one guest and relays
// nothing between two, so no tunnel runs through it; this one keeps rooms,
// answers every join of a room with a real pion peer connection, and writes
// each publisher's video into a receive slot of every other guest, as the
// service's SFU fills the slots a guest offers. Requests for a keyframe go
// back to the publisher. With it the Go server at the pin (engine mtslink on
// direct credentials) and a client meet in one room on loopback, and the
// gate's scenarios run over the carrier with no MTS Link service anywhere
// (internal/gate, TestGateRustMTSFake).
//
// What it keeps of the service, as the engine's fake and the engine's
// comments record it:
//
//   - POST /rtc/room/{session}/join?…: the offer in, the answer out, the
//     peer named in the answer's s= line. A join whose two tokens no guest
//     of the room was given is 403; an offer with more than one line that
//     only receives audio, or whose originMid is not that line's, is 400
//     "SDP validation error: …";
//   - POST /rtc/peer/{peer}/pin: 200 for a peer the room answered;
//   - DELETE /api/conferences/{id}: the engine's take-back, 204 with the
//     guest's cookies;
//   - every candidate named twice, over UDP and as passive TCP, on one UDP
//     mux and one TCP mux of the hub (mtslink.go:17-21).
//
// What it does not keep: the service's own rules about what it forwards
// (keyframe recognition), its audio, its TLS. A forwarded packet loses its
// header extensions (the publisher's mid means nothing to another guest)
// and takes the slot's SSRC and payload type.
package mtslinkfake

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

// Slots is how many video lines a guest receives on (the engine's
// receiveSlots): the most publishers one guest hears.
const Slots = 9

// maxOffer bounds a join's body.
const maxOffer = 1 << 20

// Guest is what a provider would hand an engine for one guest of a room.
type Guest struct {
	// URL is the room join (engine.Credentials.URL): it names the guest and
	// carries both tokens.
	URL string
	// Token is the guest's cookies (engine.Credentials.Token).
	Token string
	// Gateway and Conference are what takes a failed join back
	// (Extra["gateway"], Extra["conferenceId"]).
	Gateway, Conference string
	// Secrets is everything of the guest no log may carry.
	Secrets []string
}

// Joined is one join the room answered.
type Joined struct {
	// Guest is the name the guest was minted under.
	Guest string `json:"guest"`
	// Pair is the protocol of the candidate pair pion selected (udp, tcp),
	// empty while none is.
	Pair string `json:"pair"`
	// Published is how many video packets the guest sent.
	Published int64 `json:"published"`
	// Heard is how many were written into its slots.
	Heard int64 `json:"heard"`
	// Slots is how many lines the guest offered to receive video on.
	Slots int `json:"slots"`
}

// State is what a room saw.
type State struct {
	Joins []Joined `json:"joins"`
	// Refused are the joins the room turned away, by reason.
	Refused []string `json:"refused"`
	// Pins and Leaves are the calls after a join: how many pins, and the
	// conferences taken back.
	Pins   int      `json:"pins"`
	Leaves []string `json:"leaves"`
	// CookiesAtSFU counts joins and pins that carried a Cookie header: the
	// guest's cookies are the gateway's alone.
	CookiesAtSFU int `json:"cookies_at_sfu"`
	// Keyframes is how many keyframe requests went back to a publisher.
	Keyframes int64 `json:"keyframes"`
	// Strays are requests the web client never makes.
	Strays []string `json:"strays"`
}

type guest struct {
	name                         string
	user, join, publish, cookies string
	conference                   string
}

// slot is one receive line of a guest and who fills it.
type slot struct {
	track *webrtc.TrackLocalStaticRTP
	// from is the publisher written into the slot; nil when free.
	from *peer
	// freed orders the free slots: the one freed longest ago is taken
	// first, so a slot's SSRC rests before another publisher uses it.
	freed int64
}

// peer is one answered join.
type peer struct {
	room  *Room
	id    string
	guest string
	pc    *webrtc.PeerConnection

	mu sync.Mutex
	// slots are the lines the peer receives on.
	slots []*slot
	// publishes is the SSRC of the peer's published video, 0 before its
	// first packet.
	publishes uint32
	gone      bool
	pair      string

	published, heard atomic.Int64
}

// Room is one event session of the hub.
type Room struct {
	hub     *Hub
	session string
	owner   string

	mu      sync.Mutex
	guests  []guest
	peers   []*peer
	joined  []*peer
	refused []string
	pins    int
	leaves  []string
	cookies int
	strays  []string
	tick    int64
	closed  bool

	keyframes atomic.Int64
}

// Hub is the fake SFU: one HTTP listener and one ICE port each for UDP and
// TCP, all on loopback, and the rooms behind them.
type Hub struct {
	ln  net.Listener
	srv *http.Server
	udp net.PacketConn
	tcp net.Listener
	// udpMux and tcpMux are pion's ICE muxes over the two.
	udpMux, tcpMux io.Closer
	se             webrtc.SettingEngine

	mu    sync.Mutex
	rooms map[string]*Room
}

// Start listens on loopback.
func Start() (*Hub, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("mtslinkfake: listen: %w", err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("mtslinkfake: udp: %w", err)
	}
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = ln.Close()
		_ = udp.Close()
		return nil, fmt.Errorf("mtslinkfake: tcp: %w", err)
	}
	h := &Hub{ln: ln, udp: udp, tcp: tcp, rooms: make(map[string]*Room)}
	udpMux := webrtc.NewICEUDPMux(nil, udp)
	tcpMux := webrtc.NewICETCPMux(nil, tcp, 8)
	h.udpMux, h.tcpMux = udpMux, tcpMux
	h.se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeTCP4})
	h.se.SetIncludeLoopbackCandidate(true)
	h.se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	h.se.SetICEUDPMux(udpMux)
	h.se.SetICETCPMux(tcpMux)
	h.srv = &http.Server{Handler: http.HandlerFunc(h.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

// Base is the hub's http://host:port.
func (h *Hub) Base() string { return "http://" + h.ln.Addr().String() }

// Close ends every room and the listeners.
func (h *Hub) Close() {
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.mu.Unlock()
	for _, r := range rooms {
		r.Close()
	}
	_ = h.srv.Close()
	_ = h.tcpMux.Close()
	_ = h.udpMux.Close()
	_ = h.tcp.Close()
	_ = h.udp.Close()
}

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

// randomDigits is n decimal digits, the first not zero.
func randomDigits(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	out := make([]byte, n)
	for i, b := range raw {
		out[i] = '0' + b%10
	}
	if out[0] == '0' {
		out[0] = '7'
	}
	return string(out)
}

// Open makes a fresh room.
func (h *Hub) Open() *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := &Room{hub: h, session: randomDigits(13), owner: randomDigits(11)}
	h.rooms[r.session] = r
	return r
}

// Link names the room the way an event join link does (…/j/{owner}/{event}):
// it is what a run calls the room by. Nothing is served at it: a guest
// joins at its Guest's URL.
func (r *Room) Link() string { return r.hub.Base() + "/j/" + r.owner + "/" + r.session }

// Guest mints a guest of the room under name, as the gateway's five calls
// would: a user, the conference's key, the join token, the cookies and a
// device.
func (r *Room) Guest(name string) Guest {
	g := guest{
		name: name, user: randomDigits(12), join: "vcJOIN" + randomHex(14), publish: "vcPRIVATE" + randomHex(13),
		conference: randomDigits(12),
	}
	access, refresh, session := "eyJguest."+randomHex(16), randomHex(16), randomHex(8)
	g.cookies = "access=" + access + "; refresh=" + refresh + "; sessionId=" + session
	did := randomHex(8)
	pid := did[1:] + did[:1]
	r.mu.Lock()
	r.guests = append(r.guests, g)
	r.mu.Unlock()
	return Guest{
		URL: r.hub.Base() + "/rtc/room/" + r.session + "/join?userId=" + g.user + "&joinToken=" + g.join + "&disableRecording=true&userName=" + name +
			"&publishToken=" + g.publish + "&did=" + did + "&pid=" + pid,
		Token: g.cookies, Gateway: r.hub.Base(), Conference: g.conference,
		Secrets: []string{g.join, g.publish, access, refresh, session, did, pid, g.user, g.conference, r.session, r.owner},
	}
}

// State is what the room saw so far.
func (r *Room) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := State{
		Refused: append([]string{}, r.refused...), Pins: r.pins, Leaves: append([]string{}, r.leaves...),
		CookiesAtSFU: r.cookies, Keyframes: r.keyframes.Load(), Strays: append([]string{}, r.strays...),
		Joins: make([]Joined, 0, len(r.joined)),
	}
	for _, p := range r.joined {
		p.mu.Lock()
		pair, slots := p.pair, len(p.slots)
		p.mu.Unlock()
		st.Joins = append(st.Joins, Joined{
			Guest: p.guest, Pair: pair, Published: p.published.Load(), Heard: p.heard.Load(), Slots: slots,
		})
	}
	return st
}

// Close ends the room: its peer connections close and its joins are
// refused from here on.
func (r *Room) Close() {
	r.mu.Lock()
	r.closed = true
	peers := append([]*peer(nil), r.peers...)
	r.peers = nil
	r.mu.Unlock()
	for _, p := range peers {
		_ = p.pc.Close()
	}
	r.hub.mu.Lock()
	delete(r.hub.rooms, r.session)
	r.hub.mu.Unlock()
}

func (h *Hub) room(session string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rooms[session]
}

func (h *Hub) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, maxOffer))
	path := req.URL.Path
	switch {
	case req.Method == http.MethodPost && strings.HasPrefix(path, "/rtc/room/") && strings.HasSuffix(path, "/join"):
		session := strings.TrimSuffix(strings.TrimPrefix(path, "/rtc/room/"), "/join")
		r := h.room(session)
		if r == nil {
			http.Error(w, "no such room", http.StatusNotFound)
			return
		}
		r.join(w, req, string(body))
	case req.Method == http.MethodPost && strings.HasPrefix(path, "/rtc/peer/") && strings.HasSuffix(path, "/pin"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/rtc/peer/"), "/pin")
		r := h.roomOfPeer(id)
		if r == nil {
			http.Error(w, "no such peer", http.StatusNotFound)
			return
		}
		r.mu.Lock()
		r.pins++
		if req.Header.Get("Cookie") != "" {
			r.cookies++
		}
		if string(body) != `{"streams":[""]}` || req.Header.Get("Content-Type") != "application/json" {
			r.strays = append(r.strays, "a pin that is not the web client's")
		}
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case req.Method == http.MethodDelete && strings.HasPrefix(path, "/api/conferences/"):
		conference := strings.TrimPrefix(path, "/api/conferences/")
		r := h.roomOfConference(conference, req.Header.Get("Cookie"))
		if r == nil {
			http.Error(w, `{"error":{"code":401,"message":"A Token was not found in the TokenStorage."}}`,
				http.StatusUnauthorized)
			return
		}
		r.mu.Lock()
		r.leaves = append(r.leaves, conference)
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		h.mu.Lock()
		for _, r := range h.rooms {
			r.mu.Lock()
			r.strays = append(r.strays, req.Method+" of a path the web client never asks for")
			r.mu.Unlock()
		}
		h.mu.Unlock()
		http.NotFound(w, req)
	}
}

func (h *Hub) roomOfPeer(id string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.rooms {
		r.mu.Lock()
		for _, p := range r.joined {
			if p.id == id {
				r.mu.Unlock()
				return r
			}
		}
		r.mu.Unlock()
	}
	return nil
}

func (h *Hub) roomOfConference(conference, cookies string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.rooms {
		r.mu.Lock()
		for _, g := range r.guests {
			if g.conference == conference && g.cookies == cookies {
				r.mu.Unlock()
				return r
			}
		}
		r.mu.Unlock()
	}
	return nil
}

func (r *Room) refuse(w http.ResponseWriter, status int, why string) {
	r.mu.Lock()
	r.refused = append(r.refused, why)
	r.mu.Unlock()
	w.WriteHeader(status)
	_, _ = io.WriteString(w, why)
}

// audioPlayers is the mids of the offer's lines that only receive audio.
func audioPlayers(offer string) []string {
	var mids []string
	for _, section := range strings.Split(offer, "\r\nm=")[1:] {
		if !strings.HasPrefix(section, "audio ") || !strings.Contains(section, "\r\na=recvonly") {
			continue
		}
		for _, line := range strings.Split(section, "\r\n") {
			if mid, ok := strings.CutPrefix(line, "a=mid:"); ok {
				mids = append(mids, mid)
				break
			}
		}
	}
	return mids
}

func (r *Room) join(w http.ResponseWriter, req *http.Request, offer string) {
	q := req.URL.Query()
	r.mu.Lock()
	closed := r.closed
	var who *guest
	for i := range r.guests {
		g := &r.guests[i]
		if g.user == q.Get("userId") && g.join == q.Get("joinToken") && g.publish == q.Get("publishToken") {
			who = g
			break
		}
	}
	if req.Header.Get("Cookie") != "" {
		r.cookies++
	}
	r.mu.Unlock()
	switch {
	case closed:
		r.refuse(w, http.StatusGone, "the room is closed")
		return
	case who == nil:
		r.refuse(w, http.StatusForbidden, "no such guest")
		return
	case req.Header.Get("Content-Type") != "application/sdp":
		r.refuse(w, http.StatusBadRequest, "the join is not an SDP")
		return
	}
	players := audioPlayers(offer)
	switch {
	case len(players) > 1:
		r.refuse(w, http.StatusBadRequest, "SDP validation error: exceeded maximal audio players value 1")
		return
	case len(players) == 0 || q.Get("originMid") != players[0]:
		r.refuse(w, http.StatusBadRequest, "SDP validation error: originMid is not the audio player's line")
		return
	case q.Get("preferredPublishCodec") != "vp9" || q.Get("twcc") != "true":
		r.refuse(w, http.StatusBadRequest, "SDP validation error: the join does not describe its offer")
		return
	}

	me := &webrtc.MediaEngine{}
	ir := &interceptor.Registry{}
	if err := errors.Join(me.RegisterDefaultCodecs(), webrtc.RegisterDefaultInterceptors(me, ir)); err != nil {
		r.refuse(w, http.StatusInternalServerError, "media engine: "+err.Error())
		return
	}
	pc, err := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir),
		webrtc.WithSettingEngine(r.hub.se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		r.refuse(w, http.StatusInternalServerError, "peer connection: "+err.Error())
		return
	}
	p := &peer{room: r, id: "fakepeer" + randomHex(24), guest: who.name, pc: pc}
	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if track.Kind() != webrtc.RTPCodecTypeVideo {
			return
		}
		p.publish(track)
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateConnected:
			p.selected()
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			// A guest that leaves closes its DTLS, and pion closes the
			// peer connection with it: its slots are free at once.
			r.drop(p)
		case webrtc.PeerConnectionStateNew, webrtc.PeerConnectionStateConnecting,
			webrtc.PeerConnectionStateDisconnected, webrtc.PeerConnectionStateUnknown:
		}
	})
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		_ = pc.Close()
		r.refuse(w, http.StatusBadRequest, "SDP validation error: "+err.Error())
		return
	}
	// A track on every video line the guest offered to receive on: the
	// slots the room's publishers are written into.
	for _, tr := range pc.GetTransceivers() {
		if tr.Kind() != webrtc.RTPCodecTypeVideo || tr.Direction() != webrtc.RTPTransceiverDirectionSendonly ||
			len(p.slots) == Slots {
			continue
		}
		n := strconv.Itoa(len(p.slots))
		track, trackErr := webrtc.NewTrackLocalStaticRTP(
			webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP9, ClockRate: 90000}, "relay-video-"+n, "relay-"+n)
		if trackErr != nil {
			continue
		}
		sender, senderErr := webrtc.NewAPI(webrtc.WithMediaEngine(me)).NewRTPSender(track, tr.Receiver().Transport())
		if senderErr != nil || tr.SetSender(sender, track) != nil {
			continue
		}
		s := &slot{track: track}
		p.slots = append(p.slots, s)
		go p.feedback(s, sender)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		_ = pc.Close()
		r.refuse(w, http.StatusInternalServerError, "answer: "+err.Error())
		return
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		_ = pc.Close()
		r.refuse(w, http.StatusInternalServerError, "local description: "+err.Error())
		return
	}
	<-gathered
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = pc.Close()
		r.refuse(w, http.StatusGone, "the room is closed")
		return
	}
	r.peers = append(r.peers, p)
	r.joined = append(r.joined, p)
	r.mu.Unlock()
	// The SFU names the peer in the answer's s= line.
	sdp := strings.Replace(pc.LocalDescription().SDP, "\r\ns=-\r\n", "\r\ns="+p.id+"\r\n", 1)
	w.Header().Set("Content-Type", "application/sdp")
	_, _ = io.WriteString(w, sdp)
}

// selected notes the protocol of the pair pion selected.
func (p *peer) selected() {
	for _, tr := range p.pc.GetTransceivers() {
		dtls := tr.Receiver().Transport()
		if dtls == nil || dtls.ICETransport() == nil {
			continue
		}
		pair, err := dtls.ICETransport().GetSelectedCandidatePair()
		if err != nil || pair == nil || pair.Local == nil {
			continue
		}
		p.mu.Lock()
		p.pair = pair.Local.Protocol.String()
		p.mu.Unlock()
		return
	}
}

// publish reads the guest's published video to its end and writes every
// packet into the guest's slot of each other peer.
func (p *peer) publish(track *webrtc.TrackRemote) {
	p.mu.Lock()
	p.publishes = uint32(track.SSRC())
	p.mu.Unlock()
	for {
		pkt, _, err := track.ReadRTP()
		if err != nil {
			return
		}
		p.published.Add(1)
		// The publisher's extensions are its own session's: its mid names
		// no line of another guest's.
		pkt.Header.Extension, pkt.Header.ExtensionProfile, pkt.Header.Extensions = false, 0, nil
		p.room.mu.Lock()
		others := append([]*peer(nil), p.room.peers...)
		p.room.mu.Unlock()
		for _, q := range others {
			if q == p {
				continue
			}
			s, fresh := q.slotOf(p)
			if s == nil {
				continue
			}
			if fresh {
				// A guest that starts to hear a publisher needs a
				// picture to start from.
				p.keyframe()
			}
			if s.track.WriteRTP(pkt) == nil {
				q.heard.Add(1)
			}
		}
	}
}

// slotOf is the slot of q that from is written into; a free one is taken
// when from has none (the one freed longest ago), and fresh says so.
func (p *peer) slotOf(from *peer) (s *slot, fresh bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gone {
		return nil, false
	}
	var free *slot
	for _, s := range p.slots {
		if s.from == from {
			return s, false
		}
		if s.from == nil && (free == nil || s.freed < free.freed) {
			free = s
		}
	}
	if free == nil {
		return nil, false
	}
	free.from = from
	return free, true
}

// keyframe asks the publisher for a keyframe.
func (p *peer) keyframe() {
	p.mu.Lock()
	ssrc, gone := p.publishes, p.gone
	p.mu.Unlock()
	if ssrc == 0 || gone {
		return
	}
	if p.pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: ssrc}}) == nil {
		p.room.keyframes.Add(1)
	}
}

// feedback passes the keyframe requests a guest sends about a slot back to
// the publisher in it.
func (p *peer) feedback(s *slot, sender *webrtc.RTPSender) {
	for {
		pkts, _, err := sender.ReadRTCP()
		if err != nil {
			return
		}
		asked := false
		for _, pkt := range pkts {
			switch pkt.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				asked = true
			}
		}
		if !asked {
			continue
		}
		p.mu.Lock()
		from := s.from
		p.mu.Unlock()
		if from != nil {
			from.keyframe()
		}
	}
}

// drop takes a peer whose connection ended out of the room and frees the
// slots it filled.
func (r *Room) drop(p *peer) {
	p.mu.Lock()
	gone := p.gone
	p.gone = true
	p.mu.Unlock()
	if gone {
		return
	}
	r.mu.Lock()
	for i, q := range r.peers {
		if q == p {
			r.peers = append(r.peers[:i], r.peers[i+1:]...)
			break
		}
	}
	others := append([]*peer(nil), r.peers...)
	r.tick++
	tick := r.tick
	r.mu.Unlock()
	for _, q := range others {
		q.mu.Lock()
		for _, s := range q.slots {
			if s.from == p {
				s.from, s.freed = nil, tick
			}
		}
		q.mu.Unlock()
	}
}

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the interop-p2p
// engine. A room of the T1 hub (internal/engine/interoppipe) carries only
// the signalling; the media goes peer to peer, one pion PeerConnection per
// other participant, each with one VP8 video m-line. A video transport
// (vp8channel) publishes its one local track on every connection and reads
// every remote track, as it would through a carrier's SFU.
//
// The URL is tcp://host:port/room[?turn=<ice url>&turn_user=&turn_pass=&
// policy=relay|all&ice=udp|tcp|both]: the hub and room, then the ICE servers,
// the policy and the ICE mode. Without ice= the mode is the engine's first
// behaviour: UDP host candidates, no listener. Nothing but the URL names it
// (the gate writes ice= into both ends' URLs: -olcrtc.gate-ice).
//
// ICE over TCP (the MTS Link client's default, mtslink.go iceNetworkTypes):
// with ice=tcp the session gathers passive TCP host candidates on a TCP mux
// of its own (a loopback listener) and nothing over UDP, as an SFU that
// offers TCP does; with ice=both, those and the UDP ones. pion dials a
// remote's passive candidates itself (active); olc-rtc's icetcp.rs does the
// same for the Rust client.
//
// Signalling is JSON text in the hub's DATA frames:
//
//	{"t":"hello","from":ID,"to":""}     after every join
//	{"t":"hello","from":ID,"to":PEER}   to a newcomer's broadcast hello
//	{"t":"offer"|"answer","from":ID,"to":PEER,"sdp":SDP}
//	{"t":"bye","from":ID,"to":""}       before leaving
//
// The newcomer offers: a directed hello makes it open a connection to the
// sender and offer; an offer (re)opens the connection for its sender and is
// answered, unless it crosses our own unanswered offer to the sender (both
// hellos crossed, so each end took the other for the newcomer): then the
// greater id's offer stands and the lower id answers it. No trickle: each
// SDP carries every candidate gathered.
//
// The Rust client (olc-client's p2p module) speaks the same.

package interopp2p

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

// Name is the engine's name in a config (engine: { name: interop-p2p }).
const Name = "interop-p2p"

// VP8PayloadType is the one codec's payload type.
const VP8PayloadType = 96

const (
	// gatherBudget bounds the wait for ICE gathering before an SDP goes
	// out with what it has.
	gatherBudget  = 10 * time.Second
	rejoinBackoff = 100 * time.Millisecond
	rejoinMax     = 2 * time.Second
	idBytes       = 8
)

// The ICE modes of a URL's ice= (roomhint's three words).
const (
	ICEUDP  = "udp"
	ICETCP  = "tcp"
	ICEBoth = "both"
	// tcpMuxReadBuffer is the TCP mux's per-connection queue, in packets
	// (pion's example value).
	tcpMuxReadBuffer = 8
)

// The signalling message types.
const (
	msgHello  = "hello"
	msgOffer  = "offer"
	msgAnswer = "answer"
	msgBye    = "bye"
)

var (
	// ErrBadURL is a URL that is not tcp://host:port/room[?...].
	ErrBadURL = errors.New("interop-p2p: url must be tcp://host:port/room[?turn=...&policy=relay|all&ice=udp|tcp|both]")
	// ErrNotConnected is a call while the session is not in the room.
	ErrNotConnected = errors.New("interop-p2p: not connected")
	// ErrNoData is a data message: the engine carries video only.
	ErrNoData = errors.New("interop-p2p: a video engine carries no data messages")
)

// Settings is what a URL names.
type Settings struct {
	Addr, Room string
	ICEServers []webrtc.ICEServer
	Policy     webrtc.ICETransportPolicy
	// ICE is the mode: "" (the default: UDP host candidates, no TCP
	// listener), udp, tcp or both.
	ICE string
}

// ParseURL reads tcp://host:port/room and its query; unknown keys are
// ignored.
func ParseURL(raw string) (Settings, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "tcp" || u.Host == "" {
		return Settings{}, fmt.Errorf("%w: %q", ErrBadURL, raw)
	}
	room := strings.TrimPrefix(u.Path, "/")
	if room == "" {
		return Settings{}, fmt.Errorf("%w: %q", ErrBadURL, raw)
	}
	q := u.Query()
	s := Settings{Addr: u.Host, Room: room, Policy: webrtc.ICETransportPolicyAll}
	if turns := q["turn"]; len(turns) > 0 {
		s.ICEServers = []webrtc.ICEServer{{URLs: turns, Username: q.Get("turn_user"), Credential: q.Get("turn_pass")}}
	}
	switch q.Get("policy") {
	case "", "all":
	case "relay":
		s.Policy = webrtc.ICETransportPolicyRelay
	default:
		return Settings{}, fmt.Errorf("%w: policy %q", ErrBadURL, q.Get("policy"))
	}
	s.ICE = q.Get("ice")
	switch s.ICE {
	case "", ICEUDP, ICETCP, ICEBoth:
	default:
		return Settings{}, fmt.Errorf("%w: ice %q", ErrBadURL, s.ICE)
	}
	return s, nil
}

// Register adds the engine to the engine registry.
func Register() { engine.Register(Name, New) }

type message struct {
	T    string `json:"t"`
	From string `json:"from"`
	To   string `json:"to"`
	SDP  string `json:"sdp,omitempty"`
}

// peer is the connection to one other participant.
type peer struct {
	id        string
	pc        *webrtc.PeerConnection
	connected atomic.Bool
}

// Session is one participant: engine.Session and engine.VideoTrackCapable.
type Session struct {
	engine.VideoTrackState

	set Settings
	api *webrtc.API
	// mux is the TCP mux's listener (ice=tcp|both), closed with the session.
	mux io.Closer

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	conn      net.Conn
	id        string
	connected bool
	closed    bool
	peers     map[string]*peer
	replied   map[string]bool
	reconnect func()
	should    func() bool
	ended     func(string)

	wmu sync.Mutex // one frame at a time on conn

	// offers and answers count the SDPs this session made (tests).
	offers, answers atomic.Int64
}

var (
	_ engine.Session           = (*Session)(nil)
	_ engine.VideoTrackCapable = (*Session)(nil)
)

// New is the engine's factory.
func New(_ context.Context, cfg engine.Config) (engine.Session, error) {
	set, err := ParseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	api, mux, err := newAPI(set.ICE)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{set: set, api: api, mux: mux, ctx: ctx, cancel: cancel,
		peers: make(map[string]*peer), replied: make(map[string]bool)}, nil
}

// newAPI is pion with VP8 alone (payload type 96, nack, nack pli, ccm fir)
// and the default interceptors, gathering on loopback too (the gate's hosts
// are all on 127.0.0.1), IPv4, no mDNS. With mode tcp or both it listens on
// a loopback TCP port for ICE-TCP (pion's TCP mux) and gathers on loopback
// alone, where the listener is; the returned closer (nil otherwise) ends
// the listener.
func newAPI(mode string) (*webrtc.API, io.Closer, error) {
	var se webrtc.SettingEngine
	se.LoggerFactory = logger.NewPionLoggerFactory()
	se.SetIncludeLoopbackCandidate(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	types := []webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeTCP4}
	var mux io.Closer
	if mode == ICETCP || mode == ICEBoth {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, nil, fmt.Errorf("interop-p2p: ice tcp listener: %w", err)
		}
		tcpMux := webrtc.NewICETCPMux(nil, ln, tcpMuxReadBuffer)
		se.SetICETCPMux(tcpMux)
		se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
		mux = muxCloser{tcpMux, ln}
		if mode == ICETCP {
			types = []webrtc.NetworkType{webrtc.NetworkTypeTCP4}
		}
		logger.Infof("interop-p2p: ICE over %s, passive TCP on %s", mode, ln.Addr())
	}
	se.SetNetworkTypes(types)
	api, err := newAPIWith(se)
	if err != nil && mux != nil {
		_ = mux.Close()
		mux = nil
	}
	return api, mux, err
}

// muxCloser closes a TCP mux and its listener.
type muxCloser struct {
	mux ice.TCPMux
	ln  net.Listener
}

func (m muxCloser) Close() error {
	err := m.mux.Close()
	_ = m.ln.Close()
	return err
}

// newAPIWith is pion with VP8 alone and the default interceptors on se.
func newAPIWith(se webrtc.SettingEngine) (*webrtc.API, error) {
	me := &webrtc.MediaEngine{}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType: webrtc.MimeTypeVP8, ClockRate: 90000,
			RTCPFeedback: []webrtc.RTCPFeedback{{Type: "nack"}, {Type: "nack", Parameter: "pli"}, {Type: "ccm", Parameter: "fir"}},
		},
		PayloadType: VP8PayloadType,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, fmt.Errorf("interop-p2p: register vp8: %w", err)
	}
	reg := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptorsWithOptions(me, reg, engine.DefaultInterceptorOptions()...); err != nil {
		return nil, fmt.Errorf("interop-p2p: interceptors: %w", err)
	}
	return webrtc.NewAPI(webrtc.WithSettingEngine(se), webrtc.WithMediaEngine(me),
		webrtc.WithInterceptorRegistry(reg)), nil
}

func newID() string {
	var b [idBytes]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// LocalID is this join's id in the signalling.
func (s *Session) LocalID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

// Connect joins the room and says hello.
func (s *Session) Connect(ctx context.Context) error {
	conn, err := s.join(ctx)
	if err != nil {
		return err
	}
	id := newID()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return ErrNotConnected
	}
	s.conn, s.id, s.connected = conn, id, true
	s.replied = make(map[string]bool)
	s.mu.Unlock()
	go s.read(conn, id)
	s.signal(conn, message{T: msgHello, From: id})
	logger.Infof("interop-p2p: joined room %s as %s", s.set.Room, id)
	return nil
}

func (s *Session) join(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.set.Addr)
	if err != nil {
		return nil, fmt.Errorf("interop-p2p: dial hub: %w", err)
	}
	if err := interoppipe.WriteFrame(conn, interoppipe.KindJoin, []byte(s.set.Room)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("interop-p2p: join: %w", err)
	}
	return conn, nil
}

// signal sends one message on conn (the join it belongs to).
func (s *Session) signal(conn net.Conn, m message) {
	raw, err := json.Marshal(m)
	if err != nil {
		return
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := interoppipe.WriteFrame(conn, interoppipe.KindData, raw); err != nil {
		logger.Debugf("interop-p2p: signal %s: %v", m.T, err)
	}
}

func (s *Session) read(conn net.Conn, id string) {
	br := bufio.NewReaderSize(conn, interoppipe.MaxPayload+5)
	for {
		kind, payload, err := interoppipe.ReadFrame(br)
		if err != nil {
			break
		}
		switch kind {
		case interoppipe.KindData:
			s.onSignal(conn, id, payload)
		case interoppipe.KindEnd:
			s.mu.Lock()
			ended := s.ended
			if s.conn == conn {
				s.conn, s.connected = nil, false
			}
			s.mu.Unlock()
			s.closePeers()
			_ = conn.Close()
			if ended != nil {
				ended(string(payload))
			}
			return
		}
	}
	s.lost(conn)
}

func (s *Session) onSignal(conn net.Conn, id string, payload []byte) {
	var m message
	if err := json.Unmarshal(payload, &m); err != nil || m.From == "" || m.From == id {
		return
	}
	if m.To != "" && m.To != id {
		return
	}
	switch m.T {
	case msgHello:
		if m.To == id {
			go s.offer(conn, id, m.From)
			return
		}
		s.mu.Lock()
		seen := s.replied[m.From]
		s.replied[m.From] = true
		s.mu.Unlock()
		if !seen {
			s.signal(conn, message{T: msgHello, From: id, To: m.From})
		}
	case msgOffer:
		go s.answer(conn, id, m.From, m.SDP)
	case msgAnswer:
		s.accept(m.From, m.SDP)
	case msgBye:
		s.drop(m.From, nil)
	}
}

// newPeer opens the connection to remote, replacing an older one, with the
// local tracks on it.
func (s *Session) newPeer(remote string) (*peer, error) {
	pc, err := s.api.NewPeerConnection(webrtc.Configuration{
		ICEServers: s.set.ICEServers, ICETransportPolicy: s.set.Policy,
	})
	if err != nil {
		return nil, fmt.Errorf("interop-p2p: peer connection: %w", err)
	}
	p := &peer{id: remote, pc: pc}
	pc.OnTrack(func(tr *webrtc.TrackRemote, rcv *webrtc.RTPReceiver) {
		if h := s.VideoTrackHandler(); h != nil && tr.Kind() == webrtc.RTPCodecTypeVideo {
			h(tr, rcv)
			return
		}
		go func() {
			for {
				if _, _, err := tr.ReadRTP(); err != nil {
					return
				}
			}
		}()
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		logger.Infof("interop-p2p: peer %s %s", remote, st)
		switch st {
		case webrtc.PeerConnectionStateConnected:
			p.connected.Store(true)
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			p.connected.Store(false)
			s.drop(remote, p)
		default:
		}
	})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = pc.Close()
		return nil, ErrNotConnected
	}
	old := s.peers[remote]
	s.peers[remote] = p
	s.mu.Unlock()
	if old != nil {
		_ = old.pc.Close()
	}
	return p, nil
}

// attach puts the local tracks on pc (an answerer's reuse the offer's
// transceiver); with none, a receive-only video transceiver when offering.
func (s *Session) attach(pc *webrtc.PeerConnection, offering bool) error {
	var attachErr error
	had := s.RangeVideoTracks(func(track webrtc.TrackLocal, _ bool) {
		if attachErr != nil {
			return
		}
		sender, err := pc.AddTrack(track)
		if err != nil {
			attachErr = fmt.Errorf("interop-p2p: add track: %w", err)
			return
		}
		go engine.DrainRTCP(sender)
	})
	if attachErr != nil || had || !offering {
		return attachErr
	}
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		return fmt.Errorf("interop-p2p: transceiver: %w", err)
	}
	return nil
}

// settle sets desc as the local description and waits for gathering.
func (s *Session) settle(pc *webrtc.PeerConnection, desc webrtc.SessionDescription) (string, error) {
	done := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(desc); err != nil {
		return "", fmt.Errorf("interop-p2p: local description: %w", err)
	}
	select {
	case <-done:
	case <-time.After(gatherBudget):
		logger.Infof("interop-p2p: gathering still running after %s; sending what it has", gatherBudget)
	case <-s.ctx.Done():
		return "", ErrNotConnected
	}
	return pc.LocalDescription().SDP, nil
}

func (s *Session) offer(conn net.Conn, id, remote string) {
	p, err := s.newPeer(remote)
	if err != nil {
		logger.Infof("%v", err)
		return
	}
	if err := s.attach(p.pc, true); err != nil {
		logger.Infof("%v", err)
		s.drop(remote, p)
		return
	}
	desc, err := p.pc.CreateOffer(nil)
	if err == nil {
		var sdp string
		if sdp, err = s.settle(p.pc, desc); err == nil {
			s.offers.Add(1)
			s.signal(conn, message{T: msgOffer, From: id, To: remote, SDP: sdp})
			return
		}
	}
	logger.Infof("interop-p2p: offer to %s: %v", remote, err)
	s.drop(remote, p)
}

func (s *Session) answer(conn net.Conn, id, remote, sdp string) {
	// Crossed offers (the hellos crossed, so each end took the other for
	// the newcomer): the greater id's offer stands and the lower id answers
	// it. olc-client's p2p.rs keeps the same rule.
	if id > remote && s.offering(remote) {
		logger.Infof("interop-p2p: the offer from %s crossed ours; ours stands", remote)
		return
	}
	p, err := s.newPeer(remote)
	if err != nil {
		logger.Infof("%v", err)
		return
	}
	err = p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp})
	if err == nil {
		err = s.attach(p.pc, false)
	}
	var desc webrtc.SessionDescription
	if err == nil {
		desc, err = p.pc.CreateAnswer(nil)
	}
	if err == nil {
		var local string
		if local, err = s.settle(p.pc, desc); err == nil {
			s.answers.Add(1)
			s.signal(conn, message{T: msgAnswer, From: id, To: remote, SDP: local})
			return
		}
	}
	logger.Infof("interop-p2p: answer to %s: %v", remote, err)
	s.drop(remote, p)
}

// offering reports whether remote's connection holds our unanswered offer.
func (s *Session) offering(remote string) bool {
	s.mu.Lock()
	p := s.peers[remote]
	s.mu.Unlock()
	return p != nil && p.pc.SignalingState() == webrtc.SignalingStateHaveLocalOffer
}

func (s *Session) accept(remote, sdp string) {
	s.mu.Lock()
	p := s.peers[remote]
	s.mu.Unlock()
	// An answer to no offer of ours (one we gave up for a crossing offer)
	// is dropped; it must not close the connection that replaced it.
	if p == nil || p.pc.SignalingState() != webrtc.SignalingStateHaveLocalOffer {
		return
	}
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}); err != nil {
		logger.Infof("interop-p2p: answer from %s: %v", remote, err)
		s.drop(remote, p)
	}
}

// drop closes remote's connection: only p when p is set (a stale
// connection's own state change must not close its replacement).
func (s *Session) drop(remote string, p *peer) {
	s.mu.Lock()
	cur := s.peers[remote]
	if cur == nil || (p != nil && cur != p) {
		s.mu.Unlock()
		if p != nil {
			_ = p.pc.Close()
		}
		return
	}
	delete(s.peers, remote)
	s.mu.Unlock()
	_ = cur.pc.Close()
}

func (s *Session) closePeers() {
	s.mu.Lock()
	peers := s.peers
	s.peers = make(map[string]*peer)
	s.mu.Unlock()
	for _, p := range peers {
		_ = p.pc.Close()
	}
}

func (s *Session) peerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.peers)
}

// lost rejoins after the hub connection went away (or Reconnect closed it):
// the old connections close, a new id says hello, and the upper layer hears
// of it, as an SFU engine's does after an ICE restart.
func (s *Session) lost(conn net.Conn) {
	s.mu.Lock()
	if s.conn != conn || s.closed {
		s.mu.Unlock()
		return
	}
	s.conn, s.connected = nil, false
	should, cb := s.should, s.reconnect
	s.mu.Unlock()
	_ = conn.Close()
	s.closePeers()
	if should != nil && !should() {
		return
	}
	logger.Infof("interop-p2p: hub connection lost, rejoining room")
	delay := rejoinBackoff
	for s.ctx.Err() == nil {
		if err := s.Connect(s.ctx); err == nil {
			if cb != nil {
				cb()
			}
			return
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, rejoinMax)
	}
}

// bye says goodbye on the current join, if any.
func (s *Session) bye() net.Conn {
	s.mu.Lock()
	conn, id := s.conn, s.id
	s.mu.Unlock()
	if conn != nil {
		s.signal(conn, message{T: msgBye, From: id})
	}
	return conn
}

// Send implements engine.Session: refused, the engine carries video only.
func (s *Session) Send([]byte) error { return ErrNoData }

// Close leaves the room for good.
func (s *Session) Close() error {
	conn := s.bye()
	s.mu.Lock()
	s.closed, s.connected, s.conn = true, false, nil
	s.mu.Unlock()
	s.cancel()
	s.closePeers()
	if conn != nil {
		_ = conn.Close()
	}
	if s.mux != nil {
		_ = s.mux.Close()
	}
	return nil
}

// Reconnect says goodbye and drops the hub connection; the read loop
// rejoins.
func (s *Session) Reconnect(reason string) {
	logger.Infof("interop-p2p: reconnect requested: %s", reason)
	if conn := s.bye(); conn != nil {
		_ = conn.Close()
	}
}

// AddVideoTrack implements engine.VideoTrackCapable: the track goes on
// every connection made from now on.
func (s *Session) AddVideoTrack(track webrtc.TrackLocal) error {
	s.StoreVideoTrack(track)
	return nil
}

// SetReconnectCallback implements engine.Session.
func (s *Session) SetReconnectCallback(cb func()) {
	s.mu.Lock()
	s.reconnect = cb
	s.mu.Unlock()
}

// SetShouldReconnect implements engine.Session.
func (s *Session) SetShouldReconnect(fn func() bool) {
	s.mu.Lock()
	s.should = fn
	s.mu.Unlock()
}

// SetEndedCallback implements engine.Session.
func (s *Session) SetEndedCallback(cb func(string)) {
	s.mu.Lock()
	s.ended = cb
	s.mu.Unlock()
}

// WatchConnection implements engine.Session: the read loop does the watching.
func (s *Session) WatchConnection(ctx context.Context) { <-ctx.Done() }

// CanSend reports whether the room is joined: a publisher on an SFU is
// ready before anyone subscribes.
func (s *Session) CanSend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected && !s.closed
}

// SubscriberCanSend implements engine.Session.
func (s *Session) SubscriberCanSend() bool { return s.CanSend() }

// GetBufferedAmount implements engine.Session: no data channel.
func (s *Session) GetBufferedAmount() uint64 { return 0 }

// PeerSeen reports whether a peer connection is connected now.
func (s *Session) PeerSeen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.peers {
		if p.connected.Load() {
			return true
		}
	}
	return false
}

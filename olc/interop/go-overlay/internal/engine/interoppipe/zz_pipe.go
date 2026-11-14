// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the interop-pipe
// engine, a meeting room made of one TCP hub (zz_hub.go). It stands where a
// carrier's SFU stands, so the Go server and the Rust client meet through the
// engine's own transports, muxconn and smux, with no WebRTC between them.
//
// The wire, both directions, is a sequence of frames:
//
//	u32 big-endian length of what follows | u8 kind | payload
//
// kind 1 JOIN (participant to hub): the room's name; the first frame.
// kind 2 DATA: one reliable, ordered message, to every other participant.
// kind 3 DGRAM: one lossy message, the same way.
// kind 4 PEERS (hub to participant): u16 big-endian, the others in the room.
// kind 5 END (hub to participant): the conference ended, for this reason.
//
// A participant may join with ids instead (PeersName, "peer mode"), as on a
// carrier whose SFU names its participants:
//
// kind 6 JOIN as a participant with an id.
// kind 7 SELF (hub to it): its id.
// kind 8 DATA to one participant: u8 id length | id | message.
// kind 9 DGRAM to one participant, the same way.
// kind 10 DATA (hub to it): u8 id length | the sender's id | message.
// kind 11 DGRAM (hub to it), the same way.
//
// A participant that joined with kind 1 is sent kinds 2 and 3 whoever sent
// them, so the Rust side (olc-client's pipe module), which speaks kinds 1-5,
// can be in a room with a server in peer mode.
//
// A test build (olcrtc_testhooks) started with OLCRTC_TEST_BRIDGE_DELAY opens
// its bridge late, as the jitsi engine does for the gate's S6: on each join,
// once another participant is in the room (Jicofo's session-initiate), it
// waits testhooks.BeforeBridgeOpen out (jitsi/negotiate.go:60) and drops
// every message it is sent until then, as the bridge drops what is sent to an
// endpoint whose own bridge is not open. The others see it in the room all
// along (PEERS), as they see a participant in the MUC.

package interoppipe

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/testhooks"
)

// Name is the engine's name in a config (engine: { name: interop-pipe }).
const Name = "interop-pipe"

// PeersName is the engine in peer mode (engine: { name: interop-pipe-peers }):
// a session that is an engine.PeerSession, so the datachannel transport above
// it routes per peer (SupportsPeerRouting, datachannel/transport.go:137-140)
// and a server on it runs its peer-routing path (server/link.go:30-32).
const PeersName = "interop-pipe-peers"

// The frame kinds.
const (
	KindJoin  byte = 1
	KindData  byte = 2
	KindDgram byte = 3
	KindPeers byte = 4
	KindEnd   byte = 5
	// Peer mode.
	KindJoinPeers byte = 6
	KindSelf      byte = 7
	KindDataTo    byte = 8
	KindDgramTo   byte = 9
	KindDataFrom  byte = 10
	KindDgramFrom byte = 11
)

// Addressed is a peer-mode payload: u8 id length | id | message.
func Addressed(id string, msg []byte) []byte {
	out := make([]byte, 0, 1+len(id)+len(msg))
	out = append(out, byte(len(id))) //nolint:gosec // the hub's ids are a few bytes
	out = append(out, id...)
	return append(out, msg...)
}

// SplitAddressed reads a peer-mode payload: the id and the message.
func SplitAddressed(p []byte) (string, []byte, bool) {
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", nil, false
	}
	n := int(p[0])
	return string(p[1 : 1+n]), p[1+n:], true
}

// MaxPayload bounds one frame's payload: four times the datachannel's 12 KiB
// message, so no message a transport sends is refused.
const MaxPayload = 64 << 10

// SendHighWater is what a participant lets the kernel hold unsent: a
// carrier's datachannel high-water mark (defaultBufferHighWaterMark,
// goolom/session.go; bufferHighWaterMark, salutejazz/data.go: 512 KiB), which
// the carriers wait under before they send more. Without it a loopback socket
// autotunes to megabytes, a queue no carrier has. The Rust pipe sets the same
// bound (olc-client's pipe.rs SEND_HIGH_WATER).
const SendHighWater = 512 * 1024

// rejoinBackoff and rejoinMax pace the rejoins after a lost hub connection.
const (
	rejoinBackoff = 100 * time.Millisecond
	rejoinMax     = 2 * time.Second
)

var (
	// ErrNotConnected is a send while the session is not in the room.
	ErrNotConnected = errors.New("interop-pipe: not connected")
	// ErrBadURL is a URL that is not tcp://host:port/room.
	ErrBadURL = errors.New("interop-pipe: url must be tcp://host:port/room")
	// ErrFrameTooLarge is a frame over MaxPayload.
	ErrFrameTooLarge = errors.New("interop-pipe: frame too large")
)

// ParseURL splits tcp://host:port/room.
func ParseURL(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "tcp" || u.Host == "" {
		return "", "", fmt.Errorf("%w: %q", ErrBadURL, raw)
	}
	room := strings.TrimPrefix(u.Path, "/")
	if room == "" {
		return "", "", fmt.Errorf("%w: %q", ErrBadURL, raw)
	}
	return u.Host, room, nil
}

// WriteFrame writes one frame in a single Write.
func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(1+len(payload))) //nolint:gosec // bounded above
	buf[4] = kind
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err //nolint:wrapcheck // the connection's own error
}

// ReadFrame reads one frame into a fresh payload.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err //nolint:wrapcheck // the connection's own error
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 || n-1 > MaxPayload {
		return 0, nil, ErrFrameTooLarge
	}
	payload := make([]byte, n-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err //nolint:wrapcheck // the connection's own error
	}
	return hdr[4], payload, nil
}

// Register adds the engine, in both modes, to the engine registry.
func Register() {
	engine.Register(Name, New)
	engine.Register(PeersName, NewPeers)
}

// Session is one participant: engine.Session, DatagramSession and the
// transport's PeerObserver.
type Session struct {
	addr, room     string
	onData         func([]byte)
	onDatagram     func([]byte)
	peerMode       bool
	onPeerData     func(string, []byte)
	onPeerDatagram func(string, []byte)

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	conn      net.Conn
	connected bool
	closed    bool
	seen      bool
	reconnect func()
	should    func() bool
	ended     func(string)
	self      string // peer mode: the hub's id for this connection
	target    string // peer mode: the participant every Send goes to

	wmu sync.Mutex // one frame at a time on conn
}

var (
	_ engine.Session         = (*Session)(nil)
	_ engine.DatagramSession = (*Session)(nil)
)

// New is the engine's factory: cfg.URL is tcp://host:port/room.
func New(_ context.Context, cfg engine.Config) (engine.Session, error) {
	s, err := newSession(cfg, false)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// NewPeers is the factory of the engine in peer mode (PeersName).
func NewPeers(_ context.Context, cfg engine.Config) (engine.Session, error) {
	s, err := newSession(cfg, true)
	if err != nil {
		return nil, err
	}
	return &Peers{Session: s}, nil
}

func newSession(cfg engine.Config, peerMode bool) (*Session, error) {
	addr, room, err := ParseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		addr: addr, room: room, onData: cfg.OnData, onDatagram: cfg.OnDatagram,
		peerMode: peerMode, onPeerData: cfg.OnPeerData, onPeerDatagram: cfg.OnPeerDatagram,
		ctx: ctx, cancel: cancel,
	}, nil
}

// Connect joins the room.
func (s *Session) Connect(ctx context.Context) error {
	conn, err := s.join(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return ErrNotConnected
	}
	s.conn, s.connected = conn, true
	s.mu.Unlock()
	go s.read(conn)
	return nil
}

func (s *Session) join(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("interop-pipe: dial hub: %w", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.SetWriteBuffer(SendHighWater); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("interop-pipe: send buffer: %w", err)
		}
	}
	join := KindJoin
	if s.peerMode {
		join = KindJoinPeers
	}
	if err := WriteFrame(conn, join, []byte(s.room)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("interop-pipe: join: %w", err)
	}
	return conn, nil
}

func (s *Session) read(conn net.Conn) {
	br := bufio.NewReaderSize(conn, MaxPayload+5)
	bridge := newBridge()
	for {
		kind, payload, err := ReadFrame(br)
		if err != nil {
			break
		}
		if isMessage(kind) && !bridge.open() {
			continue
		}
		switch kind {
		case KindData:
			if s.onData != nil {
				s.onData(payload)
			}
		case KindDgram:
			if s.onDatagram != nil {
				s.onDatagram(payload)
			}
		case KindSelf:
			s.mu.Lock()
			s.self = string(payload)
			s.mu.Unlock()
		case KindDataFrom:
			// A server routes by the sender (OnPeerData); a client reads
			// what any peer sent (OnData), as on a carrier.
			if from, msg, ok := SplitAddressed(payload); ok {
				switch {
				case s.onPeerData != nil:
					s.onPeerData(from, msg)
				case s.onData != nil:
					s.onData(msg)
				}
			}
		case KindDgramFrom:
			if from, msg, ok := SplitAddressed(payload); ok {
				switch {
				case s.onPeerDatagram != nil:
					s.onPeerDatagram(from, msg)
				case s.onDatagram != nil:
					s.onDatagram(msg)
				}
			}
		case KindPeers:
			if len(payload) == 2 && binary.BigEndian.Uint16(payload) > 0 {
				s.mu.Lock()
				s.seen = true
				s.mu.Unlock()
				bridge.start()
			}
		case KindEnd:
			s.mu.Lock()
			ended := s.ended
			if s.conn == conn {
				s.conn, s.connected = nil, false
			}
			s.mu.Unlock()
			_ = conn.Close()
			if ended != nil {
				ended(string(payload))
			}
			return
		}
	}
	s.lost(conn)
}

// isMessage is a kind that carries a participant's message.
func isMessage(kind byte) bool {
	switch kind {
	case KindData, KindDgram, KindDataFrom, KindDgramFrom:
		return true
	}
	return false
}

// bridgeDelayEnv is what testhooks.BeforeBridgeOpen reads.
const bridgeDelayEnv = "OLCRTC_TEST_BRIDGE_DELAY"

// bridge is one join's bridge: open at once, or, in a test build started
// with a positive OLCRTC_TEST_BRIDGE_DELAY, once BeforeBridgeOpen returns
// after another participant came.
type bridge struct {
	late   bool
	once   sync.Once
	opened chan struct{}
}

func newBridge() *bridge {
	b := &bridge{opened: make(chan struct{})}
	d, err := time.ParseDuration(os.Getenv(bridgeDelayEnv))
	b.late = testhooks.Enabled && err == nil && d > 0
	if !b.late {
		close(b.opened)
	}
	return b
}

// start is the session-initiate: the bridge opens BeforeBridgeOpen later.
func (b *bridge) start() {
	if !b.late {
		return
	}
	b.once.Do(func() {
		go func() {
			testhooks.BeforeBridgeOpen()
			close(b.opened)
		}()
	})
}

func (b *bridge) open() bool {
	select {
	case <-b.opened:
		return true
	default:
		return false
	}
}

// lost rejoins after the hub connection went away, then tells the upper
// layer, as an SFU engine does after an ICE restart.
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
	if should != nil && !should() {
		return
	}
	logger.Infof("interop-pipe: hub connection lost, rejoining room")
	delay := rejoinBackoff
	for s.ctx.Err() == nil {
		next, err := s.join(s.ctx)
		if err == nil {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				_ = next.Close()
				return
			}
			s.conn, s.connected = next, true
			s.mu.Unlock()
			go s.read(next)
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

// send sends a reliable (KindData) or lossy (KindDgram) message to the room,
// or to the peer confirmed in peer mode, as a carrier's client sends to the
// peer its welcome named.
func (s *Session) send(kind byte, data []byte) error {
	s.mu.Lock()
	target := s.target
	s.mu.Unlock()
	if target != "" {
		return s.sendTo(kind, target, data)
	}
	return s.write(kind, data)
}

// sendTo sends a reliable or lossy message to one participant (peer mode).
func (s *Session) sendTo(kind byte, peerID string, data []byte) error {
	to := KindDataTo
	if kind == KindDgram {
		to = KindDgramTo
	}
	return s.write(to, Addressed(peerID, data))
}

func (s *Session) write(kind byte, payload []byte) error {
	s.mu.Lock()
	conn, ok := s.conn, s.connected && !s.closed
	s.mu.Unlock()
	if !ok {
		return ErrNotConnected
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return WriteFrame(conn, kind, payload)
}

// Send sends one reliable message to the room.
func (s *Session) Send(data []byte) error { return s.send(KindData, data) }

// SendDatagram sends one lossy message to the room.
func (s *Session) SendDatagram(data []byte) error { return s.send(KindDgram, data) }

// DatagramCanSend reports whether the room is joined.
func (s *Session) DatagramCanSend() bool { return s.CanSend() }

// Close leaves the room for good.
func (s *Session) Close() error {
	s.mu.Lock()
	conn := s.conn
	s.closed, s.connected, s.conn = true, false, nil
	s.mu.Unlock()
	s.cancel()
	if conn != nil {
		_ = conn.Close()
	}
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

// CanSend reports whether the room is joined.
func (s *Session) CanSend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected && !s.closed
}

// SubscriberCanSend implements engine.Session.
func (s *Session) SubscriberCanSend() bool { return s.CanSend() }

// GetBufferedAmount implements engine.Session: writes go straight to TCP.
func (s *Session) GetBufferedAmount() uint64 { return 0 }

// Reconnect drops the hub connection; the read loop rejoins.
func (s *Session) Reconnect(reason string) {
	logger.Infof("interop-pipe: reconnect requested: %s", reason)
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// PeerSeen implements transport.PeerObserver: another participant has been
// in the room since this session was made.
func (s *Session) PeerSeen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen
}

// Peers is a participant in peer mode (PeersName): a Session with the peer
// interfaces a carrier's engine has. The base Session has none of them, so a
// server on Name stays on its single-session path.
type Peers struct{ *Session }

var (
	_ engine.PeerSession         = (*Peers)(nil)
	_ engine.PeerDatagramSession = (*Peers)(nil)
	_ engine.PeerIdentity        = (*Peers)(nil)
	_ engine.PeerResetter        = (*Peers)(nil)
)

// SendTo sends one reliable message to one participant.
func (p *Peers) SendTo(peerID string, data []byte) error {
	return p.sendTo(KindData, peerID, data)
}

// SendDatagramTo sends one lossy message to one participant.
func (p *Peers) SendDatagramTo(peerID string, data []byte) error {
	return p.sendTo(KindDgram, peerID, data)
}

// LocalPeerID is the hub's id for the connection there is; a rejoin gets a
// new one. Empty until the hub has said it.
func (p *Peers) LocalPeerID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.self
}

// ConfirmPeer makes peerID the participant every later Send goes to.
func (p *Peers) ConfirmPeer(peerID string) error {
	p.mu.Lock()
	p.target = peerID
	p.mu.Unlock()
	return nil
}

// ResetPeer forgets the confirmed participant: Send goes to the room again.
func (p *Peers) ResetPeer() {
	p.mu.Lock()
	p.target = ""
	p.mu.Unlock()
}

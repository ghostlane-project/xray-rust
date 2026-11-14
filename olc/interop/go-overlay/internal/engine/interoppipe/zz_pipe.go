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
// The Rust side (olc-client's pipe module) speaks the same frames.

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
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

// Name is the engine's name in a config (engine: { name: interop-pipe }).
const Name = "interop-pipe"

// The frame kinds.
const (
	KindJoin  byte = 1
	KindData  byte = 2
	KindDgram byte = 3
	KindPeers byte = 4
	KindEnd   byte = 5
)

// MaxPayload bounds one frame's payload: four times the datachannel's 12 KiB
// message, so no message a transport sends is refused.
const MaxPayload = 64 << 10

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

// Register adds the engine to the engine registry.
func Register() { engine.Register(Name, New) }

// Session is one participant: engine.Session, DatagramSession and the
// transport's PeerObserver.
type Session struct {
	addr, room string
	onData     func([]byte)
	onDatagram func([]byte)

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

	wmu sync.Mutex // one frame at a time on conn
}

var (
	_ engine.Session         = (*Session)(nil)
	_ engine.DatagramSession = (*Session)(nil)
)

// New is the engine's factory: cfg.URL is tcp://host:port/room.
func New(_ context.Context, cfg engine.Config) (engine.Session, error) {
	addr, room, err := ParseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		addr: addr, room: room, onData: cfg.OnData, onDatagram: cfg.OnDatagram,
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
	if err := WriteFrame(conn, KindJoin, []byte(s.room)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("interop-pipe: join: %w", err)
	}
	return conn, nil
}

func (s *Session) read(conn net.Conn) {
	br := bufio.NewReaderSize(conn, MaxPayload+5)
	for {
		kind, payload, err := ReadFrame(br)
		if err != nil {
			break
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
		case KindPeers:
			if len(payload) == 2 && binary.BigEndian.Uint16(payload) > 0 {
				s.mu.Lock()
				s.seen = true
				s.mu.Unlock()
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

func (s *Session) send(kind byte, data []byte) error {
	s.mu.Lock()
	conn, ok := s.conn, s.connected && !s.closed
	s.mu.Unlock()
	if !ok {
		return ErrNotConnected
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return WriteFrame(conn, kind, data)
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

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the hub the
// interop-pipe engine joins, a meeting room relay with the faults a real one
// has, on demand. See zz_pipe.go for the frames.

package interoppipe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Chaos is what the hub does to the traffic it relays. The reliable lane
// keeps its order and loses nothing, as a data channel does: it is delayed,
// jittered in order, held to a rate and, now and then, delivered twice
// (the record layer's replay window must drop the copy). The lossy lane is
// lost, reordered and duplicated.
type Chaos struct {
	Delay   time.Duration // one-way, reliable and lossy alike
	Jitter  time.Duration // up to this much more, the reliable lane in order
	RateBps int64         // each participant's inbound rate, bits/s; 0 none
	DupData float64       // a reliable message delivered twice
	// The lossy lane.
	LossDgram    float64
	ReorderDgram float64
	DupDgram     float64
	Seed         int64
}

// ErrUnknownProfile is a chaos profile the hub does not know.
var ErrUnknownProfile = errors.New("interop-pipe: unknown chaos profile")

// Profile is a named chaos: "" or "clean" for none, "chaos" for the gate's
// faults (40 ms each way plus up to 20 ms of jitter, 20 Mbit/s into each
// participant, 1% of reliable messages twice; 5% of datagrams lost, 5%
// reordered, 2% twice).
func Profile(name string) (Chaos, error) {
	switch name {
	case "", "clean":
		return Chaos{}, nil
	case "chaos":
		return Chaos{
			Delay: 40 * time.Millisecond, Jitter: 20 * time.Millisecond, RateBps: 20_000_000, DupData: 0.01,
			LossDgram: 0.05, ReorderDgram: 0.05, DupDgram: 0.02, Seed: 1,
		}, nil
	}
	return Chaos{}, fmt.Errorf("%w: %q (clean or chaos)", ErrUnknownProfile, name)
}

// memberQueue bounds a participant's outbound queue in frames: a full queue
// holds the sender back on the reliable lane and drops on the lossy one.
const memberQueue = 256

// Hub relays frames between the participants of each room.
type Hub struct {
	ln    net.Listener
	chaos Chaos

	mu      sync.Mutex
	rooms   map[string]map[*member]struct{}
	black   map[string]bool
	rng     *rand.Rand
	closed  bool
	members sync.WaitGroup
}

type member struct {
	hub  *Hub
	conn net.Conn
	room string
	out  chan frame
	done chan struct{}
	once sync.Once
	last time.Time // when the last reliable frame is due; the writer's
	held *frame    // a datagram held back to be reordered; the writer's
}

type frame struct {
	kind    byte
	payload []byte
	at      time.Time
}

// StartHub listens on addr (127.0.0.1:0 for any port).
func StartHub(addr string, chaos Chaos) (*Hub, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("interop-pipe hub: %w", err)
	}
	h := &Hub{
		ln: ln, chaos: chaos, rooms: map[string]map[*member]struct{}{}, black: map[string]bool{},
		rng: rand.New(rand.NewSource(chaos.Seed)), //nolint:gosec // faults, not secrets
	}
	go h.accept()
	return h, nil
}

// URL is the engine URL of a room on this hub.
func (h *Hub) URL(room string) string { return "tcp://" + h.ln.Addr().String() + "/" + room }

// Close stops the hub and drops every participant.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	var all []*member
	for _, room := range h.rooms {
		for m := range room {
			all = append(all, m)
		}
	}
	h.mu.Unlock()
	_ = h.ln.Close()
	for _, m := range all {
		m.stop()
	}
	h.members.Wait()
}

// Members is how many participants a room holds.
func (h *Hub) Members(room string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.rooms[room])
}

// Blackhole makes a room silently drop every frame (on) or relay again (off):
// the link stays up and nothing arrives, a dead path only liveness sees.
func (h *Hub) Blackhole(room string, on bool) {
	h.mu.Lock()
	h.black[room] = on
	h.mu.Unlock()
}

// Cut drops every participant's connection to a room; their engines rejoin.
func (h *Hub) Cut(room string) {
	for _, m := range h.snapshot(room, nil) {
		m.stop()
	}
}

// End tells every participant of a room that the conference ended.
func (h *Hub) End(room, reason string) {
	for _, m := range h.snapshot(room, nil) {
		m.enqueue(frame{kind: KindEnd, payload: []byte(reason), at: time.Now()}, true)
	}
}

func (h *Hub) accept() {
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.members.Add(1)
		go h.serve(conn)
	}
}

func (h *Hub) snapshot(room string, except *member) []*member {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*member, 0, len(h.rooms[room]))
	for m := range h.rooms[room] {
		if m != except {
			out = append(out, m)
		}
	}
	return out
}

func (h *Hub) serve(conn net.Conn) {
	defer h.members.Done()
	br := bufio.NewReaderSize(conn, MaxPayload+5)
	kind, payload, err := ReadFrame(br)
	if err != nil || kind != KindJoin || len(payload) == 0 {
		_ = conn.Close()
		return
	}
	m := &member{hub: h, conn: conn, room: string(payload), out: make(chan frame, memberQueue), done: make(chan struct{})}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = conn.Close()
		return
	}
	if h.rooms[m.room] == nil {
		h.rooms[m.room] = map[*member]struct{}{}
	}
	h.rooms[m.room][m] = struct{}{}
	h.mu.Unlock()
	go m.write()
	h.announce(m.room)
	for {
		kind, payload, err := ReadFrame(br)
		if err != nil {
			break
		}
		if kind == KindData || kind == KindDgram {
			h.relay(m, kind, payload)
		}
	}
	m.stop()
	h.mu.Lock()
	delete(h.rooms[m.room], m)
	h.mu.Unlock()
	h.announce(m.room)
}

// announce tells each participant of a room how many others it holds.
func (h *Hub) announce(room string) {
	members := h.snapshot(room, nil)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(max(len(members)-1, 0))) //nolint:gosec // a handful
	for _, m := range members {
		m.enqueue(frame{kind: KindPeers, payload: n[:], at: time.Now()}, true)
	}
}

// relay hands a frame to the room's other participants under the chaos.
func (h *Hub) relay(from *member, kind byte, payload []byte) {
	h.mu.Lock()
	if h.black[from.room] {
		h.mu.Unlock()
		return
	}
	c := h.chaos
	draw := func() float64 { return h.rng.Float64() }
	lost := kind == KindDgram && draw() < c.LossDgram
	dup := (kind == KindData && draw() < c.DupData) || (kind == KindDgram && draw() < c.DupDgram)
	var jitter time.Duration
	if c.Jitter > 0 {
		jitter = time.Duration(h.rng.Int63n(int64(c.Jitter)))
	}
	reorder := kind == KindDgram && draw() < c.ReorderDgram
	h.mu.Unlock()
	if lost {
		return
	}
	at := time.Now().Add(c.Delay + jitter)
	for _, m := range h.snapshot(from.room, from) {
		f := frame{kind: kind, payload: payload, at: at}
		if reorder {
			f.kind = kindHeld
		}
		m.enqueue(f, kind == KindData)
		if dup {
			m.enqueue(frame{kind: kind, payload: payload, at: at}, kind == KindData)
		}
	}
}

// kindHeld marks a datagram the writer holds back and sends after the next.
const kindHeld byte = 0x80 | KindDgram

// enqueue queues a frame for the participant: waiting for room when reliable,
// dropping it when the queue is full otherwise.
func (m *member) enqueue(f frame, reliable bool) {
	if reliable {
		select {
		case m.out <- f:
		case <-m.done:
		}
		return
	}
	select {
	case m.out <- f:
	default:
	}
}

func (m *member) stop() {
	m.once.Do(func() {
		close(m.done)
		_ = m.conn.Close()
	})
}

// write delivers the participant's frames: each no sooner than it is due,
// the reliable ones in order, all within the rate.
func (m *member) write() {
	c := m.hub.chaos
	var budget time.Time // when the rate allows the next byte
	for {
		var f frame
		select {
		case f = <-m.out:
		case <-m.done:
			return
		}
		if f.kind == KindData && f.at.Before(m.last) {
			f.at = m.last
		}
		if f.kind == KindData {
			m.last = f.at
		}
		if f.kind == kindHeld {
			if m.held == nil {
				f.kind = KindDgram
				m.held = &f
				continue
			}
			f.kind = KindDgram
		}
		if wait := time.Until(f.at); wait > 0 {
			select {
			case <-time.After(wait):
			case <-m.done:
				return
			}
		}
		if c.RateBps > 0 {
			now := time.Now()
			if budget.Before(now) {
				budget = now
			}
			budget = budget.Add(time.Duration(int64(len(f.payload)+5) * 8 * int64(time.Second) / c.RateBps))
			if wait := time.Until(budget); wait > time.Millisecond {
				select {
				case <-time.After(wait):
				case <-m.done:
					return
				}
			}
		}
		if WriteFrame(m.conn, f.kind, f.payload) != nil {
			m.stop()
			return
		}
		if f.kind == KindEnd {
			m.stop()
			return
		}
		if m.held != nil && f.kind == KindDgram {
			held := m.held
			m.held = nil
			if WriteFrame(m.conn, held.kind, held.payload) != nil {
				m.stop()
				return
			}
		}
	}
}

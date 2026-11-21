// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): a fake Jitsi Meet
// deployment for the Rust port's T2, in two halves. This file is the XMPP
// half, Prosody and Jicofo as a client sees them: /config.js and
// /xmpp-websocket (an anonymous login, stream management, the MUC, the focus
// and the services IQs, the caps disco, the session-initiate when a second
// occupant is in the room). zz_bridge.go is the bridge half: one pion peer
// per participant as the JVB. zz_bosh.go serves the same XMPP over BOSH
// (/http-bind) to a client whose WebSocket was refused.
//
// Two listeners serve the same handlers: TLS for the Go engine (it only dials
// https and wss; the hub's certificate is in the file SSL_CERT_FILE names from
// Start on) and plain HTTP for the Rust client (its test hooks config_base and
// ws_url). Every client stanza and the headers of both requests are recorded.
// No Jitsi deployment is contacted.

package jitsifake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
)

const (
	// Domain and MUC are what config.js names, as docker-jitsi-meet's do.
	Domain = "meet.jitsi"
	MUC    = "muc.meet.jitsi"
)

// Handshake is the request line's path and the headers of what a client
// asked for.
type Handshake struct {
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
}

// ChannelInfo is a data channel a client opened on the bridge.
type ChannelInfo struct {
	Nick     string `json:"nick"`
	Label    string `json:"label"`
	Protocol string `json:"protocol"`
	Ordered  bool   `json:"ordered"`
}

// State is what a room saw.
type State struct {
	Joins       int
	Leaves      int
	Transcripts [][]string
	Config      []Handshake
	Upgrades    []Handshake
	// Initiates is the session-initiates sent; Accepts the session-accepts
	// taken; Trickles the transport-infos taken.
	Initiates, Accepts, Trickles int
	Channels                     []ChannelInfo
	// Hellos is the ClientHellos answered.
	Hellos int
	// Relayed counts what the bridge forwarded; Dropped what did not fit a
	// receiver's window.
	Relayed, Dropped int
	// Classes counts the colibriClass of every bridge message.
	Classes map[string]int
	// Video is the RTP packets the bridge read, by participant's nick.
	Video map[string]int
	// BridgesClosed counts CloseBridges' peers.
	BridgesClosed int
	// Stanzas counts every stanza a client sent, by its first word.
	Stanzas map[string]int
	// Initiated and Accepted are the session-initiate sent to a nick and the
	// session-accept it answered with (the whole IQ, the latest of each).
	Initiated, Accepted map[string]string
}

// Hub is the fake's servers.
type Hub struct {
	plain, tlsLn net.Listener
	srv          *http.Server
	udp          net.PacketConn
	api          *webrtc.API
	cert         tls.Certificate

	mu       sync.Mutex
	rooms    map[string]*Room
	fixed    []string
	jids     int
	sw       switches
	roomSeq  int
	sessions int
	// bosh is every BOSH session there was (zz_bosh.go), boshSeq their count.
	bosh    []*boshSession
	boshSeq int
}

type switches struct {
	refuseWS, refuseFocus, noDeflate, turn bool
	// refusePlainWS refuses the upgrade on the plain listener alone; bosh
	// makes config.js name /http-bind; holdPlain and holdTLS cap how long a
	// BOSH request is held on each listener (zz_bosh.go).
	refusePlainWS, bosh bool
	holdPlain, holdTLS  time.Duration
}

var (
	certOnce sync.Once
	certPair tls.Certificate
	certErr  error
)

// trust makes the process's x509 roots the hub's certificate and nothing
// else, once: Go reads SSL_CERT_FILE when it first needs the system roots.
func trust() (tls.Certificate, error) {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			certErr = err
			return
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "jitsifake"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
			BasicConstraintsValid: true, IsCA: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			certErr = err
			return
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		dir, err := os.MkdirTemp("", "jitsifake-ca")
		if err != nil {
			certErr = err
			return
		}
		file := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(file, pemBytes, 0o600); err != nil {
			certErr = err
			return
		}
		if err := os.Setenv("SSL_CERT_FILE", file); err != nil {
			certErr = err
			return
		}
		certPair = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return certPair, certErr
}

// Start starts the hub on two loopback ports.
func Start() (*Hub, error) {
	cert, err := trust()
	if err != nil {
		return nil, fmt.Errorf("jitsifake: certificate: %w", err)
	}
	plain, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = plain.Close()
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = plain.Close()
		_ = raw.Close()
		return nil, err
	}
	h := &Hub{
		plain: plain, tlsLn: tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}),
		udp: udp, cert: cert, rooms: make(map[string]*Room),
	}
	h.api = newAPI(udp)
	mux := http.NewServeMux()
	mux.HandleFunc("/config.js", h.serveConfig)
	mux.HandleFunc("/xmpp-websocket", h.serveWS)
	mux.HandleFunc(boshPath, h.serveBOSH)
	h.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = h.srv.Serve(h.plain) }()
	go func() { _ = h.srv.Serve(h.tlsLn) }()
	return h, nil
}

// Close ends every room and the listeners.
func (h *Hub) Close() {
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.mu.Unlock()
	for _, r := range rooms {
		r.closeAll()
	}
	_ = h.srv.Close()
	_ = h.udp.Close()
}

// Host is what a Go client names as the Jitsi host: the TLS listener.
func (h *Hub) Host() string { return h.tlsLn.Addr().String() }

// Base is the plain HTTP origin (the Rust client's config_base).
func (h *Hub) Base() string { return "http://" + h.plain.Addr().String() }

// WSURL is the plain WebSocket URL (the Rust client's ws_url).
func (h *Hub) WSURL() string { return "ws://" + h.plain.Addr().String() + "/xmpp-websocket" }

// FixJID makes the next connection's bound JID user part `user` (at least 8
// characters: its first 8 are the client's nick); fixed JIDs are used in the
// order given, then the counter's.
func (h *Hub) FixJID(user string) {
	h.mu.Lock()
	h.fixed = append(h.fixed, user)
	h.mu.Unlock()
}

// RefuseWebSocket turns the upgrade away (the BOSH run's case).
func (h *Hub) RefuseWebSocket(on bool) { h.setSwitch(func(s *switches) { s.refuseWS = on }) }

// RefuseFocus makes the focus IQ fail (a reconnect-limit run's case).
func (h *Hub) RefuseFocus(on bool) { h.setSwitch(func(s *switches) { s.refuseFocus = on }) }

// NoDeflate stops the fake from taking permessage-deflate.
func (h *Hub) NoDeflate(on bool) { h.setSwitch(func(s *switches) { s.noDeflate = on }) }

// Turn makes the services IQ carry a turn and a stun service.
func (h *Hub) Turn(on bool) { h.setSwitch(func(s *switches) { s.turn = on }) }

func (h *Hub) setSwitch(f func(*switches)) {
	h.mu.Lock()
	f(&h.sw)
	h.mu.Unlock()
}

func (h *Hub) switches() switches {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sw
}

// EachRoom calls f with every room of the hub and what it saw, by name.
func (h *Hub) EachRoom(f func(name string, st State)) {
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.mu.Unlock()
	for _, r := range rooms {
		f(r.name, r.State())
	}
}

// StallAll stops the bridge from handing frames to every client of every room
// while on (see Room.Stall).
func (h *Hub) StallAll(on bool) {
	h.EachRoom(func(name string, _ State) { h.room(name).Stall("", on) })
}

// Named is the room called name: the one a test knows the name of.
func (h *Hub) Named(name string) *Room { return h.room(name) }

// Open makes a room with a name of its own.
func (h *Hub) Open() *Room {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return h.room("olc" + hex.EncodeToString(b[:]))
}

func (h *Hub) room(name string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.rooms[name]
	if !ok {
		r = &Room{hub: h, name: name, state: State{Classes: map[string]int{}, Video: map[string]int{}, Stanzas: map[string]int{},
			Initiated: map[string]string{}, Accepted: map[string]string{}}}
		h.rooms[name] = r
	}
	return r
}

func (h *Hub) nextUser() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.fixed) > 0 {
		u := h.fixed[0]
		h.fixed = h.fixed[1:]
		return u
	}
	h.jids++
	return fmt.Sprintf("%08x%08x", h.jids, 0x5a5a5a5a)
}

func (h *Hub) serveConfig(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	// config.js is the deployment's, not a room's: the first room that is
	// open collects the handshake (a test opens one room per hub).
	var rooms []*Room
	for _, room := range h.rooms {
		rooms = append(rooms, room)
	}
	h.mu.Unlock()
	hs := Handshake{Path: r.URL.RequestURI(), Header: r.Header.Clone()}
	for _, room := range rooms {
		room.mu.Lock()
		room.state.Config = append(room.state.Config, hs)
		room.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = fmt.Fprintf(w, "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = '%s';\nconfig.hosts.muc = '%s';\n", Domain, MUC)
	if h.switches().bosh {
		// The BOSH URL of the listener that was asked: https for the Go
		// engine, plain http for the Rust client's test origin.
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		_, _ = fmt.Fprintf(w, "config.bosh = '%s://%s%s';\n", scheme, r.Host, boshPath)
	}
}

// Room is one conference: its occupants, its sessions, what it saw.
type Room struct {
	hub  *Hub
	name string

	mu      sync.Mutex
	members []*conn
	state   State
	sids    int
	sidn    map[string]int // sessions offered, by nick
}

// Name is the room's name.
func (r *Room) Name() string { return r.name }

// State is what the room saw so far.
func (r *Room) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.state
	s.Transcripts = make([][]string, len(r.state.Transcripts))
	for i, t := range r.state.Transcripts {
		s.Transcripts[i] = append([]string(nil), t...)
	}
	s.Config = append([]Handshake(nil), r.state.Config...)
	s.Upgrades = append([]Handshake(nil), r.state.Upgrades...)
	s.Channels = append([]ChannelInfo(nil), r.state.Channels...)
	s.Classes, s.Video, s.Stanzas = copyMap(r.state.Classes), copyMap(r.state.Video), copyMap(r.state.Stanzas)
	s.Initiated, s.Accepted = copyStrings(r.state.Initiated), copyStrings(r.state.Accepted)
	return s
}

func copyMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyStrings(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Occupants is the nicks of the members, in join order.
func (r *Room) Occupants() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.members))
	for _, c := range r.members {
		out = append(out, c.nick)
	}
	return out
}

func (r *Room) closeAll() {
	r.mu.Lock()
	members := append([]*conn(nil), r.members...)
	r.mu.Unlock()
	for _, c := range members {
		c.closeSession()
		c.hangUp()
	}
}

func (r *Room) jid() string { return r.name + "@" + MUC }

// conn is one client's XMPP connection: over a WebSocket (ws) or over BOSH
// (bosh, zz_bosh.go). A BOSH client names its room only in its focus request:
// until then room is nil and what it said waits in early.
type conn struct {
	hub   *Hub
	room  *Room
	ws    *websocket.Conn
	bosh  *boshSession
	ctx   context.Context
	idx   int
	early []string

	user, nick, full string
	authed, joined   bool
	rcvd             atomic.Int64

	smu  sync.Mutex
	sess *session
}

func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("room")
	sw := h.switches()
	if name == "" || sw.refuseWS || (sw.refusePlainWS && r.TLS == nil) {
		http.Error(w, "no websocket", http.StatusForbidden)
		return
	}
	room := h.room(name)
	mode := websocket.CompressionContextTakeover
	if sw.noDeflate {
		mode = websocket.CompressionDisabled
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"xmpp"}, OriginPatterns: []string{"*"}, CompressionMode: mode,
	})
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 20)
	hs := Handshake{Path: r.URL.RequestURI(), Header: r.Header.Clone()}
	room.mu.Lock()
	room.state.Upgrades = append(room.state.Upgrades, hs)
	room.state.Transcripts = append(room.state.Transcripts, nil)
	idx := len(room.state.Transcripts) - 1
	room.mu.Unlock()
	c := &conn{hub: h, room: room, ws: ws, ctx: r.Context(), idx: idx, user: h.nextUser()}
	c.loop()
}

func (c *conn) say(s string) {
	if c.bosh != nil {
		c.bosh.push(s)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.ws.Write(ctx, websocket.MessageText, []byte(s))
}

const mucUser = "<x xmlns='http://jabber.org/protocol/muc#user'>"

func (c *conn) loop() {
	defer c.gone()
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			return
		}
		if !c.heard(string(data)) {
			return
		}
	}
}

// heard records one stanza of the client and answers it; false ends the
// connection.
func (c *conn) heard(t string) bool {
	if c.room == nil {
		name := boshRoom(t)
		if name == "" {
			c.early = append(c.early, t)
			return c.handle(t)
		}
		// The focus request names the room: the session is that room's from
		// here on, with what it said before.
		room := c.hub.room(name)
		room.mu.Lock()
		room.state.Transcripts = append(room.state.Transcripts, nil)
		c.idx = len(room.state.Transcripts) - 1
		room.mu.Unlock()
		c.room = room
		if c.bosh != nil {
			c.bosh.mu.Lock()
			c.bosh.st.Room = name
			c.bosh.mu.Unlock()
		}
		for _, e := range c.early {
			c.record(e)
		}
		c.early = nil
	}
	c.record(t)
	return c.handle(t)
}

func (c *conn) record(t string) {
	c.room.mu.Lock()
	c.room.state.Transcripts[c.idx] = append(c.room.state.Transcripts[c.idx], t)
	first, _, _ := strings.Cut(strings.TrimPrefix(t, "<"), " ")
	c.room.state.Stanzas[strings.TrimSuffix(first, "/>")]++
	c.room.mu.Unlock()
}

// hangUp ends the client's transport from the server's side.
func (c *conn) hangUp() {
	if c.bosh != nil {
		c.bosh.end(false)
		return
	}
	_ = c.ws.Close(websocket.StatusGoingAway, "")
}

// attr is the value of the first name attribute in s, in either quote.
func attr(s, name string) string {
	for _, q := range []string{`"`, `'`} {
		key := " " + name + "=" + q
		i := strings.Index(s, key)
		if i < 0 {
			continue
		}
		i += len(key)
		if end := strings.Index(s[i:], q); end >= 0 {
			return s[i : i+end]
		}
	}
	return ""
}

// head is the root element's opening tag of a stanza.
func head(s string) string {
	if i := strings.Index(s, ">"); i >= 0 {
		return s[:i]
	}
	return s
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "'", "&apos;", `"`, "&quot;").Replace(s)
}

// handle answers one client frame; false ends the connection.
func (c *conn) handle(t string) bool {
	sw := c.hub.switches()
	switch {
	case strings.HasPrefix(t, "<open "):
		if attr(head(t), "to") != Domain {
			c.say("<stream:error xmlns:stream='http://etherx.jabber.org/streams'><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text>This server does not serve that</text></stream:error>")
			return false
		}
		c.say("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='" + Domain + "' version='1.0'/>")
		if !c.authed {
			c.say("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>")
		} else {
			c.say("<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/><sm xmlns='urn:xmpp:sm:3'/></stream:features>")
		}
	case strings.HasPrefix(t, "<auth "):
		c.authed = true
		c.say("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
	case strings.HasPrefix(t, "<enable "):
		c.say("<enabled xmlns='urn:xmpp:sm:3' id='" + c.user + "' resume='true'/>")
	case strings.HasPrefix(t, "<r ") || strings.HasPrefix(t, "<r/"):
		c.say(fmt.Sprintf("<a xmlns='urn:xmpp:sm:3' h='%d'/>", c.rcvd.Load()))
	case strings.HasPrefix(t, "<a "):
	case strings.HasPrefix(t, "<iq"):
		c.rcvd.Add(1)
		c.iq(t, sw)
	case strings.HasPrefix(t, "<presence"):
		c.rcvd.Add(1)
		c.presence(t)
	default:
		c.rcvd.Add(1)
	}
	return true
}

func (c *conn) iq(t string, sw switches) {
	id, typ, to := attr(head(t), "id"), attr(head(t), "type"), attr(head(t), "to")
	result := func(body string) {
		c.say(fmt.Sprintf("<iq id='%s' type='result' from='%s' to='%s' xmlns='jabber:client'>%s</iq>", esc(id), esc(orElse(to, Domain)), esc(c.full), body))
	}
	switch {
	case typ == "result" || typ == "error":
		// What the client answered to a get of ours (the caps disco).
	case strings.Contains(t, "bind_1"):
		c.full = c.user + "@" + Domain + "/" + c.user[:min(8, len(c.user))] + "res"
		c.say("<iq type='result' id='bind_1' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>" + c.full + "</jid></bind></iq>")
	case strings.Contains(t, "sess_1"):
		c.say("<iq type='result' id='sess_1' xmlns='jabber:client'/>")
	case strings.Contains(t, "focus_1"):
		if sw.refuseFocus {
			c.say("<iq id='focus_1' type='error' xmlns='jabber:client'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
			return
		}
		c.say("<iq id='focus_1' type='result' from='focus." + Domain + "' xmlns='jabber:client'><conference xmlns='http://jitsi.org/protocol/focus' ready='true'><property name='authentication' value='false'/><property name='externalAuth' value='false'/></conference></iq>")
	case strings.Contains(t, "disco_1"):
		services := ""
		if sw.turn {
			services = "<service type='turn' host='127.0.0.1' port='3478' transport='udp' username='u' password='p'/><service type='stun' host='127.0.0.1' port='3478'/>"
		}
		c.say("<iq id='disco_1' type='result' xmlns='jabber:client'><services xmlns='urn:xmpp:extdisco:2'>" + services + "</services></iq>")
	case typ == "get" && strings.Contains(t, "disco#info") && c.room != nil:
		result("<query xmlns='http://jabber.org/protocol/disco#info'><identity category='conference' type='text' name='" + c.room.name + "'/><feature var='http://jabber.org/protocol/muc'/></query>")
	case typ == "get":
		result("") // the XMPP ping and whatever else
	case typ == "set" && strings.Contains(t, "<jingle") && c.room != nil:
		result("")
		c.jingle(t)
	case typ == "set":
		result("")
	}
}

func orElse(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (c *conn) presence(t string) {
	h := head(t)
	to := attr(h, "to")
	if c.room == nil || !strings.HasPrefix(to, c.room.jid()+"/") {
		return
	}
	nick := strings.TrimPrefix(to, c.room.jid()+"/")
	if attr(h, "type") == "unavailable" {
		c.leave(true)
		return
	}
	c.join(nick)
}

func presenceOf(from string, extra string, typ string) string {
	t := ""
	if typ != "" {
		t = " type='" + typ + "'"
	}
	return "<presence from='" + from + "'" + t + " xmlns='jabber:client'>" + mucUser + extra + "</x></presence>"
}

func (c *conn) join(nick string) {
	r := c.room
	r.mu.Lock()
	if c.joined {
		r.mu.Unlock()
		return
	}
	c.nick, c.joined = nick, true
	others := append([]*conn(nil), r.members...)
	r.members = append(r.members, c)
	r.state.Joins++
	n := len(r.members)
	r.mu.Unlock()

	c.say(presenceOf(r.jid()+"/focus", "<item affiliation='owner' role='moderator' jid='focus@auth."+Domain+"/focus'/>", ""))
	for _, o := range others {
		c.say(presenceOf(r.jid()+"/"+o.nick, "<item affiliation='none' role='participant'/>", ""))
		o.say(presenceOf(r.jid()+"/"+nick, "<item affiliation='none' role='participant'/>", ""))
	}
	c.say(presenceOf(r.jid()+"/"+nick, "<item affiliation='none' role='participant'/><status code='110'/>", ""))
	// Jicofo's caps query comes a moment after the join, as the client's own
	// room disco goes out on seeing its presence: a transcript in one order.
	time.AfterFunc(300*time.Millisecond, func() {
		c.say(fmt.Sprintf("<iq from='%s/focus' to='%s' id='disco-%d' type='get' xmlns='jabber:client'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>", r.jid(), c.full, n))
	})
	if n >= 2 {
		r.startSessions()
	}
}

// leave takes the client out of the MUC; echo says the leave to it too.
func (c *conn) leave(echo bool) {
	r := c.room
	if r == nil {
		return
	}
	r.mu.Lock()
	if !c.joined {
		r.mu.Unlock()
		return
	}
	c.joined = false
	for i, m := range r.members {
		if m == c {
			r.members = append(r.members[:i], r.members[i+1:]...)
			break
		}
	}
	r.state.Leaves++
	rest := append([]*conn(nil), r.members...)
	r.mu.Unlock()
	c.closeSession()
	if echo {
		c.say(presenceOf(r.jid()+"/"+c.nick, "<item affiliation='none' role='none'/><status code='110'/>", "unavailable"))
	}
	for _, o := range rest {
		o.say(presenceOf(r.jid()+"/"+c.nick, "<item affiliation='none' role='none'/>", "unavailable"))
	}
}

func (c *conn) gone() {
	c.leave(false)
	if c.ws != nil {
		_ = c.ws.CloseNow()
	}
}

// Login is what a client said from its first stanza to its room disco (the
// first ten frames), with what differs from one client to the next replaced:
// the room's name, the nick (the bound JID's first 8 characters), the user
// part of the JID and the display name. Two clients that log in the same way
// say the same Login; a Go client and a Rust one must.
func Login(said []string, room string) string {
	if len(said) > 10 {
		said = said[:10]
	}
	var nick, user, name string
	for _, t := range said {
		if strings.HasPrefix(t, "<presence ") {
			to := attr(head(t), "to")
			nick = to[strings.LastIndex(to, "/")+1:]
			if i := strings.Index(t, "<nick xmlns=\"http://jabber.org/protocol/nick\">"); i >= 0 {
				rest := t[i+len("<nick xmlns=\"http://jabber.org/protocol/nick\">"):]
				name, _, _ = strings.Cut(rest, "</nick>")
			}
		}
	}
	user = nick
	var out []string
	for _, t := range said {
		if name != "" {
			t = strings.ReplaceAll(t, name[:min(3, len(name))]+"-j", "<NAME3>-j")
			t = strings.ReplaceAll(t, ">"+name+"<", "><NAME><")
		}
		if user != "" {
			t = strings.ReplaceAll(t, user, "<NICK>")
		}
		out = append(out, strings.ReplaceAll(t, room, "<ROOM>"))
	}
	return strings.Join(out, "\n")
}

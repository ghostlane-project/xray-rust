// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the fake's BOSH half,
// /http-bind as Prosody's mod_bosh serves it (XEP-0124, XEP-0206). A client
// comes here when the WebSocket was refused (Hub.RefuseWebSocket,
// Hub.RefusePlainWebSocket) and config.js names it (Hub.BOSH). The XMPP above
// it is zz_room.go's, the same handlers as over the WebSocket.
//
// What it keeps of the protocol, because a client can get it wrong:
//
//   - one request is held at a time (hold 1): a second one releases the
//     older, and what the room says goes out on the oldest held request;
//   - a held request is answered empty after the wait the client asked for
//     (or the hub's cap, BOSHHold);
//   - request ids go up by one. A request one ahead of its turn waits for the
//     missing one, as Prosody's does; anything else ends the session;
//   - a session nobody polls for a minute is gone, and so is its occupant.
//
// Every request is recorded with its headers (BOSHSessions).

package jitsifake

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	boshPath = "/http-bind"
	boshNS   = "http://jabber.org/protocol/httpbind"
	// boshReadLimit is the most of a request body that is read.
	boshReadLimit = 1 << 20
	// boshInactivity is how long a session lives with no request held.
	boshInactivity = 60 * time.Second
	// boshAheadWait is how long a request one ahead of its turn waits for
	// the missing one.
	boshAheadWait = 10 * time.Second
)

// BOSHRequest is one POST of a client.
type BOSHRequest struct {
	RID    int64       `json:"rid"`
	Body   string      `json:"body"`
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
}

// BOSHState is what one BOSH session saw.
type BOSHState struct {
	SID string
	// Room is the room the session's client asked the focus for, once it did.
	Room string
	// Requests is every request of the session, as they arrived.
	Requests []BOSHRequest
	// OutOfOrder counts the requests that came one ahead of their turn.
	OutOfOrder int
	// Refused counts the requests whose id was neither next nor one ahead.
	Refused int
	// MaxInFlight is the most requests the session had open at once.
	MaxInFlight int
	// Terminated says the client ended the session itself.
	Terminated bool
	// Expired says nobody polled for boshInactivity.
	Expired bool
	// Dropped is how long each held request had waited when its client hung
	// up on it; Held how long each answered one had.
	Dropped, Held []time.Duration
}

type boshOut struct {
	text string
	// whole says text is a reply's whole body, not a stanza to wrap.
	whole bool
}

type boshHeld struct {
	ch    chan string
	since time.Time
}

type boshSession struct {
	hub  *Hub
	c    *conn
	sid  string
	wait time.Duration

	// pmu lets one request's stanzas through at a time, in the order of
	// their ids.
	pmu sync.Mutex

	mu       sync.Mutex
	rid      int64
	ahead    chan struct{} // closed when the request one ahead may go
	held     []*boshHeld
	out      []boshOut
	ended    bool
	inflight int
	idle     *time.Timer
	st       BOSHState
}

// BOSH makes config.js name the BOSH URL of the listener it is asked on.
func (h *Hub) BOSH(on bool) { h.setSwitch(func(s *switches) { s.bosh = on }) }

// RefusePlainWebSocket turns the upgrade away on the plain listener alone
// (the Rust client's), leaving the TLS one (a Go server's) served.
func (h *Hub) RefusePlainWebSocket(on bool) {
	h.setSwitch(func(s *switches) { s.refusePlainWS = on })
}

// BOSHHold caps how long a request is held on the plain and on the TLS
// listener; zero holds for the wait the client asked for, as Prosody does.
func (h *Hub) BOSHHold(plain, tls time.Duration) {
	h.setSwitch(func(s *switches) { s.holdPlain, s.holdTLS = plain, tls })
}

// BOSHSessions is what every BOSH session of the hub saw, oldest first.
func (h *Hub) BOSHSessions() []BOSHState {
	h.mu.Lock()
	sessions := append([]*boshSession(nil), h.bosh...)
	h.mu.Unlock()
	out := make([]BOSHState, 0, len(sessions))
	for _, s := range sessions {
		s.mu.Lock()
		st := s.st
		st.Requests = append([]BOSHRequest(nil), s.st.Requests...)
		st.Dropped = append([]time.Duration(nil), s.st.Dropped...)
		st.Held = append([]time.Duration(nil), s.st.Held...)
		s.mu.Unlock()
		out = append(out, st)
	}
	return out
}

// BOSHInject says text to the client of session sid on its next answer: as
// stanzas inside the answer's body, or, with whole, as the answer's whole
// body. It is the test's way to hand a client a reply of its own writing.
func (h *Hub) BOSHInject(sid, text string, whole bool) bool {
	s := h.boshSession(sid)
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return false
	}
	s.out = append(s.out, boshOut{text: text, whole: whole})
	s.flushLocked()
	return true
}

func (h *Hub) boshSession(sid string) *boshSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.bosh {
		if s.sid == sid {
			return s
		}
	}
	return nil
}

func boshWrite(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = io.WriteString(w, body)
}

func boshTerminate(condition string) string {
	if condition == "" {
		return "<body type='terminate' xmlns='" + boshNS + "'/>"
	}
	return "<body type='terminate' condition='" + condition + "' xmlns='" + boshNS + "'/>"
}

// boshInner is what stands between a request body's opening and closing tag.
func boshInner(body string) string {
	open := strings.Index(body, ">")
	if open < 1 || body[open-1] == '/' {
		return ""
	}
	end := strings.LastIndex(body, "</body>")
	if end <= open {
		return ""
	}
	return strings.TrimSpace(body[open+1 : end])
}

func (h *Hub) serveBOSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, boshReadLimit))
	if err != nil {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	body := string(raw)
	hd := head(body)
	if !strings.HasPrefix(hd, "<body") {
		http.Error(w, "not a body", http.StatusBadRequest)
		return
	}
	rid, err := strconv.ParseInt(attr(hd, "rid"), 10, 64)
	if err != nil {
		http.Error(w, "rid", http.StatusBadRequest)
		return
	}
	rec := BOSHRequest{RID: rid, Body: body, Path: r.URL.RequestURI(), Header: r.Header.Clone()}
	sid := attr(hd, "sid")
	if sid == "" {
		h.boshCreate(w, r, hd, rec)
		return
	}
	s := h.boshSession(sid)
	if s == nil {
		http.Error(w, boshTerminate("item-not-found"), http.StatusNotFound)
		return
	}
	s.serve(w, r, hd, rec)
}

// boshCreate answers a session request: the session, and the stream's
// features in the same body, as Prosody answers.
func (h *Hub) boshCreate(w http.ResponseWriter, r *http.Request, hd string, rec BOSHRequest) {
	if attr(hd, "to") != Domain {
		boshWrite(w, boshTerminate("host-unknown"))
		return
	}
	sw := h.switches()
	wait := 60 * time.Second
	if n, err := strconv.Atoi(attr(hd, "wait")); err == nil && n > 0 && n < 60 {
		wait = time.Duration(n) * time.Second
	}
	limit := sw.holdPlain
	if r.TLS != nil {
		limit = sw.holdTLS
	}
	if limit > 0 && limit < wait {
		wait = limit
	}
	c := &conn{hub: h, user: h.nextUser()}
	s := &boshSession{hub: h, c: c, wait: wait, rid: rec.RID}
	c.bosh = s
	h.mu.Lock()
	h.boshSeq++
	s.sid = fmt.Sprintf("bosh%08x", h.boshSeq)
	s.st.SID = s.sid
	s.st.Requests = append(s.st.Requests, rec)
	s.st.MaxInFlight = 1
	h.bosh = append(h.bosh, s)
	h.mu.Unlock()
	s.mu.Lock()
	s.idleLocked()
	s.mu.Unlock()
	boshWrite(w, fmt.Sprintf("<body xmlns='%s' xmlns:stream='http://etherx.jabber.org/streams' xmlns:xmpp='urn:xmpp:xbosh' sid='%s' wait='%d' requests='2' inactivity='%d' hold='1' polling='5' ver='1.6' xmpp:version='1.0' authid='%s' from='%s' secure='true'>"+
		"<stream:features xmlns='jabber:client'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features></body>",
		boshNS, s.sid, int(wait/time.Second), int(boshInactivity/time.Second), s.sid, Domain))
}

// turn waits for the request's turn by its id; false when it has none.
func (s *boshSession) turn(r *http.Request, rid int64) bool {
	s.mu.Lock()
	switch {
	case s.ended:
		s.mu.Unlock()
		return false
	case rid == s.rid+1:
		s.rid = rid
		s.mu.Unlock()
		return true
	case rid == s.rid+2 && s.ahead == nil:
		// One ahead: the missing one is on its way on another connection.
		s.st.OutOfOrder++
		ahead := make(chan struct{})
		s.ahead = ahead
		s.mu.Unlock()
		select {
		case <-ahead:
			return true
		case <-r.Context().Done():
		case <-time.After(boshAheadWait):
		}
		s.mu.Lock()
		if s.ahead == ahead {
			s.ahead = nil
		}
		s.mu.Unlock()
		return false
	default:
		s.st.Refused++
		s.mu.Unlock()
		return false
	}
}

func (s *boshSession) serve(w http.ResponseWriter, r *http.Request, hd string, rec BOSHRequest) {
	s.mu.Lock()
	s.st.Requests = append(s.st.Requests, rec)
	s.inflight++
	if s.inflight > s.st.MaxInFlight {
		s.st.MaxInFlight = s.inflight
	}
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inflight--
		s.idleLocked()
		s.mu.Unlock()
	}()

	if !s.turn(r, rec.RID) {
		s.end(true)
		http.Error(w, boshTerminate("item-not-found"), http.StatusNotFound)
		return
	}
	s.pmu.Lock()
	terminate := attr(hd, "type") == "terminate"
	s.mu.Lock()
	over := s.ended
	s.mu.Unlock()
	switch {
	case terminate || over:
	case attr(hd, "xmpp:restart") == "true":
		s.c.say("<stream:features xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></stream:features>")
	default:
		if inner := boshInner(rec.Body); inner != "" {
			s.c.heard(inner)
		}
	}
	// The request one ahead goes after this one's stanzas.
	s.mu.Lock()
	if s.ahead != nil {
		s.rid++
		close(s.ahead)
		s.ahead = nil
	}
	s.mu.Unlock()
	s.pmu.Unlock()
	if terminate {
		s.mu.Lock()
		s.st.Terminated = true
		s.mu.Unlock()
		s.end(true)
		boshWrite(w, boshTerminate(""))
		return
	}

	held := &boshHeld{ch: make(chan string, 1), since: time.Now()}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		boshWrite(w, boshTerminate(""))
		return
	}
	s.held = append(s.held, held)
	s.flushLocked()
	s.mu.Unlock()
	timer := time.NewTimer(s.wait)
	defer timer.Stop()
	select {
	case body := <-held.ch:
		s.note(held, false)
		boshWrite(w, body)
	case <-timer.C:
		body := s.unhold(held)
		s.note(held, false)
		boshWrite(w, body)
	case <-r.Context().Done():
		// The client hung up on a held request: what was already given to it
		// is lost with it, as it would be on the wire.
		_ = s.unhold(held)
		s.note(held, true)
	}
}

func (s *boshSession) note(h *boshHeld, dropped bool) {
	d := time.Since(h.since)
	s.mu.Lock()
	if dropped {
		s.st.Dropped = append(s.st.Dropped, d)
	} else {
		s.st.Held = append(s.st.Held, d)
	}
	s.mu.Unlock()
}

// unhold takes h out of the held requests and gives the body to answer it
// with: the one already put on it, or an empty one.
func (s *boshSession) unhold(h *boshHeld) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.held {
		if x == h {
			s.held = append(s.held[:i], s.held[i+1:]...)
			break
		}
	}
	select {
	case body := <-h.ch:
		return body
	default:
	}
	if s.ended {
		return boshTerminate("")
	}
	return s.wrap(nil)
}

func (s *boshSession) wrap(stanzas []string) string {
	open := "<body xmlns='" + boshNS + "' xmlns:stream='http://etherx.jabber.org/streams' sid='" + s.sid + "'"
	if len(stanzas) == 0 {
		return open + "/>"
	}
	return open + ">" + strings.Join(stanzas, "") + "</body>"
}

// flushLocked answers the oldest held request while there is something to
// say or more than one is held.
func (s *boshSession) flushLocked() {
	for len(s.held) > 0 && (len(s.out) > 0 || len(s.held) > 1) {
		h := s.held[0]
		s.held = s.held[1:]
		var body string
		if len(s.out) > 0 && s.out[0].whole {
			body = s.out[0].text
			s.out = s.out[1:]
		} else {
			var stanzas []string
			for len(s.out) > 0 && !s.out[0].whole {
				stanzas = append(stanzas, s.out[0].text)
				s.out = s.out[1:]
			}
			body = s.wrap(stanzas)
		}
		h.ch <- body
	}
}

// push queues a stanza for the client.
func (s *boshSession) push(stanza string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.out = append(s.out, boshOut{text: stanza})
	s.flushLocked()
}

// idleLocked starts the inactivity clock when nothing of the client's is
// open.
func (s *boshSession) idleLocked() {
	if s.ended || s.inflight > 0 || s.idle != nil {
		return
	}
	s.idle = time.AfterFunc(boshInactivity, func() {
		s.mu.Lock()
		expired := !s.ended && s.inflight == 0
		if expired {
			s.st.Expired = true
		}
		s.mu.Unlock()
		if expired {
			s.end(true)
		}
	})
}

// end closes the session: every held request is answered with a terminate,
// and, with gone, the occupant leaves the room.
func (s *boshSession) end(gone bool) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	held := s.held
	s.held, s.out = nil, nil
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
	if s.ahead != nil {
		close(s.ahead)
		s.ahead = nil
	}
	s.mu.Unlock()
	for _, h := range held {
		h.ch <- boshTerminate("")
	}
	if gone {
		s.c.gone()
	}
}

// boshRoom is the room a focus request names.
func boshRoom(stanza string) string {
	if !strings.Contains(stanza, "focus_1") {
		return ""
	}
	room, _, _ := strings.Cut(attr(stanza, "room"), "@")
	return room
}

// BOSHLogin is what a client said over BOSH from its first stanza to its room
// disco (seven: no stream open and no stream management there), normalised as
// Login does.
func BOSHLogin(said []string, room string) string {
	if len(said) > 7 {
		said = said[:7]
	}
	return Login(said, room)
}

// BOSHBodies is the session's request bodies with what differs from one run
// to the next replaced (the request id by RID, the session id by SID), in the
// order of their ids, and whether those ids go up by one from the first.
func BOSHBodies(st BOSHState) (bodies []string, consecutive bool) {
	reqs := append([]BOSHRequest(nil), st.Requests...)
	sort.SliceStable(reqs, func(i, j int) bool { return reqs[i].RID < reqs[j].RID })
	consecutive = true
	for i, r := range reqs {
		if i > 0 && r.RID != reqs[i-1].RID+1 {
			consecutive = false
		}
		b := strings.Replace(r.Body, fmt.Sprintf(`rid="%d"`, r.RID), `rid="RID"`, 1)
		if st.SID != "" {
			b = strings.Replace(b, `sid="`+st.SID+`"`, `sid="SID"`, 1)
		}
		bodies = append(bodies, b)
	}
	return bodies, consecutive
}

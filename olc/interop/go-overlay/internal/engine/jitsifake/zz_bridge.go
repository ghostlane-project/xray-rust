// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the bridge half of the
// fake Jitsi room. One pion peer per participant plays the JVB for it: its
// offer (audio and video with a source each, a data section) goes out as the
// session-initiate, the client's session-accept and transport-info come back
// as an answer and candidates; the client's "JVB data channel" is answered
// (ClientHello with ServerHello) and its EndpointMessages are relayed by
// endpoint id (to empty: everyone else) with the sender in from, ordered, up
// to a window per receiver, and what does not fit is dropped (the engine's
// relayModel, internal/engine/jitsi/relaywindow_test.go). The keepalive RTP is
// read and counted. No media is forwarded between participants.

package jitsifake

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

// Window is the bytes the bridge holds for one receiver (about 2 MB).
const Window = 2 << 20

// channelLabel is the data channel the engine opens on the bridge.
const channelLabel = "JVB data channel"

func newAPI(udp net.PacketConn) *webrtc.API {
	var se webrtc.SettingEngine
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	se.SetIncludeLoopbackCandidate(true)
	se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	se.SetICEUDPMux(webrtc.NewICEUDPMux(nil, udp))
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		panic(err)
	}
	return webrtc.NewAPI(webrtc.WithSettingEngine(se), webrtc.WithMediaEngine(m))
}

// session is the bridge's peer of one participant.
type session struct {
	c     *conn
	pc    *webrtc.PeerConnection
	sid   string
	mids  []string // the offer's mids, in m-line order
	names []string // what the Jingle contents call them

	mu       sync.Mutex
	dc       *webrtc.DataChannel
	accepted bool
	early    []webrtc.ICECandidateInit
	closed   bool

	queue   chan []byte
	pending atomic.Int64
	stalled atomic.Bool
}

// startSessions offers a bridge to every member without one.
func (r *Room) startSessions() {
	r.mu.Lock()
	var todo []*conn
	for _, c := range r.members {
		c.smu.Lock()
		if c.sess == nil {
			c.sess = &session{c: c, queue: make(chan []byte, 8192)}
			todo = append(todo, c)
		}
		c.smu.Unlock()
	}
	r.mu.Unlock()
	for _, c := range todo {
		go c.sess.offer()
	}
}

func (c *conn) closeSession() {
	c.smu.Lock()
	s := c.sess
	c.sess = nil
	c.smu.Unlock()
	if s != nil {
		s.close()
	}
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	pc := s.pc
	s.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (s *session) offer() {
	r := s.c.room
	pc, err := s.c.hub.api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = pc.Close()
		return
	}
	s.pc = pc
	s.mu.Unlock()
	at, _ := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "jvb-a0", "jvb")
	vt, _ := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, "jvb-v0", "jvb")
	for _, tr := range []*webrtc.TrackLocalStaticRTP{at, vt} {
		if _, err := pc.AddTrack(tr); err != nil {
			return
		}
	}
	ordered, negotiated, id := true, true, uint16(1001)
	if _, err := pc.CreateDataChannel("bridge-side", &webrtc.DataChannelInit{Ordered: &ordered, Negotiated: &negotiated, ID: &id}); err != nil {
		return
	}
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			if _, _, err := tr.ReadRTP(); err != nil {
				return
			}
			r.mu.Lock()
			r.state.Video[s.c.nick]++
			r.mu.Unlock()
		}
	})
	pc.OnDataChannel(s.onChannel)
	off, err := pc.CreateOffer(nil)
	if err != nil {
		return
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(off); err != nil {
		return
	}
	select {
	case <-gathered:
	case <-time.After(5 * time.Second):
	}
	sdp := pc.LocalDescription().SDP
	body, mids := sdpToJingle(sdp)
	s.mids = mids
	s.names = contentNames(mids)
	body = renameContents(body, mids, s.names)
	r.mu.Lock()
	if r.sidn == nil {
		r.sidn = map[string]int{}
	}
	r.sidn[s.c.nick]++
	s.sid = fmt.Sprintf("sid-%s-%s-%d", r.name, s.c.nick, r.sidn[s.c.nick])
	r.state.Initiates++
	r.mu.Unlock()
	stanza := fmt.Sprintf("<iq from='%s/focus' to='%s' id='si-%s' type='set' xmlns='jabber:client'>"+
		"<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' initiator='%s/focus' sid='%s'>%s</jingle></iq>",
		r.jid(), s.c.full, s.sid, r.jid(), s.sid, body)
	r.mu.Lock()
	r.state.Initiated[s.c.nick] = stanza
	r.mu.Unlock()
	s.c.say(stanza)
}

func contentNames(mids []string) []string {
	out := make([]string, len(mids))
	for i := range mids {
		switch i {
		case 0:
			out[i] = "audio"
		case 1:
			out[i] = "video"
		default:
			out[i] = "data"
		}
	}
	return out
}

func renameContents(body string, mids, names []string) string {
	for i := range mids {
		body = strings.ReplaceAll(body, `name="`+mids[i]+`"`, `name="`+names[i]+`"`)
	}
	return body
}

func (s *session) onChannel(dc *webrtc.DataChannel) {
	r := s.c.room
	r.mu.Lock()
	r.state.Channels = append(r.state.Channels, ChannelInfo{Nick: s.c.nick, Label: dc.Label(), Protocol: dc.Protocol(), Ordered: dc.Ordered()})
	r.mu.Unlock()
	if dc.Label() != channelLabel {
		return
	}
	dc.OnMessage(func(m webrtc.DataChannelMessage) { s.onMessage(dc, m.Data) })
	dc.OnOpen(func() { s.ready(dc) })
	if dc.ReadyState() == webrtc.DataChannelStateOpen {
		s.ready(dc)
	}
}

func (s *session) ready(dc *webrtc.DataChannel) {
	s.mu.Lock()
	if s.dc != nil || s.closed {
		s.mu.Unlock()
		return
	}
	s.dc = dc
	s.mu.Unlock()
	go func() {
		for b := range s.queue {
			for s.stalled.Load() && !s.isClosed() {
				time.Sleep(10 * time.Millisecond)
			}
			if s.isClosed() {
				return
			}
			_ = dc.SendText(string(b))
			s.pending.Add(-int64(len(b)))
		}
	}()
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) onMessage(dc *webrtc.DataChannel, data []byte) {
	r := s.c.room
	var m map[string]json.RawMessage
	class := "?"
	if json.Unmarshal(data, &m) == nil {
		_ = json.Unmarshal(m["colibriClass"], &class)
	}
	r.mu.Lock()
	r.state.Classes[class]++
	if class == "ClientHello" {
		r.state.Hellos++
	}
	r.mu.Unlock()
	switch class {
	case "ClientHello":
		_ = dc.SendText(`{"colibriClass":"ServerHello"}`)
	case "EndpointMessage":
		to := ""
		_ = json.Unmarshal(m["to"], &to)
		from, _ := json.Marshal(s.c.nick)
		m["from"] = from
		out, err := json.Marshal(m)
		if err != nil {
			return
		}
		r.relay(s, to, out)
	}
}

// relay hands out to the receivers `to` names (everyone but from when empty),
// each in its order, or drops it for a receiver whose window it does not fit.
func (r *Room) relay(from *session, to string, out []byte) {
	r.mu.Lock()
	var targets []*session
	for _, c := range r.members {
		c.smu.Lock()
		o := c.sess
		c.smu.Unlock()
		if o == nil || o == from || (to != "" && c.nick != to) {
			continue
		}
		o.mu.Lock()
		up := o.dc != nil
		o.mu.Unlock()
		if up {
			targets = append(targets, o)
		}
	}
	r.mu.Unlock()
	for _, o := range targets {
		if o.pending.Load()+int64(len(out)) > Window {
			r.mu.Lock()
			r.state.Dropped++
			r.mu.Unlock()
			continue
		}
		o.pending.Add(int64(len(out)))
		select {
		case o.queue <- out:
			r.mu.Lock()
			r.state.Relayed++
			r.mu.Unlock()
		default:
			o.pending.Add(-int64(len(out)))
			r.mu.Lock()
			r.state.Dropped++
			r.mu.Unlock()
		}
	}
}

// CloseBridges closes every participant's peer connection, as a bridge that
// went away does; the clients are left in the MUC.
func (r *Room) CloseBridges() {
	r.mu.Lock()
	members := append([]*conn(nil), r.members...)
	r.mu.Unlock()
	for _, c := range members {
		c.smu.Lock()
		s := c.sess
		c.smu.Unlock()
		if s != nil {
			s.close()
			r.mu.Lock()
			r.state.BridgesClosed++
			r.mu.Unlock()
		}
	}
}

// Stall stops the bridge from handing frames to nick's client (every client
// when nick is empty) while on; the window fills and then drops.
func (r *Room) Stall(nick string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.members {
		if nick != "" && c.nick != nick {
			continue
		}
		c.smu.Lock()
		if c.sess != nil {
			c.sess.stalled.Store(on)
		}
		c.smu.Unlock()
	}
}

// ---- what the client says about its session ----

type xjingle struct {
	Action   string     `xml:"action,attr"`
	SID      string     `xml:"sid,attr"`
	Contents []xcontent `xml:"content"`
}

type xcontent struct {
	Name        string      `xml:"name,attr"`
	Senders     string      `xml:"senders,attr"`
	Description *xdescr     `xml:"description"`
	Transport   *xtransport `xml:"transport"`
}

type xdescr struct {
	Media    string     `xml:"media,attr"`
	Payloads []xpayload `xml:"payload-type"`
	HdrExts  []xhdrext  `xml:"rtp-hdrext"`
	Mux      *struct{}  `xml:"rtcp-mux"`
	Sources  []xsource  `xml:"source"`
	Groups   []xgroup   `xml:"ssrc-group"`
}

type xpayload struct {
	ID        string   `xml:"id,attr"`
	Name      string   `xml:"name,attr"`
	Clockrate string   `xml:"clockrate,attr"`
	Channels  string   `xml:"channels,attr"`
	Params    []xparam `xml:"parameter"`
	FB        []xfb    `xml:"rtcp-fb"`
}

type xparam struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type xfb struct {
	Type    string `xml:"type,attr"`
	Subtype string `xml:"subtype,attr"`
}

type xhdrext struct {
	ID  string `xml:"id,attr"`
	URI string `xml:"uri,attr"`
}

type xsource struct {
	SSRC   string   `xml:"ssrc,attr"`
	Params []xparam `xml:"parameter"`
}

type xgroup struct {
	Semantics string `xml:"semantics,attr"`
	Sources   []struct {
		SSRC string `xml:"ssrc,attr"`
	} `xml:"source"`
}

type xtransport struct {
	Ufrag       string  `xml:"ufrag,attr"`
	Pwd         string  `xml:"pwd,attr"`
	Candidates  []xcand `xml:"candidate"`
	Fingerprint *struct {
		Hash  string `xml:"hash,attr"`
		Setup string `xml:"setup,attr"`
		Value string `xml:",chardata"`
	} `xml:"fingerprint"`
}

type xcand struct {
	Component  string `xml:"component,attr"`
	Foundation string `xml:"foundation,attr"`
	Generation string `xml:"generation,attr"`
	IP         string `xml:"ip,attr"`
	Port       string `xml:"port,attr"`
	Priority   string `xml:"priority,attr"`
	Protocol   string `xml:"protocol,attr"`
	Type       string `xml:"type,attr"`
	RelAddr    string `xml:"rel-addr,attr"`
	RelPort    string `xml:"rel-port,attr"`
}

func (x xcand) line() string {
	l := fmt.Sprintf("%s %s %s %s %s %s typ %s", x.Foundation, orElse(x.Component, "1"), strings.ToLower(orElse(x.Protocol, "udp")),
		orElse(x.Priority, "1"), x.IP, x.Port, orElse(x.Type, "host"))
	if x.RelAddr != "" {
		l += " raddr " + x.RelAddr + " rport " + x.RelPort
	}
	return l
}

// jingle takes a client's Jingle IQ (already acknowledged).
func (c *conn) jingle(t string) {
	i := strings.Index(t, "<jingle")
	if i < 0 {
		return
	}
	end := strings.LastIndex(t, "</jingle>")
	if end < 0 {
		return
	}
	var j xjingle
	if err := xml.Unmarshal([]byte(t[i:end+len("</jingle>")]), &j); err != nil {
		return
	}
	c.smu.Lock()
	s := c.sess
	c.smu.Unlock()
	if s == nil || (j.SID != "" && s.sid != "" && j.SID != s.sid) {
		return
	}
	r := c.room
	switch j.Action {
	case "session-accept":
		r.mu.Lock()
		r.state.Accepts++
		r.state.Accepted[c.nick] = t
		r.mu.Unlock()
		go s.accept(j)
	case "transport-info":
		r.mu.Lock()
		r.state.Trickles++
		r.mu.Unlock()
		s.trickle(j)
	case "session-terminate":
		c.closeSession()
	}
}

func (s *session) accept(j xjingle) {
	answer := acceptToSDP(j, s.mids, s.names)
	s.mu.Lock()
	pc := s.pc
	closed := s.closed
	s.mu.Unlock()
	if pc == nil || closed {
		return
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		s.c.room.mu.Lock()
		s.c.room.state.Classes["answer-refused: "+err.Error()]++
		s.c.room.mu.Unlock()
		return
	}
	s.mu.Lock()
	s.accepted = true
	early := s.early
	s.early = nil
	s.mu.Unlock()
	for _, c := range early {
		_ = pc.AddICECandidate(c)
	}
}

func (s *session) trickle(j xjingle) {
	for _, ct := range j.Contents {
		idx := 0
		for i, n := range s.names {
			if n == ct.Name {
				idx = i
			}
		}
		if ct.Transport == nil || len(s.mids) == 0 {
			continue
		}
		for _, cand := range ct.Transport.Candidates {
			if cand.IP == "" || cand.Port == "" {
				continue
			}
			mid, i16 := s.mids[idx], uint16(idx)
			init := webrtc.ICECandidateInit{Candidate: "candidate:" + cand.line(), SDPMid: &mid, SDPMLineIndex: &i16}
			s.mu.Lock()
			if !s.accepted {
				s.early = append(s.early, init)
				s.mu.Unlock()
				continue
			}
			pc := s.pc
			s.mu.Unlock()
			_ = pc.AddICECandidate(init)
		}
	}
}

// ---- SDP <-> Jingle ----

// section is one m-line block of an SDP.
type section struct {
	kind  string // audio, video, application
	ids   []string
	lines []string
}

func splitSDP(sdp string) (session []string, sections []section) {
	var cur *section
	for _, l := range strings.Split(strings.ReplaceAll(sdp, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "m=") {
			f := strings.Fields(l[2:])
			sections = append(sections, section{kind: f[0], ids: f[3:]})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			session = append(session, l)
		} else {
			cur.lines = append(cur.lines, l)
		}
	}
	return session, sections
}

func attrOf(lines []string, key string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, "a="+key+":") {
			return strings.TrimPrefix(l, "a="+key+":")
		}
	}
	return ""
}

func flag(lines []string, key string) bool {
	for _, l := range lines {
		if l == "a="+key {
			return true
		}
	}
	return false
}

func q(s string) string { return esc(s) }

// sdpToJingle writes an offer as the contents of a session-initiate, and
// returns the m-lines' mids.
func sdpToJingle(sdp string) (string, []string) {
	sess, secs := splitSDP(sdp)
	var b strings.Builder
	var mids []string
	for _, s := range secs {
		mids = append(mids, attrOf(s.lines, "mid"))
	}
	b.WriteString(`<group xmlns="urn:xmpp:jingle:apps:grouping:0" semantics="BUNDLE">`)
	for _, m := range mids {
		fmt.Fprintf(&b, `<content name="%s"/>`, q(m))
	}
	b.WriteString("</group>")
	for i, s := range secs {
		lines := s.lines
		senders := "both"
		switch {
		case flag(lines, "sendonly"):
			senders = "initiator"
		case flag(lines, "recvonly"):
			senders = "responder"
		case flag(lines, "inactive"):
			senders = "none"
		}
		fmt.Fprintf(&b, `<content creator="initiator" name="%s" senders="%s">`, q(mids[i]), senders)
		if s.kind != "application" {
			fmt.Fprintf(&b, `<description xmlns="urn:xmpp:jingle:apps:rtp:1" media="%s">`, s.kind)
			for _, id := range s.ids {
				name, clock, ch := "", "", ""
				for _, l := range lines {
					if strings.HasPrefix(l, "a=rtpmap:"+id+" ") {
						f := strings.Split(strings.TrimPrefix(l, "a=rtpmap:"+id+" "), "/")
						name = f[0]
						if len(f) > 1 {
							clock = f[1]
						}
						if len(f) > 2 {
							ch = f[2]
						}
					}
				}
				fmt.Fprintf(&b, `<payload-type id="%s" name="%s" clockrate="%s"`, id, q(name), clock)
				if ch != "" {
					fmt.Fprintf(&b, ` channels="%s"`, ch)
				}
				b.WriteString(">")
				if fm := attrOf(filterPrefix(lines, "a=fmtp:"+id+" "), "fmtp"); fm != "" {
					for _, p := range strings.Split(strings.TrimPrefix(fm, id+" "), ";") {
						n, v, ok := strings.Cut(strings.TrimSpace(p), "=")
						if ok {
							fmt.Fprintf(&b, `<parameter name="%s" value="%s"/>`, q(n), q(v))
						}
					}
				}
				for _, l := range lines {
					if strings.HasPrefix(l, "a=rtcp-fb:"+id+" ") {
						f := strings.Fields(strings.TrimPrefix(l, "a=rtcp-fb:"+id+" "))
						sub := ""
						if len(f) > 1 {
							sub = ` subtype="` + q(f[1]) + `"`
						}
						fmt.Fprintf(&b, `<rtcp-fb xmlns="urn:xmpp:jingle:apps:rtp:rtcp-fb:0" type="%s"%s/>`, q(f[0]), sub)
					}
				}
				b.WriteString("</payload-type>")
			}
			// pion writes its header extensions in map order: by id, so the
			// offer is the same text every time.
			var exts [][2]string
			for _, l := range lines {
				if strings.HasPrefix(l, "a=extmap:") {
					f := strings.Fields(strings.TrimPrefix(l, "a=extmap:"))
					if len(f) >= 2 {
						id, _, _ := strings.Cut(f[0], "/")
						exts = append(exts, [2]string{id, f[1]})
					}
				}
			}
			sort.SliceStable(exts, func(i, j int) bool {
				a, _ := strconv.Atoi(exts[i][0])
				c, _ := strconv.Atoi(exts[j][0])
				return a < c
			})
			for _, e := range exts {
				fmt.Fprintf(&b, `<rtp-hdrext xmlns="urn:xmpp:jingle:apps:rtp:rtp-hdrext:0" id="%s" uri="%s"/>`, e[0], q(e[1]))
			}
			if flag(lines, "rtcp-mux") {
				b.WriteString("<rtcp-mux/>")
			}
			var order []string
			params := map[string][]string{}
			for _, l := range lines {
				if strings.HasPrefix(l, "a=ssrc:") {
					f := strings.SplitN(strings.TrimPrefix(l, "a=ssrc:"), " ", 2)
					if len(f) < 2 {
						continue
					}
					if _, ok := params[f[0]]; !ok {
						order = append(order, f[0])
					}
					n, v, _ := strings.Cut(f[1], ":")
					params[f[0]] = append(params[f[0]], fmt.Sprintf(`<parameter name="%s" value="%s"/>`, q(n), q(v)))
				}
			}
			for _, ssrc := range order {
				fmt.Fprintf(&b, `<source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="%s">%s</source>`, ssrc, strings.Join(params[ssrc], ""))
			}
			for _, l := range lines {
				if strings.HasPrefix(l, "a=ssrc-group:") {
					f := strings.Fields(strings.TrimPrefix(l, "a=ssrc-group:"))
					fmt.Fprintf(&b, `<ssrc-group xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" semantics="%s">`, q(f[0]))
					for _, ssrc := range f[1:] {
						fmt.Fprintf(&b, `<source ssrc="%s"/>`, ssrc)
					}
					b.WriteString("</ssrc-group>")
				}
			}
			b.WriteString("</description>")
		}
		ufrag, pwd := attrOf(lines, "ice-ufrag"), attrOf(lines, "ice-pwd")
		fp, setup := attrOf(lines, "fingerprint"), attrOf(lines, "setup")
		for _, l := range sess {
			if ufrag == "" && strings.HasPrefix(l, "a=ice-ufrag:") {
				ufrag = strings.TrimPrefix(l, "a=ice-ufrag:")
			}
			if pwd == "" && strings.HasPrefix(l, "a=ice-pwd:") {
				pwd = strings.TrimPrefix(l, "a=ice-pwd:")
			}
			if fp == "" && strings.HasPrefix(l, "a=fingerprint:") {
				fp = strings.TrimPrefix(l, "a=fingerprint:")
			}
			if setup == "" && strings.HasPrefix(l, "a=setup:") {
				setup = strings.TrimPrefix(l, "a=setup:")
			}
		}
		fmt.Fprintf(&b, `<transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="%s" pwd="%s">`, q(ufrag), q(pwd))
		if hv, val, ok := strings.Cut(fp, " "); ok {
			fmt.Fprintf(&b, `<fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="%s" setup="%s" required="false">%s</fingerprint>`, q(hv), orElse(setup, "actpass"), q(val))
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "a=candidate:") {
				f := strings.Fields(strings.TrimPrefix(l, "a=candidate:"))
				if len(f) < 8 || f[1] != "1" {
					continue
				}
				fmt.Fprintf(&b, `<candidate component="%s" foundation="%s" generation="0" id="%s" ip="%s" network="0" port="%s" priority="%s" protocol="%s" type="%s"/>`,
					f[1], f[0], f[0]+f[1], f[4], f[5], f[3], strings.ToLower(f[2]), f[7])
			}
		}
		if s.kind == "application" {
			b.WriteString(`<sctpmap xmlns="urn:xmpp:jingle:transports:dtls-sctp:1" number="5000" protocol="webrtc-datachannel" streams="1024"/>`)
		}
		b.WriteString("</transport></content>")
	}
	return b.String(), mids
}

func filterPrefix(lines []string, prefix string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			out = append(out, "a=fmtp:"+strings.TrimPrefix(l, "a=fmtp:"))
		}
	}
	return out
}

// acceptToSDP writes the client's session-accept as the answer to the offer
// whose m-lines carry mids (named names in the Jingle).
func acceptToSDP(j xjingle, mids, names []string) string {
	var b strings.Builder
	b.WriteString("v=0\r\no=- 0 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n")
	fmt.Fprintf(&b, "a=group:BUNDLE %s\r\na=msid-semantic: WMS *\r\n", strings.Join(mids, " "))
	for i, mid := range mids {
		var c *xcontent
		for k := range j.Contents {
			if j.Contents[k].Name == names[i] {
				c = &j.Contents[k]
			}
		}
		if c == nil {
			continue
		}
		d := c.Description
		if d == nil || d.Media == "" {
			b.WriteString("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
		} else {
			ids := make([]string, 0, len(d.Payloads))
			for _, p := range d.Payloads {
				ids = append(ids, p.ID)
			}
			fmt.Fprintf(&b, "m=%s 9 UDP/TLS/RTP/SAVPF %s\r\n", d.Media, strings.Join(ids, " "))
		}
		b.WriteString("c=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n")
		fmt.Fprintf(&b, "a=mid:%s\r\n", mid)
		if d != nil && d.Media != "" {
			switch strings.ToLower(c.Senders) {
			case "initiator":
				b.WriteString("a=recvonly\r\n")
			case "responder":
				b.WriteString("a=sendonly\r\n")
			case "none":
				b.WriteString("a=inactive\r\n")
			default:
				b.WriteString("a=sendrecv\r\n")
			}
		}
		if t := c.Transport; t != nil {
			fmt.Fprintf(&b, "a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n", t.Ufrag, t.Pwd)
			if t.Fingerprint != nil {
				fmt.Fprintf(&b, "a=fingerprint:%s %s\r\na=setup:%s\r\n", t.Fingerprint.Hash, strings.TrimSpace(t.Fingerprint.Value), orElse(t.Fingerprint.Setup, "active"))
			}
			if i == 0 {
				for _, cand := range t.Candidates {
					if cand.IP != "" && cand.Port != "" {
						fmt.Fprintf(&b, "a=candidate:%s\r\n", cand.line())
					}
				}
			}
		}
		if d == nil || d.Media == "" {
			b.WriteString("a=sctp-port:5000\r\n")
			continue
		}
		if d.Mux != nil {
			b.WriteString("a=rtcp-mux\r\n")
		}
		for _, h := range d.HdrExts {
			fmt.Fprintf(&b, "a=extmap:%s %s\r\n", h.ID, h.URI)
		}
		for _, p := range d.Payloads {
			ch := ""
			if p.Channels != "" {
				ch = "/" + p.Channels
			}
			fmt.Fprintf(&b, "a=rtpmap:%s %s/%s%s\r\n", p.ID, p.Name, orElse(p.Clockrate, "90000"), ch)
			for _, fb := range p.FB {
				fmt.Fprintf(&b, "a=rtcp-fb:%s %s %s\r\n", p.ID, fb.Type, fb.Subtype)
			}
			if len(p.Params) > 0 {
				parts := make([]string, 0, len(p.Params))
				for _, pr := range p.Params {
					if pr.Name == "" {
						parts = append(parts, pr.Value)
					} else {
						parts = append(parts, pr.Name+"="+pr.Value)
					}
				}
				fmt.Fprintf(&b, "a=fmtp:%s %s\r\n", p.ID, strings.Join(parts, ";"))
			}
		}
		for _, g := range d.Groups {
			var ss []string
			for _, s := range g.Sources {
				ss = append(ss, s.SSRC)
			}
			fmt.Fprintf(&b, "a=ssrc-group:%s %s\r\n", g.Semantics, strings.Join(ss, " "))
		}
		for _, s := range d.Sources {
			for _, p := range s.Params {
				if p.Value == "" {
					fmt.Fprintf(&b, "a=ssrc:%s %s\r\n", s.SSRC, p.Name)
				} else {
					fmt.Fprintf(&b, "a=ssrc:%s %s:%s\r\n", s.SSRC, p.Name, p.Value)
				}
			}
		}
	}
	return b.String()
}

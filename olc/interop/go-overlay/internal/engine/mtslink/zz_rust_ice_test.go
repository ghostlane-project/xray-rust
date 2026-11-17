//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the Rust client's ICE
// modes against a fake SFU that, as the service does (mtslink.go:17-21),
// names every candidate twice: UDP and passive TCP. The engine's own fake
// (mtslink_test.go) offers UDP alone; rustICESFU is that fake with its join
// answered by a pion peer on one UDP mux and one TCP mux, both on loopback
// and both counted.
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test -tags olcrtc_interop ./internal/engine/mtslink -run '^TestRustMTSICE' -v
//
//   - TestRustMTSICEOverTCP: `ice` = tcp (the client's default for a link
//     without a hint). The client dials the passive candidate, the pair
//     pion selects is a TCP one, media goes both ways over it, and not one
//     UDP datagram reaches the SFU's UDP candidate, which was there to be
//     used;
//   - TestRustMTSICEOverBoth: `ice` = both. UDP datagrams and a TCP
//     connection both arrive; the join connects;
//   - TestRustMTSICEOverUDPBesideTCP: no `ice` (a Go engine on direct
//     credentials, K3). The pair is a UDP one and nothing dials the TCP
//     candidate: the two counters can tell the modes apart.
//
// TestServedICEFakeTakesTheGoEngine holds the fake to the Go engine in tcp
// mode, with no Rust client.

package mtslink

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// rustICELine is the engine's line for a mode other than UDP
// (mtslink.go:263), as the Rust session says it.
const rustICELine = "mtslink: ICE over %s, as the room link or this side asks"

// rustCountedConn counts the datagrams that arrive on a UDP socket.
type rustCountedConn struct {
	net.PacketConn
	in atomic.Int64
}

func (c *rustCountedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.in.Add(1)
	}
	return n, addr, err
}

// rustCountedListener counts the connections a TCP listener takes.
type rustCountedListener struct {
	net.Listener
	in atomic.Int64
}

func (l *rustCountedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.in.Add(1)
	}
	return conn, err
}

// rustICESFU is the engine's fake SFU with a join that offers UDP and
// passive TCP candidates.
type rustICESFU struct {
	*fakeSFU
	udp *rustCountedConn
	tcp *rustCountedListener
	se  webrtc.SettingEngine
	// answer is the last answer the fake gave.
	answer atomic.Value
}

func newRustICESFU(t *testing.T) *rustICESFU {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = udpConn.Close()
		t.Fatal(err)
	}
	s := &rustICESFU{udp: &rustCountedConn{PacketConn: udpConn}, tcp: &rustCountedListener{Listener: ln}}
	udpMux := webrtc.NewICEUDPMux(nil, s.udp)
	tcpMux := webrtc.NewICETCPMux(nil, s.tcp, 8)
	// Registered before the fake's own cleanup, so it runs after it: the
	// peer connections close first, then what they stand on.
	t.Cleanup(func() {
		_ = tcpMux.Close()
		_ = udpMux.Close()
		_ = ln.Close()
		_ = udpConn.Close()
	})
	s.se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeTCP4})
	s.se.SetIncludeLoopbackCandidate(true)
	s.se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	s.se.SetICEUDPMux(udpMux)
	s.se.SetICETCPMux(tcpMux)

	s.fakeSFU = newFakeSFU(t)
	s.srv.Close()
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/rtc/room/"+testSession+"/join" {
			body, _ := io.ReadAll(r.Body)
			s.join(w, r, string(body))
			return
		}
		s.serve(w, r)
	}))
	return s
}

// join is fakeSFU.join with the peer on the two muxes.
func (s *rustICESFU) join(w http.ResponseWriter, r *http.Request, offer string) {
	f := s.fakeSFU
	f.mu.Lock()
	f.joins++
	f.offer, f.joinQuery, f.joinHead = offer, r.URL.Query(), r.Header.Clone()
	f.mu.Unlock()

	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		f.t.Error(err)
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		f.t.Error(err)
	}
	pc, err := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(s.se)).
		NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.pcs = append(f.pcs, pc)
	f.mu.Unlock()
	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if track.Kind() != webrtc.RTPCodecTypeVideo {
			return
		}
		select {
		case f.publisher <- track:
		default:
		}
		for {
			pkt, _, readErr := track.ReadRTP()
			if readErr != nil {
				return
			}
			select {
			case f.published <- append([]byte(nil), pkt.Payload...):
			default:
			}
		}
	})
	if srdErr := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); srdErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "SDP validation error: "+srdErr.Error())
		return
	}
	for _, tr := range pc.GetTransceivers() {
		if tr.Kind() == webrtc.RTPCodecTypeVideo && tr.Direction() == webrtc.RTPTransceiverDirectionSendonly {
			sender, senderErr := webrtc.NewAPI(webrtc.WithMediaEngine(me)).NewRTPSender(f.toEngine, tr.Receiver().Transport())
			if senderErr == nil {
				_ = tr.SetSender(sender, f.toEngine)
			}
			break
		}
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if sldErr := pc.SetLocalDescription(answer); sldErr != nil {
		f.t.Error(sldErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	<-gathered
	sdp := strings.Replace(pc.LocalDescription().SDP, "\r\ns=-\r\n", "\r\ns="+testPeer+"\r\n", 1)
	s.answer.Store(sdp)
	w.Header().Set("Content-Type", "application/sdp")
	_, _ = io.WriteString(w, sdp)
}

// relay is the peer connection of the last join.
func (s *rustICESFU) relay() *webrtc.PeerConnection {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pcs[len(s.pcs)-1]
}

// namesBoth fails the test unless the fake's answer names a UDP candidate
// and a passive TCP one: the fake is what the tests take it for.
func (s *rustICESFU) namesBoth(t *testing.T) {
	t.Helper()
	sdp, _ := s.answer.Load().(string)
	var udp, passive int
	for _, line := range strings.Split(sdp, "\r\n") {
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		fields := strings.Fields(line)
		switch {
		case len(fields) > 2 && strings.EqualFold(fields[2], "udp"):
			udp++
		case strings.Contains(line, "tcptype passive"):
			passive++
		}
	}
	if udp == 0 || passive == 0 {
		t.Fatalf("the fake's answer names %d UDP and %d passive TCP candidates, want both", udp, passive)
	}
}

// rustPairProtocol waits for the pair pion selected on pc and returns the
// protocol of its local candidate.
func rustPairProtocol(t *testing.T, pc *webrtc.PeerConnection) webrtc.ICEProtocol {
	t.Helper()
	var proto webrtc.ICEProtocol
	within(t, 15*time.Second, "pion selecting a candidate pair", func() bool {
		for _, tr := range pc.GetTransceivers() {
			dtls := tr.Receiver().Transport()
			if dtls == nil || dtls.ICETransport() == nil {
				continue
			}
			pair, err := dtls.ICETransport().GetSelectedCandidatePair()
			if err != nil || pair == nil || pair.Local == nil {
				continue
			}
			proto = pair.Local.Protocol
			return true
		}
		return false
	})
	return proto
}

// rustICEConfig joins sfu with the engine's `ice` set to mode; none sets no
// `ice`, as a Go engine on direct credentials has none.
func rustICEConfig(sfu *rustICESFU, mode string) rustConfig {
	cfg := rustSFUConfig(sfu.fakeSFU)
	if mode != "" {
		cfg.EngineExtra["ice"] = mode
	}
	return cfg
}

// rustMediaBothWays waits for what the client publishes to reach the relay
// and for what the relay writes into a slot to reach the client's reader.
func rustMediaBothWays(t *testing.T, sfu *rustICESFU, p *rustProc, seen *rustPublished) {
	t.Helper()
	within(t, 10*time.Second, "a published packet reaching the relay", func() bool {
		packets, _, _ := seen.counts()
		return packets > 0
	})
	seq := uint16(1000)
	within(t, 10*time.Second, "the relay's video reaching the client", func() bool {
		seq++
		_ = sfu.toEngine.WriteRTP(&rtp.Packet{
			Header:  rtp.Header{Version: 2, PayloadType: 98, SequenceNumber: seq, Timestamp: 1},
			Payload: append([]byte{0x9f, 0x80, 0x01, 0x10, 0x01, 0x40, 0x00, 0xb4}, blackKeyframe...),
		})
		return p.logHas(rustRemoteTrack)
	})
	if _, _, notVP9 := seen.counts(); notVP9 != 0 {
		t.Errorf("%d published packets are not VP9", notVP9)
	}
}

// Over TCP alone: the client's default for a link that says nothing.
func TestRustMTSICEOverTCP(t *testing.T) {
	rustBin(t)
	sfu := newRustICESFU(t)
	seen := rustWatchPublished(t, sfu.fakeSFU)
	p := startRust(t, rustICEConfig(sfu, "tcp"))
	rustJoined(t, sfu.fakeSFU)
	sfu.namesBoth(t)

	if proto := rustPairProtocol(t, sfu.relay()); proto != webrtc.ICEProtocolTCP {
		t.Errorf("the selected pair is over %s, want tcp", proto)
	}
	rustMediaBothWays(t, sfu, p, seen)
	for _, line := range []string{
		strings.Replace(rustICELine, "%s", "tcp", 1), "peer connection state changed: connected",
	} {
		if !p.logHas(line) {
			t.Errorf("the client's log has no %q", line)
		}
	}
	if n := sfu.tcp.in.Load(); n < 1 {
		t.Errorf("%d TCP connections to the passive candidate", n)
	}

	// The whole run, its close included: not one datagram to the UDP
	// candidate the answer named.
	p.stop(t)
	if !p.logHas("peer connection state changed: closed") {
		t.Error("the client's log has no closed peer connection after its stop")
	}
	if n := sfu.udp.in.Load(); n != 0 {
		t.Errorf("%d UDP datagrams reached the SFU from a client over TCP alone", n)
	}
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	if sfu.joins != 1 || len(sfu.leaves) != 0 {
		t.Errorf("%d joins and leaves %q, want one join and nothing taken back", sfu.joins, sfu.leaves)
	}
}

// Over both: UDP candidates and the dialled TCP one together.
func TestRustMTSICEOverBoth(t *testing.T) {
	rustBin(t)
	sfu := newRustICESFU(t)
	seen := rustWatchPublished(t, sfu.fakeSFU)
	p := startRust(t, rustICEConfig(sfu, "both"))
	rustJoined(t, sfu.fakeSFU)
	sfu.namesBoth(t)

	proto := rustPairProtocol(t, sfu.relay())
	t.Logf("with both, pion selected a pair over %s", proto)
	rustMediaBothWays(t, sfu, p, seen)
	within(t, 10*time.Second, "a TCP connection to the passive candidate", func() bool {
		return sfu.tcp.in.Load() > 0
	})
	if n := sfu.udp.in.Load(); n == 0 {
		t.Error("no UDP datagram reached the SFU from a client over both")
	}
	for _, line := range []string{
		strings.Replace(rustICELine, "%s", "both", 1), "peer connection state changed: connected",
	} {
		if !p.logHas(line) {
			t.Errorf("the client's log has no %q", line)
		}
	}
	p.stop(t)
	if !p.logHas("peer connection state changed: closed") {
		t.Error("the client's log has no closed peer connection after its stop")
	}
}

// Over UDP, the mode of a Go engine on direct credentials (K3), in a room
// that offers TCP too: the control the other two are read against.
func TestRustMTSICEOverUDPBesideTCP(t *testing.T) {
	rustBin(t)
	sfu := newRustICESFU(t)
	seen := rustWatchPublished(t, sfu.fakeSFU)
	p := startRust(t, rustICEConfig(sfu, ""))
	rustJoined(t, sfu.fakeSFU)
	sfu.namesBoth(t)

	if proto := rustPairProtocol(t, sfu.relay()); proto != webrtc.ICEProtocolUDP {
		t.Errorf("the selected pair is over %s, want udp", proto)
	}
	rustMediaBothWays(t, sfu, p, seen)
	if n := sfu.udp.in.Load(); n == 0 {
		t.Error("no UDP datagram reached the SFU from a client over UDP")
	}
	p.stop(t)
	if n := sfu.tcp.in.Load(); n != 0 {
		t.Errorf("%d TCP connections from a client over UDP", n)
	}
	if p.logHas("mtslink: ICE over ") {
		t.Error("a client over UDP names an ICE mode; the Go engine says nothing for UDP")
	}
}

// The fake with the Go engine in it, over TCP alone: what the Rust client is
// read against.
func TestServedICEFakeTakesTheGoEngine(t *testing.T) {
	sfu := newRustICESFU(t)
	cfg := sfu.config()
	cfg.Extra["ice"] = "tcp"
	s, _ := newPublishingSession(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sfu.namesBoth(t)
	if proto := rustPairProtocol(t, sfu.relay()); proto != webrtc.ICEProtocolTCP {
		t.Errorf("the selected pair is over %s, want tcp", proto)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if n := sfu.udp.in.Load(); n != 0 {
		t.Errorf("%d UDP datagrams reached the SFU from a Go engine over TCP alone", n)
	}
	if n := sfu.tcp.in.Load(); n < 1 {
		t.Errorf("%d TCP connections to the passive candidate", n)
	}
}

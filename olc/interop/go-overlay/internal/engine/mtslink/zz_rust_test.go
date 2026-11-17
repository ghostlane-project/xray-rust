//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T2 for the MTS Link
// carrier, one guest's join. The engine's own fake SFU (mtslink_test.go: a
// real pion peer connection behind the join) with the Rust client
// (olc-client, engine mtslink on direct credentials, vp8channel) in it as a
// child process:
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test -tags olcrtc_interop ./internal/engine/mtslink -run '^TestRustMTS' -v
//
//   - TestRustMTSJoinsPublishesAndHearsTheRelay: pion takes the client's
//     offer; the join's query, headers and offer are the Go engine's; one
//     pin; what the client publishes is VP9; the relay's PLIs make the
//     client's writer send keyframes; what the relay writes into a receive
//     slot reaches the client's reader; pion's state lines are said;
//   - TestRustMTSARefusedPinDoesNotFailTheJoin;
//   - TestRustMTSARefusedJoinSaysWhyAndTakesTheConferenceBack;
//   - TestRustMTSAClientThatLeavesTakesNothingBack: a guest that joined and
//     left sends no call: the service drops its conference by itself.
//
// There is no server in the room, so the client's handshake never ends: it
// gives up 15 s after its join (handshake.DefaultTimeout) and leaves. Each
// test reads what it needs before that.
//
// TestServeFakeMTSSFU serves one fake SFU and its hooks over loopback HTTP
// to a process outside this package (the gate's mtsfake target, M6.8);
// TestServedFakeMTSSFUHooks holds the hooks to the Go engine, with no Rust
// client.

package mtslink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	// rustBinEnv names the Rust client binary.
	rustBinEnv = "OLCRTC_GATE_RUST_BIN"
	// rustLifetime bounds every client process a test starts.
	rustLifetime = 3 * time.Minute
	// rustStopGrace is how long a stopped client has to say goodbye.
	rustStopGrace = 5 * time.Second
	// rustTraceEnv, set, logs every client's log (stamped to the millisecond
	// as it arrived) whether or not its test failed.
	rustTraceEnv = "OLCRTC_GATE_RUST_TRACE"
	// rustGoUserAgent is what Go's net/http calls itself over HTTP/1.1: the
	// engine names no sender on the SFU's calls (vectors: requests_sfu.json).
	rustGoUserAgent = "Go-http-client/1.1"
	// rustRemoteTrack is the client's debug line for the room's video
	// arriving (mtslink.go:403, as the Rust session says it).
	rustRemoteTrack = "mtslink: remote track kind=video codec=video/VP9"
	// rustKeyframeBytes is the least a keyframe sample's first packet
	// carries: the VP9 carrier pads a keyframe past one RTP packet
	// (vp8channel/carrier.go, vp9KeyframeSpan 1400), every other sample of
	// an idle transport is a bare header.
	rustKeyframeBytes = 1000
)

// rustKey is the client's key: any 32 bytes, no server holds it.
var rustKey = strings.Repeat("6b", 32)

// rustSecrets is what no line of the client's log may carry: the join's two
// tokens, the guest's cookies and ids, the conference and the key.
var rustSecrets = []string{
	"vcJOIN", "vcPRIVATE", "eyJguest.access", "6074c7a91c56", "529e1f7d",
	"33d131e5f5194d28", "3d131e5f5194d283", "100200999", testSession, testConf, rustKey,
}

func rustBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(rustBinEnv)
	if bin == "" {
		t.Skip(rustBinEnv + " (the olc-client binary) is not set")
	}
	return bin
}

// rustConfig is what the Rust client reads (olc-client's config.rs), as far
// as a join on direct credentials sets it.
type rustConfig struct {
	URL         string            `json:"url"`
	Engine      string            `json:"engine"`
	Token       string            `json:"token"`
	Key         string            `json:"key"`
	Transport   string            `json:"transport"`
	DNS         string            `json:"dns"`
	Socks       string            `json:"socks"`
	DeviceID    string            `json:"device_id"`
	Debug       bool              `json:"debug"`
	IceLocalIP  string            `json:"ice_local_ip"`
	EngineExtra map[string]string `json:"engine_extra"`
}

// rustSFUConfig joins sfu as the engine's own tests do (fakeSFU.config):
// the room join as the provider hands it over, the guest's cookies, the
// gateway and the conference that take a failed join back. No "ice": UDP,
// as a Go engine on direct credentials.
func rustSFUConfig(sfu *fakeSFU) rustConfig {
	return rustConfig{
		URL: sfu.joinURL(), Engine: "mtslink", Token: testCookies, Key: rustKey, Transport: "vp8channel",
		DNS: "127.0.0.1:53", Socks: "127.0.0.1:0", DeviceID: "client-1", Debug: true, IceLocalIP: "127.0.0.1",
		EngineExtra: map[string]string{"gateway": sfu.srv.URL, "conferenceId": testConf},
	}
}

// rustProc is one run of the Rust client.
type rustProc struct {
	cmd     *exec.Cmd
	logPath string
	exited  chan struct{}
	cancel  context.CancelFunc
}

// startRust runs the client on cfg until the test ends. Its end is certain:
// the cleanup stops its process group and waits, Pdeathsig kills it with the
// test process, and its context carries rustLifetime.
func startRust(t *testing.T, cfg rustConfig) *rustProc {
	t.Helper()
	bin := rustBin(t)
	dir := t.TempDir()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "client.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), rustLifetime)
	cmd := exec.CommandContext(ctx, bin, cfgPath)
	cmd.SysProcAttr = rustChildProc()
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = rustStopGrace
	cmd.Stdout = io.Discard
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	p := &rustProc{cmd: cmd, logPath: logFile.Name(), exited: make(chan struct{}), cancel: cancel}
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			_, _ = fmt.Fprintf(logFile, "%s %s\n", time.Now().Format("15:04:05.000"), sc.Text())
		}
		_ = logFile.Close()
		_ = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		p.stop(t)
		log := p.log()
		for _, secret := range rustSecrets {
			if strings.Contains(log, secret) {
				t.Errorf("the rust client's log carries a secret of the join (%d bytes of it)", len(secret))
			}
		}
		if t.Failed() || os.Getenv(rustTraceEnv) != "" {
			t.Logf("rust client log, last lines:\n%s", rustTail(log, 80))
		}
	})
	return p
}

// stop ends the client and waits for it.
func (p *rustProc) stop(t *testing.T) {
	t.Helper()
	p.cancel()
	select {
	case <-p.exited:
	case <-time.After(rustStopGrace + 5*time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		t.Errorf("the rust client was still running %s after its stop", rustStopGrace+5*time.Second)
	}
}

// log is the client's log so far.
func (p *rustProc) log() string {
	raw, _ := os.ReadFile(p.logPath)
	return string(raw)
}

func (p *rustProc) logHas(text string) bool { return strings.Contains(p.log(), text) }

// rustSample is one sample of the engine's own test track.
func rustSample() media.Sample {
	return media.Sample{Data: blackKeyframe, Duration: 20 * time.Millisecond}
}

func rustTail(log string, n int) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// rustMids is the mid of every m-line of an SDP, in order.
func rustMids(sdp string) []string {
	sections := strings.Split(sdp, "\r\nm=")[1:]
	out := make([]string, 0, len(sections))
	for _, section := range sections {
		mid := ""
		for _, line := range strings.Split(section, "\r\n") {
			if rest, ok := strings.CutPrefix(line, "a=mid:"); ok {
				mid = rest
				break
			}
		}
		out = append(out, mid)
	}
	return out
}

// rustPublished counts what a publisher sent to the fake: every packet, and
// the first packets of keyframe samples.
type rustPublished struct {
	mu        sync.Mutex
	packets   int
	keyframes int
	notVP9    int
}

// rustWatchPublished reads the fake's published payloads until the test
// ends.
func rustWatchPublished(t *testing.T, sfu *fakeSFU) *rustPublished {
	t.Helper()
	seen := &rustPublished{}
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case payload := <-sfu.published:
				var d codecs.VP9Packet
				_, err := d.Unmarshal(payload)
				seen.mu.Lock()
				seen.packets++
				if err != nil {
					seen.notVP9++
				} else if d.B && len(payload) >= rustKeyframeBytes {
					seen.keyframes++
				}
				seen.mu.Unlock()
			}
		}
	}()
	return seen
}

func (s *rustPublished) counts() (packets, keyframes, notVP9 int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.packets, s.keyframes, s.notVP9
}

// rustJoined waits for the client's join and its published track.
func rustJoined(t *testing.T, sfu *fakeSFU) *webrtc.TrackRemote {
	t.Helper()
	within(t, 30*time.Second, "the client's join", func() bool {
		sfu.mu.Lock()
		defer sfu.mu.Unlock()
		return sfu.joins > 0
	})
	select {
	case published := <-sfu.publisher:
		return published
	case <-time.After(15 * time.Second):
		t.Fatal("the relay never saw the published track")
		return nil
	}
}

// The whole join against a relay that negotiates for real
// (TestSessionJoinsPublishesAndHearsTheRelay, with the Rust client).
func TestRustMTSJoinsPublishesAndHearsTheRelay(t *testing.T) {
	rustBin(t)
	sfu := newFakeSFU(t)
	seen := rustWatchPublished(t, sfu)
	p := startRust(t, rustSFUConfig(sfu))

	// pion took the offer (the fake answers 400 otherwise), ICE, DTLS and
	// SRTP came up, and what the client writes to its track reaches the
	// relay as VP9.
	published := rustJoined(t, sfu)
	if !strings.EqualFold(published.Codec().MimeType, webrtc.MimeTypeVP9) {
		t.Fatalf("published as %s", published.Codec().MimeType)
	}
	within(t, 10*time.Second, "a published packet reaching the relay", func() bool {
		packets, _, _ := seen.counts()
		return packets > 0
	})

	// The relay asks for keyframes; the client's writer answers each, a
	// tenth of a second apart at the closest (keyframeRequestGap). Without
	// the requests it sends one every two seconds.
	sfu.mu.Lock()
	relay := sfu.pcs[len(sfu.pcs)-1]
	sfu.mu.Unlock()
	_, before, _ := seen.counts()
	asking := time.Now()
	for time.Since(asking) < 2*time.Second {
		_ = relay.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(published.SSRC())}})
		time.Sleep(20 * time.Millisecond)
	}
	if _, after, _ := seen.counts(); after-before < 5 {
		t.Errorf("%d keyframes in 2 s of keyframe requests, want at least 5: the requests did not reach the writer", after-before)
	}

	// What the relay sends into a slot reaches the client's reader.
	seq := uint16(1000)
	within(t, 10*time.Second, "the relay's video reaching the client", func() bool {
		seq++
		_ = sfu.toEngine.WriteRTP(&rtp.Packet{
			Header:  rtp.Header{Version: 2, PayloadType: 98, SequenceNumber: seq, Timestamp: 1},
			Payload: append([]byte{0x9f, 0x80, 0x01, 0x10, 0x01, 0x40, 0x00, 0xb4}, blackKeyframe...),
		})
		return p.logHas(rustRemoteTrack)
	})

	// The join: the offer as the body, nothing of the guest's cookies, Go's
	// own name for the sender, and the three things that describe the offer
	// added to what the provider gave.
	sfu.mu.Lock()
	joins, head, query, offer := sfu.joins, sfu.joinHead, sfu.joinQuery, sfu.offer
	sfu.mu.Unlock()
	if joins != 1 {
		t.Errorf("%d joins, want one", joins)
	}
	if ct := head.Get("Content-Type"); ct != "application/sdp" {
		t.Errorf("join Content-Type = %q", ct)
	}
	if head.Get("Cookie") != "" {
		t.Error("the guest's cookies went to the SFU")
	}
	if head.Get("Origin") != "" || head.Get("Referer") != "" {
		t.Error("the join names an origin; the Go engine's names none")
	}
	if ua := head.Get("User-Agent"); ua != rustGoUserAgent {
		t.Errorf("join User-Agent = %q, want %q", ua, rustGoUserAgent)
	}
	mids := rustMids(offer)
	if len(mids) != 3+receiveSlots {
		t.Fatalf("%d m-lines in the offer, want %d", len(mids), 3+receiveSlots)
	}
	for key, want := range map[string]string{
		"userId": "100200999", "joinToken": "vcJOIN", "publishToken": "vcPRIVATE", "disableRecording": "true",
		"did": "33d131e5f5194d28", "pid": "3d131e5f5194d283", "userName": "guest",
		"twcc": "true", "preferredPublishCodec": "vp9", "originMid": mids[2],
	} {
		if query.Get(key) != want {
			t.Errorf("join %s = %q, want %q", key, query.Get(key), want)
		}
	}
	if len(query) != 10 {
		t.Errorf("the join carries %d values, want the provider's seven and the offer's three", len(query))
	}

	// The offer: the published camera, a microphone line, the one audio
	// player the SFU allows, and nine video slots, VP9 alone, posted before
	// any candidate.
	want := make([]string, 0, 3+receiveSlots)
	want = append(want, "video sendrecv", "audio sendrecv", "audio recvonly")
	for range receiveSlots {
		want = append(want, "video recvonly")
	}
	if got := mediaSections(offer); strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Errorf("offer sections:\n %s\nwant:\n %s", strings.Join(got, ", "), strings.Join(want, ", "))
	}
	if mids[2] == "" {
		t.Error("the audio player's line has no mid")
	}
	if strings.Contains(offer, "VP8") || strings.Contains(offer, "H264") {
		t.Error("the offer names a video codec other than the one it publishes")
	}
	if strings.Contains(offer, "a=candidate") {
		t.Error("the offer carries a candidate; the Go engine posts it before any")
	}
	// As the Go engine's offer: only the lines that send declare a stream,
	// and the origin names no library.
	for i, section := range strings.Split(offer, "\r\nm=")[1:] {
		if !strings.Contains(section, "\r\na=recvonly") {
			continue
		}
		if strings.Contains(section, "\r\na=ssrc") || strings.Contains(section, "\r\na=msid:") {
			t.Errorf("line %d of the offer only receives and declares a stream", i)
		}
	}
	if !strings.Contains(offer, "\r\no=- ") || strings.Contains(offer, "str0m") {
		t.Error("the offer's origin is not the Go engine's \"-\"")
	}

	// The pin the web client sends after every join: nothing pinned.
	within(t, 10*time.Second, "the pin", func() bool {
		sfu.mu.Lock()
		defer sfu.mu.Unlock()
		return len(sfu.pins) > 0
	})
	sfu.mu.Lock()
	pins := append([]string(nil), sfu.pins...)
	sfu.mu.Unlock()
	if len(pins) != 1 || pins[0] != "POST /rtc/peer/"+testPeer+"/pin | {\"streams\":[\"\"]} | application/json | " {
		t.Errorf("pins = %q", pins)
	}

	// pion's state lines, which the apps read.
	for _, line := range []string{
		"ICE connection state changed: connected", "peer connection state changed: connected",
	} {
		if !p.logHas(line) {
			t.Errorf("the client's log has no %q", line)
		}
	}
	if _, _, notVP9 := seen.counts(); notVP9 != 0 {
		t.Errorf("%d published packets are not VP9", notVP9)
	}

	// A guest that joined leaves nothing to take back.
	p.stop(t)
	if !p.logHas("peer connection state changed: closed") {
		t.Error("the client's log has no closed peer connection after its stop")
	}
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	if len(sfu.leaves) != 0 {
		t.Errorf("leave calls after a join that succeeded: %q", sfu.leaves)
	}
}

// The join works without the pin (measured), so a refused pin is not a
// refused join (TestARefusedPinDoesNotFailTheJoin).
func TestRustMTSARefusedPinDoesNotFailTheJoin(t *testing.T) {
	rustBin(t)
	sfu := newFakeSFU(t)
	sfu.pinStatus = http.StatusForbidden
	seen := rustWatchPublished(t, sfu)
	p := startRust(t, rustSFUConfig(sfu))
	rustJoined(t, sfu)
	within(t, 10*time.Second, "a published packet reaching the relay", func() bool {
		packets, _, _ := seen.counts()
		return packets > 0
	})
	within(t, 10*time.Second, "the refused pin in the client's log", func() bool {
		return p.logHas("mtslink: mtslink: pin: status 403")
	})
	if !p.logHas("peer connection state changed: connected") {
		t.Error("the join with a refused pin did not connect")
	}
	// A client that leaves says its peer connection closed before it goes.
	p.stop(t)
	if !p.logHas("peer connection state changed: closed") {
		t.Error("the client's log has no closed peer connection after its stop")
	}
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	if len(sfu.pins) != 1 {
		t.Errorf("pins = %q", sfu.pins)
	}
	if len(sfu.leaves) != 0 {
		t.Errorf("a refused pin took the conference back: %q", sfu.leaves)
	}
}

// A join the SFU refuses says why, in the SFU's own words, and takes back
// the conference nothing will publish into
// (TestARefusedJoinSaysWhyAndTakesTheConferenceBack).
func TestRustMTSARefusedJoinSaysWhyAndTakesTheConferenceBack(t *testing.T) {
	rustBin(t)
	sfu := newFakeSFU(t)
	sfu.refuseStatus = http.StatusBadRequest
	sfu.refuseBody = "SDP validation error: exceeded maximal audio players value 1"
	p := startRust(t, rustSFUConfig(sfu))
	within(t, 30*time.Second, "the conference taken back", func() bool {
		sfu.mu.Lock()
		defer sfu.mu.Unlock()
		return len(sfu.leaves) > 0
	})
	within(t, 10*time.Second, "the refusal in the client's log", func() bool {
		return p.logHas("mtslink: the SFU refused the join: status 400: SDP validation error: exceeded maximal audio players value 1")
	})
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	if sfu.joins != len(sfu.leaves) && sfu.joins != len(sfu.leaves)+1 {
		t.Errorf("%d joins and %d leaves: every refused join takes its conference back", sfu.joins, len(sfu.leaves))
	}
	for _, leave := range sfu.leaves {
		if leave != "DELETE /api/conferences/"+testConf+" | "+testCookies {
			t.Errorf("leave = %q, want the conference taken back with the guest's cookies", leave)
		}
	}
	if len(sfu.pins) != 0 {
		t.Errorf("a refused join was pinned: %q", sfu.pins)
	}
}

// A guest that joined and leaves closes its peer connection and asks the
// service for nothing: no take-back, no second join.
func TestRustMTSAClientThatLeavesTakesNothingBack(t *testing.T) {
	rustBin(t)
	sfu := newFakeSFU(t)
	p := startRust(t, rustSFUConfig(sfu))
	rustJoined(t, sfu)
	p.stop(t)
	log := p.log()
	for _, line := range []string{
		"peer connection state changed: connected", "peer connection state changed: closed",
	} {
		if !strings.Contains(log, line) {
			t.Errorf("the client's log has no %q", line)
		}
	}
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	if sfu.joins != 1 || len(sfu.leaves) != 0 {
		t.Errorf("%d joins and leaves %q, want one join and nothing taken back", sfu.joins, sfu.leaves)
	}
}

// The fake SFU for a process outside this package.
const (
	// rustServeEnv switches TestServeFakeMTSSFU on.
	rustServeEnv = "OLC_FAKE_MTS_SFU_SERVE"
	// rustServeMarker opens the line that says where the hooks listen, on
	// stdout.
	rustServeMarker = "FAKE MTS SFU HOOKS LISTENING ON "
	// rustServeLifetime bounds the server when the parent never closes stdin.
	rustServeLifetime = 70 * time.Minute
)

// rustHooks is a fake SFU's hooks over HTTP:
//
//	GET  /state                the room join ("url"), the gateway, the guest's
//	                           cookies ("token") and conference; what the fake
//	                           saw: joins, the last offer, join query and
//	                           headers, pins, leaves, peers, published packets
//	POST /refuse?status=N&body=B   the next joins answer N and B; status 0
//	                           takes it back
//	POST /pinstatus?status=N   what a pin answers
//	POST /pli                  a PLI for the last published track
//	POST /slot?seq=N           one VP9 packet into the relay's slot
//	POST /closepeer            the last peer connection closes
type rustHooks struct {
	sfu *fakeSFU

	mu        sync.Mutex
	published *webrtc.TrackRemote
	packets   int
}

// newRustHooks follows the fake's publishers until done closes.
func newRustHooks(sfu *fakeSFU, done <-chan struct{}) *rustHooks {
	h := &rustHooks{sfu: sfu}
	go func() {
		for {
			select {
			case <-done:
				return
			case track := <-sfu.publisher:
				h.mu.Lock()
				h.published = track
				h.mu.Unlock()
			case <-sfu.published:
				h.mu.Lock()
				h.packets++
				h.mu.Unlock()
			}
		}
	}()
	return h
}

func (h *rustHooks) lastPeer() *webrtc.PeerConnection {
	h.sfu.mu.Lock()
	defer h.sfu.mu.Unlock()
	if len(h.sfu.pcs) == 0 {
		return nil
	}
	return h.sfu.pcs[len(h.sfu.pcs)-1]
}

func (h *rustHooks) state() map[string]any {
	h.mu.Lock()
	packets, publishing := h.packets, h.published != nil
	h.mu.Unlock()
	f := h.sfu
	f.mu.Lock()
	defer f.mu.Unlock()
	return map[string]any{
		"url": f.joinURL(), "gateway": f.srv.URL, "token": testCookies, "conference": testConf,
		"joins": f.joins, "offer": f.offer, "join_query": f.joinQuery, "join_head": f.joinHead,
		"pins": append([]string{}, f.pins...), "leaves": append([]string{}, f.leaves...),
		"peers": len(f.pcs), "publishing": publishing, "published_packets": packets,
	}
}

func (h *rustHooks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := func() (int, bool) {
		n, err := strconv.Atoi(q.Get("status"))
		if err != nil {
			http.Error(w, "status: "+err.Error(), http.StatusBadRequest)
		}
		return n, err == nil
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /state":
	case "POST /refuse":
		n, ok := status()
		if !ok {
			return
		}
		h.sfu.mu.Lock()
		h.sfu.refuseStatus, h.sfu.refuseBody = n, q.Get("body")
		h.sfu.mu.Unlock()
	case "POST /pinstatus":
		n, ok := status()
		if !ok {
			return
		}
		h.sfu.mu.Lock()
		h.sfu.pinStatus = n
		h.sfu.mu.Unlock()
	case "POST /pli":
		h.mu.Lock()
		published := h.published
		h.mu.Unlock()
		pc := h.lastPeer()
		if published == nil || pc == nil {
			http.Error(w, "nothing is published", http.StatusConflict)
			return
		}
		if err := pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(published.SSRC())}}); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	case "POST /slot":
		seq, err := strconv.ParseUint(q.Get("seq"), 10, 16)
		if err != nil {
			http.Error(w, "seq: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.sfu.toEngine.WriteRTP(&rtp.Packet{
			Header:  rtp.Header{Version: 2, PayloadType: 98, SequenceNumber: uint16(seq), Timestamp: 1},
			Payload: append([]byte{0x9f, 0x80, 0x01, 0x10, 0x01, 0x40, 0x00, 0xb4}, blackKeyframe...),
		}); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	case "POST /closepeer":
		pc := h.lastPeer()
		if pc == nil {
			http.Error(w, "no peer connection", http.StatusConflict)
			return
		}
		_ = pc.Close()
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.state())
}

// TestServeFakeMTSSFU serves one fake SFU and its hooks (rustHooks) over
// loopback HTTP until its stdin closes (the parent's end) or
// rustServeLifetime. The line rustServeMarker opens, on stdout, says where
// the hooks listen; GET /state says where the room is.
func TestServeFakeMTSSFU(t *testing.T) {
	if os.Getenv(rustServeEnv) != "1" {
		t.Skip(rustServeEnv + "=1 runs the fake SFU's server (the gate's mtsfake target starts it)")
	}
	sfu := newFakeSFU(t)
	done := make(chan struct{})
	defer close(done)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newRustHooks(sfu, done), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("%s%s\n", rustServeMarker, ln.Addr())
	stdin := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdin)
	}()
	select {
	case <-stdin:
	case <-time.After(rustServeLifetime):
		t.Errorf("served for %s without the parent closing stdin", rustServeLifetime)
	}
	_ = srv.Close()
}

// The hooks do to the Go engine what the engine's own test does by hand:
// the state names the room, a PLI reaches the keyframe handler, a packet
// into the slot reaches the track handler, a refusal refuses the next join,
// a closed peer connection ends the session's.
func TestServedFakeMTSSFUHooks(t *testing.T) {
	sfu := newFakeSFU(t)
	done := make(chan struct{})
	defer close(done)
	hooks := httptest.NewServer(newRustHooks(sfu, done))
	defer hooks.Close()
	call := func(method, path string) map[string]any {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, hooks.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
		}
		var state map[string]any
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return state
	}

	state := call(http.MethodGet, "/state")
	if state["url"] != sfu.joinURL() || state["gateway"] != sfu.srv.URL || state["token"] != testCookies ||
		state["conference"] != testConf || state["joins"] != float64(0) {
		t.Fatalf("state before a join = %v", state)
	}

	s, track := newPublishingSession(t, sfu.config())
	remote := make(chan *webrtc.TrackRemote, 4)
	s.SetVideoTrackHandler(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) { remote <- tr })
	asked := make(chan struct{}, 16)
	s.SetKeyframeRequestHandler(func() {
		select {
		case asked <- struct{}{}:
		default:
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	within(t, 10*time.Second, "the published track in the state", func() bool {
		_ = track.WriteSample(rustSample())
		state := call(http.MethodGet, "/state")
		return state["publishing"] == true && state["published_packets"].(float64) > 0
	})
	state = call(http.MethodGet, "/state")
	if state["joins"] != float64(1) || state["peers"] != float64(1) || len(state["pins"].([]any)) != 1 ||
		!strings.HasPrefix(state["offer"].(string), "v=0") {
		t.Errorf("state after a join = %v", state)
	}
	within(t, 10*time.Second, "a hooked PLI reaching the handler", func() bool {
		call(http.MethodPost, "/pli")
		select {
		case <-asked:
			return true
		default:
			return false
		}
	})
	seq := 0
	within(t, 10*time.Second, "a hooked packet reaching the track handler", func() bool {
		seq++
		call(http.MethodPost, "/slot?seq="+strconv.Itoa(seq))
		select {
		case <-remote:
			return true
		default:
			return false
		}
	})
	call(http.MethodPost, "/closepeer")
	within(t, 40*time.Second, "the session losing its closed peer", func() bool { return !s.CanSend() })

	call(http.MethodPost, "/pinstatus?status=403")
	call(http.MethodPost, "/refuse?status=400&body=no")
	s2, _ := newPublishingSession(t, sfu.config())
	if err := s2.Connect(ctx); err == nil || !strings.Contains(err.Error(), "status 400: no") {
		t.Errorf("Connect after a hooked refusal: %v", err)
	}
	state = call(http.MethodPost, "/refuse?status=0")
	if len(state["leaves"].([]any)) != 1 {
		t.Errorf("leaves after a refused join = %v", state["leaves"])
	}
}

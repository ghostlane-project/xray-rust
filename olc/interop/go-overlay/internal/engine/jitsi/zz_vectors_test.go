//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/olc-jitsi in the xray-rust fork) of
// the Jitsi engine's pure parts: nicks and hosts, config.js's rules, the
// bridge's frames and JSON, the epoch rules. An overlay file: regen.sh copies
// it into a clean checkout of the pin. It calls the engine's own functions;
// nothing here opens a socket.

package jitsi

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/zarazaex69/j"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/engine/jitsi/zz_vectors_test.go"

// ---- nick.json ----

type zzNickCase struct {
	Raw  string `json:"raw"`
	Want string `json:"want"`
}

type zzDomainCase struct {
	JID      string `json:"jid"`
	Fallback string `json:"fallback"`
	Want     string `json:"want"`
}

type zzNick struct {
	Sanitise []zzNickCase   `json:"sanitise_nick"`
	Host     []zzNickCase   `json:"normalise_host"`
	Domain   []zzDomainCase `json:"xmpp_domain"`
}

func zzNicks(t *testing.T) {
	var out zzNick
	for _, raw := range []string{
		"alice", "Alice Smith", "Конрад Олег", "olcrtc-bot42", "  bob  ", "$$$ %%%",
		"verylongnicknamethatexceedslimit", "Щщщщщщщщщщ", "a!!!b", "日本語", "--a--", "Ёж ъь", "user_1",
		"a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a", "", " ", "-", "_", "Привет, мир!", "Ъъ", "ЩЩЩЩЩ", "ab\u00e9cd",
		"ÀÉ", "Юлия Яковлева", "x\ty\nz", "a--b", "-a", "a-", "1234567890123456789",
	} {
		out.Sanitise = append(out.Sanitise, zzNickCase{Raw: raw, Want: sanitiseNick(raw)})
	}
	for _, raw := range []string{
		"meet.example.com", "https://meet.example.com", "https://meet.example.com/", "https://meet.example.com/path",
		"//meet.example.com", "  https://meet.example.com  ", "", "h/a/b", "http://h:8443/x", "://h", "https://", "//", "/",
		"meet.example.com/", "https://h//", "a://b://c", "\thost\n",
	} {
		out.Host = append(out.Host, zzNickCase{Raw: raw, Want: normaliseHost(raw)})
	}
	for _, c := range [][2]string{
		{"8307a4f4@meet.jitsi/T4i4s0jt", "meet.mamba.group"}, {"uuid@meet.jitsi", "meet.mamba.group"},
		{"", "meet.mamba.group"}, {"node-only", "meet.handyweb.org"}, {"node@/resource", "meet.small-dm.ru"},
		{"node@meet.jitsi/", "fallback.host"}, {"a@b@c/d", "f"}, {"@d/r", "f"}, {"@", "f"}, {"a@b/c/d", "f"},
	} {
		out.Domain = append(out.Domain, zzDomainCase{JID: c[0], Fallback: c[1], Want: xmppDomain(c[0], c[1])})
	}
	zzvectors.Write(t, "jitsi/nick.json", zzGenerator,
		[]string{"internal/engine/jitsi/nick.go", "internal/engine/jitsi/keepalive.go:124-136 (xmppDomain)"}, out)
}

// ---- configjs.json ----

type zzBodyCase struct {
	Name string `json:"name"`
	Body string `json:"body"`
	Want string `json:"want"`
}

type zzStatusCase struct {
	Code      int    `json:"code"`
	MediaType string `json:"media_type"`
	Final     bool   `json:"final"`
	Text      string `json:"text"`
}

type zzMediaCase struct {
	Header string `json:"header"`
	Set    bool   `json:"set"`
	Want   string `json:"want"`
}

type zzRetryCase struct {
	Err    string `json:"err"`
	HasErr bool   `json:"has_err"`
	Failed bool   `json:"failed"`
	Want   bool   `json:"want"`
}

type zzConfigJS struct {
	Domain     []zzBodyCase   `json:"library_domain"`
	WholeLines []zzBodyCase   `json:"whole_lines"`
	Status     []zzStatusCase `json:"status"`
	Media      []zzMediaCase  `json:"media_type"`
	Retry      []zzRetryCase  `json:"retry"`
	Fallback   string         `json:"fallback_config"`
}

func zzConfig(t *testing.T) {
	var out zzConfigJS
	for _, c := range []struct{ name, body string }{
		{"jitsi-meet config", "var config = {\n    // Connection\n    //\n\n    hosts: {\n        // XMPP domain.\n        domain: 'jitsi-meet.example.com',\n\n        muc: 'conference.' + subdomain + 'jitsi-meet.example.com',\n    },\n\n    bosh: 'https://jitsi-meet.example.com/' + subdir + 'http-bind',\n};\n"},
		{"docker-jitsi-meet config", "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nvar subdomain = '';\nconfig.hosts.muc = 'muc.' + subdomain + 'meet.jitsi';\n"},
		{"double quotes and a trailing comment", "config.hosts.domain = \"meet.example.org\"; // XMPP\n"},
		{"concatenated literals", "var config = {\n    hosts: {\n        domain: 'meet.' + subdomain + 'example.org',\n    },\n};\n"},
		{"hosts opened on the config line", "var config = { hosts: {\n        domain: 'xmpp.custom.example',\n    },\n};\n"},
		{"hosts brace on a line of its own", "var config = {\n    hosts:\n    {\n        domain: 'xmpp.custom.example',\n    },\n};\n"},
		{"the first domain key wins", "var other = {\n    domain: 'other.example',\n};\nvar config = {\n    hosts: {\n        domain: 'meet.example.org',\n    },\n};\n"},
		{"a key without a literal gives way", "config.hosts.domain = someVariable;\nconfig.hosts.domain = 'meet.example.org';\n"},
		{"a semicolon in the literal", "config.hosts.domain = 'meet;example.org';\n"},
		{"a comma in the literal", "config.hosts.domain = 'meet,example.org';\n"},
		{"html error page", "<html><body>Attention Required!</body></html>"},
		{"file cut before hosts", "var config = {\n    // Connection\n"},
		{"commented out", "var config = {\n    hosts: {\n        // domain: 'x.example',\n    },\n};\n"},
		{"only anonymousdomain", "var config = {\n    hosts: {\n        anonymousdomain: 'guest.example',\n    },\n};\n"},
		{"longer key", "config.hosts.domainAlias = 'x.example';\n"},
		{"not a string", "config.hosts.domain = someVariable;\n"},
		{"a literal left open", "config.hosts.domain = 'meet.' + 'exam"},
		{"a // inside a literal", "config.hosts.domain = 'http://x';\n"},
		{"crlf lines", "config.hosts.domain = 'crlf.example';\r\nconfig.hosts.muc = 'muc.crlf.example';\r\n"},
		{"a tab after the key", "domain\t= 'tab.example';\n"},
		{"a space after the key", "domain 'space.example'\n"},
		{"no separator", "domain'x.example'\n"},
		{"config. prefix only", "config.domain = 'plain.example';\n"},
		{"config.hosts. twice", "config.hosts.config.hosts.domain = 'x.example';\n"},
		{"mixed quotes", "domain: 'a\"b' + \"c'd\"\n"},
		{"empty literal then a literal", "domain: '' + 'x.example'\n"},
		{"indented", "        \t  domain: 'indented.example',\n"},
		{"two keys on a line", "domain: 'one.example', muc: 'two.example'\n"},
		{"unicode", "domain: 'м.example'\n"},
		{"empty", ""},
	} {
		out.Domain = append(out.Domain, zzBodyCase{Name: c.name, Body: c.body, Want: libraryDomain([]byte(c.body))})
	}
	for _, body := range []string{"a\nb\nc", "abc", "a\n", "", "\n", "a\n\nb"} {
		out.WholeLines = append(out.WholeLines, zzBodyCase{Name: "", Body: body, Want: string(wholeLines([]byte(body)))})
	}
	for _, c := range []struct {
		code int
		mt   string
	}{{200, "text/html"}, {301, "text/html"}, {302, "x"}, {307, "x"}, {399, "x"}, {400, "x"}, {403, "text/html"}, {404, "x"},
		{410, "x"}, {429, "x"}, {500, "x"}, {502, "x"}, {503, "no content-type"}} {
		e := &statusError{code: c.code, mediaType: c.mt}
		out.Status = append(out.Status, zzStatusCase{Code: c.code, MediaType: c.mt, Final: e.final(), Text: e.Error()})
	}
	for _, h := range []struct {
		v   string
		set bool
	}{{"text/html; charset=utf-8", true}, {"  ; x", true}, {"", false}, {"application/javascript", true}, {" text/plain ;a=b", true},
		{";", true}, {"", true}} {
		hdr := http.Header{}
		if h.set {
			hdr.Set("Content-Type", h.v)
		}
		out.Media = append(out.Media, zzMediaCase{Header: h.v, Set: h.set, Want: mediaType(hdr)})
	}
	hostUnknown := "xmpp dial: initial features: server error: <stream:error xmlns='jabber:client'><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text>This server does not serve meet.example.com</text></stream:error>"
	other := "xmpp dial: failed to WebSocket dial: expected handshake response status code 101 but got 502"
	outside := "dial tcp: lookup host-unknown.example: no such host"
	for _, c := range []struct {
		err    string
		hasErr bool
		failed bool
	}{{hostUnknown, true, true}, {hostUnknown, true, false}, {other, true, true}, {other, true, false},
		{outside, true, true}, {"", false, true}, {"<host-unknown", true, true}} {
		var err error
		if c.hasErr {
			err = errors.New(c.err)
		}
		out.Retry = append(out.Retry, zzRetryCase{Err: c.err, HasErr: c.hasErr, Failed: c.failed, Want: shouldRetryWithFallback(err, c.failed)})
	}
	out.Fallback = fallbackConfig
	zzvectors.Write(t, "jitsi/configjs.json", zzGenerator,
		[]string{"internal/engine/jitsi/configjs.go (libraryDomain, wholeLines, statusError, mediaType, shouldRetryWithFallback, fallbackConfig)"}, out)
}

// ---- frames.json ----

type zzEncodeCase struct {
	Data  string `json:"data_hex"`
	Local uint32 `json:"local"`
	Peer  uint32 `json:"peer"`
	Frame string `json:"frame_hex"`
	// Zeros is the length of a payload of zero bytes, given instead of its
	// hex; FrameLen and FrameHead then stand for the frame.
	Zeros     int    `json:"zeros,omitempty"`
	FrameLen  int    `json:"frame_len,omitempty"`
	FrameHead string `json:"frame_head_hex,omitempty"`
	TooBig    bool   `json:"too_big"`
}

type zzDecodeCase struct {
	Name   string `json:"name"`
	Class  string `json:"class"`
	Fields string `json:"fields"`
	// Want is the decoded bytes in hex; Some is false for nil.
	Want string `json:"want_hex"`
	Some bool   `json:"some"`
}

type zzMessageCase struct {
	To   string `json:"to"`
	Data string `json:"data_hex"`
	JSON string `json:"json"`
}

type zzWindowCase struct {
	Hex    string `json:"hex"`
	Parsed bool   `json:"parsed"`
	Kind   int    `json:"kind"`
	Sender uint32 `json:"sender"`
	Recv   uint32 `json:"receiver"`
	Count  uint64 `json:"counter"`
}

type zzFrames struct {
	Encode  []zzEncodeCase  `json:"encode"`
	Decode  []zzDecodeCase  `json:"decode_raw"`
	Message []zzMessageCase `json:"endpoint_message"`
	Window  []zzWindowCase  `json:"window"`
}

func zzFrameTests(t *testing.T) {
	var out zzFrames
	js := newSilentSession(t)
	for _, c := range []struct {
		data        []byte
		local, peer uint32
	}{
		{[]byte("hi"), 0x01020304, 0x0a0b0c0d}, {nil, 1, 2}, {make([]byte, bridgeMaxMessageSize-12), 1, 2},
		{make([]byte, bridgeMaxMessageSize-11), 1, 2}, {make([]byte, bridgeMaxMessageSize), 1, 2},
		{[]byte("payload"), 0xffffffff, 0}, {[]byte{0, 1, 2, 255}, 0, 0xffffffff},
	} {
		js.localEpoch.Store(c.local)
		js.peerEpoch.Store(c.peer)
		framed, err := js.encodeBridgeFrame(c.data, "")
		rec := zzEncodeCase{Data: zzvectors.Hex(c.data), Local: c.local, Peer: c.peer}
		if err != nil {
			rec.TooBig = errors.Is(err, ErrSendTooLarge)
		} else {
			rec.Frame = zzvectors.Hex(framed)
		}
		// A large payload is zero bytes: its length stands for it.
		if len(rec.Data) > 64 {
			rec.Data, rec.Zeros = "", len(c.data)
			if rec.Frame != "" {
				rec.Frame, rec.FrameLen, rec.FrameHead = "", len(framed), zzvectors.Hex(framed[:12])
			}
		}
		out.Encode = append(out.Encode, rec)
	}

	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	for _, c := range []struct{ name, class, fields string }{
		{"legacy raw", "EndpointMessage", `{"raw":"` + enc([]byte("hello world")) + `"}`},
		{"other class", "OtherClass", `{"raw":"` + enc([]byte("x")) + `"}`},
		{"no raw", "EndpointMessage", `{}`},
		{"bad base64", "EndpointMessage", `{"raw":"not-base64!!!"}`},
		{"msgPayload raw", "EndpointMessage", `{"msgPayload":{"raw":"` + enc([]byte("hello msgPayload")) + `"}}`},
		{"msgPayload without raw", "EndpointMessage", `{"msgPayload":{"other":"field"}}`},
		{"msgPayload without raw, top-level raw", "EndpointMessage", `{"msgPayload":{"other":1},"raw":"` + enc([]byte("top")) + `"}`},
		{"raw not a string", "EndpointMessage", `{"raw":5}`},
		{"msgPayload not an object", "EndpointMessage", `{"msgPayload":"x","raw":"` + enc([]byte("top")) + `"}`},
		{"msgPayload raw not a string", "EndpointMessage", `{"msgPayload":{"raw":5},"raw":"` + enc([]byte("top")) + `"}`},
		{"both, msgPayload first", "EndpointMessage", `{"msgPayload":{"raw":"` + enc([]byte("inner")) + `"},"raw":"` + enc([]byte("outer")) + `"}`},
		{"no padding", "EndpointMessage", `{"raw":"YQ"}`},
		{"padding", "EndpointMessage", `{"raw":"YQ=="}`},
		{"trailing bits", "EndpointMessage", `{"raw":"YR=="}`},
		{"newline inside", "EndpointMessage", `{"raw":"Y\nQ=="}`},
		{"carriage return inside", "EndpointMessage", `{"raw":"Y\rQ=="}`},
		{"space inside", "EndpointMessage", `{"raw":"Y Q=="}`},
		{"empty", "EndpointMessage", `{"raw":""}`},
		{"url alphabet", "EndpointMessage", `{"raw":"-_-_"}`},
		{"std alphabet", "EndpointMessage", `{"raw":"+/+/"}`},
	} {
		var fields map[string]any
		if err := json.Unmarshal([]byte(c.fields), &fields); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := decodeRaw(j.BridgeMessage{Class: c.class, Fields: fields})
		out.Decode = append(out.Decode, zzDecodeCase{Name: c.name, Class: c.class, Fields: c.fields, Want: zzvectors.Hex(got), Some: got != nil})
	}

	for _, c := range []struct {
		to   string
		data []byte
	}{
		{"abc123", []byte("payload")}, {"", nil}, {"", []byte("x")}, {"a\"b<c>&", nil}, {"a\\b", []byte{0, 255}},
		{"a\u2028b\u2029", nil}, {"ctl\u0001\u0008\u000c\n\r\t", nil}, {"é", nil}, {"endpoint-1", make([]byte, 100)},
	} {
		b, err := json.Marshal(newEndpointMessage(c.to, c.data))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out.Message = append(out.Message, zzMessageCase{To: c.to, Data: zzvectors.Hex(c.data), JSON: string(b)})
	}

	for _, f := range []windowFrame{
		{windowMark, 1, 2, 0x0102030405060708}, {windowEcho, 0xa0a0a0a0, 0xb0b0b0b0, 1}, {9, 3, 4, 5}, {0, 0, 0, 0},
		{windowMark, 0xffffffff, 0xffffffff, 0xffffffffffffffff},
	} {
		b := f.encode()
		p, ok := parseWindowFrame(b)
		out.Window = append(out.Window, zzWindowCase{Hex: zzvectors.Hex(b), Parsed: ok, Kind: int(p.kind), Sender: p.senderEpoch, Recv: p.receiverEpoch, Count: p.counter})
	}
	good := windowFrame{windowMark, 1, 2, 3}.encode()
	wrongMagic := append([]byte(nil), good...)
	wrongMagic[3] = '2'
	for _, b := range [][]byte{good[:20], append(append([]byte(nil), good...), 0), wrongMagic, nil, []byte("OLW1")} {
		p, ok := parseWindowFrame(b)
		out.Window = append(out.Window, zzWindowCase{Hex: zzvectors.Hex(b), Parsed: ok, Kind: int(p.kind), Sender: p.senderEpoch, Recv: p.receiverEpoch, Count: p.counter})
	}
	zzvectors.Write(t, "jitsi/frames.json", zzGenerator,
		[]string{"internal/engine/jitsi/epoch.go:36-48 (encodeBridgeFrame)", "internal/engine/jitsi/bridge.go:439-492,647-675", "internal/engine/jitsi/relaywindow.go:85-125"}, out)
}

// ---- epoch.json ----

type zzStep struct {
	Op     string `json:"op"`
	From   string `json:"from,omitempty"`
	Raw    string `json:"raw_hex,omitempty"`
	PeerID string `json:"peer_id,omitempty"`
	// What came of it.
	Delivered string `json:"delivered_hex"`
	Some      bool   `json:"delivered"`
	Error     string `json:"error,omitempty"`
	PeerEpoch uint32 `json:"peer_epoch"`
	Endpoint  string `json:"endpoint"`
}

type zzRun struct {
	Name     string   `json:"name"`
	Targeted bool     `json:"targeted"`
	Local    uint32   `json:"local"`
	Steps    []zzStep `json:"steps"`
}

func zzFrame(sender, receiver uint32, data string) string {
	b := append([]byte(nil), bridgeMagic[:]...)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], sender)
	binary.BigEndian.PutUint32(hdr[4:8], receiver)
	b = append(b, hdr[:]...)
	return zzvectors.Hex(append(b, data...))
}

func zzEpochs(t *testing.T) {
	recv := func(from string, raw string) zzStep { return zzStep{Op: "recv", From: from, Raw: raw} }
	runs := []zzRun{
		{Name: "the header validation", Local: 0x4444, Steps: []zzStep{
			recv("peerA", zzvectors.Hex(bridgeMagic[:])),
			recv("peerA", zzFrame(0, 0x4444, "x")),
			recv("peerA", zzFrame(0x4444, 0, "x")),
			recv("peerA", zzFrame(0x1111, 0x9999, "x")),
			recv("peerA", zzFrame(0x1111, 0, "x")),
			{Op: "reset"},
			recv("peerA", zzFrame(0x1111, 0x4444, "x")),
		}},
		{Name: "magic and the peer latch", Local: 0x9999, Steps: []zzStep{
			recv("peerA", zzFrame(0x1111, 0, "alpha")),
			recv("peerA", zzvectors.Hex([]byte("alpha-no-magic-at-all"))),
			recv("peerB", zzFrame(0x1111, 0, "beta")),
			recv("", zzFrame(0x1111, 0, "from-the-room")),
		}},
		{Name: "an old incarnation", Local: 0x2222, Steps: []zzStep{
			recv("peerA", zzFrame(0x1111, 0xaaaa, "old-smux")),
		}},
		{Name: "an announce", Local: 0x2222, Steps: []zzStep{
			recv("peerA", zzFrame(0x1111, 0, "")),
			recv("peerA", zzFrame(0x1111, 0, "b")),
			recv("peerA", zzFrame(0x3333, 0, "c")),
			recv("peerA", zzFrame(0x3333, 0x2222, "d")),
			recv("peerC", zzFrame(0x4444, 0x2222, "e")),
		}},
		{Name: "targeted until confirmed", Targeted: true, Local: 0x3333, Steps: []zzStep{
			recv("clientB", zzFrame(0x2222, 0, "CLIENT_HELLO")),
			recv("server", zzFrame(0x1111, 0x3333, "SERVER_WELCOME")),
			{Op: "confirm", PeerID: "00001111"},
			recv("clientB", zzFrame(0x2222, 0, "CLIENT_HELLO")),
			recv("clientB", zzFrame(0x2222, 0x3333, "x")),
			recv("server", zzFrame(0x1111, 0x3333, "MORE")),
			recv("server", zzFrame(0x1111, 0, "broadcast")),
			{Op: "confirm", PeerID: "00001111"},
			{Op: "confirm", PeerID: "0000abcd"},
			recv("server", zzFrame(0x1111, 0x3333, "old")),
			recv("server2", zzFrame(0xabcd, 0x3333, "new")),
			{Op: "confirm", PeerID: "00000000"},
			{Op: "confirm", PeerID: "zz"},
			{Op: "confirm", PeerID: ""},
			{Op: "confirm", PeerID: "100000000"},
			{Op: "confirm", PeerID: "ABCDEF01"},
			{Op: "confirm", PeerID: "+1"},
			{Op: "reset"},
			recv("server", zzFrame(0x1111, 0x3333, "after-reset")),
		}},
		{Name: "reset and re-latch", Local: 0xdeadbeef, Steps: []zzStep{
			recv("peerA", zzFrame(0x1111, 0, "from-A")),
			recv("peerB", zzFrame(0x2222, 0, "from-B-relatched")),
			{Op: "reset"},
			recv("peerB", zzFrame(0x2222, 0, "from-B-final")),
		}},
	}
	for ri := range runs {
		run := &runs[ri]
		var got []byte
		var seen bool
		cfg := engine.Config{
			URL:                 testHost,
			Extra:               map[string]string{credentialKeyRoom: testRoom},
			RequireTargetedPeer: run.Targeted,
			OnData:              func(b []byte) { got, seen = append([]byte(nil), b...), true },
		}
		sess, err := New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		js, ok := sess.(*Session)
		if !ok {
			t.Fatalf("sess type %T", sess)
		}
		js.localEpoch.Store(run.Local)
		for si := range run.Steps {
			st := &run.Steps[si]
			got, seen = nil, false
			switch st.Op {
			case "recv":
				raw, err := hexBytes(st.Raw)
				if err != nil {
					t.Fatalf("%s: %v", run.Name, err)
				}
				js.deliverBridgeMessage(makeBridgeMessageFrom(st.From, map[string]any{rawFieldKey: base64.StdEncoding.EncodeToString(raw)}), true)
			case "confirm":
				if err := js.ConfirmPeer(st.PeerID); err != nil {
					st.Error = "parse"
					if errors.Is(err, engine.ErrInvalidPeerID) {
						st.Error = "invalid"
					}
				}
			case "reset":
				js.ResetPeer()
			}
			st.Some = seen
			st.Delivered = zzvectors.Hex(got)
			st.PeerEpoch = js.peerEpoch.Load()
			if ep := js.peerEndpoint.Load(); ep != nil {
				st.Endpoint = *ep
			}
		}
		_ = sess.Close()
	}
	zzvectors.Write(t, "jitsi/epoch.json", zzGenerator,
		[]string{"internal/engine/jitsi/epoch.go", "internal/engine/jitsi/bridge.go:582-640 (deliverBridgeMessageGen)"}, runs)
}

func hexBytes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var b byte
		for _, c := range []byte(s[i : i+2]) {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			default:
				return nil, errors.New("bad hex")
			}
		}
		out = append(out, b)
	}
	return out, nil
}

func TestZZVectors(t *testing.T) {
	zzNicks(t)
	zzConfig(t)
	zzFrameTests(t)
	zzEpochs(t)
	zzJingle(t)
	zzRelay(t)
	zzLiveVectors(t)
}

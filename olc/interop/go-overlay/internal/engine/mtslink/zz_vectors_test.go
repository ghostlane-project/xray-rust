//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork) of the
// MTS Link engine. An overlay file: regen.sh copies it into a clean checkout
// of the pin. It calls the engine's own functions and joins its own fake SFU
// (mtslink_test.go) on loopback; nothing here reaches the service.

package mtslink

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pion/webrtc/v4"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/transport/common"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/engine/mtslink/zz_vectors_test.go"

type zzOfferURLCase struct {
	Name string `json:"name"`
	Join string `json:"join"`
	Mid  string `json:"mid"`
	// URL is offerURL's result; empty with Error set when it refused.
	URL   string `json:"url"`
	Error string `json:"error,omitempty"`
}

func zzOfferURL(t *testing.T) {
	t.Helper()
	base := "https://sfu.mts-link.ru/rtc/room/" + testSession + "/join"
	asIssued := base + "?did=33d131e5f5194d28&disableRecording=true&joinToken=vcJOIN&pid=3d131e5f5194d283" +
		"&publishToken=vcPRIVATE&userId=100200999&userName=guest"
	cases := []zzOfferURLCase{
		{Name: "the test's join", Join: base + "?userId=1&joinToken=vcJ&userName=%D0%9C", Mid: "2"},
		{Name: "a join as the provider issues it", Join: asIssued, Mid: "2"},
		{Name: "a join in the web client's order", Join: base + "?userId=100200999&joinToken=vcJOIN&disableRecording=true" +
			"&userName=guest&publishToken=vcPRIVATE&did=33d131e5f5194d28&pid=3d131e5f5194d283", Mid: "2"},
		{Name: "mid 0", Join: asIssued, Mid: "0"},
		{Name: "mid 11", Join: asIssued, Mid: "11"},
		{Name: "an empty mid", Join: asIssued, Mid: ""},
		{Name: "a mid that is not a number", Join: asIssued, Mid: "audio 1&x=y"},
		{Name: "the three values already there are replaced", Join: base + "?twcc=false&originMid=9&preferredPublishCodec=h264&userId=1", Mid: "2"},
		{Name: "a value given twice is replaced by one", Join: base + "?twcc=a&twcc=b&userId=1", Mid: "2"},
		{Name: "a key given twice keeps both, in their order", Join: base + "?userId=2&userId=1&a=1", Mid: "2"},
		{Name: "no query", Join: base, Mid: "2"},
		{Name: "an empty query", Join: base + "?", Mid: "2"},
		{Name: "a fragment stays behind the query", Join: base + "?userId=1#frag", Mid: "2"},
		{Name: "a port and http", Join: "http://127.0.0.1:8443/rtc/room/1/join?userId=1", Mid: "2"},
		{Name: "a plus is a space, a space is a plus", Join: base + "?userName=a+b%20c", Mid: "2"},
		{Name: "what a query escapes", Join: base + "?joinToken=a%2Bb%2Fc%3Dd~e*f&userName=%D0%9C%D0%B0%D1%80%D0%B8%D1%8F", Mid: "2"},
		{Name: "what a query leaves alone", Join: base + "?t=AZaz09-_.~", Mid: "2"},
		{Name: "raw punctuation in a value", Join: base + "?t=!'()*,:@$/?", Mid: "2"},
		{Name: "a key with no value and a key with an empty one", Join: base + "?a&b=&userId=1", Mid: "2"},
		{Name: "a key that needs escaping", Join: base + "?a%20b=1&%D0%BA=2", Mid: "2"},
		{Name: "a pair with a semicolon is dropped", Join: base + "?a=1;b=2&userId=1", Mid: "2"},
		{Name: "a pair with a bad escape is dropped", Join: base + "?a=%zz&userId=1", Mid: "2"},
		{Name: "an escaped path stays as written", Join: "https://sfu.mts-link.ru/rtc/room/a%20b%2Fc/join?userId=1", Mid: "2"},
		{Name: "an upper-case host and scheme", Join: "HTTPS://SFU.MTS-Link.RU/rtc/room/1/join?userId=1", Mid: "2"},
		{Name: "userinfo", Join: "https://u:p@sfu.mts-link.ru/rtc/room/1/join?userId=1", Mid: "2"},
		{Name: "no path", Join: "https://sfu.mts-link.ru?userId=1", Mid: "2"},
		// Refused.
		{Name: "a scheme with nothing in front", Join: "://nothing", Mid: "2"},
		{Name: "empty", Join: "", Mid: "2"},
		{Name: "no scheme", Join: "sfu.mts-link.ru/rtc/room/1/join?userId=1", Mid: "2"},
		{Name: "no host", Join: "https:///rtc/room/1/join?userId=1", Mid: "2"},
		{Name: "a path only", Join: "/rtc/room/1/join?userId=1", Mid: "2"},
		{Name: "a scheme-relative join", Join: "//sfu.mts-link.ru/rtc/room/1/join", Mid: "2"},
		{Name: "a control byte", Join: base + "?userId=1\x7f", Mid: "2"},
		{Name: "a space in the host", Join: "https://sfu mts-link.ru/rtc/room/1/join", Mid: "2"},
	}
	for i := range cases {
		c := &cases[i]
		got, err := offerURL(c.Join, c.Mid)
		if err != nil {
			if !errors.Is(err, ErrNoEndpoint) {
				t.Fatalf("%s: error %v is not ErrNoEndpoint", c.Name, err)
			}
			c.Error = err.Error()
			continue
		}
		c.URL = got
	}
	zzvectors.Write(t, "mtslink/offer_url.json", zzGenerator,
		[]string{"internal/engine/mtslink/signal.go:50-64 (offerURL)", "internal/engine/mtslink/mtslink_test.go:294-318"}, cases)
}

type zzPeerCase struct {
	Name   string `json:"name"`
	Answer string `json:"answer"`
	// Peer is peerOf's result: empty is no peer (ErrNoPeerID at the join).
	Peer string `json:"peer"`
}

func zzPeerOf(t *testing.T) {
	t.Helper()
	cases := []zzPeerCase{
		// TestPeerOfReadsTheSessionNameOfAnAnswer (mtslink_test.go:320-330).
		{Name: "the SFU's answer", Answer: "v=0\r\no=odin 0 0 IN IP4 127.0.0.1\r\ns=" + testPeer + "\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"},
		{Name: "no s line", Answer: "v=0\r\no=odin 0 0\r\n"},
		{Name: "a dash", Answer: "v=0\r\ns=-\r\n"},
		{Name: "a slash", Answer: "v=0\r\ns=a/b\r\n"},
		{Name: "a space", Answer: "v=0\r\ns=a b\r\n"},
		{Name: "empty", Answer: ""},
		// More.
		{Name: "line feeds alone", Answer: "v=0\no=odin 0 0 IN IP4 127.0.0.1\ns=" + testPeer + "\nt=0 0\n"},
		{Name: "carriage returns alone are no line ends", Answer: "v=0\rs=abc\rt=0 0\r"},
		{Name: "no line end behind it", Answer: "v=0\r\ns=abc"},
		{Name: "the s line first", Answer: "s=abc\r\nv=0\r\n"},
		{Name: "spaces in front of the line", Answer: "v=0\r\n   s=abc\r\n"},
		{Name: "a tab in front and spaces behind", Answer: "v=0\r\n\ts=abc  \r\n"},
		{Name: "a space behind the equals sign", Answer: "v=0\r\ns= abc\r\n"},
		{Name: "an empty name", Answer: "v=0\r\ns=\r\nt=0 0\r\n"},
		{Name: "only spaces for a name", Answer: "v=0\r\ns=   \r\n"},
		{Name: "a question mark", Answer: "v=0\r\ns=a?b\r\n"},
		{Name: "a hash", Answer: "v=0\r\ns=a#b\r\n"},
		{Name: "a percent", Answer: "v=0\r\ns=a%20b\r\n"},
		{Name: "a tab inside", Answer: "v=0\r\ns=a\tb\r\n"},
		{Name: "two dashes are a name", Answer: "v=0\r\ns=--\r\n"},
		{Name: "dots are a name", Answer: "v=0\r\ns=..\r\n"},
		{Name: "a backslash, a colon and an at sign are taken", Answer: "v=0\r\ns=a\\b:c@d\r\n"},
		{Name: "a Cyrillic name is taken", Answer: "v=0\r\ns=один\r\n"},
		{Name: "the first s line decides: a name", Answer: "v=0\r\ns=first\r\ns=second\r\n"},
		{Name: "the first s line decides: none", Answer: "v=0\r\ns=-\r\ns=second\r\n"},
		{Name: "an s line behind the media", Answer: "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 98\r\ns=late\r\n"},
		{Name: "an upper-case S is no s line", Answer: "v=0\r\nS=abc\r\n"},
		{Name: "an attribute that holds s= is no s line", Answer: "v=0\r\na=s=abc\r\nas=def\r\n"},
		{Name: "an s line that is not SDP at all", Answer: "s=only"},
		{Name: "a zero byte inside is taken", Answer: "v=0\r\ns=a\x00b\r\n"},
	}
	for i := range cases {
		cases[i].Peer = peerOf(cases[i].Answer)
		if !utf8.ValidString(cases[i].Answer) {
			t.Fatalf("%s: the answer is not UTF-8: the file holds text", cases[i].Name)
		}
	}
	zzvectors.Write(t, "mtslink/peer_of.json", zzGenerator,
		[]string{"internal/engine/mtslink/signal.go:114-128 (peerOf)", "internal/engine/mtslink/mtslink_test.go:320-330"}, cases)
}

type zzRefusalCase struct {
	Name string `json:"name"`
	// BodyHex is the refusal's body; TextHex is refusalText's result, which
	// need not be UTF-8: the cut at 200 bytes can fall inside a character.
	BodyHex string `json:"body_hex"`
	TextHex string `json:"text_hex"`
	// Text is the result as text, null when it is not UTF-8.
	Text *string `json:"text"`
	// Error is the whole error text of a join refused with status 400 and
	// this body, with what is not UTF-8 in it printed as U+FFFD.
	Error string `json:"error"`
}

func zzRefusalText(t *testing.T) {
	t.Helper()
	a := func(n int) string { return strings.Repeat("a", n) }
	inputs := []struct{ name, body string }{
		{"the SFU's own words", "SDP validation error: exceeded maximal audio players value 1"},
		{"empty", ""},
		{"only white space", " \r\n\t "},
		{"the first of several lines", "first line\nsecond line\nthird"},
		{"CRLF line ends", "first line\r\nsecond line\r\n"},
		{"empty lines in front", "\n\n  \nfirst\nsecond"},
		{"spaces and a tab around the line", " \t first \t \nsecond"},
		{"a tab inside is removed", "a\tb"},
		{"control bytes are removed", "a\x00b\x01c\x1fd\x7fe\x1b[0m"},
		{"a carriage return inside is removed", "a\rb\nc"},
		{"a vertical tab and a form feed inside are removed", "a\vb\fc"},
		{"a no-break space in front is trimmed", " first "},
		{"a next-line character inside is kept", "a\u0085b"},
		{"a line separator is no line end", "a b"},
		{"a JSON body", `{"error":{"code":403,"message":"Access denied"}}`},
		{"Cyrillic", "ошибка проверки SDP\nвторая строка"},
		{"199 bytes", a(199)},
		{"200 bytes", a(200)},
		{"201 bytes", a(201)},
		{"1000 bytes", a(1000)},
		{"200 bytes then a second line", a(200) + "\n" + a(50)},
		{"a two-byte character across byte 200", a(199) + "я" + a(10)},
		{"a two-byte character that ends at byte 200", a(198) + "я" + a(10)},
		{"a four-byte character across byte 200", a(198) + "😀" + a(10)},
		{"removed bytes do not count toward the 200", a(100) + strings.Repeat("\x01", 150) + a(150)},
		{"a byte that is not UTF-8 becomes U+FFFD", "bad \xff byte"},
		{"a cut-short character becomes U+FFFD", "bad \xd0"},
		{"U+FFFD from a bad byte across byte 200", a(198) + "\xff" + a(10)},
		{"U+FFFD from a bad byte grows the text to 200", a(197) + "\xff" + a(10)},
		{"a bad byte in a later line is not looked at", "first\n\xff"},
	}
	cases := make([]zzRefusalCase, 0, len(inputs))
	for _, in := range inputs {
		text := refusalText([]byte(in.body))
		c := zzRefusalCase{
			Name: in.name, BodyHex: hex.EncodeToString([]byte(in.body)), TextHex: hex.EncodeToString([]byte(text)),
			Error: strings.ToValidUTF8(fmt.Errorf("%w: status %d: %s", ErrJoinRefused, http.StatusBadRequest, text).Error(), "�"),
		}
		if utf8.ValidString(text) {
			c.Text = &text
		}
		if len(text) > maxRefusalText {
			t.Fatalf("%s: the text is %d bytes", in.name, len(text))
		}
		cases = append(cases, c)
	}
	zzvectors.Write(t, "mtslink/refusal_text.json", zzGenerator,
		[]string{
			"internal/engine/mtslink/signal.go:89-102 (refusalText)",
			"internal/engine/mtslink/signal.go:79-81 (the error a refused join returns)",
		},
		struct {
			MaxBytes int             `json:"max_bytes"`
			Cases    []zzRefusalCase `json:"cases"`
		}{maxRefusalText, cases})
}

// zzSession is a session with the track the video transport publishes on it:
// the VP9 capability of the transport's carrier and the transport's own track
// and stream ids (vp8channel/carrier.go:64-68, vp8channel/transport.go:273,
// common/track.go:21-37). The carrier's payloader is left out: it writes no
// SDP.
func zzSession(t *testing.T, cfg engine.Config) *Session {
	t.Helper()
	sess, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s, ok := sess.(*Session)
	if !ok {
		t.Fatalf("New returned %T", sess)
	}
	t.Cleanup(func() { _ = s.Close() })
	track, err := common.NewVideoTrack(
		webrtc.RTPCodecCapability{MimeType: s.VideoCodec(), ClockRate: 90000, SDPFmtpLine: "profile-id=0"}, "vp8channel")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddVideoTrack(track); err != nil {
		t.Fatal(err)
	}
	return s
}

var (
	zzOrigin  = regexp.MustCompile(`^o=(\S+) (\d+) (\d+) (IN IP4 \S+)$`)
	zzFinger  = regexp.MustCompile(`^a=fingerprint:(\S+) (\S+)$`)
	zzUfrag   = regexp.MustCompile(`^a=ice-ufrag:(\S+)$`)
	zzPwd     = regexp.MustCompile(`^a=ice-pwd:(\S+)$`)
	zzFID     = regexp.MustCompile(`^a=ssrc-group:FID (\d+) (\d+)$`)
	zzSSRC    = regexp.MustCompile(`^a=ssrc:(\d+) (cname|msid|mslabel|label):(.+)$`)
	zzMsid    = regexp.MustCompile(`^a=msid:(\S+) (\S+)$`)
	zzTrackID = regexp.MustCompile(`^(olcrtc|vp8channel)-([0-9a-f]{8})$`)
)

// zzMasker names what is random in one offer. A value met twice gets one
// name, so the names also say which fields are equal.
type zzMasker struct {
	byValue map[string]string
	counts  map[string]int
	// order is the names in the order they were first used; values is what
	// each stood for in this offer.
	order  []string
	values map[string]string
}

func (m *zzMasker) name(kind, value string) string {
	key := kind + "\x00" + value
	if name, ok := m.byValue[key]; ok {
		return name
	}
	name := fmt.Sprintf("<%s-%d>", kind, m.counts[kind])
	m.counts[kind]++
	m.byValue[key] = name
	m.order = append(m.order, name)
	m.values[name] = value
	return name
}

// id names a track, stream or cname id: the transport's keep their prefix.
func (m *zzMasker) id(value string) string {
	if sub := zzTrackID.FindStringSubmatch(value); sub != nil {
		return sub[1] + "-" + m.name("hex8", sub[2])
	}
	return m.name("id", value)
}

func (m *zzMasker) ids(values string) string {
	words := strings.Split(values, " ")
	for i, w := range words {
		words[i] = m.id(w)
	}
	return strings.Join(words, " ")
}

// zzMaskOffer returns the offer's lines with every random field named.
func zzMaskOffer(t *testing.T, sdp string) ([]string, *zzMasker) {
	t.Helper()
	m := &zzMasker{byValue: map[string]string{}, counts: map[string]int{}, values: map[string]string{}}
	lines := strings.Split(sdp, "\r\n")
	for i, line := range lines {
		if strings.ContainsAny(line, "\r\n") {
			t.Fatalf("offer line %q: a line end that is not CRLF", line)
		}
		if sub := zzOrigin.FindStringSubmatch(line); sub != nil {
			lines[i] = "o=" + sub[1] + " " + m.name("session-id", sub[2]) + " " + m.name("session-version", sub[3]) + " " + sub[4]
		} else if sub = zzFinger.FindStringSubmatch(line); sub != nil {
			lines[i] = "a=fingerprint:" + sub[1] + " " + m.name("fingerprint", sub[2])
		} else if sub = zzUfrag.FindStringSubmatch(line); sub != nil {
			lines[i] = "a=ice-ufrag:" + m.name("ice-ufrag", sub[1])
		} else if sub = zzPwd.FindStringSubmatch(line); sub != nil {
			lines[i] = "a=ice-pwd:" + m.name("ice-pwd", sub[1])
		} else if sub = zzFID.FindStringSubmatch(line); sub != nil {
			lines[i] = "a=ssrc-group:FID " + m.name("ssrc", sub[1]) + " " + m.name("ssrc", sub[2])
		} else if sub = zzSSRC.FindStringSubmatch(line); sub != nil {
			lines[i] = "a=ssrc:" + m.name("ssrc", sub[1]) + " " + sub[2] + ":" + m.ids(sub[3])
		} else if sub = zzMsid.FindStringSubmatch(line); sub != nil {
			lines[i] = "a=msid:" + m.ids(sub[1]+" "+sub[2])
		} else if strings.HasPrefix(line, "o=") || strings.Contains(line, "ssrc") || strings.Contains(line, "msid:") ||
			strings.Contains(line, "fingerprint") || strings.Contains(line, "ice-ufrag") || strings.Contains(line, "ice-pwd") ||
			strings.Contains(line, "candidate") {
			t.Fatalf("offer line %q: a form this generator does not know", line)
		}
	}
	return lines, m
}

// zzSortExtmap sorts every run of a=extmap lines.
func zzSortExtmap(lines []string) []string {
	out := append([]string(nil), lines...)
	for i := 0; i < len(out); {
		j := i
		for j < len(out) && strings.HasPrefix(out[j], "a=extmap:") {
			j++
		}
		if j > i+1 {
			sort.Strings(out[i:j])
		}
		if j == i {
			j++
		}
		i = j
	}
	return out
}

// zzDescribe says what the values of one random field look like.
func zzDescribe(values []string) string {
	lo, hi := len(values[0]), len(values[0])
	var digit, lowHex, low, upHex, up bool
	other := map[string]bool{}
	for _, v := range values {
		lo, hi = min(lo, len(v)), max(hi, len(v))
		for _, c := range v {
			switch {
			case c >= '0' && c <= '9':
				digit = true
			case c >= 'a' && c <= 'f':
				lowHex = true
			case c >= 'g' && c <= 'z':
				low = true
			case c >= 'A' && c <= 'F':
				upHex = true
			case c >= 'G' && c <= 'Z':
				up = true
			default:
				other[string(c)] = true
			}
		}
	}
	set := ""
	if digit {
		set += "0-9"
	}
	switch {
	case low:
		set += "a-z"
	case lowHex:
		set += "a-f"
	}
	switch {
	case up:
		set += "A-Z"
	case upHex:
		set += "A-F"
	}
	others := make([]string, 0, len(other))
	for c := range other {
		others = append(others, c)
	}
	sort.Strings(others)
	set += strings.Join(others, "")
	length := strconv.Itoa(lo)
	if hi != lo {
		length += " to " + strconv.Itoa(hi)
	}
	return length + " characters of [" + set + "]"
}

type zzPlaceholder struct {
	Name string `json:"name"`
	Form string `json:"form"`
}

type zzOfferFile struct {
	Note string `json:"note"`
	// Samples is how many offers of as many sessions were compared.
	Samples int `json:"samples"`
	// LineOrder says whether the offers' lines kept one order.
	LineOrder string `json:"line_order"`
	LineEnd   string `json:"line_end"`
	// Sections is the kind and direction of every m-line, in order.
	Sections []string `json:"sections"`
	// AudioPlayerMid is the join's originMid for these offers.
	AudioPlayerMid string `json:"audio_player_mid"`
	// Placeholders are the random fields in the order offer.sdp first names
	// them. One name in two places is one value.
	Placeholders []zzPlaceholder `json:"placeholders"`
}

const zzOfferSamples = 8

// zzOffer makes offers through refused joins - the offer is posted before any
// candidate is gathered, so no peer connection has to come up - and writes
// the one text they share once their random fields are named. It returns
// that text and whether the a=extmap lines had to be sorted to get it.
func zzOffer(t *testing.T) (string, bool) {
	t.Helper()
	sfu := newFakeSFU(t)
	sfu.mu.Lock()
	sfu.refuseStatus, sfu.refuseBody = http.StatusBadRequest, "SDP validation error: a vector generator's refusal"
	sfu.mu.Unlock()

	var raw []string
	var masked [][]string
	var maskers []*zzMasker
	for range zzOfferSamples {
		s := zzSession(t, sfu.config())
		if err := s.Connect(context.Background()); !errors.Is(err, ErrJoinRefused) {
			t.Fatalf("Connect error = %v, want %v", err, ErrJoinRefused)
		}
		_ = s.Close()
		sfu.mu.Lock()
		offer, mid := sfu.offer, sfu.joinQuery.Get("originMid")
		sfu.mu.Unlock()
		if mid != "2" {
			t.Fatalf("originMid = %q, want 2", mid)
		}
		lines, m := zzMaskOffer(t, offer)
		raw = append(raw, offer)
		masked = append(masked, lines)
		maskers = append(maskers, m)
	}

	same := func(of [][]string) bool {
		for _, lines := range of[1:] {
			if strings.Join(lines, "\r\n") != strings.Join(of[0], "\r\n") {
				return false
			}
		}
		return true
	}
	sorted := false
	order := fmt.Sprintf("the same in all %d offers", zzOfferSamples)
	if !same(masked) {
		for i := range masked {
			masked[i] = zzSortExtmap(masked[i])
		}
		if !same(masked) {
			for i, lines := range masked[1:] {
				for n := range lines {
					if n >= len(masked[0]) || lines[n] != masked[0][n] {
						t.Fatalf("offer %d differs from offer 0 at line %d beyond what is named:\n %q\n %q\noffer 0:\n%s",
							i+1, n, lines[n], masked[0][min(n, len(masked[0])-1)], raw[0])
					}
				}
			}
			t.Fatalf("the offers differ in length: %d and more lines", len(masked[0]))
		}
		sorted = true
		order = "the a=extmap lines of a section change order from offer to offer; offer.sdp holds each run of them sorted bytewise"
	}

	file := zzOfferFile{
		Note: "offer.sdp is the offer the engine posts at a join (CreateOffer's text, before any candidate), for the " +
			"layout the video transport publishes into: its VP9 track, a microphone line, the audio player, nine " +
			"receive slots. Every field that differs between two offers is replaced by a name in angle brackets; " +
			"the rest is byte for byte what pion v4.2.15 wrote.",
		Samples: zzOfferSamples, LineOrder: order, LineEnd: "CRLF, the last line included",
		Sections: mediaSections(raw[0]), AudioPlayerMid: "2",
	}
	if !strings.HasSuffix(raw[0], "\r\n") {
		file.LineEnd = "CRLF, none behind the last line"
	}
	for _, name := range maskers[0].order {
		values := make([]string, 0, len(maskers))
		for i, m := range maskers {
			v, ok := m.values[name]
			if !ok || len(m.order) != len(maskers[0].order) {
				t.Fatalf("offer %d names other fields than offer 0 (%s)", i, name)
			}
			values = append(values, v)
		}
		form := zzDescribe(values)
		switch {
		case strings.HasPrefix(name, "<session-id-"), strings.HasPrefix(name, "<session-version-"), strings.HasPrefix(name, "<ssrc-"):
			for _, v := range values {
				if _, err := strconv.ParseUint(v, 10, 64); err != nil {
					t.Fatalf("%s: %q is not a number", name, v)
				}
			}
			form = "a decimal number"
		case strings.HasPrefix(name, "<hex8-"):
			form = "eight lower-case hex digits (common.RandomID)"
		}
		file.Placeholders = append(file.Placeholders, zzPlaceholder{Name: name, Form: form})
	}
	text := strings.Join(masked[0], "\r\n")
	zzvectors.WriteRaw(t, "mtslink/offer.sdp", []byte(text))
	zzvectors.Write(t, "mtslink/offer.json", zzGenerator,
		[]string{
			"internal/engine/mtslink/mtslink.go:210-242 (the codecs)", "internal/engine/mtslink/mtslink.go:301-344 (the lines, in order)",
			"internal/engine/mtslink/mtslink.go:445-456 (the offer is posted as CreateOffer returned it)",
			"internal/transport/common/track.go:21-37 (the track's ids)", "github.com/pion/webrtc/v4@v4.2.15",
		}, file)
	return text, sorted
}

type zzFlow struct {
	Flow string `json:"flow"`
	// Error is Connect's error text, empty when it joined.
	Error    string                 `json:"error"`
	Requests []zzvectors.WireRecord `json:"requests"`
}

// zzRequests records the engine's own calls behind two listeners in front of
// the fake: one where the join URL points (the SFU), one where Extra's
// gateway points.
func zzRequests(t *testing.T, offerText string, sorted bool) {
	t.Helper()
	flows := []zzFlow{{Flow: "join"}, {Flow: "join_refused"}}
	for i := range flows {
		f := &flows[i]
		fake := newFakeSFU(t)
		if f.Flow == "join_refused" {
			fake.mu.Lock()
			fake.refuseStatus, fake.refuseBody = http.StatusBadRequest, "SDP validation error: exceeded maximal audio players value 1"
			fake.mu.Unlock()
		}
		sfu, gateway := zzvectors.NewWire(t, fake.srv.URL), zzvectors.NewWire(t, fake.srv.URL)
		mask := func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(s, sfu.Host(), "<sfu>"), gateway.Host(), "<gateway>")
		}
		cfg := fake.config()
		cfg.URL = strings.Replace(cfg.URL, fake.srv.URL, sfu.URL(), 1)
		cfg.Extra["gateway"] = gateway.URL()
		if !strings.HasPrefix(cfg.URL, sfu.URL()+"/") {
			t.Fatalf("the join URL %q does not point at the listener", cfg.URL)
		}
		s := zzSession(t, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := s.Connect(ctx)
		cancel()
		if err != nil {
			f.Error = err.Error()
		}
		if (f.Flow == "join_refused") != errors.Is(err, ErrJoinRefused) || (f.Flow == "join") != (err == nil) {
			t.Fatalf("%s: Connect error = %v", f.Flow, err)
		}
		f.Requests = append(zzvectors.WireRecords(f.Flow, "sfu", sfu.Take(), mask),
			zzvectors.WireRecords(f.Flow, "gateway", gateway.Take(), mask)...)
		// A session that joined leaves by closing its peer connection: no call.
		if err = s.Close(); err != nil {
			t.Fatalf("%s: Close: %v", f.Flow, err)
		}
		time.Sleep(200 * time.Millisecond)
		if late := append(sfu.Take(), gateway.Take()...); len(late) != 0 {
			t.Fatalf("%s: Close made %d requests, the first %s", f.Flow, len(late), late[0].Line)
		}
		zzvectors.Number(f.Requests)

		// The join's body is the offer: its named form must be offer.sdp, and
		// the record holds the name instead of the text.
		joins := 0
		for n := range f.Requests {
			r := &f.Requests[n]
			if r.Proto != "HTTP/1.1" {
				t.Fatalf("%s: %s %s over %s", f.Flow, r.Method, r.Target, r.Proto)
			}
			if r.Method != http.MethodPost || !strings.Contains(r.Target, "/join?") {
				continue
			}
			joins++
			lines, _ := zzMaskOffer(t, r.Body)
			if sorted {
				lines = zzSortExtmap(lines)
			}
			if strings.Join(lines, "\r\n") != offerText {
				t.Fatalf("%s: the offer posted is not offer.sdp once its fields are named:\n%s", f.Flow, r.Body)
			}
			lengths := 0
			for h, line := range r.Headers {
				if line == "Content-Length: "+strconv.Itoa(len(r.Body)) {
					r.Headers[h] = "Content-Length: <offer-length>"
					lengths++
				}
			}
			if lengths != 1 {
				t.Fatalf("%s: the join has %d Content-Length lines of the offer's length: %q", f.Flow, lengths, r.Headers)
			}
			r.Body = "<offer.sdp>"
		}
		if joins != 1 {
			t.Fatalf("%s: %d joins went through the listener", f.Flow, joins)
		}
	}
	zzvectors.Write(t, "mtslink/requests_sfu.json", zzGenerator,
		[]string{
			"internal/engine/mtslink/signal.go:66-87 (the join)", "internal/engine/mtslink/signal.go:130-154 (the pin)",
			"internal/engine/mtslink/signal.go:156-178 (the take-back)", "internal/engine/mtslink/mtslink.go:375-397 (Connect)",
			"internal/engine/mtslink/mtslink_test.go:45-198 (the fake SFU)", "internal/protect/protect.go:93-113 (the HTTP client)",
		},
		struct {
			Note   string            `json:"note"`
			Masked map[string]string `json:"masked"`
			Flows  []zzFlow          `json:"flows"`
		}{
			"Every request of Session.Connect as Go's net/http wrote it on a plain-HTTP loopback connection, read by " +
				"TCP listeners in front of the fake SFU: header lines in wire order, HTTP/1.1. A flow's requests are " +
				"the SFU's first, then the gateway's. Close makes no request. Over TLS the client offers h2 too, and " +
				"h2 keeps no header order between requests; that wire is not here.",
			map[string]string{
				"<sfu>":          "the host:port of the listener the join URL names",
				"<gateway>":      "the host:port of the listener Extra's gateway names",
				"<offer.sdp>":    "the offer as posted: offer.sdp with its names replaced by that join's values",
				"<offer-length>": "the offer's length in bytes, decimal",
			},
			flows,
		})
}

func TestZZVectors(t *testing.T) {
	zzOfferURL(t)
	zzPeerOf(t)
	zzRefusalText(t)
	offer, sorted := zzOffer(t)
	zzRequests(t, offer, sorted)
}

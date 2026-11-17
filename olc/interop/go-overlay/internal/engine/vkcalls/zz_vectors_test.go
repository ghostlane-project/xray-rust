//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork) of the
// VK Calls engine. An overlay file: regen.sh copies it into a clean checkout
// of the pin. It calls the engine's own functions on the offers of the
// engine's own tests; nothing here reaches the service. The frames a
// signalling socket carries are in zz_vectors_wire_test.go.

package vkcalls

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/engine/vkcalls/zz_vectors_test.go"

// zzOffers are the offers of the engine's tests, by the name the vector
// files call them.
func zzOffers(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"fixture":    fixtureOffer,
		"pion":       pionOffer(),
		"peer_after": offerWithPeer(t, false),
		"peer_ahead": offerWithPeer(t, true),
		"live":       liveShapeOffer(),
	}
}

// zzEdit replaces the first Old of a text by New.
type zzEdit struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// zzText is how a case names an SDP: a text of the file's table (Base) or
// one written out (SDP), then, in this order, every CRLF made a bare LF
// (LF), the edits, and a last line "a=" + Tail times "x" + CRLF.
type zzText struct {
	Base  string   `json:"base,omitempty"`
	SDP   *string  `json:"sdp,omitempty"`
	LF    bool     `json:"lf,omitempty"`
	Edits []zzEdit `json:"edits,omitempty"`
	Tail  int      `json:"tail,omitempty"`
}

func (x zzText) build(t *testing.T, name string, table map[string]string) string {
	t.Helper()
	var text string
	switch {
	case x.SDP != nil && x.Base == "":
		text = *x.SDP
	case x.SDP == nil:
		base, ok := table[x.Base]
		if !ok {
			t.Fatalf("%s: no text named %q", name, x.Base)
		}
		text = base
	default:
		t.Fatalf("%s: a text is a base or an sdp, not both", name)
	}
	if x.LF {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	for _, e := range x.Edits {
		if !strings.Contains(text, e.Old) {
			t.Fatalf("%s: the text does not hold %q", name, e.Old)
		}
		text = strings.Replace(text, e.Old, e.New, 1)
	}
	if x.Tail > 0 {
		text += "a=" + strings.Repeat("x", x.Tail) + "\r\n"
	}
	return text
}

func zzInline(s string) zzText { return zzText{SDP: &s} }

// zzTailFor is the Tail that makes text, with its CRLFs counted as one byte
// each, exactly size bytes long.
func zzTailFor(t *testing.T, text string, size int) int {
	t.Helper()
	n := size - len(strings.ReplaceAll(text, "\r\n", "\n")) - len("a=\n")
	if n <= 0 {
		t.Fatalf("no tail brings %d bytes to %d", len(text), size)
	}
	return n
}

// ---- shape.json ----

const (
	zzSessionID = int64(1234567890123456789)
	zzAudioSSRC = uint32(1234567890)
)

var zzShapeErrors = map[string]error{
	"ErrShapeNoCrypto":          ErrShapeNoCrypto,
	"ErrShapeNoPublish":         ErrShapeNoPublish,
	"ErrShapeSectionWithoutMID": ErrShapeSectionWithoutMID,
	"ErrShapeDirection":         ErrShapeDirection,
	"ErrShapeBundle":            ErrShapeBundle,
	"ErrShapeSDPTooLarge":       ErrShapeSDPTooLarge,
}

func zzShapeErrorName(t *testing.T, name string, err error) string {
	t.Helper()
	found := ""
	for label, sentinel := range zzShapeErrors {
		if errors.Is(err, sentinel) {
			if found != "" {
				t.Fatalf("%s: %v is two errors", name, err)
			}
			found = label
		}
	}
	if found == "" {
		t.Fatalf("%s: %v is none of the shaping errors", name, err)
	}
	return found
}

type zzShapeCase struct {
	Name   string `json:"name"`
	Offer  zzText `json:"offer"`
	Native zzText `json:"native"`
	// Is and Error are set when the first call refused: the engine's error
	// by its Go name, and its whole text. No second call is made then.
	Is    string `json:"is,omitempty"`
	Error string `json:"error,omitempty"`
	// Answer is the first call's result (o= version 2).
	Answer string `json:"answer,omitempty"`
	// The second call on the same state: its o= line, and its whole text's
	// length and SHA-256 (it is Answer with that one line changed).
	SecondO      string `json:"second_o,omitempty"`
	SecondLen    int    `json:"second_len,omitempty"`
	SecondSHA256 string `json:"second_sha256,omitempty"`
	// VersionAfter is the state's Version after the calls made.
	VersionAfter int `json:"version_after"`
}

func zzShape(t *testing.T) {
	t.Helper()
	offers := zzOffers(t)
	natives := map[string]string{
		"fixture": fixtureNative,
		// The msid and cname forms the engine's own peer writes
		// (transport/common: olcrtc-<hex8>, vp8channel-<hex8>).
		"pion_msid": strings.NewReplacer(
			"a=msid:proofkit video", "a=msid:olcrtc-1a2b3c4d vp8channel-5e6f7a8b",
			"cname:proofkit", "cname:olcrtc-1a2b3c4d").Replace(fixtureNative),
		"no_msid": strings.Replace(fixtureNative, "a=msid:proofkit video\r\n", "", 1),
	}
	fixture := func(edits ...zzEdit) zzText { return zzText{Base: "fixture", Edits: edits} }
	whole := zzText{Base: "fixture"}
	atBound := zzTailFor(t, fixtureOffer, maxSDPSize)
	nativeAtBound := zzTailFor(t, fixtureNative, maxSDPSize)
	cases := []zzShapeCase{
		{Name: "the answer test's offer and native", Offer: whole, Native: whole},
		{Name: "the offer completed for a WebRTC stack", Offer: zzText{Base: "pion"}, Native: whole},
		{Name: "a participant's section behind the publish slot", Offer: zzText{Base: "peer_after"}, Native: whole},
		{Name: "a participant's section ahead of the publish slot", Offer: zzText{Base: "peer_ahead"}, Native: whole},
		{Name: "the live numbering", Offer: zzText{Base: "live"}, Native: whole},
		{Name: "the engine's own msid and cname", Offer: whole, Native: zzText{Base: "pion_msid"}},
		{Name: "the engine's own msid and cname, the live numbering", Offer: zzText{Base: "live"}, Native: zzText{Base: "pion_msid"}},
		{Name: "a native answer with no msid line", Offer: whole, Native: zzText{Base: "no_msid"}},
		{Name: "a native answer with no msid line, the live numbering", Offer: zzText{Base: "live"}, Native: zzText{Base: "no_msid"}},
		{Name: "an msid line of one word is no msid line", Offer: whole,
			Native: fixture(zzEdit{"a=msid:proofkit video", "a=msid:proofkit"})},
		{Name: "bare line feeds in both", Offer: zzText{Base: "fixture", LF: true}, Native: zzText{Base: "fixture", LF: true}},
		{Name: "empty lines in the offer", Offer: fixture(zzEdit{"a=ice-lite\r\n", "a=ice-lite\r\n\r\n"}, zzEdit{"a=mid:3\r\n", "\r\na=mid:3\r\n\r\n"}), Native: whole},
		{Name: "no line end behind the offer's last line", Offer: fixture(zzEdit{"video-pat\r\n", "video-pat"}), Native: whole},
		{Name: "the first credentials of the native answer are taken", Offer: whole,
			Native: fixture(zzEdit{"a=mid:3\r\n", "a=mid:3\r\na=ice-ufrag:second\r\na=ice-pwd:secondsecond\r\na=fingerprint:sha-256 00:11\r\n"})},
		{Name: "a credential line with a space behind it is passed over", Offer: whole,
			Native: fixture(zzEdit{"a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n", "a=ice-ufrag:KdfaZFqRLOnUhmUW \r\n"},
				zzEdit{"a=ice-ufrag:KdfaZFqRLOnUhmUW\r\na=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\r\na=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\r\na=mid:3",
					"a=ice-ufrag:second\r\na=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\r\na=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\r\na=mid:3"})},
		{Name: "the first cname of the publish section is taken", Offer: whole,
			Native: fixture(zzEdit{"a=ssrc:3842537998 cname:proofkit\r\n", "a=ssrc:1 msid:proofkit video\r\na=ssrc:2 cname:first\r\na=ssrc:3 cname:second\r\n"})},
		{Name: "a second receive-only video section is a publish slot too", Offer: zzText{Base: "live", Edits: []zzEdit{
			{"a=sendonly\r\na=rtcp-mux\r\na=rtpmap:102 VP9/90000", "a=recvonly\r\na=rtcp-mux\r\na=rtpmap:102 VP9/90000"}}}, Native: whole},
		{Name: "an offer of exactly the bound, its CRLFs counted as one byte", Offer: zzText{Base: "fixture", Tail: atBound}, Native: whole},
		{Name: "a native answer of exactly the bound", Offer: whole, Native: zzText{Base: "fixture", Tail: nativeAtBound}},
		// Refused.
		{Name: "a native answer with nothing in it", Offer: whole, Native: zzInline("v=0")},
		{Name: "no ufrag", Offer: whole, Native: zzText{Base: "fixture", Edits: []zzEdit{
			{"a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n", ""}, {"a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n", ""}}}},
		{Name: "no password", Offer: whole, Native: zzText{Base: "fixture", Edits: []zzEdit{
			{"a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\r\n", ""}, {"a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\r\n", ""}}}},
		{Name: "no fingerprint", Offer: whole, Native: zzText{Base: "fixture", Edits: []zzEdit{
			{"a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\r\n", ""},
			{"a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\r\n", ""}}}},
		{Name: "an empty ufrag", Offer: whole, Native: zzText{Base: "fixture", Edits: []zzEdit{
			{"a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n", "a=ice-ufrag:\r\n"}, {"a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n", "a=ice-ufrag:\r\n"}}}},
		{Name: "no cname line in the publish section", Offer: whole, Native: fixture(zzEdit{"a=ssrc:3842537998 cname:proofkit\r\n", ""})},
		{Name: "the cname line in another section only", Offer: whole,
			Native: fixture(zzEdit{"a=ssrc:3842537998 cname:proofkit\r\n", ""}, zzEdit{"a=mid:0\r\n", "a=mid:0\r\na=ssrc:3842537998 cname:proofkit\r\n"})},
		{Name: "no send-only video section in the native answer", Offer: whole, Native: fixture(zzEdit{"a=sendonly", "a=sendrecv"})},
		{Name: "an SSRC past 32 bits", Offer: whole, Native: fixture(zzEdit{"a=ssrc:3842537998 cname", "a=ssrc:4294967296 cname"})},
		{Name: "no BUNDLE group", Offer: fixture(zzEdit{"a=group:BUNDLE 0 1 2 3 5\r\n", ""}), Native: whole},
		{Name: "a BUNDLE group with nothing behind it", Offer: fixture(zzEdit{"a=group:BUNDLE 0 1 2 3 5\r\n", "a=group:BUNDLE\r\n"}), Native: whole},
		{Name: "the first section has no mid", Offer: fixture(zzEdit{"a=mid:0\r\n", ""}), Native: whole},
		{Name: "the data section has no mid", Offer: fixture(zzEdit{"a=mid:1\r\n", ""}), Native: whole},
		{Name: "a mid with a space", Offer: fixture(zzEdit{"a=mid:3\r\n", "a=mid:3 4\r\n"}), Native: whole},
		{Name: "a video section both ways", Offer: fixture(zzEdit{"a=recvonly\r\na=rtcp-mux\r\na=rtpmap:102", "a=sendrecv\r\na=rtcp-mux\r\na=rtpmap:102"}), Native: whole},
		{Name: "an inactive audio section", Offer: fixture(zzEdit{"a=sendonly\r\n", "a=inactive\r\n"}), Native: whole},
		{Name: "a video section with no direction", Offer: fixture(zzEdit{"a=recvonly\r\na=rtcp-mux\r\na=rtpmap:102", "a=rtcp-mux\r\na=rtpmap:102"}), Native: whole},
		{Name: "an offer one byte past the bound", Offer: zzText{Base: "fixture", Tail: atBound + 1}, Native: whole},
		{Name: "a native answer one byte past the bound", Offer: whole, Native: zzText{Base: "fixture", Tail: nativeAtBound + 1}},
		{Name: "no native credentials is said before no BUNDLE group", Offer: fixture(zzEdit{"a=group:BUNDLE 0 1 2 3 5\r\n", ""}), Native: zzInline("v=0")},
		{Name: "no BUNDLE group is said before an offer past the bound", Offer: zzText{Base: "fixture",
			Edits: []zzEdit{{"a=group:BUNDLE 0 1 2 3 5\r\n", ""}}, Tail: atBound + 64}, Native: whole},
	}
	refused := 0
	for i := range cases {
		c := &cases[i]
		offer := c.Offer.build(t, c.Name, offers)
		native := c.Native.build(t, c.Name, natives)
		// Every audio publish slot of these offers is mid 2: with its SSRC
		// given, a call draws nothing at random.
		state := &ShapeState{SessionID: zzSessionID, AudioSSRC: map[string]uint32{"2": zzAudioSSRC}}
		first, err := ShapeAnswer(offer, native, state)
		if err != nil {
			refused++
			c.Is, c.Error, c.VersionAfter = zzShapeErrorName(t, c.Name, err), err.Error(), state.Version
			continue
		}
		second, err := ShapeAnswer(offer, native, state)
		if err != nil {
			t.Fatalf("%s: the second call: %v", c.Name, err)
		}
		if len(state.AudioSSRC) != 1 || state.AudioSSRC["2"] != zzAudioSSRC || state.SessionID != zzSessionID {
			t.Fatalf("%s: the state drew a value: %v", c.Name, state.AudioSSRC)
		}
		one, two := strings.Split(first, "\r\n"), strings.Split(second, "\r\n")
		if len(one) != len(two) || len(one) < 2 {
			t.Fatalf("%s: the two answers have %d and %d lines", c.Name, len(one), len(two))
		}
		for n := range one {
			if (one[n] != two[n]) != (n == 1) {
				t.Fatalf("%s: line %d of the two answers: %q and %q", c.Name, n, one[n], two[n])
			}
		}
		c.Answer, c.SecondO, c.SecondLen, c.SecondSHA256 = first, two[1], len(second), zzvectors.Sum([]byte(second))
		c.VersionAfter = state.Version
	}
	if refused != 21 {
		t.Fatalf("%d cases were refused, the list means 21", refused)
	}
	// A state as the engine makes it draws its values where the Go code says.
	fresh := NewShapeState()
	if _, err := ShapeAnswer(fixtureOffer, fixtureNative, fresh); err != nil {
		t.Fatal(err)
	}
	if id := fresh.SessionID; id < 1000000000000000000 || id >= 1800000000000000000 {
		t.Fatalf("a fresh session id is %d", id)
	}
	if ssrc := fresh.AudioSSRC["2"]; len(fresh.AudioSSRC) != 1 || ssrc < 1000000000 || ssrc >= 2000000000 {
		t.Fatalf("a fresh state's audio SSRCs are %v", fresh.AudioSSRC)
	}
	zzvectors.Write(t, "vkcalls/shape.json", zzGenerator,
		[]string{
			"internal/engine/vkcalls/answer.go:141-213 (ShapeAnswer)",
			"internal/engine/vkcalls/answer.go:229-290 (shapeSection), 293-302 (codecLines), 306-332 (videoPublishOf)",
			"internal/engine/vkcalls/answer.go:88-106 (splitSections: the 1 MiB bound), 108-139 (ShapeState)",
			"internal/engine/vkcalls/answer_test.go:12-98 (fixtureOffer, fixtureNative)",
			"internal/engine/vkcalls/negotiate_test.go:24-75, 251-308 (pionOffer, offerWithPeer, liveShapeOffer)",
		},
		struct {
			Note      string            `json:"note"`
			Text      string            `json:"text"`
			Bound     int               `json:"bound"`
			SessionID int64             `json:"session_id"`
			AudioSSRC map[string]uint32 `json:"audio_ssrc"`
			FreshID   []int64           `json:"fresh_session_id_range"`
			FreshSSRC []int64           `json:"fresh_audio_ssrc_range"`
			Offers    map[string]string `json:"offers"`
			Natives   map[string]string `json:"natives"`
			Cases     []zzShapeCase     `json:"cases"`
		}{
			"ShapeAnswer(offer, native, state), twice on one state made of session_id, Version 0 and audio_ssrc " +
				"(the SSRC of every audio publish slot here, so nothing is drawn at random). An answer's lines are " +
				"joined with CRLF and no line end follows the last.",
			"An offer or a native answer is: the text of the table named by base, or the text sdp; then with lf " +
				"every CRLF made a bare LF; then each edit replacing the first old by new; then with tail one more " +
				"line, a= and tail times the letter x and CRLF.",
			maxSDPSize, zzSessionID, map[string]uint32{"2": zzAudioSSRC},
			[]int64{1000000000000000000, 1800000000000000000}, []int64{1000000000, 2000000000},
			offers, natives, cases,
		})
}

// ---- view.json ----

type zzClaim struct {
	Kind string `json:"kind"`
	PT   uint8  `json:"pt"`
	Name string `json:"name"`
}

func zzClaims(memo *viewMemo) []zzClaim {
	out := []zzClaim{}
	for kind, known := range memo.claims {
		for pt, name := range known {
			out = append(out, zzClaim{kind, pt, name})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].PT < out[j].PT
	})
	return out
}

type zzViewCase struct {
	Name  string `json:"name"`
	Offer zzText `json:"offer"`
	// Publish is pionView's publish list; null is Go's nil.
	Publish []string `json:"publish"`
	View    string   `json:"view"`
	// Same says the view is the offer byte for byte.
	Same  bool   `json:"same"`
	Error string `json:"error,omitempty"`
}

type zzViewStep struct {
	Offer   zzText   `json:"offer"`
	Publish []string `json:"publish"`
	View    string   `json:"view"`
	// Claims is what the memo holds after the step, by kind and payload type.
	Claims []zzClaim `json:"claims"`
}

type zzViewChain struct {
	Name  string       `json:"name"`
	Steps []zzViewStep `json:"steps"`
}

type zzOfferFacts struct {
	Offer       string   `json:"offer"`
	PublishMid  string   `json:"publish_mid"`
	RemoteSSRCs []string `json:"remote_ssrcs"`
}

type zzPublishMidCase struct {
	Name string `json:"name"`
	SDP  string `json:"sdp"`
	Mid  string `json:"mid"`
}

type zzSSRCCase struct {
	Name  string   `json:"name"`
	SDP   string   `json:"sdp"`
	SSRCs []string `json:"ssrcs"`
}

type zzCodec struct {
	PT        uint8      `json:"pt"`
	Mime      string     `json:"mime"`
	ClockRate uint32     `json:"clock_rate"`
	Channels  uint16     `json:"channels"`
	Fmtp      string     `json:"fmtp"`
	Feedback  [][]string `json:"rtcp_fb"`
}

type zzCodecSection struct {
	Mid    string    `json:"mid"`
	Kind   string    `json:"kind"`
	Codecs []zzCodec `json:"codecs"`
}

type zzCodecTable struct {
	Name     string           `json:"name"`
	Offer    zzText           `json:"offer"`
	Publish  []string         `json:"publish"`
	Viewed   bool             `json:"viewed"`
	Sections []zzCodecSection `json:"sections"`
}

// zzCodecTableOf is registerSectionCodecs (negotiate.go:94-128) without its
// last step: the codecs it would hand the media engine, in its order.
func zzCodecTableOf(t *testing.T, sdp string) []zzCodecSection {
	t.Helper()
	sections, err := splitSections(sdp)
	if err != nil {
		t.Fatal(err)
	}
	out := []zzCodecSection{}
	for _, sec := range sections {
		head := strings.Fields(sec[0])
		if len(head) < 4 {
			continue
		}
		kind := strings.TrimPrefix(head[0], "m=")
		if kind != kindAudio && kind != kindVideo {
			continue
		}
		row := zzCodecSection{Mid: sec.mid(), Kind: kind, Codecs: []zzCodec{}}
		blocks := sectionCodecBlocks(sec)
		for _, payloadStr := range head[3:] {
			payload, err := strconv.ParseUint(payloadStr, 10, 8)
			if err != nil {
				continue
			}
			fields, ok := blocks[uint8(payload)]
			if !ok {
				continue
			}
			spec, ok := offerCodec(kind, fields, uint8(payload))
			if !ok {
				continue
			}
			codec := zzCodec{
				PT: uint8(spec.PayloadType), Mime: spec.MimeType, ClockRate: spec.ClockRate,
				Channels: spec.Channels, Fmtp: spec.SDPFmtpLine, Feedback: [][]string{},
			}
			for _, fb := range spec.RTCPFeedback {
				codec.Feedback = append(codec.Feedback, []string{fb.Type, fb.Parameter})
			}
			row.Codecs = append(row.Codecs, codec)
		}
		out = append(out, row)
	}
	return out
}

// zzView calls pionView eight times: Go walks its maps in a new order each
// time, and the view must not depend on it.
func zzView(t *testing.T, name, offer string, publish []string, memo func() *viewMemo) (string, *viewMemo, error) {
	t.Helper()
	first := memo()
	view, err := pionView(offer, publish, first)
	for range 7 {
		again := memo()
		got, gotErr := pionView(offer, publish, again)
		if got != view || (gotErr == nil) != (err == nil) {
			t.Fatalf("%s: two views of one offer differ", name)
		}
		if first != nil && fmt.Sprint(zzClaims(first)) != fmt.Sprint(zzClaims(again)) {
			t.Fatalf("%s: two memos of one offer differ", name)
		}
	}
	return view, first, err
}

func zzViewFile(t *testing.T) {
	t.Helper()
	offers := zzOffers(t)
	vp8 := vp8Publish()
	noMemo := func() *viewMemo { return nil }
	audioHead := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1\r\n"
	audio := func(mid, payloads string, lines ...string) string {
		return "m=audio 9 UDP/TLS/RTP/SAVPF " + payloads + "\r\nc=IN IP4 0.0.0.0\r\na=mid:" + mid +
			"\r\na=sendonly\r\na=rtcp-mux\r\n" + strings.Join(lines, "\r\n") + "\r\n"
	}
	cases := []zzViewCase{}
	for _, name := range []string{"fixture", "pion", "peer_after", "peer_ahead", "live"} {
		cases = append(cases,
			zzViewCase{Name: name + ", publishing VP8", Offer: zzText{Base: name}, Publish: vp8},
			zzViewCase{Name: name + ", no publish list", Offer: zzText{Base: name}})
	}
	cases = append(cases,
		zzViewCase{Name: "a codec name in upper case", Offer: zzText{Base: "live"}, Publish: []string{"VP8"}},
		zzViewCase{Name: "publishing what the slot does not name leaves the slot whole", Offer: zzText{Base: "live"}, Publish: []string{"av1"}},
		zzViewCase{Name: "publishing two codecs", Offer: zzText{Base: "live"}, Publish: []string{"vp8", "h264"}},
		zzViewCase{Name: "publishing red keeps the repair of red", Offer: zzText{Base: "live"}, Publish: []string{"red"}},
		zzViewCase{Name: "an empty publish list is no list", Offer: zzText{Base: "peer_ahead"}, Publish: []string{}},
		zzViewCase{Name: "bare line feeds", Offer: zzText{Base: "peer_ahead", LF: true}, Publish: vp8},
		zzViewCase{Name: "empty lines are dropped", Publish: vp8,
			Offer: zzText{Base: "pion", Edits: []zzEdit{{"a=ice-lite\r\n", "a=ice-lite\r\n\r\n"}, {"a=mid:3\r\n", "\r\na=mid:3\r\n\r\n"}}}},
		zzViewCase{Name: "no line end behind the last line", Publish: vp8,
			Offer: zzText{Base: "pion", Edits: []zzEdit{{"video-pat\r\n", "video-pat"}}}},
		zzViewCase{Name: "two receive-only video sections: the first moves, both are trimmed", Publish: vp8,
			Offer: zzText{Base: "peer_ahead", Edits: []zzEdit{{"a=sendonly\r\na=rtcp-mux\r\na=rtpmap:100 VP8/90000\r\na=rtcp-fb:100 nack\r\na=rtpmap:101",
				"a=recvonly\r\na=rtcp-mux\r\na=rtpmap:100 VP8/90000\r\na=rtcp-fb:100 nack\r\na=rtpmap:101"}}}},
		zzViewCase{Name: "a payload type that is no byte stays on the m line", Publish: vp8,
			Offer: zzText{Base: "live", Edits: []zzEdit{{"SAVPF 100 101 98 99 102 103 104\r\n", "SAVPF 100 101 98 99 102 103 104 300 x\r\n"}}}},
		zzViewCase{Name: "audio: the first section's meaning wins", Publish: vp8, Offer: zzInline(audioHead +
			audio("0", "111 8", "a=rtpmap:111 opus/48000/2", "a=fmtp:111 useinbandfec=1", "a=rtpmap:8 PCMA/8000") +
			audio("1", "111 8", "a=rtpmap:111 PCMU/8000", "a=rtcp-fb:111 nack", "a=rtpmap:8 pcma/8000"))},
		zzViewCase{Name: "audio: a section that would lose every payload type is left whole", Publish: vp8, Offer: zzInline(audioHead +
			audio("0", "111", "a=rtpmap:111 opus/48000/2") + audio("1", "111", "a=rtpmap:111 PCMU/8000"))},
		zzViewCase{Name: "a session with no media", Publish: vp8, Offer: zzInline("v=0\r\ns=-\r\nt=0 0\r\n")},
		zzViewCase{Name: "nothing", Publish: vp8, Offer: zzInline("")},
		// The view's own rules at their edges, on offers of a few lines.
		zzViewCase{Name: "edge: bare line feeds and blank lines, no publish list",
			Offer: zzInline("v=0\n\ns=-\nm=audio 9 X 0\n\na=mid:0\n")},
		zzViewCase{Name: "edge: a section that would keep no payload type stays whole", Publish: vp8,
			Offer: zzInline("m=video 9 UDP/TLS/RTP/SAVPF 102\r\na=mid:0\r\na=recvonly\r\na=rtpmap:102 VP9/90000\r\n")},
		zzViewCase{Name: "edge: a payload type with no rtpmap, a field that is no number, feedback for every payload", Publish: vp8,
			Offer: zzInline("m=video 9 UDP/TLS/RTP/SAVPF 100 x 101 102\r\na=mid:0\r\na=recvonly\r\na=rtpmap:100 VP8/90000\r\n" +
				"a=rtcp-fb:* nack\r\na=rtpmap:102 VP9/90000\r\na=rtcp-fb:102 nack\r\na=fmtp:102 profile-id=0\r\n")},
		zzViewCase{Name: "edge: a codec name is matched whole and in any case", Publish: []string{"VP8"},
			Offer: zzInline("m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\na=recvonly\r\na=rtpmap:100 vp8/90000\r\na=rtpmap:101 VP80/90000\r\n")},
		zzViewCase{Name: "edge: an rtx is kept by the payload it repairs", Publish: vp8,
			Offer: zzInline("m=video 9 UDP/TLS/RTP/SAVPF 100 101 102 103\r\na=recvonly\r\na=rtpmap:100 VP8/90000\r\n" +
				"a=rtpmap:101 rtx/90000\r\na=fmtp:101 rtx-time=200; apt=100\r\na=rtpmap:102 VP9/90000\r\n" +
				"a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\n")},
		zzViewCase{Name: "edge: audio is never a publish slot", Publish: vp8,
			Offer: zzInline("m=audio 9 X 111 0\r\na=recvonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n")},
		// With no publish list the view of this offer is the offer.
		zzViewCase{Name: "exactly the bound, its CRLFs counted as one byte",
			Offer: zzText{Base: "pion", Tail: zzTailFor(t, offers["pion"], maxSDPSize)}},
		zzViewCase{Name: "one byte past the bound",
			Offer: zzText{Base: "pion", Tail: zzTailFor(t, offers["pion"], maxSDPSize) + 1}},
	)
	for i := range cases {
		c := &cases[i]
		offer := c.Offer.build(t, c.Name, offers)
		view, _, err := zzView(t, c.Name, offer, c.Publish, noMemo)
		if err != nil {
			if !errors.Is(err, ErrShapeSDPTooLarge) {
				t.Fatalf("%s: %v", c.Name, err)
			}
			c.Error = err.Error()
			continue
		}
		c.Same = view == offer
		if len(view) > 16*zzvectors.LargeOutput {
			// The view of an offer at the bound: the offer again.
			if !c.Same {
				t.Fatalf("%s: a large view that is not its offer", c.Name)
			}
			continue
		}
		c.View = view
	}
	if !cases[3].Same || cases[3].Name != "pion, no publish list" {
		t.Fatal("the clean offer did not come back as it was")
	}

	chains := []zzViewChain{
		{Name: "a participant arrives in a second offer", Steps: []zzViewStep{
			{Offer: zzText{Base: "pion"}, Publish: vp8}, {Offer: zzText{Base: "peer_after"}, Publish: vp8}}},
		{Name: "a participant leaves, then the live numbering", Steps: []zzViewStep{
			{Offer: zzText{Base: "peer_ahead"}, Publish: vp8}, {Offer: zzText{Base: "pion"}, Publish: vp8}, {Offer: zzText{Base: "live"}, Publish: vp8}}},
		{Name: "the live numbering twice", Steps: []zzViewStep{
			{Offer: zzText{Base: "live"}, Publish: vp8}, {Offer: zzText{Base: "live"}, Publish: vp8}}},
		{Name: "the live numbering, then a participant", Steps: []zzViewStep{
			{Offer: zzText{Base: "live"}, Publish: vp8}, {Offer: zzText{Base: "peer_ahead"}, Publish: vp8}}},
		{Name: "no publish list, then one", Steps: []zzViewStep{
			{Offer: zzText{Base: "peer_ahead"}}, {Offer: zzText{Base: "peer_ahead"}, Publish: vp8}}},
		{Name: "no publish list: a participant arrives in a second offer", Steps: []zzViewStep{
			{Offer: zzText{Base: "pion"}}, {Offer: zzText{Base: "peer_after"}}}},
	}
	for i := range chains {
		chain := &chains[i]
		// What the memo held before a step, to give each of the eight calls
		// of that step a memo of its own.
		held := map[string]map[uint8]string{}
		for n := range chain.Steps {
			step := &chain.Steps[n]
			label := fmt.Sprintf("%s, step %d", chain.Name, n)
			offer := step.Offer.build(t, label, offers)
			view, memo, err := zzView(t, label, offer, step.Publish, func() *viewMemo {
				claims := map[string]map[uint8]string{}
				for kind, known := range held {
					claims[kind] = map[uint8]string{}
					for pt, codec := range known {
						claims[kind][pt] = codec
					}
				}
				return &viewMemo{claims: claims}
			})
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			step.View, step.Claims, held = view, zzClaims(memo), memo.claims
		}
	}

	facts := []zzOfferFacts{}
	for _, name := range []string{"fixture", "pion", "peer_after", "peer_ahead", "live"} {
		facts = append(facts, zzOfferFacts{name, publishMid(offers[name]), remoteSSRCs(offers[name])})
	}
	video := func(mid, direction string) string {
		return "m=video 9 UDP/TLS/RTP/SAVPF 100\r\na=mid:" + mid + "\r\na=" + direction + "\r\n"
	}
	mids := []zzPublishMidCase{
		{Name: "the first receive-only video section", SDP: "v=0\r\n" + video("4", "sendonly") + video("7", "recvonly") + video("9", "recvonly")},
		{Name: "bare line feeds", SDP: strings.ReplaceAll("v=0\r\n"+video("7", "recvonly"), "\r\n", "\n")},
		{Name: "a receive-only audio section is not it", SDP: "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\na=recvonly\r\n"},
		{Name: "no receive-only section", SDP: "v=0\r\n" + video("4", "sendonly") + video("5", "sendrecv")},
		{Name: "a receive-only video section with no mid", SDP: "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 100\r\na=recvonly\r\n" + video("7", "recvonly")},
		{Name: "the direction ahead of the mid", SDP: "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 100\r\na=recvonly\r\na=mid:video-0\r\n"},
		{Name: "the first direction line of a section decides", SDP: "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 100\r\na=mid:1\r\na=sendonly\r\na=recvonly\r\n"},
		{Name: "nothing", SDP: ""},
	}
	for i := range mids {
		mids[i].Mid = publishMid(mids[i].SDP)
	}
	ssrcs := []zzSSRCCase{
		{Name: "each SSRC once, in the order first seen", SDP: "a=ssrc:2 cname:a\r\na=ssrc:1 cname:b\r\na=ssrc:2 msid:a b\r\n"},
		{Name: "a carriage return behind the number counts", SDP: "a=ssrc:5\r\n"},
		{Name: "a line feed behind the number counts", SDP: "a=ssrc:5\n"},
		{Name: "a tab behind the number counts", SDP: "a=ssrc:5\tcname:a\r\n"},
		{Name: "nothing behind the number does not", SDP: "a=ssrc:5"},
		{Name: "a group line is not an attribution", SDP: "a=ssrc-group:FID 1 2\r\n"},
		{Name: "a space ahead of the line", SDP: " a=ssrc:5 cname:a\r\n"},
		{Name: "no number", SDP: "a=ssrc: cname:a\r\n"},
		{Name: "a number past 32 bits is kept as written", SDP: "a=ssrc:99999999999 cname:a\r\na=ssrc:007 cname:b\r\na=ssrc:7 cname:b\r\n"},
		{Name: "nothing", SDP: ""},
	}
	for i := range ssrcs {
		ssrcs[i].SSRCs = remoteSSRCs(ssrcs[i].SDP)
		if ssrcs[i].SSRCs == nil {
			ssrcs[i].SSRCs = []string{}
		}
	}

	odd := "v=0\r\n" +
		"m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8 9 13\r\na=mid:a\r\na=sendonly\r\n" +
		"a=fmtp:111 dropped=1\r\n" + // ahead of its rtpmap: not kept
		"a=rtpmap:111 opus/48000/2\r\na=rtcp-fb:111 transport-cc\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=fmtp:111 second=1\r\n" +
		"a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000/1\r\n" +
		"a=rtpmap:9 G722/99999999999\r\n" + // a rate past 32 bits: no codec
		"a=rtpmap:300 L16/8000\r\n" + // no byte: no codec
		"m=video 9 UDP/TLS/RTP/SAVPF 96 97 98\r\na=mid:v\r\na=sendonly\r\n" +
		"a=rtpmap:96 VP8/90000\r\na=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\na=rtcp-fb:96 ccm fir extra\r\na=rtcp-fb:96 goog-remb\r\n" +
		"a=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\n" +
		"a=rtpmap:98 VP8/90000 trailing\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:d\r\n" +
		"m=video 9 UDP/TLS/RTP/SAVPF\r\na=mid:none\r\n"
	tables := []zzCodecTable{
		{Name: "the view of the completed offer", Offer: zzText{Base: "pion"}, Publish: vp8, Viewed: true},
		{Name: "the view with a participant ahead", Offer: zzText{Base: "peer_ahead"}, Publish: vp8, Viewed: true},
		{Name: "the view of the live numbering", Offer: zzText{Base: "live"}, Publish: vp8, Viewed: true},
		{Name: "the answer test's offer as it is: a payload type with no rtpmap is no codec", Offer: zzText{Base: "fixture"}},
		{Name: "odd lines", Offer: zzInline(odd)},
	}
	for i := range tables {
		table := &tables[i]
		sdp := table.Offer.build(t, table.Name, offers)
		if table.Viewed {
			view, _, err := zzView(t, table.Name, sdp, table.Publish, noMemo)
			if err != nil {
				t.Fatal(err)
			}
			sdp = view
		}
		table.Sections = zzCodecTableOf(t, sdp)
	}

	zzvectors.Write(t, "vkcalls/view.json", zzGenerator,
		[]string{
			"internal/engine/vkcalls/negotiate.go:193-222 (pionView) and the functions below it to :456",
			"internal/engine/vkcalls/negotiate.go:30-62, 94-176 (offerCodec, registerSectionCodecs, sectionCodecBlocks)",
			"internal/engine/vkcalls/negotiate.go:510-520 (remoteSSRCs), stamp.go:68-80 (publishMid)",
			"internal/engine/vkcalls/negotiate_test.go (the offers; TestPionViewLeavesCleanOfferAlone, TestPionViewKeepsEveryMid, TestLiveShapeKeepsReceiveNumbering)",
		},
		struct {
			Note        string             `json:"note"`
			Text        string             `json:"text"`
			Bound       int                `json:"bound"`
			Offers      map[string]string  `json:"offers"`
			Views       []zzViewCase       `json:"views"`
			Chains      []zzViewChain      `json:"chains"`
			OfferFacts  []zzOfferFacts     `json:"offer_facts"`
			PublishMid  []zzPublishMidCase `json:"publish_mid"`
			RemoteSSRCs []zzSSRCCase       `json:"remote_ssrcs"`
			CodecTables []zzCodecTable     `json:"codec_tables"`
		}{
			"views: pionView(offer, publish, nil); a view is joined with CRLF and ends in CRLF. A view left out " +
				"(empty, with same true) is the offer itself. chains: the steps of a chain share one memo, as one " +
				"connection's offers do. codec_tables: the codecs registerSectionCodecs hands the WebRTC stack for " +
				"each audio and video section of the text (of its view when viewed), in its order.",
			"An offer is: the text of the table named by base, or the text sdp; then with lf every CRLF made a " +
				"bare LF; then each edit replacing the first old by new; then with tail one more line, a= and tail " +
				"times the letter x and CRLF.",
			maxSDPSize, offers, cases, chains, facts, mids, ssrcs, tables,
		})
}

// ---- msgpack.json ----

type zzIntCase struct {
	Value int64  `json:"value"`
	Hex   string `json:"hex"`
}

type zzSimulcastCase struct {
	Name     string `json:"name"`
	Sequence int    `json:"sequence"`
	Rid      string `json:"rid"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	FPS      int    `json:"fps"`
	Bitrate  int    `json:"bitrate"`
	Hex      string `json:"hex"`
}

type zzPerfCase struct {
	Sequence int    `json:"sequence"`
	Decoded  uint32 `json:"frames_decoded"`
	Received uint32 `json:"frames_received"`
	Hex      string `json:"hex"`
}

type zzEntry struct {
	// Key is null when the key's bytes are not UTF-8.
	Key       *string `json:"key"`
	KeyHex    string  `json:"key_hex"`
	Compact   uint8   `json:"compact"`
	ByCompact bool    `json:"by_compact"`
	Priority  int     `json:"priority"`
	Width     int     `json:"width"`
	Height    int     `json:"height"`
}

func zzEntryOf(e LayoutEntry) zzEntry {
	out := zzEntry{KeyHex: hex.EncodeToString([]byte(e.Key)), Compact: e.Compact, ByCompact: e.ByCompact,
		Priority: e.Priority, Width: e.Width, Height: e.Height}
	if utf8.ValidString(e.Key) {
		key := e.Key
		out.Key = &key
	}
	return out
}

func zzEntriesOf(entries []LayoutEntry) []zzEntry {
	out := make([]zzEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, zzEntryOf(e))
	}
	return out
}

type zzLayoutCase struct {
	Name     string `json:"name"`
	Sequence int    `json:"sequence"`
	// Entries, or for a long list Repeat: that many entries, entry i by
	// compact id i mod 256, priority 1, 640x360.
	Entries []zzEntry `json:"entries,omitempty"`
	Repeat  int       `json:"repeat,omitempty"`
	// Hex, or for a long frame its length and SHA-256.
	Hex    string `json:"hex,omitempty"`
	Len    int    `json:"len,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Is     string `json:"is,omitempty"`
	Error  string `json:"error,omitempty"`
}

type zzRegistryEntry struct {
	Key    *string `json:"key"`
	KeyHex string  `json:"key_hex"`
	ID     uint8   `json:"id"`
}

func zzRegistryOf(r Registry) []zzRegistryEntry {
	out := []zzRegistryEntry{}
	for _, key := range r.sortedStreams() {
		entry := zzRegistryEntry{KeyHex: hex.EncodeToString([]byte(key)), ID: r[key]}
		if utf8.ValidString(key) {
			text := key
			entry.Key = &text
		}
		out = append(out, entry)
	}
	return out
}

type zzOrderCase struct {
	Name         string            `json:"name"`
	Registry     []zzRegistryEntry `json:"registry"`
	Participants []string          `json:"participants"`
	Entries      []zzEntry         `json:"entries"`
}

type zzParseCase struct {
	Name  string `json:"name"`
	Frame string `json:"frame_hex"`
	// Registry in the keys' byte order; Is and Error when the frame is refused.
	Registry []zzRegistryEntry `json:"registry,omitempty"`
	Is       string            `json:"is,omitempty"`
	Error    string            `json:"error,omitempty"`
}

var zzControlErrors = map[string]error{
	"ErrRegistryShort":  ErrRegistryShort,
	"ErrRegistryShape":  ErrRegistryShape,
	"ErrNotRegistry":    ErrNotRegistry,
	"ErrLayoutNoStream": ErrLayoutNoStream,
	"ErrLayoutKeyLong":  ErrLayoutKeyLong,
	"ErrLayoutTooMany":  ErrLayoutTooMany,
}

func zzControlErrorName(t *testing.T, name string, err error) string {
	t.Helper()
	for label, sentinel := range zzControlErrors {
		if errors.Is(err, sentinel) {
			return label
		}
	}
	t.Fatalf("%s: %v is none of the control errors", name, err)
	return ""
}

func zzMsgpack(t *testing.T) {
	t.Helper()
	ints := []zzIntCase{}
	for _, v := range []int64{0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536, 1<<20 - 1, 1 << 20, 1<<31 - 1, 1 << 31,
		1<<32 - 1, 1 << 32, 1<<32 + 5, -1, -32, -33, -128, -32768, -32769, -(1 << 31), -(1 << 31) - 1} {
		ints = append(ints, zzIntCase{v, hex.EncodeToString(appendMPInt(nil, int(v)))})
	}

	w, h, fps, kbps := layerProfile()
	simulcast := []zzSimulcastCase{
		{Name: "the engine's call, the first command of a connection", Sequence: 1, Rid: "l", Width: w, Height: h, FPS: fps, Bitrate: kbps * 1000},
		{Name: "sequence 300", Sequence: 300, Rid: "l", Width: w, Height: h, FPS: fps, Bitrate: kbps * 1000},
		{Name: "a sequence past the other commands' modulus goes out whole", Sequence: 1<<20 + 1, Rid: "l", Width: w, Height: h, FPS: fps, Bitrate: kbps * 1000},
		{Name: "the bit rate is cut to whole kbit/s", Sequence: 2, Rid: "h", Width: 1280, Height: 720, FPS: 20, Bitrate: 1200999},
		{Name: "a longer rid, a bit rate under one kbit/s", Sequence: 127, Rid: "low", Width: 128, Height: 127, FPS: 0, Bitrate: 999},
	}
	for i := range simulcast {
		c := &simulcast[i]
		c.Hex = hex.EncodeToString(encodeChangeSimulcast(c.Sequence, c.Rid, c.Width, c.Height, c.FPS, c.Bitrate))
	}
	if simulcast[0].Hex != "0700010101a16cd10140d100b40fd100b4" {
		t.Fatalf("the engine's change-simulcast is %s", simulcast[0].Hex)
	}

	perf := []zzPerfCase{{1, 0, 0, ""}, {2, 127, 127, ""}, {3, 128, 128, ""}, {4, 40000, 40000, ""}, {5, 1<<32 - 1, 1<<32 - 1, ""},
		{6, 32767, 32768, ""}, {commandSeqMod - 1, 1 << 31, 1<<31 - 1, ""}, {0, 100, 7, ""}}
	for i := range perf {
		c := &perf[i]
		c.Hex = hex.EncodeToString(encodePerfStatReport(c.Sequence, c.Decoded, c.Received))
	}

	compact := func(n int) []LayoutEntry {
		out := make([]LayoutEntry, 0, n)
		for i := range n {
			out = append(out, LayoutEntry{Compact: uint8(i % 256), ByCompact: true, Priority: 1, Width: 640, Height: 360})
		}
		return out
	}
	type layoutIn struct {
		name     string
		sequence int
		entries  []LayoutEntry
		repeat   int
	}
	layoutIns := []layoutIn{
		{name: "TestEncodeLayoutGolden", sequence: 1, entries: []LayoutEntry{{Key: "u604532170515:sCAMERA", Compact: 0, ByCompact: true, Priority: 1, Width: 640, Height: 360}}},
		{name: "TestEncodeLayoutStringKey", sequence: 2, entries: []LayoutEntry{{Key: "42:sCAMERA", Priority: 0}}},
		{name: "15 entries: the short array header", sequence: 3, entries: compact(15)},
		{name: "16 entries: the long array header", sequence: 4, entries: compact(16)},
		{name: "17 entries", sequence: 5, entries: compact(17)},
		{name: "compact and string keys together", sequence: 6, entries: []LayoutEntry{
			{Key: "u1:sCAMERA", Compact: 3, ByCompact: true, Priority: 1, Width: 640, Height: 360},
			{Key: "u2:sCAMERA", Priority: 1, Width: 640, Height: 360}}},
		{name: "a compact id from 128 on is one raw byte", sequence: 7, entries: []LayoutEntry{
			{Compact: 127, ByCompact: true, Priority: 1, Width: 640, Height: 360},
			{Compact: 128, ByCompact: true, Priority: 1, Width: 640, Height: 360},
			{Compact: 255, ByCompact: true, Priority: 1, Width: 640, Height: 360}}},
		{name: "a size with one side zero is no size", sequence: 8, entries: []LayoutEntry{
			{Compact: 1, ByCompact: true, Priority: 1, Width: 640}, {Compact: 2, ByCompact: true, Priority: 1, Height: 360},
			{Compact: 3, ByCompact: true, Priority: 1, Width: -1, Height: 360}}},
		{name: "sizes and priorities on every side of the integer rule", sequence: 1 << 20, entries: []LayoutEntry{
			{Compact: 1, ByCompact: true, Priority: 127, Width: 127, Height: 128},
			{Compact: 2, ByCompact: true, Priority: 128, Width: 32767, Height: 32768},
			{Compact: 3, ByCompact: true, Priority: -1, Width: 1920, Height: 1080}}},
		{name: "a key of 31 bytes", sequence: 9, entries: []LayoutEntry{{Key: strings.Repeat("k", 31), Priority: 1, Width: 640, Height: 360}}},
		{name: "a key that is not UTF-8", sequence: 10, entries: []LayoutEntry{{Key: "u\xff:sCAMERA", Priority: 1, Width: 640, Height: 360}}},
		{name: "65535 entries", sequence: 11, repeat: 65535},
		// Refused.
		{name: "no entry", sequence: 1},
		{name: "a key of 32 bytes", sequence: 1, entries: []LayoutEntry{{Key: strings.Repeat("k", 32), Priority: 1}}},
		{name: "an entry with neither a compact id nor a key", sequence: 1, entries: []LayoutEntry{{Priority: 1, Width: 640, Height: 360}}},
		{name: "a refused entry behind a good one", sequence: 1, entries: []LayoutEntry{
			{Compact: 1, ByCompact: true, Priority: 1}, {Priority: 1}}},
		{name: "65536 entries", sequence: 1, repeat: 65536},
	}
	layouts := []zzLayoutCase{}
	for _, in := range layoutIns {
		c := zzLayoutCase{Name: in.name, Sequence: in.sequence, Repeat: in.repeat}
		entries := in.entries
		if in.repeat > 0 {
			entries = compact(in.repeat)
		} else {
			c.Entries = zzEntriesOf(entries)
		}
		frame, err := EncodeLayout(in.sequence, entries)
		switch {
		case err != nil:
			c.Is, c.Error = zzControlErrorName(t, in.name, err), err.Error()
		case len(frame) > zzvectors.LargeOutput:
			c.Len, c.SHA256 = len(frame), zzvectors.Sum(frame)
		default:
			c.Hex = hex.EncodeToString(frame)
		}
		layouts = append(layouts, c)
	}
	if layouts[0].Hex != "000001c091c40a000001d10280d1016800c0" || layouts[1].Hex != "000002c091c410aa34323a7343414d4552410000c0c000c0" {
		t.Fatalf("the engine's golden layouts are %s and %s", layouts[0].Hex, layouts[1].Hex)
	}

	orders := []zzOrderCase{}
	for _, in := range []struct {
		name         string
		registry     Registry
		participants []string
	}{
		{"TestLayoutEntriesAskUnknownCamerasByKey", Registry{"u1:sCAMERA": 0, "u3": 2}, []string{"3", "1", "2"}},
		{"TestRegistryLayoutFor", Registry{"b:sCAMERA": 1, "a:sCAMERA": 0}, nil},
		{"an empty registry and no participant", Registry{}, nil},
		{"an empty registry: every participant by key, in byte order", Registry{}, []string{"9", "10", "100", "1"}},
		{"registry keys in byte order: upper case first", Registry{"u2:sCAMERA": 5, "U2:sCAMERA": 6, "u10:sCAMERA": 7, "u1": 8, "u1:sSCREEN": 200}, []string{"2", "10"}},
		{"a participant named twice is asked twice", Registry{}, []string{"7", "7"}},
		{"a participant whose key would not fit is still listed", Registry{}, []string{strings.Repeat("9", 40)}},
	} {
		orders = append(orders, zzOrderCase{in.name, zzRegistryOf(in.registry), append([]string{}, in.participants...),
			zzEntriesOf(layoutEntries(in.registry, in.participants))})
	}

	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	parses := []zzParseCase{}
	for _, in := range []struct {
		name  string
		frame []byte
	}{
		// TestParseRegistry and TestParseRegistryOtherKind (control_test.go).
		{"camera stream compact 1 (a live capture)", cat([]byte{0x01, 0x81}, mpEntry("u588003930589:sCAMERA", 0x01))},
		{"three cameras in one frame", cat([]byte{0x01, 0x83}, mpEntry("u100000000001:sCAMERA", 0x00),
			mpEntry("u100000000002:sCAMERA", 0x01), mpEntry("u100000000003", 0x02))},
		{"map16 with a uint8 compact id", cat([]byte{0x01, 0xDE, 0x00, 0x02}, mpEntry("u1:sCAMERA", 0x05), mpStr("u2:sCAMERA"), []byte{0xCC, 0x80})},
		{"second entry truncated", cat([]byte{0x01, 0x82}, mpEntry("u1:sCAMERA", 0x00))},
		{"empty frame", nil},
		{"truncated", []byte{0x01, 0x01}},
		{"not a map", []byte{0x01, 0x90, 0x00}},
		{"another kind", []byte{0x02, 0x91, 0x00}},
		// More.
		{"another kind in one byte", []byte{0x06}},
		{"kind 0", []byte{0x00, 0x81, 0xA1, 0x61, 0x01}},
		{"kind 1 in one byte", []byte{0x01}},
		{"an empty map in three bytes is short", []byte{0x01, 0x80, 0x00}},
		{"an empty map in four bytes", []byte{0x01, 0x80, 0x00, 0x00}},
		{"not a map, four bytes", []byte{0x01, 0x90, 0x00, 0x00}},
		{"a 32-bit map header", []byte{0x01, 0xDF, 0x00, 0x00, 0x00, 0x00}},
		{"an empty map16", []byte{0x01, 0xDE, 0x00, 0x00}},
		{"bytes behind the last entry are not read", cat([]byte{0x01, 0x81}, mpEntry("u1", 0x07), []byte{0xFF, 0xFF})},
		{"a key given twice keeps the later id", cat([]byte{0x01, 0x82}, mpEntry("u1", 0x01), mpEntry("u1", 0x02))},
		{"an empty key", []byte{0x01, 0x81, 0xA0, 0x09}},
		{"a key of 31 bytes", cat([]byte{0x01, 0x81}, mpEntry(strings.Repeat("k", 31), 0x7F))},
		{"a key that is not UTF-8", cat([]byte{0x01, 0x81}, mpEntry("u\xff\xfe", 0x03))},
		{"the id 255 in the uint8 form", cat([]byte{0x01, 0x81}, mpStr("u1"), []byte{0xCC, 0xFF})},
		{"a small id in the uint8 form", cat([]byte{0x01, 0x81}, mpStr("u1"), []byte{0xCC, 0x05})},
		{"a key in the str8 form", []byte{0x01, 0x81, 0xD9, 0x02, 0x75, 0x31, 0x01}},
		{"a key that is a number", []byte{0x01, 0x81, 0x05, 0x01}},
		{"a key cut short", []byte{0x01, 0x81, 0xA5, 0x75, 0x31}},
		{"no id behind the key", cat([]byte{0x01, 0x81}, mpStr("u1:"))},
		{"the uint8 form cut short", cat([]byte{0x01, 0x81}, mpStr("u1:"), []byte{0xCC})},
		{"an id in the uint16 form", cat([]byte{0x01, 0x81}, mpStr("u1"), []byte{0xCD, 0x00, 0x01})},
		{"a negative id", cat([]byte{0x01, 0x81}, mpStr("u1"), []byte{0xFF})},
		{"a nil id", cat([]byte{0x01, 0x81}, mpStr("u1"), []byte{0xC0})},
		{"a map16 that names more entries than it holds", cat([]byte{0x01, 0xDE, 0x01, 0x00}, mpEntry("u1", 0x01))},
		{"sixteen entries in a map16", func() []byte {
			out := []byte{0x01, 0xDE, 0x00, 0x10}
			for i := range 16 {
				out = append(out, mpEntry(fmt.Sprintf("u%d:sCAMERA", 100+i), byte(i))...)
			}
			return out
		}()},
	} {
		c := zzParseCase{Name: in.name, Frame: hex.EncodeToString(in.frame)}
		registry, err := ParseRegistry(in.frame)
		if err != nil {
			c.Is, c.Error = zzControlErrorName(t, in.name, err), err.Error()
		} else {
			c.Registry = zzRegistryOf(registry)
		}
		parses = append(parses, c)
	}

	zzvectors.Write(t, "vkcalls/msgpack.json", zzGenerator,
		[]string{
			"internal/engine/vkcalls/control.go:171-186 (appendMPInt), 123-169 (EncodeLayout), 39-103 (ParseRegistry)",
			"internal/engine/vkcalls/control.go:188-234 (sortedStreams, cameraKey, layoutEntries, LayoutFor)",
			"internal/engine/vkcalls/stamp.go:82-121 (encodeChangeSimulcast, layerProfile, encodePerfStatReport)",
			"internal/engine/vkcalls/vkcalls.go:33, 351-365, 554-561, 599-617 (the sequence counter and its modulus)",
			"internal/engine/vkcalls/control_test.go (the frames of TestParseRegistry, the two golden layouts)",
		},
		struct {
			Note            string            `json:"note"`
			SequenceModulus int               `json:"sequence_modulus"`
			Layer           map[string]int    `json:"layer"`
			Ints            []zzIntCase       `json:"append_mp_int"`
			ChangeSimulcast []zzSimulcastCase `json:"change_simulcast"`
			PerfStat        []zzPerfCase      `json:"perf_stat_report"`
			Layout          []zzLayoutCase    `json:"encode_layout"`
			LayoutEntries   []zzOrderCase     `json:"layout_entries"`
			ParseRegistry   []zzParseCase     `json:"parse_registry"`
		}{
			"The producer command channel's bytes. A sequence is written as given: the engine sends its counter " +
				"modulo sequence_modulus in a layout and a perf report, and whole in change-simulcast. A registry " +
				"is listed in the byte order of its keys.",
			commandSeqMod, map[string]int{"width": w, "height": h, "fps": fps, "kbps": kbps},
			ints, simulcast, perf, layouts, orders, parses,
		})
}

// ---- stamp.json ----

type zzRecorder struct {
	header []byte
	exts   []zzExtension
	writes int
}

type zzExtension struct {
	ID  uint8  `json:"id"`
	Hex string `json:"hex"`
}

func (r *zzRecorder) Write(header *rtp.Header, _ []byte, _ interceptor.Attributes) (int, error) {
	raw, err := header.Marshal()
	if err != nil {
		return 0, err
	}
	r.header, r.writes = raw, r.writes+1
	r.exts = []zzExtension{}
	for _, id := range header.GetExtensionIDs() {
		r.exts = append(r.exts, zzExtension{id, hex.EncodeToString(header.GetExtension(id))})
	}
	return len(raw), nil
}

type zzNegotiated struct {
	URI string `json:"uri"`
	ID  int    `json:"id"`
}

type zzStampCase struct {
	Name string `json:"name"`
	Mime string `json:"mime"`
	// Negotiated is the stream's header extensions; Mid and Rid what the
	// stamper was made with.
	Negotiated []zzNegotiated `json:"negotiated"`
	Mid        string         `json:"mid"`
	Rid        string         `json:"rid"`
	// Before lists the extensions the header came with.
	Before []zzExtension `json:"before"`
	In     string        `json:"header_in_hex"`
	// Installed says the stamper put itself in front of the writer.
	Installed bool          `json:"installed"`
	Out       string        `json:"header_out_hex"`
	After     []zzExtension `json:"after"`
	// MidElement and RidElement are the extension elements the stamper left
	// in the header: null is none.
	MidElement *string `json:"mid_element_hex"`
	RidElement *string `json:"rid_element_hex"`
}

func zzStamp(t *testing.T) {
	t.Helper()
	const (
		midURI  = "urn:ietf:params:rtp-hdrext:sdes:mid"
		ridURI  = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
		astURI  = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
		twccURI = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
	)
	offer := liveShapeOffer()
	sections, err := splitSections(strings.ReplaceAll(offer, "\r\n", "\n"))
	if err != nil {
		t.Fatal(err)
	}
	slot := []zzNegotiated{}
	ids := map[string]int{}
	for _, sec := range sections {
		if !isPublishSlot(sec) {
			continue
		}
		for _, line := range sec {
			rest, ok := strings.CutPrefix(line, "a=extmap:")
			if !ok {
				continue
			}
			idText, uri, _ := strings.Cut(rest, " ")
			id, convErr := strconv.Atoi(idText)
			if convErr != nil {
				t.Fatalf("extmap line %q", line)
			}
			slot = append(slot, zzNegotiated{uri, id})
			ids[uri] = id
		}
		break
	}
	if ids[midURI] != 14 || ids[ridURI] != 10 || ids[astURI] != 3 || ids[twccURI] != 4 || len(slot) != 4 {
		t.Fatalf("the live publish slot's extensions are %v", slot)
	}
	mid := publishMid(offer)
	if mid != "3" {
		t.Fatalf("the live publish slot is mid %q", mid)
	}
	only := func(uris ...string) []zzNegotiated {
		out := []zzNegotiated{}
		for _, uri := range uris {
			out = append(out, zzNegotiated{uri, ids[uri]})
		}
		return out
	}
	twcc := zzExtension{uint8(ids[twccURI]), "002a"}
	cases := []zzStampCase{
		{Name: "the live publish slot, a header with no extension", Mime: "video/VP8", Negotiated: slot, Mid: mid, Rid: "l"},
		{Name: "the live publish slot, a header that came with an extension", Mime: "video/VP8", Negotiated: slot, Mid: mid, Rid: "l",
			Before: []zzExtension{twcc}},
		{Name: "a header that came with a mid and a rid: both are replaced where they stand", Mime: "video/VP8", Negotiated: slot, Mid: mid, Rid: "l",
			Before: []zzExtension{{uint8(ids[ridURI]), "68"}, twcc, {uint8(ids[midURI]), "3939"}}},
		{Name: "the mime type in another case", Mime: "VIDEO/vp8", Negotiated: slot, Mid: mid, Rid: "l"},
		{Name: "only the mid was negotiated", Mime: "video/VP8", Negotiated: only(midURI, twccURI), Mid: mid, Rid: "l"},
		{Name: "only the rid was negotiated", Mime: "video/VP8", Negotiated: only(ridURI), Mid: mid, Rid: "l"},
		{Name: "only abs-send-time was negotiated: installed, nothing written", Mime: "video/VP8", Negotiated: only(astURI), Mid: mid, Rid: "l"},
		{Name: "none of the three was negotiated", Mime: "video/VP8", Negotiated: only(twccURI), Mid: mid, Rid: "l"},
		{Name: "no extension was negotiated", Mime: "video/VP8", Negotiated: []zzNegotiated{}, Mid: mid, Rid: "l"},
		{Name: "an audio stream is left alone", Mime: "audio/opus", Negotiated: slot, Mid: mid, Rid: "l"},
		{Name: "an offer with no publish slot: no mid, the rid alone", Mime: "video/VP8", Negotiated: slot, Mid: "", Rid: "l"},
		{Name: "a longer mid", Mime: "video/VP8", Negotiated: slot, Mid: "video-12", Rid: "l"},
	}
	for i := range cases {
		c := &cases[i]
		stamper, err := sdesStamperFactory{mid: c.Mid, rid: c.Rid}.NewInterceptor("")
		if err != nil {
			t.Fatal(err)
		}
		info := &interceptor.StreamInfo{MimeType: c.Mime, SSRC: 0x0A0B0C0D}
		for _, ext := range c.Negotiated {
			info.RTPHeaderExtensions = append(info.RTPHeaderExtensions, interceptor.RTPHeaderExtension{URI: ext.URI, ID: ext.ID})
		}
		header := &rtp.Header{Version: 2, Marker: true, PayloadType: 100, SequenceNumber: 0x1234, Timestamp: 0x01020304, SSRC: 0x0A0B0C0D}
		if c.Before == nil {
			c.Before = []zzExtension{}
		}
		for _, ext := range c.Before {
			if err := header.SetExtension(ext.ID, zzvectors.MustHex(t, ext.Hex)); err != nil {
				t.Fatal(err)
			}
		}
		in, err := header.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		recorder := &zzRecorder{}
		writer := stamper.BindLocalStream(info, recorder)
		_, isRecorder := writer.(*zzRecorder)
		c.Installed = !isRecorder
		if _, err := writer.Write(header, []byte{0x90, 0x80, 0x01}, nil); err != nil {
			t.Fatal(err)
		}
		if recorder.writes != 1 {
			t.Fatalf("%s: the packet was written %d times", c.Name, recorder.writes)
		}
		c.In, c.Out, c.After = hex.EncodeToString(in), hex.EncodeToString(recorder.header), recorder.exts
		for _, ext := range c.After {
			value := ext.Hex
			for _, n := range c.Negotiated {
				if int(ext.ID) != n.ID {
					continue
				}
				switch n.URI {
				case midURI:
					c.MidElement = &value
				case ridURI:
					c.RidElement = &value
				}
			}
		}
	}
	zzvectors.Write(t, "vkcalls/stamp.json", zzGenerator,
		[]string{
			"internal/engine/vkcalls/stamp.go:26-66 (sdesStamper: BindLocalStream and its writer)",
			"internal/engine/vkcalls/negotiate.go:490-499 (where the stamper joins the interceptors: mid of the offer's publish slot, rid l)",
			"internal/engine/vkcalls/negotiate_test.go:251-308 (liveShapeOffer: the publish slot's extmap lines)",
			"github.com/pion/rtp v1.10.2 Header.SetExtension, Header.Marshal",
		},
		struct {
			Note  string        `json:"note"`
			Cases []zzStampCase `json:"cases"`
		}{
			"The engine's stamper bound to one stream (BindLocalStream) in front of a writer that keeps the header " +
				"it is handed, then one packet written through it. The header is pion's (version 2, marker, payload " +
				"type 100, sequence 0x1234, timestamp 0x01020304, SSRC 0x0a0b0c0d), marshalled before and after. " +
				"Only the mid and rid elements are the engine's; their place in the header and the header's other " +
				"bytes are pion's. abs-send-time is read to decide whether to install and never written.",
			cases,
		})
}

// ---- url.json ----

type zzURLCase struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	// URL is signalingURL's result; Error its error text when it refused.
	URL   string `json:"url"`
	Error string `json:"error,omitempty"`
	// Self is selfParticipant(endpoint), the session's own participant id.
	Self string `json:"self"`
}

type zzICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type zzICECase struct {
	Name string `json:"name"`
	// Raw is the provider's ice_servers text (Credentials.Extra).
	Raw     string        `json:"raw"`
	Servers []zzICEServer `json:"servers"`
}

func zzURL(t *testing.T) {
	t.Helper()
	// The endpoint of the auth provider's own test (auth/vkcalls/vkcalls_test.go:93).
	issued := "wss://videowebrtc.okcdn.ru/ws2?conversationId=c&peerId=10020030040&token=join-token&userId=100200300400&entityType=USER"
	cases := []zzURLCase{
		{Name: "the endpoint a join answers with", Endpoint: issued},
		{Name: "TestSignalingURL's endpoint", Endpoint: "wss://videowebrtc.okcdn.ru/ws2?userId=1&entityType=USER&conversationId=c&token=t"},
		{Name: "a test endpoint: ws and a port", Endpoint: "ws://127.0.0.1:8443/ws2?token=t&userId=42"},
		{Name: "no query", Endpoint: "wss://videowebrtc.okcdn.ru/ws2"},
		{Name: "an empty query", Endpoint: "wss://videowebrtc.okcdn.ru/ws2?"},
		{Name: "no path", Endpoint: "wss://videowebrtc.okcdn.ru?token=t"},
		{Name: "the seven values already there are replaced", Endpoint: "wss://h.okcdn.ru/ws2?platform=ANDROID&appVersion=9&version=1&device=phone&capabilities=FFFF&clientType=OK&tgt=start&token=t"},
		{Name: "a value given twice is replaced by one", Endpoint: "wss://h.okcdn.ru/ws2?tgt=a&tgt=b&token=t"},
		{Name: "a key given twice keeps both, in their order", Endpoint: "wss://h.okcdn.ru/ws2?userId=2&userId=1&token=t"},
		{Name: "what a query escapes", Endpoint: "wss://h.okcdn.ru/ws2?token=a%2Bb%2Fc%3Dd~e*f%20g+h&userId=%D0%9C"},
		{Name: "raw punctuation in a value", Endpoint: "wss://h.okcdn.ru/ws2?token=!'()*,:@$/?&userId=1"},
		{Name: "a key with no value and a key with an empty one", Endpoint: "wss://h.okcdn.ru/ws2?a&b=&userId=1"},
		{Name: "a pair with a semicolon is dropped", Endpoint: "wss://h.okcdn.ru/ws2?a=1;b=2&userId=1"},
		{Name: "a pair with a bad escape is dropped", Endpoint: "wss://h.okcdn.ru/ws2?a=%zz&userId=1"},
		{Name: "keys in upper case sort first", Endpoint: "wss://h.okcdn.ru/ws2?Zeta=1&alpha=2&Version=3"},
		{Name: "a fragment stays behind the query", Endpoint: "wss://h.okcdn.ru/ws2?token=t#frag"},
		{Name: "userinfo and an upper-case host stay", Endpoint: "wss://u:p@H.OKCDN.RU/ws2?token=t"},
		{Name: "an upper-case scheme is lowered", Endpoint: "WSS://h.okcdn.ru/ws2?token=t&userId=7"},
		{Name: "an escaped path stays as written", Endpoint: "wss://h.okcdn.ru/a%20b%2Fc?token=t"},
		// Refused.
		{Name: "https", Endpoint: "https://videowebrtc.okcdn.ru/ws2?token=t&userId=5"},
		{Name: "http", Endpoint: "http://127.0.0.1/ws2?userId=5"},
		{Name: "no scheme", Endpoint: "videowebrtc.okcdn.ru/ws2?token=t&userId=5"},
		{Name: "scheme-relative", Endpoint: "//videowebrtc.okcdn.ru/ws2?userId=5"},
		{Name: "empty", Endpoint: ""},
		{Name: "a control byte", Endpoint: "wss://h.okcdn.ru/ws2?userId=5\x7f"},
		{Name: "a scheme with nothing in front", Endpoint: "://nothing"},
	}
	for i := range cases {
		c := &cases[i]
		got, err := signalingURL(c.Endpoint)
		if err != nil {
			if !errors.Is(err, ErrSignalingEndpoint) {
				t.Fatalf("%s: %v", c.Name, err)
			}
			c.Error = err.Error()
		}
		c.URL, c.Self = got, selfParticipant(c.Endpoint)
	}
	if cases[0].Error != "" || !strings.Contains(cases[0].URL, "peerId=10020030040") {
		t.Fatalf("the issued endpoint became %q", cases[0].URL)
	}

	ice := []zzICECase{
		{Name: "what the provider writes for the join of its own test", Raw: `[{"urls":["stun:stun.example:3478"]},{"credential":"c","urls":["turn:91.231.135.155:19302","turn:91.231.135.179:19302"],"username":"u"}]`},
		{Name: "no server", Raw: `[]`},
		{Name: "an entry with no urls is skipped", Raw: `[{"username":"u","credential":"c"},{"urls":[]},{"urls":["turns:t.example:443?transport=tcp"],"username":"u2","credential":"c2"}]`},
		{Name: "unknown keys are passed over", Raw: `[{"urls":["turn:t.example:3478?transport=udp"],"username":"u","credential":"c","ttl":600}]`},
		{Name: "urls as one string: the whole text is refused", Raw: `[{"urls":["stun:a.example"]},{"urls":"turn:b.example"}]`},
		{Name: "a credential that is no string: the whole text is refused", Raw: `[{"urls":["turn:b.example"],"username":"u","credential":5}]`},
		{Name: "an object, not a list", Raw: `{"urls":["stun:a.example"]}`},
		{Name: "null", Raw: `null`},
		{Name: "empty", Raw: ``},
		{Name: "not JSON", Raw: `stun:a.example`},
	}
	for i := range ice {
		c := &ice[i]
		c.Servers = []zzICEServer{}
		for _, server := range iceServersOf(c.Raw) {
			credential, ok := server.Credential.(string)
			if !ok {
				t.Fatalf("%s: a credential of type %T", c.Name, server.Credential)
			}
			c.Servers = append(c.Servers, zzICEServer{server.URLs, server.Username, credential})
		}
	}

	zzvectors.Write(t, "vkcalls/url.json", zzGenerator,
		[]string{
			"internal/engine/vkcalls/signaling.go:148-165 (signalingURL), 167-173 (selfParticipant), 58-62 (the capabilities value)",
			"internal/engine/vkcalls/vkcalls.go:837-856 (iceServersOf)",
			"internal/engine/vkcalls/signaling_test.go:168-181 (TestSignalingURL)",
			"the link and the credentials of a join are in vkcalls/url_auth.json (the auth provider's package)",
		},
		struct {
			Note         string      `json:"note"`
			SignalingURL []zzURLCase `json:"signaling_url"`
			ICEServers   []zzICECase `json:"ice_servers_of"`
		}{
			"signaling_url: the URL the socket is dialled at for a join endpoint; the query is written again, its " +
				"keys in byte order, and a peerId in the endpoint stays. ice_servers_of: the servers the engine " +
				"reads from the provider's ice_servers text; a text it cannot read gives none.",
			cases, ice,
		})
}

func TestZZVectors(t *testing.T) {
	zzShape(t)
	zzViewFile(t)
	zzMsgpack(t)
	zzURL(t)
	zzStamp(t)
	zzFrames(t)
}

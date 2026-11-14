//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package handshake

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzConstants struct {
	ProtoVersion     int    `json:"proto_version"`
	ChallengeSize    int    `json:"challenge_size"`
	MaxMessageSize   int    `json:"max_message_size"`
	DefaultTimeoutMS int64  `json:"default_timeout_ms"`
	TypeHello        string `json:"type_hello"`
	TypeWelcome      string `json:"type_welcome"`
	TypeReject       string `json:"type_reject"`
}

type zzHelloCase struct {
	Name        string `json:"name"`
	DeviceIDHex string `json:"device_id_hex,omitempty"`
	DeviceFill  string `json:"device_id_fill,omitempty"`
	DeviceLen   int    `json:"device_id_len"`
	Challenge   string `json:"challenge"`
	Verdict     string `json:"verdict"`
	Frame       string `json:"frame,omitempty"`
	FrameSHA256 string `json:"frame_sha256,omitempty"`
	FrameLen    int    `json:"frame_len"`
}

type zzHelloFile struct {
	Constants zzConstants   `json:"constants"`
	Cases     []zzHelloCase `json:"cases"`
}

type zzServerCase struct {
	Name        string `json:"name"`
	Input       string `json:"input"`
	PeerID      string `json:"peer_id"`
	SessionID   string `json:"session_id"`
	AuthError   string `json:"auth_error,omitempty"`
	Verdict     string `json:"verdict"`
	Reply       string `json:"reply,omitempty"`
	ReplyText   string `json:"reply_text,omitempty"`
	DeviceIDHex string `json:"device_id_hex,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
}

type zzClientCase struct {
	Name      string `json:"name"`
	Challenge string `json:"challenge"`
	Input     string `json:"input"`
	Skipped   int    `json:"skipped"`
	Verdict   string `json:"verdict"`
	SessionID string `json:"session_id,omitempty"`
	PeerID    string `json:"peer_id,omitempty"`
	ErrorText string `json:"error_text,omitempty"`
}

const (
	zzChallengeA = "00112233445566778899aabbccddeeff"
	zzChallengeB = "ffeeddccbbaa99887766554433221100"
)

func zzVerdict(err error) string {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrRejected):
		return "rejected"
	case errors.Is(err, ErrProtocolVersion):
		return "protocol_version"
	case errors.Is(err, ErrUnexpectedMessage):
		return "unexpected_message"
	case errors.Is(err, ErrChallengeMismatch):
		return "challenge_mismatch"
	case errors.Is(err, ErrChallengeRequired):
		return "challenge_required"
	case errors.Is(err, ErrFrameTooLarge):
		return "frame_too_large"
	case errors.As(err, &syntax), errors.As(err, &typeErr):
		return "parse"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "read"
	case strings.HasPrefix(err.Error(), "auth: "):
		return "auth"
	default:
		return "other: " + err.Error()
	}
}

// zzHello frames a hello exactly as Client does (handshake.go:117-124).
func zzHello(deviceID, challenge string) ([]byte, error) {
	var buf bytes.Buffer
	err := writeFrame(&buf, Hello{
		Version:   ProtoVersion,
		Type:      TypeHello,
		DeviceID:  deviceID,
		Challenge: challenge,
		Claims:    nil,
	})
	return buf.Bytes(), err
}

func zzFrame(t *testing.T, msg any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := writeFrame(&buf, msg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zzRawFrame(body string) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

type zzRW struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (b *zzRW) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *zzRW) Write(p []byte) (int, error) { return b.w.Write(p) }

func TestZZVectors(t *testing.T) {
	t.Run("hello", zzHelloVectors)
	t.Run("server", zzServerVectors)
	t.Run("client", zzClientVectors)
}

func zzHelloVectors(t *testing.T) {
	file := zzHelloFile{Constants: zzConstants{
		ProtoVersion: ProtoVersion, ChallengeSize: challengeSize, MaxMessageSize: MaxMessageSize,
		DefaultTimeoutMS: DefaultTimeout.Milliseconds(),
		TypeHello:        string(TypeHello), TypeWelcome: string(TypeWelcome), TypeReject: string(TypeReject),
	}}
	ids := []struct{ name, id string }{
		{"empty device id", ""},
		{"an iOS client id", "8F2A5C1E-3B4D-4E6F-9A1B-2C3D4E5F6A7B"},
		{"quote and backslash", `a"b\c/d`},
		{"html characters", "<script>&amp;</script>"},
		{"control characters", "\x00\x01\b\f\n\r\t\x1f"},
		{"delete", "a\x7fb"},
		{"line and paragraph separators", "x\u2028y\u2029z"},
		{"non-ascii", "Ünïcödé 日本 🙂"},
		{"a real U+FFFD", "a\uFFFDb"},
		{"invalid utf-8", "a\xffb\xc3(\xe2\x82\xf0\x9f\x98c\xed\xa0\x80d"},
	}
	for _, c := range ids {
		frame, err := zzHello(c.id, zzChallengeA)
		hc := zzHelloCase{Name: c.name, DeviceIDHex: zzvectors.Hex([]byte(c.id)), DeviceLen: len(c.id),
			Challenge: zzChallengeA, Verdict: zzVerdict(err), Frame: zzvectors.Hex(frame), FrameLen: len(frame)}
		file.Cases = append(file.Cases, hc)
	}
	// The largest hello the server reads, and one byte more (handshake.go:44).
	empty, err := zzHello("", zzChallengeB)
	if err != nil {
		t.Fatal(err)
	}
	fit := MaxMessageSize - (len(empty) - 4)
	for _, n := range []int{fit, fit + 1} {
		frame, err := zzHello(strings.Repeat("a", n), zzChallengeB)
		hc := zzHelloCase{Name: "size limit", DeviceFill: "a", DeviceLen: n, Challenge: zzChallengeB,
			Verdict: zzVerdict(err), FrameLen: len(frame)}
		if err == nil {
			hc.FrameSHA256 = zzvectors.Sum(frame)
		}
		file.Cases = append(file.Cases, hc)
	}
	zzvectors.Write(t, "handshake/hello.json", "internal/handshake/zz_vectors_test.go zzHelloVectors",
		[]string{"internal/handshake/handshake.go:32-69", "internal/handshake/handshake.go:110-126",
			"internal/handshake/handshake.go:263-268", "internal/framing/framing.go:23-52"}, file)
}

func zzServerVectors(t *testing.T) {
	hello := func(id, challenge string) []byte {
		frame, err := zzHello(id, challenge)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	cases := []struct {
		name, peer, session, authErr string
		input                        []byte
	}{
		{"welcome with a peer id", "0000beef", "5f0c8d7e-1a2b-4c3d-8e9f-0a1b2c3d4e5f", "", hello("dev-1", zzChallengeA)},
		{"welcome without a peer id", "", "sess-2", "", hello("dev-2", zzChallengeB)},
		{"auth refuses", "0000beef", "", `access denied for "dev-3" <x&y>`, hello("dev-3", zzChallengeA)},
		{"an uppercase challenge is valid hex", "1", "sess-4", "", hello("dev-4", strings.ToUpper(zzChallengeA))},
		{"challenge too short", "1", "sess-5", "", hello("dev-5", zzChallengeA[:30])},
		{"challenge not hex", "1", "sess-6", "", hello("dev-6", "zz112233445566778899aabbccddeeff")},
		{"challenge missing", "1", "sess-7", "", zzRawFrame(`{"version":3,"type":"CLIENT_HELLO","device_id":"dev-7"}`)},
		{"version 2", "1", "sess-8", "", zzRawFrame(`{"version":2,"type":"CLIENT_HELLO","device_id":"dev-8","challenge":"` + zzChallengeA + `"}`)},
		{"wrong type", "1", "sess-9", "", zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","challenge":"` + zzChallengeA + `"}`)},
		{"malformed json", "1", "sess-10", "", zzRawFrame(`{"version":3,`)},
		{"claims are accepted", "1", "sess-11", "", zzRawFrame(`{"version":3,"type":"CLIENT_HELLO","device_id":"dev-11","challenge":"` + zzChallengeA + `","claims":{"tier":"pro","n":1}}`)},
		{"frame above the limit", "1", "sess-12", "", []byte{0, 1, 0, 1}},
	}
	var out []zzServerCase
	for _, c := range cases {
		rw := &zzRW{r: bytes.NewReader(c.input)}
		auth := func(string, map[string]any) (string, error) {
			if c.authErr != "" {
				return "", errors.New(c.authErr)
			}
			return c.session, nil
		}
		h, _, err := Server(rw, auth, c.peer)
		sc := zzServerCase{Name: c.name, Input: zzvectors.Hex(c.input), PeerID: c.peer, SessionID: c.session,
			AuthError: c.authErr, Verdict: zzVerdict(err), Reply: zzvectors.Hex(rw.w.Bytes()),
			DeviceIDHex: zzvectors.Hex([]byte(h.DeviceID)), Challenge: h.Challenge}
		if rw.w.Len() > 4 {
			sc.ReplyText = string(rw.w.Bytes()[4:])
		}
		out = append(out, sc)
	}
	zzvectors.Write(t, "handshake/server.json", "internal/handshake/zz_vectors_test.go zzServerVectors",
		[]string{"internal/handshake/handshake.go:203-261"}, out)
}

// zzClientRun is Client's reply loop (handshake.go:128-135) over recorded
// replies: replies to another challenge are skipped.
func zzClientRun(input []byte, challenge string) (string, string, int, error) {
	r := bytes.NewReader(input)
	skipped := 0
	for {
		sessionID, peerID, matched, err := readReply(r, challenge)
		if !matched {
			skipped++
			continue
		}
		return sessionID, peerID, skipped, err
	}
}

func zzClientVectors(t *testing.T) {
	welcome := func(challenge, session, peer string) []byte {
		return zzFrame(t, Welcome{Version: ProtoVersion, Type: TypeWelcome, SessionID: session, PeerID: peer, Challenge: challenge})
	}
	reject := func(challenge, reason string) []byte {
		return zzFrame(t, Reject{Version: ProtoVersion, Type: TypeReject, Reason: reason, Challenge: challenge})
	}
	cat := func(frames ...[]byte) []byte { return bytes.Join(frames, nil) }
	cases := []struct {
		name  string
		input []byte
	}{
		{"welcome", welcome(zzChallengeA, "sess-1", "0000beef")},
		{"welcome without a peer id", welcome(zzChallengeA, "sess-2", "")},
		{"a stale welcome is skipped", cat(welcome(zzChallengeB, "old", "1"), welcome(zzChallengeA, "sess-3", "2"))},
		{"two stale replies, then ours", cat(reject(zzChallengeB, "old"), welcome("", "x", "y"), welcome(zzChallengeA, "sess-4", "3"))},
		{"reject", reject(zzChallengeA, "access denied")},
		{"a reject with no challenge is someone else's", cat(reject("", "protocol version mismatch"), welcome(zzChallengeA, "sess-5", "4"))},
		{"only stale replies, then the stream ends", reject(zzChallengeB, "old")},
		{"version 2 welcome", zzRawFrame(`{"version":2,"type":"SERVER_WELCOME","session_id":"s","challenge":"` + zzChallengeA + `"}`)},
		{"a hello comes back", zzRawFrame(`{"version":3,"type":"CLIENT_HELLO","device_id":"d","challenge":"` + zzChallengeA + `"}`)},
		{"an unknown type", zzRawFrame(`{"version":3,"type":"SERVER_HELLO","challenge":"` + zzChallengeA + `"}`)},
		{"no type", zzRawFrame(`{"version":3,"challenge":"` + zzChallengeA + `"}`)},
		{"extra fields are ignored", zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","session_id":"s6","peer_id":"p6","challenge":"` + zzChallengeA + `","extra":[1,{"a":null}]}`)},
		{"a null challenge is not ours", cat(zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","challenge":null}`), welcome(zzChallengeA, "sess-7", ""))},
		{"null fields read as empty", zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","session_id":null,"peer_id":null,"challenge":"` + zzChallengeA + `"}`)},
		{"escaped strings", zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","session_id":"aA\n\"\\\/","peer_id":"é🙂","challenge":"` + zzChallengeA + `"}`)},
		{"escaped unicode and a surrogate pair", zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","session_id":"\u00e9\ud83d\ude42","peer_id":"\u0041","challenge":"` + zzChallengeA + `"}`)},
		{"malformed json", zzRawFrame(`{"version":3,"type":`)},
		{"a challenge that is not a string", zzRawFrame(`{"version":3,"type":"SERVER_WELCOME","challenge":7}`)},
		{"a version that is not an integer", zzRawFrame(`{"version":3.5,"type":"SERVER_WELCOME","challenge":"` + zzChallengeA + `"}`)},
		{"frame above the limit", []byte{0, 1, 0, 1}},
		{"the stream ends inside a frame", welcome(zzChallengeA, "sess-8", "")[:10]},
		{"nothing at all", nil},
	}
	var out []zzClientCase
	for _, c := range cases {
		sessionID, peerID, skipped, err := zzClientRun(c.input, zzChallengeA)
		cc := zzClientCase{Name: c.name, Challenge: zzChallengeA, Input: zzvectors.Hex(c.input), Skipped: skipped,
			Verdict: zzVerdict(err), SessionID: sessionID, PeerID: peerID}
		if err != nil {
			cc.ErrorText = err.Error()
		}
		out = append(out, cc)
	}
	zzvectors.Write(t, "handshake/client.json", "internal/handshake/zz_vectors_test.go zzClientVectors",
		[]string{"internal/handshake/handshake.go:110-192"}, out)
}

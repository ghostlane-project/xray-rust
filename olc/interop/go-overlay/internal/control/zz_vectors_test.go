//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzConstants struct {
	ProtoVersion      int    `json:"proto_version"`
	MaxMessageSize    int    `json:"max_message_size"`
	DefaultIntervalMS int64  `json:"default_interval_ms"`
	DefaultTimeoutMS  int64  `json:"default_timeout_ms"`
	DefaultFailures   int    `json:"default_failures"`
	MaxStalledProbes  int    `json:"max_stalled_probes"`
	TypePing          string `json:"type_ping"`
	TypePong          string `json:"type_pong"`
	TypeClose         string `json:"type_close"`
}

type zzEncodeCase struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Seq          uint64 `json:"seq"`
	SentUnixNano int64  `json:"sent_unix_nano"`
	Frame        string `json:"frame"`
	Body         string `json:"body"`
}

type zzParseCase struct {
	Name         string `json:"name"`
	Input        string `json:"input"`
	Verdict      string `json:"verdict"`
	Version      int    `json:"version"`
	Type         string `json:"type"`
	Seq          uint64 `json:"seq"`
	SentUnixNano int64  `json:"sent_unix_nano"`
}

type zzFile struct {
	Constants zzConstants    `json:"constants"`
	Encode    []zzEncodeCase `json:"encode"`
	Parse     []zzParseCase  `json:"parse"`
}

func zzVerdict(err error) string {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrProtocolVersion):
		return "protocol_version"
	case errors.Is(err, ErrUnexpectedMessage):
		return "unexpected_message"
	case errors.Is(err, ErrFrameTooLarge):
		return "frame_too_large"
	case errors.As(err, &syntax), errors.As(err, &typeErr):
		return "parse"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "read"
	default:
		return "other: " + err.Error()
	}
}

func zzRawFrame(body string) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

func TestZZVectors(t *testing.T) {
	file := zzFile{Constants: zzConstants{
		ProtoVersion: ProtoVersion, MaxMessageSize: MaxMessageSize,
		DefaultIntervalMS: DefaultInterval.Milliseconds(), DefaultTimeoutMS: DefaultTimeout.Milliseconds(),
		DefaultFailures: DefaultFailures, MaxStalledProbes: maxStalledProbes,
		TypePing: string(TypePing), TypePong: string(TypePong), TypeClose: string(TypeClose),
	}}
	// The messages the loop writes: a probe (control.go:385-390), the pong
	// that echoes it (:295-307) and the close notice (:485-488).
	msgs := []struct {
		name string
		msg  Message
	}{
		{"first ping", Message{Version: ProtoVersion, Type: TypePing, Seq: 1, SentUnixNano: 1762726967123456789}},
		{"its pong", Message{Version: ProtoVersion, Type: TypePong, Seq: 1, SentUnixNano: 1762726967123456789}},
		{"largest seq", Message{Version: ProtoVersion, Type: TypePing, Seq: math.MaxUint64, SentUnixNano: math.MaxInt64}},
		{"negative clock", Message{Version: ProtoVersion, Type: TypePong, Seq: 7, SentUnixNano: math.MinInt64}},
		{"zero fields are omitted", Message{Version: ProtoVersion, Type: TypePong}},
	}
	for _, m := range msgs {
		var buf bytes.Buffer
		if err := writeFrame(&buf, m.msg); err != nil {
			t.Fatal(err)
		}
		file.Encode = append(file.Encode, zzEncodeCase{Name: m.name, Type: string(m.msg.Type), Seq: m.msg.Seq,
			SentUnixNano: m.msg.SentUnixNano, Frame: zzvectors.Hex(buf.Bytes()), Body: string(buf.Bytes()[4:])})
	}
	var closing bytes.Buffer
	if err := SendClose(&closing); err != nil {
		t.Fatal(err)
	}
	file.Encode = append(file.Encode, zzEncodeCase{Name: "close", Type: string(TypeClose),
		Frame: zzvectors.Hex(closing.Bytes()), Body: string(closing.Bytes()[4:])})

	inputs := []struct {
		name  string
		input []byte
	}{
		{"ping", zzRawFrame(`{"version":1,"type":"CONTROL_PING","seq":3,"sent_unix_nano":42}`)},
		{"pong without fields", zzRawFrame(`{"version":1,"type":"CONTROL_PONG"}`)},
		{"close", zzRawFrame(`{"version":1,"type":"CONTROL_CLOSE"}`)},
		{"negative clock", zzRawFrame(`{"version":1,"type":"CONTROL_PONG","seq":18446744073709551615,"sent_unix_nano":-9223372036854775808}`)},
		{"version 2", zzRawFrame(`{"version":2,"type":"CONTROL_PING","seq":1}`)},
		{"no version", zzRawFrame(`{"type":"CONTROL_PING","seq":1}`)},
		{"an unknown type", zzRawFrame(`{"version":1,"type":"CONTROL_RESET"}`)},
		{"no type", zzRawFrame(`{"version":1,"seq":1}`)},
		{"extra fields", zzRawFrame(`{"version":1,"type":"CONTROL_PING","seq":9,"extra":{"x":[1,2]}}`)},
		{"null fields read as zero", zzRawFrame(`{"version":1,"type":"CONTROL_PING","seq":null,"sent_unix_nano":null}`)},
		{"a negative seq", zzRawFrame(`{"version":1,"type":"CONTROL_PING","seq":-1}`)},
		{"seq above uint64", zzRawFrame(`{"version":1,"type":"CONTROL_PING","seq":18446744073709551616}`)},
		{"a fractional clock", zzRawFrame(`{"version":1,"type":"CONTROL_PING","seq":1,"sent_unix_nano":1.5}`)},
		{"malformed json", zzRawFrame(`{"version":1,`)},
		{"a frame of the limit's length is read", []byte{0, 0, 0x40, 0x00}},
		{"a frame above the limit", []byte{0, 0, 0x40, 0x01}},
		{"the stream ends", nil},
	}
	for _, in := range inputs {
		msg, err := ZZReadMessage(bytes.NewReader(in.input))
		pc := zzParseCase{Name: in.name, Verdict: zzVerdict(err), Version: msg.Version, Type: string(msg.Type),
			Seq: msg.Seq, SentUnixNano: msg.SentUnixNano}
		pc.Input = zzvectors.Hex(in.input)
		file.Parse = append(file.Parse, pc)
	}
	zzvectors.Write(t, "control.json", "internal/control/zz_vectors_test.go TestZZVectors",
		[]string{"internal/control/control.go:23-113", "internal/control/control.go:295-307",
			"internal/control/control.go:470-498"}, file)
}

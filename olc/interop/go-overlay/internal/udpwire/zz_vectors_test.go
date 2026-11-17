//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package udpwire

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzConstants struct {
	Version        int    `json:"version"`
	MaxPayloadSize int    `json:"max_payload_size"`
	MaxHostLen     int    `json:"max_host_len"`
	HeaderLen      int    `json:"header_len"`
	Magic          string `json:"magic"`
}

type zzEncodeCase struct {
	Name    string `json:"name"`
	Type    int    `json:"type"`
	FlowID  uint64 `json:"flow_id"`
	Host    string `json:"host"`
	Port    uint16 `json:"port"`
	Payload string `json:"payload"`
	Verdict string `json:"verdict"`
	Wire    string `json:"wire,omitempty"`
}

type zzDecodeCase struct {
	Name    string `json:"name"`
	Wire    string `json:"wire"`
	Verdict string `json:"verdict"`
	Type    int    `json:"type"`
	FlowID  uint64 `json:"flow_id"`
	Host    string `json:"host"`
	Port    uint16 `json:"port"`
	Payload string `json:"payload"`
}

type zzFile struct {
	Constants zzConstants    `json:"constants"`
	Encode    []zzEncodeCase `json:"encode"`
	Decode    []zzDecodeCase `json:"decode"`
}

func zzVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrFrameTooShort):
		return "too_short"
	case errors.Is(err, ErrBadMagic):
		return "bad_magic"
	case errors.Is(err, ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, ErrUnknownFrameType):
		return "unknown_type"
	case errors.Is(err, ErrInvalidFlowID):
		return "invalid_flow_id"
	case errors.Is(err, ErrInvalidEndpoint):
		return "invalid_endpoint"
	case errors.Is(err, ErrPayloadTooLarge):
		return "payload_too_large"
	default:
		return "other: " + err.Error()
	}
}

// zzWire builds a frame by hand, for the decode cases Encode refuses to make.
func zzWire(version, typ byte, flow uint64, addrType byte, port uint16, addr, payload []byte, addrLen int) []byte {
	out := make([]byte, headerLen, headerLen+len(addr)+len(payload))
	copy(out, magic[:])
	out[2] = version
	out[3] = typ
	binary.BigEndian.PutUint64(out[4:12], flow)
	out[12] = addrType
	binary.BigEndian.PutUint16(out[13:15], port)
	out[15] = byte(addrLen)
	out = append(out, addr...)
	return append(out, payload...)
}

func TestZZVectors(t *testing.T) {
	file := zzFile{Constants: zzConstants{Version: int(Version), MaxPayloadSize: MaxPayloadSize,
		MaxHostLen: MaxHostLen, HeaderLen: headerLen, Magic: string(magic[:])}}
	long := strings.Repeat("a", MaxHostLen)
	encodes := []struct {
		name    string
		frame   Frame
		payload []byte
	}{
		{"ipv4", Frame{Type: FrameTypePacket, FlowID: 1, Endpoint: Endpoint{Host: "1.2.3.4", Port: 53}}, []byte("dns?")},
		{"ipv4 zeros", Frame{Type: FrameTypePacket, FlowID: 0x0102030405060708, Endpoint: Endpoint{Host: "0.0.0.0", Port: 1}}, nil},
		{"ipv4 broadcast", Frame{Type: FrameTypePacket, FlowID: ^uint64(0), Endpoint: Endpoint{Host: "255.255.255.255", Port: 65535}}, []byte{0}},
		{"ipv4 with a leading zero is a name", Frame{Type: FrameTypePacket, FlowID: 2, Endpoint: Endpoint{Host: "01.2.3.4", Port: 80}}, nil},
		{"ipv4 with five parts is a name", Frame{Type: FrameTypePacket, FlowID: 2, Endpoint: Endpoint{Host: "1.2.3.4.5", Port: 80}}, nil},
		{"ipv6 loopback", Frame{Type: FrameTypePacket, FlowID: 3, Endpoint: Endpoint{Host: "::1", Port: 443}}, []byte("quic")},
		{"ipv6", Frame{Type: FrameTypePacket, FlowID: 3, Endpoint: Endpoint{Host: "2001:db8::8a2e:370:7334", Port: 443}}, nil},
		{"ipv6 upper case", Frame{Type: FrameTypePacket, FlowID: 3, Endpoint: Endpoint{Host: "2001:DB8::1", Port: 443}}, nil},
		{"ipv6 all zeros", Frame{Type: FrameTypePacket, FlowID: 3, Endpoint: Endpoint{Host: "::", Port: 9}}, nil},
		{"ipv4-mapped ipv6 stays 16 bytes", Frame{Type: FrameTypePacket, FlowID: 4, Endpoint: Endpoint{Host: "::ffff:1.2.3.4", Port: 53}}, nil},
		{"ipv4-compatible ipv6", Frame{Type: FrameTypePacket, FlowID: 4, Endpoint: Endpoint{Host: "::1.2.3.4", Port: 53}}, nil},
		{"ipv6 with a zone drops the zone", Frame{Type: FrameTypePacket, FlowID: 5, Endpoint: Endpoint{Host: "fe80::1%eth0", Port: 5353}}, nil},
		{"ipv6 with an empty zone is a name", Frame{Type: FrameTypePacket, FlowID: 5, Endpoint: Endpoint{Host: "fe80::1%", Port: 5353}}, nil},
		{"ipv4 with a zone is a name", Frame{Type: FrameTypePacket, FlowID: 5, Endpoint: Endpoint{Host: "1.2.3.4%eth0", Port: 5353}}, nil},
		{"bracketed ipv6 is a name", Frame{Type: FrameTypePacket, FlowID: 5, Endpoint: Endpoint{Host: "[::1]", Port: 53}}, nil},
		{"domain", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: "example.com", Port: 443}}, []byte("hello")},
		{"domain of the longest length", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: long, Port: 443}}, nil},
		{"domain one byte too long", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: long + "a", Port: 443}}, nil},
		{"domain with a space", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: "a b", Port: 443}}, nil},
		{"domain with a tilde and a bang", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: "!~", Port: 443}}, nil},
		{"domain with delete", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: "a\x7fb", Port: 443}}, nil},
		{"non-ascii domain", Frame{Type: FrameTypePacket, FlowID: 6, Endpoint: Endpoint{Host: "пример.рф", Port: 443}}, nil},
		{"blank host", Frame{Type: FrameTypePacket, FlowID: 7, Endpoint: Endpoint{Host: " ", Port: 443}}, nil},
		{"no host", Frame{Type: FrameTypePacket, FlowID: 7, Endpoint: Endpoint{Port: 443}}, nil},
		{"port zero", Frame{Type: FrameTypePacket, FlowID: 7, Endpoint: Endpoint{Host: "1.1.1.1"}}, nil},
		{"flow zero", Frame{Type: FrameTypePacket, Endpoint: Endpoint{Host: "1.1.1.1", Port: 53}}, nil},
		{"largest payload", Frame{Type: FrameTypePacket, FlowID: 8, Endpoint: Endpoint{Host: "9.9.9.9", Port: 53}}, zzvectors.Pattern(MaxPayloadSize, 8)},
		{"payload one byte too large", Frame{Type: FrameTypePacket, FlowID: 8, Endpoint: Endpoint{Host: "9.9.9.9", Port: 53}}, zzvectors.Pattern(MaxPayloadSize+1, 8)},
		{"close", Frame{Type: FrameTypeClose, FlowID: 9}, nil},
		{"close with a host", Frame{Type: FrameTypeClose, FlowID: 9, Endpoint: Endpoint{Host: "1.1.1.1"}}, nil},
		{"close with a port", Frame{Type: FrameTypeClose, FlowID: 9, Endpoint: Endpoint{Port: 53}}, nil},
		{"close with a payload", Frame{Type: FrameTypeClose, FlowID: 9}, []byte("x")},
		{"type zero", Frame{Type: 0, FlowID: 9, Endpoint: Endpoint{Host: "1.1.1.1", Port: 53}}, nil},
		{"type three", Frame{Type: 3, FlowID: 9, Endpoint: Endpoint{Host: "1.1.1.1", Port: 53}}, nil},
	}
	var wires [][]byte
	for _, c := range encodes {
		f := c.frame
		f.Payload = c.payload
		wire, err := Encode(f)
		file.Encode = append(file.Encode, zzEncodeCase{Name: c.name, Type: int(f.Type), FlowID: f.FlowID,
			Host: f.Endpoint.Host, Port: f.Endpoint.Port, Payload: zzvectors.Hex(c.payload),
			Verdict: zzVerdict(err), Wire: zzvectors.Hex(wire)})
		if err == nil {
			wires = append(wires, wire)
		}
	}

	type decodeInput struct {
		name string
		wire []byte
	}
	var decodes []decodeInput
	for i, wire := range wires {
		decodes = append(decodes, decodeInput{"encoded " + file.Encode[zzOK(file.Encode, i)].Name, wire})
	}
	v4 := []byte{10, 0, 0, 1}
	v6 := zzvectors.MustHex(t, "20010db8000000000001000000000001")
	decodes = append(decodes,
		decodeInput{"fifteen bytes", zzWire(1, 1, 1, 1, 53, nil, nil, 0)[:15]},
		decodeInput{"bad magic", append([]byte("OV"), zzWire(1, 1, 1, 1, 53, v4, nil, 4)[2:]...)},
		decodeInput{"version 2", zzWire(2, 1, 1, 1, 53, v4, nil, 4)},
		decodeInput{"type zero", zzWire(1, 0, 1, 1, 53, v4, nil, 4)},
		decodeInput{"type three", zzWire(1, 3, 1, 1, 53, v4, nil, 4)},
		decodeInput{"flow zero", zzWire(1, 1, 0, 1, 53, v4, nil, 4)},
		decodeInput{"address longer than the frame", zzWire(1, 1, 1, 1, 53, v4[:3], nil, 4)},
		decodeInput{"ipv4 of three bytes", zzWire(1, 1, 1, 1, 53, v4[:3], nil, 3)},
		decodeInput{"ipv6 of fifteen bytes", zzWire(1, 1, 1, 4, 53, v6[:15], nil, 15)},
		decodeInput{"ipv6 formatting", zzWire(1, 1, 1, 4, 53, v6, []byte("p"), 16)},
		decodeInput{"ipv6 with two zero runs", zzWire(1, 1, 1, 4, 53, zzvectors.MustHex(t, "00010000000000020000000000000003"), nil, 16)},
		decodeInput{"ipv6 with one zero group", zzWire(1, 1, 1, 4, 53, zzvectors.MustHex(t, "00010002000000030004000500060007"), nil, 16)},
		decodeInput{"ipv4-mapped bytes", zzWire(1, 1, 1, 4, 53, zzvectors.MustHex(t, "00000000000000000000ffff0a000001"), nil, 16)},
		decodeInput{"ipv4-compatible bytes", zzWire(1, 1, 1, 4, 53, zzvectors.MustHex(t, "0000000000000000000000000a000001"), nil, 16)},
		decodeInput{"empty domain", zzWire(1, 1, 1, 3, 53, nil, nil, 0)},
		decodeInput{"domain with a space", zzWire(1, 1, 1, 3, 53, []byte("a b"), nil, 3)},
		decodeInput{"domain with a high byte", zzWire(1, 1, 1, 3, 53, []byte{'a', 0xc3, 0xa9}, nil, 3)},
		decodeInput{"address type two", zzWire(1, 1, 1, 2, 53, v4, nil, 4)},
		decodeInput{"address type none with bytes", zzWire(1, 1, 1, 0, 53, v4, nil, 4)},
		decodeInput{"packet without an address", zzWire(1, 1, 1, 0, 53, nil, nil, 0)},
		decodeInput{"packet to port zero", zzWire(1, 1, 1, 1, 0, v4, nil, 4)},
		decodeInput{"payload one byte too large", zzWire(1, 1, 1, 1, 53, v4, zzvectors.Pattern(MaxPayloadSize+1, 1), 4)},
		decodeInput{"close with an address", zzWire(1, 2, 1, 1, 0, v4, nil, 4)},
		decodeInput{"close with a port", zzWire(1, 2, 1, 0, 53, nil, nil, 0)},
		decodeInput{"close with a payload", zzWire(1, 2, 1, 0, 0, nil, []byte("x"), 0)},
		decodeInput{"close", zzWire(1, 2, 0xfeedface, 0, 0, nil, nil, 0)},
	)
	for _, d := range decodes {
		f, err := Decode(d.wire)
		file.Decode = append(file.Decode, zzDecodeCase{Name: d.name, Wire: zzvectors.Hex(d.wire), Verdict: zzVerdict(err),
			Type: int(f.Type), FlowID: f.FlowID, Host: f.Endpoint.Host, Port: f.Endpoint.Port, Payload: zzvectors.Hex(f.Payload)})
	}
	zzvectors.Write(t, "udpwire.json", "internal/udpwire/zz_vectors_test.go TestZZVectors",
		[]string{"internal/udpwire/wire.go:14-231"}, file)
}

// zzOK returns the index in cases of the i-th case that encoded.
func zzOK(cases []zzEncodeCase, i int) int {
	for j, c := range cases {
		if c.Verdict != "ok" {
			continue
		}
		if i == 0 {
			return j
		}
		i--
	}
	return -1
}

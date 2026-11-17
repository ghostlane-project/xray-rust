//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors of vp8channel's remote-track reader for the Rust port
// (olc/interop in the xray-rust fork): RED (W37), the reorder buffer and the
// VP8 and VP9 assemblers (W36), in vp8/rtp-reader.json. An overlay file:
// regen.sh copies it into a clean checkout of the pin.

package vp8channel

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"

	"github.com/openlibrecommunity/olcrtc/internal/transport/common"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

// zzREDPayload is a RED payload (RFC 2198) as the engine's videochannel
// tests build one: a four-byte header per redundant block, the one-byte
// primary header, the blocks' data in order, then the primary's.
func zzREDPayload(primaryType uint8, primary []byte, redundant ...[]byte) []byte {
	var out []byte
	for _, block := range redundant {
		out = append(out, 0x80|primaryType, 0, byte(len(block)>>8)&0x03, byte(len(block))) //nolint:gosec // G115: ten bits
	}
	out = append(out, primaryType)
	for _, block := range redundant {
		out = append(out, block...)
	}
	return append(out, primary...)
}

// zzFrameSpec is one frame the generator packetizes: the epoch header from
// the peer to us, then Pattern(len, seed); keyframe is for the VP9 dress.
type zzFrameSpec struct {
	Len      int  `json:"len"`
	Seed     byte `json:"seed"`
	Keyframe bool `json:"keyframe,omitempty"`
}

// zzStep is one packet the script hands the reader: the i-th generated
// packet, or raw bytes under a sequence number of its own; marker overrides
// the packet's; red wraps it ("plain", "one": with one redundant block of
// its first ten bytes, "fec": as plain but the primary typed 106); aged says
// the gap the reader holds (if any) is older than reorderHold by now.
type zzStep struct {
	I      *int    `json:"i,omitempty"`
	Raw    *string `json:"raw,omitempty"`
	Seq    *uint16 `json:"seq,omitempty"`
	Marker *bool   `json:"marker,omitempty"`
	RED    string  `json:"red,omitempty"`
	Aged   bool    `json:"aged,omitempty"`
}

func zzIdx(i int) *int          { return &i }
func zzSeq(s uint16) *uint16    { return &s }
func zzFlag(b bool) *bool       { return &b }
func zzRawHex(b []byte) *string { h := zzvectors.Hex(b); return &h }
func zzStepsOf(is ...int) []zzStep {
	out := make([]zzStep, 0, len(is))
	for _, i := range is {
		out = append(out, zzStep{I: zzIdx(i)})
	}
	return out
}

// zzGenerate packetizes frames as the writer's track does at 60 fps.
func zzGenerate(t *testing.T, payloader rtp.Payloader, seq uint16, frames []zzFrameSpec, vp9 bool) []*rtp.Packet {
	t.Helper()
	w := zzPacketizer(payloader, seq, 0)
	tok := bindingToken(zzChannel)
	var out []*rtp.Packet
	for _, f := range frames {
		frame := zzFrame(tok, zzPeer, zzLocal, zzvectors.Pattern(f.Len, f.Seed))
		if vp9 {
			frame = vp9Dress(nil, frame, f.Keyframe)
		}
		out = append(out, w.write(frame, time.Second/60)...)
	}
	return out
}

// zzListDigest is a SHA-256 over every generated packet: seq (u16 BE),
// marker (one byte), payload length (u32 BE), payload.
func zzListDigest(pkts []*rtp.Packet) map[string]any {
	var all []byte
	for _, p := range pkts {
		all = binary.BigEndian.AppendUint16(all, p.SequenceNumber)
		m := byte(0)
		if p.Marker {
			m = 1
		}
		all = append(all, m)
		all = binary.BigEndian.AppendUint32(all, uint32(len(p.Payload))) //nolint:gosec // G115: a packet
		all = append(all, p.Payload...)
	}
	return map[string]any{"packets": len(pkts), "sha256": zzvectors.Sum(all)}
}

// zzRunReader is readVP8Track's loop body (rtp_reader.go:264-302, copied:
// it reads a live TrackRemote) over the script, past the RTP parse the
// WebRTC stack does: RED unwrapped when red, then the reorder buffer and
// the carrier's assembler.
func zzRunReader(t *testing.T, c *carrier, red bool, gen []*rtp.Packet, steps []zzStep) []map[string]any {
	t.Helper()
	state := c.assembler()
	reorder := newReorderBuffer()
	out := make([]map[string]any, 0, len(steps))
	for n, s := range steps {
		var pkt *rtp.Packet
		switch {
		case s.I != nil:
			g := gen[*s.I]
			pkt = &rtp.Packet{Header: g.Header, Payload: append([]byte(nil), g.Payload...)}
		case s.Raw != nil && s.Seq != nil:
			pkt = &rtp.Packet{Header: rtp.Header{SequenceNumber: *s.Seq, PayloadType: 96}, Payload: zzvectors.MustHex(t, *s.Raw)}
		default:
			t.Fatalf("step %d: neither a packet nor raw bytes", n)
		}
		if s.Marker != nil {
			pkt.Marker = *s.Marker
		}
		switch s.RED {
		case "":
		case "plain":
			pkt.Payload = zzREDPayload(96, pkt.Payload)
		case "one":
			pkt.Payload = zzREDPayload(96, pkt.Payload, pkt.Payload[:min(10, len(pkt.Payload))])
		case "fec":
			pkt.Payload = zzREDPayload(106, pkt.Payload)
		default:
			t.Fatalf("step %d: red %q", n, s.RED)
		}
		e := map[string]any{}
		if red {
			payloadType, data, err := common.REDPrimary(pkt.Payload)
			if err != nil {
				e["skipped"] = true
				out = append(out, e)
				continue
			}
			pkt.PayloadType = payloadType
			pkt.Payload = data
		}
		// The hold, made deterministic: a gap counts as older than
		// reorderHold only on an aged step.
		if !reorder.gapSince.IsZero() {
			if s.Aged {
				reorder.gapSince = time.Now().Add(-time.Second)
			} else {
				reorder.gapSince = time.Now()
			}
		}
		frames := []map[string]any{}
		reorder.push(pkt, func(ordered *rtp.Packet) {
			if f := state.processRTPPacket(ordered); f != nil {
				frames = append(frames, zzBytes(f))
			}
		})
		e["frames"] = frames
		e["next_seq"] = reorder.nextSeq
		e["held"] = len(reorder.pkts)
		out = append(out, e)
	}
	return out
}

func zzReaderVectors(t *testing.T) {
	t.Helper()
	// RED (W37): common/red.go on the videochannel tests' fixtures and more.
	long := make([]byte, 300)
	for i := range long {
		long[i] = 9
	}
	reds := []struct {
		name string
		b    []byte
	}{
		{"single_block", zzREDPayload(100, []byte{1, 2, 3})},
		{"two_redundant_one_long", zzREDPayload(100, []byte{7, 7}, []byte{1, 2, 3}, long)},
		{"longest_redundant", zzREDPayload(96, []byte{5}, zzvectors.Pattern(1023, 1))},
		{"primary_type_127", zzREDPayload(127, []byte{1})},
		{"primary_empty", []byte{96}},
		{"redundant_to_the_end", zzREDPayload(96, nil, []byte{1, 2})},
		{"empty", []byte{}},
		{"follow_bit_only", []byte{0x80 | 100, 0}},
		{"length_past_end", []byte{0x80 | 100, 0, 0, 5, 100, 1, 2}},
		{"no_primary_block", []byte{0x80 | 100, 0, 0, 0}},
		{"three_header_bytes", []byte{0x80 | 100, 0, 0}},
	}
	var red []map[string]any
	for _, r := range reds {
		pt, data, err := common.REDPrimary(r.b)
		e := map[string]any{"name": r.name, "hex": zzvectors.Hex(r.b), "ok": err == nil}
		if err == nil {
			e["pt"], e["data"] = pt, zzvectors.Hex(data)
		}
		red = append(red, e)
	}

	vp8c, err := carrierFor("")
	if err != nil {
		t.Fatal(err)
	}
	vp9c, err := carrierFor(webrtc.MimeTypeVP9)
	if err != nil {
		t.Fatal(err)
	}
	var accepts []map[string]any
	for _, m := range []string{"video/VP8", "video/vp8", "video/red", "video/RED", "video/VP9", "video/vp9", "video/H264", "audio/opus", ""} {
		accepts = append(accepts, map[string]any{"mime": m, "vp8": vp8c.accepts(m), "vp9": vp9c.accepts(m), "own": (*carrier)(nil).accepts(m)})
	}

	// VP8: F0 across the sequence wrap, a duplicate, a loss given up by
	// the hold, a bad descriptor, a frame past maxAssembledFrameSize, a
	// frame shorter than a header, a full window behind a hole.
	vp8Frames := []zzFrameSpec{
		{Len: 3000, Seed: 1}, {Len: 10, Seed: 2}, {Len: 2400, Seed: 3}, {Len: 5, Seed: 4}, {Len: 100, Seed: 5},
		{Len: 250000, Seed: 6}, {Len: 20, Seed: 7}, {Len: 0, Seed: 8},
	}
	for i := range 263 {
		vp8Frames = append(vp8Frames, zzFrameSpec{Len: 1 + i%7, Seed: byte(i)}) //nolint:gosec // G115: a seed
	}
	vp8Gen := zzGenerate(t, &codecs.VP8Payloader{EnablePictureID: true}, 65534, vp8Frames, false)
	// Packets: F0 0-2, F1 3, F2 4-6, F3 7, F4 8, F5 9-220, F6 221, F7 222,
	// then one a frame: F8 at 223 up to F270 at 485.
	if len(vp8Gen) != 486 || !vp8Gen[220].Marker || vp8Gen[219].Marker {
		t.Fatalf("the VP8 script's packets moved: %d", len(vp8Gen))
	}
	steps := zzStepsOf(0, 2, 1, 3, 3, 4, 6)
	steps = append(steps, zzStep{I: zzIdx(7), Aged: true}, zzStep{I: zzIdx(5)})
	steps = append(steps, zzStep{Raw: zzRawHex([]byte{}), Seq: zzSeq(vp8Gen[8].SequenceNumber)})
	for i := 9; i <= 221; i++ {
		steps = append(steps, zzStep{I: zzIdx(i)})
	}
	short := append([]byte{0x10}, zzvectors.Pattern(10, 9)...)
	steps = append(steps, zzStep{Raw: zzRawHex(short), Seq: zzSeq(vp8Gen[222].SequenceNumber), Marker: zzFlag(true)})
	// The hole at 223 (F8): 257 packets behind it give it up.
	for i := 224; i <= 480; i++ {
		steps = append(steps, zzStep{I: zzIdx(i)})
	}
	steps = append(steps, zzStep{I: zzIdx(223)})
	// The hole at 481: held, not given up until an aged step.
	steps = append(steps, zzStep{I: zzIdx(482)}, zzStep{I: zzIdx(483)}, zzStep{I: zzIdx(484), Aged: true}, zzStep{I: zzIdx(485)})
	vp8Out := zzRunReader(t, nil, false, vp8Gen, steps)

	// VP8 in RED, a RED packet without a primary skipped before the reorder
	// buffer, and a primary of another payload type read all the same.
	redFrames := []zzFrameSpec{{Len: 3000, Seed: 11}, {Len: 10, Seed: 12}, {Len: 20, Seed: 13}, {Len: 30, Seed: 14}, {Len: 40, Seed: 15}}
	redGen := zzGenerate(t, &codecs.VP8Payloader{EnablePictureID: true}, 1000, redFrames, false)
	redSteps := []zzStep{
		{I: zzIdx(0), RED: "plain"}, {I: zzIdx(2), RED: "one"}, {I: zzIdx(1), RED: "one"},
		{Raw: zzRawHex([]byte{0x80 | 96, 0}), Seq: zzSeq(redGen[3].SequenceNumber)},
		{I: zzIdx(4), RED: "plain"}, {I: zzIdx(5), RED: "fec", Aged: true}, {I: zzIdx(6), RED: "one"},
	}
	redOut := zzRunReader(t, vp8c, true, redGen, redSteps)

	// VP9: dressed frames end on E or the marker; a marker before E ends a
	// frame early; then hand-made descriptors: reference indices that pion
	// counts across packets until a packet with N is refused, and a
	// spatial layer past the five it allows.
	vp9Frames := []zzFrameSpec{
		{Len: 3000, Seed: 21, Keyframe: true}, {Len: 10, Seed: 22}, {Len: 10, Seed: 23, Keyframe: true}, {Len: 20, Seed: 24},
	}
	vp9Gen := zzGenerate(t, &vp9Payloader{pictureID: 0x7ffe}, 200, vp9Frames, true)
	// Packets: H0 0-2, H1 3, H2 4-5, H3 6.
	if len(vp9Gen) != 7 {
		t.Fatalf("the VP9 script's packets moved: %d", len(vp9Gen))
	}
	tok := bindingToken(zzChannel)
	dressed := func(n int, seed byte) []byte {
		return vp9Dress(nil, zzFrame(tok, zzPeer, zzLocal, zzvectors.Pattern(n, seed)), false)
	}
	next := vp9Gen[6].SequenceNumber + 1
	raw := func(b []byte) zzStep {
		s := zzStep{Raw: zzRawHex(b), Seq: zzSeq(next)}
		next++
		return s
	}
	const pfbe = 0x40 | 0x10 | 0x08 | 0x04
	vp9Steps := []zzStep{
		{I: zzIdx(0)}, {I: zzIdx(1)}, {I: zzIdx(2)},
		{I: zzIdx(3), Marker: zzFlag(false)},
		{I: zzIdx(4), Marker: zzFlag(true)}, {I: zzIdx(5)},
		{I: zzIdx(6)},
		raw(append([]byte{pfbe, 0x02}, dressed(30, 25)...)),
		raw(append([]byte{pfbe, 0x03, 0x02}, dressed(40, 26)...)),
		raw(append([]byte{pfbe, 0x03, 0x02}, dressed(50, 27)...)),
		raw(append([]byte{pfbe, 0x02}, dressed(60, 28)...)),
		raw(append([]byte{0x20 | 0x10 | 0x08 | 0x04, 0x0a}, dressed(70, 29)...)),
		raw(append([]byte{0x20 | 0x10 | 0x08 | 0x04, 0x08}, dressed(80, 30)...)),
		raw(append([]byte{0x20 | 0x08 | 0x04, 0x00}, dressed(90, 31)...)),
		raw(append([]byte{0x20 | 0x08 | 0x04, 0x00, 0x05}, dressed(90, 31)...)),
		raw(append([]byte{0x02 | 0x08 | 0x04, 0x18, 0, 1, 0, 1, 1, 0x04, 0xaa}, dressed(100, 32)...)),
		raw(append([]byte{0x02 | 0x08 | 0x04, 0x18, 0, 1, 0, 1, 1, 0x0c, 0xaa}, dressed(100, 32)...)),
		raw([]byte{0x08 | 0x04}),
	}
	vp9Out := zzRunReader(t, vp9c, false, vp9Gen, vp9Steps)

	zzvectors.Write(t, "vp8/rtp-reader.json", zzWireGen,
		[]string{
			"internal/transport/vp8channel/rtp_reader.go", "internal/transport/vp8channel/carrier.go:28-100,255-305",
			"internal/transport/common/red.go", "pion/rtp@v1.10.2/codecs/vp8_packet.go:121-219",
			"pion/rtp@v1.10.2/codecs/vp9_packet.go:253-504",
		}, map[string]any{
			"red":     red,
			"accepts": accepts,
			"vp8": map[string]any{
				"seq": 65534, "frames": vp8Frames, "generated": zzListDigest(vp8Gen), "steps": steps, "out": vp8Out,
			},
			"vp8_red": map[string]any{
				"seq": 1000, "frames": redFrames, "generated": zzListDigest(redGen), "steps": redSteps, "out": redOut,
			},
			"vp9": map[string]any{
				"seq": 200, "picture_id": 0x7ffe, "frames": vp9Frames, "generated": zzListDigest(vp9Gen),
				"steps": vp9Steps, "out": vp9Out,
			},
		})
}

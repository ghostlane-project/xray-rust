//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors of vp8channel's wire for the Rust port (olc/interop in the
// xray-rust fork): W24-W30 under vp8/, W34-W35 under vp9/, W36 (what pion
// makes of a sample) in vp8/rtp.json. An overlay file: regen.sh copies it
// into a clean checkout of the pin. Nothing here reads the clock into a
// vector or is random, so two runs write the same bytes.

package vp8channel

import (
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"

	"github.com/openlibrecommunity/olcrtc/internal/roomhint"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/transport/common"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzWireGen = "internal/transport/vp8channel/zz_vectors_wire_test.go TestZZVectors"

// zzChannel is the channel id every vector transport binds to.
const zzChannel = "vectors"

// The epochs the vectors use: ours (newDatagramTestTransport's), the peer's
// and a third participant's.
const (
	zzLocal uint32 = 0x100
	zzPeer  uint32 = 0x200
	zzOther uint32 = 0x300
)

func zzWireVectors(t *testing.T) {
	t.Helper()
	zzEpochVectors(t)
	zzTokenVectors(t)
	zzCRCVectors(t)
	zzOLKBVectors(t)
	zzDatagramVectors(t)
	zzInboundVectors(t)
	zzVP9Vectors(t)
	zzRTPVectors(t)
}

// zzBytes is b as hex, or as its length and SHA-256 when it is large.
func zzBytes(b []byte) map[string]any {
	if len(b) > zzvectors.LargeOutput {
		return map[string]any{"len": len(b), "sha256": zzvectors.Sum(b)}
	}
	return map[string]any{"len": len(b), "hex": zzvectors.Hex(b)}
}

func zzFrame(token, src, dst uint32, payload ...[]byte) []byte {
	hdr := buildEpochHeaderTo(token, src, dst)
	out := append([]byte(nil), hdr[:]...)
	for _, p := range payload {
		out = append(out, p...)
	}
	return out
}

// zzKCPPacket is a Pattern packet with its CRC-32C trailer: what a KCP plane
// is handed.
func zzKCPPacket(n int, seed byte) []byte {
	p := zzvectors.Pattern(n, seed)
	return binary.BigEndian.AppendUint32(p, crc32.Checksum(p, crcTable))
}

func zzBatch(magic [4]byte, packets ...[]byte) []byte {
	out := append([]byte(nil), magic[:]...)
	for _, p := range packets {
		out = appendBatchPacket(out, p)
	}
	return out
}

func zzWith(b []byte, edit func([]byte)) []byte {
	c := append([]byte(nil), b...)
	edit(c)
	return c
}

func zzTestTransport(cfg transport.Config, batch int) *streamTransport {
	cfg.ChannelID = zzChannel
	return newDatagramTestTransport(cfg, Options{BatchSize: batch})
}

// W24, W26: headers (epoch.go:17-53), peer ids (peers.go:330-341) and what
// ConfirmPeer takes (transport.go:438-457).
func zzEpochVectors(t *testing.T) {
	t.Helper()
	tok := bindingToken(zzChannel)
	if a, b := buildEpochHeader(tok, zzLocal), buildEpochHeaderTo(tok, zzLocal, 0); a != b {
		t.Fatal("buildEpochHeader is not the broadcast header")
	}
	var headers []map[string]any
	for _, c := range [][3]uint32{
		{1, 2, 0},
		{tok, zzLocal, 0},
		{tok, zzLocal | controlEpochFlag, 0},
		{tok, zzLocal, zzPeer},
		{tok, zzLocal | controlEpochFlag, zzPeer | controlEpochFlag},
		{0xffffffff, 0x7fffffff, controlEpochFlag},
		{0, 0, 0},
	} {
		h := buildEpochHeaderTo(c[0], c[1], c[2])
		headers = append(headers, map[string]any{
			"token": c[0], "src": c[1], "dst": c[2], "crc": epochCRC(c[0], c[1], c[2]), "hex": zzvectors.Hex(h[:]),
		})
	}

	base := buildEpochHeaderTo(tok, zzLocal, zzPeer)
	frames := []struct {
		name string
		b    []byte
	}{
		{"header", base[:]},
		{"header_and_payload", zzFrame(tok, zzLocal, zzPeer, []byte{1, 2, 3, 4})},
		{"one_byte_short", base[:epochHdrLen-1]},
		{"empty", nil},
		{"token_bit_flipped", zzWith(base[:], func(b []byte) { b[tokenOff] ^= 0x01 })},
		{"src_bit_flipped", zzWith(base[:], func(b []byte) { b[srcOff+3] ^= 0x01 })},
		{"dst_bit_flipped", zzWith(base[:], func(b []byte) { b[dstOff+3] ^= 0x10 })},
		{"crc_bit_flipped", zzWith(base[:], func(b []byte) { b[crcOff] ^= 0x80 })},
		{"vp8_bytes_zeroed", zzWith(base[:], func(b []byte) { clear(b[:tokenOff]) })},
	}
	var parses []map[string]any
	for _, f := range frames {
		token, src, dst, ok := parseEpochHeader(f.b)
		e := map[string]any{"name": f.name, "hex": zzvectors.Hex(f.b), "ok": ok}
		if ok {
			e["token"], e["src"], e["dst"] = token, src, dst
		}
		parses = append(parses, e)
	}

	var formats []map[string]any
	for _, e := range []uint32{0, 1, zzLocal, 0x7fffffff, zzLocal | controlEpochFlag, 0xffffffff} {
		formats = append(formats, map[string]any{"epoch": e, "id": formatPeerID(e)})
	}
	var ids []map[string]any
	for _, s := range []string{
		"00000200", "200", "ABCDEF01", "abcdef01", "AbCdEf01", "0", "00000000", "ffffffff",
		"0000000000ff", "100000000", "0x200", "", "+200", "-1", "2_00", " 200", "200 ", "g", "८",
	} {
		v, err := parsePeerID(s)
		e := map[string]any{"id": s, "ok": err == nil}
		if err == nil {
			e["epoch"] = v
		}
		ids = append(ids, e)
	}

	var confirms []map[string]any
	for _, s := range []string{"00000200", "200", "7fffffff", "0", "00000000", "80000200", "ffffffff", "xyz", ""} {
		tr := zzTestTransport(transport.Config{}, 1)
		conn := newKCPConn(make(chan *packetBuffer, 1), 1, tr.epochHeader())
		tr.data.set(&kcpRuntime{conn: conn})
		err := tr.ConfirmPeer(s)
		e := map[string]any{"id": s, "ok": err == nil, "confirmed": tr.peerConfirmed.Load()}
		if err != nil && !strings.Contains(err.Error(), "parse peer id") {
			e["error"] = err.Error()
		}
		if err == nil {
			conn.hdrMu.RLock()
			hdr := conn.epochHdr
			conn.hdrMu.RUnlock()
			e["peer_epoch"] = tr.peerEpoch.Load()
			e["data_header"] = zzvectors.Hex(hdr[:])
		}
		confirms = append(confirms, e)
	}

	zzvectors.Write(t, "vp8/epoch.json", zzWireGen,
		[]string{
			"internal/transport/vp8channel/wire.go:10-44", "internal/transport/vp8channel/epoch.go:17-53,89-127",
			"internal/transport/vp8channel/peers.go:330-341", "internal/transport/vp8channel/transport.go:438-457",
		}, map[string]any{
			"keepalive":    zzvectors.Hex(vp8Keepalive),
			"binding":      map[string]any{"channel": zzChannel, "token": tok},
			"headers":      headers,
			"parse":        parses,
			"format_peer":  formats,
			"parse_peer":   ids,
			"confirm_peer": confirms,
			"local_epoch":  zzLocal,
		})
}

// W25: the binding token (transport/common/binding.go:20-35) and the room
// hint it leaves out (roomhint/roomhint.go:40-53).
func zzTokenVectors(t *testing.T) {
	t.Helper()
	cases := []struct{ channel, room string }{
		{"", ""},
		{zzChannel, ""},
		{zzChannel, "https://meet.mts.ru/room?ice=tcp"},
		{"srv-client", ""},
		{"", "https://meet.mts.ru/room"},
		{"", "https://meet.mts.ru/room?ice=tcp"},
		{"", "https://meet.mts.ru/room?ice=udp"},
		{"", "https://meet.mts.ru/room?ice=both"},
		{"", "https://meet.mts.ru/room?x=1&ice=tcp"},
		{"", "https://meet.mts.ru/room?ice=quic"},
		{"", "https://meet.mts.ru/room?ice="},
		{"", "https://meet.mts.ru/room?ice=TCP"},
		{"", "  https://meet.mts.ru/room?ice=tcp\n"},
		{"", "  https://meet.mts.ru/room  "},
		{"", "https://meet.mts.ru/room?ice=tcp&ice=udp"},
		{"", "https://meet.mts.ru/room?ice=tcp?ice=bad"},
		{"", "https://meet.mts.ru/room?ice=tcp "},
		{"", " https://meet.mts.ru/room?ice=both　"},
		{"", "?ice=tcp"},
		{"", "https://salutejazz.ru/abc#ice=tcp"},
		{"", "комната?ice=udp"},
	}
	var out []map[string]any
	for _, c := range cases {
		room, mode := roomhint.Split(c.room)
		tok := common.BindingToken(c.channel, c.room)
		if got := channelBindingToken(transport.Config{ChannelID: c.channel, RoomURL: c.room}); got != tok {
			t.Fatalf("channelBindingToken %08x, BindingToken %08x", got, tok)
		}
		out = append(out, map[string]any{
			"channel": c.channel, "room": c.room, "room_without_hint": room, "hint": mode, "token": tok,
		})
	}
	zzvectors.Write(t, "vp8/token.json", zzWireGen,
		[]string{
			"internal/transport/common/binding.go:20-35", "internal/roomhint/roomhint.go:22-53",
			"internal/transport/vp8channel/epoch.go:56-64",
		}, out)
}

// W28: the CRC-32C trailer kcpConn puts on every KCP packet and checks on
// the way in (kcpconn.go:14-30,180-205,335-352).
func zzCRCVectors(t *testing.T) {
	t.Helper()
	hdr := buildEpochHeaderTo(bindingToken(zzChannel), zzLocal, zzPeer)
	c := newKCPConn(make(chan *packetBuffer, 1), 1, hdr)
	var wraps []map[string]any
	for _, s := range []zzvectors.PatternSpec{{Len: 0, Seed: 1}, {Len: 1, Seed: 2}, {Len: 24, Seed: 3}, {Len: 1376, Seed: 4}, {Len: 1400, Seed: 5}} {
		p := zzvectors.Pattern(s.Len, s.Seed)
		w := c.wrap(p)
		wraps = append(wraps, map[string]any{"packet": s, "crc": crc32.Checksum(p, crcTable), "wire": zzBytes(w.data)})
		w.release()
	}

	good := zzKCPPacket(40, 6)
	inputs := []struct {
		name string
		b    []byte
	}{
		{"valid", good},
		{"body_bit_flipped", zzWith(good, func(b []byte) { b[3] ^= 0x04 })},
		{"crc_bit_flipped", zzWith(good, func(b []byte) { b[len(b)-1] ^= 0x01 })},
		{"three_bytes", good[:3]},
		{"empty", nil},
		{"empty_body", []byte{0, 0, 0, 0}},
		{"empty_body_wrong_crc", []byte{0, 0, 0, 1}},
		{"segment", zzKCPPacket(24, 7)},
	}
	var delivers []map[string]any
	for _, in := range inputs {
		conn := newKCPConn(make(chan *packetBuffer, 1), 4, hdr)
		conn.deliver(in.b)
		e := map[string]any{"name": in.name, "hex": zzvectors.Hex(in.b), "accepted": len(conn.in) == 1}
		if len(conn.in) == 1 {
			p := <-conn.in
			e["body"] = zzvectors.Hex(p.data)
			p.release()
		}
		e["corrupt"] = conn.corrupt.Load()
		delivers = append(delivers, e)
	}
	zzvectors.Write(t, "vp8/kcp-crc.json", zzWireGen,
		[]string{"internal/transport/vp8channel/kcpconn.go:14-30,180-205,335-352"},
		map[string]any{"header": zzvectors.Hex(hdr[:]), "wrap": wraps, "deliver": delivers})
}

// W29: OLKB batches, built (writer.go:381-441) and split (wire.go:46-77).
func zzOLKBVectors(t *testing.T) {
	t.Helper()
	a, b, c := zzKCPPacket(20, 1), zzKCPPacket(30, 2), zzKCPPacket(5, 3)
	splits := []struct {
		name string
		b    []byte
	}{
		{"legacy_single", a},
		{"short_of_the_magic", []byte("OLK")},
		{"empty", nil},
		{"magic_only", []byte("OLKB")},
		{"three", zzBatch(kcpBatchMagic, a, b, c)},
		{"zero_length_entry", append(zzBatch(kcpBatchMagic, a, b), append([]byte{0, 0}, c...)...)},
		{"entry_past_the_end", append(zzBatch(kcpBatchMagic, a), 0, 200, 1, 2, 3)},
		{"stray_byte", append(zzBatch(kcpBatchMagic, a), 7)},
		{"magic_in_lower_case", append([]byte("olkb"), a...)},
	}
	var split []map[string]any
	for _, s := range splits {
		var got []string
		splitKCPPayload(s.b, func(p []byte) { got = append(got, zzvectors.Hex(p)) })
		split = append(split, map[string]any{"name": s.name, "hex": zzvectors.Hex(s.b), "delivered": got})
	}

	hdr := buildEpochHeaderTo(bindingToken(zzChannel), zzLocal, zzPeer)
	type queued struct {
		Len  int  `json:"len"`
		Seed byte `json:"seed"`
	}
	cases := []struct {
		name   string
		batch  int
		limit  int
		frames []queued // the first, then the queue; len -1: a header-only frame
	}{
		{"three_queued", 64, 64, []queued{{100, 1}, {100, 2}, {100, 3}}},
		{"limit_two", 64, 2, []queued{{100, 1}, {100, 2}, {100, 3}}},
		{"alone", 64, 64, []queued{{50, 4}}},
		{"batch_size_one", 1, 1, []queued{{50, 5}, {50, 6}}},
		{"first_header_only", 64, 64, []queued{{-1, 0}, {50, 7}}},
		{"header_only_in_the_queue", 64, 3, []queued{{50, 8}, {-1, 0}, {50, 9}, {50, 10}}},
		{"overflow", 64, 64, func() []queued {
			q := make([]queued, 50)
			for i := range q {
				q[i] = queued{1404, byte(i)}
			}
			return q
		}()},
	}
	var batches []map[string]any
	for _, cs := range cases {
		tr := zzTestTransport(transport.Config{}, cs.batch)
		src := make(chan *packetBuffer, len(cs.frames))
		mk := func(q queued) *packetBuffer {
			if q.Len < 0 {
				return &packetBuffer{data: append([]byte(nil), hdr[:]...)}
			}
			return &packetBuffer{data: append(append([]byte(nil), hdr[:]...), zzvectors.Pattern(q.Len, q.Seed)...)}
		}
		first := mk(cs.frames[0])
		for _, q := range cs.frames[1:] {
			src <- mk(q)
		}
		sample, left := tr.batchSampleUpTo(src, first, nil, cs.limit)
		e := map[string]any{
			"name": cs.name, "batch_size": cs.batch, "limit": cs.limit, "frames": cs.frames,
			"sample": zzBytes(sample), "queue_left": len(src),
		}
		if left != nil {
			e["left_over"] = zzBytes(left.data)
		}
		batches = append(batches, e)
	}
	zzvectors.Write(t, "vp8/olkb.json", zzWireGen,
		[]string{"internal/transport/vp8channel/wire.go:46-77", "internal/transport/vp8channel/writer.go:360-441"},
		map[string]any{"header": zzvectors.Hex(hdr[:]), "split": split, "batch": batches})
}

// W30: OLUD datagrams, their OLUB batches and the size bound
// (datagram.go:15-141, writer.go:208-245).
func zzDatagramVectors(t *testing.T) {
	t.Helper()
	tok := bindingToken(zzChannel)
	maxLen := defaultMaxPayloadSize - epochHdrLen - len(datagramMagic)
	var frames []map[string]any
	for _, c := range []struct {
		dst uint32
		n   int
	}{{0, 3}, {zzPeer, 100}, {zzPeer, 0}, {zzPeer, maxLen}, {zzPeer, maxLen + 1}} {
		tr := zzTestTransport(transport.Config{}, 1)
		data := zzvectors.Pattern(c.n, 9)
		err := tr.enqueueDatagram(c.dst, data)
		e := map[string]any{"dst": c.dst, "data": zzvectors.PatternSpec{Len: c.n, Seed: 9}, "ok": err == nil}
		if err == nil {
			e["frame"] = zzBytes(<-tr.datagram)
		} else {
			e["error"] = err.Error()
		}
		frames = append(frames, e)
	}

	type dg struct {
		Dst  uint32 `json:"dst"`
		Len  int    `json:"len"`
		Seed byte   `json:"seed"`
	}
	cases := []struct {
		name  string
		batch int
		queue []dg // the first, then the queue
	}{
		{"three_to_the_peer", 64, []dg{{zzPeer, 10, 1}, {zzPeer, 20, 2}, {zzPeer, 30, 3}}},
		{"another_route_waits", 64, []dg{{zzPeer, 10, 1}, {zzPeer, 20, 2}, {0, 30, 3}, {zzPeer, 40, 4}}},
		{"alone", 64, []dg{{zzPeer, 10, 1}}},
		{"batch_size_one", 1, []dg{{zzPeer, 10, 1}, {zzPeer, 20, 2}}},
		{"batch_size_two", 2, []dg{{zzPeer, 10, 1}, {zzPeer, 20, 2}, {zzPeer, 30, 3}}},
		{"too_large_for_the_sample", 64, []dg{{zzPeer, 20000, 1}, {zzPeer, 20000, 2}, {zzPeer, 20000, 3}, {zzPeer, 20000, 4}}},
		{"empty_first", 64, []dg{{zzPeer, 0, 1}, {zzPeer, 5, 2}}},
	}
	var batches []map[string]any
	for _, cs := range cases {
		tr := zzTestTransport(transport.Config{}, cs.batch)
		for _, d := range cs.queue {
			if err := tr.enqueueDatagram(d.Dst, zzvectors.Pattern(d.Len, d.Seed)); err != nil {
				t.Fatalf("%s: %v", cs.name, err)
			}
		}
		w := newWriterState(tr)
		first := <-tr.datagram
		sample := w.batchDatagramSampleFrom(tr.datagram, first)
		e := map[string]any{
			"name": cs.name, "batch_size": cs.batch, "queue": cs.queue,
			"sample": zzBytes(sample), "queue_left": len(tr.datagram),
		}
		if w.pendingDatagram != nil {
			e["pending"] = zzBytes(w.pendingDatagram)
		}
		batches = append(batches, e)
	}

	inputs := []struct {
		name string
		b    []byte
	}{
		{"olud", append([]byte("OLUD"), "abc"...)},
		{"olud_empty", []byte("OLUD")},
		{"short_of_the_magic", []byte("OLU")},
		{"olub_empty", []byte("OLUB")},
		{"olub_two", zzBatch(datagramBatchMagic, []byte("OLUDone"), []byte("OLUDtwo"))},
		{"olub_one_length_byte", append([]byte("OLUB"), 0)},
		{"olub_short_entry", append([]byte("OLUB"), 0, 5, 'a')},
		{"olub_zero_entry", append([]byte("OLUB"), 0, 0)},
		{"olub_stray_byte", append(zzBatch(datagramBatchMagic, []byte("OLUDone")), 9)},
		{"olkb", zzBatch(kcpBatchMagic, []byte("x"))},
		{"empty", nil},
	}
	var splits []map[string]any
	for _, in := range inputs {
		e := map[string]any{"name": in.name, "hex": zzvectors.Hex(in.b)}
		if d, ok := splitDatagramPayload(in.b); ok {
			e["olud"] = zzvectors.Hex(d)
		}
		if ps, ok := splitDatagramBatchPayload(in.b); ok {
			got := make([]string, 0, len(ps))
			for _, p := range ps {
				got = append(got, zzvectors.Hex(p))
			}
			e["olub"] = got
		}
		splits = append(splits, e)
	}
	zzvectors.Write(t, "vp8/datagram.json", zzWireGen,
		[]string{"internal/transport/vp8channel/datagram.go:15-141", "internal/transport/vp8channel/writer.go:179-245"},
		map[string]any{
			"token": tok, "local_epoch": zzLocal, "max_datagram": maxLen,
			"frames": frames, "batch": batches, "split": splits,
		})
}

// W27: what a client makes of each frame (inbound.go:11-71, control.go:96-120,
// datagram.go:115-137): its effects, read off the transport. Both planes are
// hand-built kcpConns with no session, so what a plane was handed stays in
// its queue (or its corrupt count).
func zzInboundVectors(t *testing.T) {
	t.Helper()
	type effects struct {
		PeerSeen  bool `json:"peer_seen"`
		Data      int  `json:"data"`
		Control   int  `json:"control"`
		Datagrams int  `json:"datagrams"`
		Touched   bool `json:"touched"`
		Restart   bool `json:"restart"`
	}
	tok := bindingToken(zzChannel)
	lc, pc := zzLocal|controlEpochFlag, zzPeer|controlEpochFlag
	kp := zzKCPPacket(30, 1)
	kp2, kp3 := zzKCPPacket(40, 2), zzKCPPacket(10, 3)
	bad := zzWith(kp, func(b []byte) { b[len(b)-1] ^= 0xff })
	olud := func(s string) []byte { return append([]byte("OLUD"), s...) }
	cases := []struct {
		name, scenario string
		frame          []byte
	}{
		{"short", "fresh", zzFrame(tok, zzPeer, zzLocal)[:epochHdrLen-1]},
		{"bad_crc", "confirmed", zzWith(zzFrame(tok, zzPeer, zzLocal, kp), func(b []byte) { b[crcOff+2] ^= 1 })},
		{"foreign_token", "confirmed", zzFrame(bindingToken("other"), zzPeer, zzLocal, kp)},
		{"token_zero", "confirmed", zzFrame(0, zzPeer, zzLocal, kp)},
		{"loopback_data", "confirmed", zzFrame(tok, zzLocal, 0, kp)},
		{"loopback_control", "confirmed", zzFrame(tok, lc, 0, kp)},
		{"dst_other", "confirmed", zzFrame(tok, zzPeer, 0x999, kp)},
		{"dst_other_control_epoch", "confirmed", zzFrame(tok, zzPeer, 0x999|controlEpochFlag, kp)},
		{"data_to_our_control_epoch", "confirmed", zzFrame(tok, zzPeer, lc, kp)},
		{"control_keepalive", "confirmed", zzFrame(tok, pc, lc)},
		{"control_keepalive_broadcast", "confirmed", zzFrame(tok, pc, 0)},
		{"control_broadcast", "confirmed", zzFrame(tok, pc, 0, kp)},
		{"control_to_our_data_epoch", "confirmed", zzFrame(tok, pc, zzLocal, kp)},
		{"control_before_confirmation", "fresh", zzFrame(tok, pc, lc, kp)},
		{"control_batch", "confirmed", zzFrame(tok, pc, lc, zzBatch(kcpBatchMagic, kp, kp2))},
		{"control_from_another_epoch", "fresh", zzFrame(tok, zzOther|controlEpochFlag, lc, kp)},
		{"datagram", "confirmed", zzFrame(tok, zzPeer, zzLocal, olud("udp"))},
		{"datagram_broadcast", "confirmed", zzFrame(tok, zzPeer, 0, olud("udp"))},
		{"datagram_other_src", "confirmed", zzFrame(tok, zzOther, zzLocal, olud("udp"))},
		{"datagram_before_confirmation", "fresh", zzFrame(tok, zzPeer, zzLocal, olud("udp"))},
		{"datagram_batch", "confirmed", zzFrame(tok, zzPeer, zzLocal, zzBatch(datagramBatchMagic, olud("a"), olud("b")))},
		{"datagram_batch_one_bare", "confirmed", zzFrame(tok, zzPeer, zzLocal, zzBatch(datagramBatchMagic, olud("a"), []byte("raw")))},
		{"datagram_batch_truncated", "confirmed", zzFrame(tok, zzPeer, zzLocal, append([]byte("OLUB"), 0, 5, 'a'))},
		{"datagram_batch_other_src", "confirmed", zzFrame(tok, zzOther, zzLocal, zzBatch(datagramBatchMagic, olud("a")))},
		{"data_before_confirmation", "fresh", zzFrame(tok, zzPeer, 0, kp)},
		{"data_other_epoch_unhealthy", "unhealthy", zzFrame(tok, zzOther, zzLocal, kp)},
		{"data_other_epoch_unhealthy_recent", "unhealthy_recent", zzFrame(tok, zzOther, zzLocal, kp)},
		{"data_other_epoch_healthy", "confirmed", zzFrame(tok, zzOther, zzLocal, kp)},
		{"data_src_zero", "unhealthy", zzFrame(tok, 0, zzLocal, kp)},
		{"data_keepalive", "confirmed", zzFrame(tok, zzPeer, zzLocal)},
		{"data", "confirmed", zzFrame(tok, zzPeer, zzLocal, kp)},
		{"data_broadcast", "confirmed", zzFrame(tok, zzPeer, 0, kp)},
		{"data_batch", "confirmed", zzFrame(tok, zzPeer, zzLocal, zzBatch(kcpBatchMagic, kp, kp2, kp3))},
		{"data_batch_bad_entry", "confirmed", zzFrame(tok, zzPeer, zzLocal, append(zzBatch(kcpBatchMagic, kp), append([]byte{0, 0}, kp2...)...))},
		{"data_bad_kcp_crc", "confirmed", zzFrame(tok, zzPeer, zzLocal, bad)},
	}
	var out []map[string]any
	for _, cs := range cases {
		datagrams := 0
		tr := zzTestTransport(transport.Config{OnDatagram: func([]byte) { datagrams++ }}, 1)
		data := newKCPConn(make(chan *packetBuffer, 1), 64, tr.epochHeader())
		control := newKCPConn(make(chan *packetBuffer, 1), 64, tr.controlEpochHeader())
		tr.data.set(&kcpRuntime{conn: data})
		tr.control.set(&kcpRuntime{conn: control})
		switch cs.scenario {
		case "fresh":
		case "confirmed", "unhealthy", "unhealthy_recent":
			if err := tr.ConfirmPeer(formatPeerID(zzPeer)); err != nil {
				t.Fatal(err)
			}
			if cs.scenario != "unhealthy_recent" {
				// An hour since the peer's last frame (ConfirmPeer stamps now).
				tr.lastPeerFrameNano.Store(time.Now().Add(-time.Hour).UnixNano())
			}
			tr.linkUnhealthy.Store(cs.scenario != "confirmed")
		default:
			t.Fatalf("scenario %q", cs.scenario)
		}
		before := tr.lastPeerFrameNano.Load()
		tr.handleIncomingFrame(cs.frame)
		e := effects{
			PeerSeen:  tr.peerSeen.Load(),
			Data:      len(data.in) + int(data.corrupt.Load()), //nolint:gosec // G115: a count
			Control:   len(control.in) + int(control.corrupt.Load()),
			Datagrams: datagrams,
			Touched:   tr.lastPeerFrameNano.Load() != before,
			Restart:   tr.peerRestarting.Load(),
		}
		out = append(out, map[string]any{
			"name": cs.name, "scenario": cs.scenario, "frame": zzvectors.Hex(cs.frame), "effects": e,
		})
	}
	zzvectors.Write(t, "vp8/inbound-verdicts.json", zzWireGen,
		[]string{
			"internal/transport/vp8channel/inbound.go:11-102", "internal/transport/vp8channel/control.go:96-120",
			"internal/transport/vp8channel/datagram.go:115-137", "internal/transport/vp8channel/transport.go:438-457",
		}, map[string]any{
			"channel": zzChannel, "local_epoch": zzLocal, "peer_epoch": zzPeer,
			"scenarios": map[string]string{
				"fresh":            "no peer confirmed, the link healthy",
				"confirmed":        "the peer confirmed, its last frame an hour ago, the link healthy",
				"unhealthy":        "the peer confirmed, its last frame an hour ago, the link unhealthy",
				"unhealthy_recent": "the peer confirmed just now, the link unhealthy",
			},
			"cases": out,
		})
}

// W34, W35: the VP9 carrier (carrier.go:109-250).
func zzVP9Vectors(t *testing.T) {
	t.Helper()
	tok := bindingToken(zzChannel)
	var dresses []map[string]any
	var undresses []map[string]any
	for _, c := range []struct {
		n        int
		keyframe bool
	}{{0, false}, {0, true}, {10, false}, {10, true}, {1000, true}, {1294, true}, {1295, true}, {1400, true}, {3000, false}, {3000, true}} {
		frame := zzFrame(tok, zzLocal, zzPeer, zzvectors.Pattern(c.n, 4))
		d := vp9Dress(nil, frame, c.keyframe)
		dresses = append(dresses, map[string]any{
			"payload": zzvectors.PatternSpec{Len: c.n, Seed: 4}, "keyframe": c.keyframe, "dressed": zzBytes(d),
		})
		u := vp9Undress(d)
		if u == nil || string(u[tokenOff:]) != string(frame[tokenOff:]) {
			t.Fatalf("undress of a dressed frame of %d", c.n)
		}
	}
	short := vp9Dress(nil, []byte{1, 2, 3}, true)
	samples := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"one_byte", []byte{0}},
		{"head_short_of_the_token", []byte{0, 5}},
		{"head_at_the_token_no_room", []byte{0, 20}},
		{"head_past_the_sample", []byte{0, 30, 0, 0}},
		{"head_at_the_token", append(zzvectors.Pattern(38, 5), 0, 20)},
		{"one_byte_short", append(zzvectors.Pattern(37, 5), 0, 20)},
		{"short_frame_dressed", short},
		{"dressed", vp9Dress(nil, zzFrame(tok, zzLocal, zzPeer, []byte("kcp")), false)},
	}
	for _, s := range samples {
		u := vp9Undress(s.b)
		e := map[string]any{"name": s.name, "hex": zzvectors.Hex(s.b), "ok": u != nil}
		if u != nil {
			e["view"] = zzvectors.Hex(u)
		}
		undresses = append(undresses, e)
	}

	var pays []map[string]any
	for _, c := range []struct {
		id   uint16
		mtu  uint16
		lens []int
	}{
		{0x7fff, 1188, []int{2500, 1}},
		{0, 1188, []int{1180, 1181, 1185, 1186}},
		{0x1234, 1188, []int{0, 3000}},
		{5, 8, []int{1}},
		{5, 9, []int{10}},
	} {
		p := &vp9Payloader{pictureID: c.id}
		var samples []map[string]any
		for i, n := range c.lens {
			s := zzvectors.Pattern(n, byte(i+1)) //nolint:gosec // G115: a few
			pkts := p.Payload(c.mtu, s)
			hex := make([]map[string]any, 0, len(pkts))
			for _, k := range pkts {
				hex = append(hex, zzBytes(k))
			}
			samples = append(samples, map[string]any{
				"sample": zzvectors.PatternSpec{Len: n, Seed: byte(i + 1)}, "packets": hex, "next_picture_id": p.pictureID, //nolint:gosec // G115
			})
		}
		pays = append(pays, map[string]any{"picture_id": c.id, "mtu": c.mtu, "samples": samples})
	}
	zzvectors.Write(t, "vp9/carrier.json", zzWireGen,
		[]string{"internal/transport/vp8channel/carrier.go:109-250"},
		map[string]any{
			"head": zzvectors.Hex(vp9Head), "token": tok, "local_epoch": zzLocal, "peer_epoch": zzPeer,
			"dress": dresses, "undress": undresses, "payload": pays,
		})
}

// zzPacketsDigest is a sample's packets as their lengths, their first four
// bytes and one SHA-256 over every packet behind its u16 BE length.
func zzPacketsDigest(pkts [][]byte) map[string]any {
	lens := make([]int, 0, len(pkts))
	heads := make([]string, 0, len(pkts))
	var all []byte
	for _, k := range pkts {
		lens = append(lens, len(k))
		heads = append(heads, zzvectors.Hex(k[:min(len(k), 4)]))
		all = binary.BigEndian.AppendUint16(all, uint16(len(k))) //nolint:gosec // G115: a packet
		all = append(all, k...)
	}
	return map[string]any{"lens": lens, "heads": heads, "sha256": zzvectors.Sum(all)}
}

// zzSampleWriter is TrackLocalStaticSample.WriteSample's timing
// (webrtc/v4@v4.2.15/track_local_static.go:343-383, copied: the track itself
// needs a bound PeerConnection) around pion's own packetizer.
type zzSampleWriter struct {
	p         rtp.Packetizer
	remainder float64
}

func (w *zzSampleWriter) write(data []byte, d time.Duration) []*rtp.Packet {
	tickF := d.Seconds() * 90000
	curTotal := tickF + w.remainder
	curTicks := uint32(curTotal)
	w.remainder = curTotal - float64(curTicks)
	return w.p.Packetize(data, curTicks)
}

func zzPacketizer(payloader rtp.Payloader, seq uint16, ts uint32) *zzSampleWriter {
	return &zzSampleWriter{p: rtp.NewPacketizerWithOptions(
		1200, payloader, rtp.NewFixedSequencer(seq), 90000,
		rtp.WithTimestamp(ts), rtp.WithSSRC(1), rtp.WithPayloadType(96))}
}

// W36: what pion makes of the samples the transport writes on its VP8 track
// (mediaengine.go:826: picture ids on; packetizer.go; constants.go:41).
func zzRTPVectors(t *testing.T) {
	t.Helper()
	// One payloader through a wrap of the 15-bit picture id, a sample a
	// call: one byte, except at the calls where the descriptor changes size
	// or the id wraps, which carry 2400 bytes (three packets).
	p := &codecs.VP8Payloader{EnablePictureID: true}
	boundary := map[int]bool{0: true, 1: true, 127: true, 128: true, 129: true, 0x7fff: true, 0x8000: true}
	var heads, full []map[string]any
	for k := 0; k <= 0x8000+2; k++ {
		sample := []byte{0xab}
		if boundary[k] {
			sample = zzvectors.Pattern(2400, byte(k)) //nolint:gosec // G115: a seed
		}
		out := p.Payload(1188, sample)
		if k < 260 || k >= 0x7ff0 {
			heads = append(heads, map[string]any{"call": k, "hex": zzvectors.Hex(out[0][:min(len(out[0]), 5)])})
		}
		if boundary[k] {
			full = append(full, map[string]any{
				"call": k, "sample": zzvectors.PatternSpec{Len: 2400, Seed: byte(k)}, "packets": zzPacketsDigest(out), //nolint:gosec // G115
			})
		}
	}
	if out := p.Payload(1188, nil); out != nil {
		t.Fatal("an empty sample made packets")
	}
	// The sizes around one packet's worth, for each descriptor size.
	var sizes []map[string]any
	for _, calls := range []int{0, 5, 200} {
		for _, n := range []int{1183, 1184, 1185, 1186, 1187, 1188, 1189, 2368, 2369, 2374, 2375} {
			q := &codecs.VP8Payloader{EnablePictureID: true}
			for range calls {
				q.Payload(1188, []byte{0})
			}
			sizes = append(sizes, map[string]any{
				"calls_before": calls, "sample": zzvectors.PatternSpec{Len: n, Seed: 7},
				"packets": zzPacketsDigest(q.Payload(1188, zzvectors.Pattern(n, 7))),
			})
		}
	}

	var tracks []map[string]any
	for _, c := range []struct {
		name string
		fps  int
		seq  uint16
		ts   uint32
		lens []int
	}{
		{"fps60", 60, 65534, 100, []int{3000, 1, 0, 1, 1188 - 3, 1188 - 2, 20}},
		{"fps30", 30, 0, 0xfffff000, []int{20, 20, 2400}},
		{"fps240", 240, 7, 0, []int{20, 20, 20}},
	} {
		w := zzPacketizer(&codecs.VP8Payloader{EnablePictureID: true}, c.seq, c.ts)
		d := time.Second / time.Duration(c.fps)
		var samples []map[string]any
		for i, n := range c.lens {
			pkts := w.write(zzvectors.Pattern(n, byte(i)), d) //nolint:gosec // G115
			got := []map[string]any{}
			for _, k := range pkts {
				got = append(got, map[string]any{
					"seq": k.SequenceNumber, "timestamp": k.Timestamp, "marker": k.Marker, "payload": zzBytes(k.Payload),
				})
			}
			samples = append(samples, map[string]any{"sample": zzvectors.PatternSpec{Len: n, Seed: byte(i)}, "packets": got}) //nolint:gosec // G115
		}
		// A long run: the timestamp the carried fraction comes to.
		var last uint32
		for i := 0; i < 20000; i++ {
			last = w.write([]byte{1}, d)[0].Timestamp
		}
		tracks = append(tracks, map[string]any{
			"name": c.name, "frame_interval_ns": d.Nanoseconds(), "seq": c.seq, "timestamp": c.ts,
			"samples": samples, "after_20000_more": last,
		})
	}

	vp9 := zzPacketizer(&vp9Payloader{pictureID: 0x1234}, 100, 1000)
	var vp9Pkts []map[string]any
	for _, k := range vp9.write(vp9Dress(nil, zzFrame(bindingToken(zzChannel), zzLocal, zzPeer, []byte("kcp")), true), time.Second/60) {
		vp9Pkts = append(vp9Pkts, map[string]any{
			"seq": k.SequenceNumber, "timestamp": k.Timestamp, "marker": k.Marker, "payload": zzBytes(k.Payload),
		})
	}

	zzvectors.Write(t, "vp8/rtp.json", zzWireGen,
		[]string{
			"pion/webrtc/v4@v4.2.15/mediaengine.go:826", "pion/webrtc/v4@v4.2.15/track_local_static.go:343-383",
			"pion/webrtc/v4@v4.2.15/constants.go:41", "pion/rtp@v1.10.2/packetizer.go:87-145",
			"pion/rtp@v1.10.2/codecs/vp8_packet.go:1-95", "internal/transport/vp8channel/writer.go:82-112",
		}, map[string]any{
			"payload_mtu":  1188,
			"heads":        heads,
			"boundary":     full,
			"sizes":        sizes,
			"tracks":       tracks,
			"vp9_keyframe": map[string]any{"picture_id": 0x1234, "seq": 100, "timestamp": 1000, "packets": vp9Pkts},
		})
}

//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package vp8channel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	runtimecfg "github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

func TestZZVectors(t *testing.T) {
	zzvectors.Write(t, "transport/vp8channel.json", "internal/transport/vp8channel/zz_vectors_test.go TestZZVectors",
		[]string{"internal/transport/vp8channel/transport.go:56-57"}, map[string]any{
			"max_payload_size": defaultMaxPayloadSize,
		})
	zzKCPSettingsVectors(t)
	zzKCPSegmentVectors(t)
}

// zzSettingKeys are the settings the vectors keep: ZZKCPSettingFields (none
// of which a session's timer changes before a packet moves) and the
// session's own.
var zzSettingKeys = append(append([]string{}, ZZKCPSettingFields...), //nolint:gochecknoglobals // fixed
	"ackNoDelay", "writeDelay", "headerSize")

func zzSettings(sess *kcp.UDPSession) map[string]int64 {
	all := ZZKCPSettings(sess)
	out := map[string]int64{}
	for _, k := range zzSettingKeys {
		out[k] = all[k]
	}
	return out
}

// W32: what startKCP leaves in kcp-go for each host profile, read before any
// packet moves (vp8channel/kcp.go:17-36,76-106,155-179).
func zzKCPSettingsVectors(t *testing.T) {
	t.Helper()
	profile := func(constrained bool, sndWnd int) map[string]int64 {
		runtimecfg.ResetBufferProfileForTest()
		if constrained {
			runtimecfg.UseConstrainedBuffers()
		}
		defer runtimecfg.ResetBufferProfileForTest()
		out := make(chan *packetBuffer, 16)
		rt, err := startKCP(out, nil, testEpochHdr(1), sndWnd)
		if err != nil {
			t.Fatalf("startKCP: %v", err)
		}
		defer rt.close()
		return zzSettings(rt.sess)
	}
	cases := map[string]any{
		"server":       profile(false, 0),
		"server_paced": profile(false, kcpSendWindow(true)),
		"phone":        profile(true, 0),
	}
	zzvectors.Write(t, "vp8/kcp-settings.json", "internal/transport/vp8channel/zz_vectors_test.go TestZZVectors",
		[]string{
			"internal/transport/vp8channel/kcp.go:17-36,76-106,138-190",
			"kcp-go/v5@v5.6.72/kcp.go:166-200,1097-1121", "kcp-go/v5@v5.6.72/sess.go:192-240,520-640",
		}, cases)
}

// zzBareKCP is startKCPAcks without its read loop: the same conn and the
// same settings (kcp.go:149-179, copied), so nothing drains its receive
// queue and the windows it advertises do not depend on a goroutine's timing.
// zzKCPSegmentVectors checks its settings equal startKCP's.
func zzBareKCP(t *testing.T, out chan<- *packetBuffer, hdr [epochHdrLen]byte, snd, rcv int) (*kcpConn, *kcp.UDPSession) {
	t.Helper()
	c := newKCPConn(out, inboundQueueSizeFor(), hdr)
	sess, err := kcp.NewConn3(kcpConvID, fakeUDPAddr(), nil, 0, 0, c)
	if err != nil {
		t.Fatalf("kcp new conn: %v", err)
	}
	sess.SetNoDelay(1, 5, 2, 1)
	sess.SetWindowSize(snd, rcv)
	sess.SetMtu(kcpMTU)
	sess.SetStreamMode(true) //nolint:staticcheck // SA1019: as startKCP
	sess.SetACKNoDelay(true)
	sess.SetWriteDelay(false)
	return c, sess
}

// zzMask is a KCP packet with every segment's ts (bytes 8..12) zeroed, and a
// line per packet: "cmd frg wnd sn una len" per segment, ";" between them.
func zzMask(t *testing.T, p []byte) ([]byte, string) {
	t.Helper()
	m := append([]byte(nil), p...)
	var segs []string
	for off := 0; off < len(m); {
		if len(m)-off < 24 {
			t.Fatalf("a packet with %d stray bytes", len(m)-off)
		}
		h := m[off:]
		conv := binary.LittleEndian.Uint32(h[0:4])
		if conv != kcpConvID {
			t.Fatalf("conv %08x", conv)
		}
		cmd, frg := h[4], h[5]
		wnd := binary.LittleEndian.Uint16(h[6:8])
		sn := binary.LittleEndian.Uint32(h[12:16])
		una := binary.LittleEndian.Uint32(h[16:20])
		n := int(binary.LittleEndian.Uint32(h[20:24]))
		for i := 8; i < 12; i++ {
			h[i] = 0
		}
		segs = append(segs, fmt.Sprintf("%d %d %d %d %d %d", cmd, frg, wnd, sn, una, n))
		off += 24 + n
		if off > len(m) {
			t.Fatalf("a segment past its packet")
		}
	}
	return m, strings.Join(segs, ";")
}

type zzRecorder struct {
	mu   sync.Mutex
	pkts [][]byte
	last time.Time
}

func (r *zzRecorder) add(p []byte) {
	r.mu.Lock()
	r.pkts = append(r.pkts, append([]byte(nil), p...))
	r.last = time.Now()
	r.mu.Unlock()
}

func (r *zzRecorder) take() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pkts
	r.pkts = nil
	return p
}

func (r *zzRecorder) idleSince() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Since(r.last)
}

// zzPump forwards every packet from out to deliver at once, recording the
// KCP packet (no epoch header, no CRC) first.
func zzPump(t *testing.T, stop <-chan struct{}, out <-chan *packetBuffer, rec *zzRecorder, deliver func([]byte)) {
	t.Helper()
	for {
		select {
		case <-stop:
			return
		case p := <-out:
			body := p.data[epochHdrLen : len(p.data)-wireCRCLen]
			rec.add(body)
			deliver(p.data[epochHdrLen:])
			p.release()
		}
	}
}

// W31 (and W33 on the stream): the segments the engine's KCP writes for a
// fixed script, and what a receiver with the phone's windows answers, with
// the two pumped to each other at once. A is startKCP itself, server
// profile; B is zzBareKCP with the phone's 512/512 and never read, so its
// window closes. ts is masked (kcp-go stamps the wall clock); everything
// else is the bytes.
func zzKCPSegmentVectors(t *testing.T) {
	t.Helper()
	runtimecfg.ResetBufferProfileForTest()
	aOut := make(chan *packetBuffer, outboundQueueSizeFor())
	bOut := make(chan *packetBuffer, outboundQueueSizeFor())
	a, err := startKCP(aOut, nil, testEpochHdr(1), 0)
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}
	defer a.close()
	bConn, b := zzBareKCP(t, bOut, testEpochHdr(2), kcpConstrainedSndWnd, kcpConstrainedRcvWnd)
	defer func() { _ = b.Close(); _ = bConn.Close() }()

	// The bare session is startKCP's phone profile, field for field.
	runtimecfg.UseConstrainedBuffers()
	ref, err := startKCP(make(chan *packetBuffer, 16), nil, testEpochHdr(3), 0)
	runtimecfg.ResetBufferProfileForTest()
	if err != nil {
		t.Fatalf("startKCP: %v", err)
	}
	want, got := zzSettings(ref.sess), zzSettings(b)
	ref.close()
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("zzBareKCP %s = %d, startKCP's phone profile has %d", k, got[k], v)
		}
	}

	stop := make(chan struct{})
	defer close(stop)
	recA, recB := &zzRecorder{}, &zzRecorder{}
	go zzPump(t, stop, aOut, recA, bConn.deliver)
	go zzPump(t, stop, bOut, recB, a.deliver)

	settle := func(fixed time.Duration) {
		if fixed > 0 {
			time.Sleep(fixed)
			return
		}
		// Quiet for 100 ms both ways; RTO is at least 30 ms after the first
		// sample, but nothing is lost here, so nothing is resent.
		time.Sleep(20 * time.Millisecond)
		for recA.idleSince() < 100*time.Millisecond || recB.idleSince() < 100*time.Millisecond {
			time.Sleep(10 * time.Millisecond)
		}
	}
	describe := func(pkts [][]byte) map[string]any {
		lines := make([]string, 0, len(pkts))
		sum := sha256.New()
		for _, p := range pkts {
			m, line := zzMask(t, p)
			lines = append(lines, line)
			var l [4]byte
			binary.BigEndian.PutUint32(l[:], uint32(len(m))) //nolint:gosec // G115: a packet
			sum.Write(l[:])
			sum.Write(m)
		}
		return map[string]any{"packets": lines, "masked_sha256": hex.EncodeToString(sum.Sum(nil))}
	}

	type step struct {
		name  string
		msg   *zzvectors.PatternSpec // a message A sends, if any
		dup   bool                   // B gets A's first packet again
		fixed time.Duration          // a fixed wait instead of the quiet one
	}
	// B's queue holds 1 + 3 + 1 + 30 = 35 segments before "fill", whose one
	// message is 477 segments (656,348 + 4 bytes = 477 × 1376): B's window
	// closes, A probes once 500 ms later, B answers. The next probe is due
	// 750 ms after that one, so 900 ms catches exactly one.
	steps := []step{
		{name: "hello", msg: &zzvectors.PatternSpec{Len: 5, Seed: 1}},
		{name: "three_segments", msg: &zzvectors.PatternSpec{Len: 3000, Seed: 2}},
		{name: "empty", msg: &zzvectors.PatternSpec{Len: 0, Seed: 3}},
		{name: "thirty_segments", msg: &zzvectors.PatternSpec{Len: 40000, Seed: 4}},
		{name: "duplicate", dup: true},
		{name: "fill", msg: &zzvectors.PatternSpec{Len: 477*1376 - kcpLenPrefix, Seed: 5}, fixed: 900 * time.Millisecond},
	}
	var first []byte
	var out []map[string]any
	for _, s := range steps {
		switch {
		case s.msg != nil:
			if err := a.send(zzvectors.Pattern(s.msg.Len, s.msg.Seed)); err != nil {
				t.Fatalf("%s: send: %v", s.name, err)
			}
		case s.dup:
			p := append(append([]byte(nil), first...), 0, 0, 0, 0)
			binary.BigEndian.PutUint32(p[len(first):], crc32.Checksum(first, crcTable))
			bConn.deliver(p)
		}
		settle(s.fixed)
		pa, pb := recA.take(), recB.take()
		if s.name == "hello" {
			first = pa[0]
		}
		entry := map[string]any{"name": s.name, "a": describe(pa), "b": describe(pb)}
		if s.msg != nil {
			entry["message"] = s.msg
		}
		if s.dup {
			entry["duplicate_of"] = "hello"
		}
		if s.fixed > 0 {
			entry["wait_ms"] = s.fixed.Milliseconds()
		}
		out = append(out, entry)
	}
	zzvectors.Write(t, "vp8/kcp.json", "internal/transport/vp8channel/zz_vectors_test.go TestZZVectors",
		[]string{
			"internal/transport/vp8channel/kcp.go:59,66,113-118,138-190,236-256",
			"internal/transport/vp8channel/kcpconn.go:180-205,335-352",
			"kcp-go/v5@v5.6.72/kcp.go", "kcp-go/v5@v5.6.72/sess.go:366-451,970-1121",
		}, map[string]any{
			"a":     "startKCP, server profile (4096/4096)",
			"b":     "startKCP's phone profile (512/512) without its read loop",
			"steps": out,
		})
}

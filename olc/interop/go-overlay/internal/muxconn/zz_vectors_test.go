//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package muxconn

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzConstants struct {
	DataAAD             string `json:"data_aad"`
	ControlAAD          string `json:"control_aad"`
	InboundQueue        int    `json:"inbound_queue"`
	PooledFrameCap      int    `json:"pooled_frame_cap"`
	WriteReadyTimeoutMs int64  `json:"write_ready_timeout_ms"`
	DecryptLogMs        int64  `json:"decrypt_log_interval_ms"`
	SmuxHeaderSize      int    `json:"smux_header_size"`
	SmuxCmdSYN          int    `json:"smux_cmd_syn"`
	SmuxCmdPSH          int    `json:"smux_cmd_psh"`
	SmuxFirstStream     int    `json:"smux_first_stream"`
}

type zzScanCase struct {
	Name       string `json:"name"`
	Record     string `json:"record"`
	PayloadLen uint64 `json:"payload_len"`
	First      bool   `json:"first"`
	Opens      bool   `json:"opens"`
}

type zzLimitCase struct {
	MaxPayload      int   `json:"max_payload"`
	WriteIntervalUs int64 `json:"write_interval_us"`
	Batches         bool  `json:"batches"`
	Limit           int   `json:"limit"`
}

// zzBatchStep is one call on a batcher with no flusher running: "append" of
// a frame of Len bytes, "take" by the flusher, or "done" once it has sent.
type zzBatchStep struct {
	Op         string `json:"op"`
	Len        int    `json:"len,omitempty"`
	Queued     bool   `json:"queued"`
	Batch      uint64 `json:"batch"`
	Taken      int    `json:"taken"`
	DueAfter   bool   `json:"due_after"`
	PendingLen int    `json:"pending_len"`
}

type zzBatchSequence struct {
	Name       string        `json:"name"`
	MaxPayload int           `json:"max_payload"`
	Limit      int           `json:"limit"`
	Steps      []zzBatchStep `json:"steps"`
}

type zzFile struct {
	Constants zzConstants       `json:"constants"`
	Scan      []zzScanCase      `json:"scan"`
	Limits    []zzLimitCase     `json:"batch_limits"`
	Batches   []zzBatchSequence `json:"batch_sequences"`
}

// zzFrame lays out one smux frame header (version, cmd, length LE, sid LE)
// with body appended; length is the header's field, which may lie.
func zzFrame(version, cmd byte, length uint16, sid uint32, body []byte) []byte {
	out := make([]byte, 8, 8+len(body))
	out[0], out[1] = version, cmd
	binary.LittleEndian.PutUint16(out[2:4], length)
	binary.LittleEndian.PutUint32(out[4:8], sid)
	return append(out, body...)
}

func zzCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestZZVectors(t *testing.T) {
	file := zzFile{Constants: zzConstants{
		DataAAD: dataRecordAAD, ControlAAD: controlRecordAAD, InboundQueue: inboundQueue,
		PooledFrameCap: pooledFrameCap, WriteReadyTimeoutMs: writeReadyTimeout.Milliseconds(),
		DecryptLogMs: decryptLogInterval.Milliseconds(), SmuxHeaderSize: smuxHeaderSize,
		SmuxCmdSYN: smuxCmdSYN, SmuxCmdPSH: smuxCmdPSH, SmuxFirstStream: smuxFirstStream,
	}}

	body5 := []byte("hello")
	scans := []struct {
		name   string
		record []byte
	}{
		{"empty", nil},
		{"shorter than a header", []byte{2, 2, 5, 0, 3, 0, 0}},
		{"psh on stream 3", zzFrame(2, smuxCmdPSH, 5, 3, body5)},
		{"psh on stream 0", zzFrame(2, smuxCmdPSH, 5, 0, body5)},
		{"psh, version 1", zzFrame(1, smuxCmdPSH, 5, 7, body5)},
		{"psh, version 0", zzFrame(0, smuxCmdPSH, 5, 7, body5)},
		{"psh, version 3", zzFrame(3, smuxCmdPSH, 5, 7, body5)},
		{"psh with an empty body", zzFrame(2, smuxCmdPSH, 0, 3, nil)},
		{"psh on the largest stream id", zzFrame(2, smuxCmdPSH, 5, 0xffffffff, body5)},
		{"syn of the first stream", zzFrame(2, smuxCmdSYN, 0, 3, nil)},
		{"syn of stream 5", zzFrame(2, smuxCmdSYN, 0, 5, nil)},
		{"syn of stream 1", zzFrame(2, smuxCmdSYN, 0, 1, nil)},
		{"syn of stream 0", zzFrame(2, smuxCmdSYN, 0, 0, nil)},
		{"fin", zzFrame(2, 1, 0, 3, nil)},
		{"nop", zzFrame(2, 3, 0, 0, nil)},
		{"upd", zzFrame(2, 4, 8, 3, zzvectors.Pattern(8, 4))},
		{"unknown command with a body", zzFrame(2, 9, 4, 3, zzvectors.Pattern(4, 9))},
		{"length beyond the record", zzFrame(2, smuxCmdPSH, 100, 3, body5)},
		{"largest length beyond the record", zzFrame(2, smuxCmdPSH, 0xffff, 3, zzvectors.Pattern(300, 1))},
		{"a batch: syn, psh, psh, upd", zzCat(
			zzFrame(2, smuxCmdSYN, 0, 3, nil),
			zzFrame(2, smuxCmdPSH, 5, 3, body5),
			zzFrame(2, smuxCmdPSH, 3, 5, []byte("abc")),
			zzFrame(2, 4, 8, 3, zzvectors.Pattern(8, 1)))},
		{"a batch with syns of streams 5 and 3", zzCat(
			zzFrame(2, smuxCmdSYN, 0, 5, nil),
			zzFrame(2, smuxCmdSYN, 0, 3, nil))},
		{"a batch whose second frame has a bad version", zzCat(
			zzFrame(2, smuxCmdPSH, 5, 3, body5),
			zzFrame(7, smuxCmdPSH, 5, 3, body5),
			zzFrame(2, smuxCmdPSH, 5, 3, body5))},
		{"a frame then seven stray bytes", zzCat(
			zzFrame(2, smuxCmdPSH, 5, 3, body5),
			[]byte{2, 2, 1, 0, 3, 0, 0})},
		{"a frame then a syn hidden in the first's body", zzFrame(2, smuxCmdPSH, 8, 9, zzFrame(2, smuxCmdSYN, 0, 3, nil))},
		{"a frame whose length swallows the next", zzCat(
			zzFrame(2, smuxCmdPSH, 13, 3, body5),
			zzFrame(2, smuxCmdSYN, 0, 3, nil))},
	}
	for _, c := range scans {
		first, opens := openedStreams(c.record)
		file.Scan = append(file.Scan, zzScanCase{Name: c.name, Record: zzvectors.Hex(c.record),
			PayloadLen: streamPayloadLen(c.record), First: first, Opens: opens})
	}

	limits := []struct {
		max      int
		interval time.Duration
	}{
		{12 * 1024, 5 * time.Millisecond},
		{12 * 1024, 0},
		{60 * 1024, 0},
		{60 * 1024, time.Millisecond},
		{44, 5 * time.Millisecond},
		{45, 5 * time.Millisecond},
		{46, 5 * time.Millisecond},
		{0, 5 * time.Millisecond},
		{-1, 5 * time.Millisecond},
		{12 * 1024, -time.Millisecond},
	}
	for _, c := range limits {
		lc := zzLimitCase{MaxPayload: c.max, WriteIntervalUs: c.interval.Microseconds()}
		if b := newBatcher(transport.Features{MaxPayloadSize: c.max, WriteInterval: c.interval}); b != nil {
			lc.Batches, lc.Limit = true, b.limit
		}
		file.Limits = append(file.Limits, lc)
	}

	type step struct {
		op  string
		len int
	}
	appendOf := func(n int) step { return step{"append", n} }
	take := step{op: "take"}
	done := step{op: "done"}
	sequences := []struct {
		name  string
		max   int
		steps []step
	}{
		{"small frames gather until half a record", 12 * 1024, []step{
			appendOf(8), appendOf(40), appendOf(1000), appendOf(5000), appendOf(73), appendOf(1),
			take, done, appendOf(8)}},
		{"a frame that does not fit waits for the take", 12 * 1024, []step{
			appendOf(6000), appendOf(6000), appendOf(300), take, appendOf(300), done, appendOf(12244)}},
		{"a frame alone may exceed the limit", 12 * 1024, []step{
			appendOf(12300), appendOf(1), take, appendOf(1), done}},
		{"exactly the limit fits", 12 * 1024, []step{
			appendOf(6121), appendOf(6123), appendOf(1), take, done, take}},
		{"a take with nothing pending", 12 * 1024, []step{
			take, appendOf(10), take, done, take}},
		{"the smallest batching link", 46, []step{
			appendOf(1), appendOf(1), appendOf(1), take, done}},
	}
	for _, s := range sequences {
		b := newBatcher(transport.Features{MaxPayloadSize: s.max, WriteInterval: 5 * time.Millisecond})
		seq := zzBatchSequence{Name: s.name, MaxPayload: s.max, Limit: b.limit}
		var record []byte
		for _, st := range s.steps {
			bs := zzBatchStep{Op: st.op, Len: st.len}
			switch st.op {
			case "append":
				queued, batch, err := b.append(zzvectors.Pattern(st.len, byte(st.len)))
				if err != nil {
					t.Fatalf("append: %v", err)
				}
				bs.Queued, bs.Batch = queued, batch
			case "take":
				record = b.take()
				bs.Taken = len(record)
			case "done":
				b.done(record)
			}
			// The signals carry no state the vectors need; drain them so a
			// later step sees the same channels a flusher would have left.
			select {
			case <-b.kick:
			default:
			}
			select {
			case <-b.moved:
			default:
			}
			bs.DueAfter = b.due()
			b.mu.Lock()
			bs.PendingLen = len(b.pending)
			b.mu.Unlock()
			seq.Steps = append(seq.Steps, bs)
		}
		file.Batches = append(file.Batches, seq)
	}

	zzvectors.Write(t, "muxconn.json", "internal/muxconn/zz_vectors_test.go TestZZVectors",
		[]string{"internal/muxconn/conn.go:72-117", "internal/muxconn/conn.go:557-593", "internal/muxconn/batch.go:51-213"}, file)
}

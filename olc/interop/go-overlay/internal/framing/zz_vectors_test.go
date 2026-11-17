//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package framing

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzWriteCase struct {
	Body    string `json:"body"`
	Max     int    `json:"max"`
	Verdict string `json:"verdict"`
	Frame   string `json:"frame,omitempty"`
	Writes  int    `json:"writes"`
}

type zzReadCase struct {
	Name     string `json:"name"`
	Input    string `json:"input"`
	Max      int    `json:"max"`
	Verdict  string `json:"verdict"`
	Body     string `json:"body,omitempty"`
	Consumed int    `json:"consumed"`
}

type zzFile struct {
	HeaderSize int           `json:"header_size"`
	Write      []zzWriteCase `json:"write"`
	Read       []zzReadCase  `json:"read"`
}

// zzCountingWriter counts Write calls: WriteBytes makes exactly one
// (framing.go:32-52).
type zzCountingWriter struct {
	bytes.Buffer
	calls int
}

func (w *zzCountingWriter) Write(p []byte) (int, error) {
	w.calls++
	return w.Buffer.Write(p)
}

// zzReadVerdict names ReadBytes' failures by where the stream ended.
func zzReadVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrFrameTooLarge):
		return "too_large"
	case strings.HasPrefix(err.Error(), "read hdr: ") && errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated_header"
	case strings.HasPrefix(err.Error(), "read hdr: ") && errors.Is(err, io.EOF):
		return "eof_header"
	case strings.HasPrefix(err.Error(), "read body: ") && errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated_body"
	case strings.HasPrefix(err.Error(), "read body: ") && errors.Is(err, io.EOF):
		return "eof_body"
	default:
		return "other: " + err.Error()
	}
}

func TestZZVectors(t *testing.T) {
	file := zzFile{HeaderSize: headerSize}
	writes := []struct {
		body []byte
		max  int
	}{
		{nil, 0},
		{[]byte("{}"), 16},
		{zzvectors.Pattern(255, 1), 0},
		{zzvectors.Pattern(256, 2), 0},
		{zzvectors.Pattern(16, 3), 16},
		{zzvectors.Pattern(17, 4), 16},
		{[]byte(`{"version":1,"type":"CONTROL_PING","seq":1}`), 16 * 1024},
	}
	for _, c := range writes {
		var w zzCountingWriter
		err := WriteBytes(&w, c.body, c.max)
		wc := zzWriteCase{Body: zzvectors.Hex(c.body), Max: c.max, Writes: w.calls}
		if err != nil {
			wc.Verdict = zzReadVerdict(err)
		} else {
			wc.Verdict = "ok"
			wc.Frame = zzvectors.Hex(w.Bytes())
		}
		file.Write = append(file.Write, wc)
	}
	reads := []struct {
		name  string
		input string
		max   int
	}{
		{"empty body", "00000000", 0},
		{"one frame", "0000000568656c6c6f", 16},
		{"a frame, then the next one's bytes", "00000003616263646566", 0},
		{"length equal to max", "00000004deadbeef", 4},
		{"length above max", "00000005deadbeef00", 4},
		{"length above max, nothing after it", "00010001", 65536},
		{"max zero allows anything", "00000005deadbeef00", 0},
		{"stream ended before the header", "", 16},
		{"stream ended inside the header", "000000", 16},
		{"stream ended before the body", "00000005", 16},
		{"stream ended inside the body", "00000005dead", 16},
	}
	for _, c := range reads {
		input := zzvectors.MustHex(t, c.input)
		r := bytes.NewReader(input)
		body, err := ReadBytes(r, c.max)
		rc := zzReadCase{Name: c.name, Input: c.input, Max: c.max, Verdict: zzReadVerdict(err), Consumed: len(input) - r.Len()}
		if err == nil {
			rc.Body = zzvectors.Hex(body)
		}
		file.Read = append(file.Read, rc)
	}
	zzvectors.Write(t, "framing.json", "internal/framing/zz_vectors_test.go TestZZVectors",
		[]string{"internal/framing/framing.go:17-69"}, file)
}

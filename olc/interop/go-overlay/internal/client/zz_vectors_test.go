//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package client

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"github.com/openlibrecommunity/olcrtc/internal/tunnelcore"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzConnectCase struct {
	Name      string `json:"name"`
	Host      string `json:"host_hex"`
	Port      int    `json:"port"`
	Ack       int    `json:"ack"`
	Request   string `json:"request"`
	Text      string `json:"request_text"`
	Verdict   string `json:"verdict"`
	ErrorText string `json:"error_text,omitempty"`
}

type zzConnectFile struct {
	AckOK              int             `json:"ack_ok"`
	AckHostUnreachable int             `json:"ack_host_unreachable"`
	Cases              []zzConnectCase `json:"cases"`
}

// zzCapture runs sendConnectRequest (tunnel.go:95-117) on a real smux stream
// and returns what the far end read before it answered with ack.
func zzCapture(t *testing.T, host string, port int, ack byte) ([]byte, error) {
	t.Helper()
	near, far := net.Pipe()
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cs, err := smux.Client(near, cfg)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	defer func() { _ = cs.Close() }()
	ss, err := smux.Server(far, cfg)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	defer func() { _ = ss.Close() }()

	got := make(chan []byte, 1)
	go func() {
		st, err := ss.AcceptStream()
		if err != nil {
			got <- nil
			return
		}
		var buf []byte
		chunk := make([]byte, 256)
		for !json.Valid(buf) {
			n, err := st.Read(chunk)
			buf = append(buf, chunk[:n]...)
			if err != nil {
				break
			}
		}
		_, _ = st.Write([]byte{ack})
		got <- buf
	}()
	st, err := cs.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	sendErr := (&Client{}).sendConnectRequest(st, host, port)
	select {
	case body := <-got:
		return body, sendErr
	case <-time.After(10 * time.Second):
		t.Fatalf("capture of %q timed out", host)
		return nil, nil
	}
}

func TestZZVectors(t *testing.T) {
	file := zzConnectFile{AckOK: int(tunnelcore.ConnectAckOK), AckHostUnreachable: int(tunnelcore.ConnectAckHostUnreachable)}
	cases := []struct {
		name string
		host string
		port int
		ack  byte
	}{
		{"domain", "example.com", 443, tunnelcore.ConnectAckOK},
		{"ipv4", "1.2.3.4", 80, tunnelcore.ConnectAckOK},
		{"ipv6", "2001:db8::1", 443, tunnelcore.ConnectAckOK},
		{"port zero", "example.com", 0, tunnelcore.ConnectAckOK},
		{"port one", "example.com", 1, tunnelcore.ConnectAckOK},
		{"largest port", "example.com", 65535, tunnelcore.ConnectAckOK},
		{"empty host", "", 443, tunnelcore.ConnectAckOK},
		{"quote, backslash and html", `a"b\c<d>&e`, 443, tunnelcore.ConnectAckOK},
		{"short escapes", "\b\f\n\r\t", 443, tunnelcore.ConnectAckOK},
		{"other control bytes and delete", "\x00\x01\x1f\x7f", 443, tunnelcore.ConnectAckOK},
		{"line and paragraph separators", "a\u2028b\u2029c", 443, tunnelcore.ConnectAckOK},
		{"non-ascii name", "пример.рф", 443, tunnelcore.ConnectAckOK},
		{"four-byte rune", "x\U0001F600y", 443, tunnelcore.ConnectAckOK},
		{"replacement character", "\uFFFD", 443, tunnelcore.ConnectAckOK},
		{"invalid utf-8", "\xff\xfeab\xc3(\xe2\x82\xed\xa0\x80", 443, tunnelcore.ConnectAckOK},
		{"host unreachable", "2001:db8::2", 443, tunnelcore.ConnectAckHostUnreachable},
		{"other ack code", "example.com", 443, 0x01},
	}
	for _, c := range cases {
		body, err := zzCapture(t, c.host, c.port, c.ack)
		cc := zzConnectCase{Name: c.name, Host: zzvectors.Hex([]byte(c.host)), Port: c.port, Ack: int(c.ack),
			Request: zzvectors.Hex(body), Text: string(body), Verdict: "ok"}
		if err != nil {
			cc.Verdict = "ack_error"
			cc.ErrorText = err.Error()
		}
		file.Cases = append(file.Cases, cc)
	}
	zzvectors.Write(t, "connect.json", "internal/client/zz_vectors_test.go TestZZVectors",
		[]string{"internal/client/tunnel.go:95-117", "internal/tunnelcore/core.go:19-20"}, file)
}

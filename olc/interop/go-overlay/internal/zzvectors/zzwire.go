//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

package zzvectors

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// WriteRaw stores body as <OLC_VECTORS_OUT>/<name> with no envelope: a vector
// that is a text of its own (an SDP). Skipped as Write is.
func WriteRaw(t testing.TB, name string, body []byte) {
	t.Helper()
	dir := os.Getenv("OLC_VECTORS_OUT")
	if dir == "" {
		t.Skip("OLC_VECTORS_OUT is not set")
	}
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// WireRequest is one HTTP/1.1 request as its bytes arrived on a connection:
// what a handler never sees, since net/http keeps headers in a map.
type WireRequest struct {
	// Conn numbers the connections of one Wire from 0, in the order they were
	// accepted: two requests with one number shared a connection.
	Conn int
	// Line is the request line without its line end.
	Line string
	// Headers are the header lines in wire order, without their line ends.
	Headers []string
	// Body is the body, Content-Length bytes of it.
	Body []byte
}

// Method, Target and Proto are the three words of the request line.
func (r WireRequest) Method() string { return r.word(0) }

// Target: see Method.
func (r WireRequest) Target() string { return r.word(1) }

// Proto: see Method.
func (r WireRequest) Proto() string { return r.word(2) }

func (r WireRequest) word(i int) string {
	words := strings.SplitN(r.Line, " ", 3)
	if i >= len(words) {
		return ""
	}
	return words[i]
}

// Wire is a TCP listener in front of an HTTP server: it passes every byte
// both ways and keeps each request as it was written. Only what HTTP/1.1
// with a Content-Length (or no body) looks like is understood; anything else
// fails the test.
type Wire struct {
	t       testing.TB
	ln      net.Listener
	backend string

	mu    sync.Mutex
	conns int
	reqs  []WireRequest
	// errs is what the listener could not read; Take fails the test on it.
	// (A goroutine that outlives the test must not call t.Errorf.)
	errs []string
}

// NewWire listens on loopback in front of the server at backendURL
// (http://host:port) until the test ends.
func NewWire(t testing.TB, backendURL string) *Wire {
	t.Helper()
	u, err := url.Parse(backendURL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		t.Fatalf("wire: backend %q is not an http URL", backendURL)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wire: listen: %v", err)
	}
	w := &Wire{t: t, ln: ln, backend: u.Host}
	t.Cleanup(func() { _ = ln.Close() })
	go w.accept()
	return w
}

// URL is the listener as a client names it.
func (w *Wire) URL() string { return "http://" + w.ln.Addr().String() }

// Host is the listener's host:port, the Host header a client sends it.
func (w *Wire) Host() string { return w.ln.Addr().String() }

// Take returns the requests seen since the last Take, in the order their
// last byte arrived, and fails the test if any byte was not understood.
func (w *Wire) Take() []WireRequest {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.errs) > 0 {
		w.t.Fatalf("wire: %s", strings.Join(w.errs, "; "))
	}
	out := w.reqs
	w.reqs = nil
	return out
}

func (w *Wire) fail(format string, args ...any) {
	w.mu.Lock()
	w.errs = append(w.errs, fmt.Sprintf(format, args...))
	w.mu.Unlock()
}

func (w *Wire) accept() {
	for {
		client, err := w.ln.Accept()
		if err != nil {
			return
		}
		w.mu.Lock()
		n := w.conns
		w.conns++
		w.mu.Unlock()
		go w.serve(client, n)
	}
}

func (w *Wire) serve(client net.Conn, n int) {
	defer func() { _ = client.Close() }()
	server, err := net.Dial("tcp4", w.backend)
	if err != nil {
		w.fail("dial the server: %v", err)
		return
	}
	defer func() { _ = server.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(client, server)
		_ = client.Close()
	}()
	in := bufio.NewReader(client)
	for {
		req, raw, readErr := ReadWireRequest(in)
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) {
				w.fail("connection %d: %v", n, readErr)
			}
			break
		}
		req.Conn = n
		w.mu.Lock()
		w.reqs = append(w.reqs, req)
		w.mu.Unlock()
		if _, err = server.Write(raw); err != nil {
			break
		}
	}
	if tcp, ok := server.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}

// ReadWireRequest reads one request and returns it with its exact bytes.
// io.EOF is a connection closed between requests.
func ReadWireRequest(in *bufio.Reader) (WireRequest, []byte, error) {
	var req WireRequest
	var raw []byte
	line, err := in.ReadString('\n')
	if err != nil {
		if line == "" {
			return req, nil, io.EOF
		}
		return req, nil, fmt.Errorf("a request line cut short: %w", err)
	}
	raw = append(raw, line...)
	if !strings.HasSuffix(line, "\r\n") {
		return req, nil, fmt.Errorf("request line %q does not end in CRLF", line)
	}
	req.Line = strings.TrimSuffix(line, "\r\n")
	if len(strings.Split(req.Line, " ")) != 3 {
		return req, nil, fmt.Errorf("request line %q is not three words", req.Line)
	}
	length := 0
	for {
		line, err = in.ReadString('\n')
		if err != nil {
			return req, nil, fmt.Errorf("a header cut short: %w", err)
		}
		raw = append(raw, line...)
		if !strings.HasSuffix(line, "\r\n") {
			return req, nil, fmt.Errorf("header line %q does not end in CRLF", line)
		}
		line = strings.TrimSuffix(line, "\r\n")
		if line == "" {
			break
		}
		req.Headers = append(req.Headers, line)
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return req, nil, fmt.Errorf("header line %q has no colon", line)
		}
		switch strings.ToLower(name) {
		case "content-length":
			length, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil || length < 0 {
				return req, nil, fmt.Errorf("header line %q is not a length", line)
			}
		case "transfer-encoding", "expect", "upgrade":
			return req, nil, fmt.Errorf("header line %q: the wire reads plain bodies only", line)
		}
	}
	if length > 0 {
		req.Body = make([]byte, length)
		if _, err = io.ReadFull(in, req.Body); err != nil {
			return req, nil, fmt.Errorf("a body cut short: %w", err)
		}
		raw = append(raw, req.Body...)
	}
	return req, raw, nil
}

// WireRecord is a WireRequest as a vector file holds it.
type WireRecord struct {
	// Flow names the call of the engine the request belongs to; Seq counts
	// the flow's requests from 0 in the order they were sent.
	Flow string `json:"flow"`
	Seq  int    `json:"seq"`
	// Server is which listener took it; Connection numbers that server's
	// connections within the flow from 0: requests with one number shared a
	// TCP connection.
	Server     string `json:"server"`
	Connection int    `json:"connection"`
	Method     string `json:"method"`
	Target     string `json:"target"`
	Proto      string `json:"proto"`
	// Headers are the header lines in wire order.
	Headers []string `json:"headers"`
	Body    string   `json:"body"`
}

// WireRecords turns one server's requests of one flow into records. mask is
// applied to the target, every header line and the body: it replaces what
// differs between two runs (a loopback port, a random id) by a name.
func WireRecords(flow, server string, reqs []WireRequest, mask func(string) string) []WireRecord {
	conns := map[int]int{}
	out := make([]WireRecord, 0, len(reqs))
	for _, r := range reqs {
		if _, seen := conns[r.Conn]; !seen {
			conns[r.Conn] = len(conns)
		}
		headers := make([]string, 0, len(r.Headers))
		for _, h := range r.Headers {
			headers = append(headers, mask(h))
		}
		out = append(out, WireRecord{
			Flow: flow, Server: server, Connection: conns[r.Conn],
			Method: r.Method(), Target: mask(r.Target()), Proto: r.Proto(),
			Headers: headers, Body: mask(string(r.Body)),
		})
	}
	return out
}

// Number sets Seq on records in their order.
func Number(records []WireRecord) []WireRecord {
	for i := range records {
		records[i].Seq = i
	}
	return records
}

// RawServer answers on loopback: every connection's first request gets the
// bytes reply returns for it, written as they are, and the connection is
// closed. For replies net/http's own server would not write unchanged (it
// trims a header value). It returns the server's http:// URL.
func RawServer(t testing.TB, reply func(WireRequest) []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("raw server: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				req, _, readErr := ReadWireRequest(bufio.NewReader(conn))
				if readErr != nil {
					return
				}
				_, _ = conn.Write(reply(req))
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

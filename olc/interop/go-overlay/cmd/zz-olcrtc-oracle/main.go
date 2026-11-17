//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Command zz-olcrtc-oracle is the decode oracle of the Rust port of the olcRTC
// client: it hands bytes the Rust code produced to the engine's own Go code at
// the pin and says what that code made of them. It is not part of the engine:
// olc/interop/build-oracle.sh in the xray-rust fork copies it, with the
// overlay's export shims, into a clean checkout of the pin and builds it.
//
// Protocol: one JSON object per line on stdin, one JSON object per line on
// stdout, in order. Every request has "op"; byte strings are lowercase hex.
// A reply carries "error" when the op itself could not run (bad request),
// never for a verdict of the code under test, which is in "verdict".
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/control"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/framing"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/server"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/tunnelcore"
	"github.com/openlibrecommunity/olcrtc/internal/udpwire"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type request struct {
	Op string `json:"op"`

	ID        string   `json:"id,omitempty"`
	KeyHex    string   `json:"key_hex,omitempty"`
	Role      string   `json:"role,omitempty"`
	Lane      string   `json:"lane,omitempty"`
	Data      string   `json:"data,omitempty"`
	Records   []string `json:"records,omitempty"`
	Max       int      `json:"max,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	PeerID    string   `json:"peer_id,omitempty"`
	AuthError string   `json:"auth_error,omitempty"`
	Challenge string   `json:"challenge,omitempty"`
	Port      int      `json:"port,omitempty"`
	Type      int      `json:"type,omitempty"`
	FlowID    uint64   `json:"flow_id,omitempty"`
	Payload   string   `json:"payload,omitempty"`
	Keys      string   `json:"keys,omitempty"`
}

type reply map[string]any

type oracle struct {
	keys  map[string]*crypto.KeySet
	conns map[string]*muxconn.Conn
}

func main() {
	o := &oracle{keys: map[string]*crypto.KeySet{}, conns: map[string]*muxconn.Conn{}}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	for in.Scan() {
		var req request
		var rep reply
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			rep = reply{"error": "bad request: " + err.Error()}
		} else {
			rep = o.handle(req)
		}
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "encode reply:", err)
			os.Exit(1)
		}
		if err := out.Flush(); err != nil {
			os.Exit(1)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
}

func (o *oracle) handle(req request) reply {
	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return reply{"error": "data is not hex: " + err.Error()}
	}
	switch req.Op {
	case "ping":
		return reply{"pin": zzvectors.Pin}
	case "keyset":
		return o.keyset(req)
	case "seal":
		return o.seal(req, data)
	case "open":
		return o.open(req, data)
	case "frame_read":
		r := bytes.NewReader(data)
		body, err := framing.ReadBytes(r, req.Max)
		return reply{"verdict": frameVerdict(err), "body": hex.EncodeToString(body), "consumed": len(data) - r.Len()}
	case "json_string":
		out, err := json.Marshal(string(data))
		if err != nil {
			return reply{"error": err.Error()}
		}
		return reply{"json": hex.EncodeToString(out)}
	case "hello_frame":
		// What Client writes (handshake.go:117-124): no claims.
		var buf bytes.Buffer
		err := framing.WriteJSON(&buf, handshake.Hello{Version: handshake.ProtoVersion, Type: handshake.TypeHello,
			DeviceID: string(data), Challenge: req.Challenge}, handshake.MaxMessageSize)
		return reply{"verdict": handshakeVerdict(err), "frame": hex.EncodeToString(buf.Bytes())}
	case "hello_server":
		return helloServer(req, data)
	case "control_read":
		msg, err := control.ZZReadMessage(bytes.NewReader(data))
		return reply{"verdict": controlVerdict(err), "version": msg.Version, "type": string(msg.Type),
			"seq": msg.Seq, "sent_unix_nano": msg.SentUnixNano}
	case "connect_frame":
		// What sendConnectRequest writes (tunnel.go:96-98).
		out, err := json.Marshal(map[string]any{"cmd": "connect", "addr": string(data), "port": req.Port})
		if err != nil {
			return reply{"error": err.Error()}
		}
		return reply{"request": hex.EncodeToString(out)}
	case "connect_parse":
		cmd, addr, port, parsed, validErr := server.ZZParseConnect(data)
		rep := reply{"parsed": parsed, "cmd": cmd, "addr": hex.EncodeToString([]byte(addr)), "port": port,
			"valid": parsed && validErr == nil}
		if validErr != nil {
			rep["valid_error"] = validErr.Error()
		}
		return rep
	case "udpwire_encode":
		payload, err := hex.DecodeString(req.Payload)
		if err != nil {
			return reply{"error": "payload is not hex"}
		}
		wire, err := udpwire.Encode(udpwire.Frame{Type: udpwire.FrameType(req.Type), FlowID: req.FlowID,
			Endpoint: udpwire.Endpoint{Host: string(data), Port: uint16(req.Port)}, Payload: payload}) //nolint:gosec // test input
		return reply{"verdict": udpVerdict(err), "wire": hex.EncodeToString(wire)}
	case "udpwire_decode":
		f, err := udpwire.Decode(data)
		return reply{"verdict": udpVerdict(err), "type": int(f.Type), "flow_id": f.FlowID,
			"host": f.Endpoint.Host, "port": f.Endpoint.Port, "payload": hex.EncodeToString(f.Payload)}
	case "smux_scan":
		first, opens := muxconn.ZZOpenedStreams(data)
		return reply{"payload_len": muxconn.ZZStreamPayloadLen(data), "first": first, "opens": opens}
	case "muxconn_new":
		return o.muxconnNew(req)
	case "muxconn_push":
		return o.muxconnPush(req)
	default:
		return reply{"error": "unknown op " + req.Op}
	}
}

func role(name string) (crypto.Role, error) {
	switch name {
	case "client":
		return crypto.Client, nil
	case "server":
		return crypto.Server, nil
	default:
		return 0, fmt.Errorf("unknown role %q", name)
	}
}

func lane(name string) ([]byte, error) {
	switch name {
	case "data":
		return []byte(muxconn.ZZDataAAD), nil
	case "control":
		return []byte(muxconn.ZZControlAAD), nil
	case "udp":
		return []byte(tunnelcore.UDPRecordAAD), nil
	default:
		return nil, fmt.Errorf("unknown lane %q", name)
	}
}

func (o *oracle) keyset(req request) reply {
	r, err := role(req.Role)
	if err != nil {
		return reply{"error": err.Error()}
	}
	keys, err := runtime.SetupKeySet(req.KeyHex, r)
	if err != nil {
		return reply{"verdict": "refused", "error_text": err.Error()}
	}
	o.keys[req.ID] = keys
	return reply{"verdict": "ok"}
}

func (o *oracle) seal(req request, plaintext []byte) reply {
	keys, aad, rep := o.keysAndLane(req)
	if rep != nil {
		return rep
	}
	record, err := keys.SealInto(nil, plaintext, aad)
	return reply{"verdict": cryptoVerdict(err), "record": hex.EncodeToString(record)}
}

func (o *oracle) open(req request, record []byte) reply {
	keys, aad, rep := o.keysAndLane(req)
	if rep != nil {
		return rep
	}
	plaintext, err := keys.OpenInto(nil, record, aad)
	stats := keys.ReorderStats(aad)
	return reply{"verdict": cryptoVerdict(err), "plaintext": hex.EncodeToString(plaintext),
		"skipped": stats.Skipped, "late": stats.Late}
}

func (o *oracle) keysAndLane(req request) (*crypto.KeySet, []byte, reply) {
	keys := o.keys[req.ID]
	if keys == nil {
		return nil, nil, reply{"error": "no key set " + req.ID}
	}
	aad, err := lane(req.Lane)
	if err != nil {
		return nil, nil, reply{"error": err.Error()}
	}
	return keys, aad, nil
}

type rw struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (b *rw) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *rw) Write(p []byte) (int, error) { return b.w.Write(p) }

func helloServer(req request, input []byte) reply {
	stream := &rw{r: bytes.NewReader(input)}
	auth := func(string, map[string]any) (string, error) {
		if req.AuthError != "" {
			return "", errors.New(req.AuthError)
		}
		return req.SessionID, nil
	}
	h, _, err := handshake.Server(stream, auth, req.PeerID)
	claims, _ := json.Marshal(h.Claims)
	return reply{"verdict": handshakeVerdict(err), "reply": hex.EncodeToString(stream.w.Bytes()),
		"version": h.Version, "type": string(h.Type), "device_id": hex.EncodeToString([]byte(h.DeviceID)),
		"challenge": h.Challenge, "claims": string(claims)}
}

// fakeLink is a transport that sends nowhere: the oracle only pushes records
// into the conns it builds over it.
type fakeLink struct{ features transport.Features }

func (f *fakeLink) Connect(context.Context) error   { return nil }
func (f *fakeLink) Send([]byte) error               { return nil }
func (f *fakeLink) Close() error                    { return nil }
func (f *fakeLink) SetReconnectCallback(func())     {}
func (f *fakeLink) SetShouldReconnect(func() bool)  {}
func (f *fakeLink) SetEndedCallback(func(string))   {}
func (f *fakeLink) WatchConnection(context.Context) {}
func (f *fakeLink) CanSend() bool                   { return true }
func (f *fakeLink) Features() transport.Features    { return f.features }
func (f *fakeLink) Reconnect(string)                {}
func (f *fakeLink) ControlSend([]byte) error        { return nil }
func (f *fakeLink) SetControlOnData(func([]byte))   {}
func (f *fakeLink) ControlCanSend() bool            { return true }

var _ transport.ControlPlane = (*fakeLink)(nil)

// muxconnNew builds a receiving conn of the server's side: muxconn.New for
// the data lane, NewControl for the control lane, over the key set req.Keys.
// The link sends every frame on its own, so no flusher runs.
func (o *oracle) muxconnNew(req request) reply {
	keys := o.keys[req.Keys]
	if keys == nil {
		return reply{"error": "no key set " + req.Keys}
	}
	link := &fakeLink{features: transport.Features{MaxPayloadSize: req.Max}}
	var conn *muxconn.Conn
	switch req.Lane {
	case "data":
		conn = muxconn.New(link, keys)
	case "control":
		conn = muxconn.NewControl(link, keys)
	default:
		return reply{"error": "unknown lane " + req.Lane}
	}
	o.conns[req.ID+"/"+req.Lane] = conn
	return reply{"verdict": "ok"}
}

// muxconnPush pushes each record and reads back whatever plaintext it gave,
// so the inbound queue never holds more than the records that opened empty.
func (o *oracle) muxconnPush(req request) reply {
	conn := o.conns[req.ID+"/"+req.Lane]
	if conn == nil {
		return reply{"error": "no conn " + req.ID + "/" + req.Lane}
	}
	var stream []byte
	for _, recHex := range req.Records {
		rec, err := hex.DecodeString(recHex)
		if err != nil {
			return reply{"error": "record is not hex"}
		}
		before := conn.InboundBytes()
		conn.Push(rec)
		delta := conn.InboundBytes() - before
		if delta == 0 {
			continue
		}
		buf := make([]byte, delta)
		done := make(chan error, 1)
		go func() {
			_, err := io.ReadFull(conn, buf)
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				return reply{"error": "read: " + err.Error()}
			}
		case <-time.After(5 * time.Second):
			return reply{"error": "read timed out"}
		}
		stream = append(stream, buf...)
	}
	stats := conn.DecryptStats()
	reorder := conn.ReorderStats()
	return reply{"stream": hex.EncodeToString(stream), "inbound_bytes": conn.InboundBytes(),
		"payload_bytes": conn.PayloadBytes(), "bad_magic": stats.BadMagic, "auth_failed": stats.AuthFailed,
		"skipped": reorder.Skipped, "late": reorder.Late}
}

func cryptoVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, crypto.ErrRecordTooShort):
		return "too_short"
	case errors.Is(err, crypto.ErrBadRecordMagic):
		return "bad_magic"
	case errors.Is(err, crypto.ErrInvalidCounter):
		return "invalid_counter"
	case errors.Is(err, crypto.ErrAuthentication):
		return "auth"
	case errors.Is(err, crypto.ErrReplayDuplicate):
		return "duplicate"
	case errors.Is(err, crypto.ErrReplayTooOld):
		return "too_old"
	case errors.Is(err, crypto.ErrCounterExhausted):
		return "counter_exhausted"
	default:
		return "other: " + err.Error()
	}
}

func frameVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, framing.ErrFrameTooLarge):
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

func handshakeVerdict(err error) string {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, handshake.ErrRejected):
		return "rejected"
	case errors.Is(err, handshake.ErrProtocolVersion):
		return "protocol_version"
	case errors.Is(err, handshake.ErrUnexpectedMessage):
		return "unexpected_message"
	case errors.Is(err, handshake.ErrChallengeMismatch):
		return "challenge_mismatch"
	case errors.Is(err, handshake.ErrChallengeRequired):
		return "challenge_required"
	case errors.Is(err, handshake.ErrFrameTooLarge):
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

func controlVerdict(err error) string {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, control.ErrProtocolVersion):
		return "protocol_version"
	case errors.Is(err, control.ErrUnexpectedMessage):
		return "unexpected_message"
	case errors.Is(err, control.ErrFrameTooLarge):
		return "frame_too_large"
	case errors.As(err, &syntax), errors.As(err, &typeErr):
		return "parse"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "read"
	default:
		return "other: " + err.Error()
	}
}

func udpVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, udpwire.ErrFrameTooShort):
		return "too_short"
	case errors.Is(err, udpwire.ErrBadMagic):
		return "bad_magic"
	case errors.Is(err, udpwire.ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, udpwire.ErrUnknownFrameType):
		return "unknown_type"
	case errors.Is(err, udpwire.ErrInvalidFlowID):
		return "invalid_flow_id"
	case errors.Is(err, udpwire.ErrInvalidEndpoint):
		return "invalid_endpoint"
	case errors.Is(err, udpwire.ErrPayloadTooLarge):
		return "payload_too_large"
	default:
		return "other: " + err.Error()
	}
}

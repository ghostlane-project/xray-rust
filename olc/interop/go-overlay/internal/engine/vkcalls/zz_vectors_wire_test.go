//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// frames.json of the VK Calls vectors (see zz_vectors_test.go): the command
// frames of the signalling socket, from orderedCommandFrame and as the
// engine's own client wrote them to a listener on loopback that speaks just
// enough WebSocket to keep every frame as it arrived.

package vkcalls

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // RFC 6455's accept key
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

// zzWSFrame is one client frame as it arrived.
type zzWSFrame struct {
	FIN    bool   `json:"fin"`
	Opcode byte   `json:"opcode"`
	Masked bool   `json:"masked"`
	Length uint64 `json:"length"`
	// Text is the payload; a long one is left out and SHA256 is its hash.
	Text   string `json:"text,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// zzSFU is the listener: one connection, a 101 for its handshake, a
// "response" for every command but hangup.
type zzSFU struct {
	ln net.Listener

	mu        sync.Mutex
	conn      net.Conn
	handshake []string
	frames    []zzWSFrame
	failure   string

	ready chan struct{}
	pong  chan struct{}
	done  chan struct{}
}

func zzNewSFU(t *testing.T) *zzSFU {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &zzSFU{ln: ln, ready: make(chan struct{}), pong: make(chan struct{}, 1), done: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *zzSFU) fail(format string, args ...any) {
	s.mu.Lock()
	if s.failure == "" {
		s.failure = fmt.Sprintf(format, args...)
	}
	s.mu.Unlock()
}

func (s *zzSFU) text(payload string) error {
	if len(payload) >= 126 {
		return fmt.Errorf("a server frame of %d bytes", len(payload))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write(append([]byte{0x81, byte(len(payload))}, payload...))
	return err
}

func (s *zzSFU) serve() {
	defer close(s.done)
	conn, err := s.ln.Accept()
	if err != nil {
		s.fail("accept: %v", err)
		close(s.ready)
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	in := bufio.NewReader(conn)
	// The handshake: the request line, then header lines to an empty one.
	var req []string
	for {
		line, readErr := in.ReadString('\n')
		if readErr != nil || !strings.HasSuffix(line, "\r\n") {
			s.fail("handshake line %q: %v", line, readErr)
			close(s.ready)
			return
		}
		if line == "\r\n" {
			break
		}
		req = append(req, strings.TrimSuffix(line, "\r\n"))
	}
	key := zzHeader(req, "Sec-WebSocket-Key")
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // RFC 6455
	s.mu.Lock()
	s.conn, s.handshake = conn, req
	s.mu.Unlock()
	_, err = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"))
	close(s.ready)
	if err != nil {
		s.fail("handshake reply: %v", err)
		return
	}
	var message []byte
	for {
		var head [2]byte
		if _, err := io.ReadFull(in, head[:]); err != nil {
			if !errors.Is(err, io.EOF) {
				s.fail("frame header: %v", err)
			}
			return
		}
		frame := zzWSFrame{FIN: head[0]&0x80 != 0, Opcode: head[0] & 0x0f, Masked: head[1]&0x80 != 0, Length: uint64(head[1] & 0x7f)}
		if head[0]&0x70 != 0 {
			s.fail("a frame with a reserved bit: %#x", head[0])
			return
		}
		switch frame.Length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(in, ext[:]); err != nil {
				s.fail("frame length: %v", err)
				return
			}
			frame.Length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(in, ext[:]); err != nil {
				s.fail("frame length: %v", err)
				return
			}
			frame.Length = binary.BigEndian.Uint64(ext[:])
		}
		if !frame.Masked || frame.Length > 1<<22 {
			s.fail("a client frame unmasked or of %d bytes", frame.Length)
			return
		}
		var mask [4]byte
		if _, err := io.ReadFull(in, mask[:]); err != nil {
			s.fail("frame mask: %v", err)
			return
		}
		payload := make([]byte, frame.Length)
		if _, err := io.ReadFull(in, payload); err != nil {
			s.fail("frame payload: %v", err)
			return
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		if len(payload) > 2*zzvectors.LargeOutput {
			frame.SHA256 = zzvectors.Sum(payload)
		} else {
			frame.Text = string(payload)
		}
		s.mu.Lock()
		s.frames = append(s.frames, frame)
		s.mu.Unlock()
		message = append(message, payload...)
		if !frame.FIN {
			continue
		}
		whole := message
		message = nil
		if string(whole) == "pong" {
			s.pong <- struct{}{}
			continue
		}
		var command struct {
			Command  string `json:"command"`
			Sequence int64  `json:"sequence"`
		}
		if err := json.Unmarshal(whole, &command); err != nil || command.Command == "" {
			s.fail("a message that is no command: %v", err)
			return
		}
		if command.Command == "hangup" {
			continue
		}
		reply := fmt.Sprintf(`{"sequence":%d,"response":%q,"type":"response"}`, command.Sequence, command.Command)
		if err := s.text(reply); err != nil {
			s.fail("reply: %v", err)
			return
		}
	}
}

// zzHeader is the value of the header called name among a handshake's lines.
func zzHeader(lines []string, name string) string {
	for _, line := range lines {
		if got, value, ok := strings.Cut(line, ": "); ok && strings.EqualFold(got, name) {
			return value
		}
	}
	return ""
}

type zzFrameCase struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Sequence int64  `json:"sequence"`
	// Payload is the command's payload as JSON (Go's map order is not the
	// frame's: the frame has its keys in byte order); null is no payload.
	Payload json.RawMessage `json:"payload"`
	// Frame is the text frame; Error the error text of a refused payload.
	Frame string `json:"frame"`
	Error string `json:"error,omitempty"`
}

type zzWireCommand struct {
	Command  string `json:"command"`
	Sequence int64  `json:"sequence"`
	// Frame is what orderedCommandFrame gives for it; a long one is left
	// out: DescriptionLen letters x are its description, with the session
	// id "session-1" and no SSRC.
	Frame          string `json:"frame,omitempty"`
	DescriptionLen int    `json:"description_len,omitempty"`
	Len            int    `json:"len"`
	SHA256         string `json:"sha256"`
	// Error is command's error text when nothing was written.
	Error string `json:"error,omitempty"`
}

type zzHandshake struct {
	Method  string   `json:"method"`
	Target  string   `json:"target"`
	Proto   string   `json:"proto"`
	Headers []string `json:"headers"`
}

func zzFrames(t *testing.T) {
	t.Helper()
	shaped, err := ShapeAnswer(fixtureOffer, fixtureNative,
		&ShapeState{SessionID: zzSessionID, AudioSSRC: map[string]uint32{"2": zzAudioSSRC}})
	if err != nil {
		t.Fatal(err)
	}
	// The payloads of Session.Connect (vkcalls.go:158-187) and acceptOffer.
	allocate := map[string]any{"capabilities": referenceCapabilities()}
	modifiers := map[string]any{"mediaModifiers": map[string]any{"denoise": true, "denoiseAnn": true}}
	settings := map[string]any{
		"mediaSettings": map[string]any{"isAudioEnabled": false, "isVideoEnabled": false,
			"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": true},
	}
	accept := acceptPayload(fixtureOffer, shaped, "session-1")

	var every strings.Builder
	for b := 0; b < 0x80; b++ {
		every.WriteByte(byte(b))
	}
	every.WriteString("é Мария 日本 \u2028\u2029 \U0001F600 \ufeff")
	type frameIn struct {
		name     string
		command  string
		sequence int64
		payload  any
	}
	ins := []frameIn{
		{"allocate-consumer, the engine's capabilities", "allocate-consumer", 1, allocate},
		{"update-media-modifiers", "update-media-modifiers", 2, modifiers},
		{"change-media-settings", "change-media-settings", 3, settings},
		{"accept-producer, the shaped answer of the answer test", "accept-producer", 4, accept},
		{"accept-producer for an offer that names no SSRC", "accept-producer", 5, acceptPayload("v=0\r\n", "v=0\r\ns=-", "")},
		{"a description with CRLF, angle brackets, an ampersand, quotes and a backslash", "accept-producer", 6,
			map[string]any{fieldDescription: "v=0\r\na=x:<tag> & \"quoted\" 'single' back\\slash /slash\ttab\r\n", "sessionId": "s<1>&", "ssrcs": []any{"1", "2"}}},
		{"a description of every ASCII byte and some that are not ASCII", "accept-producer", 7,
			map[string]any{fieldDescription: every.String()}},
		{"no payload", "x", 2, nil},
		{"a payload with no field", "x", 2, map[string]any{}},
		{"a payload with one field", "x", 2, map[string]any{"a": 1}},
		{"keys go out in byte order, at every depth", "x", 3,
			map[string]any{"b": map[string]any{"z": 1, "Z": 2, "a": []any{map[string]any{"y": nil, "x": true}}}, "B": "upper first", "": "empty key first", "é": 1.5}},
		{"a command name that needs escaping", "a\"b<c>\n", 4, nil},
		{"the largest sequence", "x", math.MaxInt64, nil},
		{"sequence zero and a negative one are written as they are", "x", 0, map[string]any{"sequence": -1}},
		// Refused.
		{"a payload that is a list", "x", 2, []int{1}},
		{"a payload that is a string", "x", 2, "text"},
		{"a payload that is a number", "x", 2, 7},
	}
	cases := []zzFrameCase{}
	for _, in := range ins {
		c := zzFrameCase{Name: in.name, Command: in.command, Sequence: in.sequence}
		payload, marshalErr := json.Marshal(in.payload)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		c.Payload = payload
		frame, frameErr := orderedCommandFrame(in.command, in.sequence, in.payload)
		switch {
		case frameErr == nil && json.Valid(frame):
			c.Frame = string(frame)
		case frameErr != nil && errors.Is(frameErr, ErrSignalingPayload):
			c.Error = frameErr.Error()
		default:
			t.Fatalf("%s: frame %q, error %v", in.name, frame, frameErr)
		}
		cases = append(cases, c)
	}

	// The same commands through the engine's client, as one connection.
	sfu := zzNewSFU(t)
	host := sfu.ln.Addr().String()
	query := "/ws2?conversationId=c&peerId=10020030040&token=join-token&userId=100200300400&entityType=USER"
	client, err := dialSignaling(context.Background(), "ws://"+host+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-sfu.ready
	bound := func(n int) map[string]any {
		return map[string]any{fieldDescription: strings.Repeat("x", n), "sessionId": "session-1", "ssrcs": []any{}}
	}
	empty, err := orderedCommandFrame("accept-producer", 5, bound(0))
	if err != nil {
		t.Fatal(err)
	}
	fits := signalingWriteBuffer - len(empty)
	sent := []zzWireCommand{}
	wanted := []string{}
	send := func(command string, payload any, descriptionLen int, refused bool) {
		sequence := int64(len(sent) + 1)
		frame, frameErr := orderedCommandFrame(command, sequence, payload)
		if frameErr != nil {
			t.Fatal(frameErr)
		}
		record := zzWireCommand{Command: command, Sequence: sequence, DescriptionLen: descriptionLen,
			Len: len(frame), SHA256: zzvectors.Sum(frame)}
		if descriptionLen == 0 {
			record.Frame = string(frame)
		}
		_, commandErr := client.command(context.Background(), command, payload)
		switch {
		case refused && errors.Is(commandErr, ErrSignalingFrameTooLarge):
			record.Error = commandErr.Error()
		case !refused && commandErr == nil:
			wanted = append(wanted, string(frame))
		default:
			t.Fatalf("%s %d: %v", command, sequence, commandErr)
		}
		sent = append(sent, record)
	}
	send("allocate-consumer", allocate, 0, false)
	send("update-media-modifiers", modifiers, 0, false)
	send("change-media-settings", settings, 0, false)
	send("accept-producer", accept, 0, false)
	send("accept-producer", bound(fits), fits, false)
	send("accept-producer", bound(fits+1), fits+1, true)
	if sent[4].Len != signalingWriteBuffer || sent[5].Len != signalingWriteBuffer+1 {
		t.Fatalf("the frames at the bound are %d and %d bytes", sent[4].Len, sent[5].Len)
	}
	if client.Self() != "100200300400" {
		t.Fatalf("self is %q", client.Self())
	}
	// The keepalive: the text "ping" is answered by the text "pong". The
	// client is idle here, so the pong's place among the frames is fixed.
	if err := sfu.text("ping"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sfu.pong:
	case <-time.After(10 * time.Second):
		t.Fatal("no pong")
	}
	client.close()
	select {
	case <-sfu.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the socket stayed open")
	}
	sfu.mu.Lock()
	failure, frames, handshake := sfu.failure, sfu.frames, sfu.handshake
	sfu.mu.Unlock()
	if failure != "" {
		t.Fatalf("the listener: %s", failure)
	}
	hangup := `{"command":"hangup","reason":"HUNGUP","sequence":7}`
	wanted = append(wanted, "pong", hangup)
	if len(frames) != len(wanted) {
		t.Fatalf("%d frames arrived, %d were sent", len(frames), len(wanted))
	}
	for i, frame := range frames {
		if !frame.FIN || frame.Opcode != 1 || frame.Length != uint64(len(wanted[i])) {
			t.Fatalf("frame %d: fin %v, opcode %d, %d bytes; sent %d bytes", i, frame.FIN, frame.Opcode, frame.Length, len(wanted[i]))
		}
		if frame.Text != "" && frame.Text != wanted[i] || frame.SHA256 != "" && frame.SHA256 != zzvectors.Sum([]byte(wanted[i])) {
			t.Fatalf("frame %d is not what was sent", i)
		}
	}
	if len(handshake) < 2 {
		t.Fatalf("the handshake is %q", handshake)
	}
	words := strings.Split(handshake[0], " ")
	if len(words) != 3 {
		t.Fatalf("the handshake's request line is %q", handshake[0])
	}
	key := zzHeader(handshake, "Sec-WebSocket-Key")
	if raw, decodeErr := base64.StdEncoding.DecodeString(key); decodeErr != nil || len(raw) != 16 {
		t.Fatalf("the handshake's key is %q", key)
	}
	mask := strings.NewReplacer(host, "<sfu>", key, "<key>")
	shake := zzHandshake{Method: words[0], Target: mask.Replace(words[1]), Proto: words[2]}
	for _, line := range handshake[1:] {
		shake.Headers = append(shake.Headers, mask.Replace(line))
	}

	zzvectors.Write(t, "vkcalls/frames.json", zzGenerator,
		[]string{
			"internal/engine/vkcalls/signaling.go:233-262 (orderedCommandFrame), 197-231 (command), 311-317 (hangup), 46 (the frame bound)",
			"internal/engine/vkcalls/signaling.go:107-146 (dialSignaling: the handshake's headers), 176-200 (the ping answered)",
			"internal/engine/vkcalls/vkcalls.go:46-57, 158-187, 404-414 (the payloads: capabilities, modifiers, settings, acceptPayload)",
			"internal/engine/vkcalls/signaling_test.go:220-289 (TestSignalingLargeCommandIsOneFrame, TestOrderedCommandFrameIsJSON)",
			"internal/engine/vkcalls/zz_vectors_wire_test.go (this generator's listener)",
		},
		struct {
			Note       string            `json:"note"`
			FrameBound int               `json:"frame_bound"`
			Ordered    []zzFrameCase     `json:"ordered"`
			WireNote   string            `json:"wire_note"`
			Masked     map[string]string `json:"masked"`
			Endpoint   string            `json:"endpoint"`
			Handshake  zzHandshake       `json:"handshake"`
			Commands   []zzWireCommand   `json:"commands"`
			Frames     []zzWSFrame       `json:"frames"`
			Hangup     string            `json:"hangup"`
		}{
			"ordered: orderedCommandFrame(command, sequence, payload). A frame is JSON as Go's encoding/json writes " +
				"it: <, > and & as \\u003c, \\u003e and \\u0026, U+2028 and U+2029 escaped, a payload's keys in byte order.",
			signalingWriteBuffer, cases,
			"One connection of the engine's signalling client (dialSignaling) to a listener on loopback: the " +
				"handshake request as written (header lines in wire order), the commands sent in their order, and " +
				"every client frame as it arrived. A frame of exactly frame_bound bytes goes out as one frame; one " +
				"byte more is refused before any byte is written and still takes a sequence number. After the " +
				"commands the listener sends the text ping, then the client closes: hangup carries the next sequence.",
			map[string]string{
				"<sfu>": "the listener's host:port",
				"<key>": "the handshake's Sec-WebSocket-Key: sixteen random bytes in base64",
			},
			"ws://<sfu>" + query, shake, sent, frames, hangup,
		})
}

// Probe (c) of the olcRTC Rust port's M2 stack spike (xray-rust gl/olc-spike, olc/spike/):
// str0m answers a real VK Calls SFU. This file is dropped into internal/engine/vkcalls of
// the engine at the exits' pin (scripts/probe-c-vkcalls.sh does it) and never committed to
// the engine.
//
// The engine's own code does the service's part, unchanged: the anonymous guest chain
// (auth/vkcalls Issue, again for every recruited guest), the signalling socket, the wait
// for SERVER topology (recruiting signaling-only guests), allocate-consumer, the producer
// offer, ShapeAnswer and accept-producer. Where the engine gives the offer to pion, this
// gives it to the Rust sdp-bridge (str0m accept_offer, answering as the DTLS client as the
// shaped answer says), shapes str0m's answer instead of pion's, and waits for ICE + DTLS.
//
// Environment (never argv: a room link is a secret of the gate's):
//
//	OLC_SPIKE_VKCALLS_ROOM  a VK Calls join link, https://vk.ru/call/join/<id> (the gate's
//	                        GATE_VKCALLS_ROOMS holds such links; one is enough)
//	OLC_SPIKE_BRIDGE        the sdp-bridge binary
//	OLC_SPIKE_BRIDGE_ARGS   its flags (default: --dtls dimpl --version 12 --stun chrome)
//	OLC_SPIKE_OUT           where its whole stderr goes (optional)
package vkcalls

import (
	"bufio"
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	authvk "github.com/openlibrecommunity/olcrtc/internal/auth/vkcalls"
	"github.com/openlibrecommunity/olcrtc/internal/engine"
)

func TestSpikeBridgeVKCalls(t *testing.T) {
	room, bridge := os.Getenv("OLC_SPIKE_VKCALLS_ROOM"), os.Getenv("OLC_SPIKE_BRIDGE")
	if room == "" || bridge == "" {
		t.Skip("set OLC_SPIKE_VKCALLS_ROOM (a VK Calls join link) and OLC_SPIKE_BRIDGE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	issue := func(ctx context.Context) (engine.Credentials, error) {
		c, err := authvk.New().Issue(ctx, auth.Config{RoomURL: room, Name: "olc-spike"})
		return engine.Credentials{URL: c.URL, Token: c.Token, Extra: c.Extra}, err
	}
	creds, err := issue(ctx)
	if err != nil {
		t.Fatalf("guest chain: %v", err)
	}
	created, err := New(ctx, engine.Config{URL: creds.URL, Token: creds.Token, Extra: creds.Extra, Name: "olc-spike", Refresh: issue})
	if err != nil {
		t.Fatal(err)
	}
	s := created.(*Session)

	signal, err := dialSignaling(ctx, s.endpoint, s.cfg.Resolver)
	if err != nil {
		t.Fatalf("signalling: %v", err)
	}
	defer signal.close()
	defer signal.hangup()
	if _, err := s.waitConnected(ctx, signal); err != nil {
		t.Fatalf("join / SERVER topology: %v", err)
	}
	if _, err := signal.command(ctx, "allocate-consumer", map[string]any{"capabilities": referenceCapabilities()}); err != nil {
		t.Fatalf("allocate-consumer: %v", err)
	}
	if _, err := signal.command(ctx, "update-media-modifiers", map[string]any{
		"mediaModifiers": map[string]any{"denoise": true, "denoiseAnn": true},
	}); err != nil {
		t.Fatalf("update-media-modifiers: %v", err)
	}
	note := waitOffer(ctx, signal)
	if note.Description == "" {
		t.Fatal("no producer offer")
	}
	if _, err := signal.command(ctx, "change-media-settings", map[string]any{
		"mediaSettings": map[string]any{"isAudioEnabled": false, "isVideoEnabled": false,
			"isScreenSharingEnabled": false, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": true},
	}); err != nil {
		t.Fatalf("change-media-settings: %v", err)
	}

	br := spikeStartBridge(ctx, t, bridge)
	br.send("REMOTE_OFFER " + hex.EncodeToString([]byte(note.Description)))
	native, err := hex.DecodeString(strings.TrimPrefix(br.expect("ANSWER"), "ANSWER "))
	if err != nil {
		t.Fatal(err)
	}
	shaped, err := ShapeAnswer(note.Description, string(native), NewShapeState())
	if err != nil {
		t.Fatalf("ShapeAnswer over str0m's answer: %v", err)
	}
	if _, err := signal.command(ctx, "accept-producer", acceptPayload(note.Description, shaped, note.SessionID)); err != nil {
		t.Fatalf("accept-producer: %v", err)
	}
	result := br.expect("RESULT")
	t.Log(result)
	if !strings.Contains(result, `"connected":true`) {
		t.Fatal("str0m did not connect to the VK Calls SFU")
	}
}

// spikeBridge is the Rust sdp-bridge on the other end of two pipes (the same as
// go/mtslink's: test files cannot share code across packages).
type spikeBridge struct {
	t     *testing.T
	stdin interface{ Write([]byte) (int, error) }
	lines chan string
}

func spikeStartBridge(ctx context.Context, t *testing.T, bin string) *spikeBridge {
	t.Helper()
	args := strings.Fields(os.Getenv("OLC_SPIKE_BRIDGE_ARGS"))
	if len(args) == 0 {
		args = []string{"--dtls", "dimpl", "--version", "12", "--stun", "chrome"}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("OLC_SPIKE_OUT"); path != "" {
		f, ferr := os.Create(path)
		if ferr != nil {
			t.Fatal(ferr)
		}
		t.Cleanup(func() { _ = f.Close() })
		cmd.Stderr = f
	} else {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Wait() })
	b := &spikeBridge{t: t, stdin: in, lines: make(chan string, 64)}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			b.lines <- sc.Text()
		}
		close(b.lines)
	}()
	return b
}

func (b *spikeBridge) send(line string) {
	b.t.Helper()
	if _, err := b.stdin.Write([]byte(line + "\n")); err != nil {
		b.t.Fatalf("bridge stdin: %v", err)
	}
}

// expect returns the next line starting with word, logging the others (ICE, CONNECTED).
func (b *spikeBridge) expect(word string) string {
	b.t.Helper()
	timeout := time.After(90 * time.Second)
	for {
		select {
		case line, ok := <-b.lines:
			if !ok {
				b.t.Fatalf("bridge exited before %s", word)
			}
			if strings.HasPrefix(line, word+" ") {
				return line
			}
			if strings.HasPrefix(line, "RESULT ") {
				b.t.Fatalf("bridge gave up before %s: %s", word, line)
			}
			b.t.Logf("bridge: %s", line)
		case <-timeout:
			b.t.Fatalf("no %s from the bridge in 90 s", word)
		}
	}
}

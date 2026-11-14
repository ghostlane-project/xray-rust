// Probe (b) of the olcRTC Rust port's M2 stack spike (xray-rust gl/olc-spike, olc/spike/):
// str0m joins a real MTS Link room. This file is dropped into internal/engine/mtslink of
// the engine at the exits' pin (scripts/probe-b-mtslink.sh does it) and never committed
// to the engine.
//
// The engine's own code does the service's part, unchanged: the guest chain
// (auth/mtslink Issue), the join URL (offerURL), the SDP POST (joinOffer), the pin
// (pinPeer) and the take-back (takeBack). The WebRTC end is the Rust sdp-bridge, driven
// over its stdin/stdout: it makes the offer in the web client's layout and must reach
// ICE + DTLS connected with the SFU.
//
// Environment (never argv: a room link is a secret of the gate's):
//
//	OLC_SPIKE_MTSLINK_ROOM  an MTS Link event join link of an endless meeting,
//	                        https://my.mts-link.ru/j/<owner>/<event> (the gate's
//	                        GATE_MTSLINK_ROOMS holds such links; one is enough)
//	OLC_SPIKE_BRIDGE        the sdp-bridge binary
//	OLC_SPIKE_BRIDGE_ARGS   its flags (default: --dtls dimpl --version 12 --stun chrome)
//	OLC_SPIKE_OUT           where its whole stderr goes (optional)
package mtslink

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
	authmts "github.com/openlibrecommunity/olcrtc/internal/auth/mtslink"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

func TestSpikeBridgeMTSLink(t *testing.T) {
	room, bridge := os.Getenv("OLC_SPIKE_MTSLINK_ROOM"), os.Getenv("OLC_SPIKE_BRIDGE")
	if room == "" || bridge == "" {
		t.Skip("set OLC_SPIKE_MTSLINK_ROOM (an endless meeting's join link) and OLC_SPIKE_BRIDGE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	// UDP: what the bridge gathers (str0m's ICE-TCP is a later milestone's).
	creds, err := authmts.New().Issue(ctx, auth.Config{RoomURL: room, Name: "olc-spike", DefaultICE: "udp"})
	if err != nil {
		t.Fatalf("guest chain: %v", err)
	}
	t.Logf("guest issued: gateway=%t conference=%t", creds.Extra["gateway"] != "", creds.Extra["conferenceId"] != "")
	client := protect.NewHTTPClient(protect.NewResolver(""))
	defer func() {
		leaveCtx, leaveCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer leaveCancel()
		if err := takeBack(leaveCtx, client, creds.Extra["gateway"], creds.Extra["conferenceId"], creds.Token); err != nil {
			t.Logf("take-back: %v", err)
		}
		client.CloseIdleConnections()
	}()

	br := spikeStartBridge(ctx, t, bridge)
	br.send("OFFER mtslink")
	fields := strings.Fields(br.expect("OFFER"))
	if len(fields) != 3 {
		t.Fatalf("bridge: OFFER line has %d fields", len(fields))
	}
	offer, err := hex.DecodeString(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	target, err := offerURL(creds.URL, fields[2])
	if err != nil {
		t.Fatal(err)
	}
	answer, err := joinOffer(ctx, client, target, string(offer))
	if err != nil {
		t.Fatalf("join (the SFU refused str0m's offer?): %v", redactURL(err))
	}
	if peer := peerOf(answer); peer != "" {
		if err := pinPeer(ctx, client, target, peer); err != nil {
			t.Logf("pin: %v", redactURL(err))
		}
	}
	br.send("ANSWER " + hex.EncodeToString([]byte(answer)))
	result := br.expect("RESULT")
	t.Log(result)
	if !strings.Contains(result, `"connected":true`) {
		t.Fatal("str0m did not connect to the MTS Link SFU")
	}
}

// spikeBridge is the Rust sdp-bridge on the other end of two pipes.
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

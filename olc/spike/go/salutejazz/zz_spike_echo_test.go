package salutejazz

// Ghostlane olc/spike, probe (a): the harness. Dropped into the engine's
// internal/engine/salutejazz at 2d4266af by scripts/probe-a.sh, never committed
// there. The engine's own Session joins the package's fake SFU
// (fakeconnector_test.go: the connector frames of the official web client, pion
// on the SFU side) as an echo, and the Rust sfu-probe joins the same room: what
// the probe publishes to the echo comes back to it through the relay, and the
// fake records any client frame that breaks the capture's shape (lastError).

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
)

type spikeEcho struct {
	from     string
	data     []byte
	datagram bool
}

func TestSpikeRustEcho(t *testing.T) {
	bin := os.Getenv("OLC_SPIKE_PROBE")
	if bin == "" {
		t.Skip("OLC_SPIKE_PROBE (the sfu-probe binary) is not set")
	}
	url, fake := newFakeConnector(t)

	queue := make(chan spikeEcho, 16384)
	var dropped atomic.Int64
	created, err := New(context.Background(), engine.Config{
		URL: url, Token: "passw0rd", Name: "go-echo",
		Extra: map[string]string{credentialKeyRoomID: "abc123"},
		OnPeerData: func(from string, d []byte) {
			queue <- spikeEcho{from: from, data: append([]byte(nil), d...)}
		},
		OnPeerDatagram: func(from string, d []byte) {
			select {
			case queue <- spikeEcho{from: from, data: append([]byte(nil), d...), datagram: true}:
			default:
				dropped.Add(1)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	echo := created.(*Session)
	t.Cleanup(func() { _ = echo.Close() })
	if err := echo.Connect(context.Background()); err != nil {
		t.Fatalf("echo connect: %v", err)
	}
	var sendErrs atomic.Int64
	go func() {
		for m := range queue {
			var err error
			if m.datagram {
				err = echo.SendDatagramTo(m.from, m.data)
			} else {
				err = echo.SendTo(m.from, m.data)
			}
			if err != nil {
				sendErrs.Add(1)
			}
		}
	}()

	args := []string{"--url", url, "--room", "abc123", "--password", "passw0rd"}
	args = append(args, strings.Fields(os.Getenv("OLC_SPIKE_ARGS"))...)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if path := os.Getenv("OLC_SPIKE_OUT"); path != "" {
		_ = os.WriteFile(path, out, 0o644)
	}
	t.Logf("sfu-probe %s:\n%s", strings.Join(args, " "), out)
	t.Logf("echo: %d sends refused, %d datagrams dropped at the echo's queue", sendErrs.Load(), dropped.Load())
	if runErr != nil {
		t.Fatalf("sfu-probe: %v", runErr)
	}
	if e := fake.lastError(); e != "" {
		t.Fatalf("the fake SFU tripped over the probe's frames: %s", e)
	}
	if !fake.sawAnswer() || !fake.sawPublisherOffer() {
		t.Fatalf("the fake saw answer=%v publisher offer=%v", fake.sawAnswer(), fake.sawPublisherOffer())
	}
	for _, j := range fake.joins() {
		t.Logf("join seen: group=%q payload=%s", j.group, j.payload)
	}
	for _, c := range fake.clientICE() {
		t.Logf("candidate seen: target=%s ufrag=%q", c.target, c.ufrag)
	}
}

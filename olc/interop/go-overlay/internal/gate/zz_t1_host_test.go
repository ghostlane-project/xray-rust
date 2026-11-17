// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the T1 side of a
// client that runs outside this process, the iOS simulator XCTest of plan
// §10.7 on a macOS runner (Ghostlane's lab/olc-ffi). It starts the hub, the
// origin, a UDP echo and the pinned server in a hub room, writes where they
// are to $OLC_T1_HOST_OUT as one JSON object, and keeps them up until
// $OLC_T1_HOST_OUT.stop exists or $OLC_T1_HOST_FOR (a Go duration, default
// 30m) passes:
//
//	OLC_T1_HOST_OUT=/tmp/t1.json go test -tags olcrtc_interop ./internal/gate \
//	    -run '^TestT1Host$' -olcrtc.gate-target=interop -timeout 40m
//
// The simulator shares the Mac's loopback, so every address is 127.0.0.1
// but the UDP echo's second one: the Mac's own non-loopback IPv4, for a
// datagram that hev's lwIP would not take to a loopback destination. The
// Android emulator (Ghostlane's lab/olc-ffi-android, on a Linux runner)
// reaches this host's loopback as 10.0.2.2, so its test dials the room
// there; the origin and the echo are dialed by the server, on this host,
// and keep their addresses. The big pull (-olcrtc.gate-big-mb MiB) is the
// emulator's download burst.

package gate

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
)

// t1Host is what the XCTest reads.
type t1Host struct {
	Room      string `json:"room"`
	Key       string `json:"key"`
	Transport string `json:"transport"`
	DNS       string `json:"dns"`
	// Origin is the origin's 1 KB (GET), http://127.0.0.1:<port>/kb.
	Origin string `json:"origin"`
	// Big is the origin's big pull (GET), BigBytes long.
	Big      string `json:"big"`
	BigBytes int64  `json:"big_bytes"`
	// EchoPort is the UDP echo's port on every address; EchoIP the Mac's
	// non-loopback IPv4 it answers on ("" when it has none).
	EchoPort int    `json:"echo_port"`
	EchoIP   string `json:"echo_ip"`
	// ServerLog is the server's log file while the host runs; it is copied
	// to $OLC_T1_HOST_OUT.server.log when the host stops.
	ServerLog string `json:"server_log"`
}

// hostIPv4 is the first up, non-loopback IPv4 of this host.
func hostIPv4() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return n.IP.String()
			}
		}
	}
	return ""
}

// TestT1Host runs the T1 side until told to stop.
func TestT1Host(t *testing.T) {
	out := os.Getenv("OLC_T1_HOST_OUT")
	if out == "" {
		t.Skip("set OLC_T1_HOST_OUT to the file the endpoints go to")
	}
	hold := 30 * time.Minute
	if v := os.Getenv("OLC_T1_HOST_FOR"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("OLC_T1_HOST_FOR: %v", err)
		}
		hold = d
	}
	interoppipe.Register()
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	// The server lives as long as the host holds, not a scenario's
	// childLifetime: the XCTest joins after the runner has built the Rust
	// core, ten minutes and more after the server came up.
	env := &e2eEnv{t: t, target: &InteropTarget{root: moduleRoot(t), work: t.TempDir(), hub: hub,
		origin: startOrigin(t)}, lifetime: hold + 5*time.Minute}
	_, ep := env.room(env.key())
	defer env.server(ep, []string{ep.Key}, true)()
	// The server's log, kept at $OLC_T1_HOST_OUT.server.log: this cleanup
	// runs after the deferred stop and before the server's TempDir goes.
	t.Cleanup(func() {
		if raw, err := os.ReadFile(env.serverLog); err == nil {
			_ = os.WriteFile(out+".server.log", raw, 0o644)
		}
	})

	echo, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], from)
		}
	}()

	host := t1Host{Room: ep.Room, Key: ep.Key, Transport: ep.Transport, DNS: ep.DNS,
		Origin: env.target.origin.URLs.Small, Big: env.target.origin.URLs.Big,
		BigBytes: env.target.origin.URLs.BigBytes, EchoPort: echo.LocalAddr().(*net.UDPAddr).Port,
		EchoIP: hostIPv4(), ServerLog: env.serverLog}
	raw, _ := json.Marshal(host)
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, out); err != nil {
		t.Fatal(err)
	}
	t.Logf("T1 host up: %s", strings.TrimSpace(string(raw)))

	until := time.Now().Add(hold)
	for time.Now().Before(until) {
		if _, err := os.Stat(out + ".stop"); err == nil {
			t.Logf("told to stop")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("held for %s; stopping", hold)
}

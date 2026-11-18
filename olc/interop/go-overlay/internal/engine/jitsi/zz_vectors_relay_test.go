//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): relaywin.json, the
// relay window (relaywindow.go) driven by scripts of sends, echoes and room
// checks at stated times, as the Rust port's RelayWindow is: what each step
// answers (open, held, or a probe with the count to mark), which marks went
// on the bridge, and whether the window is on and holding a sender afterwards. The
// session is bare: no bridge, no clock but the one the script names (the
// steps that read the real time, sends, are scripted at time zero).

package jitsi

import (
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzRelayOp struct {
	Op      string `json:"op"` // sent, echo, room, reset, timing (N: the probe interval, ms)
	N       int    `json:"n,omitempty"`
	Counter uint64 `json:"counter,omitempty"`
	AtMS    int64  `json:"at_ms"`
}

type zzRelayStep struct {
	Op    zzRelayOp `json:"op"`
	Room  string    `json:"room,omitempty"` // open, held or probe
	Probe uint64    `json:"probe,omitempty"`
	Marks []uint64  `json:"marks"`
	On    bool      `json:"on"`
	Full  bool      `json:"full"`
}

type zzRelayScript struct {
	Name  string        `json:"name"`
	Steps []zzRelayStep `json:"steps"`
}

func zzRunRelay(t *testing.T, name string, ops []zzRelayOp) zzRelayScript {
	js := newSilentSession(t)
	var out relayFrames
	js.sendHook = out.hook
	peer := "peer"
	js.peerEndpoint.Store(&peer)
	js.peerEpoch.Store(0xB0B0B0B0)
	js.localEpoch.Store(0xA0A0A0A0)
	// The first send marks (an unanswered window probes at once); after that
	// a mark is due by bytes alone, whatever the real clock says.
	js.relayTiming = relayTiming{probe: time.Hour, dead: 30 * time.Second}
	base := time.Now()
	script := zzRelayScript{Name: name}
	seen := 0
	for _, op := range ops {
		step := zzRelayStep{Op: op}
		switch op.Op {
		case "sent":
			js.relaySent("", op.N)
		case "echo":
			js.applyEcho(peer, windowFrame{kind: windowEcho, senderEpoch: 0xB0B0B0B0, receiverEpoch: 0xA0A0A0A0, counter: op.Counter})
		case "room":
			ok, counter, probe := js.relayRoom("", base.Add(time.Duration(op.AtMS)*time.Millisecond))
			switch {
			case probe:
				step.Room, step.Probe = "probe", counter
				js.sendWindowFrame("", windowMark, js.peerEpochFor(""), counter)
			case ok:
				step.Room = "open"
			default:
				step.Room = "held"
			}
		case "timing":
			js.relayTiming.probe = time.Duration(op.N) * time.Millisecond
		case "reset":
			js.resetRelayWindows()
		default:
			t.Fatalf("unknown op %q", op.Op)
		}
		out.mu.Lock()
		step.Marks = []uint64{}
		for _, f := range out.frames[seen:] {
			step.Marks = append(step.Marks, f.counter)
		}
		seen = len(out.frames)
		out.mu.Unlock()
		js.relayMu.Lock()
		st := js.relayWin[""]
		// Full: a room check found the window full and has held the sender
		// since (heldSince), what the Rust window's is_held says.
		step.On, step.Full = st != nil && st.active, st != nil && !st.heldSince.IsZero()
		js.relayMu.Unlock()
		script.Steps = append(script.Steps, step)
	}
	return script
}

func zzRelay(t *testing.T) {
	const w = relayWindow
	scripts := []zzRelayScript{
		// The first send marks; the echo of the mark turns the window on.
		zzRunRelay(t, "an_echo_turns_the_window_on", []zzRelayOp{
			{Op: "room"}, {Op: "sent", N: 1000}, {Op: "room"}, {Op: "echo", Counter: 1000}, {Op: "room"},
			{Op: "sent", N: 100}, {Op: "echo", Counter: 5000}, {Op: "echo", Counter: 1100}, {Op: "echo", Counter: 1100},
		}),
		// A full window holds, probes once a second, and opens on the echo.
		zzRunRelay(t, "a_full_window_holds_and_probes", []zzRelayOp{
			{Op: "sent", N: 1000}, {Op: "echo", Counter: 1000}, {Op: "timing", N: 1000},
			{Op: "sent", N: w - 1000}, {Op: "room", AtMS: 100}, {Op: "sent", N: 1000}, {Op: "room", AtMS: 200},
			{Op: "room", AtMS: 1500}, {Op: "room", AtMS: 1700}, {Op: "room", AtMS: 2800},
			{Op: "echo", Counter: 1000 + w - 1000}, {Op: "room", AtMS: 2900}, {Op: "echo", Counter: 1000 + w}, {Op: "room", AtMS: 3000},
		}),
		// No echo for the dead interval: the window goes off and what waits drains.
		zzRunRelay(t, "a_silent_peer_turns_the_window_off", []zzRelayOp{
			{Op: "sent", N: 1000}, {Op: "echo", Counter: 1000}, {Op: "sent", N: w},
			{Op: "room", AtMS: 0}, {Op: "room", AtMS: 20000}, {Op: "room", AtMS: 29000}, {Op: "room", AtMS: 31000},
			{Op: "room", AtMS: 32000}, {Op: "sent", N: 10},
		}),
		// Counts never start over: a window opened after a reset starts at the session's count.
		zzRunRelay(t, "a_reset_keeps_the_count", []zzRelayOp{
			{Op: "sent", N: 3000}, {Op: "echo", Counter: 3000}, {Op: "reset"}, {Op: "room"},
			{Op: "sent", N: 70000}, {Op: "echo", Counter: 3000}, {Op: "echo", Counter: 73000}, {Op: "room"},
		}),
	}
	zzvectors.Write(t, "jitsi/relaywin.json", zzGenerator,
		[]string{"internal/engine/jitsi/relaywindow.go"}, scripts)
}

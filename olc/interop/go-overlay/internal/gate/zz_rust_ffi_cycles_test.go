// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the app API's stop
// and start, plan §11 M9. The FFI's driver (olc-ffi-client, which runs the
// Rust client through OlcrtcRuntime as the iOS extension calls it) makes n
// start / pull / stop cycles in one process against the pinned Go server in
// a hub room, and prints after each stop what the stop left: the shared
// runtime's tasks and threads, the process's threads and the live heap.
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestRustFFICycles$' \
//	    -olcrtc.gate-target=interop -olcrtc.gate-rust-bin=<olc-ffi-client>
//
// It passes when every cycle was ready and pulled the origin's 1 KB, every
// stop left the runtime stopped, no stop left a task the first stops did not
// (none, on this build), the threads never passed the runtime's own (its
// workers, its four blocking threads and main) and ended no higher than they
// began, and the live heap after the last stop is within 1 MiB of the heap
// after the tenth (the pools are warm by then).

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
)

// ffiCycles is how many stop/starts the test makes: the brief's 100.
const ffiCycles = 100

// ffiBlocking is the shared runtime's blocking threads at most
// (ghostlane_runtime::runtime::MAX_BLOCKING).
const ffiBlocking = 4

// ffiCycle is one "ffi cycle=" line.
type ffiCycle struct {
	readyMS, fetched, stopMS, tasks, rtThreads, osThreads, live int
	state                                                       string
}

// parseFFICycle reads "ffi cycle=<i> ready_ms= fetched= stop_ms= tasks=
// rt_threads= os_threads= live= state=".
func parseFFICycle(line string) (int, ffiCycle, error) {
	var c ffiCycle
	i := -1
	ints := map[string]*int{"cycle": &i, "ready_ms": &c.readyMS, "fetched": &c.fetched, "stop_ms": &c.stopMS,
		"tasks": &c.tasks, "rt_threads": &c.rtThreads, "os_threads": &c.osThreads, "live": &c.live}
	for _, f := range strings.Fields(strings.TrimPrefix(line, "ffi ")) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		if k == "state" {
			c.state = v
			continue
		}
		if p, ok := ints[k]; ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return 0, c, fmt.Errorf("%s in %q: %w", k, line, err)
			}
			*p = n
		}
	}
	if i < 0 || c.state == "" {
		return 0, c, fmt.Errorf("not a cycle line: %q", line)
	}
	return i, c, nil
}

// TestRustFFICycles runs the stop/start cycles.
func TestRustFFICycles(t *testing.T) {
	if *gateTargetName != targetInterop {
		t.Skip("the cycles run with -olcrtc.gate-target=interop")
	}
	if filepath.Base(*gateRustBin) != "olc-ffi-client" {
		t.Skip("the cycles run with -olcrtc.gate-rust-bin=<olc-ffi-client>")
	}
	interoppipe.Register()
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	capture := StartCapture()
	t.Cleanup(capture.Stop)
	env := &e2eEnv{t: t, target: &InteropTarget{root: moduleRoot(t), work: t.TempDir(), hub: hub,
		origin: startOrigin(t)}, capture: capture}
	_, ep := env.room(env.key())
	defer env.server(ep, []string{ep.Key}, true)()

	cfg := rustConfig{URL: ep.Room, Key: ep.Key, Transport: ep.Transport, DNS: ep.DNS, Socks: "127.0.0.1:0",
		DeviceID: "gate-ffi"}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
	defer cancel()
	cmd := exec.CommandContext(ctx, *gateRustBin, path)
	cmd.Env = append(os.Environ(), "OLC_FFI_CYCLES="+strconv.Itoa(ffiCycles),
		"OLC_FFI_FETCH="+env.target.origin.URLs.Small)
	// The child dies with the test process, not only when ctx ends.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopBudget
	var out bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &out
	start := time.Now()
	runErr := cmd.Run()
	text := out.String()
	if runErr != nil {
		t.Fatalf("olc-ffi-client: %v after %s:\n%s", runErr, time.Since(start).Round(time.Millisecond),
			tail(text, 40))
	}

	cycles := make([]ffiCycle, 0, ffiCycles)
	workers := -1
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "ffi cycles done "); i >= 0 {
			for _, f := range strings.Fields(line[i:]) {
				if v, ok := strings.CutPrefix(f, "workers="); ok {
					workers, _ = strconv.Atoi(v)
				}
			}
			continue
		}
		i := strings.Index(line, "ffi cycle=")
		if i < 0 {
			continue
		}
		n, c, err := parseFFICycle(line[i:])
		if err != nil {
			t.Fatal(err)
		}
		if n != len(cycles) {
			t.Fatalf("cycle %d after %d cycles:\n%s", n, len(cycles), tail(text, 20))
		}
		cycles = append(cycles, c)
	}
	if len(cycles) != ffiCycles || workers < 1 {
		t.Fatalf("%d cycles, workers=%d; want %d and the runtime's workers:\n%s", len(cycles), workers,
			ffiCycles, tail(text, 20))
	}
	maxOf := func(cs []ffiCycle, f func(ffiCycle) int) int {
		m := 0
		for _, c := range cs {
			m = max(m, f(c))
		}
		return m
	}
	threadCap := 1 + workers + ffiBlocking
	var readySum, stopSum int
	for i, c := range cycles {
		if c.fetched != 1024 || c.state != "stopped" {
			t.Fatalf("cycle %d: fetched %d bytes, state %q; want 1024 and stopped", i, c.fetched, c.state)
		}
		if c.osThreads > threadCap || c.rtThreads > workers+ffiBlocking {
			t.Fatalf("cycle %d: %d threads (%d the runtime's), more than main, %d workers and %d blocking",
				i, c.osThreads, c.rtThreads, workers, ffiBlocking)
		}
		readySum += c.readyMS
		stopSum += c.stopMS
	}
	early, late := cycles[:10], cycles[len(cycles)-50:]
	tasks := func(c ffiCycle) int { return c.tasks }
	if maxOf(late, tasks) > maxOf(early, tasks) {
		t.Fatalf("tasks grew: at most %d after the first ten stops, %d after the last fifty", maxOf(early, tasks),
			maxOf(late, tasks))
	}
	threads := func(c ffiCycle) int { return c.osThreads }
	last := cycles[len(cycles)-1]
	if last.osThreads > maxOf(early, threads) {
		t.Fatalf("threads grew: at most %d after the first ten stops, %d after the last", maxOf(early, threads),
			last.osThreads)
	}
	const heapSlack = 1 << 20
	if grown := last.live - cycles[9].live; grown > heapSlack {
		t.Fatalf("the live heap grew %d bytes from the tenth stop (%d) to the last (%d)", grown, cycles[9].live,
			last.live)
	}
	t.Logf("%d cycles in %s: ready %d ms and stop %d ms on average; after the last stop %d tasks, "+
		"%d threads (%d the runtime's, %d workers), %d live heap bytes (%+d from the tenth)",
		len(cycles), time.Since(start).Round(time.Millisecond), readySum/len(cycles), stopSum/len(cycles),
		last.tasks, last.osThreads, last.rtThreads, workers, last.live, last.live-cycles[9].live)
}

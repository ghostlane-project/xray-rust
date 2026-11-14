// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's S6 and S7
// on the interop target.
//
//   - S6, the late server bridge (olcbox#22): the pinned runS6 against a
//     server whose pipe drops what it is sent until its bridge opens, the
//     jitsi engine's testhooks.BeforeBridgeOpen (jitsi/negotiate.go:60) on
//     the pipe (zz_pipe.go). env.Delayed is what run.go:266-277 gives the
//     local target, opened on the interop target.
//   - S7, the phone's memory (olcbox#24, #26): for the cli flavour the
//     pinned runS7, which weighs the test process (the Go client, and the
//     hub beside it); for the rust flavour the same metrics and the same
//     verdict over the client's own process, sampled from /proc by
//     rustChild.sample: VmRSS for the RSS, RssAnon (the anonymous resident
//     pages: the allocator's heap and the threads' stacks) for the heap, and
//     the threads for the goroutines. The marks are the runner's
//     (env.Sampler). The baseline is zero: the process did not exist before
//     its client started, so all of it counts as what the client adds, a
//     stricter rule than the one the Go flavours are judged by (their
//     baseline is the process before the client, the runtime included). A
//     first sample is no baseline: it lands anywhere from before the loader
//     ran (150 KiB) to after the client's start (4 MiB).

package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNoRustProcess is S7 on the rust flavour with no child behind the tunnel.
var ErrNoRustProcess = errors.New("no rust client process behind the tunnel")

// liveRust is the rust flavour's running children, by their SOCKS address
// (rustClient.Start adds, the tunnel's Stop removes).
var liveRust sync.Map //nolint:gochecknoglobals // the children the gate's tunnels stand for

// rustChildBehind is the child whose SOCKS listener tun is; nil when none.
func rustChildBehind(tun *Tunnel) *rustChild {
	if tun == nil {
		return nil
	}
	c, ok := liveRust.Load(tun.SocksAddr)
	if !ok {
		return nil
	}
	return c.(*rustChild) //nolint:forcetypeassert // only rustClient.Start stores
}

// interopS6 is S6 with env.Delayed opened on the interop target, as
// run.go:266-277 opens it on the local one; withhold keeps the late
// server's room and key out of the report.
func interopS6(s Scenario, withhold func(...string)) Scenario {
	run := s.Run
	s.Run = func(ctx context.Context, env *Env) (Metrics, error) {
		env.Delayed = func(ctx context.Context, opt OpenOptions) (Endpoint, func(), error) {
			sub := filepath.Join(env.Dir, "delay-"+opt.BridgeDelay.String())
			if err := os.MkdirAll(sub, artifactsPerm); err != nil {
				return Endpoint{}, nil, fmt.Errorf("artifacts: %w", err)
			}
			late, stop, err := env.Target.Open(ctx, env.Pair, sub, opt)
			if err != nil {
				return Endpoint{}, nil, fmt.Errorf("late server: %w", err)
			}
			withhold(late.Secrets()...)
			return late, stop, nil
		}
		return run(ctx, env)
	}
	return s
}

// interopS7 is S7 over the rust client's own process; the cli flavour keeps
// the pinned runS7.
func interopS7(s Scenario) Scenario {
	run := s.Run
	s.Run = func(ctx context.Context, env *Env) (Metrics, error) {
		if env.Client.Name() != rustFlavour {
			return run(ctx, env)
		}
		child := rustChildBehind(env.Tunnel)
		if child == nil {
			return nil, ErrNoRustProcess
		}
		return childMemory(env.Sampler, child.series())
	}
	return s
}

// childMemory is runS7 (scenarios.go:308-334) over a child's samples, at the
// runner's marks.
func childMemory(runner *Sampler, samples []Sample) (Metrics, error) {
	runner.mu.Lock()
	from, okFrom := runner.marks[markLoadStart]
	to, okTo := runner.marks[markQuietEnd]
	idleAt, okIdle := runner.marks[markIdle]
	runner.mu.Unlock()
	if !okFrom || !okTo {
		return nil, fmt.Errorf("%w between %s and %s", ErrNoSample, markLoadStart, markQuietEnd)
	}
	if !okIdle {
		return nil, fmt.Errorf("%w at %s", ErrNoSample, markIdle)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("%w: the rust client was never sampled", ErrNoSample)
	}
	var heap, rss uint64
	seen := false
	for _, sm := range samples {
		if sm.At.Before(from) || sm.At.After(to) {
			continue
		}
		seen = true
		heap, rss = max(heap, sm.HeapInuse), max(rss, sm.RSS)
	}
	if !seen {
		return nil, fmt.Errorf("%w between %s and %s", ErrNoSample, markLoadStart, markQuietEnd)
	}
	idle, okI := firstAtOrAfter(samples, idleAt)
	after, okA := firstAtOrAfter(samples, to)
	if !okI {
		return nil, fmt.Errorf("%w at %s", ErrNoSample, markIdle)
	}
	if !okA {
		return nil, fmt.Errorf("%w at %s", ErrNoSample, markQuietEnd)
	}
	return Metrics{
		MetricHeapBaselineBytes: 0, MetricRSSBaselineBytes: 0,
		MetricHeapPeakBytes: float64(heap), MetricRSSPeakBytes: float64(rss),
		MetricGoroutinesIdle: float64(idle.Goroutines), MetricGoroutinesAfter: float64(after.Goroutines),
		MetricHeapProfilesInWindow: 0,
	}, nil
}

// firstAtOrAfter is sampleAt (sampler.go:180-193) over a child's samples:
// the first taken at or after t.
func firstAtOrAfter(samples []Sample, t time.Time) (Sample, bool) {
	for _, sm := range samples {
		if !sm.At.Before(t) {
			return sm, true
		}
	}
	return Sample{}, false
}

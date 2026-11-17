//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port's rejoin supervisor (olc-net's
// reconnect.rs in the xray-rust fork): the supervisor's constants, the
// backoff after each failed attempt, the request counter over a clock the
// generator moves, and the durations its log lines print. An overlay file:
// regen.sh copies it into a clean checkout of the pin. Nothing here sleeps,
// reads the real clock or opens a socket.

package engine

import (
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzReconnectConstants struct {
	WindowMS            int64 `json:"window_ms"`
	BackoffStepMS       int64 `json:"backoff_step_ms"`
	BackoffMaxMS        int64 `json:"backoff_max_ms"`
	NoRouteProbeFirstMS int64 `json:"no_route_probe_initial_ms"`
	NoRouteProbeMaxMS   int64 `json:"no_route_probe_max_ms"`
	NoRouteMaxWaitMS    int64 `json:"no_route_max_wait_ms"`
}

type zzReconnectBackoff struct {
	Count int   `json:"count"`
	MS    int64 `json:"ms"`
}

// zzReconnectCounter is one run of nextRequestCount: before call i the clock
// moves on by GapsMS[i], and the call returns Counts[i].
type zzReconnectCounter struct {
	Name   string  `json:"name"`
	GapsMS []int64 `json:"gaps_ms"`
	Counts []int   `json:"counts"`
}

// zzReconnectDuration is a wait as the supervisor's log lines print it:
// Plain is %s of the duration, Rounded is %s of Round(time.Second).
type zzReconnectDuration struct {
	MS      int64  `json:"ms"`
	Plain   string `json:"plain"`
	Rounded string `json:"rounded"`
}

type zzReconnectCases struct {
	Constants zzReconnectConstants  `json:"constants"`
	Backoff   []zzReconnectBackoff  `json:"backoff"`
	Counter   []zzReconnectCounter  `json:"counter"`
	Durations []zzReconnectDuration `json:"durations"`
}

func zzReconnectCounterCases() []zzReconnectCounter {
	window := reconnectFailureWindow.Milliseconds()
	in := []struct {
		name string
		gaps []int64
	}{
		{"the first request", []int64{0}},
		{"requests one after another", []int64{0, 0, 0, 0}},
		{"requests a second apart", []int64{0, 1000, 1000, 1000, 1000, 1000}},
		{"a gap of exactly the window keeps the count", []int64{0, window, window}},
		{"a gap one millisecond past the window starts again", []int64{0, 1000, window + 1, 1000}},
		{"the window runs from the last request, not the first", []int64{0, window - 1, window - 1, window - 1, window + 1}},
		{"a long quiet stretch, twice", []int64{0, 0, 0, 2 * window, 0, 3 * window, 0}},
		{"a first request long after the supervisor was made", []int64{10 * window, 0}},
	}
	out := make([]zzReconnectCounter, 0, len(in))
	for _, c := range in {
		now := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
		r := NewReconnector(ReconnectorConfig{MaxAttempts: 10})
		r.now = func() time.Time { return now }
		counts := make([]int, 0, len(c.gaps))
		for _, gap := range c.gaps {
			now = now.Add(time.Duration(gap) * time.Millisecond)
			counts = append(counts, r.nextRequestCount())
		}
		out = append(out, zzReconnectCounter{Name: c.name, GapsMS: c.gaps, Counts: counts})
	}
	return out
}

func zzReconnectDurations() []zzReconnectDuration {
	ms := []int64{
		0, 1, 499, 500, 501, 999, 1000, 1499, 1500, 2000, 3000, 4000, 7000, 8000, 15000, 23000,
		59000, 59499, 59500, 60000, 61000, 119500, 299000, 300000, 303000, 599000, 600000,
		3599000, 3599500, 3600000, 3661000, 36000000, 90061000,
	}
	out := make([]zzReconnectDuration, 0, len(ms))
	for _, m := range ms {
		d := time.Duration(m) * time.Millisecond
		out = append(out, zzReconnectDuration{MS: m, Plain: d.String(), Rounded: d.Round(time.Second).String()})
	}
	return out
}

// TestZZVectors writes reconnect/backoff.json (regen.sh runs the test of
// this name in every package it lists).
func TestZZVectors(t *testing.T) {
	cases := zzReconnectCases{
		Constants: zzReconnectConstants{
			WindowMS:            reconnectFailureWindow.Milliseconds(),
			BackoffStepMS:       reconnectBackoffStep.Milliseconds(),
			BackoffMaxMS:        reconnectBackoffMax.Milliseconds(),
			NoRouteProbeFirstMS: noRouteProbeInitial.Milliseconds(),
			NoRouteProbeMaxMS:   noRouteProbeMax.Milliseconds(),
			NoRouteMaxWaitMS:    noRouteMaxWait.Milliseconds(),
		},
		Counter:   zzReconnectCounterCases(),
		Durations: zzReconnectDurations(),
	}
	for count := 0; count <= 40; count++ {
		cases.Backoff = append(cases.Backoff, zzReconnectBackoff{Count: count, MS: reconnectBackoff(count).Milliseconds()})
	}
	zzvectors.Write(t, "reconnect/backoff.json", "internal/engine/zz_reconnect_vectors_test.go",
		[]string{
			"internal/engine/reconnect.go:12-24 (the constants)",
			"internal/engine/reconnect.go:382-388 (reconnectBackoff)",
			"internal/engine/reconnect.go:270-280 (nextRequestCount)",
			"internal/engine/reconnect.go:254-267 (the durations awaitRoute logs)",
		}, cases)
}

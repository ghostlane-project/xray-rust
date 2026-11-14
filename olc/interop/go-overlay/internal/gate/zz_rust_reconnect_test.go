// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): how long a reopen
// after a link change takes, the Rust client against the Go client on the
// same server and hub, with what happened in the slow rounds.

package gate

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/mobile"
)

// stampLog keeps every line with the moment it arrived: the engine log of
// this process (the Go client, and the Rust child's stderr, which startRust
// copies into it), handed on to the capture, plus the lines added to it (the
// hub's trace, the server's log file).
type stampLog struct {
	next *Capture
	t0   time.Time
	mu   sync.Mutex
	ev   []stampEvent
}

type stampEvent struct {
	at   time.Duration
	src  string
	text string
}

func newStampLog(next *Capture) *stampLog { return &stampLog{next: next, t0: time.Now()} }

// WriteLog implements mobile.LogWriter.
func (s *stampLog) WriteLog(msg string) {
	s.add("client", strings.TrimRight(msg, "\n"))
	s.next.WriteLog(msg)
}

func (s *stampLog) add(src, text string) {
	at := time.Since(s.t0)
	s.mu.Lock()
	s.ev = append(s.ev, stampEvent{at: at, src: src, text: text})
	s.mu.Unlock()
}

func (s *stampLog) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ev)
}

var logStamp = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(\.\d+)? `)

// since renders the events from mark on, in milliseconds from base, at most
// max of them.
func (s *stampLog) since(mark int, base time.Time, maxLines int) string {
	s.mu.Lock()
	ev := slices.Clone(s.ev[mark:])
	s.mu.Unlock()
	slices.SortStableFunc(ev, func(a, b stampEvent) int { return int(a.at - b.at) })
	var b strings.Builder
	off := base.Sub(s.t0)
	for i, e := range ev {
		if i == maxLines {
			fmt.Fprintf(&b, "  ... %d more\n", len(ev)-maxLines)
			break
		}
		fmt.Fprintf(&b, "  %+7.1fms %-6s %s\n", float64(e.at-off)/float64(time.Millisecond), e.src,
			logStamp.ReplaceAllString(e.text, ""))
	}
	return b.String()
}

// follow adds each line the file at path gets to s, as src, until ctx ends.
func (s *stampLog) follow(ctx context.Context, path, src string) {
	f, err := os.Open(path)
	if err != nil {
		s.add(src, "follow: "+err.Error())
		return
	}
	go func() {
		defer func() { _ = f.Close() }()
		buf := make([]byte, 64<<10)
		var part string
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			for {
				n, err := f.Read(buf)
				if n > 0 {
					part += string(buf[:n])
					for {
						i := strings.IndexByte(part, '\n')
						if i < 0 {
							break
						}
						s.add(src, part[:i])
						part = part[i+1:]
					}
				}
				if err == io.EOF || n == 0 {
					break
				}
				if err != nil {
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

// reopenRounds is one client flavour ("rust" or "cli") in a fresh room with
// its own server: the hub cuts the room rounds times, and each round is timed
// from the cut to the client's " reopened (device=" line. A round slower than
// slow is logged with everything around it.
func (e *e2eEnv) reopenRounds(flavour string, rounds int, slow time.Duration) []time.Duration {
	t := e.t
	t.Helper()
	hub := e.target.hub
	name, ep := e.room(e.key())
	srv, cli := ep, ep
	srv.Room, cli.Room = hub.URL(name+"@srv"), hub.URL(name+"@"+flavour)
	stamps := newStampLog(e.capture)
	hub.Trace(name, func(ev string) { stamps.add("hub", ev) })
	defer hub.Trace(name, nil)
	defer e.server(srv, []string{ep.Key}, true)()
	ctx, cancel := context.WithTimeout(context.Background(), childLifetime)
	defer cancel()
	stamps.follow(ctx, e.serverLog, "server")
	mobile.SetLogWriter(stamps)
	defer mobile.SetLogWriter(e.capture)
	log := e.capture.Begin()
	var socks string
	switch flavour {
	case "rust":
		var child *rustChild
		socks, child = e.client(cli, nil)
		defer child.halt(stopBudget, t.Logf)
	case "cli":
		tun, err := goInteropClient{cli: cliClient{start: startBudget, stop: stopBudget}}.Start(ctx, cli)
		if err != nil {
			t.Fatal(err)
		}
		defer tun.Stop()
		socks = tun.SocksAddr
	default:
		t.Fatalf("no flavour %q", flavour)
	}
	e.pullSoon(socks, 10*time.Second)
	took := make([]time.Duration, 0, rounds)
	for round := 1; round <= rounds; round++ {
		mark := stamps.mark()
		cut := time.Now()
		hub.Cut(name)
		deadline := cut.Add(30 * time.Second)
		for log.Count(" reopened (device=") < round {
			if time.Now().After(deadline) {
				t.Fatalf("%s round %d: no reopen within 30s:\n%s", flavour, round, stamps.since(mark, cut, 120))
			}
			time.Sleep(time.Millisecond)
		}
		d := time.Since(cut)
		took = append(took, d)
		if d > slow {
			t.Logf("%s round %d: reopened %s after the cut:\n%s", flavour, round, d.Round(time.Millisecond),
				stamps.since(mark, cut, 80))
		}
		e.pullSoon(socks, 20*time.Second)
	}
	return took
}

func sumDurations(ds []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	return total
}

func describeRounds(ds []time.Duration) string {
	sorted := slices.Clone(ds)
	slices.Sort(sorted)
	slowRounds := 0
	for _, d := range ds {
		if d >= time.Second {
			slowRounds++
		}
	}
	return fmt.Sprintf("%d rounds, total %s, median %s, max %s, %d of them 1s or more",
		len(ds), sumDurations(ds).Round(time.Millisecond), sorted[len(sorted)/2].Round(time.Millisecond),
		sorted[len(sorted)-1].Round(time.Millisecond), slowRounds)
}

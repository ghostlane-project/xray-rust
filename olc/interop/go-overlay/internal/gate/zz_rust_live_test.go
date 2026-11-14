// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T3's SaluteJazz rust
// step, run from the build box. The local target's SaluteJazz pair is a
// fresh anonymous room (the provider's own create call, no account) with the
// pinned server in it; this build's Go client runs S0-S5 there first, then
// the Rust client (olc-client with the shaped-tls feature, provider
// salutejazz) runs them in the same room, so each Rust cell is read against
// the Go cell of the same room minutes earlier:
//
//	go test -tags olcrtc_interop[,olcrtc_lean] ./internal/gate -run '^TestGateRustLive$' -olcrtc.gate \
//	    -olcrtc.gate-target=local -olcrtc.gate-providers=salutejazz -olcrtc.gate-transports=datachannel \
//	    -olcrtc.gate-rust-live -olcrtc.gate-rust-bin=<olc-client>
//
// One run joins the service three times (the server, the Go client, the
// Rust client), besides the one create call and a rejoin for any reconnect
// a cell reports; with -olcrtc.gate-rust-only the Go client stays out, so a
// run is the create call and two joins (the server, the Rust client). Go's known S2/S3 failures on this pair (known.go) apply to
// the rust cells as they do to Go's. olc/interop/live.sh runs it with the
// phones' build tags (the Go client is then the mobile flavour).

package gate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

var gateRustLive = flag.Bool("olcrtc.gate-rust-live", false,
	"run TestGateRustLive: the Rust client in a real SaluteJazz room (joins the live service)")

var gateRustOnly = flag.Bool("olcrtc.gate-rust-only", false,
	"TestGateRustLive without the Go client: one join fewer (the server and the Rust client)")

// TestGateRustLive is the rust step on the local target's SaluteJazz pair.
func TestGateRustLive(t *testing.T) {
	if !*gateOn || !*gateRustLive || *gateTargetName != targetLocal {
		t.Skip("the live rust step runs with -olcrtc.gate -olcrtc.gate-rust-live -olcrtc.gate-target=local")
	}
	if *gateProviders != providerSaluteJazz || *gateTransports != transportData {
		t.Fatalf("the live rust step runs SaluteJazz over datachannel alone: -olcrtc.gate-providers=%s "+
			"-olcrtc.gate-transports=%s", providerSaluteJazz, transportData)
	}
	root := moduleRoot(t)
	local, thresholds, secrets := gateTarget(t, root, "", false)
	// The live budget: one room, and the Rust client joins once. The gate
	// tries a server that did not come up and a client the provider refused
	// once more; here neither is tried again.
	target := &onceTarget{Target: local}

	registryMu.Lock()
	saved := registry
	registry = rtcScenarios(saved)
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})

	rust := &onceClient{Client: rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
		extra: func(cfg *rustConfig) {
			cfg.Provider = providerSaluteJazz
			cfg.MaxJoins = 1
		}}}
	clients := []Client{rust}
	if !*gateRustOnly {
		goFlavour := ownFlavour(leanBuild)
		if goFlavour == mobileFlavour {
			phoneSettings(t)
		}
		clients = []Client{flavourClient(goFlavour), rust}
	}
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, "live-"+providerSaluteJazz)
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(Report{Target: target.Name(), Runner: runnerName()})
	capture := StartCapture()
	defer capture.Stop()
	opt := Options{
		Target: target, Clients: clients, Thresholds: thresholds, Dir: dir, Recorder: rec, Capture: capture,
		Secrets: &secrets, Logf: t.Logf, ReportPath: filepath.Join(dir, reportName),
	}
	RunPlan(runContext(t), opt, func(name string, cell func() error) {
		t.Run(name, func(t *testing.T) {
			switch err := cell(); {
			case errors.Is(err, ErrKnownFailure):
				t.Log(err)
			case err != nil:
				t.Error(err)
			}
		})
	})
	rep := rec.Report()
	for _, c := range rep.Cells {
		raw, _ := json.Marshal(c.Metrics)
		t.Logf("cell %s: %s %s %q", c.ID, c.Status, raw, c.Failures)
	}
	for _, id := range unreported(rep) {
		t.Errorf("%s: %s", id, reasonDidNotRun)
	}
	for _, line := range knownLines(rep) {
		t.Log(line)
	}
	if why := gateFailure(rep); why != "" {
		t.Errorf("gate: %s; the report goes to %s", why, opt.ReportPath)
	}
}

// errLiveBudget refuses a second room or a second Rust start in a live run.
var errLiveBudget = errors.New("the live step's budget is one room and one Rust start: not tried again")

// onceTarget opens one server, ever: the gate's second try of a server that
// did not come up would be a second room.
type onceTarget struct {
	Target
	opened atomic.Bool
}

func (t *onceTarget) Open(ctx context.Context, p Pair, dir string, opt OpenOptions) (Endpoint, func(), error) {
	if t.opened.Swap(true) {
		return Endpoint{}, nil, errLiveBudget
	}
	return t.Target.Open(ctx, p, dir, opt)
}

// onceClient starts its client once: the gate's second try of a client the
// provider refused would be another join.
type onceClient struct {
	Client
	started atomic.Bool
}

func (c *onceClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	if c.started.Swap(true) {
		return nil, errLiveBudget
	}
	return c.Client.Start(ctx, ep)
}

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
// a cell reports. Go's known S2/S3 failures on this pair (known.go) apply to
// the rust cells as they do to Go's. olc/interop/live.sh runs it with the
// phones' build tags (the Go client is then the mobile flavour).

package gate

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var gateRustLive = flag.Bool("olcrtc.gate-rust-live", false,
	"run TestGateRustLive: the Rust client in a real SaluteJazz room (joins the live service)")

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
	target, thresholds, secrets := gateTarget(t, root, "", false)

	registryMu.Lock()
	saved := registry
	registry = interopScenarios(saved)
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})

	goFlavour := ownFlavour(leanBuild)
	if goFlavour == mobileFlavour {
		phoneSettings(t)
	}
	clients := []Client{
		flavourClient(goFlavour),
		rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
			extra: func(cfg *rustConfig) { cfg.Provider = providerSaluteJazz }},
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

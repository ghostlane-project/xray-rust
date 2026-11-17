//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the Rust client's
// rejoin in the engine's fake SFU (TestReconnectJoinsAgainWithFreshCredentials
// as far as a client on direct credentials goes: there is no provider to ask
// again, so the second join carries the credentials of the first, K11).
//
//	OLCRTC_GATE_RUST_BIN=<olc-client> go test -tags olcrtc_interop ./internal/engine/mtslink -run '^TestRustMTSRejoin' -v
//
//   - TestRustMTSRejoinsAfterTheSFUDropsItsPeer: the SFU closes the guest's
//     peer connection after it was up. The client says its peer connection
//     closed, joins again from scratch (a new offer, the same room join),
//     pins again, connects and publishes again, and takes no conference
//     back: a rejoin that works is no failed join;
//   - TestRustMTSARejoinTheSFURefusesTakesItsConferenceBack: the second join
//     is refused. That join's conference is taken back, with the guest's
//     cookies, and the client tries again after the supervisor's backoff.
//
// The fresh-credentials half (a provider asked again before the second
// join) is the Rust session's own test against its fakes: the Go provider's
// join is always https and the fakes are plain HTTP (M6 spec, section 12).

package mtslink

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	rustPCConnected = "peer connection state changed: connected"
	rustPCClosed    = "peer connection state changed: closed"
)

// rustCloseLastPeer closes the SFU's side of the last join.
func rustCloseLastPeer(sfu *fakeSFU) {
	sfu.mu.Lock()
	pc := sfu.pcs[len(sfu.pcs)-1]
	sfu.mu.Unlock()
	_ = pc.Close()
}

func rustJoins(sfu *fakeSFU) int {
	sfu.mu.Lock()
	defer sfu.mu.Unlock()
	return sfu.joins
}

func TestRustMTSRejoinsAfterTheSFUDropsItsPeer(t *testing.T) {
	rustBin(t)
	sfu := newFakeSFU(t)
	seen := rustWatchPublished(t, sfu)
	p := startRust(t, rustSFUConfig(sfu))
	rustJoined(t, sfu)
	within(t, 10*time.Second, "the first join connected", func() bool { return p.logHas(rustPCConnected) })
	sfu.mu.Lock()
	first, firstOffer := sfu.joinQuery, sfu.offer
	sfu.mu.Unlock()

	rustCloseLastPeer(sfu)
	within(t, 12*time.Second, "the second join", func() bool { return rustJoins(sfu) >= 2 })
	// The second join is from scratch: the published track arrives again
	// and its packets flow.
	select {
	case <-sfu.publisher:
	case <-time.After(15 * time.Second):
		t.Fatal("the relay never saw the track published again")
	}
	before, _, _ := seen.counts()
	within(t, 10*time.Second, "packets published after the rejoin", func() bool {
		packets, _, _ := seen.counts()
		return packets > before
	})
	within(t, 10*time.Second, "the second pin", func() bool {
		sfu.mu.Lock()
		defer sfu.mu.Unlock()
		return len(sfu.pins) >= 2
	})

	sfu.mu.Lock()
	joins, second, secondOffer := sfu.joins, sfu.joinQuery, sfu.offer
	pins, leaves := len(sfu.pins), append([]string(nil), sfu.leaves...)
	sfu.mu.Unlock()
	if joins != 2 {
		t.Errorf("%d joins, want the first and one rejoin", joins)
	}
	// Direct credentials: the room join of the first, value for value; only
	// the line the new offer plays the room's audio on is the new offer's.
	for _, key := range []string{"userId", "joinToken", "publishToken", "did", "pid", "userName", "disableRecording"} {
		if second.Get(key) != first.Get(key) || second.Get(key) == "" {
			t.Errorf("the rejoin's %s is not the first join's", key)
		}
	}
	if mids := rustMids(secondOffer); len(mids) != 3+receiveSlots || second.Get("originMid") != mids[2] {
		t.Errorf("the rejoin's originMid is not its own offer's audio player line")
	}
	if secondOffer == firstOffer {
		t.Error("the rejoin posted the first join's offer: it is no join from scratch")
	}
	if pins != 2 {
		t.Errorf("%d pins, want one per join", pins)
	}
	if len(leaves) != 0 {
		t.Errorf("a rejoin that worked took a conference back: %q", leaves)
	}

	// pion's lines, which the apps read: connected, closed, connected.
	within(t, 10*time.Second, "the second connected line", func() bool {
		return strings.Count(p.log(), rustPCConnected) >= 2
	})
	log := p.log()
	closed := strings.Index(log, rustPCClosed)
	if closed < 0 || closed < strings.Index(log, rustPCConnected) || closed > strings.LastIndex(log, rustPCConnected) {
		t.Error("the client's log has no closed peer connection between its two connected ones")
	}
	p.stop(t)
	if n := rustJoins(sfu); n != 2 {
		t.Errorf("%d joins after the stop, want two", n)
	}
}

func TestRustMTSARejoinTheSFURefusesTakesItsConferenceBack(t *testing.T) {
	rustBin(t)
	sfu := newFakeSFU(t)
	p := startRust(t, rustSFUConfig(sfu))
	rustJoined(t, sfu)
	within(t, 10*time.Second, "the first join connected", func() bool { return p.logHas(rustPCConnected) })

	sfu.mu.Lock()
	sfu.refuseStatus, sfu.refuseBody = http.StatusServiceUnavailable, "busy"
	sfu.mu.Unlock()
	rustCloseLastPeer(sfu)
	within(t, 12*time.Second, "the refused rejoin's conference taken back", func() bool {
		sfu.mu.Lock()
		defer sfu.mu.Unlock()
		return len(sfu.leaves) >= 1
	})
	within(t, 5*time.Second, "the failed rejoin in the client's log", func() bool {
		return p.logHas("mtslink: reconnect failed: mtslink: the SFU refused the join: status 503: busy")
	})
	sfu.mu.Lock()
	joins, leaves, pins := sfu.joins, append([]string(nil), sfu.leaves...), len(sfu.pins)
	sfu.mu.Unlock()
	// The last refused join may not have been taken back yet.
	if joins < 2 || len(leaves) > joins-1 || len(leaves) < joins-2 {
		t.Errorf("%d joins and %d conferences taken back, want one taken back per refused rejoin", joins, len(leaves))
	}
	for _, leave := range leaves {
		if leave != "DELETE /api/conferences/"+testConf+" | "+testCookies {
			t.Errorf("leave = %q, want the conference taken back with the guest's cookies", leave)
		}
	}
	if pins != 1 {
		t.Errorf("%d pins, want the first join's alone: a refused join is not pinned", pins)
	}
}

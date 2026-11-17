// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): what the Rust client's
// config (rustConfig, zz_rust_flavour_test.go) carries for the MTS Link and
// VK Calls carriers, and the names their gate targets go by. The targets
// themselves (TestGateRustMTSFake, TestGateRustVKFake) come with the carriers;
// mtslink.sh and vkcalls.sh run them under these names.

package gate

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

const (
	// targetMTSFake is the gate target of the forwarding fake MTS Link room
	// (mtslink.sh gate).
	targetMTSFake = "mtsfake"
	// targetVKFake is the gate target of the fake VK Calls SFU (vkcalls.sh
	// gate).
	targetVKFake = "vkfake"
)

// carrierKeys are the config keys only a carrier's fake sets, as olc-client's
// config.rs names them. The Rust client refuses a key it does not know, so
// none may reach a client that was not asked for it.
var carrierKeys = []string{"provider_base", "engine_extra"}

// carrierConfigFixture is a config with every carrier field set, as JSON. The
// Rust client's own test (olc-client config.rs,
// the_gates_carrier_config_reads) parses the same file: a key renamed on one
// side fails the other's test.
const carrierConfigFixture = "zz_rust_carrier_config.json"

func rustConfigKeys(t *testing.T, cfg rustConfig) map[string]any {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// TestRustConfigCarriesTheCarriersTestFields: every carrier field reaches the
// client's JSON under the key olc-client's config.rs reads: the provider's
// test base as provider_base, the direct credentials as engine_extra under
// the names Go's Extra has them by (ice_servers stays the JSON text
// Extra["ice_servers"] holds). What is written is the fixture the Rust
// client's test reads.
func TestRustConfigCarriesTheCarriersTestFields(t *testing.T) {
	const servers = `[{"urls":["stun:127.0.0.1:3478"]},{"credential":"p","urls":["turn:127.0.0.1:3478"],"username":"u"}]`
	got := rustConfigKeys(t, rustConfig{
		URL: "http://127.0.0.1:3/rtc/room/1", Key: "k", Transport: "vp8channel", DNS: "127.0.0.1:53",
		Socks: "127.0.0.1:0", DeviceID: "d", Engine: "mtslink", Token: "c=1",
		ProviderBase: "http://127.0.0.1:1",
		EngineExtra: map[string]string{
			"gateway": "http://127.0.0.1:2", "conferenceId": "20300400600", "ice": "both", "ice_servers": servers,
		},
	})
	for _, k := range carrierKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("%s is not written", k)
		}
	}
	raw, err := os.ReadFile(carrierConfigFixture)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the config written is\n%v\nthe fixture %s holds\n%v", got, carrierConfigFixture, want)
	}
}

// TestRustConfigNamesNoCarrierFieldUnasked: a config no carrier fake touched
// (every target before the carriers) holds none of the carrier keys.
func TestRustConfigNamesNoCarrierFieldUnasked(t *testing.T) {
	got := rustConfigKeys(t, rustConfig{URL: "u", Key: "k", Transport: transportData, Socks: "127.0.0.1:0"})
	for _, k := range carrierKeys {
		if _, ok := got[k]; ok {
			t.Errorf("an unset %s is written: %v", k, got[k])
		}
	}
	if targetMTSFake == targetVKFake || targetMTSFake == targetFakeRoom || targetVKFake == targetFakeRoom {
		t.Errorf("gate target names clash: %s, %s, %s", targetMTSFake, targetVKFake, targetFakeRoom)
	}
}

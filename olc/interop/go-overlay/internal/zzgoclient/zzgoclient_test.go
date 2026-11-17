// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

package zzgoclient

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	runtimecfg "github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

func sample() Config {
	return Config{
		Profile: ProfilePhone, Transport: "vp8channel", Engine: "mtslink", URL: "http://127.0.0.1:3/rtc/room/1",
		Token: `a=1; b="2"`, Channel: "chan-1", Key: strings.Repeat("ab", 32), DNS: "127.0.0.1:53",
		DeviceID: "gate-cli", VP8FPS: 60, VP8Batch: 64,
	}
}

// TestClientIsTheInProcessBaselinesConfig: the child is run on what the
// gate's in-process baseline passes the public client (goMTSClient.Start in
// zz_rust_mtsfake_test.go; the p2p and vkfake ones are the same without a
// token), so the two differ in the process and the profile and nothing
// else.
func TestClientIsTheInProcessBaselinesConfig(t *testing.T) {
	c := sample()
	want := client.Config{
		Transport: "vp8channel", Provider: "none", Engine: "mtslink", URL: c.URL, Token: c.Token,
		ChannelID: "chan-1", KeyHex: c.Key, LocalAddr: "127.0.0.1:0", DNSServer: "127.0.0.1:53", DeviceID: "gate-cli",
		TransportOptions: client.VP8Options{FPS: 60, BatchSize: 64},
	}
	if got := c.Client(); !reflect.DeepEqual(got, want) {
		t.Errorf("the client's config is\n%+v\nwant\n%+v", got, want)
	}
	if got := c.Client(); got.UDPDisabled {
		t.Error("the UDP relay is off: S5 has nothing to ask")
	}
}

// TestParseReadsWhatTheGateWrites: a config written as JSON comes back the
// same; a key Parse does not know, a profile that is neither of the two and
// a config with none are refused.
func TestParseReadsWhatTheGateWrites(t *testing.T) {
	for _, profile := range []string{ProfilePhone, ProfileServer} {
		c := sample()
		c.Profile = profile
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(raw)
		if err != nil || got != c {
			t.Errorf("Parse(%s) = %+v, %v", profile, got, err)
		}
	}
	for _, bad := range []string{
		`{"profile":"phone","socks":"127.0.0.1:1080"}`,
		`{"profile":"mobile"}`,
		`{"profile":""}`,
		`{"transport":"vp8channel"}`,
		`{"profile":"phone"`,
	} {
		if got, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%s) = %+v, want an error", bad, got)
		}
	}
}

// TestPhoneIsTheConstrainedProfile: phone is the engine's constrained profile,
// which every window and queue of the client reads; server leaves the
// process as it started.
func TestPhoneIsTheConstrainedProfile(t *testing.T) {
	t.Cleanup(runtimecfg.ResetBufferProfileForTest)
	runtimecfg.ResetBufferProfileForTest()
	useProfile(ProfileServer)
	if runtimecfg.BuffersAreConstrained() {
		t.Error("the server profile constrained the buffers")
	}
	useProfile(ProfilePhone)
	if !runtimecfg.BuffersAreConstrained() {
		t.Error("the phone profile left the buffers a server's")
	}
}

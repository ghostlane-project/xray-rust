// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Package zzgoclient is an overlay package (olc/interop in the xray-rust
// fork): the Go public client run from a config file, in a process of its
// own, in either of the engine's two buffer profiles. The gate's Go baseline
// on the vp8channel targets (internal/gate/zz_go_child_test.go) is this,
// built as cmd/zz-olcrtc-goclient.
//
// The engine's own ways of running a client do not give that baseline. Its
// gate's cli flavour runs the public client inside the test process, in the
// server profile; its CLI (cmd/olcrtc, mode cnc) is a process of its own but
// has no switch for the profile; and the phone profile, the one the Rust
// client is a port of (olc-client's vp8link.rs: constrained), is set only
// by the mobile runtime (mobile/runtime.go: client.UseConstrainedBuffers).
// What runs here is what all three run: client.New(cfg).RunWithAddress.
package zzgoclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

const (
	// ProfilePhone is the constrained buffer profile, a phone's
	// (hostprofile.UseConstrainedBuffers): KCP windows of 512 segments, smux
	// 4 MiB and 512 KiB, the short queues. The Rust client has no other.
	ProfilePhone = "phone"
	// ProfileServer is the profile a process has when nothing chose one:
	// the engine's CLI and its gate's cli flavour.
	ProfileServer = "server"
)

// Config is what the client is run on: the gate's endpoint on direct
// credentials (provider none), as JSON.
type Config struct {
	// Profile is ProfilePhone or ProfileServer; nothing else is accepted.
	Profile   string `json:"profile"`
	Transport string `json:"transport"`
	Engine    string `json:"engine"`
	URL       string `json:"url"`
	Token     string `json:"token,omitempty"`
	Channel   string `json:"channel"`
	Key       string `json:"key"`
	DNS       string `json:"dns"`
	DeviceID  string `json:"device_id"`
	VP8FPS    int    `json:"vp8_fps"`
	VP8Batch  int    `json:"vp8_batch"`

	// Provider and RoomURL join through an auth provider instead of direct
	// credentials (Jitsi: its rooms are a provider's link, the engine takes
	// no direct credentials for them); empty is provider none.
	Provider string `json:"provider,omitempty"`
	RoomURL  string `json:"room_url,omitempty"`
}

// Parse reads a Config. A key it does not know is an error, so the gate and
// the command cannot drift apart in silence, and so is a profile that is
// neither of the two.
func Parse(raw []byte) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if cfg.Profile != ProfilePhone && cfg.Profile != ProfileServer {
		return Config{}, fmt.Errorf("config: profile %q: %s or %s", cfg.Profile, ProfilePhone, ProfileServer)
	}
	return cfg, nil
}

// Client is the public client's config: what the gate's in-process baseline
// passes (goP2PClient, goMTSClient, goVKFakeClient), field for field: an
// ephemeral SOCKS port on loopback, the UDP relay on (the library's default).
func (c Config) Client() client.Config {
	provider := "none"
	if c.Provider != "" {
		provider = c.Provider
	}
	return client.Config{
		Transport: c.Transport, Provider: provider, RoomURL: c.RoomURL, Engine: c.Engine, URL: c.URL, Token: c.Token,
		ChannelID: c.Channel, KeyHex: c.Key, LocalAddr: "127.0.0.1:0", DNSServer: c.DNS, DeviceID: c.DeviceID,
		TransportOptions: client.VP8Options{FPS: c.VP8FPS, BatchSize: c.VP8Batch},
	}
}

// Run sets the process's buffer profile and runs the public client until ctx
// ends. The profile is the process's for good (the engine's switch is
// one-way), so a process runs one client.
func Run(ctx context.Context, cfg Config) error {
	useProfile(cfg.Profile)
	if err := client.New(cfg.Client()).RunWithAddress(ctx, nil); err != nil {
		return fmt.Errorf("run public client: %w", err)
	}
	return nil
}

// useProfile makes profile the process's.
func useProfile(profile string) {
	if profile == ProfilePhone {
		client.UseConstrainedBuffers()
	}
}

//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package runtime

import (
	"errors"
	"strings"
	"testing"

	"github.com/xtaci/smux"

	"github.com/openlibrecommunity/olcrtc/internal/control"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzConstants struct {
	SmuxFrameOverhead       int   `json:"smux_frame_overhead"`
	SmuxWireOverhead        int   `json:"smux_wire_overhead"`
	MinSmuxWirePayload      int   `json:"min_smux_wire_payload"`
	ConnectAckTimeoutMs     int64 `json:"connect_ack_timeout_ms"`
	ConnectRequestTimeoutMs int64 `json:"connect_request_timeout_ms"`
	LivenessTimeoutMs       int64 `json:"liveness_timeout_ms"`
}

type zzSmux struct {
	Version             int   `json:"version"`
	KeepAliveDisabled   bool  `json:"keepalive_disabled"`
	KeepAliveIntervalMs int64 `json:"keepalive_interval_ms"`
	KeepAliveTimeoutMs  int64 `json:"keepalive_timeout_ms"`
	MaxFrameSize        int   `json:"max_frame_size"`
	MaxReceiveBuffer    int   `json:"max_receive_buffer"`
	MaxStreamBuffer     int   `json:"max_stream_buffer"`
}

type zzSmuxCase struct {
	MaxWirePayload int    `json:"max_wire_payload"`
	Profile        string `json:"profile"`
	Data           zzSmux `json:"data"`
	Long           zzSmux `json:"long"`
	Control        zzSmux `json:"control"`
}

type zzKeyCase struct {
	Name      string `json:"name"`
	KeyHex    string `json:"key_hex"`
	Role      string `json:"role"`
	Verdict   string `json:"verdict"`
	ErrorText string `json:"error_text,omitempty"`
}

type zzFile struct {
	Constants zzConstants  `json:"constants"`
	Smux      []zzSmuxCase `json:"smux"`
	Keys      []zzKeyCase  `json:"setup_key_set"`
}

func zzOf(cfg *smux.Config) zzSmux {
	return zzSmux{Version: cfg.Version, KeepAliveDisabled: cfg.KeepAliveDisabled,
		KeepAliveIntervalMs: cfg.KeepAliveInterval.Milliseconds(), KeepAliveTimeoutMs: cfg.KeepAliveTimeout.Milliseconds(),
		MaxFrameSize: cfg.MaxFrameSize, MaxReceiveBuffer: cfg.MaxReceiveBuffer, MaxStreamBuffer: cfg.MaxStreamBuffer}
}

func zzKeyVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrKeyRequired):
		return "required"
	case errors.Is(err, ErrKeySize):
		return "size"
	case strings.HasPrefix(err.Error(), "failed to decode key: "):
		return "decode"
	default:
		return "other: " + err.Error()
	}
}

func TestZZVectors(t *testing.T) {
	defer ResetBufferProfileForTest()
	file := zzFile{Constants: zzConstants{
		SmuxFrameOverhead: SmuxFrameOverhead, SmuxWireOverhead: SmuxWireOverhead, MinSmuxWirePayload: MinSmuxWirePayload,
		ConnectAckTimeoutMs: ConnectAckTimeout().Milliseconds(), ConnectRequestTimeoutMs: ConnectRequestTimeout().Milliseconds(),
		LivenessTimeoutMs: control.DefaultTimeout.Milliseconds(),
	}}
	payloads := []int{-1, 0, 1, 52, 53, 54, 100, 1200, 12 * 1024, 32820, 32821, 60 * 1024, 65535, 1 << 20}
	for _, profile := range []string{"server", "constrained"} {
		ResetBufferProfileForTest()
		if profile == "constrained" {
			UseConstrainedBuffers()
		}
		for _, p := range payloads {
			file.Smux = append(file.Smux, zzSmuxCase{MaxWirePayload: p, Profile: profile,
				Data: zzOf(SmuxConfig(p)), Long: zzOf(SmuxConfigLong(p)), Control: zzOf(ControlSmuxConfig(p))})
		}
	}
	ResetBufferProfileForTest()

	good := strings.Repeat("0123456789abcdef", 4)
	keys := []struct {
		name string
		hex  string
		role crypto.Role
	}{
		{"client", good, crypto.Client},
		{"server", good, crypto.Server},
		{"upper case hex", strings.ToUpper(good), crypto.Client},
		{"empty", "", crypto.Client},
		{"odd length", good[:63], crypto.Client},
		{"not hex", "zz" + good[2:], crypto.Client},
		{"31 bytes", good[:62], crypto.Client},
		{"33 bytes", good + "00", crypto.Client},
		{"spaces", " " + good[1:], crypto.Client},
		{"role zero", good, crypto.Role(0)},
		{"role three", good, crypto.Role(3)},
	}
	for _, k := range keys {
		_, err := SetupKeySet(k.hex, k.role)
		kc := zzKeyCase{Name: k.name, KeyHex: k.hex, Role: k.role.String(), Verdict: zzKeyVerdict(err)}
		if err != nil {
			kc.ErrorText = err.Error()
		}
		file.Keys = append(file.Keys, kc)
	}
	zzvectors.Write(t, "runtime.json", "internal/runtime/zz_vectors_test.go TestZZVectors",
		[]string{"internal/runtime/runtime.go:22-233"}, file)
}

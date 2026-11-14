//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package vp8channel

import (
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

func TestZZVectors(t *testing.T) {
	zzvectors.Write(t, "transport/vp8channel.json", "internal/transport/vp8channel/zz_vectors_test.go TestZZVectors",
		[]string{"internal/transport/vp8channel/transport.go:56-57"}, map[string]any{
			"max_payload_size": defaultMaxPayloadSize,
		})
}

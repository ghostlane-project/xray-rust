//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package tunnelcore

import (
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

func TestZZVectors(t *testing.T) {
	zzvectors.Write(t, "tunnelcore.json", "internal/tunnelcore/zz_vectors_test.go TestZZVectors",
		[]string{"internal/tunnelcore/core.go:17-26"}, map[string]any{
			"connect_ack_ok":               int(ConnectAckOK),
			"connect_ack_host_unreachable": int(ConnectAckHostUnreachable),
			"udp_record_aad":               UDPRecordAAD,
		})
}

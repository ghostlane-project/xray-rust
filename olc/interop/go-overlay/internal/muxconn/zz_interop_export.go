//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Exported for the decode oracle (cmd/zz-olcrtc-oracle) of the Rust port. An
// overlay file: build-oracle.sh copies it into a clean checkout of the pin.

package muxconn

import "github.com/openlibrecommunity/olcrtc/internal/transport"

// ZZStreamPayloadLen is streamPayloadLen (conn.go:557-571).
func ZZStreamPayloadLen(record []byte) uint64 { return streamPayloadLen(record) }

// ZZOpenedStreams is openedStreams (conn.go:578-593).
func ZZOpenedStreams(record []byte) (bool, bool) { return openedStreams(record) }

// ZZDataAAD and ZZControlAAD are the lane strings (conn.go:73-74).
const (
	ZZDataAAD    = dataRecordAAD
	ZZControlAAD = controlRecordAAD
)

// ZZBatchLimit is the plaintext one batched record may carry for a link with
// these features, and false when the link sends every frame on its own
// (batch.go:51-63).
func ZZBatchLimit(features transport.Features) (int, bool) {
	b := newBatcher(features)
	if b == nil {
		return 0, false
	}
	return b.limit, true
}

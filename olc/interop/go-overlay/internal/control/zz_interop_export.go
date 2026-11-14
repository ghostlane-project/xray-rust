//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file for the Go decode oracle (olc/interop in the xray-rust
// fork): it exports, under the olcrtc_interop tag only, the two steps the
// control read loop takes on every frame.

package control

import "io"

// ZZReadMessage reads one frame and parses it as readLoop does
// (control.go:270-276: readFrame, then parseMessage).
func ZZReadMessage(r io.Reader) (Message, error) {
	raw, err := readFrame(r)
	if err != nil {
		return Message{}, err
	}
	return parseMessage(raw)
}

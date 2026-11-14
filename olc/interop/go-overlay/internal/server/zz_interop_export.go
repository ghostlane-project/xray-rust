//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Exported for the decode oracle (cmd/zz-olcrtc-oracle) of the Rust port. An
// overlay file: build-oracle.sh copies it into a clean checkout of the pin.

package server

// ZZParseConnect runs the exit's own CONNECT parse (serve.go:250-256) and the
// target check behind it (egress.go:187-195) on the bytes a stream carried.
// parsed is parseConnectRequest's verdict: the buffer is a whole JSON value
// and its cmd is "connect".
func ZZParseConnect(buf []byte) (cmd, addr string, port int, parsed bool, validErr error) {
	request, ok := parseConnectRequest(buf)
	if !ok {
		return request.Cmd, request.Addr, request.Port, false, nil
	}
	return request.Cmd, request.Addr, request.Port, true, request.validate()
}

// ZZMaxConnectRequest is handleStream's bound on a request (serve.go:226).
const ZZMaxConnectRequest = 4096

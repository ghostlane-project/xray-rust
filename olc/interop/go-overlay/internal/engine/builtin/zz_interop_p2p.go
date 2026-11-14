//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): a server built with
// the olcrtc_interop tag knows the interop-p2p engine, which the gate's p2p
// target joins it through (engine: { name: interop-p2p }).

package builtin

import "github.com/openlibrecommunity/olcrtc/internal/engine/interopp2p"

func init() { //nolint:gochecknoinits // an engine registers at load, as the built-in ones do
	interopp2p.Register()
}

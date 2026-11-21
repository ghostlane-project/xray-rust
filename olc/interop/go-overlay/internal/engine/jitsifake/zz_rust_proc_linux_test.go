// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): how the Rust client
// these tests start is tied to the test process on Linux, where they run:
// its own process group, and Pdeathsig kills it with the test process.

//go:build linux

package jitsifake

import "syscall"

func rustChildProc() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

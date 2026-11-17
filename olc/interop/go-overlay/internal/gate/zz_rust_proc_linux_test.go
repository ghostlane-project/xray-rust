// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): how the gate's
// children (the pinned server, the Rust client) are tied to the test process
// on Linux, where the gate runs.

//go:build linux

package gate

import "syscall"

// childProc is a child's SysProcAttr: Pdeathsig kills it when the test
// process dies (a panic, -timeout, a kill), where no cleanup runs; group puts
// it in a process group of its own, which its stop signals whole.
func childProc(group bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: group, Pdeathsig: syscall.SIGKILL}
}

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the same as
// zz_rust_proc_linux_test.go where there is no Pdeathsig, the macOS runner
// that hosts the iOS lab's T1 side (TestT1Host). There a child outlives a
// test process that dies without its cleanup; the runner's job end takes it.

//go:build !linux

package gate

import "syscall"

// childProc is a child's SysProcAttr: group puts it in a process group of
// its own, which its stop signals whole.
func childProc(group bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: group}
}

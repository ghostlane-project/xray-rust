// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the same as
// zz_rust_proc_linux_test.go where there is no Pdeathsig (macOS), so the
// package still builds there; a child outlives a test process that dies
// without its cleanup.

//go:build !linux

package jitsifake

import "syscall"

func rustChildProc() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

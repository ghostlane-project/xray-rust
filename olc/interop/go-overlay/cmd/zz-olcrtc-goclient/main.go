//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Command zz-olcrtc-goclient is the Go public client as a process of its
// own, for the gate's baseline on the vp8channel targets (the overlay's
// internal/gate/zz_go_child_test.go builds and runs it; internal/zzgoclient
// says why the engine's CLI does not serve). It is not part of the engine.
//
//	zz-olcrtc-goclient <config.json>
//
// The config is zzgoclient.Config. The client's log is the engine's, on
// stderr; its "SOCKS5 server listening on <addr>" line is how the gate
// learns the port. SIGTERM or an interrupt ends it.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/openlibrecommunity/olcrtc/internal/zzgoclient"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "zz-olcrtc-goclient:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: zz-olcrtc-goclient <config.json>")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg, err := zzgoclient.Parse(raw)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return zzgoclient.Run(ctx, cfg)
}

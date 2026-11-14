//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Command zz-olcrtc-kcppeer is the Go side of olc-kcp's live conformance
// (olc/olc-kcp/tests/conformance.rs in the xray-rust fork): one KCP session
// started by the engine's own startKCP (vp8channel/kcp.go:138-190) on a UDP
// socket. It is not part of the engine: olc/interop/build-kcp-peer.sh copies
// it, with the overlay's export shims, into a clean checkout of the pin and
// builds it.
//
// Each datagram is one packet as kcpConn hands it to the lane's writer
// (epoch header ‖ KCP packet ‖ CRC-32C, kcpconn.go:337-352). Inbound, the
// epoch header is dropped and the rest goes to deliver(), which checks and
// strips the CRC, as vp8channel's inbound dispatch does.
//
// The workload: -send bytes in messages from a seeded generator, and -recv
// bytes expected from the peer's generator. A message is 1 + (x mod -max-msg)
// bytes, x the generator's next value, and its bytes are the generator's next
// values, little-endian, eight at a time; a sender sends messages until it
// has sent at least -send bytes. The generator is SplitMix64.
//
// Lines on stdout:
//
//	LISTEN <addr>       first, once the socket is bound
//	SENT <ms>           every message handed to KCP, ms since start
//	DONE {json}         every expected byte received, in order and intact
//	ERR <text>          a received message differs from the expected one
//	STATS {json}        last, when stdin closes or on SIGTERM: kcp-go's SNMP
//	                    counters, kcpConn's drop counts and the settings
//
// The peer exits when its stdin closes (so it dies with the test that started
// it) or on SIGTERM.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/transport/vp8channel"
)

// gen is SplitMix64, as olc-interop's Rng.
type gen struct{ s uint64 }

func (g *gen) next() uint64 {
	g.s += 0x9e3779b97f4a7c15
	z := g.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// message is the generator's next message.
func (g *gen) message(maxMsg int) []byte {
	n := 1 + int(g.next()%uint64(maxMsg)) //nolint:gosec // G115: maxMsg > 0
	b := make([]byte, n)
	var w [8]byte
	for i := 0; i < n; i += 8 {
		binary.LittleEndian.PutUint64(w[:], g.next())
		copy(b[i:], w[:])
	}
	return b
}

type out struct {
	mu sync.Mutex
}

func (o *out) line(format string, args ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

type done struct {
	RxBytes  int64 `json:"rx_bytes"`
	RxMsgs   int64 `json:"rx_msgs"`
	FirstMs  int64 `json:"first_ms"`
	LastMs   int64 `json:"last_ms"`
	MaxGapMs int64 `json:"max_gap_ms"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "UDP address to bind")
	peer := flag.String("peer", "", "UDP address of the other side")
	sndWnd := flag.Int("snd", 0, "startKCP's sndWnd (0: the host profile's)")
	constrained := flag.Bool("constrained", false, "the phone profile (runtime.UseConstrainedBuffers)")
	send := flag.Int64("send", 0, "bytes to send")
	sendSeed := flag.Uint64("send-seed", 1, "generator seed of what this side sends")
	recv := flag.Int64("recv", 0, "bytes to expect")
	recvSeed := flag.Uint64("recv-seed", 2, "generator seed of what the other side sends")
	maxMsg := flag.Int("max-msg", 61440, "largest message")
	sockBuf := flag.Int("sockbuf", 8<<20, "socket buffer sizes")
	flag.Parse()
	if *peer == "" || *maxMsg <= 0 {
		fmt.Fprintln(os.Stderr, "usage: zz-olcrtc-kcppeer -peer <addr> [flags]")
		os.Exit(2)
	}
	if *constrained {
		runtime.UseConstrainedBuffers()
	}
	o := &out{}
	if err := run(o, *listen, *peer, *sndWnd, *send, *sendSeed, *recv, *recvSeed, *maxMsg, *sockBuf); err != nil {
		o.line("FATAL %v", err)
		os.Exit(1)
	}
}

func run(o *out, listen, peer string, sndWnd int, send int64, sendSeed uint64,
	recv int64, recvSeed uint64, maxMsg, sockBuf int,
) error {
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp", peer)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(sockBuf)
	_ = conn.SetWriteBuffer(sockBuf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case <-sig:
		case <-ctx.Done():
		}
		cancel()
	}()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()

	start := time.Now()
	ms := func() int64 { return time.Since(start).Milliseconds() }

	// The receiving side: onData runs on startKCP's read loop, in order.
	expect := &gen{s: recvSeed}
	var rx done
	var last time.Time
	var bad bool
	onData := func(msg []byte) {
		if bad || rx.RxBytes >= recv {
			if !bad {
				bad = true
				o.line("ERR a message after every expected byte (%d bytes)", len(msg))
				cancel()
			}
			return
		}
		want := expect.message(maxMsg)
		if string(want) != string(msg) {
			bad = true
			o.line("ERR message %d: got %d bytes, want %d", rx.RxMsgs, len(msg), len(want))
			cancel()
			return
		}
		now := time.Now()
		if rx.RxMsgs == 0 {
			rx.FirstMs = ms()
		} else if gap := now.Sub(last).Milliseconds(); gap > rx.MaxGapMs {
			rx.MaxGapMs = gap
		}
		last = now
		rx.RxMsgs++
		rx.RxBytes += int64(len(msg))
		rx.LastMs = ms()
		if rx.RxBytes >= recv {
			body, _ := json.Marshal(rx)
			o.line("DONE %s", body)
		}
	}

	var hdr [vp8channel.ZZEpochHdrLen]byte
	for i := range hdr {
		hdr[i] = byte(0xA0 + i)
	}
	k, err := vp8channel.ZZStartKCP(onData, hdr, sndWnd)
	if err != nil {
		return err
	}
	defer k.Close()

	o.line("LISTEN %s", conn.LocalAddr())

	// KCP's packets to the peer.
	go func() {
		var buf []byte
		for {
			var ok bool
			buf, ok = k.Next(ctx, buf[:0])
			if !ok {
				return
			}
			if _, err := conn.WriteToUDP(buf, raddr); err != nil {
				o.line("FATAL write: %v", err)
				cancel()
				return
			}
		}
	}()
	// The peer's packets to KCP.
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > vp8channel.ZZEpochHdrLen {
				k.Deliver(buf[vp8channel.ZZEpochHdrLen:n])
			}
		}
	}()
	// The sending side: Send blocks while KCP's window is full.
	go func() {
		g := &gen{s: sendSeed}
		var sent int64
		for sent < send {
			m := g.message(maxMsg)
			if err := k.Send(m); err != nil {
				if ctx.Err() == nil {
					o.line("FATAL send: %v", err)
					cancel()
				}
				return
			}
			sent += int64(len(m))
		}
		o.line("SENT %d", ms())
	}()

	<-ctx.Done()
	_ = conn.SetReadDeadline(time.Now())
	corrupt, dropped := k.Counts()
	snmp := kcp.DefaultSnmp.Copy()
	stats := map[string]any{
		"corrupt":            corrupt,
		"dropped":            dropped,
		"out_segs":           snmp.OutSegs,
		"in_segs":            snmp.InSegs,
		"repeat_segs":        snmp.RepeatSegs,
		"lost_segs":          snmp.LostSegs,
		"fast_retrans_segs":  snmp.FastRetransSegs,
		"early_retrans_segs": snmp.EarlyRetransSegs,
		"retrans_segs":       snmp.RetransSegs,
		"out_pkts":           snmp.OutPkts,
		"in_pkts":            snmp.InPkts,
		"settings":           k.Settings(),
	}
	body, _ := json.Marshal(stats)
	o.line("STATS %s", body)
	if bad {
		return fmt.Errorf("a received message differed")
	}
	return nil
}

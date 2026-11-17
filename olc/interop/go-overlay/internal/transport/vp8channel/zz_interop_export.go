//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Exported for the KCP conformance peer (cmd/zz-olcrtc-kcppeer) of the Rust
// port. An overlay file: build-kcp-peer.sh copies it into a clean checkout of
// the pin.

package vp8channel

import (
	"context"
	"reflect"

	kcp "github.com/xtaci/kcp-go/v5"
)

// ZZEpochHdrLen is epochHdrLen (wire.go): the header in front of every KCP
// packet on the wire.
const ZZEpochHdrLen = epochHdrLen

// ZZKCP is one session the engine's own startKCP (kcp.go:138-190) started,
// with its outbound queue exposed: what the lane's writer would put in frames.
type ZZKCP struct {
	rt  *kcpRuntime
	out chan *packetBuffer
}

// ZZStartKCP is startKCP with an outbound queue of this host profile's size
// (outboundQueueSizeFor), hdr in front of every packet and sndWnd (0: the
// profile's window).
func ZZStartKCP(onData func([]byte), hdr [epochHdrLen]byte, sndWnd int) (*ZZKCP, error) {
	out := make(chan *packetBuffer, outboundQueueSizeFor())
	rt, err := startKCP(out, onData, hdr, sndWnd)
	if err != nil {
		return nil, err
	}
	return &ZZKCP{rt: rt, out: out}, nil
}

// Next waits for the next packet KCP wrote (epoch header ‖ KCP packet ‖
// CRC-32C) and appends it to buf; false once ctx is done.
func (k *ZZKCP) Next(ctx context.Context, buf []byte) ([]byte, bool) {
	select {
	case p := <-k.out:
		buf = append(buf, p.data...)
		p.release()
		return buf, true
	case <-ctx.Done():
		return buf, false
	}
}

// Deliver is kcpRuntime.deliver: one packet without its epoch header, as the
// inbound dispatch hands it over (CRC checked and stripped there).
func (k *ZZKCP) Deliver(payload []byte) { k.rt.deliver(payload) }

// Send is kcpRuntime.send: one message, length-prefixed, in one write.
func (k *ZZKCP) Send(msg []byte) error { return k.rt.send(msg) }

// Close is kcpRuntime.close.
func (k *ZZKCP) Close() { k.rt.close() }

// Counts are kcpConn's drop counters: packets with a bad CRC, and packets the
// inbound queue had no room for.
func (k *ZZKCP) Counts() (corrupt, dropped uint64) {
	return k.rt.conn.corrupt.Load(), k.rt.conn.dropped.Load()
}

// Settings reads what startKCP left in kcp-go's session (kcp.go:155-179).
// The fields are kcp-go's own and unexported, so they are read by reflection,
// which reads them without changing anything.
func (k *ZZKCP) Settings() map[string]int64 { return ZZKCPSettings(k.rt.sess) }

// ZZKCPSettingFields are the kcp-go KCP fields Settings reports
// (kcp-go/kcp.go:166-200). Not updated, ts_flush or ts_probe: the session's
// timer writes those from its first tick.
var ZZKCPSettingFields = []string{ //nolint:gochecknoglobals // a fixed list
	"conv", "mtu", "mss", "state", "snd_una", "snd_nxt", "rcv_nxt",
	"ssthresh", "rx_rttvar", "rx_srtt", "rx_rto", "rx_minrto",
	"snd_wnd", "rcv_wnd", "rmt_wnd", "cwnd", "incr",
	"probe", "probe_wait", "interval", "nodelay",
	"dead_link", "fastresend", "nocwnd", "stream",
}

// ZZKCPSettings reads a session's settings: ZZKCPSettingFields of its KCP,
// and the session's own ackNoDelay, writeDelay and headerSize (1 for true).
func ZZKCPSettings(sess *kcp.UDPSession) map[string]int64 {
	out := map[string]int64{}
	s := reflect.ValueOf(sess).Elem()
	k := s.FieldByName("kcp").Elem()
	for _, name := range ZZKCPSettingFields {
		out[name] = zzInt(k.FieldByName(name))
	}
	for _, name := range []string{"ackNoDelay", "writeDelay", "headerSize"} {
		out[name] = zzInt(s.FieldByName(name))
	}
	return out
}

func zzInt(v reflect.Value) int64 {
	switch v.Kind() { //nolint:exhaustive // only the kinds these fields have
	case reflect.Bool:
		if v.Bool() {
			return 1
		}
		return 0
	case reflect.Int, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint32, reflect.Uint64, reflect.Uint:
		return int64(v.Uint()) //nolint:gosec // G115: KCP's fields are uint32
	default:
		panic("zzInt: unexpected kind " + v.Kind().String())
	}
}

//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the Jingle vectors of
// the Rust port, offer.json and accept.json, from two Go engines at the pin in
// one room of the Go fake (internal/engine/jitsifake). offer.json pairs the
// session-initiate the fake sent with the SDP the engine's pion was given
// from it (what the library's JingleToSDP made); accept.json pairs the SDP
// the engine's pion answered with and the session-accept the library wrote
// from it. What differs from run to run (ICE credentials, fingerprints,
// SSRCs, stream and track ids, candidates) is replaced by fixed values in
// both texts of a pair, by the order they first appear in.

package jitsi

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/engine/jitsifake"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

type zzOffer struct {
	InitiateXML string `json:"initiate_xml"`
	OfferSDP    string `json:"offer_sdp"`
}

type zzAccept struct {
	LocalSDP    string `json:"local_sdp"`
	AcceptXML   string `json:"accept_xml"`
	AcceptInner string `json:"accept_inner"`
}

var (
	zzUfrag  = regexp.MustCompile(`(?:a=ice-ufrag:|ufrag=")([^\s"<]+)`)
	zzPwd    = regexp.MustCompile(`(?:a=ice-pwd:|pwd=")([^\s"<]+)`)
	zzFP     = regexp.MustCompile(`[0-9A-F]{2}(?::[0-9A-F]{2}){31}`)
	zzSSRC   = regexp.MustCompile(`(?:a=ssrc:|ssrc=")(\d+)`)
	zzGroup  = regexp.MustCompile(`a=ssrc-group:\S+ ([\d ]+)`)
	zzMsid   = regexp.MustCompile(`(?:a=ssrc:\d+ (?:cname|msid):|a=msid:)(\S+)(?: (\S+))?`)
	zzCand   = regexp.MustCompile(`a=candidate:(\S+) \d (?:udp|tcp) \d+ (\S+) (\d+) typ`)
	zzXMLCnd = regexp.MustCompile(`<candidate [^>]*/>`)
	zzOrigin = regexp.MustCompile(`o=- \d+ \d+ IN`)
)

// zzScrub replaces what is random in texts with fixed values, the same in
// every text, and keeps the first candidate of each transport and section.
func zzScrub(texts ...string) []string {
	all := strings.Join(texts, "\n")
	var repl [][2]string
	seen := map[string]bool{}
	add := func(old, to string) {
		if old != "" && !seen[old] {
			seen[old] = true
			repl = append(repl, [2]string{old, to})
		}
	}
	for i, m := range zzUfrag.FindAllStringSubmatch(all, -1) {
		add(m[1], fmt.Sprintf("ufrag%02d", i))
	}
	for i, m := range zzPwd.FindAllStringSubmatch(all, -1) {
		add(m[1], fmt.Sprintf("pwd%020d", i))
	}
	for i, m := range zzFP.FindAllString(all, -1) {
		b := fmt.Sprintf("%02X", 0x10+i)
		add(m, strings.TrimSuffix(strings.Repeat(b+":", 32), ":"))
	}
	n := 0
	for _, m := range zzSSRC.FindAllStringSubmatch(all, -1) {
		add(m[1], fmt.Sprint(1000000+n))
		n++
	}
	for _, g := range zzGroup.FindAllStringSubmatch(all, -1) {
		for _, v := range strings.Fields(g[1]) {
			add(v, fmt.Sprint(1000000+n))
			n++
		}
	}
	n = 0
	for _, m := range zzMsid.FindAllStringSubmatch(all, -1) {
		for _, v := range m[1:] {
			if v != "" && v != "-" {
				add(v, fmt.Sprintf("id%02d", n))
				n++
			}
		}
	}
	n = 0
	for _, m := range zzCand.FindAllStringSubmatch(all, -1) {
		add(m[1], fmt.Sprint(100+n))
		add(m[3], fmt.Sprint(40000+n))
		n++
	}
	ips := 0
	for _, m := range zzCand.FindAllStringSubmatch(all, -1) {
		if !seen["ip:"+m[2]] {
			seen["ip:"+m[2]] = true
			add(m[2], fmt.Sprintf("192.0.2.%d", ips+1))
			ips++
		}
	}
	// Longest first: no replacement lands inside another's value.
	sort.SliceStable(repl, func(i, j int) bool { return len(repl[i][0]) > len(repl[j][0]) })
	out := make([]string, len(texts))
	for i, t := range texts {
		for _, r := range repl {
			t = strings.ReplaceAll(t, r[0], r[1])
		}
		out[i] = zzFirstCandidate(zzOrigin.ReplaceAllString(t, "o=- 1 2 IN"))
	}
	return out
}

// zzFirstCandidate drops every candidate after the first of its section (SDP)
// or transport (Jingle): how many an interface list gives is the machine's.
func zzFirstCandidate(t string) string {
	var out []string
	have := false
	for _, line := range strings.Split(t, "\n") {
		if strings.HasPrefix(line, "m=") {
			have = false
		}
		if strings.HasPrefix(line, "a=candidate:") {
			if have {
				continue
			}
			have = true
		}
		out = append(out, line)
	}
	t = strings.Join(out, "\n")
	// The Jingle form: per transport element.
	parts := strings.Split(t, "<transport ")
	for i := 1; i < len(parts); i++ {
		end := strings.Index(parts[i], "</transport>")
		if end < 0 {
			continue
		}
		body, rest := parts[i][:end], parts[i][end:]
		first := true
		body = zzXMLCnd.ReplaceAllStringFunc(body, func(c string) string {
			if first {
				first = false
				return c
			}
			return ""
		})
		parts[i] = body + rest
	}
	return strings.Join(parts, "<transport ")
}

func zzJingle(t *testing.T) {
	hub, err := jitsifake.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	hub.FixJID("0123456789abcdef")
	hub.FixJID("fedcba9876543210")
	room := hub.Named("secret-room")
	join := func(name string) *Session {
		s, err := New(context.Background(), engine.Config{URL: hub.Host(), Name: name, OnData: func([]byte) {}, Extra: map[string]string{credentialKeyRoom: "secret-room"}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s.(*Session)
	}
	a := join("olcsrv")
	_ = join("olccli")
	deadline := time.Now().Add(30 * time.Second)
	for !a.bridgeReady.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the first engine's bridge did not open within 30 s")
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.pcMu.Lock()
	pc := a.pc
	a.pcMu.Unlock()
	remote, local := pc.RemoteDescription().SDP, pc.LocalDescription().SDP
	st := room.State()
	initiate, accept := st.Initiated["01234567"], st.Accepted["01234567"]
	if initiate == "" || accept == "" {
		t.Fatalf("the fake saw no initiate (%d bytes) or accept (%d bytes) for the first engine", len(initiate), len(accept))
	}
	inner := accept[strings.Index(accept, "<jingle"):]
	inner = inner[strings.Index(inner, ">")+1 : strings.LastIndex(inner, "</jingle>")]
	o := zzScrub(initiate, remote)
	zzvectors.Write(t, "jitsi/offer.json", zzGenerator,
		[]string{"j/internal/jingle/sdp.go (JingleToSDP)", "j/internal/peer/peer.go (Accept)"}, zzOffer{InitiateXML: o[0], OfferSDP: o[1]})
	r := zzScrub(local, accept, inner)
	zzvectors.Write(t, "jitsi/accept.json", zzGenerator,
		[]string{"j/internal/jingle/build.go (SDPToJingleAccept)", "j/internal/xmpp/conn.go (SendSessionAccept)"},
		zzAccept{LocalSDP: r[0], AcceptXML: r[1], AcceptInner: r[2]})
}

//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/olc-jitsi in the xray-rust fork) of
// the Jitsi room link's reading. An overlay file: regen.sh copies it into a
// clean checkout of the pin. Nothing here opens a socket.

package jitsi

import (
	"errors"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/auth/jitsi/zz_vectors_test.go"

type zzRoomCase struct {
	Raw  string `json:"raw"`
	Host string `json:"host"`
	Room string `json:"room"`
	// Error is "", "required" (auth.ErrRoomIDRequired) or "invalid".
	Error string `json:"error"`
}

func TestZZVectors(t *testing.T) {
	raws := []string{
		"https://meet.systemli.org/myroom",
		"http://meet.example/myroom",
		"meet.example.com/myroom",
		"https://meet.example/myroom/",
		"//meet.example/myroom",
		"https://meet.example/MyRoom",
		"",
		"meet.example.com",
		"https://meet.example/",
		"https://",
		"   ",
		"  https://meet.example/a/b//  ",
		"/meet.example/room",
		"https:///room",
		"https://meet.example//",
		"https://meet.example/ / ",
		"https://meet.example/room?x=1#frag",
		"https://user:pw@meet.example/room",
		"https://meet.example:8443/room",
		"https://meet.example/jitsi/room",
		"://meet.example/room",
		"a://b://c/d",
		"\t\n meet.example/room \r\n",
		"meet.example/ room with spaces ",
		"https://\u00a0meet.example/room",
		"https://meet.example/\u00e9\u00e8",
		"/",
		"//",
		"///",
		"a/b",
		"/a/b",
		"a//b",
	}
	cases := make([]zzRoomCase, 0, len(raws))
	for _, raw := range raws {
		host, room, err := parseRoomURL(raw)
		c := zzRoomCase{Raw: raw, Host: host, Room: room}
		switch {
		case err == nil:
		case errors.Is(err, auth.ErrRoomIDRequired):
			c.Error = "required"
		case errors.Is(err, ErrInvalidRoomURL):
			c.Error = "invalid"
		default:
			t.Fatalf("parseRoomURL(%q): unexpected error %v", raw, err)
		}
		cases = append(cases, c)
	}
	zzvectors.Write(t, "jitsi/room.json", zzGenerator,
		[]string{"internal/auth/jitsi/jitsi.go:75-95 (parseRoomURL)", "internal/auth/jitsi/jitsi_test.go (TestParseRoomURL)"}, cases)
}

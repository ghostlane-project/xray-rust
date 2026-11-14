package salutejazz

// Ghostlane olc/spike, probe (e): which TURN transports SaluteJazz hands a
// client. Dropped into the engine's internal/engine/salutejazz at 2d4266af by
// scripts/probe-e.sh, never committed there. It does what the engine's carrier
// does to reach the room - the auth provider's anonymous CreateRoom and Issue
// (preconnect), the connector dial with the web client's Origin and User-Agent,
// the engine's own join frame - and reads frames until rtc:config, then leaves.
// The servers are logged with their credentials redacted to lengths, raw and as
// the engine normalises them for pion.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	authsj "github.com/openlibrecommunity/olcrtc/internal/auth/salutejazz"
	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

func TestSpikeRTCConfig(t *testing.T) {
	if os.Getenv("OLC_SPIKE_LIVE") != "1" {
		t.Skip("joins a live SaluteJazz room: set OLC_SPIKE_LIVE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	provider := authsj.New()
	ref, err := provider.CreateRoom(ctx, auth.Config{})
	if err != nil {
		t.Fatalf("create room: %v", err)
	}
	creds, err := provider.Issue(ctx, auth.Config{RoomURL: ref})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if u, perr := url.Parse(creds.URL); perr == nil {
		t.Logf("connector host %s path %s", u.Host, u.Path)
	}

	dialer := protect.NewWebSocketDialer(wsHandshakeTimeout)
	header := http.Header{}
	header.Set("Origin", webOrigin)
	header.Set("User-Agent", webUserAgent)
	conn, resp, err := dialer.DialContext(ctx, creds.URL, header)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial connector: %v", err)
	}
	defer conn.Close()

	join, _ := json.Marshal(joinRequest{
		Password: creds.Token, ParticipantName: "olc-spike",
		SupportedFeatures: supportedFeatures{AttachedRooms: true, SessionGroups: true, Transcription: true, Interpretation: true},
	})
	if err := conn.WriteJSON(envOut{RoomID: creds.Extra[credentialKeyRoomID], Payload: join, Event: eventJoin, RequestID: uuid.NewString()}); err != nil {
		t.Fatalf("join: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		var in envIn
		if err := conn.ReadJSON(&in); err != nil {
			t.Fatalf("read: %v", err)
		}
		switch in.Event {
		case eventError:
			t.Fatalf("connector error: %s", in.Payload)
		case eventJoinResponse:
			t.Logf("join-response received")
		case eventMediaOut:
			var m mediaPayload
			if err := json.Unmarshal(in.Payload, &m); err != nil {
				t.Fatalf("media-out: %v", err)
			}
			if m.Method != methodConfig || m.Configuration == nil {
				continue
			}
			spikeReportRTCConfig(t, m.Configuration)
			return
		}
	}
}

func spikeReportRTCConfig(t *testing.T, cfg *rtcConfiguration) {
	t.Helper()
	servers := make([]webrtc.ICEServer, 0, len(cfg.ICEServers))
	for i, s := range cfg.ICEServers {
		for _, u := range s.URLs {
			t.Logf("RTC_CONFIG server=%d url=%s transport=%s username_len=%d credential_len=%d",
				i, u, spikeTransportOf(u), len(s.Username), len(s.Credential))
		}
		servers = append(servers, webrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
	}
	for i, s := range engine.NormaliseICEServers(servers) {
		t.Logf("RTC_CONFIG_NORMALISED server=%d urls=%s", i, strings.Join(s.URLs, " "))
	}
}

// spikeTransportOf names what a client opens to reach one ICE URL (RFC 7064,
// RFC 7065: turn defaults to UDP, turns to TLS over TCP; turns over UDP is DTLS).
func spikeTransportOf(raw string) string {
	scheme, rest, _ := strings.Cut(raw, ":")
	transport := ""
	if i := strings.Index(rest, "?transport="); i >= 0 {
		transport = strings.ToLower(rest[i+len("?transport="):])
	}
	switch strings.ToLower(scheme) {
	case "stun":
		return "stun/udp"
	case "stuns":
		return "stuns/tls"
	case "turn":
		if transport == "" {
			transport = "udp"
		}
		return fmt.Sprintf("turn/%s", transport)
	case "turns":
		if transport == "udp" {
			return "turns/dtls"
		}
		return "turns/tls"
	}
	return "unknown"
}

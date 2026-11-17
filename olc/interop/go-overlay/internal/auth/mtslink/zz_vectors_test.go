//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork) of the
// MTS Link auth provider. An overlay file: regen.sh copies it into a clean
// checkout of the pin. It calls the provider's own functions and asks its own
// gateway fake (mtslink_test.go); nothing here reaches the service.

package mtslink

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/auth/mtslink/zz_vectors_test.go"

// zzInput is an input that need not be UTF-8: the bytes in hex, and the text
// beside them when they are one.
type zzInput struct {
	Name     string `json:"name"`
	InputHex string `json:"input_hex"`
	// Input is null when the bytes are not UTF-8.
	Input *string `json:"input"`
	OK    bool    `json:"ok"`
}

func zzInputOf(name, in string, ok bool) zzInput {
	out := zzInput{Name: name, InputHex: hex.EncodeToString([]byte(in)), OK: ok}
	if utf8.ValidString(in) {
		out.Input = &in
	}
	return out
}

type zzLinkCase struct {
	Name    string `json:"name"`
	Link    string `json:"link"`
	OK      bool   `json:"ok"`
	Event   string `json:"event"`
	Session string `json:"session"`
}

func zzParseEventLink(t *testing.T) {
	t.Helper()
	long := strings.Repeat("7", 20)
	inputs := []struct{ name, link string }{
		// The nine of TestParseEventLink (mtslink_test.go:153-176), in its order.
		{"the join link", testLink},
		{"a session behind it", testLink + "/session/" + testSession},
		{"a stream behind it names no session", testLink + "/stream-new/" + testSession},
		{"spaces and a line end around it", "  " + testLink + "\n"},
		{"an owner that is not a number", "https://my.mts-link.ru/j/abc/" + testEvent},
		{"no event", "https://my.mts-link.ru/j/" + testOwner},
		{"not a url", "not a url"},
		{"another page", "https://my.mts-link.ru/events"},
		{"empty", ""},
		// More.
		{"a trailing slash", testLink + "/"},
		{"a session and a trailing slash", testLink + "/session/" + testSession + "/"},
		{"a query", testLink + "?utm=1&x=/j/1/2"},
		{"a fragment", testLink + "#/j/1/2"},
		{"the ice hint left on", testLink + "?ice=tcp"},
		{"j deeper in the path", "https://my.mts-link.ru/ru/app/j/" + testOwner + "/" + testEvent},
		{"the first j anchors, a later one is not looked for", "https://my.mts-link.ru/j/x/j/" + testOwner + "/" + testEvent},
		{"a twenty-digit event", "https://my.mts-link.ru/j/" + testOwner + "/" + long},
		{"a twenty-one-digit event", "https://my.mts-link.ru/j/" + testOwner + "/" + long + "7"},
		{"a twenty-one-digit owner", "https://my.mts-link.ru/j/" + long + "7/" + testEvent},
		{"a twenty-one-digit session is no session", testLink + "/session/" + long + "7"},
		{"a session that is not a number is no session", testLink + "/session/abc"},
		{"session with nothing behind it", testLink + "/session"},
		{"Session in another case", testLink + "/Session/" + testSession},
		{"J in another case", "https://my.mts-link.ru/J/" + testOwner + "/" + testEvent},
		{"another host", "https://example.org/j/" + testOwner + "/" + testEvent},
		{"http", "http://my.mts-link.ru/j/" + testOwner + "/" + testEvent},
		{"a port", "https://my.mts-link.ru:8443/j/" + testOwner + "/" + testEvent},
		{"no scheme", "my.mts-link.ru/j/" + testOwner + "/" + testEvent},
		{"no host", "https:///j/" + testOwner + "/" + testEvent},
		{"a scheme-relative link", "//my.mts-link.ru/j/" + testOwner + "/" + testEvent},
		{"two slashes before j", "https://my.mts-link.ru//j/" + testOwner + "/" + testEvent},
		{"two slashes inside", "https://my.mts-link.ru/j//" + testOwner + "/" + testEvent},
		{"j written as an escape", "https://my.mts-link.ru/%6A/" + testOwner + "/" + testEvent},
		{"a digit written as an escape", "https://my.mts-link.ru/j/" + testOwner + "/2030040050%30"},
		{"a slash written as an escape", "https://my.mts-link.ru/j/" + testOwner + "%2F" + testEvent},
		{"a bad escape", "https://my.mts-link.ru/j/" + testOwner + "/" + testEvent + "%zz"},
		{"full-width digits", "https://my.mts-link.ru/j/" + testOwner + "/１２３"},
		{"a space inside the path", "https://my.mts-link.ru/j/" + testOwner + "/ " + testEvent},
		{"a control byte", "https://my.mts-link.ru/j/" + testOwner + "/" + testEvent + "\x7f"},
		{"a tab in front", "\t" + testLink},
		{"zeros", "https://my.mts-link.ru/j/0/0"},
	}
	cases := make([]zzLinkCase, 0, len(inputs))
	for _, in := range inputs {
		event, session, err := parseEventLink(in.link)
		if err != nil && !errors.Is(err, ErrRoomRef) {
			t.Fatalf("parseEventLink(%q): error %v is not ErrRoomRef", in.link, err)
		}
		if !utf8.ValidString(in.link) {
			t.Fatalf("link %q is not UTF-8: the file holds text", in.link)
		}
		cases = append(cases, zzLinkCase{Name: in.name, Link: in.link, OK: err == nil, Event: event, Session: session})
	}
	zzvectors.Write(t, "mtslink/parse_event_link.json", zzGenerator,
		[]string{"internal/auth/mtslink/api.go:65-90 (parseEventLink)", "internal/auth/mtslink/mtslink_test.go:153-176"},
		struct {
			Error string       `json:"error"`
			Cases []zzLinkCase `json:"cases"`
		}{ErrRoomRef.Error(), cases})
}

func zzIDsAndHosts(t *testing.T) {
	t.Helper()
	ids := []zzInput{}
	for _, in := range []struct{ name, in string }{
		{"empty", ""},
		{"one digit", "0"},
		{"an id", testEvent},
		{"twenty digits", strings.Repeat("9", 20)},
		{"twenty-one digits", strings.Repeat("9", 21)},
		{"a letter", "12a"},
		{"a sign", "-1"},
		{"a plus", "+1"},
		{"a space in front", " 1"},
		{"a space behind", "1 "},
		{"a dot", "1.0"},
		{"full-width digits", "１２"},
		{"an Arabic-Indic digit", "٣"},
		{"a byte that is not UTF-8", "1\xff"},
		{"a line end", "1\n"},
	} {
		ids = append(ids, zzInputOf(in.name, in.in, isID(in.in)))
	}
	zzvectors.Write(t, "mtslink/is_id.json", zzGenerator,
		[]string{"internal/auth/mtslink/api.go:92-103 (isID)"}, ids)

	label := strings.Repeat("a", 63)
	host253 := label + "." + label + "." + label + "." + strings.Repeat("b", 61)
	hosts := []zzInput{}
	for _, in := range []struct{ name, in string }{
		{"the measured SFU", "sfu.mts-link.ru"},
		{"empty", ""},
		{"one letter", "a"},
		{"upper case", "SFU.MTS-Link.RU"},
		{"a port", "sfu.mts-link.ru:443"},
		{"an IPv4 address and a port", "127.0.0.1:8443"},
		{"an IPv6 address without brackets", "::1"},
		{"an IPv6 address in brackets", "[::1]:443"},
		{"an underscore", "sfu_1.mts-link.ru"},
		{"a slash", "sfu.mts-link.ru/x"},
		{"a path and a query", "sfu.mts-link.ru/rtc?x=1"},
		{"userinfo", "user@sfu.mts-link.ru"},
		{"a space", "sfu.mts-link.ru "},
		{"a question mark", "sfu.mts-link.ru?"},
		{"a hash", "sfu.mts-link.ru#"},
		{"a percent", "sfu%2emts-link.ru"},
		{"a Cyrillic name", "сфу.рф"},
		{"a byte that is not UTF-8", "sfu\xff"},
		{"a line end", "sfu.mts-link.ru\n"},
		{"only dots and dashes", ".-.:"},
		{"253 bytes", host253},
		{"254 bytes", host253 + "b"},
	} {
		hosts = append(hosts, zzInputOf(in.name, in.in, isHost(in.in)))
	}
	if len(host253) != 253 {
		t.Fatalf("the 253-byte host is %d bytes", len(host253))
	}
	zzvectors.Write(t, "mtslink/is_host.json", zzGenerator,
		[]string{"internal/auth/mtslink/api.go:105-119 (isHost)"}, hosts)
}

var zzHex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

// zzMaskIDs names the two random values of a room join: did, eight random
// bytes in hex, and pid, did turned left by one digit. It fails when they are
// not that.
func zzMaskIDs(t *testing.T, join string) string {
	t.Helper()
	u, err := url.Parse(join)
	if err != nil {
		t.Fatalf("room join %q: %v", join, err)
	}
	did, pid := u.Query().Get("did"), u.Query().Get("pid")
	if !zzHex16.MatchString(did) || !zzHex16.MatchString(pid) {
		t.Fatalf("did %q, pid %q: want sixteen lower-case hex digits each", did, pid)
	}
	if pid != did[1:]+did[:1] {
		t.Fatalf("pid %q is not did %q turned by one digit", pid, did)
	}
	if strings.Count(join, "did="+did) != 1 || strings.Count(join, "pid="+pid) != 1 {
		t.Fatalf("did or pid is not in %q exactly once", join)
	}
	return strings.NewReplacer("did="+did, "did=<did>", "pid="+pid, "pid=<pid>").Replace(join)
}

type zzJoinCase struct {
	Name         string `json:"name"`
	Server       string `json:"server"`
	Session      string `json:"session"`
	UserID       string `json:"user_id"`
	Nickname     string `json:"nickname"`
	JoinToken    string `json:"join_token"`
	PublishToken string `json:"publish_token"`
	URL          string `json:"url"`
}

func zzRoomJoinURL(t *testing.T) {
	t.Helper()
	cases := []zzJoinCase{
		{Name: "the measured shapes", Server: "sfu.mts-link.ru", Session: testSession, UserID: "100200999",
			Nickname: "cap-a", JoinToken: "vcJOIN000000000000000000000000000", PublishToken: "vcPRIVATE0000000000000000000000000"},
		{Name: "a Cyrillic name with a space", Server: "sfu.mts-link.ru", Session: testSession, UserID: "100200999",
			Nickname: "Мария Ковалёва", JoinToken: "vcJOIN", PublishToken: "vcPRIVATE"},
		{Name: "the default name", Server: "sfu.mts-link.ru", Session: testSession, UserID: "100200999",
			Nickname: defaultNickname, JoinToken: "vcJOIN", PublishToken: "vcPRIVATE"},
		{Name: "tokens with what a query escapes", Server: "sfu.mts-link.ru", Session: testSession, UserID: "1",
			Nickname: "a+b&c=d", JoinToken: "a+b/c=d~e*f", PublishToken: "x y?z#w%v"},
		{Name: "what a query leaves alone", Server: "sfu.mts-link.ru", Session: testSession, UserID: "1",
			Nickname: "-_.~", JoinToken: "AZaz09-_.~", PublishToken: "!'()*,;:@$"},
		{Name: "a host with a port", Server: "127.0.0.1:8443", Session: "1", UserID: "2",
			Nickname: "n", JoinToken: "j", PublishToken: "p"},
		{Name: "empty values", Server: "sfu.mts-link.ru", Session: testSession, UserID: "",
			Nickname: "", JoinToken: "", PublishToken: ""},
		{Name: "an emoji and an accent", Server: "sfu.mts-link.ru", Session: testSession, UserID: "1",
			Nickname: "é😀", JoinToken: "j", PublishToken: "p"},
	}
	for i := range cases {
		c := &cases[i]
		first := roomJoinURL(c.Server, c.Session, c.UserID, c.Nickname, c.JoinToken, c.PublishToken)
		second := roomJoinURL(c.Server, c.Session, c.UserID, c.Nickname, c.JoinToken, c.PublishToken)
		if first == second {
			t.Fatalf("%s: two joins carry one did: %s", c.Name, first)
		}
		c.URL = zzMaskIDs(t, first)
		if c.URL != zzMaskIDs(t, second) {
			t.Fatalf("%s: two joins differ beyond did and pid", c.Name)
		}
	}
	zzvectors.Write(t, "mtslink/room_join_url.json", zzGenerator,
		[]string{"internal/auth/mtslink/mtslink.go:118-140 (roomJoinURL)"},
		struct {
			Random map[string]string `json:"random"`
			Cases  []zzJoinCase      `json:"cases"`
		}{map[string]string{
			"<did>": "sixteen lower-case hex digits (eight random bytes), new on every call",
			"<pid>": "<did> turned left by one digit: did[1:] + did[:1]",
		}, cases})
}

// zzGatewayMask names the gateway's loopback address.
func zzGatewayMask(wire *zzvectors.Wire) func(string) string {
	return func(s string) string { return strings.ReplaceAll(s, wire.Host(), "<gateway>") }
}

type zzFormCase struct {
	Name string `json:"name"`
	// Nickname is auth.Config.Name; empty asks for the default.
	Nickname    string `json:"nickname"`
	GuestLogin  string `json:"guestlogin_body"`
	Conferences string `json:"conferences_body"`
}

func zzForms(t *testing.T) {
	t.Helper()
	_, srv := newGateway(t)
	wire := zzvectors.NewWire(t, srv.URL)
	cases := []zzFormCase{
		{Name: "an ASCII name", Nickname: "guest"},
		{Name: "a Cyrillic name with a space", Nickname: "Мария Ковалёва"},
		{Name: "what a form escapes", Nickname: "a+b&c=d"},
		{Name: "a tilde and an asterisk", Nickname: "~*"},
		{Name: "no name: the default", Nickname: ""},
		{Name: "what a form leaves alone", Nickname: "AZaz09-_.~"},
		{Name: "punctuation", Nickname: "!'()*,;:@$/?#[]%\"<>\\^`{|}"},
		{Name: "an emoji and an accent", Nickname: "é😀"},
		{Name: "spaces around", Nickname: " a  b "},
		{Name: "a line end and a tab", Nickname: "a\r\n\tb"},
	}
	for i := range cases {
		c := &cases[i]
		_, err := Provider{gateway: wire.URL()}.Issue(context.Background(), auth.Config{RoomURL: testLink, Name: c.Nickname})
		if err != nil {
			t.Fatalf("%s: Issue: %v", c.Name, err)
		}
		for _, r := range wire.Take() {
			if r.Method() != http.MethodPost {
				continue
			}
			switch {
			case strings.HasSuffix(r.Target(), "/guestlogin"):
				c.GuestLogin = string(r.Body)
			case strings.HasSuffix(r.Target(), "/conferences"):
				c.Conferences = string(r.Body)
			default:
				t.Fatalf("%s: a POST to %s", c.Name, r.Target())
			}
		}
		if c.GuestLogin == "" || c.Conferences == "" {
			t.Fatalf("%s: a form is missing: %q, %q", c.Name, c.GuestLogin, c.Conferences)
		}
	}
	zzvectors.Write(t, "mtslink/forms.json", zzGenerator,
		[]string{
			"internal/auth/mtslink/api.go:144-147 (the body is url.Values.Encode)",
			"internal/auth/mtslink/api.go:207-213 (guestlogin)", "internal/auth/mtslink/api.go:268-274 (conferences)",
			"internal/auth/mtslink/mtslink.go:80-83 (the default name)",
		}, cases)
}

type zzCookieCase struct {
	Name string `json:"name"`
	// SetCookie is the value of every Set-Cookie line of the login's reply,
	// in order, exactly as the reply carried it.
	SetCookie []string `json:"set_cookie"`
	// Cookie is the Cookie header every later gateway call sends; empty with
	// Error set when the login kept no cookie.
	Cookie string `json:"cookie"`
	Error  string `json:"error,omitempty"`
}

func zzCookies(t *testing.T) {
	t.Helper()
	attrs := "; Path=/; Domain=.mts-link.ru; Secure; HttpOnly; SameSite=None"
	cases := []zzCookieCase{
		{Name: "as the service sets them", SetCookie: []string{
			"access=eyJguest.access" + attrs, "refresh=6074c7a91c56476840728cab1c1b42f5" + attrs, "sessionId=529e1f7db49244b0" + attrs,
		}},
		{Name: "no attributes", SetCookie: []string{"a=1", "b=2"}},
		{Name: "an empty value is skipped", SetCookie: []string{"a=1; Path=/", "b=; Path=/", "c=3"}},
		{Name: "a quoted value loses its quotes", SetCookie: []string{`a="q"; Path=/`}},
		{Name: "a quoted empty value", SetCookie: []string{`a=""`, "b=2"}},
		{Name: "one quote", SetCookie: []string{`a="q`, "b=2"}},
		{Name: "a quote inside", SetCookie: []string{`a=q"r`, "b=2"}},
		{Name: "a name set twice is sent twice", SetCookie: []string{"a=1", "a=2"}},
		{Name: "names differ by case", SetCookie: []string{"A=1", "a=2"}},
		{Name: "a space inside a value", SetCookie: []string{"a=b c", "b=2"}},
		{Name: "a space inside a quoted value", SetCookie: []string{`a="b c"`, "b=2"}},
		{Name: "a comma inside a value", SetCookie: []string{"a=b,c", "b=2"}},
		{Name: "a backslash inside a value", SetCookie: []string{`a=b\c`, "b=2"}},
		{Name: "an equals sign inside a value", SetCookie: []string{"a=1=2"}},
		{Name: "a name that is no token", SetCookie: []string{"bad name=1", "b=2"}},
		{Name: "no name", SetCookie: []string{"=v", "b=2"}},
		{Name: "no equals sign", SetCookie: []string{"novalue", "b=2"}},
		{Name: "a value that is not ASCII", SetCookie: []string{"a=é", "b=2"}},
		{Name: "spaces around the pair", SetCookie: []string{"  a=1  ; Path=/", "b = 2"}},
		{Name: "an attribute only", SetCookie: []string{"; Path=/", "b=2"}},
		{Name: "nothing kept", SetCookie: []string{"a=; Path=/", "novalue"}},
		{Name: "no Set-Cookie at all", SetCookie: []string{}},
	}
	var current []string
	base := zzvectors.RawServer(t, func(zzvectors.WireRequest) []byte {
		var b strings.Builder
		b.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
		for _, line := range current {
			b.WriteString("Set-Cookie: " + line + "\r\n")
		}
		fmt.Fprintf(&b, "Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(replyGuestLogin), replyGuestLogin)
		return []byte(b.String())
	})
	client := &http.Client{Timeout: 10 * time.Second}
	for i := range cases {
		c := &cases[i]
		current = c.SetCookie
		g, err := guestLogin(context.Background(), client, base, testSession, "guest")
		switch {
		case err == nil:
			c.Cookie = g.cookies
		case errors.Is(err, ErrIncompleteReply):
			c.Error = err.Error()
		default:
			t.Fatalf("%s: guestLogin: %v", c.Name, err)
		}
	}
	client.CloseIdleConnections()
	zzvectors.Write(t, "mtslink/cookies.json", zzGenerator,
		[]string{
			"internal/auth/mtslink/api.go:175-180 (every Set-Cookie with a name and a value, through http.Response.Cookies)",
			"internal/auth/mtslink/api.go:229-236 (joined with \"; \"; none is an incomplete reply)",
		}, cases)
}

type zzCredentials struct {
	URL   string            `json:"url"`
	Token string            `json:"token"`
	Extra map[string]string `json:"extra"`
}

type zzFlow struct {
	Flow string `json:"flow"`
	// Link, Nickname and DefaultICE are auth.Config's RoomURL, Name and
	// DefaultICE.
	Link       string `json:"link"`
	Nickname   string `json:"nickname"`
	DefaultICE string `json:"default_ice"`
	// Error is Issue's error text, empty when it issued Credentials.
	Error       string                 `json:"error"`
	Credentials *zzCredentials         `json:"credentials"`
	Requests    []zzvectors.WireRecord `json:"requests"`
}

func zzRequests(t *testing.T) {
	t.Helper()
	flows := []zzFlow{
		{Flow: "issue", Link: testLink, Nickname: "Мария Ковалёва", DefaultICE: "tcp"},
		{Flow: "issue_session_link", Link: testLink + "/session/" + testSession + "?ice=both", Nickname: "", DefaultICE: "tcp"},
		{Flow: "issue_join_token_refused", Link: testLink, Nickname: "guest", DefaultICE: ""},
	}
	for i := range flows {
		f := &flows[i]
		g, srv := newGateway(t)
		if f.Flow == "issue_join_token_refused" {
			g.status("/api/eventsessions/"+testSession+"/join-token", http.StatusUnauthorized, replyNoToken)
		}
		wire := zzvectors.NewWire(t, srv.URL)
		mask := zzGatewayMask(wire)
		creds, err := Provider{gateway: wire.URL()}.Issue(context.Background(),
			auth.Config{RoomURL: f.Link, Name: f.Nickname, DefaultICE: f.DefaultICE})
		if err != nil {
			f.Error = err.Error()
		} else {
			extra := map[string]string{}
			for k, v := range creds.Extra {
				extra[k] = mask(v)
			}
			f.Credentials = &zzCredentials{URL: zzMaskIDs(t, creds.URL), Token: creds.Token, Extra: extra}
		}
		if (f.Flow == "issue_join_token_refused") != (err != nil) {
			t.Fatalf("%s: Issue error = %v", f.Flow, err)
		}
		f.Requests = zzvectors.Number(zzvectors.WireRecords(f.Flow, "gateway", wire.Take(), mask))
		if len(f.Requests) == 0 {
			t.Fatalf("%s: no request went through the listener", f.Flow)
		}
		for _, r := range f.Requests {
			if r.Proto != "HTTP/1.1" {
				t.Fatalf("%s: %s %s over %s", f.Flow, r.Method, r.Target, r.Proto)
			}
		}
	}
	zzvectors.Write(t, "mtslink/requests_gateway.json", zzGenerator,
		[]string{
			"internal/auth/mtslink/api.go:142-182 (call.do: the headers the code sets)",
			"internal/auth/mtslink/mtslink.go:57-115 (Issue: the calls and their order)",
			"internal/auth/mtslink/mtslink_test.go:26-146 (the gateway fake and the service's replies)",
			"internal/protect/protect.go:93-113 (the HTTP client)",
		},
		struct {
			Note   string            `json:"note"`
			Masked map[string]string `json:"masked"`
			Flows  []zzFlow          `json:"flows"`
		}{
			"Every request of Provider.Issue as Go's net/http wrote it on a plain-HTTP loopback connection, " +
				"read by a TCP listener in front of the gateway fake: header lines in wire order, HTTP/1.1. " +
				"Over TLS the client offers h2 too, and h2 keeps no header order between requests; that wire is not here.",
			map[string]string{
				"<gateway>": "the listener's host:port (the Host header, and Extra's gateway behind http://)",
				"<did>":     "sixteen lower-case hex digits, random on every Issue",
				"<pid>":     "<did> turned left by one digit",
			},
			flows,
		})
}

func TestZZVectors(t *testing.T) {
	zzParseEventLink(t)
	zzIDsAndHosts(t)
	zzRoomJoinURL(t)
	zzForms(t)
	zzCookies(t)
	zzRequests(t)
}

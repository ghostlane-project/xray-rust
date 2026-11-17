//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork) of the
// VK Calls auth provider. An overlay file: regen.sh copies it into a clean
// checkout of the pin. It runs the provider against servers on loopback that
// answer with the bodies of the provider's own tests (vkcalls_test.go);
// nothing here reaches the service.

package vkcalls

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

const zzGenerator = "internal/auth/vkcalls/zz_vectors_test.go"

// zzRoom is the room the cases join: a link of the provider's own test's
// shape (vkcalls_test.go, testRoom) with an id that names no call. The
// engine's test carries an id and a participant that read like a capture;
// the vectors are published with this fork and carry made-up ones of the
// same lengths and alphabets instead (the join id here; the user id and the
// peer id in zzAPIAnswer and zzFBAnswer).
const zzRoom = "https://vk.ru/call/join/0FakeCallLinkForVectors012"

// zzAPIAnswer and zzFBAnswer are the provider's own test answers
// (vkcalls_test.go, defaultAPIAnswer and defaultFBAnswer) field for field,
// with the made-up participant and peer in place of the test's.
func zzAPIAnswer(method string) any {
	switch method {
	case "auth.getAnonymToken":
		return map[string]any{"response": map[string]any{"token": "anon-token", "expired_at": 1790619997}}
	case "messages.getCallPreview":
		return map[string]any{"response": map[string]any{"user_id": 100200300400, "secret": "s3cret"}}
	case "messages.getAnonymCallToken":
		return map[string]any{"response": map[string]any{"token": "sdk-anon-token"}}
	}
	return map[string]any{"error": map[string]any{"error_code": 10, "error_msg": "internal"}}
}

func zzFBAnswer(method string) any {
	switch method {
	case "auth.anonymLogin":
		return map[string]any{"session_key": "sk", "session_secret_key": "ssk", "api_server": "https://calls.okcdn.ru"}
	case "vchat.joinConversationByLink":
		return map[string]any{
			"endpoint":      "wss://videowebrtc.okcdn.ru/ws2?conversationId=c&peerId=10020030040&token=join-token&userId=100200300400&entityType=USER",
			"wt_endpoint":   "wss://videowebrtc.okcdn.ru/wt",
			"token":         "join-token",
			"id":            "call-id",
			"device_idx":    7,
			"client_type":   "VK",
			"p2p_forbidden": false,
			"stun_server":   map[string]any{"urls": "stun:stun.example:3478"},
			"turn_server":   map[string]any{"urls": []string{"turn:91.231.135.155:19302", "turn:91.231.135.179:19302"}, "username": "u", "credential": "c"},
		}
	}
	return map[string]any{"error": map[string]any{"error_code": 10, "error_msg": "internal"}}
}

// zzReply is one answer of a server: a status and a body as written.
type zzReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// zzVK is the two servers of the guest chain. A method named in replies is
// answered with that reply, any other with the provider's own test answer
// (zzAPIAnswer, zzFBAnswer).
type zzVK struct {
	api, fb *httptest.Server

	mu      sync.Mutex
	steps   []string
	replies map[string]zzReply
}

func zzNewVK(t *testing.T, replies map[string]zzReply) *zzVK {
	t.Helper()
	v := &zzVK{replies: replies}
	answer := func(w http.ResponseWriter, method string, fallback any) {
		v.mu.Lock()
		v.steps = append(v.steps, method)
		reply, ok := v.replies[method]
		v.mu.Unlock()
		if !ok {
			body, err := json.Marshal(fallback)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			reply = zzReply{http.StatusOK, string(body)}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.Status)
		_, _ = w.Write([]byte(reply.Body))
	}
	v.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := strings.TrimPrefix(r.URL.Path, "/method/")
		answer(w, method, zzAPIAnswer(method))
	}))
	v.fb = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		method := r.Form.Get("method")
		answer(w, method, zzFBAnswer(method))
	}))
	t.Cleanup(v.api.Close)
	t.Cleanup(v.fb.Close)
	return v
}

func (v *zzVK) provider() Provider { return Provider{APIBase: v.api.URL, FBBase: v.fb.URL} }

func (v *zzVK) taken() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := append([]string{}, v.steps...)
	v.steps = nil
	return out
}

var zzErrors = map[string]error{
	"ErrRoomURLRequired":   ErrRoomURLRequired,
	"ErrTokenUnsupported":  ErrTokenUnsupported,
	"ErrInvalidEndpoint":   ErrInvalidEndpoint,
	"ErrEndpointUserInfo":  ErrEndpointUserInfo,
	"ErrEndpointToken":     ErrEndpointToken,
	"ErrMissingClientType": ErrMissingClientType,
	"ErrInvalidDeviceIdx":  ErrInvalidDeviceIdx,
	"ErrInvalidRoomURL":    ErrInvalidRoomURL,
	"ErrRoomURLShape":      ErrRoomURLShape,
	"ErrRoomURLExtra":      ErrRoomURLExtra,
	"ErrICEServers":        ErrICEServers,
}

// zzFailure is an error of the provider: Is names a sentinel error, API is
// set for a GuestAPIError, neither for an error that is only a text (an HTTP
// status other than 200).
type zzFailure struct {
	// Text is null when the error text is not UTF-8 (a body cut inside a
	// letter); TextHex is the text's bytes then.
	Text    *string   `json:"text"`
	TextHex string    `json:"text_hex,omitempty"`
	Is      string    `json:"is,omitempty"`
	API     *zzAPIErr `json:"api,omitempty"`
}

type zzAPIErr struct {
	Stage string `json:"stage"`
	Code  int    `json:"code"`
	Kind  string `json:"kind"`
}

func zzFailureOf(err error) *zzFailure {
	out := &zzFailure{}
	if text := err.Error(); utf8.ValidString(text) {
		out.Text = &text
	} else {
		out.TextHex = hex.EncodeToString([]byte(text))
	}
	names := make([]string, 0, len(zzErrors))
	for name := range zzErrors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if errors.Is(err, zzErrors[name]) {
			out.Is = name
		}
	}
	var api *GuestAPIError
	if errors.As(err, &api) {
		out.API = &zzAPIErr{api.Stage, api.Code, api.Kind}
	}
	return out
}

type zzCredentials struct {
	URL   string            `json:"url"`
	Token string            `json:"token"`
	Extra map[string]string `json:"extra"`
}

func zzCredentialsOf(c auth.Credentials) *zzCredentials {
	return &zzCredentials{c.URL, c.Token, c.Extra}
}

type zzLinkCase struct {
	Name string `json:"name"`
	Link string `json:"link"`
	// Canonical is the link the chain is run with; JoinLink the id the join
	// step is given (linkID of it).
	Canonical string     `json:"canonical"`
	JoinLink  string     `json:"join_link"`
	Error     *zzFailure `json:"error,omitempty"`
}

func zzCanonicalLink(t *testing.T) []zzLinkCase {
	t.Helper()
	cases := []zzLinkCase{
		{Name: "the test's room", Link: zzRoom},
		{Name: "vk.com", Link: "https://vk.com/call/join/0FakeCallLinkForVectors012"},
		{Name: "a trailing slash", Link: zzRoom + "/"},
		{Name: "spaces and a line end around it", Link: "  " + zzRoom + "\r\n"},
		{Name: "an upper-case scheme is lowered", Link: "HTTPS://vk.ru/call/join/abc"},
		{Name: "an empty query and an empty fragment are no query and no fragment", Link: "https://vk.ru/call/join/abc?#"},
		{Name: "an id written with an escape comes back unescaped", Link: "https://vk.ru/call/join/a%41b"},
		{Name: "an id with a space inside", Link: "https://vk.ru/call/join/a b"},
		{Name: "an id that is not ASCII", Link: "https://vk.ru/call/join/комната"},
		{Name: "two slashes ahead of the path", Link: "https://vk.ru//call/join/abc"},
		{Name: "a question mark with nothing behind it", Link: "https://vk.ru/call/join/abc?"},
		{Name: "spaces that are not ASCII around it", Link: "\u00a0" + zzRoom + "\u2003"},
		// Refused: the six of TestIssueValidations, then more.
		{Name: "another host", Link: "https://evil.example/call/join/x"},
		{Name: "a segment behind the id", Link: "https://vk.ru/call/join/x/extra"},
		{Name: "userinfo", Link: "https://user@vk.ru/call/join/x"},
		{Name: "a port", Link: "https://vk.ru:8443/call/join/x"},
		{Name: "a query", Link: "https://vk.ru/call/join/x?token=1"},
		{Name: "another path", Link: "https://vk.ru/other/path"},
		{Name: "a fragment", Link: "https://vk.ru/call/join/x#frag"},
		{Name: "http", Link: "http://vk.ru/call/join/x"},
		{Name: "no scheme", Link: "vk.ru/call/join/x"},
		{Name: "a host in upper case", Link: "https://VK.RU/call/join/x"},
		{Name: "a host under vk.ru", Link: "https://www.vk.ru/call/join/x"},
		{Name: "vk.me", Link: "https://vk.me/call/join/x"},
		{Name: "no id", Link: "https://vk.ru/call/join/"},
		{Name: "no path", Link: "https://vk.ru"},
		{Name: "an empty segment inside", Link: "https://vk.ru/call//join/x"},
		{Name: "Call in another case", Link: "https://vk.ru/Call/join/x"},
		{Name: "a slash written as an escape", Link: "https://vk.ru/call/join/a%2Fb"},
		{Name: "userinfo is said before another path", Link: "https://user@vk.ru/other"},
		{Name: "another host is said before a port", Link: "https://evil.example:8443/call/join/x"},
		{Name: "a bad escape", Link: "https://vk.ru/call/join/x%zz"},
		{Name: "a control byte", Link: "https://vk.ru/call/join/x\x7f"},
		{Name: "empty", Link: ""},
		{Name: "spaces alone", Link: "  "},
		{Name: "an at sign with no user before it", Link: "https://@vk.ru/call/join/x"},
		{Name: "no slashes behind the scheme", Link: "https:vk.ru/call/join/x"},
		{Name: "an escape in the host", Link: "https://vk%2Eru/call/join/x"},
		{Name: "a bad escape in the fragment", Link: "https://vk.ru/call/join/x#%zz"},
		{Name: "a control byte in the fragment", Link: "https://vk.ru/call/join/x#\x7f"},
		{Name: "a host in brackets", Link: "https://[::1]/call/join/x"},
	}
	for i := range cases {
		c := &cases[i]
		link, err := canonicalLink(c.Link)
		if err != nil {
			c.Error = zzFailureOf(err)
			if c.Error.Is == "" {
				t.Fatalf("%s: %v is no error of the link", c.Name, err)
			}
			continue
		}
		c.Canonical, c.JoinLink = link, linkID(link)
	}
	return cases
}

type zzJoinCase struct {
	Name string `json:"name"`
	// Join is the body the join step is answered with.
	Join        string         `json:"join"`
	Credentials *zzCredentials `json:"credentials,omitempty"`
	Error       *zzFailure     `json:"error,omitempty"`
}

func zzJoins(t *testing.T) []zzJoinCase {
	t.Helper()
	endpoint := "wss://videowebrtc.okcdn.ru/ws2?conversationId=c&peerId=10020030040&token=join-token&userId=100200300400&entityType=USER"
	// join writes a join answer: the test's own, with the fields of set
	// replaced (a nil value takes the field out).
	join := func(set map[string]any) string {
		fields := map[string]any{
			"endpoint": endpoint, "wt_endpoint": "wss://videowebrtc.okcdn.ru/wt", "token": "join-token", "id": "call-id",
			"device_idx": 7, "client_type": "VK", "p2p_forbidden": false,
			"stun_server": map[string]any{"urls": "stun:stun.example:3478"},
			"turn_server": map[string]any{"urls": []string{"turn:91.231.135.155:19302", "turn:91.231.135.179:19302"}, "username": "u", "credential": "c"},
		}
		for key, value := range set {
			if value == nil {
				delete(fields, key)
			} else {
				fields[key] = value
			}
		}
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	raw := func(text string) json.RawMessage { return json.RawMessage(text) }
	own, err := json.Marshal(zzFBAnswer(stageJoin))
	if err != nil {
		t.Fatal(err)
	}
	cases := []zzJoinCase{
		{Name: "the test's own answer", Join: string(own)},
		// ICE servers.
		{Name: "no STUN server", Join: join(map[string]any{"stun_server": nil})},
		{Name: "no TURN server", Join: join(map[string]any{"turn_server": nil})},
		{Name: "neither", Join: join(map[string]any{"stun_server": nil, "turn_server": nil})},
		{Name: "both null", Join: join(map[string]any{"stun_server": raw("null"), "turn_server": raw("null")})},
		{Name: "STUN urls as a list, TURN urls as one string", Join: join(map[string]any{
			"stun_server": map[string]any{"urls": []string{"stun:a.example:3478", "stun:b.example:3478"}},
			"turn_server": map[string]any{"urls": "turn:t.example:3478", "username": "u", "credential": "c"}})},
		{Name: "urls that are empty or no strings are left out", Join: join(map[string]any{
			"stun_server": map[string]any{"urls": raw(`["", 5, null, "stun:a.example:3478", {"x":1}]`)},
			"turn_server": map[string]any{"urls": raw(`[""]`), "username": "u", "credential": "c"}})},
		{Name: "an empty STUN url string is kept", Join: join(map[string]any{"stun_server": map[string]any{"urls": ""}})},
		{Name: "a STUN server with a user name: only its urls are taken", Join: join(map[string]any{
			"stun_server": map[string]any{"urls": "stun:a.example", "username": "x", "credential": "y"}})},
		{Name: "a TURN server with no user name: its credential is left out", Join: join(map[string]any{
			"turn_server": map[string]any{"urls": "turn:t.example:3478", "credential": "c"}})},
		{Name: "a TURN server with a user name and no credential", Join: join(map[string]any{
			"turn_server": map[string]any{"urls": "turn:t.example:3478", "username": "u"}})},
		{Name: "a TURN server with a user name and no urls", Join: join(map[string]any{
			"turn_server": map[string]any{"username": "u", "credential": "c"}})},
		{Name: "an empty TURN server is no server", Join: join(map[string]any{"turn_server": map[string]any{}})},
		{Name: "servers that are no objects are no servers", Join: join(map[string]any{"stun_server": "stun:a.example", "turn_server": raw(`["turn:t.example"]`)})},
		{Name: "a user name that is no string is no user name", Join: join(map[string]any{
			"turn_server": map[string]any{"urls": "turn:t.example:3478", "username": 5, "credential": "c"}})},
		{Name: "what Go's JSON escapes in a url", Join: join(map[string]any{
			"turn_server": map[string]any{"urls": "turn:t.example:3478?transport=tcp&x=<1>", "username": "u&v", "credential": "c\"d\\e é\u2028"}})},
		// device_idx.
		{Name: "device_idx as a string", Join: join(map[string]any{"device_idx": "12"})},
		{Name: "device_idx absent", Join: join(map[string]any{"device_idx": nil})},
		{Name: "device_idx null", Join: join(map[string]any{"device_idx": raw("null")})},
		{Name: "device_idx an empty string", Join: join(map[string]any{"device_idx": ""})},
		{Name: "device_idx zero", Join: join(map[string]any{"device_idx": 0})},
		{Name: "device_idx with leading zeros is kept as written", Join: join(map[string]any{"device_idx": "007"})},
		{Name: "device_idx of twenty digits is kept as written", Join: join(map[string]any{"device_idx": raw("12345678901234567890")})},
		{Name: "device_idx negative", Join: join(map[string]any{"device_idx": -1})},
		{Name: "device_idx with a fraction", Join: join(map[string]any{"device_idx": raw("7.0")})},
		{Name: "device_idx with an exponent", Join: join(map[string]any{"device_idx": raw("1e3")})},
		{Name: "device_idx a string that is no number", Join: join(map[string]any{"device_idx": "x7"})},
		{Name: "device_idx true", Join: join(map[string]any{"device_idx": true})},
		{Name: "device_idx a list", Join: join(map[string]any{"device_idx": []int{7}})},
		// client_type and p2p_forbidden.
		{Name: "another client type is passed on", Join: join(map[string]any{"client_type": "OK"})},
		{Name: "no client type", Join: join(map[string]any{"client_type": nil})},
		{Name: "an empty client type", Join: join(map[string]any{"client_type": ""})},
		{Name: "p2p_forbidden true", Join: join(map[string]any{"p2p_forbidden": true})},
		{Name: "p2p_forbidden absent is true", Join: join(map[string]any{"p2p_forbidden": nil})},
		{Name: "p2p_forbidden null is true", Join: join(map[string]any{"p2p_forbidden": raw("null")})},
		{Name: "p2p_forbidden that is no boolean", Join: join(map[string]any{"p2p_forbidden": "false"})},
		// The endpoint and the token.
		{Name: "an endpoint with no peerId: no hint", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru/ws2?conversationId=c&token=join-token&userId=100200300400"})},
		{Name: "an endpoint with no token of its own", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru/ws2?userId=100200300400"})},
		{Name: "an endpoint with an empty token of its own", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru/ws2?token=&userId=1"})},
		{Name: "an endpoint with no query", Join: join(map[string]any{"endpoint": "wss://a.b.okcdn.ru/ws2"})},
		{Name: "the endpoint's token differs", Join: join(map[string]any{"token": "different-token"})},
		{Name: "of two tokens in the endpoint the first is compared", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru/ws2?token=other&token=join-token"})},
		{Name: "no endpoint", Join: join(map[string]any{"endpoint": nil})},
		{Name: "no token", Join: join(map[string]any{"token": nil})},
		{Name: "an empty token", Join: join(map[string]any{"token": ""})},
		{Name: "an endpoint over ws", Join: join(map[string]any{"endpoint": "ws://videowebrtc.okcdn.ru/ws2?token=join-token"})},
		{Name: "an endpoint over https", Join: join(map[string]any{"endpoint": "https://videowebrtc.okcdn.ru/ws2?token=join-token"})},
		{Name: "an endpoint at another host", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru.example/ws2?token=join-token"})},
		{Name: "an endpoint at okcdn.ru itself", Join: join(map[string]any{"endpoint": "wss://okcdn.ru/ws2?token=join-token"})},
		{Name: "an endpoint at a host in upper case", Join: join(map[string]any{"endpoint": "wss://VIDEOWEBRTC.OKCDN.RU/ws2?token=join-token"})},
		{Name: "an endpoint with a port", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru:443/ws2?token=join-token"})},
		{Name: "an endpoint with userinfo", Join: join(map[string]any{"endpoint": "wss://u@videowebrtc.okcdn.ru/ws2?token=join-token"})},
		{Name: "an endpoint that is no URL", Join: join(map[string]any{"endpoint": "wss://videowebrtc.okcdn.ru/ws2\x7f"})},
		{Name: "a wrong endpoint is said before a missing client type", Join: join(map[string]any{"endpoint": "https://x.example/", "client_type": nil})},
		{Name: "a missing client type is said before a wrong device_idx", Join: join(map[string]any{"client_type": nil, "device_idx": -1})},
		// The answer as a whole.
		{Name: "an error answer", Join: `{"error":{"error_code":1004,"error_msg":"call.not.found"}}`},
		{Name: "an error answer with no code", Join: `{"error":{"error_msg":"no code"}}`},
		{Name: "an empty object", Join: `{}`},
		{Name: "a list", Join: `[]`},
		{Name: "not JSON", Join: `<html>`},
		{Name: "an endpoint that is no string", Join: join(map[string]any{"endpoint": 5})},
	}
	for i := range cases {
		c := &cases[i]
		vk := zzNewVK(t, map[string]zzReply{stageJoin: {http.StatusOK, c.Join}})
		creds, err := vk.provider().Issue(context.Background(), auth.Config{RoomURL: zzRoom, Name: "Test"})
		if steps := vk.taken(); len(steps) != 5 || steps[4] != stageJoin {
			t.Fatalf("%s: the chain was %v", c.Name, steps)
		}
		if err != nil {
			c.Error = zzFailureOf(err)
			continue
		}
		c.Credentials = zzCredentialsOf(creds)
	}
	return cases
}

type zzIssueCase struct {
	Name string `json:"name"`
	// Link, Nickname and Token are auth.Config's RoomURL, Name and Token.
	Link     string `json:"link"`
	Nickname string `json:"nickname"`
	Token    string `json:"token"`
	// Replies are the answers that differ from the test's own, by method.
	Replies map[string]zzReply `json:"replies"`
	// Steps are the methods asked, in order.
	Steps       []string       `json:"steps"`
	Credentials *zzCredentials `json:"credentials,omitempty"`
	Error       *zzFailure     `json:"error,omitempty"`
}

func zzIssues(t *testing.T) []zzIssueCase {
	t.Helper()
	ok := func(body string) zzReply { return zzReply{http.StatusOK, body} }
	one := func(method string, reply zzReply) map[string]zzReply { return map[string]zzReply{method: reply} }
	cases := []zzIssueCase{
		{Name: "TestIssueHappyPath", Link: zzRoom, Nickname: "Test"},
		{Name: "no nickname", Link: zzRoom},
		{Name: "a vk.com link with a trailing slash", Link: "https://vk.com/call/join/abc/", Nickname: "Мария"},
		// Refused before any request.
		{Name: "no room link", Nickname: "Test"},
		{Name: "an account token", Link: zzRoom, Token: "acc"},
		{Name: "no room link is said before an account token", Token: "acc"},
		{Name: "a link of another shape", Link: "https://vk.ru/other/path"},
		// Step 1.
		{Name: "step 1: an error answer (TestIssueAPIErrors' shape)", Link: zzRoom,
			Replies: one(stageAnonToken, ok(`{"error":{"error_code":14,"error_msg":"Captcha needed"}}`))},
		{Name: "step 1: no token", Link: zzRoom, Replies: one(stageAnonToken, ok(`{"response":{"expired_at":1}}`))},
		{Name: "step 1: not JSON", Link: zzRoom, Replies: one(stageAnonToken, ok(`<html>`))},
		{Name: "step 1: a JSON string", Link: zzRoom, Replies: one(stageAnonToken, ok(`"<html>"`))},
		{Name: "step 1: a token that is no string", Link: zzRoom, Replies: one(stageAnonToken, ok(`{"response":{"token":5}}`))},
		{Name: "step 1: status 500, its body's line ends made spaces", Link: zzRoom,
			Replies: one(stageAnonToken, zzReply{http.StatusInternalServerError, "upstream\r\nfailed\n"})},
		{Name: "step 1: status 403 with a long body, cut to 200 bytes", Link: zzRoom,
			Replies: one(stageAnonToken, zzReply{http.StatusForbidden, strings.Repeat("0123456789", 30)})},
		{Name: "step 1: status 502 with a body cut inside a letter", Link: zzRoom,
			Replies: one(stageAnonToken, zzReply{http.StatusBadGateway, strings.Repeat("x", 199) + "é tail"})},
		{Name: "step 1: status 201 is no success", Link: zzRoom,
			Replies: one(stageAnonToken, zzReply{http.StatusCreated, `{"response":{"token":"t"}}`})},
		// Step 2.
		{Name: "step 2: a captcha (TestIssueAPIErrors)", Link: zzRoom,
			Replies: one(stagePreview, ok(`{"error":{"error_code":14,"error_msg":"Captcha needed"}}`))},
		{Name: "step 2: no secret", Link: zzRoom, Replies: one(stagePreview, ok(`{"response":{"user_id":5}}`))},
		{Name: "step 2: no user id", Link: zzRoom, Replies: one(stagePreview, ok(`{"response":{"secret":"s"}}`))},
		{Name: "step 2: a negative user id is taken", Link: zzRoom, Replies: one(stagePreview, ok(`{"response":{"user_id":-5,"secret":"s"}}`))},
		{Name: "step 2: a user id with a fraction", Link: zzRoom, Replies: one(stagePreview, ok(`{"response":{"user_id":5.5,"secret":"s"}}`))},
		{Name: "step 2: a user id as a string of digits is taken", Link: zzRoom, Replies: one(stagePreview, ok(`{"response":{"user_id":"77","secret":"s"}}`))},
		{Name: "step 2: a user id as a string that is no number", Link: zzRoom, Replies: one(stagePreview, ok(`{"response":{"user_id":"abc","secret":"s"}}`))},
		// Step 3.
		{Name: "step 3: no token", Link: zzRoom, Replies: one(stageCallToken, ok(`{"response":{}}`))},
		{Name: "step 3: an error answer", Link: zzRoom, Replies: one(stageCallToken, ok(`{"error":{"error_code":5,"error_msg":"anonym_token.expired"}}`))},
		// Step 4.
		{Name: "step 4: no session key", Link: zzRoom, Replies: one(stageLogin, ok(`{"session_secret_key":"ssk"}`))},
		{Name: "step 4: an error answer", Link: zzRoom, Replies: one(stageLogin, ok(`{"error":{"error_code":10,"error_msg":"internal"}}`))},
		{Name: "step 4: status 500", Link: zzRoom, Replies: one(stageLogin, zzReply{http.StatusInternalServerError, ""})},
	}
	for i := range cases {
		c := &cases[i]
		if c.Replies == nil {
			c.Replies = map[string]zzReply{}
		}
		vk := zzNewVK(t, c.Replies)
		creds, err := vk.provider().Issue(context.Background(), auth.Config{RoomURL: c.Link, Name: c.Nickname, Token: c.Token})
		c.Steps = vk.taken()
		if err != nil {
			c.Error = zzFailureOf(err)
			continue
		}
		c.Credentials = zzCredentialsOf(creds)
	}
	return cases
}

func zzURLAuth(t *testing.T) {
	t.Helper()
	zzvectors.Write(t, "vkcalls/url_auth.json", zzGenerator,
		[]string{
			"internal/auth/vkcalls/vkcalls.go:515-536 (canonicalLink, linkID)",
			"internal/auth/vkcalls/vkcalls.go:387-431 (credentialsFromJoin), 433-513 (iceServersJSON, urlsOf, credsOf, decimalOf)",
			"internal/auth/vkcalls/vkcalls.go:125-256 (Issue, sdkLogin), 338-385 (raw, decodeAPI), 550-562 (redact)",
			"internal/auth/vkcalls/vkcalls_test.go:75-219 (the answers of the provider's tests; TestIssueHappyPath, TestIssueValidations, TestIssueAPIErrors)",
		},
		struct {
			Note          string        `json:"note"`
			Room          string        `json:"room"`
			CanonicalLink []zzLinkCase  `json:"canonical_link"`
			Joins         []zzJoinCase  `json:"credentials_from_join"`
			Issue         []zzIssueCase `json:"issue"`
		}{
			"canonical_link: the room link as the chain uses it. credentials_from_join: Provider.Issue for room " +
				"with the nickname Test against the answers of the provider's tests, the join step answered with " +
				"join; the credentials' participant_id is the user id of step 2 (100200300400) and ice_servers is " +
				"JSON text as Go's encoding/json writes it (keys in byte order; <, > and & escaped). issue: " +
				"Provider.Issue with the answers named in replies; an error is the engine's error by its Go name " +
				"(is), a GuestAPIError's fields (api), or only its text.",
			zzRoom, zzCanonicalLink(t), zzJoins(t), zzIssues(t),
		})
}

var (
	zzSDKDevice = regexp.MustCompile(`olcrtc-sdk-[0-9a-f]{32}`)
	zzDevice    = regexp.MustCompile(`olcrtc-[0-9a-f]{32}`)
	zzGuest     = regexp.MustCompile(`guest-[0-9a-f]{8}`)
)

type zzFlow struct {
	Flow     string `json:"flow"`
	Link     string `json:"link"`
	Nickname string `json:"nickname"`
	// Steps are the methods asked, in order; Requests the same calls as
	// they were written.
	Steps       []string               `json:"steps"`
	Credentials *zzCredentials         `json:"credentials"`
	Requests    []zzvectors.WireRecord `json:"requests"`
}

func zzRequests(t *testing.T) {
	t.Helper()
	flows := []zzFlow{
		{Flow: "issue", Link: zzRoom, Nickname: "Мария Ковалёва"},
		{Flow: "issue_no_nickname", Link: "https://vk.com/call/join/abc-DEF_123/"},
	}
	for i := range flows {
		f := &flows[i]
		vk := zzNewVK(t, nil)
		api, fb := zzvectors.NewWire(t, vk.api.URL), zzvectors.NewWire(t, vk.fb.URL)
		creds, err := Provider{APIBase: api.URL(), FBBase: fb.URL()}.Issue(context.Background(),
			auth.Config{RoomURL: f.Link, Name: f.Nickname})
		if err != nil {
			t.Fatalf("%s: %v", f.Flow, err)
		}
		f.Steps, f.Credentials = vk.taken(), zzCredentialsOf(creds)
		apiReqs, fbReqs := api.Take(), fb.Take()
		if len(apiReqs) != 3 || len(fbReqs) != 2 || len(f.Steps) != 5 {
			t.Fatalf("%s: %d and %d requests, steps %v", f.Flow, len(apiReqs), len(fbReqs), f.Steps)
		}
		// One device id for the three API calls, another kind for the SDK
		// login, a guest name of eight hex digits when none was given.
		devices := map[string]bool{}
		for _, r := range apiReqs {
			found := zzDevice.FindAllString(string(r.Body), -1)
			if len(found) != 1 || zzSDKDevice.MatchString(string(r.Body)) {
				t.Fatalf("%s: device ids of %s: %v", f.Flow, r.Target(), found)
			}
			devices[found[0]] = true
		}
		if len(devices) != 1 {
			t.Fatalf("%s: the API calls carried %d device ids", f.Flow, len(devices))
		}
		if len(zzSDKDevice.FindAllString(string(fbReqs[0].Body), -1)) != 1 || zzDevice.MatchString(string(fbReqs[1].Body)) {
			t.Fatalf("%s: the SDK login's device id", f.Flow)
		}
		guests := 0
		for _, r := range apiReqs {
			guests += len(zzGuest.FindAllString(string(r.Body), -1))
		}
		if want := map[bool]int{true: 2, false: 0}[f.Nickname == ""]; guests != want {
			t.Fatalf("%s: %d guest names in the API calls, want %d", f.Flow, guests, want)
		}
		mask := func(s string) string {
			s = strings.NewReplacer(api.Host(), "<api>", fb.Host(), "<fb>").Replace(s)
			s = zzSDKDevice.ReplaceAllString(s, "olcrtc-sdk-<hex32>")
			s = zzDevice.ReplaceAllString(s, "olcrtc-<hex32>")
			return zzGuest.ReplaceAllString(s, "guest-<hex8>")
		}
		f.Requests = zzvectors.Number(append(
			zzvectors.WireRecords(f.Flow, "api", apiReqs, mask),
			zzvectors.WireRecords(f.Flow, "fb", fbReqs, mask)...))
		for _, r := range f.Requests {
			if r.Proto != "HTTP/1.1" || r.Method != http.MethodPost {
				t.Fatalf("%s: %s %s over %s", f.Flow, r.Method, r.Target, r.Proto)
			}
		}
	}
	zzvectors.Write(t, "vkcalls/requests_auth.json", zzGenerator,
		[]string{
			"internal/auth/vkcalls/vkcalls.go:125-232 (Issue: the five calls, their order and fields), 234-256 (sdkLogin)",
			"internal/auth/vkcalls/vkcalls.go:312-364 (vkCall, fbCall, raw: the fields added to every call, the one header the code sets)",
			"internal/auth/vkcalls/vkcalls_test.go:75-105 (the answers)",
			"internal/protect/protect.go (the HTTP client)",
		},
		struct {
			Note   string            `json:"note"`
			Masked map[string]string `json:"masked"`
			Flows  []zzFlow          `json:"flows"`
		}{
			"Every request of Provider.Issue as Go's net/http wrote it on a plain-HTTP loopback connection, read " +
				"by a TCP listener in front of each server: header lines in wire order, the form body with its " +
				"keys in byte order, HTTP/1.1. The three API calls come first, then the two SDK calls. Over TLS " +
				"the client offers h2 too; that wire is not here.",
			map[string]string{
				"<api>":              "the API listener's host:port",
				"<fb>":               "the SDK listener's host:port",
				"olcrtc-<hex32>":     "the device id of the three API calls: olcrtc- and 32 lower-case hex digits, random on every Issue, one for the three",
				"olcrtc-sdk-<hex32>": "the device id inside session_data: olcrtc-sdk- and 32 lower-case hex digits, random on every Issue",
				"guest-<hex8>":       "the name sent when the caller gave none: guest- and 8 lower-case hex digits, random on every Issue",
			},
			flows,
		})
}

func TestZZVectors(t *testing.T) {
	zzURLAuth(t)
	zzRequests(t)
}

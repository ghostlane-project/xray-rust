//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port's olc-net helpers (olc/interop in the
// xray-rust fork): the form encoding and the Set-Cookie reading the carriers'
// room providers get from Go's standard library. An overlay file: regen.sh
// copies it into a clean checkout of the pin. Nothing here opens a socket.

package zzvectors

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// zzPair is one form field as the caller added it. Both are hex: a Go string
// holds any bytes, and the escaping is defined on bytes.
type zzPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type zzFormCase struct {
	Name    string   `json:"name"`
	Pairs   []zzPair `json:"pairs"`
	Encoded string   `json:"encoded"`
}

type zzField struct{ k, v string }

func zzAllBytes() string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

func zzFormCases() []zzFormCase {
	all := zzAllBytes()
	in := []struct {
		name   string
		fields []zzField
	}{
		{"empty form", nil},
		// internal/auth/mtslink/api.go:211, with the nicknames a link can carry.
		{"mts guestlogin, the default nickname", []zzField{{"nickname", "olcrtc"}, {"name", ""}, {"secondName", ""}, {"phone", ""}}},
		{"mts guestlogin, an ASCII name", []zzField{{"nickname", "Alice"}, {"name", ""}, {"secondName", ""}, {"phone", ""}}},
		{"mts guestlogin, a Cyrillic name with a space", []zzField{{"nickname", "Иван Петров"}, {"name", ""}, {"secondName", ""}, {"phone", ""}}},
		{"mts guestlogin, a name of form syntax", []zzField{{"nickname", "a+b&c=d"}, {"name", ""}, {"secondName", ""}, {"phone", ""}}},
		{"mts guestlogin, tilde and star", []zzField{{"nickname", "~*"}, {"name", ""}, {"secondName", ""}, {"phone", ""}}},
		// internal/auth/mtslink/api.go:272.
		{"mts conferences", []zzField{{"hasAudio", "false"}, {"hasVideo", "true"}}},
		// internal/auth/vkcalls/vkcalls.go:321-344: a map of parameters, each set once.
		{"vk api call shape", []zzField{
			{"session_key", "-s1.AbC_d/e+f=="}, {"method", "vchat.joinConversationByLink"},
			{"format", "JSON"}, {"application_key", "CGMMEJLGDIHBABABA"},
			{"joinLink", "abc-DEF_123"}, {"isVideo", "false"}, {"protocolVersion", "5"},
			{"anonymToken", "$t0k:en!(1)*'2'"},
		}},
		{"vk json in a value", []zzField{{"session_data", `{"version":2,"device_id":"x","client_version":1.1,"client_type":"SDK_JS"}`}}},
		{"every byte in a value", []zzField{{"v", all}}},
		{"every byte in a key", []zzField{{all, "v"}}},
		{"the unreserved set", []zzField{{"u", "AZaz09-_.~"}}},
		{"the rest of ASCII punctuation", []zzField{{"p", " !\"#$%&'()*+,/:;<=>?@[\\]^`{|}"}}},
		{"a repeated key keeps its values in the order added", []zzField{{"k", "2"}, {"a", "x"}, {"k", "1"}, {"k", "3"}}},
		{"keys sort by their bytes, upper case first", []zzField{{"b", "1"}, {"B", "2"}, {"a", "3"}, {"_", "4"}, {"0", "5"}, {"~", "6"}}},
		{"keys sort before they are escaped", []zzField{{"a!b", "1"}, {"a b", "2"}, {"a+b", "3"}, {"a%b", "4"}}},
		{"a key that is a prefix of another", []zzField{{"ab", "1"}, {"a", "2"}, {"a=", "3"}, {"", "4"}}},
		{"an empty key and an empty value", []zzField{{"", ""}}},
		{"multi-byte keys", []zzField{{"я", "1"}, {"é", "2"}, {"z", "3"}, {"\xff", "4"}, {"\x00", "5"}}},
		{"a four-byte character and invalid UTF-8", []zzField{{"e", "😀"}, {"i", "\xc3\x28\xff"}}},
	}
	out := make([]zzFormCase, 0, len(in))
	for _, c := range in {
		form := url.Values{}
		pairs := make([]zzPair, 0, len(c.fields))
		for _, f := range c.fields {
			form.Add(f.k, f.v)
			pairs = append(pairs, zzPair{Key: Hex([]byte(f.k)), Value: Hex([]byte(f.v))})
		}
		out = append(out, zzFormCase{Name: c.name, Pairs: pairs, Encoded: form.Encode()})
	}
	return out
}

// zzRepeat stands for Count Set-Cookie lines "<Prefix><i>=<i>", i from 0,
// followed by Blank empty ones, instead of storing them.
type zzRepeat struct {
	Prefix string `json:"prefix"`
	Count  int    `json:"count"`
	Blank  int    `json:"blank"`
}

type zzCookieCase struct {
	Name string `json:"name"`
	// SetCookie holds the reply's Set-Cookie values in header order, in hex.
	SetCookie []string  `json:"set_cookie,omitempty"`
	Repeat    *zzRepeat `json:"repeat,omitempty"`
	// Pairs is what the room provider keeps (internal/auth/mtslink/api.go:175-180):
	// name=value of every cookie http.Response.Cookies returns whose name and
	// value are both non-empty.
	Pairs []string `json:"pairs,omitempty"`
	// PairCount and PairsSum stand for Pairs in a Repeat case.
	PairCount int    `json:"pair_count"`
	PairsSum  string `json:"pairs_sha256,omitempty"`
	// Header is Pairs joined as the provider joins them (api.go:235).
	Header string `json:"header,omitempty"`
}

func zzKept(lines []string) []string {
	resp := &http.Response{Header: http.Header{}}
	for _, l := range lines {
		resp.Header.Add("Set-Cookie", l)
	}
	set := []string{}
	for _, cookie := range resp.Cookies() {
		if cookie.Name != "" && cookie.Value != "" {
			set = append(set, cookie.Name+"="+cookie.Value)
		}
	}
	return set
}

func zzCookieCases() []zzCookieCase {
	in := []struct {
		name  string
		lines []string
	}{
		{"no Set-Cookie", nil},
		{"one plain cookie", []string{"sessionId=abc123"}},
		// internal/auth/mtslink/mtslink_test.go: the fake sets three at the login.
		{"three cookies in header order", []string{"sessionId=s-1; Path=/; HttpOnly", "userId=42; Path=/", "route=b; Path=/; Secure; SameSite=None"}},
		{"every attribute is dropped", []string{"a=b; Domain=.mts-link.ru; Path=/api; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=3600; HttpOnly; Secure; SameSite=Lax; Partitioned; Priority=High; x=y"}},
		{"a broken attribute does not drop the cookie", []string{"a=b; Max-Age=soon; Expires=never; SameSite=\"q\"; Path=\x01; \xff=1; =; ;;"}},
		{"an empty value is skipped", []string{"empty=", "kept=1"}},
		{"an empty quoted value is skipped", []string{"empty=\"\"", "kept=1"}},
		{"a quoted value loses its quotes", []string{"q=\"abc\""}},
		{"a quoted value with spaces and commas", []string{"q=\"a b, c\""}},
		{"one quote alone is refused", []string{"q=\"", "kept=1"}},
		{"a quote at one end only is refused", []string{"q=\"abc", "r=abc\"", "kept=1"}},
		{"a quote inside is refused", []string{"q=a\"b", "kept=1"}},
		{"quotes inside quotes are refused", []string{"q=\"a\"b\"", "kept=1"}},
		{"a duplicate name is kept twice", []string{"a=1", "a=2", "b=3", "a=1"}},
		{"no equals sign", []string{"novalue", "kept=1"}},
		{"an empty name", []string{"=value", "kept=1"}},
		{"a blank line", []string{"", "   ", "\t", "kept=1"}},
		{"only a separator", []string{";", "; Path=/", "kept=1"}},
		{"spaces around the pair", []string{"  a=b  ", "\tc=d\t; Path=/"}},
		{"spaces around the name", []string{" a =b", "c\t=d"}},
		{"a space inside the name is refused", []string{"a b=c", "kept=1"}},
		{"a space after the equals sign stays", []string{"a= b", "c=  d  ; Path=/"}},
		{"only spaces as a value", []string{"a=   ", "b= \t", "kept=1"}},
		{"a space inside the value stays", []string{"a=b c"}},
		{"an equals sign in the value stays", []string{"a=b=c", "t=YWJj==", "u==v"}},
		{"a comma in the value stays", []string{"a=b,c"}},
		{"a backslash is refused", []string{"a=b\\c", "kept=1"}},
		{"a control byte is refused", []string{"a=b\x01c", "b=x\ty", "c=\x7f", "kept=1"}},
		{"bytes outside ASCII are refused", []string{"a=\xd0\xb0", "b=caf\xe9", "\xd0\xb0=1", "kept=1"}},
		{"the token characters make a name", []string{"!#$%&'*+-.^_`|~09AZaz=1"}},
		{"what is not a token character is refused in a name", []string{"a(b=1", "a)b=1", "a,b=1", "a/b=1", "a:b=1", "a<b=1", "a>b=1", "a?b=1", "a@b=1", "a[b=1", "a]b=1", "a{b=1", "a}b=1", "a\"b=1", "a\\b=1", "kept=1"}},
		{"the value's printable set", []string{"v=!#$%&'()*+,-./0189:<=>?@AZ[]^_`az{|}~"}},
		{"the name keeps its case", []string{"SessionID=AbC", "sessionid=aBc"}},
		{"a long value", []string{"big=" + strings.Repeat("x", 4096)}},
		{"a line feed inside a line", []string{"a=b\nc=d", "e=f\r\ng=h", "kept=1"}},
	}
	out := make([]zzCookieCase, 0, len(in)+6)
	for _, c := range in {
		kept := zzKept(c.lines)
		lines := make([]string, 0, len(c.lines))
		for _, l := range c.lines {
			lines = append(lines, Hex([]byte(l)))
		}
		out = append(out, zzCookieCase{
			Name: c.name, SetCookie: lines, Pairs: kept, PairCount: len(kept), Header: strings.Join(kept, "; "),
		})
	}
	// How many Set-Cookie lines one reply may carry before Go returns none:
	// lines are counted, read or not.
	for _, r := range []zzRepeat{
		{Prefix: "c", Count: 1024}, {Prefix: "c", Count: 2999}, {Prefix: "c", Count: 3000},
		{Prefix: "c", Count: 3001}, {Prefix: "c", Count: 2999, Blank: 1}, {Prefix: "c", Count: 2999, Blank: 2},
	} {
		kept := zzKept(zzRepeatLines(r))
		out = append(out, zzCookieCase{
			Name: "many lines: " + itoa(r.Count) + " cookies and " + itoa(r.Blank) + " blank", Repeat: &r,
			PairCount: len(kept), PairsSum: Sum([]byte(strings.Join(kept, "; "))),
		})
	}
	return out
}

func zzRepeatLines(r zzRepeat) []string {
	lines := make([]string, 0, r.Count+r.Blank)
	for i := range r.Count {
		lines = append(lines, r.Prefix+itoa(i)+"="+itoa(i))
	}
	for range r.Blank {
		lines = append(lines, "")
	}
	return lines
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestZZVectors writes net/forms.json and net/cookies.json.
func TestZZVectors(t *testing.T) {
	Write(t, "net/forms.json", "internal/zzvectors/zz_net_vectors_test.go TestZZVectors",
		[]string{
			"net/url Values.Encode, as called at internal/auth/mtslink/api.go:144-146,211,272",
			"internal/auth/vkcalls/vkcalls.go:338-345",
		}, zzFormCases())
	Write(t, "net/cookies.json", "internal/zzvectors/zz_net_vectors_test.go TestZZVectors",
		[]string{
			"net/http Response.Cookies, as called at internal/auth/mtslink/api.go:175-180",
			"internal/auth/mtslink/api.go:235",
		}, zzCookieCases())
}

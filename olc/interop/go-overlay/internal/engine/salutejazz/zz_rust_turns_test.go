// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): T2(b) relay-only
// through TURN over TLS (`turns:`). The Rust client joins the fake SFU with
// iceTransportPolicy "relay" through a pion TURN server on a TLS listener
// with a certificate of this test's own (pion/turn/v5 takes any net.Listener,
// so tls.NewListener is a TLS TURN server). rtc:config lists the `turns:` URL
// only (zz_rust_relay_test.go's startTurnRelayWith, transport "tls").
//
// The shipped client trusts webpki-roots' roots and nothing else, so it is
// built twice: with the `turns-test-roots` feature (it also trusts the root
// OLC_TURNS_TEST_ROOT names: the "testroots" mode, where the relay must come
// up) and as shipped (the "shipped" mode, which must refuse the same server:
// the shipped client never reads the variable). OLCRTC_GATE_RUST_TURNS_ROOTS
// says which build OLCRTC_GATE_RUST_BIN is; without it these tests skip
// (fakeroom.sh turns-testroots | turns-shipped).

package salutejazz_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/salutejazz"
)

const (
	// turnsModeEnv says which client build the binary is: "testroots" or "shipped".
	turnsModeEnv = "OLCRTC_GATE_RUST_TURNS_ROOTS"
	// turnsRootEnv is the variable the testroots build reads.
	turnsRootEnv = "OLC_TURNS_TEST_ROOT"
)

// turnsOpts are the TLS relay's parameters: the host its `turns:` URL names
// and the certificate it serves.
type turnsOpts struct {
	host string
	cert tls.Certificate
}

// turnsHello is what a TLS relay's server read of the client's hello.
type turnsHello struct {
	serverName string
	protos     []string
	versions   []uint16
	curves     []tls.CurveID
	suites     []uint16
}

func (x *turnRelay) noteHello(h *tls.ClientHelloInfo) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.hellos = append(x.hellos, turnsHello{
		serverName: h.ServerName,
		protos:     slices.Clone(h.SupportedProtos),
		versions:   slices.Clone(h.SupportedVersions),
		curves:     slices.Clone(h.SupportedCurves),
		suites:     slices.Clone(h.CipherSuites),
	})
}

func (x *turnRelay) clientHellos() []turnsHello {
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.hellos)
}

// turnsPKI is a root and a server certificate under it.
type turnsPKI struct {
	rootPEM []byte
	cert    tls.Certificate
}

// newTurnsPKI makes a root CA and a server certificate for names (DNS names
// and IP literals), valid now, for server authentication.
func newTurnsPKI(t testing.TB, names ...string) turnsPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "olc turns test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			leafTpl.IPAddresses = append(leafTpl.IPAddresses, ip)
		} else {
			leafTpl.DNSNames = append(leafTpl.DNSNames, n)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return turnsPKI{
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		cert:    tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

// turnsMode is the client build under test, or a skip.
func turnsMode(t *testing.T) string {
	t.Helper()
	mode := os.Getenv(turnsModeEnv)
	if mode != "testroots" && mode != "shipped" {
		t.Skip(turnsModeEnv + " (testroots or shipped) is not set: fakeroom.sh turns-testroots | turns-shipped")
	}
	return mode
}

// trust points the client at pki's root through the environment; the
// testroots build reads it, the shipped one never does.
func (p turnsPKI) trust(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, p.rootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(turnsRootEnv, path)
}

// checkTurnsHello fails t unless the TLS relay's server read one hello with
// serverName, offering no ALPN (Chrome's TURN TLS offers none), TLS 1.3 and
// the post-quantum group first among the real ones. (The hello is held to
// Chrome 157's field by field by olc-rtc's tls_boring and turns tests.)
func checkTurnsHello(t *testing.T, x *turnRelay, serverName string) {
	t.Helper()
	hellos := x.clientHellos()
	if len(hellos) == 0 {
		t.Fatal("the TLS TURN server read no hello")
	}
	h := hellos[0]
	if h.serverName != serverName {
		t.Fatalf("the hello's server name is %q, want %q", h.serverName, serverName)
	}
	if len(h.protos) != 0 {
		t.Fatalf("the hello offers ALPN %q, Chrome's TURN TLS offers none", h.protos)
	}
	if !slices.Contains(h.versions, tls.VersionTLS13) {
		t.Fatalf("the hello's versions %x lack TLS 1.3", h.versions)
	}
	if !slices.Contains(h.curves, tls.X25519MLKEM768) {
		t.Fatalf("the hello's groups %v lack X25519MLKEM768", h.curves)
	}
	t.Logf("hello: sni %q, versions %x, groups %v, %d suites", h.serverName, h.versions, h.curves, len(h.suites))
}

// turnsJoin is the relay-only join through the TLS TURN server named by
// host, serving a certificate for names: a download and an upload move
// through it, and the server read a hello with wantSNI.
func turnsJoin(t *testing.T, host, wantSNI string, names ...string) {
	if turnsMode(t) != "testroots" {
		t.Skip("the relay comes up only in the testroots build")
	}
	pki := newTurnsPKI(t, names...)
	pki.trust(t)
	room := salutejazz.NewFakeRoom(t)
	relay := startTurnRelayWith(t, room.URL(), "tls", turnsOpts{host: host, cert: pki.cert})
	var tunnel *rustTunnel
	relay.checkClosedLines(t, &tunnel)
	tunnel = startRustTunnel(t, room, 0, 0, relay.useFor)
	down := startDownload(t, tunnel.socksAddr, startSource(t))
	up := startUpload(t, tunnel.socksAddr, startSink(t))
	const want = 4 << 20
	eventually(t, 60*time.Second, "4 MiB each way", func() bool { return down.moved() >= want && up.moved() >= want })
	for what, x := range map[string]*transfer{"download": down, "upload": up} {
		if bad := x.fault(); bad != nil {
			t.Fatalf("the %s: %v", what, bad)
		}
	}
	tunnel.checkStillUp(t)
	checkCapture(t, room)
	relay.check(t, want)
	if n := relay.accepted.Load(); n == 0 {
		t.Fatal("the TURN server accepted no TCP connection")
	} else {
		t.Logf("TURN over TLS: %d connections", n)
	}
	checkTurnsHello(t, relay, wantSNI)
	for _, line := range []string{iceConnectedLine, pcConnectedLine} {
		if !tunnel.client.logHas(line) {
			t.Fatalf("the client never said %q", line)
		}
	}
}

// TestRustTurnsJoinsThroughTurnOverTLS: a `turns:` URL naming a host, a
// certificate for that name under a trusted root: the client sends the name
// as SNI and the relay carries both transfers.
func TestRustTurnsJoinsThroughTurnOverTLS(t *testing.T) {
	turnsJoin(t, "localhost", "localhost", "localhost")
}

// TestRustTurnsJoinsThroughTurnOverTLSByAddress: the URL names an address;
// the certificate names it as an IP; the hello carries no SNI.
func TestRustTurnsJoinsThroughTurnOverTLSByAddress(t *testing.T) {
	turnsJoin(t, "127.0.0.1", "", "127.0.0.1")
}

// refusedTurns runs the relay-only client against a TLS TURN server that
// serves cert for host, with trust as the client's test root, and fails t if
// a relay comes up: the TURN server must allocate nothing, the client must
// trickle no relayed candidate, and it must say it refused the certificate.
func refusedTurns(t *testing.T, host string, cert tls.Certificate, trust turnsPKI) {
	t.Helper()
	trust.trust(t)
	room := salutejazz.NewFakeRoom(t)
	relay := startTurnRelayWith(t, room.URL(), "tls", turnsOpts{host: host, cert: cert})
	cfg := rustRoomConfig(room, tunnelKeyHex, 0, 0)
	relay.useFor(&cfg)
	proc := startRust(t, cfg, nil)
	select {
	case <-proc.listen:
	case <-proc.exited:
		t.Fatalf("the rust client ended before it listened: %v", proc.err)
	case <-time.After(30 * time.Second):
		t.Fatal("the rust client did not listen within 30 s")
	}
	// The client dials the TLS server and refuses its certificate; it keeps
	// the other (absent) relays going, so it stays up.
	eventually(t, 30*time.Second, "the client's attempt on the TLS TURN server", func() bool { return relay.accepted.Load() >= 1 })
	eventually(t, 20*time.Second, "the client's refusal of the certificate", func() bool {
		return proc.logHas("over TLS: certificate refused")
	})
	time.Sleep(5 * time.Second)
	if n := relay.allocations.Load(); n != 0 {
		t.Fatalf("the TURN server allocated %d times for a client that must have refused its certificate", n)
	}
	lines, _ := relay.clientCandidates()
	for _, l := range lines {
		if strings.Contains(l, " typ relay") {
			t.Fatalf("the client trickled a relayed candidate %q through a refused TLS TURN server", l)
		}
	}
	for _, line := range []string{iceConnectedLine, pcConnectedLine} {
		if proc.logHas(line) {
			t.Fatalf("the client reached %q through a refused TLS TURN server", line)
		}
	}
}

// TestRustTurnsRefusesACertificateNoTrustedRootSigned: the client trusts one
// root, the server's certificate is under another: no relay.
func TestRustTurnsRefusesACertificateNoTrustedRootSigned(t *testing.T) {
	turnsMode(t)
	trusted := newTurnsPKI(t, "localhost")
	served := newTurnsPKI(t, "localhost")
	refusedTurns(t, "localhost", served.cert, trusted)
}

// TestRustTurnsRefusesACertificateForAnotherName: the certificate is under
// the trusted root but names another host: no relay.
func TestRustTurnsRefusesACertificateForAnotherName(t *testing.T) {
	turnsMode(t)
	pki := newTurnsPKI(t, "elsewhere.example")
	refusedTurns(t, "localhost", pki.cert, pki)
}

// TestRustTurnsRefusesACertificateForAnotherAddress: the URL names 127.0.0.1,
// the certificate is under the trusted root and names another address.
func TestRustTurnsRefusesACertificateForAnotherAddress(t *testing.T) {
	turnsMode(t)
	pki := newTurnsPKI(t, "192.0.2.77")
	refusedTurns(t, "127.0.0.1", pki.cert, pki)
}

// TestRustTurnsShippedBuildIgnoresTheTestRoot: the shipped client, handed the
// test root through the environment, still refuses a server only that root
// signed: the variable is read by the turns-test-roots build alone.
func TestRustTurnsShippedBuildIgnoresTheTestRoot(t *testing.T) {
	if turnsMode(t) != "shipped" {
		t.Skip("the shipped build only")
	}
	pki := newTurnsPKI(t, "localhost")
	refusedTurns(t, "localhost", pki.cert, pki)
}

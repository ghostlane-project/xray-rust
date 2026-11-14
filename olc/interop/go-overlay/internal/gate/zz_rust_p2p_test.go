// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): the gate's p2p target
// (T2(a), port plan section 10.3). The server (this module's, built with the
// olcrtc_interop tag) joins a room of the in-process hub through the
// interop-p2p engine; the client joins the same room, and the two meet peer
// to peer: pion against pion (the cli flavour) or str0m (the rust flavour),
// a VP8 track each way, vp8channel and KCP end to end at the app's 60 fps
// and batch 64. TestGateP2P runs S0-S5 on that pair:
//
//	go test -tags olcrtc_interop ./internal/gate -run '^TestGateP2P$' \
//	    -olcrtc.gate-target=p2p [-olcrtc.gate-rust-bin=<olc-client>] \
//	    [-olcrtc.gate-flavours=rust,cli] [-olcrtc.gate-turn=udp|tcp|tls \
//	    -olcrtc.gate-turnserver=/usr/bin/turnserver]
//
// With -olcrtc.gate-turn the server is relay-only (policy=relay) through a
// coturn the test runs as its own child on 127.0.0.1, listening on that one
// transport alone; the clients keep their host candidates.

package gate

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/engine/interopp2p"
	"github.com/openlibrecommunity/olcrtc/internal/engine/interoppipe"
	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/client"
)

const (
	targetP2P   = "p2p"
	platformP2P = "p2p-linux"
	// p2pFPS and p2pBatch are the app's vp8channel numbers.
	p2pFPS   = 60
	p2pBatch = 64
	// turnUser and turnPass are coturn's one long-term credential.
	turnUser = "olc"
	turnPass = "olc-interop"
	// turnReadyBudget bounds coturn's start.
	turnReadyBudget = 15 * time.Second
	// turnProbeWait bounds one readiness probe of coturn's listener.
	turnProbeWait = 200 * time.Millisecond
)

var (
	gateTurn = flag.String("olcrtc.gate-turn", "none",
		"the p2p target's TURN: none, or the server relay-only through coturn over udp, tcp or tls")
	gateTurnServer = flag.String("olcrtc.gate-turnserver", "turnserver", "coturn's turnserver binary")
)

// P2PTarget is the server in a room of the hub, reached peer to peer.
type P2PTarget struct {
	builder *InteropTarget // builds the server binary
	hub     *interoppipe.Hub
	origin  *Origin
	// query is what the server's URL adds: its ICE servers and policy.
	query string
}

// Name implements Target.
func (t *P2PTarget) Name() string { return targetP2P }

// Platform implements Target.
func (t *P2PTarget) Platform() string { return platformP2P }

// Pairs implements Target: the one pair, vp8channel peer to peer.
func (t *P2PTarget) Pairs() []Pair { return []Pair{{providerInterop, transportVP8}} }

// Load implements Target.
func (t *P2PTarget) Load() LoadURLs { return t.origin.URLs }

// Open implements Target: a fresh room, channel and key, the server joined.
func (t *P2PTarget) Open(ctx context.Context, p Pair, dir string, opt OpenOptions) (Endpoint, func(), error) {
	key, err := NewKey()
	if err != nil {
		return Endpoint{}, nil, err
	}
	room, err := NewChannel()
	if err != nil {
		return Endpoint{}, nil, err
	}
	channel, err := NewChannel()
	if err != nil {
		return Endpoint{}, nil, err
	}
	ep := Endpoint{Provider: p.Provider, Transport: p.Transport, Room: t.hub.URL("gate-" + room), Channel: channel,
		Key: key, DNS: defaultDNS, VP8FPS: p2pFPS, VP8Batch: p2pBatch}
	binary, err := t.builder.build(ctx)
	if err != nil {
		return Endpoint{}, nil, err
	}
	srv, err := startServer(ctx, binary, t.builder.work, p2pServerConfig(ep, t.query), opt)
	if err != nil {
		return Endpoint{}, nil, err
	}
	secrets := ep.Secrets()
	stop := func() { srv.stop(filepath.Join(dir, serverLogName), secrets) }
	if err := waitForLine(srv.log, linkedLine, linkBudget, srv.exited); err != nil {
		tail := clip(Scrub(lastLine(srv.log), secrets...))
		stop()
		return Endpoint{}, nil, fmt.Errorf("%w; last server line: %s", err, tail)
	}
	return ep, stop, nil
}

// p2pServerConfig is the mode: srv YAML of the p2p pair: the engine's URL
// with the server's query, the room's channel, the app's vp8channel numbers.
func p2pServerConfig(ep Endpoint, query string) string {
	u := ep.Room
	if query != "" {
		u += "?" + query
	}
	return strings.Join([]string{
		"mode: srv", "auth: { provider: none }",
		"engine: { name: " + interopp2p.Name + ", url: " + strconv.Quote(u) + " }",
		"room: { channel: " + strconv.Quote(ep.Channel) + " }",
		"crypto: { key: " + strconv.Quote(ep.Key) + " }",
		"net: { transport: " + ep.Transport + ", dns: " + strconv.Quote(ep.DNS) + " }",
		fmt.Sprintf("vp8: { fps: %d, batch_size: %d }", ep.VP8FPS, ep.VP8Batch),
		"udp: { enabled: true }", "debug: true",
	}, "\n") + "\n"
}

// goP2PClient is the Go public client in the same room: the baseline.
type goP2PClient struct{ cli cliClient }

// Name implements Client.
func (goP2PClient) Name() string { return cliFlavour }

// Start implements Client.
func (g goP2PClient) Start(ctx context.Context, ep Endpoint) (*Tunnel, error) {
	cfg := client.Config{
		Transport: ep.Transport, Provider: "none", Engine: interopp2p.Name, URL: ep.Room, ChannelID: ep.Channel,
		KeyHex: ep.Key, LocalAddr: "127.0.0.1:0", DNSServer: ep.DNS, DeviceID: "gate-cli",
		TransportOptions: client.VP8Options{FPS: ep.VP8FPS, BatchSize: ep.VP8Batch},
	}
	c := g.cli
	c.run = func(ctx context.Context, _ client.Config, onReady func(addr string)) error {
		return runPublicClient(ctx, cfg, onReady)
	}
	return c.Start(ctx, ep)
}

// freePort is a port nothing listens on now (tcp and udp both free).
func freePort(t *testing.T) int {
	t.Helper()
	for range 50 {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		pc, err := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		_ = pc.Close()
		return port
	}
	t.Fatal("no free port")
	return 0
}

// selfSigned writes a certificate for localhost and 127.0.0.1 (its own CA)
// and its key into dir.
func selfSigned(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "turn-cert.pem"), filepath.Join(dir, "turn-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// startCoturn runs coturn on 127.0.0.1 with the one listener mode names
// (udp, tcp or tls) and returns the server URL's query: relay-only through
// it. coturn dies with the test (Pdeathsig, and the cleanup kills it).
// For tls the certificate is trusted through SSL_CERT_FILE, set here before
// any TLS in this process and inherited by every server it starts.
func startCoturn(t *testing.T, mode, logDir string) string {
	t.Helper()
	work := t.TempDir()
	port, tlsPort, minPort := freePort(t), freePort(t), 49152+int(time.Now().UnixNano()%8000)
	args := []string{
		"-n", "--no-cli", "--listening-ip=127.0.0.1", "--relay-ip=127.0.0.1",
		"--listening-port=" + strconv.Itoa(port), "--tls-listening-port=" + strconv.Itoa(tlsPort),
		"--min-port=" + strconv.Itoa(minPort), "--max-port=" + strconv.Itoa(minPort+400),
		"--lt-cred-mech", "--user=" + turnUser + ":" + turnPass, "--realm=olc.interop", "--fingerprint",
		"--userdb=" + filepath.Join(work, "turndb"),
		"--allow-loopback-peers", "--no-multicast-peers", "--no-dtls",
		"--log-file=stdout", "--simple-log", "--pidfile=" + filepath.Join(work, "turnserver.pid"),
	}
	var turnURL string
	switch mode {
	case "udp":
		args = append(args, "--no-tcp", "--no-tls")
		turnURL = fmt.Sprintf("turn:127.0.0.1:%d?transport=udp", port)
	case "tcp":
		args = append(args, "--no-udp", "--no-tls")
		turnURL = fmt.Sprintf("turn:127.0.0.1:%d?transport=tcp", port)
	case "tls":
		cert, key := selfSigned(t, work)
		args = append(args, "--no-udp", "--no-tcp", "--cert="+cert, "--pkey="+key)
		if err := os.Setenv("SSL_CERT_FILE", cert); err != nil {
			t.Fatal(err)
		}
		turnURL = fmt.Sprintf("turns:localhost:%d?transport=tcp", tlsPort)
	default:
		t.Fatalf("-olcrtc.gate-turn=%q: none, udp, tcp or tls", mode)
	}
	cmd := exec.Command(*gateTurnServer, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	logFile, err := os.Create(filepath.Join(logDir, "coturn-"+mode+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("coturn (%s): %v", *gateTurnServer, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			_, _ = logFile.WriteString(sc.Text() + "\n")
		}
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		_ = cmd.Wait()
		_ = logFile.Close()
	})
	// coturn 4.6 logs its listeners only when verbose, so the listener is
	// asked instead.
	deadline := time.Now().Add(turnReadyBudget)
	for !coturnAnswers(mode, port, tlsPort) {
		select {
		case <-done:
			t.Fatalf("coturn ended before it listened; see %s", logFile.Name())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("coturn not listening within %s; see %s", turnReadyBudget, logFile.Name())
		}
		time.Sleep(turnProbeWait / 2)
	}
	q := url.Values{}
	q.Set("turn", turnURL)
	q.Set("turn_user", turnUser)
	q.Set("turn_pass", turnPass)
	q.Set("policy", "relay")
	t.Logf("coturn %s: %s (relay-only server)", mode, turnURL)
	return q.Encode()
}

// coturnAnswers reports whether coturn's listener for mode is up: a STUN
// binding request answered over udp, a TCP connect for tcp and tls.
func coturnAnswers(mode string, port, tlsPort int) bool {
	if mode != "udp" {
		p := port
		if mode == "tls" {
			p = tlsPort
		}
		c, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(p), turnProbeWait)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	c, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	req := make([]byte, 20) // a binding request: type, length 0, cookie, id
	binary.BigEndian.PutUint16(req[0:], 0x0001)
	binary.BigEndian.PutUint32(req[4:], 0x2112A442)
	if _, err := rand.Read(req[8:]); err != nil {
		return false
	}
	_ = c.SetDeadline(time.Now().Add(turnProbeWait))
	if _, err := c.Write(req); err != nil {
		return false
	}
	resp := make([]byte, 1500)
	n, err := c.Read(resp)
	return err == nil && n >= 20 && binary.BigEndian.Uint16(resp) == 0x0101
}

// TestGateP2P is the gate on the p2p target.
func TestGateP2P(t *testing.T) {
	if *gateTargetName != targetP2P {
		t.Skip("the p2p gate runs with -olcrtc.gate-target=p2p")
	}
	interopp2p.Register()
	root := moduleRoot(t)
	dir, err := resolveDir(root, *gateDir)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, "p2p-"+cmpOr(*gateTurn, "none"))
	if err := os.MkdirAll(dir, artifactsPerm); err != nil {
		t.Fatal(err)
	}
	var query string
	if *gateTurn != "none" && *gateTurn != "" {
		query = startCoturn(t, *gateTurn, dir)
	}
	hub, err := interoppipe.StartHub("127.0.0.1:0", interoppipe.Chaos{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hub.Close)
	target := &P2PTarget{builder: &InteropTarget{root: root, work: t.TempDir()}, hub: hub, origin: startOrigin(t),
		query: query}

	registryMu.Lock()
	saved := registry
	registry = interopScenarios(saved)
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})

	var clients []Client
	for _, name := range splitList(*gateFlavours) {
		switch name {
		case rustFlavour:
			clients = append(clients, rustClient{bin: *gateRustBin, start: startBudget, stop: stopBudget, logf: t.Logf,
				extra: func(cfg *rustConfig) {
					cfg.Engine = interopp2p.Name
					cfg.IceLocalIP = "127.0.0.1"
				}})
		case cliFlavour:
			clients = append(clients, goP2PClient{cli: cliClient{start: startBudget, stop: stopBudget}})
		default:
			t.Fatalf("unknown flavour %q: rust or cli", name)
		}
	}
	rec := NewRecorder(Report{Target: targetP2P, Runner: runnerName()})
	capture := StartCapture()
	defer capture.Stop()
	secrets := []string{turnPass}
	opt := Options{
		Target: target, Clients: clients, Thresholds: Local, Dir: dir, Recorder: rec, Capture: capture,
		Secrets: &secrets, Logf: t.Logf, ReportPath: filepath.Join(dir, reportName),
	}
	RunPlan(runContext(t), opt, func(name string, cell func() error) {
		t.Run(name, func(t *testing.T) {
			if err := cell(); err != nil {
				t.Error(err)
			}
		})
	})
	rep := rec.Report()
	for _, c := range rep.Cells {
		raw, _ := json.Marshal(c.Metrics)
		t.Logf("cell %s: %s %s %q", c.ID, c.Status, raw, c.Failures)
	}
	for _, id := range unreported(rep) {
		t.Errorf("%s: %s", id, reasonDidNotRun)
	}
	if why := gateFailure(rep); why != "" {
		t.Errorf("gate: %s; the report goes to %s", why, opt.ReportPath)
	}
}

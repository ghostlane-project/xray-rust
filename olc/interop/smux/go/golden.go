package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// The golden captures. Each scenario runs a smux v1.5.57 client and server in
// this process over loopback TCP, in a fixed choreography, and records every
// byte each side hands to its conn: <name>.c2s and <name>.s2c.
//
// The choreography leaves 50 ms of quiet after each step, so that every frame
// a step causes is on the wire before the next step starts; with that, the
// bytes do not depend on scheduling. tests/golden.rs runs the same steps with
// olc-smux on both ends and compares the bytes.
//
// Keep each scenario in step with its twin in tests/golden.rs.

type recConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *recConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

func quiet() { time.Sleep(50 * time.Millisecond) }

// goldenCfg is a v2 config with keepalive off, so that no NOP lands at a
// time the choreography does not control.
func goldenCfg(frame, recv, stream int) *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveDisabled = true
	cfg.MaxFrameSize = frame
	cfg.MaxReceiveBuffer = recv
	cfg.MaxStreamBuffer = stream
	if err := smux.VerifyConfig(cfg); err != nil {
		fatalf("golden config: %v", err)
	}
	return cfg
}

type scenario struct {
	name         string
	client, serv *smux.Config
	run          func(c, s *smux.Session) error
}

var scenarios = []scenario{
	{"basic", goldenCfg(32768, 4<<20, 512<<10), goldenCfg(32768, 4<<20, 64<<10), scenarioBasic},
	{"window", goldenCfg(100, 4096, 1000), goldenCfg(100, 4096, 300), scenarioWindow},
	{"maxframe", goldenCfg(65535, 4<<20, 512<<10), goldenCfg(65535, 4<<20, 4<<20), scenarioMaxFrame},
	{"bigread", goldenCfg(32768, 4<<20, 64<<10), goldenCfg(32768, 4<<20, 512<<10), scenarioBigRead},
}

func runGolden(args []string) {
	fs := flag.NewFlagSet("golden", flag.ExitOnError)
	out := fs.String("out", "golden", "output directory")
	_ = fs.Parse(args)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatalf("mkdir: %v", err)
	}
	for _, sc := range scenarios {
		c2s, s2c, err := runScenario(sc)
		if err != nil {
			fatalf("scenario %s: %v", sc.name, err)
		}
		write := func(suffix string, b []byte) {
			p := filepath.Join(*out, sc.name+suffix)
			if err := os.WriteFile(p, b, 0o644); err != nil {
				fatalf("write %s: %v", p, err)
			}
			logf("GOLDEN %s%s %d bytes sha256=%x", sc.name, suffix, len(b), sha256.Sum256(b))
		}
		write(".c2s", c2s)
		write(".s2c", s2c)
	}
}

func runScenario(sc scenario) ([]byte, []byte, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	cconn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	sconn, ok := <-accepted
	if !ok {
		return nil, nil, errors.New("accept failed")
	}
	crec := &recConn{Conn: cconn}
	srec := &recConn{Conn: sconn}
	c, err := smux.Client(crec, sc.client)
	if err != nil {
		return nil, nil, err
	}
	s, err := smux.Server(srec, sc.serv)
	if err != nil {
		return nil, nil, err
	}
	runErr := sc.run(c, s)
	quiet()
	_ = c.Close()
	_ = s.Close()
	return crec.bytes(), srec.bytes(), runErr
}

func readExactly(r io.Reader, n, bufSize int) ([]byte, error) {
	buf := make([]byte, bufSize)
	var out []byte
	for len(out) < n {
		k, err := r.Read(buf)
		out = append(out, buf[:k]...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func expectEOF(r io.Reader) error {
	var b [16]byte
	n, err := r.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("want EOF, got n=%d err=%v", n, err)
	}
	return nil
}

func expectClosedPipe(err error) error {
	if !errors.Is(err, io.ErrClosedPipe) {
		return fmt.Errorf("want io.ErrClosedPipe, got %v", err)
	}
	return nil
}

func check(errs ...error) error { return errors.Join(errs...) }

// scenarioBasic: open, data both ways, first-read and threshold UPDs, a
// window-limited write, half-close both ways, the double FIN of CloseWrite
// then Close, a Close before the peer reads, and a server-opened stream.
func scenarioBasic(c, s *smux.Session) error {
	// 1. The client opens sid 3.
	cs, err := c.OpenStream()
	if err != nil {
		return err
	}
	ss, err := s.AcceptStream()
	if err != nil {
		return err
	}
	quiet()
	// 2. A zero-length write sends nothing.
	if n, err := cs.Write(nil); n != 0 || err != nil {
		return fmt.Errorf("empty write: %d %v", n, err)
	}
	// 3. "hello\n"; the server's first read sends UPD(6, 65536).
	if _, err := cs.Write([]byte("hello\n")); err != nil {
		return err
	}
	if _, err := readExactly(ss, 6, 65536); err != nil {
		return err
	}
	quiet()
	// 4. 100 bytes back; the client's first read sends UPD(100, 524288).
	if _, err := ss.Write(pattern(100, 1)); err != nil {
		return err
	}
	if _, err := readExactly(cs, 100, 65536); err != nil {
		return err
	}
	quiet()
	// 5. One 70000-byte write against the server's 65536 window: 32768,
	//    32768, then 4464 after the server's threshold UPD.
	werr := make(chan error, 1)
	go func() {
		_, err := cs.Write(pattern(70000, 2))
		werr <- err
	}()
	if _, err := readExactly(ss, 70000, 65536); err != nil {
		return err
	}
	if err := <-werr; err != nil {
		return err
	}
	quiet()
	// 6. The client half-closes; the server reads EOF.
	if err := cs.CloseWrite(); err != nil {
		return err
	}
	if err := expectEOF(ss); err != nil {
		return err
	}
	quiet()
	// 7. The server still writes; the client reads it before the server's FIN.
	if _, err := ss.Write(pattern(10, 3)); err != nil {
		return err
	}
	if _, err := readExactly(cs, 10, 65536); err != nil {
		return err
	}
	quiet()
	if err := ss.CloseWrite(); err != nil {
		return err
	}
	if err := expectEOF(cs); err != nil {
		return err
	}
	quiet()
	// 8. Both FINs are out: both streams are gone, and Close sends nothing.
	if err := check(expectClosedPipe(ss.Close()), expectClosedPipe(cs.Close())); err != nil {
		return err
	}
	quiet()
	// 9. sid 5: write and Close before the server reads. The server's UPD and
	//    FIN go to a stream the client no longer has.
	cs5, err := c.OpenStream()
	if err != nil {
		return err
	}
	if _, err := cs5.Write([]byte("abc")); err != nil {
		return err
	}
	if err := cs5.Close(); err != nil {
		return err
	}
	ss5, err := s.AcceptStream()
	if err != nil {
		return err
	}
	if _, err := readExactly(ss5, 3, 65536); err != nil {
		return err
	}
	if err := expectEOF(ss5); err != nil {
		return err
	}
	if err := ss5.Close(); err != nil {
		return err
	}
	quiet()
	// 10. sid 7: CloseWrite then Close sends FIN twice.
	cs7, err := c.OpenStream()
	if err != nil {
		return err
	}
	if err := cs7.CloseWrite(); err != nil {
		return err
	}
	if err := cs7.Close(); err != nil {
		return err
	}
	ss7, err := s.AcceptStream()
	if err != nil {
		return err
	}
	if err := expectEOF(ss7); err != nil {
		return err
	}
	if err := ss7.Close(); err != nil {
		return err
	}
	quiet()
	// 11. The server opens sid 2.
	ss2, err := s.OpenStream()
	if err != nil {
		return err
	}
	cs2, err := c.AcceptStream()
	if err != nil {
		return err
	}
	if _, err := ss2.Write(pattern(5, 4)); err != nil {
		return err
	}
	if _, err := readExactly(cs2, 5, 65536); err != nil {
		return err
	}
	quiet()
	if err := cs2.Close(); err != nil {
		return err
	}
	if err := expectEOF(ss2); err != nil {
		return err
	}
	return ss2.Close()
}

// scenarioWindow: 100-byte frames against a 300-byte window (UPD every 150
// bytes read): the writer stalls and resumes on each UPD.
func scenarioWindow(c, s *smux.Session) error {
	cs, err := c.OpenStream()
	if err != nil {
		return err
	}
	ss, err := s.AcceptStream()
	if err != nil {
		return err
	}
	if _, err := cs.Write([]byte{0x5a}); err != nil {
		return err
	}
	if _, err := readExactly(ss, 1, 1000); err != nil {
		return err
	}
	quiet()
	werr := make(chan error, 1)
	go func() {
		_, err := cs.Write(pattern(1000, 5))
		werr <- err
	}()
	if _, err := readExactly(ss, 1000, 1000); err != nil {
		return err
	}
	if err := <-werr; err != nil {
		return err
	}
	quiet()
	if err := cs.CloseWrite(); err != nil {
		return err
	}
	if err := expectEOF(ss); err != nil {
		return err
	}
	if err := ss.Close(); err != nil {
		return err
	}
	quiet()
	return expectClosedPipe(cs.Close())
}

// scenarioMaxFrame: MaxFrameSize 65535, the largest the header can carry; a
// 65536-byte write is two frames.
func scenarioMaxFrame(c, s *smux.Session) error {
	cs, err := c.OpenStream()
	if err != nil {
		return err
	}
	ss, err := s.AcceptStream()
	if err != nil {
		return err
	}
	if _, err := cs.Write(pattern(65536, 6)); err != nil {
		return err
	}
	if _, err := readExactly(ss, 65536, 70000); err != nil {
		return err
	}
	quiet()
	if err := cs.Close(); err != nil {
		return err
	}
	if err := expectEOF(ss); err != nil {
		return err
	}
	return ss.Close()
}

// scenarioBigRead: the server writes 100000 bytes at once; the client's
// window is 65536, so its UPDs come at the first read and then every 32768.
func scenarioBigRead(c, s *smux.Session) error {
	cs, err := c.OpenStream()
	if err != nil {
		return err
	}
	ss, err := s.AcceptStream()
	if err != nil {
		return err
	}
	if _, err := ss.Write(pattern(100000, 7)); err != nil {
		return err
	}
	if _, err := readExactly(cs, 100000, 65536); err != nil {
		return err
	}
	quiet()
	if err := ss.CloseWrite(); err != nil {
		return err
	}
	if err := expectEOF(cs); err != nil {
		return err
	}
	quiet()
	if err := cs.CloseWrite(); err != nil {
		return err
	}
	if err := expectEOF(ss); err != nil {
		return err
	}
	quiet()
	return check(expectClosedPipe(cs.Close()), expectClosedPipe(ss.Close()))
}

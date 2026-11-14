// Command smuxpeer is the Go side of olc-smux's conformance tests.
//
// It is built against github.com/xtaci/smux v1.5.57, the version the olcRTC
// engine pins at 2d4266af, and it is never shipped. The Rust tests in
// olc/olc-smux/tests run it as a child process named by OLC_SMUX_GO_PEER.
//
//	smuxpeer golden -out DIR                     write the golden frame captures
//	smuxpeer serve  -listen ADDR [cfg] [-once]   serve the test services on every stream
//	smuxpeer dial   -connect ADDR -script NAME [cfg]   run a client script
//
// [cfg] is -frame, -recv, -stream, -ka-interval, -ka-timeout, -ka-off: the
// fields of smux.Config. Version is always 2, as the engine sets it
// (internal/runtime/runtime.go:111,208).
//
// The stream services and the client scripts exist twice, here and in
// olc/olc-smux/tests/common, so that each language can be the client of the
// other. Keep them in step.
package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "golden":
		runGolden(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "dial":
		runDial(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: smuxpeer golden|serve|dial [flags]")
	os.Exit(2)
}

// cfgFlags are the smux.Config fields a test may set.
type cfgFlags struct {
	frame, recv, stream   int
	kaInterval, kaTimeout time.Duration
	kaOff                 bool
}

func addCfgFlags(fs *flag.FlagSet) *cfgFlags {
	c := &cfgFlags{}
	fs.IntVar(&c.frame, "frame", 32768, "MaxFrameSize")
	fs.IntVar(&c.recv, "recv", 4*1024*1024, "MaxReceiveBuffer")
	fs.IntVar(&c.stream, "stream", 512*1024, "MaxStreamBuffer")
	fs.DurationVar(&c.kaInterval, "ka-interval", 10*time.Second, "KeepAliveInterval")
	fs.DurationVar(&c.kaTimeout, "ka-timeout", 30*time.Second, "KeepAliveTimeout")
	fs.BoolVar(&c.kaOff, "ka-off", false, "KeepAliveDisabled")
	return c
}

func (c *cfgFlags) config() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxFrameSize = c.frame
	cfg.MaxReceiveBuffer = c.recv
	cfg.MaxStreamBuffer = c.stream
	cfg.KeepAliveInterval = c.kaInterval
	cfg.KeepAliveTimeout = c.kaTimeout
	cfg.KeepAliveDisabled = c.kaOff
	if err := smux.VerifyConfig(cfg); err != nil {
		fatalf("config: %v", err)
	}
	return cfg
}

var outMu sync.Mutex

// logf writes one line to stdout; the Rust tests read stdout line by line.
func logf(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func fatalf(format string, args ...any) {
	logf("FATAL "+format, args...)
	os.Exit(1)
}

// The byte pattern every test stream carries: stream seed s, offset i is
// patternTable[(i + s*7919) % patternLen]. tests/common/mod.rs has the twin.
const patternLen = 65521

var patternTable = func() []byte {
	t := make([]byte, patternLen)
	x := uint64(0x9E3779B97F4A7C15)
	for i := range t {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		t[i] = byte(x >> 24)
	}
	return t
}()

func fillPattern(b []byte, seed, off uint64) {
	pos := int((off + seed*7919) % patternLen)
	for len(b) > 0 {
		n := copy(b, patternTable[pos:])
		b = b[n:]
		pos = 0
	}
}

func pattern(n int, seed uint64) []byte {
	b := make([]byte, n)
	fillPattern(b, seed, 0)
	return b
}

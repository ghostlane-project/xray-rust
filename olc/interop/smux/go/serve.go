package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// runServe accepts TCP connections and runs a smux server on each. Every
// accepted stream starts with one command line; serveStream answers it.
//
// stdout lines: "LISTEN <addr>" first, then "SESSION START", "SESSION END
// after=<ms> err=<err>", and "ERR ..." for any service failure. The Rust
// tests fail on any ERR line.
func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "listen address")
	once := fs.Bool("once", false, "exit after the first session ends")
	cf := addCfgFlags(fs)
	_ = fs.Parse(args)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("listen: %v", err)
	}
	logf("LISTEN %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			fatalf("accept: %v", err)
		}
		if *once {
			serveConn(conn, cf.config())
			return
		}
		go serveConn(conn, cf.config())
	}
}

func serveConn(conn net.Conn, cfg *smux.Config) {
	start := time.Now()
	sess, err := smux.Server(conn, cfg)
	if err != nil {
		logf("ERR smux.Server: %v", err)
		return
	}
	logf("SESSION START")
	var wg sync.WaitGroup
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			logf("SESSION END after=%d err=%v", time.Since(start).Milliseconds(), err)
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveStream(st, sess)
		}()
	}
	_ = sess.Close()
	wg.Wait()
}

// readLine reads one command line a byte at a time, so that nothing after
// the newline is consumed.
func readLine(r io.Reader) (string, error) {
	var b [1]byte
	var line []byte
	for {
		n, err := r.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return string(line), nil
			}
			line = append(line, b[0])
			if len(line) > 256 {
				return "", errors.New("command line too long")
			}
			continue
		}
		if err != nil {
			return "", err
		}
	}
}

func atoi(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// finLinger is how long a service waits before the FIN that follows data
// sent after the client's FIN. smux v1.5.57 drops a stream's unread data
// once both sides have sent FIN (stream.go:808-833 with session.go:357-374:
// tryHalfCloseCleanup, then recycleTokens), so a client that half-closed and
// has not yet read the last data loses it when this FIN comes right after.
// Go against Go, without the linger, 40 runs of each client script failed
// 36 (half), 39 (many), 40 (slow), 31 (echo) and 30 (idle) times. The Rust
// twin lingers the same.
const finLinger = 200 * time.Millisecond

// serveStream runs one service. The commands, and their twins in Rust:
//
//	ECHO               copy back until EOF, linger, CloseWrite, Close
//	SINK n seed        read until EOF, check n pattern bytes, reply "OK n" or "BAD ...", linger, Close
//	SOURCE n seed      write n pattern bytes in 32 KiB writes, CloseWrite, read until EOF, Close
//	SLOWSINK chunk ms  read with a chunk-sized buffer and sleep ms after each read; reply "OK n", linger, Close
//	HOLD               never read; wait for the session to end
//	HALF               read until EOF, reply "GOT n", linger, CloseWrite, Close
//	LATE ms            CloseWrite, sleep ms, read until EOF, print "LATE sid=<id> got=<n> err=<err>"
//	                   (Go only: it pins the half-close drop on the server side)
func serveStream(st *smux.Stream, sess *smux.Session) {
	defer st.Close()
	line, err := readLine(st)
	if err != nil {
		logf("ERR sid=%d read command: %v", st.ID(), err)
		return
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		logf("ERR sid=%d empty command", st.ID())
		return
	}
	switch f[0] {
	case "ECHO":
		if _, err := copyToEOF(st, st); err != nil {
			logf("ERR sid=%d echo: %v", st.ID(), err)
			return
		}
		time.Sleep(finLinger)
		_ = st.CloseWrite()
	case "SINK":
		want, seed := atoi(f[1]), atoi(f[2])
		got, bad := checkPattern(st, make([]byte, 32*1024), seed, 0)
		reply := fmt.Sprintf("OK %d\n", got)
		if bad != "" || got != want {
			reply = fmt.Sprintf("BAD got=%d want=%d %s\n", got, want, bad)
			logf("ERR sid=%d sink: %s", st.ID(), strings.TrimSpace(reply))
		}
		_, _ = st.Write([]byte(reply))
		time.Sleep(finLinger)
	case "SOURCE":
		n, seed := atoi(f[1]), atoi(f[2])
		buf := make([]byte, 32*1024)
		for off := uint64(0); off < n; {
			chunk := buf
			if n-off < uint64(len(chunk)) {
				chunk = chunk[:n-off]
			}
			fillPattern(chunk, seed, off)
			if _, err := st.Write(chunk); err != nil {
				logf("ERR sid=%d source write at %d: %v", st.ID(), off, err)
				return
			}
			off += uint64(len(chunk))
		}
		_ = st.CloseWrite()
		_, _ = copyToEOF(io.Discard, st)
	case "SLOWSINK":
		chunk, delay := atoi(f[1]), atoi(f[2])
		buf := make([]byte, chunk)
		var total uint64
		for {
			n, err := st.Read(buf)
			total += uint64(n)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					logf("ERR sid=%d slowsink: %v", st.ID(), err)
				}
				break
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		_, _ = st.Write([]byte(fmt.Sprintf("OK %d\n", total)))
		time.Sleep(finLinger)
	case "HOLD":
		select {
		case <-st.GetDieCh():
		case <-sess.CloseChan():
		}
	case "HALF":
		n, err := copyToEOF(io.Discard, st)
		if err != nil {
			logf("ERR sid=%d half: %v", st.ID(), err)
			return
		}
		if _, err := st.Write([]byte(fmt.Sprintf("GOT %d\n", n))); err != nil {
			logf("ERR sid=%d half reply: %v", st.ID(), err)
			return
		}
		time.Sleep(finLinger)
		_ = st.CloseWrite()
	case "LATE":
		_ = st.CloseWrite()
		time.Sleep(time.Duration(atoi(f[1])) * time.Millisecond)
		n, err := copyToEOF(io.Discard, st)
		logf("LATE sid=%d got=%d err=%v", st.ID(), n, err)
	default:
		logf("ERR sid=%d unknown command %q", st.ID(), line)
	}
}

// copyToEOF is io.Copy for a smux source. io.Copy hands a *smux.Stream to its
// WriteTo, which returns io.EOF itself at the peer's FIN (smux/stream.go:405-407
// with :443-450), so a clean end arrives as an error; this maps it to nil.
func copyToEOF(dst io.Writer, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, src)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}

// checkPattern reads r until EOF and compares every byte with the pattern of
// seed starting at off. It returns the byte count and, on a mismatch, where.
func checkPattern(r io.Reader, buf []byte, seed, off uint64) (uint64, string) {
	want := make([]byte, len(buf))
	var total uint64
	bad := ""
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if bad == "" {
				fillPattern(want[:n], seed, off+total)
				if !bytes.Equal(want[:n], buf[:n]) {
					bad = fmt.Sprintf("mismatch-near=%d", off+total)
				}
			}
			total += uint64(n)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && bad == "" {
				bad = "read-error=" + strings.ReplaceAll(err.Error(), " ", "_")
			}
			return total, bad
		}
	}
}

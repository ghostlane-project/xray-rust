package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// runDial connects to a smux server (the Rust one, or this program's serve
// through a tracing proxy) and runs one client script. It prints "PASS" and
// exits 0, or prints "FAIL <why>" and exits 1.
func runDial(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	connect := fs.String("connect", "", "server address")
	script := fs.String("script", "", "echo|many|window|slow|half|idle|idle-silent")
	streams := fs.Int("streams", 8, "streams per direction (many, window)")
	size := fs.Int("size", 4<<20, "bytes per stream")
	slowMs := fs.Int("slow-ms", 5, "sleep after each read on a slow stream")
	idle := fs.Duration("idle", time.Second, "idle time (idle, idle-silent)")
	cf := addCfgFlags(fs)
	_ = fs.Parse(args)

	conn, err := net.Dial("tcp", *connect)
	if err != nil {
		fatalf("dial: %v", err)
	}
	sess, err := smux.Client(conn, cf.config())
	if err != nil {
		fatalf("smux.Client: %v", err)
	}
	switch *script {
	case "echo":
		err = scriptEcho(sess, *size)
	case "many":
		err = scriptMany(sess, *streams, *size)
	case "window":
		err = scriptWindow(sess, *streams, *size, *slowMs)
	case "slow":
		err = scriptSlow(sess, *size, *slowMs)
	case "half":
		err = scriptHalf(sess, *size)
	case "idle":
		time.Sleep(*idle)
		err = scriptEcho(sess, 4096)
	case "idle-silent":
		err = scriptIdleSilent(sess, *idle)
	default:
		err = fmt.Errorf("unknown script %q", *script)
	}
	if err != nil {
		logf("FAIL %v", err)
		os.Exit(1)
	}
	logf("PASS")
	_ = sess.Close()
}

func command(sess *smux.Session, line string) (*smux.Stream, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	if _, err := st.Write([]byte(line + "\n")); err != nil {
		return nil, fmt.Errorf("write command: %w", err)
	}
	return st, nil
}

// writePattern writes n pattern bytes of seed in 32 KiB writes, as the
// engine's copy loop does (internal/tunnelcore/copy.go:33-40).
func writePattern(w io.Writer, n int, seed uint64) error {
	buf := make([]byte, 32*1024)
	for off := 0; off < n; {
		chunk := buf
		if n-off < len(chunk) {
			chunk = chunk[:n-off]
		}
		fillPattern(chunk, seed, uint64(off))
		if _, err := w.Write(chunk); err != nil {
			return fmt.Errorf("write at %d: %w", off, err)
		}
		off += len(chunk)
	}
	return nil
}

// readPattern reads to EOF with a 32 KiB buffer, sleeping slow after each
// read, and checks n pattern bytes of seed.
func readPattern(r io.Reader, n int, seed uint64, slow time.Duration) error {
	got, bad := checkPatternSlow(r, seed, slow)
	if bad != "" || got != uint64(n) {
		return fmt.Errorf("read %d of %d bytes %s", got, n, bad)
	}
	return nil
}

func checkPatternSlow(r io.Reader, seed uint64, slow time.Duration) (uint64, string) {
	buf := make([]byte, 32*1024)
	want := make([]byte, len(buf))
	var total uint64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			fillPattern(want[:n], seed, total)
			if !bytes.Equal(want[:n], buf[:n]) {
				return total, fmt.Sprintf("mismatch-near=%d", total)
			}
			total += uint64(n)
			if slow > 0 {
				time.Sleep(slow)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, ""
			}
			return total, "read-error=" + strings.ReplaceAll(err.Error(), " ", "_")
		}
	}
}

func readReply(st *smux.Stream) (string, error) {
	var out bytes.Buffer
	if _, err := copyToEOF(&out, st); err != nil {
		return out.String(), fmt.Errorf("reply: %w", err)
	}
	return strings.TrimSpace(out.String()), nil
}

func scriptEcho(sess *smux.Session, size int) error {
	st, err := command(sess, "ECHO")
	if err != nil {
		return err
	}
	defer st.Close()
	werr := make(chan error, 1)
	go func() {
		err := writePattern(st, size, 1)
		if err == nil {
			err = st.CloseWrite()
		}
		werr <- err
	}()
	if err := readPattern(st, size, 1, 0); err != nil {
		return fmt.Errorf("echo: %w", err)
	}
	return <-werr
}

// scriptMany runs n SINK and n SOURCE streams at once: size bytes each way.
func scriptMany(sess *smux.Session, n, size int) error {
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		sink, err := command(sess, fmt.Sprintf("SINK %d %d", size, 100+i))
		if err != nil {
			return err
		}
		source, err := command(sess, fmt.Sprintf("SOURCE %d %d", size, 200+i))
		if err != nil {
			return err
		}
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			defer sink.Close()
			if err := writePattern(sink, size, uint64(100+i)); err != nil {
				errs <- err
				return
			}
			_ = sink.CloseWrite()
			reply, err := readReply(sink)
			if err != nil || reply != fmt.Sprintf("OK %d", size) {
				errs <- fmt.Errorf("sink %d: %q %v", i, reply, err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			defer source.Close()
			if err := readPattern(source, size, uint64(200+i), 0); err != nil {
				errs <- fmt.Errorf("source %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	return <-errs
}

// scriptWindow is the W15 workload: n SOURCE streams opened in order, read
// with 32 KiB buffers; every second stream sleeps slowMs after each read.
func scriptWindow(sess *smux.Session, n, size, slowMs int) error {
	sts := make([]*smux.Stream, n)
	for i := range sts {
		st, err := command(sess, fmt.Sprintf("SOURCE %d %d", size, 300+i))
		if err != nil {
			return err
		}
		sts[i] = st
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i, st := range sts {
		wg.Add(1)
		go func(i int, st *smux.Stream) {
			defer wg.Done()
			defer st.Close()
			slow := time.Duration(0)
			if i%2 == 1 {
				slow = time.Duration(slowMs) * time.Millisecond
			}
			if err := readPattern(st, size, uint64(300+i), slow); err != nil {
				errs <- fmt.Errorf("stream %d: %w", i, err)
			}
		}(i, st)
	}
	wg.Wait()
	close(errs)
	return <-errs
}

// scriptSlow: the server reads a SLOWSINK slowly (our writes stall on its
// window), and we read a SOURCE slowly (its writes stall on ours).
func scriptSlow(sess *smux.Session, size, slowMs int) error {
	sink, err := command(sess, fmt.Sprintf("SLOWSINK 4096 %d", 1))
	if err != nil {
		return err
	}
	source, err := command(sess, fmt.Sprintf("SOURCE %d 7", size))
	if err != nil {
		return err
	}
	errs := make(chan error, 2)
	go func() {
		defer sink.Close()
		if err := writePattern(sink, size, 9); err != nil {
			errs <- err
			return
		}
		_ = sink.CloseWrite()
		reply, err := readReply(sink)
		if err != nil || reply != fmt.Sprintf("OK %d", size) {
			errs <- fmt.Errorf("slowsink: %q %v", reply, err)
			return
		}
		errs <- nil
	}()
	go func() {
		defer source.Close()
		errs <- readPattern(source, size, 7, time.Duration(slowMs)*time.Millisecond)
	}()
	return errors.Join(<-errs, <-errs)
}

// scriptHalf: write, half-close, and read the answer the server sends after
// our FIN.
func scriptHalf(sess *smux.Session, size int) error {
	st, err := command(sess, "HALF")
	if err != nil {
		return err
	}
	defer st.Close()
	if err := writePattern(st, size, 5); err != nil {
		return err
	}
	if err := st.CloseWrite(); err != nil {
		return fmt.Errorf("closewrite: %w", err)
	}
	reply, err := readReply(st)
	if err != nil || reply != fmt.Sprintf("GOT %d", size) {
		return fmt.Errorf("half: %q %v", reply, err)
	}
	return nil
}

// scriptIdleSilent sends nothing and waits for the server's keepalive to
// close the session. It prints "CLOSED_AFTER <ms>".
func scriptIdleSilent(sess *smux.Session, limit time.Duration) error {
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := sess.AcceptStream()
		done <- err
	}()
	select {
	case err := <-done:
		logf("CLOSED_AFTER %d err=%v", time.Since(start).Milliseconds(), err)
		return nil
	case <-time.After(limit):
		return fmt.Errorf("session still open after %s", limit)
	}
}

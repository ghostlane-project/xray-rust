// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Shared test tooling: the byte pattern, the Go peer, the Rust twins of its
//! stream services and client scripts, and a tracing TCP proxy.
//!
//! The services and scripts mirror olc/interop/smux/go/serve.go and dial.go;
//! keep them in step.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use olc_smux::frame::{decode_upd, Cmd, Header, HEADER_SIZE, INITIAL_PEER_WINDOW};
use olc_smux::{Config, Error, Session, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// The pattern: main.go's patternTable and fillPattern.

pub const PATTERN_LEN: usize = 65521;

pub fn pattern_table() -> &'static [u8] {
    static T: OnceLock<Vec<u8>> = OnceLock::new();
    T.get_or_init(|| {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..PATTERN_LEN)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    })
}

pub fn fill_pattern(mut b: &mut [u8], seed: u64, off: u64) {
    let t = pattern_table();
    let mut pos = ((off + seed * 7919) % PATTERN_LEN as u64) as usize;
    while !b.is_empty() {
        let n = b.len().min(PATTERN_LEN - pos);
        b[..n].copy_from_slice(&t[pos..pos + n]);
        b = &mut b[n..];
        pos = 0;
    }
}

pub fn pattern(n: usize, seed: u64) -> Vec<u8> {
    let mut b = vec![0u8; n];
    fill_pattern(&mut b, seed, 0);
    b
}

/// Aborts the test binary if it is still running after ten minutes, so that
/// a hang cannot hold the shared build box.
pub fn watchdog() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(600));
            eprintln!("WATCHDOG: the test binary still runs after 600 s; aborting");
            std::process::abort();
        });
    });
}

// ---------------------------------------------------------------------------
// The Go peer.

/// The Go peer binary from `OLC_SMUX_GO_PEER`, or `None` with a message
/// (a test then returns early). With `OLC_SMUX_REQUIRE_GO_PEER=1` a missing
/// peer is a failure.
pub fn go_peer() -> Option<PathBuf> {
    watchdog();
    match std::env::var_os("OLC_SMUX_GO_PEER") {
        Some(p) if !p.is_empty() => {
            let p = PathBuf::from(p);
            assert!(
                p.is_file(),
                "OLC_SMUX_GO_PEER={} is not a file",
                p.display()
            );
            Some(p)
        }
        _ => {
            if std::env::var("OLC_SMUX_REQUIRE_GO_PEER").as_deref() == Ok("1") {
                panic!("OLC_SMUX_REQUIRE_GO_PEER=1 but OLC_SMUX_GO_PEER is not set");
            }
            eprintln!(
                "SKIPPED: OLC_SMUX_GO_PEER is not set; build the Go peer with \
                 olc/interop/smux/go/peer.sh and point OLC_SMUX_GO_PEER at it"
            );
            None
        }
    }
}

fn go_duration(d: Duration) -> String {
    format!("{}ms", d.as_millis())
}

/// The Go peer's config flags for a config.
pub fn go_cfg_args(cfg: &Config) -> Vec<String> {
    let mut v = vec![
        "-frame".to_string(),
        cfg.max_frame_size.to_string(),
        "-recv".to_string(),
        cfg.max_receive_buffer.to_string(),
        "-stream".to_string(),
        cfg.max_stream_buffer.to_string(),
    ];
    match cfg.keep_alive {
        Some(ka) => {
            v.push("-ka-interval".into());
            v.push(go_duration(ka.interval));
            v.push("-ka-timeout".into());
            v.push(go_duration(ka.timeout));
        }
        None => v.push("-ka-off".into()),
    }
    v
}

/// A running `smuxpeer serve`.
pub struct GoServer {
    child: Child,
    pub addr: SocketAddr,
    lines: Arc<Mutex<Vec<String>>>,
}

impl GoServer {
    pub fn start(peer: &Path, cfg: &Config) -> GoServer {
        let mut child = Command::new(peer)
            .arg("serve")
            .arg("-listen")
            .arg("127.0.0.1:0")
            .args(go_cfg_args(cfg))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the Go peer");
        let stdout = child.stdout.take().expect("stdout");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel();
        let keep = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let _ = tx.send(line.clone());
                keep.lock().unwrap().push(line);
            }
        });
        let first = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the Go peer's LISTEN line");
        let addr = first
            .strip_prefix("LISTEN ")
            .unwrap_or_else(|| panic!("unexpected first line {first:?}"))
            .parse()
            .expect("listen address");
        GoServer { child, addr, lines }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    /// Lines reporting a failure in a Go service.
    pub fn errors(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|l| l.starts_with("ERR") || l.starts_with("FATAL"))
            .collect()
    }

    pub async fn wait_line(&self, prefix: &str, limit: Duration) -> Option<String> {
        let end = Instant::now() + limit;
        loop {
            if let Some(l) = self.lines().into_iter().find(|l| l.starts_with(prefix)) {
                return Some(l);
            }
            if Instant::now() > end {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The outcome of a `smuxpeer dial` run.
#[derive(Debug)]
pub struct GoRun {
    pub ok: bool,
    pub lines: Vec<String>,
}

impl GoRun {
    pub fn line(&self, prefix: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|l| l.starts_with(prefix))
            .map(|s| s.as_str())
    }
}

/// Runs `smuxpeer dial` against `addr` to completion.
pub async fn go_dial(
    peer: &Path,
    addr: SocketAddr,
    script: &str,
    cfg: &Config,
    extra: &[&str],
) -> GoRun {
    let mut cmd = Command::new(peer);
    cmd.arg("dial")
        .arg("-connect")
        .arg(addr.to_string())
        .arg("-script")
        .arg(script)
        .args(go_cfg_args(cfg))
        .args(extra)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit());
    let out = tokio::task::spawn_blocking(move || cmd.output().expect("run the Go peer"))
        .await
        .unwrap();
    let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(String::from)
        .collect();
    GoRun {
        ok: out.status.success() && lines.iter().any(|l| l == "PASS"),
        lines,
    }
}

// ---------------------------------------------------------------------------
// Sessions.

pub type DriverHandle = JoinHandle<Result<(), Error>>;

pub async fn connect(addr: SocketAddr, cfg: Config) -> (Session, DriverHandle) {
    let conn = TcpStream::connect(addr).await.expect("connect");
    conn.set_nodelay(true).unwrap();
    let (sess, driver) = Session::client(conn, cfg).expect("client session");
    (sess, tokio::spawn(driver))
}

/// Opens a stream and writes one command line, as dial.go's `command`.
pub async fn command(sess: &Session, line: &str) -> Stream {
    let mut st = sess.open_stream().await.expect("open");
    st.write_all(format!("{line}\n").as_bytes())
        .await
        .expect("write command");
    st
}

/// `writePattern`: n bytes of seed in 32 KiB writes, as the engine's copy
/// loop writes (internal/tunnelcore/copy.go:33-40).
pub async fn write_pattern<W: AsyncWrite + Unpin>(
    w: &mut W,
    n: usize,
    seed: u64,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut off = 0;
    while off < n {
        let len = buf.len().min(n - off);
        fill_pattern(&mut buf[..len], seed, off as u64);
        w.write_all(&buf[..len]).await?;
        off += len;
    }
    Ok(())
}

/// Reads to EOF with a 32 KiB buffer, sleeping `slow` after each read, and
/// checks every byte against the pattern. Returns the count.
pub async fn read_pattern<R: AsyncRead + Unpin>(
    r: &mut R,
    seed: u64,
    slow: Duration,
) -> Result<u64, String> {
    read_pattern_with(r, seed, slow, 32 * 1024).await
}

pub async fn read_pattern_with<R: AsyncRead + Unpin>(
    r: &mut R,
    seed: u64,
    slow: Duration,
    buf_size: usize,
) -> Result<u64, String> {
    let mut buf = vec![0u8; buf_size];
    let mut want = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = r
            .read(&mut buf)
            .await
            .map_err(|e| format!("read error at {total}: {e}"))?;
        if n == 0 {
            return Ok(total);
        }
        fill_pattern(&mut want[..n], seed, total);
        if want[..n] != buf[..n] {
            return Err(format!("mismatch near {total}"));
        }
        total += n as u64;
        if !slow.is_zero() {
            tokio::time::sleep(slow).await;
        }
    }
}

pub async fn read_to_string<R: AsyncRead + Unpin>(r: &mut R) -> String {
    let mut out = Vec::new();
    r.read_to_end(&mut out).await.expect("read reply");
    String::from_utf8_lossy(&out).trim().to_string()
}

// --- dial.go's scripts, against a Go (or Rust) server. ---------------------

pub async fn script_echo(sess: &Session, size: usize) -> Result<(), String> {
    let st = command(sess, "ECHO").await;
    let (mut r, mut w) = tokio::io::split(st);
    let writer = tokio::spawn(async move {
        write_pattern(&mut w, size, 1).await?;
        w.shutdown().await?;
        Ok::<_, std::io::Error>(w)
    });
    let got = read_pattern(&mut r, 1, Duration::ZERO).await?;
    let w = writer
        .await
        .unwrap()
        .map_err(|e| format!("echo write: {e}"))?;
    let mut st = r.unsplit(w);
    let _ = st.close().await;
    if got != size as u64 {
        return Err(format!("echo: read {got} of {size}"));
    }
    Ok(())
}

pub async fn script_many(sess: &Session, n: usize, size: usize) -> Result<(), String> {
    let mut tasks = Vec::new();
    for i in 0..n {
        let mut sink = command(sess, &format!("SINK {size} {}", 100 + i)).await;
        let mut source = command(sess, &format!("SOURCE {size} {}", 200 + i)).await;
        tasks.push(tokio::spawn(async move {
            write_pattern(&mut sink, size, 100 + i as u64)
                .await
                .map_err(|e| format!("sink {i} write: {e}"))?;
            sink.shutdown()
                .await
                .map_err(|e| format!("sink {i} shutdown: {e}"))?;
            let reply = read_to_string(&mut sink).await;
            let _ = sink.close().await;
            if reply != format!("OK {size}") {
                return Err(format!("sink {i}: {reply:?}"));
            }
            Ok(())
        }));
        tasks.push(tokio::spawn(async move {
            let got = read_pattern(&mut source, 200 + i as u64, Duration::ZERO).await?;
            let _ = source.close().await;
            if got != size as u64 {
                return Err(format!("source {i}: read {got} of {size}"));
            }
            Ok(())
        }));
    }
    for t in tasks {
        t.await.unwrap()?;
    }
    Ok(())
}

/// The W15 workload: n SOURCE streams opened in order, read with 32 KiB
/// buffers, every second stream sleeping `slow` after each read. Returns
/// each stream's peak of buffered bytes.
pub async fn script_window(
    sess: &Session,
    n: usize,
    size: usize,
    slow: Duration,
) -> Result<Vec<usize>, String> {
    let mut streams = Vec::new();
    for i in 0..n {
        streams.push(command(sess, &format!("SOURCE {size} {}", 300 + i)).await);
    }
    let mut tasks = Vec::new();
    for (i, mut st) in streams.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            let pause = if i % 2 == 1 { slow } else { Duration::ZERO };
            let got = read_pattern(&mut st, 300 + i as u64, pause).await?;
            let peak = st.stats().peak_rx_buffered;
            let _ = st.close().await;
            if got != size as u64 {
                return Err(format!("stream {i}: read {got} of {size}"));
            }
            Ok(peak)
        }));
    }
    let mut peaks = Vec::new();
    for t in tasks {
        peaks.push(t.await.unwrap()?);
    }
    Ok(peaks)
}

pub async fn script_slow(
    sess: &Session,
    size: usize,
    slow: Duration,
) -> Result<(usize, usize), String> {
    let mut sink = command(sess, "SLOWSINK 4096 1").await;
    let mut source = command(sess, &format!("SOURCE {size} 7")).await;
    let a = tokio::spawn(async move {
        write_pattern(&mut sink, size, 9)
            .await
            .map_err(|e| format!("slowsink write: {e}"))?;
        sink.shutdown()
            .await
            .map_err(|e| format!("slowsink shutdown: {e}"))?;
        let reply = read_to_string(&mut sink).await;
        let peak = sink.stats().peak_rx_buffered;
        let _ = sink.close().await;
        if reply != format!("OK {size}") {
            return Err(format!("slowsink: {reply:?}"));
        }
        Ok(peak)
    });
    let b = tokio::spawn(async move {
        let got = read_pattern(&mut source, 7, slow).await?;
        let peak = source.stats().peak_rx_buffered;
        let _ = source.close().await;
        if got != size as u64 {
            return Err(format!("slow source: read {got} of {size}"));
        }
        Ok(peak)
    });
    let pa = a.await.unwrap()?;
    let pb = b.await.unwrap()?;
    Ok((pa, pb))
}

pub async fn script_half(sess: &Session, size: usize) -> Result<(), String> {
    let mut st = command(sess, "HALF").await;
    write_pattern(&mut st, size, 5)
        .await
        .map_err(|e| format!("half write: {e}"))?;
    st.shutdown()
        .await
        .map_err(|e| format!("half shutdown: {e}"))?;
    let reply = read_to_string(&mut st).await;
    // Both FINs are out: the stream is gone, and Close says so (smux/stream.go:679-681).
    assert_eq!(st.close().await, Err(Error::ClosedPipe));
    if reply != format!("GOT {size}") {
        return Err(format!("half: {reply:?}"));
    }
    Ok(())
}

// --- serve.go's services, for a Go client. ---------------------------------

/// Errors the Rust services met, as serve.go's "ERR" lines.
pub type Errors = Arc<Mutex<Vec<String>>>;

/// One frame of a stream as the tap saw it: cmd, length, and a UPD's
/// (consumed, window).
pub type FrameSeen = (u8, u16, Option<(u32, u32)>);

/// What each server session's driver returned.
pub type Ends = Arc<Mutex<Vec<Result<(), Error>>>>;

/// Serves every connection on `ln` with the test services.
pub fn serve_rust(ln: TcpListener, cfg: Config) -> (Errors, JoinHandle<()>, Ends) {
    let errors: Errors = Arc::new(Mutex::new(Vec::new()));
    let ends: Ends = Arc::new(Mutex::new(Vec::new()));
    let (e, d) = (errors.clone(), ends.clone());
    let h = tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = ln.accept().await else {
                return;
            };
            conn.set_nodelay(true).unwrap();
            let (sess, driver) = Session::server(conn, cfg.clone()).expect("server session");
            let d2 = d.clone();
            tokio::spawn(async move {
                let r = driver.await;
                d2.lock().unwrap().push(r);
            });
            let e2 = e.clone();
            tokio::spawn(async move {
                while let Ok(st) = sess.accept_stream().await {
                    let e3 = e2.clone();
                    let s2 = sess.clone();
                    tokio::spawn(async move {
                        if let Err(msg) = serve_stream(st, &s2).await {
                            e3.lock().unwrap().push(msg);
                        }
                    });
                }
                let _ = sess.close();
            });
        }
    });
    (errors, h, ends)
}

async fn read_line(st: &mut Stream) -> Result<String, String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = st
            .read(&mut b)
            .await
            .map_err(|e| format!("read command: {e}"))?;
        if n == 0 {
            return Err("EOF before the command".into());
        }
        if b[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
        line.push(b[0]);
        if line.len() > 256 {
            return Err("command line too long".into());
        }
    }
}

/// The twin of serve.go's `finLinger`: the wait before the FIN that follows
/// data sent after the client's FIN, because a Go client drops data it has
/// not read when both FINs meet (smux/stream.go:808-833).
const FIN_LINGER: Duration = Duration::from_millis(200);

async fn serve_stream(mut st: Stream, sess: &Session) -> Result<(), String> {
    let sid = st.id();
    let line = read_line(&mut st).await?;
    let f: Vec<&str> = line.split_whitespace().collect();
    let arg = |i: usize| f.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let result = match f.first().copied() {
        Some("ECHO") => {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                let n = st
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("sid={sid} echo read: {e}"))?;
                if n == 0 {
                    break;
                }
                st.write_all(&buf[..n])
                    .await
                    .map_err(|e| format!("sid={sid} echo write: {e}"))?;
            }
            tokio::time::sleep(FIN_LINGER).await;
            let _ = st.shutdown().await;
            Ok(())
        }
        Some("SINK") => {
            let (want, seed) = (arg(1), arg(2));
            let r = read_pattern(&mut st, seed, Duration::ZERO).await;
            let (reply, res) = match r {
                Ok(got) if got == want => (format!("OK {got}\n"), Ok(())),
                Ok(got) => (
                    format!("BAD got={got} want={want}\n"),
                    Err(format!("sid={sid} sink got {got}")),
                ),
                Err(e) => (format!("BAD {e}\n"), Err(format!("sid={sid} sink {e}"))),
            };
            let _ = st.write_all(reply.as_bytes()).await;
            tokio::time::sleep(FIN_LINGER).await;
            res
        }
        Some("SOURCE") => {
            let (n, seed) = (arg(1) as usize, arg(2));
            write_pattern(&mut st, n, seed)
                .await
                .map_err(|e| format!("sid={sid} source write: {e}"))?;
            let _ = st.shutdown().await;
            let mut sink = tokio::io::sink();
            let _ = tokio::io::copy(&mut st, &mut sink).await;
            Ok(())
        }
        Some("SLOWSINK") => {
            let (chunk, delay) = (arg(1) as usize, arg(2));
            let mut buf = vec![0u8; chunk.max(1)];
            let mut total = 0u64;
            loop {
                match st.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(e) => return Err(format!("sid={sid} slowsink: {e}")),
                }
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let _ = st.write_all(format!("OK {total}\n").as_bytes()).await;
            tokio::time::sleep(FIN_LINGER).await;
            Ok(())
        }
        Some("HOLD") => {
            sess.closed().await;
            Ok(())
        }
        Some("HALF") => {
            let mut sink = tokio::io::sink();
            let n = tokio::io::copy(&mut st, &mut sink)
                .await
                .map_err(|e| format!("sid={sid} half: {e}"))?;
            st.write_all(format!("GOT {n}\n").as_bytes())
                .await
                .map_err(|e| format!("sid={sid} half reply: {e}"))?;
            tokio::time::sleep(FIN_LINGER).await;
            let _ = st.shutdown().await;
            Ok(())
        }
        _ => Err(format!("sid={sid} unknown command {line:?}")),
    };
    let _ = st.close().await;
    result
}

// ---------------------------------------------------------------------------
// The tap: a TCP proxy that parses the frames going each way.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dir {
    C2S,
    S2C,
}

/// One frame seen on the wire (payload left out).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub dir: Dir,
    pub cmd: u8,
    pub sid: u32,
    pub len: u16,
    pub upd: Option<(u32, u32)>,
    pub at: Duration,
}

#[derive(Default)]
struct Parser {
    head: Vec<u8>,
    skip: usize,
    upd: Vec<u8>,
    pending: Option<Header>,
}

#[derive(Default)]
pub struct Trace {
    pub events: Vec<Event>,
    /// Payload sent per (direction, sid).
    written: BTreeMap<(Dir, u32), u64>,
    /// The last UPD seen per (direction of the UPD, sid): consumed, window.
    upd: BTreeMap<(Dir, u32), (u32, u32)>,
    /// The most a sender may have written, per (direction of the UPD, sid):
    /// the largest `consumed + window` of any UPD seen (or the initial
    /// window). The sender knows some prefix of the UPDs the tap forwarded,
    /// and a smaller later window does not take back what an earlier one
    /// allowed.
    limit: BTreeMap<(Dir, u32), u64>,
    /// The worst `written - limit` seen on any PSH (> 0 breaks the window).
    pub worst_excess: i64,
    /// The most bytes in flight seen on any stream, by sending direction.
    pub max_inflight: BTreeMap<Dir, u64>,
}

impl Trace {
    fn on(&mut self, ev: Event) {
        let other = match ev.dir {
            Dir::C2S => Dir::S2C,
            Dir::S2C => Dir::C2S,
        };
        if ev.cmd == Cmd::Psh as u8 {
            let w = self.written.entry((ev.dir, ev.sid)).or_default();
            *w += ev.len as u64;
            let (consumed, _) = self
                .upd
                .get(&(other, ev.sid))
                .copied()
                .unwrap_or((0, INITIAL_PEER_WINDOW));
            let inflight = (*w as u32).wrapping_sub(consumed) as u64;
            let limit = self
                .limit
                .get(&(other, ev.sid))
                .copied()
                .unwrap_or(INITIAL_PEER_WINDOW as u64);
            self.worst_excess = self.worst_excess.max(*w as i64 - limit as i64);
            let m = self.max_inflight.entry(ev.dir).or_default();
            *m = (*m).max(inflight);
        }
        if let Some((c, w)) = ev.upd {
            self.upd.insert((ev.dir, ev.sid), (c, w));
            let l = self
                .limit
                .entry((ev.dir, ev.sid))
                .or_insert(INITIAL_PEER_WINDOW as u64);
            *l = (*l).max(c as u64 + w as u64);
        }
        self.events.push(ev);
    }

    /// The frames of each stream in one direction, in order, keyed by the
    /// stream's place among the client's opens (sid 3 is 0, sid 5 is 1...),
    /// NOPs left out: the interleaving masked.
    pub fn per_stream(&self, dir: Dir) -> BTreeMap<u32, Vec<FrameSeen>> {
        let mut out: BTreeMap<u32, Vec<_>> = BTreeMap::new();
        for e in &self.events {
            if e.dir == dir && e.cmd != Cmd::Nop as u8 {
                let key = if e.sid % 2 == 1 {
                    (e.sid - 3) / 2
                } else {
                    1_000_000 + e.sid
                };
                out.entry(key).or_default().push((e.cmd, e.len, e.upd));
            }
        }
        out
    }

    pub fn count(&self, dir: Dir, cmd: Cmd) -> usize {
        self.events
            .iter()
            .filter(|e| e.dir == dir && e.cmd == cmd as u8)
            .count()
    }

    pub fn max_psh(&self, dir: Dir) -> u16 {
        self.events
            .iter()
            .filter(|e| e.dir == dir && e.cmd == Cmd::Psh as u8)
            .map(|e| e.len)
            .max()
            .unwrap_or(0)
    }
}

fn feed(p: &mut Parser, dir: Dir, mut data: &[u8], start: Instant, trace: &Mutex<Trace>) {
    while !data.is_empty() {
        if p.skip > 0 {
            let n = p.skip.min(data.len());
            p.skip -= n;
            data = &data[n..];
            continue;
        }
        if let Some(h) = p.pending {
            let need = 8 - p.upd.len();
            let n = need.min(data.len());
            p.upd.extend_from_slice(&data[..n]);
            data = &data[n..];
            if p.upd.len() == 8 {
                let u = decode_upd(p.upd[..8].try_into().unwrap());
                trace.lock().unwrap().on(Event {
                    dir,
                    cmd: h.cmd,
                    sid: h.sid,
                    len: h.length,
                    upd: Some(u),
                    at: start.elapsed(),
                });
                p.upd.clear();
                p.pending = None;
            }
            continue;
        }
        let need = HEADER_SIZE - p.head.len();
        let n = need.min(data.len());
        p.head.extend_from_slice(&data[..n]);
        data = &data[n..];
        if p.head.len() == HEADER_SIZE {
            let h = Header::decode(p.head[..].try_into().unwrap());
            p.head.clear();
            if h.cmd == Cmd::Upd as u8 && h.length == 8 {
                p.pending = Some(h);
            } else {
                trace.lock().unwrap().on(Event {
                    dir,
                    cmd: h.cmd,
                    sid: h.sid,
                    len: h.length,
                    upd: None,
                    at: start.elapsed(),
                });
                if h.cmd == Cmd::Psh as u8 {
                    p.skip = h.length as usize;
                }
            }
        }
    }
}

pub struct Tap {
    pub addr: SocketAddr,
    trace: Arc<Mutex<Trace>>,
    task: JoinHandle<()>,
}

impl Tap {
    /// Listens on loopback; the first connection is forwarded to `upstream`.
    pub async fn start(upstream: SocketAddr) -> Tap {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let t = trace.clone();
        let task = tokio::spawn(async move {
            let (down, _) = ln.accept().await.unwrap();
            let up = TcpStream::connect(upstream).await.unwrap();
            down.set_nodelay(true).unwrap();
            up.set_nodelay(true).unwrap();
            let start = Instant::now();
            let (mut dr, mut dw) = down.into_split();
            let (mut ur, mut uw) = up.into_split();
            let t1 = t.clone();
            let c2s = tokio::spawn(async move {
                let mut p = Parser::default();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match dr.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    // Recorded before it is forwarded: the trace never shows
                    // a server reacting to an update it has not seen yet.
                    feed(&mut p, Dir::C2S, &buf[..n], start, &t1);
                    if uw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = uw.shutdown().await;
            });
            let s2c = tokio::spawn(async move {
                let mut p = Parser::default();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match ur.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    feed(&mut p, Dir::S2C, &buf[..n], start, &t);
                    if dw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = dw.shutdown().await;
            });
            let _ = c2s.await;
            let _ = s2c.await;
        });
        Tap { addr, trace, task }
    }

    /// The trace so far.
    pub fn snapshot(&self) -> std::sync::MutexGuard<'_, Trace> {
        self.trace.lock().unwrap()
    }

    /// Waits for both directions to end and returns the trace.
    pub async fn finish(self) -> Trace {
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
        std::mem::take(&mut *self.trace.lock().unwrap())
    }
}

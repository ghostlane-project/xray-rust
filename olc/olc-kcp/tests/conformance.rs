// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Live conformance with the engine's own KCP (W31, W32): `olc-kcp` against
//! `startKCP` (vp8channel/kcp.go:138-190) at the pin, over UDP through a
//! chaos relay, data both ways at once, and a Go↔Go pair through the same
//! relay as the baseline.
//!
//! The Go side is the prebuilt peer named by `OLC_KCP_GO_PEER`
//! (olc/interop/build-kcp-peer.sh); without it these tests say so and pass,
//! and with `OLC_KCP_REQUIRE_GO_PEER=1` a missing peer fails them.
//!
//! Each datagram is a packet as vp8channel's kcpConn hands it to its lane:
//! a 36-byte epoch header, the KCP packet, its CRC-32C (W24's place, W28).
//! The relay delays every packet, drops some, holds some back so that later
//! ones overtake them, and blacks the path out both ways for a while once a
//! third of the bytes have crossed.
//!
//! The parity check (W32: throughput and recovery within ±15 % of Go↔Go) is
//! asserted on optimised builds only (`cargo test --release`); a debug build
//! runs the same transfers, checks every byte and prints the figures.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use olc_interop::Rng;
use olc_kcp::kcp::Counters;
use olc_kcp::message::{self, Reader, SendError};
use olc_kcp::{link, Config, Session, Stats};
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, watch};

const MIB: u64 = 1 << 20;
/// vp8channel's records are at most this (transport.go:56-57).
const MAX_MSG: usize = 61_440;
const HDR_LEN: usize = 36;
const SOCK_BUF: usize = 8 << 20;

// ---------------------------------------------------------------------------
// Bounds and the Go peer.

/// Aborts the test binary if it still runs after 15 minutes, so a hang cannot
/// hold the shared build box. Go peers exit when their stdin closes, which
/// the abort does too.
fn watchdog() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(900));
            eprintln!("WATCHDOG: the conformance tests still run after 900 s; aborting");
            std::process::abort();
        });
    });
}

fn go_peer() -> Option<PathBuf> {
    watchdog();
    match std::env::var_os("OLC_KCP_GO_PEER") {
        Some(p) if !p.is_empty() => {
            let p = PathBuf::from(p);
            assert!(p.is_file(), "OLC_KCP_GO_PEER={} is not a file", p.display());
            Some(p)
        }
        _ => {
            assert!(
                std::env::var("OLC_KCP_REQUIRE_GO_PEER").as_deref() != Ok("1"),
                "OLC_KCP_REQUIRE_GO_PEER=1 but OLC_KCP_GO_PEER is not set"
            );
            eprintln!(
                "SKIPPED: OLC_KCP_GO_PEER is not set; build the Go peer with \
                 olc/interop/build-kcp-peer.sh and point OLC_KCP_GO_PEER at it"
            );
            None
        }
    }
}

/// Which profile a side runs (vp8channel/kcp.go:17-36,76-106).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The phone: 512/512.
    Phone,
    /// An exit: 4096/4096.
    Server,
}

impl Role {
    fn config(self) -> Config {
        match self {
            Role::Phone => Config::vp8channel_constrained(),
            Role::Server => Config::vp8channel(4096, 4096),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Imp {
    Go,
    Rust,
}

/// What one side sends and expects.
#[derive(Debug, Clone, Copy)]
struct Plan {
    send: u64,
    send_seed: u64,
    recv: u64,
    recv_seed: u64,
}

/// One receiving side's figures (the Go peer's DONE line has the same).
#[derive(Debug, Clone, Copy, Default)]
struct Done {
    rx_bytes: u64,
    rx_msgs: u64,
    first_ms: u64,
    last_ms: u64,
    max_gap_ms: u64,
}

impl Done {
    fn from_json(v: &Value) -> Done {
        let f = |k: &str| {
            v[k].as_u64()
                .unwrap_or_else(|| panic!("DONE without {k}: {v}"))
        };
        Done {
            rx_bytes: f("rx_bytes"),
            rx_msgs: f("rx_msgs"),
            first_ms: f("first_ms"),
            last_ms: f("last_ms"),
            max_gap_ms: f("max_gap_ms"),
        }
    }

    /// Bytes per second from the first message to the last.
    fn rate(&self) -> f64 {
        self.rx_bytes as f64 / ((self.last_ms - self.first_ms).max(1) as f64 / 1000.0)
    }
}

/// A running `zz-olcrtc-kcppeer`.
struct GoPeer {
    child: Child,
    stdin: Option<ChildStdin>,
    addr: SocketAddr,
    lines: Arc<Mutex<Vec<String>>>,
}

impl GoPeer {
    fn start(bin: &Path, role: Role, peer: SocketAddr, plan: Plan) -> GoPeer {
        let mut cmd = Command::new(bin);
        cmd.args(["-listen", "127.0.0.1:0", "-peer", &peer.to_string()])
            .args([
                "-send",
                &plan.send.to_string(),
                "-send-seed",
                &plan.send_seed.to_string(),
            ])
            .args([
                "-recv",
                &plan.recv.to_string(),
                "-recv-seed",
                &plan.recv_seed.to_string(),
            ])
            .args(["-max-msg", &MAX_MSG.to_string()]);
        if role == Role::Phone {
            cmd.arg("-constrained");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the Go peer");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let keep = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                keep.lock().unwrap().push(line);
            }
        });
        let mut peer = GoPeer {
            child,
            stdin,
            addr: "0.0.0.0:0".parse().unwrap(),
            lines,
        };
        let first = peer.wait_line_blocking("LISTEN ", Duration::from_secs(10));
        peer.addr = first.parse().expect("the LISTEN address");
        peer
    }

    fn line(&self, prefix: &str) -> Option<String> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .find_map(|l| l.strip_prefix(prefix).map(str::to_string))
    }

    fn wait_line_blocking(&self, prefix: &str, limit: Duration) -> String {
        let end = Instant::now() + limit;
        loop {
            if let Some(l) = self.line(prefix) {
                return l;
            }
            assert!(
                Instant::now() < end,
                "no {prefix:?} line from the Go peer: {:?}",
                self.lines.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn failures(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("ERR") || l.starts_with("FATAL"))
            .cloned()
            .collect()
    }

    /// Closes stdin and returns the STATS line's JSON once the peer exits.
    fn finish(&mut self) -> Value {
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().expect("wait").is_none() {
            assert!(
                Instant::now() < end,
                "the Go peer did not exit after its stdin closed"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The reader thread may still be draining the pipe.
        let s = self.wait_line_blocking("STATS ", Duration::from_secs(2));
        serde_json::from_str(&s).expect("STATS json")
    }
}

impl Drop for GoPeer {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The workload: the Go peer's generator.

/// The next message of a generator: `1 + x mod MAX_MSG` bytes, then the
/// generator's values little-endian, eight bytes at a time.
fn next_message(g: &mut Rng) -> Vec<u8> {
    let n = 1 + (g.next_u64() % MAX_MSG as u64) as usize;
    let mut b = vec![0u8; n];
    for chunk in b.chunks_mut(8) {
        let w = g.next_u64().to_le_bytes();
        chunk.copy_from_slice(&w[..chunk.len()]);
    }
    b
}

fn udp(addr: &str) -> UdpSocket {
    let s =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).expect("socket");
    s.set_recv_buffer_size(SOCK_BUF).expect("SO_RCVBUF");
    s.set_send_buffer_size(SOCK_BUF).expect("SO_SNDBUF");
    s.set_nonblocking(true).expect("nonblocking");
    s.bind(&addr.parse::<SocketAddr>().unwrap().into())
        .expect("bind");
    UdpSocket::from_std(s.into()).expect("tokio socket")
}

// ---------------------------------------------------------------------------
// The Rust side: Session on a socket, driven on kcp-go's schedule.

#[derive(Debug, Default, Clone)]
struct RustReport {
    done: Option<Done>,
    error: Option<String>,
    stats: Stats,
    counters: Counters,
    peak_held: usize,
    corrupt: u64,
}

/// The receiving half: the stream read as startKCP's read loop reads it,
/// each message checked against the peer's generator.
struct Rx {
    reader: Reader,
    gen: Rng,
    want: u64,
    got: Done,
    last: Instant,
    start: Instant,
    done: Option<oneshot::Sender<Done>>,
}

impl Rx {
    /// Reads every whole message the session holds. Go's read loop runs
    /// beside KCP and drains its queue as it fills, so the window the next
    /// acknowledgement advertises is the one Go's would; this is called
    /// after every packet in for the same reason.
    fn drain(&mut self, sess: &mut Session, rep: &mut RustReport) {
        while rep.error.is_none() {
            match self.reader.next(sess) {
                Ok(Some(m)) => self.take(&m, rep),
                Ok(None) => return,
                Err(e) => rep.error = Some(format!("a length over the cap: {e:?}")),
            }
        }
    }

    fn take(&mut self, m: &[u8], rep: &mut RustReport) {
        let got = &mut self.got;
        if got.rx_bytes >= self.want {
            rep.error = Some(format!(
                "a message after every expected byte ({} bytes)",
                m.len()
            ));
            return;
        }
        let want = next_message(&mut self.gen);
        if m != want.as_slice() {
            rep.error = Some(format!(
                "message {}: {} bytes, want {}",
                got.rx_msgs,
                m.len(),
                want.len()
            ));
            return;
        }
        let t = Instant::now();
        let ms = t.duration_since(self.start).as_millis() as u64;
        if got.rx_msgs == 0 {
            got.first_ms = ms;
        } else {
            got.max_gap_ms = got
                .max_gap_ms
                .max(t.duration_since(self.last).as_millis() as u64);
        }
        self.last = t;
        got.rx_msgs += 1;
        got.rx_bytes += m.len() as u64;
        got.last_ms = ms;
        if got.rx_bytes >= self.want {
            rep.done = Some(*got);
            if let Some(d) = self.done.take() {
                let _ = d.send(*got);
            }
        }
    }
}

/// Writes the session's output queue to the socket.
async fn flush_out(
    sess: &mut Session,
    sock: &UdpSocket,
    peer: SocketAddr,
    wire: &mut Vec<u8>,
    rep: &mut RustReport,
) {
    let hdr: [u8; HDR_LEN] = std::array::from_fn(|i| 0x50 + i as u8);
    while let Some(p) = sess.peek_output() {
        wire.clear();
        link::wrap_into(wire, &hdr, p);
        if let Err(e) = sock.send_to(wire, peer).await {
            rep.error = Some(format!("send: {e}"));
            return;
        }
        sess.pop_output();
    }
}

/// Runs one session until `stop`, on kcp-go's schedule: `update` when its
/// interval is due; each packet in (CRC checked), the stream read and what
/// KCP answered written out before the next one, as kcp-go's ACK-no-delay
/// and the engine's read loop do; writes retried after every event (Go's
/// `Write` blocks on the window). `done` gets the receive figures once every
/// expected byte has arrived in order.
async fn rust_peer(
    role: Role,
    sock: UdpSocket,
    peer: SocketAddr,
    plan: Plan,
    done: oneshot::Sender<Done>,
    mut stop: watch::Receiver<bool>,
) -> RustReport {
    let start = Instant::now();
    let mut sess = Session::new(role.config(), start);
    let mut rx = Rx {
        reader: Reader::new(),
        gen: Rng::new(plan.recv_seed),
        want: plan.recv,
        got: Done::default(),
        last: start,
        start,
        done: Some(done),
    };
    let mut tx = Rng::new(plan.send_seed);
    let mut pending: Option<Vec<u8>> = None;
    let mut sent = 0u64;
    let mut rep = RustReport::default();
    let mut wire = Vec::with_capacity(2048);
    let mut buf = vec![0u8; 65_536];
    let mut next_tick = start;
    while rep.error.is_none() {
        let now = Instant::now();
        if now >= next_tick {
            let iv = sess.update(now);
            next_tick = now + Duration::from_millis(u64::from(iv));
        }
        while sent < plan.send {
            let m = pending.take().unwrap_or_else(|| next_message(&mut tx));
            match message::send(&mut sess, &m, now) {
                Ok(()) => sent += m.len() as u64,
                Err(SendError::WouldBlock) => {
                    pending = Some(m);
                    break;
                }
                Err(SendError::TooLarge) => unreachable!("messages are at most {MAX_MSG}"),
            }
        }
        rx.drain(&mut sess, &mut rep);
        flush_out(&mut sess, &sock, peer, &mut wire, &mut rep).await;
        rep.peak_held = rep.peak_held.max(sess.held_bytes());
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((mut n, _)) = r else { break };
                // This packet and whatever else has already arrived.
                for _ in 0..256 {
                    if n > HDR_LEN {
                        match link::unwrap(&buf[HDR_LEN..n]) {
                            Ok(k) => sess.input(k, Instant::now()),
                            Err(_) => rep.corrupt += 1,
                        }
                        rx.drain(&mut sess, &mut rep);
                        flush_out(&mut sess, &sock, peer, &mut wire, &mut rep).await;
                    }
                    match sock.try_recv_from(&mut buf) {
                        Ok((m, _)) => n = m,
                        Err(_) => break,
                    }
                }
                rep.peak_held = rep.peak_held.max(sess.held_bytes());
            }
            () = tokio::time::sleep_until(next_tick.into()) => {}
            _ = stop.changed() => break,
        }
    }
    rep.stats = sess.stats();
    rep.counters = sess.kcp().counters();
    rep
}

// ---------------------------------------------------------------------------
// The chaos relay.

#[derive(Debug, Clone, Copy)]
struct Chaos {
    /// One-way delay of every packet.
    delay: Duration,
    /// Share of packets dropped.
    loss: f64,
    /// Share of packets held back by `hold` more, so later ones overtake.
    reorder: f64,
    hold: Duration,
    /// Both ways dark this long once a third of the A→B bytes have crossed.
    blackout: Duration,
}

/// The W31 chaos profile: 10 % loss and 10 % reordered by 30 ms each way,
/// 20 ms each way, and a one-second blackout.
const CHAOS: Chaos = Chaos {
    delay: Duration::from_millis(20),
    loss: 0.10,
    reorder: 0.10,
    hold: Duration::from_millis(30),
    blackout: Duration::from_secs(1),
};

#[derive(Debug, Default)]
struct RelayStats {
    forwarded: [AtomicU64; 2],
    dropped: [AtomicU64; 2],
    held: [AtomicU64; 2],
    dark: [AtomicU64; 2],
    bytes_ab: AtomicU64,
}

struct Relay {
    stats: Arc<RelayStats>,
    blackout_at: Arc<Mutex<Option<Instant>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Relay {
    /// Relays between A (at `a`, talking to `pa`) and B (at `b`, talking to
    /// `pb`). The blackout starts once `trigger` A→B bytes have crossed.
    fn start(
        pa: Arc<UdpSocket>,
        pb: Arc<UdpSocket>,
        a: SocketAddr,
        b: SocketAddr,
        chaos: Chaos,
        seed: u64,
        trigger: u64,
    ) -> Relay {
        let stats = Arc::new(RelayStats::default());
        let blackout_at = Arc::new(Mutex::new(None));
        let tasks = vec![
            tokio::spawn(relay(
                pa.clone(),
                pb.clone(),
                b,
                chaos,
                Rng::new(seed),
                0,
                stats.clone(),
                blackout_at.clone(),
                trigger,
            )),
            tokio::spawn(relay(
                pb,
                pa,
                a,
                chaos,
                Rng::new(seed ^ 0x5555_AAAA_5555_AAAA),
                1,
                stats.clone(),
                blackout_at.clone(),
                trigger,
            )),
        ];
        Relay {
            stats,
            blackout_at,
            tasks,
        }
    }

    fn summary(&self) -> String {
        let s = &self.stats;
        let g = |a: &[AtomicU64; 2], i: usize| a[i].load(Ordering::Relaxed);
        format!(
            "a->b fwd {} drop {} held {} dark {}; b->a fwd {} drop {} held {} dark {}",
            g(&s.forwarded, 0),
            g(&s.dropped, 0),
            g(&s.held, 0),
            g(&s.dark, 0),
            g(&s.forwarded, 1),
            g(&s.dropped, 1),
            g(&s.held, 1),
            g(&s.dark, 1),
        )
    }
}

fn unit(rng: &mut Rng) -> f64 {
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

#[allow(clippy::too_many_arguments)]
async fn relay(
    rx: Arc<UdpSocket>,
    tx: Arc<UdpSocket>,
    to: SocketAddr,
    chaos: Chaos,
    mut rng: Rng,
    dir: usize,
    stats: Arc<RelayStats>,
    blackout_at: Arc<Mutex<Option<Instant>>>,
    trigger: u64,
) {
    let mut queue: BinaryHeap<Reverse<(Instant, u64, Vec<u8>)>> = BinaryHeap::new();
    let mut seq = 0u64;
    let mut buf = vec![0u8; 65_536];
    loop {
        let due = queue.peek().map(|Reverse((t, _, _))| *t);
        tokio::select! {
            r = rx.recv_from(&mut buf) => {
                let Ok((n, _)) = r else { return };
                let now = Instant::now();
                if dir == 0 {
                    let total = stats.bytes_ab.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                    let mut b = blackout_at.lock().unwrap();
                    if b.is_none() && total >= trigger {
                        *b = Some(now);
                    }
                }
                let dark = blackout_at
                    .lock()
                    .unwrap()
                    .is_some_and(|t| now >= t && now < t + chaos.blackout);
                if dark {
                    stats.dark[dir].fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if unit(&mut rng) < chaos.loss {
                    stats.dropped[dir].fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut at = now + chaos.delay;
                if unit(&mut rng) < chaos.reorder {
                    at += chaos.hold;
                    stats.held[dir].fetch_add(1, Ordering::Relaxed);
                }
                queue.push(Reverse((at, seq, buf[..n].to_vec())));
                seq += 1;
            }
            () = tokio::time::sleep_until(due.unwrap_or_else(Instant::now).into()), if due.is_some() => {
                let now = Instant::now();
                while queue.peek().is_some_and(|Reverse((t, _, _))| *t <= now) {
                    let Reverse((_, _, p)) = queue.pop().unwrap();
                    let _ = tx.send_to(&p, to).await;
                    stats.forwarded[dir].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// One run: A (the phone) and B (the server), N bytes each way at once.

#[derive(Debug)]
struct Run {
    /// A→B as B received it, and B→A as A received it.
    ab: Done,
    ba: Done,
    rust: Vec<(Role, RustReport)>,
    go_stats: Vec<(Role, Value)>,
    relay: String,
    blackout: bool,
}

enum Side {
    Go(GoPeer),
    Rust(tokio::task::JoinHandle<RustReport>, oneshot::Receiver<Done>),
}

async fn run(go: &Path, a_imp: Imp, b_imp: Imp, n: u64, seed: u64, chaos: Chaos) -> Run {
    let pa = Arc::new(udp("127.0.0.1:0"));
    let pb = Arc::new(udp("127.0.0.1:0"));
    let pa_addr = pa.local_addr().unwrap();
    let pb_addr = pb.local_addr().unwrap();
    let (stop_tx, stop_rx) = watch::channel(false);
    let plan_a = Plan {
        send: n,
        send_seed: seed * 2 + 1,
        recv: n,
        recv_seed: seed * 2 + 2,
    };
    let plan_b = Plan {
        send: n,
        send_seed: seed * 2 + 2,
        recv: n,
        recv_seed: seed * 2 + 1,
    };

    // Each side talks to its end of the relay; the relay learns their
    // addresses before any packet moves.
    let start = |imp: Imp, role: Role, relay_end: SocketAddr, plan: Plan| -> (Side, SocketAddr) {
        match imp {
            Imp::Go => {
                let p = GoPeer::start(go, role, relay_end, plan);
                let addr = p.addr;
                (Side::Go(p), addr)
            }
            Imp::Rust => {
                let sock = udp("127.0.0.1:0");
                let addr = sock.local_addr().unwrap();
                let (tx, rx) = oneshot::channel();
                let h = tokio::spawn(rust_peer(role, sock, relay_end, plan, tx, stop_rx.clone()));
                (Side::Rust(h, rx), addr)
            }
        }
    };
    // Both relay ends are bound first, so a side's first packets wait in
    // their buffers until the relay, which needs both sides' addresses, runs.
    let (b_side, b_addr) = start(b_imp, Role::Server, pb_addr, plan_b);
    let (a_side, a_addr) = start(a_imp, Role::Phone, pa_addr, plan_a);
    let relay = Relay::start(pa, pb, a_addr, b_addr, chaos, seed, n / 3);

    let wait = |side: Side| async move {
        match side {
            Side::Go(p) => {
                let end = Instant::now() + Duration::from_secs(120);
                loop {
                    if let Some(l) = p.line("DONE ") {
                        let d = Done::from_json(&serde_json::from_str(&l).unwrap());
                        return (d, Side::Go(p));
                    }
                    let f = p.failures();
                    assert!(f.is_empty(), "the Go peer: {f:?}");
                    assert!(
                        Instant::now() < end,
                        "the Go peer did not receive everything in 120 s"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            Side::Rust(h, rx) => {
                let d = tokio::time::timeout(Duration::from_secs(120), rx)
                    .await
                    .expect("the Rust side did not receive everything in 120 s")
                    .unwrap_or_else(|_| panic!("the Rust side ended early"));
                (d, Side::Rust(h, oneshot::channel::<Done>().1))
            }
        }
    };
    let ((ba, a_side), (ab, b_side)) = tokio::join!(wait(a_side), wait(b_side));

    let _ = stop_tx.send(true);
    let mut rust = Vec::new();
    let mut go_stats = Vec::new();
    for (role, side) in [(Role::Phone, a_side), (Role::Server, b_side)] {
        match side {
            Side::Go(mut p) => {
                go_stats.push((role, p.finish()));
                let f = p.failures();
                assert!(f.is_empty(), "the Go peer: {f:?}");
            }
            Side::Rust(h, _) => {
                let r = tokio::time::timeout(Duration::from_secs(10), h)
                    .await
                    .expect("the Rust side stops")
                    .unwrap();
                assert!(r.error.is_none(), "the Rust side: {:?}", r.error);
                rust.push((role, r));
            }
        }
    }
    let blackout = relay.blackout_at.lock().unwrap().is_some();
    let summary = relay.summary();
    drop(relay);
    Run {
        ab,
        ba,
        rust,
        go_stats,
        relay: summary,
        blackout,
    }
}

/// The phone's worst case (session.rs, Memory) with W = R = 512 and M = 45
/// segments a write (4 + 61,440 bytes): W − 1 + M sent and 2R − 1 received
/// segment buffers, plus the pool's 64 kept free, of 1476 bytes; the output
/// queue's 2048 packets and 64 kept free, of at most 1400; the read buffer.
fn phone_bound() -> usize {
    (512 - 1 + 45 + 2 * 512 - 1 + 64) * 1476 + (2048 + 64) * 1400 + 1500
}

fn check_rust(run: &Run) {
    for (role, r) in &run.rust {
        assert!(r.error.is_none(), "{role:?}: {:?}", r.error);
        assert_eq!(r.corrupt, 0, "{role:?}: the relay corrupts nothing");
        if *role == Role::Phone {
            assert!(
                r.peak_held <= phone_bound(),
                "{role:?} held {} bytes",
                r.peak_held
            );
        }
        assert!(
            r.counters.retrans_segs > 0,
            "{role:?}: nothing was resent under 10 % loss: {:?}",
            r.counters
        );
    }
}

fn print(label: &str, run: &Run) {
    eprintln!(
        "{label}: phone->server {:.2} MB/s gap {} ms ({} msgs); server->phone {:.2} MB/s gap {} ms ({} msgs); relay {}",
        run.ab.rate() / 1e6,
        run.ab.max_gap_ms,
        run.ab.rx_msgs,
        run.ba.rate() / 1e6,
        run.ba.max_gap_ms,
        run.ba.rx_msgs,
        run.relay
    );
    for (role, r) in &run.rust {
        eprintln!(
            "  rust {role:?}: peak held {} B, {:?}, {:?}",
            r.peak_held, r.stats, r.counters
        );
    }
    for (role, s) in &run.go_stats {
        eprintln!(
            "  go {role:?}: retrans {} lost {} fast {} out_segs {} corrupt {} dropped {}",
            s["retrans_segs"],
            s["lost_segs"],
            s["fast_retrans_segs"],
            s["out_segs"],
            s["corrupt"],
            s["dropped"]
        );
    }
}

// ---------------------------------------------------------------------------

/// The deployment: a Rust phone, a Go exit; 8 MiB each way at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_phone_and_go_server_both_ways_under_chaos() {
    let Some(go) = go_peer() else { return };
    let r = tokio::time::timeout(
        Duration::from_secs(240),
        run(&go, Imp::Rust, Imp::Go, 8 * MIB, 7, CHAOS),
    )
    .await
    .expect("the run ends");
    print("rust phone / go server", &r);
    assert!(r.blackout, "the blackout happened");
    check_rust(&r);
}

/// The other way round: a Go phone, a Rust server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_phone_and_rust_server_both_ways_under_chaos() {
    let Some(go) = go_peer() else { return };
    let r = tokio::time::timeout(
        Duration::from_secs(240),
        run(&go, Imp::Go, Imp::Rust, 8 * MIB, 8, CHAOS),
    )
    .await
    .expect("the run ends");
    print("go phone / rust server", &r);
    assert!(r.blackout, "the blackout happened");
    check_rust(&r);
}

/// The settings reach the wire: what the Go side reports after a run is
/// what `startKCP` set, and the Rust session's are the same (W32).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_go_sides_settings_after_a_run_are_ours() {
    let Some(go) = go_peer() else { return };
    let r = tokio::time::timeout(
        Duration::from_secs(240),
        run(&go, Imp::Go, Imp::Go, 2 * MIB, 9, CHAOS),
    )
    .await
    .expect("the run ends");
    for (role, s) in &r.go_stats {
        let ours = Session::new(role.config(), Instant::now());
        for k in [
            "conv",
            "mtu",
            "mss",
            "snd_wnd",
            "rcv_wnd",
            "interval",
            "nodelay",
            "rx_minrto",
            "fastresend",
            "nocwnd",
            "stream",
            "dead_link",
            "ackNoDelay",
            "writeDelay",
        ] {
            let want = ours
                .settings()
                .into_iter()
                .find(|(n, _)| *n == k)
                .unwrap()
                .1;
            assert_eq!(s["settings"][k].as_i64(), Some(want), "{role:?} {k}");
        }
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// W32: throughput (first to last message) and recovery (the longest wait
/// between two messages, the blackout included) of a Rust phone with a Go
/// exit, and of a Go phone with a Rust exit, within ±15 % of a Go phone with
/// a Go exit, each the median of five runs through the same chaos.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parity_with_go_under_chaos() {
    let Some(go) = go_peer() else { return };
    let seeds = [11u64, 12, 13, 14, 15];
    let mut table: Vec<(&str, Vec<Run>)> = Vec::new();
    for (label, a, b) in [
        ("go/go", Imp::Go, Imp::Go),
        ("rust/go", Imp::Rust, Imp::Go),
        ("go/rust", Imp::Go, Imp::Rust),
    ] {
        let mut runs = Vec::new();
        for s in seeds {
            let r =
                tokio::time::timeout(Duration::from_secs(240), run(&go, a, b, 8 * MIB, s, CHAOS))
                    .await
                    .expect("the run ends");
            print(label, &r);
            assert!(r.blackout);
            check_rust(&r);
            runs.push(r);
        }
        table.push((label, runs));
    }
    let fig = |runs: &[Run]| {
        (
            median(runs.iter().map(|r| r.ab.rate()).collect()),
            median(runs.iter().map(|r| r.ba.rate()).collect()),
            median(runs.iter().map(|r| r.ab.max_gap_ms as f64).collect()),
            median(runs.iter().map(|r| r.ba.max_gap_ms as f64).collect()),
        )
    };
    let base = fig(&table[0].1);
    let mut off = Vec::new();
    for (label, runs) in &table {
        let f = fig(runs);
        let ratio = (f.0 / base.0, f.1 / base.1, f.2 / base.2, f.3 / base.3);
        eprintln!(
            "PARITY {label}: phone->server {:.2} MB/s ({:.2}x), server->phone {:.2} MB/s ({:.2}x), \
             recovery phone->server {:.0} ms ({:.2}x), server->phone {:.0} ms ({:.2}x)",
            f.0 / 1e6, ratio.0, f.1 / 1e6, ratio.1, f.2, ratio.2, f.3, ratio.3
        );
        for (what, r) in [
            ("throughput p->s", ratio.0),
            ("throughput s->p", ratio.1),
            ("recovery p->s", ratio.2),
            ("recovery s->p", ratio.3),
        ] {
            if !(0.85..=1.15).contains(&r) {
                off.push(format!("{label} {what} {r:.2}x"));
            }
        }
    }
    if cfg!(debug_assertions) {
        eprintln!("PARITY: a debug build; not asserted (outside ±15 %: {off:?})");
    } else {
        assert!(off.is_empty(), "outside ±15 % of Go↔Go: {off:?}");
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The keepalive (port plan W16; smux/session.go:519-543): a NOP every
//! interval; a session closes when a whole timeout passes without a frame
//! from the peer, unless its reader is only waiting for tokens.
//!
//! Rust against Rust on tokio's paused clock, at the engine's real
//! settings; Rust against Go in real time, scaled to 100 ms / 300 ms; and,
//! ignored by default, the engine's real 45 s and 150 s idles against Go.

mod common;

use std::time::Duration;

use common::*;
use olc_smux::frame::Cmd;
use olc_smux::{
    Config, Error, HostClass, KeepAlive, Session, DATACHANNEL_MAX_PAYLOAD, VP8CHANNEL_MAX_PAYLOAD,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;

fn pair(client: Config, server: Config) -> (Session, Session, DriverHandle, DriverHandle) {
    watchdog();
    let (a, b) = tokio::io::duplex(1 << 20);
    let (c, cd) = Session::client(a, client).unwrap();
    let (s, sd) = Session::server(b, server).unwrap();
    (c, s, tokio::spawn(cd), tokio::spawn(sd))
}

fn silent() -> Config {
    let mut c = Config::client_data(DATACHANNEL_MAX_PAYLOAD, false);
    c.keep_alive = None;
    c
}

/// The data session on datachannel: 10 s / 30 s (internal/runtime/runtime.go:109-119).
fn data_cfg() -> Config {
    Config::client_data(DATACHANNEL_MAX_PAYLOAD, false)
}

#[tokio::test(start_paused = true)]
async fn nops_every_interval_keep_both_sides_open() {
    let (c, s, _cd, _sd) = pair(data_cfg(), data_cfg());
    tokio::time::sleep(Duration::from_secs(95)).await;
    let (cs, ss) = (c.stats(), s.stats());
    assert_eq!((cs.nop_out, cs.nop_in, ss.nop_out, ss.nop_in), (9, 9, 9, 9));
    assert!(!c.is_closed() && !s.is_closed());
    let mut a = c.open_stream().await.unwrap();
    let mut b = s.accept_stream().await.unwrap();
    a.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test(start_paused = true)]
async fn a_silent_peer_is_closed_after_one_timeout() {
    let t = Instant::now();
    let (c, s, _cd, sd) = pair(silent(), data_cfg());
    s.closed().await;
    // smux/session.go:530-537: the first timeout tick finds nothing received.
    assert_eq!(t.elapsed(), Duration::from_secs(30));
    assert_eq!(sd.await.unwrap(), Err(Error::Timeout));
    assert_eq!(s.close_reason(), Some(Error::Timeout));
    let e = c.accept_stream().await.unwrap_err();
    assert!(e.is_clean_eof(), "{e}");
}

#[tokio::test(start_paused = true)]
async fn one_frame_moves_the_close_to_the_next_tick() {
    let t = Instant::now();
    let (c, s, _cd, _sd) = pair(silent(), data_cfg());
    tokio::time::sleep(Duration::from_secs(5)).await;
    let _st = c.open_stream().await.unwrap();
    s.closed().await;
    assert_eq!(t.elapsed(), Duration::from_secs(60));
}

// smux/session.go:532-536: "recvLoop may block while bucket is 0, in this
// case, session should not be closed."
#[tokio::test(start_paused = true)]
async fn an_empty_bucket_keeps_the_session_open() {
    let mut server = data_cfg();
    server.max_receive_buffer = 65536;
    server.max_stream_buffer = 65536;
    let (c, s, _cd, _sd) = pair(silent(), server);
    let mut a = c.open_stream().await.unwrap();
    let data = vec![1u8; 100_000];
    a.write_all(&data).await.unwrap();
    a.flush().await.unwrap();
    let mut b = s.accept_stream().await.unwrap();
    tokio::time::sleep(Duration::from_secs(200)).await;
    assert!(!s.is_closed());
    assert!(s.stats().bucket <= 0);
    let mut got = 0;
    let mut buf = vec![0u8; 65536];
    while got < 100_000 {
        got += b.read(&mut buf).await.unwrap();
    }
    let t = Instant::now();
    s.closed().await;
    assert!(t.elapsed() <= Duration::from_secs(60), "{:?}", t.elapsed());
}

// internal/runtime/runtime.go:210: KeepAliveDisabled on the control session.
#[tokio::test(start_paused = true)]
async fn the_control_session_sends_no_nop() {
    let cfg = Config::control(VP8CHANNEL_MAX_PAYLOAD);
    let (c, s, _cd, _sd) = pair(cfg.clone(), cfg);
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert_eq!((c.stats().nop_out, s.stats().nop_out), (0, 0));
    assert!(!c.is_closed() && !s.is_closed());
}

// ---------------------------------------------------------------------------
// Against Go, scaled.

fn scaled() -> Config {
    let mut c = Config::client_data(VP8CHANNEL_MAX_PAYLOAD, true);
    c.keep_alive = Some(KeepAlive {
        interval: Duration::from_millis(100),
        timeout: Duration::from_millis(300),
    });
    c
}

fn silent_scaled() -> Config {
    let mut c = scaled();
    c.keep_alive = None;
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_server_and_rust_client_keep_each_other_alive() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &scaled());
    let tap = Tap::start(server.addr).await;
    let t = std::time::Instant::now();
    let (sess, d) = connect(tap.addr, scaled()).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!sess.is_closed());
    assert!(
        server.lines().iter().all(|l| !l.starts_with("SESSION END")),
        "{:?}",
        server.lines()
    );
    script_echo(&sess, 4096).await.unwrap();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    let ticks = (t.elapsed().as_millis() / 100) as usize;
    let trace = tap.finish().await;
    let (c2s, s2c) = (
        trace.count(Dir::C2S, Cmd::Nop),
        trace.count(Dir::S2C, Cmd::Nop),
    );
    eprintln!("KEEPALIVE scaled {ticks} intervals: nop c2s={c2s} s2c={s2c}");
    // One NOP per interval each way (smux/session.go:527-529), give or take
    // the tick at either end and a late scheduler.
    assert!(ticks >= 15, "{ticks}");
    assert!((ticks - 3..=ticks + 1).contains(&c2s), "{c2s} in {ticks}");
    assert!((ticks - 3..=ticks + 1).contains(&s2c), "{s2c} in {ticks}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_server_closes_a_silent_rust_client() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &scaled());
    let t = std::time::Instant::now();
    let (sess, d) = connect(server.addr, silent_scaled()).await;
    let e = tokio::time::timeout(Duration::from_secs(3), sess.accept_stream())
        .await
        .expect("the Go server closes the session")
        .unwrap_err();
    let after = t.elapsed();
    eprintln!("KEEPALIVE Go server closed the silent Rust client after {after:?}: {e}");
    assert!(
        (Duration::from_millis(250)..=Duration::from_millis(900)).contains(&after),
        "{after:?}"
    );
    assert!(server
        .wait_line("SESSION END", Duration::from_secs(1))
        .await
        .is_some());
    sess.close().unwrap();
    let _ = d.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_server_closes_a_silent_go_client() {
    let Some(peer) = go_peer() else { return };
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let mut server = scaled();
    server.max_receive_buffer = 32 << 20;
    server.max_stream_buffer = 4 << 20;
    let (_errors, _task, ends) = serve_rust(ln, server);
    let run = go_dial(
        &peer,
        addr,
        "idle-silent",
        &silent_scaled(),
        &["-idle", "3s"],
    )
    .await;
    assert!(run.ok, "{:?}", run.lines);
    let line = run
        .line("CLOSED_AFTER")
        .expect("CLOSED_AFTER line")
        .to_string();
    let ms: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    eprintln!("KEEPALIVE Rust server closed the silent Go client: {line}");
    assert!((250..=900).contains(&ms), "{line}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(ends.lock().unwrap().as_slice(), &[Err(Error::Timeout)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_server_and_go_client_keep_each_other_alive() {
    let Some(peer) = go_peer() else { return };
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let (errors, _task, _ends) = serve_rust(ln, scaled());
    let run = go_dial(&peer, addr, "idle", &scaled(), &["-idle", "1500ms"]).await;
    assert!(run.ok, "{:?}", run.lines);
    assert!(errors.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_session_sends_no_nop_to_go() {
    let Some(peer) = go_peer() else { return };
    let cfg = Config::control(VP8CHANNEL_MAX_PAYLOAD);
    let server = GoServer::start(&peer, &cfg);
    let tap = Tap::start(server.addr).await;
    let (sess, d) = connect(tap.addr, cfg).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    script_echo(&sess, 4096).await.unwrap();
    sess.close().unwrap();
    let _ = d.await;
    let trace = tap.finish().await;
    assert_eq!(trace.count(Dir::C2S, Cmd::Nop), 0);
    assert_eq!(trace.count(Dir::S2C, Cmd::Nop), 0);
}

// ---------------------------------------------------------------------------
// The engine's real timings against Go (W16): run with --ignored.

async fn real_idle(client: Config, server: Config, idle: Duration) -> (usize, usize) {
    let peer = go_peer().expect("the long keepalive tests need OLC_SMUX_GO_PEER");
    let server = GoServer::start(&peer, &server);
    let tap = Tap::start(server.addr).await;
    let (sess, d) = connect(tap.addr, client).await;
    tokio::time::sleep(idle).await;
    assert!(!sess.is_closed());
    assert!(
        server.lines().iter().all(|l| !l.starts_with("SESSION END")),
        "{:?}",
        server.lines()
    );
    script_echo(&sess, 64 * 1024).await.unwrap();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    let trace = tap.finish().await;
    (
        trace.count(Dir::C2S, Cmd::Nop),
        trace.count(Dir::S2C, Cmd::Nop),
    )
}

/// datachannel: keepalive 10 s / 30 s; 45 s idle, and the session holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "45 s real time; run with --ignored"]
async fn datachannel_session_holds_45s_idle() {
    let client = Config::client_data(DATACHANNEL_MAX_PAYLOAD, false);
    let server = Config::data(HostClass::Server, DATACHANNEL_MAX_PAYLOAD, false);
    let (c2s, s2c) = real_idle(client, server, Duration::from_secs(45)).await;
    eprintln!("KEEPALIVE datachannel 45s: nop c2s={c2s} s2c={s2c}");
    assert_eq!((c2s, s2c), (4, 4));
}

/// vp8channel: keepalive 10 s / 120 s; 150 s idle, and the session holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "150 s real time; run with --ignored"]
async fn vp8channel_session_holds_150s_idle() {
    let client = Config::client_data(VP8CHANNEL_MAX_PAYLOAD, true);
    let server = Config::data(HostClass::Server, VP8CHANNEL_MAX_PAYLOAD, true);
    let (c2s, s2c) = real_idle(client, server, Duration::from_secs(150)).await;
    eprintln!("KEEPALIVE vp8channel 150s: nop c2s={c2s} s2c={s2c}");
    assert_eq!((c2s, s2c), (15, 15));
}

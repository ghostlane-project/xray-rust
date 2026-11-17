// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Live interop over loopback TCP with smux v1.5.57, both ways: the Rust
//! client against the Go server, and the Go client against the Rust server.
//! The Go side is the prebuilt peer named by `OLC_SMUX_GO_PEER`
//! (olc/interop/smux/go); without it these tests say so and pass.

mod common;

use std::time::Duration;

use common::*;
use olc_smux::frame::Cmd;
use olc_smux::{
    Config, HostClass, DATACHANNEL_MAX_PAYLOAD, SMUX_WIRE_OVERHEAD, VP8CHANNEL_MAX_PAYLOAD,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const MIB: usize = 1 << 20;
const KIB: usize = 1 << 10;

/// The exit's data session (internal/runtime/runtime.go:34-36,129-152).
fn exit_cfg() -> Config {
    Config::data(HostClass::Server, VP8CHANNEL_MAX_PAYLOAD, true)
}

/// The phone's data session (internal/runtime/runtime.go:46-47; mobile/runtime.go:75-91).
fn phone_cfg() -> Config {
    Config::client_data(VP8CHANNEL_MAX_PAYLOAD, true)
}

fn assert_no_go_errors(server: &GoServer) {
    let errs = server.errors();
    assert!(errs.is_empty(), "the Go server reported: {errs:?}");
}

// ---------------------------------------------------------------------------
// Rust client, Go server.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_client_go_server_echo() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    script_echo(&sess, 4 * MIB).await.unwrap();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_no_go_errors(&server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_client_go_server_many_streams_both_ways() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    script_many(&sess, 8, 4 * MIB).await.unwrap();
    let st = sess.stats();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_no_go_errors(&server);
    // 32 MiB each way through 16 streams, never above the phone's bucket.
    assert!(st.peak_rx_buffered <= 4 * MIB + 32768, "{st:?}");
    assert!(st.peak_tx_queued <= 16 * 32768, "{st:?}");
    eprintln!("MANY rust->go {st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_client_go_server_slow_reader_both_sides() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    // The Go server reads 4 KiB a millisecond: our writes stall on its window
    // and resume. We read 32 KiB every 5 ms: its writes stall on ours.
    let (_, source_peak) = script_slow(&sess, 2 * MIB, Duration::from_millis(5))
        .await
        .unwrap();
    let st = sess.stats();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_no_go_errors(&server);
    assert!(source_peak <= 512 * KIB, "slow stream held {source_peak}");
    assert!(st.peak_rx_buffered <= 512 * KIB + 32768, "{st:?}");
    eprintln!("SLOW rust->go source_peak={source_peak} {st:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_client_go_server_half_close() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    script_half(&sess, MIB).await.unwrap();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_no_go_errors(&server);
}

/// smux v1.5.57 drops a stream's unread data once both sides have sent FIN
/// (smux/stream.go:808-833 with smux/session.go:357-374). This pins what the
/// Rust client meets on the exits: a Go server that half-closed and reads
/// late loses the client's last data when the client's FIN comes with it,
/// and keeps it when the FIN comes after the server read. A Go client meets
/// the same; olc-smux itself keeps such data
/// (tests/semantics.rs, close_and_half_close_follow_go).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_go_server_that_half_closed_drops_data_that_comes_with_the_fin() {
    let Some(peer) = go_peer() else { return };
    let server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    let mut byte = [0u8; 1];
    // The FIN right after the data: lost.
    let mut st = command(&sess, "LATE 300").await;
    assert_eq!(st.read(&mut byte).await.unwrap(), 0, "the server's FIN");
    st.write_all(&[7u8; 1000]).await.unwrap();
    st.shutdown().await.unwrap();
    let with_fin = server
        .wait_line(&format!("LATE sid={} ", st.id()), Duration::from_secs(5))
        .await;
    // The FIN after the server read: kept.
    let mut st2 = command(&sess, "LATE 300").await;
    assert_eq!(st2.read(&mut byte).await.unwrap(), 0, "the server's FIN");
    st2.write_all(&[7u8; 1000]).await.unwrap();
    st2.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    st2.shutdown().await.unwrap();
    let after_read = server
        .wait_line(&format!("LATE sid={} ", st2.id()), Duration::from_secs(5))
        .await;
    eprintln!("LATE with the FIN: {with_fin:?}; FIN after the read: {after_read:?}");
    assert!(with_fin.unwrap().contains(" got=0 "));
    assert!(after_read.unwrap().contains(" got=1000 "));
    drop((st, st2));
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_no_go_errors(&server);
}

/// The Go server goes away: readers see EOF, Accept fails, the session can
/// be closed, and the driver reports the connection's end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rust_client_sees_the_go_server_go_away() {
    let Some(peer) = go_peer() else { return };
    let mut server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    let mut hold = command(&sess, "HOLD").await;
    server
        .wait_line("SESSION START", Duration::from_secs(5))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.kill();
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(5), hold.read(&mut buf))
        .await
        .expect("a reader is not left hanging");
    assert!(matches!(r, Ok(0) | Err(_)), "{r:?}");
    let e = tokio::time::timeout(Duration::from_secs(5), sess.accept_stream())
        .await
        .expect("accept is not left hanging")
        .unwrap_err();
    eprintln!("GO AWAY: read={r:?} accept={e}");
    sess.close().unwrap();
    assert!(d.await.unwrap().is_err());
}

/// On datachannel (12 KiB messages) frames are cut to 12236 bytes, so that
/// one OLC2 record of one frame fits one message
/// (internal/runtime/runtime.go:219-226).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn datachannel_frames_fit_one_message() {
    let Some(peer) = go_peer() else { return };
    let client = Config::client_data(DATACHANNEL_MAX_PAYLOAD, false);
    assert_eq!(client.max_frame_size, 12236);
    let server = GoServer::start(
        &peer,
        &Config::data(HostClass::Server, DATACHANNEL_MAX_PAYLOAD, false),
    );
    let tap = Tap::start(server.addr).await;
    let (sess, d) = connect(tap.addr, client).await;
    script_echo(&sess, 2 * MIB).await.unwrap();
    script_many(&sess, 2, 512 * KIB).await.unwrap();
    sess.close().unwrap();
    assert_eq!(d.await.unwrap(), Ok(()));
    let trace = tap.finish().await;
    assert_no_go_errors(&server);
    assert_eq!(trace.max_psh(Dir::C2S), 12236);
    assert_eq!(trace.max_psh(Dir::S2C), 12236);
    const { assert!(12236 + SMUX_WIRE_OVERHEAD <= DATACHANNEL_MAX_PAYLOAD) };
    assert_eq!(trace.worst_excess.max(0), 0, "a window was overrun");
    eprintln!(
        "DATACHANNEL psh c2s={} s2c={} max={}",
        trace.count(Dir::C2S, Cmd::Psh),
        trace.count(Dir::S2C, Cmd::Psh),
        trace.max_psh(Dir::C2S)
    );
}

// ---------------------------------------------------------------------------
// Go client, Rust server.

async fn rust_server(cfg: Config) -> (std::net::SocketAddr, Errors) {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let (errors, _task, _ends) = serve_rust(ln, cfg);
    (addr, errors)
}

async fn go_client_script(script: &str, extra: &[&str]) {
    let Some(peer) = go_peer() else { return };
    let (addr, errors) = rust_server(exit_cfg()).await;
    let run = go_dial(&peer, addr, script, &phone_cfg(), extra).await;
    assert!(run.ok, "Go client script {script} failed: {:?}", run.lines);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let errs = errors.lock().unwrap().clone();
    assert!(errs.is_empty(), "the Rust server reported: {errs:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_rust_server_echo() {
    go_client_script("echo", &["-size", "4194304"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_rust_server_many_streams_both_ways() {
    go_client_script("many", &["-streams", "8", "-size", "4194304"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_rust_server_slow_reader_both_sides() {
    go_client_script("slow", &["-size", "2097152", "-slow-ms", "5"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_rust_server_half_close() {
    go_client_script("half", &["-size", "1048576"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_rust_server_window_workload() {
    go_client_script(
        "window",
        &["-streams", "8", "-size", "2097152", "-slow-ms", "2"],
    )
    .await;
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Window conformance with smux v1.5.57 (port plan W15 and W17): the update
//! cadence, the windows each side honours, and the memory the phone's
//! buffers allow, measured on the wire through a tap.

mod common;

use std::time::Duration;

use common::*;
use olc_smux::frame::Cmd;
use olc_smux::{Config, HostClass, Session, Stream, POOL_CHUNK_SIZE, VP8CHANNEL_MAX_PAYLOAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MIB: usize = 1 << 20;
const KIB: usize = 1 << 10;
const FRAME: usize = 32768;

fn exit_cfg() -> Config {
    Config::data(HostClass::Server, VP8CHANNEL_MAX_PAYLOAD, true)
}

fn phone_cfg() -> Config {
    Config::client_data(VP8CHANNEL_MAX_PAYLOAD, true)
}

/// The UPDs a reader sends for `size` bytes arriving in whole `frame`s and
/// read one frame per read: smux/stream.go:277-285.
fn expected_upds(size: usize, frame: usize, stream_buffer: usize) -> Vec<(u32, u32)> {
    let threshold = stream_buffer / 2;
    let (mut read, mut incr, mut out) = (0usize, 0usize, Vec::new());
    while read < size {
        let n = frame.min(size - read);
        read += n;
        incr += n;
        if incr >= threshold || read == n {
            out.push((read as u32, stream_buffer as u32));
            incr = 0;
        }
    }
    out
}

async fn wait_for(
    sess: &Session,
    what: &str,
    cond: impl Fn(&olc_smux::Stats) -> bool,
) -> olc_smux::Stats {
    let end = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let st = sess.stats();
        if cond(&st) {
            return st;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "timed out waiting for {what}: {st:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// W15: 24 streams of 5 MiB from the Go server, read with 32 KiB buffers,
/// every second one slowly. The Rust client sends the same UPDs at the same
/// points as the Go client does (compared stream by stream, interleaving
/// masked), both senders stay inside the windows, and the phone's buffers
/// bound what Rust holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w15_v2_window_conformance() {
    let Some(peer) = go_peer() else { return };
    const N: usize = 24;
    const SIZE: usize = 5 * MIB;
    let client = phone_cfg();

    let server = GoServer::start(&peer, &exit_cfg());
    let tap = Tap::start(server.addr).await;
    let (sess, d) = connect(tap.addr, client.clone()).await;
    let t = std::time::Instant::now();
    let peaks = script_window(&sess, N, SIZE, Duration::from_millis(5))
        .await
        .unwrap();
    let rust_time = t.elapsed();
    let stats = sess.stats();
    sess.close().unwrap();
    let _ = d.await;
    let rust = tap.finish().await;
    let errs = server.errors();
    assert!(errs.is_empty(), "{errs:?}");

    let server = GoServer::start(&peer, &exit_cfg());
    let tap = Tap::start(server.addr).await;
    let t = std::time::Instant::now();
    let run = go_dial(
        &peer,
        tap.addr,
        "window",
        &client,
        &["-streams", "24", "-size", "5242880", "-slow-ms", "5"],
    )
    .await;
    let go_time = t.elapsed();
    assert!(run.ok, "{:?}", run.lines);
    let go = tap.finish().await;

    // The cadence: the first read, then every 256 KiB read (half the phone's
    // 512 KiB stream buffer), each carrying the window 524288.
    let want = expected_upds(SIZE, FRAME, 512 * KIB);
    assert_eq!(want.len(), 20);
    assert_eq!(want[0], (32768, 524288));
    assert_eq!(want[1], (32768 + 262144, 524288));
    let rust_c2s = rust.per_stream(Dir::C2S);
    assert_eq!(rust_c2s.len(), N);
    for (i, frames) in &rust_c2s {
        let upds: Vec<_> = frames.iter().filter_map(|f| f.2).collect();
        assert_eq!(upds, want, "stream {i}");
        assert_eq!(frames.first().map(|f| f.0), Some(Cmd::Syn as u8));
        assert_eq!(frames.last().map(|f| f.0), Some(Cmd::Fin as u8));
    }
    // Stream by stream, both directions, the frames are the Go client's.
    assert_eq!(
        rust_c2s,
        go.per_stream(Dir::C2S),
        "client frames differ from smux's"
    );
    assert_eq!(
        rust.per_stream(Dir::S2C),
        go.per_stream(Dir::S2C),
        "server frames differ"
    );
    // Every frame stayed inside the receiver's last window.
    assert!(rust.worst_excess <= 0, "excess {}", rust.worst_excess);
    assert!(go.worst_excess <= 0, "excess {}", go.worst_excess);
    // Memory: the bucket plus one frame; a stream at most its window.
    assert!(stats.peak_rx_buffered <= 4 * MIB + FRAME, "{stats:?}");
    for (i, p) in peaks.iter().enumerate() {
        assert!(*p <= 512 * KIB, "stream {i} held {p}");
    }
    // The pool: payload plus 2 bytes a frame plus at most two partly used
    // chunks per stream, for received and queued data.
    let frames = (4 * MIB + FRAME) / FRAME + N;
    let bound = 4 * MIB + FRAME + 2 * frames + 3 * N * POOL_CHUNK_SIZE;
    assert!(stats.peak_pool_in_use <= bound, "{stats:?} bound {bound}");
    eprintln!(
        "W15 rust={rust_time:?} go={go_time:?} upd_per_stream={} max_inflight_s2c rust={:?} go={:?} \
         peak_rx={} peak_pool={} bound={bound} peaks_max={} {stats:?}",
        want.len(),
        rust.max_inflight.get(&Dir::S2C),
        go.max_inflight.get(&Dir::S2C),
        stats.peak_rx_buffered,
        stats.peak_pool_in_use,
        peaks.iter().max().unwrap()
    );
}

/// W17: 16 streams of 2 MiB that nobody reads. Each takes the initial
/// window, 256 KiB, and together they take the whole 4 MiB bucket: the
/// session stops reading, the Go server stalls on its windows without an
/// error, and nothing grows. Then every reader starts, and all the data
/// arrives within the same bounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w17_phone_buffers_hold_with_stalled_readers() {
    let Some(peer) = go_peer() else { return };
    const N: usize = 16;
    const SIZE: usize = 2 * MIB;
    let server = GoServer::start(&peer, &exit_cfg());
    let (sess, d) = connect(server.addr, phone_cfg()).await;
    let mut streams = Vec::new();
    for i in 0..N {
        streams.push(command(&sess, &format!("SOURCE {SIZE} {}", 400 + i)).await);
    }
    let full = wait_for(&sess, "the bucket to run out", |s| s.bucket <= 0).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let later = sess.stats();
    assert_eq!(full.rx_buffered, 4 * MIB, "{full:?}");
    assert_eq!(later.rx_buffered, 4 * MIB, "{later:?}");
    for st in &streams {
        assert_eq!(st.stats().rx_buffered, 262_144);
    }
    assert!(server.errors().is_empty());
    let mut tasks = Vec::new();
    for (i, mut st) in streams.into_iter().enumerate() {
        tasks.push(tokio::spawn(async move {
            let got = read_pattern(&mut st, 400 + i as u64, Duration::ZERO)
                .await
                .unwrap();
            let peak = st.stats().peak_rx_buffered;
            let _ = st.close().await;
            (got, peak)
        }));
    }
    for t in tasks {
        let (got, peak) = t.await.unwrap();
        assert_eq!(got, SIZE as u64);
        assert!(peak <= 512 * KIB, "a stream held {peak}");
    }
    let end = wait_for(&sess, "the pool to empty", |s| s.pool_in_use == 0).await;
    sess.close().unwrap();
    let _ = d.await;
    assert!(server.errors().is_empty(), "{:?}", server.errors());
    assert!(end.peak_rx_buffered <= 4 * MIB + FRAME, "{end:?}");
    eprintln!("W17 stalled={full:?} end={end:?}");
}

/// W17, the control session (internal/runtime/runtime.go:206-217): 256 KiB
/// in all, 32 KiB a stream, no keepalive. One unread stream takes the
/// whole bucket with the initial 256 KiB window; another stream then waits
/// until it is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w17_control_session_buffers() {
    let Some(peer) = go_peer() else { return };
    let cfg = Config::control(VP8CHANNEL_MAX_PAYLOAD);
    let server = GoServer::start(&peer, &cfg);
    let tap = Tap::start(server.addr).await;
    let (sess, d) = connect(tap.addr, cfg.clone()).await;
    let mut big = command(&sess, &format!("SOURCE {MIB} 600")).await;
    let full = wait_for(&sess, "the control bucket to run out", |s| s.bucket <= 0).await;
    assert_eq!(full.rx_buffered, 256 * KIB);
    let mut probe = command(&sess, "ECHO").await;
    probe.write_all(&pattern(100, 1)).await.unwrap();
    let mut buf = [0u8; 100];
    assert!(
        tokio::time::timeout(Duration::from_millis(500), probe.read_exact(&mut buf))
            .await
            .is_err(),
        "the probe was served with the bucket empty"
    );
    let reader = tokio::spawn(async move {
        let got = read_pattern(&mut big, 600, Duration::from_millis(1))
            .await
            .unwrap();
        let peak = big.stats().peak_rx_buffered;
        (got, peak)
    });
    probe.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf[..], &pattern(100, 1)[..]);
    let (got, peak) = reader.await.unwrap();
    assert_eq!(got, MIB as u64);
    assert!(peak <= 256 * KIB);
    let _ = probe.close().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(server.errors().is_empty(), "{:?}", server.errors());
    let st = sess.stats();
    sess.close().unwrap();
    let _ = d.await;
    let trace = tap.finish().await;
    assert!(st.peak_rx_buffered <= 256 * KIB + FRAME, "{st:?}");
    // Once read, the stream announces 32 KiB, and the Go sender keeps to it.
    let upds: Vec<_> = trace.per_stream(Dir::C2S)[&0]
        .iter()
        .filter_map(|f| f.2)
        .collect();
    assert_eq!(upds, expected_upds(MIB, FRAME, 32 * KIB));
    assert!(trace.worst_excess <= 0);
    assert_eq!(trace.count(Dir::C2S, Cmd::Nop), 0);
    eprintln!("W17 control {st:?} upds={}", upds.len());
}

async fn hol_probe(peer: &std::path::Path, recv: usize, stream: usize, unread: usize) -> bool {
    let server = GoServer::start(peer, &exit_cfg());
    let mut cfg = phone_cfg();
    cfg.max_receive_buffer = recv;
    cfg.max_stream_buffer = stream;
    let (sess, d) = connect(server.addr, cfg).await;
    let mut held: Vec<Stream> = Vec::new();
    for i in 0..unread {
        held.push(command(&sess, &format!("SOURCE 262144 {}", 500 + i)).await);
    }
    let want = (unread * 262_144).min(recv);
    wait_for(&sess, "the unread streams to fill", |s| {
        s.rx_buffered >= want
    })
    .await;
    let mut probe = command(&sess, "ECHO").await;
    probe.write_all(&pattern(4096, 2)).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let served = tokio::time::timeout(Duration::from_secs(1), probe.read_exact(&mut buf))
        .await
        .is_ok();
    // End the echo service before the session, so that it sees its EOF.
    let _ = probe.close().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    sess.close().unwrap();
    let _ = d.await;
    assert!(server.errors().is_empty(), "{:?}", server.errors());
    served
}

/// The phone's buffers against the memory model's smaller ones (05 §16:
/// 512 KiB / 128 KiB). A stream whose app does not read holds the initial
/// window, 256 KiB. With 512 KiB in all, two such streams stop the whole
/// session (every other stream waits); with 4 MiB it takes sixteen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_model_buffers_and_head_of_line() {
    let Some(peer) = go_peer() else { return };
    let cases = [
        (512 * KIB, 128 * KIB, 1, true),
        (512 * KIB, 128 * KIB, 2, false),
        (4 * MIB, 512 * KIB, 15, true),
        (4 * MIB, 512 * KIB, 16, false),
    ];
    for (recv, stream, unread, served) in cases {
        let got = hol_probe(&peer, recv, stream, unread).await;
        eprintln!("HOL recv={recv} stream={stream} unread={unread} probe_served={got}");
        assert_eq!(got, served, "recv={recv} stream={stream} unread={unread}");
    }
}

/// What the Go server sees from a client with the memory model's buffers:
/// the window it may fill is 128 KiB instead of 512 KiB, and the client
/// sends an update every 64 KiB read, four times as many.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_model_buffers_as_the_server_sees_them() {
    let Some(peer) = go_peer() else { return };
    let mut out = Vec::new();
    for (recv, stream) in [(4 * MIB, 512 * KIB), (512 * KIB, 128 * KIB)] {
        let server = GoServer::start(&peer, &exit_cfg());
        let tap = Tap::start(server.addr).await;
        let mut cfg = phone_cfg();
        cfg.max_receive_buffer = recv;
        cfg.max_stream_buffer = stream;
        let (sess, d) = connect(tap.addr, cfg).await;
        let t = std::time::Instant::now();
        let mut st = command(&sess, &format!("SOURCE {} 700", 5 * MIB)).await;
        let got = read_pattern(&mut st, 700, Duration::ZERO).await.unwrap();
        let took = t.elapsed();
        assert_eq!(got, 5 * MIB as u64);
        let _ = st.close().await;
        sess.close().unwrap();
        let _ = d.await;
        let trace = tap.finish().await;
        let upds: Vec<_> = trace.per_stream(Dir::C2S)[&0]
            .iter()
            .filter_map(|f| f.2)
            .collect();
        assert_eq!(upds, expected_upds(5 * MIB, FRAME, stream));
        assert!(trace.worst_excess <= 0);
        out.push((
            recv,
            stream,
            upds.len(),
            trace.max_inflight.get(&Dir::S2C).copied(),
            took,
        ));
    }
    assert_eq!(out[0].2, 20);
    assert_eq!(out[1].2, 80);
    for (recv, stream, n, inflight, took) in out {
        eprintln!("SERVER-VIEW recv={recv} stream={stream} upds_per_5MiB={n} max_inflight={inflight:?} took={took:?}");
    }
}

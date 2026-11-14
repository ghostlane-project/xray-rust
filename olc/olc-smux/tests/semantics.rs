// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! smux's rules, one at a time, against a hand-driven peer: each test writes
//! frames as bytes and reads what olc-smux writes back.

use std::io::ErrorKind;
use std::time::Duration;

use olc_smux::frame::{encode_upd, Cmd, Header, HEADER_SIZE};
use olc_smux::{Config, Error, Session, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

/// The peer: raw frames over one end of a duplex.
struct Raw {
    io: DuplexStream,
}

impl Raw {
    async fn send_header(&mut self, version: u8, cmd: u8, sid: u32, payload: &[u8]) {
        let h = Header {
            version,
            cmd,
            length: payload.len() as u16,
            sid,
        };
        self.io.write_all(&h.encode()).await.unwrap();
        self.io.write_all(payload).await.unwrap();
    }

    async fn send(&mut self, cmd: Cmd, sid: u32, payload: &[u8]) {
        self.send_header(2, cmd as u8, sid, payload).await;
    }

    async fn upd(&mut self, sid: u32, consumed: u32, window: u32) {
        self.send(Cmd::Upd, sid, &encode_upd(consumed, window))
            .await;
    }

    /// The next frame, NOPs skipped; `None` at EOF.
    async fn next(&mut self) -> Option<(Cmd, u32, Vec<u8>)> {
        loop {
            let mut h = [0u8; HEADER_SIZE];
            if self.io.read_exact(&mut h).await.is_err() {
                return None;
            }
            let h = Header::decode(h);
            let cmd = h.validate().expect("olc-smux writes valid frames");
            let mut data = vec![0u8; h.length as usize];
            self.io.read_exact(&mut data).await.unwrap();
            if cmd != Cmd::Nop {
                return Some((cmd, h.sid, data));
            }
        }
    }

    /// The next frame within `d` (paused clock), or `None`.
    async fn next_within(&mut self, d: Duration) -> Option<(Cmd, u32, Vec<u8>)> {
        tokio::time::timeout(d, self.next()).await.ok().flatten()
    }
}

fn cfg() -> Config {
    watchdog();
    let mut c = Config::go_default();
    c.keep_alive = None;
    c
}

/// Aborts the test binary after ten minutes, so that a hang cannot hold the
/// shared build box.
fn watchdog() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(600));
            eprintln!("WATCHDOG: the test binary still runs after 600 s; aborting");
            std::process::abort();
        });
    });
}

fn server(cfg: Config) -> (Session, JoinHandle<Result<(), Error>>, Raw) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (s, d) = Session::server(a, cfg).unwrap();
    (s, tokio::spawn(d), Raw { io: b })
}

fn client(cfg: Config) -> (Session, JoinHandle<Result<(), Error>>, Raw) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (s, d) = Session::client(a, cfg).unwrap();
    (s, tokio::spawn(d), Raw { io: b })
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(10)).await;
}

async fn read_some(st: &mut Stream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let k = st.read(&mut buf).await.unwrap();
    buf.truncate(k);
    buf
}

// smux/session.go:426-445 (SYN), 459-486 (PSH), stream.go:277-297 (first-read UPD),
// session.go:153-156,189 (ids by side).
#[tokio::test(start_paused = true)]
async fn peer_streams_are_accepted_and_ids_follow_the_side() {
    let (s, _d, mut raw) = server(cfg());
    raw.send(Cmd::Syn, 3, &[]).await;
    raw.send(Cmd::Psh, 3, b"hi").await;
    let mut st = s.accept_stream().await.unwrap();
    assert_eq!(st.id(), 3);
    assert_eq!(read_some(&mut st, 100).await, b"hi");
    // The first read sends UPD(consumed 2, window = own MaxStreamBuffer 65536).
    assert_eq!(
        raw.next().await,
        Some((Cmd::Upd, 3, encode_upd(2, 65536).to_vec()))
    );
    // A server opens even ids from 2.
    let a = s.open_stream().await.unwrap();
    let b = s.open_stream().await.unwrap();
    assert_eq!((a.id(), b.id()), (2, 4));
    assert_eq!(raw.next().await, Some((Cmd::Syn, 2, vec![])));
    assert_eq!(raw.next().await, Some((Cmd::Syn, 4, vec![])));
    // A client opens odd ids from 3.
    let (c, _cd, mut craw) = client(cfg());
    let x = c.open_stream().await.unwrap();
    let y = c.open_stream().await.unwrap();
    assert_eq!((x.id(), y.id()), (3, 5));
    assert_eq!(craw.next().await, Some((Cmd::Syn, 3, vec![])));
    assert_eq!(craw.next().await, Some((Cmd::Syn, 5, vec![])));
}

// smux/session.go:433 (a SYN for a sid in use), 460-462 (zero-length PSH),
// 482-485 (data for an unknown sid takes no tokens), 455 and 508 (FIN and UPD
// for an unknown sid).
#[tokio::test(start_paused = true)]
async fn what_go_ignores_is_ignored() {
    let (s, _d, mut raw) = server(cfg());
    raw.send(Cmd::Syn, 3, &[]).await;
    raw.send(Cmd::Psh, 3, &[]).await;
    raw.send(Cmd::Psh, 9, b"zzz").await;
    raw.upd(9, 1, 1).await;
    raw.send(Cmd::Fin, 9, &[]).await;
    raw.send(Cmd::Syn, 3, &[]).await;
    raw.send(Cmd::Nop, 0, &[]).await;
    raw.send(Cmd::Psh, 3, b"ok").await;
    let mut st = s.accept_stream().await.unwrap();
    settle().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), s.accept_stream())
            .await
            .is_err()
    );
    assert_eq!(s.stats().rx_buffered, 2);
    assert_eq!(read_some(&mut st, 100).await, b"ok");
    let stats = s.stats();
    assert_eq!((stats.rx_buffered, stats.bucket), (0, 4 << 20));
    assert_eq!(stats.nop_in, 1);
    assert!(!s.is_closed());
}

// smux/session.go:412-416,421-430,447-451,493-497,512-514: a bad header stops
// reading; readers and Accept get ErrInvalidProtocol; the session stays open.
#[tokio::test(start_paused = true)]
async fn protocol_errors_end_reading() {
    let cases: [(u8, u8, &[u8]); 6] = [
        (1, Cmd::Psh as u8, b"x"),
        (2, Cmd::Nop as u8, b"x"),
        (2, Cmd::Syn as u8, b"xy"),
        (2, Cmd::Fin as u8, b"x"),
        (2, Cmd::Upd as u8, b"1234"),
        (2, 5, b""),
    ];
    for (version, cmd, payload) in cases {
        let (s, _d, mut raw) = server(cfg());
        raw.send(Cmd::Syn, 3, &[]).await;
        let mut st = s.accept_stream().await.unwrap();
        raw.send_header(version, cmd, 3, payload).await;
        raw.send(Cmd::Psh, 3, b"never").await;
        let mut buf = [0u8; 16];
        let err = st.read(&mut buf).await.unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::InvalidData,
            "version {version} cmd {cmd}"
        );
        assert_eq!(err.to_string(), "invalid protocol");
        assert_eq!(s.accept_stream().await.unwrap_err(), Error::InvalidProtocol);
        assert!(!s.is_closed());
        // The send side still works, as Go's does.
        let mut o = s.open_stream().await.unwrap();
        o.write_all(b"out").await.unwrap();
        assert_eq!(raw.next().await, Some((Cmd::Syn, 2, vec![])));
        assert_eq!(raw.next().await, Some((Cmd::Psh, 2, b"out".to_vec())));
    }
}

// smux/session.go:390-399 (no header is read while the bucket is not
// positive), 478-481 (a PSH takes its length), 377-381 (a read gives it back).
#[tokio::test(start_paused = true)]
async fn the_token_bucket_stops_and_restarts_reading() {
    let mut c = cfg();
    c.max_receive_buffer = 10_000;
    c.max_stream_buffer = 10_000;
    let (s, _d, mut raw) = server(c);
    raw.send(Cmd::Syn, 3, &[]).await;
    for _ in 0..10 {
        raw.send(Cmd::Psh, 3, &[7u8; 3000]).await;
    }
    let mut st = s.accept_stream().await.unwrap();
    settle().await;
    // 10000, 7000, 4000, 1000 are positive: four frames are read, and the
    // bucket ends one frame short of empty, as in Go.
    let stats = s.stats();
    assert_eq!((stats.rx_buffered, stats.bucket), (12_000, -2_000));
    // One frame read: the bucket is back to 1000, one more frame comes in.
    assert_eq!(read_some(&mut st, 65536).await.len(), 3000);
    settle().await;
    let stats = s.stats();
    assert_eq!((stats.rx_buffered, stats.bucket), (12_000, -2_000));
    let mut total = 3000;
    while total < 30_000 {
        total += read_some(&mut st, 65536).await.len();
    }
    settle().await;
    assert_eq!(s.stats().bucket, 10_000);
    assert_eq!(s.stats().peak_rx_buffered, 12_000);
}

// smux/stream.go:581-617: the window is the peer's last window less what is
// in flight; frames are cut to it; a peer that acknowledges more than was
// written is ErrConsumed.
#[tokio::test(start_paused = true)]
async fn writes_follow_the_peer_window() {
    let (c, _d, mut raw) = client(cfg());
    let mut st = c.open_stream().await.unwrap();
    assert_eq!(raw.next().await, Some((Cmd::Syn, 3, vec![])));
    assert_eq!(st.stats().peer_window, 262_144);
    raw.upd(3, 0, 10).await;
    settle().await;
    assert_eq!(st.stats().peer_window, 10);
    let w = tokio::spawn(async move {
        st.write_all(&[1u8; 100]).await.unwrap();
        st
    });
    assert_eq!(raw.next().await, Some((Cmd::Psh, 3, vec![1u8; 10])));
    assert_eq!(raw.next_within(Duration::from_millis(100)).await, None);
    raw.upd(3, 10, 50).await;
    assert_eq!(raw.next().await, Some((Cmd::Psh, 3, vec![1u8; 50])));
    raw.upd(3, 60, 1000).await;
    assert_eq!(raw.next().await, Some((Cmd::Psh, 3, vec![1u8; 40])));
    let mut st = w.await.unwrap();
    raw.upd(3, 500, 1000).await;
    settle().await;
    let err = st.write(b"x").await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "peer consumed more than sent");
}

// smux/session.go:142,440-445: with the accept channel full, the reader
// registers one more stream and waits to hand it over.
#[tokio::test(start_paused = true)]
async fn a_full_accept_queue_stops_reading() {
    let mut c = cfg();
    c.accept_backlog = 2;
    let (s, _d, mut raw) = server(c);
    for sid in [3, 5, 7] {
        raw.send(Cmd::Syn, sid, &[]).await;
    }
    raw.send(Cmd::Psh, 3, b"x").await;
    settle().await;
    assert_eq!(s.num_streams(), 3);
    assert_eq!(s.stats().rx_buffered, 0);
    let first = s.accept_stream().await.unwrap();
    settle().await;
    assert_eq!(s.num_streams(), 3);
    assert_eq!(s.stats().rx_buffered, 1);
    assert_eq!(first.id(), 3);
}

// smux/stream.go:644-697,815-833: half-close and close as in Go.
#[tokio::test(start_paused = true)]
async fn close_and_half_close_follow_go() {
    let (c, _d, mut raw) = client(cfg());
    let mut st = c.open_stream().await.unwrap();
    raw.next().await;
    // CloseWrite: a FIN; writes fail; reads go on.
    st.shutdown().await.unwrap();
    assert_eq!(raw.next().await, Some((Cmd::Fin, 3, vec![])));
    assert_eq!(
        st.write(b"x").await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
    // A second shutdown is not an error here (Go's CloseWrite says ErrClosedPipe).
    st.shutdown().await.unwrap();
    raw.send(Cmd::Psh, 3, b"late").await;
    raw.send(Cmd::Fin, 3, &[]).await;
    settle().await;
    // Both FINs are out: the stream left the session (no UPD for what is
    // read now), but its data is still there to read.
    assert_eq!(c.num_streams(), 0);
    assert_eq!(read_some(&mut st, 100).await, b"late");
    assert_eq!(read_some(&mut st, 100).await, b"");
    assert_eq!(st.close().await, Err(Error::ClosedPipe));
    assert_eq!(raw.next_within(Duration::from_millis(100)).await, None);

    // Close: unread data goes and gives its tokens back; FIN; reads see EOF.
    let mut st = c.open_stream().await.unwrap();
    assert_eq!(raw.next().await, Some((Cmd::Syn, 5, vec![])));
    raw.send(Cmd::Psh, 5, b"abc").await;
    settle().await;
    assert_eq!(c.stats().rx_buffered, 3);
    st.close().await.unwrap();
    assert_eq!(raw.next().await, Some((Cmd::Fin, 5, vec![])));
    assert_eq!(c.stats().rx_buffered, 0);
    assert_eq!(read_some(&mut st, 100).await, b"");
    assert_eq!(
        st.write(b"x").await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
    assert_eq!(st.close().await, Err(Error::ClosedPipe));

    // CloseWrite then Close: two FINs (smux/stream.go:665,694).
    let mut st = c.open_stream().await.unwrap();
    assert_eq!(raw.next().await, Some((Cmd::Syn, 7, vec![])));
    st.shutdown().await.unwrap();
    st.close().await.unwrap();
    assert_eq!(raw.next().await, Some((Cmd::Fin, 7, vec![])));
    assert_eq!(raw.next().await, Some((Cmd::Fin, 7, vec![])));
}

// Go's finalizer Close (smux/session.go:239-241) is Drop here; the session
// ends once every handle is gone.
#[tokio::test(start_paused = true)]
async fn dropping_handles_closes_streams_then_the_session() {
    let (c, d, mut raw) = client(cfg());
    let mut st = c.open_stream().await.unwrap();
    st.write_all(b"bye").await.unwrap();
    drop(st);
    assert_eq!(raw.next().await, Some((Cmd::Syn, 3, vec![])));
    assert_eq!(raw.next().await, Some((Cmd::Psh, 3, b"bye".to_vec())));
    assert_eq!(raw.next().await, Some((Cmd::Fin, 3, vec![])));
    let c2 = c.clone();
    drop(c);
    settle().await;
    assert!(!c2.is_closed());
    drop(c2);
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_eq!(raw.next().await, None);
}

// smux/session.go:260-278: Close ends every stream; buffered data stays
// readable, then EOF (smux/stream.go:302-304).
#[tokio::test(start_paused = true)]
async fn session_close_ends_every_stream() {
    let (s, d, mut raw) = server(cfg());
    raw.send(Cmd::Syn, 3, &[]).await;
    raw.send(Cmd::Psh, 3, b"kept").await;
    let mut st = s.accept_stream().await.unwrap();
    settle().await;
    s.close().unwrap();
    assert_eq!(s.close(), Err(Error::ClosedPipe));
    assert!(s.is_closed());
    assert_eq!(read_some(&mut st, 100).await, b"kept");
    assert_eq!(read_some(&mut st, 100).await, b"");
    assert_eq!(
        st.write(b"x").await.unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
    assert_eq!(st.close().await, Err(Error::ClosedPipe));
    assert_eq!(s.open_stream().await.unwrap_err(), Error::ClosedPipe);
    assert_eq!(s.accept_stream().await.unwrap_err(), Error::ClosedPipe);
    assert_eq!(d.await.unwrap(), Ok(()));
    assert_eq!(raw.next().await, None);
}

// smux/session.go:403-407 with stream.go:451-452: the peer's clean EOF reads
// as EOF on every stream; Accept returns it; Open fails on it.
#[tokio::test(start_paused = true)]
async fn the_peers_eof_reaches_readers_and_acceptors() {
    let (s, _d, mut raw) = server(cfg());
    raw.send(Cmd::Syn, 3, &[]).await;
    let mut st = s.accept_stream().await.unwrap();
    raw.io.shutdown().await.unwrap();
    assert_eq!(read_some(&mut st, 100).await, b"");
    let e = s.accept_stream().await.unwrap_err();
    assert!(e.is_clean_eof(), "{e}");
    assert_eq!(e.to_string(), "EOF");
    assert!(s.open_stream().await.is_err());

    // Mid-frame it is "unexpected EOF", an error for readers.
    let (s, _d, mut raw) = server(cfg());
    raw.send(Cmd::Syn, 3, &[]).await;
    let mut st = s.accept_stream().await.unwrap();
    raw.io
        .write_all(&Header::new(Cmd::Psh, 10, 3).encode())
        .await
        .unwrap();
    raw.io.write_all(b"abc").await.unwrap();
    raw.io.shutdown().await.unwrap();
    let err = st.read(&mut [0u8; 16]).await.unwrap_err();
    assert_eq!(err.to_string(), "unexpected EOF");
}

// Bounded memory: a stream with nothing buffered holds no pool chunk, and a
// quiet session keeps at most pool_retain_bytes.
#[tokio::test(start_paused = true)]
async fn an_idle_stream_holds_no_payload_memory() {
    let (a, b) = tokio::io::duplex(1 << 16);
    let (c, cd) = Session::client(a, cfg()).unwrap();
    let (s, sd) = Session::server(b, cfg()).unwrap();
    tokio::spawn(cd);
    tokio::spawn(sd);
    let mut cs = c.open_stream().await.unwrap();
    let mut ss = s.accept_stream().await.unwrap();
    let data = vec![42u8; 1 << 20];
    let w = tokio::spawn(async move {
        cs.write_all(&data).await.unwrap();
        cs.flush().await.unwrap();
        cs
    });
    let mut got = 0;
    let mut buf = vec![0u8; 32 * 1024];
    while got < 1 << 20 {
        got += ss.read(&mut buf).await.unwrap();
    }
    let cs = w.await.unwrap();
    settle().await;
    for st in [c.stats(), s.stats()] {
        assert_eq!(st.pool_in_use, 0, "{st:?}");
        assert_eq!((st.rx_buffered, st.tx_queued), (0, 0));
        assert!(st.pool_held <= cfg().pool_retain_bytes, "{st:?}");
        assert!(st.peak_pool_in_use > 0);
    }
    assert_eq!(ss.stats().rx_buffered, 0);
    assert_eq!(cs.stats().tx_queued, 0);
}

// open_close_timeout (smux/session.go:40,664-671): an open whose SYN cannot be
// written in time fails with ErrTimeout and leaves nothing behind.
#[tokio::test(start_paused = true)]
async fn an_open_that_cannot_write_times_out() {
    let (a, b) = tokio::io::duplex(64);
    let mut c = cfg();
    c.open_close_timeout = Duration::from_secs(2);
    let (s, d) = Session::client(a, c).unwrap();
    tokio::spawn(d);
    // Fill the pipe: the peer never reads.
    let mut st = s.open_stream().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(100), st.write_all(&[0u8; 4096])).await;
    let t = tokio::time::Instant::now();
    assert_eq!(s.open_stream().await.unwrap_err(), Error::Timeout);
    assert_eq!(t.elapsed(), Duration::from_secs(2));
    assert_eq!(s.num_streams(), 1);
    drop(b);
}

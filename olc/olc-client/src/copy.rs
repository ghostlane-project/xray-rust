// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Both directions of one connection (`tunnelcore.CopyBidirectional`,
//! copy.go): when one direction ends cleanly the other side's write half is
//! closed and the other direction may run on, half-open, while bytes keep
//! moving: [`HALF_OPEN_GRACE`] with nothing moved either way ends it. An
//! error in either direction closes both. A smux stream's end is an error
//! (Go copies from it with `Stream.WriteTo`, which returns `io.EOF`), so a
//! server's FIN closes the local side too.
//!
//! # Memory
//!
//! A direction holds a [`COPY_BUFFER`] only while bytes move: it waits for
//! its source to be readable with no buffer, borrows one from the
//! [`Pool`] for the read and the write that follows, and gives it back. An
//! idle connection holds none (Go keeps one 32 KiB buffer per direction for
//! the connection's life). Borrowing never waits: a cap that made a
//! direction wait for a buffer would deadlock once every buffer sat in a
//! write to a destination that stopped reading, the buffers' own readers
//! among them.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// How long a half-open connection may stay silent (`HalfOpenGrace`).
pub const HALF_OPEN_GRACE: Duration = Duration::from_secs(60);

/// One read's buffer. Plan §9 gives the SOCKS front 2 × 16 KiB per moving
/// connection: 16 KiB is more than a smux frame (12,236 on datachannel), so
/// one read fills at most two frames, and the window updates the server
/// sees keep the sizes they had (a read of the smux stream takes at most
/// this much, so its `UPD` values are those of the Go client's reads).
pub const COPY_BUFFER: usize = 16 * 1024;

/// Buffers the pool keeps for reuse when they come back (128 KiB).
pub const POOL_KEEP: usize = 8;

/// The copy buffers: lent for one read and its write, kept up to
/// [`POOL_KEEP`] when they come back.
#[derive(Debug)]
pub struct Pool {
    free: Mutex<Vec<Box<[u8]>>>,
    out: AtomicUsize,
    peak: AtomicUsize,
}

static POOL: Pool = Pool::new();

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    /// An empty pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            out: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// The process's pool.
    pub fn global() -> &'static Pool {
        &POOL
    }

    fn take(&self) -> Box<[u8]> {
        let out = self.out.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(out, Ordering::Relaxed);
        let spare = self
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        spare.unwrap_or_else(|| vec![0u8; COPY_BUFFER].into_boxed_slice())
    }

    fn give(&self, buf: Box<[u8]>) {
        self.out.fetch_sub(1, Ordering::Relaxed);
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        if free.len() < POOL_KEEP {
            free.push(buf);
        }
    }

    /// Buffers lent now.
    pub fn lent(&self) -> usize {
        self.out.load(Ordering::Relaxed)
    }

    /// The most buffers ever lent at once.
    pub fn peak_lent(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Drops the buffers kept for reuse (the host's memory relief, D11);
    /// returns how many bytes that gave back.
    pub fn trim(&self) -> usize {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = free.len() * COPY_BUFFER;
        free.clear();
        free.shrink_to_fit();
        bytes
    }

    /// Buffers kept for reuse.
    pub fn kept(&self) -> usize {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// A source that can say it has something to read before a buffer is put
/// down for it. The default says so at once: the copy then borrows a buffer
/// for each poll and gives it back when the read is pending.
pub trait ReadReady {
    /// Ready when a read would not be pending.
    fn poll_read_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl ReadReady for tokio::net::TcpStream {
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::net::TcpStream::poll_read_ready(self, cx)
    }
}

impl ReadReady for olc_smux::Stream {
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        olc_smux::Stream::poll_read_ready(self, cx).map(Ok)
    }
}

impl ReadReady for tokio::io::DuplexStream {}

/// How the copy ended.
#[derive(Debug)]
pub enum CopyEnd {
    /// Both directions ended.
    Done,
    /// Half-open and silent past the grace (`ErrHalfOpenIdle`).
    HalfOpenIdle,
    /// A direction failed.
    Failed(io::Error),
    /// The run ended.
    Stopped,
}

/// Bytes each way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// From the left side to the right.
    pub left_to_right: u64,
    /// From the right side to the left.
    pub right_to_left: u64,
}

type Way = Result<u64, (u64, io::Error)>;

/// Copies between `left` (the local connection) and `right` (the tunnel's
/// stream, or a direct connection). `right_eof_fails` is set for a smux
/// stream: its end closes both sides.
pub async fn copy_bidirectional<L, R>(
    left: L,
    right: R,
    right_eof_fails: bool,
    grace: Duration,
    stop: &CancellationToken,
) -> (Counts, CopyEnd)
where
    L: AsyncRead + AsyncWrite + ReadReady + Unpin,
    R: AsyncRead + AsyncWrite + ReadReady + Unpin,
{
    copy_bidirectional_in(Pool::global(), left, right, right_eof_fails, grace, stop).await
}

/// Which direction ended.
enum Ended {
    LeftToRight(Way),
    RightToLeft(Way),
}

/// [`copy_bidirectional`] with buffers from `pool`.
pub async fn copy_bidirectional_in<L, R>(
    pool: &Pool,
    mut left: L,
    mut right: R,
    right_eof_fails: bool,
    grace: Duration,
    stop: &CancellationToken,
) -> (Counts, CopyEnd)
where
    L: AsyncRead + AsyncWrite + ReadReady + Unpin,
    R: AsyncRead + AsyncWrite + ReadReady + Unpin,
{
    let moved = AtomicU64::new(0);
    let mut l2r = Direction::new(pool, false);
    let mut r2l = Direction::new(pool, right_eof_fails);
    let mut counts = Counts::default();
    let mut next = poll_fn(|cx| {
        if !l2r.ended {
            if let Poll::Ready(w) = l2r.poll(&mut left, &mut right, &moved, cx) {
                l2r.ended = true;
                return Poll::Ready(Ended::LeftToRight(w));
            }
        }
        if !r2l.ended {
            if let Poll::Ready(w) = r2l.poll(&mut right, &mut left, &moved, cx) {
                r2l.ended = true;
                return Poll::Ready(Ended::RightToLeft(w));
            }
        }
        Poll::Pending
    });
    let note = |counts: &mut Counts, ended: Ended| -> Option<io::Error> {
        let (slot, way) = match ended {
            Ended::LeftToRight(w) => (&mut counts.left_to_right, w),
            Ended::RightToLeft(w) => (&mut counts.right_to_left, w),
        };
        match way {
            Ok(n) => {
                *slot = n;
                None
            }
            Err((n, e)) => {
                *slot = n;
                Some(e)
            }
        }
    };
    let first = tokio::select! {
        () = stop.cancelled() => return (counts, CopyEnd::Stopped),
        ended = &mut next => ended,
    };
    if let Some(e) = note(&mut counts, first) {
        return (counts, CopyEnd::Failed(e));
    }
    let mut seen = moved.load(Ordering::Relaxed);
    loop {
        tokio::select! {
            () = stop.cancelled() => return (counts, CopyEnd::Stopped),
            ended = &mut next => {
                return match note(&mut counts, ended) {
                    None => (counts, CopyEnd::Done),
                    Some(e) => (counts, CopyEnd::Failed(e)),
                };
            }
            () = tokio::time::sleep(grace) => {
                let now = moved.load(Ordering::Relaxed);
                if now == seen {
                    return (counts, CopyEnd::HalfOpenIdle);
                }
                seen = now;
            }
        }
    }
}

/// One direction's state between polls; a buffer it holds goes back to
/// its pool when it goes.
struct Direction<'a> {
    pool: &'a Pool,
    /// The buffer while its bytes are written: the bytes `pos..len`.
    buf: Option<Box<[u8]>>,
    pos: usize,
    len: usize,
    copied: u64,
    eof_fails: bool,
    /// The source ended cleanly: the destination's write half is closing.
    closing: bool,
    ended: bool,
}

impl Drop for Direction<'_> {
    fn drop(&mut self) {
        if let Some(b) = self.buf.take() {
            self.pool.give(b);
        }
    }
}

impl<'a> Direction<'a> {
    fn new(pool: &'a Pool, eof_fails: bool) -> Self {
        Self {
            pool,
            buf: None,
            pos: 0,
            len: 0,
            copied: 0,
            eof_fails,
            closing: false,
            ended: false,
        }
    }

    /// Moves bytes until the source has none or the destination takes no
    /// more; a clean end closes the destination's write half
    /// (`closeCopyWrite`), unless the source's end is an error.
    fn poll<S, D>(
        &mut self,
        src: &mut S,
        dst: &mut D,
        moved: &AtomicU64,
        cx: &mut Context<'_>,
    ) -> Poll<Way>
    where
        S: AsyncRead + ReadReady + Unpin,
        D: AsyncWrite + Unpin,
    {
        let r = self.poll_inner(src, dst, moved, cx);
        if r.is_ready() {
            if let Some(b) = self.buf.take() {
                self.pool.give(b);
            }
        }
        r
    }

    fn poll_inner<S, D>(
        &mut self,
        src: &mut S,
        dst: &mut D,
        moved: &AtomicU64,
        cx: &mut Context<'_>,
    ) -> Poll<Way>
    where
        S: AsyncRead + ReadReady + Unpin,
        D: AsyncWrite + Unpin,
    {
        let pool = self.pool;
        loop {
            if self.closing {
                let _ = ready!(Pin::new(&mut *dst).poll_shutdown(cx));
                return Poll::Ready(Ok(self.copied));
            }
            if let Some(buf) = &self.buf {
                while self.pos < self.len {
                    match ready!(Pin::new(&mut *dst).poll_write(cx, &buf[self.pos..self.len])) {
                        Ok(0) => {
                            return Poll::Ready(Err((self.copied, io::ErrorKind::WriteZero.into())))
                        }
                        Ok(n) => {
                            self.pos += n;
                            self.copied += n as u64;
                            moved.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(e) => return Poll::Ready(Err((self.copied, e))),
                    }
                }
                if let Some(b) = self.buf.take() {
                    pool.give(b);
                }
            }
            // Readable first, with no buffer down.
            if let Err(e) = ready!(src.poll_read_ready(cx)) {
                return Poll::Ready(Err((self.copied, e)));
            }
            let mut buf = pool.take();
            let mut rb = ReadBuf::new(&mut buf);
            match Pin::new(&mut *src).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    pool.give(buf);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    pool.give(buf);
                    return Poll::Ready(Err((self.copied, e)));
                }
                Poll::Ready(Ok(())) => {
                    let got = rb.filled().len();
                    if got == 0 {
                        pool.give(buf);
                        if self.eof_fails {
                            return Poll::Ready(Err((
                                self.copied,
                                io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"),
                            )));
                        }
                        self.closing = true;
                        continue;
                    }
                    self.pos = 0;
                    self.len = got;
                    self.buf = Some(buf);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn a_local_close_half_closes_and_the_reply_still_flows() {
        crate::testing::bounded(a_local_close_half_closes_and_the_reply_still_flows_body()).await;
    }

    async fn a_local_close_half_closes_and_the_reply_still_flows_body() {
        let (local, mut app) = duplex(1024);
        let (remote, mut server) = duplex(1024);
        let stop = CancellationToken::new();
        let copy = tokio::spawn(async move {
            copy_bidirectional(local, remote, true, HALF_OPEN_GRACE, &stop).await
        });
        app.write_all(b"req").await.unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap(); // the half-close arrived
        assert_eq!(got, b"req");
        server.write_all(b"reply").await.unwrap();
        let mut back = [0u8; 5];
        app.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"reply");
        drop(server); // the stream ends: an error, both close
        let (counts, end) = copy.await.unwrap();
        assert!(matches!(end, CopyEnd::Failed(_)), "{end:?}");
        assert_eq!(counts.left_to_right, 3);
        assert_eq!(counts.right_to_left, 5);
    }

    #[tokio::test]
    async fn an_idle_connection_holds_no_buffer() {
        crate::testing::bounded(async {
            let pool: &'static Pool = Box::leak(Box::new(Pool::new()));
            let (local, mut app) = duplex(64 * 1024);
            let (remote, mut server) = duplex(64 * 1024);
            let stop = CancellationToken::new();
            let handle = {
                let stop = stop.clone();
                tokio::spawn(async move {
                    copy_bidirectional_in(pool, local, remote, true, HALF_OPEN_GRACE, &stop).await
                })
            };
            let data = vec![5u8; 40_000];
            app.write_all(&data).await.unwrap();
            let mut got = vec![0u8; data.len()];
            server.read_exact(&mut got).await.unwrap();
            server.write_all(b"back").await.unwrap();
            let mut back = [0u8; 4];
            app.read_exact(&mut back).await.unwrap();
            // Both directions are waiting to read: nothing is lent.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(pool.lent(), 0);
            assert!(pool.peak_lent() >= 1 && pool.kept() >= 1);
            stop.cancel();
            let _ = handle.await.unwrap();
            assert_eq!(pool.lent(), 0, "a stopped copy gives its buffers back");
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_half_open_connection_ends_after_the_grace() {
        crate::testing::bounded_for(
            HALF_OPEN_GRACE + Duration::from_secs(10),
            a_silent_half_open_connection_ends_after_the_grace_body(),
        )
        .await;
    }

    async fn a_silent_half_open_connection_ends_after_the_grace_body() {
        let (local, mut app) = duplex(1024);
        let (remote, _server) = duplex(1024);
        let stop = CancellationToken::new();
        app.shutdown().await.unwrap();
        let (_, end) = copy_bidirectional(local, remote, true, HALF_OPEN_GRACE, &stop).await;
        assert!(matches!(end, CopyEnd::HalfOpenIdle), "{end:?}");
    }
}

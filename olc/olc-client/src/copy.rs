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
//! A direction holds a buffer only while bytes move: it waits for its
//! source to be readable with no buffer, borrows one from the [`Pool`] for
//! the read and the write that follows, and gives it back. An idle
//! connection holds none (Go keeps one 32 KiB buffer per direction for the
//! connection's life).
//!
//! A read beyond the floor takes bytes of the process's byte budget
//! ([`ghostlane_runtime::memory_budget`], the one xray's relays take theirs
//! of), held until its bytes are written: a read takes [`COPY_BUFFER`] when
//! the budget gives the bytes beyond the floor, else half, and so on down to
//! the floor ([`ByteBudget::floor`], 4 KiB), which is the direction's own.
//! So the SOCKS front holds at most `B` plus a floor per moving direction,
//! whatever the number of connections, and a connection whose bytes the
//! budget cannot give reads less: it is slowed, never refused. Borrowing
//! never waits: a direction that waited for bytes would deadlock once every
//! byte sat in a write to a destination that stopped reading, the bytes'
//! own readers among them; the floor is what keeps every direction moving.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use ghostlane_runtime::memory_budget::{BudgetPermits, ByteBudget};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// How long a half-open connection may stay silent (`HalfOpenGrace`).
pub const HALF_OPEN_GRACE: Duration = Duration::from_secs(60);

/// One read's buffer, at most: the read's size when the budget gives the
/// bytes beyond the floor. Plan §9 gives the SOCKS front 2 × 16 KiB per moving
/// connection: 16 KiB is more than a smux frame (12,236 on datachannel), so
/// one read fills at most two frames, and the window updates the server
/// sees keep the sizes they had (a read of the smux stream takes at most
/// this much, so its `UPD` values are those of the Go client's reads).
pub const COPY_BUFFER: usize = 16 * 1024;

/// [`COPY_BUFFER`]s the pool keeps for reuse when they come back (128 KiB);
/// a smaller read's buffer is freed when it comes back.
pub const POOL_KEEP: usize = 8;

/// The copy buffers: lent for one read and its write, kept up to
/// [`POOL_KEEP`] when they come back. The bytes of a read beyond the floor
/// are taken of the pool's budget by the direction before it borrows.
#[derive(Debug)]
pub struct Pool {
    free: Mutex<Vec<Box<[u8]>>>,
    /// The budget its directions' reads take bytes of; `None` is the
    /// process's.
    budget: Option<&'static ByteBudget>,
    out: AtomicUsize,
    peak: AtomicUsize,
    out_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
}

static POOL: Pool = Pool::new();

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    /// An empty pool whose reads take bytes of the process's budget
    /// ([`ByteBudget::process`], the one xray's relays take theirs of).
    #[must_use]
    pub const fn new() -> Self {
        Self::in_budget(None)
    }

    /// An empty pool whose reads take bytes of `budget` (a test's own).
    #[must_use]
    pub const fn with_budget(budget: &'static ByteBudget) -> Self {
        Self::in_budget(Some(budget))
    }

    const fn in_budget(budget: Option<&'static ByteBudget>) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            budget,
            out: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            out_bytes: AtomicUsize::new(0),
            peak_bytes: AtomicUsize::new(0),
        }
    }

    /// The process's pool.
    pub fn global() -> &'static Pool {
        &POOL
    }

    /// The budget this pool's reads take bytes of.
    pub fn budget(&self) -> &'static ByteBudget {
        self.budget.unwrap_or_else(ByteBudget::process)
    }

    /// A buffer of `len` bytes: a kept one for a [`COPY_BUFFER`].
    fn take(&self, len: usize) -> Box<[u8]> {
        let out = self.out.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(out, Ordering::Relaxed);
        let bytes = self.out_bytes.fetch_add(len, Ordering::Relaxed) + len;
        self.peak_bytes.fetch_max(bytes, Ordering::Relaxed);
        let spare = if len == COPY_BUFFER {
            self.free
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop()
        } else {
            None
        };
        spare.unwrap_or_else(|| vec![0u8; len].into_boxed_slice())
    }

    fn give(&self, buf: Box<[u8]>) {
        self.out.fetch_sub(1, Ordering::Relaxed);
        self.out_bytes.fetch_sub(buf.len(), Ordering::Relaxed);
        if buf.len() != COPY_BUFFER {
            return;
        }
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

    /// Bytes of the buffers lent now.
    pub fn lent_bytes(&self) -> usize {
        self.out_bytes.load(Ordering::Relaxed)
    }

    /// The most bytes ever lent at once.
    pub fn peak_lent_bytes(&self) -> usize {
        self.peak_bytes.load(Ordering::Relaxed)
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
/// its pool when it goes, and the budget's bytes for it with it.
struct Direction<'a> {
    pool: &'a Pool,
    /// The budget's bytes for the read beyond the floor, held while `buf` is.
    permits: BudgetPermits<'static>,
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
            self.give_back(b);
        }
    }
}

impl<'a> Direction<'a> {
    fn new(pool: &'a Pool, eof_fails: bool) -> Self {
        Self {
            pool,
            permits: BudgetPermits::new(pool.budget()),
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
                self.give_back(b);
            }
        }
        r
    }

    /// The next read's size: [`COPY_BUFFER`] when the budget gives the
    /// bytes beyond the floor, else half, and so on down to the floor,
    /// which takes nothing of it. The bytes are held until the read's
    /// buffer goes back.
    fn plan(&mut self) -> usize {
        let floor = self.permits.budget().floor().min(COPY_BUFFER);
        let mut size = COPY_BUFFER;
        while size > floor {
            let need = size - floor;
            if self.permits.try_hold(need) >= need {
                return size;
            }
            size /= 2;
        }
        self.permits.try_hold(0);
        floor
    }

    /// A read's buffer goes back, and the budget's bytes for it.
    fn give_back(&mut self, buf: Box<[u8]>) {
        self.pool.give(buf);
        self.permits.try_hold(0);
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
                    self.give_back(b);
                }
            }
            // Readable first, with no buffer down.
            if let Err(e) = ready!(src.poll_read_ready(cx)) {
                return Poll::Ready(Err((self.copied, e)));
            }
            let size = self.plan();
            let mut buf = self.pool.take(size);
            let mut rb = ReadBuf::new(&mut buf);
            match Pin::new(&mut *src).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    self.give_back(buf);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.give_back(buf);
                    return Poll::Ready(Err((self.copied, e)));
                }
                Poll::Ready(Ok(())) => {
                    let got = rb.filled().len();
                    if got == 0 {
                        self.give_back(buf);
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

    /// Plan §9's worst case at the SOCKS front: all [`MAX_SOCKS_CONNS`]
    /// connections moving both ways at once.
    const MOVING: usize = crate::socks::MAX_SOCKS_CONNS;
    /// Each way of each connection.
    const EACH_WAY: usize = 64 * 1024;
    /// The pipes on both sides: smaller than one read, so a direction's
    /// write waits on its reader while it holds the read's buffer.
    const PIPE: usize = 8 * 1024;
    /// The readers on both sides take this much at a time and pause: they
    /// are slower than the copy, so every direction has a read waiting to
    /// be written.
    const READER_STEP: usize = 4 * 1024;
    const FLOOR: usize = 4 * 1024;

    fn pattern(conn: usize, way: u8) -> Vec<u8> {
        (0..EACH_WAY)
            .map(|k| {
                (k as u32)
                    .wrapping_mul(31)
                    .wrapping_add(conn as u32 * 7 + u32::from(way)) as u8
            })
            .collect()
    }

    /// One end of a connection: sends `send` and closes its write half,
    /// while it reads everything the other end sends, slowly.
    async fn one_end(stream: tokio::io::DuplexStream, send: Vec<u8>) -> Vec<u8> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let sending = async move {
            wr.write_all(&send).await.unwrap();
            wr.shutdown().await.unwrap();
        };
        let reading = async move {
            let mut got = Vec::with_capacity(EACH_WAY);
            let mut step = vec![0u8; READER_STEP];
            loop {
                let n = rd.read(&mut step).await.unwrap();
                if n == 0 {
                    return got;
                }
                got.extend_from_slice(&step[..n]);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let ((), got) = tokio::join!(sending, reading);
        got
    }

    /// [`MOVING`] connections through one pool on a budget of `capacity`:
    /// returns the pool and the budget, every copy having ended.
    async fn move_all(capacity: usize) -> (&'static Pool, &'static ByteBudget) {
        let budget: &'static ByteBudget = Box::leak(Box::new(ByteBudget::with_settings(
            ghostlane_runtime::ByteBudgetSettings {
                capacity,
                floor: FLOOR,
            },
        )));
        let pool: &'static Pool = Box::leak(Box::new(Pool::with_budget(budget)));
        let stop = CancellationToken::new();
        let (go, ready) = tokio::sync::watch::channel(false);
        let mut copies = tokio::task::JoinSet::new();
        let mut ends = tokio::task::JoinSet::new();
        for conn in 0..MOVING {
            let (local, app) = duplex(PIPE);
            let (remote, server) = duplex(PIPE);
            let stop = stop.clone();
            copies.spawn(async move {
                copy_bidirectional_in(pool, local, remote, false, HALF_OPEN_GRACE, &stop).await
            });
            for (stream, send, expect) in [
                (app, pattern(conn, 0), pattern(conn, 1)),
                (server, pattern(conn, 1), pattern(conn, 0)),
            ] {
                let mut ready = ready.clone();
                ends.spawn(async move {
                    ready.wait_for(|go| *go).await.unwrap();
                    let got = one_end(stream, send).await;
                    assert!(got == expect, "connection {conn}: the bytes differ");
                });
            }
        }
        go.send(true).unwrap();
        while let Some(done) = ends.join_next().await {
            done.unwrap();
        }
        let mut finished = 0;
        while let Some(done) = copies.join_next().await {
            let (counts, end) = done.unwrap();
            assert!(matches!(end, CopyEnd::Done), "{end:?}");
            assert_eq!(counts.left_to_right, EACH_WAY as u64);
            assert_eq!(counts.right_to_left, EACH_WAY as u64);
            finished += 1;
        }
        assert_eq!(finished, MOVING, "every connection finished");
        assert_eq!(pool.lent_bytes(), 0, "every buffer came back");
        assert_eq!(budget.in_use(), 0, "every byte of the budget came back");
        assert!(budget.usage().peak <= capacity);
        (pool, budget)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn five_hundred_twelve_moving_connections_stay_within_the_budget() {
        crate::testing::bounded_for(Duration::from_secs(40), async {
            const CAPACITY: usize = 1 << 20;
            let (pool, budget) = move_all(CAPACITY).await;
            let bound = CAPACITY + 2 * MOVING * FLOOR;
            eprintln!(
                "{MOVING} moving on a budget of {CAPACITY}: {} bytes lent at most, \
                 {} of the budget",
                pool.peak_lent_bytes(),
                budget.usage().peak
            );
            assert!(
                pool.peak_lent_bytes() <= bound,
                "{MOVING} moving connections had {} bytes of buffers lent at once; \
                 the budget and the floors allow {bound}",
                pool.peak_lent_bytes()
            );
            // Not on the floors alone: reads took bytes of the budget.
            assert!(budget.usage().peak > 0, "no read took bytes of the budget");
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spent_budget_moves_every_connection_on_its_floor() {
        crate::testing::bounded_for(Duration::from_secs(40), async {
            let (pool, _) = move_all(0).await;
            let bound = 2 * MOVING * FLOOR;
            eprintln!(
                "{MOVING} moving on an empty budget: {} bytes lent at most",
                pool.peak_lent_bytes()
            );
            assert!(
                pool.peak_lent_bytes() <= bound,
                "on an empty budget {} bytes were lent at once; the floors allow {bound}",
                pool.peak_lent_bytes()
            );
        })
        .await;
    }

    #[test]
    fn the_process_pool_takes_bytes_of_the_process_budget() {
        assert!(std::ptr::eq(Pool::global().budget(), ByteBudget::process()));
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

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Both directions of one connection (`tunnelcore.CopyBidirectional`,
//! copy.go): when one direction ends cleanly the other side's write half is
//! closed and the other direction may run on, half-open, while bytes keep
//! moving: [`HALF_OPEN_GRACE`] with nothing moved either way ends it. An
//! error in either direction closes both. A smux stream's end is an error
//! (Go copies from it with `Stream.WriteTo`, which returns `io.EOF`), so a
//! server's FIN closes the local side too.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// How long a half-open connection may stay silent (`HalfOpenGrace`).
pub const HALF_OPEN_GRACE: Duration = Duration::from_secs(60);

/// One direction's buffer. Plan §9 gives the SOCKS front 2 × 16 KiB per
/// connection: 16 KiB is more than a smux frame (12,236 on datachannel), so
/// one read fills at most two frames, and 512 connections hold 16 MiB at
/// most (Go's 32 KiB would be 32 MiB).
pub const COPY_BUFFER: usize = 16 * 1024;

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
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);
    let moved = AtomicU64::new(0);
    let mut counts = Counts::default();
    let l2r = one_way(lr, rw, &moved, false);
    let r2l = one_way(rr, lw, &moved, right_eof_fails);
    tokio::pin!(l2r, r2l);
    let first_l2r = tokio::select! {
        () = stop.cancelled() => return (counts, CopyEnd::Stopped),
        r = &mut l2r => match r {
            Ok(n) => { counts.left_to_right = n; true }
            Err((n, e)) => { counts.left_to_right = n; return (counts, CopyEnd::Failed(e)); }
        },
        r = &mut r2l => match r {
            Ok(n) => { counts.right_to_left = n; false }
            Err((n, e)) => { counts.right_to_left = n; return (counts, CopyEnd::Failed(e)); }
        },
    };
    let mut seen = moved.load(Ordering::Relaxed);
    loop {
        let other = async {
            if first_l2r {
                (&mut r2l).await
            } else {
                (&mut l2r).await
            }
        };
        tokio::select! {
            () = stop.cancelled() => return (counts, CopyEnd::Stopped),
            r = other => {
                let slot = if first_l2r { &mut counts.right_to_left } else { &mut counts.left_to_right };
                return match r {
                    Ok(n) => { *slot = n; (counts, CopyEnd::Done) }
                    Err((n, e)) => { *slot = n; (counts, CopyEnd::Failed(e)) }
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

/// One direction. A clean end closes the destination's write half
/// (`closeCopyWrite`), unless the source's end is an error.
async fn one_way<S, D>(mut src: S, mut dst: D, moved: &AtomicU64, eof_fails: bool) -> Way
where
    S: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUFFER];
    let mut n = 0u64;
    loop {
        let got = match src.read(&mut buf).await {
            Ok(got) => got,
            Err(e) => return Err((n, e)),
        };
        if got == 0 {
            if eof_fails {
                return Err((n, io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")));
            }
            let _ = dst.shutdown().await;
            return Ok(n);
        }
        if let Err(e) = dst.write_all(&buf[..got]).await {
            return Err((n, e));
        }
        n += got as u64;
        moved.fetch_add(got as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

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

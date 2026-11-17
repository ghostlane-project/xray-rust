// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A dial that is tried again, for the carriers' HTTP calls (decision D4 of
//! the M6/M7 plan).
//!
//! Go's HTTP client for the room providers retries a request up to three
//! times, waiting 0, 500 and 1000 ms before the tries
//! (`internal/protect/protect.go:120-166`), on a DNS failure, no route, a
//! refused or timed-out dial, and also on a reply that timed out or was
//! reset: its POST bodies are replayable, so a join whose answer was lost
//! is sent a second time.
//!
//! Here only the dial is tried again: the lookup and the TCP connection,
//! `stream::dial_tcp`. When that fails nothing of the request has left,
//! so a retry cannot be a second join. TLS and the exchange run once, and
//! their errors are told as they come. That is narrower than Go on purpose.
//!
//! Nothing is held between tries: no stream, no buffer, one timer.

use std::future::Future;
use std::io;
use std::time::Duration;

use crate::fetch;
use crate::http::{HttpError, HttpRequest, HttpResponse};
use crate::stream::{self, Dialed, Offer, Target};

/// How many times a dial is made at most (Go's `maxRetries`).
pub const TRIES: u32 = 3;
/// The wait before try `n`, counted from 0, is `n` times this
/// (`waitForRetry`): 0, 500 ms, 1000 ms.
pub const STEP: Duration = Duration::from_millis(500);

/// Whether a failed TCP dial ([`crate::net::dial_tcp_host`]) is worth
/// another try: the name did not resolve (`NotFound`, the resolver's kind
/// and the dial's for a name with no address), there is no route to the
/// host or the network, the dial was refused, or it timed out.
///
/// The protector's refusal is not: Go does not retry it either, and a
/// phone without a route is the reconnect supervisor's to wait out
/// ([`crate::net::probe_route`]).
#[must_use]
pub fn retriable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::TimedOut
    )
}

/// Runs `dial` until it succeeds, at most [`TRIES`] times while its error
/// is [`retriable`], waiting [`STEP`] times the try's number before each.
///
/// `dial` must not have written anything when it fails.
///
/// # Errors
/// The last try's error.
pub async fn dial<T, F, Fut>(mut dial: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut attempt = 0;
    loop {
        if attempt > 0 {
            tokio::time::sleep(STEP * attempt).await;
        }
        match dial().await {
            Err(e) if attempt + 1 < TRIES && retriable(&e) => attempt += 1,
            done => return done,
        }
    }
}

/// [`stream::dial_for`] with the TCP dial tried again; TLS is made once.
///
/// # Errors
/// The last dial's, the TLS's, or `Unsupported` for TLS with no connector.
pub async fn dial_for(t: &Target, offer: Offer) -> io::Result<Dialed> {
    let tcp = dial(|| stream::dial_tcp(t)).await?;
    stream::secure(tcp, t, offer).await
}

/// [`fetch::fetch`] with the TCP dial tried again. The request is written
/// at most once. The whole call, dials and waits included, is bounded by
/// `req.timeout`, as Go's client timeout covers every attempt.
///
/// # Errors
/// As [`fetch::fetch`].
pub async fn fetch(t: &Target, req: &HttpRequest<'_>) -> Result<HttpResponse, HttpError> {
    let call = async {
        let dialed = dial_for(t, Offer::Fetch).await?;
        fetch::on(dialed, req).await
    };
    fetch::bounded(req.timeout, call).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::bounded;
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::Instant;

    /// A dial that fails with `kind` until `good` (counted from 1) and notes
    /// when each try began.
    async fn run(kind: ErrorKind, good: usize) -> (io::Result<usize>, Vec<Duration>) {
        let began = Instant::now();
        let tries = Mutex::new(Vec::new());
        let out = dial(|| {
            let n = {
                let mut t = tries.lock().unwrap();
                t.push(began.elapsed());
                t.len()
            };
            async move {
                if n == good {
                    Ok(n)
                } else {
                    Err(io::Error::new(kind, "stub"))
                }
            }
        })
        .await;
        (out, tries.into_inner().unwrap())
    }

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[tokio::test(start_paused = true)]
    async fn a_dial_that_keeps_failing_is_tried_three_times_after_0_500_and_1000_ms() {
        let (out, tries) = bounded(run(ErrorKind::ConnectionRefused, 0)).await;
        assert_eq!(out.unwrap_err().kind(), ErrorKind::ConnectionRefused);
        // Go waits attempt x 500 ms before each try: 0, then 500, then 1000.
        assert_eq!(tries, [MS(0), MS(500), MS(1500)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dial_that_succeeds_is_not_tried_again() {
        let (out, tries) = bounded(run(ErrorKind::TimedOut, 1)).await;
        assert_eq!(out.unwrap(), 1);
        assert_eq!(tries, [MS(0)]);
        let (out, tries) = bounded(run(ErrorKind::TimedOut, 2)).await;
        assert_eq!(out.unwrap(), 2);
        assert_eq!(tries, [MS(0), MS(500)]);
        let (out, tries) = bounded(run(ErrorKind::TimedOut, 3)).await;
        assert_eq!(out.unwrap(), 3);
        assert_eq!(tries, [MS(0), MS(500), MS(1500)]);
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_dial_that_reached_nobody_is_tried_again() {
        // DNS, no route, a refused or timed-out dial (D4; Go's
        // isRetriableError for the errors a dial can give).
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
        ] {
            let (out, tries) = bounded(run(kind, 0)).await;
            assert_eq!(out.unwrap_err().kind(), kind);
            assert_eq!(tries.len(), 3, "{kind:?}");
            assert!(retriable(&io::Error::new(kind, "x")), "{kind:?}");
        }
        // The protector's refusal, a peer that reset or closed, TLS's
        // errors: told the first time.
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
            ErrorKind::InvalidData,
            ErrorKind::InvalidInput,
            ErrorKind::Unsupported,
            ErrorKind::Other,
        ] {
            let (out, tries) = bounded(run(kind, 0)).await;
            assert_eq!(out.unwrap_err().kind(), kind);
            assert_eq!(tries, [MS(0)], "{kind:?}");
            assert!(!retriable(&io::Error::new(kind, "x")), "{kind:?}");
        }
        // The errno itself, as the kernel's connect gives it.
        for errno in [
            libc::EHOSTUNREACH,
            libc::ENETUNREACH,
            libc::ECONNREFUSED,
            libc::ETIMEDOUT,
        ] {
            assert!(retriable(&io::Error::from_raw_os_error(errno)), "{errno}");
        }
        for errno in [libc::ECONNRESET, libc::EPIPE, libc::EACCES, libc::EPERM] {
            assert!(!retriable(&io::Error::from_raw_os_error(errno)), "{errno}");
        }
    }

    fn post(body: &'static [u8]) -> HttpRequest<'static> {
        HttpRequest {
            method: "POST",
            host: "h.test",
            path: "/join",
            headers: &[("Content-Type", "application/x-www-form-urlencoded")],
            body,
            max_body: 1024,
            timeout: Duration::from_secs(8),
        }
    }

    /// A server on loopback that reads each connection's request and
    /// answers with `reply` (nothing: it closes). Returns its URL and the
    /// count of connections it took.
    async fn server(reply: &'static [u8]) -> (Target, Arc<AtomicUsize>) {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/join", ln.local_addr().unwrap());
        let taken = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&taken);
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = ln.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let mut got = Vec::new();
                let mut buf = [0u8; 1024];
                while !got.ends_with(b"a=1") {
                    match conn.read(&mut buf).await {
                        Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                let _ = conn.write_all(reply).await;
            }
        });
        (stream::parse_url(&url).unwrap(), taken)
    }

    /// D4: Go's transport resends a POST whose reply failed; this one does
    /// not, so a join is never seen twice.
    #[tokio::test]
    async fn a_request_that_was_written_is_not_sent_again() {
        bounded(async {
            let (target, taken) = server(b"").await;
            let err = fetch(&target, &post(b"a=1")).await.unwrap_err();
            assert!(
                matches!(err, HttpError::Io(_) | HttpError::Protocol(_)),
                "{err}"
            );
            assert_eq!(taken.load(Ordering::SeqCst), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn a_fetch_that_is_answered_dials_once() {
        bounded(async {
            let (target, taken) =
                server(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok").await;
            let got = fetch(&target, &post(b"a=1")).await.unwrap();
            assert_eq!((got.status, got.body.as_slice()), (201, &b"ok"[..]));
            assert_eq!(taken.load(Ordering::SeqCst), 1);
        })
        .await;
    }

    /// The real dial: a port nobody listens on is asked three times, 1.5 s
    /// in all, and the refusal is what the caller is told.
    #[tokio::test]
    async fn a_refused_dial_is_tried_three_times() {
        bounded(async {
            let port = {
                let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
                ln.local_addr().unwrap().port()
            };
            let target = stream::parse_url(&format!("http://127.0.0.1:{port}/")).unwrap();
            let began = Instant::now();
            let err = dial_for(&target, Offer::Fetch).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
            let took = began.elapsed();
            assert!(took >= MS(1500) && took < MS(4000), "{took:?}");
            let err = fetch(&target, &post(b"a=1")).await.unwrap_err();
            assert!(
                matches!(&err, HttpError::Io(e) if e.kind() == ErrorKind::ConnectionRefused),
                "{err}"
            );
        })
        .await;
    }

    /// The waits are inside the call's own bound, as Go's client timeout
    /// covers every attempt.
    #[tokio::test]
    async fn the_calls_bound_covers_the_waits() {
        bounded(async {
            let port = {
                let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
                ln.local_addr().unwrap().port()
            };
            let target = stream::parse_url(&format!("http://127.0.0.1:{port}/")).unwrap();
            let mut req = post(b"a=1");
            req.timeout = MS(700);
            let began = Instant::now();
            let err = fetch(&target, &req).await.unwrap_err();
            assert!(matches!(err, HttpError::Timeout), "{err}");
            assert!(began.elapsed() < MS(1400), "{:?}", began.elapsed());
        })
        .await;
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57 session.go, Copyright (c) 2016-2017 xtaci, MIT.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Interval, MissedTickBehavior};

use crate::frame::{Cmd, Header, HEADER_SIZE, MAX_FRAME_SIZE, UPD_SIZE};
use crate::state::{InFlight, Shared};
use crate::Error;

/// The task that owns a session's connection. It is Go's `recvLoop`,
/// `shaperLoop`, `sendLoop` and `keepalive` (`smux/session.go:384-662`) in
/// one future: it reads and dispatches frames while the token bucket is
/// positive, writes queued frames one per `poll_write` in the shaper's order,
/// sends a NOP every keepalive interval and closes the session when a whole
/// keepalive timeout passed without a frame from the peer.
///
/// Spawn it. It resolves when the session closes, dropping the connection:
/// `Ok(())` after [`Session::close`](crate::Session::close) or once every
/// handle is gone; otherwise the error that ended it ([`Error::Timeout`]
/// for the keepalive, or the connection's).
#[derive(Debug)]
#[must_use = "the driver does nothing unless spawned or polled"]
pub struct Driver<T> {
    conn: Option<T>,
    shared: Arc<Shared>,
    rbuf: Vec<u8>,
    rstart: usize,
    rend: usize,
    wbuf: Vec<u8>,
    wpos: usize,
    inflight: Option<InFlight>,
    need_flush: bool,
    read_done: bool,
    write_done: bool,
    keepalive: Option<Keepalive>,
    started: bool,
}

#[derive(Debug)]
struct Keepalive {
    ping: Interval,
    timeout: Interval,
}

impl<T> Driver<T> {
    pub(crate) fn new(conn: T, shared: Arc<Shared>) -> Driver<T> {
        let rlen = shared.cfg.read_buffer_size;
        let wlen = HEADER_SIZE + shared.cfg.max_frame_size.max(UPD_SIZE);
        {
            let mut st = shared.lock();
            st.counters.read_buffer = rlen;
            st.counters.write_buffer = wlen;
        }
        Driver {
            conn: Some(conn),
            shared,
            rbuf: vec![0u8; rlen],
            rstart: 0,
            rend: 0,
            wbuf: vec![0u8; wlen],
            wpos: 0,
            inflight: None,
            need_flush: false,
            read_done: false,
            write_done: false,
            keepalive: None,
            started: false,
        }
    }
}

/// A driver dropped before the session ended (its task aborted, its
/// runtime gone) ends the session: nothing would read or write for it, and
/// its streams would wait forever.
impl<T> Drop for Driver<T> {
    fn drop(&mut self) {
        if self.conn.is_some() {
            self.shared.lock().close_session(Some(Error::ClosedPipe));
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Driver<T> {
    /// Go starts its tickers with the session (`smux/session.go:162-164,521-522`);
    /// here they start at the first poll, which needs the runtime's clock.
    fn start(&mut self) {
        self.started = true;
        if let Some(ka) = self.shared.cfg.keep_alive {
            // time.NewTicker fires first after one period.
            let now = Instant::now();
            let mut ping = tokio::time::interval_at(now + ka.interval, ka.interval);
            ping.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut timeout = tokio::time::interval_at(now + ka.timeout, ka.timeout);
            timeout.set_missed_tick_behavior(MissedTickBehavior::Skip);
            self.keepalive = Some(Keepalive { ping, timeout });
        }
    }

    /// `keepalive` (`smux/session.go:520-543`).
    fn poll_keepalive(&mut self, cx: &mut Context<'_>) {
        let Some(ka) = &mut self.keepalive else {
            return;
        };
        while ka.ping.poll_tick(cx).is_ready() {
            let mut st = self.shared.lock();
            if st.write_err.is_none() {
                st.queue_nop();
            }
        }
        while ka.timeout.poll_tick(cx).is_ready() {
            let mut st = self.shared.lock();
            // smux/session.go:531-537: nothing arrived for a whole timeout,
            // and the reader is not just waiting for tokens.
            if !st.active {
                // Reading stopped for room is waiting, as for tokens.
                if st.rx_room() > 0 {
                    st.close_session(Some(Error::Timeout));
                    return;
                }
            } else {
                st.active = false;
            }
        }
    }

    /// `recvLoop` (`smux/session.go:384-517`). Returns whether it made progress.
    fn poll_read_side(&mut self, cx: &mut Context<'_>) -> bool {
        let mut progress = false;
        let cfg = &self.shared.cfg;
        loop {
            // Frames already buffered.
            {
                let mut st = self.shared.lock();
                loop {
                    if st.closed {
                        return progress;
                    }
                    // smux/session.go:390-399: not even a header while the
                    // bucket is empty; the connection is not read either.
                    if !st.may_read(cfg) {
                        return progress;
                    }
                    let avail = self.rend - self.rstart;
                    if avail < HEADER_SIZE {
                        break;
                    }
                    let head: [u8; HEADER_SIZE] = self.rbuf[self.rstart..self.rstart + HEADER_SIZE]
                        .try_into()
                        .expect("8 bytes");
                    let hdr = Header::decode(head);
                    // smux/session.go:410: any header marks the session active.
                    st.active = true;
                    let cmd = match hdr.validate() {
                        Ok(cmd) => cmd,
                        Err(_) => {
                            st.fail_read(None);
                            self.read_done = true;
                            return true;
                        }
                    };
                    let body = match cmd {
                        Cmd::Psh | Cmd::Upd => hdr.length as usize,
                        _ => 0,
                    };
                    if avail < HEADER_SIZE + body {
                        if HEADER_SIZE + body > self.rbuf.len() {
                            // A frame larger than the buffer: grow it to fit
                            // (at most 8 + 65535 bytes).
                            debug_assert!(body <= MAX_FRAME_SIZE);
                            self.rbuf.copy_within(self.rstart..self.rend, 0);
                            self.rend -= self.rstart;
                            self.rstart = 0;
                            self.rbuf.resize(HEADER_SIZE + body, 0);
                            st.counters.read_buffer = self.rbuf.len();
                        }
                        break;
                    }
                    let start = self.rstart + HEADER_SIZE;
                    // smux/session.go:459-462: a zero-length PSH is skipped.
                    if !(cmd == Cmd::Psh && body == 0) {
                        st.on_frame(cmd, hdr.sid, &self.rbuf[start..start + body]);
                    }
                    self.rstart = start + body;
                    progress = true;
                }
            }
            if self.rstart == self.rend {
                self.rstart = 0;
                self.rend = 0;
            } else if self.rend == self.rbuf.len() {
                self.rbuf.copy_within(self.rstart..self.rend, 0);
                self.rend -= self.rstart;
                self.rstart = 0;
            }
            // A whole frame always fits (the buffer grows to the frame), so
            // there is room here.
            debug_assert!(self.rend < self.rbuf.len());
            let conn = self.conn.as_mut().expect("conn while open");
            let mut rb = ReadBuf::new(&mut self.rbuf[self.rend..]);
            match Pin::new(conn).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // io.ReadFull: "EOF" with nothing of the frame part
                        // it was reading, "unexpected EOF" with some.
                        let avail = self.rend - self.rstart;
                        let mid = if avail < HEADER_SIZE {
                            avail > 0
                        } else {
                            avail > HEADER_SIZE
                        };
                        self.end_read(Error::eof(mid));
                        return true;
                    }
                    self.rend += n;
                    progress = true;
                }
                Poll::Ready(Err(e)) => {
                    self.end_read(e.into());
                    return true;
                }
                Poll::Pending => return progress,
            }
        }
    }

    fn end_read(&mut self, err: Error) {
        self.read_done = true;
        self.shared.lock().fail_read(Some(err));
    }

    /// `sendLoop` (`smux/session.go:596-662`): one frame per write.
    fn poll_write_side(&mut self, cx: &mut Context<'_>) -> bool {
        let mut progress = false;
        loop {
            let f = match self.inflight {
                Some(f) => f,
                None => {
                    let next = {
                        let mut st = self.shared.lock();
                        if st.closed {
                            return progress;
                        }
                        st.pop_frame(&self.shared.cfg, &mut self.wbuf)
                    };
                    match next {
                        Some(f) => {
                            self.inflight = Some(f);
                            self.wpos = 0;
                            f
                        }
                        None => {
                            if self.need_flush {
                                let conn = self.conn.as_mut().expect("conn while open");
                                match Pin::new(conn).poll_flush(cx) {
                                    Poll::Ready(Ok(())) => self.need_flush = false,
                                    Poll::Ready(Err(e)) => {
                                        self.end_write(e);
                                        return true;
                                    }
                                    Poll::Pending => {}
                                }
                            }
                            return progress;
                        }
                    }
                }
            };
            while self.wpos < f.wire_len {
                let conn = self.conn.as_mut().expect("conn while open");
                match Pin::new(conn).poll_write(cx, &self.wbuf[self.wpos..f.wire_len]) {
                    Poll::Ready(Ok(0)) => {
                        self.end_write(io::ErrorKind::WriteZero.into());
                        return true;
                    }
                    Poll::Ready(Ok(n)) => self.wpos += n,
                    Poll::Ready(Err(e)) => {
                        self.end_write(e);
                        return true;
                    }
                    Poll::Pending => return progress,
                }
            }
            self.inflight = None;
            self.need_flush = true;
            progress = true;
            let mut st = self.shared.lock();
            st.frame_written(f);
            if st.rr_is_empty() && st.rx_total == 0 && st.tx_total == 0 {
                st.trim_pool();
            }
        }
    }

    fn end_write(&mut self, e: io::Error) {
        self.write_done = true;
        self.inflight = None;
        self.shared.lock().fail_write(e.into());
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Future for Driver<T> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let this = self.get_mut();
        if this.conn.is_none() {
            return Poll::Ready(Err(Error::ClosedPipe));
        }
        if !this.started {
            this.start();
        }
        loop {
            {
                let mut st = this.shared.lock();
                match &st.driver_waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => st.driver_waker = Some(cx.waker().clone()),
                }
                // Every handle is gone and what they queued is written.
                let idle = st.session_handles == 0
                    && st.stream_handles == 0
                    && st.rr_is_empty()
                    && this.inflight.is_none();
                // Both directions of the connection failed: nothing is left
                // to do.
                if !st.closed && (idle || (this.read_done && this.write_done)) {
                    st.close_session(None);
                }
                if st.closed {
                    let result = match st.close_reason.clone() {
                        Some(e) => Err(e),
                        None => match (&st.read_err, &st.write_err, st.proto_err) {
                            (_, _, true) => Err(Error::InvalidProtocol),
                            (Some(e), _, _) | (None, Some(e), _) => Err(e.clone()),
                            (None, None, false) => Ok(()),
                        },
                    };
                    st.driver_waker = None;
                    drop(st);
                    // Go closes the connection (smux/session.go:277).
                    this.conn = None;
                    this.rbuf = Vec::new();
                    this.wbuf = Vec::new();
                    return Poll::Ready(result);
                }
            }
            this.poll_keepalive(cx);
            let mut progress = false;
            if !this.read_done {
                progress |= this.poll_read_side(cx);
            }
            if !this.write_done {
                progress |= this.poll_write_side(cx);
            }
            if !progress {
                // A last look: the keepalive may have closed the session.
                if this.shared.lock().closed {
                    continue;
                }
                return Poll::Pending;
            }
        }
    }
}

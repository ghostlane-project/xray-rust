// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57 session.go, Copyright (c) 2016-2017 xtaci, MIT.

use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::arena::CHUNK;
use crate::driver::Driver;
pub use crate::state::Role;
use crate::state::{flag, Shared};
use crate::stream::Stream;
use crate::{Config, Error};

/// A smux session: Go's `*smux.Session` (`smux/session.go:92-134`).
///
/// A `Session` is a cheap handle (one pointer) and can be cloned. The
/// connection belongs to the [`Driver`] the constructor returns, which the
/// caller spawns. The session closes on [`Session::close`], on the
/// keepalive timeout, or once every `Session` and [`Stream`] handle is gone
/// and the frames they queued are written.
#[derive(Debug)]
pub struct Session {
    shared: Arc<Shared>,
}

/// A snapshot of a session's counters and buffers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Streams in the sid map: `NumStreams` (`smux/session.go:321-328`).
    pub streams: usize,
    /// Received payload not yet read, all streams. Equals
    /// `max_receive_buffer` minus the token bucket.
    pub rx_buffered: usize,
    /// The most `rx_buffered` ever was.
    pub peak_rx_buffered: usize,
    /// The token bucket (`smux/session.go:101`); at most 0 stops reading.
    pub bucket: i64,
    /// Payload queued to send, all streams.
    pub tx_queued: usize,
    /// The most `tx_queued` ever was.
    pub peak_tx_queued: usize,
    /// Pool bytes holding queued data.
    pub pool_in_use: usize,
    /// The most `pool_in_use` ever was.
    pub peak_pool_in_use: usize,
    /// Pool bytes allocated: in use plus kept for reuse.
    pub pool_held: usize,
    /// The driver's read buffer.
    pub read_buffer: usize,
    /// The driver's write buffer.
    pub write_buffer: usize,
    /// Frames received and written.
    pub frames_in: u64,
    /// Frames written to the connection.
    pub frames_out: u64,
    /// NOPs received.
    pub nop_in: u64,
    /// NOPs written.
    pub nop_out: u64,
    /// UPDs received (for any sid).
    pub upd_in: u64,
    /// UPDs written.
    pub upd_out: u64,
}

impl Session {
    /// A client session over `conn`: `smux.Client` (`smux/mux.go:111-117`).
    /// Spawn the returned [`Driver`].
    pub fn client<T>(conn: T, config: Config) -> Result<(Session, Driver<T>), Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        Session::new(conn, config, Role::Client)
    }

    /// A server session over `conn`: `smux.Server` (`smux/mux.go:120-126`).
    /// The olcRTC client never serves; this exists for tests.
    pub fn server<T>(conn: T, config: Config) -> Result<(Session, Driver<T>), Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        Session::new(conn, config, Role::Server)
    }

    /// A session of either role.
    pub fn new<T>(conn: T, config: Config, role: Role) -> Result<(Session, Driver<T>), Error>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        config.verify()?;
        let shared = Arc::new(Shared::new(config, role));
        let driver = Driver::new(conn, shared.clone());
        Ok((Session { shared }, driver))
    }

    /// The settings the session runs with.
    pub fn config(&self) -> &Config {
        &self.shared.cfg
    }

    /// This side's role.
    pub fn role(&self) -> Role {
        self.shared.role
    }

    /// Opens a stream: `OpenStream` (`smux/session.go:169-219`). The next
    /// id of this side's parity is taken, a SYN is written, and the stream
    /// is returned once the SYN is on the connection. Fails with
    /// [`Error::ClosedPipe`] on a closed session, [`Error::GoAway`] once ids
    /// run out, [`Error::Timeout`] when the SYN is not written within
    /// [`Config::open_close_timeout`], and with the connection's error when
    /// its read or write side has failed.
    pub async fn open_stream(&self) -> Result<Stream, Error> {
        let idx = {
            let mut st = self.shared.lock();
            if st.closed {
                return Err(Error::ClosedPipe);
            }
            if st.go_away {
                return Err(Error::GoAway);
            }
            // smux/session.go:181-190: ids advance by 2 until they wrap.
            let Some(sid) = st.next_sid.checked_add(2) else {
                st.go_away = true;
                return Err(Error::GoAway);
            };
            st.next_sid = sid;
            if let Some(e) = &st.write_err {
                return Err(e.clone());
            }
            // Registered before the SYN is written, so that nothing the peer
            // sends after it can miss the stream (Go registers after,
            // smux/session.go:195-209).
            let idx = st.alloc_slot(sid, flag::HANDLE | flag::SYN_QUEUED);
            st.register(idx);
            st.push_rr(idx);
            idx
        };
        let mut guard = OpenGuard {
            shared: &self.shared,
            idx,
            armed: true,
        };
        let wait = poll_fn(|cx| {
            let mut st = self.shared.lock();
            if st.closed {
                return Poll::Ready(Err(Error::ClosedPipe));
            }
            if let Some(e) = &st.write_err {
                return Poll::Ready(Err(e.clone()));
            }
            let s = st.slot_mut(idx);
            if s.has(flag::SYN_QUEUED | flag::SYN_FLIGHT) {
                crate::state::set_waker(&mut s.write_waker, cx);
                return Poll::Pending;
            }
            // smux/session.go:201-207: a failed read side fails the open (a
            // protocol error does not).
            if let Some(e) = &st.read_err {
                return Poll::Ready(Err(e.clone()));
            }
            st.stream_handles += 1;
            Poll::Ready(Ok(st.slot(idx).sid))
        });
        match tokio::time::timeout(self.shared.cfg.open_close_timeout, wait).await {
            Ok(Ok(sid)) => {
                guard.armed = false;
                Ok(Stream::new(self.shared.clone(), idx, sid))
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Waits for the next stream the peer opens: `AcceptStream`
    /// (`smux/session.go:228-252`). Fails with the connection's read error,
    /// [`Error::InvalidProtocol`], or [`Error::ClosedPipe`] once the session
    /// is closed. Cancel-safe.
    pub async fn accept_stream(&self) -> Result<Stream, Error> {
        poll_fn(|cx| {
            let mut st = self.shared.lock();
            if let Some(idx) = st.accept_q.pop_front() {
                st.stream_handles += 1;
                if st.read_paused {
                    st.read_paused = false;
                    st.wake_driver();
                }
                let sid = st.slot(idx).sid;
                return Poll::Ready(Ok(Stream::new(self.shared.clone(), idx, sid)));
            }
            if st.closed {
                return Poll::Ready(Err(Error::ClosedPipe));
            }
            if let Some(e) = &st.read_err {
                return Poll::Ready(Err(e.clone()));
            }
            if st.proto_err {
                return Poll::Ready(Err(Error::InvalidProtocol));
            }
            st.add_accept_waker(cx);
            Poll::Pending
        })
        .await
    }

    /// Closes the session and every stream: `Close` (`smux/session.go:260-278`).
    /// Nothing more is written; the driver drops the connection. A second
    /// call returns [`Error::ClosedPipe`].
    pub fn close(&self) -> Result<(), Error> {
        if self.shared.lock().close_session(None) {
            Ok(())
        } else {
            Err(Error::ClosedPipe)
        }
    }

    /// `IsClosed` (`smux/session.go:316-318`).
    pub fn is_closed(&self) -> bool {
        self.shared.lock().closed
    }

    /// Resolves once the session is closed: `CloseChan` (`smux/session.go:282-284`).
    pub async fn closed(&self) {
        poll_fn(|cx| {
            let mut st = self.shared.lock();
            if st.closed {
                Poll::Ready(())
            } else {
                st.add_closed_waker(cx);
                Poll::Pending
            }
        })
        .await
    }

    /// Why the session closed: `None` while open or after [`Session::close`];
    /// [`Error::Timeout`] after the keepalive closed it; otherwise the
    /// connection's first error.
    pub fn close_reason(&self) -> Option<Error> {
        let st = self.shared.lock();
        if !st.closed {
            return None;
        }
        st.close_reason
            .clone()
            .or_else(|| st.read_err.clone())
            .or_else(|| st.write_err.clone())
            .or(if st.proto_err {
                Some(Error::InvalidProtocol)
            } else {
                None
            })
    }

    /// `NumStreams` (`smux/session.go:321-328`).
    pub fn num_streams(&self) -> usize {
        let st = self.shared.lock();
        if st.closed {
            0
        } else {
            st.sids.len()
        }
    }

    /// Counters and buffer sizes.
    pub fn stats(&self) -> Stats {
        let st = self.shared.lock();
        Stats {
            streams: st.sids.len(),
            rx_buffered: st.rx_total,
            peak_rx_buffered: st.counters.peak_rx,
            bucket: st.bucket,
            tx_queued: st.tx_total,
            peak_tx_queued: st.counters.peak_tx,
            pool_in_use: st.arena.in_use() * CHUNK,
            peak_pool_in_use: st.arena.peak_in_use() * CHUNK,
            pool_held: st.arena.held() * CHUNK,
            read_buffer: st.counters.read_buffer,
            write_buffer: st.counters.write_buffer,
            frames_in: st.counters.frames_in,
            frames_out: st.counters.frames_out,
            nop_in: st.counters.nop_in,
            nop_out: st.counters.nop_out,
            upd_in: st.counters.upd_in,
            upd_out: st.counters.upd_out,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_next_stream_id(&self, sid: u32) {
        self.shared.lock().next_sid = sid;
    }
}

impl Clone for Session {
    fn clone(&self) -> Session {
        self.shared.lock().session_handles += 1;
        Session {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        st.session_handles -= 1;
        if st.session_handles == 0 {
            st.wake_driver();
        }
    }
}

/// Undoes an open that did not finish.
struct OpenGuard<'a> {
    shared: &'a Arc<Shared>,
    idx: u32,
    armed: bool,
}

impl Drop for OpenGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut st = self.shared.lock();
            if !st.closed {
                st.cancel_open(self.idx);
            } else {
                st.slot_mut(self.idx).clear(flag::HANDLE);
                st.free_if_done(self.idx);
            }
        }
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57 stream.go, Copyright (c) 2016-2017 xtaci, MIT.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::state::{flag, set_waker, Shared};
use crate::Error;

/// One multiplexed stream: Go's `*smux.Stream` (`smux/stream.go:35-79`).
///
/// - Reading ([`AsyncRead`]) returns at most the rest of one received frame
///   per call, as Go's `Read` does (`smux/stream.go:155-176,260-308`), and
///   sends the window update Go sends at the same points: on the first read,
///   and whenever the bytes read since the last update reach half of
///   [`Config::max_stream_buffer`](crate::Config::max_stream_buffer). As in
///   Go, the next read waits until that update is written. End of stream
///   (`Ok(0)`) comes after the peer's FIN, after this stream was closed, or
///   after the connection's clean EOF.
/// - Writing ([`AsyncWrite`]) cuts the data into frames exactly as Go's
///   `writeV2` (`smux/stream.go:533-642`) does, honours the peer's window,
///   and queues the frames for the driver. `poll_write` returns once whole
///   frames are queued; `poll_flush` waits until they are written.
/// - `poll_shutdown` is `CloseWrite` (`smux/stream.go:648-668`): once the
///   queued data is written, a FIN; reading goes on.
/// - [`Stream::close`] is `Close` (`smux/stream.go:672-697`). Dropping the
///   handle closes the stream the same way without waiting.
#[derive(Debug)]
pub struct Stream {
    shared: Arc<Shared>,
    idx: u32,
    sid: u32,
}

/// A snapshot of one stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Received payload not yet read.
    pub rx_buffered: usize,
    /// The most `rx_buffered` ever was.
    pub peak_rx_buffered: usize,
    /// Payload queued to send.
    pub tx_queued: usize,
    /// `numRead` (`smux/stream.go:70`).
    pub num_read: u32,
    /// `numWritten` (`smux/stream.go:71`).
    pub num_written: u32,
    /// `peerConsumed` (`smux/stream.go:75`).
    pub peer_consumed: u32,
    /// `peerWindow` (`smux/stream.go:76`).
    pub peer_window: u32,
    /// The peer's FIN arrived.
    pub peer_fin: bool,
}

impl Stream {
    /// The handle for slot `idx` of stream `sid`. The caller has counted it
    /// in `stream_handles`.
    pub(crate) fn new(shared: Arc<Shared>, idx: u32, sid: u32) -> Stream {
        Stream { shared, idx, sid }
    }

    /// The stream id: `ID` (`smux/stream.go:199-201`).
    pub fn id(&self) -> u32 {
        self.sid
    }

    /// Counters and buffers.
    pub fn stats(&self) -> StreamStats {
        let st = self.shared.lock();
        let s = st.slot(self.idx);
        StreamStats {
            rx_buffered: s.rx_payload as usize,
            peak_rx_buffered: s.peak_rx as usize,
            tx_queued: s.tx_payload as usize,
            num_read: s.num_read,
            num_written: s.num_written,
            peer_consumed: s.peer_consumed,
            peer_window: s.peer_window,
            peer_fin: s.has(flag::PEER_FIN),
        }
    }

    /// Go's `Close` (`smux/stream.go:672-697`): both directions. Returns
    /// [`Error::ClosedPipe`] if the stream is already dead (closed before,
    /// both FINs exchanged, or the session closed), and sends nothing then.
    /// Otherwise unread data is dropped, a FIN goes after the queued data
    /// (also after a `CloseWrite`, as in Go), and the call waits until it is
    /// written, at most [`Config::open_close_timeout`](crate::Config::open_close_timeout)
    /// ([`Error::Timeout`]; the FIN stays queued).
    pub async fn close(&mut self) -> Result<(), Error> {
        // Go's Close follows the Write calls, which return once their frames
        // are on the connection (smux/stream.go:607-613): the data queued
        // here goes out first, then the FIN is queued.
        let drained = self.wait_written().await;
        self.shared.lock().close_stream(self.idx)?;
        drained?;
        self.wait_written().await
    }

    async fn wait_written(&mut self) -> Result<(), Error> {
        let wait = poll_fn(|cx| {
            let mut st = self.shared.lock();
            if st.closed {
                return Poll::Ready(Err(Error::ClosedPipe));
            }
            if let Some(e) = &st.write_err {
                return Poll::Ready(Err(e.clone()));
            }
            let s = st.slot_mut(self.idx);
            if s.tx_frames == 0 {
                return Poll::Ready(Ok(()));
            }
            set_waker(&mut s.write_waker, cx);
            Poll::Pending
        });
        match tokio::time::timeout(self.shared.cfg.open_close_timeout, wait).await {
            Ok(r) => r,
            Err(_) => Err(Error::Timeout),
        }
    }
}

impl Stream {
    /// Ready once a read would not wait: data, the peer's FIN, the end of
    /// the stream or the session, or an error. A copy waits here before it
    /// puts a buffer down; the wait counts as a read waiting
    /// (`flag::READ_PARKED`), so the read after it sees the stream's
    /// death as a waiting read does.
    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut guard = self.shared.lock();
        let st = &mut *guard;
        let idx = self.idx;
        if st.slot(idx).has(flag::UPD_QUEUED | flag::UPD_FLIGHT) {
            set_waker(&mut st.slot_mut(idx).read_waker, cx);
            return Poll::Pending;
        }
        let over = st.closed || st.read_err.is_some() || st.proto_err;
        let s = st.slot_mut(idx);
        if over || !s.rx.is_empty() || s.has(flag::PEER_FIN | flag::DIED) {
            return Poll::Ready(());
        }
        s.set(flag::READ_PARKED);
        set_waker(&mut s.read_waker, cx);
        Poll::Pending
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let cfg = &this.shared.cfg;
        let mut guard = this.shared.lock();
        let st = &mut *guard;
        let idx = this.idx;
        // Go's Read returns only after its window update is written
        // (smux/stream.go:296-297,412-428); here the next read waits for it.
        if st.slot(idx).has(flag::UPD_QUEUED | flag::UPD_FLIGHT) {
            set_waker(&mut st.slot_mut(idx).read_waker, cx);
            return Poll::Pending;
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let n = {
            let crate::state::State {
                slots,
                arena,
                rx_headers,
                ..
            } = &mut *st;
            let s = slots[idx as usize].as_mut().expect("live slot");
            let before = s.rx.stored();
            let n = s.rx.read_front(arena, buf.initialize_unfilled());
            // A frame opened here gave its length back to the pool.
            *rx_headers -= before - s.rx.stored() - n;
            n
        };
        if n > 0 {
            buf.advance(n);
            let s = st.slot_mut(idx);
            s.clear(flag::READ_PARKED);
            s.rx_payload -= n as u32;
            // smux/stream.go:277-285: the first read, or half the buffer
            // read since the last update, sends one.
            s.num_read = s.num_read.wrapping_add(n as u32);
            s.incr = s.incr.wrapping_add(n as u32);
            let threshold = (cfg.max_stream_buffer / 2) as u32;
            let mut notify = 0;
            if s.incr >= threshold || s.num_read == n as u32 {
                notify = s.num_read;
                s.incr = 0;
            }
            let registered = s.has(flag::REGISTERED);
            st.return_tokens(n);
            // smux/stream.go:296-297; an update only while the peer can still
            // hear of this stream.
            if notify > 0 && registered && !st.closed && st.write_err.is_none() {
                st.queue_upd(idx, notify);
            }
            return Poll::Ready(Ok(()));
        }
        let closed = st.closed;
        let s = st.slot_mut(idx);
        let parked = s.has(flag::READ_PARKED);
        s.clear(flag::READ_PARKED);
        // smux/stream.go:302-307,443-450: EOF once nothing is left and the
        // peer sent FIN.
        if s.has(flag::PEER_FIN) {
            return Poll::Ready(Ok(()));
        }
        let died = s.has(flag::DIED) || closed;
        // smux/stream.go:451-454.
        if let Some(e) = &st.read_err {
            return Poll::Ready(if e.is_clean_eof() {
                Ok(())
            } else {
                Err(e.clone().into())
            });
        }
        if st.proto_err {
            return Poll::Ready(Err(Error::InvalidProtocol.into()));
        }
        // `waitRead` (smux/stream.go): a read that waited when the stream
        // died gets io.ErrClosedPipe; one that starts after it, io.EOF
        // (`tryRead`).
        if died {
            return Poll::Ready(if parked {
                Err(Error::ClosedPipe.into())
            } else {
                Ok(())
            });
        }
        let s = st.slot_mut(idx);
        s.set(flag::READ_PARKED);
        set_waker(&mut s.read_waker, cx);
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let cfg = &this.shared.cfg;
        let idx = this.idx;
        // smux/stream.go:535-537.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut guard = this.shared.lock();
        let st = &mut *guard;
        // smux/stream.go:540-542,630-637.
        if st.closed {
            return Poll::Ready(Err(Error::ClosedPipe.into()));
        }
        let s = st.slot(idx);
        if s.has(flag::WRITE_CLOSED | flag::DIED) {
            return Poll::Ready(Err(Error::ClosedPipe.into()));
        }
        if let Some(e) = &st.write_err {
            return Poll::Ready(Err(e.clone().into()));
        }
        // smux/stream.go:581-587, modulo 2^32 as in Go.
        let inflight = s.num_written.wrapping_sub(s.peer_consumed) as i32;
        if inflight < 0 {
            return Poll::Ready(Err(Error::Consumed.into()));
        }
        let win = (s.peer_window as i32).wrapping_sub(inflight);
        if win <= 0 {
            set_waker(&mut st.slot_mut(idx).write_waker, cx);
            return Poll::Pending;
        }
        // smux/stream.go:589-617: up to the window, in frames of at most
        // MaxFrameSize. Only whole frames of that cut are queued, so the
        // frames match Go's whatever the queue room.
        let n = buf.len().min(win as usize);
        let mut stream_room = cfg
            .max_stream_send_buffer
            .saturating_sub(s.tx_payload as usize);
        let mut session_room = cfg.max_send_buffer.saturating_sub(st.tx_total);
        let mut done = 0;
        let mut session_full = false;
        while done < n {
            let size = cfg.max_frame_size.min(n - done);
            if size > session_room {
                session_full = true;
                break;
            }
            if size > stream_room {
                break;
            }
            st.queue_data(idx, &buf[done..done + size]);
            let s = st.slot_mut(idx);
            s.num_written = s.num_written.wrapping_add(size as u32);
            stream_room -= size;
            session_room -= size;
            done += size;
        }
        if done == 0 {
            if session_full {
                st.wait_room(idx, cx);
            } else {
                set_waker(&mut st.slot_mut(idx).write_waker, cx);
            }
            return Poll::Pending;
        }
        Poll::Ready(Ok(done))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut st = this.shared.lock();
        if st.closed {
            return Poll::Ready(Err(Error::ClosedPipe.into()));
        }
        if let Some(e) = &st.write_err {
            return Poll::Ready(Err(e.clone().into()));
        }
        let s = st.slot_mut(this.idx);
        if s.tx_frames == 0 {
            return Poll::Ready(Ok(()));
        }
        set_waker(&mut s.write_waker, cx);
        Poll::Pending
    }

    /// `CloseWrite` (`smux/stream.go:648-668`): a FIN after the queued data,
    /// then wait until it is written. Unlike Go's, a second call is not an
    /// error: it waits for the same FIN.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut st = this.shared.lock();
        if !st.slot(this.idx).has(flag::WRITE_CLOSED) {
            // As in Go, where CloseWrite follows Write calls that returned
            // with their frames on the connection (smux/stream.go:607-613),
            // the FIN is queued once this stream's data is written.
            let live = !st.closed && st.write_err.is_none();
            let s = st.slot_mut(this.idx);
            if live && s.tx_frames > 0 {
                set_waker(&mut s.write_waker, cx);
                return Poll::Pending;
            }
            if let Err(e) = st.close_write(this.idx) {
                return Poll::Ready(Err(e.into()));
            }
        }
        if st.closed {
            return Poll::Ready(Err(Error::ClosedPipe.into()));
        }
        if let Some(e) = &st.write_err {
            return Poll::Ready(Err(e.clone().into()));
        }
        let s = st.slot_mut(this.idx);
        if s.tx_frames == 0 {
            return Poll::Ready(Ok(()));
        }
        set_waker(&mut s.write_waker, cx);
        Poll::Pending
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.shared.lock().drop_handle(self.idx);
    }
}

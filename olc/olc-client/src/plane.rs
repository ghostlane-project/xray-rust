// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A lane of a transport that batches nothing and has a control plane of
//! its own (vp8channel; `muxconn.Conn` with no batcher, conn.go): each
//! smux frame is sealed into one record of the lane's kind
//! ([`olc_muxconn::Sender`]) and sent as one transport message, on the
//! data plane or the control plane; the records that arrive open into a
//! bounded queue that reads as a byte stream ([`olc_muxconn::Receiver`]).
//!
//! # Bounds
//!
//! - inbound: the receiver's queue,
//!   [`olc_muxconn::conn::inbound_capacity`] bytes; a full queue makes
//!   [`PlaneLane::push`] wait, which stops the plane's reads;
//! - outbound: the sender's one record and one record being sent, each at
//!   most `WIRE_OVERHEAD + max_frame` bytes; a write waits while both are
//!   taken (Go's `Write` blocks in the transport's `Send` the same way).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use olc_muxconn::conn::inbound_capacity;
use olc_muxconn::{
    DecryptStats, Features, Push, Receiver, Sender, Stats, DECRYPT_LOG_INTERVAL,
    WRITE_READY_TIMEOUT,
};
use olc_net::link::{DataSink, SinkFuture};
use olc_wire::record::{KeySet, Lane as RecordLane};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::vp8link::Vp8Link;

/// One lane over a plane.
pub struct PlaneLane {
    link: Arc<Vp8Link>,
    kind: RecordLane,
    stats: Arc<Stats>,
    st: Mutex<State>,
    /// The receiver has room again (for [`PlaneLane::push`]).
    space: Notify,
    /// A record waits to go, or the lane closed (for the sender task).
    kick: Notify,
}

impl std::fmt::Debug for PlaneLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneLane")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

struct State {
    rx: Receiver,
    tx: Sender,
    /// The sealed record waiting for the sender task; `None` when free.
    out: Option<Vec<u8>>,
    /// The buffer the next record is copied into (the one the task gave
    /// back).
    spare: Vec<u8>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    closed: bool,
    failed: Option<io::ErrorKind>,
    decrypt_logged_at: Option<Instant>,
    decrypt_logged: u64,
}

impl PlaneLane {
    /// A lane of `kind` (data or control) over `link`'s plane of that kind,
    /// for frames as `features` bound them, and the connection smux runs
    /// on. The sender task starts now and ends with the lane.
    #[must_use]
    pub fn new(
        link: Arc<Vp8Link>,
        keys: Arc<KeySet>,
        features: &Features,
        kind: RecordLane,
    ) -> (Arc<PlaneLane>, PlaneIo) {
        let rx = Receiver::new(
            keys.clone(),
            kind,
            inbound_capacity(features.max_record_plaintext()),
        );
        let stats = rx.stats().clone();
        let lane = Arc::new(PlaneLane {
            link,
            kind,
            stats,
            st: Mutex::new(State {
                rx,
                tx: Sender::new(keys, kind, features.max_frame()),
                out: None,
                spare: Vec::new(),
                read_waker: None,
                write_waker: None,
                closed: false,
                failed: None,
                decrypt_logged_at: None,
                decrypt_logged: 0,
            }),
            space: Notify::new(),
            kick: Notify::new(),
        });
        tokio::spawn(send_loop(lane.clone()));
        (
            lane.clone(),
            PlaneIo {
                lane,
                link_wait: None,
            },
        )
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn control(&self) -> bool {
        self.kind == RecordLane::Control
    }

    fn can_send(&self) -> bool {
        if self.control() {
            self.link.control_can_send()
        } else {
            self.link.can_send()
        }
    }

    /// The counters the control loop and the classifier read.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// What the peer has sent in stream payload (`PayloadBytes`).
    pub fn payload_bytes(&self) -> u64 {
        self.stats.payload_bytes()
    }

    /// Records that did not open, by kind (`DecryptStats`).
    pub fn decrypt_stats(&self) -> DecryptStats {
        self.stats.decrypt_stats()
    }

    /// Whether sending has stalled past the write-ready timeout.
    pub fn send_stalled(&self) -> bool {
        self.stats.send_stalled()
    }

    /// Whether the lane is closed.
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Closes the lane: reads end, writes fail, a waiting push returns.
    pub fn close(&self) {
        let (r, w) = {
            let mut st = self.lock();
            st.closed = true;
            (st.read_waker.take(), st.write_waker.take())
        };
        if let Some(w) = r {
            w.wake();
        }
        if let Some(w) = w {
            w.wake();
        }
        self.space.notify_one();
        self.kick.notify_one();
    }

    fn fail(&self, kind: io::ErrorKind) {
        self.lock().failed = Some(kind);
        self.close();
    }

    /// Opens one transport message into the queue (`Push`), waiting while
    /// the queue is full. Returns at once on a closed lane.
    pub async fn push(&self, record: &mut [u8]) {
        loop {
            let space = self.space.notified();
            {
                let mut st = self.lock();
                if st.closed {
                    return;
                }
                match st.rx.push(record) {
                    Push::Busy => {}
                    Push::Taken(_) => {
                        if let Some(w) = st.read_waker.take() {
                            drop(st);
                            w.wake();
                        }
                        return;
                    }
                    Push::Dropped(err) => {
                        note_decrypt_failure(&mut st, &self.stats, record.len(), &err);
                        return;
                    }
                    Push::Oversized(n) => {
                        crate::info!("muxconn: dropped an oversized record of {n} bytes");
                        return;
                    }
                }
            }
            space.await;
        }
    }
}

impl DataSink for PlaneLane {
    fn push<'a>(&'a self, record: &'a mut [u8]) -> SinkFuture<'a> {
        Box::pin(PlaneLane::push(self, record))
    }
}

/// Go's `noteDecryptFailure` (as the batched lane logs it).
fn note_decrypt_failure(st: &mut State, stats: &Stats, size: usize, err: &impl std::fmt::Display) {
    let total = stats.decrypt_fails();
    let now = Instant::now();
    match st.decrypt_logged_at {
        None => {
            st.decrypt_logged_at = Some(now);
            st.decrypt_logged = total;
            crate::info!("muxconn: decrypt failed len={size}: {err}");
        }
        Some(at) if now.duration_since(at) >= DECRYPT_LOG_INTERVAL => {
            let dropped = total - st.decrypt_logged;
            st.decrypt_logged_at = Some(now);
            st.decrypt_logged = total;
            crate::info!(
                "muxconn: decrypt failed for {dropped} more frames in the last {}s, latest len={size}: {err}",
                DECRYPT_LOG_INTERVAL.as_secs()
            );
        }
        Some(_) => {}
    }
}

/// Sends each sealed record as one message on the lane's plane.
async fn send_loop(lane: Arc<PlaneLane>) {
    loop {
        let record = loop {
            let kicked = lane.kick.notified();
            {
                let mut st = lane.lock();
                if st.closed {
                    return;
                }
                if let Some(r) = st.out.take() {
                    break r;
                }
            }
            kicked.await;
        };
        // The record is taken: a write waiting for room may seal the next.
        let w = lane.lock().write_waker.take();
        if let Some(w) = w {
            w.wake();
        }
        let sent = if lane.control() {
            lane.link.control_send(&record).await
        } else {
            lane.link.send(&record).await
        };
        if let Err(e) = sent {
            crate::debug!("muxconn: send: {e}");
            lane.fail(io::ErrorKind::BrokenPipe);
            return;
        }
        let w = {
            let mut st = lane.lock();
            if st.spare.capacity() < record.capacity() {
                st.spare = record;
            }
            st.write_waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

/// The connection smux runs on. Dropping it closes the lane.
pub struct PlaneIo {
    lane: Arc<PlaneLane>,
    /// The wait for a plane that cannot send.
    link_wait: Option<Pin<Box<dyn Future<Output = bool> + Send + Sync>>>,
}

impl std::fmt::Debug for PlaneIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneIo")
            .field("lane", &self.lane)
            .finish_non_exhaustive()
    }
}

impl Drop for PlaneIo {
    fn drop(&mut self) {
        self.lane.close();
    }
}

impl AsyncRead for PlaneIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let lane = &self.lane;
        let mut st = lane.lock();
        let n = st.rx.read(buf.initialize_unfilled());
        if n > 0 {
            buf.advance(n);
            drop(st);
            lane.space.notify_one();
            return Poll::Ready(Ok(()));
        }
        if st.closed {
            return Poll::Ready(Ok(()));
        }
        st.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn refused(st: &State) -> Option<io::Error> {
    if let Some(kind) = st.failed {
        return Some(kind.into());
    }
    st.closed.then(|| io::ErrorKind::BrokenPipe.into())
}

impl AsyncWrite for PlaneIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        frame: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let lane = &this.lane;
        // `awaitLink`: a wait that runs out marks the lane stalled.
        if this.link_wait.is_some() || !lane.can_send() {
            {
                let mut st = lane.lock();
                if let Some(err) = refused(&st) {
                    this.link_wait = None;
                    return Poll::Ready(Err(err));
                }
                st.write_waker = Some(cx.waker().clone());
            }
            let wait = this.link_wait.get_or_insert_with(|| {
                let link = lane.link.clone();
                let control = lane.control();
                Box::pin(async move { link.wait_ready(WRITE_READY_TIMEOUT, control).await })
            });
            match wait.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(ready) => {
                    this.link_wait = None;
                    if !ready {
                        lane.stats.note_write_stall();
                        lane.fail(io::ErrorKind::TimedOut);
                        return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                    }
                    lane.stats.note_write_ready();
                }
            }
        }
        let mut st = lane.lock();
        if let Some(err) = refused(&st) {
            return Poll::Ready(Err(err));
        }
        if st.out.is_some() {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut out = std::mem::take(&mut st.spare);
        match st.tx.seal(frame) {
            Ok(record) => {
                out.clear();
                out.extend_from_slice(record);
            }
            Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, e))),
        }
        st.out = Some(out);
        drop(st);
        lane.kick.notify_one();
        Poll::Ready(Ok(frame.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.lane.close();
        Poll::Ready(Ok(()))
    }
}

/// The lanes one session runs on: one batched lane (datachannel), or a lane
/// on each plane (vp8channel: the data session's and the control
/// session's).
#[derive(Debug, Clone)]
pub enum SessLane {
    /// One lane, every record on it.
    Batched(Arc<crate::lane::Lane>),
    /// The data plane's lane and the control plane's.
    Planes {
        /// The data session's.
        data: Arc<PlaneLane>,
        /// The control session's (the hello, the pings).
        control: Arc<PlaneLane>,
    },
}

impl SessLane {
    /// What the peer has sent in stream payload: the data lane's.
    pub fn payload_bytes(&self) -> u64 {
        match self {
            Self::Batched(l) => l.payload_bytes(),
            Self::Planes { data, .. } => data.payload_bytes(),
        }
    }

    /// Whether the data lane's sending has stalled.
    pub fn send_stalled(&self) -> bool {
        match self {
            Self::Batched(l) => l.send_stalled(),
            Self::Planes { data, .. } => data.send_stalled(),
        }
    }

    /// The records that did not open on the lane the hello's reply comes
    /// on: the one lane, or the control plane's.
    pub fn decrypt_stats(&self) -> DecryptStats {
        match self {
            Self::Batched(l) => l.decrypt_stats(),
            Self::Planes { control, .. } => control.decrypt_stats(),
        }
    }

    /// Closes every lane of the session.
    pub fn close(&self) {
        match self {
            Self::Batched(l) => l.close(),
            Self::Planes { data, control } => {
                data.close();
                control.close();
            }
        }
    }
}

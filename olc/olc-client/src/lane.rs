// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The data lane as smux sees it (`muxconn.Conn`, conn.go): an
//! `AsyncRead + AsyncWrite` connection whose writes are smux frames batched
//! into records ([`olc_muxconn::Batcher`]) and sent by a flusher task as one
//! transport message each, and whose reads come from the records the link
//! pushes in ([`olc_muxconn::Receiver`]).
//!
//! # Bounds
//!
//! - inbound: the receiver's queue, [`olc_muxconn::conn::inbound_capacity`]
//!   bytes (1 MiB on datachannel); a full queue makes [`Lane::push`] wait,
//!   which stops the link's reads (Go's `Push` blocking);
//! - outbound: one batch being filled and one being sent, each
//!   `max(MaxPayload − 44, max_frame)` bytes (12,244 on datachannel); a
//!   write that does not fit waits for the flusher to take the batch.
//!
//! `poll_write` takes a whole smux frame or nothing, as the smux driver
//! needs.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use olc_muxconn::conn::inbound_capacity;
use olc_muxconn::{
    Append, Batcher, DecryptStats, Features, Push, Receiver, Stats, Turn, DECRYPT_LOG_INTERVAL,
    WRITE_READY_TIMEOUT,
};
use olc_wire::record::{KeySet, Lane as RecordLane};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::pipe::PipeLink;

/// The datachannel transport's features (`datachannel/transport.go`):
/// messages of at most 12 KiB, small frames batched 5 ms apart.
pub const DATACHANNEL: Features = Features {
    max_payload_size: olc_smux::DATACHANNEL_MAX_PAYLOAD,
    write_interval: std::time::Duration::from_millis(5),
};

/// A lane that cannot be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LaneError {
    /// The transport has no write interval: every frame would be a record of
    /// its own, which the port does not do yet (vp8channel will).
    #[error("muxconn: a transport without batching is not carried yet")]
    NoBatching,
}

/// One data lane: the half the link pushes into and the flusher sends from.
#[derive(Debug)]
pub struct Lane {
    keys: Arc<KeySet>,
    link: Arc<PipeLink>,
    stats: Arc<Stats>,
    st: Mutex<State>,
    /// The receiver has room again (for [`Lane::push`]).
    space: Notify,
    /// Frames wait in the batch, or the lane closed (for the flusher).
    kick: Notify,
}

#[derive(Debug)]
struct State {
    rx: Receiver,
    batch: Batcher,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    closed: bool,
    failed: Option<io::ErrorKind>,
    decrypt_logged_at: Option<Instant>,
    decrypt_logged: u64,
}

impl Lane {
    /// A lane over `link` for a transport with `features`, and the
    /// connection smux runs on. The flusher task starts now and ends with the
    /// lane.
    ///
    /// # Errors
    /// [`LaneError::NoBatching`].
    pub fn new(
        link: Arc<PipeLink>,
        keys: Arc<KeySet>,
        features: &Features,
    ) -> Result<(Arc<Lane>, LaneIo), LaneError> {
        let batch = Batcher::new(features, features.max_frame()).ok_or(LaneError::NoBatching)?;
        let rx = Receiver::new(
            keys.clone(),
            RecordLane::Data,
            inbound_capacity(features.max_record_plaintext()),
        );
        let stats = rx.stats().clone();
        let lane = Arc::new(Lane {
            keys,
            link,
            stats,
            st: Mutex::new(State {
                rx,
                batch,
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
        tokio::spawn(flush(lane.clone()));
        Ok((
            lane.clone(),
            LaneIo {
                lane,
                due: None,
                link_wait: None,
            },
        ))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The counters the control loop and the classifier read.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// What the peer has sent in stream payload (`PayloadBytes`): the
    /// control loop's progress.
    pub fn payload_bytes(&self) -> u64 {
        self.stats.payload_bytes()
    }

    /// Records that did not open, by kind (`DecryptStats`).
    pub fn decrypt_stats(&self) -> DecryptStats {
        self.stats.decrypt_stats()
    }

    /// Whether sending has stalled past the write-ready timeout
    /// (`SendStalled`).
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

    fn fail(&self, kind: io::ErrorKind) {
        self.lock().failed = Some(kind);
        self.close();
    }
}

/// Go's `noteDecryptFailure`: the first failure is logged, then one line per
/// [`DECRYPT_LOG_INTERVAL`] with the count since.
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

/// The flusher (`batcher.flush`, batch.go): takes the batch when its turn
/// comes, waits for the link, seals and sends it.
async fn flush(lane: Arc<Lane>) {
    let mut last: Option<Instant> = None;
    loop {
        // Wait for frames and for their turn.
        let mut batch = loop {
            let kicked = lane.kick.notified();
            let at = {
                let mut st = lane.lock();
                if st.closed {
                    return;
                }
                if st.batch.pending_len() == 0 {
                    None
                } else {
                    match st.batch.turn(last, Instant::now()) {
                        Turn::Now => {
                            let batch = st.batch.take().expect("frames are pending");
                            let w = st.write_waker.take();
                            drop(st);
                            if let Some(w) = w {
                                w.wake();
                            }
                            break batch;
                        }
                        Turn::At(at) => Some(at),
                    }
                }
            };
            match at {
                None => kicked.await,
                Some(at) => {
                    tokio::select! {
                        () = kicked => {}
                        () = tokio::time::sleep_until(at.into()) => {}
                    }
                }
            }
        };
        // `awaitLink`: a wait that runs out marks the lane stalled.
        if !lane.link.can_send() && !lane.link.wait_ready(WRITE_READY_TIMEOUT).await {
            lane.stats.note_write_stall();
            lane.fail(io::ErrorKind::TimedOut);
            return;
        }
        lane.stats.note_write_ready();
        let sent = match batch.seal(&lane.keys, RecordLane::Data) {
            Ok(record) => lane.link.send(record).await,
            Err(e) => Err(io::Error::other(e)),
        };
        if let Err(e) = sent {
            crate::debug!("muxconn: send: {e}");
            lane.fail(io::ErrorKind::BrokenPipe);
            return;
        }
        last = Some(Instant::now());
        let w = {
            let mut st = lane.lock();
            st.batch.done(batch);
            st.write_waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

/// The connection smux runs on. Dropping it closes the lane.
///
/// A write returns once the link can send (`awaitLink`, conn.go:724) and,
/// when its frame made the batch due, once that batch has gone (`waitSent`,
/// batch.go): the hello's reply window starts when its SYN is on the way,
/// not while the path is closed (olcrtc#10). A write that returned
/// `Pending` after its frame was taken must be polled again with the same
/// frame, as the smux driver does.
pub struct LaneIo {
    lane: Arc<Lane>,
    /// The frame taken into batch `.0`, `.1` bytes, waiting for it to go.
    due: Option<(u64, usize)>,
    /// The wait for a link that cannot send.
    link_wait: Option<LinkWait>,
}

type LinkWait = Pin<Box<dyn Future<Output = bool> + Send + Sync>>;

impl std::fmt::Debug for LaneIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneIo")
            .field("due", &self.due)
            .field("link_wait", &self.link_wait.is_some())
            .finish_non_exhaustive()
    }
}

impl LaneIo {
    /// The lane behind it.
    pub fn lane(&self) -> &Arc<Lane> {
        &self.lane
    }
}

impl Drop for LaneIo {
    fn drop(&mut self) {
        self.lane.close();
    }
}

impl AsyncRead for LaneIo {
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

/// Why a write cannot go on: the lane failed or closed.
fn refused(st: &State) -> Option<io::Error> {
    if let Some(kind) = st.failed {
        return Some(kind.into());
    }
    st.closed.then(|| io::ErrorKind::BrokenPipe.into())
}

impl AsyncWrite for LaneIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        frame: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let lane = &this.lane;
        // `waitSent`: the frame is in a batch that has not gone yet.
        if let Some((batch, len)) = this.due {
            let mut st = lane.lock();
            if st.batch.sent() >= batch {
                this.due = None;
                return Poll::Ready(Ok(len));
            }
            if let Some(err) = refused(&st) {
                this.due = None;
                return Poll::Ready(Err(err));
            }
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // `awaitLink`: a wait that runs out marks the lane stalled; one that
        // does not clears it.
        if this.link_wait.is_some() || !lane.link.can_send() {
            {
                let mut st = lane.lock();
                if let Some(err) = refused(&st) {
                    this.link_wait = None;
                    return Poll::Ready(Err(err));
                }
                // The close wakes it.
                st.write_waker = Some(cx.waker().clone());
            }
            let wait = this.link_wait.get_or_insert_with(|| {
                let link = lane.link.clone();
                Box::pin(async move { link.wait_ready(WRITE_READY_TIMEOUT).await })
            });
            match wait.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(joined) => {
                    this.link_wait = None;
                    if !joined {
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
        match st.batch.append(frame) {
            Ok(Append::Queued) => {
                drop(st);
                lane.kick.notify_one();
                Poll::Ready(Ok(frame.len()))
            }
            Ok(Append::Due(batch)) => {
                this.due = Some((batch, frame.len()));
                st.write_waker = Some(cx.waker().clone());
                drop(st);
                lane.kick.notify_one();
                Poll::Pending
            }
            Ok(Append::Full) => {
                st.write_waker = Some(cx.waker().clone());
                drop(st);
                lane.kick.notify_one();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.lane.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::{LinkEvent, KIND_DATA};
    use crate::testhub::TestHub;
    use crate::testing::bounded;
    use olc_wire::record::Role;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    async fn lane_on(room: &str) -> (TestHub, Arc<PipeLink>, Arc<Lane>, LaneIo) {
        let (hub, url) = TestHub::start(room).await;
        let (tx, _) = mpsc::channel::<LinkEvent>(4);
        let link = PipeLink::connect(&url, tx).await.unwrap();
        let keys = Arc::new(KeySet::from_hex(&"11".repeat(32), Role::Client).unwrap());
        let (lane, io) = Lane::new(link.clone(), keys, &DATACHANNEL).unwrap();
        (hub, link, lane, io)
    }

    #[tokio::test]
    async fn a_batched_write_waits_for_a_link_that_can_send() {
        bounded(async {
            let (hub, link, _lane, mut io) = lane_on("await-link").await;
            let mut m = hub.accept().await;
            link.set_ready(false);
            let mut write = Box::pin(io.write(&[7u8; 10]));
            assert!(
                timeout(Duration::from_millis(300), write.as_mut())
                    .await
                    .is_err(),
                "a write returned while the link could not send (awaitLink, conn.go:724)"
            );
            link.set_ready(true);
            assert_eq!(timeout(Duration::from_secs(2), write).await.unwrap().unwrap(), 10);
            let (kind, _) = m.read().await.unwrap();
            assert_eq!(kind, KIND_DATA);
        })
        .await;
    }

    #[tokio::test]
    async fn a_write_that_makes_its_batch_due_returns_once_the_batch_went() {
        bounded(async {
            let (hub, _link, lane, mut io) = lane_on("wait-sent").await;
            let _m = hub.accept().await; // never reads
            let frame = vec![9u8; 7000];
            assert!(frame.len() >= DATACHANNEL.max_frame() / 2);
            let mut accepted = 0usize;
            loop {
                match timeout(Duration::from_millis(300), io.write(&frame)).await {
                    Ok(r) => {
                        assert_eq!(r.unwrap(), frame.len());
                        accepted += 1;
                        assert!(accepted < 10_000, "the hub never backed up");
                    }
                    Err(_) => break,
                }
            }
            // The write that waits is the one whose batch the flusher holds
            // (waitSent, batch.go): nothing was taken in after it.
            assert_eq!(lane.lock().batch.pending_len(), 0);
        })
        .await;
    }

    #[test]
    fn the_datachannel_numbers() {
        assert_eq!(DATACHANNEL.max_frame(), 12_244);
        assert_eq!(
            inbound_capacity(DATACHANNEL.max_record_plaintext()),
            olc_muxconn::conn::INBOUND_BYTE_CAP
        );
    }
}

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
//!
//! A write that fails (a link that cannot send for the write-ready timeout,
//! a failed send) fails writes only, as in Go: the reads go on until the
//! session above ends on its liveness rule (`SendStalled`, a control write
//! that fails) and closes the lane.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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
    /// What every write reports once the flusher gave up (`batcher.err`).
    failed: Option<(io::ErrorKind, String)>,
    decrypt_logged_at: Option<Instant>,
    decrypt_logged: u64,
    /// How long a write waits for the link (`sendDeadline`, conn.go:226-231):
    /// [`WRITE_READY_TIMEOUT`]; only tests change it (`writeTimeout`).
    write_timeout: std::time::Duration,
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
                write_timeout: WRITE_READY_TIMEOUT,
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

    /// `batcher.fail` (batch.go:206-213): every later write reports `err`
    /// and the writer that waits is woken. Nothing else changes: the reads
    /// go on (`Conn.Read`, conn.go:637-699, never looks at it) until the
    /// session above ends on its liveness rule and closes the lane.
    fn fail(&self, err: &io::Error) {
        let w = {
            let mut st = self.lock();
            st.failed = Some((err.kind(), err.to_string()));
            st.write_waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
}

/// `ErrWriteTimeout` (conn.go:42-54).
fn write_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "muxconn: write timeout waiting for transport",
    )
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
        // `writeRecord` (conn.go:731-743): `awaitLink`, whose wait that runs
        // out marks the lane stalled (conn.go:751-758), then the seal and
        // the send. What fails it fails the batcher, and the flusher ends
        // (`flushLoop`, batch.go:240-246).
        let limit = lane.lock().write_timeout;
        if !lane.link.can_send() && !lane.link.wait_ready(limit).await {
            lane.stats.note_write_stall();
            lane.fail(&write_timeout());
            return;
        }
        lane.stats.note_write_ready();
        let sent = match batch.seal(&lane.keys, RecordLane::Data) {
            Ok(record) => lane
                .link
                .send(record)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("send: {e}"))),
            Err(e) => Err(io::Error::other(format!("encrypt: {e}"))),
        };
        if let Err(e) = sent {
            crate::debug!("muxconn: {e}");
            lane.fail(&e);
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

/// Why a write cannot go on: the lane closed (`ErrClosed`, conn.go:38-39,
/// looked at first, as `waitSendReady` and `add` do: conn.go:779-817,
/// batch.go:75-80) or the batcher failed (`append`, batch.go:103-105).
fn refused(st: &State) -> Option<io::Error> {
    if st.closed {
        return Some(io::Error::new(io::ErrorKind::BrokenPipe, "muxconn: closed"));
    }
    let (kind, why) = st.failed.as_ref()?;
    Some(io::Error::new(*kind, why.clone()))
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
            let limit;
            {
                let mut st = lane.lock();
                if let Some(err) = refused(&st) {
                    this.link_wait = None;
                    return Poll::Ready(Err(err));
                }
                // The close wakes it.
                st.write_waker = Some(cx.waker().clone());
                limit = st.write_timeout;
            }
            let wait = this.link_wait.get_or_insert_with(|| {
                let link = lane.link.clone();
                Box::pin(async move { link.wait_ready(limit).await })
            });
            match wait.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(joined) => {
                    this.link_wait = None;
                    if !joined {
                        // `Conn.Write` returns `awaitLink`'s error and fails
                        // nothing (conn.go:724-726): smux's send loop ends on
                        // it (smux session.go:655-657).
                        lane.stats.note_write_stall();
                        return Poll::Ready(Err(write_timeout()));
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
            assert_eq!(
                timeout(Duration::from_secs(2), write)
                    .await
                    .unwrap()
                    .unwrap(),
                10
            );
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
            while let Ok(r) = timeout(Duration::from_millis(300), io.write(&frame)).await {
                assert_eq!(r.unwrap(), frame.len());
                accepted += 1;
                assert!(accepted < 10_000, "the hub never backed up");
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

    /// A write that fails fails writes only, as Go's (`batcher.fail`,
    /// batch.go:206-213, touches no read state; `Conn.Read`,
    /// conn.go:637-699, never looks at it): the reads go on until the
    /// liveness rule ends the session. M4's datachannels under backpressure
    /// are the case: a link that cannot send and still delivers.
    mod write_failures {
        use super::*;
        use crate::config::Liveness;
        use crate::control::{self, End, Hooks};
        use crate::testhub::Member;
        use olc_smux::Session;
        use tokio::io::AsyncReadExt;
        use tokio_util::sync::CancellationToken;

        impl Lane {
            /// Go's `writeTimeout` (conn.go:217-219).
            fn set_write_timeout(&self, limit: Duration) {
                self.lock().write_timeout = limit;
            }
        }

        const QUICK: Duration = Duration::from_secs(2);
        /// `ErrWriteTimeout` (conn.go:42-54).
        const WRITE_TIMEOUT_TEXT: &str = "muxconn: write timeout waiting for transport";
        /// What the pipe double's sends fail with, as `writeRecord` wraps it
        /// (conn.go:739-741).
        const SEND_FAILED_TEXT: &str = "send: pipe double: send refused";

        fn server_keys() -> KeySet {
            KeySet::from_hex(&"11".repeat(32), Role::Server).unwrap()
        }

        /// The far end sends `plain` in a record; the lane must read it.
        async fn reads_on(m: &mut Member, keys: &KeySet, io: &mut LaneIo, plain: &[u8]) {
            let mut record = Vec::new();
            keys.seal_into(RecordLane::Data, plain, &mut record)
                .unwrap();
            m.send(KIND_DATA, &record).await.unwrap();
            let mut buf = vec![0u8; plain.len() + 16];
            let n = timeout(QUICK, io.read(&mut buf))
                .await
                .expect("a read")
                .unwrap();
            assert_eq!(
                &buf[..n],
                plain,
                "the reads ended with the writes; Go's go on (conn.go:637-699)"
            );
        }

        async fn until(what: &str, done: impl Fn() -> bool) {
            let wait = async {
                while !done() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            timeout(QUICK, wait)
                .await
                .unwrap_or_else(|_| panic!("{what}"));
        }

        /// `Conn.Write` (conn.go:713-728): a write whose wait for the link
        /// runs out reports `ErrWriteTimeout` (`waitSendReady`,
        /// conn.go:779-817) and marks the conn stalled (`awaitLink`,
        /// conn.go:751-757). The batcher is not failed: smux's send loop ends
        /// on that error (smux session.go:655-657).
        #[tokio::test]
        async fn a_write_that_waits_out_the_link_fails_alone_and_the_reads_go_on() {
            bounded(async {
                let (hub, link, lane, mut io) = lane_on("write-stall").await;
                let mut m = hub.accept().await;
                let server = server_keys();
                link.set_data(Some(lane.clone()));
                lane.set_write_timeout(Duration::from_millis(200));
                link.set_ready(false);
                let err = timeout(QUICK, io.write(&[7u8; 10]))
                    .await
                    .expect("the wait ran out")
                    .unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::TimedOut);
                assert!(lane.send_stalled(), "SendStalled (conn.go:612-617)");
                reads_on(&mut m, &server, &mut io, b"after the stall").await;
                assert_eq!(err.to_string(), WRITE_TIMEOUT_TEXT);
            })
            .await;
        }

        /// `flushLoop` (batch.go:225-249): a record the link never takes
        /// (`writeRecord`'s own wait, conn.go:731-734, for a link that went
        /// away after the write, conn.go:721-723) fails the batcher, and every
        /// write after reports that error (`append`, batch.go:103-105), even
        /// once the link can send again.
        #[tokio::test]
        async fn a_batch_the_link_never_takes_fails_every_write_and_the_reads_go_on() {
            bounded(async {
                let (hub, link, lane, mut io) = lane_on("flush-stall").await;
                let mut m = hub.accept().await;
                let server = server_keys();
                link.set_data(Some(lane.clone()));
                lane.set_write_timeout(Duration::from_millis(200));
                link.set_ready(false);
                assert!(matches!(
                    lane.lock().batch.append(&[7u8; 10]),
                    Ok(Append::Queued)
                ));
                lane.kick.notify_one();
                until("the flusher's wait never ran out", || lane.send_stalled()).await;
                link.set_ready(true);
                let err = timeout(QUICK, io.write(&[8u8; 10]))
                    .await
                    .expect("a failed batcher answers at once")
                    .unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::TimedOut);
                reads_on(&mut m, &server, &mut io, b"after the stall").await;
                assert_eq!(err.to_string(), WRITE_TIMEOUT_TEXT);
            })
            .await;
        }

        /// `writeRecord` (conn.go:739-741): a failed send is `send: <err>` and
        /// fails the batcher (batch.go:243-246); the write waiting for that
        /// record hears why (`waitSent`, batch.go:132-147), every write after
        /// reports it (batch.go:103-105), and it is no stall (only
        /// `ErrWriteTimeout` counts, conn.go:751-757).
        #[tokio::test]
        async fn a_send_that_fails_fails_every_write_and_the_reads_go_on() {
            bounded(async {
                let (hub, link, lane, mut io) = lane_on("send-fails").await;
                let mut m = hub.accept().await;
                let server = server_keys();
                link.set_data(Some(lane.clone()));
                link.refuse_sends(Some(io::ErrorKind::ConnectionReset));
                let due = vec![9u8; 7000];
                assert!(due.len() >= DATACHANNEL.max_frame() / 2);
                let waited = timeout(QUICK, io.write(&due))
                    .await
                    .expect("the record went or failed")
                    .unwrap_err();
                let later = timeout(QUICK, io.write(&[8u8; 10]))
                    .await
                    .expect("a failed batcher answers at once")
                    .unwrap_err();
                assert!(!lane.send_stalled());
                reads_on(&mut m, &server, &mut io, b"after the failed send").await;
                for err in [&waited, &later] {
                    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
                    assert_eq!(err.to_string(), SEND_FAILED_TEXT);
                }
            })
            .await;
        }

        /// The client's probe interval in the session tests.
        const TICK: Duration = Duration::from_secs(1);

        /// What the data plane does at the fault.
        #[derive(Clone, Copy)]
        enum Fault {
            /// The link stops taking writes and still delivers; a write
            /// waits this long for it.
            Stall(Duration),
            /// Every send fails; the link still delivers.
            Refuse,
        }

        /// One session's death, timed from its control loop's start.
        struct Death {
            end: End,
            fault: Duration,
            ended: Duration,
            /// When the client read the server's data, after the fault.
            reads: Vec<Duration>,
        }

        impl std::fmt::Debug for Death {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "end={:?} fault={:?} ended={:?} reads after the fault={} last={:?}",
                    self.end,
                    self.fault,
                    self.ended,
                    self.reads.len(),
                    self.reads.last()
                )
            }
        }

        impl Death {
            /// The reads went on after `from` until the session ended.
            fn read_on(&self, from: Duration) {
                let last = self.reads.last().copied().unwrap_or_default();
                assert!(
                    self.reads.iter().any(|&t| t > from + Duration::from_millis(150))
                        && last + Duration::from_millis(200) >= self.ended,
                    "the reads ended before the session did (Go's go on, conn.go:637-699): {self:?}"
                );
            }

            /// The session ended at `at`, within the box's jitter.
            fn ended_at(&self, at: Duration) {
                assert!(
                    self.ended + Duration::from_millis(50) >= at
                        && self.ended <= at + Duration::from_millis(400),
                    "the session did not end at {at:?}, where Go's does: {self:?}"
                );
            }
        }

        /// The client's and the server's lanes over one hub room, the hub
        /// relaying between them; each link hands its records to its lane.
        async fn plane(room: &str) -> (Arc<PipeLink>, Arc<Lane>, LaneIo, LaneIo) {
            let (hub, url) = TestHub::start(room).await;
            let (tx, _) = mpsc::channel::<LinkEvent>(4);
            let client = PipeLink::connect(&url, tx.clone()).await.unwrap();
            let mut a = hub.accept().await;
            let server = PipeLink::connect(&url, tx).await.unwrap();
            let mut b = hub.accept().await;
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut a.stream, &mut b.stream).await;
            });
            let (lane, io) = lane_over(&client, Role::Client);
            let (_, server_io) = lane_over(&server, Role::Server);
            (client, lane, io, server_io)
        }

        fn lane_over(link: &Arc<PipeLink>, role: Role) -> (Arc<Lane>, LaneIo) {
            let keys = Arc::new(KeySet::from_hex(&"11".repeat(32), role).unwrap());
            let (lane, io) = Lane::new(link.clone(), keys, &DATACHANNEL).unwrap();
            link.set_data(Some(lane.clone()));
            (lane, io)
        }

        /// A data session with its control loop at both ends and the server
        /// streaming to the client. Once the client's first probe has its
        /// pong, `fault` hits the client's data plane and the client writes
        /// one frame; the client's control loop runs until it ends. The
        /// server never pings, so the client's own probes and writes decide.
        async fn die(room: &str, fault: Fault) -> Death {
            let (link, lane, io, server_io) = plane(room).await;
            let cfg = olc_smux::Config::client_data(DATACHANNEL.max_payload_size, false);
            let (client, driver) = Session::client(io, cfg.clone()).unwrap();
            tokio::spawn(driver);
            let (server, driver) = Session::server(server_io, cfg).unwrap();
            tokio::spawn(driver);
            let control_stream = client.open_stream().await.unwrap();
            let data = client.open_stream().await.unwrap();
            let server_control = server.accept_stream().await.unwrap();
            let mut server_data = server.accept_stream().await.unwrap();

            let server_stop = CancellationToken::new();
            let quiet = Liveness {
                interval_ms: 3_600_000,
                timeout_ms: 3_600_000,
                failures: 0,
            };
            let server_hooks = Hooks {
                fields: "role=server".into(),
                progress: Box::new(|| 0),
                send_stalled: Box::new(|| false),
                on_pong: Box::new(|_| {}),
            };
            tokio::spawn(control::run(
                server_control,
                quiet,
                server_hooks,
                server_stop.clone(),
            ));
            let feeder = tokio::spawn(async move {
                while server_data.write_all(&[1u8; 100]).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });

            let (pong_tx, mut pong_rx) = mpsc::unbounded_channel::<()>();
            let hooks = Hooks {
                fields: "role=client session=t".into(),
                progress: Box::new({
                    let lane = lane.clone();
                    move || lane.payload_bytes()
                }),
                send_stalled: Box::new({
                    let lane = lane.clone();
                    move || lane.send_stalled()
                }),
                on_pong: Box::new(move |_| {
                    let _ = pong_tx.send(());
                }),
            };
            let liveness = Liveness {
                interval_ms: u64::try_from(TICK.as_millis()).unwrap(),
                ..Liveness::default()
            };
            let (mut rd, mut wr) = tokio::io::split(data);
            let run = Instant::now();
            let control = tokio::spawn(control::run(
                control_stream,
                liveness,
                hooks,
                CancellationToken::new(),
            ));
            timeout(TICK * 2, pong_rx.recv())
                .await
                .expect("the first probe's pong")
                .unwrap();
            let fault_at = run.elapsed();
            let reader = tokio::spawn(async move {
                let mut reads = Vec::new();
                let mut buf = [0u8; 4096];
                while matches!(rd.read(&mut buf).await, Ok(n) if n > 0) {
                    reads.push(run.elapsed());
                }
                reads
            });
            match fault {
                Fault::Stall(limit) => {
                    lane.set_write_timeout(limit);
                    link.set_ready(false);
                }
                Fault::Refuse => link.refuse_sends(Some(io::ErrorKind::ConnectionReset)),
            }
            let writer = tokio::spawn(async move {
                let _ = wr.write_all(b"x").await;
                let _ = wr.flush().await;
                wr
            });
            let end = control.await.unwrap();
            let ended = run.elapsed();
            // The death tears the session down (`dropSessionLocked`); only
            // then do the reads end.
            let _ = client.close();
            lane.close();
            let reads = timeout(QUICK, reader)
                .await
                .expect("the reads end with the session")
                .unwrap();
            server_stop.cancel();
            let _ = server.close();
            feeder.abort();
            writer.abort();
            Death {
                end,
                fault: fault_at,
                ended,
                reads: reads.into_iter().filter(|&t| t > fault_at).collect(),
            }
        }

        /// A stall that runs out between two probes, with no control write
        /// waiting: the writes are gone (smux session.go:655-657), the reads
        /// go on, and the next probe ends the session on `SendStalled`
        /// before it looks at the pongs (control.go:338-349,
        /// tunnelcore/control.go:92-94).
        #[tokio::test]
        async fn a_stall_between_probes_ends_the_session_at_the_next_probe() {
            bounded(async {
                let stall = Duration::from_millis(300);
                let d = die("die-stall-probe", Fault::Stall(stall)).await;
                d.read_on(d.fault + stall);
                assert_eq!(
                    d.end,
                    End::Unhealthy("the data plane stopped sending".into()),
                    "{d:?}"
                );
                d.ended_at(TICK * 2);
            })
            .await;
        }

        /// A stall that runs out while a probe waits to be written: that
        /// write fails with the stall's error then (smux stream.go:607-612
        /// waits for each frame, session.go:704-706 hands it the write
        /// error), and the session ends at the stall (control.go:454-468,
        /// 490-495, framing.go:48-50), not at the next probe.
        #[tokio::test]
        async fn a_stall_under_a_waiting_probe_ends_the_session_at_the_stall() {
            bounded(async {
                let stall = TICK + TICK / 2;
                let d = die("die-stall-write", Fault::Stall(stall)).await;
                d.read_on(d.fault);
                assert_eq!(
                    d.end,
                    End::Failed(format!("control: write frame: {WRITE_TIMEOUT_TEXT}")),
                    "{d:?}"
                );
                d.ended_at(d.fault + stall);
            })
            .await;
        }

        /// A failed send fails the batcher; the next control write, the
        /// next probe's ping, gets its error (batch.go:103-105, smux
        /// session.go:648-657) and ends the session then.
        #[tokio::test]
        async fn a_failed_send_ends_the_session_at_the_next_control_write() {
            bounded(async {
                let d = die("die-send", Fault::Refuse).await;
                d.read_on(d.fault);
                assert_eq!(
                    d.end,
                    End::Failed(format!("control: write frame: {SEND_FAILED_TEXT}")),
                    "{d:?}"
                );
                d.ended_at(TICK * 2);
            })
            .await;
        }
    }
}

//! Write batching (`internal/muxconn/batch.go`): small smux frames written
//! close together share one record, on a transport that asks for it with a
//! write interval (datachannel: 5 ms).
//!
//! The Jitsi-style bridges queue few messages per sender and drop the oldest
//! when they fall behind; a burst of new streams sent one frame per message
//! overflowed that queue (batch.go:13-32). A record that carries several
//! whole frames needs nothing new from the peer, which reads a byte stream.
//!
//! [`Batcher`] is Go's `batcher` without its locks and channels: the caller
//! is the writer and the flusher both, and does the waiting.
//!
//! - A writer offers a frame with [`Batcher::append`]. [`Append::Queued`]: its
//!   write is done. [`Append::Due`]: the batch is half a record or more, and
//!   the write is done once that batch has gone ([`Batcher::sent`] reaches
//!   it). [`Append::Full`]: wait until a batch is taken, then offer again.
//! - The flusher waits for its [`Batcher::turn`], takes the batch
//!   ([`Batcher::take`]), seals and sends it, and hands it back
//!   ([`Batcher::done`]).
//!
//! Memory: two buffers at most, the one writers fill and the one being sent,
//! each `RECORD_HEADER_SIZE + capacity + TAG_SIZE` bytes, where capacity is
//! the larger of the batch limit and the largest frame (see
//! [`Batcher::new`]). A batch is sealed where it was gathered.

use std::time::{Duration, Instant};

use olc_wire::record::{KeySet, Lane, SealError, RECORD_HEADER_SIZE, TAG_SIZE, WIRE_OVERHEAD};

use crate::conn::{Features, SendError};

/// The plaintext one batched record may carry, or `None` when the transport
/// wants every frame in a record of its own: no write interval, or a message
/// cap that leaves no room past the record overhead (`newBatcher`,
/// batch.go:50-63).
#[must_use]
pub fn batch_limit(features: &Features) -> Option<usize> {
    if features.write_interval.is_zero() {
        return None;
    }
    features
        .max_payload_size
        .checked_sub(WIRE_OVERHEAD)
        .filter(|&limit| limit > 0)
}

/// What [`Batcher::append`] did with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Append {
    /// The frame is in the batch; the write is done.
    Queued,
    /// The frame is in the batch, which is now due; the write is done once
    /// batch number `.0` has been sent.
    Due(u64),
    /// The frame does not fit beside what is pending; offer it again once a
    /// batch has been taken. The batch is due meanwhile.
    Full,
}

/// When the flusher may take the batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// Now: an interval has passed since the last record, or the batch is due.
    Now,
    /// Not before this, unless the batch becomes due first.
    At(Instant),
}

/// A batch the flusher has taken: the frames, with room for the record
/// header in front.
#[derive(Debug)]
pub struct Batch {
    buf: Vec<u8>,
}

impl Batch {
    /// The frames' bytes.
    #[must_use]
    pub fn frames(&self) -> &[u8] {
        &self.buf[RECORD_HEADER_SIZE..]
    }

    /// Seals the batch as one record of `lane` and returns it, ready to send.
    ///
    /// # Errors
    /// [`SealError::CounterExhausted`] when the lane has no counter left.
    pub fn seal(&mut self, keys: &KeySet, lane: Lane) -> Result<&[u8], SealError> {
        let len = self.buf.len();
        self.buf.resize(len + TAG_SIZE, 0);
        match keys.seal_in_place(lane, &mut self.buf) {
            Ok(()) => Ok(&self.buf),
            Err(e) => {
                self.buf.truncate(len);
                Err(e)
            }
        }
    }
}

/// Go's `batcher`, without IO (batch.go:33-213).
#[derive(Debug)]
pub struct Batcher {
    interval: Duration,
    limit: usize,
    capacity: usize,
    pending: Vec<u8>,
    spare: Option<Vec<u8>>,
    blocked: bool,
    taken: u64,
    sent: u64,
}

impl Batcher {
    /// A batcher for `features`, or `None` when it wants no batching
    /// ([`batch_limit`]). `max_frame` is the largest frame the writer
    /// writes: the smux frame header plus its frame size,
    /// `8 + olc_wire::sizes::max_frame_size(max_payload_size)`. A frame
    /// alone may be larger than the limit, as in Go, so each buffer holds
    /// `max(limit, max_frame)` bytes of frames.
    #[must_use]
    pub fn new(features: &Features, max_frame: usize) -> Option<Self> {
        let limit = batch_limit(features)?;
        let capacity = limit.max(max_frame);
        Some(Self {
            interval: features.write_interval,
            limit,
            capacity,
            pending: Self::buffer(capacity),
            spare: None,
            blocked: false,
            taken: 0,
            sent: 0,
        })
    }

    fn buffer(capacity: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RECORD_HEADER_SIZE + capacity + TAG_SIZE);
        buf.resize(RECORD_HEADER_SIZE, 0);
        buf
    }

    /// The plaintext limit of one batched record.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// The bytes of frames waiting in the batch.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len() - RECORD_HEADER_SIZE
    }

    /// Batches the flusher has taken.
    #[must_use]
    pub const fn taken(&self) -> u64 {
        self.taken
    }

    /// Batches the flusher has sent; a writer told [`Append::Due`]`(n)` is
    /// done once this reaches `n`.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Puts `frame` in the batch when it fits: when nothing is pending, or
    /// the batch stays within the limit (`append`, batch.go:97-116).
    ///
    /// # Errors
    /// [`SendError::FrameTooLarge`] for a frame over the `max_frame` the
    /// batcher was made for.
    pub fn append(&mut self, frame: &[u8]) -> Result<Append, SendError> {
        if frame.len() > self.capacity {
            return Err(SendError::FrameTooLarge {
                len: frame.len(),
                max: self.capacity,
            });
        }
        let pending = self.pending_len();
        let fits = pending == 0 || pending + frame.len() <= self.limit;
        self.blocked = !fits;
        if !fits {
            return Ok(Append::Full);
        }
        self.pending.extend_from_slice(frame);
        if self.pending_len() < self.limit / 2 {
            return Ok(Append::Queued);
        }
        Ok(Append::Due(self.taken + 1))
    }

    /// Whether the batch should leave without waiting out the interval: a
    /// writer waits for room, or the batch is half a record (`due`,
    /// batch.go:149-155).
    #[must_use]
    pub fn due(&self) -> bool {
        self.blocked || self.pending_len() >= self.limit / 2
    }

    /// When the flusher may take the batch, given when the last record went
    /// (`None` before the first) and the time now (`waitTurn`,
    /// batch.go:157-175). Go waits again after each wake-up; so does the
    /// caller, asking again.
    #[must_use]
    pub fn turn(&self, last: Option<Instant>, now: Instant) -> Turn {
        let Some(last) = last else {
            return Turn::Now;
        };
        let at = last + self.interval;
        if at <= now || self.due() {
            Turn::Now
        } else {
            Turn::At(at)
        }
    }

    /// Hands the batch to the flusher and starts an empty one; `None`, with
    /// nothing changed, when nothing is pending (`take`, batch.go:177-194).
    /// Only one batch is out at a time: hand it back with [`Batcher::done`]
    /// before taking the next.
    pub fn take(&mut self) -> Option<Batch> {
        if self.pending_len() == 0 {
            return None;
        }
        let next = self
            .spare
            .take()
            .unwrap_or_else(|| Self::buffer(self.capacity));
        let buf = std::mem::replace(&mut self.pending, next);
        self.blocked = false;
        self.taken += 1;
        Some(Batch { buf })
    }

    /// Records that the batch taken last has gone, and keeps its buffer for
    /// the one after next (`done`, batch.go:196-204).
    pub fn done(&mut self, batch: Batch) {
        let mut buf = batch.buf;
        buf.truncate(RECORD_HEADER_SIZE);
        self.spare = Some(buf);
        self.sent = self.taken;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(max: usize, interval_ms: u64) -> Features {
        Features {
            max_payload_size: max,
            write_interval: Duration::from_millis(interval_ms),
        }
    }

    #[test]
    fn the_buffers_never_grow() {
        let mut b = Batcher::new(&features(12288, 5), 8 + 12236).unwrap();
        let cap = b.pending.capacity();
        assert_eq!(cap, 12288, "a batch buffer is one transport message");
        for _ in 0..3 {
            while b.append(&[0; 1000]).unwrap() != Append::Full {}
            let batch = b.take().unwrap();
            assert_eq!(batch.buf.capacity(), cap);
            b.done(batch);
            assert_eq!(b.pending.capacity(), cap);
        }
    }

    #[test]
    fn the_first_batch_goes_at_once_and_later_ones_wait_an_interval() {
        let b = Batcher::new(&features(12288, 5), 8 + 12236).unwrap();
        let now = Instant::now();
        assert_eq!(b.turn(None, now), Turn::Now);
        assert_eq!(
            b.turn(Some(now), now),
            Turn::At(now + Duration::from_millis(5))
        );
        assert_eq!(b.turn(Some(now), now + Duration::from_millis(5)), Turn::Now);
    }

    #[test]
    fn a_frame_over_the_largest_is_refused() {
        let mut b = Batcher::new(&features(100, 5), 56).unwrap();
        assert!(matches!(
            b.append(&[0; 57]),
            Err(SendError::FrameTooLarge { len: 57, max: 56 })
        ));
        assert_eq!(b.pending_len(), 0);
    }
}

//! A lane's two directions (`internal/muxconn/conn.go`): [`Sender`] seals one
//! record per smux frame; [`Receiver`] opens the records that arrive into a
//! bounded queue that reads as a byte stream; [`Stats`] are the counters the
//! client's liveness check and handshake classifier read.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use olc_wire::record::{
    KeySet, Lane, OpenError, ReorderStats, SealError, RECORD_HEADER_SIZE, TAG_SIZE, WIRE_OVERHEAD,
};
use olc_wire::sizes;

use crate::batch::batch_limit;
use crate::scan::{self, SMUX_HEADER_SIZE};

/// What a transport tells the lanes (`transport.Features`, the parts muxconn
/// reads). Go's negative values mean what zero means, so they have no form
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Features {
    /// The largest message the transport carries; 0 for no limit
    /// (datachannel 12288, vp8channel 61440, or lower under a traffic shaper).
    pub max_payload_size: usize,
    /// Batch small frames written this close together; zero for no batching
    /// (datachannel 5 ms).
    pub write_interval: Duration,
}

impl Features {
    /// The largest frame smux writes over this transport: its header and the
    /// frame size `runtime` clamps it to (runtime.go:219-226).
    #[must_use]
    pub fn max_frame(&self) -> usize {
        let cap = i64::try_from(self.max_payload_size).unwrap_or(i64::MAX);
        SMUX_HEADER_SIZE + sizes::max_frame_size(cap)
    }

    /// The largest plaintext a record from a Go peer on this transport holds:
    /// one frame, or a batch of up to the batch limit.
    #[must_use]
    pub fn max_record_plaintext(&self) -> usize {
        self.max_frame().max(batch_limit(self).unwrap_or(0))
    }
}

/// A frame could not be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// Larger than the buffer was made for; smux, configured from the same
    /// [`Features`], never writes one.
    #[error("muxconn: frame of {len} bytes, at most {max}")]
    FrameTooLarge {
        /// The frame's length.
        len: usize,
        /// The largest frame.
        max: usize,
    },
    /// The lane has no counter left.
    #[error("encrypt: {0}")]
    Seal(#[from] SealError),
}

/// Seals each frame as one record of its lane (`writeRecord`,
/// conn.go:724-738), in one buffer of `WIRE_OVERHEAD + max_frame` bytes.
#[derive(Debug)]
pub struct Sender {
    keys: Arc<KeySet>,
    lane: Lane,
    max_frame: usize,
    record: Vec<u8>,
}

impl Sender {
    /// A sender of `lane` for frames of at most `max_frame` bytes
    /// ([`Features::max_frame`]).
    #[must_use]
    pub fn new(keys: Arc<KeySet>, lane: Lane, max_frame: usize) -> Self {
        Self {
            keys,
            lane,
            max_frame,
            record: Vec::with_capacity(WIRE_OVERHEAD + max_frame),
        }
    }

    /// The key set it seals with.
    #[must_use]
    pub const fn keys(&self) -> &Arc<KeySet> {
        &self.keys
    }

    /// The lane it seals on.
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
    }

    /// Seals `frame` as one record and returns it, ready to send as one
    /// transport message.
    ///
    /// # Errors
    /// [`SendError`]; nothing is sealed then.
    pub fn seal(&mut self, frame: &[u8]) -> Result<&[u8], SendError> {
        if frame.len() > self.max_frame {
            return Err(SendError::FrameTooLarge {
                len: frame.len(),
                max: self.max_frame,
            });
        }
        self.record.clear();
        self.record.resize(RECORD_HEADER_SIZE, 0);
        self.record.extend_from_slice(frame);
        self.record
            .resize(RECORD_HEADER_SIZE + frame.len() + TAG_SIZE, 0);
        self.keys.seal_in_place(self.lane, &mut self.record)?;
        Ok(&self.record)
    }
}

/// Records that did not open, by kind (`DecryptStats`, conn.go:617-630): a
/// bad magic is a peer on a pre-v2 record layer, a failed authentication a
/// peer on another key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecryptStats {
    /// Too short or not `OLC2`.
    pub bad_magic: u64,
    /// The tag did not match.
    pub auth_failed: u64,
}

/// A lane's counters, shared with whoever watches the link.
#[derive(Debug, Default)]
pub struct Stats {
    inbound_bytes: AtomicU64,
    payload_bytes: AtomicU64,
    decrypt_fails: AtomicU64,
    bad_magic: AtomicU64,
    auth_failed: AtomicU64,
    oversized: AtomicU64,
    write_stalls: AtomicU32,
}

impl Stats {
    /// Plaintext opened from the peer, of every record that authenticated
    /// (`InboundBytes`, conn.go:519-527).
    pub fn inbound_bytes(&self) -> u64 {
        self.inbound_bytes.load(Ordering::Relaxed)
    }

    /// Payload of PSH frames on streams, the only bytes that show the peer
    /// delivering something (`PayloadBytes`, conn.go:529-555). The control
    /// stream's liveness check reads this.
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes.load(Ordering::Relaxed)
    }

    /// Records that did not open, by kind.
    pub fn decrypt_stats(&self) -> DecryptStats {
        DecryptStats {
            bad_magic: self.bad_magic.load(Ordering::Relaxed),
            auth_failed: self.auth_failed.load(Ordering::Relaxed),
        }
    }

    /// Every record that did not open, whatever the reason; the rate-limited
    /// log line reads it (conn.go:487-517).
    pub fn decrypt_fails(&self) -> u64 {
        self.decrypt_fails.load(Ordering::Relaxed)
    }

    /// Authentic records too large for the inbound queue, dropped. Always 0
    /// with a Go peer on the same transport; Go would have taken them.
    pub fn oversized(&self) -> u64 {
        self.oversized.load(Ordering::Relaxed)
    }

    /// The writer waited [`crate::WRITE_READY_TIMEOUT`] and the transport
    /// never accepted data (`awaitLink`, conn.go:740-760).
    pub fn note_write_stall(&self) {
        self.write_stalls.fetch_add(1, Ordering::Relaxed);
    }

    /// The transport accepted a write.
    pub fn note_write_ready(&self) {
        self.write_stalls.store(0, Ordering::Relaxed);
    }

    /// A write waited out the whole deadline and nothing has got through
    /// since (`SendStalled`, conn.go:595-615). One stall is the whole answer.
    pub fn send_stalled(&self) -> bool {
        self.write_stalls.load(Ordering::Relaxed) > 0
    }

    fn note_open_failure(&self, err: OpenError) {
        match err {
            OpenError::TooShort(_) | OpenError::BadMagic => {
                self.bad_magic.fetch_add(1, Ordering::Relaxed);
            }
            OpenError::Authentication => {
                self.auth_failed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.decrypt_fails.fetch_add(1, Ordering::Relaxed);
    }
}

/// The inbound queue in bytes for records of at most `max_record_plaintext`:
/// Go's [`crate::INBOUND_QUEUE`] records, capped at [`INBOUND_BYTE_CAP`], and
/// never less than one record.
#[must_use]
pub fn inbound_capacity(max_record_plaintext: usize) -> usize {
    crate::INBOUND_QUEUE
        .saturating_mul(max_record_plaintext)
        .min(INBOUND_BYTE_CAP)
        .max(max_record_plaintext)
}

/// The most the inbound queue holds (the memory budget's 1 MiB for it,
/// plan §9). Go's 128 records of up to 32 KiB come to 4 MiB; a fuller
/// queue here stops the transport's reads sooner, which smux's own receive
/// window does anyway.
pub const INBOUND_BYTE_CAP: usize = 1 << 20;

/// What [`Receiver::push`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Opened; this many plaintext bytes joined the queue.
    Taken(usize),
    /// Did not open, and is dropped (Go counts and logs it).
    Dropped(OpenError),
    /// Opened, but larger than the whole queue: counted in
    /// [`Stats::oversized`] and dropped.
    Oversized(usize),
    /// The queue has no room for it yet: nothing was done, not even the
    /// open. Read, then push the same record again. This is Go's `Push`
    /// blocking on a full queue (conn.go:405-418).
    Busy,
}

/// Opens a lane's records into a bounded queue read as a byte stream
/// (`Push` and `Read`, conn.go:326-418, 632-692).
#[derive(Debug)]
pub struct Receiver {
    keys: Arc<KeySet>,
    lane: Lane,
    stats: Arc<Stats>,
    queue: VecDeque<u8>,
    capacity: usize,
}

impl Receiver {
    /// A receiver of `lane` whose queue holds `capacity` bytes, allocated now
    /// ([`inbound_capacity`]).
    #[must_use]
    pub fn new(keys: Arc<KeySet>, lane: Lane, capacity: usize) -> Self {
        Self {
            keys,
            lane,
            stats: Arc::new(Stats::default()),
            queue: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// The counters, to share with the liveness check.
    #[must_use]
    pub const fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// The reordering the key set saw on this lane (`ReorderStats`,
    /// conn.go:420-435).
    #[must_use]
    pub fn reorder_stats(&self) -> ReorderStats {
        self.keys.reorder_stats(self.lane)
    }

    /// Bytes waiting to be read.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.queue.len()
    }

    /// Opens one transport message, in place, and queues its plaintext.
    pub fn push(&mut self, record: &mut [u8]) -> Push {
        let plaintext = record.len().saturating_sub(WIRE_OVERHEAD);
        if plaintext <= self.capacity && plaintext > self.capacity - self.queue.len() {
            return Push::Busy;
        }
        let opened = match self.keys.open_in_place(self.lane, record) {
            Ok(opened) => opened,
            Err(e) => {
                self.stats.note_open_failure(e);
                return Push::Dropped(e);
            }
        };
        if opened.len() > self.capacity {
            self.stats.oversized.fetch_add(1, Ordering::Relaxed);
            return Push::Oversized(opened.len());
        }
        self.stats
            .inbound_bytes
            .fetch_add(opened.len() as u64, Ordering::Relaxed);
        self.stats
            .payload_bytes
            .fetch_add(scan::stream_payload_len(opened), Ordering::Relaxed);
        self.queue.extend(opened.iter());
        Push::Taken(opened.len())
    }

    /// Moves queued bytes into `out` and returns how many; 0 when the queue
    /// is empty. Like Go's `Read`, one call drains as many records as fit.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.queue.len());
        let (a, b) = self.queue.as_slices();
        let from_a = n.min(a.len());
        out[..from_a].copy_from_slice(&a[..from_a]);
        out[from_a..n].copy_from_slice(&b[..n - from_a]);
        self.queue.drain(..n);
        n
    }
}

#[cfg(test)]
mod tests {
    use olc_wire::record::Role;

    use super::*;

    const PSK: [u8; 32] = [9; 32];

    fn pair(capacity: usize) -> (Sender, Receiver) {
        let client = Arc::new(KeySet::new(&PSK, Role::Client).unwrap());
        let server = Arc::new(KeySet::new(&PSK, Role::Server).unwrap());
        (
            Sender::new(client, Lane::Data, 64),
            Receiver::new(server, Lane::Data, capacity),
        )
    }

    #[test]
    fn the_sizes_of_the_two_transports() {
        let dc = Features {
            max_payload_size: 12288,
            write_interval: Duration::from_millis(5),
        };
        assert_eq!(dc.max_frame(), 12244);
        assert_eq!(dc.max_record_plaintext(), 12244);
        assert_eq!(
            inbound_capacity(dc.max_record_plaintext()),
            INBOUND_BYTE_CAP
        );
        let vp8 = Features {
            max_payload_size: 61440,
            write_interval: Duration::ZERO,
        };
        assert_eq!(vp8.max_record_plaintext(), 32776);
        assert_eq!(Features::default().max_record_plaintext(), 32776);
    }

    #[test]
    fn a_full_queue_leaves_the_record_for_later() {
        let (mut tx, mut rx) = pair(10);
        let mut first = tx.seal(&[1; 6]).unwrap().to_vec();
        let mut second = tx.seal(&[2; 6]).unwrap().to_vec();
        assert_eq!(rx.push(&mut first), Push::Taken(6));
        let untouched = second.clone();
        assert_eq!(rx.push(&mut second), Push::Busy);
        assert_eq!(second, untouched, "a busy push does not open the record");
        let mut out = [0; 4];
        assert_eq!(rx.read(&mut out), 4);
        assert_eq!(rx.push(&mut second), Push::Taken(6));
        let mut out = [0; 16];
        assert_eq!(rx.read(&mut out), 8);
        assert_eq!(&out[..8], &[1, 1, 2, 2, 2, 2, 2, 2]);
        assert_eq!(rx.stats().inbound_bytes(), 12);
    }

    #[test]
    fn records_that_do_not_open_are_counted_by_kind() {
        let (mut tx, mut rx) = pair(64);
        let mut record = tx.seal(b"x").unwrap().to_vec();
        record[30] ^= 1;
        assert_eq!(
            rx.push(&mut record),
            Push::Dropped(OpenError::Authentication)
        );
        assert_eq!(
            rx.push(&mut [0u8; 3]),
            Push::Dropped(OpenError::TooShort(3))
        );
        assert_eq!(
            rx.stats().decrypt_stats(),
            DecryptStats {
                bad_magic: 1,
                auth_failed: 1
            }
        );
        assert_eq!(rx.stats().decrypt_fails(), 2);
    }

    #[test]
    fn a_record_larger_than_the_queue_is_dropped_after_it_opens() {
        let (mut tx, mut rx) = pair(8);
        let mut record = tx.seal(&[0; 9]).unwrap().to_vec();
        assert_eq!(rx.push(&mut record), Push::Oversized(9));
        assert_eq!(rx.stats().oversized(), 1);
        assert_eq!(rx.buffered(), 0);
    }

    #[test]
    fn a_stall_lasts_until_a_write_gets_through() {
        let stats = Stats::default();
        stats.note_write_stall();
        assert!(stats.send_stalled());
        stats.note_write_ready();
        assert!(!stats.send_stalled());
    }

    #[test]
    fn hot_structs_stay_small() {
        // Memory model §16: what each lane keeps besides its buffers.
        assert!(
            std::mem::size_of::<Sender>() <= 48,
            "{}",
            std::mem::size_of::<Sender>()
        );
        assert!(
            std::mem::size_of::<Receiver>() <= 64,
            "{}",
            std::mem::size_of::<Receiver>()
        );
        assert_eq!(std::mem::size_of::<Stats>(), 56);
    }
}

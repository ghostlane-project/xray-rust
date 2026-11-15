//! What one relay direction reads into.
//!
//! A direction owns no buffer. For each read it borrows one from the
//! process's pool, sized for that read, and gives it back as soon as the
//! read's bytes are written, or at once when the read finds nothing: a quiet
//! flow holds no payload buffer at all, and a busy one only for the moment
//! a read and its write take.
//!
//! The size of a read starts small and doubles each time a read fills it,
//! up to the cap, as a direction that grew its own buffer did; a read that
//! brings no more than half of what it could take sets the next size from
//! what it brought, so a burst's size does not outlive the burst.
//!
//! Bytes beyond the flow's floor come out of the process's byte budget
//! ([`xray_transport::memory_budget`]): a read takes them for its buffer
//! before it borrows it, and so does what the direction wrote that its
//! writer may still hold, until the writer is flushed. When the budget is
//! spent a direction reads less, down to its floor, and when even the floor
//! is taken by unflushed bytes it flushes before it reads again. It never
//! allocates past the budget.
//!
//! Buffer sizes are powers of two from 1 KiB to 1 MiB. The pool keeps a few
//! freed buffers of up to 128 KiB for the next read (`kept_bytes`), each
//! thread one beside the pool's lists, and [`relieve`] lets go of all of
//! them.

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use xray_transport::memory_budget::{BudgetPermits, ByteBudget};
use xray_transport::MemoryClass;

/// The largest buffer the pool keeps: one read of the default cap. A larger
/// one (a `bufferSize` above 128 KiB) is freed when it comes back.
pub(super) const LENT_BUFFER_SIZE: usize = super::DEFAULT_COPY_BUFFER_SIZE;

/// The smallest buffer: [`super::MIN_COPY_BUFFER_SIZE`], 1 KiB.
const SMALLEST_CLASS_SHIFT: u32 = 10;
/// Classes from 1 KiB to [`super::MAX_COPY_BUFFER_SIZE`], 1 MiB: 11.
const CLASSES: usize = 11;

/// Free buffer bytes the process keeps for the next read, by memory class:
/// sixty-four 128 KiB buffers (8 MiB), and on a constrained host four
/// (512 KiB). Kept bytes are those in the pool's lists and in the threads'
/// spares together.
const KEPT_BYTES: usize = 64 * LENT_BUFFER_SIZE;
const KEPT_BYTES_CONSTRAINED: usize = 4 * LENT_BUFFER_SIZE;

fn kept_bytes(class: MemoryClass) -> usize {
    match class {
        MemoryClass::Standard => KEPT_BYTES,
        MemoryClass::Constrained => KEPT_BYTES_CONSTRAINED,
    }
}

fn process_keeps() -> usize {
    kept_bytes(xray_transport::memory_class())
}

/// The class of the buffer a read of `len` bytes takes.
fn class_of(len: usize) -> usize {
    let len = len.max(1 << SMALLEST_CLASS_SHIFT).next_power_of_two();
    ((len.trailing_zeros() - SMALLEST_CLASS_SHIFT) as usize).min(CLASSES - 1)
}

fn class_len(class: usize) -> usize {
    1 << (SMALLEST_CLASS_SHIFT as usize + class)
}

/// The buffers no direction holds right now.
pub(super) struct Pool {
    free: Mutex<[Vec<Box<[u8]>>; CLASSES]>,
    /// Bytes in `free` and in threads' spares.
    kept: AtomicUsize,
    /// How many bytes to keep.
    keep: fn() -> usize,
    /// Whether each thread keeps the buffer it got back last beside those.
    thread_spare: bool,
    /// Moved on by [`relieve`]: a thread's spare from before is freed the
    /// next time the thread uses the pool.
    generation: AtomicUsize,
}

/// A thread's spare: the buffer it got back last, and which pool's.
struct Spare {
    pool: &'static Pool,
    generation: usize,
    buffer: Option<Box<[u8]>>,
}

impl Spare {
    fn into_buffer(mut self) -> Box<[u8]> {
        let buffer = self.buffer.take().expect("a spare holds its buffer");
        self.pool.kept.fetch_sub(buffer.len(), Ordering::Relaxed);
        buffer
    }

    fn is_current(&self) -> bool {
        self.generation == self.pool.generation.load(Ordering::Relaxed)
    }

    fn len(&self) -> usize {
        self.buffer.as_ref().map_or(0, |buffer| buffer.len())
    }
}

impl Drop for Spare {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.kept.fetch_sub(buffer.len(), Ordering::Relaxed);
        }
    }
}

thread_local! {
    /// The buffer this thread got back last. A stream that reads in several
    /// steps finds nothing between them many times a second, and its
    /// direction gives its buffer back each time; the direction that takes
    /// one next on this thread is most often the same one, and gets it
    /// without the lock the pool's lists need.
    static THREAD_SPARE: Cell<Option<Spare>> = const { Cell::new(None) };
}

/// The pool every relay in the process shares.
pub(super) static PROCESS_POOL: Pool = Pool::with_spares(process_keeps);

/// Frees every buffer the process's relays keep for later, and has every
/// thread free its spare the next time it relays: for a host under memory
/// pressure. Returns the bytes freed at once.
pub(crate) fn relieve() -> usize {
    PROCESS_POOL.relieve()
}

/// The bytes of free buffers the process's relays keep now, in the pool's
/// lists and the threads' spares: at most `kept_bytes` of the host's class.
pub(crate) fn kept_now() -> usize {
    PROCESS_POOL.kept.load(Ordering::Relaxed)
}

impl Pool {
    const fn with_spares(keep: fn() -> usize) -> Self {
        Self {
            free: Mutex::new([const { Vec::new() }; CLASSES]),
            kept: AtomicUsize::new(0),
            keep,
            thread_spare: true,
            generation: AtomicUsize::new(0),
        }
    }

    /// A pool of its own, without the threads' spares.
    #[cfg(test)]
    const fn new(keep: fn() -> usize) -> Self {
        Self {
            free: Mutex::new([const { Vec::new() }; CLASSES]),
            kept: AtomicUsize::new(0),
            keep,
            thread_spare: false,
            generation: AtomicUsize::new(0),
        }
    }

    /// A buffer of `class`: the thread's spare, the one of that class given
    /// back last, or a new one.
    fn take(&'static self, class: usize) -> Box<[u8]> {
        if self.thread_spare {
            if let Some(buffer) = self.take_spare(class) {
                return buffer;
            }
        }
        let kept = self.free.lock().unwrap_or_else(PoisonError::into_inner)[class].pop();
        match kept {
            Some(buffer) => {
                self.kept.fetch_sub(buffer.len(), Ordering::Relaxed);
                buffer
            }
            None => vec![0; class_len(class)].into_boxed_slice(),
        }
    }

    fn take_spare(&'static self, class: usize) -> Option<Box<[u8]>> {
        // No spare is reachable while the thread is ending.
        let spare = THREAD_SPARE.try_with(Cell::take).ok().flatten()?;
        if !spare.is_current() {
            drop(spare);
            return None;
        }
        if std::ptr::eq(spare.pool, self) && spare.len() == class_len(class) {
            return Some(spare.into_buffer());
        }
        // Another size: it stays the thread's spare.
        let _ = THREAD_SPARE.try_with(|slot| slot.set(Some(spare)));
        None
    }

    fn give_back(&'static self, buffer: Box<[u8]>) {
        let len = buffer.len();
        if len > LENT_BUFFER_SIZE || !self.reserve(len) {
            return;
        }
        let buffer = if self.thread_spare {
            let spare = Spare {
                pool: self,
                generation: self.generation.load(Ordering::Relaxed),
                buffer: Some(buffer),
            };
            // The thread keeps the newest; the one it kept goes to the list.
            // A thread that is ending keeps none, and the buffer is freed.
            match THREAD_SPARE.try_with(|slot| slot.replace(Some(spare))) {
                Ok(Some(displaced)) if displaced.is_current() => displaced.into_list(),
                Ok(_) | Err(_) => return,
            }
        } else {
            Some((self, buffer))
        };
        if let Some((pool, buffer)) = buffer {
            pool.push(buffer);
        }
    }

    /// Counts `len` more bytes as kept, if the pool may keep them.
    fn reserve(&self, len: usize) -> bool {
        let keep = (self.keep)();
        self.kept
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |kept| {
                (kept + len <= keep).then_some(kept + len)
            })
            .is_ok()
    }

    /// Puts a buffer already counted as kept on its list.
    fn push(&self, buffer: Box<[u8]>) {
        let class = class_of(buffer.len());
        self.free.lock().unwrap_or_else(PoisonError::into_inner)[class].push(buffer);
    }

    fn relieve(&self) -> usize {
        self.generation.fetch_add(1, Ordering::Relaxed);
        let freed: Vec<Box<[u8]>> = {
            let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
            free.iter_mut().flat_map(std::mem::take).collect()
        };
        let bytes = freed.iter().map(|buffer| buffer.len()).sum();
        self.kept.fetch_sub(bytes, Ordering::Relaxed);
        bytes
    }

    #[cfg(test)]
    fn free_buffers(&self) -> usize {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(Vec::len)
            .sum()
    }
}

impl Spare {
    /// The spare's buffer, still counted as kept, for its pool's list.
    fn into_list(mut self) -> Option<(&'static Pool, Box<[u8]>)> {
        let buffer = self.buffer.take()?;
        Some((self.pool, buffer))
    }
}

pub(super) struct RelayBuffer<'p> {
    pool: &'static Pool,
    permits: BudgetPermits<'p>,
    /// The buffer of the last read, held until its bytes are written.
    borrowed: Option<Box<[u8]>>,
    /// The most a read takes at all.
    cap: usize,
    /// The most the next read takes, budget permitting.
    limit: usize,
    /// Bytes written since the writer was last flushed, which it may hold.
    unflushed: usize,
}

impl<'p> RelayBuffer<'p> {
    pub(super) fn new(cap: usize, pool: &'static Pool, budget: &'p ByteBudget) -> Self {
        Self {
            pool,
            permits: BudgetPermits::new(budget),
            borrowed: None,
            limit: cap.min(super::INITIAL_COPY_BUFFER_SIZE),
            cap,
            unflushed: 0,
        }
    }

    /// The largest read, at most the current size, whose buffer and the
    /// unflushed bytes fit in the floor and the bytes the budget gives.
    /// `None` when not even the smallest read fits.
    fn plan(&mut self) -> Option<usize> {
        let floor = self.permits.budget().floor();
        let smallest = class_len(0);
        let mut size = self.limit;
        loop {
            let buffer = class_len(class_of(size));
            let need = (self.unflushed + buffer).saturating_sub(floor);
            if self.permits.try_hold(need) >= need {
                self.permits.stop_waiting();
                return Some(size);
            }
            if size <= smallest {
                break;
            }
            size = (buffer / 2).clamp(smallest, size);
        }
        self.permits.try_hold(self.unflushed.saturating_sub(floor));
        None
    }

    /// What the smallest read needs of the budget, beside the floor.
    fn smallest_need(&self) -> usize {
        let floor = self.permits.budget().floor();
        (self.unflushed + class_len(0)).saturating_sub(floor)
    }

    /// Whether the writer has to be flushed before the next read: what it
    /// may hold leaves no room for the smallest read.
    pub(super) fn must_flush(&mut self) -> bool {
        self.unflushed > 0 && self.borrowed.is_none() && self.plan().is_none()
    }

    /// Bytes written since the writer was last flushed.
    pub(super) fn unflushed(&self) -> usize {
        self.unflushed
    }

    /// Reads once. The bytes are [`Self::filled`] until [`Self::written`].
    pub(super) fn poll_read<R: AsyncRead + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        reader: Pin<&mut R>,
    ) -> Poll<io::Result<usize>> {
        self.give_back();
        let size = match self.plan() {
            Some(size) => size,
            None => {
                // Woken once the budget has handed this direction the bytes
                // for its smallest read; the caller's flush makes room too.
                if !self.permits.wake_when_free(cx, self.smallest_need()) {
                    return Poll::Pending;
                }
                match self.plan() {
                    Some(size) => size,
                    None => {
                        // Taken by another holder meanwhile: wait again.
                        if self.permits.wake_when_free(cx, self.smallest_need()) {
                            cx.waker().wake_by_ref();
                        }
                        return Poll::Pending;
                    }
                }
            }
        };
        let mut buffer = self.pool.take(class_of(size));
        let mut read = ReadBuf::new(&mut buffer[..size]);
        match reader.poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                let len = read.filled().len();
                self.borrowed = Some(buffer);
                self.adapt(size, len);
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(error)) => {
                self.pool.give_back(buffer);
                self.hold_for_unflushed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                self.pool.give_back(buffer);
                self.hold_for_unflushed();
                Poll::Pending
            }
        }
    }

    /// The next read's size after a read of `size` brought `len` bytes.
    fn adapt(&mut self, size: usize, len: usize) {
        if len == size && size == self.limit {
            self.limit = (self.limit * 2).min(self.cap);
        } else if len > 0 && len <= size / 2 {
            let floor = self.cap.min(super::INITIAL_COPY_BUFFER_SIZE);
            self.limit = class_len(class_of(len)).clamp(floor, self.cap);
        }
    }

    /// The first `len` bytes of the last read.
    pub(super) fn filled(&self, len: usize) -> &[u8] {
        let buffer = self
            .borrowed
            .as_ref()
            .expect("the last read's buffer is held until its bytes are written");
        &buffer[..len]
    }

    /// The last read's `len` bytes were written: its buffer goes back, and
    /// the bytes count as unflushed until [`Self::flushed`].
    pub(super) fn written(&mut self, len: usize) {
        self.give_back();
        self.unflushed += len;
        self.hold_for_unflushed();
    }

    /// The writer was flushed: it holds nothing the direction wrote.
    pub(super) fn flushed(&mut self) {
        self.unflushed = 0;
        self.hold_for_unflushed();
    }

    fn hold_for_unflushed(&mut self) {
        let floor = self.permits.budget().floor();
        self.permits.try_hold(self.unflushed.saturating_sub(floor));
    }

    fn give_back(&mut self) {
        if let Some(buffer) = self.borrowed.take() {
            self.pool.give_back(buffer);
        }
    }
}

impl Drop for RelayBuffer<'_> {
    fn drop(&mut self) {
        self.give_back();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Waker;

    use xray_transport::memory_budget::ByteBudgetSettings;

    use super::*;

    const SMALL: usize = super::super::INITIAL_COPY_BUFFER_SIZE;
    const KIB: usize = 1024;

    fn keep_two() -> usize {
        2 * LENT_BUFFER_SIZE
    }

    fn pool() -> &'static Pool {
        Box::leak(Box::new(Pool::new(keep_two)))
    }

    fn budget(capacity: usize) -> &'static ByteBudget {
        Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
            capacity,
            floor: SMALL,
        })))
    }

    fn plenty() -> &'static ByteBudget {
        budget(64 * 1024 * KIB)
    }

    /// What a reader does at each read: hands over that many bytes, or has
    /// nothing yet.
    enum Step {
        Bytes(usize),
        Nothing,
    }

    /// As many bytes as the read takes.
    const FULL: Step = Step::Bytes(usize::MAX);

    struct Scripted {
        steps: VecDeque<Step>,
        /// The value of the next byte, so that order and content are checked.
        next: u8,
    }

    impl Scripted {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                next: 0,
            }
        }
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.steps.pop_front() {
                Some(Step::Bytes(len)) => {
                    let len = len.min(buf.remaining());
                    for _ in 0..len {
                        let byte = self.next;
                        buf.put_slice(&[byte]);
                        self.next = byte.wrapping_add(1);
                    }
                    Poll::Ready(Ok(()))
                }
                Some(Step::Nothing) => Poll::Pending,
                None => Poll::Ready(Ok(())),
            }
        }
    }

    /// One read and its write: its length, or `None` when the reader had
    /// nothing.
    fn read(buffer: &mut RelayBuffer<'_>, reader: &mut Scripted) -> Option<usize> {
        let len = read_held(buffer, reader)?;
        buffer.written(len);
        buffer.flushed();
        Some(len)
    }

    /// One read, its buffer still held.
    fn read_held(buffer: &mut RelayBuffer<'_>, reader: &mut Scripted) -> Option<usize> {
        let mut cx = Context::from_waker(Waker::noop());
        match buffer.poll_read(&mut cx, Pin::new(reader)) {
            Poll::Ready(result) => Some(result.expect("a scripted read does not fail")),
            Poll::Pending => None,
        }
    }

    /// A direction whose reads reached the cap.
    fn grown(pool: &'static Pool, budget: &'static ByteBudget) -> RelayBuffer<'static> {
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, pool, budget);
        let mut reader = Scripted::new((0..6).map(|_| FULL));
        for _ in 0..6 {
            read(&mut buffer, &mut reader);
        }
        assert_eq!(buffer.limit, LENT_BUFFER_SIZE);
        buffer
    }

    #[test]
    fn reads_double_while_they_fill_and_follow_a_short_one_down() {
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, pool(), plenty());
        let mut reader = Scripted::new([
            Step::Bytes(100),
            FULL,
            FULL,
            Step::Bytes(10 * KIB),
            FULL,
            FULL,
            FULL,
            FULL,
            FULL,
            FULL,
            Step::Bytes(10 * KIB),
            FULL,
        ]);

        assert_eq!(read(&mut buffer, &mut reader), Some(100));
        assert_eq!(read(&mut buffer, &mut reader), Some(SMALL));
        assert_eq!(read(&mut buffer, &mut reader), Some(8 * KIB));
        // A read that brings more than half keeps the size where it is.
        assert_eq!(read(&mut buffer, &mut reader), Some(10 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(16 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(32 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(64 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(128 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(128 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(128 * KIB));
        // The burst is over: one that brings less than half shrinks it.
        assert_eq!(read(&mut buffer, &mut reader), Some(10 * KIB));
        assert_eq!(read(&mut buffer, &mut reader), Some(16 * KIB));
    }

    #[test]
    fn a_direction_holds_no_buffer_between_reads() {
        let pool = pool();
        let mut buffer = grown(pool, plenty());
        assert!(buffer.borrowed.is_none(), "given back after its write");
        let free = pool.free_buffers();
        let mut reader = Scripted::new([Step::Nothing, Step::Bytes(10)]);
        assert_eq!(read_held(&mut buffer, &mut reader), None);
        assert!(
            buffer.borrowed.is_none(),
            "a read that finds nothing gives it back"
        );
        assert_eq!(pool.free_buffers(), free);
        assert_eq!(read_held(&mut buffer, &mut reader), Some(10));
        assert!(
            buffer.borrowed.is_some(),
            "held until its bytes are written"
        );
        assert_eq!(pool.free_buffers(), free - 1);
        buffer.written(10);
        assert!(buffer.borrowed.is_none());
        assert_eq!(pool.free_buffers(), free);
    }

    #[test]
    fn the_small_buffer_is_borrowed_too() {
        // R7: an idle direction that never grew holds nothing either.
        let pool = pool();
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, pool, plenty());
        let mut reader = Scripted::new([Step::Bytes(10), Step::Nothing]);
        assert_eq!(read(&mut buffer, &mut reader), Some(10));
        assert_eq!(read_held(&mut buffer, &mut reader), None);
        assert!(buffer.borrowed.is_none());
        assert_eq!(pool.free_buffers(), 1);
        assert_eq!(pool.kept.load(Ordering::Relaxed), SMALL);
    }

    #[test]
    fn the_last_read_stays_readable_until_it_is_written() {
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, pool(), plenty());
        let mut reader = Scripted::new([
            Step::Bytes(7),
            FULL,
            Step::Bytes(6000),
            Step::Nothing,
            Step::Bytes(3),
            FULL,
        ]);
        let mut expected = 0u8;
        let mut total = 0;
        for _ in 0..6 {
            let Some(len) = read_held(&mut buffer, &mut reader) else {
                continue;
            };
            for byte in buffer.filled(len) {
                assert_eq!(*byte, expected);
                expected = expected.wrapping_add(1);
            }
            buffer.written(len);
            buffer.flushed();
            total += len;
        }
        assert_eq!(total, 7 + SMALL + 6000 + 3 + SMALL);
    }

    #[test]
    fn directions_share_one_buffer_when_they_move_bulk_in_turn() {
        let pool = pool();
        let budget = plenty();
        let mut addresses = Vec::new();
        for _ in 0..8 {
            let mut buffer = grown(pool, budget);
            let mut reader = Scripted::new([FULL]);
            read_held(&mut buffer, &mut reader).expect("a full read");
            addresses.push(buffer.borrowed.as_ref().expect("held").as_ptr());
        }
        assert!(addresses.iter().all(|address| *address == addresses[0]));
    }

    #[test]
    fn the_pool_keeps_no_more_bytes_than_it_may() {
        let pool = pool();
        let class = class_of(LENT_BUFFER_SIZE);
        let taken: Vec<_> = (0..5).map(|_| pool.take(class)).collect();
        for buffer in taken {
            pool.give_back(buffer);
        }
        assert_eq!(pool.free_buffers(), 2);
        assert_eq!(pool.kept.load(Ordering::Relaxed), keep_two());
        // Nor a small one beside them.
        pool.give_back(pool.take(class_of(SMALL)));
        assert_eq!(pool.free_buffers(), 2);
        assert_eq!(pool.kept.load(Ordering::Relaxed), keep_two());
    }

    #[test]
    fn a_read_takes_no_more_than_the_cap() {
        let pool = pool();
        let budget = plenty();
        // Below the small size the direction reads at its cap.
        let mut tiny = RelayBuffer::new(KIB, pool, budget);
        let mut reader = Scripted::new([FULL, FULL]);
        assert_eq!(read(&mut tiny, &mut reader), Some(KIB));
        assert_eq!(read(&mut tiny, &mut reader), Some(KIB));

        // Between two sizes its reads stop at the cap.
        let mut middle = RelayBuffer::new(12 * KIB, pool, budget);
        let mut reader = Scripted::new([FULL, FULL, FULL, FULL]);
        assert_eq!(read(&mut middle, &mut reader), Some(SMALL));
        assert_eq!(read(&mut middle, &mut reader), Some(8 * KIB));
        assert_eq!(read(&mut middle, &mut reader), Some(12 * KIB));
        assert_eq!(read(&mut middle, &mut reader), Some(12 * KIB));
    }

    #[test]
    fn a_cap_above_the_kept_size_reads_large_and_keeps_nothing() {
        let pool = pool();
        let cap = 4 * LENT_BUFFER_SIZE;
        let mut buffer = RelayBuffer::new(cap, pool, plenty());
        let mut reader = Scripted::new((0..8).map(|_| FULL).chain([Step::Nothing, FULL]));
        let mut sizes = Vec::new();
        for _ in 0..8 {
            sizes.push(read(&mut buffer, &mut reader).expect("a full read"));
        }
        assert_eq!(
            sizes,
            [4, 8, 16, 32, 64, 128, 256, 512].map(|kib| kib * KIB)
        );
        assert_eq!(read(&mut buffer, &mut reader), None);
        assert!(buffer.borrowed.is_none(), "nothing is kept while idle");
        assert_eq!(read(&mut buffer, &mut reader), Some(cap));
        drop(buffer);
        assert!(pool.kept.load(Ordering::Relaxed) <= keep_two());
    }

    #[test]
    fn reads_beyond_the_floor_take_the_budget_and_give_it_back() {
        let budget = budget(100 * KIB);
        let mut buffer = grown(pool(), budget);
        assert_eq!(budget.in_use(), 0, "nothing held between reads");
        let mut reader = Scripted::new([FULL, FULL]);
        // 128 KiB does not fit in the floor and 100 KiB: it reads 64.
        assert_eq!(read_held(&mut buffer, &mut reader), Some(64 * KIB));
        assert_eq!(budget.in_use(), 60 * KIB);
        buffer.written(64 * KIB);
        assert_eq!(budget.in_use(), 60 * KIB, "the writer may hold them");
        buffer.flushed();
        assert_eq!(budget.in_use(), 0);
        // Another holder took the budget: the floor alone.
        let mut other = BudgetPermits::new(budget);
        other.try_hold(100 * KIB);
        assert_eq!(read_held(&mut buffer, &mut reader), Some(SMALL));
        buffer.written(SMALL);
        assert!(buffer.must_flush(), "the floor is written but not flushed");
        buffer.flushed();
        assert!(!buffer.must_flush());
        drop(other);
        assert_eq!(budget.in_use(), 0);
    }

    #[test]
    fn a_direction_waits_for_the_budget_rather_than_allocate() {
        let budget = budget(16 * KIB);
        let mut buffer = RelayBuffer::new(LENT_BUFFER_SIZE, pool(), budget);
        let mut reader = Scripted::new([FULL, FULL]);
        assert_eq!(read_held(&mut buffer, &mut reader), Some(SMALL));
        buffer.written(SMALL);
        let mut other = BudgetPermits::new(budget);
        other.try_hold(16 * KIB);
        // Unflushed bytes fill the floor and B is spent: no read.
        assert_eq!(read_held(&mut buffer, &mut reader), None);
        assert!(buffer.borrowed.is_none());
        drop(other);
        assert_eq!(read_held(&mut buffer, &mut reader), Some(8 * KIB));
    }

    #[test]
    fn a_thread_keeps_the_buffer_it_got_back_last_without_the_list() {
        let pool: &'static Pool = Box::leak(Box::new(Pool::with_spares(keep_two)));
        let class = class_of(LENT_BUFFER_SIZE);
        let first = pool.take(class);
        let second = pool.take(class);
        let (first_at, second_at) = (first.as_ptr(), second.as_ptr());

        pool.give_back(first);
        assert_eq!(pool.free_buffers(), 0, "the thread holds it");
        let first = pool.take(class);
        assert_eq!(first.as_ptr(), first_at);

        // With one held already, the newer stays and the older goes to the
        // list.
        pool.give_back(first);
        pool.give_back(second);
        assert_eq!(pool.free_buffers(), 1);
        let newer = pool.take(class);
        let older = pool.take(class);
        assert_eq!(newer.as_ptr(), second_at);
        assert_eq!(older.as_ptr(), first_at);
        assert_eq!(pool.free_buffers(), 0);
        assert_eq!(pool.kept.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn relieving_the_pool_frees_its_lists_and_the_threads_spares() {
        let pool: &'static Pool = Box::leak(Box::new(Pool::with_spares(keep_two)));
        let class = class_of(LENT_BUFFER_SIZE);
        let (first, second) = (pool.take(class), pool.take(class));
        pool.give_back(first);
        pool.give_back(second);
        assert_eq!(pool.kept.load(Ordering::Relaxed), 2 * LENT_BUFFER_SIZE);
        assert_eq!(pool.relieve(), LENT_BUFFER_SIZE, "the list's one at once");
        assert_eq!(pool.free_buffers(), 0);
        // The thread's spare is from before: it is freed, not handed out.
        let fresh = pool.take(class);
        assert_eq!(pool.kept.load(Ordering::Relaxed), 0);
        drop(fresh);
    }

    #[test]
    fn a_constrained_process_keeps_four_buffers() {
        assert_eq!(kept_bytes(MemoryClass::Standard), 64 * LENT_BUFFER_SIZE);
        assert_eq!(kept_bytes(MemoryClass::Constrained), 4 * LENT_BUFFER_SIZE);
    }

    #[test]
    fn buffer_classes_are_powers_of_two_from_one_kib_to_one_mib() {
        assert_eq!(class_len(class_of(1)), KIB);
        assert_eq!(class_len(class_of(KIB + 1)), 2 * KIB);
        assert_eq!(class_len(class_of(12 * KIB)), 16 * KIB);
        assert_eq!(class_len(class_of(128 * KIB)), 128 * KIB);
        assert_eq!(
            class_len(class_of(super::super::MAX_COPY_BUFFER_SIZE)),
            super::super::MAX_COPY_BUFFER_SIZE
        );
    }
}

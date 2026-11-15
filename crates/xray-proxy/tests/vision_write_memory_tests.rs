//! What a padded Vision write holds of the heap while its carrier waits,
//! counted by this binary's allocator on the test's own thread.
//!
//! A relay counts the bytes it hands a write in the process's byte budget
//! until the write returns, and keeps them meanwhile in its own buffer. A
//! padded write that copied its input and its padding into a buffer of the
//! stream's (`VisionStream`'s `pending_write`) held them a second time,
//! outside the budget, for as long as its carrier waited: up to 64 KiB and
//! 1,399 B of padding a flow while Vision pads. A phone's packet tunnel is
//! killed at about 50 MB and plans for 256 flows.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_proxy::vless::{VisionStream, VisionStreamIo};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static COUNTED: Cell<bool> = const { Cell::new(false) };
}

fn counted() -> bool {
    COUNTED.try_with(Cell::get).unwrap_or(false)
}

fn count(delta: isize) {
    let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    if delta > 0 {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: every call goes to `System` unchanged; the counters only watch.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && counted() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() && counted() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        if counted() {
            count(-(layout.size() as isize));
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() && counted() {
            count(new_size as isize - layout.size() as isize);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

static TURN: Mutex<()> = Mutex::new(());

/// Counts this thread's allocations until dropped; one test at a time.
struct Counted {
    _turn: MutexGuard<'static, ()>,
}

impl Counted {
    fn start() -> Self {
        let turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
        COUNTED.with(|counted| counted.set(true));
        Self { _turn: turn }
    }

    fn live(&self) -> isize {
        LIVE.load(Ordering::Relaxed)
    }

    /// Starts the peak again from what is live now.
    fn reset_peak(&self) -> isize {
        let now = self.live();
        PEAK.store(now, Ordering::Relaxed);
        now
    }

    fn peak(&self) -> isize {
        PEAK.load(Ordering::Relaxed)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        COUNTED.with(|counted| counted.set(false));
    }
}

const USER_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const SEED: [u32; 4] = [900, 500, 900, 256];
/// What the stream may hold of the heap while its carrier waits: none of
/// the writer's bytes, which are 32 KiB here.
const HELD_AT_MOST: isize = 1024;

/// A carrier that takes `left` bytes and then waits, keeping none of them;
/// one that gathers takes several slices in one call.
struct Stalling {
    left: usize,
    gathers: bool,
    taken: usize,
}

impl Stalling {
    fn new(left: usize, gathers: bool) -> Self {
        Self {
            left,
            gathers,
            taken: 0,
        }
    }

    fn take(&mut self, offered: usize) -> Poll<io::Result<usize>> {
        let len = offered.min(self.left);
        if len == 0 {
            return Poll::Pending;
        }
        self.left -= len;
        self.taken += len;
        Poll::Ready(Ok(len))
    }
}

impl AsyncRead for Stalling {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Stalling {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().take(input.len())
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let offered = if this.gathers {
            inputs.iter().map(|input| input.len()).sum()
        } else {
            inputs
                .iter()
                .find(|input| !input.is_empty())
                .map_or(0, |input| input.len())
        };
        this.take(offered)
    }

    fn is_write_vectored(&self) -> bool {
        self.gathers
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl VisionStreamIo for Stalling {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

/// Writes `payload` until the carrier waits; returns the bytes it took.
fn write_until_waiting(stream: &mut VisionStream<Stalling>, payload: &[u8]) -> usize {
    let mut cx = Context::from_waker(Waker::noop());
    let mut written = 0;
    while written < payload.len() {
        match Pin::new(&mut *stream).poll_write(&mut cx, &payload[written..]) {
            Poll::Ready(Ok(len)) => {
                assert_ne!(len, 0, "a write of bytes took none");
                written += len;
            }
            Poll::Ready(Err(error)) => panic!("the write failed: {error}"),
            Poll::Pending => break,
        }
    }
    written
}

/// A padded write whose carrier takes nothing, or the first frame's user
/// ID and part of its payload, and then waits: while it waits the stream
/// holds none of the writer's 32 KiB nor its padding, on a carrier that
/// gathers and on one that does not, and a carrier that gathers is offered
/// the writer's bytes without a copy of them even for the call. The stream
/// owed a copy of 32 KiB and its padding until the carrier took it.
#[test]
fn a_padded_write_that_waits_holds_none_of_its_bytes() {
    let payload: Vec<u8> = (0..32 * 1024).map(|at| at as u8).collect();
    // The padding's draws come from the thread's generator, which is made
    // on its first use and kept: a first write makes it before the count.
    let mut first = VisionStream::new(Stalling::new(usize::MAX, false), USER_ID, SEED);
    write_until_waiting(&mut first, b"warm");

    for gathers in [true, false] {
        for takes in [0, 1_000] {
            let mut stream = VisionStream::new(Stalling::new(takes, gathers), USER_ID, SEED);
            let counted = Counted::start();
            let before = counted.reset_peak();
            let written = write_until_waiting(&mut stream, &payload);
            let held = counted.live() - before;
            let peak = counted.peak() - before;
            drop(counted);

            assert!(written < payload.len(), "the carrier took the whole write");
            assert!(
                held <= HELD_AT_MOST,
                "a carrier that gathers: {gathers}, takes {takes} B: the stream held {held} B \
                 of the heap while its carrier waited, {written} B of the write taken"
            );
            if gathers {
                assert!(
                    peak <= HELD_AT_MOST,
                    "a carrier that gathers, takes {takes} B: the write allocated {peak} B at \
                     its peak"
                );
            }
            let taken = stream.get_ref().taken;
            assert!(
                takes == 0 || taken == takes,
                "the carrier took {taken} B of the {takes} it could"
            );
        }
    }
}

//! The uplink of a packet-up flow: the bytes written to it that no POST has
//! taken yet.
//!
//! Xray's packet-up writer puts every write into pooled 8 KiB buffers
//! (`pipe.New(pipe.WithSizeLimit(maxUploadSize - buf.Size))` in
//! `splithttp/dialer.go`), and its uploader takes all of them as one POST. A
//! flow there holds memory for the bytes waiting to be sent and nothing more.
//!
//! This pipe keeps the same bound, `scMaxEachPostBytes`, and the same POSTs: a
//! reader takes everything waiting, which is at most one POST. Its memory is
//! the bytes waiting plus at most one partly filled 8 KiB chunk, and a take
//! hands those bytes over and leaves the pipe holding nothing. tokio's duplex,
//! which this replaces, kept its buffer at its high-water mark (up to the
//! bound) for the flow's lifetime, and the worker read it into a scratch
//! buffer of the bound that every flow held, idle or not.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::mem;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use tokio::io::AsyncWrite;

/// Go's `buf.Size`: the unit small writes are gathered in.
const CHUNK_BYTES: usize = 8 * 1024;

/// A pipe that holds at most `capacity` bytes; a write past that waits for a
/// take.
pub(super) fn packet_pipe(capacity: usize) -> (PacketPipeWriter, PacketPipeReader) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            chunks: VecDeque::new(),
            buffered: 0,
            capacity: capacity.max(1),
            writer_closed: false,
            reader_closed: false,
            read_waker: None,
            write_waker: None,
        }),
    });
    (
        PacketPipeWriter {
            shared: Arc::clone(&shared),
        },
        PacketPipeReader { shared },
    )
}

struct Shared {
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // No code holding this lock can panic between two consistent states.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct State {
    /// Every chunk but the last is full; only the last may have room.
    chunks: VecDeque<Vec<u8>>,
    buffered: usize,
    capacity: usize,
    writer_closed: bool,
    reader_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl State {
    /// Copies as much of `input` as the pipe has room for. Small writes fill
    /// the last chunk's spare room; what does not fit gets one new chunk,
    /// sized to it but at least [`CHUNK_BYTES`], and never more than the pipe
    /// can still hold, so the chunks together never exceed `capacity`.
    fn push(&mut self, input: &[u8]) -> usize {
        let accepted = input.len().min(self.capacity - self.buffered);
        let mut rest = &input[..accepted];
        if let Some(last) = self.chunks.back_mut() {
            let fill = (last.capacity() - last.len()).min(rest.len());
            last.extend_from_slice(&rest[..fill]);
            rest = &rest[fill..];
        }
        if !rest.is_empty() {
            let room = self.capacity - self.buffered - (accepted - rest.len());
            let mut chunk = Vec::with_capacity(rest.len().max(CHUNK_BYTES).min(room));
            chunk.extend_from_slice(rest);
            self.chunks.push_back(chunk);
        }
        self.buffered += accepted;
        accepted
    }

    fn register(slot: &mut Option<Waker>, waker: &Waker) {
        match slot {
            Some(registered) if registered.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }
}

/// The flow's side: an [`AsyncWrite`] that accepts up to the pipe's room.
pub(super) struct PacketPipeWriter {
    shared: Arc<Shared>,
}

impl PacketPipeWriter {
    fn close(&self) {
        let reader = {
            let mut state = self.shared.lock();
            state.writer_closed = true;
            state.read_waker.take()
        };
        if let Some(reader) = reader {
            reader.wake();
        }
    }

    /// Heap the pipe holds now: its chunks and their queue.
    #[cfg(test)]
    pub(super) fn retained_bytes(&self) -> usize {
        let state = self.shared.lock();
        state.chunks.iter().map(Vec::capacity).sum::<usize>()
            + state.chunks.capacity() * mem::size_of::<Vec<u8>>()
    }
}

impl AsyncWrite for PacketPipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let (accepted, reader) = {
            let mut state = self.shared.lock();
            if state.reader_closed || state.writer_closed {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if state.buffered == state.capacity {
                State::register(&mut state.write_waker, cx.waker());
                return Poll::Pending;
            }
            let accepted = state.push(input);
            (accepted, state.read_waker.take())
        };
        if let Some(reader) = reader {
            reader.wake();
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for PacketPipeWriter {
    fn drop(&mut self) {
        self.close();
    }
}

/// The packet worker's side.
pub(super) struct PacketPipeReader {
    shared: Arc<Shared>,
}

impl PacketPipeReader {
    /// Takes everything waiting as one payload, or `None` once the writer is
    /// closed and nothing is left. Waits while the pipe is empty. Cancel-safe:
    /// bytes leave the pipe only in the poll that returns them.
    pub(super) async fn take(&mut self) -> Option<Vec<u8>> {
        poll_fn(|cx| self.poll_take(cx)).await
    }

    fn poll_take(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let (chunks, buffered, writer) = {
            let mut state = self.shared.lock();
            if state.buffered == 0 {
                if state.writer_closed {
                    return Poll::Ready(None);
                }
                State::register(&mut state.read_waker, cx.waker());
                return Poll::Pending;
            }
            let chunks = mem::take(&mut state.chunks);
            let buffered = mem::replace(&mut state.buffered, 0);
            (chunks, buffered, state.write_waker.take())
        };
        if let Some(writer) = writer {
            writer.wake();
        }
        Poll::Ready(Some(join_chunks(chunks, buffered)))
    }
}

impl Drop for PacketPipeReader {
    fn drop(&mut self) {
        let (chunks, writer) = {
            let mut state = self.shared.lock();
            state.reader_closed = true;
            state.buffered = 0;
            (mem::take(&mut state.chunks), state.write_waker.take())
        };
        drop(chunks);
        if let Some(writer) = writer {
            writer.wake();
        }
    }
}

/// One exactly sized payload. A lone chunk moves (trimmed of its spare
/// room); several are copied once, each freed as soon as it is copied.
fn join_chunks(chunks: VecDeque<Vec<u8>>, buffered: usize) -> Vec<u8> {
    let mut chunks = chunks.into_iter();
    if chunks.len() == 1 {
        if let Some(mut only) = chunks.next() {
            only.shrink_to_fit();
            return only;
        }
    }
    let mut payload = Vec::with_capacity(buffered);
    for chunk in chunks {
        payload.extend_from_slice(&chunk);
    }
    payload
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    use tokio::io::AsyncWriteExt;

    use super::*;

    const POST: usize = 200_000;

    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<CountingWaker>, Waker) {
        let counter = Arc::new(CountingWaker(AtomicUsize::new(0)));
        (Arc::clone(&counter), Waker::from(counter))
    }

    #[tokio::test]
    async fn an_idle_pipe_holds_nothing_and_a_header_holds_one_chunk() {
        let (mut writer, mut reader) = packet_pipe(POST);
        assert_eq!(writer.retained_bytes(), 0);

        writer.write_all(&[0x42; 64]).await.unwrap();
        assert!(
            writer.retained_bytes() <= CHUNK_BYTES + 4 * mem::size_of::<Vec<u8>>(),
            "a 64-byte header holds {} bytes",
            writer.retained_bytes()
        );

        let payload = reader.take().await.unwrap();
        assert_eq!(payload, [0x42; 64]);
        assert_eq!(payload.capacity(), payload.len());
        assert_eq!(writer.retained_bytes(), 0);
    }

    #[tokio::test]
    async fn a_take_returns_everything_waiting_in_order_and_releases_it() {
        let (mut writer, mut reader) = packet_pipe(POST);
        let input: Vec<u8> = (0..150_000_usize).map(|index| index as u8).collect();
        for piece in input.chunks(1_000) {
            writer.write_all(piece).await.unwrap();
        }
        // Small writes are gathered: no chunk per write.
        let retained = writer.retained_bytes();
        assert!(
            retained <= input.len() + CHUNK_BYTES + 64 * mem::size_of::<Vec<u8>>(),
            "150 000 bytes in 1 000-byte writes hold {retained} bytes"
        );

        let payload = reader.take().await.unwrap();
        assert!(payload == input, "the payload lost or reordered bytes");
        assert_eq!(payload.capacity(), payload.len());
        assert_eq!(writer.retained_bytes(), 0);
    }

    #[tokio::test]
    async fn a_large_write_moves_as_one_chunk_without_a_copy() {
        let (mut writer, mut reader) = packet_pipe(POST);
        let input = vec![0x5a; POST];
        let written = writer.write(&input).await.unwrap();
        assert_eq!(written, POST);
        let retained = writer.retained_bytes();
        assert!(
            (POST..=POST + 4 * mem::size_of::<Vec<u8>>()).contains(&retained),
            "one {POST}-byte write holds {retained} bytes"
        );
        let written_at = writer.shared.lock().chunks[0].as_ptr();

        let payload = reader.take().await.unwrap();
        assert_eq!(payload.len(), POST);
        assert_eq!(payload.capacity(), POST);
        assert_eq!(payload.as_ptr(), written_at);
    }

    #[tokio::test]
    async fn the_pipe_holds_at_most_its_capacity_and_a_take_makes_room() {
        let (mut writer, mut reader) = packet_pipe(POST);
        let input = vec![0x11; POST + 10];
        assert_eq!(writer.write(&input).await.unwrap(), POST);
        assert!(writer.retained_bytes() <= POST + 4 * mem::size_of::<Vec<u8>>());

        let (wakes, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer)
            .poll_write(&mut cx, &input[POST..])
            .is_pending());

        assert_eq!(reader.take().await.unwrap().len(), POST);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &input[POST..]),
            Poll::Ready(Ok(10))
        ));
        assert_eq!(reader.take().await.unwrap(), [0x11; 10]);
    }

    #[tokio::test]
    async fn a_reader_waits_for_bytes_and_ends_after_the_last_ones() {
        let (mut writer, mut reader) = packet_pipe(POST);
        let (wakes, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(reader.poll_take(&mut cx).is_pending());

        writer.write_all(b"last").await.unwrap();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        writer.shutdown().await.unwrap();

        assert_eq!(reader.take().await.unwrap(), b"last");
        assert_eq!(reader.take().await, None);
        assert_eq!(
            writer.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test]
    async fn dropping_the_writer_ends_the_reader() {
        let (writer, mut reader) = packet_pipe(POST);
        drop(writer);
        assert_eq!(reader.take().await, None);
    }

    #[tokio::test]
    async fn dropping_the_reader_frees_its_bytes_and_breaks_a_waiting_writer() {
        let (mut writer, reader) = packet_pipe(POST);
        let input = vec![0x22; POST + 1];
        assert_eq!(writer.write(&input).await.unwrap(), POST);
        let (wakes, waker) = counting_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer)
            .poll_write(&mut cx, &input[POST..])
            .is_pending());

        drop(reader);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(writer.retained_bytes(), 0);
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &input[POST..]),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
    }

    #[tokio::test]
    async fn a_cancelled_take_leaves_the_bytes_in_the_pipe() {
        let (mut writer, mut reader) = packet_pipe(POST);
        {
            let take = reader.take();
            tokio::pin!(take);
            let (_wakes, waker) = counting_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(take.as_mut().poll(&mut cx).is_pending());
        }
        writer.write_all(b"kept").await.unwrap();
        assert_eq!(reader.take().await.unwrap(), b"kept");
    }
}

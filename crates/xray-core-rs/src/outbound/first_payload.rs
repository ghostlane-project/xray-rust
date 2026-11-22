//! Request headers held back so they leave together with the first payload.
//!
//! Xray-core buffers an outbound request header and waits a bounded time for
//! the first client payload, so header and payload go out in one write and,
//! over TLS or REALITY, in one record. Only when the wait expires does it
//! send the header alone (`proxy/vless/outbound/outbound.go:311-345`,
//! `proxy/trojan/client.go:102-123`, `proxy/vmess/outbound/outbound.go:153-174`,
//! `proxy/shadowsocks/client.go:118-131`,
//! `proxy/shadowsocks_2022/outbound.go:130-150`). Writing the header eagerly
//! instead gives the first record a fixed, header-only size.
use super::*;
use std::future::Future;
use std::io::IoSlice;
use std::task::ready;
use tokio::time::Sleep;

/// The slices a held header gathers behind itself in the first write:
/// more than a Vision frame's (its head, its payload and its padding in
/// 4 KiB pieces, 18 at most).
const HELD_GATHER: usize = 31;

/// Xray-core's VLESS wait for the first payload
/// (`ReadMultiBufferTimeout(time.Millisecond * 500)`).
pub(super) const VLESS_FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(500);
/// Xray-core's Trojan wait (`buf.CopyOnceTimeout(..., time.Millisecond*100)`).
pub(super) const TROJAN_FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);
/// Xray-core's VMess wait, the same for every command
/// (`buf.CopyOnceTimeout(input, bodyWriter, time.Millisecond*100)`).
pub(super) const VMESS_FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);
/// Xray-core's wait for the classic AEAD methods
/// (`buf.CopyOnceTimeout(link.Reader, bodyWriter, time.Millisecond*100)`).
pub(super) const SHADOWSOCKS_FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);
/// Xray-core's Shadowsocks 2022 outbound takes only a payload that is
/// already there (`ReadMultiBufferTimeout(0)`).
pub(super) const SHADOWSOCKS_2022_FIRST_PAYLOAD_WAIT: Duration = Duration::ZERO;

/// Carrier wrapper that prepends a held request header to the first write.
///
/// The header and the first payload are handed to the carrier in a single
/// `poll_write`, which TLS seals into a single record. A flush or shutdown
/// before any payload sends the header alone.
///
/// A first payload written vectored to a carrier that gathers goes behind
/// the header as slices of its own, the same bytes in the same write, and
/// is not copied. Vision writes its padded frames so. A first payload
/// written whole is copied behind the header for each try. Either way the
/// write waits until the carrier takes it and reports only what it took:
/// a writer that writes once and then waits for an answer, as a sniffing
/// inbound does with a client's request, never flushes, so a payload held
/// here would wait for the client to give up. A gRPC carrier cannot take
/// the first write on a stream its connection has not opened yet.
pub(super) struct HeldHeader {
    inner: BoxedTransportStream,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    /// The next write is the header itself, from a codec that writes its own.
    capture: bool,
    merged: bool,
}

impl HeldHeader {
    pub(super) fn new(inner: BoxedTransportStream, header: &[u8]) -> Self {
        Self {
            inner,
            pending: Zeroizing::new(header.to_vec()),
            pending_pos: 0,
            capture: false,
            merged: false,
        }
    }

    /// Holds the first write as the header, for VMess and Shadowsocks codecs
    /// that encode their request header themselves and write it first.
    pub(super) fn first_write(inner: BoxedTransportStream) -> Self {
        Self {
            capture: true,
            ..Self::new(inner, &[])
        }
    }

    /// The header is handed over: its copy goes, and writes pass through.
    fn merge_done(&mut self) {
        self.merged = true;
        // Wipe the header copy as soon as it has been handed over.
        self.pending = Zeroizing::new(Vec::new());
        self.pending_pos = 0;
    }

    /// The first payload behind what is left of the header, in one write.
    /// A carrier that cannot take it yet keeps the write waiting, and the
    /// payload stays the writer's: the next try may differ. The copy is made
    /// again for each try, the same bytes for the same input, as a carrier
    /// that frames a write it has started expects.
    fn poll_write_merged(&mut self, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let header_len = self.pending.len() - self.pending_pos;
            if header_len == 0 {
                self.merge_done();
                return Pin::new(&mut *self.inner).poll_write(cx, input);
            }
            let mut merged = Zeroizing::new(Vec::with_capacity(header_len + input.len()));
            merged.extend_from_slice(&self.pending[self.pending_pos..]);
            merged.extend_from_slice(input);
            let written = ready!(Pin::new(&mut *self.inner).poll_write(cx, &merged))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            if written > header_len {
                self.merge_done();
                return Poll::Ready(Ok(written - header_len));
            }
            self.pending_pos += written;
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match ready!(
                Pin::new(&mut *self.inner).poll_write(cx, &self.pending[self.pending_pos..])
            )? {
                0 => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                n => self.pending_pos += n,
            }
        }
        if !self.pending.is_empty() {
            // Wipe the header copy as soon as it has been handed over.
            self.pending = Zeroizing::new(Vec::new());
            self.pending_pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for HeldHeader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for HeldHeader {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.capture && !input.is_empty() {
            this.capture = false;
            this.pending.extend_from_slice(input);
            return Poll::Ready(Ok(input.len()));
        }
        if !this.merged && !input.is_empty() {
            return this.poll_write_merged(cx, input);
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_write(cx, input)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let has_bytes = inputs.iter().any(|input| !input.is_empty());
        if this.capture || !has_bytes || !this.inner.is_write_vectored() {
            // What `poll_write` takes of a vectored write: its first slice
            // with bytes.
            let first = inputs
                .iter()
                .find(|input| !input.is_empty())
                .map_or(&[][..], |input| &**input);
            return Pin::new(this).poll_write(cx, first);
        }
        if this.merged {
            ready!(this.poll_drain(cx))?;
            return Pin::new(&mut *this.inner).poll_write_vectored(cx, inputs);
        }
        loop {
            let header = &this.pending[this.pending_pos..];
            if header.is_empty() {
                this.merge_done();
                return Pin::new(&mut *this.inner).poll_write_vectored(cx, inputs);
            }
            let header_len = header.len();
            // A vectored write may take less than it is offered: slices past
            // `HELD_GATHER` wait for the next write.
            let gathered = inputs.len().min(HELD_GATHER);
            let mut slices = [IoSlice::new(&[]); HELD_GATHER + 1];
            slices[0] = IoSlice::new(header);
            slices[1..=gathered].copy_from_slice(&inputs[..gathered]);
            let written =
                ready!(Pin::new(&mut *this.inner).poll_write_vectored(cx, &slices[..=gathered]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            if written > header_len {
                this.merge_done();
                return Poll::Ready(Ok(written - header_len));
            }
            this.pending_pos += written;
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl TransportStream for HeldHeader {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read_direct(cx, output)
    }

    #[cfg(target_os = "linux")]
    fn raw_read_direct(&mut self) -> xray_transport::RawRead<'_> {
        self.inner.raw_read_direct()
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Direct mode only starts after padded writes, so the header is gone.
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut *this.inner).poll_shutdown_direct(cx)
    }
}

/// Outer wrapper that bounds how long a held header waits for a payload.
///
/// The relay polls reads from the start, so the deadline is driven from
/// `poll_read`: once it expires without a write, `on_timeout` runs (Vision
/// queues its empty padding frame there) and the stream is flushed, which
/// sends the held header. Any write, flush or shutdown disarms it.
pub(super) struct FirstPayloadDeadline<S> {
    inner: S,
    deadline: Option<Pin<Box<Sleep>>>,
    on_timeout: fn(&mut S) -> io::Result<()>,
    flushing: bool,
}

impl<S> FirstPayloadDeadline<S> {
    pub(super) fn new(inner: S, wait: Duration, on_timeout: fn(&mut S) -> io::Result<()>) -> Self {
        Self {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(wait))),
            on_timeout,
            flushing: false,
        }
    }

    fn disarm(&mut self) {
        self.deadline = None;
        self.flushing = false;
    }
}

impl<S: TransportStream> FirstPayloadDeadline<S> {
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(deadline) = &mut self.deadline {
            if deadline.as_mut().poll(cx).is_ready() {
                self.deadline = None;
                (self.on_timeout)(&mut self.inner)?;
                self.flushing = true;
            }
        }
        if self.flushing {
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.flushing = false;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: TransportStream> AsyncRead for FirstPayloadDeadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_expired(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: TransportStream> AsyncWrite for FirstPayloadDeadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !input.is_empty() {
            this.disarm();
        }
        Pin::new(&mut this.inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: TransportStream> TransportStream for FirstPayloadDeadline<S> {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_expired(cx))?;
        Pin::new(&mut this.inner).poll_read_direct(cx, output)
    }

    #[cfg(target_os = "linux")]
    fn raw_read(&mut self) -> xray_transport::RawRead<'_> {
        // Reads drive the deadline and the flush that follows it.
        if self.deadline.is_some() || self.flushing {
            return xray_transport::RawRead::NotYet;
        }
        self.inner.raw_read()
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !input.is_empty() {
            this.disarm();
        }
        Pin::new(&mut this.inner).poll_write_direct(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_flush_direct(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.disarm();
        Pin::new(&mut this.inner).poll_shutdown_direct(cx)
    }
}

/// Timeout action for protocols whose held header is sent alone.
pub(super) fn flush_header_alone<S>(_: &mut S) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;

    type Writes = Arc<Mutex<Vec<Vec<u8>>>>;

    /// Carrier that records every `poll_write` and never yields read data.
    #[derive(Default)]
    struct Recorder {
        writes: Writes,
        timeouts: usize,
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(input.to_vec());
            Poll::Ready(Ok(input.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TransportStream for Recorder {
        fn poll_read_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.poll_read(cx, output)
        }
        fn poll_write_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.poll_write(cx, input)
        }
    }

    const HEADER: &[u8] = b"request-header";

    fn held(wait: Duration) -> (FirstPayloadDeadline<HeldHeader>, Writes) {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let stream = FirstPayloadDeadline::new(
            HeldHeader::new(Box::new(recorder), HEADER),
            wait,
            flush_header_alone,
        );
        (stream, writes)
    }

    #[tokio::test(start_paused = true)]
    async fn header_and_first_payload_share_one_carrier_write() {
        let (mut stream, writes) = held(TROJAN_FIRST_PAYLOAD_WAIT);
        assert!(writes.lock().unwrap().is_empty());
        stream.write_all(b"first payload").await.unwrap();
        stream.write_all(b"second").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            [b"request-headerfirst payload".to_vec(), b"second".to_vec()]
        );
        // A late deadline must not emit anything once the header is gone.
        tokio::time::advance(TROJAN_FIRST_PAYLOAD_WAIT * 2).await;
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_millis(1), stream.read(&mut byte)).await;
        assert!(read.is_err());
        assert_eq!(writes.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn header_is_sent_alone_only_after_the_wait_expires() {
        let (mut stream, writes) = held(VLESS_FIRST_PAYLOAD_WAIT);
        let mut byte = [0; 1];
        let early = VLESS_FIRST_PAYLOAD_WAIT - Duration::from_millis(1);
        assert!(tokio::time::timeout(early, stream.read(&mut byte))
            .await
            .is_err());
        assert!(writes.lock().unwrap().is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(2), stream.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(*writes.lock().unwrap(), [HEADER.to_vec()]);
        stream.write_all(b"late payload").await.unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            [HEADER.to_vec(), b"late payload".to_vec()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_action_runs_once_before_the_flush() {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut stream = FirstPayloadDeadline::new(recorder, TROJAN_FIRST_PAYLOAD_WAIT, |inner| {
            inner.timeouts += 1;
            inner.writes.lock().unwrap().push(b"padding".to_vec());
            Ok(())
        });
        let mut byte = [0; 1];
        let wait = TROJAN_FIRST_PAYLOAD_WAIT * 3;
        assert!(tokio::time::timeout(wait, stream.read(&mut byte))
            .await
            .is_err());
        assert_eq!(stream.inner.timeouts, 1);
        assert_eq!(*writes.lock().unwrap(), [b"padding".to_vec()]);
    }

    fn vision(recorder: Recorder) -> FirstPayloadDeadline<VisionOutboundStream> {
        let carrier: BoxedTransportStream = Box::new(HeldHeader::new(Box::new(recorder), HEADER));
        let stream = VlessResponseStream::new(VisionTransportStream::new(carrier));
        FirstPayloadDeadline::new(
            VisionOutboundStream::new(VisionStream::new(
                stream,
                [7; 16],
                xray_proxy::vless::DEFAULT_VISION_SEED,
            )),
            VLESS_FIRST_PAYLOAD_WAIT,
            |stream| stream.inner.queue_empty_padding_frame(),
        )
    }

    /// Header, UUID and the padded frame header in front of the content.
    const VISION_PREFIX: usize = HEADER.len() + 16 + 5;

    #[tokio::test(start_paused = true)]
    async fn vision_header_leaves_with_the_padded_first_payload() {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut stream = vision(recorder);
        stream.write_all(b"client hello").await.unwrap();
        stream.flush().await.unwrap();
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "no empty padding frame before the payload");
        assert!(writes[0].starts_with(HEADER));
        assert_eq!(writes[0][HEADER.len()..][..16], [7; 16]);
        assert_eq!(writes[0][VISION_PREFIX..][..12], *b"client hello");
    }

    #[tokio::test(start_paused = true)]
    async fn vision_timeout_pads_an_empty_frame_behind_the_header() {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut stream = vision(recorder);
        let mut byte = [0; 1];
        let wait = VLESS_FIRST_PAYLOAD_WAIT + Duration::from_millis(1);
        assert!(tokio::time::timeout(wait, stream.read(&mut byte))
            .await
            .is_err());
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].starts_with(HEADER));
        assert_eq!(writes[0][HEADER.len()..][..16], [7; 16]);
        // Empty content with Xray's long padding (seed 900 + random 0..500).
        let frame = &writes[0][HEADER.len() + 16..];
        assert_eq!(frame[1..3], [0, 0]);
        let padding = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        assert!((900..1400).contains(&padding), "{padding}");
        assert_eq!(writes[0].len(), VISION_PREFIX + padding);
    }

    /// A carrier that gathers: it records each write it takes as the bytes
    /// of its slices in order, takes at most `cap` bytes a write, and waits
    /// while it is closed. A `plain` one does not gather.
    #[derive(Default)]
    struct Gatherer {
        writes: Writes,
        state: Arc<Mutex<GatherState>>,
    }

    #[derive(Default)]
    struct GatherState {
        closed: bool,
        cap: Option<usize>,
        waiting: Option<std::task::Waker>,
        plain: bool,
    }

    impl Gatherer {
        /// A closed carrier that takes one buffer a write, as gRPC's does.
        fn plain_and_closed() -> Self {
            let gatherer = Self::default();
            {
                let mut state = gatherer.state.lock().unwrap();
                state.plain = true;
                state.closed = true;
            }
            gatherer
        }

        /// Opens the carrier and wakes the write that waits on it, as h2's
        /// connection task does when it grants a stream capacity.
        fn open(state: &Mutex<GatherState>) {
            let waiting = {
                let mut state = state.lock().unwrap();
                state.closed = false;
                state.waiting.take()
            };
            if let Some(waiting) = waiting {
                waiting.wake();
            }
        }

        fn accept(&self, cx: &mut Context<'_>, inputs: &[&[u8]]) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                state.waiting = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let mut left = state.cap.unwrap_or(usize::MAX);
            let mut taken = Vec::new();
            for input in inputs {
                let len = left.min(input.len());
                taken.extend_from_slice(&input[..len]);
                left -= len;
            }
            let len = taken.len();
            self.writes.lock().unwrap().push(taken);
            Poll::Ready(Ok(len))
        }
    }

    impl AsyncRead for Gatherer {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Gatherer {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.accept(cx, &[input])
        }
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            inputs: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let inputs: Vec<&[u8]> = inputs.iter().map(|input| &**input).collect();
            self.accept(cx, &inputs)
        }
        fn is_write_vectored(&self) -> bool {
            !self.state.lock().unwrap().plain
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TransportStream for Gatherer {
        fn poll_read_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.poll_read(cx, output)
        }
        fn poll_write_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.poll_write(cx, input)
        }
    }

    /// A first payload written vectored to a carrier that gathers waits
    /// with the carrier and holds none of its bytes: the header's copy is
    /// all a held header keeps. Taken a few bytes at a time, the carrier
    /// gets the header and then the payload, in order, and the writes after
    /// pass through gathered.
    #[test]
    fn a_gathered_first_payload_waits_uncopied_behind_the_header() {
        let gatherer = Gatherer::default();
        let writes = gatherer.writes.clone();
        let state = gatherer.state.clone();
        state.lock().unwrap().closed = true;
        let mut held = HeldHeader::new(Box::new(gatherer), HEADER);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let payload: [&[u8]; 2] = [b"first ", b"payload"];
        let slices = |from: usize| -> Vec<u8> { payload.concat()[from..].to_vec() };

        let write = |held: &mut HeldHeader, cx: &mut Context<'_>, bytes: &[u8]| {
            let at = bytes.len() / 2;
            let halves = [IoSlice::new(&bytes[..at]), IoSlice::new(&bytes[at..])];
            Pin::new(held).poll_write_vectored(cx, &halves)
        };
        let first = write(&mut held, &mut cx, &slices(0));
        assert_eq!(&held.pending[..], HEADER, "the payload is not copied");
        assert!(first.is_pending(), "the write waits with the carrier");
        assert!(writes.lock().unwrap().is_empty());
        assert!(held.is_write_vectored(), "it gathers as its carrier does");

        {
            let mut state = state.lock().unwrap();
            state.closed = false;
            state.cap = Some(5);
        }
        let mut sent = 0;
        while sent < 13 {
            match write(&mut held, &mut cx, &slices(sent)) {
                Poll::Ready(Ok(len)) => sent += len,
                other => panic!("the carrier takes every write: {other:?}"),
            }
        }
        assert!(held.pending.is_empty(), "the header's copy is gone");
        let writes = writes.lock().unwrap().clone();
        assert!(writes.iter().all(|write| write.len() <= 5));
        assert_eq!(writes.concat(), [HEADER, b"first payload"].concat());
        assert_eq!(writes.len(), (HEADER.len() + 13).div_ceil(5));
    }

    /// A first payload written once to a carrier that cannot take it yet,
    /// and then only read behind: what a SOCKS inbound does with the bytes it
    /// sniffed before the relay starts, and what gRPC's carrier is until h2's
    /// connection task has opened the stream. The write waits with the
    /// carrier, and once the carrier opens, header and payload leave in one
    /// write, with no flush and no later write to carry them out.
    #[tokio::test(start_paused = true)]
    async fn a_first_payload_leaves_when_its_carrier_opens_without_a_flush() {
        let gatherer = Gatherer::plain_and_closed();
        let writes = gatherer.writes.clone();
        let state = gatherer.state.clone();
        let mut stream = FirstPayloadDeadline::new(
            HeldHeader::new(Box::new(gatherer), HEADER),
            VLESS_FIRST_PAYLOAD_WAIT,
            flush_header_alone,
        );
        let opener = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Gatherer::open(&state);
        });
        tokio::time::timeout(STEP, stream.write_all(b"first payload"))
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0; 1];
        let read = tokio::time::timeout(VLESS_FIRST_PAYLOAD_WAIT * 2, stream.read(&mut byte)).await;
        assert!(read.is_err());
        opener.await.unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            [[HEADER, b"first payload"].concat()],
            "the payload left behind the header, once"
        );
    }

    /// A first write the carrier did not take is not the stream's: the
    /// caller may write other bytes in its place, and only those leave.
    #[test]
    fn a_first_payload_the_carrier_did_not_take_can_be_replaced() {
        let gatherer = Gatherer::plain_and_closed();
        let writes = gatherer.writes.clone();
        let state = gatherer.state.clone();
        let mut held = HeldHeader::new(Box::new(gatherer), HEADER);
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let first = Pin::new(&mut held).poll_write(&mut cx, b"given up");
        assert!(first.is_pending(), "the write waits with the carrier");
        assert!(writes.lock().unwrap().is_empty());

        Gatherer::open(&state);
        let second = Pin::new(&mut held).poll_write(&mut cx, b"instead");
        assert!(matches!(second, Poll::Ready(Ok(7))), "{second:?}");
        assert_eq!(*writes.lock().unwrap(), [[HEADER, b"instead"].concat()]);
        assert!(held.pending.is_empty(), "the header's copy is gone");
    }

    /// Taken a few bytes at a time, a first payload written whole leaves
    /// behind the header in order, and each write is reported for the
    /// payload bytes it carried and no more.
    #[test]
    fn a_first_payload_taken_in_pieces_is_reported_as_it_leaves() {
        let gatherer = Gatherer::plain_and_closed();
        let writes = gatherer.writes.clone();
        let state = gatherer.state.clone();
        let mut held = HeldHeader::new(Box::new(gatherer), HEADER);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        const PAYLOAD: &[u8] = b"first payload";

        assert!(Pin::new(&mut held)
            .poll_write(&mut cx, PAYLOAD)
            .is_pending());
        state.lock().unwrap().cap = Some(5);
        Gatherer::open(&state);
        let mut sent = 0;
        while sent < PAYLOAD.len() {
            match Pin::new(&mut held).poll_write(&mut cx, &PAYLOAD[sent..]) {
                Poll::Ready(Ok(len)) => sent += len,
                other => panic!("the carrier takes every write: {other:?}"),
            }
        }
        assert_eq!(sent, PAYLOAD.len());
        assert!(held.pending.is_empty(), "the header's copy is gone");
        let writes = writes.lock().unwrap().clone();
        assert!(writes.iter().all(|write| write.len() <= 5));
        assert_eq!(writes.concat(), [HEADER, PAYLOAD].concat());
    }

    /// Over a carrier that gathers, Vision's first padded frame leaves
    /// behind the header in one write, as over one that does not.
    #[tokio::test(start_paused = true)]
    async fn vision_header_leaves_with_the_gathered_first_frame() {
        let gatherer = Gatherer::default();
        let writes = gatherer.writes.clone();
        let carrier: BoxedTransportStream = Box::new(HeldHeader::new(Box::new(gatherer), HEADER));
        let stream = VlessResponseStream::new(VisionTransportStream::new(carrier));
        let mut stream = FirstPayloadDeadline::new(
            VisionOutboundStream::new(VisionStream::new(
                stream,
                [7; 16],
                xray_proxy::vless::DEFAULT_VISION_SEED,
            )),
            VLESS_FIRST_PAYLOAD_WAIT,
            |stream| stream.inner.queue_empty_padding_frame(),
        );
        stream.write_all(b"client hello").await.unwrap();
        stream.write_all(b"second").await.unwrap();
        stream.flush().await.unwrap();
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 2, "a frame a write");
        assert!(writes[0].starts_with(HEADER));
        assert_eq!(writes[0][HEADER.len()..][..16], [7; 16]);
        assert_eq!(writes[0][VISION_PREFIX..][..12], *b"client hello");
        let padding =
            u16::from_be_bytes([writes[0][VISION_PREFIX - 2], writes[0][VISION_PREFIX - 1]]);
        assert_eq!(writes[0].len(), VISION_PREFIX + 12 + usize::from(padding));
        assert_eq!(writes[1][5..][..6], *b"second");
    }

    /// A codec over a carrier that holds the header the codec writes first,
    /// as the VMess and Shadowsocks outbounds build it.
    fn codec<S: AsyncRead + AsyncWrite + Unpin + Send>(
        wait: Duration,
        build: impl FnOnce(BoxedTransportStream) -> S,
    ) -> (
        FirstPayloadDeadline<protocol_stream::ProtocolStream<S>>,
        Writes,
    ) {
        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let carrier: BoxedTransportStream = Box::new(HeldHeader::first_write(Box::new(recorder)));
        let stream = FirstPayloadDeadline::new(
            protocol_stream::ProtocolStream(build(carrier)),
            wait,
            flush_header_alone,
        );
        (stream, writes)
    }

    const STEP: Duration = Duration::from_secs(1);

    /// Checks Xray-core's behaviour for a codec that writes its own header:
    /// nothing leaves while the relay reads before the wait is over, a
    /// payload leaves in one carrier write behind the header, and without one
    /// the header leaves alone only once the wait is over. Returns the
    /// lengths of the merged write, the lone header and the lone record.
    async fn codec_holds_its_header<S: AsyncRead + AsyncWrite + Unpin + Send>(
        wait: Duration,
        build: impl Fn(BoxedTransportStream) -> S,
    ) -> (usize, usize, usize) {
        const PAYLOAD: &[u8] = b"first payload";
        let mut byte = [0; 1];

        let (mut stream, writes) = codec(wait, &build);
        let early = wait - Duration::from_millis(1);
        let read = tokio::time::timeout(early, stream.read(&mut byte)).await;
        assert!(read.is_err());
        assert!(writes.lock().unwrap().is_empty(), "header left early");
        tokio::time::timeout(STEP, stream.write_all(PAYLOAD))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(STEP, stream.flush())
            .await
            .unwrap()
            .unwrap();
        let merged = writes.lock().unwrap().clone();
        assert_eq!(merged.len(), 1, "header and payload share one write");

        let (mut stream, writes) = codec(wait, &build);
        let read = tokio::time::timeout(early, stream.read(&mut byte)).await;
        assert!(read.is_err());
        assert!(writes.lock().unwrap().is_empty(), "header left early");
        let read = tokio::time::timeout(Duration::from_millis(2), stream.read(&mut byte)).await;
        assert!(read.is_err());
        assert_eq!(writes.lock().unwrap().len(), 1, "header leaves alone");
        tokio::time::timeout(STEP, stream.write_all(PAYLOAD))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(STEP, stream.flush())
            .await
            .unwrap()
            .unwrap();
        let alone = writes.lock().unwrap().clone();
        assert_eq!(alone.len(), 2);
        assert!(alone[1].len() > PAYLOAD.len() && alone[0].len() > alone[1].len() - PAYLOAD.len());
        (merged[0].len(), alone[0].len(), alone[1].len())
    }

    fn vmess_account() -> xray_proxy::vmess::Account {
        xray_proxy::vmess::Account::new(
            &[7; 16],
            xray_proxy::vmess::Cipher::parse("aes-128-gcm").unwrap(),
            xray_proxy::vmess::Options {
                authenticated_length: false,
                no_termination_signal: false,
            },
        )
    }

    fn target(network: RoutingNetwork) -> Target {
        Target::new(
            RoutingTargetAddr::Domain("example.test".into()),
            443,
            network,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn vmess_holds_its_header_for_every_command() {
        let account = vmess_account();
        for network in [RoutingNetwork::Tcp, RoutingNetwork::Udp] {
            let target = target(network);
            codec_holds_its_header(VMESS_FIRST_PAYLOAD_WAIT, |carrier| {
                xray_proxy::vmess::ClientStream::new(carrier, &account, &target).unwrap()
            })
            .await;
        }
        // Mux.Cool and XUDP ride command 3.
        codec_holds_its_header(VMESS_FIRST_PAYLOAD_WAIT, |carrier| {
            xray_proxy::vmess::ClientStream::new_mux(carrier, &account).unwrap()
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn shadowsocks_aead_holds_its_header() {
        let method = xray_proxy::shadowsocks::Method::new("aes-128-gcm", "synthetic").unwrap();
        for target in [target(RoutingNetwork::Tcp), super::super::mux::target()] {
            let (merged, header, record) =
                codec_holds_its_header(SHADOWSOCKS_FIRST_PAYLOAD_WAIT, |carrier| {
                    xray_proxy::shadowsocks::ClientStream::new(carrier, &method, &target).unwrap()
                })
                .await;
            // Salt, sealed length and sealed address, then one sealed record.
            assert_eq!(merged, header + record);
        }
    }

    /// Xray-core's 2022 outbound takes only a payload already there: one
    /// written before the relay first reads shares the header's write, and
    /// the first read sends the header alone.
    #[tokio::test(start_paused = true)]
    async fn shadowsocks_2022_takes_only_a_ready_payload() {
        let method = xray_proxy::shadowsocks::Method::new(
            "2022-blake3-aes-128-gcm",
            "AQEBAQEBAQEBAQEBAQEBAQ==",
        )
        .unwrap();
        let target = target(RoutingNetwork::Tcp);
        let build = |carrier| {
            xray_proxy::shadowsocks::ClientStream::new(carrier, &method, &target).unwrap()
        };
        let (mut stream, writes) = codec(SHADOWSOCKS_2022_FIRST_PAYLOAD_WAIT, build);
        assert!(writes.lock().unwrap().is_empty());
        tokio::time::timeout(STEP, stream.write_all(b"ready payload"))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(STEP, stream.flush())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(writes.lock().unwrap().len(), 1);

        let (mut stream, writes) = codec(SHADOWSOCKS_2022_FIRST_PAYLOAD_WAIT, build);
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_millis(1), stream.read(&mut byte)).await;
        assert!(read.is_err());
        assert_eq!(writes.lock().unwrap().len(), 1, "header leaves alone");
        tokio::time::timeout(STEP, stream.write_all(b"late payload"))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(STEP, stream.flush())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(writes.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_without_payload_still_sends_the_header() {
        let (mut stream, writes) = held(TROJAN_FIRST_PAYLOAD_WAIT);
        stream.shutdown().await.unwrap();
        assert_eq!(*writes.lock().unwrap(), [HEADER.to_vec()]);
    }
}

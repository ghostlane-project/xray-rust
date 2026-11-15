use std::cmp;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::vision::{FrameHead, FRAME_HEAD_MAX};
use super::{unpad_vision_block, VisionCommand, VisionError, VisionPadding};

const HEADER_LEN: usize = 5;
const USER_ID_LEN: usize = 16;
const MAX_CONTENT_LEN: usize = u16::MAX as usize;
const READ_CHUNK_LEN: usize = 8 * 1024;
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS_13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;
/// Padding goes out of this, a piece at a time: it is zeros.
const PADDING_ZEROS_LEN: usize = 4 * 1024;
static PADDING_ZEROS: [u8; PADDING_ZEROS_LEN] = [0; PADDING_ZEROS_LEN];
/// The slices of one frame write: its head, its payload and its padding,
/// at most `u16::MAX` zeros.
const FRAME_SLICES: usize = 2 + MAX_CONTENT_LEN.div_ceil(PADDING_ZEROS_LEN);

/// Whether the bytes a stream has yet to return are a TCP socket's, unchanged.
///
/// A relay asks before each read. Once a stream answers [`RawRead::Socket`]
/// the relay may stop reading the stream and move the socket's bytes itself,
/// which on Linux it does in the kernel with `splice(2)`. The answer is
/// therefore a promise: nothing is buffered above the socket, and every later
/// read would have done nothing but hand the socket's bytes over.
#[cfg(target_os = "linux")]
pub enum RawRead<'a> {
    /// The stream decodes what it reads, and always will.
    Never,
    /// Bytes are still buffered above the socket, or the stream has not
    /// switched to it yet. Read once more, then ask again.
    NotYet,
    /// Everything left to read is still in this socket.
    Socket(&'a tokio::net::TcpStream),
}

pub trait VisionStreamIo: AsyncRead + AsyncWrite + Unpin {
    /// Notify the transport that direct mode can never engage on this stream,
    /// so any record-boundary read alignment kept for a lossless direct-mode
    /// unwrap can be dropped. Default: no-op.
    fn release_record_alignment(&mut self) {}

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;

    /// What [`poll_read_direct`](Self::poll_read_direct) reads from, when
    /// that is a bare TCP socket. Asking commits the stream to direct reads,
    /// as the first `poll_read_direct` does.
    #[cfg(target_os = "linux")]
    fn raw_read_direct(&mut self) -> RawRead<'_> {
        RawRead::Never
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl VisionStreamIo for tokio::io::DuplexStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

impl<T> VisionStreamIo for std::io::Cursor<T>
where
    std::io::Cursor<T>: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

/// What a padded frame still has to hand the carrier: the rest of its head,
/// the payload still to come from the writer and its padding.
///
/// No byte of the payload is copied. It goes from the writer's own buffer,
/// beside the head and the padding, in the one write a frame in a buffer of
/// its own would have been: gathered when the carrier gathers, so a TLS
/// session seals the same records. A frame holds 28 bytes however large its
/// payload, where a copy held the payload and the padding, up to 64 KiB
/// and as much again, outside the byte budget, for as long as the carrier
/// waited.
#[derive(Debug, Clone, Copy)]
struct FrameTail {
    head: [u8; FRAME_HEAD_MAX],
    head_from: u8,
    head_to: u8,
    payload: u16,
    padding: u16,
}

impl FrameTail {
    fn new(head: FrameHead, payload: usize) -> Self {
        let bytes = head.bytes();
        let mut tail = Self {
            head: [0; FRAME_HEAD_MAX],
            head_from: 0,
            head_to: bytes.len() as u8,
            payload: payload as u16,
            padding: head.padding_len,
        };
        tail.head[..bytes.len()].copy_from_slice(bytes);
        tail
    }

    fn head(&self) -> &[u8] {
        &self.head[usize::from(self.head_from)..usize::from(self.head_to)]
    }

    /// Whether any byte of the frame has gone. A head always goes first.
    fn started(&self) -> bool {
        self.head_from > 0
    }

    fn is_done(&self) -> bool {
        self.head_from == self.head_to && self.payload == 0 && self.padding == 0
    }

    /// The carrier took `written` bytes of a write of the rest of the head,
    /// `payload` bytes of payload and `padding` zeros: the payload bytes
    /// among them.
    fn advance(&mut self, written: usize, payload: usize, padding: usize) -> io::Result<usize> {
        let head = self.head().len();
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write vision frame",
            ));
        }
        if written > head + payload + padding {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the carrier took more than the vision frame gave it",
            ));
        }
        let from_head = written.min(head);
        let from_payload = (written - from_head).min(payload);
        let from_padding = written - from_head - from_payload;
        self.head_from += from_head as u8;
        self.payload -= from_payload as u16;
        self.padding -= from_padding as u16;
        Ok(from_payload)
    }
}

/// One carrier write of `head`, `payload` and `padding` zeros: the bytes a
/// frame in a buffer of its own would hold there. A carrier that gathers
/// gets them as slices; one that does not gets a copy for this call only,
/// gone before it returns, unless there is one piece to write.
///
/// So a carrier that does not gather and takes a frame in pieces has the
/// rest copied again on each call, a call it waits on too: a 65,535 B
/// payload to one that takes 8,192 B a call costs 5.9 µs a frame where the
/// one copy into a frame buffer cost 1.7 µs, and 11.2 µs when it waits
/// between pieces (release build, medians of 10 rounds on the build box).
/// Offering it a bounded piece instead would change what a carrier is
/// offered, which the wire tests pin with writes of up to 70,000 B. The
/// cost is paid only for a padded frame, and a flow pads only its first
/// ones; the client's carriers over TLS and REALITY gather
/// (`outbound::vision_chain_tests`).
fn poll_write_parts<S: AsyncWrite + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    head: &[u8],
    payload: &[u8],
    padding: usize,
) -> Poll<io::Result<usize>> {
    let pieces =
        usize::from(!head.is_empty()) + usize::from(!payload.is_empty()) + usize::from(padding > 0);
    if pieces <= 1 && padding <= PADDING_ZEROS_LEN {
        let piece = if !head.is_empty() {
            head
        } else if !payload.is_empty() {
            payload
        } else {
            &PADDING_ZEROS[..padding]
        };
        return Pin::new(inner).poll_write(cx, piece);
    }
    if inner.is_write_vectored() {
        let mut slices = [IoSlice::new(&[]); FRAME_SLICES];
        let mut len = 0;
        for part in [head, payload] {
            if !part.is_empty() {
                slices[len] = IoSlice::new(part);
                len += 1;
            }
        }
        let mut zeros = padding;
        while zeros > 0 {
            let piece = zeros.min(PADDING_ZEROS_LEN);
            slices[len] = IoSlice::new(&PADDING_ZEROS[..piece]);
            len += 1;
            zeros -= piece;
        }
        return Pin::new(inner).poll_write_vectored(cx, &slices[..len]);
    }
    let mut frame = Vec::with_capacity(head.len() + payload.len() + padding);
    frame.extend_from_slice(head);
    frame.extend_from_slice(payload);
    frame.resize(frame.len() + padding, 0);
    Pin::new(inner).poll_write(cx, &frame)
}

pub struct VisionStream<S> {
    inner: S,
    user_id: [u8; USER_ID_LEN],
    padding: VisionPadding,
    /// The padded frame being written.
    frame: Option<FrameTail>,
    pending_direct_write_mode: bool,
    pending_end_write_mode: bool,
    raw_read: BytesMut,
    decoded_read: BytesMut,
    inbound_user_id_seen: bool,
    padding_write_mode: bool,
    direct_write_mode: bool,
    padding_read_mode: bool,
    direct_read_mode: bool,
    inner_eof: bool,
    packets_to_filter: usize,
    enable_xtls: bool,
    is_tls12_or_above: bool,
    is_tls: bool,
    cipher: u16,
    remaining_server_hello: i32,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, user_id: [u8; USER_ID_LEN], seed: [u32; 4]) -> Self {
        Self {
            inner,
            user_id,
            padding: VisionPadding::new(user_id, seed),
            frame: None,
            pending_direct_write_mode: false,
            pending_end_write_mode: false,
            raw_read: BytesMut::new(),
            decoded_read: BytesMut::new(),
            inbound_user_id_seen: false,
            padding_write_mode: true,
            direct_write_mode: false,
            padding_read_mode: true,
            direct_read_mode: false,
            inner_eof: false,
            packets_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Queues a frame with no payload, which the next flush sends.
    pub fn queue_empty_padding_frame(&mut self) -> io::Result<()> {
        self.start_frame(0, VisionCommand::Continue, true)
    }

    fn fill_output(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let len = cmp::min(output.remaining(), self.decoded_read.len());
        if len == 0 {
            return false;
        }

        output.put_slice(&self.decoded_read[..len]);
        self.decoded_read.advance(len);
        if self.decoded_read.is_empty() {
            // Nothing decoded waits: the buffer goes with it, so a flow
            // whose padding ended keeps none.
            self.decoded_read = BytesMut::new();
        }
        true
    }

    /// Starts a padded frame for the next `content_len` bytes written.
    fn start_frame(
        &mut self,
        content_len: usize,
        command: VisionCommand,
        long_padding: bool,
    ) -> io::Result<()> {
        if self.frame.is_some() {
            return Err(io::Error::other("a vision frame is still being written"));
        }
        let head = self
            .padding
            .frame_head(content_len, command, long_padding, 0)
            .map_err(vision_to_io)?;
        self.frame = Some(FrameTail::new(head, content_len));
        Ok(())
    }

    fn next_frame_len(&self) -> io::Result<Option<usize>> {
        let Some(offset) = self.next_frame_offset() else {
            return Ok(None);
        };

        if self.raw_read.len() < offset + HEADER_LEN {
            return Ok(None);
        }

        VisionCommand::try_from(self.raw_read[offset]).map_err(vision_to_io)?;
        let content_len =
            u16::from_be_bytes([self.raw_read[offset + 1], self.raw_read[offset + 2]]) as usize;
        let padding_len =
            u16::from_be_bytes([self.raw_read[offset + 3], self.raw_read[offset + 4]]) as usize;
        let frame_len = offset + HEADER_LEN + content_len + padding_len;

        if self.raw_read.len() < frame_len {
            return Ok(None);
        }

        Ok(Some(frame_len))
    }

    fn next_frame_offset(&self) -> Option<usize> {
        if self.raw_read.is_empty() {
            return None;
        }

        if self.inbound_user_id_seen {
            return Some(0);
        }

        if self.raw_read.len() < USER_ID_LEN {
            if self.user_id.starts_with(&self.raw_read) {
                return None;
            }

            return Some(0);
        }

        if self.raw_read[..USER_ID_LEN] == self.user_id {
            Some(USER_ID_LEN)
        } else {
            Some(0)
        }
    }

    fn filter_tls_packet(&mut self, packet: &[u8]) {
        if self.packets_to_filter == 0 || packet.is_empty() {
            return;
        }

        self.packets_to_filter -= 1;
        if packet.len() >= 6 {
            if packet[..TLS_SERVER_HANDSHAKE_START.len()] == TLS_SERVER_HANDSHAKE_START
                && packet[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
            {
                self.remaining_server_hello =
                    (i32::from(packet[3]) << 8 | i32::from(packet[4])) + HEADER_LEN as i32;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if packet.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = packet[43] as usize;
                    let cipher_offset = 43 + session_id_len + 1;
                    if packet.len() >= cipher_offset + 2 {
                        self.cipher =
                            u16::from_be_bytes([packet[cipher_offset], packet[cipher_offset + 1]]);
                    }
                }
            } else if packet[..TLS_CLIENT_HANDSHAKE_START.len()] == TLS_CLIENT_HANDSHAKE_START
                && packet[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
            {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let end = cmp::min(self.remaining_server_hello as usize, packet.len());
            self.remaining_server_hello -= packet.len() as i32;
            if packet[..end]
                .windows(TLS_13_SUPPORTED_VERSIONS.len())
                .any(|window| window == TLS_13_SUPPORTED_VERSIONS)
            {
                if self.cipher != 0 && self.cipher != TLS_AES_128_CCM_8_SHA256 {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

impl<S> VisionStream<S>
where
    S: VisionStreamIo,
{
    fn decode_next_frame(&mut self) -> io::Result<bool> {
        let Some(frame_len) = self.next_frame_len()? else {
            return Ok(false);
        };

        let frame = self.raw_read.split_to(frame_len);
        if self.raw_read.is_empty() {
            // The frame takes the buffer's bytes along, and nothing is
            // left for the buffer to keep.
            self.raw_read = BytesMut::new();
        }
        let unpadded = unpad_vision_block(&frame, &self.user_id).map_err(vision_to_io)?;
        self.inbound_user_id_seen = true;
        let command = unpadded.command;
        self.filter_tls_packet(&unpadded.payload);
        self.decoded_read.extend_from_slice(&unpadded.payload);
        if matches!(command, VisionCommand::End | VisionCommand::Direct) {
            self.padding_read_mode = false;
            self.direct_read_mode = command == VisionCommand::Direct;
            // What followed the block in the last read is the stream's; the
            // frame buffer is not needed again.
            let rest = std::mem::take(&mut self.raw_read);
            self.decoded_read.extend_from_slice(&rest);
            if command == VisionCommand::End {
                // The peer will never switch this stream to direct mode; the
                // transport can stop aligning reads to TLS record boundaries.
                self.inner.release_record_alignment();
            }
        }

        Ok(true)
    }

    /// Whether the rest of the download is the carrier's socket: true once
    /// the peer sent `Direct` and everything decoded before it was read.
    #[cfg(target_os = "linux")]
    pub fn raw_read(&mut self) -> RawRead<'_> {
        if !self.decoded_read.is_empty() {
            return RawRead::NotYet;
        }
        if self.direct_read_mode {
            return self.inner.raw_read_direct();
        }
        if self.padding_read_mode {
            RawRead::NotYet
        } else {
            // `End`: the carrier's own session keeps decoding to the last byte.
            RawRead::Never
        }
    }

    /// Writes the frame with the writer's `input` as its payload: the rest
    /// of its head, as much of `input` as the frame takes and, with the
    /// payload's last byte, its padding. Returns the bytes of `input` the
    /// carrier took, which are 0 only for an empty `input`. Once the carrier
    /// has taken the payload's last byte, the rest of the padding goes on
    /// while it takes it, as a frame in a buffer of its own did, so a read
    /// or a wait for the writer's next bytes comes after the frame; the call
    /// returns when it is done or the carrier waits, and what the carrier
    /// left goes before the next write, flush or shutdown. A frame done
    /// switches the stream as its command asks.
    fn poll_write_frame(&mut self, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let Some(frame) = self.frame.as_mut() else {
                return Poll::Ready(Ok(0));
            };
            let payload = &input[..input.len().min(usize::from(frame.payload))];
            if payload.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let padding = if payload.len() == usize::from(frame.payload) {
                usize::from(frame.padding)
            } else {
                0
            };
            let written = std::task::ready!(poll_write_parts(
                &mut self.inner,
                cx,
                frame.head(),
                payload,
                padding
            ))?;
            let took = frame.advance(written, payload.len(), padding)?;
            if frame.is_done() {
                self.frame = None;
            }
            if took > 0 {
                // The padding left, while the carrier takes it, and the
                // switch of a frame done. A switch whose flush waits is
                // finished by the next call.
                if let Poll::Ready(Err(error)) = self.poll_finish_frame(cx) {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(took));
            }
        }
    }

    /// Finishes a frame whose payload has all gone, its head when it has no
    /// payload and its padding, then switches as its command asks. A frame
    /// still owed payload waits for the writer.
    fn poll_finish_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(frame) = self.frame.as_mut() {
            if frame.payload > 0 {
                return Poll::Ready(Ok(()));
            }
            let padding = usize::from(frame.padding);
            let written = std::task::ready!(poll_write_parts(
                &mut self.inner,
                cx,
                frame.head(),
                &[],
                padding
            ))?;
            frame.advance(written, 0, padding)?;
            if frame.is_done() {
                self.frame = None;
            }
        }
        self.poll_switch(cx)
    }

    /// Once the frame that ends padding is written: on `Direct`, flushes
    /// the session that carried it and writes past it from then on; on
    /// `End`, writes unpadded.
    fn poll_switch(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_direct_write_mode {
            std::task::ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.padding_write_mode = false;
            self.direct_write_mode = true;
            self.pending_direct_write_mode = false;
        } else if self.pending_end_write_mode {
            self.padding_write_mode = false;
            self.pending_end_write_mode = false;
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for VisionStream<S>
where
    S: VisionStreamIo,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.fill_output(output) || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.direct_read_mode {
            return Pin::new(&mut this.inner).poll_read_direct(cx, output);
        }
        if !this.padding_read_mode {
            return Pin::new(&mut this.inner).poll_read(cx, output);
        }

        loop {
            if this.decode_next_frame()? {
                if this.fill_output(output) || output.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                if this.direct_read_mode {
                    return Pin::new(&mut this.inner).poll_read_direct(cx, output);
                }
                if !this.padding_read_mode {
                    return Pin::new(&mut this.inner).poll_read(cx, output);
                }
                continue;
            }

            if this.inner_eof {
                return Poll::Ready(Ok(()));
            }

            let mut bytes = [0; READ_CHUNK_LEN];
            let mut read_buf = ReadBuf::new(&mut bytes);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        this.inner_eof = true;
                        if this.raw_read.is_empty() {
                            return Poll::Ready(Ok(()));
                        }

                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete vision frame",
                        )));
                    }

                    this.raw_read.extend_from_slice(filled);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for VisionStream<S>
where
    S: VisionStreamIo,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // A frame begun is owed the writer's next bytes as its payload.
        if this.frame.is_some_and(|frame| frame.payload > 0) {
            return this.poll_write_frame(cx, input);
        }
        std::task::ready!(this.poll_finish_frame(cx))?;

        if this.direct_write_mode {
            return Pin::new(&mut this.inner).poll_write_direct(cx, input);
        }
        if !this.padding_write_mode {
            return Pin::new(&mut this.inner).poll_write(cx, input);
        }

        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let accepted_len = cmp::min(input.len(), MAX_CONTENT_LEN);
        let input = &input[..accepted_len];
        this.filter_tls_packet(input);
        if this.is_tls && is_complete_tls_application_data_records(input) {
            if this.enable_xtls {
                this.start_frame(accepted_len, VisionCommand::Direct, true)?;
                this.pending_direct_write_mode = true;
            } else {
                this.start_frame(accepted_len, VisionCommand::End, true)?;
                this.pending_end_write_mode = true;
            }
        } else if !this.is_tls12_or_above && this.packets_to_filter <= 1 {
            this.start_frame(accepted_len, VisionCommand::End, this.is_tls)?;
            this.pending_end_write_mode = true;
        } else {
            this.start_frame(accepted_len, VisionCommand::Continue, this.is_tls)?;
        }

        this.poll_write_frame(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_finish_frame(cx))?;
        if this.direct_write_mode {
            Pin::new(&mut this.inner).poll_flush_direct(cx)
        } else {
            Pin::new(&mut this.inner).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_finish_frame(cx))?;
        if let Some(frame) = this.frame {
            // Owed payload the writer never gave: a frame not begun goes,
            // one begun cannot end.
            if frame.started() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the stream shut down inside a vision frame",
                )));
            }
            this.frame = None;
            this.pending_direct_write_mode = false;
            this.pending_end_write_mode = false;
        }
        if this.direct_write_mode {
            Pin::new(&mut this.inner).poll_shutdown_direct(cx)
        } else {
            Pin::new(&mut this.inner).poll_shutdown(cx)
        }
    }
}

fn vision_to_io(error: VisionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn is_complete_tls_application_data_records(input: &[u8]) -> bool {
    let mut offset = 0;
    while offset < input.len() {
        if input.len() - offset < HEADER_LEN {
            return false;
        }
        if input[offset..offset + TLS_APPLICATION_DATA_START.len()] != TLS_APPLICATION_DATA_START {
            return false;
        }

        let record_len = u16::from_be_bytes([input[offset + 3], input[offset + 4]]) as usize;
        offset += HEADER_LEN;
        if input.len() - offset < record_len {
            return false;
        }
        offset += record_len;
    }

    !input.is_empty()
}

#[cfg(test)]
mod wire_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::DEFAULT_VISION_SEED as DEFAULT_SEED;
    use tokio::io::AsyncReadExt;

    const USER_ID: [u8; USER_ID_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[tokio::test]
    async fn a_written_frame_leaves_nothing_behind() {
        let (inner, mut peer) = tokio::io::duplex(256 * 1024);
        let mut stream = VisionStream::new(inner, USER_ID, DEFAULT_SEED);
        let payload = vec![7u8; 64 * 1024];

        tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
            .await
            .unwrap();

        assert!(stream.padding_write_mode, "the frames were padded");
        assert!(stream.frame.is_none(), "a written frame is kept");
        let mut written = vec![0; USER_ID_LEN + HEADER_LEN];
        peer.read_exact(&mut written).await.unwrap();
        assert_eq!(&written[..USER_ID_LEN], &USER_ID);
    }

    /// While the carrier waits, a padded write holds its frame's head and
    /// three counts, and none of the writer's bytes: the stream has no
    /// buffer to hold them in. The bytes go once the carrier takes them.
    #[tokio::test]
    async fn a_padded_write_that_waits_holds_none_of_its_bytes() {
        let (inner, mut peer) = tokio::io::duplex(1024);
        let mut stream = VisionStream::new(inner, USER_ID, DEFAULT_SEED);
        let payload: Vec<u8> = (0..32 * 1024).map(|at| at as u8).collect();
        let mut cx = Context::from_waker(std::task::Waker::noop());

        let mut written = 0;
        while let Poll::Ready(len) = Pin::new(&mut stream).poll_write(&mut cx, &payload[written..])
        {
            written += len.unwrap();
        }
        let frame = stream.frame.expect("the frame waits for the carrier");
        assert!(written < payload.len() && frame.started());
        assert_eq!(
            usize::from(frame.payload),
            payload.len() - written,
            "the frame is owed the bytes the carrier has not taken"
        );

        let reader = tokio::spawn(async move {
            let mut wire = Vec::new();
            peer.read_to_end(&mut wire).await.unwrap();
            wire
        });
        tokio::io::AsyncWriteExt::write_all(&mut stream, &payload[written..])
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut stream)
            .await
            .unwrap();
        drop(stream);
        let wire = reader.await.unwrap();
        let block = unpad_vision_block(&wire, &USER_ID).unwrap();
        assert_eq!(&block.payload[..], &payload[..]);
    }

    /// A frame being written costs its stream 30 bytes or so, whatever its
    /// payload: its head and three counts.
    #[test]
    fn a_frame_being_written_holds_its_head_and_counts() {
        let size = std::mem::size_of::<Option<FrameTail>>();
        assert!(size <= 32, "a frame being written is {size} B");
    }

    #[tokio::test]
    async fn read_frames_leave_no_buffer_behind_once_padding_ended() {
        let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
        let mut wire = Vec::new();
        for _ in 0..3 {
            let frame = padding
                .pad(BytesMut::from(&[1u8; 5000][..]), VisionCommand::Continue, 0)
                .unwrap();
            wire.extend_from_slice(&frame);
        }
        let end = padding
            .pad(BytesMut::from(&[2u8; 10][..]), VisionCommand::End, 0)
            .unwrap();
        wire.extend_from_slice(&end);
        wire.extend_from_slice(&[3u8; 700]);
        let mut stream = VisionStream::new(std::io::Cursor::new(wire), USER_ID, [0, 0, 0, 0]);

        let mut output = Vec::new();
        let mut chunk = [0; 1000];
        while output.len() < 3 * 5000 + 10 + 700 {
            let len = stream.read(&mut chunk).await.unwrap();
            assert_ne!(len, 0);
            output.extend_from_slice(&chunk[..len]);
        }

        assert!(!stream.padding_read_mode);
        assert!(!stream.raw_read.try_reclaim(1), "raw frames");
        assert!(!stream.decoded_read.try_reclaim(1), "decoded bytes");
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output.len(), 3 * 5000 + 10 + 700);
        assert!(output[..15000].iter().all(|byte| *byte == 1));
        assert!(output[15000..15010].iter().all(|byte| *byte == 2));
        assert!(output[15010..].iter().all(|byte| *byte == 3));
    }

    #[tokio::test]
    async fn reads_raw_bytes_after_direct_block() {
        let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
        let direct = padding
            .pad(BytesMut::from(&b"padded"[..]), VisionCommand::Direct, 0)
            .unwrap();
        let mut stream = VisionStream::new(
            std::io::Cursor::new([direct.to_vec(), b"raw".to_vec()].concat()),
            USER_ID,
            [0, 0, 0, 0],
        );
        let mut output = Vec::new();

        stream.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, b"paddedraw");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn raw_read_waits_for_decoded_bytes_and_never_follows_end() {
        let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
        let end = padding
            .pad(BytesMut::from(&b"padded"[..]), VisionCommand::End, 0)
            .unwrap();
        let mut stream =
            VisionStream::new(std::io::Cursor::new(end.to_vec()), USER_ID, [0, 0, 0, 0]);
        let mut output = [0; 3];

        // Still padding: the peer may yet send `Direct`.
        assert!(matches!(stream.raw_read(), RawRead::NotYet));
        stream.read_exact(&mut output).await.unwrap();
        // `End` arrived, but half of its payload is still to be read.
        assert!(matches!(stream.raw_read(), RawRead::NotYet));
        stream.read_exact(&mut output).await.unwrap();
        assert!(matches!(stream.raw_read(), RawRead::Never));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn raw_read_after_direct_is_the_carriers_answer() {
        let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
        let direct = padding
            .pad(BytesMut::from(&b"padded"[..]), VisionCommand::Direct, 0)
            .unwrap();
        let mut stream = VisionStream::new(
            std::io::Cursor::new([direct.to_vec(), b"raw".to_vec()].concat()),
            USER_ID,
            [0, 0, 0, 0],
        );
        let mut output = [0; 9];

        stream.read_exact(&mut output[..6]).await.unwrap();
        // "raw" followed the block into the stream's own buffer.
        assert!(matches!(stream.raw_read(), RawRead::NotYet));
        stream.read_exact(&mut output[6..]).await.unwrap();
        assert_eq!(&output, b"paddedraw");
        // A cursor is no socket, and says so as any carrier does by default.
        assert!(matches!(stream.raw_read(), RawRead::Never));
    }
}

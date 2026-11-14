use crate::frame::{self, Frame, Kind, Reason};
use crate::frame::{
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_SETTINGS_HEADER_TABLE_SIZE, MAX_MAX_FRAME_SIZE,
};
use crate::proto::Error;

use crate::hpack;

use futures_core::Stream;

use bytes::{Buf, BytesMut};

use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tokio_util::codec::FramedRead as InnerFramedRead;
use tokio_util::codec::{LengthDelimitedCodec, LengthDelimitedCodecError};

// 16 MB "sane default" taken from golang http2
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 16 << 20;

#[derive(Debug)]
pub struct FramedRead<T> {
    inner: InnerFramedRead<T, LengthDelimitedCodec>,

    decoder: FrameDecoder,
}

#[derive(Debug)]
struct FrameDecoder {
    // hpack decoder state
    hpack: hpack::Decoder,

    max_header_list_size: usize,

    max_continuation_frames: usize,

    partial: Option<Partial>,
}

/// Partially loaded headers frame
#[derive(Debug)]
struct Partial {
    /// Empty frame
    frame: Continuable,

    /// Partial header payload
    buf: BytesMut,

    continuation_frames_count: usize,
}

#[derive(Debug)]
enum Continuable {
    Headers(frame::Headers),
    PushPromise(frame::PushPromise),
}

impl<T> FramedRead<T> {
    pub fn new(inner: InnerFramedRead<T, LengthDelimitedCodec>) -> FramedRead<T> {
        let decoder = FrameDecoder::new(inner.decoder().max_frame_length());
        FramedRead { inner, decoder }
    }

    pub fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Returns the current max frame size setting
    #[inline]
    pub fn max_frame_size(&self) -> usize {
        self.inner.decoder().max_frame_length()
    }

    /// Updates the max frame size setting.
    ///
    /// Must be within 16,384 and 16,777,215.
    #[inline]
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usize);
        self.inner.decoder_mut().set_max_frame_length(val);
        // Update max CONTINUATION frames too, since its based on this
        self.decoder.set_max_frame_size(val);
    }

    /// Update the max header list size setting.
    #[inline]
    pub fn set_max_header_list_size(&mut self, val: usize) {
        self.decoder
            .set_max_header_list_size(val, self.max_frame_size());
    }

    /// Update the header table size setting.
    #[inline]
    pub fn set_header_table_size(&mut self, val: usize) {
        self.decoder.set_header_table_size(val);
    }
}

fn calc_max_continuation_frames(header_max: usize, frame_max: usize) -> usize {
    // At least this many frames needed to use max header list size
    let min_frames_for_list = (header_max / frame_max).max(1);
    // Some padding for imperfectly packed frames
    // 25% without floats
    let padding = min_frames_for_list >> 2;
    min_frames_for_list.saturating_add(padding).max(5)
}

impl FrameDecoder {
    fn new(max_frame_size: usize) -> Self {
        let max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        FrameDecoder {
            hpack: hpack::Decoder::new(DEFAULT_SETTINGS_HEADER_TABLE_SIZE),
            max_header_list_size,
            max_continuation_frames: calc_max_continuation_frames(
                max_header_list_size,
                max_frame_size,
            ),
            partial: None,
        }
    }

    fn set_max_frame_size(&mut self, val: usize) {
        self.max_continuation_frames = calc_max_continuation_frames(self.max_header_list_size, val);
    }

    fn set_max_header_list_size(&mut self, val: usize, max_frame_size: usize) {
        self.max_header_list_size = val;
        // Update max CONTINUATION frames too, since its based on this
        self.max_continuation_frames = calc_max_continuation_frames(val, max_frame_size);
    }

    fn set_header_table_size(&mut self, val: usize) {
        self.hpack.queue_size_update(val);
    }

    fn decode(&mut self, bytes: BytesMut) -> Result<Option<Frame>, Error> {
        decode_frame(self, bytes)
    }
}

/// Decodes a frame.
///
/// This function is intentionally de-generified and outlined because it is very large.
fn decode_frame(decoder: &mut FrameDecoder, mut bytes: BytesMut) -> Result<Option<Frame>, Error> {
    let span = tracing::trace_span!("FramedRead::decode_frame", offset = bytes.len());
    let _e = span.enter();

    tracing::trace!("decoding frame from {}B", bytes.len());

    // Parse the head
    let head = frame::Head::parse(&bytes);

    if decoder.partial.is_some() && head.kind() != Kind::Continuation {
        proto_err!(conn: "expected CONTINUATION, got {:?}", head.kind());
        return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
    }

    let kind = head.kind();

    tracing::trace!(frame.kind = ?kind);

    macro_rules! header_block {
        ($frame:ident, $head:ident, $bytes:ident) => ({
            // Drop the frame header
            $bytes.advance(frame::HEADER_LEN);

            // Parse the header frame w/o parsing the payload
            let (mut frame, mut payload) = match frame::$frame::load($head, $bytes) {
                Ok(res) => res,
                Err(frame::Error::InvalidDependencyId) => {
                    proto_err!(stream: "invalid HEADERS dependency ID");
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    return Err(Error::library_reset($head.stream_id(), Reason::PROTOCOL_ERROR));
                },
                Err(e) => {
                    proto_err!(conn: "failed to load frame; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            let is_end_headers = frame.is_end_headers();

            // Load the HPACK encoded headers
            match frame.load_hpack(&mut payload, decoder.max_header_list_size, &mut decoder.hpack) {
                Ok(_) => {},
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {},
                Err(frame::Error::MalformedMessage) => {
                    let id = $head.stream_id();
                    proto_err!(stream: "malformed header block; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                },
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                },
                Err(e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                frame.into()
            } else {
                tracing::trace!("loaded partial header block");
                // Defer returning the frame
                decoder.partial = Some(Partial {
                    frame: Continuable::$frame(frame),
                    buf: payload,
                    continuation_frames_count: 0,
                });

                return Ok(None);
            }
        });
    }

    let frame = match kind {
        Kind::Settings => {
            let res = frame::Settings::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load SETTINGS frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Ping => {
            let res = frame::Ping::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load PING frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::WindowUpdate => {
            let res = frame::WindowUpdate::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load WINDOW_UPDATE frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Data => {
            bytes.advance(frame::HEADER_LEN);
            let res = frame::Data::load(head, bytes.freeze());

            // TODO: Should this always be connection level? Probably not...
            res.map_err(|e| {
                proto_err!(conn: "failed to load DATA frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Headers => header_block!(Headers, head, bytes),
        Kind::Reset => {
            let res = frame::Reset::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|e| {
                proto_err!(conn: "failed to load RESET frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::GoAway => {
            let res = frame::GoAway::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|e| {
                proto_err!(conn: "failed to load GO_AWAY frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::PushPromise => header_block!(PushPromise, head, bytes),
        Kind::Priority => {
            if head.stream_id() == 0 {
                // Invalid stream identifier
                proto_err!(conn: "invalid stream ID 0");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            match frame::Priority::load(head, &bytes[frame::HEADER_LEN..]) {
                Ok(frame) => frame.into(),
                Err(frame::Error::InvalidDependencyId) => {
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    let id = head.stream_id();
                    proto_err!(stream: "PRIORITY invalid dependency ID; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(e) => {
                    proto_err!(conn: "failed to load PRIORITY frame; err={:?};", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }
        }
        Kind::Continuation => {
            let is_end_headers = (head.flag() & 0x4) == 0x4;

            let mut partial = match decoder.partial.take() {
                Some(partial) => partial,
                None => {
                    proto_err!(conn: "received unexpected CONTINUATION frame");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            // The stream identifiers must match
            if partial.frame.stream_id() != head.stream_id() {
                proto_err!(conn: "CONTINUATION frame stream ID does not match previous frame stream ID");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            // Check for CONTINUATION flood
            if is_end_headers {
                partial.continuation_frames_count = 0;
            } else {
                let cnt = partial.continuation_frames_count + 1;
                if cnt > decoder.max_continuation_frames {
                    tracing::debug!(
                        "too_many_continuations, max = {}",
                        decoder.max_continuation_frames
                    );
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "too_many_continuations",
                    ));
                } else {
                    partial.continuation_frames_count = cnt;
                }
            }

            // Extend the buf
            if partial.buf.is_empty() {
                partial.buf = bytes.split_off(frame::HEADER_LEN);
            } else {
                if partial.frame.is_over_size() {
                    // If there was left over bytes previously, they may be
                    // needed to continue decoding, even though we will
                    // be ignoring this frame. This is done to keep the HPACK
                    // decoder state up-to-date.
                    //
                    // Still, we need to be careful, because if a malicious
                    // attacker were to try to send a gigantic string, such
                    // that it fits over multiple header blocks, we could
                    // grow memory uncontrollably again, and that'd be a shame.
                    //
                    // Instead, we use a simple heuristic to determine if
                    // we should continue to ignore decoding, or to tell
                    // the attacker to go away.
                    if partial.buf.len() + bytes.len() > decoder.max_header_list_size {
                        proto_err!(conn: "CONTINUATION frame header block size over ignorable limit");
                        return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                    }
                }
                partial.buf.extend_from_slice(&bytes[frame::HEADER_LEN..]);
            }

            match partial.frame.load_hpack(
                &mut partial.buf,
                decoder.max_header_list_size,
                &mut decoder.hpack,
            ) {
                Ok(_) => {}
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {}
                Err(frame::Error::MalformedMessage) => {
                    let id = head.stream_id();
                    proto_err!(stream: "malformed CONTINUATION frame; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded CONTINUATION header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                }
                Err(e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                partial.frame.into()
            } else {
                decoder.partial = Some(partial);
                return Ok(None);
            }
        }
        Kind::Unknown => {
            // Unknown frames are ignored
            return Ok(None);
        }
    };

    Ok(Some(frame))
}

impl<T> Stream for FramedRead<T>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let span = tracing::trace_span!("FramedRead::poll_next");
        let _e = span.enter();
        loop {
            tracing::trace!("poll");
            let bytes = match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => return Poll::Ready(Some(Err(map_err(e)))),
                None => return Poll::Ready(None),
            };

            tracing::trace!(read.bytes = bytes.len());
            if let Some(frame) = self.decoder.decode(bytes)? {
                tracing::debug!(?frame, "received");
                return Poll::Ready(Some(Ok(frame)));
            }
        }
    }
}

fn map_err(err: io::Error) -> Error {
    if let io::ErrorKind::InvalidData = err.kind() {
        if let Some(custom) = err.get_ref() {
            if custom.is::<LengthDelimitedCodecError>() {
                return Error::library_go_away(Reason::FRAME_SIZE_ERROR);
            }
        }
    }
    err.into()
}

// ===== impl Continuable =====

impl Continuable {
    fn stream_id(&self) -> frame::StreamId {
        match *self {
            Continuable::Headers(ref h) => h.stream_id(),
            Continuable::PushPromise(ref p) => p.stream_id(),
        }
    }

    fn is_over_size(&self) -> bool {
        match *self {
            Continuable::Headers(ref h) => h.is_over_size(),
            Continuable::PushPromise(ref p) => p.is_over_size(),
        }
    }

    fn load_hpack(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), frame::Error> {
        match *self {
            Continuable::Headers(ref mut h) => h.load_hpack(src, max_header_list_size, decoder),
            Continuable::PushPromise(ref mut p) => p.load_hpack(src, max_header_list_size, decoder),
        }
    }
}

impl<T> From<Continuable> for Frame<T> {
    fn from(cont: Continuable) -> Self {
        match cont {
            Continuable::Headers(mut headers) => {
                headers.set_end_headers();
                headers.into()
            }
            Continuable::PushPromise(mut push) => {
                push.set_end_headers();
                push.into()
            }
        }
    }
}

/// xray-rust: frames as the reader hands them on, however the bytes arrive.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Codec;
    use crate::proto::Initiator;

    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use tokio::io::{AsyncWrite, ReadBuf};

    /// What the peer's side of the connection does at each read.
    #[derive(Debug)]
    enum Step {
        Bytes(Vec<u8>),
        Pending,
        Eof,
    }

    /// A connection that plays `steps`; once they are over, it is at EOF.
    #[derive(Debug)]
    struct Script(VecDeque<Step>);

    impl AsyncRead for Script {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.pop_front() {
                None | Some(Step::Eof) => Poll::Ready(Ok(())),
                Some(Step::Pending) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(Step::Bytes(mut bytes)) => {
                    let n = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        bytes.drain(..n);
                        self.0.push_front(Step::Bytes(bytes));
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    impl AsyncWrite for Script {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct NoWake;

    impl Wake for NoWake {
        fn wake(self: Arc<Self>) {}
    }

    fn codec_for(steps: Vec<Step>) -> Codec<Script, Bytes> {
        Codec::new(Script(steps.into()))
    }

    /// Polls until the codec is ready: a `Pending` step wakes at once.
    fn next(codec: &mut Codec<Script, Bytes>) -> Option<Result<Frame, Error>> {
        let waker = Waker::from(Arc::new(NoWake));
        let mut cx = Context::from_waker(&waker);
        for _ in 0..1_000_000 {
            if let Poll::Ready(item) = Pin::new(&mut *codec).poll_next(&mut cx) {
                return item;
            }
        }
        panic!("the codec never became ready");
    }

    fn raw_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut frame = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        frame.extend_from_slice(&stream.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn data(stream: u32, payload: &[u8]) -> Vec<u8> {
        raw_frame(0x0, 0, stream, payload)
    }

    fn ping(payload: [u8; 8]) -> Vec<u8> {
        raw_frame(0x6, 0, 0, &payload)
    }

    fn data_payload(item: Option<Result<Frame, Error>>) -> Bytes {
        match item {
            Some(Ok(Frame::Data(data))) => data.into_payload(),
            other => panic!("expected a DATA frame, got {:?}", other),
        }
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
    }

    /// Two DATA frames that arrive in one read: each frame's payload is an
    /// allocation of its own from the moment it is decoded, not a share of a
    /// read buffer that the next frame's bytes keep alive while the payload
    /// waits in a stream's queue.
    #[test]
    fn a_data_frame_owns_its_bytes() {
        let first = pattern(8 * 1024, 1);
        let second = pattern(8 * 1024, 2);
        let mut wire = data(1, &first);
        wire.extend(data(1, &second));
        let mut codec = codec_for(vec![Step::Bytes(wire)]);

        let first_payload = data_payload(next(&mut codec));
        assert_eq!(first_payload, first);
        assert!(
            first_payload.is_unique(),
            "the first frame's payload shares its allocation with the read buffer"
        );
        let second_payload = data_payload(next(&mut codec));
        assert_eq!(second_payload, second);
        assert!(
            second_payload.is_unique(),
            "the second frame's payload shares its allocation with the read buffer"
        );
    }

    /// The same frames, cut at every size and with the peer pausing between
    /// pieces, decode to the same frames; a frame larger than the default
    /// maximum is read whole once the maximum allows it.
    #[test]
    fn frames_arrive_whole_however_the_bytes_are_cut() {
        let small = pattern(1, 3);
        let empty = Vec::new();
        let large = pattern(300 * 1024 + 7, 4);
        let mut wire = ping(*b"xray-h2r");
        wire.extend(data(1, &small));
        wire.extend(data(3, &empty));
        wire.extend(data(1, &large));
        wire.extend(raw_frame(0x8, 0, 0, &1000_u32.to_be_bytes()));

        for cut in [1, 7, 9, 10, 4096, 16_393, wire.len()] {
            let mut steps = Vec::new();
            for piece in wire.chunks(cut) {
                steps.push(Step::Bytes(piece.to_vec()));
                steps.push(Step::Pending);
            }
            let mut codec = codec_for(steps);
            codec.set_max_recv_frame_size(1 << 20);

            match next(&mut codec) {
                Some(Ok(Frame::Ping(ping))) => assert_eq!(ping.payload(), b"xray-h2r"),
                other => panic!("cut {}: expected PING, got {:?}", cut, other),
            }
            assert_eq!(data_payload(next(&mut codec)), small, "cut {}", cut);
            assert_eq!(data_payload(next(&mut codec)), empty, "cut {}", cut);
            assert_eq!(data_payload(next(&mut codec)), large, "cut {}", cut);
            match next(&mut codec) {
                Some(Ok(Frame::WindowUpdate(update))) => {
                    assert_eq!(update.size_increment(), 1000)
                }
                other => panic!("cut {}: expected WINDOW_UPDATE, got {:?}", cut, other),
            }
            assert!(next(&mut codec).is_none(), "cut {}: EOF ends the stream", cut);
        }
    }

    /// A frame larger than SETTINGS_MAX_FRAME_SIZE is a connection error of
    /// type FRAME_SIZE_ERROR, read from its header alone; then the stream ends.
    #[test]
    fn a_frame_above_the_maximum_is_a_frame_size_error() {
        let oversize = data(1, &vec![0; DEFAULT_MAX_FRAME_SIZE as usize + 1]);
        let header = oversize[..frame::HEADER_LEN].to_vec();
        let mut codec = codec_for(vec![Step::Bytes(header), Step::Pending]);
        match next(&mut codec) {
            Some(Err(Error::GoAway(_, Reason::FRAME_SIZE_ERROR, Initiator::Library))) => {}
            other => panic!("expected FRAME_SIZE_ERROR, got {:?}", other),
        }
        assert!(next(&mut codec).is_none(), "the stream ends after the error");

        // The largest frame the maximum allows is read.
        let largest = pattern(DEFAULT_MAX_FRAME_SIZE as usize, 5);
        let mut codec = codec_for(vec![Step::Bytes(data(1, &largest))]);
        assert_eq!(data_payload(next(&mut codec)), largest);
    }

    /// EOF between frames ends the stream; EOF inside a frame's header or
    /// payload is the error tokio-util's reader gave, and then the stream ends.
    #[test]
    fn eof_inside_a_frame_is_an_error() {
        let whole = data(1, &pattern(100, 6));
        let mut codec = codec_for(vec![Step::Bytes(whole.clone()), Step::Eof]);
        assert_eq!(data_payload(next(&mut codec)).len(), 100);
        assert!(next(&mut codec).is_none(), "EOF between frames");

        for cut in [1, frame::HEADER_LEN - 1, frame::HEADER_LEN, whole.len() - 1] {
            let mut codec = codec_for(vec![Step::Bytes(whole[..cut].to_vec()), Step::Eof]);
            match next(&mut codec) {
                Some(Err(Error::Io(io::ErrorKind::Other, Some(message)))) => {
                    assert_eq!(message, "bytes remaining on stream", "cut {}", cut)
                }
                other => panic!("cut {}: expected an I/O error, got {:?}", cut, other),
            }
            assert!(next(&mut codec).is_none(), "cut {}: the stream ends", cut);
        }
    }
}

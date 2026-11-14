//! Length framing of the handshake and control streams
//! (`internal/framing/framing.go`): a big-endian `u32` length, then that many
//! bytes of body, written as one piece.
//!
//! One piece matters: every layer below turns one write into one unit (a smux
//! frame, a record, a relay message), and a frame written as two could arrive
//! with its body where its length belongs (framing.go:32-40). [`encode`] and
//! [`Frame`] build the whole frame in one buffer for one write.
//!
//! A limit of 0 means none, as in Go; the handshake reads with 64 KiB
//! ([`crate::handshake::MAX_MESSAGE_SIZE`]) and the control stream with
//! 16 KiB ([`crate::control::MAX_MESSAGE_SIZE`]).

use std::io::{self, Read};

/// The length prefix: a big-endian `u32` (framing.go:20-21).
pub const HEADER_SIZE: usize = 4;

/// A frame's body is longer than the limit (framing.go:17-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("frame too large: {len} > {max}")]
pub struct FrameTooLarge {
    /// The body's length.
    pub len: u64,
    /// The limit.
    pub max: usize,
}

/// Why [`read`] did not return a frame. The variants are where
/// `framing.ReadBytes` stopped (framing.go:54-69), and
/// [`ReadError::verdict`] their names in the vectors.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The header announced more than the limit; nothing after the header was
    /// read.
    #[error(transparent)]
    TooLarge(#[from] FrameTooLarge),
    /// The stream ended before the header.
    #[error("read hdr: EOF")]
    EofHeader,
    /// The stream ended inside the header.
    #[error("read hdr: unexpected EOF")]
    TruncatedHeader,
    /// The stream ended right after the header.
    #[error("read body: EOF")]
    EofBody,
    /// The stream ended inside the body.
    #[error("read body: unexpected EOF")]
    TruncatedBody,
    /// The reader failed in the header (`read hdr: %w`).
    #[error("read hdr: {0}")]
    IoHeader(#[source] io::Error),
    /// The reader failed in the body (`read body: %w`).
    #[error("read body: {0}")]
    IoBody(#[source] io::Error),
}

impl ReadError {
    /// The verdict's name in the vectors.
    #[must_use]
    pub const fn verdict(&self) -> &'static str {
        match self {
            Self::TooLarge(_) => "too_large",
            Self::EofHeader => "eof_header",
            Self::TruncatedHeader => "truncated_header",
            Self::EofBody => "eof_body",
            Self::TruncatedBody => "truncated_body",
            Self::IoHeader(_) | Self::IoBody(_) => "io",
        }
    }
}

fn check(len: usize, max: usize) -> Result<(), FrameTooLarge> {
    if max > 0 && len > max {
        return Err(FrameTooLarge {
            len: len as u64,
            max,
        });
    }
    Ok(())
}

/// Appends the frame of `body` to `out` (`WriteBytes`, framing.go:41-52).
///
/// # Errors
/// [`FrameTooLarge`] when `max` > 0 and the body is longer; `out` is then
/// unchanged.
pub fn encode(body: &[u8], max: usize, out: &mut Vec<u8>) -> Result<(), FrameTooLarge> {
    check(body.len(), max)?;
    let len = u32::try_from(body.len()).map_err(|_| FrameTooLarge {
        len: body.len() as u64,
        max,
    })?;
    out.reserve(HEADER_SIZE + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(())
}

/// A frame being written straight into a buffer: the body is appended after
/// [`Frame::begin`], and [`Frame::finish`] fills in the length. Spares the
/// copy [`encode`] makes of a body built elsewhere.
#[derive(Debug)]
#[must_use = "a frame must be finished"]
pub struct Frame {
    start: usize,
}

impl Frame {
    /// Reserves the header at the end of `out`.
    pub fn begin(out: &mut Vec<u8>) -> Self {
        let start = out.len();
        out.extend_from_slice(&[0; HEADER_SIZE]);
        Self { start }
    }

    /// Writes the length of everything appended since [`Frame::begin`].
    ///
    /// # Errors
    /// [`FrameTooLarge`] when `max` > 0 and the body is longer; `out` is then
    /// back to what it was before [`Frame::begin`].
    pub fn finish(self, out: &mut Vec<u8>, max: usize) -> Result<(), FrameTooLarge> {
        let body = out.len() - self.start - HEADER_SIZE;
        let len = check(body, max).and_then(|()| {
            u32::try_from(body).map_err(|_| FrameTooLarge {
                len: body as u64,
                max,
            })
        });
        match len {
            Ok(len) => {
                out[self.start..self.start + HEADER_SIZE].copy_from_slice(&len.to_be_bytes());
                Ok(())
            }
            Err(e) => {
                out.truncate(self.start);
                Err(e)
            }
        }
    }
}

/// Finds the first frame in `buf`: `Some((body, consumed))`, or `None` when
/// `buf` does not hold all of it yet.
///
/// # Errors
/// [`FrameTooLarge`] as soon as the header announces more than `max` (> 0).
pub fn try_decode(buf: &[u8], max: usize) -> Result<Option<(&[u8], usize)>, FrameTooLarge> {
    let Some(header) = buf.get(..HEADER_SIZE) else {
        return Ok(None);
    };
    let len = u32::from_be_bytes(header.try_into().expect("4 bytes"));
    if max > 0 && u64::from(len) > max as u64 {
        return Err(FrameTooLarge {
            len: u64::from(len),
            max,
        });
    }
    let end = HEADER_SIZE + len as usize;
    Ok(buf.get(HEADER_SIZE..end).map(|body| (body, end)))
}

/// Reads one frame from `r` into `out` (cleared first), as `ReadBytes` does
/// (framing.go:54-69). The body is read as it arrives, so a header that lies
/// about the length costs no more memory than the bytes that follow it.
///
/// # Errors
/// The [`ReadError`] for where the stream stopped.
pub fn read<R: Read + ?Sized>(r: &mut R, max: usize, out: &mut Vec<u8>) -> Result<(), ReadError> {
    out.clear();
    let mut header = [0u8; HEADER_SIZE];
    match read_full(r, &mut header).map_err(ReadError::IoHeader)? {
        0 => return Err(ReadError::EofHeader),
        HEADER_SIZE => {}
        _ => return Err(ReadError::TruncatedHeader),
    }
    let len = u32::from_be_bytes(header);
    if max > 0 && u64::from(len) > max as u64 {
        return Err(FrameTooLarge {
            len: u64::from(len),
            max,
        }
        .into());
    }
    let len = len as usize;
    let got = r
        .take(len as u64)
        .read_to_end(out)
        .map_err(ReadError::IoBody)?;
    match got {
        n if n == len => Ok(()),
        0 => Err(ReadError::EofBody),
        _ => Err(ReadError::TruncatedBody),
    }
}

/// `io.ReadFull` for a small buffer: the number of bytes read before the
/// stream ended.
fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_built_in_place_matches_encode() {
        let mut direct = Vec::new();
        encode(b"{}", 16, &mut direct).unwrap();
        let mut built = vec![9];
        let frame = Frame::begin(&mut built);
        built.extend_from_slice(b"{}");
        frame.finish(&mut built, 16).unwrap();
        assert_eq!(&built[1..], &direct[..]);
    }

    #[test]
    fn a_frame_over_the_limit_leaves_the_buffer_alone() {
        let mut out = vec![1, 2];
        let frame = Frame::begin(&mut out);
        out.extend_from_slice(&[0; 17]);
        assert_eq!(
            frame.finish(&mut out, 16),
            Err(FrameTooLarge { len: 17, max: 16 })
        );
        assert_eq!(out, [1, 2]);
        assert!(encode(&[0; 17], 16, &mut out).is_err());
        assert_eq!(out, [1, 2]);
    }

    #[test]
    fn try_decode_waits_for_the_whole_frame() {
        let frame = [0, 0, 0, 3, b'a', b'b', b'c', 0xff];
        assert_eq!(try_decode(&frame[..3], 0), Ok(None));
        assert_eq!(try_decode(&frame[..6], 0), Ok(None));
        assert_eq!(try_decode(&frame, 0), Ok(Some((&b"abc"[..], 7))));
        assert_eq!(
            try_decode(&frame[..4], 2),
            Err(FrameTooLarge { len: 3, max: 2 })
        );
    }
}

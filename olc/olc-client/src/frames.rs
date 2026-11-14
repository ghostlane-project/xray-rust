// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `framing.ReadBytes` over an async stream: a `u32` big-endian length and
//! the body, with Go's errors ([`olc_wire::framing::ReadError`]).

use olc_wire::framing::{FrameTooLarge, ReadError, HEADER_SIZE};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Reads one frame of at most `max` bytes (0: no limit) into `buf`, which
/// then holds the body alone.
///
/// # Errors
/// Where the read stopped, as Go names it.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    max: usize,
    buf: &mut Vec<u8>,
) -> Result<(), ReadError> {
    let mut hdr = [0u8; HEADER_SIZE];
    fill(
        r,
        &mut hdr,
        ReadError::EofHeader,
        ReadError::TruncatedHeader,
        ReadError::IoHeader,
    )
    .await?;
    let len = u32::from_be_bytes(hdr) as usize;
    if max > 0 && len > max {
        return Err(ReadError::TooLarge(FrameTooLarge {
            len: len as u64,
            max,
        }));
    }
    buf.clear();
    buf.resize(len, 0);
    fill(
        r,
        buf,
        ReadError::EofBody,
        ReadError::TruncatedBody,
        ReadError::IoBody,
    )
    .await
}

async fn fill<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    out: &mut [u8],
    eof: ReadError,
    truncated: ReadError,
    failed: fn(std::io::Error) -> ReadError,
) -> Result<(), ReadError> {
    let mut at = 0;
    while at < out.len() {
        match r.read(&mut out[at..]).await {
            Ok(0) if at == 0 => return Err(eof),
            Ok(0) => return Err(truncated),
            Ok(n) => at += n,
            Err(e) => return Err(failed(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_errors_name_where_the_read_stopped() {
        crate::testing::bounded(the_errors_name_where_the_read_stopped_body()).await;
    }

    async fn the_errors_name_where_the_read_stopped_body() {
        let mut buf = Vec::new();
        let mut whole: &[u8] = &[0, 0, 0, 2, b'h', b'i'];
        read_frame(&mut whole, 16, &mut buf).await.unwrap();
        assert_eq!(buf, b"hi");
        for (wire, verdict) in [
            (&[][..], "eof_header"),
            (&[0, 0][..], "truncated_header"),
            (&[0, 0, 0, 2][..], "eof_body"),
            (&[0, 0, 0, 2, 1][..], "truncated_body"),
            (&[0, 0, 0, 17][..], "too_large"),
        ] {
            let mut r = wire;
            let err = read_frame(&mut r, 16, &mut buf).await.unwrap_err();
            assert_eq!(err.verdict(), verdict);
        }
        // The empty-body case of Go's io.ReadFull: zero bytes are no read.
        let mut empty: &[u8] = &[0, 0, 0, 0];
        read_frame(&mut empty, 16, &mut buf).await.unwrap();
        assert!(buf.is_empty());
    }
}

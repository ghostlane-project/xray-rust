// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! permessage-deflate (RFC 7692) for [`crate::ws`], offered the way the Go
//! engine's WebSocket library (coder/websocket 1.8.14) offers it: the bare
//! `permessage-deflate`, no parameters. A server's answer is checked as that
//! library checks it: one extension, the two context-takeover parameters and
//! `server_max_window_bits` accepted (a window up to 32 KiB is read whatever
//! the server's own is), anything else a handshake error.
//!
//! Memory: the inflater is one 32 KiB window and the compressor, made at the
//! first message that reaches [`THRESHOLD`], about 0.3 MiB; with no context
//! takeover the same state is reset after each message, not freed. The
//! inflated size is bounded by the caller's read limit while it is made, not
//! after.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::ws::WsError;

/// The smallest message the client compresses (coder/websocket's default
/// for context takeover, 128 bytes).
pub(crate) const THRESHOLD: usize = 128;

/// The empty stored block every message's deflate stream ends with, left out
/// on the wire (RFC 7692 section 7.2.1).
const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// One step of output room asked of the buffer at a time.
const STEP: usize = 16 * 1024;

/// What the server's reply settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Params {
    /// The client resets its compressor after every message.
    pub client_no_context_takeover: bool,
    /// The server resets its compressor after every message.
    pub server_no_context_takeover: bool,
}

fn bad(why: &str) -> WsError {
    WsError::Handshake(format!("permessage-deflate: {why}"))
}

/// Reads the `Sec-WebSocket-Extensions` values of a reply (each header line
/// as one string). `None` when there is no extension at all.
pub(crate) fn parse_reply(values: &[&str]) -> Result<Option<Params>, WsError> {
    let mut exts = values
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|e| !e.is_empty());
    let Some(first) = exts.next() else {
        return Ok(None);
    };
    if exts.next().is_some() {
        return Err(bad("more than one extension in the reply"));
    }
    let mut parts = first.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|n| n.eq_ignore_ascii_case("permessage-deflate"))
    {
        return Err(bad("unsupported extension from the server"));
    }
    let mut p = Params {
        client_no_context_takeover: false,
        server_no_context_takeover: false,
    };
    let (mut seen_c, mut seen_s, mut seen_w) = (false, false, false);
    for param in parts {
        let lower = param.to_ascii_lowercase();
        let (name, value) = match lower.split_once('=') {
            Some((n, v)) => (
                n.trim().to_owned(),
                Some(v.trim().trim_matches('"').to_owned()),
            ),
            None => (lower.clone(), None),
        };
        match (name.as_str(), value) {
            ("client_no_context_takeover", None) if !seen_c => {
                seen_c = true;
                p.client_no_context_takeover = true;
            }
            ("server_no_context_takeover", None) if !seen_s => {
                seen_s = true;
                p.server_no_context_takeover = true;
            }
            ("server_max_window_bits", Some(v)) if !seen_w => {
                seen_w = true;
                match v.parse::<u8>() {
                    Ok(8..=15) => {}
                    _ => return Err(bad("bad server_max_window_bits")),
                }
            }
            _ => return Err(bad("unsupported or repeated parameter")),
        }
    }
    Ok(Some(p))
}

/// The reading side: one raw-deflate window, kept between messages unless
/// the server said not to.
pub(crate) struct Inflater {
    d: Decompress,
    reset: bool,
}

impl Inflater {
    pub(crate) fn new(p: Params) -> Self {
        Self {
            d: Decompress::new(false),
            reset: p.server_no_context_takeover,
        }
    }

    /// One message's compressed bytes to its text, at most `limit` bytes of
    /// it.
    pub(crate) fn inflate(&mut self, compressed: &[u8], limit: usize) -> Result<Vec<u8>, WsError> {
        let mut out: Vec<u8> = Vec::new();
        for part in [compressed, &TAIL[..]] {
            let mut pos = 0;
            loop {
                let room = STEP.min(limit + 1 - out.len()).max(1);
                out.reserve_exact(room);
                let spare = out.capacity() - out.len();
                let (in0, out0) = (self.d.total_in(), self.d.total_out());
                let status = self
                    .d
                    .decompress_vec(&part[pos..], &mut out, FlushDecompress::Sync)
                    .map_err(|_| WsError::Protocol("invalid deflate data"))?;
                let used = usize::try_from(self.d.total_in() - in0).unwrap_or(usize::MAX);
                let made = usize::try_from(self.d.total_out() - out0).unwrap_or(usize::MAX);
                pos += used;
                if out.len() > limit {
                    return Err(WsError::TooLarge);
                }
                if status == Status::StreamEnd {
                    break;
                }
                if pos >= part.len() && made < spare {
                    break;
                }
                if used == 0 && made == 0 {
                    break;
                }
            }
        }
        if self.reset {
            self.d.reset(false);
        }
        Ok(out)
    }
}

/// The writing side. The compressor is made when the first message that is
/// worth compressing comes.
pub(crate) struct Deflater {
    c: Option<Compress>,
    reset: bool,
}

impl Deflater {
    pub(crate) fn new(p: Params) -> Self {
        Self {
            c: None,
            reset: p.client_no_context_takeover,
        }
    }

    /// One message's payload as it goes on the wire (RSV1 set), without the
    /// trailing empty block.
    pub(crate) fn deflate(&mut self, data: &[u8]) -> Vec<u8> {
        let c = self
            .c
            .get_or_insert_with(|| Compress::new(Compression::default(), false));
        let mut out: Vec<u8> = Vec::with_capacity(data.len() / 2 + 64);
        let mut pos = 0;
        loop {
            if out.capacity() - out.len() < 64 {
                out.reserve(STEP);
            }
            let spare = out.capacity() - out.len();
            let (in0, out0) = (c.total_in(), c.total_out());
            // A failure here cannot come from the data; nothing sensible is
            // left to send but what is made.
            let _ = c.compress_vec(&data[pos..], &mut out, FlushCompress::Sync);
            pos += usize::try_from(c.total_in() - in0).unwrap_or(usize::MAX);
            let made = usize::try_from(c.total_out() - out0).unwrap_or(usize::MAX);
            if pos >= data.len() && made < spare {
                break;
            }
        }
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - TAIL.len());
        }
        if self.reset {
            c.reset();
        }
        out
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! vp8channel's messages on a KCP stream (W33): `u32 BE length ‖ message`,
//! written in one session write.
//!
//! Go: olcRTC `internal/transport/vp8channel/kcp.go:108-118,192-256` at
//! 2d4266af. The engine runs KCP in stream mode and frames its own messages,
//! because kcp-go's `Write` cuts a message into `mss` pieces outside
//! `kcp.Send`, which loses the fragment numbers message mode relies on.
//!
//! - send: a message over 8 MiB is refused ("vp8channel: kcp message exceeds
//!   maximum size"); prefix and message go in one write, so a failure cannot
//!   leave a prefix without its bytes.
//! - read: a zero length is skipped; a length over 8 MiB ends the reader for
//!   good (Go's read loop returns, and nothing reads that session again).
//!
//! Memory: Go allocates the declared length at once (`kcp.go:207`). Here the
//! message buffer grows as its bytes arrive, so a declared length costs
//! nothing before the bytes come; one message in assembly holds at most its
//! own length (≤ 8 MiB; vp8channel's records are ≤ 61,440).

use std::time::Instant;

use crate::session::{Session, WouldBlock};

/// `kcpLenPrefix`.
pub const LEN_PREFIX: usize = 4;
/// `kcpMaxMessage`.
pub const MAX_MESSAGE: usize = 8 * 1024 * 1024;
/// How much of a declared length is reserved before its bytes arrive.
const INITIAL_RESERVE: usize = 64 * 1024;

/// Why a message was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// Over [`MAX_MESSAGE`] (`ErrKCPMessageTooLarge`).
    TooLarge,
    /// The send window is full; retry.
    WouldBlock,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("vp8channel: kcp message exceeds maximum size"),
            Self::WouldBlock => f.write_str("kcp send window full"),
        }
    }
}

impl std::error::Error for SendError {}

/// `kcpRuntime.send` (`kcp.go:236-256`).
pub fn send(session: &mut Session, msg: &[u8], now: Instant) -> Result<(), SendError> {
    if msg.len() > MAX_MESSAGE {
        return Err(SendError::TooLarge);
    }
    let prefix = (msg.len() as u32).to_be_bytes();
    // Stream mode cuts the byte stream at `mss` whatever the slices, so two
    // slices make exactly the segments of Go's one concatenated buffer.
    session
        .write(&[&prefix, msg], now)
        .map(|_| ())
        .map_err(|WouldBlock| SendError::WouldBlock)
}

/// A length over [`MAX_MESSAGE`] arrived: the reader is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge(pub u32);

/// `kcpRuntime.readLoop` (`kcp.go:192-215`) as a state machine.
#[derive(Debug, Default)]
pub struct Reader {
    hdr: [u8; LEN_PREFIX],
    hdr_have: usize,
    need: usize,
    body: Vec<u8>,
    dead: bool,
}

impl Reader {
    /// A reader at a message boundary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next whole message, `Ok(None)` when the session has no more bytes
    /// for now, `Err` once a length over the cap has arrived (and on every
    /// call after it).
    pub fn next(&mut self, session: &mut Session) -> Result<Option<Vec<u8>>, TooLarge> {
        if self.dead {
            return Err(TooLarge(0));
        }
        loop {
            if self.hdr_have < LEN_PREFIX {
                match session.read(&mut self.hdr[self.hdr_have..]) {
                    Some(n) => self.hdr_have += n,
                    None => return Ok(None),
                }
                if self.hdr_have < LEN_PREFIX {
                    continue;
                }
                let size = u32::from_be_bytes(self.hdr);
                if size == 0 {
                    self.hdr_have = 0;
                    continue;
                }
                if size as usize > MAX_MESSAGE {
                    self.dead = true;
                    return Err(TooLarge(size));
                }
                self.need = size as usize;
                self.body = Vec::with_capacity(self.need.min(INITIAL_RESERVE));
            }
            while self.body.len() < self.need {
                let have = self.body.len();
                let want = (self.need - have).min(INITIAL_RESERVE);
                self.body.resize(have + want, 0);
                match session.read(&mut self.body[have..]) {
                    Some(n) => self.body.truncate(have + n),
                    None => {
                        self.body.truncate(have);
                        return Ok(None);
                    }
                }
            }
            self.hdr_have = 0;
            self.need = 0;
            return Ok(Some(std::mem::take(&mut self.body)));
        }
    }

    /// Bytes of a message in assembly.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.body.capacity()
    }
}

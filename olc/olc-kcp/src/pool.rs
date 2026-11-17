// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Segment buffers: Go's `defaultBufferPool` (`kcp-go/bufferpool.go`), one
//! per connection here, with a cap on what it keeps.
//!
//! kcp-go hands every segment a buffer of `mtuLimit` (1500) bytes from a
//! process-wide `sync.Pool`. Here every buffer has [`BUF_CAP`] bytes of
//! capacity: the largest segment payload a packet of `mtuLimit` bytes can
//! carry (1500 − 24), which is also at least the `mss` of every MTU the
//! session allows, so stream-mode appends never reallocate (Go relies on the
//! same: "the underlying cap is guaranteed to be larger than kcp.mss",
//! `kcp-go/kcp.go:399-400`).
//!
//! Memory: buffers in use are bounded by the segments the queues may hold
//! (see [`crate::session`] for the formula); the free list keeps at most
//! [`Pool::DEFAULT_RETAIN`] buffers, `DEFAULT_RETAIN × BUF_CAP` = 94,464
//! bytes, and [`Pool::trim`] gives them all back.

use crate::kcp::IKCP_OVERHEAD;

/// kcp-go's `mtuLimit` (`kcp-go/sess.go:77`): the largest packet it reads or
/// writes.
pub const MTU_LIMIT: usize = 1500;

/// Capacity of every segment buffer: `MTU_LIMIT − IKCP_OVERHEAD` = 1476.
pub const BUF_CAP: usize = MTU_LIMIT - IKCP_OVERHEAD;

/// A free list of segment buffers.
#[derive(Debug)]
pub struct Pool {
    free: Vec<Vec<u8>>,
    retain: usize,
    in_use: usize,
    peak_in_use: usize,
}

impl Default for Pool {
    fn default() -> Self {
        Self::with_retain(Self::DEFAULT_RETAIN)
    }
}

impl Pool {
    /// Buffers kept free by default: 64, one OLKB batch of packets.
    pub const DEFAULT_RETAIN: usize = 64;

    /// A pool that keeps at most `retain` free buffers.
    #[must_use]
    pub fn with_retain(retain: usize) -> Self {
        Self {
            free: Vec::new(),
            retain,
            in_use: 0,
            peak_in_use: 0,
        }
    }

    /// An empty buffer with [`BUF_CAP`] bytes of capacity.
    pub fn get(&mut self) -> Vec<u8> {
        self.in_use += 1;
        self.peak_in_use = self.peak_in_use.max(self.in_use);
        match self.free.pop() {
            Some(mut b) => {
                b.clear();
                b
            }
            None => Vec::with_capacity(BUF_CAP),
        }
    }

    /// Gives a buffer back. An empty one (a segment already acknowledged)
    /// is ignored; one of another capacity is dropped, as Go's `Put`
    /// refuses a buffer of the wrong size.
    pub fn put(&mut self, buf: Vec<u8>) {
        if buf.capacity() == 0 {
            return;
        }
        self.in_use = self.in_use.saturating_sub(1);
        if buf.capacity() == BUF_CAP && self.free.len() < self.retain {
            self.free.push(buf);
        }
    }

    /// Buffers handed out and not given back.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.in_use
    }

    /// The most buffers ever handed out at once.
    #[must_use]
    pub fn peak_in_use(&self) -> usize {
        self.peak_in_use
    }

    /// Bytes the free list holds.
    #[must_use]
    pub fn free_bytes(&self) -> usize {
        self.free.len() * BUF_CAP
    }

    /// Drops every free buffer.
    pub fn trim(&mut self) {
        self.free = Vec::new();
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The session's chunk pool and the byte queues built on it.
//!
//! Go gives every received frame a buffer of its own from a size-class
//! allocator (`smux/alloc.go:42-101`, `smux/session.go:465`) and keeps the
//! buffers in a per-stream ring (`smux/stream.go:81-176`). Here every byte a
//! session holds, received or queued to send, sits in fixed 4 KiB chunks
//! from one pool per session. A queue is a linked list of chunks; a queue
//! that empties gives its chunks back at once, so a stream with nothing
//! buffered holds no payload memory. The pool keeps up to
//! [`Config::pool_retain_bytes`](crate::Config::pool_retain_bytes) of free
//! chunks for reuse and returns the rest to the allocator, so a busy session
//! allocates nothing per frame once warm.
//!
//! Frames keep their boundaries: a [`FrameQueue`] stores each frame as a
//! 2-byte length and its payload. A queue of `p` payload bytes in `f` frames
//! spans at most `ceil((p + 2f) / 4096) + 1` chunks.

/// The chunk size.
pub(crate) const CHUNK: usize = 4096;

const NIL: u32 = u32::MAX;

/// The chunk pool.
#[derive(Debug)]
pub(crate) struct Arena {
    /// Chunk memory by id; `None` once given back to the allocator.
    bufs: Vec<Option<Box<[u8]>>>,
    /// The next chunk of the queue a chunk belongs to.
    links: Vec<u32>,
    /// Ids with memory, not in use.
    pooled: Vec<u32>,
    /// Ids without memory.
    spare: Vec<u32>,
    in_use: usize,
    peak_in_use: usize,
    retain: usize,
}

impl Arena {
    pub(crate) fn new(retain_bytes: usize) -> Arena {
        Arena {
            bufs: Vec::new(),
            links: Vec::new(),
            pooled: Vec::new(),
            spare: Vec::new(),
            in_use: 0,
            peak_in_use: 0,
            retain: retain_bytes / CHUNK,
        }
    }

    fn alloc(&mut self) -> u32 {
        let id = if let Some(id) = self.pooled.pop() {
            id
        } else if let Some(id) = self.spare.pop() {
            self.bufs[id as usize] = Some(vec![0u8; CHUNK].into_boxed_slice());
            id
        } else {
            let id = self.bufs.len() as u32;
            self.bufs.push(Some(vec![0u8; CHUNK].into_boxed_slice()));
            self.links.push(NIL);
            id
        };
        self.links[id as usize] = NIL;
        self.in_use += 1;
        self.peak_in_use = self.peak_in_use.max(self.in_use);
        id
    }

    fn free(&mut self, id: u32) {
        self.in_use -= 1;
        if self.pooled.len() < self.retain {
            self.pooled.push(id);
        } else {
            self.bufs[id as usize] = None;
            self.spare.push(id);
        }
    }

    fn chunk(&self, id: u32) -> &[u8] {
        self.bufs[id as usize].as_deref().expect("chunk in use")
    }

    fn chunk_mut(&mut self, id: u32) -> &mut [u8] {
        self.bufs[id as usize].as_deref_mut().expect("chunk in use")
    }

    /// Gives every pooled chunk back to the allocator.
    pub(crate) fn release_pool(&mut self) {
        while let Some(id) = self.pooled.pop() {
            self.bufs[id as usize] = None;
            self.spare.push(id);
        }
    }

    /// Chunks holding queued bytes.
    pub(crate) fn in_use(&self) -> usize {
        self.in_use
    }

    /// The most chunks ever in use at once.
    pub(crate) fn peak_in_use(&self) -> usize {
        self.peak_in_use
    }

    /// Chunks with memory: in use plus pooled.
    pub(crate) fn held(&self) -> usize {
        self.in_use + self.pooled.len()
    }
}

/// A byte FIFO over pool chunks. 16 bytes.
#[derive(Debug)]
pub(crate) struct ByteQueue {
    head: u32,
    tail: u32,
    head_off: u16,
    tail_end: u16,
    len: u32,
}

impl Default for ByteQueue {
    fn default() -> ByteQueue {
        ByteQueue {
            head: NIL,
            tail: NIL,
            head_off: 0,
            tail_end: 0,
            len: 0,
        }
    }
}

impl ByteQueue {
    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    pub(crate) fn push(&mut self, arena: &mut Arena, mut data: &[u8]) {
        while !data.is_empty() {
            if self.tail == NIL || self.tail_end as usize == CHUNK {
                let id = arena.alloc();
                if self.tail == NIL {
                    self.head = id;
                    self.head_off = 0;
                } else {
                    arena.links[self.tail as usize] = id;
                }
                self.tail = id;
                self.tail_end = 0;
            }
            let end = self.tail_end as usize;
            let n = data.len().min(CHUNK - end);
            arena.chunk_mut(self.tail)[end..end + n].copy_from_slice(&data[..n]);
            self.tail_end = (end + n) as u16;
            self.len += n as u32;
            data = &data[n..];
        }
    }

    /// Moves up to `out.len()` bytes from the front into `out`.
    pub(crate) fn pop(&mut self, arena: &mut Arena, out: &mut [u8]) -> usize {
        let want = out.len().min(self.len as usize);
        let mut done = 0;
        while done < want {
            let off = self.head_off as usize;
            let avail = if self.head == self.tail {
                self.tail_end as usize - off
            } else {
                CHUNK - off
            };
            let n = avail.min(want - done);
            out[done..done + n].copy_from_slice(&arena.chunk(self.head)[off..off + n]);
            done += n;
            self.head_off = (off + n) as u16;
            self.len -= n as u32;
            if self.len == 0 {
                arena.free(self.head);
                *self = ByteQueue::default();
                break;
            }
            if self.head_off as usize == CHUNK {
                let next = arena.links[self.head as usize];
                arena.free(self.head);
                self.head = next;
                self.head_off = 0;
            }
        }
        done
    }

    /// Drops everything and gives the chunks back.
    pub(crate) fn clear(&mut self, arena: &mut Arena) {
        let mut id = self.head;
        while id != NIL {
            let next = if id == self.tail {
                NIL
            } else {
                arena.links[id as usize]
            };
            arena.free(id);
            id = next;
        }
        *self = ByteQueue::default();
    }
}

/// Frames in a [`ByteQueue`], each a 2-byte little-endian length and its
/// payload, read either a frame at a time or a frame's remainder at a time.
/// 20 bytes.
#[derive(Debug, Default)]
pub(crate) struct FrameQueue {
    q: ByteQueue,
    /// Payload bytes left in the front frame, once its length was read.
    front: u16,
    /// Whether `front` is valid (the front frame's length was taken).
    front_open: bool,
}

impl FrameQueue {
    pub(crate) fn is_empty(&self) -> bool {
        self.q.len() == 0 && !self.front_open
    }

    /// Appends one frame. `len` may be 0 (a marker frame).
    pub(crate) fn push(&mut self, arena: &mut Arena, data: &[u8]) {
        debug_assert!(data.len() <= u16::MAX as usize);
        self.q.push(arena, &(data.len() as u16).to_le_bytes());
        self.q.push(arena, data);
    }

    /// Opens the front frame if needed and returns its remaining length,
    /// or `None` when the queue is empty.
    pub(crate) fn front_len(&mut self, arena: &mut Arena) -> Option<usize> {
        if !self.front_open {
            if self.q.len() == 0 {
                return None;
            }
            let mut l = [0u8; 2];
            self.q.pop(arena, &mut l);
            self.front = u16::from_le_bytes(l);
            self.front_open = true;
        }
        Some(self.front as usize)
    }

    /// Copies up to `out.len()` bytes of the front frame's remainder; closes
    /// the frame once it is consumed. Go's `consumeFront`
    /// (`smux/stream.go:155-176`): never more than one frame.
    pub(crate) fn read_front(&mut self, arena: &mut Arena, out: &mut [u8]) -> usize {
        let Some(front) = self.front_len(arena) else {
            return 0;
        };
        let take = front.min(out.len());
        let n = self.q.pop(arena, &mut out[..take]);
        self.front -= n as u16;
        if self.front == 0 {
            self.front_open = false;
        }
        n
    }

    /// Pops the whole front frame into `out` and returns its length, or
    /// `None` when the queue is empty. `out` must hold 65535 bytes.
    pub(crate) fn pop_frame(&mut self, arena: &mut Arena, out: &mut [u8]) -> Option<usize> {
        let front = self.front_len(arena)?;
        let n = self.q.pop(arena, &mut out[..front]);
        debug_assert_eq!(n, front);
        self.front = 0;
        self.front_open = false;
        Some(n)
    }

    pub(crate) fn clear(&mut self, arena: &mut Arena) {
        self.q.clear(arena);
        self.front = 0;
        self.front_open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_across_chunks_and_free_on_empty() {
        let mut a = Arena::new(2 * CHUNK);
        let mut q = ByteQueue::default();
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        q.push(&mut a, &data);
        assert_eq!(q.len(), 10_000);
        assert_eq!(a.in_use(), 3);
        let mut out = vec![0u8; 10_000];
        assert_eq!(q.pop(&mut a, &mut out[..5000]), 5000);
        assert_eq!(a.in_use(), 2);
        assert_eq!(q.pop(&mut a, &mut out[5000..]), 5000);
        assert_eq!(out, data);
        assert_eq!(a.in_use(), 0);
        // Two chunks kept for reuse, the third given back.
        assert_eq!(a.held(), 2);
        assert_eq!(a.peak_in_use(), 3);
        a.release_pool();
        assert_eq!(a.held(), 0);
    }

    #[test]
    fn frames_keep_their_boundaries() {
        let mut a = Arena::new(0);
        let mut q = FrameQueue::default();
        q.push(&mut a, b"hello");
        q.push(&mut a, &[]);
        q.push(&mut a, &[9u8; 5000]);
        let mut out = [0u8; 3];
        assert_eq!(q.read_front(&mut a, &mut out), 3);
        assert_eq!(&out, b"hel");
        let mut big = vec![0u8; 65535];
        // The rest of the first frame only, though the buffer is larger.
        assert_eq!(q.read_front(&mut a, &mut big), 2);
        assert_eq!(&big[..2], b"lo");
        assert_eq!(q.pop_frame(&mut a, &mut big), Some(0));
        assert_eq!(q.pop_frame(&mut a, &mut big), Some(5000));
        assert!(big[..5000].iter().all(|&b| b == 9));
        assert_eq!(q.pop_frame(&mut a, &mut big), None);
        assert!(q.is_empty());
        assert_eq!(a.in_use(), 0);
        assert_eq!(a.held(), 0);
    }

    #[test]
    fn clear_frees_every_chunk() {
        let mut a = Arena::new(64 * CHUNK);
        let mut q = FrameQueue::default();
        for _ in 0..10 {
            q.push(&mut a, &[1u8; 3000]);
        }
        assert!(a.in_use() >= 8);
        q.clear(&mut a);
        assert_eq!(a.in_use(), 0);
        assert!(q.is_empty());
    }
}

use slab::Slab;

/// xray-rust: the slots a buffer keeps once it is empty, in bytes: 4 KiB, what
/// an idle connection may keep of it. Upstream kept every slot the buffer had
/// ever grown to, one per frame queued at once: a burst of 8 KiB DATA frames
/// queued in a 4 MiB window is 512 slots, and they stayed. Up to this size a
/// buffer that drains keeps its slots, so a stream that queues a few frames
/// between reads does not reallocate at each read.
const EMPTY_BUFFER_KEEP_BYTES: usize = 4 * 1024;

/// Buffers frames for multiple streams.
#[derive(Debug)]
pub struct Buffer<T> {
    slab: Slab<Slot<T>>,
}

/// A sequence of frames in a `Buffer`
#[derive(Debug)]
pub struct Deque {
    indices: Option<Indices>,
}

/// Tracks the head & tail for a sequence of frames in a `Buffer`.
#[derive(Debug, Default, Copy, Clone)]
struct Indices {
    head: usize,
    tail: usize,
}

#[derive(Debug)]
struct Slot<T> {
    value: T,
    next: Option<usize>,
}

impl<T> Buffer<T> {
    pub fn new() -> Self {
        Buffer { slab: Slab::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.slab.is_empty()
    }

    /// xray-rust: an empty buffer gives back slots beyond
    /// `EMPTY_BUFFER_KEEP_BYTES`. No key is held once it is empty: every
    /// `Deque` on it is empty too.
    fn release_slots(&mut self) {
        let kept = self
            .slab
            .capacity()
            .saturating_mul(std::mem::size_of::<Slot<T>>());
        if self.slab.is_empty() && kept > EMPTY_BUFFER_KEEP_BYTES {
            self.slab = Slab::new();
        }
    }
}

impl Deque {
    pub fn new() -> Self {
        Deque { indices: None }
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_none()
    }

    pub fn push_back<T>(&mut self, buf: &mut Buffer<T>, value: T) {
        let key = buf.slab.insert(Slot { value, next: None });

        match self.indices {
            Some(ref mut idxs) => {
                buf.slab[idxs.tail].next = Some(key);
                idxs.tail = key;
            }
            None => {
                self.indices = Some(Indices {
                    head: key,
                    tail: key,
                });
            }
        }
    }

    pub fn push_front<T>(&mut self, buf: &mut Buffer<T>, value: T) {
        let key = buf.slab.insert(Slot { value, next: None });

        match self.indices {
            Some(ref mut idxs) => {
                buf.slab[key].next = Some(idxs.head);
                idxs.head = key;
            }
            None => {
                self.indices = Some(Indices {
                    head: key,
                    tail: key,
                });
            }
        }
    }

    pub fn pop_front<T>(&mut self, buf: &mut Buffer<T>) -> Option<T> {
        match self.indices {
            Some(mut idxs) => {
                let mut slot = buf.slab.remove(idxs.head);
                buf.release_slots();

                if idxs.head == idxs.tail {
                    assert!(slot.next.is_none());
                    self.indices = None;
                } else {
                    idxs.head = slot.next.take().unwrap();
                    self.indices = Some(idxs);
                }

                Some(slot.value)
            }
            None => None,
        }
    }
}

/// xray-rust: the slots a drained buffer keeps.
#[cfg(test)]
mod tests {
    use super::*;

    /// A buffer that queued many frames and was drained gives their slots
    /// back, keeping at most 4 KiB of them; one that queued a few keeps them.
    #[test]
    fn a_drained_buffer_gives_its_slots_back() {
        let slot = std::mem::size_of::<Slot<[u8; 200]>>();
        let mut buf: Buffer<[u8; 200]> = Buffer::new();
        let mut deque = Deque::new();
        for _ in 0..512 {
            deque.push_back(&mut buf, [0; 200]);
        }
        while deque.pop_front(&mut buf).is_some() {}
        assert!(buf.is_empty());
        let kept = buf.slab.capacity() * slot;
        assert!(kept <= 4 * 1024, "a drained buffer keeps {} B of slots", kept);

        for _ in 0..4 {
            deque.push_back(&mut buf, [0; 200]);
        }
        let capacity = buf.slab.capacity();
        while deque.pop_front(&mut buf).is_some() {}
        assert_eq!(buf.slab.capacity(), capacity, "a few slots are kept");
    }
}

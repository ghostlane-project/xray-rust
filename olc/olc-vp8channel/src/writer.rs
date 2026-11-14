// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The paced writer: `writerState` and `writerLoop` (`vp8channel/writer.go`
//! at 2d4266af). Each frame interval it writes, in Go's order:
//!
//! 1. a bare keyframe header every two seconds, or soon after a relay
//!    asked for one ([`Writer::force_keepalive`]);
//! 2. every queued control frame;
//! 3. the queued datagrams, those to the same peer batched as OLUB;
//! 4. one data sample through the [`DataLane`], or a bare header after
//!    100 ms with nothing to send.

use std::collections::VecDeque;

use crate::conn::{Packet, Plane};
use crate::lane::{DataLane, LaneParams};
use crate::wire::{
    append_batch_packet, same_epoch_header, EpochHeader, DATAGRAM_BATCH_MAGIC, EPOCH_HDR_LEN,
    MAX_PAYLOAD_SIZE,
};

/// `keepaliveIdlePeriod`, ns.
pub const KEEPALIVE_IDLE: i64 = 100_000_000;
/// `forceKeepalivePeriod`, ns.
pub const FORCE_KEEPALIVE: i64 = 2_000_000_000;
/// `keyframeRequestGap`, ns.
pub const KEYFRAME_REQUEST_GAP: i64 = 100_000_000;
/// `datagramQueueSize`.
pub const DATAGRAM_QUEUE: usize = 4096;

/// Where samples go: the track (`writeSampleLocked`, and
/// `writeKeyframeLocked` with `keyframe`). `true` when it took the sample.
pub trait SampleSink {
    /// Writes one sample.
    fn write(&mut self, sample: &[u8], keyframe: bool) -> bool;
}

impl<F: FnMut(&[u8], bool) -> bool> SampleSink for F {
    fn write(&mut self, sample: &[u8], keyframe: bool) -> bool {
        self(sample, keyframe)
    }
}

/// What one tick works on.
pub struct Tick<'a> {
    /// The control plane: its queue is drained whole.
    pub control: &'a mut Plane,
    /// The data plane, through the lane.
    pub data: &'a mut Plane,
    /// The lossy datagram frames.
    pub datagram: &'a mut VecDeque<Vec<u8>>,
    /// The transport's numbers.
    pub params: &'a LaneParams,
    /// `epochHeader()`: the data epoch, broadcast.
    pub keepalive: EpochHeader,
    /// A relay asked for a keyframe (`keyframeWanted`).
    pub keyframe_wanted: &'a mut bool,
    /// The track.
    pub sink: &'a mut dyn SampleSink,
    /// Now, on the channel's clock.
    pub now: i64,
}

/// `writerState`.
#[derive(Debug)]
pub struct Writer {
    keepalive_every: i64,
    idle_ticks: i64,
    force_keepalive_every: i64,
    ticks_since_keepalive: i64,
    keyframe_gap: i64,
    pending_control: Option<Packet>,
    /// The data lane.
    pub data: DataLane,
    pending_datagram: Option<Vec<u8>>,
}

impl Writer {
    /// `newWriterState` for a writer ticking every `frame_interval` ns.
    #[must_use]
    pub fn new(frame_interval: i64) -> Self {
        Self {
            keepalive_every: (KEEPALIVE_IDLE / frame_interval).max(1),
            idle_ticks: 0,
            force_keepalive_every: (FORCE_KEEPALIVE / frame_interval).max(1),
            ticks_since_keepalive: 0,
            keyframe_gap: (KEYFRAME_REQUEST_GAP / frame_interval).max(1),
            pending_control: None,
            data: DataLane::new("data"),
            pending_datagram: None,
        }
    }

    /// The datagram held for the next sample (`pendingDatagram`): one that
    /// failed its write, or the first of another route.
    #[must_use]
    pub fn pending_datagram(&self) -> Option<&[u8]> {
        self.pending_datagram.as_deref()
    }

    /// One tick of `writerLoop`.
    pub fn tick(&mut self, t: &mut Tick<'_>) {
        self.force_keepalive(t);
        if !self.drain_control(t) {
            return;
        }
        if !self.drain_datagram(t) {
            return;
        }
        self.drain_data(t);
    }

    /// `forceKeepalive`.
    fn force_keepalive(&mut self, t: &mut Tick<'_>) {
        self.ticks_since_keepalive += 1;
        let mut due = self.ticks_since_keepalive >= self.force_keepalive_every;
        if !due && self.ticks_since_keepalive >= self.keyframe_gap && *t.keyframe_wanted {
            due = true;
        }
        if !due {
            return;
        }
        *t.keyframe_wanted = false;
        self.ticks_since_keepalive = 0;
        let _ = t.sink.write(&t.keepalive, true);
    }

    /// `drainControl`: false when a frame failed and waits for the next tick.
    fn drain_control(&mut self, t: &mut Tick<'_>) -> bool {
        if let Some(p) = self.pending_control.take() {
            if !t.sink.write(&p.data, false) {
                self.pending_control = Some(p);
                return false;
            }
            t.control.release(p.data);
        }
        while let Some(frame) = t.control.out.pop_front() {
            self.idle_ticks = 0;
            if !t.sink.write(&frame.data, false) {
                self.pending_control = Some(frame);
                return false;
            }
            t.control.release(frame.data);
        }
        true
    }

    /// `drainDatagram`: false when a sample waits for the next tick.
    fn drain_datagram(&mut self, t: &mut Tick<'_>) -> bool {
        if let Some(s) = self.pending_datagram.take() {
            if !t.sink.write(&s, false) {
                self.pending_datagram = Some(s);
                return false;
            }
        }
        while let Some(frame) = t.datagram.pop_front() {
            let sample = self.batch_datagram_sample_from(t.datagram, frame, t.params.batch_size);
            self.idle_ticks = 0;
            if !t.sink.write(&sample, false) {
                self.pending_datagram = Some(sample);
                return false;
            }
        }
        true
    }

    /// `batchDatagramSampleFrom`: `first` and the datagrams behind it with
    /// the same header in one OLUB sample. One bound elsewhere, or one that
    /// no longer fits, waits as the pending datagram.
    pub fn batch_datagram_sample_from(
        &mut self,
        src: &mut VecDeque<Vec<u8>>,
        first: Vec<u8>,
        batch_size: usize,
    ) -> Vec<u8> {
        if first.len() <= EPOCH_HDR_LEN || batch_size <= 1 {
            return first;
        }
        let mut sample = Vec::with_capacity(MAX_PAYLOAD_SIZE);
        sample.extend_from_slice(&first[..EPOCH_HDR_LEN]);
        sample.extend_from_slice(&DATAGRAM_BATCH_MAGIC);
        append_batch_packet(&mut sample, &first[EPOCH_HDR_LEN..]);
        for packets in 1..batch_size {
            let Some(frame) = src.pop_front() else {
                if packets == 1 {
                    return first;
                }
                return sample;
            };
            if !same_epoch_header(&first, &frame) {
                self.pending_datagram = Some(frame);
                return sample;
            }
            let payload = &frame[EPOCH_HDR_LEN..];
            if sample.len() + 2 + payload.len() > MAX_PAYLOAD_SIZE {
                self.pending_datagram = Some(frame);
                return sample;
            }
            append_batch_packet(&mut sample, payload);
        }
        sample
    }

    /// `drainData`: one data sample, or a keepalive when idle.
    fn drain_data(&mut self, t: &mut Tick<'_>) {
        let sink = &mut *t.sink;
        let mut write = |s: &[u8]| sink.write(s, false);
        if self.data.flush(t.data, t.params, t.now, &mut write) {
            self.idle_ticks = 0;
            return;
        }
        if self.data.held_back {
            return;
        }
        self.idle_ticks += 1;
        if self.idle_ticks >= self.keepalive_every {
            self.idle_ticks = 0;
            let _ = t.sink.write(&t.keepalive, false);
        }
    }

    /// `releasePending`: what the writer carried over, back to the planes.
    pub fn release(&mut self, control: &mut Plane, data: &mut Plane) {
        if let Some(p) = self.pending_control.take() {
            control.release(p.data);
        }
        self.data.release(data);
        self.pending_datagram = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{datagram_frame, epoch_header, split_datagram_batch_payload};
    use olc_kcp::Config;
    use std::time::Instant;

    struct Rig {
        control: Plane,
        data: Plane,
        datagram: VecDeque<Vec<u8>>,
        params: LaneParams,
        wanted: bool,
        written: Vec<(Vec<u8>, bool)>,
        refuse: usize,
    }

    impl Rig {
        fn new() -> Self {
            let now = Instant::now();
            let mut control = Plane::new(2048, false, Config::vp8channel_constrained(), now);
            let mut data = Plane::new(1024, true, Config::vp8channel_constrained(), now);
            control.start(epoch_header(1, 0x8000_0002, 0), now);
            data.start(epoch_header(1, 2, 0), now);
            Self {
                control,
                data,
                datagram: VecDeque::new(),
                params: LaneParams::new(1_000_000_000 / 60, 64, 512),
                wanted: false,
                written: Vec::new(),
                refuse: 0,
            }
        }

        fn tick(&mut self, w: &mut Writer, now: i64) {
            let (written, refuse) = (&mut self.written, &mut self.refuse);
            let mut sink = |s: &[u8], k: bool| {
                if *refuse > 0 {
                    *refuse -= 1;
                    return false;
                }
                written.push((s.to_vec(), k));
                true
            };
            let mut t = Tick {
                control: &mut self.control,
                data: &mut self.data,
                datagram: &mut self.datagram,
                params: &self.params,
                keepalive: epoch_header(1, 2, 0),
                keyframe_wanted: &mut self.wanted,
                sink: &mut sink,
                now,
            };
            w.tick(&mut t);
        }
    }

    #[test]
    fn the_counts_follow_the_frame_interval() {
        let w = Writer::new(1_000_000_000 / 60);
        assert_eq!(
            (w.keepalive_every, w.force_keepalive_every, w.keyframe_gap),
            (6, 120, 6)
        );
        let w = Writer::new(1_000_000_000 / 30);
        assert_eq!(
            (w.keepalive_every, w.force_keepalive_every, w.keyframe_gap),
            (3, 60, 3)
        );
        let w = Writer::new(1_000_000_000);
        assert_eq!(
            (w.keepalive_every, w.force_keepalive_every, w.keyframe_gap),
            (1, 2, 1)
        );
    }

    #[test]
    fn an_idle_writer_sends_keepalives_and_a_keyframe_every_two_seconds() {
        let mut r = Rig::new();
        let mut w = Writer::new(1_000_000_000 / 60);
        for i in 0..240 {
            r.tick(&mut w, 1 + i * 16_666_666);
        }
        let keyframes = r.written.iter().filter(|(_, k)| *k).count();
        let keepalives = r.written.iter().filter(|(_, k)| !*k).count();
        assert_eq!(keyframes, 2);
        assert_eq!(keepalives, 40, "one every six idle ticks");
        assert!(r.written.iter().all(|(s, _)| s == &epoch_header(1, 2, 0)));
    }

    #[test]
    fn a_keyframe_request_is_answered_after_the_gap() {
        let mut r = Rig::new();
        let mut w = Writer::new(1_000_000_000 / 60);
        r.wanted = true;
        for i in 0..6 {
            r.tick(&mut w, 1 + i);
        }
        assert_eq!(
            r.written.iter().filter(|(_, k)| *k).count(),
            1,
            "on the sixth tick"
        );
        assert!(!r.wanted);
    }

    #[test]
    fn control_then_datagrams_then_data_and_a_failed_control_frame_blocks_the_tick() {
        // datagram_test.go:203, :230
        let mut r = Rig::new();
        let mut w = Writer::new(1_000_000_000 / 60);
        let now = Instant::now();
        r.control.send(b"ctl", now, 1).unwrap();
        r.data.send(b"data", now, 1).unwrap();
        r.datagram
            .push_back(datagram_frame(&epoch_header(1, 2, 9), b"dg").unwrap());
        r.refuse = 1;
        r.tick(&mut w, 1);
        assert!(
            r.written.is_empty(),
            "the refused control frame holds the tick"
        );
        r.tick(&mut w, 2);
        let srcs: Vec<u32> = r
            .written
            .iter()
            .map(|(s, _)| u32::from_be_bytes(s[24..28].try_into().unwrap()))
            .collect();
        assert_eq!(srcs, [0x8000_0002, 2, 2], "control, datagram, data");
        assert_eq!(
            &r.written[1].0[36..40],
            b"OLUD",
            "a lone datagram goes as it is"
        );
        assert_eq!(&r.written[2].0[36..40], b"OLKB");
    }

    #[test]
    fn datagrams_to_one_peer_batch_and_other_routes_wait() {
        // datagram_test.go:255, :281
        let mut w = Writer::new(1_000_000_000 / 60);
        let h1 = epoch_header(1, 2, 9);
        let h2 = epoch_header(1, 2, 10);
        let mut q: VecDeque<Vec<u8>> = [b"b".as_slice(), b"c"]
            .iter()
            .map(|d| datagram_frame(&h1, d).unwrap())
            .collect();
        q.push_back(datagram_frame(&h2, b"d").unwrap());
        let first = datagram_frame(&h1, b"a").unwrap();
        let s = w.batch_datagram_sample_from(&mut q, first, 64);
        let parts = split_datagram_batch_payload(&s[36..]).unwrap();
        assert_eq!(parts, [&b"OLUDa"[..], b"OLUDb", b"OLUDc"]);
        assert_eq!(
            w.pending_datagram.as_deref(),
            Some(&datagram_frame(&h2, b"d").unwrap()[..])
        );
        assert!(q.is_empty());
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The data lane: `vp8channel/lane.go` at 2d4266af (issue #12).
//!
//! It carries the reliable data queue to the track, a sample a tick, and
//! watches the pushes it writes against the acknowledgements its conn
//! receives. While the peer acknowledges nothing for [`DEFAULT_BLACKOUT_AFTER`]
//! it has the conn hold pushes back (a probe every [`DEFAULT_PROBE_EVERY`]),
//! so an SFU that stopped forwarding an over-budget stream can take it
//! back; once the peer answers again it writes at most half of what it was
//! writing ([`Pace`]) and grows back. On a lossy path it shrinks its frames
//! ([`FrameCap`]).

use crate::conn::{Packet, Plane};
use crate::frames::{stamps_of, FrameCap, Verdict};
use crate::log::info;
use crate::pace::{Pace, DEFAULT_GROW_EVERY};
use crate::segment::answers;
use crate::wire::{
    append_batch_packet, split_kcp_payload, BATCH_LEN_LEN, EPOCH_HDR_LEN, KCP_BATCH_MAGIC, KCP_MTU,
    MAX_PAYLOAD_SIZE, WIRE_CRC_LEN,
};

/// `defaultBlackoutAfter`: pushes unanswered this long make the path dark.
pub const DEFAULT_BLACKOUT_AFTER: i64 = 3_000_000_000;
/// `defaultProbeEvery`: a dark lane lets one resent push through this often.
pub const DEFAULT_PROBE_EVERY: i64 = 250_000_000;
/// `capQueue`: how long KCP's window takes to go out at a capped pace.
pub const CAP_QUEUE: i64 = 300_000_000;
/// `minCapWindow`: the fewest segments a capped lane keeps in flight.
pub const MIN_CAP_WINDOW: usize = 32;

/// What the lane reads off its transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneParams {
    /// `blackoutAfter`, ns.
    pub blackout_after: i64,
    /// `probeEvery`, ns.
    pub probe_every: i64,
    /// `growEvery`, ns.
    pub grow_every: i64,
    /// `sendWindow`: the transport's KCP send window, the ceiling.
    pub send_window: usize,
    /// `frameInterval`, ns.
    pub frame_interval: i64,
    /// `batchSize`.
    pub batch_size: usize,
}

impl LaneParams {
    /// The defaults for a transport at `fps` with `batch` packets a sample.
    #[must_use]
    pub fn new(frame_interval: i64, batch_size: usize, send_window: usize) -> Self {
        Self {
            blackout_after: DEFAULT_BLACKOUT_AFTER,
            probe_every: DEFAULT_PROBE_EVERY,
            grow_every: DEFAULT_GROW_EVERY,
            send_window,
            frame_interval,
            batch_size,
        }
    }

    /// `fullRate`: a full sample every frame, bytes per second.
    #[must_use]
    pub fn full_rate(&self) -> f64 {
        let sample =
            (self.batch_size * (EPOCH_HDR_LEN + KCP_MTU + WIRE_CRC_LEN)).min(MAX_PAYLOAD_SIZE);
        #[allow(clippy::cast_precision_loss)]
        let r = sample as f64 * 1e9 / self.frame_interval as f64;
        r
    }

    /// `fullPackets`: KCP packets an uncapped sample carries.
    #[must_use]
    pub fn full_packets(&self) -> usize {
        let room = (MAX_PAYLOAD_SIZE - EPOCH_HDR_LEN - KCP_BATCH_MAGIC.len())
            / (BATCH_LEN_LEN + KCP_MTU + WIRE_CRC_LEN);
        self.batch_size.min(room).max(1)
    }

    /// `canBatch`.
    #[must_use]
    pub fn can_batch(&self, frame: &[u8]) -> bool {
        frame.len() > EPOCH_HDR_LEN && self.batch_size > 1
    }
}

/// Go's `time.Duration.Round(time.Millisecond).String()` for a span of
/// nanoseconds.
#[must_use]
pub fn go_millis(ns: i64) -> String {
    let ms = (ns + 500_000) / 1_000_000;
    if ms == 0 {
        return "0s".into();
    }
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let (m, rest) = (ms / 60_000, ms % 60_000);
    let secs = if rest % 1000 == 0 {
        format!("{}", rest / 1000)
    } else {
        let s = format!("{}.{:03}", rest / 1000, rest % 1000);
        s.trim_end_matches('0').to_owned()
    };
    if m == 0 {
        format!("{secs}s")
    } else {
        format!("{m}m{secs}s")
    }
}

/// `dataLane`.
#[derive(Debug, Default)]
pub struct DataLane {
    /// The packet carried over from the last batch (`pending`).
    pub pending: Option<Packet>,
    batch_buf: Vec<u8>,
    ack_pending: Option<Packet>,
    ack_buf: Vec<u8>,
    seen: Option<u64>,
    push_since: i64,
    dark_since: i64,
    dark_rate: f64,
    /// The cap after a dark spell.
    pub pace: Pace,
    /// The cap on a lossy path.
    pub frames: FrameCap,
    /// The last flush had a frame and held it (`heldBack`).
    pub held_back: bool,
    name: &'static str,
}

/// What a lane writes samples with: `true` when the sample went out.
pub type Write<'a> = dyn FnMut(&[u8]) -> bool + 'a;

impl DataLane {
    /// A lane named `name` in the log.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }

    /// Whether the lane counts its path dark.
    #[must_use]
    pub fn dark(&self) -> bool {
        self.dark_since != 0
    }

    /// `flush`: this tick's data; whether a sample went out.
    pub fn flush(
        &mut self,
        plane: &mut Plane,
        p: &LaneParams,
        now: i64,
        write: &mut Write<'_>,
    ) -> bool {
        if self.watch(plane, p, now) {
            plane.probe(now);
        } else if self.pace.grow(now, p.grow_every, p.full_rate()) {
            self.resize(plane, p);
            if self.pace.rate == 0.0 {
                self.frames.hand_back_to_frames();
            }
        }
        let acked = self.send_acks(plane, p, write);
        let sent = self.send(plane, p, now, write);
        if self.seen.is_some() {
            if let Some(rt) = plane.rt.as_mut() {
                let (share, verdict) = self.frames.judge(&mut rt.delivery, p.full_packets());
                #[allow(clippy::cast_possible_truncation)]
                let pct = (share * 100.0) as i64;
                match verdict {
                    Verdict::None => {}
                    Verdict::Frames => {
                        self.resize(plane, p);
                        info!(
                            "vp8channel: {}: {}% of pushed packets answered, {}",
                            self.name,
                            pct,
                            self.frame_note()
                        );
                    }
                    Verdict::Rate => {
                        let rate = share * self.pace.sent_rate(now);
                        self.pace.cut_to(rate, now);
                        self.resize(plane, p);
                        info!(
                            "vp8channel: {}: {}% answered, smaller frames lift none - pacing at delivered: at most {} KiB/s",
                            self.name,
                            pct,
                            kib(self.pace.rate)
                        );
                    }
                    Verdict::RateCut => {
                        let rate = share * self.pace.sent_rate(now);
                        self.pace.cut_to(rate, now);
                        self.resize(plane, p);
                        info!(
                            "vp8channel: {}: {}% answered over the pace - cut to what is delivered: at most {} KiB/s",
                            self.name,
                            pct,
                            kib(self.pace.rate)
                        );
                    }
                }
            }
        }
        sent || acked
    }

    fn frame_note(&self) -> String {
        if self.frames.limit == 0 {
            "full frames again".into()
        } else {
            format!("at most {} packets a frame from now", self.frames.limit)
        }
    }

    /// `sendAcks`: what only acknowledges the peer, one sample, uncapped.
    fn send_acks(&mut self, plane: &mut Plane, p: &LaneParams, write: &mut Write<'_>) -> bool {
        let first = match self.ack_pending.take() {
            Some(f) => f,
            None => match plane
                .acks
                .as_mut()
                .and_then(std::collections::VecDeque::pop_front)
            {
                Some(f) => f,
                None => return false,
            },
        };
        if !p.can_batch(&first.data) {
            let _ = write(&first.data);
            plane.release(first.data);
            return true;
        }
        let buf = std::mem::take(&mut self.ack_buf);
        let Some(acks) = plane.acks.as_mut() else {
            return false;
        };
        let (sample, pending, freed) = batch_sample_up_to(acks, first, buf, p, p.batch_size);
        for b in freed {
            plane.release(b);
        }
        self.ack_pending = pending;
        let _ = write(&sample);
        self.ack_buf = sample;
        true
    }

    /// `watch`: whether pushes have gone unanswered for the blackout.
    fn watch(&mut self, plane: &mut Plane, p: &LaneParams, now: i64) -> bool {
        let id = plane.rt.as_ref().map(|c| c.id);
        if id != self.seen {
            self.seen = id;
            self.push_since = 0;
            self.dark_since = 0;
            self.pace = Pace::default();
            self.frames = FrameCap::default();
        }
        let Some(rt) = plane.rt.as_mut() else {
            return false;
        };
        if self.push_since != 0 && rt.last_ack >= self.push_since {
            self.push_since = 0;
        }
        let dark = self.push_since != 0 && now - self.push_since >= p.blackout_after;
        if dark && self.dark_since == 0 {
            self.dark_since = now;
            self.dark_rate = self.pace.sent_rate(now);
            rt.hold(p.probe_every);
            self.sift(plane);
            let mut frames = String::new();
            if self.frames.halve(p.full_packets()) {
                self.resize(plane, p);
                frames = format!(", {}", self.frame_note());
            }
            info!(
                "vp8channel: {}: nothing acknowledged for {}, holding pushes back until the peer answers{}",
                self.name,
                go_millis(now - self.push_since),
                frames
            );
        } else if !dark && self.dark_since != 0 {
            rt.hold(0);
            self.settle(plane, p, now);
            self.dark_since = 0;
            self.frames.forget();
        }
        dark
    }

    /// `settle`: a spell of half the blackout or longer was an SFU that
    /// stopped forwarding: the lane goes on at half of what it wrote.
    fn settle(&mut self, plane: &mut Plane, p: &LaneParams, now: i64) {
        let held = now - self.dark_since;
        let mut after = String::new();
        if held >= p.blackout_after / 2 && self.pace.slow(now, self.dark_rate, p.full_rate()) {
            self.resize(plane, p);
            after = format!(", at most {} KiB/s from now", kib(self.pace.rate));
        }
        info!(
            "vp8channel: {}: the peer answers again after {} dark{}",
            self.name,
            go_millis(held),
            after
        );
    }

    /// `resize`: the send window to what the lane writes in [`CAP_QUEUE`] at
    /// the lower of its caps, never over the transport's own.
    fn resize(&self, plane: &mut Plane, p: &LaneParams) {
        let mut segments = p.send_window;
        let mut rate = self.pace.rate;
        if self.frames.limit > 0 {
            #[allow(clippy::cast_precision_loss)]
            let frame_rate = (self.frames.limit * KCP_MTU) as f64 * 1e9 / p.frame_interval as f64;
            if rate == 0.0 || frame_rate < rate {
                rate = frame_rate;
            }
        }
        if rate > 0.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let w = ((rate * 0.3) as i64).max(0) as usize / KCP_MTU;
            segments = w.max(MIN_CAP_WINDOW).min(segments);
        }
        plane.set_window(segments);
    }

    /// `send`: the next queued packet, batched as far as the transport and
    /// the cap allow.
    fn send(&mut self, plane: &mut Plane, p: &LaneParams, now: i64, write: &mut Write<'_>) -> bool {
        let mut limit = if self.frames.limit == 0 {
            p.full_packets()
        } else {
            self.frames.limit
        };
        let allow = self.pace.allow(now);
        if allow >= 0 {
            if allow == 0 {
                let queued = self.pending.is_some() || !plane.out.is_empty();
                self.pace.held = self.pace.held || queued;
                self.held_back = queued;
                return false;
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let by_credit = (allow as usize / KCP_MTU).max(1);
            limit = by_credit.min(limit);
        }
        let Some(frame) = self.take_fresh(plane, now) else {
            self.held_back = false;
            return false;
        };
        // No publish limiter on the carriers this client rides (only the
        // generic LiveKit engine polices one, olcrtc#26): readyToSend holds.
        let sent_len;
        let wrote_pushes;
        if p.can_batch(&frame.data) {
            let buf = std::mem::take(&mut self.batch_buf);
            let (sample, pending, freed) = batch_sample_up_to(&mut plane.out, frame, buf, p, limit);
            for b in freed {
                plane.release(b);
            }
            self.pending = pending;
            wrote_pushes = write(&sample) && self.note_pushes(plane, &sample);
            sent_len = sample.len();
            self.batch_buf = sample;
        } else {
            wrote_pushes = write(&frame.data) && self.note_pushes(plane, &frame.data);
            sent_len = frame.data.len();
            plane.release(frame.data);
        }
        if wrote_pushes && self.push_since == 0 {
            self.push_since = now;
        }
        self.held_back = false;
        self.pace.wrote(now, sent_len);
        self.pace.held = self.pace.held
            || (self.pace.rate > 0.0 && (self.pending.is_some() || !plane.out.is_empty()));
        true
    }

    /// `sift`: as the lane goes dark, drops the queued pushes and keeps what
    /// answers the peer; the last push dropped is the conn's first probe.
    fn sift(&mut self, plane: &mut Plane) {
        let mut keep = Vec::new();
        for _ in 0..=plane.out_cap {
            let Some(frame) = self.take(plane) else {
                break;
            };
            let n = frame.data.len();
            if n > EPOCH_HDR_LEN + WIRE_CRC_LEN && answers(&frame.data[EPOCH_HDR_LEN..]) {
                keep.push(frame);
                continue;
            }
            if n > EPOCH_HDR_LEN + WIRE_CRC_LEN {
                if let Some(rt) = plane.rt.as_mut() {
                    rt.keep_probe(&frame.data[EPOCH_HDR_LEN..n - WIRE_CRC_LEN]);
                }
            }
            plane.release(frame.data);
        }
        for frame in keep {
            if plane.out.len() < plane.out_cap {
                plane.out.push_back(frame);
            } else {
                plane.release(frame.data);
            }
        }
    }

    /// `takeFresh`: [`DataLane::take`] for a capped lane, dropping pushes
    /// that waited over twice [`CAP_QUEUE`].
    fn take_fresh(&mut self, plane: &mut Plane, now: i64) -> Option<Packet> {
        for _ in 0..=plane.out_cap {
            let frame = self.take(plane)?;
            if (self.pace.rate == 0.0 && self.frames.limit == 0)
                || now - frame.queued <= 2 * CAP_QUEUE
                || (frame.data.len() > EPOCH_HDR_LEN && answers(&frame.data[EPOCH_HDR_LEN..]))
            {
                return Some(frame);
            }
            plane.release(frame.data);
        }
        None
    }

    /// `take`: the carried-over packet or the next queued one.
    fn take(&mut self, plane: &mut Plane) -> Option<Packet> {
        self.pending.take().or_else(|| plane.out.pop_front())
    }

    /// `release`: the carried-over packets back to the pool.
    pub fn release(&mut self, plane: &mut Plane) {
        for p in [self.pending.take(), self.ack_pending.take()]
            .into_iter()
            .flatten()
        {
            plane.release(p.data);
        }
    }

    /// `notePushes`: counts the packets of a written sample that hold a
    /// push, for the frame cap; whether any did.
    fn note_pushes(&mut self, plane: &mut Plane, sample: &[u8]) -> bool {
        if sample.len() <= EPOCH_HDR_LEN {
            return false;
        }
        let (mut found, mut last) = (false, 0u32);
        let seen = self.seen.is_some();
        let mut rt = plane.rt.as_mut().filter(|_| seen);
        let frames = &mut self.frames;
        split_kcp_payload(&sample[EPOCH_HDR_LEN..], |packet| {
            if packet.len() < WIRE_CRC_LEN {
                return;
            }
            let st = stamps_of(&packet[..packet.len() - WIRE_CRC_LEN]);
            if st.pushed {
                if let Some(rt) = rt.as_mut() {
                    frames.pushed(&mut rt.delivery, st.push);
                }
            }
            found = found || st.pushed;
            if st.push != 0 {
                last = st.push;
            }
        });
        if found {
            if let Some(rt) = rt {
                FrameCap::wrote(&mut rt.delivery, last);
            }
        }
        found
    }
}

#[allow(clippy::cast_possible_truncation)]
fn kib(rate: f64) -> i64 {
    (rate as i64) >> 10
}

/// `batchSampleUpTo`: `first` and the packets queued behind it in one OLKB
/// sample of at most `limit` packets and [`MAX_PAYLOAD_SIZE`] bytes, into
/// `dst`'s buffer. Returns the sample, the packet that did not fit, and the
/// buffers it emptied (for the plane's free list).
pub fn batch_sample_up_to(
    src: &mut std::collections::VecDeque<Packet>,
    first: Packet,
    dst: Vec<u8>,
    p: &LaneParams,
    limit: usize,
) -> (Vec<u8>, Option<Packet>, Vec<Vec<u8>>) {
    if !p.can_batch(&first.data) {
        return (first.data, None, Vec::new());
    }
    let mut sample = prepare_batch_buffer(dst, src.len(), first.data.len(), limit);
    let mut freed = Vec::new();
    sample.extend_from_slice(&first.data[..EPOCH_HDR_LEN]);
    sample.extend_from_slice(&KCP_BATCH_MAGIC);
    append_batch_packet(&mut sample, &first.data[EPOCH_HDR_LEN..]);
    freed.push(first.data);
    for _ in 1..limit {
        let Some(frame) = src.pop_front() else {
            return (sample, None, freed);
        };
        if frame.data.len() <= EPOCH_HDR_LEN {
            freed.push(frame.data);
            continue;
        }
        let payload = &frame.data[EPOCH_HDR_LEN..];
        if sample.len() + BATCH_LEN_LEN + payload.len() > MAX_PAYLOAD_SIZE {
            return (sample, Some(frame), freed);
        }
        append_batch_packet(&mut sample, payload);
        freed.push(frame.data);
    }
    (sample, None, freed)
}

/// `prepareBatchBuffer`.
fn prepare_batch_buffer(
    mut dst: Vec<u8>,
    queued: usize,
    first_len: usize,
    limit: usize,
) -> Vec<u8> {
    let packet = first_len - EPOCH_HDR_LEN;
    let count = limit.min(queued + 1).max(1);
    let want = (EPOCH_HDR_LEN + KCP_BATCH_MAGIC.len() + count * (BATCH_LEN_LEN + packet))
        .min(MAX_PAYLOAD_SIZE);
    if dst.capacity() < want {
        return Vec::with_capacity(want);
    }
    dst.clear();
    dst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{epoch_header, split_kcp_payload};
    use olc_kcp::Config;
    use std::collections::VecDeque;
    use std::time::Instant;

    fn params() -> LaneParams {
        LaneParams::new(1_000_000_000 / 60, 64, 512)
    }

    fn pk(n: usize, queued: i64) -> Packet {
        let mut data = epoch_header(1, 2, 3).to_vec();
        data.extend(std::iter::repeat_n(0x5a, n));
        Packet { data, queued }
    }

    #[test]
    fn full_packets_and_rate_follow_the_sample_size() {
        let p = params();
        assert_eq!(p.full_packets(), 43, "a sample holds 43 packets, not 64");
        assert!((p.full_rate() - 61440.0 * 60.0).abs() < 1.0);
        assert_eq!(LaneParams::new(1, 1, 512).full_packets(), 1);
    }

    #[test]
    fn a_batch_carries_packets_up_to_the_limit_and_keeps_the_overflow() {
        // transport_test.go:114, :189
        let p = params();
        let mut q: VecDeque<Packet> = (0..3).map(|_| pk(1400, 0)).collect();
        let (s, pending, freed) = batch_sample_up_to(&mut q, pk(1400, 0), Vec::new(), &p, 64);
        assert!(pending.is_none() && q.is_empty() && freed.len() == 4);
        assert_eq!(&s[EPOCH_HDR_LEN..EPOCH_HDR_LEN + 4], b"OLKB");
        let mut n = 0;
        split_kcp_payload(&s[EPOCH_HDR_LEN..], |pkt| {
            assert_eq!(pkt.len(), 1400);
            n += 1;
        });
        assert_eq!(n, 4);

        let mut q: VecDeque<Packet> = (0..60).map(|_| pk(1400, 0)).collect();
        let (s, pending, _) = batch_sample_up_to(&mut q, pk(1400, 0), Vec::new(), &p, 64);
        assert!(s.len() <= MAX_PAYLOAD_SIZE);
        assert!(
            pending.is_some(),
            "the packet that did not fit is carried over"
        );
        assert_eq!(q.len(), 60 - 43);

        let mut q: VecDeque<Packet> = (0..10).map(|_| pk(100, 0)).collect();
        let (_, _, freed) = batch_sample_up_to(&mut q, pk(100, 0), Vec::new(), &p, 4);
        assert_eq!(
            (freed.len(), q.len()),
            (4, 7),
            "a capped lane asks for fewer"
        );

        // A header alone is no batch; one packet with a body is an OLKB of one.
        let (s, ..) = batch_sample_up_to(&mut VecDeque::new(), pk(0, 0), Vec::new(), &p, 64);
        assert_eq!(s.len(), EPOCH_HDR_LEN);
        let (s, ..) = batch_sample_up_to(&mut VecDeque::new(), pk(5, 0), Vec::new(), &p, 64);
        assert_eq!(&s[EPOCH_HDR_LEN..EPOCH_HDR_LEN + 4], b"OLKB");
    }

    #[test]
    fn go_durations() {
        assert_eq!(go_millis(250_000_000), "250ms");
        assert_eq!(go_millis(3_012_400_000), "3.012s");
        assert_eq!(go_millis(3_000_000_000), "3s");
        assert_eq!(go_millis(3_100_000_000), "3.1s");
        assert_eq!(go_millis(61_500_000_000), "1m1.5s");
        assert_eq!(go_millis(0), "0s");
    }

    fn data_plane(now: Instant) -> Plane {
        let mut pl = Plane::new(1024, true, Config::vp8channel_constrained(), now);
        pl.start(epoch_header(1, 2, 3), now);
        pl
    }

    /// A wrapped packet of one push stamped `ts` (the CRC is not read).
    fn push_packet(ts: u32) -> Packet {
        let mut data = epoch_header(1, 2, 3).to_vec();
        data.extend(crate::segment::tests::seg(
            crate::segment::CMD_PUSH,
            ts,
            1376,
        ));
        data.extend([0; 4]);
        Packet { data, queued: 0 }
    }

    #[test]
    fn going_dark_holds_pushes_and_keeps_probing_then_halves_the_pace() {
        // lane_test.go:301
        let now = Instant::now();
        let mut pl = data_plane(now);
        let p = params();
        let mut lane = DataLane::new("data");
        let written = std::cell::RefCell::new(Vec::new());
        let mut write = |s: &[u8]| {
            written.borrow_mut().push(s.len());
            true
        };
        let s = 1_000_000_000i64;
        let tick = s / 60;
        let mut t = 10 * s;
        // A loud lane: a full sample every tick for a second and a half.
        let mut ts = 0u32;
        while t < 10 * s + 3 * s / 2 {
            for _ in 0..43 {
                let mut pk = push_packet(ts);
                pk.queued = t;
                pl.out.push_back(pk);
            }
            ts += 16;
            lane.flush(&mut pl, &p, t, &mut write);
            t += tick;
        }
        assert!(!lane.dark());
        // Nothing comes back, KCP resends: three seconds after the first
        // push the lane counts its path dark.
        while !lane.dark() && t < 14 * s {
            for _ in 0..43 {
                pl.out.push_back(push_packet(ts));
            }
            lane.flush(&mut pl, &p, t, &mut write);
            t += tick;
        }
        assert!(t >= 13 * s, "dark before the blackout");
        assert!(lane.dark(), "dark after the blackout");
        assert!(pl.rt.as_ref().unwrap().holding());
        assert_eq!(lane.frames.limit, 21, "the frames halve as it goes dark");
        // While dark, a probe goes out each probe interval and no other push.
        let before = written.borrow().len();
        let end = t + 2 * s;
        while t < end {
            lane.flush(&mut pl, &p, t, &mut write);
            t += tick;
        }
        let probes = written.borrow().len() - before;
        assert!(
            (7..=9).contains(&probes),
            "{probes} samples in two dark seconds"
        );
        // An answer brings it back, at half of what it wrote.
        pl.rt.as_mut().unwrap().last_ack = t;
        lane.flush(&mut pl, &p, t, &mut write);
        assert!(!lane.dark());
        assert!(!pl.rt.as_ref().unwrap().holding());
        assert!(lane.pace.rate > 0.0, "a long spell halves the pace");
    }

    #[test]
    fn a_capped_lane_drops_stale_pushes_but_not_answers() {
        // lane_test.go:437
        let now = Instant::now();
        let mut pl = data_plane(now);
        let mut lane = DataLane::new("data");
        lane.pace.rate = 1e9;
        let mut ack = epoch_header(1, 2, 3).to_vec();
        let mut seg = crate::segment::tests::seg(crate::segment::CMD_ACK, 1, 0);
        seg.extend([0; 4]);
        ack.extend(seg);
        pl.out.push_back(pk(100, 0));
        pl.out.push_back(Packet {
            data: ack.clone(),
            queued: 0,
        });
        pl.out.push_back(pk(100, 10 * CAP_QUEUE));
        let t = 10 * CAP_QUEUE + 1;
        assert_eq!(
            lane.take_fresh(&mut pl, t).unwrap().data,
            ack,
            "a stale push is dropped"
        );
        assert_eq!(lane.take_fresh(&mut pl, t).unwrap().queued, 10 * CAP_QUEUE);
        assert!(lane.take_fresh(&mut pl, t).is_none());
    }

    #[test]
    fn the_lane_never_asks_for_more_window_than_the_transport_runs_with() {
        // lane_test.go:414
        let now = Instant::now();
        let mut pl = data_plane(now);
        let p = params();
        let mut lane = DataLane::new("data");
        lane.pace.rate = 1e12;
        lane.resize(&mut pl, &p);
        assert_eq!(pl.rt.as_ref().unwrap().sess.kcp().snd_wnd(), 512);
        lane.pace.rate = 1.0;
        lane.resize(&mut pl, &p);
        assert_eq!(
            pl.rt.as_ref().unwrap().sess.kcp().snd_wnd(),
            MIN_CAP_WINDOW as u32
        );
        lane.pace.rate = 0.0;
        lane.frames.limit = 10;
        lane.resize(&mut pl, &p);
        // 10 packets a frame at 60 fps: 840 KB/s, 252 KB in 300 ms: 180.
        assert_eq!(pl.rt.as_ref().unwrap().sess.kcp().snd_wnd(), 180);
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The frame size a data lane keeps on a path that loses packets:
//! `vp8channel/frames.go` at 2d4266af (issue #12).
//!
//! A frame reaches the peer only when every RTP packet of it does, so on a
//! path that loses one packet in twenty-five a full frame of fifty is lost
//! seven times in eight, and every KCP segment in it. The lane counts the
//! packets with a push it writes and the acknowledgements that come back
//! for them ([`DeliveryTrack`]), and [`FrameCap`] shrinks the frames until
//! about [`AIM_SHARE`] of them get through, or hands the lane's rate to
//! [`crate::pace`] when the loss follows the rate instead.

use crate::segment::{read_u32_le, CMD_ACK, CMD_OFF, CMD_PUSH, LEN_OFF, OVERHEAD, TS_OFF};

/// `deliveryBucketMs`: milliseconds of KCP timestamps per bucket.
pub const DELIVERY_BUCKET_MS: i64 = 250;
/// `minJudgedPushes`: the fewest pushed packets a judgement rests on.
pub const MIN_JUDGED_PUSHES: i64 = 64;
/// `minJudgedFrames`: the fewest frames they came in.
pub const MIN_JUDGED_FRAMES: i64 = 24;
/// `minFramePackets`: the fewest KCP packets a capped lane puts in a frame.
pub const MIN_FRAME_PACKETS: usize = 4;
/// `darkShare`: under it next to nothing got through (a dark path).
pub const DARK_SHARE: f64 = 0.02;
/// `lossyShare`: two readings under it in a row shrink the frames.
pub const LOSSY_SHARE: f64 = 0.25;
/// `aimShare`: what a shrink aims to bring back, a little over 1/e.
pub const AIM_SHARE: f64 = 0.40;
/// `frameGrowBuckets`: buckets between two raises of a clean lane's cap.
pub const FRAME_GROW_BUCKETS: i64 = 8;
/// `rateGain`: a shrink that buys less than this of the predicted lift
/// reads as rate loss.
pub const RATE_GAIN: f64 = 0.6;
/// `rateSuspects`: judgements in a row that read like rate loss.
pub const RATE_SUSPECTS: i32 = 2;
/// `rateCutShare`: while pace owns the rate, readings under it (twice)
/// cut the rate again. (`rateHealthyShare`, 0.85, is declared in Go and
/// read nowhere.)
pub const RATE_CUT_SHARE: f64 = 0.6;

const BUCKETS: usize = 32;

/// `stampClock`: kcp-go's u32 millisecond stamps as a count that keeps
/// rising, each read as the signed difference from the newest seen.
#[derive(Debug, Clone, Copy, Default)]
pub struct StampClock {
    newest: i64,
    seen: bool,
}

impl StampClock {
    /// `unwrap`.
    pub fn unwrap(&mut self, ts: u32) -> i64 {
        if !self.seen {
            self.newest = i64::from(ts);
            self.seen = true;
            return self.newest;
        }
        // Go: uint32(c.newest) truncates, int32(...) is the signed difference.
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let diff = ts.wrapping_sub(self.newest as u32) as i32;
        let at = self.newest + i64::from(diff);
        self.newest = self.newest.max(at);
        at
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DeliveryBucket {
    id: i64,
    pushes: i64,
    acks: i64,
    frames: i64,
}

/// `deliveryTrack`: pushes sent and acknowledgements back, both under the
/// timestamp of the packet's last push (an acknowledgement echoes it).
#[derive(Debug, Clone, Default)]
pub struct DeliveryTrack {
    clock: StampClock,
    buckets: [DeliveryBucket; BUCKETS],
    newest_ack: i64,
}

impl DeliveryTrack {
    /// `count`: adds under the push timestamp `ts`, returns its bucket. An
    /// acknowledgement for a bucket already judged or reused is dropped.
    pub fn count(&mut self, ts: u32, pushes: i64, acks: i64, frames: i64) -> i64 {
        let id = self.clock.unwrap(ts) / DELIVERY_BUCKET_MS + 1;
        if acks > 0 && id > self.newest_ack {
            self.newest_ack = id;
        }
        // Go indexes by id % 32, which a negative id (a stamp from before
        // the session's first) would make panic; rem_euclid keeps it in range.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let b = &mut self.buckets[id.rem_euclid(BUCKETS as i64) as usize];
        if b.id != id {
            if pushes == 0 || id < b.id {
                return id;
            }
            *b = DeliveryBucket {
                id,
                ..DeliveryBucket::default()
            };
        }
        b.pushes += pushes;
        b.acks += acks;
        b.frames += frames;
        id
    }

    /// `take`: clears the buckets before the newest acknowledged one and
    /// returns the counts of those from `from` on.
    pub fn take(&mut self, from: i64) -> (i64, i64, i64) {
        let before = self.newest_ack;
        if before == 0 {
            return (0, 0, 0);
        }
        let (mut pushes, mut acks, mut frames) = (0, 0, 0);
        for b in &mut self.buckets {
            if b.id == 0 || b.id >= before {
                continue;
            }
            if b.id >= from {
                pushes += b.pushes;
                acks += b.acks;
                frames += b.frames;
            }
            *b = DeliveryBucket::default();
        }
        (pushes, acks, frames)
    }
}

/// `capVerdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing changes.
    None,
    /// The frame cap changed: the lane resizes its window.
    Frames,
    /// The loss follows the lane's rate: pace takes it at what was delivered.
    Rate,
    /// A cut of that rate after an overrun.
    RateCut,
}

/// `frameCap`: the most KCP packets a data lane puts in one frame.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameCap {
    /// The cap, 0 for none.
    pub limit: usize,
    newest: i64,
    since: i64,
    grown_at: i64,
    pushes: i64,
    acks: i64,
    frames: i64,
    lossy: bool,
    /// The lane's rate is pace's: the frames run full.
    pub rate_kept: bool,
    suspects: i32,
    pred_share: f64,
    pred_limit: usize,
    pred_ready: bool,
}

fn or(a: usize, b: usize) -> usize {
    if a == 0 {
        b
    } else {
        a
    }
}

impl FrameCap {
    /// `pushed`: a packet with a push went out under `ts`.
    pub fn pushed(&mut self, track: &mut DeliveryTrack, ts: u32) {
        self.newest = track.count(ts, 1, 0, 0);
    }

    /// `wrote`: the frame those pushes went out in, under its last stamp.
    pub fn wrote(track: &mut DeliveryTrack, ts: u32) {
        track.count(ts, 0, 0, 1);
    }

    /// `forget`: drops the evidence and what was pushed before now.
    pub fn forget(&mut self) {
        self.pushes = 0;
        self.acks = 0;
        self.frames = 0;
        self.lossy = false;
        self.since = self.newest + 1;
        self.suspects = 0;
        self.pred_ready = false;
    }

    /// `halve`: as the lane goes dark; reports whether the cap changed.
    pub fn halve(&mut self, full: usize) -> bool {
        if self.rate_kept {
            return false;
        }
        let limit = (or(self.limit, full) / 2).max(MIN_FRAME_PACKETS);
        let changed = limit != self.limit;
        self.limit = limit;
        self.grown_at = self.newest;
        self.forget();
        changed
    }

    /// `judge`: the share answered and what to do.
    pub fn judge(&mut self, track: &mut DeliveryTrack, full: usize) -> (f64, Verdict) {
        let (pushes, acks, frames) = track.take(self.since);
        self.pushes += pushes;
        self.acks += acks;
        self.frames += frames;
        if self.pushes < MIN_JUDGED_PUSHES || self.frames < MIN_JUDGED_FRAMES {
            return (0.0, Verdict::None);
        }
        #[allow(clippy::cast_precision_loss)]
        let share = self.acks as f64 / self.pushes as f64;
        self.pushes = 0;
        self.acks = 0;
        self.frames = 0;
        if self.rate_kept {
            return self.judge_kept(share);
        }
        self.judge_frames(share, full)
    }

    fn judge_frames(&mut self, share: f64, full: usize) -> (f64, Verdict) {
        let lossy_before = self.lossy;
        self.lossy = (DARK_SHARE..LOSSY_SHARE).contains(&share);
        let mut limit = self.limit;
        if share < DARK_SHARE {
            self.suspects = 0;
            self.pred_ready = false;
            return (share, Verdict::None);
        } else if self.lossy && lossy_before {
            if self.suspects >= RATE_SUSPECTS {
                self.hand_rate_to_pace();
                return (share, Verdict::Rate);
            }
            if self.pred_ready && limit > 0 {
                #[allow(clippy::cast_precision_loss)]
                let predicted = self.pred_share.powf(limit as f64 / self.pred_limit as f64);
                if share < predicted * RATE_GAIN {
                    self.suspects += 1;
                } else {
                    self.suspects = 0;
                }
            }
            self.pred_share = share;
            self.pred_limit = or(limit, full);
            self.pred_ready = true;
            limit = shrunk(or(limit, full), share);
        } else if limit > 0 && !self.lossy && self.newest - self.grown_at >= FRAME_GROW_BUCKETS {
            limit += (limit / 4).max(1);
            if limit >= full {
                limit = 0;
            }
            self.suspects = 0;
            self.pred_ready = false;
        }
        if limit == self.limit {
            return (share, Verdict::None);
        }
        self.limit = limit;
        self.since = self.newest + 1;
        self.grown_at = self.newest;
        (share, Verdict::Frames)
    }

    fn judge_kept(&mut self, share: f64) -> (f64, Verdict) {
        if share < DARK_SHARE {
            return (share, Verdict::None);
        }
        if share < RATE_CUT_SHARE {
            self.suspects += 1;
            if self.suspects >= RATE_SUSPECTS {
                self.suspects = 0;
                return (share, Verdict::RateCut);
            }
        } else {
            self.suspects = 0;
        }
        (share, Verdict::None)
    }

    fn hand_rate_to_pace(&mut self) {
        self.rate_kept = true;
        self.limit = 0;
        self.lossy = false;
        self.suspects = 0;
        self.pred_ready = false;
        self.pushes = 0;
        self.acks = 0;
        self.frames = 0;
        self.since = self.newest + 1;
        self.grown_at = self.newest;
    }

    /// `handBackToFrames`: pace lifted the rate cap.
    pub fn hand_back_to_frames(&mut self) {
        if !self.rate_kept {
            return;
        }
        self.rate_kept = false;
        self.suspects = 0;
        self.pred_ready = false;
        self.pushes = 0;
        self.acks = 0;
        self.frames = 0;
        self.since = self.newest + 1;
        self.grown_at = self.newest;
    }
}

/// `shrunk`: the frame size that should bring back [`AIM_SHARE`] where
/// frames of `limit` brought back `share`; at most half, at least
/// [`MIN_FRAME_PACKETS`].
#[must_use]
pub fn shrunk(limit: usize, share: f64) -> usize {
    #[allow(clippy::cast_precision_loss)]
    let aim = limit as f64 * AIM_SHARE.ln() / share.ln();
    // Go's int(aim): truncation (and here saturation for an infinity).
    #[allow(clippy::cast_possible_truncation)]
    let aim = aim as i64;
    #[allow(clippy::cast_possible_wrap)]
    let half = (limit / 2) as i64;
    #[allow(clippy::cast_possible_wrap)]
    let floor = MIN_FRAME_PACKETS as i64;
    #[allow(clippy::cast_sign_loss)]
    let out = aim.min(half).max(floor) as usize;
    out
}

/// `packetStamp`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketStamp {
    /// The last push's ts.
    pub push: u32,
    /// The last acknowledgement's ts.
    pub ack: u32,
    /// A push was there.
    pub pushed: bool,
    /// An acknowledgement was there.
    pub acked: bool,
}

/// `stampsOf`: walks a KCP packet; a length longer than what is left ends
/// the walk.
#[must_use]
pub fn stamps_of(mut segs: &[u8]) -> PacketStamp {
    let mut st = PacketStamp::default();
    while segs.len() >= OVERHEAD {
        let ts = read_u32_le(segs, TS_OFF);
        match segs[CMD_OFF] {
            CMD_PUSH => {
                st.push = ts;
                st.pushed = true;
            }
            CMD_ACK => {
                st.ack = ts;
                st.acked = true;
            }
            _ => {}
        }
        let size = read_u32_le(segs, LEN_OFF) as usize;
        let rest = &segs[OVERHEAD..];
        if size > rest.len() {
            break;
        }
        segs = &rest[size..];
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::tests::seg;

    #[test]
    fn delivery_track_judges_a_bucket_once_a_later_one_is_answered() {
        // frames_test.go:136
        let mut track = DeliveryTrack::default();
        let at: u32 = 10_000;
        let bucket = i64::from(at) / DELIVERY_BUCKET_MS + 1;
        for i in 0..8u32 {
            assert_eq!(track.count(at + i, 1, 0, 0), bucket);
        }
        track.count(at, 0, 3, 0);
        assert_eq!(
            track.take(0),
            (0, 0, 0),
            "judged before a later bucket answered"
        );
        track.count(at + 300, 1, 0, 0);
        track.count(at + 300, 0, 1, 0);
        assert_eq!(track.take(0), (8, 3, 0));
        assert_eq!(track.take(0), (0, 0, 0), "a bucket is judged once");
    }

    #[test]
    fn stamp_clock_unwraps_across_the_wrap() {
        let mut c = StampClock::default();
        assert_eq!(c.unwrap(u32::MAX - 10), i64::from(u32::MAX - 10));
        assert_eq!(c.unwrap(5), i64::from(u32::MAX) + 6);
        // An older stamp reads as before the newest, not 49 days ahead.
        assert_eq!(c.unwrap(u32::MAX - 20), i64::from(u32::MAX - 20));
    }

    #[test]
    fn delivery_track_judges_the_wrapped_buckets_in_order() {
        let mut track = DeliveryTrack::default();
        let before = u32::MAX - 100;
        track.count(before, 10, 0, 1);
        track.count(before.wrapping_add(400), 1, 0, 0);
        track.count(before, 0, 10, 0);
        track.count(before.wrapping_add(400), 0, 1, 0);
        assert_eq!(track.take(0), (10, 10, 1));
    }

    #[test]
    fn frame_cap_shrinks_on_loss_and_grows_back_when_clean() {
        let full = 43;
        let mut f = FrameCap::default();
        let mut track = DeliveryTrack::default();
        let mut ts = 1000u32;
        // A frame every 20 ms, `full` pushes each, `acked` of them back.
        let mut feed =
            |f: &mut FrameCap, track: &mut DeliveryTrack, frames: u32, per: u32, back: u32| {
                for _ in 0..frames {
                    for _ in 0..per {
                        f.pushed(track, ts);
                    }
                    FrameCap::wrote(track, ts);
                    track.count(ts, 0, i64::from(back), 0);
                    ts += 20;
                }
            };
        feed(&mut f, &mut track, 30, 43, 4);
        assert_eq!(
            f.judge(&mut track, full).1,
            Verdict::None,
            "one lossy reading is luck"
        );
        feed(&mut f, &mut track, 30, 43, 4);
        let (share, v) = f.judge(&mut track, full);
        assert_eq!(v, Verdict::Frames, "share {share}");
        assert_eq!(f.limit, shrunk(full, share));
        assert!(f.limit <= full / 2 && f.limit >= MIN_FRAME_PACKETS);
        // Clean from here: it grows a quarter at a time back to full.
        let mut grew = 0;
        for _ in 0..40 {
            let per = u32::try_from(or(f.limit, full)).unwrap();
            feed(&mut f, &mut track, 30, per, per);
            if f.judge(&mut track, full).1 == Verdict::Frames {
                grew += 1;
            }
            if f.limit == 0 {
                break;
            }
        }
        assert_eq!(f.limit, 0, "lifted after {grew} raises");
    }

    #[test]
    fn halving_as_the_lane_goes_dark_and_forgetting() {
        let mut f = FrameCap::default();
        assert!(f.halve(43));
        assert_eq!(f.limit, 21);
        assert!(f.halve(43));
        assert_eq!(f.limit, 10);
        f.limit = 5;
        assert!(f.halve(43));
        assert_eq!(f.limit, MIN_FRAME_PACKETS);
        assert!(!f.halve(43), "at the floor nothing changes");
        f.rate_kept = true;
        f.limit = 0;
        assert!(
            !f.halve(43),
            "a lane whose rate pace owns keeps full frames"
        );
    }

    #[test]
    fn shrunk_aims_at_the_share_and_stays_in_bounds() {
        // 43 packets at share 0.1: 43 * ln 0.4 / ln 0.1 = 17.1.
        assert_eq!(shrunk(43, 0.1), 17);
        assert_eq!(shrunk(43, 0.24), 21, "at most half");
        assert_eq!(shrunk(8, 0.021), MIN_FRAME_PACKETS, "at least the floor");
    }

    #[test]
    fn judge_hands_the_rate_to_pace_when_shrinks_buy_nothing() {
        let full = 43;
        let mut f = FrameCap::default();
        let mut track = DeliveryTrack::default();
        let (mut ts, mut n) = (0u32, 0u32);
        let mut verdicts = Vec::new();
        // One push in ten answered whatever the frames: rate loss.
        for _ in 0..40 {
            let per = or(f.limit, full);
            for _ in 0..30 {
                for _ in 0..per {
                    f.pushed(&mut track, ts);
                    n += 1;
                    if n % 10 == 0 {
                        track.count(ts, 0, 1, 0);
                    }
                }
                FrameCap::wrote(&mut track, ts);
                ts += 20;
            }
            let v = f.judge(&mut track, full).1;
            verdicts.push(v);
            if v == Verdict::Rate {
                break;
            }
        }
        // A judgement waits for enough evidence, so Nones come between.
        let acted: Vec<_> = verdicts
            .into_iter()
            .filter(|v| *v != Verdict::None)
            .collect();
        assert_eq!(
            acted,
            [
                Verdict::Frames,
                Verdict::Frames,
                Verdict::Frames,
                Verdict::Rate
            ]
        );
        assert!(f.rate_kept && f.limit == 0);
        f.hand_back_to_frames();
        assert!(!f.rate_kept);
    }

    #[test]
    fn stamps_of_reads_the_last_push_and_ack() {
        let mut p = seg(CMD_ACK, 7, 0);
        p.extend(seg(CMD_ACK, 9, 0));
        p.extend(seg(CMD_PUSH, 11, 3));
        p.extend(seg(CMD_PUSH, 12, 0));
        let st = stamps_of(&p);
        assert_eq!(
            st,
            PacketStamp {
                push: 12,
                ack: 9,
                pushed: true,
                acked: true
            }
        );
        // A hostile length ends the walk where it stands.
        let mut bad = seg(CMD_ACK, 1, 0);
        bad.extend(seg(CMD_PUSH, 2, 0));
        bad[OVERHEAD + LEN_OFF] = 0xff;
        bad.extend(seg(CMD_PUSH, 3, 0));
        assert_eq!(stamps_of(&bad).push, 2);
    }
}

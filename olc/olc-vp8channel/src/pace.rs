// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The cap a data lane keeps after it has been dark: `vp8channel/pace.go`
//! at 2d4266af (issue #12). Times are `crate::clock` nanoseconds.

use crate::wire::KCP_MTU;

/// `defaultGrowEvery`: a capped lane whose cap held data back raises it by
/// a quarter this often.
pub const DEFAULT_GROW_EVERY: i64 = 2_000_000_000;
/// `capObeyed`: how far over its cap a lane's busiest second may go and
/// still count as keeping to it.
pub const CAP_OBEYED: f64 = 1.25;
/// `minPaceRate`: the lowest cap, bytes per second.
pub const MIN_PACE_RATE: f64 = 16.0 * 1024.0;
/// `quietRate`: a lane writing at most this is not dark by its own doing.
pub const QUIET_RATE: f64 = 4.0 * MIN_PACE_RATE;
/// `paceBurst`: the credit a capped lane may bank, in seconds at its rate.
pub const PACE_BURST_SECS: f64 = 0.05;
/// `paceQuarter`: one bucket of the sent history.
pub const PACE_QUARTER: i64 = 250_000_000;

const SECOND: f64 = 1e9;

/// `pace`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pace {
    /// The cap, bytes per second; 0 for none.
    pub rate: f64,
    credit: f64,
    credit_at: i64,
    /// The cap left data queued since it last grew.
    pub held: bool,
    grown_at: i64,
    sent: [i64; 16],
    sent_at: i64,
}

impl Pace {
    /// `wrote`: `n` bytes written at `now`, taken off the credit.
    pub fn wrote(&mut self, now: i64, n: usize) {
        self.roll(now);
        #[allow(clippy::cast_possible_wrap)]
        let n_i = n as i64;
        self.sent[0] += n_i;
        #[allow(clippy::cast_precision_loss)]
        let n_f = n as f64;
        self.credit -= n_f;
    }

    fn roll(&mut self, now: i64) {
        while now - self.sent_at >= PACE_QUARTER {
            self.sent.copy_within(0..15, 1);
            self.sent[0] = 0;
            self.sent_at += PACE_QUARTER;
            if now - self.sent_at >= 16 * PACE_QUARTER {
                self.sent = [0; 16];
                self.sent_at = now;
            }
        }
    }

    /// `sentRate`: bytes per second over the busiest second of the last four.
    pub fn sent_rate(&mut self, now: i64) -> f64 {
        self.roll(now);
        let (mut window, mut busiest) = (0i64, 0i64);
        for i in 0..self.sent.len() {
            window += self.sent[i];
            if i >= 4 {
                window -= self.sent[i - 4];
            }
            busiest = busiest.max(window);
        }
        #[allow(clippy::cast_precision_loss)]
        let b = busiest as f64;
        b
    }

    /// `slow`: caps the lane at half of `sent` (or of its cap if lower);
    /// reports whether the cap changed.
    pub fn slow(&mut self, now: i64, sent: f64, full: f64) -> bool {
        if sent < QUIET_RATE.max(full / 8.0) || (self.rate > 0.0 && sent <= self.rate * CAP_OBEYED)
        {
            return false;
        }
        let sent = if self.rate > 0.0 {
            sent.min(self.rate)
        } else {
            sent
        };
        self.rate = (sent / 2.0).max(MIN_PACE_RATE);
        self.credit = 0.0;
        self.credit_at = now;
        self.held = false;
        self.grown_at = now;
        true
    }

    /// `cutTo`: caps the lane at what was delivered. Go reads `monoNow()`
    /// inside; the caller's `now` is the same instant within the flush.
    pub fn cut_to(&mut self, delivered: f64, now: i64) {
        self.rate = delivered.max(MIN_PACE_RATE);
        self.credit = 0.0;
        self.credit_at = now;
        self.held = false;
        self.grown_at = now;
    }

    /// `grow`: a quarter up after a whole interval in which the cap held
    /// data back, lifted at `full`; reports whether the cap changed.
    pub fn grow(&mut self, now: i64, every: i64, full: f64) -> bool {
        if self.rate == 0.0 || !self.held || now - self.grown_at < every {
            return false;
        }
        self.rate += self.rate / 4.0;
        if self.rate >= full {
            self.rate = 0.0;
        }
        self.held = false;
        self.grown_at = now;
        true
    }

    /// `allow`: refills the credit to `now`; the bytes that may go, or -1
    /// without a cap.
    pub fn allow(&mut self, now: i64) -> i64 {
        if self.rate == 0.0 {
            return -1;
        }
        #[allow(clippy::cast_precision_loss)]
        let dt = (now - self.credit_at) as f64;
        self.credit += self.rate * dt / SECOND;
        #[allow(clippy::cast_precision_loss)]
        let floor = KCP_MTU as f64;
        self.credit = self.credit.min((self.rate * PACE_BURST_SECS).max(floor));
        self.credit_at = now;
        #[allow(clippy::cast_possible_truncation)]
        let out = self.credit.max(0.0) as i64;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i64 = 1_000_000_000;

    #[test]
    fn pace_halves_the_busiest_second_and_grows_back() {
        // pace_test.go:13
        let mut s = Pace::default();
        let mut now = 10 * S;
        for i in 0..4 {
            s.wrote(now + i * PACE_QUARTER, 100 << 10);
        }
        now += 3 * S;
        s.wrote(now, 10 << 10);
        let sent = s.sent_rate(now);
        assert!(
            s.slow(now, sent, f64::from(1 << 20)),
            "slow() left a loud lane uncapped"
        );
        assert_eq!(s.rate, f64::from(200 << 10));

        let grow = |s: &mut Pace, at: i64| s.grow(at, 2 * S, f64::from(1 << 30));
        assert!(
            !grow(&mut s, now + 3 * S),
            "grew a cap that held nothing back"
        );
        s.held = true;
        assert!(!grow(&mut s, now + S), "grew before the interval passed");
        assert!(grow(&mut s, now + 3 * S));
        assert_eq!(s.rate, f64::from(200 << 10) * 5.0 / 4.0);
        let capped = s.rate;
        s.wrote(now + 4 * S, 100 << 10);
        let sent = s.sent_rate(now + 4 * S);
        assert!(!s.slow(now + 4 * S, sent, f64::from(1 << 20)) && s.rate == capped);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        s.wrote(now + 5 * S, capped as usize);
        let sent = s.sent_rate(now + 5 * S);
        assert!(!s.slow(now + 5 * S, sent, f64::from(1 << 20)) && s.rate == capped);
        s.wrote(now + 6 * S, 400 << 10);
        let sent = s.sent_rate(now + 6 * S);
        assert!(s.slow(now + 6 * S, sent, f64::from(1 << 20)) && s.rate == capped / 2.0);
        s.held = true;
        let full = s.rate;
        assert!(
            s.grow(now + 8 * S, 2 * S, full) && s.rate == 0.0,
            "lifted at full"
        );
    }

    #[test]
    fn pace_leaves_a_quiet_lane_uncapped() {
        let mut s = Pace::default();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        s.wrote(S, (QUIET_RATE / 2.0) as usize);
        let sent = s.sent_rate(S + 1);
        assert!(!s.slow(S + 1, sent, f64::from(1 << 20)) && s.rate == 0.0);
        s.wrote(S + 1, 90 << 10);
        let sent = s.sent_rate(S + 2);
        assert!(!s.slow(S + 2, sent, f64::from(1 << 20)) && s.rate == 0.0);
        assert_eq!(s.allow(2 * S), -1);
    }

    #[test]
    fn pace_credit_follows_the_rate_without_banking() {
        let mut s = Pace {
            rate: f64::from(100 << 10),
            ..Pace::default()
        };
        assert_eq!(s.allow(10_000_000), 1024);
        s.wrote(10_000_000, 3000);
        assert_eq!(s.allow(20_000_000), 0, "repaid first");
        #[allow(clippy::cast_possible_truncation)]
        let burst = (f64::from(100 << 10) * PACE_BURST_SECS) as i64;
        assert!(s.allow(10 * S) <= burst);
    }
}

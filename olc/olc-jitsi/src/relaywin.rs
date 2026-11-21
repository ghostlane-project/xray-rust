// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! An end-to-end window over the bridge's relay
//! (`internal/engine/jitsi/relaywindow.go`, olcrtc#15), for a single peer.
//!
//! The JVB reads a sender's association as fast as frames arrive and queues
//! them for the receiver in a send buffer of about 2 MB, dropping what does
//! not fit. So a sender bounds what it has handed the bridge and the
//! destination has not yet taken off it: [`WINDOW`] bytes. It follows its
//! frames with a mark carrying how many bytes it has sent; the destination
//! echoes the mark as soon as its receive loop reaches it; the channel is
//! ordered, so an echo means every frame before the mark has been handed up.
//! A build without the window drops the frames unread, and a sender only
//! holds back once an echo has come.
//!
//! This is the state alone: no clock of its own, no I/O. The caller sends
//! what [`RelayWindow::sent`], [`RelayWindow::room`] and
//! [`RelayWindow::on_frame`] ask for, and waits as [`Room::Held`] says.

use std::time::{Duration, Instant};

use crate::epoch::Epochs;
use crate::frame::{WindowFrame, WindowKind, WINDOW_FRAME_LEN};

/// 512 KiB of frames, about 700 KB of `EndpointMessage` JSON at the bridge,
/// well under the 2 MB it holds for one receiver (`relayWindow`).
pub const WINDOW: usize = 512 << 10;
/// A mark every eighth of the window (`relayMarkEvery`).
pub const MARK_EVERY: usize = WINDOW / 8;

/// The window's timers (`relayTiming`); [`Default`] is the constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// A sender held this long since its last mark marks again, which
    /// repairs a lost mark or echo; until a destination has echoed, its
    /// frames are marked this often too (`relayProbeAfter`).
    pub probe: Duration,
    /// A destination that has held the sender this long without echoing is
    /// gone, and its window is turned off (`relayDeadAfter`).
    pub dead: Duration,
    /// How often a held sender looks again (`relayRetry`).
    pub retry: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            probe: Duration::from_secs(1),
            dead: Duration::from_secs(30),
            retry: Duration::from_millis(250),
        }
    }
}

/// May a frame go now (`relayRoom`)?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Room {
    /// Yes.
    Open,
    /// No: the window is full; look again in [`Timing::retry`], or when an
    /// echo or a reset wakes the sender.
    Held,
    /// No, and a probe is due: send a mark with this count.
    Probe(u64),
}

/// What an echo did (`applyEcho`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoResult {
    /// The window moved: wake a held sender.
    pub moved: bool,
    /// This echo is the first: the destination speaks the window.
    pub turned_on: bool,
}

/// What a window frame from the bridge asks for (`handleWindowFrame`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing: not for this session, or no kind that is acted on.
    None,
    /// Echo the mark: send [`WindowKind::Echo`] to `receiver_epoch`.
    SendEcho {
        /// The mark's sender's epoch.
        receiver_epoch: u32,
        /// Its count.
        counter: u64,
    },
    /// An echo was taken.
    Echoed {
        /// Whether it moved the window.
        moved: bool,
        /// Whether it turned the window on.
        turned_on: bool,
    },
}

/// The 21 bytes of a mark or echo from `local` to `receiver`; `None` while
/// the receiver's epoch is not known: only a mark addressed to its epoch is
/// echoed (`sendWindowFrame`).
#[must_use]
pub fn window_frame_bytes(
    kind: WindowKind,
    local: u32,
    receiver: u32,
    counter: u64,
) -> Option<[u8; WINDOW_FRAME_LEN]> {
    (receiver != 0).then(|| {
        WindowFrame {
            kind,
            sender_epoch: local,
            receiver_epoch: receiver,
            counter,
        }
        .encode()
    })
}

/// The window toward one destination (`relayState`).
#[derive(Debug, Clone, Copy)]
struct State {
    /// Bytes handed to the bridge for the destination.
    sent: u64,
    /// `sent` as of the last mark.
    marked: u64,
    /// The highest mark the destination has echoed.
    echoed: u64,
    /// An echo came: the destination speaks the window.
    active: bool,
    /// When the last mark went out.
    marked_at: Option<Instant>,
    /// When the window filled; reset by every echo.
    held_since: Option<Instant>,
}

/// The window of a single-peer session.
#[derive(Debug)]
pub struct RelayWindow {
    st: Option<State>,
    /// Bytes sent by the session in all, which never starts over: a window
    /// opened after a reset starts here, past every mark sent before, so a
    /// late echo of one is out of its range.
    count: u64,
    timing: Timing,
}

impl RelayWindow {
    /// A window with no destination yet.
    #[must_use]
    pub fn new(timing: Timing) -> Self {
        Self {
            st: None,
            count: 0,
            timing,
        }
    }

    /// The timers.
    #[must_use]
    pub fn timing(&self) -> Timing {
        self.timing
    }

    /// The probe interval, changed in the middle of a run (the vectors'
    /// scripts do).
    #[cfg(test)]
    pub(crate) fn set_probe(&mut self, probe: std::time::Duration) {
        self.timing.probe = probe;
    }

    /// An echo has turned the window on.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.st.is_some_and(|s| s.active)
    }

    /// The window filled and still holds the sender.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.st.is_some_and(|s| s.held_since.is_some())
    }

    /// Whether a frame may go now; a held window that is due a probe hands
    /// back the count to mark (`relayRoom`).
    pub fn room(&mut self, now: Instant) -> Room {
        let timing = self.timing;
        let Some(st) = self.st.as_mut() else {
            return Room::Open;
        };
        if !st.active || st.sent - st.echoed < WINDOW as u64 {
            st.held_since = None;
            return Room::Open;
        }
        let since = *st.held_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= timing.dead {
            // Gone: what waits for it drains as it used to.
            st.active = false;
            return Room::Open;
        }
        if st
            .marked_at
            .is_none_or(|m| now.saturating_duration_since(m) >= timing.probe)
        {
            st.marked = st.sent;
            st.marked_at = Some(now);
            return Room::Probe(st.sent);
        }
        Room::Held
    }

    /// Counts a frame of `n` bytes that went on the bridge; the count to
    /// mark when a mark is due: every [`MARK_EVERY`] bytes, and once a probe
    /// interval while the destination has not echoed yet (`relaySent`).
    pub fn sent(&mut self, n: usize, now: Instant) -> Option<u64> {
        let timing = self.timing;
        let count = self.count;
        let st = self.st.get_or_insert(State {
            sent: count,
            marked: count,
            echoed: count,
            active: false,
            marked_at: None,
            held_since: None,
        });
        let add = n as u64;
        st.sent += add;
        self.count += add;
        let due = st.sent - st.marked >= MARK_EVERY as u64
            || (!st.active
                && st
                    .marked_at
                    .is_none_or(|m| now.saturating_duration_since(m) >= timing.probe));
        if due {
            st.marked = st.sent;
            st.marked_at = Some(now);
            return Some(st.sent);
        }
        None
    }

    /// Takes an echo for `counter`: it moves the window only for a count past
    /// the last echo and within what was sent (`applyEcho`, after the caller
    /// checked whose echo it is).
    pub fn echo(&mut self, counter: u64) -> EchoResult {
        let none = EchoResult {
            moved: false,
            turned_on: false,
        };
        let Some(st) = self.st.as_mut() else {
            return none;
        };
        if counter <= st.echoed || counter > st.sent {
            return none;
        }
        let turned_on = !st.active;
        st.active = true;
        st.echoed = counter;
        st.held_since = None;
        EchoResult {
            moved: true,
            turned_on,
        }
    }

    /// Takes a window frame that came from endpoint `from`: only what is
    /// addressed to this session's epoch counts, and an echo only from the
    /// endpoint and under the epoch this session sends that peer's frames to
    /// (`handleWindowFrame`).
    pub fn on_frame(&mut self, from: &str, f: &WindowFrame, epochs: &Epochs) -> Action {
        let local = epochs.local();
        if f.receiver_epoch != local || f.sender_epoch == 0 || f.sender_epoch == local {
            return Action::None;
        }
        match f.kind {
            WindowKind::Mark => Action::SendEcho {
                receiver_epoch: f.sender_epoch,
                counter: f.counter,
            },
            WindowKind::Echo => {
                if f.sender_epoch != epochs.echoer_epoch(from) {
                    return Action::Echoed {
                        moved: false,
                        turned_on: false,
                    };
                }
                let r = self.echo(f.counter);
                Action::Echoed {
                    moved: r.moved,
                    turned_on: r.turned_on,
                }
            }
            WindowKind::Other(_) => Action::None,
        }
    }

    /// Forgets the window: this session or its peer starts over
    /// (`resetRelayWindows`). The session's count goes on.
    pub fn reset(&mut self) {
        self.st = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{WindowFrame, WindowKind};
    use std::collections::VecDeque;

    const FRAME: usize = 12 * 1024;
    const LOAD: usize = 6 * 512 * 1024 / FRAME;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// A window that has seen an echo, so it holds.
    fn active(t0: Instant) -> RelayWindow {
        let mut w = RelayWindow::new(Timing::default());
        let mark = w.sent(FRAME, t0).expect("the first frame is marked");
        assert!(w.echo(mark).moved);
        assert!(w.is_active());
        w
    }

    #[test]
    fn the_constants() {
        assert_eq!(WINDOW, 512 << 10);
        assert_eq!(MARK_EVERY, 64 << 10);
        assert_eq!(Timing::default().probe, secs(1));
        assert_eq!(Timing::default().dead, secs(30));
        assert_eq!(Timing::default().retry, Duration::from_millis(250));
    }

    /// `TestAPeerThatNeverEchoesIsSentToAsBefore`: until an echo has come the
    /// window never holds.
    #[test]
    fn a_window_that_never_echoed_never_holds() {
        let t0 = Instant::now();
        let mut w = RelayWindow::new(Timing::default());
        for i in 0..LOAD * 2 {
            assert_eq!(w.room(t0), Room::Open, "frame {i}");
            w.sent(FRAME, t0);
        }
        assert!(!w.is_held());
    }

    /// The first frame is marked at once, then every `MARK_EVERY` bytes; until
    /// the destination has echoed, once a probe interval too.
    #[test]
    fn marks_come_every_eighth_of_the_window_and_by_the_probe_until_an_echo() {
        let t0 = Instant::now();
        let mut w = RelayWindow::new(Timing::default());
        assert_eq!(w.sent(100, t0), Some(100), "the first frame");
        assert_eq!(w.sent(100, t0), None);
        assert_eq!(w.sent(100, t0 + Duration::from_millis(999)), None);
        assert_eq!(
            w.sent(100, t0 + secs(1)),
            Some(400),
            "a probe interval later"
        );
        // Past the mark interval in bytes.
        assert_eq!(
            w.sent(MARK_EVERY, t0 + secs(1)),
            Some(400 + MARK_EVERY as u64)
        );
        // Once active, only the bytes count.
        assert!(w.echo(400).moved);
        assert_eq!(w.sent(10, t0 + secs(100)), None);
        assert_eq!(
            w.sent(MARK_EVERY, t0 + secs(100)),
            Some(400 + MARK_EVERY as u64 + 10 + MARK_EVERY as u64)
        );
    }

    #[test]
    fn an_echo_moves_the_window_only_within_what_was_sent() {
        let t0 = Instant::now();
        let mut w = RelayWindow::new(Timing::default());
        w.sent(1000, t0);
        w.sent(1000, t0);
        // Past what was sent, at or behind the last echo: nothing.
        assert!(!w.echo(2001).moved);
        assert!(!w.echo(0).moved);
        assert!(!w.is_active());
        let e = w.echo(1000);
        assert!(e.moved && e.turned_on);
        let e = w.echo(2000);
        assert!(e.moved && !e.turned_on);
        assert!(!w.echo(2000).moved);
        assert!(!w.echo(1500).moved, "behind a later echo");
    }

    #[test]
    fn a_full_window_holds_and_an_echo_makes_room() {
        let t0 = Instant::now();
        let mut w = active(t0);
        let mut counter = FRAME as u64;
        let mut sent = FRAME;
        while sent - FRAME < WINDOW {
            assert_eq!(w.room(t0), Room::Open);
            if let Some(m) = w.sent(FRAME, t0) {
                counter = m;
            }
            sent += FRAME;
        }
        assert!(w.is_held() || w.room(t0) != Room::Open);
        assert_ne!(w.room(t0), Room::Open);
        // The echo of a mark lets some through.
        assert!(w.echo(counter).moved);
        assert_eq!(w.room(t0), Room::Open);
    }

    /// `TestALostEchoIsRepairedByAProbe`: a held sender marks again once a
    /// probe interval has passed.
    #[test]
    fn a_held_sender_probes_once_a_second() {
        let t0 = Instant::now();
        let mut w = active(t0);
        w.sent(WINDOW, t0);
        let held_at = t0 + secs(5);
        // Held, and the last mark is old: probe now.
        assert!(matches!(w.room(held_at), Room::Probe(c) if c == (FRAME + WINDOW) as u64));
        assert_eq!(w.room(held_at + Duration::from_millis(500)), Room::Held);
        assert!(matches!(w.room(held_at + secs(1)), Room::Probe(_)));
    }

    /// `TestAPeerThatStopsEchoingIsLetGo`: held for `dead`, the window turns
    /// off and the sender is let through, as before.
    #[test]
    fn a_peer_that_stops_echoing_is_let_go() {
        let t0 = Instant::now();
        let mut w = active(t0);
        w.sent(WINDOW, t0);
        assert!(matches!(w.room(t0), Room::Probe(_)) || w.room(t0) == Room::Held);
        assert_ne!(w.room(t0 + secs(29)), Room::Open);
        assert_eq!(w.room(t0 + secs(30)), Room::Open);
        assert!(!w.is_active());
        // And it holds no more, however much goes.
        for _ in 0..LOAD {
            assert_eq!(w.room(t0 + secs(31)), Room::Open);
            w.sent(FRAME, t0 + secs(31));
        }
    }

    /// `TestAnEchoStartsTheDeadClockOver`.
    #[test]
    fn an_echo_starts_the_dead_clock_over() {
        let t0 = Instant::now();
        let timing = Timing {
            probe: secs(3600),
            dead: secs(60),
            retry: secs(1),
        };
        let mut w = RelayWindow::new(timing);
        w.sent(FRAME, t0);
        let first = FRAME as u64;
        let second = w.sent(MARK_EVERY, t0).unwrap();
        w.sent(2 * WINDOW, t0);
        assert!(w.echo(first).moved);
        assert_eq!(w.room(t0), Room::Held, "the window is on and full");
        assert!(w.echo(second).moved);
        assert_ne!(
            w.room(t0 + secs(120)),
            Room::Open,
            "an echo did not start the clock over"
        );
        assert_eq!(
            w.room(t0 + secs(240)),
            Room::Open,
            "twice the dead period of silence"
        );
    }

    /// A window opened after a reset starts at the session's count, past
    /// every mark sent before: a late echo of one moves nothing
    /// (`TestAnEchoFromBeforeAResetMovesNoWindow`).
    #[test]
    fn an_echo_from_before_a_reset_moves_nothing() {
        let t0 = Instant::now();
        let mut w = active(t0);
        let old_mark = w.sent(MARK_EVERY, t0).unwrap();
        w.reset();
        assert!(!w.is_active());
        assert_eq!(w.room(t0), Room::Open);
        let fresh = w.sent(FRAME, t0).unwrap();
        assert_eq!(fresh, old_mark + FRAME as u64, "the count goes on");
        assert!(!w.echo(old_mark).moved, "a late echo of an old mark");
        assert!(w.echo(fresh).moved);
    }

    fn epochs(local: u32, peer: u32) -> Epochs {
        let mut e = Epochs::new(local, true);
        e.confirm_peer(&format!("{peer:08x}")).unwrap();
        e.latch_endpoint("peer", Instant::now());
        e
    }

    fn frame(kind: WindowKind, from: u32, to: u32, counter: u64) -> WindowFrame {
        WindowFrame {
            kind,
            sender_epoch: from,
            receiver_epoch: to,
            counter,
        }
    }

    /// `TestWindowFramesStayBetweenTheTwoEnds`: only what is addressed to this
    /// session's epoch, from another epoch, counts; a mark is answered by an
    /// echo to the sender's epoch.
    #[test]
    fn frames_count_only_between_the_two_ends() {
        let e = epochs(0xA0A0_A0A0, 0xB0B0_B0B0);
        let mut w = RelayWindow::new(Timing::default());
        let mark = frame(WindowKind::Mark, 0xB0B0_B0B0, 0xA0A0_A0A0, 77);
        assert_eq!(
            w.on_frame("peer", &mark, &e),
            Action::SendEcho {
                receiver_epoch: 0xB0B0_B0B0,
                counter: 77
            }
        );
        // Addressed to another epoch, from our own epoch, from epoch 0.
        for f in [
            frame(WindowKind::Mark, 0xB0B0_B0B0, 0x1234, 1),
            frame(WindowKind::Mark, 0xA0A0_A0A0, 0xA0A0_A0A0, 1),
            frame(WindowKind::Mark, 0, 0xA0A0_A0A0, 1),
            frame(WindowKind::Other(9), 0xB0B0_B0B0, 0xA0A0_A0A0, 1),
        ] {
            assert_eq!(w.on_frame("peer", &f, &e), Action::None, "{f:?}");
        }
    }

    /// `TestOnlyThePeersEndpointMovesTheWindow`.
    #[test]
    fn only_the_peers_endpoint_and_epoch_move_the_window() {
        let e = epochs(0xA0A0_A0A0, 0xB0B0_B0B0);
        let t0 = Instant::now();
        let mut w = RelayWindow::new(Timing::default());
        w.sent(1000, t0);
        let echo = |from_epoch| frame(WindowKind::Echo, from_epoch, 0xA0A0_A0A0, 1000);
        // Another endpoint, even under the peer's epoch.
        assert_eq!(
            w.on_frame("stranger", &echo(0xB0B0_B0B0), &e),
            Action::Echoed {
                moved: false,
                turned_on: false
            }
        );
        // The peer's endpoint under another epoch.
        assert_eq!(
            w.on_frame("peer", &echo(0xC0C0_C0C0), &e),
            Action::Echoed {
                moved: false,
                turned_on: false
            }
        );
        assert!(!w.is_active());
        assert_eq!(
            w.on_frame("peer", &echo(0xB0B0_B0B0), &e),
            Action::Echoed {
                moved: true,
                turned_on: true
            }
        );
        assert!(w.is_active());
    }

    #[test]
    fn a_frame_to_an_unknown_epoch_is_not_sent() {
        assert_eq!(window_frame_bytes(WindowKind::Mark, 1, 0, 5), None);
        let b = window_frame_bytes(WindowKind::Mark, 1, 2, 5).unwrap();
        assert_eq!(
            WindowFrame::parse(&b),
            Some(frame(WindowKind::Mark, 1, 2, 5))
        );
    }

    // ---- the relay, as it was measured: `relayModel` ----

    /// The bridge in memory: it takes whatever a sender hands it at once,
    /// holds for the receiver up to `BUFFER` bytes of `EndpointMessage` JSON
    /// (data and window frames alike), drops what does not fit, and delivers
    /// in order only while the receiver's leg is up.
    const BUFFER: usize = 2_000_000;
    /// What one 12 KiB frame costs at the bridge: base64 and the wrapper.
    const WIRE: usize = (FRAME + 13 + 8 + 4) * 4 / 3 + 80;

    #[derive(Default)]
    struct Relay {
        to_b: VecDeque<(usize, Vec<u8>)>,
        queued: usize,
        to_a: VecDeque<Vec<u8>>,
        dropped: usize,
        stalled: bool,
    }

    /// A sender `a` and a receiver `b` over the relay, on a manual clock.
    struct Pair {
        now: Instant,
        relay: Relay,
        a: RelayWindow,
        a_epochs: Epochs,
        b_epochs: Epochs,
        b_window: RelayWindow,
        next_seq: u64,
        got: Vec<u64>,
        a_epoch: u32,
        b_epoch: u32,
        lose_echoes: bool,
    }

    impl Pair {
        fn new(timing: Timing) -> Self {
            let (a_epoch, b_epoch) = (0xA0A0_A0A0, 0xB0B0_B0B0);
            let mut a_epochs = Epochs::new(a_epoch, true);
            a_epochs.confirm_peer(&format!("{b_epoch:08x}")).unwrap();
            a_epochs.latch_endpoint("b", Instant::now());
            let mut b_epochs = Epochs::new(b_epoch, true);
            b_epochs.confirm_peer(&format!("{a_epoch:08x}")).unwrap();
            b_epochs.latch_endpoint("a", Instant::now());
            Self {
                now: Instant::now(),
                relay: Relay::default(),
                a: RelayWindow::new(timing),
                a_epochs,
                b_epochs,
                b_window: RelayWindow::new(timing),
                next_seq: 0,
                got: Vec::new(),
                a_epoch,
                b_epoch,
                lose_echoes: false,
            }
        }

        fn put(&mut self, frame: Vec<u8>, cost: usize) {
            if self.relay.queued + cost > BUFFER {
                self.relay.dropped += 1;
                return;
            }
            self.relay.queued += cost;
            self.relay.to_b.push_back((cost, frame));
        }

        /// A tries to send one frame; true when it went.
        fn try_send(&mut self) -> bool {
            match self.a.room(self.now) {
                Room::Open => {}
                Room::Held => return false,
                Room::Probe(c) => {
                    self.send_window(WindowKind::Mark, c);
                    return false;
                }
            }
            let mut data = vec![0u8; FRAME];
            data[..8].copy_from_slice(&self.next_seq.to_be_bytes());
            self.next_seq += 1;
            let f = crate::frame::encode_frame(&data, self.a_epoch, self.b_epoch).unwrap();
            self.put(f, WIRE);
            if let Some(c) = self.a.sent(FRAME + 12, self.now) {
                self.send_window(WindowKind::Mark, c);
            }
            true
        }

        fn send_window(&mut self, kind: WindowKind, counter: u64) {
            if let Some(b) = window_frame_bytes(kind, self.a_epoch, self.b_epoch, counter) {
                self.put(b.to_vec(), 120);
            }
        }

        /// B's leg: delivers while it is up; marks are echoed.
        fn deliver(&mut self) {
            while !self.relay.stalled {
                let Some((cost, f)) = self.relay.to_b.pop_front() else {
                    break;
                };
                self.relay.queued -= cost;
                if let Some(w) = WindowFrame::parse(&f) {
                    if let Action::SendEcho {
                        receiver_epoch,
                        counter,
                    } = self.b_window.on_frame("a", &w, &self.b_epochs)
                    {
                        let echo = window_frame_bytes(
                            WindowKind::Echo,
                            self.b_epoch,
                            receiver_epoch,
                            counter,
                        )
                        .unwrap();
                        self.relay.to_a.push_back(echo.to_vec());
                    }
                    continue;
                }
                let got = self.b_epochs.receive("a", &f, self.now);
                let body = got.body.expect("a frame for b");
                self.got
                    .push(u64::from_be_bytes(body[..8].try_into().unwrap()));
            }
            if self.lose_echoes {
                self.relay.to_a.clear();
            }
            while let Some(f) = self.relay.to_a.pop_front() {
                let w = WindowFrame::parse(&f).unwrap();
                self.a.on_frame("b", &w, &self.a_epochs);
            }
        }

        /// A sends frames until it is held or has sent `n`; 1 ms per frame.
        fn pump(&mut self, n: usize) {
            while (self.next_seq as usize) < n {
                if !self.try_send() {
                    break;
                }
                self.now += Duration::from_millis(1);
                self.deliver();
            }
        }
    }

    /// `TestAStalledReceiverLosesNothingAtTheRelay`: six phones' worth of
    /// frames toward a receiver that does not read, then it reads.
    #[test]
    fn a_stalled_receiver_loses_nothing_at_the_relay() {
        let mut p = Pair::new(Timing::default());
        // The handshake: one frame over the open leg, so the window is on.
        p.pump(1);
        assert_eq!(p.got, [0]);
        assert!(p.a.is_active(), "the first echo turned the window on");
        p.relay.stalled = true;
        p.pump(LOAD + 1);
        assert!(p.a.is_held(), "the window held the sender back");
        assert!(
            (p.next_seq as usize) < LOAD + 1,
            "{} frames went",
            p.next_seq
        );
        assert_eq!(
            p.relay.dropped, 0,
            "the sender handed the relay more than it holds"
        );
        // The receiver reads again; the sender goes on to the end.
        p.relay.stalled = false;
        p.deliver();
        for _ in 0..10_000 {
            p.pump(LOAD + 1);
            p.deliver();
            if p.got.len() == LOAD + 1 {
                break;
            }
        }
        assert_eq!(p.relay.dropped, 0);
        assert_eq!(
            p.got,
            (0..=LOAD as u64).collect::<Vec<_>>(),
            "in order, every one"
        );
    }

    /// Without the window the same load overruns the relay: the model drops
    /// (the test above would pass on a model that never did).
    #[test]
    fn the_model_does_drop_when_nothing_holds_the_sender() {
        let mut p = Pair::new(Timing::default());
        p.relay.stalled = true;
        for _ in 0..LOAD * 2 {
            let mut data = vec![0u8; FRAME];
            data[..8].copy_from_slice(&p.next_seq.to_be_bytes());
            p.next_seq += 1;
            let f = crate::frame::encode_frame(&data, p.a_epoch, p.b_epoch).unwrap();
            p.put(f, WIRE);
        }
        assert!(p.relay.dropped > 0);
    }

    /// `TestAPeerThatNeverEchoesIsSentToAsBefore`, end to end: marks are
    /// lost on the way, the sender is never held.
    #[test]
    fn an_old_peer_that_never_echoes_does_not_hold_the_sender() {
        let mut p = Pair::new(Timing::default());
        p.relay.stalled = true;
        p.pump(LOAD + 1);
        assert_eq!(p.next_seq as usize, LOAD + 1);
        assert!(!p.a.is_active());
    }

    /// `TestALostEchoIsRepairedByAProbe`, end to end: with every echo lost the
    /// window lets `WINDOW` through and holds; the probe a held sender sends
    /// once a probe interval brings a fresh echo, and the load goes on.
    #[test]
    fn a_lost_echo_is_repaired_by_a_probe() {
        let timing = Timing {
            probe: Duration::from_millis(20),
            dead: secs(60),
            retry: Duration::from_millis(5),
        };
        let mut p = Pair::new(timing);
        p.pump(1);
        assert!(p.a.is_active());
        p.lose_echoes = true;
        for _ in 0..50 {
            p.pump(LOAD + 1);
            p.now += Duration::from_millis(30);
            p.deliver();
        }
        assert!(p.a.is_held(), "the sender was never held");
        assert!(
            p.got.len() <= WINDOW / FRAME + 2,
            "{} frames arrived with every echo lost; the window lets {} through",
            p.got.len(),
            WINDOW / FRAME
        );
        p.lose_echoes = false;
        for _ in 0..10_000 {
            p.pump(LOAD + 1);
            p.now += Duration::from_millis(30);
            p.deliver();
            if p.got.len() == LOAD + 1 {
                break;
            }
        }
        assert_eq!(
            p.got.len(),
            LOAD + 1,
            "the sender stayed held after the echoes came back"
        );
        assert_eq!(p.relay.dropped, 0);
    }
}

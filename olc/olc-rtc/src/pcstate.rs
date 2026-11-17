// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! One peer connection's state as pion tells it, for every carrier.
//!
//! The Go engine at 2d4266af runs pion, whose `pc` logger says two lines at
//! info through `PionLoggerFactory`:
//!
//! ```text
//! [pc] INFO: ICE connection state changed: <state>
//! [pc] INFO: peer connection state changed: <state>
//! ```
//!
//! The apps read them (critique G1, W45: Android's `handleRtcLine` and iOS's
//! `IosVpnManager` restart the tunnel on them), and the carriers rejoin on
//! the second line's `failed` and `closed`. str0m has neither line, and its
//! ICE agent (`is`) has no failed state at all: a path that broke stays
//! `Disconnected` for good.
//!
//! [`PcWatcher`] is fed a peer's events ([`PeerEvent`]) and keeps both
//! states as pion would:
//!
//! - the ICE line follows str0m's ICE state, in pion's words. str0m's
//!   `Completed` is `connected` too: pion's agent never reports
//!   `completed` (pion/ice 4.2.7 defines the state and never sets it), so
//!   the Go client's log has no such line;
//! - the peer connection is `connecting` while ICE checks or DTLS is not up,
//!   `connected` once both are, `disconnected` while ICE is;
//! - ICE that stays disconnected for [`ICE_FAILED_AFTER`] is `failed`
//!   (pion's `ICEFailedTimeout`), and so is the peer connection. As in pion
//!   nothing follows `failed` but `closed`: a path that comes back later
//!   is not told, the owner is already rejoining;
//! - a peer whose ICE over TCP has nothing left, a connection that broke
//!   or a dial that failed with no other path alive
//!   ([`PeerEvent::Failed`]), is `failed` at once, before its first
//!   connect too: [`PcWatcher::failed`] returns without the wait (plan D7;
//!   pion gets there up to 30 s later);
//! - the driver's end ([`PeerEvent::Closed`]) is `closed` on both lines.
//!
//! Each line is said once per change. One watcher serves one peer
//! connection, so a carrier makes one per peer per generation.
//!
//! The watcher holds two bytes of state and one deadline: no task, no
//! queue, no allocation but a line's text when a state changes.

use std::fmt;
use std::time::Duration;

use tokio::time::Instant;

use crate::peer::{IceConnectionState, PeerEvent};

/// How long an ICE path may stay disconnected before the peer connection
/// counts as failed: pion's `ICEFailedTimeout` default (25 s, after its 5 s
/// to disconnected).
pub const ICE_FAILED_AFTER: Duration = Duration::from_secs(25);

/// pion's `[pc]` line for an ICE state, less the state.
const ICE_LINE: &str = "[pc] INFO: ICE connection state changed: ";
/// pion's `[pc]` line for a peer connection state, less the state.
const PC_LINE: &str = "[pc] INFO: peer connection state changed: ";

/// pion's `ICEConnectionState` as pion reports it: str0m's states (its
/// `Completed` is `Connected` here) and the two it lacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IceState {
    /// Nothing gathered or checked yet.
    New,
    /// Checks are running.
    Checking,
    /// A pair works.
    Connected,
    /// The pair that worked stopped answering.
    Disconnected,
    /// Disconnected for [`ICE_FAILED_AFTER`].
    Failed,
    /// The peer connection's driver ended.
    Closed,
}

impl IceState {
    /// pion's word for it (`ICEConnectionState.String`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Checking => "checking",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }
}

impl From<IceConnectionState> for IceState {
    fn from(s: IceConnectionState) -> Self {
        match s {
            IceConnectionState::New => Self::New,
            IceConnectionState::Checking => Self::Checking,
            IceConnectionState::Connected | IceConnectionState::Completed => Self::Connected,
            IceConnectionState::Disconnected => Self::Disconnected,
        }
    }
}

impl fmt::Display for IceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// pion's `PeerConnectionState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcState {
    /// Nothing started.
    New,
    /// ICE is checking, or DTLS is not up yet.
    Connecting,
    /// ICE has a pair and DTLS is up.
    Connected,
    /// ICE lost its pair, less than [`ICE_FAILED_AFTER`] ago.
    Disconnected,
    /// ICE failed. Only `Closed` follows.
    Failed,
    /// The peer connection's driver ended. Nothing follows.
    Closed,
}

impl PcState {
    /// pion's word for it (`PeerConnectionState.String`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }
}

impl fmt::Display for PcState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one event changed: the states that are new, each named once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// The ICE state, when it changed.
    pub ice: Option<IceState>,
    /// The peer connection's state, when it changed.
    pub pc: Option<PcState>,
}

impl Change {
    /// pion's lines for this change, the ICE one first as pion says them.
    #[must_use]
    pub fn lines(&self) -> [Option<String>; 2] {
        [
            self.ice.map(|s| format!("{ICE_LINE}{s}")),
            self.pc.map(|s| format!("{PC_LINE}{s}")),
        ]
    }

    /// Says [`Change::lines`] in the engine's log, at info.
    fn log(&self) {
        for line in self.lines().into_iter().flatten() {
            olc_net::info!("{line}");
        }
    }
}

/// One peer connection's two states, kept as pion keeps them. See the
/// module's words.
#[derive(Debug)]
pub struct PcWatcher {
    ice: IceState,
    pc: PcState,
    dtls_up: bool,
    was_connected: bool,
    /// When a disconnected ICE path becomes a failed one.
    failing: Option<Instant>,
    /// The peer said its last path is gone ([`PeerEvent::Failed`]): no ICE
    /// state that follows takes the deadline back.
    lost_for_good: bool,
}

impl Default for PcWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PcWatcher {
    /// A watcher for a peer connection that has not started.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ice: IceState::New,
            pc: PcState::New,
            dtls_up: false,
            was_connected: false,
            failing: None,
            lost_for_good: false,
        }
    }

    /// The peer connection's state now.
    #[must_use]
    pub const fn state(&self) -> PcState {
        self.pc
    }

    /// The ICE state now.
    #[must_use]
    pub const fn ice_state(&self) -> IceState {
        self.ice
    }

    /// Whether the peer connection has been `connected` at any time: a
    /// carrier's `Connect` fails on a `failed` or `closed` that comes before
    /// it, and rejoins on one that comes after.
    #[must_use]
    pub const fn was_connected(&self) -> bool {
        self.was_connected
    }

    /// Takes one of the peer's events, says pion's lines for what it
    /// changed and returns the change. Events that carry no state (data,
    /// channels, candidates, keyframe requests) change nothing.
    pub fn observe(&mut self, ev: &PeerEvent) -> Change {
        let change = match ev {
            PeerEvent::IceState(s) => self.ice_moved((*s).into()),
            PeerEvent::Connected => self.dtls_came_up(),
            PeerEvent::Closed(_) => self.closed(),
            PeerEvent::Failed(_) => {
                // `failed` says it, so the owner has one place to rejoin
                // from: its deadline is now.
                if !self.ended() {
                    self.failing = Some(Instant::now());
                    self.lost_for_good = true;
                }
                Change::default()
            }
            PeerEvent::LocalCandidate(_)
            | PeerEvent::ChannelOpen(..)
            | PeerEvent::Data(_)
            | PeerEvent::ChannelClose(_)
            | PeerEvent::KeyframeRequest(_) => Change::default(),
        };
        change.log();
        change
    }

    /// Waits until a disconnected ICE path has been so for
    /// [`ICE_FAILED_AFTER`], or the peer said its last path is gone
    /// ([`PeerEvent::Failed`]), then says `failed` on both lines and returns
    /// the change. It never returns while there is no such path, and
    /// returns once per peer connection.
    ///
    /// Cancel safe: the deadline is the watcher's, not the future's, so it
    /// can be one arm of a `select!` beside the peer's event receiver.
    pub async fn failed(&mut self) -> Change {
        let Some(at) = self.failing else {
            return std::future::pending().await;
        };
        tokio::time::sleep_until(at).await;
        self.failing = None;
        self.ice = IceState::Failed;
        let change = Change {
            ice: Some(IceState::Failed),
            pc: self.pc_moved(),
        };
        change.log();
        change
    }

    /// Whether nothing but `closed` may follow.
    const fn ended(&self) -> bool {
        matches!(self.ice, IceState::Failed | IceState::Closed)
    }

    fn ice_moved(&mut self, to: IceState) -> Change {
        if self.ended() || to == self.ice {
            return Change::default();
        }
        self.ice = to;
        match to {
            // A second `disconnected` after a spell of checking keeps the
            // first one's deadline: only a working pair clears it.
            IceState::Disconnected => {
                if self.failing.is_none() {
                    self.failing = Some(Instant::now() + ICE_FAILED_AFTER);
                }
            }
            IceState::Connected if !self.lost_for_good => {
                self.failing = None;
            }
            _ => {}
        }
        Change {
            ice: Some(to),
            pc: self.pc_moved(),
        }
    }

    fn dtls_came_up(&mut self) -> Change {
        if self.ended() || self.dtls_up {
            return Change::default();
        }
        self.dtls_up = true;
        Change {
            ice: None,
            pc: self.pc_moved(),
        }
    }

    fn closed(&mut self) -> Change {
        if self.ice == IceState::Closed {
            return Change::default();
        }
        self.failing = None;
        self.ice = IceState::Closed;
        Change {
            ice: Some(IceState::Closed),
            pc: self.pc_moved(),
        }
    }

    /// pion's rule for the peer connection's state from the ICE and DTLS
    /// ones (`updateConnectionState`), for one transport of each. Returns
    /// the state when it is not the one already told.
    fn pc_moved(&mut self) -> Option<PcState> {
        let to = match self.ice {
            IceState::Closed => PcState::Closed,
            IceState::Failed => PcState::Failed,
            IceState::Disconnected => PcState::Disconnected,
            IceState::New if !self.dtls_up => PcState::New,
            IceState::Connected if self.dtls_up => PcState::Connected,
            IceState::New | IceState::Checking | IceState::Connected => PcState::Connecting,
        };
        if to == self.pc {
            return None;
        }
        self.pc = to;
        if to == PcState::Connected {
            self.was_connected = true;
        }
        Some(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn ice(w: &mut PcWatcher, s: IceConnectionState) -> Change {
        w.observe(&PeerEvent::IceState(s))
    }

    fn both(ice: IceState, pc: PcState) -> Change {
        Change {
            ice: Some(ice),
            pc: Some(pc),
        }
    }

    fn ice_only(ice: IceState) -> Change {
        Change {
            ice: Some(ice),
            pc: None,
        }
    }

    fn pc_only(pc: PcState) -> Change {
        Change {
            ice: None,
            pc: Some(pc),
        }
    }

    /// A watcher whose peer connection is connected.
    fn connected() -> PcWatcher {
        let mut w = PcWatcher::new();
        ice(&mut w, IceConnectionState::Checking);
        ice(&mut w, IceConnectionState::Connected);
        w.observe(&PeerEvent::Connected);
        assert_eq!(w.state(), PcState::Connected);
        w
    }

    /// Whether `failed` returns within `within`.
    async fn fails_within(w: &mut PcWatcher, within: Duration) -> Option<Change> {
        tokio::time::timeout(within, w.failed()).await.ok()
    }

    /// The apps match these bytes (Go: pion's `pc` logger through
    /// `PionLoggerFactory`).
    #[test]
    fn the_lines_are_pions() {
        assert_eq!(
            both(IceState::Connected, PcState::Connected).lines(),
            [
                Some("[pc] INFO: ICE connection state changed: connected".to_owned()),
                Some("[pc] INFO: peer connection state changed: connected".to_owned()),
            ]
        );
        assert_eq!(
            pc_only(PcState::Closed).lines(),
            [
                None,
                Some("[pc] INFO: peer connection state changed: closed".to_owned())
            ]
        );
        assert_eq!(Change::default().lines(), [None, None]);
    }

    #[test]
    fn the_states_take_pions_words() {
        for (s, word) in [
            (IceConnectionState::New, "new"),
            (IceConnectionState::Checking, "checking"),
            (IceConnectionState::Connected, "connected"),
            (IceConnectionState::Completed, "connected"),
            (IceConnectionState::Disconnected, "disconnected"),
        ] {
            assert_eq!(IceState::from(s).as_str(), word);
        }
        assert_eq!(IceState::Failed.to_string(), "failed");
        assert_eq!(IceState::Closed.to_string(), "closed");
        for (s, word) in [
            (PcState::New, "new"),
            (PcState::Connecting, "connecting"),
            (PcState::Connected, "connected"),
            (PcState::Disconnected, "disconnected"),
            (PcState::Failed, "failed"),
            (PcState::Closed, "closed"),
        ] {
            assert_eq!(s.to_string(), word);
        }
    }

    /// pion's agent never reports `completed` (the state is defined and
    /// never set), so the Go client's log has no such line: a pair that
    /// works is `connected`, said once, whichever of str0m's two states
    /// comes first.
    #[test]
    fn str0ms_completed_is_pions_connected() {
        let mut w = PcWatcher::new();
        ice(&mut w, IceConnectionState::Checking);
        let change = ice(&mut w, IceConnectionState::Completed);
        assert_eq!(change, ice_only(IceState::Connected));
        assert_eq!(
            change.lines()[0].as_deref(),
            Some("[pc] INFO: ICE connection state changed: connected")
        );
        assert_eq!(
            w.observe(&PeerEvent::Connected),
            pc_only(PcState::Connected)
        );
        let mut w = PcWatcher::new();
        ice(&mut w, IceConnectionState::Checking);
        assert_eq!(
            ice(&mut w, IceConnectionState::Connected),
            ice_only(IceState::Connected)
        );
        assert_eq!(
            ice(&mut w, IceConnectionState::Completed),
            Change::default()
        );
        assert_eq!(
            ice(&mut w, IceConnectionState::Connected),
            Change::default()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_join_tells_each_change_once() {
        let mut w = PcWatcher::new();
        assert_eq!(w.state(), PcState::New);
        assert_eq!(ice(&mut w, IceConnectionState::New), Change::default());
        assert_eq!(
            ice(&mut w, IceConnectionState::Checking),
            both(IceState::Checking, PcState::Connecting)
        );
        // ICE has a pair, DTLS is not up: still connecting, as in pion.
        assert_eq!(
            ice(&mut w, IceConnectionState::Connected),
            ice_only(IceState::Connected)
        );
        assert!(!w.was_connected());
        assert_eq!(
            w.observe(&PeerEvent::Connected),
            pc_only(PcState::Connected)
        );
        assert!(w.was_connected());
        // The same state again is no change, and no line; str0m's
        // `Completed` is the same state.
        assert_eq!(
            ice(&mut w, IceConnectionState::Completed),
            Change::default()
        );
        assert_eq!(w.observe(&PeerEvent::Connected), Change::default());
        // Events without a state.
        assert_eq!(
            w.observe(&PeerEvent::LocalCandidate("candidate:1".into())),
            Change::default()
        );
        assert_eq!(w.state(), PcState::Connected);
        assert_eq!(w.ice_state(), IceState::Connected);
        // Connected: nothing is failing.
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn disconnected_for_25_s_is_failed_once() {
        let mut w = connected();
        assert_eq!(
            ice(&mut w, IceConnectionState::Disconnected),
            both(IceState::Disconnected, PcState::Disconnected)
        );
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER - MS).await, None);
        assert_eq!(w.state(), PcState::Disconnected);
        assert_eq!(
            fails_within(&mut w, MS * 2).await,
            Some(both(IceState::Failed, PcState::Failed))
        );
        assert_eq!(w.state(), PcState::Failed);
        assert_eq!(w.ice_state(), IceState::Failed);
        assert!(w.was_connected());
        // Once per peer connection.
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
    }

    /// Plan D7: the peer's word that its last path (an ICE-TCP connection)
    /// broke is `failed` at once, on both lines, once; no ICE state that
    /// str0m still reports afterwards takes it back or says more.
    #[tokio::test(start_paused = true)]
    async fn a_lost_last_path_is_failed_at_once() {
        let mut w = connected();
        assert_eq!(
            w.observe(&PeerEvent::Failed(
                "ice tcp 192.0.2.1:443: read: EOF".into()
            )),
            Change::default()
        );
        // A state str0m had queued before it noticed.
        ice(&mut w, IceConnectionState::Connected);
        assert_eq!(
            fails_within(&mut w, MS).await,
            Some(both(IceState::Failed, PcState::Failed))
        );
        assert!(w.was_connected());
        assert_eq!(
            ice(&mut w, IceConnectionState::Disconnected),
            Change::default()
        );
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
        assert_eq!(
            w.observe(&PeerEvent::Closed("closed".into())),
            both(IceState::Closed, PcState::Closed)
        );
        // Before the first connect too (a carrier's `Connect` fails on it).
        let mut w = PcWatcher::new();
        ice(&mut w, IceConnectionState::Checking);
        w.observe(&PeerEvent::Failed("gone".into()));
        assert_eq!(
            fails_within(&mut w, MS).await,
            Some(both(IceState::Failed, PcState::Failed))
        );
        assert!(!w.was_connected());
        // After the end nothing is said.
        let mut w = connected();
        w.observe(&PeerEvent::Closed("closed".into()));
        w.observe(&PeerEvent::Failed("gone".into()));
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_path_that_comes_back_in_time_is_connected_again() {
        let mut w = connected();
        ice(&mut w, IceConnectionState::Disconnected);
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER - MS).await, None);
        assert_eq!(
            ice(&mut w, IceConnectionState::Connected),
            both(IceState::Connected, PcState::Connected)
        );
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
        // The next loss has 25 s of its own.
        assert_eq!(
            ice(&mut w, IceConnectionState::Disconnected),
            both(IceState::Disconnected, PcState::Disconnected)
        );
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER - MS).await, None);
        assert_eq!(
            fails_within(&mut w, MS * 2).await,
            Some(both(IceState::Failed, PcState::Failed))
        );
    }

    /// str0m's agent may go from disconnected back to checking (a new pair
    /// to try) and to disconnected again: only a working pair stops the
    /// clock.
    #[tokio::test(start_paused = true)]
    async fn checking_does_not_restart_the_25_s() {
        let mut w = connected();
        ice(&mut w, IceConnectionState::Disconnected);
        assert_eq!(fails_within(&mut w, Duration::from_secs(10)).await, None);
        assert_eq!(
            ice(&mut w, IceConnectionState::Checking),
            both(IceState::Checking, PcState::Connecting)
        );
        assert_eq!(fails_within(&mut w, Duration::from_secs(10)).await, None);
        assert_eq!(
            ice(&mut w, IceConnectionState::Disconnected),
            both(IceState::Disconnected, PcState::Disconnected)
        );
        // 20 s gone of the first loss's 25.
        assert_eq!(
            fails_within(&mut w, Duration::from_secs(5) - MS).await,
            None
        );
        assert_eq!(
            fails_within(&mut w, MS * 2).await,
            Some(both(IceState::Failed, PcState::Failed))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_connected_fails_too() {
        let mut w = PcWatcher::new();
        ice(&mut w, IceConnectionState::Checking);
        // `is`: "no possible pairs".
        assert_eq!(
            ice(&mut w, IceConnectionState::Disconnected),
            both(IceState::Disconnected, PcState::Disconnected)
        );
        assert_eq!(
            fails_within(&mut w, ICE_FAILED_AFTER + MS).await,
            Some(both(IceState::Failed, PcState::Failed))
        );
        assert!(!w.was_connected());
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_follows_failed_but_closed() {
        let mut w = connected();
        ice(&mut w, IceConnectionState::Disconnected);
        assert!(fails_within(&mut w, ICE_FAILED_AFTER + MS).await.is_some());
        // The path comes back after all: pion's agent would not say so.
        assert_eq!(
            ice(&mut w, IceConnectionState::Connected),
            Change::default()
        );
        assert_eq!(
            ice(&mut w, IceConnectionState::Disconnected),
            Change::default()
        );
        assert_eq!(w.observe(&PeerEvent::Connected), Change::default());
        assert_eq!(w.state(), PcState::Failed);
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
        assert_eq!(
            w.observe(&PeerEvent::Closed("the owner closed".into())),
            both(IceState::Closed, PcState::Closed)
        );
        // And nothing follows closed.
        assert_eq!(
            w.observe(&PeerEvent::Closed("again".into())),
            Change::default()
        );
        assert_eq!(ice(&mut w, IceConnectionState::Checking), Change::default());
        assert_eq!(w.state(), PcState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_close_ends_a_pending_failure() {
        let mut w = connected();
        ice(&mut w, IceConnectionState::Disconnected);
        assert_eq!(
            w.observe(&PeerEvent::Closed("the remote closed".into())),
            both(IceState::Closed, PcState::Closed)
        );
        assert_eq!(fails_within(&mut w, ICE_FAILED_AFTER * 4).await, None);
        assert_eq!(w.state(), PcState::Closed);

        // Closed before anything else.
        let mut w = PcWatcher::new();
        assert_eq!(
            w.observe(&PeerEvent::Closed("no socket".into())),
            both(IceState::Closed, PcState::Closed)
        );
        assert!(!w.was_connected());
    }

    /// One per peer connection, inside its owner's task: two states, two
    /// flags and a deadline.
    #[test]
    fn a_watcher_stays_small() {
        assert!(
            size_of::<PcWatcher>() <= 24,
            "PcWatcher is {} bytes",
            size_of::<PcWatcher>()
        );
    }
}

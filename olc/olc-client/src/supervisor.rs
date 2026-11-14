// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The room supervisor (`internal/supervisor`, as `mobile/runtime.go` runs
//! it): the rooms are walked in order, the primary first; when the room a
//! session is in ends (the server retired it, or it died, or it was empty
//! while another room waits) the next is tried after [`RETRY_DELAY`]. One
//! forward pass ([`MAX_CYCLES`]) and the run ends with an error: the host
//! owns the retry loop. With a [`Reload`] the list is the host's and is
//! asked again at every hop, never during a session (`Config.Reload`): a
//! room added while a session is live is used when that session ends, and a
//! list that rolled past the room just left starts again at its head. A pass where no room held a session for
//! [`PROFILE_HELD_FOR`] doubles the pause, at most [`MAX_RETRY_DELAY`].

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::client::{Client, SessionListener};
use crate::config::Config;

/// The pause between rooms (`failoverRetryDelay`).
pub const RETRY_DELAY: Duration = Duration::from_secs(2);
/// One forward pass (`failoverMaxCycles`).
pub const MAX_CYCLES: u32 = 1;
/// A room that held a session this long counts as held (`profileHeldFor`).
pub const PROFILE_HELD_FOR: Duration = Duration::from_secs(60);
/// The longest pause (`maxRetryDelay`).
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);
/// The pause doubles at most this many times (`maxRetryBackoff`).
pub const MAX_RETRY_BACKOFF: u32 = 8;

/// Why the walk ended.
#[derive(Debug, thiserror::Error)]
pub enum SuperviseError {
    /// `ErrNoProfiles`.
    #[error("supervisor: no profiles configured")]
    NoRooms,
    /// `ErrMaxCyclesExceeded`, with the last room's end.
    #[error(
        "supervisor: max failover cycles exceeded after {cycles} cycle(s): profile {room:?}: {why}"
    )]
    MaxCycles {
        /// Passes made.
        cycles: u32,
        /// The last room.
        room: String,
        /// How it ended.
        why: String,
    },
}

/// The rooms in order: `url` first, then `rooms` (`defaults.rooms()`).
pub fn rooms(cfg: &Config) -> Vec<String> {
    let mut out = Vec::with_capacity(1 + cfg.rooms.len());
    if !cfg.url.is_empty() {
        out.push(cfg.url.clone());
    }
    for r in &cfg.rooms {
        if !r.is_empty() && !out.contains(r) {
            out.push(r.clone());
        }
    }
    out
}

/// Where the walk is (`lastProfile`): the room that ran last, by name and
/// by its place in the list it ran from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Last {
    name: String,
    index: usize,
}

/// `nextStep`: the room after `last`, and whether getting there went past
/// the end of the list (one pass, what [`MAX_CYCLES`] counts). The room that
/// ran is found by name, searching from where it ran, so the list may roll
/// underneath the walk and names may repeat; a list that no longer holds it
/// rolled past it, so its head is next and no pass ended.
fn next_step(rooms: &[String], last: Option<&Last>) -> (usize, bool) {
    let Some(last) = last else {
        return (0, false);
    };
    let n = rooms.len();
    for offset in 0..n {
        let i = (last.index + offset) % n;
        if rooms[i] == last.name {
            return ((i + 1) % n, i + 1 == n);
        }
    }
    (0, false)
}

/// `profileList`: the rolling list the walk follows. With a reload it is
/// asked again on every access; an empty answer keeps the last list, so a
/// bad write never leaves the walk with nowhere to go.
struct RoomList {
    current: Vec<String>,
    reload: Option<Reload>,
}

impl RoomList {
    fn refresh(&mut self) -> &[String] {
        if let Some(reload) = &self.reload {
            let next = reload();
            if !next.is_empty() {
                self.current = next;
            }
        }
        &self.current
    }
}

/// `profilePace`.
#[derive(Debug, Default)]
struct Pace {
    dead_cycles: u32,
    held: bool,
}

impl Pace {
    fn wait(&mut self, base: Duration, pass_complete: bool) -> Duration {
        if pass_complete {
            if self.held {
                self.dead_cycles = 0;
            } else {
                self.dead_cycles += 1;
            }
            self.held = false;
        }
        if self.dead_cycles == 0 {
            return base;
        }
        base.saturating_mul(1 << self.dead_cycles.min(MAX_RETRY_BACKOFF))
            .min(MAX_RETRY_DELAY)
    }
}

/// The host's room list, asked again at every hop (`Config.Reload` over the
/// mobile runtime's `profilesSnapshot`).
pub type Reload = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// How one room's run ended: `Ok` for a clean end, else the error's text.
pub type RoomEnd = Result<(), String>;

/// Walks the rooms of `cfg` until `stop`; `on_ready` is told each room's
/// SOCKS address as it listens.
///
/// # Errors
/// [`SuperviseError`].
pub async fn run(
    cfg: Config,
    stop: CancellationToken,
    on_ready: Arc<dyn Fn(SocketAddr) + Send + Sync>,
    on_session_open: Option<SessionListener>,
) -> Result<(), SuperviseError> {
    let list = rooms(&cfg);
    let base = cfg.clone();
    let token = stop.clone();
    walk(list, None, &stop, move |room, end_on_empty_room| {
        let mut run_cfg = base.clone();
        run_cfg.url = room;
        run_cfg.rooms.clear();
        run_cfg.end_on_empty_room = end_on_empty_room;
        let ready = on_ready.clone();
        let listener = on_session_open.clone();
        let child = token.child_token();
        async move {
            Client::run_with(run_cfg, child, move |a| ready(a), listener)
                .await
                .map_err(|e| e.to_string())
        }
    })
    .await
}

/// The walk itself (`supervisor.Run`): `run_room(room, end_on_empty_room)`
/// runs one room until it ends. `reload`, when given, is the host's list.
///
/// # Errors
/// [`SuperviseError`].
pub async fn walk<F, Fut>(
    initial: Vec<String>,
    reload: Option<Reload>,
    stop: &CancellationToken,
    run_room: F,
) -> Result<(), SuperviseError>
where
    F: FnMut(String, bool) -> Fut,
    Fut: Future<Output = RoomEnd>,
{
    walk_paced(initial, reload, stop, RETRY_DELAY, run_room).await
}

/// [`walk`] with its own pause between rooms in place of [`RETRY_DELAY`]
/// (`Config.RetryDelay`; the mobile runtime's tests shorten it, as Go's
/// `failoverRetryDelay` hook does). Zero is [`RETRY_DELAY`].
///
/// # Errors
/// [`SuperviseError`].
pub async fn walk_paced<F, Fut>(
    initial: Vec<String>,
    reload: Option<Reload>,
    stop: &CancellationToken,
    retry_delay: Duration,
    mut run_room: F,
) -> Result<(), SuperviseError>
where
    F: FnMut(String, bool) -> Fut,
    Fut: Future<Output = RoomEnd>,
{
    // A zero delay is a busy loop against a room that fails at once.
    let retry_delay = if retry_delay.is_zero() {
        RETRY_DELAY
    } else {
        retry_delay
    };
    let mut list = RoomList {
        current: initial,
        reload,
    };
    if list.refresh().is_empty() {
        return Err(SuperviseError::NoRooms);
    }
    let mut pace = Pace::default();
    let mut last: Option<Last> = None;
    let mut cycle = 1u32;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        // Never empty: the first refresh had rooms and an empty answer keeps
        // them (Go's empty-list wait cannot be reached either).
        let rooms = list.refresh();
        let (idx, wrapped) = next_step(rooms, last.as_ref());
        if wrapped {
            cycle += 1;
        }
        let room = rooms[idx].clone();
        last = Some(Last {
            name: room.clone(),
            index: idx,
        });
        crate::info!("failover cycle={cycle} starting room={room}");
        // Read as this room starts (`EndOnEmptyRoom = r.roomCount() > 1`): a
        // room the host appends is in force from the next start on, and with
        // one room there is nowhere to give up to.
        let end_on_empty_room = list.refresh().len() > 1;
        let started = Instant::now();
        let ended = run_room(room.clone(), end_on_empty_room).await;
        if stop.is_cancelled() {
            return Ok(());
        }
        if started.elapsed() >= PROFILE_HELD_FOR {
            pace.held = true;
        }
        let why = match ended {
            Ok(()) => {
                crate::info!("failover cycle={cycle} room={room} ended");
                "profile ended".to_owned()
            }
            Err(e) => {
                crate::info!("failover cycle={cycle} room={room} ended with error: {e}");
                e
            }
        };
        // Judged against the list as it is now, not as it was when this room
        // started, and before the pause, so a list with nowhere left to go
        // fails fast.
        let (_, done) = next_step(list.refresh(), last.as_ref());
        if cycle >= MAX_CYCLES && done {
            return Err(SuperviseError::MaxCycles {
                cycles: cycle,
                room,
                why,
            });
        }
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep(pace.wait(retry_delay, done)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rooms_walk_forward_once_and_the_pace_doubles_on_dead_passes() {
        let abc = names(&["a", "b", "c"]);
        let at = |name: &str, index| Last {
            name: name.to_owned(),
            index,
        };
        assert_eq!(next_step(&abc, None), (0, false));
        assert_eq!(next_step(&abc, Some(&at("a", 0))), (1, false));
        assert_eq!(next_step(&abc, Some(&at("c", 2))), (0, true));
        // Found by name wherever it moved, and not found: the head, no pass.
        assert_eq!(next_step(&abc, Some(&at("b", 0))), (2, false));
        assert_eq!(next_step(&abc, Some(&at("gone", 1))), (0, false));
        // A repeated name is found from where it ran.
        let same = names(&["x", "x"]);
        assert_eq!(next_step(&same, Some(&at("x", 1))), (0, true));
        assert_eq!(next_step(&[], Some(&at("x", 0))), (0, false));
        let mut p = Pace::default();
        assert_eq!(p.wait(RETRY_DELAY, false), RETRY_DELAY);
        assert_eq!(p.wait(RETRY_DELAY, true), RETRY_DELAY * 2);
        assert_eq!(p.wait(RETRY_DELAY, true), RETRY_DELAY * 4);
        p.held = true;
        assert_eq!(p.wait(RETRY_DELAY, true), RETRY_DELAY);
        for _ in 0..20 {
            p.wait(RETRY_DELAY, true);
        }
        assert_eq!(p.wait(RETRY_DELAY, false), MAX_RETRY_DELAY);
    }

    #[test]
    fn the_primary_room_comes_first() {
        let cfg = Config::from_json(br#"{"url":"a","rooms":["b","a","c"],"key":"k"}"#).unwrap();
        assert_eq!(rooms(&cfg), ["a", "b", "c"]);
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// What the host's list is, shared with the rooms' runs.
    #[derive(Clone, Default)]
    struct Host(Arc<std::sync::Mutex<Vec<String>>>);

    impl Host {
        fn new(list: &[&str]) -> Self {
            Self(Arc::new(std::sync::Mutex::new(names(list))))
        }
        fn set(&self, list: &[&str]) {
            *self.0.lock().unwrap() = names(list);
        }
        fn get(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
        fn reload(&self) -> Reload {
            let me = self.clone();
            Arc::new(move || me.get())
        }
    }

    /// Runs `walk` over `host`'s list; `each(n, room, end_on_empty)` is called
    /// as the n-th room (from 0) starts and says how it ends. The rooms run,
    /// with their `end_on_empty_room`, and the walk's end come back.
    async fn walk_host(
        host: &Host,
        stop: &CancellationToken,
        mut each: impl FnMut(usize, &str, bool) -> RoomEnd,
    ) -> (Vec<(String, bool)>, Result<(), SuperviseError>) {
        let ran = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = ran.clone();
        let end = walk(host.get(), Some(host.reload()), stop, |room, empty| {
            let n = {
                let mut ran = seen.lock().unwrap();
                ran.push((room.clone(), empty));
                ran.len() - 1
            };
            let out = each(n, &room, empty);
            async move { out }
        })
        .await;
        let ran = ran.lock().unwrap().clone();
        (ran, end)
    }

    fn rooms_of(ran: &[(String, bool)]) -> Vec<&str> {
        ran.iter().map(|(r, _)| r.as_str()).collect()
    }

    /// TestRunDynamicReloadFollowsRollingWindow: once the room just left is
    /// out of the list the walk lands on the new head, so R1..R5 run although
    /// each was added only after the one before it started.
    #[tokio::test(start_paused = true)]
    async fn the_walk_follows_a_rolling_window() {
        crate::testing::bounded_for(Duration::from_secs(600), async {
            let windows: [&[&str]; 5] = [
                &["R1"],
                &["R1", "R2"],
                &["R2", "R3"],
                &["R3", "R4"],
                &["R4", "R5"],
            ];
            let host = Host::new(windows[0]);
            let stop = CancellationToken::new();
            let (ran, end) = walk_host(&host, &stop, |n, _, _| {
                host.set(windows[(n + 1).min(windows.len() - 1)]);
                if n + 1 == windows.len() {
                    stop.cancel();
                }
                Ok(())
            })
            .await;
            assert!(end.is_ok(), "{end:?}");
            assert_eq!(rooms_of(&ran), ["R1", "R2", "R3", "R4", "R5"]);
        })
        .await;
    }

    /// TestRunMaxCyclesCountsProfilesAddedDuringThePass: a room appended while
    /// the only room runs is part of this pass, so one pass tries it before
    /// the walk gives up; that is how a host hands a live client its next
    /// room.
    #[tokio::test(start_paused = true)]
    async fn a_room_added_during_a_session_is_tried_in_the_same_pass() {
        crate::testing::bounded_for(Duration::from_secs(600), async {
            let host = Host::new(&["R1"]);
            let stop = CancellationToken::new();
            let (ran, end) = walk_host(&host, &stop, |n, _, _| {
                if n == 0 {
                    host.set(&["R1", "R2"]);
                }
                Err("boom".to_owned())
            })
            .await;
            assert_eq!(rooms_of(&ran), ["R1", "R2"]);
            match end {
                Err(SuperviseError::MaxCycles { cycles, room, why }) => {
                    assert_eq!((cycles, room.as_str(), why.as_str()), (1, "R2", "boom"));
                }
                other => panic!("{other:?}"),
            }
        })
        .await;
    }

    /// TestRunKeepsTheLastListWhenReloadFails: an empty answer keeps the last
    /// list, so a bad write never strands the walk.
    #[tokio::test(start_paused = true)]
    async fn an_empty_reload_keeps_the_last_list() {
        crate::testing::bounded_for(Duration::from_secs(600), async {
            let stop = CancellationToken::new();
            let ran = Arc::new(std::sync::Mutex::new(Vec::new()));
            let seen = ran.clone();
            let end = walk(
                names(&["R1", "R2"]),
                Some(Arc::new(Vec::new)),
                &stop,
                |room, _| {
                    seen.lock().unwrap().push(room);
                    async { Err("boom".to_owned()) }
                },
            )
            .await;
            assert!(
                matches!(end, Err(SuperviseError::MaxCycles { .. })),
                "{end:?}"
            );
            assert_eq!(*ran.lock().unwrap(), ["R1", "R2"]);
        })
        .await;
    }

    /// TestRunStatusKeepsProfilesDroppedOnReload's walk, and nextStep's
    /// rolled list: the room just left is gone, so the head runs next and no
    /// pass is counted for a list never finished.
    #[tokio::test(start_paused = true)]
    async fn a_list_rolled_past_the_room_just_left_starts_at_its_head() {
        crate::testing::bounded_for(Duration::from_secs(600), async {
            let host = Host::new(&["R1", "R2"]);
            let stop = CancellationToken::new();
            let (ran, end) = walk_host(&host, &stop, |n, _, _| {
                if n == 0 {
                    host.set(&["R2", "R3"]);
                }
                Err("boom".to_owned())
            })
            .await;
            assert_eq!(rooms_of(&ran), ["R1", "R2", "R3"]);
            match end {
                Err(SuperviseError::MaxCycles { cycles, room, .. }) => {
                    assert_eq!((cycles, room.as_str()), (1, "R3"));
                }
                other => panic!("{other:?}"),
            }
        })
        .await;
    }

    /// TestASecondRoomLetsTheNextStartGiveUpOnAnEmptyRoom, at the walk: the
    /// count behind `end_on_empty_room` is read as each room starts, so a
    /// room the host appends is in force from the next start on.
    #[tokio::test(start_paused = true)]
    async fn giving_up_on_an_empty_room_is_decided_at_each_start() {
        crate::testing::bounded_for(Duration::from_secs(600), async {
            let host = Host::new(&["R1"]);
            let stop = CancellationToken::new();
            let (ran, _) = walk_host(&host, &stop, |n, _, _| {
                if n == 0 {
                    host.set(&["R1", "R2"]);
                }
                Err("boom".to_owned())
            })
            .await;
            assert_eq!(
                ran,
                [("R1".to_owned(), false), ("R2".to_owned(), true)],
                "R1 started alone; R2 started with a room to give up to"
            );
        })
        .await;
    }

    /// TestRunWalksProfilesWhoseNamesRepeat: two entries with one name are
    /// two rooms; the walk finds where it is before it looks the name up.
    #[tokio::test(start_paused = true)]
    async fn rooms_whose_names_repeat_are_each_walked() {
        crate::testing::bounded_for(Duration::from_secs(600), async {
            let stop = CancellationToken::new();
            let list = names(&["same", "same"]);
            let reload: Reload = {
                let list = list.clone();
                Arc::new(move || list.clone())
            };
            let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = runs.clone();
            let end = walk(list, Some(reload), &stop, |_, _| {
                if count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 2 {
                    stop.cancel();
                }
                async { Err("boom".to_owned()) }
            })
            .await;
            assert!(
                matches!(end, Err(SuperviseError::MaxCycles { .. })),
                "{end:?}"
            );
            assert_eq!(runs.load(std::sync::atomic::Ordering::Relaxed), 2);
        })
        .await;
    }

    /// Cancelling during a room's run ends the walk cleanly
    /// (TestRunReturnsNilOnContextCancel).
    #[tokio::test(start_paused = true)]
    async fn a_stop_ends_the_walk_cleanly() {
        crate::testing::bounded(async {
            let host = Host::new(&["R1", "R2"]);
            let stop = CancellationToken::new();
            let (ran, end) = walk_host(&host, &stop, |_, _, _| {
                stop.cancel();
                Err("cancelled".to_owned())
            })
            .await;
            assert!(end.is_ok(), "{end:?}");
            assert_eq!(rooms_of(&ran), ["R1"]);
        })
        .await;
    }

    #[tokio::test]
    async fn no_rooms_is_an_error() {
        crate::testing::bounded(no_rooms_is_an_error_body()).await;
    }

    async fn no_rooms_is_an_error_body() {
        let cfg = Config::from_json(br#"{"url":"","key":"k"}"#).unwrap();
        let err = run(cfg, CancellationToken::new(), Arc::new(|_| {}), None)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "supervisor: no profiles configured");
    }
}

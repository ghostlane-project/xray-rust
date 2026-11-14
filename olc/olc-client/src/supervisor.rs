// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The room supervisor (`internal/supervisor`, as `mobile/runtime.go` runs
//! it): the rooms are walked in order, the primary first; when the room a
//! session is in ends (the server retired it, or it died, or it was empty
//! while another room waits) the next is tried after [`RETRY_DELAY`]. One
//! forward pass ([`MAX_CYCLES`]) and the run ends with an error: the host
//! owns the retry loop. A pass where no room held a session for
//! [`PROFILE_HELD_FOR`] doubles the pause, at most [`MAX_RETRY_DELAY`].

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
    #[error("supervisor: max failover cycles exceeded after {cycles} cycle(s): profile {room:?}: {why}")]
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

/// `nextStep`: the room after `last`, and whether that wraps the pass.
fn next_step(n: usize, last: Option<usize>) -> (usize, bool) {
    match last {
        None => (0, false),
        Some(i) => ((i + 1) % n, i + 1 == n),
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
    if list.is_empty() {
        return Err(SuperviseError::NoRooms);
    }
    let mut pace = Pace::default();
    let mut last = None;
    let mut cycle = 1u32;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let (idx, wrapped) = next_step(list.len(), last);
        if wrapped {
            cycle += 1;
        }
        last = Some(idx);
        let room = &list[idx];
        crate::info!("failover cycle={cycle} starting room={room}");
        let mut run_cfg = cfg.clone();
        run_cfg.url.clone_from(room);
        run_cfg.rooms.clear();
        run_cfg.end_on_empty_room = list.len() > 1;
        let started = Instant::now();
        let ready = on_ready.clone();
        let ended = Client::run_with(run_cfg, stop.child_token(), move |a| ready(a), on_session_open.clone()).await;
        if stop.is_cancelled() {
            return Ok(());
        }
        if started.elapsed() >= PROFILE_HELD_FOR {
            pace.held = true;
        }
        let why = match &ended {
            Ok(()) => {
                crate::info!("failover cycle={cycle} room={room} ended");
                "profile ended".to_owned()
            }
            Err(e) => {
                crate::info!("failover cycle={cycle} room={room} ended with error: {e}");
                e.to_string()
            }
        };
        let (_, done) = next_step(list.len(), last);
        if cycle >= MAX_CYCLES && done {
            return Err(SuperviseError::MaxCycles {
                cycles: cycle,
                room: room.clone(),
                why,
            });
        }
        tokio::select! {
            () = stop.cancelled() => return Ok(()),
            () = tokio::time::sleep(pace.wait(RETRY_DELAY, done)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rooms_walk_forward_once_and_the_pace_doubles_on_dead_passes() {
        assert_eq!(next_step(3, None), (0, false));
        assert_eq!(next_step(3, Some(0)), (1, false));
        assert_eq!(next_step(3, Some(2)), (0, true));
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

    #[tokio::test]
    async fn no_rooms_is_an_error() {
        crate::testing::bounded(no_rooms_is_an_error_body()).await;
    }

    async fn no_rooms_is_an_error_body() {
        let cfg = Config::from_json(br#"{"url":"","key":"k"}"#).unwrap();
        let err = run(cfg, CancellationToken::new(), Arc::new(|_| {}), None).await.unwrap_err();
        assert_eq!(err.to_string(), "supervisor: no profiles configured");
    }
}

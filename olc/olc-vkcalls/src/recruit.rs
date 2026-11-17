// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The wait for SERVER topology and the guests that end it (`recruit.go`,
//! `waitConnected` of `vkcalls.go`).
//!
//! A fresh VK room keeps its first participants in DIRECT: two alone never
//! switch, and a third simultaneous participant is what flips the SFU to
//! SERVER, which then sticks for the room's lifetime. While the engine
//! waits in DIRECT it therefore joins signalling-only guests of its own and
//! drops them the moment the wait is over.
//!
//! Every guest leaves with a hangup ([`Signaling::close`]), however the wait
//! ends: the switch, the socket going, the caller's stop, or the caller's
//! future dropped in the middle (the recruiter runs in a task of its own,
//! which sees its owner go).
//!
//! Memory: [`MAX_RECRUITS`] guests at most, each a signalling socket whose
//! notifications are read and let go as they come
//! ([`crate::signaling::READ_PEAK`] while one is decoded), and one
//! credential chain at a time ([`crate::auth::REPLY_LIMIT`]). Nothing of a
//! guest is kept but its socket.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::auth::{self, Credentials};
use crate::signaling::{DialOptions, Notification, Notifications, Signaling, SignalingError};

/// How many guests the engine adds besides itself (`maxRecruits`): one
/// already makes three with the waiting peer, two cover the case the peer
/// has not joined yet.
pub const MAX_RECRUITS: usize = 2;
/// Lets the waiting peer join first, so its own connection already counts
/// toward the three (`recruitFirstDelay`).
pub const RECRUIT_FIRST_DELAY: Duration = Duration::from_secs(2);
/// Spaces the joins: the flip lands on a join, and a burst buys nothing
/// (`recruitNextDelay`).
pub const RECRUIT_NEXT_DELAY: Duration = Duration::from_secs(3);

/// The pauses before a guest's join. The defaults are Go's; a test names
/// its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delays {
    /// Before the first guest.
    pub first: Duration,
    /// Before every later one.
    pub next: Duration,
}

impl Default for Delays {
    fn default() -> Self {
        Delays {
            first: RECRUIT_FIRST_DELAY,
            next: RECRUIT_NEXT_DELAY,
        }
    }
}

/// The handshake headers of a signalling socket, owned
/// ([`DialOptions`] borrows them). The defaults are what Go at the pin
/// sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headers {
    /// `Origin`.
    pub origin: String,
    /// `Referer`.
    pub referer: String,
    /// `User-Agent`; empty sends none.
    pub user_agent: String,
}

impl Default for Headers {
    fn default() -> Self {
        let go = DialOptions::default();
        Headers {
            origin: go.origin.to_owned(),
            referer: go.referer.to_owned(),
            user_agent: go.user_agent.to_owned(),
        }
    }
}

impl Headers {
    /// The headers as [`Signaling::dial`] takes them.
    #[must_use]
    pub fn options(&self) -> DialOptions<'_> {
        DialOptions {
            origin: &self.origin,
            referer: &self.referer,
            user_agent: &self.user_agent,
        }
    }
}

/// One run of the provider's chain for a fresh guest.
pub type Issuing = Pin<Box<dyn Future<Output = Result<Credentials, auth::Error>> + Send>>;

/// Issues a fresh guest's credentials (Go's `cfg.Refresh`): the provider's
/// whole chain, a new guest each time. The engine's rejoin and the
/// recruiter both ask it.
pub type Issue = Arc<dyn Fn() -> Issuing + Send + Sync>;

/// The recruiter of one wait (`recruitGuests`): a task that joins guests
/// until it is told the wait is over, [`MAX_RECRUITS`] of them at most, and
/// hangs every one of them up on its way out.
///
/// [`Recruiter::finish`] ends it and returns once the guests have left.
/// Dropped instead, it ends the same way on its own.
#[derive(Debug)]
pub struct Recruiter {
    /// Dropped (or sent on) when the wait is over.
    over: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Recruiter {
    /// Starts recruiting on the current runtime. Without an issuer there is
    /// nothing to join with and nothing is started: the wait stands on its
    /// own.
    #[must_use]
    pub fn start(issue: Option<Issue>, headers: Headers, delays: Delays) -> Self {
        let Some(issue) = issue else {
            return Recruiter {
                over: None,
                task: None,
            };
        };
        let (over, done) = oneshot::channel();
        Recruiter {
            over: Some(over),
            task: Some(tokio::spawn(recruit_guests(issue, headers, delays, done))),
        }
    }

    /// The wait is over: no further guest joins, a join in flight is given
    /// up, and every guest hangs up and goes. Returns when they have (each
    /// hangup is bounded by [`crate::signaling::HANGUP_TIMEOUT`]).
    pub async fn finish(mut self) {
        drop(self.over.take());
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// `recruitGuests`. `done` resolves when the main socket saw the switch or
/// gave up (its sender is used or dropped).
async fn recruit_guests(
    issue: Issue,
    headers: Headers,
    delays: Delays,
    mut done: oneshot::Receiver<()>,
) {
    let mut guests: Vec<Signaling> = Vec::with_capacity(MAX_RECRUITS);
    let mut delay = delays.first;
    let mut over = false;
    for _ in 0..MAX_RECRUITS {
        // `recruitPause`.
        tokio::select! {
            biased;
            _ = &mut done => {
                over = true;
                break;
            }
            () = tokio::time::sleep(delay) => {}
        }
        delay = delays.next;
        // The socket of a join in flight is kept here, so that it is
        // closed, not only dropped, when the wait ends under it.
        let mut held: Option<Signaling> = None;
        let outcome = {
            let joining = recruit_one(&issue, &headers, &mut held);
            tokio::pin!(joining);
            tokio::select! {
                biased;
                _ = &mut done => None,
                joined = &mut joining => Some(joined),
            }
        };
        match (outcome, held) {
            (Some(Ok(())), Some(guest)) => {
                guests.push(guest);
                olc_net::debug!(
                    "vkcalls: recruited a signaling-only guest to flip the fresh room to SERVER"
                );
            }
            (Some(Ok(())), None) => {}
            (Some(Err(error)), held) => {
                if let Some(guest) = held {
                    guest.close().await;
                }
                // A failed recruit counts toward the two, as in Go.
                olc_net::debug!("vkcalls: guest recruit: {error}");
            }
            (None, held) => {
                if let Some(guest) = held {
                    guest.close().await;
                }
                over = true;
                break;
            }
        }
    }
    if !over {
        // Out of guests: what is left is to hold them until the wait ends.
        let _ = (&mut done).await;
    }
    for guest in guests {
        guest.close().await;
    }
}

/// Why a guest did not join. The texts are Go's; none names the room, the
/// endpoint or a token.
#[derive(Debug, thiserror::Error)]
enum RecruitError {
    #[error("guest credentials: {0}")]
    Credentials(auth::Error),
    #[error("{0}")]
    Dial(SignalingError),
    #[error("guest join: {0}")]
    Join(SignalingError),
}

/// `recruitOne`: a fresh guest's credentials, its signalling socket, its
/// `connection` notification; then the socket is held open, answering
/// keepalives and nothing else: no peer connection, no commands, the
/// participant only counts. The socket is in `held` from the moment it is
/// dialled, whatever comes after.
async fn recruit_one(
    issue: &Issue,
    headers: &Headers,
    held: &mut Option<Signaling>,
) -> Result<(), RecruitError> {
    let credentials = issue().await.map_err(RecruitError::Credentials)?;
    let dialed = Signaling::dial(&credentials.url, headers.options()).await;
    // The endpoint carries the join token: it is wiped as soon as the
    // socket has it.
    drop(credentials);
    let (guest, mut notifications) = dialed.map_err(RecruitError::Dial)?;
    *held = Some(guest);
    notifications
        .await_join()
        .await
        .map_err(RecruitError::Join)?;
    // `drainNotifications`: ends with the socket.
    tokio::spawn(notifications.drain());
    Ok(())
}

/// Waits for the socket's `connection` notification and, when the room
/// opened outside SERVER topology, keeps waiting while the recruiter joins
/// the guests that flip a fresh room (`waitConnected`). Returns the
/// `connection` notification (its participant list is the join's own).
///
/// `stop` is the caller's (Go's context) and ends either wait; the wait
/// for the switch has no timer of its own. The guests have left when this
/// returns; the caller's own socket is the caller's to close.
///
/// # Errors
///
/// As [`Notifications::await_join`] and
/// [`Notifications::wait_server_topology`];
/// [`SignalingError::JoinStopped`] when `stop` ends the first.
pub async fn wait_connected(
    notifications: &mut Notifications,
    issue: Option<Issue>,
    headers: &Headers,
    delays: Delays,
    stop: impl Future<Output = ()>,
) -> Result<Notification, SignalingError> {
    tokio::pin!(stop);
    let connection = tokio::select! {
        biased;
        joined = notifications.await_join() => joined?,
        () = &mut stop => return Err(SignalingError::JoinStopped),
    };
    let server = connection
        .conversation
        .as_ref()
        .is_some_and(|c| c.topology == crate::signaling::TOPOLOGY_SERVER);
    if server {
        return Ok(connection);
    }
    let recruiter = Recruiter::start(issue, headers.clone(), delays);
    let waited = notifications
        .wait_server_topology(connection.clone(), stop)
        .await;
    recruiter.finish().await;
    waited.map(|()| connection)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use tokio::net::TcpListener;
    use tokio::sync::watch;

    use super::*;
    use crate::signaling::tests::{
        accept, bounded_for, connection, listen, read_frame, write_text,
    };

    /// The pauses of the tests: short, so that the Go test's 2 s + 3 s take
    /// a tenth of a second here.
    const QUICK: Delays = Delays {
        first: Duration::from_millis(40),
        next: Duration::from_millis(40),
    };

    /// One test's bound.
    const BOUND: Duration = Duration::from_secs(15);

    /// What the fake room saw of one connection.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct Seen {
        /// The hangup frames it sent.
        hangups: Vec<String>,
        /// Every other frame it sent.
        others: Vec<String>,
        /// The stream ended.
        gone: bool,
    }

    /// The fresh room of `TestRecruitFlipsFreshRoom`: every connection is
    /// told DIRECT, and the `flip_at`-th simultaneous one flips the SFU to
    /// SERVER, which it announces to everyone. It counts what each
    /// connection sent, the hangups apart.
    struct FreshRoom {
        seen: Arc<Mutex<Vec<Seen>>>,
        serve: JoinHandle<()>,
    }

    impl FreshRoom {
        fn serve(listener: TcpListener, flip_at: usize) -> Self {
            let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
            let (flip, _) = watch::channel(false);
            let serve = tokio::spawn({
                let seen = Arc::clone(&seen);
                async move {
                    loop {
                        let (_, mut read, write) = accept(&listener).await;
                        let (index, count) = {
                            let mut seen = seen.lock().unwrap();
                            seen.push(Seen::default());
                            (seen.len() - 1, seen.len())
                        };
                        write_text(
                            &write,
                            &connection("DIRECT", serde_json::json!([])).to_string(),
                        )
                        .await;
                        let mut flipped = flip.subscribe();
                        if count == flip_at {
                            flip.send_replace(true);
                        }
                        tokio::spawn(async move {
                            if flipped.wait_for(|on| *on).await.is_ok() {
                                let frame = serde_json::json!({
                                    "type": "notification",
                                    "notification": "topology-changed",
                                    "topology": "SERVER",
                                });
                                write_text(&write, &frame.to_string()).await;
                            }
                            // The write half lives as long as the room
                            // would hold the socket.
                            std::future::pending::<()>().await;
                        });
                        let seen = Arc::clone(&seen);
                        tokio::spawn(async move {
                            while let Some(frame) = read_frame(&mut read).await {
                                let text = frame.text().to_owned();
                                let hangup = serde_json::from_str::<serde_json::Value>(&text)
                                    .is_ok_and(|v| v["command"] == "hangup");
                                let mut seen = seen.lock().unwrap();
                                if hangup {
                                    seen[index].hangups.push(text);
                                } else {
                                    seen[index].others.push(text);
                                }
                            }
                            seen.lock().unwrap()[index].gone = true;
                        });
                    }
                }
            });
            FreshRoom { seen, serve }
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }

        /// Waits until what the room saw satisfies `settled`.
        async fn until(&self, what: &str, settled: impl Fn(&[Seen]) -> bool) -> Vec<Seen> {
            for _ in 0..500 {
                let seen = self.seen();
                if settled(&seen) {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("{what}: the room saw {:?}", self.seen());
        }
    }

    impl Drop for FreshRoom {
        fn drop(&mut self) {
            self.serve.abort();
        }
    }

    /// An issuer whose every guest gets `endpoint`, counting its calls; the
    /// calls whose number (from 1) is in `failing` are refused.
    fn issuer(endpoint: &str, failing: &'static [usize]) -> (Issue, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = endpoint.to_owned();
        let issue: Issue = Arc::new({
            let calls = Arc::clone(&calls);
            move || -> Issuing {
                let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                let endpoint = endpoint.clone();
                Box::pin(async move {
                    if failing.contains(&call) {
                        return Err(auth::Error::InvalidRoomUrl);
                    }
                    Ok(Credentials {
                        url: endpoint,
                        token: String::new(),
                        room_url: String::new(),
                        ice_servers: String::new(),
                        participant_id: String::new(),
                        peer_id_hint: None,
                        device_idx: String::new(),
                        client_type: "VK".to_owned(),
                        p2p_forbidden: true,
                    })
                })
            }
        });
        (issue, calls)
    }

    const HANGUP_FIRST: &str = r#"{"command":"hangup","reason":"HUNGUP","sequence":1}"#;

    fn left(seen: &Seen) -> bool {
        seen.gone && seen.hangups == [HANGUP_FIRST] && seen.others.is_empty()
    }

    // TestRecruitFlipsFreshRoom: the first two connections stay DIRECT, and
    // the third simultaneous participant is what flips the SFU to SERVER.
    // The session's wait, with its recruiter running, must end on that
    // flip, and the recruiter's guests leave with the wait; each of them
    // hangs up (fidelity S4), and so does the session's own socket when it
    // is closed.
    #[tokio::test]
    async fn recruit_flips_fresh_room() {
        bounded_for(BOUND, async {
            let (listener, endpoint) = listen().await;
            let room = FreshRoom::serve(listener, 3);
            let (issue, calls) = issuer(&endpoint, &[]);
            let (signal, mut notifications) = Signaling::dial(&endpoint, DialOptions::default())
                .await
                .unwrap();
            let connection = wait_connected(
                &mut notifications,
                Some(issue),
                &Headers::default(),
                QUICK,
                std::future::pending(),
            )
            .await
            .expect("the recruited third participant did not flip the room");
            assert_eq!(connection.notification, "connection");
            assert_eq!(connection.conversation.unwrap().topology, "DIRECT");
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            // The session plus two recruits, and the recruits have left:
            // one hangup each, nothing else said, the socket gone. The
            // session's own socket is still there and has said nothing.
            let seen = room
                .until("the guests leave with the wait", |seen| {
                    seen.len() == 3 && seen[1..].iter().all(left)
                })
                .await;
            assert_eq!(seen[0], Seen::default());

            signal.close().await;
            let seen = room
                .until("the session's own hangup", |seen| left(&seen[0]))
                .await;
            assert_eq!(
                seen.len(),
                3,
                "connections, want the session plus two recruits"
            );
        })
        .await;
    }

    /// A recruit that fails is logged and counts toward the two: with the
    /// first refused there is one guest, the room (which needs three) stays
    /// DIRECT, and the wait goes on until the caller stops it. The guest
    /// then leaves with a hangup.
    #[tokio::test]
    async fn a_failed_recruit_counts_and_the_stop_ends_the_wait() {
        bounded_for(BOUND, async {
            let (listener, endpoint) = listen().await;
            let room = FreshRoom::serve(listener, 3);
            let (issue, calls) = issuer(&endpoint, &[1]);
            let (signal, mut notifications) = Signaling::dial(&endpoint, DialOptions::default())
                .await
                .unwrap();
            let (stop, stopped) = oneshot::channel::<()>();
            let wait = tokio::spawn(async move {
                let waited = wait_connected(
                    &mut notifications,
                    Some(issue),
                    &Headers::default(),
                    QUICK,
                    async {
                        let _ = stopped.await;
                    },
                )
                .await;
                (waited, notifications)
            });
            room.until("the one guest joins", |seen| seen.len() == 2)
                .await;
            // Out of recruits: nothing more comes, and the wait holds.
            tokio::time::sleep(4 * QUICK.next).await;
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(room.seen().len(), 2);
            assert!(!wait.is_finished(), "the wait ended in DIRECT");
            assert_eq!(room.seen()[1], Seen::default(), "the guest only counts");

            stop.send(()).unwrap();
            let (waited, _notifications) = wait.await.unwrap();
            assert_eq!(waited, Err(SignalingError::NotServer));
            let seen = room
                .until("the guest leaves with the wait", |seen| left(&seen[1]))
                .await;
            assert_eq!(seen[0], Seen::default());
            signal.close().await;
            room.until("the session's own hangup", |seen| left(&seen[0]))
                .await;
        })
        .await;
    }

    /// A wait that is dropped in the middle (the join's future given up)
    /// still has its guests hang up: the recruiter sees its owner go. And
    /// the session's socket, dropped unclosed, hangs up too.
    #[tokio::test]
    async fn a_dropped_wait_still_hangs_its_guests_up() {
        bounded_for(BOUND, async {
            let (listener, endpoint) = listen().await;
            // A room that never flips.
            let room = FreshRoom::serve(listener, usize::MAX);
            let (issue, _calls) = issuer(&endpoint, &[]);
            let (signal, mut notifications) = Signaling::dial(&endpoint, DialOptions::default())
                .await
                .unwrap();
            let wait = tokio::spawn(async move {
                let _signal = signal;
                wait_connected(
                    &mut notifications,
                    Some(issue),
                    &Headers::default(),
                    QUICK,
                    std::future::pending(),
                )
                .await
            });
            room.until("both guests join", |seen| seen.len() == 3).await;
            wait.abort();
            let seen = room
                .until("everyone leaves", |seen| seen.iter().all(left))
                .await;
            assert_eq!(seen.len(), 3);
        })
        .await;
    }

    /// A room that switches before the first pause is over is joined by no
    /// guest, and one that opened in SERVER is not waited for at all; with
    /// no issuer the wait stands on its own.
    #[tokio::test]
    async fn no_guest_joins_a_room_that_needs_none() {
        bounded_for(BOUND, async {
            let slow = Delays {
                first: Duration::from_secs(600),
                next: Duration::from_secs(600),
            };
            // The session's own connection flips this room.
            let (listener, endpoint) = listen().await;
            let room = FreshRoom::serve(listener, 1);
            let (issue, calls) = issuer(&endpoint, &[]);
            let (signal, mut notifications) = Signaling::dial(&endpoint, DialOptions::default())
                .await
                .unwrap();
            wait_connected(
                &mut notifications,
                Some(issue),
                &Headers::default(),
                slow,
                std::future::pending(),
            )
            .await
            .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(room.seen().len(), 1);
            signal.close().await;

            // A room the recruiter has not got to yet (its first pause is
            // not over), and one with no issuer at all: the wait stands on
            // its own until a second participant's join switches the room,
            // and nobody was recruited.
            for with_issuer in [true, false] {
                let (listener, endpoint) = listen().await;
                let room = FreshRoom::serve(listener, 2);
                let (issue, calls) = issuer(&endpoint, &[]);
                let (signal, mut notifications) =
                    Signaling::dial(&endpoint, DialOptions::default())
                        .await
                        .unwrap();
                let wait = tokio::spawn(async move {
                    let waited = wait_connected(
                        &mut notifications,
                        with_issuer.then_some(issue),
                        &Headers::default(),
                        slow,
                        std::future::pending(),
                    )
                    .await;
                    (waited, notifications)
                });
                tokio::time::sleep(6 * QUICK.next).await;
                assert!(!wait.is_finished(), "issuer: {with_issuer}");
                assert_eq!(room.seen().len(), 1, "issuer: {with_issuer}");
                assert_eq!(calls.load(Ordering::SeqCst), 0, "issuer: {with_issuer}");
                let (other, _other_notes) = Signaling::dial(&endpoint, DialOptions::default())
                    .await
                    .unwrap();
                wait.await.unwrap().0.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 0, "issuer: {with_issuer}");
                assert_eq!(room.seen().len(), 2, "issuer: {with_issuer}");
                other.close().await;
                signal.close().await;
            }
        })
        .await;
    }

    /// The caller's stop ends the wait for the `connection` notification
    /// too (a close while a join waits for it), long before that wait's
    /// own 30 s, and says which wait it was.
    #[tokio::test]
    async fn a_stop_ends_the_wait_for_the_connection_notification() {
        bounded_for(BOUND, async {
            let (listener, endpoint) = listen().await;
            let (dialed, accepted) = tokio::join!(
                Signaling::dial(&endpoint, DialOptions::default()),
                accept(&listener)
            );
            let (signal, mut notifications) = dialed.unwrap();
            // The room says nothing.
            let (_head, _read, _write) = accepted;
            let began = std::time::Instant::now();
            let waited = wait_connected(
                &mut notifications,
                None,
                &Headers::default(),
                QUICK,
                tokio::time::sleep(Duration::from_millis(100)),
            )
            .await;
            assert_eq!(waited.map(|_| ()), Err(SignalingError::JoinStopped));
            assert!(began.elapsed() < Duration::from_secs(5));
            assert_eq!(
                SignalingError::JoinStopped.to_string(),
                "vkcalls: connection wait: stopped"
            );
            signal.close().await;
        })
        .await;
    }

    /// Go's numbers, and the headers Go sends.
    #[test]
    fn the_defaults_are_gos() {
        assert_eq!(MAX_RECRUITS, 2);
        assert_eq!(
            Delays::default(),
            Delays {
                first: Duration::from_secs(2),
                next: Duration::from_secs(3),
            }
        );
        assert_eq!(Headers::default().options(), DialOptions::default());
    }
}

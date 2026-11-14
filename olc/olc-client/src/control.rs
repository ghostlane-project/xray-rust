// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The control loop (`control.Run`, control.go, run by
//! `tunnelcore.ControlRunner` and `client.startControlLoop`): a ping every
//! interval on the control stream, each pong expected within the timeout;
//! a timed-out ping is excused while the peer is still sending stream
//! payload (at most [`MAX_STALLED_PROBES`] in a row), and the session is
//! declared dead after `failures` missed pongs, when the data plane stops
//! sending, or when the peer sends `CONTROL_CLOSE`. Pings from the peer are
//! answered. Stopping the loop announces the close to the peer first
//! (`NotifyControlClose`, bounded by [`CLOSE_NOTICE_BUDGET`]).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use olc_smux::Stream;
use olc_wire::control::{
    self, Message, MsgType, CLOSE_LINGER, CLOSE_WRITE_DEADLINE, MAX_MESSAGE_SIZE,
};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub use olc_wire::control::MAX_STALLED_PROBES;

use crate::config::Liveness;
use crate::frames::read_frame;

/// How long stopping waits for the close to be announced
/// (`closeNoticeBudget`).
pub const CLOSE_NOTICE_BUDGET: Duration = Duration::from_millis(1500);

/// Messages waiting for the writer (Go's `out`, 16).
pub const OUT_QUEUE: usize = 16;

/// How the loop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// It was stopped.
    Stopped,
    /// The peer sent `CONTROL_CLOSE` (`ErrClosedByPeer`).
    ClosedByPeer,
    /// Liveness gave up (`ErrUnhealthy`), with Go's words.
    Unhealthy(String),
    /// The stream failed or the peer spoke wrongly, with Go's words.
    Failed(String),
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => f.write_str("context canceled"),
            Self::ClosedByPeer => f.write_str("control stream closed by peer"),
            Self::Unhealthy(why) => write!(f, "control stream unhealthy: {why}"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

/// What the loop asks of and tells the client.
pub struct Hooks {
    /// `role=client session=<id>`, for the log lines.
    pub fields: String,
    /// Stream payload the peer has sent so far (`PayloadBytes`).
    pub progress: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Whether the data plane has stopped sending (`SendStalled`).
    pub send_stalled: Box<dyn Fn() -> bool + Send + Sync>,
    /// A pong came back after this long.
    pub on_pong: Box<dyn Fn(Duration) + Send + Sync>,
}

/// The probes in flight and the counters (`state`, control.go).
#[derive(Debug, Clone, Default)]
pub struct Probes {
    pending: Vec<(u64, Instant)>,
    next_seq: u64,
    failures: u32,
    stalled: u32,
    last_progress: Option<u64>,
}

/// What one probe tick decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// Send this ping. `missed` is the failures so far when this tick added
    /// some; `late` the timed-out pings excused by the peer's progress.
    Ping {
        /// The ping.
        seq: u64,
        /// Missed pongs so far, when this tick missed one.
        missed: Option<u32>,
        /// Pings excused as late this tick.
        late: u32,
    },
    /// The data plane stopped sending.
    SendStalled,
    /// Too many missed pongs; `missed_now` when this tick added some.
    Unhealthy {
        /// The missed pongs.
        missed: u32,
        /// Whether this tick missed one.
        missed_now: bool,
    },
}

impl Probes {
    /// One probe tick at `now` (`sendProbe`), given the peer's progress and
    /// whether the data plane is stalled.
    pub fn tick(
        &mut self,
        now: Instant,
        progress: u64,
        send_stalled: bool,
        timeout: Duration,
        failures: u32,
    ) -> Tick {
        let moved = self.last_progress.is_some_and(|p| p != progress);
        self.last_progress = Some(progress);
        if send_stalled {
            return Tick::SendStalled;
        }
        let before = self.pending.len();
        self.pending
            .retain(|&(_, sent)| now.saturating_duration_since(sent) < timeout);
        let mut timed_out = u32::try_from(before - self.pending.len()).unwrap_or(u32::MAX);
        let mut late = 0;
        if timed_out > 0 && moved && self.stalled < MAX_STALLED_PROBES {
            self.stalled += timed_out;
            late = timed_out;
            timed_out = 0;
        }
        self.failures += timed_out;
        if self.failures >= failures {
            return Tick::Unhealthy {
                missed: self.failures,
                missed_now: timed_out > 0,
            };
        }
        self.next_seq += 1;
        self.pending.push((self.next_seq, now));
        Tick::Ping {
            seq: self.next_seq,
            missed: (timed_out > 0).then_some(self.failures),
            late,
        }
    }

    /// A pong for `seq` at `now` (`handlePong`): its round trip, when it
    /// answered a ping in flight.
    pub fn pong(&mut self, seq: u64, now: Instant) -> Option<Duration> {
        let i = self.pending.iter().position(|&(s, _)| s == seq)?;
        let (_, sent) = self.pending.swap_remove(i);
        self.failures = 0;
        self.stalled = 0;
        Some(now.saturating_duration_since(sent))
    }
}

fn unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

/// Runs the loop on `stream` until it ends or `stop` is cancelled; a stop
/// announces the close to the peer first, within [`CLOSE_NOTICE_BUDGET`].
pub async fn run(stream: Stream, liveness: Liveness, hooks: Hooks, stop: CancellationToken) -> End {
    let (rd, wr) = tokio::io::split(stream);
    let probes = Arc::new(Mutex::new(Probes::default()));
    let hooks = Arc::new(hooks);
    let (out_tx, out_rx) = mpsc::channel::<Message>(OUT_QUEUE);
    let inner = stop.child_token();
    let reader = tokio::spawn(read_loop(
        rd,
        out_tx.clone(),
        probes.clone(),
        hooks.clone(),
        inner.clone(),
    ));
    let writer = tokio::spawn(write_loop(wr, out_rx, inner.clone()));
    let prober = probe_loop(liveness, out_tx, probes, hooks.clone(), inner.clone());
    tokio::pin!(reader, writer, prober);
    let mut wr_back = None;
    let mut writer_done = false;
    let end = tokio::select! {
        () = stop.cancelled() => End::Stopped,
        r = &mut reader => r.unwrap_or_else(|e| End::Failed(e.to_string())),
        r = &mut writer => {
            writer_done = true;
            match r {
                Ok((end, half)) => { wr_back = half; end }
                Err(e) => End::Failed(e.to_string()),
            }
        },
        end = &mut prober => end,
    };
    inner.cancel();
    // Go logs as Run returns (tunnelcore/control.go:50-56); Run's watcher
    // announces the close on every end, not only a stop (control.go:219-223).
    if !matches!(end, End::Stopped) {
        crate::info!("control stream ended {}: {end}", hooks.fields);
    }
    reader.abort();
    if !writer_done {
        if let Ok((_, half)) = writer.await {
            wr_back = half;
        }
    }
    if let Some(mut half) = wr_back {
        if end == End::Stopped {
            let _ = tokio::time::timeout(CLOSE_NOTICE_BUDGET, notify_close(&mut half)).await;
        } else {
            // A death goes on to the reconnect at once, as in Go, while the
            // notice is sent beside it.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(CLOSE_NOTICE_BUDGET, notify_close(&mut half)).await;
            });
        }
    }
    end
}

/// `NotifyControlClose`: `CONTROL_CLOSE` within its write deadline, a
/// moment for it to leave, then the write side closed.
async fn notify_close(half: &mut WriteHalf<Stream>) {
    let mut out = Vec::with_capacity(64);
    let _ = control::encode(&Message::close(), &mut out);
    let sent = tokio::time::timeout(CLOSE_WRITE_DEADLINE, half.write_all(&out)).await;
    if matches!(sent, Ok(Ok(()))) {
        tokio::time::sleep(CLOSE_LINGER).await;
    }
    let _ = half.shutdown().await;
}

async fn read_loop(
    mut rd: ReadHalf<Stream>,
    out: mpsc::Sender<Message>,
    probes: Arc<Mutex<Probes>>,
    hooks: Arc<Hooks>,
    stop: CancellationToken,
) -> End {
    let mut buf = Vec::with_capacity(256);
    loop {
        let read = tokio::select! {
            () = stop.cancelled() => return End::Stopped,
            r = read_frame(&mut rd, MAX_MESSAGE_SIZE, &mut buf) => r,
        };
        if let Err(e) = read {
            return End::Failed(format!("control: {e}"));
        }
        let msg = match control::parse(&buf) {
            Ok(m) => m,
            Err(e) => return End::Failed(e.to_string()),
        };
        match msg.kind {
            MsgType::Ping => {
                tokio::select! {
                    () = stop.cancelled() => return End::Stopped,
                    r = out.send(Message::pong_for(&msg)) => if r.is_err() { return End::Stopped },
                }
            }
            MsgType::Pong => {
                let rtt = probes
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pong(msg.seq, Instant::now());
                if let Some(rtt) = rtt {
                    (hooks.on_pong)(rtt);
                    crate::debug!("control alive {} rtt={rtt:?} seq={}", hooks.fields, msg.seq);
                }
            }
            MsgType::Close => return End::ClosedByPeer,
        }
    }
}

async fn write_loop(
    mut wr: WriteHalf<Stream>,
    mut rx: mpsc::Receiver<Message>,
    stop: CancellationToken,
) -> (End, Option<WriteHalf<Stream>>) {
    let mut out = Vec::with_capacity(256);
    loop {
        let msg = tokio::select! {
            () = stop.cancelled() => return (End::Stopped, Some(wr)),
            m = rx.recv() => match m {
                Some(m) => m,
                None => return (End::Stopped, Some(wr)),
            },
        };
        out.clear();
        let _ = control::encode(&msg, &mut out);
        let wrote = tokio::select! {
            () = stop.cancelled() => return (End::Stopped, Some(wr)),
            r = wr.write_all(&out) => r,
        };
        if let Err(e) = wrote {
            return (End::Failed(format!("control: write frame: {e}")), Some(wr));
        }
    }
}

async fn probe_loop(
    liveness: Liveness,
    out: mpsc::Sender<Message>,
    probes: Arc<Mutex<Probes>>,
    hooks: Arc<Hooks>,
    stop: CancellationToken,
) -> End {
    let interval = liveness.interval();
    let mut tick = tokio::time::interval_at(Instant::now() + interval, interval);
    // A Go Ticker drops the ticks a slow receiver missed.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return End::Stopped,
            _ = tick.tick() => {}
        }
        let decided = probes.lock().unwrap_or_else(PoisonError::into_inner).tick(
            Instant::now(),
            (hooks.progress)(),
            (hooks.send_stalled)(),
            liveness.timeout(),
            liveness.failures(),
        );
        let f = &hooks.fields;
        match decided {
            Tick::SendStalled => {
                crate::info!("control healthy {f} but the data plane has stopped sending — tearing the session down");
                return End::Unhealthy("the data plane stopped sending".to_owned());
            }
            Tick::Unhealthy { missed, missed_now } => {
                if missed_now {
                    crate::info!("control missed pong {f} missed={missed}");
                }
                crate::info!("control unhealthy {f} missed={missed}");
                return End::Unhealthy(format!("missed {missed} pong(s)"));
            }
            Tick::Ping { seq, missed, late } => {
                if let Some(missed) = missed {
                    crate::info!("control missed pong {f} missed={missed}");
                }
                if late > 0 {
                    crate::info!("control pong late {f} but the peer is still sending — not counting {late} as missed");
                }
                let ping = Message::ping(seq, unix_nanos());
                tokio::select! {
                    () = stop.cancelled() => return End::Stopped,
                    r = out.send(ping) => if r.is_err() { return End::Stopped },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(15);

    #[tokio::test(start_paused = true)]
    async fn four_missed_pongs_end_the_session() {
        crate::testing::bounded(four_missed_pongs_end_the_session_body()).await;
    }

    async fn four_missed_pongs_end_the_session_body() {
        let mut p = Probes::default();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(
            p.tick(at(10), 0, false, T, 4),
            Tick::Ping {
                seq: 1,
                missed: None,
                late: 0
            }
        );
        assert_eq!(
            p.tick(at(20), 0, false, T, 4),
            Tick::Ping {
                seq: 2,
                missed: None,
                late: 0
            }
        );
        assert_eq!(
            p.tick(at(30), 0, false, T, 4),
            Tick::Ping {
                seq: 3,
                missed: Some(1),
                late: 0
            }
        );
        assert_eq!(
            p.tick(at(40), 0, false, T, 4),
            Tick::Ping {
                seq: 4,
                missed: Some(2),
                late: 0
            }
        );
        assert_eq!(
            p.tick(at(50), 0, false, T, 4),
            Tick::Ping {
                seq: 5,
                missed: Some(3),
                late: 0
            }
        );
        assert_eq!(
            p.tick(at(60), 0, false, T, 4),
            Tick::Unhealthy {
                missed: 4,
                missed_now: true
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_pong_clears_the_count_and_progress_excuses_three() {
        crate::testing::bounded(a_pong_clears_the_count_and_progress_excuses_three_body()).await;
    }

    async fn a_pong_clears_the_count_and_progress_excuses_three_body() {
        let mut p = Probes::default();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        p.tick(at(10), 0, false, T, 4);
        assert_eq!(p.pong(1, at(11)), Some(Duration::from_secs(1)));
        assert_eq!(p.pong(1, at(12)), None);
        // The peer keeps sending payload: timed-out pings are late, not missed.
        p.tick(at(20), 1, false, T, 4);
        let mut late = 0;
        for (i, s) in [40u64, 60, 80].into_iter().enumerate() {
            match p.tick(at(s), 2 + i as u64, false, T, 4) {
                Tick::Ping {
                    missed: None,
                    late: l,
                    ..
                } => late += l,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(late, 3);
        // The fourth timed-out ping counts, progress or not.
        assert!(matches!(
            p.tick(at(100), 9, false, T, 4),
            Tick::Ping {
                missed: Some(1),
                ..
            }
        ));
    }

    /// A client and a server smux session over memory, keepalive off.
    fn smux_pair() -> (olc_smux::Session, olc_smux::Session) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut cfg = olc_smux::Config::client_data(12288, false);
        cfg.keep_alive = None;
        let (c, cd) = olc_smux::Session::client(a, cfg.clone()).unwrap();
        let (s, sd) = olc_smux::Session::server(b, cfg).unwrap();
        tokio::spawn(cd);
        tokio::spawn(sd);
        (c, s)
    }

    fn quiet_hooks() -> Hooks {
        Hooks {
            fields: "role=client session=t".into(),
            progress: Box::new(|| 0),
            send_stalled: Box::new(|| false),
            on_pong: Box::new(|_| {}),
        }
    }

    #[tokio::test]
    async fn a_close_from_the_peer_ends_the_loop_closed_by_peer() {
        crate::testing::bounded(async {
            let (c, s) = smux_pair();
            let ours = c.open_stream().await.unwrap();
            let mut theirs = s.accept_stream().await.unwrap();
            let mut out = Vec::new();
            control::encode(&Message::close(), &mut out).unwrap();
            theirs.write_all(&out).await.unwrap();
            let end = run(
                ours,
                Liveness::default(),
                quiet_hooks(),
                CancellationToken::new(),
            )
            .await;
            assert_eq!(end, End::ClosedByPeer);
            assert_eq!(end.to_string(), "control stream closed by peer");
        })
        .await;
    }

    #[tokio::test]
    async fn a_stop_says_control_close_to_the_peer_first() {
        crate::testing::bounded(async {
            let (c, s) = smux_pair();
            let ours = c.open_stream().await.unwrap();
            let mut theirs = s.accept_stream().await.unwrap();
            let stop = CancellationToken::new();
            let looped = tokio::spawn(run(ours, Liveness::default(), quiet_hooks(), stop.clone()));
            stop.cancel();
            assert_eq!(looped.await.unwrap(), End::Stopped);
            let mut buf = Vec::new();
            crate::frames::read_frame(&mut theirs, MAX_MESSAGE_SIZE, &mut buf)
                .await
                .unwrap();
            assert_eq!(control::parse(&buf).unwrap().kind, MsgType::Close);
        })
        .await;
    }

    #[tokio::test]
    async fn a_session_that_dies_under_the_loop_ends_it_with_the_closed_pipe_text() {
        crate::testing::bounded(async {
            let (c, s) = smux_pair();
            let ours = c.open_stream().await.unwrap();
            let _theirs = s.accept_stream().await.unwrap();
            let looped = tokio::spawn(run(
                ours,
                Liveness::default(),
                quiet_hooks(),
                CancellationToken::new(),
            ));
            // Let the read park, then the session dies (smux's waitRead:
            // a parked read gets io.ErrClosedPipe).
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = c.close();
            let end = looped.await.unwrap();
            assert_eq!(
                end.to_string(),
                "control: read hdr: io: read/write on closed pipe",
                "the line the apps react to"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn every_end_says_control_close_to_the_peer() {
        crate::testing::bounded(async {
            let (c, s) = smux_pair();
            let ours = c.open_stream().await.unwrap();
            let mut theirs = s.accept_stream().await.unwrap();
            // A frame that is not a control message ends the loop (Go's
            // Run cancels its context on every end, and the watcher
            // announces the close: control.go:219-223).
            theirs
                .write_all(&[0, 0, 0, 3, b'b', b'a', b'd'])
                .await
                .unwrap();
            let end = run(
                ours,
                Liveness::default(),
                quiet_hooks(),
                CancellationToken::new(),
            )
            .await;
            assert!(matches!(end, End::Failed(_)), "{end:?}");
            let mut buf = Vec::new();
            crate::frames::read_frame(&mut theirs, MAX_MESSAGE_SIZE, &mut buf)
                .await
                .unwrap();
            assert_eq!(control::parse(&buf).unwrap().kind, MsgType::Close);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_data_plane_ends_it_at_once() {
        crate::testing::bounded(a_stalled_data_plane_ends_it_at_once_body()).await;
    }

    async fn a_stalled_data_plane_ends_it_at_once_body() {
        let mut p = Probes::default();
        assert_eq!(p.tick(Instant::now(), 0, true, T, 4), Tick::SendStalled);
    }
}

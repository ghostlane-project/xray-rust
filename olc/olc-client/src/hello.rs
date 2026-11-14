// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The hello race (`openControlStreamTimeout`, link.go:180-330): the first
//! stream opens once this side's path takes its SYN (at most `timeout`),
//! then a hello goes out on a fresh stream with a fresh challenge every
//! [`HELLO_RESEND_INTERVAL`], at most [`MAX_HELLO_ATTEMPTS`] streams, all
//! under one deadline `timeout` after the first. The first welcome wins and
//! the other streams are closed; an answer that is not a welcome (a reject,
//! a version mismatch, a malformed reply) ends the race, since another hello
//! would get the same one.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use olc_smux::{Session, Stream};
use olc_wire::framing::ReadError;
use olc_wire::handshake::{
    encode_hello, parse_reply, Challenge, HandshakeError, Reply, Welcome, MAX_MESSAGE_SIZE,
};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub use olc_wire::handshake::{DEFAULT_TIMEOUT, HELLO_RESEND_INTERVAL, MAX_HELLO_ATTEMPTS};

use crate::frames::read_frame;

/// Why the race found no session.
#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    /// The first stream did not open (`open control stream: …`).
    #[error("open control stream: {0}")]
    Open(String),
    /// The hello could not be written.
    #[error("send hello: {0}")]
    Send(#[source] io::Error),
    /// The reply ended the handshake, Go's error.
    #[error("{0}")]
    Reply(#[source] HandshakeError),
    /// The deadline passed with no answer: smux's deadline on the stream.
    #[error("read welcome: read hdr: timeout")]
    Timeout,
    /// The run ended.
    #[error("context canceled")]
    Cancelled,
}

impl HelloError {
    /// `helloAnswered`: the peer replied, however badly; another hello would
    /// get the same answer.
    pub fn answered(&self) -> bool {
        match self {
            Self::Reply(e) => matches!(
                e,
                HandshakeError::Rejected(_)
                    | HandshakeError::ProtocolVersion(_)
                    | HandshakeError::UnexpectedMessage(_)
                    | HandshakeError::ChallengeMismatch
                    | HandshakeError::Read(ReadError::TooLarge(_))
            ),
            _ => false,
        }
    }

    /// `helloRefused`: a reject or another version.
    pub fn refused(&self) -> bool {
        matches!(
            self,
            Self::Reply(HandshakeError::Rejected(_) | HandshakeError::ProtocolVersion(_))
        )
    }
}

/// The won race: the control stream and what the server granted.
#[derive(Debug)]
pub struct Opened {
    /// The stream the welcome came back on: the control stream from now on.
    pub stream: Stream,
    /// The welcome.
    pub welcome: Welcome,
}

/// Runs the race on `session` for `device_id`; `stop` ends it.
///
/// # Errors
/// [`HelloError`] (Go wraps it as `handshake client: …`).
pub async fn open_control_stream(
    session: &Session,
    device_id: &str,
    timeout: Duration,
    stop: &CancellationToken,
) -> Result<Opened, HelloError> {
    let first = tokio::select! {
        () = stop.cancelled() => return Err(HelloError::Cancelled),
        r = tokio::time::timeout(timeout, session.open_stream()) => match r {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(HelloError::Open(e.to_string())),
            Err(_) => return Err(HelloError::Open("timeout".to_owned())),
        },
    };
    let deadline = Instant::now() + timeout;
    let device: Arc<str> = Arc::from(device_id);
    let mut race = Race {
        session,
        device,
        deadline,
        set: JoinSet::new(),
        streams: 0,
        pending: 0,
    };
    race.start(first);
    let mut resend = tokio::time::interval_at(
        Instant::now() + HELLO_RESEND_INTERVAL,
        HELLO_RESEND_INTERVAL,
    );
    // A Go Ticker drops the ticks a slow receiver missed.
    resend.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => {
                race.set.abort_all();
                return Err(HelloError::Cancelled);
            }
            _ = resend.tick() => {
                race.resend().await;
            }
            Some(joined) = race.set.join_next() => {
                race.pending -= 1;
                let Ok((stream, result)) = joined else { continue };
                match result {
                    Ok(welcome) => {
                        race.set.abort_all();
                        return Ok(Opened { stream, welcome });
                    }
                    Err(e) => {
                        drop(stream);
                        if stop.is_cancelled() {
                            race.set.abort_all();
                            return Err(HelloError::Cancelled);
                        }
                        if !e.answered() && (race.pending > 0 || race.resend().await) {
                            continue;
                        }
                        race.set.abort_all();
                        return Err(e);
                    }
                }
            }
        }
    }
}

struct Race<'a> {
    session: &'a Session,
    device: Arc<str>,
    deadline: Instant,
    set: JoinSet<(Stream, Result<Welcome, HelloError>)>,
    streams: u32,
    pending: u32,
}

impl Race<'_> {
    fn start(&mut self, stream: Stream) {
        self.streams += 1;
        self.pending += 1;
        self.set
            .spawn(hello_on(stream, self.device.clone(), self.deadline));
    }

    /// Another hello when the cap and the deadline allow: one that would
    /// time out within half an interval is not worth sending.
    async fn resend(&mut self) -> bool {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if self.streams >= MAX_HELLO_ATTEMPTS || left <= HELLO_RESEND_INTERVAL / 2 {
            return false;
        }
        match self.session.open_stream().await {
            Ok(stream) => {
                self.start(stream);
                true
            }
            Err(e) => {
                crate::debug!("handshake: resend hello: open control stream: {e}");
                false
            }
        }
    }
}

/// One hello and its reply (`handshake.Client`), under the race's deadline.
async fn hello_on(
    mut stream: Stream,
    device: Arc<str>,
    deadline: Instant,
) -> (Stream, Result<Welcome, HelloError>) {
    let exchange = async {
        let challenge = Challenge::random();
        let mut out = Vec::with_capacity(256);
        encode_hello(device.as_bytes(), &challenge, &mut out)
            .map_err(|e| HelloError::Send(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        stream.write_all(&out).await.map_err(HelloError::Send)?;
        let mut buf = Vec::new();
        loop {
            read_frame(&mut stream, MAX_MESSAGE_SIZE, &mut buf)
                .await
                .map_err(|e| HelloError::Reply(HandshakeError::Read(e)))?;
            match parse_reply(&buf, &challenge) {
                Ok(Reply::NotOurs) => {}
                Ok(Reply::Welcome(w)) => return Ok(w),
                Err(e) => return Err(HelloError::Reply(e)),
            }
        }
    };
    let result = tokio::time::timeout_at(deadline, exchange)
        .await
        .unwrap_or(Err(HelloError::Timeout));
    (stream, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_and_refusals_are_gos() {
        let rejected = HelloError::Reply(HandshakeError::Rejected("no".into()));
        assert!(rejected.answered() && rejected.refused());
        let version = HelloError::Reply(HandshakeError::ProtocolVersion(2));
        assert!(version.answered() && version.refused());
        let mismatch = HelloError::Reply(HandshakeError::ChallengeMismatch);
        assert!(mismatch.answered() && !mismatch.refused());
        assert!(!HelloError::Timeout.answered());
        assert!(!HelloError::Reply(HandshakeError::Read(ReadError::EofHeader)).answered());
    }
}

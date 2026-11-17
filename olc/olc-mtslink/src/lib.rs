// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The MTS Link carrier (`internal/auth/mtslink` and
//! `internal/engine/mtslink` of the Go engine at 2d4266af).
//!
//! [`auth`] walks a guest into an endless meeting: the gateway's five
//! calls, and what the engine joins with. [`signal`] is the SFU's side:
//! the one SDP exchange, the pin behind it and the take-back of a
//! conference nothing will publish into. [`session`] is the engine: one
//! peer connection to the SFU, the published VP9 track out and the room's
//! video back, as the video transport's engine; [`readers`] keeps the
//! room's video apart, one reader per publisher.
//!
//! No HTTP call keeps a connection or a buffer: every call is one request
//! on its own connection, its reply bounded by [`REPLY_LIMIT`] and dropped
//! once read. What the gateway hands out to be kept is bounded too
//! ([`auth::MAX_TICKET`], [`auth::MAX_COOKIES`]), and zeroed when it goes.
//! What a joined session holds is in [`session`]'s words on memory.
//!
//! What a request says about its sender (the User-Agent, the page it
//! claims to come from, the device id of a join) is a parameter:
//! [`auth::Web`], [`auth::Request::did`], [`signal::Sfu`]. Each default is
//! what the Go client at the pin sends.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::Duration;

pub mod auth;
mod gourl;
pub mod readers;
pub mod session;
pub mod signal;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod vectors;

/// The most of a reply read, the gateway's and the SFU's alike
/// (`replyLimit`, `maxSignalBody`): 1 MiB. The largest the flow reads are
/// the event's public record, a few kilobytes, and an SDP answer, about
/// forty. Go cuts a longer reply short; here it is an error of the call.
pub const REPLY_LIMIT: usize = 1 << 20;

/// The time one call may take, dial and reply together (Go's client
/// timeout, `internal/protect/protect.go:28`).
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The time the call that takes a conference back may take (`leaveWait`,
/// `internal/engine/mtslink/mtslink.go:66`): it follows a join that came
/// to nothing, and holds that join's error back no longer than this.
pub const LEAVE_WAIT: Duration = Duration::from_secs(5);

/// How the guest's media reaches the SFU: the room link's `?ice=` hint, or
/// the default of the side that joins (`internal/roomhint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ice {
    /// UDP alone.
    Udp,
    /// ICE-TCP alone: what the client side asks for when the link says
    /// nothing.
    Tcp,
    /// UDP and ICE-TCP.
    Both,
}

impl Ice {
    /// `roomhint.Mode`: the mode `word` names, none for any other word.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    /// The word of the mode, as a room link spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Both => "both",
        }
    }
}

/// The carrier's errors. The texts are Go's (`api.go:45-63`,
/// `signal.go:25-34`, `mtslink.go:50-57`); tests and reports read them.
///
/// No variant carries a URL, a cookie or a gateway reply: the join URL
/// holds both of the guest's tokens, and a reply can hold one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `ErrRoomRef`: a room reference that is not the event join link.
    #[error("mtslink: room must be the event join link (…/j/{{ownerId}}/{{eventId}})")]
    RoomRef,
    /// `ErrRoomGone` at the named call: 404, 406 or 410.
    #[error("{0}: mtslink: the service has no such room")]
    RoomGone(&'static str),
    /// `ErrNoSession`: the event has no session to join.
    #[error("mtslink: the event has no session")]
    NoSession,
    /// `ErrNotAccepted`: the service turned the guest away.
    #[error("mtslink: the service did not accept the guest")]
    NotAccepted,
    /// `ErrBadStatus`: the call and the number, never the body.
    #[error("{call}: mtslink: unexpected status {status}")]
    BadStatus {
        /// The gateway call.
        call: &'static str,
        /// The status it answered.
        status: u16,
    },
    /// `ErrIncompleteReply`: the named call's reply lacks what the flow
    /// needs from it.
    #[error("{0}: mtslink: incomplete reply")]
    IncompleteReply(&'static str),
    /// `ErrConferenceID`: a conference id that is not a number.
    #[error("mtslink: conference id is not a number")]
    ConferenceId,
    /// `ErrNoEndpoint` from `offerURL`: the join URL has no scheme or no
    /// host.
    #[error("mtslink: room join URL missing: the join URL does not parse")]
    JoinUrl,
    /// `ErrJoinRefused`: the SFU's status and the first line of its words
    /// about the offer ([`signal::refusal_text`], printed lossily), less
    /// what they repeat of the request ([`signal::Held`]).
    #[error("mtslink: the SFU refused the join: status {status}: {text}")]
    JoinRefused {
        /// The status the join answered.
        status: u16,
        /// The refusal's first line, bounded and printable.
        text: String,
    },
    /// `ErrNoAnswer`: a join that answered 200 and no SDP.
    #[error("mtslink: the room join did not answer an SDP")]
    NoAnswer,
    /// `ErrNoPeerID`: an answer that names no peer.
    #[error("mtslink: the answer named no peer")]
    NoPeerId,
    /// A pin the SFU answered with another status than 200. A note for the
    /// log: the join stands without the pin.
    #[error("mtslink: pin: status {0}")]
    PinStatus(u16),
    /// A call that got no reply: the call's name and the reason, without
    /// the URL.
    #[error("mtslink: {call}: {cause}")]
    Transport {
        /// The call, as Go names it in the error.
        call: &'static str,
        /// What failed.
        cause: String,
    },
    /// `ErrSessionClosed`: the session was closed, or the join was torn
    /// down under the wait.
    #[error("mtslink: session closed")]
    SessionClosed,
    /// `ErrNoEndpoint`: a session made without the room join.
    #[error("mtslink: room join URL missing")]
    NoEndpoint,
    /// `ErrNoVideoTrack`: a join asked of a session nothing publishes on.
    #[error("mtslink: nothing to publish: the engine carries a video transport only")]
    NoVideoTrack,
    /// `ErrConnectTimeout`: the peer connection did not come up within
    /// [`session::CONNECT_WAIT`].
    #[error("mtslink: peer connection did not connect")]
    ConnectTimeout,
    /// `ErrConnectFailed`: the peer connection failed or closed before it
    /// ever connected.
    #[error("mtslink: peer connection failed")]
    ConnectFailed,
    /// The whole join took longer than [`session::CONNECT_BOUND`] (Go:
    /// the transport's context ending under `Connect`).
    #[error("mtslink: connect wait: context deadline exceeded")]
    ConnectBound,
    /// `builtin.ErrAuthFailed`: the provider gave no credentials, with its
    /// own error. Go wraps every error of the provider's `Issue` so, the
    /// first one and each refresh's (`builtin.go:216-220`).
    #[error("auth provider rejected the request: {0}")]
    Auth(Box<Error>),
    /// A rejoin whose provider gave no fresh credentials (`refresh
    /// credentials: …`, `mtslink.go:557`), with what the refresh returned:
    /// an [`Error::Auth`].
    #[error("refresh credentials: {0}")]
    Refresh(Box<Error>),
    /// Credentials past what a provider can issue
    /// ([`auth::Credentials::fits`]): the Rust client's own, Go has no
    /// bound on what a session keeps.
    #[error("mtslink: credentials too large")]
    CredentialsTooLarge,
    /// The run's join budget is spent (`max_joins`, the Rust client's own:
    /// Go has none): nothing is asked of the service.
    #[error("mtslink: join budget spent: {0} joins")]
    JoinBudget(u32),
    /// The peer connection refused a step of the join (`mtslink: new peer
    /// connection: …`, `mtslink: offer: …`, `mtslink: remote description:
    /// …`): the step and the first line of the reason, bounded.
    #[error("mtslink: {step}: {cause}")]
    Peer {
        /// The step, as Go names it in the error.
        step: &'static str,
        /// What the peer connection said.
        cause: String,
    },
}

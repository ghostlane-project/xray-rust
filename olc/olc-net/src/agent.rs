// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The `User-Agent` of a call whose Go code names no sender.
//!
//! Go's `net/http` then names itself, and by the protocol the call is
//! spoken in: the engine's client asks for HTTP/2 (`ForceAttemptHTTP2`,
//! `internal/protect/protect.go:98`), says [`GO_USER_AGENT_H2`] where the
//! server picks it and [`GO_USER_AGENT_HTTP1`] where it does not. A carrier
//! that ports such a call takes an [`Agent`] and asks it for the value once
//! the connection says which protocol it speaks ([`crate::stream::Dialed`]),
//! never before: the other pairings no Go client sends.

/// What Go's `net/http` calls itself on HTTP/1.1 (`defaultUserAgent`).
pub const GO_USER_AGENT_HTTP1: &str = "Go-http-client/1.1";
/// What Go's `net/http` calls itself on HTTP/2 (`http2defaultUserAgent`).
pub const GO_USER_AGENT_H2: &str = "Go-http-client/2.0";

/// The `User-Agent` of a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Agent<'a> {
    /// What the Go client at the pin sends: `net/http`'s own name for the
    /// protocol the call is spoken in.
    #[default]
    Go,
    /// These words in either protocol; empty sends no `User-Agent`.
    Named(&'a str),
}

impl<'a> Agent<'a> {
    /// The `User-Agent` on a connection that speaks HTTP/2 (`h2`) or
    /// HTTP/1.1; empty for none.
    #[must_use]
    pub const fn on(self, h2: bool) -> &'a str {
        match self {
            Self::Go if h2 => GO_USER_AGENT_H2,
            Self::Go => GO_USER_AGENT_HTTP1,
            Self::Named(words) => words,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_names_itself_by_the_protocol() {
        assert_eq!(Agent::default(), Agent::Go);
        assert_eq!(Agent::Go.on(false), "Go-http-client/1.1");
        assert_eq!(Agent::Go.on(true), "Go-http-client/2.0");
        for h2 in [false, true] {
            assert_eq!(Agent::Named("agent/1").on(h2), "agent/1");
            assert_eq!(Agent::Named("").on(h2), "");
        }
    }
}

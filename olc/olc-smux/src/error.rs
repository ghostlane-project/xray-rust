// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57, Copyright (c) 2016-2017 xtaci, MIT.

use std::fmt;
use std::io;
use std::sync::Arc;

/// The errors a session or stream reports. The texts are Go's, so that log
/// lines read as they did with the Go engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `io.ErrClosedPipe`: the stream or session is closed.
    ClosedPipe,
    /// `smux.ErrTimeout` (`smux/session.go:58-74`): the open or close
    /// deadline (`openCloseTimeout`, 30 s, `smux/session.go:40`) passed.
    Timeout,
    /// `smux.ErrGoAway` (`smux/session.go:73`): stream ids are exhausted.
    GoAway,
    /// `smux.ErrInvalidProtocol` (`smux/session.go:71`): the peer sent a
    /// frame `recvLoop` rejects.
    InvalidProtocol,
    /// `smux.ErrConsumed` (`smux/session.go:72`): the peer acknowledged more
    /// than this side wrote (`smux/stream.go:581-584`).
    Consumed,
    /// A read or write on the underlying connection failed. EOF is
    /// `UnexpectedEof` with Go's text, "EOF" or "unexpected EOF".
    Io(io::ErrorKind, Arc<str>),
    /// A [`Config`](crate::Config) that `VerifyConfig` (`smux/mux.go:74-108`)
    /// would reject, with Go's text, or a Rust-only setting out of range.
    Config(&'static str),
}

impl Error {
    pub(crate) fn eof(mid_frame: bool) -> Error {
        let text = if mid_frame { "unexpected EOF" } else { "EOF" };
        Error::Io(io::ErrorKind::UnexpectedEof, Arc::from(text))
    }

    /// Go's `io.EOF` from `io.ReadFull` at a frame boundary: the peer closed
    /// the connection cleanly. A stream reader blocked in `waitRead` gets
    /// exactly this value (`smux/stream.go:451-452`), which Go code treats as
    /// a clean end of stream.
    pub fn is_clean_eof(&self) -> bool {
        matches!(self, Error::Io(io::ErrorKind::UnexpectedEof, text) if &**text == "EOF")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ClosedPipe => f.write_str("io: read/write on closed pipe"),
            Error::Timeout => f.write_str("timeout"),
            Error::GoAway => f.write_str("stream id overflows, should start a new connection"),
            Error::InvalidProtocol => f.write_str("invalid protocol"),
            Error::Consumed => f.write_str("peer consumed more than sent"),
            Error::Io(_, text) => f.write_str(text),
            Error::Config(text) => f.write_str(text),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e.kind(), Arc::from(e.to_string()))
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match &e {
            Error::ClosedPipe => io::ErrorKind::BrokenPipe,
            Error::Timeout => io::ErrorKind::TimedOut,
            Error::GoAway => io::ErrorKind::Other,
            Error::InvalidProtocol | Error::Consumed => io::ErrorKind::InvalidData,
            Error::Io(kind, _) => *kind,
            Error::Config(_) => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, e)
    }
}

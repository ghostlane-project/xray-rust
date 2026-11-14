// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57 frame.go, Copyright (c) 2016-2017 xtaci, MIT.

//! The smux frame: an 8-byte header and its payload (`smux/frame.go`).
//!
//! ```text
//! | ver u8 | cmd u8 | length u16 LE | sid u32 LE | data[length] |
//! ```

use crate::Error;

/// The protocol version on every frame. olcRTC sets 2 on both sessions
/// (`internal/runtime/runtime.go:111,208`); version 1 is not implemented.
pub const VERSION: u8 = 2;

/// Header size: ver, cmd, length, sid (`smux/frame.go:53-59`).
pub const HEADER_SIZE: usize = 8;

/// The UPD payload size: consumed u32 LE, window u32 LE (`smux/frame.go:42-46`).
pub const UPD_SIZE: usize = 8;

/// The window a new stream assumes for its peer until the first UPD
/// (`smux/frame.go:48-51`, `smux/stream.go:190`).
pub const INITIAL_PEER_WINDOW: u32 = 262_144;

/// The largest payload a header can describe, and the largest
/// `MaxFrameSize` smux accepts (`smux/mux.go:95-97`).
pub const MAX_FRAME_SIZE: usize = 65_535;

/// The five commands (`smux/frame.go:30-40`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Cmd {
    /// Stream open.
    Syn = 0,
    /// Stream close: EOF for the reader.
    Fin = 1,
    /// Data.
    Psh = 2,
    /// No operation: the keepalive.
    Nop = 3,
    /// Window update, protocol version 2 only.
    Upd = 4,
}

impl Cmd {
    /// The command for a wire byte, if it is one.
    pub fn from_u8(b: u8) -> Option<Cmd> {
        match b {
            0 => Some(Cmd::Syn),
            1 => Some(Cmd::Fin),
            2 => Some(Cmd::Psh),
            3 => Some(Cmd::Nop),
            4 => Some(Cmd::Upd),
            _ => None,
        }
    }
}

/// A frame header as it is on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Protocol version.
    pub version: u8,
    /// Command byte (see [`Cmd`]).
    pub cmd: u8,
    /// Payload length.
    pub length: u16,
    /// Stream id; 0 for NOP.
    pub sid: u32,
}

impl Header {
    /// A version-2 header.
    pub const fn new(cmd: Cmd, length: u16, sid: u32) -> Header {
        Header {
            version: VERSION,
            cmd: cmd as u8,
            length,
            sid,
        }
    }

    /// The 8 bytes `sendLoop` writes (`smux/session.go:627-630`).
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let l = self.length.to_le_bytes();
        let s = self.sid.to_le_bytes();
        [self.version, self.cmd, l[0], l[1], s[0], s[1], s[2], s[3]]
    }

    /// `rawHeader`'s accessors (`smux/frame.go:74-91`).
    pub fn decode(b: [u8; HEADER_SIZE]) -> Header {
        Header {
            version: b[0],
            cmd: b[1],
            length: u16::from_le_bytes([b[2], b[3]]),
            sid: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// The checks `recvLoop` makes before it acts on a header
    /// (`smux/session.go:412-416,421-430,447-451,488-497,512-514`): the version
    /// must be 2; NOP, SYN and FIN carry nothing; UPD carries exactly 8 bytes;
    /// any other command is a protocol error that ends the session's reading.
    pub fn validate(&self) -> Result<Cmd, Error> {
        if self.version != VERSION {
            return Err(Error::InvalidProtocol);
        }
        let cmd = Cmd::from_u8(self.cmd).ok_or(Error::InvalidProtocol)?;
        let ok = match cmd {
            Cmd::Nop | Cmd::Syn | Cmd::Fin => self.length == 0,
            Cmd::Upd => self.length as usize == UPD_SIZE,
            Cmd::Psh => true,
        };
        if ok {
            Ok(cmd)
        } else {
            Err(Error::InvalidProtocol)
        }
    }
}

/// The UPD payload: bytes consumed so far (cumulative, wrapping) and the
/// receiver's own `MaxStreamBuffer` (`smux/stream.go:421-425`).
pub fn encode_upd(consumed: u32, window: u32) -> [u8; UPD_SIZE] {
    let c = consumed.to_le_bytes();
    let w = window.to_le_bytes();
    [c[0], c[1], c[2], c[3], w[0], w[1], w[2], w[3]]
}

/// `updHeader`'s accessors (`smux/frame.go:98-106`): (consumed, window).
pub fn decode_upd(b: [u8; UPD_SIZE]) -> (u32, u32) {
    (
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    )
}

/// One whole frame borrowed from a byte slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The header.
    pub header: Header,
    /// The payload, `header.length` bytes.
    pub data: &'a [u8],
}

impl Frame<'_> {
    /// Appends the frame's wire bytes to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(self.data);
    }
}

/// Splits a byte slice into whole frames, for tooling and tests. The session
/// does not use it: it reads incrementally.
pub fn frames(buf: &[u8]) -> Frames<'_> {
    Frames { rest: buf }
}

/// Iterator returned by [`frames`]. It stops at the first incomplete frame;
/// [`Frames::remainder`] holds what is left.
#[derive(Clone, Debug)]
pub struct Frames<'a> {
    rest: &'a [u8],
}

impl<'a> Frames<'a> {
    /// The bytes not yet returned as frames.
    pub fn remainder(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        let head: [u8; HEADER_SIZE] = self.rest.get(..HEADER_SIZE)?.try_into().ok()?;
        let header = Header::decode(head);
        let end = HEADER_SIZE + header.length as usize;
        let data = self.rest.get(HEADER_SIZE..end)?;
        self.rest = &self.rest[end..];
        Some(Frame { header, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-derived from smux/session.go:627-630 (LE length and sid after ver
    // and cmd) and the commands at smux/frame.go:30-40.
    #[test]
    fn header_bytes_match_go_send_loop() {
        assert_eq!(
            Header::new(Cmd::Syn, 0, 3).encode(),
            [2, 0, 0, 0, 3, 0, 0, 0]
        );
        assert_eq!(
            Header::new(Cmd::Fin, 0, 7).encode(),
            [2, 1, 0, 0, 7, 0, 0, 0]
        );
        assert_eq!(
            Header::new(Cmd::Psh, 0x1234, 0x0102_0304).encode(),
            [2, 2, 0x34, 0x12, 4, 3, 2, 1]
        );
        assert_eq!(
            Header::new(Cmd::Nop, 0, 0).encode(),
            [2, 3, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            Header::new(Cmd::Upd, 8, 5).encode(),
            [2, 4, 8, 0, 5, 0, 0, 0]
        );
        assert_eq!(
            Header::new(Cmd::Psh, 65535, u32::MAX).encode(),
            [2, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn header_round_trips() {
        for (cmd, len, sid) in [
            (0u8, 0u16, 1u32),
            (2, 65535, 2),
            (4, 8, u32::MAX),
            (9, 7, 0),
        ] {
            let h = Header {
                version: 2,
                cmd,
                length: len,
                sid,
            };
            assert_eq!(Header::decode(h.encode()), h);
        }
    }

    #[test]
    fn upd_payload_matches_go() {
        // smux/stream.go:423-424: consumed then MaxStreamBuffer, both LE.
        assert_eq!(encode_upd(6, 65536), [6, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(
            decode_upd(encode_upd(0xdead_beef, 524_288)),
            (0xdead_beef, 524_288)
        );
    }

    // smux/session.go:412-514.
    #[test]
    fn validate_follows_recv_loop() {
        let h = |v: u8, c: u8, l: u16| Header {
            version: v,
            cmd: c,
            length: l,
            sid: 3,
        };
        assert_eq!(h(1, 2, 5).validate(), Err(Error::InvalidProtocol));
        assert_eq!(h(2, 3, 0).validate(), Ok(Cmd::Nop));
        assert_eq!(h(2, 3, 1).validate(), Err(Error::InvalidProtocol));
        assert_eq!(h(2, 0, 0).validate(), Ok(Cmd::Syn));
        assert_eq!(h(2, 0, 4).validate(), Err(Error::InvalidProtocol));
        assert_eq!(h(2, 1, 0).validate(), Ok(Cmd::Fin));
        assert_eq!(h(2, 1, 2).validate(), Err(Error::InvalidProtocol));
        assert_eq!(h(2, 2, 0).validate(), Ok(Cmd::Psh));
        assert_eq!(h(2, 2, 900).validate(), Ok(Cmd::Psh));
        assert_eq!(h(2, 4, 8).validate(), Ok(Cmd::Upd));
        assert_eq!(h(2, 4, 4).validate(), Err(Error::InvalidProtocol));
        assert_eq!(h(2, 5, 0).validate(), Err(Error::InvalidProtocol));
        assert_eq!(h(2, 255, 0).validate(), Err(Error::InvalidProtocol));
    }

    #[test]
    fn frames_splits_and_keeps_the_remainder() {
        let mut buf = Vec::new();
        Frame {
            header: Header::new(Cmd::Psh, 3, 3),
            data: b"abc",
        }
        .encode_into(&mut buf);
        buf.extend_from_slice(&Header::new(Cmd::Fin, 0, 3).encode());
        buf.extend_from_slice(&[2, 2, 5, 0]);
        let mut it = frames(&buf);
        assert_eq!(it.next().map(|f| f.data), Some(&b"abc"[..]));
        assert_eq!(it.next().map(|f| f.header.cmd), Some(Cmd::Fin as u8));
        assert!(it.next().is_none());
        assert_eq!(it.remainder(), &[2, 2, 5, 0]);
    }
}

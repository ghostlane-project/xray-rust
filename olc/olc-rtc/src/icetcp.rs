// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Active ICE-TCP (RFC 6544) for a peer connection: the TCP connections it
//! opens to the remote's `tcptype passive` candidates, and RFC 4571's
//! framing on them.
//!
//! The Go engine at 2d4266af runs pion, which in a TCP network mode gathers
//! nothing of its own and, for every remote passive candidate, dials it and
//! makes a local `tcp` / `tcptype active` host candidate of the connection
//! (`ice/agent.go:1047-1104`, `ice/active_tcp.go`). MTS Link's client
//! default is that mode alone (`internal/client/link.go:847-852`). Here:
//!
//! - [`IceMode`] is the peer's choice (`udp`, `tcp`, `both`: Go's
//!   `iceNetworkTypes`);
//! - the dial is [`olc_net::net::dial_tcp`], a protected socket, where pion
//!   uses a plain dialer bound to the interface: stricter, and intended;
//! - each packet (STUN, DTLS, SRTP) goes as a 2-byte big-endian length and
//!   the packet (`ice/tcp_mux.go:443-468`); a frame longer than
//!   [`MAX_FRAME`], pion's read buffer (`ice/candidate.go:13`), ends the
//!   connection;
//! - a connection that broke is not dialled again (pion's neither).
//!
//! # Memory
//!
//! Per connection, of which a peer holds at most [`MAX_CONNS`]: one read
//! buffer of [`READ_BUF`] bytes for as long as the connection lives (as the
//! UDP socket's [`crate::peer::RECV_BUF`]), and nothing for writing while
//! the socket takes what it is given. No task and no queue: the peer's
//! driver reads and writes the sockets itself, so a slow driver slows the
//! far sender through TCP's window.
//!
//! # A socket that does not take a packet
//!
//! pion's write blocks its caller until the socket has room, so nothing is
//! lost and the sender is slowed. Here the part of a frame the socket
//! refused waits in the connection (one frame at most), and the driver
//! takes nothing more out of str0m, and gives it nothing, until it has
//! gone (`Conns::held_back`): str0m keeps what it has to send. Its data
//! channels' writers see their buffers fill (SCTP's own bound); its RTP
//! send queue has no bound, so the send line keeps one
//! ([`crate::media::SEND_BACKLOG_PACKETS`]) and refuses the batch that
//! would pass it. A socket stalled for longer than
//! [`STALL_MAX`] holds the peer back no more: its packets wait up to
//! [`OUT_PENDING_MAX`] bytes and are dropped beyond, as a full UDP socket
//! drops them, so the peer's timers and events (the lost path among them)
//! move on. The buffer is freed when it drains.

use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::task::Poll;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

/// The longest packet a frame carries, either way: pion's
/// `receiveMTU` (8192), the buffer its ICE-TCP reader reads a frame into.
pub const MAX_FRAME: usize = 8192;

/// RFC 4571's length field.
pub const FRAME_HEADER: usize = 2;

/// One connection's read buffer: a whole frame of the largest size.
pub const READ_BUF: usize = FRAME_HEADER + MAX_FRAME;

/// The ICE-TCP connections one peer holds at most; remote passive
/// candidates beyond it are not dialled. An SFU names one address or two
/// (MTS Link: one, port 443), each perhaps on two families.
pub const MAX_CONNS: usize = 4;

/// The remote passive candidates one peer dials at most (an SDP may name
/// one per interface of the far end, most of them unreachable); each dial
/// is a short task, and only [`MAX_CONNS`] of those that connect are kept.
pub const MAX_DIALS: usize = 16;

/// What one connection keeps of the packets its socket would not take, in
/// bytes: the frame being written and one more. Only a socket stalled past
/// [`STALL_MAX`] gets beyond one frame; packets beyond the bound are
/// dropped.
pub const OUT_PENDING_MAX: usize = 2 * READ_BUF;

/// The kernel's send buffer for an ICE-TCP connection (`SO_SNDBUF`, set
/// before the dial so autotuning never grows it; the kernel doubles it):
/// as a TURN connection's ([`crate::turn::STREAM_SNDBUF`]). It bounds what
/// sits unsent below the engine, where pion leaves the kernel to grow the
/// buffer to megabytes; 128 KiB in flight is 20 Mbit/s at a 50 ms round
/// trip.
pub const SNDBUF: u32 = 64 * 1024;

/// How long a socket that takes nothing holds the peer's output back (as
/// a blocking write holds pion's writer) before packets for it are dropped
/// instead.
pub const STALL_MAX: Duration = Duration::from_secs(1);

/// How soon the driver looks again while it is held back, the socket's
/// own readiness aside.
pub const STALL_POLL: Duration = Duration::from_millis(50);

/// What one peer's ICE-TCP holds at most, in bytes, every connection open
/// and stalled with a full pending buffer (the budget's row).
pub const MAX_HELD: usize = MAX_CONNS * (READ_BUF + OUT_PENDING_MAX);

// The budget's row stays under 100 KiB, and every kept connection had a dial.
const _: () = assert!(MAX_HELD <= 100 << 10);
const _: () = assert!(MAX_DIALS >= MAX_CONNS);

/// Which transports a peer's ICE uses: Go's `iceNetworkTypes`
/// (`mtslink.go:285-293`), by the same three words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IceMode {
    /// UDP alone: a host candidate (and relayed ones), no TCP dial.
    #[default]
    Udp,
    /// TCP alone: no host candidate, no TURN allocation, no UDP datagram;
    /// a connection to each remote passive TCP candidate.
    Tcp,
    /// Both: the UDP candidates and the active TCP ones; ICE's priorities
    /// pick.
    Both,
}

impl IceMode {
    /// Reads Go's word for a mode (`udp`, `tcp`, `both`).
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    /// Go's word for it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Both => "both",
        }
    }

    /// Whether UDP candidates are gathered.
    #[must_use]
    pub const fn udp(self) -> bool {
        !matches!(self, Self::Tcp)
    }

    /// Whether remote passive TCP candidates are dialled.
    #[must_use]
    pub const fn tcp(self) -> bool {
        !matches!(self, Self::Udp)
    }
}

/// A frame longer than [`MAX_FRAME`]: the stream cannot be read on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("ice tcp: a frame of {0} bytes is longer than {MAX_FRAME}")]
pub struct Oversize(pub usize);

/// RFC 4571's 2-byte length for a packet; `None` for one that does not fit
/// a frame.
#[must_use]
pub fn frame_header(len: usize) -> Option<[u8; FRAME_HEADER]> {
    if len > MAX_FRAME {
        return None;
    }
    u16::try_from(len).ok().map(u16::to_be_bytes)
}

/// Cuts a TCP stream back into its packets. Bytes are read into
/// [`Deframer::space`], told with [`Deframer::filled`], and taken a frame
/// at a time with [`Deframer::next_frame`].
#[derive(Debug)]
pub struct Deframer {
    buf: Box<[u8]>,
    start: usize,
    end: usize,
}

impl Default for Deframer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deframer {
    /// An empty one, with its [`READ_BUF`] bytes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; READ_BUF].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    /// Where the next read goes. Never empty after [`Deframer::next_frame`]
    /// returned `Ok(None)`: a partial frame is at most [`READ_BUF`] less
    /// one byte.
    pub fn space(&mut self) -> &mut [u8] {
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        &mut self.buf[self.end..]
    }

    /// `n` bytes were read into [`Deframer::space`].
    pub fn filled(&mut self, n: usize) {
        self.end = (self.end + n).min(self.buf.len());
    }

    /// Whether [`Deframer::next_frame`] has something to say without more
    /// bytes: a whole frame, or one too long.
    #[must_use]
    pub fn has_frame(&self) -> bool {
        let have = self.end - self.start;
        if have < FRAME_HEADER {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([
            self.buf[self.start],
            self.buf[self.start + 1],
        ]));
        len > MAX_FRAME || have >= FRAME_HEADER + len
    }

    /// The next whole packet, `Ok(None)` when more bytes are needed. A
    /// frame of no bytes is skipped.
    ///
    /// # Errors
    /// A frame longer than [`MAX_FRAME`]: nothing more can be read.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, Oversize> {
        loop {
            let have = self.end - self.start;
            if have < FRAME_HEADER {
                return Ok(None);
            }
            let len = usize::from(u16::from_be_bytes([
                self.buf[self.start],
                self.buf[self.start + 1],
            ]));
            if len > MAX_FRAME {
                return Err(Oversize(len));
            }
            if have < FRAME_HEADER + len {
                return Ok(None);
            }
            let at = self.start + FRAME_HEADER;
            self.start = at + len;
            if len > 0 {
                return Ok(Some(&self.buf[at..at + len]));
            }
        }
    }
}

/// What a connection's socket is ready for ([`Conns::ready`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ready {
    /// Bytes to read (or its end).
    Read,
    /// Room for what waits to be written.
    Write,
}

/// A connection that ended, for the driver to judge ([`Conns::take_lost`]).
#[derive(Debug)]
pub(crate) struct Lost {
    /// Its local address (the local candidate's).
    pub(crate) local: SocketAddr,
    /// The remote candidate it was dialled to.
    pub(crate) remote: SocketAddr,
    /// Whether a packet ever arrived on it: a path ICE had checked.
    pub(crate) heard: bool,
    /// Why, in Go's words where it has them.
    pub(crate) why: String,
}

struct Conn {
    stream: TcpStream,
    local: SocketAddr,
    remote: SocketAddr,
    de: Deframer,
    /// Framed bytes the socket has not taken, from `out_at` on.
    out: Vec<u8>,
    out_at: usize,
    /// Since when bytes wait.
    stalled: Option<Instant>,
    heard: bool,
    lost: Option<String>,
}

impl Conn {
    fn pending(&self) -> usize {
        self.out.len() - self.out_at
    }

    /// One packet out: framed, to the socket, the rest (or all of it) to
    /// the pending buffer. `false` for a packet dropped.
    fn send(&mut self, data: &[u8], now: Instant) -> bool {
        let Some(header) = frame_header(data.len()) else {
            return false;
        };
        if self.lost.is_some() {
            return false;
        }
        if self.pending() > 0 {
            if self.pending() + FRAME_HEADER + data.len() > OUT_PENDING_MAX {
                return false;
            }
            self.out.extend_from_slice(&header);
            self.out.extend_from_slice(data);
            return true;
        }
        let wrote = match self
            .stream
            .try_write_vectored(&[IoSlice::new(&header), IoSlice::new(data)])
        {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            Err(e) => {
                self.lost = Some(format!("write: {e}"));
                return false;
            }
        };
        // A frame is never left half written: what the socket did not
        // take waits, whatever its size (one frame at most here).
        if wrote < FRAME_HEADER {
            self.out.extend_from_slice(&header[wrote..]);
            self.out.extend_from_slice(data);
        } else if wrote < FRAME_HEADER + data.len() {
            self.out.extend_from_slice(&data[wrote - FRAME_HEADER..]);
        }
        if self.pending() > 0 {
            self.stalled = Some(now);
        }
        true
    }

    /// Writes what waits; frees the buffer once it is empty.
    fn flush(&mut self) {
        while self.pending() > 0 {
            match self.stream.try_write(&self.out[self.out_at..]) {
                Ok(0) => {
                    self.lost = Some("write: the connection closed".into());
                    break;
                }
                Ok(n) => self.out_at += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // What went is given up now, so the buffer's length
                    // stays the bytes that wait.
                    self.out.drain(..self.out_at);
                    self.out_at = 0;
                    return;
                }
                Err(e) => {
                    self.lost = Some(format!("write: {e}"));
                    break;
                }
            }
        }
        self.out = Vec::new();
        self.out_at = 0;
        self.stalled = None;
    }
}

/// One peer's ICE-TCP connections, owned by its driver.
#[derive(Default)]
pub(crate) struct Conns {
    list: Vec<Conn>,
    dropped: u64,
}

impl Conns {
    /// Takes a connected stream; returns its local address, the local
    /// candidate's. `None` (the stream dropped) beyond [`MAX_CONNS`], for a
    /// stream without addresses, or for a second one between the same two.
    pub(crate) fn add(&mut self, stream: TcpStream) -> Option<(SocketAddr, SocketAddr)> {
        if self.list.len() >= MAX_CONNS {
            return None;
        }
        let (local, remote) = (stream.local_addr().ok()?, stream.peer_addr().ok()?);
        if self.find(local, remote).is_some() {
            return None;
        }
        self.list.push(Conn {
            stream,
            local,
            remote,
            de: Deframer::new(),
            out: Vec::new(),
            out_at: 0,
            stalled: None,
            heard: false,
            lost: None,
        });
        Some((local, remote))
    }

    fn find(&self, local: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.list
            .iter()
            .position(|c| c.local == local && c.remote == remote)
    }

    /// Sends one packet from `source` to `destination`. A packet for which
    /// there is no connection (ICE pairs every local TCP candidate with
    /// every remote one; only the dialled pair exists), or that the
    /// connection cannot hold, is dropped and counted.
    pub(crate) fn send(
        &mut self,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
        now: Instant,
    ) {
        let sent = self
            .find(source, destination)
            .is_some_and(|i| self.list[i].send(data, now));
        if !sent {
            self.dropped += 1;
        }
    }

    /// Whether a connection's socket has bytes waiting, for less than
    /// [`STALL_MAX`]: the driver takes nothing more out of str0m until they
    /// have gone.
    pub(crate) fn held_back(&self, now: Instant) -> bool {
        self.list.iter().any(|c| {
            c.lost.is_none()
                && c.pending() > 0
                && c.stalled
                    .is_some_and(|since| now.saturating_duration_since(since) < STALL_MAX)
        })
    }

    /// Packets dropped so far ([`Conns::send`]).
    pub(crate) const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The connections held (one that ended is held until
    /// [`Conns::take_lost`] removes it).
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }

    /// How many of the connections held a packet has arrived on.
    #[cfg(test)]
    pub(crate) fn heard(&self) -> usize {
        self.list.iter().filter(|c| c.heard).count()
    }

    /// Waits until a connection has a packet read already or can be read
    /// (with `reads`), or one with bytes waiting can be written; never
    /// returns with no connection. Cancel safe: it holds nothing but the
    /// sockets' wakers.
    pub(crate) async fn ready(&self, reads: bool) -> (usize, Ready) {
        poll_fn(|cx| {
            for (i, c) in self.list.iter().enumerate() {
                if c.lost.is_some() {
                    continue;
                }
                if reads && (c.de.has_frame() || c.stream.poll_read_ready(cx).is_ready()) {
                    return Poll::Ready((i, Ready::Read));
                }
                if c.pending() > 0 && c.stream.poll_write_ready(cx).is_ready() {
                    return Poll::Ready((i, Ready::Write));
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Acts on what [`Conns::ready`] returned for connection `i`: a write
    /// of what waits, or one packet given to `feed` with the connection's
    /// remote and local addresses, read from the socket when none was
    /// waiting. One packet a turn, as one datagram a turn comes from the
    /// UDP socket: str0m is polled between two (its DTLS holds only a few
    /// records it has not been polled for; more is `receive queue full`,
    /// the peer's end). The packets a read brought beside the first wait in
    /// the read buffer.
    ///
    /// # Errors
    /// `feed`'s own (the driver's end); a connection's errors are kept for
    /// [`Conns::take_lost`].
    pub(crate) fn turn<E>(
        &mut self,
        i: usize,
        what: Ready,
        mut feed: impl FnMut(SocketAddr, SocketAddr, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(c) = self.list.get_mut(i) else {
            return Ok(());
        };
        if what == Ready::Write {
            c.flush();
            return Ok(());
        }
        if !c.de.has_frame() {
            match c.stream.try_read(c.de.space()) {
                // Go's words for a stream that ended.
                Ok(0) => c.lost = Some("read: EOF".into()),
                Ok(n) => c.de.filled(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => c.lost = Some(format!("read: {e}")),
            }
        }
        match c.de.next_frame() {
            Ok(Some(frame)) => {
                c.heard = true;
                feed(c.remote, c.local, frame)?;
            }
            Ok(None) => {}
            Err(e) => c.lost = Some(e.to_string()),
        }
        Ok(())
    }

    /// Removes one connection that ended (its socket closes) and says which.
    pub(crate) fn take_lost(&mut self) -> Option<Lost> {
        let i = self.list.iter().position(|c| c.lost.is_some())?;
        let c = self.list.remove(i);
        Some(Lost {
            local: c.local,
            remote: c.remote,
            heard: c.heard,
            why: c.lost.unwrap_or_default(),
        })
    }

    /// Closes every connection (tests: a path cut under a live peer).
    #[cfg(test)]
    pub(crate) fn cut(&mut self) {
        self.list.clear();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::testing::bounded;

    fn framed(packets: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in packets {
            out.extend_from_slice(&frame_header(p.len()).unwrap());
            out.extend_from_slice(p);
        }
        out
    }

    /// Feeds `bytes` in pieces of `step` and returns the packets cut.
    fn deframe(bytes: &[u8], step: usize) -> Result<Vec<Vec<u8>>, Oversize> {
        let mut de = Deframer::new();
        let mut got = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let space = de.space();
            assert!(!space.is_empty(), "no room to read into");
            let n = step.min(rest.len()).min(space.len());
            space[..n].copy_from_slice(&rest[..n]);
            de.filled(n);
            rest = &rest[n..];
            while let Some(frame) = de.next_frame()? {
                got.push(frame.to_vec());
            }
        }
        Ok(got)
    }

    #[test]
    fn the_modes_take_gos_words() {
        for (word, mode, udp, tcp) in [
            ("udp", IceMode::Udp, true, false),
            ("tcp", IceMode::Tcp, false, true),
            ("both", IceMode::Both, true, true),
        ] {
            assert_eq!(IceMode::parse(word), Some(mode));
            assert_eq!(mode.as_str(), word);
            assert_eq!((mode.udp(), mode.tcp()), (udp, tcp), "{word}");
        }
        assert_eq!(IceMode::parse("TCP"), None);
        assert_eq!(IceMode::parse(""), None);
        assert_eq!(IceMode::default(), IceMode::Udp);
    }

    #[test]
    fn the_header_is_rfc_4571s() {
        assert_eq!(frame_header(0), Some([0, 0]));
        assert_eq!(frame_header(1200), Some([0x04, 0xb0]));
        assert_eq!(frame_header(MAX_FRAME), Some([0x20, 0x00]));
        assert_eq!(frame_header(MAX_FRAME + 1), None);
        assert_eq!(frame_header(70_000), None);
    }

    /// The same packets come out however the stream's bytes were cut: one
    /// at a time, mid-header, mid-packet, several frames in one read.
    #[test]
    fn frames_survive_split_and_joined_reads() {
        let a = [1u8; 20];
        let b = [2u8; 1200];
        let c = [3u8; 1];
        let d = vec![4u8; 3000];
        let bytes = framed(&[&a, &b, &[], &c, &d]);
        let want: Vec<Vec<u8>> = vec![a.to_vec(), b.to_vec(), c.to_vec(), d.clone()];
        for step in [
            1,
            2,
            3,
            7,
            21,
            22,
            23,
            1199,
            1223,
            4096,
            READ_BUF,
            usize::MAX,
        ] {
            assert_eq!(deframe(&bytes, step).unwrap(), want, "step {step}");
        }
    }

    /// pion's bound: 8192 bytes pass, also right behind another frame; one
    /// byte more ends the reader, and nothing after it is read.
    #[test]
    fn a_frame_of_8192_passes_and_a_longer_one_ends_the_reader() {
        let big = vec![9u8; MAX_FRAME];
        let small = [5u8; 100];
        for step in [1, 4096, READ_BUF] {
            let got = deframe(&framed(&[&small, &big, &big, &small]), step).unwrap();
            assert_eq!(got.len(), 4, "step {step}");
            assert_eq!(got[1], big);
            assert_eq!(got[2], big);
            assert_eq!(got[3], small);
        }
        let mut bytes = framed(&[&small]);
        bytes.extend_from_slice(&u16::try_from(MAX_FRAME + 1).unwrap().to_be_bytes());
        bytes.extend_from_slice(&vec![0u8; MAX_FRAME + 1]);
        bytes.extend_from_slice(&framed(&[&small]));
        for step in [1, 4096, READ_BUF] {
            assert_eq!(
                deframe(&bytes, step),
                Err(Oversize(MAX_FRAME + 1)),
                "step {step}"
            );
        }
        let mut de = Deframer::new();
        de.space()[..2].copy_from_slice(&[0xff, 0xff]);
        de.filled(2);
        assert_eq!(de.next_frame(), Err(Oversize(65535)));
        // And it stays so: the stream has no frame boundary any more.
        assert_eq!(de.next_frame(), Err(Oversize(65535)));
    }

    #[test]
    fn the_bounds_are_the_budgets() {
        assert_eq!(READ_BUF, 8194);
        assert_eq!(MAX_HELD, 4 * (8194 + 2 * 8194));
        // A connection's own state: the socket, two addresses, the buffers'
        // handles.
        assert!(size_of::<Conn>() <= 224, "{}", size_of::<Conn>());
        assert!(size_of::<Deframer>() <= 32, "{}", size_of::<Deframer>());
    }

    /// A connected pair on loopback: the dialled end and the accepted one.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dial = TcpStream::connect(ln.local_addr().unwrap());
        let (a, b) = tokio::join!(dial, ln.accept());
        (a.unwrap(), b.unwrap().0)
    }

    /// Packets go out framed, to the connection of their two addresses
    /// alone; one for no connection, or too long for a frame, is dropped
    /// and counted.
    #[tokio::test]
    async fn a_packet_goes_framed_on_its_own_connection() {
        bounded(async {
            let (a, mut far) = tcp_pair().await;
            let mut conns = Conns::default();
            let (local, remote) = conns.add(a).unwrap();
            let now = Instant::now();
            conns.send(local, remote, &[7u8; 300], now);
            conns.send(local, remote, &[8u8; 5], now);
            assert!(!conns.held_back(now));
            let mut got = vec![0u8; 2 + 300 + 2 + 5];
            far.read_exact(&mut got).await.unwrap();
            assert_eq!(got, framed(&[&[7u8; 300], &[8u8; 5]]));
            assert_eq!(conns.dropped(), 0);

            let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
            conns.send(local, elsewhere, &[1], now);
            conns.send(elsewhere, remote, &[1], now);
            conns.send(local, remote, &vec![0u8; MAX_FRAME + 1], now);
            assert_eq!(conns.dropped(), 3);
            conns.send(local, remote, &[9u8; 1], now);
            let mut got = [0u8; 3];
            far.read_exact(&mut got).await.unwrap();
            assert_eq!(
                got,
                [0, 1, 9],
                "nothing of the dropped ones reached the wire"
            );
        })
        .await;
    }

    /// A far end that does not read: the driver is held back from the
    /// first byte the socket refuses, for [`STALL_MAX`] and no longer; what
    /// is sent all the same waits up to the bound and no further, whole
    /// frames only; once the far end reads, every byte kept arrives in
    /// order and the buffer is given back.
    #[tokio::test]
    async fn a_stalled_socket_holds_its_bound_and_drains_in_order() {
        bounded(async {
            let (a, mut far) = tcp_pair().await;
            let mut conns = Conns::default();
            let (local, remote) = conns.add(a).unwrap();
            let mut sent = 0u32;
            let t0 = Instant::now();
            let mut held_from = None;
            // Far more than the kernel's buffers and the bound together.
            for i in 0..40_000u32 {
                let mut p = [0u8; 1200];
                p[..4].copy_from_slice(&i.to_be_bytes());
                let before = conns.dropped();
                assert_eq!(conns.held_back(t0), held_from.is_some(), "packet {i}");
                conns.send(local, remote, &p, t0);
                if held_from.is_none() && conns.list[0].pending() > 0 {
                    // The driver would stop here: one frame at most waits.
                    assert!(conns.list[0].pending() <= READ_BUF);
                    assert_eq!(conns.dropped(), 0);
                    held_from = Some(i);
                }
                if conns.dropped() == before {
                    assert_eq!(sent, i, "a packet was kept after one was dropped");
                    sent += 1;
                }
                assert!(conns.list[0].pending() <= OUT_PENDING_MAX + READ_BUF);
            }
            assert!(
                conns.dropped() > 0,
                "the socket took 48 MB without stalling"
            );
            assert!(conns.list[0].pending() > 0);
            assert!(conns.held_back(t0 + STALL_MAX - Duration::from_millis(1)));
            assert!(!conns.held_back(t0 + STALL_MAX), "held back for good");
            assert!(conns.list[0].out.capacity() <= 2 * (OUT_PENDING_MAX + READ_BUF));

            let reader = tokio::spawn(async move {
                let mut de = Deframer::new();
                let mut next = 0u32;
                while next < sent {
                    let n = far.read(de.space()).await.unwrap();
                    assert!(n > 0, "the stream ended at packet {next} of {sent}");
                    de.filled(n);
                    while let Some(f) = de.next_frame().unwrap() {
                        assert_eq!(f.len(), 1200);
                        assert_eq!(f[..4], next.to_be_bytes());
                        next += 1;
                    }
                }
                far
            });
            while conns.list[0].pending() > 0 {
                let (i, what) = conns.ready(false).await;
                assert_eq!(what, Ready::Write);
                conns.turn(i, what, |_, _, _| Ok::<(), ()>(())).unwrap();
            }
            assert_eq!(
                conns.list[0].out.capacity(),
                0,
                "an idle connection holds no write buffer"
            );
            assert!(!conns.held_back(t0));
            let _far = reader.await.unwrap();
            assert!(conns.take_lost().is_none());
        })
        .await;
    }

    /// What arrives is cut into packets and handed up with the connection's
    /// addresses; the far end's close, or a frame too long, loses the
    /// connection, and the driver is told which and whether it was heard.
    #[tokio::test]
    async fn arrivals_are_handed_up_and_an_end_is_told() {
        bounded(async {
            let (a, mut far) = tcp_pair().await;
            let (b, mut far_b) = tcp_pair().await;
            let mut conns = Conns::default();
            let (local, remote) = conns.add(a).unwrap();
            let (local_b, remote_b) = conns.add(b).unwrap();
            far.write_all(&framed(&[&[1u8; 10], &[2u8; 20]]))
                .await
                .unwrap();
            let mut got = Vec::new();
            let mut most = 0;
            while got.len() < 2 {
                let (i, what) = conns.ready(true).await;
                let before = got.len();
                conns
                    .turn(i, what, |from, to, p| {
                        got.push((from, to, p.to_vec()));
                        Ok::<(), ()>(())
                    })
                    .unwrap();
                most = most.max(got.len() - before);
            }
            assert_eq!(most, 1, "one packet a turn: str0m is polled between two");
            assert_eq!(got[0], (remote, local, vec![1u8; 10]));
            assert_eq!(got[1], (remote, local, vec![2u8; 20]));
            assert_eq!((conns.len(), conns.heard()), (2, 1));

            // The unheard one sends a frame too long; the heard one closes.
            far_b.write_all(&[0x20, 0x01, 0, 0]).await.unwrap();
            drop(far);
            let mut lost = Vec::new();
            while lost.len() < 2 {
                let (i, what) = conns.ready(true).await;
                conns.turn(i, what, |_, _, _| Ok::<(), ()>(())).unwrap();
                while let Some(l) = conns.take_lost() {
                    lost.push(l);
                }
            }
            lost.sort_by_key(|l| l.heard);
            assert_eq!((lost[0].local, lost[0].remote), (local_b, remote_b));
            assert!(!lost[0].heard);
            assert_eq!(
                lost[0].why,
                "ice tcp: a frame of 8193 bytes is longer than 8192"
            );
            assert_eq!((lost[1].local, lost[1].remote), (local, remote));
            assert!(lost[1].heard);
            assert_eq!(lost[1].why, "read: EOF");
            assert!(conns.list.is_empty());
        })
        .await;
    }

    /// No more than [`MAX_CONNS`] connections, and one per address pair.
    #[tokio::test]
    async fn connections_are_bounded() {
        bounded(async {
            let mut conns = Conns::default();
            let mut far = Vec::new();
            for _ in 0..MAX_CONNS {
                let (a, b) = tcp_pair().await;
                assert!(conns.add(a).is_some());
                far.push(b);
            }
            let (a, _b) = tcp_pair().await;
            assert!(conns.add(a).is_none());
            assert_eq!(conns.list.len(), MAX_CONNS);
        })
        .await;
    }
}

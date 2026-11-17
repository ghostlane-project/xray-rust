//! olcRTC's lanes over a record stream, as `internal/muxconn` at the engine
//! pin does them, without IO.
//!
//! A transport carries messages; smux wants a byte stream. Each smux frame,
//! or each batch of whole frames, goes out as one OLC2 record in one
//! transport message ([`Sender`], [`Batcher`]); each message that arrives is
//! opened into a bounded inbound queue that reads as a byte stream
//! ([`Receiver`]). The data session and the control session each have a lane
//! of their own ([`olc_wire::record::Lane`]), and so do datagrams
//! ([`DatagramLane`]).
//!
//! The async adaptors that turn these into smux's conn, and the waits Go's
//! `Conn.Write` makes on the transport, belong to the client (M3); this crate
//! is the state each of them drives. Every buffer here is sized when its
//! owner is made, from a formula stated where it is made, and never grows.
//!
//! Not ported: `PushSession` and `PushOpened` (conn.go:350-398), which only a
//! server uses to tell a client's new smux session from its old one, and
//! the multi-key `PinGroup` of a server's key ring.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod batch;
pub mod conn;
pub mod datagram;
pub mod scan;

use std::time::Duration;

pub use batch::{Append, Batch, Batcher, Turn};
pub use conn::{DecryptStats, Features, Push, Receiver, SendError, Sender, Stats};
pub use datagram::DatagramLane;

/// The inbound queue of a Go conn holds this many records (conn.go:76-82).
/// [`conn::inbound_capacity`] turns it into bytes.
pub const INBOUND_QUEUE: usize = 128;
/// The capacity Go's pooled plaintext buffers are born with (conn.go:84-89).
/// Recorded for the vectors; the Rust receiver sizes its queue by the
/// transport instead.
pub const POOLED_FRAME_CAP: usize = 64 * 1024;
/// A write that waits this long for the transport to accept data fails, and
/// the conn counts a stall (conn.go:91-96, 697-711; [`Stats::send_stalled`]).
pub const WRITE_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// The least time between two log lines about records that did not open
/// (conn.go:98-101).
pub const DECRYPT_LOG_INTERVAL: Duration = Duration::from_secs(30);

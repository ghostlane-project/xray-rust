//! The olcRTC record layer and wire messages, byte for byte as the Go engine
//! at commit `2d4266af3947f4d9940efafb0d5aabb6207f6659` writes and reads them.
//!
//! The olcRTC client tunnels a SOCKS byte stream over a WebRTC carrier to a Go
//! server. Everything here is what both ends have to agree on, below the smux
//! session and above the carrier: the sealed record ([`record`]), the length
//! framing of the handshake and control streams ([`framing`]), the handshake
//! ([`handshake`]), the control stream ([`control`]), the CONNECT request of a
//! tunnel stream ([`connect`]), the UDP relay's frames ([`udpwire`]), and the
//! sizes that tie them to a transport ([`sizes`]). smux itself is `olc-smux`;
//! carrying records over a transport is `olc-muxconn`.
//!
//! Every item says which Go file and lines it reproduces. The golden vectors
//! under `olc/interop/vectors/2d4266af/` were written by that Go code, and the
//! tests check this crate against them; with `OLC_GO_ORACLE` set, they also
//! hand what this crate writes to the Go code and check how it reads it.
//!
//! Nothing here does I/O except the small blocking readers in [`framing`],
//! [`handshake`] and [`control`], which take any [`std::io::Read`]. Writers
//! append to a caller's `Vec<u8>`, so a caller that keeps its buffer pays no
//! allocation per message.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod connect;
pub mod control;
pub mod framing;
pub mod gojson;
pub mod handshake;
pub mod record;
pub mod sizes;
pub mod udpwire;

/// The engine commit this crate reproduces.
pub const ENGINE_PIN: &str = "2d4266af3947f4d9940efafb0d5aabb6207f6659";

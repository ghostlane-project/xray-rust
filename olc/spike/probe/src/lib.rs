//! The M2 spike's probes, as a library so the iOS link test (ios-link) runs the same code.
//!
//! - [`mem`]: what a probe costs (the owner's rule: memory is a design input). A counting
//!   allocator for the Rust heap, the process RSS/footprint, and the C heap (BoringSSL and
//!   aws-lc allocate there, critique C7).
//! - [`lk`]: the two LiveKit messages the SFU relays, hand-encoded (DataPacket, UserPacket).
//! - [`wire`]: taps on the datagrams str0m sends and receives: the first STUN binding request
//!   and the first DTLS ClientHello, as hex, for the shape comparisons.
//! - [`peer`]: one str0m `Rtc` on one UDP socket, driven synchronously.
//! - [`loopback`]: two `Rtc`s joined in-process, no sockets: a DTLS handshake and a data
//!   channel echo, for any crypto provider.
//! - [`crypto`]: the providers by name: `dimpl` (str0m's default) and `boring`.

pub mod crypto;
pub mod lk;
pub mod loopback;
pub mod mem;
pub mod peer;
pub mod util;
pub mod wire;

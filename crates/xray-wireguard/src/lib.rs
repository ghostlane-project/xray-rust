// Size lints (clippy.toml, memory model 05 T9) guard the app's paths. Test code
// is off them: a test's stack is not a tunnel worker's and a test's future
// is never a flow's.
#![cfg_attr(test, allow(clippy::large_futures, clippy::large_stack_arrays))]
//! WireGuard client transport and an independently bounded userspace IP interface.
mod client;
mod config;
mod io;
mod netstack;
mod stack;

pub use client::{Client, Error, TcpStream, UdpSession};
pub use config::{Config, PeerConfig};
pub use netstack::{Netstack, NetstackPackets};

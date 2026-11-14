// Size lints (clippy.toml, memory model 05 T9) guard the app's paths. Test code
// is off them: a test's stack is not a tunnel worker's and a test's future
// is never a flow's.
#![cfg_attr(test, allow(clippy::large_futures, clippy::large_stack_arrays))]
mod aead;
mod erase;
mod record_buffer;

pub mod go_url;

pub mod hysteria;
pub mod inbound;
pub mod mux;
pub mod outbound;
pub mod reverse;
pub mod shadowsocks;
pub mod shadowsocks2022;
pub mod trojan;
pub mod vless;
pub mod vmess;
pub mod wireguard;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

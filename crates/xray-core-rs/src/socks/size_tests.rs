//! Size guards for the SOCKS inbound's futures (memory model 05, section 15 T1).
//! Release sizes: run with `cargo test --release`.
use super::*;
use crate::size_guard::{never, size_of_returned};

/// One UDP flow's task future lives for the flow. Formula: the flow holds its
/// own state (target, `SocksUdpFlowContext` 400 B, the queue receiver, the
/// shutdown receiver, the open permit) plus the largest suspended callee, and
/// every arm that dials or relays is boxed, so it holds one pointer for it.
/// Base 36,128 B; ceiling 4,096 B = one 4 KiB page of Rust heap per flow.
const UDP_FLOW_FUTURE_MAX: usize = 4_096;
/// One SOCKS TCP connection's task future. Base 9,264 B, 5,776 B reached
/// (SOCKS 4 and HTTP handlers, 5.7 and 7.3 KB, boxed; the relay phase's
/// state is what is left). Ceiling 6,144 B = 6 KiB, reached plus 368.
/// The model's 4 KB needs the relay phase's locals shrunk, not boxed: boxing
/// the relay moves its 2.6 KB to another block and saves nothing.
const CONNECTION_FUTURE_MAX: usize = 6_144;
/// The CONNECT handler. Base 6,640 B, 4,816 B reached with the dial boxed;
/// ceiling 5,120 B, reached plus 304.
const CONNECT_FUTURE_MAX: usize = 5_120;

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn udp_flow_future_stays_under_one_page() {
    let size =
        size_of_returned(|| bridge_socks_udp_flow(never(), never(), never(), never(), never()));
    assert!(
        size <= UDP_FLOW_FUTURE_MAX,
        "bridge_socks_udp_flow future is {size} B, ceiling {UDP_FLOW_FUTURE_MAX} B"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn socks_connection_future_stays_small() {
    let size = size_of_returned(|| {
        handle_socks_connection(
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
        )
    });
    assert!(
        size <= CONNECTION_FUTURE_MAX,
        "handle_socks_connection future is {size} B, ceiling {CONNECTION_FUTURE_MAX} B"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn socks_connect_future_stays_within_model_ceiling() {
    let size = size_of_returned(|| {
        handle_socks_connect::<true>(
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
            never(),
        )
    });
    assert!(
        size <= CONNECT_FUTURE_MAX,
        "handle_socks_connect future is {size} B, ceiling {CONNECT_FUTURE_MAX} B"
    );
}

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
/// One SOCKS TCP connection's task future. Base 9,264 B; model target about
/// 4 KB, ceiling 4,608 B = 4,096 + 512.
const CONNECTION_FUTURE_MAX: usize = 4_608;
/// Model ceiling (base 6,640 B, section 15 T1).
const CONNECT_FUTURE_MAX: usize = 7_168;

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn udp_flow_future_stays_under_one_page() {
    let size = size_of_returned(|| {
        bridge_socks_udp_flow(never(), never(), never(), never(), never())
    });
    println!("bridge_socks_udp_flow: {size} B");
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
    println!("handle_socks_connection: {size} B");
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
    println!("handle_socks_connect::<true>: {size} B");
    assert!(
        size <= CONNECT_FUTURE_MAX,
        "handle_socks_connect future is {size} B, ceiling {CONNECT_FUTURE_MAX} B"
    );
}

#[test]
fn print_parts() {
    let n = |name: &str, size: usize| println!("PART {name}: {size} B");
    n("associate", size_of_returned(|| handle_socks_udp_associate(never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never())));
    n("in_tcp", size_of_returned(|| handle_socks_udp_in_tcp(never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never())));
    n("socks4", size_of_returned(|| handle_socks4_connection(never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never())));
    n("http", size_of_returned(|| handle_socks_http_connection(never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never(), never())));
    n("negotiate", size_of_returned(|| negotiate_socks5(never::<&mut TcpStream>(), never::<&SocksInboundAuth>())));
}

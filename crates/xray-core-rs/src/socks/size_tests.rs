//! Size guards for the SOCKS inbound's futures (memory model 05, section 15 T1).
//! Release sizes: run with `cargo test --release`. On Linux the relay phase is
//! `copy_bidirectional_with_splice` (2,648 B), on iOS the 1,992 B copy loop, so
//! the connection guards are about 650 B above what iOS holds.
use super::*;
use crate::size_guard::{never, size_of_returned};

/// One UDP flow's task future lives for the flow. Formula: the flow holds its
/// own state (target, `SocksUdpFlowContext` 400 B, the queue receiver, the
/// shutdown receiver, the open permit) plus one pointer for the boxed arm it
/// awaits. Base 36,192 B, reached 2,288 B; ceiling 2,560 B (reached + 12 %).
const UDP_FLOW_FUTURE_MAX: usize = 2_560;
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

/// The boxed arms of a UDP flow: a flow holds one of them for its life, so
/// each is guarded at the size reached (VLESS 2,416 B, was 9,920 B with its
/// open future stored twice; DNS 6,192 B; freedom 4,768 B; the datagram relay
/// 7,248 B, was 34,384 B) plus about 6 %.
const VLESS_ARM_MAX: usize = 2_560;
const DNS_ARM_MAX: usize = 6_656;
const FREEDOM_ARM_MAX: usize = 5_120;
const DATAGRAM_ARM_MAX: usize = 7_680;

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn udp_flow_arms_stay_small() {
    let vless = size_of_returned(|| {
        bridge_socks_udp_vless_flow(
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
    let dns = size_of_returned(|| {
        bridge_socks_udp_dns_flow(
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
    let freedom = size_of_returned(|| {
        bridge_socks_udp_freedom_flow(
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
    let datagram = size_of_returned(|| {
        datagram::bridge(
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
        vless <= VLESS_ARM_MAX,
        "VLESS UDP flow is {vless} B, ceiling {VLESS_ARM_MAX} B"
    );
    assert!(
        dns <= DNS_ARM_MAX,
        "DNS UDP flow is {dns} B, ceiling {DNS_ARM_MAX} B"
    );
    assert!(
        freedom <= FREEDOM_ARM_MAX,
        "freedom UDP flow is {freedom} B, ceiling {FREEDOM_ARM_MAX} B"
    );
    assert!(
        datagram <= DATAGRAM_ARM_MAX,
        "datagram relay is {datagram} B, ceiling {DATAGRAM_ARM_MAX} B"
    );
}

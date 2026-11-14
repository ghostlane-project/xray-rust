//! Size guards for the outbound dial path (memory model 05, section 15 T1).
//! Release sizes: run with `cargo test --release`.
use super::*;
use crate::size_guard::{never, size_of_returned};

/// Model ceiling: base 4,352 B plus 256 B.
const OPEN_TCP_FUTURE_MAX: usize = 4_608;
/// Model ceiling: base 216 B plus 40 B.
const VISION_STREAM_MAX: usize = 256;

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn open_tcp_stream_future_stays_within_model_ceiling() {
    let size = size_of_returned(|| {
        open_tcp_stream_with_resolvers_and_dialer(
            never(),
            never(),
            never::<&dyn DnsResolver>(),
            never::<&dyn DnsResolver>(),
            never(),
            never(),
        )
    });
    assert!(
        size <= OPEN_TCP_FUTURE_MAX,
        "open_tcp_stream_with_resolvers_and_dialer future is {size} B, ceiling {OPEN_TCP_FUTURE_MAX} B"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn vision_outbound_stream_stays_within_model_ceiling() {
    let size = std::mem::size_of::<VisionOutboundStream>();
    assert!(
        size <= VISION_STREAM_MAX,
        "VisionOutboundStream is {size} B, ceiling {VISION_STREAM_MAX} B"
    );
}

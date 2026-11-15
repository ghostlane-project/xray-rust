//! Size guards for the relay (memory model 05, section 15 T1).
//! Release sizes: run with `cargo test --release`.
use super::relay_buffer::RelayBuffer;
use super::*;
use crate::size_guard::{never, size_of_returned};
use tokio::net::TcpStream;
use xray_transport::BoxedTransportStream;

/// Model ceiling: base 1,992 B plus 56 B.
const IOS_RELAY_FUTURE_MAX: usize = 2_048;
/// Model ceiling: base 72 B plus 24 B.
const RELAY_BUFFER_MAX: usize = 96;

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn ios_relay_future_stays_within_model_ceiling() {
    let size = size_of_returned(|| {
        copy_bidirectional_with_idle_timeout_and_traffic::<TcpStream, BoxedTransportStream>(
            never(),
            never(),
            never(),
            never(),
            never(),
        )
    });
    assert!(
        size <= IOS_RELAY_FUTURE_MAX,
        "iOS relay future is {size} B, ceiling {IOS_RELAY_FUTURE_MAX} B"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn relay_buffer_stays_within_model_ceiling() {
    let size = std::mem::size_of::<RelayBuffer<'static>>();
    assert!(
        size <= RELAY_BUFFER_MAX,
        "RelayBuffer is {size} B, ceiling {RELAY_BUFFER_MAX} B"
    );
}

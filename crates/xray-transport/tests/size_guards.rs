// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
//! Size guard for the QUIC connection a Hysteria2 dial holds (memory model 05,
//! section 15 T1). Release size: run with `cargo test --release`.

/// Model ceiling: base 6,096 B plus 304 B.
const QUINN_PROTO_CONNECTION_MAX: usize = 6_400;

#[test]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
fn quinn_proto_connection_stays_within_model_ceiling() {
    let size = std::mem::size_of::<quinn_proto::Connection>();
    assert!(
        size <= QUINN_PROTO_CONNECTION_MAX,
        "quinn_proto::Connection is {size} B, ceiling {QUINN_PROTO_CONNECTION_MAX} B"
    );
}

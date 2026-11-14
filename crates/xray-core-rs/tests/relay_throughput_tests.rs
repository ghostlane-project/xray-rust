//! What the byte budget costs a relay in speed: 32 Vision flows over TLS on
//! loopback share a phone's default budget and none starves. The tests take
//! turns: the budget is the process's.
//!
//! One flow with the default budget against one without a limit is a
//! benchmark, not a test (`--ignored`): one flow never reaches `B`, so both
//! arms run the same code and the run measures the host.
//!
//! Every test prints its numbers (`--nocapture`).

// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
#[path = "relay_memory/support.rs"]
mod support;

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use support::MIB;
use xray_transport::memory_budget::DEFAULT_FLOW_FLOOR;
use xray_transport::{byte_budget, set_byte_budget, ByteBudgetSettings};

static TURN: Mutex<()> = Mutex::new(());

fn take_turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

fn nothing() {}

/// Seconds one Vision flow takes to send `bytes` and have them arrive.
fn send_seconds(far: &tokio::runtime::Runtime, socks: std::net::SocketAddr, bytes: usize) -> f64 {
    far.block_on(async {
        let started = Instant::now();
        support::vision_send_and_close(socks, bytes).await;
        started.elapsed().as_secs_f64()
    })
}

fn mbit_per_second(bytes: usize, seconds: f64) -> f64 {
    bytes as f64 * 8.0 / seconds / 1e6
}

#[test]
#[ignore = "a benchmark of the host: both arms run the same code"]
fn one_flow_moves_as_fast_with_the_default_budget_as_without_a_limit() {
    const BYTES: usize = 64 * MIB;
    let _turn = take_turn();
    let far = support::runtime(2, nothing);
    let near = support::runtime(2, nothing);
    let (server, client_config) = far.block_on(support::start_vision_server(support::Uplink::Fast));
    let mut core =
        near.block_on(async { support::vision_core(server, client_config, support::Uplink::Fast) });
    near.block_on(core.start()).unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let unlimited = ByteBudgetSettings {
        capacity: usize::MAX / 2,
        floor: DEFAULT_FLOW_FLOOR,
    };

    // One flow never reaches B, so both arms run the same code: what differs
    // between them is the host's noise (±15 % a run on a shared one). The
    // best of five interleaved runs keeps that near the 10 % allowed.
    send_seconds(&far, socks, 16 * MIB);
    let (mut budgeted, mut free) = (f64::MAX, f64::MAX);
    for _ in 0..5 {
        set_byte_budget(None);
        budgeted = budgeted.min(send_seconds(&far, socks, BYTES));
        set_byte_budget(Some(unlimited));
        free = free.min(send_seconds(&far, socks, BYTES));
    }
    set_byte_budget(None);
    near.block_on(core.stop()).unwrap();

    eprintln!(
        "one Vision flow, best of 5 × 64 MiB: {:.0} Mbit/s with B = {} B, {:.0} Mbit/s without a limit",
        mbit_per_second(BYTES, budgeted),
        byte_budget().capacity,
        mbit_per_second(BYTES, free),
    );
    assert!(
        budgeted <= free / 0.9,
        "the default budget took {budgeted:.3} s where no limit took {free:.3} s"
    );
}

#[test]
fn thirty_two_flows_share_the_default_budget_and_none_starves() {
    const FLOWS: usize = 32;
    const BYTES: usize = 4 * MIB;
    let _turn = take_turn();
    set_byte_budget(None);
    let far = support::runtime(2, nothing);
    let near = support::runtime(2, nothing);
    let (server, client_config) = far.block_on(support::start_vision_server(support::Uplink::Fast));
    let mut core =
        near.block_on(async { support::vision_core(server, client_config, support::Uplink::Fast) });
    near.block_on(core.start()).unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();

    let mut seconds = far.block_on(async {
        let started = Instant::now();
        let mut flows = tokio::task::JoinSet::new();
        for _ in 0..FLOWS {
            flows.spawn(async move {
                support::vision_send_and_close(socks, BYTES).await;
                started.elapsed().as_secs_f64()
            });
        }
        tokio::time::timeout(Duration::from_secs(120), flows.join_all())
            .await
            .expect("every flow finished")
    });
    near.block_on(core.stop()).unwrap();

    seconds.sort_by(f64::total_cmp);
    let median = seconds[FLOWS / 2];
    let slowest = seconds[FLOWS - 1];
    eprintln!(
        "{FLOWS} Vision flows × 4 MiB with B = {} B: first done in {:.3} s, median {median:.3} s, \
         last {slowest:.3} s, {:.0} Mbit/s together",
        byte_budget().capacity,
        seconds[0],
        mbit_per_second(FLOWS * BYTES, slowest),
    );
    assert!(
        slowest <= 4.0 * median,
        "the last flow took {slowest:.3} s, the median {median:.3} s"
    );
}

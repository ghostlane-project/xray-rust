// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! `TestProbeRouteFollowsProtector` (`internal/protect/route_test.go`). The
//! protector is process-wide, so the test runs in a process of its own.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use olc_net::net::{probe_route, set_protector};

/// The probe asks the host protector, not the network: the iOS pin refuses
/// every socket while no physical interface exists, and that refusal is the
/// only signal the engine has that dialing is pointless right now.
#[test]
fn the_route_probe_follows_the_protector() {
    set_protector(None);
    assert!(probe_route(), "false without a protector");

    let asked = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&asked);
    set_protector(Some(Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        false
    })));
    assert!(
        !probe_route(),
        "true while the protector refuses every socket"
    );
    // One socket of each family, as Go asks udp4 then udp6; a host without
    // IPv6 asks once.
    let n = asked.load(Ordering::SeqCst);
    assert!((1..=2).contains(&n), "the protector was asked {n} times");

    // The first socket it accepts answers: nothing more is opened.
    let asked = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&asked);
    set_protector(Some(Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        true
    })));
    assert!(probe_route(), "false while the protector accepts sockets");
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    set_protector(None);
}

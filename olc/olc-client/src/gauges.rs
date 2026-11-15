// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the client holds now, layer by layer (plan §9's per-layer gauges),
//! summed over the runs alive in the process. The host reads it beside its
//! footprint (`memory_stats` in olc-ffi, MemoryWatch on iOS): at a peak the
//! gauges say which layer moved. [`crate::sizes::budget`] holds the caps.

use std::sync::{Arc, Mutex, PoisonError, Weak};

use crate::client::Inner;
use crate::copy::{Pool, COPY_BUFFER};
use crate::sizes::FLOW_ENTRY;

static RUNS: Mutex<Vec<Weak<Inner>>> = Mutex::new(Vec::new());

/// Counts a run until its state is dropped.
pub(crate) fn register(inner: &Arc<Inner>) {
    let mut runs = RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    runs.retain(|w| w.strong_count() > 0);
    runs.push(Arc::downgrade(inner));
}

/// One reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Gauges {
    /// Runs whose state is alive (a stopped run's state goes with its tasks).
    pub runs: usize,
    /// SOCKS connections open.
    pub socks_conns: usize,
    /// Requests waiting for a session.
    pub parked: usize,
    /// Copy buffers lent and kept, in bytes.
    pub copy_bytes: usize,
    /// UDP flows through the tunnel, and dialed directly.
    pub udp_flows: usize,
    /// UDP flows dialed directly.
    pub direct_flows: usize,
    /// `FWD_UDP` replies queued, bytes.
    pub fwd_queued: usize,
    /// DNS queries in flight.
    pub dns_in_flight: usize,
    /// The data lane's inbound plaintext waiting to be read, bytes.
    pub lane_rx: usize,
    /// smux streams.
    pub smux_streams: usize,
    /// smux payload received and not read, bytes.
    pub smux_rx: usize,
    /// smux payload queued to send, bytes.
    pub smux_tx: usize,
    /// smux pool bytes allocated (in use and kept).
    pub smux_pool: usize,
}

impl Gauges {
    /// The UDP layer's bytes: the flow table and the `FWD_UDP` queues.
    #[must_use]
    pub fn udp_bytes(&self) -> usize {
        (self.udp_flows + self.direct_flows) * FLOW_ENTRY + self.fwd_queued
    }
}

/// Reads every layer now.
#[must_use]
pub fn snapshot() -> Gauges {
    let pool = Pool::global();
    let mut g = Gauges {
        copy_bytes: pool.lent_bytes() + pool.kept() * COPY_BUFFER,
        fwd_queued: crate::udp::fwd_queued_bytes(),
        ..Gauges::default()
    };
    let runs: Vec<Arc<Inner>> = {
        let mut runs = RUNS.lock().unwrap_or_else(PoisonError::into_inner);
        runs.retain(|w| w.strong_count() > 0);
        runs.iter().filter_map(Weak::upgrade).collect()
    };
    for inner in runs {
        g.runs += 1;
        g.socks_conns += inner.socks_conns.load(std::sync::atomic::Ordering::Relaxed);
        g.parked += inner.parked.load(std::sync::atomic::Ordering::Relaxed);
        g.dns_in_flight += inner
            .dns_in_flight
            .load(std::sync::atomic::Ordering::Relaxed);
        let (tunnel, direct) = inner.flows.counts();
        g.udp_flows += tunnel;
        g.direct_flows += direct;
        let (stats, lane) = {
            let sess = inner.sess.lock().unwrap_or_else(PoisonError::into_inner);
            (
                sess.session.as_ref().map(olc_smux::Session::stats),
                sess.lane.clone(),
            )
        };
        if let Some(s) = stats {
            g.smux_streams += s.streams;
            g.smux_rx += s.rx_buffered;
            g.smux_tx += s.tx_queued;
            g.smux_pool += s.pool_held;
        }
        if let Some(lane) = lane {
            g.lane_rx += lane.rx_buffered();
        }
    }
    g
}

/// Drops what the client keeps for reuse (the host's memory relief,
/// `design.md` D11): the copy buffers' pool. Returns the bytes given back.
pub fn trim() -> usize {
    Pool::global().trim()
}

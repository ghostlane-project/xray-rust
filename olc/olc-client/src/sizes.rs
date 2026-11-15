// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's memory, layer by layer (plan §9): every cap here is computed
//! from the constants that bound it in code, and the tests hold the
//! per-session and per-stream state to its `size_of`.
//!
//! The rows are the client's own (the SOCKS front, UDP, DNS, the lane, the
//! link); smux's rows are `olc_smux`'s and are added from its config.
//!
//! The SOCKS front's and the UDP reads' rows hold the process's byte budget
//! `B` ([`ghostlane_runtime::memory_budget`]): beyond its floor each read
//! takes bytes of `B`, which the copies, UDP and xray's relays share, so each
//! of those rows is at most `B` plus its floors, and all of them together
//! too: `B` counts once in the process, not once per row.

use ghostlane_runtime::ByteBudgetSettings;

use crate::copy::{COPY_BUFFER, POOL_KEEP};
use crate::dns::{MAX_IN_FLIGHT, MAX_MESSAGE};
use crate::lane::DATACHANNEL;
use crate::pipe::{FRAME_HEADER, MAX_PAYLOAD};
use crate::socks::MAX_SOCKS_CONNS;
use crate::udp::{DEFAULT_MAX_FLOWS, FWD_QUEUE_BUDGET, FWD_REPLY_QUEUE, READ_BUFFER};

/// One row of the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    /// The layer.
    pub layer: &'static str,
    /// The hard bound, in bytes, with every queue full.
    pub cap: usize,
    /// The bound at the gate's burst: 64 live connections, 64 DNS queries
    /// in flight, a handful of UDP flows.
    pub burst: usize,
    /// How the cap is computed.
    pub formula: &'static str,
}

/// Live SOCKS connections at the gate's burst (32 down, then 32 up, with
/// the 64 of S1 as the peak).
pub const BURST_CONNECTIONS: usize = 64;

/// The client's rows, on the process's byte budget as it is now.
pub fn budget() -> Vec<Row> {
    budget_with(ghostlane_runtime::byte_budget())
}

/// The client's rows on a byte budget of `bytes`.
pub fn budget_with(bytes: ByteBudgetSettings) -> Vec<Row> {
    let smux = olc_smux::Config::client_data(DATACHANNEL.max_payload_size, false);
    let inbound = olc_muxconn::conn::inbound_capacity(DATACHANNEL.max_record_plaintext());
    let copy_floor = bytes.floor.min(COPY_BUFFER);
    let socks = |moving: usize| {
        (moving * 2 * COPY_BUFFER).min(bytes.capacity.saturating_add(moving * 2 * copy_floor))
            + POOL_KEEP * COPY_BUFFER
    };
    let read_floor = bytes.floor.min(READ_BUFFER);
    let reads = |draining: usize| {
        (draining * READ_BUFFER).min(bytes.capacity.saturating_add(draining * read_floor))
    };
    vec![
        Row {
            layer: "SOCKS front copy buffers (only while bytes move)",
            cap: socks(MAX_SOCKS_CONNS),
            burst: socks(BURST_CONNECTIONS),
            formula: "2 directions x one read per connection moving bytes: COPY_BUFFER (16 KiB) \
                      when the byte budget B gives the bytes beyond the floor, else less, down \
                      to the floor (4 KiB): min(N x 2 x 16 KiB, B + N x 2 x floor), \
                      + POOL_KEEP (8) kept; an idle connection holds none",
        },
        Row {
            layer: "UDP flow table",
            cap: DEFAULT_MAX_FLOWS * 2 * FLOW_ENTRY,
            burst: 64 * FLOW_ENTRY,
            formula: "DEFAULT_MAX_FLOWS (1024) x 2 tables x FLOW_ENTRY",
        },
        Row {
            layer: "UDP read buffers (only while a socket has datagrams waiting)",
            cap: reads(MAX_SOCKS_CONNS),
            burst: reads(4),
            formula: "one READ_BUFFER (16 KiB) per association being drained when B gives \
                      the bytes beyond the floor, else the floor: min(N x 16 KiB, B + N x floor)",
        },
        Row {
            layer: "FWD_UDP reply queues",
            cap: FWD_QUEUE_BUDGET,
            burst: FWD_QUEUE_BUDGET.min(4 * FWD_REPLY_QUEUE * crate::udp::FWD_CLIENT_BUFFER),
            formula: "FWD_QUEUE_BUDGET (512 KiB) for every connection's queued and \
                      in-flight frames (queues of FWD_REPLY_QUEUE (32) x <= 1500); beyond \
                      each connection's floor the bytes are B's too",
        },
        Row {
            layer: "DNS queries in flight",
            cap: MAX_IN_FLIGHT * (2 + MAX_MESSAGE) * 2,
            burst: MAX_IN_FLIGHT * 2 * 512,
            formula: "MAX_IN_FLIGHT (64) x (query + response, each <= 2 + 65535)",
        },
        Row {
            layer: "data lane inbound queue",
            cap: inbound,
            burst: inbound / 4,
            formula: "olc_muxconn inbound_capacity: min(128 records x max record, 1 MiB)",
        },
        Row {
            layer: "data lane outbound batches",
            cap: 2 * smux.max_frame_size.max(DATACHANNEL.max_payload_size),
            burst: 2 * smux.max_frame_size.max(DATACHANNEL.max_payload_size),
            formula: "one batch filling + one sending, each max(MaxPayload - 44, max_frame)",
        },
        Row {
            layer: "interop-pipe link buffers",
            cap: 2 * (FRAME_HEADER + MAX_PAYLOAD),
            burst: 2 * (FRAME_HEADER + MAX_PAYLOAD),
            formula: "one read and one write buffer of FRAME_HEADER + MAX_PAYLOAD (64 KiB)",
        },
        Row {
            layer: "smux session receive",
            cap: smux.max_receive_buffer,
            burst: smux.max_receive_buffer / 2,
            formula: "olc_smux client_data MaxReceiveBuffer",
        },
    ]
}

/// What one flow costs in the table: the entry, its key's host and the
/// index's copy of the key (a name is at most 255 bytes; an address 39).
pub const FLOW_ENTRY: usize = 256;

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn per_session_and_per_stream_state_stays_small() {
        // The session every request waits for: handles, not buffers.
        assert!(
            size_of::<crate::client::Sess>() <= 128,
            "{}",
            size_of::<crate::client::Sess>()
        );
        // Per CONNECT: the job and the stream handle.
        assert!(
            size_of::<crate::socks::Job>() <= 64,
            "{}",
            size_of::<crate::socks::Job>()
        );
        assert!(
            size_of::<olc_smux::Stream>() <= 24,
            "{}",
            size_of::<olc_smux::Stream>()
        );
        // Per UDP flow.
        assert!(
            size_of::<crate::udp::Flow>() <= 128,
            "{}",
            size_of::<crate::udp::Flow>()
        );
        assert!(
            size_of::<crate::udp::Reply>() <= 64,
            "{}",
            size_of::<crate::udp::Reply>()
        );
        assert!(
            size_of::<crate::udp::DirectFlow>() <= 48,
            "{}",
            size_of::<crate::udp::DirectFlow>()
        );
        let entry = size_of::<crate::udp::Flow>() + size_of::<crate::udp::FlowKey>() + 39 + 16;
        assert!(
            entry <= FLOW_ENTRY,
            "a flow with an address host costs {entry}"
        );
    }

    fn phone() -> ByteBudgetSettings {
        ByteBudgetSettings::for_class(ghostlane_runtime::MemoryClass::Constrained)
    }

    #[test]
    fn the_burst_fits_the_engine_budget() {
        let rows = budget_with(phone());
        let burst: usize = rows.iter().map(|r| r.burst).sum();
        // Plan §9: the engine at or below 12 MiB, the SOCKS front 3 MiB,
        // UDP 0.5 MiB, the smux receive 4 MiB, the muxconn queue 1 MiB.
        assert!(burst <= 12 << 20, "the client's rows at the burst: {burst}");
        let row = |name: &str| rows.iter().find(|r| r.layer.starts_with(name)).unwrap();
        assert!(row("SOCKS front").burst <= 3 << 20);
        assert!(row("UDP flow table").cap <= 1 << 20);
        assert!(row("data lane inbound").cap <= 1 << 20);
        assert!(row("smux session receive").cap <= 4 << 20);
        for r in &rows {
            assert!(r.burst <= r.cap, "{}", r.layer);
        }
    }

    #[test]
    fn two_hundred_fifty_six_connections_fit_while_the_burst_moves() {
        // Plan §9 at 256 connections: the idle ones hold no copy buffer, so
        // the SOCKS front is the burst's, whatever the connection count.
        let held = |moving: usize| (moving * 2 + POOL_KEEP) * COPY_BUFFER;
        assert!(held(BURST_CONNECTIONS / 2) <= 3 << 20);
        assert!(held(0) <= 128 << 10, "256 idle connections");
        let rows = budget_with(phone());
        let fwd = rows
            .iter()
            .find(|r| r.layer.starts_with("FWD_UDP"))
            .unwrap();
        assert!(
            fwd.cap <= 512 << 10,
            "UDP 0.5 MiB, whatever the connection count"
        );
    }

    #[test]
    fn all_five_hundred_twelve_moving_hold_the_byte_budget_and_their_floors() {
        // Without the budget: (512 x 2 + 8) x 16 KiB = 16.1 MiB. With the
        // phone's (B 3,000,000 bytes, floors of 4 KiB): B + 4 MiB + 128 KiB,
        // and B is the process's, not the front's alone.
        let b = phone();
        let rows = budget_with(b);
        let row = |name: &str| rows.iter().find(|r| r.layer.starts_with(name)).unwrap();
        assert_eq!(
            row("SOCKS front").cap,
            b.capacity + MAX_SOCKS_CONNS * 2 * b.floor + POOL_KEEP * COPY_BUFFER
        );
        assert!(row("SOCKS front").cap < (MAX_SOCKS_CONNS * 2 + POOL_KEEP) * COPY_BUFFER / 2);
        assert_eq!(
            row("UDP read buffers").cap,
            b.capacity + MAX_SOCKS_CONNS * b.floor
        );
        // A budget larger than every read: the reads' own sizes bound them.
        let roomy = budget_with(ByteBudgetSettings {
            capacity: usize::MAX,
            floor: b.floor,
        });
        let row = |name: &str| roomy.iter().find(|r| r.layer.starts_with(name)).unwrap();
        assert_eq!(
            row("SOCKS front").cap,
            (MAX_SOCKS_CONNS * 2 + POOL_KEEP) * COPY_BUFFER
        );
    }
}

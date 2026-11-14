// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's memory, layer by layer (plan §9): every cap here is computed
//! from the constants that bound it in code, and the tests hold the
//! per-session and per-stream state to its `size_of`.
//!
//! The rows are the client's own (the SOCKS front, UDP, DNS, the lane, the
//! link); smux's rows are `olc_smux`'s and are added from its config.

use crate::copy::COPY_BUFFER;
use crate::dns::{MAX_IN_FLIGHT, MAX_MESSAGE};
use crate::lane::DATACHANNEL;
use crate::pipe::{FRAME_HEADER, MAX_PAYLOAD};
use crate::socks::MAX_SOCKS_CONNS;
use crate::udp::{DEFAULT_MAX_FLOWS, FWD_REPLY_QUEUE, FWD_WRITE_BATCH, READ_BUFFER};

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

/// The client's rows.
pub fn budget() -> Vec<Row> {
    let smux = olc_smux::Config::client_data(DATACHANNEL.max_payload_size, false);
    let inbound = olc_muxconn::conn::inbound_capacity(DATACHANNEL.max_record_plaintext());
    vec![
        Row {
            layer: "SOCKS front copy buffers",
            cap: MAX_SOCKS_CONNS * 2 * COPY_BUFFER,
            burst: BURST_CONNECTIONS * 2 * COPY_BUFFER,
            formula: "MAX_SOCKS_CONNS (512) x 2 directions x COPY_BUFFER (16 KiB)",
        },
        Row {
            layer: "UDP flow table",
            cap: DEFAULT_MAX_FLOWS * 2 * FLOW_ENTRY,
            burst: 64 * FLOW_ENTRY,
            formula: "DEFAULT_MAX_FLOWS (1024) x 2 tables x FLOW_ENTRY",
        },
        Row {
            layer: "UDP read buffers (only while a socket has datagrams waiting)",
            cap: MAX_SOCKS_CONNS * READ_BUFFER,
            burst: 4 * READ_BUFFER,
            formula: "one READ_BUFFER (16 KiB) per association being drained",
        },
        Row {
            layer: "FWD_UDP reply queues",
            cap: MAX_SOCKS_CONNS * (FWD_REPLY_QUEUE * crate::udp::FWD_CLIENT_BUFFER + FWD_WRITE_BATCH),
            burst: 4 * (FWD_REPLY_QUEUE * crate::udp::FWD_CLIENT_BUFFER + FWD_WRITE_BATCH),
            formula: "per connection FWD_REPLY_QUEUE (32) x 1500 + one FWD_WRITE_BATCH (16 KiB)",
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
        assert!(size_of::<crate::client::Sess>() <= 128, "{}", size_of::<crate::client::Sess>());
        // Per CONNECT: the job and the stream handle.
        assert!(size_of::<crate::socks::Job>() <= 64, "{}", size_of::<crate::socks::Job>());
        assert!(size_of::<olc_smux::Stream>() <= 24, "{}", size_of::<olc_smux::Stream>());
        // Per UDP flow.
        assert!(size_of::<crate::udp::Flow>() <= 128, "{}", size_of::<crate::udp::Flow>());
        assert!(size_of::<crate::udp::Reply>() <= 64, "{}", size_of::<crate::udp::Reply>());
        assert!(size_of::<crate::udp::DirectFlow>() <= 48, "{}", size_of::<crate::udp::DirectFlow>());
        let entry = size_of::<crate::udp::Flow>() + size_of::<crate::udp::FlowKey>() + 39 + 16;
        assert!(entry <= FLOW_ENTRY, "a flow with an address host costs {entry}");
    }

    #[test]
    fn the_burst_fits_the_engine_budget() {
        let rows = budget();
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
}

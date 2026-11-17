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
    let mut rows = vec![
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
    ];
    rows.push(Row {
        layer: "ICE over TCP connections (MTS Link's default; none over UDP)",
        cap: olc_rtc::icetcp::MAX_HELD + olc_rtc::media::SEND_BACKLOG_MAX,
        // One connection, its socket taking what it is given.
        burst: olc_rtc::icetcp::READ_BUF,
        formula: "per peer connection: MAX_CONNS (4) x (READ_BUF (2 + 8192, held while \
                  connected) + OUT_PENDING_MAX (2 frames, only while the socket is stalled)) \
                  + SEND_BACKLOG_MAX: the video line's RTP written and not yet taken by a \
                  slow socket, SEND_BACKLOG_PACKETS (256) x (SEND_PACKET_MAX (1200) + \
                  SEND_PACKET_SLOT (416)); a batch beyond it is refused",
    });
    rows.extend(mtslink_rows());
    rows.extend(vkcalls_rows());
    #[cfg(feature = "boring")]
    rows.extend(turns_rows());
    rows
}

/// MTS Link's rows: what its session holds per join ([`olc_mtslink::session`]).
fn mtslink_rows() -> [Row; 6] {
    use olc_mtslink::auth::CREDENTIALS_HELD;
    use olc_mtslink::readers::MAX_READERS;
    use olc_mtslink::session::{JOIN_HELD, REFRESH_HELD, RESEND_HELD};
    use olc_mtslink::signal::TAKE_BACK_HELD;
    use olc_vp8channel::rtp_reader::{MAX_ASSEMBLED_FRAME, READER_HELD, REORDER_IDLE};
    [
        Row {
            layer: "MTS Link published stream's resend cache",
            cap: RESEND_HELD,
            burst: RESEND_HELD,
            formula: "RESEND_PACKETS (257: the far reader's reorder window and one) x \
                      RTP_OUTBOUND_MTU (1200), each kept RESEND_AGE (300 ms) at most",
        },
        Row {
            layer: "MTS Link remote video readers",
            cap: MAX_READERS * READER_HELD,
            // One publisher (the server), no gap in its video: a frame at
            // the bound being assembled, and what a reader keeps anyway.
            burst: REORDER_IDLE + MAX_ASSEMBLED_FRAME,
            formula: "MAX_READERS (9: one per receive slot, the one fed longest ago \
                      replaced) x olc_vp8channel's READER_HELD, in capacities: \
                      (REORDER_WINDOW + 1) (257) packet buffers of MAX_RETAINED_PAYLOAD \
                      (2 KiB each, whatever the packet; a longer packet is dropped before \
                      the reader) behind a gap, the two lists they are in (16 KiB), and \
                      the one frame buffer, MAX_ASSEMBLED_FRAME (240 KiB) at most. Between \
                      frames with no gap a reader keeps READER_IDLE (80 KiB)",
        },
        Row {
            layer: "MTS Link join (only while a join runs)",
            cap: 2 * olc_mtslink::REPLY_LIMIT + JOIN_HELD,
            burst: 0,
            formula: "the SFU's answer, REPLY_LIMIT (1 MiB) read and once more as text, \
                      + JOIN_HELD: the offer (8 KiB), the join's copy of the credentials \
                      (CREDENTIALS_HELD), the join URL twice more (4 x MAX_JOIN_URL with \
                      the values a refusal is cleared of) and the cookies' values and \
                      ids once more. A rejoin is one join at a time, after the old \
                      generation is gone and the join before it is over; the provider's \
                      replies before it are read one at a time, each REPLY_LIMIT at most",
        },
        Row {
            layer: "MTS Link credentials (kept for the session)",
            cap: CREDENTIALS_HELD,
            // The service's: a join URL of about 600 bytes, three cookies.
            burst: 2 << 10,
            formula: "MAX_JOIN_URL (32 KiB; the provider's worst is under 26 KiB) + \
                      MAX_COOKIES (8 KiB) + MAX_GATEWAY (2 KiB) + 3 x MAX_ID (64); \
                      credentials past a bound make no session, direct ones included",
        },
        Row {
            layer: "MTS Link take-back (only after a join that failed, 5 s at most)",
            cap: 2 * TAKE_BACK_HELD,
            burst: 0,
            formula: "2 x TAKE_BACK_HELD: the call's reply, REPLY_LIMIT (1 MiB), + 3 x \
                      (MAX_COOKIES + MAX_GATEWAY + MAX_ID) for the task's copies, the \
                      request and what its failure is cleared of. A failed join waits \
                      for its own; the one of a dropped or closed join runs alone for \
                      LEAVE_WAIT (5 s) at most, and the next join starts after it or \
                      after that wait, so two is the most at once",
        },
        Row {
            layer: "MTS Link rejoin (what the provider is asked again with)",
            cap: REFRESH_HELD,
            burst: REFRESH_HELD,
            formula: "MAX_ROOM_LINK (2 KiB) + MAX_NAME (256) + 64, kept for the session; \
                      the supervisor itself holds a flag and two counters",
        },
    ]
}

/// VK Calls' rows (task M7.10): what a session of `olc-vkcalls` holds
/// beside its peer connection. The caps are the crate's bounds; the bursts
/// are counted with a live call's offer
/// ([`olc_vkcalls::engine::LIVE_OFFER`]) and one camera forwarded.
fn vkcalls_rows() -> [Row; 8] {
    use olc_rtc::turn::{SEND_BUF, STREAM_QUEUE, STREAM_READ};
    use olc_vkcalls::auth::REPLY_LIMIT;
    use olc_vkcalls::engine::{
        CONTROL_HELD, KEPT_HELD, LIVE_OFFER, OFFER_TEXTS, PEER_HELD, READERS_MAX, RESEND_HELD,
    };
    use olc_vkcalls::recruit::MAX_RECRUITS;
    use olc_vkcalls::signaling::{FRAME_MAX, NOTIFICATION_BYTES, READ_PEAK};
    use olc_vp8channel::rtp_reader::READER_HELD;
    [
        Row {
            layer: "VK Calls signalling socket",
            cap: READ_PEAK + NOTIFICATION_BYTES + 2 * FRAME_MAX,
            // One offer being read, one waiting, one answer being written.
            burst: 4 * LIVE_OFFER + LIVE_OFFER + 2 * LIVE_OFFER,
            formula: "READ_PEAK (4 x READ_LIMIT (512 KiB), while a frame is decoded) + \
                      NOTIFICATION_BYTES (1 MiB waiting, 16 at most) + 2 x FRAME_MAX \
                      (256 KiB: a command frame and its copy while it is written)",
        },
        Row {
            layer: "VK Calls offer being answered (only while it is)",
            cap: OFFER_TEXTS,
            burst: 4 * LIVE_OFFER,
            formula: "4 x READ_LIMIT: the offer, its view, the text the stack is given \
                      and the answer; only the answer outlives the call, until it is sent",
        },
        Row {
            layer: "VK Calls track readers",
            cap: READERS_MAX * READER_HELD,
            // One camera forwarded, its reader full.
            burst: READER_HELD,
            formula: "READERS_MAX (9, one per SSRC, the least recently fed replaced) x \
                      olc_vp8channel's READER_HELD, in capacities: 257 packet buffers of \
                      MAX_RETAINED_PAYLOAD (2 KiB each; a longer packet is dropped before \
                      the reader) behind a gap, the two lists they are in (16 KiB), and \
                      the one frame buffer, MAX_ASSEMBLED_FRAME (240 KiB) at most; a frame \
                      buffer over FRAME_KEPT (64 KiB) is released once its frame was read",
        },
        Row {
            layer: "VK Calls resend cache",
            cap: RESEND_HELD,
            burst: RESEND_HELD,
            formula: "RESEND_PACKETS (257) x 1200 bytes, each kept RESEND_AGE (300 ms)",
        },
        Row {
            layer: "VK Calls control route",
            cap: CONTROL_HELD,
            burst: 4 << 10,
            formula: "(REGISTRY_MAX (256) + PARTICIPANTS_MAX (256)) x (an entry of 64 bytes \
                      + its blob of the layout frame, under 256)",
        },
        Row {
            layer: "VK Calls guests and their credentials (only during a join)",
            cap: MAX_RECRUITS * READ_PEAK + REPLY_LIMIT,
            // None once the room is joined.
            burst: 0,
            formula: "MAX_RECRUITS (2) sockets x READ_PEAK while a fresh room is flipped + \
                      one reply of the provider's chain at REPLY_LIMIT (256 KiB)",
        },
        Row {
            layer: "VK Calls peer connection (the service's TURN relays, SCTP, events)",
            cap: PEER_HELD,
            // Two relays over TCP with their queues full, nothing half read.
            burst: 2 * (STREAM_QUEUE * SEND_BUF + STREAM_READ),
            formula: "MAX_ALLOCATIONS (6) relays x (STREAM_QUEUE (16) x SEND_BUF (2112) + \
                      STREAM_READ (4 KiB) + a message not whole yet (65,556)) + \
                      STREAM_INBOUND (8) x STREAM_READ waiting for the driver + \
                      SCTP_BUFFERED (64 KiB unacknowledged on the service channels) + \
                      INBOUND_BYTES (256 KiB: one data message at its largest) + \
                      EVENT_QUEUE (64) events; str0m's own state is not in it",
        },
        Row {
            layer: "VK Calls rejoin (what the session keeps to join again with)",
            cap: KEPT_HELD,
            // An endpoint of some 300 bytes, two ICE servers, a join link.
            burst: 2 << 10,
            formula: "the endpoint (TOKEN_MAX, 4 KiB) + the ICE servers' text \
                      (ICE_JSON_MAX, 102 KiB: 34 texts of 512 bytes, each byte written \
                      as six at worst) + the link, an account token and a test's base \
                      (MAX_ROOM_LINK, 2 KiB each) + MAX_NAME (256) + the handshake's \
                      headers (512); credentials or a link past a bound make no session",
        },
    ]
}

/// TURN over TLS's rows (the `boring` build only): what a `turns:`
/// connection holds beside the plain TCP relay's own queue (its bound is
/// `olc_rtc::turn`'s), and the sessions kept for resumption.
#[cfg(feature = "boring")]
fn turns_rows() -> [Row; 2] {
    use olc_rtc::turn::MAX_ALLOCATIONS;
    use olc_rtc::turns::{TICKET_HEAP_MAX, TICKET_SERVERS, TLS_CONNECTION_MAX};
    [
        Row {
            layer: "TURN over TLS connections (beside the TCP relay's queue)",
            cap: MAX_ALLOCATIONS * TLS_CONNECTION_MAX,
            // SaluteJazz lists two TURN hosts, each over TLS once.
            burst: 2 * TLS_CONNECTION_MAX,
            formula: "MAX_ALLOCATIONS (6) x TLS_CONNECTION_MAX: BoringSSL's C heap per \
                      connection (measured, TLS_BORINGSSL_MAX) + the task's buffers + \
                      TLS_MAX_CERT_LIST while the handshake runs",
        },
        Row {
            layer: "TURN over TLS kept sessions",
            cap: TICKET_SERVERS * TICKET_HEAP_MAX,
            burst: 2 * TICKET_HEAP_MAX,
            formula: "TICKET_SERVERS (6) x TICKET_HEAP_MAX: one session per server, \
                      each at most TICKET_MAX_DER serialised, its heap measured",
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

    /// TURN over TLS's rows are the module's constants multiplied, and the
    /// whole of them is a small part of the engine's budget.
    #[cfg(feature = "boring")]
    #[test]
    fn the_turns_rows_follow_the_constants() {
        use olc_rtc::turns::{TICKET_HEAP_MAX, TICKET_SERVERS, TLS_CONNECTION_MAX};
        let rows = budget();
        let row = |name: &str| rows.iter().find(|r| r.layer.starts_with(name)).unwrap();
        let conns = row("TURN over TLS connections");
        assert_eq!(conns.cap, 6 * TLS_CONNECTION_MAX);
        assert!(conns.cap <= 1 << 20, "{}", conns.cap);
        let kept = row("TURN over TLS kept");
        assert_eq!(kept.cap, TICKET_SERVERS * TICKET_HEAP_MAX);
        assert!(kept.cap <= 512 << 10, "{}", kept.cap);
        // One kept session is a heap-measured number; the stored entry
        // itself (key, pointer) is small.
        assert!(std::mem::size_of::<(String, usize)>() <= 64);
    }

    /// MTS Link's rows are its session's constants, and a small part of
    /// the engine's budget.
    #[test]
    fn the_mtslink_rows_follow_the_constants() {
        use olc_mtslink::readers::{MAX_READERS, READERS_HELD, READER_HELD};
        use olc_mtslink::session::{RESEND_HELD, RESEND_PACKETS};
        use olc_vp8channel::rtp_reader as reader;
        let rows = budget();
        let row = |name: &str| rows.iter().find(|r| r.layer.starts_with(name)).unwrap();
        let resends = row("MTS Link published stream's resend cache");
        assert_eq!(resends.cap, RESEND_PACKETS * 1200);
        assert_eq!(resends.cap, RESEND_HELD);
        assert!(resends.cap <= 320 << 10, "{}", resends.cap);
        let readers = row("MTS Link remote video readers");
        // The reader's own bound, which is on what its buffers can hold
        // (capacities; olc-vp8channel's tests hold a reader to it).
        assert_eq!(readers.cap, MAX_READERS * reader::READER_HELD);
        // The session counts with the same bound (W3-core.md: the
        // carrier's own sum, two frame buffers in lengths, is gone).
        assert_eq!(READER_HELD, reader::READER_HELD);
        assert_eq!(readers.cap, READERS_HELD);
        assert_eq!(MAX_READERS, 9);
        const { assert!(READER_HELD <= 1 << 20) };
        assert!(readers.cap <= 7 << 20, "{}", readers.cap);
        assert_eq!(
            readers.burst,
            reader::REORDER_IDLE + reader::MAX_ASSEMBLED_FRAME
        );
        assert!(readers.burst <= 288 << 10, "{}", readers.burst);
        let join = row("MTS Link join");
        assert_eq!(
            join.cap,
            2 * olc_mtslink::REPLY_LIMIT + olc_mtslink::session::JOIN_HELD
        );
        const { assert!(olc_mtslink::session::JOIN_HELD <= 192 << 10) };
        assert_eq!(join.burst, 0, "no join runs under the burst");
        let rejoin = row("MTS Link rejoin");
        assert_eq!(
            rejoin.cap,
            olc_mtslink::session::MAX_ROOM_LINK + olc_mtslink::session::MAX_NAME + 64
        );
        assert!(rejoin.cap <= 4 << 10, "{}", rejoin.cap);
        assert_eq!(rejoin.burst, rejoin.cap, "kept while the session lives");
        // What the provider issued, kept for the session's life, and the
        // take-back of a join that failed or was given up.
        let kept = row("MTS Link credentials");
        assert_eq!(kept.cap, olc_mtslink::auth::CREDENTIALS_HELD);
        assert_eq!(
            kept.cap,
            olc_mtslink::auth::MAX_JOIN_URL
                + olc_mtslink::auth::MAX_COOKIES
                + olc_mtslink::auth::MAX_GATEWAY
                + 3 * olc_mtslink::auth::MAX_ID
        );
        assert!(kept.cap <= 43 << 10, "{}", kept.cap);
        assert!(kept.burst <= kept.cap);
        let leave = row("MTS Link take-back");
        assert_eq!(leave.cap, 2 * olc_mtslink::signal::TAKE_BACK_HELD);
        assert!(leave.cap <= (2 << 20) + (64 << 10), "{}", leave.cap);
        assert_eq!(leave.burst, 0, "no join fails under the burst");
    }

    /// ICE over TCP's row is the modules' constants multiplied, and small:
    /// the connections' buffers, and the send line's packets a slow socket
    /// has not taken (str0m's queue, bounded by the line).
    #[test]
    fn the_ice_tcp_row_follows_the_constants() {
        use olc_rtc::icetcp::{MAX_CONNS, OUT_PENDING_MAX, READ_BUF};
        use olc_rtc::media::{SEND_BACKLOG_PACKETS, SEND_PACKET_MAX, SEND_PACKET_SLOT};
        let rows = budget();
        let row = rows
            .iter()
            .find(|r| r.layer.starts_with("ICE over TCP"))
            .unwrap();
        let conns = MAX_CONNS * (READ_BUF + OUT_PENDING_MAX);
        let line = SEND_BACKLOG_PACKETS * (SEND_PACKET_MAX + SEND_PACKET_SLOT);
        assert_eq!(row.cap, conns + line);
        assert!(conns <= 100 << 10, "{conns}");
        assert_eq!((SEND_BACKLOG_PACKETS, SEND_PACKET_MAX), (256, 1200));
        assert!(row.cap <= 512 << 10, "{}", row.cap);
        assert_eq!(row.burst, READ_BUF);
    }

    /// VK Calls' rows are the crate's constants multiplied (task M7.10):
    /// the readers stay under the engine's budget with every one of them
    /// full (plan K10: 36 declared tracks would not), and a call as it
    /// runs holds about two megabytes beside its peer connection.
    #[test]
    fn the_vk_calls_rows_follow_the_constants() {
        use olc_vkcalls::engine::{READERS_MAX, READER_HELD, RESEND_HELD};
        use olc_vkcalls::signaling::{FRAME_MAX, NOTIFICATION_BYTES, READ_LIMIT};
        use olc_vp8channel::rtp_reader as reader;
        let rows = budget();
        let row = |name: &str| {
            rows.iter()
                .find(|r| r.layer.starts_with(name))
                .unwrap_or_else(|| panic!("no row {name}"))
        };
        let vk: Vec<&Row> = rows
            .iter()
            .filter(|r| r.layer.starts_with("VK Calls"))
            .collect();
        assert_eq!(vk.len(), 8);

        let readers = row("VK Calls track readers");
        assert_eq!(READERS_MAX, 9);
        // The row is the reader's own bound, on capacities (one frame
        // buffer, the packet buffers at their fixed size and the two lists
        // they are in), and the engine counts with the same one, as MTS
        // Link's session does.
        assert_eq!(READER_HELD, reader::READER_HELD);
        assert_eq!(READER_HELD, olc_mtslink::readers::READER_HELD);
        assert_eq!(readers.cap, 9 * reader::READER_HELD);
        assert!(readers.cap <= 7 << 20, "{}", readers.cap);
        assert_eq!(readers.burst, reader::READER_HELD);

        let socket = row("VK Calls signalling socket");
        assert_eq!(
            socket.cap,
            4 * READ_LIMIT + NOTIFICATION_BYTES + 2 * FRAME_MAX
        );
        // 1 MiB of notifications wait at most (it was 2): 3.5 MiB.
        assert_eq!(NOTIFICATION_BYTES, 1 << 20);
        assert_eq!(socket.cap, (3 << 20) + (512 << 10));
        assert_eq!(row("VK Calls offer being answered").cap, 4 * READ_LIMIT);
        assert_eq!(row("VK Calls resend cache").cap, RESEND_HELD);
        assert_eq!(RESEND_HELD, 257 * 1200);
        assert!(row("VK Calls control route").cap <= 256 << 10);
        assert_eq!(row("VK Calls guests").cap, 2 * 4 * READ_LIMIT + (256 << 10));

        // Every bound of the session together, the guests' row apart (it
        // is a join's): 14,441,320 bytes (13.77 MiB) in a call with every
        // queue full at once, above the engine's 12 MiB. Not claimed to
        // fit: what is held to 12 MiB is the burst. The readers are 6.77
        // MiB of it; READERS_MAX at 6 would bring the call to 11.5 MiB
        // (T3 says how many cameras a call forwards), the offer's 4 x
        // READ_LIMIT (2 MiB, while one is answered) is the next largest.
        let cap: usize = vk.iter().map(|r| r.cap).sum();
        assert!(cap <= 20 << 20, "{cap}");
        let in_a_call = cap - row("VK Calls guests").cap;
        assert_eq!(in_a_call, 14_441_320);
        assert_eq!(in_a_call - 3 * reader::READER_HELD, 12_075_688);
        let burst: usize = vk.iter().map(|r| r.burst).sum();
        assert!(burst <= 9 << 18, "{burst}");

        // The peer connection's own queues (memory 5 of the wave-2 review:
        // they had no row): the service's TURN relays, SCTP's unacknowledged
        // bytes and the events that wait for the session.
        use olc_rtc::turn::{MAX_ALLOCATIONS, SEND_BUF, STREAM_INBOUND, STREAM_QUEUE, STREAM_READ};
        use olc_vkcalls::engine::{KEPT_HELD, PEER_HELD, SCTP_BUFFERED};
        let peer = row("VK Calls peer connection");
        assert_eq!(peer.cap, PEER_HELD);
        assert_eq!(
            peer.cap,
            MAX_ALLOCATIONS * (STREAM_QUEUE * SEND_BUF + STREAM_READ + 65_556)
                + STREAM_INBOUND * STREAM_READ
                + SCTP_BUFFERED
                + olc_rtc::peer::INBOUND_BYTES
                + olc_rtc::peer::EVENT_QUEUE * 128
        );
        assert_eq!((MAX_ALLOCATIONS, SCTP_BUFFERED), (6, 64 << 10));
        assert!(peer.cap <= 1 << 20, "{}", peer.cap);
        assert!(std::mem::size_of::<olc_rtc::peer::PeerEvent>() <= 128);
        assert!(peer.burst <= 96 << 10, "{}", peer.burst);
        // What the session keeps for its life to join again with.
        let kept = row("VK Calls rejoin");
        assert_eq!(kept.cap, KEPT_HELD);
        assert_eq!(
            kept.cap,
            olc_vkcalls::auth::TOKEN_MAX
                + olc_vkcalls::auth::ICE_JSON_MAX
                + 3 * olc_vkcalls::engine::MAX_ROOM_LINK
                + olc_vkcalls::engine::MAX_NAME
                + 512
        );
        assert!(kept.cap <= 114 << 10, "{}", kept.cap);
        assert!(kept.burst <= 4 << 10, "{}", kept.burst);

        // The hard bound of a call with every queue full at once is still
        // above the engine's 12 MiB, so it is not asserted to fit: the
        // readers' row apart (olc-vp8channel's bound on a reader), a call's
        // rows are 7.01 MiB, and nine full readers are more than 5 MiB by
        // any count of them. What is held to 12 MiB is the burst.
        let beside_readers = in_a_call - readers.cap;
        assert_eq!(
            beside_readers,
            socket.cap
                + 4 * READ_LIMIT
                + RESEND_HELD
                + row("VK Calls control route").cap
                + PEER_HELD
                + KEPT_HELD
        );
        assert!(beside_readers <= (7 << 20) + (16 << 10), "{beside_readers}");
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

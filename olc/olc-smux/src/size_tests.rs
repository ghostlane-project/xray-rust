// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The fixed memory of a session and of a stream, asserted.

use std::mem::size_of;

use crate::arena::{ByteQueue, FrameQueue};
use crate::state::{Slot, State};
use crate::{Driver, Session, Stream};

#[test]
fn handle_and_state_sizes() {
    // A session handle is one pointer; a stream handle a pointer and two
    // ids (u32 each), on 64-bit and 32-bit targets alike (armeabi-v7a).
    let ptr = size_of::<usize>();
    assert_eq!(size_of::<Session>(), ptr);
    assert_eq!(size_of::<Stream>(), ptr + 8);
    // A queue is four indices and a length; it owns no memory while empty.
    assert_eq!(size_of::<ByteQueue>(), 16);
    assert_eq!(size_of::<FrameQueue>(), 20);
    // Everything a stream keeps beyond its buffered bytes.
    assert!(
        size_of::<Slot>() <= 128,
        "Slot is {} bytes",
        size_of::<Slot>()
    );
    assert!(
        size_of::<Option<Slot>>() <= 136,
        "Option<Slot> is {} bytes",
        size_of::<Option<Slot>>()
    );
    // The session's fixed part, before its read and write buffers.
    assert!(
        size_of::<State>() <= 640,
        "State is {} bytes",
        size_of::<State>()
    );
    assert!(
        size_of::<Driver<tokio::net::TcpStream>>() <= 512,
        "Driver<TcpStream> is {} bytes",
        size_of::<Driver<tokio::net::TcpStream>>()
    );
    eprintln!(
        "SIZES Session={} Stream={} Slot={} Option<Slot>={} State={} Driver<TcpStream>={}",
        size_of::<Session>(),
        size_of::<Stream>(),
        size_of::<Slot>(),
        size_of::<Option<Slot>>(),
        size_of::<State>(),
        size_of::<Driver<tokio::net::TcpStream>>()
    );
}

// smux/session.go:181-190: the last ids before GoAway.
#[tokio::test]
async fn stream_ids_run_out_with_go_away() {
    let (a, b) = tokio::io::duplex(1 << 16);
    let (client, cd) = Session::client(a, crate::Config::go_default()).unwrap();
    let (server, sd) = Session::server(b, crate::Config::go_default()).unwrap();
    tokio::spawn(cd);
    tokio::spawn(sd);
    client.set_next_stream_id(u32::MAX - 4);
    let s = client.open_stream().await.unwrap();
    assert_eq!(s.id(), u32::MAX - 2);
    let s2 = client.open_stream().await.unwrap();
    assert_eq!(s2.id(), u32::MAX);
    assert_eq!(
        client.open_stream().await.unwrap_err(),
        crate::Error::GoAway
    );
    assert_eq!(
        client.open_stream().await.unwrap_err(),
        crate::Error::GoAway
    );
    server.set_next_stream_id(u32::MAX - 3);
    assert_eq!(server.open_stream().await.unwrap().id(), u32::MAX - 1);
    assert_eq!(
        server.open_stream().await.unwrap_err(),
        crate::Error::GoAway
    );
}

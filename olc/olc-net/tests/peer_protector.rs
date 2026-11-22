// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The protector that is told the peer: a TCP dial names the address it
//! dials, and a protector of the old form is handed the same sockets as
//! before. The protector is process-wide, so this is one test in a process of
//! its own.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use olc_net::net::{dial_tcp, set_peer_protector, set_protector, udp_socket};

const REFUSED: &str = "protect: socket protector rejected the socket";

#[tokio::test]
async fn a_dial_tells_the_protector_its_address_and_the_old_form_keeps_working() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();

    let peers: Arc<Mutex<Vec<Option<SocketAddr>>>> = Arc::default();
    let record = Arc::clone(&peers);
    set_peer_protector(Some(Arc::new(move |_, peer| {
        record.lock().unwrap().push(peer);
        true
    })));
    dial_tcp(addr).await.unwrap();
    udp_socket(Ipv4Addr::UNSPECIFIED.into()).await.unwrap();
    assert_eq!(
        *peers.lock().unwrap(),
        [Some(addr), None],
        "a TCP dial names its address; a UDP socket has no peer yet"
    );

    set_peer_protector(Some(Arc::new(|_, _| false)));
    let refused = dial_tcp(addr).await.unwrap_err();
    assert_eq!(refused.to_string(), REFUSED);

    // The old form, as olc-ffi installs it: each socket, once, as before.
    let sockets: Arc<Mutex<Vec<RawFd>>> = Arc::default();
    let record = Arc::clone(&sockets);
    set_protector(Some(Arc::new(move |fd| {
        record.lock().unwrap().push(fd);
        true
    })));
    let stream = dial_tcp(addr).await.unwrap();
    let socket = udp_socket(Ipv4Addr::UNSPECIFIED.into()).await.unwrap();
    {
        use std::os::fd::AsRawFd;
        assert_eq!(
            *sockets.lock().unwrap(),
            [stream.as_raw_fd(), socket.as_raw_fd()]
        );
    }
    set_protector(Some(Arc::new(|_| false)));
    let refused = dial_tcp(addr).await.unwrap_err();
    assert_eq!(refused.to_string(), REFUSED);

    set_protector(None);
    dial_tcp(addr).await.unwrap();
}

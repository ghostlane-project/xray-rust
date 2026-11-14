// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The protector is process-wide, so its test runs in a process of its own.

use std::sync::Arc;

use olc_client::net::{dial_tcp, set_protector};

/// The test's bound: a stuck dial fails it instead of holding the build box.
const BOUND: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test]
async fn a_refusing_protector_fails_the_dial_with_gos_words() {
    tokio::time::timeout(BOUND, refused_then_allowed())
        .await
        .expect("the test did not finish within its bound");
}

async fn refused_then_allowed() {
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    set_protector(Some(Arc::new(|_| false)));
    let err = dial_tcp(addr).await.unwrap_err();
    set_protector(None);
    assert!(err
        .to_string()
        .contains("socket protector rejected the socket"));
    dial_tcp(addr).await.unwrap();
}

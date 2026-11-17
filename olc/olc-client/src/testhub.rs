// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A hub for this crate's tests: it takes a participant's JOIN and then
//! leaves the test to play the room (send END, stop reading, read frames).

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::pipe::{FRAME_HEADER, KIND_JOIN, MAX_PAYLOAD};

/// A listening hub.
pub(crate) struct TestHub {
    listener: TcpListener,
}

/// One participant's connection, the hub's end.
pub(crate) struct Member {
    pub(crate) stream: TcpStream,
}

impl TestHub {
    /// Listens on loopback; the hub and the URL of room `room` on it. Its
    /// receive buffer is small, so a hub that stops reading backs the
    /// sender up within a few frames.
    pub(crate) async fn start(room: &str) -> (Self, String) {
        let sock = TcpSocket::new_v4().unwrap();
        sock.set_recv_buffer_size(64 * 1024).unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = sock.listen(16).unwrap();
        let url = format!("tcp://{}/{room}", listener.local_addr().unwrap());
        (Self { listener }, url)
    }

    /// The next participant, once its JOIN is read.
    pub(crate) async fn accept(&self) -> Member {
        let (stream, _) = self.listener.accept().await.unwrap();
        let mut m = Member { stream };
        let (kind, _) = m.read().await.unwrap();
        assert_eq!(kind, KIND_JOIN);
        m
    }
}

impl Member {
    /// Sends one frame.
    pub(crate) async fn send(&mut self, kind: u8, payload: &[u8]) -> io::Result<()> {
        let mut buf = Vec::with_capacity(FRAME_HEADER + payload.len());
        buf.extend_from_slice(&u32::try_from(1 + payload.len()).unwrap().to_be_bytes());
        buf.push(kind);
        buf.extend_from_slice(payload);
        self.stream.write_all(&buf).await
    }

    /// Reads one frame.
    pub(crate) async fn read(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let mut hdr = [0u8; FRAME_HEADER];
        self.stream.read_exact(&mut hdr).await?;
        let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        assert!(len >= 1 && len - 1 <= MAX_PAYLOAD, "frame of {len}");
        let mut payload = vec![0u8; len - 1];
        self.stream.read_exact(&mut payload).await?;
        Ok((hdr[4], payload))
    }
}

/// A config for room `url` with a fixed key.
pub(crate) fn config(url: &str) -> crate::Config {
    crate::Config::from_json(
        format!(
            r#"{{"url":"{url}","key":"{}","device_id":"t"}}"#,
            "11".repeat(32)
        )
        .as_bytes(),
    )
    .unwrap()
}

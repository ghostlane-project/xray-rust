// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A small RFC 6455 WebSocket client, generic over the transport stream.
//!
//! The handshake mimics a browser's header order (an extension is offered only
//! when the caller's headers name `Sec-WebSocket-Extensions`: permessage-deflate,
//! the crate's own `ws_deflate`),
//! client frames are always masked, and the reader assembles fragmented
//! messages under a hard size limit. Every buffer is bounded; the bound is
//! stated in a doc comment next to it.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::ws_deflate::{self, Deflater, Inflater};

/// The GUID that RFC 6455 mixes into `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Upper bound on the HTTP response head of the handshake: 16 KiB.
const MAX_HEAD: usize = 16 * 1024;

/// Size of one socket read while looking for the end of the handshake head.
/// The handshake buffer never exceeds `MAX_HEAD + HEAD_CHUNK` bytes.
const HEAD_CHUNK: usize = 1024;

/// Payload bytes are pulled from the socket in steps of at most this size, so
/// the message buffer only grows as data really arrives.
const PAYLOAD_CHUNK: usize = 64 * 1024;

/// Errors of the WebSocket client.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    /// The transport failed (including an unexpected end of stream).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The opening handshake was refused or malformed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// The peer broke the WebSocket protocol.
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    /// A message would exceed the configured read limit.
    #[error("message too large")]
    TooLarge,
    /// The peer closed the connection with this status code and reason.
    #[error("connection closed: {0} {1}")]
    Closed(u16, String),
    /// The handshake did not finish in time.
    #[error("timed out")]
    Timeout,
}

/// Parameters of the opening handshake.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Value of the `Host` header, with `:port` only if the port is not the default.
    pub host: &'a str,
    /// Request target: path plus query.
    pub path: &'a str,
    /// Extra headers (for example `Origin`, `User-Agent`), name and value.
    pub headers: &'a [(&'a str, &'a str)],
    /// Largest assembled incoming message accepted, in bytes.
    pub read_limit: usize,
    /// Time allowed for the whole handshake.
    pub timeout: Duration,
}

/// A complete incoming message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A text message (valid UTF-8).
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
}

/// The shared write half of the connection.
type SharedWrite<S> = Arc<Mutex<WriteHalf<S>>>;

/// Sending half of a connection. Cheap to clone; sends are serialised.
pub struct Writer<S> {
    inner: SharedWrite<S>,
    /// permessage-deflate's compressor when it was negotiated. Locked only
    /// while `inner` is, so messages are compressed in the order they go.
    deflate: Option<Arc<std::sync::Mutex<Deflater>>>,
}

impl<S> Clone for Writer<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            deflate: self.deflate.clone(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite> Writer<S> {
    /// Sends `text` as one masked text frame.
    pub async fn send_text(&self, text: &str) -> Result<(), WsError> {
        self.send_data(0x1, text.as_bytes()).await
    }

    /// Sends `b` as one masked binary frame.
    pub async fn send_binary(&self, b: &[u8]) -> Result<(), WsError> {
        self.send_data(0x2, b).await
    }

    /// One data message: compressed from [`ws_deflate::THRESHOLD`] bytes
    /// when the extension is on.
    async fn send_data(&self, op: u8, payload: &[u8]) -> Result<(), WsError> {
        let mut g = self.inner.lock().await;
        let frame = match &self.deflate {
            Some(d) if payload.len() >= ws_deflate::THRESHOLD => {
                let packed = d
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .deflate(payload);
                build_frame_rsv(op, 0x40, &packed)
            }
            _ => build_frame(op, payload),
        };
        g.write_all(&frame).await?;
        g.flush().await?;
        Ok(())
    }

    /// Sends a close frame with status 1000; errors are ignored.
    pub async fn close(&self) {
        let _ = send_frame(&self.inner, 0x8, &1000u16.to_be_bytes()).await;
    }
}

/// Receiving half of a connection. It also answers pings and close frames
/// through the shared write half.
pub struct Reader<S> {
    read: ReadHalf<S>,
    write: SharedWrite<S>,
    /// Bytes that arrived together with the handshake response. Bounded by
    /// `HEAD_CHUNK` (1 KiB); emptied and freed once consumed.
    lead: Vec<u8>,
    lead_pos: usize,
    read_limit: usize,
    /// permessage-deflate's decompressor when it was negotiated.
    inflate: Option<Inflater>,
}

/// Builds one masked, final frame. The result is at most `payload.len() + 14`
/// bytes long.
fn build_frame(op: u8, payload: &[u8]) -> Vec<u8> {
    build_frame_rsv(op, 0, payload)
}

/// [`build_frame`] with reserved bits (`0x40` is RSV1) set.
fn build_frame_rsv(op: u8, rsv: u8, payload: &[u8]) -> Vec<u8> {
    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    let len = payload.len();
    let mut f = Vec::with_capacity(len + 14);
    f.push(0x80 | rsv | op);
    if len < 126 {
        f.push(0x80 | len as u8);
    } else if len <= 0xffff {
        f.push(0x80 | 126);
        f.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    f
}

async fn send_frame<S: AsyncRead + AsyncWrite>(
    w: &Mutex<WriteHalf<S>>,
    op: u8,
    payload: &[u8],
) -> Result<(), WsError> {
    let frame = build_frame(op, payload);
    let mut g = w.lock().await;
    g.write_all(&frame).await?;
    g.flush().await?;
    Ok(())
}

fn accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    STANDARD.encode(h.finalize())
}

fn clean(s: &str) -> Result<(), WsError> {
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(WsError::Handshake("control character in request".into()));
    }
    Ok(())
}

fn build_request(req: &Request<'_>, key: &str) -> Result<String, WsError> {
    clean(req.host)?;
    clean(req.path)?;
    let mut ua = None;
    let mut origin = None;
    let mut rest: Vec<(&str, &str)> = Vec::new();
    for &(n, v) in req.headers {
        clean(n)?;
        clean(v)?;
        if n.eq_ignore_ascii_case("user-agent") {
            ua.get_or_insert(v);
        } else if n.eq_ignore_ascii_case("origin") {
            origin.get_or_insert(v);
        } else {
            rest.push((n, v));
        }
    }
    let mut s = String::new();
    s.push_str(&format!("GET {} HTTP/1.1\r\n", req.path));
    s.push_str(&format!("Host: {}\r\n", req.host));
    s.push_str("Connection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\n");
    if let Some(v) = ua {
        s.push_str(&format!("User-Agent: {v}\r\n"));
    }
    s.push_str("Upgrade: websocket\r\n");
    if let Some(v) = origin {
        s.push_str(&format!("Origin: {v}\r\n"));
    }
    s.push_str("Sec-WebSocket-Version: 13\r\n");
    s.push_str("Accept-Language: en-US,en;q=0.9\r\n");
    s.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    for (n, v) in rest {
        s.push_str(&format!("{n}: {v}\r\n"));
    }
    s.push_str("\r\n");
    Ok(s)
}

/// Reads the response head. Returns the head (at most `MAX_HEAD` bytes,
/// including the blank line) and any bytes that followed it (at most
/// `HEAD_CHUNK`).
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<(Vec<u8>, Vec<u8>), WsError> {
    let mut buf: Vec<u8> = Vec::with_capacity(HEAD_CHUNK);
    let mut chunk = [0u8; HEAD_CHUNK];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(WsError::Handshake(
                "connection closed during handshake".into(),
            ));
        }
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + i + 4;
            if end > MAX_HEAD {
                return Err(WsError::Handshake("response head too large".into()));
            }
            let lead = buf.split_off(end);
            return Ok((buf, lead));
        }
        if buf.len() > MAX_HEAD {
            return Err(WsError::Handshake("response head too large".into()));
        }
    }
}

fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// Checks the reply; the extension it settled on, when the offer had one.
fn check_response(
    head: &[u8],
    key: &str,
    offered_deflate: bool,
) -> Result<Option<ws_deflate::Params>, WsError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| WsError::Handshake("response head is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("");
    let ok_status = status
        .strip_prefix("HTTP/1.1 101")
        .is_some_and(|r| r.is_empty() || r.starts_with(' '));
    if !ok_status {
        return Err(WsError::Handshake(format!("unexpected status: {status}")));
    }
    let (mut upgrade, mut connection, mut accept) = (false, false, false);
    let want = accept_key(key);
    let mut extensions: Vec<&str> = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= has_token(value, "websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection |= has_token(value, "upgrade");
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept |= value == want;
        } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
            extensions.push(value);
        }
    }
    if !upgrade {
        return Err(WsError::Handshake("missing Upgrade: websocket".into()));
    }
    if !connection {
        return Err(WsError::Handshake("missing Connection: upgrade".into()));
    }
    if !accept {
        return Err(WsError::Handshake("bad Sec-WebSocket-Accept".into()));
    }
    let params = ws_deflate::parse_reply(&extensions)?;
    if params.is_some() && !offered_deflate {
        return Err(WsError::Handshake("an extension nobody offered".into()));
    }
    Ok(params)
}

async fn do_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    req: &Request<'_>,
) -> Result<(Vec<u8>, Option<ws_deflate::Params>), WsError> {
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let key = STANDARD.encode(raw);
    let text = build_request(req, &key)?;
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await?;
    let (head, lead) = read_head(stream).await?;
    let offered = req.headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("sec-websocket-extensions")
            && v.to_ascii_lowercase().contains("permessage-deflate")
    });
    let params = check_response(&head, &key, offered)?;
    Ok((lead, params))
}

/// Performs the client handshake on `stream` and splits it into a
/// [`Reader`] and a [`Writer`]. The whole exchange is bounded by
/// `req.timeout`.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    req: &Request<'_>,
) -> Result<(Reader<S>, Writer<S>), WsError> {
    let (lead, params) =
        match tokio::time::timeout(req.timeout, do_handshake(&mut stream, req)).await {
            Err(_) => return Err(WsError::Timeout),
            Ok(r) => r?,
        };
    let (read, write) = split(stream);
    let write = Arc::new(Mutex::new(write));
    let reader = Reader {
        read,
        write: Arc::clone(&write),
        lead,
        lead_pos: 0,
        read_limit: req.read_limit,
        inflate: params.map(Inflater::new),
    };
    let deflate = params.map(|p| Arc::new(std::sync::Mutex::new(Deflater::new(p))));
    Ok((
        reader,
        Writer {
            inner: write,
            deflate,
        },
    ))
}

impl<S: AsyncRead + AsyncWrite> Reader<S> {
    /// Fills `out` completely, first from the handshake leftovers.
    async fn fill(&mut self, out: &mut [u8]) -> Result<(), WsError> {
        let mut done = 0;
        if self.lead_pos < self.lead.len() {
            let n = (self.lead.len() - self.lead_pos).min(out.len());
            out[..n].copy_from_slice(&self.lead[self.lead_pos..self.lead_pos + n]);
            self.lead_pos += n;
            done = n;
            if self.lead_pos == self.lead.len() {
                self.lead = Vec::new();
                self.lead_pos = 0;
            }
        }
        if done < out.len() {
            self.read.read_exact(&mut out[done..]).await?;
        }
        Ok(())
    }

    /// Reads the next complete message, answering pings and closes on the way.
    ///
    /// The message buffer holds only bytes that have arrived; its capacity is
    /// at most twice the assembled size, which never exceeds `read_limit`.
    pub async fn next(&mut self) -> Result<Message, WsError> {
        let mut msg: Vec<u8> = Vec::new();
        let mut in_progress: Option<bool> = None; // Some(is_text)
        let mut packed = false; // the message's first frame had RSV1
        loop {
            let mut h = [0u8; 2];
            self.fill(&mut h).await?;
            let fin = h[0] & 0x80 != 0;
            let op = h[0] & 0x0f;
            // RSV1 is permessage-deflate's, on the first frame of a data
            // message and only when the extension was agreed.
            let rsv1 = h[0] & 0x40 != 0;
            if h[0] & 0x30 != 0 || (rsv1 && (self.inflate.is_none() || op == 0 || op & 8 != 0)) {
                return Err(WsError::Protocol("reserved bits set"));
            }
            if h[1] & 0x80 != 0 {
                return Err(WsError::Protocol("masked server frame"));
            }
            if !matches!(op, 0 | 1 | 2 | 8 | 9 | 10) {
                return Err(WsError::Protocol("unknown opcode"));
            }
            let len: u64 = match h[1] & 0x7f {
                126 => {
                    let mut b = [0u8; 2];
                    self.fill(&mut b).await?;
                    u64::from(u16::from_be_bytes(b))
                }
                127 => {
                    let mut b = [0u8; 8];
                    self.fill(&mut b).await?;
                    let v = u64::from_be_bytes(b);
                    if v >> 63 != 0 {
                        return Err(WsError::Protocol("invalid 64-bit length"));
                    }
                    v
                }
                n => u64::from(n),
            };

            if op & 0x8 != 0 {
                if len > 125 {
                    return Err(WsError::Protocol("control frame too long"));
                }
                if !fin {
                    return Err(WsError::Protocol("fragmented control frame"));
                }
                // At most 125 bytes.
                let mut payload = vec![0u8; len as usize];
                self.fill(&mut payload).await?;
                match op {
                    9 => send_frame(&self.write, 0xA, &payload).await?,
                    10 => {}
                    _ => return self.handle_close(&payload).await,
                }
                continue;
            }

            match (op, in_progress) {
                (0, None) => return Err(WsError::Protocol("continuation without start")),
                (1 | 2, Some(_)) => {
                    return Err(WsError::Protocol("new message inside fragmented message"))
                }
                (1, None) => {
                    in_progress = Some(true);
                    packed = rsv1;
                }
                (2, None) => {
                    in_progress = Some(false);
                    packed = rsv1;
                }
                _ => {}
            }
            // Checked before any allocation for this frame.
            if (msg.len() as u64).saturating_add(len) > self.read_limit as u64 {
                return Err(WsError::TooLarge);
            }
            let mut remaining = len as usize; // <= read_limit, fits usize
            while remaining > 0 {
                let take = remaining.min(PAYLOAD_CHUNK);
                let start = msg.len();
                msg.resize(start + take, 0);
                self.fill(&mut msg[start..]).await?;
                remaining -= take;
            }
            if fin {
                if packed {
                    if let Some(inflater) = self.inflate.as_mut() {
                        msg = inflater.inflate(&msg, self.read_limit)?;
                    }
                }
                return if in_progress == Some(true) {
                    String::from_utf8(msg)
                        .map(Message::Text)
                        .map_err(|_| WsError::Protocol("invalid utf-8 in text message"))
                } else {
                    Ok(Message::Binary(msg))
                };
            }
        }
    }

    async fn handle_close(&mut self, payload: &[u8]) -> Result<Message, WsError> {
        let (code, reason) = match payload.len() {
            0 => (1005, String::new()),
            1 => return Err(WsError::Protocol("malformed close payload")),
            _ => (
                u16::from_be_bytes([payload[0], payload[1]]),
                String::from_utf8_lossy(&payload[2..]).into_owned(),
            ),
        };
        let echo: &[u8] = if payload.len() >= 2 {
            &payload[..2]
        } else {
            &[]
        };
        let _ = send_frame(&self.write, 0x8, echo).await;
        Err(WsError::Closed(code, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;
    use tokio::time::timeout;

    const KEY_LINE: &str = "Sec-WebSocket-Key: ";

    async fn read_request_head(s: &mut DuplexStream) -> String {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).await.unwrap();
            buf.push(b[0]);
        }
        String::from_utf8(buf).unwrap()
    }

    fn key_of(head: &str) -> String {
        head.lines()
            .find_map(|l| l.strip_prefix(KEY_LINE))
            .unwrap()
            .to_string()
    }

    /// A server's answer to a handshake, from the request's key.
    type Respond = Box<dyn FnOnce(&str) -> Vec<u8> + Send>;

    fn ok_response(key: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(key)
        )
        .into_bytes()
    }

    fn request(read_limit: usize, timeout: Duration) -> Request<'static> {
        Request {
            host: "example.test",
            path: "/ws?x=1",
            headers: &[
                ("Origin", "https://example.test"),
                ("X-Extra", "1"),
                ("User-Agent", "UA/1"),
            ],
            read_limit,
            timeout,
        }
    }

    /// Runs a handshake against a fake server that answers with `respond(key)`
    /// followed by `first`. Returns the client result, the request head the
    /// server saw, and the server stream.
    async fn run(
        respond: impl FnOnce(&str) -> Vec<u8> + Send + 'static,
        first: Vec<u8>,
        read_limit: usize,
    ) -> (
        Result<(Reader<DuplexStream>, Writer<DuplexStream>), WsError>,
        String,
        DuplexStream,
    ) {
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move {
            let head = read_request_head(&mut server).await;
            let mut out = respond(&key_of(&head));
            out.extend_from_slice(&first);
            server.write_all(&out).await.unwrap();
            (head, server)
        });
        let res = handshake(client, &request(read_limit, Duration::from_secs(5))).await;
        let (head, server) = task.await.unwrap();
        (res, head, server)
    }

    async fn connect(
        first: Vec<u8>,
        read_limit: usize,
    ) -> (Reader<DuplexStream>, Writer<DuplexStream>, DuplexStream) {
        let (res, _, server) = run(ok_response, first, read_limit).await;
        let (r, w) = res.expect("handshake");
        (r, w, server)
    }

    fn frame(op: u8, fin: bool, payload: &[u8], force64: bool) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | op];
        let n = payload.len();
        if force64 {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        } else if n < 126 {
            f.push(n as u8);
        } else if n <= 0xffff {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
        f.extend_from_slice(payload);
        f
    }

    async fn read_client_frame(s: &mut DuplexStream) -> (u8, Vec<u8>) {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await.unwrap();
        assert!(h[1] & 0x80 != 0, "client frame must be masked");
        let len = match h[1] & 0x7f {
            126 => {
                let mut b = [0u8; 2];
                s.read_exact(&mut b).await.unwrap();
                u16::from_be_bytes(b) as usize
            }
            127 => {
                let mut b = [0u8; 8];
                s.read_exact(&mut b).await.unwrap();
                u64::from_be_bytes(b) as usize
            }
            n => n as usize,
        };
        let mut m = [0u8; 4];
        s.read_exact(&mut m).await.unwrap();
        let mut p = vec![0u8; len];
        s.read_exact(&mut p).await.unwrap();
        for (i, b) in p.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
        (h[0], p)
    }

    async fn within<F: std::future::Future>(f: F) -> F::Output {
        timeout(Duration::from_secs(10), f)
            .await
            .expect("test timed out")
    }

    #[test]
    fn accept_key_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn handshake_success_request_bytes_and_leftover() {
        within(async {
            let first = frame(1, true, b"hello", false);
            let (res, head, _server) = run(ok_response, first, 1024).await;
            let (mut reader, _w) = res.expect("handshake");
            let key = key_of(&head);
            let expected = format!(
                "GET /ws?x=1 HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nUser-Agent: UA/1\r\nUpgrade: websocket\r\nOrigin: https://example.test\r\nSec-WebSocket-Version: 13\r\nAccept-Language: en-US,en;q=0.9\r\nSec-WebSocket-Key: {key}\r\nX-Extra: 1\r\n\r\n"
            );
            assert_eq!(head, expected);
            assert_eq!(STANDARD.decode(&key).unwrap().len(), 16);
            assert_eq!(reader.next().await.unwrap(), Message::Text("hello".into()));
        })
        .await;
    }

    #[tokio::test]
    async fn handshake_rejections() {
        within(async {
            let good = |k: &str| accept_key(k);
            let cases: Vec<(&str, Respond)> = vec![
                (
                    "status",
                    Box::new(move |k| {
                        format!("HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", good(k)).into_bytes()
                    }),
                ),
                (
                    "upgrade",
                    Box::new(move |k| {
                        format!("HTTP/1.1 101 X\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", good(k)).into_bytes()
                    }),
                ),
                (
                    "connection",
                    Box::new(move |k| {
                        format!("HTTP/1.1 101 X\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n", good(k)).into_bytes()
                    }),
                ),
                (
                    "accept",
                    Box::new(|_| {
                        b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAA\r\n\r\n".to_vec()
                    }),
                ),
                (
                    "head too large",
                    Box::new(|_| {
                        let mut v = b"HTTP/1.1 101 X\r\nX: ".to_vec();
                        v.extend(std::iter::repeat_n(b'a', 20_000));
                        v
                    }),
                ),
            ];
            for (name, f) in cases {
                let (res, _, _s) = run(f, Vec::new(), 1024).await;
                match res.err() {
                    Some(WsError::Handshake(_)) => {}
                    other => panic!("case {name}: unexpected {other:?}"),
                }
            }
            // Case-insensitive acceptance with a token list.
            let (res, _, _s) = run(
                |k| {
                    format!("HTTP/1.1 101 X\r\nupgrade: WebSocket\r\nconnection: keep-alive, UPGRADE\r\nsec-websocket-accept: {}\r\n\r\n", accept_key(k)).into_bytes()
                },
                Vec::new(),
                1024,
            )
            .await;
            assert!(res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn handshake_times_out() {
        within(async {
            let (client, _server) = tokio::io::duplex(4096);
            let r = handshake(client, &request(1024, Duration::from_millis(50))).await;
            assert!(matches!(r.err(), Some(WsError::Timeout)));
        })
        .await;
    }

    #[tokio::test]
    async fn client_frames_are_masked_with_all_length_forms() {
        within(async {
            let (_r, w, mut server) = connect(Vec::new(), 1024).await;
            w.send_text("hi").await.unwrap();
            assert_eq!(read_client_frame(&mut server).await, (0x81, b"hi".to_vec()));

            let mid = vec![7u8; 300];
            w.send_binary(&mid).await.unwrap();
            assert_eq!(read_client_frame(&mut server).await, (0x82, mid));

            let big: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
            let (r, got) = tokio::join!(w.send_binary(&big), read_client_frame(&mut server));
            r.unwrap();
            assert_eq!(got, (0x82, big));

            w.clone().close().await;
            let (op, p) = read_client_frame(&mut server).await;
            assert_eq!((op, p), (0x88, 1000u16.to_be_bytes().to_vec()));
        })
        .await;
    }

    #[tokio::test]
    async fn server_length_forms() {
        within(async {
            let mid = vec![b'a'; 300];
            let big = vec![b'b'; 70_000];
            let mut first = frame(1, true, &mid, false);
            first.extend(frame(2, true, b"xy", true));
            let (mut r, _w, mut server) = connect(first, 100_000).await;
            assert_eq!(
                r.next().await.unwrap(),
                Message::Text(String::from_utf8(mid).unwrap())
            );
            assert_eq!(r.next().await.unwrap(), Message::Binary(b"xy".to_vec()));
            let f = frame(2, true, &big, false);
            let (w, got) = tokio::join!(server.write_all(&f), r.next());
            w.unwrap();
            assert_eq!(got.unwrap(), Message::Binary(big));
        })
        .await;
    }

    #[tokio::test]
    async fn fragmentation_with_interleaved_ping() {
        within(async {
            let mut first = frame(1, false, b"hel", false);
            first.extend(frame(9, true, b"p", false));
            first.extend(frame(0, false, b"l", false));
            first.extend(frame(10, true, b"", false));
            first.extend(frame(0, true, b"o", false));
            let (mut r, _w, mut server) = connect(first, 1024).await;
            assert_eq!(r.next().await.unwrap(), Message::Text("hello".into()));
            assert_eq!(read_client_frame(&mut server).await, (0x8A, b"p".to_vec()));
        })
        .await;
    }

    #[tokio::test]
    async fn ping_is_answered_with_same_payload() {
        within(async {
            let mut first = frame(9, true, b"abc", false);
            first.extend(frame(1, true, b"x", false));
            let (mut r, _w, mut server) = connect(first, 1024).await;
            assert_eq!(r.next().await.unwrap(), Message::Text("x".into()));
            assert_eq!(
                read_client_frame(&mut server).await,
                (0x8A, b"abc".to_vec())
            );
        })
        .await;
    }

    #[tokio::test]
    async fn close_is_echoed() {
        within(async {
            let mut payload = 1001u16.to_be_bytes().to_vec();
            payload.extend_from_slice(b"bye");
            let (mut r, _w, mut server) = connect(frame(8, true, &payload, false), 1024).await;
            match r.next().await {
                Err(WsError::Closed(1001, reason)) => assert_eq!(reason, "bye"),
                other => panic!("unexpected {other:?}"),
            }
            let (op, p) = read_client_frame(&mut server).await;
            assert_eq!((op, p), (0x88, 1001u16.to_be_bytes().to_vec()));
        })
        .await;
    }

    #[tokio::test]
    async fn too_large_is_detected_before_payload_arrives() {
        within(async {
            // Header only: claims 11 bytes, limit is 10; no payload is sent.
            let mut hdr = frame(1, true, b"", false);
            hdr[1] = 11;
            let (mut r, _w, _s) = connect(hdr, 10).await;
            assert!(matches!(r.next().await, Err(WsError::TooLarge)));

            // Assembled size across fragments.
            let mut first = frame(2, false, &[0u8; 6], false);
            first.extend(frame(0, true, &[0u8; 6], false));
            let (mut r, _w, _s) = connect(first, 10).await;
            assert!(matches!(r.next().await, Err(WsError::TooLarge)));

            // Exactly at the limit is fine.
            let (mut r, _w, _s) = connect(frame(2, true, &[1u8; 10], false), 10).await;
            assert_eq!(r.next().await.unwrap(), Message::Binary(vec![1u8; 10]));
        })
        .await;
    }

    #[tokio::test]
    async fn invalid_utf8_text_is_rejected() {
        within(async {
            let (mut r, _w, _s) = connect(frame(1, true, &[0xff, 0xfe], false), 1024).await;
            assert!(matches!(r.next().await, Err(WsError::Protocol(_))));
            // The same bytes as binary are fine.
            let (mut r, _w, _s) = connect(frame(2, true, &[0xff, 0xfe], false), 1024).await;
            assert_eq!(r.next().await.unwrap(), Message::Binary(vec![0xff, 0xfe]));
        })
        .await;
    }

    #[tokio::test]
    async fn protocol_violations_are_rejected() {
        within(async {
            let cases: Vec<(&str, Vec<u8>)> = vec![
                ("masked", vec![0x81, 0x81, 1, 2, 3, 4, 0x41]),
                ("reserved bit", vec![0xC1, 0x00]),
                ("unknown opcode", vec![0x83, 0x00]),
                ("long control", frame(9, true, &[0u8; 126], false)),
                ("fragmented control", frame(9, false, b"", false)),
                ("orphan continuation", frame(0, true, b"x", false)),
                ("nested start", {
                    let mut v = frame(1, false, b"a", false);
                    v.extend(frame(1, true, b"b", false));
                    v
                }),
                ("one-byte close", frame(8, true, &[3], false)),
            ];
            for (name, bytes) in cases {
                let (mut r, _w, _s) = connect(bytes, 1024).await;
                match r.next().await {
                    Err(WsError::Protocol(_)) => {}
                    other => panic!("case {name}: unexpected {other:?}"),
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn eof_is_an_io_error() {
        within(async {
            let (mut r, _w, server) = connect(vec![0x81], 1024).await;
            drop(server);
            assert!(matches!(r.next().await, Err(WsError::Io(_))));
        })
        .await;
    }

    // ---- PJ2: the caller's read limit, a subprotocol the reply leaves out ----

    #[tokio::test]
    async fn a_message_one_byte_over_the_read_limit_ends_the_reader() {
        within(async {
            let limit = 1 << 20;
            let (mut r, _w, _s) =
                connect(frame(1, true, &vec![b'a'; limit + 1], false), limit).await;
            assert!(matches!(r.next().await, Err(WsError::TooLarge)));
            let (mut r, _w, _s) = connect(frame(1, true, &vec![b'a'; limit], false), limit).await;
            match r.next().await.unwrap() {
                Message::Text(t) => assert_eq!(t.len(), limit),
                m => panic!("{m:?}"),
            }
        })
        .await;
    }

    #[tokio::test]
    async fn a_reply_without_the_requested_subprotocol_connects() {
        within(async {
            let (client, mut server) = tokio::io::duplex(1 << 16);
            let task = tokio::spawn(async move {
                let head = read_request_head(&mut server).await;
                server
                    .write_all(&ok_response(&key_of(&head)))
                    .await
                    .unwrap();
                head
            });
            let headers = [("Sec-WebSocket-Protocol", "xmpp")];
            let req = Request {
                host: "example.test",
                path: "/xmpp-websocket",
                headers: &headers,
                read_limit: 1 << 20,
                timeout: Duration::from_secs(5),
            };
            assert!(handshake(client, &req).await.is_ok());
            let head = task.await.unwrap();
            assert!(head.contains("Sec-WebSocket-Protocol: xmpp\r\n"), "{head}");
        })
        .await;
    }

    // ---- PJ3: permessage-deflate (RFC 7692) ----

    const OFFER: [(&str, &str); 1] = [("Sec-WebSocket-Extensions", "permessage-deflate")];

    fn ok_with_extension(ext: &'static str) -> impl FnOnce(&str) -> Vec<u8> + Send + 'static {
        move |key: &str| {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Extensions: {ext}\r\n\r\n",
                accept_key(key)
            )
            .into_bytes()
        }
    }

    /// A handshake that offers permessage-deflate and is answered with
    /// `reply` (the extension header's value; `None` for no header).
    async fn deflating(
        reply: Option<&'static str>,
        first: Vec<u8>,
        read_limit: usize,
    ) -> (
        Result<(Reader<DuplexStream>, Writer<DuplexStream>), WsError>,
        String,
        DuplexStream,
    ) {
        let (client, mut server) = tokio::io::duplex(1 << 22);
        let task = tokio::spawn(async move {
            let head = read_request_head(&mut server).await;
            let mut out = match reply {
                Some(ext) => ok_with_extension(ext)(&key_of(&head)),
                None => ok_response(&key_of(&head)),
            };
            out.extend_from_slice(&first);
            server.write_all(&out).await.unwrap();
            (head, server)
        });
        let req = Request {
            host: "example.test",
            path: "/xmpp-websocket",
            headers: &OFFER,
            read_limit,
            timeout: Duration::from_secs(5),
        };
        let res = handshake(client, &req).await;
        let (head, server) = task.await.unwrap();
        (res, head, server)
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut c = flate2::Compress::new(flate2::Compression::default(), false);
        let mut out = Vec::with_capacity(data.len() + 64);
        c.compress_vec(data, &mut out, flate2::FlushCompress::Sync)
            .unwrap();
        assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
        out.truncate(out.len() - 4);
        out
    }

    fn raw_inflate(data: &[u8]) -> Vec<u8> {
        let mut d = flate2::Decompress::new(false);
        let mut input = data.to_vec();
        input.extend_from_slice(&[0, 0, 0xff, 0xff]);
        let mut out = Vec::with_capacity(1 << 20);
        d.decompress_vec(&input, &mut out, flate2::FlushDecompress::Sync)
            .unwrap();
        out
    }

    fn compressed_frame(op: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut f = frame(op, fin, payload, false);
        f[0] |= 0x40;
        f
    }

    #[tokio::test]
    async fn the_offer_is_the_bare_extension_and_a_reply_with_it_connects() {
        within(async {
            let (res, head, _s) = deflating(Some("permessage-deflate"), Vec::new(), 1 << 20).await;
            assert!(res.is_ok());
            assert!(
                head.contains("Sec-WebSocket-Extensions: permessage-deflate\r\n"),
                "{head}"
            );
        })
        .await;
    }

    /// RFC 7692 section 7.2.3.1: "Hello" compressed is f2 48 cd c9 c9 07 00.
    #[tokio::test]
    async fn rfc_7692_hello_is_read() {
        within(async {
            let wire = compressed_frame(1, true, &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
            assert_eq!(&wire[..2], &[0xc1, 0x07]);
            let (res, _, _s) = deflating(Some("permessage-deflate"), wire, 1 << 20).await;
            let (mut r, _w) = res.unwrap();
            assert_eq!(r.next().await.unwrap(), Message::Text("Hello".into()));
        })
        .await;
    }

    /// Section 7.2.3.3: one message in two fragments, RSV1 on the first only.
    #[tokio::test]
    async fn rfc_7692_a_fragmented_message_is_read() {
        within(async {
            let mut wire = compressed_frame(1, false, &[0xf2, 0x48, 0xcd]);
            wire.extend(frame(0, true, &[0xc9, 0xc9, 0x07, 0x00], false));
            assert_eq!(
                wire,
                [0x41, 0x03, 0xf2, 0x48, 0xcd, 0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00]
            );
            let (res, _, _s) = deflating(Some("permessage-deflate"), wire, 1 << 20).await;
            let (mut r, _w) = res.unwrap();
            assert_eq!(r.next().await.unwrap(), Message::Text("Hello".into()));
        })
        .await;
    }

    /// Section 7.2.3.2 and context takeover: the second "Hello" is five
    /// bytes that only mean something after the first.
    #[tokio::test]
    async fn the_context_is_kept_between_messages() {
        within(async {
            let mut wire = compressed_frame(1, true, &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
            wire.extend(compressed_frame(1, true, &[0xf2, 0x00, 0x11, 0x00, 0x00]));
            let (res, _, _s) = deflating(Some("permessage-deflate"), wire, 1 << 20).await;
            let (mut r, _w) = res.unwrap();
            assert_eq!(r.next().await.unwrap(), Message::Text("Hello".into()));
            assert_eq!(r.next().await.unwrap(), Message::Text("Hello".into()));
        })
        .await;
    }

    #[tokio::test]
    async fn a_message_that_inflates_past_the_limit_ends_the_reader() {
        within(async {
            let bomb = raw_deflate(&vec![0u8; 3 << 20]);
            assert!(bomb.len() < 8192, "{}", bomb.len());
            let (res, _, _s) = deflating(
                Some("permessage-deflate"),
                compressed_frame(2, true, &bomb),
                1 << 20,
            )
            .await;
            let (mut r, _w) = res.unwrap();
            assert!(matches!(r.next().await, Err(WsError::TooLarge)));
            // Exactly the limit passes.
            let ok = raw_deflate(&vec![7u8; 1 << 20]);
            let (res, _, _s) = deflating(
                Some("permessage-deflate"),
                compressed_frame(2, true, &ok),
                1 << 20,
            )
            .await;
            let (mut r, _w) = res.unwrap();
            match r.next().await.unwrap() {
                Message::Binary(b) => assert_eq!(b.len(), 1 << 20),
                m => panic!("{m:?}"),
            }
        })
        .await;
    }

    #[tokio::test]
    async fn rsv1_without_the_extension_is_still_an_error() {
        within(async {
            let wire = compressed_frame(1, true, &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
            // Not offered, not answered.
            let (mut r, _w, _s) = connect(wire.clone(), 1 << 20).await;
            assert!(matches!(
                r.next().await,
                Err(WsError::Protocol("reserved bits set"))
            ));
            // Offered, but the reply left the extension out.
            let (res, _, _s) = deflating(None, wire, 1 << 20).await;
            let (mut r, _w) = res.unwrap();
            assert!(matches!(
                r.next().await,
                Err(WsError::Protocol("reserved bits set"))
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn rsv1_on_a_continuation_or_a_control_frame_is_an_error() {
        within(async {
            let mut wire = compressed_frame(1, false, &[0xf2, 0x48, 0xcd]);
            wire.extend(compressed_frame(0, true, &[0xc9, 0xc9, 0x07, 0x00]));
            let (res, _, _s) = deflating(Some("permessage-deflate"), wire, 1 << 20).await;
            let (mut r, _w) = res.unwrap();
            assert!(matches!(
                r.next().await,
                Err(WsError::Protocol("reserved bits set"))
            ));
            let (res, _, _s) = deflating(
                Some("permessage-deflate"),
                compressed_frame(9, true, b""),
                1 << 20,
            )
            .await;
            let (mut r, _w) = res.unwrap();
            assert!(matches!(
                r.next().await,
                Err(WsError::Protocol("reserved bits set"))
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn the_servers_extension_reply_is_checked_as_gos_is() {
        within(async {
            for ok in [
                "permessage-deflate; client_no_context_takeover",
                "permessage-deflate; server_no_context_takeover",
                "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
                "permessage-deflate; server_max_window_bits=15",
                "permessage-deflate; server_max_window_bits=10",
                "Permessage-Deflate",
            ] {
                let (res, _, _s) = deflating(Some(ok), Vec::new(), 1 << 20).await;
                assert!(res.is_ok(), "{ok}");
            }
            for bad in [
                "permessage-deflate; client_max_window_bits=15",
                "permessage-deflate; client_max_window_bits",
                "permessage-deflate; unknown",
                "permessage-deflate; server_max_window_bits=7",
                "permessage-deflate; server_max_window_bits=16",
                "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
                "x-webkit-deflate-frame",
                "permessage-deflate, permessage-deflate",
            ] {
                let (res, _, _s) = deflating(Some(bad), Vec::new(), 1 << 20).await;
                assert!(matches!(res, Err(WsError::Handshake(_))), "{bad}");
            }
            // An extension nobody offered.
            let (res, _, _s) =
                run(ok_with_extension("permessage-deflate"), Vec::new(), 1 << 20).await;
            assert!(matches!(res, Err(WsError::Handshake(_))));
        })
        .await;
    }

    #[tokio::test]
    async fn outgoing_messages_from_128_bytes_are_compressed_and_the_context_is_kept() {
        within(async {
            let (res, _, mut s) = deflating(Some("permessage-deflate"), Vec::new(), 1 << 20).await;
            let (_r, w) = res.unwrap();
            // Below the threshold: plain.
            w.send_text(&"a".repeat(127)).await.unwrap();
            let (b0, p) = read_client_frame(&mut s).await;
            assert_eq!((b0, p.len()), (0x81, 127));
            // At it: compressed, RSV1 set.
            let text = format!("<iq type='result' id='{}'/>", "x".repeat(200));
            w.send_text(&text).await.unwrap();
            let (b0, p1) = read_client_frame(&mut s).await;
            assert_eq!(b0, 0xc1);
            assert!(p1.len() < text.len() / 2, "{}", p1.len());
            // The same message again: context kept, so it is smaller still.
            w.send_text(&text).await.unwrap();
            let (b0, p2) = read_client_frame(&mut s).await;
            assert_eq!(b0, 0xc1);
            assert!(p2.len() < p1.len(), "{} !< {}", p2.len(), p1.len());
            // Binary too; a fresh inflater reads the first, one that saw the
            // first reads the second.
            let mut d = flate2::Decompress::new(false);
            let mut out = Vec::with_capacity(4096);
            for p in [&p1, &p2] {
                let mut input = (*p).clone();
                input.extend_from_slice(&[0, 0, 0xff, 0xff]);
                out.clear();
                d.decompress_vec(&input, &mut out, flate2::FlushDecompress::Sync)
                    .unwrap();
                assert_eq!(out, text.as_bytes());
            }
            assert_eq!(raw_inflate(&p1), text.as_bytes());
        })
        .await;
    }

    #[tokio::test]
    async fn client_no_context_takeover_compresses_each_message_alone() {
        within(async {
            let (res, _, mut s) = deflating(
                Some("permessage-deflate; client_no_context_takeover"),
                Vec::new(),
                1 << 20,
            )
            .await;
            let (_r, w) = res.unwrap();
            let text = "y".repeat(500);
            w.send_text(&text).await.unwrap();
            w.send_text(&text).await.unwrap();
            let (_, p1) = read_client_frame(&mut s).await;
            let (_, p2) = read_client_frame(&mut s).await;
            assert_eq!(
                p1, p2,
                "the second message was compressed with the first in its window"
            );
            assert_eq!(raw_inflate(&p2), text.as_bytes());
        })
        .await;
    }

    /// The server's own takeover choice: a fresh window for every message.
    #[tokio::test]
    async fn server_no_context_takeover_reads_messages_each_from_a_fresh_window() {
        within(async {
            let one = raw_deflate(b"Hello");
            let mut wire = compressed_frame(1, true, &one);
            wire.extend(compressed_frame(1, true, &one));
            let (res, _, _s) = deflating(
                Some("permessage-deflate; server_no_context_takeover"),
                wire,
                1 << 20,
            )
            .await;
            let (mut r, _w) = res.unwrap();
            assert_eq!(r.next().await.unwrap(), Message::Text("Hello".into()));
            assert_eq!(r.next().await.unwrap(), Message::Text("Hello".into()));
        })
        .await;
    }

    #[tokio::test]
    async fn without_the_extension_nothing_is_compressed() {
        within(async {
            let (_r, w, mut s) = connect(Vec::new(), 1 << 20).await;
            w.send_text(&"a".repeat(1000)).await.unwrap();
            let (b0, p) = read_client_frame(&mut s).await;
            assert_eq!((b0, p.len()), (0x81, 1000));
        })
        .await;
    }
}

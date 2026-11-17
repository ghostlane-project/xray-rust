// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A browser's `fetch`: one request on a connection whose TLS offered `h2`
//! and `http/1.1`, as Chrome's does (port plan section 8: what an observer
//! sees of the auth's REST calls is Chrome's hello), spoken in whichever the
//! server picked. HTTP/1.1 is [`crate::http`]'s; HTTP/2 is the fork's `h2`
//! with Chrome's connection preface: its SETTINGS (in its order), its
//! connection window and its pseudo-header order.
//!
//! Memory, per call (one at a time, for the length of the call): the
//! request; HPACK's tables (ours at most [`H2_HEADER_TABLE_SIZE`], the
//! server's at most its own setting, 4 KiB by default); a response head of
//! at most [`H2_MAX_HEADER_LIST`]; and the body. The body is read frame by
//! frame and the call fails past `max_body`, so it holds at most `max_body`
//! plus what `h2` buffered ahead of the read. That is at most the stream
//! window [`H2_STREAM_WINDOW`] (Chrome's 6 MiB), and only from a server
//! that sends far more than the call accepts; a SaluteJazz preconnect reply
//! is a few hundred bytes.

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::http::{self, HttpError, HttpRequest, HttpResponse};
use crate::stream::{self, Dialed, Offer, Target};

/// Chrome's `SETTINGS_HEADER_TABLE_SIZE`: 64 KiB.
pub const H2_HEADER_TABLE_SIZE: u32 = 65_536;
/// Chrome's `SETTINGS_INITIAL_WINDOW_SIZE`: 6 MiB.
pub const H2_STREAM_WINDOW: u32 = 6 * 1024 * 1024;
/// Chrome's `SETTINGS_MAX_HEADER_LIST_SIZE`: 256 KiB.
pub const H2_MAX_HEADER_LIST: u32 = 256 * 1024;
/// Chrome's connection window: 15 MiB, its WINDOW_UPDATE of 15,663,105 on
/// top of the protocol's 65,535.
pub const H2_CONNECTION_WINDOW: u32 = 15 * 1024 * 1024;

/// Sends `req` to `t` as a browser's `fetch` does: the TLS offers `h2` and
/// `http/1.1` ([`Offer::Fetch`]), and the request goes in the protocol the
/// server picked; a plain `http://` URL is HTTP/1.1. The whole call, the
/// dial included, is bounded by `req.timeout`.
///
/// # Errors
/// The dial's, the TLS's (as [`HttpError::Io`]), or the exchange's.
pub async fn fetch(t: &Target, req: &HttpRequest<'_>) -> Result<HttpResponse, HttpError> {
    let call = async {
        let dialed = stream::dial_for(t, Offer::Fetch).await?;
        on(dialed, req).await
    };
    bounded(req.timeout, call).await
}

/// One exchange on a dialed connection, in the protocol its TLS picked.
pub(crate) async fn on(dialed: Dialed, req: &HttpRequest<'_>) -> Result<HttpResponse, HttpError> {
    if dialed.h2 {
        request_h2(dialed.stream, req).await
    } else {
        let mut s = dialed.stream;
        http::request(&mut s, req).await
    }
}

/// Sends `req` on `io`, a stream whose TLS picked `h2`, and reads one
/// response, bounded by `req.timeout`. The connection is driven in this
/// call and ends with it: nothing is spawned.
///
/// # Errors
/// [`HttpError::Io`] for the transport, [`HttpError::Protocol`] for
/// HTTP/2's own errors and a malformed request, [`HttpError::TooLarge`]
/// past `req.max_body`, [`HttpError::Unsupported`] for a content coding.
pub async fn request_h2<S>(io: S, req: &HttpRequest<'_>) -> Result<HttpResponse, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let call = async {
        let (send, conn) = h2::client::Builder::new()
            .header_table_size(H2_HEADER_TABLE_SIZE)
            .enable_push(false)
            .initial_window_size(H2_STREAM_WINDOW)
            .max_header_list_size(H2_MAX_HEADER_LIST)
            .initial_connection_window_size(H2_CONNECTION_WINDOW)
            // Chrome's order: :method, :authority, :scheme, :path.
            .authority_after_method(true)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(h2_error)?;
        // The connection runs until the exchange ends; when it fails first,
        // the exchange's own futures report that.
        let drive = async {
            let _ = conn.await;
            std::future::pending::<()>().await;
        };
        tokio::select! {
            r = exchange(send, req) => r,
            () = drive => unreachable!("the drive never ends"),
        }
    };
    bounded(req.timeout, call).await
}

pub(crate) async fn bounded<F>(limit: Duration, call: F) -> Result<HttpResponse, HttpError>
where
    F: std::future::Future<Output = Result<HttpResponse, HttpError>>,
{
    match tokio::time::timeout(limit, call).await {
        Ok(r) => r,
        Err(_) => Err(HttpError::Timeout),
    }
}

/// Headers HTTP/2 carries otherwise (`host` is `:authority`) or forbids
/// (RFC 9113 section 8.2.2).
fn connection_specific(name: &str) -> bool {
    [
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

/// One request and its response on `send`.
async fn exchange(
    send: h2::client::SendRequest<Bytes>,
    req: &HttpRequest<'_>,
) -> Result<HttpResponse, HttpError> {
    let bad = |e: &dyn std::fmt::Display| HttpError::Protocol(format!("request: {e}"));
    let mut b = ::http::Request::builder()
        .method(req.method)
        .uri(format!("https://{}{}", req.host, req.path));
    for &(n, v) in req.headers {
        if !connection_specific(n) {
            b = b.header(n, v);
        }
    }
    let m = req.method;
    if !req.body.is_empty()
        || m.eq_ignore_ascii_case("POST")
        || m.eq_ignore_ascii_case("PUT")
        || m.eq_ignore_ascii_case("PATCH")
    {
        b = b.header("content-length", req.body.len());
    }
    let request = b.body(()).map_err(|e| bad(&e))?;
    let mut send = send.ready().await.map_err(h2_error)?;
    let end = req.body.is_empty();
    let (response, mut body_tx) = send.send_request(request, end).map_err(h2_error)?;
    if !end {
        body_tx
            .send_data(Bytes::copy_from_slice(req.body), true)
            .map_err(h2_error)?;
    }
    let response = response.await.map_err(h2_error)?;
    let (parts, mut body) = response.into_parts();
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let find = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    };
    if let Some(enc) = find("content-encoding") {
        if !enc.is_empty() && !enc.eq_ignore_ascii_case("identity") {
            return Err(HttpError::Unsupported(format!("content-encoding {enc}")));
        }
    }
    if let Some(n) = find("content-length").and_then(|v| v.parse::<u64>().ok()) {
        if n > req.max_body as u64 {
            return Err(HttpError::TooLarge);
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        if chunk.len() > req.max_body - out.len() {
            return Err(HttpError::TooLarge);
        }
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status: parts.status.as_u16(),
        headers,
        body: out,
    })
}

fn h2_error(e: h2::Error) -> HttpError {
    if e.is_io() {
        if let Some(io) = e.into_io() {
            return HttpError::Io(io);
        }
        return HttpError::Protocol("http2: i/o".into());
    }
    HttpError::Protocol(format!("http2: {e}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::testing::bounded as within;

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    fn post<'a>(max_body: usize) -> HttpRequest<'a> {
        HttpRequest {
            method: "POST",
            host: "h.test",
            path: "/a?b=1",
            headers: &[
                ("User-Agent", "UA/1"),
                ("Content-Type", "application/json"),
                ("Connection", "close"),
            ],
            body: b"{}",
            max_body,
            timeout: Duration::from_secs(5),
        }
    }

    /// What the server saw of the request, and the bytes the client wrote.
    struct Seen {
        request: ::http::Request<()>,
        body: Vec<u8>,
        wire: Arc<Mutex<Vec<u8>>>,
    }

    /// An h2 server answering one request with `status`, `headers` and
    /// `body` (in one DATA frame), behind a relay that records what the
    /// client wrote. Returns the client's end and the server's task.
    fn server(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: Vec<u8>,
    ) -> (DuplexStream, tokio::task::JoinHandle<Seen>) {
        let (client, relay_a) = tokio::io::duplex(1 << 20);
        let (relay_b, srv) = tokio::io::duplex(1 << 20);
        let wire = Arc::new(Mutex::new(Vec::new()));
        let (mut ra, mut wa) = tokio::io::split(relay_a);
        let (mut rb, mut wb) = tokio::io::split(relay_b);
        let rec = wire.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = ra.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                rec.lock().unwrap().extend_from_slice(&buf[..n]);
                if wb.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = wb.shutdown().await;
        });
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut rb, &mut wa).await;
        });
        let task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(srv).await.unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            let (parts, mut rx) = request.into_parts();
            let mut got = Vec::new();
            while let Some(d) = rx.data().await {
                let d = d.unwrap();
                let _ = rx.flow_control().release_capacity(d.len());
                got.extend_from_slice(&d);
            }
            let mut resp = ::http::Response::builder().status(status);
            for &(n, v) in headers {
                resp = resp.header(n, v);
            }
            let mut tx = respond
                .send_response(resp.body(()).unwrap(), body.is_empty())
                .unwrap();
            if !body.is_empty() {
                tx.send_data(Bytes::from(body), true).unwrap();
            }
            Seen {
                request: ::http::Request::from_parts(parts, ()),
                body: got,
                wire,
            }
        });
        (client, task)
    }

    /// The frames after the preface: (type, flags, stream, payload).
    fn frames(wire: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        assert!(wire.starts_with(PREFACE), "no client preface");
        let mut at = PREFACE.len();
        let mut out = Vec::new();
        while at + 9 <= wire.len() {
            let len = usize::from(wire[at]) << 16
                | usize::from(wire[at + 1]) << 8
                | usize::from(wire[at + 2]);
            if at + 9 + len > wire.len() {
                break;
            }
            let stream =
                u32::from_be_bytes([wire[at + 5], wire[at + 6], wire[at + 7], wire[at + 8]])
                    & 0x7fff_ffff;
            out.push((
                wire[at + 3],
                wire[at + 4],
                stream,
                wire[at + 9..at + 9 + len].to_vec(),
            ));
            at += 9 + len;
        }
        out
    }

    /// The names of a header block's first `n` fields, read just far
    /// enough (RFC 7541 section 6): static-table names only, which is all
    /// pseudo-headers are.
    fn first_names(block: &[u8], n: usize) -> Vec<&'static str> {
        const STATIC: [&str; 8] = [
            "?",
            ":authority",
            ":method",
            ":method",
            ":path",
            ":path",
            ":scheme",
            ":scheme",
        ];
        fn int(b: &[u8], at: &mut usize, prefix: u32) -> usize {
            let mask = (1usize << prefix) - 1;
            let mut v = usize::from(b[*at]) & mask;
            *at += 1;
            if v < mask {
                return v;
            }
            let mut shift = 0;
            loop {
                let x = b[*at];
                *at += 1;
                v += usize::from(x & 0x7f) << shift;
                shift += 7;
                if x & 0x80 == 0 {
                    return v;
                }
            }
        }
        fn skip(b: &[u8], at: &mut usize) {
            let len = int(b, at, 7);
            *at += len;
        }
        let name = |i: usize| STATIC.get(i).copied().unwrap_or("?");
        let mut at = 0;
        let mut out = Vec::new();
        while out.len() < n && at < block.len() {
            let x = block[at];
            if x & 0x80 != 0 {
                out.push(name(int(block, &mut at, 7)));
            } else if x & 0xe0 == 0x20 {
                int(block, &mut at, 5);
            } else {
                let i = int(block, &mut at, if x & 0x40 != 0 { 6 } else { 4 });
                if i == 0 {
                    skip(block, &mut at);
                }
                out.push(name(i));
                skip(block, &mut at);
            }
        }
        out
    }

    /// The preface Chrome sends: SETTINGS 1, 2, 4, 6 with its values, then
    /// the connection window, then HEADERS in its pseudo-header order; the
    /// request reaches the server as asked, without the headers HTTP/2
    /// forbids, and the reply comes back whole.
    #[tokio::test]
    async fn an_h2_request_opens_as_chromes_does() {
        within(async {
            let (io, srv) = server(
                200,
                &[("content-type", "application/json")],
                b"{\"ok\":1}".to_vec(),
            );
            let resp = request_h2(io, &post(100)).await.unwrap();
            assert_eq!(resp.status, 200);
            assert_eq!(resp.header("content-type"), Some("application/json"));
            assert_eq!(resp.body, b"{\"ok\":1}");
            let seen = srv.await.unwrap();
            assert_eq!(seen.request.method(), "POST");
            assert_eq!(seen.request.uri().authority().unwrap(), "h.test");
            assert_eq!(seen.request.uri().path_and_query().unwrap(), "/a?b=1");
            assert_eq!(seen.request.uri().scheme_str(), Some("https"));
            let h = seen.request.headers();
            assert_eq!(h["user-agent"], "UA/1");
            assert_eq!(h["content-length"], "2");
            assert!(!h.contains_key("connection") && !h.contains_key("host"));
            assert_eq!(seen.body, b"{}");

            let wire = seen.wire.lock().unwrap().clone();
            let f = frames(&wire);
            let (kind, _, stream, settings) = &f[0];
            assert_eq!((*kind, *stream), (4, 0), "SETTINGS first");
            let pairs: Vec<(u16, u32)> = settings
                .chunks(6)
                .map(|c| {
                    (
                        u16::from_be_bytes([c[0], c[1]]),
                        u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                    )
                })
                .collect();
            assert_eq!(pairs, [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)]);
            let (kind, _, stream, inc) = &f[1];
            assert_eq!((*kind, *stream), (8, 0), "WINDOW_UPDATE second");
            assert_eq!(
                u32::from_be_bytes([inc[0], inc[1], inc[2], inc[3]]),
                15_663_105
            );
            let headers = f
                .iter()
                .find(|(k, _, s, _)| *k == 1 && *s == 1)
                .expect("HEADERS on stream 1");
            assert_eq!(
                first_names(&headers.3, 4),
                [":method", ":authority", ":scheme", ":path"]
            );
        })
        .await;
    }

    /// A GET's HEADERS end its stream; a reply past `max_body` fails,
    /// whether its length is announced or not.
    #[tokio::test]
    async fn an_h2_reply_is_capped() {
        within(async {
            let mut get = post(100);
            get.method = "GET";
            get.body = b"";
            let (io, srv) = server(204, &[], Vec::new());
            assert_eq!(request_h2(io, &get).await.unwrap().status, 204);
            let seen = srv.await.unwrap();
            assert!(!seen.request.headers().contains_key("content-length"));
            let wire = seen.wire.lock().unwrap().clone();
            let headers = frames(&wire).into_iter().find(|f| f.0 == 1).unwrap();
            assert_eq!(headers.1 & 0x1, 0x1, "END_STREAM on a GET's HEADERS");

            let (io, _srv) = server(200, &[("content-length", "1000")], vec![b'x'; 1000]);
            assert!(matches!(
                request_h2(io, &post(100)).await,
                Err(HttpError::TooLarge)
            ));
            let (io, _srv) = server(200, &[], vec![b'x'; 1000]);
            assert!(matches!(
                request_h2(io, &post(100)).await,
                Err(HttpError::TooLarge)
            ));
            let (io, _srv) = server(200, &[("content-encoding", "gzip")], vec![b'x'; 10]);
            assert!(matches!(
                request_h2(io, &post(100)).await,
                Err(HttpError::Unsupported(_))
            ));
        })
        .await;
    }

    /// A plain `http://` URL is HTTP/1.1, as before.
    #[tokio::test]
    async fn a_plain_fetch_is_http_1_1() {
        within(async {
            let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = ln.local_addr().unwrap().port();
            let srv = tokio::spawn(async move {
                let (mut s, _) = ln.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
                String::from_utf8_lossy(&buf[..n]).into_owned()
            });
            let t = crate::stream::parse_url(&format!("http://127.0.0.1:{port}/p")).unwrap();
            let mut req = post(100);
            req.host = &t.authority;
            req.path = &t.path;
            let resp = fetch(&t, &req).await.unwrap();
            assert_eq!(resp.body, b"ok");
            assert!(srv.await.unwrap().starts_with("POST /p HTTP/1.1\r\n"));
        })
        .await;
    }
}

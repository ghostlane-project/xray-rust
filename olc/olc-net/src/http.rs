// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A minimal one-request HTTP/1.1 client over any async stream.
//!
//! One request is written with `Connection: close`, one response is read.
//! Bodies may be delimited by `Content-Length`, by chunked transfer coding or
//! by the end of the stream, and are capped by the caller. Every buffer is
//! bounded; the bound is stated in a doc comment next to it.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound on the response head (status line plus headers): 16 KiB.
const MAX_HEAD: usize = 16 * 1024;
/// Upper bound on one chunk-size line or trailer line: 4 KiB.
const MAX_LINE: usize = 4 * 1024;
/// Upper bound on all trailer bytes together: 16 KiB.
const MAX_TRAILERS: usize = 16 * 1024;
/// Size of the socket read buffer: 8 KiB.
const READ_CHUNK: usize = 8 * 1024;

/// Errors of the HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The transport failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The response was malformed.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The body would exceed `max_body`.
    #[error("response body too large")]
    TooLarge,
    /// The response uses a feature this client does not implement.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The call did not finish in time.
    #[error("timed out")]
    Timeout,
}

/// A request to send.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    /// Method, for example `GET` or `POST`.
    pub method: &'a str,
    /// Value of the `Host` header.
    pub host: &'a str,
    /// Request target: path plus query.
    pub path: &'a str,
    /// Extra headers, sent in this order after `Host`.
    pub headers: &'a [(&'a str, &'a str)],
    /// Request body; may be empty.
    pub body: &'a [u8],
    /// Largest response body accepted, in bytes.
    pub max_body: usize,
    /// Time allowed for the whole call.
    pub timeout: Duration,
}

/// A received response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Headers in arrival order.
    pub headers: Vec<(String, String)>,
    /// Decoded body (at most `max_body` bytes).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Returns the first header named `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn no_ctl(s: &str) -> Result<(), HttpError> {
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(HttpError::Protocol("control character in request".into()));
    }
    Ok(())
}

fn build_request(req: &HttpRequest<'_>) -> Result<Vec<u8>, HttpError> {
    no_ctl(req.method)?;
    no_ctl(req.host)?;
    no_ctl(req.path)?;
    let mut s = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        req.method, req.path, req.host
    );
    for &(n, v) in req.headers {
        no_ctl(n)?;
        no_ctl(v)?;
        s.push_str(&format!("{n}: {v}\r\n"));
    }
    let m = req.method;
    if !req.body.is_empty()
        || m.eq_ignore_ascii_case("POST")
        || m.eq_ignore_ascii_case("PUT")
        || m.eq_ignore_ascii_case("PATCH")
    {
        s.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    s.push_str("Connection: close\r\n\r\n");
    // Head plus the caller's body.
    let mut out = s.into_bytes();
    out.extend_from_slice(req.body);
    Ok(out)
}

/// A buffered reader over the stream.
struct Src<'a, S> {
    s: &'a mut S,
    /// Read buffer, at most `READ_CHUNK` bytes.
    buf: Vec<u8>,
    pos: usize,
}

impl<'a, S: AsyncRead + Unpin> Src<'a, S> {
    fn new(s: &'a mut S) -> Self {
        Self {
            s,
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Makes sure unread bytes are buffered; false at end of stream.
    async fn fill(&mut self) -> Result<bool, HttpError> {
        if self.pos < self.buf.len() {
            return Ok(true);
        }
        self.buf.clear();
        self.pos = 0;
        self.buf.resize(READ_CHUNK, 0);
        let n = self.s.read(&mut self.buf).await?;
        self.buf.truncate(n);
        Ok(n > 0)
    }

    async fn byte(&mut self) -> Result<Option<u8>, HttpError> {
        if !self.fill().await? {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    /// Returns up to `max` buffered bytes; empty at end of stream.
    async fn take(&mut self, max: usize) -> Result<&[u8], HttpError> {
        if max == 0 || !self.fill().await? {
            return Ok(&[]);
        }
        let n = max.min(self.buf.len() - self.pos);
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..start + n])
    }

    /// Reads one line without its line ending; at most `MAX_LINE` bytes.
    async fn line(&mut self) -> Result<Vec<u8>, HttpError> {
        let mut l = Vec::new();
        loop {
            match self.byte().await? {
                None => return Err(HttpError::Protocol("unexpected end of stream".into())),
                Some(b'\n') => {
                    if l.last() == Some(&b'\r') {
                        l.pop();
                    }
                    return Ok(l);
                }
                Some(b) => {
                    if l.len() >= MAX_LINE {
                        return Err(HttpError::Protocol("line too long".into()));
                    }
                    l.push(b);
                }
            }
        }
    }
}

type Head = (u16, Vec<(String, String)>);

/// Reads and parses the head; its raw text is at most `MAX_HEAD` bytes.
async fn read_head<S: AsyncRead + Unpin>(src: &mut Src<'_, S>) -> Result<Head, HttpError> {
    let mut raw: Vec<u8> = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        match src.byte().await? {
            None => return Err(HttpError::Protocol("stream ended inside the head".into())),
            Some(b) => raw.push(b),
        }
        if raw.len() > MAX_HEAD {
            return Err(HttpError::Protocol("response head too large".into()));
        }
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| HttpError::Protocol("response head is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Protocol(format!(
            "bad status line: {status_line}"
        )));
    }
    let status: u16 = parts
        .next()
        .and_then(|c| if c.len() == 3 { c.parse().ok() } else { None })
        .ok_or_else(|| HttpError::Protocol(format!("bad status line: {status_line}")))?;
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let (n, v) = l
            .split_once(':')
            .ok_or_else(|| HttpError::Protocol(format!("bad header line: {l}")))?;
        headers.push((n.trim().to_string(), v.trim().to_string()));
    }
    Ok((status, headers))
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

async fn read_exact_body<S: AsyncRead + Unpin>(
    src: &mut Src<'_, S>,
    mut remaining: usize,
    body: &mut Vec<u8>,
) -> Result<(), HttpError> {
    while remaining > 0 {
        let got = src.take(remaining).await?;
        if got.is_empty() {
            return Err(HttpError::Protocol("body truncated".into()));
        }
        remaining -= got.len();
        body.extend_from_slice(got);
    }
    Ok(())
}

async fn read_chunked<S: AsyncRead + Unpin>(
    src: &mut Src<'_, S>,
    max_body: usize,
) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    loop {
        let line = src.line().await?;
        let text =
            std::str::from_utf8(&line).map_err(|_| HttpError::Protocol("bad chunk size".into()))?;
        let size_str = text.split(';').next().unwrap_or("").trim();
        if size_str.is_empty() || size_str.len() > 16 {
            return Err(HttpError::Protocol("bad chunk size".into()));
        }
        let size = u64::from_str_radix(size_str, 16)
            .map_err(|_| HttpError::Protocol("bad chunk size".into()))?;
        if size == 0 {
            let mut total = 0usize;
            loop {
                let t = src.line().await?;
                if t.is_empty() {
                    return Ok(body);
                }
                total += t.len() + 2;
                if total > MAX_TRAILERS {
                    return Err(HttpError::Protocol("trailers too large".into()));
                }
            }
        }
        if (body.len() as u64).saturating_add(size) > max_body as u64 {
            return Err(HttpError::TooLarge);
        }
        read_exact_body(src, size as usize, &mut body).await?;
        if !src.line().await?.is_empty() {
            return Err(HttpError::Protocol("missing chunk terminator".into()));
        }
    }
}

async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    method: &str,
    max_body: usize,
) -> Result<HttpResponse, HttpError> {
    let mut src = Src::new(stream);
    let (status, headers) = read_head(&mut src).await?;
    if let Some(enc) = find(&headers, "content-encoding") {
        let enc = enc.trim();
        if !enc.is_empty() && !enc.eq_ignore_ascii_case("identity") {
            return Err(HttpError::Unsupported(format!("content-encoding {enc}")));
        }
    }
    let bodiless = method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304;
    let chunked = find(&headers, "transfer-encoding").is_some_and(|v| {
        v.split(',')
            .next_back()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("chunked"))
    });
    // Grows only as bytes arrive; capacity at most twice `max_body`.
    let body = if bodiless {
        Vec::new()
    } else if chunked {
        read_chunked(&mut src, max_body).await?
    } else if let Some(cl) = find(&headers, "content-length") {
        let n: u64 = cl
            .trim()
            .parse()
            .map_err(|_| HttpError::Protocol("bad Content-Length".into()))?;
        if n > max_body as u64 {
            return Err(HttpError::TooLarge);
        }
        let mut body = Vec::new();
        read_exact_body(&mut src, n as usize, &mut body).await?;
        body
    } else {
        let mut body = Vec::new();
        loop {
            let allowed = max_body - body.len();
            let got = src.take(allowed.saturating_add(1)).await?;
            if got.is_empty() {
                break body;
            }
            if got.len() > allowed {
                return Err(HttpError::TooLarge);
            }
            body.extend_from_slice(got);
        }
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Sends `req` on `stream` and reads one response. The whole call is bounded
/// by `req.timeout`.
pub async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    req: &HttpRequest<'_>,
) -> Result<HttpResponse, HttpError> {
    let bytes = build_request(req)?;
    let work = async {
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        read_response(stream, req.method, req.max_body).await
    };
    match tokio::time::timeout(req.timeout, work).await {
        Ok(r) => r,
        Err(_) => Err(HttpError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn req<'a>(max_body: usize) -> HttpRequest<'a> {
        HttpRequest {
            method: "GET",
            host: "h.test",
            path: "/p",
            headers: &[],
            body: b"",
            max_body,
            timeout: Duration::from_secs(5),
        }
    }

    /// Fake server: reads `expect_len` request bytes, writes `response`,
    /// then (unless `hold`) closes. Returns the request bytes.
    async fn serve(
        mut server: DuplexStream,
        expect_len: usize,
        response: Vec<u8>,
        hold: bool,
    ) -> Vec<u8> {
        let mut got = vec![0u8; expect_len];
        server.read_exact(&mut got).await.unwrap();
        server.write_all(&response).await.unwrap();
        if hold {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        got
    }

    async fn call(
        r: HttpRequest<'_>,
        expect_len: usize,
        response: &[u8],
    ) -> (Result<HttpResponse, HttpError>, Vec<u8>) {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(serve(server, expect_len, response.to_vec(), false));
        let res = request(&mut client, &r).await;
        (res, task.await.unwrap())
    }

    const GET_LEN: usize = "GET /p HTTP/1.1\r\nHost: h.test\r\nConnection: close\r\n\r\n".len();

    async fn within<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test timed out")
    }

    #[tokio::test]
    async fn exact_request_bytes() {
        within(async {
            let r = HttpRequest {
                method: "POST",
                host: "h.test",
                path: "/a?b=1",
                headers: &[("Accept", "*/*"), ("X-A", "1")],
                body: b"{}",
                max_body: 100,
                timeout: Duration::from_secs(5),
            };
            let expected = "POST /a?b=1 HTTP/1.1\r\nHost: h.test\r\nAccept: */*\r\nX-A: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            let (res, got) = call(r, expected.len(), b"HTTP/1.1 204 No Content\r\n\r\n").await;
            assert_eq!(String::from_utf8(got).unwrap(), expected);
            assert_eq!(res.unwrap().status, 204);

            let (res, got) = call(req(10), GET_LEN, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
            assert_eq!(
                String::from_utf8(got).unwrap(),
                "GET /p HTTP/1.1\r\nHost: h.test\r\nConnection: close\r\n\r\n"
            );
            res.unwrap();

            // An empty POST still announces its length.
            let mut r = req(10);
            r.method = "POST";
            let expected = "POST /p HTTP/1.1\r\nHost: h.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let (res, got) = call(r, expected.len(), b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
            assert_eq!(String::from_utf8(got).unwrap(), expected);
            res.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn content_length_body_and_headers() {
        within(async {
            let (res, _) = call(
                req(100),
                GET_LEN,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhelloEXTRA",
            )
            .await;
            let r = res.unwrap();
            assert_eq!(r.status, 200);
            assert_eq!(r.body, b"hello");
            assert_eq!(r.header("content-TYPE"), Some("text/plain"));
            assert_eq!(r.header("missing"), None);
        })
        .await;
    }

    #[tokio::test]
    async fn chunked_with_extensions_and_trailers() {
        within(async {
            let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\nA\r\n, world!!!\r\n0\r\nX-Trailer: 1\r\nY: 2\r\n\r\n";
            let (res, _) = call(req(100), GET_LEN, resp).await;
            assert_eq!(res.unwrap().body, b"hello, world!!!");
        })
        .await;
    }

    #[tokio::test]
    async fn eof_delimited_body() {
        within(async {
            let (res, _) = call(req(100), GET_LEN, b"HTTP/1.0 200 OK\r\n\r\nuntil the end").await;
            assert_eq!(res.unwrap().body, b"until the end");
        })
        .await;
    }

    #[tokio::test]
    async fn body_cap_is_enforced_in_every_mode() {
        within(async {
            let (res, _) = call(req(4), GET_LEN, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
            assert!(matches!(res, Err(HttpError::TooLarge)));
            let (res, _) = call(
                req(4),
                GET_LEN,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            )
            .await;
            assert!(matches!(res, Err(HttpError::TooLarge)));
            let (res, _) = call(req(4), GET_LEN, b"HTTP/1.1 200 OK\r\n\r\nhello").await;
            assert!(matches!(res, Err(HttpError::TooLarge)));
            // Exactly at the cap is accepted.
            let (res, _) = call(req(5), GET_LEN, b"HTTP/1.1 200 OK\r\n\r\nhello").await;
            assert_eq!(res.unwrap().body, b"hello");
        })
        .await;
    }

    #[tokio::test]
    async fn unsupported_content_encoding() {
        within(async {
            let (res, _) = call(
                req(100),
                GET_LEN,
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            assert!(matches!(res, Err(HttpError::Unsupported(_))));
            let (res, _) = call(
                req(100),
                GET_LEN,
                b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 1\r\n\r\nx",
            )
            .await;
            assert_eq!(res.unwrap().body, b"x");
        })
        .await;
    }

    #[tokio::test]
    async fn malformed_responses() {
        within(async {
            let big_head = {
                let mut v = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
                v.extend(std::iter::repeat_n(b'a', 20_000));
                v
            };
            let cases: Vec<(&str, Vec<u8>)> = vec![
                (
                    "truncated body",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec(),
                ),
                ("bad status", b"NOPE\r\n\r\n".to_vec()),
                (
                    "bad length",
                    b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n".to_vec(),
                ),
                (
                    "bad chunk",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec(),
                ),
                ("head too large", big_head),
                ("ended in head", b"HTTP/1.1 200 OK\r\nX: y".to_vec()),
            ];
            for (name, resp) in cases {
                let (res, _) = call(req(100), GET_LEN, &resp).await;
                match res {
                    Err(HttpError::Protocol(_)) => {}
                    other => panic!("case {name}: unexpected {other:?}"),
                }
            }
        })
        .await;
    }

    #[tokio::test]
    async fn no_body_for_head_and_204() {
        within(async {
            let mut r = req(100);
            r.method = "HEAD";
            let expected_len =
                "HEAD /p HTTP/1.1\r\nHost: h.test\r\nConnection: close\r\n\r\n".len();
            let (res, _) = call(
                r,
                expected_len,
                b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n",
            )
            .await;
            assert!(res.unwrap().body.is_empty());
        })
        .await;
    }

    #[tokio::test]
    async fn times_out_when_server_is_silent() {
        within(async {
            let (mut client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(serve(server, GET_LEN, Vec::new(), true));
            let mut r = req(100);
            r.timeout = Duration::from_millis(50);
            let res = request(&mut client, &r).await;
            assert!(matches!(res, Err(HttpError::Timeout)));
            task.abort();
        })
        .await;
    }
}

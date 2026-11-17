// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A loopback HTTP server for the tests: it keeps every request as it
//! was written and answers with what the test's closure returns. One
//! request per connection, as `olc_net` sends them.
//!
//! It speaks HTTP/1.1, or HTTP/2 behind an `https://` base ([`Proto`]).
//! There is no TLS in either: [`fake_tls`] installs a connector that hands
//! the TCP stream back as it is and says which protocol "the TLS picked",
//! by the port dialed. What a call sends on h2 is then seen without a
//! certificate.

use std::future::Future;
use std::sync::{Arc, Mutex, Once};
use std::thread::ThreadId;
use std::time::Duration;

use olc_net::stream::{self, Dialed, Offer, TlsFuture};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How a [`Stub`] is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proto {
    /// `http://`: HTTP/1.1 on plain TCP.
    Plain,
    /// `https://` whose TLS picked `http/1.1`.
    TlsHttp1,
    /// `https://` whose TLS picked `h2`.
    TlsH2,
}

/// The ports whose "TLS" picks `h2`.
static H2_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// Installs, once for the test binary, a TLS connector that is no TLS: the
/// stream as it is, `h2` for a fetch to a port in [`H2_PORTS`].
fn fake_tls() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        stream::set_tls_connector(Some(Arc::new(
            |tcp: TcpStream, _host: String, offer: Offer| -> TlsFuture {
                Box::pin(async move {
                    let port = tcp.peer_addr()?.port();
                    let h2 = offer == Offer::Fetch && H2_PORTS.lock().unwrap().contains(&port);
                    Ok(Dialed {
                        stream: Box::new(tcp),
                        h2,
                    })
                })
            },
        )));
    });
}

/// A request as the server read it.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: String,
    /// The path and the query.
    pub(crate) target: String,
    /// The header lines in wire order.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What the server answers.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    status: u16,
    /// Header lines, written as given.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    pub(crate) fn new(status: u16, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.as_ref().to_vec(),
        }
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// The server. It stops when dropped.
pub(crate) struct Stub {
    /// `http://127.0.0.1:<port>`.
    pub(crate) base: String,
    /// The `Host` a request to it carries.
    pub(crate) host: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: JoinHandle<()>,
}

async fn read_request(s: &mut TcpStream) -> Option<Seen> {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let n = s.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        got.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8(got[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = got[head_end + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Some(Seen {
        method,
        target,
        headers,
        body,
    })
}

async fn write_reply(s: &mut TcpStream, reply: &Reply) {
    let mut head = format!("HTTP/1.1 {} Status\r\n", reply.status);
    for (n, v) in &reply.headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    if reply.status != 204 {
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let _ = s.write_all(head.as_bytes()).await;
    if reply.status != 204 {
        let _ = s.write_all(&reply.body).await;
    }
    let _ = s.shutdown().await;
}

/// One HTTP/2 connection: its first request, kept and answered. The header
/// names are HTTP/2's (lower case).
async fn serve_h2<F>(s: TcpStream, seen: &Mutex<Vec<Seen>>, answer: &F)
where
    F: Fn(&Seen) -> Reply,
{
    let Ok(mut conn) = h2::server::handshake(s).await else {
        return;
    };
    let Some(Ok((request, mut respond))) = conn.accept().await else {
        return;
    };
    // The connection is driven while the body is read and the reply goes.
    let drive = tokio::spawn(async move { while conn.accept().await.is_some() {} });
    let (parts, mut rx) = request.into_parts();
    let mut body = Vec::new();
    while let Some(Ok(chunk)) = rx.data().await {
        let _ = rx.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    let req = Seen {
        method: parts.method.to_string(),
        target: parts
            .uri
            .path_and_query()
            .map_or_else(String::new, |t| t.as_str().to_owned()),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body,
    };
    let reply = answer(&req);
    seen.lock().unwrap().push(req);
    let mut head = http::Response::builder().status(reply.status);
    for (n, v) in &reply.headers {
        head = head.header(n.as_str(), v.as_str());
    }
    let empty = reply.status == 204 || reply.body.is_empty();
    if let Ok(mut tx) = respond.send_response(head.body(()).unwrap(), empty) {
        if !empty {
            let _ = tx.send_data(bytes::Bytes::from(reply.body), true);
        }
    }
    // The reply is on its way once the client ends the connection.
    let _ = drive.await;
}

impl Stub {
    pub(crate) async fn start<F>(answer: F) -> Self
    where
        F: Fn(&Seen) -> Reply + Send + Sync + 'static,
    {
        Self::start_as(Proto::Plain, answer).await
    }

    /// A server reached in `proto`.
    pub(crate) async fn start_as<F>(proto: Proto, answer: F) -> Self
    where
        F: Fn(&Seen) -> Reply + Send + Sync + 'static,
    {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let host = addr.to_string();
        let scheme = if proto == Proto::Plain {
            "http"
        } else {
            fake_tls();
            "https"
        };
        {
            // A port the kernel hands out again is what this server makes it.
            let mut h2 = H2_PORTS.lock().unwrap();
            h2.retain(|&port| port != addr.port());
            if proto == Proto::TlsH2 {
                h2.push(addr.port());
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let theirs = seen.clone();
        let answer = Arc::new(answer);
        let task = tokio::spawn(async move {
            while let Ok((mut s, _)) = ln.accept().await {
                let (seen, answer) = (theirs.clone(), answer.clone());
                tokio::spawn(async move {
                    if proto == Proto::TlsH2 {
                        serve_h2(s, &seen, &*answer).await;
                        return;
                    }
                    let Some(req) = read_request(&mut s).await else {
                        return;
                    };
                    let reply = answer(&req);
                    seen.lock().unwrap().push(req);
                    write_reply(&mut s, &reply).await;
                });
            }
        });
        Self {
            base: format!("{scheme}://{host}"),
            host,
            seen,
            task,
        }
    }

    /// Every request so far, in order.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A loopback port nothing listens on.
pub(crate) async fn closed_port() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    ln.local_addr().unwrap().port()
}

/// `f`, or a failed test when it has not ended in 20 s.
pub(crate) async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), f)
        .await
        .expect("the call did not end in 20 s")
}

/// The log lines of the test binary, each with the thread that wrote it.
static LINES: Mutex<Vec<(ThreadId, String)>> = Mutex::new(Vec::new());

/// Takes the engine's log for the test binary, debug lines included, and
/// returns a reader of the lines this thread writes from now on. A test on
/// a current-thread runtime (`#[tokio::test]`'s default) runs every task of
/// its own on its thread, so what it reads is its own, whatever the other
/// tests log meanwhile.
pub(crate) fn log_lines() -> LogLines {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        olc_net::log::set_verbose(true);
        olc_net::log::set_sink(Some(Arc::new(|line: &str| {
            LINES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((std::thread::current().id(), line.to_owned()));
        })));
    });
    let from = LINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    LogLines {
        thread: std::thread::current().id(),
        from,
    }
}

/// The lines one test's thread logged since [`log_lines`].
pub(crate) struct LogLines {
    thread: ThreadId,
    from: usize,
}

impl LogLines {
    /// The lines so far, without their stamps.
    pub(crate) fn read(&self) -> Vec<String> {
        LINES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[self.from..]
            .iter()
            .filter(|(thread, _)| *thread == self.thread)
            // `2006/01/02 15:04:05 `: twenty bytes.
            .map(|(_, line)| line.get(20..).unwrap_or(line).to_owned())
            .collect()
    }

    /// The lines so far that start with `head`.
    pub(crate) fn starting(&self, head: &str) -> Vec<String> {
        self.read()
            .into_iter()
            .filter(|line| line.starts_with(head))
            .collect()
    }
}

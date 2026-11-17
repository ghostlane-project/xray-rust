// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The signalling's TLS (`shaped_tls`, Chrome's hello over shaped-rustls)
//! against a server that accepts ALPS (application_settings) for `h2` as
//! Google's front ends do: BoringSSL, in this process, on loopback. Nothing
//! leaves 127.0.0.1.
//!
//! A `fetch` offers ALPS for `h2`; the server accepts it and then waits for
//! the client's own ALPS in the client's EncryptedExtensions, before its
//! Finished. Without it the server ends the connection with
//! `unexpected_message` as soon as the client speaks (www.google.com did
//! the same), so an h2 request is the test. A WebSocket's connection offers
//! `http/1.1` alone and, as Chrome's, no ALPS.
//!
//! BoringSSL needs cmake and libclang to build, so this is behind the
//! `alps-test-server` feature and runs on a GitHub runner (ghostlane
//! lab/olc-alps): `cargo test -p olc-net --features alps-test-server --test
//! alps_fetch`.
//!
//! Memory: a ClientHello is read whole up to MAX_HELLO bytes; the server
//! buffers at most MAX_H2 bytes of a connection's HTTP/2 and MAX_HEAD of an
//! HTTP/1.1 request head; every socket times out after IO_TIMEOUT and every
//! test is bounded by LIMIT.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::asn1::Asn1Time;
use boring::bn::{BigNum, MsbOption};
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::ssl::{
    select_next_proto, AlpnError, Ssl, SslContext, SslContextBuilder, SslMethod, SslRef, SslVersion,
};
use boring::x509::{X509Builder, X509NameBuilder, X509};
use foreign_types::ForeignTypeRef;
use olc_net::fetch::request_h2;
use olc_net::http::HttpRequest;
use olc_net::shaped_tls::{client_config, FINGERPRINT};
use olc_net::stream::Offer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_transport::{BoxedTransportStream, TlsConnector};

/// What Chrome sends as its own ALPS for `h2`, in its EncryptedExtensions,
/// to a BoringSSL server that accepted ALPS: nothing. Chrome 157.0.8103.50,
/// six connections (page loads and a `fetch()`), each the same (ghostlane
/// lab/olc-alps, run 43651119103).
const CHROME_CLIENT_ALPS: &[u8] = &[];

/// The codepoint Chrome 157 offers ALPS at (BoringSSL's newer one).
const ALPS_NEW: u16 = 0x44cd;
const ALPS_OLD: u16 = 0x4469;

const NAME: &str = "alps.test";
const LIMIT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HELLO: usize = 64 * 1024;
const MAX_H2: usize = 64 * 1024;
const MAX_HEAD: usize = 8 * 1024;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The server's ALPS for `h2`, as Google's carry: an HTTP/2 SETTINGS frame
/// (MAX_CONCURRENT_STREAMS = 100).
const SERVER_ALPS: &[u8] = &[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100];

/// What the server saw of one connection.
#[derive(Debug, Default)]
struct Seen {
    /// The ALPS extension of the ClientHello: its codepoint and protocols.
    alps_offered: Option<(u16, Vec<Vec<u8>>)>,
    handshake: Option<String>,
    alpn: Option<Vec<u8>>,
    alps_negotiated: bool,
    /// The client's ALPS (its EncryptedExtensions'), when negotiated.
    client_alps: Vec<u8>,
    h2_requests: usize,
    http1_head: Vec<u8>,
}

/// A stream that first replays the bytes already read from it.
#[derive(Debug)]
struct Replay {
    head: Vec<u8>,
    at: usize,
    inner: TcpStream,
}

impl Read for Replay {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at < self.head.len() {
            let n = buf.len().min(self.head.len() - self.at);
            buf[..n].copy_from_slice(&self.head[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl Write for Replay {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn certificate() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(serial.to_asn1_integer().unwrap().as_ref())
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let at = |secs: u64| libc::time_t::try_from(secs).unwrap_or(libc::time_t::MAX);
    let not_before: Asn1Time = Asn1Time::from_unix(at(now.saturating_sub(86_400))).unwrap();
    let not_after: Asn1Time = Asn1Time::from_unix(at(now + 86_400)).unwrap();
    b.set_not_before(&not_before).unwrap();
    b.set_not_after(&not_after).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", NAME).unwrap();
    let name = name.build();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

/// TLS 1.3 alone, ALPN `h2` then `http/1.1` by the server's preference.
fn context() -> SslContext {
    let (cert, key) = certificate();
    let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    ctx.set_certificate(&cert).unwrap();
    ctx.set_private_key(&key).unwrap();
    ctx.set_alpn_select_callback(|_, client| {
        select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    ctx.build()
}

/// The TLS records up to the end of the first handshake message.
fn read_client_hello(tcp: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut msg = Vec::new();
    loop {
        let mut header = [0u8; 5];
        tcp.read_exact(&mut header)?;
        if header[0] != 22 {
            return Err(io::Error::other("not a handshake record"));
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if raw.len() + 5 + len > MAX_HELLO {
            return Err(io::Error::other("ClientHello over the bound"));
        }
        let mut body = vec![0u8; len];
        tcp.read_exact(&mut body)?;
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&body);
        msg.extend_from_slice(&body);
        if msg.len() >= 4 {
            let want = 4
                + ((usize::from(msg[1]) << 16) | (usize::from(msg[2]) << 8) | usize::from(msg[3]));
            if msg.len() >= want {
                msg.truncate(want);
                return Ok((raw, msg));
            }
        }
    }
}

/// u16-prefixed u8-prefixed names (ALPN's and ALPS's lists).
fn names(list: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if list.len() < 2 {
        return out;
    }
    let end = (2 + usize::from(u16::from_be_bytes([list[0], list[1]]))).min(list.len());
    let mut i = 2;
    while i < end {
        let n = usize::from(list[i]);
        if i + 1 + n > end {
            break;
        }
        out.push(list[i + 1..i + 1 + n].to_vec());
        i += 1 + n;
    }
    out
}

/// The ALPS extension of a ClientHello message.
fn alps_offered(msg: &[u8]) -> Option<(u16, Vec<Vec<u8>>)> {
    let get = |at: usize, n: usize| msg.get(at..at + n);
    let mut at = 4 + 2 + 32;
    let &[sid] = get(at, 1)? else { return None };
    at += 1 + usize::from(sid);
    let &[a, b] = get(at, 2)? else { return None };
    at += 2 + usize::from(u16::from_be_bytes([a, b]));
    let &[c] = get(at, 1)? else { return None };
    at += 1 + usize::from(c);
    let &[a, b] = get(at, 2)? else { return None };
    let end = (at + 2 + usize::from(u16::from_be_bytes([a, b]))).min(msg.len());
    at += 2;
    while at + 4 <= end {
        let kind = u16::from_be_bytes([msg[at], msg[at + 1]]);
        let len = usize::from(u16::from_be_bytes([msg[at + 2], msg[at + 3]]));
        let body = msg.get(at + 4..at + 4 + len)?;
        if kind == ALPS_NEW || kind == ALPS_OLD {
            return Some((kind, names(body)));
        }
        at += 4 + len;
    }
    None
}

/// (negotiated, the client's ALPS) of a finished handshake.
fn negotiated_alps(ssl: &SslRef) -> (bool, Vec<u8>) {
    // SAFETY: the SSL is live for the call; the client's settings belong to
    // it and are copied out at once.
    unsafe {
        let p = ssl.as_ptr();
        let has = boring_sys::SSL_has_application_settings(p) == 1;
        let mut data: *const u8 = std::ptr::null();
        let mut len: usize = 0;
        boring_sys::SSL_get0_peer_application_settings(p, &mut data, &mut len);
        let bytes = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        (has, bytes)
    }
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Enough HTTP/2 for one request: the server's SETTINGS, ACKs, and `200`
/// with `ok` to each request. Returns the number of requests answered.
fn serve_h2<S: Read + Write>(s: &mut S) -> usize {
    let mut buf = Vec::new();
    let mut answered = 0;
    let mut preface = false;
    if s.write_all(&frame(4, 0, 0, &[])).is_err() {
        return 0;
    }
    let mut chunk = [0u8; 4096];
    loop {
        let n = match s.read(&mut chunk) {
            Ok(0) | Err(_) => return answered,
            Ok(n) => n,
        };
        if buf.len() + n > MAX_H2 {
            return answered;
        }
        buf.extend_from_slice(&chunk[..n]);
        if !preface {
            if buf.len() < H2_PREFACE.len() {
                continue;
            }
            if &buf[..H2_PREFACE.len()] != H2_PREFACE {
                return answered;
            }
            buf.drain(..H2_PREFACE.len());
            preface = true;
        }
        while buf.len() >= 9 {
            let len =
                (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (kind, flags) = (buf[3], buf[4]);
            let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            let payload = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);
            let reply = match kind {
                4 if flags & 1 == 0 => frame(4, 1, 0, &[]),
                6 if flags & 1 == 0 => frame(6, 1, 0, &payload),
                1 | 9 if flags & 4 != 0 && stream != 0 => {
                    answered += 1;
                    let mut r = frame(1, 4, stream, &[0x88]); // :status 200
                    r.extend(frame(0, 1, stream, b"ok\n"));
                    r
                }
                7 => return answered,
                _ => continue,
            };
            if s.write_all(&reply).is_err() {
                return answered;
            }
        }
    }
}

/// One HTTP/1.1 request head, answered with `200` and `ok`.
fn serve_http1<S: Read + Write>(s: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while head.len() < MAX_HEAD && !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&chunk[..n.min(MAX_HEAD - head.len())]),
        }
    }
    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n");
    head
}

fn handle(ctx: &SslContext, mut tcp: TcpStream) -> Seen {
    let mut seen = Seen::default();
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    let (raw, msg) = match read_client_hello(&mut tcp) {
        Ok(hello) => hello,
        Err(e) => {
            seen.handshake = Some(format!("no ClientHello: {e}"));
            return seen;
        }
    };
    seen.alps_offered = alps_offered(&msg);
    // Answer at the codepoint offered, as a server does.
    let use_new = seen
        .alps_offered
        .as_ref()
        .is_none_or(|(codepoint, _)| *codepoint == ALPS_NEW);
    let ssl = Ssl::new(ctx).unwrap();
    // SAFETY: the SSL is live and not in a handshake yet; BoringSSL copies
    // the protocol and the settings.
    let added = unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), i32::from(use_new));
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            SERVER_ALPS.as_ptr(),
            SERVER_ALPS.len(),
        )
    };
    assert_eq!(added, 1, "SSL_add_application_settings");
    let stream = Replay {
        head: raw,
        at: 0,
        inner: tcp,
    };
    let mut tls = match ssl.accept(stream) {
        Ok(tls) => tls,
        Err(e) => {
            seen.handshake = Some(format!("{e}"));
            return seen;
        }
    };
    seen.handshake = Some("ok".to_owned());
    seen.alpn = tls.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
    (seen.alps_negotiated, seen.client_alps) = negotiated_alps(tls.ssl());
    if seen.alpn.as_deref() == Some(b"h2") {
        seen.h2_requests = serve_h2(&mut tls);
    } else {
        seen.http1_head = serve_http1(&mut tls);
    }
    let _ = tls.shutdown();
    seen
}

/// A BoringSSL server on a fresh loopback port for one connection; what it
/// saw arrives on the channel once the connection ends.
fn serve_one() -> (u16, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let ctx = context();
        let deadline = Instant::now() + LIMIT;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((tcp, _)) => {
                    let _ = tcp.set_nonblocking(false);
                    let _ = tx.send(handle(&ctx, tcp));
                    return;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    (port, rx)
}

/// The signalling's own dial (`shaped_tls::install`'s): Chrome's hello for
/// `offer`. The server's certificate is made by the test, so the check is
/// off; nothing else differs.
async fn dial(port: u16, offer: Offer) -> (BoxedTransportStream, Option<Vec<u8>>) {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut cfg = client_config(NAME.to_owned(), offer, FINGERPRINT);
    cfg.allow_insecure = true;
    TlsConnector::system()
        .unwrap()
        .connect_stream_with_alpn(Box::new(tcp), &cfg)
        .await
        .unwrap()
}

fn seen(rx: &mpsc::Receiver<Seen>) -> Seen {
    rx.recv_timeout(LIMIT)
        .expect("the server saw no connection")
}

#[tokio::test]
async fn a_fetch_answers_a_server_that_accepts_alps_as_chrome_answers() {
    tokio::time::timeout(LIMIT, async {
        let (port, rx) = serve_one();
        let (stream, alpn) = dial(port, Offer::Fetch).await;
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]));
        let authority = format!("{NAME}:{port}");
        let req = HttpRequest {
            method: "GET",
            host: &authority,
            path: "/",
            headers: &[],
            body: b"",
            max_body: 1024,
            timeout: IO_TIMEOUT,
        };
        let resp = request_h2(stream, &req).await.expect("an h2 request");
        assert_eq!((resp.status, resp.body.as_slice()), (200, &b"ok\n"[..]));

        let seen = seen(&rx);
        assert_eq!(seen.handshake.as_deref(), Some("ok"));
        assert_eq!(seen.alps_offered, Some((ALPS_NEW, vec![b"h2".to_vec()])));
        assert!(seen.alps_negotiated, "the server did not negotiate ALPS");
        assert_eq!(seen.client_alps, CHROME_CLIENT_ALPS);
        assert_eq!(seen.h2_requests, 1);
    })
    .await
    .expect("within the limit");
}

#[tokio::test]
async fn a_websocket_connection_offers_no_alps_as_chrome_offers_none() {
    tokio::time::timeout(LIMIT, async {
        let (port, rx) = serve_one();
        let (mut stream, alpn) = dial(port, Offer::WebSocket).await;
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]));
        let head = format!("GET /ws HTTP/1.1\r\nHost: {NAME}:{port}\r\nConnection: close\r\n\r\n");
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut reply = vec![0u8; 512];
        let n = stream.read(&mut reply).await.unwrap();
        assert!(reply[..n].starts_with(b"HTTP/1.1 200 OK\r\n"));

        let seen = seen(&rx);
        assert_eq!(seen.handshake.as_deref(), Some("ok"));
        assert_eq!(
            seen.alps_offered, None,
            "Chrome's WebSocket hello has no ALPS"
        );
        assert!(!seen.alps_negotiated);
        assert!(seen.http1_head.starts_with(b"GET /ws HTTP/1.1\r\n"));
    })
    .await
    .expect("within the limit");
}

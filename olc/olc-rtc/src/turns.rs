// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! TURN over TLS (`turns:`, RFC 7350): one TURN server's TLS connection.
//!
//! TURN over TLS frames STUN and ChannelData exactly as over TCP
//! ([`crate::turn::stream`]'s framing, `TurnClientTcp` the client), inside a
//! TLS connection whose hello is Chrome 157's ([`crate::tls_boring`]). This
//! task is the TCP task with BoringSSL between the queue and the socket,
//! driven over memory buffers (the pattern of [`crate::dtls_boring`]); there
//! is no tokio-boring.
//!
//! One task owns the connection and one state machine: a TCP read of at most
//! [`STREAM_READ`] bytes is fed to BoringSSL and what it decrypts goes to the
//! driver in chunks of at most [`STREAM_READ`] (waiting for the driver, so a
//! slow driver slows the server through TCP); a datagram from the queue is
//! encrypted into a buffer of [`TLS_OUT_MAX`] and written to the socket as it
//! drains, never blocking the reads. Neither a read nor a write of the socket
//! waits on the other.
//!
//! # Memory, per connection
//!
//! Ours: the read buffer and the plaintext buffer ([`STREAM_READ`] each), the
//! ciphertext waiting to be fed ([`STREAM_READ`]) and to be sent
//! ([`TLS_OUT_MAX`]), one datagram held while the handshake runs
//! ([`crate::turn::SEND_BUF`]); and the queue the driver fills
//! ([`crate::turn::STREAM_QUEUE`]). BoringSSL's: its connection state, a
//! record's read and write buffers, and a certificate chain of at most
//! [`TLS_MAX_CERT_LIST`] while the handshake runs (Chrome's is 100 KiB; no
//! real chain is near this one). The tests measure the whole connection on
//! the C heap beside a plain TCP one; the numbers are in the lab's report and
//! `olc-client`'s `sizes.rs` row.
//!
//! # Certificates
//!
//! BoringSSL's custom verify callback calls
//! [`crate::turns_verify::verify_server_chain`] (rustls-webpki, webpki-roots)
//! with the URL's host: a DNS name is checked against the certificate's
//! names and sent as SNI; an IP literal is checked against its address names
//! and sent as no SNI. A chain that fails ends this relay (the others go
//! on).
//!
//! # Resumption
//!
//! As Chrome's client session cache does: the sessions a server gives are
//! kept, at most one per server (`host:port`) and [`TICKET_SERVERS`]
//! servers, each at most [`TICKET_MAX_DER`] bytes serialised; the next
//! connection to that server offers it, so its hello carries
//! `pre_shared_key`. A TLS 1.3 ticket is single use, as Chrome treats it: it
//! leaves the cache when offered.

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use boring::ssl::{
    ErrorCode, HandshakeError, MidHandshakeSslStream, SslAlert, SslContext, SslRef, SslSession,
    SslStream, SslVerifyError, SslVerifyMode,
};
use foreign_types::ForeignTypeRef;
use rustls_pki_types::{ServerName, TrustAnchor, UnixTime};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::turn::{
    StreamChunk, MAX_ALLOCATIONS, SEND_BUF, STREAM_READ, STREAM_SNDBUF, STREAM_WRITE_STALL,
};
use crate::turns_verify::{shipped_extra_roots, verify_server_chain};

/// The ciphertext waiting for the socket, at most: a handshake flight or a
/// record of one datagram ([`SEND_BUF`] plus the record's overhead), with
/// room for the one before it draining. A datagram is encrypted only when
/// this has room for its record, so BoringSSL never writes past it.
pub const TLS_OUT_MAX: usize = 8 * 1024;

/// What a record adds to its plaintext, at most: the header (5), the
/// content type and the tag (TLS 1.3), the padding, rounded up.
const RECORD_OVERHEAD: usize = 64;

/// A handshake that has not finished in this long ends the connection
/// (Chrome's connect timeout is longer; ICE gives up on the pair first).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The most certificate bytes BoringSSL takes from a server in one
/// handshake (`SSL_set_max_cert_list`; its default, which Chrome keeps, is
/// 100 KiB). A real chain is 3 to 6 KiB.
pub const TLS_MAX_CERT_LIST: usize = 32 * 1024;

/// The servers whose session is kept: one per TURN server of a peer
/// connection ([`MAX_ALLOCATIONS`]).
pub const TICKET_SERVERS: usize = MAX_ALLOCATIONS;

/// A session longer than this serialised (`i2d_SSL_SESSION`: the ticket and
/// the server's certificate chain) is not kept.
pub const TICKET_MAX_DER: usize = 12 * 1024;

/// The C heap one kept session holds, at most (its serialised form,
/// BoringSSL's parsed copy of the chain, the ticket): the cap of the row in
/// `olc-client`'s `sizes.rs`; a test measures a session of a real-sized
/// chain against it.
pub const TICKET_HEAP_MAX: usize = 48 * 1024;

/// The C heap BoringSSL's state of one connection adds to a plain TCP relay's
/// (its `SSL`, the handshake's keys, a record's buffers), at most: the cap
/// the connection row of `olc-client`'s `sizes.rs` is made from. The lab's
/// heap test (`heap_a_tls_connection_beside_a_tcp_one`) measures it.
pub const TLS_BORINGSSL_MAX: usize = 64 * 1024;

/// What one `turns:` connection holds beside a plain TCP relay's, at most:
/// BoringSSL's state, the buffers of this module (a socket read, the
/// plaintext, the ciphertext in and out, the datagram held during the
/// handshake) and, while the handshake runs, the certificate chain
/// ([`TLS_MAX_CERT_LIST`]).
pub const TLS_CONNECTION_MAX: usize =
    TLS_BORINGSSL_MAX + 3 * STREAM_READ + TLS_OUT_MAX + SEND_BUF + TLS_MAX_CERT_LIST;

/// The bounds of one connection, a test's to shorten.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) handshake: Duration,
    pub(crate) stall: Duration,
    pub(crate) drain: Duration,
}

impl Limits {
    pub(crate) const SHIPPED: Limits = Limits {
        handshake: TLS_HANDSHAKE_TIMEOUT,
        stall: STREAM_WRITE_STALL,
        drain: crate::peer::CLOSE_DRAIN,
    };
}

/// What a connection is made with: the roots a test adds, its bounds, and
/// the session cache (the process's one, [`TICKETS`], unless a test brings
/// its own).
#[derive(Clone)]
pub(crate) struct Setup {
    pub(crate) extra: Arc<Vec<TrustAnchor<'static>>>,
    pub(crate) limits: Limits,
    pub(crate) cache: &'static Mutex<Tickets>,
}

impl Setup {
    fn shipped() -> Setup {
        Setup {
            extra: shipped_extra_roots(),
            limits: Limits::SHIPPED,
            cache: &TICKETS,
        }
    }
}

// ---------------------------------------------------------------------------
// The session cache.

thread_local! {
    /// The session BoringSSL last offered on this thread, between its
    /// callback and the call that raised it (every BoringSSL call here is
    /// followed at once by [`collect_ticket`], on the same thread).
    static OFFERED: RefCell<Option<SslSession>> = const { RefCell::new(None) };
}

/// BoringSSL's new-session callback: the latest session of the call that
/// raised it (a server may send several tickets; one is kept).
pub(crate) fn offer_session(session: SslSession) {
    OFFERED.with(|o| *o.borrow_mut() = Some(session));
}

/// The sessions kept, by server, oldest first.
pub(crate) struct Tickets {
    list: Vec<(String, SslSession)>,
}

impl Tickets {
    pub(crate) const fn new() -> Tickets {
        Tickets { list: Vec::new() }
    }

    /// Keeps `session` for `key`, in place of the server's earlier one; over
    /// [`TICKET_SERVERS`] servers the oldest goes. A session over
    /// [`TICKET_MAX_DER`] is dropped. Returns whether it was kept.
    pub(crate) fn store(&mut self, key: &str, session: SslSession) -> bool {
        match session.to_der() {
            Ok(der) if der.len() <= TICKET_MAX_DER => {}
            _ => return false,
        }
        self.list.retain(|(k, _)| k != key);
        if self.list.len() >= TICKET_SERVERS {
            self.list.remove(0);
        }
        self.list.push((key.to_owned(), session));
        true
    }

    /// The session to offer `key`: a TLS 1.3 one leaves the cache (a ticket
    /// is single use), an older one stays.
    pub(crate) fn take(&mut self, key: &str) -> Option<SslSession> {
        let at = self.list.iter().position(|(k, _)| k == key)?;
        // SAFETY: the session is live; the call only reads it.
        let single =
            unsafe { boring_sys::SSL_SESSION_should_be_single_use(self.list[at].1.as_ptr()) };
        if single == 1 {
            Some(self.list.remove(at).1)
        } else {
            Some(self.list[at].1.clone())
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }
}

static TICKETS: Mutex<Tickets> = Mutex::new(Tickets::new());

fn locked(cache: &Mutex<Tickets>) -> std::sync::MutexGuard<'_, Tickets> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Moves the session BoringSSL offered during the last call into the cache.
fn collect_ticket(cache: &Mutex<Tickets>, key: &str) {
    if let Some(s) = OFFERED.with(|o| o.borrow_mut().take()) {
        locked(cache).store(key, s);
    }
}

/// The context every `turns:` connection is made from, built once.
fn context() -> Result<&'static SslContext, String> {
    static CTX: OnceLock<Result<SslContext, String>> = OnceLock::new();
    CTX.get_or_init(|| crate::tls_boring::turns_context().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

// ---------------------------------------------------------------------------
// BoringSSL over memory.

/// BoringSSL's two byte streams: ciphertext in (what the socket read, until
/// BoringSSL has taken it) and ciphertext out (until the socket has taken
/// it). Both are bounded: in by [`STREAM_READ`], out by [`TLS_OUT_MAX`].
#[derive(Debug)]
struct Mem {
    rx: Vec<u8>,
    rx_at: usize,
    tx: Vec<u8>,
    tx_at: usize,
}

impl Mem {
    fn new() -> Mem {
        Mem {
            rx: Vec::with_capacity(STREAM_READ),
            rx_at: 0,
            tx: Vec::with_capacity(TLS_OUT_MAX),
            tx_at: 0,
        }
    }

    /// Takes a socket read; BoringSSL has taken the last one by now.
    fn feed(&mut self, data: &[u8]) -> Result<(), String> {
        if self.rx_at != self.rx.len() || data.len() > STREAM_READ {
            return Err("TLS input was not taken".into());
        }
        self.rx.clear();
        self.rx_at = 0;
        self.rx.extend_from_slice(data);
        Ok(())
    }

    /// What BoringSSL wrote that the socket has not taken.
    fn pending(&self) -> &[u8] {
        &self.tx[self.tx_at..]
    }

    fn sent(&mut self, n: usize) {
        self.tx_at += n;
        if self.tx_at == self.tx.len() {
            self.tx.clear();
            self.tx_at = 0;
        }
    }
}

impl Read for Mem {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = &self.rx[self.rx_at..];
        if left.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = left.len().min(buf.len());
        buf[..n].copy_from_slice(&left[..n]);
        self.rx_at += n;
        Ok(n)
    }
}

impl Write for Mem {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pending().len() + buf.len() > TLS_OUT_MAX {
            return Err(io::Error::other("TLS output past its bound"));
        }
        if self.tx_at > 0 {
            // What the socket took is gone: the buffer never grows past
            // its bound.
            self.tx.drain(..self.tx_at);
            self.tx_at = 0;
        }
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Tls {
    Connecting(MidHandshakeSslStream<Mem>),
    Up(SslStream<Mem>),
}

/// What reading the connection led to.
enum Flow {
    Continue,
    /// The server closed the TLS connection.
    Closed,
}

/// One connection's TLS client and what it says about itself.
struct Conn {
    tls: Option<Tls>,
    /// The session cache's key: `host:port`.
    key: String,
    cache: &'static Mutex<Tickets>,
    /// Why the certificate was refused, when it was.
    refused: Arc<Mutex<Option<String>>>,
}

impl Conn {
    /// A client for `host`, offering the cached session of `key` if any.
    fn start(host: &str, key: String, setup: &Setup) -> Result<Conn, String> {
        let extra = Arc::clone(&setup.extra);
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| format!("the TLS name {host:?} is neither a DNS name nor an address"))?;
        let ctx = context()?;
        let mut ssl = crate::tls_boring::chrome_ssl(ctx, host).map_err(|e| e.to_string())?;
        // SAFETY: the Ssl is live and takes a size.
        unsafe { boring_sys::SSL_set_max_cert_list(ssl.as_ptr(), TLS_MAX_CERT_LIST) };
        let refused = Arc::new(Mutex::new(None));
        let note = Arc::clone(&refused);
        ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl: &mut SslRef| {
            let chain: Vec<Vec<u8>> = ssl
                .peer_cert_chain()
                .map(|c| c.iter().filter_map(|x| x.to_der().ok()).collect())
                .unwrap_or_default();
            // The verdict: the one place the certificate is judged.
            let verdict = verify_server_chain(&chain, &name, UnixTime::now(), &extra);
            match verdict {
                Ok(()) => Ok(()),
                Err(e) => {
                    *note
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(e.to_string());
                    Err(SslVerifyError::Invalid(alert_for(&e)))
                }
            }
        });
        if let Some(session) = locked(setup.cache).take(&key) {
            // SAFETY: the session came from a connection of this process's
            // one `turns:` context, which `ssl` is made from.
            unsafe { ssl.set_session(&session) }.map_err(|e| e.to_string())?;
        }
        let tls = match ssl.connect(Mem::new()) {
            Err(HandshakeError::WouldBlock(mid)) => Tls::Connecting(mid),
            Ok(_) => return Err("a handshake with nobody".into()),
            Err(e) => return Err(e.to_string()),
        };
        Ok(Conn {
            tls: Some(tls),
            key,
            cache: setup.cache,
            refused,
        })
    }

    fn mem(&mut self) -> &mut Mem {
        match self.tls.as_mut() {
            Some(Tls::Connecting(m)) => m.get_mut(),
            Some(Tls::Up(s)) => s.get_mut(),
            None => unreachable!("the connection's state is put back before any call returns"),
        }
    }

    fn is_up(&self) -> bool {
        matches!(self.tls, Some(Tls::Up(_)))
    }

    fn pending(&mut self) -> usize {
        self.mem().pending().len()
    }

    /// Runs the handshake and reads what BoringSSL can deliver from the
    /// ciphertext fed, each chunk to `inbound` (at most [`STREAM_READ`]).
    async fn pump(
        &mut self,
        plain: &mut [u8],
        slot: usize,
        inbound: &mpsc::Sender<StreamChunk>,
    ) -> Result<Flow, String> {
        loop {
            let Some(tls) = self.tls.take() else {
                return Err("no TLS connection".into());
            };
            match tls {
                Tls::Connecting(mid) => {
                    let r = mid.handshake();
                    collect_ticket(self.cache, &self.key);
                    match r {
                        Ok(s) => self.tls = Some(Tls::Up(s)),
                        Err(HandshakeError::WouldBlock(mid)) => {
                            self.tls = Some(Tls::Connecting(mid));
                            return Ok(Flow::Continue);
                        }
                        Err(HandshakeError::Failure(mid)) => {
                            let why = self.refusal(&mid.error().to_string());
                            return Err(why);
                        }
                        Err(HandshakeError::SetupFailure(e)) => return Err(e.to_string()),
                    }
                }
                Tls::Up(mut s) => {
                    let r = s.ssl_read(plain);
                    collect_ticket(self.cache, &self.key);
                    self.tls = Some(Tls::Up(s));
                    match r {
                        Ok(0) => return Ok(Flow::Closed),
                        Ok(n) => {
                            let chunk = StreamChunk {
                                slot,
                                data: plain[..n].to_vec(),
                            };
                            if inbound.send(chunk).await.is_err() {
                                return Ok(Flow::Closed);
                            }
                        }
                        Err(e) => match e.code() {
                            ErrorCode::WANT_READ => return Ok(Flow::Continue),
                            ErrorCode::ZERO_RETURN => return Ok(Flow::Closed),
                            _ => return Err(e.to_string()),
                        },
                    }
                }
            }
        }
    }

    /// The handshake's failure in words: the certificate's reason when the
    /// check refused it.
    fn refusal(&self, ssl_error: &str) -> String {
        let note = self
            .refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match note {
            Some(why) => format!("certificate refused: {why}"),
            None => format!("handshake failed: {ssl_error}"),
        }
    }

    /// Encrypts one datagram.
    fn send(&mut self, data: &[u8]) -> Result<(), String> {
        let Some(Tls::Up(s)) = self.tls.as_mut() else {
            return Err("TLS is not up".into());
        };
        let r = s.ssl_write(data);
        collect_ticket(self.cache, &self.key);
        match r {
            Ok(n) if n == data.len() => Ok(()),
            Ok(n) => Err(format!("TLS took {n} of {} bytes", data.len())),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Queues the TLS close (close_notify).
    fn close(&mut self) {
        if let Some(Tls::Up(s)) = self.tls.as_mut() {
            let _ = s.shutdown();
        }
    }
}

/// The alert a refused chain is sent, as BoringSSL's own verifier says it.
fn alert_for(e: &webpki::Error) -> SslAlert {
    match e {
        webpki::Error::UnknownIssuer => SslAlert::UNKNOWN_CA,
        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
            SslAlert::CERTIFICATE_EXPIRED
        }
        _ => SslAlert::BAD_CERTIFICATE,
    }
}

// ---------------------------------------------------------------------------
// The task.

/// Why a connection's task ended.
enum Outcome {
    /// The relays were dropped: nothing to tell the driver.
    Dropped,
    /// The connection ended; the driver hears an empty chunk.
    Ended(String),
}

/// One TURN server's TLS connection ([`crate::turn::Relays`] spawns it):
/// dials it from a protected socket, runs Chrome's TLS over it, writes what
/// `out` holds (encrypted), reads into chunks for the driver. It ends when
/// the server closes the connection, the handshake or the certificate fails,
/// the handshake outlasts [`TLS_HANDSHAKE_TIMEOUT`] or a write stalls for
/// [`STREAM_WRITE_STALL`] (the driver hears an empty chunk), or when the
/// relays are dropped: then it writes what is queued (a closing Refresh),
/// the TLS close and shuts the connection down, within
/// [`crate::peer::CLOSE_DRAIN`].
pub(crate) async fn stream(
    slot: usize,
    host: String,
    server: SocketAddr,
    out: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<StreamChunk>,
) {
    stream_with(slot, host, server, out, inbound, Setup::shipped()).await;
}

pub(crate) async fn stream_with(
    slot: usize,
    host: String,
    server: SocketAddr,
    mut out: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<StreamChunk>,
    setup: Setup,
) {
    match run(slot, &host, server, &mut out, &inbound, &setup).await {
        Outcome::Dropped => {}
        Outcome::Ended(why) => {
            if !why.is_empty() {
                olc_net::debug!("webrtc: TURN server {server} over TLS: {why}");
            }
            let _ = inbound
                .send(StreamChunk {
                    slot,
                    data: Vec::new(),
                })
                .await;
        }
    }
}

async fn run(
    slot: usize,
    host: &str,
    server: SocketAddr,
    out: &mut mpsc::Receiver<Vec<u8>>,
    inbound: &mpsc::Sender<StreamChunk>,
    setup: &Setup,
) -> Outcome {
    let limits = setup.limits;
    let ended = Outcome::Ended;
    let tcp = match olc_net::net::dial_tcp_with(server, Some(STREAM_SNDBUF)).await {
        Ok(tcp) => tcp,
        Err(e) => return ended(e.to_string()),
    };
    let _ = tcp.set_nodelay(true);
    let mut conn = match Conn::start(host, format!("{host}:{}", server.port()), setup) {
        Ok(c) => c,
        Err(e) => return ended(e),
    };
    let mut read = vec![0u8; STREAM_READ];
    let mut plain = vec![0u8; STREAM_READ];
    let started = Instant::now();
    // The datagram taken from the queue while the handshake runs, and the
    // time the socket has had ciphertext waiting without taking any.
    let mut held: Option<Vec<u8>> = None;
    let mut stalled_since: Option<Instant> = None;
    loop {
        if conn.is_up() {
            if let Some(b) = held.take() {
                if let Err(e) = conn.send(&b) {
                    return ended(e);
                }
            }
        }
        let pending = conn.pending();
        if pending == 0 {
            stalled_since = None;
        } else if stalled_since.is_none() {
            stalled_since = Some(Instant::now());
        }
        let room = pending + SEND_BUF + RECORD_OVERHEAD <= TLS_OUT_MAX;
        let (deadline, why) = if conn.is_up() {
            match stalled_since {
                Some(t) => (t + limits.stall, "write stalled"),
                None => (Instant::now() + Duration::from_secs(24 * 3600), ""),
            }
        } else {
            (started + limits.handshake, "handshake timed out")
        };
        tokio::select! {
            r = tcp.readable() => {
                if let Err(e) = r {
                    return ended(e.to_string());
                }
                match tcp.try_read(&mut read) {
                    Ok(0) => return ended("the server closed the connection".into()),
                    Ok(n) => {
                        if let Err(e) = conn.mem().feed(&read[..n]) {
                            return ended(e);
                        }
                        match conn.pump(&mut plain, slot, inbound).await {
                            Ok(Flow::Continue) => {}
                            Ok(Flow::Closed) => return ended("the server closed the TLS connection".into()),
                            Err(e) => return ended(e),
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return ended(e.to_string()),
                }
            }
            r = tcp.writable(), if pending > 0 => {
                if let Err(e) = r {
                    return ended(e.to_string());
                }
                match tcp.try_write(conn.mem().pending()) {
                    Ok(n) => {
                        conn.mem().sent(n);
                        stalled_since = None;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return ended(format!("write: {e}")),
                }
            }
            item = out.recv(), if held.is_none() && room => {
                match item {
                    Some(b) => held = Some(b),
                    None => break,
                }
            }
            () = tokio::time::sleep_until(deadline) => return ended(why.into()),
        }
    }
    close(&mut conn, held.take(), tcp, limits.drain).await;
    Outcome::Dropped
}

/// The relays are gone: writes the datagram held, closes TLS and the
/// socket, all within `drain`.
async fn close(conn: &mut Conn, held: Option<Vec<u8>>, mut tcp: TcpStream, drain: Duration) {
    use tokio::io::AsyncWriteExt;
    if !conn.is_up() {
        return;
    }
    if let Some(b) = held {
        if conn.send(&b).is_err() {
            return;
        }
    }
    conn.close();
    let flush = async {
        while conn.pending() > 0 {
            if tcp.writable().await.is_err() {
                return;
            }
            match tcp.try_write(conn.mem().pending()) {
                Ok(n) => conn.mem().sent(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
        let _ = tcp.shutdown().await;
    };
    let _ = tokio::time::timeout(drain, flush).await;
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream as StdTcp};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::JoinHandle;
    use std::time::Instant as StdInstant;

    use boring::ssl::{NameType, ShutdownState, Ssl, SslContextBuilder, SslMethod};
    use tokio::task::JoinHandle as TaskHandle;

    use super::*;
    use crate::tls_boring::hello_util::{assert_is_chromes, parse, Hello};
    use crate::turn::{STREAM_INBOUND, STREAM_QUEUE};
    use crate::turns_verify::testpki::{self, Cert, Leaf};
    use crate::turns_verify::{anchor_of, MAX_CHAIN};

    // -----------------------------------------------------------------
    // Fixtures: a root, an intermediate and a server certificate.

    struct Fixture {
        root: Cert,
        mid: Cert,
        leaf: Cert,
    }

    fn fixture(dns: &[&str], ips: &[&str]) -> Fixture {
        let root = testpki::ca("olc turns test root");
        let mid = testpki::intermediate("olc turns test intermediate", &root);
        let leaf = testpki::leaf(&Leaf::new(dns, ips), &mid);
        Fixture { root, mid, leaf }
    }

    fn roots(f: &Fixture) -> Arc<Vec<TrustAnchor<'static>>> {
        Arc::new(vec![anchor_of(&f.root.x509.to_der().unwrap()).unwrap()])
    }

    fn server_ctx(f: &Fixture) -> SslContext {
        let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
        b.set_certificate(&f.leaf.x509).unwrap();
        b.add_extra_chain_cert(f.mid.x509.clone()).unwrap();
        b.set_private_key(&f.leaf.key).unwrap();
        b.build()
    }

    const TEST_LIMITS: Limits = Limits {
        handshake: Duration::from_secs(5),
        stall: Duration::from_secs(5),
        drain: Duration::from_secs(2),
    };

    /// A setup with its own session cache.
    fn setup(extra: Arc<Vec<TrustAnchor<'static>>>) -> Setup {
        Setup {
            extra,
            limits: TEST_LIMITS,
            cache: Box::leak(Box::new(Mutex::new(Tickets::new()))),
        }
    }

    // -----------------------------------------------------------------
    // A TLS server on loopback, in a thread of its own (BoringSSL, blocking).

    /// What a test server saw.
    #[derive(Default)]
    struct Seen {
        /// The first TLS record of each connection: the ClientHello.
        hellos: Vec<Vec<u8>>,
        /// The server name each connection sent.
        sni: Vec<Option<String>>,
        /// Whether each connection resumed a session.
        reused: Vec<bool>,
        /// What the clients sent, decrypted.
        received: Vec<u8>,
        /// Connections that ended with the client's close_notify.
        closed_clean: usize,
        /// Handshakes that failed (the client refused the certificate).
        failed: usize,
        /// Connections that finished their handshake.
        accepted: usize,
    }

    /// A reader that remembers the first TLS record the client sent.
    struct Tee {
        inner: StdTcp,
        first: Vec<u8>,
    }

    impl Read for Tee {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            let mut at = 0;
            while at < n {
                let want = if self.first.len() >= 5 {
                    5 + usize::from(u16::from_be_bytes([self.first[3], self.first[4]]))
                } else {
                    5
                };
                if self.first.len() >= want {
                    break;
                }
                let take = (want - self.first.len()).min(n - at);
                self.first.extend_from_slice(&buf[at..at + take]);
                at += take;
            }
            Ok(n)
        }
    }

    impl Write for Tee {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    struct TestServer {
        addr: SocketAddr,
        seen: Arc<Mutex<Seen>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestServer {
        /// Serves `ctx`; the first bytes a client sends are answered with
        /// `reply`. `stall`: accepts and says nothing.
        fn start(ctx: SslContext, reply: Vec<u8>, stall: bool) -> TestServer {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = Arc::new(Mutex::new(Seen::default()));
            let stop = Arc::new(AtomicBool::new(false));
            let (s2, st2) = (Arc::clone(&seen), Arc::clone(&stop));
            let thread = std::thread::spawn(move || {
                let mut conns = Vec::new();
                while !st2.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((tcp, _)) => {
                            let (ctx, seen, stop, reply) = (
                                ctx.clone(),
                                Arc::clone(&s2),
                                Arc::clone(&st2),
                                reply.clone(),
                            );
                            conns.push(std::thread::spawn(move || {
                                serve(&ctx, tcp, &seen, &stop, &reply, stall);
                            }));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
                for c in conns {
                    let _ = c.join();
                }
            });
            TestServer {
                addr,
                seen,
                stop,
                thread: Some(thread),
            }
        }

        fn seen<R>(&self, f: impl FnOnce(&Seen) -> R) -> R {
            f(&self.seen.lock().unwrap())
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn serve(
        ctx: &SslContext,
        tcp: StdTcp,
        seen: &Mutex<Seen>,
        stop: &AtomicBool,
        reply: &[u8],
        stall: bool,
    ) {
        let _ = tcp.set_nonblocking(false);
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(200)));
        if stall {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
            }
            return;
        }
        let tee = Tee {
            inner: tcp,
            first: Vec::new(),
        };
        let ssl = Ssl::new(ctx).unwrap();
        let mut stream = match ssl.accept(tee) {
            Ok(s) => s,
            Err(e) => {
                let first = match &e {
                    HandshakeError::Failure(m) | HandshakeError::WouldBlock(m) => {
                        m.get_ref().first.clone()
                    }
                    HandshakeError::SetupFailure(_) => Vec::new(),
                };
                let mut s = seen.lock().unwrap();
                s.hellos.push(first);
                s.sni.push(None);
                s.reused.push(false);
                s.failed += 1;
                return;
            }
        };
        {
            let mut s = seen.lock().unwrap();
            s.hellos.push(stream.get_ref().first.clone());
            s.sni.push(
                stream
                    .ssl()
                    .servername(NameType::HOST_NAME)
                    .map(str::to_owned),
            );
            s.reused.push(stream.ssl().session_reused());
            s.accepted += 1;
        }
        let mut answered = false;
        let mut buf = vec![0u8; 16 * 1024];
        while !stop.load(Ordering::Relaxed) {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    seen.lock().unwrap().received.extend_from_slice(&buf[..n]);
                    if !answered && !reply.is_empty() {
                        answered = true;
                        if stream.write_all(reply).is_err() {
                            return;
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
        if stream.get_shutdown().contains(ShutdownState::RECEIVED) {
            seen.lock().unwrap().closed_clean += 1;
        }
    }

    // -----------------------------------------------------------------
    // The client side of a test: one relay task and its two queues.

    struct Relay {
        out: Option<mpsc::Sender<Vec<u8>>>,
        chunks: mpsc::Receiver<StreamChunk>,
        task: TaskHandle<()>,
        biggest: usize,
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn relay(slot: usize, host: &str, addr: SocketAddr, setup: Setup) -> Relay {
        let (otx, orx) = mpsc::channel(STREAM_QUEUE);
        let (itx, irx) = mpsc::channel(STREAM_INBOUND);
        let task = tokio::spawn(stream_with(slot, host.to_owned(), addr, orx, itx, setup));
        Relay {
            out: Some(otx),
            chunks: irx,
            task,
            biggest: 0,
        }
    }

    impl Relay {
        async fn send(&self, data: Vec<u8>) {
            self.out.as_ref().unwrap().send(data).await.unwrap();
        }

        /// Reads chunks until `n` bytes came (None: the relay ended first).
        async fn collect(&mut self, n: usize) -> Option<Vec<u8>> {
            let mut got = Vec::new();
            while got.len() < n {
                let c = self.chunks.recv().await?;
                if c.data.is_empty() {
                    return None;
                }
                self.biggest = self.biggest.max(c.data.len());
                got.extend_from_slice(&c.data);
            }
            Some(got)
        }

        /// Whether the relay ends (an empty chunk) before anything else.
        async fn ends(&mut self) -> bool {
            matches!(self.chunks.recv().await, Some(c) if c.data.is_empty())
        }

        /// Drops the queue's sender, as dropping the relays does, and waits
        /// for the task.
        async fn close(&mut self) {
            self.out = None;
            let _ = (&mut self.task).await;
        }
    }

    async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
        for _ in 0..500 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("never: {what}");
    }

    const HOST: &str = "turn.olc.test";

    // -----------------------------------------------------------------
    // The tests.

    /// Datagrams from the queue reach the server in order, decrypted; what
    /// the server sends comes back in chunks of at most [`STREAM_READ`]; and
    /// dropping the relays ends with the TLS close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tls_relay_carries_datagrams_both_ways_and_closes_cleanly() {
        crate::testing::bounded(async {
            let f = fixture(&[HOST], &[]);
            let reply: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
            let srv = TestServer::start(server_ctx(&f), reply.clone(), false);
            let mut r = relay(0, HOST, srv.addr, setup(roots(&f)));
            let sent: Vec<Vec<u8>> = (0..STREAM_QUEUE)
                .map(|i| vec![u8::try_from(i).unwrap(); 1259])
                .collect();
            // All of it queued before the handshake can have finished: the
            // task holds one, the queue the rest, and all of it arrives.
            for d in &sent {
                r.send(d.clone()).await;
            }
            let got = r.collect(reply.len()).await.expect("the relay ended");
            assert_eq!(got, reply);
            assert!(r.biggest <= STREAM_READ, "a chunk of {}", r.biggest);
            let want: Vec<u8> = sent.concat();
            eventually("the server read every datagram", || {
                srv.seen(|s| s.received.len() >= want.len())
            })
            .await;
            assert_eq!(srv.seen(|s| s.received.clone()), want);
            r.close().await;
            eventually("the server saw the TLS close", || {
                srv.seen(|s| s.closed_clean == 1)
            })
            .await;
        })
        .await;
    }

    /// The hello a real `turns:` relay sends ([`crate::turn::Relays`], the
    /// shipped context) is Chrome 157's, as the profile's own test holds
    /// `tls_boring`'s to: not some other context's. The server here only
    /// reads the first record, so no root is involved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_relays_hello_is_the_profiles() {
        use crate::turn::{Relays, Resolved, TurnTransport};
        crate::testing::bounded(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = listener.local_addr().unwrap();
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let resolved = [Resolved {
                host: HOST.into(),
                addr: server,
                transport: TurnTransport::Tls,
                username: "u".into(),
                password: "p".into(),
            }];
            let (inbound, mut chunks) = mpsc::channel(STREAM_INBOUND);
            let _relays = Relays::new(
                &resolved,
                sock.local_addr().unwrap(),
                std::time::Instant::now(),
                &inbound,
            );
            let (mut conn, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt as _;
            let mut head = [0u8; 5];
            conn.read_exact(&mut head).await.unwrap();
            let mut body = vec![0u8; usize::from(u16::from_be_bytes([head[3], head[4]]))];
            conn.read_exact(&mut body).await.unwrap();
            let hello = [&head[..], &body[..]].concat();
            assert_is_chromes(&parse(&hello));
            // The server goes away: the relay ends and says so.
            drop(conn);
            let c = chunks.recv().await.unwrap();
            assert!(c.data.is_empty());
        })
        .await;
    }

    /// A chain no trusted root signed ends that relay; another relay, to a
    /// server with a good certificate, goes on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_untrusted_certificate_ends_that_relay_only() {
        crate::testing::bounded(async {
            let good = fixture(&[HOST], &[]);
            let bad = fixture(&[HOST], &[]);
            let reply = vec![7u8; 100];
            let srv_good = TestServer::start(server_ctx(&good), reply.clone(), false);
            let srv_bad = TestServer::start(server_ctx(&bad), reply.clone(), false);
            // Both relays trust only the good root.
            let trust = roots(&good);
            let mut a = relay(0, HOST, srv_bad.addr, setup(Arc::clone(&trust)));
            let mut b = relay(1, HOST, srv_good.addr, setup(trust));
            b.send(vec![1; 40]).await;
            assert!(a.ends().await, "the untrusted relay did not end");
            assert_eq!(b.collect(100).await.expect("the good relay ended"), reply);
            assert_eq!(srv_bad.seen(|s| s.failed), 1, "the server saw no alert");
            assert_eq!(srv_bad.seen(|s| s.received.len()), 0, "bytes got through");
        })
        .await;
    }

    /// A certificate that is trusted but names another host ends the relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_for_another_name_ends_the_relay() {
        crate::testing::bounded(async {
            let f = fixture(&["elsewhere.olc.test"], &[]);
            let srv = TestServer::start(server_ctx(&f), vec![1; 10], false);
            let mut r = relay(0, HOST, srv.addr, setup(roots(&f)));
            r.send(vec![1; 40]).await;
            assert!(r.ends().await, "the relay did not end");
            assert_eq!(srv.seen(|s| s.received.len()), 0, "bytes got through");
        })
        .await;
    }

    /// An address literal sends no server name and is checked against the
    /// certificate's address names: the right address passes, another does
    /// not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_address_literal_sends_no_sni_and_is_checked_as_an_address() {
        crate::testing::bounded(async {
            let f = fixture(&[HOST], &["127.0.0.1"]);
            let srv = TestServer::start(server_ctx(&f), vec![9; 50], false);
            let mut r = relay(0, "127.0.0.1", srv.addr, setup(roots(&f)));
            r.send(vec![1; 40]).await;
            assert_eq!(r.collect(50).await.expect("the relay ended"), vec![9; 50]);
            assert_eq!(srv.seen(|s| s.sni.clone()), [None]);
            let hello = parse(&srv.seen(|s| s.hellos[0].clone()));
            assert!(
                !hello.bodies.contains_key(&0x0000),
                "a server name in the hello"
            );
            // The address the certificate does not name.
            let other = fixture(&[HOST], &["192.0.2.55"]);
            let srv2 = TestServer::start(server_ctx(&other), vec![9; 50], false);
            let mut r2 = relay(1, "127.0.0.1", srv2.addr, setup(roots(&other)));
            assert!(
                r2.ends().await,
                "the relay to the wrong address did not end"
            );
            // A name, by contrast, is sent.
            let srv3 = TestServer::start(server_ctx(&f), vec![9; 50], false);
            let mut r3 = relay(2, HOST, srv3.addr, setup(roots(&f)));
            r3.send(vec![1; 40]).await;
            assert!(r3.collect(50).await.is_some());
            assert_eq!(srv3.seen(|s| s.sni.clone()), [Some(HOST.to_owned())]);
        })
        .await;
    }

    /// The first hello to a server has no PSK; the second carries one (last,
    /// after the GREASE extension BoringSSL puts last) and the server
    /// resumes; every other field the profile's; and so the third, since a
    /// TLS 1.3 ticket is single use and each connection brings its own.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_later_connection_to_a_server_resumes_and_its_hello_carries_the_psk() {
        crate::testing::bounded(async {
            let f = fixture(&[HOST], &[]);
            let srv = TestServer::start(server_ctx(&f), vec![5; 20], false);
            let s = setup(roots(&f));
            for i in 0..3 {
                let mut r = relay(0, HOST, srv.addr, s.clone());
                r.send(vec![1; 40]).await;
                assert_eq!(r.collect(20).await.expect("the relay ended"), vec![5; 20]);
                r.close().await;
                eventually("the connection was served", || {
                    srv.seen(|x| x.closed_clean == i + 1)
                })
                .await;
            }
            let hellos: Vec<Hello> = srv.seen(|x| x.hellos.iter().map(|h| parse(h)).collect());
            assert_eq!(srv.seen(|x| x.reused.clone()), [false, true, true]);
            let set = |h: &Hello| {
                let mut v: Vec<(u16, usize)> = h
                    .order
                    .iter()
                    .copied()
                    .filter(|(id, _)| !matches!(*id, 0xfe0d | 0x0029))
                    .collect();
                v.sort_unstable();
                v
            };
            assert!(
                !hellos[0].order.iter().any(|(id, _)| *id == 0x0029),
                "a PSK in the first hello"
            );
            assert_is_chromes(&hellos[0]);
            for h in &hellos[1..] {
                assert_eq!(
                    h.order.last().map(|(id, _)| *id),
                    Some(0x0029),
                    "{:04x?}",
                    h.order
                );
                assert_eq!(h.order[h.order.len() - 2], (0x0a0a, 1), "{:04x?}", h.order);
                assert_eq!(set(h), set(&hellos[0]), "the other extensions");
                assert_eq!(h.suites, hellos[0].suites);
                assert_eq!(h.session_id_len, hellos[0].session_id_len);
                assert_eq!(h.bodies.get(&0x0000), hellos[0].bodies.get(&0x0000));
                assert_eq!(h.bodies.get(&0xca34), hellos[0].bodies.get(&0xca34));
                // psk_key_exchange_modes stays what it was.
                assert_eq!(h.bodies.get(&0x002d), hellos[0].bodies.get(&0x002d));
            }
        })
        .await;
    }

    /// One session per server, at most [`TICKET_SERVERS`] servers (the
    /// oldest goes), and a session over [`TICKET_MAX_DER`] is not kept (its
    /// connection works all the same).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_ticket_cache_keeps_one_session_per_server_and_few_servers() {
        crate::testing::bounded(async {
            let f = fixture(&[HOST], &[]);
            let s = setup(roots(&f));
            let mut servers = Vec::new();
            for _ in 0..TICKET_SERVERS + 2 {
                let srv = TestServer::start(server_ctx(&f), vec![5; 20], false);
                let mut r = relay(0, HOST, srv.addr, s.clone());
                r.send(vec![1; 40]).await;
                assert!(r.collect(20).await.is_some());
                r.close().await;
                eventually("served", || srv.seen(|x| x.closed_clean == 1)).await;
                servers.push(srv);
                assert!(locked(s.cache).len() <= TICKET_SERVERS);
            }
            let keys: Vec<String> = locked(s.cache)
                .list
                .iter()
                .map(|(k, _)| k.clone())
                .collect();
            let want: Vec<String> = servers[2..]
                .iter()
                .map(|x| format!("{HOST}:{}", x.addr.port()))
                .collect();
            assert_eq!(keys, want, "the two oldest servers are gone");
            // The last server again: its session is replaced, not added.
            let last = servers.last().unwrap();
            let mut r = relay(0, HOST, last.addr, s.clone());
            r.send(vec![1; 40]).await;
            assert!(r.collect(20).await.is_some());
            r.close().await;
            eventually("served", || last.seen(|x| x.closed_clean == 2)).await;
            assert_eq!(locked(s.cache).len(), TICKET_SERVERS);
            drop(r);

            // A chain too long to keep.
            let names: Vec<String> = (0..900).map(|i| format!("pad{i:04}.olc.test")).collect();
            let mut all: Vec<&str> = names.iter().map(String::as_str).collect();
            all.push(HOST);
            let fat = fixture(&all, &[]);
            let s2 = setup(roots(&fat));
            let srv = TestServer::start(server_ctx(&fat), vec![5; 20], false);
            let mut r = relay(0, HOST, srv.addr, s2.clone());
            r.send(vec![1; 40]).await;
            assert!(r.collect(20).await.is_some(), "the connection must work");
            r.close().await;
            eventually("served", || srv.seen(|x| x.closed_clean == 1)).await;
            assert_eq!(
                locked(s2.cache).len(),
                0,
                "a session over {TICKET_MAX_DER} bytes was kept"
            );
        })
        .await;
    }

    /// A server that accepts and never answers ends the relay at the
    /// handshake's bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_handshake_that_never_finishes_ends_the_relay() {
        crate::testing::bounded(async {
            let f = fixture(&[HOST], &[]);
            let srv = TestServer::start(server_ctx(&f), Vec::new(), true);
            let mut s = setup(roots(&f));
            s.limits.handshake = Duration::from_millis(300);
            let mut r = relay(0, HOST, srv.addr, s);
            let t = StdInstant::now();
            assert!(r.ends().await);
            assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        })
        .await;
    }

    /// BoringSSL never writes past the output bound: the memory buffer says
    /// no, and its input takes one socket read at a time.
    #[test]
    fn the_memory_buffers_stay_in_their_bounds() {
        let mut m = Mem::new();
        assert!(m.write(&vec![0u8; TLS_OUT_MAX]).is_ok());
        assert!(m.write(&[0u8]).is_err(), "a write past TLS_OUT_MAX");
        m.sent(100);
        assert!(m.write(&[0u8; 100]).is_ok());
        assert!(m.write(&[0u8]).is_err());
        let mut m = Mem::new();
        assert!(m.feed(&vec![1u8; STREAM_READ]).is_ok());
        assert!(
            m.feed(&[1]).is_err(),
            "a second read before the first was taken"
        );
        let mut buf = [0u8; 10];
        assert_eq!(m.read(&mut buf).unwrap(), 10);
        let mut rest = vec![0u8; STREAM_READ];
        assert_eq!(m.read(&mut rest).unwrap(), STREAM_READ - 10);
        assert_eq!(
            m.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            m.feed(&vec![1u8; STREAM_READ + 1]).is_err(),
            "a read past STREAM_READ"
        );
        assert!(m.feed(&[1, 2, 3]).is_ok());
    }

    /// The chain bound and the per-connection bounds fit the budget the
    /// module states: what BoringSSL may be handed is capped, and the cache
    /// is [`TICKET_SERVERS`] sessions.
    #[test]
    fn the_bounds_are_consistent() {
        assert!(TICKET_SERVERS >= MAX_ALLOCATIONS);
        assert!(TLS_OUT_MAX >= 2 * (SEND_BUF + RECORD_OVERHEAD));
        assert!(TLS_MAX_CERT_LIST >= 16 * 1024 && TLS_MAX_CERT_LIST <= 100 * 1024);
        assert!(MAX_CHAIN * 4096 <= TLS_MAX_CERT_LIST * 2);
        assert!(TICKET_MAX_DER < TICKET_HEAP_MAX);
    }

    // -----------------------------------------------------------------
    // Heap, measured on the C heap (glibc's mallinfo2), in a process of its
    // own (the lab runs these with --ignored --test-threads=1): the server
    // of the connection measurement is a child process, so what is counted
    // is the client's alone.

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    mod heap {
        use std::io::BufRead;
        use std::process::{Child, Command, Stdio};
        use std::sync::atomic::AtomicUsize;

        use super::*;

        /// Bytes in use on the C heap, all arenas, mmapped blocks included.
        fn used() -> usize {
            // SAFETY: mallinfo2 only reads the allocator's counters.
            let m = unsafe { libc::mallinfo2() };
            m.uordblks + m.hblkhd
        }

        /// The measurement's server: a child process of this test binary
        /// (a TLS echo server, or a plain TCP one), which says its port and
        /// ends when its stdin does.
        #[test]
        #[ignore = "the heap measurement's server process; the test below starts it"]
        fn heap_server_child() {
            let Ok(dir) = std::env::var("OLC_TURNS_CHILD_DIR") else {
                return;
            };
            let plain = std::env::var("OLC_TURNS_CHILD_MODE").as_deref() == Ok("plain");
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            println!("PORT {}", listener.local_addr().unwrap().port());
            std::io::stdout().flush().unwrap();
            let ctx = {
                let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
                b.set_certificate_chain_file(format!("{dir}/chain.pem"))
                    .unwrap();
                b.set_private_key_file(format!("{dir}/key.pem"), boring::ssl::SslFiletype::PEM)
                    .unwrap();
                b.build()
            };
            std::thread::spawn(move || {
                for tcp in listener.incoming().flatten() {
                    let ctx = ctx.clone();
                    std::thread::spawn(move || {
                        let mut buf = vec![0u8; 4096];
                        if plain {
                            let mut tcp = tcp;
                            while let Ok(n) = tcp.read(&mut buf) {
                                if n == 0 || tcp.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        } else if let Ok(mut s) = Ssl::new(&ctx).unwrap().accept(tcp) {
                            while let Ok(n) = s.read(&mut buf) {
                                if n == 0 || s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
            });
            let mut one = [0u8; 1];
            while std::io::stdin().read(&mut one).unwrap_or(0) > 0 {}
        }

        struct ServerProcess {
            child: Child,
            port: u16,
        }

        impl Drop for ServerProcess {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        fn server_process(dir: &str, plain: bool) -> ServerProcess {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "turns::tests::heap::heap_server_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("OLC_TURNS_CHILD_DIR", dir)
                .env("OLC_TURNS_CHILD_MODE", if plain { "plain" } else { "tls" })
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let out = child.stdout.take().unwrap();
            let mut port = 0;
            for line in std::io::BufReader::new(out).lines() {
                let line = line.unwrap();
                if let Some(p) = line.strip_prefix("PORT ") {
                    port = p.trim().parse().unwrap();
                    break;
                }
            }
            assert_ne!(port, 0, "the server process said no port");
            ServerProcess { child, port }
        }

        /// What `n` idle connections hold, each, once they have each
        /// echoed a datagram: at rest and at the highest the heap went while
        /// they were made. A TLS connection's total includes its tasks,
        /// queues, buffers and BoringSSL's state.
        async fn per_connection(dir: &str, plain: bool, setup: &Setup, n: usize) -> (usize, usize) {
            let server = server_process(dir, plain);
            let addr = SocketAddr::from(([127, 0, 0, 1], server.port));
            let make = |slot: usize| {
                if plain {
                    let (otx, orx) = mpsc::channel(STREAM_QUEUE);
                    let (itx, irx) = mpsc::channel(STREAM_INBOUND);
                    let task = tokio::spawn(crate::turn::stream(slot, addr, orx, itx));
                    Relay {
                        out: Some(otx),
                        chunks: irx,
                        task,
                        biggest: 0,
                    }
                } else {
                    relay(slot, HOST, addr, setup.clone())
                }
            };
            // One connection first: the one-time state (the context, the
            // roots, the runtime's own) is not a connection's.
            let mut warm = make(99);
            warm.send(vec![1; 100]).await;
            assert!(warm.collect(100).await.is_some(), "the warm-up connection");
            warm.close().await;
            drop(warm);
            tokio::time::sleep(Duration::from_millis(200)).await;

            let peak = Arc::new(AtomicUsize::new(0));
            let run = Arc::new(AtomicBool::new(true));
            let before = used();
            let sampler = {
                let (peak, run) = (Arc::clone(&peak), Arc::clone(&run));
                std::thread::spawn(move || {
                    while run.load(Ordering::Relaxed) {
                        peak.fetch_max(used(), Ordering::Relaxed);
                        std::thread::sleep(Duration::from_micros(300));
                    }
                })
            };
            let mut relays: Vec<Relay> = (0..n).map(make).collect();
            for r in &relays {
                r.send(vec![1; 100]).await;
            }
            for r in &mut relays {
                assert!(r.collect(100).await.is_some(), "a connection never echoed");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let rest = used().saturating_sub(before);
            run.store(false, Ordering::Relaxed);
            sampler.join().unwrap();
            let high = peak.load(Ordering::Relaxed).saturating_sub(before);
            for r in &mut relays {
                r.close().await;
            }
            (rest / n, high / n)
        }

        /// The C heap one `turns:` connection holds beside a TCP one's, and
        /// the highest it went while 16 were made at once, against the
        /// constants the budget states.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "heap measurement: needs the process to itself (--test-threads=1)"]
        async fn heap_a_tls_connection_beside_a_tcp_one() {
            let names: Vec<String> = (0..60).map(|i| format!("pad{i:04}.olc.test")).collect();
            let mut all: Vec<&str> = names.iter().map(String::as_str).collect();
            all.push(HOST);
            let f = fixture(&all, &[]);
            let dir = std::env::temp_dir().join(format!("olc-turns-heap-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let chain = [f.leaf.x509.to_pem().unwrap(), f.mid.x509.to_pem().unwrap()].concat();
            std::fs::write(dir.join("chain.pem"), chain).unwrap();
            std::fs::write(
                dir.join("key.pem"),
                f.leaf.key.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();
            let der_len = f.leaf.x509.to_der().unwrap().len() + f.mid.x509.to_der().unwrap().len();
            let dir_s = dir.to_str().unwrap().to_owned();
            let s = setup(roots(&f));
            let n = 16;
            let (tcp, tcp_peak) = per_connection(&dir_s, true, &s, n).await;
            let (tls, tls_peak) = per_connection(&dir_s, false, &s, n).await;
            let _ = std::fs::remove_dir_all(&dir);
            eprintln!(
                "TURNS-HEAP chain {der_len} B; per connection, {n} at once: plain TCP {tcp} B (peak {tcp_peak}), \
                 TLS {tls} B (peak {tls_peak}); TLS adds {} B at rest, {} B at the peak",
                tls.saturating_sub(tcp),
                tls_peak.saturating_sub(tcp_peak),
            );
            assert!(
                tls.saturating_sub(tcp) <= TLS_BORINGSSL_MAX,
                "TLS adds {} B at rest, over TLS_BORINGSSL_MAX {TLS_BORINGSSL_MAX}",
                tls.saturating_sub(tcp)
            );
            assert!(
                tls_peak.saturating_sub(tcp_peak) <= TLS_BORINGSSL_MAX + TLS_MAX_CERT_LIST,
                "TLS adds {} B at the peak",
                tls_peak.saturating_sub(tcp_peak)
            );
        }

        /// One kept session's heap (the serialised session, BoringSSL's copy
        /// of the chain, the ticket), for a chain of about 5 KiB, against
        /// [`TICKET_HEAP_MAX`].
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "heap measurement: needs the process to itself (--test-threads=1)"]
        async fn heap_a_kept_session() {
            let names: Vec<String> = (0..160).map(|i| format!("pad{i:04}.olc.test")).collect();
            let mut all: Vec<&str> = names.iter().map(String::as_str).collect();
            all.push(HOST);
            let f = fixture(&all, &[]);
            let der_len = f.leaf.x509.to_der().unwrap().len() + f.mid.x509.to_der().unwrap().len();
            let s = setup(roots(&f));
            let servers: Vec<TestServer> = (0..TICKET_SERVERS)
                .map(|_| TestServer::start(server_ctx(&f), vec![5; 20], false))
                .collect();
            // One connection first, for the one-time state.
            {
                let warm = TestServer::start(server_ctx(&f), vec![5; 20], false);
                let mut r = relay(0, HOST, warm.addr, setup(roots(&f)));
                r.send(vec![1; 40]).await;
                assert!(r.collect(20).await.is_some());
                r.close().await;
                eventually("served", || warm.seen(|x| x.closed_clean == 1)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let before = used();
            for srv in &servers {
                let mut r = relay(0, HOST, srv.addr, s.clone());
                r.send(vec![1; 40]).await;
                assert!(r.collect(20).await.is_some());
                r.close().await;
                eventually("served", || srv.seen(|x| x.closed_clean == 1)).await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let held = used().saturating_sub(before);
            assert_eq!(locked(s.cache).len(), TICKET_SERVERS);
            let der: usize = locked(s.cache)
                .list
                .iter()
                .map(|(_, x)| x.to_der().unwrap().len())
                .sum::<usize>()
                / TICKET_SERVERS;
            eprintln!(
                "TURNS-HEAP chain {der_len} B; a kept session: {der} B serialised, {} B of heap \
                 ({} B for {TICKET_SERVERS}); cap {TICKET_HEAP_MAX} B each",
                held / TICKET_SERVERS,
                held
            );
            assert!(held / TICKET_SERVERS <= TICKET_HEAP_MAX);
        }
    }
}

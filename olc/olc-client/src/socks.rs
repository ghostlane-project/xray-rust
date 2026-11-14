// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SOCKS5 front (socks.go, tunnel.go): the method and the RFC 1929 login,
//! one request (`CONNECT`, `UDP ASSOCIATE`, or hev's `FWD_UDP`), all within
//! [`NEGOTIATION_TIMEOUT`]; then a CONNECT waits for the session (one of at
//! most [`crate::client::MAX_PARKED`]), opens a stream and has the exit dial.
//!
//! # Bounds
//!
//! At most [`MAX_SOCKS_CONNS`] connections; each direction borrows a
//! [`crate::copy::COPY_BUFFER`] only while bytes move ([`crate::copy`]), so
//! an idle connection holds none: 2 MiB for the 64 moving connections of
//! the burst, whatever the number open (plan §9: cap 3 MiB at the expected
//! load; 16 MiB only if all 512 moved at once).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use olc_smux::{Session, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::client::{Inner, WaitRefused};
use crate::copy::{copy_bidirectional, CopyEnd, HALF_OPEN_GRACE};
use crate::direct::{classify, Route};
use crate::tunnel::{is_ipv6_literal, rep, reply, send_connect, ConnectError};

/// Bounds everything before the target is known (`socksNegotiationTimeout`).
pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Concurrent SOCKS clients (`maxSocksConns`).
pub const MAX_SOCKS_CONNS: usize = 512;
/// The first pause after a failed accept (`acceptRetryDelay`).
pub const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
/// The longest (`maxAcceptRetryDelay`).
pub const MAX_ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// The SOCKS version.
pub const VERSION: u8 = 5;

/// Commands.
pub mod cmd {
    /// `CONNECT`.
    pub const CONNECT: u8 = 1;
    /// `UDP ASSOCIATE`.
    pub const UDP_ASSOCIATE: u8 = 3;
    /// hev-socks5's `FWD_UDP`: UDP framed on the TCP connection.
    pub const FWD_UDP: u8 = 5;
}

/// Address types.
pub mod atyp {
    /// IPv4.
    pub const IPV4: u8 = 1;
    /// A name.
    pub const DOMAIN: u8 = 3;
    /// IPv6.
    pub const IPV6: u8 = 4;
}

/// The reply that refuses UDP (`REP = 0x07`, command not supported).
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 7;

/// Why a negotiation failed; the texts are Go's.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    /// `ErrInvalidSOCKSVersion`.
    #[error("invalid socks version: {0}")]
    Version(u8),
    /// The login's version.
    #[error("invalid socks version: expected auth version 1, got {0}")]
    AuthVersion(u8),
    /// `ErrSOCKSAuthFailed`.
    #[error("SOCKS5 authentication failed")]
    AuthFailed,
    /// `ErrUnsupportedSOCKSCommand`.
    #[error("unsupported socks command: {0}")]
    Command(u8),
    /// `ErrUnsupportedAddressType`.
    #[error("unsupported address type: {0}")]
    AddressType(u8),
    /// `ErrEmptySOCKSDomain`.
    #[error("empty socks5 domain")]
    EmptyDomain,
    /// UDP is off: `FWD_UDP` got `REP = 0x07`.
    #[error("udp relay disabled")]
    UdpDisabled,
    /// A read or write failed.
    #[error("{0}: {1}")]
    Io(&'static str, #[source] io::Error),
}

/// One parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// [`cmd`].
    pub cmd: u8,
    /// The target as Go's string: dotted IPv4, `net.IP.String` IPv6, or the
    /// name.
    pub addr: String,
    /// The port.
    pub port: u16,
}

/// The method negotiation and, with a user set, the RFC 1929 login
/// (`socks5Handshake`). The offered methods are read and ignored, as Go does.
///
/// # Errors
/// [`SocksError`].
pub async fn handshake<S>(conn: &mut S, user: &str, pass: &str) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    read(conn, &mut header, "read socks5 header").await?;
    if header[0] != VERSION {
        return Err(SocksError::Version(header[0]));
    }
    let mut methods = [0u8; 255];
    read(
        conn,
        &mut methods[..usize::from(header[1])],
        "read socks5 methods",
    )
    .await?;
    if user.is_empty() {
        return write(conn, &[VERSION, 0], "write socks5 auth").await;
    }
    write(conn, &[VERSION, 2], "write socks5 auth method").await?;
    read(conn, &mut header, "read socks5 auth header").await?;
    if header[0] != 1 {
        return Err(SocksError::AuthVersion(header[0]));
    }
    let mut got_user = [0u8; 255];
    let got_user = &mut got_user[..usize::from(header[1])];
    read(conn, got_user, "read socks5 username").await?;
    let mut plen = [0u8; 1];
    read(conn, &mut plen, "read socks5 plen").await?;
    let mut got_pass = [0u8; 255];
    let got_pass = &mut got_pass[..usize::from(plen[0])];
    read(conn, got_pass, "read socks5 password").await?;
    // Both comparisons always run.
    let user_ok = constant_time_eq(got_user, user.as_bytes());
    let pass_ok = constant_time_eq(got_pass, pass.as_bytes());
    if !(user_ok & pass_ok) {
        let _ = conn.write_all(&[1, 1]).await;
        return Err(SocksError::AuthFailed);
    }
    write(conn, &[1, 0], "write socks5 auth success").await
}

/// `subtle.ConstantTimeCompare`: lengths are not secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reads one request (`readSocks5Request`). Go takes CONNECT and UDP
/// ASSOCIATE; `FWD_UDP` is taken too, and refused with `REP = 0x07` before
/// its address is read when `udp_disabled`, as xray-rust does.
///
/// # Errors
/// [`SocksError`]; an unsupported command closes without a reply, as Go.
pub async fn read_request<S>(conn: &mut S, udp_disabled: bool) -> Result<Request, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    read(conn, &mut header, "read socks5 request").await?;
    let command = header[1];
    if !matches!(command, cmd::CONNECT | cmd::UDP_ASSOCIATE | cmd::FWD_UDP) {
        return Err(SocksError::Command(command));
    }
    if command == cmd::FWD_UDP && udp_disabled {
        let _ = conn.write_all(&reply(REP_COMMAND_NOT_SUPPORTED, "")).await;
        return Err(SocksError::UdpDisabled);
    }
    let addr = read_addr(conn, header[3]).await?;
    let mut port = [0u8; 2];
    read(conn, &mut port, "read socks5 port").await?;
    Ok(Request {
        cmd: command,
        addr,
        port: u16::from_be_bytes(port),
    })
}

async fn read_addr<S: AsyncRead + Unpin>(conn: &mut S, kind: u8) -> Result<String, SocksError> {
    match kind {
        atyp::IPV4 => {
            let mut b = [0u8; 4];
            read(conn, &mut b, "read socks5 ipv4").await?;
            Ok(Ipv4Addr::from(b).to_string())
        }
        atyp::IPV6 => {
            let mut b = [0u8; 16];
            read(conn, &mut b, "read socks5 ipv6").await?;
            Ok(go_ip_string(IpAddr::V6(Ipv6Addr::from(b))))
        }
        atyp::DOMAIN => {
            let mut len = [0u8; 1];
            read(conn, &mut len, "read socks5 domain len").await?;
            if len[0] == 0 {
                return Err(SocksError::EmptyDomain);
            }
            let mut b = vec![0u8; usize::from(len[0])];
            read(conn, &mut b, "read socks5 domain").await?;
            Ok(String::from_utf8_lossy(&b).into_owned())
        }
        other => Err(SocksError::AddressType(other)),
    }
}

/// `net.IP.String`: an IPv4-mapped address is dotted, any other IPv6 is
/// RFC 5952 (Go's form, which `udpwire::Host` writes).
pub fn go_ip_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => olc_wire::udpwire::Host::V6(a).to_string(),
        },
    }
}

async fn read<S: AsyncRead + Unpin>(
    conn: &mut S,
    buf: &mut [u8],
    what: &'static str,
) -> Result<(), SocksError> {
    conn.read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|e| SocksError::Io(what, e))
}

async fn write<S: AsyncWrite + Unpin>(
    conn: &mut S,
    buf: &[u8],
    what: &'static str,
) -> Result<(), SocksError> {
    conn.write_all(buf)
        .await
        .map_err(|e| SocksError::Io(what, e))
}

/// One CONNECT on its way out (`connectJob`): the target, what the client
/// sent while it was sniffed, and whether the reply is on the wire.
#[derive(Debug, Default)]
pub(crate) struct Job {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) head: Vec<u8>,
    pub(crate) replied: bool,
}

impl Job {
    /// The reply owed for a CONNECT that will not be served.
    pub(crate) async fn fail(&self, conn: &mut TcpStream, code: u8) {
        if !self.replied {
            let _ = conn.write_all(&reply(code, &self.host)).await;
        }
    }

    /// Success when still owed, then the sniffed bytes into the outbound.
    pub(crate) async fn open<W: AsyncWrite + Unpin>(
        &self,
        conn: &mut TcpStream,
        out: &mut W,
    ) -> bool {
        if !self.replied
            && conn
                .write_all(&reply(rep::SUCCESS, &self.host))
                .await
                .is_err()
        {
            return false;
        }
        self.head.is_empty() || out.write_all(&self.head).await.is_ok()
    }
}

/// A slot among [`MAX_SOCKS_CONNS`], given back on drop.
struct ConnSlot(Arc<Inner>);

impl ConnSlot {
    fn take(inner: &Arc<Inner>) -> Option<Self> {
        let n = inner.socks_conns.fetch_add(1, Ordering::Relaxed);
        if n >= MAX_SOCKS_CONNS {
            inner.socks_conns.fetch_sub(1, Ordering::Relaxed);
            crate::info!(
                "SOCKS5: {MAX_SOCKS_CONNS} concurrent connections reached, refusing new ones"
            );
            return None;
        }
        Some(Self(inner.clone()))
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.socks_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `nextAcceptDelay`.
fn next_accept_delay(current: Duration) -> Duration {
    if current.is_zero() {
        ACCEPT_RETRY_DELAY
    } else {
        (current * 2).min(MAX_ACCEPT_RETRY_DELAY)
    }
}

/// A duration as Go's `%s` prints the ones used here.
pub(crate) fn go_duration(d: Duration) -> String {
    if d < Duration::from_secs(1) {
        format!("{}ms", d.as_millis())
    } else if d.subsec_millis() == 0 {
        let s = d.as_secs();
        if s >= 60 {
            format!("{}m{}s", s / 60, s % 60)
        } else {
            format!("{s}s")
        }
    } else {
        format!("{}s", d.as_secs_f64())
    }
}

impl Inner {
    /// `acceptLoop`.
    pub(crate) async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        let mut delay = Duration::ZERO;
        loop {
            let accepted = tokio::select! {
                () = self.run.cancelled() => return,
                r = listener.accept() => r,
            };
            match accepted {
                Err(e) => {
                    delay = next_accept_delay(delay);
                    crate::info!("Accept error (retry in {}): {e}", go_duration(delay));
                    tokio::select! {
                        () = self.run.cancelled() => return,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
                Ok((conn, _)) => {
                    delay = Duration::ZERO;
                    let Some(slot) = ConnSlot::take(&self) else {
                        continue;
                    };
                    let me = self.clone();
                    tokio::spawn(async move {
                        let _slot = slot;
                        tokio::select! {
                            () = me.run.cancelled() => {}
                            () = me.handle_socks(conn) => {}
                        }
                    });
                }
            }
        }
    }

    /// `handleSocks5`.
    async fn handle_socks(self: &Arc<Self>, mut conn: TcpStream) {
        let negotiated = tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
            handshake(&mut conn, &self.cfg.socks_user, &self.cfg.socks_pass).await?;
            read_request(&mut conn, self.cfg.udp_disabled).await
        })
        .await;
        let req = match negotiated {
            Ok(Ok(req)) => req,
            Ok(Err(e)) => {
                crate::debug!("socks: {e}");
                return;
            }
            Err(_) => return,
        };
        match req.cmd {
            cmd::UDP_ASSOCIATE => self.udp_associate(conn, req).await,
            cmd::FWD_UDP => self.fwd_udp(conn, req).await,
            _ => self.serve_connect(conn, req).await,
        }
    }

    /// `serveConnect`.
    async fn serve_connect(self: &Arc<Self>, conn: TcpStream, req: Request) {
        let job = Job {
            host: req.addr,
            port: req.port,
            ..Job::default()
        };
        match classify(self.rules.as_ref(), &job.host) {
            Route::Direct(reason) => self.dial_direct(conn, job, reason, None).await,
            Route::Sniff => self.sniff_then_route(conn, job).await,
            Route::Tunnel => self.tunnel_when_ready(conn, job).await,
        }
    }

    /// `tunnelWhenReady`.
    async fn tunnel_when_ready(self: &Arc<Self>, mut conn: TcpStream, job: Job) {
        match self.prepare_tunnel(&job.host, job.port).await {
            Ok(stream) => self.pump_tunnel(conn, stream, job).await,
            Err(code) => job.fail(&mut conn, code).await,
        }
    }

    /// `prepareTunnel`: waits for the session, opens a stream and has the
    /// exit dial; the reply code on failure.
    pub(crate) async fn prepare_tunnel(&self, host: &str, port: u16) -> Result<Stream, u8> {
        if is_ipv6_literal(host) && self.no_ipv6_route() {
            return Err(rep::HOST_UNREACHABLE);
        }
        let (session, _) = match self.wait_session().await {
            Ok(s) => s,
            Err(WaitRefused::Saturated) => return Err(rep::NETWORK_UNREACHABLE),
            Err(WaitRefused::Timeout) => return Err(rep::HOST_UNREACHABLE),
        };
        self.open_tunnel(&session, host, port).await
    }

    /// `openTunnel`.
    async fn open_tunnel(&self, session: &Session, host: &str, port: u16) -> Result<Stream, u8> {
        let mut stream = match session.open_stream().await {
            Ok(s) => s,
            Err(e) => {
                crate::info!("OpenStream failed: {e}");
                return Err(rep::HOST_UNREACHABLE);
            }
        };
        crate::info!("sid={} tunnel to {host}:{port}", stream.id());
        match send_connect(&mut stream, host, port).await {
            Ok(()) => {
                if is_ipv6_literal(host) {
                    self.note_ipv6_ok();
                }
                Ok(stream)
            }
            Err(e) => {
                crate::info!("sid={} connect failed: {e}", stream.id());
                if let ConnectError::Refused(r) = &e {
                    if r.code == rep::HOST_UNREACHABLE && is_ipv6_literal(host) {
                        self.note_ipv6_unreachable(host);
                    }
                }
                Err(e.reply_code())
            }
        }
    }

    /// `pumpTunnel`.
    pub(crate) async fn pump_tunnel(&self, mut conn: TcpStream, mut stream: Stream, job: Job) {
        if !job.open(&mut conn, &mut stream).await {
            return;
        }
        // Its sniffed bytes are sent: they are not held for the copy's life.
        drop(job);
        let sid = stream.id();
        let (_, end) = copy_bidirectional(conn, stream, true, HALF_OPEN_GRACE, &self.run).await;
        if matches!(end, CopyEnd::HalfOpenIdle) {
            crate::debug!("sid={sid} closed: half-open and silent for 1m0s");
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn no_login_answers_method_zero_and_reads_a_connect() {
        crate::testing::bounded(no_login_answers_method_zero_and_reads_a_connect_body()).await;
    }

    async fn no_login_answers_method_zero_and_reads_a_connect_body() {
        let (mut client, mut server) = duplex(256);
        let srv = tokio::spawn(async move {
            handshake(&mut server, "", "").await.unwrap();
            read_request(&mut server, false).await.unwrap()
        });
        client.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut m = [0u8; 2];
        client.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, 0]);
        client
            .write_all(&[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                1, 187,
            ])
            .await
            .unwrap();
        let req = srv.await.unwrap();
        assert_eq!(
            req,
            Request {
                cmd: cmd::CONNECT,
                addr: "example.com".into(),
                port: 443
            }
        );
    }

    #[tokio::test]
    async fn a_login_is_checked_and_a_wrong_one_gets_1_1() {
        crate::testing::bounded(a_login_is_checked_and_a_wrong_one_gets_1_1_body()).await;
    }

    async fn a_login_is_checked_and_a_wrong_one_gets_1_1_body() {
        for (user, pass, ok) in [
            (&b"u"[..], &b"p"[..], true),
            (b"u", b"x", false),
            (b"uu", b"p", false),
        ] {
            let (mut client, mut server) = duplex(256);
            let srv = tokio::spawn(async move { handshake(&mut server, "u", "p").await });
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [5, 2]);
            let mut login = vec![1, u8::try_from(user.len()).unwrap()];
            login.extend_from_slice(user);
            login.push(u8::try_from(pass.len()).unwrap());
            login.extend_from_slice(pass);
            client.write_all(&login).await.unwrap();
            client.read_exact(&mut m).await.unwrap();
            assert_eq!(m, if ok { [1, 0] } else { [1, 1] });
            let r = srv.await.unwrap();
            assert_eq!(r.is_ok(), ok);
            if !ok {
                assert_eq!(r.unwrap_err().to_string(), "SOCKS5 authentication failed");
            }
        }
    }

    #[tokio::test]
    async fn requests_read_as_gos_and_fwd_udp_is_refused_with_7_when_udp_is_off() {
        crate::testing::bounded(
            requests_read_as_gos_and_fwd_udp_is_refused_with_7_when_udp_is_off_body(),
        )
        .await;
    }

    async fn requests_read_as_gos_and_fwd_udp_is_refused_with_7_when_udp_is_off_body() {
        let (mut client, mut server) = duplex(256);
        let mut v6 = vec![5, 3, 0, 4];
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0, 53]);
        client.write_all(&v6).await.unwrap();
        let req = read_request(&mut server, false).await.unwrap();
        assert_eq!(
            (req.cmd, req.addr.as_str(), req.port),
            (cmd::UDP_ASSOCIATE, "2001:db8::1", 53)
        );
        let mut mapped = vec![5, 1, 0, 4];
        mapped.extend_from_slice(&Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped().octets());
        mapped.extend_from_slice(&[0, 80]);
        client.write_all(&mapped).await.unwrap();
        assert_eq!(
            read_request(&mut server, false).await.unwrap().addr,
            "1.2.3.4"
        );
        client.write_all(&[5, 2, 0, 1]).await.unwrap();
        assert_eq!(
            read_request(&mut server, false)
                .await
                .unwrap_err()
                .to_string(),
            "unsupported socks command: 2"
        );
        client.write_all(&[5, 1, 0, 3, 0]).await.unwrap();
        assert!(matches!(
            read_request(&mut server, false).await,
            Err(SocksError::EmptyDomain)
        ));
        client.write_all(&[5, 5, 0, 1]).await.unwrap();
        assert!(matches!(
            read_request(&mut server, true).await,
            Err(SocksError::UdpDisabled)
        ));
        let mut r = [0u8; 10];
        client.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn accept_delays_and_durations_print_as_gos() {
        let mut d = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..9 {
            d = next_accept_delay(d);
            seen.push(go_duration(d));
        }
        assert_eq!(
            seen,
            ["10ms", "20ms", "40ms", "80ms", "160ms", "320ms", "640ms", "1s", "1s"]
        );
        assert_eq!(go_duration(Duration::from_secs(120)), "2m0s");
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Every socket the engine opens (`internal/protect`): each goes through the
//! host's protector first ([`set_protector`]: Android's
//! `VpnService.protect`, the iOS extension's interface pin), so the engine's
//! own traffic never loops into the tunnel it carries. A protector that
//! refuses a socket fails the dial with Go's words. A protector installed
//! with [`set_peer_protector`] is told, beside the socket, the address a TCP
//! socket dials ([`protect_to`]); one installed with [`set_protector`] is
//! handed every socket as before.
//!
//! Names are looked up by the [`crate::resolver`] ring when one is set, else
//! by the system.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Decides whether a socket may be used; `false` refuses it
/// (`protect.SetProtector`).
pub type Protector = Arc<dyn Fn(RawFd) -> bool + Send + Sync>;

/// A [`Protector`] that is also told where the socket goes: the address a
/// TCP socket dials, `None` where the engine does not know it (a UDP socket,
/// bound before its peers are known).
pub type PeerProtector = Arc<dyn Fn(RawFd, Option<SocketAddr>) -> bool + Send + Sync>;

static PROTECTOR: RwLock<Option<PeerProtector>> = RwLock::new(None);

/// Go's dial timeout for the engine's own connections (`defaultDialTimeout`).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Installs the protector; `None` removes it.
pub fn set_protector(p: Option<Protector>) {
    set_peer_protector(p.map(|p| -> PeerProtector { Arc::new(move |fd, _peer| p(fd)) }));
}

/// Installs a protector that is told the peer; `None` removes it. It takes
/// the place of one installed with [`set_protector`].
pub fn set_peer_protector(p: Option<PeerProtector>) {
    *PROTECTOR.write().unwrap_or_else(PoisonError::into_inner) = p;
}

/// Whether a protector is installed (`protect.HasProtector`).
pub fn has_protector() -> bool {
    PROTECTOR
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

/// Runs the protector on a socket, if there is one.
///
/// # Errors
/// `protect: socket protector rejected the socket`.
pub fn protect(fd: RawFd) -> io::Result<()> {
    protect_peer(fd, None)
}

/// [`protect`] for a socket that will connect or send to `peer`.
///
/// # Errors
/// As [`protect`].
pub fn protect_to(fd: RawFd, peer: SocketAddr) -> io::Result<()> {
    protect_peer(fd, Some(peer))
}

fn protect_peer(fd: RawFd, peer: Option<SocketAddr>) -> io::Result<()> {
    let p = PROTECTOR
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    match p {
        Some(p) if !p(fd, peer) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protect: socket protector rejected the socket",
        )),
        _ => Ok(()),
    }
}

/// Dials `addr` over TCP from a protected socket, within [`DIAL_TIMEOUT`].
///
/// # Errors
/// The protector's refusal, the dial's error, or a timeout.
pub async fn dial_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    dial_tcp_with(addr, None).await
}

/// A protected TCP socket for `addr`'s family; `send_buffer`, when given,
/// bounds what the kernel holds unsent (`SO_SNDBUF`), set before the dial so
/// autotuning never grows it.
fn tcp_socket(addr: SocketAddr, send_buffer: Option<u32>) -> io::Result<TcpSocket> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect(socket.as_raw_fd())?;
    if let Some(n) = send_buffer {
        socket.set_send_buffer_size(n)?;
    }
    Ok(socket)
}

/// [`dial_tcp`] with the kernel's send buffer bounded to `send_buffer`.
///
/// # Errors
/// As [`dial_tcp`], or the socket option's.
pub async fn dial_tcp_with(addr: SocketAddr, send_buffer: Option<u32>) -> io::Result<TcpStream> {
    let socket = tcp_socket(addr, send_buffer)?;
    match tokio::time::timeout(DIAL_TIMEOUT, socket.connect(addr)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("dial tcp {addr}: i/o timeout"),
        )),
    }
}

/// Dials `host:port` (a name or a literal) over TCP: every address the
/// lookup gives, in order, until one answers.
///
/// # Errors
/// The last dial's error, or the lookup's.
pub async fn dial_tcp_host(host_port: &str) -> io::Result<TcpStream> {
    dial_tcp_host_with(host_port, None).await
}

/// [`dial_tcp_host`] with the kernel's send buffer bounded to `send_buffer`.
///
/// # Errors
/// As [`dial_tcp_host`].
pub async fn dial_tcp_host_with(
    host_port: &str,
    send_buffer: Option<u32>,
) -> io::Result<TcpStream> {
    let (host, port) = split_host_port(host_port)?;
    let addrs = crate::resolver::lookup(host).await?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
    for ip in addrs {
        match dial_tcp_with(SocketAddr::new(ip, port), send_buffer).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// A UDP socket bound to the unspecified address of `family`'s kind,
/// protected.
///
/// # Errors
/// The bind's error or the protector's refusal.
pub async fn udp_socket(family: IpAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = if family.is_ipv4() {
        "0.0.0.0:0".parse().expect("literal")
    } else {
        "[::]:0".parse().expect("literal")
    };
    let socket = UdpSocket::bind(bind).await?;
    protect(socket.as_raw_fd())?;
    Ok(socket)
}

/// Whether the host protector accepts a socket right now
/// (`protect.ProbeRoute`).
///
/// It is a statement about the device, not about any host. The iOS pin
/// refuses every socket while no physical interface carries traffic out,
/// and that refusal is all the engine sees of a phone that has just lost
/// its network: every dial fails at once. Asking with one socket that is
/// never used lets a reconnect wait for the route instead of dialing to
/// learn the same thing. Without a protector there is nothing to ask.
///
/// One UDP socket is opened, shown to the protector and closed: IPv4, then
/// IPv6 when that one could not be opened or was refused. Nothing is sent.
#[must_use]
pub fn probe_route() -> bool {
    if !has_protector() {
        return true;
    }
    ["0.0.0.0:0", "[::]:0"].into_iter().any(|bind| {
        std::net::UdpSocket::bind(bind).is_ok_and(|socket| protect(socket.as_raw_fd()).is_ok())
    })
}

/// Splits `host:port`, `[v6]:port` included.
///
/// # Errors
/// `InvalidInput` for an address without a port.
pub fn split_host_port(s: &str) -> io::Result<(&str, u16)> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("address {s}: missing port"),
        )
    };
    let (host, port) = s.rsplit_once(':').ok_or_else(bad)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = port.parse().map_err(|_| bad())?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_send_buffer_bound_is_set_on_the_socket_before_it_dials() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let bounded = tcp_socket(addr, Some(512 * 1024)).unwrap();
        // Linux keeps twice what was asked (the kernel's bookkeeping share).
        let got = bounded.send_buffer_size().unwrap();
        assert!((512 * 1024..=1024 * 1024).contains(&got), "{got}");
        let small = tcp_socket(addr, Some(64 * 1024)).unwrap();
        assert!(small.send_buffer_size().unwrap() < got);
    }

    #[test]
    fn host_port_splits_as_go() {
        assert_eq!(split_host_port("1.2.3.4:53").unwrap(), ("1.2.3.4", 53));
        assert_eq!(split_host_port("[::1]:443").unwrap(), ("::1", 443));
        assert_eq!(split_host_port("a.example:80").unwrap(), ("a.example", 80));
        assert!(split_host_port("a.example").is_err());
    }
}

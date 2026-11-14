// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Every socket the engine opens (`internal/protect`): each goes through the
//! host's protector first ([`set_protector`]: Android's
//! `VpnService.protect`, the iOS extension's interface pin), so the engine's
//! own traffic never loops into the tunnel it carries. A protector that
//! refuses a socket fails the dial with Go's words.
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

static PROTECTOR: RwLock<Option<Protector>> = RwLock::new(None);

/// Go's dial timeout for the engine's own connections (`defaultDialTimeout`).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Installs the protector; `None` removes it.
pub fn set_protector(p: Option<Protector>) {
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
    let p = PROTECTOR
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    match p {
        Some(p) if !p(fd) => Err(io::Error::new(
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
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect(socket.as_raw_fd())?;
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
    let (host, port) = split_host_port(host_port)?;
    let addrs = crate::resolver::lookup(host).await?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
    for ip in addrs {
        match dial_tcp(SocketAddr::new(ip, port)).await {
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

/// Splits `host:port`, `[v6]:port` included.
///
/// # Errors
/// `InvalidInput` for an address without a port.
pub fn split_host_port(s: &str) -> io::Result<(&str, u16)> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("address {s}: missing port"));
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
    fn host_port_splits_as_go() {
        assert_eq!(split_host_port("1.2.3.4:53").unwrap(), ("1.2.3.4", 53));
        assert_eq!(split_host_port("[::1]:443").unwrap(), ("::1", 443));
        assert_eq!(split_host_port("a.example:80").unwrap(), ("a.example", 80));
        assert!(split_host_port("a.example").is_err());
    }

}

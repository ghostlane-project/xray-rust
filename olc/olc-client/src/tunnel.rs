// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A CONNECT through the tunnel (tunnel.go): a smux stream, the CONNECT
//! request on it (`{"addr":…,"cmd":"connect","port":…}`, written within
//! [`WRITE_TIMEOUT`]), the server's one-byte ack within [`ACK_TIMEOUT`],
//! and the SOCKS reply that follows from it.

use std::io;
use std::net::IpAddr;

use olc_smux::Stream;
use olc_wire::connect::{check_ack, encode_request, AckRefused, ACK_TIMEOUT, WRITE_TIMEOUT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The SOCKS reply codes the client sends.
pub mod rep {
    /// Succeeded.
    pub const SUCCESS: u8 = 0;
    /// No way out: no session, or too many requests wait for one.
    pub const NETWORK_UNREACHABLE: u8 = 3;
    /// The target could not be reached.
    pub const HOST_UNREACHABLE: u8 = 4;
}

/// Why a CONNECT request failed.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The request did not go out (`write connect req`).
    #[error("sid={sid} write connect req: {err}")]
    Write {
        /// The stream.
        sid: u32,
        /// Why.
        err: io::Error,
    },
    /// No ack came (`ErrRemoteNotReady`).
    #[error("sid={sid}: remote not ready (read_err={err})")]
    NotReady {
        /// The stream.
        sid: u32,
        /// Why.
        err: io::Error,
    },
    /// The server refused with this code.
    #[error(transparent)]
    Refused(#[from] AckRefused),
}

impl ConnectError {
    /// The SOCKS reply for this failure (`replyForConnectError`): the
    /// server's code when it sent one, host unreachable otherwise.
    pub fn reply_code(&self) -> u8 {
        match self {
            Self::Refused(r) => r.code,
            _ => rep::HOST_UNREACHABLE,
        }
    }
}

/// Sends the CONNECT request for `host:port` on `stream` and reads its ack
/// (`sendConnectRequest`).
///
/// # Errors
/// [`ConnectError`].
pub async fn send_connect(stream: &mut Stream, host: &str, port: u16) -> Result<(), ConnectError> {
    let sid = stream.id();
    let mut req = Vec::with_capacity(48 + host.len());
    encode_request(host.as_bytes(), port, &mut req);
    match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&req)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(ConnectError::Write { sid, err }),
        Err(_) => {
            return Err(ConnectError::Write {
                sid,
                err: io::Error::new(io::ErrorKind::TimedOut, "timeout"),
            })
        }
    }
    let mut ack = [0u8; 1];
    match tokio::time::timeout(ACK_TIMEOUT, stream.read_exact(&mut ack)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => return Err(ConnectError::NotReady { sid, err }),
        Err(_) => {
            return Err(ConnectError::NotReady {
                sid,
                err: io::Error::new(io::ErrorKind::TimedOut, "timeout"),
            })
        }
    }
    check_ack(ack[0], sid)?;
    Ok(())
}

/// A SOCKS5 reply with code `rep` (`socks5Reply`): the bound address is
/// zero, IPv6 when the target is an IPv6 literal, IPv4 otherwise.
pub fn reply(rep: u8, target: &str) -> Vec<u8> {
    let v6 = matches!(target.parse::<IpAddr>(), Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none());
    let (atyp, len) = if v6 { (4u8, 16) } else { (1u8, 4) };
    let mut out = vec![0u8; 4 + len + 2];
    out[0] = 5;
    out[1] = rep;
    out[3] = atyp;
    out
}

/// Whether `target` is an IPv6 literal (`isIPv6Literal`).
pub fn is_ipv6_literal(target: &str) -> bool {
    matches!(target.parse::<IpAddr>(), Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_are_gos() {
        assert_eq!(reply(rep::SUCCESS, "example.com"), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply(rep::HOST_UNREACHABLE, "10.0.0.1"), [5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        let v6 = reply(rep::NETWORK_UNREACHABLE, "2001:db8::1");
        assert_eq!(v6.len(), 22);
        assert_eq!(&v6[..4], &[5, 3, 0, 4]);
        // Go's To4() reads a mapped address as IPv4.
        assert_eq!(reply(rep::SUCCESS, "::ffff:1.2.3.4").len(), 10);
        assert!(is_ipv6_literal("::1") && !is_ipv6_literal("::ffff:1.2.3.4") && !is_ipv6_literal("a"));
    }
}

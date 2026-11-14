// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! ICE credentials and the local address a host candidate names.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

use rand::Rng;
use str0m::IceCreds;

/// The characters an ICE ufrag and password are drawn from (RFC 8839
/// `ice-char`: ALPHA / DIGIT / "+" / "/"), as Chrome draws them.
const ICE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Chrome's ufrag length (`ICE_UFRAG_LENGTH`, webrtc p2p/base/p2p_constants).
pub const UFRAG_LEN: usize = 4;
/// Chrome's password length (`ICE_PWD_LENGTH`).
pub const PWD_LEN: usize = 24;

/// Fresh credentials of Chrome's sizes.
#[must_use]
pub fn chrome_creds() -> IceCreds {
    IceCreds {
        ufrag: ice_chars(UFRAG_LEN),
        pass: ice_chars(PWD_LEN),
    }
}

fn ice_chars(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| char::from(ICE_CHARS[rng.gen_range(0..ICE_CHARS.len())]))
        .collect()
}

/// The address the host's default IPv4 route leaves from, as a browser's
/// host candidate names it. The probe socket is protected first, so under a
/// VPN the answer is the physical interface's address, not the tunnel's; it
/// is connected, never written to.
///
/// # Errors
/// No IPv4 route, or the protector refused the probe socket.
pub fn default_ipv4() -> io::Result<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    olc_net::net::protect(s.as_raw_fd())?;
    // TEST-NET-1 (RFC 5737): routed like the internet, never answered.
    s.connect(SocketAddr::from(([192, 0, 2, 1], 9)))?;
    let ip = s.local_addr()?.ip();
    if ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv4 address on the default route",
        ));
    }
    Ok(ip)
}

/// The ufrag a candidate line or an SDP names (`a=ice-ufrag:` or the
/// `ufrag` extension of a candidate), as Go's `ufragFromSDP`.
#[must_use]
pub fn ufrag_from_sdp(sdp: &str) -> Option<&str> {
    sdp.lines()
        .find_map(|l| l.trim_end().strip_prefix("a=ice-ufrag:"))
        .map(str::trim)
        .filter(|u| !u.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_have_chromes_sizes_and_alphabet() {
        let a = chrome_creds();
        let b = chrome_creds();
        assert_eq!(a.ufrag.len(), 4);
        assert_eq!(a.pass.len(), 24);
        assert!(a
            .ufrag
            .bytes()
            .chain(a.pass.bytes())
            .all(|c| ICE_CHARS.contains(&c)));
        assert_ne!(a.pass, b.pass);
    }

    #[test]
    fn the_ufrag_is_read_from_an_sdp() {
        let sdp = "v=0\r\na=group:BUNDLE 0\r\na=ice-ufrag:AbC9\r\na=ice-pwd:x\r\n";
        assert_eq!(ufrag_from_sdp(sdp), Some("AbC9"));
        assert_eq!(ufrag_from_sdp("v=0\r\n"), None);
    }
}

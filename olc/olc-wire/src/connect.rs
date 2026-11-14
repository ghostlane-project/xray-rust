//! The CONNECT request that opens a tunnel stream (`internal/client/tunnel.go`).
//!
//! On a new smux stream the client writes, in one write and with no length
//! prefix, the JSON `json.Marshal(map[string]any{"cmd": "connect", "addr":
//! host, "port": port})` makes, keys sorted: `{"addr":…,"cmd":"connect",
//! "port":…}` (tunnel.go:95-104). It then writes nothing more until the
//! server's one-byte ack (tunnel.go:107-116): [`ACK_OK`], or a SOCKS reply
//! code the client hands its SOCKS client as is ([`check_ack`]).
//!
//! The server reads until the bytes so far parse as a request, at most
//! [`MAX_REQUEST_SIZE`] of them, for at most [`REQUEST_TIMEOUT`]
//! (server/serve.go:226-247), and refuses an empty host or a port outside
//! 1..=65535 (server/egress.go:183-195).

use std::time::Duration;

use crate::gojson;

/// The ack of a target the exit has dialled (tunnelcore/core.go:19).
pub const ACK_OK: u8 = 0x00;
/// The ack of a target the exit could not reach: SOCKS5 "host unreachable"
/// (tunnelcore/core.go:20).
pub const ACK_HOST_UNREACHABLE: u8 = 0x04;
/// The request's command (tunnel.go:97; server/egress.go).
pub const COMMAND: &str = "connect";
/// The server reads at most this much request (server/serve.go:226).
pub const MAX_REQUEST_SIZE: usize = 4096;
/// The client's write deadline for the request (tunnel.go:102).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the client waits for the ack (runtime.go:189-195).
pub const ACK_TIMEOUT: Duration = Duration::from_secs(90);
/// How long the server waits for the request; longer than [`ACK_TIMEOUT`] so
/// the client is the side that gives up (runtime.go:165-200).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Appends the request for `host`:`port` to `out` (tunnel.go:96-98). `host`
/// is written as Go writes a string of these bytes (see [`gojson`]).
pub fn encode_request(host: &[u8], port: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(b"{\"addr\":");
    gojson::write_string(out, host);
    out.extend_from_slice(b",\"cmd\":\"connect\",\"port\":");
    gojson::write_u64(out, u64::from(port));
    out.push(b'}');
}

/// The server answered a request with an ack other than [`ACK_OK`]
/// (`connectAckError`, tunnel.go:186-195). The code is the SOCKS5 reply to
/// give the SOCKS client (tunnel.go:197-203); the message is Go's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sid={stream_id}: remote not ready (connect ack=0x{code:02x})")]
pub struct AckRefused {
    /// The smux stream the request went out on.
    pub stream_id: u32,
    /// The ack byte.
    pub code: u8,
}

/// Reads the ack byte of the request on `stream_id` (tunnel.go:113-115).
///
/// # Errors
/// [`AckRefused`] for any byte but [`ACK_OK`].
pub const fn check_ack(code: u8, stream_id: u32) -> Result<(), AckRefused> {
    if code == ACK_OK {
        Ok(())
    } else {
        Err(AckRefused { stream_id, code })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_come_sorted() {
        let mut out = Vec::new();
        encode_request(b"example.com", 443, &mut out);
        assert_eq!(out, br#"{"addr":"example.com","cmd":"connect","port":443}"#);
        assert!(out.len() < MAX_REQUEST_SIZE);
    }

    #[test]
    fn acks() {
        assert_eq!(check_ack(ACK_OK, 3), Ok(()));
        let refused = check_ack(ACK_HOST_UNREACHABLE, 3).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "sid=3: remote not ready (connect ack=0x04)"
        );
    }
}

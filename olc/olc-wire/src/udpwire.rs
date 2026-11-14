//! The UDP lane's messages (`internal/udpwire/wire.go`), sealed one per record
//! on the `olcrtc/udp/v1` lane.
//!
//! ```text
//! "OU" | version 1 | type | flow id u64 BE | addr type | port u16 BE | addr len
//!   2  |     1     |  1   |        8       |     1     |      2      |    1     = 16
//! then addr len bytes of address, then the payload (at most 1200 bytes).
//! ```
//!
//! A host is carried as Go carries it, a string, and encoded as `encodeHost`
//! decides (wire.go:174-196): what `netip.ParseAddr` reads as IPv4 is 4
//! bytes, what it reads as IPv6 is 16 (a zone is dropped, an IPv4-mapped
//! address stays 16), and anything else is a name of printable ASCII without
//! spaces. [`encode`] ports `ParseAddr` byte for byte (Go 1.26
//! `net/netip/netip.go`), since Rust's parsers draw the line elsewhere (a
//! zone, a bracket). A decoded host prints as `netip.Addr.String` does
//! ([`Host`]'s `Display`).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The wire version (wire.go:15-16).
pub const VERSION: u8 = 1;
/// The largest payload, below common WebRTC and QUIC MTUs (wire.go:17-18).
pub const MAX_PAYLOAD_SIZE: usize = 1200;
/// The longest name (wire.go:19-20).
pub const MAX_HOST_LEN: usize = 255;
/// The fixed header (wire.go:23-26).
pub const HEADER_LEN: usize = 16;
/// The marker (wire.go:28).
pub const MAGIC: [u8; 2] = *b"OU";
/// The longest frame: header, the longest name, the largest payload.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_HOST_LEN + MAX_PAYLOAD_SIZE;

const ADDR_NONE: u8 = 0;
const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 3;
const ADDR_IPV6: u8 = 4;

/// What a frame means (wire.go:47-55).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// One datagram to or from an endpoint.
    Packet = 1,
    /// The flow is over; no endpoint, no payload.
    Close = 2,
}

impl FrameType {
    /// The type of a wire byte; `None` for a type Go refuses.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Packet),
            2 => Some(Self::Close),
            _ => None,
        }
    }
}

/// Why a frame was refused (wire.go:30-45). [`Error::verdict`] names it as
/// the vectors do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Shorter than the header, or than the header and its address.
    #[error("udpwire: frame too short")]
    TooShort,
    /// Not `OU`.
    #[error("udpwire: bad magic")]
    BadMagic,
    /// Another version.
    #[error("udpwire: unsupported version: {0}")]
    UnsupportedVersion(u8),
    /// Neither a packet nor a close.
    #[error("udpwire: unknown frame type: {0}")]
    UnknownType(u8),
    /// Flow 0 is reserved.
    #[error("udpwire: invalid flow id")]
    InvalidFlowId,
    /// A packet without a usable endpoint, a close with one, or an address
    /// that does not read.
    #[error("udpwire: invalid endpoint")]
    InvalidEndpoint,
    /// Over [`MAX_PAYLOAD_SIZE`].
    #[error("udpwire: payload too large")]
    PayloadTooLarge,
}

impl Error {
    /// The verdict's name in the vectors.
    #[must_use]
    pub const fn verdict(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::BadMagic => "bad_magic",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::UnknownType(_) => "unknown_type",
            Self::InvalidFlowId => "invalid_flow_id",
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::PayloadTooLarge => "payload_too_large",
        }
    }
}

/// A decoded endpoint host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
    /// No address: a close.
    None,
    /// Four bytes.
    V4(Ipv4Addr),
    /// Sixteen bytes.
    V6(Ipv6Addr),
    /// A name: 1..=255 bytes of `!`..=`~`.
    Domain(&'a str),
}

impl fmt::Display for Host<'_> {
    /// As Go's `netip.Addr.String` (or the name itself; nothing for none).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write_go_ipv6(f, a),
            Self::Domain(name) => f.write_str(name),
        }
    }
}

/// `netip.Addr.String` of a 16-byte address: `::ffff:` and dotted quad for
/// an IPv4-mapped one, else RFC 5952 with the first of the longest runs of
/// two or more zero groups shortened (`appendTo6`).
fn write_go_ipv6(f: &mut fmt::Formatter<'_>, a: &Ipv6Addr) -> fmt::Result {
    let o = a.octets();
    if o[..10] == [0; 10] && o[10] == 0xff && o[11] == 0xff {
        return write!(f, "::ffff:{}.{}.{}.{}", o[12], o[13], o[14], o[15]);
    }
    let g = a.segments();
    let (mut zero_start, mut zero_end) = (8usize, 8usize);
    for i in 0..8 {
        let mut j = i;
        while j < 8 && g[j] == 0 {
            j += 1;
        }
        if j - i >= 2 && j - i > zero_end - zero_start {
            (zero_start, zero_end) = (i, j);
        }
    }
    let mut i = 0;
    while i < 8 {
        if i == zero_start {
            f.write_str("::")?;
            i = zero_end;
            if i >= 8 {
                break;
            }
        } else if i > 0 {
            f.write_str(":")?;
        }
        write!(f, "{:x}", g[i])?;
        i += 1;
    }
    Ok(())
}

/// One decoded frame; the host and payload borrow the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Packet or close.
    pub kind: FrameType,
    /// The flow, never 0.
    pub flow_id: u64,
    /// The endpoint's host; [`Host::None`] on a close.
    pub host: Host<'a>,
    /// The endpoint's port; 0 on a close.
    pub port: u16,
    /// The datagram; empty on a close.
    pub payload: &'a [u8],
}

/// Appends the frame Go's `Encode` makes of a host string (wire.go:79-103).
/// `host` is the bytes of the Go string; on a close it must be empty.
///
/// # Errors
/// The [`Error`] Go gives, checked in Go's order; `out` is then unchanged.
pub fn encode(
    kind: FrameType,
    flow_id: u64,
    host: &[u8],
    port: u16,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    validate(kind, flow_id, host.is_empty(), port, payload)?;
    // A packet's host is not empty here. Go also refuses a host that is all
    // white space (`strings.TrimSpace`); such a host is never an address and
    // never a name either, so `encode_host` refuses it the same way.
    let (addr_type, addr) = match kind {
        FrameType::Close => (ADDR_NONE, EncodedHost::None),
        FrameType::Packet => encode_host(host)?,
    };
    write(
        kind,
        flow_id,
        addr_type,
        addr.bytes(host),
        port,
        payload,
        out,
    );
    Ok(())
}

fn write(
    kind: FrameType,
    flow_id: u64,
    addr_type: u8,
    addr: &[u8],
    port: u16,
    payload: &[u8],
    out: &mut Vec<u8>,
) {
    out.reserve(HEADER_LEN + addr.len() + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&flow_id.to_be_bytes());
    out.push(addr_type);
    out.extend_from_slice(&port.to_be_bytes());
    out.push(u8::try_from(addr.len()).expect("an address is at most 255 bytes"));
    out.extend_from_slice(addr);
    out.extend_from_slice(payload);
}

impl Frame<'_> {
    /// Appends this frame as Go encodes it after decoding it. An address
    /// goes out as the same bytes (`netip` prints and reads it back to the
    /// same address); a name goes through `encode_host` again, so a name that
    /// reads as an address goes out as one, as in Go.
    ///
    /// # Errors
    /// As [`encode`].
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut buf = [0u8; 16];
        let (addr_type, len) = match self.host {
            Host::None => {
                return encode(self.kind, self.flow_id, b"", self.port, self.payload, out)
            }
            Host::Domain(name) => {
                return encode(
                    self.kind,
                    self.flow_id,
                    name.as_bytes(),
                    self.port,
                    self.payload,
                    out,
                )
            }
            Host::V4(a) => {
                buf[..4].copy_from_slice(&a.octets());
                (ADDR_IPV4, 4)
            }
            Host::V6(a) => {
                buf = a.octets();
                (ADDR_IPV6, 16)
            }
        };
        validate(self.kind, self.flow_id, false, self.port, self.payload)?;
        write(
            self.kind,
            self.flow_id,
            addr_type,
            &buf[..len],
            self.port,
            self.payload,
            out,
        );
        Ok(())
    }
}

/// Reads one frame (wire.go:109-150). The host and payload borrow `data`.
///
/// # Errors
/// The [`Error`] Go gives, checked in Go's order.
pub fn decode(data: &[u8]) -> Result<Frame<'_>, Error> {
    if data.len() < HEADER_LEN {
        return Err(Error::TooShort);
    }
    if data[..2] != MAGIC {
        return Err(Error::BadMagic);
    }
    if data[2] != VERSION {
        return Err(Error::UnsupportedVersion(data[2]));
    }
    let kind = FrameType::from_byte(data[3]).ok_or(Error::UnknownType(data[3]))?;
    let flow_id = u64::from_be_bytes(data[4..12].try_into().expect("8 bytes"));
    if flow_id == 0 {
        return Err(Error::InvalidFlowId);
    }
    let addr_type = data[12];
    let port = u16::from_be_bytes([data[13], data[14]]);
    let addr_len = usize::from(data[15]);
    let Some(raw) = data.get(HEADER_LEN..HEADER_LEN + addr_len) else {
        return Err(Error::TooShort);
    };
    let host = decode_host(addr_type, raw)?;
    let payload = &data[HEADER_LEN + addr_len..];
    validate(kind, flow_id, host == Host::None, port, payload)?;
    Ok(Frame {
        kind,
        flow_id,
        host,
        port,
        payload,
    })
}

/// `validateFrame` (wire.go:152-172), less its type check, which the type
/// system makes, and its white-space check (see [`encode`]).
fn validate(
    kind: FrameType,
    flow_id: u64,
    no_host: bool,
    port: u16,
    payload: &[u8],
) -> Result<(), Error> {
    if flow_id == 0 {
        return Err(Error::InvalidFlowId);
    }
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadTooLarge);
    }
    let usable = match kind {
        FrameType::Close => no_host && port == 0 && payload.is_empty(),
        FrameType::Packet => !no_host && port != 0,
    };
    if usable {
        Ok(())
    } else {
        Err(Error::InvalidEndpoint)
    }
}

enum EncodedHost {
    None,
    V4([u8; 4]),
    V6([u8; 16]),
    Domain,
}

impl EncodedHost {
    fn bytes<'a>(&'a self, host: &'a [u8]) -> &'a [u8] {
        match self {
            Self::None => &[],
            Self::V4(a) => a,
            Self::V6(a) => a,
            Self::Domain => host,
        }
    }
}

/// `encodeHost` (wire.go:174-196) of a non-empty host.
fn encode_host(host: &[u8]) -> Result<(u8, EncodedHost), Error> {
    match parse_addr(host) {
        Some(Parsed::V4(a)) => Ok((ADDR_IPV4, EncodedHost::V4(a))),
        Some(Parsed::V6(a)) => Ok((ADDR_IPV6, EncodedHost::V6(a))),
        None if is_name(host) => Ok((ADDR_DOMAIN, EncodedHost::Domain)),
        None => Err(Error::InvalidEndpoint),
    }
}

/// A name Go accepts: at most 255 bytes, every rune in `!`..=`~`. A byte
/// outside ASCII makes a rune above `~` (or U+FFFD), so bytes will do.
fn is_name(host: &[u8]) -> bool {
    host.len() <= MAX_HOST_LEN && host.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// `decodeHost` (wire.go:198-231).
fn decode_host(addr_type: u8, raw: &[u8]) -> Result<Host<'_>, Error> {
    match addr_type {
        ADDR_NONE if raw.is_empty() => Ok(Host::None),
        ADDR_IPV4 => <[u8; 4]>::try_from(raw)
            .map(|a| Host::V4(Ipv4Addr::from(a)))
            .map_err(|_| Error::InvalidEndpoint),
        ADDR_IPV6 => <[u8; 16]>::try_from(raw)
            .map(|a| Host::V6(Ipv6Addr::from(a)))
            .map_err(|_| Error::InvalidEndpoint),
        ADDR_DOMAIN if !raw.is_empty() && is_name(raw) => Ok(Host::Domain(
            std::str::from_utf8(raw).expect("printable ASCII"),
        )),
        _ => Err(Error::InvalidEndpoint),
    }
}

enum Parsed {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// `netip.ParseAddr`: the first `.`, `:` or `%` decides how the whole string
/// is read; a zone is accepted and dropped.
fn parse_addr(s: &[u8]) -> Option<Parsed> {
    match s.iter().find(|&&c| matches!(c, b'.' | b':' | b'%'))? {
        b'.' => {
            let mut a = [0u8; 4];
            parse_ipv4_fields(s, &mut a)?;
            Some(Parsed::V4(a))
        }
        b':' => parse_ipv6(s).map(Parsed::V6),
        _ => None,
    }
}

/// `netip.parseIPv4Fields`: four decimal fields, no leading zero, none over
/// 255, nothing else.
fn parse_ipv4_fields(s: &[u8], fields: &mut [u8]) -> Option<()> {
    let (mut val, mut pos, mut digits) = (0u32, 0usize, 0u32);
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'0'..=b'9' => {
                if digits == 1 && val == 0 {
                    return None;
                }
                val = val * 10 + u32::from(c - b'0');
                digits += 1;
                if val > 255 {
                    return None;
                }
            }
            b'.' => {
                if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' || pos == 3 {
                    return None;
                }
                fields[pos] = val as u8;
                pos += 1;
                val = 0;
                digits = 0;
            }
            _ => return None,
        }
    }
    if pos < 3 {
        return None;
    }
    fields[3] = val as u8;
    Some(())
}

/// `netip.parseIPv6`, step for step.
fn parse_ipv6(input: &[u8]) -> Option<[u8; 16]> {
    let mut s = input;
    if let Some(i) = s.iter().position(|&c| c == b'%') {
        if i + 1 == s.len() {
            return None; // the zone must not be empty
        }
        s = &s[..i];
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: Option<usize> = None;
    if s.starts_with(b"::") {
        ellipsis = Some(0);
        s = &s[2..];
        if s.is_empty() {
            return Some(ip);
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let mut off = 0;
        let mut acc = 0u32;
        while off < s.len() {
            let v = match s[off] {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'f' => c - b'a' + 10,
                c @ b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            acc = (acc << 4) + u32::from(v);
            if off > 3 || acc > 0xffff {
                return None;
            }
            off += 1;
        }
        if off == 0 {
            return None;
        }
        if s.get(off) == Some(&b'.') {
            if (ellipsis.is_none() && i != 12) || i + 4 > 16 {
                return None;
            }
            parse_ipv4_fields(s, &mut ip[i..i + 4])?;
            s = &[];
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if s[0] != b':' || s.len() == 1 {
            return None;
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis.is_some() {
                return None;
            }
            ellipsis = Some(i);
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return None;
    }
    match ellipsis {
        Some(e) if i < 16 => {
            let n = 16 - i;
            ip.copy_within(e..i, e + n);
            ip[e..e + n].fill(0);
        }
        None if i == 16 => {}
        _ => return None,
    }
    Some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(s: &str) -> Option<Vec<u8>> {
        match parse_addr(s.as_bytes())? {
            Parsed::V4(a) => Some(a.to_vec()),
            Parsed::V6(a) => Some(a.to_vec()),
        }
    }

    #[test]
    fn addresses_read_as_go_reads_them() {
        assert_eq!(host("1.2.3.4"), Some(vec![1, 2, 3, 4]));
        assert_eq!(host("01.2.3.4"), None);
        assert_eq!(host("1.2.3.4%eth0"), None);
        assert_eq!(host("fe80::1%"), None);
        assert_eq!(host("::"), Some(vec![0; 16]));
        let mapped = host("::ffff:1.2.3.4%x").expect("v6");
        assert_eq!(&mapped[10..], &[0xff, 0xff, 1, 2, 3, 4]);
        assert_eq!(
            host("1:2:3:4:5:6:7::"),
            Some([0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0].to_vec())
        );
        assert_eq!(host("1:2:3:4:5:6:7:8::"), None);
        assert_eq!(host("1::2:3:4:5:6:7:8"), None);
        assert_eq!(host("12345::"), None);
        assert_eq!(host("1:2:3:4:5:6:1.2.3.4"), host("1:2:3:4:5:6:102:304"));
        assert_eq!(host("1:2:3:4:5:1.2.3.4"), None);
    }

    #[test]
    fn a_frame_round_trips() {
        let mut out = Vec::new();
        encode(FrameType::Packet, 7, b"::ffff:10.0.0.1", 53, b"q", &mut out).unwrap();
        let frame = decode(&out).unwrap();
        assert_eq!(frame.host.to_string(), "::ffff:10.0.0.1");
        let mut again = Vec::new();
        frame.encode(&mut again).unwrap();
        assert_eq!(again, out);
    }

    #[test]
    fn a_refused_frame_leaves_the_buffer_alone() {
        let mut out = vec![9];
        assert_eq!(
            encode(FrameType::Packet, 1, b"a b", 53, b"", &mut out),
            Err(Error::InvalidEndpoint)
        );
        assert_eq!(out, [9]);
    }
}

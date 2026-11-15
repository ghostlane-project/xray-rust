// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! TLS for TURN over TLS (`turns:`) on BoringSSL (the `boring` crate, 5.5),
//! shaped as Chrome's.
//!
//! Chrome opens a `turns:` server through its network stack's TLS socket,
//! not libwebrtc's adapter: the hello is Chrome's HTTPS hello without ALPN.
//! Chrome 157's, captured on loopback by the lab (ghostlane
//! `lab-olc-rtc.yml`, job `turn-capture`: 24 hellos over three launches, one
//! of them kept as `testdata/chrome-157-turns-client-hello.hex`), is the
//! same in every field but GREASE values, the extension order and the GREASE
//! ECH's length:
//!
//!   - TLS 1.2 to 1.3, GREASE, extensions permuted (a GREASE extension first
//!     and a one-byte one last, as BoringSSL places them);
//!   - Chrome's cipher command [`CHROME_TLS_CIPHERS`];
//!   - groups X25519MLKEM768, X25519, P-256, P-384, with key shares for the
//!     first two (BoringSSL's default: two, at most one post-quantum);
//!   - signature algorithms [`CHROME_TLS_SIGALGS`], ML-DSA first;
//!   - status_request, signed_certificate_timestamp, compress_certificate
//!     (brotli), an empty session_ticket, a GREASE ECH, and trust_anchors
//!     (0xca34) listing [`CHROME_TRUST_ANCHORS`].
//!
//! `turns:` connects from [`turns_context`] ([`crate::turns`]); the hello is
//! held to the capture by the tests below, for a fresh connection, a
//! resumed one and one to an address literal (run on a runner: the build box
//! cannot build BoringSSL).
//!
//! Memory, per connection: BoringSSL's own state (its C heap, outside the
//! Rust gauges); a certificate chain of at most BoringSSL's `max_cert_list`
//! (100 KiB), compressed or not, since a decompressed one is written into a
//! buffer of the length the server declared and BoringSSL refuses a longer
//! declaration first.

use std::io::{self, Write};

use boring::error::ErrorStack;
use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslContext};
use boring::ssl::{SslContextBuilder, SslMethod, SslSessionCacheMode, SslVersion};

/// Chrome's cipher command (net/socket/ssl_client_socket_impl.cc): BoringSSL's
/// suites without PSK, 3DES and ECDSA with CBC-SHA1.
pub const CHROME_TLS_CIPHERS: &str = "ALL:!aPSK:!ECDSA+SHA1:!3DES";
/// The groups Chrome 157 offers over TLS, in its order.
pub const CHROME_TLS_GROUPS: &str = "X25519MLKEM768:X25519:P-256:P-384";
/// The signature algorithms Chrome 157's TLS hello lists after BoringSSL's
/// GREASE value, in its order.
pub const CHROME_TLS_SIGALGS: [u16; 11] = [
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
/// The trust anchor IDs Chrome 157 asks for (draft-ietf-tls-trust-anchor-ids,
/// extension 0xca34), in wire format: 28 length-prefixed IDs of its root
/// store, the same in every captured hello. A Chrome release that changes
/// its root store changes them.
pub const CHROME_TRUST_ANCHORS: [u8; 184] = [
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x01, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x06, 0x05, 0x82, 0xdf, 0x13,
    0x02, 0x0d, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f, 0x05, 0x82,
    0xdf, 0x13, 0x02, 0x12, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x13, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x14,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d,
    0x01, 0x08, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09, 0x08, 0x83, 0x9a, 0x64, 0x8c,
    0x9b, 0x2d, 0x01, 0x0a, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b, 0x08, 0x83, 0x9a,
    0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d, 0x08,
    0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01,
    0x13, 0x04, 0xd6, 0x79, 0x09, 0x01, 0x04, 0xd6, 0x79, 0x09, 0x04, 0x04, 0xd6, 0x79, 0x09, 0x05,
    0x04, 0xd6, 0x79, 0x09, 0x06, 0x04, 0xd6, 0x79, 0x09, 0x07, 0x04, 0xd6, 0x79, 0x09, 0x08, 0x04,
    0xd6, 0x79, 0x09, 0x0a, 0x04, 0xd6, 0x79, 0x09, 0x0b, 0x04, 0xd6, 0x79, 0x09, 0x0c, 0x04, 0xd6,
    0x79, 0x09, 0x0d, 0x04, 0xd6, 0x79, 0x09, 0x0f,
];

/// Brotli, decompression only (Chrome offers brotli and compresses nothing).
struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut r = brotli_decompressor::Decompressor::new(input, 4096);
        io::copy(&mut r, output)?;
        output.flush()
    }
}

/// The context every `turns:` connection is made from: Chrome 157's TLS
/// client, without ALPN.
///
/// # Errors
/// BoringSSL refused a setting.
pub fn chrome_tls_context() -> Result<SslContext, ErrorStack> {
    Ok(chrome_builder()?.build())
}

/// The context [`crate::turns`] connects from: [`chrome_tls_context`]'s
/// profile, and the client session cache switched on as Chrome's is, so a
/// later hello to a server that gave a ticket carries its PSK. The sessions
/// BoringSSL negotiates are handed to [`crate::turns`]'s own bounded cache
/// (one per server), not kept here.
///
/// # Errors
/// BoringSSL refused a setting.
pub fn turns_context() -> Result<SslContext, ErrorStack> {
    let mut ctx = chrome_builder()?;
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    ctx.set_new_session_callback(|_ssl, session| crate::turns::offer_session(session));
    Ok(ctx.build())
}

/// Chrome 157's settings, not yet built into a context.
fn chrome_builder() -> Result<SslContextBuilder, ErrorStack> {
    let mut ctx = SslContextBuilder::new(SslMethod::tls())?;
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    ctx.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    ctx.set_cipher_list(CHROME_TLS_CIPHERS)?;
    ctx.set_curves_list(CHROME_TLS_GROUPS)?;
    ctx.set_grease_enabled(true);
    ctx.set_permute_extensions(true);
    ctx.enable_ocsp_stapling();
    ctx.enable_signed_cert_timestamps();
    ctx.add_certificate_compression_algorithm(Brotli)?;
    // SAFETY: the context is live and the lists outlive the calls (BoringSSL
    // copies them).
    let ok = unsafe {
        boring_sys::SSL_CTX_set_verify_algorithm_prefs(
            ctx.as_ptr(),
            CHROME_TLS_SIGALGS.as_ptr(),
            CHROME_TLS_SIGALGS.len(),
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    // SAFETY: as above.
    let ok = unsafe {
        boring_sys::SSL_CTX_set1_requested_trust_anchors(
            ctx.as_ptr(),
            CHROME_TRUST_ANCHORS.as_ptr(),
            CHROME_TRUST_ANCHORS.len(),
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    Ok(ctx)
}

/// One connection's TLS client for `host` from `ctx`, with a GREASE ECH as
/// Chrome sends. A name is the hello's server name; an address literal is
/// not (Chrome's TLS never sends an IP as SNI, [`crate::turn::sni_name`]).
///
/// # Errors
/// BoringSSL refused the name.
pub fn chrome_ssl(ctx: &SslContext, host: &str) -> Result<Ssl, ErrorStack> {
    let mut ssl = Ssl::new(ctx)?;
    if let Some(name) = crate::turn::sni_name(host) {
        ssl.set_hostname(name)?;
    }
    ssl.set_enable_ech_grease(true);
    Ok(ssl)
}

/// What the hello tests share with [`crate::turns`]'s: a hello as BoringSSL
/// writes it, Chrome 157's capture, and a parser of both.
#[cfg(test)]
pub(crate) mod hello_util {
    use std::collections::BTreeMap;

    use boring::ssl::HandshakeError;

    use super::*;

    /// A byte pipe that takes what BoringSSL writes and has nothing to read.
    #[derive(Default)]
    struct Pipe {
        out: Vec<u8>,
    }

    impl io::Read for Pipe {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl io::Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Our first flight to `host`: the TLS records BoringSSL wrote.
    pub(crate) fn our_hello(host: &str) -> Vec<u8> {
        our_hello_for(&chrome_tls_context().unwrap(), host)
    }

    /// Our first flight to `host` from `ctx`.
    pub(crate) fn our_hello_for(ctx: &SslContext, host: &str) -> Vec<u8> {
        flight(chrome_ssl(ctx, host).unwrap())
    }

    /// The TLS records `ssl` writes before it waits for the server.
    pub(crate) fn flight(ssl: Ssl) -> Vec<u8> {
        match ssl.connect(Pipe::default()) {
            Err(HandshakeError::WouldBlock(mid)) => mid.get_ref().out.clone(),
            Ok(_) => panic!("a handshake with nobody"),
            Err(e) => panic!("{e}"),
        }
    }

    /// The captured Chrome 157 hello (lab-olc-rtc.yml, turn-capture).
    pub(crate) fn chromes_hello() -> Vec<u8> {
        let hex = include_str!("../testdata/chrome-157-turns-client-hello.hex").trim();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
    }

    /// A ClientHello's fields, GREASE values named as such.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Hello {
        pub(crate) record_version: u16,
        pub(crate) legacy_version: u16,
        pub(crate) session_id_len: usize,
        pub(crate) suites: Vec<u16>,
        pub(crate) compression: Vec<u8>,
        /// (id, body length) in order; GREASE ids as 0x0a0a.
        pub(crate) order: Vec<(u16, usize)>,
        /// Bodies by id (GREASE ones left out).
        pub(crate) bodies: BTreeMap<u16, Vec<u8>>,
    }

    pub(crate) fn parse(records: &[u8]) -> Hello {
        let mut hs = Vec::new();
        let mut at = 0;
        while at + 5 <= records.len() {
            assert_eq!(records[at], 22, "a record that is not a handshake");
            let n = usize::from(u16::from_be_bytes([records[at + 3], records[at + 4]]));
            hs.extend_from_slice(&records[at + 5..at + 5 + n]);
            at += 5 + n;
        }
        assert_eq!(hs[0], 1, "not a ClientHello");
        let len = usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]);
        let h = &hs[4..4 + len];
        let mut at = 34;
        let session_id_len = usize::from(h[at]);
        at += 1 + session_id_len;
        let n = usize::from(u16::from_be_bytes([h[at], h[at + 1]]));
        let suites = h[at + 2..at + 2 + n]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .map(|s| if is_grease(s) { 0x0a0a } else { s })
            .collect();
        at += 2 + n;
        let compression = h[at + 1..at + 1 + usize::from(h[at])].to_vec();
        at += 1 + usize::from(h[at]);
        let end = at + 2 + usize::from(u16::from_be_bytes([h[at], h[at + 1]]));
        at += 2;
        let (mut order, mut bodies) = (Vec::new(), BTreeMap::new());
        while at + 4 <= end {
            let id = u16::from_be_bytes([h[at], h[at + 1]]);
            let n = usize::from(u16::from_be_bytes([h[at + 2], h[at + 3]]));
            if is_grease(id) {
                order.push((0x0a0a, n));
            } else {
                order.push((id, n));
                bodies.insert(id, h[at + 4..at + 4 + n].to_vec());
            }
            at += 4 + n;
        }
        Hello {
            record_version: u16::from_be_bytes([records[1], records[2]]),
            legacy_version: u16::from_be_bytes([h[0], h[1]]),
            session_id_len,
            suites,
            compression,
            order,
            bodies,
        }
    }

    /// A list of u16s after a length prefix of `skip` bytes, GREASE named.
    pub(crate) fn u16s(b: &[u8], skip: usize) -> Vec<u16> {
        b[skip..]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .map(|v| if is_grease(v) { 0x0a0a } else { v })
            .collect()
    }

    /// key_share: (group, share length), GREASE named.
    pub(crate) fn shares(b: &[u8]) -> Vec<(u16, usize)> {
        let (mut at, mut out) = (2, Vec::new());
        while at + 4 <= b.len() {
            let g = u16::from_be_bytes([b[at], b[at + 1]]);
            let n = usize::from(u16::from_be_bytes([b[at + 2], b[at + 3]]));
            out.push((if is_grease(g) { 0x0a0a } else { g }, n));
            at += 4 + n;
        }
        out
    }

    /// `ours` equals the captured Chrome 157 hello field by field: versions,
    /// the session id's length, the suites, every extension's id and length
    /// (the GREASE ECH's length is one of the four Chrome sent), and the
    /// bodies that carry no randomness.
    pub(crate) fn assert_is_chromes(ours: &Hello) {
        let chrome = parse(&chromes_hello());
        assert_eq!(ours.record_version, chrome.record_version, "record version");
        assert_eq!(ours.legacy_version, chrome.legacy_version, "legacy version");
        assert_eq!(ours.session_id_len, chrome.session_id_len, "session id");
        assert_eq!(ours.suites, chrome.suites, "cipher suites");
        assert_eq!(ours.compression, chrome.compression, "compression");
        // The first and last extensions are GREASE, empty and one byte.
        for h in [ours, &chrome] {
            assert_eq!(h.order.first(), Some(&(0x0a0a, 0)), "{:04x?}", h.order);
            assert_eq!(h.order.last(), Some(&(0x0a0a, 1)), "{:04x?}", h.order);
        }
        let set = |h: &Hello| {
            let mut s: Vec<(u16, usize)> = h
                .order
                .iter()
                .copied()
                .filter(|(id, _)| *id != 0xfe0d)
                .collect();
            s.sort_unstable();
            s
        };
        assert_eq!(set(ours), set(&chrome), "extensions and their lengths");
        let ech = ours.bodies.get(&0xfe0d).map(Vec::len);
        assert!(
            matches!(ech, Some(186 | 218 | 250 | 282)),
            "a GREASE ECH of {ech:?} bytes"
        );
        // Bodies without randomness, byte for byte.
        for id in [
            0x0000, 0x0005, 0x000b, 0x0012, 0x0017, 0x001b, 0x0023, 0x002d, 0xca34, 0xff01,
        ] {
            assert_eq!(
                ours.bodies.get(&id),
                chrome.bodies.get(&id),
                "extension {id:#06x}"
            );
        }
        assert_eq!(
            u16s(&ours.bodies[&0x000a], 2),
            u16s(&chrome.bodies[&0x000a], 2),
            "groups"
        );
        assert_eq!(
            u16s(&ours.bodies[&0x000d], 2),
            u16s(&chrome.bodies[&0x000d], 2),
            "sigalgs"
        );
        assert_eq!(
            u16s(&ours.bodies[&0x002b], 1),
            u16s(&chrome.bodies[&0x002b], 1),
            "versions"
        );
        assert_eq!(
            shares(&ours.bodies[&0x0033]),
            shares(&chrome.bodies[&0x0033]),
            "key shares"
        );
        assert_eq!(
            chrome.bodies[&0xca34][2..],
            CHROME_TRUST_ANCHORS,
            "the fixture's trust anchors"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::hello_util::{assert_is_chromes, our_hello, our_hello_for, parse, Hello};
    use super::*;

    /// Our hello to the capture's server name equals Chrome 157's field by
    /// field (see [`assert_is_chromes`]).
    #[test]
    fn the_turns_hello_is_chromes() {
        assert_is_chromes(&parse(&our_hello("turn.olc.test")));
    }

    /// The `turns:` context (the session cache on) sends the same first
    /// hello, and one shared context sends them permuted per connection.
    #[test]
    fn the_turns_context_sends_chromes_hello() {
        let ctx = turns_context().unwrap();
        for _ in 0..2 {
            assert_is_chromes(&parse(&our_hello_for(&ctx, "turn.olc.test")));
        }
        let order = || {
            parse(&our_hello_for(&ctx, "turn.olc.test"))
                .order
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        };
        let first = order();
        assert!(
            (0..4).any(|_| order() != first),
            "five hellos from one context with one extension order"
        );
    }

    /// To an address literal the hello has no server name and is otherwise
    /// the same (Chrome's TLS sends none for an IP).
    #[test]
    fn a_hello_to_an_address_names_no_server() {
        let ctx = chrome_tls_context().unwrap();
        let named = parse(&our_hello_for(&ctx, "turn.olc.test"));
        let set = |h: &Hello| {
            let mut s: Vec<(u16, usize)> = h
                .order
                .iter()
                .copied()
                .filter(|(id, _)| !matches!(*id, 0x0000 | 0xfe0d))
                .collect();
            s.sort_unstable();
            s
        };
        for ip in ["127.0.0.1", "2001:db8::1"] {
            let ours = parse(&our_hello_for(&ctx, ip));
            assert!(!ours.bodies.contains_key(&0x0000), "{ip}: a server name");
            assert!(ours.order.iter().all(|(id, _)| *id != 0x0000), "{ip}");
            assert_eq!(set(&ours), set(&named), "{ip}: the other extensions");
            assert_eq!(ours.suites, named.suites);
        }
    }

    /// The extensions are permuted per hello, as Chrome's are.
    #[test]
    fn the_turns_extensions_are_permuted() {
        let order = || {
            parse(&our_hello("turn.olc.test"))
                .order
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        };
        let first = order();
        assert!(
            (0..4).any(|_| order() != first),
            "five hellos with one extension order"
        );
    }
}

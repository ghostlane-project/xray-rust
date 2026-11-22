// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! A str0m `DtlsProvider` on BoringSSL (the `boring` crate, 5.5), shaped as
//! Chrome's DTLS (port plan section 8, X2-X4). From the M2 spike
//! (`gl/olc-spike`, `olc/spike/dtls-boring`), whose hello equalled Chrome
//! 157's field by field on a runner.
//!
//! str0m's own DTLS (dimpl) sends a ClientHello no browser sends. Chrome's
//! comes from BoringSSL, configured by libwebrtc, so the shortest way to
//! Chrome's bytes is BoringSSL configured the same way. The profile is
//! libwebrtc's (`OpenSSLStreamAdapter::SetupSSLContext` and `ConfigureSsl`):
//!
//!   - DTLS 1.2 to 1.3, `SSL_CTX_set_permute_extensions`, no session
//!     tickets, MTU 1200;
//!   - the cipher string [`CHROME_CIPHERS`];
//!   - groups X25519MLKEM768, X25519, P-256, P-384 (key shares 11ec, 001d);
//!   - signature algorithms as Chrome lists them ([`CHROME_SIGALGS`], no
//!     ML-DSA, which BoringSSL 5.5 would add);
//!   - use_srtp AES128_CM_SHA1_80, AEAD_AES_256_GCM, AEAD_AES_128_GCM;
//!   - a self-signed ECDSA P-256 certificate, CN "WebRTC", 64-bit serial,
//!     valid from a day ago for 30 days, no extensions
//!     (`rtc::SSLIdentity::Create`, KT_ECDSA).
//!
//! The handshake timer is BoringSSL's own: `DTLSv1_get_timeout` gives the
//! next deadline and `DTLSv1_handle_timeout` fires it (critique C6), so
//! retransmissions and DTLS 1.3 ACKs run on BoringSSL's schedule.
//!
//! Everything else in the `CryptoProvider` (SRTP, the STUN HMAC, the
//! hashes) stays str0m's aws-lc-rs provider: [`provider`] swaps the DTLS
//! part only.
//!
//! Memory, per DTLS instance (one per peer connection): BoringSSL's own
//! state (its C heap, outside the Rust gauges); one read buffer of
//! [`READ_CHUNK`]; and queues that str0m drains after every call. str0m
//! hands over one datagram per call and polls everything out before the
//! next, so `incoming` holds one datagram between calls (capped at
//! [`INCOMING_MAX`] datagrams, the oldest dropped as a full socket buffer
//! would), `packets` one flight or one record, and `app_data` the records of
//! one datagram (at most [`crate::peer::RECV_BUF`] bytes). Application data
//! written before the handshake ends waits in `queued`, at most
//! [`QUEUED_MAX`] bytes; str0m starts SCTP only once DTLS is up, so nothing
//! is expected there.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::asn1::Asn1Time;
use boring::bn::{BigNum, MsbOption};
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::PKey;
use boring::srtp::SrtpProfileId;
use boring::ssl::{ErrorCode, ShutdownState, Ssl, SslContext, SslContextBuilder, SslMethod};
use boring::ssl::{SslOptions, SslStream, SslVerifyMode, SslVersion};
use boring::x509::{X509Builder, X509NameBuilder, X509};
use foreign_types::ForeignTypeRef;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsCryptoError, DtlsCryptoOperation, DtlsImplError};
use str0m_proto::crypto::dtls::{DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::dtls::{KeyingMaterial, ProtocolVersion, SrtpProfile};
use str0m_proto::crypto::{CryptoError, CryptoProvider, DtlsVersion};

/// libwebrtc's cipher string (rtc_base/openssl_stream_adapter.cc).
pub const CHROME_CIPHERS: &str =
    "DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK:!3DES";
/// The groups Chrome offers in its DTLS ClientHello, in its order.
pub const CHROME_GROUPS: &str = "X25519MLKEM768:X25519:P-256:P-384";
/// The SRTP profiles in Chrome's use_srtp extension, in its order.
pub const CHROME_SRTP: &str = "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM";
/// The signature algorithms Chrome 157's DTLS ClientHello lists, in its
/// order (captured on a runner, M2 spike).
pub const CHROME_SIGALGS: [u16; 9] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
/// libwebrtc's DTLS MTU (`dtls_mtu_`): the handshake's fragment size is
/// part of the shape, so it is not str0m's 1150.
pub const CHROME_DTLS_MTU: u32 = 1200;

/// The read buffer: one TLS record's largest plaintext (2^14) plus slack.
pub const READ_CHUNK: usize = 16 * 1024 + 256;
/// Datagrams waiting for BoringSSL to read them: three DTLS 1.3 flights of
/// ten records each. str0m hands over one per call and BoringSSL reads them
/// in that call, so this is reached only by a peer that floods the
/// handshake.
pub const INCOMING_MAX: usize = 32;
/// Application data held until the handshake ends: one SCTP receive window
/// (`crate::peer::INBOUND_BYTES`, Chrome's 256 KiB).
pub const QUEUED_MAX: usize = crate::peer::INBOUND_BYTES;

const DTLS_SRTP_LABEL: &str = "EXTRACTOR-dtls_srtp";

/// The aws-lc-rs provider with its DTLS part replaced by BoringSSL.
#[must_use]
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        dtls_provider: &BORING,
        ..str0m_aws_lc_rs::default_provider()
    }
}

static BORING: BoringDtlsProvider = BoringDtlsProvider;

/// The provider itself: a certificate maker and an instance maker.
pub struct BoringDtlsProvider;

impl fmt::Debug for BoringDtlsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoringDtlsProvider")
    }
}

impl DtlsProvider for BoringDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        match chrome_certificate() {
            Ok(c) => Some(c),
            Err(e) => {
                olc_net::info!("webrtc: DTLS certificate: {e}");
                None
            }
        }
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        _now: Instant,
        dtls_version: DtlsVersion,
        _mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let (min, max) = match dtls_version {
            DtlsVersion::Dtls12 => (SslVersion::DTLS1_2, SslVersion::DTLS1_2),
            DtlsVersion::Dtls13 => (SslVersion::DTLS1_3, SslVersion::DTLS1_3),
            // Chrome's: 1.2 to 1.3, the peer decides.
            _ => (SslVersion::DTLS1_2, SslVersion::DTLS1_3),
        };
        Ok(Box::new(
            BoringDtls::new(cert, min, max).map_err(boring_err)?,
        ))
    }
}

fn boring_err(e: boring::error::ErrorStack) -> CryptoError {
    CryptoError::Other(format!("boring: {e}"))
}

fn op_failed(op: DtlsCryptoOperation) -> DtlsImplError {
    DtlsImplError::CryptoError(DtlsCryptoError::OperationFailed(op))
}

/// The certificate libwebrtc makes for a peer connection (KT_ECDSA).
///
/// # Errors
/// BoringSSL's.
pub fn chrome_certificate() -> Result<DtlsCert, boring::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
    b.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let day = 24 * 3600;
    // libc marks time_t deprecated on musl (its width there follows the musl
    // release); Asn1Time::from_unix takes it as it is.
    #[allow(deprecated)]
    let at = |secs: u64| libc::time_t::try_from(secs).unwrap_or(libc::time_t::MAX);
    let not_before = Asn1Time::from_unix(at(now.saturating_sub(day)))?;
    let not_after = Asn1Time::from_unix(at(now + 30 * day))?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "WebRTC")?;
    let name = name.build();
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    b.set_pubkey(&key)?;
    b.sign(&key, MessageDigest::sha256())?;
    let cert = b.build();
    Ok(DtlsCert {
        certificate: cert.to_der()?,
        private_key: key.private_key_to_der()?,
    })
}

fn chrome_context(
    cert: &DtlsCert,
    min: SslVersion,
    max: SslVersion,
) -> Result<SslContext, boring::error::ErrorStack> {
    let mut ctx = SslContextBuilder::new(SslMethod::dtls())?;
    ctx.set_min_proto_version(Some(min))?;
    ctx.set_max_proto_version(Some(max))?;
    ctx.set_cipher_list(CHROME_CIPHERS)?;
    ctx.set_curves_list(CHROME_GROUPS)?;
    ctx.set_tlsext_use_srtp(CHROME_SRTP)?;
    ctx.set_permute_extensions(true);
    let len = CHROME_SIGALGS.len();
    // SAFETY: the context is live and the list outlives the call (BoringSSL
    // copies it).
    let ok = unsafe {
        boring_sys::SSL_CTX_set_verify_algorithm_prefs(ctx.as_ptr(), CHROME_SIGALGS.as_ptr(), len)
    };
    if ok != 1 {
        return Err(boring::error::ErrorStack::get());
    }
    ctx.set_options(SslOptions::NO_TICKET | SslOptions::NO_QUERY_MTU | SslOptions::SINGLE_ECDH_USE);
    // Both ends present a certificate; str0m checks the peer's against the
    // SDP fingerprint.
    ctx.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_, _| true,
    );
    let x509 = X509::from_der(&cert.certificate)?;
    let key = PKey::private_key_from_der(&cert.private_key)?;
    ctx.set_certificate(&x509)?;
    ctx.set_private_key(&key)?;
    Ok(ctx.build())
}

/// The datagram pipe between str0m and BoringSSL: one read is one
/// datagram, one write is one datagram.
#[derive(Default)]
struct Io {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}

impl io::Read for Io {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.incoming.pop_front() {
            None => Err(io::ErrorKind::WouldBlock.into()),
            Some(d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
        }
    }
}

impl io::Write for Io {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing.push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoringDtls {
    stream: SslStream<Io>,
    read_buf: Box<[u8]>,
    active: Option<bool>,
    established: bool,
    started: Option<Instant>,
    deadline: Option<Instant>,
    packets: VecDeque<Vec<u8>>,
    app_data: VecDeque<Vec<u8>>,
    connected_pending: bool,
    peer_cert: Option<Vec<u8>>,
    keying: Option<(Vec<u8>, SrtpProfile)>,
    queued: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    close_received: bool,
    close_emitted: bool,
    close_sent: bool,
    /// Application records read and written: the first and the 20th of
    /// each are logged (SCTP's first packets each way).
    app_in: u32,
    app_out: u32,
}

// SAFETY: str0m owns one instance per Rtc and calls it only through
// `&mut self`, or `&self` for reads of settled state; nothing here is shared
// between threads at once. `SslStream` is not `Sync` only because of the BIO
// method pointer it keeps, which is never touched outside those calls.
unsafe impl Send for BoringDtls {}
// SAFETY: as above.
unsafe impl Sync for BoringDtls {}

impl fmt::Debug for BoringDtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringDtls")
            .field("active", &self.active)
            .field("established", &self.established)
            .finish_non_exhaustive()
    }
}

impl BoringDtls {
    fn new(
        cert: &DtlsCert,
        min: SslVersion,
        max: SslVersion,
    ) -> Result<Self, boring::error::ErrorStack> {
        let ctx = chrome_context(cert, min, max)?;
        let mut ssl = Ssl::new(&ctx)?;
        ssl.set_mtu(CHROME_DTLS_MTU)?;
        let stream = SslStream::new(ssl, Io::default())?;
        Ok(BoringDtls {
            stream,
            read_buf: vec![0u8; READ_CHUNK].into_boxed_slice(),
            active: None,
            established: false,
            started: None,
            deadline: None,
            packets: VecDeque::new(),
            app_data: VecDeque::new(),
            connected_pending: false,
            peer_cert: None,
            keying: None,
            queued: VecDeque::new(),
            queued_bytes: 0,
            close_received: false,
            close_emitted: false,
            close_sent: false,
            app_in: 0,
            app_out: 0,
        })
    }

    fn ssl_ptr(&self) -> *mut boring_sys::SSL {
        self.stream.ssl().as_ptr()
    }

    /// Moves what BoringSSL wrote to the outgoing queue and re-reads its
    /// timer.
    fn collect(&mut self) {
        let io = self.stream.get_mut();
        while let Some(p) = io.outgoing.pop_front() {
            self.packets.push_back(p);
        }
        self.refresh_deadline();
    }

    fn refresh_deadline(&mut self) {
        // SAFETY: a zeroed timeval is a valid out-parameter.
        let mut tv: boring_sys::timeval = unsafe { std::mem::zeroed() };
        // SAFETY: the SSL pointer is live for as long as self.
        let armed = unsafe { boring_sys::DTLSv1_get_timeout(self.ssl_ptr(), &mut tv) };
        self.deadline = if armed == 1 {
            let secs = u64::try_from(tv.tv_sec).unwrap_or(0);
            let micros = u64::try_from(tv.tv_usec).unwrap_or(0);
            Some(Instant::now() + Duration::from_secs(secs) + Duration::from_micros(micros))
        } else {
            None
        };
    }

    /// Runs the handshake as far as the queued datagrams allow, then reads
    /// any records.
    fn drive(&mut self) -> Result<(), DtlsImplError> {
        let active = self.active.unwrap_or(false);
        if !self.established {
            self.started.get_or_insert_with(Instant::now);
            let r = if active {
                self.stream.connect()
            } else {
                self.stream.accept()
            };
            match r {
                Ok(()) => self.on_established()?,
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                }
                Err(e) => {
                    self.collect();
                    olc_net::debug!("webrtc: DTLS handshake failed: {e}");
                    return Err(op_failed(DtlsCryptoOperation::Decrypt));
                }
            }
        }
        if self.established {
            loop {
                match self.stream.ssl_read(&mut self.read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.app_in = self.app_in.saturating_add(1);
                        if self.app_in <= 4 || self.app_in == 20 {
                            olc_net::debug!(
                                "webrtc: DTLS application record {} in, {n} bytes: {}",
                                self.app_in,
                                sctp_head(&self.read_buf[..n])
                            );
                        }
                        self.app_data.push_back(self.read_buf[..n].to_vec());
                    }
                    Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                        self.close_received = true;
                        if !self.close_sent {
                            let _ = self.stream.shutdown();
                            self.close_sent = true;
                        }
                        break;
                    }
                    Err(e)
                        if e.code() == ErrorCode::WANT_READ
                            || e.code() == ErrorCode::WANT_WRITE =>
                    {
                        break
                    }
                    Err(e) => {
                        self.collect();
                        if self.stream.get_shutdown().contains(ShutdownState::RECEIVED) {
                            self.close_received = true;
                            break;
                        }
                        olc_net::debug!("webrtc: DTLS read failed: {e}");
                        return Err(op_failed(DtlsCryptoOperation::Decrypt));
                    }
                }
            }
        }
        self.collect();
        Ok(())
    }

    fn on_established(&mut self) -> Result<(), DtlsImplError> {
        self.established = true;
        self.connected_pending = true;
        let ssl = self.stream.ssl();
        let peer = ssl
            .peer_certificate()
            .ok_or(op_failed(DtlsCryptoOperation::Decrypt))?;
        self.peer_cert = Some(
            peer.to_der()
                .map_err(|_| op_failed(DtlsCryptoOperation::Decrypt))?,
        );
        let profile = match ssl.selected_srtp_profile().map(|p| p.id()) {
            Some(SrtpProfileId::SRTP_AES128_CM_SHA1_80) => SrtpProfile::AES128_CM_SHA1_80,
            Some(SrtpProfileId::SRTP_AEAD_AES_128_GCM) => SrtpProfile::AEAD_AES_128_GCM,
            Some(SrtpProfileId::SRTP_AEAD_AES_256_GCM) => SrtpProfile::AEAD_AES_256_GCM,
            _ => return Err(op_failed(DtlsCryptoOperation::Decrypt)),
        };
        let mut km = vec![0u8; profile.keying_material_len()];
        ssl.export_keying_material(&mut km, DTLS_SRTP_LABEL, None)
            .map_err(|_| op_failed(DtlsCryptoOperation::Decrypt))?;
        olc_net::debug!(
            "webrtc: DTLS {} {} {} srtp {profile:?}, {} ms as the {}",
            ssl.version_str(),
            ssl.current_cipher().map_or("", |c| c.name()),
            ssl.curve_name().unwrap_or(""),
            self.started.map_or(0, |s| s.elapsed().as_millis()),
            if self.active.unwrap_or(false) {
                "client"
            } else {
                "server"
            },
        );
        self.keying = Some((km, profile));
        while let Some(d) = self.queued.pop_front() {
            self.queued_bytes -= d.len();
            self.write_app(&d)?;
        }
        Ok(())
    }

    fn write_app(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        match self.stream.ssl_write(data) {
            Ok(_) => {
                self.app_out = self.app_out.saturating_add(1);
                if self.app_out <= 4 || self.app_out == 20 {
                    olc_net::debug!(
                        "webrtc: DTLS application record {} out, {} bytes: {}",
                        self.app_out,
                        data.len(),
                        sctp_head(data)
                    );
                }
                self.collect();
                Ok(())
            }
            Err(e) => {
                olc_net::debug!("webrtc: DTLS write of {} bytes failed: {e}", data.len());
                Err(op_failed(DtlsCryptoOperation::Encrypt))
            }
        }
    }
}

/// An SCTP packet's ports and chunk types with their lengths, for the logs:
/// no payload bytes.
fn sctp_head(p: &[u8]) -> String {
    if p.len() < 12 {
        return format!("short {}", p.len());
    }
    let port = |i: usize| u16::from_be_bytes([p[i], p[i + 1]]);
    let mut out = format!("ports {}->{}", port(0), port(2));
    let mut at = 12;
    while at + 4 <= p.len() && out.len() < 200 {
        let len = usize::from(port(at + 2));
        out.push_str(&format!(" chunk {} flags {} len {len}", p[at], p[at + 1]));
        if len < 4 {
            break;
        }
        at += (len + 3) & !3;
    }
    out
}

impl DtlsInstance for BoringDtls {
    fn set_active(&mut self, active: bool) {
        self.active = Some(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        if !packet.is_empty() {
            let incoming = &mut self.stream.get_mut().incoming;
            if incoming.len() >= INCOMING_MAX {
                incoming.pop_front();
            }
            incoming.push_back(packet.to_vec());
        }
        self.drive()
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        if let Some(p) = self.packets.front() {
            if p.len() <= buf.len() {
                let p = self.packets.pop_front().unwrap_or_default();
                buf[..p.len()].copy_from_slice(&p);
                return DtlsOutput::Packet(&buf[..p.len()]);
            }
        }
        if self.connected_pending {
            self.connected_pending = false;
            return DtlsOutput::Connected;
        }
        if let Some(c) = self.peer_cert.take() {
            if c.len() <= buf.len() {
                buf[..c.len()].copy_from_slice(&c);
                return DtlsOutput::PeerCert(&buf[..c.len()]);
            }
            self.peer_cert = Some(c);
        }
        if let Some((km, profile)) = self.keying.take() {
            if km.len() <= buf.len() {
                buf[..km.len()].copy_from_slice(&km);
                return DtlsOutput::KeyingMaterial(KeyingMaterial::new(&buf[..km.len()]), profile);
            }
            self.keying = Some((km, profile));
        }
        if self.close_received && !self.close_emitted {
            self.close_emitted = true;
            return DtlsOutput::CloseNotify;
        }
        if let Some(d) = self.app_data.front() {
            if d.len() <= buf.len() {
                let d = self.app_data.pop_front().unwrap_or_default();
                buf[..d.len()].copy_from_slice(&d);
                return DtlsOutput::ApplicationData(&buf[..d.len()]);
            }
        }
        DtlsOutput::Timeout(
            self.deadline
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600)),
        )
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        if self.active.is_none() {
            return Ok(());
        }
        if !self.established && self.started.is_none() {
            // str0m's first call after set_active: the client sends its
            // ClientHello here (the server's accept() only arms itself).
            return self.drive();
        }
        if let Some(d) = self.deadline {
            if now >= d {
                // SAFETY: the SSL pointer is live for as long as self.
                let r = unsafe { boring_sys::DTLSv1_handle_timeout(self.ssl_ptr()) };
                if r < 0 {
                    return Err(op_failed(DtlsCryptoOperation::Encrypt));
                }
                self.collect();
                return Ok(());
            }
        }
        self.refresh_deadline();
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<usize, DtlsImplError> {
        if !self.established {
            if self.queued_bytes + data.len() > QUEUED_MAX {
                return Err(op_failed(DtlsCryptoOperation::Encrypt));
            }
            self.queued_bytes += data.len();
            self.queued.push_back(data.to_vec());
            return Ok(data.len());
        }
        self.write_app(data)?;
        Ok(data.len())
    }

    fn is_active(&self) -> bool {
        self.active.unwrap_or(false)
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        if !self.established {
            return None;
        }
        match self.stream.ssl().version2() {
            Some(v) if v == SslVersion::DTLS1_3 => Some(ProtocolVersion::DTLS1_3),
            Some(_) => Some(ProtocolVersion::DTLS1_2),
            None => None,
        }
    }

    fn is_closing(&self) -> bool {
        self.close_sent || self.close_received
    }

    fn is_closed(&self) -> bool {
        self.close_sent && self.packets.is_empty()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        if self.established && !self.close_sent {
            let _ = self.stream.shutdown();
            self.collect();
        }
        self.close_sent = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The handshake messages in some DTLS datagrams, reassembled from
    /// their fragments: (type, body) by message_seq.
    fn handshakes(datagrams: &[Vec<u8>]) -> BTreeMap<u16, (u8, Vec<u8>)> {
        let mut out: BTreeMap<u16, (u8, Vec<u8>)> = BTreeMap::new();
        for d in datagrams {
            let mut at = 0;
            while at + 13 <= d.len() {
                let kind = d[at];
                let len = usize::from(u16::from_be_bytes([d[at + 11], d[at + 12]]));
                let rec = &d[at + 13..at + 13 + len];
                at += 13 + len;
                if kind != 22 {
                    continue;
                }
                let mut i = 0;
                while i + 12 <= rec.len() {
                    let u24 = |b: &[u8]| {
                        usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2])
                    };
                    let msg = rec[i];
                    let total = u24(&rec[i + 1..]);
                    let seq = u16::from_be_bytes([rec[i + 4], rec[i + 5]]);
                    let off = u24(&rec[i + 6..]);
                    let flen = u24(&rec[i + 9..]);
                    let frag = &rec[i + 12..i + 12 + flen];
                    let entry = out.entry(seq).or_insert_with(|| (msg, vec![0; total]));
                    entry.1[off..off + flen].copy_from_slice(frag);
                    i += 12 + flen;
                }
            }
        }
        out
    }

    /// A fresh client instance's first flight.
    fn first_flight() -> Vec<Vec<u8>> {
        let cert = chrome_certificate().unwrap();
        let mut d = BoringDtls::new(&cert, SslVersion::DTLS1_2, SslVersion::DTLS1_3).unwrap();
        d.set_active(true);
        d.handle_timeout(Instant::now()).unwrap();
        let mut buf = vec![0u8; 2048];
        let mut out = Vec::new();
        while let DtlsOutput::Packet(p) = d.poll_output(&mut buf) {
            out.push(p.to_vec());
        }
        out
    }

    /// A ClientHello's suites and extensions (id, body), in order.
    fn parse_hello(body: &[u8]) -> (Vec<u16>, Vec<(u16, Vec<u8>)>) {
        let mut at = 2 + 32;
        at += 1 + usize::from(body[at]); // session id
        at += 1 + usize::from(body[at]); // cookie
        let n = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        let suites = body[at + 2..at + 2 + n]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        at += 2 + n;
        at += 1 + usize::from(body[at]); // compression
        let end = at + 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2;
        let mut ext = Vec::new();
        while at + 4 <= end {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let len = usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
            ext.push((id, body[at + 4..at + 4 + len].to_vec()));
            at += 4 + len;
        }
        (suites, ext)
    }

    fn u16s(b: &[u8]) -> Vec<u16> {
        b.chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    /// Chrome 157's DTLS ClientHello, as the M2 spike captured it on a
    /// runner: its suites, groups, key shares, sigalgs, SRTP profiles and
    /// versions, in fragments of libwebrtc's MTU.
    #[test]
    fn the_client_hello_is_chromes() {
        let flight = first_flight();
        assert!(
            flight.iter().all(|d| d.len() <= CHROME_DTLS_MTU as usize),
            "a datagram past the MTU"
        );
        let msgs = handshakes(&flight);
        let (kind, hello) = &msgs[&0];
        assert_eq!(*kind, 1, "the first message is a ClientHello");
        let (suites, ext) = parse_hello(hello);
        assert_eq!(
            suites,
            [
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a,
                0xc014, 0x009c, 0x002f, 0x0035
            ]
        );
        let get = |id: u16| {
            ext.iter()
                .find(|(e, _)| *e == id)
                .map(|(_, b)| b.clone())
                .unwrap_or_else(|| panic!("no extension {id:#06x}"))
        };
        assert_eq!(
            u16s(&get(10)[2..]),
            [0x11ec, 0x001d, 0x0017, 0x0018],
            "supported_groups"
        );
        assert_eq!(u16s(&get(13)[2..]), CHROME_SIGALGS, "signature_algorithms");
        let srtp = get(14);
        assert_eq!(
            u16s(&srtp[2..2 + usize::from(u16::from_be_bytes([srtp[0], srtp[1]]))]),
            [0x0001, 0x0008, 0x0007],
            "use_srtp"
        );
        let versions = get(43);
        assert_eq!(
            u16s(&versions[1..]),
            [0xfefc, 0xfefd],
            "supported_versions: DTLS 1.3, 1.2"
        );
        let shares = get(51);
        let (mut at, mut got) = (2, Vec::new());
        while at + 4 <= shares.len() {
            let group = u16::from_be_bytes([shares[at], shares[at + 1]]);
            let len = usize::from(u16::from_be_bytes([shares[at + 2], shares[at + 3]]));
            got.push((group, len));
            at += 4 + len;
        }
        assert_eq!(got, [(0x11ec, 1216), (0x001d, 32)], "key_share");
        for id in [23, 45, 0xff01] {
            get(id);
        }
        assert!(ext.iter().all(|(id, _)| *id != 35), "a session ticket");
    }

    /// The extensions are permuted per hello, as Chrome's are.
    #[test]
    fn the_extensions_are_permuted() {
        let order = || {
            let msgs = handshakes(&first_flight());
            parse_hello(&msgs[&0].1)
                .1
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

    /// libwebrtc's certificate: ECDSA P-256, CN "WebRTC", self-signed, a
    /// 64-bit serial, valid from a day ago for 30 days, no extensions.
    #[test]
    fn the_certificate_is_libwebrtcs() {
        let c = chrome_certificate().unwrap();
        let x = X509::from_der(&c.certificate).unwrap();
        let cn = x
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        assert_eq!(cn.data().as_slice(), b"WebRTC");
        assert_eq!(
            x.issuer_name().to_der().unwrap(),
            x.subject_name().to_der().unwrap()
        );
        let key = x.public_key().unwrap().ec_key().unwrap();
        assert_eq!(key.group().curve_name(), Some(Nid::X9_62_PRIME256V1));
        assert!(x.serial_number().to_bn().unwrap().num_bits() <= 64);
        // Within a minute of the test's own clock, read after the certificate
        // was made.
        let now = Asn1Time::days_from_now(0).unwrap();
        let secs = |from: &boring::asn1::Asn1TimeRef, to: &boring::asn1::Asn1TimeRef| {
            let d = from.diff(to).unwrap();
            i64::from(d.days) * 86_400 + i64::from(d.secs)
        };
        let ago = secs(x.not_before(), &now);
        assert!(
            (86_400..86_460).contains(&ago),
            "not before: a day ago, {ago} s"
        );
        let on = secs(&now, x.not_after());
        assert!(
            (30 * 86_400 - 60..=30 * 86_400).contains(&on),
            "not after: 30 days on, {on} s"
        );
        assert!(x.verify(&x.public_key().unwrap()).unwrap(), "self-signed");
    }

    /// What waits for the handshake is capped at [`QUEUED_MAX`].
    #[test]
    fn data_before_the_handshake_is_capped() {
        let cert = chrome_certificate().unwrap();
        let mut d = BoringDtls::new(&cert, SslVersion::DTLS1_2, SslVersion::DTLS1_3).unwrap();
        d.set_active(true);
        let chunk = vec![0u8; 1200];
        let fits = QUEUED_MAX / chunk.len();
        for _ in 0..fits {
            assert_eq!(d.send_application_data(&chunk).unwrap(), chunk.len());
        }
        assert!(d.send_application_data(&chunk).is_err());
        assert_eq!(d.queued_bytes, fits * chunk.len());
    }
}

//! A str0m `DtlsProvider` on BoringSSL (the `boring` crate, 5.5), for the M2 stack spike.
//!
//! What it is for: str0m's own DTLS (dimpl) sends a ClientHello no browser sends. Chrome's
//! comes from BoringSSL, configured by libwebrtc, so the shortest way to Chrome's bytes is
//! BoringSSL configured the same way. The profile below is libwebrtc's
//! (`OpenSSLStreamAdapter::SetupSSLContext` and `ConfigureSsl`, Chrome 147):
//!
//!   - DTLS 1.2 to 1.3, `SSL_CTX_set_permute_extensions`, no session tickets, MTU 1200;
//!   - the cipher string `DEFAULT:!NULL:!aNULL:!SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK:!3DES`;
//!   - groups X25519MLKEM768, X25519, P-256, P-384 (the hello carries 11ec and 001d key shares);
//!   - signature algorithms as Chrome lists them ([`CHROME_SIGALGS`], no ML-DSA);
//!   - use_srtp AES128_CM_SHA1_80, AEAD_AES_256_GCM, AEAD_AES_128_GCM (0001 0008 0007);
//!   - a self-signed ECDSA P-256 certificate, CN "WebRTC", 64-bit serial, valid from a day
//!     ago for 30 days, no extensions (`rtc::SSLIdentity::Create`, KT_ECDSA).
//!
//! The handshake timer is BoringSSL's own: `DTLSv1_get_timeout` gives the next deadline and
//! `DTLSv1_handle_timeout` fires it (critique C6), so DTLS 1.3 ACKs and retransmissions run
//! on BoringSSL's schedule, not on a fixed poll.
//!
//! Everything else in the `CryptoProvider` (SRTP, the STUN HMAC, SHA-1/SHA-256) stays
//! str0m's aws-lc-rs provider: [`provider`] swaps the DTLS part only.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::Mutex;
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
/// The groups Chrome 147 offers in its DTLS ClientHello, in its order.
pub const CHROME_GROUPS: &str = "X25519MLKEM768:X25519:P-256:P-384";
/// The SRTP profiles in Chrome's use_srtp extension, in its order.
pub const CHROME_SRTP: &str = "SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM";
/// The signature algorithms Chrome 157's DTLS ClientHello lists, in its order (captured on
/// a runner, M2 spike): 0403 0804 0401 0503 0805 0501 0806 0601 0201. BoringSSL's own default
/// with DTLS 1.3 enabled puts ML-DSA (0904 0905 0906) in front, which Chrome's hello does not.
pub const CHROME_SIGALGS: [u16; 9] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];
/// libwebrtc's DTLS MTU (`dtls_mtu_`).
pub const CHROME_DTLS_MTU: u32 = 1200;

const DTLS_SRTP_LABEL: &str = "EXTRACTOR-dtls_srtp";

/// What one handshake settled on, for the probe's report.
#[derive(Debug, Clone)]
pub struct Handshake {
    pub active: bool,
    pub version: String,
    pub cipher: String,
    pub group: String,
    pub srtp: String,
    pub millis: u128,
}

static HANDSHAKES: Mutex<Vec<Handshake>> = Mutex::new(Vec::new());

/// Every handshake finished since the last call, oldest first.
pub fn take_handshakes() -> Vec<Handshake> {
    std::mem::take(&mut *HANDSHAKES.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The aws-lc-rs provider with its DTLS part replaced by BoringSSL.
pub fn provider() -> CryptoProvider {
    CryptoProvider { dtls_provider: &BORING, ..str0m_aws_lc_rs::default_provider() }
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
        chrome_certificate().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        _now: Instant,
        dtls_version: DtlsVersion,
        _mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        // str0m's own MTU (1150 by default) is not what Chrome uses for the handshake's
        // fragments; the record size is part of the shape, so it is libwebrtc's 1200.
        let (min, max) = match dtls_version {
            DtlsVersion::Dtls12 => (SslVersion::DTLS1_2, SslVersion::DTLS1_2),
            DtlsVersion::Dtls13 => (SslVersion::DTLS1_3, SslVersion::DTLS1_3),
            // Chrome: 1.2 to 1.3, the peer decides (and so any version str0m adds later).
            _ => (SslVersion::DTLS1_2, SslVersion::DTLS1_3),
        };
        Ok(Box::new(BoringDtls::new(cert, min, max).map_err(boring_err)?))
    }
}

fn boring_err(e: boring::error::ErrorStack) -> CryptoError {
    CryptoError::Other(format!("boring: {e}"))
}

fn op_failed(op: DtlsCryptoOperation) -> DtlsImplError {
    DtlsImplError::CryptoError(DtlsCryptoError::OperationFailed(op))
}

/// The certificate libwebrtc makes for a peer connection (KT_ECDSA).
pub fn chrome_certificate() -> Result<DtlsCert, boring::error::ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
    b.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let day = 24 * 3600;
    let not_before = Asn1Time::from_unix((now - day) as libc::time_t)?;
    let not_after = Asn1Time::from_unix((now + 30 * day) as libc::time_t)?;
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
    Ok(DtlsCert { certificate: cert.to_der()?, private_key: key.private_key_to_der()? })
}

fn chrome_context(cert: &DtlsCert, min: SslVersion, max: SslVersion) -> Result<SslContext, boring::error::ErrorStack> {
    let mut ctx = SslContextBuilder::new(SslMethod::dtls())?;
    ctx.set_min_proto_version(Some(min))?;
    ctx.set_max_proto_version(Some(max))?;
    ctx.set_cipher_list(CHROME_CIPHERS)?;
    ctx.set_curves_list(CHROME_GROUPS)?;
    ctx.set_tlsext_use_srtp(CHROME_SRTP)?;
    ctx.set_permute_extensions(true);
    // SAFETY: the context is live and the list outlives the call (BoringSSL copies it).
    let ok = unsafe {
        boring_sys::SSL_CTX_set_verify_algorithm_prefs(ctx.as_ptr(), CHROME_SIGALGS.as_ptr(), CHROME_SIGALGS.len() as _)
    };
    if ok != 1 {
        return Err(boring::error::ErrorStack::get());
    }
    ctx.set_options(SslOptions::NO_TICKET | SslOptions::NO_QUERY_MTU | SslOptions::SINGLE_ECDH_USE);
    // Both ends present a certificate; str0m checks the peer's against the SDP fingerprint.
    ctx.set_verify_callback(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT, |_, _| true);
    let x509 = X509::from_der(&cert.certificate)?;
    let key = PKey::private_key_from_der(&cert.private_key)?;
    ctx.set_certificate(&x509)?;
    ctx.set_private_key(&key)?;
    Ok(ctx.build())
}

/// The datagram pipe between str0m and BoringSSL: one read is one datagram, one write is one
/// datagram.
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
    close_received: bool,
    close_emitted: bool,
    close_sent: bool,
}

// SAFETY: str0m owns one instance per Rtc and calls it only through `&mut self`, or `&self`
// for reads of settled state; nothing here is shared between threads at once. `SslStream`
// is not `Sync` only because of the BIO method pointer it keeps, which is never touched
// outside those calls.
unsafe impl Send for BoringDtls {}
unsafe impl Sync for BoringDtls {}

impl fmt::Debug for BoringDtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringDtls").field("active", &self.active).field("established", &self.established).finish()
    }
}

impl BoringDtls {
    fn new(cert: &DtlsCert, min: SslVersion, max: SslVersion) -> Result<Self, boring::error::ErrorStack> {
        let ctx = chrome_context(cert, min, max)?;
        let mut ssl = Ssl::new(&ctx)?;
        ssl.set_mtu(CHROME_DTLS_MTU)?;
        let stream = SslStream::new(ssl, Io::default())?;
        Ok(BoringDtls {
            stream,
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
            close_received: false,
            close_emitted: false,
            close_sent: false,
        })
    }

    fn ssl_ptr(&self) -> *mut boring_sys::SSL {
        self.stream.ssl().as_ptr()
    }

    /// Moves what BoringSSL wrote to the outgoing queue and re-reads its timer.
    fn collect(&mut self) {
        let io = self.stream.get_mut();
        while let Some(p) = io.outgoing.pop_front() {
            self.packets.push_back(p);
        }
        self.refresh_deadline();
    }

    fn refresh_deadline(&mut self) {
        // SAFETY: a zeroed timeval is a valid out-parameter; the SSL pointer is live.
        let mut tv: boring_sys::timeval = unsafe { std::mem::zeroed() };
        let armed = unsafe { boring_sys::DTLSv1_get_timeout(self.ssl_ptr(), &mut tv) };
        self.deadline = if armed == 1 {
            let left = Duration::from_secs(tv.tv_sec as u64) + Duration::from_micros(tv.tv_usec as u64);
            Some(Instant::now() + left)
        } else {
            None
        };
    }

    /// Runs the handshake as far as the queued datagrams allow, then reads any records.
    fn drive(&mut self) -> Result<(), DtlsImplError> {
        let active = self.active.unwrap_or(false);
        if !self.established {
            self.started.get_or_insert_with(Instant::now);
            let r = if active { self.stream.connect() } else { self.stream.accept() };
            match r {
                Ok(()) => self.on_established()?,
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {}
                Err(e) => {
                    self.collect();
                    eprintln!("dtls-boring: handshake failed: {e}");
                    return Err(op_failed(DtlsCryptoOperation::Decrypt));
                }
            }
        }
        if self.established {
            let mut buf = vec![0u8; 16 * 1024 + 256];
            loop {
                match self.stream.ssl_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => self.app_data.push_back(buf[..n].to_vec()),
                    Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                        self.close_received = true;
                        if !self.close_sent {
                            let _ = self.stream.shutdown();
                            self.close_sent = true;
                        }
                        break;
                    }
                    Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => break,
                    Err(e) => {
                        self.collect();
                        if self.stream.get_shutdown().contains(ShutdownState::RECEIVED) {
                            self.close_received = true;
                            break;
                        }
                        eprintln!("dtls-boring: read failed: {e}");
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
        let peer = ssl.peer_certificate().ok_or(op_failed(DtlsCryptoOperation::Decrypt))?;
        self.peer_cert = Some(peer.to_der().map_err(|_| op_failed(DtlsCryptoOperation::Decrypt))?);
        let id = ssl.selected_srtp_profile().map(|p| p.id());
        let profile = match id {
            Some(SrtpProfileId::SRTP_AES128_CM_SHA1_80) => SrtpProfile::AES128_CM_SHA1_80,
            Some(SrtpProfileId::SRTP_AEAD_AES_128_GCM) => SrtpProfile::AEAD_AES_128_GCM,
            Some(SrtpProfileId::SRTP_AEAD_AES_256_GCM) => SrtpProfile::AEAD_AES_256_GCM,
            _ => return Err(op_failed(DtlsCryptoOperation::Decrypt)),
        };
        let mut km = vec![0u8; profile.keying_material_len()];
        ssl.export_keying_material(&mut km, DTLS_SRTP_LABEL, None)
            .map_err(|_| op_failed(DtlsCryptoOperation::Decrypt))?;
        self.keying = Some((km, profile));
        let hs = Handshake {
            active: self.active.unwrap_or(false),
            version: ssl.version_str().to_string(),
            cipher: ssl.current_cipher().map(|c| c.name().to_string()).unwrap_or_default(),
            group: ssl.curve_name().unwrap_or("").to_string(),
            srtp: format!("{profile:?}"),
            millis: self.started.map(|s| s.elapsed().as_millis()).unwrap_or(0),
        };
        HANDSHAKES.lock().unwrap_or_else(|e| e.into_inner()).push(hs);
        while let Some(d) = self.queued.pop_front() {
            self.write_app(&d)?;
        }
        Ok(())
    }

    fn write_app(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        match self.stream.ssl_write(data) {
            Ok(_) => {
                self.collect();
                Ok(())
            }
            Err(_) => Err(op_failed(DtlsCryptoOperation::Encrypt)),
        }
    }
}

impl DtlsInstance for BoringDtls {
    fn set_active(&mut self, active: bool) {
        self.active = Some(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        if !packet.is_empty() {
            self.stream.get_mut().incoming.push_back(packet.to_vec());
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
        DtlsOutput::Timeout(self.deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600)))
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        if self.active.is_none() {
            return Ok(());
        }
        if !self.established && self.started.is_none() {
            // str0m's first call after set_active: the client sends its ClientHello here (the
            // server's accept() only arms itself).
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

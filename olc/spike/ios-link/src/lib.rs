//! Probe (d): BoringSSL, aws-lc-rs and ring in one binary, each doing real work.
//!
//! 1. A DTLS handshake through BoringSSL: two str0m peers in-process with the BoringSSL
//!    provider (DTLS 1.2 to 1.3, so they settle on 1.3) and a data-channel echo; the SRTP,
//!    STUN HMAC and hashes in the same provider are aws-lc-rs.
//! 2. A TLS 1.3 handshake through rustls on aws-lc-rs, in memory, against a certificate rcgen
//!    makes with ring.
//! 3. ring and aws-lc-rs called directly (SHA-256, HMAC), so neither can be dropped as unused.
//!
//! `olc_spike_ios_run` is the C entry an app (c/main.c here) calls; 0 means every step held.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use olc_spike_probe::{crypto, loopback, mem, util::hex};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use str0m::config::DtlsVersion;

/// The C entry point.
#[no_mangle]
pub extern "C" fn olc_spike_ios_run() -> i32 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("FAIL: {e}");
            1
        }
    }
}

pub fn run() -> Result<(), String> {
    eprintln!("BoringSSL: {} ({})", boring::version::version(), boring::version::number());
    mem::report("start");

    // 1. DTLS through BoringSSL.
    let provider = Arc::new(olc_spike_dtls_boring::provider());
    let r = loopback::run(&provider, DtlsVersion::Auto, 1 << 20, 16 * 1024, Duration::from_secs(20))?;
    let hs = crypto::handshakes_json();
    for h in &hs {
        eprintln!("HANDSHAKE {h}");
    }
    if !hs.iter().any(|h| h.contains("\"version\":\"DTLSv1.3\"")) {
        return Err(format!("no DTLS 1.3 handshake: {hs:?}"));
    }
    for b in r.offerer_hello.iter().take(2) {
        eprintln!("DTLS_CH_TX ios {}", hex(b));
    }
    eprintln!("DTLS_OK connected_ms={} echo_ms={} bytes={}", r.connected_ms, r.echo_ms, r.bytes);
    mem::report("after-dtls");

    // 2. TLS through rustls + aws-lc-rs, with a ring-made certificate.
    let tls = tls_round_trip()?;
    eprintln!("TLS_OK {tls}");
    mem::report("after-tls");

    // 3. Both libraries directly.
    let a = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"olc");
    let g = ring::digest::digest(&ring::digest::SHA256, b"olc");
    if a.as_ref() != g.as_ref() {
        return Err("aws-lc-rs and ring disagree on SHA-256".into());
    }
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"k"), b"olc");
    let tag2 = aws_lc_rs::hmac::sign(&aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, b"k"), b"olc");
    if tag.as_ref() != tag2.as_ref() {
        return Err("aws-lc-rs and ring disagree on HMAC-SHA256".into());
    }
    eprintln!("DIGEST_OK sha256(olc)={}", hex(a.as_ref()));
    let m = mem::report("end");
    println!(
        "RESULT {{\"probe\":\"ios-link\",\"dtls13\":true,\"dtls_echo_ms\":{},\"tls\":\"{tls}\",\"mem\":{}}}",
        r.echo_ms,
        m.json()
    );
    Ok(())
}

fn tls_round_trip() -> Result<String, String> {
    let ck = rcgen::generate_simple_self_signed(vec!["olc.example".to_string()]).map_err(|e| e.to_string())?;
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let p = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = ServerConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .map_err(|e| e.to_string())?;
    let mut roots = RootCertStore::empty();
    roots.add(cert).map_err(|e| e.to_string())?;
    let client = ClientConfig::builder_with_provider(p)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from("olc.example").map_err(|e| e.to_string())?;
    let mut c = ClientConnection::new(Arc::new(client), name).map_err(|e| e.to_string())?;
    let mut s = ServerConnection::new(Arc::new(server)).map_err(|e| e.to_string())?;
    c.writer().write_all(b"ping").map_err(|e| e.to_string())?;
    let mut got = Vec::new();
    for _ in 0..20 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            s.read_tls(&mut rd).map_err(|e| e.to_string())?;
            s.process_new_packets().map_err(|e| e.to_string())?;
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).map_err(|e| e.to_string())?;
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            c.read_tls(&mut rd).map_err(|e| e.to_string())?;
            c.process_new_packets().map_err(|e| e.to_string())?;
        }
        let mut chunk = [0u8; 64];
        if let Ok(n) = s.reader().read(&mut chunk) {
            got.extend_from_slice(&chunk[..n]);
        }
        if got == b"ping" && !c.is_handshaking() {
            return Ok(format!(
                "{:?} {:?} {:?}",
                c.protocol_version(),
                c.negotiated_cipher_suite().map(|s| s.suite()),
                c.negotiated_key_exchange_group().map(|g| g.name())
            ));
        }
    }
    Err(format!("TLS: no round trip (client handshaking {}, got {got:?})", c.is_handshaking()))
}

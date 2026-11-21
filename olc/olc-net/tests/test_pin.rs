// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The test-only trust of the signalling's TLS (`shaped_tls`'s
//! `tls-test-pin`): a lab's deployment has a certificate of the lab's own
//! CA, and a test build is told that CA by its SHA-256
//! (`OLC_TLS_TEST_PIN`). This holds the pin to what a lab needs and no more,
//! against a BoringSSL server in this process, on loopback:
//!
//! - a chain under the pinned CA, for the name dialled, is trusted;
//! - the same chain for another name is refused: the name is still checked;
//! - an expired certificate under the pinned CA is refused;
//! - a chain under another CA is refused, though it would verify by itself;
//! - a leaf of the pinned CA sent without the CA is refused: the pin is a
//!   certificate the server presents, not a root the client holds;
//! - the pinned CA's own certificate as the leaf is taken as it is, which is
//!   the connector's rule for a leaf (Xray's `pinnedPeerCertSha256`) and the
//!   reason a lab pins its CA and keeps the CA's key off the server.
//!
//! The pin is read once in a process, so every test here runs under the one
//! CA `lab()` makes. `cargo test -p olc-net --features
//! alps-test-server,tls-test-pin --test test_pin` (BoringSSL: cmake and
//! libclang).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::asn1::Asn1Time;
use boring::bn::{BigNum, MsbOption};
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey::{PKey, Private};
use boring::ssl::{select_next_proto, AlpnError, Ssl, SslContext, SslContextBuilder, SslMethod};
use boring::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use boring::x509::{X509Builder, X509NameBuilder, X509};
use olc_net::shaped_tls::{client_config, FINGERPRINT, TEST_PIN_ENV};
use olc_net::stream::Offer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_transport::TlsConnector;

const NAME: &str = "meet.lab.test";
const LIMIT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const DAY: i64 = 86_400;

/// A certificate and its key.
struct Cert {
    x509: X509,
    key: PKey<Private>,
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// A builder with the fields every certificate here has; valid from
/// `from` to `to`, in days from now.
fn builder(cn: &str, from: i64, to: i64) -> X509Builder {
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(serial.to_asn1_integer().unwrap().as_ref())
        .unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap();
    let at =
        |days: i64| Asn1Time::from_unix(libc::time_t::try_from(now + days * DAY).unwrap()).unwrap();
    b.set_not_before(&at(from)).unwrap();
    b.set_not_after(&at(to)).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b
}

/// A self-signed CA.
fn ca(cn: &str) -> Cert {
    let key = key();
    let mut b = builder(cn, -1, 30);
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    b.set_issuer_name(&name.build()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b.append_extension(
        &KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    Cert {
        x509: b.build(),
        key,
    }
}

/// A server certificate for `dns` signed by `issuer`, valid from `from` to
/// `to` (days from now).
fn leaf(dns: &str, issuer: &Cert, from: i64, to: i64) -> Cert {
    let key = key();
    let mut b = builder(dns, from, to);
    b.set_issuer_name(issuer.x509.subject_name()).unwrap();
    b.set_pubkey(&key).unwrap();
    b.append_extension(&BasicConstraints::new().build().unwrap())
        .unwrap();
    b.append_extension(
        &KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    b.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let mut san = SubjectAlternativeName::new();
    san.dns(dns);
    let ext = san
        .build(&b.x509v3_context(Some(&issuer.x509), None))
        .unwrap();
    b.append_extension(&ext).unwrap();
    b.sign(&issuer.key, MessageDigest::sha256()).unwrap();
    Cert {
        x509: b.build(),
        key,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The lab's CA, made once; making it names it to this process's TLS, before
/// any dial reads the pin.
fn lab() -> &'static Cert {
    static LAB: OnceLock<Cert> = OnceLock::new();
    LAB.get_or_init(|| {
        let ca = ca("olc test lab CA");
        let pin = boring::sha::sha256(&ca.x509.to_der().unwrap());
        std::env::set_var(TEST_PIN_ENV, hex(&pin));
        ca
    })
}

/// A server for one connection: `cert` and its key, `chain` sent after it.
/// It answers one HTTP/1.1 request with `200` and `ok`.
fn serve_one(cert: &Cert, chain: &[&X509]) -> u16 {
    let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    ctx.set_certificate(&cert.x509).unwrap();
    ctx.set_private_key(&cert.key).unwrap();
    for c in chain {
        ctx.add_extra_chain_cert((*c).clone()).unwrap();
    }
    ctx.set_alpn_select_callback(|_, client| {
        select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    let ctx: SslContext = ctx.build();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let deadline = Instant::now() + LIMIT;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((tcp, _)) => {
                    let _ = tcp.set_nonblocking(false);
                    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
                    let Ok(mut tls) = Ssl::new(&ctx).unwrap().accept(tcp) else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while head.len() < 8 * 1024 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
                    );
                    let _ = tls.shutdown();
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    port
}

/// The signalling's own dial for `name` (`shaped_tls::install`'s settings,
/// nothing switched off), and one request over it.
async fn dial(port: u16, name: &str) -> Result<(), String> {
    let work = async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let cfg = client_config(name.to_owned(), Offer::WebSocket, FINGERPRINT);
        assert!(!cfg.allow_insecure);
        let (mut stream, _) = TlsConnector::system()
            .map_err(|e| format!("connector: {e}"))?
            .connect_stream_with_alpn(Box::new(tcp), &cfg)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        let head = format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut reply = vec![0u8; 256];
        let n = stream
            .read(&mut reply)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if reply[..n].starts_with(b"HTTP/1.1 200 OK\r\n") {
            Ok(())
        } else {
            Err(format!("an answer of {n} bytes that is not a 200"))
        }
    };
    tokio::time::timeout(LIMIT, work)
        .await
        .map_err(|_| "no answer within the limit".to_owned())?
}

fn refused(what: &str, got: Result<(), String>) {
    let err = got.expect_err(what);
    assert!(err.starts_with("tls: "), "{what}: refused elsewhere: {err}");
}

#[tokio::test]
async fn a_chain_under_the_pinned_ca_is_trusted_for_its_name() {
    let lab = lab();
    let cert = leaf(NAME, lab, -1, 3);
    let port = serve_one(&cert, &[&lab.x509]);
    dial(port, NAME).await.expect("the lab's own chain");
}

#[tokio::test]
async fn the_name_is_still_checked_under_the_pin() {
    let lab = lab();
    let cert = leaf(NAME, lab, -1, 3);
    let port = serve_one(&cert, &[&lab.x509]);
    refused(
        "the lab's chain for another name",
        dial(port, "other.lab.test").await,
    );
}

#[tokio::test]
async fn an_expired_certificate_is_refused_under_the_pin() {
    let lab = lab();
    let cert = leaf(NAME, lab, -3, -1);
    let port = serve_one(&cert, &[&lab.x509]);
    refused("an expired leaf of the lab's CA", dial(port, NAME).await);
}

#[tokio::test]
async fn a_chain_under_another_ca_is_refused() {
    let _ = lab();
    let other = ca("another CA");
    let cert = leaf(NAME, &other, -1, 3);
    let port = serve_one(&cert, &[&other.x509]);
    refused(
        "a chain of a CA that is not the pin",
        dial(port, NAME).await,
    );
}

#[tokio::test]
async fn a_leaf_without_the_pinned_ca_beside_it_is_refused() {
    let lab = lab();
    let cert = leaf(NAME, lab, -1, 3);
    let port = serve_one(&cert, &[]);
    refused(
        "the lab's leaf sent without the lab's CA",
        dial(port, NAME).await,
    );
}

/// The connector's rule for a pinned leaf (Xray's): the certificate with the
/// pin's hash, served as the leaf, is taken as it is, whatever name it has.
/// A lab therefore pins its CA and serves a leaf: the CA's key never sits on
/// the server, and the name is checked (the tests above).
#[tokio::test]
async fn the_pinned_certificate_itself_as_the_leaf_is_taken_as_it_is() {
    let lab = lab();
    let port = serve_one(lab, &[]);
    dial(port, NAME)
        .await
        .expect("the pinned certificate as the leaf");
}

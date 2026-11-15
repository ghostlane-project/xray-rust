// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The certificate check of TURN over TLS (`turns:`), as Chrome makes it for
//! an HTTPS server: the chain must lead to a trusted root, the leaf must be
//! valid now, valid for the name (a DNS name, or an IP literal the URL
//! named), and allowed to authenticate a server (an extended key usage, when
//! it has one, naming serverAuth). rustls-webpki does the checking against
//! webpki-roots' trust anchors (Mozilla's roots), through BoringSSL's custom
//! verify callback ([`crate::turns`]), so BoringSSL's own X.509 stack is not
//! the judge.
//!
//! What Chrome does and this does not: Chrome's root store is its own (the
//! Chrome Root Store, with its constraints and distrust dates), it enforces
//! Certificate Transparency for publicly trusted roots, consults its CRLSets
//! and revocation (soft-fail), and rejects leaves valid for more than 398
//! days. The roots are webpki-roots', and none of the others is checked.
//!
//! Trust for tests only: the cargo feature `turns-test-roots` adds one root,
//! read from the PEM file the environment variable
//! [`TEST_ROOT_ENV`] names. The shipped features never read it.

use std::sync::{Arc, OnceLock};

use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};

/// The longest chain taken: a leaf and its intermediates. A server sends
/// two or three; a longer chain is refused before any signature is checked.
pub const MAX_CHAIN: usize = 8;

/// The environment variable the `turns-test-roots` feature reads: a PEM file
/// holding one root certificate.
pub const TEST_ROOT_ENV: &str = "OLC_TURNS_TEST_ROOT";

/// Why a chain was refused.
pub type VerifyError = webpki::Error;

/// Checks `chain` (DER certificates, the leaf first) for `name` at `now`
/// against `extra` (roots added by a test) and webpki-roots' roots.
///
/// # Errors
/// The chain is empty, too long, malformed, not trusted, not valid at
/// `now`, not valid for `name` or not for server authentication.
pub fn verify_server_chain(
    chain: &[Vec<u8>],
    name: &ServerName<'_>,
    now: UnixTime,
    extra: &[TrustAnchor<'static>],
) -> Result<(), VerifyError> {
    let Some(first) = chain.first() else {
        return Err(webpki::Error::BadDer);
    };
    if chain.len() > MAX_CHAIN {
        return Err(webpki::Error::BadDer);
    }
    let leaf = CertificateDer::from(first.as_slice());
    let ee = EndEntityCert::try_from(&leaf)?;
    let inter: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let against = |anchors: &[TrustAnchor<'_>]| {
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            anchors,
            &inter,
            now,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
    };
    let trusted = if extra.is_empty() {
        against(webpki_roots::TLS_SERVER_ROOTS)
    } else {
        against(extra).or_else(|_| against(webpki_roots::TLS_SERVER_ROOTS))
    };
    trusted?;
    ee.verify_is_valid_for_subject_name(name)
}

/// The roots the shipped client adds to webpki-roots': none, whatever the
/// environment says, unless the `turns-test-roots` feature is on.
#[must_use]
pub fn shipped_extra_roots() -> Arc<Vec<TrustAnchor<'static>>> {
    static ROOTS: OnceLock<Arc<Vec<TrustAnchor<'static>>>> = OnceLock::new();
    Arc::clone(ROOTS.get_or_init(|| Arc::new(test_roots())))
}

#[cfg(feature = "turns-test-roots")]
fn test_roots() -> Vec<TrustAnchor<'static>> {
    let Ok(path) = std::env::var(TEST_ROOT_ENV) else {
        return Vec::new();
    };
    let der = match std::fs::read(&path)
        .map_err(|e| e.to_string())
        .and_then(|pem| boring::x509::X509::from_pem(&pem).map_err(|e| e.to_string()))
        .and_then(|x| x.to_der().map_err(|e| e.to_string()))
    {
        Ok(der) => der,
        Err(e) => {
            olc_net::info!("webrtc: TURN test root {path}: {e}");
            return Vec::new();
        }
    };
    match anchor_of(&der) {
        Ok(a) => vec![a],
        Err(e) => {
            olc_net::info!("webrtc: TURN test root {path}: {e}");
            Vec::new()
        }
    }
}

#[cfg(not(feature = "turns-test-roots"))]
fn test_roots() -> Vec<TrustAnchor<'static>> {
    Vec::new()
}

/// A trust anchor from a root certificate's DER.
///
/// # Errors
/// The DER is not a certificate a root can be made of.
pub fn anchor_of(der: &[u8]) -> Result<TrustAnchor<'static>, VerifyError> {
    let cert = CertificateDer::from(der);
    Ok(webpki::anchor_from_trusted_cert(&cert)?.to_owned())
}

#[cfg(test)]
pub(crate) mod testpki {
    //! Certificates for the tests, made with BoringSSL.

    use boring::asn1::Asn1Time;
    use boring::bn::{BigNum, MsbOption};
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::{PKey, Private};
    use boring::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage as KU, SubjectAlternativeName,
    };
    use boring::x509::{X509Builder, X509NameBuilder, X509};

    /// A certificate and its key.
    pub(crate) struct Cert {
        pub(crate) x509: X509,
        pub(crate) key: PKey<Private>,
    }

    /// What a leaf is made for.
    pub(crate) struct Leaf<'a> {
        pub(crate) dns: &'a [&'a str],
        pub(crate) ips: &'a [&'a str],
        /// `None`: no extended key usage; else `server`, `client`.
        pub(crate) eku: Option<&'a str>,
        /// Days from now: the validity's start and end.
        pub(crate) from_days: i32,
        pub(crate) to_days: u32,
    }

    impl Leaf<'_> {
        pub(crate) fn new<'a>(dns: &'a [&'a str], ips: &'a [&'a str]) -> Leaf<'a> {
            Leaf {
                dns,
                ips,
                eku: Some("server"),
                from_days: 0,
                to_days: 30,
            }
        }
    }

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn serial() -> boring::asn1::Asn1Integer {
        let mut b = BigNum::new().unwrap();
        b.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        b.to_asn1_integer().unwrap()
    }

    fn name(cn: &str) -> boring::x509::X509Name {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        n.build()
    }

    fn validity(b: &mut X509Builder, from_days: i32, to_days: u32) {
        // `days_from_now` takes unsigned days: a start in the past is made
        // from the current time minus the seconds.
        let from = if from_days >= 0 {
            Asn1Time::days_from_now(from_days.unsigned_abs()).unwrap()
        } else {
            Asn1Time::from_unix(
                i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                )
                .unwrap()
                    - i64::from(from_days.unsigned_abs()) * 86_400,
            )
            .unwrap()
        };
        b.set_not_before(&from).unwrap();
        b.set_not_after(&Asn1Time::days_from_now(to_days).unwrap())
            .unwrap();
    }

    /// A self-signed CA.
    pub(crate) fn ca(cn: &str) -> Cert {
        let key = key();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        let n = name(cn);
        b.set_subject_name(&n).unwrap();
        b.set_issuer_name(&n).unwrap();
        b.set_pubkey(&key).unwrap();
        validity(&mut b, -1, 3650);
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KU::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
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

    /// An intermediate CA signed by `issuer`.
    pub(crate) fn intermediate(cn: &str, issuer: &Cert) -> Cert {
        let key = key();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name(cn)).unwrap();
        b.set_issuer_name(issuer.x509.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        validity(&mut b, -1, 3000);
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KU::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.sign(&issuer.key, MessageDigest::sha256()).unwrap();
        Cert {
            x509: b.build(),
            key,
        }
    }

    /// A server certificate signed by `issuer`.
    pub(crate) fn leaf(spec: &Leaf<'_>, issuer: &Cert) -> Cert {
        let key = key();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name(spec.dns.first().copied().unwrap_or("leaf")))
            .unwrap();
        b.set_issuer_name(issuer.x509.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        validity(&mut b, spec.from_days, spec.to_days);
        b.append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        b.append_extension(KU::new().critical().digital_signature().build().unwrap())
            .unwrap();
        match spec.eku {
            Some("server") => b
                .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
                .unwrap(),
            Some("client") => b
                .append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
                .unwrap(),
            _ => {}
        }
        let mut san = SubjectAlternativeName::new();
        for d in spec.dns {
            san.dns(d);
        }
        for i in spec.ips {
            san.ip(i);
        }
        let ctx = b.x509v3_context(Some(&issuer.x509), None);
        let ext = san.build(&ctx).unwrap();
        b.append_extension(ext).unwrap();
        b.sign(&issuer.key, MessageDigest::sha256()).unwrap();
        Cert {
            x509: b.build(),
            key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testpki::{ca, intermediate, leaf, Leaf};
    use super::*;

    fn now() -> UnixTime {
        UnixTime::now()
    }

    fn days(n: u64) -> UnixTime {
        UnixTime::since_unix_epoch(
            now()
                .as_secs()
                .checked_add(n * 86_400)
                .map_or(std::time::Duration::ZERO, std::time::Duration::from_secs),
        )
    }

    fn dns(n: &str) -> ServerName<'static> {
        ServerName::try_from(n.to_owned()).unwrap()
    }

    fn chain(certs: &[&super::testpki::Cert]) -> Vec<Vec<u8>> {
        certs.iter().map(|c| c.x509.to_der().unwrap()).collect()
    }

    fn root_of(c: &super::testpki::Cert) -> Vec<TrustAnchor<'static>> {
        vec![anchor_of(&c.x509.to_der().unwrap()).unwrap()]
    }

    #[test]
    fn a_chain_to_a_trusted_root_for_the_name_is_taken() {
        let root = ca("olc test root");
        let l = leaf(&Leaf::new(&["turn.olc.test"], &[]), &root);
        let got = verify_server_chain(&chain(&[&l]), &dns("turn.olc.test"), now(), &root_of(&root));
        assert_eq!(got, Ok(()));
        // Through an intermediate the server sends.
        let mid = intermediate("olc test intermediate", &root);
        let l = leaf(&Leaf::new(&["turn.olc.test"], &[]), &mid);
        let got = verify_server_chain(
            &chain(&[&l, &mid]),
            &dns("turn.olc.test"),
            now(),
            &root_of(&root),
        );
        assert_eq!(got, Ok(()));
        // Without it the issuer is unknown.
        let got = verify_server_chain(&chain(&[&l]), &dns("turn.olc.test"), now(), &root_of(&root));
        assert_eq!(got, Err(webpki::Error::UnknownIssuer));
    }

    #[test]
    fn a_root_nobody_trusts_is_refused() {
        let root = ca("olc test root");
        let other = ca("another root");
        let l = leaf(&Leaf::new(&["turn.olc.test"], &[]), &root);
        // Neither the test roots nor Mozilla's hold it.
        let got = verify_server_chain(&chain(&[&l]), &dns("turn.olc.test"), now(), &[]);
        assert_eq!(got, Err(webpki::Error::UnknownIssuer));
        let got = verify_server_chain(
            &chain(&[&l]),
            &dns("turn.olc.test"),
            now(),
            &root_of(&other),
        );
        assert_eq!(got, Err(webpki::Error::UnknownIssuer));
    }

    #[test]
    fn a_certificate_for_another_name_is_refused() {
        let root = ca("olc test root");
        let l = leaf(&Leaf::new(&["turn.olc.test"], &[]), &root);
        let got = verify_server_chain(
            &chain(&[&l]),
            &dns("other.olc.test"),
            now(),
            &root_of(&root),
        );
        assert!(
            matches!(got, Err(webpki::Error::CertNotValidForName(_))),
            "{got:?}"
        );
    }

    #[test]
    fn an_address_literal_is_checked_against_the_address_names() {
        let root = ca("olc test root");
        let l = leaf(&Leaf::new(&["turn.olc.test"], &["127.0.0.1"]), &root);
        let ip = |s: &str| ServerName::try_from(s.to_owned()).unwrap();
        assert!(matches!(ip("127.0.0.1"), ServerName::IpAddress(_)));
        let got = verify_server_chain(&chain(&[&l]), &ip("127.0.0.1"), now(), &root_of(&root));
        assert_eq!(got, Ok(()));
        let got = verify_server_chain(&chain(&[&l]), &ip("127.0.0.2"), now(), &root_of(&root));
        assert!(
            matches!(got, Err(webpki::Error::CertNotValidForName(_))),
            "{got:?}"
        );
        // A DNS name in the certificate is no IP's.
        let l = leaf(&Leaf::new(&["127.0.0.1"], &[]), &root);
        let got = verify_server_chain(&chain(&[&l]), &ip("127.0.0.1"), now(), &root_of(&root));
        assert!(
            matches!(got, Err(webpki::Error::CertNotValidForName(_))),
            "{got:?}"
        );
    }

    #[test]
    fn a_certificate_out_of_its_validity_is_refused() {
        let root = ca("olc test root");
        let l = leaf(&Leaf::new(&["turn.olc.test"], &[]), &root);
        let got = verify_server_chain(
            &chain(&[&l]),
            &dns("turn.olc.test"),
            days(40),
            &root_of(&root),
        );
        assert!(
            matches!(got, Err(webpki::Error::CertExpired { .. })),
            "{got:?}"
        );
        let future = Leaf {
            from_days: 10,
            to_days: 40,
            ..Leaf::new(&["turn.olc.test"], &[])
        };
        let l = leaf(&future, &root);
        let got = verify_server_chain(&chain(&[&l]), &dns("turn.olc.test"), now(), &root_of(&root));
        assert!(
            matches!(got, Err(webpki::Error::CertNotValidYet { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn a_certificate_not_for_servers_is_refused() {
        let root = ca("olc test root");
        let client_only = Leaf {
            eku: Some("client"),
            ..Leaf::new(&["turn.olc.test"], &[])
        };
        let l = leaf(&client_only, &root);
        let got = verify_server_chain(&chain(&[&l]), &dns("turn.olc.test"), now(), &root_of(&root));
        assert!(got.is_err(), "a clientAuth-only certificate was taken");
        // No extended key usage at all is any purpose (RFC 5280 section
        // 4.2.1.12), as Chrome takes it.
        let none = Leaf {
            eku: None,
            ..Leaf::new(&["turn.olc.test"], &[])
        };
        let l = leaf(&none, &root);
        let got = verify_server_chain(&chain(&[&l]), &dns("turn.olc.test"), now(), &root_of(&root));
        assert_eq!(got, Ok(()));
    }

    #[test]
    fn an_empty_or_long_or_garbled_chain_is_refused() {
        let root = ca("olc test root");
        let l = leaf(&Leaf::new(&["turn.olc.test"], &[]), &root);
        let n = dns("turn.olc.test");
        assert!(verify_server_chain(&[], &n, now(), &root_of(&root)).is_err());
        let long = vec![l.x509.to_der().unwrap(); MAX_CHAIN + 1];
        assert!(verify_server_chain(&long, &n, now(), &root_of(&root)).is_err());
        assert!(verify_server_chain(&[vec![1, 2, 3]], &n, now(), &root_of(&root)).is_err());
    }

    /// The shipped client adds no root of its own: the feature is the only
    /// way in, and this build's test for it is the end-to-end one.
    #[test]
    fn the_shipped_extra_roots_follow_the_feature() {
        if !cfg!(feature = "turns-test-roots") {
            assert!(shipped_extra_roots().is_empty());
        }
    }
}

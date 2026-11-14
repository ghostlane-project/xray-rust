//! The `chrome` fingerprint held to Google Chrome 156 itself.
//!
//! `tests/fixtures/chrome156/` holds fourteen first flights a lab captured from
//! Chrome 156.0.8078.79 (headless, a fresh profile, Linux x86_64): seven to a
//! REALITY server name, `reality.lab.test`, and seven to a plain TLS one,
//! `webtunnel.lab.test`. Each file is the client's bytes as they left it: the
//! ClientHello record, a ChangeCipherSpec, and the encrypted alert Chrome sent
//! when it did not trust the lab's certificate. They hold lab names and
//! throwaway keys only.
//!
//! Hellos this crate builds under `chrome` for the same names, plain TLS and
//! REALITY, are read the way the captures are and compared with them:
//!
//! * byte for byte, everything Chrome sends the same on every connection: the
//!   record header, the cipher suites (all fifteen, the six TLS-1.2-only ones
//!   included), the extensions present and every body but the drawn ones, the
//!   server name included;
//! * as a draw, what Chrome draws anew for each connection: the GREASE values
//!   (cipher, group, the key share tied to the group, version, signature
//!   algorithm, and the two extensions, which never agree), the ECH GREASE
//!   payload (one of 144, 176, 208 and 240 bytes behind a 32-byte `enc`), and
//!   the order of the extensions between the two GREASE ones.
//!
//! Key share and ECH material is random in both and compared by its layout.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use xray_transport::{
    plain_tls_client_hello_bytes,
    reality_connector::{RealityClientHelloRequest, RealityTlsSessionProvider},
    RustlsRealityTlsSessionProvider, TlsClientConfig,
};

const REALITY_NAME: &str = "reality.lab.test";
const TLS_NAME: &str = "webtunnel.lab.test";

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// Where every GREASE value is written in a canonical hello.
const GREASE: u16 = 0x0a0a;
/// BoringSSL's ECH GREASE payloads: `32 * [4, 7] + 16`.
const ECH_PAYLOAD_LENGTHS: [usize; 4] = [144, 176, 208, 240];
/// How many hellos each test builds: all four ECH lengths come up in 96 with
/// odds of missing one below `10^-11`.
const HELLOS: usize = 96;

macro_rules! capture {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!("../../../tests/fixtures/chrome156/", $name, ".bin")) as &[u8],
        )
    };
}

const REALITY_CAPTURES: [(&str, &[u8]); 7] = [
    capture!("reality-first-flight-1-1"),
    capture!("reality-first-flight-1-2"),
    capture!("reality-first-flight-1-3"),
    capture!("reality-first-flight-2-1"),
    capture!("reality-first-flight-2-2"),
    capture!("reality-first-flight-3-1"),
    capture!("reality-first-flight-3-2"),
];

const TLS_CAPTURES: [(&str, &[u8]); 7] = [
    capture!("tls-first-flight-1-1"),
    capture!("tls-first-flight-1-2"),
    capture!("tls-first-flight-2-1"),
    capture!("tls-first-flight-2-2"),
    capture!("tls-first-flight-3-1"),
    capture!("tls-first-flight-3-2"),
    capture!("tls-first-flight-3-3"),
];

fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// `bytes` read as a list of u16s.
fn u16s(bytes: &[u8]) -> Vec<u16> {
    assert_eq!(bytes.len() % 2, 0, "a list of u16s has an even length");
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

fn canonical(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .map(|value| if is_grease(*value) { GREASE } else { *value })
        .collect()
}

/// A list of u16s behind a length of `prefix` bytes, written back with every
/// GREASE value canonical.
fn canonical_list(body: &[u8], prefix: usize) -> (Vec<u16>, Vec<u8>) {
    let listed = match prefix {
        1 => usize::from(body[0]),
        _ => usize::from(u16_at(body, 0)),
    };
    assert_eq!(listed, body.len() - prefix, "the list fills its body");
    let values = u16s(&body[prefix..]);
    let mut out = body[..prefix].to_vec();
    for value in canonical(&values) {
        out.extend_from_slice(&value.to_be_bytes());
    }
    (values, out)
}

/// The ClientHello handshake message of a first flight, after checking its
/// record header: a handshake record at version 0x0301, as Chrome and rustls
/// both write the first one.
fn hello_of_flight(flight: &[u8]) -> &[u8] {
    assert_eq!(
        flight[..3],
        [0x16, 0x03, 0x01],
        "a TLS 1.0 handshake record"
    );
    let length = usize::from(u16_at(flight, 3));
    &flight[5..5 + length]
}

/// What Chrome sends the same on every connection to one name.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    legacy_version: u16,
    session_id_len: usize,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    /// Every extension between the two GREASE ones by type, its body
    /// canonical: GREASE values written as 0x0a0a, a key share as its group
    /// and length, the ECH GREASE extension as its fixed fields.
    extensions: BTreeMap<u16, Vec<u8>>,
}

/// What Chrome draws anew for every connection.
#[derive(Debug)]
struct Draws {
    /// cipher, group, version, signature algorithm, first and last extension.
    grease: [u16; 6],
    ech_payload_len: usize,
    /// The extension types between the two GREASE extensions, in order.
    order: Vec<u16>,
}

/// Reads a ClientHello handshake message, from its type byte, into what
/// stays and what is drawn, checking on the way every rule the draws follow.
fn read(hello: &[u8]) -> (Shape, Draws) {
    assert_eq!(hello[0], 0x01, "a ClientHello");
    let length = (usize::from(hello[1]) << 16) | usize::from(u16_at(hello, 2));
    assert_eq!(length, hello.len() - 4, "the handshake length");
    let legacy_version = u16_at(hello, 4);
    let mut cursor = 4 + 2 + 32;
    let session_id_len = usize::from(hello[cursor]);
    cursor += 1 + session_id_len;
    let suites_len = usize::from(u16_at(hello, cursor));
    let suites = u16s(&hello[cursor + 2..cursor + 2 + suites_len]);
    cursor += 2 + suites_len;
    let compression_len = usize::from(hello[cursor]);
    let compression_methods = hello[cursor + 1..cursor + 1 + compression_len].to_vec();
    cursor += 1 + compression_len;
    let extensions_end = cursor + 2 + usize::from(u16_at(hello, cursor));
    assert_eq!(extensions_end, hello.len(), "the extensions end the hello");
    cursor += 2;
    let mut listed = Vec::new();
    while cursor < extensions_end {
        let body_len = usize::from(u16_at(hello, cursor + 2));
        listed.push((
            u16_at(hello, cursor),
            &hello[cursor + 4..cursor + 4 + body_len],
        ));
        cursor += 4 + body_len;
    }
    assert_eq!(cursor, extensions_end, "the last extension ends the hello");

    // The two GREASE extensions frame the rest: the first empty, the last one
    // zero byte, each its own value.
    let ((first, first_body), rest) = listed.split_first().expect("extensions");
    let ((last, last_body), middle) = rest.split_last().expect("extensions");
    assert!(is_grease(*first), "first extension {first:#06x}");
    assert!(is_grease(*last), "last extension {last:#06x}");
    assert_ne!(first, last, "the two GREASE extensions differ");
    assert_eq!((*first_body, *last_body), (&[][..], &[0u8][..]));

    assert!(is_grease(suites[0]), "GREASE leads the cipher suites");
    let mut extensions = BTreeMap::new();
    let mut order = Vec::new();
    let mut group_grease = None;
    let mut key_share_grease = None;
    let mut version_grease = None;
    let mut signature_grease = None;
    let mut ech_payload_len = None;
    for (extension_type, body) in middle {
        assert!(
            !is_grease(*extension_type),
            "a third GREASE extension, {extension_type:#06x}"
        );
        order.push(*extension_type);
        let canonical_body = match *extension_type {
            EXT_SUPPORTED_GROUPS => {
                let (groups, out) = canonical_list(body, 2);
                group_grease = Some(groups[0]);
                out
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let (schemes, out) = canonical_list(body, 2);
                signature_grease = Some(schemes[0]);
                out
            }
            EXT_SUPPORTED_VERSIONS => {
                let (versions, out) = canonical_list(body, 1);
                version_grease = Some(versions[0]);
                out
            }
            EXT_KEY_SHARE => {
                assert_eq!(usize::from(u16_at(body, 0)), body.len() - 2);
                let mut out = Vec::new();
                let mut share = 2;
                while share < body.len() {
                    let group = u16_at(body, share);
                    let exchange_len = usize::from(u16_at(body, share + 2));
                    let exchange = &body[share + 4..share + 4 + exchange_len];
                    if is_grease(group) {
                        assert_eq!(exchange, [0], "a GREASE key share is one zero byte");
                        key_share_grease.get_or_insert(group);
                    } else {
                        assert!(
                            exchange.iter().any(|byte| *byte != 0),
                            "{group:#06x}: a real key share"
                        );
                    }
                    out.extend_from_slice(&canonical(&[group])[0].to_be_bytes());
                    out.extend_from_slice(&(exchange_len as u16).to_be_bytes());
                    share += 4 + exchange_len;
                }
                assert_eq!(share, body.len(), "the key shares fill their body");
                out
            }
            EXT_ENCRYPTED_CLIENT_HELLO => {
                // An outer ECHClientHello: type 0, HKDF-SHA256, AES-128-GCM,
                // a random config id, a 32-byte enc and the payload.
                assert_eq!(body[..5], [0x00, 0x00, 0x01, 0x00, 0x01], "ECH suite");
                assert_eq!(u16_at(body, 6), 32, "ECH enc length");
                let enc = &body[8..40];
                assert!(enc.iter().any(|byte| *byte != 0), "a real enc");
                let payload_len = usize::from(u16_at(body, 40));
                assert_eq!(body.len(), 42 + payload_len, "the payload ends the body");
                assert!(
                    ECH_PAYLOAD_LENGTHS.contains(&payload_len),
                    "ECH payload of {payload_len} bytes"
                );
                ech_payload_len = Some(payload_len);
                body[..5].to_vec()
            }
            _ => body.to_vec(),
        };
        assert!(
            extensions.insert(*extension_type, canonical_body).is_none(),
            "{extension_type:#06x} twice"
        );
    }

    let group_grease = group_grease.expect("supported_groups");
    assert!(is_grease(group_grease), "GREASE leads supported_groups");
    assert_eq!(
        key_share_grease,
        Some(group_grease),
        "the GREASE key share takes supported_groups' GREASE value"
    );
    let version_grease = version_grease.expect("supported_versions");
    assert!(is_grease(version_grease), "GREASE leads supported_versions");
    let signature_grease = signature_grease.expect("signature_algorithms");
    assert!(
        is_grease(signature_grease),
        "GREASE leads signature_algorithms"
    );

    (
        Shape {
            legacy_version,
            session_id_len,
            cipher_suites: canonical(&suites),
            compression_methods,
            extensions,
        },
        Draws {
            grease: [
                suites[0],
                group_grease,
                version_grease,
                signature_grease,
                *first,
                *last,
            ],
            ech_payload_len: ech_payload_len.expect("an ECH GREASE extension"),
            order,
        },
    )
}

/// The one shape every capture of `captures` shows, with their draws.
fn chrome(captures: &[(&str, &[u8])]) -> (Shape, Vec<Draws>) {
    let mut shape = None;
    let mut draws = Vec::new();
    for (name, flight) in captures {
        let (this, drawn) = read(hello_of_flight(flight));
        match &shape {
            None => shape = Some(this),
            Some(shape) => assert_eq!(&this, shape, "{name}: Chrome's own shape changed"),
        }
        draws.push(drawn);
    }
    (shape.expect("captures"), draws)
}

/// What a run of hellos drew: each holds to the rules `read` checks, and
/// together they show the spread a real draw shows.
fn assert_drawn_as_chrome_draws(draws: &[Draws]) {
    let orders = draws
        .iter()
        .map(|draws| draws.order.clone())
        .collect::<HashSet<_>>();
    assert!(
        orders.len() > draws.len() / 2,
        "{} extension orders in {} hellos",
        orders.len(),
        draws.len()
    );
    let ech = draws
        .iter()
        .map(|draws| draws.ech_payload_len)
        .collect::<BTreeSet<_>>();
    assert_eq!(ech, ECH_PAYLOAD_LENGTHS.into_iter().collect());
    for slot in 0..6 {
        let values = draws
            .iter()
            .map(|draws| draws.grease[slot])
            .collect::<HashSet<_>>();
        assert!(values.len() > 4, "GREASE slot {slot}: {values:04x?}");
    }
}

fn plain_tls_chrome_hello() -> Vec<u8> {
    plain_tls_client_hello_bytes(&TlsClientConfig {
        server_name: TLS_NAME.to_owned(),
        allow_insecure: false,
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: Vec::new(),
        fingerprint: Some("chrome".to_owned()),
    })
    .expect("a chrome ClientHello")
}

fn reality_chrome_hello(provider: &RustlsRealityTlsSessionProvider) -> Vec<u8> {
    let prepared = provider
        .create_session(RealityClientHelloRequest {
            server_name: REALITY_NAME,
            fingerprint: "chrome",
        })
        .expect("a chrome REALITY session")
        .prepared_client_hello()
        .expect("a prepared ClientHello");
    prepared.raw_client_hello.clone()
}

/// The captures agree with each other on everything this file calls fixed,
/// and differ in what it calls drawn: fourteen hellos, fourteen orders, and
/// each of the four ECH lengths.
#[test]
fn the_captures_show_one_chrome_156_shape_per_name() {
    let (reality, reality_draws) = chrome(&REALITY_CAPTURES);
    let (tls, tls_draws) = chrome(&TLS_CAPTURES);
    assert_eq!(
        reality.cipher_suites,
        [
            GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ]
    );
    assert_eq!(reality.extensions.len(), 17);
    // The two names differ in the server name alone.
    let without_name = |shape: &Shape| {
        let mut extensions = shape.extensions.clone();
        extensions.remove(&EXT_SERVER_NAME);
        extensions
    };
    assert_eq!(without_name(&reality), without_name(&tls));
    let all = reality_draws.iter().chain(&tls_draws).collect::<Vec<_>>();
    assert_eq!(
        all.iter()
            .map(|draws| draws.order.clone())
            .collect::<HashSet<_>>()
            .len(),
        14
    );
    assert_eq!(
        all.iter()
            .map(|draws| draws.ech_payload_len)
            .collect::<BTreeSet<_>>(),
        ECH_PAYLOAD_LENGTHS.into_iter().collect()
    );
}

/// A plain TLS hello under `chrome` is Chrome 156's for the same name.
#[test]
fn a_plain_tls_chrome_hello_is_chrome_156s() {
    let (expected, _) = chrome(&TLS_CAPTURES);
    let mut draws = Vec::new();
    for _ in 0..HELLOS {
        let (shape, drawn) = read(hello_of_flight(&plain_tls_chrome_hello()));
        assert_eq!(shape, expected);
        draws.push(drawn);
    }
    assert_drawn_as_chrome_draws(&draws);
}

/// A REALITY hello under `chrome` is Chrome 156's for the same name. Its
/// session id is still the zeros REALITY seals over; its length is Chrome's.
#[test]
fn a_reality_chrome_hello_is_chrome_156s() {
    let (expected, _) = chrome(&REALITY_CAPTURES);
    let provider = RustlsRealityTlsSessionProvider::new();
    let mut draws = Vec::new();
    for _ in 0..HELLOS {
        let (shape, drawn) = read(&reality_chrome_hello(&provider));
        assert_eq!(shape, expected);
        draws.push(drawn);
    }
    assert_drawn_as_chrome_draws(&draws);
}

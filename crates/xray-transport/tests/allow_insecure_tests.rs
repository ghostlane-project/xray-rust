//! What `TlsClientConfig::allow_insecure` waives, against self-signed
//! servers on loopback, over TCP TLS and over Hysteria 2's QUIC: the
//! certificate check and nothing else. Without it the system roots refuse
//! the server as they always did; with it the connection carries data; the
//! ClientHello's server name and ALPN are the same either way; and a pin or a
//! verification name beside it still verifies.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use xray_proxy::hysteria::decode_tcp_request;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::{HysteriaClient, HysteriaConfig, HysteriaError};
use xray_transport::{TlsClientConfig, TlsConnector, TransportError};

const DEADLINE: Duration = Duration::from_secs(10);
const AUTH: &str = "synthetic-allow-insecure-auth";

/// Aborts its task when dropped, so a failed assertion leaves no server.
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A self-signed certificate for `localhost`, which no system root issued.
struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    sha256: [u8; 32],
}

fn identity() -> Identity {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = generated.cert.der().clone();
    let sha256 = Sha256::digest(certificate.as_ref()).into();
    Identity {
        certificate,
        key: PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()),
        sha256,
    }
}

/// On aws-lc-rs, which has every key exchange group a shaped hello plans.
fn server_config(
    identity: &Identity,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![identity.certificate.clone()],
        PrivateKeyDer::Pkcs8(identity.key.clone_key()),
    )
    .unwrap();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

fn client(allow_insecure: bool, fingerprint: &str) -> TlsClientConfig {
    TlsClientConfig {
        server_name: "localhost".into(),
        allow_insecure,
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: vec!["h2".into(), "http/1.1".into()],
        fingerprint: Some(fingerprint.into()),
    }
}

/// What one TCP connection showed the server: its hello's server name and
/// ALPN, and whether the handshake finished.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    server_name: Option<String>,
    alpn: Vec<Vec<u8>>,
    finished: bool,
}

/// A TLS echo server on loopback that reports every connection.
async fn tls_echo(identity: &Identity) -> (SocketAddr, mpsc::UnboundedReceiver<Seen>, Task) {
    let config = Arc::new(server_config(
        identity,
        rustls::ALL_VERSIONS,
        &[b"h2", b"http/1.1"],
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen, reports) = mpsc::unbounded_channel();
    let task = Task(tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let (config, seen) = (Arc::clone(&config), seen.clone());
            tokio::spawn(async move {
                let acceptor = tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    socket,
                );
                let Ok(start) = acceptor.await else {
                    return;
                };
                let hello = start.client_hello();
                let server_name = hello.server_name().map(str::to_owned);
                let alpn = hello
                    .alpn()
                    .map(|list| list.map(<[u8]>::to_vec).collect())
                    .unwrap_or_default();
                match start.into_stream(config).await {
                    Ok(mut stream) => {
                        let _ = seen.send(Seen {
                            server_name,
                            alpn,
                            finished: true,
                        });
                        let mut buffer = [0; 64];
                        while let Ok(n) = stream.read(&mut buffer).await {
                            if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                            let _ = stream.flush().await;
                        }
                    }
                    Err(_) => {
                        let _ = seen.send(Seen {
                            server_name,
                            alpn,
                            finished: false,
                        });
                    }
                }
            });
        }
    }));
    (address, reports, task)
}

async fn next(reports: &mut mpsc::UnboundedReceiver<Seen>) -> Seen {
    timeout(DEADLINE, reports.recv())
        .await
        .expect("the server reports the connection")
        .unwrap()
}

/// A TLS dial that sends a line and reads it back.
async fn echo_over_tls(
    connector: &TlsConnector,
    address: SocketAddr,
    config: &TlsClientConfig,
) -> Result<(), TransportError> {
    let mut stream = timeout(DEADLINE, connector.connect_socket_addr(address, config))
        .await
        .expect("the dial ends")?;
    stream.write_all(b"carried").await.unwrap();
    stream.flush().await.unwrap();
    let mut back = [0; 7];
    timeout(DEADLINE, stream.read_exact(&mut back))
        .await
        .expect("the echo comes back")
        .unwrap();
    assert_eq!(&back, b"carried");
    Ok(())
}

fn a_handshake_failure(result: Result<(), TransportError>, case: &str) {
    match result {
        Err(TransportError::Tls(_)) => {}
        other => panic!("{case}: the handshake must fail on the certificate, got {other:?}"),
    }
}

#[tokio::test]
async fn tcp_tls_refuses_a_self_signed_server_without_the_flag_and_carries_it_with_the_flag() {
    let identity = identity();
    let (address, mut reports, _server) = tls_echo(&identity).await;
    let connector = TlsConnector::system().unwrap();
    for fingerprint in ["chrome", "firefox", "unsafe"] {
        a_handshake_failure(
            echo_over_tls(&connector, address, &client(false, fingerprint)).await,
            fingerprint,
        );
        let strict = next(&mut reports).await;
        assert!(!strict.finished, "{fingerprint}: {strict:?}");

        echo_over_tls(&connector, address, &client(true, fingerprint))
            .await
            .unwrap_or_else(|error| panic!("{fingerprint}: the flag carries: {error}"));
        let waived = next(&mut reports).await;
        assert!(waived.finished, "{fingerprint}: {waived:?}");

        // The flag waives the check only: the hello names the same server
        // and offers the same protocols.
        assert_eq!(strict.server_name.as_deref(), Some("localhost"));
        assert_eq!(
            (&strict.server_name, &strict.alpn),
            (&waived.server_name, &waived.alpn),
            "{fingerprint}"
        );
        assert!(!waived.alpn.is_empty(), "{fingerprint}: {waived:?}");
    }
}

#[tokio::test]
async fn tcp_tls_a_pin_or_a_name_beside_the_flag_still_verifies() {
    let identity = identity();
    let (address, mut reports, _server) = tls_echo(&identity).await;
    let connector = TlsConnector::system().unwrap();
    for fingerprint in ["chrome", "unsafe"] {
        // The server's own certificate, pinned: carried, with the flag or
        // without it.
        for allow_insecure in [false, true] {
            let mut pinned = client(allow_insecure, fingerprint);
            pinned.pinned_peer_cert_sha256 = vec![identity.sha256];
            echo_over_tls(&connector, address, &pinned)
                .await
                .unwrap_or_else(|error| {
                    panic!("{fingerprint}, flag {allow_insecure}: the pin carries: {error}")
                });
            assert!(next(&mut reports).await.finished);
        }

        // Another certificate's pin: the flag does not waive it.
        let mut other = client(true, fingerprint);
        other.pinned_peer_cert_sha256 = vec![[0x5a; 32]];
        a_handshake_failure(
            echo_over_tls(&connector, address, &other).await,
            "another pin",
        );
        assert!(!next(&mut reports).await.finished);

        // A verification name verifies against the system roots: the flag
        // does not waive that either.
        let mut named = client(true, fingerprint);
        named.verify_peer_cert_by_name = vec!["localhost".into()];
        a_handshake_failure(
            echo_over_tls(&connector, address, &named).await,
            "a verification name",
        );
        assert!(!next(&mut reports).await.finished);
    }
}

/// A Hysteria 2 server on loopback with a self-signed certificate: it
/// reports each QUIC handshake, answers the authentication and echoes every
/// TCP stream.
struct HysteriaEcho {
    address: SocketAddr,
    handshakes: mpsc::UnboundedReceiver<bool>,
    endpoint: quinn::Endpoint,
    _task: Task,
}

impl Drop for HysteriaEcho {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
    }
}

fn hysteria_echo(identity: &Identity) -> HysteriaEcho {
    let tls = server_config(identity, &[&rustls::version::TLS13], &[b"h3"]);
    let server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint =
        quinn::Endpoint::server(server, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = endpoint.local_addr().unwrap();
    let accepting = endpoint.clone();
    let (handshake, handshakes) = mpsc::unbounded_channel();
    let task = Task(tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            let handshake = handshake.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    let _ = handshake.send(false);
                    return;
                };
                let _ = handshake.send(true);
                serve_hysteria(connection).await;
            });
        }
    }));
    HysteriaEcho {
        address,
        handshakes,
        endpoint,
        _task: task,
    }
}

async fn serve_hysteria(connection: quinn::Connection) {
    let Ok(mut http3) =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
            .await
    else {
        return;
    };
    let Ok(Some(request)) = http3.accept().await else {
        return;
    };
    let Ok((request, mut response)) = request.resolve_request().await else {
        return;
    };
    let status = if request
        .headers()
        .get("hysteria-auth")
        .is_some_and(|auth| auth == AUTH)
    {
        233
    } else {
        404
    };
    let reply = Response::builder()
        .status(status)
        .header("hysteria-udp", "false")
        .header("hysteria-cc-rx", "auto")
        .body(())
        .unwrap();
    if response.send_response(reply).await.is_err() || response.finish().await.is_err() {
        return;
    }
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        tokio::spawn(async move {
            let mut wire = Vec::new();
            while decode_tcp_request(&wire).is_err() {
                let mut bytes = [0; 1024];
                match recv.read(&mut bytes).await {
                    Ok(Some(n)) => wire.extend_from_slice(&bytes[..n]),
                    _ => return,
                }
            }
            if send.write_all(b"\x00\x00\x00").await.is_err() {
                return;
            }
            let _ = tokio::io::copy(&mut recv, &mut send).await;
            let _ = send.finish();
        });
    }
    drop(http3);
}

fn hysteria_config(
    server: &HysteriaEcho,
    tls: TlsClientConfig,
    chrome_parrot: bool,
) -> HysteriaConfig {
    let mut config = HysteriaConfig::new(server.address, tls, AUTH.into());
    config.quic.chrome_parrot = chrome_parrot;
    config
}

fn quic_client(allow_insecure: bool) -> TlsClientConfig {
    TlsClientConfig {
        server_name: "localhost".into(),
        allow_insecure,
        pinned_peer_cert_sha256: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        alpn: vec!["h3".into()],
        fingerprint: None,
    }
}

async fn echo_over_hysteria(
    connector: &TlsConnector,
    config: HysteriaConfig,
) -> Result<(), HysteriaError> {
    let client = timeout(DEADLINE, HysteriaClient::connect(config, connector))
        .await
        .expect("the dial ends")?;
    let target = Target::new(TargetAddr::Domain("example.com".into()), 443, Network::Tcp);
    let mut stream = client.open_tcp(&target).await?;
    stream.write_all(b"carried over QUIC").await.unwrap();
    let mut back = [0; 17];
    timeout(DEADLINE, stream.read_exact(&mut back))
        .await
        .expect("the echo comes back")
        .unwrap();
    assert_eq!(&back, b"carried over QUIC");
    client.close();
    Ok(())
}

async fn handshake(server: &mut HysteriaEcho) -> bool {
    timeout(DEADLINE, server.handshakes.recv())
        .await
        .expect("the server reports the handshake")
        .unwrap()
}

#[tokio::test]
async fn hysteria_refuses_a_self_signed_server_without_the_flag_and_carries_it_with_the_flag() {
    let identity = identity();
    let mut server = hysteria_echo(&identity);
    let connector = TlsConnector::system().unwrap();
    for chrome_parrot in [false, true] {
        let strict = hysteria_config(&server, quic_client(false), chrome_parrot);
        assert_eq!(
            echo_over_hysteria(&connector, strict).await,
            Err(HysteriaError::Connect),
            "chrome parrot {chrome_parrot}: the system roots refuse the server"
        );
        assert!(
            !handshake(&mut server).await,
            "chrome parrot {chrome_parrot}"
        );

        let waived = hysteria_config(&server, quic_client(true), chrome_parrot);
        if let Err(error) = echo_over_hysteria(&connector, waived).await {
            panic!("chrome parrot {chrome_parrot}: the flag carries: {error}");
        }
        assert!(
            handshake(&mut server).await,
            "chrome parrot {chrome_parrot}"
        );
    }
}

#[tokio::test]
async fn hysteria_a_pin_beside_the_flag_still_verifies() {
    let identity = identity();
    let mut server = hysteria_echo(&identity);
    let connector = TlsConnector::system().unwrap();
    for chrome_parrot in [false, true] {
        let mut pinned = quic_client(true);
        pinned.pinned_peer_cert_sha256 = vec![identity.sha256];
        echo_over_hysteria(&connector, hysteria_config(&server, pinned, chrome_parrot))
            .await
            .unwrap_or_else(|error| {
                panic!("chrome parrot {chrome_parrot}: the pin carries: {error}")
            });
        assert!(handshake(&mut server).await);

        let mut other = quic_client(true);
        other.pinned_peer_cert_sha256 = vec![[0x5a; 32]];
        assert_eq!(
            echo_over_hysteria(&connector, hysteria_config(&server, other, chrome_parrot)).await,
            Err(HysteriaError::Connect),
            "chrome parrot {chrome_parrot}: another certificate's pin is not waived"
        );
        assert!(!handshake(&mut server).await);
    }
}

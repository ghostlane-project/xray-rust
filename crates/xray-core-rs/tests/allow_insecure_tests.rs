//! `allowInsecure: true` from a parsed config, through a running core, to
//! self-signed servers on loopback: a VLESS line over TCP TLS and a
//! Hysteria 2 line with no pin are refused without the flag, as before, and
//! carried with it, and the parse that carries it warns naming the outbound
//! and its server. A pin beside the flag still verifies, and a REALITY line
//! never reads the flag.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use xray_config::{parse_xray_json, DiagnosticSeverity};
use xray_core_rs::Core;

const DEADLINE: Duration = Duration::from_secs(10);
const UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const UUID_BYTES: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const FLAG: &str = "$.outbounds[0].streamSettings.tlsSettings.allowInsecure";

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
    sha256: String,
}

fn identity() -> Identity {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = generated.cert.der().clone();
    let sha256 = Sha256::digest(certificate.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
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

/// What one connection reached on the server's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    /// The TLS handshake failed: the client refused the certificate.
    Refused,
    /// A VLESS request with the configured user arrived over TLS.
    Request,
}

/// A VLESS server over TLS on loopback: it reads the request header, answers
/// it and echoes what follows.
async fn vless_tls_server(identity: &Identity) -> (SocketAddr, mpsc::UnboundedReceiver<Reached>, Task) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config(
        identity,
        rustls::ALL_VERSIONS,
        &[],
    )));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (reached, reports) = mpsc::unbounded_channel();
    let task = Task(tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let (acceptor, reached) = (acceptor.clone(), reached.clone());
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    let _ = reached.send(Reached::Refused);
                    return;
                };
                if read_vless_request(&mut stream).await.is_err() {
                    return;
                }
                let _ = reached.send(Reached::Request);
                if stream.write_all(&[0, 0]).await.is_err() {
                    return;
                }
                let mut buffer = [0; 1024];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    }));
    (address, reports, task)
}

async fn read_vless_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<()> {
    let mut head = [0; 18];
    stream.read_exact(&mut head).await?;
    assert_eq!(head[0], 0, "VLESS version");
    assert_eq!(head[1..17], UUID_BYTES, "the configured user");
    let mut addons = vec![0; usize::from(head[17])];
    stream.read_exact(&mut addons).await?;
    let mut command_port_type = [0; 4];
    stream.read_exact(&mut command_port_type).await?;
    let length = match command_port_type[3] {
        1 => 4,
        3 => 16,
        2 => usize::from(stream.read_u8().await?),
        other => panic!("VLESS address type {other}"),
    };
    let mut address = vec![0; length];
    stream.read_exact(&mut address).await?;
    Ok(())
}

async fn next(reports: &mut mpsc::UnboundedReceiver<Reached>) -> Reached {
    timeout(DEADLINE, reports.recv())
        .await
        .expect("the server reports the connection")
        .unwrap()
}

fn socks_inbound() -> Value {
    json!({"tag":"socks-in","protocol":"socks","listen":"127.0.0.1","port":0,
        "settings":{"auth":"noauth","udp":false}})
}

fn vless_line(server: SocketAddr, security: Value) -> Value {
    let mut stream = security;
    stream["network"] = json!("raw");
    json!({"inbounds":[socks_inbound()],
        "outbounds":[{"tag":"proxy","protocol":"vless",
            "settings":{"vnext":[{"address":server.ip().to_string(),"port":server.port(),
                "users":[{"id":UUID,"encryption":"none"}]}]},
            "streamSettings":stream}]})
}

fn tls(settings: Value) -> Value {
    json!({"security":"tls","tlsSettings":settings})
}

/// Parses `config`, says whether the parse warned at `allowInsecure`, and
/// starts a core on it.
async fn start(config: &Value) -> (Core, bool) {
    let parsed = parse_xray_json(&config.to_string())
        .unwrap_or_else(|error| panic!("{config} must parse: {:?}", error.diagnostics));
    let warned = parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.path.as_deref() == Some(FLAG)
            && diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.message.contains("`proxy`")
    });
    let mut core = Core::new(parsed.config).expect("the core takes the config");
    core.start().await.expect("the core starts");
    (core, warned)
}

/// A SOCKS CONNECT through the core and a line sent: whether it came back.
async fn carried(core: &Core) -> bool {
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let attempt = async {
        let mut stream = TcpStream::connect(socks).await.ok()?;
        stream.write_all(&[5, 1, 0]).await.ok()?;
        let mut hello = [0; 2];
        stream.read_exact(&mut hello).await.ok()?;
        stream
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 9])
            .await
            .ok()?;
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await.ok()?;
        if reply[1] != 0 {
            return None;
        }
        stream.write_all(b"through the core").await.ok()?;
        let mut back = [0; 16];
        stream.read_exact(&mut back).await.ok()?;
        Some(&back == b"through the core")
    };
    timeout(DEADLINE, attempt).await.ok().flatten().unwrap_or(false)
}

#[tokio::test]
async fn vless_over_tls_is_refused_unless_the_config_waives_the_check() {
    let identity = identity();
    let (server, mut reports, _server) = vless_tls_server(&identity).await;
    for fingerprint in [None, Some("unsafe")] {
        for flag in [None, Some(false), Some(true)] {
            let mut settings = json!({"serverName":"localhost"});
            if let Some(fingerprint) = fingerprint {
                settings["fingerprint"] = json!(fingerprint);
            }
            if let Some(flag) = flag {
                settings["allowInsecure"] = json!(flag);
            }
            let case = format!("fingerprint {fingerprint:?}, allowInsecure {flag:?}");
            let (mut core, warned) = start(&vless_line(server, tls(settings))).await;
            let waived = flag == Some(true);
            assert_eq!(warned, waived, "{case}: the warning");
            assert_eq!(carried(&core).await, waived, "{case}: the data");
            let expected = if waived {
                Reached::Request
            } else {
                Reached::Refused
            };
            assert_eq!(next(&mut reports).await, expected, "{case}: the server");
            core.stop().await.unwrap();
            while reports.try_recv().is_ok() {}
        }
    }
}

#[tokio::test]
async fn vless_over_tls_a_pin_beside_the_flag_still_verifies() {
    let identity = identity();
    let (server, mut reports, _server) = vless_tls_server(&identity).await;
    for (pin, expected) in [
        (identity.sha256.clone(), Reached::Request),
        ("5a".repeat(32), Reached::Refused),
    ] {
        let settings = json!({"serverName":"localhost","allowInsecure":true,"pinnedPeerCertSha256":pin});
        let (mut core, warned) = start(&vless_line(server, tls(settings))).await;
        assert!(!warned, "the pin verifies, so nothing is waived");
        assert_eq!(carried(&core).await, expected == Reached::Request);
        assert_eq!(next(&mut reports).await, expected);
        core.stop().await.unwrap();
        while reports.try_recv().is_ok() {}
    }
}

#[tokio::test]
async fn reality_does_not_read_the_flag() {
    // A REALITY line to a server whose certificate is not REALITY's: the
    // flag, in realitySettings or in a tlsSettings beside it, waives
    // nothing.
    let identity = identity();
    let (server, mut reports, _server) = vless_tls_server(&identity).await;
    let reality = json!({"security":"reality",
        "realitySettings":{"serverName":"localhost","fingerprint":"chrome",
            "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","shortId":"02030405",
            "allowInsecure":true},
        "tlsSettings":{"allowInsecure":true}});
    let (mut core, warned) = start(&vless_line(server, reality)).await;
    assert!(!warned);
    assert!(!carried(&core).await, "no data crosses");
    assert_eq!(next(&mut reports).await, Reached::Refused);
    core.stop().await.unwrap();
}

/// A QUIC server on loopback with a self-signed certificate and ALPN h3: it
/// reports whether each handshake finished, which is as far as the
/// certificate check reaches.
struct QuicServer {
    address: SocketAddr,
    handshakes: mpsc::UnboundedReceiver<bool>,
    endpoint: quinn::Endpoint,
    _task: Task,
}

impl Drop for QuicServer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
    }
}

fn quic_server(identity: &Identity) -> QuicServer {
    let tls = server_config(identity, &[&rustls::version::TLS13], &[b"h3"]);
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint =
        quinn::Endpoint::server(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = endpoint.local_addr().unwrap();
    let accepting = endpoint.clone();
    let (handshake, handshakes) = mpsc::unbounded_channel();
    let task = Task(tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            let handshake = handshake.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        let _ = handshake.send(true);
                        connection.closed().await;
                    }
                    Err(_) => {
                        let _ = handshake.send(false);
                    }
                }
            });
        }
    }));
    QuicServer {
        address,
        handshakes,
        endpoint,
        _task: task,
    }
}

fn hysteria_line(server: SocketAddr, tls_settings: Value, chrome_parrot: bool) -> Value {
    let mut config: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/configs/hysteria2.json"))
            .unwrap();
    config["inbounds"] = json!([socks_inbound()]);
    config["outbounds"][0]["settings"]["address"] = json!(server.ip().to_string());
    config["outbounds"][0]["settings"]["port"] = json!(server.port());
    let stream = &mut config["outbounds"][0]["streamSettings"];
    stream["tlsSettings"] = tls_settings;
    if chrome_parrot {
        stream.as_object_mut().unwrap().remove("finalmask");
    }
    config
}

/// A SOCKS CONNECT through the core with a line behind it, which makes the
/// line dial; the stream is kept open until the server has reported.
async fn poke(core: &Core) -> TcpStream {
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream
        .write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 9])
        .await
        .unwrap();
    stream.write_all(b"through the core").await.unwrap();
    stream
}

async fn quic_handshake(server: &mut QuicServer) -> bool {
    timeout(DEADLINE, server.handshakes.recv())
        .await
        .expect("the server reports the handshake")
        .unwrap()
}

#[tokio::test]
async fn hysteria_without_a_pin_is_refused_unless_the_config_waives_the_check() {
    let identity = identity();
    let mut server = quic_server(&identity);
    for chrome_parrot in [false, true] {
        for flag in [None, Some(false), Some(true)] {
            let mut settings = json!({"serverName":"localhost","alpn":["h3"]});
            if let Some(flag) = flag {
                settings["allowInsecure"] = json!(flag);
            }
            let case = format!("chrome parrot {chrome_parrot}, allowInsecure {flag:?}");
            let (mut core, warned) =
                start(&hysteria_line(server.address, settings, chrome_parrot)).await;
            let waived = flag == Some(true);
            assert_eq!(warned, waived, "{case}: the warning");
            // The server never authenticates, so no data crosses; what the
            // flag decides is whether the QUIC handshake gets past the
            // certificate.
            let _flow = poke(&core).await;
            assert_eq!(quic_handshake(&mut server).await, waived, "{case}: the handshake");
            core.stop().await.unwrap();
            while server.handshakes.try_recv().is_ok() {}
        }
    }
}

#[tokio::test]
async fn hysteria_a_pin_beside_the_flag_still_verifies() {
    let identity = identity();
    let mut server = quic_server(&identity);
    for (pin, finished) in [(identity.sha256.clone(), true), ("5a".repeat(32), false)] {
        let settings = json!({"serverName":"localhost","alpn":["h3"],
            "allowInsecure":true,"pinnedPeerCertSha256":pin});
        let (mut core, warned) = start(&hysteria_line(server.address, settings, false)).await;
        assert!(!warned, "the pin verifies, so nothing is waived");
        let _flow = poke(&core).await;
        assert_eq!(quic_handshake(&mut server).await, finished);
        core.stop().await.unwrap();
        while server.handshakes.try_recv().is_ok() {}
    }
}

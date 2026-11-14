//! A core relaying SOCKS flows, on a runtime of its own, and the far ends
//! of those flows on another: a TLS VLESS Vision server and a plain sink.
//! Only what the core's runtime does is the core's, so a counting allocator
//! can tell which runtime's threads it counts.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;
use xray_core_rs::{Core, TunRuntimeOptions, TunRuntimeProfile};
use xray_proxy::vless::{VisionCommand, VisionPadding};
use xray_transport::{DnsResolver, TlsConnector, TransportDialer, TransportError};

pub const KIB: usize = 1024;
pub const MIB: usize = 1024 * KIB;
pub const SERVER_NAME: &str = "vless.test";
const USER_ID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
pub const USER_ID_BYTES: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
/// What flows write: zeros, from one static buffer.
pub static ZEROS: [u8; 64 * 1024] = [0; 64 * 1024];

/// A runtime of `workers` threads, each running `on_start` first.
pub fn runtime(workers: usize, on_start: fn()) -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .on_thread_start(on_start)
        .enable_all()
        .build()
        .expect("a runtime")
}

#[derive(Debug)]
struct StaticDns(SocketAddr);

#[async_trait]
impl DnsResolver for StaticDns {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        if domain == SERVER_NAME && port == self.0.port() {
            Ok(self.0)
        } else {
            Err(TransportError::NoResolvedAddress(domain.to_owned(), port))
        }
    }
}

fn tls_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).expect("a certificate");
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).expect("a root");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("a server config");
    (Arc::new(client), Arc::new(server))
}

/// A core whose SOCKS inbound relays every flow over TLS VLESS Vision to
/// a server at `server`, as a phone's (`LowMemory`) core does. For a slow
/// uplink its sockets to the server get a 16 KiB send buffer, as a phone's
/// would hold: loopback's 64 KiB segments would otherwise grow the kernel's
/// buffer to take a whole upload.
pub fn vision_core(server: SocketAddr, client: Arc<rustls::ClientConfig>, uplink: Uplink) -> Core {
    let sockopt = match uplink {
        Uplink::Fast => "",
        Uplink::Slow => {
            r#", "sockopt": { "customSockopt": [{ "system": "linux", "network": "tcp",
                "level": "1", "opt": "7", "value": "16384", "type": "int" }] }"#
        }
    };
    let raw = format!(
        r#"{{
          "inbounds": [{{
            "tag": "socks-in", "protocol": "socks",
            "listen": "127.0.0.1", "port": 0, "settings": {{ "udp": false }}
          }}],
          "outbounds": [{{
            "tag": "proxy", "protocol": "vless",
            "settings": {{ "vnext": [{{
              "address": "{SERVER_NAME}", "port": {port},
              "users": [{{ "id": "{USER_ID}", "encryption": "none",
                           "flow": "xtls-rprx-vision" }}]
            }}] }},
            "streamSettings": {{
              "network": "tcp", "security": "tls",
              "tlsSettings": {{ "serverName": "{SERVER_NAME}" }}{sockopt}
            }}
          }}]
        }}"#,
        port = server.port()
    );
    let config = xray_config::parse_xray_json(&raw)
        .expect("the config parses")
        .config;
    let dialer =
        TransportDialer::with_tls_connector(TlsConnector::with_pinned_client_config(client));
    Core::with_runtime_dependencies_and_tun_options(
        config,
        Arc::new(StaticDns(server)),
        Arc::new(dialer),
        TunRuntimeOptions::with_profile(TunRuntimeProfile::LowMemory),
    )
    .expect("a core")
}

/// A core whose SOCKS inbound relays every flow straight to its target.
pub fn direct_core() -> Core {
    let raw = r#"{
      "inbounds": [{
        "tag": "socks-in", "protocol": "socks",
        "listen": "127.0.0.1", "port": 0, "settings": { "udp": false }
      }],
      "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;
    let config = xray_config::parse_xray_json(raw)
        .expect("the config parses")
        .config;
    Core::with_runtime_dependencies_and_tun_options(
        config,
        Arc::new(StaticDns(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            1,
        ))),
        Arc::new(TransportDialer::system().expect("a dialer")),
        TunRuntimeOptions::with_profile(TunRuntimeProfile::LowMemory),
    )
    .expect("a core")
}

/// How fast the Vision server takes an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uplink {
    /// As fast as it comes.
    Fast,
    /// As a phone's uplink would: 4 KiB a millisecond a flow, through a
    /// small socket buffer, so that what the core sends waits in the core
    /// rather than in the kernel.
    Slow,
}

/// Starts a TLS VLESS Vision server; returns its address and the client
/// config that trusts it. Must run inside the far ends' runtime.
pub async fn start_vision_server(uplink: Uplink) -> (SocketAddr, Arc<rustls::ClientConfig>) {
    let (client, server) = tls_configs();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    if uplink == Uplink::Slow {
        socket.set_recv_buffer_size(4 * KIB as u32).unwrap();
    }
    socket
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap();
    let listener = socket.listen(1024).unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(socket).await {
                    let _ = vision_session(tls, uplink).await;
                }
            });
        }
    });
    (addr, client)
}

/// One flow at the server: `o` opens it and is answered `k`; `d` asks for a
/// MiB, `u` brings one and is answered `k`.
async fn vision_session<S>(mut tls: S, uplink: Uplink) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_vless_request(&mut tls).await?;
    let mut reader = VisionReader::default();
    let mut op = [0; 1];
    reader.read_exact(&mut tls, &mut op).await?;
    assert_eq!(op[0], b'o');
    // The response header, one padded `End` block, then raw bytes.
    let mut padding = VisionPadding::new(USER_ID_BYTES, [0, 0, 0, 0]);
    let mut opening = vec![0u8, 0];
    opening.extend_from_slice(
        &padding
            .pad(BytesMut::new(), VisionCommand::End, 0)
            .expect("an empty block pads"),
    );
    opening.push(b'k');
    tls.write_all(&opening).await?;
    tls.flush().await?;
    let mut sink = vec![0; 16 * KIB];
    loop {
        if reader.read(&mut tls, &mut op).await? == 0 {
            return tls.shutdown().await;
        }
        match op[0] {
            b'd' => {
                for _ in 0..MIB / ZEROS.len() {
                    tls.write_all(&ZEROS).await?;
                }
                tls.flush().await?;
            }
            b'u' => {
                let chunk = match uplink {
                    Uplink::Fast => sink.len(),
                    Uplink::Slow => 4 * KIB,
                };
                let mut left = MIB;
                while left > 0 {
                    let want = left.min(chunk);
                    let len = reader.read(&mut tls, &mut sink[..want]).await?;
                    if len == 0 {
                        return Err(std::io::ErrorKind::UnexpectedEof.into());
                    }
                    left -= len;
                    if uplink == Uplink::Slow {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                }
                tls.write_all(b"k").await?;
                tls.flush().await?;
            }
            b's' => {
                // Swallows everything to the end.
                while reader.read(&mut tls, &mut sink).await? > 0 {}
                tls.write_all(b"k").await?;
                return tls.shutdown().await;
            }
            other => panic!("unknown op {other}"),
        }
    }
}

async fn read_vless_request<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<()> {
    let mut head = [0; 18];
    stream.read_exact(&mut head).await?;
    assert_eq!(head[0], 0, "VLESS version");
    assert_eq!(&head[1..17], &USER_ID_BYTES);
    let mut addons = vec![0; usize::from(head[17])];
    stream.read_exact(&mut addons).await?;
    let mut command_port_type = [0; 4];
    stream.read_exact(&mut command_port_type).await?;
    assert_eq!(command_port_type[0], 1, "a TCP flow");
    let len = match command_port_type[3] {
        1 => 4,
        3 => 16,
        2 => usize::from(stream.read_u8().await?),
        other => panic!("address type {other}"),
    };
    let mut address = vec![0; len];
    stream.read_exact(&mut address).await?;
    Ok(())
}

/// Reads what a client's Vision sends: padded blocks until `End`, then raw.
#[derive(Default)]
struct VisionReader {
    user_id_seen: bool,
    content: usize,
    padding: usize,
    ended: bool,
    raw: bool,
}

impl VisionReader {
    async fn read<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        loop {
            if self.raw {
                return stream.read(buf).await;
            }
            if self.content > 0 {
                let want = buf.len().min(self.content);
                let len = stream.read(&mut buf[..want]).await?;
                if len == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                self.content -= len;
                return Ok(len);
            }
            if self.padding > 0 {
                let mut skip = vec![0; self.padding];
                stream.read_exact(&mut skip).await?;
                self.padding = 0;
            }
            if self.ended {
                self.raw = true;
                continue;
            }
            if !self.user_id_seen {
                let mut user_id = [0; 16];
                match stream.read_exact(&mut user_id).await {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(0)
                    }
                    Err(error) => return Err(error),
                }
                assert_eq!(user_id, USER_ID_BYTES);
                self.user_id_seen = true;
            }
            let mut header = [0; 5];
            match stream.read_exact(&mut header).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(error) => return Err(error),
            }
            self.content = usize::from(u16::from_be_bytes([header[1], header[2]]));
            self.padding = usize::from(u16::from_be_bytes([header[3], header[4]]));
            self.ended = header[0] != 0;
        }
    }

    async fn read_exact<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        buf: &mut [u8],
    ) -> std::io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let len = self.read(stream, &mut buf[filled..]).await?;
            if len == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            filled += len;
        }
        Ok(())
    }
}

/// Starts a server that reads each connection to its end, answers `k` and
/// closes. Must run inside the far ends' runtime.
pub async fn start_sink() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut sink = vec![0; 64 * KIB];
                while matches!(socket.read(&mut sink).await, Ok(len) if len > 0) {}
                let _ = socket.write_all(b"k").await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

/// A SOCKS5 flow through `socks` to `target`.
pub async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.expect("the SOCKS inbound");
    stream.set_nodelay(true).unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let IpAddr::V4(ip) = target.ip() else {
        panic!("an IPv4 target");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "the SOCKS inbound connected");
    stream
}

/// The target a Vision flow names; the server is its far end whatever it is.
pub fn any_target() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9)
}

/// Opens a Vision flow: `o`, answered `k`.
pub async fn open_vision_flow(socks: SocketAddr) -> TcpStream {
    let mut stream = socks_connect(socks, any_target()).await;
    stream.write_all(b"o").await.unwrap();
    let mut answer = [0; 1];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"k");
    stream
}

/// Asks for a MiB and reads it.
pub async fn download(stream: &mut TcpStream) {
    stream.write_all(b"d").await.unwrap();
    let mut buf = vec![0; 64 * KIB];
    let mut left = MIB;
    while left > 0 {
        let want = left.min(buf.len());
        let len = stream.read(&mut buf[..want]).await.unwrap();
        assert_ne!(len, 0, "the download ended early");
        left -= len;
    }
}

/// Sends a MiB and waits for the server to have it.
pub async fn upload(stream: &mut TcpStream) {
    stream.write_all(b"u").await.unwrap();
    for _ in 0..MIB / ZEROS.len() {
        stream.write_all(&ZEROS).await.unwrap();
    }
    let mut answer = [0; 1];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"k");
}

/// Sends `bytes` and closes, then waits for the far end's `k` and close.
pub async fn send_and_close(mut stream: TcpStream, bytes: usize) {
    let mut left = bytes;
    while left > 0 {
        let len = left.min(ZEROS.len());
        stream.write_all(&ZEROS[..len]).await.unwrap();
        left -= len;
    }
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"k");
}

/// Opens a Vision flow that sends `bytes` raw to the server and closes.
pub async fn vision_send_and_close(socks: SocketAddr, bytes: usize) {
    let mut stream = open_vision_flow(socks).await;
    stream.write_all(b"s").await.unwrap();
    send_and_close(stream, bytes).await;
}

//! VLESS over the `http` transport (`type=http`: HTTP/2) against sing-box.
//!
//! sing-box (an official release, named by `SING_BOX`) is the server: a VLESS
//! inbound with `transport: http`, over TLS and over REALITY. The client is a
//! core with the line as a share link or a config writes it, `network: "http"`,
//! which this core runs as XHTTP in `stream-one` mode. A download and an upload
//! of a few MiB each go through a SOCKS inbound and the far side checks every
//! byte. `scripts/ghostlane/p6-tests.d/vless-http.sh` fetches the release.
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use xray_config::parse_xray_json;
use xray_core_rs::Core;

const UUID: &str = "11111111-1111-1111-1111-111111111111";
const PATH: &str = "/media/h2";
const HOST: &str = "front.interop.test";
const REALITY_PRIVATE_KEY: &str = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
const REALITY_PUBLIC_KEY: &str = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
const REALITY_SERVER_NAME: &str = "reality.interop.test";
const REALITY_SHORT_ID: &str = "ab12cd34";
const SIZE: usize = 4 * 1024 * 1024;
const WITHIN: Duration = Duration::from_secs(30);

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Server {
    child: Child,
    log: PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("sing-box log:\n{}", tail(&self.log, 40));
        }
    }
}

fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn openssl(args: &str) {
    let output = Command::new("openssl")
        .args(args.split(' '))
        .output()
        .expect("openssl runs");
    assert!(
        output.status.success(),
        "openssl {args}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The byte at `at` of the stream a download carries.
fn pattern(at: usize) -> u8 {
    (at.wrapping_mul(31).wrapping_add(at >> 8) % 251) as u8
}

/// A far side that does what its first byte says. `D`: write [`SIZE`] bytes of
/// the pattern. `U`: read a u64 length and that many bytes, then answer with
/// the sum of the bytes it read as a u64.
async fn far_side() -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut mode = [0u8; 1];
                if socket.read_exact(&mut mode).await.is_err() {
                    return;
                }
                if mode[0] == b'D' {
                    let data: Vec<u8> = (0..SIZE).map(pattern).collect();
                    let _ = socket.write_all(&data).await;
                    let _ = socket.shutdown().await;
                } else {
                    let Ok(length) = socket.read_u64().await else {
                        return;
                    };
                    let mut sum = 0u64;
                    let mut left = length as usize;
                    let mut buffer = vec![0; 64 * 1024];
                    while left > 0 {
                        let want = left.min(buffer.len());
                        match socket.read(&mut buffer[..want]).await {
                            Ok(read) if read > 0 => {
                                sum += buffer[..read].iter().map(|b| u64::from(*b)).sum::<u64>();
                                left -= read;
                            }
                            _ => return,
                        }
                    }
                    let _ = socket.write_u64(sum).await;
                    let _ = socket.shutdown().await;
                }
            });
        }
    });
    (addr, Task(task))
}

/// A SOCKS5 CONNECT to `target` through `socks`.
async fn connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut hello = [0; 2];
    stream.read_exact(&mut hello).await.unwrap();
    assert_eq!(hello, [5, 0]);
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 only")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS refused the connect: {reply:?}");
    stream
}

async fn download(socks: SocketAddr, far: SocketAddr) {
    let mut stream = connect(socks, far).await;
    stream.write_all(b"D").await.unwrap();
    let mut got = 0usize;
    let mut buffer = vec![0; 64 * 1024];
    while got < SIZE {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "the download ended at {got} of {SIZE} bytes");
        for (at, byte) in buffer[..read].iter().enumerate() {
            assert_eq!(*byte, pattern(got + at), "byte {} differs", got + at);
        }
        got += read;
    }
}

async fn upload(socks: SocketAddr, far: SocketAddr) {
    let mut stream = connect(socks, far).await;
    let data: Vec<u8> = (0..SIZE).map(|at| pattern(at + 7)).collect();
    let expected: u64 = data.iter().map(|b| u64::from(*b)).sum();
    stream.write_all(b"U").await.unwrap();
    stream.write_u64(SIZE as u64).await.unwrap();
    stream.write_all(&data).await.unwrap();
    assert_eq!(
        stream.read_u64().await.unwrap(),
        expected,
        "the far side summed other bytes than were sent"
    );
}

/// What a REALITY server borrows its handshake from: TLS 1.3, h2 offered.
async fn reality_site(dir: &Path) -> (SocketAddr, Task) {
    let file = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let (key_pem, crt_pem) = (file("site.key.pem"), file("site.crt.pem"));
    let (key_der, crt_der) = (file("site.key.der"), file("site.crt.der"));
    openssl(&format!(
        "req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=site.interop.test \
         -addext subjectAltName=DNS:site.interop.test -keyout {key_pem} -out {crt_pem}"
    ));
    openssl(&format!("x509 -in {crt_pem} -outform DER -out {crt_der}"));
    openssl(&format!(
        "pkcs8 -topk8 -nocrypt -in {key_pem} -outform DER -out {key_der}"
    ));
    let certificate = CertificateDer::from(std::fs::read(&crt_der).unwrap());
    let key = PrivatePkcs8KeyDer::from(std::fs::read(&key_der).unwrap());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], PrivateKeyDer::Pkcs8(key))
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(Ok(mut tls)) =
                    timeout(Duration::from_secs(15), acceptor.accept(socket)).await
                else {
                    return;
                };
                let mut buffer = [0; 4096];
                while matches!(tls.read(&mut buffer).await, Ok(read) if read > 0) {}
            });
        }
    });
    (addr, Task(task))
}

/// A sing-box VLESS inbound on `http`, its `tls` object as given.
async fn sing_box(binary: &str, dir: &Path, tls: Value) -> (Server, SocketAddr) {
    let port = free_port();
    let config = json!({
        "log": { "level": "debug" },
        "inbounds": [{
            "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
            "users": [{ "name": "u", "uuid": UUID }],
            "tls": tls,
            "transport": { "type": "http", "host": [HOST], "path": PATH }
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    });
    let path = dir.join(format!("sing-box-{port}.json"));
    std::fs::write(&path, config.to_string()).unwrap();
    let log = dir.join(format!("sing-box-{port}.log"));
    let output = std::fs::File::create(&log).unwrap();
    let child = Command::new(binary)
        .args(["run", "-c"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap_or_else(|error| panic!("start {binary}: {error}"));
    let mut server = Server { child, log };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..150 {
        if TcpStream::connect(addr).await.is_ok() {
            return (server, addr);
        }
        if let Ok(Some(status)) = server.child.try_wait() {
            panic!(
                "sing-box exited at start ({status}):\n{}",
                tail(&server.log, 30)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("sing-box did not listen:\n{}", tail(&server.log, 30));
}

fn line(server: SocketAddr, stream: Value) -> Value {
    json!({
        "log": { "loglevel": "warning", "access": "none" },
        "inbounds": [{
            "tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [{
            "tag": "out", "protocol": "vless",
            "settings": { "vnext": [{
                "address": server.ip().to_string(), "port": server.port(),
                "users": [{ "id": UUID, "encryption": "none" }]
            }] },
            "streamSettings": stream
        }]
    })
}

/// A download, an upload, and a download again, on streams of one core.
async fn carries(line: &Value, far: SocketAddr) {
    let parsed = parse_xray_json(&line.to_string())
        .unwrap_or_else(|error| panic!("{line} must parse: {:?}", error.diagnostics));
    let mut core = Core::new(parsed.config).expect("the core takes the config");
    core.start().await.expect("the core starts");
    let socks = core.inbound_addr(Some("in")).expect("SOCKS is bound");
    timeout(WITHIN, download(socks, far))
        .await
        .expect("the download finished in time");
    timeout(WITHIN, upload(socks, far))
        .await
        .expect("the upload finished in time");
    timeout(WITHIN, download(socks, far))
        .await
        .expect("a second download finished in time");
    core.stop().await.expect("the core stops");
}

fn binary() -> String {
    std::env::var("SING_BOX").expect("SING_BOX names the sing-box binary")
}

fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vless-http-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs sing-box in SING_BOX, and openssl"]
async fn vless_http_carries_a_download_and_an_upload_over_tls() {
    let dir = work_dir("tls");
    let file = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    openssl(&format!(
        "req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
         -addext subjectAltName=DNS:localhost -keyout {} -out {}",
        file("key.pem"),
        file("cert.pem")
    ));
    let (_far_task, far) = {
        let (addr, task) = far_side().await;
        (task, addr)
    };
    let (_server, addr) = sing_box(
        &binary(),
        &dir,
        json!({
            "enabled": true, "server_name": "localhost", "alpn": ["h2"],
            "certificate_path": file("cert.pem"), "key_path": file("key.pem")
        }),
    )
    .await;
    // The link's way: `type=http` with a host and a path, and no ALPN of its
    // own, which the transport must fill in as h2.
    let stream = json!({
        "network": "http", "security": "tls",
        "tlsSettings": { "serverName": "localhost", "allowInsecure": true },
        "httpSettings": { "host": [HOST], "path": PATH }
    });
    carries(&line(addr, stream), far).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs sing-box in SING_BOX, and openssl"]
async fn vless_http_carries_a_download_and_an_upload_over_reality() {
    let dir = work_dir("reality");
    let (site, _site_task) = reality_site(&dir).await;
    let (far, _far_task) = far_side().await;
    let (_server, addr) = sing_box(
        &binary(),
        &dir,
        json!({
            "enabled": true, "server_name": REALITY_SERVER_NAME,
            "reality": {
                "enabled": true,
                "handshake": { "server": "127.0.0.1", "server_port": site.port() },
                "private_key": REALITY_PRIVATE_KEY,
                "short_id": [REALITY_SHORT_ID]
            }
        }),
    )
    .await;
    let stream = json!({
        "network": "http", "security": "reality",
        "realitySettings": {
            "serverName": REALITY_SERVER_NAME, "fingerprint": "chrome",
            "publicKey": REALITY_PUBLIC_KEY, "shortId": REALITY_SHORT_ID
        },
        "httpSettings": { "host": [HOST], "path": PATH }
    });
    carries(&line(addr, stream), far).await;
    let _ = std::fs::remove_dir_all(&dir);
}

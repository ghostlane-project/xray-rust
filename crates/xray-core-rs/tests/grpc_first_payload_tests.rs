//! A request written once and then waited on, over VLESS on gRPC.
//!
//! A SOCKS inbound that sniffs (`routeOnly`, as the app's builder writes every
//! inbound) reads a client's first bytes before it opens the outbound, and
//! writes them to the new stream once, before the relay starts. An HTTP GET is
//! all a client sends until it is answered, so nothing writes to or flushes
//! that stream again until the client gives up. Over gRPC that write is the
//! first a new HTTP/2 stream gets, and h2 gives a stream no capacity until its
//! connection task has opened it, so the write cannot be taken in the poll
//! that makes it. It still has to reach the server as soon as h2 can take it.
//!
//! The server here stands in for an Xray gRPC inbound and answers only once a
//! whole request has arrived. On a current-thread runtime the connection task
//! cannot run between the call being opened and the request being written, so
//! every flow meets a stream h2 has not opened yet; on a multi-threaded one,
//! the flows on a connection that has gone quiet do.
//!
//! `requests_written_once_are_answered_by_official_xray_over_reality`
//! (ignored) runs the same flows against official Xray releases, REALITY under
//! gRPC and under XHTTP's stream-one, whose uplink is an HTTP/2 stream too;
//! `scripts/ghostlane/p6-tests.d/grpc-first-payload.sh` fetches them.
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use xray_config::parse_xray_json;
use xray_core_rs::Core;

const UUID: &str = "11111111-1111-1111-1111-111111111111";
const SERVICE_NAME: &str = "media/sync";
const XHTTP_PATH: &str = "/download";
/// Where every flow asks to go. Neither server dials it: the stand-in answers
/// itself and the Xray servers' freedom outbound redirects to the page.
const TARGET: [u8; 4] = [203, 0, 113, 10];
const REQUEST: &[u8] = b"GET /down HTTP/1.1\r\nHost: page.interop.test\r\nAccept: */*\r\n\r\n";
/// A flow that is carried is answered in milliseconds; one that is held is
/// never answered at all, so this only has to outlast a loaded runner.
const ANSWER_WITHIN: Duration = Duration::from_secs(5);

/// REALITY's key pair for the official servers, the loopback pair the local
/// Xray interop tests use.
const REALITY_PRIVATE_KEY: &str = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
const REALITY_PUBLIC_KEY: &str = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
const REALITY_SERVER_NAME: &str = "reality.interop.test";
const REALITY_SHORT_ID: &str = "ab12cd34";

/// Aborts its task when dropped, so a failed assertion leaves no server.
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What became of one flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// The whole answer came back.
    Answered,
    /// The request was written and no answer came within [`ANSWER_WITHIN`].
    Held,
    /// The SOCKS exchange or the answer itself went wrong.
    Failed,
}

/// The page's answer as the client reads it.
fn page_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// A SOCKS5 CONNECT through `socks`, [`REQUEST`] written once and nothing
/// after it, and `answer` read back.
async fn flow(socks: SocketAddr, answer: &[u8]) -> Flow {
    let opened = timeout(ANSWER_WITHIN, async {
        let mut stream = TcpStream::connect(socks).await.ok()?;
        stream.write_all(&[5, 1, 0]).await.ok()?;
        let mut hello = [0; 2];
        stream.read_exact(&mut hello).await.ok()?;
        let mut connect = vec![5, 1, 0, 1];
        connect.extend_from_slice(&TARGET);
        connect.extend_from_slice(&80u16.to_be_bytes());
        stream.write_all(&connect).await.ok()?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.ok()?;
        let bound = match reply[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => usize::from(stream.read_u8().await.ok()?) + 2,
            _ => return None,
        };
        let mut bound = vec![0; bound];
        stream.read_exact(&mut bound).await.ok()?;
        (hello == [5, 0] && reply[1] == 0).then_some(stream)
    })
    .await;
    let Ok(Some(mut stream)) = opened else {
        return Flow::Failed;
    };
    if stream.write_all(REQUEST).await.is_err() {
        return Flow::Failed;
    }
    let mut read = vec![0; answer.len()];
    match timeout(ANSWER_WITHIN, stream.read_exact(&mut read)).await {
        Err(_) => Flow::Held,
        Ok(Ok(_)) if read == answer => Flow::Answered,
        Ok(_) => Flow::Failed,
    }
}

/// The line as the app's builder dumps it for a SOCKS inbound: sniffing with
/// `routeOnly`, and VLESS with `stream` under it.
fn line(server: SocketAddr, stream: Value) -> Value {
    json!({
        "log": { "loglevel": "warning", "access": "none" },
        "inbounds": [{
            "tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": { "auth": "noauth", "udp": true },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }
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

/// gRPC's stream settings, `security` under them.
fn grpc(security: Value) -> Value {
    let mut stream = security;
    stream["network"] = json!("grpc");
    stream["grpcSettings"] = json!({ "serviceName": SERVICE_NAME });
    stream
}

/// XHTTP's, in `mode`, `security` under them.
fn xhttp(security: Value, mode: &str) -> Value {
    let mut stream = security;
    stream["network"] = json!("xhttp");
    stream["xhttpSettings"] =
        json!({ "host": REALITY_SERVER_NAME, "path": XHTTP_PATH, "mode": mode });
    stream
}

async fn start(config: &Value) -> Core {
    let parsed = parse_xray_json(&config.to_string())
        .unwrap_or_else(|error| panic!("{config} must parse: {:?}", error.diagnostics));
    let mut core = Core::new(parsed.config).expect("the core takes the config");
    core.start().await.expect("the core starts");
    core
}

/// `flows` flows, one after another, through a core of their own: the first
/// opens its connection, the rest ride it. Returns how each went.
async fn flows_through_one_core(line: &Value, flows: usize, answer: &[u8]) -> Vec<Flow> {
    let mut core = start(line).await;
    let socks = core
        .inbound_addr(Some("in"))
        .expect("the SOCKS inbound is bound");
    let mut outcomes = Vec::with_capacity(flows);
    for _ in 0..flows {
        outcomes.push(flow(socks, answer).await);
    }
    core.stop().await.expect("the core stops");
    outcomes
}

// ---------------------------------------------------------------- the stand-in

/// One `Hunk` as gRPC frames it: uncompressed, its length, then field 1.
fn encode_hunk(data: &[u8]) -> Vec<u8> {
    let mut message = vec![0x0a];
    let mut len = data.len();
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            message.push(byte);
            break;
        }
        message.push(byte | 0x80);
    }
    message.extend_from_slice(data);
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

/// The payload of the first whole `Hunk` at the front of `wire`, taken off it.
fn take_hunk(wire: &mut Vec<u8>) -> Option<Vec<u8>> {
    let len = usize::try_from(u32::from_be_bytes(wire.get(1..5)?.try_into().unwrap())).unwrap();
    if wire.len() < 5 + len {
        return None;
    }
    let message: Vec<u8> = wire.drain(..5 + len).skip(5).collect();
    if message.is_empty() {
        return Some(Vec::new());
    }
    assert_eq!(message[0], 0x0a, "a Hunk carries field 1, bytes");
    let (mut at, mut data_len, mut shift) = (1, 0usize, 0);
    loop {
        let byte = message[at];
        at += 1;
        data_len |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some(message[at..at + data_len].to_vec())
}

/// Where the payload starts behind a whole VLESS request header.
fn vless_header_len(tunnel: &[u8]) -> Option<usize> {
    // Version, the 16-byte id, the addons' length and the addons, the
    // command, the port, then the address by its type.
    let addons = usize::from(*tunnel.get(17)?);
    let kind = 18 + addons + 1 + 2;
    let address = match *tunnel.get(kind)? {
        1 => 4,
        2 => 1 + usize::from(*tunnel.get(kind + 1)?),
        3 => 16,
        _ => return None,
    };
    let end = kind + 1 + address;
    (tunnel.len() >= end).then_some(end)
}

/// Whether `tunnel` holds the VLESS request header and a whole HTTP request.
fn holds_a_request(tunnel: &[u8]) -> bool {
    vless_header_len(tunnel)
        .is_some_and(|start| tunnel[start..].windows(4).any(|end| end == b"\r\n\r\n"))
}

/// An Xray gRPC inbound in miniature, over plain TCP: one call a tunnel, VLESS
/// in `Hunk`s. A call is answered with `answer` behind the VLESS response
/// header once its request header and a whole HTTP request have arrived, and
/// not before, the way a page answers only a request.
async fn grpc_vless_server(answer: Vec<u8>) -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = Bytes::from(encode_hunk(&[&[0, 0][..], &answer].concat()));
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let answer = answer.clone();
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(socket).await else {
                    return;
                };
                while let Some(Ok((request, respond))) = connection.accept().await {
                    tokio::spawn(serve_call(request.into_body(), respond, answer.clone()));
                }
            });
        }
    });
    (addr, Task(task))
}

async fn serve_call(
    mut body: h2::RecvStream,
    mut respond: h2::server::SendResponse<Bytes>,
    answer: Bytes,
) {
    let (mut wire, mut tunnel) = (Vec::new(), Vec::new());
    while !holds_a_request(&tunnel) {
        let Some(Ok(chunk)) = body.data().await else {
            return;
        };
        let _ = body.flow_control().release_capacity(chunk.len());
        wire.extend_from_slice(&chunk);
        while let Some(hunk) = take_hunk(&mut wire) {
            tunnel.extend_from_slice(&hunk);
        }
    }
    let head = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let Ok(mut send) = respond.send_response(head, false) else {
        return;
    };
    if send.send_data(answer, false).is_err() {
        return;
    }
    // Held open until the client is done, as an inbound holds a tunnel.
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    let _ = send.send_trailers(trailers);
}

const PAGE: &[u8] = b"page";

/// Every flow on a current-thread runtime meets a stream the connection task
/// has not opened yet: the request is written while h2 cannot take it.
#[tokio::test]
async fn a_request_written_once_is_answered_on_a_current_thread_runtime() {
    let answer = page_response(PAGE);
    let (server, _server) = grpc_vless_server(answer.clone()).await;
    let outcomes = flows_through_one_core(&line(server, grpc(json!({}))), 3, &answer).await;
    assert_eq!(outcomes, [Flow::Answered; 3]);
}

/// Twenty flows, one after another, on the one connection a core keeps to
/// its server, and three cores in a row, on a multi-threaded runtime as the
/// apps run the core.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_written_once_are_answered_on_one_connection() {
    let answer = page_response(PAGE);
    let (server, _server) = grpc_vless_server(answer.clone()).await;
    let client = line(server, grpc(json!({})));
    let mut outcomes = Vec::new();
    for _ in 0..3 {
        outcomes.extend(flows_through_one_core(&client, 20, &answer).await);
    }
    let held = outcomes
        .iter()
        .filter(|outcome| **outcome == Flow::Held)
        .count();
    println!("GRPC-STAND-IN: {held} of {} flows held", outcomes.len());
    assert!(
        outcomes.iter().all(|outcome| *outcome == Flow::Answered),
        "{outcomes:?}"
    );
}

// ---------------------------------------------------------------- official Xray

/// Kills its server when dropped.
struct Server {
    child: Child,
    log: PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `openssl` with `args`, split at spaces: the paths are the test's own, under
/// the temporary directory.
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

/// What a REALITY server borrows its handshake from, as a real site answers:
/// TLS 1.3, h2 offered, an RSA certificate larger than the server's own.
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

/// The page the Xray servers' freedom outbound redirects every flow to.
async fn page_server(answer: Vec<u8>) -> (SocketAddr, Task) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = Arc::new(answer);
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let answer = Arc::clone(&answer);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                    match socket.read(&mut buffer).await {
                        Ok(read) if read > 0 => request.extend_from_slice(&buffer[..read]),
                        _ => return,
                    }
                }
                let _ = socket.write_all(&answer).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, Task(task))
}

/// An official Xray server: VLESS over `stream` over REALITY, its freedom
/// outbound sending every flow to the page.
async fn official_server(
    xray: &str,
    dir: &Path,
    stream: Value,
    site: SocketAddr,
    page: SocketAddr,
) -> (Server, SocketAddr) {
    let port = free_port();
    let mut stream = stream;
    stream["security"] = json!("reality");
    stream["realitySettings"] = json!({
        "dest": site.to_string(),
        "serverNames": [REALITY_SERVER_NAME],
        "privateKey": REALITY_PRIVATE_KEY,
        "shortIds": [REALITY_SHORT_ID]
    });
    let config = json!({
        "log": { "loglevel": "info" },
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
            "streamSettings": stream
        }],
        "outbounds": [{
            "tag": "direct", "protocol": "freedom",
            "settings": {
                "redirect": page.to_string(), "ipsBlocked": [],
                "finalRules": [{ "action": "allow", "ip": ["127.0.0.0/8"] }]
            }
        }]
    });
    let path = dir.join(format!("server-{port}.json"));
    std::fs::write(&path, config.to_string()).unwrap();
    let log = dir.join(format!("server-{port}.log"));
    let child = Command::new(xray)
        .args(["run", "-config"])
        .arg(&path)
        .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("start {xray}: {error}"));
    let mut server = Server { child, log };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    for _ in 0..150 {
        if TcpStream::connect(addr).await.is_ok() {
            return (server, addr);
        }
        if let Ok(Some(status)) = server.child.try_wait() {
            panic!("{xray} exited at start ({status}):\n{}", tail(&server.log));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{xray} did not listen:\n{}", tail(&server.log));
}

fn tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(20)..].join("\n")
}

fn count(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a count, got {value:?}"))
    })
}

/// The lines against each official Xray release in `XRAY_SERVERS`
/// (`<version>=<path to xray>`, separated by spaces or commas), REALITY under
/// gRPC as the builder writes it and under XHTTP in stream-one mode, the other
/// line whose uplink is an HTTP/2 stream of its own. Each round is a new core,
/// so its first flow opens a connection and the flows after it ride that one
/// once it has gone quiet. `GRPC_FIRST_PAYLOAD_ROUNDS` and
/// `GRPC_FIRST_PAYLOAD_FLOWS` size the run; a `FIRST-PAYLOAD` line for each
/// release and line says how it went.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs official Xray builds named in XRAY_SERVERS, and openssl"]
async fn requests_written_once_are_answered_by_official_xray_over_reality() {
    let servers = std::env::var("XRAY_SERVERS").expect("XRAY_SERVERS names the Xray builds");
    let rounds = count("GRPC_FIRST_PAYLOAD_ROUNDS", 10);
    let flows = count("GRPC_FIRST_PAYLOAD_FLOWS", 3);
    let dir = std::env::temp_dir().join(format!("grpc-first-payload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let body: Vec<u8> = (0..64 * 1024).map(|at| (at % 251) as u8).collect();
    let answer = page_response(&body);
    let (site, _site) = reality_site(&dir).await;
    let (page, _page) = page_server(answer.clone()).await;
    let reality = json!({
        "security": "reality",
        "realitySettings": {
            "serverName": REALITY_SERVER_NAME, "fingerprint": "chrome",
            "publicKey": REALITY_PUBLIC_KEY, "shortId": REALITY_SHORT_ID
        }
    });
    // (name, the server's stream settings, the client's)
    let lines = [
        ("grpc", grpc(json!({})), grpc(reality.clone())),
        (
            "xhttp-stream-one",
            xhttp(json!({}), "auto"),
            xhttp(reality.clone(), "stream-one"),
        ),
    ];

    let mut not_answered = Vec::new();
    for entry in servers.split([' ', ',']).filter(|entry| !entry.is_empty()) {
        let (version, xray) = entry.split_once('=').expect("<version>=<path to xray>");
        for (name, server_stream, client_stream) in &lines {
            let (server, addr) =
                official_server(xray, &dir, server_stream.clone(), site, page).await;
            let client = line(addr, client_stream.clone());
            let (mut first, mut later) = ((0, 0), (0, 0));
            let mut other = 0;
            for _ in 0..rounds {
                for (at, outcome) in flows_through_one_core(&client, flows, &answer)
                    .await
                    .into_iter()
                    .enumerate()
                {
                    let tally = if at == 0 { &mut first } else { &mut later };
                    tally.1 += 1;
                    match outcome {
                        Flow::Answered => {}
                        Flow::Held => tally.0 += 1,
                        Flow::Failed => other += 1,
                    }
                }
            }
            println!(
                "FIRST-PAYLOAD {version} {name}: {} of {} flows held ({} of {} first on a connection, {} of {} after it), {other} failed otherwise",
                first.0 + later.0,
                first.1 + later.1,
                first.0,
                first.1,
                later.0,
                later.1
            );
            if first.0 + later.0 + other > 0 {
                eprintln!("{version} {name} server log (end):\n{}", tail(&server.log));
                not_answered.push(format!("{version} {name}"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        not_answered.is_empty(),
        "flows were not answered on {not_answered:?}"
    );
}

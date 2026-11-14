//! Shared by `dns_forward_tests` and `dns_forward_memory_tests`: a line
//! server, a direct resolver, a SOCKS5 client and the app's two DNS configs.
//!
//! The line server is a plain VLESS server (no TLS, no flow) for one user.
//! It never dials anything: it records the target and network each flow
//! asks for and answers DNS itself, so a TXT that comes back "via-line"
//! went through the line. The direct resolver answers "via-direct".
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::time::{timeout, Instant};
use xray_core_rs::{Core, TunRuntimeOptions, TunRuntimeProfile};
use xray_proxy::vless::{encode_udp_packet, read_udp_packet};

pub const USER: &str = "dns-forward-user";
pub const PASS: &str = "dns-forward-pass";
const LINE_UUID: &str = "11111111-1111-1111-1111-111111111111";
const LINE_UUID_BYTES: [u8; 16] = [0x11; 16];

pub const QTYPE_A: u16 = 1;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_SRV: u16 = 33;
pub const QTYPE_HTTPS: u16 = 65;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_REFUSED: u8 = 5;

/// What the app's writer emits: every type but A, AAAA and HTTPS.
pub const FORWARD_QTYPES: &str = "2-27,29-64,66-65535";
pub const VIA_LINE: &[u8] = b"via-line";
pub const VIA_DIRECT: &[u8] = b"via-direct";
pub const LINE_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
pub const DIRECT_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 53);
/// SRV rdata the line answers: priority 0, weight 5, port 5222, target.
pub const SRV_PORT: u16 = 5222;
pub const SRV_TARGET: &str = "xmpp.example.com";

/// The DNS address the app's tunnel hands its system, as the reviewer's
/// harness used it. Any address on port 53 reaches the DNS outbound.
pub const TUN_DNS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(172, 19, 0, 2), 53);

// ---------------------------------------------------------------- configs

/// The app's Global config: SOCKS in, the line out, dns-out with the HTTPS
/// refusal and the forward rule.
pub fn global_config(line: SocketAddr) -> Value {
    config(
        line,
        json!({
            "rules": [
                {"action": "return", "qType": 65, "rCode": 5},
                {"action": "forward", "qType": FORWARD_QTYPES,
                 "address": "1.1.1.1", "port": 53, "outboundTag": "out"}
            ]
        }),
    )
}

/// The app's Bypass Russia config: Russian names to the network's resolver,
/// HTTPS refused, every other non-address type through the line.
pub fn bypass_config(line: SocketAddr, resolver: SocketAddr) -> Value {
    config(
        line,
        json!({
            "rewriteAddress": resolver.ip().to_string(),
            "rewritePort": resolver.port(),
            "rules": [
                {"action": "direct", "domain": ["domain:ru", "domain:sberbank.ru"]},
                {"action": "return", "qType": 65, "rCode": 5},
                {"action": "forward", "qType": FORWARD_QTYPES,
                 "address": "1.1.1.1", "port": 53, "outboundTag": "out"}
            ]
        }),
    )
}

fn config(line: SocketAddr, dns_settings: Value) -> Value {
    json!({
        "log": {"loglevel": "warning", "access": "none"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "fakeIp": {"enabled": true, "ipv4Pool": "198.18.0.0/15"}
        },
        "inbounds": [{
            "tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": {
                "auth": "password",
                "accounts": [{"user": USER, "pass": PASS}],
                "udp": true
            },
            "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}
        }],
        "outbounds": [
            {
                "tag": "out", "protocol": "vless",
                "settings": {"vnext": [{
                    "address": line.ip().to_string(), "port": line.port(),
                    "users": [{"id": LINE_UUID, "encryption": "none"}]
                }]}
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns", "settings": dns_settings}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{
                "type": "field", "inboundTag": ["in"], "network": "tcp,udp",
                "port": 53, "outboundTag": "dns-out"
            }]
        }
    })
}

pub async fn start(config: &Value, profile: TunRuntimeProfile) -> (Core, SocketAddr) {
    let parsed = xray_config::parse_xray_json(&config.to_string()).expect("the config parses");
    let options = TunRuntimeOptions {
        profile,
        ..TunRuntimeOptions::default()
    };
    let mut core = Core::with_tun_runtime_options(parsed.config, options).expect("core built");
    core.start().await.expect("core started");
    let socks = core
        .inbound_addr(Some("in"))
        .expect("the SOCKS inbound listens");
    (core, socks)
}

// ------------------------------------------------------------ line server

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Answer,
    /// UDP answers carry TC and no records; TCP answers are whole.
    TruncateUdp,
    /// Read the query and answer only once released.
    Stall,
}

pub struct LineServer {
    pub addr: SocketAddr,
    state: Arc<LineState>,
}

struct LineState {
    mode: Mutex<Mode>,
    seen: Mutex<Vec<(String, &'static str)>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
    closed: AtomicUsize,
    release: watch::Sender<bool>,
}

impl LineServer {
    pub async fn spawn(mode: Mode) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(LineState {
            mode: Mutex::new(mode),
            seen: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
            release: watch::channel(false).0,
        });
        let accept_state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_line(stream, Arc::clone(&accept_state)));
            }
        });
        Self { addr, state }
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.state.mode.lock().unwrap() = mode;
        self.state.release.send_replace(false);
    }

    /// Answers every stalled query.
    pub fn release(&self) {
        self.state.release.send_replace(true);
    }

    /// Each flow's (target, network), in the order they arrived.
    pub fn seen(&self) -> Vec<(String, &'static str)> {
        self.state.seen.lock().unwrap().clone()
    }

    pub fn active(&self) -> usize {
        self.state.active.load(Ordering::SeqCst)
    }

    pub fn max_active(&self) -> usize {
        self.state.max_active.load(Ordering::SeqCst)
    }

    pub fn reset_max_active(&self) {
        self.state
            .max_active
            .store(self.state.active.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    pub fn closed(&self) -> usize {
        self.state.closed.load(Ordering::SeqCst)
    }

    pub fn clear_seen(&self) {
        self.state.seen.lock().unwrap().clear();
    }
}

struct Active<'a>(&'a LineState);

impl<'a> Active<'a> {
    fn new(state: &'a LineState) -> Self {
        let now = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.max_active.fetch_max(now, Ordering::SeqCst);
        Self(state)
    }
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.closed.fetch_add(1, Ordering::SeqCst);
    }
}

async fn serve_line(mut stream: TcpStream, state: Arc<LineState>) {
    let Ok((command, target)) = read_vless_request(&mut stream).await else {
        return;
    };
    let network = match command {
        1 => "tcp",
        2 => "udp",
        _ => return,
    };
    let _active = Active::new(&state);
    state.seen.lock().unwrap().push((target, network));
    let mut header = Some([0_u8, 0]);
    loop {
        let query = if command == 1 {
            read_dns_tcp(&mut stream).await
        } else {
            read_udp_packet(&mut stream)
                .await
                .map(|packet| packet.to_vec())
        };
        let Ok(query) = query else {
            return;
        };
        let mode = *state.mode.lock().unwrap();
        if mode == Mode::Stall {
            let mut release = state.release.subscribe();
            let mut probe = [0_u8; 1];
            tokio::select! {
                _ = release.wait_for(|released| *released) => {}
                // The client gave up: its end closed.
                _ = stream.read(&mut probe) => return,
            }
        }
        let truncated = mode == Mode::TruncateUdp && command == 2;
        let answer = dns_answer(&query, VIA_LINE, LINE_A, truncated);
        let mut frame = header
            .take()
            .map_or_else(Vec::new, |header| header.to_vec());
        if command == 1 {
            frame.extend_from_slice(&(answer.len() as u16).to_be_bytes());
            frame.extend_from_slice(&answer);
        } else {
            frame.extend_from_slice(&encode_udp_packet(&answer).unwrap());
        }
        if stream.write_all(&frame).await.is_err() {
            return;
        }
    }
}

/// The VLESS request header: (command, "address:port").
async fn read_vless_request(stream: &mut TcpStream) -> std::io::Result<(u8, String)> {
    let version = stream.read_u8().await?;
    let mut uuid = [0_u8; 16];
    stream.read_exact(&mut uuid).await?;
    if version != 0 || uuid != LINE_UUID_BYTES {
        return Err(std::io::Error::other("not the line's user"));
    }
    let addons = stream.read_u8().await?;
    let mut skipped = vec![0_u8; usize::from(addons)];
    stream.read_exact(&mut skipped).await?;
    let command = stream.read_u8().await?;
    let port = stream.read_u16().await?;
    let address = match stream.read_u8().await? {
        1 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        2 => {
            let len = stream.read_u8().await?;
            let mut name = vec![0_u8; usize::from(len)];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        3 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        }
        other => return Err(std::io::Error::other(format!("address type {other}"))),
    };
    Ok((command, format!("{address}:{port}")))
}

async fn read_dns_tcp<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let len = stream.read_u16().await?;
    let mut message = vec![0_u8; usize::from(len)];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

// -------------------------------------------------------- direct resolver

/// The network's own resolver, on UDP and TCP at one port.
pub struct DirectResolver {
    pub addr: SocketAddr,
    asked: Arc<AtomicUsize>,
}

impl DirectResolver {
    pub async fn spawn() -> Self {
        loop {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = udp.local_addr().unwrap();
            let Ok(tcp) = TcpListener::bind(addr).await else {
                continue;
            };
            let asked = Arc::new(AtomicUsize::new(0));
            let udp_asked = Arc::clone(&asked);
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4096];
                while let Ok((len, from)) = udp.recv_from(&mut buffer).await {
                    udp_asked.fetch_add(1, Ordering::SeqCst);
                    let answer = dns_answer(&buffer[..len], VIA_DIRECT, DIRECT_A, false);
                    let _ = udp.send_to(&answer, from).await;
                }
            });
            let tcp_asked = Arc::clone(&asked);
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = tcp.accept().await {
                    let asked = Arc::clone(&tcp_asked);
                    tokio::spawn(async move {
                        while let Ok(query) = read_dns_tcp(&mut stream).await {
                            asked.fetch_add(1, Ordering::SeqCst);
                            let answer = dns_answer(&query, VIA_DIRECT, DIRECT_A, false);
                            let mut frame = (answer.len() as u16).to_be_bytes().to_vec();
                            frame.extend_from_slice(&answer);
                            if stream.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
            return Self { addr, asked };
        }
    }

    pub fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

// ------------------------------------------------------------- DNS wire

pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut message = id.to_be_bytes().to_vec();
    message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    push_name(&mut message, name);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    message
}

fn push_name(message: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
}

/// An answer to `query`: header and question copied, A as `a`, TXT as
/// `txt`, SRV as [`SRV_PORT`] at [`SRV_TARGET`], nothing for other types.
/// `truncated` sets TC and leaves the records out.
fn dns_answer(query: &[u8], txt: &[u8], a: Ipv4Addr, truncated: bool) -> Vec<u8> {
    let mut at = 12;
    while query[at] != 0 {
        at += usize::from(query[at]) + 1;
    }
    let question_end = at + 5;
    let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
    let mut answer = query[..question_end].to_vec();
    answer[2] = 0x80 | (query[2] & 0x79) | if truncated { 0x02 } else { 0 };
    answer[3] = 0x80;
    answer[6..12].fill(0);
    if truncated {
        return answer;
    }
    let rdata = match qtype {
        QTYPE_A => a.octets().to_vec(),
        QTYPE_TXT => {
            let mut rdata = vec![txt.len() as u8];
            rdata.extend_from_slice(txt);
            rdata
        }
        QTYPE_SRV => {
            let mut rdata = vec![0, 0, 0, 5];
            rdata.extend_from_slice(&SRV_PORT.to_be_bytes());
            push_name(&mut rdata, SRV_TARGET);
            rdata
        }
        _ => return answer,
    };
    answer[7] = 1;
    answer.extend_from_slice(&[0xc0, 0x0c]);
    answer.extend_from_slice(&qtype.to_be_bytes());
    answer.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    answer.extend_from_slice(&rdata);
    answer
}

/// An answer as a test reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub count: u16,
    /// The first record's type and data.
    pub first: Option<(u16, Vec<u8>)>,
}

impl Answer {
    pub fn parse(message: &[u8]) -> Self {
        let count = u16::from_be_bytes([message[6], message[7]]);
        let mut at = 12;
        while message[at] != 0 {
            at += usize::from(message[at]) + 1;
        }
        at += 5;
        let first = (count > 0).then(|| {
            if message[at] & 0xc0 == 0xc0 {
                at += 2;
            } else {
                while message[at] != 0 {
                    at += usize::from(message[at]) + 1;
                }
                at += 1;
            }
            let rtype = u16::from_be_bytes([message[at], message[at + 1]]);
            let len = usize::from(u16::from_be_bytes([message[at + 8], message[at + 9]]));
            (rtype, message[at + 10..at + 10 + len].to_vec())
        });
        Self {
            id: u16::from_be_bytes([message[0], message[1]]),
            rcode: message[3] & 0x0f,
            truncated: message[2] & 0x02 != 0,
            count,
            first,
        }
    }

    pub fn txt(&self) -> Option<&[u8]> {
        match &self.first {
            Some((QTYPE_TXT, rdata)) => rdata.get(1..),
            _ => None,
        }
    }

    pub fn a(&self) -> Option<Ipv4Addr> {
        match &self.first {
            Some((QTYPE_A, rdata)) if rdata.len() == 4 => {
                Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            }
            _ => None,
        }
    }

    /// The SRV record's (port, target).
    pub fn srv(&self) -> Option<(u16, String)> {
        let Some((QTYPE_SRV, rdata)) = &self.first else {
            return None;
        };
        let port = u16::from_be_bytes([rdata[4], rdata[5]]);
        let mut labels = Vec::new();
        let mut at = 6;
        while rdata[at] != 0 {
            let len = usize::from(rdata[at]);
            labels.push(String::from_utf8_lossy(&rdata[at + 1..at + 1 + len]).into_owned());
            at += len + 1;
        }
        Some((port, labels.join(".")))
    }

    pub fn is_fake(&self) -> bool {
        self.a().is_some_and(|ip| {
            let octets = ip.octets();
            octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
        })
    }
}

// --------------------------------------------------------------- SOCKS5

pub async fn socks_login(socks: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2], "the inbound asks for the login");
    let mut auth = vec![1, USER.len() as u8];
    auth.extend_from_slice(USER.as_bytes());
    auth.push(PASS.len() as u8);
    auth.extend_from_slice(PASS.as_bytes());
    stream.write_all(&auth).await.unwrap();
    let mut status = [0_u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0], "the login is accepted");
    stream
}

/// The reply to a SOCKS5 request: (REP, BND.ADDR as IPv4).
async fn read_reply(stream: &mut TcpStream) -> (u8, SocketAddrV4) {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[3], 1, "an IPv4 bind address");
    let mut bind = [0_u8; 6];
    stream.read_exact(&mut bind).await.unwrap();
    let address = SocketAddrV4::new(
        Ipv4Addr::new(bind[0], bind[1], bind[2], bind[3]),
        u16::from_be_bytes([bind[4], bind[5]]),
    );
    (head[1], address)
}

/// One query over a SOCKS5 CONNECT to the tunnel's DNS address, as DNS over
/// TCP. `None` when no answer came within `wait`.
pub async fn tcp_dns(socks: SocketAddr, message: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let mut stream = socks_login(socks).await;
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&TUN_DNS.ip().octets());
    request.extend_from_slice(&TUN_DNS.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let (rep, _) = read_reply(&mut stream).await;
    assert_eq!(rep, 0, "CONNECT to the DNS address");
    stream
        .write_all(&(message.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(message).await.unwrap();
    timeout(wait, read_dns_tcp(&mut stream)).await.ok()?.ok()
}

/// A SOCKS5 UDP association with a declared client port, which a password
/// inbound requires.
pub struct UdpAssociation {
    control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl UdpAssociation {
    pub async fn open(socks: SocketAddr) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let local = socket.local_addr().unwrap();
        let mut control = socks_login(socks).await;
        let mut request = vec![5, 3, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&local.port().to_be_bytes());
        control.write_all(&request).await.unwrap();
        let (rep, bind) = read_reply(&mut control).await;
        assert_eq!(rep, 0, "UDP ASSOCIATE with a declared port");
        let ip = if bind.ip().is_unspecified() {
            Ipv4Addr::LOCALHOST
        } else {
            *bind.ip()
        };
        Self {
            control,
            socket,
            relay: SocketAddr::from((ip, bind.port())),
        }
    }

    pub async fn send(&self, target: SocketAddrV4, message: &[u8]) {
        let mut datagram = vec![0, 0, 0, 1];
        datagram.extend_from_slice(&target.ip().octets());
        datagram.extend_from_slice(&target.port().to_be_bytes());
        datagram.extend_from_slice(message);
        self.socket.send_to(&datagram, self.relay).await.unwrap();
    }

    /// The next datagram's payload, or `None` after `wait`.
    pub async fn recv(&self, wait: Duration) -> Option<Vec<u8>> {
        let mut buffer = vec![0_u8; 4096];
        let (len, _) = timeout(wait, self.socket.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        Some(buffer[10..len].to_vec())
    }

    pub async fn close(self) {
        drop(self.socket);
        drop(self.control);
    }
}

/// One query over a fresh UDP association.
pub async fn udp_dns(socks: SocketAddr, message: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let association = UdpAssociation::open(socks).await;
    association.send(TUN_DNS, message).await;
    let answer = association.recv(wait).await;
    association.close().await;
    answer
}

/// Waits up to `wait` for `condition`.
pub async fn eventually(wait: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

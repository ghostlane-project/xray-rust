//! The front: the core half of a session with both halves, run in front of
//! the room. `front.rs` points its way to the room, the outbound tagged
//! `room`, at the room's SOCKS port; the core then carries what its rules
//! send there, TCP and UDP, beside a name its rules send direct, and beside
//! a LAN inbound that asks for a login.
//!
//! The room here is a stand-in on loopback: a SOCKS5 server that carries
//! each request to its target on this machine and records what it was asked
//! for, as the room's port carries a request to the room's far side. The
//! front is the core half as the program runs it (`core_run`), after
//! [`front::point`]. No privilege and no network beyond loopback.
//!
//! A session with both halves through the program, with a real room on the
//! `none` carrier and every socket but loopback's bound to an interface, is
//! `tests/netns_front.sh`: it needs root and the olcRTC server.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ghostlane_engine::core_run::CoreLine;
use ghostlane_engine::events::{Events, FailureCode};
use ghostlane_engine::front::{self, ROOM_OUTBOUND};
use ghostlane_engine::Ctx;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// How long a step that should be immediate may take on a loaded runner.
const SOON: Duration = Duration::from_secs(10);
/// The login of the LAN inbound.
const LAN_USER: &str = "lan-user";
const LAN_PASS: &str = "lan-pass";

// ---------------------------------------------------------------------------
// The way to the room, pointed.

fn room_at(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// A core half whose way to the room is `way`, beside a direct outbound.
fn with_way(way: Value) -> Value {
    json!({
        "inbounds": [{"tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, way]
    })
}

#[test]
fn the_way_to_the_room_is_pointed_at_its_port_and_keeps_the_rest() {
    // One server written flat, with a login: the address and the port are
    // the room's, the login and the level stay.
    let mut core = with_way(json!({
        "tag": "room", "protocol": "socks",
        "settings": {"address": "127.0.0.1", "port": 1080, "user": "u", "pass": "p", "level": 1}
    }));
    let before = core.clone();
    front::point(&mut core, room_at(41_234)).unwrap();
    assert_eq!(
        core["outbounds"][1]["settings"],
        json!({"address": "127.0.0.1", "port": 41_234, "user": "u", "pass": "p", "level": 1})
    );
    assert_eq!(
        core["outbounds"][0], before["outbounds"][0],
        "the direct outbound"
    );
    assert_eq!(core["inbounds"], before["inbounds"]);
    assert_eq!(core["outbounds"][1]["tag"], ROOM_OUTBOUND);

    // Whatever it named before: the room's port replaces it.
    let mut core = with_way(json!({
        "tag": "room", "protocol": "socks",
        "settings": {"address": "192.0.2.1", "port": 443}
    }));
    front::point(&mut core, room_at(7)).unwrap();
    assert_eq!(
        core["outbounds"][1]["settings"],
        json!({"address": "127.0.0.1", "port": 7})
    );

    // The one `servers` entry: its users stay.
    let mut core = with_way(json!({
        "tag": "room", "protocol": "socks",
        "settings": {"servers": [{"address": "localhost", "port": 1, "users": [{"user": "u", "pass": "p"}]}]}
    }));
    front::point(&mut core, room_at(41_235)).unwrap();
    assert_eq!(
        core["outbounds"][1]["settings"],
        json!({"servers": [{"address": "127.0.0.1", "port": 41_235, "users": [{"user": "u", "pass": "p"}]}]})
    );

    // No settings, or null ones: the server is written flat.
    for settings in [None, Some(Value::Null)] {
        let mut way = json!({"tag": "room", "protocol": "socks"});
        if let Some(settings) = settings {
            way["settings"] = settings;
        }
        let mut core = with_way(way);
        front::point(&mut core, room_at(41_236)).unwrap();
        assert_eq!(
            core["outbounds"][1]["settings"],
            json!({"address": "127.0.0.1", "port": 41_236})
        );
    }

    // `streamSettings` and `proxySettings` that are null are absent.
    let mut core = with_way(json!({
        "tag": "room", "protocol": "socks", "streamSettings": null, "proxySettings": null,
        "settings": {"address": "127.0.0.1", "port": 1, "servers": null}
    }));
    front::point(&mut core, "[::1]:41237".parse().unwrap()).unwrap();
    assert_eq!(
        core["outbounds"][1]["settings"],
        json!({"address": "::1", "port": 41_237, "servers": null})
    );
}

#[test]
fn a_core_half_with_no_way_to_the_room_is_refused_and_left_as_it_was() {
    let socks = |more: Value| {
        let mut way = json!({"tag": "room", "protocol": "socks"});
        for (name, value) in more.as_object().unwrap() {
            way[name] = value.clone();
        }
        with_way(way)
    };
    let cases = [
        (json!({"inbounds": []}), "no outbound is tagged `room`"),
        (
            json!({"outbounds": {"tag": "room"}}),
            "no outbound is tagged `room`",
        ),
        (
            json!({"outbounds": [{"tag": "proxy", "protocol": "socks"}, "room"]}),
            "no outbound is tagged `room`",
        ),
        (
            json!({"outbounds": [
                {"tag": "room", "protocol": "socks"},
                {"tag": "room", "protocol": "socks"}
            ]}),
            "$.outbounds[1]: a second outbound is tagged `room`",
        ),
        (
            with_way(json!({"tag": "room", "protocol": "freedom"})),
            "$.outbounds[1]: the way to the room is a `socks` outbound",
        ),
        (
            with_way(json!({"tag": "room"})),
            "$.outbounds[1]: the way to the room is a `socks` outbound",
        ),
        (
            socks(json!({"streamSettings": {"sockopt": {"interface": "eth0"}}})),
            "$.outbounds[1].streamSettings: the way to the room is plain SOCKS",
        ),
        (
            socks(json!({"proxySettings": {"tag": "direct"}})),
            "$.outbounds[1].proxySettings: the way to the room is plain SOCKS",
        ),
        (
            socks(json!({"settings": [{"address": "127.0.0.1"}]})),
            "$.outbounds[1].settings: must be an object",
        ),
        (
            socks(json!({"settings": {"servers": []}})),
            "$.outbounds[1].settings.servers: the way to the room names one server",
        ),
        (
            socks(json!({"settings": {"servers": [
                {"address": "127.0.0.1", "port": 1},
                {"address": "127.0.0.1", "port": 2}
            ]}})),
            "$.outbounds[1].settings.servers: the way to the room names one server",
        ),
        (
            socks(json!({"settings": {"servers": ["127.0.0.1:1"]}})),
            "$.outbounds[1].settings.servers: the way to the room names one server",
        ),
    ];
    for (core, words) in cases {
        let mut pointed = core.clone();
        let failure = front::point(&mut pointed, room_at(41_238)).unwrap_err();
        assert_eq!(failure.code, FailureCode::Config, "{core}: {failure:?}");
        assert!(
            failure.message.contains(words),
            "{core}: {:?} does not say {words:?}",
            failure.message
        );
        assert_eq!(pointed, core, "a refused core half is left as it was");
    }
}

// ---------------------------------------------------------------------------
// The stand-in for the room's port.

/// A SOCKS5 server on loopback with no login, CONNECT and UDP ASSOCIATE,
/// that carries each request to its target on this machine (a name is this
/// machine too) and records what it was asked for: `tcp <host>:<port>` and
/// `udp <host>:<port>`.
struct StandIn {
    address: SocketAddr,
    asked: Arc<Mutex<Vec<String>>>,
}

impl StandIn {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&asked);
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let _ = Self::serve(client, &record).await;
                });
            }
        });
        Self { address, asked }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }

    async fn serve(mut client: TcpStream, asked: &Mutex<Vec<String>>) -> io::Result<()> {
        let mut head = [0_u8; 2];
        client.read_exact(&mut head).await?;
        let mut methods = vec![0_u8; usize::from(head[1])];
        client.read_exact(&mut methods).await?;
        if head[0] != 5 || !methods.contains(&0) {
            return client.write_all(&[5, 0xff]).await;
        }
        client.write_all(&[5, 0]).await?;
        let mut request = [0_u8; 4];
        client.read_exact(&mut request).await?;
        let (host, port) = read_target(&mut client, request[3]).await?;
        match request[1] {
            1 => {
                asked.lock().unwrap().push(format!("tcp {host}:{port}"));
                let ip = host.parse().unwrap_or(Ipv4Addr::LOCALHOST);
                let mut target = TcpStream::connect((ip, port)).await?;
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                Ok(())
            }
            3 => Self::relay(client, asked).await,
            _ => client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await,
        }
    }

    /// One UDP association: each datagram is sent on to its target and its
    /// one answer handed back, until the control connection closes.
    async fn relay(mut control: TcpStream, asked: &Mutex<Vec<String>>) -> io::Result<()> {
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let out = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let SocketAddr::V4(at) = relay.local_addr()? else {
            unreachable!("bound on IPv4 loopback")
        };
        let mut reply = vec![5, 0, 0, 1];
        reply.extend_from_slice(&at.ip().octets());
        reply.extend_from_slice(&at.port().to_be_bytes());
        control.write_all(&reply).await?;
        let mut datagram = vec![0_u8; 65_536];
        let mut answer = vec![0_u8; 65_536];
        let mut closed = [0_u8; 1];
        loop {
            tokio::select! {
                read = control.read(&mut closed) => {
                    if matches!(read, Ok(0) | Err(_)) {
                        return Ok(());
                    }
                }
                got = relay.recv_from(&mut datagram) => {
                    let (len, from) = got?;
                    let Some((host, port, header)) = datagram_target(&datagram[..len]) else {
                        continue;
                    };
                    asked.lock().unwrap().push(format!("udp {host}:{port}"));
                    let ip = host.parse().unwrap_or(Ipv4Addr::LOCALHOST);
                    out.send_to(&datagram[header..len], (ip, port)).await?;
                    let Ok(Ok((n, _))) = timeout(SOON, out.recv_from(&mut answer)).await else {
                        continue;
                    };
                    let mut back = datagram[..header].to_vec();
                    back.extend_from_slice(&answer[..n]);
                    relay.send_to(&back, from).await?;
                }
            }
        }
    }
}

/// A request's target: an IPv4 address, a name or an IPv6 address, then
/// the port.
async fn read_target(stream: &mut TcpStream, kind: u8) -> io::Result<(String, u16)> {
    let host = match kind {
        1 => {
            let mut ip = [0_u8; 4];
            stream.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut name = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut ip = [0_u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Err(io::Error::other("an address of no SOCKS5 kind")),
    };
    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

/// A SOCKS5 datagram's target and the length of its header.
fn datagram_target(datagram: &[u8]) -> Option<(String, u16, usize)> {
    let (host, at) = match *datagram.get(3)? {
        1 => {
            let ip: [u8; 4] = datagram.get(4..8)?.try_into().ok()?;
            (Ipv4Addr::from(ip).to_string(), 8)
        }
        3 => {
            let length = usize::from(*datagram.get(4)?);
            let name = datagram.get(5..5 + length)?;
            (String::from_utf8_lossy(name).into_owned(), 5 + length)
        }
        _ => return None,
    };
    let port = datagram.get(at..at + 2)?;
    Some((host, u16::from_be_bytes([port[0], port[1]]), at + 2))
}

// ---------------------------------------------------------------------------
// What the front's clients reach.

/// A TCP echo that counts its connections, and a UDP echo, on loopback.
struct Echoes {
    tcp: SocketAddr,
    udp: SocketAddr,
    connections: Arc<AtomicUsize>,
}

impl Echoes {
    async fn start() -> Self {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp_at = tcp.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut from, mut to) = stream.split();
                    let _ = tokio::io::copy(&mut from, &mut to).await;
                });
            }
        });
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_at = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            while let Ok((len, from)) = udp.recv_from(&mut buffer).await {
                let _ = udp.send_to(&buffer[..len], from).await;
            }
        });
        Self {
            tcp: tcp_at,
            udp: udp_at,
            connections,
        }
    }
}

// ---------------------------------------------------------------------------
// The front.

/// The core half of a front as a parent writes it: the session's SOCKS
/// inbound, a LAN inbound with a login on every address when `lan`, the way
/// to the room first (what no rule claims rides it), and `direct.test` sent
/// direct, which the core's own hosts answer.
fn front_core(lan: bool) -> Value {
    let mut inbounds = vec![json!({
        "tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
        "settings": {"auth": "noauth", "udp": true}
    })];
    if lan {
        inbounds.push(json!({
            "tag": "lan-in", "protocol": "socks", "listen": "0.0.0.0", "port": 0,
            "settings": {
                "auth": "password",
                "accounts": [{"user": LAN_USER, "pass": LAN_PASS}],
                "udp": true,
                "allowUnauthenticatedLan": true
            }
        }));
    }
    json!({
        "log": {"loglevel": "warning"},
        "dns": {"hosts": {"direct.test": "127.0.0.1"}},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "room", "protocol": "socks", "settings": {"address": "127.0.0.1", "port": 1080}},
            {"tag": "direct", "protocol": "freedom"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "domain": ["domain:direct.test"], "outboundTag": "direct"}]
        }
    })
}

/// The front of `room`, running: its listeners by tag.
async fn front(room: &StandIn, lan: bool) -> (CoreLine, HashMap<String, SocketAddr>) {
    let mut core = front_core(lan);
    front::point(&mut core, room.address).unwrap();
    let ctx = Ctx {
        events: Events::to(Box::new(io::sink())),
        escape: None,
    };
    let line = CoreLine::start(&core, None, &ctx)
        .await
        .unwrap_or_else(|failure| panic!("the front: {failure:?}"));
    let listeners = line
        .inbounds()
        .iter()
        .map(|inbound| {
            let mut address: SocketAddr = inbound.address.parse().unwrap();
            if address.ip().is_unspecified() {
                address.set_ip(Ipv4Addr::LOCALHOST.into());
            }
            (inbound.tag.clone().unwrap_or_default(), address)
        })
        .collect();
    (line, listeners)
}

enum Login<'a> {
    None,
    Password(&'a str, &'a str),
}

/// A SOCKS5 greeting with `login`: the connection, once the proxy chose the
/// method and took the login; an error when it did not.
async fn greet(proxy: SocketAddr, login: &Login<'_>) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    let method = match login {
        Login::None => 0,
        Login::Password(..) => 2,
    };
    stream.write_all(&[5, 1, method]).await?;
    let mut chosen = [0_u8; 2];
    stream.read_exact(&mut chosen).await?;
    if chosen != [5, method] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the proxy chose {chosen:?}"),
        ));
    }
    if let Login::Password(user, pass) = login {
        let mut auth = vec![1, u8::try_from(user.len()).unwrap()];
        auth.extend_from_slice(user.as_bytes());
        auth.push(u8::try_from(pass.len()).unwrap());
        auth.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth).await?;
        let mut status = [0_u8; 2];
        stream.read_exact(&mut status).await?;
        if status != [1, 0] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the login was refused: {status:?}"),
            ));
        }
    }
    Ok(stream)
}

/// A round trip through `proxy` to the TCP echo's port at the name `host`.
async fn tcp_by_name(
    proxy: SocketAddr,
    login: &Login<'_>,
    host: &str,
    echo: SocketAddr,
) -> io::Result<()> {
    let mut stream = greet(proxy, login).await?;
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[..2] != [5, 0] {
        return Err(io::Error::other(format!(
            "the CONNECT was answered {reply:?}"
        )));
    }
    let said = format!("tcp to {host} through the front");
    stream.write_all(said.as_bytes()).await?;
    let mut echoed = vec![0_u8; said.len()];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(echoed, said.as_bytes());
    Ok(())
}

/// A datagram through `proxy` to the UDP echo at `target` and back. The
/// association names the address the datagrams come from: an inbound with a
/// login pins it there, and refuses one that names no port.
async fn udp_round_trip(
    proxy: SocketAddr,
    login: &Login<'_>,
    target: SocketAddr,
) -> io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut control = greet(proxy, login).await?;
    let mut associate = vec![5, 3, 0, 1];
    associate.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    associate.extend_from_slice(&socket.local_addr()?.port().to_be_bytes());
    control.write_all(&associate).await?;
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).await?;
    assert_eq!(reply[..4], [5, 0, 0, 1], "the association, on IPv4");
    let mut relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    if relay.ip().is_unspecified() {
        relay.set_ip(proxy.ip());
    }
    let SocketAddr::V4(target) = target else {
        unreachable!("the echo is on IPv4 loopback")
    };
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&target.ip().octets());
    datagram.extend_from_slice(&target.port().to_be_bytes());
    datagram.extend_from_slice(b"a datagram through the front");
    socket.send_to(&datagram, relay).await?;
    let mut buffer = [0_u8; 2048];
    let (len, _) = timeout(SOON, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no datagram came back"))??;
    assert!(len > 10, "a reply with its header");
    assert_eq!(&buffer[10..len], b"a datagram through the front");
    drop(control);
    Ok(())
}

/// What the front sends to its room goes there, TCP and UDP, by the room's
/// port; the name its rules send direct reaches its target without the room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_front_carries_tcp_and_a_datagram_to_the_room_and_one_name_direct() {
    let echoes = Echoes::start().await;
    let room = StandIn::start().await;
    let (line, listeners) = front(&room, false).await;
    let own = listeners["in"];

    timeout(
        SOON,
        tcp_by_name(own, &Login::None, "room.test", echoes.tcp),
    )
    .await
    .expect("TCP by the room: no answer")
    .unwrap();
    assert_eq!(
        room.asked(),
        [format!("tcp room.test:{}", echoes.tcp.port())],
        "the name reached the room as a name"
    );
    assert_eq!(echoes.connections.load(Ordering::SeqCst), 1);

    timeout(
        SOON,
        tcp_by_name(own, &Login::None, "direct.test", echoes.tcp),
    )
    .await
    .expect("TCP direct: no answer")
    .unwrap();
    assert_eq!(
        room.asked().len(),
        1,
        "the direct name never reached the room"
    );
    assert_eq!(
        echoes.connections.load(Ordering::SeqCst),
        2,
        "it reached its target without the room"
    );

    timeout(SOON, udp_round_trip(own, &Login::None, echoes.udp))
        .await
        .expect("UDP by the room: no answer")
        .unwrap();
    assert_eq!(
        room.asked().last(),
        Some(&format!("udp 127.0.0.1:{}", echoes.udp.port())),
        "the datagram went by the room: {:?}",
        room.asked()
    );
    line.stop().await.unwrap();
}

/// A LAN inbound beside the session's own: a client with no login, or with
/// a wrong one, cannot use it, and nothing it asks reaches the room; with
/// the login, its TCP and its datagrams ride the same rules to the room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lan_inbound_refuses_a_client_with_no_login() {
    let echoes = Echoes::start().await;
    let room = StandIn::start().await;
    let (line, listeners) = front(&room, true).await;
    let lan = listeners["lan-in"];

    // No login offered: the inbound takes no method, and a request sent
    // anyway is not carried.
    let mut stream = TcpStream::connect(lan).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut chosen = [0_u8; 2];
    match timeout(SOON, stream.read_exact(&mut chosen)).await {
        Ok(Ok(_)) => assert_eq!(chosen, [5, 0xff], "no acceptable method"),
        Ok(Err(_)) => {} // closed at once
        Err(_) => panic!("the LAN inbound neither refused nor closed"),
    }
    let mut request = vec![5, 1, 0, 3, 9];
    request.extend_from_slice(b"room.test");
    request.extend_from_slice(&echoes.tcp.port().to_be_bytes());
    let _ = stream.write_all(&request).await;
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
    assert!(
        !rest.starts_with(&[5, 0]),
        "a request with no login was answered: {rest:?}"
    );
    drop(stream);

    // A wrong login.
    let wrong = timeout(SOON, greet(lan, &Login::Password(LAN_USER, "not-the-pass")))
        .await
        .expect("the LAN inbound neither refused nor closed");
    assert!(wrong.is_err(), "a wrong login was taken");

    assert!(room.asked().is_empty(), "{:?}", room.asked());
    assert_eq!(echoes.connections.load(Ordering::SeqCst), 0);

    // With the login: the same rules, to the room.
    timeout(
        SOON,
        tcp_by_name(
            lan,
            &Login::Password(LAN_USER, LAN_PASS),
            "room.test",
            echoes.tcp,
        ),
    )
    .await
    .expect("TCP from the LAN: no answer")
    .unwrap();
    assert_eq!(
        room.asked(),
        [format!("tcp room.test:{}", echoes.tcp.port())]
    );
    timeout(
        SOON,
        udp_round_trip(lan, &Login::Password(LAN_USER, LAN_PASS), echoes.udp),
    )
    .await
    .expect("UDP from the LAN: no answer")
    .unwrap();
    assert_eq!(
        room.asked().last(),
        Some(&format!("udp 127.0.0.1:{}", echoes.udp.port())),
        "the datagram went by the room: {:?}",
        room.asked()
    );
    line.stop().await.unwrap();
}

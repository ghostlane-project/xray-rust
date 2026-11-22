//! The way out leaves loopback alone. A socket the core half opens towards
//! 127.0.0.1 or ::1 (a front's dial to its room's SOCKS port, the TCP control
//! connection and the UDP relay socket) is never handed to the system's
//! binder: a socket bound to the physical interface could not reach loopback.
//! Every other socket is, and so is one whose peer the opener does not say.
//!
//! The binder is a stand-in that records the kind of each socket it is handed
//! and binds nothing, so the test needs no privilege and no network beyond
//! loopback. The TEST-NET servers (192.0.2.0/24, 2001:db8::/32) are never
//! reached: the binder is asked before the dial, which may then fail.
#![cfg(unix)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghostlane_engine::core_run::CoreLine;
use ghostlane_engine::escape::{Binder, Escape, RawSocket};
use ghostlane_engine::events::Events;
use ghostlane_engine::Ctx;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// How long a step that should be immediate may take on a loaded runner.
const SOON: Duration = Duration::from_secs(10);

/// What the binder sees of a socket to loopback.
const NONE: Vec<Kind> = Vec::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp,
    Udp,
}

fn kind(socket: RawSocket) -> Kind {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the socket stays open while the binder is asked about it, and
    // `value` is a local `c_int` of the size passed.
    let result = unsafe {
        libc::getsockopt(
            socket as libc::c_int,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    match value {
        libc::SOCK_STREAM => Kind::Tcp,
        libc::SOCK_DGRAM => Kind::Udp,
        other => panic!("a socket of type {other}"),
    }
}

/// The stand-in for a system's binder: it records and binds nothing.
#[derive(Default)]
struct Recorder(Mutex<Vec<Kind>>);

impl Binder for Recorder {
    fn bind(&self, socket: RawSocket) -> io::Result<()> {
        self.0.lock().unwrap().push(kind(socket));
        Ok(())
    }
}

impl Recorder {
    fn seen(&self) -> Vec<Kind> {
        self.0.lock().unwrap().clone()
    }

    /// What the binder saw once it has seen `count` sockets, or after
    /// [`SOON`].
    async fn seen_at_least(&self, count: usize) -> Vec<Kind> {
        let deadline = Instant::now() + SOON;
        loop {
            let seen = self.seen();
            if seen.len() >= count || Instant::now() >= deadline {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn recorded() -> (Arc<Recorder>, Escape) {
    let recorder = Arc::new(Recorder::default());
    let escape = Escape::with_binder("test0", recorder.clone());
    (recorder, escape)
}

fn ctx(escape: Option<Escape>) -> Ctx {
    Ctx {
        events: Events::to(Box::new(io::sink())),
        escape,
    }
}

/// Whether this host has IPv6 loopback; the IPv6 cases are skipped without.
fn ipv6() -> bool {
    match StdUdpSocket::bind((Ipv6Addr::LOCALHOST, 0)) {
        Ok(_) => true,
        Err(error) => {
            eprintln!("no IPv6 loopback here ({error}): its cases are skipped");
            false
        }
    }
}

fn socket_fd(socket: &StdUdpSocket) -> RawSocket {
    use std::os::fd::AsRawFd;
    RawSocket::from(socket.as_raw_fd())
}

fn at(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), 1080)
}

#[test]
fn only_a_loopback_peer_is_left_unbound() {
    let (recorder, escape) = recorded();
    let socket = StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let fd = socket_fd(&socket);
    for peer in ["127.0.0.1", "127.3.2.1", "::1", "::ffff:127.0.0.1"] {
        escape.bind(fd, Some(at(peer))).unwrap();
        assert_eq!(recorder.seen(), NONE, "{peer} reached the binder");
    }
    for peer in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
        escape.bind(fd, Some(at(peer))).unwrap();
    }
    // A socket whose peer is not said is bound: that is the safe side.
    escape.bind(fd, None).unwrap();
    assert_eq!(recorder.seen(), [Kind::Udp; 4]);
}

/// The core's protector skips by the same rule, told the peer by the openers
/// that know it.
#[tokio::test]
async fn the_cores_protector_leaves_loopback_unbound() {
    let (recorder, escape) = recorded();
    let protector = escape.core_protector();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    xray_transport::connect_tcp_stream(listener.local_addr().unwrap(), Some(&*protector))
        .await
        .unwrap();
    if ipv6() {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        xray_transport::connect_tcp_stream(listener.local_addr().unwrap(), Some(&*protector))
            .await
            .unwrap();
    }
    let socket = StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    xray_transport::protect_std_udp_socket_to(&socket, at("127.0.0.1"), Some(&*protector)).unwrap();
    assert_eq!(
        recorder.seen(),
        NONE,
        "a loopback socket reached the binder"
    );

    // The binder is asked before the dial, which may fail here.
    let _ = timeout(
        Duration::from_millis(500),
        xray_transport::connect_tcp_stream(at("192.0.2.1"), Some(&*protector)),
    )
    .await;
    xray_transport::protect_std_udp_socket_to(&socket, at("192.0.2.1"), Some(&*protector)).unwrap();
    xray_transport::protect_std_udp_socket(&socket, Some(&*protector)).unwrap();
    assert_eq!(recorder.seen(), [Kind::Tcp, Kind::Udp, Kind::Udp]);
}

/// A TCP and a UDP echo on IPv4 loopback.
async fn echoes() -> (SocketAddr, SocketAddr) {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp_at = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
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
    (tcp_at, udp_at)
}

fn socks_inbound(tag: &str, listen: &str) -> Value {
    json!({"tag": tag, "protocol": "socks", "listen": listen, "port": 0,
           "settings": {"auth": "noauth", "udp": true}})
}

/// The stand-in for a room's SOCKS port: a core with no way out, its SOCKS
/// inbound (TCP and UDP) on IPv4 loopback, and on IPv6 loopback when `v6`,
/// carrying everything direct. The listeners, by tag.
async fn room(v6: bool) -> (CoreLine, Vec<(String, SocketAddr)>) {
    let mut inbounds = vec![socks_inbound("room-v4", "127.0.0.1")];
    if v6 {
        inbounds.push(socks_inbound("room-v6", "::1"));
    }
    let config = json!({
        "inbounds": inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    });
    let line = CoreLine::start(&config, None, &ctx(None))
        .await
        .unwrap_or_else(|failure| panic!("the room's stand-in: {failure:?}"));
    let listeners = line
        .inbounds()
        .iter()
        .map(|inbound| {
            (
                inbound.tag.clone().unwrap_or_default(),
                inbound.address.parse().unwrap(),
            )
        })
        .collect();
    (line, listeners)
}

/// A front: a core line with the way out, its SOCKS inbound on loopback,
/// and a `socks` outbound to `server`, TCP and UDP. Its inbound's address.
async fn front(server: SocketAddr, escape: Escape) -> (CoreLine, SocketAddr) {
    let config = json!({
        "inbounds": [socks_inbound("socks-in", "127.0.0.1")],
        "outbounds": [{"tag": "room", "protocol": "socks",
                       "settings": {"address": server.ip().to_string(), "port": server.port()}}]
    });
    let line = CoreLine::start(&config, None, &ctx(Some(escape)))
        .await
        .unwrap_or_else(|failure| panic!("the front to {server}: {failure:?}"));
    let address = line.inbounds()[0].address.parse().unwrap();
    (line, address)
}

async fn greet(proxy: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "SOCKS5 with no login");
    stream
}

fn ipv4_address(addr: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(addr) = addr else {
        panic!("the test's targets are IPv4: {addr}");
    };
    let mut bytes = vec![1];
    bytes.extend_from_slice(&addr.ip().octets());
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}

/// A SOCKS5 CONNECT to `target` through `proxy`, the request sent.
async fn connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = greet(proxy).await;
    let mut request = vec![5, 1, 0];
    request.extend(ipv4_address(target));
    stream.write_all(&request).await.unwrap();
    stream
}

/// A round trip through `proxy` to the TCP echo at `target`.
async fn tcp_round_trip(proxy: SocketAddr, target: SocketAddr) {
    let mut stream = connect(proxy, target).await;
    let mut reply = [0_u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..2], [5, 0], "the CONNECT is accepted");
    stream.write_all(b"tcp through the front").await.unwrap();
    let mut echoed = [0_u8; 21];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"tcp through the front");
}

/// A UDP association with `proxy`: its control connection, held, and a
/// client socket that sends one datagram for `target` to its relay.
async fn associate(proxy: SocketAddr, target: SocketAddr) -> (TcpStream, UdpSocket) {
    let mut control = greet(proxy).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..4], [5, 0, 0, 1], "the association, on IPv4");
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut datagram = vec![0, 0, 0];
    datagram.extend(ipv4_address(target));
    datagram.extend_from_slice(b"udp through the front");
    socket.send_to(&datagram, relay).await.unwrap();
    (control, socket)
}

/// A datagram through `proxy` to the UDP echo at `target` and back.
async fn udp_round_trip(proxy: SocketAddr, target: SocketAddr) {
    let (_control, socket) = associate(proxy, target).await;
    let mut buffer = [0_u8; 2048];
    let (len, _) = timeout(SOON, socket.recv_from(&mut buffer))
        .await
        .expect("the datagram comes back through the front and the room")
        .unwrap();
    assert!(len > 10, "a reply with its header");
    assert_eq!(&buffer[10..len], b"udp through the front");
}

/// A front's dials to its room on loopback, TCP and the UDP relay, by
/// 127.0.0.1, ::1 and ::ffff:127.0.0.1, reach the room and never the binder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fronts_dials_to_its_room_on_loopback_never_reach_the_binder() {
    let (tcp_echo, udp_echo) = echoes().await;
    let v6 = ipv6();
    let (room, listeners) = room(v6).await;
    let mut servers = Vec::new();
    for (tag, address) in &listeners {
        servers.push(*address);
        if tag == "room-v4" {
            let SocketAddr::V4(v4) = address else {
                panic!("{tag} at {address}");
            };
            servers.push(SocketAddr::new(
                IpAddr::V6(v4.ip().to_ipv6_mapped()),
                v4.port(),
            ));
        }
    }
    assert_eq!(servers.len(), if v6 { 3 } else { 2 }, "{listeners:?}");

    for server in servers {
        let (recorder, escape) = recorded();
        let (line, proxy) = front(server, escape).await;
        timeout(SOON, tcp_round_trip(proxy, tcp_echo))
            .await
            .unwrap_or_else(|_| panic!("TCP to the room at {server}: no answer"));
        timeout(SOON, udp_round_trip(proxy, udp_echo))
            .await
            .unwrap_or_else(|_| panic!("UDP to the room at {server}: no answer"));
        assert_eq!(
            recorder.seen(),
            NONE,
            "the front's sockets to its room at {server} reached the binder"
        );
        line.stop().await.unwrap();
    }
    room.stop().await.unwrap();
}

/// The same front with its room elsewhere: each of its sockets reaches the
/// binder, the relay socket first, as the association opens it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fronts_dials_elsewhere_reach_the_binder() {
    let mut servers = vec![at("192.0.2.1")];
    if ipv6() {
        servers.push(at("2001:db8::1"));
    }
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    for server in servers {
        let (recorder, escape) = recorded();
        let (line, proxy) = front(server, escape).await;
        let tcp = connect(proxy, target).await;
        assert_eq!(
            recorder.seen_at_least(1).await,
            [Kind::Tcp],
            "the CONNECT's dial to {server}"
        );
        drop(tcp);

        let (recorder, escape) = recorded();
        let (udp_line, proxy) = front(server, escape).await;
        let _association = associate(proxy, target).await;
        assert_eq!(
            recorder.seen_at_least(2).await,
            [Kind::Udp, Kind::Tcp],
            "the association with {server}: its relay socket, then its control connection"
        );
        let _ = timeout(SOON, line.stop()).await;
        let _ = timeout(SOON, udp_line.stop()).await;
    }
}

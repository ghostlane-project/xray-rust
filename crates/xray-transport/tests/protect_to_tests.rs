//! The peer a socket is opened for, told to the platform's protector
//! ([`SocketProtector::protect_to`]), and the contract that does not move for
//! a protector that implements only `protect` (Android's, the iPhone's, every
//! older test's): it is handed every socket as before, once each and in the
//! same order.
#![cfg(unix)]

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    os::fd::{AsRawFd, RawFd},
    sync::{Arc, Mutex},
};

use tokio::net::{TcpListener, UdpSocket};
use xray_transport::{
    connect_tcp_stream, protect_std_udp_socket, protect_std_udp_socket_to, protect_udp_socket,
    protect_udp_socket_to, SocketHandle, SocketOptions, SocketOptionsProtector, SocketProtector,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp,
    Udp,
}

/// One call a protector was handed: which of the two, the socket's kind and
/// the peer it was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Protect(Kind),
    ProtectTo(Kind, SocketAddr),
}

fn get(fd: RawFd, level: libc::c_int, name: libc::c_int) -> libc::c_int {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a socket that stays open for this call, and `value` is
    // a local `c_int` of the size passed.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0, "{}", io::Error::last_os_error());
    value
}

fn kind(socket: SocketHandle) -> Kind {
    match get(socket.raw() as RawFd, libc::SOL_SOCKET, libc::SO_TYPE) {
        libc::SOCK_STREAM => Kind::Tcp,
        libc::SOCK_DGRAM => Kind::Udp,
        other => panic!("a socket of type {other}"),
    }
}

/// A protector of today's kind: it implements only `protect`.
#[derive(Default)]
struct ProtectOnly(Mutex<Vec<Kind>>);

impl SocketProtector for ProtectOnly {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        self.0.lock().unwrap().push(kind(socket));
        Ok(())
    }
}

impl ProtectOnly {
    fn seen(&self) -> Vec<Kind> {
        self.0.lock().unwrap().clone()
    }
}

/// A protector that is told the peer; `multipath` asks for Multipath TCP.
#[derive(Default)]
struct PeerAware {
    calls: Mutex<Vec<Call>>,
    multipath: bool,
}

impl SocketProtector for PeerAware {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        self.calls.lock().unwrap().push(Call::Protect(kind(socket)));
        Ok(())
    }

    fn protect_to(&self, socket: SocketHandle, peer: SocketAddr) -> io::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::ProtectTo(kind(socket), peer));
        Ok(())
    }

    fn multipath_tcp(&self) -> bool {
        self.multipath
    }
}

impl PeerAware {
    fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

/// A listener on IPv4 loopback that accepts and drops every connection.
async fn listener_v4() -> SocketAddr {
    listener((Ipv4Addr::LOCALHOST, 0).into()).await.unwrap()
}

/// The same on IPv6 loopback, or `None` on a host without it.
async fn listener_v6() -> Option<SocketAddr> {
    match listener((Ipv6Addr::LOCALHOST, 0).into()).await {
        Ok(addr) => Some(addr),
        Err(error) => {
            eprintln!("no IPv6 loopback here ({error}): its cases are skipped");
            None
        }
    }
}

async fn listener(at: SocketAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(at).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    Ok(addr)
}

/// `addr` as an IPv4-mapped IPv6 address.
fn mapped(addr: SocketAddr) -> SocketAddr {
    let SocketAddr::V4(v4) = addr else {
        panic!("{addr} is not IPv4");
    };
    (v4.ip().to_ipv6_mapped(), v4.port()).into()
}

fn udp_v4() -> StdUdpSocket {
    StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap()
}

const TEST_NET: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 1080);

#[tokio::test]
async fn a_tcp_dial_tells_the_protector_the_address_it_connects_to() {
    let protector = PeerAware::default();
    let v4 = listener_v4().await;
    connect_tcp_stream(v4, Some(&protector)).await.unwrap();
    assert_eq!(protector.take(), [Call::ProtectTo(Kind::Tcp, v4)]);

    // A mapped address is dialed, and told, as the IPv4 address it is.
    connect_tcp_stream(mapped(v4), Some(&protector))
        .await
        .unwrap();
    assert_eq!(protector.take(), [Call::ProtectTo(Kind::Tcp, v4)]);

    if let Some(v6) = listener_v6().await {
        connect_tcp_stream(v6, Some(&protector)).await.unwrap();
        assert_eq!(protector.take(), [Call::ProtectTo(Kind::Tcp, v6)]);
    }
}

#[tokio::test]
async fn the_udp_helpers_that_know_the_peer_tell_it() {
    let protector = PeerAware::default();
    let std_socket = udp_v4();
    protect_std_udp_socket_to(&std_socket, TEST_NET, Some(&protector)).unwrap();
    protect_std_udp_socket(&std_socket, Some(&protector)).unwrap();
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    protect_udp_socket_to(&socket, TEST_NET, Some(&protector)).unwrap();
    protect_udp_socket(&socket, Some(&protector)).unwrap();
    assert_eq!(
        protector.take(),
        [
            Call::ProtectTo(Kind::Udp, TEST_NET),
            Call::Protect(Kind::Udp),
            Call::ProtectTo(Kind::Udp, TEST_NET),
            Call::Protect(Kind::Udp),
        ]
    );
    // No protector, nothing to tell.
    protect_std_udp_socket_to(&std_socket, TEST_NET, None).unwrap();
    protect_udp_socket_to(&socket, TEST_NET, None).unwrap();
}

/// `sockopt` wraps the platform's protector: the peer reaches it, and the
/// options still go on after it (TCP keepalive, on by default).
#[tokio::test]
async fn socket_options_tell_the_platform_protector_the_peer_and_still_apply() {
    let platform = Arc::new(PeerAware::default());
    let options = SocketOptionsProtector::new(
        Some(platform.clone()),
        Arc::new(SocketOptions::default()),
        None,
    );
    let v4 = listener_v4().await;
    let stream = connect_tcp_stream(v4, Some(&options)).await.unwrap();
    assert_eq!(platform.take(), [Call::ProtectTo(Kind::Tcp, v4)]);
    assert_ne!(
        get(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE),
        0,
        "the options went on after the protector"
    );

    let socket = udp_v4();
    protect_std_udp_socket_to(&socket, TEST_NET, Some(&options)).unwrap();
    protect_std_udp_socket(&socket, Some(&options)).unwrap();
    assert_eq!(
        platform.take(),
        [
            Call::ProtectTo(Kind::Udp, TEST_NET),
            Call::Protect(Kind::Udp)
        ]
    );
}

/// The contract the phones' protectors rely on: one implementing only
/// `protect` is handed each socket once, in the order the sockets are made,
/// by every opener that now knows the peer, directly and under `sockopt`.
#[tokio::test]
async fn a_protector_with_only_protect_is_handed_every_socket_as_before() {
    let protector = Arc::new(ProtectOnly::default());
    let v4 = listener_v4().await;
    let mut want = Vec::new();

    connect_tcp_stream(v4, Some(&*protector)).await.unwrap();
    connect_tcp_stream(mapped(v4), Some(&*protector))
        .await
        .unwrap();
    want.extend([Kind::Tcp, Kind::Tcp]);
    if let Some(v6) = listener_v6().await {
        connect_tcp_stream(v6, Some(&*protector)).await.unwrap();
        want.push(Kind::Tcp);
    }

    let std_socket = udp_v4();
    protect_std_udp_socket(&std_socket, Some(&*protector)).unwrap();
    protect_std_udp_socket_to(&std_socket, TEST_NET, Some(&*protector)).unwrap();
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    protect_udp_socket(&socket, Some(&*protector)).unwrap();
    protect_udp_socket_to(&socket, TEST_NET, Some(&*protector)).unwrap();
    want.extend([Kind::Udp, Kind::Udp, Kind::Udp, Kind::Udp]);

    let options = SocketOptionsProtector::new(
        Some(protector.clone()),
        Arc::new(SocketOptions::default()),
        None,
    );
    connect_tcp_stream(v4, Some(&options)).await.unwrap();
    protect_std_udp_socket_to(&std_socket, TEST_NET, Some(&options)).unwrap();
    protect_std_udp_socket(&std_socket, Some(&options)).unwrap();
    want.extend([Kind::Tcp, Kind::Udp, Kind::Udp]);

    assert_eq!(protector.seen(), want);
}

/// A Multipath TCP dial tells the peer too, and so does the plain TCP dial
/// it falls back to on a kernel without it.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn a_multipath_dial_tells_the_protector_the_address_too() {
    let protector = PeerAware {
        multipath: true,
        ..PeerAware::default()
    };
    let v4 = listener_v4().await;
    connect_tcp_stream(v4, Some(&protector)).await.unwrap();
    let calls = protector.take();
    assert!(!calls.is_empty());
    assert!(
        calls
            .iter()
            .all(|call| *call == Call::ProtectTo(Kind::Tcp, v4)),
        "{calls:?}"
    );
}

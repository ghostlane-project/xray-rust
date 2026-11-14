//! hev-socks5's `FWD_UDP` (`0x05`) on the SOCKS inbound: UDP carried in the
//! authenticated control connection, as hev-socks5-tunnel sends it with
//! `udp: 'tcp'`. The request names `0.0.0.0:0` and is answered `05 00 00 01`
//! with a zero address; each datagram then travels in both directions as
//! `DATLEN (u16) | HDRLEN (u8) | ATYP | ADDR | PORT | DATA`.

use super::blackhole::CountingSocketProtector;
use super::*;
use xray_proxy::inbound::{
    decode_socks5_udp_in_tcp_frame, encode_socks5_udp_in_tcp_frame, SocksUdpDatagram,
};

const USER: &[u8] = b"synthetic-user";
const PASS: &[u8] = b"synthetic-pass";
const LOGIN: &str = r#""auth": "password",
    "accounts": [{"user": "synthetic-user", "pass": "synthetic-pass"}]"#;
/// hev-socks5's `FWD_UDP` request: an all-zero IPv4 address and port.
const FWD_UDP_REQUEST: [u8; 10] = [5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
const FWD_UDP_GRANTED: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
/// The largest datagram an app sends through a 9,000-byte tun.
const TUN_LARGEST_DATAGRAM: usize = 9000 - 28;

async fn start_core(raw: &str) -> (Core, Arc<CountingSocketProtector>, SocketAddr) {
    let config = parse_xray_json(raw)
        .expect("synthetic FWD_UDP config parses")
        .config;
    let protector = Arc::new(CountingSocketProtector::default());
    let dialer = TransportDialer::system()
        .unwrap()
        .with_socket_protector(Arc::clone(&protector) as Arc<dyn xray_transport::SocketProtector>);
    let mut core = Core::with_transport_dialer_and_tun_options(
        config,
        Arc::new(dialer),
        TunRuntimeOptions::default(),
    )
    .unwrap();
    core.start().await.unwrap();
    let socks_addr = core.inbound_addr(Some("in")).unwrap();
    (core, protector, socks_addr)
}

fn freedom_config(udp: bool) -> String {
    format!(
        r#"{{
        "inbounds": [{{"tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": {{{LOGIN}, "udp": {udp}}}}}],
        "outbounds": [{{"tag": "direct", "protocol": "freedom"}}]
    }}"#
    )
}

/// Logs in and opens an association as hev-socks5-tunnel does.
async fn open_fwd_udp(socks_addr: SocketAddr) -> TcpStream {
    let mut control = TcpStream::connect(socks_addr).await.unwrap();
    control.set_nodelay(true).unwrap();
    assert_eq!(socks5_password_login(&mut control, USER, PASS).await, 0);
    control.write_all(&FWD_UDP_REQUEST).await.unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, FWD_UDP_GRANTED);
    control
}

fn udp_target(addr: SocketAddr) -> Target {
    Target::new(
        RoutingTargetAddr::Ip(addr.ip()),
        addr.port(),
        RoutingNetwork::Udp,
    )
}

fn frame(to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    encode_socks5_udp_in_tcp_frame(&udp_target(to), payload).unwrap()
}

async fn read_frame(control: &mut TcpStream, received: &mut BytesMut) -> SocksUdpDatagram {
    loop {
        if let Some(datagram) = decode_socks5_udp_in_tcp_frame(received).unwrap() {
            return datagram;
        }
        let read = control.read_buf(received).await.unwrap();
        assert_ne!(read, 0, "the association closed before the frame");
    }
}

async fn assert_no_frame(control: &mut TcpStream, received: &mut BytesMut, why: &str) {
    assert!(
        timeout(Duration::from_millis(300), read_frame(control, received))
            .await
            .is_err(),
        "{why}"
    );
}

/// Answers `size?` and a big-endian `u16` with that many bytes, `len?` with
/// the length of what it got as a big-endian `u32`, and echoes the rest.
async fn spawn_udp_reflector() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((len, peer)) = socket.recv_from(&mut buffer).await {
            let datagram = &buffer[..len];
            let reply = if let Some(size) = datagram.strip_prefix(b"size?") {
                vec![0x42; usize::from(u16::from_be_bytes([size[0], size[1]]))]
            } else if datagram.starts_with(b"len?") {
                u32::try_from(len).unwrap().to_be_bytes().to_vec()
            } else {
                datagram.to_vec()
            };
            let _ = socket.send_to(&reply, peer).await;
        }
    });
    (addr, handle)
}

fn size_request(size: usize) -> Vec<u8> {
    let mut request = b"size?".to_vec();
    request.extend_from_slice(&u16::try_from(size).unwrap().to_be_bytes());
    request
}

async fn wait_for_no_connections(core: &Core, why: &str) {
    let deadline = TokioInstant::now() + Duration::from_secs(2);
    while !core.connection_snapshot().connections.is_empty() {
        assert!(TokioInstant::now() < deadline, "{why}");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn fwd_udp_carries_framed_datagrams_both_ways_and_ends_with_its_connection() {
    timeout(Duration::from_secs(5), async {
        let (reflector, reflector_handle) = spawn_udp_reflector().await;
        let (mut core, _, socks_addr) = start_core(&freedom_config(true)).await;
        let mut control = open_fwd_udp(socks_addr).await;
        let mut received = BytesMut::new();

        // Several frames in one write, so in one read.
        let mut batch = Vec::new();
        for payload in [&b"one"[..], b"two", b"three"] {
            batch.extend(frame(reflector, payload));
        }
        control.write_all(&batch).await.unwrap();
        for payload in [&b"one"[..], b"two", b"three"] {
            let reply = read_frame(&mut control, &mut received).await;
            assert_eq!(reply.target, udp_target(reflector));
            assert_eq!(&reply.payload[..], payload);
        }

        // One frame cut inside its lengths, its address and its data.
        let split = frame(reflector, b"a frame in pieces");
        for piece in [&split[..2], &split[2..7], &split[7..14], &split[14..]] {
            control.write_all(piece).await.unwrap();
            sleep(Duration::from_millis(30)).await;
        }
        let reply = read_frame(&mut control, &mut received).await;
        assert_eq!(&reply.payload[..], b"a frame in pieces");

        // The largest datagram the tun hands over, in many reads.
        let mut largest = b"len?".to_vec();
        largest.resize(TUN_LARGEST_DATAGRAM, 0x17);
        control
            .write_all(&frame(reflector, &largest))
            .await
            .unwrap();
        let reply = read_frame(&mut control, &mut received).await;
        assert_eq!(
            reply.payload[..],
            u32::try_from(TUN_LARGEST_DATAGRAM).unwrap().to_be_bytes()
        );

        // One flow, under the inbound's tag, until the client closes.
        let snapshot = core.connection_snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].inbound_tag.as_deref(), Some("in"));
        assert_eq!(
            snapshot.connections[0].outbound_tag.as_deref(),
            Some("direct")
        );
        assert_eq!(snapshot.connections[0].target.port, reflector.port());
        drop(control);
        wait_for_no_connections(&core, "the association outlived its connection").await;

        core.stop().await.unwrap();
        reflector_handle.abort();
    })
    .await
    .unwrap();
}

/// hev-socks5-tunnel reads 1,500 bytes of address and data and stops reading
/// the association at a larger frame, so such a reply is dropped alone.
#[tokio::test]
async fn fwd_udp_drops_alone_a_reply_larger_than_hev_socks5_reads() {
    timeout(Duration::from_secs(5), async {
        let (reflector, reflector_handle) = spawn_udp_reflector().await;
        let (mut core, _, socks_addr) = start_core(&freedom_config(true)).await;
        let mut control = open_fwd_udp(socks_addr).await;
        let mut received = BytesMut::new();

        control
            .write_all(&frame(reflector, &size_request(1493)))
            .await
            .unwrap();
        let reply = read_frame(&mut control, &mut received).await;
        assert_eq!(reply.payload.len(), 1493, "an IPv4 reply hev-socks5 reads");

        control
            .write_all(&frame(reflector, &size_request(1494)))
            .await
            .unwrap();
        assert_no_frame(
            &mut control,
            &mut received,
            "a reply hev-socks5 cannot read must not be sent",
        )
        .await;

        control
            .write_all(&frame(reflector, b"still framed"))
            .await
            .unwrap();
        let reply = read_frame(&mut control, &mut received).await;
        assert_eq!(&reply.payload[..], b"still framed");

        drop(control);
        core.stop().await.unwrap();
        reflector_handle.abort();
    })
    .await
    .unwrap();
}

/// The app's shape: a port-53 rule sends the tun resolver's queries to the
/// DNS outbound, which answers from the fake-IP pool; a datagram to a fake
/// address then routes by its name, and its reply names the fake address.
#[tokio::test]
async fn fwd_udp_answers_dns_through_the_port_53_hijack_with_fake_ips() {
    timeout(Duration::from_secs(5), async {
        let (reflector, reflector_handle) = spawn_udp_reflector().await;
        let raw = format!(
            r#"{{
            "dns": {{"fakeIp": {{"enabled": true, "ipv4Pool": "198.18.0.0/15"}}}},
            "inbounds": [{{"tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
                "settings": {{{LOGIN}, "udp": true}},
                "sniffing": {{"enabled": true, "destOverride": ["http", "tls", "quic"]}}}}],
            "outbounds": [
                {{"tag": "direct", "protocol": "freedom"}},
                {{"tag": "named", "protocol": "freedom",
                  "settings": {{"redirect": "127.0.0.1:{reflector_port}"}}}},
                {{"tag": "dns-out", "protocol": "dns"}}
            ],
            "routing": {{"domainStrategy": "AsIs", "rules": [
                {{"type": "field", "inboundTag": ["in"], "network": "udp", "port": 53,
                  "outboundTag": "dns-out"}},
                {{"type": "field", "domain": ["full:fwd-udp.example"], "outboundTag": "named"}}
            ]}}
        }}"#,
            reflector_port = reflector.port()
        );
        let (mut core, protector, socks_addr) = start_core(&raw).await;
        let mut control = open_fwd_udp(socks_addr).await;
        let mut received = BytesMut::new();

        let resolver = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
        let query = build_dns_a_query(0x5ec7, "fwd-udp.example");
        control.write_all(&frame(resolver, &query)).await.unwrap();
        let answer = read_frame(&mut control, &mut received).await;
        assert_eq!(
            answer.target,
            udp_target(resolver),
            "the reply names the resolver"
        );
        assert_eq!(answer.payload[..2], query[..2]);
        let fake_ip = dns_response_answer_ipv4(&answer.payload).expect("an A answer");
        assert_eq!(
            u32::from(fake_ip) & 0xfffe_0000,
            u32::from(Ipv4Addr::new(198, 18, 0, 0)),
            "{fake_ip} is outside the fake-IP pool"
        );
        assert_eq!(protector.calls(), 0, "the hijacked query left the core");

        let fake = SocketAddr::from((fake_ip, 9));
        control.write_all(&frame(fake, b"by name")).await.unwrap();
        let reply = read_frame(&mut control, &mut received).await;
        assert_eq!(
            reply.target,
            udp_target(fake),
            "the reply names the fake address"
        );
        assert_eq!(&reply.payload[..], b"by name");
        let snapshot = core.connection_snapshot();
        assert!(snapshot
            .connections
            .iter()
            .any(|connection| connection.outbound_tag.as_deref() == Some("named")));

        drop(control);
        core.stop().await.unwrap();
        reflector_handle.abort();
    })
    .await
    .unwrap();
}

/// An answer from the DNS outbound that a hev-socks5 client could not read
/// whole is cut to an empty one with TC set, which sends the resolver to
/// TCP, instead of being dropped as any other oversize reply is.
#[tokio::test]
async fn fwd_udp_truncates_a_dns_answer_to_what_hev_socks5_reads() {
    timeout(Duration::from_secs(5), async {
        // 100 A records: a 1,641-byte answer, past the 1,493 bytes a frame
        // from an IPv4 address carries and within the 4,096 the query offers.
        let hosts = (1..=100)
            .map(|host| format!(r#""198.51.100.{host}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let raw = format!(
            r#"{{
            "dns": {{"hosts": {{"many.example": [{hosts}]}},
                     "fakeIp": {{"enabled": true, "ipv4Pool": "198.18.0.0/15"}}}},
            "inbounds": [{{"tag": "in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
                "settings": {{{LOGIN}, "udp": true}}}}],
            "outbounds": [
                {{"tag": "direct", "protocol": "freedom"}},
                {{"tag": "dns-out", "protocol": "dns"}}
            ],
            "routing": {{"rules": [
                {{"type": "field", "inboundTag": ["in"], "network": "udp", "port": 53,
                  "outboundTag": "dns-out"}}
            ]}}
        }}"#
        );
        let (mut core, protector, socks_addr) = start_core(&raw).await;
        let mut control = open_fwd_udp(socks_addr).await;
        let mut received = BytesMut::new();

        let resolver = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
        let mut query = build_dns_a_query(0x7c01, "many.example");
        // One additional record: EDNS's OPT, offering 4,096 bytes.
        query[10..12].copy_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
        control.write_all(&frame(resolver, &query)).await.unwrap();
        let answer = timeout(
            Duration::from_secs(2),
            read_frame(&mut control, &mut received),
        )
        .await
        .expect("the answer comes back, cut to what the client reads");
        assert_eq!(answer.target, udp_target(resolver));
        assert!(answer.payload.len() <= 1493, "{}", answer.payload.len());
        assert_eq!(answer.payload[..2], query[..2], "the query's id");
        assert_ne!(answer.payload[2] & 0x02, 0, "TC is set");
        assert_eq!(answer.payload[6..8], [0, 0], "no answer record");
        assert_eq!(protector.calls(), 0, "the hijacked query left the core");

        drop(control);
        core.stop().await.unwrap();
    })
    .await
    .unwrap();
}

/// `FWD_UDP` is a request on the control connection, so it goes no further
/// than the login: without one, with a wrong one, or under `"udp": false`
/// nothing is dialed. `UDP ASSOCIATE` for `0.0.0.0:0` stays refused.
#[tokio::test]
async fn fwd_udp_is_refused_without_the_login_and_with_udp_off() {
    timeout(Duration::from_secs(5), async {
        let (reflector, reflector_handle) = spawn_udp_reflector().await;
        let (mut core, protector, socks_addr) = start_core(&freedom_config(true)).await;
        let mut hev_session = FWD_UDP_REQUEST.to_vec();
        hev_session.extend(frame(reflector, b"must not leave"));

        let mut no_auth = TcpStream::connect(socks_addr).await.unwrap();
        no_auth.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        no_auth.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0xff], "no-auth must not be selected");
        let _ = no_auth.write_all(&hev_session).await;
        let mut rest = Vec::new();
        let _ = no_auth.read_to_end(&mut rest).await;
        assert!(rest.is_empty(), "nothing may follow the refusal");

        let mut wrong = TcpStream::connect(socks_addr).await.unwrap();
        assert_eq!(
            socks5_password_login(&mut wrong, USER, b"another-pass").await,
            0xff
        );
        let _ = wrong.write_all(&hev_session).await;
        let mut rest = Vec::new();
        let _ = wrong.read_to_end(&mut rest).await;
        assert!(rest.is_empty(), "nothing may follow a failed login");

        let mut undeclared = TcpStream::connect(socks_addr).await.unwrap();
        assert_eq!(socks5_password_login(&mut undeclared, USER, PASS).await, 0);
        undeclared
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0; 10];
        undeclared.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply,
            [5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
            "UDP ASSOCIATE without a declared port stays refused"
        );
        assert_eq!(protector.calls(), 0, "a refused request dialed");
        core.stop().await.unwrap();

        let (mut core, protector, socks_addr) = start_core(&freedom_config(false)).await;
        let mut udp_off = TcpStream::connect(socks_addr).await.unwrap();
        assert_eq!(socks5_password_login(&mut udp_off, USER, PASS).await, 0);
        udp_off.write_all(&hev_session).await.unwrap();
        let mut reply = [0; 10];
        udp_off.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 7, 0, 1, 0, 0, 0, 0, 0, 0], "udp: false");
        let mut rest = Vec::new();
        let _ = udp_off.read_to_end(&mut rest).await;
        assert!(rest.is_empty());
        assert_eq!(protector.calls(), 0, "udp: false dialed");
        core.stop().await.unwrap();
        reflector_handle.abort();
    })
    .await
    .unwrap();
}

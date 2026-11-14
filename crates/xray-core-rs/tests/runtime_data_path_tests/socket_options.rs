//! Freedom's `sockopt` on the UDP sockets the SOCKS inbound and TUN open
//! through it, and on DNS queries TUN forwards through it.

use super::*;

const SOCKS_IN: &str = r#"{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
    "port": 0, "settings": {"udp": true}}"#;
const TUN_IN: &str = r#"{"tag": "tun-in", "protocol": "tun"}"#;
/// An interface no host has: a socket bound to it fails, so nothing leaves.
const MISSING_INTERFACE: &str = r#"{"interface": "xray-missing0"}"#;

async fn start(inbound: &str, sockopt: &str, dns: &str) -> Core {
    let raw = format!(
        r#"{{
        "dns": {dns},
        "inbounds": [{inbound}],
        "outbounds": [{{"tag": "direct", "protocol": "freedom",
                        "streamSettings": {{"sockopt": {sockopt}}}}}]
    }}"#
    );
    let config = parse_xray_json(&raw)
        .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics))
        .config;
    let mut core = Core::new(config).unwrap();
    core.start().await.unwrap();
    core
}

/// Whether `server` receives a datagram within a short wait.
async fn arrives(server: &UdpSocket) -> bool {
    let mut buffer = [0; 2048];
    timeout(Duration::from_millis(500), server.recv_from(&mut buffer))
        .await
        .is_ok()
}

#[tokio::test]
async fn socks_udp_through_freedom_takes_its_socket_options() {
    for (sockopt, expected) in [("{}", true), (MISSING_INTERFACE, false)] {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut core = start(SOCKS_IN, sockopt, "{}").await;
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let mut control = TcpStream::connect(socks).await.unwrap();
        let relay = socks5_udp_associate(&mut control).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = Target::new(
            RoutingTargetAddr::Ip(server_addr.ip()),
            server_addr.port(),
            RoutingNetwork::Udp,
        );
        let request = encode_socks5_udp_datagram(&target, b"options").unwrap();
        client.send_to(&request, relay).await.unwrap();
        assert_eq!(arrives(&server).await, expected, "{sockopt}");
        drop(control);
        core.stop().await.unwrap();
    }
}

#[tokio::test]
async fn tun_udp_through_freedom_takes_its_socket_options() {
    for (sockopt, expected) in [("{}", true), (MISSING_INTERFACE, false)] {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        let mut core = start(TUN_IN, sockopt, "{}").await;
        let packet = ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            49_191,
            Ipv4Addr::LOCALHOST,
            port,
            b"options",
        );
        core.tun().push_inbound(Bytes::from(packet)).await.unwrap();
        assert_eq!(arrives(&server).await, expected, "{sockopt}");
        core.stop().await.unwrap();
    }
}

/// An option that fails without failing its dial is logged at info, as
/// Xray-core logs it: the line is written at `loglevel: info` and not at
/// `warning`, and the datagram still leaves.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[tokio::test]
async fn a_socket_option_that_fails_is_logged_at_info() {
    // An unknown type fails when the option is applied, on every platform.
    const FAILING: &str = r#"{"customSockopt": [{"opt": "1", "type": "bool"}]}"#;
    const LINE: &str = " info failed to apply socket options: unknown CustomSockopt type: bool";
    for (level, expected) in [("info", 1), ("warning", 0)] {
        let log_dir = create_runtime_log_temp_dir("xray-rust-sockopt-log");
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let raw = format!(
            r#"{{
            "log": {{"loglevel": "{level}"}},
            "inbounds": [{SOCKS_IN}],
            "outbounds": [{{"tag": "direct", "protocol": "freedom",
                            "streamSettings": {{"sockopt": {FAILING}}}}}]
        }}"#
        );
        let parsed = parse_xray_json(&raw)
            .unwrap_or_else(|error| panic!("{raw} should parse: {:?}", error.diagnostics));
        let mut core = Core::new(parsed.config).unwrap();
        core.set_runtime_logger(
            RuntimeLogger::new(RuntimeLogConfig::directory(&log_dir.path).with_log(parsed.log))
                .unwrap(),
        );
        core.start().await.unwrap();
        let socks = core.inbound_addr(Some("socks-in")).unwrap();
        let mut control = TcpStream::connect(socks).await.unwrap();
        let relay = socks5_udp_associate(&mut control).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = Target::new(
            RoutingTargetAddr::Ip(server_addr.ip()),
            server_addr.port(),
            RoutingNetwork::Udp,
        );
        let request = encode_socks5_udp_datagram(&target, b"options").unwrap();
        client.send_to(&request, relay).await.unwrap();
        assert!(arrives(&server).await, "{level}: the dial went on");
        drop(control);
        core.stop().await.unwrap();
        drop(core);

        // The log thread writes what is queued within its 100 ms flush.
        let error_log = log_dir.path.join("xray-error.log");
        let deadline = TokioInstant::now() + Duration::from_secs(2);
        let log = loop {
            let log = std::fs::read_to_string(&error_log).unwrap_or_default();
            if log.contains(LINE) || TokioInstant::now() >= deadline {
                break log;
            }
            sleep(Duration::from_millis(50)).await;
        };
        let failures = log
            .lines()
            .filter(|line| line.contains("failed to apply socket options"))
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), expected, "{level}: {log}");
        assert!(failures.iter().all(|line| line.contains(LINE)), "{log}");
    }
}

/// TUN answers an A or AAAA question through the resolver and forwards any
/// other one itself; both leave through freedom with its options.
#[tokio::test]
async fn tun_dns_queries_through_freedom_take_its_socket_options() {
    for (sockopt, expected, qtype) in [
        ("{}", true, 1),
        (MISSING_INTERFACE, false, 1),
        ("{}", true, 65),
        (MISSING_INTERFACE, false, 65),
    ] {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let dns = format!(r#"{{"servers": [{{"address": "127.0.0.1", "port": {port}}}]}}"#);
        let mut core = start(TUN_IN, sockopt, &dns).await;
        let query = build_dns_query(0x2420, "options.example", qtype, 1);
        let packet = ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            53_042,
            Ipv4Addr::new(198, 18, 0, 1),
            53,
            &query,
        );
        core.tun().push_inbound(Bytes::from(packet)).await.unwrap();
        assert_eq!(arrives(&upstream).await, expected, "{sockopt} {qtype}");
        core.stop().await.unwrap();
    }
}

//! The access log's lines for the SOCKS inbound: written whenever `access`
//! names a log, whatever the `loglevel`, with the source and the destination
//! address redacted.

use super::*;

const SOCKS_IN: &str = r#"{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
    "port": 0, "settings": {"udp": true}}"#;

/// A SOCKS connection and a SOCKS UDP flow each write their accepted line at
/// `loglevel: warning`, where no debug line is written: the work for an
/// access line is gated on access lines, not on debug ones.
#[tokio::test]
async fn socks_connections_and_udp_flows_write_access_lines_at_warning() {
    let log_dir = create_runtime_log_temp_dir("xray-rust-socks-access-log");
    let raw = format!(
        r#"{{
        "log": {{"loglevel": "warning", "access": "/var/log/xray/access.log"}},
        "inbounds": [{SOCKS_IN}],
        "outbounds": [{{"tag": "direct", "protocol": "freedom"}}]
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

    let (tcp_server, tcp_handle) = spawn_echo_server().await;
    let mut client = TcpStream::connect(socks).await.unwrap();
    socks5_connect(&mut client, tcp_server).await;
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    drop(client);

    let (udp_server, udp_handle) = spawn_udp_echo_server().await;
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(&mut control).await;
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(udp_server.ip()),
        udp_server.port(),
        RoutingNetwork::Udp,
    );
    let request = encode_socks5_udp_datagram(&target, b"pong").unwrap();
    udp_client.send_to(&request, relay).await.unwrap();
    let mut buffer = [0; 2048];
    timeout(Duration::from_secs(2), udp_client.recv_from(&mut buffer))
        .await
        .expect("the datagram comes back")
        .unwrap();
    drop(control);
    core.stop().await.unwrap();
    drop(core);
    tcp_handle.abort();
    udp_handle.abort();

    let accepted = |server: SocketAddr| {
        format!(
            " access from <redacted-source> accepted <redacted-ip>:{} outbound=freedom",
            server.port()
        )
    };
    let (tcp_line, udp_line) = (accepted(tcp_server), accepted(udp_server));
    // The log thread writes what is queued within its 100 ms flush.
    let access_log = log_dir.path.join("xray-access.log");
    let deadline = TokioInstant::now() + Duration::from_secs(2);
    let log = loop {
        let log = std::fs::read_to_string(&access_log).unwrap_or_default();
        let both = log.contains(&tcp_line) && log.contains(&udp_line);
        if both || TokioInstant::now() >= deadline {
            break log;
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert!(log.contains(&tcp_line), "the connection's line: {log}");
    assert!(log.contains(&udp_line), "the flow's line: {log}");
    assert!(!log.contains("127.0.0.1"), "{log}");
}

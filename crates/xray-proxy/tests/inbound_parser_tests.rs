// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
use bytes::BytesMut;
use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_proxy::inbound::{
    decode_http_basic_credentials, decode_socks5_udp_in_tcp_frame, encode_socks5_udp_datagram,
    encode_socks5_udp_in_tcp_frame, negotiate_socks5, negotiate_socks5_no_auth, parse_http_connect,
    parse_http_connect_request, parse_socks4_connect, parse_socks5_connect, parse_socks5_request,
    parse_socks5_request_message, parse_socks5_udp_datagram, read_socks5_command,
    read_socks5_target, socks5_udp_in_tcp_max_reply, write_socks5_command_not_supported,
    write_socks5_failure, write_socks5_success, write_socks5_success_with_bind,
    HttpInboundAccounts, HttpParseError, SocksAccount, SocksCommand, SocksInboundAuth,
    SocksParseError, SocksUdpDatagram, MAX_SOCKS_CREDENTIAL_LENGTH,
    SOCKS5_UDP_IN_TCP_CLIENT_BUFFER,
};
use xray_routing::{Network, Target, TargetAddr};

#[derive(Debug)]
struct CountingIo {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_calls: usize,
    write_calls: usize,
}

impl CountingIo {
    fn new(input: impl Into<Vec<u8>>) -> Self {
        Self {
            input: Cursor::new(input.into()),
            output: Vec::new(),
            read_calls: 0,
            write_calls: 0,
        }
    }
}

impl AsyncRead for CountingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.read_calls += 1;
        let source = self.input.get_ref();
        let start = self.input.position() as usize;
        if start >= source.len() {
            return Poll::Ready(Ok(()));
        }

        let len = buf.remaining().min(source.len() - start);
        buf.put_slice(&source[start..start + len]);
        self.input.set_position((start + len) as u64);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CountingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_calls += 1;
        self.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn socks5_negotiate_no_auth_writes_method_selection() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5_no_auth(server).await });

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0]);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks5_negotiate_rejects_when_no_auth_is_absent() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5_no_auth(server).await });

    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0xff]);
    assert_eq!(
        server_task.await.unwrap(),
        Err(SocksParseError::NoAcceptableMethods)
    );
}

fn password_auth() -> SocksInboundAuth {
    SocksInboundAuth::Password(vec![
        SocksAccount::new(b"first-user", b"first-pass").unwrap(),
        SocksAccount::new(b"synthetic-user", b"synthetic-pass").unwrap(),
    ])
}

fn password_request(user: &[u8], pass: &[u8]) -> Vec<u8> {
    let mut request = vec![1, u8::try_from(user.len()).unwrap()];
    request.extend_from_slice(user);
    request.push(u8::try_from(pass.len()).unwrap());
    request.extend_from_slice(pass);
    request
}

#[tokio::test]
async fn socks5_password_auth_accepts_any_configured_account() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

    client.write_all(&[5, 2, 0, 2]).await.unwrap();
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 2]);

    client
        .write_all(&password_request(b"synthetic-user", b"synthetic-pass"))
        .await
        .unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).await.unwrap();

    assert_eq!(status, [1, 0]);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks5_password_auth_rejects_wrong_credentials() {
    let attempts: [(&[u8], &[u8]); 3] = [
        (b"synthetic-user", b"wrong-pass"),
        (b"wrong-user", b"synthetic-pass"),
        (b"first-user", b"synthetic-pass"),
    ];
    for (user, pass) in attempts {
        let (mut client, server) = tokio::io::duplex(64);
        let server_task =
            tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selection = [0; 2];
        client.read_exact(&mut selection).await.unwrap();
        client
            .write_all(&password_request(user, pass))
            .await
            .unwrap();
        let mut status = [0; 2];
        client.read_exact(&mut status).await.unwrap();

        // Xray-core answers a failed login with 0xFF.
        assert_eq!(status, [1, 0xff]);
        assert_eq!(
            server_task.await.unwrap(),
            Err(SocksParseError::AuthenticationFailed)
        );
    }
}

#[tokio::test]
async fn socks5_password_auth_never_selects_no_auth() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();

    assert_eq!(reply, [5, 0xff]);
    assert_eq!(
        server_task.await.unwrap(),
        Err(SocksParseError::NoAcceptableMethods)
    );
}

#[tokio::test]
async fn socks5_password_auth_ignores_the_subnegotiation_version() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { negotiate_socks5(server, &password_auth()).await });

    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await.unwrap();
    // Xray-core does not check the version byte.
    let mut request = password_request(b"synthetic-user", b"synthetic-pass");
    request[0] = 5;
    client.write_all(&request).await.unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).await.unwrap();

    assert_eq!(status, [1, 0]);
    assert!(server_task.await.unwrap().is_ok());
}

#[tokio::test]
async fn socks5_password_auth_fails_on_truncated_credentials() {
    let mut stream = CountingIo::new([5, 1, 2, 1, 14, b's', b'y', b'n']);

    assert_eq!(
        negotiate_socks5(&mut stream, &password_auth()).await,
        Err(SocksParseError::Io)
    );
    assert_eq!(stream.output, [5, 2]);
}

#[test]
fn socks_accounts_enforce_rfc1929_lengths_and_redact_debug() {
    let longest = vec![b'a'; MAX_SOCKS_CREDENTIAL_LENGTH];
    let too_long = vec![b'a'; MAX_SOCKS_CREDENTIAL_LENGTH + 1];
    assert!(SocksAccount::new(&longest, &longest).is_some());
    // Xray-core keeps empty credentials, which the wire can carry.
    assert!(SocksAccount::new(b"", b"").is_some());
    assert!(SocksAccount::new(&too_long, b"synthetic-pass").is_none());
    assert!(SocksAccount::new(b"synthetic-user", &too_long).is_none());

    let debug = format!("{:?}", password_auth());
    assert!(!debug.contains("synthetic"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

#[tokio::test]
async fn socks5_negotiate_no_auth_reads_greeting_with_two_io_reads() {
    let mut stream = CountingIo::new([5, 2, 2, 0]);

    negotiate_socks5_no_auth(&mut stream).await.unwrap();

    assert_eq!(stream.read_calls, 2);
    assert_eq!(stream.write_calls, 1);
    assert_eq!(stream.output, [5, 0]);
}

#[tokio::test]
async fn socks5_request_parser_reads_ipv4_request_with_three_io_reads() {
    let mut reader = CountingIo::new([5, 1, 0, 1, 192, 0, 2, 1, 0, 80]);

    let request = parse_socks5_request_message(&mut reader).await.unwrap();

    assert_eq!(request.command, SocksCommand::Connect);
    assert_eq!(request.target.port, 80);
    assert_eq!(
        request.target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
    // The command is read before the address, so it can be refused first.
    assert_eq!(reader.read_calls, 3);
}

#[tokio::test]
async fn socks5_request_parser_reads_connect_after_greeting() {
    let bytes = [
        5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
        0xbb,
    ];

    let target = parse_socks5_request(&bytes[..]).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn socks5_request_parser_reads_udp_associate_command() {
    let bytes = [5, 3, 0, 1, 0, 0, 0, 0, 0, 0];

    let request = parse_socks5_request_message(&bytes[..]).await.unwrap();

    assert_eq!(request.command, SocksCommand::UdpAssociate);
    assert_eq!(request.target.network, Network::Udp);
    assert_eq!(request.target.port, 0);
    assert_eq!(
        request.target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    );
}

#[tokio::test]
async fn socks5_reply_writers_emit_ipv4_success_and_failure() {
    let mut output = Vec::new();

    write_socks5_success(&mut output).await.unwrap();
    write_socks5_failure(&mut output).await.unwrap();
    write_socks5_command_not_supported(&mut output)
        .await
        .unwrap();

    assert_eq!(
        output,
        vec![
            5, 0, 0, 1, 0, 0, 0, 0, 0, 0, // success
            5, 1, 0, 1, 0, 0, 0, 0, 0, 0, // general failure
            5, 7, 0, 1, 0, 0, 0, 0, 0, 0, // command not supported, as Xray-core sends it
        ]
    );
}

#[tokio::test]
async fn socks5_success_writer_can_emit_bound_udp_address() {
    let mut output = Vec::new();
    let bind = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 53000));

    write_socks5_success_with_bind(&mut output, bind)
        .await
        .unwrap();

    assert_eq!(output, vec![5, 0, 0, 1, 127, 0, 0, 1, 0xcf, 0x08]);
}

#[test]
fn socks5_udp_datagram_round_trips_ipv4_target() {
    let target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        5353,
        Network::Udp,
    );

    let encoded = encode_socks5_udp_datagram(&target, b"dns-ish").unwrap();
    let decoded = parse_socks5_udp_datagram(&encoded).unwrap();

    assert_eq!(decoded.target, target);
    assert_eq!(&decoded.payload[..], b"dns-ish");
}

#[tokio::test]
async fn parses_socks5_connect_domain_target() {
    let (mut client, server) = tokio::io::duplex(64);
    let server_task = tokio::spawn(async move { parse_socks5_connect(server).await });

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);

    client
        .write_all(&[
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ])
        .await
        .unwrap();

    let target = server_task.await.unwrap().unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn parses_socks5_request_ipv4_target() {
    let bytes = [0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x00, 0x50];

    let target = parse_socks5_request(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 80);
    assert_eq!(
        target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
    );
}

#[tokio::test]
async fn parses_socks5_request_ipv6_target() {
    let bytes = [
        0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xbb,
    ];

    let target = parse_socks5_request(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.network, Network::Tcp);
    assert_eq!(target.port, 443);
    assert_eq!(
        target.addr,
        TargetAddr::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
    );
}

#[tokio::test]
async fn rejects_socks5_unsupported_command() {
    let bytes = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::UnsupportedCommand(0x02));
}

#[tokio::test]
async fn socks5_requests_ignore_their_version_and_reserved_bytes() {
    // Xray-core checks only the command byte.
    let bytes = [
        0x04, 0x01, 0x01, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x01, 0xbb,
    ];

    let target = parse_socks5_request(Cursor::new(bytes)).await.unwrap();

    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn rejects_socks5_unsupported_address_type() {
    let bytes = [0x05, 0x01, 0x00, 0x05];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::UnsupportedAddressType(0x05));
}

#[tokio::test]
async fn rejects_socks5_empty_domain() {
    let bytes = [0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xbb];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::InvalidDomain);
}

#[tokio::test]
async fn rejects_socks5_invalid_utf8_domain() {
    let bytes = [0x05, 0x01, 0x00, 0x03, 0x01, 0xff, 0x01, 0xbb];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::InvalidDomain);
}

#[tokio::test]
async fn rejects_socks5_truncated_input_as_io() {
    let bytes = [0x05, 0x01, 0x00, 0x01, 127, 0, 0];

    let err = parse_socks5_request(Cursor::new(bytes)).await.unwrap_err();

    assert_eq!(err, SocksParseError::Io);
}

#[tokio::test]
async fn parses_http_connect_domain_target() {
    let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
}

#[tokio::test]
async fn parses_http_connect_consumes_headers_before_payload() {
    let mut input = Cursor::new(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\npayload".to_vec(),
    );

    let target = parse_http_connect(&mut input).await.unwrap();
    let mut remaining = Vec::new();
    input.read_to_end(&mut remaining).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Domain("example.com".to_owned()));
    assert_eq!(remaining, b"payload");
}

#[tokio::test]
async fn parses_http_connect_ipv4_literal_target() {
    let raw = b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 8080);
    assert_eq!(
        target.addr,
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    );
}

#[tokio::test]
async fn parses_http_connect_bracketed_ipv6_literal_target() {
    let raw = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 443);
    assert_eq!(target.addr, TargetAddr::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[tokio::test]
async fn rejects_http_non_connect_method() {
    let raw = b"GET example.com:443 HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::NotConnect);
}

#[tokio::test]
async fn rejects_http_invalid_port() {
    let raw = b"CONNECT example.com:https HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::InvalidPort);
}

#[tokio::test]
async fn rejects_http_overlong_request_line() {
    let raw = format!("CONNECT {}:443 HTTP/1.1\r\n\r\n", "a".repeat(8192));

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::LineTooLong);
}

#[tokio::test]
async fn rejects_http_empty_host() {
    let raw = b"CONNECT :443 HTTP/1.1\r\n\r\n";

    let err = parse_http_connect(Cursor::new(raw)).await.unwrap_err();

    assert_eq!(err, HttpParseError::InvalidAuthority);
}

#[tokio::test]
async fn keeps_http_port_zero_to_fail_when_dialed() {
    // As in Xray-core, which answers it and then fails to dial it.
    let raw = b"CONNECT example.com:0 HTTP/1.1\r\n\r\n";

    let target = parse_http_connect(Cursor::new(raw)).await.unwrap();

    assert_eq!(target.port, 0);
}

/// A SOCKS 4 request after its version byte.
fn socks4_body(command: u8, port: u16, ip: [u8; 4], user: &[u8], domain: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![command];
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&ip);
    body.extend_from_slice(user);
    body.push(0);
    if let Some(domain) = domain {
        body.extend_from_slice(domain);
        body.push(0);
    }
    body
}

#[tokio::test]
async fn parses_socks4_and_socks4a_connect_like_xray() {
    let target = |body: Vec<u8>| async move { parse_socks4_connect(Cursor::new(body)).await };
    assert_eq!(
        target(socks4_body(1, 443, [192, 0, 2, 7], b"user-id", None)).await,
        Ok(Target::new(
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
            443,
            Network::Tcp
        ))
    );
    // Any address with a zero first byte announces a 4a domain.
    assert_eq!(
        target(socks4_body(1, 80, [0, 0, 0, 9], b"", Some(b"example.test"))).await,
        Ok(Target::new(
            TargetAddr::Domain("example.test".to_owned()),
            80,
            Network::Tcp
        ))
    );
    // Go's ParseAddress turns a literal into an IP target.
    assert_eq!(
        target(socks4_body(1, 80, [0, 0, 0, 1], b"", Some(b"2001:db8::1"))).await,
        Ok(Target::new(
            TargetAddr::Ip("2001:db8::1".parse().unwrap()),
            80,
            Network::Tcp
        ))
    );
    for (body, error) in [
        (
            socks4_body(2, 80, [192, 0, 2, 7], b"", None),
            SocksParseError::UnsupportedCommand(2),
        ),
        (
            socks4_body(1, 80, [0, 0, 0, 1], b"", Some(b"")),
            SocksParseError::InvalidDomain,
        ),
        (
            socks4_body(1, 80, [0, 0, 0, 1], b"", Some(b"\xff\xfe")),
            SocksParseError::InvalidDomain,
        ),
        (
            socks4_body(1, 80, [192, 0, 2, 7], &[b'u'; 256], None),
            SocksParseError::InvalidDomain,
        ),
        (vec![1, 0, 80, 192, 0, 2, 7, b'u'], SocksParseError::Io),
    ] {
        assert_eq!(target(body.clone()).await, Err(error), "{body:?}");
    }
    assert!(
        target(socks4_body(1, 80, [192, 0, 2, 7], &[b'u'; 255], None))
            .await
            .is_ok()
    );
}

#[test]
fn decodes_http_basic_credentials_like_go() {
    let decoded = |value: &[u8]| {
        decode_http_basic_credentials(value).map(|(user, pass)| (user.to_vec(), pass.to_vec()))
    };
    assert_eq!(
        decoded(b"Basic dXNlcjpwYXNz"),
        Some((b"user".to_vec(), b"pass".to_vec()))
    );
    // Split at the first colon; empty halves are Go's result too.
    assert_eq!(
        decoded(b"Basic dXNlcjpwOmFzcw=="),
        Some((b"user".to_vec(), b"p:ass".to_vec()))
    );
    assert_eq!(decoded(b"Basic Og=="), Some((Vec::new(), Vec::new())));
    for refused in [
        &b"basic dXNlcjpwYXNz"[..],
        b"Bearer dXNlcjpwYXNz",
        b"Basic dXNlcjpwYXNz=",
        b"Basic dXNlcnBhc3M=",
        b"Basic ",
    ] {
        assert_eq!(
            decoded(refused),
            None,
            "{:?}",
            String::from_utf8_lossy(refused)
        );
    }
}

#[tokio::test]
async fn http_connect_keeps_the_first_proxy_authorization() {
    // Go's `Header.Get` returns a header's first value.
    let request = parse_http_connect_request(Cursor::new(
        b"CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization:\tBasic dXNlcjpwYXNz \r\nPROXY-AUTHORIZATION: Basic Zmlyc3Q6Zmlyc3Q=\r\nHost: example.test:443\r\n\r\n".to_vec(),
    ))
    .await
    .unwrap();
    assert_eq!(
        request.proxy_authorization.as_deref().map(Vec::as_slice),
        Some(&b"Basic dXNlcjpwYXNz"[..])
    );
    let auth = SocksInboundAuth::Password(vec![SocksAccount::new(b"user", b"pass").unwrap()]);
    let accounts = HttpInboundAccounts::from(&auth);
    let user = accounts
        .basic_user(request.proxy_authorization.as_deref().map(Vec::as_slice))
        .expect("the first credentials are admitted")
        .expect("an account names the user");
    assert_eq!(user.as_str(), "user");
    assert!(accounts
        .basic_user(Some(b"Basic Zmlyc3Q6Zmlyc3Q="))
        .is_none());
    assert!(accounts.basic_user(None).is_none());
    let none = HttpInboundAccounts::from(&SocksInboundAuth::NoAuth);
    assert!(matches!(none.basic_user(None), Some(None)));

    let anonymous = parse_http_connect_request(Cursor::new(
        b"CONNECT example.test:443 HTTP/1.1\r\n\r\n".to_vec(),
    ))
    .await
    .unwrap();
    assert_eq!(anonymous.proxy_authorization, None);
}

#[test]
fn http_accounts_keep_one_password_per_name() {
    // As Xray-core's accounts map: the later password replaces the earlier.
    let mut accounts = HttpInboundAccounts::default();
    accounts.insert(b"a", b"old");
    accounts.insert(b"a", b"new");
    accounts.insert(b"", b"");
    assert!(accounts.basic_user(Some(b"Basic YTpvbGQ=")).is_none());
    assert!(accounts.basic_user(Some(b"Basic YTpuZXc=")).is_some());
    // Empty names and passwords are accounts too.
    assert!(accounts.basic_user(Some(b"Basic Og==")).is_some());
    assert_eq!(
        format!("{accounts:?}"),
        "HttpInboundAccounts { accounts: 2 }"
    );
}

#[tokio::test]
async fn http_requests_read_as_go_reads_them() {
    let target = |raw: &'static [u8]| async move {
        parse_http_connect_request(Cursor::new(raw.to_vec()))
            .await
            .map(|request| request.target)
    };
    let domain = |name: &str, port| {
        Ok(Some(Target::new(
            TargetAddr::Domain(name.to_owned()),
            port,
            Network::Tcp,
        )))
    };
    // A missing or empty port is port 80, a long one is cut to 16 bits.
    assert_eq!(
        target(b"CONNECT example.com HTTP/1.1\r\n\r\n").await,
        domain("example.com", 80)
    );
    assert_eq!(
        target(b"CONNECT example.com: HTTP/1.1\r\n\r\n").await,
        domain("example.com", 80)
    );
    assert_eq!(
        target(b"CONNECT [::1] HTTP/1.1\r\n\r\n").await,
        Ok(Some(Target::new(
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            80,
            Network::Tcp
        )))
    );
    assert_eq!(
        target(b"CONNECT example.com:70000 HTTP/1.1\r\n\r\n").await,
        domain("example.com", 4464)
    );
    // Versions Go reads, and headers written with `\n` alone.
    assert_eq!(
        target(b"CONNECT example.com:443 HTTP/2.0\r\n\r\n").await,
        domain("example.com", 443)
    );
    assert_eq!(
        target(b"CONNECT example.com:443 HTTP/1.1\nHost: x\n\n").await,
        domain("example.com", 443)
    );
    // A name with a space before its colon is kept, uncanonicalized.
    assert_eq!(
        target(b"CONNECT example.com:443 HTTP/1.1\r\nHost : x\r\n\r\n").await,
        domain("example.com", 443)
    );
    // Another method has no target here.
    assert_eq!(
        target(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await,
        Ok(None)
    );
    assert_eq!(
        target(b"connect example.com:443 HTTP/1.1\r\n\r\n").await,
        Ok(None)
    );

    for (raw, error) in [
        (
            &b"CONNECT example.com:443\r\n\r\n"[..],
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/10.0\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1 x\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT  example.com:443 HTTP/1.1\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (b"\x01\x02garbage\r\n\r\n", HttpParseError::Malformed),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nNoColon\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\n: x\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nBad\x01Name: x\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\n folded\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n",
            HttpParseError::Malformed,
        ),
        (
            b"CONNECT example.com:+80 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidPort,
        ),
        (
            b"CONNECT example.com:99999999999999999999 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidPort,
        ),
        (
            b"CONNECT ::1:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
        (
            b"CONNECT exa%41mple.com:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
        (
            b"CONNECT exa[mple.com:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
        (
            b"CONNECT [::1]x:443 HTTP/1.1\r\n\r\n",
            HttpParseError::InvalidAuthority,
        ),
    ] {
        assert_eq!(
            parse_http_connect_request(Cursor::new(raw.to_vec())).await,
            Err(error),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

/// The target of a SOCKS5 `CONNECT` to the domain `name`.
async fn socks5_domain_target(name: &[u8]) -> Result<Target, SocksParseError> {
    let mut request = vec![5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
    request.extend_from_slice(name);
    request.extend_from_slice(&443_u16.to_be_bytes());
    parse_socks5_request(&request[..]).await
}

fn ip(text: &str) -> Result<TargetAddr, SocksParseError> {
    Ok(TargetAddr::Ip(text.parse().unwrap()))
}

fn domain(text: &str) -> Result<TargetAddr, SocksParseError> {
    Ok(TargetAddr::Domain(text.to_owned()))
}

#[tokio::test]
async fn socks5_domains_read_as_xray_core_reads_them() {
    for (name, expected) in [
        // A name that starts with a digit or `[` and is an IP literal to Go's
        // net.ParseAddress is that IP.
        (b"192.0.2.7".as_slice(), ip("192.0.2.7")),
        (b"[2001:db8::1]", ip("2001:db8::1")),
        (b"[192.0.2.7]", ip("192.0.2.7")),
        (b"2001:db8::1", ip("2001:db8::1")),
        (b"0::ffff:192.0.2.7", ip("192.0.2.7")),
        (b"192.0.2.7 ", ip("192.0.2.7")),
        (b"192.0.2.7\t\n", ip("192.0.2.7")),
        // Other names keep to letters, digits, `-`, `.` and `_`.
        (b"1password.example", domain("1password.example")),
        (b"Under_Score-1.example.", domain("Under_Score-1.example.")),
        (b"192.0.2.256", domain("192.0.2.256")),
        (b"::1", Err(SocksParseError::InvalidDomain)),
        (b" 192.0.2.7", Err(SocksParseError::InvalidDomain)),
        (b"[example.com]", Err(SocksParseError::InvalidDomain)),
        (b"[]", Err(SocksParseError::InvalidDomain)),
        (b"exa mple.com", Err(SocksParseError::InvalidDomain)),
        (b"example.com:443", Err(SocksParseError::InvalidDomain)),
        (b"a/b", Err(SocksParseError::InvalidDomain)),
        (
            "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}".as_bytes(),
            Err(SocksParseError::InvalidDomain),
        ),
        (b"\xff.example", Err(SocksParseError::InvalidDomain)),
    ] {
        let target = socks5_domain_target(name).await.map(|target| target.addr);
        assert_eq!(target, expected, "{}", String::from_utf8_lossy(name));
    }
}

#[tokio::test]
async fn socks5_ipv4_mapped_addresses_read_as_ipv4() {
    let mut request = vec![5, 1, 0, 4];
    request.extend_from_slice(&"::ffff:192.0.2.7".parse::<Ipv6Addr>().unwrap().octets());
    request.extend_from_slice(&80_u16.to_be_bytes());
    let target = parse_socks5_request(&request[..]).await.unwrap();
    assert_eq!(Ok(target.addr), ip("192.0.2.7"));

    let mut datagram = vec![0, 0, 0, 4];
    datagram.extend_from_slice(&"::ffff:192.0.2.7".parse::<Ipv6Addr>().unwrap().octets());
    datagram.extend_from_slice(&53_u16.to_be_bytes());
    datagram.extend_from_slice(b"payload");
    let decoded = parse_socks5_udp_datagram(&datagram).unwrap();
    assert_eq!(Ok(decoded.target.addr), ip("192.0.2.7"));
}

#[tokio::test]
async fn socks5_tor_resolve_commands_read_as_connect() {
    for command in [0xf0, 0xf1] {
        let bytes = [5, command, 0, 1, 192, 0, 2, 7, 0, 80];
        let request = parse_socks5_request_message(&bytes[..]).await.unwrap();
        assert_eq!(request.command, SocksCommand::Connect);
        assert_eq!(request.target.network, Network::Tcp);
    }
}

#[tokio::test]
async fn socks5_commands_are_refused_before_their_address() {
    // BIND and unknown commands fail on the three bytes before the address.
    for command in [2, 4, 0xff] {
        let mut reader = CountingIo::new([5, command, 0]);
        assert_eq!(
            read_socks5_command(&mut reader).await,
            Err(SocksParseError::UnsupportedCommand(command))
        );
    }
    let mut reader = CountingIo::new([5, 3, 0]);
    assert_eq!(
        read_socks5_command(&mut reader).await,
        Ok(SocksCommand::UdpAssociate)
    );
    let mut reader = CountingIo::new([1, 192, 0, 2, 7, 0, 53]);
    let target = read_socks5_target(&mut reader, SocksCommand::UdpAssociate)
        .await
        .unwrap();
    assert_eq!(target.network, Network::Udp);
}

/// hev-socks5's `FWD_UDP` request as its client sends it: an all-zero
/// IPv4 address and port.
#[tokio::test]
async fn socks5_fwd_udp_reads_as_udp_in_tcp() {
    let request = [5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
    let request = parse_socks5_request_message(&request[..]).await.unwrap();
    assert_eq!(request.command, SocksCommand::UdpInTcp);
    assert_eq!(request.target.network, Network::Udp);
    assert_eq!(request.target.port, 0);
}

fn udp_target(addr: Result<TargetAddr, SocksParseError>, port: u16) -> Target {
    Target::new(addr.unwrap(), port, Network::Udp)
}

/// One frame for each address type, laid out as hev-socks5-core writes its
/// `HevSocks5UDPHdr` (`hev-socks5-udp.c` at `162dd996`).
#[test]
fn socks5_udp_in_tcp_frames_lay_out_as_hev_socks5_writes_them() {
    let ipv4 = udp_target(ip("192.0.2.53"), 53);
    assert_eq!(
        encode_socks5_udp_in_tcp_frame(&ipv4, b"abc").unwrap(),
        [0, 3, 10, 1, 192, 0, 2, 53, 0, 53, b'a', b'b', b'c']
    );
    let ipv6 = udp_target(ip("2001:db8::1"), 443);
    let frame = encode_socks5_udp_in_tcp_frame(&ipv6, b"q").unwrap();
    assert_eq!(frame[..4], [0, 1, 22, 4]);
    assert_eq!(frame[20..], [1, 187, b'q']);
    let name = udp_target(domain("example.com"), 443);
    let frame = encode_socks5_udp_in_tcp_frame(&name, b"").unwrap();
    assert_eq!(frame[..5], [0, 0, 18, 3, 11]);
    assert_eq!(&frame[5..16], b"example.com");
    assert_eq!(frame[16..], [1, 187]);

    let tcp = Target::new(
        TargetAddr::Domain("example.com".to_owned()),
        443,
        Network::Tcp,
    );
    assert_eq!(
        encode_socks5_udp_in_tcp_frame(&tcp, b"x"),
        Err(SocksParseError::InvalidUdpFrame)
    );
}

/// Frames split by the reads that carry them, a byte at a time, and several
/// arriving in one read come out whole, in order, and only once complete.
#[test]
fn socks5_udp_in_tcp_frames_survive_split_and_joined_reads() {
    let datagrams = [
        (udp_target(ip("192.0.2.53"), 53), b"first query".to_vec()),
        (udp_target(ip("2001:db8::1"), 443), vec![0x5a; 1200]),
        (udp_target(domain("example.com"), 3478), b"".to_vec()),
        (udp_target(ip("192.0.2.7"), 9), b"last".to_vec()),
    ];
    let mut stream = Vec::new();
    for (target, payload) in &datagrams {
        stream.extend(encode_socks5_udp_in_tcp_frame(target, payload).unwrap());
    }
    let expected: Vec<SocksUdpDatagram> = datagrams
        .iter()
        .map(|(target, payload)| SocksUdpDatagram {
            target: target.clone(),
            payload: payload.clone().into(),
        })
        .collect();

    // A byte at a time: nothing until a frame's last byte.
    let mut buffer = BytesMut::new();
    let mut decoded = Vec::new();
    for (index, byte) in stream.iter().enumerate() {
        buffer.extend_from_slice(&[*byte]);
        while let Some(datagram) = decode_socks5_udp_in_tcp_frame(&mut buffer).unwrap() {
            decoded.push((index, datagram));
        }
    }
    let mut end = 0;
    let ends: Vec<usize> = datagrams
        .iter()
        .map(|(target, payload)| {
            end += encode_socks5_udp_in_tcp_frame(target, payload)
                .unwrap()
                .len();
            end - 1
        })
        .collect();
    assert_eq!(
        decoded.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        ends
    );
    assert_eq!(
        decoded
            .into_iter()
            .map(|(_, datagram)| datagram)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(buffer.is_empty());

    // Every frame in one read, then the last frame cut in two.
    let mut buffer = BytesMut::from(&stream[..stream.len() - 2]);
    let mut decoded = Vec::new();
    while let Some(datagram) = decode_socks5_udp_in_tcp_frame(&mut buffer).unwrap() {
        decoded.push(datagram);
    }
    assert_eq!(decoded, expected[..3]);
    assert_eq!(buffer.len(), 12, "the last frame's first twelve bytes wait");
    buffer.extend_from_slice(&stream[stream.len() - 2..]);
    assert_eq!(
        decode_socks5_udp_in_tcp_frame(&mut buffer).unwrap(),
        Some(expected[3].clone())
    );
    assert_eq!(decode_socks5_udp_in_tcp_frame(&mut buffer).unwrap(), None);
}

/// `DATLEN` carries up to 65,535 bytes and `HDRLEN` a domain of up to 248;
/// a hev-socks5 client reads at most 1,500 bytes of address and data.
#[test]
fn socks5_udp_in_tcp_frames_carry_the_largest_datagram() {
    let target = udp_target(ip("192.0.2.7"), 4500);
    let largest = vec![0xa5; usize::from(u16::MAX)];
    let frame = encode_socks5_udp_in_tcp_frame(&target, &largest).unwrap();
    assert_eq!(frame.len(), 10 + largest.len());
    let mut buffer = BytesMut::from(&frame[..frame.len() - 1]);
    assert_eq!(decode_socks5_udp_in_tcp_frame(&mut buffer).unwrap(), None);
    assert!(buffer.capacity() >= frame.len());
    buffer.extend_from_slice(&frame[frame.len() - 1..]);
    let datagram = decode_socks5_udp_in_tcp_frame(&mut buffer)
        .unwrap()
        .unwrap();
    assert_eq!(datagram.target, target);
    assert_eq!(datagram.payload.len(), largest.len());
    assert!(buffer.is_empty());
    assert_eq!(
        encode_socks5_udp_in_tcp_frame(&target, &vec![0; largest.len() + 1]),
        Err(SocksParseError::PayloadTooLarge)
    );

    let name = |len: usize| udp_target(domain(&"a".repeat(len)), 53);
    let frame = encode_socks5_udp_in_tcp_frame(&name(248), b"x").unwrap();
    assert_eq!(frame[2], u8::MAX);
    let mut buffer = BytesMut::from(&frame[..]);
    assert_eq!(
        decode_socks5_udp_in_tcp_frame(&mut buffer).unwrap(),
        Some(SocksUdpDatagram {
            target: name(248),
            payload: b"x".as_slice().into(),
        })
    );
    assert_eq!(
        encode_socks5_udp_in_tcp_frame(&name(249), b"x"),
        Err(SocksParseError::InvalidDomain)
    );

    assert_eq!(SOCKS5_UDP_IN_TCP_CLIENT_BUFFER, 1500);
    assert_eq!(socks5_udp_in_tcp_max_reply(&target), 1493);
    assert_eq!(
        socks5_udp_in_tcp_max_reply(&udp_target(ip("2001:db8::1"), 53)),
        1481
    );
    assert_eq!(socks5_udp_in_tcp_max_reply(&name(11)), 1485);
}

/// A header whose address does not end where `HDRLEN` says, or cannot be
/// read, leaves nothing after it readable as frames.
#[test]
fn socks5_udp_in_tcp_frames_refuse_a_header_that_misstates_its_address() {
    let decode = |frame: &[u8]| decode_socks5_udp_in_tcp_frame(&mut BytesMut::from(frame));
    // IPv4 needs ten header bytes: one short, one over.
    assert_eq!(
        decode(&[0, 1, 9, 1, 192, 0, 2, 7, 0, 53, b'x']),
        Err(SocksParseError::InvalidUdpFrame)
    );
    assert_eq!(
        decode(&[0, 1, 11, 1, 192, 0, 2, 7, 0, 53, 0, b'x']),
        Err(SocksParseError::InvalidUdpFrame)
    );
    // IPv6 in an IPv4-sized header, and a header too short for any address.
    assert_eq!(
        decode(&[0, 0, 10, 4, 0x20, 1, 0x0d, 0xb8, 0, 0]),
        Err(SocksParseError::TruncatedUdpDatagram)
    );
    assert_eq!(
        decode(&[0, 0, 0]),
        Err(SocksParseError::TruncatedUdpDatagram)
    );
    assert_eq!(
        decode(&[0, 0, 10, 2, 0, 0, 0, 0, 0, 53]),
        Err(SocksParseError::UnsupportedAddressType(2))
    );
    let mut bad_name = vec![0, 0, 14, 3, 7];
    bad_name.extend_from_slice(b"exa mpl");
    bad_name.extend_from_slice(&53_u16.to_be_bytes());
    assert_eq!(decode(&bad_name), Err(SocksParseError::InvalidDomain));
    assert_eq!(
        decode(&[0, 0, 7, 3, 0, 0, 53]),
        Err(SocksParseError::InvalidDomain),
        "an empty domain"
    );
    // Refused once the header is in, without waiting for the 65,535 bytes
    // of data it announces.
    assert_eq!(
        decode(&[0xff, 0xff, 9, 1, 192, 0, 2, 7, 0, 53]),
        Err(SocksParseError::InvalidUdpFrame)
    );
    let mut buffer = BytesMut::from(&[0xff, 0xff, 10, 1, 192, 0, 2, 7][..]);
    assert_eq!(decode_socks5_udp_in_tcp_frame(&mut buffer), Ok(None));
    buffer.extend_from_slice(&[0, 53]);
    assert_eq!(
        decode_socks5_udp_in_tcp_frame(&mut buffer),
        Ok(None),
        "a header that holds is followed by its data"
    );
}

/// `parse_socks5_request` reads only `CONNECT` and names the command it
/// refused, whichever it was.
#[tokio::test]
async fn socks5_connect_request_names_the_command_it_refuses() {
    for command in [3, 5] {
        let bytes = [5, command, 0, 1, 192, 0, 2, 7, 0, 80];
        assert_eq!(
            parse_socks5_request(&bytes[..]).await,
            Err(SocksParseError::UnsupportedCommand(command))
        );
    }
}

#[test]
fn socks5_udp_datagrams_read_as_xray_core_reads_them() {
    let datagram = |head: [u8; 3], name: &[u8]| {
        let mut datagram = head.to_vec();
        datagram.push(3);
        datagram.push(u8::try_from(name.len()).unwrap());
        datagram.extend_from_slice(name);
        datagram.extend_from_slice(&53_u16.to_be_bytes());
        datagram.extend_from_slice(b"payload");
        parse_socks5_udp_datagram(&datagram).map(|decoded| decoded.target.addr)
    };
    // The reserved bytes are not checked; a fragment is refused.
    assert_eq!(
        datagram([0xff, 0xff, 0], b"example.com"),
        domain("example.com")
    );
    assert_eq!(
        datagram([0, 0, 1], b"example.com"),
        Err(SocksParseError::UnsupportedUdpFragment)
    );
    assert_eq!(datagram([0, 0, 0], b"192.0.2.7"), ip("192.0.2.7"));
    assert_eq!(
        datagram([0, 0, 0], b"exa mple.com"),
        Err(SocksParseError::InvalidDomain)
    );
}

#[tokio::test]
async fn socks4a_domains_read_through_go_parse_address() {
    let socks4a = |name: &[u8]| {
        let mut body = vec![1, 0, 80, 0, 0, 0, 1, 0];
        body.extend_from_slice(name);
        body.push(0);
        body
    };
    for (name, expected) in [
        (b"[2001:db8::1]".as_slice(), ip("2001:db8::1")),
        (b"::ffff:192.0.2.7", ip("192.0.2.7")),
        (b" 192.0.2.7 ", ip("192.0.2.7")),
        // Unlike SOCKS5, the name is not checked, only trimmed.
        (b" exa mple.com ", domain("exa mple.com")),
        (b"[example.com]", domain("example.com")),
        (b" ", Err(SocksParseError::InvalidDomain)),
    ] {
        let target = parse_socks4_connect(&socks4a(name)[..])
            .await
            .map(|target| target.addr);
        assert_eq!(target, expected, "{}", String::from_utf8_lossy(name));
    }
}

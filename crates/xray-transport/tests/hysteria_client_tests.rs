#[path = "hysteria/support.rs"]
mod support;

use std::future::pending;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use support::{AUTH, DEADLINE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use xray_proxy::hysteria::{decode_tcp_request, decode_udp_message};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::hysteria::{HysteriaClient, HysteriaConfig, HysteriaError, HysteriaWindows};
use xray_transport::memory_budget::{ByteBudget, ByteBudgetSettings};
use xray_transport::{MemoryClass, SocketHandle, SocketProtector, TlsConnector};

#[derive(Clone, Copy)]
enum Mode {
    Good,
    Rejected,
    Malformed,
    AuthStall,
    TcpStall,
    Prefetch,
    HalfClose,
    TcpRejected,
    TcpMalformed,
    Udp,
    /// Answers every TCP request, then, once the client sends a byte, writes
    /// until the client's flow control stops it and reports how much it wrote.
    Hold,
    /// Answers every TCP request and echoes the stream.
    Echo,
    /// Answers every TCP request, then, once the client sends a byte, writes
    /// until the client stops the stream.
    Stream,
}

struct Mock {
    endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
    accepted: mpsc::Receiver<quinn::Connection>,
    tcp_cancelled: Arc<AtomicBool>,
    held: mpsc::UnboundedReceiver<usize>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
        self.driver.abort();
    }
}

impl Mock {
    fn start(mode: Mode) -> (Self, TlsConnector) {
        let identity = support::identity();
        let endpoint = quinn::Endpoint::server(identity.server, support::localhost()).unwrap();
        let accepting = endpoint.clone();
        let (tx, accepted) = mpsc::channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let tcp_cancelled = Arc::clone(&cancelled);
        let (held_tx, held) = mpsc::unbounded_channel();
        let driver = tokio::spawn(async move {
            let Ok(connection) = accepting.accept().await.unwrap().await else {
                return;
            };
            tx.send(connection.clone()).await.unwrap();
            let mut http3: h3::server::Connection<_, Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
            let Ok(Some(request)) = http3.accept().await else {
                return;
            };
            let Ok((request, mut response)) = request.resolve_request().await else {
                return;
            };
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().authority().unwrap().as_str(), "hysteria");
            assert_eq!(request.uri().path(), "/auth");
            assert_eq!(request.headers()["hysteria-auth"], AUTH);
            assert_eq!(request.headers()["hysteria-cc-rx"], "0");
            let padding = request.headers()["hysteria-padding"].as_bytes();
            assert!((256..2048).contains(&padding.len()));
            if matches!(mode, Mode::AuthStall) {
                pending::<()>().await;
            }
            let status = if matches!(mode, Mode::Rejected) {
                404
            } else {
                233
            };
            let udp = match mode {
                Mode::Malformed => "invalid",
                Mode::Udp => "true",
                _ => "false",
            };
            response
                .send_response(
                    Response::builder()
                        .status(status)
                        .header("hysteria-udp", udp)
                        .header("hysteria-cc-rx", "auto")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            response.finish().await.unwrap();
            if matches!(
                mode,
                Mode::TcpStall
                    | Mode::Prefetch
                    | Mode::HalfClose
                    | Mode::TcpRejected
                    | Mode::TcpMalformed
            ) {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let mut wire = Vec::new();
                while decode_tcp_request(&wire).is_err() {
                    let mut bytes = [0; 1024];
                    let n = recv.read(&mut bytes).await.unwrap().unwrap();
                    wire.extend_from_slice(&bytes[..n]);
                }
                if matches!(mode, Mode::TcpStall) {
                    let _ = send.stopped().await;
                    cancelled.store(true, Ordering::Release);
                } else if matches!(mode, Mode::HalfClose) {
                    send.write_all(b"\x00\x00\x00").await.unwrap();
                    let data = recv.read_to_end(4096).await.unwrap();
                    send.write_all(&data).await.unwrap();
                    send.finish().unwrap();
                } else if matches!(mode, Mode::TcpRejected) {
                    send.write_all(b"\x07\x06secret\x00").await.unwrap();
                    send.finish().unwrap();
                } else if matches!(mode, Mode::TcpMalformed) {
                    send.write_all(b"\x00\x7f\xff").await.unwrap();
                    send.finish().unwrap();
                } else {
                    send.write_all(b"\x00\x00\x00prefetched-data")
                        .await
                        .unwrap();
                    send.finish().unwrap();
                }
            } else if matches!(mode, Mode::Hold | Mode::Echo | Mode::Stream) {
                let mut streams = tokio::task::JoinSet::new();
                while let Ok((send, recv)) = connection.accept_bi().await {
                    match mode {
                        Mode::Hold => streams.spawn(hold(send, recv, held_tx.clone())),
                        Mode::Stream => streams.spawn(stream_out(send, recv)),
                        _ => streams.spawn(echo(send, recv)),
                    };
                }
            }
            connection.closed().await;
            drop(http3);
        });
        (
            Self {
                endpoint,
                driver,
                accepted,
                tcp_cancelled,
                held,
            },
            identity.connector,
        )
    }
    fn config(&self) -> HysteriaConfig {
        HysteriaConfig::new(
            self.endpoint.local_addr().unwrap(),
            support::tls_settings(),
            AUTH.into(),
        )
    }
    /// A config with the windows of a host of `class`, whatever this one's.
    fn config_on(&self, class: MemoryClass) -> HysteriaConfig {
        HysteriaConfig::with_windows(
            self.endpoint.local_addr().unwrap(),
            support::tls_settings(),
            AUTH.into(),
            HysteriaWindows::for_class(class),
        )
    }
    async fn connection(&mut self) -> quinn::Connection {
        timeout(DEADLINE, self.accepted.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn authentication_headers_fail_closed_and_do_not_expose_auth() {
    for (mode, expected) in [
        (Mode::Rejected, HysteriaError::Authentication),
        (Mode::Malformed, HysteriaError::AuthenticationHeaders),
    ] {
        let (mut server, tls) = Mock::start(mode);
        let config = server.config();
        assert!(!format!("{config:?}").contains(AUTH));
        assert_eq!(
            HysteriaClient::connect(config, &tls).await.err(),
            Some(expected)
        );
        assert!(!format!("{expected:?} {expected}").contains(AUTH));
        timeout(DEADLINE, server.connection().await.closed())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn auth_deadline_and_caller_cancellation_close_pending_connection() {
    let (mut server, tls) = Mock::start(Mode::AuthStall);
    let mut config = server.config();
    config.limits.operation_timeout = Duration::from_millis(100);
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Timeout)
    );
    timeout(DEADLINE, server.connection().await.closed())
        .await
        .unwrap();

    let (mut server, tls) = Mock::start(Mode::AuthStall);
    let config = server.config();
    let task = tokio::spawn(async move { HysteriaClient::connect(config, &tls).await });
    let connection = server.connection().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    timeout(DEADLINE, connection.closed()).await.unwrap();
}

#[tokio::test]
async fn disabled_udp_last_clone_and_explicit_close_release_connection() {
    let (mut server, tls) = Mock::start(Mode::Good);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    assert!(!client.udp_enabled());
    assert!(matches!(
        client.open_udp(),
        Err(HysteriaError::UdpUnsupported)
    ));
    let connection = server.connection().await;
    let last = client.clone();
    drop(client);
    assert!(last.is_live());
    drop(last);
    timeout(DEADLINE, connection.closed()).await.unwrap();

    let (mut server, tls) = Mock::start(Mode::Good);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let local = client.local_addr().unwrap();
    client.close();
    assert!(client.local_addr().is_err());
    timeout(DEADLINE, server.connection().await.closed())
        .await
        .unwrap();
    timeout(DEADLINE, async {
        loop {
            if std::net::UdpSocket::bind(local).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed connection releases socket while client handle remains");
}

/// Reads one TCP request and answers it with success.
async fn answer_tcp(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) {
    let mut wire = Vec::new();
    while decode_tcp_request(&wire).is_err() {
        let mut bytes = [0; 1024];
        let n = recv.read(&mut bytes).await.unwrap().unwrap();
        wire.extend_from_slice(&bytes[..n]);
    }
    send.write_all(b"\x00\x00\x00").await.unwrap();
}

async fn hold(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    held: mpsc::UnboundedSender<usize>,
) {
    answer_tcp(&mut send, &mut recv).await;
    recv.read_exact(&mut [0; 1]).await.unwrap();
    // A write takes what flow control allows at once, and waits for credit
    // only when there is none.
    let chunk = [0; 64 * 1024];
    let mut written = 0;
    while let Ok(Ok(n)) = timeout(Duration::from_millis(500), send.write(&chunk)).await {
        written += n;
    }
    let _ = held.send(written);
    pending::<()>().await;
}

async fn echo(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    answer_tcp(&mut send, &mut recv).await;
    tokio::io::copy(&mut recv, &mut send).await.unwrap();
    send.finish().unwrap();
}

/// Writes for as long as the client reads: unlike [`hold`], a write that
/// waits for credit does not end the stream.
async fn stream_out(mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    answer_tcp(&mut send, &mut recv).await;
    recv.read_exact(&mut [0; 1]).await.unwrap();
    let chunk = [0; 64 * 1024];
    while send.write_all(&chunk).await.is_ok() {}
}

fn target() -> Target {
    Target::new(TargetAddr::Domain("example.com".into()), 443, Network::Tcp)
}

#[tokio::test]
async fn empty_udp_datagram_is_skipped_and_the_session_keeps_sending() {
    let (mut server, tls) = Mock::start(Mode::Udp);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let connection = server.connection().await;
    let session = client.open_udp().unwrap();
    let target = Target::new(TargetAddr::Domain("example.com".into()), 53, Network::Udp);

    timeout(DEADLINE, session.send(&target, b""))
        .await
        .unwrap()
        .unwrap();
    timeout(DEADLINE, session.send(&target, b"after"))
        .await
        .unwrap()
        .unwrap();

    let wire = timeout(DEADLINE, connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let message = decode_udp_message(&wire).unwrap();
    assert_eq!(message.session_id, session.session_id());
    assert_eq!(message.payload, b"after");
}

#[tokio::test]
async fn tcp_response_deadline_resets_stream_and_releases_slot() {
    let (server, tls) = Mock::start(Mode::TcpStall);
    let mut config = server.config();
    config.limits.operation_timeout = Duration::from_millis(150);
    config.limits.max_tcp_streams = 1;
    let client = HysteriaClient::connect(config, &tls).await.unwrap();
    assert!(matches!(
        client.open_tcp(&target()).await,
        Err(HysteriaError::Timeout)
    ));
    timeout(DEADLINE, async {
        while !server.tcp_cancelled.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A second attempt reaches the peer (then times out), rather than leaking
    // the only local slot from the cancelled request.
    assert!(matches!(
        client.open_tcp(&target()).await,
        Err(HysteriaError::Timeout)
    ));
    client.close();
}

#[tokio::test]
async fn tcp_response_preserves_prefetched_application_bytes() {
    let (server, tls) = Mock::start(Mode::Prefetch);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let mut stream = client.open_tcp(&target()).await.unwrap();
    let mut output = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output, b"prefetched-data");
}

#[tokio::test]
async fn tcp_half_close_keeps_the_receive_direction_open() {
    let (server, tls) = Mock::start(Mode::HalfClose);
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let mut stream = client.open_tcp(&target()).await.unwrap();
    stream.write_all(b"reply after FIN").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut output = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(output, b"reply after FIN");
}

#[tokio::test]
async fn a_constrained_host_holds_less_unread_and_still_moves_more_than_its_windows() {
    const MIB: usize = 1024 * 1024;
    let (mut standard, standard_tls) = Mock::start(Mode::Hold);
    let standard_config = standard.config_on(MemoryClass::Standard);
    let (mut held, held_tls) = Mock::start(Mode::Hold);
    let mut held_config = held.config_on(MemoryClass::Constrained);
    let (echo, echo_tls) = Mock::start(Mode::Echo);
    let echo_config = echo.config_on(MemoryClass::Constrained);
    assert_eq!(
        (
            held_config.quic.initial_stream_receive_window,
            held_config.quic.initial_connection_receive_window,
            held_config.limits.max_send_window,
            held_config.limits.max_tcp_streams,
            held_config.limits.max_udp_sessions,
        ),
        (MIB as u64, 3 * MIB as u64, 4 * MIB as u64, 64, 32),
        "the stream limits are the same on every host"
    );

    // The server can send a stream the client does not read its window less
    // the 3-byte response: 2 MiB on a standard host, 1 MiB on a constrained
    // one, where three such streams use up the 3 MiB of the connection.
    let client = HysteriaClient::connect(standard_config, &standard_tls)
        .await
        .unwrap();
    // The send window grows to 10 MB on a standard host, 4 MiB on a
    // constrained one: what the connection may hold unacknowledged.
    assert_eq!(client.send_window_ceiling(), 10_000_000);
    let mut stream = client.open_tcp(&target()).await.unwrap();
    stream.write_all(b"g").await.unwrap();
    let written = timeout(DEADLINE, standard.held.recv()).await.unwrap();
    assert_eq!(written, Some(2 * MIB - 3));
    client.close();

    held_config.limits.operation_timeout = Duration::from_secs(2);
    let client = HysteriaClient::connect(held_config, &held_tls)
        .await
        .unwrap();
    assert_eq!(client.send_window_ceiling(), 4 * MIB as u64);
    let mut streams = Vec::new();
    let mut written = Vec::new();
    for _ in 0..3 {
        let mut stream = client.open_tcp(&target()).await.unwrap();
        stream.write_all(b"g").await.unwrap();
        written.push(timeout(DEADLINE, held.held.recv()).await.unwrap().unwrap());
        streams.push(stream);
    }
    // The connection's 3 MiB also carried the authentication's HTTP/3
    // frames, so the third stream gets that much less.
    assert_eq!(written[..2], [MIB - 3; 2]);
    let http3 = 3 * MIB - 3 * 3 - written.iter().sum::<usize>();
    assert!((1..1024).contains(&http3), "{written:?}");
    assert_eq!(
        client.open_tcp(&target()).await.err(),
        Some(HysteriaError::Timeout),
        "a fourth response finds no connection credit"
    );
    client.close();

    // Echoed through those windows, four streams of 4 MiB come back whole.
    let client = HysteriaClient::connect(echo_config, &echo_tls)
        .await
        .unwrap();
    assert_eq!(client.send_window_ceiling(), 4 * MIB as u64);
    let mut transfers = tokio::task::JoinSet::new();
    for seed in 0..4u8 {
        let stream = client.open_tcp(&target()).await.unwrap();
        transfers.spawn(async move {
            let data: Vec<u8> = (0..4 * MIB).map(|i| (i % 251) as u8 ^ seed).collect();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let sent = data.clone();
            let writing = async move {
                writer.write_all(&sent).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let mut echoed = Vec::new();
            let ((), read) = tokio::join!(writing, reader.read_to_end(&mut echoed));
            read.unwrap();
            assert!(
                echoed == data,
                "stream {seed} came back with {} of {} bytes",
                echoed.len(),
                data.len()
            );
        });
    }
    timeout(Duration::from_secs(60), async {
        while let Some(transfer) = transfers.join_next().await {
            transfer.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_connection_holds_its_windows_within_a_byte_budget_while_it_moves_data() {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;
    let budget: &'static ByteBudget =
        Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
            capacity: 320 * KIB,
            floor: 4 * KIB,
        })));
    let (echo, echo_tls) = Mock::start(Mode::Echo);
    let mut config = echo.config_on(MemoryClass::Constrained);
    config.byte_budget = budget;
    let client = HysteriaClient::connect(config, &echo_tls).await.unwrap();
    assert_eq!(budget.in_use(), 0, "nothing moves: nothing held");

    for turn in 0..3 {
        let stream = client.open_tcp(&target()).await.unwrap();
        assert_eq!(
            budget.in_use(),
            0,
            "turn {turn}: an open stream alone holds nothing"
        );
        // Through the windows 2 MiB go out and come back whole.
        let data: Vec<u8> = (0..2 * MIB).map(|i| (i % 251) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let sent = data.clone();
        let writing = async move {
            writer.write_all(&sent).await.unwrap();
            writer.shutdown().await.unwrap();
            writer
        };
        let mut echoed = Vec::new();
        let (writer, read) = timeout(Duration::from_secs(60), async {
            tokio::join!(writing, reader.read_to_end(&mut echoed))
        })
        .await
        .unwrap();
        read.unwrap();
        assert!(
            echoed == data,
            "turn {turn}: {} of {} bytes",
            echoed.len(),
            data.len()
        );
        let usage = budget.usage();
        assert!(
            usage.window_bytes > 0,
            "turn {turn}: the busy connection held a lease"
        );
        assert!(
            usage.peak <= budget.window_cap(),
            "turn {turn}: the lease held {} of the leases' {}",
            usage.peak,
            budget.window_cap()
        );
        drop(reader.unsplit(writer));
        // A second without traffic: the windows fall to the floor.
        timeout(Duration::from_secs(5), async {
            while budget.in_use() > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("turn {turn}: the idle lease kept {} bytes", budget.in_use()));
        assert_eq!(budget.usage().windows, 0);
        budget.reset_peak();
    }
    client.close();
    assert_eq!(budget.in_use(), 0);
}

/// Windows that fall to the floor when the connection goes quiet and grow
/// again when it moves data leave the server no more connection credit than
/// the handshake announced, however many such turns there were: after four,
/// streams nobody reads take at most the announced 3 MiB, as on a connection
/// that never went quiet.
#[tokio::test]
async fn idle_and_busy_turns_leave_the_server_no_more_credit_than_announced() {
    const MIB: usize = 1024 * 1024;
    const TURNS: usize = 4;
    const MOST_STREAMS: usize = 6;
    let budget: &'static ByteBudget = Box::leak(Box::new(ByteBudget::with_settings(
        ByteBudgetSettings::for_class(MemoryClass::Constrained),
    )));
    let (mut held, held_tls) = Mock::start(Mode::Hold);
    let mut config = held.config_on(MemoryClass::Constrained);
    config.byte_budget = budget;
    config.limits.operation_timeout = Duration::from_secs(2);
    let announced = config.quic.initial_connection_receive_window as usize;
    let client = HysteriaClient::connect(config, &held_tls).await.unwrap();

    for turn in 0..TURNS {
        // Busy: a MiB comes in and is read.
        let mut stream = client.open_tcp(&target()).await.unwrap();
        stream.write_all(b"g").await.unwrap();
        let mut bytes = vec![0; MIB];
        timeout(DEADLINE, stream.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        drop(stream);
        timeout(DEADLINE, held.held.recv()).await.unwrap().unwrap();
        // Quiet: the windows fall to the floor.
        timeout(Duration::from_secs(5), async {
            while budget.in_use() > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("turn {turn}: the idle lease kept {} bytes", budget.in_use()));
    }

    // Streams nobody reads take what credit the server has.
    let mut streams = Vec::new();
    let mut taken = 0;
    while streams.len() < MOST_STREAMS {
        match client.open_tcp(&target()).await {
            Ok(mut stream) => {
                stream.write_all(b"g").await.unwrap();
                // The 3-byte response came through the same credit.
                taken += 3 + timeout(DEADLINE, held.held.recv()).await.unwrap().unwrap();
                streams.push(stream);
            }
            Err(HysteriaError::Timeout) => break,
            Err(error) => panic!("{error:?}"),
        }
    }
    assert!(
        taken <= announced,
        "after {TURNS} idle and busy turns {} unread streams took {taken} B; the handshake \
         announced {announced} B",
        streams.len()
    );
    drop(streams);
    client.close();
}

#[tokio::test]
async fn tcp_failure_status_and_malformed_headers_fail_without_server_text() {
    for (mode, expected) in [
        (Mode::TcpRejected, HysteriaError::TcpRejected),
        (Mode::TcpMalformed, HysteriaError::TcpResponse),
    ] {
        let (server, tls) = Mock::start(mode);
        let client = HysteriaClient::connect(server.config(), &tls)
            .await
            .unwrap();
        let error = client.open_tcp(&target()).await.err().unwrap();
        assert_eq!(error, expected);
        assert!(!format!("{error} {error:?}").contains("secret"));
    }
}

struct Protector {
    calls: AtomicUsize,
    reject: bool,
}
impl SocketProtector for Protector {
    fn protect(&self, _socket: SocketHandle) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            Err(io::Error::other("synthetic rejection"))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn socket_protection_precedes_handshake_and_tls_remains_verified() {
    let (server, tls) = Mock::start(Mode::Good);
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        reject: true,
    });
    let protected = tls.with_socket_protector(protector.clone());
    assert_eq!(
        HysteriaClient::connect(server.config(), &protected)
            .await
            .err(),
        Some(HysteriaError::SocketProtection)
    );
    assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
    assert!(!server.driver.is_finished());
    // System trust must reject the generated local self-signed certificate.
    assert_eq!(
        HysteriaClient::connect(server.config(), &TlsConnector::system().unwrap())
            .await
            .err(),
        Some(HysteriaError::Connect)
    );
    let (server, tls) = Mock::start(Mode::Good);
    let protector = Arc::new(Protector {
        calls: AtomicUsize::new(0),
        reject: false,
    });
    let protected = tls.with_socket_protector(protector.clone());
    let client = HysteriaClient::connect(server.config(), &protected)
        .await
        .unwrap();
    assert_eq!(protector.calls.load(Ordering::Relaxed), 1);
    client.close();
}

#[tokio::test]
async fn config_validation_happens_before_opening_a_socket() {
    let (server, tls) = Mock::start(Mode::Good);
    let mut config = server.config();
    config.limits.udp_queue_bytes = usize::MAX;
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    let mut config = server.config();
    config.auth = zeroize::Zeroizing::new("bad\r\nheader".into());
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    let mut config = server.config();
    config.tls.fingerprint = Some("chrome".into());
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    let mut config = server.config();
    config.tls.alpn = vec!["h2".into()];
    assert_eq!(
        HysteriaClient::connect(config, &tls).await.err(),
        Some(HysteriaError::Configuration)
    );
    assert!(!server.driver.is_finished());
}

#[tokio::test]
async fn dedicated_endpoint_advertises_zero_length_local_cid() {
    let (server, tls) = Mock::start(Mode::Good);
    let capture = tokio::net::UdpSocket::bind(support::localhost())
        .await
        .unwrap();
    let mut config = server.config();
    config.remote_addr = capture.local_addr().unwrap();
    let connecting = tokio::spawn(async move { HysteriaClient::connect(config, &tls).await });
    let mut packet = [0u8; 2048];
    let (len, _) = timeout(DEADLINE, capture.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    connecting.abort();
    assert!(len >= 1200, "QUIC Initial minimum datagram size");
    assert_eq!(packet[0] & 0xc0, 0xc0, "QUIC long header");
    assert_eq!(&packet[1..5], &1u32.to_be_bytes(), "QUIC v1");
    let destination_len = packet[5] as usize;
    assert!(destination_len >= 8, "initial server CID remains nonempty");
    assert_eq!(packet[6 + destination_len], 0, "empty client source CID");
}

#[tokio::test]
async fn rebind_from_host_thread_preserves_connection_and_protects_each_socket() {
    #[derive(Default)]
    struct Count(AtomicUsize);
    impl SocketProtector for Count {
        fn protect(&self, _: SocketHandle) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (mut server, tls) = Mock::start(Mode::Good);
    let count = Arc::new(Count::default());
    let tls = tls.with_socket_protector(count.clone());
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let connection = server.connection().await;
    let old = client.local_addr().unwrap();
    // A plain host thread has no Tokio context, as with the Swift/FFI caller.
    let host = client.clone();
    std::thread::spawn(move || {
        for _ in 0..100 {
            assert!(host.rebind());
        }
    })
    .join()
    .unwrap();
    timeout(DEADLINE, async {
        while client.local_addr().unwrap() == old {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 2);
    assert!(client.is_live());
    assert!(connection.close_reason().is_none());
    client.close();
    assert!(!client.rebind());
    timeout(DEADLINE, connection.closed()).await.unwrap();
}

#[tokio::test]
async fn rebind_protection_failure_closes_live_connection() {
    #[derive(Default)]
    struct RejectSecond(AtomicUsize);
    impl SocketProtector for RejectSecond {
        fn protect(&self, _: SocketHandle) -> io::Result<()> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
    }
    let (mut server, tls) = Mock::start(Mode::Good);
    let protector = Arc::new(RejectSecond::default());
    let tls = tls.with_socket_protector(protector.clone());
    let client = HysteriaClient::connect(server.config(), &tls)
        .await
        .unwrap();
    let connection = server.connection().await;
    assert!(client.rebind());
    timeout(DEADLINE, connection.closed()).await.unwrap();
    assert!(!client.is_live());
    assert!(client.local_addr().is_err());
    assert!(!client.rebind());
    assert_eq!(protector.0.load(Ordering::SeqCst), 2);
}

/// A UDP relay that holds every datagram `one_way` in each direction: the
/// client sends to its address, and it speaks to `server` from one socket.
async fn delay_relay(
    server: std::net::SocketAddr,
    one_way: Duration,
) -> (std::net::SocketAddr, support::Task) {
    use tokio::net::UdpSocket;
    use tokio::time::{sleep_until, Instant};

    let front = Arc::new(UdpSocket::bind(support::localhost()).await.unwrap());
    let back = Arc::new(UdpSocket::bind(support::localhost()).await.unwrap());
    back.connect(server).await.unwrap();
    let address = front.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (to_server, mut for_server) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        let (to_client, mut for_client) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        let client = Arc::new(std::sync::Mutex::new(None));
        let mut tasks = tokio::task::JoinSet::new();
        let (socket, peer) = (Arc::clone(&front), Arc::clone(&client));
        tasks.spawn(async move {
            let mut buffer = vec![0; 65_536];
            while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
                *peer.lock().unwrap() = Some(from);
                let _ = to_server.send((Instant::now() + one_way, buffer[..read].to_vec()));
            }
        });
        let socket = Arc::clone(&back);
        tasks.spawn(async move {
            let mut buffer = vec![0; 65_536];
            while let Ok(read) = socket.recv(&mut buffer).await {
                let _ = to_client.send((Instant::now() + one_way, buffer[..read].to_vec()));
            }
        });
        let socket = Arc::clone(&back);
        tasks.spawn(async move {
            while let Some((due, datagram)) = for_server.recv().await {
                sleep_until(due).await;
                let _ = socket.send(&datagram).await;
            }
        });
        tasks.spawn(async move {
            while let Some((due, datagram)) = for_client.recv().await {
                sleep_until(due).await;
                let peer = *client.lock().unwrap();
                if let Some(peer) = peer {
                    let _ = front.send_to(&datagram, peer).await;
                }
            }
        });
        while tasks.join_next().await.is_some() {}
    });
    (address, support::Task(task))
}

/// The windows a phone runs with, within a phone's byte budget.
fn phone_budget(config: &mut HysteriaConfig) {
    config.byte_budget = Box::leak(Box::new(ByteBudget::with_settings(
        ByteBudgetSettings::for_class(MemoryClass::Constrained),
    )));
}

/// Mbit/s of `flows` downloads of `each` bytes at once, through a 120 ms
/// round trip with a phone's windows.
async fn download_at_120ms(flows: usize, each: usize) -> f64 {
    let (server, tls) = Mock::start(Mode::Stream);
    let mut config = server.config_on(MemoryClass::Constrained);
    phone_budget(&mut config);
    let (relay, _relay) = delay_relay(config.remote_addr, Duration::from_millis(60)).await;
    config.remote_addr = relay;
    let client = HysteriaClient::connect(config, &tls).await.unwrap();
    // Every stream is open before any asks for data: a stream that streams
    // while later ones open would leave their answers no connection credit.
    let mut streams = Vec::new();
    for _ in 0..flows {
        streams.push(client.open_tcp(&target()).await.unwrap());
    }
    let started = std::time::Instant::now();
    for stream in &mut streams {
        stream.write_all(b"g").await.unwrap();
    }
    futures_util::future::join_all(streams.iter_mut().map(|stream| async move {
        let mut bytes = vec![0; each];
        stream.read_exact(&mut bytes).await.unwrap();
    }))
    .await;
    let elapsed = started.elapsed();
    drop(streams);
    client.close();
    (flows * each) as f64 * 8.0 / elapsed.as_secs_f64() / 1e6
}

/// Hysteria2 downloads at a simulated 120 ms round trip with a phone's
/// windows, one stream and then 32 at once: numbers for the tables, run by
/// hand with `--ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a benchmark: prints Mbit/s at a simulated 120 ms round trip"]
async fn hysteria_downloads_at_a_120ms_round_trip() {
    const MIB: usize = 1024 * 1024;
    for (flows, each) in [(1, 16 * MIB), (32, 2 * MIB)] {
        let mut runs = Vec::new();
        for _ in 0..3 {
            runs.push(download_at_120ms(flows, each).await);
        }
        let best = runs.iter().copied().fold(0.0, f64::max);
        eprintln!("HYSTERIA-RTT120 flows {flows}: best {best:.0} Mbit/s of {runs:.0?}");
    }
}

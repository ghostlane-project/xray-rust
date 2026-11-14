//! Receive credit, backpressure and latency regressions for issue #28, and
//! the same credit under a byte budget.
use super::*;
use h2::SendStream;
use tokio::time::{sleep_until, Instant};
use xray_transport::memory_budget::ByteBudget;
use xray_transport::{ByteBudgetSettings, MemoryClass};

const STREAM_WINDOW: usize = 4 * 1024 * 1024;

/// A byte budget of the test's own with `class`'s numbers: 15 MB for a
/// desktop's 4 MiB windows, 3 MB for a phone's adaptive ones. A test whose
/// credit depends on the budget holds its responses within its own, so no
/// other test in the binary moves its numbers and the memory class of the
/// host that runs it does not either.
fn budget_of(class: MemoryClass) -> &'static ByteBudget {
    Box::leak(Box::new(ByteBudget::with_settings(
        ByteBudgetSettings::for_class(class),
    )))
}

#[tokio::test(start_paused = true)]
async fn configured_receive_windows_bound_unread_data_and_replenish_only_consumed_bytes() {
    let budget = budget_of(MemoryClass::Standard);
    for window in [65535, 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024] {
        let (client, mut server) = pair_with_window(server::Builder::new(), Some(window)).await;
        let client = client.with_byte_budget(budget);
        let (mut body, mut send) = response_pair(&client, &mut server).await;
        timeout(DEADLINE, send_bytes(&mut send, window as usize))
            .await
            .unwrap();
        assert_blocked(&mut send).await;
        let count = window as usize / 2;
        let mut bytes = vec![0; count];
        body.read_exact(&mut bytes).await.unwrap();
        assert!(bytes.iter().all(|b| *b == 0xa5));
        timeout(DEADLINE, send_bytes(&mut send, count))
            .await
            .unwrap();
        assert_blocked(&mut send).await;
        drop(body);
        assert_eq!(
            timeout(DEADLINE, poll_fn(|cx| send.poll_reset(cx)))
                .await
                .unwrap()
                .unwrap(),
            Reason::CANCEL
        );
        server.close().await;
    }
}

#[tokio::test]
async fn invalid_receive_window_is_rejected_before_writing_the_preface() {
    for window in [0, 65534, 16 * 1024 * 1024 + 1, u32::MAX] {
        let (client, mut server) = tokio::io::duplex(64);
        assert!(matches!(
            connect_h2_with_receive_window(Box::new(client), None, window).await,
            Err(H2Error::Configuration(_))
        ));
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        assert!(wire.is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn a_larger_stream_override_does_not_raise_shared_connection_credit() {
    let (client, mut server) =
        pair_with_window(server::Builder::new(), Some(8 * 1024 * 1024)).await;
    let client = client.with_byte_budget(budget_of(MemoryClass::Standard));
    let mut stalled = Vec::new();
    for _ in 0..2 {
        let (body, mut send) = response_pair(&client, &mut server).await;
        timeout(DEADLINE, send_bytes(&mut send, 8 * 1024 * 1024))
            .await
            .unwrap();
        stalled.push((body, send));
    }
    let (mut victim, mut send) = response_pair(&client, &mut server).await;
    assert_blocked(&mut send).await;
    let (body, mut cancelled_send) = stalled.remove(0);
    drop(body);
    assert_eq!(
        timeout(DEADLINE, poll_fn(|cx| cancelled_send.poll_reset(cx)))
            .await
            .unwrap()
            .unwrap(),
        Reason::CANCEL
    );
    timeout(DEADLINE, send_bytes(&mut send, 1)).await.unwrap();
    let mut byte = [0];
    timeout(DEADLINE, victim.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(byte, [0xa5]);
    drop(stalled);
    drop(victim);
    server.close().await;
}

async fn response_pair(
    client: &H2Client,
    server: &mut TestServer,
) -> (impl tokio::io::AsyncRead + Unpin, SendStream<Bytes>) {
    let pending = client
        .start_fixed(
            request(Method::GET, "http://example.test/window"),
            Bytes::new(),
        )
        .await
        .unwrap();
    let (_, mut respond) = server.accept().await.unwrap().unwrap();
    let send = respond
        .send_response(response(StatusCode::OK), false)
        .unwrap();
    (pending.open().await.unwrap(), send)
}

/// Credit for a sixteenth of the window goes back while the window is still
/// open, not only after a third of it has been read.
#[tokio::test(start_paused = true)]
async fn a_sixteenth_of_the_window_read_returns_its_credit_while_the_window_is_open() {
    let (client, mut server) = pair().await;
    let client = client.with_byte_budget(budget_of(MemoryClass::Standard));
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW / 4))
        .await
        .unwrap();

    let mut bytes = vec![0; STREAM_WINDOW / 16];
    body.read_exact(&mut bytes).await.unwrap();

    timeout(
        DEADLINE,
        send_bytes(&mut send, STREAM_WINDOW * 3 / 4 + bytes.len()),
    )
    .await
    .expect("reading a sixteenth of the window returns its credit");
    assert_blocked(&mut send).await;
    drop(body);
    server.close().await;
}

/// A smaller read keeps its credit while the sender has window left, so a
/// fast reader does not send a WINDOW_UPDATE for every read.
#[tokio::test(start_paused = true)]
async fn a_smaller_read_keeps_its_credit_while_the_window_is_open() {
    let (client, mut server) = pair().await;
    let client = client.with_byte_budget(budget_of(MemoryClass::Standard));
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW / 4))
        .await
        .unwrap();

    let mut bytes = vec![0; STREAM_WINDOW / 32];
    body.read_exact(&mut bytes).await.unwrap();

    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW * 3 / 4))
        .await
        .unwrap();
    assert_blocked(&mut send).await;
    drop(body);
    server.close().await;
}

async fn send_bytes(send: &mut SendStream<Bytes>, mut count: usize) {
    let chunk = Bytes::from(vec![0xa5; 16 * 1024]);
    while count > 0 {
        send.reserve_capacity(count.min(chunk.len()));
        let granted = poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
        let take = granted.min(count).min(chunk.len());
        assert!(take > 0);
        send.send_data(chunk.slice(..take), false).unwrap();
        count -= take;
    }
}

async fn assert_blocked(send: &mut SendStream<Bytes>) {
    send.reserve_capacity(1);
    assert!(
        timeout(
            Duration::from_millis(25),
            poll_fn(|cx| send.poll_capacity(cx))
        )
        .await
        .is_err(),
        "unread DATA must remain flow controlled"
    );
    send.reserve_capacity(0);
}

#[tokio::test(start_paused = true)]
async fn unread_response_is_bounded_and_partial_reads_return_credit() {
    let (client, mut server) = pair().await;
    let client = client.with_byte_budget(budget_of(MemoryClass::Standard));
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW))
        .await
        .expect("one stream must accept a mobile-path bandwidth-delay product");
    assert_blocked(&mut send).await;

    // Return enough credit for h2's coalesced WINDOW_UPDATE while reading in
    // awkward pieces, including a partial DATA frame. Never grant unread bytes.
    let mut read = 0;
    let mut buffer = [0; 8191];
    while read < STREAM_WINDOW / 2 {
        let limit = buffer.len().min(STREAM_WINDOW / 2 - read);
        let n = body.read(&mut buffer[..limit]).await.unwrap();
        assert!(n > 0);
        assert!(buffer[..n].iter().all(|byte| *byte == 0xa5));
        read += n;
    }
    timeout(DEADLINE, send_bytes(&mut send, read))
        .await
        .expect("consumed bytes must replenish the stream");
    assert_blocked(&mut send).await;
    drop(body);
    assert_eq!(
        timeout(DEADLINE, poll_fn(|cx| send.poll_reset(cx)))
            .await
            .unwrap()
            .unwrap(),
        Reason::CANCEL
    );
    server.close().await;
}

#[tokio::test(start_paused = true)]
async fn stalled_responses_share_a_bounded_connection_and_cancel_restores_progress() {
    let (client, mut server) = pair().await;
    let client = client.with_byte_budget(budget_of(MemoryClass::Standard));
    let mut stalled = Vec::new();
    for _ in 0..3 {
        let (body, mut send) = response_pair(&client, &mut server).await;
        timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW))
            .await
            .unwrap();
        stalled.push((body, send));
    }
    // Three entirely unread streams must leave room for a fast stream to
    // recycle credit repeatedly, including beyond the connection's 16 MiB.
    let (mut fast, mut send) = response_pair(&client, &mut server).await;
    let sender = tokio::spawn(async move {
        send_bytes(&mut send, 5 * STREAM_WINDOW + 1).await;
        send.send_data(Bytes::new(), true).unwrap();
    });
    let mut received = Vec::new();
    timeout(DEADLINE, fast.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.len(), 5 * STREAM_WINDOW + 1);
    assert!(received.iter().all(|byte| *byte == 0xa5));
    sender.await.unwrap();

    // Four unread streams can fill the entire connection. This is an explicit
    // memory/backpressure boundary, not a promise of unlimited stalled peers.
    let (body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, STREAM_WINDOW))
        .await
        .unwrap();
    stalled.push((body, send));
    let (mut victim, mut send) = response_pair(&client, &mut server).await;
    assert_blocked(&mut send).await;
    let (body, mut cancelled_send) = stalled.remove(0);
    drop(body);
    assert_eq!(
        timeout(DEADLINE, poll_fn(|cx| cancelled_send.poll_reset(cx)))
            .await
            .unwrap()
            .unwrap(),
        Reason::CANCEL
    );
    timeout(DEADLINE, send_bytes(&mut send, 1)).await.unwrap();
    let mut byte = [0];
    timeout(DEADLINE, victim.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(byte, [0xa5]);
    drop(stalled);
    drop(victim);
    server.close().await;
}

/// A delay line, not a per-chunk sleep: chunks already in flight have their
/// own arrival times, so a larger window can actually pipeline DATA. Queues
/// and duplex pipes are bounded, and both directions receive half the RTT.
fn delay_direction(
    mut read: tokio::io::ReadHalf<DuplexStream>,
    mut write: tokio::io::WriteHalf<DuplexStream>,
    delay: Duration,
) -> [JoinHandle<()>; 2] {
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(256);
    let reader = tokio::spawn(async move {
        loop {
            let mut bytes = vec![0; 16 * 1024];
            let Ok(n) = read.read(&mut bytes).await else {
                break;
            };
            if n == 0 {
                break;
            }
            bytes.truncate(n);
            if tx.send((Instant::now() + delay, bytes)).await.is_err() {
                break;
            }
        }
    });
    let writer = tokio::spawn(async move {
        while let Some((arrival, bytes)) = rx.recv().await {
            sleep_until(arrival).await;
            if write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write.shutdown().await;
    });
    [reader, writer]
}

#[tokio::test(start_paused = true)]
async fn single_download_pipelines_across_a_113ms_path() {
    let (client_io, client_wire) = tokio::io::duplex(1024 * 1024);
    let (server_wire, server_io) = tokio::io::duplex(1024 * 1024);
    let (client_read, client_write) = tokio::io::split(client_wire);
    let (server_read, server_write) = tokio::io::split(server_wire);
    let delay = Duration::from_micros(56_500);
    let forward = delay_direction(client_read, server_write, delay);
    let backward = delay_direction(server_read, client_write, delay);
    let peer = tokio::spawn(async move {
        let mut connection = server::handshake(server_io).await.unwrap();
        let (_, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(response(StatusCode::OK), false)
            .unwrap();
        let sender = tokio::spawn(async move {
            send_bytes(&mut send, 2 * STREAM_WINDOW).await;
            send.send_data(Bytes::new(), true).unwrap();
        });
        while let Some(exchange) = connection.accept().await {
            exchange.unwrap();
        }
        sender.await.unwrap();
    });
    let client = connect_h2(Box::new(client_io))
        .await
        .unwrap()
        .with_byte_budget(budget_of(MemoryClass::Standard));
    let started = Instant::now();
    let mut body = client
        .send_fixed(
            request(Method::GET, "http://example.test/latency"),
            Bytes::new(),
        )
        .await
        .unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(30), body.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(received.len(), 2 * STREAM_WINDOW);
    assert!(received.iter().all(|byte| *byte == 0xa5));
    // A 64 KiB window needs well over ten seconds; leave ample margin for
    // handshake, WINDOW_UPDATE batching and the bounded simulated link.
    assert!(
        elapsed < Duration::from_secs(2),
        "8 MiB took {elapsed:?} at RTT 113 ms"
    );
    eprintln!("XHTTP/H2: 8 MiB at simulated RTT 113 ms in {elapsed:?}");
    drop(body);
    drop(client);
    peer.abort();
    for task in forward.into_iter().chain(backward) {
        task.abort();
    }
}

const ADAPTIVE: H2ReceiveWindow = H2ReceiveWindow::Adaptive {
    initial: 1024 * 1024,
    max: 4 * 1024 * 1024,
};

/// A client with `window` whose responses are held within `budget`.
async fn pair_over(
    client_io: DuplexStream,
    server_io: DuplexStream,
    window: H2ReceiveWindow,
    budget: &'static ByteBudget,
) -> (H2Client, TestServer) {
    let client = connect_h2_with_window(Box::new(client_io), None, window);
    let server = server::Builder::new().handshake::<_, Bytes>(server_io);
    let (client, server) = tokio::join!(client, server);
    let (request_tx, requests) = mpsc::unbounded_channel();
    let (commands, command_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(drive_server(server.unwrap(), request_tx, command_rx));
    let server = TestServer {
        requests,
        commands: Some(commands),
        driver: Some(driver),
    };
    (client.unwrap().with_byte_budget(budget), server)
}

/// A stalled reader on a constrained host pins the opening window, not Go's.
#[tokio::test(start_paused = true)]
async fn an_adaptive_window_holds_a_stalled_reader_to_its_opening_window() {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let budget = budget_of(MemoryClass::Constrained);
    let (client, mut server) = pair_over(client_io, server_io, ADAPTIVE, budget).await;
    let (body, mut send) = response_pair(&client, &mut server).await;

    timeout(DEADLINE, send_bytes(&mut send, 1024 * 1024))
        .await
        .unwrap();
    assert_blocked(&mut send).await;
    drop(body);
    server.close().await;
}

/// Two pipes joined by a relay that holds every byte for `one_way` in each
/// direction.
fn delayed_link(one_way: Duration) -> (DuplexStream, DuplexStream) {
    let (client, client_side) = tokio::io::duplex(1 << 20);
    let (server_side, server) = tokio::io::duplex(1 << 20);
    let (client_read, client_write) = tokio::io::split(client_side);
    let (server_read, server_write) = tokio::io::split(server_side);
    tokio::spawn(delay(client_read, server_write, one_way));
    tokio::spawn(delay(server_read, client_write, one_way));
    (client, server)
}

async fn delay(
    mut from: impl tokio::io::AsyncRead + Unpin,
    mut to: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    one_way: Duration,
) {
    let (queue, mut queued) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let writer = tokio::spawn(async move {
        while let Some((due, bytes)) = queued.recv().await {
            sleep_until(due).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    let mut buffer = vec![0u8; 64 * 1024];
    while let Ok(read @ 1..) = from.read(&mut buffer).await {
        let _ = queue.send((Instant::now() + one_way, buffer[..read].to_vec()));
    }
    drop(queue);
    let _ = writer.await;
}

/// Reads an 8 MiB response over a 40 ms round trip, under a phone's budget,
/// and returns how long it took on the paused clock.
async fn download_over_a_long_link(window: H2ReceiveWindow) -> Duration {
    const SIZE: usize = 8 * 1024 * 1024;

    let (client_io, server_io) = delayed_link(Duration::from_millis(20));
    let budget = budget_of(MemoryClass::Constrained);
    let (client, mut server) = pair_over(client_io, server_io, window, budget).await;
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    let sender = tokio::spawn(async move {
        send_bytes(&mut send, SIZE).await;
        send.send_data(Bytes::new(), true).unwrap();
    });

    let started = Instant::now();
    let mut received = Vec::with_capacity(SIZE);
    timeout(DEADLINE, body.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(received.len(), SIZE);
    sender.await.unwrap();
    server.close().await;
    elapsed
}

/// A reader that keeps up grows the adaptive window to Go's 4 MiB.
///
/// Held at the opening 1 MiB, the 8 MiB after the first window needs seven
/// more round trips, 280 ms; growing to 4 MiB brings that under five.
#[tokio::test(start_paused = true)]
async fn an_adaptive_window_grows_for_a_reader_that_keeps_up() {
    let fixed = download_over_a_long_link(H2ReceiveWindow::Fixed(1024 * 1024)).await;
    let adaptive = download_over_a_long_link(ADAPTIVE).await;

    assert!(
        fixed >= Duration::from_millis(280),
        "fixed 1 MiB took {fixed:?}"
    );
    assert!(
        adaptive < Duration::from_millis(200),
        "adaptive took {adaptive:?}"
    );
}

/// Under a spent budget a reader's credit waits for its queue: a reader that
/// stops with more than `B` queued keeps the credit of what it read until its
/// reads take the queue within the windows' part of `B` (`B` less the relays'
/// eighth), and then all of it goes back at once.
#[tokio::test(start_paused = true)]
async fn a_reader_that_stops_with_more_than_the_budget_queued_keeps_its_credit_until_it_drains() {
    const WINDOW: usize = 8 * 1024 * 1024;
    const MIB: usize = 1024 * 1024;
    let budget = budget_of(MemoryClass::Constrained);
    let (client, mut server) = pair_with_window(server::Builder::new(), Some(WINDOW as u32)).await;
    let client = client.with_byte_budget(budget);
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, WINDOW))
        .await
        .unwrap();
    assert_blocked(&mut send).await;

    // 6 MiB stay queued, more than the phone's 3 MB: the 2 MiB read wait.
    // The gate holds the windows' part of B and the relays keep B / 8.
    let mut bytes = vec![0; 2 * MIB];
    body.read_exact(&mut bytes).await.unwrap();
    assert_blocked(&mut send).await;
    let usage = budget.usage();
    assert_eq!(
        usage.in_use,
        budget.window_cap(),
        "the queue holds the windows' part of B: {usage:?}"
    );

    // 2 MiB stay queued, within B: the 6 MiB read go back, and no more.
    let mut bytes = vec![0; 4 * MIB];
    body.read_exact(&mut bytes).await.unwrap();
    timeout(DEADLINE, send_bytes(&mut send, 6 * MIB))
        .await
        .expect("a queue within B hands back every byte read");
    assert_blocked(&mut send).await;
    drop(body);
    server.close().await;
}

/// Opens `idle` responses on a fresh connection over a 120 ms round trip with
/// a phone's windows, reads 1 MiB from each and leaves them open; then times
/// a download of `size` on one more, all within a phone's budget of its own.
/// Returns the time and what the budget had taken while only the idle
/// responses were open.
async fn beside_idle_streams(idle: usize, size: usize) -> (Duration, usize) {
    let (client_io, server_io) = delayed_link(Duration::from_millis(60));
    let budget = budget_of(MemoryClass::Constrained);
    let (client, mut server) = pair_over(client_io, server_io, ADAPTIVE, budget).await;
    let mut open = Vec::new();
    for _ in 0..idle {
        let (mut body, mut send) = response_pair(&client, &mut server).await;
        let mut bytes = vec![0; 1024 * 1024];
        let ((), read) = tokio::join!(
            send_bytes(&mut send, bytes.len()),
            body.read_exact(&mut bytes)
        );
        read.unwrap();
        open.push((body, send));
    }
    let held = budget.in_use();

    let (mut body, mut send) = response_pair(&client, &mut server).await;
    let sender = tokio::spawn(async move {
        send_bytes(&mut send, size).await;
        send.send_data(Bytes::new(), true).unwrap();
    });
    let started = Instant::now();
    let mut received = Vec::with_capacity(size);
    timeout(Duration::from_secs(60), body.read_to_end(&mut received))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} of {size} bytes in 60 s beside {idle} idle responses holding {held} B",
                received.len()
            )
        })
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(received.len(), size);
    sender.await.unwrap();
    drop(open);
    server.close().await;
    (elapsed, held)
}

/// Responses that were read and left open, as a messenger's or a browser's
/// keep-alive streams are, hold nothing of the budget: on a phone (3 MB, its
/// 1 MiB opening windows) a download beside four of them runs as fast as one
/// alone, and the relays keep all of `B` for their reads.
#[tokio::test(start_paused = true)]
async fn responses_left_open_after_their_reads_leave_a_new_download_its_speed() {
    const SIZE: usize = 8 * 1024 * 1024;
    let (lone, _) = beside_idle_streams(0, SIZE).await;
    let (beside, held) = beside_idle_streams(4, SIZE).await;
    eprintln!("XHTTP/H2 phone, 8 MiB at RTT 120 ms: alone {lone:?}, beside four idle {beside:?}");
    assert_eq!(held, 0, "four idle responses held {held} B of the budget");
    assert!(
        beside <= lone * 5 / 4,
        "beside four idle responses {beside:?}, alone {lone:?}"
    );
}

/// Eight downloads on one connection, each with Go's 4 MiB window and the
/// connection's 16 MiB between them, under a phone's 3 MB: each reader's
/// credit waits only for its own queue, so every one of them finishes.
#[tokio::test(start_paused = true)]
async fn eight_parallel_downloads_on_one_connection_all_finish_under_a_phone_budget() {
    const STREAMS: usize = 8;
    const SIZE: usize = 6 * 1024 * 1024;
    let budget = budget_of(MemoryClass::Constrained);
    let (client, mut server) = pair().await;
    let client = client.with_byte_budget(budget);
    let mut bodies = Vec::new();
    let mut senders = Vec::new();
    for _ in 0..STREAMS {
        let (body, mut send) = response_pair(&client, &mut server).await;
        bodies.push(body);
        senders.push(tokio::spawn(async move {
            send_bytes(&mut send, SIZE).await;
            send.send_data(Bytes::new(), true).unwrap();
        }));
    }
    let reads = futures_util::future::join_all(bodies.iter_mut().map(|body| async move {
        let mut buffer = vec![0; 16 * 1024];
        let mut total = 0;
        loop {
            match body.read(&mut buffer).await.unwrap() {
                0 => break total,
                read => total += read,
            }
        }
    }));
    let totals = timeout(Duration::from_secs(60), reads)
        .await
        .expect("the downloads stalled");
    assert_eq!(totals, vec![SIZE; STREAMS]);
    for sender in senders {
        sender.await.unwrap();
    }
    let usage = budget.usage();
    assert_eq!(
        usage.in_use, 0,
        "finished downloads still hold the budget: {usage:?}"
    );
    drop(bodies);
    server.close().await;
}

/// A body dropped in the middle of a pressed download hands the credit its
/// reader took, and the budget held back, to the connection at once, though
/// the request's upload half is still open and keeps the stream: another
/// response on the connection can use it. The credit of what was still
/// queued comes back with the stream, once the upload half ends too.
#[tokio::test(start_paused = true)]
async fn a_body_dropped_mid_download_hands_its_withheld_credit_to_the_connection() {
    const WINDOW: usize = 8 * 1024 * 1024;
    const MIB: usize = 1024 * 1024;
    // Far below the queue: every read's credit waits.
    let budget: &'static ByteBudget =
        Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
            capacity: MIB,
            floor: 4 * 1024,
        })));
    let (client, mut server) = pair_with_window(server::Builder::new(), Some(WINDOW as u32)).await;
    let client = client.with_byte_budget(budget);
    let (upload, pending) = client
        .start_streaming(request(Method::POST, "http://example.test/one"))
        .await
        .unwrap();
    let (_, mut respond) = server.accept().await.unwrap().unwrap();
    let mut send = respond
        .send_response(response(StatusCode::OK), false)
        .unwrap();
    let mut body = pending.open().await.unwrap();
    // A second response takes the rest of the connection's 16 MiB.
    let (unread, mut other) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, WINDOW))
        .await
        .unwrap();
    timeout(DEADLINE, send_bytes(&mut other, WINDOW))
        .await
        .unwrap();
    let (_victim_body, mut victim) = response_pair(&client, &mut server).await;
    assert_blocked(&mut victim).await;

    // 4 MiB read and 4 MiB still queued, beyond the budget: their credit
    // waits.
    let mut bytes = vec![0; 4 * MIB];
    body.read_exact(&mut bytes).await.unwrap();
    assert_blocked(&mut victim).await;

    drop(body);
    timeout(DEADLINE, send_bytes(&mut victim, 4 * MIB))
        .await
        .expect("the dropped body's withheld credit reaches the connection");
    assert_blocked(&mut victim).await;
    drop(upload);
    timeout(DEADLINE, send_bytes(&mut victim, 4 * MIB))
        .await
        .expect("the queue's credit comes back with the stream");
    assert_eq!(budget.in_use(), 0, "the dropped body holds nothing");
    drop(unread);
    server.close().await;
}

/// Credit paused readers took under a spent budget goes back once the budget
/// has room for their queues, though neither reads again; and not before.
/// Two responses fill the connection's 16 MiB, their readers take all but
/// 8 KiB each and stop: while `B` is spent, a third response gets nothing,
/// even after a few bytes of `B` come back, fewer than the queues need; once
/// `B` is free it gets its window, and the paused queues hold their bytes of
/// `B`. (When the paused queues themselves fill the windows' part, room in
/// `B` is not enough: the next test.)
#[tokio::test(start_paused = true)]
async fn paused_readers_hand_back_their_withheld_credit_once_the_budget_has_room() {
    const WINDOW: usize = 8 * 1024 * 1024;
    const KIB: usize = 1024;
    const LEFT: usize = 8 * KIB;
    const FLOOR: usize = 4 * KIB;
    let budget: &'static ByteBudget =
        Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
            capacity: 1024 * KIB,
            floor: FLOOR,
        })));
    // Another holder has all of `B`.
    let mut other = xray_transport::memory_budget::BudgetPermits::new(budget);
    assert_eq!(other.try_hold(1024 * KIB), 1024 * KIB);
    let (client, mut server) = pair_with_window(server::Builder::new(), Some(WINDOW as u32)).await;
    let client = client.with_byte_budget(budget);
    let (mut first, mut send_first) = response_pair(&client, &mut server).await;
    let (mut second, mut send_second) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send_first, WINDOW))
        .await
        .unwrap();
    timeout(DEADLINE, send_bytes(&mut send_second, WINDOW))
        .await
        .unwrap();
    // Every byte is queued before a reader starts.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut bytes = vec![0; WINDOW - LEFT];
    first.read_exact(&mut bytes).await.unwrap();
    second.read_exact(&mut bytes).await.unwrap();
    let (_victim_body, mut victim) = response_pair(&client, &mut server).await;
    assert_blocked(&mut victim).await;

    // 2 KiB of `B` come back, less than each queue's 4 KiB beyond the floor:
    // the queues still cannot be held, and their credit stays back.
    assert_eq!(other.try_hold(1022 * KIB), 1022 * KIB);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_blocked(&mut victim).await;
    assert!(
        budget.free() < LEFT - FLOOR,
        "B still has less free than one queue needs: {:?}",
        budget.usage()
    );

    drop(other);
    timeout(DEADLINE, send_bytes(&mut victim, WINDOW))
        .await
        .expect("the paused readers' credit goes back once B has room for their queues");
    assert_eq!(
        budget.in_use(),
        2 * (LEFT - FLOOR),
        "each paused queue holds its bytes beyond the floor"
    );
    drop((first, second));
    assert_eq!(budget.in_use(), 0);
    server.close().await;
}

/// Room in `B` is not enough: a paused stream's credit goes back once the
/// windows' part, less what the other gates hold, covers its queue, so it
/// can wait on another paused stream's reader. Under a 1 MiB budget, whose
/// windows' part is 896 KiB, two responses' readers take all but 600 KiB
/// each and stop. The first queue fits; the second does not fit beside it,
/// and its gate keeps the credit its reader took. Bytes come back to `B`
/// while it has room, and a third response still gets only what the
/// connection has beside that credit; once the first reader, not the
/// second, reads 300 KiB, the second queue fits and the third response gets
/// the rest of its window.
#[tokio::test(start_paused = true)]
async fn a_paused_streams_credit_waits_on_another_paused_streams_reader_while_b_has_room() {
    const WINDOW: usize = 8 * 1024 * 1024;
    /// `connect_h2_with_window`'s connection credit.
    const CONNECTION: usize = 16 * 1024 * 1024;
    const KIB: usize = 1024;
    const FLOOR: usize = 4 * KIB;
    const QUEUE: usize = 600 * KIB;
    let budget: &'static ByteBudget =
        Box::leak(Box::new(ByteBudget::with_settings(ByteBudgetSettings {
            capacity: 1024 * KIB,
            floor: FLOOR,
        })));
    let (client, mut server) = pair_with_window(server::Builder::new(), Some(WINDOW as u32)).await;
    let client = client.with_byte_budget(budget);
    let (mut first, mut send_first) = response_pair(&client, &mut server).await;
    let (mut second, mut send_second) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send_first, WINDOW))
        .await
        .unwrap();
    timeout(DEADLINE, send_bytes(&mut send_second, WINDOW))
        .await
        .unwrap();
    // Every byte is queued before a reader starts.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut bytes = vec![0; WINDOW - QUEUE];
    first.read_exact(&mut bytes).await.unwrap();
    second.read_exact(&mut bytes).await.unwrap();
    let usage = budget.usage();
    assert_eq!(
        usage.window_bytes,
        budget.window_cap(),
        "the first queue's {} KiB beyond the floor and what is left of the windows' part \
         for the second: {usage:?}",
        (QUEUE - FLOOR) / KIB
    );
    assert!(budget.free() > 0, "B has room: {usage:?}");

    // Bytes come back to `B` while it has room: the settler runs a round.
    let mut relay = xray_transport::memory_budget::BudgetPermits::new(budget);
    assert_eq!(relay.try_hold(64 * KIB), 64 * KIB);
    drop(relay);
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (_victim_body, mut victim) = response_pair(&client, &mut server).await;
    // The connection less the two queues and the credit the second holds
    // back, which is the rest of its window.
    timeout(DEADLINE, send_bytes(&mut victim, CONNECTION - QUEUE - WINDOW))
        .await
        .expect("the connection's credit beside the second stream's");
    assert_blocked(&mut victim).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_blocked(&mut victim).await;
    assert!(budget.free() > 0, "B still has room: {:?}", budget.usage());

    // The first reader reads: its queue falls, and the second's fits.
    let mut bytes = vec![0; 300 * KIB];
    first.read_exact(&mut bytes).await.unwrap();
    timeout(DEADLINE, send_bytes(&mut victim, WINDOW - (CONNECTION - QUEUE - WINDOW)))
        .await
        .expect("the second stream's credit goes back once its queue fits");
    assert_blocked(&mut victim).await;
    assert_eq!(
        budget.in_use(),
        (QUEUE - 300 * KIB - FLOOR) + (QUEUE - FLOOR),
        "each paused queue holds its bytes beyond the floor"
    );
    drop((first, second));
    assert_eq!(budget.in_use(), 0);
    server.close().await;
}

/// Mbit/s of `streams` downloads of `each` bytes at once on one connection,
/// through a link that holds every byte 60 ms each way, with a phone's
/// adaptive windows and the process's byte budget, if it has one, at a
/// phone's; `None` if they did not all finish within 20 s. Every response
/// is open before any data is sent.
async fn xhttp_download_at_120ms(streams: usize, each: usize) -> Option<f64> {
    let (client_io, server_io) = delayed_link(Duration::from_millis(60));
    let client = connect_h2_with_window(Box::new(client_io), None, ADAPTIVE);
    let server = server::Builder::new().handshake::<_, Bytes>(server_io);
    let (client, server) = tokio::join!(client, server);
    let client = client.unwrap();
    let (request_tx, requests) = mpsc::unbounded_channel();
    let (commands, command_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(drive_server(server.unwrap(), request_tx, command_rx));
    let mut server = TestServer {
        requests,
        commands: Some(commands),
        driver: Some(driver),
    };
    let mut bodies = Vec::new();
    let mut sends = Vec::new();
    for _ in 0..streams {
        let (body, send) = response_pair(&client, &mut server).await;
        bodies.push(body);
        sends.push(send);
    }
    let started = Instant::now();
    let senders: Vec<_> = sends
        .into_iter()
        .map(|mut send| {
            tokio::spawn(async move {
                send_bytes(&mut send, each).await;
                let _ = send.send_data(Bytes::new(), true);
            })
        })
        .collect();
    let reads = bodies.into_iter().map(|mut body| async move {
        let mut bytes = vec![0; each];
        body.read_exact(&mut bytes).await.is_ok()
    });
    let finished = timeout(
        Duration::from_secs(20),
        futures_util::future::join_all(reads),
    )
    .await
    .is_ok_and(|reads| reads.into_iter().all(|read| read));
    let elapsed = started.elapsed();
    for sender in senders {
        sender.abort();
    }
    drop(client);
    server.close().await;
    let mbit = (streams * each) as f64 * 8.0 / elapsed.as_secs_f64() / 1e6;
    finished.then_some(mbit)
}

/// XHTTP H2 downloads at a simulated 120 ms round trip on a phone: one
/// stream, four and 32 on one connection, each best of three. Numbers for
/// the tables, run by hand with `--ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a benchmark: prints Mbit/s at a simulated 120 ms round trip"]
async fn xhttp_downloads_at_a_120ms_round_trip() {
    const MIB: usize = 1024 * 1024;
    xray_transport::set_memory_class(Some(xray_transport::MemoryClass::Constrained));
    for (streams, each) in [(1, 16 * MIB), (4, 4 * MIB), (32, MIB)] {
        let mut runs = Vec::new();
        for _ in 0..3 {
            runs.push(xhttp_download_at_120ms(streams, each).await);
        }
        let best = runs.iter().flatten().copied().fold(0.0, f64::max);
        let shown: Vec<String> = runs
            .iter()
            .map(|run| match run {
                Some(mbit) => format!("{mbit:.0}"),
                None => "stalled".to_owned(),
            })
            .collect();
        eprintln!(
            "XHTTP-RTT120 streams {streams}: best {best:.0} Mbit/s of [{}]",
            shown.join(", ")
        );
    }
    xray_transport::set_memory_class(None);
}

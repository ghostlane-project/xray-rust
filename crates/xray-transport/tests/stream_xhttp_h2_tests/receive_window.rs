//! Receive credit, backpressure and latency regressions for issue #28, and
//! the same credit under the process's byte budget.
use super::*;
use h2::SendStream;
use tokio::time::{sleep_until, Instant};
use xray_transport::{ByteBudgetSettings, MemoryClass};

const STREAM_WINDOW: usize = 4 * 1024 * 1024;

/// The process has one byte budget for every flow in this binary. The tests
/// here move megabytes through it, so they take turns, each under the budget
/// of the memory class its windows belong to; the binary's other tests move
/// a few kilobytes at a time, within the floor each flow keeps outside it.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A test's turn with the budget; the budget follows the memory class again
/// when the turn ends.
struct BudgetTurn {
    _turn: tokio::sync::MutexGuard<'static, ()>,
}

impl Drop for BudgetTurn {
    fn drop(&mut self) {
        xray_transport::set_byte_budget(None);
    }
}

/// Takes the turn with the process's budget set to `class`'s: 15 MB for a
/// desktop's 4 MiB windows, 3 MB for a phone's adaptive ones.
async fn budget_of(class: MemoryClass) -> BudgetTurn {
    let turn = TURN.lock().await;
    xray_transport::set_byte_budget(Some(ByteBudgetSettings::for_class(class)));
    xray_transport::reset_byte_budget_peak();
    BudgetTurn { _turn: turn }
}

#[tokio::test(start_paused = true)]
async fn configured_receive_windows_bound_unread_data_and_replenish_only_consumed_bytes() {
    let _turn = budget_of(MemoryClass::Standard).await;
    for window in [65535, 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024] {
        let (client, mut server) = pair_with_window(server::Builder::new(), Some(window)).await;
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
    let _turn = budget_of(MemoryClass::Standard).await;
    let (client, mut server) =
        pair_with_window(server::Builder::new(), Some(8 * 1024 * 1024)).await;
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
    let _turn = budget_of(MemoryClass::Standard).await;
    let (client, mut server) = pair().await;
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
    let _turn = budget_of(MemoryClass::Standard).await;
    let (client, mut server) = pair().await;
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
    let _turn = budget_of(MemoryClass::Standard).await;
    let (client, mut server) = pair().await;
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
    let _turn = budget_of(MemoryClass::Standard).await;
    let (client, mut server) = pair().await;
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
    let _turn = budget_of(MemoryClass::Standard).await;
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
    let client = connect_h2(Box::new(client_io)).await.unwrap();
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

async fn pair_over(
    client_io: DuplexStream,
    server_io: DuplexStream,
    window: H2ReceiveWindow,
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
    (client.unwrap(), server)
}

/// A stalled reader on a constrained host pins the opening window, not Go's.
#[tokio::test(start_paused = true)]
async fn an_adaptive_window_holds_a_stalled_reader_to_its_opening_window() {
    let _turn = budget_of(MemoryClass::Constrained).await;
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (client, mut server) = pair_over(client_io, server_io, ADAPTIVE).await;
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

/// Reads an 8 MiB response over a 40 ms round trip and returns how long it
/// took on the paused clock.
async fn download_over_a_long_link(window: H2ReceiveWindow) -> Duration {
    const SIZE: usize = 8 * 1024 * 1024;

    let (client_io, server_io) = delayed_link(Duration::from_millis(20));
    let (client, mut server) = pair_over(client_io, server_io, window).await;
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
    let _turn = budget_of(MemoryClass::Constrained).await;
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
/// reads take the queue down to `B`, and then all of it goes back at once.
#[tokio::test(start_paused = true)]
async fn a_reader_that_stops_with_more_than_the_budget_queued_keeps_its_credit_until_it_drains() {
    const WINDOW: usize = 8 * 1024 * 1024;
    const MIB: usize = 1024 * 1024;
    let _turn = budget_of(MemoryClass::Constrained).await;
    let budget = xray_transport::byte_budget_usage().capacity;
    let (client, mut server) = pair_with_window(server::Builder::new(), Some(WINDOW as u32)).await;
    let (mut body, mut send) = response_pair(&client, &mut server).await;
    timeout(DEADLINE, send_bytes(&mut send, WINDOW))
        .await
        .unwrap();
    assert_blocked(&mut send).await;

    // 6 MiB stay queued, more than the phone's 3 MB: the 2 MiB read wait.
    let mut bytes = vec![0; 2 * MIB];
    body.read_exact(&mut bytes).await.unwrap();
    assert_blocked(&mut send).await;
    let usage = xray_transport::byte_budget_usage();
    assert_eq!(usage.in_use, budget, "the queue holds all of B: {usage:?}");

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
/// a download of `size` on one more. Returns the time and what the budget had
/// taken while only the idle responses were open.
async fn beside_idle_streams(idle: usize, size: usize) -> (Duration, usize) {
    let (client_io, server_io) = delayed_link(Duration::from_millis(60));
    let (client, mut server) = pair_over(client_io, server_io, ADAPTIVE).await;
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
    let held = xray_transport::byte_budget_usage().in_use;

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
    let _turn = budget_of(MemoryClass::Constrained).await;
    let (lone, _) = beside_idle_streams(0, SIZE).await;
    let (beside, held) = beside_idle_streams(4, SIZE).await;
    eprintln!("XHTTP/H2 phone, 8 MiB at RTT 120 ms: alone {lone:?}, beside four idle {beside:?}");
    assert!(
        held <= 64 * 1024,
        "four idle responses held {held} B of the budget"
    );
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
    let _turn = budget_of(MemoryClass::Constrained).await;
    let (client, mut server) = pair().await;
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
    let usage = xray_transport::byte_budget_usage();
    assert!(
        usage.in_use <= 64 * 1024,
        "finished downloads still hold the budget: {usage:?}"
    );
    drop(bodies);
    server.close().await;
}

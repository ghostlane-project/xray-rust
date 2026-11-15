//! Heap that HTTP/2 frame reading and XHTTP request composition keep.
//!
//! A counting global allocator (live bytes, a resettable peak, and the number
//! of allocation calls) measures this test binary. dhat-rs has no peak reset,
//! and only one global allocator may exist per test binary, so this file is a
//! binary of its own and every test takes [`MEASURING`] before it builds its
//! runtime: the counters are process-wide, and libtest runs the tests on
//! threads of their own. The clients run on the test's current-thread
//! runtime; the HTTP/2 servers run on a thread of their own whose heap is not
//! counted (on a phone the server is elsewhere, and the pipe between them
//! stands for kernel socket buffers), so what is measured is the client's.
//!
//! - An idle HTTP/2 connection keeps no read buffer once a download is over:
//!   h2 used to keep a buffer as large as the largest frame it had read.
//! - A burst of 32 packet-up downloads whose readers lag keeps every frame
//!   waiting for its reader in an allocation of its own size, not a share
//!   of a larger read buffer, and peaks under a ceiling set from that.
//! - A packet-up POST costs fewer allocations to compose and convert: the
//!   static header block is built once per transport.
//! - A burst of 32 packet-up uploads peaks lower: a POST is sent from the
//!   chunks its bytes were written into, each freed once it is sent, not
//!   from a joined copy held until the POST's last DATA frame is written.
//! - The request headers, and the DATA frames of POSTs whose chunks end
//!   inside frames, are pinned byte for byte.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::{server, RecvStream};
use http::{Method, Request, Response, StatusCode, Version};
use rand::rngs::mock::StepRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::{timeout, Instant, Sleep};

use xray_transport::stream::xhttp_composer_test_only::{
    NormalizedRange, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpMetadataPlacement,
    XhttpModeSelection, XhttpPaddingPlacement, XhttpRange, XhttpScheme,
};
use xray_transport::stream::xhttp_h2_test_only::{connect_h2_with_window, H2ReceiveWindow};
use xray_transport::stream::xhttp_transport_test_only::{
    XhttpDial, XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy,
};
use xray_transport::stream::HeaderMap;
use xray_transport::{BoxedTransportStream, TransportStream};

/// Counts live heap bytes, their peak, allocation calls, and live bytes by
/// size class, on every thread but the servers'.
struct CountingAllocator;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);
static PEAK_BYTES: AtomicIsize = AtomicIsize::new(0);
static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
/// Size classes: class `c` holds blocks of `2^(c-1) < size <= 2^c` bytes.
const SIZE_CLASSES: usize = 48;
static LIVE_BY_CLASS: [AtomicIsize; SIZE_CLASSES] = [const { AtomicIsize::new(0) }; SIZE_CLASSES];
/// Two allocation sizes watched exactly (0: none), and the live bytes in
/// allocations of each.
static WATCHED_SIZES: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static LIVE_WATCHED: [AtomicIsize; 2] = [const { AtomicIsize::new(0) }; 2];

thread_local! {
    /// Set on the servers' thread: its heap is not the client's. Memory that
    /// thread frees for the client (the pipes, at the end) is not subtracted,
    /// which moves later baselines only.
    static UNCOUNTED: Cell<bool> = const { Cell::new(false) };
}

fn counted() -> bool {
    !UNCOUNTED.try_with(Cell::get).unwrap_or(false)
}

fn size_class(size: usize) -> usize {
    ((usize::BITS - size.saturating_sub(1).leading_zeros()) as usize).min(SIZE_CLASSES - 1)
}

fn add_live(size: usize, sign: isize) {
    let delta = size as isize * sign;
    LIVE_BY_CLASS[size_class(size)].fetch_add(delta, Ordering::Relaxed);
    for (watched, live) in WATCHED_SIZES.iter().zip(&LIVE_WATCHED) {
        if size == watched.load(Ordering::Relaxed) {
            live.fetch_add(delta, Ordering::Relaxed);
        }
    }
    let live = LIVE_BYTES.fetch_add(delta, Ordering::Relaxed) + delta;
    if delta > 0 {
        PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` unchanged and only counts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && counted() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            add_live(layout.size(), 1);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() && counted() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            add_live(layout.size(), 1);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        if counted() {
            add_live(layout.size(), -1);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() && counted() {
            ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            add_live(layout.size(), -1);
            add_live(new_size, 1);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One measurement at a time: the counters are process-wide.
static MEASURING: Mutex<()> = Mutex::new(());

/// Runs one measurement as `#[tokio::test]` would, on a current-thread
/// runtime, but takes [`MEASURING`] before that runtime is built, and starts
/// the servers' runtime first: a runtime built on another test's thread
/// while a measurement runs would be counted in it.
fn measured(test: impl Future<Output = ()>) {
    let _measuring = MEASURING.lock().unwrap_or_else(PoisonError::into_inner);
    server_runtime();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

fn live_bytes() -> isize {
    LIVE_BYTES.load(Ordering::SeqCst)
}

/// Watches allocations of exactly these sizes from now on (0: none).
fn watch_sizes(sizes: [usize; 2]) {
    for (watched, (live, size)) in WATCHED_SIZES.iter().zip(LIVE_WATCHED.iter().zip(sizes)) {
        live.store(0, Ordering::SeqCst);
        watched.store(size, Ordering::SeqCst);
    }
}

/// Live bytes in allocations of each watched size.
fn live_watched() -> [isize; 2] {
    std::array::from_fn(|i| LIVE_WATCHED[i].load(Ordering::SeqCst))
}

fn reset_peak() {
    PEAK_BYTES.store(live_bytes(), Ordering::SeqCst);
}

fn peak_bytes() -> isize {
    PEAK_BYTES.load(Ordering::SeqCst)
}

fn allocation_calls() -> u64 {
    ALLOCATION_CALLS.load(Ordering::SeqCst)
}

fn live_by_class() -> [isize; SIZE_CLASSES] {
    std::array::from_fn(|class| LIVE_BY_CLASS[class].load(Ordering::SeqCst))
}

/// The size classes whose live bytes moved by 1 KiB or more, e.g.
/// `<=16 KiB: +16384`.
fn class_changes(before: &[isize; SIZE_CLASSES], after: &[isize; SIZE_CLASSES]) -> String {
    let mut changes = Vec::new();
    for class in 0..SIZE_CLASSES {
        let moved = after[class] - before[class];
        if moved.abs() >= 1024 {
            let bound = 1_u64 << class;
            let bound = match bound {
                b if b >= 1 << 20 => format!("{} MiB", b >> 20),
                b if b >= 1 << 10 => format!("{} KiB", b >> 10),
                b => format!("{b} B"),
            };
            changes.push(format!("<={bound}: {moved:+}"));
        }
    }
    changes.join(", ")
}

/// The servers' runtime: one worker thread whose heap is not counted.
fn server_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .on_thread_start(|| UNCOUNTED.with(|uncounted| uncounted.set(true)))
            .enable_all()
            .build()
            .unwrap()
    })
}

const DEADLINE: Duration = Duration::from_secs(60);

/// Lets every driver, response task and server task finish what the last
/// exchange left it.
async fn settle() {
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ===== an idle connection after a download =====

/// The download: 4 MiB, from a zeroed static so the server holds no heap copy.
const DOWNLOAD_LEN: usize = 4 << 20;
static DOWNLOAD: [u8; DOWNLOAD_LEN] = [0; DOWNLOAD_LEN];
/// What the read side of an idle connection may keep once a download is
/// over: a frame header's worth of state, nothing sized by the frames read.
const IDLE_READ_LIMIT: isize = 16 * 1024;
/// The frame sizes a server sends the download in: the largest the XHTTP H2
/// client allows (its SETTINGS_MAX_FRAME_SIZE, Go's 1 MiB), and Xray's Go
/// server's own (one DATA frame per 8 KiB `buf.Buffer` it writes).
const DOWNLOAD_FRAMES: [usize; 2] = [1 << 20, 8 * 1024];

#[test]
fn an_idle_h2_connection_keeps_no_read_buffer_after_a_4_mib_download() {
    measured(idle_connection());
}

async fn idle_connection() {
    let mut failures = Vec::new();
    for frame in DOWNLOAD_FRAMES {
        let (retained, classes) = retained_after_download(frame).await;
        eprintln!(
            "idle H2 connection after a {DOWNLOAD_LEN} B download in {frame} B frames: \
             {retained} B kept (limit {IDLE_READ_LIMIT}); by size class: [{classes}]"
        );
        if retained > IDLE_READ_LIMIT {
            failures.push(format!("{frame} B frames: {retained} B"));
        }
    }
    assert!(
        failures.is_empty(),
        "an idle H2 connection keeps more than {IDLE_READ_LIMIT} B after a {DOWNLOAD_LEN} B \
         download: {failures:?}"
    );
}

/// Heap one idle H2 connection keeps after a 4 MiB download, beyond what it
/// kept after a small one, and the size classes it is in.
async fn retained_after_download(frame: usize) -> (isize, String) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = server_runtime().spawn(serve_downloads(server_io, frame));
    let client = connect_h2_with_window(
        Box::new(client_io),
        None,
        H2ReceiveWindow::Fixed(DOWNLOAD_LEN as u32),
    )
    .await
    .unwrap();

    // The small download opens the connection's tables, encoders and slabs:
    // they belong to the baseline, not to the 4 MiB.
    download(&client, 16 * 1024).await;
    settle().await;
    let baseline = live_bytes();
    let baseline_classes = live_by_class();

    download(&client, DOWNLOAD_LEN).await;
    settle().await;
    let retained = live_bytes() - baseline;
    let classes = class_changes(&baseline_classes, &live_by_class());
    drop(client);
    server.abort();
    (retained, classes)
}

async fn download(client: &xray_transport::stream::xhttp_h2_test_only::H2Client, len: usize) {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://example.com/{len}"))
        .version(Version::HTTP_2)
        .body(())
        .unwrap();
    let mut body = timeout(DEADLINE, client.send_fixed(request, Bytes::new()))
        .await
        .expect("the download did not start")
        .unwrap();
    let mut sink = [0_u8; 4096];
    let mut got = 0;
    loop {
        let read = timeout(DEADLINE, body.read(&mut sink))
            .await
            .expect("the download stalled")
            .unwrap();
        if read == 0 {
            break;
        }
        got += read;
    }
    assert_eq!(got, len, "the download ended short");
}

/// An H2 server answering `GET /<len>` with `len` bytes, `frame` at a time.
async fn serve_downloads(io: DuplexStream, frame: usize) {
    let Ok(mut connection) = server::handshake::<_>(io).await else {
        return;
    };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let len: usize = request.uri().path()[1..].parse().unwrap();
        tokio::spawn(async move {
            let Ok(mut body) = respond.send_response(ok_response(), false) else {
                return;
            };
            let mut pieces = DOWNLOAD[..len].chunks(frame).peekable();
            while let Some(piece) = pieces.next() {
                let last = pieces.peek().is_none();
                if body.send_data(Bytes::from_static(piece), last).is_err() {
                    return;
                }
            }
        });
    }
}

fn ok_response() -> Response<()> {
    Response::builder().status(StatusCode::OK).body(()).unwrap()
}

// ===== a burst of packet-up downloads =====

/// The lab's burst (32 downloads at once over three xmux connections), with
/// Xray's Go server's 8 KiB DATA frames. No reader runs until every download
/// has arrived (the clients have read every DATA frame's bytes from their
/// pipes, and then the heap has settled), as on a phone whose readers lag
/// the network: the 32 MiB wait in h2's queues (the stream windows, 4 MiB,
/// and the connection windows, 16 MiB for the 11 flows placed on each, let
/// all of it in), so the peak is what a queued byte costs, and it does not
/// depend on how the readers are timed.
/// With every download queued, every frame is checked to be in an
/// allocation of exactly its own size: the reader's, 8,201 B with its
/// header, for the frame a response passes straight to its queue, or the
/// 8,192 B copy the XHTTP body makes of a frame that waits behind another
/// (`drain_response`). A frame cut from a shared read buffer is neither.
const BURST: usize = 32;
const BURST_DOWN_EACH: usize = 1 << 20;
const GO_SERVER_FRAME: usize = 8 * 1024;
/// Bytes the server may have in flight on one connection's pipe.
const BURST_PIPE: usize = 8 << 20;
/// The xmux connections the burst's 33 flows (the warm-up's and 32) use.
const BURST_CONNECTIONS: usize = 3;
/// Flows a connection is given: xmux's `maxConcurrency`, so the flows fill
/// one connection after another, ceil(33 / 3) = 11 each. With
/// `maxConnections` 3 instead, each flow after the first three draws its
/// connection at random, and one burst in 22 (the chance that a draw puts
/// 17 of the 32 on one connection) asked a connection to hold more unread
/// downloads than its window: its server stopped at 16 MiB, waiting for
/// credit that only a reader gives back, and no reader runs until all has
/// arrived.
const BURST_FLOWS_PER_CONNECTION: usize = (BURST + 1).div_ceil(BURST_CONNECTIONS);
/// The client's HTTP/2 connection receive window
/// (`H2_CONNECTION_RECEIVE_WINDOW`).
const CLIENT_CONNECTION_WINDOW: usize = 16 << 20;
// A connection's flows, the warm-up's counted as if still unread, fit in its
// window: 11 × 1 MiB <= 16 MiB.
const _: () = assert!(BURST_FLOWS_PER_CONNECTION * BURST_DOWN_EACH <= CLIENT_CONNECTION_WINDOW);
/// The DATA frames the burst queues: 32 × 1 MiB / 8 KiB = 4,096.
const BURST_FRAMES: usize = BURST * BURST_DOWN_EACH / GO_SERVER_FRAME;
/// A frame read into an allocation of its own size: its 9-byte header and
/// its payload, 8,201 B.
const FRAME_ALLOCATION: usize = 9 + GO_SERVER_FRAME;
/// The structural part of the peak, at most: every queued frame in an
/// allocation of its own size, 4,096 × 8,201 = 33,591,296 B.
const BURST_FRAME_BYTES: isize = (BURST_FRAMES * FRAME_ALLOCATION) as isize;
/// Everything else the peak may hold, with its margin: the `Bytes` handle
/// each queued frame is held by, the bytes share that splits a frame's
/// header off, 33 flows and three connections (about 50 to 80 KB measured
/// for the warm-up flow and its connection). Measured on the build box:
/// 0.70 to 0.74 MB; 2 MiB is 2.8 times the larger. A reader whose frames share
/// larger buffers fails the exact check on the frames' allocations, not
/// this one.
const BURST_OTHER_LIMIT: isize = 2 << 20;
/// The ceiling on the burst's peak.
const BURST_PEAK_LIMIT: isize = BURST_FRAME_BYTES + BURST_OTHER_LIMIT;

#[test]
fn a_burst_of_32_queued_downloads_keeps_each_frame_in_its_own_allocation() {
    measured(download_burst());
}

async fn download_burst() {
    let server = Arc::new(Server::new(BURST_DOWN_EACH, GO_SERVER_FRAME));
    let dial = server_dial(Arc::clone(&server), BURST_PIPE, None);
    let transport = burst_transport();

    // The peak counts from before the first connection: what the warm-up
    // left behind (h2's tables, a queue's slots, a read buffer) is heap the
    // burst runs on top of, kept or not.
    let baseline = live_bytes();
    let warm = open_flow(&transport, &dial, BURST_DOWN_EACH).await;
    settle().await;
    let idle = live_bytes() - baseline;
    reset_peak();
    watch_sizes([FRAME_ALLOCATION, GO_SERVER_FRAME]);

    let read_before = client_read();
    let mut flows = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        flows.push(open_unread_flow(&transport, &dial).await);
    }
    // Arrival is told by the pipes, not by the code under test: once the
    // clients have read every DATA frame's bytes, at most the last frame's
    // tail (the pipes also carry the responses' HEADERS and the new
    // connections' SETTINGS) is still on its way when the heap settles.
    wait_for_client_read(read_before + BURST_FRAME_BYTES as usize).await;
    let queued = settled_heap().await - baseline;
    let read = client_read() - read_before;
    let [in_read_allocations, in_copies] = live_watched();
    for flow in &mut flows {
        read_download(flow, BURST_DOWN_EACH).await;
    }
    let peak = peak_bytes() - baseline;
    watch_sizes([0, 0]);
    let frames_in_own_allocations =
        in_read_allocations / FRAME_ALLOCATION as isize + in_copies / GO_SERVER_FRAME as isize;
    eprintln!(
        "burst of {BURST} packet-up downloads of {BURST_DOWN_EACH} B in {GO_SERVER_FRAME} B \
         frames, read once all had arrived ({read} B read from the pipes): peak heap {peak} B \
         above the heap before the first connection ({queued} B with every download queued: \
         {in_read_allocations} B in allocations of {FRAME_ALLOCATION} B and {in_copies} B in \
         allocations of {GO_SERVER_FRAME} B, {frames_in_own_allocations} of the {BURST_FRAMES} \
         frames; {idle} B kept by the idle warm-up flow), limit {BURST_PEAK_LIMIT} ({BURST_FRAME_BYTES} B of \
         frames and {BURST_OTHER_LIMIT} B else)"
    );
    drop(flows);
    drop(warm);
    assert_eq!(
        frames_in_own_allocations, BURST_FRAMES as isize,
        "with every download queued, its {BURST_FRAMES} frames are not each in an allocation \
         of their own size ({FRAME_ALLOCATION} B as read, {GO_SERVER_FRAME} B as copied)"
    );
    assert!(
        peak <= BURST_PEAK_LIMIT,
        "the burst peaked at {peak} B; the limit is {BURST_PEAK_LIMIT}"
    );
}

/// The VLESS request header [`open_flow`] sends.
const REQUEST_HEADER_LEN: usize = 64;

/// A packet-up flow that has read its whole download. The VLESS request
/// header goes up first, as a proxied connection's does.
async fn open_flow(
    transport: &XhttpTransport,
    dial: &XhttpDial,
    download_len: usize,
) -> BoxedTransportStream {
    let mut flow = open_unread_flow(transport, dial).await;
    read_download(&mut flow, download_len).await;
    flow
}

/// A packet-up flow that has sent its request header and read nothing.
async fn open_unread_flow(transport: &XhttpTransport, dial: &XhttpDial) -> BoxedTransportStream {
    let mut flow = transport
        .open_stream_with_dial(Arc::clone(dial))
        .await
        .unwrap();
    flow.write_all(&[0x42; REQUEST_HEADER_LEN]).await.unwrap();
    flow.flush().await.unwrap();
    flow
}

/// Waits until the clients have read `bytes` from their pipes in all.
async fn wait_for_client_read(bytes: usize) {
    let arrived = timeout(DEADLINE, async {
        while client_read() < bytes {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(
        arrived.is_ok(),
        "the clients read {} B from their pipes, not the {bytes} B awaited",
        client_read()
    );
}

/// The live heap once it has stopped moving: five 20 ms rounds in a row
/// within 1 KiB of each other.
async fn settled_heap() -> isize {
    timeout(DEADLINE, async {
        let mut last = live_bytes();
        let mut still = 0;
        while still < 5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let now = live_bytes();
            still = if (now - last).abs() < 1024 {
                still + 1
            } else {
                0
            };
            last = now;
        }
        last
    })
    .await
    .expect("the heap never settled")
}

/// Reads `download_len` bytes of `flow`'s download.
async fn read_download(flow: &mut BoxedTransportStream, download_len: usize) {
    let mut sink = vec![0; 32 * 1024];
    let mut left = download_len;
    while left > 0 {
        let read = timeout(DEADLINE, flow.read(&mut sink))
            .await
            .expect("the packet-up download stalled")
            .unwrap();
        assert!(read > 0, "the packet-up download ended early");
        left -= read.min(left);
    }
}

/// The packet-up server: every GET is a downlink of `download` bytes sent
/// `frame` at a time and then kept open; every POST is read and answered.
struct Server {
    download: usize,
    frame: usize,
    posts: AtomicUsize,
    uploaded: AtomicUsize,
    downlinks: Mutex<Vec<h2::SendStream<Bytes>>>,
}

impl Server {
    fn new(download: usize, frame: usize) -> Self {
        Self {
            download,
            frame,
            posts: AtomicUsize::new(0),
            uploaded: AtomicUsize::new(0),
            downlinks: Mutex::new(Vec::new()),
        }
    }

    async fn wait_for_uploaded(&self, bytes: usize) {
        timeout(DEADLINE, async {
            while self.uploaded.load(Ordering::Acquire) < bytes {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the server did not receive every uploaded byte");
    }

    async fn wait_for_posts(&self, posts: usize) {
        timeout(DEADLINE, async {
            while self.posts.load(Ordering::Acquire) < posts {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the server did not answer every POST");
    }
}

/// Dials an in-process H2 server over a pipe of `pipe` bytes; with
/// `record`, every byte the client writes is appended to it.
fn server_dial(server: Arc<Server>, pipe: usize, record: Option<Arc<Mutex<Vec<u8>>>>) -> XhttpDial {
    windowed_server_dial(server, pipe, None, record)
}

/// [`server_dial`] with the server's stream and connection windows set to
/// `windows` (h2's 65,535 B when `None`).
fn windowed_server_dial(
    server: Arc<Server>,
    pipe: usize,
    windows: Option<u32>,
    record: Option<Arc<Mutex<Vec<u8>>>>,
) -> XhttpDial {
    Arc::new(move || {
        let server = Arc::clone(&server);
        let (client, server_io) = tokio::io::duplex(pipe);
        spawn_server(Arc::clone(&server), server_io, windows);
        let client: BoxedTransportStream = Box::new(ClientIo {
            io: client,
            writes: record.clone(),
        });
        Box::pin(async move { Ok(client) })
    })
}

/// Serves one connection on the servers' thread, with the server's stream
/// and connection windows set to `windows` (h2's 65,535 B when `None`).
fn spawn_server(server: Arc<Server>, io: DuplexStream, windows: Option<u32>) {
    server_runtime().spawn(async move {
        let mut builder = server::Builder::new();
        if let Some(windows) = windows {
            builder
                .initial_window_size(windows)
                .initial_connection_window_size(windows);
        }
        let Ok(mut connection) = builder.handshake::<_, Bytes>(io).await else {
            return;
        };
        while let Some(Ok((request, respond))) = connection.accept().await {
            tokio::spawn(serve(Arc::clone(&server), request, respond));
        }
    });
}

async fn serve(
    server: Arc<Server>,
    request: http::Request<RecvStream>,
    mut respond: server::SendResponse<Bytes>,
) {
    if request.method() == Method::GET {
        let Ok(mut downlink) = respond.send_response(ok_response(), false) else {
            return;
        };
        for piece in DOWNLOAD[..server.download].chunks(server.frame) {
            if downlink
                .send_data(Bytes::from_static(piece), false)
                .is_err()
            {
                return;
            }
        }
        server.downlinks.lock().unwrap().push(downlink);
        return;
    }
    let mut body = request.into_body();
    while let Some(Ok(chunk)) = body.data().await {
        server.uploaded.fetch_add(chunk.len(), Ordering::AcqRel);
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let _ = respond.send_response(ok_response(), true);
    server.posts.fetch_add(1, Ordering::AcqRel);
}

/// The app's packet-up shape: Xray's defaults (padding 100-1000,
/// `scMaxBufferedPosts` 30, `scMinPostsIntervalMs` 30, the Chrome
/// masquerade) at the app's `scMaxEachPostBytes` 200000 and three xmux
/// connections. `headers` replaces the configured headers, and pins the RNG.
fn app_shaped_transport(headers: Option<HeaderMap>) -> XhttpTransport {
    let mut input = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        sc_max_each_post_bytes: XhttpRange::exact(200_000),
        ..XhttpConfigInput::default()
    };
    let pinned = headers.is_some();
    if let Some(headers) = headers {
        input.headers = headers;
    }
    let config = XhttpConfig::normalize(input).unwrap();
    transport_for(config, 3, pinned)
}

/// [`app_shaped_transport`] with its flows placed
/// [`BURST_FLOWS_PER_CONNECTION`] to a connection.
fn burst_transport() -> XhttpTransport {
    let config = XhttpConfig::normalize(XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        sc_max_each_post_bytes: XhttpRange::exact(200_000),
        ..XhttpConfigInput::default()
    })
    .unwrap();
    xmux_transport(config, BURST_FLOWS_PER_CONNECTION as i32, 0, false)
}

fn transport_for(config: XhttpConfig, connections: i32, pinned_rng: bool) -> XhttpTransport {
    xmux_transport(config, 0, connections, pinned_rng)
}

/// A transport whose xmux has `maxConcurrency` `concurrency` and
/// `maxConnections` `connections` (0: no limit).
fn xmux_transport(
    config: XhttpConfig,
    concurrency: i32,
    connections: i32,
    pinned_rng: bool,
) -> XhttpTransport {
    let endpoint = XhttpEndpoint::new(XhttpScheme::Https, "example.com").unwrap();
    let xmux = XhttpXmuxPolicy {
        max_concurrency: XhttpRange::exact(concurrency),
        max_connections: XhttpRange::exact(connections),
        c_max_reuse_times: XhttpRange::exact(0),
        h_max_request_times: XhttpRange::exact(0),
        h_max_reusable_secs: XhttpRange::exact(0),
        h_keep_alive_period_secs: 0,
    };
    let transport = XhttpTransport::new(config, endpoint, XhttpHttpVersion::Http2, xmux).unwrap();
    if pinned_rng {
        transport
            .with_rng(Box::new(StepRng::new(0x0102_0304_0506_0708, 0x1111_1111)))
            .unwrap()
    } else {
        transport
    }
}

// ===== a burst of packet-up uploads =====

/// The lab's upload burst: 32 flows each write 1 MiB in 32 KiB writes as
/// fast as their pipes take them, over three xmux connections whose uplink
/// is throttled to 2 MB/s each (about the lab's 44 Mbit/s in all), to a
/// server with Go's 1 MiB stream and connection windows.
const UP_EACH: usize = 1 << 20;
const UP_WRITE: usize = 32 * 1024;
static UP_WRITE_BYTES: [u8; UP_WRITE] = [0x55; UP_WRITE];
const UPLINK_RATE: f64 = 2_000_000.0;
const GO_SERVER_WINDOW: u32 = 1 << 20;
/// The ceiling on the upload burst's peak. Measured on the build box: 22.15
/// and 22.54 MB when each POST was joined into one allocation, held whole
/// until its last DATA frame was written; 16.88 to 17.23 MB sent from its
/// chunks, each freed once sent. 19 MiB lies between them.
const UPLOAD_BURST_PEAK_LIMIT: isize = 19 << 20;

#[test]
fn a_burst_of_32_packet_up_uploads_peaks_lower() {
    measured(upload_burst());
}

async fn upload_burst() {
    let server = Arc::new(Server::new(16, 16));
    let dial = throttled_server_dial(Arc::clone(&server), UPLINK_RATE);
    let transport = app_shaped_transport(None);

    // As in the download burst, the peak counts from before the first
    // connection.
    let baseline = live_bytes();
    let warm = open_flow(&transport, &dial, 16).await;
    server.wait_for_posts(1).await;
    settle().await;
    let idle = live_bytes() - baseline;
    let uploaded_before = server.uploaded.load(Ordering::Acquire);
    reset_peak();

    let mut uploads = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let transport = transport.clone();
        let dial = Arc::clone(&dial);
        uploads.spawn(async move {
            let mut flow = open_flow(&transport, &dial, 16).await;
            let mut left = UP_EACH;
            while left > 0 {
                let piece = UP_WRITE.min(left);
                flow.write_all(&UP_WRITE_BYTES[..piece]).await.unwrap();
                left -= piece;
            }
            flow.flush().await.unwrap();
            flow
        });
    }
    let mut flows = Vec::with_capacity(BURST);
    while let Some(done) = timeout(DEADLINE, uploads.join_next())
        .await
        .expect("the upload burst stalled")
    {
        flows.push(done.unwrap());
    }
    server
        .wait_for_uploaded(uploaded_before + BURST * (UP_EACH + REQUEST_HEADER_LEN))
        .await;
    let peak = peak_bytes() - baseline;
    eprintln!(
        "burst of {BURST} packet-up uploads of {UP_EACH} B in {UP_WRITE} B writes at \
         {UPLINK_RATE} B/s a connection: peak heap {peak} B above the heap before the first \
         connection ({idle} B of it kept by the idle warm-up flow), limit \
         {UPLOAD_BURST_PEAK_LIMIT}"
    );
    drop(flows);
    drop(warm);
    assert!(
        peak <= UPLOAD_BURST_PEAK_LIMIT,
        "the upload burst peaked at {peak} B; the limit is {UPLOAD_BURST_PEAK_LIMIT}"
    );
}

/// Like [`server_dial`], with Go's server windows and the client's writes
/// limited to `rate` bytes a second.
fn throttled_server_dial(server: Arc<Server>, rate: f64) -> XhttpDial {
    Arc::new(move || {
        let (client, server_io) = tokio::io::duplex(256 * 1024);
        spawn_server(Arc::clone(&server), server_io, Some(GO_SERVER_WINDOW));
        let client = Throttled {
            inner: client,
            rate,
            next_free: Instant::now(),
            wait: None,
        };
        Box::pin(async move { Ok(Box::new(client) as BoxedTransportStream) })
    })
}

/// A client stream whose writes go out at `rate` bytes a second.
struct Throttled {
    inner: DuplexStream,
    rate: f64,
    next_free: Instant,
    wait: Option<Pin<Box<Sleep>>>,
}

impl AsyncRead for Throttled {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}

impl AsyncWrite for Throttled {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Some(wait) = self.wait.as_mut() {
                ready!(wait.as_mut().poll(cx));
                self.wait = None;
            }
            let now = Instant::now();
            if self.next_free > now {
                self.wait = Some(Box::pin(tokio::time::sleep_until(self.next_free)));
                continue;
            }
            let piece = input.len().min(16 * 1024);
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &input[..piece]))?;
            let spent = Duration::from_secs_f64(written as f64 / self.rate);
            self.next_free = self.next_free.max(now) + spent;
            return Poll::Ready(Ok(written));
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TransportStream for Throttled {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

// ===== allocations per POST =====

/// POSTs counted together.
const POSTS: u64 = 200;
/// A packet's payload: a typical small upload.
const POST_PAYLOAD: usize = 1200;
/// Allocation calls one POST may cost to compose and convert into its H2
/// request, the payload not included. Measured: 123 when every POST
/// masqueraded and converted every header again, 25 from the transport's
/// template; 40 leaves room for a few more fields.
const ALLOCATIONS_PER_POST_LIMIT: u64 = 40;

#[test]
fn a_packet_post_is_composed_with_few_allocations() {
    measured(post_allocations());
}

async fn post_allocations() {
    let transport = app_shaped_transport(None);
    // The first POST resolves the browser versions, once per process.
    drop(
        transport
            .h2_packet_request_for_test("session", 0, vec![0x55; POST_PAYLOAD])
            .unwrap(),
    );
    let payloads: Vec<Vec<u8>> = (0..POSTS).map(|_| vec![0x55; POST_PAYLOAD]).collect();

    let before = allocation_calls();
    for (sequence, payload) in (1..).zip(payloads) {
        let request = transport
            .h2_packet_request_for_test("session", sequence, payload)
            .unwrap();
        drop(request);
    }
    let per_post = (allocation_calls() - before) / POSTS;
    eprintln!(
        "one packet-up POST: {per_post} allocation calls to compose and convert \
         (limit {ALLOCATIONS_PER_POST_LIMIT})"
    );
    assert!(
        per_post <= ALLOCATIONS_PER_POST_LIMIT,
        "a packet-up POST costs {per_post} allocation calls; the limit is \
         {ALLOCATIONS_PER_POST_LIMIT}"
    );
}

// ===== the request headers on the wire =====

/// POSTs each wire case sends.
const WIRE_POSTS: usize = 6;

/// The HEADERS frames a packet-up flow writes (its GET, then one POST per
/// upload), compared byte for byte with what the code wrote before the
/// static header block was cached. The configured User-Agent turns the
/// browser masquerade off, whose versions are drawn once per process, so
/// these bytes are the same in every run.
#[test]
fn packet_up_request_headers_on_the_wire_are_unchanged() {
    measured(request_headers_on_the_wire());
}

async fn request_headers_on_the_wire() {
    let mut changed = Vec::new();
    for (name, config, expected) in wire_cases() {
        let headers = wire_headers(config).await;
        let digest = fnv1a(&headers);
        eprintln!(
            "wire case {name}: {} B of HEADERS, digest {digest:#018x}",
            headers.len()
        );
        if (headers.len(), digest) != expected {
            changed.push(name);
        }
    }
    assert!(
        changed.is_empty(),
        "the request headers changed on the wire in {changed:?}"
    );
}

/// (name, config, (HEADERS bytes, FNV-1a of them)) recorded before the change.
fn wire_cases() -> Vec<(&'static str, XhttpConfig, (usize, u64))> {
    let mut plain = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        ..XhttpConfigInput::default()
    };
    plain.headers.set("User-Agent", "wire-test");
    plain.headers.set("X-Static", "kept");

    // Static headers that the per-request ones meet: a Referer the padding
    // replaces in place, a Cookie the session cookie joins, and padding,
    // session and sequence in a header, a cookie and the query.
    let mut colliding = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api?static=1".to_owned(),
        x_padding_obfs_mode: true,
        x_padding_key: "pad".to_owned(),
        x_padding_header: "Referer".to_owned(),
        x_padding_placement: XhttpPaddingPlacement::Header,
        session_placement: XhttpMetadataPlacement::Cookie,
        session_key: "sid".to_owned(),
        seq_placement: XhttpMetadataPlacement::Query,
        seq_key: "seq".to_owned(),
        ..XhttpConfigInput::default()
    };
    colliding.headers.set("User-Agent", "wire-test");
    colliding
        .headers
        .set("Referer", "https://example.com/static");
    colliding.headers.set("Cookie", "static=1");
    colliding.headers.set("Accept-Encoding", "");

    let mut in_headers = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        x_padding_obfs_mode: true,
        x_padding_key: "pad".to_owned(),
        x_padding_header: "X-Pad".to_owned(),
        x_padding_placement: XhttpPaddingPlacement::Cookie,
        session_placement: XhttpMetadataPlacement::Header,
        session_key: "X-Session".to_owned(),
        seq_placement: XhttpMetadataPlacement::Header,
        seq_key: "X-Seq".to_owned(),
        ..XhttpConfigInput::default()
    };
    in_headers.headers.set("User-Agent", "wire-test");
    in_headers.headers.set("X-Session", "static");

    let normalize = |input: XhttpConfigInput| {
        let mut config = XhttpConfig::normalize(input).unwrap();
        config.min_posts_interval_ms = NormalizedRange::exact(0);
        config
    };
    vec![
        ("plain", normalize(plain), (4247, 0x2cf1_02cc_9161_d3be)),
        (
            "colliding",
            normalize(colliding),
            (4211, 0x97fc_b44b_4158_f263),
        ),
        (
            "in-headers",
            normalize(in_headers),
            (3950, 0xfb89_def9_1c70_86a6),
        ),
    ]
}

/// The HEADERS and CONTINUATION frames, header and payload, that one
/// packet-up flow of `config` writes for its GET and `WIRE_POSTS` uploads.
async fn wire_headers(config: XhttpConfig) -> Vec<u8> {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let server = Arc::new(Server::new(16, 16));
    let dial = server_dial(Arc::clone(&server), 64 * 1024, Some(Arc::clone(&writes)));
    let transport = transport_for(config, 1, true);
    let mut flow = transport
        .open_stream_with_dial(Arc::clone(&dial))
        .await
        .unwrap();
    for post in 0..WIRE_POSTS {
        flow.write_all(&vec![0x30 + post as u8; 100 + post * 50])
            .await
            .unwrap();
        flow.flush().await.unwrap();
        server.wait_for_posts(post + 1).await;
    }
    let mut download = [0; 16];
    timeout(DEADLINE, flow.read_exact(&mut download))
        .await
        .expect("the downlink did not arrive")
        .unwrap();
    drop(flow);
    let writes = writes.lock().unwrap();
    header_frames(&writes)
}

/// One POST's writes: a header-sized write and a large one share an 8 KiB
/// chunk, small writes gather into another, so the POST's chunks end inside
/// its 16 KiB DATA frames, one frame spans three chunks, and the last chunk
/// has spare room.
const DATA_WIRE_WRITES: [usize; 7] = [64, 40_000, 1_000, 1_000, 1_000, 33_000, 7];
const DATA_WIRE_POSTS: usize = 3;
/// The DATA payload lengths: the flow's request header, then each POST's
/// 76,071 B cut at 16,384 (`MAX_UPLOAD_DATA_BYTES`, every grant whole under
/// Go's 1 MiB windows).
const DATA_WIRE_LENS: [usize; 16] = [
    64, 16_384, 16_384, 16_384, 16_384, 10_535, 16_384, 16_384, 16_384, 16_384, 10_535, 16_384,
    16_384, 16_384, 16_384, 10_535,
];
/// (DATA frame bytes, FNV-1a of them) recorded before the change.
const DATA_WIRE_EXPECTED: (usize, u64) = (228_421, 0x8a0a_6b54_e278_deac);

/// The DATA frames a packet-up flow writes for its POSTs, header and payload,
/// compared byte for byte with what the code wrote when it sent a joined
/// copy of each payload.
#[test]
fn packet_up_data_frames_on_the_wire_are_unchanged() {
    measured(data_frames_on_the_wire());
}

async fn data_frames_on_the_wire() {
    let mut input = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        ..XhttpConfigInput::default()
    };
    input.headers.set("User-Agent", "wire-test");
    let mut config = XhttpConfig::normalize(input).unwrap();
    config.min_posts_interval_ms = NormalizedRange::exact(0);

    let writes = Arc::new(Mutex::new(Vec::new()));
    let server = Arc::new(Server::new(16, 16));
    let dial = windowed_server_dial(
        Arc::clone(&server),
        1 << 20,
        Some(GO_SERVER_WINDOW),
        Some(Arc::clone(&writes)),
    );
    let transport = transport_for(config, 1, true);
    // The download is read once the server's SETTINGS and window are in.
    let mut flow = open_flow(&transport, &dial, 16).await;
    server.wait_for_posts(1).await;
    for post in 0..DATA_WIRE_POSTS {
        // Written without a pause, so the worker takes them as one POST.
        for (index, len) in DATA_WIRE_WRITES.into_iter().enumerate() {
            let byte = (post * DATA_WIRE_WRITES.len() + index) as u8;
            flow.write_all(&vec![byte; len]).await.unwrap();
        }
        flow.flush().await.unwrap();
        server.wait_for_posts(post + 2).await;
    }
    drop(flow);

    let (frames, lens) = frames_of(&writes.lock().unwrap(), &[FRAME_DATA]);
    let digest = fnv1a(&frames);
    eprintln!(
        "wire DATA frames: {} B, digest {digest:#018x}, payload lengths {lens:?}",
        frames.len()
    );
    assert_eq!(
        lens, DATA_WIRE_LENS,
        "the POSTs' DATA frames were cut elsewhere"
    );
    assert_eq!(
        (frames.len(), digest),
        DATA_WIRE_EXPECTED,
        "the POSTs' DATA frames changed on the wire"
    );
}

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_CONTINUATION: u8 = 0x9;

fn header_frames(writes: &[u8]) -> Vec<u8> {
    frames_of(writes, &[FRAME_HEADERS, FRAME_CONTINUATION]).0
}

/// The client's frames of the given types, header and payload, one after
/// another, and their payload lengths.
fn frames_of(writes: &[u8], kinds: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut offset = if writes.starts_with(CLIENT_PREFACE) {
        CLIENT_PREFACE.len()
    } else {
        0
    };
    let mut frames = Vec::new();
    let mut lens = Vec::new();
    while offset + 9 <= writes.len() {
        let payload = usize::from(writes[offset]) << 16
            | usize::from(writes[offset + 1]) << 8
            | usize::from(writes[offset + 2]);
        let end = offset + 9 + payload;
        assert!(end <= writes.len(), "a client frame was cut short");
        if kinds.contains(&writes[offset + 3]) {
            frames.extend_from_slice(&writes[offset..end]);
            lens.push(payload);
        }
        offset = end;
    }
    (frames, lens)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Bytes every client stream has read from its pipe.
static CLIENT_READ: AtomicUsize = AtomicUsize::new(0);

fn client_read() -> usize {
    CLIENT_READ.load(Ordering::Acquire)
}

/// A client stream that counts the bytes read from it in [`CLIENT_READ`]
/// and, with `writes`, keeps a copy of everything written to it.
struct ClientIo {
    io: DuplexStream,
    writes: Option<Arc<Mutex<Vec<u8>>>>,
}

impl AsyncRead for ClientIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = output.filled().len();
        let read = Pin::new(&mut self.io).poll_read(cx, output);
        CLIENT_READ.fetch_add(output.filled().len() - before, Ordering::AcqRel);
        read
    }
}

impl AsyncWrite for ClientIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = match Pin::new(&mut self.io).poll_write(cx, input) {
            Poll::Ready(Ok(written)) => written,
            other => return other,
        };
        if let Some(writes) = &self.writes {
            writes.lock().unwrap().extend_from_slice(&input[..written]);
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl TransportStream for ClientIo {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

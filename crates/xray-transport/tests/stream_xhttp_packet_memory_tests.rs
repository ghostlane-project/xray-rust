// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
//! Heap a packet-up flow keeps while it only downloads or sits idle.
//!
//! Xray's packet-up uplink is a pipe of pooled 8 KiB buffers
//! (`splithttp/dialer.go`): a flow holds memory for the bytes waiting to be
//! POSTed and nothing more, so `scMaxEachPostBytes` bounds a POST, not what
//! every flow keeps. These tests count the live heap of this test binary with
//! a counting global allocator and check that what an idle or download-only
//! flow keeps does not grow with `scMaxEachPostBytes`, before and after the
//! flow has uploaded more than one POST's worth.
//!
//! The global allocator counts the whole process, so the tests take turns
//! (`MEASURING`) and every flow, the H2 server included, runs on the test's
//! current-thread runtime.

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::{server, RecvStream};
use http::{Method, Response, StatusCode};
use rand::rngs::mock::StepRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::time::{timeout, Instant, Sleep};

use xray_transport::stream::xhttp_composer_test_only::{
    NormalizedRange, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpModeSelection, XhttpRange,
    XhttpScheme,
};
use xray_transport::stream::xhttp_transport_test_only::{
    XhttpDial, XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy,
};
use xray_transport::{BoxedTransportStream, TransportStream};

/// Counts the bytes of every live heap allocation, and their peak.
struct CountingAllocator;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);
static PEAK_BYTES: AtomicIsize = AtomicIsize::new(0);

fn add_live(delta: isize) {
    let live = LIVE_BYTES.fetch_add(delta, Ordering::Relaxed) + delta;
    if delta > 0 {
        PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` unchanged and only counts sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add_live(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            add_live(layout.size() as isize);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        add_live(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            add_live(new_size as isize - layout.size() as isize);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One measurement at a time: the counter is process-wide.
static MEASURING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const DEADLINE: Duration = Duration::from_secs(30);
/// The flows measured together; the H2 connection's own buffers are shared
/// by all of them and largely sit in the baseline.
const FLOWS: usize = 8;
/// Large enough that one POST-sized buffer per flow dwarfs everything else a
/// flow legitimately keeps (its H2 streams, tasks and request headers).
const MAX_POST: usize = 1_000_000;
/// What a flow may keep, with room for that legitimate state: an eighth of
/// one POST.
const PER_FLOW_LIMIT: isize = (MAX_POST / 8) as isize;
/// The VLESS request header a proxied connection sends before it downloads.
const REQUEST_HEADER: [u8; 64] = [0x42; 64];
const DOWNLOAD_LEN: usize = 16 * 1024;
static DOWNLOAD: [u8; DOWNLOAD_LEN] = [0x44; DOWNLOAD_LEN];

#[tokio::test]
async fn download_only_packet_up_flows_keep_no_post_sized_upload_buffer() {
    let _measuring = MEASURING.lock().await;
    let server = Arc::new(Server::default());
    let dial = server_dial(Arc::clone(&server));
    let transport = packet_up_transport(MAX_POST);

    // The first flow opens the H2 connection and the xmux client; both are
    // shared, so they belong to the baseline, not to any one flow.
    let warm = open_downloading_flow(&transport, &dial).await;
    server.wait_for_posts(1).await;
    settle().await;
    let baseline = live_bytes();

    let mut flows = Vec::with_capacity(FLOWS);
    for _ in 0..FLOWS {
        flows.push(open_downloading_flow(&transport, &dial).await);
    }
    server.wait_for_posts(1 + FLOWS).await;
    settle().await;

    let per_flow = (live_bytes() - baseline) / FLOWS as isize;
    eprintln!(
        "download-only packet-up flow: {per_flow} bytes of heap each \
         (scMaxEachPostBytes {MAX_POST}, limit {PER_FLOW_LIMIT})"
    );
    assert!(
        per_flow < PER_FLOW_LIMIT,
        "a download-only packet-up flow keeps {per_flow} bytes of heap; \
         with scMaxEachPostBytes {MAX_POST} it may keep under {PER_FLOW_LIMIT}"
    );
    drop(flows);
    drop(warm);
}

#[tokio::test]
async fn packet_up_flows_release_their_upload_buffers_once_the_posts_are_sent() {
    let _measuring = MEASURING.lock().await;
    let server = Arc::new(Server::default());
    let dial = server_dial(Arc::clone(&server));
    let transport = packet_up_transport(MAX_POST);

    let warm = open_downloading_flow(&transport, &dial).await;
    server.wait_for_posts(1).await;
    settle().await;
    let baseline = live_bytes();

    // One and a half POSTs each: a full one and a partial one, then idle.
    let upload = vec![0x55; MAX_POST + MAX_POST / 2];
    let mut flows = Vec::with_capacity(FLOWS);
    for _ in 0..FLOWS {
        let mut flow = open_downloading_flow(&transport, &dial).await;
        flow.write_all(&upload).await.unwrap();
        flow.flush().await.unwrap();
        flows.push(flow);
    }
    drop(upload);
    server
        .wait_for_uploaded(REQUEST_HEADER.len() * (1 + FLOWS) + FLOWS * (MAX_POST + MAX_POST / 2))
        .await;
    settle().await;

    let per_flow = (live_bytes() - baseline) / FLOWS as isize;
    eprintln!(
        "packet-up flow idle after uploading {} bytes: {per_flow} bytes of heap each \
         (scMaxEachPostBytes {MAX_POST}, limit {PER_FLOW_LIMIT})",
        MAX_POST + MAX_POST / 2
    );
    assert!(
        per_flow < PER_FLOW_LIMIT,
        "an idle packet-up flow keeps {per_flow} bytes of heap after its POSTs were sent; \
         with scMaxEachPostBytes {MAX_POST} it may keep under {PER_FLOW_LIMIT}"
    );
    drop(flows);
    drop(warm);
}

/// The lab's burst (`run_burst`: 32 downloads at once, then 32 uploads at
/// once, one connection each) through packet-up at the app's
/// `scMaxEachPostBytes` 200000 and three xmux connections, with the client's
/// writes throttled so POSTs queue behind the uplink as they do on a phone,
/// and the server's H2 windows set to Go's (1 MiB). Prints the peak heap above
/// the idle baseline in each half. A measurement, not an assertion:
///
/// ```text
/// cargo test -p xray-transport --test stream_xhttp_packet_memory_tests -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "heap measurement, run explicitly"]
async fn burst_peak_heap_at_the_apps_post_size() {
    const APP_MAX_POST: usize = 200_000;
    const BURST: usize = 32;
    const DOWN_EACH: usize = 1 << 20;
    const UP_EACH: usize = 1 << 20;
    /// Bytes a second the client may write on each of its three
    /// connections: about the lab's 44 Mbit/s upload in all.
    const UPLINK_RATE: f64 = 2_000_000.0;

    let _measuring = MEASURING.lock().await;
    let server = Arc::new(Server::default());
    let dial = throttled_server_dial(Arc::clone(&server), UPLINK_RATE);
    let transport = app_shaped_transport(APP_MAX_POST);
    let warm = open_downloading_flow(&transport, &dial).await;
    server.wait_for_posts(1).await;
    settle().await;
    let baseline = live_bytes();

    // Downloads: each flow sends its request header and reads its download.
    server.extra_download.store(DOWN_EACH, Ordering::Release);
    reset_peak();
    let mut downloads = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let transport = transport.clone();
        let dial = Arc::clone(&dial);
        downloads.spawn(async move {
            let mut flow = open_downloading_flow(&transport, &dial).await;
            let mut sink = vec![0; 32 * 1024];
            let mut left = DOWN_EACH;
            while left > 0 {
                let read = flow.read(&mut sink).await.unwrap();
                assert!(read > 0, "a burst download ended early");
                left -= read.min(left);
            }
        });
    }
    while let Some(done) = timeout(DEADLINE, downloads.join_next())
        .await
        .expect("the download burst stalled")
    {
        done.unwrap();
    }
    let down_peak = peak_bytes() - baseline;
    server.extra_download.store(0, Ordering::Release);
    settle().await;

    // Uploads: each flow writes its upload as fast as the pipe takes it.
    reset_peak();
    let before = server.uploaded.load(Ordering::Acquire);
    let mut uploads = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let transport = transport.clone();
        let dial = Arc::clone(&dial);
        uploads.spawn(async move {
            let mut flow = open_downloading_flow(&transport, &dial).await;
            let chunk = vec![0x55; 32 * 1024];
            let mut left = UP_EACH;
            while left > 0 {
                let piece = chunk.len().min(left);
                flow.write_all(&chunk[..piece]).await.unwrap();
                left -= piece;
            }
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
        .wait_for_uploaded(before + BURST * (UP_EACH + REQUEST_HEADER.len()))
        .await;
    let up_peak = peak_bytes() - baseline;

    eprintln!(
        "burst at scMaxEachPostBytes {APP_MAX_POST}: {BURST} x {DOWN_EACH} B down, peak heap \
         {down_peak} B above idle ({} B a flow); {BURST} x {UP_EACH} B up, peak heap {up_peak} B \
         above idle ({} B a flow)",
        down_peak / BURST as isize,
        up_peak / BURST as isize
    );
    drop(flows);
    drop(warm);
}

/// One flow pushing 64 MiB through packet-up with no pacing and no throttle,
/// so the rate is what the uplink's copies and H2 framing cost. Prints MB/s;
/// compare builds of the same profile only. A measurement, not an assertion.
#[tokio::test]
#[ignore = "throughput measurement, run explicitly"]
async fn unpaced_single_flow_upload_rate() {
    const APP_MAX_POST: usize = 200_000;
    const UPLOAD: usize = 64 << 20;

    let _measuring = MEASURING.lock().await;
    let server = Arc::new(Server::default());
    let dial = throttled_server_dial(Arc::clone(&server), f64::INFINITY);
    let transport = packet_up_transport(APP_MAX_POST);
    let mut flow = open_downloading_flow(&transport, &dial).await;
    server.wait_for_posts(1).await;
    let before = server.uploaded.load(Ordering::Acquire);

    let chunk = vec![0x55; 32 * 1024];
    let started = Instant::now();
    let mut left = UPLOAD;
    while left > 0 {
        let piece = chunk.len().min(left);
        flow.write_all(&chunk[..piece]).await.unwrap();
        left -= piece;
    }
    server.wait_for_uploaded(before + UPLOAD).await;
    let elapsed = started.elapsed();
    eprintln!(
        "unpaced packet-up upload at scMaxEachPostBytes {APP_MAX_POST}: {UPLOAD} B in {:.3} s, \
         {:.1} MB/s",
        elapsed.as_secs_f64(),
        UPLOAD as f64 / elapsed.as_secs_f64() / 1e6
    );
}

/// Like [`server_dial`], with Go's server windows and the client's writes
/// limited to `rate` bytes a second (`f64::INFINITY`: no limit).
fn throttled_server_dial(server: Arc<Server>, rate: f64) -> XhttpDial {
    Arc::new(move || {
        let server = Arc::clone(&server);
        let (client, server_io) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let mut builder = server::Builder::new();
            builder
                .initial_window_size(1 << 20)
                .initial_connection_window_size(1 << 20);
            let Ok(mut connection) = builder.handshake::<_, Bytes>(server_io).await else {
                return;
            };
            while let Some(Ok((request, respond))) = connection.accept().await {
                tokio::spawn(serve(Arc::clone(&server), request, respond));
            }
        });
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

fn live_bytes() -> isize {
    LIVE_BYTES.load(Ordering::SeqCst)
}

fn reset_peak() {
    PEAK_BYTES.store(live_bytes(), Ordering::SeqCst);
}

fn peak_bytes() -> isize {
    PEAK_BYTES.load(Ordering::SeqCst)
}

/// Lets every response task, H2 driver and server task finish what the
/// last exchange left it.
async fn settle() {
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn open_downloading_flow(
    transport: &XhttpTransport,
    dial: &XhttpDial,
) -> BoxedTransportStream {
    let mut flow = transport
        .open_stream_with_dial(Arc::clone(dial))
        .await
        .unwrap();
    flow.write_all(&REQUEST_HEADER).await.unwrap();
    flow.flush().await.unwrap();
    let mut download = vec![0; DOWNLOAD_LEN];
    timeout(DEADLINE, flow.read_exact(&mut download))
        .await
        .expect("the packet-up download did not arrive")
        .unwrap();
    assert!(download.iter().all(|&byte| byte == 0x44));
    flow
}

#[derive(Default)]
struct Server {
    /// POSTs answered.
    posts: AtomicUsize,
    /// POSTs begun and not yet answered.
    open_posts: AtomicUsize,
    uploaded: AtomicUsize,
    /// Bytes each new download sends after [`DOWNLOAD`].
    extra_download: AtomicUsize,
    /// Open downloads: a download-only flow's GET never ends.
    downlinks: Mutex<Vec<h2::SendStream<Bytes>>>,
}

impl Server {
    async fn wait_for_posts(&self, posts: usize) {
        timeout(DEADLINE, async {
            while self.posts.load(Ordering::Acquire) < posts {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the server did not answer every POST");
    }

    /// Waits until `bytes` arrived and every POST that carried them is
    /// answered.
    async fn wait_for_uploaded(&self, bytes: usize) {
        timeout(DEADLINE, async {
            while self.uploaded.load(Ordering::Acquire) < bytes
                || self.open_posts.load(Ordering::Acquire) > 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the server did not receive every uploaded byte");
    }
}

fn server_dial(server: Arc<Server>) -> XhttpDial {
    Arc::new(move || {
        let server = Arc::clone(&server);
        let (client, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let Ok(mut connection) = server::handshake::<_>(server_io).await else {
                return;
            };
            while let Some(Ok((request, respond))) = connection.accept().await {
                tokio::spawn(serve(Arc::clone(&server), request, respond));
            }
        });
        Box::pin(async move { Ok(Box::new(client) as BoxedTransportStream) })
    })
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
        // Static bytes: the server's queue holds no heap copy of them.
        let pieces = 1 + server.extra_download.load(Ordering::Acquire) / DOWNLOAD_LEN;
        for _ in 0..pieces {
            if downlink
                .send_data(Bytes::from_static(&DOWNLOAD), false)
                .is_err()
            {
                return;
            }
        }
        server.downlinks.lock().unwrap().push(downlink);
        return;
    }
    server.open_posts.fetch_add(1, Ordering::AcqRel);
    let mut body = request.into_body();
    while let Some(Ok(chunk)) = body.data().await {
        let _ = body.flow_control().release_capacity(chunk.len());
        server.uploaded.fetch_add(chunk.len(), Ordering::AcqRel);
    }
    let _ = respond.send_response(ok_response(), true);
    server.posts.fetch_add(1, Ordering::AcqRel);
    server.open_posts.fetch_sub(1, Ordering::AcqRel);
}

fn ok_response() -> Response<()> {
    Response::builder().status(StatusCode::OK).body(()).unwrap()
}

fn packet_up_transport(max_post: usize) -> XhttpTransport {
    let input = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        x_padding_bytes: XhttpRange::exact(1),
        sc_max_each_post_bytes: XhttpRange::exact(i32::try_from(max_post).unwrap()),
        sc_min_posts_interval_ms: XhttpRange::exact(1),
        sc_max_buffered_posts: 4,
        ..XhttpConfigInput::default()
    };
    let mut config = XhttpConfig::normalize(input).unwrap();
    config.min_posts_interval_ms = NormalizedRange::exact(0);
    let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com").unwrap();
    let xmux = XhttpXmuxPolicy {
        max_concurrency: XhttpRange::exact(0),
        max_connections: XhttpRange::exact(0),
        c_max_reuse_times: XhttpRange::exact(0),
        h_max_request_times: XhttpRange::exact(0),
        h_max_reusable_secs: XhttpRange::exact(0),
        h_keep_alive_period_secs: 0,
    };
    XhttpTransport::new(config, endpoint, XhttpHttpVersion::Http2, xmux)
        .unwrap()
        .with_rng(Box::new(StepRng::new(0x0102_0304_0506_0708, 1)))
        .unwrap()
}

/// The app's packet-up shape: Xray's defaults (padding 100-1000,
/// `scMaxBufferedPosts` 30, `scMinPostsIntervalMs` 30) and three xmux
/// connections.
fn app_shaped_transport(max_post: usize) -> XhttpTransport {
    let input = XhttpConfigInput {
        mode: XhttpModeSelection::PacketUp,
        path: "/api".to_owned(),
        sc_max_each_post_bytes: XhttpRange::exact(i32::try_from(max_post).unwrap()),
        ..XhttpConfigInput::default()
    };
    let config = XhttpConfig::normalize(input).unwrap();
    let endpoint = XhttpEndpoint::new(XhttpScheme::Http, "example.com").unwrap();
    let xmux = XhttpXmuxPolicy {
        max_concurrency: XhttpRange::exact(0),
        max_connections: XhttpRange::exact(3),
        c_max_reuse_times: XhttpRange::exact(0),
        h_max_request_times: XhttpRange::exact(0),
        h_max_reusable_secs: XhttpRange::exact(0),
        h_keep_alive_period_secs: 0,
    };
    XhttpTransport::new(config, endpoint, XhttpHttpVersion::Http2, xmux).unwrap()
}

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
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h2::{server, RecvStream};
use http::{Method, Response, StatusCode};
use rand::rngs::mock::StepRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use xray_transport::stream::xhttp_composer_test_only::{
    NormalizedRange, XhttpConfig, XhttpConfigInput, XhttpEndpoint, XhttpModeSelection, XhttpRange,
    XhttpScheme,
};
use xray_transport::stream::xhttp_transport_test_only::{
    XhttpDial, XhttpHttpVersion, XhttpTransport, XhttpXmuxPolicy,
};
use xray_transport::BoxedTransportStream;

/// Counts the bytes of every live heap allocation.
struct CountingAllocator;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every method forwards to `System` unchanged and only counts sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE_BYTES.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One measurement at a time: the counter is process-wide.
static MEASURING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const DEADLINE: Duration = Duration::from_secs(10);
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

fn live_bytes() -> isize {
    LIVE_BYTES.load(Ordering::SeqCst)
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
        if downlink
            .send_data(Bytes::from_static(&DOWNLOAD), false)
            .is_ok()
        {
            server.downlinks.lock().unwrap().push(downlink);
        }
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

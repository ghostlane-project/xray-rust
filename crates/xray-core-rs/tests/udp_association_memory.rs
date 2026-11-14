//! A SOCKS UDP association's heap stays bounded at 117 associations, the
//! number hev-socks5-tunnel kept alive during the iOS speed test (memory model
//! 05, section 5.1 and R3/R4).
//!
//! One test per file: the counting allocator is process-global. Release sizes
//! (a future above tokio's box threshold is a separate block only there): run
//! with `cargo test --release --test udp_association_memory`.
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use xray_config::parse_xray_json;
use xray_core_rs::{Core, TunRuntimeOptions};
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_proxy::outbound::socks5_udp_associate;
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::TransportDialer;

/// Heap bytes live now, as requested from the allocator (a `calloc`ed 64 KiB
/// counts whole, though the OS maps only the pages that are touched; this
/// is the number the model's formulas add up).
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: forwards every call to `System` and only counts the sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const ASSOCIATIONS: usize = 117;
const WORKERS: usize = 2;

/// Heap one association may hold: a 40 B datagram, a DNS query's size, relayed
/// through a freedom flow (the DNS-outbound arm of the flow is guarded in
/// `socks/size_tests.rs`). Formula, in bytes:
///   control connection task (`handle_socks_connection`)          5,776
/// + association future (`handle_socks_udp_associate`)             1,536
/// + flow task future (`bridge_socks_udp_flow`)                    2,304
/// + the freedom arm it awaits, boxed                              4,864
/// + the flow's queue block, the relay socket's and the
///   connection's registry entries, the targets and the
///   client's own sockets in this test                             6,000
///
/// That is 20,480 B = 20 KiB; measured 18,606 B. Before the change: two 64 KiB
/// buffers, a 36 KB flow future and a 9.3 KB control task, measured 182,310 B.
const PER_ASSOCIATION_MAX: usize = 20 * 1024;
/// The per-thread receive scratch: 65,536 B once per worker that reads a
/// socket (the test's own thread runs `block_on` and never polls core tasks),
/// not per association. The warm-up round allocates at least one of them; a
/// second worker's first read may fall in the measured round.
const SCRATCH_MAX: usize = WORKERS * 65_536;

async fn start_core() -> (Core, SocketAddr) {
    let raw = r#"{
        "inbounds": [
            {"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
             "settings": {"auth": "noauth", "udp": true}}
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    }"#;
    let config = parse_xray_json(raw).expect("config parses").config;
    let dialer = TransportDialer::system().unwrap();
    let mut core = Core::with_transport_dialer_and_tun_options(
        config,
        Arc::new(dialer),
        TunRuntimeOptions::default(),
    )
    .unwrap();
    core.start().await.unwrap();
    let socks = core.inbound_addr(Some("socks-in")).unwrap();
    (core, socks)
}

async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..len], from).await;
        }
    });
    addr
}

/// One association: control connection, client socket, one datagram echoed
/// back through the core's flow. Both stay open for the caller to hold.
async fn associate(socks: SocketAddr, echo: SocketAddr) -> (TcpStream, UdpSocket) {
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut control = TcpStream::connect(socks).await.unwrap();
    let relay = socks5_udp_associate(
        &mut control,
        None,
        client.local_addr().unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )
    .await
    .unwrap();
    let target = Target::new(TargetAddr::Ip(echo.ip()), echo.port(), Network::Udp);
    // A DNS query's size.
    let query = [0x5a_u8; 40];
    let request = encode_socks5_udp_datagram(&target, &query).unwrap();
    client.send_to(&request, relay).await.unwrap();
    let mut response = vec![0; 2048];
    let (len, _) = timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("the flow answered")
        .unwrap();
    let response = parse_socks5_udp_datagram(&response[..len]).unwrap();
    assert_eq!(&response.payload[..], &query[..]);
    (control, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "sizes are release-mode sizes")]
async fn udp_associations_stay_bounded_at_117() {
    let echo = spawn_udp_echo().await;
    let (mut core, socks) = start_core().await;
    // Warm-up: the first association creates the per-thread and per-process
    // state (scratch, pools, registries) that is not per association.
    let warm = associate(socks, echo).await;
    drop(warm);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let baseline = LIVE.load(Ordering::Relaxed);

    let mut held = Vec::with_capacity(ASSOCIATIONS);
    for _ in 0..ASSOCIATIONS {
        held.push(associate(socks, echo).await);
    }
    let live = LIVE.load(Ordering::Relaxed);
    let grown = live.saturating_sub(baseline);
    let per = grown / ASSOCIATIONS;
    println!("{ASSOCIATIONS} associations hold {grown} B ({per} B each)");

    let ceiling = ASSOCIATIONS * PER_ASSOCIATION_MAX + SCRATCH_MAX;
    assert!(
        grown <= ceiling,
        "{ASSOCIATIONS} associations hold {grown} B ({per} B each); ceiling {ceiling} B \
         ({PER_ASSOCIATION_MAX} B each plus {SCRATCH_MAX} B of per-thread scratch)"
    );

    drop(held);
    core.stop().await.unwrap();
}

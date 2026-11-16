//! What the TUN bridge holds for its TCP flows, counted by this binary's
//! allocator.
//!
//! The core runs on a runtime of its own whose threads are counted; the app
//! (a smoltcp client that writes its packets into the TUN) and the far end
//! (a TCP server the core's freedom outbound dials) are not. Only blocks of
//! 16 KiB or more are counted: a payload buffer is one of those (on iOS a
//! block above 15 KiB takes whole 16 KiB pages), while a packet (at most
//! the 1500-byte MTU) is allocated on the app's thread and freed on the
//! core's, and would make the count drift if it were counted.
//!
//! The rule (memory model 05, §13; byte budget 10): a flow holds no payload
//! buffer while it is quiet, and what busy flows hold for payload is the
//! process's byte budget `B` plus each flow's floor, whatever their number.
//! What the TUN's own queues hold (the stack's pending download and upload
//! bytes, with budgets of their own) is read from the TUN's statistics and
//! allowed on top.
//!
//! Every test prints its numbers (`--nocapture`).

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use smoltcp::iface::{
    Config as SmolInterfaceConfig, Interface as SmolInterface, SocketHandle, SocketSet,
};
use smoltcp::phy::{
    ChecksumCapabilities, Device as SmolDevice, DeviceCapabilities as SmolDeviceCapabilities,
    Medium as SmolMedium, RxToken as SmolRxToken, TxToken as SmolTxToken,
};
use smoltcp::socket::tcp as smol_tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress as SmolHardwareAddress, IpAddress as SmolIpAddress, IpCidr as SmolIpCidr,
    Ipv4Address as SmolIpv4Address,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use xray_core_rs::{Core, TunRuntimeOptions};
use xray_transport::memory_budget::{ByteBudgetSettings, DEFAULT_FLOW_FLOOR};

const KIB: usize = 1024;
/// The smallest block counted.
const COUNTED_BLOCK: usize = 16 * KIB;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static COUNTED: Cell<bool> = const { Cell::new(false) };
}

fn counted() -> bool {
    COUNTED.try_with(Cell::get).unwrap_or(false)
}

fn count(size: usize, sign: isize) {
    if size < COUNTED_BLOCK || !counted() {
        return;
    }
    let delta = sign * size as isize;
    let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    if delta > 0 {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: every call goes to `System` unchanged; the counters only watch.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            count(layout.size(), 1);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            count(layout.size(), 1);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        count(layout.size(), -1);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            count(layout.size(), -1);
            count(new_size, 1);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn count_this_thread() {
    COUNTED.with(|counted| counted.set(true));
}

fn leave_this_thread() {}

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

fn reset_peak() -> isize {
    let now = live();
    PEAK.store(now, Ordering::Relaxed);
    now
}

fn peak() -> isize {
    PEAK.load(Ordering::Relaxed)
}

static TURN: Mutex<()> = Mutex::new(());

fn take_turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(PoisonError::into_inner)
}

fn runtime(workers: usize, on_start: fn()) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .on_thread_start(on_start)
        .enable_all()
        .build()
        .expect("a runtime")
}

/// The budget of the test: a third of a phone's 3 MB, as T4's.
const BUDGET: usize = 1_000_000;
const FLOWS: usize = 256;
/// What each flow fetches and then sends: two of the bridge's 64 KiB
/// chunks each way.
const DOWNLOAD: usize = 128 * KIB;
const UPLOAD: usize = 128 * KIB;
/// The flows that send more, and how much: enough to outlast the kernel's
/// socket buffers at the far end's pace, so that their batches coalesce.
const BIG_FLOWS: usize = 4;
const BIG_UPLOAD: usize = 8 * 1024 * KIB;
/// How long the far end leaves a big upload unread: long enough for the app
/// to fill the kernel's socket buffers and the flow's upload queue.
const BIG_UPLOAD_PAUSE: Duration = Duration::from_secs(3);
/// The core's smoltcp socket of a TCP flow at MTU 1500: a 32 KiB receive
/// buffer (`max(32 KiB, 4 × MSS)`) and a 32 KiB send buffer. They are the
/// flow's TCP window toward the app, as hev's lwIP window is, and held for
/// the flow's life; they are not what this file is about.
const SOCKET_BUFFERS: isize = 64 * KIB as isize;
/// What the TUN's tables (the socket set, the flow maps) take a flow in
/// blocks of 16 KiB or more: a slot each, well under a KiB, rounded up.
const TABLES: isize = KIB as isize;

/// What `flows` quiet flows may hold: their sockets, their slots in the
/// tables, and two more sockets (the listener that takes the next SYN, and
/// one for slack). No payload buffer.
fn quiet_bound(flows: usize) -> isize {
    (flows as isize + 2) * SOCKET_BUFFERS + flows as isize * TABLES
}

/// The free buffers the relays' pool keeps for the next read on a
/// constrained host (a phone), whose class the tests take: four of 128 KiB,
/// in its lists and its threads' spares together. They are the process's,
/// not a flow's.
const POOL_KEEPS: isize = 4 * 128 * KIB as isize;

fn set_budget(capacity: usize) {
    xray_transport::set_byte_budget(Some(ByteBudgetSettings {
        capacity,
        floor: DEFAULT_FLOW_FLOOR,
    }));
}

fn tun_core() -> Core {
    let raw = r#"{
      "inbounds": [{ "tag": "tun-in", "protocol": "tun", "listen": "127.0.0.1", "port": 0 }],
      "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
    }"#;
    let config = xray_config::parse_xray_json(raw)
        .expect("the config parses")
        .config;
    Core::with_tun_runtime_options(config, TunRuntimeOptions::default()).expect("a core")
}

/// The far end. Each connection takes commands: `d` has it send `download`
/// bytes; `u` has it read `upload` bytes and `U` `big_upload` bytes, and
/// answer `k`. With `paced`, it reads through a 16 KiB receive buffer and
/// leaves a big upload unread for `BIG_UPLOAD_PAUSE` first, as a stalled
/// uplink: the kernel's buffers fill, the bridge's writes wait, and the
/// upload's chunks queue into batches of many messages.
async fn start_far_server(
    download: usize,
    upload: usize,
    big_upload: usize,
    paced: bool,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    if paced {
        socket.set_recv_buffer_size(16 * KIB as u32).unwrap();
    }
    socket
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let listener: TcpListener = socket.listen(1024).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let payload = vec![0x5a_u8; download.max(1)];
                let mut sink = vec![0_u8; 16 * KIB];
                let mut command = [0_u8; 1];
                while stream.read_exact(&mut command).await.is_ok() {
                    match command[0] {
                        b'd' => {
                            if stream.write_all(&payload[..download]).await.is_err() {
                                return;
                            }
                        }
                        b'u' | b'U' => {
                            let big = command[0] == b'U';
                            let mut left = if big { big_upload } else { upload };
                            if paced && big {
                                // Not read for a while: the kernel's buffers fill and
                                // the bridge's writes wait.
                                tokio::time::sleep(BIG_UPLOAD_PAUSE).await;
                            }
                            while left > 0 {
                                let want = left.min(sink.len());
                                match stream.read(&mut sink[..want]).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(read) => left -= read,
                                }
                            }
                            if stream.write_all(b"k").await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    (addr, accepted)
}

/// The app: one smoltcp interface with a socket per flow.
struct App {
    iface: SmolInterface,
    device: PacketDevice,
    sockets: SocketSet<'static>,
    flows: Vec<SocketHandle>,
    /// What each flow has received.
    received: Vec<usize>,
    /// What each flow has still to send.
    to_send: Vec<usize>,
}

impl App {
    fn new(flows: usize, buffer: usize) -> Self {
        let mut device = PacketDevice::default();
        let mut config = SmolInterfaceConfig::new(SmolHardwareAddress::Ip);
        config.random_seed = 0x7475_6e6d_656d_0001;
        let mut iface = SmolInterface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(SmolIpCidr::new(SmolIpAddress::v4(10, 10, 0, 2), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(SmolIpv4Address::new(10, 10, 0, 1))
            .unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let handles = (0..flows)
            .map(|_| {
                let mut socket = smol_tcp::Socket::new(
                    smol_tcp::SocketBuffer::new(vec![0; buffer]),
                    smol_tcp::SocketBuffer::new(vec![0; buffer]),
                );
                socket.set_congestion_control(smol_tcp::CongestionControl::None);
                sockets.add(socket)
            })
            .collect();
        Self {
            iface,
            device,
            sockets,
            flows: handles,
            received: vec![0; flows],
            to_send: vec![0; flows],
        }
    }

    fn connect_all(&mut self, target: SocketAddr) {
        let SocketAddr::V4(target) = target else {
            panic!("IPv4 targets only");
        };
        for (index, handle) in self.flows.iter().copied().enumerate() {
            self.sockets
                .get_mut::<smol_tcp::Socket>(handle)
                .connect(
                    self.iface.context(),
                    (*target.ip(), target.port()),
                    40000 + u16::try_from(index).unwrap(),
                )
                .unwrap();
        }
    }

    fn all_may_send(&mut self) -> bool {
        self.flows
            .iter()
            .all(|handle| self.sockets.get::<smol_tcp::Socket>(*handle).may_send())
    }

    /// Queues `command` on every flow, then `extra` bytes more to send.
    fn command_all(&mut self, command: u8, extra: usize) {
        self.command_each(|_| Some((command, extra)));
    }

    /// Queues on each flow the command `of` its index gives, if any, then
    /// the bytes more to send it gives.
    fn command_each(&mut self, of: impl Fn(usize) -> Option<(u8, usize)>) {
        for (index, handle) in self.flows.iter().copied().enumerate() {
            let Some((command, extra)) = of(index) else {
                continue;
            };
            let sent = self
                .sockets
                .get_mut::<smol_tcp::Socket>(handle)
                .send_slice(&[command])
                .unwrap();
            assert_eq!(sent, 1, "flow {index} took its command");
            self.to_send[index] = extra;
            self.received[index] = 0;
        }
    }

    /// Sends what fits, takes what arrived; whether anything moved.
    fn exchange(&mut self) -> bool {
        let chunk = [0xa5_u8; 4 * KIB];
        let mut moved = false;
        for (index, handle) in self.flows.iter().copied().enumerate() {
            let socket = self.sockets.get_mut::<smol_tcp::Socket>(handle);
            while self.to_send[index] > 0 && socket.can_send() {
                let want = self.to_send[index].min(chunk.len());
                let sent = socket.send_slice(&chunk[..want]).unwrap();
                if sent == 0 {
                    break;
                }
                self.to_send[index] -= sent;
                moved = true;
            }
            while socket.can_recv() {
                let taken = socket.recv(|data| (data.len(), data.len())).unwrap();
                self.received[index] += taken;
                moved = true;
            }
        }
        moved
    }

    fn poll(&mut self) {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }
}

/// Moves packets both ways until `done`, for at most `wait`.
async fn pump(
    app: &mut App,
    core: &Core,
    wait: Duration,
    what: &str,
    mut done: impl FnMut(&mut App) -> bool,
) {
    let deadline = Instant::now() + wait;
    loop {
        app.poll();
        let mut moved = app.exchange();
        while let Some(packet) = app.device.outbound.pop_front() {
            match core.tun().push_inbound(packet.clone()).await {
                Ok(()) => moved = true,
                // The TUN's queue is full: the packet waits for the next pass.
                Err(xray_tun::TunError::QueueFull) => {
                    app.device.outbound.push_front(packet);
                    break;
                }
                Err(error) => panic!("the TUN took no packet: {error}"),
            }
        }
        while let Some(packet) = core.tun().try_poll_outbound().await.unwrap() {
            app.device.inbound.push_back(packet);
            moved = true;
        }
        app.poll();
        if done(app) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out: {what}");
        if !moved {
            tokio::time::sleep(Duration::from_millis(1)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
}

/// What one run held, in bytes over the core before its flows.
#[derive(Debug, Clone, Copy)]
struct Run {
    quiet: isize,
    busy: isize,
    permits: usize,
    after: isize,
    batches: u64,
    batch_max_messages: u64,
    batch_max_bytes: u64,
}

fn run_flows(flows: usize) -> Run {
    let far = runtime(2, leave_this_thread);
    let near = runtime(2, count_this_thread);
    let (server, accepted) = far.block_on(start_far_server(DOWNLOAD, UPLOAD, BIG_UPLOAD, true));
    let mut core = near.block_on(async { tun_core() });
    near.block_on(core.start()).unwrap();
    let base = live();

    let mut app = App::new(flows, 8 * KIB);
    far.block_on(async {
        app.connect_all(server);
        pump(&mut app, &core, Duration::from_secs(30), "flows open", |app| {
            app.all_may_send()
        })
        .await;
        let wait_accepted = Instant::now() + Duration::from_secs(30);
        while accepted.load(Ordering::SeqCst) < flows {
            pump(&mut app, &core, Duration::from_secs(1), "settle", |_| true).await;
            assert!(Instant::now() < wait_accepted, "the far end took every flow");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let quiet_until = Instant::now() + Duration::from_millis(300);
        pump(&mut app, &core, Duration::from_secs(5), "quiet", |_| {
            Instant::now() >= quiet_until
        })
        .await;
    });
    let quiet = live() - base;

    let busy_from = reset_peak();
    xray_transport::reset_byte_budget_peak();
    far.block_on(async {
        app.command_all(b'd', 0);
        pump(&mut app, &core, Duration::from_secs(120), "downloads", |app| {
            app.received.iter().all(|received| *received >= DOWNLOAD)
        })
        .await;
        // The big uploads alone first: the app's packets then reach their
        // flows fast enough to fill the far end's buffers while it waits.
        app.command_each(|index| (index < BIG_FLOWS).then_some((b'U', BIG_UPLOAD)));
        pump(&mut app, &core, Duration::from_secs(120), "big uploads", |app| {
            app.to_send[..BIG_FLOWS].iter().all(|left| *left == 0)
                && app.received[..BIG_FLOWS].iter().all(|received| *received >= 1)
        })
        .await;
        app.command_all(b'u', UPLOAD);
        pump(&mut app, &core, Duration::from_secs(120), "uploads", |app| {
            app.to_send.iter().all(|left| *left == 0)
                && app.received.iter().all(|received| *received >= 1)
        })
        .await;
    });
    let busy = peak() - base;
    debug_assert!(busy_from >= base);
    let permits = xray_transport::byte_budget_usage().peak;
    let stats = near.block_on(core.tun().stats());

    far.block_on(async {
        let quiet_until = Instant::now() + Duration::from_millis(300);
        pump(&mut app, &core, Duration::from_secs(5), "quiet again", |_| {
            Instant::now() >= quiet_until
        })
        .await;
    });
    let after = live() - base;
    drop(app);
    near.block_on(core.stop()).unwrap();
    Run {
        quiet,
        busy,
        permits,
        after,
        batches: stats.tcp_remote_write_batches,
        batch_max_messages: stats.tcp_remote_write_batch_max_messages,
        batch_max_bytes: stats.tcp_remote_write_batch_max_bytes,
    }
}

/// T11: 256 TCP flows through the TUN to a far server, quiet, then each
/// fetching 128 KiB, then 4 of them sending 8 MiB to a far end that leaves
/// it unread for 3 s (more than a loopback socket's 4 MiB send buffer can
/// take), then each sending 128 KiB, all at once a phase,
/// then quiet again, under a budget of 1 MB.
///
/// Quiet, the flows hold their smoltcp sockets and nothing for payload.
/// Busy, the bridge's reads and its chunks on their way to the stack take
/// bytes of `B` beyond each flow's floor, and no more than `B`. Quiet
/// again, after upload batches that filled the 64 KiB coalescing buffer,
/// they are back where they were, but for the buffers the pool keeps.
///
/// The busy peak is printed, not bounded: beside `B` and the floors it holds
/// the TUN's own queues (the stack's download prefetch, up to 256 KiB a flow,
/// and its upload queue, up to 512 KiB a flow), which have budgets of their
/// own and statistics that are sampled, not peaks.
///
/// Before the bridge took its buffers from the budget, each flow kept a
/// 64 KiB read buffer for its life, its reads took nothing of `B`, and its
/// upload batch kept its capacity (64 KiB and more) after the batch: 16-32
/// MiB at 256 flows, whatever `B`.
#[test]
fn quiet_and_busy_tun_flows_hold_the_budget_and_their_floors() {
    let _turn = take_turn();
    xray_transport::set_memory_class(Some(xray_transport::MemoryClass::Constrained));
    set_budget(BUDGET);
    let run = run_flows(FLOWS);
    let floors = FLOWS as isize * 2 * DEFAULT_FLOW_FLOOR as isize;
    let quiet_bound = quiet_bound(FLOWS);

    println!(
        "T11 {FLOWS} TUN flows: quiet {} B ({} B a flow, bound {quiet_bound}); busy peak {} B; \
         budget {BUDGET} B, floors {floors} B; \
         permits {} B; quiet again {} B; upload batches {} (largest {} messages, {} B)",
        run.quiet,
        run.quiet / FLOWS as isize,
        run.busy,
        run.permits,
        run.after,
        run.batches,
        run.batch_max_messages,
        run.batch_max_bytes,
    );
    // The uploads made batches that fill the bridge's 64 KiB coalescing
    // buffer, so a flow that kept that buffer after its batch would show
    // quiet again.
    let mut failures = Vec::new();
    if run.batch_max_bytes < 64 * KIB as u64 {
        failures.push(format!(
            "the largest upload batch had {} B: the uploads did not fill a coalescing buffer",
            run.batch_max_bytes
        ));
    }
    if run.quiet > quiet_bound {
        failures.push(format!(
            "quiet flows hold {} B, over their sockets' {quiet_bound} B",
            run.quiet
        ));
    }
    if run.permits == 0 || run.permits > BUDGET {
        failures.push(format!(
            "the bridge took {} B of permits; the budget is {BUDGET} B",
            run.permits
        ));
    }
    let after_bound = run.quiet + POOL_KEEPS;
    if run.after > after_bound {
        failures.push(format!(
            "flows quiet again hold {} B, over the {} B they held quiet and the pool's \
             {POOL_KEEPS} B",
            run.after, run.quiet
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

/// One flow's rate through the TUN, both ways, best of five: a measurement
/// for the record, not an assertion. Run with
///
/// ```text
/// cargo test --release -p xray-core-rs --test tun_memory_tests -- --ignored --nocapture
/// ```
#[test]
#[ignore = "a measurement"]
fn one_tun_flow_rate_best_of_five() {
    let _turn = take_turn();
    xray_transport::set_byte_budget(None);
    const BYTES: usize = 32 * 1024 * KIB;
    let far = runtime(2, leave_this_thread);
    let near = runtime(2, leave_this_thread);
    let (server, _) = far.block_on(start_far_server(BYTES, BYTES, BYTES, false));
    let mut core = near.block_on(async { tun_core() });
    near.block_on(core.start()).unwrap();
    // A window like an app's: 256 KiB each way.
    let mut app = App::new(1, 256 * KIB);
    let (mut down, mut up) = (0.0_f64, 0.0_f64);
    far.block_on(async {
        app.connect_all(server);
        pump(&mut app, &core, Duration::from_secs(10), "open", App::all_may_send).await;
        for round in 0..6 {
            let start = Instant::now();
            app.command_all(b'd', 0);
            pump(&mut app, &core, Duration::from_secs(120), "download", |app| {
                app.received[0] >= BYTES
            })
            .await;
            let down_rate = BYTES as f64 / start.elapsed().as_secs_f64() / 1e6;
            let start = Instant::now();
            app.command_all(b'u', BYTES);
            pump(&mut app, &core, Duration::from_secs(120), "upload", |app| {
                app.to_send[0] == 0 && app.received[0] >= 1
            })
            .await;
            let up_rate = BYTES as f64 / start.elapsed().as_secs_f64() / 1e6;
            println!("round {round}: down {down_rate:.0} MB/s, up {up_rate:.0} MB/s");
            // The first round warms up.
            if round > 0 {
                down = down.max(down_rate);
                up = up.max(up_rate);
            }
        }
    });
    println!("one TUN flow, best of 5 × 32 MiB: down {down:.0} MB/s, up {up:.0} MB/s");
    drop(app);
    near.block_on(core.stop()).unwrap();
}

#[derive(Default)]
struct PacketDevice {
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

const MTU: usize = 1500;

impl SmolDevice for PacketDevice {
    type RxToken<'a>
        = PacketRx
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            PacketRx(packet),
            PacketTx {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(PacketTx {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> SmolDeviceCapabilities {
        let mut capabilities = SmolDeviceCapabilities::default();
        capabilities.medium = SmolMedium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities.max_burst_size = None;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

struct PacketRx(Bytes);

impl SmolRxToken for PacketRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct PacketTx<'a> {
    outbound: &'a mut VecDeque<Bytes>,
}

impl SmolTxToken for PacketTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len.min(MTU)];
        let result = f(&mut packet);
        self.outbound.push_back(Bytes::from(packet));
        result
    }
}

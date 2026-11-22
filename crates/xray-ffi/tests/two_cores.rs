//! Two core handles in one process (a session on one, a probe on the other).
//!
//! On a phone the room check and the line probe run in the app's process
//! beside a running session, so two running handles must not share anything
//! but the one byte budget: each keeps its own inbound, its own socket
//! protector and its own lifecycle. Loopback servers only.

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_core_probe_outbound_url,
    xray_core_set_socket_protect_callback, xray_core_start, xray_core_stop, XrayCoreHandle,
    XrayOutboundProbeFailureKind, XrayStatus,
};

unsafe extern "C" fn count_protect(fd: libc::c_int, user_data: *mut libc::c_void) -> libc::c_int {
    assert!(fd >= 0);
    let calls = unsafe { &*user_data.cast::<AtomicUsize>() };
    calls.fetch_add(1, Ordering::SeqCst);
    1
}

fn reserve_loopback_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A core with a SOCKS inbound on its own port, a freedom outbound and its
/// own protector counting into `calls`.
fn started(calls: &'static AtomicUsize) -> (*mut XrayCoreHandle, u16) {
    let port = reserve_loopback_port();
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    assert_eq!(
        unsafe {
            xray_core_set_socket_protect_callback(
                core,
                Some(count_protect),
                std::ptr::from_ref(calls).cast_mut().cast(),
                &mut err,
            )
        },
        XrayStatus::Ok
    );
    let raw = CString::new(format!(
        r#"{{
          "inbounds": [{{ "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
                          "port": {port}, "settings": {{ "udp": false }} }}],
          "outbounds": [{{ "tag": "direct", "protocol": "freedom" }}]
        }}"#
    ))
    .unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);
    (core, port)
}

/// Echoes every connection until `stop` is set; also answers an HTTP probe
/// (a request line ending in a blank line) with 204.
fn spawn_server(stop: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let stop = stop.clone();
                    thread::spawn(move || {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_millis(200)))
                            .unwrap();
                        let mut buffer = [0_u8; 16 * 1024];
                        while !stop.load(Ordering::SeqCst) {
                            match stream.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(n) if buffer[..n].starts_with(b"GET ") => {
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    );
                                    break;
                                }
                                Ok(n) => {
                                    if stream.write_all(&buffer[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    addr
}

/// Accepts connections and never reads them, so what a relay sends into one
/// stays in the relay's buffers.
fn spawn_sink(stop: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let mut held = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    addr
}

/// Writes into `client` until the pipe is full (a write times out), so the
/// relay behind it holds what it could not pass on.
fn fill(client: &mut TcpStream) -> usize {
    client
        .set_write_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let chunk = vec![0xa5_u8; 64 * 1024];
    let mut sent = 0;
    while sent < 64 * 1024 * 1024 {
        match client.write(&chunk) {
            Ok(n) => sent += n,
            Err(_) => break,
        }
    }
    sent
}

/// A SOCKS5 CONNECT to `target` through the inbound on `port`.
fn socks_connect(port: u16, target: SocketAddr) -> TcpStream {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 only");
    };
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0_u8; 2];
    client.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    let mut connect = vec![5, 1, 0, 1];
    connect.extend_from_slice(&target.ip().octets());
    connect.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&connect).unwrap();
    let mut response = [0_u8; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response[..2], &[5, 0]);
    client
}

fn echo(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).unwrap();
    let mut back = vec![0_u8; payload.len()];
    client.read_exact(&mut back).unwrap();
    assert_eq!(back, payload);
}

fn probe(core: *mut XrayCoreHandle, addr: SocketAddr) {
    let url = CString::new(format!("http://127.0.0.1:{}/health", addr.port())).unwrap();
    let (mut delay, mut kind, mut http) = (0_u64, -1_i32, 0_u16);
    let mut err = std::ptr::null_mut();
    let status = unsafe {
        xray_core_probe_outbound_url(
            core,
            url.as_ptr(),
            5_000,
            std::ptr::null(),
            &mut delay,
            &mut kind,
            &mut http,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(kind, XrayOutboundProbeFailureKind::None as i32);
}

#[test]
fn two_running_cores_keep_their_own_inbound_and_protector_and_one_budget() {
    static CALLS_A: AtomicUsize = AtomicUsize::new(0);
    static CALLS_B: AtomicUsize = AtomicUsize::new(0);
    let stop = Arc::new(AtomicBool::new(false));
    let server = spawn_server(stop.clone());

    // The one byte budget of the process, small so that a leak past it shows.
    let floor = xray_transport::byte_budget().floor;
    let capacity = 4 * 1024 * 1024;
    xray_transport::set_byte_budget(Some(xray_transport::ByteBudgetSettings { capacity, floor }));
    xray_transport::reset_byte_budget_peak();
    assert_eq!(xray_transport::byte_budget_usage().peak, 0, "a fresh budget");

    let (core_a, port_a) = started(&CALLS_A);
    let (core_b, port_b) = started(&CALLS_B);
    assert_ne!(port_a, port_b);

    // A session on A, live through everything below.
    let mut session = socks_connect(port_a, server);
    echo(&mut session, b"session on A");
    let a_before = CALLS_A.load(Ordering::SeqCst);
    assert!(a_before > 0, "A's own protector saw A's dial");
    assert_eq!(
        CALLS_B.load(Ordering::SeqCst),
        0,
        "B has dialled nothing yet"
    );

    // Probes and a flow on B beside the session, with a large transfer on A.
    for _ in 0..3 {
        probe(core_b, server);
    }
    let mut flow_b = socks_connect(port_b, server);
    let big = vec![0x5a_u8; 512 * 1024];
    echo(&mut flow_b, &big);
    echo(&mut session, &big);
    assert!(
        CALLS_B.load(Ordering::SeqCst) >= 4,
        "B's protector saw B's dials"
    );
    assert_eq!(
        CALLS_A.load(Ordering::SeqCst),
        a_before,
        "B's dials never reach A's protector"
    );

    // B's relay and A's relay took from the process budget (the peak was
    // reset before the cores started, so only these flows could raise it).
    let usage = xray_transport::byte_budget_usage();
    assert_eq!(usage.capacity, capacity);
    assert!(
        usage.peak > 0,
        "the relays of the two cores took nothing from the process budget"
    );
    assert!(
        usage.peak <= capacity,
        "peak {} beyond the budget {capacity}",
        usage.peak
    );

    // Both cores hold bytes at once: A's flow is stuck against a server that
    // reads nothing, so A's relay keeps what it was given; then B runs a
    // probe and a flow beside it, and the one budget carries both.
    let sink = spawn_sink(stop.clone());
    let mut stuck_a = socks_connect(port_a, sink);
    let sent = fill(&mut stuck_a);
    assert!(sent > 0);
    thread::sleep(Duration::from_millis(300));
    let held_by_a = xray_transport::byte_budget_usage().in_use;
    assert!(held_by_a > 0, "A's stuck relay holds nothing of the budget");
    assert!(held_by_a <= capacity);
    xray_transport::reset_byte_budget_peak();
    probe(core_b, server);
    let mut flow_b2 = socks_connect(port_b, server);
    echo(&mut flow_b2, &big);
    let both = xray_transport::byte_budget_usage();
    assert!(
        both.peak > held_by_a && both.peak <= capacity,
        "B took nothing beside A, or went past the budget: peak {} outside ({held_by_a}, {capacity}]",
        both.peak
    );
    drop(flow_b2);
    drop(stuck_a);

    // Stopping B leaves A running and passing traffic.
    let mut err = std::ptr::null_mut();
    drop(flow_b);
    assert_eq!(unsafe { xray_core_stop(core_b, &mut err) }, XrayStatus::Ok);
    unsafe { xray_core_free(core_b) };
    echo(&mut session, b"still on A after B stopped");
    let mut second = socks_connect(port_a, server);
    echo(&mut second, b"a new flow on A");
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port_b)).is_err(),
        "B's inbound is gone"
    );
    assert!(xray_transport::byte_budget_usage().peak <= capacity);

    drop(second);
    drop(session);
    assert_eq!(unsafe { xray_core_stop(core_a, &mut err) }, XrayStatus::Ok);
    unsafe { xray_core_free(core_a) };
    stop.store(true, Ordering::SeqCst);
    xray_transport::set_byte_budget(None);
}

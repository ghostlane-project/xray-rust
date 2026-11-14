use std::fmt;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h3::client::SendRequest;
use http::{HeaderValue, Method, Request};
use quinn::{Connection, Endpoint, VarInt};
use rand::{distributions::Alphanumeric, Rng};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::memory_budget::{ByteBudget, WindowLease};
use crate::quic_congestion::ControllerSwitch;
use crate::stream::{
    configure_quic_datagram_socket, connect_quic_transport_with_datagrams, H3ConnectConfig,
    H3Error, H3QuicConfig, QuicSendWindow, QUIC_INITIAL_SEND_WINDOW, QUIC_MAX_SEND_WINDOW,
};
use crate::{memory_class, MemoryClass, TlsClientConfig, TlsConnector, TransportError};

use super::udp::Registry;

const AUTH_HEADER_LIMIT: u64 = 8192;
const MAX_AUTH_BYTES: usize = 4096;
const QUIC_DATAGRAM_BUFFER: usize = 256 * 1024;
// Match pinned Xray without shrinking Quinn's aggregate receive queue.
const QUIC_DATAGRAM_FRAME_SIZE: u16 = 1200;

/// A constrained host's stream window: half the 2 MiB a stream of sing-box's
/// quic-go starts with, so it takes three readers that stop to use up the
/// connection window where it takes one and a half there. 1 MiB is 84 Mbit/s
/// per flow at 100 ms, where a constrained host's gRPC stops growing too.
const CONSTRAINED_STREAM_RECEIVE_WINDOW: u64 = 1024 * 1024;
/// A constrained host's connection window: the 3 MiB quic-go starts a
/// connection with and grows, which quinn does not, so it is also all its
/// streams may hold unread together. 252 Mbit/s at 100 ms.
const CONSTRAINED_CONNECTION_RECEIVE_WINDOW: u64 = 3 * 1024 * 1024;
/// The most a constrained host's send window grows to: the 4 MiB all of its
/// XHTTP H3 uploads share. 335 Mbit/s at 100 ms.
const CONSTRAINED_MAX_SEND_WINDOW: u64 = 4 * 1024 * 1024;

/// The flow-control windows of one Hysteria connection: the receive windows
/// its handshake announces and the most its send window grows to. quinn
/// keeps a Hysteria connection's receive windows where the handshake puts
/// them, where quic-go grows them, and holds written data until it is
/// acknowledged up to the send window, so these three numbers are what a
/// connection may hold unread on the way in and unacknowledged on the way
/// out.
///
/// The host's memory class picks them ([`Self::for_class`]), and every
/// Hysteria number that depends on the class is here. They are plain
/// inputs: [`HysteriaConfig::with_windows`] takes them as given, so a
/// process-wide byte budget could hand a connection its share instead. To
/// move a live connection, such a budget would set the connection receive
/// window with quinn's `set_receive_window`, and lower the ceiling of the
/// connection's send window rather than call `set_send_window` itself, as
/// the window's growth sets it again at the next sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HysteriaWindows {
    /// Receive credit per stream.
    pub stream_receive: u64,
    /// Receive credit per connection, shared by its streams.
    pub connection_receive: u64,
    /// The most the send window grows to, from 2 MiB toward twice the
    /// congestion window: [`HysteriaLimits::max_send_window`].
    pub max_send: u64,
}

impl HysteriaWindows {
    /// xray-rust's QUIC defaults on a [`MemoryClass::Standard`] host: 2 MiB
    /// and 3 MiB, and a send window that grows to 10 MB. On a constrained
    /// host 1 MiB and 3 MiB, and 4 MiB. ChromeParrot replaces the receive
    /// windows with Chrome's 6 MiB and 15 MiB, which its handshake must
    /// carry; the send window is the client's own on either.
    pub fn for_class(class: MemoryClass) -> Self {
        match class {
            MemoryClass::Standard => {
                let defaults = H3QuicConfig::default();
                Self {
                    stream_receive: defaults.initial_stream_receive_window,
                    connection_receive: defaults.initial_connection_receive_window,
                    max_send: QUIC_MAX_SEND_WINDOW,
                }
            }
            MemoryClass::Constrained => Self {
                stream_receive: CONSTRAINED_STREAM_RECEIVE_WINDOW,
                connection_receive: CONSTRAINED_CONNECTION_RECEIVE_WINDOW,
                max_send: CONSTRAINED_MAX_SEND_WINDOW,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HysteriaLimits {
    pub max_tcp_streams: usize,
    pub max_udp_sessions: usize,
    pub udp_queue_packets: usize,
    pub udp_queue_bytes: usize,
    pub udp_payload_bytes: usize,
    pub fragment_timeout: Duration,
    pub operation_timeout: Duration,
    /// The most the send window grows to, from 2 MiB toward twice the
    /// congestion window: 2 MiB to 10 MB. The default is a
    /// [`MemoryClass::Standard`] host's 10 MB ([`HysteriaWindows::max_send`]).
    pub max_send_window: u64,
}

impl Default for HysteriaLimits {
    fn default() -> Self {
        Self {
            max_tcp_streams: 64,
            max_udp_sessions: 32,
            // Absorb short QUIC receive bursts while a ready relay is scheduled.
            // Payload storage remains capped by the shared byte budget below.
            udp_queue_packets: 16,
            udp_queue_bytes: 1024 * 1024,
            udp_payload_bytes: 65535,
            fragment_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(10),
            max_send_window: QUIC_MAX_SEND_WINDOW,
        }
    }
}

impl HysteriaLimits {
    fn validate(&self) -> Result<(), HysteriaError> {
        if !(1..=256).contains(&self.max_tcp_streams)
            || !(1..=128).contains(&self.max_udp_sessions)
            || !(1..=16).contains(&self.udp_queue_packets)
            || !(1..=4 * 1024 * 1024).contains(&self.udp_queue_bytes)
            || !(1..=65535).contains(&self.udp_payload_bytes)
            || self.fragment_timeout.is_zero()
            || self.fragment_timeout > Duration::from_secs(30)
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(60)
            || !(QUIC_INITIAL_SEND_WINDOW..=QUIC_MAX_SEND_WINDOW).contains(&self.max_send_window)
        {
            return Err(HysteriaError::Configuration);
        }
        Ok(())
    }
}

/// One resolved server candidate. Endpoint resolution belongs to the core DNS
/// policy; the socket protector is taken from the supplied TLS connector.
pub struct HysteriaConfig {
    pub remote_addr: SocketAddr,
    pub tls: TlsClientConfig,
    pub auth: Zeroizing<String>,
    pub quic: H3QuicConfig,
    pub limits: HysteriaLimits,
    pub carrier: super::HysteriaCarrierConfig,
    /// `brutalDown` in bytes per second, announced to the server as
    /// `Hysteria-CC-RX`. A server with its own Brutal rate sends at the lower
    /// of the two; zero leaves it on BBR.
    pub receive_bytes_per_second: u64,
    /// What a `realm` mask in `carrier` takes from the dial.
    pub realm: Option<crate::realm::RealmEnv>,
    /// The byte budget the connection's windows are held within: the
    /// process's ([`ByteBudget::process`]) unless set. While the connection
    /// moves data its receive and send windows run at the flow floor plus
    /// their parts of one [`WindowLease`], at most as configured; once it
    /// moved nothing for [`WINDOW_IDLE_FIT`], at the floor. The handshake
    /// still announces `quic`'s windows.
    pub byte_budget: &'static ByteBudget,
}

impl HysteriaConfig {
    /// The windows follow the host's memory class at the time of the call
    /// ([`HysteriaWindows::for_class`]).
    pub fn new(remote_addr: SocketAddr, tls: TlsClientConfig, auth: String) -> Self {
        Self::with_windows(
            remote_addr,
            tls,
            auth,
            HysteriaWindows::for_class(memory_class()),
        )
    }

    /// A configuration whose receive windows and send-window ceiling are
    /// `windows`, whatever the host's class.
    pub fn with_windows(
        remote_addr: SocketAddr,
        tls: TlsClientConfig,
        auth: String,
        windows: HysteriaWindows,
    ) -> Self {
        Self {
            remote_addr,
            tls,
            auth: Zeroizing::new(auth),
            limits: HysteriaLimits {
                max_send_window: windows.max_send,
                ..HysteriaLimits::default()
            },
            carrier: super::HysteriaCarrierConfig::default(),
            quic: H3QuicConfig {
                max_idle_timeout: Duration::from_secs(30),
                initial_stream_receive_window: windows.stream_receive,
                initial_connection_receive_window: windows.connection_receive,
                ..H3QuicConfig::default()
            },
            receive_bytes_per_second: 0,
            realm: None,
            byte_budget: ByteBudget::process(),
        }
    }
}

impl fmt::Debug for HysteriaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaConfig")
            .field("remote_addr", &self.remote_addr)
            .field("auth", &"<redacted>")
            .field("quic", &self.quic)
            .field("limits", &self.limits)
            .field("carrier", &self.carrier)
            .field("receive_bytes_per_second", &self.receive_bytes_per_second)
            .finish_non_exhaustive()
    }
}

/// Stage-specific errors deliberately omit untrusted server messages, HTTP
/// headers, credentials and QUIC application-close reason bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HysteriaError {
    #[error("invalid or unsupported Hysteria configuration")]
    Configuration,
    #[error("could not build Hysteria TLS policy")]
    TlsConfiguration,
    #[error("Hysteria UDP socket protection failed")]
    SocketProtection,
    #[error("Hysteria QUIC connection failed")]
    Connect,
    #[error("Hysteria operation timed out")]
    Timeout,
    #[error("Hysteria HTTP/3 authentication failed")]
    Authentication,
    #[error("invalid Hysteria authentication response headers")]
    AuthenticationHeaders,
    #[error("Hysteria connection is closed")]
    Closed,
    #[error("Hysteria session limit reached")]
    SessionLimit,
    #[error("invalid Hysteria target")]
    Target,
    #[error("Hysteria TCP request was rejected")]
    TcpRejected,
    #[error("invalid Hysteria TCP response")]
    TcpResponse,
    #[error("Hysteria stream failed")]
    Stream,
    #[error("Hysteria server does not support UDP")]
    UdpUnsupported,
    #[error("Hysteria UDP message exceeds the supported size")]
    DatagramSize,
    #[error("Hysteria UDP send failed")]
    DatagramSend,
}

type AuthSender = SendRequest<h3_quinn::OpenStreams, Bytes>;

// Owns the connection as soon as it exists, including authentication errors
// and cancellation before a usable client can be returned.
struct Connecting {
    endpoint: Option<Endpoint>,
    connection: Connection,
    driver: Option<JoinHandle<()>>,
}

impl Drop for Connecting {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            self.connection.close(VarInt::from_u32(0x100), b"");
            endpoint.close(VarInt::from_u32(0x100), b"");
        }
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

#[derive(Default)]
struct RebindRequest {
    pending: AtomicBool,
    wake: Notify,
}

/// How long a connection whose windows hold bytes of the budget may move
/// nothing before they fall to the floor: a second, eight round trips of
/// the 120 ms path the budget is sized for. A connection at the floor sets
/// no timer.
pub(super) const WINDOW_IDLE_FIT: Duration = Duration::from_secs(1);

/// Bytes read or written while the last fit left the windows short of what
/// they want, after which they are fitted again: 64 KiB, a fiftieth of a
/// constrained connection's 3 MiB, so a short window follows the traffic
/// without a fit for every read.
const SHORT_REFIT_BYTES: u64 = 64 * 1024;

/// The bytes one direction of a connection's TCP streams moved, counted in
/// turns of [`WINDOW_IDLE_FIT`] since the connection opened.
#[derive(Debug, Default, Clone, Copy)]
struct Moved {
    turn: u64,
    current: u64,
    previous: u64,
}

impl Moved {
    /// What moved in this turn and the one before: within the last one to
    /// two [`WINDOW_IDLE_FIT`]s.
    fn recent(&self, turn: u64) -> u64 {
        match turn.saturating_sub(self.turn) {
            0 => self.current.saturating_add(self.previous),
            1 => self.current,
            _ => 0,
        }
    }

    /// Counts `bytes` moved in `turn`; returns whether the direction had
    /// been quiet, its window perhaps at the floor.
    fn add(&mut self, turn: u64, bytes: u64) -> bool {
        let quiet = self.recent(turn) == 0;
        match turn.saturating_sub(self.turn) {
            0 => {}
            1 => self.previous = std::mem::take(&mut self.current),
            _ => {
                self.previous = 0;
                self.current = 0;
            }
        }
        self.turn = self.turn.max(turn);
        self.current = self.current.saturating_add(bytes);
        quiet
    }
}

/// What a connection's TCP streams moved lately.
#[derive(Debug, Default)]
struct Activity {
    received: Moved,
    sent: Moved,
    /// Bytes moved since a fit that left the windows short of what they
    /// want; `None` after one that gave them all of it.
    unfitted: Option<u64>,
}

/// Splits `held` bytes between the receive and the send window: in
/// proportion to what each direction moved lately, each at most what it
/// wants, and what one cannot use to the other.
fn split_windows(held: u64, want: [u64; 2], moved: [u64; 2]) -> [u64; 2] {
    if held >= want[0].saturating_add(want[1]) {
        return want;
    }
    let total = u128::from(moved[0]) + u128::from(moved[1]);
    let receive = if total == 0 {
        held / 2
    } else {
        (u128::from(held) * u128::from(moved[0]) / total) as u64
    };
    let send = (held - receive.min(want[0])).min(want[1]);
    [(held - send).min(want[0]), send]
}

/// Whether a fit moves the receive window from `now` to `next`: to the floor
/// at once, otherwise by an eighth of the window or more, the step at which
/// quinn's reads announce credit, so that a fit that hardly changes the
/// window sends the peer no `MAX_DATA` of its own.
fn resizes(now: u64, next: u64, floor: u64) -> bool {
    next != now && (next == floor || now.abs_diff(next) >= now.max(next) / 8)
}

/// A Hysteria connection's windows within a byte budget.
struct HysteriaBudget {
    lease: WindowLease<'static>,
    /// The connection receive window the handshake announced.
    announced_receive: u64,
    /// The receive window set on the connection last.
    receive_window: u64,
}

pub(super) struct Shared {
    connection: Mutex<Option<Connection>>,
    send_window: QuicSendWindow,
    budget: Mutex<HysteriaBudget>,
    /// What the TCP streams moved, in turns since `opened`.
    opened: std::time::Instant,
    activity: Mutex<Activity>,
    /// Fits the windows when the budget changes or another lease falls
    /// short, and once they hold bytes, after [`WINDOW_IDLE_FIT`].
    window_driver: Mutex<Option<JoinHandle<()>>>,
    /// Told when a fit makes the windows hold bytes, so the driver starts
    /// its idle timer.
    window_wake: Arc<Notify>,
    endpoint: Mutex<Option<Endpoint>>,
    // Last h3 SendRequest drop closes its connection. Retain it after auth.
    auth_sender: Mutex<Option<AuthSender>>,
    h3_driver: JoinHandle<()>,
    pub udp_driver: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
    rebind: Arc<RebindRequest>,
    rebind_driver: Mutex<Option<JoinHandle<()>>>,
    bind_addr: SocketAddr,
    carrier: super::HysteriaCarrierConfig,
    // The remote address the current carrier sends to, so the next hop
    // starts from it.
    wire_peer: Mutex<SocketAddr>,
    session: super::carrier::CarrierSession,
    protector: Option<Arc<dyn crate::SocketProtector>>,
    pub limits: HysteriaLimits,
    pub tcp_slots: Arc<Semaphore>,
    pub udp: Arc<Registry>,
    pub udp_enabled: bool,
}

/// Fits a connection's windows again whenever the budget asks
/// ([`ByteBudget::window_events`]: it changed, or another lease fell short
/// or gave bytes back), and [`WINDOW_IDLE_FIT`] after each fit that left
/// them holding bytes, so that a connection that went quiet gives them back.
/// A connection at the floor waits for budget events only.
async fn drive_windows(
    owner: std::sync::Weak<Shared>,
    budget: &'static ByteBudget,
    holds: Arc<Notify>,
) {
    let mut holding = false;
    let mut seen = budget.window_generation();
    loop {
        let events = budget.window_events();
        tokio::pin!(events);
        events.as_mut().enable();
        if budget.window_generation() == seen {
            if holding {
                tokio::select! {
                    () = &mut events => {}
                    () = tokio::time::sleep(WINDOW_IDLE_FIT) => {}
                }
            } else {
                tokio::select! {
                    () = &mut events => {}
                    () = holds.notified() => {}
                }
            }
        }
        seen = budget.window_generation();
        let Some(shared) = owner.upgrade() else { break };
        holding = shared.fit_windows();
    }
}

impl Shared {
    // Called only after another MiB has been written, never from an idle timer.
    // Keep local queues small, but allow high-BDP paths to use the previous cap.
    pub(super) fn grow_send_window(&self) {
        let guard = self.connection.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(connection) = guard.as_ref() {
            self.send_window.grow(connection);
        }
    }

    /// A TCP stream read `received` bytes and wrote `sent`. The windows are
    /// fitted again at once when a direction moves after a quiet turn (its
    /// window may sit at the floor), after [`SHORT_REFIT_BYTES`] while the
    /// last fit left them short of what they want, or when `force`d.
    pub(super) fn moved(&self, received: usize, sent: usize, force: bool) {
        let turn = self.turn();
        let fit = {
            let mut activity = self.activity.lock().unwrap_or_else(|e| e.into_inner());
            let mut fit = force;
            if received > 0 && activity.received.add(turn, received as u64) {
                fit = true;
            }
            if sent > 0 && activity.sent.add(turn, sent as u64) {
                fit = true;
            }
            if let Some(unfitted) = activity.unfitted.as_mut() {
                *unfitted = unfitted.saturating_add((received + sent) as u64);
                if *unfitted >= SHORT_REFIT_BYTES {
                    fit = true;
                }
            }
            fit
        };
        if fit {
            self.fit_windows();
        }
    }

    /// The turn of [`WINDOW_IDLE_FIT`] the connection is in.
    fn turn(&self) -> u64 {
        let turn = self.opened.elapsed().as_millis() / WINDOW_IDLE_FIT.as_millis();
        u64::try_from(turn).unwrap_or(u64::MAX)
    }

    /// Sizes the connection's windows within the byte budget, as one lease:
    /// each direction that moved bytes in this turn of [`WINDOW_IDLE_FIT`]
    /// or the last wants its whole window, the receive window as the
    /// handshake announced it and the send window as far as it has grown;
    /// one that moved nothing wants only the floor. The lease takes what its
    /// share allows and the windows run at the floor plus their parts of it,
    /// split by what each direction moved ([`split_windows`]): a download's
    /// requests leave its receive window nearly all of a short lease.
    /// Returns whether the lease holds bytes, which then wait for an idle
    /// fit.
    ///
    /// A smaller receive window takes back no credit the peer has: quinn
    /// keeps it as debt that reads pay back, and a later growth pays the debt
    /// before it grants more (`vendor/quinn-proto/XRAY-PATCH.md`), so idle and
    /// busy turns never leave the peer more than the announced window.
    pub(super) fn fit_windows(&self) -> bool {
        let turn = self.turn();
        let (received, sent) = {
            let activity = self.activity.lock().unwrap_or_else(|e| e.into_inner());
            (activity.received.recent(turn), activity.sent.recent(turn))
        };
        let closed = self.closed.load(Ordering::Acquire);
        let guard = self.connection.lock().unwrap_or_else(|e| e.into_inner());
        let mut budget = self.budget.lock().unwrap_or_else(|e| e.into_inner());
        let floor = budget.lease.budget().floor() as u64;
        let receive_want = if received > 0 && !closed {
            budget.announced_receive.saturating_sub(floor)
        } else {
            0
        };
        let send_want = if sent > 0 && !closed {
            self.send_window.grown().saturating_sub(floor)
        } else {
            0
        };
        let want = receive_want.saturating_add(send_want);
        let held_before = budget.lease.held();
        let held = budget
            .lease
            .fit(usize::try_from(want).unwrap_or(usize::MAX)) as u64;
        if held_before == 0 && held > 0 {
            // The driver's idle timer starts.
            self.window_wake.notify_one();
        }
        let fitted = held >= want && !budget.lease.is_short();
        self.activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unfitted = (!fitted).then_some(0);
        let [receive_part, send_part] =
            split_windows(held, [receive_want, send_want], [received, sent]);
        let receive = floor
            .saturating_add(receive_part)
            .min(budget.announced_receive);
        let send = floor.saturating_add(send_part);
        if let Some(connection) = guard.as_ref() {
            if resizes(budget.receive_window, receive, floor) {
                budget.receive_window = receive;
                connection.set_receive_window(VarInt::from_u64(receive).unwrap_or(VarInt::MAX));
            }
            self.send_window.limit(connection, send);
        }
        held > 0
    }

    pub fn is_live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self
                .connection
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|connection| connection.close_reason().is_none())
            && !self.h3_driver.is_finished()
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(connection) = self
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            connection.close(VarInt::from_u32(0x100), b"");
        }
        self.auth_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(endpoint) = self
            .endpoint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            endpoint.close(VarInt::from_u32(0x100), b"");
        }
        if let Some(task) = self
            .rebind_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        if let Some(task) = self
            .window_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        self.tcp_slots.close();
        // Closed: the windows give their bytes of the budget back.
        self.fit_windows();
        self.h3_driver.abort();
        if let Some(task) = self
            .udp_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        self.udp.close();
    }

    fn rebind_socket(&self) -> Result<(), HysteriaError> {
        if !self.is_live() {
            return Err(HysteriaError::Closed);
        }
        // The server's NAT opened for the realm socket alone; a new socket
        // needs a new introduction, so the next dial makes one.
        if self.carrier.realm.is_some() {
            return Err(HysteriaError::Connect);
        }
        let socket = UdpSocket::bind(self.bind_addr).map_err(|_| HysteriaError::Connect)?;
        configure_quic_datagram_socket(&socket);
        crate::protect_std_udp_socket(&socket, self.protector.as_deref())
            .map_err(|_| HysteriaError::SocketProtection)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| HysteriaError::Connect)?;
        let logical_peer = self.connection()?.remote_address();
        let endpoint = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Acquire) {
            return Err(HysteriaError::Closed);
        }
        let endpoint = endpoint.as_ref().ok_or(HysteriaError::Closed)?;
        // On the captured runtime. Quinn retains at most the current and
        // previous carrier until an authenticated packet arrives on the new one.
        let result = if self.carrier.enabled() {
            let wire_peer = self.carrier.next_hop_peer(
                logical_peer,
                *self.wire_peer.lock().unwrap_or_else(|e| e.into_inner()),
            );
            let socket = super::carrier::wrap(
                socket,
                logical_peer,
                wire_peer,
                &self.carrier,
                &self.session,
            )
            .map_err(|_| HysteriaError::Connect)?;
            endpoint
                .rebind_abstract(socket)
                .map(|()| *self.wire_peer.lock().unwrap_or_else(|e| e.into_inner()) = wire_peer)
        } else {
            #[cfg(target_os = "macos")]
            {
                let socket = crate::connected_quic::wrap(socket, logical_peer)
                    .map_err(|_| HysteriaError::Connect)?;
                endpoint.rebind_abstract(socket)
            }
            #[cfg(not(target_os = "macos"))]
            endpoint.rebind(socket)
        };
        result.map_err(|_| HysteriaError::Connect)
    }

    pub fn connection(&self) -> Result<Connection, HysteriaError> {
        self.connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(HysteriaError::Closed)
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close();
    }
}

/// A single authenticated multiplexed QUIC connection. Clones and live TCP/UDP
/// leases share ownership. Dropping the last lease closes sockets and tasks.
/// Explicit `close` closes all leases; reconnect requires a fresh `connect`.
#[derive(Clone)]
pub struct HysteriaClient {
    pub(super) shared: Arc<Shared>,
}

impl fmt::Debug for HysteriaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaClient")
            .field("live", &self.is_live())
            .field("udp_enabled", &self.shared.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl HysteriaClient {
    pub async fn connect(
        config: HysteriaConfig,
        tls: &TlsConnector,
    ) -> Result<Self, HysteriaError> {
        config.limits.validate()?;
        config.carrier.validate()?;
        if config.remote_addr.port() == 0
            || config.auth.is_empty()
            || config.auth.len() > MAX_AUTH_BYTES
            || config.tls.fingerprint.is_some()
            || (!config.tls.alpn.is_empty() && config.tls.alpn != ["h3"])
        {
            return Err(HysteriaError::Configuration);
        }
        config
            .quic
            .diagnostics()
            .map_err(|_| HysteriaError::Configuration)?;
        let mut auth = HeaderValue::from_bytes(config.auth.as_bytes())
            .map_err(|_| HysteriaError::Configuration)?;
        auth.set_sensitive(true);
        // A realm introduction comes before the QUIC handshake.
        let deadline = config.limits.operation_timeout
            + if config.carrier.realm.is_some() {
                crate::realm::ESTABLISH_BUDGET
            } else {
                Duration::ZERO
            };
        timeout(deadline, Self::connect_inner(config, tls, auth))
            .await
            .map_err(|_| HysteriaError::Timeout)?
    }

    async fn connect_inner(
        config: HysteriaConfig,
        tls: &TlsConnector,
        auth: HeaderValue,
    ) -> Result<Self, HysteriaError> {
        let tls_config = tls
            .h3_client_config_for(&config.tls, b"h3", config.quic.chrome_parrot)
            .map_err(|_| HysteriaError::TlsConfiguration)?;
        let mut session = super::carrier::CarrierSession::new(&config.carrier)
            .map_err(|_| HysteriaError::Configuration)?;
        session
            .open_xdns(&config.carrier, tls.socket_protector_arc())
            .await
            .map_err(|_| HysteriaError::Connect)?;
        // Opened with the session, so a rebind keeps the id the server
        // knows.
        session
            .open_xicmp(
                &config.carrier,
                crate::canonicalize_socket_addr(config.remote_addr).ip(),
                tls.socket_protector_arc(),
            )
            .await
            .map_err(|_| HysteriaError::Connect)?;
        // Xray's Hysteria dialer installs its controller after
        // authentication: Brutal or BBR, in its default mode by the server's
        // reply.
        let switch = Arc::new(ControllerSwitch::default());
        let (endpoint, connection, _, wire_peer) = connect_quic_transport_with_datagrams(
            H3ConnectConfig {
                remote_addr: config.remote_addr,
                server_name: config.tls.server_name.clone(),
                tls_config,
                socket_protector: tls.socket_protector_arc(),
                quic: config.quic.clone(),
                realm: config.realm.clone(),
                // The client rebinds its own endpoint.
                network_changes: None,
            },
            b"h3",
            Some((
                QUIC_DATAGRAM_BUFFER,
                QUIC_DATAGRAM_BUFFER,
                QUIC_DATAGRAM_FRAME_SIZE,
            )),
            Some(&config.carrier),
            session.clone(),
            Some(&switch),
        )
        .await
        .map_err(|error| match error {
            H3Error::Transport(TransportError::SocketProtection(_)) => {
                HysteriaError::SocketProtection
            }
            _ => HysteriaError::Connect,
        })?;
        connection.set_send_window(QUIC_INITIAL_SEND_WINDOW);
        let mut pending = Connecting {
            endpoint: Some(endpoint),
            connection,
            driver: None,
        };
        let (mut driver, mut sender) = h3::client::builder()
            .max_field_section_size(AUTH_HEADER_LIMIT)
            .build(h3_quinn::Connection::new(pending.connection.clone()))
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        let driver_connection = pending.connection.clone();
        pending.driver = Some(tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            driver_connection.close(VarInt::from_u32(0x100), b"");
        }));
        let padding = random_padding(256, 2048);
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header("hysteria-auth", auth)
            .header("hysteria-cc-rx", config.receive_bytes_per_second)
            .header("hysteria-padding", padding)
            .body(())
            .map_err(|_| HysteriaError::Configuration)?;
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        stream
            .finish()
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        let response = stream
            .recv_response()
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        if response.status().as_u16() != 233 {
            return Err(HysteriaError::Authentication);
        }
        let (udp_enabled, server_receive_rate) = parse_auth_headers(response.headers())?;
        if let Some(installed) = config.quic.installed_controller(Some(server_receive_rate)) {
            switch.install(installed);
        }
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        drop(stream);
        let registry = Arc::new(Registry::new(config.limits));
        let bind_addr = match crate::canonicalize_socket_addr(config.remote_addr).ip() {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let rebind = Arc::new(RebindRequest::default());
        let shared = Arc::new(Shared {
            connection: Mutex::new(Some(pending.connection.clone())),
            send_window: QuicSendWindow::new(config.limits.max_send_window),
            budget: Mutex::new(HysteriaBudget {
                lease: WindowLease::new(config.byte_budget),
                announced_receive: config.quic.populated().initial_connection_receive_window,
                receive_window: config.quic.populated().initial_connection_receive_window,
            }),
            opened: std::time::Instant::now(),
            activity: Mutex::new(Activity::default()),
            window_driver: Mutex::new(None),
            window_wake: Arc::new(Notify::new()),
            endpoint: Mutex::new(pending.endpoint.take()),
            auth_sender: Mutex::new(Some(sender)),
            h3_driver: pending.driver.take().expect("started H3 driver"),
            udp_driver: Mutex::new(None),
            closed: AtomicBool::new(false),
            rebind: rebind.clone(),
            rebind_driver: Mutex::new(None),
            bind_addr,
            carrier: config.carrier.clone(),
            wire_peer: Mutex::new(wire_peer),
            session,
            protector: tls.socket_protector_arc(),
            limits: config.limits,
            tcp_slots: Arc::new(Semaphore::new(config.limits.max_tcp_streams)),
            udp: registry,
            udp_enabled,
        });
        let owner = Arc::downgrade(&shared);
        let hopping = config.carrier;
        let task = tokio::spawn(async move {
            loop {
                // A disabled hop policy creates no timer and preserves the
                // event-driven network-rebind worker.
                let hop = async {
                    match hopping.next_interval() {
                        Some(delay) => tokio::time::sleep(delay).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                let requested = tokio::select! {
                    _ = rebind.wake.notified() => true,
                    _ = hop => false,
                };
                if requested {
                    rebind.pending.store(false, Ordering::Release);
                }
                let Some(shared) = owner.upgrade() else { break };
                if shared.rebind_socket().is_err() && requested {
                    // A scheduled hop failure retains the protected old path,
                    // matching Xray. A host network update cannot keep a stale carrier.
                    shared.close();
                    break;
                }
            }
        });
        *shared
            .rebind_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(task);
        let task = tokio::spawn(drive_windows(
            Arc::downgrade(&shared),
            config.byte_budget,
            Arc::clone(&shared.window_wake),
        ));
        *shared
            .window_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(task);
        if udp_enabled {
            let task = super::udp::spawn_receiver(shared.connection()?, Arc::clone(&shared.udp));
            *shared.udp_driver.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        }
        Ok(Self { shared })
    }

    pub fn is_live(&self) -> bool {
        self.shared.is_live()
    }
    /// Queue a fresh protected carrier socket on the connection's runtime.
    /// Preserves QUIC/TCP/UDP state and the remote address. A replacement
    /// failure closes the client; true means accepted, not path validation.
    pub fn rebind(&self) -> bool {
        if !self.is_live() {
            return false;
        }
        if !self.shared.rebind.pending.swap(true, Ordering::AcqRel) {
            self.shared.rebind.wake.notify_one();
        }
        true
    }
    pub fn udp_enabled(&self) -> bool {
        self.shared.udp_enabled
    }
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.shared
            .endpoint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "Hysteria connection closed",
                )
            })?
            .local_addr()
    }
    pub fn close(&self) {
        self.shared.close();
    }
    pub fn active_udp_sessions(&self) -> usize {
        self.shared.udp.len()
    }
    /// The most this connection's send window grows to
    /// ([`HysteriaLimits::max_send_window`]). For diagnostics and tests.
    #[doc(hidden)]
    pub fn send_window_ceiling(&self) -> u64 {
        self.shared.send_window.ceiling()
    }
    /// The congestion controller the connection runs now: `new-reno`,
    /// `quinn-bbr`, `xray-bbr-<profile>` or `brutal`. For diagnostics and
    /// tests.
    #[doc(hidden)]
    pub fn congestion_controller(&self) -> Option<&'static str> {
        let connection = self.shared.connection().ok()?;
        Some(crate::quic_congestion::controller_name(
            connection.congestion_state(),
        ))
    }
}

pub(super) fn random_padding(min: usize, max: usize) -> String {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(min..max);
    (&mut rng)
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Returns whether the server relays UDP and the receive rate it announces in
/// bytes per second, zero for `auto`.
fn parse_auth_headers(headers: &http::HeaderMap) -> Result<(bool, u64), HysteriaError> {
    let one = |name| {
        let mut values = headers.get_all(name).iter();
        let value = values.next().ok_or(HysteriaError::AuthenticationHeaders)?;
        if values.next().is_some() {
            return Err(HysteriaError::AuthenticationHeaders);
        }
        value
            .to_str()
            .map_err(|_| HysteriaError::AuthenticationHeaders)
    };
    let udp = match one("hysteria-udp")? {
        "true" | "True" | "TRUE" | "t" | "T" | "1" => true,
        "false" | "False" | "FALSE" | "f" | "F" | "0" => false,
        _ => return Err(HysteriaError::AuthenticationHeaders),
    };
    let rate = match one("hysteria-cc-rx")? {
        "auto" => 0,
        rate if !rate.is_empty() && rate.bytes().all(|b| b.is_ascii_digit()) => rate
            .parse::<u64>()
            .map_err(|_| HysteriaError::AuthenticationHeaders)?,
        _ => return Err(HysteriaError::AuthenticationHeaders),
    };
    Ok((udp, rate))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn windows_follow_the_memory_class_and_stream_limits_do_not() {
        let standard = HysteriaWindows::for_class(MemoryClass::Standard);
        assert_eq!(
            (
                standard.stream_receive,
                standard.connection_receive,
                standard.max_send
            ),
            (2 * MIB, 3 * MIB, 10_000_000)
        );
        let constrained = HysteriaWindows::for_class(MemoryClass::Constrained);
        assert_eq!(
            (
                constrained.stream_receive,
                constrained.connection_receive,
                constrained.max_send
            ),
            (MIB, 3 * MIB, 4 * MIB)
        );

        // The default limits are a standard host's, and 64 TCP streams and
        // 32 UDP sessions on every host.
        let limits = HysteriaLimits::default();
        assert_eq!(
            (
                limits.max_tcp_streams,
                limits.max_udp_sessions,
                limits.max_send_window
            ),
            (64, 32, standard.max_send)
        );
        for max_send_window in [standard.max_send, constrained.max_send] {
            let limits = HysteriaLimits {
                max_send_window,
                ..limits
            };
            assert_eq!(limits.validate(), Ok(()));
        }
        for max_send_window in [2 * MIB - 1, 10_000_001] {
            let limits = HysteriaLimits {
                max_send_window,
                ..limits
            };
            assert_eq!(limits.validate(), Err(HysteriaError::Configuration));
        }
    }

    #[test]
    fn auth_response_requires_single_valid_udp_and_rate_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("hysteria-udp", HeaderValue::from_static("True"));
        headers.insert(
            "hysteria-cc-rx",
            HeaderValue::from_static("18446744073709551615"),
        );
        assert_eq!(parse_auth_headers(&headers), Ok((true, u64::MAX)));
        for value in ["", "+1", "-1", "18446744073709551616", "AUTO", "1,2"] {
            headers.insert("hysteria-cc-rx", HeaderValue::from_str(value).unwrap());
            assert_eq!(
                parse_auth_headers(&headers),
                Err(HysteriaError::AuthenticationHeaders)
            );
        }
        headers.insert("hysteria-cc-rx", HeaderValue::from_static("auto"));
        headers.append("hysteria-udp", HeaderValue::from_static("false"));
        assert_eq!(
            parse_auth_headers(&headers),
            Err(HysteriaError::AuthenticationHeaders)
        );
        headers.remove("hysteria-udp");
        assert_eq!(
            parse_auth_headers(&headers),
            Err(HysteriaError::AuthenticationHeaders)
        );
        headers.insert("hysteria-udp", HeaderValue::from_static("0"));
        assert_eq!(parse_auth_headers(&headers), Ok((false, 0)), "auto");
        headers.insert("hysteria-cc-rx", HeaderValue::from_static("1250000"));
        assert_eq!(parse_auth_headers(&headers), Ok((false, 1_250_000)));
        headers.append("hysteria-cc-rx", HeaderValue::from_static("0"));
        assert_eq!(
            parse_auth_headers(&headers),
            Err(HysteriaError::AuthenticationHeaders)
        );
    }

    #[test]
    fn a_short_lease_goes_to_the_direction_that_moves_the_bytes() {
        let want = [3 * MIB, 2 * MIB];
        // Enough for both: each its whole window.
        assert_eq!(split_windows(6 * MIB, want, [1, 1]), want);
        // A download and its requests: the receive window takes nearly all.
        let [receive, send] = split_windows(2 * MIB, want, [25_000_000, 50_000]);
        assert_eq!(receive + send, 2 * MIB);
        assert!(send < 8 * 1024, "{send}");
        // An upload: the send window takes what it wants, the rest receives.
        assert_eq!(
            split_windows(4 * MIB, want, [10_000, 25_000_000]),
            [2 * MIB, 2 * MIB]
        );
        // A quiet direction wants nothing and gets nothing.
        assert_eq!(split_windows(MIB, [0, 2 * MIB], [0, 5]), [0, MIB]);
    }

    #[test]
    fn a_direction_is_recent_for_one_or_two_turns_and_then_quiet() {
        let mut moved = Moved::default();
        assert_eq!(moved.recent(0), 0);
        assert!(moved.add(0, 10), "the first bytes come after quiet");
        assert!(!moved.add(0, 5));
        assert_eq!(moved.recent(0), 15);
        assert!(!moved.add(1, 7), "still recent in the next turn");
        assert_eq!((moved.recent(1), moved.recent(2), moved.recent(3)), (22, 7, 0));
        assert!(moved.add(3, 1), "two turns without bytes are quiet");
        assert_eq!(moved.recent(3), 1);
    }

    #[test]
    fn the_receive_window_moves_by_an_eighth_or_to_the_floor() {
        const FLOOR: u64 = 4096;
        assert!(!resizes(3 * MIB, 3 * MIB, FLOOR));
        assert!(!resizes(3 * MIB, 3 * MIB - MIB / 4, FLOOR));
        assert!(resizes(3 * MIB, 2 * MIB, FLOOR));
        assert!(resizes(2 * MIB, 3 * MIB, FLOOR));
        assert!(resizes(3 * MIB, FLOOR, FLOOR));
        assert!(resizes(FLOOR, 64 * 1024, FLOOR));
    }
}

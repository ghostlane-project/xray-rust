// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! UDP from the SOCKS client (udp.go, direct_udp.go): RFC 1928 `UDP
//! ASSOCIATE` (a loopback socket per association) and hev-socks5's
//! `FWD_UDP` (datagrams framed on the TCP connection itself). Every
//! (association, client, target) is a flow with a random id, sealed on the
//! datagram lane; the server answers on the same flow. A port-53 datagram is
//! answered over a stream instead ([`crate::dns`]), and a target the direct
//! rules name gets a protected socket of this process.
//!
//! # Bounds
//!
//! - flows: at most [`DEFAULT_MAX_FLOWS`] lane flows and as many direct
//!   ones, each idle out after [`FLOW_IDLE_TIMEOUT`]; one sweeper for all;
//! - a read buffer of [`READ_BUFFER`] exists only while a socket has
//!   datagrams waiting (Go holds one per association for its life: 117
//!   associations held 7.5 MB on iOS, olcbox 1.0.428);
//! - `FWD_UDP` replies: a queue of [`FWD_REPLY_QUEUE`] frames per
//!   connection and [`FWD_QUEUE_BUDGET`] bytes for all of them, counted
//!   until written (gathered writes of up to [`FWD_WRITE_BATCH`], no buffer
//!   of their own); a full queue or budget drops the datagram (the lane is
//!   lossy by contract); a quiet connection holds no read buffer.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use olc_wire::record::Lane as RecordLane;
use olc_wire::sizes::UDP_MAX_RECORD;
use olc_wire::udpwire::{self, FrameType, Host};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::client::Inner;
use crate::socks::{atyp, go_ip_string, Request};
use crate::tunnel::{rep, reply};

/// One read of a UDP socket: the tun's MTU (9000 behind hev) and a SOCKS
/// UDP header fit (`udpConstrainedReadBufferSize`).
pub const READ_BUFFER: usize = 16 * 1024;
/// A flow silent this long is dropped (`udpFlowIdleTimeout`).
pub const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the sweeper looks (`udpFlowSweepInterval`).
pub const FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Flows at most (`defaultMaxUDPFlows`).
pub const DEFAULT_MAX_FLOWS: usize = 1024;
/// How long a datagram waits for the lane (`defaultDatagramReadyTimeout`).
pub const DATAGRAM_READY_TIMEOUT: Duration = Duration::from_secs(1);
/// How often a waiting datagram asks again (`datagramPollDelay`).
pub const DATAGRAM_POLL_DELAY: Duration = Duration::from_millis(2);
/// hev-socks5's `UDP_BUF_SIZE`: the reply frame's address and data must fit.
pub const FWD_CLIENT_BUFFER: usize = 1500;
/// Reply frames queued per `FWD_UDP` connection (xray-rust's 32).
pub const FWD_REPLY_QUEUE: usize = 32;
/// One write to the `FWD_UDP` connection gathers frames up to this much.
pub const FWD_WRITE_BATCH: usize = 16 * 1024;
/// Frames in one gathered write at most.
const FWD_GATHER: usize = FWD_REPLY_QUEUE + 1;
/// The replies all `FWD_UDP` connections may hold queued, in bytes (plan
/// §9: UDP 0.5 MiB); past it a reply is dropped, as a full queue drops it.
pub const FWD_QUEUE_BUDGET: usize = 512 * 1024;

/// Reply bytes queued on every `FWD_UDP` connection now.
static FWD_QUEUED: AtomicUsize = AtomicUsize::new(0);

/// One reply frame in a `FWD_UDP` queue, counted in [`FWD_QUEUED`] until it
/// is written or dropped.
#[derive(Debug)]
pub(crate) struct Queued(Vec<u8>);

impl Queued {
    /// The frame, if the budget has room for it.
    fn new(frame: Vec<u8>) -> Option<Self> {
        let len = frame.len();
        if FWD_QUEUED.fetch_add(len, Ordering::Relaxed) + len > FWD_QUEUE_BUDGET {
            FWD_QUEUED.fetch_sub(len, Ordering::Relaxed);
            return None;
        }
        Some(Self(frame))
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        FWD_QUEUED.fetch_sub(self.0.len(), Ordering::Relaxed);
    }
}

/// Reply bytes queued on every `FWD_UDP` connection.
pub fn fwd_queued() -> usize {
    FWD_QUEUED.load(Ordering::Relaxed)
}

/// Writes `frames` whole, gathered: one vectored write after another.
async fn write_frames<W: tokio::io::AsyncWrite + Unpin>(
    wr: &mut W,
    frames: &[Queued],
) -> std::io::Result<()> {
    let (mut i, mut off) = (0, 0);
    while i < frames.len() {
        let mut slices = [std::io::IoSlice::new(&[]); FWD_GATHER];
        let mut n = 0;
        for (k, f) in frames[i..].iter().take(FWD_GATHER).enumerate() {
            slices[n] = std::io::IoSlice::new(&f.0[if k == 0 { off } else { 0 }..]);
            n += 1;
        }
        let mut wrote = wr.write_vectored(&slices[..n]).await?;
        if wrote == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        while wrote > 0 {
            let left = frames[i].0.len() - off;
            if wrote >= left {
                wrote -= left;
                (i, off) = (i + 1, 0);
            } else {
                off += wrote;
                wrote = 0;
            }
        }
    }
    Ok(())
}
/// `DATLEN | HDRLEN`.
const FWD_LENGTHS: usize = 3;

/// An address as a SOCKS UDP header names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Addr {
    /// IPv4.
    V4(Ipv4Addr),
    /// IPv6.
    V6(Ipv6Addr),
    /// A name.
    Domain(String),
}

impl Addr {
    /// From a Go host string (`socksAddrBytes`): a literal is an address,
    /// a mapped IPv6 one IPv4.
    pub fn parse(host: &str) -> Self {
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => Self::V4(a),
            Ok(IpAddr::V6(a)) => a.to_ipv4_mapped().map_or(Self::V6(a), Self::V4),
            Err(_) => Self::Domain(host.to_owned()),
        }
    }

    fn from_host(h: &Host<'_>) -> Option<Self> {
        match h {
            Host::None => None,
            Host::V4(a) => Some(Self::V4(*a)),
            Host::V6(a) => Some(a.to_ipv4_mapped().map_or(Self::V6(*a), Self::V4)),
            Host::Domain(d) => Some(Self::Domain((*d).to_owned())),
        }
    }

    /// ATYP, ADDR and PORT's length.
    fn wire_len(&self) -> usize {
        match self {
            Self::V4(_) => 1 + 4 + 2,
            Self::V6(_) => 1 + 16 + 2,
            Self::Domain(d) => 1 + 1 + d.len() + 2,
        }
    }

    /// Appends ATYP | ADDR; `None` for a name SOCKS cannot carry.
    fn put(&self, out: &mut Vec<u8>) -> Option<()> {
        match self {
            Self::V4(a) => {
                out.push(atyp::IPV4);
                out.extend_from_slice(&a.octets());
            }
            Self::V6(a) => {
                out.push(atyp::IPV6);
                out.extend_from_slice(&a.octets());
            }
            Self::Domain(d) => {
                let len = u8::try_from(d.len()).ok().filter(|&l| l > 0)?;
                out.push(atyp::DOMAIN);
                out.push(len);
                out.extend_from_slice(d.as_bytes());
            }
        }
        Some(())
    }

    fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::V4(a) => Some(IpAddr::V4(*a)),
            Self::V6(a) => Some(IpAddr::V6(*a)),
            Self::Domain(_) => None,
        }
    }
}

/// Why a SOCKS UDP packet was dropped; the texts are Go's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// `errSocksUDPShortPacket`.
    #[error("short packet")]
    Short,
    /// `errSocksUDPBadReservedBytes`.
    #[error("bad reserved bytes")]
    Reserved,
    /// `errSocksUDPFragmented`.
    #[error("fragmentation unsupported")]
    Fragmented,
    /// `errSocksUDPMissingPort`.
    #[error("missing port")]
    MissingPort,
    /// `errSocksUDPMissingAddrType`.
    #[error("missing address type")]
    MissingAddrType,
    /// `errSocksUDPShortIPv4`.
    #[error("short ipv4 address")]
    ShortIpv4,
    /// `errSocksUDPMissingDomainSize`.
    #[error("missing domain length")]
    MissingDomainSize,
    /// `errSocksUDPShortDomain`.
    #[error("short domain")]
    ShortDomain,
    /// `errSocksUDPShortIPv6`.
    #[error("short ipv6 address")]
    ShortIpv6,
    /// `ErrUnsupportedAddressType`.
    #[error("unsupported address type: {0}")]
    AddressType(u8),
    /// A `FWD_UDP` header that does not end where its address does.
    #[error("invalid udp frame")]
    Frame,
}

/// A datagram's target and payload, borrowed from the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// The host as Go's string.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The data.
    pub payload: &'a [u8],
}

/// `parseSocksUDP`: `RSV RSV FRAG ATYP ADDR PORT DATA`.
///
/// # Errors
/// [`PacketError`].
pub fn parse_socks_udp(packet: &[u8]) -> Result<Datagram<'_>, PacketError> {
    if packet.len() < 4 {
        return Err(PacketError::Short);
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(PacketError::Reserved);
    }
    if packet[2] != 0 {
        return Err(PacketError::Fragmented);
    }
    let (host, off) = parse_host(packet, 3)?;
    if packet.len() < off + 2 {
        return Err(PacketError::MissingPort);
    }
    Ok(Datagram {
        host,
        port: u16::from_be_bytes([packet[off], packet[off + 1]]),
        payload: &packet[off + 2..],
    })
}

/// `parseSocksUDPHost`.
fn parse_host(packet: &[u8], off: usize) -> Result<(String, usize), PacketError> {
    let kind = *packet.get(off).ok_or(PacketError::MissingAddrType)?;
    match kind {
        atyp::IPV4 => {
            let b: [u8; 4] = packet
                .get(off + 1..off + 5)
                .and_then(|s| s.try_into().ok())
                .ok_or(PacketError::ShortIpv4)?;
            Ok((Ipv4Addr::from(b).to_string(), off + 5))
        }
        atyp::DOMAIN => {
            let size = usize::from(*packet.get(off + 1).ok_or(PacketError::MissingDomainSize)?);
            let name = packet
                .get(off + 2..off + 2 + size)
                .filter(|_| size > 0)
                .ok_or(PacketError::ShortDomain)?;
            Ok((String::from_utf8_lossy(name).into_owned(), off + 2 + size))
        }
        atyp::IPV6 => {
            let b: [u8; 16] = packet
                .get(off + 1..off + 17)
                .and_then(|s| s.try_into().ok())
                .ok_or(PacketError::ShortIpv6)?;
            Ok((go_ip_string(IpAddr::V6(Ipv6Addr::from(b))), off + 17))
        }
        other => Err(PacketError::AddressType(other)),
    }
}

/// `buildSocksUDP`: the header and the data, or `None` for a host SOCKS
/// cannot name.
pub fn build_socks_udp(from: &Addr, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(3 + from.wire_len() + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    from.put(&mut out)?;
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// `replySuccessUDP`: the relay socket's IPv4 address and port.
pub fn reply_success_udp(addr: SocketAddr) -> [u8; 10] {
    let ip = match addr.ip() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
    };
    let o = ip.octets();
    let p = addr.port().to_be_bytes();
    [5, 0, 0, 1, o[0], o[1], o[2], o[3], p[0], p[1]]
}

/// Frames a datagram as `FWD_UDP` carries it, in both directions:
/// `DATLEN u16 | HDRLEN u8 | ATYP | ADDR | PORT | DATA`, `HDRLEN` counting
/// the three length bytes and the address with its type and port.
pub fn encode_fwd_frame(addr: &Addr, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let data_len = u16::try_from(payload.len()).ok()?;
    let mut out = Vec::with_capacity(FWD_LENGTHS + addr.wire_len() + payload.len());
    out.extend_from_slice(&data_len.to_be_bytes());
    out.push(0);
    addr.put(&mut out)?;
    out.extend_from_slice(&port.to_be_bytes());
    out[2] = u8::try_from(out.len()).ok()?;
    out.extend_from_slice(payload);
    Some(out)
}

/// The first `FWD_UDP` frame in `buf`: the datagram and the bytes it took,
/// `Ok(None)` until it is whole. A header that misstates its address is an
/// error as soon as the header is in.
///
/// # Errors
/// [`PacketError`]; nothing more on the connection reads as frames then.
pub fn decode_fwd_frame(buf: &[u8]) -> Result<Option<(Datagram<'_>, usize)>, PacketError> {
    let Some(&[hi, lo, header_len]) = buf.get(..FWD_LENGTHS) else {
        return Ok(None);
    };
    let header_len = usize::from(header_len);
    let frame_len = header_len + usize::from(u16::from_be_bytes([hi, lo]));
    let Some(header) = buf.get(..header_len) else {
        return Ok(None);
    };
    let (host, off) = parse_host(header, FWD_LENGTHS).map_err(|e| match e {
        PacketError::AddressType(t) => PacketError::AddressType(t),
        _ => PacketError::Frame,
    })?;
    if off + 2 != header_len {
        return Err(PacketError::Frame);
    }
    if buf.len() < frame_len {
        return Ok(None);
    }
    Ok(Some((
        Datagram {
            host,
            port: u16::from_be_bytes([buf[off], buf[off + 1]]),
            payload: &buf[header_len..frame_len],
        },
        frame_len,
    )))
}

/// The most data a hev client reads in one frame naming `from`: 1,493
/// bytes from IPv4, 1,481 from IPv6.
pub fn fwd_max_reply(from: &Addr) -> usize {
    FWD_CLIENT_BUFFER.saturating_sub(from.wire_len())
}

/// Where a flow's answers go.
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// A `UDP ASSOCIATE` socket and the client's address on it.
    Assoc {
        sock: Arc<UdpSocket>,
        client: SocketAddr,
    },
    /// A `FWD_UDP` connection's writer, and the target the client sent to.
    Fwd {
        tx: mpsc::Sender<Queued>,
        to: Addr,
        to_port: u16,
    },
}

impl Reply {
    /// Hands one answer from `from:port` to the client; a full queue or a
    /// busy socket drops it.
    pub(crate) fn deliver(&self, from: &Addr, port: u16, payload: &[u8]) {
        match self {
            Self::Assoc { sock, client } => {
                let Some(pkt) = build_socks_udp(from, port, payload) else {
                    crate::debug!("drop udp response encode failed: unsupported address type");
                    return;
                };
                let _ = sock.try_send_to(&pkt, *client);
            }
            Self::Fwd { tx, to, to_port } => {
                // hev hands lwIP only an address of the client socket's
                // family: a name or the other family is answered as the
                // address the client sent to.
                let named = match (from.ip(), to.ip()) {
                    (Some(f), Some(t)) if f.is_ipv4() == t.is_ipv4() => Some((from, port)),
                    _ => None,
                };
                let (addr, port) = named.unwrap_or((to, *to_port));
                if payload.len() > fwd_max_reply(addr) {
                    crate::debug!(
                        "drop oversize udp reply ({} bytes) for a FWD_UDP client",
                        payload.len()
                    );
                    return;
                }
                if let Some(frame) = encode_fwd_frame(addr, port, payload) {
                    let Some(frame) = Queued::new(frame) else {
                        crate::debug!("drop udp reply: the FWD_UDP replies hold their budget");
                        return;
                    };
                    if tx.try_send(frame).is_err() {
                        crate::debug!("drop udp reply: the FWD_UDP queue is full");
                    }
                }
            }
        }
    }
}

/// Flows are keyed by their owner (one association or `FWD_UDP`
/// connection), the client's address and the target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    owner: u64,
    client: SocketAddr,
    /// A boxed str, not a `String`: the key is held twice (the flow and the
    /// index), and the capacity word is 8 bytes in each.
    host: Box<str>,
    port: u16,
}

#[derive(Debug)]
pub(crate) struct Flow {
    key: FlowKey,
    reply: Reply,
    last_seen: Instant,
}

#[derive(Debug)]
pub(crate) struct DirectFlow {
    remote: Arc<UdpSocket>,
    last_seen: Instant,
    reader: tokio::task::AbortHandle,
}

#[derive(Debug, Default)]
struct Table {
    by_id: HashMap<u64, Flow>,
    index: HashMap<FlowKey, u64>,
    direct: HashMap<FlowKey, DirectFlow>,
}

/// The run's flows.
#[derive(Debug)]
pub(crate) struct Flows {
    max: usize,
    table: Mutex<Table>,
    next_owner: AtomicU64,
    sweeping: AtomicBool,
}

impl Flows {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max: if max == 0 { DEFAULT_MAX_FLOWS } else { max },
            table: Mutex::new(Table::default()),
            next_owner: AtomicU64::new(1),
            sweeping: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn owner(&self) -> u64 {
        self.next_owner.fetch_add(1, Ordering::Relaxed)
    }

    /// `udpFlowID`: the flow's id, a new random one under the cap.
    fn id(&self, key: FlowKey, reply: &Reply) -> Option<u64> {
        let mut t = self.lock();
        let now = Instant::now();
        if let Some(&id) = t.index.get(&key) {
            if let Some(f) = t.by_id.get_mut(&id) {
                f.last_seen = now;
            }
            return Some(id);
        }
        if t.by_id.len() >= self.max {
            return None;
        }
        loop {
            let id: u64 = rand::random();
            if id != 0 && !t.by_id.contains_key(&id) {
                t.index.insert(key.clone(), id);
                t.by_id.insert(
                    id,
                    Flow {
                        key,
                        reply: reply.clone(),
                        last_seen: now,
                    },
                );
                return Some(id);
            }
        }
    }

    /// The flow's reply, marked seen.
    fn reply(&self, id: u64) -> Option<Reply> {
        let mut t = self.lock();
        let f = t.by_id.get_mut(&id)?;
        f.last_seen = Instant::now();
        Some(f.reply.clone())
    }

    /// Removes the flows `matches` takes; the lane flows' ids, to be told.
    fn remove(&self, matches: impl Fn(&FlowKey, Instant) -> bool) -> Vec<u64> {
        let mut t = self.lock();
        let gone: Vec<u64> = t
            .by_id
            .iter()
            .filter(|(_, f)| matches(&f.key, f.last_seen))
            .map(|(&id, _)| id)
            .collect();
        for id in &gone {
            if let Some(f) = t.by_id.remove(id) {
                t.index.remove(&f.key);
            }
        }
        t.direct.retain(|k, f| {
            let drop = matches(k, f.last_seen);
            if drop {
                f.reader.abort();
            }
            !drop
        });
        if t.by_id.capacity() > 64 && t.by_id.len() < t.by_id.capacity() / 4 {
            let n = t.by_id.len() * 2;
            t.by_id.shrink_to(n);
            let n = t.index.len() * 2;
            t.index.shrink_to(n);
        }
        gone
    }

    /// Lane and direct flows now held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> (usize, usize) {
        let t = self.lock();
        (t.by_id.len(), t.direct.len())
    }
}

/// `udpAssociationSource`: the TCP peer's address, narrowed by the request.
/// A request that named no port is pinned to the port of the first
/// datagram it takes, as hev's server connects its socket to the first
/// sender (hev-socks5-udp.c:260-279): another process at the client's
/// address cannot use an association it did not open, login or not. Go
/// takes any port at the peer's address (udp.go:256).
#[derive(Debug, Clone, Copy)]
struct Source {
    peer: IpAddr,
    request: Option<IpAddr>,
    port: u16,
}

impl Source {
    fn allows(&mut self, src: SocketAddr) -> bool {
        let ip = unmap(src.ip());
        if ip != self.peer || self.request.is_some_and(|r| r != ip) {
            return false;
        }
        if self.port == 0 {
            self.port = src.port();
        }
        src.port() == self.port
    }
}

/// The flows of one association or `FWD_UDP` connection, removed when it
/// ends however it ends (its task aborted included).
struct OwnedFlows<'a> {
    inner: &'a Arc<Inner>,
    owner: u64,
}

impl Drop for OwnedFlows<'_> {
    fn drop(&mut self) {
        let owner = self.owner;
        self.inner.remove_flows(|k, _| k.owner == owner);
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

impl Inner {
    /// `prepareUDPAssociate`: UDP on, and, with no rules, the session up.
    async fn prepare_udp(&self) -> bool {
        if self.cfg.udp_disabled {
            return false;
        }
        self.rules.is_some() || self.wait_session().await.is_ok()
    }

    /// `handleUDPAssociate`.
    pub(crate) async fn udp_associate(self: &Arc<Self>, mut conn: TcpStream, req: Request) {
        let peer = conn.peer_addr().map(|a| unmap(a.ip()));
        let (true, Ok(peer)) = (self.prepare_udp().await, peer) else {
            let _ = conn
                .write_all(&reply(rep::HOST_UNREACHABLE, &req.addr))
                .await;
            return;
        };
        let mut allowed = Source {
            peer,
            request: req
                .addr
                .parse::<IpAddr>()
                .ok()
                .filter(|ip| !ip.is_unspecified())
                .map(unmap),
            port: req.port,
        };
        let ip = match conn.local_addr().map(|a| a.ip()) {
            Ok(IpAddr::V4(a)) if !a.is_unspecified() => a,
            _ => Ipv4Addr::LOCALHOST,
        };
        let sock = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(ip), 0)).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                crate::info!("socks udp associate listen failed: listen udp associate: {e}");
                let _ = conn
                    .write_all(&reply(rep::HOST_UNREACHABLE, &req.addr))
                    .await;
                return;
            }
        };
        self.ensure_sweeper();
        let Ok(addr) = sock.local_addr() else {
            let _ = conn
                .write_all(&reply(rep::HOST_UNREACHABLE, &req.addr))
                .await;
            return;
        };
        if conn.write_all(&reply_success_udp(addr)).await.is_err() {
            return;
        }
        crate::info!("SOCKS5 UDP associate listening on {addr}");
        let owner = self.flows.owner();
        let _flows = OwnedFlows { inner: self, owner };
        let assoc = self.run.child_token();
        let (mut rd, _wr) = conn.into_split();
        let watch = {
            let assoc = assoc.clone();
            tokio::spawn(async move {
                let mut b = [0u8; 64];
                loop {
                    tokio::select! {
                        () = assoc.cancelled() => break,
                        r = rd.read(&mut b) => if matches!(r, Ok(0) | Err(_)) { break },
                    }
                }
                assoc.cancel();
            })
        };
        'assoc: loop {
            tokio::select! {
                () = assoc.cancelled() => break,
                r = sock.readable() => if let Err(e) = r {
                    crate::debug!("socks udp read failed: {e}");
                    break;
                },
            }
            // The buffer lives only while datagrams wait.
            let mut buf = vec![0u8; READ_BUFFER];
            loop {
                let (n, src) = match sock.try_recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        crate::debug!("socks udp read failed: {e}");
                        break 'assoc;
                    }
                };
                if !allowed.allows(src) {
                    crate::debug!("drop socks udp packet from unbound source: {src}");
                    continue;
                }
                let dg = match parse_socks_udp(&buf[..n]) {
                    Ok(dg) => dg,
                    Err(e) => {
                        crate::debug!("drop malformed socks udp packet: {e}");
                        continue;
                    }
                };
                let reply = Reply::Assoc {
                    sock: sock.clone(),
                    client: src,
                };
                self.forward(owner, src, &reply, &dg, &assoc).await;
            }
        }
        assoc.cancel();
        watch.abort();
    }

    /// hev's `FWD_UDP`: datagrams framed on this connection both ways.
    pub(crate) async fn fwd_udp(self: &Arc<Self>, mut conn: TcpStream, req: Request) {
        let peer = conn.peer_addr();
        let (true, Ok(peer)) = (self.prepare_udp().await, peer) else {
            let _ = conn
                .write_all(&reply(rep::HOST_UNREACHABLE, &req.addr))
                .await;
            return;
        };
        if conn.write_all(&reply(rep::SUCCESS, "")).await.is_err() {
            return;
        }
        let _ = conn.set_nodelay(true);
        crate::debug!("SOCKS5 FWD_UDP from {peer}");
        self.ensure_sweeper();
        let owner = self.flows.owner();
        let _flows = OwnedFlows { inner: self, owner };
        let assoc = self.run.child_token();
        let (mut rd, mut wr) = conn.into_split();
        let (tx, mut rx) = mpsc::channel::<Queued>(FWD_REPLY_QUEUE);
        let writer = {
            let assoc = assoc.clone();
            tokio::spawn(async move {
                let mut gather: Vec<Queued> = Vec::with_capacity(FWD_GATHER);
                loop {
                    let first = tokio::select! {
                        () = assoc.cancelled() => break,
                        f = rx.recv() => match f { Some(f) => f, None => break },
                    };
                    // The frames go out gathered in one vectored write, and
                    // stay counted in the budget until written: no buffer
                    // of their own. The write ends with the association,
                    // however slow the client reads.
                    let mut bytes = first.0.len();
                    gather.push(first);
                    while bytes < FWD_WRITE_BATCH && gather.len() < FWD_GATHER {
                        match rx.try_recv() {
                            Ok(f) => {
                                bytes += f.0.len();
                                gather.push(f);
                            }
                            Err(_) => break,
                        }
                    }
                    let wrote = tokio::select! {
                        () = assoc.cancelled() => break,
                        r = write_frames(&mut wr, &gather) => r,
                    };
                    gather.clear();
                    if wrote.is_err() {
                        break;
                    }
                }
                assoc.cancel();
            })
        };
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match decode_fwd_frame(&buf) {
                Ok(Some((dg, used))) => {
                    let reply = Reply::Fwd {
                        tx: tx.clone(),
                        to: Addr::parse(&dg.host),
                        to_port: dg.port,
                    };
                    self.forward(owner, peer, &reply, &dg, &assoc).await;
                    buf.drain(..used);
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    crate::debug!("drop FWD_UDP connection: {e}");
                    break;
                }
            }
            if buf.is_empty() {
                // A quiet connection holds no buffer.
                buf = Vec::new();
                let ready = tokio::select! {
                    () = assoc.cancelled() => break,
                    r = rd.readable() => r,
                };
                if ready.is_err() {
                    break;
                }
            }
            if buf.capacity() - buf.len() < 2048 {
                buf.reserve(2048);
            }
            let got = tokio::select! {
                () = assoc.cancelled() => break,
                r = rd.read_buf(&mut buf) => r,
            };
            if matches!(got, Ok(0) | Err(_)) {
                break;
            }
        }
        assoc.cancel();
        drop(tx);
        // Its write ends with the association: this cannot hang.
        let _ = writer.await;
    }

    /// `forwardLocalUDP`: direct DNS, DNS over a stream, a direct flow, or
    /// the datagram lane.
    async fn forward(
        self: &Arc<Self>,
        owner: u64,
        client: SocketAddr,
        reply: &Reply,
        dg: &Datagram<'_>,
        assoc: &CancellationToken,
    ) {
        if self.try_dns_direct(reply, dg, assoc) || self.try_dns_over_stream(reply, dg, assoc) {
            return;
        }
        if self.try_direct_udp(owner, client, reply, dg, assoc).await {
            return;
        }
        let key = FlowKey {
            owner,
            client,
            host: dg.host.as_str().into(),
            port: dg.port,
        };
        let Some(id) = self.flows.id(key, reply) else {
            crate::debug!("drop udp packet: too many udp flows");
            return;
        };
        let mut record = [0u8; UDP_MAX_RECORD];
        let len = {
            let mut lane = self.datagram.lock().unwrap_or_else(PoisonError::into_inner);
            match lane.seal(
                FrameType::Packet,
                id,
                dg.host.as_bytes(),
                dg.port,
                dg.payload,
            ) {
                Ok(r) => {
                    record[..r.len()].copy_from_slice(r);
                    r.len()
                }
                Err(olc_muxconn::datagram::SealDatagramError::Encode(e)) => {
                    crate::debug!("drop udp packet encode failed: {e}");
                    return;
                }
                Err(e) => {
                    crate::debug!("drop udp packet encrypt failed: {e}");
                    return;
                }
            }
        };
        if !self.wait_datagram_ready(assoc).await {
            crate::debug!("drop udp packet: the datagram lane did not take it");
            return;
        }
        if let Err(e) = self.link.send_datagram(&record[..len]).await {
            crate::debug!("send udp datagram failed: {e}");
        }
    }

    /// `waitDatagramReady`.
    async fn wait_datagram_ready(&self, assoc: &CancellationToken) -> bool {
        if self.link.can_send() {
            return true;
        }
        let deadline = Instant::now() + DATAGRAM_READY_TIMEOUT;
        loop {
            tokio::select! {
                () = assoc.cancelled() => return false,
                () = tokio::time::sleep_until(deadline) => return false,
                () = tokio::time::sleep(DATAGRAM_POLL_DELAY) => {
                    if self.link.can_send() {
                        return true;
                    }
                }
            }
        }
    }

    /// `onDatagram`: a record from the lane, to its flow's client.
    pub(crate) fn on_datagram(&self, record: &mut [u8]) {
        if self.cfg.udp_disabled {
            return;
        }
        let wire = match self.keys.open_in_place(RecordLane::Udp, record) {
            Ok(w) => w,
            Err(e) => {
                crate::debug!("drop udp datagram decrypt failed: {e}");
                return;
            }
        };
        let frame = match udpwire::decode(wire) {
            Ok(f) => f,
            Err(e) => {
                crate::debug!("drop udp datagram decode failed: {e}");
                return;
            }
        };
        if frame.kind != FrameType::Packet {
            return;
        }
        let Some(reply) = self.flows.reply(frame.flow_id) else {
            return;
        };
        let Some(from) = Addr::from_host(&frame.host) else {
            return;
        };
        reply.deliver(&from, frame.port, frame.payload);
    }

    /// `tryDirectUDP`: a target the rules name gets a socket of this
    /// process; a dial that fails drops the packet.
    async fn try_direct_udp(
        self: &Arc<Self>,
        owner: u64,
        client: SocketAddr,
        reply: &Reply,
        dg: &Datagram<'_>,
        assoc: &CancellationToken,
    ) -> bool {
        if !self.rules.as_ref().is_some_and(|r| r.match_host(&dg.host)) {
            return false;
        }
        let key = FlowKey {
            owner,
            client,
            host: dg.host.as_str().into(),
            port: dg.port,
        };
        let existing = {
            let mut t = self.flows.lock();
            let held = t.direct.len();
            match t.direct.get_mut(&key) {
                Some(f) => {
                    f.last_seen = Instant::now();
                    Some(f.remote.clone())
                }
                None if held >= self.flows.max => {
                    crate::debug!("direct udp to {}:{}: too many udp flows", dg.host, dg.port);
                    return false;
                }
                None => None,
            }
        };
        let remote = match existing {
            Some(r) => r,
            None => match self.open_direct_flow(key, reply, dg, assoc).await {
                Some(r) => r,
                None => return true,
            },
        };
        if let Err(e) = remote.send(dg.payload).await {
            crate::debug!("direct udp to {}:{} write failed: {e}", dg.host, dg.port);
        }
        true
    }

    async fn open_direct_flow(
        self: &Arc<Self>,
        key: FlowKey,
        reply: &Reply,
        dg: &Datagram<'_>,
        assoc: &CancellationToken,
    ) -> Option<Arc<UdpSocket>> {
        let target = crate::direct::join_host_port(&dg.host, dg.port);
        let dialed = async {
            let ip = *crate::resolver::lookup(&dg.host)
                .await?
                .first()
                .ok_or_else(|| std::io::Error::other("no address"))?;
            let sock = crate::net::udp_socket(ip).await?;
            sock.connect(SocketAddr::new(ip, dg.port)).await?;
            Ok::<_, std::io::Error>(sock)
        };
        let remote = match dialed.await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                crate::info!("direct udp to {target} failed: {e}");
                return None;
            }
        };
        let mut t = self.flows.lock();
        if let Some(f) = t.direct.get(&key) {
            return Some(f.remote.clone());
        }
        let reader = tokio::spawn(read_direct_flow(
            Arc::downgrade(self),
            key.clone(),
            remote.clone(),
            reply.clone(),
            Addr::parse(&dg.host),
            dg.port,
            assoc.clone(),
        ));
        t.direct.insert(
            key,
            DirectFlow {
                remote: remote.clone(),
                last_seen: Instant::now(),
                reader: reader.abort_handle(),
            },
        );
        drop(t);
        crate::info!("direct udp to {}:{}", dg.host, dg.port);
        Some(remote)
    }

    /// Starts the run's one idle-flow sweeper.
    fn ensure_sweeper(self: &Arc<Self>) {
        if self.flows.sweeping.swap(true, Ordering::Relaxed) {
            return;
        }
        let me = Arc::downgrade(self);
        let run = self.run.clone();
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval_at(Instant::now() + FLOW_SWEEP_INTERVAL, FLOW_SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = run.cancelled() => return,
                    now = tick.tick() => {
                        let Some(inner) = me.upgrade() else { return };
                        inner.remove_flows(|_, seen| now.duration_since(seen) >= FLOW_IDLE_TIMEOUT);
                    }
                }
            }
        });
    }

    /// Removes flows and tells the server of the lane's
    /// (`sendUDPFlowCloses`).
    fn remove_flows(self: &Arc<Self>, matches: impl Fn(&FlowKey, Instant) -> bool) {
        let gone = self.flows.remove(matches);
        if gone.is_empty() || self.cfg.udp_disabled || !self.link.can_send() {
            return;
        }
        // From a drop guard the runtime may be going away: then the server
        // learns of the flows' end from their idle timeout.
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let me = self.clone();
        rt.spawn(async move {
            let mut record = [0u8; UDP_MAX_RECORD];
            for id in gone {
                let len = {
                    let mut lane = me.datagram.lock().unwrap_or_else(PoisonError::into_inner);
                    match lane.seal(FrameType::Close, id, b"", 0, b"") {
                        Ok(r) => {
                            record[..r.len()].copy_from_slice(r);
                            r.len()
                        }
                        Err(_) => continue,
                    }
                };
                let _ = me.link.send_datagram(&record[..len]).await;
            }
        });
    }
}

/// `readDirectFlow`: the target's datagrams back to the client until the
/// flow is removed or its association ends.
async fn read_direct_flow(
    inner: std::sync::Weak<Inner>,
    key: FlowKey,
    remote: Arc<UdpSocket>,
    reply: Reply,
    target: Addr,
    port: u16,
    assoc: CancellationToken,
) {
    loop {
        tokio::select! {
            () = assoc.cancelled() => return,
            r = remote.readable() => if r.is_err() { return },
        }
        let mut buf = vec![0u8; READ_BUFFER];
        loop {
            let n = match remote.try_recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            };
            let Some(inner) = inner.upgrade() else { return };
            if let Some(f) = inner.flows.lock().direct.get_mut(&key) {
                f.last_seen = Instant::now();
            }
            reply.deliver(&target, port, &buf[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_udp_packets_parse_and_build_as_gos() {
        let pkt = [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 0xab];
        let dg = parse_socks_udp(&pkt).unwrap();
        assert_eq!(
            (dg.host.as_str(), dg.port, dg.payload),
            ("8.8.8.8", 53, &[0xab][..])
        );
        let built = build_socks_udp(&Addr::parse(&dg.host), dg.port, dg.payload).unwrap();
        assert_eq!(built, pkt);
        assert_eq!(
            parse_socks_udp(&[0, 0, 1, 1]).unwrap_err().to_string(),
            "fragmentation unsupported"
        );
        assert_eq!(
            parse_socks_udp(&[0, 1, 0, 1]).unwrap_err(),
            PacketError::Reserved
        );
        assert_eq!(
            parse_socks_udp(&[0, 0, 0, 3, 0, 0, 1]).unwrap_err(),
            PacketError::ShortDomain
        );
        assert_eq!(
            parse_socks_udp(&[0, 0, 0, 1, 1, 2, 3, 4, 0]).unwrap_err(),
            PacketError::MissingPort
        );
        assert_eq!(
            parse_socks_udp(&[0, 0, 0, 9]).unwrap_err().to_string(),
            "unsupported address type: 9"
        );
        assert_eq!(
            Addr::parse("::ffff:1.2.3.4"),
            Addr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert!(build_socks_udp(&Addr::Domain(String::new()), 1, b"").is_none());
        let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        assert_eq!(
            reply_success_udp(addr),
            [5, 0, 0, 1, 127, 0, 0, 1, 0x14, 0xe9]
        );
    }

    #[test]
    fn fwd_frames_lay_out_as_hev_writes_them_and_split_reads_wait() {
        let frame = encode_fwd_frame(&Addr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53, b"q").unwrap();
        assert_eq!(frame, [0, 1, 10, 1, 192, 0, 2, 53, 0, 53, b'q']);
        for cut in 0..frame.len() {
            assert_eq!(decode_fwd_frame(&frame[..cut]).unwrap(), None, "cut {cut}");
        }
        let mut two = frame.clone();
        two.extend_from_slice(&frame);
        let (dg, used) = decode_fwd_frame(&two).unwrap().unwrap();
        assert_eq!(
            (dg.host.as_str(), dg.port, dg.payload, used),
            ("192.0.2.53", 53, &b"q"[..], 11)
        );
        // A header length that is not the address's: a frame error once the
        // whole header (12 bytes here) has arrived.
        let mut bad = frame.clone();
        bad[2] = 12;
        bad.push(0);
        assert_eq!(decode_fwd_frame(&bad).unwrap_err(), PacketError::Frame);
        let v6 = Addr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(fwd_max_reply(&Addr::V4(Ipv4Addr::LOCALHOST)), 1493);
        assert_eq!(fwd_max_reply(&v6), 1481);
        assert_eq!(encode_fwd_frame(&v6, 1, b"").unwrap()[2], 22);
    }

    #[tokio::test]
    async fn gathered_frames_are_written_whole_through_short_writes() {
        crate::testing::bounded(async {
            let (mut a, mut b) = tokio::io::duplex(7);
            let frames: Vec<Queued> = (1..=5u8)
                .map(|i| Queued::new(vec![i; usize::from(i) * 3]).unwrap())
                .collect();
            let want: Vec<u8> = frames.iter().flat_map(|f| f.0.clone()).collect();
            let read = tokio::spawn(async move {
                let mut got = vec![0; 45];
                b.read_exact(&mut got).await.unwrap();
                got
            });
            write_frames(&mut a, &frames).await.unwrap();
            assert_eq!(read.await.unwrap(), want);
        })
        .await;
    }

    #[tokio::test]
    async fn fwd_replies_name_the_target_family_and_drop_what_hev_cannot_read() {
        crate::testing::bounded(fwd_replies()).await;
    }

    async fn fwd_replies() {
        let (tx, mut rx) = mpsc::channel(4);
        let to = Addr::V4(Ipv4Addr::new(198, 18, 0, 7));
        let reply = Reply::Fwd {
            tx,
            to: to.clone(),
            to_port: 443,
        };
        reply.deliver(&Addr::V6("2001:db8::35".parse().unwrap()), 9, b"a");
        let f = rx.recv().await.unwrap();
        assert_eq!(
            &f.0[3..10],
            &[1, 198, 18, 0, 7, 1, 187],
            "the other family is answered as the target"
        );
        reply.deliver(&Addr::V4(Ipv4Addr::new(192, 0, 2, 9)), 4433, b"b");
        let f = rx.recv().await.unwrap();
        assert_eq!(&f.0[3..10], &[1, 192, 0, 2, 9, 0x11, 0x51]);
        reply.deliver(&Addr::V4(Ipv4Addr::LOCALHOST), 1, &[0; 1494]);
        reply.deliver(&Addr::V4(Ipv4Addr::LOCALHOST), 1, &[0; 1493]);
        assert_eq!(
            rx.recv().await.unwrap().0.len(),
            10 + 1493,
            "the oversize one alone is dropped"
        );
    }

    #[test]
    fn fwd_replies_share_one_byte_budget() {
        // A client that stops reading holds at most the budget, whatever
        // its queue's length.
        let (tx, mut rx) = mpsc::channel(1000);
        let reply = Reply::Fwd {
            tx,
            to: Addr::V4(Ipv4Addr::LOCALHOST),
            to_port: 1,
        };
        for _ in 0..1000 {
            reply.deliver(&Addr::V4(Ipv4Addr::LOCALHOST), 1, &[0; 1493]);
        }
        let mut frames = Vec::new();
        while let Ok(f) = rx.try_recv() {
            frames.push(f);
        }
        let held: usize = frames.iter().map(|f| f.0.len()).sum();
        let frame = 10 + 1493;
        // Other tests may hold a few frames of the same budget meanwhile.
        assert!(held <= FWD_QUEUE_BUDGET, "{held}");
        assert!(held + 8 * frame > FWD_QUEUE_BUDGET, "{held}");
        assert!(frames.len() < 1000, "the budget, not the queue, stopped it");
        let before = fwd_queued();
        drop(frames);
        assert!(fwd_queued() + held <= before, "every frame gives its bytes back");
    }

    #[test]
    fn flows_take_random_ids_under_the_cap_and_idle_out() {
        let flows = Flows::new(2);
        let (tx, _rx) = mpsc::channel(1);
        let reply = Reply::Fwd {
            tx,
            to: Addr::V4(Ipv4Addr::LOCALHOST),
            to_port: 1,
        };
        let key = |port| FlowKey {
            owner: 1,
            client: "127.0.0.1:1".parse().unwrap(),
            host: "h".into(),
            port,
        };
        let a = flows.id(key(1), &reply).unwrap();
        assert_ne!(a, 0);
        assert_eq!(
            flows.id(key(1), &reply),
            Some(a),
            "the same flow keeps its id"
        );
        assert!(flows.id(key(2), &reply).is_some());
        assert_eq!(flows.id(key(3), &reply), None, "the cap");
        assert!(flows.reply(a).is_some());
        let gone = flows.remove(|k, _| k.port == 1);
        assert_eq!(gone, vec![a]);
        assert_eq!(flows.len(), (1, 0));
    }

    #[test]
    fn an_association_source_is_the_peer_narrowed_by_the_request() {
        let any = Source {
            peer: "127.0.0.1".parse().unwrap(),
            request: None,
            port: 0,
        };
        let mut first = any;
        assert!(!first.allows("127.0.0.2:5000".parse().unwrap()));
        assert!(first.allows("[::ffff:127.0.0.1]:5000".parse().unwrap()));
        let mut pinned = Source { port: 7, ..any };
        assert!(!pinned.allows("127.0.0.1:5000".parse().unwrap()));
        assert!(pinned.allows("127.0.0.1:7".parse().unwrap()));
    }

    #[test]
    fn a_request_that_named_no_port_is_pinned_to_its_first_sender() {
        // hev's UDP-in-UDP connects its socket to the first datagram's
        // sender (hev-socks5-udp.c:260-279): another process at the same
        // address cannot use the association after it.
        let mut any = Source {
            peer: "127.0.0.1".parse().unwrap(),
            request: None,
            port: 0,
        };
        assert!(any.allows("127.0.0.1:5000".parse().unwrap()));
        assert!(!any.allows("127.0.0.1:5001".parse().unwrap()));
        assert!(any.allows("127.0.0.1:5000".parse().unwrap()));
    }
}

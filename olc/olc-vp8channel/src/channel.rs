// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The client's vp8channel, sans-IO: `streamTransport` in single-peer mode
//! (`vp8channel/transport.go`, `epoch.go`, `inbound.go`, `control.go`,
//! `datagram.go` at 2d4266af). The server mode (a session per remote
//! epoch, `peers.go`) is the Go server's and is not ported.
//!
//! Two KCP planes ride one track: bulk data on the local data epoch, and
//! control (handshake, liveness) on `epoch | 0x80000000`, so control never
//! queues behind a large write; lossy datagrams go around KCP. The data
//! plane's packets are addressed to the server's epoch once the encrypted
//! handshake confirmed it ([`Channel::confirm_peer`]); before that every
//! frame is a broadcast. [`Channel::tick`] is the writer's frame interval,
//! [`Channel::update`] the KCP timers, [`Channel::handle_incoming_frame`]
//! a frame the track reader assembled.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use olc_kcp::Config as KcpConfig;

use crate::conn::{
    Plane, SendError, CAN_SEND_HIGH_WATERMARK, CONSTRAINED_OUTBOUND_QUEUE, CONTROL_OUTBOUND_QUEUE,
    OUTBOUND_QUEUE,
};
use crate::lane::LaneParams;
use crate::log::{debug, info};
use crate::vp9;
use crate::wire::{
    binding_token, datagram_frame, epoch_header, format_peer_id, parse_epoch_header, parse_peer_id,
    random_epoch, split_datagram_batch_payload, split_datagram_payload, split_kcp_payload,
    EpochHeader, TooLarge, CONTROL_EPOCH_FLAG, EPOCH_HDR_LEN, MAX_PAYLOAD_SIZE,
};
use crate::writer::{SampleSink, Tick, Writer, DATAGRAM_QUEUE};

/// `defaultFPS`.
pub const DEFAULT_FPS: u32 = 30;
/// `defaultBatchSize`.
pub const DEFAULT_BATCH_SIZE: usize = 64;
/// `transport.MaxFPS`.
pub const MAX_FPS: u32 = 240;
/// `defaultPeerRestartGrace`.
pub const DEFAULT_PEER_RESTART_GRACE: Duration = Duration::from_secs(6);
/// `kcpSndWnd`, `kcpRcvWnd`: the server profile's windows.
pub const KCP_WND: i32 = 4096;
/// `kcpConstrainedSndWnd`, `kcpConstrainedRcvWnd`: the phone's.
pub const KCP_CONSTRAINED_WND: i32 = 512;

/// `vp8channel.Options` after `withDefaults`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Frames a second the writer ticks at.
    pub fps: u32,
    /// KCP packets a sample carries at most.
    pub batch_size: usize,
}

impl Options {
    /// `withDefaults`: FPS 0 is 30, over 240 is 240; batch 0 is 64.
    #[must_use]
    pub fn with_defaults(fps: u32, batch_size: usize) -> Self {
        Self {
            fps: match fps {
                0 => DEFAULT_FPS,
                f => f.min(MAX_FPS),
            },
            batch_size: if batch_size == 0 {
                DEFAULT_BATCH_SIZE
            } else {
                batch_size
            },
        }
    }

    /// `time.Second / time.Duration(FPS)`, ns.
    #[must_use]
    pub fn frame_interval(&self) -> i64 {
        1_000_000_000 / i64::from(self.fps)
    }
}

/// The codec the frames ride as (`carrier.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Carrier {
    /// The transport's own: every frame opens with the VP8 keepalive.
    #[default]
    Vp8,
    /// MTS Link: re-headed as a VP9 keyframe ([`crate::vp9`]); the relay's
    /// keyframe requests are answered.
    Vp9,
}

/// What the channel is built from.
#[derive(Debug, Clone)]
pub struct Config {
    /// `cfg.ChannelID`.
    pub channel_id: String,
    /// `cfg.RoomURL` (its `?ice=` hint is no part of the token).
    pub room_url: String,
    /// FPS and batch.
    pub options: Options,
    /// The phone profile (`runtime.BuffersAreConstrained`).
    pub constrained: bool,
    /// The codec.
    pub carrier: Carrier,
}

/// What [`Channel::handle_incoming_frame`] made of a frame (`inbound.go`),
/// for tests and the vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// Short, or the CRC does not match.
    BadHeader,
    /// Another pair's binding token.
    ForeignToken,
    /// Our own frame, data or control, back from the relay.
    Loopback,
    /// Addressed to another participant.
    NotForUs,
    /// An empty control frame.
    ControlKeepalive,
    /// A control frame not addressed to our control epoch.
    ControlNotOurs,
    /// Handed to the control plane.
    Control,
    /// An OLUB batch: this many of its datagrams were delivered.
    DatagramBatch(usize),
    /// An OLUD datagram, delivered or not.
    Datagram(bool),
    /// Data before the handshake confirmed a peer.
    DataUnconfirmed,
    /// Data from an epoch that is not the peer's.
    DataOtherEpoch,
    /// An empty data frame from the peer (a keepalive).
    DataKeepalive,
    /// Handed to the data plane.
    Data,
}

/// `ConfirmPeer`'s refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmError {
    /// Not eight hex digits' worth of `u32`.
    #[error("vp8channel: confirm peer: invalid peer id {0:?}")]
    BadId(String),
    /// Zero, or a control epoch.
    #[error("vp8channel: invalid peer id: data epoch 0x{0:08x}")]
    NotData(u32),
}

/// `SendDatagram`'s refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    /// `ErrTransportClosed`.
    #[error("vp8channel transport closed")]
    Closed,
    /// `ErrTrafficPayloadTooLarge` (`transport/transport.go`), in its words.
    #[error("traffic payload exceeds max_payload_size")]
    TooLarge,
    /// `ErrDatagramQueueFull`.
    #[error("vp8channel datagram queue full")]
    QueueFull,
}

/// Takes each datagram as it arrives (`OnDatagram`); it must not block.
pub type DatagramSink = Box<dyn FnMut(&[u8]) + Send>;

/// The client's transport state.
pub struct Channel {
    base: Instant,
    token: u32,
    local_epoch: u32,
    peer_epoch: u32,
    peer_confirmed: bool,
    peer_seen: bool,
    link_unhealthy: bool,
    last_peer_frame: Option<Instant>,
    peer_restarting: bool,
    /// `peerRestartGrace` (tests shorten it).
    pub peer_restart_grace: Duration,
    /// The data plane.
    pub data: Plane,
    /// The control plane.
    pub control: Plane,
    datagram: VecDeque<Vec<u8>>,
    on_datagram: Option<DatagramSink>,
    writer: Writer,
    /// The lane's numbers (tests shorten the blackout and probe).
    pub params: LaneParams,
    keyframe_wanted: bool,
    carrier: Carrier,
    dress_buf: Vec<u8>,
    closed: bool,
    reconnect_wanted: Option<&'static str>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("local_epoch", &format_args!("{:08x}", self.local_epoch))
            .field("peer_epoch", &format_args!("{:08x}", self.peer_epoch))
            .field("peer_confirmed", &self.peer_confirmed)
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// `newStreamTransport` in client mode; `now` is the clocks' origin.
    #[must_use]
    pub fn new(cfg: &Config, now: Instant) -> Self {
        Self::with_epoch(cfg, now, random_epoch())
    }

    /// [`Channel::new`] with a chosen first epoch (tests, vectors).
    #[must_use]
    pub fn with_epoch(cfg: &Config, now: Instant, epoch: u32) -> Self {
        let wnd = if cfg.constrained {
            KCP_CONSTRAINED_WND
        } else {
            KCP_WND
        };
        let kcp = KcpConfig::vp8channel(wnd, wnd);
        let out = if cfg.constrained {
            CONSTRAINED_OUTBOUND_QUEUE
        } else {
            OUTBOUND_QUEUE
        };
        let fi = cfg.options.frame_interval();
        #[allow(clippy::cast_sign_loss)]
        let send_window = wnd as usize;
        Self {
            base: now,
            token: binding_token(&cfg.channel_id, &cfg.room_url),
            local_epoch: epoch,
            peer_epoch: 0,
            peer_confirmed: false,
            peer_seen: false,
            link_unhealthy: false,
            last_peer_frame: None,
            peer_restarting: false,
            peer_restart_grace: DEFAULT_PEER_RESTART_GRACE,
            data: Plane::new(out, true, kcp, now),
            control: Plane::new(CONTROL_OUTBOUND_QUEUE, false, kcp, now),
            datagram: VecDeque::new(),
            on_datagram: None,
            writer: Writer::new(fi),
            params: LaneParams::new(fi, cfg.options.batch_size, send_window),
            keyframe_wanted: false,
            carrier: cfg.carrier,
            dress_buf: Vec::new(),
            closed: false,
            reconnect_wanted: None,
        }
    }

    /// The channel's clock: ns since its origin, never 0 (`monoNow`).
    #[must_use]
    pub fn ns(&self, now: Instant) -> i64 {
        i64::try_from(now.saturating_duration_since(self.base).as_nanos()).unwrap_or(i64::MAX - 1)
            + 1
    }

    /// Sets the datagram callback (`cfg.OnDatagram`).
    pub fn set_datagram_sink(&mut self, sink: Option<DatagramSink>) {
        self.on_datagram = sink;
    }

    /// The binding token.
    #[must_use]
    pub fn token(&self) -> u32 {
        self.token
    }

    /// The data epoch.
    #[must_use]
    pub fn local_epoch(&self) -> u32 {
        self.local_epoch
    }

    /// `controlEpochValue`.
    #[must_use]
    pub fn control_epoch(&self) -> u32 {
        self.local_epoch | CONTROL_EPOCH_FLAG
    }

    /// `LocalPeerID`.
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        format_peer_id(self.local_epoch)
    }

    /// `epochHeader`: the data epoch, broadcast.
    #[must_use]
    pub fn epoch_header(&self) -> EpochHeader {
        epoch_header(self.token, self.local_epoch, 0)
    }

    /// `controlEpochHeader`.
    #[must_use]
    pub fn control_epoch_header(&self) -> EpochHeader {
        epoch_header(self.token, self.control_epoch(), 0)
    }

    /// `Connect` past the provider: both planes up (once).
    pub fn connect(&mut self, now: Instant) {
        if self.data.start(self.epoch_header(), now) {
            info!(
                "vp8channel: KCP started localEpoch=0x{:08x}",
                self.local_epoch
            );
        }
        if self.control.start(self.control_epoch_header(), now) {
            info!(
                "vp8channel: control KCP started epoch=0x{:08x}",
                self.control_epoch()
            );
        }
    }

    /// `rotateEpochHeader`: a fresh data epoch.
    fn rotate_epoch_header(&mut self) -> EpochHeader {
        loop {
            let next = random_epoch();
            if next != self.local_epoch {
                self.local_epoch = next;
                break;
            }
        }
        self.epoch_header()
    }

    /// `restartPlanes` (`ResetPeer`, and the provider's reconnect): a new
    /// epoch, both planes restarted on it, the peer forgotten.
    pub fn restart_planes(&mut self, now: Instant) {
        self.peer_confirmed = false;
        self.peer_seen = false;
        self.peer_epoch = 0;
        let hdr = self.rotate_epoch_header();
        self.data.restart(hdr, now);
        let chdr = self.control_epoch_header();
        self.control.restart(chdr, now);
    }

    /// `ConfirmPeer`: binds the data plane to the server's epoch.
    ///
    /// # Errors
    /// [`ConfirmError`].
    pub fn confirm_peer(&mut self, peer_id: &str, now: Instant) -> Result<(), ConfirmError> {
        let epoch =
            parse_peer_id(peer_id).ok_or_else(|| ConfirmError::BadId(peer_id.to_owned()))?;
        if epoch == 0 || epoch & CONTROL_EPOCH_FLAG != 0 {
            return Err(ConfirmError::NotData(epoch));
        }
        self.data
            .set_header(epoch_header(self.token, self.local_epoch, epoch));
        self.peer_epoch = epoch;
        self.last_peer_frame = Some(now);
        self.peer_restarting = false;
        self.peer_confirmed = true;
        info!("vp8channel: authenticated peer epoch=0x{epoch:08x}");
        Ok(())
    }

    /// Whether the handshake confirmed a peer.
    #[must_use]
    pub fn peer_confirmed(&self) -> bool {
        self.peer_confirmed
    }

    /// `PeerSeen`.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        self.peer_seen
    }

    /// `NotifyLinkHealth`.
    pub fn notify_link_health(&mut self, unhealthy: bool) {
        self.link_unhealthy = unhealthy;
    }

    /// `requestKeyframe`: a relay asked; only a carrier whose relay asks
    /// this way answers.
    pub fn request_keyframe(&mut self) {
        if self.carrier == Carrier::Vp9 {
            self.keyframe_wanted = true;
        }
    }

    /// The provider rebuild the peer-restart watchdog asked for, once.
    pub fn take_reconnect(&mut self) -> Option<&'static str> {
        self.reconnect_wanted.take()
    }

    /// `Send` on the data plane.
    ///
    /// # Errors
    /// [`SendError`]; `WouldBlock` is Go's blocking `Write`.
    pub fn send(&mut self, msg: &[u8], now: Instant) -> Result<(), SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        let ns = self.ns(now);
        self.data.send(msg, now, ns)
    }

    /// `ControlSend`.
    ///
    /// # Errors
    /// [`SendError`].
    pub fn control_send(&mut self, msg: &[u8], now: Instant) -> Result<(), SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        let ns = self.ns(now);
        self.control.send(msg, now, ns)
    }

    /// `SendDatagram`: to the confirmed peer, before that a broadcast.
    ///
    /// # Errors
    /// [`DatagramError`].
    pub fn send_datagram(&mut self, data: &[u8]) -> Result<(), DatagramError> {
        if self.closed {
            return Err(DatagramError::Closed);
        }
        let hdr = epoch_header(self.token, self.local_epoch, self.peer_epoch);
        let frame = datagram_frame(&hdr, data).map_err(|TooLarge| DatagramError::TooLarge)?;
        if self.datagram.len() >= DATAGRAM_QUEUE {
            return Err(DatagramError::QueueFull);
        }
        self.datagram.push_back(frame);
        Ok(())
    }

    /// `CanSend`: the data plane is up, the provider takes writes and the
    /// queue is under 90 %.
    #[must_use]
    pub fn can_send(&self, provider_ready: bool) -> bool {
        !self.closed
            && self.data.rt.is_some()
            && provider_ready
            && self.data.out.len() < self.data.out_cap * CAN_SEND_HIGH_WATERMARK / 100
    }

    /// Whether a data send would be taken now.
    #[must_use]
    pub fn writable(&self) -> bool {
        !self.closed && self.data.writable()
    }

    /// Whether a control send would be taken now.
    #[must_use]
    pub fn control_writable(&self) -> bool {
        !self.closed && self.control.writable()
    }

    /// `ControlCanSend`.
    #[must_use]
    pub fn control_can_send(&self, subscriber_ready: bool) -> bool {
        !self.closed && self.control.rt.is_some() && subscriber_ready
    }

    /// `DatagramCanSend`.
    #[must_use]
    pub fn datagram_can_send(&self, provider_ready: bool) -> bool {
        !self.closed
            && provider_ready
            && self.datagram.len() < DATAGRAM_QUEUE * CAN_SEND_HIGH_WATERMARK / 100
    }

    /// The next data message, as `readLoop` hands it to `OnData`.
    pub fn read_data(&mut self) -> Option<Vec<u8>> {
        self.data.read()
    }

    /// The next control message.
    pub fn read_control(&mut self) -> Option<Vec<u8>> {
        self.control.read()
    }

    /// The KCP timers: flushes what is due; when to come back.
    pub fn update(&mut self, now: Instant) -> Option<Instant> {
        let ns = self.ns(now);
        let a = self.data.update(now, ns);
        let b = self.control.update(now, ns);
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// One writer tick (`writerLoop`): `write` is the track's
    /// `WriteSample`, given the sample as it goes out (dressed for the
    /// carrier).
    pub fn tick(&mut self, now: Instant, write: &mut dyn FnMut(&[u8]) -> bool) {
        if self.closed {
            return;
        }
        let ns = self.ns(now);
        self.data.pump(ns);
        self.control.pump(ns);
        let keepalive = self.epoch_header();
        let carrier = self.carrier;
        let mut sink = Dress {
            carrier,
            buf: &mut self.dress_buf,
            out: write,
        };
        let mut t = Tick {
            control: &mut self.control,
            data: &mut self.data,
            datagram: &mut self.datagram,
            params: &self.params,
            keepalive,
            keyframe_wanted: &mut self.keyframe_wanted,
            sink: &mut sink,
            now: ns,
        };
        self.writer.tick(&mut t);
        self.data.pump(ns);
        self.control.pump(ns);
    }

    /// `Close`: both planes and every queue.
    pub fn close(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.writer.release(&mut self.control, &mut self.data);
        self.data.close(now);
        self.control.close(now);
        self.datagram.clear();
    }

    /// Whether [`Channel::close`] ran.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the data lane counts its path dark.
    #[must_use]
    pub fn data_dark(&self) -> bool {
        self.writer.data.dark()
    }

    /// Bytes the channel holds in its planes and queues.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.data.held_bytes()
            + self.control.held_bytes()
            + self.datagram.iter().map(Vec::capacity).sum::<usize>()
            + self.dress_buf.capacity()
    }

    /// Gives pooled buffers back.
    pub fn trim(&mut self) {
        self.data.trim();
        self.control.trim();
        self.dress_buf = Vec::new();
    }

    fn accepts_dst(&self, dst: u32) -> bool {
        dst == 0 || dst == self.local_epoch || dst == self.control_epoch()
    }

    /// `handleIncomingFrame`: a whole frame off the track.
    pub fn handle_incoming_frame(&mut self, frame: &[u8], now: Instant) -> Inbound {
        let Some(h) = parse_epoch_header(frame) else {
            debug!("vp8channel: incoming frame bad header len={}", frame.len());
            return Inbound::BadHeader;
        };
        if h.token != self.token {
            debug!(
                "vp8channel: incoming frame token mismatch got=0x{:08x} want=0x{:08x}",
                h.token, self.token
            );
            return Inbound::ForeignToken;
        }
        let payload = &frame[EPOCH_HDR_LEN..];
        if h.src == self.local_epoch || h.src == self.control_epoch() {
            return Inbound::Loopback;
        }
        self.peer_seen = true;
        if !self.accepts_dst(h.dst) {
            return Inbound::NotForUs;
        }
        let ns = self.ns(now);
        if h.src & CONTROL_EPOCH_FLAG != 0 {
            if payload.is_empty() {
                return Inbound::ControlKeepalive;
            }
            if h.dst != self.control_epoch() {
                return Inbound::ControlNotOurs;
            }
            deliver_kcp_payload(&mut self.control, payload, now, ns);
            return Inbound::Control;
        }
        if let Some(packets) = split_datagram_batch_payload(payload) {
            let mut n = 0;
            for packet in packets {
                if let Some(d) = split_datagram_payload(packet) {
                    if self.handle_datagram(h.src, d, now) {
                        n += 1;
                    }
                }
            }
            return Inbound::DatagramBatch(n);
        }
        if let Some(d) = split_datagram_payload(payload) {
            return Inbound::Datagram(self.handle_datagram(h.src, d, now));
        }
        if !self.peer_confirmed {
            return Inbound::DataUnconfirmed;
        }
        if h.src != self.peer_epoch {
            self.maybe_peer_restart(h.src, now);
            return Inbound::DataOtherEpoch;
        }
        self.last_peer_frame = Some(now);
        if payload.is_empty() {
            return Inbound::DataKeepalive;
        }
        deliver_kcp_payload(&mut self.data, payload, now, ns);
        Inbound::Data
    }

    /// `handleDatagramFrame` on the client: only the latched peer's.
    fn handle_datagram(&mut self, src: u32, payload: &[u8], now: Instant) -> bool {
        if !self.peer_confirmed || src != self.peer_epoch {
            return false;
        }
        self.last_peer_frame = Some(now);
        if let Some(sink) = self.on_datagram.as_mut() {
            sink(payload);
        }
        true
    }

    /// `maybePeerRestart`: a frame from another epoch after the peer has
    /// been silent for the grace, with our own control plane unhealthy,
    /// is the server restarted: the provider is rebuilt, once.
    fn maybe_peer_restart(&mut self, src: u32, now: Instant) {
        if !self.link_unhealthy || self.peer_restart_grace.is_zero() {
            return;
        }
        let Some(last) = self.last_peer_frame else {
            return;
        };
        if now.saturating_duration_since(last) < self.peer_restart_grace || self.peer_restarting {
            return;
        }
        self.peer_restarting = true;
        info!(
            "vp8channel: peer restart detected old=0x{:08x} new=0x{src:08x} - rebuilding provider",
            self.peer_epoch
        );
        self.reconnect_wanted = Some("peer restart");
    }

    /// `Features().MaxPayloadSize`.
    #[must_use]
    pub fn max_payload_size() -> usize {
        MAX_PAYLOAD_SIZE
    }
}

/// `deliverKCPPayload`: each packet of the payload to the plane.
fn deliver_kcp_payload(plane: &mut Plane, payload: &[u8], now: Instant, ns: i64) {
    if plane.rt.is_none() || payload.is_empty() {
        return;
    }
    split_kcp_payload(payload, |p| plane.deliver(p, now, ns));
}

/// `writeLocked`'s dress: a carrier that is not VP8 re-heads the sample.
struct Dress<'a> {
    carrier: Carrier,
    buf: &'a mut Vec<u8>,
    out: &'a mut dyn FnMut(&[u8]) -> bool,
}

impl SampleSink for Dress<'_> {
    fn write(&mut self, sample: &[u8], keyframe: bool) -> bool {
        match self.carrier {
            Carrier::Vp8 => (self.out)(sample),
            Carrier::Vp9 => {
                vp9::dress(self.buf, sample, keyframe);
                (self.out)(self.buf)
            }
        }
    }
}

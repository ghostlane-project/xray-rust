// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The interop-pipe engine: a meeting room made of one TCP hub, the Rust
//! twin of the Go overlay's `internal/engine/interoppipe/zz_pipe.go`. It
//! stands where a carrier's SFU will: the server and this client meet
//! through it with the engine's own lanes and smux between them, and the
//! gate's interop target runs every scenario over it.
//!
//! Both directions are frames of `u32 BE length | u8 kind | payload`
//! (kinds [`KIND_JOIN`] .. [`KIND_END`]). The link joins its room, hands
//! each reliable message to the data lane and each lossy one to the
//! datagram sink, and when the hub connection goes it rejoins and reports
//! [`LinkEvent::Reconnected`], as an SFU engine does after an ICE restart;
//! a conference end is [`LinkEvent::Ended`].

use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch, Notify};
use tokio_util::sync::CancellationToken;

use crate::lane::Lane;
use crate::net;

/// Participant to hub: the room's name, the first frame.
pub const KIND_JOIN: u8 = 1;
/// One reliable, ordered message to every other participant.
pub const KIND_DATA: u8 = 2;
/// One lossy message, the same way.
pub const KIND_DGRAM: u8 = 3;
/// Hub to participant: `u16 BE`, the others in the room.
pub const KIND_PEERS: u8 = 4;
/// Hub to participant: the conference ended, for this reason.
pub const KIND_END: u8 = 5;

/// The largest payload a frame carries: four datachannel messages
/// (4 × 12 KiB), as the Go hub. It is the size of the link's one read
/// buffer.
pub const MAX_PAYLOAD: usize = 64 << 10;

/// The frame header: length and kind.
pub const FRAME_HEADER: usize = 5;

/// The first pause between rejoins, doubled up to [`REJOIN_MAX`].
pub const REJOIN_BACKOFF: Duration = Duration::from_millis(100);
/// The longest pause between rejoins.
pub const REJOIN_MAX: Duration = Duration::from_secs(2);

/// [`LinkEvent`]s held for the client: a rejoin and an end are all a link
/// ever reports, and the client reads them at once.
pub const EVENT_QUEUE: usize = 16;

/// What the link tells the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// The link rejoined the room after losing it: the session over it is
    /// gone and must be built again (the engine's reconnect callback).
    Reconnected,
    /// The conference ended (the engine's ended callback).
    Ended(String),
}

/// Why the link did not come up.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// Not `tcp://host:port/room`.
    #[error("interop-pipe: url must be tcp://host:port/room, not {0:?}")]
    BadUrl(String),
    /// The hub did not take the join.
    #[error("interop-pipe: join: {0}")]
    Join(#[source] io::Error),
}

/// Splits `tcp://host:port/room`.
///
/// # Errors
/// [`LinkError::BadUrl`].
pub fn parse_url(raw: &str) -> Result<(String, String), LinkError> {
    let bad = || LinkError::BadUrl(raw.to_owned());
    let rest = raw.strip_prefix("tcp://").ok_or_else(bad)?;
    let (host, room) = rest.split_once('/').ok_or_else(bad)?;
    if host.is_empty() || room.is_empty() || !host.contains(':') {
        return Err(bad());
    }
    Ok((host.to_owned(), room.to_owned()))
}

/// Takes one lossy message as it arrived; the buffer is the link's and is
/// only valid during the call.
pub type DatagramSink = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

/// One participant in a hub room.
pub struct PipeLink {
    addr: String,
    room: String,
    sinks: Mutex<Sinks>,
    writer: tokio::sync::Mutex<Option<Writer>>,
    ready: watch::Sender<bool>,
    reconnect: Notify,
    shut: CancellationToken,
    events: mpsc::Sender<LinkEvent>,
}

impl std::fmt::Debug for PipeLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeLink")
            .field("addr", &self.addr)
            .field("ready", &*self.ready.borrow())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Sinks {
    data: Option<Arc<Lane>>,
    datagram: Option<DatagramSink>,
    peer_seen: bool,
}

struct Writer {
    half: OwnedWriteHalf,
    /// One frame at a time: [`FRAME_HEADER`] + the largest message sent.
    buf: Vec<u8>,
}

impl PipeLink {
    /// Joins the room `url` names and starts reading it; events go to
    /// `events`.
    ///
    /// # Errors
    /// [`LinkError`].
    pub async fn connect(
        url: &str,
        events: mpsc::Sender<LinkEvent>,
    ) -> Result<Arc<Self>, LinkError> {
        let (addr, room) = parse_url(url)?;
        let (ready, _) = watch::channel(false);
        let link = Arc::new(Self {
            addr,
            room,
            sinks: Mutex::new(Sinks::default()),
            writer: tokio::sync::Mutex::new(None),
            ready,
            reconnect: Notify::new(),
            shut: CancellationToken::new(),
            events,
        });
        let read = link.join().await.map_err(LinkError::Join)?;
        tokio::spawn(link.clone().read_loop(read));
        Ok(link)
    }

    async fn join(&self) -> io::Result<OwnedReadHalf> {
        let stream = net::dial_tcp_host(&self.addr).await?;
        stream.set_nodelay(true)?;
        let (read, mut half) = stream.into_split();
        let mut buf = Vec::with_capacity(FRAME_HEADER + MAX_PAYLOAD);
        frame_into(&mut buf, KIND_JOIN, self.room.as_bytes())?;
        half.write_all(&buf).await?;
        *self.writer.lock().await = Some(Writer { half, buf });
        self.ready.send_replace(true);
        Ok(read)
    }

    /// Hands reliable messages to `lane` from now on (`None`: drop them).
    pub fn set_data(&self, lane: Option<Arc<Lane>>) {
        self.lock().data = lane;
    }

    /// Hands lossy messages to `sink` from now on.
    pub fn set_datagram(&self, sink: Option<DatagramSink>) {
        self.lock().datagram = sink;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Sinks> {
        self.sinks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether another participant has been in the room
    /// (`transport.PeerObserver`).
    pub fn peer_seen(&self) -> bool {
        self.lock().peer_seen
    }

    /// Whether the room is joined (`CanSend`).
    pub fn can_send(&self) -> bool {
        *self.ready.borrow()
    }

    /// Waits until the room is joined, at most `limit`; whether it is.
    pub async fn wait_ready(&self, limit: Duration) -> bool {
        let mut rx = self.ready.subscribe();
        let joined = tokio::time::timeout(limit, rx.wait_for(|r| *r)).await;
        matches!(joined, Ok(Ok(_)))
    }

    /// Sends one reliable message.
    ///
    /// # Errors
    /// `NotConnected` while the room is not joined, or the socket's error.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.send_kind(KIND_DATA, payload).await
    }

    /// Sends one lossy message.
    ///
    /// # Errors
    /// As [`PipeLink::send`].
    pub async fn send_datagram(&self, payload: &[u8]) -> io::Result<()> {
        self.send_kind(KIND_DGRAM, payload).await
    }

    async fn send_kind(&self, kind: u8, payload: &[u8]) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let Some(w) = guard.as_mut() else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        frame_into(&mut w.buf, kind, payload)?;
        let res = w.half.write_all(&w.buf).await;
        if res.is_err() {
            *guard = None;
            self.ready.send_replace(false);
        }
        res
    }

    /// Drops the hub connection; the read loop rejoins
    /// (`Session.Reconnect`).
    pub fn reconnect(&self, reason: &str) {
        crate::info!("interop-pipe: reconnect requested: {reason}");
        self.reconnect.notify_one();
    }

    /// Leaves the room for good.
    pub async fn close(&self) {
        self.shut.cancel();
        self.ready.send_replace(false);
        if let Some(mut w) = self.writer.lock().await.take() {
            let _ = w.half.shutdown().await;
        }
        let mut sinks = self.lock();
        sinks.data = None;
        sinks.datagram = None;
    }

    async fn read_loop(self: Arc<Self>, mut read: OwnedReadHalf) {
        // The one read buffer: the largest frame the hub relays.
        let mut buf = vec![0u8; MAX_PAYLOAD];
        loop {
            let got = tokio::select! {
                biased;
                () = self.shut.cancelled() => return,
                () = self.reconnect.notified() => Err(io::Error::other("reconnect requested")),
                r = read_frame(&mut read, &mut buf) => r,
            };
            match got {
                Ok((KIND_DATA, n)) => {
                    let lane = self.lock().data.clone();
                    if let Some(lane) = lane {
                        lane.push(&mut buf[..n]).await;
                    }
                }
                Ok((KIND_DGRAM, n)) => {
                    let sink = self.lock().datagram.clone();
                    if let Some(sink) = sink {
                        sink(&mut buf[..n]);
                    }
                }
                Ok((KIND_PEERS, 2)) => {
                    if u16::from_be_bytes([buf[0], buf[1]]) > 0 {
                        self.lock().peer_seen = true;
                    }
                }
                Ok((KIND_END, n)) => {
                    let reason = String::from_utf8_lossy(&buf[..n]).into_owned();
                    self.drop_writer().await;
                    let _ = self.events.try_send(LinkEvent::Ended(reason));
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    self.drop_writer().await;
                    if self.shut.is_cancelled() {
                        return;
                    }
                    crate::info!("interop-pipe: hub connection lost, rejoining room");
                    let Some(next) = self.rejoin().await else {
                        return;
                    };
                    read = next;
                    let _ = self.events.try_send(LinkEvent::Reconnected);
                }
            }
        }
    }

    async fn drop_writer(&self) {
        self.ready.send_replace(false);
        self.writer.lock().await.take();
    }

    async fn rejoin(&self) -> Option<OwnedReadHalf> {
        let mut delay = REJOIN_BACKOFF;
        loop {
            if self.shut.is_cancelled() {
                return None;
            }
            if let Ok(read) = self.join().await {
                if self.shut.is_cancelled() {
                    self.drop_writer().await;
                    return None;
                }
                return Some(read);
            }
            tokio::select! {
                () = self.shut.cancelled() => return None,
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(REJOIN_MAX);
        }
    }
}

/// Writes one frame into `buf`, replacing what it held.
fn frame_into(buf: &mut Vec<u8>, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interop-pipe: frame too large",
        ));
    }
    buf.clear();
    let len = u32::try_from(1 + payload.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.push(kind);
    buf.extend_from_slice(payload);
    Ok(())
}

/// Reads one frame's payload into `buf`; its kind and length.
async fn read_frame(read: &mut OwnedReadHalf, buf: &mut [u8]) -> io::Result<(u8, usize)> {
    let mut hdr = [0u8; FRAME_HEADER];
    read.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    if len == 0 || len - 1 > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "interop-pipe: frame too large",
        ));
    }
    read.read_exact(&mut buf[..len - 1]).await?;
    Ok((hdr[4], len - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_names_the_hub_and_the_room() {
        assert_eq!(
            parse_url("tcp://127.0.0.1:4000/gate-ab").unwrap(),
            ("127.0.0.1:4000".to_owned(), "gate-ab".to_owned())
        );
        for bad in [
            "udp://127.0.0.1:1/r",
            "tcp://127.0.0.1:1/",
            "tcp://127.0.0.1:1",
            "tcp:///r",
            "tcp://host/r",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_frame_is_length_kind_payload() {
        let mut buf = Vec::new();
        frame_into(&mut buf, KIND_JOIN, b"room").unwrap();
        assert_eq!(buf, [0, 0, 0, 5, 1, b'r', b'o', b'o', b'm']);
        assert!(frame_into(&mut buf, KIND_DATA, &vec![0; MAX_PAYLOAD + 1]).is_err());
    }
}

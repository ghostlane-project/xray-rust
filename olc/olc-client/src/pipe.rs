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
use tokio::sync::{mpsc, watch};
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

/// What the link lets the kernel hold unsent: a carrier's datachannel
/// high-water mark (`defaultBufferHighWaterMark`, goolom/session.go:37;
/// `bufferHighWaterMark`, salutejazz/data.go:42: 512 KiB), which the carriers
/// wait under before they send more (goolom/sendqueue.go:54). Without it a
/// loopback socket autotunes to megabytes, a queue no carrier has, and a
/// connect opened under an upload waits behind all of it. The Go pipe sets
/// the same bound (zz_pipe.go).
pub const SEND_HIGH_WATER: u32 = 512 * 1024;

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
    /// The joined connection's cut, `None` while not joined: cancelling it
    /// drops that connection, as Go's `conn.Close()` does (a reconnect, a
    /// failed write, the close), and frees a write stuck on a far end that
    /// stopped reading without waiting for the writer's lock.
    conn: Mutex<Option<CancellationToken>>,
    ready: watch::Sender<bool>,
    shut: CancellationToken,
    /// Taken by [`PipeLink::close`]: the client's event queue ends with it.
    events: Mutex<Option<mpsc::Sender<LinkEvent>>>,
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
    /// The connection's cut.
    cut: CancellationToken,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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
            conn: Mutex::new(None),
            ready,
            shut: CancellationToken::new(),
            events: Mutex::new(Some(events)),
        });
        let (read, cut) = link.join().await.map_err(LinkError::Join)?;
        tokio::spawn(link.clone().read_loop(read, cut));
        Ok(link)
    }

    async fn join(&self) -> io::Result<(OwnedReadHalf, CancellationToken)> {
        let stream = net::dial_tcp_host_with(&self.addr, Some(SEND_HIGH_WATER)).await?;
        stream.set_nodelay(true)?;
        let (read, mut half) = stream.into_split();
        let mut buf = Vec::with_capacity(FRAME_HEADER + MAX_PAYLOAD);
        frame_into(&mut buf, KIND_JOIN, self.room.as_bytes())?;
        half.write_all(&buf).await?;
        // A child of the link's end: the close cuts every connection.
        let cut = self.shut.child_token();
        *self.writer.lock().await = Some(Writer {
            half,
            buf,
            cut: cut.clone(),
        });
        *locked(&self.conn) = Some(cut.clone());
        self.ready.send_replace(true);
        Ok((read, cut))
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
        locked(&self.sinks)
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
    /// `NotConnected` while the room is not joined or once the connection
    /// was cut, or the socket's error.
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

    /// One frame at a time, as Go's `wmu` (zz_pipe.go:290): the write has
    /// no deadline there either, and ends with its connection.
    async fn send_kind(&self, kind: u8, payload: &[u8]) -> io::Result<()> {
        let mut guard = self.writer.lock().await;
        let Some(w) = guard.as_mut() else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        frame_into(&mut w.buf, kind, payload)?;
        let cut = w.cut.clone();
        let res = tokio::select! {
            biased;
            () = cut.cancelled() => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "interop-pipe: connection dropped",
            )),
            r = w.half.write_all(&w.buf) => r,
        };
        if res.is_err() {
            // Under the lock, so a rejoin cannot be marked joined first.
            *guard = None;
            self.ready.send_replace(false);
            cut.cancel();
        }
        res
    }

    /// Drops the hub connection there is; the read loop rejoins
    /// (`Session.Reconnect`). Not joined, it does nothing, as Go's.
    pub fn reconnect(&self, reason: &str) {
        crate::info!("interop-pipe: reconnect requested: {reason}");
        if let Some(cut) = locked(&self.conn).as_ref() {
            cut.cancel();
        }
    }

    /// Leaves the room for good; the event queue ends.
    pub async fn close(&self) {
        self.shut.cancel();
        self.ready.send_replace(false);
        locked(&self.events).take();
        locked(&self.conn).take();
        if let Some(mut w) = self.writer.lock().await.take() {
            let _ = w.half.shutdown().await;
        }
        let mut sinks = self.lock();
        sinks.data = None;
        sinks.datagram = None;
    }

    fn event(&self, ev: LinkEvent) {
        if let Some(tx) = locked(&self.events).as_ref() {
            let _ = tx.try_send(ev);
        }
    }

    async fn read_loop(self: Arc<Self>, mut read: OwnedReadHalf, mut cut: CancellationToken) {
        // The one read buffer: the largest frame the hub relays.
        let mut buf = vec![0u8; MAX_PAYLOAD];
        loop {
            let got = tokio::select! {
                biased;
                () = self.shut.cancelled() => return,
                () = cut.cancelled() => Err(io::Error::other("connection dropped")),
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
                    self.drop_conn(&cut).await;
                    self.event(LinkEvent::Ended(reason));
                    return;
                }
                Ok(_) => {}
                Err(_) => {
                    self.drop_conn(&cut).await;
                    if self.shut.is_cancelled() {
                        return;
                    }
                    crate::info!("interop-pipe: hub connection lost, rejoining room");
                    let Some((next, next_cut)) = self.rejoin().await else {
                        return;
                    };
                    (read, cut) = (next, next_cut);
                    self.event(LinkEvent::Reconnected);
                }
            }
        }
    }

    /// Forgets connection `cut`: not joined, its writer gone.
    async fn drop_conn(&self, cut: &CancellationToken) {
        self.ready.send_replace(false);
        cut.cancel();
        {
            let mut conn = locked(&self.conn);
            if conn.as_ref().is_some_and(|c| c.is_cancelled()) {
                *conn = None;
            }
        }
        let mut w = self.writer.lock().await;
        if w.as_ref().is_some_and(|w| w.cut.is_cancelled()) {
            *w = None;
        }
    }

    async fn rejoin(&self) -> Option<(OwnedReadHalf, CancellationToken)> {
        let mut delay = REJOIN_BACKOFF;
        loop {
            if self.shut.is_cancelled() {
                return None;
            }
            if let Ok(joined) = self.join().await {
                if self.shut.is_cancelled() {
                    self.drop_conn(&joined.1).await;
                    return None;
                }
                return Some(joined);
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
impl PipeLink {
    /// Marks the room joined or not without touching the connection.
    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.send_replace(ready);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhub::TestHub;
    use crate::testing::bounded;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::timeout;

    const QUICK: Duration = Duration::from_secs(2);

    /// Sends full frames until a send stops returning (the hub stopped
    /// reading); the sender, which ends when a send fails.
    async fn stall(link: &Arc<PipeLink>) -> tokio::task::JoinHandle<()> {
        let sent = Arc::new(AtomicUsize::new(0));
        let filler = {
            let (link, sent) = (link.clone(), sent.clone());
            tokio::spawn(async move {
                let p = vec![0u8; MAX_PAYLOAD];
                while link.send(&p).await.is_ok() {
                    sent.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let mut last = usize::MAX;
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let n = sent.load(Ordering::Relaxed);
            if n == last {
                return filler;
            }
            last = n;
        }
    }

    #[tokio::test]
    async fn a_send_stuck_on_a_far_end_that_stopped_reading_holds_back_neither_reconnect_nor_close(
    ) {
        bounded(async {
            let (hub, url) = TestHub::start("stall").await;
            let (tx, mut rx) = mpsc::channel(EVENT_QUEUE);
            let link = PipeLink::connect(&url, tx).await.unwrap();
            let _first = hub.accept().await;
            let filler = stall(&link).await;
            link.reconnect("test");
            let _second = timeout(QUICK, hub.accept())
                .await
                .expect("the link rejoins while a send is stuck");
            assert_eq!(
                timeout(QUICK, rx.recv()).await.unwrap(),
                Some(LinkEvent::Reconnected)
            );
            timeout(QUICK, filler)
                .await
                .expect("the stuck send fails with its connection")
                .unwrap();
            let filler = stall(&link).await;
            timeout(QUICK, link.close())
                .await
                .expect("close does not wait for a stuck send");
            timeout(QUICK, filler).await.unwrap().unwrap();
            assert!(!link.can_send());
        })
        .await;
    }

    #[tokio::test]
    async fn reconnects_asked_together_drop_one_connection() {
        bounded(async {
            let (hub, url) = TestHub::start("twice").await;
            let (tx, mut rx) = mpsc::channel(EVENT_QUEUE);
            let link = PipeLink::connect(&url, tx).await.unwrap();
            let _first = hub.accept().await;
            // Go's Reconnect closes the connection there is (zz_pipe.go:355):
            // a second one finds it closed or gone, and the next connection
            // stays.
            link.reconnect("test");
            link.reconnect("test");
            let _second = timeout(QUICK, hub.accept()).await.unwrap();
            assert_eq!(rx.recv().await, Some(LinkEvent::Reconnected));
            assert!(
                timeout(Duration::from_millis(500), hub.accept())
                    .await
                    .is_err(),
                "a third connection"
            );
            link.close().await;
        })
        .await;
    }

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

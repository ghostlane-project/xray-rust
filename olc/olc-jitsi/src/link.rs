// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The link the client runs over (`internal/engine/jitsi` as the datachannel
//! transport's engine): the session with the surface of SaluteJazz's `Link`,
//! so olc-client's `Link` takes it as it takes that one. A Jitsi room is one
//! peer, one reliable lane (the bridge's data channel); there is no lossy
//! lane (`set_datagram` keeps the sink, `send_datagram` says so).

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use olc_net::link::{DataSink, DatagramSink, LinkEvent};
use tokio::sync::mpsc;

use crate::bridge::{BridgeError, OnDataAsync};
use crate::epoch::PeerIdError;
use crate::join::{JoinConfig, JoinError};
use crate::relaywin::Timing;
use crate::session::{RejoinTimes, Session, SessionConfig};

/// What a link needs.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// The room and how it is joined.
    pub join: JoinConfig,
    /// The address the peer's host candidate names; the default route's
    /// when `None`.
    pub host_ip: Option<IpAddr>,
    /// Only relayed candidates.
    pub relay_only: bool,
}

/// A Jitsi link.
pub struct Link {
    session: Session,
    datagram: RwLock<Option<DatagramSink>>,
    data: Arc<RwLock<Option<Arc<dyn DataSink>>>>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

impl Link {
    /// Joins the room; the offer is waited for in the background (it comes
    /// when another participant is there). The reconnect watcher runs from
    /// then on and reports to `events`.
    ///
    /// # Errors
    /// The join's, or the host's address.
    pub async fn connect(
        cfg: LinkConfig,
        events: mpsc::Sender<LinkEvent>,
    ) -> Result<Arc<Self>, JoinError> {
        let host_ip = match cfg.host_ip {
            Some(ip) => ip,
            None => olc_rtc::ice::default_ipv4()
                .map_err(|e| JoinError(format!("jitsi local address: {e}")))?,
        };
        let data: Arc<RwLock<Option<Arc<dyn DataSink>>>> = Arc::default();
        let sink = data.clone();
        let on_data_async: OnDataAsync = Arc::new(move |mut record: Vec<u8>| {
            let s = sink.read().unwrap_or_else(PoisonError::into_inner).clone();
            Box::pin(async move {
                if let Some(s) = s {
                    s.push(&mut record).await;
                }
            })
        });
        let (ended, reconnected) = (events.clone(), events);
        let session = Session::connect(SessionConfig {
            join: cfg.join,
            host_ip,
            relay_only: cfg.relay_only,
            require_targeted_peer: true,
            on_data: Arc::new(|_| {}),
            on_data_async: Some(on_data_async),
            on_ended: Arc::new(move |why| {
                let _ = ended.try_send(LinkEvent::Ended(why.to_owned()));
            }),
            on_reconnected: Arc::new(move || {
                let _ = reconnected.try_send(LinkEvent::Reconnected);
            }),
            times: RejoinTimes::default(),
            timing: Timing::default(),
        })
        .await?;
        Ok(Arc::new(Self {
            session,
            datagram: RwLock::new(None),
            data,
        }))
    }

    /// Where reliable messages go (`OnData`).
    pub fn set_data(&self, sink: Option<Arc<dyn DataSink>>) {
        *self.data.write().unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// Where datagrams would go; Jitsi carries none.
    pub fn set_datagram(&self, sink: Option<DatagramSink>) {
        *self
            .datagram
            .write()
            .unwrap_or_else(PoisonError::into_inner) = sink;
    }

    /// This side's epoch as eight hex digits (`LocalPeerID`).
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        self.session.local_peer_id()
    }

    /// A peer's epoch is latched, or others are in the room.
    #[must_use]
    pub fn peer_seen(&self) -> bool {
        self.session.peer_seen()
    }

    /// The bridge is open.
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.session.can_send()
    }

    /// Waits until the first hello can reach somebody: the bridge open and
    /// a peer in the room; the caller bounds it.
    pub async fn wait_peer_settled(&self) {
        while !(self.can_send() && self.peer_seen()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Waits up to `timeout` for [`Link::can_send`].
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        let until = tokio::time::Instant::now() + timeout;
        loop {
            if self.can_send() {
                return true;
            }
            if tokio::time::Instant::now() >= until {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Sends one reliable message to the peer.
    ///
    /// # Errors
    /// The session's: closed, bridge not ready, too large.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.session
            .send(payload)
            .await
            .map_err(|e: BridgeError| io::Error::other(e.to_string()))
    }

    /// Jitsi's session has no lossy lane (`ErrDatagramUnsupported`).
    ///
    /// # Errors
    /// Always.
    pub async fn send_datagram(&self, _payload: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "jitsi: datagrams are not supported",
        ))
    }

    /// Binds sends to the authenticated peer (`ConfirmPeer`).
    ///
    /// # Errors
    /// A peer id that is no epoch.
    pub async fn confirm_peer(&self, peer_id: &str) -> Result<(), PeerIdError> {
        self.session.confirm_peer(peer_id)
    }

    /// Forgets the binding (`ResetPeer`).
    pub fn reset_peer(&self) {
        self.session.reset_peer();
    }

    /// Waits until a peer epoch is confirmed, at most `timeout`.
    ///
    /// # Errors
    /// The wait's text.
    pub async fn wait_for_peer(&self, timeout: Duration) -> Result<(), String> {
        match tokio::time::timeout(timeout, self.session.wait_for_peer()).await {
            Ok(true) => Ok(()),
            Ok(false) => Err("jitsi: session closed".into()),
            Err(_) => Err("context deadline exceeded".into()),
        }
    }

    /// Asks to join again.
    pub fn reconnect(&self, reason: &str) {
        self.session.reconnect(reason);
    }

    /// Leaves the room.
    pub async fn close(&self) {
        self.session.close().await;
    }
}

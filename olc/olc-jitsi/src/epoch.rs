// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Who a frame is from and for: the local and the peer epoch, the endpoint
//! latch, the acceptance rules of a single-peer session
//! (`internal/engine/jitsi/epoch.go`, `bridge.go`'s `deliverBridgeMessage`).

use std::time::{Duration, Instant};

use crate::frame::{EPOCH_HEADER, MAGIC};

/// A peer that came back is told apart from one that never left for this
/// long (`reconnectGrace`).
pub const RECONNECT_GRACE: Duration = Duration::from_secs(20);

/// How long the latched endpoint is a destination without a frame from it
/// (`peerLatchFresh`): three liveness intervals of silence.
pub const PEER_LATCH_FRESH: Duration = Duration::from_secs(30);

/// A local epoch: four random bytes, never zero (`randomEpoch`).
#[must_use]
pub fn random_epoch() -> u32 {
    match rand::random::<u32>() {
        0 => 1,
        v => v,
    }
}

/// A peer id that is no epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerIdError {
    /// Not up to eight hex digits.
    #[error("parse peer id")]
    Parse,
    /// Epoch zero (`engine.ErrInvalidPeerID`).
    #[error("invalid peer id")]
    Invalid,
}

/// What [`Epochs::receive`] made of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// The data, when the frame was accepted; empty for an announce. `None`
    /// when it was dropped.
    pub body: Option<Vec<u8>>,
    /// The peer is a new one: its relay window starts over.
    pub reset_windows: bool,
}

const DROPPED: Received = Received {
    body: None,
    reset_windows: false,
};

/// The epochs and the latch of one single-peer session: a client's view of
/// who it talks to.
#[derive(Debug)]
pub struct Epochs {
    local: u32,
    peer: u32,
    require_targeted: bool,
    endpoint: Option<String>,
    endpoint_seen: Option<Instant>,
    last_reconnect: Option<Instant>,
}

impl Epochs {
    /// A session with local epoch `local`; with `require_targeted_peer` only
    /// frames addressed to it, from the confirmed peer, are taken
    /// (`RequireTargetedPeer`).
    #[must_use]
    pub fn new(local: u32, require_targeted: bool) -> Self {
        Self {
            local,
            peer: 0,
            require_targeted,
            endpoint: None,
            endpoint_seen: None,
            last_reconnect: None,
        }
    }

    /// The local epoch.
    #[must_use]
    pub fn local(&self) -> u32 {
        self.local
    }

    /// A new local epoch, for a rebuilt session.
    pub fn set_local(&mut self, epoch: u32) {
        self.local = epoch;
    }

    /// The peer's epoch, 0 before there is one.
    #[must_use]
    pub fn peer_epoch(&self) -> u32 {
        self.peer
    }

    /// The latched endpoint.
    #[must_use]
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// The local epoch as the peer id the layers above exchange: eight hex
    /// digits (`LocalPeerID`).
    #[must_use]
    pub fn local_peer_id(&self) -> String {
        format!("{:08x}", self.local)
    }

    /// The header of `payload`'s frame and its data; `None` for a frame too
    /// short, from epoch 0 or from ourselves (a local echo), or addressed to
    /// another epoch than ours (`parseEpochFrame`).
    #[must_use]
    pub fn parse<'a>(&self, payload: &'a [u8]) -> Option<(u32, u32, &'a [u8])> {
        if payload.len() < MAGIC.len() + EPOCH_HEADER {
            return None;
        }
        let off = MAGIC.len();
        let sender = u32::from_be_bytes(payload[off..off + 4].try_into().ok()?);
        let receiver = u32::from_be_bytes(payload[off + 4..off + 8].try_into().ok()?);
        if sender == 0 || sender == self.local {
            return None;
        }
        if receiver != 0 && receiver != self.local {
            return None;
        }
        Some((sender, receiver, &payload[off + EPOCH_HEADER..]))
    }

    /// A data message's payload from endpoint `from` (the part of
    /// `deliverBridgeMessageGen` after the window frames): the magic, the
    /// acceptance rules, the latch.
    pub fn receive(&mut self, from: &str, payload: &[u8], now: Instant) -> Received {
        if payload.len() < MAGIC.len() || payload[..MAGIC.len()] != MAGIC {
            return DROPPED;
        }
        let Some((sender, receiver, body)) = self.parse(payload) else {
            return DROPPED;
        };
        let mut reset_windows = false;
        if self.require_targeted {
            if receiver != self.local {
                return DROPPED;
            }
            if self.peer != 0 && sender != self.peer {
                return DROPPED;
            }
        } else if self.peer == 0 {
            self.peer = sender;
        } else if self.peer != sender {
            // A peer epoch change is fresh peer state, not a reason to
            // reconnect: a fresh peer starts a fresh relay window.
            self.peer = sender;
            reset_windows = true;
        }
        if !self.require_targeted || self.peer != 0 {
            self.latch_endpoint(from, now);
        }
        Received {
            body: Some(body.to_vec()),
            reset_windows,
        }
    }

    /// Records the sender of a valid frame, and re-binds when the peer came
    /// back under a new bridge endpoint id; an empty sender is a broadcast
    /// (`latchPeerEndpoint`).
    pub fn latch_endpoint(&mut self, from: &str, now: Instant) {
        if from.is_empty() {
            return;
        }
        self.endpoint_seen = Some(now);
        if self.endpoint.as_deref() != Some(from) {
            self.endpoint = Some(from.to_owned());
        }
    }

    /// Where a frame goes: the latched endpoint while a frame from it came
    /// within [`PEER_LATCH_FRESH`], else the room, which is `""`
    /// (`broadcastTarget`).
    #[must_use]
    pub fn send_target(&self, now: Instant) -> &str {
        match (&self.endpoint, self.endpoint_seen) {
            (Some(ep), Some(seen)) if now.saturating_duration_since(seen) <= PEER_LATCH_FRESH => ep,
            _ => "",
        }
    }

    /// Binds the session to an authenticated peer epoch (`ConfirmPeer`);
    /// whether it changed, which starts the relay window over.
    ///
    /// # Errors
    /// [`PeerIdError`]; nothing changes.
    pub fn confirm_peer(&mut self, peer_id: &str) -> Result<bool, PeerIdError> {
        if peer_id.is_empty() || !peer_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PeerIdError::Parse);
        }
        let epoch = u32::from_str_radix(peer_id, 16).map_err(|_| PeerIdError::Parse)?;
        if epoch == 0 {
            return Err(PeerIdError::Invalid);
        }
        let changed = self.peer != epoch;
        self.peer = epoch;
        Ok(changed)
    }

    /// Forgets the peer and the latch (`ResetPeer`); the caller starts the
    /// relay window over.
    pub fn reset_peer(&mut self) {
        self.endpoint = None;
        self.endpoint_seen = None;
        self.peer = 0;
    }

    /// The epoch an echo from endpoint `from` must carry: the confirmed
    /// peer's, and only from the endpoint latched for it (`echoerEpoch`).
    #[must_use]
    pub fn echoer_epoch(&self, from: &str) -> u32 {
        match &self.endpoint {
            Some(ep) if ep == from => self.peer,
            _ => 0,
        }
    }

    /// A peer epoch is latched, or the bridge lists another occupant of the
    /// room (`PeerSeen`).
    #[must_use]
    pub fn peer_seen(&self, occupants: usize) -> bool {
        self.peer != 0 || occupants > 0
    }

    /// A reconnect began now.
    pub fn note_reconnect(&mut self, now: Instant) {
        self.last_reconnect = Some(now);
    }

    /// Within [`RECONNECT_GRACE`] of the last reconnect (`inReconnectGrace`).
    #[must_use]
    pub fn in_reconnect_grace(&self, now: Instant) -> bool {
        self.last_reconnect
            .is_some_and(|t| now.saturating_duration_since(t) < RECONNECT_GRACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::encode_frame;

    const NOW: fn() -> Instant = Instant::now;

    /// A data frame from epoch `sender` to epoch `receiver`.
    fn frame(sender: u32, receiver: u32, data: &[u8]) -> Vec<u8> {
        encode_frame(data, sender, receiver).unwrap()
    }

    /// `TestParseEpochFrameSharedValidation` (`regression_test.go:330`).
    #[test]
    fn the_header_validation() {
        let mut e = Epochs::new(0x4444, false);
        let rows: [(&str, Vec<u8>, bool); 6] = [
            ("short frame", crate::frame::MAGIC.to_vec(), false),
            ("zero sender epoch", frame(0, 0x4444, b"x"), false),
            ("own echo", frame(0x4444, 0, b"x"), false),
            (
                "addressed to old incarnation",
                frame(0x1111, 0x9999, b"x"),
                false,
            ),
            ("broadcast", frame(0x1111, 0, b"x"), true),
            ("targeted", frame(0x1111, 0x4444, b"x"), true),
        ];
        for (name, payload, want) in rows {
            assert_eq!(e.parse(&payload).is_some(), want, "{name}: parse");
            assert_eq!(
                e.receive("peerA", &payload, NOW()).body.is_some(),
                want,
                "{name}: receive"
            );
            e.reset_peer();
        }
    }

    /// `TestLatchPeerEndpointIgnoresBroadcast` (`regression_test.go:367`).
    #[test]
    fn a_broadcast_does_not_move_the_latch() {
        let mut e = Epochs::new(1, false);
        e.latch_endpoint("peerA", NOW());
        e.latch_endpoint("", NOW());
        assert_eq!(e.endpoint(), Some("peerA"));
        e.latch_endpoint("peerB", NOW());
        assert_eq!(e.endpoint(), Some("peerB"));
    }

    /// `TestDeliverBridgeMessageMagicAndPeerLatch` (`jitsi_test.go:267`).
    #[test]
    fn a_frame_without_the_magic_is_dropped_and_a_new_sender_relatches() {
        let mut e = Epochs::new(0x9999, false);
        let got = e.receive("peerA", &frame(0x1111, 0, b"alpha"), NOW());
        assert_eq!(got.body.as_deref(), Some(&b"alpha"[..]));
        assert_eq!(e.endpoint(), Some("peerA"));
        // No magic: not ours.
        let bad = e.receive("peerA", b"alpha-no-magic-at-all", NOW());
        assert!(bad.body.is_none() && !bad.reset_windows);
        // Another sender that passes the magic is a peer that came back on
        // another endpoint.
        let beta = e.receive("peerB", &frame(0x1111, 0, b"beta"), NOW());
        assert_eq!(beta.body.as_deref(), Some(&b"beta"[..]));
        assert_eq!(e.endpoint(), Some("peerB"));
    }

    /// `TestDeliverBridgeMessageDropsStalePeerEpoch` (`jitsi_test.go:342`).
    #[test]
    fn a_frame_for_an_old_incarnation_is_not_delivered() {
        let mut e = Epochs::new(0x2222, false);
        assert!(e
            .receive("peerA", &frame(0x1111, 0xaaaa, b"old-smux"), NOW())
            .body
            .is_none());
        assert_eq!(e.peer_epoch(), 0);
        assert_eq!(e.endpoint(), None);
    }

    /// `TestReconnectEpochAnnounceWithZeroPeerEpochIsAccepted` (`:367`).
    #[test]
    fn an_announce_sets_the_peer_epoch() {
        let mut e = Epochs::new(0x2222, false);
        let got = e.receive("peerA", &frame(0x1111, 0, b""), NOW());
        assert_eq!(e.peer_epoch(), 0x1111);
        // An announce has no data: nothing to deliver, but it was accepted.
        assert_eq!(got.body.as_deref(), Some(&b""[..]));
        assert!(!got.reset_windows);
    }

    /// A fresh peer (its epoch changed) starts a fresh relay window and is
    /// not a reason to reconnect.
    #[test]
    fn a_new_peer_epoch_resets_the_windows() {
        let mut e = Epochs::new(0x2222, false);
        let first = e.receive("peerA", &frame(0x1111, 0, b"a"), NOW());
        assert!(
            !first.reset_windows,
            "the first epoch is learned, not changed"
        );
        let same = e.receive("peerA", &frame(0x1111, 0, b"b"), NOW());
        assert!(!same.reset_windows);
        let changed = e.receive("peerA", &frame(0x3333, 0, b"c"), NOW());
        assert!(changed.reset_windows);
        assert_eq!(changed.body.as_deref(), Some(&b"c"[..]));
        assert_eq!(e.peer_epoch(), 0x3333);
    }

    /// `TestRequireTargetedPeerIgnoresBroadcastUntilConfirmed` (`:390`).
    #[test]
    fn a_targeted_session_takes_only_what_is_addressed_to_it_and_confirmed() {
        let mut e = Epochs::new(0x3333, true);
        let foreign = frame(0x2222, 0, b"CLIENT_HELLO");
        let got = e.receive("clientB", &foreign, NOW());
        assert!(got.body.is_none());
        assert_eq!(e.peer_epoch(), 0);

        let welcome = frame(0x1111, 0x3333, b"SERVER_WELCOME");
        let got = e.receive("server", &welcome, NOW());
        assert_eq!(got.body.as_deref(), Some(&b"SERVER_WELCOME"[..]));
        assert_eq!(
            e.peer_epoch(),
            0,
            "no peer is bound before the confirmation"
        );
        assert_eq!(e.endpoint(), None);

        assert_eq!(e.confirm_peer("00001111"), Ok(true));
        assert_eq!(e.peer_epoch(), 0x1111);
        assert!(e.receive("clientB", &foreign, NOW()).body.is_none());
        // A frame from another epoch, even if addressed to us, is not the peer's.
        assert!(e
            .receive("clientB", &frame(0x2222, 0x3333, b"x"), NOW())
            .body
            .is_none());

        let more = e.receive("server", &frame(0x1111, 0x3333, b"MORE"), NOW());
        assert_eq!(more.body.as_deref(), Some(&b"MORE"[..]));
        assert_eq!(e.endpoint(), Some("server"));
    }

    #[test]
    fn confirming_a_peer() {
        let mut e = Epochs::new(7, true);
        assert_eq!(e.confirm_peer("0000abcd"), Ok(true));
        assert_eq!(
            e.confirm_peer("0000abcd"),
            Ok(false),
            "the same epoch twice moves nothing"
        );
        assert_eq!(e.confirm_peer("0000abce"), Ok(true));
        assert_eq!(e.confirm_peer("ABCDEF01"), Ok(true));
        assert_eq!(e.peer_epoch(), 0xabcd_ef01);
        assert_eq!(e.confirm_peer("00000000"), Err(PeerIdError::Invalid));
        assert_eq!(e.confirm_peer("zz"), Err(PeerIdError::Parse));
        assert_eq!(e.confirm_peer(""), Err(PeerIdError::Parse));
        assert_eq!(
            e.confirm_peer("100000000"),
            Err(PeerIdError::Parse),
            "more than 32 bits"
        );
        assert_eq!(e.peer_epoch(), 0xabcd_ef01, "a refusal changes nothing");
    }

    /// `TestResetPeerClearsBindingForNewPeer` (`churn_test.go`).
    #[test]
    fn reset_peer_clears_the_binding() {
        let mut e = Epochs::new(0xDEAD_BEEF, false);
        let mut delivered = Vec::new();
        for (from, ep, data) in [
            ("peerA", 0x1111, "from-A"),
            ("peerB", 0x2222, "from-B-relatched"),
        ] {
            let g = e.receive(from, &frame(ep, 0, data.as_bytes()), NOW());
            delivered.push(g.body.unwrap());
        }
        e.reset_peer();
        assert_eq!(e.peer_epoch(), 0);
        assert_eq!(e.endpoint(), None);
        let g = e.receive("peerB", &frame(0x2222, 0, b"from-B-final"), NOW());
        delivered.push(g.body.unwrap());
        assert_eq!(
            delivered,
            [
                b"from-A".to_vec(),
                b"from-B-relatched".to_vec(),
                b"from-B-final".to_vec()
            ]
        );
    }

    /// `TestChurnPeerEpochChanges`, one thread: nothing addressed to another
    /// epoch is ever delivered, and the peer epoch tracks the latest sender.
    #[test]
    fn churn() {
        let mut e = Epochs::new(0x4242_4242, false);
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2000 {
            match next() % 3 {
                0 => {
                    let ep = ((next() as u32) | 1) & 0xFFFF_FFFE;
                    let got = e.receive("peerA", &frame(ep, 0, b"ok"), NOW());
                    assert!(got.body.is_some());
                    assert_eq!(e.peer_epoch(), ep);
                }
                1 => {
                    let got = e.receive("peerA", &frame(0x1111, 0xBAD_BAD, b"STALE-rcv"), NOW());
                    assert!(got.body.is_none(), "a stale frame was delivered");
                }
                _ => {
                    let got = e.receive("peerA", &frame(0x9999, 0x4242_4242, b"ack"), NOW());
                    assert!(got.body.is_some());
                    assert_eq!(e.peer_epoch(), 0x9999);
                }
            }
        }
    }

    /// `TestAClientSendsToTheEndpointItLatched`, `TestAStaleLatchFallsBackToTheRoom`
    /// (`unicast_test.go:13,29`).
    #[test]
    fn a_client_sends_to_its_latched_endpoint_while_it_is_fresh() {
        let mut e = Epochs::new(1, false);
        let t0 = Instant::now();
        assert_eq!(e.send_target(t0), "", "before the latch: the room");
        e.latch_endpoint("peerA", t0);
        assert_eq!(e.send_target(t0), "peerA");
        assert_eq!(e.send_target(t0 + PEER_LATCH_FRESH), "peerA");
        assert_eq!(
            e.send_target(t0 + PEER_LATCH_FRESH + Duration::from_secs(1)),
            ""
        );
        // The next frame from the peer makes it a destination again.
        let t1 = t0 + PEER_LATCH_FRESH + Duration::from_secs(2);
        e.latch_endpoint("peerA", t1);
        assert_eq!(e.send_target(t1), "peerA");
        assert_eq!(PEER_LATCH_FRESH, Duration::from_secs(30));
    }

    /// An echo counts only from the latched endpoint, under the peer's epoch.
    #[test]
    fn the_echoer_is_the_latched_endpoint() {
        let mut e = Epochs::new(1, false);
        assert_eq!(e.echoer_epoch("peerA"), 0);
        e.receive("peerA", &frame(0x1111, 0, b"x"), Instant::now());
        assert_eq!(e.echoer_epoch("peerA"), 0x1111);
        assert_eq!(e.echoer_epoch("peerB"), 0);
        assert_eq!(e.echoer_epoch(""), 0);
    }

    #[test]
    fn the_local_peer_id_is_the_epoch_in_eight_hex_digits() {
        assert_eq!(Epochs::new(0xabc, false).local_peer_id(), "00000abc");
        assert_eq!(Epochs::new(0xdead_beef, false).local_peer_id(), "deadbeef");
    }

    #[test]
    fn a_random_epoch_is_never_zero() {
        for _ in 0..1000 {
            assert_ne!(random_epoch(), 0);
        }
    }

    #[test]
    fn peer_seen_is_an_epoch_or_an_occupant() {
        let mut e = Epochs::new(1, false);
        assert!(!e.peer_seen(0));
        assert!(e.peer_seen(1), "another occupant of the room");
        e.confirm_peer("00000005").unwrap();
        assert!(e.peer_seen(0));
        assert_eq!(RECONNECT_GRACE, Duration::from_secs(20));
    }

    #[test]
    fn the_reconnect_grace() {
        let mut e = Epochs::new(1, false);
        let t0 = Instant::now();
        assert!(!e.in_reconnect_grace(t0));
        e.note_reconnect(t0);
        assert!(e.in_reconnect_grace(t0 + Duration::from_secs(19)));
        assert!(!e.in_reconnect_grace(t0 + Duration::from_secs(20)));
    }
}

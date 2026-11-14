//! The OS network changed under live connections on UDP sockets of their
//! own: QUIC carriers and mKCP. A host's reset of the network also lets go
//! of the connections the TCP transports keep for later flows.

use std::sync::Arc;

use tokio::sync::watch;

/// One core's signal that the OS network changed. A QUIC connection dialed
/// with it takes a fresh protected socket on every change and keeps its
/// streams, as a Hysteria client does on its own rebind. A connection that
/// cannot move, behind a `realm`, `xdns` or `xicmp` mask, is left alone. An
/// mKCP connection on its own UDP socket cannot move either: its server
/// knows a session by the client's address. It fails at once if its
/// datagrams leave from another address now; otherwise it waits a short
/// while for its peer, and fails if the peer is not heard.
#[derive(Clone, Debug)]
pub struct NetworkChanges(Arc<watch::Sender<u64>>);

impl Default for NetworkChanges {
    fn default() -> Self {
        Self(Arc::new(watch::channel(0).0))
    }
}

impl NetworkChanges {
    /// Tells every connection that follows these changes of one: a QUIC
    /// connection takes a fresh socket, an mKCP connection fails or starts
    /// waiting for its peer. Returns how many follow them, of either kind: neither
    /// paths validated nor connections that will survive. An mKCP connection
    /// is counted until its driver is gone, a while after its stream.
    pub fn notify(&self) -> u64 {
        self.0
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.0.receiver_count() as u64
    }

    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

/// One core's signal that the host reset its network, as a host does when
/// the device moved to another network: a connection a transport keeps for
/// later flows, opened on the old path, is let go instead of waiting for its
/// timeouts, and so is an answer a DNS cache kept from it.
///
/// Each reset starts a new generation. A pooled connection belongs to the
/// generation its dial started in: it is handed to no flow of a later one,
/// and the pool lets it go when the generation moves on, idle or not. A
/// dialer made from another by cloning shares its resets, as it shares its
/// [`NetworkChanges`].
#[derive(Clone, Debug)]
pub struct NetworkResets(Arc<watch::Sender<u64>>);

impl Default for NetworkResets {
    fn default() -> Self {
        Self(Arc::new(watch::channel(0).0))
    }
}

impl NetworkResets {
    /// Starts a new generation. Nonblocking: the pools that follow it let
    /// their connections go on their own tasks, and every other holder
    /// checks the generation before its next use. Returns how many followers
    /// were told, as [`NetworkChanges::notify`] counts them: one per gRPC
    /// connection pooled or being dialed, and one per XHTTP transport over
    /// TCP however many slots it keeps. It is not a count of connections let
    /// go.
    pub fn reset(&self) -> u64 {
        self.0
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        self.0.receiver_count() as u64
    }

    /// The current generation, 0 until the first reset.
    pub fn generation(&self) -> u64 {
        *self.0.borrow()
    }

    pub(crate) fn follow(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

/// Returns once `resets` has moved past `generation`, at once if it already
/// has; never when the signal is gone with its dialer, as no reset can come.
pub(crate) async fn reset_after(resets: &mut watch::Receiver<u64>, generation: u64) {
    if resets
        .wait_for(|current| *current != generation)
        .await
        .is_err()
    {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resets count generations, every dialer made from one shares them,
    /// and a follower wakes for a reset it has not seen, even one made
    /// before it waited.
    #[tokio::test]
    async fn resets_count_generations_shared_by_derived_dialers() {
        let base = crate::TransportDialer::system().unwrap();
        let derived = base
            .clone()
            .with_socket_options(Arc::new(crate::SocketOptions::default()));
        assert_eq!(derived.network_resets().generation(), 0);
        assert_eq!(base.network_resets().reset(), 0);
        let mut follower = derived.network_resets().follow();
        assert_eq!(base.network_resets().generation(), 1);
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            reset_after(&mut follower, 1),
        )
        .await
        .expect_err("no reset since the follower's generation");
        assert_eq!(base.network_resets().reset(), 1);
        assert_eq!(derived.network_resets().generation(), 2);
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            reset_after(&mut follower, 1),
        )
        .await
        .expect("a follower sees a reset made before it waited");

        let other = crate::TransportDialer::system().unwrap();
        assert_eq!(other.network_resets().generation(), 0);

        // With its dialer gone, the follower waits for nothing.
        drop((base, derived));
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            reset_after(&mut follower, 2),
        )
        .await
        .expect_err("no reset can come without the dialer");
    }

    /// One signal for a core: a dialer made from another by cloning shares
    /// it, so a notification on the first reaches whoever follows the second.
    #[test]
    fn dialers_made_from_one_share_its_changes() {
        let base = crate::TransportDialer::system().unwrap();
        let derived = base
            .clone()
            .with_socket_options(Arc::new(crate::SocketOptions::default()));
        assert_eq!(base.network_changes().notify(), 0);
        let follower = derived.network_changes().follow();
        assert!(!follower.has_changed().unwrap());
        assert_eq!(base.network_changes().notify(), 1);
        assert!(follower.has_changed().unwrap());
        drop(follower);
        assert_eq!(base.network_changes().notify(), 0);

        let other = crate::TransportDialer::system().unwrap();
        let _stranger = other.network_changes().follow();
        assert_eq!(base.network_changes().notify(), 0);
    }
}

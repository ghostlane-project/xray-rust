//! One receive buffer per thread for every SOCKS UDP socket.
//!
//! A UDP association used to own a 64 KiB buffer for its life, and so did each
//! freedom flow. They sit in an async fn's state across `.await`, so each is a
//! separate allocation; on iOS the resolver opens an association per query,
//! hev kept 117 alive (memory model 05, R4). A datagram is read here instead,
//! with `try_recv_from` right after the socket is readable: the borrow of the
//! scratch buffer never crosses an `.await`, so a task may move between
//! workers, and the datagram leaves as an exact-size copy.
//!
//! Formula: scratch bytes = runtime workers that read a SOCKS UDP socket x
//! 65,536 B (1 on iOS, `available_parallelism().clamp(2, 6)` elsewhere; the
//! blocking pool never reads), a constant whatever the number of associations.
//! Each is allocated by the first read on its worker and never freed. The
//! buffer is `calloc`ed and only the pages a datagram touches are resident
//! (one for a DNS-sized one).
use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// The largest UDP datagram is 65,507 B; 65,536 B keeps the old buffer's size.
pub(super) const SCRATCH_SIZE: usize = 65_536;

thread_local! {
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Reads one datagram if one is ready and hands it to `f` as a slice of the
/// thread's scratch buffer. `f` runs with the buffer borrowed: it must copy
/// what it keeps and must not call back into this module.
pub(super) fn try_recv_with<R>(
    socket: &UdpSocket,
    f: impl FnOnce(&[u8], SocketAddr) -> R,
) -> io::Result<R> {
    SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        if scratch.len() != SCRATCH_SIZE {
            *scratch = vec![0; SCRATCH_SIZE];
        }
        let (len, from) = socket.try_recv_from(&mut scratch)?;
        Ok(f(&scratch[..len], from))
    })
}

/// Waits until a datagram arrives, then runs `f` on it as [`try_recv_with`]
/// does. Cancel safe: dropped before it completes, no datagram is consumed.
pub(super) async fn recv_with<R>(
    socket: &UdpSocket,
    mut f: impl FnMut(&[u8], SocketAddr) -> R,
) -> io::Result<R> {
    loop {
        socket.readable().await?;
        match try_recv_with(socket, &mut f) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => return result,
        }
    }
}

/// [`recv_with`] that keeps the datagram: an exact-size copy and its sender.
pub(super) async fn recv_exact(socket: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    recv_with(socket, |datagram, from| (datagram.to_vec(), from)).await
}

/// [`recv_exact`] for a freedom flow's socket. A plain socket reads through the
/// scratch buffer. A socket under `finalmask.udp` unmasks into `spare`: a rare
/// path that keeps the 64 KiB buffer it always had. It is allocated on the
/// first call (the flow's first loop pass, right after its first send, before
/// any reply) and belongs to that flow; a plain flow's `spare` stays empty.
pub(super) async fn recv_freedom(
    socket: &crate::outbound::FreedomUdpSocket,
    spare: &mut Vec<u8>,
) -> io::Result<(Vec<u8>, SocketAddr)> {
    use crate::outbound::FreedomUdpSocket;
    match socket {
        FreedomUdpSocket::Plain(socket) => recv_exact(socket).await,
        FreedomUdpSocket::Masked(_) => {
            if spare.len() != SCRATCH_SIZE {
                *spare = vec![0; SCRATCH_SIZE];
            }
            let (len, from) = socket.recv_from(spare).await?;
            Ok((spare[..len].to_vec(), from))
        }
    }
}

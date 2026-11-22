//! The way out on macOS: a socket leaves by the interface the session
//! names (`IP_BOUND_IF` and `IPV6_BOUND_IF`).
//!
//! Not built yet: a session that names an interface is refused.

use std::sync::Arc;

use crate::escape::Binder;
use crate::events::Events;
use crate::session::Bind;
use crate::Failure;

/// The binding of sockets to `bind.interface`. `events` is for a way out
/// that moves later: each move is printed as `bound`.
///
/// # Errors
/// `bind` when the interface cannot be used.
pub fn open(bind: &Bind, events: &Events) -> Result<Arc<dyn Binder>, Failure> {
    let _ = events;
    Err(Failure::unsupported(format!(
        "binding sockets to `{}` is not built for macOS yet",
        bind.interface
    )))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use serde_json::{json, Map};

    use std::io;

    use crate::events::{Events, FailureCode};

    use super::*;

    fn bind(interface: &str, more: Map<String, serde_json::Value>) -> Bind {
        Bind {
            interface: interface.to_owned(),
            more,
        }
    }

    fn quiet() -> Events {
        Events::to(Box::new(std::io::sink()))
    }

    fn refusal(found: Result<Arc<dyn Binder>, Failure>) -> Failure {
        match found {
            Ok(_) => panic!("the interface was taken"),
            Err(failure) => failure,
        }
    }

    /// An unbound, non-blocking socket of `domain` and `kind`.
    fn socket(domain: libc::c_int, kind: libc::c_int) -> OwnedFd {
        // SAFETY: socket takes plain integers.
        let fd = unsafe { libc::socket(domain, kind, 0) };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: `fd` is a socket this function owns.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fcntl on a valid descriptor.
        let status = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        assert_eq!(status, 0, "fcntl: {}", io::Error::last_os_error());
        owned
    }

    /// Whether `fd` connects to `peer` within `within`. A refusal at once
    /// (no route out of the bound interface) and a connect that never
    /// completes are both "no".
    fn connects(fd: &OwnedFd, peer: SocketAddrV4, within: Duration) -> bool {
        let address = libc::sockaddr_in {
            sin_len: u8::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap(),
            sin_family: u8::try_from(libc::AF_INET).unwrap(),
            sin_port: peer.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*peer.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `address` is a sockaddr_in of the length passed.
        let status = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap(),
            )
        };
        if status == 0 {
            return true;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            eprintln!("connect to {peer}: {error}");
            return false;
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                eprintln!("connect to {peer}: no answer in {within:?}");
                return false;
            }
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let wait = libc::c_int::try_from(left.as_millis().min(200)).unwrap_or(200);
            // SAFETY: one valid pollfd.
            let ready = unsafe { libc::poll(&mut poll, 1, wait) };
            if ready <= 0 {
                continue;
            }
            let mut failed: libc::c_int = 0;
            let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
            // SAFETY: `failed` and `length` are valid for the call.
            let status = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    std::ptr::from_mut(&mut failed).cast(),
                    &mut length,
                )
            };
            assert_eq!(status, 0, "SO_ERROR: {}", io::Error::last_os_error());
            if failed != 0 {
                eprintln!(
                    "connect to {peer}: {}",
                    io::Error::from_raw_os_error(failed)
                );
            }
            return failed == 0;
        }
    }

    /// Addresses that are not loopback and answer on 443 from the open
    /// internet; a way out that works reaches at least one.
    fn far_away() -> Vec<SocketAddrV4> {
        [[1, 1, 1, 1], [8, 8, 8, 8], [140, 82, 112, 3]]
            .into_iter()
            .map(|octets| SocketAddrV4::new(Ipv4Addr::from(octets), 443))
            .collect()
    }

    /// The interface the system's default route leaves by.
    fn default_interface() -> String {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .expect("route runs");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.lines()
            .find_map(|line| line.trim().strip_prefix("interface:"))
            .map(|name| name.trim().to_owned())
            .unwrap_or_else(|| panic!("no default interface in: {text}"))
    }

    #[test]
    fn an_interface_that_is_not_there_is_a_bind_failure() {
        let failure = refusal(open(&bind("eth9-none", Map::new()), &quiet()));
        assert_eq!(failure.code, FailureCode::Bind);
        assert_eq!(failure.message, "interface `eth9-none` does not exist");

        for name in ["", "a-name-longer-than-ifnamsiz", "nul\0in"] {
            let failure = refusal(open(&bind(name, Map::new()), &quiet()));
            assert_eq!(failure.code, FailureCode::Bind, "{name:?}");
        }

        let mut more = Map::new();
        more.insert("service".to_owned(), json!("x"));
        let failure = refusal(open(&bind("lo0", more), &quiet()));
        assert_eq!(failure.message, "`bind.service` is not read on macOS");
    }

    /// Both families are bound, again and again, and what is not a socket
    /// is refused.
    #[test]
    fn both_families_are_bound_and_a_number_that_is_not_a_socket_is_refused() {
        let binder = open(&bind("lo0", Map::new()), &quiet()).expect("lo0 is there");
        for (domain, kind) in [
            (libc::AF_INET, libc::SOCK_STREAM),
            (libc::AF_INET, libc::SOCK_DGRAM),
            (libc::AF_INET6, libc::SOCK_STREAM),
            (libc::AF_INET6, libc::SOCK_DGRAM),
        ] {
            let fd = socket(domain, kind);
            let raw = i64::from(fd.as_raw_fd());
            binder
                .bind(raw)
                .unwrap_or_else(|e| panic!("{domain} {kind}: {e}"));
            binder.bind(raw).expect("bound again, unchanged");
        }
        let local = socket(libc::AF_UNIX, libc::SOCK_STREAM);
        assert!(binder.bind(i64::from(local.as_raw_fd())).is_err());
        assert!(binder.bind(-1).is_err());
        assert!(binder.bind(i64::MAX).is_err());
    }

    /// Bound to loopback's interface, a socket cannot leave for an address
    /// that is not loopback: nothing out of lo0 routes there.
    #[test]
    fn bound_to_lo0_a_fetch_of_a_non_loopback_address_fails() {
        let binder = open(&bind("lo0", Map::new()), &quiet()).expect("lo0 is there");
        for peer in far_away() {
            let fd = socket(libc::AF_INET, libc::SOCK_STREAM);
            binder.bind(i64::from(fd.as_raw_fd())).unwrap();
            assert!(
                !connects(&fd, peer, Duration::from_secs(3)),
                "a socket bound to lo0 reached {peer}"
            );
        }
    }

    /// Bound to the interface the default route leaves by, the same socket
    /// reaches the internet.
    #[test]
    fn bound_to_the_default_interface_a_fetch_passes() {
        let interface = default_interface();
        let binder = open(&bind(&interface, Map::new()), &quiet()).expect("the default interface");
        let reached = far_away().into_iter().any(|peer| {
            let fd = socket(libc::AF_INET, libc::SOCK_STREAM);
            binder.bind(i64::from(fd.as_raw_fd())).unwrap();
            connects(&fd, peer, Duration::from_secs(8))
        });
        assert!(reached, "no address answered through {interface}");
    }
}

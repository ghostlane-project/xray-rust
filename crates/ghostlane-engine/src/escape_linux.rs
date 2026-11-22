//! The way out on Linux: a socket leaves by the interface the session
//! names (`SO_BINDTODEVICE`).
//!
//! An unprivileged process may bind a socket that is not bound yet (Linux
//! 5.7 and later); binding one again to another interface needs
//! `CAP_NET_RAW`, so a socket already bound to the session's interface is
//! left as it is. Routing then looks only at routes out of that interface:
//! a default route through a tunnel in a table of its own, which every other
//! socket follows, is passed over, and the interface's own route is used.
//! Loopback sockets never get here (`escape.rs` leaves them out). The
//! session's `bind` holds the interface alone on Linux.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::sync::Arc;

use crate::escape::{Binder, RawSocket};
use crate::events::{Events, FailureCode};
use crate::session::Bind;
use crate::Failure;

/// The binding of sockets to `bind.interface`. `events` is for a way out
/// that moves later: each move is printed as `bound`.
///
/// # Errors
/// `bind` when the interface cannot be used.
pub fn open(bind: &Bind, events: &Events) -> Result<Arc<dyn Binder>, Failure> {
    let _ = events;
    let refused = |message: String| Failure::new(FailureCode::Bind, message);
    if let Some(field) = bind.more.keys().next() {
        return Err(refused(format!("`bind.{field}` is not read on Linux")));
    }
    let interface = &bind.interface;
    let name = CString::new(interface.as_str())
        .ok()
        .filter(|name| !name.as_bytes().is_empty() && name.as_bytes().len() < libc::IFNAMSIZ)
        .ok_or_else(|| refused(format!("`{interface}` is not an interface name")))?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
        return Err(refused(format!("interface `{interface}` does not exist")));
    }
    Ok(Arc::new(DeviceBinder {
        interface: interface.clone(),
        name,
    }))
}

struct DeviceBinder {
    interface: String,
    name: CString,
}

impl DeviceBinder {
    /// The interface `fd` is bound to now, if any.
    fn bound_to(fd: RawFd) -> io::Result<Vec<u8>> {
        let mut name = [0_u8; libc::IFNAMSIZ];
        let mut length = libc::socklen_t::try_from(name.len())
            .map_err(|_| io::Error::other("the interface name buffer is too long"))?;
        // SAFETY: `name` and `length` are valid for writes of `length` bytes
        // and a socklen_t, as getsockopt asks.
        let status = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length).unwrap_or(0).min(name.len());
        let bound = &name[..length];
        let end = bound.iter().position(|&b| b == 0).unwrap_or(bound.len());
        Ok(bound[..end].to_vec())
    }
}

impl Binder for DeviceBinder {
    fn bind(&self, socket: RawSocket) -> io::Result<()> {
        let fd = RawFd::try_from(socket)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a file descriptor"))?;
        let wanted = self.name.as_bytes();
        if Self::bound_to(fd).is_ok_and(|bound| bound == wanted) {
            return Ok(());
        }
        let with_nul = self.name.as_bytes_with_nul();
        let length = libc::socklen_t::try_from(with_nul.len())
            .map_err(|_| io::Error::other("the interface name is too long"))?;
        // SAFETY: `with_nul` is valid for reads of `length` bytes.
        let status = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                with_nul.as_ptr().cast(),
                length,
            )
        };
        if status != 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("binding to `{}`: {error}", self.interface),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, UdpSocket};
    use std::os::fd::AsRawFd;

    use serde_json::{json, Map};

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
        let failure = refusal(open(&bind("lo", more), &quiet()));
        assert_eq!(failure.message, "`bind.service` is not read on Linux");
    }

    /// Bound to loopback, a socket keeps its binding when it is handed in
    /// again, and a number that is not a socket is refused.
    #[test]
    fn a_socket_is_bound_once_and_kept() {
        let binder = open(&bind("lo", Map::new()), &quiet()).expect("lo is there");
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let fd = udp.as_raw_fd();
        binder.bind(i64::from(fd)).expect("bound to lo");
        assert_eq!(DeviceBinder::bound_to(fd).unwrap(), b"lo");
        binder.bind(i64::from(fd)).expect("bound again, unchanged");
        assert!(binder.bind(-1).is_err());
        assert!(binder.bind(i64::MAX).is_err());
    }
}

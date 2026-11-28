//! The way out on Windows: a socket leaves by the interface the session
//! names (`IP_UNICAST_IF` for an IPv4 socket, `IPV6_UNICAST_IF` for an IPv6
//! one, set by the interface's index).
//!
//! The index is read once, when the way out opens, so an interface that is
//! not there is refused at the start. The interface is named by its alias as
//! the adapter list shows it (`Ethernet`); a number names an index.
//! Loopback sockets never get here (`escape.rs` leaves them out). The
//! session's `bind` holds the interface alone on Windows.

use std::io;
use std::sync::Arc;

use xray_transport::windows_interface;

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
        return Err(refused(format!("`bind.{field}` is not read on Windows")));
    }
    let interface = &bind.interface;
    if interface.is_empty() {
        return Err(refused(format!("`{interface}` is not an interface name")));
    }
    let index = windows_interface::interface_index(interface)
        .map_err(|error| refused(format!("interface `{interface}`: {error}")))?;
    Ok(Arc::new(IndexBinder {
        interface: interface.clone(),
        index,
    }))
}

struct IndexBinder {
    interface: String,
    index: u32,
}

impl Binder for IndexBinder {
    fn bind(&self, socket: RawSocket) -> io::Result<()> {
        windows_interface::set_unicast_if(socket, self.index).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("binding to `{}`: {error}", self.interface),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    use std::os::windows::io::AsRawSocket;

    use serde_json::{json, Map};

    use super::*;

    fn bind_of(interface: &str) -> Bind {
        Bind {
            interface: interface.to_owned(),
            more: Map::new(),
        }
    }

    /// An interface that exists on every Windows host: the loopback pseudo
    /// interface, whose index is read back from the system, never assumed.
    fn an_interface() -> (String, u32) {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetAdapter -IncludeHidden | Select-Object -First 1 | ForEach-Object { $_.Name + '|' + $_.ifIndex })",
            ])
            .output()
            .expect("run powershell");
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let (name, index) = text.rsplit_once('|').unwrap_or_else(|| {
            panic!(
                "no adapter listed: {text:?} {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (name.to_owned(), index.parse().expect("an index"))
    }

    #[test]
    fn a_socket_leaves_by_ip_unicast_if() {
        let (name, index) = an_interface();
        let binder = open(&bind_of(&name), &Events::to(Box::new(std::io::sink())))
            .expect("the way out opens");
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let raw = i64::try_from(socket.as_raw_socket()).unwrap();
        // The option is not set before the binder runs.
        assert_eq!(windows_interface::unicast_if_of(raw, false).unwrap(), 0);
        binder.bind(raw).expect("the binder sets the option");
        assert_eq!(
            windows_interface::unicast_if_of(raw, false).unwrap(),
            index,
            "IP_UNICAST_IF holds the index of `{name}`"
        );
    }

    #[test]
    fn an_ipv6_socket_takes_ipv6_unicast_if() {
        let (name, index) = an_interface();
        let binder = open(&bind_of(&name), &Events::to(Box::new(std::io::sink())))
            .expect("the way out opens");
        let Ok(socket) = UdpSocket::bind("[::]:0") else {
            return; // no IPv6 on this host
        };
        let raw = i64::try_from(socket.as_raw_socket()).unwrap();
        binder.bind(raw).expect("the binder sets the option");
        assert_eq!(windows_interface::unicast_if_of(raw, true).unwrap(), index);
    }

    #[test]
    fn a_tcp_socket_is_bound_too() {
        let (name, index) = an_interface();
        let binder = open(&bind_of(&name), &Events::to(Box::new(std::io::sink())))
            .expect("the way out opens");
        let socket = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let raw = i64::try_from(socket.as_raw_socket()).unwrap();
        binder.bind(raw).unwrap();
        assert_eq!(windows_interface::unicast_if_of(raw, false).unwrap(), index);
    }

    #[test]
    fn an_interface_that_is_not_there_is_refused_at_the_start() {
        let Err(failure) = open(
            &bind_of("no-such-interface-x"),
            &Events::to(Box::new(std::io::sink())),
        ) else {
            panic!("a missing interface must be refused");
        };
        assert!(failure.message.contains("no-such-interface-x"));
    }

    #[test]
    fn a_field_this_system_does_not_read_is_refused() {
        let more = json!({"table": 5}).as_object().unwrap().clone();
        let bind = Bind {
            interface: "Ethernet".to_owned(),
            more,
        };
        assert!(open(&bind, &Events::to(Box::new(std::io::sink()))).is_err());
    }
}

//! The way out past a tunnel. When the machine's default route is a tunnel
//! that leads back to this engine, the engine's own sockets must not follow
//! it: each socket but loopback's is bound, before it connects, to the
//! interface the session names (`bind.interface`). How a socket is bound is
//! the system's business, one file per system: `escape_linux.rs`,
//! `escape_macos.rs`, `escape_windows.rs`.
//!
//! Both halves use one [`Escape`]: the core through
//! [`Escape::core_protector`], the room through [`Escape::bind`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use xray_transport::{SocketHandle, SocketProtector};

use crate::events::{Event, Events};
use crate::session::Bind;
use crate::Failure;

/// A socket as the system names it: a file descriptor on Unix, a `SOCKET`
/// on Windows.
pub type RawSocket = i64;

/// What a system's file gives: the binding of one socket.
pub trait Binder: Send + Sync {
    /// Binds `socket`, which has not connected or sent yet, to the way out.
    ///
    /// # Errors
    /// The system's refusal; the socket is then not used.
    fn bind(&self, socket: RawSocket) -> io::Result<()>;
}

/// A session's way out.
#[derive(Clone)]
pub struct Escape {
    interface: String,
    binder: Arc<dyn Binder>,
}

impl Escape {
    /// Opens the way out the session names and prints `bound`.
    ///
    /// # Errors
    /// `bind` when the interface cannot be used, `unsupported` when this
    /// build has no escape for the system.
    pub fn open(bind: &Bind, events: &Events) -> Result<Self, Failure> {
        let binder = system(bind, events)?;
        events.emit(&Event::Bound {
            interface: bind.interface.clone(),
        });
        Ok(Self::with_binder(bind.interface.clone(), binder))
    }

    /// A way out by `interface` over `binder`: what [`Self::open`] makes of
    /// the system's binder, and what a test makes of a stand-in. Prints
    /// nothing.
    #[must_use]
    pub fn with_binder(interface: impl Into<String>, binder: Arc<dyn Binder>) -> Self {
        Self {
            interface: interface.into(),
            binder,
        }
    }

    /// The interface's name.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Binds one socket of the room half, which will connect or send to
    /// `peer` when the opener knows it.
    ///
    /// # Errors
    /// The system's refusal.
    pub fn bind(&self, socket: RawSocket, peer: Option<SocketAddr>) -> io::Result<()> {
        let _ = peer;
        self.binder.bind(socket)
    }

    /// The same binding as the core's socket protector.
    #[must_use]
    pub fn core_protector(&self) -> Arc<dyn SocketProtector> {
        Arc::new(CoreProtector(Arc::clone(&self.binder)))
    }
}

#[cfg(target_os = "linux")]
use crate::escape_linux::open as system;
#[cfg(target_os = "macos")]
use crate::escape_macos::open as system;
#[cfg(windows)]
use crate::escape_windows::open as system;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn system(bind: &Bind, events: &Events) -> Result<Arc<dyn Binder>, Failure> {
    let _ = (bind, events);
    Err(Failure::unsupported(
        "binding sockets to an interface is not built for this system",
    ))
}

struct CoreProtector(Arc<dyn Binder>);

impl SocketProtector for CoreProtector {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        self.0.bind(socket.raw())
    }
}

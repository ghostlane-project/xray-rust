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

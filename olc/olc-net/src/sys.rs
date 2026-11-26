// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The one call into the C library the network layer needs: a scoped
//! address's interface. The only `unsafe` in the crate.

#![allow(unsafe_code)]

/// The index of interface `name` (`if_nametoindex`), for a scoped
/// link-local resolver such as `fe80::1%pdp_ip0`.
pub(crate) fn if_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call;
    // `if_nametoindex` only reads it.
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (idx != 0).then_some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_loopback_interface_has_an_index() {
        assert!(if_index("lo").or_else(|| if_index("lo0")).is_some());
        assert_eq!(if_index("no-such-interface0"), None);
    }

    #[cfg(windows)]
    #[test]
    fn a_named_zone_has_no_index_without_if_nametoindex() {
        assert_eq!(if_index("no-such-interface0"), None);
    }
}

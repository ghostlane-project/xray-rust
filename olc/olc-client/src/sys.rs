// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Where the client asks the C library for the file limit at start, on
//! hosts that have the call. The only `unsafe` in the crate. (A scoped
//! address's interface, which the resolver needs, is in `olc_net::sys`
//! with the resolver.)
//!
//! [`raise_nofile_limit`] is xray-cli's (`crates/xray-cli/src/lib.rs`,
//! `raise_nofile_limit`), carried here so the engine needs none of the Xray
//! crates: the binary calls it first thing, and so will the FFI's init.

#![allow(unsafe_code)]

/// The process's file limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofileLimits {
    /// What the process may open now.
    pub soft: u64,
    /// What the soft limit may be raised to.
    pub hard: u64,
}

/// The file limits now.
#[cfg(unix)]
#[must_use]
#[allow(
    clippy::unnecessary_cast,
    reason = "rlim_t is only u64 on some unix targets"
)]
pub fn nofile_limits() -> Option<NofileLimits> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the provided struct only on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return None;
    }
    Some(NofileLimits {
        soft: limits.rlim_cur as u64,
        hard: limits.rlim_max as u64,
    })
}

/// The file limits now. Without `getrlimit` the process keeps the limit
/// the host started it with, and there is no value to report here.
#[cfg(not(unix))]
#[must_use]
pub fn nofile_limits() -> Option<NofileLimits> {
    None
}

/// Raises the soft file limit to the hard one, clamped on macOS and iOS to
/// `kern.maxfilesperproc` (setrlimit refuses more there even when the hard
/// limit says unlimited), and returns the limits in effect. The Go runtime
/// does the same at start (`syscall` package init), so the Go client ran at
/// the hard limit: 256 connections need more than iOS's default 256 files.
#[cfg(unix)]
#[allow(
    clippy::unnecessary_cast,
    reason = "rlim_t is only u64 on some unix targets"
)]
pub fn raise_nofile_limit() -> Option<NofileLimits> {
    let current = nofile_limits()?;
    let target = current.hard;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let target = match max_files_per_proc() {
        Some(max_files) => target.min(max_files),
        None => target,
    };
    if current.soft >= target {
        return Some(current);
    }
    let desired = libc::rlimit {
        rlim_cur: target as libc::rlim_t,
        rlim_max: current.hard as libc::rlim_t,
    };
    // SAFETY: setrlimit reads the provided struct; failure leaves limits
    // unchanged, so the follow-up getrlimit reports whatever is in effect.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &desired) };
    nofile_limits()
}

/// Raises the soft file limit to the hard one. Without `setrlimit` there
/// is no limit to raise: the host's value is left as it is.
#[cfg(not(unix))]
pub fn raise_nofile_limit() -> Option<NofileLimits> {
    None
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn max_files_per_proc() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: sysctlbyname writes at most `len` bytes into `value`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && value > 0).then_some(u64::try_from(value).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_soft_limit_is_raised_to_the_hard_one() {
        let after = raise_nofile_limit().expect("getrlimit");
        assert_eq!(after.soft, after.hard.min(after.soft.max(after.hard)));
        assert_eq!(after, nofile_limits().unwrap());
        assert_eq!(after.soft, after.hard, "{after:?}");
    }

    #[cfg(not(unix))]
    #[test]
    fn no_file_limits_without_getrlimit() {
        assert_eq!(nofile_limits(), None);
        assert_eq!(raise_nofile_limit(), None);
    }
}

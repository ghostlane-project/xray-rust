// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The errors the apps see, worded as `mobile/runtime.go:36-43` words them:
//! the apps show them as they are and match some of them
//! (`OlcrtcFailure.describe`, the desktop's fatal markers), so the texts are
//! Go's. A flat error crosses the FFI as its text: the Kotlin exception's
//! `message` is it, and in Swift `swift/OlcrtcError+Localized.swift` makes
//! it the `localizedDescription` (gomobile's NSError carried it there).

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum OlcrtcError {
    /// `ErrAlreadyRunning`.
    #[error("olcRTC runtime is already active")]
    AlreadyRunning,
    /// `ErrNotRunning`.
    #[error("olcRTC runtime has not been started")]
    NotRunning,
    /// `ErrStoppedBeforeReady`.
    #[error("olcRTC runtime stopped before becoming ready")]
    StoppedBeforeReady,
    /// `ErrReadyTimeout`.
    #[error("olcRTC runtime readiness timed out")]
    ReadyTimeout,
    /// `ErrStopTimeout`.
    #[error("olcRTC runtime stop timed out")]
    StopTimeout,
    /// `ErrInvalidConfig` with what was wrong (`%w: <detail>`).
    #[error("invalid mobile runtime configuration: {0}")]
    InvalidConfig(String),
    /// `ErrUnsupportedProvider: %q`: a provider this build does not carry.
    #[error("unsupported provider: {0:?}")]
    UnsupportedProvider(String),
    /// `ErrUnsupportedTransport: %q`.
    #[error("unsupported transport: {0:?}")]
    UnsupportedTransport(String),
    /// A setting refused with its own words (`dtls profile %q: ...`).
    #[error("{0}")]
    Setting(String),
    /// How a generation ended: the supervisor's error, with the room's
    /// (`supervisor: max failover cycles exceeded after 1 cycle(s): profile
    /// "<room>": run public client: client: ...`).
    #[error("{0}")]
    Run(String),
    /// A probe's failure (`Check`, `Ping`).
    #[error("{0}")]
    Probe(String),
}

/// `fmt.Errorf("%w: %s", ErrInvalidConfig, detail)`.
pub(crate) fn invalid(detail: impl Into<String>) -> OlcrtcError {
    OlcrtcError::InvalidConfig(detail.into())
}

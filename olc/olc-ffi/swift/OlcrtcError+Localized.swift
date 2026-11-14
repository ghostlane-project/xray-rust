// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

// Shipped beside the generated OlcFfi.swift. gomobile threw an NSError whose
// localizedDescription was the Go error's text, and the extension shows it
// and matches it (OlcrtcEngine's NSError domain "org.proofkit.tunnel" code 5,
// OlcrtcFailure). UniFFI's flat error carries that text as each case's
// message; this makes it the description. The switch is exhaustive, so a
// new case fails the build here rather than showing a reflection.

import Foundation

extension OlcrtcError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .AlreadyRunning(message),
             let .NotRunning(message),
             let .StoppedBeforeReady(message),
             let .ReadyTimeout(message),
             let .StopTimeout(message),
             let .InvalidConfig(message),
             let .UnsupportedProvider(message),
             let .UnsupportedTransport(message),
             let .Setting(message),
             let .Run(message),
             let .Probe(message):
            return message
        }
    }
}

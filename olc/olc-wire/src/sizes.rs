//! The numbers that tie the record layer to smux and to a transport
//! (`internal/runtime/runtime.go`, the transports' `Features`).
//!
//! A record carries whole smux frames, and a transport message carries one
//! record, so a smux frame's payload is capped at the transport's message cap
//! less [`SMUX_WIRE_OVERHEAD`] (record overhead plus smux header), and never
//! above [`SMUX_MAX_FRAME_SIZE`] (runtime.go:219-226). Both ends must agree on
//! the frame size and on smux version 2.

use std::time::Duration;

use crate::record::WIRE_OVERHEAD;
use crate::udpwire;

/// The smux frame header (runtime.go:23-26).
pub const SMUX_FRAME_OVERHEAD: usize = 8;
/// Record overhead plus smux header: 52 (runtime.go:27-29).
pub const SMUX_WIRE_OVERHEAD: usize = WIRE_OVERHEAD + SMUX_FRAME_OVERHEAD;
/// The smallest message cap that still carries a byte of smux payload
/// (runtime.go:30-32).
pub const MIN_SMUX_WIRE_PAYLOAD: usize = SMUX_WIRE_OVERHEAD + 1;
/// The smux payload cap without a transport limit (runtime.go:34).
pub const SMUX_MAX_FRAME_SIZE: usize = 32 * 1024;
/// The smux protocol version both ends speak (runtime.go:111, 208).
pub const SMUX_VERSION: u8 = 2;
/// smux keepalive interval on the data session (runtime.go:116).
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// smux keepalive timeout on the data session (runtime.go:117).
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// The keepalive timeout of a transport with a control plane (runtime.go:129-133).
pub const KEEPALIVE_TIMEOUT_LONG: Duration = Duration::from_secs(120);

/// The largest record the UDP lane carries: a full `udpwire` frame, sealed.
pub const UDP_MAX_RECORD: usize = WIRE_OVERHEAD + udpwire::MAX_FRAME_LEN;

/// The receive windows a process advertises (runtime.go:34-47, 73-78).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferProfile {
    /// A server's: 32 MiB per session, 4 MiB per stream.
    Server,
    /// A phone's (`UseConstrainedBuffers`): 4 MiB per session, 512 KiB per
    /// stream. The iOS extension lives in about 50 MB.
    Constrained,
}

/// Which smux session the settings are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmuxSession {
    /// The data session (`SmuxConfig`, runtime.go:105-119).
    Data,
    /// The data session on a transport with a control plane
    /// (`SmuxConfigLong`, runtime.go:121-133).
    DataLong,
    /// The isolated control session (`ControlSmuxConfig`, runtime.go:202-217).
    Control,
}

/// The smux settings the Go code uses, for `olc-smux`'s config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmuxSettings {
    /// Always [`SMUX_VERSION`].
    pub version: u8,
    /// The control session runs no smux keepalive; the control stream's own
    /// pings stand in for it.
    pub keepalive_disabled: bool,
    /// Time between keepalives.
    pub keepalive_interval: Duration,
    /// Silence after which the session is dead.
    pub keepalive_timeout: Duration,
    /// The largest smux frame payload.
    pub max_frame_size: usize,
    /// The session's receive window.
    pub max_receive_buffer: usize,
    /// Each stream's receive window.
    pub max_stream_buffer: usize,
}

/// The smux frame payload cap for a transport whose messages hold
/// `max_wire_payload` bytes; 0 or less, or too small to carry a frame, means
/// no transport limit (`clampMaxFrameSize`, runtime.go:219-226).
#[must_use]
pub fn max_frame_size(max_wire_payload: i64) -> usize {
    match usize::try_from(max_wire_payload) {
        Ok(cap) if cap >= MIN_SMUX_WIRE_PAYLOAD => {
            SMUX_MAX_FRAME_SIZE.min(cap - SMUX_WIRE_OVERHEAD)
        }
        _ => SMUX_MAX_FRAME_SIZE,
    }
}

/// The settings of `session` for a transport cap of `max_wire_payload` under
/// `profile` (runtime.go:105-133, 202-217). The control session's windows do
/// not depend on the profile.
#[must_use]
pub fn smux_settings(
    session: SmuxSession,
    max_wire_payload: i64,
    profile: BufferProfile,
) -> SmuxSettings {
    let (receive, stream) = match profile {
        BufferProfile::Server => (32 << 20, 4 << 20),
        BufferProfile::Constrained => (4 << 20, 512 << 10),
    };
    let max_frame_size = max_frame_size(max_wire_payload);
    match session {
        SmuxSession::Data | SmuxSession::DataLong => SmuxSettings {
            version: SMUX_VERSION,
            keepalive_disabled: false,
            keepalive_interval: KEEPALIVE_INTERVAL,
            keepalive_timeout: if session == SmuxSession::DataLong {
                KEEPALIVE_TIMEOUT_LONG
            } else {
                KEEPALIVE_TIMEOUT
            },
            max_frame_size,
            max_receive_buffer: receive,
            max_stream_buffer: stream,
        },
        SmuxSession::Control => SmuxSettings {
            version: SMUX_VERSION,
            keepalive_disabled: true,
            // smux's defaults, unused while disabled.
            keepalive_interval: KEEPALIVE_INTERVAL,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            max_frame_size,
            max_receive_buffer: 256 << 10,
            max_stream_buffer: 32 << 10,
        },
    }
}

/// The data channel transport (`internal/transport/datachannel/transport.go`).
pub mod datachannel {
    use std::time::Duration;

    /// Its message cap before any traffic shaper lowers it (transport.go:14,
    /// 211-217; `Shaper.Features`, transport/traffic.go:87-97).
    pub const MAX_PAYLOAD_SIZE: usize = 12 * 1024;
    /// It asks for write batching at this interval (transport.go:16-26).
    pub const WRITE_INTERVAL: Duration = Duration::from_millis(5);
}

/// The VP8 channel transport (`internal/transport/vp8channel/transport.go`).
/// It asks for no write interval (transport.go:558).
pub mod vp8channel {
    /// Its message cap before any traffic shaper lowers it (transport.go:56-57).
    pub const MAX_PAYLOAD_SIZE: usize = 60 * 1024;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_sizes_the_plan_names() {
        assert_eq!(max_frame_size(datachannel::MAX_PAYLOAD_SIZE as i64), 12236);
        assert_eq!(max_frame_size(vp8channel::MAX_PAYLOAD_SIZE as i64), 32768);
        assert_eq!(UDP_MAX_RECORD, 1515);
    }
}

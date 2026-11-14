// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0
// Ported from smux v1.5.57 mux.go, Copyright (c) 2016-2017 xtaci, MIT, and
// from olcRTC internal/runtime/runtime.go at 2d4266af, Apache-2.0.

use std::time::Duration;

use crate::frame::{HEADER_SIZE, MAX_FRAME_SIZE};
use crate::Error;

/// The OLC2 record overhead, `crypto.WireOverhead`: magic, counter and
/// prefix (28) plus the Poly1305 tag (16) (olcRTC `internal/crypto/chacha.go:33-44`).
pub const OLC_RECORD_OVERHEAD: usize = 44;

/// `SmuxWireOverhead`: what a whole smux frame adds on the transport, the
/// record overhead plus the frame header (`internal/runtime/runtime.go:26-29`).
pub const SMUX_WIRE_OVERHEAD: usize = OLC_RECORD_OVERHEAD + HEADER_SIZE;

/// `MinSmuxWirePayload` (`internal/runtime/runtime.go:30-32`).
pub const MIN_SMUX_WIRE_PAYLOAD: usize = SMUX_WIRE_OVERHEAD + 1;

/// The datachannel transport's `MaxPayloadSize`
/// (`internal/transport/datachannel/transport.go:14`).
pub const DATACHANNEL_MAX_PAYLOAD: usize = 12 * 1024;

/// The vp8channel transport's `MaxPayloadSize`
/// (`internal/transport/vp8channel/transport.go:57`).
pub const VP8CHANNEL_MAX_PAYLOAD: usize = 60 * 1024;

const SMUX_MAX_FRAME_SIZE: usize = 32 * 1024; // runtime.go:34

/// `clampMaxFrameSize` (`internal/runtime/runtime.go:219-226`): with a
/// transport payload cap of at least [`MIN_SMUX_WIRE_PAYLOAD`], the frame
/// size is at most the cap less [`SMUX_WIRE_OVERHEAD`], so that one record
/// holding one whole frame fits one transport message. A cap of 0 means none.
pub fn clamp_max_frame_size(frame_size: usize, max_wire_payload: usize) -> usize {
    if max_wire_payload >= MIN_SMUX_WIRE_PAYLOAD {
        frame_size.min(max_wire_payload - SMUX_WIRE_OVERHEAD)
    } else {
        frame_size
    }
}

/// The two buffer profiles olcRTC chooses between per process
/// (`internal/runtime/runtime.go:34-78`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostClass {
    /// Phones: the iOS packet tunnel extension and the Android VPN service.
    /// `mobile.New` switches the Go client to it (`mobile/runtime.go:75-91`).
    /// Session 4 MiB, stream 512 KiB (`runtime.go:46-47`).
    Constrained,
    /// Servers and desktop clients: session 32 MiB, stream 4 MiB
    /// (`runtime.go:35-36`).
    Server,
}

impl HostClass {
    /// (`MaxReceiveBuffer`, `MaxStreamBuffer`) for the data session
    /// (`receiveBufferSizes`, `internal/runtime/runtime.go:73-78`).
    pub const fn receive_buffers(self) -> (usize, usize) {
        match self {
            HostClass::Constrained => (4 * 1024 * 1024, 512 * 1024),
            HostClass::Server => (32 * 1024 * 1024, 4 * 1024 * 1024),
        }
    }
}

/// The keepalive: a NOP every `interval`, and the session closed when no
/// frame at all arrived during a whole `timeout` (`smux/session.go:519-543`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepAlive {
    /// `KeepAliveInterval`.
    pub interval: Duration,
    /// `KeepAliveTimeout`.
    pub timeout: Duration,
}

/// A session's settings: smux's `Config` (`smux/mux.go:31-57`) plus the
/// bounds this port adds for the memory it owns. The protocol version is
/// always 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// `KeepAliveInterval` and `KeepAliveTimeout`; `None` is
    /// `KeepAliveDisabled`.
    pub keep_alive: Option<KeepAlive>,
    /// `MaxFrameSize`: the largest PSH payload this side sends. At most 65535.
    pub max_frame_size: usize,
    /// `MaxReceiveBuffer`: the session token bucket, in payload bytes.
    pub max_receive_buffer: usize,
    /// `MaxStreamBuffer`: the window this side announces in every UPD, and
    /// twice the UPD threshold.
    pub max_stream_buffer: usize,
    /// How many peer-opened streams wait for `accept_stream` before the
    /// session stops reading (`defaultAcceptBacklog`, `smux/session.go:37,142,440-445`).
    pub accept_backlog: usize,
    /// How long opening and closing a stream wait for their SYN or FIN to
    /// be written (`openCloseTimeout`, `smux/session.go:40`).
    pub open_close_timeout: Duration,
    /// Port only: the outgoing payload one stream may queue before its
    /// writes wait. Go has no queue: its `Write` blocks until each frame is
    /// on the connection (`smux/session.go:674-711`).
    pub max_stream_send_buffer: usize,
    /// Port only: the outgoing payload all streams together may queue.
    pub max_send_buffer: usize,
    /// Port only: the session's read buffer for the connection.
    pub read_buffer_size: usize,
    /// Port only: how much of the chunk pool a quiet session keeps.
    pub pool_retain_bytes: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config::go_default()
    }
}

impl Config {
    /// smux's `DefaultConfig` (`smux/mux.go:62-71`) at version 2: keepalive
    /// 10 s / 30 s, frames 32768, session 4 MiB, stream 64 KiB.
    pub fn go_default() -> Config {
        Config::with_port_defaults(
            Some(KeepAlive {
                interval: Duration::from_secs(10),
                timeout: Duration::from_secs(30),
            }),
            32768,
            4 * 1024 * 1024,
            65536,
        )
    }

    /// The data session as olcRTC builds it (`SmuxConfig`, `SmuxConfigLong`
    /// and `SmuxConfigFor`, `internal/runtime/runtime.go:109-152`): version 2,
    /// keepalive every 10 s with a 30 s timeout, or 120 s on transports with a
    /// control plane (vp8channel), frames clamped to the transport, buffers by
    /// host class.
    pub fn data(host: HostClass, max_wire_payload: usize, control_plane: bool) -> Config {
        let (receive, stream) = host.receive_buffers();
        let timeout = if control_plane { 120 } else { 30 };
        Config::with_port_defaults(
            Some(KeepAlive {
                interval: Duration::from_secs(10),
                timeout: Duration::from_secs(timeout),
            }),
            clamp_max_frame_size(SMUX_MAX_FRAME_SIZE, max_wire_payload),
            receive,
            stream,
        )
    }

    /// The data session of the shipped client: [`Config::data`] with
    /// [`HostClass::Constrained`], as on every phone.
    pub fn client_data(max_wire_payload: usize, control_plane: bool) -> Config {
        Config::data(HostClass::Constrained, max_wire_payload, control_plane)
    }

    /// The isolated control session (`ControlSmuxConfig`,
    /// `internal/runtime/runtime.go:202-217`): session 256 KiB, stream 32 KiB,
    /// keepalive disabled, frames clamped to the transport. Both host classes
    /// use it.
    pub fn control(max_wire_payload: usize) -> Config {
        let mut cfg = Config::with_port_defaults(
            None,
            clamp_max_frame_size(SMUX_MAX_FRAME_SIZE, max_wire_payload),
            256 * 1024,
            32 * 1024,
        );
        // Control frames are a few hundred bytes; keep the port's own buffers small.
        cfg.read_buffer_size = 4096;
        cfg.pool_retain_bytes = 16 * 1024;
        cfg
    }

    fn with_port_defaults(
        keep_alive: Option<KeepAlive>,
        max_frame_size: usize,
        max_receive_buffer: usize,
        max_stream_buffer: usize,
    ) -> Config {
        Config {
            keep_alive,
            max_frame_size,
            max_receive_buffer,
            max_stream_buffer,
            accept_backlog: 1024,
            open_close_timeout: Duration::from_secs(30),
            max_stream_send_buffer: 2 * max_frame_size,
            max_send_buffer: 16 * max_frame_size,
            read_buffer_size: 16 * 1024,
            pool_retain_bytes: 256 * 1024,
        }
    }

    /// `VerifyConfig` (`smux/mux.go:74-108`), with Go's texts, then the
    /// port's own settings.
    pub fn verify(&self) -> Result<(), Error> {
        if let Some(ka) = self.keep_alive {
            if ka.interval.is_zero() {
                return Err(Error::Config("keep-alive interval must be positive"));
            }
            if ka.timeout < ka.interval {
                return Err(Error::Config(
                    "keep-alive timeout must be larger than keep-alive interval",
                ));
            }
        }
        if self.max_frame_size == 0 {
            return Err(Error::Config("max frame size must be positive"));
        }
        if self.max_frame_size > MAX_FRAME_SIZE {
            return Err(Error::Config(
                "max frame size must not be larger than 65535",
            ));
        }
        if self.max_receive_buffer == 0 {
            return Err(Error::Config("max receive buffer must be positive"));
        }
        if self.max_receive_buffer > i32::MAX as usize {
            return Err(Error::Config(
                "max receive buffer cannot be larger than 2147483647",
            ));
        }
        if self.max_stream_buffer == 0 {
            return Err(Error::Config("max stream buffer must be positive"));
        }
        if self.max_stream_buffer > self.max_receive_buffer {
            return Err(Error::Config(
                "max stream buffer must not be larger than max receive buffer",
            ));
        }
        if self.accept_backlog == 0 {
            return Err(Error::Config("accept backlog must be positive"));
        }
        if self.open_close_timeout.is_zero() {
            return Err(Error::Config("open/close timeout must be positive"));
        }
        if self.max_stream_send_buffer == 0 || self.max_send_buffer == 0 {
            return Err(Error::Config("send buffers must be positive"));
        }
        // A whole frame must fit, or a full one never leaves.
        if self.max_stream_send_buffer < self.max_frame_size
            || self.max_send_buffer < self.max_frame_size
        {
            return Err(Error::Config("send buffers must hold a whole frame"));
        }
        if self.read_buffer_size < HEADER_SIZE {
            return Err(Error::Config("read buffer must hold a frame header"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // internal/runtime/runtime.go:219-226 with the transports' payload caps.
    #[test]
    fn frame_sizes_per_transport() {
        assert_eq!(SMUX_WIRE_OVERHEAD, 52);
        assert_eq!(MIN_SMUX_WIRE_PAYLOAD, 53);
        assert_eq!(clamp_max_frame_size(32768, DATACHANNEL_MAX_PAYLOAD), 12236);
        assert_eq!(clamp_max_frame_size(32768, VP8CHANNEL_MAX_PAYLOAD), 32768);
        assert_eq!(clamp_max_frame_size(32768, 16 * 1024), 16332);
        assert_eq!(clamp_max_frame_size(32768, 0), 32768);
        assert_eq!(clamp_max_frame_size(32768, 52), 32768);
        assert_eq!(clamp_max_frame_size(32768, 53), 1);
    }

    // internal/runtime/runtime.go:46-47,109-133 as mobile/runtime.go:75-91 uses them.
    #[test]
    fn client_data_is_the_phone_profile() {
        let dc = Config::client_data(DATACHANNEL_MAX_PAYLOAD, false);
        assert_eq!(dc.max_receive_buffer, 4 * 1024 * 1024);
        assert_eq!(dc.max_stream_buffer, 512 * 1024);
        assert_eq!(dc.max_frame_size, 12236);
        assert_eq!(
            dc.keep_alive,
            Some(KeepAlive {
                interval: Duration::from_secs(10),
                timeout: Duration::from_secs(30)
            })
        );
        let vp8 = Config::client_data(VP8CHANNEL_MAX_PAYLOAD, true);
        assert_eq!(vp8.max_frame_size, 32768);
        assert_eq!(
            vp8.keep_alive.map(|k| k.timeout),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            vp8.keep_alive.map(|k| k.interval),
            Some(Duration::from_secs(10))
        );
        dc.verify().unwrap();
        vp8.verify().unwrap();
    }

    // internal/runtime/runtime.go:34-36: the server and desktop profile.
    #[test]
    fn server_profile() {
        let cfg = Config::data(HostClass::Server, VP8CHANNEL_MAX_PAYLOAD, true);
        assert_eq!(cfg.max_receive_buffer, 32 * 1024 * 1024);
        assert_eq!(cfg.max_stream_buffer, 4 * 1024 * 1024);
        cfg.verify().unwrap();
    }

    // internal/runtime/runtime.go:206-217.
    #[test]
    fn control_session_profile() {
        let cfg = Config::control(VP8CHANNEL_MAX_PAYLOAD);
        assert_eq!(cfg.max_receive_buffer, 256 * 1024);
        assert_eq!(cfg.max_stream_buffer, 32 * 1024);
        assert_eq!(cfg.keep_alive, None);
        assert_eq!(cfg.max_frame_size, 32768);
        assert_eq!(
            Config::control(DATACHANNEL_MAX_PAYLOAD).max_frame_size,
            12236
        );
        cfg.verify().unwrap();
    }

    // smux/mux.go:62-71.
    #[test]
    fn go_default_config() {
        let cfg = Config::go_default();
        assert_eq!(cfg.max_frame_size, 32768);
        assert_eq!(cfg.max_receive_buffer, 4194304);
        assert_eq!(cfg.max_stream_buffer, 65536);
        assert_eq!(cfg.accept_backlog, 1024);
        assert_eq!(cfg.open_close_timeout, Duration::from_secs(30));
        cfg.verify().unwrap();
    }

    // smux/mux.go:74-108, case by case.
    #[test]
    fn verify_rejects_what_go_rejects() {
        let base = Config::go_default();
        let bad = |f: &dyn Fn(&mut Config)| {
            let mut c = base.clone();
            f(&mut c);
            c.verify().unwrap_err().to_string()
        };
        assert_eq!(
            bad(&|c| c.keep_alive = Some(KeepAlive {
                interval: Duration::ZERO,
                timeout: Duration::from_secs(1)
            })),
            "keep-alive interval must be positive"
        );
        assert_eq!(
            bad(&|c| c.keep_alive = Some(KeepAlive {
                interval: Duration::from_secs(2),
                timeout: Duration::from_secs(1)
            })),
            "keep-alive timeout must be larger than keep-alive interval"
        );
        assert_eq!(
            bad(&|c| c.max_frame_size = 0),
            "max frame size must be positive"
        );
        assert_eq!(
            bad(&|c| c.max_frame_size = 65536),
            "max frame size must not be larger than 65535"
        );
        assert_eq!(
            bad(&|c| c.max_receive_buffer = 0),
            "max receive buffer must be positive"
        );
        assert_eq!(
            bad(&|c| c.max_receive_buffer = 1 << 31),
            "max receive buffer cannot be larger than 2147483647"
        );
        assert_eq!(
            bad(&|c| c.max_stream_buffer = 0),
            "max stream buffer must be positive"
        );
        assert_eq!(
            bad(&|c| c.max_stream_buffer = c.max_receive_buffer + 1),
            "max stream buffer must not be larger than max receive buffer"
        );
        let mut off = base.clone();
        off.keep_alive = None;
        off.verify().unwrap();
        let mut max = base;
        max.max_frame_size = 65535;
        max.verify().unwrap();
    }
}

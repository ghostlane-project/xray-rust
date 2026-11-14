//! One str0m `Rtc` on one UDP socket, driven synchronously from the probe's loop.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use str0m::config::{CryptoProvider, DtlsVersion};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc, RtcConfig};

use crate::wire::Taps;

pub struct Peer {
    pub name: &'static str,
    pub rtc: Rtc,
    pub sock: UdpSocket,
    pub local: SocketAddr,
    pub creds: IceCreds,
    pub timeout: Instant,
    pub events: VecDeque<Event>,
    pub taps: Taps,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    /// Datagrams the host refused to send (counted, not fatal).
    pub send_errors: usize,
}

/// The str0m configuration every probe uses: RTP mode (str0m hands RTP through untouched,
/// as the carriers' media will need), Chrome-sized ICE credentials, the given crypto.
pub fn rtc_config(provider: &Arc<CryptoProvider>, version: DtlsVersion, creds: &IceCreds) -> RtcConfig {
    RtcConfig::new()
        .set_crypto_provider(provider.clone())
        .set_dtls_version(version)
        .set_rtp_mode(true)
        .set_local_ice_credentials(creds.clone())
}

impl Peer {
    /// A connection whose one host candidate is `ip` on a fresh port.
    pub fn new(name: &'static str, ip: IpAddr, provider: &Arc<CryptoProvider>, version: DtlsVersion, creds: IceCreds) -> io::Result<Self> {
        let cfg = rtc_config(provider, version, &creds);
        Self::with_config(name, ip, cfg, creds)
    }

    /// The same with a configuration of the caller's (codecs, ICE lite, ...); `creds` must be
    /// the ones `cfg` was given.
    pub fn with_config(name: &'static str, ip: IpAddr, cfg: RtcConfig, creds: IceCreds) -> io::Result<Self> {
        let sock = UdpSocket::bind(SocketAddr::new(ip, 0))?;
        sock.set_nonblocking(true)?;
        let local = sock.local_addr()?;
        let rtc = cfg.build(Instant::now());
        Ok(Peer {
            name,
            rtc,
            sock,
            local,
            creds,
            timeout: Instant::now(),
            events: VecDeque::new(),
            taps: Taps::default(),
            tx_bytes: 0,
            rx_bytes: 0,
            send_errors: 0,
        })
    }

    /// Adds the socket's host candidate; returns its SDP line, for trickling.
    pub fn add_host_candidate(&mut self) -> Result<String, String> {
        let c = Candidate::host(self.local, "udp").map_err(|e| e.to_string())?;
        let added = self.rtc.add_local_candidate(c).ok_or("str0m refused the host candidate")?;
        Ok(added.to_sdp_string())
    }

    /// Polls str0m until it asks to be woken later: sends what it transmits, queues events.
    pub fn pump(&mut self) -> Result<(), String> {
        loop {
            match self.rtc.poll_output().map_err(|e| format!("{}: poll: {e}", self.name))? {
                Output::Timeout(t) => {
                    self.timeout = t;
                    return Ok(());
                }
                Output::Transmit(t) => {
                    self.taps.sent(&t.contents);
                    self.tx_bytes += t.contents.len();
                    if let Err(e) = self.sock.send_to(&t.contents, t.destination) {
                        // A pair whose path the host refuses (EPERM from a firewall, an
                        // unreachable network) fails on its own, as in any ICE agent; the
                        // other pairs go on.
                        if e.kind() != io::ErrorKind::WouldBlock {
                            self.send_errors += 1;
                            if self.send_errors <= 3 {
                                eprintln!("{}: send to {} refused: {e}", self.name, t.destination);
                            }
                        }
                    }
                }
                Output::Event(e) => self.events.push_back(e),
            }
        }
    }

    /// Reads every datagram waiting on the socket into str0m; true if any arrived.
    pub fn receive(&mut self) -> Result<bool, String> {
        let mut buf = [0u8; 2048];
        let mut any = false;
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    any = true;
                    self.rx_bytes += n;
                    self.taps.received(&buf[..n]);
                    if let Ok(r) = Receive::new(Protocol::Udp, src, self.local, &buf[..n]) {
                        self.rtc
                            .handle_input(Input::Receive(Instant::now(), r))
                            .map_err(|e| format!("{}: input: {e}", self.name))?;
                        self.pump()?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(any),
                Err(e) => return Err(format!("{}: recv: {e}", self.name)),
            }
        }
    }

    /// Fires str0m's timer if it is due.
    pub fn tick(&mut self) -> Result<(), String> {
        let now = Instant::now();
        if now >= self.timeout {
            self.rtc.handle_input(Input::Timeout(now)).map_err(|e| format!("{}: timeout: {e}", self.name))?;
        }
        self.pump()
    }
}

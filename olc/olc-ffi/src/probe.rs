// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The app's probes (`mobile/probe.go`, `ping.go`): one room joined on its
//! own (no supervisor, no failover), timed to its SOCKS port (`Check`), then
//! timed by HTTP requests through that port (`Ping`). The settings are the
//! runtime's (DTLS, DNS, UDP, rules) with the probe's own room, key, device
//! and port, on loopback without a login.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::{RuntimeConfig, DEFAULT_SOCKS_HOST};
use crate::error::{invalid, OlcrtcError};
use crate::runtime::{RoomRun, Runner};

/// `defaultCheckTimeout`.
pub const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(8);
/// `defaultPingTimeout`.
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(10);
/// `probeShutdownWait`.
pub const PROBE_SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
/// `defaultHTTPPingURL`.
pub const DEFAULT_PING_URL: &str = "https://www.google.com/generate_204";
/// `httpPingWarmupTimeout`, `httpPingSampleTimeout`.
const SAMPLE_TIMEOUT: Duration = Duration::from_millis(1500);
/// `httpPingSamples`.
const SAMPLES: usize = 3;
/// `httpPingSampleDelay`.
const SAMPLE_DELAY: Duration = Duration::from_millis(80);
/// The most a response's head may be.
const MAX_HEAD: usize = 16 * 1024;
/// The most of a body a ping reads before it gives the connection up.
const MAX_BODY: usize = 256 * 1024;

/// One probe's arguments.
pub(crate) struct Probe {
    pub provider: String,
    pub transport: String,
    pub room: String,
    pub device_id: String,
    pub key_hex: String,
    pub socks_port: i64,
    pub timeout_millis: i64,
    pub vp8: (i64, i64),
    pub ping_url: Option<String>,
}

/// `probeConfig` and `runProbe`.
pub(crate) fn run(defaults: &RuntimeConfig, runner: &Runner, p: Probe) -> Result<i64, OlcrtcError> {
    let mut t = defaults.clone();
    t.provider = p.provider;
    t.transport = p.transport;
    t.room = p.room;
    t.device_id = p.device_id;
    t.key_hex = p.key_hex;
    DEFAULT_SOCKS_HOST.clone_into(&mut t.socks_host);
    t.socks_user.clear();
    t.socks_pass.clear();
    if p.vp8.0 > 0 {
        t.vp8.0 = p.vp8.0;
    }
    if p.vp8.1 > 0 {
        t.vp8.1 = p.vp8.1;
    }
    let port = u16::try_from(p.socks_port)
        .map_err(|_| invalid("probe port must be between 0 and 65535"))?;
    // `validateProbeConfig`: port 0 (any) passes the start's check as 1.
    t.socks_port = port.max(1);
    t.validate()?;
    t.socks_port = port;
    if !(1..=120).contains(&t.vp8.0) || t.vp8.1 < 1 {
        return Err(invalid("invalid VP8 probe options"));
    }
    let url = match &p.ping_url {
        Some(u) => Some(normalize_url(u)?),
        None => None,
    };
    let device = crate::config::resolve_device_id(&t.device_id, &t.device_id_path)
        .map_err(OlcrtcError::Probe)?;
    let mut cfg = t.client_config(device, olc_client::log::verbose());
    cfg.url.clone_from(&t.room);
    let fallback = if url.is_some() {
        DEFAULT_PING_TIMEOUT
    } else {
        DEFAULT_CHECK_TIMEOUT
    };
    let timeout = u64::try_from(p.timeout_millis)
        .ok()
        .filter(|&ms| ms > 0)
        .map_or(fallback, Duration::from_millis);
    // A probe may be the first thing the process does: what a start puts
    // in for the signalling, it puts in too.
    crate::runtime::ensure_signalling_tls().map_err(OlcrtcError::Probe)?;
    let rt = ghostlane_runtime::handle()
        .map_err(|e| OlcrtcError::Probe(format!("olcRTC runtime: no threads: {e}")))?;
    let runner = runner.clone();
    crate::runtime::off_worker(|| rt.block_on(probe(runner, cfg, timeout, url)))
}

async fn probe(
    runner: Runner,
    cfg: olc_client::Config,
    timeout: Duration,
    url: Option<Target>,
) -> Result<i64, OlcrtcError> {
    let deadline = Instant::now() + timeout;
    let stop = CancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<SocketAddr>();
    let started = Instant::now();
    let mut done = tokio::spawn(runner(RoomRun {
        cfg,
        stop: stop.clone(),
        on_ready: Box::new(move |addr| {
            let _ = tx.send(addr);
        }),
        on_session_open: Arc::new(|_| {}),
    }));
    // Ready, ended or out of time, as `runProbe` selects. A run that lets
    // its `on_ready` go without calling it has not ended: only its end or
    // the deadline says so.
    let ready = async move {
        match rx.await {
            Ok(addr) => addr,
            Err(_) => std::future::pending().await,
        }
    };
    let addr = tokio::select! {
        biased;
        addr = ready => addr,
        ended = &mut done => {
            // The run ended before it was ready.
            return match ended {
                Ok(Err(e)) => Err(OlcrtcError::Probe(e)),
                _ => Err(OlcrtcError::StoppedBeforeReady),
            };
        }
        () = tokio::time::sleep_until(deadline) => {
            stop.cancel();
            shutdown(&mut done).await;
            return Err(OlcrtcError::ReadyTimeout);
        }
    };
    let out = match url {
        None => Ok(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)),
        Some(target) => match tokio::time::timeout_at(deadline, http_ping(addr, &target)).await {
            Ok(r) => r.map_err(OlcrtcError::Probe),
            Err(_) => Err(OlcrtcError::Probe("HTTP ping timed out".to_owned())),
        },
    };
    stop.cancel();
    shutdown(&mut done).await;
    out
}

/// `waitProbeDone`.
async fn shutdown(done: &mut tokio::task::JoinHandle<Result<(), String>>) {
    let _ = tokio::time::timeout(PROBE_SHUTDOWN_WAIT, done).await;
}

/// Where a ping goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

/// `normalizeHTTPPingURL`: empty is Google's 204; `http` or `https` only.
pub(crate) fn normalize_url(raw: &str) -> Result<Target, OlcrtcError> {
    let raw = if raw.is_empty() {
        DEFAULT_PING_URL
    } else {
        raw
    };
    let bad = |why: &str| OlcrtcError::Probe(format!("parse HTTP ping URL: {why}"));
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| bad(&format!("parse {raw:?}: invalid URI for request")))?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        other => {
            return Err(OlcrtcError::Probe(format!(
                "parse HTTP ping URL: invalid mobile runtime configuration: unsupported scheme {other:?}"
            )))
        }
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => match p.parse::<u16>() {
            Ok(p) => (h, p),
            Err(_) => return Err(bad(&format!("parse {raw:?}: invalid port"))),
        },
        _ => (authority, if tls { 443 } else { 80 }),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(bad(&format!("parse {raw:?}: no host")));
    }
    Ok(Target {
        tls,
        host: host.to_owned(),
        port,
        path: path.to_owned(),
    })
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// `httpPingThroughSocks`: a warm-up request, then the best of three.
async fn http_ping(socks: SocketAddr, target: &Target) -> Result<i64, String> {
    let mut conn: Option<Box<dyn Io>> = None;
    let _ = sample(&mut conn, socks, target).await;
    let mut best = 0i64;
    let mut last_err = None;
    for i in 0..SAMPLES {
        match sample(&mut conn, socks, target).await {
            Ok(ms) if ms > 0 && (best == 0 || ms < best) => best = ms,
            Ok(_) => {}
            Err(e) => last_err = Some(e),
        }
        if i + 1 < SAMPLES {
            tokio::time::sleep(SAMPLE_DELAY).await;
        }
    }
    if best > 0 {
        return Ok(best);
    }
    Err(last_err.unwrap_or_else(|| "HTTP ping timed out".to_owned()))
}

/// `singleHTTPPingRequest`: one GET on the kept connection (or a new one),
/// timed to its response head.
async fn sample(
    conn: &mut Option<Box<dyn Io>>,
    socks: SocketAddr,
    t: &Target,
) -> Result<i64, String> {
    let started = Instant::now();
    let r = tokio::time::timeout(SAMPLE_TIMEOUT, async {
        if conn.is_none() {
            *conn = Some(connect(socks, t).await?);
        }
        let io = conn.as_mut().expect("just set");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Olcbox-Android\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nAccept-Encoding: gzip\r\n\r\n",
            t.path,
            host_header(t)
        );
        io.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let head = read_head(io).await?;
        let elapsed = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        let keep = drain_body(io, &head).await?;
        Ok::<_, String>((elapsed, head.status, keep))
    })
    .await;
    match r {
        Ok(Ok((elapsed, status, keep))) => {
            if !keep {
                *conn = None;
            }
            if !(200..=308).contains(&status) {
                return Err(format!("unexpected HTTP status: {status}"));
            }
            Ok(elapsed)
        }
        Ok(Err(e)) => {
            *conn = None;
            Err(format!("perform HTTP ping request: {e}"))
        }
        Err(_) => {
            *conn = None;
            Err("perform HTTP ping request: context deadline exceeded".to_owned())
        }
    }
}

fn host_header(t: &Target) -> String {
    let host = if t.host.contains(':') {
        format!("[{}]", t.host)
    } else {
        t.host.clone()
    };
    if t.port == if t.tls { 443 } else { 80 } {
        host
    } else {
        format!("{host}:{}", t.port)
    }
}

/// SOCKS5 CONNECT to the target by name (as Go's proxy dialer asks), then
/// TLS for `https`.
async fn connect(socks: SocketAddr, t: &Target) -> Result<Box<dyn Io>, String> {
    let mut s = tokio::net::TcpStream::connect(socks)
        .await
        .map_err(|e| format!("socks connect tcp {socks}: {e}"))?;
    s.write_all(&[5, 1, 0]).await.map_err(|e| e.to_string())?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).await.map_err(|e| e.to_string())?;
    if hello != [5, 0] {
        return Err("socks connect: method not accepted".to_owned());
    }
    let name = t.host.as_bytes();
    let len = u8::try_from(name.len()).map_err(|_| "socks connect: host too long".to_owned())?;
    let mut req = vec![5, 1, 0, 3, len];
    req.extend_from_slice(name);
    req.extend_from_slice(&t.port.to_be_bytes());
    s.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).await.map_err(|e| e.to_string())?;
    if rep[1] != 0 {
        return Err(format!("socks connect: reply {}", rep[1]));
    }
    let skip = match rep[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            usize::from(l[0]) + 2
        }
        _ => return Err("socks connect: bad reply".to_owned()),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
    if !t.tls {
        return Ok(Box::new(s));
    }
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name =
        rustls::pki_types::ServerName::try_from(t.host.clone()).map_err(|e| e.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, s)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Box::new(tls))
}

struct Head {
    status: u16,
    length: Option<usize>,
    chunked: bool,
    close: bool,
    /// Body bytes read with the head.
    extra: Vec<u8>,
}

async fn read_head(io: &mut Box<dyn Io>) -> Result<Head, String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err("response head too large".to_owned());
        }
        let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF".to_owned());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let text = String::from_utf8_lossy(&buf[..end]);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| "malformed HTTP response".to_owned())?;
    let mut head = Head {
        status,
        length: None,
        chunked: false,
        close: false,
        extra: buf[end + 4..].to_vec(),
    };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            head.length = v.parse().ok();
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = v.to_ascii_lowercase().contains("chunked");
        } else if k.eq_ignore_ascii_case("connection") {
            head.close = v.eq_ignore_ascii_case("close");
        }
    }
    Ok(head)
}

/// Reads the body away (`io.Copy(io.Discard, resp.Body)`); whether the
/// connection can carry the next request.
async fn drain_body(io: &mut Box<dyn Io>, head: &Head) -> Result<bool, String> {
    if head.status == 204 || head.status == 304 || (100..200).contains(&head.status) {
        return Ok(!head.close);
    }
    let mut have = head.extra.clone();
    let mut chunk = [0u8; 4096];
    if let Some(len) = head.length {
        if len > MAX_BODY {
            return Ok(false);
        }
        while have.len() < len {
            let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(false);
            }
            have.extend_from_slice(&chunk[..n]);
        }
        return Ok(!head.close);
    }
    if head.chunked {
        // Enough of chunked to find its end: the zero chunk and the blank line.
        loop {
            if have.windows(5).any(|w| w == b"0\r\n\r\n") {
                return Ok(!head.close);
            }
            if have.len() > MAX_BODY {
                return Ok(false);
            }
            let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(false);
            }
            have.extend_from_slice(&chunk[..n]);
        }
    }
    // No length: the body runs to the close.
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_urls_are_read_as_go_reads_them() {
        assert_eq!(
            normalize_url("").unwrap(),
            Target {
                tls: true,
                host: "www.google.com".into(),
                port: 443,
                path: "/generate_204".into()
            }
        );
        assert_eq!(
            normalize_url("http://127.0.0.1:8080/x?y=1").unwrap(),
            Target {
                tls: false,
                host: "127.0.0.1".into(),
                port: 8080,
                path: "/x?y=1".into()
            }
        );
        assert_eq!(normalize_url("http://[::1]:81").unwrap().host, "::1");
        assert!(normalize_url("ftp://x/")
            .unwrap_err()
            .to_string()
            .contains("unsupported scheme \"ftp\""));
        assert!(normalize_url("nothing").is_err());
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Joining a room (`J/j.go:JoinMUC`, `J/internal/xmpp/conn.go:Dial`, and the
//! engine's `configjs.go`): config.js discovery with its attempts and
//! budget, the WebSocket to the XMPP domain, the login, the focus, the
//! services, the room; and once more on docker-jitsi-meet's defaults when the
//! server refused the guessed domain.
//!
//! When the WebSocket does not dial and config.js names a BOSH URL, the
//! login goes over BOSH ([`crate::xmpp::bosh`]), as the library's does
//! (`conn.go:164-171`).

use std::time::Duration;

use olc_net::fetch::fetch;
use olc_net::http::HttpRequest;
use olc_net::stream::{parse_url, BoxStream};
use olc_net::ws::{self, Message};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::configjs::{
    browser_headers, library_domain, media_type, should_retry_with_fallback, whole_lines,
    JitsiConfig, StatusError, ATTEMPTS, ATTEMPT_TIMEOUT, BROWSER_USER_AGENT, BUDGET,
    FALLBACK_CONFIG, FALLBACK_XMPP_DOMAIN, GRACE, MAX_BODY, PAUSE,
};
use crate::ice::{convert_ice, IceServer};
use crate::xmpp::bosh;
use crate::xmpp::conn::{BoxFut, Conn, ConnConfig, ConnError, FocusInfo, Incoming, Rx, Tx};

/// The WebSocket's read limit (`SetReadLimit(1 << 20)`).
pub const WS_READ_LIMIT: usize = 1 << 20;
/// The WebSocket's handshake, the login's steps and the focus's wait each
/// get what is left of the join's budget; this is the handshake's own cap.
pub const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// The most of config.js held while it is read: more than the window the
/// library looks at, so a larger file is cut and not refused.
pub const FETCH_MAX: usize = 1 << 20;

/// The clock of discovery; tests shorten it (`configJSLimits`).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Before the second attempt, twice that before the third.
    pub pause: Duration,
    /// One attempt, request to end of body.
    pub attempt: Duration,
    /// The rest of the body once the domain is in (not used: see
    /// [`fetch_config`]).
    pub grace: Duration,
    /// Attempts and pauses together.
    pub budget: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pause: PAUSE,
            attempt: ATTEMPT_TIMEOUT,
            grace: GRACE,
            budget: BUDGET,
        }
    }
}

/// One join's settings.
#[derive(Debug, Clone)]
pub struct JoinConfig {
    /// The web host.
    pub host: String,
    /// The room.
    pub room: String,
    /// The nick the presence carries.
    pub nick: String,
    /// The whole join's budget.
    pub budget: Duration,
    /// Where config.js is asked for, instead of `https://<host>`; for the
    /// tests' fakes (plan D13).
    pub config_base: Option<String>,
    /// The WebSocket's URL without the room, instead of the config's or
    /// `wss://<host>/xmpp-websocket`; for the tests' fakes.
    pub ws_url: Option<String>,
    /// The discovery's clock.
    pub limits: Limits,
    /// Offer permessage-deflate (as Go does).
    pub deflate: bool,
}

impl JoinConfig {
    /// A join with Go's defaults.
    #[must_use]
    pub fn new(host: &str, room: &str, nick: &str, budget: Duration) -> Self {
        Self {
            host: host.to_owned(),
            room: room.to_owned(),
            nick: nick.to_owned(),
            budget,
            config_base: None,
            ws_url: None,
            limits: Limits::default(),
            deflate: true,
        }
    }
}

/// What discovery found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    /// The domain the library took from the config.js it was handed; empty
    /// when discovery failed or the file named none.
    pub found: String,
    /// Why discovery failed; empty when it did not.
    pub failure: String,
}

/// A room joined.
pub struct Joined {
    /// The connection.
    pub conn: Conn,
    /// What the read loop hands the session.
    pub incoming: mpsc::Receiver<Incoming>,
    /// The ICE servers the focus advertised.
    pub ice: Vec<IceServer>,
    /// The focus's answer.
    pub focus: FocusInfo,
    /// How the XMPP domain was found.
    pub discovery: Discovery,
    /// The join fell back to docker-jitsi-meet's defaults.
    pub fell_back: bool,
}

impl std::fmt::Debug for Joined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Joined")
            .field("fell_back", &self.fell_back)
            .field("discovery", &self.discovery)
            .finish_non_exhaustive()
    }
}

/// A join that did not happen. The text is the engine's; it holds no room
/// name, and no stanza beyond what the server's own refusal quotes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JoinError(pub String);

/// The WebSocket as a transport.
struct WsTx(ws::Writer<BoxStream>);
struct WsRx(ws::Reader<BoxStream>);

impl Tx for WsTx {
    fn send<'a>(&'a self, text: &'a str) -> BoxFut<'a, Result<(), ConnError>> {
        Box::pin(async move {
            self.0
                .send_text(text)
                .await
                .map_err(|e| ConnError::Transport(e.to_string()))
        })
    }

    fn close(&self) -> BoxFut<'_, ()> {
        Box::pin(async move { self.0.close().await })
    }
}

impl Rx for WsRx {
    fn recv(&mut self) -> BoxFut<'_, Result<String, ConnError>> {
        Box::pin(async move {
            match self.0.next().await {
                Ok(Message::Text(t)) => Ok(t),
                Ok(Message::Binary(b)) => Ok(String::from_utf8_lossy(&b).into_owned()),
                Err(e) => Err(ConnError::Transport(e.to_string())),
            }
        })
    }
}

/// Asks for config.js as the engine does: up to three times within the
/// budget, one and then two pauses apart, the first answer that declares a
/// domain by the library's rules wins, and an answer the same request would
/// get again ends it at once. Returns the body the library is handed (its
/// first 64 KiB, cut at a line end when the window is full) and its domain.
///
/// Not ported: the grace for a body that stalls after the domain (the HTTP
/// client here returns a body whole or not at all, so such a stall costs the
/// attempt's timeout).
///
/// # Errors
/// Why the last attempt failed, in Go's words.
pub async fn fetch_config(
    base: &str,
    host: &str,
    limits: Limits,
) -> Result<(String, String), String> {
    let deadline = Instant::now() + limits.budget;
    let url = format!("{base}/config.js");
    let target = parse_url(&url).map_err(|e| format!("get config.js: {e}"))?;
    let mut attempt = 1u32;
    loop {
        let err = match try_once(
            &target,
            host,
            limits
                .attempt
                .min(deadline.saturating_duration_since(Instant::now())),
        )
        .await
        {
            Ok(ok) => return Ok(ok),
            Err(e) => e,
        };
        olc_net::debug!(
            "jitsi: config.js attempt {attempt}/{ATTEMPTS}: {}",
            err.text
        );
        if attempt == ATTEMPTS || Instant::now() >= deadline || err.is_final {
            return Err(err.text);
        }
        let wait = limits.pause * attempt;
        if Instant::now() + wait >= deadline {
            tokio::time::sleep_until(deadline).await;
            return Err(format!(
                "wait for config.js retry: context deadline exceeded, after {}",
                err.text
            ));
        }
        tokio::time::sleep(wait).await;
        attempt += 1;
    }
}

struct AttemptError {
    text: String,
    is_final: bool,
}

async fn try_once(
    target: &olc_net::stream::Target,
    host: &str,
    timeout: Duration,
) -> Result<(String, String), AttemptError> {
    let scheme = if target.tls { "https" } else { "http" };
    let owned = browser_headers(scheme, &target.authority);
    let _ = host;
    let headers: Vec<(&str, &str)> = owned.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let req = HttpRequest {
        method: "GET",
        host: &target.authority,
        path: &target.path,
        headers: &headers,
        body: &[],
        max_body: FETCH_MAX,
        timeout,
    };
    let resp = fetch(target, &req).await.map_err(|e| AttemptError {
        text: format!("get config.js: {e}"),
        is_final: false,
    })?;
    if resp.status != 200 {
        let e = StatusError {
            code: resp.status,
            media_type: media_type(resp.header("content-type")),
        };
        return Err(AttemptError {
            is_final: e.is_final(),
            text: e.to_string(),
        });
    }
    let mut body = resp.body.as_slice();
    let read = body.len();
    if body.len() > MAX_BODY {
        body = &body[..MAX_BODY];
    }
    let body = if body.len() == MAX_BODY {
        whole_lines(body)
    } else {
        body
    };
    let domain = library_domain(body);
    if domain.is_empty() {
        return Err(AttemptError {
            text: format!(
                "no hosts.domain in {} bytes of {}",
                read.min(MAX_BODY),
                media_type(resp.header("content-type"))
            ),
            is_final: false,
        });
    }
    Ok((String::from_utf8_lossy(body).into_owned(), domain))
}

/// The library's `Dial`, then the focus, the services and the room.
async fn join_once(cfg: &JoinConfig, fallback: bool) -> (Result<Joined, JoinError>, Discovery) {
    let mut disc = Discovery::default();
    let body = if fallback {
        FALLBACK_CONFIG.to_owned()
    } else {
        let base = cfg
            .config_base
            .clone()
            .unwrap_or_else(|| format!("https://{}", cfg.host));
        match fetch_config(&base, &cfg.host, cfg.limits).await {
            Ok((body, domain)) => {
                disc.found = domain;
                body
            }
            Err(e) => {
                disc.failure = e;
                String::new()
            }
        }
    };
    let jc = JitsiConfig::from_body(&cfg.host, &body);
    let ws_url = match &cfg.ws_url {
        Some(u) => {
            let sep = if u.contains('?') { '&' } else { '?' };
            format!("{u}{sep}room={}", cfg.room)
        }
        None => jc.websocket_url(&cfg.host, &cfg.room),
    };
    let steps = async {
        let cc = ConnConfig {
            host: cfg.host.clone(),
            room: cfg.room.clone(),
            xmpp_domain: jc.xmpp_domain.clone(),
            muc_domain: jc.muc_domain.clone(),
        };
        let login = match dial_ws(&ws_url, &cfg.host, cfg.deflate).await {
            Ok((tx, rx)) => Conn::login(std::sync::Arc::new(tx), rx, cc, cfg.budget).await,
            Err(e) if jc.bosh.is_empty() => {
                return Err(JoinError(format!(
                    "xmpp dial: failed to WebSocket dial: {e}"
                )));
            }
            // The library's order: BOSH when the WebSocket did not dial and
            // config.js names one.
            Err(e) => {
                olc_net::debug!("jitsi: the WebSocket did not dial ({e}); BOSH instead");
                login_bosh(&jc.bosh, cc, cfg.budget).await
            }
        };
        let (conn, incoming) = login.map_err(|e| JoinError(format!("xmpp dial: {e}")))?;
        let focus = match conn.allocate_focus(cfg.budget).await {
            Ok(f) => f,
            Err(e) => {
                conn.close().await;
                return Err(JoinError(format!("allocate focus: {e}")));
            }
        };
        let services = match conn.discover_services(cfg.budget).await {
            Ok(s) => s,
            Err(e) => {
                conn.close().await;
                return Err(JoinError(format!("discover services: {e}")));
            }
        };
        if let Err(e) = conn.join_muc(&cfg.nick, cfg.budget).await {
            conn.close().await;
            return Err(JoinError(format!("join muc: {e}")));
        }
        Ok((conn, incoming, focus, services))
    };
    let result = match tokio::time::timeout(cfg.budget, steps).await {
        Ok(Ok((conn, incoming, focus, services))) => Ok(Joined {
            conn,
            incoming,
            ice: convert_ice(&services),
            focus,
            discovery: disc.clone(),
            fell_back: fallback,
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(JoinError("join muc: context deadline exceeded".into())),
    };
    (result, disc)
}

/// `dialBOSH`: the session at the URL config.js names, and the login over
/// it. A login that fails ends the session it opened.
async fn login_bosh(
    url: &str,
    cc: ConnConfig,
    budget: Duration,
) -> Result<(Conn, mpsc::Receiver<Incoming>), ConnError> {
    let post = bosh::Http::new(url).map_err(|e| ConnError::Transport(format!("bosh init: {e}")))?;
    let (tx, rx) = bosh::open(std::sync::Arc::new(post), &cc.xmpp_domain).await?;
    let tx = std::sync::Arc::new(tx);
    match Conn::login(tx.clone(), rx, cc, budget).await {
        Ok(ok) => Ok(ok),
        Err(e) => {
            tx.close().await;
            Err(e)
        }
    }
}

async fn dial_ws(url: &str, host: &str, deflate: bool) -> Result<(WsTx, WsRx), String> {
    let target = parse_url(url).map_err(|e| e.to_string())?;
    let origin = format!("https://{host}");
    let mut headers: Vec<(&str, &str)> = vec![
        ("User-Agent", BROWSER_USER_AGENT),
        ("Origin", &origin),
        ("Accept", "*/*"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-Fetch-Mode", "websocket"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-WebSocket-Protocol", "xmpp"),
    ];
    if deflate {
        headers.push(("Sec-WebSocket-Extensions", "permessage-deflate"));
    }
    let fut = async {
        let stream = olc_net::stream::dial(&target)
            .await
            .map_err(|e| e.to_string())?;
        let req = ws::Request {
            host: &target.authority,
            path: &target.path,
            headers: &headers,
            read_limit: WS_READ_LIMIT,
            timeout: WS_HANDSHAKE_TIMEOUT,
        };
        ws::handshake(stream, &req).await.map_err(|e| e.to_string())
    };
    let (r, w) = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| "i/o timeout".to_owned())??;
    Ok((WsTx(w), WsRx(r)))
}

/// Joins the room as the engine does (`joinMUC`): with discovery, and once
/// more on docker-jitsi-meet's defaults when the server refused the XMPP
/// domain the library guessed because config.js could not be read.
///
/// # Errors
/// The engine's text: `jitsi join muc: <cause>` and, when discovery failed,
/// ` (config.js unavailable: <why>)`.
pub async fn join_muc(cfg: &JoinConfig) -> Result<Joined, JoinError> {
    let (first, disc) = join_once(cfg, false).await;
    let failed = !disc.failure.is_empty();
    let retry = should_retry_with_fallback(first.as_ref().err().map(|e| e.0.as_str()), failed);
    let result = if retry {
        olc_net::info!(
            "jitsi: server refused XMPP domain {}, config.js unavailable ({}); retrying with {FALLBACK_XMPP_DOMAIN}",
            cfg.host,
            disc.failure
        );
        join_once(cfg, true).await.0
    } else {
        first
    };
    match result {
        Ok(mut j) => {
            j.discovery = disc;
            Ok(j)
        }
        Err(e) if failed => Err(JoinError(format!(
            "jitsi join muc: {e} (config.js unavailable: {})",
            disc.failure
        ))),
        Err(e) => Err(JoinError(format!("jitsi join muc: {e}"))),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::stanza;
    use crate::xmpp::bosh::{Post, REPLY_LIMIT};
    use crate::xmpp::testing::BoshServer;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// What a config.js request is answered with: status, type, body.
    pub(crate) type Reply = (u16, &'static str, String);

    /// What a fake says after a client has joined the room.
    pub(crate) type AfterJoin = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

    /// What a fake does besides the script.
    #[derive(Clone)]
    pub(crate) struct Opts {
        /// A Jicofo that sends its offer once a client has joined.
        pub after_join: Option<AfterJoin>,
        /// The services answer names a TURN server.
        pub turn: bool,
        /// Accept permessage-deflate when it is offered.
        pub deflate: bool,
        /// The upgrade is answered 403: no WebSocket here.
        pub refuse_ws: bool,
        /// What serves `/http-bind`; without one it is not there.
        pub bosh: Option<BoshServer>,
        /// `/http-bind` answers every request with this status and body.
        pub bosh_status: Option<(u16, &'static str)>,
    }

    impl Default for Opts {
        fn default() -> Self {
            Self {
                after_join: None,
                turn: true,
                deflate: false,
                refuse_ws: false,
                bosh: None,
                bosh_status: None,
            }
        }
    }

    #[derive(Default)]
    pub(crate) struct Seen {
        /// The request heads of config.js, in order.
        pub config: Vec<String>,
        /// The upgrade heads.
        pub upgrades: Vec<String>,
        /// What the clients said on the sockets, per connection.
        pub said: Vec<Vec<String>>,
        /// Compressed frames the clients sent.
        pub compressed: usize,
        /// The request heads of `/http-bind`, in order.
        pub posts: Vec<String>,
    }

    pub(crate) struct Fake {
        pub addr: SocketAddr,
        pub seen: Arc<Mutex<Seen>>,
    }

    /// An HTTP and WebSocket server in one: `/config.js` answered from
    /// `script` (a 404 once it runs out; `ADDR` in a body is the fake's own
    /// address), `/xmpp-websocket` as a Prosody and Jicofo that serve the
    /// XMPP domain `serves`, and `/http-bind` when [`Opts::bosh`] serves it.
    pub(crate) async fn fake(script: Vec<Reply>, serves: &'static str) -> Fake {
        fake_with(script, serves, Opts::default()).await
    }

    pub(crate) async fn fake_with(script: Vec<Reply>, serves: &'static str, opts: Opts) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let s2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(
                    sock,
                    addr,
                    script.clone(),
                    s2.clone(),
                    serves,
                    opts.clone(),
                ));
            }
        });
        Fake { addr, seen }
    }

    async fn read_head(sock: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if sock.read_exact(&mut b).await.is_err() {
                break;
            }
            buf.push(b[0]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn serve(
        mut sock: TcpStream,
        addr: SocketAddr,
        script: Arc<Mutex<VecDeque<Reply>>>,
        seen: Arc<Mutex<Seen>>,
        serves: &'static str,
        opts: Opts,
    ) {
        let head = read_head(&mut sock).await;
        if head.starts_with("GET /config.js") {
            seen.lock().unwrap().config.push(head);
            let (status, ctype, body) = script.lock().unwrap().pop_front().unwrap_or((
                404,
                "text/html",
                "not found".into(),
            ));
            let body = body.replace("ADDR", &addr.to_string());
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            return;
        }
        if head.starts_with("POST /http-bind") {
            let Some(bosh) = opts.bosh.clone() else {
                return;
            };
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            if sock.read_exact(&mut body).await.is_err() {
                return;
            }
            seen.lock().unwrap().posts.push(head);
            let body = String::from_utf8_lossy(&body).into_owned();
            let (status, answer) = match opts.bosh_status {
                Some((status, answer)) => (status, answer.to_owned()),
                None => match bosh.post(body, Duration::from_secs(3600)).await {
                    Ok(answer) => (200, answer),
                    Err(_) => return,
                },
            };
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(answer.as_bytes()).await;
            return;
        }
        if !head.starts_with("GET /xmpp-websocket") {
            return;
        }
        if opts.refuse_ws {
            seen.lock().unwrap().upgrades.push(head);
            let _ = sock
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        }
        let key = head
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .to_owned();
        let index = {
            let mut s = seen.lock().unwrap();
            s.upgrades.push(head.clone());
            s.said.push(Vec::new());
            s.said.len() - 1
        };
        let accept = {
            use base64::Engine as _;
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(key.as_bytes());
            h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            base64::engine::general_purpose::STANDARD.encode(h.finalize())
        };
        let ext = if opts.deflate && head.contains("permessage-deflate") {
            "Sec-WebSocket-Extensions: permessage-deflate\r\n"
        } else {
            ""
        };
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{ext}\r\n"
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
        let opts = Opts {
            deflate: opts.deflate && head.contains("permessage-deflate"),
            ..opts
        };
        xmpp_server(sock, seen, index, serves, opts).await;
    }

    /// A server-side WebSocket: frames in the clear, or permessage-deflate
    /// with context takeover when the client offered it and the fake took it.
    struct Wsc {
        sock: TcpStream,
        deflate: Option<(flate2::Compress, flate2::Decompress)>,
        compressed_seen: bool,
    }

    async fn say(ws: &mut Wsc, text: &str) {
        let mut payload = text.as_bytes().to_vec();
        let mut first = 0x81u8;
        if let Some((c, _)) = ws.deflate.as_mut() {
            let mut out = Vec::with_capacity(payload.len() + 64);
            c.compress_vec(&payload, &mut out, flate2::FlushCompress::Sync)
                .unwrap();
            assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
            out.truncate(out.len() - 4);
            payload = out;
            first |= 0x40;
        }
        let mut f = vec![first];
        if payload.len() < 126 {
            f.push(payload.len() as u8);
        } else {
            f.push(126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(&payload);
        ws.sock.write_all(&f).await.unwrap();
    }

    async fn hear(ws: &mut Wsc) -> Option<String> {
        let mut h = [0u8; 2];
        ws.sock.read_exact(&mut h).await.ok()?;
        let op = h[0] & 0x0f;
        let mut len = usize::from(h[1] & 0x7f);
        if len == 126 {
            let mut b = [0u8; 2];
            ws.sock.read_exact(&mut b).await.ok()?;
            len = usize::from(u16::from_be_bytes(b));
        }
        let mut mask = [0u8; 4];
        ws.sock.read_exact(&mut mask).await.ok()?;
        let mut p = vec![0u8; len];
        ws.sock.read_exact(&mut p).await.ok()?;
        for (i, x) in p.iter_mut().enumerate() {
            *x ^= mask[i & 3];
        }
        if op == 8 {
            return None;
        }
        if h[0] & 0x40 != 0 {
            let (_, d) = ws.deflate.as_mut().expect("RSV1 without the extension");
            p.extend_from_slice(&[0, 0, 0xff, 0xff]);
            let mut out = Vec::with_capacity(1 << 16);
            d.decompress_vec(&p, &mut out, flate2::FlushDecompress::Sync)
                .unwrap();
            p = out;
            ws.compressed_seen = true;
        }
        Some(String::from_utf8_lossy(&p).into_owned())
    }

    /// Prosody and Jicofo for one connection: the login, the focus, the
    /// services, the room's echo. A domain it does not serve is `host-unknown`.
    async fn xmpp_server(
        sock: TcpStream,
        seen: Arc<Mutex<Seen>>,
        index: usize,
        serves: &'static str,
        opts: Opts,
    ) {
        let mut ws = Wsc {
            sock,
            deflate: opts.deflate.then(|| {
                (
                    flate2::Compress::new(flate2::Compression::default(), false),
                    flate2::Decompress::new(false),
                )
            }),
            compressed_seen: false,
        };
        let record = |t: &str| seen.lock().unwrap().said[index].push(t.to_owned());
        let Some(open) = hear(&mut ws).await else {
            return;
        };
        record(&open);
        if !open.contains(&format!("to=\"{serves}\"")) {
            say(&mut ws, "<stream:error xmlns:stream='http://etherx.jabber.org/streams'><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text>This server does not serve that</text></stream:error>").await;
            return;
        }
        say(
            &mut ws,
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='x' version='1.0'/>",
        )
        .await;
        say(&mut ws, "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features>").await;
        while let Some(t) = hear(&mut ws).await {
            if ws.compressed_seen {
                seen.lock().unwrap().compressed += 1;
                ws.compressed_seen = false;
            }
            record(&t);
            if t.starts_with("<auth ") {
                say(
                    &mut ws,
                    "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
                )
                .await;
            } else if t.starts_with("<open ") {
                say(
                    &mut ws,
                    "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='x' version='1.0'/>",
                )
                .await;
                say(&mut ws, "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>").await;
            } else if t.contains("bind_1") {
                say(&mut ws, &format!("<iq type='result' id='bind_1' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>0123456789abcdef@{serves}/res</jid></bind></iq>")).await;
            } else if t.contains("sess_1") {
                say(
                    &mut ws,
                    "<iq type='result' id='sess_1' xmlns='jabber:client'/>",
                )
                .await;
            } else if t.starts_with("<enable ") {
                say(&mut ws, "<enabled xmlns='urn:xmpp:sm:3' id='1'/>").await;
            } else if t.contains("focus_1") {
                say(&mut ws, "<iq id='focus_1' type='result' xmlns='jabber:client'><conference xmlns='http://jitsi.org/protocol/focus' ready='true'/></iq>").await;
            } else if t.contains("disco_1") {
                let turn = if opts.turn {
                    "<service type='turn' host='turn.example' port='3478' transport='udp' username='u' password='p'/>"
                } else {
                    ""
                };
                say(&mut ws, &format!("<iq id='disco_1' type='result' xmlns='jabber:client'><services xmlns='urn:xmpp:extdisco:2'>{turn}<service type='stun' host='stun.example'/></services></iq>")).await;
            } else if t.starts_with("<presence ") {
                let to = t
                    .split("to=\"")
                    .nth(1)
                    .and_then(|r| r.split('"').next())
                    .unwrap_or("");
                if t.contains("type=\"unavailable\"") {
                    say(&mut ws, &format!("<presence from='{to}' type='unavailable' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'><status code='110'/></x></presence>")).await;
                    continue;
                }
                say(&mut ws, &format!("<presence from='{to}' xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc#user'><status code='110'/></x></presence>")).await;
                if let Some(h) = &opts.after_join {
                    for stanza in h() {
                        say(&mut ws, &stanza).await;
                    }
                }
            }
        }
    }

    const DOCKER: &str = "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nconfig.hosts.muc = 'muc.meet.jitsi';\n";

    fn quick(fake: &Fake, host: &str) -> JoinConfig {
        let mut c = JoinConfig::new(host, "secret-room", "olcrtc", Duration::from_secs(20));
        c.config_base = Some(format!("http://{}", fake.addr));
        c.ws_url = Some(format!("ws://{}/xmpp-websocket", fake.addr));
        c.limits = Limits {
            pause: Duration::from_millis(20),
            attempt: Duration::from_secs(5),
            grace: Duration::from_secs(1),
            budget: Duration::from_secs(10),
        };
        c
    }

    #[tokio::test]
    async fn a_join_discovers_the_domain_dials_and_joins() {
        let f = fake(
            vec![(200, "application/javascript", DOCKER.into())],
            "meet.jitsi",
        )
        .await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert!(!j.fell_back);
        assert_eq!(
            j.discovery,
            Discovery {
                found: "meet.jitsi".into(),
                failure: String::new()
            }
        );
        assert_eq!(j.conn.nick(), "01234567");
        assert!(j.focus.ready);
        // The turn service is kept (with its credentials), the stun one too.
        assert_eq!(j.ice.len(), 2);
        assert_eq!(j.ice[0].urls, ["turn:turn.example:3478?transport=udp"]);
        // The room's disco goes out after the join returns.
        for _ in 0..100 {
            if f.seen.lock().unwrap().said[0].len() >= 10 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let s = f.seen.lock().unwrap();
        // What the client said, as transcript: Go's text for each step.
        let said = &s.said[0];
        assert_eq!(said[0], stanza::open("meet.jitsi"));
        assert_eq!(said[1], stanza::AUTH_ANONYMOUS);
        assert_eq!(said[2], stanza::open("meet.jitsi"));
        assert_eq!(said[3], stanza::BIND);
        assert_eq!(said[4], stanza::SESSION);
        assert_eq!(said[5], stanza::ENABLE_SM);
        assert_eq!(
            said[6],
            stanza::focus("meet.jitsi", "secret-room@muc.meet.jitsi", "01234567")
        );
        assert_eq!(said[7], stanza::extdisco("meet.jitsi"));
        assert_eq!(
            said[8],
            stanza::join_presence("secret-room@muc.meet.jitsi/01234567", "olcrtc", "01234567")
        );
        assert!(said[9].contains("disco#info"));
        // The headers of the config.js request and of the upgrade.
        let c = &s.config[0];
        assert!(c.contains("User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0\r\n"), "{c}");
        assert!(
            c.contains("Accept: */*\r\n") && c.contains("Accept-Language: en-US,en;q=0.9\r\n"),
            "{c}"
        );
        assert!(
            c.contains(&format!("Referer: http://{}/\r\n", f.addr)),
            "{c}"
        );
        let u = &s.upgrades[0];
        assert!(
            u.starts_with("GET /xmpp-websocket?room=secret-room HTTP/1.1\r\n"),
            "{u}"
        );
        for h in [
            "Origin: https://web.example\r\n",
            "Sec-WebSocket-Protocol: xmpp\r\n",
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "Sec-Fetch-Dest: empty\r\n",
            "Sec-Fetch-Mode: websocket\r\n",
            "Sec-Fetch-Site: same-origin\r\n",
            "Accept: */*\r\n",
            "Pragma: no-cache\r\n",
            "Cache-Control: no-cache\r\n",
            "Accept-Language: en-US,en;q=0.9\r\n",
        ] {
            assert!(u.contains(h), "{h} missing in {u}");
        }
    }

    /// J12's `F`: what the Go engine at the pin says to a room and asks of
    /// it, recorded by the Go fake (`jitsi/transcript.json`,
    /// `jitsi/handshake.json`), is what this client says and asks. The login
    /// and the room disco are byte for byte; the headers are Go's, less what
    /// the HTTP client of Go adds on its own (`Accept-Encoding`) and what
    /// the test's plain-text origin changes (the scheme of the `Referer`).
    #[tokio::test]
    async fn the_join_says_and_asks_what_go_says_and_asks() {
        let t = olc_interop::load("jitsi/transcript.json");
        let h = olc_interop::load("jitsi/handshake.json");
        let f = fake(
            vec![(200, "application/javascript", DOCKER.into())],
            "meet.jitsi",
        )
        .await;
        let _j = join_muc(&quick(&f, "web.example")).await.unwrap();
        for _ in 0..100 {
            if f.seen.lock().unwrap().said[0].len() >= 10 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let s = f.seen.lock().unwrap();
        let login = t["login"].as_array().unwrap();
        assert_eq!(login.len(), 10);
        assert_eq!(t["room"], "secret-room");
        assert_eq!(t["nick"], "01234567");
        assert_eq!(t["name"], "olcrtc");
        for (i, want) in login.iter().enumerate() {
            assert_eq!(s.said[0][i], want.as_str().unwrap(), "stanza {i}");
        }
        // The headers of a request: Go's, as sent, in name and value.
        let check = |what: &str, head: &str, want: &serde_json::Value, skip: &[&str]| {
            let lines: Vec<&str> = head.split("\r\n").collect();
            for (name, values) in want["header"].as_object().unwrap() {
                if skip.contains(&name.as_str()) {
                    continue;
                }
                for v in values.as_array().unwrap() {
                    let v = v
                        .as_str()
                        .unwrap()
                        .replace("https://HOST/", &format!("http://{}/", f.addr))
                        .replace("https://HOST", "https://web.example");
                    assert!(
                        lines.iter().any(|l| l.to_ascii_lowercase()
                            == format!(
                                "{}: {}",
                                name.to_ascii_lowercase(),
                                v.to_ascii_lowercase()
                            )),
                        "{what}: Go sends {name}: {v}, this client sends:\n{head}"
                    );
                }
            }
            assert!(
                head.starts_with(&format!("GET {} HTTP/1.1", want["path"].as_str().unwrap())),
                "{what}: {head}"
            );
        };
        check(
            "config.js",
            &s.config[0],
            &h["config_js"],
            &["Accept-Encoding"],
        );
        check(
            "upgrade",
            &s.upgrades[0],
            &h["upgrade"],
            &["Accept-Encoding", "Sec-Websocket-Extensions"],
        );
    }

    /// config.js as docker-jitsi-meet's, and a BOSH URL: the fake's own.
    const WITH_BOSH: &str = "var config = {};\nconfig.hosts = {};\nconfig.hosts.domain = 'meet.jitsi';\nconfig.hosts.muc = 'muc.meet.jitsi';\nconfig.bosh = 'http://ADDR/http-bind';\n";

    async fn bosh_fake(config: &str, opts: Opts) -> (Fake, BoshServer) {
        let bosh = BoshServer::new();
        let f = fake_with(
            vec![(200, "application/javascript", config.into())],
            "meet.jitsi",
            Opts {
                bosh: Some(bosh.clone()),
                ..opts
            },
        )
        .await;
        (f, bosh)
    }

    fn no_ws() -> Opts {
        Opts {
            refuse_ws: true,
            ..Opts::default()
        }
    }

    /// The library's order (`conn.go:148-171`): the WebSocket, and BOSH when
    /// that does not dial and config.js names one. The join's requests are
    /// the Go client's (`jitsi/bosh.json`), posted to the URL as config.js
    /// gives it (no room in it), with Go's Content-Type; the User-Agent is
    /// the one this client names on config.js and on the WebSocket, where Go
    /// leaves its HTTP library's own.
    #[tokio::test]
    async fn a_websocket_that_does_not_dial_falls_to_the_bosh_config_js_names() {
        let v = olc_interop::load("jitsi/bosh.json");
        let (f, bosh) = bosh_fake(WITH_BOSH, no_ws()).await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(j.conn.nick(), "fedcba98");
        assert!(!j.fell_back);
        j.conn.leave_muc_wait(Duration::from_secs(5)).await.unwrap();
        j.conn.close().await;
        assert!(bosh.state().terminated);

        let poll = v["poll"].as_str().unwrap();
        let (bodies, consecutive) = bosh.normalised();
        assert!(consecutive, "the request ids go up by one");
        let ours: Vec<&str> = bodies
            .iter()
            .map(String::as_str)
            .filter(|b| {
                *b != poll
                    && !b.contains("type=\"unavailable\"")
                    && !b.contains("type=\"terminate\"")
            })
            .collect();
        let want: Vec<&str> = v["sequence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(ours, want);
        assert!(bosh.state().max_open <= 2, "{}", bosh.state().max_open);

        let s = f.seen.lock().unwrap();
        assert_eq!(s.upgrades.len(), 1, "the WebSocket was tried, once");
        assert!(s.said.is_empty());
        assert_eq!(s.posts.len(), bodies.len());
        assert_eq!(v["path"], "/http-bind");
        assert_eq!(v["header"]["User-Agent"][0], "Go-http-client/1.1");
        let want_type = v["header"]["Content-Type"][0].as_str().unwrap();
        for head in &s.posts {
            let mut lines = head.trim_end().split("\r\n");
            assert_eq!(lines.next(), Some("POST /http-bind HTTP/1.1"), "{head}");
            let mut names: Vec<String> = Vec::new();
            for l in lines {
                let (n, said) = l.split_once(": ").unwrap();
                match n.to_ascii_lowercase().as_str() {
                    "content-type" => assert_eq!(said, want_type),
                    "user-agent" => assert_eq!(said, BROWSER_USER_AGENT),
                    "host" => assert_eq!(said, f.addr.to_string()),
                    _ => {}
                }
                names.push(n.to_ascii_lowercase());
            }
            names.sort();
            assert_eq!(
                names,
                [
                    "connection",
                    "content-length",
                    "content-type",
                    "host",
                    "user-agent"
                ],
                "{head}"
            );
        }
    }

    /// Without a BOSH URL in config.js a refused WebSocket is the join's
    /// failure, in the words it had, and nothing is posted.
    #[tokio::test]
    async fn a_websocket_that_does_not_dial_and_no_bosh_named_fails_as_before() {
        let (f, bosh) = bosh_fake(DOCKER, no_ws()).await;
        let e = join_muc(&quick(&f, "web.example")).await.unwrap_err();
        assert!(
            e.0.starts_with("jitsi join muc: xmpp dial: failed to WebSocket dial: "),
            "{e}"
        );
        assert!(f.seen.lock().unwrap().posts.is_empty());
        assert!(bosh.state().bodies.is_empty());
    }

    /// A WebSocket that dials is taken, whatever config.js names.
    #[tokio::test]
    async fn a_websocket_that_dials_is_taken_and_bosh_is_left_alone() {
        let (f, bosh) = bosh_fake(WITH_BOSH, Opts::default()).await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(j.conn.nick(), "01234567");
        let s = f.seen.lock().unwrap();
        assert_eq!(s.upgrades.len(), 1);
        assert!(s.said[0][0].starts_with("<open "));
        assert!(s.posts.is_empty());
        assert!(bosh.state().bodies.is_empty());
    }

    /// An answer is read up to a megabyte, the WebSocket's limit for a
    /// stanza, and one byte more is the request's failure.
    #[tokio::test]
    async fn a_bosh_answer_is_read_up_to_a_megabyte_and_no_further() {
        assert_eq!(REPLY_LIMIT, WS_READ_LIMIT);
        let session = |len: usize| {
            let head = "<body xmlns='http://jabber.org/protocol/httpbind' xmlns:stream='http://etherx.jabber.org/streams' sid='sid-0001' wait='60' pad='";
            let tail = "'><stream:features xmlns='jabber:client'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms></stream:features></body>";
            format!("{head}{}{tail}", "p".repeat(len - head.len() - tail.len()))
        };
        let (f, bosh) = bosh_fake(WITH_BOSH, no_ws()).await;
        bosh.state().create = Some(session(REPLY_LIMIT));
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        j.conn.close().await;

        let (f, bosh) = bosh_fake(WITH_BOSH, no_ws()).await;
        bosh.state().create = Some(session(REPLY_LIMIT + 1));
        let e = join_muc(&quick(&f, "web.example")).await.unwrap_err();
        assert_eq!(
            e.0,
            "jitsi join muc: xmpp dial: bosh init: response body too large"
        );
        assert_eq!(bosh.state().bodies.len(), 1, "nothing after the refusal");
    }

    /// An answer other than 200 is the request's failure in Go's words
    /// (`conn.go:1239-1241`).
    #[tokio::test]
    async fn a_bosh_answer_other_than_200_fails_in_go_s_words() {
        let (f, _bosh) = bosh_fake(
            WITH_BOSH,
            Opts {
                bosh_status: Some((404, "<body type='terminate' condition='item-not-found'/>")),
                ..no_ws()
            },
        )
        .await;
        let e = join_muc(&quick(&f, "web.example")).await.unwrap_err();
        assert_eq!(
            e.0,
            "jitsi join muc: xmpp dial: bosh init: bosh: HTTP 404: <body type='terminate' condition='item-not-found'/>"
        );
        assert_eq!(f.seen.lock().unwrap().posts.len(), 1);
    }

    /// A login that fails over BOSH ends the session it opened
    /// (`dialBOSH`: `_ = bt.Close()`), so nothing is left polling.
    #[tokio::test]
    async fn a_login_that_fails_over_bosh_ends_its_session() {
        let (f, bosh) = bosh_fake(WITH_BOSH, no_ws()).await;
        bosh.state().create = Some("<body xmlns='http://jabber.org/protocol/httpbind' sid='sid-0001' wait='60'><stream:features xmlns='jabber:client'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features></body>".into());
        let e = join_muc(&quick(&f, "web.example")).await.unwrap_err();
        assert_eq!(
            e.0,
            "jitsi join muc: xmpp dial: server does not advertise anonymous XMPP login"
        );
        for _ in 0..200 {
            if bosh.state().terminated {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(bosh.state().terminated);
        let n = bosh.state().bodies.len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(bosh.state().bodies.len(), n, "no poll after the terminate");
    }

    /// PJ3 inside the join: the extension is offered, the fake takes it, and
    /// the login, the focus and the room go through it both ways.
    #[tokio::test]
    async fn a_join_over_permessage_deflate_goes_through() {
        let f = fake_with(
            vec![(200, "application/javascript", DOCKER.into())],
            "meet.jitsi",
            Opts {
                deflate: true,
                ..Opts::default()
            },
        )
        .await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(j.conn.nick(), "01234567");
        for _ in 0..100 {
            if f.seen.lock().unwrap().said[0].len() >= 10 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let s = f.seen.lock().unwrap();
        assert!(s.upgrades[0].contains("Sec-WebSocket-Extensions: permessage-deflate\r\n"));
        // The focus request is over 128 bytes: it went compressed, and the
        // server read what Go's client writes.
        assert!(s.compressed >= 1, "{} compressed frames", s.compressed);
        assert_eq!(
            s.said[0][6],
            stanza::focus("meet.jitsi", "secret-room@muc.meet.jitsi", "01234567")
        );
        assert_eq!(s.said[0][0], stanza::open("meet.jitsi"));
    }

    #[tokio::test]
    async fn without_config_js_the_web_host_is_the_domain_and_the_text_says_why() {
        // 403 three times (not final): three attempts, then the web host.
        let f = fake(
            vec![
                (403, "text/html", "no".into()),
                (403, "text/html", "no".into()),
                (403, "text/html", "no".into()),
            ],
            "web.example",
        )
        .await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(j.discovery.found, "");
        assert_eq!(j.discovery.failure, "HTTP 403 text/html");
        assert_eq!(f.seen.lock().unwrap().config.len(), 3);
        assert_eq!(j.conn.config().muc_domain, "conference.web.example");
    }

    #[tokio::test]
    async fn a_404_is_final_and_a_missing_domain_is_retried() {
        let f = fake(vec![(404, "text/html", "x".into())], "web.example").await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(f.seen.lock().unwrap().config.len(), 1);
        assert_eq!(j.discovery.failure, "HTTP 404 text/html");
        let f = fake(
            vec![
                (200, "text/html", "<html>challenge</html>".into()),
                (200, "text/javascript", DOCKER.into()),
            ],
            "meet.jitsi",
        )
        .await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(f.seen.lock().unwrap().config.len(), 2);
        assert_eq!(j.discovery.found, "meet.jitsi");
        let f = fake(
            vec![(200, "text/html", "<html>no domain</html>".into()); 3],
            "web.example",
        )
        .await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert_eq!(
            j.discovery.failure,
            "no hosts.domain in 22 bytes of text/html"
        );
    }

    #[tokio::test]
    async fn a_refused_guess_is_retried_on_the_docker_defaults() {
        // config.js unreadable (403 x3), the web host is refused as
        // host-unknown, the docker domain is served.
        let f = fake(vec![(403, "text/html", "no".into()); 3], "meet.jitsi").await;
        let j = join_muc(&quick(&f, "web.example")).await.unwrap();
        assert!(j.fell_back);
        assert_eq!(j.conn.config().xmpp_domain, "meet.jitsi");
        assert_eq!(j.conn.config().muc_domain, "muc.meet.jitsi");
        assert_eq!(f.seen.lock().unwrap().upgrades.len(), 2);
        // Good discovery and a refused domain: no second try, the text carries the cause.
        let f = fake(
            vec![(
                200,
                "text/javascript",
                "config.hosts.domain = 'wrong.example';\n".into(),
            )],
            "meet.jitsi",
        )
        .await;
        let e = join_muc(&quick(&f, "web.example")).await.unwrap_err();
        assert!(
            e.0.starts_with(
                "jitsi join muc: xmpp dial: initial features: server error: <stream:error"
            ),
            "{e}"
        );
        assert!(!e.0.contains("config.js unavailable"));
        assert_eq!(f.seen.lock().unwrap().upgrades.len(), 1);
        // Failed discovery and a refusal that is not host-unknown: no retry, and the reason is named.
        let f = fake(vec![(403, "text/html", "no".into()); 3], "never").await;
        let mut c = quick(&f, "web.example");
        c.ws_url = Some("ws://127.0.0.1:1/xmpp-websocket".into());
        let e = join_muc(&c).await.unwrap_err();
        assert!(
            e.0.starts_with("jitsi join muc: xmpp dial: failed to WebSocket dial: "),
            "{e}"
        );
        assert!(
            e.0.ends_with("(config.js unavailable: HTTP 403 text/html)"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn the_room_name_is_in_no_error_text_of_ours() {
        let f = fake(vec![], "x").await;
        let mut c = quick(&f, "web.example");
        c.ws_url = Some("ws://127.0.0.1:1/xmpp-websocket".into());
        let e = join_muc(&c).await.unwrap_err();
        assert!(!e.0.contains("secret-room"), "{e}");
    }

    /// The read limit and the bounds of discovery.
    #[test]
    fn the_constants() {
        assert_eq!(WS_READ_LIMIT, 1 << 20);
        let l = Limits::default();
        assert_eq!(
            (l.pause, l.attempt, l.grace, l.budget),
            (PAUSE, ATTEMPT_TIMEOUT, GRACE, BUDGET)
        );
    }
}

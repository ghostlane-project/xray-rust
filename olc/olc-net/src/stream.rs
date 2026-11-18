// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Byte streams to a signalling server: `ws://` and `http://` over a
//! protected TCP connection ([`crate::net`]), `wss://` and `https://`
//! through the TLS the host installs ([`set_tls_connector`]). The host
//! shapes that TLS as a browser's (port plan section 8: the signalling's
//! ClientHello is Chrome's); this crate has none of its own, so a build
//! without one cannot reach a TLS server at all rather than reach it with a
//! hello that does not look like a browser's.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// A byte stream: TCP, or TLS over it.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// A boxed [`Stream`].
pub type BoxStream = Box<dyn Stream>;

/// What a dial's TLS offers in ALPN: what Chrome offers on that kind of
/// connection (port plan section 8: the observer sees Chrome's hello).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// A WebSocket's own connection: `http/1.1` alone.
    WebSocket,
    /// A `fetch` (the auth's REST calls): `h2` and `http/1.1`.
    Fetch,
}

/// A dialed stream, and whether its TLS picked `h2`.
pub struct Dialed {
    /// The stream: TCP, or TLS over it.
    pub stream: BoxStream,
    /// The server picked `h2` in ALPN (only ever for [`Offer::Fetch`]).
    pub h2: bool,
}

impl std::fmt::Debug for Dialed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialed")
            .field("h2", &self.h2)
            .finish_non_exhaustive()
    }
}

/// The future a TLS connector returns.
pub type TlsFuture = Pin<Box<dyn Future<Output = io::Result<Dialed>> + Send>>;

/// Wraps a connected TCP stream in TLS for a server name (SNI and the
/// certificate check), offering the ALPN of an [`Offer`].
pub type TlsConnector = Arc<dyn Fn(TcpStream, String, Offer) -> TlsFuture + Send + Sync>;

static TLS: RwLock<Option<TlsConnector>> = RwLock::new(None);

/// Installs the TLS connector; `None` removes it.
pub fn set_tls_connector(c: Option<TlsConnector>) {
    *TLS.write().unwrap_or_else(PoisonError::into_inner) = c;
}

/// Whether a TLS connector is installed.
#[must_use]
pub fn tls_connector_installed() -> bool {
    TLS.read().unwrap_or_else(PoisonError::into_inner).is_some()
}

/// A URL's parts, as the dial needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Whether the scheme is `wss` or `https`.
    pub tls: bool,
    /// The host, without brackets.
    pub host: String,
    /// The port, the scheme's default when the URL names none.
    pub port: u16,
    /// The path and query, `/` at least.
    pub path: String,
    /// The `Host` header: the host, with the port only when it is not the
    /// scheme's default.
    pub authority: String,
}

/// Splits `ws://`, `wss://`, `http://` or `https://` URLs.
///
/// # Errors
/// `InvalidInput` for another scheme, no host, or a bad port.
pub fn parse_url(url: &str) -> io::Result<Target> {
    let bad =
        |why: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("url {url:?}: {why}"));
    let (scheme, rest) = url.split_once("://").ok_or_else(|| bad("no scheme"))?;
    let (tls, default_port) = match scheme.to_ascii_lowercase().as_str() {
        "ws" | "http" => (false, 80),
        "wss" | "https" => (true, 443),
        _ => return Err(bad("unsupported scheme")),
    };
    let (hostport, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
        Some(i) => (&rest[..i], rest[i..].to_owned()),
        None => (rest, "/".to_owned()),
    };
    if hostport.contains('@') {
        return Err(bad("credentials in the URL"));
    }
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| bad("unclosed ["))?;
        match after.strip_prefix(':') {
            Some(p) => (h, p.parse().map_err(|_| bad("bad port"))?),
            None if after.is_empty() => (h, default_port),
            None => return Err(bad("junk after ]")),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| bad("bad port"))?),
            None => (hostport, default_port),
        }
    };
    if host.is_empty() {
        return Err(bad("no host"));
    }
    let shown = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = if port == default_port {
        shown
    } else {
        format!("{shown}:{port}")
    };
    Ok(Target {
        tls,
        host: host.to_owned(),
        port,
        path,
        authority,
    })
}

/// Dials `t` for a WebSocket: a protected TCP connection, in TLS offering
/// `http/1.1` alone when the URL asks.
///
/// # Errors
/// The dial's, the TLS's, or `Unsupported` for TLS with no connector.
pub async fn dial(t: &Target) -> io::Result<BoxStream> {
    dial_for(t, Offer::WebSocket).await.map(|d| d.stream)
}

/// Dials `t`: a protected TCP connection, in TLS offering `offer`'s ALPN
/// when the URL asks.
///
/// # Errors
/// The dial's, the TLS's, or `Unsupported` for TLS with no connector.
pub async fn dial_for(t: &Target, offer: Offer) -> io::Result<Dialed> {
    let tcp = dial_tcp(t).await?;
    secure(tcp, t, offer).await
}

/// The first half of [`dial_for`]: the lookup and the protected TCP
/// connection to `t`'s host. Nothing of a request has left when it fails,
/// which is what [`crate::retry`] rests on.
pub(crate) async fn dial_tcp(t: &Target) -> io::Result<TcpStream> {
    let host_port = if t.host.contains(':') {
        format!("[{}]:{}", t.host, t.port)
    } else {
        format!("{}:{}", t.host, t.port)
    };
    let tcp = crate::net::dial_tcp_host(&host_port).await?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

/// The second half of [`dial_for`]: `tcp` as it is for a plain URL, in TLS
/// offering `offer`'s ALPN when the URL asks.
pub(crate) async fn secure(tcp: TcpStream, t: &Target, offer: Offer) -> io::Result<Dialed> {
    if !t.tls {
        return Ok(Dialed {
            stream: Box::new(tcp),
            h2: false,
        });
    }
    let tls = TLS.read().unwrap_or_else(PoisonError::into_inner).clone();
    match tls {
        Some(connect) => connect(tcp, t.host.clone(), offer).await,
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no TLS connector installed for a TLS URL",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_as_the_dial_needs() {
        let t = parse_url("ws://127.0.0.1:41234/connector").unwrap();
        assert_eq!(
            (t.tls, t.host.as_str(), t.port, t.path.as_str()),
            (false, "127.0.0.1", 41234, "/connector")
        );
        assert_eq!(t.authority, "127.0.0.1:41234");
        let t = parse_url("wss://ws.salutejazz.ru/connector").unwrap();
        assert_eq!(
            (t.tls, t.port, t.authority.as_str()),
            (true, 443, "ws.salutejazz.ru")
        );
        let t = parse_url("https://bk.salutejazz.ru").unwrap();
        assert_eq!(t.path, "/");
        let t = parse_url("ws://[::1]:9/x?y=1").unwrap();
        assert_eq!(
            (
                t.host.as_str(),
                t.port,
                t.path.as_str(),
                t.authority.as_str()
            ),
            ("::1", 9, "/x?y=1", "[::1]:9")
        );
        let t = parse_url("ws://h?q").unwrap();
        assert_eq!(t.path, "/?q");
        assert!(parse_url("tcp://h:1").is_err());
        assert!(parse_url("ws://:1").is_err());
        assert!(parse_url("ws://u:p@h").is_err());
    }
}

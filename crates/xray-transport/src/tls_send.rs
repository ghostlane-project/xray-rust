//! What a TLS client session holds to send.
//!
//! rustls takes a write while the records it has queued for the carrier
//! hold less than its buffer limit, 64 KiB by default, whether or not the
//! carrier takes them, and takes what fits of a write that does not. A
//! relay's write whose carrier waits then leaves bytes in two places: in
//! the records rustls queued, and in the relay buffer the writer holds
//! until the whole write returns. The byte budget counts those bytes once:
//! a relay direction counts its buffer until the write returns, and what it
//! wrote as unflushed from then until its flush. Of a 32 KiB write, 32,724 B
//! sat in both (the test below, before this rule). 64 flows on a GitHub
//! runner held 90 to 261 KB that way at their peak, which took the uploads
//! of `relay_memory_tests` T4 up to 102 KB over its bound in CI and 235 KB
//! in a lab run.
//!
//! So a TLS client session takes a write only once the records of the
//! writes before it have all gone to the carrier. While the carrier waits,
//! the session holds the records of the one write it took last: its bytes
//! and 22 B a record of at most 16 KiB, 32,812 B for a phone relay's largest
//! write (32 KiB), where rustls held up to 64 KiB and more. Its writer counts
//! those bytes as written, and a write that waits has given the session
//! none of its bytes. The writer waits for the carrier instead.
//!
//! Records keep their sizes: rustls cuts a write it takes whole into 16 KiB
//! records and the rest, as it always did. Only a write that met a nearly
//! full queue was cut where the limit fell, and none meets a queue now.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;

use crate::{BoxedTransportStream, TransportStream};

/// `Ready` once `session` has handed its carrier every record it queued,
/// and so may take a write. The session's flush writes them, and flushes
/// the carrier after.
pub(crate) fn poll_records_gone<S>(
    session: &mut TlsStream<S>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if session.get_ref().1.wants_write() {
        Pin::new(session).poll_flush(cx)
    } else {
        Poll::Ready(Ok(()))
    }
}

/// `poll_write` on `session`, once [`poll_records_gone`].
pub(crate) fn poll_write<S>(
    session: &mut TlsStream<S>,
    cx: &mut Context<'_>,
    input: &[u8],
) -> Poll<io::Result<usize>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !input.is_empty() {
        ready!(poll_records_gone(session, cx))?;
    }
    Pin::new(session).poll_write(cx, input)
}

/// `poll_write_vectored` on `session`, once [`poll_records_gone`].
pub(crate) fn poll_write_vectored<S>(
    session: &mut TlsStream<S>,
    cx: &mut Context<'_>,
    inputs: &[IoSlice<'_>],
) -> Poll<io::Result<usize>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if inputs.iter().any(|input| !input.is_empty()) {
        ready!(poll_records_gone(session, cx))?;
    }
    Pin::new(session).poll_write_vectored(cx, inputs)
}

/// TLS that Vision never unwraps: the session under an HTTP-based stream
/// transport, where Vision requires VLESS encryption and its Direct command
/// removes only that layer, and the sessions `TlsConnector` dials for DNS
/// and probes. Direct I/O therefore stays inside the session. The raw
/// transport's TLS, which Vision does unwrap, is a `PenetratingTlsStream`.
/// Both take a write only once their records have gone (module docs).
pub(crate) struct TlsClientStream(TlsStream<BoxedTransportStream>);

impl TlsClientStream {
    pub(crate) fn new(session: TlsStream<BoxedTransportStream>) -> Self {
        Self(session)
    }
}

impl AsyncRead for TlsClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, output)
    }
}

impl AsyncWrite for TlsClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_write(&mut self.get_mut().0, cx, input)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        poll_write_vectored(&mut self.get_mut().0, cx, inputs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl TransportStream for TlsClientStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
    use tokio_rustls::TlsAcceptor;

    use crate::utls_tls::TlsAlpnPolicy;
    use crate::{BoxedTransportStream, TlsClientConfig, TlsConnector, TransportStream};

    /// A phone relay's largest write: `CONSTRAINED_READ` in the core's
    /// relay memory tests.
    const WRITE: usize = 32 * 1024;

    /// The bytes the TLS 1.3 records of `len` bytes of writes take: 22 B a
    /// record (a 5-byte header, the content type and a 16-byte tag) of at
    /// most 16 KiB.
    const fn records_len(len: usize) -> usize {
        len + 22 * len.div_ceil(16 * 1024)
    }

    /// Whether the carrier takes writes, who waits for it to, and the bytes
    /// it took.
    #[derive(Clone, Default)]
    struct Gate(Arc<Mutex<GateState>>);

    #[derive(Default)]
    struct GateState {
        closed: bool,
        waiting: Option<Waker>,
        taken: usize,
    }

    impl Gate {
        fn close(&self) {
            self.0.lock().unwrap().closed = true;
        }

        fn open(&self) {
            let waiting = {
                let mut gate = self.0.lock().unwrap();
                gate.closed = false;
                gate.waiting.take()
            };
            if let Some(waker) = waiting {
                waker.wake();
            }
        }

        fn taken(&self) -> usize {
            self.0.lock().unwrap().taken
        }

        /// `Pending` while the gate is closed, remembering `cx` to wake.
        fn poll_open(&self, cx: &mut Context<'_>) -> Poll<()> {
            let mut gate = self.0.lock().unwrap();
            if gate.closed {
                gate.waiting = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }
    }

    /// A carrier that takes no writes while its gate is closed.
    struct GatedCarrier {
        io: DuplexStream,
        gate: Gate,
    }

    impl AsyncRead for GatedCarrier {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedCarrier {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            std::task::ready!(self.gate.poll_open(cx));
            let written = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, buf))?;
            self.gate.0.lock().unwrap().taken += written;
            Poll::Ready(Ok(written))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    impl TransportStream for GatedCarrier {
        fn poll_read_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncRead::poll_read(self, cx, output)
        }

        fn poll_write_direct(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            AsyncWrite::poll_write(self, cx, input)
        }
    }

    /// The TLS paths a relay's client session takes.
    #[derive(Clone, Copy, Debug)]
    enum Path {
        /// TLS under an HTTP-based transport, DNS and probes.
        Plain,
        /// The raw transport's TLS, which Vision may unwrap (REALITY's too).
        Penetrating,
    }

    /// A client session on `path` over a gated carrier, and the server's
    /// end, both past the handshake.
    async fn connected(
        path: Path,
    ) -> (
        BoxedTransportStream,
        tokio_rustls::server::TlsStream<DuplexStream>,
        Gate,
    ) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["server.test".to_owned()])
                .expect("generate self-signed certificate");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add test root");
        let provider = || Arc::new(rustls::crypto::ring::default_provider());
        let client_config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server certificate config");

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let gate = Gate::default();
        let carrier = Box::new(GatedCarrier {
            io: client_io,
            gate: gate.clone(),
        });
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(server_config))
                .accept(server_io)
                .await
                .expect("accept TLS")
        });
        let connector = TlsConnector::with_pinned_client_config(Arc::new(client_config));
        let config = TlsClientConfig {
            server_name: "server.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: None,
        };
        let client = match path {
            Path::Plain => connector.connect_stream(carrier, &config).await,
            Path::Penetrating => {
                let prepared = connector
                    .prepare_stream(&config, TlsAlpnPolicy::Raw)
                    .expect("prepare TLS");
                connector
                    .connect_prepared_penetrating_stream(carrier, prepared)
                    .await
            }
        }
        .expect("client TLS connect");
        let server = server.await.expect("server task");
        (client, server, gate)
    }

    /// Writes of `WRITE` bytes into `stream`, whose carrier takes nothing,
    /// until one waits: the bytes the session took, and those of them the
    /// waiting write gave it.
    fn write_until_one_waits(stream: &mut BoxedTransportStream, bytes: &[u8]) -> (usize, usize) {
        let mut cx = Context::from_waker(Waker::noop());
        let mut took = 0;
        loop {
            let mut offset = 0;
            while offset < bytes.len() {
                match Pin::new(&mut *stream).poll_write(&mut cx, &bytes[offset..]) {
                    Poll::Ready(written) => offset += written.expect("the session takes the write"),
                    Poll::Pending => return (took + offset, offset),
                }
            }
            took += bytes.len();
            assert!(
                took <= 1 << 20,
                "the session took {took} B while its carrier took none"
            );
        }
    }

    /// While its carrier takes nothing, a session takes one write: what it
    /// holds to send is that write's records, whose bytes its writer counts
    /// as written, and the write after it waits having given it nothing,
    /// so no byte the writer still holds sits in the session too. Once the
    /// carrier takes writes again, every byte arrives.
    #[tokio::test]
    async fn a_session_takes_a_write_once_its_records_have_gone() {
        for path in [Path::Plain, Path::Penetrating] {
            let (mut client, mut server, gate) = connected(path).await;
            let bytes: Vec<u8> = (0..WRITE).map(|i| i as u8).collect();
            gate.close();
            let (took, waiting) = write_until_one_waits(&mut client, &bytes);
            assert!(
                took <= WRITE && waiting == 0,
                "{path:?}: while the carrier took nothing the session took {took} B, \
                 {waiting} B of them from the write that waits; one {WRITE} B write at most, \
                 none of the waiting one"
            );

            // What the session held to send: the records its flush hands
            // the carrier once the carrier takes them.
            let before = gate.taken();
            gate.open();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                Pin::new(&mut client).poll_flush(&mut cx).is_ready(),
                "{path:?}: the session's records fit the carrier"
            );
            let queued = gate.taken() - before;
            assert!(
                queued <= records_len(WRITE),
                "{path:?}: the session held {queued} B to send; one {WRITE} B write's \
                 records are {} B",
                records_len(WRITE)
            );

            let writer = tokio::spawn(async move {
                client.write_all(&bytes[waiting..]).await.expect("write");
                client.flush().await.expect("flush");
                client
            });
            let mut arrived = vec![0; took + WRITE - waiting];
            server.read_exact(&mut arrived).await.expect("read");
            let _client = writer.await.expect("writer");
            let expected: Vec<u8> = (0..took + WRITE - waiting)
                .map(|i| (i % WRITE) as u8)
                .collect();
            assert!(arrived == expected, "{path:?}: the bytes arrived changed");
        }
    }
}

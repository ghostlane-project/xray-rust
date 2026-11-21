//! The REALITY hello fallback (`xray_transport::reality_hello_fallback`),
//! from the dialer through a path to a REALITY server and back.
//!
//! The path is a relay that lets a first flight through whole when it fits
//! one TCP segment and, when it does not, forwards its first 1388 bytes and
//! nothing of that connection's client bytes after them: what a network does
//! that delivers the first segment of a two-segment ClientHello and never
//! the second. The server is a small REALITY server made here, since the
//! tree has none: it reads the ClientHello, derives the authentication key
//! from the hello's X25519 share and its own secret, and answers with the
//! temporary certificate REALITY binds to that key.
//!
//! The sockets are real, so the clock is too. The dialer's stall window is
//! set through `with_reality_hello_stall_window`: short where a stall is the
//! point, long where there must be none.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use hmac::{Hmac, KeyInit, Mac};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    SignatureScheme,
};
use sha2::Sha512;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    reality::{derive_reality_auth_key, RealityError},
    reality_connector::{RealityClientHelloRequest, RealityTlsSessionProvider},
    reality_hello_fallback::{
        remembered_servers, REALITY_HELLO_MEMORY_CAPACITY, REALITY_HELLO_MEMORY_TTL,
        REALITY_SHORT_HELLO_FINGERPRINT,
    },
    stream::TransportLayer,
    BoxedTransportStream, ConnectorConfig, RealityClientConfig, RealityHelloEvent,
    RustlsRealityTlsSessionProvider, ShortHelloVerdict, TransportDialer, TransportError,
};

/// What the path lets through of a first flight longer than this.
const FIRST_SEGMENT: usize = 1388;
/// The short hello's first flight stays under this: one segment on any path
/// a TCP connection is likely to cross.
const SHORT_FLIGHT_MAX: usize = 1200;
/// A fingerprint whose hello carries the X25519MLKEM768 share.
const HYBRID: &str = "chrome";
/// The stall window of the tests in which the hello is never answered. The
/// retry's answer has to arrive within it, from a server on this machine.
const STALL: Duration = Duration::from_millis(400);
/// Longer than any dial here takes: a dial that reaches it has hung.
const DEADLINE: Duration = Duration::from_secs(10);

/// The memory under test is the process's, so the tests take turns.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Empties the memory the way a host does.
fn forget_everything() {
    TransportDialer::system()
        .expect("the system dialer")
        .network_resets()
        .reset();
    assert_eq!(remembered_servers(), 0);
}

// The path.

#[derive(Clone, Copy)]
enum Path {
    /// Forwards [`FIRST_SEGMENT`] bytes of a longer first flight, then drops
    /// whatever else the client sends on that connection.
    DropsTheTail,
    PassesAll,
}

struct Relay {
    addr: SocketAddr,
    /// The size of each connection's first flight, in the order they came.
    flights: Arc<Mutex<Vec<usize>>>,
}

impl Relay {
    async fn spawn(server: SocketAddr, path: Path) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind the relay");
        let addr = listener.local_addr().expect("the relay's address");
        let flights = Arc::new(Mutex::new(Vec::new()));
        let seen = flights.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(relay(client, server, path, seen.clone()));
            }
        });
        Self { addr, flights }
    }

    fn flights(&self) -> Vec<usize> {
        self.flights.lock().expect("the relay's log").clone()
    }
}

/// The first flight is the client's first TLS record: its ClientHello.
async fn read_first_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut record = vec![0u8; 5];
    stream.read_exact(&mut record).await?;
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

async fn relay(
    mut client: TcpStream,
    server: SocketAddr,
    path: Path,
    flights: Arc<Mutex<Vec<usize>>>,
) {
    let Ok(mut upstream) = TcpStream::connect(server).await else {
        return;
    };
    let Ok(flight) = read_first_record(&mut client).await else {
        return;
    };
    flights.lock().expect("the relay's log").push(flight.len());
    if matches!(path, Path::DropsTheTail) && flight.len() > FIRST_SEGMENT {
        if upstream.write_all(&flight[..FIRST_SEGMENT]).await.is_err() {
            return;
        }
        // The server's side stays open, as it would: it only never hears
        // the rest. Both sides go when the client gives up.
        let mut lost = [0u8; 4096];
        while matches!(client.read(&mut lost).await, Ok(read) if read > 0) {}
        return;
    }
    if upstream.write_all(&flight).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

// The server.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Answers {
    /// REALITY, to any hello it can read.
    Reality,
    /// REALITY to a hello with the hybrid share; to any other, the ordinary
    /// site a REALITY server shows a client it does not take for its own.
    RealityToTheHybridShareOnly,
    /// A fatal alert, and the connection closed.
    Alert,
    /// The first byte of an answer, and no more.
    OneByte,
    /// Nothing, to a hello it reads to the end.
    Nothing,
    /// REALITY to the first hello without the hybrid share it reads, and to
    /// any with the share; nothing to a later hello without it.
    RealityToTheFirstShortHelloOnly,
    /// The connection closed, without a byte, on a hello it reads to the end.
    Closes,
}

struct Server {
    addr: SocketAddr,
    public_key: [u8; 32],
    answers: Arc<Mutex<Answers>>,
    /// For each ClientHello read to its end, whether it had the hybrid share.
    hellos: Arc<Mutex<Vec<bool>>>,
}

impl Server {
    async fn spawn(answers: Answers) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind the server");
        let addr = listener.local_addr().expect("the server's address");
        let secret = [0x5a; 32];
        let public_key = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
        let answers = Arc::new(Mutex::new(answers));
        let hellos = Arc::new(Mutex::new(Vec::new()));
        let (mode, seen) = (answers.clone(), hellos.clone());
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(serve(client, secret, mode.clone(), seen.clone()));
            }
        });
        Self {
            addr,
            public_key,
            answers,
            hellos,
        }
    }

    fn now_answers(&self, answers: Answers) {
        *self.answers.lock().expect("the server's mode") = answers;
    }

    fn hellos(&self) -> Vec<bool> {
        self.hellos.lock().expect("the server's log").clone()
    }
}

async fn serve(
    mut client: TcpStream,
    secret: [u8; 32],
    answers: Arc<Mutex<Answers>>,
    hellos: Arc<Mutex<Vec<bool>>>,
) {
    let Ok(record) = read_first_record(&mut client).await else {
        return;
    };
    let Some(hello) = ClientHello::parse(&record) else {
        return;
    };
    // The hellos without the hybrid share read so far, this one included.
    let short_hellos = {
        let mut hellos = hellos.lock().expect("the server's log");
        hellos.push(hello.hybrid_share.is_some());
        hellos.iter().filter(|hybrid| !**hybrid).count()
    };
    // What this hello gets.
    let answers = match *answers.lock().expect("the server's mode") {
        Answers::RealityToTheFirstShortHelloOnly
            if hello.hybrid_share.is_none() && short_hellos > 1 =>
        {
            Answers::Nothing
        }
        Answers::RealityToTheFirstShortHelloOnly => Answers::Reality,
        answers => answers,
    };
    let config = match answers {
        Answers::RealityToTheFirstShortHelloOnly => unreachable!("read as another answer above"),
        Answers::Closes => return,
        Answers::Nothing => {
            let mut lost = [0u8; 4096];
            while matches!(client.read(&mut lost).await, Ok(read) if read > 0) {}
            return;
        }
        Answers::OneByte => {
            let _ = client.write_all(&[0x16]).await;
            let mut lost = [0u8; 4096];
            while matches!(client.read(&mut lost).await, Ok(read) if read > 0) {}
            return;
        }
        Answers::Alert => {
            // handshake_failure, fatal.
            let _ = client
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
                .await;
            return;
        }
        Answers::RealityToTheHybridShareOnly if hello.hybrid_share.is_none() => ordinary_site(),
        Answers::Reality | Answers::RealityToTheHybridShareOnly => {
            let Some(config) = reality_answer(secret, &hello) else {
                return;
            };
            config
        }
    };
    let replayed = Replayed {
        head: record,
        at: 0,
        rest: client,
    };
    let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(config)
        .accept(replayed)
        .await
    else {
        return;
    };
    // Whatever arrives goes back.
    let mut bytes = [0u8; 1024];
    while let Ok(read) = tls.read(&mut bytes).await {
        if read == 0 || tls.write_all(&bytes[..read]).await.is_err() {
            return;
        }
        let _ = tls.flush().await;
    }
}

/// What the server needs of a ClientHello.
struct ClientHello {
    random: [u8; 32],
    x25519_share: Option<[u8; 32]>,
    /// The X25519 half of an X25519MLKEM768 share: its last 32 bytes.
    hybrid_share: Option<[u8; 32]>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|bytes| usize::from(bytes[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }
}

impl ClientHello {
    fn parse(record: &[u8]) -> Option<Self> {
        let mut hello = Reader(record);
        // The record header, the handshake header, the legacy version.
        if hello.take(5)?[0] != 0x16 || hello.u8()? != 0x01 {
            return None;
        }
        hello.take(3 + 2)?;
        let random = hello.take(32)?.try_into().ok()?;
        let session_id = hello.u8()?;
        hello.take(session_id)?;
        let cipher_suites = hello.u16()?;
        hello.take(cipher_suites)?;
        let compression = hello.u8()?;
        hello.take(compression)?;
        let extensions = hello.u16()?;
        let mut extensions = Reader(hello.take(extensions)?);

        let (mut x25519_share, mut hybrid_share) = (None, None);
        while !extensions.0.is_empty() {
            let kind = extensions.u16()?;
            let len = extensions.u16()?;
            let mut body = Reader(extensions.take(len)?);
            if kind != 0x0033 {
                continue;
            }
            let shares = body.u16()?;
            let mut shares = Reader(body.take(shares)?);
            while !shares.0.is_empty() {
                let group = shares.u16()?;
                let len = shares.u16()?;
                let key = shares.take(len)?;
                match group {
                    0x001d => x25519_share = key.try_into().ok(),
                    0x11ec => hybrid_share = key.last_chunk::<32>().copied(),
                    _ => {}
                }
            }
        }
        Some(Self {
            random,
            x25519_share,
            hybrid_share,
        })
    }
}

/// Signs with Ed25519 whatever the hello offers, as a REALITY server does: a
/// Chrome hello does not offer it, and a REALITY client takes it all the
/// same.
#[derive(Debug)]
struct SignsEd25519(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for SignsEd25519 {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

fn server_config() -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert> {
    rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("server protocol versions")
    .with_no_client_auth()
}

/// REALITY's answer to `hello`: a certificate made for this connection, whose
/// signature is HMAC-SHA512 of its Ed25519 key under the authentication key
/// both sides derive.
fn reality_answer(secret: [u8; 32], hello: &ClientHello) -> Option<Arc<rustls::ServerConfig>> {
    // The share a REALITY client derives from: X25519 where the hello has
    // one, else the X25519 half of the hybrid share.
    let client_share = hello.x25519_share.or(hello.hybrid_share)?;
    let shared = StaticSecret::from(secret)
        .diffie_hellman(&PublicKey::from(client_share))
        .to_bytes();
    let auth_key = derive_reality_auth_key(&shared, &hello.random).ok()?;

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("an Ed25519 key");
    let mut certificate = rcgen::CertificateParams::new(vec!["reality.test".to_owned()])
        .expect("certificate parameters")
        .self_signed(&key)
        .expect("a certificate")
        .der()
        .to_vec();
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&auth_key).expect("any key length");
    mac.update(key.public_key_raw());
    let binding = mac.finalize().into_bytes();
    // An Ed25519 signature is the last 64 bytes of the certificate.
    let signature = certificate.len() - binding.len();
    certificate[signature..].copy_from_slice(binding.as_slice());

    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        key.serialize_der().into(),
    ))
    .expect("an Ed25519 signing key");
    Some(Arc::new(server_config().with_cert_resolver(Arc::new(
        rustls::sign::SingleCertAndKey::from(rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(certificate)],
            Arc::new(SignsEd25519(signer)),
        )),
    ))))
}

/// A site with a certificate of its own, which no REALITY client's key binds
/// and no trust store knows.
fn ordinary_site() -> Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["site.test".to_owned()])
        .expect("an ordinary certificate");
    let key = PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    Arc::new(
        server_config()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("a server certificate"),
    )
}

/// A stream that gives back what was read from it before the rest.
struct Replayed<S> {
    head: Vec<u8>,
    at: usize,
    rest: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replayed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.at < this.head.len() {
            let take = (this.head.len() - this.at).min(output.remaining());
            output.put_slice(&this.head[this.at..this.at + take]);
            this.at += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.rest).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replayed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().rest).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().rest).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().rest).poll_shutdown(cx)
    }
}

// The client.

struct Client {
    dialer: TransportDialer,
    /// What the dialer reported, in order.
    events: Arc<Mutex<Vec<(Target, RealityHelloEvent)>>>,
}

impl Client {
    fn new(stall_window: Duration) -> Self {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let dialer = TransportDialer::system()
            .expect("the system dialer")
            .with_reality_hello_stall_window(stall_window)
            .with_reality_hello_report(Arc::new(
                move |server: &Target, event: RealityHelloEvent| {
                    sink.lock()
                        .expect("the client's log")
                        .push((server.clone(), event));
                },
            ));
        Self { dialer, events }
    }

    fn events(&self) -> Vec<(Target, RealityHelloEvent)> {
        self.events.lock().expect("the client's log").clone()
    }

    /// A dial that must end by itself.
    async fn dial(&self, route: &Route) -> Result<BoxedTransportStream, TransportError> {
        tokio::time::timeout(DEADLINE, self.dial_unbounded(route))
            .await
            .expect("the dial ends by itself")
    }

    async fn dial_unbounded(&self, route: &Route) -> Result<BoxedTransportStream, TransportError> {
        self.dialer
            .connect_stream(
                &route.config,
                &TransportLayer::Raw,
                &route.target,
                &[route.door],
                None,
            )
            .await
    }
}

/// One server as a config names it, and the address its dials go to.
struct Route {
    target: Target,
    door: SocketAddr,
    config: ConnectorConfig,
}

impl Route {
    fn new(server_name: &str, door: SocketAddr, server: &Server) -> Self {
        Self {
            target: Target::new(
                TargetAddr::Domain(server_name.to_owned()),
                door.port(),
                Network::Tcp,
            ),
            door,
            config: ConnectorConfig::Reality(RealityClientConfig {
                server_name: server_name.to_owned(),
                fingerprint: HYBRID.to_owned(),
                public_key: server.public_key,
                short_id: vec![0x01, 0x02, 0x03, 0x04],
                spider_x: "/".to_owned(),
                mldsa65_verify: None,
            }),
        }
    }
}

fn failure(result: Result<BoxedTransportStream, TransportError>) -> TransportError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("the dial must fail"),
    }
}

fn is_the_stall(error: &TransportError, window: Duration) -> bool {
    matches!(
        error,
        TransportError::Reality(RealityError::ClientHelloUnanswered { waited_ms })
            if u128::from(*waited_ms) == window.as_millis()
    )
}

async fn assert_carries_bytes_both_ways(mut stream: BoxedTransportStream) {
    let sent = b"over the hello that got through";
    stream.write_all(sent).await.expect("write to the server");
    stream.flush().await.expect("flush to the server");
    let mut echoed = vec![0u8; sent.len()];
    tokio::time::timeout(DEADLINE, stream.read_exact(&mut echoed))
        .await
        .expect("the echo arrives")
        .expect("read from the server");
    assert_eq!(echoed, sent);
}

async fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while !holds() {
        assert!(tokio::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn fallback_used(route: &Route, window: Duration) -> (Target, RealityHelloEvent) {
    (
        route.target.clone(),
        RealityHelloEvent::FallbackUsed { waited: window },
    )
}

fn remembered(route: &Route, verdict: ShortHelloVerdict) -> (Target, RealityHelloEvent) {
    (
        route.target.clone(),
        RealityHelloEvent::Remembered {
            verdict,
            ttl: REALITY_HELLO_MEMORY_TTL,
        },
    )
}

// The tests.

/// The hybrid hello leaves in two segments and the short one in one, with
/// room to spare, whatever each hello draws and however long the name is.
#[test]
fn the_short_hello_fits_one_segment_and_the_hybrid_hello_does_not() {
    let provider = RustlsRealityTlsSessionProvider::new();
    let first_flight = |fingerprint: &str, server_name: &str| {
        let session = provider
            .create_session(RealityClientHelloRequest {
                server_name,
                fingerprint,
            })
            .expect("a REALITY session");
        // The record header goes on the wire before the hello.
        5 + session
            .prepared_client_hello()
            .expect("a ClientHello")
            .raw_client_hello
            .len()
    };
    let long_name = format!("{0}.{0}.{0}.example", "a".repeat(63));
    for _ in 0..64 {
        for server_name in ["a.example", long_name.as_str()] {
            let short = first_flight(REALITY_SHORT_HELLO_FINGERPRINT, server_name);
            assert!(short <= SHORT_FLIGHT_MAX, "{short} bytes to {server_name}");
        }
        let hybrid = first_flight(HYBRID, "a.example");
        assert!(hybrid > FIRST_SEGMENT, "{hybrid} bytes");
    }
}

/// (a) The hybrid hello is cut on the path and never answered: the dial
/// falls back to the short hello on a new connection and carries bytes both
/// ways. (b) A second dial within the memory's time, from any dialer of the
/// process, sends the short hello at once and no long one.
#[tokio::test]
async fn an_unanswered_hybrid_hello_falls_back_to_the_short_one_and_the_server_is_remembered() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Reality).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("cut.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    let stream = client.dial(&route).await.expect("the fallback connects");
    assert_carries_bytes_both_ways(stream).await;

    let flights = relay.flights();
    assert_eq!(flights.len(), 2, "one hybrid hello, one retry: {flights:?}");
    assert!(flights[0] > FIRST_SEGMENT, "{flights:?}");
    assert!(flights[1] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(
        server.hellos(),
        [false],
        "the server heard the short hello alone, to its end"
    );
    assert_eq!(
        client.events(),
        [
            fallback_used(&route, STALL),
            remembered(&route, ShortHelloVerdict::Works)
        ]
    );
    assert_eq!(remembered_servers(), 1);

    // Another dialer, whose window no test could wait out: had it sent the
    // hybrid hello, this dial would not end in time.
    let second = Client::new(Duration::from_secs(60));
    let stream = second
        .dial(&route)
        .await
        .expect("the short hello connects at once");
    assert_carries_bytes_both_ways(stream).await;

    let flights = relay.flights();
    assert_eq!(flights.len(), 3, "{flights:?}");
    assert!(flights[2] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(server.hellos(), [false, false]);
    assert!(
        second.events().is_empty(),
        "nothing fell back, nothing is new"
    );
    assert_eq!(remembered_servers(), 1);
}

/// (c) On a path that drops nothing the hybrid hello is answered, and no
/// short hello is ever sent.
#[tokio::test]
async fn an_answered_hybrid_hello_is_never_followed_by_a_short_one() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Reality).await;
    let relay = Relay::spawn(server.addr, Path::PassesAll).await;
    let route = Route::new("whole.reality-hello.test", relay.addr, &server);
    let client = Client::new(Duration::from_secs(60));

    for dials in 1..=2 {
        let stream = client
            .dial(&route)
            .await
            .expect("the hybrid hello connects");
        assert_carries_bytes_both_ways(stream).await;

        let flights = relay.flights();
        assert_eq!(flights.len(), dials, "{flights:?}");
        assert!(
            flights.iter().all(|flight| *flight > FIRST_SEGMENT),
            "{flights:?}"
        );
        assert_eq!(server.hellos(), vec![true; dials]);
    }
    assert!(client.events().is_empty());
    assert_eq!(remembered_servers(), 0);
}

/// (d) A server that takes only the hybrid hello, behind the path that cuts
/// it: the retry is refused, the dial fails with the stall as its error, and
/// the next dial sends the hybrid hello alone, unwatched, as every dial did
/// before the fallback.
#[tokio::test]
async fn where_the_short_hello_does_not_help_the_dial_fails_with_the_stall_and_later_dials_stay_hybrid(
) {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::RealityToTheHybridShareOnly).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("hybrid-only.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    let error = failure(client.dial(&route).await);
    assert!(is_the_stall(&error, STALL), "{error}");

    let flights = relay.flights();
    assert_eq!(flights.len(), 2, "{flights:?}");
    assert!(flights[0] > FIRST_SEGMENT, "{flights:?}");
    assert!(flights[1] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(server.hellos(), [false]);
    let events = [
        fallback_used(&route, STALL),
        remembered(&route, ShortHelloVerdict::DoesNotHelp),
    ];
    assert_eq!(client.events(), events);
    assert_eq!(remembered_servers(), 1);

    // With the watch on, this dial would end inside two windows.
    let next = tokio::time::timeout(STALL * 2, client.dial_unbounded(&route)).await;
    assert!(
        next.is_err(),
        "nobody answers and nothing watches: the dial waits for its caller"
    );
    eventually("the third connection's hello", || {
        relay.flights().len() == 3
    })
    .await;
    assert!(relay.flights()[2] > FIRST_SEGMENT, "{:?}", relay.flights());
    assert_eq!(server.hellos(), [false], "no second short hello");
    assert_eq!(client.events(), events, "and nothing new to report");
}

/// Two dials stall together and retry together; the server answers the
/// first short hello and never the second. The retry that stalls ends a
/// window after the one that worked, and its outcome does not undo that
/// proof: the memory still says the short hello works here, and a third dial
/// sends it at once.
#[tokio::test]
async fn a_retry_that_fails_after_another_worked_leaves_the_short_hello_remembered() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::RealityToTheFirstShortHelloOnly).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("burst.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    let (one, two) = tokio::join!(client.dial(&route), client.dial(&route));
    let (connected, failed) = match (one, two) {
        (Ok(stream), Err(error)) | (Err(error), Ok(stream)) => (stream, error),
        (one, two) => panic!(
            "one dial connects and one fails: {:?}, {:?}",
            one.map(drop),
            two.map(drop)
        ),
    };
    assert!(is_the_stall(&failed, STALL), "{failed}");
    assert_carries_bytes_both_ways(connected).await;

    let flights = relay.flights();
    assert_eq!(flights.len(), 4, "{flights:?}");
    assert_eq!(
        flights
            .iter()
            .filter(|flight| **flight > FIRST_SEGMENT)
            .count(),
        2,
        "{flights:?}"
    );
    assert_eq!(server.hellos(), [false, false]);
    let mut events = client.events();
    events.sort_by_key(|(_, event)| matches!(event, RealityHelloEvent::Remembered { .. }));
    assert_eq!(
        events,
        [
            fallback_used(&route, STALL),
            fallback_used(&route, STALL),
            remembered(&route, ShortHelloVerdict::Works)
        ],
        "the stalled retry writes nothing over the proof"
    );
    assert_eq!(remembered_servers(), 1);

    server.now_answers(Answers::Reality);
    // A window no test could wait out: had it sent the hybrid hello, this
    // dial would not end in time.
    let third = Client::new(Duration::from_secs(60));
    let stream = third
        .dial(&route)
        .await
        .expect("the short hello connects at once");
    assert_carries_bytes_both_ways(stream).await;
    let flights = relay.flights();
    assert_eq!(flights.len(), 5, "{flights:?}");
    assert!(flights[4] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert!(third.events().is_empty());
}

/// A retry that ends with neither an answer nor a refusal, here a server that
/// closes the connection on the short hello, says nothing about the hello:
/// the dial fails with the stall, nothing is remembered, and the next dial is
/// watched again.
#[tokio::test]
async fn a_retry_that_ends_without_an_answer_or_a_refusal_remembers_nothing() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Closes).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("closed.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    let error = failure(client.dial(&route).await);
    assert!(is_the_stall(&error, STALL), "{error}");
    assert_eq!(server.hellos(), [false]);
    assert_eq!(client.events(), [fallback_used(&route, STALL)]);
    assert_eq!(remembered_servers(), 0);

    let error = failure(client.dial(&route).await);
    assert!(is_the_stall(&error, STALL), "{error}");
    let flights = relay.flights();
    assert_eq!(flights.len(), 4, "{flights:?}");
    assert!(flights[2] > FIRST_SEGMENT, "watched again: {flights:?}");
    assert!(flights[3] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(remembered_servers(), 0);
}

/// (e) A network reset empties the memory, and the next dial starts with the
/// hybrid hello again.
#[tokio::test]
async fn a_network_reset_forgets_the_server_and_the_hybrid_hello_is_tried_again() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Reality).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("reset.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    drop(client.dial(&route).await.expect("the fallback connects"));
    assert_eq!(remembered_servers(), 1);

    // What a core's network reset calls, on a dialer that shares nothing
    // with the one that dialed.
    TransportDialer::system()
        .expect("the system dialer")
        .network_resets()
        .reset();
    assert_eq!(remembered_servers(), 0);

    drop(client.dial(&route).await.expect("the fallback connects"));
    let flights = relay.flights();
    assert_eq!(flights.len(), 4, "{flights:?}");
    assert!(
        flights[2] > FIRST_SEGMENT,
        "hybrid first again: {flights:?}"
    );
    assert!(flights[3] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(remembered_servers(), 1);
}

/// (e) A dial under way when the network is reset learnt its outcome on the
/// old network. It ends as it ends, but writes nothing into the memory the
/// reset emptied, and the next dial starts with the hybrid hello.
#[tokio::test]
async fn a_dial_under_way_at_a_network_reset_remembers_nothing() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Reality).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("moved.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    let (dialed, ()) = tokio::join!(client.dial(&route), async {
        // The hybrid hello is out and waits for its answer: the device moves.
        eventually("the hybrid hello on the path", || {
            !relay.flights().is_empty()
        })
        .await;
        client.dialer.network_resets().reset();
    });
    drop(dialed.expect("the fallback connects"));
    assert_eq!(client.events(), [fallback_used(&route, STALL)]);
    assert_eq!(remembered_servers(), 0);

    drop(client.dial(&route).await.expect("the fallback connects"));
    let flights = relay.flights();
    assert_eq!(flights.len(), 4, "{flights:?}");
    assert!(flights[2] > FIRST_SEGMENT, "hybrid first: {flights:?}");
    assert!(flights[3] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(remembered_servers(), 1);
}

/// (e) The memory never holds more servers than its capacity, however many
/// are dialed.
#[tokio::test]
async fn the_memory_stays_within_its_capacity() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Nothing).await;
    // Nothing ever answers here, so no window is too short.
    let window = Duration::from_millis(5);
    let client = Client::new(window);

    for index in 0..REALITY_HELLO_MEMORY_CAPACITY + 6 {
        let route = Route::new(
            &format!("s{index}.reality-hello.test"),
            server.addr,
            &server,
        );
        let error = failure(client.dial(&route).await);
        assert!(is_the_stall(&error, window), "{error}");
        assert!(remembered_servers() <= REALITY_HELLO_MEMORY_CAPACITY);
    }
    assert_eq!(remembered_servers(), REALITY_HELLO_MEMORY_CAPACITY);

    client.dialer.network_resets().reset();
    assert_eq!(remembered_servers(), 0);
}

/// A server that answers is never downgraded: an alert is an answer, the
/// dial ends with it, and no second hello of any kind is sent.
#[tokio::test]
async fn a_server_that_answers_with_an_alert_is_not_retried() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Alert).await;
    let route = Route::new("alert.reality-hello.test", server.addr, &server);
    let client = Client::new(STALL);

    let error = failure(client.dial(&route).await);
    assert!(matches!(error, TransportError::Tls(_)), "{error}");
    assert_eq!(server.hellos(), [true]);
    assert!(client.events().is_empty());
    assert_eq!(remembered_servers(), 0);
}

/// One byte ends the watch: a server that starts to answer and then takes
/// its time is waited for as before, past any stall window.
#[tokio::test]
async fn one_byte_of_answer_ends_the_watch() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::OneByte).await;
    let route = Route::new("slow.reality-hello.test", server.addr, &server);
    let window = Duration::from_millis(200);
    let client = Client::new(window);

    let dial = tokio::time::timeout(window * 3, client.dial_unbounded(&route)).await;
    assert!(dial.is_err(), "the dial is still waiting for the server");
    assert_eq!(server.hellos(), [true]);
    assert!(client.events().is_empty());
    assert_eq!(remembered_servers(), 0);
}

/// A server the short hello worked at stops taking it: the short dial fails
/// with its own error, the server is forgotten, and the next dial starts
/// with the hybrid hello again.
#[tokio::test]
async fn a_short_hello_that_stops_working_is_forgotten() {
    let _turn = TURN.lock().await;
    forget_everything();
    let server = Server::spawn(Answers::Reality).await;
    let relay = Relay::spawn(server.addr, Path::DropsTheTail).await;
    let route = Route::new("changed.reality-hello.test", relay.addr, &server);
    let client = Client::new(STALL);

    drop(client.dial(&route).await.expect("the fallback connects"));
    assert_eq!(remembered_servers(), 1);

    server.now_answers(Answers::RealityToTheHybridShareOnly);
    let error = failure(client.dial(&route).await);
    assert!(
        matches!(error, TransportError::Tls(_)),
        "the short dial's own error, not a stall: {error}"
    );
    let flights = relay.flights();
    assert_eq!(flights.len(), 3, "{flights:?}");
    assert!(flights[2] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(remembered_servers(), 0);

    let error = failure(client.dial(&route).await);
    assert!(is_the_stall(&error, STALL), "{error}");
    let flights = relay.flights();
    assert_eq!(flights.len(), 5, "{flights:?}");
    assert!(
        flights[3] > FIRST_SEGMENT,
        "hybrid first again: {flights:?}"
    );
    assert!(flights[4] <= SHORT_FLIGHT_MAX, "{flights:?}");
    assert_eq!(
        client.events()[2..],
        [
            fallback_used(&route, STALL),
            remembered(&route, ShortHelloVerdict::DoesNotHelp)
        ]
    );
}

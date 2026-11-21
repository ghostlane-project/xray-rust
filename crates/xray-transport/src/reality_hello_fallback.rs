//! REALITY: one retry with a ClientHello that fits one TCP segment, when the
//! configured one was never answered.
//!
//! A ClientHello with the X25519MLKEM768 key share is about 1.8 KB and leaves
//! in two TCP segments. Some networks deliver the first segment and never the
//! rest, retransmissions included: the server waits for the end of the hello
//! until its own timeout, and the client sees a handshake nobody answers. A
//! hello with the X25519 share alone fits one segment and passes there.
//!
//! What a dial does about it (`TransportDialer`, the REALITY arm, on a bare
//! TCP socket of its own):
//!
//! 1. A fingerprint whose hello has the hybrid share
//!    (`xray_utls::is_reality_fingerprint_hybrid`) is dialed with a watch.
//!    When TCP is up, the hello is written and not one byte comes back within
//!    [`REALITY_HELLO_STALL_WINDOW`], that connection is closed and one more
//!    is made, once, with the hello of [`REALITY_SHORT_HELLO_FINGERPRINT`]: a
//!    profile this crate already carries, picked from the fingerprint table
//!    as it stands.
//! 2. A server that answers is never downgraded. Any byte ends the watch, an
//!    alert or the first byte of a handshake that then fails verification
//!    included, and the dial ends as it would without this module.
//! 3. The outcome is remembered per server (address, port, server name) for
//!    [`REALITY_HELLO_MEMORY_TTL`]. Where the short hello worked, later dials
//!    start with it and do not pay the stall; when the time is up the
//!    configured hello is tried again. Where it did not help (it stalled as
//!    well, or the handshake failed: a server from Xray-core v26.10.21 on
//!    refuses a hello without the hybrid share), the dial fails with the
//!    stall as its error and later dials send only the configured hello,
//!    unwatched, exactly as before.
//!
//! What the retry gives up, and to whom. The short hello has no ML-KEM-768
//! share, so the connection it opens is keyed by X25519 alone: the key
//! exchange every REALITY client used before the hybrid share existed. That
//! holds for that one connection, and for the dials the memory then starts
//! short. REALITY's own authentication (the sealed session id and the
//! certificate binding, with ML-DSA-65 when configured) is the same for both
//! hellos. Whoever stands on the path and can drop packets can force the
//! retry by dropping the hybrid hello's second segment; the same party can
//! also drop the whole connection. A recorded short-hello session is not
//! protected against a later quantum computer; a server that requires the
//! hybrid share refuses the short hello, so nothing is carried over it there.
//!
//! Not covered: a handshake behind `tlshello` fragmentation, behind `sudoku`
//! or `xmc`, through another outbound, or on an engine that dials its own
//! socket. Those dial as before.
//!
//! The memory is process-wide, holds at most
//! [`REALITY_HELLO_MEMORY_CAPACITY`] servers (the oldest goes first), keeps
//! no task or timer, and is emptied by `NetworkResets::reset`, which a host
//! calls when the device moved to another network.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use tokio::time::Instant;
use xray_routing::{Target, TargetAddr};

use crate::{reality::RealityError, RealityClientConfig, TransportError};

/// How long a watched hello may go without one byte of answer.
///
/// A server answers a hello one round trip after it arrives. A segment lost
/// on the way is sent again after at most a second (the retransmission
/// timeout TCP starts from; sooner once the connection has measured its
/// round trip), and again two seconds after that: four seconds let both
/// retransmissions and their answers through, so a path that merely loses a
/// packet or two is not read as one that eats the hello.
///
/// It is under the deadlines a REALITY dial runs inside. The outbound's
/// `handshake` policy (10 s by default) leaves the retry more time than the
/// first attempt had. The 5 s a gRPC transport gives one cold connection
/// leave it about one second: enough on a path that answers, and a dial the
/// deadline cuts short remembers nothing.
pub const REALITY_HELLO_STALL_WINDOW: Duration = Duration::from_secs(4);

/// How long one server's outcome is kept. Long enough that the flows of a
/// session do not each pay the stall, short enough that a path which heals
/// gets the hybrid hello back within minutes.
pub const REALITY_HELLO_MEMORY_TTL: Duration = Duration::from_secs(600);

/// How many servers the memory holds; one more pushes the oldest out.
pub const REALITY_HELLO_MEMORY_CAPACITY: usize = 64;

/// The profile the retry sends: uTLS's Chrome 120, whose only key share
/// beside GREASE is X25519, so its hello is a third the size of the hybrid
/// one and fits one segment with room to spare. It is one of the names the
/// config parser already takes for REALITY, and REALITY servers older than
/// Xray-core v26.10.21 accept it.
pub const REALITY_SHORT_HELLO_FINGERPRINT: &str = "hellochrome_120";

/// What is remembered of the short hello at one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortHelloVerdict {
    /// It completed the handshake after the configured hello had stalled.
    Works,
    /// It stalled as well, or its handshake failed.
    DoesNotHelp,
}

/// What a dialer tells its host, for the host's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityHelloEvent {
    /// The configured hello got no byte of answer within `waited`; the retry
    /// with the short hello follows.
    FallbackUsed { waited: Duration },
    /// The retry's outcome, kept for `ttl`.
    Remembered {
        verdict: ShortHelloVerdict,
        ttl: Duration,
    },
}

/// Receives each [`RealityHelloEvent`] with the server it is about, the
/// target the dial was asked for.
pub type RealityHelloReport = Arc<dyn Fn(&Target, RealityHelloEvent) + Send + Sync>;

/// One server as the memory knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerKey {
    addr: TargetAddr,
    port: u16,
    server_name: String,
}

impl ServerKey {
    fn new(server: &Target, config: &RealityClientConfig) -> Self {
        Self {
            addr: server.addr.clone(),
            port: server.port,
            server_name: config.server_name.clone(),
        }
    }
}

struct Entry {
    server: ServerKey,
    verdict: ShortHelloVerdict,
    until: Instant,
}

/// The outcomes, oldest first. Every method takes the time, so nothing here
/// owns a clock.
struct HelloMemory {
    entries: VecDeque<Entry>,
}

impl HelloMemory {
    const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    fn recall(&mut self, server: &ServerKey, now: Instant) -> Option<ShortHelloVerdict> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.server == *server)?;
        if self.entries[index].until <= now {
            self.entries.remove(index);
            return None;
        }
        Some(self.entries[index].verdict)
    }

    fn remember(&mut self, server: ServerKey, verdict: ShortHelloVerdict, now: Instant) {
        self.entries
            .retain(|entry| entry.until > now && entry.server != server);
        while self.entries.len() >= REALITY_HELLO_MEMORY_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            server,
            verdict,
            until: now + REALITY_HELLO_MEMORY_TTL,
        });
    }

    fn forget(&mut self, server: &ServerKey) {
        self.entries.retain(|entry| entry.server != *server);
    }

    /// Lets the buffer go with the entries.
    fn clear(&mut self) {
        self.entries = VecDeque::new();
    }
}

static MEMORY: Mutex<HelloMemory> = Mutex::new(HelloMemory::new());

fn memory() -> MutexGuard<'static, HelloMemory> {
    MEMORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Off in this commit, so every dial runs as it did before: the tests that
/// pin the fallback are seen failing first. The next commit removes it.
const PLANS_DIALS: bool = false;

/// How one dial opens.
pub(crate) enum HelloPlan {
    /// The configured hello, watched; on a stall, the one retry.
    Watched(ServerKey),
    /// The short hello at once: it worked here within the memory's time.
    ShortFirst(ServerKey),
}

/// The plan for a dial of `config` to `server`, or `None` when the dial runs
/// as it did before this module: the fingerprint has no hybrid share, or the
/// short hello is known not to help here.
pub(crate) fn plan(config: &RealityClientConfig, server: &Target) -> Option<HelloPlan> {
    if !PLANS_DIALS {
        return None;
    }
    if !xray_utls::is_reality_fingerprint_hybrid(&config.fingerprint) {
        return None;
    }
    let key = ServerKey::new(server, config);
    match memory().recall(&key, Instant::now()) {
        None => Some(HelloPlan::Watched(key)),
        Some(ShortHelloVerdict::Works) => Some(HelloPlan::ShortFirst(key)),
        Some(ShortHelloVerdict::DoesNotHelp) => None,
    }
}

/// `config` with the short hello's profile in place of its own. Everything
/// REALITY authenticates with is kept.
pub(crate) fn short_hello_config(config: &RealityClientConfig) -> RealityClientConfig {
    let mut short = config.clone();
    short.fingerprint = REALITY_SHORT_HELLO_FINGERPRINT.to_owned();
    short
}

/// Whether `error` is the watch's verdict that nobody answered the hello.
pub(crate) fn is_unanswered(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Reality(RealityError::ClientHelloUnanswered { .. })
    )
}

pub(crate) fn remember(server: ServerKey, verdict: ShortHelloVerdict) {
    memory().remember(server, verdict, Instant::now());
}

pub(crate) fn forget(server: &ServerKey) {
    memory().forget(server);
}

/// Empties the memory: the network the outcomes were seen on is gone.
pub(crate) fn forget_all() {
    memory().clear();
}

/// How many servers the process-wide memory holds, expired ones included
/// until they are next looked at. For tests.
#[doc(hidden)]
pub fn remembered_servers() -> usize {
    memory().entries.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_routing::Network;

    fn server(index: usize) -> ServerKey {
        ServerKey {
            addr: TargetAddr::Domain(format!("server-{index}.example")),
            port: 443,
            server_name: "www.example.com".to_owned(),
        }
    }

    /// The retry's profile is one REALITY already accepts and has no hybrid
    /// share, and every name the watch covers is one that has it.
    #[test]
    fn the_short_profile_is_an_existing_reality_profile_without_the_hybrid_share() {
        assert_eq!(
            xray_utls::normalize_reality_supported_fingerprint(REALITY_SHORT_HELLO_FINGERPRINT),
            Some(REALITY_SHORT_HELLO_FINGERPRINT)
        );
        assert!(!xray_utls::is_reality_fingerprint_hybrid(
            REALITY_SHORT_HELLO_FINGERPRINT
        ));
        assert!(crate::utls_profiles::reality_profile_for_fingerprint(
            REALITY_SHORT_HELLO_FINGERPRINT
        )
        .is_some_and(|profile| profile
            .key_shares
            .iter()
            .all(|share| share.key_exchange_len <= 32)));
    }

    #[test]
    fn an_outcome_is_recalled_until_its_time_is_up_and_then_forgotten() {
        let mut memory = HelloMemory::new();
        let start = Instant::now();
        memory.remember(server(1), ShortHelloVerdict::Works, start);
        memory.remember(server(2), ShortHelloVerdict::DoesNotHelp, start);

        let late = start + REALITY_HELLO_MEMORY_TTL - Duration::from_millis(1);
        assert_eq!(
            memory.recall(&server(1), late),
            Some(ShortHelloVerdict::Works)
        );
        assert_eq!(
            memory.recall(&server(2), late),
            Some(ShortHelloVerdict::DoesNotHelp)
        );
        assert_eq!(memory.recall(&server(3), late), None);

        let after = start + REALITY_HELLO_MEMORY_TTL;
        assert_eq!(memory.recall(&server(1), after), None);
        assert_eq!(memory.entries.len(), 1, "an expired entry is dropped");
        assert_eq!(memory.recall(&server(2), after), None);
        assert!(memory.entries.is_empty());
    }

    #[test]
    fn a_new_outcome_for_a_server_replaces_the_old_one() {
        let mut memory = HelloMemory::new();
        let start = Instant::now();
        memory.remember(server(1), ShortHelloVerdict::Works, start);
        let later = start + Duration::from_secs(60);
        memory.remember(server(1), ShortHelloVerdict::DoesNotHelp, later);

        assert_eq!(memory.entries.len(), 1);
        assert_eq!(
            memory.recall(&server(1), start + REALITY_HELLO_MEMORY_TTL),
            Some(ShortHelloVerdict::DoesNotHelp),
            "the new outcome has its own time"
        );
        memory.forget(&server(1));
        assert!(memory.entries.is_empty());
    }

    #[test]
    fn the_memory_holds_its_capacity_and_the_oldest_goes_first() {
        let mut memory = HelloMemory::new();
        let start = Instant::now();
        for index in 0..REALITY_HELLO_MEMORY_CAPACITY + 3 {
            memory.remember(server(index), ShortHelloVerdict::Works, start);
            assert!(memory.entries.len() <= REALITY_HELLO_MEMORY_CAPACITY);
        }
        assert_eq!(memory.entries.len(), REALITY_HELLO_MEMORY_CAPACITY);
        for index in 0..3 {
            assert_eq!(memory.recall(&server(index), start), None, "{index}");
        }
        assert_eq!(
            memory.recall(&server(3), start),
            Some(ShortHelloVerdict::Works)
        );
        assert_eq!(
            memory.recall(&server(REALITY_HELLO_MEMORY_CAPACITY + 2), start),
            Some(ShortHelloVerdict::Works)
        );

        // Entries whose time is up make room before a live one is pushed out.
        let after = start + REALITY_HELLO_MEMORY_TTL;
        memory.remember(server(1000), ShortHelloVerdict::Works, after);
        assert_eq!(memory.entries.len(), 1);

        memory.clear();
        assert!(memory.entries.is_empty());
        assert_eq!(memory.entries.capacity(), 0, "the buffer goes too");
    }

    /// Two servers differ by any of address, port and server name.
    #[test]
    fn a_server_is_its_address_port_and_server_name() {
        let config = |server_name: &str| RealityClientConfig {
            server_name: server_name.to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [0; 32],
            short_id: Vec::new(),
            spider_x: String::new(),
            mldsa65_verify: None,
        };
        let target = |host: &str, port: u16| {
            Target::new(TargetAddr::Domain(host.to_owned()), port, Network::Tcp)
        };
        let base = ServerKey::new(&target("a.example", 443), &config("www.example.com"));
        assert_eq!(
            base,
            ServerKey::new(&target("a.example", 443), &config("www.example.com"))
        );
        assert_ne!(
            base,
            ServerKey::new(&target("b.example", 443), &config("www.example.com"))
        );
        assert_ne!(
            base,
            ServerKey::new(&target("a.example", 8443), &config("www.example.com"))
        );
        assert_ne!(
            base,
            ServerKey::new(&target("a.example", 443), &config("www.example.org"))
        );
    }

    /// Only a fingerprint with the hybrid share is planned for, and the
    /// short hello's configuration differs from the dial's in its
    /// fingerprint alone.
    #[test]
    fn only_a_hybrid_fingerprint_is_planned_for() {
        let mut config = RealityClientConfig {
            server_name: "plan.reality-hello.example".to_owned(),
            fingerprint: "chrome".to_owned(),
            public_key: [7; 32],
            short_id: vec![1, 2, 3],
            spider_x: "/x".to_owned(),
            mldsa65_verify: Some(vec![9; 4]),
        };
        let target = Target::new(
            TargetAddr::Domain("plan.reality-hello.example".to_owned()),
            443,
            Network::Tcp,
        );
        assert!(matches!(
            plan(&config, &target),
            Some(HelloPlan::Watched(_))
        ));

        let short = short_hello_config(&config);
        assert_eq!(short.fingerprint, REALITY_SHORT_HELLO_FINGERPRINT);
        assert_eq!(short.server_name, config.server_name);
        assert_eq!(short.public_key, config.public_key);
        assert_eq!(short.short_id, config.short_id);
        assert_eq!(short.spider_x, config.spider_x);
        assert_eq!(short.mldsa65_verify, config.mldsa65_verify);
        assert!(plan(&short, &target).is_none(), "the short hello is final");

        for fingerprint in ["ios", "edge", "qq", "hellofirefox_120"] {
            config.fingerprint = fingerprint.to_owned();
            assert!(plan(&config, &target).is_none(), "{fingerprint}");
        }
    }
}

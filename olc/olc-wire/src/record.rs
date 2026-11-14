//! The v2 record layer: directional keys, the sealed record, its counters and
//! the receive replay window (`internal/crypto/chacha.go`).
//!
//! A record is
//!
//! ```text
//! "OLC2" ‖ counter u64 BE ‖ sender prefix [16] ‖ XChaCha20-Poly1305(plaintext) ‖ tag [16]
//! ```
//!
//! sealed with nonce `prefix ‖ counter BE` and the lane's name as the only
//! associated data (chacha.go:232-262). Each lane numbers its own records
//! from 1 under a prefix of its own, picked at random when the key set is
//! made (chacha.go:205-225); a lane whose counter reaches `u64::MAX` seals
//! nothing more rather than wrap (chacha.go:271-281).
//!
//! Opening checks, in this order, the length, the magic, a counter of 0, the
//! tag, and only then the replay window: 64 records per (lane, sender prefix),
//! for at most 1024 senders over all lanes, the least recently used forgotten
//! first (chacha.go:291-382). A record that fails any check changes nothing.
//!
//! One [`KeySet`] serves every lane of one role for as long as the process
//! runs: its prefixes and counters must survive a reconnect, or the server's
//! replay window rejects the new session's records (W06).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF info of the client-to-server key (chacha.go:31).
pub const CLIENT_TO_SERVER_LABEL: &str = "olcrtc/v2/client-to-server";
/// HKDF info of the server-to-client key (chacha.go:32).
pub const SERVER_TO_CLIENT_LABEL: &str = "olcrtc/v2/server-to-client";
/// The first four bytes of every record (chacha.go:33).
pub const RECORD_MAGIC: [u8; 4] = *b"OLC2";
/// The random per-lane part of the nonce: 24 − 8 bytes (chacha.go:34).
pub const NONCE_PREFIX_SIZE: usize = 16;
/// Magic, counter and prefix (chacha.go:35).
pub const RECORD_HEADER_SIZE: usize = RECORD_MAGIC.len() + 8 + NONCE_PREFIX_SIZE;
/// The Poly1305 tag that ends a record.
pub const TAG_SIZE: usize = 16;
/// Everything a record adds to its plaintext: 44 bytes (chacha.go:43-44).
pub const WIRE_OVERHEAD: usize = RECORD_HEADER_SIZE + TAG_SIZE;
/// Records remembered behind the highest one seen, per sender (chacha.go:36).
pub const REPLAY_WINDOW_SIZE: u64 = 64;
/// Senders remembered over all lanes (chacha.go:37-41).
pub const MAX_REPLAY_SENDERS: usize = 1024;
/// The pre-shared key is 32 bytes (chacha.go:157; runtime.go:95).
pub const PSK_SIZE: usize = 32;

/// Which end of the tunnel a key set is: it seals with its own direction's key
/// and opens with the other's (chacha.go:83-91, 179-188).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Seals client-to-server, opens server-to-client.
    Client,
    /// Seals server-to-client, opens client-to-server.
    Server,
}

impl Role {
    /// The name the Go code prints for the role (chacha.go:94-103).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// A lane: a stream of records with its own counter, prefix and replay
/// window, told apart by the associated data it is sealed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lane {
    /// The smux data session (muxconn/conn.go:73).
    Data,
    /// The isolated control session of a transport with a control plane
    /// (muxconn/conn.go:74).
    Control,
    /// The lossy datagram lane of the UDP relay (tunnelcore/core.go:26).
    Udp,
}

impl Lane {
    /// Every lane, in the order the vectors list them.
    pub const ALL: [Self; 3] = [Self::Data, Self::Control, Self::Udp];

    /// The associated data a record of this lane is sealed with.
    #[must_use]
    pub const fn aad(self) -> &'static [u8] {
        match self {
            Self::Data => b"olcrtc/muxconn/v2/data",
            Self::Control => b"olcrtc/muxconn/v2/control",
            Self::Udp => b"olcrtc/udp/v1",
        }
    }

    /// The short name the vectors and the oracle use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Control => "control",
            Self::Udp => "udp",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Data => 0,
            Self::Control => 1,
            Self::Udp => 2,
        }
    }
}

/// A key set could not be made. The messages are the Go code's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// No key was given (runtime.go:88-90).
    #[error("key required (use -key <hex>)")]
    Required,
    /// The key is not hex (runtime.go:91-94).
    #[error("failed to decode key: {0}")]
    Decode(HexError),
    /// The key is not 32 bytes (chacha.go:157-159; runtime.go:95-97).
    #[error("key must be 32 bytes, got {0}")]
    Size(usize),
}

impl KeyError {
    /// The verdict's name in the vectors.
    #[must_use]
    pub const fn verdict(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Decode(_) => "decode",
            Self::Size(_) => "size",
        }
    }
}

/// Why Go's `hex.DecodeString` refused a string: the first bad byte, or,
/// when every byte is a digit, an odd length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// `encoding/hex: odd length hex string`.
    OddLength,
    /// `encoding/hex: invalid byte: %#U`.
    InvalidByte(u8),
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::OddLength => f.write_str("encoding/hex: odd length hex string"),
            Self::InvalidByte(b) => {
                // `%#U` of the byte as a rune: the quoted character only when
                // Go's `strconv.IsPrint` holds for it.
                write!(f, "encoding/hex: invalid byte: U+{:04X}", b)?;
                let printable = matches!(b, 0x20..=0x7e | 0xa1..=0xac | 0xae..=0xff);
                if printable {
                    write!(f, " '{}'", char::from(b))?;
                }
                Ok(())
            }
        }
    }
}

/// A record could not be sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The lane has used every counter; it seals nothing more rather than wrap
    /// (chacha.go:66, 271-281).
    #[error("seal record: record counter exhausted")]
    CounterExhausted,
    /// The buffer given to [`KeySet::seal_in_place`] cannot hold a record.
    #[error("seal record: buffer of {0} bytes is shorter than the record overhead")]
    BufferTooShort(usize),
}

/// A record did not open. The variants are the Go errors (chacha.go:47-67),
/// and [`OpenError::verdict`] their names in the vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// Shorter than the 44-byte overhead.
    #[error("open record: record too short: got {0}")]
    TooShort(usize),
    /// Not an `OLC2` record.
    #[error("open record: bad record magic")]
    BadMagic,
    /// Counter 0, which no sender uses.
    #[error("open record: invalid record counter")]
    InvalidCounter,
    /// The tag does not match: another key, another lane, or damage.
    #[error("open record: record authentication failed")]
    Authentication,
    /// Authentic, but this sender's record with this counter was taken already.
    #[error("open record: duplicate record")]
    Duplicate,
    /// Authentic, but 64 or more records behind the sender's highest.
    #[error("open record: record too old")]
    TooOld,
    /// The output buffer given to [`KeySet::open_to`] is too small; not a
    /// verdict of the Go code, which grows its buffer.
    #[error("open record: output buffer of {have} bytes, need {need}")]
    BufferTooSmall {
        /// The plaintext length.
        need: usize,
        /// The buffer's length.
        have: usize,
    },
}

impl OpenError {
    /// The verdict's name in the vectors and the oracle.
    #[must_use]
    pub const fn verdict(self) -> &'static str {
        match self {
            Self::TooShort(_) => "too_short",
            Self::BadMagic => "bad_magic",
            Self::InvalidCounter => "invalid_counter",
            Self::Authentication => "auth",
            Self::Duplicate => "duplicate",
            Self::TooOld => "too_old",
            Self::BufferTooSmall { .. } => "buffer_too_small",
        }
    }
}

/// Reordering seen on one lane, summed over its senders (chacha.go:128-134).
/// `skipped − late` is what the window still misses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReorderStats {
    /// Records jumped over when a higher counter arrived.
    pub skipped: u64,
    /// Records that arrived below the highest and inside the window.
    pub late: u64,
}

/// The two directional keys derived from a pre-shared key; wiped on drop.
pub struct DirectionalKeys {
    /// HKDF-SHA256(psk, no salt, [`CLIENT_TO_SERVER_LABEL`]).
    pub client_to_server: [u8; 32],
    /// HKDF-SHA256(psk, no salt, [`SERVER_TO_CLIENT_LABEL`]).
    pub server_to_client: [u8; 32],
}

impl Drop for DirectionalKeys {
    fn drop(&mut self) {
        self.client_to_server.zeroize();
        self.server_to_client.zeroize();
    }
}

impl std::fmt::Debug for DirectionalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectionalKeys(..)")
    }
}

/// Derives both directions' keys from `psk` (chacha.go:160-177).
#[must_use]
pub fn derive_keys(psk: &[u8; PSK_SIZE]) -> DirectionalKeys {
    let hkdf = Hkdf::<Sha256>::new(None, psk);
    let mut keys = DirectionalKeys {
        client_to_server: [0; 32],
        server_to_client: [0; 32],
    };
    hkdf.expand(
        CLIENT_TO_SERVER_LABEL.as_bytes(),
        &mut keys.client_to_server,
    )
    .expect("32 bytes is a valid HKDF-SHA256 length");
    hkdf.expand(
        SERVER_TO_CLIENT_LABEL.as_bytes(),
        &mut keys.server_to_client,
    )
    .expect("32 bytes is a valid HKDF-SHA256 length");
    keys
}

/// One lane's sender: its prefix and the last counter it used
/// (chacha.go:105-109).
#[derive(Debug)]
struct SealState {
    prefix: [u8; NONCE_PREFIX_SIZE],
    counter: AtomicU64,
}

impl SealState {
    /// The next counter, never 0 and never past `u64::MAX` (chacha.go:271-281).
    fn next_counter(&self) -> Result<u64, SealError> {
        self.counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| SealError::CounterExhausted)
    }
}

/// One sender's window on one lane (chacha.go:111-126). 64 bytes.
#[derive(Debug, Clone, Copy)]
struct ReplayEntry {
    prefix: [u8; NONCE_PREFIX_SIZE],
    highest: u64,
    seen: u64,
    skipped: u64,
    late: u64,
    /// When this entry was last inserted or accepted a record; the smallest is
    /// the back of the Go code's LRU list (chacha.go:336, 349, 366-371).
    used: u64,
    lane: Lane,
}

/// Every sender's window, at most [`MAX_REPLAY_SENDERS`] of them
/// (chacha.go:136-142). A vector searched in order: a client sees a handful of
/// senders (the server's lanes), and only authentic records reach it.
#[derive(Debug, Default)]
struct ReplayCache {
    entries: Vec<ReplayEntry>,
    tick: u64,
}

impl ReplayCache {
    /// Records `counter` from (lane, prefix), or says why not
    /// (chacha.go:319-351).
    fn accept(
        &mut self,
        lane: Lane,
        prefix: &[u8; NONCE_PREFIX_SIZE],
        counter: u64,
    ) -> Result<(), OpenError> {
        self.tick += 1;
        let tick = self.tick;
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.lane == lane && &e.prefix == prefix)
        else {
            self.insert(lane, prefix, counter, tick);
            return Ok(());
        };
        if counter > entry.highest {
            let shift = counter - entry.highest;
            entry.skipped += shift - 1;
            entry.seen = if shift >= REPLAY_WINDOW_SIZE {
                1
            } else {
                entry.seen << shift | 1
            };
            entry.highest = counter;
            entry.used = tick;
            return Ok(());
        }
        let age = entry.highest - counter;
        if age >= REPLAY_WINDOW_SIZE {
            return Err(OpenError::TooOld);
        }
        let mask = 1u64 << age;
        if entry.seen & mask != 0 {
            return Err(OpenError::Duplicate);
        }
        entry.seen |= mask;
        entry.late += 1;
        entry.used = tick;
        Ok(())
    }

    /// Adds a sender, forgetting the least recently used one when full
    /// (chacha.go:365-382).
    fn insert(&mut self, lane: Lane, prefix: &[u8; NONCE_PREFIX_SIZE], counter: u64, tick: u64) {
        let entry = ReplayEntry {
            prefix: *prefix,
            highest: counter,
            seen: 1,
            skipped: 0,
            late: 0,
            used: tick,
            lane,
        };
        if self.entries.len() < MAX_REPLAY_SENDERS {
            self.entries.push(entry);
            return;
        }
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.used)
            .map(|(i, _)| i)
            .expect("a full cache is not empty");
        self.entries[oldest] = entry;
    }

    fn stats(&self, lane: Lane) -> ReorderStats {
        self.entries
            .iter()
            .filter(|e| e.lane == lane)
            .fold(ReorderStats::default(), |acc, e| ReorderStats {
                skipped: acc.skipped + e.skipped,
                late: acc.late + e.late,
            })
    }
}

/// The keys of one role: a sender per lane and the shared receive window
/// (chacha.go:144-153). Safe to share between the data, control and datagram
/// lanes of every session of a run.
pub struct KeySet {
    role: Role,
    send: XChaCha20Poly1305,
    receive: XChaCha20Poly1305,
    lanes: [SealState; 3],
    replay: Mutex<ReplayCache>,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl KeySet {
    /// The key set of `role` for a 32-byte `psk`, each lane under a random
    /// prefix (chacha.go:155-225).
    ///
    /// # Errors
    /// [`KeyError::Size`] when `psk` is not 32 bytes.
    pub fn new(psk: &[u8], role: Role) -> Result<Self, KeyError> {
        let mut prefixes = [[0u8; NONCE_PREFIX_SIZE]; 3];
        for prefix in &mut prefixes {
            rand::rngs::OsRng.fill_bytes(prefix);
        }
        Self::with_prefixes(psk, role, prefixes)
    }

    /// [`KeySet::new`] from the 64 hex digits the apps hold
    /// (`runtime.SetupKeySet`, runtime.go:86-103).
    ///
    /// # Errors
    /// [`KeyError::Required`] for an empty string, [`KeyError::Decode`] when it
    /// is not hex, [`KeyError::Size`] when it is not 32 bytes.
    pub fn from_hex(psk_hex: &str, role: Role) -> Result<Self, KeyError> {
        if psk_hex.is_empty() {
            return Err(KeyError::Required);
        }
        let mut psk = decode_hex(psk_hex).map_err(KeyError::Decode)?;
        let keys = Self::new(&psk, role);
        psk.zeroize();
        keys
    }

    /// A key set whose lanes use the given prefixes (data, control, udp)
    /// instead of random ones. For tests and vectors: two key sets with one
    /// prefix and one key collide in the peer's replay window.
    ///
    /// # Errors
    /// [`KeyError::Size`] when `psk` is not 32 bytes.
    pub fn with_prefixes(
        psk: &[u8],
        role: Role,
        prefixes: [[u8; NONCE_PREFIX_SIZE]; 3],
    ) -> Result<Self, KeyError> {
        let psk: &[u8; PSK_SIZE] = psk.try_into().map_err(|_| KeyError::Size(psk.len()))?;
        let keys = derive_keys(psk);
        let (send, receive) = match role {
            Role::Client => (&keys.client_to_server, &keys.server_to_client),
            Role::Server => (&keys.server_to_client, &keys.client_to_server),
        };
        let lane = |prefix| SealState {
            prefix,
            counter: AtomicU64::new(0),
        };
        let [data, control, udp] = prefixes;
        Ok(Self {
            role,
            send: cipher(send),
            receive: cipher(receive),
            lanes: [lane(data), lane(control), lane(udp)],
            replay: Mutex::new(ReplayCache::default()),
        })
    }

    /// The role this key set seals as.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The prefix `lane`'s records carry.
    #[must_use]
    pub fn prefix(&self, lane: Lane) -> [u8; NONCE_PREFIX_SIZE] {
        self.lanes[lane.index()].prefix
    }

    /// Moves the counter `lane` used last up to `counter`, so its next record
    /// carries `counter + 1`. For the vectors, which seal at fixed counters.
    /// It only ever moves forward: a counter once used is never used again,
    /// whoever calls this.
    #[doc(hidden)]
    pub fn set_last_counter(&self, lane: Lane, counter: u64) {
        self.lanes[lane.index()]
            .counter
            .fetch_max(counter, Ordering::AcqRel);
    }

    /// Seals the record laid out in `record` in place:
    /// `[RECORD_HEADER_SIZE bytes, overwritten][plaintext][TAG_SIZE bytes, overwritten]`.
    /// The record is all of `record` (chacha.go:243-262).
    ///
    /// # Errors
    /// [`SealError::BufferTooShort`] when `record` is shorter than
    /// [`WIRE_OVERHEAD`], [`SealError::CounterExhausted`] when the lane has no
    /// counter left; `record` is then unchanged.
    pub fn seal_in_place(&self, lane: Lane, record: &mut [u8]) -> Result<(), SealError> {
        if record.len() < WIRE_OVERHEAD {
            return Err(SealError::BufferTooShort(record.len()));
        }
        let state = &self.lanes[lane.index()];
        let counter = state.next_counter()?;
        let (header, rest) = record.split_at_mut(RECORD_HEADER_SIZE);
        header[..4].copy_from_slice(&RECORD_MAGIC);
        header[4..12].copy_from_slice(&counter.to_be_bytes());
        header[12..].copy_from_slice(&state.prefix);
        let (body, tag) = rest.split_at_mut(rest.len() - TAG_SIZE);
        let sealed = self
            .send
            .encrypt_inout_detached(
                &nonce(&state.prefix, counter),
                lane.aad(),
                InOutBuf::from(body),
            )
            .expect("a record's plaintext is far below the AEAD's limits");
        tag.copy_from_slice(sealed.as_slice());
        Ok(())
    }

    /// Appends one record sealing `plaintext` to `out` (`SealInto`,
    /// chacha.go:232-240).
    ///
    /// # Errors
    /// [`SealError::CounterExhausted`] when the lane has no counter left; `out`
    /// is then unchanged.
    pub fn seal_into(
        &self,
        lane: Lane,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), SealError> {
        let start = out.len();
        out.resize(start + RECORD_HEADER_SIZE, 0);
        out.extend_from_slice(plaintext);
        out.resize(out.len() + TAG_SIZE, 0);
        let result = self.seal_in_place(lane, &mut out[start..]);
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    /// Checks everything but the tag and the window, and returns the counter
    /// and prefix (chacha.go:292-303).
    fn header(record: &[u8]) -> Result<(u64, [u8; NONCE_PREFIX_SIZE]), OpenError> {
        if record.len() < WIRE_OVERHEAD {
            return Err(OpenError::TooShort(record.len()));
        }
        if record[..4] != RECORD_MAGIC {
            return Err(OpenError::BadMagic);
        }
        let counter = u64::from_be_bytes(record[4..12].try_into().expect("8 bytes"));
        if counter == 0 {
            return Err(OpenError::InvalidCounter);
        }
        let prefix = record[12..RECORD_HEADER_SIZE].try_into().expect("16 bytes");
        Ok((counter, prefix))
    }

    fn accept(
        &self,
        lane: Lane,
        prefix: &[u8; NONCE_PREFIX_SIZE],
        counter: u64,
    ) -> Result<(), OpenError> {
        self.replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accept(lane, prefix, counter)
    }

    /// Opens `record` in place and returns its plaintext, a slice of it
    /// (`OpenInto`, chacha.go:288-317).
    ///
    /// # Errors
    /// The [`OpenError`] the Go code gives. A record refused before its tag is
    /// checked is unchanged; one refused by the replay window has been
    /// decrypted in place all the same.
    pub fn open_in_place<'r>(
        &self,
        lane: Lane,
        record: &'r mut [u8],
    ) -> Result<&'r mut [u8], OpenError> {
        let (counter, prefix) = Self::header(record)?;
        let (_, rest) = record.split_at_mut(RECORD_HEADER_SIZE);
        let (body, tag) = rest.split_at_mut(rest.len() - TAG_SIZE);
        let tag = Tag::try_from(&*tag).expect("16 bytes");
        self.receive
            .decrypt_inout_detached(
                &nonce(&prefix, counter),
                lane.aad(),
                InOutBuf::from(&mut *body),
                &tag,
            )
            .map_err(|_| OpenError::Authentication)?;
        self.accept(lane, &prefix, counter)?;
        Ok(body)
    }

    /// Opens `record` into the start of `out` and returns the plaintext's
    /// length; `record` is not changed.
    ///
    /// # Errors
    /// The [`OpenError`] the Go code gives, or [`OpenError::BufferTooSmall`]
    /// when `out` is shorter than the plaintext.
    pub fn open_to(&self, lane: Lane, record: &[u8], out: &mut [u8]) -> Result<usize, OpenError> {
        let (counter, prefix) = Self::header(record)?;
        let body = &record[RECORD_HEADER_SIZE..record.len() - TAG_SIZE];
        let need = body.len();
        let Some(out) = out.get_mut(..need) else {
            return Err(OpenError::BufferTooSmall {
                need,
                have: out.len(),
            });
        };
        let tag = Tag::try_from(&record[record.len() - TAG_SIZE..]).expect("16 bytes");
        let buf = InOutBuf::new(body, out).expect("equal lengths");
        self.receive
            .decrypt_inout_detached(&nonce(&prefix, counter), lane.aad(), buf, &tag)
            .map_err(|_| OpenError::Authentication)?;
        self.accept(lane, &prefix, counter)?;
        Ok(need)
    }

    /// Appends the plaintext of `record` to `out` and returns its length; on
    /// an error `out` is unchanged.
    ///
    /// # Errors
    /// The [`OpenError`] the Go code gives.
    pub fn open_into(
        &self,
        lane: Lane,
        record: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<usize, OpenError> {
        Self::header(record)?;
        let start = out.len();
        out.resize(start + record.len() - WIRE_OVERHEAD, 0);
        let result = self.open_to(lane, record, &mut out[start..]);
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    /// The reordering seen on `lane` from the senders still remembered
    /// (chacha.go:353-363).
    #[must_use]
    pub fn reorder_stats(&self, lane: Lane) -> ReorderStats {
        self.replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stats(lane)
    }
}

fn nonce(prefix: &[u8; NONCE_PREFIX_SIZE], counter: u64) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..NONCE_PREFIX_SIZE].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_SIZE..].copy_from_slice(&counter.to_be_bytes());
    XNonce::from(nonce)
}

/// A cipher under `key`, built through a key buffer that is wiped after; the
/// cipher wipes its own copy when dropped (chacha20poly1305's `zeroize`).
fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut k = Key::default();
    k.copy_from_slice(key);
    let c = XChaCha20Poly1305::new(&k);
    k.as_mut_slice().zeroize();
    c
}

/// Decodes hex as Go's `hex.DecodeString` does: either case; the pairs are
/// checked first, then the odd byte, then the length (`hex.Decode`).
fn decode_hex(text: &str) -> Result<Vec<u8>, HexError> {
    fn digit(c: u8) -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(HexError::InvalidByte(c)),
        }
    }
    let text = text.as_bytes();
    let pairs = text.chunks_exact(2);
    let odd = pairs.remainder().first().copied();
    // Sized once, so no key byte is left behind in a grown-out buffer; wiped
    // on every refusal.
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(text.len() / 2));
    for pair in pairs {
        out.push(digit(pair[0])? << 4 | digit(pair[1])?);
    }
    if let Some(c) = odd {
        digit(c)?;
        return Err(HexError::OddLength);
    }
    Ok(std::mem::take(&mut *out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: [u8; 32] = [7; 32];

    #[test]
    fn hot_structs_stay_small() {
        // Memory model §16: the per-record and per-sender state is fixed.
        assert_eq!(std::mem::size_of::<ReplayEntry>(), 64);
        assert_eq!(std::mem::size_of::<SealState>(), 24);
        // The cache's ceiling: 1024 senders of 64 bytes.
        assert_eq!(
            MAX_REPLAY_SENDERS * std::mem::size_of::<ReplayEntry>(),
            64 * 1024
        );
    }

    #[test]
    fn the_counter_hook_never_moves_a_counter_back() {
        let keys = KeySet::new(&PSK, Role::Client).unwrap();
        let mut out = Vec::new();
        keys.set_last_counter(Lane::Data, 10);
        keys.seal_into(Lane::Data, b"a", &mut out).unwrap();
        assert_eq!(out[4..12], 11u64.to_be_bytes());
        keys.set_last_counter(Lane::Data, 3);
        out.clear();
        keys.seal_into(Lane::Data, b"b", &mut out).unwrap();
        assert_eq!(out[4..12], 12u64.to_be_bytes(), "a nonce is never reused");
    }

    #[test]
    fn counter_exhaustion_does_not_wrap() {
        // TestCounterExhaustionDoesNotWrap (chacha_test.go).
        let keys = KeySet::new(&PSK, Role::Client).unwrap();
        keys.set_last_counter(Lane::Data, u64::MAX - 1);
        let mut out = Vec::new();
        keys.seal_into(Lane::Data, b"last", &mut out).unwrap();
        assert_eq!(out[4..12], u64::MAX.to_be_bytes());
        let len = out.len();
        assert_eq!(
            keys.seal_into(Lane::Data, b"x", &mut out),
            Err(SealError::CounterExhausted)
        );
        assert_eq!(out.len(), len, "a refused seal leaves the buffer alone");
        // The other lanes number their own records.
        keys.seal_into(Lane::Control, b"x", &mut out).unwrap();
        assert_eq!(out[len + 4..len + 12], 1u64.to_be_bytes());
    }

    #[test]
    fn a_failed_open_leaves_the_record_and_the_window_alone() {
        let client = KeySet::new(&PSK, Role::Client).unwrap();
        let server = KeySet::new(&PSK, Role::Server).unwrap();
        let mut record = Vec::new();
        client.seal_into(Lane::Data, b"hello", &mut record).unwrap();
        let mut bad = record.clone();
        *bad.last_mut().unwrap() ^= 1;
        let copy = bad.clone();
        assert_eq!(
            server.open_in_place(Lane::Data, &mut bad).unwrap_err(),
            OpenError::Authentication
        );
        assert_eq!(bad, copy);
        let mut plain = Vec::new();
        assert_eq!(server.open_into(Lane::Data, &record, &mut plain), Ok(5));
        assert_eq!(plain, b"hello");
        assert_eq!(
            server.open_into(Lane::Data, &record, &mut plain),
            Err(OpenError::Duplicate)
        );
        assert_eq!(plain, b"hello", "a refused open leaves the output alone");
    }

    #[test]
    fn open_to_wants_room_for_the_plaintext() {
        let client = KeySet::new(&PSK, Role::Client).unwrap();
        let server = KeySet::new(&PSK, Role::Server).unwrap();
        let mut record = Vec::new();
        client
            .seal_into(Lane::Udp, b"datagram", &mut record)
            .unwrap();
        let mut small = [0u8; 7];
        assert_eq!(
            server.open_to(Lane::Udp, &record, &mut small),
            Err(OpenError::BufferTooSmall { need: 8, have: 7 })
        );
        let mut room = [0u8; 8];
        assert_eq!(server.open_to(Lane::Udp, &record, &mut room), Ok(8));
        assert_eq!(&room, b"datagram");
    }

    #[test]
    fn from_hex_refuses_what_setup_key_set_refuses() {
        assert_eq!(
            KeySet::from_hex("", Role::Client).unwrap_err(),
            KeyError::Required
        );
        assert_eq!(
            KeySet::from_hex("abc", Role::Client).unwrap_err(),
            KeyError::Decode(HexError::OddLength)
        );
        assert_eq!(
            KeySet::from_hex("zz", Role::Client).unwrap_err(),
            KeyError::Decode(HexError::InvalidByte(b'z'))
        );
        assert_eq!(
            KeySet::from_hex("abz", Role::Client).unwrap_err(),
            KeyError::Decode(HexError::InvalidByte(b'z'))
        );
        assert_eq!(
            KeySet::from_hex("abcd", Role::Client).unwrap_err(),
            KeyError::Size(2)
        );
        assert!(KeySet::from_hex(&"Ab".repeat(32), Role::Server).is_ok());
    }
}

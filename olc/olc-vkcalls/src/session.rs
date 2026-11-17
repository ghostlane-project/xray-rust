// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! One connection attempt's peer connection (`negotiate`, `acceptOffer`,
//! `reanswer`, `openControlChannels` and `iceServersOf` of `vkcalls.go`):
//! the SFU offers, we answer as the DTLS client, and the answer the SFU is
//! sent is shaped from its own offer.
//!
//! The Go engine runs pion; here the peer is [`olc_rtc::peer::Peer`]
//! (str0m). What that changes, none of it on the wire to the SFU:
//!
//! - str0m is given the view of the offer ([`offer_view`]) with three more
//!   changes ([`for_stack`]): every `a=setup` made `passive` (pion is told
//!   its role by `SetAnsweringDTLSRole`, str0m takes it from the offer), the
//!   abs-send-time line taken out of the publish slot (the Go engine writes
//!   none on what it publishes, str0m writes every extension a slot names),
//!   and the sections put in the order str0m holds them
//!   ([`olc_rtc::sdp::in_order`]);
//! - the shaper is given our fields ([`Native`]) directly: the ICE
//!   credentials and the fingerprint of the peer, the CNAME str0m reports
//!   under, and the track's ids in the Go engine's form ([`TrackIds`]).
//!   str0m's own answer text would do for the first three (a test holds it
//!   to that), but its msid is str0m's.
//!
//! Memory: one attempt holds its peer (olc-rtc's bounds), the view's memo
//! (one name per payload type and kind), the shaper's state and the mids of
//! the description last applied ([`crate::answer::MAX_SDP_SECTIONS`] at
//! most). While an offer is answered, the offer, its view, the text str0m
//! is given and the answer are alive together: four texts of the offer's
//! size ([`crate::signaling::READ_LIMIT`] at most each), all dropped but
//! the answer when the call returns.

use std::time::Instant;

use olc_rtc::media::{with_codecs, CodecLine, ResendCache, RtpOut, SendLine};
use olc_rtc::peer::{Peer, PeerConfig, PeerEvent};
use olc_rtc::sdp::{in_order, section_mids};
use olc_rtc::str0m::change::{SdpAnswer, SdpOffer};
use olc_rtc::str0m::channel::{ChannelConfig, ChannelId, Reliability};
use olc_rtc::str0m::format::{Codec, FormatParams};
use olc_rtc::str0m::media::{Mid, Pt, Rid};
use olc_rtc::turn::TurnServer;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::answer::{self, shape_answer, Native, ShapeError, ShapeState};
use crate::auth::{ICE_TEXT_MAX, ICE_URLS_MAX};
use crate::negotiate::{codec_table, offer_view, publish_mid, MediaKind, ViewError, ViewMemo};

/// The layer the engine publishes: the SFU is told three (`l`, `m`, `h`)
/// and binds this one by its rid.
pub const PUBLISH_RID: &str = "l";
/// The codecs of the tracks we publish, as the view is told them
/// (`publishCodecs`: the video transport's one VP8 track).
pub const PUBLISH_CODECS: [&str; 1] = ["vp8"];
/// The service channel the stream registry arrives on; made first.
pub const NOTIFICATION_CHANNEL: &str = "producerNotification";
/// The service channel the engine's commands go out on; made second.
pub const COMMAND_CHANNEL: &str = "producerCommand";
/// Not in Go: the entries read of an `ice_servers` text. The provider
/// writes two (STUN, TURN).
pub const ICE_SERVERS_MAX: usize = 8;

const ABS_SEND_TIME: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

// ---------------------------------------------------------------------------
// The service's ICE servers.

/// One entry of the provider's `ice_servers` text (`iceServersOf`'s
/// `serverJSON`). The credential is wiped when the entry goes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct IceServer {
    /// `urls`.
    pub urls: Vec<String>,
    /// `username`; empty when the entry has none.
    pub username: String,
    /// `credential`; empty when the entry has none.
    pub credential: String,
}

impl std::fmt::Debug for IceServer {
    /// The servers are the service's and the credential is the guest's:
    /// neither is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceServer")
            .field("urls", &self.urls.len())
            .field("username_len", &self.username.len())
            .field("credential_len", &self.credential.len())
            .finish()
    }
}

impl Drop for IceServer {
    fn drop(&mut self) {
        self.username.zeroize();
        self.credential.zeroize();
    }
}

/// A string field of Go's struct: a string or `null`.
enum Text {
    Null,
    Value(String),
    TooLong,
}

struct TextSeed;

impl<'de> DeserializeSeed<'de> for TextSeed {
    type Value = Text;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Text, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl Visitor<'_> for TextSeed {
    type Value = Text;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a string")
    }
    fn visit_unit<E>(self) -> Result<Text, E> {
        Ok(Text::Null)
    }
    fn visit_str<E>(self, s: &str) -> Result<Text, E> {
        // Before the copy.
        Ok(if s.len() > ICE_TEXT_MAX {
            Text::TooLong
        } else {
            Text::Value(s.to_owned())
        })
    }
}

/// `[]string`: a list of strings (a `null` among them is an empty one), or
/// `null`, which leaves the field as it was.
struct UrlsSeed<'a>(&'a mut Vec<String>);

impl<'de> DeserializeSeed<'de> for UrlsSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UrlsSeed<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a list of strings")
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.0.clear();
        while let Some(url) = seq.next_element_seed(TextSeed)? {
            let url = match url {
                Text::Null => String::new(),
                Text::Value(url) => url,
                // Not copied; a URL this long is no server's.
                Text::TooLong => continue,
            };
            if self.0.len() < ICE_URLS_MAX {
                self.0.push(url);
            }
        }
        Ok(())
    }
}

/// One element of the list: an object or `null`.
struct ServerSeed;

/// An entry as it was read, and whether a credential text was past its
/// bound (the entry is then no use).
struct ReadServer {
    server: IceServer,
    over: bool,
}

impl<'de> DeserializeSeed<'de> for ServerSeed {
    type Value = ReadServer;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<ReadServer, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ServerSeed {
    type Value = ReadServer;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an object")
    }
    fn visit_unit<E>(self) -> Result<ReadServer, E> {
        Ok(ReadServer {
            server: IceServer::default(),
            over: false,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ReadServer, A::Error> {
        let mut server = IceServer::default();
        let (mut name_over, mut credential_over) = (false, false);
        // `encoding/json`: a field by its name in any case, the last of a
        // repeated name, an unknown name passed over.
        while let Some(key) = map.next_key::<String>()? {
            if key.eq_ignore_ascii_case("urls") {
                map.next_value_seed(UrlsSeed(&mut server.urls))?;
            } else if key.eq_ignore_ascii_case("username") || key.eq_ignore_ascii_case("credential")
            {
                let (into, over) = if key.eq_ignore_ascii_case("username") {
                    (&mut server.username, &mut name_over)
                } else {
                    (&mut server.credential, &mut credential_over)
                };
                match map.next_value_seed(TextSeed)? {
                    Text::Null => {}
                    Text::Value(value) => {
                        into.zeroize();
                        *into = value;
                        *over = false;
                    }
                    Text::TooLong => {
                        into.zeroize();
                        into.clear();
                        *over = true;
                    }
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(ReadServer {
            server,
            over: name_over || credential_over,
        })
    }
}

/// The whole text: a list or `null`.
struct Servers(Vec<IceServer>);

impl<'de> Deserialize<'de> for Servers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct List;
        impl<'de> Visitor<'de> for List {
            type Value = Servers;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a list")
            }
            fn visit_unit<E>(self) -> Result<Servers, E> {
                Ok(Servers(Vec::new()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Servers, A::Error> {
                let mut out = Vec::new();
                while let Some(read) = seq.next_element_seed(ServerSeed)? {
                    // `iceServersOf`: an entry with no URL is skipped.
                    if read.server.urls.is_empty() || read.over || out.len() >= ICE_SERVERS_MAX {
                        continue;
                    }
                    out.push(read.server);
                }
                Ok(Servers(out))
            }
        }
        deserializer.deserialize_any(List)
    }
}

/// The servers of the provider's `ice_servers` text (`iceServersOf`): a
/// list of `{urls, username, credential}` read as `encoding/json` reads it
/// into Go's struct; an entry without a URL is skipped, and a text that
/// cannot be read gives none (the SFU's own candidates arrive in the
/// offer).
///
/// Bounds Go does not have: [`ICE_SERVERS_MAX`] entries, each with
/// [`ICE_URLS_MAX`] URLs of [`ICE_TEXT_MAX`] bytes; what is past them is
/// left out, and so is an entry whose user name or credential is longer.
#[must_use]
pub fn ice_servers_of(raw: &str) -> Vec<IceServer> {
    serde_json::from_str::<Servers>(raw)
        .map(|servers| servers.0)
        .unwrap_or_default()
}

/// The TURN servers the peer allocates on, from the service's list (K9):
/// every `turn:` URL over UDP or TCP, in the list's order; `stun:` entries
/// are left out (the peer asks no STUN server: the SFU's candidates are in
/// the offer and it learns ours from our checks), and `turns:` ones too
/// unless the build has Chrome's TLS ([`olc_rtc::turn::servers`]).
#[must_use]
pub fn turn_servers(servers: &[IceServer]) -> Vec<TurnServer> {
    let mut out: Vec<TurnServer> = Vec::new();
    for server in servers {
        for turn in olc_rtc::turn::servers(&server.urls, &server.username, &server.credential) {
            if !out.contains(&turn) {
                out.push(turn);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The answer's own names.

/// The ids of the track we publish, as the answer's `a=msid` names them.
/// Go's video transport makes them (`common.NewVideoTrack`): the stream
/// `olcrtc-<8 hex>`, the track `vp8channel-<8 hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackIds {
    /// The stream id (`a=msid-semantic: WMS <stream>`).
    pub stream: String,
    /// The track id.
    pub track: String,
}

impl TrackIds {
    /// Fresh ids in Go's form.
    #[must_use]
    pub fn random() -> Self {
        let id = || format!("{:08x}", rand::random::<u32>());
        TrackIds {
            stream: format!("olcrtc-{}", id()),
            track: format!("vp8channel-{}", id()),
        }
    }
}

// ---------------------------------------------------------------------------
// The negotiation.

/// Why an offer was not answered. The texts are Go's as far as they go;
/// none quotes the offer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NegotiateError {
    /// The view of the offer.
    #[error(transparent)]
    View(#[from] ViewError),
    /// The shaper; [`ShapeError::NoPublish`] also for an offer with no slot
    /// to publish VP8 into.
    #[error(transparent)]
    Shape(#[from] ShapeError),
    /// The peer could not be made (its socket).
    #[error("vkcalls: new peer connection: {0}")]
    NewPeer(String),
    /// The stack refused the first offer.
    #[error("vkcalls: set remote description: {0}")]
    Remote(String),
    /// The stack refused a later offer.
    #[error("vkcalls: renegotiation remote: {0}")]
    RenegotiationRemote(String),
    /// The peer's own candidates.
    #[error("vkcalls: set local description: {0}")]
    Local(String),
    /// Not in Go, whose stack keeps a codec table per kind: the description
    /// gives this payload type two meanings among the codecs the peer is
    /// built with (across audio and video, or a codec and an RTX), or
    /// names a payload type past 127. str0m keeps one table, and its rule
    /// of one claim per payload type is an `assert!` (plan K2).
    #[error("vkcalls: payload type {0} has two meanings for the stack")]
    Payload(u8),
}

/// What the payload types mean to the stack, as far as it claims them: the
/// codecs the peer is built with ([`codec_lines`]: VP8, video `red`, Opus)
/// and the RTX of each, and audio `red`, which str0m attaches to an audio
/// codec. Every other codec has no parameters in the peer and claims
/// nothing.
///
/// The view settles one meaning per payload type within a kind, as Go's
/// stack needs it. str0m has one table for both kinds, locks a codec to the
/// number an offer gives it, and asserts on the next section when two of
/// its codecs hold one number: a panic in the join, in a rejoin (the
/// supervisor's task) or in the notification loop. So a description is
/// admitted here before str0m sees it, and what earlier descriptions of the
/// attempt claimed stands (str0m's locks outlive an offer).
#[derive(Clone, Copy)]
struct StackClaims([u8; 128]);

/// A claim of [`StackClaims`]: 0 is none; an RTX is its codec's claim and
/// this bit.
const CLAIM_RTX: u8 = 0x10;

impl StackClaims {
    fn new() -> Self {
        StackClaims([0; 128])
    }

    /// The claim an rtpmap's encoding name makes in a section of `kind`.
    fn claim(kind: &str, name: &str) -> u8 {
        let is = |codec: &str| name.eq_ignore_ascii_case(codec);
        match kind {
            answer::KIND_VIDEO if is("VP8") => 1,
            answer::KIND_VIDEO if is("red") => 2,
            answer::KIND_AUDIO if is("opus") => 3,
            answer::KIND_AUDIO if is("red") => 4,
            _ => 0,
        }
    }

    /// `a=rtpmap:<pt> <name>/...`, read more loosely than the view reads
    /// it: a line the view passes over still reaches the stack.
    fn rtpmap(line: &str) -> Option<(Option<u8>, &str)> {
        let rest = line.strip_prefix("a=rtpmap:")?;
        let (pt, what) = rest.split_once(|c: char| c.is_ascii_whitespace())?;
        let name = what.trim_start().split('/').next().unwrap_or("").trim();
        Some((pt.trim().parse::<u8>().ok().filter(|pt| *pt < 128), name))
    }

    /// The payload type and the `apt` of an `a=fmtp` line that has one.
    fn apt(line: &str) -> Option<(u8, u8)> {
        let rest = line.strip_prefix("a=fmtp:")?;
        let (pt, params) = rest.split_once(|c: char| c.is_ascii_whitespace())?;
        let apt = params
            .split(';')
            .find_map(|param| param.trim().strip_prefix("apt="))?;
        Some((pt.trim().parse().ok()?, apt.trim().parse().ok()?))
    }

    /// Takes the description `given` in: every claim it makes is new or
    /// the one already there.
    ///
    /// # Errors
    ///
    /// [`NegotiateError::Payload`] with the payload type that would have
    /// two; [`ShapeError::SdpTooLarge`].
    fn admit(&mut self, given: &str) -> Result<(), NegotiateError> {
        for section in answer::sections(given)? {
            let kind = section.kind();
            if kind != answer::KIND_AUDIO && kind != answer::KIND_VIDEO {
                continue;
            }
            // A number past 127 is no payload type, and str0m's table has
            // 128 places.
            let head = section.0.first().copied().unwrap_or("");
            for field in head.split_whitespace().skip(3) {
                if field.parse::<u32>().is_ok_and(|pt| pt > 127) {
                    return Err(NegotiateError::Payload(u8::MAX));
                }
            }
            let mut named: Vec<(u8, u8)> = Vec::new();
            let mut resends: Vec<u8> = Vec::new();
            for line in &section.0 {
                let Some((pt, name)) = Self::rtpmap(line.trim_end()) else {
                    continue;
                };
                let Some(pt) = pt else {
                    return Err(NegotiateError::Payload(u8::MAX));
                };
                if name.eq_ignore_ascii_case("rtx") {
                    resends.push(pt);
                } else {
                    named.push((pt, Self::claim(kind, name)));
                }
            }
            for line in &section.0 {
                let Some((pt, apt)) = Self::apt(line.trim_end()) else {
                    continue;
                };
                if !resends.contains(&pt) {
                    continue;
                }
                let of: Vec<u8> = named
                    .iter()
                    .filter(|(of, claim)| *of == apt && *claim != 0)
                    .map(|(_, claim)| claim | CLAIM_RTX)
                    .collect();
                named.extend(of.into_iter().map(|claim| (pt, claim)));
            }
            for (pt, claim) in named {
                if claim == 0 {
                    continue;
                }
                let held = &mut self.0[usize::from(pt)];
                if *held != 0 && *held != claim {
                    return Err(NegotiateError::Payload(pt));
                }
                *held = claim;
            }
        }
        Ok(())
    }
}

/// One connection attempt's peer connection and what its answers are made
/// from: the view's memo, the shaper's state and our fields, kept across
/// the attempt's renegotiations and never across attempts.
pub struct Negotiation {
    peer: Peer,
    memo: ViewMemo,
    shape: ShapeState,
    /// The mids of the description last applied, in str0m's order.
    known: Vec<String>,
    native: Native,
    line: SendLine,
    /// The payload type video `red` arrives at, when the offer names one.
    red: Option<u8>,
    notification: ChannelId,
    command: ChannelId,
    /// What the descriptions given to the stack so far claim.
    claims: StackClaims,
}

impl std::fmt::Debug for Negotiation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Negotiation")
            .field("sections", &self.known.len())
            .field("shape", &self.shape)
            .field("publish", &self.line)
            .finish_non_exhaustive()
    }
}

/// A peer connection that answered its first offer.
#[derive(Debug)]
pub struct Opened {
    /// The attempt's negotiation.
    pub negotiation: Negotiation,
    /// The peer's events ([`olc_rtc::peer::EVENT_QUEUE`] of them wait at
    /// most).
    pub events: mpsc::Receiver<PeerEvent>,
    /// The shaped answer, for `accept-producer`.
    pub answer: String,
}

/// The offer as str0m is given it: `view` with every `a=setup` made
/// `passive` (we are the DTLS client whatever the offer says, as Go's
/// `SetAnsweringDTLSRole`), the abs-send-time line out of every publish
/// slot (D9), and the sections `known` names first, in its order.
///
/// # Errors
///
/// [`ShapeError::SdpTooLarge`].
pub fn for_stack(view: &str, known: &[String]) -> Result<String, ShapeError> {
    let publish: Vec<bool> = answer::sections(view)?
        .iter()
        .map(|section| {
            section.kind() == answer::KIND_VIDEO
                && section.direction() == Some(answer::DIR_RECV_ONLY)
        })
        .collect();
    let mut out = String::with_capacity(view.len());
    let mut section = 0usize;
    for line in answer::lines(view).filter(|line| !line.is_empty()) {
        if line.starts_with("m=") {
            section += 1;
        }
        // `section` is one past the index of the section the line is in.
        let in_publish = section
            .checked_sub(1)
            .and_then(|index| publish.get(index))
            .copied()
            .unwrap_or(false);
        if line.starts_with("a=setup:") {
            out.push_str("a=setup:passive");
        } else if in_publish && is_abs_send_time(line) {
            continue;
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    Ok(in_order(&out, known))
}

/// Whether `line` is the `a=extmap` of abs-send-time.
fn is_abs_send_time(line: &str) -> bool {
    line.strip_prefix("a=extmap:")
        .and_then(|rest| rest.split_whitespace().nth(1))
        == Some(ABS_SEND_TIME)
}

/// The payload types the peer is built with, at the view's own numbers:
/// VP8 as the first video section names it (the view puts the publish slot
/// there), `red` as the receive slots do, Opus, each with its RTX. One
/// entry a codec: the rest of the offer's vocabulary is echoed to the SFU
/// by the shaper and never sent or read.
///
/// # Errors
///
/// As [`codec_table`]; [`ShapeError::NoPublish`] for a view without VP8.
fn codec_lines(view: &str) -> Result<Vec<CodecLine>, NegotiateError> {
    let table = codec_table(view)?;
    let first = |kind: MediaKind, name: &str| {
        table
            .iter()
            .find(|codec| codec.kind == kind && codec.name.eq_ignore_ascii_case(name))
            .map(|codec| codec.payload_type)
    };
    let rtx_of = |pt: u8| {
        table
            .iter()
            .find(|codec| {
                codec.kind == MediaKind::Video
                    && codec.name.eq_ignore_ascii_case("rtx")
                    && codec
                        .fmtp
                        .split(';')
                        .find_map(|p| p.trim().strip_prefix("apt="))
                        .and_then(|apt| apt.parse::<u8>().ok())
                        == Some(pt)
            })
            .map(|codec| codec.payload_type)
    };
    let vp8 = first(MediaKind::Video, "VP8").ok_or(ShapeError::NoPublish)?;
    let mut lines = vec![CodecLine::video(
        vp8,
        rtx_of(vp8),
        Codec::Vp8,
        FormatParams::default(),
    )];
    if let Some(red) = first(MediaKind::Video, "red") {
        lines.push(CodecLine::video_red(red, rtx_of(red)));
    }
    if let Some(opus) = first(MediaKind::Audio, "opus") {
        lines.push(CodecLine::opus(opus, FormatParams::default()));
    }
    Ok(lines)
}

/// Gives `peer` the offer `sdp`: str0m applies it and answers in one step
/// (pion's `SetRemoteDescription`, `CreateAnswer`, `SetLocalDescription`).
/// The parser's own words are not passed on: they quote the text.
fn accept(peer: &Peer, sdp: &str) -> Result<SdpAnswer, String> {
    let offer = SdpOffer::from_sdp_string(sdp)
        .map_err(|_| "the offer is not an SDP the stack reads".to_owned())?;
    peer.with_rtc(|rtc| rtc.sdp_api().accept_offer(offer))
        .map_err(|e| e.to_string())
}

fn service_channel(label: &str) -> ChannelConfig {
    ChannelConfig {
        label: label.to_owned(),
        ordered: true,
        reliability: Reliability::Reliable,
        negotiated: None,
        protocol: String::new(),
    }
}

impl Negotiation {
    /// Answers an attempt's first offer (`negotiate` + `acceptOffer`, up to
    /// the answer): a peer built on `config` with the view's codecs takes
    /// the offer as the DTLS client, the two service channels are made
    /// (notification first, as the SDK orders them), the publish slot's
    /// layer `l` is declared with its mid and rid on every packet, the
    /// peer starts gathering, and the answer for the SFU is shaped from
    /// the real offer.
    ///
    /// The peer is closed again when any of it fails. Call it on a tokio
    /// runtime: the peer's driver is a task.
    ///
    /// # Errors
    ///
    /// [`NegotiateError`].
    pub fn open(
        offer: &str,
        config: &PeerConfig,
        ids: &TrackIds,
    ) -> Result<Opened, NegotiateError> {
        Self::open_native(offer, config, ids).map(|(opened, _)| opened)
    }

    /// [`Negotiation::open`], with str0m's own answer beside ours.
    fn open_native(
        offer: &str,
        config: &PeerConfig,
        ids: &TrackIds,
    ) -> Result<(Opened, SdpAnswer), NegotiateError> {
        let mut memo = ViewMemo::new();
        let view = offer_view(offer, &PUBLISH_CODECS, Some(&mut memo))?;
        let codecs = codec_lines(&view)?;
        let given = for_stack(&view, &[])?;
        drop(view);
        let mut claims = StackClaims::new();
        claims.admit(&given)?;
        olc_rtc::init();
        let (peer, events) = Peer::start_tuned(config, |c| with_codecs(c, &codecs))
            .map_err(|e| NegotiateError::NewPeer(e.to_string()))?;
        match Self::settle(&peer, offer, &given, (memo, claims), ids) {
            Ok((negotiation, answer, native)) => Ok((
                Opened {
                    negotiation,
                    events,
                    answer,
                },
                native,
            )),
            Err(error) => {
                peer.close();
                Err(error)
            }
        }
    }

    /// What follows the peer's start; on an error the caller closes it.
    fn settle(
        peer: &Peer,
        offer: &str,
        given: &str,
        (memo, claims): (ViewMemo, StackClaims),
        ids: &TrackIds,
    ) -> Result<(Negotiation, String, SdpAnswer), NegotiateError> {
        let native_answer = accept(peer, given).map_err(NegotiateError::Remote)?;
        peer.remote_described(given);
        let known = section_mids(given);

        // The service channels come before the track, in the SDK's order.
        let (notification, command) = peer.with_rtc(|rtc| {
            let mut api = rtc.direct_api();
            (
                api.create_data_channel(service_channel(NOTIFICATION_CHANNEL)),
                api.create_data_channel(service_channel(COMMAND_CHANNEL)),
            )
        });

        // The publish slot carries the video transport's track at the
        // slot's own VP8 number, read back from the stack.
        let slot = publish_mid(offer).ok_or(ShapeError::NoPublish)?;
        let mid = Mid::from(slot);
        if &*mid != slot {
            // str0m keeps a mid as 16 bytes of letters and digits and
            // would stamp another name than the one the SFU gave the slot
            // (pion stamps any). VK's mids are small numbers.
            return Err(ShapeError::NoPublish.into());
        }
        let vp8: Pt = peer
            .with_rtc(|rtc| {
                rtc.codec_config()
                    .find(|p| p.spec().codec == Codec::Vp8)
                    .map(|p| p.pt())
            })
            .ok_or(ShapeError::NoPublish)?;
        let red: Option<u8> = peer.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == Codec::Red)
                .map(|p| *p.pt())
        });
        let line = SendLine::declare(peer, mid, Some(Rid::from(PUBLISH_RID)), vp8, false)
            .ok_or(ShapeError::NoPublish)?;
        if !line.keep_mid_rid(peer) {
            return Err(ShapeError::NoPublish.into());
        }
        let cname = peer
            .with_rtc(|rtc| rtc.media(mid).map(|media| media.cname().to_owned()))
            .ok_or(ShapeError::NoPublish)?;
        let fingerprint =
            peer.with_rtc(|rtc| rtc.direct_api().local_dtls_fingerprint().to_string());
        peer.gather()
            .map_err(|e| NegotiateError::Local(e.to_string()))?;

        let native = Native {
            ufrag: peer.creds().ufrag.clone(),
            pwd: peer.creds().pass.clone(),
            fingerprint_line: format!("a=fingerprint:{fingerprint}"),
            msid_stream: ids.stream.clone(),
            msid_track: ids.track.clone(),
            cname,
        };
        let mut shape = ShapeState::new();
        let answer = shape_answer(offer, &native, &mut shape)?;
        Ok((
            Negotiation {
                peer: peer.clone(),
                memo,
                shape,
                known,
                native,
                line,
                red,
                notification,
                command,
                claims,
            },
            answer,
            native_answer,
        ))
    }

    /// Answers a later offer on the established transport (`reanswer`): the
    /// view with the attempt's memo, the sections str0m knows kept where
    /// they are, and the answer shaped with the attempt's state (the same
    /// session id and audio SSRCs, the version two further).
    ///
    /// # Errors
    ///
    /// [`NegotiateError`]; the caller asks for a rejoin, as Go does.
    pub fn reanswer(&mut self, offer: &str) -> Result<String, NegotiateError> {
        self.reanswer_native(offer).map(|(answer, _)| answer)
    }

    /// [`Negotiation::reanswer`], with str0m's own answer beside ours.
    fn reanswer_native(&mut self, offer: &str) -> Result<(String, SdpAnswer), NegotiateError> {
        let view = offer_view(offer, &PUBLISH_CODECS, Some(&mut self.memo))?;
        let given = for_stack(&view, &self.known)?;
        drop(view);
        // Against what the attempt's earlier offers claimed; a refused
        // offer leaves the claims as they were.
        let mut claims = self.claims;
        claims.admit(&given)?;
        self.claims = claims;
        let native_answer =
            accept(&self.peer, &given).map_err(NegotiateError::RenegotiationRemote)?;
        self.peer.remote_described(&given);
        self.known = section_mids(&given);
        drop(given);
        let answer = shape_answer(offer, &self.native, &mut self.shape)?;
        Ok((answer, native_answer))
    }

    /// The peer connection.
    #[must_use]
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// The channel the stream registry arrives on (`producerNotification`).
    #[must_use]
    pub fn notification_channel(&self) -> ChannelId {
        self.notification
    }

    /// The channel the engine's commands go out on (`producerCommand`).
    #[must_use]
    pub fn command_channel(&self) -> ChannelId {
        self.command
    }

    /// The payload type what we publish goes out at: the publish slot's
    /// own VP8 number.
    #[must_use]
    pub fn publish_pt(&self) -> u8 {
        *self.line.pt()
    }

    /// The payload type video wrapped in `red` arrives at (the receive
    /// slots' own number); `None` when the offer names no `red`.
    #[must_use]
    pub fn red_pt(&self) -> Option<u8> {
        self.red
    }

    /// Sizes the resend cache of what we publish; before the first packet
    /// (it empties what the cache holds). `false` when the peer no longer
    /// has the stream.
    pub fn size_resends(&self, cache: ResendCache) -> bool {
        self.line.size_resends(&self.peer, cache)
    }

    /// Writes `packets` on the publish slot's layer, in order, each with
    /// the slot's mid and the rid `l`. How many went to the stack; `None`
    /// when the peer no longer has the stream. Fewer than were given, or
    /// none, is a sample the send line refused whole because the stack
    /// still holds its backlog ([`olc_rtc::media::SEND_BACKLOG_PACKETS`]):
    /// a dropped sample, not one to offer again.
    pub fn publish<I>(&mut self, wallclock: Instant, packets: I) -> Option<usize>
    where
        I: IntoIterator<Item = RtpOut>,
        I::IntoIter: ExactSizeIterator,
    {
        self.line.write(&self.peer, wallclock, packets)
    }

    /// Closes the peer connection. Dropping the negotiation does the same.
    pub fn close(&self) {
        self.peer.close();
    }
}

impl Drop for Negotiation {
    fn drop(&mut self) {
        self.peer.close();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use olc_rtc::peer::IceMode;
    use olc_rtc::str0m::rtp::RtpPacket;
    use olc_rtc::str0m::Candidate;
    use olc_rtc::turn::TurnTransport;
    use olc_rtc::DtlsVersion;

    use super::*;
    use crate::answer::shape_answer_sdp;
    use crate::negotiate::tests::{live_shape_offer, offer_with_peer, pion_offer};
    use crate::signaling::tests::bounded;

    const O_LINE: &str = "o=- 1790552099500 1790552100511 IN IP4 127.0.0.1";
    const O_LINE_LATER: &str = "o=- 1790552099500 1790552100512 IN IP4 127.0.0.1";

    pub(crate) fn config(name: &'static str) -> PeerConfig {
        PeerConfig {
            name,
            crypto: olc_rtc::crypto(),
            dtls_version: DtlsVersion::Dtls12,
            host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            sctp_max_buffered: 64 << 10,
            turn: Vec::new(),
            relay_only: false,
            ice_mode: IceMode::Udp,
        }
    }

    fn ids() -> TrackIds {
        TrackIds {
            stream: "olcrtc-ab12cd34".to_owned(),
            track: "vp8channel-0102fefd".to_owned(),
        }
    }

    fn open(offer: &str) -> (Opened, String) {
        let (opened, native) = Negotiation::open_native(offer, &config("client"), &ids())
            .unwrap_or_else(|e| panic!("open: {e}"));
        (opened, native.to_sdp_string())
    }

    /// `text` with its one `from` made `to`.
    fn swap(text: &str, from: &str, to: &str) -> String {
        assert_eq!(text.matches(from).count(), 1, "{from:?} is not there once");
        text.replacen(from, to, 1)
    }

    /// The lines of `sdp`'s section whose mid is `mid`.
    fn section<'a>(sdp: &'a str, mid: &str) -> Vec<&'a str> {
        let name = format!("a=mid:{mid}");
        let lines: Vec<&str> = sdp.split("\r\n").collect();
        let mut starts: Vec<usize> = (0..lines.len())
            .filter(|i| lines[*i].starts_with("m="))
            .collect();
        starts.push(lines.len());
        starts
            .windows(2)
            .map(|w| lines[w[0]..w[1]].to_vec())
            .find(|s| s.contains(&name.as_str()))
            .unwrap_or_else(|| panic!("no section with mid {mid} in:\n{sdp}"))
    }

    fn mids(sdp: &str) -> Vec<&str> {
        sdp.split("\r\n")
            .filter_map(|l| l.strip_prefix("a=mid:"))
            .collect()
    }

    fn numbers(peer: &Peer, codec: Codec) -> Option<(u8, Option<u8>)> {
        peer.with_rtc(|rtc| {
            rtc.codec_config()
                .find(|p| p.spec().codec == codec)
                .map(|p| (*p.pt(), p.resend().map(|pt| *pt)))
        })
    }

    /// `assertPublishVP8`: the publish slot answers and sends VP8 at pt
    /// 100, the slot's own payload type the shaped answer declares.
    fn assert_publish_vp8(native: &str, negotiation: &Negotiation) {
        let publish = native
            .split("m=video")
            .skip(1)
            .filter(|sec| sec.contains("a=sendonly"))
            .map(|sec| sec.split("\r\n").next().unwrap())
            .last()
            .unwrap_or_else(|| panic!("no sendonly video section in:\n{native}"));
        assert!(
            format!("{publish} ").contains(" 100 "),
            "publish section does not negotiate VP8 pt=100: {publish:?}"
        );
        assert_eq!(negotiation.publish_pt(), 100, "publish sender's VP8");
        assert_eq!(
            numbers(negotiation.peer(), Codec::Vp8),
            Some((100, Some(101)))
        );
    }

    /// The fixtures of the Go engine's negotiation tests.
    fn fixtures() -> Vec<(&'static str, String)> {
        vec![
            ("pion", pion_offer()),
            ("peer after the publish slot", offer_with_peer(false)),
            ("peer ahead of the publish slot", offer_with_peer(true)),
            ("live shape", live_shape_offer()),
        ]
    }

    /// Review finding S2 of wave 1: what the shaper needs of the native
    /// answer, asked of str0m's real one for every Go fixture. The engine
    /// builds [`Native`] from the peer's fields; the same fields read out
    /// of str0m's own answer text (`Native::parse`, Go's way) are the ones
    /// it uses, and the two answers differ in the msid alone, which is
    /// ours in Go's form.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stacks_own_answer_has_what_the_shaper_reads() {
        bounded(async {
            for (name, offer) in fixtures() {
                let (opened, native_sdp) = open(&offer);
                let ours = &opened.negotiation.native;
                let parsed = Native::parse(&native_sdp)
                    .unwrap_or_else(|e| panic!("{name}: {e}\n{native_sdp}"));
                assert_eq!(parsed.ufrag, ours.ufrag, "{name}");
                assert_eq!(parsed.pwd, ours.pwd, "{name}");
                assert_eq!(parsed.fingerprint_line, ours.fingerprint_line, "{name}");
                assert_eq!(parsed.cname, ours.cname, "{name}");
                assert!(!ours.cname.is_empty() && !ours.ufrag.is_empty(), "{name}");
                assert_eq!(
                    (ours.msid_stream.as_str(), ours.msid_track.as_str()),
                    ("olcrtc-ab12cd34", "vp8channel-0102fefd"),
                    "{name}"
                );

                // Go's ShapeAnswer(offer, native, state) on the stack's real
                // answer, and ours from the fields.
                let from_text =
                    shape_answer_sdp(&offer, &native_sdp, &mut ShapeState::with_rng(|_| 0))
                        .unwrap_or_else(|e| panic!("{name}: ShapeAnswer: {e}"));
                let from_fields = shape_answer(&offer, ours, &mut ShapeState::with_rng(|_| 0))
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                let msid = format!("a=msid:{} {}", parsed.msid_stream, parsed.msid_track);
                let as_ours = from_text
                    .replace(&msid, "a=msid:olcrtc-ab12cd34 vp8channel-0102fefd")
                    .replace(
                        &format!("a=msid:{} ", parsed.msid_stream),
                        "a=msid:olcrtc-ab12cd34 ",
                    )
                    .replace(
                        &format!("a=msid-semantic: WMS {}", parsed.msid_stream),
                        "a=msid-semantic: WMS olcrtc-ab12cd34",
                    );
                assert!(as_ours == from_fields, "{name}: the two answers differ");

                // The answer the SFU is sent.
                let answer = &opened.answer;
                assert!(answer.contains(&format!("a=ice-ufrag:{}\r\n", ours.ufrag)));
                assert!(answer.contains("a=msid-semantic: WMS olcrtc-ab12cd34\r\n"));
                assert!(answer.contains("a=msid:olcrtc-ab12cd34 vp8channel-0102fefd\r\n"));
                assert!(answer.contains("\r\no=- ") && answer.contains(" 2 IN IP4 127.0.0.1\r\n"));
                assert_eq!(mids(answer), mids(&offer), "{name}: the offer's order");
                opened.negotiation.close();
            }
        })
        .await;
    }

    // TestPayloadClashNegotiates (#72): a room that already holds a
    // participant offers that participant's forward section with its own
    // payload numbering. The engine's whole order must go through and
    // publish VP8 at the payload type the shaped answer declares.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn payload_clash_negotiates() {
        bounded(async {
            for (name, ahead) in [
                ("peer after publish slot", false),
                ("peer ahead of publish slot", true),
            ] {
                let offer = offer_with_peer(ahead);
                let (opened, native) = open(&offer);
                assert_publish_vp8(&native, &opened.negotiation);
                // The SFU still gets the offer's full vocabulary, clashes
                // included.
                let shaped = &opened.answer;
                assert!(
                    shaped.contains("a=mid:6") && shaped.contains("a=rtpmap:102 H264/90000"),
                    "{name}: shaped answer no longer echoes the peer's forward section"
                );
                // We are the DTLS client, in str0m's answer and in ours.
                assert!(native.contains("a=setup:active\r\n"), "{name}:\n{native}");
                assert!(!native.contains("a=setup:passive"), "{name}:\n{native}");
                assert!(!shaped.contains("a=setup:passive") && !shaped.contains("actpass"));
                // Every section was taken by the stack.
                assert_eq!(opened.negotiation.known.len(), 6, "{name}");
                for mid in mids(&offer) {
                    let head = section(&native, mid)[0];
                    assert!(
                        !head.contains(" 0 UDP/"),
                        "{name}: mid {mid} refused: {head}"
                    );
                }
                opened.negotiation.close();
            }
        })
        .await;
    }

    // TestLiveShapeKeepsReceiveNumbering, the negotiation half: the receive
    // slots' numbering wins for everything we do not publish (red is 104),
    // while VP8 still goes out at the publish slot's pt 100.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_shape_keeps_receive_numbering() {
        bounded(async {
            let offer = live_shape_offer();
            let (opened, native) = open(&offer);
            assert_publish_vp8(&native, &opened.negotiation);
            assert_eq!(
                numbers(opened.negotiation.peer(), Codec::Red),
                Some((104, Some(105)))
            );
            // The SFU is still told the publish slot's own vocabulary.
            let publish = section(&opened.answer, "3");
            assert!(publish.contains(&"a=rtpmap:102 red/90000"), "{publish:?}");
            assert!(publish.contains(&"a=sendonly"), "{publish:?}");
            assert!(publish.contains(&"a=simulcast:send l;m;h"), "{publish:?}");
            assert!(
                !publish.iter().any(|l| l.starts_with("a=ssrc:")),
                "{publish:?}"
            );
            opened.negotiation.close();
        })
        .await;
    }

    // TestPayloadClashRenegotiates: the room was fresh at connect and the
    // participant arrives in a renegotiation offer, behind the sections the
    // stack holds or among them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn payload_clash_renegotiates() {
        bounded(async {
            for ahead in [false, true] {
                let (opened, _) = open(&pion_offer());
                let mut negotiation = opened.negotiation;
                assert_eq!(negotiation.known, ["0", "1", "2", "3", "5"]);
                let session_id = negotiation.shape.session_id();
                let (notification, command) = (
                    negotiation.notification_channel(),
                    negotiation.command_channel(),
                );

                let reoffer = swap(&offer_with_peer(ahead), O_LINE, O_LINE_LATER);
                let (shaped, native) = negotiation
                    .reanswer_native(&reoffer)
                    .unwrap_or_else(|e| panic!("ahead {ahead}: renegotiation: {e}"));
                let native = native.to_sdp_string();
                assert_publish_vp8(&native, &negotiation);
                // The sections the stack knew stay where they were; the
                // SFU is answered in its own order.
                assert_eq!(negotiation.known, ["0", "1", "2", "3", "5", "6"]);
                assert_eq!(mids(&native), ["0", "1", "2", "3", "5", "6"]);
                assert_eq!(mids(&shaped), mids(&reoffer), "ahead {ahead}");
                assert!(negotiation
                    .peer()
                    .with_rtc(|rtc| rtc.media(Mid::from("6")).is_some()));
                // The attempt's state: the same session, the version two
                // further, the same channels.
                assert!(
                    shaped.contains(&format!("\r\no=- {session_id} 4 IN IP4 127.0.0.1\r\n")),
                    "ahead {ahead}"
                );
                assert_eq!(
                    (
                        negotiation.notification_channel(),
                        negotiation.command_channel()
                    ),
                    (notification, command)
                );
                // Go's test shapes the same answer through its parser.
                shape_answer_sdp(&reoffer, &native, &mut ShapeState::new())
                    .unwrap_or_else(|e| panic!("ahead {ahead}: ShapeAnswer: {e}"));
                negotiation.close();
            }
        })
        .await;
    }

    /// Correctness S3, plan K2: str0m's one-claim-per-payload-type rule
    /// is an `assert!`, and a panic under a rejoin or in the notification
    /// loop is the task's silent death. The view settles one meaning per
    /// number within a kind; str0m has one table for audio and video. An
    /// offer that gives a number two meanings among the peer's codecs is
    /// refused before str0m sees it, as a first offer and as a later one;
    /// the others are answered or refused by the stack's own error: none
    /// reaches the assert.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offer_with_two_meanings_at_one_number_never_panics() {
        bounded(async {
            let base = live_shape_offer();
            let audio = |pt: &str| {
                base.replace(
                    "m=audio 9 UDP/TLS/RTP/SAVPF 111",
                    &format!("m=audio 9 UDP/TLS/RTP/SAVPF {pt}"),
                )
                .replace(
                    "a=rtpmap:111 opus/48000/2",
                    &format!("a=rtpmap:{pt} opus/48000/2"),
                )
            };
            // The offer, and the payload type it is refused for; `None`
            // is one the view or the stack settles in its own way, answered
            // or refused: all that is asked of it is no panic.
            let hostile: Vec<(&str, String, Option<u8>)> = vec![
                (
                    "VP9 at two numbers of a section",
                    base.replace("a=rtpmap:104 red/90000", "a=rtpmap:104 VP9/90000"),
                    None,
                ),
                ("opus at VP8's number", audio("100"), Some(100)),
                ("opus at VP8's RTX number", audio("101"), Some(101)),
                ("opus at video red's number", audio("104"), Some(104)),
                ("opus at VP9's number", audio("102"), None),
                (
                    "an RTX at its own codec's number",
                    base.replace(
                        "a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100",
                        "a=rtpmap:100 rtx/90000\r\na=fmtp:100 apt=100",
                    ),
                    None,
                ),
                (
                    "red's RTX at VP8's number",
                    base.replace(
                        "a=rtpmap:105 rtx/90000\r\na=fmtp:105 apt=104",
                        "a=rtpmap:100 rtx/90000\r\na=fmtp:100 apt=104",
                    ),
                    None,
                ),
                (
                    "an RTX of VP9 at H264's number",
                    base.replace(
                        "a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102",
                        "a=rtpmap:98 rtx/90000\r\na=fmtp:98 apt=102",
                    ),
                    None,
                ),
                (
                    "one number named three times in a line",
                    base.replace(
                        "m=video 9 UDP/TLS/RTP/SAVPF 100 101 98 99 102 103 104",
                        "m=video 9 UDP/TLS/RTP/SAVPF 100 100 101 98 99 102 103 104 100",
                    ),
                    None,
                ),
                (
                    "H264 at VP8's RTX number",
                    base.replace("a=rtpmap:98 H264/90000", "a=rtpmap:101 H264/90000")
                        .replace("a=fmtp:98 packetization", "a=fmtp:101 packetization"),
                    None,
                ),
                (
                    "a payload type past 127",
                    base.replace("a=rtpmap:106 ulpfec/90000", "a=rtpmap:228 ulpfec/90000"),
                    None,
                ),
            ];
            for (name, offer, refused) in &hostile {
                assert_ne!(*offer, base, "{name}: the offer is the clean one");
                // As a first offer.
                match Negotiation::open(offer, &config("client"), &ids()) {
                    Ok(opened) => {
                        assert_eq!(*refused, None, "{name}: answered");
                        opened.negotiation.close();
                    }
                    Err(NegotiateError::Payload(pt)) if refused.is_some() => {
                        assert_eq!(*refused, Some(pt), "{name}");
                    }
                    Err(other) => assert_eq!(*refused, None, "{name}: {other}"),
                }
                // As a later offer, against what the first answer locked.
                let (opened, _) = open(&base);
                let mut negotiation = opened.negotiation;
                let later = swap(offer, O_LINE, O_LINE_LATER);
                match negotiation.reanswer(&later) {
                    Ok(_) => assert_eq!(*refused, None, "{name}: answered later"),
                    Err(NegotiateError::Payload(pt)) if refused.is_some() => {
                        assert_eq!(*refused, Some(pt), "{name}: later");
                    }
                    Err(other) => assert_eq!(*refused, None, "{name}: later: {other}"),
                }
                // A refused offer changed nothing: the clean one, a session
                // further, is still answered on the same peer connection.
                if refused.is_some() {
                    let again = swap(&base, "1790552100511", "1790552100513");
                    negotiation
                        .reanswer(&again)
                        .unwrap_or_else(|e| panic!("{name}: the clean offer after it: {e}"));
                }
                negotiation.close();
            }

            // What a later offer may not do to what an earlier one claimed,
            // though it has one meaning per number itself: VP8 is gone from
            // it, and Opus stands at VP8's number.
            let (opened, _) = open(&base);
            let mut negotiation = opened.negotiation;
            let moved = swap(&audio("100"), O_LINE, O_LINE_LATER).replace("VP8/90000", "AV1/90000");
            let refused = negotiation.reanswer(&moved).unwrap_err();
            assert!(
                matches!(
                    refused,
                    NegotiateError::Payload(100) | NegotiateError::Shape(ShapeError::NoPublish)
                ),
                "{refused}"
            );
            negotiation.close();
            assert_eq!(
                NegotiateError::Payload(100).to_string(),
                "vkcalls: payload type 100 has two meanings for the stack"
            );
        })
        .await;
    }

    /// The claims' own table: the fixtures every other test answers are
    /// admitted, alone and one after another; a claim stands across
    /// descriptions.
    #[test]
    fn the_stacks_claims() {
        let given = |offer: &str| {
            let view = offer_view(offer, &PUBLISH_CODECS, None).unwrap();
            for_stack(&view, &[]).unwrap()
        };
        for offer in [
            live_shape_offer(),
            pion_offer(),
            offer_with_peer(false),
            offer_with_peer(true),
        ] {
            let mut claims = StackClaims::new();
            claims.admit(&given(&offer)).unwrap();
            claims.admit(&given(&offer)).unwrap();
        }
        let mut claims = StackClaims::new();
        claims.admit(&given(&live_shape_offer())).unwrap();
        // VP8 100, its RTX 101, video red 104 and its RTX 105, Opus 111.
        let held: Vec<(usize, u8)> = claims
            .0
            .iter()
            .enumerate()
            .filter(|(_, claim)| **claim != 0)
            .map(|(pt, claim)| (pt, *claim))
            .collect();
        assert_eq!(
            held,
            [
                (100, 1),
                (101, 1 | CLAIM_RTX),
                (104, 2),
                (105, 2 | CLAIM_RTX),
                (111, 3)
            ]
        );
        // A later description that has one meaning per number in itself.
        let later = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 104\r\na=rtpmap:104 opus/48000/2\r\n";
        assert_eq!(claims.admit(later), Err(NegotiateError::Payload(104)));
        let fine = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 63\r\na=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:63 red/48000/2\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                    a=rtpmap:100 opus/48000/2\r\n";
        assert_eq!(claims.admit(fine), Ok(()));
        assert_eq!(claims.0[63], 4);

        // Within one description: a codec and an RTX at one number, an RTX
        // of two codecs, a number past 127 in a line or in an rtpmap,
        // however the line is spaced or cased.
        let admit = |body: &str| {
            StackClaims::new().admit(&format!("v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n{body}"))
        };
        let two = |pt: u8| Err(NegotiateError::Payload(pt));
        assert_eq!(
            admit("a=rtpmap:100 VP8/90000\r\na=rtpmap:100 rtx/90000\r\na=fmtp:100 apt=100\r\n"),
            two(100)
        );
        assert_eq!(
            admit(concat!(
                "a=rtpmap:100 VP8/90000\r\na=rtpmap:104 red/90000\r\n",
                "a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\na=fmtp:101 x=1; apt=104\r\n",
            )),
            two(101)
        );
        assert_eq!(
            admit(
                "a=rtpmap:100 VP8/90000\r\na=rtpmap:100\tvp8/90000\r\na=rtpmap:100  RED/90000\r\n"
            ),
            two(100)
        );
        assert_eq!(admit("a=rtpmap:228 ulpfec/90000\r\n"), two(u8::MAX));
        assert_eq!(admit("a=rtpmap:x VP8/90000\r\n"), two(u8::MAX));
        assert_eq!(
            StackClaims::new().admit("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 128\r\n"),
            two(u8::MAX)
        );
        // What the stack has no parameters for claims nothing.
        assert_eq!(
            admit(
                "a=rtpmap:100 VP9/90000\r\na=rtpmap:100 H264/90000\r\na=rtpmap:100 rtx/90000\r\n"
            ),
            Ok(())
        );
    }

    /// What str0m is given: the DTLS server's part for the far end
    /// whatever the offer said, no abs-send-time in the publish slot and
    /// only there, every other line as the view has it, and the known
    /// sections first.
    #[test]
    fn the_offer_as_the_stack_is_given_it() {
        let offer = live_shape_offer();
        let view = offer_view(&offer, &PUBLISH_CODECS, None).unwrap();
        let given = for_stack(&view, &[]).unwrap();
        assert_eq!(given.matches("a=setup:").count(), 1);
        assert!(given.contains("a=setup:passive\r\n"));
        let abs = format!("a=extmap:3 {ABS_SEND_TIME}");
        assert!(!section(&given, "3").contains(&abs.as_str()));
        assert!(section(&given, "5").contains(&abs.as_str()));
        assert!(section(&given, "6").contains(&abs.as_str()));
        let expected = swap(
            &view.replace("a=setup:actpass", "a=setup:passive"),
            &format!("a=mid:3\r\na=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n{abs}\r\n"),
            "a=mid:3\r\na=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
        );
        assert!(given == expected, "{given}");

        // An offer that would have us the server, or says nothing new.
        for setup in ["a=setup:active", "a=setup:passive", "a=setup:holdconn"] {
            let odd = view.replace("a=setup:actpass", setup);
            assert!(for_stack(&odd, &[]).unwrap() == expected, "{setup}");
        }

        // The known sections come first, the group with them.
        let ahead = offer_view(&offer_with_peer(true), &PUBLISH_CODECS, None).unwrap();
        assert_eq!(mids(&ahead), ["0", "1", "2", "3", "6", "5"]);
        let known: Vec<String> = ["0", "1", "2", "3", "5"].map(str::to_owned).to_vec();
        let given = for_stack(&ahead, &known).unwrap();
        assert_eq!(mids(&given), ["0", "1", "2", "3", "5", "6"]);
        assert!(given.contains("a=group:BUNDLE 0 1 2 3 5 6\r\n"));
        // An abs-send-time line with a direction, and one in a section
        // that is not a publish slot.
        assert!(is_abs_send_time(&format!(
            "a=extmap:3/sendonly {ABS_SEND_TIME}"
        )));
        assert!(!is_abs_send_time(
            "a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid"
        ));
    }

    /// An offer the engine cannot publish into, and one the stack refuses:
    /// Go's errors, no peer left behind, nothing of the offer in the text.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_offer_that_cannot_be_answered() {
        bounded(async {
            let open = |offer: &str| {
                Negotiation::open(offer, &config("client"), &ids()).map(|opened| opened.answer)
            };
            // No slot to publish into.
            let no_slot = live_shape_offer().replace("a=recvonly", "a=sendonly");
            assert_eq!(open(&no_slot), Err(ShapeError::NoPublish.into()));
            // A publish slot without VP8.
            let no_vp8 = live_shape_offer().replace("VP8/90000", "AV1/90000");
            assert_eq!(open(&no_vp8), Err(ShapeError::NoPublish.into()));
            // No BUNDLE group: the stack takes it, the shaper does not.
            let no_bundle = live_shape_offer().replace("a=group:BUNDLE 0 1 3 5 6\r\n", "");
            assert!(matches!(
                open(&no_bundle),
                Err(NegotiateError::Shape(ShapeError::Bundle) | NegotiateError::Remote(_))
            ));
            // No fingerprint: the stack refuses the description.
            let secret = "32:16:0D:10:FC:A1:F1:04:43:F5:22:01:9B:2E:53:38";
            let bare =
                live_shape_offer().replace(&format!("a=fingerprint:sha-256 {secret}\r\n"), "");
            let refused = open(&bare).unwrap_err();
            assert!(matches!(refused, NegotiateError::Remote(_)), "{refused:?}");
            let text = refused.to_string();
            assert!(
                text.starts_with("vkcalls: set remote description: "),
                "{text}"
            );
            for part in ["QcK1avCrgDjn21p", "GZU7Kw3Sq1YSJxrABCtRTGhms", "192.0.2.1"] {
                assert!(!text.contains(part), "{text}");
            }
            // Video sections the stack cannot read.
            let broken = live_shape_offer().replace("m=video 9 UDP/TLS/RTP/SAVPF", "m=video x y");
            let refused = open(&broken).unwrap_err().to_string();
            assert!(!refused.contains("m=video"), "{refused}");

            // A later offer the stack refuses says which step it was, and
            // the shaper's state stays where it was; the caller tears the
            // attempt down.
            let (opened, _) = self::open(&live_shape_offer());
            let mut negotiation = opened.negotiation;
            let refused = negotiation
                .reanswer(&swap(&broken, O_LINE, O_LINE_LATER))
                .unwrap_err();
            let text = refused.to_string();
            assert!(
                text.starts_with("vkcalls: renegotiation remote: "),
                "{text}"
            );
            assert!(!text.contains("m=video"), "{text}");
            assert_eq!(negotiation.shape.version(), 2);
        })
        .await;
    }

    // ----- A far end.

    /// What a peer's sink saw of one packet.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Seen {
        pub(crate) pt: u8,
        pub(crate) seq: u16,
        pub(crate) mid: Option<String>,
        pub(crate) rid: Option<String>,
        pub(crate) abs_send_time: bool,
        pub(crate) twcc: bool,
    }

    pub(crate) fn watch(peer: &Peer) -> mpsc::UnboundedReceiver<Seen> {
        let (tx, rx) = mpsc::unbounded_channel();
        peer.set_rtp_sink(Some(Box::new(move |p: &RtpPacket| {
            let _ = tx.send(Seen {
                pt: *p.header.payload_type,
                seq: p.header.sequence_number,
                mid: p.header.ext_vals.mid.map(|mid| mid.to_string()),
                rid: p.header.ext_vals.rid.map(|rid| rid.to_string()),
                abs_send_time: p.header.ext_vals.abs_send_time.is_some(),
                twcc: p.header.ext_vals.transport_cc.is_some(),
            });
        })));
        rx
    }

    /// A peer's events, those read while waiting for something else kept.
    struct Events {
        kept: VecDeque<PeerEvent>,
        rx: mpsc::Receiver<PeerEvent>,
    }

    impl Events {
        async fn next(&mut self) -> PeerEvent {
            if let Some(e) = self.kept.pop_front() {
                return e;
            }
            self.rx.recv().await.expect("the peer's driver went")
        }

        /// The next two channels that open, with their labels.
        async fn two_open(&mut self) -> Vec<(ChannelId, String)> {
            let mut open = Vec::new();
            while open.len() < 2 {
                match self.next().await {
                    PeerEvent::ChannelOpen(id, label) => open.push((id, label)),
                    PeerEvent::Closed(r) => panic!("closed: {r}"),
                    _ => {}
                }
            }
            open
        }
    }

    struct Room {
        negotiation: Negotiation,
        client_events: Events,
        sfu: Peer,
        sfu_events: Events,
        /// The offer the SFU made.
        offer: String,
    }

    impl Room {
        fn close(&self) {
            self.sfu.set_rtp_sink(None);
            self.negotiation.close();
            self.sfu.close();
        }

        /// Publishes `n` packets numbered from `first`, 25 ms apart.
        async fn publish(&mut self, first: u16, n: u16) {
            for i in 0..n {
                let seq = first.wrapping_add(i);
                let wrote = self.negotiation.publish(
                    Instant::now(),
                    [RtpOut {
                        seq,
                        timestamp: 3000 * u32::from(seq),
                        marker: true,
                        payload: vec![0x90, 0x80, 0, 9, 9],
                    }],
                );
                assert_eq!(wrote, Some(1));
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    /// The next `n` packets a sink sees, or those seen within `within`.
    async fn take(rx: &mut mpsc::UnboundedReceiver<Seen>, n: usize, within: Duration) -> Vec<Seen> {
        let mut got = Vec::new();
        let _ = tokio::time::timeout(within, async {
            while got.len() < n {
                match rx.recv().await {
                    Some(seen) => got.push(seen),
                    None => break,
                }
            }
        })
        .await;
        got
    }

    pub(crate) fn stream_id(peer: &Peer, id: ChannelId) -> Option<u16> {
        peer.with_rtc(|rtc| rtc.direct_api().sctp_stream_id_by_channel_id(id))
    }

    /// The session as the fake SFU holds it, written as an offer for a
    /// str0m peer: the sections of the view of its own offer with the
    /// directions turned, and the ICE credentials and the fingerprint the
    /// shaped answer told it, the answerer being the DTLS client. It is the
    /// shaped answer's form with one meaning per payload type (the fake is
    /// a str0m peer too, and takes no clash). The publish slot keeps every
    /// extension the SFU offered, abs-send-time among them, so the fake
    /// reads one if the client writes one.
    pub(crate) fn sfu_side(view: &str, shaped: &str) -> String {
        let crypto: Vec<&str> = ["a=ice-ufrag:", "a=ice-pwd:", "a=fingerprint:"]
            .iter()
            .map(|head| {
                shaped
                    .split("\r\n")
                    .find(|line| line.starts_with(head))
                    .unwrap_or_else(|| panic!("the shaped answer has no {head}"))
            })
            .collect();
        assert!(shaped.contains("a=setup:active"));
        let sections = answer::sections(view).unwrap();
        let mids: Vec<&str> = sections.iter().map(|s| s.mid().unwrap()).collect();
        let mut out = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE {}\r\n",
            mids.join(" ")
        );
        let mut push = |line: &str| {
            out.push_str(line);
            out.push_str("\r\n");
        };
        for section in &sections {
            push(section.0[0]);
            push("c=IN IP4 0.0.0.0");
            for line in &crypto {
                push(line);
            }
            push("a=setup:active");
            push(&format!("a=mid:{}", section.mid().unwrap()));
            if section.kind() == "application" {
                push("a=sctp-port:5000");
                continue;
            }
            for line in section.0.iter().filter(|l| l.starts_with("a=extmap:")) {
                push(line);
            }
            let publish = section.direction() == Some(answer::DIR_RECV_ONLY);
            push(if publish { "a=sendonly" } else { "a=recvonly" });
            push("a=rtcp-mux");
            for line in section.0.iter().filter(|l| {
                l.starts_with("a=rtpmap:")
                    || l.starts_with("a=fmtp:")
                    || l.starts_with("a=rtcp-fb:")
            }) {
                push(line);
            }
            if publish && section.kind() == answer::KIND_VIDEO {
                push("a=rid:l send");
                push("a=simulcast:send l");
            }
        }
        out
    }

    /// `offer` with the fake SFU's own candidate, credentials and
    /// fingerprint in the fixture's places.
    pub(crate) fn offered_by(sfu: &Peer, offer: &str) -> String {
        let fingerprint = sfu.with_rtc(|rtc| rtc.direct_api().local_dtls_fingerprint().to_string());
        swap(
            &swap(
                offer,
                "a=candidate:1 1 udp 1 192.0.2.1 43210 typ host",
                &format!("a={}", sfu.add_host_candidate().unwrap()),
            ),
            "a=fingerprint:sha-256 32:16:0D:10:FC:A1:F1:04:43:F5:22:01:9B:2E:53:38",
            &format!("a=fingerprint:{fingerprint}"),
        )
        .replace("QcK1avCrgDjn21p", &sfu.creds().ufrag)
        .replace("GZU7Kw3Sq1YSJxrABCtRTGhms", &sfu.creds().pass)
    }

    /// The engine's negotiation joined to a fake SFU: a str0m peer, ICE-lite
    /// as VK's, that offers `fixture` and is told the shaped answer's
    /// credentials and fingerprint and nothing else of the client.
    async fn join(fixture: &str) -> Room {
        olc_rtc::init();
        let sfu_codecs = [
            CodecLine::video(100, Some(101), Codec::Vp8, FormatParams::default()),
            CodecLine::opus(111, FormatParams::default()),
        ];
        let (sfu, mut sfu_rx) = Peer::start_tuned(&config("sfu"), |c| {
            with_codecs(c.set_ice_lite(true), &sfu_codecs)
        })
        .unwrap();
        let offer = offered_by(&sfu, fixture);
        let opened = Negotiation::open(&offer, &config("client"), &ids())
            .unwrap_or_else(|e| panic!("open: {e}"));
        let view = offer_view(&offer, &PUBLISH_CODECS, None).unwrap();
        let mirror = SdpOffer::from_sdp_string(&sfu_side(&view, &opened.answer)).unwrap();
        let _answer = sfu
            .with_rtc(|rtc| rtc.sdp_api().accept_offer(mirror))
            .unwrap_or_else(|e| panic!("the fake SFU: {e}"));
        let ours = Candidate::host(opened.negotiation.peer().local_addr(), "udp").unwrap();
        sfu.add_remote_candidate(ours);

        let mut client_rx = opened.events;
        let mut up = (false, false);
        let mut kept = (VecDeque::new(), VecDeque::new());
        while !(up.0 && up.1) {
            tokio::select! {
                e = client_rx.recv() => match e.expect("the client's driver went") {
                    PeerEvent::Connected => up.0 = true,
                    PeerEvent::Closed(r) => panic!("the client closed: {r}"),
                    e => kept.0.push_back(e),
                },
                e = sfu_rx.recv() => match e.expect("the SFU's driver went") {
                    PeerEvent::Connected => up.1 = true,
                    PeerEvent::Closed(r) => panic!("the SFU closed: {r}"),
                    e => kept.1.push_back(e),
                },
            }
        }
        Room {
            negotiation: opened.negotiation,
            client_events: Events {
                kept: kept.0,
                rx: client_rx,
            },
            sfu,
            sfu_events: Events {
                kept: kept.1,
                rx: sfu_rx,
            },
            offer,
        }
    }

    /// The negotiation against a far end that knows of us only what the
    /// shaped answer says (its ICE credentials and fingerprint): we are the
    /// DTLS client; the two service channels open at the SFU in the
    /// SDK's order, notification first, on SCTP streams 0 and 2, and carry
    /// a frame each way; what we publish arrives at the publish slot's VP8
    /// number with the slot's mid and the rid `l` on every packet and no
    /// abs-send-time; and all of it stays so after a later offer with one
    /// more participant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_channels_and_what_we_publish_reach_the_far_end() {
        bounded(async {
            let mut room = join(&live_shape_offer()).await;
            let (notification, command) = (
                room.negotiation.notification_channel(),
                room.negotiation.command_channel(),
            );
            let ours = room.client_events.two_open().await;
            assert_eq!(
                ours,
                vec![
                    (notification, NOTIFICATION_CHANNEL.to_owned()),
                    (command, COMMAND_CHANNEL.to_owned())
                ]
            );
            let client = room.negotiation.peer().clone();
            assert_eq!(stream_id(&client, notification), Some(0));
            assert_eq!(stream_id(&client, command), Some(2));
            let theirs = room.sfu_events.two_open().await;
            let labels: Vec<(Option<u16>, &str)> = theirs
                .iter()
                .map(|(id, label)| (stream_id(&room.sfu, *id), label.as_str()))
                .collect();
            assert_eq!(
                labels,
                vec![
                    (Some(0), "producerNotification"),
                    (Some(2), "producerCommand")
                ]
            );

            // A frame each way: a command out, a registry frame in.
            let frame = crate::control::encode_change_simulcast(1, "l", 320, 180, 15, 180_000);
            assert!(client.write(command, true, &frame).unwrap());
            loop {
                match room.sfu_events.next().await {
                    PeerEvent::Data(m) => {
                        assert_eq!(stream_id(&room.sfu, m.channel), Some(2));
                        assert_eq!(m.data, frame);
                        break;
                    }
                    PeerEvent::Closed(r) => panic!("the SFU closed: {r}"),
                    _ => {}
                }
            }
            assert!(room.sfu.write(theirs[0].0, true, b"registry").unwrap());
            loop {
                match room.client_events.next().await {
                    PeerEvent::Data(m) => {
                        assert_eq!(m.channel, notification);
                        assert_eq!(m.data, b"registry");
                        break;
                    }
                    PeerEvent::Closed(r) => panic!("the client closed: {r}"),
                    _ => {}
                }
            }

            let mut seen = watch(&room.sfu);
            let stamped = |got: &[Seen], first: u16| {
                for (i, p) in got.iter().enumerate() {
                    assert_eq!(p.pt, 100, "{p:?}");
                    assert_eq!(p.seq, first + u16::try_from(i).unwrap(), "{p:?}");
                    assert_eq!(p.mid.as_deref(), Some("3"), "{p:?}");
                    assert_eq!(p.rid.as_deref(), Some(PUBLISH_RID), "{p:?}");
                    assert!(!p.abs_send_time, "{p:?}");
                    assert!(p.twcc, "{p:?}");
                }
            };
            // Long enough for the far end's first receiver reports.
            room.publish(1000, 60).await;
            let got = take(&mut seen, 60, Duration::from_secs(3)).await;
            assert_eq!(got.len(), 60);
            stamped(&got, 1000);

            // A later offer with one more participant: answered on the
            // same peer, and what we publish goes on as it was.
            let more = section(&room.offer, "6")
                .join("\r\n")
                .replace("a=mid:6", "a=mid:7")
                .replace("2463708140", "2463708141")
                .replace("pat-6", "pat-7");
            let later = swap(
                &swap(&room.offer, O_LINE, O_LINE_LATER),
                "a=group:BUNDLE 0 1 3 5 6",
                "a=group:BUNDLE 0 1 3 5 6 7",
            ) + &more;
            let shaped = room.negotiation.reanswer(&later).unwrap();
            assert_eq!(mids(&shaped), ["0", "1", "3", "5", "6", "7"]);
            assert!(section(&shaped, "7").contains(&"a=recvonly"));
            assert_eq!(room.negotiation.publish_pt(), 100);
            room.publish(1060, 20).await;
            let got = take(&mut seen, 20, Duration::from_secs(3)).await;
            assert_eq!(got.len(), 20);
            stamped(&got, 1060);
            room.close();
        })
        .await;
    }

    /// Where the offer names no RTX for VP8 the publish stream has no RTX
    /// SSRC, and str0m would leave the mid and the rid out once the far
    /// end has reported on the stream (from the second packet on); the SFU
    /// is told no SSRC and binds the stream by its rid, so both stay on
    /// every packet, as Go's stamper writes them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mid_and_rid_stay_where_the_offer_names_no_rtx() {
        bounded(async {
            let offer = live_shape_offer()
                .replace("a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\n", "")
                .replace(" 100 101 98 ", " 100 98 ");
            assert!(!offer.contains("101"), "{offer}");
            let mut room = join(&offer).await;
            assert_eq!(
                numbers(room.negotiation.peer(), Codec::Vp8),
                Some((100, None))
            );
            let mut seen = watch(&room.sfu);
            room.publish(500, 60).await;
            let got = take(&mut seen, 60, Duration::from_secs(3)).await;
            assert_eq!(got.len(), 60);
            let bare: Vec<u16> = got
                .iter()
                .filter(|p| p.mid.as_deref() != Some("3") || p.rid.as_deref() != Some(PUBLISH_RID))
                .map(|p| p.seq)
                .collect();
            assert!(
                bare.is_empty(),
                "{} of 60 packets without their mid or rid, the first numbered {}",
                bare.len(),
                bare[0]
            );
            room.close();
        })
        .await;
    }

    // ----- Vectors.

    /// `vkcalls/stamp.json`: what Go's stamper leaves on a packet of the
    /// publish stream. Every case's mid element is the publish slot's mid
    /// and its rid element the layer we publish; and for the live publish
    /// slot, which names both extensions, a packet of ours read at a far
    /// end that holds the offer's ids carries those two elements, and no
    /// abs-send-time, which Go's stamper reads and never writes. The
    /// vector's slot with a mid str0m cannot hold (`video-12`) is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stamp_is_gos() {
        const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
        const RID: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
        bounded(async {
            let file = olc_interop::load("vkcalls/stamp.json");
            let cases = file["cases"].as_array().expect("the cases");
            assert!(cases.len() >= 12, "{} cases", cases.len());
            let live = live_shape_offer();
            let live_ids: Vec<(String, u64)> = section(&live, "3")
                .iter()
                .filter_map(|l| l.strip_prefix("a=extmap:"))
                .map(|l| {
                    let (id, uri) = l.split_once(' ').unwrap();
                    (uri.to_owned(), id.parse().unwrap())
                })
                .collect();
            let mut joined: Vec<String> = Vec::new();
            for case in cases {
                let name = case["name"].as_str().unwrap();
                let mid = case["mid"].as_str().unwrap();
                let negotiated: Vec<(String, u64)> = case["negotiated"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| {
                        (
                            n["uri"].as_str().unwrap().to_owned(),
                            n["id"].as_u64().unwrap(),
                        )
                    })
                    .collect();
                let has = |uri: &str| negotiated.iter().any(|(u, _)| u == uri);
                let video = case["mime"]
                    .as_str()
                    .unwrap()
                    .to_ascii_lowercase()
                    .starts_with("video/");

                // The elements Go wrote are the slot's mid and our rid,
                // each where its extension was negotiated.
                let want_mid = (video && has(MID) && !mid.is_empty())
                    .then(|| olc_interop::hex(mid.as_bytes()));
                let want_rid =
                    (video && has(RID)).then(|| olc_interop::hex(PUBLISH_RID.as_bytes()));
                assert_eq!(
                    case["mid_element_hex"].as_str(),
                    want_mid.as_deref(),
                    "{name}"
                );
                assert_eq!(
                    case["rid_element_hex"].as_str(),
                    want_rid.as_deref(),
                    "{name}"
                );
                assert_eq!(case["rid"].as_str(), Some(PUBLISH_RID), "{name}");

                // On the wire: the slots that name both extensions, each
                // slot once.
                if !(video && has(MID) && has(RID))
                    || mid.is_empty()
                    || joined.iter().any(|m| m == mid)
                {
                    continue;
                }
                assert_eq!(negotiated, live_ids, "{name}: the live slot's extensions");
                joined.push(mid.to_owned());
                if mid.len() > 16 || !mid.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    // Go stamps any mid; str0m keeps a mid as 16 letters
                    // and digits, so a slot named otherwise is refused
                    // here instead of stamped under another name.
                    let offer = swap(
                        &swap(&live, "a=mid:3\r\n", &format!("a=mid:{mid}\r\n")),
                        "a=group:BUNDLE 0 1 3 5 6",
                        &format!("a=group:BUNDLE 0 1 {mid} 5 6"),
                    );
                    assert_eq!(publish_mid(&offer), Some(mid), "{name}");
                    let refused = Negotiation::open(&offer, &config("client"), &ids())
                        .map(|opened| opened.answer);
                    assert_eq!(refused, Err(ShapeError::NoPublish.into()), "{name}");
                    continue;
                }
                let offer = if mid == "3" {
                    live.clone()
                } else {
                    swap(
                        &swap(&live, "a=mid:3\r\n", &format!("a=mid:{mid}\r\n")),
                        "a=group:BUNDLE 0 1 3 5 6",
                        &format!("a=group:BUNDLE 0 1 {mid} 5 6"),
                    )
                };
                assert_eq!(publish_mid(&offer), Some(mid), "{name}");
                let mut room = join(&offer).await;
                let mut seen = watch(&room.sfu);
                room.publish(0x1234, 30).await;
                let got = take(&mut seen, 30, Duration::from_secs(3)).await;
                assert_eq!(got.len(), 30, "{name}");
                for p in &got {
                    assert_eq!(p.pt, 100, "{name}: {p:?}");
                    let hex_of =
                        |v: &Option<String>| v.as_ref().map(|v| olc_interop::hex(v.as_bytes()));
                    assert_eq!(
                        hex_of(&p.mid).as_deref(),
                        case["mid_element_hex"].as_str(),
                        "{name}: {p:?}"
                    );
                    assert_eq!(
                        hex_of(&p.rid).as_deref(),
                        case["rid_element_hex"].as_str(),
                        "{name}: {p:?}"
                    );
                    assert!(!p.abs_send_time, "{name}: {p:?}");
                }
                room.close();
            }
            assert_eq!(joined, ["3", "video-12"]);
        })
        .await;
    }

    /// `vkcalls/url.json`, `ice_servers_of`: the servers the engine reads
    /// from the provider's text, as Go reads them.
    #[test]
    fn the_ice_servers_are_gos() {
        let file = olc_interop::load("vkcalls/url.json");
        let cases = file["ice_servers_of"].as_array().expect("the cases");
        assert!(cases.len() >= 10, "{} cases", cases.len());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let want: Vec<IceServer> = case["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| IceServer {
                    urls: s["urls"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|u| u.as_str().unwrap().to_owned())
                        .collect(),
                    username: s["username"].as_str().unwrap().to_owned(),
                    credential: s["credential"].as_str().unwrap().to_owned(),
                })
                .collect();
            assert!(
                ice_servers_of(case["raw"].as_str().unwrap()) == want,
                "{name}"
            );
        }
    }

    /// What the vectors do not reach of `encoding/json`'s rules, the
    /// bounds, and what the peer is given of the list (K9).
    #[test]
    fn the_ice_servers_beyond_the_vectors() {
        let urls = |raw: &str| -> Vec<Vec<String>> {
            ice_servers_of(raw).iter().map(|s| s.urls.clone()).collect()
        };
        // A name in another case, the last of a repeated name, a null that
        // leaves a field as it was, a null among the URLs.
        let read = ice_servers_of(
            r#"[{"URLS":["turn:a.example"],"UserName":"u","username":"v","credential":"c","Credential":null},null,{"urls":["turn:b.example",null],"urls":null}]"#,
        );
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].urls, ["turn:a.example"]);
        assert_eq!(
            (read[0].username.as_str(), read[0].credential.as_str()),
            ("v", "c")
        );
        assert_eq!(read[1].urls, ["turn:b.example", ""]);
        // A value of another type refuses the whole text.
        for raw in [
            r#"[{"urls":["turn:a.example"]},5]"#,
            r#"[{"urls":["turn:a.example"]},{"urls":[5]}]"#,
            r#"[{"urls":["turn:a.example"]},{"urls":{}}]"#,
            r#"[{"urls":["turn:a.example"],"username":["u"]}]"#,
            r#"[{"urls":["turn:a.example"]}] x"#,
        ] {
            assert!(ice_servers_of(raw).is_empty(), "{raw}");
        }

        // The bounds.
        let many: Vec<String> = (0..ICE_SERVERS_MAX + 3)
            .map(|i| format!(r#"{{"urls":["turn:t{i}.example"]}}"#))
            .collect();
        assert_eq!(
            urls(&format!("[{}]", many.join(","))).len(),
            ICE_SERVERS_MAX
        );
        let list: Vec<String> = (0..ICE_URLS_MAX + 3)
            .map(|i| format!(r#""turn:t{i}.example""#))
            .collect();
        assert_eq!(
            urls(&format!(r#"[{{"urls":[{}]}}]"#, list.join(",")))[0].len(),
            ICE_URLS_MAX
        );
        let long = "x".repeat(ICE_TEXT_MAX + 1);
        let at = "x".repeat(ICE_TEXT_MAX - 5);
        assert_eq!(
            urls(&format!(r#"[{{"urls":["turn:{long}","turn:{at}"]}}]"#)),
            [[format!("turn:{at}")]]
        );
        assert!(ice_servers_of(&format!(
            r#"[{{"urls":["turn:a.example"],"credential":"{long}"}}]"#
        ))
        .is_empty());

        // Debug shows neither the servers nor the credential.
        let secret = ice_servers_of(
            r#"[{"urls":["turn:91.231.135.155:19302"],"username":"NAME","credential":"SECRET"}]"#,
        );
        let shown = format!("{secret:?}");
        for part in ["91.231", "NAME", "SECRET"] {
            assert!(!shown.contains(part), "{shown}");
        }

        // The peer's TURN servers: turn: URLs over UDP and TCP in the
        // list's order, each once; STUN is not asked.
        let servers = ice_servers_of(
            r#"[{"urls":["stun:stun.example:3478"]},{"credential":"c","urls":["turn:91.231.135.155:19302","turn:t.example?transport=tcp","turn:91.231.135.155:19302","stun:s.example","nonsense"],"username":"u"}]"#,
        );
        let turn = turn_servers(&servers);
        let got: Vec<(&str, u16, TurnTransport, &str, &str)> = turn
            .iter()
            .map(|t| {
                (
                    t.host.as_str(),
                    t.port,
                    t.transport,
                    t.username.as_str(),
                    t.password.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("91.231.135.155", 19302, TurnTransport::Udp, "u", "c"),
                ("t.example", 3478, TurnTransport::Tcp, "u", "c"),
            ]
        );
        assert!(turn_servers(&ice_servers_of("[]")).is_empty());
    }

    /// The names the answer carries by default are Go's forms.
    #[test]
    fn the_track_ids_are_gos_forms() {
        let ids = TrackIds::random();
        let hex8 = |s: &str| {
            s.len() == 8
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        assert!(
            ids.stream.strip_prefix("olcrtc-").is_some_and(hex8),
            "{ids:?}"
        );
        assert!(
            ids.track.strip_prefix("vp8channel-").is_some_and(hex8),
            "{ids:?}"
        );
        assert_ne!(TrackIds::random(), ids);
        assert_eq!(
            (
                PUBLISH_RID,
                NOTIFICATION_CHANNEL,
                COMMAND_CHANNEL,
                PUBLISH_CODECS
            ),
            ("l", "producerNotification", "producerCommand", ["vp8"])
        );
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The offer as our own WebRTC stack is given it (`negotiate.go`,
//! `pionView`), and what the stack is told from it: the codecs, in the
//! offer's numbering, and the header extensions' ids.
//!
//! VK's SFU does not keep one payload numbering across the bundle: the
//! publish slot names pt 102 `red` and 104 `ulpfec` while each receive slot
//! names 102 `VP9` and 104 `red`. A stack keeps one codec per payload type
//! for the whole connection (str0m asserts it), so the view puts the publish
//! slot first among the video sections, shows it only the codecs we publish
//! and their rtx, gives every payload type one meaning and trims the payload
//! types that lost theirs. Every mid stays. The SFU never sees the view: the
//! answer is shaped from the real offer ([`crate::answer`]).
//!
//! Pure text. The offer is read through borrowed lines; the view is written
//! once into one string, and the tables borrow from the text they were read
//! from.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::answer::{self, Section, ShapeError, DIR_RECV_ONLY, KIND_AUDIO, KIND_VIDEO};

pub use crate::answer::remote_ssrcs;

/// The longest codec identity (`name/rate[/channels]`) a view accepts. Go has
/// no bound; the longest a browser or the SFU names is `telephone-event/48000`
/// (21 bytes). A [`ViewMemo`] keeps identities for a whole connection, so
/// their size is bounded here.
pub const CODEC_NAME_MAX: usize = 64;

/// The most `a=rtcp-fb` entries kept for one codec of the table; the rest
/// are left out. Go keeps every line; Chrome names five at most.
pub const FEEDBACK_MAX: usize = 16;

/// The header extensions registered for audio and video alike
/// (`offerMediaEngine`), in Go's order.
pub const HEADER_EXTENSIONS: [&str; 9] = [
    "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
    "urn:ietf:params:rtp-hdrext:sdes:mid",
    "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
    "urn:ietf:params:rtp-hdrext:toffset",
    "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
    "urn:3gpp:video-orientation",
    "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
];

/// What the view and the tables refuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    /// The offer could not be split (`splitSections`' error).
    #[error(transparent)]
    Shape(#[from] ShapeError),
    /// Not in Go: a codec identity longer than [`CODEC_NAME_MAX`].
    #[error("vkcalls: offer names a codec longer than the bound")]
    CodecName,
    /// One payload type naming two codecs of a kind: the table is asked of a
    /// view, where it cannot happen (Go: `register <mime> pt=<n>: codec
    /// already registered for same payload type`).
    #[error("vkcalls: register {kind}/{name} pt={payload_type}: codec already registered for same payload type")]
    Clash {
        /// `audio` or `video`.
        kind: MediaKind,
        /// The encoding name of the codec that came second.
        name: String,
        /// The payload type.
        payload_type: u8,
    },
}

/// The two kinds of section that carry codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediaKind {
    /// `m=audio`.
    Audio,
    /// `m=video`.
    Video,
}

impl MediaKind {
    fn of(kind: &str) -> Option<Self> {
        match kind {
            KIND_AUDIO => Some(Self::Audio),
            KIND_VIDEO => Some(Self::Video),
            _ => None,
        }
    }

    /// The kind as an `m=` line names it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audio => KIND_AUDIO,
            Self::Video => KIND_VIDEO,
        }
    }
}

impl std::fmt::Display for MediaKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one connection's views have settled so far (`viewMemo`): a stack
/// keeps its first meaning of a payload type for good, so a renegotiation's
/// view starts from the meanings of the views before it.
///
/// At most 256 identities of at most [`CODEC_NAME_MAX`] bytes per kind.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ViewMemo {
    audio: BTreeMap<u8, Box<str>>,
    video: BTreeMap<u8, Box<str>>,
}

impl ViewMemo {
    /// A memo with nothing settled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The identity (`name/rate[/channels]`, lower case) a payload type has
    /// settled on.
    #[must_use]
    pub fn claim(&self, kind: MediaKind, payload_type: u8) -> Option<&str> {
        self.of(kind).get(&payload_type).map(|name| &**name)
    }

    fn of(&self, kind: MediaKind) -> &BTreeMap<u8, Box<str>> {
        match kind {
            MediaKind::Audio => &self.audio,
            MediaKind::Video => &self.video,
        }
    }

    fn of_mut(&mut self, kind: MediaKind) -> &mut BTreeMap<u8, Box<str>> {
        match kind {
            MediaKind::Audio => &mut self.audio,
            MediaKind::Video => &mut self.video,
        }
    }
}

/// Go's `strconv.ParseUint(text, 10, 8)`: digits alone (Rust's parser would
/// take a sign).
fn payload_type(text: &str) -> Option<u8> {
    digits_only(text).then(|| text.parse().ok()).flatten()
}

fn digits_only(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The length of the leading run of ASCII digits.
fn digits(text: &str) -> usize {
    text.bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(text.len())
}

/// What Go's `\S` does not match.
fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// The length of the leading run of `\S`.
fn non_space(text: &str) -> usize {
    text.bytes().position(is_space).unwrap_or(text.len())
}

/// One `a=rtpmap` line as `rtpmapLine` reads it:
/// `^a=rtpmap:(\d+) ([A-Za-z0-9-]+)/(\d+)(?:/(\d+))?`.
struct Rtpmap<'a> {
    /// The payload type's digits.
    payload: &'a str,
    name: &'a str,
    rate: &'a str,
    channels: Option<&'a str>,
    /// `name/rate[/channels]` as written: the codec's identity once
    /// lower-cased.
    identity: &'a str,
}

fn rtpmap(line: &str) -> Option<Rtpmap<'_>> {
    let rest = line.strip_prefix("a=rtpmap:")?;
    let pt = digits(rest);
    if pt == 0 {
        return None;
    }
    let after = rest[pt..].strip_prefix(' ')?;
    let name = after
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'-'))
        .unwrap_or(after.len());
    if name == 0 {
        return None;
    }
    let tail = after[name..].strip_prefix('/')?;
    let rate = digits(tail);
    if rate == 0 {
        return None;
    }
    let mut end = name + 1 + rate;
    let mut channels = None;
    if let Some(more) = tail[rate..].strip_prefix('/') {
        let count = digits(more);
        if count > 0 {
            channels = Some(&more[..count]);
            end += 1 + count;
        }
    }
    Some(Rtpmap {
        payload: &rest[..pt],
        name: &after[..name],
        rate: &tail[..rate],
        channels,
        identity: &after[..end],
    })
}

/// `fmtpLine`, `^a=fmtp:(\d+) (.*)$`: the payload type's digits and the
/// parameters.
fn fmtp(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("a=fmtp:")?;
    let pt = digits(rest);
    if pt == 0 {
        return None;
    }
    Some((&rest[..pt], rest[pt..].strip_prefix(' ')?))
}

/// `feedbackLin`, `^a=rtcp-fb:(\d+) (\S+)(?: (\S+))?`: the payload type's
/// digits, the type and the parameter (empty when there is none).
fn feedback(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("a=rtcp-fb:")?;
    let pt = digits(rest);
    if pt == 0 {
        return None;
    }
    let after = rest[pt..].strip_prefix(' ')?;
    let kind = non_space(after);
    if kind == 0 {
        return None;
    }
    let parameter = after[kind..]
        .strip_prefix(' ')
        .map_or("", |more| &more[..non_space(more)]);
    Some((&rest[..pt], &after[..kind], parameter))
}

/// The payload type an rtpmap, fmtp or rtcp-fb line belongs to
/// (`codecLinePayload`).
fn codec_line_payload(line: &str) -> Option<u8> {
    for prefix in ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let pt = rest.split_once(' ').map_or(rest, |(pt, _)| pt);
            return payload_type(pt);
        }
    }
    None
}

/// A set of payload types.
#[derive(Default, Clone, Copy)]
struct Payloads([u64; 4]);

impl Payloads {
    fn insert(&mut self, pt: u8) {
        self.0[usize::from(pt >> 6)] |= 1 << (pt & 63);
    }

    fn remove(&mut self, pt: u8) {
        self.0[usize::from(pt >> 6)] &= !(1 << (pt & 63));
    }

    fn contains(&self, pt: u8) -> bool {
        self.0[usize::from(pt >> 6)] & (1 << (pt & 63)) != 0
    }

    fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }
}

/// One section of the view: the `m=` line, rewritten when payload types
/// were dropped from it, and the other lines.
struct Slot<'a> {
    head: Cow<'a, str>,
    body: Vec<&'a str>,
    /// The `m=` line's kind; trimming never changes it.
    kind: &'a str,
    /// The first direction line; trimming never changes it.
    direction: Option<&'a str>,
}

impl<'a> Slot<'a> {
    fn new(section: Section<'a>) -> Self {
        let kind = section.kind();
        let direction = section.direction();
        let mut lines = section.0.into_iter();
        let head = lines.next().unwrap_or("");
        Slot {
            head: Cow::Borrowed(head),
            body: lines.collect(),
            kind,
            direction,
        }
    }

    /// Whether this is the video section the SFU receives on
    /// (`isPublishSlot`).
    fn is_publish(&self) -> bool {
        self.kind == KIND_VIDEO && self.direction == Some(DIR_RECV_ONLY)
    }

    /// The section's payload types and their identities as written
    /// (`rtpmapNames`, which lower-cases them: here they are compared without
    /// regard to case instead). A payload type named twice keeps its last
    /// line.
    fn names(&self) -> BTreeMap<u8, &'a str> {
        let mut names = BTreeMap::new();
        for &line in &self.body {
            if let Some(map) = rtpmap(line) {
                if let Some(pt) = payload_type(map.payload) {
                    names.insert(pt, map.identity);
                }
            }
        }
        names
    }

    /// The rtx payload types and the payload each repairs (`rtxApts`).
    fn rtx_apts(&self, names: &BTreeMap<u8, &str>) -> BTreeMap<u8, u8> {
        let mut out = BTreeMap::new();
        for &line in &self.body {
            let Some((pt, params)) = fmtp(line) else {
                continue;
            };
            let Some(pt) = payload_type(pt) else {
                continue;
            };
            if !names
                .get(&pt)
                .is_some_and(|name| starts_with_fold(name, "rtx/"))
            {
                continue;
            }
            for param in params.split(';') {
                if let Some(apt) = param.trim().strip_prefix("apt=").and_then(payload_type) {
                    out.insert(pt, apt);
                }
            }
        }
        out
    }

    /// Removes payload types from the `m=` line and their rtpmap, fmtp and
    /// rtcp-fb lines (`dropPayloads`). A section that would be left with none
    /// stays whole: there is nothing to negotiate in it either way.
    fn drop_payloads(&mut self, drop: &Payloads) {
        if drop.is_empty() {
            return;
        }
        let mut fields = self.head.split_whitespace();
        let lead: Vec<&str> = fields.by_ref().take(3).collect();
        let kept: Vec<&str> = fields
            .filter(|field| !payload_type(field).is_some_and(|pt| drop.contains(pt)))
            .collect();
        if lead.len() < 3 || kept.is_empty() {
            // Fewer than four fields, or none left. (With exactly three
            // fields Go returns the section whole as well.)
            return;
        }
        let mut head = lead.join(" ");
        for field in kept {
            head.push(' ');
            head.push_str(field);
        }
        self.head = Cow::Owned(head);
        self.body
            .retain(|line| !codec_line_payload(line).is_some_and(|pt| drop.contains(pt)));
    }

    /// Trims the publish slot to the codecs we publish and the rtx payloads
    /// repairing them (`publishedOnly`).
    fn published_only(&mut self, publish: &[&str]) {
        let names = self.names();
        let mut keep = Payloads::default();
        for (pt, name) in &names {
            if is_published(name, publish) {
                keep.insert(*pt);
            }
        }
        for (pt, apt) in self.rtx_apts(&names) {
            if keep.contains(apt) {
                keep.insert(pt);
            }
        }
        let mut drop = Payloads::default();
        for pt in names.keys() {
            if !keep.contains(*pt) {
                drop.insert(*pt);
            }
        }
        self.drop_payloads(&drop);
    }
}

/// `strings.HasPrefix(strings.ToLower(text), prefix)` for an ASCII prefix.
fn starts_with_fold(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Whether an rtpmap identity is one of `publish`'s codecs (`isPublished`).
fn is_published(name: &str, publish: &[&str]) -> bool {
    publish.iter().any(|codec| {
        starts_with_fold(name, codec) && name.as_bytes().get(codec.len()) == Some(&b'/')
    })
}

/// Moves the video publish slot ahead of every other video section, keeping
/// all else in order (`publishSlotFirst`).
fn publish_slot_first(slots: &mut [Slot<'_>]) {
    let mut first = None;
    let mut slot = None;
    for (i, sec) in slots.iter().enumerate() {
        if sec.kind != KIND_VIDEO {
            continue;
        }
        if first.is_none() {
            first = Some(i);
        }
        if sec.direction == Some(DIR_RECV_ONLY) {
            slot = Some(i);
            break;
        }
    }
    if let (Some(first), Some(slot)) = (first, slot) {
        if slot > first {
            slots[first..=slot].rotate_right(1);
        }
    }
}

/// Settles which codec each audio and video payload type names
/// (`claimPayloads`): what the memo settled before, then the codecs we
/// publish as the publish slot numbers them, then the other sections in
/// offer order (the SFU forwards to us in their numbering), then the publish
/// slot's other codecs where their payload type is still free.
fn claim_payloads(slots: &[Slot<'_>], publish: &[&str], claims: &mut ViewMemo) {
    fn claim(claims: &mut ViewMemo, slot: &Slot<'_>, wanted: impl Fn(&str) -> bool) {
        let Some(kind) = MediaKind::of(slot.kind) else {
            return;
        };
        let known = claims.of_mut(kind);
        for (pt, name) in slot.names() {
            if !known.contains_key(&pt) && wanted(name) {
                known.insert(pt, name.to_ascii_lowercase().into_boxed_str());
            }
        }
    }
    for slot in slots.iter().filter(|slot| slot.is_publish()) {
        claim(claims, slot, |name| is_published(name, publish));
    }
    for slot in slots.iter().filter(|slot| !slot.is_publish()) {
        claim(claims, slot, |_| true);
    }
    for slot in slots.iter().filter(|slot| slot.is_publish()) {
        claim(claims, slot, |_| true);
    }
}

/// Drops from an audio or video section the payload types whose claim
/// another codec won (`trimClashes`).
fn trim_clashes(slot: &mut Slot<'_>, claims: &ViewMemo) {
    let Some(kind) = MediaKind::of(slot.kind) else {
        return;
    };
    let known = claims.of(kind);
    let mut drop = Payloads::default();
    for (pt, name) in slot.names() {
        if let Some(winner) = known.get(&pt) {
            if !winner.eq_ignore_ascii_case(name) {
                olc_net::debug!(
                    "vkcalls: mid {}: pt={pt} {} yields to {winner}, hidden from pion",
                    slot.body
                        .iter()
                        .find_map(|line| line.strip_prefix("a=mid:"))
                        .unwrap_or(""),
                    name.to_ascii_lowercase()
                );
                drop.insert(pt);
            }
        }
    }
    slot.drop_payloads(&drop);
}

/// The offer as our own stack is given it (`pionView`). `publish` names the
/// codecs of our tracks (`["vp8"]`); `memo`, which may be absent, carries
/// the settled meanings across one connection's renegotiations.
///
/// A clean offer (no clash, the publish slot already first) with nothing to
/// publish comes back byte for byte.
///
/// # Errors
///
/// [`ShapeError::SdpTooLarge`] as [`ViewError::Shape`];
/// [`ViewError::CodecName`]. A refused offer leaves the memo as it was.
pub fn offer_view(
    offer: &str,
    publish: &[&str],
    memo: Option<&mut ViewMemo>,
) -> Result<String, ViewError> {
    let mut slots: Vec<Slot<'_>> = answer::sections(offer)?
        .into_iter()
        .map(Slot::new)
        .collect();
    // Before anything is claimed: a refusal must not leave half a memo.
    for slot in &slots {
        for line in &slot.body {
            if rtpmap(line).is_some_and(|map| map.identity.len() > CODEC_NAME_MAX) {
                return Err(ViewError::CodecName);
            }
        }
    }
    publish_slot_first(&mut slots);
    if !publish.is_empty() {
        for slot in slots.iter_mut().filter(|slot| slot.is_publish()) {
            slot.published_only(publish);
        }
    }
    let mut own = ViewMemo::default();
    let claims = memo.unwrap_or(&mut own);
    claim_payloads(&slots, publish, claims);

    let mut out = String::with_capacity(offer.len() + 2);
    let mut push = |line: &str| {
        if !out.is_empty() {
            out.push_str("\r\n");
        }
        out.push_str(line);
    };
    for line in answer::lines(offer)
        .take_while(|line| !line.starts_with("m="))
        .filter(|line| !line.is_empty())
    {
        push(line);
    }
    for slot in &mut slots {
        trim_clashes(slot, claims);
        push(&slot.head);
        for line in &slot.body {
            push(line);
        }
    }
    out.push_str("\r\n");
    Ok(out)
}

/// The mid of the offer's video section the SFU receives on (`publishMid`):
/// what every packet we publish is stamped with.
#[must_use]
pub fn publish_mid(offer: &str) -> Option<&str> {
    answer::sections(offer)
        .ok()?
        .iter()
        .find(|sec| sec.kind() == KIND_VIDEO && sec.direction() == Some(DIR_RECV_ONLY))
        .and_then(Section::mid)
}

/// One `a=rtcp-fb` entry of a codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feedback<'a> {
    /// The type (`nack`, `transport-cc`).
    pub kind: &'a str,
    /// The parameter (`pli`), empty when there is none.
    pub parameter: &'a str,
}

/// One offered codec, as the stack is to register it (`offerCodec`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferCodec<'a> {
    /// The section's kind.
    pub kind: MediaKind,
    /// The payload type, the offer's own.
    pub payload_type: u8,
    /// The rtpmap's encoding name, as written (`VP8`, `opus`).
    pub name: &'a str,
    /// The clock rate.
    pub clock_rate: u32,
    /// The channel count; 0 when the rtpmap names none.
    pub channels: u16,
    /// The payload type's fmtp parameters; empty when it has none.
    pub fmtp: &'a str,
    /// The payload type's rtcp-fb entries, [`FEEDBACK_MAX`] at most.
    pub feedback: Vec<Feedback<'a>>,
}

/// The codecs of every audio and video section (`offerMediaEngine`,
/// `registerSectionCodecs`): each section's payload types in its `m=` line's
/// order, each with its rtpmap, its fmtp line and its rtcp-fb lines. A
/// payload type a section before already gave the same codec is listed once.
///
/// The text is a view ([`offer_view`]): there no payload type names two
/// codecs of a kind.
///
/// # Errors
///
/// [`ShapeError::SdpTooLarge`] as [`ViewError::Shape`]; [`ViewError::Clash`]
/// for a text that is not a view.
pub fn codec_table(view: &str) -> Result<Vec<OfferCodec<'_>>, ViewError> {
    let mut table: Vec<OfferCodec<'_>> = Vec::new();
    for section in answer::sections(view)? {
        let Some(kind) = MediaKind::of(section.kind()) else {
            continue;
        };
        let Some(head) = section.0.first() else {
            continue;
        };
        // `sectionCodecBlocks`: an rtpmap line opens its payload type's
        // block (again, if it had one); the fmtp and rtcp-fb lines after it
        // join the block.
        let mut blocks: BTreeMap<u8, OfferCodec<'_>> = BTreeMap::new();
        let mut broken = Payloads::default();
        for &line in &section.0 {
            if let Some(map) = rtpmap(line) {
                let Some(pt) = payload_type(map.payload) else {
                    continue;
                };
                // `offerCodec` refuses a rate past 32 bits and a channel
                // count past 16: the payload type is then not registered.
                let rate = map.rate.parse::<u32>().ok();
                let channels = map.channels.map_or(Some(0), |c| c.parse::<u16>().ok());
                broken.remove(pt);
                if rate.is_none() || channels.is_none() {
                    broken.insert(pt);
                }
                blocks.insert(
                    pt,
                    OfferCodec {
                        kind,
                        payload_type: pt,
                        name: map.name,
                        clock_rate: rate.unwrap_or(0),
                        channels: channels.unwrap_or(0),
                        fmtp: "",
                        feedback: Vec::new(),
                    },
                );
            } else if let Some((pt, params)) = fmtp(line) {
                if let Some(block) = payload_type(pt).and_then(|pt| blocks.get_mut(&pt)) {
                    block.fmtp = params;
                }
            } else if let Some((pt, fb_kind, parameter)) = feedback(line) {
                if let Some(block) = payload_type(pt).and_then(|pt| blocks.get_mut(&pt)) {
                    // `strings.Fields` of the type and the parameter.
                    let mut parts = fb_kind
                        .split_whitespace()
                        .chain(parameter.split_whitespace());
                    if let Some(first) = parts.next() {
                        if block.feedback.len() < FEEDBACK_MAX {
                            block.feedback.push(Feedback {
                                kind: first,
                                parameter: parts.next().unwrap_or(""),
                            });
                        }
                    }
                }
            }
        }
        for field in head.split_whitespace().skip(3) {
            let Some(pt) = payload_type(field) else {
                continue;
            };
            if broken.contains(pt) {
                continue;
            }
            let Some(codec) = blocks.remove(&pt) else {
                continue;
            };
            match table
                .iter()
                .find(|known| known.kind == kind && known.payload_type == pt)
            {
                None => table.push(codec),
                Some(known) if same_codec(known, &codec) => {}
                Some(_) => {
                    return Err(ViewError::Clash {
                        kind,
                        name: codec.name.to_owned(),
                        payload_type: pt,
                    })
                }
            }
        }
    }
    Ok(table)
}

/// Whether a payload type's second codec is its first again, as Go's stack
/// judges it (pion's `addCodec`): the name without regard to case, the clock
/// rate and the channel count, an unnamed one standing for the codec's
/// default (opus 48000 and 2 channels, PCMU and PCMA 8000, else 90000; one
/// channel).
fn same_codec(a: &OfferCodec<'_>, b: &OfferCodec<'_>) -> bool {
    let is = |name: &str| a.kind == MediaKind::Audio && a.name.eq_ignore_ascii_case(name);
    let rate = |rate: u32| match rate {
        0 if is("opus") => 48000,
        0 if is("pcmu") || is("pcma") => 8000,
        0 => 90000,
        rate => rate,
    };
    let channels = |channels: u16| match channels {
        0 if is("opus") => 2,
        0 => 1,
        channels => channels,
    };
    a.name.eq_ignore_ascii_case(b.name)
        && rate(a.clock_rate) == rate(b.clock_rate)
        && channels(a.channels) == channels(b.channels)
}

/// One header extension the offer numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferExtension<'a> {
    /// The section's kind.
    pub kind: MediaKind,
    /// The id the offer gives the extension.
    pub id: u8,
    /// One of [`HEADER_EXTENSIONS`].
    pub uri: &'a str,
}

/// The ids the offer gives the extensions of [`HEADER_EXTENSIONS`], per kind,
/// each extension once at the id of its first line: what Go's stack learns
/// from the remote description for the extensions `offerMediaEngine`
/// registers. 18 entries at most.
#[must_use]
pub fn offer_extensions(view: &str) -> Vec<OfferExtension<'_>> {
    let mut out: Vec<OfferExtension<'_>> = Vec::new();
    let Ok(sections) = answer::sections(view) else {
        return out;
    };
    for section in sections {
        let Some(kind) = MediaKind::of(section.kind()) else {
            continue;
        };
        for &line in &section.0 {
            let Some(rest) = line.strip_prefix("a=extmap:") else {
                continue;
            };
            let mut fields = rest.split(' ');
            // `<id>[/<direction>] <uri>`.
            let id = fields
                .next()
                .map(|id| id.split_once('/').map_or(id, |(id, _)| id))
                .and_then(payload_type);
            let (Some(id), Some(uri)) = (id, fields.next()) else {
                continue;
            };
            if HEADER_EXTENSIONS.contains(&uri)
                && !out.iter().any(|ext| ext.kind == kind && ext.uri == uri)
            {
                out.push(OfferExtension { kind, id, uri });
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::answer::tests::FIXTURE_OFFER;

    /// What the vp8channel transport publishes (`vp8Publish`).
    const VP8: &[&str] = &["vp8"];

    /// The fixture's video publish slot `m=` line (`publishSlotLine`).
    const PUBLISH_SLOT_LINE: &str = "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101\r\n";

    /// `pionOffer`: the fixture completed for a stack's own parser and given
    /// an H264 in the publish slot, as the live offers carry.
    pub(crate) fn pion_offer() -> String {
        let offer = FIXTURE_OFFER.replacen(
            PUBLISH_SLOT_LINE,
            "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101 104\r\n",
            1,
        );
        let offer = offer.replacen(
            "a=rtcp-fb:100 nack pli\r\n",
            concat!(
                "a=rtcp-fb:100 nack pli\r\n",
                "a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\n",
                "a=rtpmap:104 H264/90000\r\n",
                "a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n",
            ),
            1,
        );
        offer.replacen(
            "a=rtcp-fb:100 nack\r\na=ssrc:",
            "a=rtcp-fb:100 nack\r\na=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\na=ssrc:",
            1,
        )
    }

    /// `peerSection`: the forward section the SFU adds for a participant
    /// already in the room, in the producer's own numbering: pt 102 is H264
    /// while the publish slot of the same offer says VP9.
    fn peer_section(mid: &str) -> String {
        format!(
            concat!(
                "m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103\r\n",
                "c=IN IP4 0.0.0.0\r\n",
                "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
                "a=mid:{}\r\n",
                "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
                "a=sendonly\r\n",
                "a=rtcp-mux\r\n",
                "a=rtpmap:96 VP8/90000\r\n",
                "a=rtcp-fb:96 nack\r\n",
                "a=rtpmap:97 rtx/90000\r\n",
                "a=fmtp:97 apt=96\r\n",
                "a=rtpmap:102 H264/90000\r\n",
                "a=rtcp-fb:102 nack\r\n",
                "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n",
                "a=rtpmap:103 rtx/90000\r\n",
                "a=fmtp:103 apt=102\r\n",
                "a=ssrc:2463708140 cname:guest\r\n",
                "a=ssrc:2463708140 msid:guest video-guest\r\n",
            ),
            mid
        )
    }

    /// `offerWithPeer`: the stack-ready fixture with a forward section for
    /// one more participant, after the publish slot or ahead of it.
    pub(crate) fn offer_with_peer(ahead: bool) -> String {
        let offer =
            pion_offer().replacen("a=group:BUNDLE 0 1 2 3 5", "a=group:BUNDLE 0 1 2 3 5 6", 1);
        if !ahead {
            return offer + &peer_section("6");
        }
        let slot = "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101 104\r\n";
        assert!(offer.contains(slot), "fixture lost its publish slot");
        offer.replacen(slot, &(peer_section("6") + slot), 1)
    }

    /// `liveShapeOffer`: the payload numbering of a live offer with
    /// sanitized values. The publish slot names pt 102 red and 104 ulpfec,
    /// the receive slots 102 VP9, 104 red and 106 ulpfec; VP8 is 100 in both.
    pub(crate) fn live_shape_offer() -> String {
        let session = concat!(
            "v=0\r\n",
            "o=- 1790552099500 1790552100511 IN IP4 127.0.0.1\r\n",
            "s=-\r\nt=0 0\r\n",
            "a=group:BUNDLE 0 1 3 5 6\r\n",
            "a=ice-lite\r\n",
            "a=msid-semantic: WMS *\r\n",
        );
        let audio = concat!(
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=candidate:1 1 udp 1 192.0.2.1 43210 typ host\r\n",
            "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
            "a=ice-pwd:GZU7Kw3Sq1YSJxrABCtRTGhms\r\n",
            "a=fingerprint:sha-256 32:16:0D:10:FC:A1:F1:04:43:F5:22:01:9B:2E:53:38\r\n",
            "a=setup:actpass\r\n",
            "a=mid:0\r\n",
            "a=sendonly\r\n",
            "a=rtcp-mux\r\n",
            "a=rtpmap:111 opus/48000/2\r\n",
            "a=ssrc:2463708138 cname:audio-mix\r\n",
        );
        let app = concat!(
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "a=mid:1\r\n",
            "a=sendrecv\r\n",
        );
        let ext = concat!(
            "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
            "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n",
        );
        let vp8 = concat!(
            "a=rtpmap:100 VP8/90000\r\na=rtcp-fb:100 nack\r\na=rtcp-fb:100 nack pli\r\n",
            "a=rtpmap:101 rtx/90000\r\na=fmtp:101 apt=100\r\n",
        );
        let h264 = concat!(
            "a=rtpmap:98 H264/90000\r\n",
            "a=fmtp:98 packetization-mode=1;level-asymmetry-allowed=1;profile-level-id=42e034\r\n",
            "a=rtpmap:99 rtx/90000\r\na=fmtp:99 apt=98\r\n",
        );
        let publish = format!(
            concat!(
                "m=video 9 UDP/TLS/RTP/SAVPF 100 101 98 99 102 103 104\r\n",
                "c=IN IP4 0.0.0.0\r\n",
                "a=mid:3\r\n{ext}",
                "a=extmap:14 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
                "a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n",
                "a=recvonly\r\n",
                "a=rtcp-mux\r\n{vp8}{h264}",
                "a=rtpmap:102 red/90000\r\n",
                "a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\n",
                "a=rtpmap:104 ulpfec/90000\r\n",
                "a=rid:l recv\r\n",
                "a=simulcast:recv l\r\n",
            ),
            ext = ext,
            vp8 = vp8,
            h264 = h264
        );
        let receive = |mid: &str, ssrc: &str| {
            format!(
                concat!(
                    "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101 98 99 104 105 106\r\n",
                    "c=IN IP4 0.0.0.0\r\n",
                    "a=mid:{mid}\r\n{ext}",
                    "a=sendonly\r\n",
                    "a=rtcp-mux\r\n",
                    "a=rtpmap:102 VP9/90000\r\n",
                    "a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\n{vp8}{h264}",
                    "a=rtpmap:104 red/90000\r\n",
                    "a=rtpmap:105 rtx/90000\r\na=fmtp:105 apt=104\r\n",
                    "a=rtpmap:106 ulpfec/90000\r\n",
                    "a=ssrc:{ssrc} cname:pat-{mid}\r\n",
                    "a=ssrc:{ssrc} msid:pat-{mid} video-pat-{mid}\r\n",
                ),
                mid = mid,
                ssrc = ssrc,
                ext = ext,
                vp8 = vp8,
                h264 = h264
            )
        };
        [
            session,
            audio,
            app,
            &publish,
            &receive("5", "2463708139"),
            &receive("6", "2463708140"),
        ]
        .concat()
    }

    /// What `pionView` at the pin returned for `offer`: the case `name` of
    /// `vkcalls/view.json`, which must be a case about this very offer.
    fn go_view(name: &str, offer: &str) -> String {
        let file = olc_interop::load("vkcalls/view.json");
        let case = file["views"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap_or_else(|| panic!("view.json has no case {name:?}"));
        assert_eq!(
            crate::vectors::text_of(&case["offer"], &file["offers"], &case["name"]),
            offer,
            "{name}: the vector is about another offer"
        );
        case["view"].as_str().unwrap().to_owned()
    }

    /// The views of the chain `name` of `vkcalls/view.json`, step by step,
    /// which must be a chain over these very offers.
    fn go_chain(name: &str, offers: &[&str]) -> Vec<String> {
        let file = olc_interop::load("vkcalls/view.json");
        let chain = file["chains"]
            .as_array()
            .unwrap()
            .iter()
            .find(|chain| chain["name"] == name)
            .unwrap_or_else(|| panic!("view.json has no chain {name:?}"));
        let steps = chain["steps"].as_array().unwrap();
        assert_eq!(steps.len(), offers.len(), "{name}");
        steps
            .iter()
            .zip(offers)
            .map(|(step, offer)| {
                assert_eq!(
                    crate::vectors::text_of(&step["offer"], &file["offers"], &chain["name"]),
                    *offer,
                    "{name}: the vector is about another offer"
                );
                step["view"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    /// A view's sections as slots.
    fn slots(sdp: &str) -> Vec<Slot<'_>> {
        answer::sections(sdp)
            .unwrap()
            .into_iter()
            .map(Slot::new)
            .collect()
    }

    fn mid_of<'a>(slot: &Slot<'a>) -> &'a str {
        slot.body
            .iter()
            .find_map(|line| line.strip_prefix("a=mid:"))
            .unwrap_or("")
    }

    /// The lower-cased identities of a slot (`rtpmapNames` as Go returns it).
    fn lower_names(slot: &Slot<'_>) -> BTreeMap<u8, String> {
        slot.names()
            .into_iter()
            .map(|(pt, name)| (pt, name.to_ascii_lowercase()))
            .collect()
    }

    /// `assertOneMeaning`: no payload type names two codecs of one kind
    /// anywhere in a view.
    fn assert_one_meaning(view: &str) {
        let mut seen: BTreeMap<(String, u8), String> = BTreeMap::new();
        for slot in slots(view) {
            for (pt, name) in lower_names(&slot) {
                if let Some(prior) = seen.insert((slot.kind.to_owned(), pt), name.clone()) {
                    assert_eq!(
                        prior,
                        name,
                        "pt={pt} is {prior} in one section and {name} in mid {}",
                        mid_of(&slot)
                    );
                }
            }
        }
    }

    /// What `pionView` at the pin returns for the offers these tests build
    /// (`vkcalls/view.json`, whose offers are Go's own test offers).
    #[test]
    fn the_views_as_go_writes_them() {
        let view = |offer: &str, publish: &[&str]| offer_view(offer, publish, None).unwrap();
        let (pion, ahead, after, live) = (
            pion_offer(),
            offer_with_peer(true),
            offer_with_peer(false),
            live_shape_offer(),
        );
        assert_eq!(view(&pion, &[]), go_view("pion, no publish list", &pion));
        assert_eq!(
            view(&ahead, VP8),
            go_view("peer_ahead, publishing VP8", &ahead)
        );
        assert_eq!(
            view(&after, VP8),
            go_view("peer_after, publishing VP8", &after)
        );
        assert_eq!(view(&live, VP8), go_view("live, publishing VP8", &live));
        let after_nil = go_view("peer_after, no publish list", &after);
        assert_eq!(view(&after, &[]), after_nil);
        assert_eq!(
            view(FIXTURE_OFFER, VP8),
            go_view("fixture, publishing VP8", FIXTURE_OFFER)
        );
        // A memo carried from one offer to the next.
        let go = go_chain(
            "no publish list: a participant arrives in a second offer",
            &[&pion, &after],
        );
        let mut memo = ViewMemo::new();
        assert_eq!(offer_view(&pion, &[], Some(&mut memo)).unwrap(), go[0]);
        assert_eq!(offer_view(&after, &[], Some(&mut memo)).unwrap(), go[1]);
        // The memo changed the second view, or the check above says nothing
        // of it.
        assert_ne!(go[1], after_nil);
        let go = go_chain("a participant arrives in a second offer", &[&pion, &after]);
        let mut memo = ViewMemo::new();
        assert_eq!(offer_view(&pion, VP8, Some(&mut memo)).unwrap(), go[0]);
        assert_eq!(offer_view(&after, VP8, Some(&mut memo)).unwrap(), go[1]);
    }

    // TestPionViewLeavesCleanOfferAlone.
    #[test]
    fn a_clean_offer_is_left_alone() {
        let offer = pion_offer();
        assert_eq!(offer_view(&offer, &[], None).unwrap(), offer);
    }

    // TestPionViewKeepsEveryMid.
    #[test]
    fn the_view_keeps_every_mid() {
        let offer = offer_with_peer(true);
        let view = offer_view(&offer, VP8, None).unwrap();
        let mids = |sdp: &str| -> Vec<String> {
            let mut mids: Vec<String> = slots(sdp).iter().map(|s| mid_of(s).to_owned()).collect();
            mids.sort();
            mids
        };
        assert_eq!(mids(&view), mids(&offer));
        assert_eq!(mids(&view), ["0", "1", "2", "3", "5", "6"]);
        // pt 102 is VP9 in the publish slot, H264 in the receive section: we
        // do not publish VP9, so the receive section's meaning wins.
        assert!(view.contains("a=rtpmap:102 H264"), "{view}");
        assert!(!view.contains("a=rtpmap:102 VP9"), "{view}");
        assert_one_meaning(&view);
    }

    // TestLiveShapeKeepsReceiveNumbering, the view half.
    #[test]
    fn the_live_shape_keeps_the_receive_numbering() {
        let offer = live_shape_offer();
        let view = offer_view(&offer, VP8, None).unwrap();
        assert_one_meaning(&view);
        let mut seen = Vec::new();
        for slot in slots(&view) {
            let names = lower_names(&slot);
            let name = |pt: u8| names.get(&pt).map_or("", String::as_str);
            match mid_of(&slot) {
                "3" => {
                    assert_eq!(
                        (name(100), name(104), name(102)),
                        ("vp8/90000", "", ""),
                        "publish slot in the view: {names:?}"
                    );
                    seen.push("3");
                }
                mid @ ("5" | "6") => {
                    assert_eq!(
                        (name(104), name(102), name(100)),
                        ("red/90000", "vp9/90000", "vp8/90000"),
                        "receive slot {mid} in the view: {names:?}"
                    );
                    seen.push(mid);
                }
                _ => {}
            }
        }
        assert_eq!(seen, ["3", "5", "6"]);
    }

    // TestPublishedOnlyKeepsRepair.
    #[test]
    fn published_only_keeps_the_repair() {
        let offer = live_shape_offer();
        let mut slot = slots(&offer)
            .into_iter()
            .find(Slot::is_publish)
            .expect("no publish slot");
        slot.published_only(VP8);
        assert_eq!(slot.head, "m=video 9 UDP/TLS/RTP/SAVPF 100 101");
        let names = lower_names(&slot);
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            [(100, "vp8/90000".to_owned()), (101, "rtx/90000".to_owned())]
        );
    }

    /// The whole view of the live shape, byte for byte: the publish slot
    /// (already first among the video sections) trimmed to VP8 and its rtx,
    /// the receive slots whole.
    #[test]
    fn the_live_shape_view_whole() {
        let offer = live_shape_offer();
        let view = offer_view(&offer, VP8, None).unwrap();
        let dropped = concat!(
            "a=rtpmap:98 H264/90000\r\n",
            "a=fmtp:98 packetization-mode=1;level-asymmetry-allowed=1;profile-level-id=42e034\r\n",
            "a=rtpmap:99 rtx/90000\r\na=fmtp:99 apt=98\r\n",
            "a=rtpmap:102 red/90000\r\n",
            "a=rtpmap:103 rtx/90000\r\na=fmtp:103 apt=102\r\n",
            "a=rtpmap:104 ulpfec/90000\r\n",
            "a=rid:l recv\r\n",
        );
        let want = offer
            .replacen(
                "m=video 9 UDP/TLS/RTP/SAVPF 100 101 98 99 102 103 104\r\n",
                "m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\n",
                1,
            )
            .replacen(dropped, "a=rid:l recv\r\n", 1);
        assert_ne!(want, offer);
        assert_eq!(view, want);
    }

    /// The publish slot moves ahead of the video section before it and loses
    /// what it does not publish; the receive section keeps its numbering.
    #[test]
    fn the_publish_slot_moves_ahead_of_a_peer_section() {
        let offer = offer_with_peer(true);
        let view = offer_view(&offer, VP8, None).unwrap();
        let order: Vec<&str> = slots(&view).iter().map(mid_of).collect();
        assert_eq!(order, ["0", "1", "2", "3", "6", "5"]);
        let heads: Vec<String> = slots(&view).iter().map(|s| s.head.to_string()).collect();
        assert_eq!(
            heads[3..],
            [
                "m=video 9 UDP/TLS/RTP/SAVPF 100 101",
                "m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103",
                // pt 101 (rtx/90000) is its own in mid 5 and in the publish
                // slot alike: nothing to trim.
                "m=video 9 UDP/TLS/RTP/SAVPF 100 101",
            ]
        );
        // With the peer after the publish slot nothing moves.
        let view = offer_view(&offer_with_peer(false), VP8, None).unwrap();
        let order: Vec<&str> = slots(&view).iter().map(mid_of).collect();
        assert_eq!(order, ["0", "1", "2", "3", "5", "6"]);
    }

    /// With nothing to publish the publish slot keeps every codec; the
    /// clashes are still settled, the other sections first.
    #[test]
    fn without_a_publish_list_the_other_sections_win() {
        let view = offer_view(&offer_with_peer(false), &[], None).unwrap();
        assert_one_meaning(&view);
        let all = slots(&view);
        let publish = all.iter().find(|s| s.is_publish()).unwrap();
        // 102 (VP9) and 103 (its rtx, apt=102: but rtx/90000 is rtx/90000
        // in mid 6 as well, so it stays) against mid 6's H264 at 102.
        assert_eq!(publish.head, "m=video 9 UDP/TLS/RTP/SAVPF 103 100 101 104");
        assert!(!view.contains("a=rtpmap:102 VP9"));
    }

    /// A renegotiation's view starts from what the views before settled: a
    /// payload type keeps its first meaning though the new offer alone would
    /// settle it otherwise.
    #[test]
    fn the_memo_carries_the_meanings_across_offers() {
        // Nothing published: the publish slot keeps every codec, and with no
        // receive section naming 102 its VP9 takes it in the last pass.
        let mut memo = ViewMemo::new();
        let first = offer_view(&pion_offer(), &[], Some(&mut memo)).unwrap();
        assert_eq!(first, pion_offer());
        assert_eq!(memo.claim(MediaKind::Video, 102), Some("vp9/90000"));
        assert_eq!(memo.claim(MediaKind::Video, 100), Some("vp8/90000"));
        assert_eq!(memo.claim(MediaKind::Video, 104), Some("h264/90000"));
        assert_eq!(memo.claim(MediaKind::Audio, 111), Some("opus/48000/2"));
        assert_eq!(memo.claim(MediaKind::Video, 96), None);

        // 102 stays VP9: the peer's H264 at 102 is hidden. Its rtx at 103
        // stays (rtx/90000 is the same identity; apt is not looked at).
        let second = offer_view(&offer_with_peer(false), &[], Some(&mut memo)).unwrap();
        assert_one_meaning(&second);
        assert!(!second.contains("a=rtpmap:102 H264"), "{second}");
        assert!(second.contains("a=rtpmap:102 VP9"), "{second}");
        let peer = slots(&second)
            .into_iter()
            .find(|s| mid_of(s) == "6")
            .unwrap();
        assert_eq!(peer.head, "m=video 9 UDP/TLS/RTP/SAVPF 96 97 103");
        assert!(!peer.body.iter().any(|line| line.contains(":102 ")));
        assert_eq!(memo.claim(MediaKind::Video, 96), Some("vp8/90000"));
        assert_eq!(memo.claim(MediaKind::Video, 102), Some("vp9/90000"));

        // Without the memo the same offer settles 102 on H264.
        let alone = offer_view(&offer_with_peer(false), &[], None).unwrap();
        assert!(alone.contains("a=rtpmap:102 H264"));
        assert!(!alone.contains("a=rtpmap:102 VP9"));

        // What we publish: the first view claims VP8 and its rtx alone, so a
        // peer arriving in a renegotiation settles 102 itself.
        let mut memo = ViewMemo::new();
        offer_view(&pion_offer(), VP8, Some(&mut memo)).unwrap();
        assert_eq!(memo.claim(MediaKind::Video, 102), None);
        assert_eq!(memo.claim(MediaKind::Video, 101), Some("rtx/90000"));
        let second = offer_view(&offer_with_peer(false), VP8, Some(&mut memo)).unwrap();
        assert!(second.contains("a=rtpmap:102 H264"));
        assert_eq!(memo.claim(MediaKind::Video, 102), Some("h264/90000"));
    }

    /// The view's own rules at their edges.
    #[test]
    fn view_edges() {
        // LF alone and blank lines come back as CRLF without the blanks.
        let lf = "v=0\n\ns=-\nm=audio 9 X 0\n\na=mid:0\n";
        let view = offer_view(lf, &[], None).unwrap();
        assert_eq!(view, "v=0\r\ns=-\r\nm=audio 9 X 0\r\na=mid:0\r\n");
        assert_eq!(
            view,
            go_view("edge: bare line feeds and blank lines, no publish list", lf)
        );
        // Nothing at all.
        assert_eq!(offer_view("", VP8, None).unwrap(), "\r\n");
        assert_eq!(go_view("nothing", ""), "\r\n");
        // A section that would keep no payload type stays whole.
        let only_vp9 = concat!(
            "m=video 9 UDP/TLS/RTP/SAVPF 102\r\n",
            "a=mid:0\r\n",
            "a=recvonly\r\n",
            "a=rtpmap:102 VP9/90000\r\n",
        );
        assert_eq!(offer_view(only_vp9, VP8, None).unwrap(), only_vp9);
        assert_eq!(
            go_view(
                "edge: a section that would keep no payload type stays whole",
                only_vp9
            ),
            only_vp9
        );
        // A payload the m= line names without an rtpmap is not dropped; a
        // non-numeric field stays; `a=rtcp-fb:*` belongs to no payload.
        let odd = concat!(
            "m=video 9 UDP/TLS/RTP/SAVPF 100 x 101 102\r\n",
            "a=mid:0\r\n",
            "a=recvonly\r\n",
            "a=rtpmap:100 VP8/90000\r\n",
            "a=rtcp-fb:* nack\r\n",
            "a=rtpmap:102 VP9/90000\r\n",
            "a=rtcp-fb:102 nack\r\n",
            "a=fmtp:102 profile-id=0\r\n",
        );
        let want = concat!(
            "m=video 9 UDP/TLS/RTP/SAVPF 100 x 101\r\n",
            "a=mid:0\r\n",
            "a=recvonly\r\n",
            "a=rtpmap:100 VP8/90000\r\n",
            "a=rtcp-fb:* nack\r\n",
        );
        assert_eq!(offer_view(odd, VP8, None).unwrap(), want);
        assert_eq!(
            go_view(
                "edge: a payload type with no rtpmap, a field that is no number, feedback for every payload",
                odd
            ),
            want
        );
        // The codec's name is matched whole and without regard to case.
        let cases = concat!(
            "m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\n",
            "a=recvonly\r\n",
            "a=rtpmap:100 vp8/90000\r\n",
            "a=rtpmap:101 VP80/90000\r\n",
        );
        let view = offer_view(cases, &["VP8"], None).unwrap();
        assert!(
            view.starts_with("m=video 9 UDP/TLS/RTP/SAVPF 100\r\n"),
            "{view}"
        );
        assert_eq!(
            view,
            go_view("edge: a codec name is matched whole and in any case", cases)
        );
        // An rtx is kept by the payload it repairs, whatever else its fmtp
        // says; one repairing a dropped payload goes.
        let rtx = concat!(
            "m=video 9 UDP/TLS/RTP/SAVPF 100 101 102 103\r\n",
            "a=recvonly\r\n",
            "a=rtpmap:100 VP8/90000\r\n",
            "a=rtpmap:101 rtx/90000\r\n",
            "a=fmtp:101 rtx-time=200; apt=100\r\n",
            "a=rtpmap:102 VP9/90000\r\n",
            "a=rtpmap:103 rtx/90000\r\n",
            "a=fmtp:103 apt=102\r\n",
        );
        let view = offer_view(rtx, VP8, None).unwrap();
        assert!(
            view.starts_with("m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\n"),
            "{view}"
        );
        assert_eq!(
            view,
            go_view("edge: an rtx is kept by the payload it repairs", rtx)
        );
        // Audio is never a publish slot.
        let audio = "m=audio 9 X 111 0\r\na=recvonly\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:0 PCMU/8000\r\n";
        assert_eq!(offer_view(audio, VP8, None).unwrap(), audio);
        assert_eq!(go_view("edge: audio is never a publish slot", audio), audio);
    }

    /// Not Go's: the view refuses an offer of more sections or lines than
    /// the bounds, as it refuses a large one, and leaves the memo alone.
    #[test]
    fn the_view_refuses_more_sections_or_lines_than_the_bounds() {
        use crate::answer::{MAX_SDP_LINES, MAX_SDP_SECTIONS};
        let too_large = Err(ViewError::Shape(ShapeError::SdpTooLarge));
        let section = "m=audio 9 X 0\r\na=mid:0\r\na=recvonly\r\n";
        let at = section.repeat(MAX_SDP_SECTIONS);
        assert_eq!(offer_view(&at, VP8, None).unwrap(), at);
        let past = section.repeat(MAX_SDP_SECTIONS + 1);
        assert_eq!(offer_view(&past, VP8, None), too_large);
        assert_eq!(publish_mid(&past), None);
        assert_eq!(
            codec_table(&past),
            Err(ViewError::Shape(ShapeError::SdpTooLarge))
        );
        assert!(offer_extensions(&past).is_empty());

        let lines = |count: usize| format!("m=audio 9 X 0\r\n{}", "a=x\r\n".repeat(count - 1));
        let at = lines(MAX_SDP_LINES);
        assert_eq!(offer_view(&at, VP8, None).unwrap(), at);
        assert_eq!(offer_view(&lines(MAX_SDP_LINES + 1), VP8, None), too_large);
    }

    #[test]
    fn the_view_refuses_what_it_cannot_bound() {
        // One byte past the bound as Go measures it (a CRLF counts one).
        // Long lines: the bound on the lines is not what refuses.
        let line = format!("a=rtcp-fb:100 {}\r\n", "x".repeat(986));
        let line = line.as_str();
        let offer = pion_offer();
        let measured = offer.len() - offer.matches("\r\n").count();
        let fill = (answer::MAX_SDP_SIZE - measured) / (line.len() - 1);
        let fits = offer.clone() + &line.repeat(fill);
        assert!(offer_view(&fits, VP8, None).is_ok());
        let large = offer + &line.repeat(fill + 1);
        assert_eq!(
            offer_view(&large, VP8, None),
            Err(ViewError::Shape(ShapeError::SdpTooLarge))
        );
        assert_eq!(publish_mid(&large), None);
        assert_eq!(
            codec_table(&large),
            Err(ViewError::Shape(ShapeError::SdpTooLarge))
        );
        assert!(offer_extensions(&large).is_empty());

        // An identity of the bound passes, one byte more is refused and
        // leaves the memo as it was.
        let name = |len: usize| "x".repeat(len - "/90000".len());
        let with = |len: usize| {
            format!(
                "m=video 9 X 96 97\r\na=sendonly\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:97 {}/90000\r\n",
                name(len)
            )
        };
        let mut memo = ViewMemo::new();
        offer_view(&with(CODEC_NAME_MAX), VP8, Some(&mut memo)).unwrap();
        assert_eq!(
            memo.claim(MediaKind::Video, 97).map(str::len),
            Some(CODEC_NAME_MAX)
        );
        let mut memo = ViewMemo::new();
        assert_eq!(
            offer_view(&with(CODEC_NAME_MAX + 1), VP8, Some(&mut memo)),
            Err(ViewError::CodecName)
        );
        assert_eq!(memo, ViewMemo::new());
    }

    #[test]
    fn the_publish_mid() {
        assert_eq!(publish_mid(FIXTURE_OFFER), Some("3"));
        assert_eq!(publish_mid(&live_shape_offer()), Some("3"));
        // The first recvonly video section, wherever it stands.
        assert_eq!(publish_mid(&offer_with_peer(true)), Some("3"));
        // LF alone.
        assert_eq!(
            publish_mid("m=video 9 X 1\na=mid:7\na=recvonly\n"),
            Some("7")
        );
        // An audio publish slot is not it; nor a video section we receive.
        assert_eq!(
            publish_mid("m=audio 9 X 1\r\na=mid:2\r\na=recvonly\r\n"),
            None
        );
        assert_eq!(
            publish_mid("m=video 9 X 1\r\na=mid:5\r\na=sendonly\r\n"),
            None
        );
        // The slot without a mid: Go's "".
        assert_eq!(publish_mid("m=video 9 X 1\r\na=recvonly\r\n"), None);
        assert_eq!(publish_mid(""), None);
    }

    /// `remoteSSRCs` is answer.rs's; it is reachable from here as Go has it.
    #[test]
    fn remote_ssrcs_is_the_answers() {
        assert_eq!(
            remote_ssrcs(&live_shape_offer()),
            ["2463708138", "2463708139", "2463708140"]
        );
    }

    fn fb<'a>(kind: &'a str, parameter: &'a str) -> Feedback<'a> {
        Feedback { kind, parameter }
    }

    /// The table of the live shape's view: each section's payload types in
    /// its `m=` order, each codec once, the publish slot's first.
    #[test]
    fn the_codec_table_of_the_live_shape() {
        let view = offer_view(&live_shape_offer(), VP8, None).unwrap();
        let table = codec_table(&view).unwrap();
        let rows: Vec<(MediaKind, u8, &str, u32, u16, &str)> = table
            .iter()
            .map(|c| {
                (
                    c.kind,
                    c.payload_type,
                    c.name,
                    c.clock_rate,
                    c.channels,
                    c.fmtp,
                )
            })
            .collect();
        let h264 = "packetization-mode=1;level-asymmetry-allowed=1;profile-level-id=42e034";
        assert_eq!(
            rows,
            [
                (MediaKind::Audio, 111, "opus", 48000, 2, ""),
                (MediaKind::Video, 100, "VP8", 90000, 0, ""),
                (MediaKind::Video, 101, "rtx", 90000, 0, "apt=100"),
                (MediaKind::Video, 102, "VP9", 90000, 0, ""),
                (MediaKind::Video, 103, "rtx", 90000, 0, "apt=102"),
                (MediaKind::Video, 98, "H264", 90000, 0, h264),
                (MediaKind::Video, 99, "rtx", 90000, 0, "apt=98"),
                (MediaKind::Video, 104, "red", 90000, 0, ""),
                (MediaKind::Video, 105, "rtx", 90000, 0, "apt=104"),
                (MediaKind::Video, 106, "ulpfec", 90000, 0, ""),
            ]
        );
        assert_eq!(table[1].feedback, [fb("nack", ""), fb("nack", "pli")]);
        assert!(table[2].feedback.is_empty());
    }

    /// The raw offers clash, which is why the view exists (#72, K2).
    #[test]
    fn the_codec_table_names_a_clash() {
        let clash = |name: &str| ViewError::Clash {
            kind: MediaKind::Video,
            name: name.to_owned(),
            payload_type: 102,
        };
        assert_eq!(codec_table(&live_shape_offer()), Err(clash("VP9")));
        assert_eq!(codec_table(&offer_with_peer(false)), Err(clash("H264")));
        // Go's text (`offerMediaEngine` on the same offer, run at the pin).
        assert_eq!(
            clash("VP9").to_string(),
            "vkcalls: register video/VP9 pt=102: codec already registered for same payload type"
        );
        for ahead in [false, true] {
            let view = offer_view(&offer_with_peer(ahead), VP8, None).unwrap();
            let table = codec_table(&view).unwrap();
            let vp8: Vec<u8> = table
                .iter()
                .filter(|c| c.name == "VP8")
                .map(|c| c.payload_type)
                .collect();
            // The publish slot's VP8 first: what we send at.
            assert_eq!(vp8.first(), Some(&100), "ahead={ahead}");
            assert!(table
                .iter()
                .any(|c| c.payload_type == 102 && c.name == "H264"));
        }
    }

    #[test]
    fn codec_table_edges() {
        let sdp = concat!(
            "m=audio 9 X 111 0 8 9 13 x 300\r\n",
            // Before its rtpmap: lost.
            "a=fmtp:111 early=1\r\n",
            "a=rtpmap:111 opus/48000/2\r\n",
            "a=rtcp-fb:111 transport-cc\r\n",
            "a=fmtp:111 first=1\r\n",
            "a=fmtp:111 useinbandfec=1;minptime=10\r\n",
            "a=rtcp-fb:111 nack pli extra\r\n",
            "a=rtcp-fb:111 ccm  fir\r\n",
            // No rtpmap for 0: not in the table. No m= entry for 96.
            "a=rtpmap:96 VP8/90000\r\n",
            // A rate past 32 bits, a channel count past 16: not registered.
            "a=rtpmap:8 PCMA/4294967296\r\n",
            "a=rtpmap:9 G722/8000/65536\r\n",
            // Named twice: the second line opens the block again.
            "a=rtpmap:13 CN/8000\r\n",
            "a=fmtp:13 gone=1\r\n",
            "a=rtpmap:13 CN/16000 trailing\r\n",
            // Not a payload type.
            "a=rtpmap:300 big/8000\r\n",
            "m=application 9 X webrtc-datachannel\r\n",
            "a=rtpmap:111 no/1\r\n",
            "m=video 9 X\r\n",
            "a=rtpmap:100 VP8/90000\r\n",
            "m=audio 9 X 111\r\n",
            "a=rtpmap:111 OPUS/48000/2\r\n",
            "a=fmtp:111 later=1\r\n",
        );
        let table = codec_table(sdp).unwrap();
        assert_eq!(
            table,
            [
                OfferCodec {
                    kind: MediaKind::Audio,
                    payload_type: 111,
                    name: "opus",
                    clock_rate: 48000,
                    channels: 2,
                    fmtp: "useinbandfec=1;minptime=10",
                    feedback: vec![fb("transport-cc", ""), fb("nack", "pli"), fb("ccm", "")],
                },
                OfferCodec {
                    kind: MediaKind::Audio,
                    payload_type: 13,
                    name: "CN",
                    clock_rate: 16000,
                    channels: 0,
                    fmtp: "",
                    feedback: vec![],
                },
            ]
        );
        // The feedback bound.
        let mut many = String::from("m=video 9 X 100\r\na=rtpmap:100 VP8/90000\r\n");
        for i in 0..FEEDBACK_MAX + 5 {
            many.push_str(&format!("a=rtcp-fb:100 fb{i}\r\n"));
        }
        let table = codec_table(&many).unwrap();
        assert_eq!(table[0].feedback.len(), FEEDBACK_MAX);
        assert_eq!(table[0].feedback[FEEDBACK_MAX - 1].kind, "fb15");
        // The same payload type with another rate or channel count clashes;
        // an unnamed count is the codec's default (Go's answers, run at the
        // pin: nil for the first three, an error for the rate).
        let twice = |a: &str, b: &str| {
            let kind = if a.starts_with("VP8") {
                "video"
            } else {
                "audio"
            };
            format!(
                "m={kind} 9 X 100\r\na=rtpmap:100 {a}\r\nm={kind} 9 X 100\r\na=rtpmap:100 {b}\r\n"
            )
        };
        for (a, b) in [
            ("opus/48000/2", "opus/48000"),
            ("PCMA/8000/1", "PCMA/8000"),
            ("opus/48000/2", "OPUS/48000/2"),
        ] {
            assert_eq!(codec_table(&twice(a, b)).unwrap().len(), 1, "{a} {b}");
        }
        for (a, b, name) in [
            ("VP8/90000", "VP8/8000", "VP8"),
            ("opus/48000/2", "opus/48000/1", "opus"),
            ("PCMA/8000", "PCMA/8000/2", "PCMA"),
            ("opus/48000/2", "PCMA/8000", "PCMA"),
        ] {
            assert!(
                matches!(
                    codec_table(&twice(a, b)),
                    Err(ViewError::Clash { name: n, payload_type: 100, .. }) if n == name
                ),
                "{a} {b}"
            );
        }
        // Audio and video number their payload types apart.
        assert_eq!(
            codec_table("m=audio 9 X 100\r\na=rtpmap:100 opus/48000/2\r\nm=video 9 X 100\r\na=rtpmap:100 VP8/90000\r\n")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn the_offers_extension_ids() {
        let ext = |kind, id, uri| OfferExtension { kind, id, uri };
        let twcc = HEADER_EXTENSIONS[5];
        let ast = HEADER_EXTENSIONS[4];
        assert_eq!(
            offer_extensions(&live_shape_offer()),
            [
                ext(MediaKind::Video, 4, twcc),
                ext(MediaKind::Video, 3, ast),
                ext(MediaKind::Video, 14, HEADER_EXTENSIONS[1]),
                ext(MediaKind::Video, 10, HEADER_EXTENSIONS[2]),
            ]
        );
        assert_eq!(
            offer_extensions(FIXTURE_OFFER),
            [
                ext(MediaKind::Audio, 4, twcc),
                ext(MediaKind::Audio, 1, HEADER_EXTENSIONS[0]),
                ext(MediaKind::Video, 4, twcc),
                ext(MediaKind::Video, 3, ast),
            ]
        );
        // A direction after the id, an unknown extension, a bad id, an
        // extension numbered again later, attributes after the URI.
        let sdp = concat!(
            "a=extmap:9 urn:3gpp:video-orientation\r\n",
            "m=video 9 X 1\r\n",
            "a=extmap:7/recvonly urn:3gpp:video-orientation attr\r\n",
            "a=extmap:8 urn:example:unknown\r\n",
            "a=extmap:x urn:ietf:params:rtp-hdrext:toffset\r\n",
            "a=extmap:300 urn:ietf:params:rtp-hdrext:toffset\r\n",
            "a=extmap:11 urn:3gpp:video-orientation\r\n",
            "m=application 9 X 1\r\n",
            "a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n",
        );
        assert_eq!(
            offer_extensions(sdp),
            [ext(MediaKind::Video, 7, "urn:3gpp:video-orientation")]
        );
    }

    #[test]
    fn the_line_patterns() {
        let map = rtpmap("a=rtpmap:111 opus/48000/2").unwrap();
        assert_eq!(
            (map.payload, map.name, map.rate, map.channels, map.identity),
            ("111", "opus", "48000", Some("2"), "opus/48000/2")
        );
        let map = rtpmap("a=rtpmap:096 telephone-event/8000/ x").unwrap();
        assert_eq!(
            (map.payload, map.name, map.channels, map.identity),
            ("096", "telephone-event", None, "telephone-event/8000")
        );
        for bad in [
            "a=rtpmap: VP8/90000",
            "a=rtpmap:96VP8/90000",
            "a=rtpmap:96  VP8/90000",
            "a=rtpmap:96 /90000",
            "a=rtpmap:96 VP8",
            "a=rtpmap:96 VP8/",
            "a=rtpmap:96 VP_8/90000",
            " a=rtpmap:96 VP8/90000",
        ] {
            assert!(rtpmap(bad).is_none(), "{bad:?}");
        }
        assert_eq!(fmtp("a=fmtp:101 apt=100"), Some(("101", "apt=100")));
        assert_eq!(fmtp("a=fmtp:101 "), Some(("101", "")));
        assert_eq!(fmtp("a=fmtp:101"), None);
        assert_eq!(fmtp("a=fmtp:x y"), None);
        assert_eq!(
            feedback("a=rtcp-fb:100 nack pli"),
            Some(("100", "nack", "pli"))
        );
        assert_eq!(feedback("a=rtcp-fb:100 nack"), Some(("100", "nack", "")));
        assert_eq!(
            feedback("a=rtcp-fb:100 nack  pli"),
            Some(("100", "nack", ""))
        );
        assert_eq!(
            feedback("a=rtcp-fb:100 nack pli x"),
            Some(("100", "nack", "pli"))
        );
        assert_eq!(feedback("a=rtcp-fb:* nack"), None);
        assert_eq!(feedback("a=rtcp-fb:100 "), None);
        assert_eq!(codec_line_payload("a=rtpmap:96 x"), Some(96));
        assert_eq!(codec_line_payload("a=fmtp:255"), Some(255));
        assert_eq!(codec_line_payload("a=rtcp-fb:256 nack"), None);
        assert_eq!(codec_line_payload("a=rtcp-fb:+5 nack"), None);
        assert_eq!(codec_line_payload("a=mid:96"), None);
        assert_eq!(payload_type("+5"), None);
        assert_eq!(payload_type("007"), Some(7));
        assert_eq!(payload_type(""), None);
    }

    #[test]
    fn sizes() {
        // A memo is two maps; a slot is a line list and three references.
        assert!(
            std::mem::size_of::<ViewMemo>() <= 48,
            "ViewMemo is {} bytes",
            std::mem::size_of::<ViewMemo>()
        );
        assert!(
            std::mem::size_of::<OfferCodec<'_>>() <= 80,
            "OfferCodec is {} bytes",
            std::mem::size_of::<OfferCodec<'_>>()
        );
        assert!(std::mem::size_of::<Payloads>() == 32);
    }
}

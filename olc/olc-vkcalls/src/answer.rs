// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The answer VK's SFU accepts (`answer.go`): every content-bearing line
//! (the `m=` payload lists, the extmap and codec blocks, the directions)
//! comes from the offer in the reference client's order; the ICE and DTLS
//! fields and the video publish declaration come from our own stack's
//! answer. The session header is generated.
//!
//! Pure text. Nothing here keeps an SDP: the offer is read through borrowed
//! lines and the answer is written once into one string.

use std::collections::{BTreeMap, BTreeSet};

use crate::control;

/// The bound on an SDP given to the shaper (`maxSDPSize`); live offers are
/// about 70 KB.
pub const MAX_SDP_SIZE: usize = 1 << 20;

/// The most `m=` sections an SDP given to the shaper or the view may have.
/// Not in Go, which bounds the text alone: every section costs a list of its
/// own, and a megabyte of `m=` lines would be some 350,000 of them. The live
/// offer has 41 (36 video slots); past the bound the SDP is refused as too
/// large ([`ShapeError::SdpTooLarge`]).
pub const MAX_SDP_SECTIONS: usize = 128;

/// The most lines, empty ones aside, an SDP given to the shaper or the view
/// may have. Not in Go: every line kept costs 16 bytes of list beside its
/// text. The live offer has about 1,500; past the bound the SDP is refused
/// as too large ([`ShapeError::SdpTooLarge`]).
pub const MAX_SDP_LINES: usize = 16_384;

/// The most audio publish slots one connection attempt keeps a synthetic
/// SSRC for. Go keeps one for every mid it is ever offered; the live offer
/// has one such slot. Past the bound the offer is refused
/// ([`ShapeError::AudioSlots`]).
pub const AUDIO_SLOTS_MAX: usize = 64;

/// Shaping errors. They name the missing piece, never the values; the texts
/// are Go's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShapeError {
    /// `ErrShapeNoCrypto`.
    #[error("vkcalls: native answer carries no ICE/DTLS fields")]
    NoCrypto,
    /// `ErrShapeNoPublish`.
    #[error("vkcalls: native answer declares no video publish section")]
    NoPublish,
    /// `ErrShapeSectionWithoutMID`.
    #[error("vkcalls: offer section without a=mid")]
    SectionWithoutMid,
    /// `ErrShapeDirection`, with the section's mid.
    #[error("vkcalls: offer section with unsupported direction: mid {0}")]
    Direction(String),
    /// `ErrShapeBundle`.
    #[error("vkcalls: offer without a BUNDLE group")]
    Bundle,
    /// `ErrShapeSDPTooLarge`.
    #[error("vkcalls: SDP exceeds size bound")]
    SdpTooLarge,
    /// Not in Go: more audio publish slots than [`AUDIO_SLOTS_MAX`].
    #[error("vkcalls: offer names more audio publish slots than the bound")]
    AudioSlots,
}

/// What the shaper takes from our own stack's answer.
#[derive(Clone, PartialEq, Eq)]
pub struct Native {
    /// The ICE user fragment.
    pub ufrag: String,
    /// The ICE password.
    pub pwd: String,
    /// The whole `a=fingerprint:…` line.
    pub fingerprint_line: String,
    /// The stream id of the publish section's `a=msid:<stream> <track>`.
    pub msid_stream: String,
    /// The track id of that line.
    pub msid_track: String,
    /// The publish section's CNAME.
    pub cname: String,
}

impl std::fmt::Debug for Native {
    /// The ICE credentials and the fingerprint stay out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Native")
            .field("msid_stream", &self.msid_stream)
            .field("msid_track", &self.msid_track)
            .field("cname", &self.cname)
            .finish_non_exhaustive()
    }
}

impl Native {
    /// Reads the fields out of a native answer as Go's `ShapeAnswer` does:
    /// the first `a=ice-ufrag:`, `a=ice-pwd:` and `a=fingerprint:` lines,
    /// then the first `sendonly` video section that has an
    /// `a=ssrc:<n> cname:<c>` line, with its `a=msid:` line (or
    /// `a=msid:proofkit video`).
    ///
    /// # Errors
    ///
    /// [`ShapeError::NoCrypto`], then [`ShapeError::SdpTooLarge`], then
    /// [`ShapeError::NoPublish`], in Go's order.
    pub fn parse(native: &str) -> Result<Self, ShapeError> {
        let (mut ufrag, mut pwd, mut fingerprint) = (None, None, None);
        for line in lines(native) {
            if ufrag.is_none() {
                ufrag = line.strip_prefix("a=ice-ufrag:").and_then(token);
            }
            if pwd.is_none() {
                pwd = line.strip_prefix("a=ice-pwd:").and_then(token);
            }
            if fingerprint.is_none() && line.starts_with("a=fingerprint:") {
                fingerprint = Some(line);
            }
            if ufrag.is_some() && pwd.is_some() && fingerprint.is_some() {
                break;
            }
        }
        let (Some(ufrag), Some(pwd), Some(fingerprint)) = (ufrag, pwd, fingerprint) else {
            return Err(ShapeError::NoCrypto);
        };
        // `videoPublishOf`.
        for section in sections(native)? {
            if section.kind() != KIND_VIDEO || section.direction() != Some(DIR_SEND_ONLY) {
                continue;
            }
            let (stream, track) = section
                .0
                .iter()
                .find_map(|line| msid_of(line))
                .unwrap_or(("proofkit", "video"));
            if let Some((ssrc, cname)) = section.0.iter().find_map(|line| ssrc_cname_of(line)) {
                if ssrc.parse::<u32>().is_err() {
                    return Err(ShapeError::NoPublish);
                }
                return Ok(Self {
                    ufrag: ufrag.to_owned(),
                    pwd: pwd.to_owned(),
                    fingerprint_line: fingerprint.to_owned(),
                    msid_stream: stream.to_owned(),
                    msid_track: track.to_owned(),
                    cname: cname.to_owned(),
                });
            }
        }
        Err(ShapeError::NoPublish)
    }
}

pub(crate) const KIND_AUDIO: &str = "audio";
pub(crate) const KIND_VIDEO: &str = "video";
pub(crate) const DIR_SEND_ONLY: &str = "sendonly";
pub(crate) const DIR_RECV_ONLY: &str = "recvonly";

/// What Go's `\s` matches.
fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// Go's `(\S+)$`: the text when it is one token.
fn token(text: &str) -> Option<&str> {
    (!text.is_empty() && !text.bytes().any(is_space)).then_some(text)
}

/// The lines of an SDP as Go has them after
/// `strings.ReplaceAll(sdp, "\r\n", "\n")` and a split at `\n`, without a
/// copy of the text: a CR is dropped only where an LF follows it.
pub(crate) fn lines(sdp: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(sdp);
    std::iter::from_fn(move || {
        let text = rest?;
        match text.split_once('\n') {
            Some((line, tail)) => {
                rest = Some(tail);
                Some(line.strip_suffix('\r').unwrap_or(line))
            }
            None => {
                rest = None;
                Some(text)
            }
        }
    })
}

/// One `m=` section's lines, the `m=` line first (`section`).
#[derive(Debug)]
pub(crate) struct Section<'a>(pub(crate) Vec<&'a str>);

impl<'a> Section<'a> {
    /// The first `a=mid:<token>` line's token.
    pub(crate) fn mid(&self) -> Option<&'a str> {
        self.0
            .iter()
            .find_map(|line| line.strip_prefix("a=mid:").and_then(token))
    }

    /// The first direction line, without its `a=`.
    pub(crate) fn direction(&self) -> Option<&'a str> {
        self.0.iter().find_map(|line| match *line {
            "a=sendonly" | "a=recvonly" | "a=sendrecv" | "a=inactive" => line.strip_prefix("a="),
            _ => None,
        })
    }

    /// The media kind: the `m=` line's first field without `m=`.
    pub(crate) fn kind(&self) -> &'a str {
        let head = self
            .0
            .first()
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or("");
        head.strip_prefix("m=").unwrap_or(head)
    }
}

/// An SDP's `m=` sections (`splitSections`): empty lines and everything
/// before the first `m=` line are dropped. The bound on the size is on the
/// text as Go measures it, with each CRLF counted as one byte. The bounds on
/// the sections and on the lines (empty ones aside, the session's own
/// included) are not Go's: they are met before a list is made for what is
/// past them, so the lists of one SDP hold at most [`MAX_SDP_SECTIONS`]
/// sections and [`MAX_SDP_LINES`] lines of 16 bytes each.
///
/// # Errors
///
/// [`ShapeError::SdpTooLarge`] past [`MAX_SDP_SIZE`], [`MAX_SDP_SECTIONS`]
/// or [`MAX_SDP_LINES`] ([`breached`] says which).
pub(crate) fn sections(sdp: &str) -> Result<Vec<Section<'_>>, ShapeError> {
    split(sdp).map_err(|_| ShapeError::SdpTooLarge)
}

/// [`sections`], with the bound that refused the text.
fn split(sdp: &str) -> Result<Vec<Section<'_>>, SdpBound> {
    if sdp.len() > MAX_SDP_SIZE && sdp.len() - sdp.matches("\r\n").count() > MAX_SDP_SIZE {
        return Err(SdpBound::Size);
    }
    let mut out: Vec<Section<'_>> = Vec::new();
    let mut count = 0usize;
    for line in lines(sdp) {
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_SDP_LINES {
            return Err(SdpBound::Lines);
        }
        if line.starts_with("m=") {
            if out.len() == MAX_SDP_SECTIONS {
                return Err(SdpBound::Sections);
            }
            out.push(Section(vec![line]));
        } else if let Some(last) = out.last_mut() {
            last.0.push(line);
        }
    }
    Ok(out)
}

/// One of the three bounds on an SDP. Their breach is one error
/// ([`ShapeError::SdpTooLarge`], Go's, whose shaper has the first bound
/// alone); this is which, for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpBound {
    /// [`MAX_SDP_SIZE`].
    Size,
    /// [`MAX_SDP_SECTIONS`].
    Sections,
    /// [`MAX_SDP_LINES`].
    Lines,
}

impl std::fmt::Display for SdpBound {
    /// The constant's name and its value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdpBound::Size => write!(f, "MAX_SDP_SIZE ({MAX_SDP_SIZE} bytes)"),
            SdpBound::Sections => write!(f, "MAX_SDP_SECTIONS ({MAX_SDP_SECTIONS})"),
            SdpBound::Lines => write!(f, "MAX_SDP_LINES ({MAX_SDP_LINES})"),
        }
    }
}

/// The bound `sdp` is refused for as too large, if it is: the one
/// [`ShapeError::SdpTooLarge`] stands for when the shaper, the view or the
/// negotiation refuses this text.
#[must_use]
pub fn breached(sdp: &str) -> Option<SdpBound> {
    split(sdp).err()
}

/// `^(a=msid:\S+ \S+)$`: the stream and the track.
fn msid_of(line: &str) -> Option<(&str, &str)> {
    let (stream, track) = line.strip_prefix("a=msid:")?.split_once(' ')?;
    Some((token(stream)?, token(track)?))
}

/// `^a=ssrc:(\d+) cname:(\S+)$`: the digits and the CNAME.
fn ssrc_cname_of(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("a=ssrc:")?;
    let digits = rest.bytes().position(|b| !b.is_ascii_digit())?;
    if digits == 0 {
        return None;
    }
    let cname = token(rest[digits..].strip_prefix(" cname:")?)?;
    Some((&rest[..digits], cname))
}

/// The shaping state of one connection attempt, kept across re-answers
/// (`ShapeState`): the generated `o=` session id, the `o=` version and the
/// synthetic SSRCs of audio publish slots (nothing is sent there, but the
/// reference client declares them and the SFU expects them to stay). A
/// rejoin makes a new one.
pub struct ShapeState {
    session_id: u64,
    version: u64,
    audio_ssrc: BTreeMap<Box<str>, u32>,
    rng: Box<dyn FnMut(u64) -> u64 + Send>,
}

impl std::fmt::Debug for ShapeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShapeState")
            .field("version", &self.version)
            .field("audio_slots", &self.audio_ssrc.len())
            .finish_non_exhaustive()
    }
}

impl Default for ShapeState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShapeState {
    /// A state with a fresh session id (`NewShapeState`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_rng(|n| rand::Rng::gen_range(&mut rand::thread_rng(), 0..n))
    }

    /// A state drawing from `rng`, which returns a number in `0..n` for the
    /// `n` it is given: the session id is
    /// `1_000_000_000_000_000_000 + rng(800_000_000_000_000_000)`, drawn
    /// here; an audio slot's SSRC is `1_000_000_000 + rng(1_000_000_000)`,
    /// drawn at its first use.
    pub fn with_rng(rng: impl FnMut(u64) -> u64 + Send + 'static) -> Self {
        let mut rng: Box<dyn FnMut(u64) -> u64 + Send> = Box::new(rng);
        let session_id = 1_000_000_000_000_000_000 + rng(SESSION_ID_SPAN) % SESSION_ID_SPAN;
        Self {
            session_id,
            version: 0,
            audio_ssrc: BTreeMap::new(),
            rng,
        }
    }

    /// The `o=` session id.
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// The `o=` version of the last answer shaped (0 before the first).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The synthetic SSRC of an audio publish slot, made at its first use
    /// and kept (`audioSSRC`).
    fn audio_ssrc(&mut self, mid: &str) -> Result<u32, ShapeError> {
        if let Some(ssrc) = self.audio_ssrc.get(mid) {
            return Ok(*ssrc);
        }
        if self.audio_ssrc.len() >= AUDIO_SLOTS_MAX {
            return Err(ShapeError::AudioSlots);
        }
        let draw = u32::try_from((self.rng)(AUDIO_SSRC_SPAN) % AUDIO_SSRC_SPAN).unwrap_or(0);
        let ssrc = 1_000_000_000 + draw;
        self.audio_ssrc.insert(mid.into(), ssrc);
        Ok(ssrc)
    }
}

/// The session id is `10^18` plus a number below this.
const SESSION_ID_SPAN: u64 = 800_000_000_000_000_000;
/// An audio slot's SSRC is `10^9` plus a number below this.
const AUDIO_SSRC_SPAN: u64 = 1_000_000_000;

/// Go's `ShapeAnswer`: the answer for `offer`, with our fields read out of
/// the native answer `native_sdp`.
///
/// # Errors
///
/// As [`Native::parse`], then as [`shape_answer`].
pub fn shape_answer_sdp(
    offer: &str,
    native_sdp: &str,
    state: &mut ShapeState,
) -> Result<String, ShapeError> {
    shape_answer(offer, &Native::parse(native_sdp)?, state)
}

/// The answer for `offer` in the reference client's byte order: lines joined
/// with CRLF, none after the last.
///
/// # Errors
///
/// [`ShapeError::Bundle`] for an offer without a BUNDLE group,
/// [`ShapeError::SdpTooLarge`] past [`MAX_SDP_SIZE`]; then, with the version
/// already advanced, [`ShapeError::SectionWithoutMid`],
/// [`ShapeError::Direction`] for an audio or video section that is neither
/// `sendonly` nor `recvonly`, and [`ShapeError::AudioSlots`].
pub fn shape_answer(
    offer: &str,
    native: &Native,
    state: &mut ShapeState,
) -> Result<String, ShapeError> {
    // `(?m)^a=group:BUNDLE (.*)$`, the first.
    let bundle = lines(offer)
        .find_map(|line| line.strip_prefix("a=group:BUNDLE "))
        .ok_or(ShapeError::Bundle)?;
    let offer_sections = sections(offer)?;
    state.version += 2;

    let msid = format!("a=msid:{} {}", native.msid_stream, native.msid_track);
    // Go's strings.Fields(msid)[0]: `a=msid:<stream>`.
    let msid_stream = msid.split_whitespace().next().unwrap_or("a=msid:");
    let crypto = [
        format!("a=ice-ufrag:{}", native.ufrag),
        format!("a=ice-pwd:{}", native.pwd),
        "a=ice-options:trickle".to_owned(),
        native.fingerprint_line.clone(),
        "a=setup:active".to_owned(),
    ];

    // The answer is a little smaller than its offer (about 50 KB for 70).
    let mut out = Answer(String::with_capacity(offer.len()));
    out.0.push_str("v=0");
    out.line(&format!(
        "o=- {} {} IN IP4 127.0.0.1",
        state.session_id, state.version
    ));
    out.line("s=-");
    out.line("t=0 0");
    out.pair("a=group:BUNDLE ", bundle);
    out.pair(
        "a=msid-semantic: WMS ",
        msid_stream.strip_prefix("a=msid:").unwrap_or(msid_stream),
    );
    for section in &offer_sections {
        shape_section(
            &mut out,
            section,
            &crypto,
            state,
            &msid,
            msid_stream,
            &native.cname,
        )?;
    }
    Ok(out.0)
}

/// The answer being written: CRLF before every line but the first.
struct Answer(String);

impl Answer {
    fn line(&mut self, line: &str) {
        self.0.push_str("\r\n");
        self.0.push_str(line);
    }

    fn pair(&mut self, head: &str, tail: &str) {
        self.line(head);
        self.0.push_str(tail);
    }

    fn lines<'a>(&mut self, lines: impl IntoIterator<Item = &'a str>) {
        for line in lines {
            self.line(line);
        }
    }
}

/// One offer section in the reference byte order (`shapeSection`).
fn shape_section(
    out: &mut Answer,
    section: &Section<'_>,
    crypto: &[String; 5],
    state: &mut ShapeState,
    msid: &str,
    msid_stream: &str,
    cname: &str,
) -> Result<(), ShapeError> {
    let mid = section.mid().ok_or(ShapeError::SectionWithoutMid)?;
    let kind = section.kind();
    out.lines(section.0.first().copied());
    out.line("c=IN IP4 0.0.0.0");
    if kind == "application" {
        out.lines(crypto.iter().map(String::as_str));
        out.pair("a=mid:", mid);
        out.line("a=sctp-port:5000");
        return Ok(());
    }
    out.line("a=rtcp:9 IN IP4 0.0.0.0");
    out.lines(crypto.iter().map(String::as_str));
    out.pair("a=mid:", mid);
    out.lines(
        section
            .0
            .iter()
            .copied()
            .filter(|line| line.starts_with("a=extmap:")),
    );
    // `codecLines`: the offer's rtpmap, fmtp and rtcp-fb lines in its order.
    let codecs = section.0.iter().copied().filter(|line| {
        line.starts_with("a=rtpmap:")
            || line.starts_with("a=fmtp:")
            || line.starts_with("a=rtcp-fb:")
    });
    match section.direction() {
        // The SFU sends here: recvonly with the offered vocabulary.
        Some(DIR_SEND_ONLY) => {
            out.line("a=recvonly");
            out.line("a=rtcp-mux");
            out.lines(codecs);
            Ok(())
        }
        // A publish slot.
        Some(DIR_RECV_ONLY) => {
            out.line("a=sendonly");
            if kind == KIND_AUDIO {
                out.line(msid_stream);
                out.0.push(' ');
                out.0.push_str(mid);
                out.0.push_str("-audio");
            } else {
                out.line(msid);
            }
            out.line("a=rtcp-mux");
            out.lines(codecs);
            if kind == KIND_AUDIO {
                // Nothing is sent here; the SSRC is declared and kept.
                let ssrc = state.audio_ssrc(mid)?;
                out.line(&format!("a=ssrc:{ssrc} cname:{cname}"));
                return Ok(());
            }
            // The browser's simulcast declaration with the low layer alone
            // published, and no a=ssrc: the SFU binds the stream by the rid
            // header.
            out.line(&format!(
                "a=rid:{} send max-width={};max-height={};max-fps={};max-br={}",
                control::LAYER_RID,
                control::LAYER_WIDTH,
                control::LAYER_HEIGHT,
                control::LAYER_FPS,
                control::LAYER_KBPS * 1000
            ));
            out.line("a=rid:m send max-width=640;max-height=360;max-fps=20;max-br=500000");
            out.line("a=rid:h send max-width=1280;max-height=720;max-fps=20;max-br=1200000");
            out.line("a=simulcast:send l;m;h");
            Ok(())
        }
        _ => Err(ShapeError::Direction(mid.to_owned())),
    }
}

/// The distinct SSRC attributions of an offer in their first order
/// (`remoteSSRCs`): the streams `accept-producer` reports knowing about.
///
/// Read from the first [`MAX_SDP_LINES`] lines that are not empty, which
/// are all the lines of an offer the shaper took: the list is bounded for
/// any text, and the same as Go's for every offer that is answered.
#[must_use]
pub fn remote_ssrcs(offer: &str) -> Vec<&str> {
    // `(?m)^a=ssrc:(\d+)\s` over the text as it came: digits, then white
    // space, which the line's own end is and the end of the text is not.
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut rest = Some(offer);
    let mut count = 0usize;
    while let Some(text) = rest {
        let (line, tail) = match text.split_once('\n') {
            Some((line, tail)) => (line, Some(tail)),
            None => (text, None),
        };
        rest = tail;
        // A line is empty to the shaper when only its CR is there.
        if !line.is_empty() && line != "\r" {
            count += 1;
            if count > MAX_SDP_LINES {
                break;
            }
        }
        let Some(after) = line.strip_prefix("a=ssrc:") else {
            continue;
        };
        let digits = after
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(after.len());
        let followed = match after.as_bytes().get(digits) {
            Some(byte) => is_space(*byte),
            None => tail.is_some(),
        };
        if digits > 0 && followed && seen.insert(&after[..digits]) {
            out.push(&after[..digits]);
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `fixtureOffer`: the live SFU offer's structure with sanitized values:
    /// an audio-mix sendonly section, the application section, two publish
    /// slots (audio and video recvonly) and one video recv section.
    pub(crate) const FIXTURE_OFFER: &str = concat!(
        "v=0\r\n",
        "o=- 1790552099500 1790552100511 IN IP4 127.0.0.1\r\n",
        "s=-\r\nt=0 0\r\n",
        "a=group:BUNDLE 0 1 2 3 5\r\n",
        "a=ice-lite\r\n",
        "a=msid-semantic: WMS *\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=rtcp:9 IN IP4 0.0.0.0\r\n",
        "a=candidate:1 1 udp 1 192.0.2.1 43210 typ host\r\n",
        "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
        "a=ice-pwd:GZU7Kw3Sq1YSJxrABCtRTGhms\r\n",
        "a=fingerprint:sha-256 32:16:0D:10:FC:A1:F1:04:43:F5:22:01:9B:2E:53:38\r\n",
        "a=setup:actpass\r\n",
        "a=mid:0\r\n",
        "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
        "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n",
        "a=sendonly\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "a=rtcp-fb:111 transport-cc\r\n",
        "a=fmtp:111 useinbandfec=1;minptime=10\r\n",
        "a=ssrc:2463708138 cname:audio-mix\r\n",
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
        "a=ice-pwd:GZU7Kw3Sq1YSJxrABCtRTGhms\r\n",
        "a=mid:1\r\n",
        "a=sendrecv\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
        "a=mid:2\r\n",
        "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n",
        "a=recvonly\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:111 opus/48000/2\r\n",
        "a=fmtp:111 useinbandfec=1;minptime=10;maxaveragebitrate=64000\r\n",
        "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
        "a=mid:3\r\n",
        "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
        "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n",
        "a=recvonly\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:102 VP9/90000\r\n",
        "a=rtcp-fb:102 transport-cc\r\n",
        "a=rtpmap:103 rtx/90000\r\n",
        "a=fmtp:103 apt=102\r\n",
        "a=rtpmap:100 VP8/90000\r\n",
        "a=rtcp-fb:100 nack\r\n",
        "a=rtcp-fb:100 nack pli\r\n",
        "a=rid:l recv\r\n",
        "a=simulcast:recv l\r\n",
        "m=video 9 UDP/TLS/RTP/SAVPF 100 101\r\n",
        "c=IN IP4 0.0.0.0\r\n",
        "a=ice-ufrag:QcK1avCrgDjn21p\r\n",
        "a=mid:5\r\n",
        "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
        "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n",
        "a=sendonly\r\n",
        "a=rtcp-mux\r\n",
        "a=rtpmap:100 VP8/90000\r\n",
        "a=rtcp-fb:100 nack\r\n",
        "a=ssrc:2463708139 cname:pat\r\n",
        "a=ssrc:2463708139 msid:pat video-pat\r\n",
    );

    /// `fixtureNative`: the fields the shaper takes from the stack's answer.
    const FIXTURE_NATIVE: &str = concat!(
        "v=0\r\n",
        "o=- 123 2 IN IP4 127.0.0.1\r\n",
        "s=-\r\nt=0 0\r\n",
        "a=group:BUNDLE 0 1 2 3 5\r\n",
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n",
        "a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n",
        "a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\r\n",
        "a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\r\n",
        "a=mid:0\r\n",
        "a=recvonly\r\n",
        "m=video 9 UDP/TLS/RTP/SAVPF 100\r\n",
        "a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n",
        "a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc\r\n",
        "a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA\r\n",
        "a=mid:3\r\n",
        "a=sendonly\r\n",
        "a=msid:proofkit video\r\n",
        "a=ssrc:3842537998 cname:proofkit\r\n",
    );

    const CRYPTO: [&str; 5] = [
        "a=ice-ufrag:KdfaZFqRLOnUhmUW",
        "a=ice-pwd:WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc",
        "a=ice-options:trickle",
        "a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA",
        "a=setup:active",
    ];

    const TWCC: &str =
        "a=extmap:4 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
    const ABS_SEND_TIME: &str =
        "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";

    fn zero_state() -> ShapeState {
        ShapeState::with_rng(|_| 0)
    }

    /// `sectionOf`: the first run of sections whose `m=` line is `m_line`.
    fn section_of<'a>(lines: &[&'a str], m_line: &str) -> Vec<&'a str> {
        let mut out: Option<Vec<&str>> = None;
        for &line in lines {
            if line.starts_with("m=") {
                if line == m_line {
                    out.get_or_insert_with(Vec::new).push(line);
                } else if out.is_some() {
                    break;
                }
                continue;
            }
            if let Some(out) = out.as_mut() {
                out.push(line);
            }
        }
        out.unwrap_or_else(|| panic!("section {m_line:?} not found"))
    }

    /// `sectionByMid`: the first section holding the line `mid`.
    fn section_by_mid<'a>(lines: &[&'a str], mid: &str) -> Vec<&'a str> {
        let mut sections: Vec<Vec<&str>> = Vec::new();
        for &line in lines {
            if line.starts_with("m=") {
                sections.push(vec![line]);
            } else if let Some(last) = sections.last_mut() {
                last.push(line);
            }
        }
        sections
            .into_iter()
            .find(|section| section.contains(&mid))
            .unwrap_or_else(|| panic!("section with {mid:?} not found"))
    }

    // TestShapeAnswerStructure.
    #[test]
    fn shape_answer_structure() {
        let mut state = ShapeState::new();
        let shaped = shape_answer_sdp(FIXTURE_OFFER, FIXTURE_NATIVE, &mut state).unwrap();
        let lines: Vec<&str> = shaped.split("\r\n").collect();

        // Session header: fully generated, BUNDLE echoed from the offer.
        assert_eq!(lines[0], "v=0");
        assert!(
            lines[1].starts_with("o=- "),
            "session header {:?}",
            &lines[..6]
        );
        assert_eq!(lines[4], "a=group:BUNDLE 0 1 2 3 5");
        assert_eq!(lines[5], "a=msid-semantic: WMS proofkit");

        // The application section keeps the reference shape: no direction,
        // no rtcp.
        let app = section_of(&lines, "m=application 9 UDP/DTLS/SCTP webrtc-datachannel");
        let mut want = vec![
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
        ];
        want.extend(CRYPTO);
        want.extend(["a=mid:1", "a=sctp-port:5000"]);
        assert_eq!(app, want);

        // A recv section answers recvonly with the offered codec vocabulary,
        // no SSRC attributions, no rid/simulcast from the offer.
        let recv = section_of(&lines, "m=video 9 UDP/TLS/RTP/SAVPF 100 101");
        let mut want = vec![
            "m=video 9 UDP/TLS/RTP/SAVPF 100 101",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
        ];
        want.extend(CRYPTO);
        want.extend([
            "a=mid:5",
            TWCC,
            ABS_SEND_TIME,
            "a=recvonly",
            "a=rtcp-mux",
            "a=rtpmap:100 VP8/90000",
            "a=rtcp-fb:100 nack",
        ]);
        assert_eq!(recv, want);

        // The video publish slot takes the browser's simulcast declaration:
        // three rid constraints, one simulcast line, no SSRC attribution.
        let publish = section_of(&lines, "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101");
        for want in [
            "a=sendonly",
            "a=msid:proofkit video",
            "a=rid:l send max-width=320;max-height=180;max-fps=15;max-br=180000",
            "a=rid:m send max-width=640;max-height=360;max-fps=20;max-br=500000",
            "a=rid:h send max-width=1280;max-height=720;max-fps=20;max-br=1200000",
            "a=simulcast:send l;m;h",
        ] {
            assert!(
                publish.contains(&want),
                "publish section missing {want:?}: {publish:?}"
            );
        }
        assert!(
            !publish.iter().any(|line| line.starts_with("a=ssrc:")),
            "ssrc attribution leaked into the video publish slot: {publish:?}"
        );

        // The audio publish slot gets a stable synthetic SSRC and our msid
        // with a slot-scoped track id. Both audio sections share one m=
        // text, so the publish one is found by its mid.
        let audio = section_by_mid(&lines, "a=mid:2");
        assert!(
            audio.contains(&"a=sendonly"),
            "audio publish section {audio:?}"
        );
        assert!(
            audio.contains(&"a=msid:proofkit 2-audio"),
            "audio publish msid: {audio:?}"
        );
        let ssrc = audio
            .iter()
            .find(|line| line.starts_with("a=ssrc:"))
            .expect("audio publish slot without SSRC");
        let number: u32 = ssrc
            .strip_prefix("a=ssrc:")
            .and_then(|rest| rest.strip_suffix(" cname:proofkit"))
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("audio ssrc line {ssrc:?}"));
        assert!((1_000_000_000..2_000_000_000).contains(&number));
        let again = shape_answer_sdp(FIXTURE_OFFER, FIXTURE_NATIVE, &mut state).unwrap();
        assert!(
            again.split("\r\n").any(|line| line == *ssrc),
            "synthetic audio SSRC is not stable across re-answers"
        );

        // Offer candidates and ssrc attributions never leak into the answer.
        for line in &lines {
            assert!(
                !line.starts_with("a=candidate:"),
                "candidate leaked: {line:?}"
            );
            assert_ne!(*line, "a=ssrc:2463708138 cname:audio-mix");
        }
        // The session id is in Go's range.
        assert!(
            (1_000_000_000_000_000_000..1_800_000_000_000_000_000).contains(&state.session_id())
        );
    }

    // TestShapeAnswerVersionBumps: the version moves by two, the session id
    // stays.
    #[test]
    fn shape_answer_version_bumps() {
        let mut state = ShapeState::new();
        let first = shape_answer_sdp(FIXTURE_OFFER, FIXTURE_NATIVE, &mut state).unwrap();
        let second = shape_answer_sdp(FIXTURE_OFFER, FIXTURE_NATIVE, &mut state).unwrap();
        let o1: Vec<&str> = first.split("\r\n").nth(1).unwrap().split(' ').collect();
        let o2: Vec<&str> = second.split("\r\n").nth(1).unwrap().split(' ').collect();
        assert_eq!(o1[1], o2[1], "o= session id changed across answers");
        assert_eq!(o1[1], state.session_id().to_string());
        assert_eq!((o1[2], o2[2]), ("2", "4"));
        assert_eq!(state.version(), 4);
    }

    // TestShapeAnswerErrors.
    #[test]
    fn shape_answer_errors() {
        assert_eq!(
            shape_answer_sdp(FIXTURE_OFFER, "v=0", &mut ShapeState::new()),
            Err(ShapeError::NoCrypto)
        );
        let no_publish = FIXTURE_NATIVE.replace("a=ssrc:3842537998 cname:proofkit\r\n", "");
        assert_eq!(
            shape_answer_sdp(FIXTURE_OFFER, &no_publish, &mut ShapeState::new()),
            Err(ShapeError::NoPublish)
        );
        let no_bundle = FIXTURE_OFFER.replace("a=group:BUNDLE 0 1 2 3 5\r\n", "");
        assert_eq!(
            shape_answer_sdp(&no_bundle, FIXTURE_NATIVE, &mut ShapeState::new()),
            Err(ShapeError::Bundle)
        );
    }

    // The errors Go's test does not reach, and where the version stands
    // after each: it moves once the offer has a BUNDLE group and is within
    // the bound, before the sections are read.
    #[test]
    fn shape_answer_section_errors() {
        let native = Native::parse(FIXTURE_NATIVE).unwrap();

        let mut state = zero_state();
        let no_mid = FIXTURE_OFFER.replace("a=mid:2\r\n", "");
        assert_eq!(
            shape_answer(&no_mid, &native, &mut state),
            Err(ShapeError::SectionWithoutMid)
        );
        assert_eq!(state.version(), 2);

        // `a=mid:` must be followed by one token to count.
        let mut state = zero_state();
        let spaced = FIXTURE_OFFER.replace("a=mid:2\r\n", "a=mid:2 x\r\n");
        assert_eq!(
            shape_answer(&spaced, &native, &mut state),
            Err(ShapeError::SectionWithoutMid)
        );

        // sendrecv on a media section (the application section's is never
        // read).
        let mut state = zero_state();
        let both = FIXTURE_OFFER.replace("a=mid:5\r\n", "a=mid:5\r\na=sendrecv\r\n");
        assert_eq!(
            shape_answer(&both, &native, &mut state),
            Err(ShapeError::Direction("5".into()))
        );
        // No direction at all.
        let none = FIXTURE_OFFER
            .replace("a=mid:3\r\n", "a=mid:3x\r\n")
            .replacen(
                "a=recvonly\r\na=rtcp-mux\r\na=rtpmap:102",
                "a=rtcp-mux\r\na=rtpmap:102",
                1,
            );
        assert_eq!(
            shape_answer(&none, &native, &mut state),
            Err(ShapeError::Direction("3x".into()))
        );
        assert_eq!(state.version(), 4);

        // The bound: one byte past it is refused, with the version where it
        // was. Go measures the text after CRLF became LF.
        let mut state = zero_state();
        let measured = FIXTURE_OFFER.len() - FIXTURE_OFFER.matches("\r\n").count();
        let mut large = String::from(FIXTURE_OFFER);
        large.push_str(&"x".repeat(MAX_SDP_SIZE - measured));
        assert!(large.len() > MAX_SDP_SIZE);
        shape_answer(&large, &native, &mut state).expect("at the bound once CRLF is one byte");
        large.push('x');
        assert_eq!(
            shape_answer(&large, &native, &mut state),
            Err(ShapeError::SdpTooLarge)
        );
        assert_eq!(state.version(), 2);
        // One long line: the bound on the lines is not what refuses it.
        let mut large_native = String::from(FIXTURE_NATIVE);
        large_native.push_str("a=");
        large_native.push_str(&"x".repeat(MAX_SDP_SIZE));
        large_native.push('\n');
        assert_eq!(Native::parse(&large_native), Err(ShapeError::SdpTooLarge));
        // Go reads the crypto lines before it measures.
        assert_eq!(
            Native::parse(&"a=x\n".repeat(MAX_SDP_SIZE / 4 + 1)),
            Err(ShapeError::NoCrypto)
        );
    }

    /// Not Go's: an SDP of more sections or more lines than the bounds is
    /// refused as too large, before a list is made for what is past them.
    #[test]
    fn the_sections_and_the_lines_of_an_sdp_are_bounded() {
        let count = |sdp: &str| sections(sdp).map(|found| found.len());
        // Sections: 128 pass, the 129th refuses.
        let section = "m=audio 9 X 0\r\na=mid:0\r\n";
        assert_eq!(
            count(&section.repeat(MAX_SDP_SECTIONS)),
            Ok(MAX_SDP_SECTIONS)
        );
        assert_eq!(
            count(&section.repeat(MAX_SDP_SECTIONS + 1)),
            Err(ShapeError::SdpTooLarge)
        );
        // Lines: the session's count, empty ones do not. 16,384 pass.
        let at = format!(
            "v=0\r\n\r\nm=audio 9 X 0\r\n{}",
            "a=x\r\n\r\n".repeat(MAX_SDP_LINES - 2)
        );
        let found = sections(&at).unwrap();
        assert_eq!((found.len(), found[0].0.len()), (1, MAX_SDP_LINES - 1));
        drop(found);
        assert_eq!(count(&(at.clone() + "a=x")), Err(ShapeError::SdpTooLarge));
        // A line with no `m=` before it counts as well.
        assert_eq!(
            count(&"a=x\n".repeat(MAX_SDP_LINES + 1)),
            Err(ShapeError::SdpTooLarge)
        );
        assert_eq!(count(&"a=x\n".repeat(MAX_SDP_LINES)), Ok(0));
        assert!(
            at.len() < MAX_SDP_SIZE / 4,
            "the size bound is not what refused"
        );

        // The shaper refuses such an offer where it refuses a large one:
        // before the version moves.
        let native = Native::parse(FIXTURE_NATIVE).unwrap();
        let mut state = zero_state();
        let before = state.version();
        let many = String::from(FIXTURE_OFFER) + &section.repeat(MAX_SDP_SECTIONS - 4);
        assert_eq!(
            shape_answer(&many, &native, &mut state),
            Err(ShapeError::SdpTooLarge)
        );
        let long = String::from(FIXTURE_OFFER) + &"a=x\r\n".repeat(MAX_SDP_LINES);
        assert_eq!(
            shape_answer(&long, &native, &mut state),
            Err(ShapeError::SdpTooLarge)
        );
        assert_eq!(state.version(), before);

        // Which bound it was, for the log: the same walk says.
        assert_eq!(breached(FIXTURE_OFFER), None);
        assert_eq!(breached(&section.repeat(MAX_SDP_SECTIONS)), None);
        assert_eq!(breached(&many), Some(SdpBound::Sections));
        assert_eq!(breached(&long), Some(SdpBound::Lines));
        assert_eq!(
            breached(&"a=x\n".repeat(MAX_SDP_SIZE / 4 + 1)),
            Some(SdpBound::Size)
        );
        assert_eq!(
            [SdpBound::Size, SdpBound::Sections, SdpBound::Lines].map(|b| b.to_string()),
            [
                "MAX_SDP_SIZE (1048576 bytes)",
                "MAX_SDP_SECTIONS (128)",
                "MAX_SDP_LINES (16384)"
            ]
        );
        // The SSRCs of an offer are read from as many lines and no more.
        let ssrcs: String = (0..MAX_SDP_LINES + 5)
            .map(|n| format!("a=ssrc:{n} cname:x\n"))
            .collect();
        assert_eq!(remote_ssrcs(&ssrcs).len(), MAX_SDP_LINES);
        assert_eq!(remote_ssrcs(&ssrcs).last(), Some(&"16383"));
    }

    // The whole answer for the fixture, byte for byte, with the random
    // parts at their lowest. Worked out by hand from answer.go:141-290 (the
    // Go-generated shape.json joins at the merge).
    #[test]
    fn shape_answer_whole_text() {
        let mut state = zero_state();
        let shaped = shape_answer_sdp(FIXTURE_OFFER, FIXTURE_NATIVE, &mut state).unwrap();
        let mut want: Vec<&str> = vec![
            "v=0",
            "o=- 1000000000000000000 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0 1 2 3 5",
            "a=msid-semantic: WMS proofkit",
        ];
        // mid 0: the SFU's audio mix.
        want.extend([
            "m=audio 9 UDP/TLS/RTP/SAVPF 111",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
        ]);
        want.extend(CRYPTO);
        want.extend([
            "a=mid:0",
            TWCC,
            "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            "a=recvonly",
            "a=rtcp-mux",
            "a=rtpmap:111 opus/48000/2",
            "a=rtcp-fb:111 transport-cc",
            "a=fmtp:111 useinbandfec=1;minptime=10",
        ]);
        // mid 1: the data channels.
        want.extend([
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
        ]);
        want.extend(CRYPTO);
        want.extend(["a=mid:1", "a=sctp-port:5000"]);
        // mid 2: the audio publish slot.
        want.extend([
            "m=audio 9 UDP/TLS/RTP/SAVPF 111",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
        ]);
        want.extend(CRYPTO);
        want.extend([
            "a=mid:2",
            "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            "a=sendonly",
            "a=msid:proofkit 2-audio",
            "a=rtcp-mux",
            "a=rtpmap:111 opus/48000/2",
            "a=fmtp:111 useinbandfec=1;minptime=10;maxaveragebitrate=64000",
            "a=ssrc:1000000000 cname:proofkit",
        ]);
        // mid 3: the video publish slot.
        want.extend([
            "m=video 9 UDP/TLS/RTP/SAVPF 102 103 100 101",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
        ]);
        want.extend(CRYPTO);
        want.extend([
            "a=mid:3",
            TWCC,
            ABS_SEND_TIME,
            "a=sendonly",
            "a=msid:proofkit video",
            "a=rtcp-mux",
            "a=rtpmap:102 VP9/90000",
            "a=rtcp-fb:102 transport-cc",
            "a=rtpmap:103 rtx/90000",
            "a=fmtp:103 apt=102",
            "a=rtpmap:100 VP8/90000",
            "a=rtcp-fb:100 nack",
            "a=rtcp-fb:100 nack pli",
            "a=rid:l send max-width=320;max-height=180;max-fps=15;max-br=180000",
            "a=rid:m send max-width=640;max-height=360;max-fps=20;max-br=500000",
            "a=rid:h send max-width=1280;max-height=720;max-fps=20;max-br=1200000",
            "a=simulcast:send l;m;h",
        ]);
        // mid 5: a video the SFU sends.
        want.extend([
            "m=video 9 UDP/TLS/RTP/SAVPF 100 101",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
        ]);
        want.extend(CRYPTO);
        want.extend([
            "a=mid:5",
            TWCC,
            ABS_SEND_TIME,
            "a=recvonly",
            "a=rtcp-mux",
            "a=rtpmap:100 VP8/90000",
            "a=rtcp-fb:100 nack",
        ]);
        assert_eq!(shaped.split("\r\n").collect::<Vec<_>>(), want);
        // CRLF between lines, none after the last.
        assert_eq!(shaped, want.join("\r\n"));

        // An offer with bare LF and blank lines shapes the same.
        let mut state = zero_state();
        let bare = FIXTURE_OFFER
            .replace("\r\n", "\n")
            .replace("a=mid:5\n", "\n\na=mid:5\n");
        let native = FIXTURE_NATIVE.replace("\r\n", "\n");
        assert_eq!(
            shape_answer_sdp(&bare, &native, &mut state).unwrap(),
            want.join("\r\n")
        );
    }

    // The native parser's rules, as Go's regular expressions have them.
    #[test]
    fn native_parse_follows_gos_patterns() {
        let native = Native::parse(FIXTURE_NATIVE).unwrap();
        assert_eq!(native.ufrag, "KdfaZFqRLOnUhmUW");
        assert_eq!(native.pwd, "WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc");
        assert_eq!(
            native.fingerprint_line,
            "a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA"
        );
        assert_eq!(
            (
                native.msid_stream.as_str(),
                native.msid_track.as_str(),
                native.cname.as_str()
            ),
            ("proofkit", "video", "proofkit")
        );
        // Debug shows no credential.
        let shown = format!("{native:?}");
        assert!(!shown.contains("KdfaZ") && !shown.contains("WTug") && !shown.contains("BC:92"));

        // A line that is not one token is passed over for the next that is.
        let two = FIXTURE_NATIVE.replacen(
            "a=ice-ufrag:KdfaZFqRLOnUhmUW\r\n",
            "a=ice-ufrag:two words\r\na=ice-ufrag:\r\n",
            1,
        );
        assert_eq!(Native::parse(&two).unwrap().ufrag, "KdfaZFqRLOnUhmUW");

        // No msid line: the default.
        let plain = FIXTURE_NATIVE.replace("a=msid:proofkit video\r\n", "");
        let native = Native::parse(&plain).unwrap();
        assert_eq!(
            (native.msid_stream.as_str(), native.msid_track.as_str()),
            ("proofkit", "video")
        );
        // An msid line with one token is not one.
        let odd = FIXTURE_NATIVE.replace("a=msid:proofkit video\r\n", "a=msid:alone\r\n");
        assert_eq!(Native::parse(&odd).unwrap().msid_stream, "proofkit");
        let named =
            FIXTURE_NATIVE.replace("a=msid:proofkit video", "a=msid:olcrtc-ab vp8channel-cd");
        let native = Native::parse(&named).unwrap();
        assert_eq!(
            (native.msid_stream.as_str(), native.msid_track.as_str()),
            ("olcrtc-ab", "vp8channel-cd")
        );

        // A sendonly video section without a cname line is passed over for
        // the next one that has it; a recvonly one is never read.
        let later = format!(
            "{}{}",
            FIXTURE_NATIVE.replace("a=ssrc:3842537998 cname:proofkit\r\n", ""),
            "m=video 9 UDP/TLS/RTP/SAVPF 100\r\na=mid:7\r\na=sendonly\r\na=ssrc:5 cname:second\r\n"
        );
        let native = Native::parse(&later).unwrap();
        assert_eq!(
            (native.msid_stream.as_str(), native.cname.as_str()),
            ("proofkit", "second")
        );
        let receive_only = FIXTURE_NATIVE.replace("a=sendonly", "a=recvonly");
        assert_eq!(Native::parse(&receive_only), Err(ShapeError::NoPublish));

        // An SSRC that does not fit 32 bits ends the search.
        let wide = FIXTURE_NATIVE.replace("a=ssrc:3842537998 ", "a=ssrc:4294967296 ");
        assert_eq!(Native::parse(&wide), Err(ShapeError::NoPublish));
        // Without a final line end, the last line still counts.
        let cut = FIXTURE_NATIVE.trim_end();
        assert_eq!(Native::parse(cut).unwrap().cname, "proofkit");
        // A lone CR at the very end is part of the token's line: no match.
        let lone = format!("{cut}\r");
        assert_eq!(Native::parse(&lone), Err(ShapeError::NoPublish));
    }

    // A caller that builds `Native` itself gets the same text as the parser.
    #[test]
    fn shape_answer_from_fields() {
        let native = Native {
            ufrag: "KdfaZFqRLOnUhmUW".into(),
            pwd: "WTugXtAYkOEfiYMfOWDCKNNQNhVqAkoc".into(),
            fingerprint_line:
                "a=fingerprint:sha-256 BC:92:07:E6:13:23:65:25:C2:FE:85:A0:9D:EE:46:CA".into(),
            msid_stream: "olcrtc-ab".into(),
            msid_track: "vp8channel-cd".into(),
            cname: "cn".into(),
        };
        let shaped = shape_answer(FIXTURE_OFFER, &native, &mut zero_state()).unwrap();
        let lines: Vec<&str> = shaped.split("\r\n").collect();
        assert_eq!(lines[5], "a=msid-semantic: WMS olcrtc-ab");
        assert!(lines.contains(&"a=msid:olcrtc-ab vp8channel-cd"));
        assert!(lines.contains(&"a=msid:olcrtc-ab 2-audio"));
        assert!(lines.contains(&"a=ssrc:1000000000 cname:cn"));
        let from_text = shape_answer_sdp(
            FIXTURE_OFFER,
            &FIXTURE_NATIVE
                .replace("a=msid:proofkit video", "a=msid:olcrtc-ab vp8channel-cd")
                .replace("cname:proofkit", "cname:cn"),
            &mut zero_state(),
        )
        .unwrap();
        assert_eq!(shaped, from_text);
    }

    // Every audio publish slot keeps its own SSRC, drawn once; the number
    // of slots kept is bounded.
    #[test]
    fn audio_slots_keep_their_ssrc_and_are_bounded() {
        let native = Native::parse(FIXTURE_NATIVE).unwrap();
        let mut next = 0u64;
        let mut state = ShapeState::with_rng(move |n| {
            next += 7;
            next % n
        });
        assert_eq!(state.session_id(), 1_000_000_000_000_000_007);
        let slot =
            |mid: &str| format!("m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:{mid}\r\na=recvonly\r\n");
        let offer = format!("a=group:BUNDLE a b\r\n{}{}", slot("a"), slot("b"));
        let first = shape_answer(&offer, &native, &mut state).unwrap();
        assert!(first.contains("a=ssrc:1000000014 cname:proofkit\r\n"));
        assert!(first.ends_with("a=ssrc:1000000021 cname:proofkit"));
        let swapped = format!("a=group:BUNDLE b a\r\n{}{}", slot("b"), slot("a"));
        let second = shape_answer(&swapped, &native, &mut state).unwrap();
        assert!(second.contains(
            "a=mid:b\r\na=sendonly\r\na=msid:proofkit b-audio\r\na=rtcp-mux\r\na=ssrc:1000000021 "
        ));
        assert!(second.ends_with("a=ssrc:1000000014 cname:proofkit"));

        let mut state = zero_state();
        let many: String = (0..AUDIO_SLOTS_MAX).map(|i| slot(&i.to_string())).collect();
        let offer = format!("a=group:BUNDLE x\r\n{many}");
        shape_answer(&offer, &native, &mut state).unwrap();
        // The same slots again are known; one more is refused.
        shape_answer(&offer, &native, &mut state).unwrap();
        let more = format!("{offer}{}", slot("one-more"));
        assert_eq!(
            shape_answer(&more, &native, &mut state),
            Err(ShapeError::AudioSlots)
        );
    }

    // TestRemoteSSRCs.
    #[test]
    fn remote_ssrcs_of_the_fixture() {
        assert_eq!(remote_ssrcs(FIXTURE_OFFER), ["2463708138", "2463708139"]);
    }

    // The pattern is `(?m)^a=ssrc:(\d+)\s`: digits, then white space, which
    // a line end is and the end of the text is not.
    #[test]
    fn remote_ssrcs_follows_gos_pattern() {
        assert_eq!(
            remote_ssrcs("a=ssrc:7 cname:x\na=ssrc:7 msid:y\na=ssrc:8\na=ssrc:9"),
            ["7", "8"]
        );
        assert_eq!(
            remote_ssrcs("a=ssrc:1\ta\r\na=ssrc:2\r\n a=ssrc:3 x\na=ssrc: 4\na=ssrc:5x y\n"),
            ["1", "2"]
        );
        assert!(remote_ssrcs("").is_empty());
        assert_eq!(
            remote_ssrcs("a=ssrc-group:FID 1 2\na=ssrc:3 a\na=ssrc:1 a\na=ssrc:3 b\n"),
            ["3", "1"]
        );
    }

    #[test]
    fn the_state_is_small() {
        assert!(
            std::mem::size_of::<ShapeState>() <= 64,
            "ShapeState is {} bytes",
            std::mem::size_of::<ShapeState>()
        );
    }
}

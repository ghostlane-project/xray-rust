// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The producer control route (`control.go`, `stamp.go`, and the counter and
//! registry of `vkcalls.go`'s `generation`): a small MessagePack subset over
//! the `producerCommand` data channel, and the registry frames of
//! `producerNotification`.
//!
//! The subset is written by hand because no MessagePack library writes it:
//! an integer from 128 to 32,767 goes out as int16 (`D1`), never as uint8 or
//! uint16, which is what the service's own encoder picks.

use std::collections::{BTreeMap, BTreeSet};

/// The leading byte of the one `producerNotification` kind that is read: a
/// map of stream descriptions to the compact ids this consumer addresses
/// them by.
pub const REGISTRY_KIND: u8 = 1;

/// Sequence numbers on `producerCommand` are the counter modulo this
/// (`commandSeqMod`), except in the first `change-simulcast`.
pub const COMMAND_SEQ_MOD: u64 = 1 << 20;

/// The one simulcast layer the engine declares (`stamp.go`): its rid.
pub const LAYER_RID: &str = "l";
/// The declared layer's width.
pub const LAYER_WIDTH: i64 = 320;
/// The declared layer's height.
pub const LAYER_HEIGHT: i64 = 180;
/// The declared layer's frame rate.
pub const LAYER_FPS: i64 = 15;
/// The declared layer's bitrate in kbit/s.
pub const LAYER_KBPS: i64 = 180;

/// What every layout entry asks for (`LayoutFor`, `layoutEntries`).
pub const TILE_PRIORITY: i64 = 1;
/// The tile width every layout entry asks for.
pub const TILE_WIDTH: i64 = 640;
/// The tile height every layout entry asks for.
pub const TILE_HEIGHT: i64 = 360;

/// The most streams the registry keeps. Go keeps every key it is told; a
/// compact id is one byte, so no more than this many streams can be
/// addressed at once, and a key past the bound is not kept.
pub const REGISTRY_MAX: usize = 256;

/// The most participants noted at once. Go has no bound; past this one a
/// participant is not noted (its camera is asked for once the registry names
/// it, or never).
pub const PARTICIPANTS_MAX: usize = 256;

/// Why a `producerNotification` frame gave no registry. The texts are Go's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// `ErrRegistryShort`.
    #[error("vkcalls: producerNotification shorter than its header")]
    Short,
    /// `ErrRegistryShape`.
    #[error("vkcalls: producerNotification registry is not a one-entry map")]
    Shape,
    /// `ErrNotRegistry`: a frame of another kind, expected and skipped.
    #[error("vkcalls: frame is not a registry update")]
    NotRegistry,
}

/// Why a layout was not encoded. The texts are Go's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    /// `ErrLayoutNoStream`.
    #[error("vkcalls: layout update without any registry stream")]
    NoStream,
    /// `ErrLayoutKeyLong`, with the key's (or the entry's) size.
    #[error("vkcalls: registry stream key exceeds the fixstr bound: {0} bytes")]
    KeyLong(usize),
    /// `ErrLayoutTooMany`, with the number of entries.
    #[error("vkcalls: layout update exceeds the array16 bound: {0} entries")]
    TooMany(usize),
}

/// Stream descriptions and the compact ids this consumer must address them
/// by in `update-display-layout`. Keys are kept as the bytes the service
/// sent, in bytewise order (Go's `sort.Strings`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Registry(BTreeMap<Box<[u8]>, u8>);

impl<K: AsRef<[u8]>, const N: usize> From<[(K, u8); N]> for Registry {
    fn from(entries: [(K, u8); N]) -> Self {
        let mut out = Self::default();
        for (key, id) in entries {
            out.insert(key, id);
        }
        out
    }
}

impl Registry {
    /// Decodes a kind-1 `producerNotification` frame (`ParseRegistry`).
    ///
    /// # Errors
    ///
    /// [`RegistryError::NotRegistry`] for a frame of another kind,
    /// [`RegistryError::Short`] for a truncated one, [`RegistryError::Shape`]
    /// for anything that is not a map of fixstr keys to small ids.
    pub fn parse(frame: &[u8]) -> Result<Self, RegistryError> {
        let Some(&kind) = frame.first() else {
            return Err(RegistryError::Short);
        };
        if kind != REGISTRY_KIND {
            return Err(RegistryError::NotRegistry);
        }
        if frame.len() < 4 {
            return Err(RegistryError::Short);
        }
        let (count, mut pos) = match frame[1] {
            // fixmap
            head if head & 0xF0 == 0x80 => (usize::from(head & 0x0F), 2),
            // map16
            0xDE => (usize::from(u16::from_be_bytes([frame[2], frame[3]])), 4),
            _ => return Err(RegistryError::Shape),
        };
        let mut out = Self::default();
        for _ in 0..count {
            let (key, next) = read_registry_key(frame, pos)?;
            let (id, after) = read_registry_id(frame, next)?;
            out.0.insert(key.into(), id);
            pos = after;
        }
        Ok(out)
    }

    /// The number of streams.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no stream is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The compact id of a stream description.
    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<u8> {
        self.0.get(key.as_ref()).copied()
    }

    /// Sets a stream's compact id.
    pub fn insert(&mut self, key: impl AsRef<[u8]>, id: u8) {
        self.0.insert(key.as_ref().into(), id);
    }

    /// The streams in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], u8)> {
        self.0.iter().map(|(key, id)| (&**key, *id))
    }

    /// The subscription of every registry stream by its compact id, in key
    /// order (`LayoutFor`).
    ///
    /// # Errors
    ///
    /// [`LayoutError::NoStream`] for an empty registry.
    pub fn layout_for(&self) -> Result<Vec<LayoutEntry>, LayoutError> {
        if self.0.is_empty() {
            return Err(LayoutError::NoStream);
        }
        Ok(self
            .0
            .iter()
            .map(|(key, id)| LayoutEntry {
                key: key.to_vec(),
                compact: *id,
                by_compact: true,
                priority: TILE_PRIORITY,
                width: TILE_WIDTH,
                height: TILE_HEIGHT,
            })
            .collect())
    }
}

/// The fixstr stream description at `pos` and where it ends
/// (`readRegistryKey`).
fn read_registry_key(frame: &[u8], pos: usize) -> Result<(&[u8], usize), RegistryError> {
    let head = *frame.get(pos).ok_or(RegistryError::Short)?;
    if head & 0xE0 != 0xA0 {
        return Err(RegistryError::Shape);
    }
    let end = pos + 1 + usize::from(head & 0x1F);
    let key = frame.get(pos + 1..end).ok_or(RegistryError::Short)?;
    Ok((key, end))
}

/// The compact id at `pos` and where it ends (`readRegistryID`): a positive
/// fixint, or the uint8 form the service's encoder picks from 128 on.
fn read_registry_id(frame: &[u8], pos: usize) -> Result<(u8, usize), RegistryError> {
    match frame.get(pos) {
        None => Err(RegistryError::Short),
        Some(&id) if id < 0x80 => Ok((id, pos + 1)),
        Some(0xCC) => match frame.get(pos + 1) {
            Some(&id) => Ok((id, pos + 2)),
            None => Err(RegistryError::Short),
        },
        Some(_) => Err(RegistryError::Shape),
    }
}

/// One stream subscription: the tile priority and the size the consumer
/// displays it at, which the SFU uses to pick a simulcast layer.
/// `by_compact` selects the compact-id addressing; otherwise the key goes
/// out as a fixstr.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LayoutEntry {
    /// The stream description.
    pub key: Vec<u8>,
    /// The compact id, read when `by_compact` is set.
    pub compact: u8,
    /// Address the stream by `compact`.
    pub by_compact: bool,
    /// The tile priority.
    pub priority: i64,
    /// The tile width; 0 leaves the size unset.
    pub width: i64,
    /// The tile height; 0 leaves the size unset.
    pub height: i64,
}

/// Appends an integer in the wire's form (`appendMPInt`): one byte for
/// 0..=127, the int16 marker for the rest of the int16 range, otherwise the
/// int32 marker with the low 32 bits.
pub fn append_mp_int(dst: &mut Vec<u8>, value: i64) {
    match (u8::try_from(value), i16::try_from(value)) {
        (Ok(small), _) if small < 128 => dst.push(small),
        (_, Ok(short)) => {
            dst.push(0xD1);
            dst.extend_from_slice(&short.to_be_bytes());
        }
        _ => {
            // The low 32 bits, as Go's uint32(value).
            dst.push(0xD2);
            dst.extend_from_slice(&value.to_be_bytes()[4..]);
        }
    }
}

/// The `update-display-layout` frame (`EncodeLayout`):
/// `[0, 0, sequence, nil, [bin(layout)…], nil]`.
///
/// # Errors
///
/// [`LayoutError::NoStream`] for no entries or an entry with neither a
/// compact id nor a key, [`LayoutError::TooMany`] past 65,535 entries,
/// [`LayoutError::KeyLong`] for a key of 32 bytes or more.
pub fn encode_layout(sequence: i64, entries: &[LayoutEntry]) -> Result<Vec<u8>, LayoutError> {
    if entries.is_empty() {
        return Err(LayoutError::NoStream);
    }
    let Ok(count) = u16::try_from(entries.len()) else {
        return Err(LayoutError::TooMany(entries.len()));
    };
    // A compact entry is 12 bytes; one asked by a camera key about 30.
    let mut out = Vec::with_capacity(8 + entries.len() * 16);
    append_mp_int(&mut out, 0);
    append_mp_int(&mut out, 0);
    append_mp_int(&mut out, sequence);
    out.push(0xC0);
    match count.to_be_bytes() {
        [0, few] if few < 16 => out.push(0x90 | few),
        [high, low] => out.extend_from_slice(&[0xDC, high, low]),
    }
    for entry in entries {
        // bin8: the length is written once the blob is.
        out.push(0xC4);
        let length_at = out.len();
        out.push(0);
        if entry.by_compact {
            out.push(entry.compact);
        } else if !entry.key.is_empty() {
            match u8::try_from(entry.key.len()) {
                Ok(length) if length < 32 => out.push(0xA0 | length),
                _ => return Err(LayoutError::KeyLong(entry.key.len())),
            }
            out.extend_from_slice(&entry.key);
        } else {
            return Err(LayoutError::NoStream);
        }
        out.push(0x00); // variant 0: set the tile layout
        append_mp_int(&mut out, entry.priority);
        if entry.width > 0 && entry.height > 0 {
            append_mp_int(&mut out, entry.width);
            append_mp_int(&mut out, entry.height);
        } else {
            out.extend_from_slice(&[0xC0, 0xC0]);
        }
        out.push(0x00); // fit=cv
        let blob = out.len() - length_at - 1;
        let Ok(length) = u8::try_from(blob) else {
            return Err(LayoutError::KeyLong(blob));
        };
        out[length_at] = length;
    }
    out.push(0xC0);
    Ok(out)
}

/// The `change-simulcast` frame (`encodeChangeSimulcast`): `07 00 seq 1 1`,
/// then the layer's rid, width, height, frame rate and bitrate in kbit/s
/// (`bitrate` is in bit/s).
#[must_use]
pub fn encode_change_simulcast(
    sequence: i64,
    rid: &str,
    width: i64,
    height: i64,
    fps: i64,
    bitrate: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + rid.len());
    append_mp_int(&mut out, 7);
    append_mp_int(&mut out, 0);
    append_mp_int(&mut out, sequence);
    append_mp_int(&mut out, 1); // the media source: the camera
    append_mp_int(&mut out, 1); // one layer
                                // Go's byte(len(rid)): the low byte, whatever the length.
    out.push(0xA0 | rid.len().to_le_bytes()[0]);
    out.extend_from_slice(rid.as_bytes());
    append_mp_int(&mut out, width);
    append_mp_int(&mut out, height);
    append_mp_int(&mut out, fps);
    // The web client writes bitrate/1e3: kbit/s, not bit/s.
    append_mp_int(&mut out, bitrate / 1000);
    out
}

/// The `report-perf-stat` frame (`encodePerfStatReport`):
/// `[1, 0, sequence, framesDecoded, framesReceived]`.
#[must_use]
pub fn encode_perf_stat_report(
    sequence: i64,
    frames_decoded: u32,
    frames_received: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    append_mp_int(&mut out, 1);
    append_mp_int(&mut out, 0);
    append_mp_int(&mut out, sequence);
    append_mp_int(&mut out, i64::from(frames_decoded));
    append_mp_int(&mut out, i64::from(frames_received));
    out
}

/// The stream description of a participant's camera (`cameraKey`).
#[must_use]
pub fn camera_key(participant: &str) -> String {
    format!("u{participant}:sCAMERA")
}

/// The whole subscription (`layoutEntries`): every registry stream by its
/// compact id, then, sorted, the camera of every participant the registry
/// does not name yet by its string key. The SFU answers a string key with a
/// registry entry for it; without asking, a participant who joins later is
/// never named and never forwarded.
pub fn layout_entries<'a>(
    registry: &Registry,
    participants: impl IntoIterator<Item = &'a str>,
) -> Vec<LayoutEntry> {
    // An empty registry adds nothing.
    let mut entries = registry.layout_for().unwrap_or_default();
    let mut asked: Vec<String> = participants
        .into_iter()
        .map(camera_key)
        .filter(|key| registry.get(key).is_none())
        .collect();
    asked.sort_unstable();
    entries.extend(asked.into_iter().map(|key| LayoutEntry {
        key: key.into_bytes(),
        compact: 0,
        by_compact: false,
        priority: TILE_PRIORITY,
        width: TILE_WIDTH,
        height: TILE_HEIGHT,
    }));
    entries
}

/// A counter value as the integer the encoder takes.
fn as_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// What one connection attempt keeps for the control route: the registry,
/// the other participants, and the sequence counter all three commands
/// share. Go guards the three with one mutex; here the owner holds `&mut`.
#[derive(Debug, Default)]
pub struct ControlState {
    registry: Registry,
    participants: BTreeSet<Box<str>>,
    seq: u64,
}

impl ControlState {
    /// A fresh attempt's state: nothing known, the counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry so far.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The participants noted so far, sorted.
    pub fn participants(&self) -> impl Iterator<Item = &str> {
        self.participants.iter().map(|id| &**id)
    }

    /// Records another participant and says whether it is new
    /// (`noteParticipant`). Past [`PARTICIPANTS_MAX`] it is not recorded.
    pub fn note_participant(&mut self, id: &str) -> bool {
        if self.participants.contains(id) || self.participants.len() >= PARTICIPANTS_MAX {
            return false;
        }
        self.participants.insert(id.into())
    }

    /// Drops a hung-up participant and its streams (`removeStream`): the
    /// keys `u<id>`, `u<id>:…` and `<id>:…`.
    pub fn remove_stream(&mut self, participant: &str) {
        self.participants.remove(participant);
        self.registry.0.remove(format!("u{participant}").as_bytes());
        let prefixes = [format!("u{participant}:"), format!("{participant}:")];
        self.registry.0.retain(|key, _| {
            !prefixes
                .iter()
                .any(|prefix| key.len() > prefix.len() && key.starts_with(prefix.as_bytes()))
        });
    }

    /// Folds registry entries in and says how many were not kept because the
    /// registry is at [`REGISTRY_MAX`].
    pub fn merge(&mut self, entries: &Registry) -> usize {
        let mut dropped = 0;
        for (key, id) in entries.iter() {
            if let Some(known) = self.registry.0.get_mut(key) {
                *known = id;
            } else if self.registry.0.len() < REGISTRY_MAX {
                self.registry.0.insert(key.into(), id);
            } else {
                dropped += 1;
            }
        }
        dropped
    }

    /// Reads a `producerNotification` frame (`onServiceFrame`) and folds a
    /// registry in. `Ok(n)` is the number of entries the frame held: when it
    /// is not zero the caller sends [`ControlState::layout`] again.
    ///
    /// # Errors
    ///
    /// As [`Registry::parse`]; the caller skips
    /// [`RegistryError::NotRegistry`] silently.
    pub fn on_service_frame(&mut self, frame: &[u8]) -> Result<usize, RegistryError> {
        let entries = Registry::parse(frame)?;
        if !entries.is_empty() {
            self.merge(&entries);
        }
        Ok(entries.len())
    }

    /// The next sequence number (`nextSeq`): the counter, advanced, modulo
    /// [`COMMAND_SEQ_MOD`].
    pub fn next_seq(&mut self) -> i64 {
        self.seq += 1;
        as_int(self.seq % COMMAND_SEQ_MOD)
    }

    /// The `change-simulcast` command sent once when `producerCommand`
    /// opens: the declared layer, under the raw counter (not the modulo), as
    /// Go sends it.
    pub fn change_simulcast(&mut self) -> Vec<u8> {
        self.seq += 1;
        encode_change_simulcast(
            as_int(self.seq),
            LAYER_RID,
            LAYER_WIDTH,
            LAYER_HEIGHT,
            LAYER_FPS,
            LAYER_KBPS * 1000,
        )
    }

    /// The `update-display-layout` command for everything known
    /// (`subscribeAll`). The counter advances even when there is nothing to
    /// ask for (`Ok(None)`), so gaps in the sequence are normal.
    ///
    /// # Errors
    ///
    /// As [`encode_layout`].
    pub fn layout(&mut self) -> Result<Option<Vec<u8>>, LayoutError> {
        let entries = layout_entries(&self.registry, self.participants());
        let sequence = self.next_seq();
        if entries.is_empty() {
            return Ok(None);
        }
        encode_layout(sequence, &entries).map(Some)
    }

    /// The `report-perf-stat` command: both values are the video RTP packets
    /// received so far.
    pub fn perf_stat(&mut self, received: u32) -> Vec<u8> {
        encode_perf_stat_report(self.next_seq(), received, received)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A MessagePack fixstr (`mpStr`).
    fn mp_str(key: &str) -> Vec<u8> {
        let mut out = vec![0xA0 | (key.len() as u8 & 0x1F)];
        out.extend_from_slice(key.as_bytes());
        out
    }

    /// One registry entry with a fixint id (`mpEntry`).
    fn mp_entry(key: &str, id: u8) -> Vec<u8> {
        let mut out = mp_str(key);
        out.push(id);
        out
    }

    fn mp_int(value: i64) -> String {
        let mut out = Vec::new();
        append_mp_int(&mut out, value);
        hex(&out)
    }

    // The integer rule (`appendMPInt`): 128..=32767 is int16, which no
    // general MessagePack encoder picks.
    #[test]
    fn integers_take_the_int16_marker_from_128() {
        assert_eq!(mp_int(0), "00");
        assert_eq!(mp_int(127), "7f");
        assert_eq!(mp_int(128), "d10080");
        assert_eq!(mp_int(255), "d100ff");
        assert_eq!(mp_int(256), "d10100");
        assert_eq!(mp_int(32_767), "d17fff");
        assert_eq!(mp_int(32_768), "d200008000");
        assert_eq!(mp_int(65_535), "d20000ffff");
        assert_eq!(mp_int(-1), "d1ffff");
        assert_eq!(mp_int(-32_768), "d18000");
        assert_eq!(mp_int(-32_769), "d2ffff7fff");
        assert_eq!(mp_int(i64::from(u32::MAX)), "d2ffffffff");
        // Past 32 bits the low 32 are written, as Go's uint32(value).
        assert_eq!(mp_int(1 << 32), "d200000000");
        assert_eq!(mp_int((1 << 32) + 5), "d200000005");
    }

    // TestParseRegistry, its seven cases. The first vector is a frame
    // captured from the live SFU (base64 AYG1dTU4ODAwMzkzMDU4OTpzQ0FNRVJBAQ==).
    #[test]
    fn parse_registry_camera_stream_compact_1() {
        let mut frame = vec![0x01, 0x81, 0xB5];
        frame.extend_from_slice(b"u588003930589:sCAMERA");
        frame.push(0x01);
        assert_eq!(
            Registry::parse(&frame),
            Ok(Registry::from([("u588003930589:sCAMERA", 1)]))
        );
    }

    #[test]
    fn parse_registry_three_cameras_in_one_frame() {
        let mut frame = vec![0x01, 0x83];
        frame.extend(mp_entry("u100000000001:sCAMERA", 0x00));
        frame.extend(mp_entry("u100000000002:sCAMERA", 0x01));
        frame.extend(mp_entry("u100000000003", 0x02));
        assert_eq!(
            Registry::parse(&frame),
            Ok(Registry::from([
                ("u100000000001:sCAMERA", 0),
                ("u100000000002:sCAMERA", 1),
                ("u100000000003", 2),
            ]))
        );
    }

    #[test]
    fn parse_registry_map16_with_a_uint8_compact_id() {
        let mut frame = vec![0x01, 0xDE, 0x00, 0x02];
        frame.extend(mp_entry("u1:sCAMERA", 0x05));
        frame.extend(mp_str("u2:sCAMERA"));
        frame.extend([0xCC, 0x80]);
        assert_eq!(
            Registry::parse(&frame),
            Ok(Registry::from([("u1:sCAMERA", 5), ("u2:sCAMERA", 128)]))
        );
    }

    #[test]
    fn parse_registry_refuses_what_go_refuses() {
        // second entry truncated
        let mut frame = vec![0x01, 0x82];
        frame.extend(mp_entry("u1:sCAMERA", 0x00));
        assert_eq!(Registry::parse(&frame), Err(RegistryError::Short));
        // empty frame
        assert_eq!(Registry::parse(&[]), Err(RegistryError::Short));
        // truncated (base64 AQE=)
        assert_eq!(Registry::parse(&[0x01, 0x01]), Err(RegistryError::Short));
        // not a map (base64 AZAA): three bytes are short of the header
        assert_eq!(
            Registry::parse(&[0x01, 0x90, 0x00]),
            Err(RegistryError::Short)
        );
        // not a map, long enough to be read
        assert_eq!(
            Registry::parse(&[0x01, 0x90, 0x00, 0x00]),
            Err(RegistryError::Shape)
        );
        // a key that is not a fixstr
        assert_eq!(
            Registry::parse(&[0x01, 0x81, 0x05, 0x00]),
            Err(RegistryError::Shape)
        );
        // a key running past the frame
        assert_eq!(
            Registry::parse(&[0x01, 0x81, 0xA5, b'u']),
            Err(RegistryError::Short)
        );
        // an id that is neither a fixint nor a uint8
        assert_eq!(
            Registry::parse(&[0x01, 0x81, 0xA1, b'u', 0xCD]),
            Err(RegistryError::Shape)
        );
        // a uint8 id without its byte
        assert_eq!(
            Registry::parse(&[0x01, 0x81, 0xA1, b'u', 0xCC]),
            Err(RegistryError::Short)
        );
        // an empty map is a registry with nothing in it
        assert_eq!(
            Registry::parse(&[0x01, 0x80, 0x00, 0x00]),
            Ok(Registry::default())
        );
    }

    // TestParseRegistryOtherKind: the notification channel carries several
    // kinds.
    #[test]
    fn parse_registry_marks_other_kinds() {
        assert_eq!(
            Registry::parse(&[0x02, 0x91, 0x00]),
            Err(RegistryError::NotRegistry)
        );
    }

    // TestEncodeLayoutGolden: the compact-addressed form the live SFU
    // accepted: sequence 1, one stream at compact id 0, priority 1, 640x360.
    #[test]
    fn encode_layout_golden() {
        let frame = encode_layout(
            1,
            &[LayoutEntry {
                key: b"u604532170515:sCAMERA".to_vec(),
                compact: 0,
                by_compact: true,
                priority: 1,
                width: 640,
                height: 360,
            }],
        )
        .unwrap();
        assert_eq!(hex(&frame), "000001c091c40a000001d10280d1016800c0");
    }

    // TestEncodeLayoutStringKey: priority 0 is a set value, fixint 0; no
    // size is two nils.
    #[test]
    fn encode_layout_string_key() {
        let frame = encode_layout(
            2,
            &[LayoutEntry {
                key: b"42:sCAMERA".to_vec(),
                ..LayoutEntry::default()
            }],
        )
        .unwrap();
        assert_eq!(
            hex(&frame),
            "000002c091c410aa34323a7343414d4552410000c0c000c0"
        );
    }

    // TestEncodeLayoutEmpty.
    #[test]
    fn encode_layout_refuses_no_entries() {
        assert_eq!(encode_layout(1, &[]), Err(LayoutError::NoStream));
        // An entry that names nothing.
        assert_eq!(
            encode_layout(1, &[LayoutEntry::default()]),
            Err(LayoutError::NoStream)
        );
    }

    #[test]
    fn encode_layout_bounds_the_key_and_the_count() {
        let long = LayoutEntry {
            key: vec![b'k'; 32],
            ..LayoutEntry::default()
        };
        assert_eq!(encode_layout(1, &[long]), Err(LayoutError::KeyLong(32)));
        let longest = LayoutEntry {
            key: vec![b'k'; 31],
            ..LayoutEntry::default()
        };
        let frame = encode_layout(1, &[longest]).unwrap();
        assert_eq!(frame[5..8], [0xC4, 37, 0xBF]);
        let entry = LayoutEntry {
            by_compact: true,
            ..LayoutEntry::default()
        };
        assert_eq!(
            encode_layout(1, &vec![entry; 65_536]),
            Err(LayoutError::TooMany(65_536))
        );
    }

    // TestEncodeLayoutManyEntries: sixteen streams and more take array16.
    #[test]
    fn encode_layout_many_entries() {
        let entries: Vec<LayoutEntry> = (0..17u8)
            .map(|i| LayoutEntry {
                compact: i,
                by_compact: true,
                priority: 1,
                width: 640,
                height: 360,
                ..LayoutEntry::default()
            })
            .collect();
        let frame = encode_layout(3, &entries).unwrap();
        assert_eq!(frame[..7], [0x00, 0x00, 0x03, 0xC0, 0xDC, 0x00, 17]);
        // header, 17 entries of bin8 + 10 bytes, the closing nil
        assert_eq!(frame.len(), 7 + 17 * 12 + 1);
        assert_eq!(frame[frame.len() - 1], 0xC0);
        // Fifteen still fit the fixarray.
        let frame = encode_layout(3, &entries[..15]).unwrap();
        assert_eq!(frame[..5], [0x00, 0x00, 0x03, 0xC0, 0x9F]);
    }

    // TestRegistryLayoutFor: every registry stream, compact-addressed, in
    // key order.
    #[test]
    fn registry_layout_for() {
        let registry = Registry::from([("b:sCAMERA", 1), ("a:sCAMERA", 0)]);
        let entries = registry.layout_for().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, b"a:sCAMERA");
        assert!(entries[0].by_compact);
        assert_eq!(entries[0].compact, 0);
        assert_eq!(entries[1].key, b"b:sCAMERA");
        assert_eq!(entries[1].compact, 1);
        assert_eq!(
            (entries[0].priority, entries[0].width, entries[0].height),
            (1, 640, 360)
        );
        assert_eq!(Registry::default().layout_for(), Err(LayoutError::NoStream));
    }

    fn describe(entries: &[LayoutEntry]) -> String {
        let mut out = Vec::new();
        for e in entries {
            let key = String::from_utf8_lossy(&e.key);
            if e.by_compact {
                out.push(format!("{key}#{}", e.compact));
            } else {
                out.push(format!("{key}#str"));
            }
            assert_eq!(
                (e.priority, e.width, e.height),
                (1, 640, 360),
                "layout fields {e:?}"
            );
        }
        out.join(",")
    }

    // TestLayoutEntriesAskUnknownCamerasByKey: a stream the registry names
    // goes by its compact id; a participant's camera it does not name yet
    // goes by its string key.
    #[test]
    fn layout_entries_ask_unknown_cameras_by_key() {
        let registry = Registry::from([("u1:sCAMERA", 0), ("u3", 2)]);
        let entries = layout_entries(&registry, ["3", "1", "2"]);
        assert_eq!(
            describe(&entries),
            "u1:sCAMERA#0,u3#2,u2:sCAMERA#str,u3:sCAMERA#str"
        );
        assert!(layout_entries(&Registry::default(), []).is_empty());
    }

    fn keys(state: &ControlState) -> String {
        layout_entries(state.registry(), state.participants())
            .iter()
            .map(|e| String::from_utf8_lossy(&e.key).into_owned())
            .collect::<Vec<_>>()
            .join(",")
    }

    // TestGenerationTracksParticipants: a participant noted is asked for by
    // its camera key until the registry names it; one who hangs up leaves
    // both the asked set and the registry. (Go's test then builds layouts
    // from four goroutines under -race; here the state is behind `&mut`.)
    #[test]
    fn the_state_tracks_participants() {
        let mut state = ControlState::new();
        assert_eq!(
            state.merge(&Registry::from([
                ("u7:sCAMERA", 3),
                ("u7", 4),
                ("u8:sCAMERA", 5)
            ])),
            0
        );
        assert!(state.note_participant("9"));
        assert!(
            !state.note_participant("9"),
            "noteParticipant reports a new id once"
        );
        state.note_participant("7");
        assert_eq!(keys(&state), "u7,u7:sCAMERA,u8:sCAMERA,u9:sCAMERA");
        state.remove_stream("7");
        state.remove_stream("9");
        assert_eq!(keys(&state), "u8:sCAMERA");
    }

    // removeStream's prefixes: `u<id>:` and `<id>:` with something after
    // them, and the bare `u<id>`; nothing of a participant whose id only
    // starts the same.
    #[test]
    fn remove_stream_takes_only_that_participants_keys() {
        let mut state = ControlState::new();
        state.merge(&Registry::from([
            ("u7", 0),
            ("u7:sCAMERA", 1),
            ("7:sSCREEN", 2),
            ("u7:", 3),
            ("7", 4),
            ("u77:sCAMERA", 5),
            ("u77", 6),
            ("77:sCAMERA", 7),
        ]));
        state.remove_stream("7");
        let left: Vec<String> = state
            .registry()
            .iter()
            .map(|(key, id)| format!("{}={id}", String::from_utf8_lossy(key)))
            .collect();
        // Go's test is `len(key) > len(prefix)`: the bare "u7:" stays, and
        // so does "7".
        assert_eq!(left.join(","), "7=4,77:sCAMERA=7,u77=6,u77:sCAMERA=5,u7:=3");
    }

    // The change-simulcast bytes of stamp.go for sequence 1 and the declared
    // layer (the plan's spot check 13).
    #[test]
    fn change_simulcast_golden() {
        let frame = encode_change_simulcast(1, "l", 320, 180, 15, 180_000);
        assert_eq!(hex(&frame), "0700010101a16cd10140d100b40fd100b4");
        // The bitrate travels in kbit/s, rounded down.
        let frame = encode_change_simulcast(300, "m", 640, 360, 20, 500_999);
        assert_eq!(hex(&frame), "0700d1012c0101a16dd10280d1016814d101f4");
    }

    #[test]
    fn perf_stat_report_golden() {
        assert_eq!(
            hex(&encode_perf_stat_report(5, 1_000, 1_000)),
            "010005d103e8d103e8"
        );
        assert_eq!(
            hex(&encode_perf_stat_report(6, 0, 70_000)),
            "01000600d200011170"
        );
        // A counter past 2^31 keeps its 32 bits.
        assert_eq!(
            hex(&encode_perf_stat_report(7, u32::MAX, 0x8000_0001)),
            "010007d2ffffffffd280000001"
        );
    }

    // One counter for the three commands; the first change-simulcast sends
    // the raw counter; a layout with nothing to ask for still takes a
    // number.
    #[test]
    fn the_three_commands_share_one_counter() {
        let mut state = ControlState::new();
        // A registry frame that arrived before the channel opened: nothing
        // to send, the counter moves.
        assert_eq!(state.layout(), Ok(None));
        assert_eq!(
            hex(&state.change_simulcast()),
            "0700020101a16cd10140d100b40fd100b4"
        );
        assert_eq!(state.layout(), Ok(None));
        assert!(state.note_participant("42"));
        let layout = state.layout().unwrap().unwrap();
        // sequence 4, one camera asked by key at priority 1, 640x360
        assert_eq!(
            hex(&layout),
            "000004c091c415ab7534323a7343414d4552410001d10280d1016800c0"
        );
        assert_eq!(hex(&state.perf_stat(9)), "0100050909");
        assert_eq!(state.next_seq(), 6);
    }

    #[test]
    fn the_sequence_wraps_at_two_to_the_twenty_except_in_change_simulcast() {
        let mut state = ControlState {
            seq: COMMAND_SEQ_MOD - 2,
            ..ControlState::default()
        };
        assert_eq!(state.next_seq(), 1_048_575);
        assert_eq!(state.next_seq(), 0);
        // perf-stat under the wrapped number
        assert_eq!(hex(&state.perf_stat(1)), "0100010101");
        // change-simulcast under the raw counter, 2^20 + 2
        assert_eq!(&hex(&state.change_simulcast())[..14], "0700d200100002");
    }

    // onServiceFrame: a registry frame is folded in and asks for a new
    // layout; other kinds and broken frames change nothing.
    #[test]
    fn a_service_frame_folds_the_registry_in() {
        let mut state = ControlState::new();
        state.note_participant("1");
        let mut frame = vec![0x01, 0x82];
        frame.extend(mp_entry("u1:sCAMERA", 0x04));
        frame.extend(mp_entry("u1", 0x05));
        assert_eq!(state.on_service_frame(&frame), Ok(2));
        assert_eq!(state.registry().get("u1:sCAMERA"), Some(4));
        assert_eq!(keys(&state), "u1,u1:sCAMERA");
        // The same key again moves its id.
        let mut again = vec![0x01, 0x81];
        again.extend(mp_entry("u1:sCAMERA", 0x09));
        again.push(0x00);
        assert_eq!(state.on_service_frame(&again), Ok(1));
        assert_eq!(state.registry().get("u1:sCAMERA"), Some(9));
        assert_eq!(
            state.on_service_frame(&[0x06, 0x00]),
            Err(RegistryError::NotRegistry)
        );
        assert_eq!(
            state.on_service_frame(&[0x01, 0x81]),
            Err(RegistryError::Short)
        );
        assert_eq!(state.on_service_frame(&[0x01, 0x80, 0x00, 0x00]), Ok(0));
        assert_eq!(state.registry().len(), 2);
    }

    // Memory: the registry and the participants are bounded; a known key is
    // still updated at the bound.
    #[test]
    fn the_registry_and_the_participants_are_bounded() {
        let mut state = ControlState::new();
        for i in 0..REGISTRY_MAX + 10 {
            let mut one = Registry::default();
            one.insert(format!("u{i}:sCAMERA"), (i % 256) as u8);
            let dropped = state.merge(&one);
            assert_eq!(dropped, usize::from(i >= REGISTRY_MAX), "entry {i}");
        }
        assert_eq!(state.registry().len(), REGISTRY_MAX);
        assert_eq!(state.merge(&Registry::from([("u0:sCAMERA", 77)])), 0);
        assert_eq!(state.registry().get("u0:sCAMERA"), Some(77));
        // A hang-up makes room.
        state.remove_stream("0");
        assert_eq!(state.merge(&Registry::from([("u999:sCAMERA", 1)])), 0);

        for i in 0..PARTICIPANTS_MAX {
            assert!(state.note_participant(&i.to_string()));
        }
        assert!(!state.note_participant("more"));
        assert_eq!(state.participants().count(), PARTICIPANTS_MAX);
        state.remove_stream("5");
        assert!(state.note_participant("more"));
    }

    #[test]
    fn the_state_is_small() {
        assert!(
            std::mem::size_of::<ControlState>() <= 64,
            "ControlState is {} bytes",
            std::mem::size_of::<ControlState>()
        );
        assert!(
            std::mem::size_of::<LayoutEntry>() <= 56,
            "LayoutEntry is {} bytes",
            std::mem::size_of::<LayoutEntry>()
        );
    }
}

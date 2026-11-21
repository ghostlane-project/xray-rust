// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a `session-initiate` and a `transport-info` say
//! (`J/internal/jingle/types.go`, `jingle.go`, `E/trickle.go`).

use std::borrow::Cow;

use crate::xml::{Event, Reader, Start, XmlError};

/// The most contents read from a stanza; a room has three. Go has no bound.
pub const MAX_CONTENTS: usize = 8;
/// The most payload types read from one description.
pub const MAX_PAYLOADS: usize = 64;
/// The most candidates read from one transport.
pub const MAX_CANDIDATES: usize = 128;
/// The most sources read from one description.
pub const MAX_SOURCES: usize = 128;
/// The most parameters, feedback entries, extensions, groups, group members
/// and sockets read from one parent.
pub const MAX_SMALL: usize = 32;

/// A Jingle stanza (`XMLJingle`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Jingle {
    /// `action`.
    pub action: String,
    /// `initiator`.
    pub initiator: String,
    /// `responder`.
    pub responder: String,
    /// `sid`.
    pub sid: String,
    /// The `content` children.
    pub contents: Vec<Content>,
    /// The `group` child.
    pub group: Option<Group>,
}

/// A `group` of contents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Group {
    /// `BUNDLE`.
    pub semantics: String,
    /// The names of its contents.
    pub contents: Vec<String>,
}

/// One `content`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Content {
    /// `creator`.
    pub creator: String,
    /// `name`: the mid.
    pub name: String,
    /// `senders`.
    pub senders: String,
    /// What it carries.
    pub description: Option<Description>,
    /// How it is reached.
    pub transport: Option<Transport>,
}

/// A `description`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Description {
    /// `media`.
    pub media: String,
    /// The payload types.
    pub payloads: Vec<PayloadType>,
    /// The sources.
    pub sources: Vec<Source>,
    /// The SSRC groups.
    pub ssrc_groups: Vec<SsrcGroup>,
    /// `rtcp-mux` is there.
    pub rtcp_mux: bool,
    /// The header extensions.
    pub hdrexts: Vec<HdrExt>,
    /// The SCTP map, in a description.
    pub sctpmap: Option<SctpMap>,
}

/// A `payload-type`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PayloadType {
    /// `id`.
    pub id: String,
    /// `name`.
    pub name: String,
    /// `clockrate`.
    pub clockrate: String,
    /// `channels`.
    pub channels: String,
    /// `parameter`s: name, value.
    pub parameters: Vec<(String, String)>,
    /// `rtcp-fb`s: type, subtype.
    pub rtcp_fb: Vec<(String, String)>,
}

/// A `source`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Source {
    /// `ssrc`.
    pub ssrc: String,
    /// `parameter`s: name, value.
    pub parameters: Vec<(String, String)>,
}

/// An `ssrc-group`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsrcGroup {
    /// `semantics`.
    pub semantics: String,
    /// Its members' SSRCs.
    pub ssrcs: Vec<String>,
}

/// An `rtp-hdrext`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HdrExt {
    /// `id`.
    pub id: String,
    /// `uri`.
    pub uri: String,
}

/// An `sctpmap`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SctpMap {
    /// `number`.
    pub number: String,
    /// `port`.
    pub port: String,
    /// `protocol`.
    pub protocol: String,
    /// `streams`.
    pub streams: String,
}

/// A `transport`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transport {
    /// `ufrag`.
    pub ufrag: String,
    /// `pwd`.
    pub pwd: String,
    /// The candidates.
    pub candidates: Vec<Candidate>,
    /// The DTLS fingerprint.
    pub fingerprint: Option<Fingerprint>,
    /// The SCTP map, in a transport.
    pub sctpmap: Option<SctpMap>,
    /// The `web-socket` URLs.
    pub websockets: Vec<String>,
}

/// A `fingerprint`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// `hash`.
    pub hash: String,
    /// `setup`.
    pub setup: String,
    /// The text inside.
    pub value: String,
}

/// A `candidate`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidate {
    /// `component`.
    pub component: String,
    /// `foundation`.
    pub foundation: String,
    /// `generation`.
    pub generation: String,
    /// `id`.
    pub id: String,
    /// `ip`.
    pub ip: String,
    /// `port`.
    pub port: String,
    /// `priority`.
    pub priority: String,
    /// `protocol`.
    pub protocol: String,
    /// `type`.
    pub kind: String,
    /// `rel-addr`.
    pub rel_addr: String,
    /// `rel-port`.
    pub rel_port: String,
    /// `tcptype`.
    pub tcp_type: String,
}

fn attr(s: &Start<'_>, name: &str) -> String {
    s.attr(name)
        .ok()
        .flatten()
        .map(Cow::into_owned)
        .unwrap_or_default()
}

/// Calls `f` for each child element of `s`; `f` reads the child to its end.
fn children<'a>(
    r: &mut Reader<'a>,
    s: &Start<'a>,
    mut f: impl FnMut(&mut Reader<'a>, Start<'a>) -> Result<(), XmlError>,
) -> Result<(), XmlError> {
    if s.self_closing {
        return Ok(());
    }
    loop {
        match r.next_event()? {
            Some(Event::Start(c)) => f(r, c)?,
            Some(Event::End(_)) => return Ok(()),
            Some(Event::Text(_)) => {}
            None => return Err(XmlError::Eof),
        }
    }
}

fn skip<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<(), XmlError> {
    children(r, s, |r, c| skip(r, &c))
}

/// The character data of an element itself, not its children's.
fn chardata<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<String, XmlError> {
    let mut out = String::new();
    if s.self_closing {
        return Ok(out);
    }
    loop {
        match r.next_event()? {
            Some(Event::Text(t)) => out.push_str(&t),
            Some(Event::Start(c)) => skip(r, &c)?,
            Some(Event::End(_)) => return Ok(out),
            None => return Err(XmlError::Eof),
        }
    }
}

fn push<T>(v: &mut Vec<T>, max: usize, item: T) {
    if v.len() < max {
        v.push(item);
    }
}

fn parameters<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<Vec<(String, String)>, XmlError> {
    let mut out = Vec::new();
    children(r, s, |r, c| {
        if c.name == "parameter" {
            push(&mut out, MAX_SMALL, (attr(&c, "name"), attr(&c, "value")));
        }
        skip(r, &c)
    })?;
    Ok(out)
}

fn sctpmap(s: &Start<'_>) -> SctpMap {
    SctpMap {
        number: attr(s, "number"),
        port: attr(s, "port"),
        protocol: attr(s, "protocol"),
        streams: attr(s, "streams"),
    }
}

fn candidate(s: &Start<'_>) -> Candidate {
    Candidate {
        component: attr(s, "component"),
        foundation: attr(s, "foundation"),
        generation: attr(s, "generation"),
        id: attr(s, "id"),
        ip: attr(s, "ip"),
        port: attr(s, "port"),
        priority: attr(s, "priority"),
        protocol: attr(s, "protocol"),
        kind: attr(s, "type"),
        rel_addr: attr(s, "rel-addr"),
        rel_port: attr(s, "rel-port"),
        tcp_type: attr(s, "tcptype"),
    }
}

fn payload<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<PayloadType, XmlError> {
    let mut p = PayloadType {
        id: attr(s, "id"),
        name: attr(s, "name"),
        clockrate: attr(s, "clockrate"),
        channels: attr(s, "channels"),
        ..PayloadType::default()
    };
    children(r, s, |r, c| {
        match c.name {
            "parameter" => push(
                &mut p.parameters,
                MAX_SMALL,
                (attr(&c, "name"), attr(&c, "value")),
            ),
            "rtcp-fb" => push(
                &mut p.rtcp_fb,
                MAX_SMALL,
                (attr(&c, "type"), attr(&c, "subtype")),
            ),
            _ => {}
        }
        skip(r, &c)
    })?;
    Ok(p)
}

fn description<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<Description, XmlError> {
    let mut d = Description {
        media: attr(s, "media"),
        ..Description::default()
    };
    children(r, s, |r, c| match c.name {
        "payload-type" => {
            let p = payload(r, &c)?;
            push(&mut d.payloads, MAX_PAYLOADS, p);
            Ok(())
        }
        "source" => {
            let ssrc = attr(&c, "ssrc");
            let parameters = parameters(r, &c)?;
            push(&mut d.sources, MAX_SOURCES, Source { ssrc, parameters });
            Ok(())
        }
        "ssrc-group" => {
            let mut g = SsrcGroup {
                semantics: attr(&c, "semantics"),
                ssrcs: Vec::new(),
            };
            children(r, &c, |r, m| {
                if m.name == "source" {
                    push(&mut g.ssrcs, MAX_SMALL, attr(&m, "ssrc"));
                }
                skip(r, &m)
            })?;
            push(&mut d.ssrc_groups, MAX_SMALL, g);
            Ok(())
        }
        "rtcp-mux" => {
            d.rtcp_mux = true;
            skip(r, &c)
        }
        "rtp-hdrext" => {
            push(
                &mut d.hdrexts,
                MAX_SMALL,
                HdrExt {
                    id: attr(&c, "id"),
                    uri: attr(&c, "uri"),
                },
            );
            skip(r, &c)
        }
        "sctpmap" => {
            d.sctpmap.get_or_insert_with(|| sctpmap(&c));
            skip(r, &c)
        }
        _ => skip(r, &c),
    })?;
    Ok(d)
}

fn transport<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<Transport, XmlError> {
    let mut t = Transport {
        ufrag: attr(s, "ufrag"),
        pwd: attr(s, "pwd"),
        ..Transport::default()
    };
    children(r, s, |r, c| match c.name {
        "candidate" => {
            push(&mut t.candidates, MAX_CANDIDATES, candidate(&c));
            skip(r, &c)
        }
        "fingerprint" => {
            let f = Fingerprint {
                hash: attr(&c, "hash"),
                setup: attr(&c, "setup"),
                value: chardata(r, &c)?,
            };
            t.fingerprint.get_or_insert(f);
            Ok(())
        }
        "sctpmap" => {
            t.sctpmap.get_or_insert_with(|| sctpmap(&c));
            skip(r, &c)
        }
        "web-socket" => {
            push(&mut t.websockets, MAX_SMALL, attr(&c, "url"));
            skip(r, &c)
        }
        _ => skip(r, &c),
    })?;
    Ok(t)
}

fn content<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<Content, XmlError> {
    let mut c = Content {
        creator: attr(s, "creator"),
        name: attr(s, "name"),
        senders: attr(s, "senders"),
        ..Content::default()
    };
    children(r, s, |r, ch| match ch.name {
        "description" if c.description.is_none() => {
            c.description = Some(description(r, &ch)?);
            Ok(())
        }
        "transport" if c.transport.is_none() => {
            c.transport = Some(transport(r, &ch)?);
            Ok(())
        }
        _ => skip(r, &ch),
    })?;
    Ok(c)
}

fn jingle<'a>(r: &mut Reader<'a>, s: &Start<'a>) -> Result<Jingle, XmlError> {
    let mut j = Jingle {
        action: attr(s, "action"),
        initiator: attr(s, "initiator"),
        responder: attr(s, "responder"),
        sid: attr(s, "sid"),
        ..Jingle::default()
    };
    children(r, s, |r, c| match c.name {
        "content" => {
            let ct = content(r, &c)?;
            push(&mut j.contents, MAX_CONTENTS, ct);
            Ok(())
        }
        "group" if j.group.is_none() => {
            let mut g = Group {
                semantics: attr(&c, "semantics"),
                contents: Vec::new(),
            };
            children(r, &c, |r, m| {
                if m.name == "content" {
                    push(&mut g.contents, MAX_CONTENTS, attr(&m, "name"));
                }
                skip(r, &m)
            })?;
            j.group = Some(g);
            Ok(())
        }
        _ => skip(r, &c),
    })?;
    Ok(j)
}

/// The Jingle element of an IQ (`ParseStanza`): the root must be `iq`; an IQ
/// with no `jingle` child gives an empty one.
///
/// # Errors
/// The text is not an IQ, or is not well-formed.
pub fn parse_stanza(xml: &str) -> Result<Jingle, XmlError> {
    let mut r = Reader::new(xml);
    let root = match r.next_event()? {
        Some(Event::Start(s)) if s.name == "iq" => s,
        _ => return Err(XmlError::Syntax("not an iq")),
    };
    let mut out: Option<Jingle> = None;
    children(&mut r, &root, |r, c| {
        if c.name == "jingle" && out.is_none() {
            out = Some(jingle(r, &c)?);
            Ok(())
        } else {
            skip(r, &c)
        }
    })?;
    Ok(out.unwrap_or_default())
}

/// A source's ids as the engine reads them (`Source`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceName {
    /// `ssrc`.
    pub ssrc: String,
    /// The `msid` parameter.
    pub name: String,
    /// The `label` parameter.
    pub label: String,
}

/// The data channel's description (`DataChannel`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataChannel {
    /// The SCTP port.
    pub port: String,
    /// Its protocol.
    pub protocol: String,
}

/// What the library keeps of a `session-initiate` (`jingle.Parsed`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// `sid`.
    pub sid: String,
    /// `initiator`.
    pub initiator: String,
    /// The offer as SDP.
    pub sdp: String,
    /// The stanza read.
    pub jingle: Option<Jingle>,
    /// Every candidate.
    pub candidates: Vec<Candidate>,
    /// The audio sources.
    pub audio_sources: Vec<SourceName>,
    /// The video sources.
    pub video_sources: Vec<SourceName>,
    /// The data channel.
    pub data_channel: Option<DataChannel>,
    /// The bridge's WebSocket URL.
    pub colibri_ws: String,
}

impl Parsed {
    /// Reads `raw` (`Parse`); what cannot be read is empty.
    #[must_use]
    pub fn of(raw: &str) -> Self {
        let mut p = Self::default();
        let Ok(j) = parse_stanza(raw) else {
            return p;
        };
        p.sid.clone_from(&j.sid);
        p.initiator.clone_from(&j.initiator);
        p.sdp = crate::jingle::sdp::to_sdp(&j);
        for c in &j.contents {
            if let Some(t) = &c.transport {
                if p.colibri_ws.is_empty() {
                    if let Some(ws) = t.websockets.iter().find(|u| !u.is_empty()) {
                        p.colibri_ws.clone_from(ws);
                    }
                }
                p.candidates.extend(t.candidates.iter().cloned());
            }
            if let Some(d) = &c.description {
                for s in &d.sources {
                    let find = |k: &str| {
                        s.parameters
                            .iter()
                            .find(|(n, _)| n == k)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default()
                    };
                    let name = SourceName {
                        ssrc: s.ssrc.clone(),
                        name: find("msid"),
                        label: find("label"),
                    };
                    match d.media.as_str() {
                        "audio" => p.audio_sources.push(name),
                        "video" => p.video_sources.push(name),
                        _ => {}
                    }
                }
            }
            let d_map = c.description.as_ref().and_then(|d| d.sctpmap.as_ref());
            let t_map = c.transport.as_ref().and_then(|t| t.sctpmap.as_ref());
            if c.name == "data" || d_map.is_some() || t_map.is_some() {
                let first = |m: &SctpMap| {
                    if m.number.is_empty() {
                        m.port.clone()
                    } else {
                        m.number.clone()
                    }
                };
                let mut dc = DataChannel {
                    port: String::new(),
                    protocol: String::new(),
                };
                if let Some(m) = d_map {
                    dc.port = first(m);
                    dc.protocol.clone_from(&m.protocol);
                }
                if let Some(m) = t_map {
                    if dc.port.is_empty() {
                        dc.port = first(m);
                    }
                    if dc.protocol.is_empty() {
                        dc.protocol.clone_from(&m.protocol);
                    }
                }
                p.data_channel = Some(dc);
            }
        }
        p.jingle = Some(j);
        p
    }
}

/// One content of a `transport-info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportInfoContent {
    /// The content's name: the mid.
    pub name: String,
    /// The candidates it carries.
    pub candidates: Vec<Candidate>,
}

/// A `transport-info` as `applyTrickleICE` reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportInfo {
    /// `action`.
    pub action: String,
    /// Its contents.
    pub contents: Vec<TransportInfoContent>,
}

/// Reads a `transport-info` IQ.
///
/// # Errors
/// The text is not an IQ, or is not well-formed.
pub fn parse_transport_info(xml: &str) -> Result<TransportInfo, XmlError> {
    let mut r = Reader::new(xml);
    let root = match r.next_event()? {
        Some(Event::Start(s)) if s.name == "iq" => s,
        _ => return Err(XmlError::Syntax("not an iq")),
    };
    let mut ti = TransportInfo::default();
    let mut seen = false;
    children(&mut r, &root, |r, c| {
        if c.name != "jingle" || seen {
            return skip(r, &c);
        }
        seen = true;
        ti.action = attr(&c, "action");
        children(r, &c, |r, ct| {
            if ct.name != "content" {
                return skip(r, &ct);
            }
            let mut tc = TransportInfoContent {
                name: attr(&ct, "name"),
                candidates: Vec::new(),
            };
            let mut got_transport = false;
            children(r, &ct, |r, t| {
                if t.name != "transport" || got_transport {
                    return skip(r, &t);
                }
                got_transport = true;
                children(r, &t, |r, cand| {
                    if cand.name == "candidate" {
                        push(&mut tc.candidates, MAX_CANDIDATES, candidate(&cand));
                    }
                    skip(r, &cand)
                })
            })?;
            push(&mut ti.contents, MAX_CONTENTS, tc);
            Ok(())
        })
    })?;
    Ok(ti)
}

/// The SDP candidate line for a trickled candidate, or `None` without an
/// address or a port (`buildSDPCandidate`): component 1, udp, priority 1 and
/// host where the stanza says none.
#[must_use]
pub fn candidate_line(c: &Candidate) -> Option<String> {
    if c.ip.is_empty() || c.port.is_empty() {
        return None;
    }
    let component = if c.component.is_empty() {
        "1"
    } else {
        &c.component
    };
    let protocol = if c.protocol.is_empty() {
        "udp".to_owned()
    } else {
        c.protocol.to_lowercase()
    };
    let priority = if c.priority.is_empty() {
        "1"
    } else {
        &c.priority
    };
    let kind = if c.kind.is_empty() { "host" } else { &c.kind };
    let mut s = format!(
        "candidate:{} {component} {protocol} {priority} {} {} typ {kind}",
        c.foundation, c.ip, c.port
    );
    if !c.rel_addr.is_empty() && !c.rel_port.is_empty() {
        s.push_str(&format!(" raddr {} rport {}", c.rel_addr, c.rel_port));
    }
    if !c.generation.is_empty() {
        s.push_str(" generation ");
        s.push_str(&c.generation);
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jingle::fixtures::INITIATE;

    #[test]
    fn the_initiate_is_read() {
        let j = parse_stanza(INITIATE).unwrap();
        assert_eq!(
            (
                j.action.as_str(),
                j.sid.as_str(),
                j.initiator.as_str(),
                j.responder.as_str()
            ),
            (
                "session-initiate",
                "sid123",
                "room@muc.meet.jitsi/focus",
                ""
            )
        );
        let g = j.group.as_ref().unwrap();
        assert_eq!(g.semantics, "BUNDLE");
        assert_eq!(g.contents, ["audio", "video", "data"]);
        assert_eq!(j.contents.len(), 3);
        let a = &j.contents[0];
        assert_eq!(
            (a.name.as_str(), a.senders.as_str(), a.creator.as_str()),
            ("audio", "both", "initiator")
        );
        let d = a.description.as_ref().unwrap();
        assert_eq!(d.media, "audio");
        assert!(d.rtcp_mux);
        assert_eq!(d.payloads.len(), 2);
        assert_eq!(d.payloads[0].id, "111");
        assert_eq!(d.payloads[0].channels, "2");
        assert_eq!(
            d.payloads[0].parameters,
            [
                ("minptime".into(), "10".into()),
                ("useinbandfec".into(), "1".into())
            ]
        );
        assert_eq!(
            d.payloads[0].rtcp_fb,
            [("transport-cc".into(), String::new())]
        );
        assert_eq!(d.hdrexts[0].id, "1");
        assert_eq!(d.sources[0].ssrc, "1111");
        assert_eq!(
            d.sources[0].parameters[1],
            ("msid".into(), "mixedmslabel mixedlabel0".into())
        );
        let t = a.transport.as_ref().unwrap();
        assert_eq!((t.ufrag.as_str(), t.pwd.as_str()), ("ufr", "pwdpwd"));
        let f = t.fingerprint.as_ref().unwrap();
        assert_eq!(
            (f.hash.as_str(), f.setup.as_str(), f.value.as_str()),
            ("sha-256", "actpass", "AA:BB")
        );
        assert_eq!(t.candidates.len(), 2);
        assert_eq!(t.candidates[1].kind, "srflx");
        assert_eq!(t.candidates[1].rel_addr, "10.0.0.1");
        let v = j.contents[1].description.as_ref().unwrap();
        assert_eq!(v.ssrc_groups[0].semantics, "FID");
        assert_eq!(v.ssrc_groups[0].ssrcs, ["2222", "3333"]);
        assert_eq!(v.payloads[1].parameters, [("apt".into(), "100".into())]);
        assert_eq!(v.payloads[0].rtcp_fb[1], ("nack".into(), "pli".into()));
        let data = &j.contents[2];
        assert!(data.description.as_ref().unwrap().sctpmap.is_none());
        let t = data.transport.as_ref().unwrap();
        assert_eq!(t.sctpmap.as_ref().unwrap().number, "5000");
        assert_eq!(t.websockets, ["wss://jvb.example/colibri-ws/x"]);
        // The fingerprint's text is what stands between its tags.
        assert_eq!(t.fingerprint.as_ref().unwrap().value, "\n  AA:BB\n");
    }

    /// The root must be an iq (the struct is tagged `iq`); a missing jingle
    /// child is an empty one, not an error.
    #[test]
    fn what_is_not_an_iq_with_a_jingle() {
        assert!(parse_stanza("<message/>").is_err());
        assert!(parse_stanza("not xml").is_err());
        let j = parse_stanza("<iq type='set'/>").unwrap();
        assert!(j.contents.is_empty() && j.sid.is_empty());
        // A jingle that is not a direct child is not read.
        assert!(parse_stanza("<iq><x><jingle sid='a'/></x></iq>")
            .unwrap()
            .sid
            .is_empty());
    }

    #[test]
    fn the_summary_go_keeps() {
        let p = Parsed::of(INITIATE);
        assert_eq!(
            (p.sid.as_str(), p.initiator.as_str()),
            ("sid123", "room@muc.meet.jitsi/focus")
        );
        assert_eq!(p.candidates.len(), 2);
        assert_eq!(p.colibri_ws, "wss://jvb.example/colibri-ws/x");
        assert_eq!(p.audio_sources.len(), 1);
        assert_eq!(p.audio_sources[0].name, "mixedmslabel mixedlabel0");
        assert_eq!(p.video_sources.len(), 1);
        assert_eq!(p.data_channel.as_ref().unwrap().port, "5000");
        assert_eq!(
            p.data_channel.as_ref().unwrap().protocol,
            "webrtc-datachannel"
        );
        assert!(p.sdp.starts_with("v=0\r\n"));
        // Nothing to read: what is known from the text stays.
        let bad = Parsed::of("<message sid='x'/>");
        assert!(bad.sdp.is_empty() && bad.jingle.is_none());
    }

    #[test]
    fn the_sizes_are_bounded() {
        let mut x = String::from("<iq><jingle sid='s'><content name='a'><transport>");
        for i in 0..1000 {
            x.push_str(&format!(
                "<candidate ip='10.0.{}.{}' port='1'/>",
                i / 250,
                i % 250
            ));
        }
        x.push_str("</transport></content></jingle></iq>");
        let j = parse_stanza(&x).unwrap();
        assert_eq!(
            j.contents[0].transport.as_ref().unwrap().candidates.len(),
            MAX_CANDIDATES
        );
        let many = format!(
            "<iq><jingle>{}</jingle></iq>",
            "<content name='c'/>".repeat(100)
        );
        assert_eq!(parse_stanza(&many).unwrap().contents.len(), MAX_CONTENTS);
    }

    /// `applyTrickleICE`'s reading: every candidate of every content, by the
    /// content's name.
    #[test]
    fn a_transport_info_gives_its_candidates() {
        let x = "<iq from='room@muc.meet.jitsi/focus' type='set' id='ti1' xmlns='jabber:client'><jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='sid123'>\
<content name='video'><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>\
<candidate component='1' foundation='7' generation='0' ip='1.2.3.4' port='4443' priority='5' protocol='UDP' type='relay' rel-addr='9.9.9.9' rel-port='1'/>\
<candidate foundation='8' ip='' port='1'/>\
<candidate foundation='9' ip='5.6.7.8' port='2'/></transport></content></jingle></iq>";
        let t = parse_transport_info(x).unwrap();
        assert_eq!(t.action, "transport-info");
        assert_eq!(t.contents.len(), 1);
        assert_eq!(t.contents[0].name, "video");
        let c = &t.contents[0].candidates;
        assert_eq!(c.len(), 3);
        assert_eq!(
            candidate_line(&c[0]).as_deref(),
            Some("candidate:7 1 udp 5 1.2.3.4 4443 typ relay raddr 9.9.9.9 rport 1 generation 0")
        );
        assert_eq!(candidate_line(&c[1]), None, "no address");
        // Go's defaults: component 1, udp, priority 1, host.
        assert_eq!(
            candidate_line(&c[2]).as_deref(),
            Some("candidate:9 1 udp 1 5.6.7.8 2 typ host")
        );
        assert!(parse_transport_info("<message/>").is_err());
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The stack's answer as the `session-accept`'s body, and a candidate as a
//! `transport-info`'s (`J/internal/jingle/build.go`, `J/internal/peer`).

use std::fmt::Write as _;

/// `s` for an attribute, as Go's replacer writes it: `&`, `"`, `'`, `<`, `>`.
#[must_use]
pub fn xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

fn split_lines(s: &str) -> Vec<String> {
    s.replace('\r', "")
        .trim()
        .split('\n')
        .map(str::to_owned)
        .collect()
}

fn get_attr(lines: &[String], key: &str) -> String {
    let prefix = format!("a={key}:");
    lines
        .iter()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(|v| v.trim().to_owned())
        .unwrap_or_default()
}

fn has_flag(lines: &[String], key: &str) -> bool {
    let target = format!("a={key}");
    lines.iter().any(|l| l.trim() == target)
}

/// `a=<key>:<id> <rest>` for the entry of payload `id`, the whole after the
/// colon.
fn get_attr_for<'a>(lines: &'a [String], key: &str, id: &str) -> &'a str {
    let prefix = format!("a={key}:");
    for l in lines {
        let Some(rest) = l.strip_prefix(&prefix) else {
            continue;
        };
        let Some(sp) = rest.find(' ') else { continue };
        if &rest[..sp] == id {
            return rest;
        }
    }
    ""
}

#[derive(Default)]
struct Shared {
    ufrag: String,
    pwd: String,
    fingerprint: String,
    setup: String,
    candidates: Vec<String>,
}

fn extract_shared(session: &str, media: &[&str]) -> Shared {
    let sl = split_lines(session);
    let mut st = Shared {
        ufrag: get_attr(&sl, "ice-ufrag"),
        pwd: get_attr(&sl, "ice-pwd"),
        fingerprint: get_attr(&sl, "fingerprint"),
        setup: get_attr(&sl, "setup"),
        candidates: Vec::new(),
    };
    for sec in media {
        let lines = split_lines(sec);
        if st.ufrag.is_empty() {
            st.ufrag = get_attr(&lines, "ice-ufrag");
        }
        if st.pwd.is_empty() {
            st.pwd = get_attr(&lines, "ice-pwd");
        }
        if st.fingerprint.is_empty() {
            st.fingerprint = get_attr(&lines, "fingerprint");
        }
        if st.setup.is_empty() {
            st.setup = get_attr(&lines, "setup");
        }
        if st.candidates.is_empty() {
            for l in &lines {
                if let Some(c) = l.strip_prefix("a=candidate:") {
                    st.candidates.push(c.to_owned());
                }
            }
        }
    }
    st
}

/// The body of the `session-accept` for the stack's answer
/// (`SDPToJingleAccept`): the BUNDLE group, then one content per media
/// section, with the transport the sections share where one carries none.
#[must_use]
pub fn accept_body(sdp: &str) -> String {
    let mut parts = sdp.split("\nm=");
    let session = parts.next().unwrap_or("");
    let media_owned: Vec<String> = parts.map(|p| format!("m={p}")).collect();
    let media: Vec<&str> = media_owned.iter().map(String::as_str).collect();
    let mut bundle: Vec<String> = Vec::new();
    for line in session.split('\n') {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=group:BUNDLE ") {
            bundle = rest.split_whitespace().map(str::to_owned).collect();
        }
    }
    let shared = extract_shared(session, &media);
    let mut b = String::new();
    if !bundle.is_empty() {
        b.push_str(r#"<group xmlns="urn:xmpp:jingle:apps:grouping:0" semantics="BUNDLE">"#);
        for m in &bundle {
            let _ = write!(b, r#"<content name="{}"/>"#, xml_attr(m));
        }
        b.push_str("</group>");
    }
    for sec in &media {
        write_content(&mut b, sec, &shared);
    }
    b
}

fn write_content(b: &mut String, section: &str, shared: &Shared) {
    let lines = split_lines(section);
    let first = lines[0].strip_prefix("m=").unwrap_or(&lines[0]);
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 3 {
        return;
    }
    let (media, proto, ids) = (parts[0], parts[2], &parts[3..]);
    let mut mid = get_attr(&lines, "mid");
    if mid.is_empty() {
        mid = media.to_owned();
    }
    let senders = if has_flag(&lines, "sendrecv") {
        "both"
    } else if has_flag(&lines, "sendonly") {
        "responder"
    } else if has_flag(&lines, "recvonly") {
        "initiator"
    } else if has_flag(&lines, "inactive") {
        "none"
    } else {
        "both"
    };
    let _ = write!(
        b,
        r#"<content creator="responder" name="{}" senders="{senders}">"#,
        xml_attr(&mid)
    );
    if proto.contains("SCTP") {
        let mut port = get_attr(&lines, "sctp-port");
        if port.is_empty() {
            port = "5000".to_owned();
        }
        b.push_str(r#"<description xmlns="urn:xmpp:jingle:transports:dtls-sctp:1"/>"#);
        write_transport(b, &lines, &port, shared);
    } else {
        let _ = write!(
            b,
            r#"<description xmlns="urn:xmpp:jingle:apps:rtp:1" media="{}">"#,
            xml_attr(media)
        );
        write_payloads(b, &lines, ids);
        write_hdrexts(b, &lines);
        if has_flag(&lines, "rtcp-mux") {
            b.push_str("<rtcp-mux/>");
        }
        b.push_str(&write_sources(&lines));
        b.push_str(&write_ssrc_groups(&lines));
        b.push_str("</description>");
        write_transport(b, &lines, "", shared);
    }
    b.push_str("</content>");
}

fn write_payloads(b: &mut String, lines: &[String], ids: &[&str]) {
    for id in ids {
        let rtpmap = get_attr_for(lines, "rtpmap", id);
        let (mut name, mut clock, mut channels) = ("", "", "");
        if !rtpmap.is_empty() {
            let rest = rtpmap.split_once(' ').map_or(rtpmap, |(_, r)| r);
            let mut f = rest.split('/');
            name = f.next().unwrap_or("");
            clock = f.next().unwrap_or("");
            channels = f.next().unwrap_or("");
        }
        let _ = write!(b, r#"<payload-type id="{}""#, xml_attr(id));
        if !name.is_empty() {
            let _ = write!(b, r#" name="{}""#, xml_attr(name));
        }
        if !clock.is_empty() {
            let _ = write!(b, r#" clockrate="{}""#, xml_attr(clock));
        }
        if !channels.is_empty() {
            let _ = write!(b, r#" channels="{}""#, xml_attr(channels));
        }
        b.push('>');
        let fmtp = get_attr_for(lines, "fmtp", id);
        if !fmtp.is_empty() {
            let params = fmtp.split_once(' ').map_or(fmtp, |(_, r)| r);
            for kv in params.split(';') {
                let kv = kv.trim();
                if kv.is_empty() {
                    continue;
                }
                match kv.split_once('=') {
                    Some((k, v)) => {
                        let _ = write!(
                            b,
                            r#"<parameter name="{}" value="{}"/>"#,
                            xml_attr(k),
                            xml_attr(v)
                        );
                    }
                    None => {
                        let _ = write!(b, r#"<parameter value="{}"/>"#, xml_attr(kv));
                    }
                }
            }
        }
        for line in lines {
            let Some(rest) = line.strip_prefix("a=rtcp-fb:") else {
                continue;
            };
            let fs: Vec<&str> = rest.split_whitespace().collect();
            if fs.len() >= 2 && fs[0] == *id {
                if fs.len() >= 3 {
                    let _ = write!(
                        b,
                        r#"<rtcp-fb xmlns="urn:xmpp:jingle:apps:rtp:rtcp-fb:0" type="{}" subtype="{}"/>"#,
                        xml_attr(fs[1]),
                        xml_attr(fs[2])
                    );
                } else {
                    let _ = write!(
                        b,
                        r#"<rtcp-fb xmlns="urn:xmpp:jingle:apps:rtp:rtcp-fb:0" type="{}"/>"#,
                        xml_attr(fs[1])
                    );
                }
            }
        }
        b.push_str("</payload-type>");
    }
}

fn write_hdrexts(b: &mut String, lines: &[String]) {
    for line in lines {
        let Some(rest) = line.strip_prefix("a=extmap:") else {
            continue;
        };
        let fs: Vec<&str> = rest.split_whitespace().collect();
        if fs.len() >= 2 {
            let _ = write!(
                b,
                r#"<rtp-hdrext xmlns="urn:xmpp:jingle:apps:rtp:rtp-hdrext:0" id="{}" uri="{}"/>"#,
                xml_attr(fs[0]),
                xml_attr(fs[1])
            );
        }
    }
}

/// The `a=ssrc-group:` entries as `[semantics, ssrc...]`.
fn ssrc_groups(lines: &[String]) -> Vec<Vec<&str>> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("a=ssrc-group:"))
        .map(|r| r.split_whitespace().collect::<Vec<_>>())
        .filter(|fs| fs.len() >= 2)
        .collect()
}

/// The `<source/>` elements of a section (`writeSources`): one per SSRC with
/// an `a=ssrc` line, in order, and one for each SSRC a group names that has
/// none, with a declared sibling's parameters: Jicofo refuses a group that
/// names an unsignalled source.
#[must_use]
pub fn write_sources(lines: &[String]) -> String {
    let mut sources: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for line in lines {
        let Some(rest) = line.strip_prefix("a=ssrc:") else {
            continue;
        };
        let Some(sp) = rest.find(' ') else { continue };
        let (ssrc, val) = (&rest[..sp], &rest[sp + 1..]);
        let (name, value) = match val.split_once(':') {
            Some((n, v)) => (n, v),
            None => (val, ""),
        };
        let at = match sources.iter().position(|(s, _)| s == ssrc) {
            Some(i) => i,
            None => {
                sources.push((ssrc.to_owned(), Vec::new()));
                sources.len() - 1
            }
        };
        sources[at].1.push((name.to_owned(), value.to_owned()));
    }
    for g in ssrc_groups(lines) {
        let Some(donor) = g[1..]
            .iter()
            .find_map(|s| sources.iter().find(|(x, _)| x == s))
            .map(|(_, p)| p.clone())
        else {
            continue;
        };
        for ssrc in &g[1..] {
            if sources.iter().any(|(x, _)| x == ssrc) {
                continue;
            }
            sources.push(((*ssrc).to_owned(), donor.clone()));
        }
    }
    let mut b = String::new();
    for (ssrc, params) in &sources {
        let _ = write!(
            b,
            r#"<source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="{}">"#,
            xml_attr(ssrc)
        );
        for (n, v) in params {
            if v.is_empty() {
                let _ = write!(b, r#"<parameter name="{}"/>"#, xml_attr(n));
            } else {
                let _ = write!(
                    b,
                    r#"<parameter name="{}" value="{}"/>"#,
                    xml_attr(n),
                    xml_attr(v)
                );
            }
        }
        b.push_str("</source>");
    }
    b
}

fn write_ssrc_groups(lines: &[String]) -> String {
    let mut b = String::new();
    for g in ssrc_groups(lines) {
        let _ = write!(
            b,
            r#"<ssrc-group xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" semantics="{}">"#,
            xml_attr(g[0])
        );
        for ssrc in &g[1..] {
            let _ = write!(b, r#"<source ssrc="{}"/>"#, xml_attr(ssrc));
        }
        b.push_str("</ssrc-group>");
    }
    b
}

fn candidate_component(raw: &str) -> &str {
    raw.split_whitespace().nth(1).unwrap_or("")
}

fn write_transport(b: &mut String, lines: &[String], sctp_port: &str, shared: &Shared) {
    let rtcp_mux = has_flag(lines, "rtcp-mux");
    let mut ufrag = get_attr(lines, "ice-ufrag");
    if ufrag.is_empty() {
        ufrag.clone_from(&shared.ufrag);
    }
    let mut pwd = get_attr(lines, "ice-pwd");
    if pwd.is_empty() {
        pwd.clone_from(&shared.pwd);
    }
    let _ = write!(
        b,
        r#"<transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="{}" pwd="{}">"#,
        xml_attr(&ufrag),
        xml_attr(&pwd)
    );
    let mut fp = get_attr(lines, "fingerprint");
    if fp.is_empty() {
        fp.clone_from(&shared.fingerprint);
    }
    if let Some((hash, val)) = fp.split_once(' ') {
        let mut setup = get_attr(lines, "setup");
        if setup.is_empty() {
            setup.clone_from(&shared.setup);
        }
        if setup.is_empty() {
            setup = "active".to_owned();
        }
        let _ = write!(
            b,
            r#"<fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="{}" setup="{}">{}</fingerprint>"#,
            xml_attr(hash),
            xml_attr(&setup),
            xml_attr(val)
        );
    }
    let mut wrote = false;
    for line in lines {
        let Some(raw) = line.strip_prefix("a=candidate:") else {
            continue;
        };
        if rtcp_mux && candidate_component(raw) == "2" {
            continue;
        }
        write_candidate(b, raw);
        wrote = true;
    }
    if !wrote {
        for raw in &shared.candidates {
            if rtcp_mux && candidate_component(raw) == "2" {
                continue;
            }
            write_candidate(b, raw);
        }
    }
    if !sctp_port.is_empty() {
        let _ = write!(
            b,
            r#"<sctpmap xmlns="urn:xmpp:jingle:transports:dtls-sctp:1" number="{}" protocol="webrtc-datachannel" streams="1024"/>"#,
            xml_attr(sctp_port)
        );
    }
    b.push_str("</transport>");
}

/// One `<candidate/>` for an SDP candidate line (without `a=candidate:`):
/// generation 0 where none is named, the id the foundation and component
/// together; nothing for a line of fewer than eight fields.
pub fn write_candidate(b: &mut String, raw: &str) {
    let fs: Vec<&str> = raw.split_whitespace().collect();
    if fs.len() < 8 {
        return;
    }
    let (foundation, component, protocol, priority, ip, port, kind) =
        (fs[0], fs[1], fs[2], fs[3], fs[4], fs[5], fs[7]);
    let (mut raddr, mut rport, mut generation, mut tcptype) = ("", "", "", "");
    let mut i = 8;
    while i + 1 < fs.len() {
        match fs[i] {
            "raddr" => raddr = fs[i + 1],
            "rport" => rport = fs[i + 1],
            "generation" => generation = fs[i + 1],
            "tcptype" => tcptype = fs[i + 1],
            _ => {}
        }
        i += 2;
    }
    if generation.is_empty() {
        generation = "0";
    }
    let _ = write!(
        b,
        r#"<candidate component="{}" foundation="{}" generation="{}" id="{}{}" ip="{}" network="0" port="{}" priority="{}" protocol="{}" type="{}""#,
        xml_attr(component),
        xml_attr(foundation),
        xml_attr(generation),
        xml_attr(foundation),
        xml_attr(component),
        xml_attr(ip),
        xml_attr(port),
        xml_attr(priority),
        xml_attr(&protocol.to_lowercase()),
        xml_attr(kind)
    );
    if !raddr.is_empty() {
        let _ = write!(
            b,
            r#" rel-addr="{}" rel-port="{}""#,
            xml_attr(raddr),
            xml_attr(rport)
        );
    }
    if !tcptype.is_empty() {
        let _ = write!(b, r#" tcptype="{}""#, xml_attr(tcptype));
    }
    b.push_str("/>");
}

/// The body of a `transport-info` that trickles one candidate to the focus
/// (`SendTransportInfo`): `candidate_line` with or without `a=` and
/// `candidate:` in front.
#[must_use]
pub fn transport_info_content(media_name: &str, candidate_line: &str) -> String {
    let raw = candidate_line.strip_prefix("a=").unwrap_or(candidate_line);
    let raw = raw.strip_prefix("candidate:").unwrap_or(raw);
    let mut cand = String::new();
    write_candidate(&mut cand, raw);
    format!(
        r#"<content creator="responder" name="{}"><transport xmlns="urn:xmpp:jingle:transports:ice-udp:1">{cand}</transport></content>"#,
        xml_attr(media_name)
    )
}

/// The content a mid belongs to, for a `transport-info`
/// (`mediaNameForMid`): `0` and `audio`, `1` and `video`, `2` and `data`.
#[must_use]
pub fn media_name_for_mid(mid: &str) -> &str {
    match mid {
        "0" | "audio" => "audio",
        "1" | "video" => "video",
        "2" | "data" => "data",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources_of(lines: &[&str]) -> String {
        let lines: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
        write_sources(&lines)
    }

    /// `TestWriteSourcesSynthesizesRTX` (`build_test.go`): pion writes a=ssrc
    /// for the primary only; Jicofo refuses a group that names an unsignalled
    /// source.
    #[test]
    fn the_rtx_source_is_made_from_its_sibling() {
        let lines = [
            "a=ssrc-group:FID 3354541959 3299577015",
            "a=ssrc:3354541959 cname:olcrtc-ka-WMutBdYz",
            "a=ssrc:3354541959 msid:olcrtc-ka-WMutBdYz jitsi-ka-4x861OUH",
            "a=ssrc:3354541959 mslabel:olcrtc-ka-WMutBdYz",
            "a=ssrc:3354541959 label:jitsi-ka-4x861OUH",
        ];
        let out = sources_of(&lines);
        assert!(out.contains(r#"ssrc="3354541959""#), "{out}");
        assert!(out.contains(r#"ssrc="3299577015""#), "{out}");
        assert!(out.matches("olcrtc-ka-WMutBdYz").count() >= 2, "{out}");
        // In the order of the lines, the made one after.
        assert!(out.find("3354541959").unwrap() < out.find("3299577015").unwrap());
    }

    /// `TestGroupSSRCsAllSignaled`.
    #[test]
    fn every_ssrc_of_a_group_has_a_source() {
        let lines = [
            "a=ssrc-group:FID 111 222",
            "a=ssrc-group:SIM 111 333 444",
            "a=ssrc:111 cname:foo",
        ];
        let out = sources_of(&lines);
        for s in ["111", "222", "333", "444"] {
            assert!(out.contains(&format!(r#"ssrc="{s}""#)), "{s}: {out}");
        }
    }

    /// `TestNoDuplicateSourceWhenSignaled`.
    #[test]
    fn a_signalled_source_is_not_made_again() {
        let out = sources_of(&[
            "a=ssrc-group:FID 111 222",
            "a=ssrc:111 cname:foo",
            "a=ssrc:222 cname:bar",
        ]);
        assert_eq!(out.matches(r#"ssrc="222""#).count(), 1, "{out}");
        assert!(out.contains("bar"), "{out}");
    }

    #[test]
    fn a_source_is_written_as_go_writes_it() {
        let out = sources_of(&[
            "a=ssrc:5 cname:a&b",
            "a=ssrc:5 msid:x y",
            "a=ssrc:5 flag",
            "a=ssrc:6",
            "junk",
        ]);
        assert_eq!(
            out,
            r#"<source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="5"><parameter name="cname" value="a&amp;b"/><parameter name="msid" value="x y"/><parameter name="flag"/></source>"#
        );
    }

    const ANSWER: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE audio data\r\na=msid-semantic:WMS*\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:uf\r\na=ice-pwd:pw\r\na=fingerprint:sha-256 CC:DD\r\na=setup:active\r\na=mid:audio\r\na=recvonly\r\na=rtcp-mux\r\n\
a=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=candidate:1 1 udp 2130706431 10.1.1.1 5000 typ host\r\na=candidate:1 2 udp 2130706430 10.1.1.1 5001 typ host\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:data\r\na=sctp-port:5000\r\n";

    #[test]
    fn the_accept_body_byte_for_byte() {
        let want = concat!(
            r#"<group xmlns="urn:xmpp:jingle:apps:grouping:0" semantics="BUNDLE"><content name="audio"/><content name="data"/></group>"#,
            r#"<content creator="responder" name="audio" senders="initiator">"#,
            r#"<description xmlns="urn:xmpp:jingle:apps:rtp:1" media="audio">"#,
            r#"<payload-type id="111" name="opus" clockrate="48000" channels="2"><parameter name="minptime" value="10"/><parameter name="useinbandfec" value="1"/></payload-type>"#,
            r#"<rtcp-mux/></description>"#,
            r#"<transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="uf" pwd="pw">"#,
            r#"<fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="sha-256" setup="active">CC:DD</fingerprint>"#,
            r#"<candidate component="1" foundation="1" generation="0" id="11" ip="10.1.1.1" network="0" port="5000" priority="2130706431" protocol="udp" type="host"/>"#,
            r#"</transport></content>"#,
            r#"<content creator="responder" name="data" senders="both">"#,
            r#"<description xmlns="urn:xmpp:jingle:transports:dtls-sctp:1"/>"#,
            r#"<transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="uf" pwd="pw">"#,
            r#"<fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="sha-256" setup="active">CC:DD</fingerprint>"#,
            r#"<candidate component="1" foundation="1" generation="0" id="11" ip="10.1.1.1" network="0" port="5000" priority="2130706431" protocol="udp" type="host"/>"#,
            r#"<candidate component="2" foundation="1" generation="0" id="12" ip="10.1.1.1" network="0" port="5001" priority="2130706430" protocol="udp" type="host"/>"#,
            r#"<sctpmap xmlns="urn:xmpp:jingle:transports:dtls-sctp:1" number="5000" protocol="webrtc-datachannel" streams="1024"/>"#,
            r#"</transport></content>"#,
        );
        assert_eq!(accept_body(ANSWER), want);
    }

    #[test]
    fn senders_are_the_offerers_view() {
        for (flag, want) in [
            ("sendrecv", "both"),
            ("sendonly", "responder"),
            ("recvonly", "initiator"),
            ("inactive", "none"),
        ] {
            let sdp = format!("v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\na={flag}\r\n");
            assert!(
                accept_body(&sdp).contains(&format!(r#"name="a" senders="{want}""#)),
                "{flag}"
            );
        }
        // A section named by no mid is named by its media.
        assert!(accept_body("v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 0\r\n").contains(r#"name="video""#));
        // Too short an m-line is skipped; no BUNDLE line, no group.
        let none = accept_body("v=0\r\nm=audio 9\r\n");
        assert_eq!(none, "");
    }

    #[test]
    fn a_fingerprint_and_ice_come_from_the_session_level_too() {
        let sdp = "v=0\r\na=ice-ufrag:su\r\na=ice-pwd:sp\r\na=fingerprint:sha-256 EE:FF\r\na=setup:passive\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\n";
        let b = accept_body(sdp);
        assert!(b.contains(r#"ufrag="su" pwd="sp""#), "{b}");
        assert!(
            b.contains(r#"hash="sha-256" setup="passive">EE:FF</fingerprint>"#),
            "{b}"
        );
        // No setup anywhere: active.
        let none =
            "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 0\r\na=mid:a\r\na=fingerprint:sha-256 EE:FF\r\n";
        assert!(accept_body(none).contains(r#"setup="active""#));
    }

    #[test]
    fn a_candidate_has_go_s_defaults_and_options() {
        let c = |raw: &str| {
            let mut s = String::new();
            write_candidate(&mut s, raw);
            s
        };
        assert_eq!(
            c("842163049 1 UDP 1677729535 1.2.3.4 4000 typ srflx raddr 10.0.0.1 rport 4000 generation 3 tcptype passive"),
            r#"<candidate component="1" foundation="842163049" generation="3" id="8421630491" ip="1.2.3.4" network="0" port="4000" priority="1677729535" protocol="udp" type="srflx" rel-addr="10.0.0.1" rel-port="4000" tcptype="passive"/>"#
        );
        assert_eq!(c("1 1 udp 2 ::1 9"), "", "fewer than eight fields");
        // An odd trailing field is left unread.
        assert!(c("1 1 udp 2 1.1.1.1 9 typ host odd").contains(r#"type="host"/>"#));
    }

    #[test]
    fn a_trickled_candidate_is_a_transport_info_content() {
        assert_eq!(
            transport_info_content("audio", "candidate:7 1 udp 5 1.2.3.4 4443 typ host"),
            r#"<content creator="responder" name="audio"><transport xmlns="urn:xmpp:jingle:transports:ice-udp:1"><candidate component="1" foundation="7" generation="0" id="71" ip="1.2.3.4" network="0" port="4443" priority="5" protocol="udp" type="host"/></transport></content>"#
        );
        // "a=" in front is taken off too; a line that is not a candidate gives an empty transport.
        assert!(
            transport_info_content("data", "a=candidate:7 1 udp 5 1.2.3.4 4443 typ host")
                .contains(r#"foundation="7""#)
        );
        assert!(transport_info_content("data", "junk").contains("ice-udp:1\"></transport>"));
        for (mid, want) in [
            ("0", "audio"),
            ("audio", "audio"),
            ("1", "video"),
            ("video", "video"),
            ("2", "data"),
            ("data", "data"),
            ("x", "x"),
        ] {
            assert_eq!(media_name_for_mid(mid), want);
        }
    }

    #[test]
    fn xml_attr_is_gos_replacer() {
        assert_eq!(
            xml_attr(r#"a&b"c'd<e>f"#),
            "a&amp;b&quot;c&apos;d&lt;e&gt;f"
        );
    }
}

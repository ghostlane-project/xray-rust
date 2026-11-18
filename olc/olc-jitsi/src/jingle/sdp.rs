// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The offer as SDP (`J/internal/jingle/sdp.go`, `J/internal/peer/peer.go`'s
//! `stripRemoteSourcesForPion`) and the view of it the stack is given.

use std::fmt::Write as _;

use crate::jingle::parse::{Content, Jingle};

/// The offer as SDP (`JingleToSDP`).
#[must_use]
pub fn to_sdp(j: &Jingle) -> String {
    let mut b = String::new();
    b.push_str("v=0\r\no=- 0 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n");
    let mids: Vec<&str> = match &j.group {
        Some(g) if g.semantics.eq_ignore_ascii_case("BUNDLE") => {
            g.contents.iter().map(String::as_str).collect()
        }
        _ => j.contents.iter().map(|c| c.name.as_str()).collect(),
    };
    let _ = write!(b, "a=group:BUNDLE {}\r\n", mids.join(" "));
    b.push_str("a=msid-semantic: WMS *\r\n");
    for c in &j.contents {
        write_content(&mut b, c);
    }
    b
}

fn write_content(b: &mut String, c: &Content) {
    let desc = c.description.as_ref();
    let transport = c.transport.as_ref();
    let mut media = desc.map(|d| d.media.as_str()).unwrap_or("");
    let has_sctp =
        desc.is_some_and(|d| d.sctpmap.is_some()) || transport.is_some_and(|t| t.sctpmap.is_some());
    if media.is_empty() && (c.name == "data" || has_sctp) {
        media = "application";
    }
    if media == "application" {
        b.push_str("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
    } else {
        let mut ids: Vec<&str> = desc
            .map(|d| d.payloads.iter().map(|p| p.id.as_str()).collect())
            .unwrap_or_default();
        if ids.is_empty() {
            ids = vec!["0"];
        }
        let _ = write!(b, "m={media} 9 UDP/TLS/RTP/SAVPF {}\r\n", ids.join(" "));
    }
    b.push_str("c=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n");
    let _ = write!(b, "a=mid:{}\r\n", c.name);
    match c.senders.to_lowercase().as_str() {
        "both" | "" => b.push_str("a=sendrecv\r\n"),
        "initiator" => b.push_str("a=recvonly\r\n"),
        "responder" => b.push_str("a=sendonly\r\n"),
        "none" => b.push_str("a=inactive\r\n"),
        _ => {}
    }
    if let Some(t) = transport {
        if !t.ufrag.is_empty() {
            let _ = write!(b, "a=ice-ufrag:{}\r\n", t.ufrag);
        }
        if !t.pwd.is_empty() {
            let _ = write!(b, "a=ice-pwd:{}\r\n", t.pwd);
        }
        b.push_str("a=ice-options:trickle\r\n");
        if let Some(f) = &t.fingerprint {
            let _ = write!(b, "a=fingerprint:{} {}\r\n", f.hash, f.value.trim());
            let setup = if f.setup.is_empty() {
                "actpass"
            } else {
                &f.setup
            };
            let _ = write!(b, "a=setup:{setup}\r\n");
        }
        for ca in &t.candidates {
            let _ = write!(
                b,
                "a=candidate:{} {} {} {} {} {} typ {}",
                ca.foundation,
                ca.component,
                ca.protocol.to_lowercase(),
                ca.priority,
                ca.ip,
                ca.port,
                ca.kind
            );
            if !ca.rel_addr.is_empty() {
                let _ = write!(b, " raddr {} rport {}", ca.rel_addr, ca.rel_port);
            }
            if !ca.generation.is_empty() {
                let _ = write!(b, " generation {}", ca.generation);
            }
            if !ca.tcp_type.is_empty() {
                let _ = write!(b, " tcptype {}", ca.tcp_type);
            }
            b.push_str("\r\n");
        }
    }
    if media == "application" {
        let mut port = "5000";
        if let Some(m) = desc.and_then(|d| d.sctpmap.as_ref()) {
            if !m.number.is_empty() {
                port = &m.number;
            }
        }
        if let Some(m) = transport.and_then(|t| t.sctpmap.as_ref()) {
            if !m.number.is_empty() {
                port = &m.number;
            }
        }
        let _ = write!(b, "a=sctp-port:{port}\r\na=max-message-size:262144\r\n");
        return;
    }
    let Some(d) = desc else { return };
    if d.rtcp_mux {
        b.push_str("a=rtcp-mux\r\n");
    }
    for e in &d.hdrexts {
        let _ = write!(b, "a=extmap:{} {}\r\n", e.id, e.uri);
    }
    for pt in &d.payloads {
        let channels = if pt.channels.is_empty() {
            String::new()
        } else {
            format!("/{}", pt.channels)
        };
        let clock = if pt.clockrate.is_empty() {
            "90000"
        } else {
            &pt.clockrate
        };
        let _ = write!(b, "a=rtpmap:{} {}/{clock}{channels}\r\n", pt.id, pt.name);
        for (kind, sub) in &pt.rtcp_fb {
            if sub.is_empty() {
                let _ = write!(b, "a=rtcp-fb:{} {kind}\r\n", pt.id);
            } else {
                let _ = write!(b, "a=rtcp-fb:{} {kind} {sub}\r\n", pt.id);
            }
        }
        if !pt.parameters.is_empty() {
            let parts: Vec<String> = pt
                .parameters
                .iter()
                .map(|(n, v)| {
                    if n.is_empty() {
                        v.clone()
                    } else {
                        format!("{n}={v}")
                    }
                })
                .collect();
            let _ = write!(b, "a=fmtp:{} {}\r\n", pt.id, parts.join(";"));
        }
    }
    for g in &d.ssrc_groups {
        let _ = write!(b, "a=ssrc-group:{} {}\r\n", g.semantics, g.ssrcs.join(" "));
    }
    for s in &d.sources {
        for (n, v) in &s.parameters {
            if n.is_empty() {
                let _ = write!(b, "a=ssrc:{} {v}\r\n", s.ssrc);
            } else if v.is_empty() {
                let _ = write!(b, "a=ssrc:{} {n}\r\n", s.ssrc);
            } else {
                let _ = write!(b, "a=ssrc:{} {n}:{v}\r\n", s.ssrc);
            }
        }
    }
}

/// `sdp` without the remote sources: a stack that holds an explicit SSRC
/// drops RTP for one it was not told of, and the bridge forwards a newly
/// announced source before its `source-add` is applied
/// (`stripRemoteSourcesForPion`).
#[must_use]
pub fn strip_remote_sources(sdp: &str) -> String {
    sdp.split("\r\n")
        .filter(|l| !l.starts_with("a=ssrc:") && !l.starts_with("a=ssrc-group:"))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// What the stack is given: no remote sources, and the offer's `actpass`
/// read as `passive`, so it answers as the DTLS client, as Go's does
/// (plan D6; the SaluteJazz carrier does the same).
#[must_use]
pub fn stack_view(sdp: &str) -> String {
    strip_remote_sources(sdp).replace("a=setup:actpass", "a=setup:passive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jingle::fixtures::INITIATE;
    use crate::jingle::parse::parse_stanza;

    const CRLF: &str = "\r\n";

    fn lines(parts: &[&str]) -> String {
        parts.iter().map(|l| format!("{l}{CRLF}")).collect()
    }

    #[test]
    fn the_initiate_as_sdp_line_for_line() {
        let want = lines(&[
            "v=0",
            "o=- 0 2 IN IP4 0.0.0.0",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE audio video data",
            "a=msid-semantic: WMS *",
            "m=audio 9 UDP/TLS/RTP/SAVPF 111 126",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            "a=mid:audio",
            "a=sendrecv",
            "a=ice-ufrag:ufr",
            "a=ice-pwd:pwdpwd",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 AA:BB",
            "a=setup:actpass",
            "a=candidate:1 1 udp 2130706431 10.0.0.1 10000 typ host generation 0",
            "a=candidate:2 1 udp 1677724415 1.2.3.4 10000 typ srflx raddr 10.0.0.1 rport 10000 generation 0",
            "a=rtcp-mux",
            "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            "a=rtpmap:111 opus/48000/2",
            "a=rtcp-fb:111 transport-cc",
            "a=fmtp:111 minptime=10;useinbandfec=1",
            "a=rtpmap:126 telephone-event/8000",
            "a=ssrc:1111 cname:mixed",
            "a=ssrc:1111 msid:mixedmslabel mixedlabel0",
            "m=video 9 UDP/TLS/RTP/SAVPF 100 96",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            "a=mid:video",
            "a=sendrecv",
            "a=ice-ufrag:ufr",
            "a=ice-pwd:pwdpwd",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 AA:BB",
            "a=setup:actpass",
            "a=rtcp-mux",
            "a=rtpmap:100 VP8/90000",
            "a=rtcp-fb:100 nack",
            "a=rtcp-fb:100 nack pli",
            "a=rtpmap:96 rtx/90000",
            "a=fmtp:96 apt=100",
            "a=ssrc-group:FID 2222 3333",
            "a=ssrc:2222 cname:v",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            "a=mid:data",
            "a=sendrecv",
            "a=ice-ufrag:ufr",
            "a=ice-pwd:pwdpwd",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 AA:BB",
            "a=setup:actpass",
            "a=sctp-port:5000",
            "a=max-message-size:262144",
        ]);
        let j = parse_stanza(INITIATE).unwrap();
        assert_eq!(to_sdp(&j), want);
    }

    #[test]
    fn senders_and_the_group_follow_go() {
        let x = |senders: &str| {
            format!(
                "<iq><jingle><content name='a' senders='{senders}'><description media='audio'><payload-type id='0' name='PCMU'/></description></content></jingle></iq>"
            )
        };
        for (s, want) in [
            ("both", "a=sendrecv"),
            ("", "a=sendrecv"),
            ("initiator", "a=recvonly"),
            ("responder", "a=sendonly"),
            ("none", "a=inactive"),
            ("BOTH", "a=sendrecv"),
        ] {
            let sdp = to_sdp(&parse_stanza(&x(s)).unwrap());
            assert!(sdp.contains(&format!("{want}\r\n")), "{s}: {sdp}");
        }
        // An unknown value writes no direction line at all.
        assert!(!to_sdp(&parse_stanza(&x("weird")).unwrap()).contains("a=sendrecv"));
        // No group in the stanza: the contents' names.
        assert!(to_sdp(&parse_stanza(&x("both")).unwrap()).contains("a=group:BUNDLE a\r\n"));
        // A group that is not BUNDLE is not used.
        let g = "<iq><jingle><group semantics='LS'><content name='z'/></group><content name='a'/></jingle></iq>";
        assert!(to_sdp(&parse_stanza(g).unwrap()).contains("a=group:BUNDLE a\r\n"));
        // A payload with no clockrate has 90000; no payloads, payload 0.
        let np =
            "<iq><jingle><content name='v'><description media='video'/></content></jingle></iq>";
        assert!(to_sdp(&parse_stanza(np).unwrap()).contains("m=video 9 UDP/TLS/RTP/SAVPF 0\r\n"));
        let nc = "<iq><jingle><content name='v'><description media='video'><payload-type id='9' name='X'/></description></content></jingle></iq>";
        assert!(to_sdp(&parse_stanza(nc).unwrap()).contains("a=rtpmap:9 X/90000\r\n"));
        // A parameter with no name is its value alone.
        let nn = "<iq><jingle><content name='v'><description media='video'><payload-type id='9' name='X'><parameter value='p'/><parameter name='k' value='v'/></payload-type></description></content></jingle></iq>";
        assert!(to_sdp(&parse_stanza(nn).unwrap()).contains("a=fmtp:9 p;k=v\r\n"));
    }

    #[test]
    fn a_data_content_is_found_by_its_name_or_its_sctpmap() {
        for x in [
            "<iq><jingle><content name='data'/></jingle></iq>",
            "<iq><jingle><content name='x'><description><sctpmap number='5001'/></description></content></jingle></iq>",
            "<iq><jingle><content name='x'><transport><sctpmap port='5001'/></transport></content></jingle></iq>",
        ] {
            let sdp = to_sdp(&parse_stanza(x).unwrap());
            assert!(sdp.contains("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"), "{x}");
        }
        let t = "<iq><jingle><content name='x'><description><sctpmap number='5001'/></description><transport><sctpmap number='5002'/></transport></content></jingle></iq>";
        assert!(
            to_sdp(&parse_stanza(t).unwrap()).contains("a=sctp-port:5002\r\n"),
            "the transport's wins"
        );
        let p = "<iq><jingle><content name='x'><transport><sctpmap port='5001'/></transport></content></jingle></iq>";
        assert!(
            to_sdp(&parse_stanza(p).unwrap()).contains("a=sctp-port:5000\r\n"),
            "only a number is used"
        );
    }

    /// `stripRemoteSourcesForPion`, and the role: the offer's `actpass` is
    /// read as `passive` so the stack answers as the DTLS client (plan D6).
    #[test]
    fn the_stack_is_given_no_sources_and_is_the_dtls_client() {
        let sdp = to_sdp(&parse_stanza(INITIATE).unwrap());
        let view = stack_view(&sdp);
        assert!(!view.contains("a=ssrc"), "{view}");
        assert!(!view.contains("actpass"));
        assert_eq!(view.matches("a=setup:passive\r\n").count(), 3);
        // Everything else is as it was.
        let keep: Vec<&str> = sdp
            .split("\r\n")
            .filter(|l| !l.starts_with("a=ssrc") && !l.starts_with("a=setup"))
            .collect();
        let got: Vec<&str> = view
            .split("\r\n")
            .filter(|l| !l.starts_with("a=setup"))
            .collect();
        assert_eq!(got, keep);
        assert_eq!(
            strip_remote_sources("a=ssrc-group:FID 1 2\r\na=ssrc:1 cname:x\r\na=mid:0"),
            "a=mid:0"
        );
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Every stanza the client writes, as the exact text the Go client at the
//! pin sends.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha1::{Digest, Sha1};

use crate::xml::escape;

/// The caps node of jitsi-meet (`jitsiCapsNode`).
pub const CAPS_NODE: &str = "https://jitsi.org/jitsi-meet";

/// The features the client says it has (`jitsiMeetFeatures`), sorted as the
/// caps hash and the disco reply list them.
pub const FEATURES: [&str; 16] = [
    "http://jabber.org/protocol/caps",
    "http://jitsi.org/json-encoded-sources",
    "http://jitsi.org/receive-multiple-video-streams",
    "http://jitsi.org/remb",
    "http://jitsi.org/source-name",
    "http://jitsi.org/start-muted-room-metadata",
    "http://jitsi.org/tcc",
    "http://jitsi.org/visitors-1",
    "urn:ietf:rfc:4588",
    "urn:xmpp:jingle:1",
    "urn:xmpp:jingle:apps:dtls:0",
    "urn:xmpp:jingle:apps:rtp:1",
    "urn:xmpp:jingle:apps:rtp:audio",
    "urn:xmpp:jingle:apps:rtp:video",
    "urn:xmpp:jingle:transports:dtls-sctp:1",
    "urn:xmpp:jingle:transports:ice-udp:1",
];

/// The caps `ver`: SHA-1 of each feature followed by `<`, in order, base64
/// (`calculateJitsiCapsVersion`).
#[must_use]
pub fn caps_ver() -> String {
    let mut h = Sha1::new();
    for f in FEATURES {
        h.update(f.as_bytes());
        h.update(b"<");
    }
    STANDARD.encode(h.finalize())
}

/// The stream opening (`<open/>` of RFC 7395).
#[must_use]
pub fn open(xmpp_domain: &str) -> String {
    format!(
        r#"<open to="{}" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#,
        escape(xmpp_domain)
    )
}

/// SASL ANONYMOUS.
pub const AUTH_ANONYMOUS: &str =
    r#"<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>"#;
/// Resource binding.
pub const BIND: &str = r#"<iq type="set" id="bind_1" xmlns="jabber:client"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></iq>"#;
/// Session establishment.
pub const SESSION: &str = r#"<iq type="set" id="sess_1" xmlns="jabber:client"><session xmlns="urn:ietf:params:xml:ns:xmpp-session"/></iq>"#;
/// Stream management on, with resumption asked for.
pub const ENABLE_SM: &str = r#"<enable resume="true" xmlns="urn:xmpp:sm:3"/>"#;
/// A stream management request (the keepalive).
pub const SM_REQUEST: &str = r#"<r xmlns="urn:xmpp:sm:3"/>"#;

/// A stream management acknowledgement of `h` stanzas.
#[must_use]
pub fn sm_ack(h: u32) -> String {
    format!(r#"<a h="{h}" xmlns="urn:xmpp:sm:3"/>"#)
}

/// The external services (STUN/TURN) request.
#[must_use]
pub fn extdisco(xmpp_domain: &str) -> String {
    format!(
        r#"<iq type="get" to="{}" id="disco_1" xmlns="jabber:client"><services xmlns="urn:xmpp:extdisco:2"/></iq>"#,
        escape(xmpp_domain)
    )
}

/// The conference request to Jicofo.
#[must_use]
pub fn focus(xmpp_domain: &str, room_jid: &str, nick: &str) -> String {
    format!(
        r#"<iq to="focus.{}" type="set" id="focus_1" xmlns="jabber:client"><conference room="{}" machine-uid="{}" xmlns="http://jitsi.org/protocol/focus"><property name="rtcstatsEnabled" value="false"/><property name="visitors-version" value="1"/></conference></iq>"#,
        escape(xmpp_domain),
        escape(room_jid),
        escape(nick)
    )
}

/// The presence that joins the room (`JoinMUC`). The stats id is the first
/// three bytes of the name (less, at a character boundary) and `-j`.
#[must_use]
pub fn join_presence(room_jid: &str, display_name: &str, nick: &str) -> String {
    let mut cut = display_name.len().min(3);
    while !display_name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        r#"<presence to="{}" xmlns="jabber:client"><x xmlns="http://jabber.org/protocol/muc"/><stats-id>{}-j</stats-id><c hash="sha-1" node="{CAPS_NODE}" ver="{}" xmlns="http://jabber.org/protocol/caps"/><SourceInfo>{{"{n}-a0":{{"muted":true}},"{n}-v0":{{"muted":true}}}}</SourceInfo><jitsi_participant_codecList>vp8,h264,av1,vp9</jitsi_participant_codecList><nick xmlns="http://jabber.org/protocol/nick">{}</nick></presence>"#,
        escape(room_jid),
        escape(&display_name[..cut]),
        caps_ver(),
        escape(display_name),
        n = escape(nick),
    )
}

/// The room's disco#info request.
#[must_use]
pub fn room_info(room_bare_jid: &str, id: &str) -> String {
    format!(
        r#"<iq to="{}" type="get" id="{}" xmlns="jabber:client"><query xmlns="http://jabber.org/protocol/disco#info"/></iq>"#,
        escape(room_bare_jid),
        escape(id)
    )
}

/// Leaving the room.
#[must_use]
pub fn leave(room_jid: &str) -> String {
    format!(
        r#"<presence to="{}" type="unavailable" xmlns="jabber:client"/>"#,
        escape(room_jid)
    )
}

/// The empty result that acknowledges an IQ set.
#[must_use]
pub fn iq_result(to: &str, id: &str) -> String {
    format!(
        r#"<iq to="{}" id="{}" type="result" xmlns="jabber:client"/>"#,
        escape(to),
        escape(id)
    )
}

/// The XMPP ping (`keepalive.go`).
#[must_use]
pub fn ping(to: &str, id: &str) -> String {
    format!(
        r#"<iq type="get" to="{}" id="{}" xmlns="jabber:client"><ping xmlns="urn:xmpp:ping"/></iq>"#,
        escape(to),
        escape(id)
    )
}

/// The answer to a disco#info get: [`FEATURES`], no identity.
#[must_use]
pub fn disco_result(to: &str, id: &str) -> String {
    let mut s = format!(
        r#"<iq to="{}" id="{}" type="result" xmlns="jabber:client"><query xmlns="http://jabber.org/protocol/disco#info">"#,
        escape(to),
        escape(id)
    );
    for f in FEATURES {
        s.push_str(&format!(r#"<feature var="{f}"/>"#));
    }
    s.push_str("</query></iq>");
    s
}

/// The `session-accept` (`SendSessionAccept`): `to` is the focus's room JID.
#[must_use]
pub fn session_accept(to: &str, sid: &str, initiator: &str, responder: &str, body: &str) -> String {
    jingle_with(
        to,
        "accept_1",
        "session-accept",
        sid,
        initiator,
        responder,
        body,
    )
}

/// Any Jingle action (`SendJingle`); `body` is XML and goes in as it is.
#[must_use]
pub fn jingle(
    to: &str,
    id: &str,
    action: &str,
    sid: &str,
    initiator: &str,
    responder: &str,
    body: &str,
) -> String {
    jingle_with(to, id, action, sid, initiator, responder, body)
}

fn jingle_with(
    to: &str,
    id: &str,
    action: &str,
    sid: &str,
    initiator: &str,
    responder: &str,
    body: &str,
) -> String {
    format!(
        r#"<iq to="{}" type="set" id="{}" xmlns="jabber:client"><jingle xmlns="urn:xmpp:jingle:1" action="{}" sid="{}" initiator="{}" responder="{}">{body}</jingle></iq>"#,
        escape(to),
        escape(id),
        escape(action),
        escape(sid),
        escape(initiator),
        escape(responder),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_caps_version_is_jitsi_meets() {
        assert_eq!(caps_ver(), "xUTPQ7C5wic8q6nOytcEI8dwRJI=");
        assert_eq!(FEATURES.len(), 16);
        let mut sorted = FEATURES.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, FEATURES, "the list is kept sorted");
    }

    #[test]
    fn the_login_stanzas() {
        assert_eq!(
            open("meet.example"),
            r#"<open to="meet.example" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#
        );
        assert_eq!(
            AUTH_ANONYMOUS,
            r#"<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>"#
        );
        assert_eq!(
            BIND,
            r#"<iq type="set" id="bind_1" xmlns="jabber:client"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></iq>"#
        );
        assert_eq!(
            SESSION,
            r#"<iq type="set" id="sess_1" xmlns="jabber:client"><session xmlns="urn:ietf:params:xml:ns:xmpp-session"/></iq>"#
        );
        assert_eq!(
            ENABLE_SM,
            r#"<enable resume="true" xmlns="urn:xmpp:sm:3"/>"#
        );
        assert_eq!(SM_REQUEST, r#"<r xmlns="urn:xmpp:sm:3"/>"#);
        assert_eq!(sm_ack(7), r#"<a h="7" xmlns="urn:xmpp:sm:3"/>"#);
        assert_eq!(
            extdisco("meet.example"),
            r#"<iq type="get" to="meet.example" id="disco_1" xmlns="jabber:client"><services xmlns="urn:xmpp:extdisco:2"/></iq>"#
        );
    }

    #[test]
    fn the_focus_request_and_the_presence() {
        assert_eq!(
            focus("meet.example", "room@muc.meet.example", "abcdef01"),
            r#"<iq to="focus.meet.example" type="set" id="focus_1" xmlns="jabber:client"><conference room="room@muc.meet.example" machine-uid="abcdef01" xmlns="http://jitsi.org/protocol/focus"><property name="rtcstatsEnabled" value="false"/><property name="visitors-version" value="1"/></conference></iq>"#
        );
        assert_eq!(
            join_presence("room@muc.meet.example/abcdef01", "olcrtc", "abcdef01"),
            concat!(
                r#"<presence to="room@muc.meet.example/abcdef01" xmlns="jabber:client">"#,
                r#"<x xmlns="http://jabber.org/protocol/muc"/><stats-id>olc-j</stats-id>"#,
                r#"<c hash="sha-1" node="https://jitsi.org/jitsi-meet" ver="xUTPQ7C5wic8q6nOytcEI8dwRJI=" xmlns="http://jabber.org/protocol/caps"/>"#,
                r#"<SourceInfo>{"abcdef01-a0":{"muted":true},"abcdef01-v0":{"muted":true}}</SourceInfo>"#,
                r#"<jitsi_participant_codecList>vp8,h264,av1,vp9</jitsi_participant_codecList>"#,
                r#"<nick xmlns="http://jabber.org/protocol/nick">olcrtc</nick></presence>"#
            )
        );
        // A name shorter than three bytes gives all of it; a cut never
        // lands inside a character.
        assert!(join_presence("r@m/n", "ab", "n").contains("<stats-id>ab-j</stats-id>"));
        assert!(
            join_presence("r@m/n", "a\u{e9}\u{e9}", "n").contains("<stats-id>a\u{e9}-j</stats-id>")
        );
        // A name with markup stays text.
        let p = join_presence("r@m/n", "a<b>&", "n");
        assert!(
            p.contains("<nick xmlns=\"http://jabber.org/protocol/nick\">a&lt;b&gt;&amp;</nick>"),
            "{p}"
        );
        assert!(crate::xml::Reader::new(&p).next_event().is_ok());
    }

    #[test]
    fn room_info_leave_and_the_replies() {
        assert_eq!(
            room_info("room@muc.meet.example", "j-4"),
            r#"<iq to="room@muc.meet.example" type="get" id="j-4" xmlns="jabber:client"><query xmlns="http://jabber.org/protocol/disco#info"/></iq>"#
        );
        assert_eq!(
            leave("room@muc.meet.example/abcdef01"),
            r#"<presence to="room@muc.meet.example/abcdef01" type="unavailable" xmlns="jabber:client"/>"#
        );
        assert_eq!(
            iq_result("focus@auth.meet.example", "si_123"),
            r#"<iq to="focus@auth.meet.example" id="si_123" type="result" xmlns="jabber:client"/>"#
        );
        assert_eq!(
            ping("meet.example", "j-9"),
            r#"<iq type="get" to="meet.example" id="j-9" xmlns="jabber:client"><ping xmlns="urn:xmpp:ping"/></iq>"#
        );
    }

    #[test]
    fn the_disco_reply_has_sixteen_features_and_no_identity() {
        let r = disco_result("focus@auth.meet.example", "disco_99");
        assert!(r.starts_with(
            r#"<iq to="focus@auth.meet.example" id="disco_99" type="result" xmlns="jabber:client"><query xmlns="http://jabber.org/protocol/disco#info">"#
        ));
        assert!(r.ends_with("</query></iq>"));
        assert_eq!(r.matches("<feature var=").count(), 16);
        assert!(!r.contains("<identity"));
        assert!(r.contains(r#"<feature var="urn:xmpp:jingle:transports:dtls-sctp:1"/>"#));
        // In sorted order, as the caps hash is.
        let at = |f: &str| r.find(f).unwrap();
        assert!(at("http://jabber.org/protocol/caps") < at("urn:xmpp:jingle:1"));
    }

    #[test]
    fn the_jingle_stanzas() {
        assert_eq!(
            session_accept(
                "room@muc.meet.example/focus",
                "sid1",
                "room@muc.meet.example/focus",
                "abc@meet.example/res",
                "<content/>"
            ),
            r#"<iq to="room@muc.meet.example/focus" type="set" id="accept_1" xmlns="jabber:client"><jingle xmlns="urn:xmpp:jingle:1" action="session-accept" sid="sid1" initiator="room@muc.meet.example/focus" responder="abc@meet.example/res"><content/></jingle></iq>"#
        );
        assert_eq!(
            jingle(
                "room@muc.meet.example/focus",
                "j-5",
                "transport-info",
                "sid1",
                "room@muc.meet.example/focus",
                "abc@meet.example/res",
                "<content/>"
            ),
            r#"<iq to="room@muc.meet.example/focus" type="set" id="j-5" xmlns="jabber:client"><jingle xmlns="urn:xmpp:jingle:1" action="transport-info" sid="sid1" initiator="room@muc.meet.example/focus" responder="abc@meet.example/res"><content/></jingle></iq>"#
        );
    }

    #[test]
    fn what_goes_in_an_attribute_is_escaped() {
        let s = iq_result("a\"b", "c<d");
        assert_eq!(
            s,
            r#"<iq to="a&#34;b" id="c&lt;d" type="result" xmlns="jabber:client"/>"#
        );
        assert!(crate::xml::root(&s).is_ok());
    }
}

// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! Jingle (XEP-0166) as the j library speaks it
//! (`J/internal/jingle/{types,jingle,sdp,build}.go`, `J/internal/peer`):
//! [`parse`] reads a `session-initiate` and a `transport-info`, [`sdp`] turns
//! the offer into the SDP the stack is given, [`build`] turns the stack's
//! answer back into the `session-accept`'s body and a candidate into a
//! `transport-info`'s.

pub mod build;
pub mod parse;
pub mod sdp;

#[cfg(test)]
pub(crate) mod fixtures {
    /// A `session-initiate` as Jicofo writes it, trimmed: audio, video, data.
    pub const INITIATE: &str = "<iq from='room@muc.meet.jitsi/focus' to='abc@meet.jitsi/res' id='si1' type='set' xmlns='jabber:client'>\
<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' initiator='room@muc.meet.jitsi/focus' sid='sid123'>\
<group xmlns='urn:xmpp:jingle:apps:grouping:0' semantics='BUNDLE'><content name='audio'/><content name='video'/><content name='data'/></group>\
<content creator='initiator' name='audio' senders='both'>\
<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>\
<payload-type id='111' name='opus' clockrate='48000' channels='2'><parameter name='minptime' value='10'/><parameter name='useinbandfec' value='1'/><rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='transport-cc'/></payload-type>\
<payload-type id='126' name='telephone-event' clockrate='8000'/>\
<rtp-hdrext xmlns='urn:xmpp:jingle:apps:rtp:rtp-hdrext:0' id='1' uri='urn:ietf:params:rtp-hdrext:ssrc-audio-level'/>\
<rtcp-mux/>\
<source xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' ssrc='1111'><parameter name='cname' value='mixed'/><parameter name='msid' value='mixedmslabel mixedlabel0'/></source>\
</description>\
<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='ufr' pwd='pwdpwd'>\
<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass' required='false'>AA:BB</fingerprint>\
<candidate component='1' foundation='1' generation='0' id='c1' ip='10.0.0.1' network='0' port='10000' priority='2130706431' protocol='udp' type='host'/>\
<candidate component='1' foundation='2' generation='0' id='c2' ip='1.2.3.4' network='0' port='10000' priority='1677724415' protocol='UDP' type='srflx' rel-addr='10.0.0.1' rel-port='10000'/>\
</transport></content>\
<content creator='initiator' name='video' senders='both'>\
<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='video'>\
<payload-type id='100' name='VP8' clockrate='90000'><rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='nack'/><rtcp-fb xmlns='urn:xmpp:jingle:apps:rtp:rtcp-fb:0' type='nack' subtype='pli'/></payload-type>\
<payload-type id='96' name='rtx' clockrate='90000'><parameter name='apt' value='100'/></payload-type>\
<rtcp-mux/>\
<source xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' ssrc='2222'><parameter name='cname' value='v'/></source>\
<ssrc-group xmlns='urn:xmpp:jingle:apps:rtp:ssma:0' semantics='FID'><source ssrc='2222'/><source ssrc='3333'/></ssrc-group>\
</description>\
<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='ufr' pwd='pwdpwd'>\
<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>AA:BB</fingerprint></transport></content>\
<content creator='initiator' name='data' senders='both'>\
<description xmlns='urn:xmpp:jingle:transports:dtls-sctp:1'/>\
<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' ufrag='ufr' pwd='pwdpwd'>\
<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>\n  AA:BB\n</fingerprint>\
<sctpmap xmlns='urn:xmpp:jingle:transports:dtls-sctp:1' number='5000' protocol='webrtc-datachannel' streams='1024'/>\
<web-socket xmlns='http://jitsi.org/protocol/colibri' url='wss://jvb.example/colibri-ws/x'/>\
</transport></content></jingle></iq>";
}

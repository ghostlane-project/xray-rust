// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The connector's JSON (signaling.go): what goes out in the engine's field
//! order (serde writes a struct's fields in declaration order, as
//! `encoding/json` does), what comes in read leniently.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `event` values.
pub mod event {
    /// Client to connector: join the room.
    pub const JOIN: &str = "join";
    /// The join's answer.
    pub const JOIN_RESPONSE: &str = "join-response";
    /// Client to connector: a media message.
    pub const MEDIA_IN: &str = "media-in";
    /// Connector to client: a media message.
    pub const MEDIA_OUT: &str = "media-out";
    /// A refusal.
    pub const ERROR: &str = "error";
    /// Someone left.
    pub const PARTICIPANT_LEFT: &str = "participant-left";
}

/// `method` values of media messages.
pub mod method {
    /// The ICE servers.
    pub const CONFIG: &str = "rtc:config";
    /// An SDP offer.
    pub const OFFER: &str = "rtc:offer";
    /// An SDP answer.
    pub const ANSWER: &str = "rtc:answer";
    /// Trickled candidates.
    pub const ICE: &str = "rtc:ice";
    /// The keepalive.
    pub const PING: &str = "rtc:ping";
    /// Its answer.
    pub const PONG: &str = "rtc:pong";
    /// The room as the join found it.
    pub const JOIN: &str = "rtc:join";
    /// The room changed.
    pub const PARTICIPANTS: &str = "rtc:participants:update";
}

/// The peer connection the SFU offers (it sends on it; this side receives).
pub const TARGET_SUBSCRIBER: &str = "SUBSCRIBER";
/// The peer connection this side offers (it sends on it).
pub const TARGET_PUBLISHER: &str = "PUBLISHER";

/// `envOut`.
#[derive(Debug, Serialize)]
pub struct EnvOut<'a, P: Serialize> {
    /// The room code.
    #[serde(rename = "roomId")]
    pub room_id: &'a str,
    /// The payload.
    pub payload: &'a P,
    /// The event.
    pub event: &'a str,
    /// The participant group, once known (`omitempty`).
    #[serde(rename = "groupId", skip_serializing_if = "str::is_empty")]
    pub group_id: &'a str,
    /// A fresh UUID.
    #[serde(rename = "requestId")]
    pub request_id: &'a str,
}

/// `envIn`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EnvIn {
    /// The event.
    pub event: String,
    /// The request it answers.
    #[serde(rename = "requestId")]
    pub request_id: String,
    /// The group.
    #[serde(rename = "groupId")]
    pub group_id: String,
    /// Who it is about (participant-left).
    #[serde(rename = "participantId")]
    pub participant_id: String,
    /// The payload.
    pub payload: Value,
}

/// `mediaIn`.
#[derive(Debug, Default, Serialize)]
pub struct MediaIn<'a> {
    /// The method.
    pub method: &'a str,
    /// An SDP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<SdpOut<'a>>,
    /// Candidates.
    #[serde(rename = "rtcIceCandidates", skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<IceOut<'a>>,
    /// A ping.
    #[serde(rename = "ping_req", skip_serializing_if = "Option::is_none")]
    pub ping_req: Option<PingReq>,
}

/// `sdpOut`.
#[derive(Debug, Serialize)]
pub struct SdpOut<'a> {
    /// The SDP.
    pub sdp: &'a str,
    /// `offer` or `answer`.
    #[serde(rename = "type")]
    pub kind: &'a str,
}

/// `pingRequest`.
#[derive(Debug, Serialize)]
pub struct PingReq {
    /// Unix milliseconds.
    pub timestamp: i64,
    /// The last round trip, ms.
    pub rtt: i64,
}

/// `iceCandidate`, going out.
#[derive(Debug, Serialize)]
pub struct IceOut<'a> {
    /// `candidate:...`.
    pub candidate: &'a str,
    /// Always `"0"` here.
    #[serde(rename = "sdpMid")]
    pub sdp_mid: &'a str,
    /// Always 0 here.
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_mline_index: u16,
    /// The local ufrag (the fake SFU refuses a candidate without it).
    #[serde(rename = "usernameFragment", skip_serializing_if = "str::is_empty")]
    pub username_fragment: &'a str,
    /// Which peer connection.
    pub target: &'a str,
}

/// `joinRequest`.
#[derive(Debug, Serialize)]
pub struct JoinRequest<'a> {
    /// The room's password.
    pub password: &'a str,
    /// The display name.
    #[serde(rename = "participantName")]
    pub participant_name: &'a str,
    /// The web client's features.
    #[serde(rename = "supportedFeatures")]
    pub supported_features: SupportedFeatures,
    /// Always false.
    #[serde(rename = "isSilent")]
    pub is_silent: bool,
}

/// `supportedFeatures`: all four on, as the web client sends.
#[derive(Debug, Serialize)]
pub struct SupportedFeatures {
    /// On.
    #[serde(rename = "attachedRooms")]
    pub attached_rooms: bool,
    /// On.
    #[serde(rename = "sessionGroups")]
    pub session_groups: bool,
    /// On.
    pub transcription: bool,
    /// On.
    pub interpretation: bool,
}

/// `mediaPayload`, coming in.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MediaPayload {
    /// The method.
    pub method: String,
    /// rtc:config.
    pub configuration: Option<RtcConfiguration>,
    /// rtc:offer, rtc:answer.
    pub description: Option<SdpIn>,
    /// rtc:ice.
    #[serde(rename = "rtcIceCandidates")]
    pub candidates: Vec<IceIn>,
    /// rtc:pong.
    pub pong_resp: Option<PongResp>,
    /// rtc:join.
    pub join: Option<RoomState>,
    /// rtc:participants:update.
    pub update: Option<ParticipantsUpdate>,
}

/// `rtcConfiguration`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RtcConfiguration {
    /// The servers.
    #[serde(rename = "iceServers")]
    pub ice_servers: Vec<IceServer>,
}

/// `iceServer`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct IceServer {
    /// `stun:` / `turn:` / `turns:` URLs.
    pub urls: Vec<String>,
    /// TURN user.
    pub username: String,
    /// TURN password.
    pub credential: String,
}

/// `sdpDescription`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SdpIn {
    /// `offer` or `answer`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The SDP.
    pub sdp: String,
}

/// `iceCandidate`, coming in.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct IceIn {
    /// `candidate:...`.
    pub candidate: String,
    /// Which peer connection; empty means the subscriber.
    pub target: String,
}

/// `pongResponse`: the timestamps come as numbers or strings.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PongResp {
    /// The ping it answers.
    #[serde(rename = "lastPingTimestamp")]
    pub last_ping_timestamp: Value,
}

/// `roomState`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RoomState {
    /// Everyone else.
    #[serde(rename = "otherParticipants")]
    pub other_participants: Vec<Participant>,
}

/// `participantsUpdate`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ParticipantsUpdate {
    /// Who changed.
    pub participants: Vec<Participant>,
}

/// `participant`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Participant {
    /// LiveKit's sid.
    pub sid: String,
    /// The identity DataPackets name.
    pub identity: String,
    /// `DISCONNECTED` when it went.
    pub state: String,
}

/// `participantLeft`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ParticipantLeft {
    /// Who.
    #[serde(rename = "participantId")]
    pub participant_id: String,
    /// Or here.
    pub participant: ParticipantRef,
}

/// `participantLeft.participant`, and `joinResponse.participant`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ParticipantRef {
    /// Who.
    #[serde(rename = "participantId")]
    pub participant_id: String,
}

/// `joinResponse`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct JoinResponse {
    /// The meeting.
    #[serde(rename = "meetingId")]
    pub meeting_id: String,
    /// This side.
    pub participant: ParticipantRef,
    /// The group frames carry from now on.
    #[serde(rename = "participantGroup")]
    pub participant_group: GroupRef,
}

/// `joinResponse.participantGroup`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GroupRef {
    /// The group.
    #[serde(rename = "groupId")]
    pub group_id: String,
}

/// `serverError`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServerError {
    /// `NOT_FOUND`, `ROOM_CLOSED`, ...
    pub code: String,
    /// Words.
    pub message: String,
}

/// `parseMillis`: a number or a quoted number; 0 for anything else.
#[must_use]
pub fn parse_millis(v: &Value) -> i64 {
    match v {
        Value::Number(n) => n.as_i64().unwrap_or(0),
        Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// `roomIsGone`.
#[must_use]
pub fn room_is_gone(code: &str) -> bool {
    if code == "NOT_FOUND" {
        return true;
    }
    ["ROOM_", "MEETING_"].iter().any(|p| {
        code.strip_prefix(p).is_some_and(|rest| {
            matches!(
                rest,
                "NOT_FOUND" | "CLOSED" | "ENDED" | "FINISHED" | "DELETED" | "EXPIRED"
            )
        })
    })
}

/// `endedReason`.
#[must_use]
pub fn ended_reason(what: &str, code: &str) -> String {
    let code = if code.is_empty() { "no code" } else { code };
    format!("salutejazz: {what} ({code})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_go_out_in_the_engines_field_order() {
        let join = JoinRequest {
            password: "pw",
            participant_name: "Ann Lee",
            supported_features: SupportedFeatures {
                attached_rooms: true,
                session_groups: true,
                transcription: true,
                interpretation: true,
            },
            is_silent: false,
        };
        let env = EnvOut {
            room_id: "abc123",
            payload: &join,
            event: event::JOIN,
            group_id: "",
            request_id: "r",
        };
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"roomId":"abc123","payload":{"password":"pw","participantName":"Ann Lee","supportedFeatures":{"attachedRooms":true,"sessionGroups":true,"transcription":true,"interpretation":true},"isSilent":false},"event":"join","requestId":"r"}"#
        );
        let ice = MediaIn {
            method: method::ICE,
            candidates: vec![IceOut {
                candidate: "candidate:1 1 udp 2130706431 192.0.2.7 5000 typ host",
                sdp_mid: "0",
                sdp_mline_index: 0,
                username_fragment: "AbCd",
                target: TARGET_PUBLISHER,
            }],
            ..MediaIn::default()
        };
        let env = EnvOut {
            room_id: "abc123",
            payload: &ice,
            event: event::MEDIA_IN,
            group_id: "g1",
            request_id: "r",
        };
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"roomId":"abc123","payload":{"method":"rtc:ice","rtcIceCandidates":[{"candidate":"candidate:1 1 udp 2130706431 192.0.2.7 5000 typ host","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"AbCd","target":"PUBLISHER"}]},"event":"media-in","groupId":"g1","requestId":"r"}"#
        );
        let ping = MediaIn {
            method: method::PING,
            ping_req: Some(PingReq {
                timestamp: 5,
                rtt: 0,
            }),
            ..MediaIn::default()
        };
        assert_eq!(
            serde_json::to_string(&ping).unwrap(),
            r#"{"method":"rtc:ping","ping_req":{"timestamp":5,"rtt":0}}"#
        );
    }

    #[test]
    fn incoming_frames_are_read_leniently() {
        let f: EnvIn = serde_json::from_str(r#"{"event":"media-out","payload":{"method":"rtc:pong","pong_resp":{"lastPingTimestamp":"17"}},"extra":1}"#).unwrap();
        let m: MediaPayload = serde_json::from_value(f.payload).unwrap();
        assert_eq!(parse_millis(&m.pong_resp.unwrap().last_ping_timestamp), 17);
        assert_eq!(parse_millis(&serde_json::json!(18)), 18);
        assert_eq!(parse_millis(&serde_json::json!(null)), 0);
    }

    #[test]
    fn the_rooms_gone_codes_are_gos() {
        for c in [
            "NOT_FOUND",
            "ROOM_CLOSED",
            "MEETING_ENDED",
            "ROOM_NOT_FOUND",
            "MEETING_EXPIRED",
        ] {
            assert!(room_is_gone(c), "{c}");
        }
        for c in ["", "ROOM_FULL", "FORBIDDEN", "CLOSED"] {
            assert!(!room_is_gone(c), "{c}");
        }
        assert_eq!(
            ended_reason("the room is gone", ""),
            "salutejazz: the room is gone (no code)"
        );
    }
}

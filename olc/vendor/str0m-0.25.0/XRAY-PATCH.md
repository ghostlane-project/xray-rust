# str0m 0.25.0: NACK resends without RTX

Source: the complete unchanged-version crates.io `str0m` **0.25.0** archive,
SHA256 `357c7e453c033c8bb59e912312f9f9ff07c2a9ce7268bcb94f0c828a5b47e58f`.
Upstream licenses and the published lockfile remain intact. `XRAY-PATCH.diff`
reconstructs the local source from that archive with zero fuzz. Run
`scripts/check-vendored-sources.sh` to verify the archive, exact reconstruction,
and the crate's library and NACK tests from an isolated copy. The olcRTC
engine (`olc/olc-rtc`) uses it through the workspace's `[patch.crates-io]`.

## A NACK is answered when no RTX is negotiated

Upstream resends a NACKed packet only on an RTX stream: a packet whose payload
type has no RTX payload type is marked not nackable when it goes out, and a
receive stream whose payload has no RTX sends no NACK (`suppress_nack`). With
RTX absent from the SDP, a lost packet is gone.

libwebrtc and pion answer such a NACK with the packet itself, on its own SSRC
and sequence number. pion's responder (interceptor 0.1.45,
`internal/rtpbuffer/packet_factory.go`) adds the RTX header only when the
stream has an RTX SSRC and payload type, and it sits innermost in the
interceptor chain, so the packet it resends is the one it stored: the same
header, transport-wide sequence number included, and the same payload.

The olcRTC engine writes KCP into video frames, and the carriers' SFUs forward
whatever they are offered. Where a video payload type is negotiated with
`nack` feedback and no RTX (the p2p lab pair's VP8, and any far end whose SDP
leaves RTX out), a packet lost on the upload cost its whole frame until KCP
resent it. Where no `nack` is negotiated at all (the Go engine's MAX carrier
registers VP8 with no feedback, `internal/engine/maxcalls/maxcalls.go:188-193`)
nothing is NACKed, with or without this patch.

The patch, keyed only on what was negotiated:

- `streams/send.rs`: a packet on a payload type with `nack` feedback stays
  nackable when that payload type has no RTX payload type, or the stream has
  no RTX SSRC. A NACK for it is answered with `NextPacketKind::ResendPlain`:
  the cached header and payload as they went the first time. A regular
  packet's cached header keeps the abs-send-time and transport-cc values it
  went with, and a plain resend sets neither again, so the bytes and the SRTP
  index are the original's. RTX padding never takes such a packet; it pads
  with a blank packet instead.
- `session.rs`: a transport-cc number is registered only when the packet took
  a new one, so a plain resend registers nothing.
- `streams/mod.rs` and `change/sdp.rs`: a receive stream with no RTX sends
  NACKs when its payloads take them (`a=rtcp-fb:<pt> nack`).

With RTX negotiated nothing changes: the resend goes on the RTX stream as
upstream sends it. The direct API's streams declared without an RTX SSRC on
an RTX-capable payload type now resend plainly; upstream reached
`expect("Should have RTX SSRC for resends")` there.

`tests/nack.rs` `nack_without_rtx_resends_the_packet_on_its_own_ssrc` loses one
packet on a stream with no RTX and checks that the receiver gets it again on
its own SSRC, byte for byte, with nothing sent on any other SSRC. Before the
patch it panicked at that `expect`.

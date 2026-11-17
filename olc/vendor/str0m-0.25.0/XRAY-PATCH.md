# str0m 0.25.0: five patches for the olcRTC engine

1. A NACK is answered when no RTX is negotiated.
2. Video RED is a payload type of its own.
3. A send stream can keep its Mid and Rid on every packet.
4. A send stream says how many written packets it still holds.
5. A close inside SCTP's handshake still says DTLS's goodbye.

Source: the complete unchanged-version crates.io `str0m` **0.25.0** archive,
SHA256 `357c7e453c033c8bb59e912312f9f9ff07c2a9ce7268bcb94f0c828a5b47e58f`.
Upstream licenses and the published lockfile remain intact. `XRAY-PATCH.diff`
reconstructs the local source from that archive with zero fuzz. Run
`scripts/check-vendored-sources.sh` to verify the archive, exact reconstruction,
and the crate's library tests and the integration tests of the five patches
from an isolated copy. The olcRTC
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

## Video RED is a payload type of its own

Upstream knows RED (RFC 2198) for audio only. It builds payload parameters for
the rtpmaps that are audio codecs, video codecs or telephone-event, and hangs a
`red` payload type on the audio codec its fmtp names. `red` on a video line is
neither: it gets no parameters, and RTP at a payload type without parameters is
dropped before `Event::RtpPacket`.

VK Calls' SFU forwards a participant's camera wrapped in RED. Its offer names
it on every receive slot, with an RTX of its own and no fmtp:

    a=rtpmap:104 red/90000
    a=rtpmap:105 rtx/90000
    a=fmtp:105 apt=104

pion registers `video/red` as a codec like any other, and the Go engine's
reader takes the primary block out of each packet
(`internal/transport/vp8channel/rtp_reader.go`, `common.REDPrimary`). The Rust
engine's reader does the same (`olc-vp8channel`, `red_primary`), so all it
needs of str0m is the packet as it came.

The patch gives such a `red` parameters of its own, in RTP mode's terms a codec
whose payload str0m never looks into:

- `sdp/data.rs` (`MediaLine::rtp_params`): a `red` rtpmap of a video section is
  kept, with the RTX whose `apt` names it and its rtcp-fb lines. Audio sections
  are read as before.
- `format/codec_config.rs` (`all_for_kind`): such an entry counts as video, so
  a video line written by this end names it too.
- `session.rs` (`handle_rtp`): a frame-mode session has no depacketizer for
  RED (`CodecDepacketizer::from` panics on it), so there a packet at such a
  payload type is dropped, as it was when it had no parameters.

It is opt-in: negotiation keeps a remote payload type only when the local
table has a matching entry, and none of upstream's `enable_*` adds `red` for
video. A session asks for it with
`CodecConfig::add_config(pt, Some(rtx), Codec::Red, Frequency::NINETY_KHZ, None, FormatParams::default())`
(`olc-rtc`: `media::CodecLine::video_red`). Without that entry nothing changes.
`Codec::Red` stays neither `is_audio()` nor `is_video()`, and audio RED stays a
property of its codec (`PayloadParams::red`).

What reaches `Event::RtpPacket` is the RED packet: its own payload type in the
header, the RED header first in the payload. A lost one is NACKed and comes
back over its RTX, unwrapped by str0m as any RTX is. Writing video RED is not
part of this: the frame API has no packetizer for it, and in RTP mode a caller
writes whatever bytes it likes at the payload type.

`tests/red.rs`, module `video`: `video_red_is_negotiated_and_reaches_the_packet_event`
(both ends hold `red` at 104 with RTX 105 after an offer and answer, 20 packets
arrive as written), `a_lost_video_red_packet_is_resent_over_its_rtx`, and
`a_frame_mode_receiver_drops_video_red`. Without the `sdp/data.rs` line the
first two fail (the line's remote payload types hold no 104; the lost packet
never arrives again); without the `session.rs` guard the third panics in
`CodecDepacketizer::from`.

The answering end of those tests starts with `red` at other numbers than the
offer's, on purpose. str0m looks an incoming packet's payload type up in the
whole local table, entries no description has confirmed included, so an
unpatched session does hand RED up when its own table happens to hold `red`
at the very number the far end sends. That is a coincidence of numbers, not a
negotiation: with the patch the table takes the number the description names.

## A send stream can keep its Mid and Rid on every packet

Upstream writes the Mid and Rid header extensions on a stream's packets until
an RTCP receiver report names the stream's SSRC, then leaves them out: the
receiver has shown that it bound the SSRC (libwebrtc's rule,
`rtp_sender.cc`). The first report comes right behind the first packet, so in
practice only the first packets carry them.

VK Calls' SFU is never told an SSRC: the answer it is sent declares the layers
by rid alone (`a=rid:l send`, no `a=ssrc`), and the Go engine installs an
interceptor that writes the mid and the rid on every packet it publishes
(`internal/engine/vkcalls/stamp.go`, `sdesStamper`).

The patch adds a switch to the send stream, off by default:

- `streams/send.rs`: `StreamTx::set_mid_rid_on_every_packet(bool)`. On, the
  stream is treated as one the receiver has not bound: every packet carries
  the Mid and the Rid, every RTX packet the Mid (the repaired Rid is on each
  of those in any case). Off, nothing changes.

One thing upstream does already and the patch leaves alone: a stream that has
an RTX SSRC never records the report for its main SSRC (`handle_rtcp` looks at
the RTX SSRC first and at the main one only when there is no RTX), so such a
stream stamps every main packet without the switch. The switch does not rely
on that.

`tests/rtp-direct-mid-rid.rs` `mid_and_rid_stay_on_every_packet_when_kept`
sends six seconds of video on a stream with a rid and no RTX, once as
upstream (the first packet carries both, the last neither) and once with the
switch (every packet carries both). Before the patch the second half fails.

## A send stream says how many written packets it still holds

`StreamTx::write_rtp` puts a packet in the stream's send queue, a `VecDeque`
with no bound, and `Rtc::poll_output` takes it out. An owner that polls as
fast as packets are written never sees the queue; one that cannot does. The
olcRTC engine's ICE-TCP path stops polling while a socket has part of a frame
left to take (pion's write blocks there), so on a link slower than its writer
the difference stayed in this queue and grew without end. Upstream's
`StreamTx::queue_info` is a sample taken at the pacer's last update: it is
stale exactly while the owner is not polling.

The patch adds a read, nothing else:

- `streams/send_queue.rs`: `SendQueue::len`.
- `streams/send.rs`: `StreamTx::queued_packets()`, the number of packets
  written and not yet handed out (resends and padding are not in it).

`olc-rtc`'s `media::SendLine::write` reads it under the same lock as the
write and refuses the batch that would pass its bound
(`media::SEND_BACKLOG_PACKETS`). No behaviour of str0m changes.

`tests/rtp-direct-mid-rid.rs` `a_stream_counts_the_packets_it_holds` writes
five packets (the count is 5), runs the session for a second (the count is 0,
five packets arrived).

## A close inside SCTP's handshake still says DTLS's goodbye

Upstream's `Rtc::close` (`start_close`) queues the RTCP BYEs, asks the SCTP
association to shut down, and then starts DTLS's close_notify. sctp-proto
0.10.8 refuses to shut down an association that is not established
(`Association::shutdown`: `ErrShutdownNonEstablished`), and `start_close`
returned that refusal with `?`: the state stayed as it was and no
close_notify was ever queued. A peer connection closed in the few
milliseconds between DTLS connecting and SCTP's COOKIE-ACK therefore said
nothing, and the far end learnt of it only when its ICE timed out (seen in
olc-vkcalls' fake SFU: its peer had not ended 8 s after the client's closed;
merge item 4 of wave 2). pion closes its SCTP association and its DTLS
connection independently, so its far end hears the close either way.

The patch, `lib.rs` `start_close`: SCTP's refusal is logged at debug and
dropped; the state becomes `Closing` and the close_notify goes out as for an
established association. An established association shuts down as before.

`tests/dtls-close.rs` `a_close_inside_the_sctp_handshake_still_says_goodbye`
connects DTLS, starts SCTP on both sides and closes before anything of the
association has gone out; the far end must see `Event::Closed`. Before the
patch `close()` returned `Sctp(Proto(ErrShutdownNonEstablished))`.

# sctp-proto 0.10.8: an INIT ACK's Unrecognized Parameter read

sctp-proto is str0m's SCTP, under every olcRTC data channel.

1. An Unrecognized Parameter (type 8, RFC 9260 section 3.3.3.1) is read as
   an unknown parameter (`src/param/mod.rs`, `build_param`). Upstream sent
   it to the arm for unknown types, where a type whose top bit is 0 means
   "stop processing": the INIT ACK carrying it was dropped whole and the
   INIT sent again until the association gave up. VK Calls' SFU answers our
   INIT, which names Supported Extensions (0x8008), with exactly that
   parameter and its State Cookie, so no data channel opened on VK (Ghostlane
   1.0.477 to 1.0.479; pion and Chrome read it). The test is
   `chunk::chunk_test::test_init_ack_with_an_unrecognized_parameter`.

Source: the crates.io `sctp-proto` **0.10.8** archive, SHA256
`28aca56f649fa088cbdda778a5121f2227995ed057e77de462112b2e5890d591` (the
workspace lockfile's checksum), without `Cargo.toml.orig`. `XRAY-PATCH.diff`
reconstructs this copy from it with zero fuzz; `scripts/check-vendored-sources.sh`
verifies that and runs the crate's library tests. The workspace uses it
through `[patch.crates-io]`.

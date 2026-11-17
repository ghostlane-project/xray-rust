# is 0.12.0: two changes for the olcRTC engine

`is` is str0m's ICE crate. The olcRTC engine's connectivity checks are
written as a browser's (port plan section 8).

1. Chrome's binding request. `StunProfile::Chrome` (`set_stun_profile`,
   `set_network_info`, `src/stun.rs`) writes USERNAME, GOOG-NETWORK-INFO,
   ICE-CONTROLLING with USE-CANDIDATE (or ICE-CONTROLLED), PRIORITY, as
   libwebrtc does; upstream writes USERNAME, ICE-CONTROLLED/-CONTROLLING,
   PRIORITY, USE-CANDIDATE and never GOOG-NETWORK-INFO. A message is written
   in Chrome's order when it carries GOOG-NETWORK-INFO; the default profile is
   upstream's. Test: `stun::test::chrome_profile_rebuilds_chromes_binding_request`.
2. A relayed candidate ranks by its path to the TURN server.
   `Candidate::relayed_via` (`src/candidate.rs`) records the client's
   transport to the server, and the type preference follows it as libwebrtc's
   does (UDP 2, TCP 1, TLS 0); upstream keys it on the relayed address's
   protocol, which is UDP whatever the path. `Candidate::relayed` is unchanged.

Source: the unchanged-version crates.io `is` **0.12.0** archive, SHA256
`72dd0494853a6c3769c87adc610e8b228fd8c65c41cc4d2717ff6151ee2d6c73`. The
vendored copy keeps `Cargo.toml`, `README.md` and `src/`; the published
lockfile, `Cargo.toml.orig` and `.cargo_vcs_info.json` are left out.
`XRAY-PATCH.diff` reconstructs those three paths from the archive with zero
fuzz. `scripts/check-vendored-sources.sh` verifies the archive, the exact
reconstruction and the crate's library tests from an isolated copy. The
workspace uses it through `[patch.crates-io]`.

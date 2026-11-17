# turn-client-proto 0.8.0: libwebrtc's Allocate requests

turn-client-proto is the olcRTC engine's TURN client (`olc/olc-rtc`). A TURN
server must see Chrome's requests (port plan section 8).

1. The first Allocate carries REQUESTED-TRANSPORT alone: no LIFETIME (the
   server's default stands) and no DONT-FRAGMENT (`src/protocol.rs`,
   `send_initial_request`).
2. The authenticated Allocate carries REQUESTED-TRANSPORT, then the
   signature; no LIFETIME. Both as Chrome 157 sent them to the lab's capture
   server.
3. `Cargo.toml` names no integration test, no bench and none of their
   dev-dependencies: the vendored copy leaves `tests/` and `benches/` out.

Source: the unchanged-version crates.io `turn-client-proto` **0.8.0** archive,
SHA256 `57914c655cc6cc1d6cb6541673b87be69595365a3226b6bfd34dad8af7d779a1`.
The vendored copy keeps `Cargo.toml`, `README.md` and `src/`.
`XRAY-PATCH.diff` reconstructs those three paths from the archive with zero
fuzz. `scripts/check-vendored-sources.sh` verifies the archive and the exact
reconstruction, and runs the library tests on the patched sources under the
published manifest (the published lockfile still names what the vendored
manifest drops). The workspace uses it through `[patch.crates-io]`.

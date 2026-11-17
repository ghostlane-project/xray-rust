# stun-proto 2.0.5: a TURN client's 401 read as libwebrtc reads it

stun-proto is the STUN agent under `turn-client-proto`, the olcRTC engine's
TURN client. A TURN server must see Chrome's requests (port plan section 8).

1. A client reads a 401 as classic long-term credentials whatever its nonce
   says (`CLIENT_READS_NONCE_SECURITY = false`, `src/auth.rs`): the nonce
   cookie of RFC 8489 section 9.2 and PASSWORD-ALGORITHMS are not looked at,
   and the retried request carries MESSAGE-INTEGRITY with the MD5 key and
   echoes neither PASSWORD-ALGORITHMS nor PASSWORD-ALGORITHM. The server's
   side is upstream's.
2. A signed request carries USERNAME, REALM, NONCE in libwebrtc's order
   (`AddRequestAuthInfo`); upstream writes NONCE, REALM, USERNAME.
3. `Cargo.toml` names no example, no bench and no `criterion`: the vendored
   copy leaves `examples/` and `benches/` out.

Source: the unchanged-version crates.io `stun-proto` **2.0.5** archive,
SHA256 `25cbfd0e9a3033f7cb5d9c4eb1155f18b2531f34bd75dae9032f0b77823c4190`.
The vendored copy keeps `Cargo.toml`, `README.md` and `src/`.
`XRAY-PATCH.diff` reconstructs those three paths from the archive with zero
fuzz. `scripts/check-vendored-sources.sh` verifies the archive and the exact
reconstruction, and runs the library tests on the patched sources under the
published manifest (the published lockfile still names what the vendored
manifest drops). Six of upstream's 66 library tests stage a client that reads
the nonce's security bits (`long_term_full_auth_userhash_sha1`, `_userhash_sha256`,
`_uses_sha256`, `long_term_full_auth_flow_server_sha256_mismatch` and the two
`bid_down_attack` tests): they fail with change 1 by design and the script
skips those six by name. The workspace uses it through `[patch.crates-io]`.

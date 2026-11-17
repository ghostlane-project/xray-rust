#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-provenance.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

# Include ignored files here: an upstream .gitignore can hide crate files on
# the developer's filesystem even though a clean checkout will omit them.
untracked="$(git -C "$ROOT" ls-files --others -- vendor/blake3 vendor/h2 vendor/h3 vendor/h3-quinn vendor/quinn vendor/quinn-proto vendor/gotatun vendor/smoltcp olc/vendor/str0m-0.25.0 olc/vendor/is-0.12.0 olc/vendor/stun-proto-2.0.5 olc/vendor/turn-client-proto-0.8.0)"
if [[ -n "$untracked" ]]; then
  echo 'vendored source files are absent from the Git index:' >&2
  printf '%s\n' "$untracked" >&2
  exit 1
fi

download_and_verify() {
  local name="$1"
  local version="$2"
  local expected="$3"
  local archive="$temporary/$name-$version.crate"

  curl --fail --location --silent --show-error \
    --proto '=https' --tlsv1.2 --retry 3 \
    --user-agent 'xray-rust-vendor-provenance/1.0' \
    --output "$archive" \
    "https://static.crates.io/crates/$name/$name-$version.crate"
  echo "$expected  $archive" | sha256sum --check -
  tar -xzf "$archive" -C "$temporary"
}

download_and_verify \
  blake3 1.8.5 \
  0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce
download_and_verify \
  h3-quinn 0.0.10 \
  8b2e732c8d91a74731663ac8479ab505042fbf547b9a207213ab7fbcbfc4f8b4
download_and_verify \
  quinn-proto 0.11.16 \
  2f4bfc015262b9df63c8845072ce59068853ff5872180c2ce2f13038b970e560
download_and_verify \
  quinn 0.11.9 \
  b9e20a958963c291dc322d98411f541009df2ced7b5a4f2bd52337638cfccf20
patch --batch --fuzz=0 -p1 \
  -d "$temporary/quinn-0.11.9" \
  <"$ROOT/vendor/quinn/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/quinn-0.11.9" "$ROOT/vendor/quinn"

patch --batch --fuzz=0 -p1 \
  -d "$temporary/blake3-1.8.5" \
  <"$ROOT/vendor/blake3/XRAY-PATCH.diff"
diff -ruN \
  --exclude XRAY-PATCH.diff \
  --exclude XRAY-PATCH.md \
  "$temporary/blake3-1.8.5" \
  "$ROOT/vendor/blake3"

patch --batch --fuzz=0 -p1 \
  -d "$temporary/h3-quinn-0.0.10" \
  <"$ROOT/vendor/h3-quinn/XRAY-PATCH.diff"
for path in Cargo.toml LICENSE README.md src; do
  diff -ruN \
    "$temporary/h3-quinn-0.0.10/$path" \
    "$ROOT/vendor/h3-quinn/$path"
done

download_and_verify \
  h3 0.0.8 \
  10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be
patch --batch --fuzz=0 -p1 \
  -d "$temporary/h3-0.0.8" \
  <"$ROOT/vendor/h3/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/h3-0.0.8" "$ROOT/vendor/h3"
# The published tests module includes h3-quinn from upstream's repository
# layout, which no release ships; run the crate's other unit tests.
: >"$temporary/h3-0.0.8/src/tests/mod.rs"
cargo test --locked --manifest-path "$temporary/h3-0.0.8/Cargo.toml" --lib

patch --batch --fuzz=0 -p1 \
  -d "$temporary/quinn-proto-0.11.16" \
  <"$ROOT/vendor/quinn-proto/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/quinn-proto-0.11.16" "$ROOT/vendor/quinn-proto"
cargo test --locked --manifest-path "$temporary/quinn-proto-0.11.16/Cargo.toml" \
  --no-default-features --features rustls-ring --lib

# The quinn patch calls quinn-proto's patched `set_stream_receive_window`, so
# quinn is tested against the reconstruction above. Its published lockfile
# pins crates.io quinn-proto 0.11.13: move that entry, and only what 0.11.16
# needs, before the locked test.
quinn_proto_patch="patch.crates-io.quinn-proto.path=\"$temporary/quinn-proto-0.11.16\""
cargo update --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.9/Cargo.toml" \
  -p quinn-proto --precise 0.11.16
cargo test --locked --config "$quinn_proto_patch" \
  --manifest-path "$temporary/quinn-0.11.9/Cargo.toml" \
  --no-default-features --features runtime-tokio,rustls-ring --lib

download_and_verify \
  smoltcp 0.14.0 \
  b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f
patch --batch --fuzz=0 -p1 \
  -d "$temporary/smoltcp-0.14.0" \
  <"$ROOT/vendor/smoltcp/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/smoltcp-0.14.0" "$ROOT/vendor/smoltcp"
cargo test --locked --manifest-path "$temporary/smoltcp-0.14.0/Cargo.toml" \
  --no-default-features --features std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-tcp-reno,socket-udp \
  --lib

download_and_verify \
  h2 0.4.20 \
  7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118
patch --batch --fuzz=0 -p1 \
  -d "$temporary/h2-0.4.20" \
  <"$ROOT/vendor/h2/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/h2-0.4.20" "$ROOT/vendor/h2"
# The published crate omits the HPACK fixture files its fixture tests read.
cargo test --locked --manifest-path "$temporary/h2-0.4.20/Cargo.toml" \
  --lib -- --skip hpack::test::fixture

download_and_verify \
  str0m 0.25.0 \
  357c7e453c033c8bb59e912312f9f9ff07c2a9ce7268bcb94f0c828a5b47e58f
patch --batch --fuzz=0 -p1 \
  -d "$temporary/str0m-0.25.0" \
  <"$ROOT/olc/vendor/str0m-0.25.0/XRAY-PATCH.diff"
diff -ruN --exclude XRAY-PATCH.diff --exclude XRAY-PATCH.md \
  "$temporary/str0m-0.25.0" "$ROOT/olc/vendor/str0m-0.25.0"
# The library and the integration tests that cover what the patches touch:
# NACK, RTX and padding; RED (audio's, and video's as a payload type of its
# own); the Mid and Rid on a stream's packets and the count of the packets a
# stream still holds (both in rtp-direct-mid-rid), SDP negotiation, and the
# close inside SCTP's handshake (dtls-close).
# Upstream's tests reach internals through `_internal_test_exports`, which
# its workspace turns on with a dev-dependency the published crate drops.
cargo test --locked --manifest-path "$temporary/str0m-0.25.0/Cargo.toml" \
  --features _internal_test_exports --lib --test nack --test rtx-cache-0 --test early-rtx-padding --test sdp-rtx-apt \
  --test red --test rtp-direct-mid-rid --test rtp-direct-mid --test simulcast-rid-mapping --test sdp-negotiation \
  --test dtls-close

# str0m's ICE crate, the olcRTC engine's STUN crate and its TURN client
# (olc/vendor): each keeps the published manifest, README and sources and
# leaves the rest of the archive out, so those three paths are compared.
download_and_verify \
  is 0.12.0 \
  72dd0494853a6c3769c87adc610e8b228fd8c65c41cc4d2717ff6151ee2d6c73
patch --batch --fuzz=0 -p1 \
  -d "$temporary/is-0.12.0" \
  <"$ROOT/olc/vendor/is-0.12.0/XRAY-PATCH.diff"
for path in Cargo.toml README.md src; do
  diff -ruN \
    "$temporary/is-0.12.0/$path" \
    "$ROOT/olc/vendor/is-0.12.0/$path"
done
cargo test --locked --manifest-path "$temporary/is-0.12.0/Cargo.toml" --lib

# The vendored manifests of stun-proto and turn-client-proto drop the
# example, benches, integration tests and dev-dependencies the vendored
# copies leave out; the published lockfiles still name those packages. The
# library tests therefore run on the patched sources under the published
# manifest, kept aside before the patch and put back after the comparison.
download_and_verify \
  stun-proto 2.0.5 \
  25cbfd0e9a3033f7cb5d9c4eb1155f18b2531f34bd75dae9032f0b77823c4190
cp "$temporary/stun-proto-2.0.5/Cargo.toml" "$temporary/stun-proto-2.0.5.published.toml"
patch --batch --fuzz=0 -p1 \
  -d "$temporary/stun-proto-2.0.5" \
  <"$ROOT/olc/vendor/stun-proto-2.0.5/XRAY-PATCH.diff"
for path in Cargo.toml README.md src; do
  diff -ruN \
    "$temporary/stun-proto-2.0.5/$path" \
    "$ROOT/olc/vendor/stun-proto-2.0.5/$path"
done
cp "$temporary/stun-proto-2.0.5.published.toml" "$temporary/stun-proto-2.0.5/Cargo.toml"
# Six of upstream's tests stage what the patch turns off, a client that reads
# the nonce's security bits (userhash, SHA-256, the bid-down checks of
# RFC 8489 section 9.2): they fail by design and are the only ones skipped.
cargo test --locked --manifest-path "$temporary/stun-proto-2.0.5/Cargo.toml" --lib -- \
  --skip auth::tests::long_term_full_auth_userhash_sha1 \
  --skip auth::tests::long_term_full_auth_userhash_sha256 \
  --skip auth::tests::long_term_full_auth_uses_sha256 \
  --skip auth::tests::long_term_full_auth_flow_server_sha256_mismatch \
  --skip auth::tests::long_term_full_client_bid_down_attack_remove_password_algorithms_from_server_response \
  --skip auth::tests::long_term_full_server_bid_down_attack_remove_password_algorithms_value_from_server_response

download_and_verify \
  turn-client-proto 0.8.0 \
  57914c655cc6cc1d6cb6541673b87be69595365a3226b6bfd34dad8af7d779a1
cp "$temporary/turn-client-proto-0.8.0/Cargo.toml" "$temporary/turn-client-proto-0.8.0.published.toml"
patch --batch --fuzz=0 -p1 \
  -d "$temporary/turn-client-proto-0.8.0" \
  <"$ROOT/olc/vendor/turn-client-proto-0.8.0/XRAY-PATCH.diff"
for path in Cargo.toml README.md src; do
  diff -ruN \
    "$temporary/turn-client-proto-0.8.0/$path" \
    "$ROOT/olc/vendor/turn-client-proto-0.8.0/$path"
done
cp "$temporary/turn-client-proto-0.8.0.published.toml" "$temporary/turn-client-proto-0.8.0/Cargo.toml"
cargo test --locked --manifest-path "$temporary/turn-client-proto-0.8.0/Cargo.toml" --lib

bash "$ROOT/scripts/check-wireguard-adapter-prototype.sh" --verify-vendor-only

# Vendored crates are path dependencies, so Cargo enforces their own lint
# levels instead of capping them as it does for registry crates. cargo-fuzz
# builds them with `--cfg fuzzing`, which otherwise only the release-gate
# fuzz job compiles.
RUSTFLAGS="--cfg fuzzing" cargo check --locked \
  --manifest-path "$ROOT/Cargo.toml" --target-dir "$temporary/fuzzing-target" \
  -p blake3 -p gotatun -p h2 -p h3 -p h3-quinn -p quinn -p quinn-proto -p smoltcp
echo "verified vendored sources against checksum-pinned archives"

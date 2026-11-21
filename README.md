<p align="center">
  <a href="https://github.com/ghostlane-project/ghostlane"><img src="https://github.com/ghostlane-project/ghostlane/raw/main/androidApp/src/main/res/playstore_icon.png" alt="Ghostlane" width="96"></a>
</p>

<h1 align="center">Ghostlane core</h1>

<p align="center">
  <b>The Rust core of the Ghostlane apps.</b><br>
  One native library for the ordinary proxy protocols and for olcRTC.
</p>

<p align="center">
  <a href="#licence"><img src="https://img.shields.io/badge/license-MPL--2.0-b5f23d?labelColor=07080d" alt="License: MPL-2.0"></a>
  <a href="https://github.com/ghostlane-project/ghostlane"><img src="https://img.shields.io/badge/app-Ghostlane-b5f23d?labelColor=07080d&logo=github&logoColor=white" alt="The app: ghostlane-project/ghostlane"></a>
  <a href="https://opencollective.com/ghostlane"><img src="https://img.shields.io/badge/funding-Open_Collective-b5f23d?labelColor=07080d&logo=opencollective&logoColor=white" alt="Funding: Open Collective"></a>
</p>

## What this is

[Ghostlane](https://github.com/ghostlane-project/ghostlane) is an open-source
VPN client for Android, iOS, macOS, Windows and Linux. This repository is the
core its apps are moving to: one Rust library, `ghostlane-core`, with two
engines inside.

- **A proxy core** for the ordinary protocols: VLESS with REALITY, Vision,
  XHTTP and Mux, VMess AEAD, Trojan, Shadowsocks, Hysteria 2 and WireGuard.
- **An olcRTC client.** olcRTC is the project's transport, a tunnel inside a
  WebRTC video call. Its engine in Go is
  [ghostlane-project/olcrtc](https://github.com/ghostlane-project/olcrtc).

Both run on one Tokio runtime, with one allocator that counts the heap and one
budget for the bytes held in flight, because an iPhone packet tunnel extension
gets about 50 MB. On the app's `main` branch that extension links this library.

## Built on xray-rust

The proxy core is
**[aimalygin/xray-rust](https://github.com/aimalygin/xray-rust)**, under the
MPL-2.0. Its author and contributors wrote the configuration parser, routing
and DNS, the TUN stack, the protocol clients and transports, the C ABI, the
Swift and Kotlin adapters, the fuzz targets and the checks against Xray-core.
What is not listed under [What Ghostlane adds](#what-ghostlane-adds) comes from
that project, and we are grateful for it.

For everything we did not change, upstream is the reference: its
[README](https://github.com/aimalygin/xray-rust#readme) for the protocol
matrix, benchmarks, releases and mobile SDK packages, and its documentation,
kept in [`docs/`](docs) with our additions: [status](docs/status.md),
[configuration compatibility](docs/config-compatibility.md),
[differences from Xray-core](docs/xray-core-differences.md),
[architecture](docs/architecture.md) and [verification](docs/verification.md).

## What Ghostlane adds

| Where | What |
| --- | --- |
| [`olc/`](olc) | The olcRTC client in Rust, ported from the Go engine |
| [`crates/ghostlane-core`](crates/ghostlane-core) | The one library the apps link, with both engines |
| [`crates/ghostlane-runtime`](crates/ghostlane-runtime) | The runtime, counting allocator and byte budget they share |
| [`crates/xray-ffi`](crates/xray-ffi) | A [network reset](docs/ffi.md#network-reset) and a [log callback](docs/ffi.md#runtime-log-abi-119) in the C ABI |
| `crates/xray-core-rs`, `xray-proxy`, `xray-config` | hev-socks5's [`FWD_UDP`](docs/xray-core-differences.md#socks-inbound-fwd_udp-hev-socks5), a [DNS forward rule](docs/config-compatibility.md#dns-outbound), a runtime log that follows the config |
| `crates/xray-transport`, [`vendor/`](vendor) | One byte budget for the payload held in flight, HTTP/2 receive credit inside it |
| [`ghostlane-guards.yml`](.github/workflows/ghostlane-guards.yml) | Memory guards: size lints and release-profile size tests |

Inside `olc/`: the client and its SOCKS5 front, WebRTC on str0m, the wire and
mux crates, one crate per meeting service, the apps' API (`olc-ffi`), patched
dependencies (`olc/vendor`) and an interop suite that runs this client against
the Go engine at a pinned commit (`olc/interop`). The changes to the proxy core
in the table are described under `Unreleased` in the [changelog](CHANGELOG.md).

## Branches

| Branch | What it is |
| --- | --- |
| `main` | A mirror of upstream. We never commit to it |
| `ghostlane` | Upstream plus our changes. The apps build from it, pinned by commit |
| `gl/*` | Topic and lab branches |

## Layout

```text
crates/           xray-* (the proxy core), ghostlane-core, ghostlane-runtime
olc/              the olcRTC client, its vendored crates, its interop suite
platform/         upstream's Swift and Kotlin adapters and sample apps
vendor/           patched third-party crates
tests/  fuzz/     shared fixtures, cargo-fuzz targets
tools/  scripts/  Go oracles; build, interop, benchmark and release checks
docs/   website/  documentation, upstream's website source
```

## Building and testing

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml). These
are commands the workflow files on this branch run:

```sh
# upstream's test suite, .github/workflows/ci.yml
cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked
# Ghostlane's memory guards, .github/workflows/ghostlane-guards.yml
cargo test --release --locked -p xray-core-rs --lib size_tests
cargo test --release --locked -p xray-transport --test size_guards
cargo test --release --locked -p xray-core-rs --test udp_association_memory
# the olcRTC crates, .github/workflows/olc-p2p-lab.yml
cargo test --locked -p olc-rtc -p olc-vp8channel -p olc-kcp -p olc-client -p olc-net
```

The gates under [`olc/interop`](olc/interop) need Go and fetch the Go engine at
its pin. The olcRTC crates' `boring` feature, which the apps' builds turn on,
needs cmake and libclang.

## Using it

The apps link `ghostlane-core`. They call the proxy core through upstream's
C ABI ([`xray_ffi.h`](crates/xray-ffi/include/xray_ffi.h), explained in
[docs/ffi.md](docs/ffi.md)) and the olcRTC client through `OlcrtcRuntime` in
[`olc/olc-ffi`](olc/olc-ffi), a UniFFI API with generated Swift and Kotlin
bindings. The app repository's
[`build-ghostlane-core-ios.sh`](https://github.com/ghostlane-project/ghostlane/blob/main/scripts/build-ghostlane-core-ios.sh)
is a complete build at a pinned commit.

## Status

- In active development, and not a released library: no releases of ours (the
  tags are upstream's) and no crates or packages published from here.
- What works in the Ghostlane apps today is what the
  [app repository](https://github.com/ghostlane-project/ghostlane) says.
- The olcRTC client on this branch reaches three meeting services: Sber
  SaluteJazz, VK Calls and MTS Link.
- No independent security audit: upstream says so of the proxy core in its
  [security policy](SECURITY.md), and none is recorded here for what we added.

## Funding

Ghostlane is free, and nothing in it is sold. The project, this core included,
is funded through **[Open Collective](https://opencollective.com/ghostlane)**.
Open Source Collective holds the funds as fiscal host, and every contribution
and expense is public on the collective's page. The rules are in the app's
[FUNDING.md](https://github.com/ghostlane-project/ghostlane/blob/main/FUNDING.md).

The donation addresses in upstream's README belong to upstream's author, not to
this project. To support that work, see
[upstream's README](https://github.com/aimalygin/xray-rust#support-the-project).

## Help and security

Issues are switched off here. Bugs and questions go to the
[app's tracker](https://github.com/ghostlane-project/ghostlane/issues).
Security problems never go in a public issue: report them privately, as the app's
[SECURITY.md](https://github.com/ghostlane-project/ghostlane/blob/main/SECURITY.md)
describes. [`SECURITY.md`](SECURITY.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md)
in this tree are upstream's own and describe upstream's process.

## Licence

The repository is under the [Mozilla Public License 2.0](LICENSE), as upstream
is. The [`olc/`](olc) directory is under the Apache License 2.0
([`olc/LICENSE`](olc/LICENSE), [`olc/NOTICE`](olc/NOTICE)), as is the olcRTC
engine it is ported from. The crates under [`vendor/`](vendor) and
[`olc/vendor/`](olc/vendor) are third-party code under their own licences,
named in each crate's `Cargo.toml`. Downloaded geodata and other third-party
components remain under their respective licences; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

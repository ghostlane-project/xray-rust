// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The engine's memory for MemoryWatch (plan §9): `memory_stats()` replaces
//! `MobileMemoryStats` and `trim()` replaces `MobileFreeOSMemory` (with the
//! system allocator's relief on Apple and Android targets);
//! `set_byte_budget()` sets the process's byte budget, which the olcRTC
//! client and the xray core share (`design.md` D11's relief).
//!
//! One JSON line, written beside the extension's `phys_footprint` four times
//! a second:
//!
//! ```text
//! {"v":1,"heap":{"live":..,"peak":..,"allocs":..},
//!  "rt":{"workers":1,"threads":2,"tasks":17},
//!  "n":{"runs":1,"conns":3,"parked":0,"flows":2,"direct":0,"dns":0,"streams":3},
//!  "layers":{"socks":[held,cap,budget],...},"budget":12582912,
//!  "bytes":{"cap":3000000,"floor":4096,"held":..,"peak":..,"windows":..}}
//! ```
//!
//! `heap` is the counting allocator's (null when it is not installed),
//! `rt` the shared runtime's. Each layer is `[held, cap, budget]` in bytes:
//! what it holds now, the hard bound in code (`olc_client::sizes`), and §9's
//! budget for it. A layer this build does not have yet (KCP, the VP8
//! channel, RTP, str0m, SCTP, signalling: M4 and M5) holds null.
//!
//! `bytes` is the process's byte budget (`ghostlane_runtime::memory_budget`):
//! `cap` is `B`, the payload bytes in flight that the client's copies and
//! UDP and the xray core's relays and HTTP/2 windows may take beyond their
//! floors together, `floor` what each holder keeps outside `B`, `held` what
//! is taken now, `peak` the most since the process began, `windows` the
//! HTTP/2 windows' part of `held`. The socks and udp layers' caps are on
//! the budget as it is now (`olc_client::sizes::budget`).

use ghostlane_runtime::ByteBudgetSettings;
use serde_json::{json, Value};

const MIB: f64 = 1024.0 * 1024.0;

/// §9's budget for a layer, bytes.
fn budget(mib: f64) -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let b = (mib * MIB) as u64;
    b
}

/// The engine's budget (§9: at or below 12 MiB).
pub const ENGINE_BUDGET: u64 = 12 * 1024 * 1024;

/// The layers this build does not carry yet, with §9's budget.
const NOT_YET: &[(&str, f64)] = &[
    ("kcp", 1.5),
    ("vp8", 2.0),
    ("rtp", 1.0),
    ("str0m", 1.0),
    ("sctp", 2.5),
    ("signalling", 1.0),
];

fn code_cap(rows: &[olc_client::sizes::Row], prefixes: &[&str]) -> Option<usize> {
    let caps: Vec<usize> = prefixes
        .iter()
        .filter_map(|p| rows.iter().find(|r| r.layer.starts_with(p)).map(|r| r.cap))
        .collect();
    (caps.len() == prefixes.len()).then(|| caps.iter().sum())
}

/// `MemoryStats`: the heap, the runtime and every layer, one JSON line.
#[uniffi::export]
#[must_use]
pub fn memory_stats() -> String {
    stats().to_string()
}

/// The reading as a value (the tests read it).
#[must_use]
pub fn stats() -> Value {
    let g = olc_client::gauges::snapshot();
    let rows = olc_client::sizes::budget();
    let bytes = ghostlane_runtime::byte_budget_usage();
    let heap = ghostlane_runtime::alloc::heap().map_or(
        Value::Null,
        |h| json!({"live": h.live, "peak": h.peak, "allocs": h.allocs}),
    );
    let rt = json!({
        "workers": ghostlane_runtime::runtime::built().map(|p| p.workers),
        "threads": ghostlane_runtime::runtime::threads(),
        "tasks": ghostlane_runtime::runtime::alive_tasks(),
    });
    let mut layers = serde_json::Map::new();
    let mut put = |name: &str, held: Option<usize>, cap: Option<usize>, mib: f64| {
        layers.insert(name.to_owned(), json!([held, cap, budget(mib)]));
    };
    put(
        "socks",
        Some(g.copy_bytes),
        code_cap(&rows, &["SOCKS front"]),
        3.0,
    );
    put(
        "udp",
        Some(g.udp_bytes()),
        code_cap(&rows, &["UDP flow table", "FWD_UDP"]),
        0.5,
    );
    put(
        "smux_rx",
        Some(g.smux_rx),
        code_cap(&rows, &["smux session receive"]),
        4.0,
    );
    put("smux_tx", Some(g.smux_tx), None, 2.0);
    put(
        "mux_in",
        Some(g.lane_rx),
        code_cap(&rows, &["data lane inbound"]),
        1.0,
    );
    for (name, mib) in NOT_YET {
        put(name, None, None, *mib);
    }
    // The engine writes each line straight to the host's writer.
    put("logs", Some(0), Some(0), 0.2);
    json!({
        "v": 1,
        "heap": heap,
        "rt": rt,
        "n": {
            "runs": g.runs,
            "conns": g.socks_conns,
            "parked": g.parked,
            "flows": g.udp_flows,
            "direct": g.direct_flows,
            "dns": g.dns_in_flight,
            "streams": g.smux_streams,
            "smux_pool": g.smux_pool,
        },
        "layers": layers,
        "budget": ENGINE_BUDGET,
        "bytes": {
            "cap": bytes.capacity,
            "floor": bytes.floor,
            "held": bytes.in_use,
            "peak": bytes.peak,
            "windows": bytes.window_bytes,
        },
    })
}

/// Sets the process's byte budget `B`: the payload bytes in flight that the
/// olcRTC client's copies and UDP and the xray core's relays and HTTP/2
/// windows take, beyond each holder's floor, together. `0` returns it to
/// the formula for the host's memory class (3,000,000 bytes on a phone,
/// 15,000,000 elsewhere); the floor stays what it is.
///
/// The extension's relief (`design.md` D11) lowers it under memory pressure,
/// beside `trim()`, and sets `0` again once the pressure has passed. A lower
/// budget takes effect as held bytes come back: nothing held is revoked, and
/// no connection is refused for it: each reads less, down to its floor.
#[uniffi::export]
pub fn set_byte_budget(bytes: u64) {
    let settings = (bytes != 0).then(|| ByteBudgetSettings {
        capacity: usize::try_from(bytes).unwrap_or(usize::MAX),
        floor: ghostlane_runtime::byte_budget().floor,
    });
    ghostlane_runtime::set_byte_budget(settings);
}

/// `FreeOSMemory`: drops what the engine keeps for reuse (its pools) and,
/// on Apple and Android targets, asks the system allocator for its free
/// pages back (`malloc_zone_pressure_relief(NULL, 0)`; bionic's
/// `mallopt(M_PURGE_ALL, 0)`, else `M_PURGE`): the relief MemoryWatch asks
/// for above its threshold (`design.md` D11), in the core, so the app needs
/// no call of its own. Returns the bytes given back: the pools' bytes, or
/// the fall of the footprint (`phys_footprint`; Android's `RssAnon`) across
/// the pools and the relief when that is more (`ghostlane_runtime::relief`).
/// Elsewhere the allocator is not asked, and it returns the pools' bytes.
#[uniffi::export]
pub fn trim() -> u64 {
    u64::try_from(ghostlane_runtime::relief::trim(olc_client::gauges::trim)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_names_every_layer_of_the_budget() {
        let s = stats();
        let layers = s["layers"].as_object().unwrap();
        for name in [
            "socks",
            "udp",
            "smux_rx",
            "smux_tx",
            "mux_in",
            "kcp",
            "vp8",
            "rtp",
            "str0m",
            "sctp",
            "signalling",
            "logs",
        ] {
            let l = layers[name].as_array().unwrap();
            assert_eq!(l.len(), 3, "{name}");
            assert!(l[2].as_u64().unwrap() > 0, "{name} has a budget");
        }
        assert!(layers["socks"][1].as_u64().is_some(), "a code cap");
        assert_eq!(layers["smux_rx"][2].as_u64(), Some(4 << 20), "§9's 4 MiB");
        assert!(layers["kcp"][0].is_null(), "not in this build");
        let line = memory_stats();
        assert!(!line.contains('\n') && line.len() < 1024, "{line}");
    }

    #[test]
    fn set_byte_budget_sets_the_process_budget_and_zero_restores_the_formula() {
        let formula = ByteBudgetSettings::for_class(ghostlane_runtime::memory_class());
        set_byte_budget(1_000_000);
        let s = stats();
        set_byte_budget(0);
        assert_eq!(s["bytes"]["cap"].as_u64(), Some(1_000_000), "{s}");
        assert_eq!(s["bytes"]["floor"].as_u64(), Some(formula.floor as u64));
        // The socks layer's cap is on the budget set: B, the floors of 512
        // connections both ways, and the pool's kept buffers.
        let socks = 1_000_000
            + olc_client::socks::MAX_SOCKS_CONNS * 2 * formula.floor
            + olc_client::copy::POOL_KEEP * olc_client::copy::COPY_BUFFER;
        assert_eq!(s["layers"]["socks"][1].as_u64(), Some(socks as u64), "{s}");
        let s = stats();
        assert_eq!(
            s["bytes"]["cap"].as_u64(),
            Some(formula.capacity as u64),
            "{s}"
        );
        assert!(memory_stats().len() < 1024);
    }
}

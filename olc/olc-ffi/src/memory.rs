// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The engine's memory for MemoryWatch (plan §9): `memory_stats()` replaces
//! `MobileMemoryStats` and `trim()` replaces `MobileFreeOSMemory`.
//!
//! One JSON line, written beside the extension's `phys_footprint` four times
//! a second:
//!
//! ```text
//! {"v":1,"heap":{"live":..,"peak":..,"allocs":..},
//!  "rt":{"workers":1,"threads":2,"tasks":17},
//!  "n":{"runs":1,"conns":3,"parked":0,"flows":2,"direct":0,"dns":0,"streams":3},
//!  "layers":{"socks":[held,cap,budget],...},"budget":12582912}
//! ```
//!
//! `heap` is the counting allocator's (null when it is not installed),
//! `rt` the shared runtime's. Each layer is `[held, cap, budget]` in bytes:
//! what it holds now, the hard bound in code (`olc_client::sizes`), and §9's
//! budget for it. A layer this build does not have yet (KCP, the VP8
//! channel, RTP, str0m, SCTP, signalling: M4 and M5) holds null.

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
    })
}

/// `FreeOSMemory`: drops what the engine keeps for reuse (its pools), the
/// relief MemoryWatch asks for above its threshold (`design.md` D11).
/// Returns the bytes given back.
#[uniffi::export]
pub fn trim() -> u64 {
    u64::try_from(olc_client::gauges::trim()).unwrap_or(u64::MAX)
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
}

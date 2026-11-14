// Copyright 2026 The Ghostlane Project contributors.
// SPDX-License-Identifier: Apache-2.0

//! The Go engine's KCP at the pin, as golden vectors (olc/interop/vectors):
//!
//! - `vp8/kcp-settings.json` (W32): what `startKCP` leaves in kcp-go for the
//!   server, paced-server and phone profiles;
//! - `vp8/kcp.json` (W31, W33): the packets the engine's KCP writes for a
//!   fixed script and what a phone-profile receiver answers, ts masked.

use std::time::{Duration, Instant};

use olc_interop::{load, pattern, sha256_hex};
use olc_kcp::{message, Config, Session};
use serde_json::Value;

const CONV: u32 = 0xC0FF_EE01;

fn assert_settings(name: &str, want: &Value, s: &Session) {
    let want = want.as_object().expect("an object of settings");
    let got = s.settings();
    for (k, v) in &got {
        assert_eq!(
            want.get(*k).and_then(Value::as_i64),
            Some(*v),
            "{name}: {k} is {v} here"
        );
    }
    assert_eq!(
        want.len(),
        got.len(),
        "{name}: Go reports {:?}",
        want.keys().collect::<Vec<_>>()
    );
}

#[test]
fn settings_are_start_kcps_for_each_profile() {
    let v = load("vp8/kcp-settings.json");
    let now = Instant::now();
    for (name, cfg) in [
        ("server", Config::vp8channel(4096, 4096)),
        ("server_paced", Config::vp8channel(512, 4096)),
        ("phone", Config::vp8channel_constrained()),
    ] {
        assert_settings(name, &v[name], &Session::new(cfg, now));
    }
}

/// A KCP packet with every segment's ts zeroed, and its line: `cmd frg wnd
/// sn una len` per segment, `;` between them (as the generator writes it).
fn mask(p: &[u8]) -> (Vec<u8>, String) {
    let mut m = p.to_vec();
    let mut segs = Vec::new();
    let mut off = 0;
    while off < m.len() {
        assert!(m.len() - off >= 24, "{} stray bytes", m.len() - off);
        let h = &mut m[off..];
        let u32le = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
        assert_eq!(u32le(&h[0..4]), CONV);
        let (cmd, frg) = (h[4], h[5]);
        let wnd = u16::from_le_bytes([h[6], h[7]]);
        let sn = u32le(&h[12..16]);
        let una = u32le(&h[16..20]);
        let n = u32le(&h[20..24]) as usize;
        h[8..12].fill(0);
        segs.push(format!("{cmd} {frg} {wnd} {sn} {una} {n}"));
        off += 24 + n;
        assert!(off <= m.len(), "a segment past its packet");
    }
    (m, segs.join(";"))
}

fn describe(pkts: &[Vec<u8>]) -> (Vec<String>, String) {
    let mut lines = Vec::new();
    let mut all = Vec::new();
    for p in pkts {
        let (m, line) = mask(p);
        lines.push(line);
        all.extend_from_slice(&(m.len() as u32).to_be_bytes());
        all.extend_from_slice(&m);
    }
    (lines, sha256_hex(&all))
}

/// The two sessions pumped to each other at once, as the generator's pumps
/// do; what each wrote is recorded.
struct Pair {
    a: Session,
    b: Session,
    now: Instant,
    rec_a: Vec<Vec<u8>>,
    rec_b: Vec<Vec<u8>>,
}

impl Pair {
    fn pump(&mut self) {
        loop {
            let mut moved = false;
            while let Some(p) = self.a.peek_output() {
                let p = p.to_vec();
                self.a.pop_output();
                self.b.input(&p, self.now);
                self.rec_a.push(p);
                moved = true;
            }
            while let Some(p) = self.b.peek_output() {
                let p = p.to_vec();
                self.b.pop_output();
                self.a.input(&p, self.now);
                self.rec_b.push(p);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    /// `d` of virtual time, both sessions' timers ticking every 10 ms (the
    /// interval), packets moving at once.
    fn settle(&mut self, d: Duration) {
        let end = self.now + d;
        while self.now < end {
            self.now += Duration::from_millis(10);
            self.a.update(self.now);
            self.pump();
            self.b.update(self.now);
            self.pump();
        }
    }
}

#[test]
fn the_engines_segments_and_a_phones_answers() {
    let v = load("vp8/kcp.json");
    let start = Instant::now();
    let mut pair = Pair {
        a: Session::new(Config::vp8channel(4096, 4096), start),
        b: Session::new(Config::vp8channel_constrained(), start),
        now: start,
        rec_a: Vec::new(),
        rec_b: Vec::new(),
    };
    let mut first: Option<Vec<u8>> = None;
    let steps = v["steps"].as_array().expect("steps");
    assert_eq!(steps.len(), 6);
    for step in steps {
        let name = step["name"].as_str().unwrap();
        if let Some(msg) = step.get("message") {
            let len = msg["len"].as_u64().unwrap() as usize;
            let seed = msg["seed"].as_u64().unwrap() as u8;
            message::send(&mut pair.a, &pattern(len, seed), pair.now).expect("send");
        } else if step.get("duplicate_of").is_some() {
            let p = first.clone().expect("the first packet");
            pair.b.input(&p, pair.now);
        }
        pair.pump();
        let wait = step.get("wait_ms").and_then(Value::as_u64).unwrap_or(120);
        pair.settle(Duration::from_millis(wait));
        let (pa, pb) = (
            std::mem::take(&mut pair.rec_a),
            std::mem::take(&mut pair.rec_b),
        );
        if name == "hello" {
            first = Some(pa[0].clone());
        }
        for (side, pkts) in [("a", &pa), ("b", &pb)] {
            let (lines, sum) = describe(pkts);
            let want: Vec<String> = step[side]["packets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap().to_string())
                .collect();
            assert_eq!(lines.len(), want.len(), "{name}/{side}: packet count");
            for (i, (g, w)) in lines.iter().zip(&want).enumerate() {
                assert_eq!(g, w, "{name}/{side}: packet {i}");
            }
            assert_eq!(
                sum,
                step[side]["masked_sha256"].as_str().unwrap(),
                "{name}/{side}: bytes"
            );
        }
    }
    // B was never read: everything A sent is in its queue, in order.
    let mut got = Vec::new();
    let mut r = message::Reader::new();
    while let Some(m) = r.next(&mut pair.b).expect("a sane length") {
        got.push(m.len());
    }
    assert_eq!(
        got,
        [5, 3000, 40000, 477 * 1376 - 4],
        "empty messages are skipped"
    );
}

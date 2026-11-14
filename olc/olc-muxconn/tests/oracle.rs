//! olc-muxconn against the Go engine's own muxconn at the pin: records the
//! Rust lanes seal are pushed into a Go `muxconn.Conn`, which must read back
//! the same byte stream and count the same payload and failures as the Rust
//! receiver does; Go's records are read by the Rust receiver. Skips, saying
//! so, without `OLC_GO_ORACLE`.

use std::sync::Arc;
use std::time::Duration;

use olc_interop::{hex, unhex, Oracle, Rng};
use olc_muxconn::conn::inbound_capacity;
use olc_muxconn::scan::{opened_streams, stream_payload_len};
use olc_muxconn::{Append, Batcher, Features, Push, Receiver, Sender};
use olc_wire::record::{KeySet, Lane, Role};
use serde_json::{json, Value};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a u64: {v}"))
}

/// A smux v2 frame: header and body.
fn frame(cmd: u8, sid: u32, body: &[u8]) -> Vec<u8> {
    let mut f = vec![2, cmd];
    f.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
    f.extend_from_slice(&sid.to_le_bytes());
    f.extend_from_slice(body);
    f
}

/// The frames a session might write: a SYN, data, window updates, NOPs, FINs.
fn session_frames(rng: &mut Rng, n: usize, max_frame: usize) -> Vec<Vec<u8>> {
    let mut out = vec![frame(0, 3, &[])];
    for _ in 0..n {
        let sid = [3u32, 5, 7][rng.below(3)];
        let f = match rng.below(10) {
            0 => frame(0, sid, &[]),
            1 => frame(4, sid, &rng.bytes(8)),
            2 => frame(3, 0, &[]),
            3 => frame(1, sid, &[]),
            4 => frame(2, sid, &rng.bytes(max_frame - 8)),
            _ => frame(2, sid, &rng.bytes_below(600)),
        };
        out.push(f);
    }
    out
}

#[test]
fn records_scan_as_go_scans_them() {
    let Some(mut o) = Oracle::from_env("records_scan_as_go_scans_them") else {
        return;
    };
    let mut rng = Rng::new(11);
    for i in 0..2000 {
        let mut record = Vec::new();
        for _ in 0..rng.below(5) {
            let version = [2u8, 2, 2, 1, 0, 3][rng.below(6)];
            let cmd = [0u8, 1, 2, 2, 3, 4, 9][rng.below(7)];
            let sid = [0u32, 1, 3, 3, 5, u32::MAX][rng.below(6)];
            let body = rng.bytes_below(20);
            let declared = match rng.below(4) {
                0 => rng.below(65536),
                1 => body.len() + rng.below(3),
                _ => body.len(),
            };
            record.push(version);
            record.push(cmd);
            record.extend_from_slice(&u16::try_from(declared).unwrap().to_le_bytes());
            record.extend_from_slice(&sid.to_le_bytes());
            record.extend_from_slice(&body);
        }
        if rng.below(5) == 0 {
            record.truncate(rng.below(record.len() + 1));
        }
        let go = o.call(&json!({"op": "smux_scan", "data": hex(&record)}));
        let (first, opens) = opened_streams(&record);
        assert_eq!(
            stream_payload_len(&record),
            u(&go["payload_len"]),
            "#{i}: {}",
            hex(&record)
        );
        assert_eq!(
            first,
            go["first"].as_bool().unwrap(),
            "#{i}: {}",
            hex(&record)
        );
        assert_eq!(
            opens,
            go["opens"].as_bool().unwrap(),
            "#{i}: {}",
            hex(&record)
        );
    }
}

/// Seals `frames` as a Rust client would on `features`: a record per frame,
/// or batches when the link batches.
fn seal(keys: &Arc<KeySet>, lane: Lane, features: &Features, frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    match Batcher::new(features, features.max_frame()) {
        None => {
            let mut tx = Sender::new(Arc::clone(keys), lane, features.max_frame());
            for f in frames {
                records.push(tx.seal(f).unwrap().to_vec());
            }
        }
        Some(mut b) => {
            let flush = |b: &mut Batcher, records: &mut Vec<Vec<u8>>| {
                if let Some(mut batch) = b.take() {
                    records.push(batch.seal(keys, lane).unwrap().to_vec());
                    b.done(batch);
                }
            };
            for f in frames {
                loop {
                    match b.append(f).unwrap() {
                        Append::Queued => break,
                        Append::Due(n) => {
                            flush(&mut b, &mut records);
                            assert!(b.sent() >= n);
                            break;
                        }
                        Append::Full => flush(&mut b, &mut records),
                    }
                }
            }
            flush(&mut b, &mut records);
        }
    }
    records
}

#[test]
fn rust_lanes_feed_a_go_conn() {
    let Some(mut o) = Oracle::from_env("rust_lanes_feed_a_go_conn") else {
        return;
    };
    let mut rng = Rng::new(12);
    let psk = rng.bytes(32);
    let stranger = rng.bytes(32);
    let links = [
        (
            "datachannel",
            Features {
                max_payload_size: 12288,
                write_interval: Duration::from_millis(5),
            },
        ),
        (
            "vp8channel",
            Features {
                max_payload_size: 61440,
                write_interval: Duration::ZERO,
            },
        ),
        ("unlimited", Features::default()),
    ];
    for (name, features) in links {
        let r =
            o.call(&json!({"op": "keyset", "id": name, "key_hex": hex(&psk), "role": "server"}));
        assert_eq!(r["verdict"], "ok");
        let client = Arc::new(KeySet::new(&psk, Role::Client).unwrap());
        let other = Arc::new(KeySet::new(&stranger, Role::Client).unwrap());
        for lane in [Lane::Data, Lane::Control] {
            let max = i64::try_from(features.max_payload_size).unwrap();
            o.call(&json!({"op": "muxconn_new", "id": name, "lane": lane.name(), "keys": name, "max": max}));
            let server = Arc::new(KeySet::new(&psk, Role::Server).unwrap());
            let plaintext_cap = features.max_record_plaintext();
            let mut rx = Receiver::new(server, lane, inbound_capacity(plaintext_cap));
            let frames = session_frames(&mut rng, 300, features.max_frame());
            let mut records = seal(&client, lane, &features, &frames);
            if features.write_interval > Duration::ZERO {
                assert!(
                    records.len() < frames.len(),
                    "{name}: small frames share records"
                );
            }
            // What arrives besides: junk, another key's records, a replay,
            // and a record of the other lane.
            // The replay is of a record the receivers have seen by then, so
            // the stream keeps its order.
            let replay = records[5].clone();
            let wrong_key = Sender::new(Arc::clone(&other), lane, 64)
                .seal(b"x")
                .unwrap()
                .to_vec();
            let other_lane = if lane == Lane::Data {
                Lane::Control
            } else {
                Lane::Data
            };
            let crossed = Sender::new(Arc::clone(&client), other_lane, 64)
                .seal(&frame(3, 0, &[]))
                .unwrap()
                .to_vec();
            for (at, extra) in [
                (10, rng.bytes(30)),
                (
                    20,
                    b"OLC1 and then some bytes, enough for a header".to_vec(),
                ),
                (30, wrong_key),
                (40, replay),
                (50, crossed),
            ] {
                records.insert(at.min(records.len()), extra);
            }
            let mut stream = Vec::new();
            let mut buf = vec![0; 4096];
            for record in &records {
                let mut copy = record.clone();
                loop {
                    match rx.push(&mut copy) {
                        Push::Busy => {
                            let n = rx.read(&mut buf);
                            stream.extend_from_slice(&buf[..n]);
                        }
                        Push::Oversized(n) => panic!("{name}: a record of {n} bytes did not fit"),
                        _ => break,
                    }
                }
            }
            loop {
                let n = rx.read(&mut buf);
                if n == 0 {
                    break;
                }
                stream.extend_from_slice(&buf[..n]);
            }
            assert_eq!(
                stream,
                frames.concat(),
                "{name} {}: the Rust receiver reads the frames back",
                lane.name()
            );
            let hexes: Vec<String> = records.iter().map(|r| hex(r.as_slice())).collect();
            let go = o.call(
                &json!({"op": "muxconn_push", "id": name, "lane": lane.name(), "records": hexes}),
            );
            let what = format!("{name} {}", lane.name());
            assert_eq!(
                unhex(s(&go["stream"])),
                stream,
                "{what}: Go reads the same stream"
            );
            let stats = rx.stats();
            assert_eq!(u(&go["inbound_bytes"]), stats.inbound_bytes(), "{what}");
            assert_eq!(u(&go["payload_bytes"]), stats.payload_bytes(), "{what}");
            assert_eq!(
                u(&go["bad_magic"]),
                stats.decrypt_stats().bad_magic,
                "{what}"
            );
            assert_eq!(
                u(&go["auth_failed"]),
                stats.decrypt_stats().auth_failed,
                "{what}"
            );
            assert_eq!(stats.decrypt_stats().bad_magic, 2, "{what}");
            assert_eq!(
                stats.decrypt_stats().auth_failed,
                2,
                "{what}: another key, another lane"
            );
            assert_eq!(stats.decrypt_fails(), 5, "{what}: and the replay");
            let reorder = rx.reorder_stats();
            assert_eq!(
                (u(&go["skipped"]), u(&go["late"])),
                (reorder.skipped, reorder.late),
                "{what}"
            );
            for r in &records {
                assert!(
                    r.len() <= features.max_payload_size.max(32820),
                    "{what}: a record fits one message"
                );
            }
        }
    }
}

#[test]
fn go_records_feed_the_rust_receiver() {
    let Some(mut o) = Oracle::from_env("go_records_feed_the_rust_receiver") else {
        return;
    };
    let mut rng = Rng::new(13);
    let psk = rng.bytes(32);
    let r =
        o.call(&json!({"op": "keyset", "id": "go-client", "key_hex": hex(&psk), "role": "client"}));
    assert_eq!(r["verdict"], "ok");
    let features = Features {
        max_payload_size: 12288,
        write_interval: Duration::from_millis(5),
    };
    let server = Arc::new(KeySet::new(&psk, Role::Server).unwrap());
    let mut rx = Receiver::new(
        server,
        Lane::Data,
        inbound_capacity(features.max_record_plaintext()),
    );
    let frames = session_frames(&mut rng, 200, features.max_frame());
    let mut stream = Vec::new();
    let mut buf = vec![0; 1 << 16];
    let mut payload = 0;
    for f in &frames {
        let go = o.call(&json!({"op": "seal", "id": "go-client", "lane": "data", "data": hex(f)}));
        let mut record = unhex(s(&go["record"]));
        assert_eq!(rx.push(&mut record), Push::Taken(f.len()));
        payload += stream_payload_len(f);
        let n = rx.read(&mut buf);
        stream.extend_from_slice(&buf[..n]);
    }
    assert_eq!(stream, frames.concat());
    assert_eq!(rx.stats().payload_bytes(), payload);
}

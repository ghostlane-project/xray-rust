//! The muxconn vectors of the Go engine at the pin, checked against
//! olc-muxconn: what a record says about smux streams (W19's scan), and when
//! frames share a record (W19's batching).

use std::time::Duration;

use olc_interop::{load, pattern, unhex};
use olc_muxconn::batch::{batch_limit, Append, Batch, Batcher};
use olc_muxconn::scan::{self, opened_streams, stream_payload_len};
use olc_muxconn::Features;
use olc_wire::record::Lane;
use serde_json::Value;

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a u64: {v}"))
}

fn features(max_payload: &Value, interval_us: &Value) -> Features {
    // Go's negative values mean what zero means.
    Features {
        max_payload_size: usize::try_from(max_payload.as_i64().unwrap().max(0)).unwrap(),
        write_interval: Duration::from_micros(
            u64::try_from(interval_us.as_i64().unwrap().max(0)).unwrap(),
        ),
    }
}

#[test]
fn w19_constants() {
    let k = &load("muxconn.json")["constants"];
    assert_eq!(k["data_aad"].as_str().unwrap().as_bytes(), Lane::Data.aad());
    assert_eq!(
        k["control_aad"].as_str().unwrap().as_bytes(),
        Lane::Control.aad()
    );
    assert_eq!(u(&k["inbound_queue"]), olc_muxconn::INBOUND_QUEUE as u64);
    assert_eq!(
        u(&k["pooled_frame_cap"]),
        olc_muxconn::POOLED_FRAME_CAP as u64
    );
    assert_eq!(
        Duration::from_millis(u(&k["write_ready_timeout_ms"])),
        olc_muxconn::WRITE_READY_TIMEOUT
    );
    assert_eq!(
        Duration::from_millis(u(&k["decrypt_log_interval_ms"])),
        olc_muxconn::DECRYPT_LOG_INTERVAL
    );
    assert_eq!(u(&k["smux_header_size"]), scan::SMUX_HEADER_SIZE as u64);
    assert_eq!(u(&k["smux_cmd_syn"]), u64::from(scan::SMUX_CMD_SYN));
    assert_eq!(u(&k["smux_cmd_psh"]), u64::from(scan::SMUX_CMD_PSH));
    assert_eq!(
        u(&k["smux_first_stream"]),
        u64::from(scan::SMUX_FIRST_STREAM)
    );
}

#[test]
fn w19_what_a_record_says_about_streams() {
    for case in load("muxconn.json")["scan"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let record = unhex(case["record"].as_str().unwrap());
        assert_eq!(
            stream_payload_len(&record),
            u(&case["payload_len"]),
            "{name}"
        );
        let (first, opens) = opened_streams(&record);
        assert_eq!(first, case["first"].as_bool().unwrap(), "{name}");
        assert_eq!(opens, case["opens"].as_bool().unwrap(), "{name}");
    }
}

#[test]
fn w19_when_a_link_batches() {
    for case in load("muxconn.json")["batch_limits"].as_array().unwrap() {
        let f = features(&case["max_payload"], &case["write_interval_us"]);
        let limit = batch_limit(&f);
        assert_eq!(
            limit.is_some(),
            case["batches"].as_bool().unwrap(),
            "{case}"
        );
        assert_eq!(limit.unwrap_or(0) as u64, u(&case["limit"]), "{case}");
        assert_eq!(Batcher::new(&f, f.max_frame()).is_some(), limit.is_some());
    }
}

#[test]
fn w19_which_frames_share_a_record() {
    for seq in load("muxconn.json")["batch_sequences"].as_array().unwrap() {
        let name = seq["name"].as_str().unwrap();
        let f = Features {
            max_payload_size: usize::try_from(u(&seq["max_payload"])).unwrap(),
            write_interval: Duration::from_millis(5),
        };
        let steps = seq["steps"].as_array().unwrap();
        let largest = steps
            .iter()
            .filter_map(|s| s.get("len"))
            .map(u)
            .max()
            .unwrap_or(0);
        let mut b = Batcher::new(&f, usize::try_from(largest).unwrap()).unwrap();
        assert_eq!(b.limit() as u64, u(&seq["limit"]), "{name}");
        let mut out: Option<Batch> = None;
        for (i, step) in steps.iter().enumerate() {
            let (mut queued, mut batch, mut taken) = (false, 0, 0);
            match step["op"].as_str().unwrap() {
                "append" => {
                    let len = usize::try_from(u(&step["len"])).unwrap();
                    match b.append(&pattern(len, i as u8)).unwrap() {
                        Append::Queued => queued = true,
                        Append::Due(n) => (queued, batch) = (true, n),
                        Append::Full => {}
                    }
                }
                "take" => {
                    assert!(out.is_none(), "{name} step {i}: one batch out at a time");
                    out = b.take();
                    taken = out.as_ref().map_or(0, |o| o.frames().len());
                }
                "done" => b.done(out.take().expect("a batch to hand back")),
                other => panic!("unknown op {other}"),
            }
            assert_eq!(queued, step["queued"].as_bool().unwrap(), "{name} step {i}");
            assert_eq!(batch, u(&step["batch"]), "{name} step {i}");
            assert_eq!(taken as u64, u(&step["taken"]), "{name} step {i}");
            assert_eq!(
                b.due(),
                step["due_after"].as_bool().unwrap(),
                "{name} step {i}"
            );
            assert_eq!(
                b.pending_len() as u64,
                u(&step["pending_len"]),
                "{name} step {i}"
            );
        }
    }
}

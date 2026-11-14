//! The core on the process's one runtime (`shared-runtime`, as
//! ghostlane-core builds it): its handle no longer owns the runtime, so a
//! stop and a free must leave none of its tasks behind on it, and two cores
//! run on the same threads.
#![cfg(feature = "shared-runtime")]

use std::ffi::CString;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_core_start, xray_core_stop,
    XrayStatus,
};

const FREEDOM: &str = r#"{
  "inbounds": [{ "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
                 "settings": { "udp": false } }],
  "outbounds": [{ "tag": "direct", "protocol": "freedom" }]
}"#;

fn started() -> *mut xray_ffi::XrayCoreHandle {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    let raw = CString::new(FREEDOM).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);
    core
}

fn settle(want: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = ghostlane_runtime::runtime::alive_tasks().unwrap();
        if now <= want || Instant::now() >= deadline {
            return now;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cores_on_the_shared_runtime_leave_no_task_behind() {
    let workers = ghostlane_runtime::Profile::host().workers;
    let first = started();
    let second = started();
    let rt = ghostlane_runtime::handle().unwrap();
    assert_eq!(rt.metrics().num_workers(), workers, "one runtime for both");
    let mut err = std::ptr::null_mut();
    for core in [first, second] {
        assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
        unsafe { xray_core_free(core) };
    }
    let baseline = settle(0);
    for round in 0..20 {
        let core = started();
        assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
        unsafe { xray_core_free(core) };
        let left = settle(baseline);
        assert!(
            left <= baseline,
            "round {round}: {left} tasks alive, {baseline} before"
        );
    }
    assert!(
        ghostlane_runtime::runtime::threads() <= workers + ghostlane_runtime::runtime::MAX_BLOCKING,
        "{} threads",
        ghostlane_runtime::runtime::threads()
    );
}

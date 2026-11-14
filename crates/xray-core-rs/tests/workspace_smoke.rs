// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
#[test]
fn workspace_exports_version() {
    assert_eq!(xray_core_rs::version(), env!("CARGO_PKG_VERSION"));
}

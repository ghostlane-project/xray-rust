// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&xray_config::tooling::configuration_contract()).unwrap()
    );
}

//! In-process loopback: two str0m peers, one data channel, an echo.
//!
//!   loopback --dtls boring --version auto --bytes 4194304
//!
//! Prints `HANDSHAKE <json>` per DTLS handshake (BoringSSL only), `DTLS_CH_TX loop <hex>` for
//! the ClientHello records, `MEM <phase> <json>`, and `RESULT <json>`; exits 0 on an echo.

use std::time::Duration;

use olc_spike_probe::util::{hex, Args};
use olc_spike_probe::{crypto, loopback, mem};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("FAIL: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<(), String> {
    let args = Args::from_env();
    let dtls = args.or("dtls", "dimpl");
    let version = args.or("version", "auto");
    let bytes = args.num("bytes", 4 << 20)?;
    let chunk = args.num("chunk", 16 * 1024)?;
    mem::report("start");
    mem::reset_peak();
    let provider = crypto::provider(&dtls)?;
    let r = loopback::run(&provider, crypto::version(&version)?, bytes, chunk, Duration::from_secs(20))?;
    let m = mem::report("after-echo");
    for h in crypto::handshakes_json() {
        eprintln!("HANDSHAKE {h}");
    }
    for b in &r.offerer_hello {
        eprintln!("DTLS_CH_TX loop {}", hex(b));
    }
    let mbps = if r.echo_ms > r.open_ms { (r.bytes as f64 * 8.0 / 1e6) / ((r.echo_ms - r.open_ms) as f64 / 1e3) } else { 0.0 };
    println!(
        "RESULT {{\"probe\":\"loopback\",\"dtls\":\"{dtls}\",\"version\":\"{version}\",\"connected_ms\":{},\"open_ms\":{},\"echo_ms\":{},\"bytes\":{},\"messages\":{},\"echo_mbit_s\":{:.1},\"mem\":{}}}",
        r.connected_ms,
        r.open_ms,
        r.echo_ms,
        r.bytes,
        r.messages,
        mbps,
        m.json()
    );
    Ok(())
}

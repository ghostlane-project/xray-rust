//! The same checks as the static library's C entry, as a plain executable (run under
//! `xcrun simctl spawn` in the iOS simulator, or on any host).

fn main() {
    std::process::exit(olc_spike_ios_link::olc_spike_ios_run());
}

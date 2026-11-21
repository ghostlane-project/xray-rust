//! What a blocked-only list costs once it is loaded: 81,000 names and 25,000
//! prefixes, read from v2fly `.dat` files through `ext:file.dat:tag` in a
//! routing rule and in the DNS outbound's rule. The heap the parsed config
//! holds, the peak while it loads and the time are printed, and the heap is
//! held under a stated ceiling so a later regression is red.
//!
//! The `.dat` files are generated here from made-up names and prefixes;
//! nothing is downloaded.
//!
//! A test binary of its own with one test: the counting allocator sees the
//! whole process, so nothing else may run.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xray_config::{parse_xray_json_with_exclusive_geodata_dirs, OutboundSettings, ParsedConfig};

const NAMES: usize = 81_000;
const PREFIXES: usize = 25_000;

/// The heap the config holds for 81,000 names in one routing rule.
const NAMES_BOUND: usize = 1;
/// The same for 25,000 prefixes in one routing rule.
const PREFIXES_BOUND: usize = 1;
/// The app's shape: the names in a routing rule and again in the DNS
/// outbound's rule, the prefixes in a second routing rule.
const APP_SHAPE_BOUND: usize = 1;
/// The peak over the heap before the load, while the app's shape loads: the
/// file's bytes, the decoded list and the matchers are alive together.
const APP_SHAPE_PEAK_BOUND: usize = 1;

struct CountingAllocator;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrank(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` unchanged and only counts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One load: what the parsed config holds, the peak while parsing, the time.
struct Loaded {
    parsed: ParsedConfig,
    held: usize,
    peak: usize,
    took: Duration,
}

fn load(dir: &Path, raw: &str) -> Loaded {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let started = Instant::now();
    let parsed = parse_xray_json_with_exclusive_geodata_dirs(raw, &[dir])
        .unwrap_or_else(|error| panic!("the config should parse: {:?}", error.diagnostics));
    let took = started.elapsed();
    let held = LIVE.load(Ordering::Relaxed).saturating_sub(before);
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    Loaded {
        parsed,
        held,
        peak,
        took,
    }
}

fn report(what: &str, loaded: &Loaded, entries: usize) {
    println!(
        "LIST-MEMORY {what}: held {} bytes ({:.2} MiB, {} bytes an entry), peak while loading {} bytes ({:.2} MiB), load {} ms",
        loaded.held,
        loaded.held as f64 / 1_048_576.0,
        loaded.held / entries.max(1),
        loaded.peak,
        loaded.peak as f64 / 1_048_576.0,
        loaded.took.as_millis()
    );
}

#[test]
fn the_heap_of_81k_names_and_25k_prefixes_read_through_ext() {
    let fixture = Fixture::new();
    println!(
        "LIST-MEMORY files: names.dat {} bytes ({NAMES} names), prefixes.dat {} bytes ({PREFIXES} prefixes), profile {}",
        fs::metadata(fixture.dir.join("names.dat")).unwrap().len(),
        fs::metadata(fixture.dir.join("prefixes.dat")).unwrap().len(),
        if cfg!(debug_assertions) { "debug" } else { "release" }
    );

    // The config with no list: what everything but the lists holds.
    let empty = load(&fixture.dir, &config(&[], false));
    report("no list", &empty, 1);
    drop(empty);

    let names_rule = json!({"domain": ["ext:names.dat:blocked"]});
    let prefixes_rule = json!({"ip": ["ext:prefixes.dat:blocked"]});

    let names = load(&fixture.dir, &config(&[names_rule.clone()], false));
    report("names in a routing rule", &names, NAMES);
    {
        let rule = &names.parsed.config.routing.rules[0];
        let started = Instant::now();
        for index in 0..NAMES {
            assert!(rule.matches_domain(Some(&name(index))), "name {index}");
        }
        // Under a listed name, and names the list does not hold.
        assert!(rule.matches_domain(Some(&format!("www.{}", name(NAMES - 1)))));
        for index in NAMES..NAMES + 1_000 {
            assert!(!rule.matches_domain(Some(&name(index))), "name {index}");
        }
        assert!(!rule.matches_domain(Some("example")));
        println!(
            "LIST-MEMORY names: {} lookups in {} ms",
            NAMES + 1_002,
            started.elapsed().as_millis()
        );
    }
    let names_held = names.held;
    drop(names);

    let prefixes = load(&fixture.dir, &config(&[prefixes_rule.clone()], false));
    report("prefixes in a routing rule", &prefixes, PREFIXES);
    {
        let rule = &prefixes.parsed.config.routing.rules[0];
        let started = Instant::now();
        for index in 0..PREFIXES {
            let first = IpAddr::V4(prefix(index));
            let mut last = prefix(index).octets();
            last[3] = 255;
            assert!(rule.matches_ip(Some(&first)), "prefix {index}");
            assert!(rule.matches_ip(Some(&IpAddr::from(last))), "prefix {index}");
            // The /24 after each listed one is a hole.
            let mut hole = prefix(index).octets();
            hole[2] += 1;
            assert!(!rule.matches_ip(Some(&IpAddr::from(hole))), "hole {index}");
        }
        assert!(!rule.matches_ip(Some(&IpAddr::V4(prefix(PREFIXES)))));
        println!(
            "LIST-MEMORY prefixes: {} lookups in {} ms",
            PREFIXES * 3 + 1,
            started.elapsed().as_millis()
        );
    }
    let prefixes_held = prefixes.held;
    drop(prefixes);

    let app = load(&fixture.dir, &config(&[names_rule, prefixes_rule], true));
    report(
        "names in a routing rule and in the DNS outbound's rule, prefixes in a routing rule",
        &app,
        NAMES * 2 + PREFIXES,
    );
    {
        let rules = &app.parsed.config.routing.rules;
        assert!(rules[0].matches_domain(Some(&name(NAMES - 1))));
        assert!(!rules[0].matches_domain(Some(&name(NAMES))));
        assert!(rules[1].matches_ip(Some(&IpAddr::V4(prefix(PREFIXES - 1)))));
        assert!(!rules[1].matches_ip(Some(&IpAddr::V4(prefix(PREFIXES)))));
        let OutboundSettings::Dns(dns) = &app.parsed.config.outbounds[2].settings else {
            panic!("expected a DNS outbound");
        };
        assert!(dns.rules[0].matches(1, &name(0)));
        assert!(dns.rules[0].matches(28, &name(NAMES - 1)));
        assert!(!dns.rules[0].matches(1, &name(NAMES)));
    }
    let (app_held, app_peak) = (app.held, app.peak);
    drop(app);

    // Every number is printed before any is judged.
    assert!(
        names_held <= NAMES_BOUND,
        "{NAMES} names hold {names_held} bytes, over the ceiling of {NAMES_BOUND}"
    );
    assert!(
        prefixes_held <= PREFIXES_BOUND,
        "{PREFIXES} prefixes hold {prefixes_held} bytes, over the ceiling of {PREFIXES_BOUND}"
    );
    assert!(
        app_held <= APP_SHAPE_BOUND,
        "the app's shape holds {app_held} bytes, over the ceiling of {APP_SHAPE_BOUND}"
    );
    assert!(
        app_peak <= APP_SHAPE_PEAK_BOUND,
        "loading the app's shape peaks at {app_peak} bytes, over the ceiling of {APP_SHAPE_PEAK_BOUND}"
    );
}

/// A made-up name, unique for its index, about as long as a real one.
fn name(index: usize) -> String {
    format!("host{index}.zone{}.example", index % 977)
}

/// A /24 of its own for each index, every second one so that the compiled
/// matcher cannot merge neighbours.
fn prefix(index: usize) -> Ipv4Addr {
    let n = (index * 2) as u32;
    Ipv4Addr::new(100, (n >> 8) as u8, n as u8, 0)
}

fn config(rules: &[Value], dns_rule: bool) -> String {
    let rules: Vec<Value> = rules
        .iter()
        .map(|condition| {
            let mut rule = json!({"type": "field", "outboundTag": "blocked-out"});
            for (key, value) in condition.as_object().unwrap() {
                rule[key] = value.clone();
            }
            rule
        })
        .collect();
    let dns_rules = if dns_rule {
        json!([{"action": "drop", "domain": ["ext:names.dat:blocked"]}])
    } else {
        json!([])
    };
    json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked-out", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns", "settings": {"rules": dns_rules}}
        ],
        "routing": {"rules": rules}
    })
    .to_string()
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "xray-list-memory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let fixture = Self { dir };

        // GeoSite { country_code = 1; repeated Domain domain = 2 } with
        // Domain { Type type = 1 (2 is a domain and all under it); string value = 2 }.
        let mut site = Vec::new();
        bytes_field(&mut site, 1, b"BLOCKED");
        for index in 0..NAMES {
            let mut domain = Vec::new();
            varint_field(&mut domain, 1, 2);
            bytes_field(&mut domain, 2, name(index).as_bytes());
            bytes_field(&mut site, 2, &domain);
        }
        // GeoSiteList { repeated GeoSite entry = 1 }.
        let mut list = Vec::new();
        bytes_field(&mut list, 1, &site);
        fs::write(fixture.dir.join("names.dat"), list).unwrap();

        // GeoIP { country_code = 1; repeated CIDR cidr = 2 } with
        // CIDR { bytes ip = 1; uint32 prefix = 2 }.
        let mut entry = Vec::new();
        bytes_field(&mut entry, 1, b"BLOCKED");
        for index in 0..PREFIXES {
            let mut cidr = Vec::new();
            bytes_field(&mut cidr, 1, &prefix(index).octets());
            varint_field(&mut cidr, 2, 24);
            bytes_field(&mut entry, 2, &cidr);
        }
        // GeoIPList { repeated GeoIP entry = 1 }.
        let mut list = Vec::new();
        bytes_field(&mut list, 1, &entry);
        fs::write(fixture.dir.join("prefixes.dat"), list).unwrap();
        fixture
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn bytes_field(out: &mut Vec<u8>, tag: u64, body: &[u8]) {
    varint(out, tag << 3 | 2);
    varint(out, body.len() as u64);
    out.extend_from_slice(body);
}

fn varint_field(out: &mut Vec<u8>, tag: u64, value: u64) {
    varint(out, tag << 3);
    varint(out, value);
}

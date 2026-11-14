// Test target: off the app's paths, so the size lints (clippy.toml, memory model
// 05 T9) do not apply to a test's stack arrays or futures.
#![allow(clippy::large_futures, clippy::large_stack_arrays)]
//! The top-level `log` object, as Xray-core v26.11.9 `infra/conf/log.go`
//! reads it, and what it asks of the embedding's runtime log.

use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity, LogConfig, LogLevel};

fn config(log: Value) -> String {
    json!({"log": log, "outbounds": [{"protocol": "freedom"}]}).to_string()
}

fn log(log: Value) -> LogConfig {
    parse_xray_json(&config(log.clone()))
        .unwrap_or_else(|error| panic!("{log} should parse: {:?}", error.diagnostics))
        .log
}

#[test]
fn absent_or_null_log_writes_warnings_and_no_access_log() {
    let default = LogConfig {
        level: Some(LogLevel::Warning),
        access: false,
    };
    assert_eq!(LogConfig::default(), default);
    let parsed = parse_xray_json(&json!({"outbounds": [{"protocol": "freedom"}]}).to_string())
        .expect("a config without log parses");
    assert_eq!(parsed.log, default);
    assert_eq!(log(Value::Null), default);
    assert_eq!(log(json!({})), default);
}

#[test]
fn loglevel_names_the_least_severe_line_written() {
    for (name, level) in [
        ("debug", Some(LogLevel::Debug)),
        ("info", Some(LogLevel::Info)),
        ("warning", Some(LogLevel::Warning)),
        ("error", Some(LogLevel::Error)),
        ("none", None),
        // Go lowercases the value before it compares.
        ("DEBUG", Some(LogLevel::Debug)),
        ("Error", Some(LogLevel::Error)),
        // Empty and null read as Xray-core's default.
        ("", Some(LogLevel::Warning)),
    ] {
        assert_eq!(log(json!({"loglevel": name})).level, level, "{name}");
        // Xray-core's own struct tag; Go matches either spelling.
        assert_eq!(log(json!({"logLevel": name})).level, level, "{name}");
    }
    assert_eq!(
        log(json!({"loglevel": null})).level,
        Some(LogLevel::Warning)
    );
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warning);
    assert!(LogLevel::Warning < LogLevel::Error);
}

#[test]
fn an_unknown_loglevel_reads_as_warning_with_a_warning() {
    let parsed = parse_xray_json(&config(json!({"loglevel": "warn"})))
        .expect("Xray-core accepts any loglevel string");
    assert_eq!(parsed.log.level, Some(LogLevel::Warning));
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.path.as_deref() == Some("$.log.loglevel")
    }));
}

#[test]
fn the_access_log_is_written_only_when_access_names_one() {
    for (access, expected) in [
        (Value::Null, false),
        (json!(""), false),
        (json!("none"), false),
        (json!("/var/log/xray/access.log"), true),
        // Xray-core compares "none" exactly; any other text is a file name.
        (json!("None"), true),
    ] {
        assert_eq!(log(json!({"access": access})).access, expected, "{access}");
    }
    // An absent access field turns the access log off, where Xray-core sends
    // it to standard output.
    assert!(!log(json!({"loglevel": "debug"})).access);
}

#[test]
fn none_turns_logs_off() {
    // loglevel none turns both logs off, whatever access says.
    assert_eq!(
        log(json!({"loglevel": "none", "access": "access.log"})),
        LogConfig {
            level: None,
            access: false,
        }
    );
    // error none turns the error log off and leaves the access log alone.
    assert_eq!(
        log(json!({"loglevel": "debug", "error": "none", "access": "access.log"})),
        LogConfig {
            level: None,
            access: true,
        }
    );
    assert_eq!(
        log(json!({"error": "error.log"})).level,
        Some(LogLevel::Warning)
    );
}

#[test]
fn dns_log_and_mask_address_are_checked_and_change_nothing() {
    for value in [
        json!({"dnsLog": true}),
        json!({"dnsLog": false}),
        json!({"maskAddress": "quarter"}),
        json!({"maskAddress": "/16+/64"}),
    ] {
        assert_eq!(log(value.clone()), LogConfig::default(), "{value}");
    }
}

#[test]
fn malformed_log_objects_are_refused_at_their_path() {
    for (value, path) in [
        (json!("warning"), "$.log"),
        (json!([]), "$.log"),
        (json!({"loglevel": 4}), "$.log.loglevel"),
        (json!({"logLevel": true}), "$.log.logLevel"),
        (
            json!({"loglevel": "info", "logLevel": "debug"}),
            "$.log.logLevel",
        ),
        (json!({"access": 1}), "$.log.access"),
        (json!({"error": {}}), "$.log.error"),
        (json!({"dnsLog": "true"}), "$.log.dnsLog"),
        (json!({"maskAddress": 16}), "$.log.maskAddress"),
        (json!({"level": "debug"}), "$.log.level"),
    ] {
        let error = parse_xray_json(&config(value.clone()))
            .expect_err(&format!("{value} should be refused"));
        assert!(
            error
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.path.as_deref() == Some(path)),
            "{value}: {:?}",
            error.diagnostics
        );
    }
}

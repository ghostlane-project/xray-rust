//! The top-level `log` object.
//!
//! Read as Xray-core v26.11.9 `infra/conf/log.go` reads it. `access` and
//! `error` are strings, and exactly `"none"` turns that log off. `loglevel`
//! is `debug`, `info`, `warning`, `error` or `none` after Go's lowercasing,
//! and `none` turns both logs off; any other string reads as `warning`, as in
//! Xray-core, with a warning. Its struct tag is `logLevel`, and Go's decoder
//! matches keys ignoring case, so both spellings are read; giving both is
//! refused, since which one Go keeps depends on their order. `dnsLog` is a
//! boolean and `maskAddress` a string. Null reads as absent, as Go leaves the
//! zero value. Unknown keys fail like every other registered grammar node,
//! where Go would ignore them.
//!
//! The core opens no file the object names: the embedding decides where lines
//! go. Unlike Xray-core, which writes the access log to standard output when
//! `access` is empty or absent, the access log is written only when `access`
//! names one, so a config that says nothing records no connection. `dnsLog`
//! and `maskAddress` change nothing: no line here holds a DNS name or an
//! address, whatever they say.

use super::*;
use crate::{go_lowercase, LogConfig, LogLevel};

impl Parser<'_> {
    pub(super) fn parse_log(&mut self) -> LogConfig {
        let path = "$.log";
        let log = match self.root.get("log") {
            None | Some(Value::Null) => return LogConfig::default(),
            Some(log) if log.is_object() => log,
            Some(_) => {
                self.error(path, "log must be an object or null");
                return LogConfig::default();
            }
        };
        self.reject_unknown_fields(log, path, &surface::LOG);

        let access = self.nullable_string_at(log, "access", format!("{path}.access"));
        let error = self.nullable_string_at(log, "error", format!("{path}.error"));
        let level = self.log_level(log, path);
        match log.get("dnsLog") {
            None | Some(Value::Null | Value::Bool(_)) => {}
            Some(_) => self.error(
                format!("{path}.dnsLog"),
                "field `dnsLog` must be a boolean or null",
            ),
        }
        self.nullable_string_at(log, "maskAddress", format!("{path}.maskAddress"));

        let (Some(access), Some(error), Some(level)) = (access, error, level) else {
            return LogConfig::default();
        };
        LogConfig {
            level: level.filter(|_| error != "none"),
            access: level.is_some() && !access.is_empty() && access != "none",
        }
    }

    /// `Some(None)` is `none`; `None` means the field was refused.
    fn log_level(&mut self, log: &Value, path: &str) -> Option<Option<LogLevel>> {
        let (key, raw) = match (log.get("loglevel"), log.get("logLevel")) {
            (Some(lower), Some(upper)) if !lower.is_null() && !upper.is_null() => {
                self.error(
                    format!("{path}.logLevel"),
                    "`loglevel` and `logLevel` are the same field; give one",
                );
                return None;
            }
            (Some(lower), _) if !lower.is_null() => ("loglevel", lower),
            (_, Some(upper)) => ("logLevel", upper),
            (lower, None) => ("loglevel", lower.unwrap_or(&Value::Null)),
        };
        let field_path = format!("{path}.{key}");
        let raw = match raw {
            Value::Null => "",
            Value::String(raw) => raw.as_str(),
            _ => {
                self.error(
                    field_path,
                    format!("field `{key}` must be a string or null"),
                );
                return None;
            }
        };
        Some(match go_lowercase(raw).as_ref() {
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "" | "warning" => Some(LogLevel::Warning),
            "error" => Some(LogLevel::Error),
            "none" => None,
            _ => {
                self.warning(
                    field_path,
                    format!("unknown {key} `{raw}` reads as warning, as in Xray-core"),
                );
                Some(LogLevel::Warning)
            }
        })
    }
}

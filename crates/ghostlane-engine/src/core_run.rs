//! The core half of a session: an Xray JSON config run by `xray-core-rs`,
//! as a library in this process. Its listeners are the session's inbounds,
//! its log lines and the parser's remarks become events, and its sockets go
//! through the session's way out when there is one.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use xray_config::{
    parse_xray_json, parse_xray_json_with_exclusive_geodata_dirs, ConfigParseError,
    DiagnosticSeverity, ParsedConfig,
};
use xray_core_rs::{Core, RuntimeLogKind, RuntimeLogger, TunRuntimeOptions};
use xray_transport::TransportDialer;

use crate::events::{Diagnostic, Event, FailureCode, Inbound, Level, Severity, Source};
use crate::{Ctx, Failure};

/// A running core line.
pub struct CoreLine {
    core: Core,
    inbounds: Vec<Inbound>,
}

fn parse(config: &Value, geodata_dir: Option<&Path>) -> Result<ParsedConfig, ConfigParseError> {
    let raw = config.to_string();
    match geodata_dir {
        Some(dir) => parse_xray_json_with_exclusive_geodata_dirs(&raw, &[dir]),
        None => parse_xray_json(&raw),
    }
}

fn diagnostic(found: xray_config::Diagnostic) -> Diagnostic {
    Diagnostic {
        severity: match found.severity {
            DiagnosticSeverity::Warning => Severity::Warning,
            DiagnosticSeverity::Error => Severity::Error,
        },
        source: Source::Core,
        path: found.path,
        message: found.message,
    }
}

/// One sentence from a refusal's findings: `path: message`, joined.
fn sentence(findings: &[Diagnostic]) -> String {
    findings
        .iter()
        .map(|found| match &found.path {
            Some(path) => format!("{path}: {}", found.message),
            None => found.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// What the parser says of a core half, starting nothing: its remarks when
/// it accepts the config, its errors when it does not.
#[must_use]
pub fn check(config: &Value, geodata_dir: Option<&Path>) -> Vec<Diagnostic> {
    let found = match parse(config, geodata_dir) {
        Ok(parsed) => parsed.diagnostics,
        Err(refusal) => refusal.diagnostics,
    };
    found.into_iter().map(diagnostic).collect()
}

fn level(kind: RuntimeLogKind) -> Level {
    match kind {
        RuntimeLogKind::Debug => Level::Debug,
        RuntimeLogKind::Info => Level::Info,
        RuntimeLogKind::Warning => Level::Warning,
        RuntimeLogKind::Error => Level::Error,
        RuntimeLogKind::Access => Level::Access,
    }
}

impl CoreLine {
    /// Parses `config`, builds the core and starts it. The parser's remarks
    /// are printed as `warning` events; the config's `log` object decides
    /// which of the core's lines become `log` events.
    ///
    /// # Errors
    /// [`FailureCode::Config`] when the parser or the core refuses the
    /// config, [`FailureCode::Start`] when the core cannot start,
    /// [`FailureCode::Internal`] when the engine cannot set it up.
    pub async fn start(
        config: &Value,
        geodata_dir: Option<&Path>,
        ctx: &Ctx,
    ) -> Result<Self, Failure> {
        let parsed = parse(config, geodata_dir).map_err(|refusal| {
            let findings: Vec<_> = refusal.diagnostics.into_iter().map(diagnostic).collect();
            Failure::new(FailureCode::Config, sentence(&findings))
        })?;
        for found in parsed.diagnostics.into_iter().map(diagnostic) {
            ctx.events.emit(&Event::Warning {
                source: found.source,
                path: found.path,
                message: found.message,
            });
        }
        let tags: Vec<Option<String>> = parsed
            .config
            .inbounds
            .iter()
            .map(|inbound| inbound.tag.clone())
            .collect();

        let protector = ctx
            .escape
            .as_ref()
            .map(crate::escape::Escape::core_protector);
        let dialer = TransportDialer::system_with_socket_protector(protector)
            .map_err(|error| Failure::new(FailureCode::Internal, error.to_string()))?;
        let mut core = Core::with_transport_dialer_and_tun_options(
            parsed.config,
            Arc::new(dialer),
            TunRuntimeOptions::default(),
        )
        .map_err(|error| Failure::new(FailureCode::Config, error.to_string()))?;

        let events = ctx.events.clone();
        let logger = RuntimeLogger::with_callback(parsed.log, move |kind, line| {
            events.emit(&Event::Log {
                source: Source::Core,
                level: level(kind),
                line: line.to_owned(),
            });
        })
        .map_err(|error| {
            Failure::new(
                FailureCode::Internal,
                format!("the log thread could not start: {error}"),
            )
        })?;
        core.set_runtime_logger(logger);

        core.start().await.map_err(|error| {
            Failure::new(
                FailureCode::Start,
                format!("the core could not start: {error}"),
            )
        })?;
        let inbounds = tags
            .into_iter()
            .filter_map(|tag| {
                let address = core.inbound_addr(tag.as_deref())?.to_string();
                Some(Inbound { tag, address })
            })
            .collect();
        Ok(Self { core, inbounds })
    }

    /// The listeners, each where it was bound.
    #[must_use]
    pub fn inbounds(&self) -> &[Inbound] {
        &self.inbounds
    }

    /// The core itself, for a question asked of a running line.
    #[must_use]
    pub fn core(&self) -> &Core {
        &self.core
    }

    /// Stops the core: its listeners close and its flows end.
    ///
    /// # Errors
    /// [`FailureCode::Internal`] when the core says it could not stop.
    pub async fn stop(mut self) -> Result<(), Failure> {
        self.core
            .stop()
            .await
            .map_err(|error| Failure::new(FailureCode::Internal, error.to_string()))
    }
}

//! The one-shot questions: `probe` (one request for a URL through the
//! session's line), `olc-check` (one join of the session's room) and
//! `olc-ping` (a join, then the best of three requests through the room).
//! Each is a process of its own that prints one line and ends; none of them
//! serves a port for the parent, and none prints `bound` or a log line: the
//! session's way out is used, quietly.
//!
//! An answer that did not come is a no: `ok: false` and why, and the exit
//! status is 1. A question that cannot be asked (a flag, a session without
//! the half it needs, a half that is refused) is an `error` line instead.

use std::time::Duration;

use serde_json::{json, Value};
use xray_core_rs::{
    OutboundHealthFailure, OutboundProbeError, OutboundProbeOutcome, StartupProbeOptions,
};

use crate::args::Flags;
use crate::core_run::CoreLine;
use crate::escape::Escape;
use crate::events::{Events, FailureCode};
use crate::session::Session;
use crate::{room, Ctx, Failure};

/// The flags `probe` takes besides `--session`.
pub const PROBE_FLAGS: &[&str] = &["url", "timeout-ms", "outbound"];
/// The flags `olc-check` takes besides `--session`.
pub const OLC_CHECK_FLAGS: &[&str] = &["timeout-ms"];
/// The flags `olc-ping` takes besides `--session`.
pub const OLC_PING_FLAGS: &[&str] = &["url", "timeout-ms"];

/// `probe`'s time when `--timeout-ms` is not given, and the most it takes
/// (the core's own bound).
const PROBE_TIMEOUT: (u64, u64) = (5_000, 60_000);
/// `olc-check`'s and `olc-ping`'s, the phones' defaults; a join of a real
/// carrier's room may take a while, so the most is ten minutes.
const OLC_CHECK_TIMEOUT: (u64, u64) = (8_000, 600_000);
const OLC_PING_TIMEOUT: (u64, u64) = (10_000, 600_000);
/// How long the core is given to stop after a probe.
const CORE_STOP: Duration = Duration::from_millis(1_000);

/// A question's answer, printed as the one line of its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The line or the room answered.
    pub ok: bool,
    /// How long the answer took, milliseconds.
    pub millis: Option<u64>,
    /// Why there was none.
    pub error: Option<String>,
}

impl Outcome {
    fn yes(millis: u64) -> Self {
        Self {
            ok: true,
            millis: Some(millis),
            error: None,
        }
    }

    fn no(why: impl Into<String>) -> Self {
        Self {
            ok: false,
            millis: None,
            error: Some(why.into()),
        }
    }
}

fn usage(message: impl Into<String>) -> Failure {
    Failure::new(FailureCode::Usage, message)
}

/// `--timeout-ms`, from 1 to `most`, or `default` when not given.
fn timeout(flags: &Flags, (default, most): (u64, u64)) -> Result<Duration, Failure> {
    let millis = flags.number("timeout-ms", default)?;
    if !(1..=most).contains(&millis) {
        return Err(usage(format!(
            "`--timeout-ms` takes a whole number from 1 to {most}"
        )));
    }
    Ok(Duration::from_millis(millis))
}

/// `--url`, an `http://` or `https://` URL.
fn url(flags: &Flags) -> Result<&str, Failure> {
    let url = flags.required("url")?;
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(url)
    } else {
        Err(usage("`--url` takes an http:// or https:// URL"))
    }
}

/// The core half as a probe runs it: the outbounds, the routing and the DNS
/// of the session, with one SOCKS listener on a port of the system's choice
/// in place of the session's inbounds. A probe asks an outbound directly, so
/// no inbound carries it; the core starts only with one, and the session's
/// own (a TUN device, a port the running session holds) are not the probe's.
fn probe_config(core: &Value) -> Value {
    let mut config = core.clone();
    if let Some(config) = config.as_object_mut() {
        config.insert(
            "inbounds".to_owned(),
            json!([{
                "tag": "ghostlane-probe",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 0
            }]),
        );
    }
    config
}

/// What the core says of a request that was not answered, in words.
fn failure_words(failure: OutboundHealthFailure) -> String {
    match failure {
        OutboundHealthFailure::Timeout => "the request timed out".to_owned(),
        OutboundHealthFailure::Transport => "the line could not carry the request".to_owned(),
        OutboundHealthFailure::Tls => "TLS to the URL's server failed".to_owned(),
        OutboundHealthFailure::Io => "the connection failed".to_owned(),
        OutboundHealthFailure::MalformedHttpResponse => "the answer was not HTTP".to_owned(),
        OutboundHealthFailure::HttpStatus(status) => format!("the answer was HTTP status {status}"),
    }
}

fn refusal(error: &OutboundProbeError) -> Failure {
    match error {
        OutboundProbeError::UnsupportedUrl => usage("`--url` is not a URL the probe can ask for"),
        OutboundProbeError::InvalidTimeout => usage("`--timeout-ms` is out of the probe's range"),
        OutboundProbeError::UnknownOutbound => {
            usage("`--outbound` names no outbound of the core half")
        }
        OutboundProbeError::NoDefaultOutbound => Failure::new(
            FailureCode::Config,
            "the core half has no default outbound to probe",
        ),
        OutboundProbeError::NotRunning
        | OutboundProbeError::Cancelled
        | OutboundProbeError::CancelledInFlight => Failure::new(
            FailureCode::Internal,
            format!("the probe was not asked: {error}"),
        ),
    }
}

/// `probe`: starts the session's core half with no listener of its own
/// needed, asks for `--url` through `--outbound` (the default outbound when
/// not given) within `--timeout-ms`, and stops.
///
/// # Errors
/// A session or flags the question cannot be asked with; an answer that did
/// not come is an [`Outcome`], not an error.
pub fn probe(session: &Session, flags: &Flags) -> Result<Outcome, Failure> {
    let url = url(flags)?.to_owned();
    let timeout = timeout(flags, PROBE_TIMEOUT)?;
    let outbound_tag = flags.get("outbound").map(str::to_owned);
    let Some(core) = &session.core else {
        return Err(Failure::new(
            FailureCode::Session,
            "the session has no core half to probe through; a room is asked with `olc-check` or `olc-ping`",
        ));
    };
    if session.room.is_some() {
        return Err(Failure::unsupported(
            "a probe through a core in front of a room is not built yet",
        ));
    }
    let config = probe_config(core);
    let quiet = Events::to(Box::new(std::io::sink()));
    let escape = session
        .bind
        .as_ref()
        .map(|bind| Escape::open(bind, &quiet))
        .transpose()?;
    let ctx = Ctx {
        events: quiet,
        escape,
    };
    let runtime = ghostlane_runtime::handle().map_err(|error| {
        Failure::new(
            FailureCode::Internal,
            format!("the runtime could not start: {error}"),
        )
    })?;
    runtime.block_on(async {
        let line = CoreLine::start(&config, session.geodata_dir.as_deref(), &ctx).await?;
        let options = StartupProbeOptions {
            url,
            timeout,
            outbound_tag,
        };
        // The core bounds the request by `timeout`; this bounds the rest.
        let asked = tokio::time::timeout(
            timeout + Duration::from_secs(2),
            line.core().probe_outbound_url(options),
        )
        .await;
        let _ = tokio::time::timeout(CORE_STOP, line.stop()).await;
        match asked {
            Err(_) => Ok(Outcome::no("the request timed out")),
            Ok(Ok(OutboundProbeOutcome::Reachable { delay })) => Ok(Outcome::yes(
                u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            )),
            Ok(Ok(OutboundProbeOutcome::Failed(failure))) => {
                Ok(Outcome::no(failure_words(failure)))
            }
            Ok(Err(error)) => Err(refusal(&error)),
        }
    })
}

/// The session's room half, for a room question.
fn room_half(session: &Session) -> Result<&Value, Failure> {
    session.room.as_ref().ok_or_else(|| {
        Failure::new(
            FailureCode::Session,
            "the session has no room half to ask; a line is asked with `probe`",
        )
    })
}

fn room_answer(asked: Result<u64, String>) -> Outcome {
    match asked {
        Ok(millis) => Outcome::yes(millis),
        Err(why) => Outcome::no(why),
    }
}

/// `olc-check`: joins the session's room alone and waits for its SOCKS
/// port, within `--timeout-ms`.
///
/// # Errors
/// As [`probe`].
pub fn olc_check(session: &Session, flags: &Flags) -> Result<Outcome, Failure> {
    let timeout = timeout(flags, OLC_CHECK_TIMEOUT)?;
    let spec = room_half(session)?;
    room::ask(spec, session.bind.as_ref(), timeout, None).map(room_answer)
}

/// `olc-ping`: [`olc_check`], then the best of three requests for `--url`
/// through the room.
///
/// # Errors
/// As [`probe`].
pub fn olc_ping(session: &Session, flags: &Flags) -> Result<Outcome, Failure> {
    let url = url(flags)?;
    let timeout = timeout(flags, OLC_PING_TIMEOUT)?;
    let spec = room_half(session)?;
    room::ask(spec, session.bind.as_ref(), timeout, Some(url)).map(room_answer)
}

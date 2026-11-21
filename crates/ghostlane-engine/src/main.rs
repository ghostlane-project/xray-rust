//! `ghostlane-engine`, the program. It reads its command, and for `run`
//! starts the session's halves in order (the room, the front, the core),
//! prints `ready`, and serves until SIGTERM or until its stdin closes: a
//! parent that dies closes it, so an engine never outlives its parent. There
//! is no command channel; what is read from stdin is ignored.
//!
//! Exit status: 0 after a stop that was asked for or an answer that is a
//! yes, 1 after a failure or an answer that is a no, 2 when the command
//! line was not understood.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use ghostlane_engine::args::{self, Command, Flags, Invocation};
use ghostlane_engine::core_run::{self, CoreLine};
use ghostlane_engine::escape::Escape;
use ghostlane_engine::events::{
    EndReason, Event, Events, FailureCode, Inbound, Severity, PROTOCOL,
};
use ghostlane_engine::probe::{self, Outcome};
use ghostlane_engine::room::{self, Room};
use ghostlane_engine::session::{self, Session};
use ghostlane_engine::{front, Ctx, Failure};

/// The system allocator, counted, as in the phones' library.
#[global_allocator]
static ALLOC: ghostlane_runtime::alloc::CountingAlloc = ghostlane_runtime::alloc::CountingAlloc;

/// How long after a stop is asked for the process is gone, whatever its
/// halves are doing: `ended` is printed and the process exits.
const STOP_DEADLINE: Duration = Duration::from_millis(1500);
/// How long each half is given to close what it holds.
const HALF_STOP: Duration = Duration::from_millis(1000);

fn main() -> ExitCode {
    let events = Events::parent();
    let arguments: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect();
    let invocation = arguments
        .map_err(|_| Failure::new(FailureCode::Usage, "the arguments are not UTF-8"))
        .and_then(|arguments| args::parse(&arguments));
    let invocation = match invocation {
        Ok(invocation) => invocation,
        Err(failure) => {
            eprintln!("{}", args::USAGE);
            return refuse(&events, &failure);
        }
    };
    match invocation.command {
        Command::Version => {
            events.emit(&version());
            ExitCode::SUCCESS
        }
        Command::CheckConfig => check_config(&invocation, &events),
        Command::Run => run(&invocation, &events),
        Command::Probe => ask(&invocation, &events, probe::probe, |answer| Event::Probe {
            ok: answer.ok,
            millis: answer.millis,
            error: answer.error,
        }),
        Command::OlcCheck => ask(&invocation, &events, probe::olc_check, |answer| {
            Event::OlcCheck {
                ok: answer.ok,
                millis: answer.millis,
                error: answer.error,
            }
        }),
        Command::OlcPing => ask(&invocation, &events, probe::olc_ping, |answer| {
            Event::OlcPing {
                ok: answer.ok,
                millis: answer.millis,
                error: answer.error,
            }
        }),
    }
}

fn version() -> Event {
    Event::Version {
        engine: env!("CARGO_PKG_VERSION").to_owned(),
        protocol: PROTOCOL,
        pin: ghostlane_engine::PIN.to_owned(),
        boringssl: ghostlane_engine::boringssl(),
        rooms: ghostlane_engine::rooms(),
        target: ghostlane_engine::TARGET.to_owned(),
    }
}

/// The one line of a command that failed, and its exit status.
fn refuse(events: &Events, failure: &Failure) -> ExitCode {
    events.emit(&Event::Error {
        code: failure.code,
        message: failure.message.clone(),
    });
    ExitCode::from(failure.exit_status())
}

fn yes_or_no(yes: bool) -> ExitCode {
    if yes {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// The session file of a command that takes one; `args::parse` saw to it
/// that it is named.
fn session_of(invocation: &Invocation) -> Result<Session, Failure> {
    let path = invocation
        .session
        .as_deref()
        .ok_or_else(|| Failure::new(FailureCode::Usage, "no session file is named"))?;
    session::load(path)
}

fn check_config(invocation: &Invocation, events: &Events) -> ExitCode {
    let session = match session_of(invocation) {
        Ok(session) => session,
        Err(failure) => return refuse(events, &failure),
    };
    let mut diagnostics = Vec::new();
    if let Some(core) = &session.core {
        diagnostics.extend(core_run::check(core, session.geodata_dir.as_deref()));
    }
    if let Some(spec) = &session.room {
        diagnostics.extend(room::check(spec));
    }
    let ok = diagnostics
        .iter()
        .all(|found| found.severity != Severity::Error);
    events.emit(&Event::CheckConfig { ok, diagnostics });
    yes_or_no(ok)
}

/// A one-shot question: one line of its kind, or the `error` line.
fn ask(
    invocation: &Invocation,
    events: &Events,
    question: fn(&Session, &Flags) -> Result<Outcome, Failure>,
    line: fn(Outcome) -> Event,
) -> ExitCode {
    match session_of(invocation).and_then(|session| question(&session, &invocation.flags)) {
        Ok(answer) => {
            let ok = answer.ok;
            events.emit(&line(answer));
            yes_or_no(ok)
        }
        Err(failure) => refuse(events, &failure),
    }
}

fn run(invocation: &Invocation, events: &Events) -> ExitCode {
    let (reason, failure) = match (invocation.session.as_deref(), ghostlane_runtime::handle()) {
        (None, _) => {
            let failure = Failure::new(FailureCode::Usage, "no session file is named");
            (EndReason::Failed, Some(failure))
        }
        (Some(_), Err(error)) => {
            let failure = Failure::new(
                FailureCode::Internal,
                format!("the runtime could not start: {error}"),
            );
            (EndReason::Failed, Some(failure))
        }
        (Some(path), Ok(runtime)) => {
            raise_file_limit();
            runtime.block_on(serve(path, events))
        }
    };
    events.emit(&ended(reason, failure.as_ref()));
    ExitCode::from(failure.as_ref().map_or(0, Failure::exit_status))
}

fn ended(reason: EndReason, failure: Option<&Failure>) -> Event {
    Event::Ended {
        reason,
        code: failure.map(|failure| failure.code),
        message: failure.map(|failure| failure.message.clone()),
    }
}

/// What a session has running.
#[derive(Default)]
struct Up {
    room: Option<Room>,
    core: Option<CoreLine>,
}

impl Up {
    /// Resolves when a half ends on its own.
    async fn ended(&mut self) -> Failure {
        match self.room.as_mut() {
            Some(room) => room.ended().await,
            None => std::future::pending().await,
        }
    }

    /// Stops the core, then the room behind it.
    async fn stop(self) {
        if let Some(core) = self.core {
            let _ = tokio::time::timeout(HALF_STOP, core.stop()).await;
        }
        if let Some(room) = self.room {
            room.stop(HALF_STOP).await;
        }
    }
}

/// One session, from its file to its end: why it ended, and the failure when
/// it was one. Whatever was started is stopped before this returns, and the
/// process is gone [`STOP_DEADLINE`] after the end began even if a half does
/// not stop.
async fn serve(path: &Path, events: &Events) -> (EndReason, Option<Failure>) {
    let mut stop = match Stop::watch() {
        Ok(stop) => stop,
        Err(error) => {
            let failure = Failure::new(
                FailureCode::Internal,
                format!("the stop cannot be watched for: {error}"),
            );
            return (EndReason::Failed, Some(failure));
        }
    };
    let mut up = Up::default();
    let started = tokio::select! {
        biased;
        reason = stop.asked() => Err((reason, None)),
        started = start(path, events, &mut up) => {
            started.map_err(|failure| (EndReason::Failed, Some(failure)))
        }
    };
    let (reason, failure) = match started {
        Err(end) => end,
        Ok(()) => tokio::select! {
            biased;
            reason = stop.asked() => (reason, None),
            failure = up.ended() => (EndReason::Failed, Some(failure)),
        },
    };
    let last = ended(reason, failure.as_ref());
    let status = failure.as_ref().map_or(0, Failure::exit_status);
    let watchdog = events.clone();
    // If the thread cannot start, the halves' own deadlines still hold.
    let _ = std::thread::Builder::new()
        .name("ghostlane-deadline".to_owned())
        .spawn(move || {
            std::thread::sleep(STOP_DEADLINE);
            watchdog.emit(&last);
            std::process::exit(i32::from(status));
        });
    up.stop().await;
    (reason, failure)
}

/// Starts what the session holds, in order: the way out, the room, the
/// front, the core. Then `ready`.
async fn start(path: &Path, events: &Events, up: &mut Up) -> Result<(), Failure> {
    let session = session::load(path)?;
    let escape = match &session.bind {
        Some(bind) => Some(Escape::open(bind, events)?),
        None => None,
    };
    let ctx = Ctx {
        events: events.clone(),
        escape,
    };
    let mut core = session.core;
    if let Some(spec) = &session.room {
        let room = up.room.insert(room::start(spec, &ctx).await?);
        if let Some(core) = core.as_mut() {
            front::join(core, room, &ctx)?;
        }
    }
    if let Some(core) = &core {
        let line = CoreLine::start(core, session.geodata_dir.as_deref(), &ctx).await?;
        up.core = Some(line);
    }
    let inbounds = match (&up.core, &up.room) {
        (Some(line), _) => line.inbounds().to_vec(),
        (None, Some(room)) => vec![Inbound {
            tag: Some("room".to_owned()),
            address: room.socks().to_string(),
        }],
        (None, None) => Vec::new(),
    };
    events.emit(&Event::Ready { inbounds });
    Ok(())
}

/// The two ways a stop is asked for: stdin closes, or a signal.
struct Stop {
    asked: watch::Receiver<Option<EndReason>>,
}

impl Stop {
    /// Starts watching. Called on the runtime: the signal handlers are in
    /// place when this returns.
    fn watch() -> std::io::Result<Self> {
        let (tell, asked) = watch::channel(None);
        let tell = Arc::new(tell);
        let signals = Signals::install()?;
        let on_signal = Arc::clone(&tell);
        tokio::spawn(async move {
            signals.wait().await;
            Self::tell(&on_signal, EndReason::Signal);
        });
        std::thread::Builder::new()
            .name("ghostlane-stdin".to_owned())
            .spawn(move || {
                wait_for_stdin_to_close();
                Self::tell(&tell, EndReason::StdinClosed);
            })?;
        Ok(Self { asked })
    }

    /// The first reason stays.
    fn tell(tell: &watch::Sender<Option<EndReason>>, reason: EndReason) {
        let _ = tell.send_if_modified(|asked| {
            if asked.is_none() {
                *asked = Some(reason);
                true
            } else {
                false
            }
        });
    }

    /// Resolves once a stop is asked for, and again at once ever after.
    async fn asked(&mut self) -> EndReason {
        loop {
            if let Some(reason) = *self.asked.borrow_and_update() {
                return reason;
            }
            if self.asked.changed().await.is_err() {
                // Nobody is left to ask: only a failure ends the session.
                return std::future::pending().await;
            }
        }
    }
}

/// Reads stdin to its end. What is read is ignored: there is no command
/// channel.
fn wait_for_stdin_to_close() {
    use std::io::Read;
    let mut stdin = std::io::stdin().lock();
    let mut ignored = [0_u8; 256];
    loop {
        match stdin.read(&mut ignored) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

#[cfg(unix)]
struct Signals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    async fn wait(mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct Signals;

#[cfg(not(unix))]
impl Signals {
    #[allow(clippy::unnecessary_wraps)]
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn wait(self) {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Lifts the soft limit on open files to the hard one, as the Go cores'
/// runtime did at start: a desktop's default of 256 or 1024 is a few
/// hundred flows.
#[cfg(unix)]
#[allow(
    clippy::unnecessary_cast,
    reason = "rlim_t is only u64 on some unix targets"
)]
fn raise_file_limit() {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct given, and only on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return;
    }
    let target = limits.rlim_max as u64;
    // macOS refuses a soft limit above kern.maxfilesperproc even when the
    // hard limit says unlimited.
    #[cfg(target_os = "macos")]
    let target = match max_files_per_process() {
        Some(most) => target.min(most),
        None => target,
    };
    if limits.rlim_cur as u64 >= target {
        return;
    }
    limits.rlim_cur = target as libc::rlim_t;
    // SAFETY: setrlimit reads the struct given; a refusal leaves the limit as
    // it was.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) };
}

#[cfg(target_os = "macos")]
fn max_files_per_process() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>();
    // SAFETY: sysctlbyname writes at most `length` bytes into `value`.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && value > 0).then_some(value as u64)
}

#[cfg(not(unix))]
fn raise_file_limit() {}

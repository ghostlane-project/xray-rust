use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use xray_config::{LogConfig, LogLevel};

const LOG_QUEUE_CAPACITY: usize = 4096;
const LOG_FLUSH_INTERVAL: Duration = Duration::from_millis(100);
const LOG_FLUSH_BATCH_SIZE: usize = 256;

/// The size a runtime log file may reach. The line that would take it past
/// this first moves it to `<name>.1`, replacing the previous one, so a log
/// takes at most twice this on disk.
pub const DEFAULT_RUNTIME_LOG_FILE_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLogConfig {
    access_path: PathBuf,
    error_path: PathBuf,
    log: LogConfig,
    max_file_bytes: u64,
}

impl RuntimeLogConfig {
    /// `xray-access.log` and `xray-error.log` in `dir`, each capped at
    /// [`DEFAULT_RUNTIME_LOG_FILE_MAX_BYTES`]. Every severity and the access
    /// log are written until [`Self::with_log`] narrows them, as an embedding
    /// does with the `log` object of the config it loads.
    pub fn directory(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            access_path: dir.join("xray-access.log"),
            error_path: dir.join("xray-error.log"),
            log: LogConfig {
                level: Some(LogLevel::Debug),
                access: true,
            },
            max_file_bytes: DEFAULT_RUNTIME_LOG_FILE_MAX_BYTES,
        }
    }

    /// Writes only the lines `log` asks for. A file that would receive none
    /// is not opened.
    pub fn with_log(mut self, log: LogConfig) -> Self {
        self.log = log;
        self
    }

    /// Caps each file at `max_file_bytes`, at least one byte, instead of
    /// [`DEFAULT_RUNTIME_LOG_FILE_MAX_BYTES`].
    pub fn with_max_file_bytes(mut self, max_file_bytes: u64) -> Self {
        self.max_file_bytes = max_file_bytes.max(1);
        self
    }

    pub fn access_path(&self) -> &Path {
        &self.access_path
    }

    pub fn error_path(&self) -> &Path {
        &self.error_path
    }

    pub fn log(&self) -> LogConfig {
        self.log
    }

    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }
}

/// What one runtime log line is: an error-log line of a severity, or an
/// access-log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeLogKind {
    Debug,
    Info,
    Warning,
    Error,
    Access,
}

impl RuntimeLogKind {
    fn label(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Access => "access",
        }
    }

    fn severity(self) -> Option<LogLevel> {
        match self {
            Self::Debug => Some(LogLevel::Debug),
            Self::Info => Some(LogLevel::Info),
            Self::Warning => Some(LogLevel::Warning),
            Self::Error => Some(LogLevel::Error),
            Self::Access => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeLogger {
    inner: Option<Arc<RuntimeLoggerInner>>,
}

impl RuntimeLogger {
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn new(config: RuntimeLogConfig) -> io::Result<Self> {
        Self::with_queue_capacity(config, LOG_QUEUE_CAPACITY)
    }

    /// Hands each line to `callback` instead of writing files: one at a time,
    /// in order, on the logger's own thread, without a timestamp, on one line
    /// with control characters escaped. The callback is dropped on that thread
    /// after the last line, once every clone of the logger is gone, or at once
    /// when `log` asks for no line.
    pub fn with_callback(
        log: LogConfig,
        callback: impl FnMut(RuntimeLogKind, &str) + Send + 'static,
    ) -> io::Result<Self> {
        if !writes_any_line(log) {
            return Ok(Self::disabled());
        }
        Self::spawn(log, LOG_QUEUE_CAPACITY, CallbackSink(callback))
    }

    fn with_queue_capacity(config: RuntimeLogConfig, queue_capacity: usize) -> io::Result<Self> {
        let log = config.log;
        if !writes_any_line(log) {
            return Ok(Self::disabled());
        }
        let open = |wanted: bool, path: &Path| {
            wanted
                .then(|| CappedFile::open(path, config.max_file_bytes))
                .transpose()
        };
        let sink = FileSink {
            access: open(log.access, config.access_path())?,
            error: open(log.level.is_some(), config.error_path())?,
        };
        Self::spawn(log, queue_capacity, sink)
    }

    fn spawn(
        log: LogConfig,
        queue_capacity: usize,
        sink: impl LogSink + 'static,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let worker = thread::Builder::new()
            .name("xray-runtime-log".to_owned())
            .spawn(move || writer_loop(receiver, sink))?;

        Ok(Self {
            inner: Some(Arc::new(RuntimeLoggerInner {
                sender: Some(sender),
                dropped_lines: AtomicU64::new(0),
                worker: Some(worker),
                log,
            })),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Whether debug lines are written, for callers that do work only to
    /// produce them.
    pub fn debug_enabled(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.writes(RuntimeLogKind::Debug))
    }

    pub fn dropped_lines(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.dropped_lines.load(Ordering::Relaxed))
    }

    pub fn debug(&self, message: impl FnOnce() -> String) {
        self.write(RuntimeLogKind::Debug, message);
    }

    pub fn info(&self, message: impl FnOnce() -> String) {
        self.write(RuntimeLogKind::Info, message);
    }

    pub fn warning(&self, message: impl FnOnce() -> String) {
        self.write(RuntimeLogKind::Warning, message);
    }

    pub fn error(&self, message: impl FnOnce() -> String) {
        self.write(RuntimeLogKind::Error, message);
    }

    pub fn access(&self, message: impl FnOnce() -> String) {
        self.write(RuntimeLogKind::Access, message);
    }

    /// Builds the message only when its line is written.
    fn write(&self, kind: RuntimeLogKind, message: impl FnOnce() -> String) {
        let Some(inner) = &self.inner else {
            return;
        };
        if !inner.writes(kind) {
            return;
        }
        inner.enqueue(LogRecord {
            kind,
            message: message(),
        });
    }
}

fn writes_any_line(log: LogConfig) -> bool {
    log.level.is_some() || log.access
}

/// Rate-limits recurring log events. `register` records one event and
/// returns `Some(events_since_last_log)` when enough time has passed since
/// the previous emission (the first event always logs).
///
/// Time is passed in as milliseconds so callers control the clock; pair with
/// [`monotonic_millis`] in production code.
pub(crate) struct LogThrottle {
    interval_millis: u64,
    /// `u64::MAX` means no event has been logged yet.
    last_logged_millis: AtomicU64,
    pending_events: AtomicU64,
}

impl LogThrottle {
    pub(crate) const fn new(interval: Duration) -> Self {
        Self {
            interval_millis: interval.as_millis() as u64,
            last_logged_millis: AtomicU64::new(u64::MAX),
            pending_events: AtomicU64::new(0),
        }
    }

    pub(crate) fn register(&self, now_millis: u64) -> Option<u64> {
        self.pending_events.fetch_add(1, Ordering::Relaxed);
        let last = self.last_logged_millis.load(Ordering::Relaxed);
        let due = last == u64::MAX || now_millis.saturating_sub(last) >= self.interval_millis;
        if !due {
            return None;
        }
        if self
            .last_logged_millis
            .compare_exchange(last, now_millis, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // Another thread won the race and logs this window.
            return None;
        }
        Some(self.pending_events.swap(0, Ordering::Relaxed))
    }
}

/// Milliseconds elapsed since the first call in this process. Monotonic, so
/// safe for throttling decisions regardless of wall-clock adjustments.
pub(crate) fn monotonic_millis() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct RuntimeLoggerInner {
    sender: Option<SyncSender<LogRecord>>,
    dropped_lines: AtomicU64,
    worker: Option<JoinHandle<()>>,
    log: LogConfig,
}

impl std::fmt::Debug for RuntimeLoggerInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeLoggerInner")
            .field("queue_connected", &self.sender.is_some())
            .field("dropped_lines", &self.dropped_lines.load(Ordering::Relaxed))
            .field("log", &self.log)
            .finish_non_exhaustive()
    }
}

impl RuntimeLoggerInner {
    fn writes(&self, kind: RuntimeLogKind) -> bool {
        match kind.severity() {
            Some(severity) => self.log.level.is_some_and(|level| severity >= level),
            None => self.log.access,
        }
    }

    fn enqueue(&self, record: LogRecord) {
        let Some(sender) = self.sender.as_ref() else {
            self.dropped_lines.fetch_add(1, Ordering::Relaxed);
            return;
        };
        enqueue_nonblocking(sender, &self.dropped_lines, record);
    }
}

impl Drop for RuntimeLoggerInner {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
struct LogRecord {
    kind: RuntimeLogKind,
    message: String,
}

fn enqueue_nonblocking(
    sender: &SyncSender<LogRecord>,
    dropped_lines: &AtomicU64,
    record: LogRecord,
) {
    if matches!(
        sender.try_send(record),
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_))
    ) {
        dropped_lines.fetch_add(1, Ordering::Relaxed);
    }
}

/// Where the log thread puts each line. It is dropped on that thread when the
/// last logger clone is gone.
trait LogSink: Send {
    fn write(&mut self, record: LogRecord);
    fn flush(&mut self);
}

/// `xray-access.log` and `xray-error.log`; a log the config turns off has no
/// file.
struct FileSink {
    access: Option<CappedFile>,
    error: Option<CappedFile>,
}

impl LogSink for FileSink {
    fn write(&mut self, record: LogRecord) {
        let file = match record.kind {
            RuntimeLogKind::Access => &mut self.access,
            _ => &mut self.error,
        };
        if let Some(file) = file {
            file.write_line(format!(
                "{} {} {}\n",
                timestamp_millis(),
                record.kind.label(),
                single_line_message(&record.message)
            ));
        }
    }

    fn flush(&mut self) {
        for file in [&mut self.access, &mut self.error].into_iter().flatten() {
            file.flush();
        }
    }
}

struct CallbackSink<F>(F);

impl<F: FnMut(RuntimeLogKind, &str) + Send> LogSink for CallbackSink<F> {
    fn write(&mut self, record: LogRecord) {
        (self.0)(record.kind, &single_line_message(&record.message));
    }

    fn flush(&mut self) {}
}

/// One log file kept under its cap. The line that would take the file past
/// the cap first moves it to `<name>.1`, replacing the previous one, and
/// starts the file anew; a single line longer than the cap is cut to it.
struct CappedFile {
    path: PathBuf,
    /// `None` once the file could not be opened again: its lines are dropped.
    writer: Option<BufWriter<File>>,
    len: u64,
    max_bytes: u64,
}

impl CappedFile {
    fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let writer = open_log_file(path)?;
        let len = writer.get_ref().metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            writer: Some(writer),
            len,
            max_bytes,
        })
    }

    fn write_line(&mut self, mut line: String) {
        if line.len() as u64 > self.max_bytes {
            let mut end = usize::try_from(self.max_bytes - 1).unwrap_or(usize::MAX);
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
            line.push('\n');
        }
        let line_len = line.len() as u64;
        if self.len > 0 && self.len + line_len > self.max_bytes {
            self.rotate();
        }
        let Some(writer) = self.writer.as_mut() else {
            return;
        };
        if writer.write_all(line.as_bytes()).is_ok() {
            self.len += line_len;
        }
    }

    fn flush(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writer.flush();
        }
    }

    fn rotate(&mut self) {
        let Some(mut writer) = self.writer.take() else {
            return;
        };
        let _ = writer.flush();
        let (file, _) = writer.into_parts();
        // Only the file this logger writes is moved: not one that replaced it.
        if is_same_file(&file, &self.path)
            && std::fs::rename(&self.path, rotated_log_path(&self.path)).is_err()
        {
            // The file stays where it is: start it again to keep the cap.
            if file.set_len(0).is_ok() {
                self.len = 0;
                self.writer = Some(BufWriter::new(file));
            }
            return;
        }
        // Moved aside, by this rotation or by someone else: open the path anew.
        if let Ok(writer) = open_log_file(&self.path) {
            self.len = writer
                .get_ref()
                .metadata()
                .map_or(0, |metadata| metadata.len());
            self.writer = Some(writer);
        }
    }
}

fn rotated_log_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

#[cfg(unix)]
fn is_same_file(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(open), Ok(named)) => open.dev() == named.dev() && open.ino() == named.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn is_same_file(_file: &File, path: &Path) -> bool {
    path.is_file()
}

fn writer_loop(receiver: Receiver<LogRecord>, mut sink: impl LogSink) {
    let mut pending_since_flush = 0usize;

    loop {
        match receiver.recv_timeout(LOG_FLUSH_INTERVAL) {
            Ok(record) => {
                sink.write(record);
                pending_since_flush += 1;

                while pending_since_flush < LOG_FLUSH_BATCH_SIZE {
                    match receiver.try_recv() {
                        Ok(record) => {
                            sink.write(record);
                            pending_since_flush += 1;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            sink.flush();
                            return;
                        }
                    }
                }

                if pending_since_flush >= LOG_FLUSH_BATCH_SIZE {
                    sink.flush();
                    pending_since_flush = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if pending_since_flush > 0 {
                    sink.flush();
                    pending_since_flush = 0;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                sink.flush();
                return;
            }
        }
    }
}

fn single_line_message(message: &str) -> String {
    let mut sanitized = String::with_capacity(message.len());
    for character in message.chars() {
        match character {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(sanitized, "\\u{{{:x}}}", u32::from(character));
            }
            character => sanitized.push(character),
        }
    }
    sanitized
}

fn open_log_file(path: &Path) -> io::Result<BufWriter<File>> {
    #[cfg(unix)]
    {
        open_log_file_unix(path).map(BufWriter::new)
    }

    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let file = options.open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime log target is not a regular file",
            ));
        }
        Ok(BufWriter::new(file))
    }
}

/// The sandbox on iOS (and hardened macOS contexts) grants search/traversal
/// through the ancestors of the app container but refuses to open them for
/// reading, so the component-by-component `openat` walk used on other unix
/// platforms fails with EPERM inside a Network Extension. Resolving the whole
/// path in one call is allowed; `O_NOFOLLOW_ANY` rejects symlinks in every
/// path component, which is the property the walk existed to enforce.
#[cfg(target_vendor = "apple")]
fn open_log_file_unix(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::DirBuilderExt;

    let path = normalize_apple_system_directory_alias(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let path = CString::new(path.into_os_string().into_vec()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "runtime log path contains NUL")
    })?;
    let flags = libc::O_WRONLY
        | libc::O_APPEND
        | libc::O_CREAT
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW_ANY
        | libc::O_NONBLOCK;
    // SAFETY: `path` is NUL-terminated and a creation mode is supplied
    // because O_CREAT is set. The returned fd is uniquely owned.
    let fd = unsafe { libc::open(path.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a fresh owned fd and this is its sole owner.
    validate_log_file(unsafe { File::from_raw_fd(fd) })
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn open_log_file_unix(path: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    fn open_directory(path: &CString) -> io::Result<File> {
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_DIRECTORY;
        // SAFETY: `path` is NUL-terminated and flags request a read-only
        // directory descriptor. The returned fd is uniquely owned.
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned a fresh owned fd and this is its sole owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime log path has no file name",
        )
    })?;
    let starting_path = if parent.is_absolute() { "/" } else { "." };
    let starting_path = CString::new(starting_path).expect("static path contains no NUL");
    let mut current_dir = open_directory(&starting_path)?;

    for component in parent.components() {
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime log path may not contain parent or prefix components",
            ));
        };
        let component = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime log directory component contains NUL",
            )
        })?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_DIRECTORY;
        // SAFETY: the directory fd is live and `component` is one
        // NUL-terminated path component. No writable access is requested.
        let mut fd = unsafe { libc::openat(current_dir.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            // SAFETY: both arguments are valid and the mode only grants
            // access to the current user (subject to a stricter umask).
            let mkdir_result =
                unsafe { libc::mkdirat(current_dir.as_raw_fd(), component.as_ptr(), 0o700) };
            if mkdir_result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: same live directory fd and component as above.
            fd = unsafe { libc::openat(current_dir.as_raw_fd(), component.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh owned fd.
        current_dir = unsafe { File::from_raw_fd(fd) };
    }

    let file_name = CString::new(file_name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime log file name contains NUL",
        )
    })?;
    let flags = libc::O_WRONLY
        | libc::O_APPEND
        | libc::O_CREAT
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK;
    // SAFETY: the directory fd is live, `file_name` is one NUL-terminated
    // component, and a creation mode is supplied because O_CREAT is set.
    let fd = unsafe { libc::openat(current_dir.as_raw_fd(), file_name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh owned fd and this is its sole owner.
    validate_log_file(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn validate_log_file(file: File) -> io::Result<File> {
    use std::os::fd::AsRawFd;

    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime log target is not a regular file",
        ));
    }
    // SAFETY: `file` owns a live descriptor. Tightening permissions to 0600
    // prevents a pre-existing log from retaining broader access.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(target_vendor = "apple")]
fn normalize_apple_system_directory_alias(path: &Path) -> PathBuf {
    for alias in ["/var", "/tmp", "/etc"] {
        let alias = Path::new(alias);
        if let Ok(suffix) = path.strip_prefix(alias) {
            return Path::new("/private")
                .join(alias.strip_prefix("/").expect("absolute static alias"))
                .join(suffix);
        }
    }
    path.to_path_buf()
}

fn timestamp_millis() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}.{}", duration.as_secs(), duration.subsec_millis()),
        Err(_) => "0.000".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use xray_config::{LogConfig, LogLevel};

    use super::{
        monotonic_millis, LogThrottle, RuntimeLogConfig, RuntimeLogKind, RuntimeLogger,
        RuntimeLoggerInner,
    };

    #[test]
    fn log_throttle_reports_first_event_immediately() {
        let throttle = LogThrottle::new(Duration::from_secs(5));

        assert_eq!(throttle.register(0), Some(1));
    }

    #[test]
    fn log_throttle_suppresses_events_until_interval_elapses() {
        let throttle = LogThrottle::new(Duration::from_secs(5));

        assert_eq!(throttle.register(1_000), Some(1));
        assert_eq!(throttle.register(2_000), None);
        assert_eq!(throttle.register(5_999), None);
        assert_eq!(throttle.register(6_000), Some(3));
        assert_eq!(throttle.register(6_001), None);
    }

    #[test]
    fn monotonic_millis_is_nondecreasing() {
        let first = monotonic_millis();
        let second = monotonic_millis();

        assert!(second >= first);
    }

    #[test]
    fn disabled_logger_does_not_evaluate_message_closure() {
        let logger = RuntimeLogger::disabled();
        let evaluated = AtomicBool::new(false);

        assert!(!logger.is_enabled());
        logger.debug(|| {
            evaluated.store(true, Ordering::SeqCst);
            "should not be built".to_owned()
        });

        assert!(!evaluated.load(Ordering::SeqCst));
    }

    #[test]
    fn enabled_logger_flushes_debug_and_access_files_on_drop() {
        let dir = unique_temp_dir("xray-runtime-log");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");

        logger.debug(|| "Debug routeDecision target=example.com:443".to_owned());
        logger.error(|| "startup probe failed: tls handshake eof".to_owned());
        logger.access(|| "from 10.0.0.2:49152 accepted example.com:443 proxy".to_owned());
        drop(logger);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        let access_log =
            std::fs::read_to_string(dir.join("xray-access.log")).expect("access log should exist");
        assert!(error_log.contains("Debug routeDecision"));
        assert!(error_log.contains("startup probe failed"));
        assert!(access_log.contains("accepted example.com:443"));
    }

    #[test]
    fn full_queue_drops_without_blocking_producer() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let logger = RuntimeLogger {
            inner: Some(Arc::new(RuntimeLoggerInner {
                sender: Some(sender),
                dropped_lines: AtomicU64::new(0),
                worker: None,
                log: LogConfig {
                    level: Some(LogLevel::Debug),
                    access: true,
                },
            })),
        };

        logger.debug(|| "first".to_owned());
        logger.debug(|| "second".to_owned());

        assert_eq!(logger.dropped_lines(), 1);
    }

    #[test]
    fn last_clone_owns_writer_shutdown() {
        let dir = unique_temp_dir("xray-runtime-log-clone");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");
        let clone = logger.clone();
        logger.debug(|| "before first drop".to_owned());
        drop(logger);
        clone.debug(|| "before final drop".to_owned());
        drop(clone);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");

        assert!(error_log.contains("before final drop"));
    }

    #[test]
    fn control_characters_cannot_forge_additional_log_records() {
        let dir = unique_temp_dir("xray-runtime-log-control");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir))
            .expect("logger should open files");

        logger.error(|| "proxy\n123 error forged\r\u{7}".to_owned());
        drop(logger);

        let error_log =
            std::fs::read_to_string(dir.join("xray-error.log")).expect("error log should exist");
        assert_eq!(error_log.lines().count(), 1);
        assert!(error_log.contains(r"proxy\n123 error forged\r\u{7}"));
    }

    #[cfg(unix)]
    #[test]
    fn logger_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = unique_temp_dir("xray-runtime-log-symlink");
        let target = dir.join("target");
        std::fs::write(&target, "unchanged").unwrap();
        symlink(&target, dir.join("xray-access.log")).unwrap();

        let error = RuntimeLogger::new(RuntimeLogConfig::directory(&dir)).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn logger_rejects_intermediate_directory_symlink() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("xray-runtime-log-directory-symlink");
        let base = root.join("base");
        let outside = root.join("outside");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, base.join("logs")).unwrap();

        let error = RuntimeLogger::new(RuntimeLogConfig::directory(base.join("logs"))).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!outside.join("xray-access.log").exists());
        assert!(!outside.join("xray-error.log").exists());
    }

    #[cfg(unix)]
    #[test]
    fn logger_rejects_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = unique_temp_dir("xray-runtime-log-fifo");
        let fifo = dir.join("xray-access.log");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_path` is a live NUL-terminated filesystem path.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);

        let started = Instant::now();
        let error = RuntimeLogger::new(RuntimeLogConfig::directory(&dir)).unwrap_err();

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(started.elapsed().as_secs() < 1);
    }

    #[test]
    fn level_filter_writes_only_lines_at_or_above_the_level() {
        let dir = unique_temp_dir("xray-runtime-log-level");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_log(LogConfig {
            level: Some(LogLevel::Warning),
            access: true,
        }))
        .expect("logger should open files");
        let evaluated = AtomicBool::new(false);

        assert!(logger.is_enabled());
        assert!(!logger.debug_enabled());
        logger.debug(|| {
            evaluated.store(true, Ordering::SeqCst);
            "a debug line".to_owned()
        });
        logger.info(|| "an info line".to_owned());
        logger.warning(|| "a warning line".to_owned());
        logger.error(|| "an error line".to_owned());
        logger.access(|| "an access line".to_owned());
        drop(logger);

        assert!(!evaluated.load(Ordering::SeqCst));
        let error_log = std::fs::read_to_string(dir.join("xray-error.log")).unwrap();
        assert!(!error_log.contains("a debug line"), "{error_log}");
        assert!(!error_log.contains("an info line"), "{error_log}");
        assert!(error_log.contains(" warning a warning line"), "{error_log}");
        assert!(error_log.contains(" error an error line"), "{error_log}");
        let access_log = std::fs::read_to_string(dir.join("xray-access.log")).unwrap();
        assert!(access_log.contains(" access an access line"), "{access_log}");

        let dir = unique_temp_dir("xray-runtime-log-debug");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_log(LogConfig {
            level: Some(LogLevel::Debug),
            access: false,
        }))
        .unwrap();
        assert!(logger.debug_enabled());
        logger.debug(|| "a debug line".to_owned());
        logger.info(|| "an info line".to_owned());
        drop(logger);
        let error_log = std::fs::read_to_string(dir.join("xray-error.log")).unwrap();
        assert!(error_log.contains(" debug a debug line"), "{error_log}");
        assert!(error_log.contains(" info an info line"), "{error_log}");
    }

    #[test]
    fn default_log_config_opens_no_access_log() {
        let dir = unique_temp_dir("xray-runtime-log-default");
        let logger =
            RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_log(LogConfig::default()))
                .unwrap();
        logger.access(|| "from tun accepted <redacted-domain>:443".to_owned());
        logger.error(|| "an error line".to_owned());
        drop(logger);

        assert!(!dir.join("xray-access.log").exists());
        assert!(std::fs::read_to_string(dir.join("xray-error.log"))
            .unwrap()
            .contains("an error line"));
    }

    #[test]
    fn a_log_config_that_writes_nothing_opens_nothing() {
        let dir = unique_temp_dir("xray-runtime-log-none");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_log(LogConfig {
            level: None,
            access: false,
        }))
        .unwrap();

        assert!(!logger.is_enabled());
        logger.error(|| "an error line".to_owned());
        drop(logger);
        assert!(!dir.join("xray-error.log").exists());
        assert!(!dir.join("xray-access.log").exists());
    }

    #[test]
    fn each_log_file_is_capped_with_one_rotation() {
        let dir = unique_temp_dir("xray-runtime-log-cap");
        let cap = 256;
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_max_file_bytes(cap))
            .unwrap();
        for index in 0..100 {
            logger.error(move || format!("line {index:03} {}", "x".repeat(40)));
            logger.access(move || format!("access {index:03} {}", "y".repeat(40)));
        }
        drop(logger);

        for name in ["xray-error.log", "xray-access.log"] {
            let current = std::fs::read_to_string(dir.join(name)).unwrap();
            let rotated = std::fs::read_to_string(dir.join(format!("{name}.1"))).unwrap();
            assert!(current.len() as u64 <= cap, "{name}: {}", current.len());
            assert!(rotated.len() as u64 <= cap, "{name}.1: {}", rotated.len());
            assert!(!current.is_empty() && !rotated.is_empty(), "{name}");
            // The newest line is in the file, the lines just before it in .1,
            // and the oldest are gone.
            assert!(current.lines().last().unwrap().contains(" 099 "), "{current}");
            assert!(!rotated.contains(" 000 "), "{rotated}");
            assert!(!dir.join(format!("{name}.2")).exists());
            for line in current.lines().chain(rotated.lines()) {
                assert!(line.ends_with(&"x".repeat(40)) || line.ends_with(&"y".repeat(40)));
            }
        }
    }

    #[test]
    fn a_file_over_the_cap_from_before_is_rotated_on_the_first_line() {
        let dir = unique_temp_dir("xray-runtime-log-cap-existing");
        std::fs::write(dir.join("xray-error.log"), "z".repeat(1000)).unwrap();
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_max_file_bytes(256))
            .unwrap();
        logger.error(|| "a new line".to_owned());
        drop(logger);

        let current = std::fs::read_to_string(dir.join("xray-error.log")).unwrap();
        assert!(current.contains("a new line") && !current.contains('z'), "{current}");
        assert_eq!(
            std::fs::read_to_string(dir.join("xray-error.log.1")).unwrap(),
            "z".repeat(1000)
        );
    }

    #[test]
    fn a_line_longer_than_the_cap_is_cut_to_it() {
        let dir = unique_temp_dir("xray-runtime-log-cap-line");
        let logger = RuntimeLogger::new(RuntimeLogConfig::directory(&dir).with_max_file_bytes(64))
            .unwrap();
        logger.error(|| "é".repeat(1000));
        drop(logger);

        let current = std::fs::read_to_string(dir.join("xray-error.log")).unwrap();
        assert!(current.len() <= 64, "{}", current.len());
        assert!(current.ends_with('\n'));
    }

    #[test]
    fn callback_receives_each_line_with_its_kind_instead_of_files() {
        struct Released(Arc<AtomicBool>);
        impl Drop for Released {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let released = Arc::new(AtomicBool::new(false));
        let guard = Released(Arc::clone(&released));
        let (sender, receiver) = mpsc::channel();
        let logger = RuntimeLogger::with_callback(
            LogConfig {
                level: Some(LogLevel::Info),
                access: true,
            },
            move |kind, line| {
                let _ = &guard;
                sender.send((kind, line.to_owned())).unwrap();
            },
        )
        .expect("log thread should start");

        logger.debug(|| "a debug line".to_owned());
        logger.info(|| "an info\nline".to_owned());
        logger.warning(|| "a warning line".to_owned());
        logger.error(|| "an error line".to_owned());
        logger.access(|| "an access line".to_owned());
        drop(logger);

        assert_eq!(
            receiver.iter().collect::<Vec<_>>(),
            [
                (RuntimeLogKind::Info, r"an info\nline".to_owned()),
                (RuntimeLogKind::Warning, "a warning line".to_owned()),
                (RuntimeLogKind::Error, "an error line".to_owned()),
                (RuntimeLogKind::Access, "an access line".to_owned()),
            ]
        );
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn callback_with_nothing_to_write_is_dropped_at_once() {
        let (sender, receiver) = mpsc::channel::<(RuntimeLogKind, String)>();
        let logger = RuntimeLogger::with_callback(
            LogConfig {
                level: None,
                access: false,
            },
            move |kind, line| sender.send((kind, line.to_owned())).unwrap(),
        )
        .unwrap();

        assert!(!logger.is_enabled());
        logger.error(|| "an error line".to_owned());
        assert!(receiver.recv().is_err());
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn logger_opens_logs_behind_search_only_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root bypasses permission checks, so the scenario cannot be built
        }

        // The iOS Network Extension sandbox lets the process traverse (search)
        // ancestors of the app-group container but not read them. Model that
        // with an ancestor directory whose read bit is dropped.
        let root = unique_temp_dir("xray-runtime-log-search-only");
        let locked = root.join("locked");
        let logs = locked.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o311)).unwrap();

        let result = RuntimeLogger::new(RuntimeLogConfig::directory(&logs));

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let logger = result.expect("search-only ancestor must not break file logging");
        drop(logger);
        assert!(logs.join("xray-access.log").exists());
        assert!(logs.join("xray-error.log").exists());
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }
}

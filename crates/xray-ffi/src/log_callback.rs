use super::*;
use xray_core_rs::RuntimeLogKind;

/// Kind of a line handed to the log callback (ABI 1.19): Xray-core's log
/// severities, numbered as its `Severity`, and `Access` for an access-log
/// line. The C ABI transports it as `int32_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayLogLevel {
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    Access = 5,
}

impl From<RuntimeLogKind> for XrayLogLevel {
    fn from(kind: RuntimeLogKind) -> Self {
        match kind {
            RuntimeLogKind::Error => Self::Error,
            RuntimeLogKind::Warning => Self::Warning,
            RuntimeLogKind::Info => Self::Info,
            RuntimeLogKind::Debug => Self::Debug,
            RuntimeLogKind::Access => Self::Access,
        }
    }
}

pub type XrayLogCallback =
    Option<unsafe extern "C" fn(level: i32, line: *const c_char, line_len: usize, *mut c_void)>;
pub type XrayLogRelease = Option<unsafe extern "C" fn(*mut c_void)>;

/// The host's callback and context, released once the handle and the log
/// thread are both done with them.
pub(crate) struct FfiLogCallback {
    callback: unsafe extern "C" fn(i32, *const c_char, usize, *mut c_void),
    release: unsafe extern "C" fn(*mut c_void),
    user_data: usize,
}

// The callback runs on the log thread only; the handle merely holds it until
// the logger takes a reference at config load.
unsafe impl Send for FfiLogCallback {}
unsafe impl Sync for FfiLogCallback {}

impl FfiLogCallback {
    /// Hands one line to the host, NUL-terminated in `buffer`. The runtime
    /// log escapes every control character, so the line holds no NUL.
    pub(crate) fn deliver(&self, buffer: &mut Vec<u8>, kind: RuntimeLogKind, line: &str) {
        buffer.clear();
        buffer.extend_from_slice(line.as_bytes());
        buffer.push(0);
        unsafe {
            (self.callback)(
                XrayLogLevel::from(kind) as i32,
                buffer.as_ptr().cast(),
                line.len(),
                self.user_data as *mut c_void,
            );
        }
    }
}

impl Drop for FfiLogCallback {
    fn drop(&mut self) {
        // The host transfers ownership only after successful registration.
        unsafe {
            (self.release)(self.user_data as *mut c_void);
        }
    }
}

/// Sends the runtime log to a host callback instead of files (ABI 1.19).
///
/// Register before config load. Once set, `xray_core_set_file_logging` opens
/// no file. The config's `log` object decides which lines are delivered, as it
/// does for files. The callback runs on the core's log thread, one line at a
/// time and in order, never on a data-path thread; when the log falls 4,096
/// lines behind, new lines are dropped rather than waited for. `line` is UTF-8
/// on one line, control characters escaped, NUL-terminated and borrowed for
/// the call; `line_len` excludes the NUL. A null callback clears the
/// registration and requires null release and user_data. On success release
/// is called exactly once, after the last line, possibly after
/// `xray_core_free` and on any thread; replacing or clearing a registration
/// releases the previous one. Failure retains ownership with the caller.
///
/// # Safety
/// Handle/error must be valid, lifecycle calls externally serialized. Both
/// callbacks must be thread-safe, return promptly, never unwind across FFI,
/// and must not invoke core lifecycle operations. Code and user_data must
/// remain valid until release.
#[no_mangle]
pub unsafe extern "C" fn xray_core_set_log_callback(
    handle: *mut XrayCoreHandle,
    callback: XrayLogCallback,
    release: XrayLogRelease,
    user_data: *mut c_void,
    error: *mut *mut XrayError,
) -> XrayStatus {
    unsafe {
        ffi_status(error, || {
            clear_error(error);
            let Some(handle) = handle.as_mut() else {
                set_error(error, XrayStatus::NullArgument, "core handle is null");
                return XrayStatus::NullArgument;
            };
            if handle.core.is_some() {
                set_error(
                    error,
                    XrayStatus::RuntimeError,
                    "log callback must be set before config load",
                );
                return XrayStatus::RuntimeError;
            }
            let Some(callback) = callback else {
                if release.is_some() || !user_data.is_null() {
                    set_error(
                        error,
                        XrayStatus::InvalidArgument,
                        "clearing the log callback requires null context and release",
                    );
                    return XrayStatus::InvalidArgument;
                }
                handle.log_callback = None;
                return XrayStatus::Ok;
            };
            let Some(release) = release else {
                set_error(
                    error,
                    XrayStatus::InvalidArgument,
                    "log callback requires a context release callback",
                );
                return XrayStatus::InvalidArgument;
            };
            handle.log_callback = Some(Arc::new(FfiLogCallback {
                callback,
                release,
                user_data: user_data as usize,
            }));
            XrayStatus::Ok
        })
    }
}

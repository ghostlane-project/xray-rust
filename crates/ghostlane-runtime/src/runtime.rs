//! The process's one Tokio runtime.
//!
//! It is built on first use from the [`Profile`] in force: [`configure`]
//! sets one before that, otherwise [`Profile::for_target`] applies. It is
//! never dropped: the cores' handles come and go (an app starts and stops a
//! tunnel many times), the runtime stays, so a stop leaves no thread of its
//! own behind and a start pays for none. What a stop must leave behind is no
//! task, which [`alive_tasks`] counts.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tokio::runtime::{Builder, Handle, Runtime};

/// A worker's stack (plan §3.4: futures live on the heap, so 512 KiB is
/// enough; checked on the device from M9).
pub const WORKER_STACK: usize = 512 * 1024;
/// The most blocking threads (`design.md` D11: at most four).
pub const MAX_BLOCKING: usize = 4;
/// How long an idle blocking thread lives on the phone: 2 s, not Tokio's
/// 10 s, so the threads a burst of `getaddrinfo` calls started leave soon
/// with their touched stacks. xray-ffi's own iOS plan (`runtime_plan_for`)
/// reads this constant too.
pub const PHONE_KEEP_ALIVE: Duration = Duration::from_secs(2);
/// Elsewhere: Tokio's default, as xray-ffi's plan keeps it off iOS.
pub const HOST_KEEP_ALIVE: Duration = Duration::from_secs(10);
/// The threads' name.
pub const THREAD_NAME: &str = "ghostlane-rt";

/// The runtime's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Worker threads.
    pub workers: usize,
    /// The most blocking threads at once.
    pub max_blocking: usize,
    /// Each thread's stack, bytes.
    pub stack: usize,
    /// How long an idle blocking thread is kept.
    pub keep_alive: Duration,
}

impl Profile {
    /// The iOS extension's: one worker (the lab showed one carries the
    /// lines, D11), four blocking threads, each idle one gone after
    /// [`PHONE_KEEP_ALIVE`].
    #[must_use]
    pub const fn phone() -> Self {
        Self {
            workers: 1,
            max_blocking: MAX_BLOCKING,
            stack: WORKER_STACK,
            keep_alive: PHONE_KEEP_ALIVE,
        }
    }

    /// Elsewhere: xray-ffi's own worker count (`runtime_worker_threads`, the
    /// cores the machine has, 2 to 6), four blocking threads, Tokio's
    /// keep-alive.
    #[must_use]
    pub fn host() -> Self {
        let available = std::thread::available_parallelism().map_or(2, usize::from);
        Self {
            workers: available.clamp(2, 6),
            keep_alive: HOST_KEEP_ALIVE,
            ..Self::phone()
        }
    }

    /// [`Profile::phone`] on iOS, [`Profile::host`] elsewhere.
    #[must_use]
    pub fn for_target() -> Self {
        if cfg!(target_os = "ios") {
            Self::phone()
        } else {
            Self::host()
        }
    }
}

struct Slot {
    profile: Option<Profile>,
    built: Option<(&'static Runtime, Profile)>,
}

static SLOT: Mutex<Slot> = Mutex::new(Slot {
    profile: None,
    built: None,
});
static THREADS: AtomicUsize = AtomicUsize::new(0);

fn slot() -> std::sync::MutexGuard<'static, Slot> {
    SLOT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Sets the profile the runtime will be built with.
///
/// # Errors
/// Once the runtime is built its profile cannot change: the one in force.
pub fn configure(profile: Profile) -> Result<(), Profile> {
    let mut slot = slot();
    if let Some((_, built)) = slot.built {
        return if built == profile { Ok(()) } else { Err(built) };
    }
    slot.profile = Some(profile);
    Ok(())
}

/// The runtime's handle, building it on first use.
///
/// # Errors
/// The runtime could not be built (no threads); the next call tries again.
pub fn handle() -> io::Result<Handle> {
    let mut slot = slot();
    if let Some((rt, _)) = slot.built {
        return Ok(rt.handle().clone());
    }
    let profile = slot.profile.unwrap_or_else(Profile::for_target);
    let rt = Builder::new_multi_thread()
        .worker_threads(profile.workers)
        .max_blocking_threads(profile.max_blocking)
        .thread_stack_size(profile.stack)
        .thread_keep_alive(profile.keep_alive)
        .thread_name(THREAD_NAME)
        .on_thread_start(|| {
            THREADS.fetch_add(1, Ordering::Relaxed);
        })
        .on_thread_stop(|| {
            THREADS.fetch_sub(1, Ordering::Relaxed);
        })
        .enable_all()
        .build()?;
    let rt: &'static Runtime = Box::leak(Box::new(rt));
    slot.built = Some((rt, profile));
    Ok(rt.handle().clone())
}

/// The profile the runtime was built with; `None` before it is.
#[must_use]
pub fn built() -> Option<Profile> {
    slot().built.map(|(_, p)| p)
}

/// The runtime's threads alive now: its workers and blocking threads.
#[must_use]
pub fn threads() -> usize {
    THREADS.load(Ordering::Relaxed)
}

/// Tasks alive on the runtime; `None` before it is built.
#[must_use]
pub fn alive_tasks() -> Option<usize> {
    slot()
        .built
        .map(|(rt, _)| rt.handle().metrics().num_alive_tasks())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_runtime_of_the_configured_shape_serves_every_caller() {
        let want = Profile {
            workers: 1,
            max_blocking: 2,
            stack: WORKER_STACK,
            keep_alive: Duration::from_millis(200),
        };
        assert_eq!(configure(want), Ok(()));
        assert_eq!(built(), None);
        let a = handle().unwrap();
        let b = handle().unwrap();
        assert_eq!(a.id(), b.id(), "one runtime");
        assert_eq!(built(), Some(want));
        assert_eq!(a.metrics().num_workers(), 1);
        assert_eq!(configure(want), Ok(()), "the same shape is no change");
        assert_eq!(configure(Profile::phone()), Err(want));
        let settle = |done: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !done() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        settle(&|| threads() == 1);
        assert_eq!(threads(), 1, "the worker");
        // A task is counted while it lives (an async one: the blocking pool
        // is not in the count), and threads are the runtime's.
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = a.spawn(async move { rx.await.ok() });
        assert_eq!(alive_tasks(), Some(1));
        drop(tx);
        a.block_on(task).unwrap();
        settle(&|| alive_tasks() == Some(0));
        assert_eq!(alive_tasks(), Some(0), "an ended task is not counted");
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let task = a.spawn_blocking(move || rx.recv().ok());
        settle(&|| threads() == 2);
        assert_eq!(threads(), 2, "the worker and the blocking thread");
        drop(tx);
        a.block_on(task).unwrap();
        // The blocking thread leaves after its keep-alive.
        settle(&|| threads() == 1);
        assert_eq!(threads(), 1, "only the worker is left");
        // A caller outside the runtime waits on the runtime's timers (the
        // probes' deadlines run so), with its one worker idle.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let h = handle().unwrap();
            h.block_on(async { tokio::time::sleep(Duration::from_millis(5)).await });
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "a timer awaited from outside the runtime fires"
        );
    }

    /// xray-ffi's own plan idles a blocking thread 2 s on iOS, not Tokio's
    /// 10 s, and keeps Tokio's elsewhere: the shared runtime does the same.
    #[test]
    fn an_idle_blocking_thread_lives_two_seconds_on_the_phone_and_ten_elsewhere() {
        assert_eq!(Profile::phone().keep_alive, Duration::from_secs(2));
        assert_eq!(Profile::phone().keep_alive, PHONE_KEEP_ALIVE);
        assert_eq!(Profile::host().keep_alive, Duration::from_secs(10));
        assert_eq!(Profile::host().keep_alive, HOST_KEEP_ALIVE);
    }
}

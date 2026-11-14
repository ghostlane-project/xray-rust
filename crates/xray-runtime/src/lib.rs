// Size lints (clippy.toml, memory model 05 T9) guard the app's paths. Test code
// is off them: a test's stack is not a tunnel worker's and a test's future
// is never a flow's.
#![cfg_attr(test, allow(clippy::large_futures, clippy::large_stack_arrays))]
use tokio::sync::watch;

#[derive(Debug)]
pub struct Shutdown {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self { sender, receiver }
    }

    pub fn signal(&self) {
        let _ = self.sender.send(true);
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

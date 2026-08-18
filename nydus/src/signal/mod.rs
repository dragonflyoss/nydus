//! Signal lifecycle shared by the uffd/nbd/ublk/fanotify daemons: the
//! termination-signal registration done first in every daemon's startup
//! preamble, and the signal thread that drives the graceful shutdown.

use nydus_error::{Context, Error, Result};
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::flag;
use signal_hook::iterator::{Handle, Signals};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tracing::info;

/// Register the termination signals and return the iterator the signal
/// thread will drain. Called first in the daemon startup preamble: the first
/// registration in a process is the one signal-hook documents as racy once
/// other threads exist, and signals arriving during the rest of the startup
/// queue here instead of killing the process.
///
/// Registration is two-phase, following signal-hook's documented shutdown
/// pattern: the first termination signal only arms the escalation flag (and
/// is delivered to the iterator for the graceful shutdown); once armed, the
/// next one terminates the process straight from the signal handler with the
/// shell's 128+N status for death by signal N. Keeping the escalation at
/// handler level means a second signal works even while the signal thread is
/// busy inside the graceful-shutdown callback (e.g. an unmount retrying
/// against a stuck backend).
pub fn register_termination_signals() -> Result<Signals> {
    let termination_signals: Vec<i32> = TERM_SIGNALS.iter().copied().chain([SIGHUP]).collect();
    let armed = Arc::new(AtomicBool::new(false));
    for &signal in &termination_signals {
        // Order matters: the conditional shutdown must be registered before
        // the arming flag, or the first signal would arm and then terminate
        // in the same delivery.
        flag::register_conditional_shutdown(signal, 128 + signal, Arc::clone(&armed))
            .with_context(|| format!("failed to register forced shutdown for signal {signal}"))?;
        flag::register(signal, Arc::clone(&armed))
            .with_context(|| format!("failed to register signal {signal}"))?;
    }

    Signals::new(&termination_signals).context("failed to register termination signals")
}

/// A running daemon signal thread, spawned by [`spawn_signal_thread`].
pub struct SignalThread {
    name: String,
    handle: Handle,
    thread: std::thread::JoinHandle<()>,
}

/// Implement the shutdown for SignalThread.
impl SignalThread {
    /// Stop listening for signals and join the thread.
    pub fn shutdown(self) -> Result<()> {
        self.handle.close();
        self.thread
            .join()
            .map_err(|_| Error::Runtime(format!("{} signal thread panicked", self.name)))
    }
}

/// Spawn the signal thread shared by the uffd/nbd/ublk/fanotify daemons: the
/// first termination signal is logged and runs `on_first` (the daemon's
/// graceful shutdown). A second signal while the graceful shutdown is in
/// progress forces an immediate exit straight from the signal handler — see
/// [`register_termination_signals`] — rather than requiring SIGKILL. `name`
/// is the short daemon name used for the thread name and error contexts.
pub fn spawn_signal_thread(
    name: &str,
    mut signals: Signals,
    on_first: impl FnOnce() + Send + 'static,
) -> Result<SignalThread> {
    let handle = signals.handle();
    let thread = std::thread::Builder::new()
        .name(format!("nydus_{name}_signal"))
        .spawn(move || {
            // First signal: run the daemon's graceful shutdown. Escalation on
            // a second signal lives in the signal handler itself, so there is
            // nothing more to drain here even while `on_first` is still
            // running.
            if let Some(signal) = signals.forever().next() {
                // Log the symbolic signal name, falling back to the raw
                // number for signals signal-hook cannot name.
                let signal_name = signal_hook::low_level::signal_name(signal)
                    .map(str::to_string)
                    .unwrap_or_else(|| signal.to_string());
                info!("received signal {signal_name}, stopping the daemon");
                on_first();
            }
        })
        .with_context(|| format!("failed to spawn {name} signal thread"))?;

    Ok(SignalThread {
        name: name.to_string(),
        handle,
        thread,
    })
}

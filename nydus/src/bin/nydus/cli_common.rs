//! Shared CLI plumbing for the `nydus` subcommands: the log flag blocks that
//! every command repeats, the daemon startup preamble (signal registration +
//! tracing + storage config), and the daemon shutdown helpers (signal thread
//! + unmount retry loop).

use std::path::{Path, PathBuf};

use clap::Args;
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use nydus::error::Error;
use nydus::error::{Context, Result};
#[cfg(any(feature = "fanotify", feature = "nbd"))]
use nydus::mount::unmount;
use nydus_config::Config;
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use nydus_telemetry::logging::{init_tracing, WorkerGuard};
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use signal_hook::iterator::{Handle, Signals};
use tracing::Level;
#[cfg(any(feature = "fanotify", feature = "nbd"))]
use tracing::{debug, error};
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use tracing::{info, warn};

/// Log flags shared by the long-running daemon subcommands
/// (fuse/fanotify/nbd/ublk/uffd). Flatten with `#[command(flatten)]`.
#[derive(Args)]
pub struct DaemonLogArgs {
    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(
        long,
        default_value_os_t = PathBuf::from("/var/log/nydus/"),
        help = "Specify the log directory"
    )]
    pub log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        help = "Specify the max number of log files"
    )]
    pub log_max_files: usize,

    #[arg(long, hide = true, default_value_t = true)]
    pub console: bool,
}

/// Log flags shared by the one-shot commands (build/merge/optimize/check),
/// which log to the console only.
#[derive(Args)]
pub struct CommandLogArgs {
    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        help = "Specify whether to print log"
    )]
    pub console: bool,
}

/// Image source flags shared by the daemon subcommands
/// (fanotify/nbd/ublk/uffd): the bootstrap to serve and the storage config it
/// is served with. Flatten with `#[command(flatten)]`.
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
#[derive(Args)]
pub struct ImageSourceArgs {
    /// File path to nydus bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// File path to a YAML storage config providing backend/cache directories.
    #[arg(long)]
    pub config: PathBuf,
}

/// Load the YAML storage config from `path` with the shared error context.
pub fn load_storage_config(path: &Path) -> Result<Config> {
    Config::load(path).context("failed to load storage config")
}

/// Default worker parallelism: the available CPU count clamped to
/// `[min, max]`.
pub fn default_parallelism(min: usize, max: usize) -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(min)
        .clamp(min, max)
}

/// The daemon startup preamble shared by uffd/nbd/ublk/fanotify: register
/// termination signals (TERM set + SIGHUP), initialize file tracing, and load
/// the storage config. The returned guards must stay alive for the daemon's
/// lifetime or file logging stops.
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
pub fn daemon_preamble(
    log: &DaemonLogArgs,
    config_path: &Path,
) -> Result<(Signals, Vec<WorkerGuard>, Config)> {
    let signals = Signals::new(TERM_SIGNALS.iter().copied().chain([SIGHUP]))
        .context("failed to register termination signals")?;
    let guards = init_tracing(
        "nydus",
        log.log_dir.clone(),
        log.log_level,
        log.log_max_files,
        log.console,
    );
    let config = load_storage_config(config_path)?;
    Ok((signals, guards, config))
}

/// Shutdown unmount retry window: EBUSY is expected while readers still hold
/// files open, so keep trying for a bounded window (10 s) before giving up.
#[cfg(any(feature = "fanotify", feature = "nbd"))]
const UNMOUNT_RETRY_ATTEMPTS: u32 = 40;
#[cfg(any(feature = "fanotify", feature = "nbd"))]
const UNMOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// True when an unmount error means "nothing is mounted there" (EINVAL: not a
/// mount point; ENOENT: the path is gone), so retrying is pointless.
#[cfg(any(feature = "fanotify", feature = "nbd"))]
fn is_not_mounted(err: &Error) -> bool {
    matches!(
        err.io_error().and_then(|io| io.raw_os_error()),
        Some(libc::EINVAL) | Some(libc::ENOENT)
    )
}

/// Unmount `mountpoint` during a daemon shutdown, retrying for a bounded
/// window: EBUSY is expected while readers still hold files open.
/// `between_attempts` runs between two attempts (e.g. fanotify deny-drains
/// newly queued events); `failure_hint` is appended to the error logged when
/// the final attempt still fails.
#[cfg(any(feature = "fanotify", feature = "nbd"))]
pub fn unmount_with_retry(
    mountpoint: &Path,
    mut between_attempts: impl FnMut(),
    failure_hint: &str,
) {
    for attempt in 1..=UNMOUNT_RETRY_ATTEMPTS {
        match unmount(mountpoint) {
            Ok(()) => {
                info!("unmounted {}", mountpoint.display());
                break;
            }
            // Nothing mounted (e.g. the signal arrived before the mount
            // happened): retrying would only stall the shutdown for the
            // whole retry window.
            Err(err) if is_not_mounted(&err) => {
                debug!(
                    "nothing mounted at {}: {}",
                    mountpoint.display(),
                    err.report()
                );
                break;
            }
            Err(err) if attempt < UNMOUNT_RETRY_ATTEMPTS => {
                debug!(
                    "unmount attempt {attempt} failed: {}; retrying",
                    err.report()
                );
                between_attempts();
                std::thread::sleep(UNMOUNT_RETRY_DELAY);
            }
            Err(err) => {
                error!(
                    "failed to unmount {} after {UNMOUNT_RETRY_ATTEMPTS} attempts: {}; \
                     {failure_hint}",
                    mountpoint.display(),
                    err.report()
                );
                break;
            }
        }
    }
}

/// A running daemon signal thread, spawned by [`spawn_signal_thread`].
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
pub struct SignalThread {
    name: String,
    handle: Handle,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
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
/// first termination signal logs `stopping` and runs `on_first` (the daemon's
/// graceful shutdown). A second signal while the graceful shutdown is in
/// progress (e.g. a stuck backend keeping readers blocked) forces exit rather
/// than requiring SIGKILL. `name` is the short daemon name used for the
/// thread name and error contexts.
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
pub fn spawn_signal_thread(
    name: &str,
    stopping: &str,
    mut signals: Signals,
    on_first: impl FnOnce() + Send + 'static,
) -> Result<SignalThread> {
    let handle = signals.handle();
    let stopping = stopping.to_string();
    let thread = std::thread::Builder::new()
        .name(format!("nydus_{name}_signal"))
        .spawn(move || {
            let mut on_first = Some(on_first);
            for signal in signals.forever() {
                match on_first.take() {
                    Some(on_first) => {
                        info!("received signal {signal}, stopping {stopping}");
                        on_first();
                    }
                    None => {
                        warn!("received second signal {signal}, forcing immediate exit");
                        std::process::exit(130);
                    }
                }
            }
        })
        .with_context(|| format!("failed to spawn {name} signal thread"))?;
    Ok(SignalThread {
        name: name.to_string(),
        handle,
        thread,
    })
}

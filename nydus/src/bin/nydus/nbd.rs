use clap::Parser;
use nydus::error::{Context, Error, Result};
use nydus::mount::{umount2, unmount};
use nydus::nbd::{mount_nbd, NbdCore, NbdService};
use nydus::signal;
use nydus_config::Config;
use nydus_telemetry::logging::init_tracing;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn, Level};

use super::*;

/// How long to wait for the kernel to commit the NBD device geometry after
/// `NBD_DO_IT` starts before giving up on the mount; the commit normally
/// lands within microseconds.
const CAPACITY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default worker-thread cap: connection-level parallelism saturates well
/// before this, and every worker costs a kernel connection (one blk-mq
/// hardware queue each). An explicit `--threads` is not capped.
const DEFAULT_MAX_THREADS: usize = 16;

/// The subcommand of nbd.
#[derive(Debug, Clone, Parser)]
pub struct NbdCommand {
    #[arg(
        long,
        env = "NYDUS_NBD_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_NBD_CONFIG",
        help = "Specify the file path to a YAML storage config providing backend/cache directories"
    )]
    config: PathBuf,

    #[arg(
        long,
        env = "NYDUS_NBD_DEVICE",
        help = "Specify the path to the NBD device node to attach (e.g. /dev/nbd0)"
    )]
    device: String,

    #[arg(
        long,
        env = "NYDUS_NBD_THREADS",
        help = "Specify the number of worker threads servicing the NBD socket, each with its own socket pair so concurrent backend fetches overlap. Defaults to the available CPU count, capped at 16"
    )]
    threads: Option<NonZeroUsize>,

    #[arg(
        long,
        default_value_t = NonZeroU64::new(60).unwrap(),
        env = "NYDUS_NBD_TIMEOUT",
        help = "Specify the seconds the kernel NBD driver waits for one reply before failing the request and tearing the session down. Must exceed the worst-case cold fetch of a single read from the backend (registry latency included). Zero is rejected: the kernel would silently keep its own default"
    )]
    timeout: NonZeroU64,

    #[arg(
        long,
        env = "NYDUS_NBD_MOUNTPOINT",
        help = "Specify the mountpoint for the NBD block device. When given, the daemon mounts the device as EROFS once the session is live and unmounts it on shutdown; when omitted, only the device is attached and the caller mounts it"
    )]
    mountpoint: Option<PathBuf>,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_NBD_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_NBD_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_NBD_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_NBD_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Determine the default number of worker threads for the NBD socket.
fn default_nbd_threads() -> NonZeroUsize {
    NonZeroUsize::new(default_parallelism(1, DEFAULT_MAX_THREADS)).unwrap()
}

/// Implement the execute for NbdCommand.
impl NbdCommand {
    /// Executes the nbd sub command, exporting the nydus image as a block
    /// device through the NBD protocol until a termination signal arrives.
    pub fn execute(&self) -> Result<()> {
        // Register the termination signals (TERM set + SIGHUP).
        let signals = signal::register_termination_signals()?;

        // Initialize tracing. The returned guards must stay alive for the
        // daemon's lifetime or file logging stops.
        let _guards = init_tracing(
            NAME,
            self.log_dir.clone(),
            self.log_level,
            self.log_max_files,
            self.console,
        );

        // Load the storage config.
        let config = Config::load(&self.config)?;

        // Runs the NBD service until shutdown.
        self.run(signals, config)
    }

    /// Runs the NBD service: builds the core, attaches the device, spawns
    /// the workers, optionally mounts the device, and serves until a
    /// termination signal stops it.
    fn run(&self, signals: signal::Signals, config: Config) -> Result<()> {
        let core =
            Arc::new(NbdCore::new(&self.bootstrap, config).context("failed to build nbd core")?);
        let service = Arc::new(NbdService::new(
            core.clone(),
            &self.device,
            self.timeout.get(),
        )?);
        let threads = self.threads.unwrap_or_else(default_nbd_threads);

        info!(
            "nydus nbd service attached to {} ({} blocks, {} bytes, {} worker thread(s))",
            self.device,
            core.block_count(),
            core.device_size(),
            threads
        );

        // Each worker owns its own socket pair; the kernel dispatches requests
        // across them once `NBD_DO_IT` runs.
        let mut worker_handles = Vec::new();
        for i in 0..threads.get() {
            let worker = service.create_worker()?;
            worker_handles.push(
                std::thread::Builder::new()
                    .name(format!("nydus_nbd_worker_{i}"))
                    .spawn(move || worker.run())
                    .context("failed to spawn nbd worker thread")?,
            );
        }

        let mountpoint = self.mountpoint.clone();
        let device = self.device.clone();

        // Signal thread: the first termination signal performs the ordered
        // shutdown — unmount (if mounted) BEFORE `stop()` clears the socket,
        // because the kernel must keep serving the umount's own reads and tearing
        // the session down first would leave a live mount backed by a dead device.
        // A second signal forces immediate exit.
        let signal_service = service.clone();
        let signal_mountpoint = mountpoint.clone();
        let signal_thread = signal::spawn_signal_thread("nbd", signals, move || {
            if let Some(mp) = &signal_mountpoint {
                if let Err(err) = unmount(mp, || {}) {
                    error!("{}", err.report());
                }
            }
            signal_service.stop();
        })?;

        let outcome = if let Some(mp) = mountpoint {
            // `NBD_DO_IT` blocks its thread, so run it on a dedicated one and
            // mount from here once the kernel has committed the device geometry
            // (deferred into `NBD_DO_IT` since ~6.13, see `wait_for_capacity`).
            let doit_service = service.clone();
            let doit_handle = std::thread::Builder::new()
                .name("nydus_nbd_loop".to_string())
                .spawn(move || doit_service.run())
                .context("failed to spawn nbd event loop thread")?;

            let mounted = service
                .wait_for_capacity(core.device_size(), CAPACITY_WAIT_TIMEOUT)
                .context("nbd device did not reach the expected capacity")
                .and_then(|()| mount_nbd(&device, &mp, "erofs"));

            match mounted {
                Ok(()) => {
                    info!("mounted {device} at {}", mp.display());
                    // Block until the session ends (clean disconnect or `stop()`
                    // from the signal thread).
                    let joined = doit_handle
                        .join()
                        .map_err(|_| Error::Runtime("nbd event loop thread panicked".to_string()));
                    // The signal path already unmounted on a signal-driven
                    // shutdown; if the session self-exited the mount is still up
                    // over a dead device, so try a final best-effort umount.
                    if let Err(err) = umount2(&mp) {
                        debug!("post-join unmount of {}: {}", mp.display(), err.report());
                    }
                    joined
                }
                Err(err) => {
                    // The session is live but nothing got mounted: stop it so the
                    // event loop and the workers drain through the joins below.
                    warn!(
                        "failed to mount {device} at {}: {}",
                        mp.display(),
                        err.report()
                    );
                    service.stop();
                    let _ = doit_handle.join();
                    // Both `wait_for_capacity` and `mount_nbd` already attach
                    // self-sufficient context — no extra layer needed.
                    Err(err)
                }
            }
        } else {
            // Pure NBD: no mount to own. Block on `NBD_DO_IT` on this thread; the
            // signal thread's `stop()` (clear-sock) unblocks it.
            service.run();
            Ok(())
        };

        // Workers see the inactive flag / closed socket and exit; join them so a
        // stuck worker is surfaced rather than left dangling.
        for handle in worker_handles {
            if handle.join().is_err() {
                warn!("nbd worker thread panicked during join");
            }
        }

        signal_thread.shutdown()?;
        outcome
    }
}

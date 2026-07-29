use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use nydus::config::Config;
use nydus::nbd::{mount_nbd, unmount_nbd, NbdCore, NbdService};
use nydus::tracing::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use tracing::{debug, error, info, warn, Level};

/// EBUSY is expected while readers still hold files open, so keep trying for a
/// bounded window before giving up — mirrors the fanotify shutdown ordering.
const UNMOUNT_RETRY_ATTEMPTS: u32 = 40;
const UNMOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// How long to wait for the kernel to commit the NBD device geometry after
/// `NBD_DO_IT` starts before giving up on the mount; the commit normally
/// lands within microseconds.
const CAPACITY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Args)]
pub struct NbdArgs {
    /// File path to nydus bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// File path to a YAML storage config providing backend/cache directories.
    #[arg(long)]
    pub config: PathBuf,

    /// Path to the NBD device node to attach (e.g. /dev/nbd0).
    #[arg(long)]
    pub device: String,

    /// Number of worker threads servicing the NBD socket, each with its own
    /// socket pair so concurrent backend fetches overlap. Defaults to the
    /// available CPU count, capped at 16.
    #[arg(long)]
    pub threads: Option<NonZeroUsize>,

    /// Seconds the kernel NBD driver waits for one reply before failing the
    /// request and tearing the session down. Must exceed the worst-case cold
    /// fetch of a single read from the backend (registry latency included).
    /// Zero is rejected: the kernel would silently keep its own default.
    #[arg(long, default_value_t = NonZeroU64::new(60).unwrap())]
    pub timeout: NonZeroU64,

    /// Mountpoint for the NBD block device. When given, the daemon mounts the
    /// device as EROFS once the session is live and unmounts it on shutdown;
    /// when omitted, only the device is attached and the caller mounts it.
    #[arg(long)]
    pub mountpoint: Option<PathBuf>,

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

/// Default worker-thread cap: connection-level parallelism saturates well
/// before this, and every worker costs a kernel connection (one blk-mq
/// hardware queue each). An explicit `--threads` is not capped.
const DEFAULT_MAX_THREADS: usize = 16;

fn default_nbd_threads() -> NonZeroUsize {
    let cpus = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1);
    NonZeroUsize::new(cpus.min(DEFAULT_MAX_THREADS)).unwrap()
}

/// True when an unmount error means "nothing is mounted there" (EINVAL: not a
/// mount point; ENOENT: the path is gone), so retrying is pointless.
fn not_mounted(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<std::io::Error>()
            .and_then(|io| io.raw_os_error()),
        Some(libc::EINVAL) | Some(libc::ENOENT)
    )
}

pub fn run_nbd_service(args: NbdArgs) -> Result<()> {
    let mut signals = Signals::new(TERM_SIGNALS.iter().copied().chain([SIGHUP]))
        .context("failed to register termination signals")?;
    let signal_handle = signals.handle();

    let _guards = init_tracing(
        "nydus",
        args.log_dir.clone(),
        args.log_level,
        args.log_max_files,
        args.console,
    );

    let config = Config::from_file(&args.config).context("failed to load storage config")?;
    let core = Arc::new(NbdCore::new(&args.bootstrap, config).context("failed to build nbd core")?);
    let service = Arc::new(NbdService::new(
        core.clone(),
        &args.device,
        args.timeout.get(),
    )?);
    let threads = args.threads.unwrap_or_else(default_nbd_threads);

    info!(
        "nydus nbd service attached to {} ({} blocks, {} bytes, {} worker thread(s))",
        args.device,
        core.blocks(),
        core.flat_size(),
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

    let mountpoint = args.mountpoint;
    let device = args.device;

    // Signal thread: the first termination signal performs the ordered
    // shutdown — unmount (if mounted) BEFORE `stop()` clears the socket,
    // because the kernel must keep serving the umount's own reads and tearing
    // the session down first would leave a live mount backed by a dead device.
    // A second signal forces immediate exit.
    let signal_service = service.clone();
    let signal_mountpoint = mountpoint.clone();
    let signal_thread = std::thread::Builder::new()
        .name("nydus_nbd_signal".to_string())
        .spawn(move || {
            let mut first = true;
            for signal in signals.forever() {
                if first {
                    first = false;
                    info!("received signal {signal}, stopping nydus nbd service");
                    if let Some(mp) = &signal_mountpoint {
                        for attempt in 1..=UNMOUNT_RETRY_ATTEMPTS {
                            match unmount_nbd(mp) {
                                Ok(()) => {
                                    info!("unmounted {}", mp.display());
                                    break;
                                }
                                // Nothing mounted (signal arrived before the
                                // mount happened): retrying would only stall
                                // the shutdown for the whole retry window.
                                Err(err) if not_mounted(&err) => {
                                    debug!("nothing mounted at {}: {err:#}", mp.display());
                                    break;
                                }
                                Err(err) if attempt < UNMOUNT_RETRY_ATTEMPTS => {
                                    debug!("unmount attempt {attempt} failed: {err:#}; retrying");
                                    std::thread::sleep(UNMOUNT_RETRY_DELAY);
                                }
                                Err(err) => {
                                    error!(
                                        "failed to unmount {} after {UNMOUNT_RETRY_ATTEMPTS} \
                                         attempts: {err:#}; the device will be detached anyway — \
                                         unmount manually if needed",
                                        mp.display()
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    signal_service.stop();
                } else {
                    warn!("received second signal {signal}, forcing immediate exit");
                    std::process::exit(130);
                }
            }
        })
        .context("failed to spawn nbd signal thread")?;

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
            .wait_for_capacity(core.flat_size(), CAPACITY_WAIT_TIMEOUT)
            .context("nbd device did not reach the expected capacity")
            .and_then(|()| mount_nbd(&device, &mp, "erofs"));

        match mounted {
            Ok(()) => {
                info!("mounted {device} at {}", mp.display());
                // Block until the session ends (clean disconnect or `stop()`
                // from the signal thread).
                let joined = doit_handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("nbd event loop thread panicked"));
                // The signal path already unmounted on a signal-driven
                // shutdown; if the session self-exited the mount is still up
                // over a dead device, so try a final best-effort umount.
                if let Err(err) = unmount_nbd(&mp) {
                    debug!("post-join unmount of {}: {err:#}", mp.display());
                }
                joined
            }
            Err(err) => {
                // The session is live but nothing got mounted: stop it so the
                // event loop and the workers drain through the joins below.
                warn!("failed to mount {device} at {}: {err:#}", mp.display());
                service.stop();
                let _ = doit_handle.join();
                Err(err).context("failed to mount nbd device")
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

    signal_handle.close();
    let _ = signal_thread.join();
    outcome
}

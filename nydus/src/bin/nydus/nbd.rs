use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;
use nydus::error::{Context, Error, Result};

use crate::cli_common;
use nydus::mount::unmount;
use nydus::nbd::{mount_nbd, NbdCore, NbdService};
use tracing::{debug, info, warn};

/// How long to wait for the kernel to commit the NBD device geometry after
/// `NBD_DO_IT` starts before giving up on the mount; the commit normally
/// lands within microseconds.
const CAPACITY_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Args)]
pub struct NbdArgs {
    #[command(flatten)]
    pub source: cli_common::ImageSourceArgs,

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

    #[command(flatten)]
    pub log: cli_common::DaemonLogArgs,
}

/// Default worker-thread cap: connection-level parallelism saturates well
/// before this, and every worker costs a kernel connection (one blk-mq
/// hardware queue each). An explicit `--threads` is not capped.
const DEFAULT_MAX_THREADS: usize = 16;

fn default_nbd_threads() -> NonZeroUsize {
    NonZeroUsize::new(cli_common::default_parallelism(1, DEFAULT_MAX_THREADS)).unwrap()
}

pub fn run_nbd(args: NbdArgs) -> Result<()> {
    let (signals, _guards, config) = cli_common::daemon_preamble(&args.log, &args.source.config)?;
    let core =
        Arc::new(NbdCore::new(&args.source.bootstrap, config).context("failed to build nbd core")?);
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

    let mountpoint = args.mountpoint;
    let device = args.device;

    // Signal thread: the first termination signal performs the ordered
    // shutdown — unmount (if mounted) BEFORE `stop()` clears the socket,
    // because the kernel must keep serving the umount's own reads and tearing
    // the session down first would leave a live mount backed by a dead device.
    // A second signal forces immediate exit.
    let signal_service = service.clone();
    let signal_mountpoint = mountpoint.clone();
    let signal_thread =
        cli_common::spawn_signal_thread("nbd", "nydus nbd service", signals, move || {
            if let Some(mp) = &signal_mountpoint {
                cli_common::unmount_with_retry(
                    mp,
                    || {},
                    "the device will be detached anyway — unmount manually if needed",
                );
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
                if let Err(err) = unmount(&mp) {
                    debug!("post-join unmount of {}: {err}", mp.display());
                }
                joined
            }
            Err(err) => {
                // The session is live but nothing got mounted: stop it so the
                // event loop and the workers drain through the joins below.
                warn!("failed to mount {device} at {}: {err}", mp.display());
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

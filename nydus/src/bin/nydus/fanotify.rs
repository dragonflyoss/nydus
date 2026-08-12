use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli_common;
use nydus::fanotify::{deny_queued_events, mount_erofs, FanotifyCore, FanotifyService, FetchPool};
use tracing::{info, warn};

#[derive(Args)]
pub struct FanotifyArgs {
    #[command(flatten)]
    pub source: cli_common::ImageSourceArgs,

    /// Mountpoint for the file-backed EROFS bootstrap. The daemon mounts the
    /// bootstrap with `device=` options after the fanotify group is ready, and
    /// unmounts during shutdown. The mount and its lifecycle are owned by this
    /// daemon so that shutdown can unmount before the fail-open fd drop.
    #[arg(long)]
    pub mountpoint: PathBuf,

    /// Maximum number of concurrent blob fetches. Defaults to max(ncpu, 64).
    /// Fetch is network-bound, so the default is larger than the CPU count.
    #[arg(long, default_value_t = default_fetch_concurrency())]
    pub fetch_concurrency: NonZeroUsize,

    #[command(flatten)]
    pub log: cli_common::DaemonLogArgs,
}

fn default_fetch_concurrency() -> NonZeroUsize {
    NonZeroUsize::new(cli_common::default_parallelism(64, usize::MAX)).unwrap()
}

/// Raise the open-file soft limit to the hard limit. Each in-flight cold read
/// pins a dup'd event fd until its fetch completes, and admission is unbounded,
/// so a container-startup storm against a slow backend can otherwise exhaust a
/// default (e.g. 1024) soft limit — surfacing as a fatal `read` failure. Best
/// effort: on failure the daemon still runs, just closer to that cliff.
fn raise_nofile_limit() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        warn!(
            "fanotify: getrlimit(NOFILE) failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    if lim.rlim_cur >= lim.rlim_max {
        return;
    }
    let target = lim.rlim_max;
    lim.rlim_cur = target;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
        warn!(
            "fanotify: setrlimit(NOFILE) to {target} failed: {}",
            std::io::Error::last_os_error()
        );
    } else {
        info!("fanotify: raised RLIMIT_NOFILE soft limit to {target}");
    }
}

pub fn run_fanotify(args: FanotifyArgs) -> Result<()> {
    let (signals, _guards, config) = cli_common::daemon_preamble(&args.log, &args.source.config)?;

    raise_nofile_limit();
    let core = std::sync::Arc::new(
        FanotifyCore::new(&args.source.bootstrap, config)
            .context("failed to build fanotify core")?,
    );

    let service = FanotifyService::new(core.clone())?;
    let device_count = core.devices().len();

    // Thread pool for fetch jobs, bounded by --fetch-concurrency.
    let pool = Arc::new(FetchPool::new(args.fetch_concurrency.get())?);

    // Stop handle for the service's self-pipe: writing wakes the epoll-based
    // event loop for shutdown.
    let stop = service.stop_handle();

    let signal_thread = {
        let stop = stop.clone();
        cli_common::spawn_signal_thread("fanotify", "nydus fanotify service", signals, move || {
            stop.stop()
        })?
    };

    let (ready_tx, ready_rx) = mpsc::channel();

    // Spawn the event loop on a dedicated thread so we can wait for readiness
    // before mounting.  `service.run` blocks until the stop signal arrives or
    // a fatal error occurs.
    let bootstrap = args.source.bootstrap.clone();
    let mountpoint = args.mountpoint.clone();
    let loop_handle = std::thread::Builder::new()
        .name("nydus_fanotify_loop".to_string())
        .spawn(move || service.run(ready_tx, pool))
        .context("failed to spawn fanotify event loop thread")?;

    // Wait for the event loop to be ready.
    ready_rx
        .recv()
        .context("fanotify event loop exited before becoming ready")?;

    info!(
        "nydus fanotify event loop ready for {} blob device(s), bootstrap {}",
        device_count,
        bootstrap.display()
    );

    // Mount the EROFS bootstrap now that the fanotify group is ready.
    match mount_erofs(&bootstrap, core.devices(), &mountpoint) {
        Ok(()) => info!("mounted file-backed EROFS at {}", mountpoint.display()),
        Err(err) => {
            warn!("failed to mount file-backed EROFS: {err:#}");
            // Stop the loop and join it. The loop never served a request, so its
            // returned fd can be dropped without unmounting (nothing is mounted).
            stop.stop();
            let _ = loop_handle.join();
            return Err(err).context("failed to mount file-backed EROFS");
        }
    }

    // Wait for the event loop to exit (clean stop or fatal error). It hands back
    // the group fd in both cases, having already denied outstanding events so the
    // mount is quiescent.
    let (fan_fd, outcome) = loop_handle
        .join()
        .map_err(|_| anyhow::anyhow!("fanotify event loop thread panicked"))?;

    // Unmount BEFORE dropping the fd: `fanotify_release` fail-opens any residue,
    // and unmounting first ensures those ALLOWs cannot reach a live filesystem.
    // This holds on the fatal path too, which is why the loop returns the fd.
    // EBUSY is expected while readers still hold files open, so retry for a
    // bounded window, deny-draining newly queued events in between — a reader
    // racing the shutdown gets EPERM (fail-closed) instead of blocking forever
    // and wedging the unmount.
    cli_common::unmount_with_retry(
        &mountpoint,
        || {
            if let Err(err) = deny_queued_events(&fan_fd) {
                warn!("deny-draining fanotify events between unmount retries failed: {err:#}");
            }
        },
        "dropping the fanotify group fd will fail-open residual events and unfetched ranges on \
         the still-live mount will read as zeros — stop remaining readers and unmount manually",
    );
    drop(fan_fd);

    signal_thread.shutdown()?;

    outcome
}

use clap::Parser;
use nydus::error::{Context, Error, Result};
use nydus::fanotify::{deny_queued_events, mount_erofs, FanotifyCore, FanotifyService, FetchPool};
use nydus_config::Config;
use nydus_telemetry::logging::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use tracing::{info, warn, Level};

use super::*;

/// The subcommand of fanotify.
#[derive(Debug, Clone, Parser)]
pub struct FanotifyCommand {
    #[arg(
        long,
        env = "NYDUS_FANOTIFY_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_FANOTIFY_CONFIG",
        help = "Specify the file path to a YAML storage config providing backend/cache directories"
    )]
    config: PathBuf,

    #[arg(
        long,
        env = "NYDUS_FANOTIFY_MOUNTPOINT",
        help = "Specify the mountpoint for the file-backed EROFS bootstrap. The daemon mounts the bootstrap with `device=` options after the fanotify group is ready, and unmounts during shutdown. The mount and its lifecycle are owned by this daemon so that shutdown can unmount before the fail-open fd drop"
    )]
    mountpoint: PathBuf,

    #[arg(
        long,
        default_value_t = default_fetch_concurrency(),
        env = "NYDUS_FANOTIFY_FETCH_CONCURRENCY",
        help = "Specify the maximum number of concurrent blob fetches. Defaults to max(ncpu, 64). Fetch is network-bound, so the default is larger than the CPU count"
    )]
    fetch_concurrency: NonZeroUsize,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_FANOTIFY_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_FANOTIFY_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_FANOTIFY_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_FANOTIFY_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Determine the default maximum number of concurrent blob fetches.
fn default_fetch_concurrency() -> NonZeroUsize {
    NonZeroUsize::new(default_parallelism(64, usize::MAX)).unwrap()
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

/// Implement the execute for FanotifyCommand.
impl FanotifyCommand {
    /// Executes the fanotify sub command, serving the EROFS image on demand
    /// through fanotify pre-content hooks until a termination signal arrives.
    pub fn execute(&self) -> Result<()> {
        // Register the termination signals (TERM set + SIGHUP).
        let signals = Signals::new(TERM_SIGNALS.iter().copied().chain([SIGHUP]))
            .context("failed to register termination signals")?;

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
        let config = Config::load(&self.config).context("failed to load storage config")?;

        raise_nofile_limit();
        let core = std::sync::Arc::new(
            FanotifyCore::new(&self.bootstrap, config).context("failed to build fanotify core")?,
        );

        let service = FanotifyService::new(core.clone())?;
        let device_count = core.devices().len();

        // Thread pool for fetch jobs, bounded by --fetch-concurrency.
        let pool = Arc::new(FetchPool::new(self.fetch_concurrency.get())?);

        // Stop handle for the service's self-pipe: writing wakes the epoll-based
        // event loop for shutdown.
        let stop = service.stop_handle();

        let signal_thread = {
            let stop = stop.clone();
            spawn_signal_thread("fanotify", "nydus fanotify service", signals, move || {
                stop.stop()
            })?
        };

        let (ready_tx, ready_rx) = mpsc::channel();

        // Spawn the event loop on a dedicated thread so we can wait for readiness
        // before mounting.  `service.run` blocks until the stop signal arrives or
        // a fatal error occurs.
        let bootstrap = self.bootstrap.clone();
        let mountpoint = self.mountpoint.clone();
        let loop_handle = std::thread::Builder::new()
            .name("nydus_fanotify_loop".to_string())
            .spawn(move || service.run(ready_tx, pool))
            .context("failed to spawn fanotify event loop thread")?;

        // Wait for the event loop to be ready.
        ready_rx.recv().map_err(|err| {
            Error::Runtime(format!(
                "fanotify event loop exited before becoming ready: {err}"
            ))
        })?;

        info!(
            "nydus fanotify event loop ready for {} blob device(s), bootstrap {}",
            device_count,
            bootstrap.display()
        );

        // Mount the EROFS bootstrap now that the fanotify group is ready.
        match mount_erofs(&bootstrap, core.devices(), &mountpoint) {
            Ok(()) => info!("mounted file-backed EROFS at {}", mountpoint.display()),
            Err(err) => {
                warn!("failed to mount file-backed EROFS: {}", err.report());
                // Stop the loop and join it. The loop never served a request, so its
                // returned fd can be dropped without unmounting (nothing is mounted).
                stop.stop();
                let _ = loop_handle.join();
                // `mount_erofs` already reports "failed to mount file-backed
                // EROFS {bootstrap} at {mountpoint}" — no extra layer needed.
                return Err(err);
            }
        }

        // Wait for the event loop to exit (clean stop or fatal error). It hands back
        // the group fd in both cases, having already denied outstanding events so the
        // mount is quiescent.
        let (fan_fd, outcome) = loop_handle
            .join()
            .map_err(|_| Error::Runtime("fanotify event loop thread panicked".to_string()))?;

        // Unmount BEFORE dropping the fd: `fanotify_release` fail-opens any residue,
        // and unmounting first ensures those ALLOWs cannot reach a live filesystem.
        // This holds on the fatal path too, which is why the loop returns the fd.
        // EBUSY is expected while readers still hold files open, so retry for a
        // bounded window, deny-draining newly queued events in between — a reader
        // racing the shutdown gets EPERM (fail-closed) instead of blocking forever
        // and wedging the unmount.
        unmount_with_retry(
            &mountpoint,
            || {
                if let Err(err) = deny_queued_events(&fan_fd) {
                    warn!(
                        "deny-draining fanotify events between unmount retries failed: {}",
                        err.report()
                    );
                }
            },
            "dropping the fanotify group fd will fail-open residual events and unfetched ranges on \
             the still-live mount will read as zeros — stop remaining readers and unmount manually",
        );
        drop(fan_fd);

        signal_thread.shutdown()?;

        outcome
    }
}

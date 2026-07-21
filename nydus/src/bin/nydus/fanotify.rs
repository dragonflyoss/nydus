use std::num::NonZeroUsize;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use nydus::config::Config;
use nydus::fanotify::{mount_erofs, unmount_erofs, FanotifyCore, FanotifyService};
use nydus::tracing::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use tracing::{debug, error, info, warn, Level};

const STOP_WAKE_BYTES: usize = 1;

// Shutdown unmount retry window: EBUSY is expected while readers still hold
// files open, so keep trying (deny-draining new events in between) for 10 s
// before giving up.
const UNMOUNT_RETRY_ATTEMPTS: u32 = 40;
const UNMOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Args)]
pub struct FanotifyArgs {
    /// File path to nydus bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// File path to a YAML storage config providing backend/cache directories.
    #[arg(long)]
    pub config: PathBuf,

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

fn default_fetch_concurrency() -> NonZeroUsize {
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    NonZeroUsize::new(ncpu.max(64)).unwrap()
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

pub fn run_fanotify_service(args: FanotifyArgs) -> Result<()> {
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

    raise_nofile_limit();

    let config = Config::from_file(&args.config).context("failed to load storage config")?;
    let core = std::sync::Arc::new(
        FanotifyCore::new(&args.bootstrap, config).context("failed to build fanotify core")?,
    );

    let service = FanotifyService::setup(core.clone())?;
    let device_count = core.devices().len();

    // Thread pool for fetch jobs, bounded by --fetch-concurrency.
    let pool = Arc::new(nydus::fanotify::service::FetchPool::new(
        args.fetch_concurrency.get(),
    )?);

    // Self-pipe for stop signal: the signal thread writes to the pipe to
    // wake the epoll-based event loop.
    let mut pipe_fds = [-1i32; 2];
    let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    anyhow::ensure!(
        ret == 0,
        "pipe2 failed: {}",
        std::io::Error::last_os_error()
    );
    // pipe_fds[0] is owned exclusively by the event-loop thread below;
    // wrapping it into a second OwnedFd here would double-close it.
    let stop_write = pipe_fds[1]; // raw fd, handed to signal thread

    let stop_write_signal = stop_write;
    let _signal_thread = std::thread::Builder::new()
        .name("nydus_fanotify_signal".to_string())
        .spawn(move || {
            let mut first = true;
            for signal in signals.forever() {
                if first {
                    first = false;
                    info!("received signal {signal}, stopping nydus fanotify service");
                    let buf = [1u8; STOP_WAKE_BYTES];
                    unsafe {
                        libc::write(
                            stop_write_signal,
                            buf.as_ptr() as *const libc::c_void,
                            buf.len(),
                        )
                    };
                } else {
                    // A second signal while a graceful shutdown is in progress
                    // (e.g. a stuck backend keeping readers blocked) forces exit
                    // rather than requiring SIGKILL.
                    warn!("received second signal {signal}, forcing immediate exit");
                    std::process::exit(130);
                }
            }
        })
        .context("failed to spawn fanotify signal thread")?;

    let (ready_tx, ready_rx) = mpsc::channel();

    // Spawn the event loop on a dedicated thread so we can wait for readiness
    // before mounting.  `service.run` blocks until the stop signal arrives or
    // a fatal error occurs.
    let bootstrap = args.bootstrap.clone();
    let mountpoint = args.mountpoint.clone();
    let loop_handle = {
        let service = service;
        let stop_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        std::thread::Builder::new()
            .name("nydus_fanotify_loop".to_string())
            .spawn(move || service.run(stop_read, ready_tx, pool))
            .context("failed to spawn fanotify event loop thread")?
    };

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
            let buf = [1u8; STOP_WAKE_BYTES];
            unsafe { libc::write(stop_write, buf.as_ptr() as *const libc::c_void, buf.len()) };
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
    for attempt in 1..=UNMOUNT_RETRY_ATTEMPTS {
        match unmount_erofs(&mountpoint) {
            Ok(()) => {
                info!("unmounted {}", mountpoint.display());
                break;
            }
            Err(err) if attempt < UNMOUNT_RETRY_ATTEMPTS => {
                debug!("unmount attempt {attempt} failed: {err:#}; retrying");
                if let Err(err) = nydus::fanotify::service::deny_queued_events(&fan_fd) {
                    warn!("deny-draining fanotify events between unmount retries failed: {err:#}");
                }
                std::thread::sleep(UNMOUNT_RETRY_DELAY);
            }
            Err(err) => {
                error!(
                    "failed to unmount {} after {UNMOUNT_RETRY_ATTEMPTS} attempts: {err:#}; \
                     dropping the fanotify group fd will fail-open residual events and \
                     unfetched ranges on the still-live mount will read as zeros — stop \
                     remaining readers and unmount manually",
                    mountpoint.display()
                );
            }
        }
    }
    drop(fan_fd);

    signal_handle.close();
    let _ = unsafe { libc::close(stop_write) };

    outcome
}

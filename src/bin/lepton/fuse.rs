use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use fuser::{Config as FuseConfig, MountOption, Session};
use lepton::config::Config;
use lepton::fs::{ErofsFs, ErofsReader};
use lepton::storage::backend::{build_backend, BlobBackend, LocalBackend};
use lepton::storage::prefetch::{BlobPrefetcher, DEFAULT_PREFETCH_THREADS};
use lepton::tracing::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;
use tracing::{error, info, warn, Level};

struct TermSignalMask {
    mask: libc::sigset_t,
    restore_on_drop: bool,
}

impl TermSignalMask {
    fn new() -> Result<Self> {
        let mut mask = unsafe { MaybeUninit::<libc::sigset_t>::zeroed().assume_init() };
        let empty_ret = unsafe { libc::sigemptyset(&mut mask) };
        if empty_ret != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to initialize signal mask");
        }
        for signal in termination_signals() {
            let add_ret = unsafe { libc::sigaddset(&mut mask, *signal) };
            if add_ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to add signal {signal} to mask"));
            }
        }

        Ok(Self {
            mask,
            restore_on_drop: false,
        })
    }

    fn block() -> Result<Self> {
        let mut mask = Self::new()?;

        let mask_ret =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask.mask, std::ptr::null_mut()) };
        if mask_ret != 0 {
            return Err(std::io::Error::from_raw_os_error(mask_ret))
                .context("failed to block termination signals");
        }

        mask.restore_on_drop = true;
        Ok(mask)
    }

    fn wait(&self) -> Result<i32> {
        let mut signal = 0;
        let wait_ret = unsafe { libc::sigwait(&self.mask, &mut signal) };
        if wait_ret != 0 {
            return Err(std::io::Error::from_raw_os_error(wait_ret))
                .context("failed to wait for termination signal");
        }
        Ok(signal)
    }
}

fn termination_signals() -> impl Iterator<Item = &'static libc::c_int> {
    TERM_SIGNALS.iter().chain(std::iter::once(&SIGHUP))
}

impl Drop for TermSignalMask {
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = unsafe {
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &self.mask, std::ptr::null_mut())
            };
        }
    }
}

fn is_mountpoint_active(mountpoint: &Path) -> std::io::Result<bool> {
    let metadata = match fs::metadata(mountpoint) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };

    let Some(parent) = mountpoint.parent() else {
        return Ok(true);
    };
    let parent_metadata = fs::metadata(parent)?;

    Ok(metadata.dev() != parent_metadata.dev()
        || (metadata.dev() == parent_metadata.dev() && metadata.ino() == parent_metadata.ino()))
}

#[derive(Args)]
pub struct FuseArgs {
    /// Directory path including lepton data blob.
    #[arg(long)]
    pub blob_dir: Option<PathBuf>,

    /// Directory path for persistent chunk cache files.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// File path to a YAML storage config providing backend/cache directories
    /// and prefetch options. When set, --blob-dir and --cache-dir can be omitted.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Enable background blob prefetch after mounting. Off by default; when
    /// --config is provided, the config's `prefetch.enable` also turns it on.
    #[arg(long, default_value_t = false)]
    pub prefetch: bool,

    /// File path to lepton bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// File path to lepton blob.
    #[arg(long)]
    pub blob: Option<PathBuf>,

    /// Directory path to mount lepton filesystem.
    #[arg(long)]
    pub mountpoint: PathBuf,

    /// Number of worker threads.
    #[arg(long, hide = true, default_value_t = default_threads())]
    pub threads: usize,

    /// Filesystem name shown in /proc/mounts SOURCE column.
    #[arg(long, hide = true, default_value = "lepton")]
    pub fsname: String,

    /// Serve Prometheus metrics over a Unix socket, e.g.
    /// `unix:///run/lepton/api.sock`. The metrics are exposed at `/metrics`.
    #[arg(long)]
    pub apiserver: Option<String>,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(
        long,
        default_value_os_t = PathBuf::from("/var/log/lepton/"),
        help = "Specify the log directory"
    )]
    pub log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        help = "Specify the max number of log files"
    )]
    pub log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        help = "Specify whether to print log"
    )]
    pub console: bool,
}

/// Determine the default number of worker threads for FUSE mounting, clamped to a reasonable
/// range.
fn default_threads() -> usize {
    let n = available_parallelism().map(|x| x.get()).unwrap_or(4);
    n.clamp(4, 16)
}

/// Run the FUSE mount command.
pub fn run_fuse_mount(args: FuseArgs) -> Result<()> {
    // Block termination signals before starting any helper threads so later
    // sigwait-based handling is the only path that consumes them.
    let _blocked_signals = TermSignalMask::block()?;

    let _guards = init_tracing(
        "lepton",
        args.log_dir.clone(),
        args.log_level,
        args.log_max_files,
        args.console,
    );

    let mountpoint = &args.mountpoint;
    if !mountpoint.is_dir() {
        bail!("mountpoint {} is not a directory", mountpoint.display());
    }

    // Load the optional storage config. CLI flags take precedence over config
    // values, so --blob-dir/--cache-dir override the backend/cache directories.
    let storage_config = match &args.config {
        Some(path) => Some(Config::from_file(path).context("failed to load storage config")?),
        None => None,
    };

    let cache_dir = if let Some(dir) = args.cache_dir.clone() {
        Some(dir)
    } else if let Some(config) = storage_config.as_ref() {
        Some(
            config
                .cache_dir()
                .context("failed to resolve cache directory from config")?,
        )
    } else {
        None
    };

    let (prefetch_enable, prefetch_threads, prefetch_full) = match storage_config.as_ref() {
        Some(config) => (
            config.prefetch.enable || args.prefetch,
            config.prefetch.threads,
            config.prefetch.full,
        ),
        None => (args.prefetch, DEFAULT_PREFETCH_THREADS, false),
    };

    // Build the blob backend. A direct `--blob <path>` is self-contained and
    // needs no backend. Otherwise a `--bootstrap` is served by either an
    // explicit `--blob-dir` (local backend) or the backend from `--config`.
    let backend: Option<Arc<dyn BlobBackend>> = if args.blob.is_some() {
        None
    } else if let Some(dir) = args.blob_dir.as_ref() {
        if !dir.is_dir() {
            bail!("blob-dir {} is not a directory", dir.display());
        }
        Some(Arc::new(LocalBackend::new(dir.clone())))
    } else if let Some(config) = storage_config.as_ref() {
        Some(build_backend(&config.backend).context("failed to build blob backend")?)
    } else {
        None
    };

    match (&args.blob, &args.bootstrap, &backend) {
        (Some(_), None, _) => {}
        (None, Some(_), Some(_)) => {}
        _ => {
            bail!("fuse expects either --blob <path> or --bootstrap <path> with a backend from --blob-dir or --config")
        }
    }
    if let Some(cache_dir) = &cache_dir {
        if cache_dir.exists() && !cache_dir.is_dir() {
            bail!("cache-dir {} is not a directory", cache_dir.display());
        }
    }

    let reader = ErofsReader::open(
        args.blob.as_deref(),
        args.bootstrap.as_deref(),
        backend,
        cache_dir.as_deref(),
    )
    .context("failed to open EROFS image")?;

    let reader = Arc::new(reader);
    let fs = ErofsFs::new(reader.clone());
    let mut config = FuseConfig::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName(args.fsname.clone()),
        MountOption::DefaultPermissions,
    ];
    config.n_threads = Some(args.threads);
    config.clone_fd = true;

    let session =
        Session::new(fs, mountpoint, &config).map_err(|e| anyhow!("mount failed: {e}"))?;
    let bg = session.spawn().map_err(|e| anyhow!("spawn failed: {e}"))?;

    if prefetch_enable {
        match BlobPrefetcher::new(reader.clone(), prefetch_threads, prefetch_full).spawn() {
            Ok(_handle) => info!(
                "started blob prefetch with {} worker threads (full={})",
                prefetch_threads, prefetch_full
            ),
            Err(err) => warn!("failed to start blob prefetch: {}", err),
        }
    } else {
        info!("blob prefetch disabled (enable with --prefetch or the config's prefetch.enable)");
    }

    // Optionally expose Prometheus metrics over a Unix socket. A failure here is
    // non-fatal: the mount keeps serving without metrics.
    let api_server = match args.apiserver.as_deref() {
        Some(address) => match crate::apiserver::ApiServer::start(address) {
            Ok(server) => Some(server),
            Err(err) => {
                warn!("failed to start metrics apiserver: {:#}", err);
                None
            }
        },
        None => None,
    };

    let wait_signals = TermSignalMask::new()?;
    let signal_mountpoint = mountpoint.to_path_buf();
    let (unmount_tx, unmount_rx) = mpsc::channel::<i32>();
    let (result_tx, result_rx) = mpsc::channel::<std::io::Result<()>>();

    std::thread::Builder::new()
        .name("lepton_fuse_controller".to_string())
        .spawn(move || {
            let mut bg = Some(bg);

            loop {
                if bg.as_ref().is_some_and(|bg| bg.guard.is_finished()) {
                    let result = bg.take().expect("background session already taken").join();
                    let _ = result_tx.send(result);
                    return;
                }

                match unmount_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(signal) => {
                        let result = match is_mountpoint_active(&signal_mountpoint) {
                            Ok(true) => {
                                info!("unmounting {}", signal_mountpoint.display());
                                bg.take()
                                    .expect("background session already taken")
                                    .umount_and_join()
                            }
                            Ok(false) => {
                                bg.take().expect("background session already taken").join()
                            }
                            Err(err) => {
                                error!(
                                    "failed to inspect mountpoint {} before unmount: {:?}",
                                    signal_mountpoint.display(),
                                    err
                                );
                                bg.take()
                                    .expect("background session already taken")
                                    .umount_and_join()
                            }
                        };
                        if let Err(err) = &result {
                            if err.raw_os_error() == Some(libc::EINVAL)
                                && is_mountpoint_active(&signal_mountpoint)
                                    .is_ok_and(|active| !active)
                            {
                                let _ = result_tx.send(Ok(()));
                                return;
                            }
                            error!(
                                "failed to unmount after receiving signal {}: {:?}",
                                signal, err
                            );
                        }
                        let _ = result_tx.send(result);
                        return;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let result = bg.take().expect("background session already taken").join();
                        let _ = result_tx.send(result);
                        return;
                    }
                }
            }
        })
        .context("failed to spawn fuse controller thread")?;

    std::thread::Builder::new()
        .name("lepton_fuse_signal".to_string())
        .spawn(move || match wait_signals.wait() {
            Ok(signal) => {
                let _ = unmount_tx.send(signal);
            }
            Err(e) => {
                error!("signal wait error: {:?}", e)
            }
        })
        .context("failed to spawn signal thread")?;

    let join_result = result_rx
        .recv()
        .context("failed to receive fuse controller result")?;

    // Tear down the metrics server before reporting the mount result.
    if let Some(server) = api_server {
        server.stop();
    }

    match &join_result {
        Ok(()) => {}
        Err(e) => error!("background fuse session join returned error: {:?}", e),
    }

    join_result.map_err(|e| anyhow!("join failed: {e}"))?;

    Ok(())
}

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;

use crate::cli_common;
use fuser::{Config as FuseConfig, MountOption, SessionACL};
use nydus::fuse::{ErofsFs, FuseSession, TermSignalMask};
use nydus_core::config::Config;
use nydus_core::config::DEFAULT_PREFETCH_THREADS;
use nydus_core::fs::ErofsReader;
use nydus_core::storage::backend::{build_backend, BlobBackend, LocalBackend};
use nydus_core::storage::prefetch::BlobPrefetcher;
use nydus_core::telemetry::logging::init_tracing;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::available_parallelism;
use tracing::{error, info, warn};

#[derive(Args)]
pub struct FuseArgs {
    /// Directory path including nydus data blob.
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

    /// File path to nydus bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// File path to nydus blob.
    #[arg(long)]
    pub blob: Option<PathBuf>,

    /// Directory path to mount nydus filesystem.
    #[arg(long)]
    pub mountpoint: PathBuf,

    /// Number of worker threads.
    #[arg(long, hide = true, default_value_t = default_threads())]
    pub threads: usize,

    /// Filesystem name shown in /proc/mounts SOURCE column.
    #[arg(long, hide = true, default_value = "nydus")]
    pub fsname: String,

    /// Serve Prometheus metrics over a Unix socket, e.g.
    /// `unix:///run/nydus/api.sock`. The metrics are exposed at `/metrics`.
    #[arg(long)]
    pub apiserver: Option<String>,

    #[command(flatten)]
    pub log: cli_common::DaemonLogArgs,
}

/// Determine the default number of worker threads for FUSE mounting, clamped to a reasonable
/// range.
fn default_threads() -> usize {
    let n = available_parallelism().map(|x| x.get()).unwrap_or(4);
    n.clamp(4, 16)
}

/// Run the FUSE mount command.
pub fn run_fuse(args: FuseArgs) -> Result<()> {
    // Block termination signals before starting any helper threads so later
    // sigwait-based handling is the only path that consumes them.
    let _blocked_signals = TermSignalMask::block()?;

    let _guards = init_tracing(
        "nydus",
        args.log.log_dir.clone(),
        args.log.log_level,
        args.log.log_max_files,
        args.log.console,
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
        Some(nydus_core::storage::backend::metered(Arc::new(
            LocalBackend::new(dir.clone()),
        )))
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
    // Matches nydus v2's fuse_kern_mount: a container rootfs is read by uids
    // other than the daemon's, setuid binaries in the image have to keep
    // working, and nothing on a read-only image can record an access time.
    // fuser's default ACL rejects every request from another uid in userspace,
    // before the kernel's own permission check is ever reached.
    config.acl = SessionACL::All;
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName(args.fsname.clone()),
        MountOption::DefaultPermissions,
        MountOption::Suid,
        MountOption::NoAtime,
    ];
    config.n_threads = Some(args.threads);
    config.clone_fd = true;

    let session = FuseSession::mount(fs, mountpoint, &config)?;

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
        Some(address) => match crate::api_server::ApiServer::start(address) {
            Ok(server) => Some(server),
            Err(err) => {
                warn!("failed to start metrics apiserver: {:#}", err);
                None
            }
        },
        None => None,
    };

    let join_result = session.serve()?;

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

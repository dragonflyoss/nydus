use clap::Parser;
use fuser::{Config as FuseConfig, MountOption, SessionACL};
use nydus::error::{Context, Error, Result};
use nydus::fuse::{ErofsFs, FuseService, TermSignalMask};
use nydus_backend::{build_backend, BlobBackend, Local};
use nydus_config::{
    default_prefetch_concurrent_blob_count, default_prefetch_retry_delay_max,
    default_prefetch_retry_delay_min, default_prefetch_timeout, Config, PrefetchScope,
};
use nydus_core::ErofsReader;
use nydus_storage::prefetch::BlobPrefetcher;
use nydus_telemetry::logging::init_tracing;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn, Level};

use super::*;

/// The subcommand of fuse.
#[derive(Debug, Clone, Parser)]
pub struct FuseCommand {
    #[arg(
        long,
        env = "NYDUS_FUSE_BLOB_DIR",
        help = "Specify the content-addressed store directory holding the blobs recorded in the bootstrap, named by their SHA256"
    )]
    blob_dir: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_FUSE_CACHE_DIR",
        help = "Specify the directory path for persistent chunk cache files"
    )]
    cache_dir: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_FUSE_CONFIG",
        help = "Specify the file path to a YAML storage config providing backend/cache directories and prefetch options. When set, --blob-dir and --cache-dir can be omitted"
    )]
    config: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = false,
        env = "NYDUS_FUSE_PREFETCH",
        help = "Specify whether to enable background blob prefetch after mounting. Off by default; when --config is provided, the config's `prefetch.scope` also turns it on"
    )]
    prefetch: bool,

    #[arg(
        long,
        env = "NYDUS_FUSE_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_FUSE_BLOB",
        help = "Specify the file path to nydus blob"
    )]
    blob: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_FUSE_MOUNTPOINT",
        help = "Specify the directory path to mount nydus filesystem"
    )]
    mountpoint: PathBuf,

    #[arg(
        long,
        hide = true,
        default_value_t = default_threads(),
        env = "NYDUS_FUSE_THREADS",
        help = "Specify the number of worker threads"
    )]
    threads: usize,

    #[arg(
        long,
        hide = true,
        default_value = "nydus",
        env = "NYDUS_FUSE_FSNAME",
        help = "Specify the filesystem name shown in /proc/mounts SOURCE column"
    )]
    fsname: String,

    #[arg(
        long,
        env = "NYDUS_FUSE_APISERVER",
        help = "Specify the address to serve Prometheus metrics over a Unix socket, e.g. `unix:///run/nydus/api.sock`. The metrics are exposed at `/metrics`"
    )]
    apiserver: Option<String>,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_FUSE_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_FUSE_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_FUSE_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_FUSE_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Determine the default number of worker threads for FUSE mounting, clamped to a reasonable
/// range.
fn default_threads() -> usize {
    default_parallelism(4, 16)
}

/// Implement the execute for FuseCommand.
impl FuseCommand {
    /// Executes the fuse sub command, mounting the nydus image through FUSE
    /// and serving it until a termination signal arrives.
    pub fn execute(&self) -> Result<()> {
        // Block termination signals before starting any helper threads so later
        // sigwait-based handling is the only path that consumes them.
        let _blocked_signals = TermSignalMask::block()?;

        // Initialize tracing.
        let _guards = init_tracing(
            NAME,
            self.log_dir.clone(),
            self.log_level,
            self.log_max_files,
            self.console,
        );

        // Validates the mountpoint before any expensive work.
        self.validate()?;

        // Load the optional storage config. CLI flags take precedence over config
        // values, so --blob-dir/--cache-dir override the backend/cache directories.
        let storage_config = match &self.config {
            Some(path) => Some(Config::load(path)?),
            None => None,
        };

        // Runs the FUSE service until shutdown.
        self.run(storage_config)
    }

    /// Validates that the mountpoint is an existing directory.
    fn validate(&self) -> Result<()> {
        if !self.mountpoint.is_dir() {
            return Err(Error::InvalidParameter(format!(
                "mountpoint {} is not a directory",
                self.mountpoint.display()
            )));
        }

        Ok(())
    }

    /// Runs the FUSE service: resolves the cache, prefetch, and backend
    /// settings, opens the EROFS image, mounts it, and serves until a
    /// termination signal stops it.
    fn run(&self, storage_config: Option<Config>) -> Result<()> {
        let mountpoint = &self.mountpoint;

        let cache_dir = if let Some(dir) = self.cache_dir.clone() {
            Some(dir)
        } else {
            storage_config
                .as_ref()
                .and_then(|config| config.storage.dir.clone())
        };

        let (
            prefetch_scope,
            prefetch_concurrent_blob_count,
            prefetch_timeout,
            prefetch_retry_delay_min,
            prefetch_retry_delay_max,
        ) = match storage_config.as_ref() {
            Some(config) => {
                // `--prefetch` forces prefetch on when the config disables it.
                let scope = if config.prefetch.scope == PrefetchScope::None && self.prefetch {
                    PrefetchScope::default()
                } else {
                    config.prefetch.scope
                };
                (
                    scope,
                    config.prefetch.concurrent_blob_count,
                    config.prefetch.timeout,
                    config.prefetch.retry_delay_min,
                    config.prefetch.retry_delay_max,
                )
            }
            None => (
                if self.prefetch {
                    PrefetchScope::default()
                } else {
                    PrefetchScope::None
                },
                default_prefetch_concurrent_blob_count(),
                default_prefetch_timeout(),
                default_prefetch_retry_delay_min(),
                default_prefetch_retry_delay_max(),
            ),
        };

        // Build the blob backend. A direct `--blob <path>` is self-contained and
        // needs no backend. Otherwise a `--bootstrap` is served by either an
        // explicit `--blob-dir` (local backend) or the backend from `--config`.
        let backend: Option<Arc<dyn BlobBackend>> = if self.blob.is_some() {
            None
        } else if let Some(dir) = self.blob_dir.as_ref() {
            if !dir.is_dir() {
                return Err(Error::InvalidParameter(format!(
                    "blob-dir {} is not a directory",
                    dir.display()
                )));
            }
            Some(nydus_backend::metered(Arc::new(Local::new(dir.clone()))))
        } else if let Some(config) = storage_config.as_ref() {
            Some(build_backend(&config.backend).context("failed to build blob backend")?)
        } else {
            None
        };

        if let Some(cache_dir) = &cache_dir {
            if cache_dir.exists() && !cache_dir.is_dir() {
                return Err(Error::InvalidParameter(format!(
                    "cache-dir {} is not a directory",
                    cache_dir.display()
                )));
            }
        }

        let reader = match (&self.blob, &self.bootstrap, backend) {
            (Some(blob), None, _) => ErofsReader::open_blob(blob),
            (None, Some(bootstrap), Some(backend)) => {
                ErofsReader::open_bootstrap(bootstrap, backend, cache_dir.as_deref(), None)
            }
            _ => {
                return Err(Error::InvalidParameter(
                    "fuse expects either --blob <path> or --bootstrap <path> with a backend from --blob-dir or --config".to_string(),
                ))
            }
        }
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
            MountOption::FSName(self.fsname.clone()),
            MountOption::DefaultPermissions,
            MountOption::Suid,
            MountOption::NoAtime,
        ];
        config.n_threads = Some(self.threads);
        config.clone_fd = true;

        let session = FuseService::mount(fs, mountpoint, &config)?;

        let mut prefetch_stop = None;
        if prefetch_scope == PrefetchScope::None {
            info!("blob prefetch disabled (enable with --prefetch or the config's prefetch.scope)");
        } else if cache_dir.is_none() {
            info!("blob prefetch disabled: diskless reads have no cache to warm (set --cache-dir or storage.dir)");
        } else {
            let prefetcher = BlobPrefetcher::new(
                reader.blob_caches(),
                reader.prefetch_plan(),
                prefetch_concurrent_blob_count,
                prefetch_scope,
                prefetch_timeout,
                prefetch_retry_delay_min,
                prefetch_retry_delay_max,
            );
            let stop = prefetcher.stop_flag();
            match prefetcher.spawn() {
                Ok(_handle) => {
                    prefetch_stop = Some(stop);
                    info!(
                        "started blob prefetch (concurrent_blob_count={}, scope={:?})",
                        prefetch_concurrent_blob_count, prefetch_scope
                    );
                }
                Err(err) => warn!("failed to start blob prefetch: {}", err),
            }
        }

        // Optionally expose Prometheus metrics over a Unix socket. A failure here is
        // non-fatal: the mount keeps serving without metrics.
        let api_server = match self.apiserver.as_deref() {
            Some(address) => match api_server::ApiServer::start(address) {
                Ok(server) => Some(server),
                Err(err) => {
                    warn!("failed to start metrics apiserver: {}", err.report());
                    None
                }
            },
            None => None,
        };

        let join_result = session.serve()?;

        // The filesystem is unmounted: wind down the detached prefetch thread
        // (it may be sleeping towards a rescheduled throttled-blob retry).
        if let Some(stop) = prefetch_stop {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // Tear down the metrics server before reporting the mount result.
        if let Some(server) = api_server {
            server.stop();
        }

        match &join_result {
            Ok(()) => {}
            Err(err) => error!("background fuse session join returned error: {:?}", err),
        }

        join_result.context("failed to join fuse session thread")?;

        Ok(())
    }
}

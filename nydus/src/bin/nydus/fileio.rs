use clap::Parser;
use nydus::error::{Context, Result};
use nydus::fileio::{image_path, mount_image_file, warm_bootstrap, FileioService, FlatImageFs};
use nydus::signal;
use nydus_config::Config;
use nydus_core::flat::{FlatImage, BLOCK_SIZE};
use nydus_telemetry::logging::init_tracing;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, Level};

use super::*;

/// Default worker-thread cap for the export. The kernel drives cold reads
/// through EROFS's async pipeline, so a handful of threads keeps concurrent
/// backend fetches overlapping without oversubscribing small guests.
const DEFAULT_MAX_THREADS: usize = 8;

#[derive(Debug, Clone, Parser)]
pub struct FileioCommand {
    #[arg(
        long,
        env = "NYDUS_FILEIO_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_FILEIO_CONFIG",
        help = "Specify the file path to a YAML storage config providing backend/cache directories"
    )]
    config: PathBuf,

    #[arg(
        long,
        env = "NYDUS_FILEIO_EXPORT_DIR",
        help = "Specify the directory where the flattened image file is exported over FUSE"
    )]
    export_dir: PathBuf,

    #[arg(
        long,
        env = "NYDUS_FILEIO_MOUNTPOINT",
        help = "Specify the mountpoint for the EROFS filesystem. When given, the daemon mounts the exported image file once the export is live and unmounts it on shutdown; when omitted, only the file is exported and the caller mounts it"
    )]
    mountpoint: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_FILEIO_THREADS",
        help = "Specify the number of FUSE worker threads serving the exported image file. Defaults to the available CPU count, capped at 8"
    )]
    threads: Option<NonZeroUsize>,

    #[arg(
        long,
        default_value_t = true,
        env = "NYDUS_FILEIO_WARM_BOOTSTRAP",
        help = "Push the bootstrap region into the export's page cache at startup, so the kernel can resolve metadata without faulting it in folio by folio. Measured no difference against a local backend; it can only pay off when fetching the bootstrap is slow",
        action = clap::ArgAction::Set
    )]
    warm_bootstrap: bool,

    #[arg(
        long,
        default_value_t = true,
        env = "NYDUS_FILEIO_DIRECT_IO",
        help = "Mount the image with EROFS 'directio' so the export's page cache stays empty; without it the image data is held both there and against the inode the application reads (measured ~40% more page cache). Warm reads are unaffected; the cost is roughly 80ms on the first read of a cold file, from losing readahead on the export",
        action = clap::ArgAction::Set
    )]
    direct_io: bool,
    #[arg(
        long,
        env = "NYDUS_FILEIO_APISERVER",
        help = "Specify the address to serve Prometheus metrics over a Unix socket, e.g. `unix:///run/nydus/api.sock`. The metrics are exposed at `/metrics`"
    )]
    apiserver: Option<String>,
    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_FILEIO_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_FILEIO_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_FILEIO_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_FILEIO_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

fn default_fileio_threads() -> NonZeroUsize {
    NonZeroUsize::new(default_parallelism(1, DEFAULT_MAX_THREADS)).unwrap()
}

impl FileioCommand {
    /// Export the flattened image over FUSE and, when a mountpoint is given,
    /// mount it as file-backed EROFS until a termination signal arrives.
    pub fn execute(&self) -> Result<()> {
        let signals = signal::register_termination_signals()?;

        // The returned guards must stay alive for the daemon's lifetime or
        // file logging stops.
        let _guards = init_tracing(
            NAME,
            self.log_dir.clone(),
            self.log_level,
            self.log_max_files,
            self.console,
        );

        let config = Config::load(&self.config)?;
        self.run(signals, config)
    }

    fn run(&self, signals: signal::Signals, config: Config) -> Result<()> {
        // The kernel EROFS driver reads the backing file in whole blocks.
        let flat = Arc::new(
            FlatImage::open(&self.bootstrap, config, BLOCK_SIZE)
                .context("failed to build the flattened view")?,
        );
        // Warm the blob preparation (meta download + cache file sizing) in
        // the background so the FUSE export and EROFS mount come up without
        // waiting on backend round trips. flat_layout() is single-flight: a
        // first read arriving early joins the same preparation.
        let warm = flat.core().clone();
        std::thread::Builder::new()
            .name("fileio-blob-warmup".to_string())
            .spawn(move || {
                if let Err(err) = warm.blobs.flat_layout() {
                    tracing::warn!("background blob preparation failed: {err:#}");
                }
            })
            .context("failed to spawn the blob warm-up thread")?;
        let bootstrap_size = flat.core().bootstrap_size;
        let fs = FlatImageFs::new(flat.clone());
        let image_size = fs.image_size();

        let threads = self.threads.unwrap_or_else(default_fileio_threads);
        let mut fuse_config = fuser::Config::default();
        // A container rootfs is read by uids other than the daemon's, and
        // fuser's default ACL rejects those in userspace before the kernel's
        // own permission check is reached. The export itself is read-only.
        fuse_config.acl = fuser::SessionACL::All;
        fuse_config.mount_options = vec![
            fuser::MountOption::RO,
            fuser::MountOption::FSName("nydus-fileio".to_string()),
            fuser::MountOption::NoAtime,
        ];
        fuse_config.n_threads = Some(threads.get());
        fuse_config.clone_fd = true;

        let mut service = FileioService::mount(fs, &self.export_dir, &fuse_config)?;
        let image = image_path(&self.export_dir);
        info!(
            "exported {} as {} ({} bytes, {} worker thread(s))",
            self.bootstrap.display(),
            image.display(),
            image_size,
            threads
        );

        if self.warm_bootstrap {
            // A second handle onto the same shared view; warming reads through
            // exactly the path the export serves.
            let warm_fs = FlatImageFs::new(flat.clone());
            warm_bootstrap(&warm_fs, &service.notifier(), bootstrap_size);
        }

        if let Some(mountpoint) = &self.mountpoint {
            if let Err(err) = mount_image_file(&image, mountpoint, self.direct_io) {
                // Nothing is mounted on top, so ending the session here leaves
                // no stale EROFS mount behind.
                service.shutdown();
                return Err(err);
            }
            service.set_erofs_mountpoint(mountpoint);
            info!("mounted {} at {}", image.display(), mountpoint.display());
        }

        // Non-fatal like the fuse service: the export keeps serving without metrics.
        let api_server = match self.apiserver.as_deref() {
            Some(address) => match crate::api_server::ApiServer::start(address) {
                Ok(server) => Some(server),
                Err(err) => {
                    warn!("failed to start metrics apiserver: {}", err.report());
                    None
                }
            },
            None => None,
        };

        // The export is served on background threads, so the daemon parks
        // here until the signal thread reports a termination signal.
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        let signal_thread = signal::spawn_signal_thread("fileio", signals, move || {
            let _ = shutdown_tx.send(());
        })?;
        let _ = shutdown_rx.recv();

        service.shutdown();
        if let Some(server) = api_server {
            server.stop();
        }
        signal_thread.shutdown()?;
        Ok(())
    }
}

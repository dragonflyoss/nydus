use clap::Parser;
use nydus::error::{Context, Result};
use nydus::nbd::{upgrade::Startup, NbdCore, NbdOptions};
use nydus::pool::FetchPool;
use nydus::signal;
use nydus_config::Config;
use nydus_telemetry::logging::init_tracing;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::Level;

use super::{default_log_dir, default_parallelism, NAME};

/// The default connection cap: connection-level parallelism saturates well
/// before this, and every connection costs a blk-mq hardware queue and a
/// request reader thread. An explicit `--threads` is not capped.
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
        help = "Specify the number of kernel connections (blk-mq hardware queues), 1 to 16, each with its own socket pair and request reader; reads run on the --fetch-concurrency pool. Defaults to the available CPU count, capped at 16; inherited during takeover and recovery"
    )]
    threads: Option<NonZeroUsize>,

    #[arg(
        long,
        default_value_t = default_fetch_concurrency(),
        env = "NYDUS_NBD_FETCH_CONCURRENCY",
        help = "Specify the maximum number of reads served concurrently across all connections, so a slow backend fetch does not hold up later requests on the same connection. Defaults to max(ncpu, 64)"
    )]
    fetch_concurrency: NonZeroUsize,

    #[arg(
        long,
        default_value_t = NonZeroU64::new(60).unwrap(),
        env = "NYDUS_NBD_TIMEOUT",
        help = "Specify the seconds the kernel NBD driver waits for one reply before retrying the request. Must exceed the worst-case cold fetch of a single read from the backend (registry latency included). Zero is rejected: the kernel would silently keep its own default. Inherited during takeover and recovery"
    )]
    timeout: NonZeroU64,

    #[arg(
        long,
        default_value_t = 60,
        env = "NYDUS_NBD_DEAD_CONN_TIMEOUT",
        help = "Specify the seconds I/O stays queued while no connection is alive, as until a crashed daemon is restarted; once it expires, I/O fails until a daemon reattaches. Applied when a session is created and inherited during takeover and recovery"
    )]
    dead_conn_timeout: u64,

    #[arg(
        long,
        env = "NYDUS_NBD_APISERVER",
        help = "Specify an optional Unix HTTP endpoint for metrics, tracing and automatic hot upgrade, e.g. unix:///run/nydus/nbd0.sock"
    )]
    apiserver: Option<String>,

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

/// Returns the default number of kernel connections.
fn default_nbd_threads() -> NonZeroUsize {
    NonZeroUsize::new(default_parallelism(1, DEFAULT_MAX_THREADS)).unwrap()
}

/// Returns the default maximum number of concurrent reads.
fn default_fetch_concurrency() -> NonZeroUsize {
    NonZeroUsize::new(default_parallelism(64, usize::MAX)).unwrap()
}

/// Implement the execute for NbdCommand.
impl NbdCommand {
    /// Executes the nbd sub command, exporting the nydus image as a block
    /// device through the NBD protocol until a termination signal arrives.
    pub fn execute(&self) -> Result<()> {
        // Register the termination signals (TERM set + SIGHUP) and handle them from the start,
        // so a signal during startup cancels it instead of waiting for the session to serve.
        let signals = signal::register_termination_signals()?;
        let stop = Arc::new(AtomicBool::new(false));
        let requested = stop.clone();
        let signal_thread = signal::spawn_signal_thread("nbd", signals, move || {
            requested.store(true, Ordering::Release);
        })?;

        // Initialize tracing. The returned guards must stay alive for the
        // daemon's lifetime or file logging stops.
        let _guards = init_tracing(
            NAME,
            self.log_dir.clone(),
            self.log_level,
            self.log_max_files,
            self.console,
        );

        // Load the storage config and run the NBD service until shutdown.
        let result = Config::load(&self.config).and_then(|config| self.run(stop, config));
        signal_thread.shutdown()?;
        result
    }

    /// Runs the NBD service: builds the core, then attaches, takes over or
    /// recovers the session on the device and serves it until a termination
    /// signal, a release to a successor or a failure.
    fn run(&self, stop: Arc<AtomicBool>, config: Config) -> Result<()> {
        let runtime_dir = config.runtime_dir.clone();
        let core =
            Arc::new(NbdCore::new(&self.bootstrap, config).context("failed to build nbd core")?);
        let api_socket = self
            .apiserver
            .as_deref()
            .map(nydus::parse_unix_address)
            .transpose()?;
        let startup = Startup::new(
            std::path::Path::new(&self.device),
            self.mountpoint.as_deref(),
            &runtime_dir,
            api_socket,
            NbdOptions {
                connections: self.threads.unwrap_or_else(default_nbd_threads).get(),
                timeout_secs: self.timeout.get(),
                dead_conn_timeout_secs: self.dead_conn_timeout,
            },
            core.core(),
        )?;
        let pool = Arc::new(FetchPool::new(self.fetch_concurrency.get())?);
        startup.start(core, pool, stop.clone())?.serve(stop)
    }
}

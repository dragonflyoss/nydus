use clap::Parser;
use nydus::error::{Context, Result};
use nydus::uffd::{UffdCore, UffdService};
use nydus_config::Config;
use nydus_telemetry::logging::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Level;

use super::*;

/// The subcommand of uffd.
#[derive(Debug, Clone, Parser)]
pub struct UffdCommand {
    #[arg(
        long,
        env = "NYDUS_UFFD_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_UFFD_CONFIG",
        help = "Specify the file path to a YAML storage config providing backend/cache directories"
    )]
    config: PathBuf,

    #[arg(
        long,
        env = "NYDUS_UFFD_SOCKET",
        help = "Specify the Unix socket path for the UFFD protocol"
    )]
    socket: PathBuf,

    #[arg(
        long,
        env = "NYDUS_UFFD_THREADS",
        help = "Specify the number of Tokio runtime worker threads. Defaults to the available CPU count"
    )]
    threads: Option<NonZeroUsize>,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_UFFD_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_UFFD_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_UFFD_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_UFFD_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Implement the execute for UffdCommand.
impl UffdCommand {
    /// Executes the uffd sub command, serving the nydus image through
    /// userfaultfd until a termination signal arrives.
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

        let core = Arc::new(UffdCore::new(&self.bootstrap, config)?);
        let service = Arc::new(UffdService::new(core, self.socket.clone()));
        let signal_service = service.clone();
        let signal_thread =
            spawn_signal_thread("uffd", "nydus uffd service", signals, move || {
                signal_service.stop();
            })?;

        let mut runtime = tokio::runtime::Builder::new_multi_thread();
        runtime.enable_all().thread_name("nydus_uffd");
        if let Some(threads) = self.threads {
            runtime.worker_threads(threads.get());
        }
        let rt = runtime.build().context("failed to build tokio runtime")?;
        let result = rt.block_on(service.run());
        signal_thread.shutdown()?;
        result
    }
}

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use nydus::config::Config;
use nydus::tracing::init_tracing;
use nydus::uffd::{UffdCore, UffdOptions, UffdService};
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use tracing::Level;

#[derive(Args)]
pub struct UffdArgs {
    /// File path to nydus bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// File path to a YAML storage config providing backend/cache directories.
    #[arg(long)]
    pub config: PathBuf,

    /// Unix socket path for the UFFD protocol.
    #[arg(long)]
    pub socket: PathBuf,

    /// Number of Tokio runtime worker threads. Defaults to the available CPU count.
    #[arg(long)]
    pub threads: Option<NonZeroUsize>,

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

pub fn run_uffd_service(args: UffdArgs) -> Result<()> {
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

    let config = Config::from_file(&args.config).context("failed to load storage config")?;
    let core = Arc::new(UffdCore::new(UffdOptions {
        bootstrap: args.bootstrap,
        config,
    })?);
    let service = Arc::new(UffdService::new(core, args.socket));
    let signal_service = service.clone();
    let signal_thread = std::thread::Builder::new()
        .name("nydus_uffd_signal".to_string())
        .spawn(move || {
            if let Some(signal) = signals.forever().next() {
                tracing::info!("received signal {signal}, stopping nydus uffd service");
                signal_service.stop();
            }
        })
        .context("failed to spawn UFFD signal thread")?;

    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all().thread_name("nydus_uffd");
    if let Some(threads) = args.threads {
        runtime.worker_threads(threads.get());
    }
    let rt = runtime.build().context("failed to build tokio runtime")?;
    let result = rt.block_on(service.run());
    signal_handle.close();
    signal_thread
        .join()
        .map_err(|_| anyhow!("UFFD signal thread panicked"))?;
    result
}

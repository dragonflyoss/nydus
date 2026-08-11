use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::cli_common;
use nydus::uffd::{UffdCore, UffdService};

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

    #[command(flatten)]
    pub log: cli_common::DaemonLogArgs,
}

pub fn run_uffd(args: UffdArgs) -> Result<()> {
    let (mut signals, _guards, config) = cli_common::daemon_preamble(&args.log, &args.config)?;
    let signal_handle = signals.handle();
    let core = Arc::new(UffdCore::new(&args.bootstrap, config)?);
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

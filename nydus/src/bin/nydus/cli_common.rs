//! Shared CLI plumbing for the `nydus` subcommands: the log flag blocks that
//! every command repeats, and the daemon startup preamble (signal
//! registration + tracing + storage config).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use nydus_core::config::Config;
use nydus::tracing::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;

/// Log flags shared by the long-running daemon subcommands
/// (fuse/fanotify/nbd/ublk/uffd). Flatten with `#[command(flatten)]`.
#[derive(Args)]
pub struct DaemonLogArgs {
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

/// Log flags shared by the one-shot commands (build/merge/optimize/check),
/// which log to the console only.
#[derive(Args)]
pub struct CommandLogArgs {
    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        help = "Specify whether to print log"
    )]
    pub console: bool,
}

/// The daemon startup preamble shared by uffd/nbd/ublk/fanotify: register
/// termination signals (TERM set + SIGHUP), initialize file tracing, and load
/// the storage config. The returned guards must stay alive for the daemon's
/// lifetime or file logging stops.
pub fn daemon_preamble(
    log: &DaemonLogArgs,
    config_path: &Path,
) -> Result<(Signals, Vec<WorkerGuard>, Config)> {
    let signals = Signals::new(TERM_SIGNALS.iter().copied().chain([SIGHUP]))
        .context("failed to register termination signals")?;
    let guards = init_tracing(
        "nydus",
        log.log_dir.clone(),
        log.log_level,
        log.log_max_files,
        log.console,
    );
    let config = Config::from_file(config_path).context("failed to load storage config")?;
    Ok((signals, guards, config))
}

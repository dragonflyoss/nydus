use clap::Parser;
use nydus::error::{Context, Result};
use nydus::signal;
use nydus::ublk::{
    default_queues, UblkCore, UblkOptions, UblkService, DEFAULT_IO_BUF_BYTES, DEFAULT_QUEUE_DEPTH,
};
use nydus_config::Config;
use nydus_telemetry::logging::init_tracing;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};

use super::*;

/// The subcommand of ublk.
#[derive(Debug, Clone, Parser)]
pub struct UblkCommand {
    #[arg(
        long,
        env = "NYDUS_UBLK_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_UBLK_CONFIG",
        help = "Specify the file path to a YAML storage config providing backend/cache directories"
    )]
    config: PathBuf,

    #[arg(
        long,
        default_value_t = -1,
        allow_hyphen_values = true,
        env = "NYDUS_UBLK_DEV_ID",
        help = "Specify the device id to create. Defaults to letting the driver allocate one"
    )]
    dev_id: i32,

    #[arg(
        long,
        env = "NYDUS_UBLK_QUEUES",
        help = "Specify the number of hardware queues; each queue is served by its own thread. Defaults to the CPU count, capped at 4"
    )]
    queues: Option<u16>,

    #[arg(
        long,
        default_value_t = DEFAULT_QUEUE_DEPTH,
        env = "NYDUS_UBLK_DEPTH",
        help = "Specify the per-queue depth, i.e. the number of in-flight block requests"
    )]
    depth: u16,

    #[arg(
        long,
        default_value_t = DEFAULT_IO_BUF_BYTES,
        env = "NYDUS_UBLK_IO_BUF_BYTES",
        help = "Specify the maximum bytes transferred by a single block request"
    )]
    io_buf_bytes: u32,

    #[arg(
        long,
        env = "NYDUS_UBLK_UNPRIVILEGED",
        help = "Specify whether to create the device in unprivileged mode (UBLK_F_UNPRIVILEGED_DEV)"
    )]
    unprivileged: bool,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_UBLK_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_UBLK_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_UBLK_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_UBLK_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Implement the execute for UblkCommand.
impl UblkCommand {
    /// Executes the ublk sub command, serving the nydus image as a read-only
    /// ublk block device until a termination signal arrives.
    ///
    /// The device path is printed to stdout once it is ready, so callers can mount
    /// it with `mount -t erofs <device> <mountpoint>`.
    ///
    /// Note: the daemon must not share a mount namespace with whoever mounts the
    /// device. Otherwise the unmount triggered while the daemon exits flushes I/O
    /// to a device that is no longer being served, and both sides deadlock.
    pub fn execute(&self) -> Result<()> {
        // Register the termination signals (TERM set + SIGHUP).
        let signals = signal::register_termination_signals()?;

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

        let core = Arc::new(UblkCore::new(&self.bootstrap, config)?);
        info!(
            "serving {} as a {} byte block device",
            self.bootstrap.display(),
            core.device_size()
        );

        let options = UblkOptions {
            dev_id: self.dev_id,
            queues: self.queues.unwrap_or_else(default_queues).max(1),
            depth: self.depth.max(1),
            io_buf_bytes: self.io_buf_bytes,
            unprivileged: self.unprivileged,
        };
        let service = UblkService::new(core, &options)?;
        println!("{}", service.dev_path());

        let handle = service.handle();
        let signal_thread = signal::spawn_signal_thread("ublk", signals, move || {
            handle.stop();
        })?;

        let result = service.run();
        service.delete();

        signal_thread.shutdown()?;
        result
    }
}

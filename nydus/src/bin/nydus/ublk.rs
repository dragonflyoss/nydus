use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use nydus::config::Config;
use nydus::tracing::init_tracing;
use nydus::ublk::{
    default_queues, UblkCore, UblkOptions, UblkTarget, DEFAULT_IO_BUF_BYTES, DEFAULT_QUEUE_DEPTH,
};
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use signal_hook::iterator::Signals;
use tracing::{info, Level};

#[derive(Args)]
pub struct UblkArgs {
    /// File path to nydus bootstrap. Every blob it references is served
    /// automatically, so no blob needs to be listed on the command line.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// File path to a YAML storage config providing the backend and cache
    /// directories.
    #[arg(long)]
    pub config: PathBuf,

    /// Device id to create. Defaults to letting the driver allocate one.
    #[arg(long, default_value_t = -1, allow_hyphen_values = true)]
    pub dev_id: i32,

    /// Number of hardware queues; each queue is served by its own thread.
    /// Defaults to the CPU count, capped at 4.
    #[arg(long)]
    pub queues: Option<u16>,

    /// Per-queue depth, i.e. the number of in-flight block requests.
    #[arg(long, default_value_t = DEFAULT_QUEUE_DEPTH)]
    pub depth: u16,

    /// Maximum bytes transferred by a single block request.
    #[arg(long, default_value_t = DEFAULT_IO_BUF_BYTES)]
    pub io_buf_bytes: u32,

    /// Create the device in unprivileged mode (UBLK_F_UNPRIVILEGED_DEV).
    #[arg(long)]
    pub unprivileged: bool,

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

/// Serve a nydus image as a read-only ublk block device.
///
/// The device path is printed to stdout once it is ready, so callers can mount
/// it with `mount -t erofs <device> <mountpoint>`.
///
/// Note: the daemon must not share a mount namespace with whoever mounts the
/// device. Otherwise the unmount triggered while the daemon exits flushes I/O
/// to a device that is no longer being served, and both sides deadlock.
pub fn run_ublk(args: UblkArgs) -> Result<()> {
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
    let core = Arc::new(UblkCore::new(&args.bootstrap, config)?);
    info!(
        "serving {} as a {} byte block device",
        args.bootstrap.display(),
        core.device_size()
    );

    let options = UblkOptions {
        dev_id: args.dev_id,
        queues: args.queues.unwrap_or_else(default_queues).max(1),
        depth: args.depth.max(1),
        io_buf_bytes: args.io_buf_bytes,
        unprivileged: args.unprivileged,
    };
    let target = UblkTarget::new(core, &options)?;
    println!("{}", target.dev_path());

    let handle = target.handle();
    let signal_thread = std::thread::Builder::new()
        .name("nydus_ublk_signal".to_string())
        .spawn(move || {
            if let Some(signal) = signals.forever().next() {
                info!("received signal {signal}, stopping nydus ublk device");
                handle.stop();
            }
        })
        .context("failed to spawn ublk signal thread")?;

    let result = target.run();
    target.delete();

    signal_handle.close();
    signal_thread
        .join()
        .map_err(|_| anyhow!("ublk signal thread panicked"))?;
    result
}

use std::sync::Arc;

use anyhow::Result;
use clap::Args;

use crate::cli_common;
use nydus::ublk::{
    default_queues, UblkCore, UblkOptions, UblkService, DEFAULT_IO_BUF_BYTES, DEFAULT_QUEUE_DEPTH,
};
use tracing::info;

#[derive(Args)]
pub struct UblkArgs {
    #[command(flatten)]
    pub source: cli_common::ImageSourceArgs,

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

    #[command(flatten)]
    pub log: cli_common::DaemonLogArgs,
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
    let (signals, _guards, config) = cli_common::daemon_preamble(&args.log, &args.source.config)?;
    let core = Arc::new(UblkCore::new(&args.source.bootstrap, config)?);
    info!(
        "serving {} as a {} byte block device",
        args.source.bootstrap.display(),
        core.device_size()
    );

    let options = UblkOptions {
        dev_id: args.dev_id,
        queues: args.queues.unwrap_or_else(default_queues).max(1),
        depth: args.depth.max(1),
        io_buf_bytes: args.io_buf_bytes,
        unprivileged: args.unprivileged,
    };
    let service = UblkService::new(core, &options)?;
    println!("{}", service.dev_path());

    let handle = service.handle();
    let signal_thread =
        cli_common::spawn_signal_thread("ublk", "nydus ublk device", signals, move || {
            handle.stop();
        })?;

    let result = service.run();
    service.delete();

    signal_thread.shutdown()?;
    result
}

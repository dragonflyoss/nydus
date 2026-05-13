use std::path::Path;
use std::sync::Arc;
use std::thread::available_parallelism;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, ValueEnum};
use log::{error, info, LevelFilter};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use simple_logger::SimpleLogger;

use fuser::{Config, MountOption, Session};

use lepton::fs::{ErofsFs, ErofsReader};

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Driver {
    /// Mount via FUSE.
    Fuse,
}

#[derive(Args)]
pub struct MountArgs {
    /// EROFS image file.
    image: String,

    /// Mount point.
    mountpoint: String,

    /// Mount driver (default: fuse).
    #[arg(long, value_enum, default_value_t = Driver::Fuse)]
    pub driver: Driver,

    /// Optional blob device for chunk-based files.
    #[arg(long)]
    blobdev: Option<String>,

    /// Number of worker threads.
    #[arg(long, default_value_t = default_threads())]
    threads: usize,

    /// Filesystem name shown in /proc/mounts SOURCE column.
    #[arg(long, default_value = "lepton")]
    fsname: String,
}

/// Determine the default number of worker threads for FUSE mounting, clamped to a reasonable
/// range.
fn default_threads() -> usize {
    let n = available_parallelism().map(|x| x.get()).unwrap_or(4);
    n.clamp(4, 16)
}

/// Run the FUSE mount driverEROFS.
pub fn run_fuse_mount(args: MountArgs) -> Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .map_err(|e| anyhow!("failed to init logger: {}", e))?;

    let mountpoint = Path::new(&args.mountpoint);
    if !mountpoint.is_dir() {
        bail!("mountpoint {} is not a directory", args.mountpoint);
    }

    // ErofsReader::open() is async — use a temporary tokio runtime for initialization.
    let reader = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build tokio runtime")?;
        rt.block_on(ErofsReader::open(&args.image, args.blobdev.as_deref()))
            .context("failed to open EROFS image")?
    };
    info!(
        "opened EROFS image: root_nid={}, blocks={}, inos={}",
        reader.sb().root_nid(),
        reader.sb().blocks(),
        reader.sb().inos()
    );

    let fs = ErofsFs::new(Arc::new(reader));
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName(args.fsname.clone()),
        MountOption::DefaultPermissions,
    ];
    config.n_threads = Some(args.threads);
    config.clone_fd = true;

    let mut session =
        Session::new(fs, mountpoint, &config).map_err(|e| anyhow!("mount failed: {}", e))?;
    info!("mounted on {}", args.mountpoint);

    let mut unmounter = session.unmount_callable();

    // Spawn a thread to wait for termination signals and trigger unmount.
    let mut signals = Signals::new(TERM_SIGNALS).context("failed to register signal handler")?;
    std::thread::Builder::new()
        .name("lepton_fuse_signal".to_string())
        .spawn(move || {
            if let Some(_sig) = signals.forever().next() {
                info!("received termination signal, unmounting...");
                if let Err(e) = unmounter.unmount() {
                    error!("unmount error: {:?}", e);
                }
            }
        })
        .context("failed to spawn signal thread")?;

    // Run the session loop in the background and wait for it to finish.
    let bg = session
        .spawn()
        .map_err(|e| anyhow!("spawn failed: {}", e))?;
    bg.join().map_err(|e| anyhow!("join failed: {}", e))?;

    Ok(())
}

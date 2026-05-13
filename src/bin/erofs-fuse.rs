// erofs-fuse — mount an EROFS image via FUSE.
//
// Usage:
//   sudo erofs-fuse <image> <mountpoint> [--blobdev <path>]

use std::io::{Error, Result};
use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use log::{error, info, LevelFilter};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use simple_logger::SimpleLogger;

use fuser::{MountOption, Session};

use mkfs_erofs::fs::{ErofsFs, ErofsReader};

#[derive(Parser)]
#[command(name = "erofs-fuse", about = "Mount an EROFS image via FUSE")]
struct Args {
    /// EROFS image file
    image: String,

    /// Mount point
    mountpoint: String,

    /// Optional blob device for chunk-based files
    #[arg(long)]
    blobdev: Option<String>,

    /// Filesystem name shown in /proc/mounts SOURCE column
    #[arg(long, default_value = "erofs-fuse")]
    fsname: String,
}

fn main() -> Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();

    let args = Args::parse();

    let mountpoint = Path::new(&args.mountpoint);
    if !mountpoint.is_dir() {
        error!("mountpoint {} is not a directory", args.mountpoint);
        return Err(Error::from_raw_os_error(libc::EINVAL));
    }

    // ErofsReader::open() is async — use a temporary tokio runtime for initialization.
    let reader = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        rt.block_on(ErofsReader::open(&args.image, args.blobdev.as_deref()))?
    };
    info!(
        "opened EROFS image: root_nid={}, blocks={}, inos={}",
        reader.sb().root_nid(),
        reader.sb().blocks(),
        reader.sb().inos()
    );

    let fs = ErofsFs::new(Arc::new(reader));

    let mount_options = vec![
        MountOption::RO,
        MountOption::FSName(args.fsname.clone()),
        MountOption::DefaultPermissions,
    ];

    let mut session = Session::new(fs, mountpoint, &mount_options)
        .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("{}", e)))?;
    info!("mounted on {}", args.mountpoint);

    let mut unmounter = session.unmount_callable();

    // Spawn a thread to wait for termination signals and trigger unmount.
    let mut signals =
        Signals::new(TERM_SIGNALS).map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
    std::thread::Builder::new()
        .name("erofs_fuse_signal".to_string())
        .spawn(move || {
            for _sig in signals.forever() {
                info!("received termination signal, unmounting...");
                if let Err(e) = unmounter.unmount() {
                    error!("unmount error: {:?}", e);
                }
                break;
            }
        })
        .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("{}", e)))?;

    // Run the session loop on the main thread until the filesystem is unmounted.
    session
        .run()
        .map_err(|e| Error::new(std::io::ErrorKind::Other, format!("{}", e)))?;

    Ok(())
}

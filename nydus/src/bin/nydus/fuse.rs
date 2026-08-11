use anyhow::{anyhow, bail, Context, Result};
use clap::Args;

use crate::cli_common;
use fuser::{Config as FuseConfig, MountOption, Session, SessionACL};
use nydus::config::Config;
use nydus::fs::ErofsReader;
use nydus::fuse::ErofsFs;
use nydus::storage::backend::{build_backend, BlobBackend, LocalBackend};
use nydus::storage::prefetch::{BlobPrefetcher, DEFAULT_PREFETCH_THREADS};
use nydus::tracing::init_tracing;
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use std::fs;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;
use tracing::{error, info, warn};

struct TermSignalMask {
    mask: libc::sigset_t,
    restore_on_drop: bool,
}

impl TermSignalMask {
    fn new() -> Result<Self> {
        let mut mask = unsafe { MaybeUninit::<libc::sigset_t>::zeroed().assume_init() };
        let empty_ret = unsafe { libc::sigemptyset(&mut mask) };
        if empty_ret != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to initialize signal mask");
        }
        for signal in termination_signals() {
            let add_ret = unsafe { libc::sigaddset(&mut mask, *signal) };
            if add_ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to add signal {signal} to mask"));
            }
        }

        Ok(Self {
            mask,
            restore_on_drop: false,
        })
    }

    fn block() -> Result<Self> {
        let mut mask = Self::new()?;

        let mask_ret =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask.mask, std::ptr::null_mut()) };
        if mask_ret != 0 {
            return Err(std::io::Error::from_raw_os_error(mask_ret))
                .context("failed to block termination signals");
        }

        mask.restore_on_drop = true;
        Ok(mask)
    }

    fn wait(&self) -> Result<i32> {
        let mut signal = 0;
        let wait_ret = unsafe { libc::sigwait(&self.mask, &mut signal) };
        if wait_ret != 0 {
            return Err(std::io::Error::from_raw_os_error(wait_ret))
                .context("failed to wait for termination signal");
        }
        Ok(signal)
    }
}

fn termination_signals() -> impl Iterator<Item = &'static libc::c_int> {
    TERM_SIGNALS.iter().chain(std::iter::once(&SIGHUP))
}

impl Drop for TermSignalMask {
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = unsafe {
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &self.mask, std::ptr::null_mut())
            };
        }
    }
}

/// Returns the `major:minor` that /proc/self/mountinfo reports for
/// `mountpoint`, or `None` when nothing is mounted there.
///
/// Read from mountinfo rather than stat() so that it stays answerable while the
/// session is being torn down, and deliberately not the mount ID: the kernel
/// recycles those as soon as a mount is destroyed, so a successor at the same
/// path routinely inherits the ID its predecessor had.
fn mount_dev_of(mountpoint: &Path) -> std::io::Result<Option<String>> {
    let target = match fs::canonicalize(mountpoint) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut found = None;
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        let (Some(_id), Some(_parent), Some(dev), Some(_root), Some(point)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if unescape_mountinfo(point) != target.as_os_str().to_string_lossy() {
            continue;
        }
        // Later entries shadow earlier ones when mounts are stacked.
        found = Some(dev.to_string());
    }

    Ok(found)
}

/// mountinfo escapes space, tab, newline and backslash as octal sequences.
fn unescape_mountinfo(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let octal: String = chars.clone().take(3).collect();
        match u8::from_str_radix(&octal, 8) {
            Ok(byte) if octal.len() == 3 => {
                out.push(byte as char);
                for _ in 0..3 {
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Tears the session down, unmounting only while the mount at `mountpoint` is
/// still the one we created.
///
/// fuser unmounts by path: both `BackgroundSession::umount_and_join` and the
/// `Mount` destructor reach `umount(2)` on the mountpoint string, which as root
/// succeeds against whatever happens to be mounted there. Once our own mount is
/// gone that would detach the next daemon's mount, and the victim then dies
/// reporting "Unmount failed: Invalid argument".
///
/// A live session is the authoritative signal that the mount is still ours,
/// because the kernel tears our channel down as soon as the mount goes away.
/// The device number additionally covers a lazy unmount, which detaches the
/// path while leaving the connection open. When neither holds we leak the
/// session rather than dropping it; the process is exiting and there is nothing
/// left to release.
fn finish_session(
    session: fuser::BackgroundSession,
    mountpoint: &Path,
    our_dev: Option<String>,
) -> std::io::Result<()> {
    let session_alive = !session.guard.is_finished();
    let same_dev = match mount_dev_of(mountpoint) {
        Ok(current) => current.is_some() && current == our_dev,
        Err(err) => {
            error!(
                "failed to inspect mountpoint {} before unmount: {:?}",
                mountpoint.display(),
                err
            );
            false
        }
    };

    if session_alive && same_dev {
        info!("unmounting {}", mountpoint.display());
        return session.umount_and_join();
    }

    for _ in 0..100 {
        if session.guard.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::mem::forget(session);
    Ok(())
}

#[derive(Args)]
pub struct FuseArgs {
    /// Directory path including nydus data blob.
    #[arg(long)]
    pub blob_dir: Option<PathBuf>,

    /// Directory path for persistent chunk cache files.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// File path to a YAML storage config providing backend/cache directories
    /// and prefetch options. When set, --blob-dir and --cache-dir can be omitted.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Enable background blob prefetch after mounting. Off by default; when
    /// --config is provided, the config's `prefetch.enable` also turns it on.
    #[arg(long, default_value_t = false)]
    pub prefetch: bool,

    /// File path to nydus bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// File path to nydus blob.
    #[arg(long)]
    pub blob: Option<PathBuf>,

    /// Directory path to mount nydus filesystem.
    #[arg(long)]
    pub mountpoint: PathBuf,

    /// Number of worker threads.
    #[arg(long, hide = true, default_value_t = default_threads())]
    pub threads: usize,

    /// Filesystem name shown in /proc/mounts SOURCE column.
    #[arg(long, hide = true, default_value = "nydus")]
    pub fsname: String,

    /// Serve Prometheus metrics over a Unix socket, e.g.
    /// `unix:///run/nydus/api.sock`. The metrics are exposed at `/metrics`.
    #[arg(long)]
    pub apiserver: Option<String>,

    #[command(flatten)]
    pub log: cli_common::DaemonLogArgs,
}

/// Determine the default number of worker threads for FUSE mounting, clamped to a reasonable
/// range.
fn default_threads() -> usize {
    let n = available_parallelism().map(|x| x.get()).unwrap_or(4);
    n.clamp(4, 16)
}

/// Run the FUSE mount command.
pub fn run_fuse(args: FuseArgs) -> Result<()> {
    // Block termination signals before starting any helper threads so later
    // sigwait-based handling is the only path that consumes them.
    let _blocked_signals = TermSignalMask::block()?;

    let _guards = init_tracing(
        "nydus",
        args.log.log_dir.clone(),
        args.log.log_level,
        args.log.log_max_files,
        args.log.console,
    );

    let mountpoint = &args.mountpoint;
    if !mountpoint.is_dir() {
        bail!("mountpoint {} is not a directory", mountpoint.display());
    }

    // Load the optional storage config. CLI flags take precedence over config
    // values, so --blob-dir/--cache-dir override the backend/cache directories.
    let storage_config = match &args.config {
        Some(path) => Some(Config::from_file(path).context("failed to load storage config")?),
        None => None,
    };

    let cache_dir = if let Some(dir) = args.cache_dir.clone() {
        Some(dir)
    } else if let Some(config) = storage_config.as_ref() {
        Some(
            config
                .cache_dir()
                .context("failed to resolve cache directory from config")?,
        )
    } else {
        None
    };

    let (prefetch_enable, prefetch_threads, prefetch_full) = match storage_config.as_ref() {
        Some(config) => (
            config.prefetch.enable || args.prefetch,
            config.prefetch.threads,
            config.prefetch.full,
        ),
        None => (args.prefetch, DEFAULT_PREFETCH_THREADS, false),
    };

    // Build the blob backend. A direct `--blob <path>` is self-contained and
    // needs no backend. Otherwise a `--bootstrap` is served by either an
    // explicit `--blob-dir` (local backend) or the backend from `--config`.
    let backend: Option<Arc<dyn BlobBackend>> = if args.blob.is_some() {
        None
    } else if let Some(dir) = args.blob_dir.as_ref() {
        if !dir.is_dir() {
            bail!("blob-dir {} is not a directory", dir.display());
        }
        Some(nydus::storage::backend::metered(Arc::new(
            LocalBackend::new(dir.clone()),
        )))
    } else if let Some(config) = storage_config.as_ref() {
        Some(build_backend(&config.backend).context("failed to build blob backend")?)
    } else {
        None
    };

    match (&args.blob, &args.bootstrap, &backend) {
        (Some(_), None, _) => {}
        (None, Some(_), Some(_)) => {}
        _ => {
            bail!("fuse expects either --blob <path> or --bootstrap <path> with a backend from --blob-dir or --config")
        }
    }
    if let Some(cache_dir) = &cache_dir {
        if cache_dir.exists() && !cache_dir.is_dir() {
            bail!("cache-dir {} is not a directory", cache_dir.display());
        }
    }

    let reader = ErofsReader::open(
        args.blob.as_deref(),
        args.bootstrap.as_deref(),
        backend,
        cache_dir.as_deref(),
    )
    .context("failed to open EROFS image")?;

    let reader = Arc::new(reader);
    let fs = ErofsFs::new(reader.clone());
    let mut config = FuseConfig::default();
    // Matches nydus v2's fuse_kern_mount: a container rootfs is read by uids
    // other than the daemon's, setuid binaries in the image have to keep
    // working, and nothing on a read-only image can record an access time.
    // fuser's default ACL rejects every request from another uid in userspace,
    // before the kernel's own permission check is ever reached.
    config.acl = SessionACL::All;
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName(args.fsname.clone()),
        MountOption::DefaultPermissions,
        MountOption::Suid,
        MountOption::NoAtime,
    ];
    config.n_threads = Some(args.threads);
    config.clone_fd = true;

    let session =
        Session::new(fs, mountpoint, &config).map_err(|e| anyhow!("mount failed: {e}"))?;
    let bg = session.spawn().map_err(|e| anyhow!("spawn failed: {e}"))?;

    if prefetch_enable {
        match BlobPrefetcher::new(reader.clone(), prefetch_threads, prefetch_full).spawn() {
            Ok(_handle) => info!(
                "started blob prefetch with {} worker threads (full={})",
                prefetch_threads, prefetch_full
            ),
            Err(err) => warn!("failed to start blob prefetch: {}", err),
        }
    } else {
        info!("blob prefetch disabled (enable with --prefetch or the config's prefetch.enable)");
    }

    // Optionally expose Prometheus metrics over a Unix socket. A failure here is
    // non-fatal: the mount keeps serving without metrics.
    let api_server = match args.apiserver.as_deref() {
        Some(address) => match crate::api_server::ApiServer::start(address) {
            Ok(server) => Some(server),
            Err(err) => {
                warn!("failed to start metrics apiserver: {:#}", err);
                None
            }
        },
        None => None,
    };

    let wait_signals = TermSignalMask::new()?;
    let signal_mountpoint = mountpoint.to_path_buf();
    // Captured before anything can replace the mount, so the teardown below can
    // tell our own mount apart from a successor's at the same path.
    let our_dev = mount_dev_of(mountpoint)
        .with_context(|| format!("failed to read mount device of {}", mountpoint.display()))?;
    let (unmount_tx, unmount_rx) = mpsc::channel::<i32>();
    let (result_tx, result_rx) = mpsc::channel::<std::io::Result<()>>();

    std::thread::Builder::new()
        .name("nydus_fuse_controller".to_string())
        .spawn(move || {
            let mut bg = Some(bg);

            loop {
                if bg.as_ref().is_some_and(|bg| bg.guard.is_finished()) {
                    let session = bg.take().expect("background session already taken");
                    let result = finish_session(session, &signal_mountpoint, our_dev.clone());
                    let _ = result_tx.send(result);
                    return;
                }

                match unmount_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(signal) => {
                        let session = bg.take().expect("background session already taken");
                        let result = finish_session(session, &signal_mountpoint, our_dev.clone());
                        if let Err(err) = &result {
                            error!(
                                "failed to unmount after receiving signal {}: {:?}",
                                signal, err
                            );
                        }
                        let _ = result_tx.send(result);
                        return;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let session = bg.take().expect("background session already taken");
                        let result = finish_session(session, &signal_mountpoint, our_dev.clone());
                        let _ = result_tx.send(result);
                        return;
                    }
                }
            }
        })
        .context("failed to spawn fuse controller thread")?;

    std::thread::Builder::new()
        .name("nydus_fuse_signal".to_string())
        .spawn(move || match wait_signals.wait() {
            Ok(signal) => {
                let _ = unmount_tx.send(signal);
            }
            Err(e) => {
                error!("signal wait error: {:?}", e)
            }
        })
        .context("failed to spawn signal thread")?;

    let join_result = result_rx
        .recv()
        .context("failed to receive fuse controller result")?;

    // Tear down the metrics server before reporting the mount result.
    if let Some(server) = api_server {
        server.stop();
    }

    match &join_result {
        Ok(()) => {}
        Err(e) => error!("background fuse session join returned error: {:?}", e),
    }

    join_result.map_err(|e| anyhow!("join failed: {e}"))?;

    Ok(())
}

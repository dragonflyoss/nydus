use clap::{Parser, Subcommand};
use nydus::error::Result;
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use nydus::error::{Context, Error};
#[cfg(any(feature = "fanotify", feature = "nbd"))]
use nydus::mount::unmount;
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use signal_hook::iterator::{Handle, Signals};
use std::path::PathBuf;
#[cfg(any(feature = "fanotify", feature = "nbd"))]
use tracing::{debug, error};
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
use tracing::{info, warn};

pub mod api_server;
pub mod build;
pub mod check;
#[cfg(feature = "fanotify")]
pub mod fanotify;
pub mod fuse;
pub mod merge;
#[cfg(feature = "nbd")]
pub mod nbd;
pub mod optimize;
#[cfg(feature = "ublk")]
pub mod ublk;
#[cfg(feature = "uffd")]
pub mod uffd;

/// The name of the package.
pub const NAME: &str = "nydus";

/// The short git commit hash of the package.
pub const GIT_COMMIT_SHORT_HASH: &str = {
    match option_env!("GIT_COMMIT_SHORT_HASH") {
        Some(hash) => hash,
        None => "unknown",
    }
};

/// The git commit date of the package.
pub const GIT_COMMIT_DATE: &str = {
    match option_env!("GIT_COMMIT_DATE") {
        Some(hash) => hash,
        None => "unknown",
    }
};

/// A custom value parser for the version flag.
#[derive(Debug, Clone)]
pub struct VersionValueParser;

/// Implement the TypedValueParser trait for VersionValueParser.
impl clap::builder::TypedValueParser for VersionValueParser {
    type Value = bool;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        if value == std::ffi::OsStr::new("true") {
            println!(
                "{} {} ({}, {})",
                cmd.get_name(),
                cmd.get_version().unwrap_or("unknown"),
                GIT_COMMIT_SHORT_HASH,
                GIT_COMMIT_DATE,
            );

            std::process::exit(0);
        }

        Ok(false)
    }
}

#[derive(Debug, Parser)]
#[command(
    name = NAME,
    author,
    version,
    about = "nydus is a command line tool for building and mounting nydus images",
    long_about = "A command line tool for the EROFS-based nydus image format. It builds nydus images \
    from directories, merges layers into an overlaid bootstrap, optimizes images with recorded access \
    patterns, statically checks images, and serves them through FUSE, NBD, ublk, userfaultfd, and \
    fanotify frontends.",
    disable_version_flag = true
)]
struct Args {
    #[arg(
        short = 'V',
        long = "version",
        help = "Print version information",
        default_value_t = false,
        action = clap::ArgAction::SetTrue,
        value_parser = VersionValueParser
    )]
    version: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
#[command(args_conflicts_with_subcommands = true)]
pub enum Command {
    #[command(
        name = "build",
        author,
        version,
        about = "Build a nydus filesystem image",
        long_about = "Build a chunk-based nydus filesystem image from a directory, producing a full blob and an optional standalone bootstrap. With --type nydus-tar, unpack a nydus full blob back into an uncompressed OCI layer tar stream."
    )]
    Build(build::BuildCommand),

    #[command(
        name = "check",
        author,
        version,
        about = "Statically inspect a nydus / EROFS image",
        long_about = "Statically inspect a nydus / EROFS image and print its superblock, filesystem summary, and per-blob details. Fails when the image contains inline data the kernel cannot read."
    )]
    Check(check::CheckCommand),

    #[command(
        name = "merge",
        author,
        version,
        about = "Merge multiple nydus layers into an overlaid bootstrap",
        long_about = "Merge multiple nydus layer blobs into a single overlaid bootstrap, applying the whiteout specification while stacking layers."
    )]
    Merge(merge::MergeCommand),

    #[command(
        name = "optimize",
        author,
        version,
        about = "Build an ondemand blob from an access pattern",
        long_about = "Build an ondemand blob from a recorded access pattern and rewrite the bootstrap, so a later mount can warm the hot working set in recorded order without pulling the whole image."
    )]
    Optimize(optimize::OptimizeCommand),

    #[command(
        name = "fuse",
        author,
        version,
        about = "Mount a nydus image through FUSE",
        long_about = "Mount a nydus image through FUSE and serve reads on demand from a local directory or a configured backend, with optional background blob prefetch and a Prometheus metrics apiserver."
    )]
    Fuse(fuse::FuseCommand),

    #[cfg(feature = "ublk")]
    #[command(
        name = "ublk",
        author,
        version,
        about = "Serve a flattened nydus image as a ublk block device",
        long_about = "Serve a flattened nydus image as a read-only ublk block device. The device path is printed to stdout once it is ready, so callers can mount it with `mount -t erofs <device> <mountpoint>`."
    )]
    Ublk(ublk::UblkCommand),

    #[cfg(feature = "uffd")]
    #[command(
        name = "uffd",
        author,
        version,
        about = "Serve a flattened nydus image through userfaultfd",
        long_about = "Serve a flattened nydus image through userfaultfd for microVM virtio-pmem use cases, resolving page faults over a Unix socket."
    )]
    Uffd(uffd::UffdCommand),

    #[cfg(feature = "fanotify")]
    #[command(
        name = "fanotify",
        author,
        version,
        about = "Serve an EROFS image on demand through fanotify",
        long_about = "Serve an EROFS image on demand through fanotify pre-content hooks (FAN_CLASS_PRE_CONTENT + FAN_PRE_ACCESS, requires Linux >= 6.15). The daemon mounts the file-backed EROFS bootstrap and owns the mount lifecycle."
    )]
    Fanotify(fanotify::FanotifyCommand),

    #[cfg(feature = "nbd")]
    #[command(
        name = "nbd",
        author,
        version,
        about = "Export a nydus image as a block device through the NBD protocol",
        long_about = "Export a nydus image as a read-only block device through the NBD protocol, optionally mounting the device as EROFS once the session is live."
    )]
    Nbd(nbd::NbdCommand),
}

/// Implement the execute for Command.
impl Command {
    pub fn execute(self) -> Result<()> {
        match self {
            Self::Build(cmd) => cmd.execute(),
            Self::Check(cmd) => cmd.execute(),
            Self::Merge(cmd) => cmd.execute(),
            Self::Optimize(cmd) => cmd.execute(),
            Self::Fuse(cmd) => cmd.execute(),
            #[cfg(feature = "ublk")]
            Self::Ublk(cmd) => cmd.execute(),
            #[cfg(feature = "uffd")]
            Self::Uffd(cmd) => cmd.execute(),
            #[cfg(feature = "fanotify")]
            Self::Fanotify(cmd) => cmd.execute(),
            #[cfg(feature = "nbd")]
            Self::Nbd(cmd) => cmd.execute(),
        }
    }
}

fn main() -> std::process::ExitCode {
    // Parse command line arguments.
    let args = Args::parse();

    // Execute the command.
    match args.command.execute() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {}", err.report());
            std::process::ExitCode::FAILURE
        }
    }
}

/// Returns the default log directory for nydus.
pub fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/nydus/")
}

/// Returns the default worker parallelism: the available CPU count clamped to
/// `[min, max]`.
pub fn default_parallelism(min: usize, max: usize) -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(min)
        .clamp(min, max)
}

/// Shutdown unmount retry window: EBUSY is expected while readers still hold
/// files open, so keep trying for a bounded window (10 s) before giving up.
#[cfg(any(feature = "fanotify", feature = "nbd"))]
const UNMOUNT_RETRY_ATTEMPTS: u32 = 40;
#[cfg(any(feature = "fanotify", feature = "nbd"))]
const UNMOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// True when an unmount error means "nothing is mounted there" (EINVAL: not a
/// mount point; ENOENT: the path is gone), so retrying is pointless.
#[cfg(any(feature = "fanotify", feature = "nbd"))]
fn is_not_mounted(err: &Error) -> bool {
    matches!(
        err.io_error().and_then(|io| io.raw_os_error()),
        Some(libc::EINVAL) | Some(libc::ENOENT)
    )
}

/// Unmount `mountpoint` during a daemon shutdown, retrying for a bounded
/// window: EBUSY is expected while readers still hold files open.
/// `between_attempts` runs between two attempts (e.g. fanotify deny-drains
/// newly queued events); `failure_hint` is appended to the error logged when
/// the final attempt still fails.
#[cfg(any(feature = "fanotify", feature = "nbd"))]
pub fn unmount_with_retry(
    mountpoint: &std::path::Path,
    mut between_attempts: impl FnMut(),
    failure_hint: &str,
) {
    for attempt in 1..=UNMOUNT_RETRY_ATTEMPTS {
        match unmount(mountpoint) {
            Ok(()) => {
                info!("unmounted {}", mountpoint.display());
                break;
            }
            // Nothing mounted (e.g. the signal arrived before the mount
            // happened): retrying would only stall the shutdown for the
            // whole retry window.
            Err(err) if is_not_mounted(&err) => {
                debug!(
                    "nothing mounted at {}: {}",
                    mountpoint.display(),
                    err.report()
                );
                break;
            }
            Err(err) if attempt < UNMOUNT_RETRY_ATTEMPTS => {
                debug!(
                    "unmount attempt {attempt} failed: {}; retrying",
                    err.report()
                );
                between_attempts();
                std::thread::sleep(UNMOUNT_RETRY_DELAY);
            }
            Err(err) => {
                error!(
                    "failed to unmount {} after {UNMOUNT_RETRY_ATTEMPTS} attempts: {}; \
                     {failure_hint}",
                    mountpoint.display(),
                    err.report()
                );
                break;
            }
        }
    }
}

/// A running daemon signal thread, spawned by [`spawn_signal_thread`].
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
pub struct SignalThread {
    name: String,
    handle: Handle,
    thread: std::thread::JoinHandle<()>,
}

/// Implement the shutdown for SignalThread.
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
impl SignalThread {
    /// Stop listening for signals and join the thread.
    pub fn shutdown(self) -> Result<()> {
        self.handle.close();
        self.thread
            .join()
            .map_err(|_| Error::Runtime(format!("{} signal thread panicked", self.name)))
    }
}

/// Spawn the signal thread shared by the uffd/nbd/ublk/fanotify daemons: the
/// first termination signal logs `stopping` and runs `on_first` (the daemon's
/// graceful shutdown). A second signal while the graceful shutdown is in
/// progress (e.g. a stuck backend keeping readers blocked) forces exit rather
/// than requiring SIGKILL. `name` is the short daemon name used for the
/// thread name and error contexts.
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
pub fn spawn_signal_thread(
    name: &str,
    stopping: &str,
    mut signals: Signals,
    on_first: impl FnOnce() + Send + 'static,
) -> Result<SignalThread> {
    let handle = signals.handle();
    let stopping = stopping.to_string();
    let thread = std::thread::Builder::new()
        .name(format!("nydus_{name}_signal"))
        .spawn(move || {
            let mut on_first = Some(on_first);
            for signal in signals.forever() {
                match on_first.take() {
                    Some(on_first) => {
                        info!("received signal {signal}, stopping {stopping}");
                        on_first();
                    }
                    None => {
                        warn!("received second signal {signal}, forcing immediate exit");
                        std::process::exit(130);
                    }
                }
            }
        })
        .with_context(|| format!("failed to spawn {name} signal thread"))?;
    Ok(SignalThread {
        name: name.to_string(),
        handle,
        thread,
    })
}

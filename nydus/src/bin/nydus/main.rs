use clap::{Parser, Subcommand};
use nydus::error::Result;
use nydus_config::{default_log_dir, VersionValueParser, NAME};

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

/// Returns the default worker parallelism: the available CPU count clamped to
/// `[min, max]`.
pub fn default_parallelism(min: usize, max: usize) -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(min)
        .clamp(min, max)
}

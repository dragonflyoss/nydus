use clap::{Parser, Subcommand};
use nydus::error::Result;
use nydus_config::{default_log_dir, VersionValueParser, NAME};

// musl's malloc serializes every allocation on one lock, which the many
// backend and FUSE threads contend on.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// mimalloc's `mi_option_purge_delay`, entry 15 of its `mi_option_t`; the
/// bindings name no constant for it.
const MI_OPTION_PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;

/// mimalloc's own purge delay in milliseconds, which proves
/// [`MI_OPTION_PURGE_DELAY`] still names that option before it is changed.
const MI_DEFAULT_PURGE_DELAY_MS: std::ffi::c_long = 1000;

/// The purge delay of the mount services in milliseconds: freed pages go
/// back to the OS at once.
const DAEMON_PURGE_DELAY_MS: std::ffi::c_long = 0;

pub use nydus::api_server;
pub mod build;
pub mod check;
pub mod export;
#[cfg(feature = "fanotify")]
pub mod fanotify;
#[cfg(feature = "fileio")]
pub mod fileio;
pub mod fuse;
pub mod merge;
#[cfg(feature = "nbd")]
pub mod nbd;
pub mod optimize;
pub mod repack;
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
        long_about = "Build a chunk-based nydus filesystem image from a directory, producing a full blob and an optional standalone bootstrap."
    )]
    Build(build::BuildCommand),

    #[command(
        name = "repack",
        about = "Prune metadata and compact live blobs in one pass"
    )]
    Repack(repack::RepackCommand),

    #[command(
        name = "export",
        author,
        version,
        about = "Export a nydus image as an OCI layer tar stream",
        long_about = "Export a nydus full blob back into an uncompressed OCI layer tar stream, written to a file or stdout."
    )]
    Export(export::ExportCommand),

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

    #[cfg(feature = "fileio")]
    #[command(
        name = "fileio",
        author,
        version,
        about = "Serve a flattened nydus image as a file-backed EROFS mount",
        long_about = "Export a flattened nydus image as a single file over FUSE and let the kernel EROFS driver mount that file directly (CONFIG_EROFS_FS_BACKED_BY_FILE, Linux >= 6.12). Lookup, readdir, stat and xattr are resolved in-kernel; only cold byte ranges reach the daemon."
    )]
    Fileio(fileio::FileioCommand),
}

/// Implement the execute for Command.
impl Command {
    /// True for the long-running mount services, as opposed to one-shot tools.
    fn is_daemon(&self) -> bool {
        !matches!(
            self,
            Self::Build(_)
                | Self::Repack(_)
                | Self::Export(_)
                | Self::Check(_)
                | Self::Merge(_)
                | Self::Optimize(_)
        )
    }

    pub fn execute(self) -> Result<()> {
        match self {
            Self::Build(cmd) => cmd.execute(),
            Self::Repack(cmd) => cmd.execute(),
            Self::Export(cmd) => cmd.execute(),
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
            #[cfg(feature = "fileio")]
            Self::Fileio(cmd) => cmd.execute(),
        }
    }
}

fn main() -> std::process::ExitCode {
    // Parse command line arguments.
    let args = Args::parse();

    if args.command.is_daemon() {
        tune_daemon_allocator();
        disable_transparent_huge_pages();
        tune_mimalloc();
    }

    // Execute the command.
    match args.command.execute() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            print_error(&err);
            std::process::ExitCode::FAILURE
        }
    }
}

/// Prints the error and its cause chain in the cargo style — a colored
/// `error:` line matching clap's own output, then the causes indented under
/// `Caused by:` — instead of one run-on `a: b: c` line.
fn print_error(err: &nydus::Error) {
    let red = anstyle::Style::new()
        .bold()
        .fg_color(Some(anstyle::AnsiColor::Red.into()));
    let bold = anstyle::Style::new().bold();
    anstream::eprintln!("{red}error:{red:#} {err}");

    let mut causes = Vec::new();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    match causes.as_slice() {
        [] => {}
        [only] => anstream::eprintln!("\n{bold}Caused by:{bold:#}\n    {only}"),
        causes => {
            anstream::eprintln!("\n{bold}Caused by:{bold:#}");
            for (index, cause) in causes.iter().enumerate() {
                anstream::eprintln!("    {index}: {cause}");
            }
        }
    }
}

/// Cap glibc malloc at two arenas and pin its mmap/trim thresholds for the
/// mount services. By default every worker thread grows its own arena and the
/// dynamic mmap threshold keeps freed multi-hundred-KiB buffers inside those
/// arenas, which measured as roughly 11 MiB of idle RSS. The fixed threshold
/// stays above hyper's ~408 KiB HTTP read buffer, which is reallocated several
/// times per response and must be recycled rather than mapped each time.
/// Explicit `MALLOC_*` or `GLIBC_TUNABLES` settings in the environment take
/// precedence. Must run before worker threads exist, since arenas are assigned
/// on first use.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn tune_daemon_allocator() {
    const EXPLICIT: [&str; 4] = [
        "MALLOC_ARENA_MAX",
        "MALLOC_MMAP_THRESHOLD_",
        "MALLOC_TRIM_THRESHOLD_",
        "GLIBC_TUNABLES",
    ];
    if EXPLICIT.iter().any(|name| std::env::var_os(name).is_some()) {
        return;
    }
    // SAFETY: mallopt only updates allocator parameters and has no memory-safety
    // preconditions; a rejected value returns 0 and leaves the default in place.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 2);
        libc::mallopt(libc::M_MMAP_THRESHOLD, 512 * 1024);
        libc::mallopt(libc::M_TRIM_THRESHOLD, 1024 * 1024);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn tune_daemon_allocator() {}

/// Keeps the kernel from backing the mount services with transparent huge
/// pages: where they are `always` on, a huge page makes a whole 2 MiB resident
/// for a few small allocations or the head of a chunk group buffer, roughly
/// doubling the daemon's anonymous memory. mimalloc does this itself only
/// when told through `MIMALLOC_ALLOW_THP=0`; its `no_thp` build merely stops
/// it asking for huge pages. An explicit `MIMALLOC_ALLOW_THP` takes
/// precedence.
#[cfg(target_os = "linux")]
fn disable_transparent_huge_pages() {
    if std::env::var_os("MIMALLOC_ALLOW_THP").is_some() {
        return;
    }
    // SAFETY: PR_SET_THP_DISABLE only sets a flag of this process; a kernel
    // without it fails the call, which leaves huge pages as they were.
    unsafe {
        libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn disable_transparent_huge_pages() {}

/// Has mimalloc return freed pages to the OS at once in the mount services,
/// instead of a second later: their memory comes in bursts of chunk group
/// buffers and network pieces, and the delay keeps a burst resident long
/// after it is gone. An explicit `MIMALLOC_PURGE_DELAY` takes precedence.
/// Must run before other threads exist, as mimalloc options are not thread
/// safe.
fn tune_mimalloc() {
    if std::env::var_os("MIMALLOC_PURGE_DELAY").is_some() {
        return;
    }
    // SAFETY: no other thread runs yet, and the option is only changed when
    // it holds mimalloc's own purge delay, so the id names that option.
    unsafe {
        if libmimalloc_sys::mi_option_get(MI_OPTION_PURGE_DELAY) == MI_DEFAULT_PURGE_DELAY_MS {
            libmimalloc_sys::mi_option_set(MI_OPTION_PURGE_DELAY, DAEMON_PURGE_DELAY_MS);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn transparent_huge_pages_are_disabled_for_the_process() {
        if std::env::var_os("MIMALLOC_ALLOW_THP").is_some() {
            return;
        }
        disable_transparent_huge_pages();
        // SAFETY: PR_GET_THP_DISABLE only reads a flag of this process.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_THP_DISABLE, 0, 0, 0, 0) },
            1
        );
    }

    #[test]
    fn purge_delay_option_id_names_mimallocs_purge_delay() {
        if std::env::var_os("MIMALLOC_PURGE_DELAY").is_some() {
            return;
        }
        // SAFETY: reading an option has no preconditions.
        let delay = unsafe { libmimalloc_sys::mi_option_get(MI_OPTION_PURGE_DELAY) };
        assert_eq!(delay, MI_DEFAULT_PURGE_DELAY_MS);
    }
}

use clap::{Parser, Subcommand};
use nydus::error::Result;
use nydus_config::{default_log_dir, VersionValueParser, NAME};

// musl's malloc serializes every allocation on one lock, which the many
// backend and FUSE threads contend on.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A mimalloc option the mount services change.
struct MiOption {
    /// Its entry in mimalloc v3's `mi_option_t`; the bindings name no
    /// constants for these.
    id: libmimalloc_sys::mi_option_t,

    /// mimalloc's own default, which proves `id` still names the option
    /// before it is changed.
    default: std::ffi::c_long,

    /// The environment variable that takes precedence.
    env: &'static std::ffi::CStr,

    /// The value of the mount services.
    value: std::ffi::c_long,
}

/// The mimalloc options of the mount services, whose memory comes in bursts
/// of chunk group buffers and network pieces.
const DAEMON_MI_OPTIONS: [MiOption; 3] = [
    // `purge_delay` (ms): freed pages go back to the OS at once rather than
    // a second later, which kept a burst resident long after it was gone.
    MiOption {
        id: 15,
        default: 1000,
        env: c"MIMALLOC_PURGE_DELAY",
        value: 0,
    },
    // `arena_max_object_size` (KiB): objects over 4 MiB, mimalloc's largest
    // page, are mapped from the OS instead of carved from an arena. fuser
    // zeroes a 16 MiB request buffer per FUSE thread, and mimalloc writes
    // those zeros over arena memory it cannot prove clean, making the whole
    // buffer resident; fresh OS pages are zero and stay untouched.
    MiOption {
        id: 45,
        default: 2 * 1024 * 1024,
        env: c"MIMALLOC_ARENA_MAX_OBJECT_SIZE",
        value: 4 * 1024,
    },
    // `arena_reserve` (KiB): arenas of 64 MiB rather than 1 GiB. An arena
    // keeps 120 bytes of page metadata per 64 KiB slice, and as pages come
    // and go across a 1 GiB arena up to 2 MiB of it becomes resident; more
    // arenas are added, each larger, as the heap grows.
    MiOption {
        id: 23,
        default: 1024 * 1024,
        env: c"MIMALLOC_ARENA_RESERVE",
        value: 64 * 1024,
    },
];

/// How long a backend runtime thread waits between two [`collect_freed_blocks`].
const COLLECT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Has mimalloc take back into this thread's pages the blocks other threads
/// have freed, full pages included, and release the pages left empty: run by
/// a backend runtime thread each time it runs out of work, as the readers it
/// fed free its network buffers. A plain collection skips full pages, whose
/// network buffers the readers free last. A thread runs out of work every few milliseconds while
/// it streams, and a collection costs a few microseconds, so it collects at
/// most once per [`COLLECT_INTERVAL`].
fn collect_freed_blocks() {
    thread_local! {
        static LAST: std::cell::Cell<Option<std::time::Instant>> =
            const { std::cell::Cell::new(None) };
    }
    let now = std::time::Instant::now();
    if LAST
        .get()
        .is_some_and(|last| now.duration_since(last) < COLLECT_INTERVAL)
    {
        return;
    }
    LAST.set(Some(now));
    // SAFETY: mi_collect only works on the calling thread's heap.
    unsafe { libmimalloc_sys::mi_collect(true) }
}

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

/// The subcommands that run a long-lived mount service, see
/// [`Command::is_daemon`].
const DAEMON_COMMANDS: [&[u8]; 6] = [b"fuse", b"ublk", b"uffd", b"fanotify", b"nbd", b"fileio"];

/// The subcommands that run once and exit.
#[cfg(test)]
const ONESHOT_COMMANDS: [&str; 6] = ["build", "repack", "export", "check", "merge", "optimize"];

/// The subcommand of a NUL-separated command line: its first argument that
/// is not a flag.
fn subcommand_of(cmdline: &[u8]) -> Option<&[u8]> {
    cmdline
        .split(|byte| *byte == 0)
        .skip(1)
        .find(|arg| !arg.is_empty() && !arg.starts_with(b"-"))
}

/// Whether this process runs a mount service, read from
/// `/proc/self/cmdline` without allocating.
#[cfg(target_os = "linux")]
fn invoked_as_daemon() -> bool {
    let mut cmdline = [0u8; 4096];
    // SAFETY: plain syscalls on a stack buffer of the length given.
    let len = unsafe {
        let fd = libc::open(
            c"/proc/self/cmdline".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return false;
        }
        let len = libc::read(fd, cmdline.as_mut_ptr().cast(), cmdline.len());
        libc::close(fd);
        len
    };
    usize::try_from(len)
        .ok()
        .and_then(|len| subcommand_of(&cmdline[..len]))
        .is_some_and(|name| DAEMON_COMMANDS.contains(&name))
}

/// Tunes the allocator of a mount service before anything allocates: the
/// runtime and the argument parser allocate before `main` could, and the first
/// allocation reserves mimalloc's first arena under the settings of the
/// moment. Applied later, transparent huge pages would already back the
/// arena's metadata (2 MiB resident where they are `always` on) and the arena
/// would already be 1 GiB. Runs from `.init_array`, ahead of constructors
/// without a priority, and must not allocate.
#[cfg(target_os = "linux")]
extern "C" fn tune_before_first_allocation() {
    if invoked_as_daemon() {
        disable_transparent_huge_pages();
        tune_mimalloc();
    }
}

#[cfg(target_os = "linux")]
#[used]
#[link_section = ".init_array.00099"]
static TUNE_BEFORE_FIRST_ALLOCATION: extern "C" fn() = tune_before_first_allocation;

/// Whether the environment variable `name` is set, without allocating.
fn env_is_set(name: &std::ffi::CStr) -> bool {
    // SAFETY: getenv reads the environment; nothing here changes it.
    unsafe { !libc::getenv(name.as_ptr()).is_null() }
}

fn main() -> std::process::ExitCode {
    // Parse command line arguments.
    let args = Args::parse();

    if args.command.is_daemon() {
        tune_daemon_allocator();
        // Already done before the first allocation; these find the settings
        // in place and only matter where that hook could not run.
        disable_transparent_huge_pages();
        tune_mimalloc();
        nydus_backend::set_runtime_idle_hook(collect_freed_blocks);
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
/// doubling the daemon's anonymous memory. An explicit `MIMALLOC_ALLOW_THP`
/// takes precedence.
#[cfg(target_os = "linux")]
fn disable_transparent_huge_pages() {
    if env_is_set(c"MIMALLOC_ALLOW_THP") {
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

/// Applies [`DAEMON_MI_OPTIONS`] in the mount services, each unless its
/// environment variable is set. Must run before other threads exist, as
/// mimalloc options are not thread safe, and does not allocate.
fn tune_mimalloc() {
    for option in &DAEMON_MI_OPTIONS {
        if env_is_set(option.env) {
            continue;
        }
        // SAFETY: no other thread runs yet, and an option is only changed
        // while it holds mimalloc's own default, so the id names it.
        unsafe {
            if libmimalloc_sys::mi_option_get(option.id) == option.default {
                libmimalloc_sys::mi_option_set(option.id, option.value);
            }
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

    #[test]
    fn every_subcommand_is_either_a_daemon_or_oneshot() {
        use clap::CommandFactory;
        // Subcommands behind features are absent from other builds.
        for command in Args::command().get_subcommands() {
            let name = command.get_name();
            assert!(
                DAEMON_COMMANDS.contains(&name.as_bytes()) != ONESHOT_COMMANDS.contains(&name),
                "classify subcommand {name} in DAEMON_COMMANDS or ONESHOT_COMMANDS"
            );
        }
    }

    #[test]
    fn the_subcommand_is_the_first_argument_that_is_not_a_flag() {
        assert_eq!(
            subcommand_of(b"nydus\0fuse\0--bootstrap\0b\0"),
            Some(&b"fuse"[..])
        );
        assert_eq!(
            subcommand_of(b"/bin/nydus\0-V\0build\0dir\0"),
            Some(&b"build"[..])
        );
        assert_eq!(subcommand_of(b"nydus\0"), None);
        assert_eq!(subcommand_of(b"nydus"), None);
        assert_eq!(subcommand_of(b""), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transparent_huge_pages_are_disabled_for_the_process() {
        if env_is_set(c"MIMALLOC_ALLOW_THP") {
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
    fn daemon_mimalloc_option_ids_name_their_options() {
        for option in &DAEMON_MI_OPTIONS {
            if env_is_set(option.env) {
                continue;
            }
            // SAFETY: reading an option has no preconditions.
            let value = unsafe { libmimalloc_sys::mi_option_get(option.id) };
            assert_eq!(value, option.default, "{:?}", option.env);
        }
    }
}

use std::ffi::CStr;

/// The mimalloc tuning of the mount services.
///
/// mimalloc reads its options and reserves its first arena before `main`
/// runs, so [`Mimalloc::tune`] runs from `.init_array` ahead of mimalloc's own
/// constructor. Set from `main`, the huge pages touched by then stay
/// resident, 4 MiB on an idle FUSE mount.
struct Mimalloc;

/// Implements the mimalloc tuning.
impl Mimalloc {
    /// The options of the mount services, as the environment variables
    /// mimalloc reads when it initializes.
    const OPTIONS: [(&'static CStr, &'static CStr); 4] = [
        // A huge page makes a whole 2 MiB resident for a few small objects.
        (c"MIMALLOC_ALLOW_THP", c"0"),
        // Freed pages go back to the OS at once, not a second later.
        (c"MIMALLOC_PURGE_DELAY", c"0"),
        // fuser zeroes a 16 MiB request buffer per FUSE thread, resident when
        // carved from an arena and untouched when mapped from the OS.
        (c"MIMALLOC_ARENA_MAX_OBJECT_SIZE", c"4MiB"),
        // A 1 GiB arena keeps up to 2 MiB of page metadata resident.
        (c"MIMALLOC_ARENA_RESERVE", c"64MiB"),
    ];

    /// The subcommands that run a mount service, see
    /// [`crate::Command::is_daemon`].
    const DAEMON_COMMANDS: [&'static [u8]; 6] =
        [b"fuse", b"ublk", b"uffd", b"fanotify", b"nbd", b"fileio"];

    /// Returns whether the NUL-separated command line `cmdline` runs a mount
    /// service, its subcommand being its first argument that is not a flag.
    fn is_daemon(cmdline: &[u8]) -> bool {
        cmdline
            .split(|byte| *byte == 0)
            .skip(1)
            .find(|arg| !arg.is_empty() && !arg.starts_with(b"-"))
            .is_some_and(|subcommand| Self::DAEMON_COMMANDS.contains(&subcommand))
    }

    /// Sets [`Self::OPTIONS`] for a mount service, each unless already set.
    /// It must not allocate, which would initialize mimalloc first.
    extern "C" fn tune() {
        let mut cmdline = [0u8; 4096];
        // SAFETY: plain syscalls on a stack buffer of the length given.
        let len = unsafe {
            let fd = libc::open(
                c"/proc/self/cmdline".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return;
            }
            let len = libc::read(fd, cmdline.as_mut_ptr().cast(), cmdline.len());
            libc::close(fd);
            len
        };

        let Ok(len) = usize::try_from(len) else {
            return;
        };
        if !Self::is_daemon(&cmdline[..len]) {
            return;
        }

        for (name, value) in &Self::OPTIONS {
            // SAFETY: no other thread runs yet, and both strings are
            // NUL-terminated.
            unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), 0) };
        }
    }
}

/// The `.init_array` entry that runs [`Mimalloc::tune`] before `main`.
#[used]
#[unsafe(link_section = ".init_array.00099")]
static TUNE_MIMALLOC: extern "C" fn() = Mimalloc::tune;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Args;
    use clap::CommandFactory;

    #[test]
    fn is_daemon_tells_the_mount_services_from_the_one_shot_tools() {
        let oneshot = ["build", "repack", "export", "check", "merge", "optimize"];

        for command in Args::command().get_subcommands() {
            let name = command.get_name();
            let cmdline = format!("nydus\0{name}\0--help\0");
            assert_ne!(
                Mimalloc::is_daemon(cmdline.as_bytes()),
                oneshot.contains(&name),
                "{name}"
            );
        }
    }

    #[test]
    fn is_daemon_reads_the_first_argument_that_is_not_a_flag() {
        let test_cases: Vec<(&[u8], bool)> = vec![
            (b"nydus\0fuse\0--bootstrap\0b\0", true),
            (b"/bin/nydus\0-V\0fuse\0", true),
            (b"nydus\0build\0fuse\0", false),
            (b"nydus\0", false),
            (b"nydus", false),
            (b"", false),
        ];

        for (cmdline, expected) in test_cases {
            assert_eq!(Mimalloc::is_daemon(cmdline), expected);
        }
    }
}

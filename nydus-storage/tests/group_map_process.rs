#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    assert!(
        std::env::var_os("CI").is_none(),
        "deterministic hardware watchpoint requires Linux x86-64"
    );
    eprintln!("SKIP KI-3: deterministic hardware watchpoint requires Linux x86-64");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    linux::set_ready_racing_a_reset_leaves_the_group_cold();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::io;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use nydus_storage::chunk_group_map::ChunkGroupMap;
    use tempfile::tempdir;

    const CHILD_MAP: &str = "NYDUS_TEST_GROUP_MAP_CHILD";

    struct TracedChild(Child);

    impl Drop for TracedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn set_ready_under_trace() {
        let Some(path) = std::env::var_os(CHILD_MAP) else {
            return;
        };
        let map = ChunkGroupMap::open(path.as_ref(), 1).unwrap();
        // SAFETY: PTRACE_TRACEME takes no pointers; null addr and data are ignored.
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if result == -1 {
            eprintln!("ptrace precondition: {}", io::Error::last_os_error());
            std::process::exit(77);
        }
        // SAFETY: raise only delivers SIGSTOP to this process.
        unsafe { libc::raise(libc::SIGSTOP) };
        map.set_ready(0).unwrap();
    }

    fn wait(pid: i32) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: `status` is a valid, writable i32 for the duration of the call.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
            assert!(result >= 0, "waitpid: {}", io::Error::last_os_error());
            if result == pid {
                return status;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn trace(request: u32, pid: i32, address: usize, data: usize) {
        // SAFETY: the requests used here pass addr and data as plain integers, not pointers.
        let result = unsafe {
            libc::ptrace(
                request,
                pid,
                address as *mut libc::c_void,
                data as *mut libc::c_void,
            )
        };
        assert_ne!(result, -1, "ptrace: {}", io::Error::last_os_error());
    }

    pub fn set_ready_racing_a_reset_leaves_the_group_cold() {
        if std::env::var_os(CHILD_MAP).is_some() {
            set_ready_under_trace();
            return;
        }
        let dir = tempdir().unwrap();
        let path = dir.path().join("group-map");
        let map = ChunkGroupMap::open(&path, 1).unwrap();
        let child = TracedChild(
            Command::new(std::env::current_exe().unwrap())
                .env(CHILD_MAP, &path)
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id() as i32;
        let status = wait(pid);
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 77 {
            assert!(
                std::env::var_os("CI").is_none(),
                "ptrace required but unavailable"
            );
            eprintln!("SKIP KI-3: ptrace denied; CI requires it");
            return;
        }
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        let canonical = path.canonicalize().unwrap();
        let line = maps
            .lines()
            .find(|line| line.ends_with(canonical.to_str().unwrap()))
            .unwrap();
        let start = usize::from_str_radix(line.split('-').next().unwrap(), 16).unwrap();
        let debug = std::mem::offset_of!(libc::user, u_debugreg);
        let dr0 = debug;
        let dr7 = debug + 7 * 8;
        let dr0_local_one_byte_write = 1 | (1 << 16);
        trace(libc::PTRACE_POKEUSER, pid, dr0, start + 4096);
        trace(libc::PTRACE_POKEUSER, pid, dr7, dr0_local_one_byte_write);

        trace(libc::PTRACE_CONT, pid, 0, 0);
        let status = wait(pid);

        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert!(map.is_ready(0).unwrap());
        assert!(!map.is_all_ready());

        map.reset().unwrap();

        assert!(!map.is_ready(0).unwrap());

        trace(libc::PTRACE_POKEUSER, pid, dr7, 0);
        trace(libc::PTRACE_CONT, pid, 0, 0);
        let status = wait(pid);

        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(!map.is_ready(0).unwrap());
        assert!(!map.is_range_ready(0..1).unwrap());
    }
}

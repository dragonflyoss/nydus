//! Build an idmapped clone of a Linux FUSE mount.
//!
//! Idmapped mounts are a kernel VFS feature (Linux >= 6.12 for FUSE): the
//! kernel's mnt_idmap layer rewrites uids/gids going through the mount
//! according to a user namespace's `uid_map`/`gid_map`. Permission checks
//! happen in the kernel VFS layer. For non-creation FUSE requests, the
//! kernel deliberately reports `FUSE_INVALID_UIDGID` in the request header,
//! so the daemon must not rely on request uid/gid for idmap translation.
//!
//! This module turns `id_mapping` triples into a fresh user namespace
//! (created in a forked child so the parent daemon never leaves its own
//! userns). It then clones the staging FUSE mount with `open_tree(2)`, calls
//! `mount_setattr(2)` with `MOUNT_ATTR_IDMAP` on the detached clone, and hands
//! that still-detached mount to the lifecycle module. Linux only permits
//! `MOUNT_ATTR_IDMAP` while the mount is detached from every mount namespace.
//!
//! The lifecycle code below owns target attachment, mount identity, and
//! teardown ordering around those mapping primitives.
//!
//! `ErofsFs::init` must first advertise `FUSE_ALLOW_IDMAP` to the kernel via
//! fuser's `KernelConfig::add_capabilities`. The caller must have observed a
//! completed FUSE_INIT before invoking [`prepare_idmap`].
//!
//! Only `libc` is used directly (no `nix` dependency) so the post-fork child
//! path can stay async-signal-safe.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{serialize_id_mappings, IdMapTriple};
use anyhow::{anyhow, bail, Context, Result};
use fuser::BackgroundSession;
use tracing::{debug, error, warn};

/// How long the daemon waits on each step of the handshake with its forked
/// user-namespace helper. The child only unshares and opens one file, so any
/// real delay here means it is wedged and the mount should fail rather than
/// hang the daemon at startup.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UNMOUNT_RETRY_ATTEMPTS: u32 = 40;
const UNMOUNT_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_STAGING_ROOT: &str = "/run/nydus/idmap";
const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x4000;
const FUSE_SUPER_MAGIC: libc::c_long = 0x6573_5546;

/// A detached mount with its idmap already applied.
///
/// Attaching this mount and recording its identity belong to the mount
/// lifecycle. Keeping it detached here ensures that operation cannot expose a
/// mount before the lifecycle owns enough state to tear it down safely.
pub(crate) struct DetachedIdmappedMount {
    mount_fd: OwnedFd,
    mount_id: u64,
}

impl DetachedIdmappedMount {
    pub(crate) fn mount_fd(&self) -> RawFd {
        self.mount_fd.as_raw_fd()
    }

    fn mount_id(&self) -> u64 {
        self.mount_id
    }
}

/// Clone `source_mountpoint` and apply `MOUNT_ATTR_IDMAP` to the detached clone
/// using a fresh user namespace populated from `mappings`.
///
/// The source must be a private staging FUSE mount that has completed
/// `FUSE_INIT` with `FUSE_ALLOW_IDMAP`. The caller owns target serialization,
/// attachment, mount identity, and teardown.
pub(crate) fn prepare_idmap(
    source_mountpoint: &Path,
    mappings: &[IdMapTriple],
) -> Result<DetachedIdmappedMount> {
    if mappings.is_empty() {
        bail!("id_mapping requested but no entries provided");
    }

    // Defensive re-validation: callers (e.g. `Config::from_file`) already
    // reject bad mappings at startup, but a programmatic caller could reach
    // here with an in-memory `Vec<IdMapTriple>`. Catch it before we fork.
    crate::config::validate_id_mappings(mappings).context("id_mapping config is invalid")?;

    let userns_fd =
        create_userns_fd(mappings).context("failed to build user namespace for idmap")?;

    let detached_mount = open_tree(source_mountpoint).with_context(|| {
        format!(
            "failed to clone source mount {}",
            source_mountpoint.display()
        )
    })?;

    let attr = MountAttr {
        attr_set: libc::MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_raw_fd() as u64,
    };

    mount_setattr(detached_mount.as_raw_fd(), &attr)
        .context("mount_setattr(MOUNT_ATTR_IDMAP) on detached mount failed")?;
    let mount_id = mount_unique_id(detached_mount.as_raw_fd())
        .context("reading detached idmapped mount identity")?;

    Ok(DetachedIdmappedMount {
        mount_fd: detached_mount,
        mount_id,
    })
}

/// Fork a child that unshares a fresh user namespace; the parent writes
/// the child's `uid_map` and `gid_map`, then the child sends back a fd to
/// `/proc/self/ns/user`.
///
/// Doing the unshare in a forked child (rather than in the daemon itself)
/// keeps the daemon in its original user namespace, so its own file
/// access (blob cache, backend sockets) is unaffected.
fn create_userns_fd(mappings: &[IdMapTriple]) -> Result<OwnedFd> {
    let (mut parent_sock, child_sock) = UnixStream::pair().context("socketpair failed")?;
    // Neither side may block forever on the other. Configure both endpoints
    // before fork so the raw-syscall child inherits bounded I/O as well.
    parent_sock
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting userns handshake read timeout")?;
    parent_sock
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting userns handshake write timeout")?;
    child_sock
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting child userns handshake read timeout")?;
    child_sock
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .context("setting child userns handshake write timeout")?;
    let parent_fd = parent_sock.as_raw_fd();

    // SAFETY: `fork()` is async-signal-safe; the parent side uses Rust
    // stdlib (fine), the child side below uses only libc calls and _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error()).context("fork failed");
    }
    if pid == 0 {
        // === CHILD PATH — async-signal-safe only from here to _exit ===
        // No Rust allocations, no stdlib buffered I/O, no locks.
        unsafe { child_path(child_sock.as_raw_fd(), parent_fd) };
        // unreachable: child_path calls _exit
    }

    // === PARENT PATH ===
    let child_pid = pid;
    drop(child_sock);
    let mut child = ChildReaper::new(child_pid);
    // Wait for the child to report it has finished unshare().
    let mut ack = [0u8; 1];
    parent_sock
        .read_exact(&mut ack)
        .context("waiting for child unshare ack")?;
    if ack[0] != 1 {
        child
            .reap_ignoring_status()
            .context("reaping child after unshare failure")?;
        bail!("child reported unshare failure (byte={})", ack[0]);
    }

    // Write the uid_map and gid_map for the child's userns. The parent
    // must hold CAP_SETUID/CAP_SETGID in the parent userns of the child's
    // userns (i.e. the daemon's own userns) — the normal host/container
    // case for a root or CAP_SETUID-enabled nydusd.
    let map_text = serialize_id_mappings(mappings);
    let uid_map_path = format!("/proc/{child_pid}/uid_map");
    let gid_map_path = format!("/proc/{child_pid}/gid_map");
    let setgroups_path = format!("/proc/{child_pid}/setgroups");
    if let Err(e) = std::fs::write(&uid_map_path, &map_text) {
        return Err(e).with_context(|| format!("writing {uid_map_path}"));
    }
    match std::fs::write(&setgroups_path, b"deny") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("writing {setgroups_path}")),
    }
    if let Err(e) = std::fs::write(&gid_map_path, &map_text) {
        return Err(e).with_context(|| format!("writing {gid_map_path}"));
    }

    // Ack so the child opens its userns fd and sends it back.
    parent_sock
        .write_all(&[1u8])
        .context("ack to child after writing uid/gid maps")?;

    let userns_fd = recv_fd(&parent_sock).context("receiving userns fd from child")?;
    child.reap().context("reaping user namespace child")?;
    Ok(userns_fd)
}

/// Child-side post-fork routine. Must only use libc syscalls. Calls
/// `_exit` directly; never returns.
///
/// Sequence:
///   0. close the inherited parent end of the socket pair
///   1. `unshare(CLONE_NEWUSER)`
///   2. signal parent via 1-byte write
///   3. wait for parent's 1-byte ack (uid/gid maps written)
///   4. `open("/proc/self/ns/user", O_RDONLY|O_CLOEXEC)`
///   5. `sendmsg(SCM_RIGHTS)` to hand the fd back
///   6. `_exit(0)`
unsafe fn child_path(sock_fd: RawFd, inherited_parent_fd: RawFd) -> ! {
    let err_byte: u8 = 0;
    let ok_byte: u8 = 1;

    // 0. fork duplicated *both* ends of the pair into this process. While
    // this copy of the parent's end stays open, the read below can never see
    // EOF — so a parent that dies before acking would leave this child
    // blocked forever, holding dups of the daemon's fds (/dev/fuse among
    // them) and pinning the FUSE connection.
    libc::close(inherited_parent_fd);

    // 1. unshare(CLONE_NEWUSER)
    let rc = libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER as libc::c_long);
    if rc < 0 {
        let _ = libc::write(sock_fd, &err_byte as *const u8 as *const libc::c_void, 1);
        libc::_exit(1);
    }

    // 2. signal parent
    let _ = libc::write(sock_fd, &ok_byte as *const u8 as *const libc::c_void, 1);

    // 3. wait for parent's ack
    let mut buf: [u8; 1] = [0];
    let mut total = 0usize;
    while total < 1 {
        let n = libc::read(sock_fd, buf.as_mut_ptr() as *mut libc::c_void, 1);
        if n < 0 {
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            libc::_exit(2);
        }
        if n == 0 {
            // EOF: parent closed the socket without acking (died or gave
            // up). No point retrying.
            libc::_exit(2);
        }
        total += n as usize;
    }
    if buf[0] != 1 {
        libc::_exit(3);
    }

    // 4. open userns fd
    let path = b"/proc/self/ns/user\0";
    let userns_fd = libc::open(
        path.as_ptr() as *const libc::c_char,
        libc::O_RDONLY | libc::O_CLOEXEC,
    );
    if userns_fd < 0 {
        libc::_exit(4);
    }

    // 5. sendmsg with SCM_RIGHTS carrying userns_fd
    send_fd_raw(sock_fd, userns_fd);

    // 6. exit
    libc::_exit(0);
}

/// Parent-side helper: receive a single fd via SCM_RIGHTS over a Unix
/// socket. Uses only libc so the parent can stay in Rust stdlib while
/// the protocol is symmetric with the child's `send_fd_raw`.
fn recv_fd(sock: &UnixStream) -> Result<OwnedFd> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // 64 bytes is enough cmsg space for one RawFd on any Linux platform.
    let mut cmsg_buf = CmsgBuffer::default();
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.0.len() as _;

    let raw = sock.as_raw_fd();
    // MSG_CMSG_CLOEXEC: the userns fd must not survive an exec, the same way
    // the child opened /proc/self/ns/user with O_CLOEXEC.
    let n = unsafe { libc::recvmsg(raw, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error()).context("recvmsg for userns fd");
    }
    if n == 0 {
        bail!("child closed socket without sending userns fd");
    }
    if data[0] != 1 {
        bail!(
            "child sent invalid user namespace fd protocol byte {}",
            data[0]
        );
    }
    // A truncated control message means the kernel dropped descriptors it
    // could not fit; whatever is left in the buffer is not a usable fd.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("truncated SCM_RIGHTS control message while receiving userns fd");
    }

    // Walk the cmsg buffer to find an SCM_RIGHTS entry.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let cmsg_ref = &*cmsg;
            if cmsg_ref.cmsg_level == libc::SOL_SOCKET && cmsg_ref.cmsg_type == libc::SCM_RIGHTS {
                if cmsg_ref.cmsg_len
                    < libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as _
                {
                    bail!("short SCM_RIGHTS control message");
                }
                let data_ptr = libc::CMSG_DATA(cmsg);
                let fd: RawFd = std::ptr::read(data_ptr as *const RawFd);
                return Ok(OwnedFd::from_raw_fd(fd));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    bail!("no SCM_RIGHTS cmsg received from child")
}

/// Child-side helper: send a single fd via `sendmsg` with `SCM_RIGHTS`,
/// using only stack-allocated buffers so the post-fork child stays
/// async-signal-safe.
unsafe fn send_fd_raw(sock_fd: RawFd, fd: RawFd) {
    let data: [u8; 1] = [1];
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut cmsg_buf = CmsgBuffer::default();
    let cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint);
    if cmsg_len as usize > cmsg_buf.0.len() {
        libc::_exit(5);
    }

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_len as _;

    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    if cmsg.is_null() {
        libc::_exit(6);
    }
    // Set the cmsghdr fields individually — libc's `cmsghdr` layout
    // varies across Linux libc (glibc has only cmsg_len/level/type,
    // musl adds __pad1), so a struct literal is not portable.
    (*cmsg).cmsg_len = cmsg_len as _;
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    let data_ptr = libc::CMSG_DATA(cmsg);
    std::ptr::copy_nonoverlapping(
        &fd as *const RawFd as *const u8,
        data_ptr,
        std::mem::size_of::<RawFd>(),
    );

    let rc = libc::sendmsg(sock_fd, &msg, 0);
    if rc < 0 {
        libc::_exit(7);
    }
}

/// Convert a path to the C representation expected by mount syscalls.
fn path_cstring(path: &Path) -> Result<CString> {
    let cstr = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| anyhow!("invalid path: {e}"))?;
    Ok(cstr)
}

/// Clone the source mount into an anonymous mount namespace. The returned fd
/// names a detached mount, which is the only state in which Linux accepts
/// `MOUNT_ATTR_IDMAP`.
fn open_tree(source_mountpoint: &Path) -> Result<OwnedFd> {
    let source = path_cstring(source_mountpoint)?;
    // SAFETY: source is NUL-terminated and remains live for the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD as libc::c_long,
            source.as_ptr(),
            (libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("open_tree({})", source_mountpoint.display()));
    }
    // SAFETY: a nonnegative syscall result is a newly owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// `struct mount_attr` from <linux/mount.h>. libc 0.2.178 exposes it,
/// but we redefine it locally to avoid depending on a specific libc
/// version for the struct layout. The constants `MOUNT_ATTR_IDMAP` and
/// `SYS_mount_setattr` we DO require from libc.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Aligned control-message buffer for a single `cmsghdr` plus its payload
/// (one `RawFd`). 64 bytes covers `CMSG_SPACE(sizeof(int))` on every Linux
/// platform (24 on 64-bit, 16 on 32-bit).
///
/// `#[repr(align(8))]` is required because `cmsghdr`'s leading `size_t`
/// field demands natural alignment: `alignof(cmsghdr) == alignof(size_t)`,
/// which is 8 on 64-bit Linux and 4 on 32-bit. A plain `[u8; 64]` has
/// `align(1)`, and `CMSG_FIRSTHDR` just casts `msg_control` to
/// `*mut cmsghdr` without any alignment fix-up, so a byte buffer that
/// happened to land on an unaligned stack address would make the
/// subsequent `(*cmsg).cmsg_len = ...` store / `&*cmsg` reference be
/// undefined behavior at the LLVM-IR level (and an alignment fault on
/// strict-alignment hardware). `align(8)` subsumes both 4 and 8.
#[repr(C, align(8))]
struct CmsgBuffer([u8; 64]);

impl Default for CmsgBuffer {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

// ---- Compile-time layout / constant invariants ------------------------
//
// These are `const _` assertions (not `#[test]`) because they describe
// properties that must hold for *every* build, not just `cargo test`.
// `cargo build` will fail if the kernel UAPI constants or struct layouts
// drift — no need to run tests to catch a regression.

const _: () = {
    // struct mount_attr from <linux/mount.h>: four u64 fields, 32 bytes.
    assert!(std::mem::size_of::<MountAttr>() == 32);
    assert!(std::mem::offset_of!(MountAttr, attr_set) == 0);
    assert!(std::mem::offset_of!(MountAttr, attr_clr) == 8);
    assert!(std::mem::offset_of!(MountAttr, propagation) == 16);
    assert!(std::mem::offset_of!(MountAttr, userns_fd) == 24);
};

const _: () = {
    // From <linux/mount.h>: MOUNT_ATTR_IDMAP = 0x00100000 (bit 20).
    // libc 0.2.178 exposes this constant; the assert guards against a
    // future libc version renaming or renumbering it under us.
    assert!(libc::MOUNT_ATTR_IDMAP == 0x00100000);
};

const _: () = {
    // CmsgBuffer must be at least as aligned as cmsghdr (whose leading
    // size_t field drives the alignment requirement: 8 on 64-bit, 4 on
    // 32-bit). `#[repr(align(8))]` subsumes both. This invariant is the
    // thing that keeps `CMSG_FIRSTHDR` + `(*cmsg).field` / `&*cmsg`
    // well-defined; if someone reverts to a plain `[u8; N]` (align 1)
    // this const assertion fails at compile time.
    assert!(std::mem::align_of::<CmsgBuffer>() >= std::mem::align_of::<libc::cmsghdr>());
    // 64 bytes covers CMSG_SPACE(sizeof(int)) on every Linux platform
    // (24 on 64-bit, 16 on 32-bit) with room to spare.
    assert!(std::mem::size_of::<CmsgBuffer>() >= 64);
};

/// Apply `mount_setattr(MOUNT_ATTR_IDMAP)` to the detached `open_tree` fd
/// after the caller has observed the FUSE init reply. Errors here are
/// permanent configuration or capability failures, not an init race.
fn mount_setattr(detached_mount_fd: RawFd, attr: &MountAttr) -> Result<()> {
    // SAFETY: detached_mount_fd and attr live across the call; attr is POD.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            detached_mount_fd as libc::c_long,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_long,
            attr as *const MountAttr as *const libc::c_void,
            std::mem::size_of::<MountAttr>() as libc::c_long,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Reap a child process. Blocking is safe and required here: every caller
/// has already observed the child's final output on the socket (either the
/// ack byte on unshare failure, or the userns fd on success), which means
/// the child is past its last blocking syscall and on its way to `_exit`.
///
/// Using `WNOHANG` here would race the child's `_exit` syscall: parent's
/// `recvmsg` returns within nanoseconds of the child's `sendmsg`, but the
/// child still has to run Rust's frame epilogue and the `_exit` kernel
/// cleanup — so `WNOHANG` would frequently return 0 ("not exited yet"),
/// leaving the child to become a zombie that nobody reaps.
fn waitpid(pid: libc::pid_t) -> io::Result<libc::c_int> {
    loop {
        // SAFETY: pid is the child we just forked.
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc >= 0 {
            return Ok(status);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

/// SIGKILL the child and reap it, used on error-shutdown paths.
fn kill_and_reap(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: pid is the child we just forked.
    if unsafe { libc::kill(pid, libc::SIGKILL) } < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err);
        }
    }
    waitpid(pid).map(|_| ())
}

/// Ensures a forked user namespace helper is reaped on every parent-side
/// return path after fork.
struct ChildReaper {
    pid: libc::pid_t,
    reaped: bool,
}

impl ChildReaper {
    fn new(pid: libc::pid_t) -> Self {
        Self { pid, reaped: false }
    }

    fn reap(&mut self) -> io::Result<()> {
        let status = waitpid(self.pid)?;
        self.reaped = true;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(io::Error::other(format!(
                "user namespace child exited unsuccessfully (status={status:#x})"
            )));
        }
        Ok(())
    }

    fn reap_ignoring_status(&mut self) -> io::Result<()> {
        waitpid(self.pid)?;
        self.reaped = true;
        Ok(())
    }
}

impl Drop for ChildReaper {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = kill_and_reap(self.pid);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// Prepared target and private staging directory for one idmapped FUSE mount.
///
/// The preparation owns cleanup as soon as it is created. Once the caller has
/// spawned the FUSE session, it must hand the session to [`set_session`]
/// before waiting for FUSE_INIT so every later error tears the session down.
pub struct IdmapMountPreparation {
    target_path: PathBuf,
    target_fd: Option<File>,
    target_identity: FileIdentity,
    target_mount_id: u64,
    staging_instance: PathBuf,
    staging_mountpoint: PathBuf,
    target_lock: Option<File>,
    session: Option<BackgroundSession>,
    cleanup_armed: bool,
}

impl IdmapMountPreparation {
    pub fn new(target: &Path) -> Result<Self> {
        let staging_root = Path::new(DEFAULT_STAGING_ROOT);
        ensure_private_staging_mount(staging_root).with_context(|| {
            format!(
                "isolating idmap staging root {} from mount propagation",
                staging_root.display()
            )
        })?;
        Self::new_in(target, staging_root)
    }

    fn new_in(target: &Path, staging_root: &Path) -> Result<Self> {
        let target_path = absolute_path(target)?;
        let target_fd = open_directory(&target_path)
            .with_context(|| format!("opening idmap target {}", target_path.display()))?;
        let target_identity = FileIdentity::from_file(&target_fd)
            .with_context(|| format!("inspecting idmap target {}", target_path.display()))?;
        let target_mount_id =
            mount_unique_id(target_fd.as_raw_fd()).context("reading target mount identity")?;
        reject_mountpoint_or_root(&target_fd, target_identity, target_mount_id)
            .with_context(|| format!("validating idmap target {}", target_path.display()))?;

        ensure_private_dir(staging_root, 0o700).with_context(|| {
            format!(
                "creating private idmap staging root {}",
                staging_root.display()
            )
        })?;
        let target_lock = acquire_target_lock(&target_fd)?;

        let current_target = open_directory(&target_path).with_context(|| {
            format!(
                "reopening idmap target {} after acquiring lock",
                target_path.display()
            )
        })?;
        if FileIdentity::from_file(&current_target)? != target_identity
            || mount_unique_id(current_target.as_raw_fd())? != target_mount_id
        {
            bail!(
                "idmap target {} changed while it was being prepared",
                target_path.display()
            );
        }

        let staging_instance = staging_root.join(uuid::Uuid::new_v4().to_string());
        create_dir_with_mode(&staging_instance, 0o700).with_context(|| {
            format!(
                "creating idmap staging instance {}",
                staging_instance.display()
            )
        })?;
        let staging_mountpoint = staging_instance.join("mount");
        if let Err(err) = create_dir_with_mode(&staging_mountpoint, 0o755) {
            let _ = fs::remove_dir(&staging_instance);
            return Err(err).with_context(|| {
                format!(
                    "creating idmap staging mountpoint {}",
                    staging_mountpoint.display()
                )
            });
        }
        Ok(Self {
            target_path,
            target_fd: Some(target_fd),
            target_identity,
            target_mount_id,
            staging_instance,
            staging_mountpoint,
            target_lock: Some(target_lock),
            session: None,
            cleanup_armed: true,
        })
    }

    pub fn staging_mountpoint(&self) -> &Path {
        &self.staging_mountpoint
    }

    pub fn set_session(&mut self, session: BackgroundSession) -> Result<()> {
        if self.session.is_some() {
            bail!("idmap staging FUSE session was already set");
        }
        self.session = Some(session);
        Ok(())
    }

    pub fn attach(
        mut self,
        mappings: &[IdMapTriple],
        init_timeout: Duration,
    ) -> Result<IdmappedSession> {
        if self.session.is_none() {
            bail!("idmap staging FUSE session has not been started");
        }
        verify_staging_fuse_mount(&self.staging_mountpoint, init_timeout)?;
        self.verify_target_unchanged()?;

        let detached = prepare_idmap(&self.staging_mountpoint, mappings)?;
        let visible_mount_id = detached.mount_id();
        move_mount(
            detached.mount_fd(),
            self.target_fd
                .as_ref()
                .expect("target fd missing before attach")
                .as_raw_fd(),
        )
        .with_context(|| {
            format!(
                "attaching idmapped mount to target {}",
                self.target_path.display()
            )
        })?;

        let session = self
            .session
            .take()
            .expect("session checked before idmap attach");
        let target_fd = self
            .target_fd
            .take()
            .expect("target fd checked before idmap attach");
        let target_lock = self
            .target_lock
            .take()
            .expect("target lock missing before idmap attach");
        self.cleanup_armed = false;

        Ok(IdmappedSession {
            target_path: std::mem::take(&mut self.target_path),
            target_fd: Some(target_fd),
            visible_mount_id: Some(visible_mount_id),
            staging_instance: std::mem::take(&mut self.staging_instance),
            staging_mountpoint: std::mem::take(&mut self.staging_mountpoint),
            target_lock: Some(target_lock),
            session: Some(session),
            cleanup_complete: false,
        })
    }

    fn verify_target_unchanged(&self) -> Result<()> {
        let current_target = open_directory(&self.target_path).with_context(|| {
            format!(
                "reopening idmap target {} before attach",
                self.target_path.display()
            )
        })?;
        if FileIdentity::from_file(&current_target)? != self.target_identity {
            bail!(
                "idmap target {} changed while preparing",
                self.target_path.display()
            );
        }
        if mount_unique_id(current_target.as_raw_fd())? != self.target_mount_id {
            bail!(
                "idmap target {} became a mountpoint while preparing",
                self.target_path.display()
            );
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.cleanup_armed {
            return Ok(());
        }
        self.cleanup_armed = false;

        let mut first_error = None;
        if let Some(session) = self.session.take() {
            if let Err(err) = session.umount_and_join() {
                first_error = Some(anyhow!(err).context("unmounting staging FUSE session"));
            }
        }
        cleanup_staging_dirs(
            &[&self.staging_mountpoint, &self.staging_instance],
            &mut first_error,
        );
        self.target_fd.take();
        self.target_lock.take();

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl Drop for IdmapMountPreparation {
    fn drop(&mut self) {
        if let Err(err) = self.cleanup() {
            error!("failed to clean idmap mount preparation: {err:#}");
        }
    }
}

fn verify_staging_fuse_mount(staging_mountpoint: &Path, timeout: Duration) -> Result<()> {
    let staging = open_directory(staging_mountpoint).with_context(|| {
        format!(
            "opening staging FUSE mount {}",
            staging_mountpoint.display()
        )
    })?;
    let barrier_fd = staging
        .try_clone()
        .context("duplicating staging mount fd for FUSE_INIT barrier")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("nydus_idmap_init_barrier".to_string())
        .spawn(move || {
            let mut statfs = MaybeUninit::<libc::statfs>::zeroed();
            let rc = unsafe { libc::fstatfs(barrier_fd.as_raw_fd(), statfs.as_mut_ptr()) };
            let result = if rc < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { statfs.assume_init() }.f_type as libc::c_long)
            };
            let _ = sender.send(result);
        })
        .context("spawning FUSE_INIT readiness barrier")?;

    let fs_type = match receiver.recv_timeout(timeout) {
        Ok(result) => result.context("fstatfs on staging mount")?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            bail!(
                "timed out waiting for staging FUSE mount {} to complete FUSE_INIT",
                staging_mountpoint.display()
            )
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            bail!(
                "FUSE_INIT readiness barrier ended before checking staging mount {}",
                staging_mountpoint.display()
            )
        }
    };
    if fs_type != FUSE_SUPER_MAGIC {
        bail!(
            "staging path {} is not a FUSE mount",
            staging_mountpoint.display()
        );
    }

    let staging_mount_id = mount_unique_id(staging.as_raw_fd())?;
    let parent = open_parent(&staging)?;
    if staging_mount_id == mount_unique_id(parent.as_raw_fd())? {
        bail!(
            "staging path {} is not a distinct mount",
            staging_mountpoint.display()
        );
    }
    Ok(())
}

/// Running idmapped visible mount and its private staging FUSE session.
pub struct IdmappedSession {
    target_path: PathBuf,
    target_fd: Option<File>,
    visible_mount_id: Option<u64>,
    staging_instance: PathBuf,
    staging_mountpoint: PathBuf,
    target_lock: Option<File>,
    session: Option<BackgroundSession>,
    cleanup_complete: bool,
}

impl IdmappedSession {
    pub fn session_finished(&self) -> bool {
        self.session
            .as_ref()
            .is_none_or(|session| session.guard.is_finished())
    }

    pub fn finish(mut self) -> Result<()> {
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleanup_complete {
            return Ok(());
        }
        self.cleanup_complete = true;

        if let Some(expected_mount_id) = self.visible_mount_id.take() {
            let current_mount_id = open_directory(&self.target_path)
                .and_then(|file| mount_unique_id(file.as_raw_fd()).map_err(io::Error::other));
            match current_mount_id {
                Ok(current) if current == expected_mount_id => {
                    if let Err(err) = eager_unmount(&self.target_path) {
                        self.preserve_residual_session();
                        return Err(err).with_context(|| {
                            format!(
                                "unmounting visible idmapped mount {}; residual idmapped mount preserved",
                                self.target_path.display()
                            )
                        });
                    }
                }
                Ok(current) => {
                    self.preserve_residual_session();
                    bail!(
                        "refusing to unmount {}: mount identity changed from {} to {}; residual idmapped mount preserved",
                        self.target_path.display(),
                        expected_mount_id,
                        current
                    );
                }
                Err(err) => {
                    self.preserve_residual_session();
                    return Err(err).with_context(|| {
                        format!(
                            "refusing to unmount {} because its mount identity cannot be verified; residual idmapped mount preserved",
                            self.target_path.display()
                        )
                    });
                }
            }
        }

        let mut first_error = None;
        if let Some(session) = self.session.take() {
            if let Err(err) = session.umount_and_join() {
                first_error = Some(anyhow!(err).context("unmounting staging FUSE session"));
            }
        }
        cleanup_staging_dirs(
            &[&self.staging_mountpoint, &self.staging_instance],
            &mut first_error,
        );
        self.target_fd.take();
        self.target_lock.take();

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn preserve_residual_session(&mut self) {
        if let Some(session) = self.session.take() {
            std::mem::forget(session);
        }
        warn!(
            "preserving staging mount {} for residual visible mount",
            self.staging_mountpoint.display()
        );
    }
}

impl Drop for IdmappedSession {
    fn drop(&mut self) {
        if let Err(err) = self.cleanup() {
            error!("failed to clean idmapped FUSE session: {err:#}");
        }
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("reading current directory")?
            .join(path))
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn open_parent(directory: &File) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"..".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn reject_mountpoint_or_root(
    target: &File,
    target_identity: FileIdentity,
    target_mount_id: u64,
) -> Result<()> {
    let parent = open_parent(target).context("opening target parent")?;
    let parent_identity = FileIdentity::from_file(&parent).context("inspecting target parent")?;
    if target_identity == parent_identity {
        bail!("the filesystem root cannot be used as an idmap target");
    }
    let parent_mount_id =
        mount_unique_id(parent.as_raw_fd()).context("reading target parent mount identity")?;
    if target_mount_id != parent_mount_id {
        bail!("idmap target is already a mountpoint");
    }
    Ok(())
}

fn ensure_private_dir(path: &Path, mode: u32) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{} is not a real directory", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "{} is not owned by the daemon uid {}",
            path.display(),
            unsafe { libc::geteuid() }
        );
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn ensure_private_staging_mount(path: &Path) -> Result<()> {
    ensure_private_dir(path, 0o700)?;

    let lock_path = path.join(".propagation.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| format!("opening staging propagation lock {}", lock_path.display()))?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err).context("locking staging mount propagation");
        }
    }

    let staging = open_directory(path).context("opening idmap staging root")?;
    let parent = open_parent(&staging).context("opening idmap staging root parent")?;
    if mount_unique_id(staging.as_raw_fd())? == mount_unique_id(parent.as_raw_fd())? {
        let path = path_cstring(path)?;
        let rc = unsafe {
            libc::mount(
                path.as_ptr(),
                path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("creating staging bind mount");
        }
    }

    let path = path_cstring(path)?;
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            path.as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error())
            .context("marking staging mount recursively private");
    }
    Ok(())
}

fn create_dir_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(mode).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn acquire_target_lock(target: &File) -> Result<File> {
    // O_PATH descriptors cannot be flocked. Reopen "." relative to the
    // already validated target fd so the lock follows the directory inode
    // without creating persistent per-target lock files.
    let fd = unsafe {
        libc::openat(
            target.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("opening idmap target for locking");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            bail!("another idmap mount operation already owns target lock");
        }
        return Err(err).context("locking idmap target");
    }
    Ok(file)
}

fn mount_unique_id(fd: RawFd) -> Result<u64> {
    let mut stat = MaybeUninit::<libc::statx>::zeroed();
    let rc = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            STATX_MNT_ID_UNIQUE,
            stat.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("statx(STATX_MNT_ID_UNIQUE)");
    }
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
        bail!("kernel did not return STATX_MNT_ID_UNIQUE");
    }
    Ok(stat.stx_mnt_id)
}

fn move_mount(detached_mount_fd: RawFd, target_fd: RawFd) -> Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            detached_mount_fd as libc::c_long,
            c"".as_ptr(),
            target_fd as libc::c_long,
            c"".as_ptr(),
            (libc::MOVE_MOUNT_F_EMPTY_PATH | libc::MOVE_MOUNT_T_EMPTY_PATH) as libc::c_uint,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("move_mount to target fd");
    }
    Ok(())
}

fn eager_unmount(path: &Path) -> Result<()> {
    let target = path_cstring(path)?;
    for attempt in 1..=UNMOUNT_RETRY_ATTEMPTS {
        let rc = unsafe { libc::umount2(target.as_ptr(), libc::UMOUNT_NOFOLLOW) };
        if rc == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBUSY) || attempt == UNMOUNT_RETRY_ATTEMPTS {
            return Err(err).context("umount2");
        }

        debug!(
            "idmapped unmount attempt {attempt} for {} failed with EBUSY; retrying",
            path.display()
        );
        std::thread::sleep(UNMOUNT_RETRY_DELAY);
    }
    unreachable!("unmount retry loop always returns")
}

fn cleanup_staging_dirs(paths: &[&Path], first_error: &mut Option<anyhow::Error>) {
    for path in paths {
        if let Err(err) = fs::remove_dir(path) {
            if err.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                *first_error = Some(anyhow!(err).context(format!(
                    "removing idmap staging directory {}",
                    path.display()
                )));
            }
        }
    }
}

#[cfg(test)]
fn apply_idmap(
    source_mountpoint: &Path,
    target_mountpoint: &Path,
    mappings: &[IdMapTriple],
) -> Result<()> {
    if source_mountpoint == target_mountpoint {
        bail!("idmap source and target mountpoints must differ");
    }
    let detached = prepare_idmap(source_mountpoint, mappings)?;
    let target = open_directory(target_mountpoint)?;
    move_mount(detached.mount_fd(), target.as_raw_fd())?;
    drop(detached);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuser::{
        Config as FuseConfig, FileAttr, FileType, Filesystem, INodeNo, InitFlags, KernelConfig,
        MountOption, ReplyAttr, ReplyStatfs, Request, Session, SessionACL,
    };
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Output};
    use std::sync::{mpsc::Sender, Arc};
    use std::time::{Duration, UNIX_EPOCH};
    use tempfile::TempDir;

    const FUSE_INVALID_UIDGID: u32 = u32::MAX;

    /// A minimal FUSE filesystem that reports a single root inode (ino=1)
    /// as a directory with a fixed uid/gid. Used so that `stat` on the
    /// mountpoint returns a known id, letting us observe how `apply_idmap`
    /// rewrites it at the kernel VFS layer.
    ///
    /// `last_caller_ids` records the raw uid/gid the kernel put in the most
    /// recent FUSE request header. For non-creation requests on an idmapped
    /// mount, the kernel reports `FUSE_INVALID_UIDGID`; tests verify that the
    /// daemon cannot rely on these fields for idmap translation.
    struct MockFs {
        stored_uid: u32,
        stored_gid: u32,
        last_caller_ids: CallerIdRecorder,
        init_notifier: Option<Sender<bool>>,
    }

    impl Filesystem for MockFs {
        fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
            // Mirror what ErofsFs::init does so mount_setattr(IDMAP) is
            // accepted by the kernel.
            let idmap_supported = config.add_capabilities(InitFlags::FUSE_ALLOW_IDMAP).is_ok();
            if let Some(notifier) = self.init_notifier.take() {
                let _ = notifier.send(idmap_supported);
            }
            Ok(())
        }
        fn getattr(
            &self,
            req: &Request,
            ino: INodeNo,
            _fh: Option<fuser::FileHandle>,
            reply: ReplyAttr,
        ) {
            // Record the raw caller ids from the request header. For getattr
            // through an idmapped mount, tests expect FUSE_INVALID_UIDGID.
            if let Ok(mut g) = self.last_caller_ids.lock() {
                *g = Some((req.uid(), req.gid()));
            }
            if ino.0 != 1 {
                reply.error(fuser::Errno::ENOENT);
                return;
            }
            let attr = FileAttr {
                ino: INodeNo(1),
                size: 0,
                blocks: 0,
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: self.stored_uid,
                gid: self.stored_gid,
                rdev: 0,
                blksize: 4096,
                flags: 0,
            };
            // Every request-path assertion needs a fresh getattr instead of
            // reusing the root inode attributes cached by an earlier stat.
            reply.attr(&Duration::ZERO, &attr);
        }

        fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
            reply.statfs(0, 0, 0, 1, 0, 4096, 255, 4096);
        }
    }

    /// The uid/gid the kernel put in the most recent FUSE request header.
    type CallerIdRecorder = Arc<std::sync::Mutex<Option<(u32, u32)>>>;

    /// What [`mount_mock_fs`] hands back: the staging source directory, the
    /// unmounted idmap target directory, the running session, the caller-id
    /// recorder, and whether the kernel accepted `FUSE_ALLOW_IDMAP`.
    type MockMount = (
        TempDir,
        TempDir,
        fuser::BackgroundSession,
        CallerIdRecorder,
        bool,
    );

    /// Mount a `MockFs` at a staging tempdir. The caller must unmount an
    /// idmapped target before calling `bg.umount_and_join()` on the staging
    /// source.
    fn mount_mock_fs(stored_uid: u32, stored_gid: u32) -> MockMount {
        let source = TempDir::new().expect("tempdir for mock fuse mount");
        let target = TempDir::new().expect("tempdir for idmapped target mount");
        std::fs::set_permissions(source.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make mock FUSE source searchable");
        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make mock idmapped target searchable");
        let (bg, last_caller_ids, idmap_supported) =
            mount_mock_fs_at(source.path(), stored_uid, stored_gid);
        (source, target, bg, last_caller_ids, idmap_supported)
    }

    fn mount_mock_fs_at(
        source: &Path,
        stored_uid: u32,
        stored_gid: u32,
    ) -> (fuser::BackgroundSession, CallerIdRecorder, bool) {
        let mut cfg = FuseConfig::default();
        cfg.mount_options = vec![
            MountOption::FSName("nydus-idmap-test".to_string()),
            // The kernel accepts FUSE_ALLOW_IDMAP in the init reply only
            // when default_permissions is enabled.
            MountOption::DefaultPermissions,
        ];
        cfg.acl = SessionACL::All;
        cfg.n_threads = Some(1);
        let last_caller_ids = Arc::new(std::sync::Mutex::new(None));
        let (init_tx, init_rx) = std::sync::mpsc::channel();
        let fs = MockFs {
            stored_uid,
            stored_gid,
            last_caller_ids: last_caller_ids.clone(),
            init_notifier: Some(init_tx),
        };
        let session = Session::new(fs, source, &cfg).expect("fuse mount");
        let bg = session.spawn().expect("fuse spawn");
        let idmap_supported = init_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("FUSE init reply");
        verify_staging_fuse_mount(source, Duration::from_secs(5))
            .expect("complete FUSE_INIT request barrier");
        (bg, last_caller_ids, idmap_supported)
    }

    fn skip_unless_fuse_allow_idmap(
        idmap_supported: bool,
        source: &Path,
        bg: fuser::BackgroundSession,
    ) -> Option<fuser::BackgroundSession> {
        if idmap_supported {
            return Some(bg);
        }

        detach_mock_fs(source, bg);
        eprintln!("skipping: kernel does not support FUSE_ALLOW_IDMAP");
        None
    }

    /// Verify the host-side uid/gid reported by `stat` as a mapped caller.
    fn assert_stat_mountpoint_uid_gid_as(
        path: &Path,
        caller_uid: u32,
        caller_gid: u32,
        expected_uid: u32,
        expected_gid: u32,
    ) {
        let output = run_as_uid(path, caller_uid, caller_gid)
            .unwrap_or_else(|err| panic!("stat as uid {caller_uid} failed to start: {err}"));
        assert!(
            output.status.success(),
            "stat as uid {caller_uid} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!("{expected_uid}:{expected_gid}"),
            "stat as uid {caller_uid} returned unexpected ownership"
        );
    }

    fn unmount_idmapped_target(path: &Path) {
        let path = path_cstring(path).expect("target mountpoint C string");
        // SAFETY: path is NUL-terminated and remains live through the call.
        let rc = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
        assert_eq!(rc, 0, "unmount target: {}", io::Error::last_os_error());
    }

    fn detach_mock_fs(path: &Path, bg: fuser::BackgroundSession) {
        let path = path_cstring(path).expect("mock source mountpoint C string");
        // SAFETY: path is NUL-terminated and remains live through the call.
        let rc = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
        assert_eq!(rc, 0, "detach mock source: {}", io::Error::last_os_error());
        bg.join().expect("join detached mock FUSE session");
    }

    /// Run `stat` in a separate process with exactly the requested credentials.
    ///
    /// FUSE has already started worker threads at each call site, so a
    /// hand-written fork must not run Rust code in the child before exec.
    fn run_as_uid(path: &Path, drop_uid: u32, drop_gid: u32) -> io::Result<Output> {
        let mut command = Command::new("stat");
        command.args(["--format=%u:%g", "--"]).arg(path);
        // SAFETY: setgroups, setgid, and setuid are async-signal-safe, and
        // pre_exec propagates any credential-change failure through spawn.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(drop_gid as libc::gid_t) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(drop_uid as libc::uid_t) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.output()
    }

    #[test]
    fn serialize_id_mappings_formats_one_entry_per_line() {
        let m = vec![IdMapTriple {
            internal: 0,
            external: 100000,
            range: 65536,
        }];
        assert_eq!(serialize_id_mappings(&m), "0 100000 65536\n");
    }

    #[test]
    fn serialize_id_mappings_formats_multiple_entries() {
        let m = vec![
            IdMapTriple {
                internal: 0,
                external: 100000,
                range: 65536,
            },
            IdMapTriple {
                internal: 65536,
                external: 1000,
                range: 1,
            },
        ];
        assert_eq!(serialize_id_mappings(&m), "0 100000 65536\n65536 1000 1\n");
    }

    #[test]
    fn preparation_rejects_symlink_target() {
        let root = TempDir::new().unwrap();
        let target = root.path().join("target");
        let link = root.path().join("link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();
        let err = IdmapMountPreparation::new_in(&link, &root.path().join("staging"))
            .err()
            .expect("symlink target should fail");
        assert!(
            format!("{err:#}").contains("opening idmap target"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn preparation_serializes_same_target() {
        let root = TempDir::new().unwrap();
        let target = root.path().join("target");
        let staging = root.path().join("staging");
        fs::create_dir(&target).unwrap();

        let first = IdmapMountPreparation::new_in(&target, &staging).unwrap();
        assert!(
            !staging.join("locks").exists(),
            "target inode locking must not create persistent lock files"
        );
        let err = IdmapMountPreparation::new_in(&target, &staging)
            .err()
            .expect("second preparation should fail");
        assert!(
            format!("{err:#}").contains("already owns target lock"),
            "unexpected error: {err:#}"
        );
        drop(first);
        drop(IdmapMountPreparation::new_in(&target, &staging).unwrap());
    }

    #[test]
    fn preparation_rejects_replaced_target_before_attach() {
        let root = TempDir::new().unwrap();
        let target = root.path().join("target");
        let moved_target = root.path().join("moved-target");
        let staging = root.path().join("staging");
        fs::create_dir(&target).unwrap();

        let preparation = IdmapMountPreparation::new_in(&target, &staging).unwrap();
        fs::rename(&target, &moved_target).unwrap();
        fs::create_dir(&target).unwrap();

        let err = preparation.verify_target_unchanged().unwrap_err();
        assert!(
            format!("{err:#}").contains("changed while preparing"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn preparation_rejects_missing_target_before_attach() {
        let root = TempDir::new().unwrap();
        let target = root.path().join("target");
        let staging = root.path().join("staging");
        fs::create_dir(&target).unwrap();

        let preparation = IdmapMountPreparation::new_in(&target, &staging).unwrap();
        fs::remove_dir(&target).unwrap();

        let err = preparation.verify_target_unchanged().unwrap_err();
        assert!(
            format!("{err:#}").contains("reopening idmap target"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn apply_idmap_rejects_empty_mappings() {
        let source = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        let r = apply_idmap(source.path(), target.path(), &[]);
        assert!(
            r.is_err(),
            "apply_idmap should refuse an empty mapping list"
        );
        let msg = format!("{}", r.unwrap_err());
        assert!(
            msg.contains("no entries") || msg.contains("empty"),
            "error should mention emptiness: {msg}"
        );
    }

    #[test]
    fn apply_idmap_rejects_invalid_mappings_defensively() {
        // `Config::from_file` rejects this at startup, but a programmatic
        // caller could pass an in-memory Vec. apply_idmap must re-validate
        // before forking the userns child.
        let source = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        // overlapping on internal side: [0,1000) and [500,1500)
        let bad = vec![
            IdMapTriple {
                internal: 0,
                external: 100000,
                range: 1000,
            },
            IdMapTriple {
                internal: 500,
                external: 200000,
                range: 1000,
            },
        ];
        let r = apply_idmap(source.path(), target.path(), &bad);
        assert!(
            r.is_err(),
            "apply_idmap should reject overlapping mappings defensively"
        );
        // The error chain includes the validator's "overlap" message.
        let msg = format!("{:#}", r.unwrap_err());
        assert!(
            msg.contains("overlap"),
            "error should mention overlap: {msg}"
        );
    }

    #[test]
    fn apply_idmap_rejects_too_many_entries_defensively() {
        let source = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        let bad: Vec<IdMapTriple> = (0..=crate::config::MAX_ID_MAP_ENTRIES as u32)
            .map(|i| IdMapTriple {
                internal: i,
                external: 100000 + i,
                range: 1,
            })
            .collect();
        let r = apply_idmap(source.path(), target.path(), &bad);
        assert!(
            r.is_err(),
            "apply_idmap should defensively reject more than {} entries",
            crate::config::MAX_ID_MAP_ENTRIES
        );
    }

    #[test]
    fn apply_idmap_rejects_identical_source_and_target() {
        let tmp = TempDir::new().unwrap();
        let mappings = [IdMapTriple {
            internal: 0,
            external: 100000,
            range: 65536,
        }];
        let err = apply_idmap(tmp.path(), tmp.path(), &mappings).unwrap_err();
        assert!(err.to_string().contains("must differ"));
    }

    #[test]
    #[ignore = "requires root + Linux >= 6.12 with FUSE_ALLOW_IDMAP"]
    fn lifecycle_rejects_target_path_replacement() {
        let root = TempDir::new().expect("lifecycle root");
        let target = root.path().join("target");
        let moved_target = root.path().join("moved-target");
        let staging = root.path().join("staging");
        fs::create_dir(&target).expect("create target");

        let mut preparation =
            IdmapMountPreparation::new_in(&target, &staging).expect("prepare idmap mount");
        let (bg, _, idmap_supported) = mount_mock_fs_at(preparation.staging_mountpoint(), 0, 0);
        preparation.set_session(bg).expect("record FUSE session");
        if !idmap_supported {
            eprintln!("skipping: kernel does not support FUSE_ALLOW_IDMAP");
            return;
        }

        fs::rename(&target, &moved_target).expect("replace target after preparation");
        fs::create_dir(&target).expect("create replacement target");
        let err = match preparation.attach(
            &[IdMapTriple {
                internal: 0,
                external: 100000,
                range: 65536,
            }],
            Duration::from_secs(5),
        ) {
            Ok(_) => panic!("attach must reject a replaced target path"),
            Err(err) => err,
        };
        assert!(
            format!("{err:#}").contains("changed while preparing"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[ignore = "requires root + Linux >= 6.12 with FUSE_ALLOW_IDMAP"]
    fn it_should_apply_id_mapping_after_mount() {
        // The mock fs stores uid/gid = 0/0 (the "internal" / image-side
        // value). With id_mapping [(0, 100000, 65536)] the kernel must
        // rewrite these to 100000/100000 for host-side `stat`.
        let (source, target, bg, _recorder, idmap_supported) = mount_mock_fs(0, 0);
        let Some(bg) = skip_unless_fuse_allow_idmap(idmap_supported, source.path(), bg) else {
            return;
        };

        let mappings = vec![IdMapTriple {
            internal: 0,
            external: 100000,
            range: 65536,
        }];
        apply_idmap(source.path(), target.path(), &mappings)
            .expect("apply_idmap should succeed on a FUSE mount that advertised FUSE_ALLOW_IDMAP");

        assert_stat_mountpoint_uid_gid_as(target.path(), 100000, 100000, 100000, 100000);

        unmount_idmapped_target(target.path());
        bg.umount_and_join().expect("unmount mock fs");
    }

    #[test]
    #[ignore = "requires root + Linux >= 6.12 with FUSE_ALLOW_IDMAP"]
    fn it_should_keep_per_mount_id_mapping_isolated() {
        // Two FUSE mounts, each backed by a MockFs storing uid/gid = 0/0,
        // but with different external mappings. Each mountpoint must
        // observe its own external value, proving the idmaps do not leak
        // between mounts.
        let (source_a, target_a, bg_a, _, idmap_supported_a) = mount_mock_fs(0, 0);
        let (source_b, target_b, bg_b, _, idmap_supported_b) = mount_mock_fs(0, 0);
        if !idmap_supported_a || !idmap_supported_b {
            detach_mock_fs(source_a.path(), bg_a);
            detach_mock_fs(source_b.path(), bg_b);
            eprintln!("skipping: kernel does not support FUSE_ALLOW_IDMAP");
            return;
        }

        apply_idmap(
            source_a.path(),
            target_a.path(),
            &[IdMapTriple {
                internal: 0,
                external: 100000,
                range: 65536,
            }],
        )
        .expect("apply_idmap on mount A");
        apply_idmap(
            source_b.path(),
            target_b.path(),
            &[IdMapTriple {
                internal: 0,
                external: 200000,
                range: 65536,
            }],
        )
        .expect("apply_idmap on mount B");

        assert_stat_mountpoint_uid_gid_as(target_a.path(), 100000, 100000, 100000, 100000);
        assert_stat_mountpoint_uid_gid_as(target_b.path(), 200000, 200000, 200000, 200000);

        unmount_idmapped_target(target_a.path());
        unmount_idmapped_target(target_b.path());
        bg_a.umount_and_join().expect("unmount A");
        bg_b.umount_and_join().expect("unmount B");
    }

    #[test]
    #[ignore = "requires root + Linux >= 6.12 with FUSE_ALLOW_IDMAP"]
    fn it_should_hide_non_creation_caller_ids_from_daemon() {
        // For idmapped FUSE mounts, the kernel performs permission checks
        // itself. It deliberately sends FUSE_INVALID_UIDGID for non-creation
        // requests such as getattr rather than exposing a possibly ambiguous
        // mapped caller uid/gid to the daemon.
        let (source, target, bg, recorder, idmap_supported) = mount_mock_fs(0, 0);
        let Some(bg) = skip_unless_fuse_allow_idmap(idmap_supported, source.path(), bg) else {
            return;
        };
        let mountpoint = target.path().to_path_buf();

        apply_idmap(
            source.path(),
            target.path(),
            &[IdMapTriple {
                internal: 0,
                external: 100000,
                range: 65536,
            }],
        )
        .expect("apply_idmap");

        // Clear any prior request then stat as the externally mapped user.
        {
            let mut g = recorder.lock().expect("recorder lock");
            *g = None;
        }
        let output = run_as_uid(&mountpoint, 100000, 100000).expect("start stat as uid 100000");
        assert!(
            output.status.success(),
            "child stat as uid 100000 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let observed = {
            let g = recorder.lock().expect("recorder lock");
            *g
        };
        let (uid_seen, gid_seen) =
            observed.expect("daemon did not receive a getattr after the child's stat");
        assert_eq!(
            uid_seen, FUSE_INVALID_UIDGID,
            "non-creation requests must hide the caller uid",
        );
        assert_eq!(
            gid_seen, FUSE_INVALID_UIDGID,
            "non-creation requests must hide the caller gid"
        );
        unmount_idmapped_target(target.path());
        bg.umount_and_join().expect("unmount mock fs");
    }

    #[test]
    #[ignore = "requires root + Linux >= 6.12 with FUSE_ALLOW_IDMAP"]
    fn it_should_hide_non_creation_caller_ids_on_every_idmapped_mount() {
        // FUSE_INVALID_UIDGID applies independently to each idmapped mount's
        // non-creation request path. The metadata-path test above verifies
        // that the per-mount mappings themselves remain isolated.
        let (source_a, target_a, bg_a, rec_a, idmap_supported_a) = mount_mock_fs(0, 0);
        let (source_b, target_b, bg_b, rec_b, idmap_supported_b) = mount_mock_fs(0, 0);
        if !idmap_supported_a || !idmap_supported_b {
            detach_mock_fs(source_a.path(), bg_a);
            detach_mock_fs(source_b.path(), bg_b);
            eprintln!("skipping: kernel does not support FUSE_ALLOW_IDMAP");
            return;
        }

        apply_idmap(
            source_a.path(),
            target_a.path(),
            &[IdMapTriple {
                internal: 0,
                external: 100000,
                range: 65536,
            }],
        )
        .expect("apply_idmap A");
        apply_idmap(
            source_b.path(),
            target_b.path(),
            &[IdMapTriple {
                internal: 0,
                external: 200000,
                range: 65536,
            }],
        )
        .expect("apply_idmap B");

        // Stat A as host uid 100000 -> daemon A sees the invalid-id sentinel.
        {
            let mut g = rec_a.lock().unwrap();
            *g = None;
        }
        let output =
            run_as_uid(target_a.path(), 100000, 100000).expect("start stat A as uid 100000");
        assert!(
            output.status.success(),
            "stat A as 100000: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (u_a, _) = rec_a.lock().unwrap().expect("A recorder empty");
        assert_eq!(
            u_a, FUSE_INVALID_UIDGID,
            "mount A must hide non-creation caller IDs"
        );

        // Stat B as host uid 200000 -> daemon B sees the invalid-id sentinel.
        {
            let mut g = rec_b.lock().unwrap();
            *g = None;
        }
        let output =
            run_as_uid(target_b.path(), 200000, 200000).expect("start stat B as uid 200000");
        assert!(
            output.status.success(),
            "stat B as 200000: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (u_b, _) = rec_b.lock().unwrap().expect("B recorder empty");
        assert_eq!(
            u_b, FUSE_INVALID_UIDGID,
            "mount B must hide non-creation caller IDs"
        );

        unmount_idmapped_target(target_a.path());
        unmount_idmapped_target(target_b.path());
        bg_a.umount_and_join().expect("unmount A");
        bg_b.umount_and_join().expect("unmount B");
    }

    #[test]
    #[ignore = "requires root + Linux >= 6.12 with FUSE_ALLOW_IDMAP"]
    fn it_should_fail_gracefully_when_kernel_lacks_fuse_allow_idmap() {
        // On a kernel without FUSE_ALLOW_IDMAP, MockFs::init's
        // add_capabilities returns the bit as unsupported (silently
        // dropped by fuser), and mount_setattr then fails. apply_idmap
        // must return an Err rather than panic, so the caller can clean up
        // the private source mount.
        let (source, target, bg, _, _idmap_supported) = mount_mock_fs(0, 0);
        let mappings = vec![IdMapTriple {
            internal: 0,
            external: 100000,
            range: 65536,
        }];
        let result = apply_idmap(source.path(), target.path(), &mappings);

        if result.is_ok() {
            // Kernel supports it — sanity-check that the idmap took effect.
            assert_stat_mountpoint_uid_gid_as(target.path(), 100000, 100000, 100000, 100000);
            unmount_idmapped_target(target.path());
        } else {
            // Kernel refused — verify we got an Err, not a panic, and
            // that the mount itself is still usable (stat returns the
            // stored uid 0).
            let err = result.unwrap_err();
            assert!(
                format!("{err:#}").contains("mount_setattr"),
                "error should mention mount_setattr: {err:#}"
            );
            let metadata = std::fs::metadata(source.path()).expect("stat source mountpoint");
            assert_eq!(
                metadata.uid(),
                0,
                "without idmap, stat must return the stored uid"
            );
        }
        bg.umount_and_join().expect("unmount mock fs");
    }
}

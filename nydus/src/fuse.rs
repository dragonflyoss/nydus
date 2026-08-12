use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenFlags, PollEvents, PollFlags, PollNotifier, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyPoll, ReplyStatfs,
    ReplyXattr, Request,
};
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use tracing::{error, info};

use nydus_core::metadata::*;
use nydus_core::telemetry::metrics;

use nydus_core::fs::{ErofsReader, RawDirEntry};

const FUSE_ROOT_ID: u64 = 1;
const EROFS_FUSE_TIMEOUT: Duration = Duration::from_secs(86400 * 365 * 10);

/// Longest name EROFS can encode, reported through statfs and enforced in
/// lookup. The kernel only rejects names above FUSE_NAME_MAX (1024), so a
/// filesystem that advertises a smaller f_namelen has to check it itself or
/// callers get ENOENT where POSIX requires ENAMETOOLONG.
const EROFS_NAME_MAX: usize = 255;

pub struct ErofsFs {
    reader: Arc<ErofsReader>,
    dir_handles: Mutex<HashMap<u64, Arc<DirHandle>>>,
    next_dir_handle: AtomicU64,
}

struct DirHandle {
    entries: Vec<RawDirEntry>,
}

impl ErofsFs {
    pub fn new(reader: Arc<ErofsReader>) -> Self {
        Self {
            reader,
            dir_handles: Mutex::new(HashMap::new()),
            next_dir_handle: AtomicU64::new(1),
        }
    }

    fn ino_to_nid(&self, ino: u64) -> u64 {
        if ino == FUSE_ROOT_ID {
            self.reader.sb().root_nid()
        } else {
            ino - FUSE_ROOT_ID
        }
    }

    fn nid_to_ino(&self, nid: u64) -> u64 {
        if nid == self.reader.sb().root_nid() {
            FUSE_ROOT_ID
        } else {
            nid + FUSE_ROOT_ID
        }
    }

    fn make_attr(&self, nid: u64, inode: &ErofsInode<'_>) -> FileAttr {
        let ino = self.nid_to_ino(nid);
        let sb = self.reader.sb();
        let block_size = 1u64 << sb.blkszbits;
        let mtime_secs = inode.mtime(sb.epoch());
        let mtime_nsec = inode.effective_mtime_nsec(sb.fixed_nsec());
        let size = inode.size();
        let blocks = size.div_ceil(block_size) * block_size / 512;
        let time = UNIX_EPOCH + Duration::new(mtime_secs, mtime_nsec);

        let mode = inode.mode() as u32;
        let kind = mode_to_kind(mode);
        let rdev =
            if (mode & libc::S_IFMT) == libc::S_IFCHR || (mode & libc::S_IFMT) == libc::S_IFBLK {
                inode.rdev()
            } else {
                0
            };

        // The root directory is created by whichever tool staged the layer, so
        // its permission bits are really that tool's umask. A umask of 0077
        // yields 0700 and locks every other uid out of the container rootfs,
        // and `rootmode=` does not override them. nydus v2 pins the root to
        // 0755 at runtime for the same reason.
        let perm = if ino == FUSE_ROOT_ID {
            (mode & !0o777) | 0o755
        } else {
            mode
        } & 0o7777;

        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm: perm as u16,
            nlink: inode.nlink(),
            uid: inode.uid(),
            gid: inode.gid(),
            rdev,
            blksize: block_size as u32,
            flags: 0,
        }
    }

    fn iterate_dir<F>(&self, inode: u64, mut cb: F) -> io::Result<()>
    where
        F: FnMut(u64, u8, &[u8]) -> io::Result<bool>,
    {
        let nid = self.ino_to_nid(inode);
        let vi = self.reader.inode(nid)?;
        self.reader
            .for_each_dir_entry(nid, &vi, |entry_nid, file_type, name| {
                cb(entry_nid, file_type, name)
            })
    }

    fn create_dir_handle(&self, inode: u64) -> io::Result<u64> {
        let nid = self.ino_to_nid(inode);
        let vi = self.reader.inode(nid)?;
        let entries = self.reader.read_dir(nid, &vi)?;
        let handle = self.next_dir_handle.fetch_add(1, Ordering::Relaxed);
        let dir_handle = Arc::new(DirHandle { entries });
        self.dir_handles.lock().unwrap().insert(handle, dir_handle);
        Ok(handle)
    }

    fn dir_handle(&self, handle: u64) -> io::Result<Arc<DirHandle>> {
        self.dir_handles
            .lock()
            .unwrap()
            .get(&handle)
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
    }
}

fn io_errno(e: &io::Error) -> Errno {
    Errno::from_i32(e.raw_os_error().unwrap_or(libc::EIO))
}

/// RAII guard that records a FUSE operation's outcome and latency on drop.
/// It assumes success unless [`fail`](FsOpMetric::fail) is called before the
/// op replies with an error.
struct FsOpMetric {
    op: metrics::FsOp,
    start: Instant,
    errored: bool,
}

impl FsOpMetric {
    fn new(op: metrics::FsOp) -> Self {
        Self {
            op,
            start: Instant::now(),
            errored: false,
        }
    }

    fn fail(&mut self) {
        self.errored = true;
    }
}

impl Drop for FsOpMetric {
    fn drop(&mut self) {
        metrics::record_fs_op(self.op, self.start.elapsed(), self.errored);
    }
}

fn mode_to_kind(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFREG => FileType::RegularFile,
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

fn erofs_ft_to_kind(ft: u8) -> FileType {
    match ft {
        EROFS_FT_REG_FILE => FileType::RegularFile,
        EROFS_FT_DIR => FileType::Directory,
        EROFS_FT_CHRDEV => FileType::CharDevice,
        EROFS_FT_BLKDEV => FileType::BlockDevice,
        EROFS_FT_FIFO => FileType::NamedPipe,
        EROFS_FT_SOCK => FileType::Socket,
        EROFS_FT_SYMLINK => FileType::Symlink,
        _ => FileType::RegularFile,
    }
}

fn should_hide_xattr(ino: u64, name: &[u8]) -> bool {
    ino == FUSE_ROOT_ID && is_nydus_xattr(name)
}

impl Filesystem for ErofsFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut m = FsOpMetric::new(metrics::FsOp::Lookup);
        let target = name.as_bytes();
        if target.len() > EROFS_NAME_MAX {
            m.fail();
            reply.error(Errno::ENAMETOOLONG);
            return;
        }
        let mut found = None;
        let res = self.iterate_dir(parent.0, |entry_nid, _file_type, entry_name| {
            if entry_name == target {
                found = Some(entry_nid);
                return Ok(false);
            }
            Ok(true)
        });
        if let Err(e) = res {
            m.fail();
            reply.error(io_errno(&e));
            return;
        }

        if let Some(child_nid) = found {
            match self.reader.inode(child_nid) {
                Ok(child_inode) => {
                    let attr = self.make_attr(child_nid, &child_inode);
                    reply.entry(&EROFS_FUSE_TIMEOUT, &attr, Generation(0));
                }
                Err(e) => {
                    m.fail();
                    reply.error(io_errno(&e));
                }
            }
            return;
        }

        m.fail();
        reply.error(Errno::ENOENT);
    }

    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {
        let _m = FsOpMetric::new(metrics::FsOp::Forget);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let mut m = FsOpMetric::new(metrics::FsOp::Getattr);
        let nid = self.ino_to_nid(ino.0);
        match self.reader.inode(nid) {
            Ok(vi) => {
                let attr = self.make_attr(nid, &vi);
                reply.attr(&EROFS_FUSE_TIMEOUT, &attr);
            }
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
            }
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let mut m = FsOpMetric::new(metrics::FsOp::Open);
        if flags.0 & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            m.fail();
            reply.error(Errno::EROFS);
            return;
        }

        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        if (vi.mode() as u32 & libc::S_IFMT) != libc::S_IFREG {
            m.fail();
            reply.error(Errno::EISDIR);
            return;
        }

        reply.opened(FileHandle(nid), FopenFlags::FOPEN_KEEP_CACHE);
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let _m = FsOpMetric::new(metrics::FsOp::Release);
        reply.ok();
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Read-only filesystem: there is no dirty state or lock bookkeeping to
        // flush. Implement this explicitly to avoid the fuser default ENOSYS
        // warning on every close() of duplicated file descriptors.
        reply.ok();
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let mut m = FsOpMetric::new(metrics::FsOp::Read);
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };

        // Use write_file_data_to to fill a Vec<u8> zero-copy from mmap.
        let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
        match self
            .reader
            .write_file_data_to(nid, &vi, offset, size, &mut buf)
        {
            Ok(_) => reply.data(&buf),
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
            }
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let mut m = FsOpMetric::new(metrics::FsOp::Readlink);
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        match self.reader.read_symlink(nid, &vi) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
            }
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut m = FsOpMetric::new(metrics::FsOp::Opendir);
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        if (vi.mode() as u32 & libc::S_IFMT) != libc::S_IFDIR {
            m.fail();
            reply.error(Errno::ENOTDIR);
            return;
        }

        match self.create_dir_handle(ino.0) {
            Ok(handle) => reply.opened(
                FileHandle(handle),
                FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_CACHE_DIR,
            ),
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut m = FsOpMetric::new(metrics::FsOp::Readdir);
        let dir_handle = match self.dir_handle(fh.0) {
            Ok(h) => h,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in dir_handle.entries.iter().enumerate().skip(start) {
            let ino = self.nid_to_ino(entry.nid);
            let kind = erofs_ft_to_kind(entry.file_type);
            let name = OsStr::from_bytes(&entry.name);
            if reply.add(INodeNo(ino), (index as u64) + 1, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let mut m = FsOpMetric::new(metrics::FsOp::Readdirplus);
        let dir_handle = match self.dir_handle(fh.0) {
            Ok(h) => h,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in dir_handle.entries.iter().enumerate().skip(start) {
            let child_inode = match self.reader.inode(entry.nid) {
                Ok(vi) => vi,
                Err(e) => {
                    m.fail();
                    reply.error(io_errno(&e));
                    return;
                }
            };
            let attr = self.make_attr(entry.nid, &child_inode);
            let ino = self.nid_to_ino(entry.nid);
            let name = OsStr::from_bytes(&entry.name);
            if reply.add(
                INodeNo(ino),
                (index as u64) + 1,
                name,
                &EROFS_FUSE_TIMEOUT,
                &attr,
                Generation(0),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.dir_handles.lock().unwrap().remove(&fh.0);
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let _m = FsOpMetric::new(metrics::FsOp::Statfs);
        let sb = self.reader.sb();
        let block_size = 1u64 << sb.blkszbits;
        reply.statfs(
            sb.blocks(),
            0,
            0,
            sb.inos(),
            0,
            block_size as u32,
            EROFS_NAME_MAX as u32,
            block_size as u32,
        );
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        let _m = FsOpMetric::new(metrics::FsOp::Access);
        reply.ok();
    }

    fn poll(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _ph: PollNotifier,
        events: PollEvents,
        _flags: PollFlags,
        reply: ReplyPoll,
    ) {
        // Regular files are always ready for the events requested by the
        // kernel. Returning readiness avoids fuser's default ENOSYS warning
        // while preserving normal poll/select behavior for read handles.
        reply.poll(events);
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let mut m = FsOpMetric::new(metrics::FsOp::Getxattr);
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        let name_bytes = name.as_bytes();
        if should_hide_xattr(ino.0, name_bytes) {
            m.fail();
            reply.error(Errno::ENODATA);
            return;
        }

        let xattrs = match self.reader.read_xattrs(nid, &vi) {
            Ok(x) => x,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        for (xname, xvalue) in &xattrs {
            if xname.as_slice() == name_bytes {
                if size == 0 {
                    reply.size(xvalue.len() as u32);
                    return;
                }
                if (size as usize) < xvalue.len() {
                    m.fail();
                    reply.error(Errno::ERANGE);
                    return;
                }
                reply.data(xvalue);
                return;
            }
        }

        m.fail();
        reply.error(Errno::ENODATA);
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let mut m = FsOpMetric::new(metrics::FsOp::Listxattr);
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };
        let xattrs = match self.reader.read_xattrs(nid, &vi) {
            Ok(x) => x,
            Err(e) => {
                m.fail();
                reply.error(io_errno(&e));
                return;
            }
        };

        // Build null-separated list of xattr names
        let mut names_buf: Vec<u8> = Vec::new();
        for (xname, _) in &xattrs {
            if should_hide_xattr(ino.0, xname) {
                continue;
            }
            names_buf.extend_from_slice(xname);
            names_buf.push(0);
        }

        if size == 0 {
            reply.size(names_buf.len() as u32);
            return;
        }
        if (size as usize) < names_buf.len() {
            m.fail();
            reply.error(Errno::ERANGE);
            return;
        }
        reply.data(&names_buf);
    }
}

/// Mask over the termination signals ([`TERM_SIGNALS`] plus `SIGHUP`) that the
/// mount lifecycle handles via `sigwait` instead of asynchronous handlers.
pub struct TermSignalMask {
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

    /// Blocks the termination signals on the calling thread (and every thread
    /// it spawns afterwards), returning a guard that restores the previous
    /// mask on drop.
    pub fn block() -> Result<Self> {
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

/// A FUSE filesystem mounted and served on background threads, remembering
/// which mount it created so teardown never unmounts a successor's mount.
pub struct FuseSession {
    session: fuser::BackgroundSession,
    mountpoint: PathBuf,
}

impl FuseSession {
    /// Mounts `fs` at `mountpoint` and starts serving it in the background.
    pub fn mount(fs: ErofsFs, mountpoint: &Path, config: &fuser::Config) -> Result<Self> {
        let session = fuser::Session::new(fs, mountpoint, config)
            .map_err(|e| anyhow!("mount failed: {e}"))?;
        let session = session.spawn().map_err(|e| anyhow!("spawn failed: {e}"))?;
        Ok(Self {
            session,
            mountpoint: mountpoint.to_path_buf(),
        })
    }

    /// Serves until the session ends on its own or a termination signal
    /// arrives, then tears the mount down and returns the session's join
    /// result. The caller is expected to have blocked the termination signals
    /// with [`TermSignalMask::block`] before spawning any threads.
    pub fn serve(self) -> Result<std::io::Result<()>> {
        let FuseSession {
            session: bg,
            mountpoint,
        } = self;

        let wait_signals = TermSignalMask::new()?;
        // Captured before anything can replace the mount, so the teardown below
        // can tell our own mount apart from a successor's at the same path.
        let our_dev = mount_dev_of(&mountpoint)
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
                        let result = finish_session(session, &mountpoint, our_dev.clone());
                        let _ = result_tx.send(result);
                        return;
                    }

                    match unmount_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(signal) => {
                            let session = bg.take().expect("background session already taken");
                            let result = finish_session(session, &mountpoint, our_dev.clone());
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
                            let result = finish_session(session, &mountpoint, our_dev.clone());
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

        result_rx
            .recv()
            .context("failed to receive fuse controller result")
    }
}

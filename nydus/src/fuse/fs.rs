use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, InitFlags, KernelConfig, LockOwner, OpenFlags, PollEvents, PollFlags, PollNotifier,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyPoll, ReplyStatfs, ReplyXattr, Request,
};

use nydus_format::erofs::{
    is_nydus_xattr, ErofsInode, EROFS_FEATURE_COMPAT_NYDUS_NO_XATTR, EROFS_FT_BLKDEV,
    EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK,
    EROFS_FT_SYMLINK,
};
use nydus_telemetry::metrics;

use nydus_core::reader::RawDirEntry;
use nydus_core::ErofsReader;

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
    /// Kernel accepts ENOSYS from open/opendir as "stop sending them": file
    /// and directory opens then cost no FUSE round-trip at all and the dummy
    /// handles keep the page cache (KEEP_CACHE, and CACHE_DIR for dirs).
    no_open: AtomicBool,
    no_opendir: AtomicBool,
    /// Image-wide "no inode has xattrs" declaration from the builder: xattr
    /// requests answer ENOSYS so the kernel stops sending them entirely.
    no_xattr: bool,
}

/// An opened directory. Entries materialize on the first readdir; with
/// FOPEN_CACHE_DIR the kernel usually serves repeat listings from the page
/// cache and never sends that readdir, so opendir must not pay for one.
struct DirHandle {
    ino: u64,
    entries: Mutex<Option<Arc<Vec<RawDirEntry>>>>,
}

impl DirHandle {
    fn entries(&self, fs: &ErofsFs) -> io::Result<Arc<Vec<RawDirEntry>>> {
        let mut guard = self.entries.lock().unwrap();
        if let Some(entries) = guard.as_ref() {
            return Ok(entries.clone());
        }
        let nid = fs.ino_to_nid(self.ino);
        let vi = fs.reader.inode(nid)?;
        let entries = Arc::new(fs.reader.read_dir(nid, &vi)?);
        *guard = Some(entries.clone());
        Ok(entries)
    }
}

impl ErofsFs {
    pub fn new(reader: Arc<ErofsReader>) -> Self {
        let no_xattr =
            reader.superblock().feature_compat() & EROFS_FEATURE_COMPAT_NYDUS_NO_XATTR != 0;
        Self {
            reader,
            dir_handles: Mutex::new(HashMap::new()),
            next_dir_handle: AtomicU64::new(1),
            no_open: AtomicBool::new(false),
            no_opendir: AtomicBool::new(false),
            no_xattr,
        }
    }

    fn ino_to_nid(&self, ino: u64) -> u64 {
        if ino == FUSE_ROOT_ID {
            self.reader.superblock().root_nid()
        } else {
            ino - FUSE_ROOT_ID
        }
    }

    fn nid_to_ino(&self, nid: u64) -> u64 {
        if nid == self.reader.superblock().root_nid() {
            FUSE_ROOT_ID
        } else {
            nid + FUSE_ROOT_ID
        }
    }

    fn make_attr(&self, nid: u64, inode: &ErofsInode<'_>) -> FileAttr {
        let ino = self.nid_to_ino(nid);
        let sb = self.reader.superblock();
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

    fn create_dir_handle(&self, ino: u64) -> io::Result<u64> {
        let handle = self.next_dir_handle.fetch_add(1, Ordering::Relaxed);
        let dir_handle = Arc::new(DirHandle {
            ino,
            entries: Mutex::new(None),
        });
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

    /// Directory entries for a readdir(plus): through the handle when opendir
    /// issued one, or straight from the inode for the kernel's no-opendir
    /// dummy handle (fh 0).
    fn dir_entries(&self, ino: INodeNo, fh: FileHandle) -> io::Result<Arc<Vec<RawDirEntry>>> {
        if fh.0 != 0 {
            return self.dir_handle(fh.0)?.entries(self);
        }
        let nid = self.ino_to_nid(ino.0);
        let vi = self.reader.inode(nid)?;
        Ok(Arc::new(self.reader.read_dir(nid, &vi)?))
    }
}

fn io_errno(e: &io::Error) -> Errno {
    Errno::from_i32(e.raw_os_error().unwrap_or(libc::EIO))
}

/// The reply body for a cached negative lookup: ino 0 tells the kernel "no
/// such entry, remember that for the ttl". Every other field is ignored.
fn negative_attr() -> FileAttr {
    FileAttr {
        ino: INodeNo(0),
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 0,
        flags: 0,
    }
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
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // fuser only requests ASYNC_READ|BIG_WRITES|MAX_PAGES by default, so
        // without these the kernel never issues READDIRPLUS (leaving our
        // readdirplus implementation dead code), serializes lookups within one
        // directory, and drops cached symlink targets.
        let _ = config.add_capabilities(InitFlags::FUSE_DO_READDIRPLUS);
        // Deliberately NOT FUSE_READDIRPLUS_AUTO: under AUTO the kernel's
        // heuristic falls back to plain READDIR for large directories, and a
        // following stat of every entry becomes one LOOKUP round trip each.
        let _ = config.add_capabilities(InitFlags::FUSE_PARALLEL_DIROPS);
        let _ = config.add_capabilities(InitFlags::FUSE_CACHE_SYMLINKS);
        if config
            .add_capabilities(InitFlags::FUSE_NO_OPEN_SUPPORT)
            .is_ok()
        {
            self.no_open.store(true, Ordering::Relaxed);
        }
        if config
            .add_capabilities(InitFlags::FUSE_NO_OPENDIR_SUPPORT)
            .is_ok()
        {
            self.no_opendir.store(true, Ordering::Relaxed);
        }
        // Default of 16 throttles the kernel's async readahead pipeline.
        let _ = config.set_max_background(64);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut m = FsOpMetric::new(metrics::FsOp::Lookup);
        let target = name.as_bytes();
        if target.len() > EROFS_NAME_MAX {
            m.fail();
            reply.error(Errno::ENAMETOOLONG);
            return;
        }
        let parent_nid = self.ino_to_nid(parent.0);
        let found = match self
            .reader
            .inode(parent_nid)
            .and_then(|vi| self.reader.lookup_dir_entry(parent_nid, &vi, target))
        {
            Ok(found) => found,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
                return;
            }
        };

        if let Some(child_nid) = found {
            match self.reader.inode(child_nid) {
                Ok(child_inode) => {
                    let attr = self.make_attr(child_nid, &child_inode);
                    reply.entry(&EROFS_FUSE_TIMEOUT, &attr, Generation(0));
                }
                Err(err) => {
                    m.fail();
                    reply.error(io_errno(&err));
                }
            }
            return;
        }

        // Cache the miss: an entry with ino 0 is a negative dentry the kernel
        // keeps for the ttl, so repeats resolve in the dcache instead of one
        // FUSE round trip each. The image is immutable, so a miss holds
        // forever — and module resolution (Node's require walk, Python's
        // sys.path probing) retries the same missing names constantly.
        m.fail();
        reply.entry(&EROFS_FUSE_TIMEOUT, &negative_attr(), Generation(0));
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
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
            }
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let mut m = FsOpMetric::new(metrics::FsOp::Open);
        // ENOSYS makes the kernel treat this and every later open as success
        // without a handle, with KEEP_CACHE semantics; the read-only mount
        // already rejects write opens before they reach us.
        if self.no_open.load(Ordering::Relaxed) {
            reply.error(Errno::ENOSYS);
            return;
        }
        if flags.0 & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            m.fail();
            reply.error(Errno::EROFS);
            return;
        }

        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
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
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
                return;
            }
        };

        // Reuse a per-worker buffer: a fresh Vec per request costs an mmap
        // round-trip plus page faults for every large read.
        thread_local! {
            static READ_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        }
        READ_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            buf.clear();
            buf.reserve(size as usize);
            match self
                .reader
                .write_file_data_to(nid, &vi, offset, size, &mut *buf)
            {
                Ok(_) => reply.data(&buf),
                Err(err) => {
                    m.fail();
                    reply.error(io_errno(&err));
                }
            }
        });
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let mut m = FsOpMetric::new(metrics::FsOp::Readlink);
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
                return;
            }
        };
        match self.reader.read_symlink(nid, &vi) {
            Ok(data) => reply.data(&data),
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
            }
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut m = FsOpMetric::new(metrics::FsOp::Opendir);
        // See open(): dropping opendir/releasedir round-trips also gives the
        // kernel-side dummy handle FOPEN_CACHE_DIR, so repeat listings are
        // served from the page cache without any FUSE traffic.
        if self.no_opendir.load(Ordering::Relaxed) {
            reply.error(Errno::ENOSYS);
            return;
        }
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
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
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
            }
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut m = FsOpMetric::new(metrics::FsOp::Readdir);
        let entries = match self.dir_entries(ino, fh) {
            Ok(entries) => entries,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
                return;
            }
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in entries.iter().enumerate().skip(start) {
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
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let mut m = FsOpMetric::new(metrics::FsOp::Readdirplus);
        let entries = match self.dir_entries(ino, fh) {
            Ok(entries) => entries,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
                return;
            }
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in entries.iter().enumerate().skip(start) {
            let child_inode = match self.reader.inode(entry.nid) {
                Ok(vi) => vi,
                Err(err) => {
                    m.fail();
                    reply.error(io_errno(&err));
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
        let sb = self.reader.superblock();
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
        if self.no_xattr {
            reply.error(Errno::ENOSYS);
            return;
        }
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
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
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
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
        if self.no_xattr {
            reply.error(Errno::ENOSYS);
            return;
        }
        let nid = self.ino_to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
                return;
            }
        };
        let xattrs = match self.reader.read_xattrs(nid, &vi) {
            Ok(x) => x,
            Err(err) => {
                m.fail();
                reply.error(io_errno(&err));
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

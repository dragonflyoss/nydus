use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, InitFlags, KernelConfig, LockOwner, OpenFlags, PollEvents, PollFlags, PollNotifier,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyPoll, ReplyStatfs, ReplyXattr, Request,
};

use nydus_format::erofs::{
    erofs_xattr_name_split, is_nydus_xattr, ErofsInode, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV,
    EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK,
    EROFS_XATTR_INDEX_TRUSTED, NYDUS_XATTR_SUFFIX_NO_XATTR,
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
    pub fn new(reader: Arc<ErofsReader>) -> io::Result<Self> {
        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid)?;
        let no_xattr = reader
            .read_xattrs(root_nid, &root)?
            .iter()
            .any(|(name, value)| {
                erofs_xattr_name_split(name)
                    == Some((EROFS_XATTR_INDEX_TRUSTED, NYDUS_XATTR_SUFFIX_NO_XATTR))
                    && value == b"1"
            });
        Ok(Self {
            reader,
            dir_handles: Mutex::new(HashMap::new()),
            next_dir_handle: AtomicU64::new(1),
            no_open: AtomicBool::new(false),
            no_opendir: AtomicBool::new(false),
            no_xattr,
        })
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
        let time = erofs_time(mtime_secs, mtime_nsec);

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

    /// Iterate a readdir(plus) page through an opened handle's cached entries,
    /// or directly from the inode for the kernel's no-opendir dummy handle (fh 0).
    /// Cookies are entry ordinals for opened handles and directory byte offsets
    /// for dummy handles. The callback receives the next cookie; returning
    /// `false` stops iteration, so callers only save cookies for accepted entries.
    fn for_each_dir_entry<F>(
        &self,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut cb: F,
    ) -> io::Result<()>
    where
        F: FnMut(u64, u8, &[u8], u64) -> io::Result<bool>,
    {
        if fh.0 != 0 {
            let entries = self.dir_handle(fh.0)?.entries(self)?;
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            for (index, entry) in entries.iter().enumerate().skip(start) {
                if !cb(entry.nid, entry.file_type, &entry.name, index as u64 + 1)? {
                    break;
                }
            }
            return Ok(());
        }
        let nid = self.ino_to_nid(ino.0);
        let vi = self.reader.inode(nid)?;
        self.reader.for_each_dir_entry_from(nid, &vi, offset, cb)
    }
}

fn io_errno(e: &io::Error) -> Errno {
    Errno::from_i32(e.raw_os_error().unwrap_or(libc::EIO))
}

/// EROFS stores seconds as u64 but the kernel reads them as signed, so a
/// layer time before the epoch is valid.
fn erofs_time(secs: u64, nsec: u32) -> SystemTime {
    let secs = secs as i64;
    let whole = if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    };
    whole
        .and_then(|time| time.checked_add(Duration::from_nanos(nsec.into())))
        .unwrap_or(UNIX_EPOCH)
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
                    tracing::warn!(nid, offset, size, "read failed: {err}");
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
        let result = self.for_each_dir_entry(
            ino,
            fh,
            offset,
            |entry_nid, file_type, name, next_offset| {
                let ino = self.nid_to_ino(entry_nid);
                let kind = erofs_ft_to_kind(file_type);
                Ok(!reply.add(INodeNo(ino), next_offset, kind, OsStr::from_bytes(name)))
            },
        );
        if let Err(err) = result {
            m.fail();
            reply.error(io_errno(&err));
            return;
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
        let result = self.for_each_dir_entry(
            ino,
            fh,
            offset,
            |entry_nid, _file_type, name, next_offset| {
                let child_inode = self.reader.inode(entry_nid)?;
                let attr = self.make_attr(entry_nid, &child_inode);
                let ino = self.nid_to_ino(entry_nid);
                Ok(!reply.add(
                    INodeNo(ino),
                    next_offset,
                    OsStr::from_bytes(name),
                    &EROFS_FUSE_TIMEOUT,
                    &attr,
                    Generation(0),
                ))
            },
        );
        if let Err(err) = result {
            m.fail();
            reply.error(io_errno(&err));
            return;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::blob_chunk::BlobWriter;
    use crate::build::bootstrap::render_bootstrap;
    use crate::build::inode::{build_tree, resolve_chunk_addrs};
    use nydus_format::erofs::{
        XattrEntry, EROFS_BLOCK_SIZE, EROFS_DIRENT_SIZE, EROFS_INODE_FLAT_INLINE,
        EROFS_INODE_FLAT_PLAIN, EROFS_XATTR_INDEX_USER,
    };
    use std::collections::HashSet;
    use std::fs;

    #[test]
    fn erofs_times_before_the_epoch_are_signed() {
        assert_eq!(erofs_time(5, 7), UNIX_EPOCH + Duration::new(5, 7));
        assert_eq!(
            erofs_time(-1i64 as u64, 0),
            UNIX_EPOCH - Duration::from_secs(1)
        );
        assert_eq!(
            erofs_time(-2i64 as u64, 500_000_000),
            UNIX_EPOCH - Duration::from_millis(1500)
        );
        assert_eq!(
            erofs_time(i64::MIN as u64, 0),
            UNIX_EPOCH - Duration::from_secs(i64::MIN.unsigned_abs())
        );
    }

    #[test]
    fn no_xattr_is_derived_from_root_marker() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("child"), b"").unwrap();
        let mut writer = BlobWriter::plain(
            fs::File::create(directory.path().join("data")).unwrap(),
            EROFS_BLOCK_SIZE,
        );
        let mut inodes =
            build_tree(&source, &mut writer, EROFS_BLOCK_SIZE, &HashSet::new()).unwrap();
        writer.finish().unwrap();
        resolve_chunk_addrs(&mut inodes, &writer).unwrap();
        let bootstrap = directory.path().join("bootstrap");

        for (name_index, suffix, value, expected) in [
            (
                EROFS_XATTR_INDEX_TRUSTED,
                NYDUS_XATTR_SUFFIX_NO_XATTR,
                b"1".as_slice(),
                true,
            ),
            (
                EROFS_XATTR_INDEX_TRUSTED,
                NYDUS_XATTR_SUFFIX_NO_XATTR,
                b"0".as_slice(),
                false,
            ),
            (
                EROFS_XATTR_INDEX_TRUSTED,
                NYDUS_XATTR_SUFFIX_NO_XATTR,
                b"".as_slice(),
                false,
            ),
            (
                EROFS_XATTR_INDEX_USER,
                NYDUS_XATTR_SUFFIX_NO_XATTR,
                b"1".as_slice(),
                false,
            ),
            (
                EROFS_XATTR_INDEX_TRUSTED,
                b"nydus.other".as_slice(),
                b"1".as_slice(),
                false,
            ),
        ] {
            inodes[0].xattrs = vec![XattrEntry {
                name_index,
                suffix: suffix.to_vec(),
                value: value.to_vec(),
            }];
            inodes[1].xattrs = vec![XattrEntry {
                name_index: EROFS_XATTR_INDEX_TRUSTED,
                suffix: NYDUS_XATTR_SUFFIX_NO_XATTR.to_vec(),
                value: b"1".to_vec(),
            }];
            let bytes = render_bootstrap(&mut inodes, 0, &[], &[0; 16]).unwrap();
            fs::write(&bootstrap, bytes).unwrap();
            let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
            let filesystem = ErofsFs::new(Arc::new(reader)).unwrap();
            assert_eq!(filesystem.no_xattr, expected);
        }
        assert!(should_hide_xattr(FUSE_ROOT_ID, b"trusted.nydus.no_xattr"));
        assert!(!should_hide_xattr(
            FUSE_ROOT_ID + 1,
            b"trusted.nydus.no_xattr"
        ));
    }

    #[test]
    fn directory_pagination_preserves_entries_and_cookies() {
        for (child_count, layout) in [
            (0, EROFS_INODE_FLAT_INLINE),
            (105, EROFS_INODE_FLAT_PLAIN),
            (120, EROFS_INODE_FLAT_INLINE),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let source = directory.path().join("source");
            fs::create_dir(&source).unwrap();
            let mut names = vec![b".".to_vec(), b"..".to_vec()];
            for index in 0..child_count {
                let name = format!("{index:04}-{}", "n".repeat(60));
                fs::write(source.join(&name), b"").unwrap();
                names.push(name.into_bytes());
            }
            let mut writer = BlobWriter::plain(
                fs::File::create(directory.path().join("data")).unwrap(),
                EROFS_BLOCK_SIZE,
            );
            let mut inodes =
                build_tree(&source, &mut writer, EROFS_BLOCK_SIZE, &HashSet::new()).unwrap();
            writer.finish().unwrap();
            resolve_chunk_addrs(&mut inodes, &writer).unwrap();
            let bootstrap = directory.path().join("bootstrap");
            fs::write(
                &bootstrap,
                render_bootstrap(&mut inodes, 0, &[], &[0; 16]).unwrap(),
            )
            .unwrap();
            let filesystem = ErofsFs::new(Arc::new(
                ErofsReader::open_metadata_only(&bootstrap).unwrap(),
            ))
            .unwrap();
            let nid = filesystem.reader.superblock().root_nid();
            let inode = filesystem.reader.inode(nid).unwrap();
            assert_eq!(inode.data_layout(), layout);
            if child_count > 0 {
                assert!(inode.size() > EROFS_BLOCK_SIZE as u64);
            }
            let expected: Vec<_> = filesystem
                .reader
                .read_dir(nid, &inode)
                .unwrap()
                .into_iter()
                .map(|entry| (entry.nid, entry.file_type, entry.name))
                .collect();
            assert_eq!(
                expected.iter().map(|entry| &entry.2).collect::<Vec<_>>(),
                names.iter().collect::<Vec<_>>()
            );
            assert_eq!(expected[0], (nid, EROFS_FT_DIR, b".".to_vec()));
            assert_eq!(expected[1], (nid, EROFS_FT_DIR, b"..".to_vec()));

            let ino = INodeNo(FUSE_ROOT_ID);
            let handle = filesystem.create_dir_handle(ino.0).unwrap();
            for fh in [FileHandle(0), FileHandle(handle)] {
                for capacity in [1, 2, 7, 53, 54, 55, 200] {
                    let mut offset = 0;
                    let mut seen = Vec::new();
                    let mut cookies = Vec::new();
                    loop {
                        let mut accepted = 0;
                        let mut calls = 0;
                        filesystem
                            .for_each_dir_entry(ino, fh, offset, |nid, ft, name, next| {
                                calls += 1;
                                if accepted == capacity {
                                    return Ok(false);
                                }
                                // Exercise the same inode/attribute lookup as readdirplus.
                                let child = filesystem.reader.inode(nid)?;
                                let attr = filesystem.make_attr(nid, &child);
                                assert_eq!(attr.kind, erofs_ft_to_kind(ft));
                                assert!(next > offset);
                                offset = next;
                                cookies.push(next);
                                seen.push((nid, ft, name.to_vec()));
                                accepted += 1;
                                Ok(true)
                            })
                            .unwrap();
                        assert!(calls <= capacity + 1);
                        assert!(seen.len() <= expected.len());
                        if accepted == 0 {
                            break;
                        }
                    }
                    assert_eq!(
                        seen, expected,
                        "children={child_count}, fh={}, capacity={capacity}",
                        fh.0
                    );
                    if fh.0 == 0 {
                        assert_eq!(cookies[0], EROFS_DIRENT_SIZE as u64);
                        assert_eq!(offset, inode.size());
                        if child_count > 0 {
                            // The first block holds dot, dotdot and 52 long names.
                            assert_eq!(cookies[53], EROFS_BLOCK_SIZE as u64);
                            assert_eq!(
                                cookies[54],
                                (EROFS_BLOCK_SIZE as usize + EROFS_DIRENT_SIZE) as u64
                            );
                        }
                    } else {
                        assert_eq!(cookies, (1..=expected.len() as u64).collect::<Vec<_>>());
                    }
                    // A saved cookie must also work after later pages have been read.
                    for (index, cookie) in cookies.iter().copied().enumerate() {
                        let mut next_entry = None;
                        filesystem
                            .for_each_dir_entry(ino, fh, cookie, |nid, ft, name, _| {
                                next_entry = Some((nid, ft, name.to_vec()));
                                Ok(false)
                            })
                            .unwrap();
                        assert_eq!(next_entry.as_ref(), expected.get(index + 1));
                    }
                }

                let mut calls = 0;
                filesystem
                    .for_each_dir_entry(ino, fh, 0, |_, _, name, _| {
                        calls += 1;
                        assert_eq!(name, b".");
                        Ok(false)
                    })
                    .unwrap();
                assert_eq!(calls, 1);
                let err = filesystem
                    .for_each_dir_entry(ino, fh, 0, |_, _, _, _| {
                        Err(io::Error::from_raw_os_error(libc::EIO))
                    })
                    .unwrap_err();
                assert_eq!(err.raw_os_error(), Some(libc::EIO));
                filesystem
                    .for_each_dir_entry(ino, fh, u64::MAX, |_, _, _, _| {
                        panic!("offset past EOF must not yield entries")
                    })
                    .unwrap();
            }
            let err = filesystem
                .for_each_dir_entry(ino, FileHandle(u64::MAX), 0, |_, _, _, _| {
                    panic!("invalid handle must not yield entries")
                })
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EBADF));
        }
    }
}

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyXattr, Request,
};

use crate::metadata::*;

use super::{CachedDirEntry, ErofsReader};

const FUSE_ROOT_ID: u64 = 1;
const EROFS_FUSE_TIMEOUT: Duration = Duration::from_secs(86400 * 365 * 10);

pub struct ErofsFs {
    reader: Arc<ErofsReader>,
    dir_handles: Mutex<HashMap<u64, Arc<DirHandle>>>,
    next_dir_handle: AtomicU64,
}

struct DirHandle {
    entries: Vec<CachedDirEntry>,
}

impl ErofsFs {
    pub fn new(reader: Arc<ErofsReader>) -> Self {
        Self {
            reader,
            dir_handles: Mutex::new(HashMap::new()),
            next_dir_handle: AtomicU64::new(1),
        }
    }

    fn to_nid(&self, ino: u64) -> u64 {
        if ino == FUSE_ROOT_ID {
            self.reader.sb().root_nid()
        } else {
            ino - FUSE_ROOT_ID
        }
    }

    fn to_ino(&self, nid: u64) -> u64 {
        if nid == self.reader.sb().root_nid() {
            FUSE_ROOT_ID
        } else {
            nid + FUSE_ROOT_ID
        }
    }

    fn make_attr(&self, nid: u64, inode: &ErofsInode<'_>) -> FileAttr {
        let ino = self.to_ino(nid);
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

        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm: (mode & 0o7777) as u16,
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
        let nid = self.to_nid(inode);
        let vi = self.reader.inode(nid)?;
        self.reader
            .for_each_dir_entry(nid, &vi, |entry_nid, file_type, name| {
                cb(entry_nid, file_type, name)
            })
    }

    fn create_dir_handle(&self, inode: u64) -> io::Result<u64> {
        let nid = self.to_nid(inode);
        let vi = self.reader.inode(nid)?;
        let entries = self.reader.read_dir_cached(nid, &vi)?;
        let handle = self.next_dir_handle.fetch_add(1, Ordering::Relaxed);
        let dir_handle = Arc::new(DirHandle { entries });
        self.dir_handles.lock().unwrap().insert(handle, dir_handle);
        Ok(handle)
    }

    fn get_dir_handle(&self, handle: u64) -> io::Result<Arc<DirHandle>> {
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
    ino == FUSE_ROOT_ID && is_lepton_xattr(name)
}

impl Filesystem for ErofsFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let target = name.as_bytes();
        let mut found = None;
        let res = self.iterate_dir(parent.0, |entry_nid, _file_type, entry_name| {
            if entry_name == target {
                found = Some(entry_nid);
                return Ok(false);
            }
            Ok(true)
        });
        if let Err(e) = res {
            reply.error(io_errno(&e));
            return;
        }

        if let Some(child_nid) = found {
            match self.reader.inode(child_nid) {
                Ok(child_inode) => {
                    let attr = self.make_attr(child_nid, &child_inode);
                    reply.entry(&EROFS_FUSE_TIMEOUT, &attr, Generation(0));
                }
                Err(e) => reply.error(io_errno(&e)),
            }
            return;
        }

        reply.error(Errno::ENOENT);
    }

    fn forget(&self, _req: &Request, _ino: INodeNo, _nlookup: u64) {}

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let nid = self.to_nid(ino.0);
        match self.reader.inode(nid) {
            Ok(vi) => {
                let attr = self.make_attr(nid, &vi);
                reply.attr(&EROFS_FUSE_TIMEOUT, &attr);
            }
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if flags.0 & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            reply.error(Errno::EROFS);
            return;
        }

        let nid = self.to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        if (vi.mode() as u32 & libc::S_IFMT) != libc::S_IFREG {
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
        let nid = self.to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
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
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let nid = self.to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        match self.reader.read_symlink(nid, &vi) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let nid = self.to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        if (vi.mode() as u32 & libc::S_IFMT) != libc::S_IFDIR {
            reply.error(Errno::ENOTDIR);
            return;
        }

        match self.create_dir_handle(ino.0) {
            Ok(handle) => reply.opened(
                FileHandle(handle),
                FopenFlags::FOPEN_KEEP_CACHE | FopenFlags::FOPEN_CACHE_DIR,
            ),
            Err(e) => reply.error(io_errno(&e)),
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
        let dir_handle = match self.get_dir_handle(fh.0) {
            Ok(h) => h,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (idx, entry) in dir_handle.entries.iter().enumerate().skip(start) {
            let ino = self.to_ino(entry.nid);
            let kind = erofs_ft_to_kind(entry.file_type);
            let name = OsStr::from_bytes(&entry.name);
            if reply.add(INodeNo(ino), (idx as u64) + 1, kind, name) {
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
        let dir_handle = match self.get_dir_handle(fh.0) {
            Ok(h) => h,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (idx, entry) in dir_handle.entries.iter().enumerate().skip(start) {
            let child_inode = match self.reader.inode(entry.nid) {
                Ok(vi) => vi,
                Err(e) => {
                    reply.error(io_errno(&e));
                    return;
                }
            };
            let attr = self.make_attr(entry.nid, &child_inode);
            let ino = self.to_ino(entry.nid);
            let name = OsStr::from_bytes(&entry.name);
            if reply.add(
                INodeNo(ino),
                (idx as u64) + 1,
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
        let sb = self.reader.sb();
        let block_size = 1u64 << sb.blkszbits;
        reply.statfs(
            sb.blocks(),
            0,
            0,
            sb.inos(),
            0,
            block_size as u32,
            255,
            block_size as u32,
        );
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let nid = self.to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        let name_bytes = name.as_bytes();
        if should_hide_xattr(ino.0, name_bytes) {
            reply.error(Errno::ENODATA);
            return;
        }

        let xattrs = match self.reader.read_xattrs(nid, &vi) {
            Ok(x) => x,
            Err(e) => {
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
                    reply.error(Errno::ERANGE);
                    return;
                }
                reply.data(xvalue);
                return;
            }
        }

        reply.error(Errno::ENODATA);
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let nid = self.to_nid(ino.0);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        let xattrs = match self.reader.read_xattrs(nid, &vi) {
            Ok(x) => x,
            Err(e) => {
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
            reply.error(Errno::ERANGE);
            return;
        }
        reply.data(&names_buf);
    }
}

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyXattr, Request,
};

use crate::metadata::*;

use super::{CachedDirEntry, ErofsReader};

const FUSE_ROOT_ID: u64 = 1;
const EROFS_FUSE_TIMEOUT: Duration = Duration::from_secs(86400 * 365 * 10);

// FUSE open flags (FOPEN_*). fuser 0.16 does not re-export these constants;
// values match include/uapi/linux/fuse.h.
const FOPEN_KEEP_CACHE: u32 = 1 << 1;
const FOPEN_CACHE_DIR: u32 = 1 << 3;

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
        let mtime_nsec = inode.mtime_nsec();
        let size = inode.size();
        let blocks = ((size + block_size - 1) / block_size * block_size / 512) as u64;
        let time = UNIX_EPOCH + Duration::new(mtime_secs, mtime_nsec);

        let mode = inode.mode() as u32;
        let kind = mode_to_kind(mode);
        let rdev = if (mode & libc::S_IFMT) == libc::S_IFCHR
            || (mode & libc::S_IFMT) == libc::S_IFBLK
        {
            inode.rdev() as u32
        } else {
            0
        };

        FileAttr {
            ino,
            size,
            blocks,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm: (mode & 0o7777) as u16,
            nlink: inode.nlink() as u32,
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
        self.dir_handles
            .lock()
            .unwrap()
            .insert(handle, dir_handle);
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

fn io_errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
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

impl Filesystem for ErofsFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let target = name.as_bytes();
        let mut found = None;
        let res = self.iterate_dir(parent, |entry_nid, _file_type, entry_name| {
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
                    reply.entry(&EROFS_FUSE_TIMEOUT, &attr, 0);
                }
                Err(e) => reply.error(io_errno(&e)),
            }
            return;
        }

        reply.error(libc::ENOENT);
    }

    fn forget(&mut self, _req: &Request<'_>, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let nid = self.to_nid(ino);
        match self.reader.inode(nid) {
            Ok(vi) => {
                let attr = self.make_attr(nid, &vi);
                reply.attr(&EROFS_FUSE_TIMEOUT, &attr);
            }
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if flags & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            reply.error(libc::EROFS);
            return;
        }

        let nid = self.to_nid(ino);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        if (vi.mode() as u32 & libc::S_IFMT) != libc::S_IFREG {
            reply.error(libc::EISDIR);
            return;
        }

        // FOPEN_KEEP_CACHE
        reply.opened(nid, FOPEN_KEEP_CACHE);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let nid = self.to_nid(ino);
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
            .write_file_data_to(nid, &vi, offset as u64, size, &mut buf)
        {
            Ok(_) => reply.data(&buf),
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let nid = self.to_nid(ino);
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

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let nid = self.to_nid(ino);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        if (vi.mode() as u32 & libc::S_IFMT) != libc::S_IFDIR {
            reply.error(libc::ENOTDIR);
            return;
        }

        match self.create_dir_handle(ino) {
            // FOPEN_KEEP_CACHE | FOPEN_CACHE_DIR
            Ok(handle) => reply.opened(handle, FOPEN_KEEP_CACHE | FOPEN_CACHE_DIR),
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let dir_handle = match self.get_dir_handle(fh) {
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
            if reply.add(ino, (idx as i64) + 1, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let dir_handle = match self.get_dir_handle(fh) {
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
                ino,
                (idx as i64) + 1,
                name,
                &EROFS_FUSE_TIMEOUT,
                &attr,
                0,
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.dir_handles.lock().unwrap().remove(&fh);
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
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

    fn access(&mut self, _req: &Request<'_>, _ino: u64, _mask: i32, reply: ReplyEmpty) {
        reply.ok();
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let nid = self.to_nid(ino);
        let vi = match self.reader.inode(nid) {
            Ok(vi) => vi,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        let name_bytes = name.as_bytes();

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
                    reply.error(libc::ERANGE);
                    return;
                }
                reply.data(xvalue);
                return;
            }
        }

        reply.error(libc::ENODATA);
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        let nid = self.to_nid(ino);
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
            names_buf.extend_from_slice(xname);
            names_buf.push(0);
        }

        if size == 0 {
            reply.size(names_buf.len() as u32);
            return;
        }
        if (size as usize) < names_buf.len() {
            reply.error(libc::ERANGE);
            return;
        }
        reply.data(&names_buf);
    }
}

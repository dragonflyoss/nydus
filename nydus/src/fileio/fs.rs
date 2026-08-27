// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Single-file FUSE export of the flattened image.
//!
//! The mount holds exactly one regular file whose contents are the flattened
//! device view built by [`FlatImage`]: the bootstrap at the head, then each
//! blob at its mapped offset. The kernel EROFS driver mounts that file
//! directly (`CONFIG_EROFS_FS_BACKED_BY_FILE`), so every filesystem
//! operation — lookup, readdir, stat, xattr — is resolved in-kernel against
//! metadata bytes that live in this file's page cache. Only cold byte ranges
//! come back here as FUSE reads.
//!
//! Directory contents are fixed at mount time, so there is no inode table:
//! the root is [`ROOT_INO`] and the image file is [`IMAGE_INO`].

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    KernelConfig, LockOwner, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyXattr, Request,
};
use nydus_core::flat::{FlatImage, BLOCK_SIZE};
use nydus_format::erofs::EROFS_BLOCK_SIZE;

/// Inode of the root directory, fixed by the FUSE protocol.
pub const ROOT_INO: u64 = 1;
/// Inode of the exported flattened image file.
pub const IMAGE_INO: u64 = 2;
/// Name of the exported flattened image file inside the mount.
pub const IMAGE_NAME: &str = "image";

/// The export is immutable for the mount's lifetime, so the kernel can cache
/// attributes and dentries indefinitely.
const ENTRY_TIMEOUT: Duration = Duration::from_secs(86400 * 365 * 10);

/// Single-file view of the flattened image.
pub struct FlatImageFs {
    image: Arc<FlatImage>,
}

impl FlatImageFs {
    /// Export `image`'s flattened view as one file named [`IMAGE_NAME`].
    pub fn new(image: Arc<FlatImage>) -> Self {
        Self { image }
    }

    /// Size in bytes of the exported image file.
    pub fn image_size(&self) -> u64 {
        self.image.size()
    }

    fn attr(&self, ino: u64) -> Option<FileAttr> {
        let (kind, perm, size, nlink) = match ino {
            ROOT_INO => (FileType::Directory, 0o555, 0, 2),
            IMAGE_INO => (FileType::RegularFile, 0o444, self.image_size(), 1),
            _ => return None,
        };
        Some(FileAttr {
            ino: INodeNo(ino),
            size,
            // Reported in 512 B units like stat(2), rounded up.
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: EROFS_BLOCK_SIZE,
            flags: 0,
        })
    }

    /// Read `[offset, offset + size)` of the flattened view into a fresh
    /// buffer, clamped at EOF.
    ///
    /// [`FlatImage::read_at`] only accepts block-aligned windows, so an
    /// unaligned request is widened to block boundaries and the interesting
    /// slice is copied out. The kernel issues page-aligned reads in practice;
    /// this keeps a hand-rolled `read(2)` on the export correct as well.
    pub fn read_image(&self, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let image_size = self.image_size();
        if offset >= image_size {
            return Ok(Vec::new());
        }
        let want = (size as u64).min(image_size - offset);
        if want == 0 {
            return Ok(Vec::new());
        }

        let start = offset - offset % BLOCK_SIZE;
        let end = (offset + want)
            .div_ceil(BLOCK_SIZE)
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(|| io::Error::other("flat read range overflow"))?
            .min(image_size);
        let mut aligned = vec![0u8; (end - start) as usize];
        self.image
            .read_at(start, &mut aligned)
            .map_err(|err| io::Error::from_raw_os_error(error_to_errno(&err)))?;

        let from = (offset - start) as usize;
        aligned.drain(..from);
        aligned.truncate(want as usize);
        Ok(aligned)
    }
}

/// Map a core error onto the errno reported to the kernel. Anything that is
/// not a plain I/O failure is still an I/O failure from the mount's point of
/// view, so EROFS surfaces it as a read error rather than something a caller
/// might retry differently.
fn error_to_errno(err: &nydus_error::Error) -> i32 {
    match err {
        nydus_error::Error::Io(err) => err.raw_os_error().unwrap_or(libc::EIO),
        _ => libc::EIO,
    }
}

impl Filesystem for FlatImageFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // EROFS reads metadata one folio at a time through `read_folio`, so
        // the depth of the kernel's async pipeline is what keeps cold data
        // reads from serializing behind each other.
        let _ = config.set_max_background(64);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent.0 != ROOT_INO || name.as_bytes() != IMAGE_NAME.as_bytes() {
            reply.error(Errno::ENOENT);
            return;
        }
        match self.attr(IMAGE_INO) {
            Some(attr) => reply.entry(&ENTRY_TIMEOUT, &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr(ino.0) {
            Some(attr) => reply.attr(&ENTRY_TIMEOUT, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino.0 != IMAGE_INO {
            reply.error(Errno::ENOENT);
            return;
        }
        // KEEP_CACHE is what makes this mode worthwhile: the image is
        // immutable, so metadata folios EROFS already faulted in stay valid
        // for the lifetime of the mount instead of being dropped on open.
        reply.opened(FileHandle(0), FopenFlags::FOPEN_KEEP_CACHE);
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
        if ino.0 != IMAGE_INO {
            reply.error(Errno::ENOENT);
            return;
        }
        match self.read_image(offset, size) {
            Ok(data) => reply.data(&data),
            Err(err) => reply.error(Errno::from_i32(err.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino.0 != ROOT_INO {
            reply.error(Errno::ENOTDIR);
            return;
        }
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino.0 != ROOT_INO {
            reply.error(Errno::ENOTDIR);
            return;
        }
        let entries = [
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (IMAGE_INO, FileType::RegularFile, IMAGE_NAME),
        ];
        for (index, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            // The offset handed back is where a resumed readdir continues, so
            // it must point past the entry just added.
            if reply.add(
                INodeNo(*entry_ino),
                index as u64 + 1,
                *kind,
                OsStr::new(*name),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let blocks = self.image_size().div_ceil(BLOCK_SIZE);
        reply.statfs(
            blocks,
            0,
            0,
            2,
            0,
            EROFS_BLOCK_SIZE,
            IMAGE_NAME.len() as u32,
            EROFS_BLOCK_SIZE,
        );
    }

    /// Neither the root nor the image file carries extended attributes: the
    /// ones a container cares about live inside the image and are resolved by
    /// the EROFS driver mounted on top, never through this export.
    ///
    /// Answering with an empty list rather than letting the default `ENOSYS`
    /// through keeps tooling that walks the export (`ls -l`, `cp -a`, `tar`)
    /// from reporting an error on a mount that simply has no xattrs.
    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        if self.attr(ino.0).is_none() {
            reply.error(Errno::from_i32(libc::ENOENT));
            return;
        }
        // A zero `size` is the caller probing for the buffer it must allocate.
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    /// Counterpart to [`Self::listxattr`]: every name misses. `ENODATA` says
    /// "this file has no such attribute", which is what callers probing for
    /// `security.*` or `system.posix_acl_access` expect, whereas the default
    /// `ENOSYS` would claim the whole mount lacks xattr support and can make
    /// the kernel stop asking on other inodes too.
    fn getxattr(&self, _req: &Request, ino: INodeNo, _name: &OsStr, _size: u32, reply: ReplyXattr) {
        let errno = if self.attr(ino.0).is_none() {
            libc::ENOENT
        } else {
            libc::ENODATA
        };
        reply.error(Errno::from_i32(errno));
    }
}

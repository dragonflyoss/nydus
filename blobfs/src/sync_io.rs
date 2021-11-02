// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Fuse passthrough file system, mirroring an existing FS hierarchy.

#[cfg(feature = "virtiofs")]
use std::cmp::min;
#[cfg(feature = "virtiofs")]
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::{self, size_of, ManuallyDrop, MaybeUninit};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
#[cfg(feature = "virtiofs")]
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use fuse_backend_rs::{api::CreateIn, bytes_to_cstr};
#[cfg(feature = "virtiofs")]
use storage::device::BlobPrefetchRequest;

macro_rules! scoped_cred {
    ($name:ident, $ty:ty, $syscall_nr:expr) => {
        #[derive(Debug)]
        struct $name;

        impl $name {
            // Changes the effective uid/gid of the current thread to `val`.  Changes
            // the thread's credentials back to root when the returned struct is dropped.
            fn new(val: $ty) -> io::Result<Option<$name>> {
                if val == 0 {
                    // Nothing to do since we are already uid 0.
                    return Ok(None);
                }

                // We want credential changes to be per-thread because otherwise
                // we might interfere with operations being carried out on other
                // threads with different uids/gids.  However, posix requires that
                // all threads in a process share the same credentials.  To do this
                // libc uses signals to ensure that when one thread changes its
                // credentials the other threads do the same thing.
                //
                // So instead we invoke the syscall directly in order to get around
                // this limitation.  Another option is to use the setfsuid and
                // setfsgid systems calls.   However since those calls have no way to
                // return an error, it's preferable to do this instead.

                // This call is safe because it doesn't modify any memory and we
                // check the return value.
                let res = unsafe { libc::syscall($syscall_nr, -1, val, -1) };
                if res == 0 {
                    Ok(Some($name))
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                let res = unsafe { libc::syscall($syscall_nr, -1, 0, -1) };
                if res < 0 {
                    error!(
                        "fuse: failed to change credentials back to root: {}",
                        io::Error::last_os_error(),
                    );
                }
            }
        }
    };
}
scoped_cred!(ScopedUid, libc::uid_t, libc::SYS_setresuid);
scoped_cred!(ScopedGid, libc::gid_t, libc::SYS_setresgid);

fn set_creds(
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<(Option<ScopedUid>, Option<ScopedGid>)> {
    // We have to change the gid before we change the uid because if we change the uid first then we
    // lose the capability to change the gid.  However changing back can happen in any order.
    ScopedGid::new(gid).and_then(|gid| Ok((ScopedUid::new(uid)?, gid)))
}

impl BlobFs {
    #[cfg(feature = "virtiofs")]
    fn get_blob_id_and_size(&self, inode: Inode) -> io::Result<(String, i64)> {
        // locate blob file that the inode refers to
        let data = self.inode_map.get(inode)?;
        let pathname =
            CString::new(format!("self/fd/{}", data.get_raw_fd())).map_err(|e| einval!(e))?;

        let blob_id_full_path = self.readlinkat_proc_file(&pathname)?;
        let parent = blob_id_full_path
            .parent()
            .ok_or_else(|| einval!("blobfs: failed to find parent"))?;

        trace!(
            "parent {:?} ------  {:?}",
            parent,
            Path::new(self.bootstrap_args.blob_cache_dir.as_str())
        );
        if parent
            != Path::new(self.cfg.root_dir.as_str())
                .join(self.bootstrap_args.blob_cache_dir.as_str())
        {
            error!("blobfs: blob path is not valid.");
            return Err(einval!("blobfs: blob path is not valid"));
        }
        let blob_id = blob_id_full_path
            .file_name()
            .ok_or_else(|| einval!("blobfs: failed to find blob file"))?;

        trace!("load_chunks_on_demand: blob_id {:?}", blob_id);

        let st = Self::stat(&data.file).map_err(|e| {
            error!("get_blob_id_and_size: stat failed {:?}", e);
            e
        })?;

        Ok((blob_id.to_os_string().into_string().unwrap(), st.st_size))
    }

    #[cfg(feature = "virtiofs")]
    fn load_chunks_on_demand(&self, inode: Inode, foffset: u64) -> io::Result<()> {
        // prepare BlobPrefetchRequest and call device.prefetch().
        // Make sure prefetch doesn't use delay_persist as we need the
        // data immediately.
        let (blob_id, size) = self.get_blob_id_and_size(inode)?;
        let offset: u32 = foffset.try_into().map_err(|_| {
            einval!(format!(
                "blobfs: load_chunks_on_demand: foffset {} is larger than u32::MAX",
                foffset
            ))
        })?;
        let len = (size - offset as i64).try_into().map_err(|_| {
            einval!(format!(
                "blobfs: load_chunks_on_demand: len {} is larger than u32::MAX",
                (size - offset as i64)
            ))
        })?;
        let req = BlobPrefetchRequest {
            blob_id,
            offset,
            len: min(len, 0x0020_0000_u32), // 2M range
        };

        self.bootstrap_args
            .rafs
            .fetch_range_synchronous(&[req])
            .unwrap_or_else(|e| warn!("load chunks: error, {:?}", e));

        Ok(())
    }

    // #[cfg(feature = "virtiofs")]
    // fn load_chunks_on_demand_v1(&self, inode: Inode, foffset: u64) -> io::Result<()> {
    //     // locate blob file that the inode refers to
    //     let data = self.inode_map.get(inode)?;
    //     let pathname =
    //         CString::new(format!("self/fd/{}", data.get_raw_fd())).map_err(|e| einval!(e))?;

    //     let blob_id_full_path = self.readlinkat_proc_file(&pathname)?;
    //     let parent = blob_id_full_path
    //         .parent()
    //         .ok_or_else(|| einval!("blobfs: failed to find parent"))?;

    //     trace!(
    //         "parent {:?} ------  {:?}",
    //         parent,
    //         Path::new(self.cfg.root_dir.as_str()).join(self.bootstrap_args.blob_cache_dir.as_str())
    //     );
    //     if parent
    //         != Path::new(self.cfg.root_dir.as_str())
    //             .join(self.bootstrap_args.blob_cache_dir.as_str())
    //     {
    //         return Ok(());
    //     }
    //     let blob_id = blob_id_full_path
    //         .file_name()
    //         .ok_or_else(|| einval!("blobfs: failed to find blob file"))?;

    //     trace!("load_chunks_on_demand: blob_id {:?}", blob_id);

    //     // make sure chunks are available.
    //     let blob_offset_map_ptr = match self.blob_offset_map.get(&blob_id.to_os_string()) {
    //         Ok(arg) => arg.base,
    //         Err(_) => {
    //             // blob_offset_map and bootstrap is in the same directory.
    //             let bootstrap_path = Path::new(self.cfg.root_dir.as_str())
    //                 .join(self.bootstrap_args.bootstrap.as_str());
    //             let blob_offset_map_path = bootstrap_path
    //                 .with_file_name(blob_id)
    //                 .with_extension("blob_offset_map");

    //             trace!("blob_offset_map {:?}", blob_offset_map_path);
    //             let map_f = File::open(&blob_offset_map_path).map_err(|e| einval!(e))?;
    //             let size = map_f.metadata()?.len() as usize;
    //             trace!(
    //                 "blobfs: blob offset map {:?} size {}",
    //                 blob_offset_map_path,
    //                 size
    //             );
    //             if size == 0 {
    //                 return Err(einval!("invalid blob offset map file size"));
    //             }

    //             let base = unsafe {
    //                 libc::mmap(
    //                     std::ptr::null_mut(),
    //                     size,
    //                     libc::PROT_READ,
    //                     libc::MAP_NORESERVE | libc::MAP_SHARED,
    //                     map_f.as_raw_fd(),
    //                     0,
    //                 )
    //             } as *const u8;
    //             if base as *mut core::ffi::c_void == libc::MAP_FAILED {
    //                 return Err(last_error!("failed to mmap blob offset map"));
    //             }
    //             if base.is_null() {
    //                 return Err(ebadf!("failed to mmap blob offset map"));
    //             }

    //             // save the ptr for later use.
    //             self.blob_offset_map.insert(
    //                 blob_id.to_os_string(),
    //                 Arc::new(BlobOffsetMapArg { base, size }),
    //             );
    //             base
    //         }
    //     };

    //     let index = foffset >> 21;
    //     let mut ptr = blob_offset_map_ptr.wrapping_add((index * 16) as usize);
    //     let mut chunk_vec_off = unsafe { *(ptr as *const u64) };

    //     ptr = ptr.wrapping_add(std::mem::size_of::<u64>());
    //     let mut chunk_vec_len = unsafe { *(ptr as *const u64) };

    //     loop {
    //         ptr = blob_offset_map_ptr.wrapping_add(chunk_vec_off as usize);
    //         // let chunk = unsafe { *(ptr as *const OndiskChunkInfo) };
    //         let chunk_info_pos = unsafe { *(ptr as *const u64) };
    //         // ptr = self
    //         //     .bootstrap_args
    //         //     .base
    //         //     .wrapping_add(chunk_info_pos as usize);
    //         // let chunk = unsafe { *(ptr as *const OndiskChunkInfo) };
    //         let chunk = self
    //             .bootstrap_args
    //             .rafs
    //             .sb
    //             .inodes
    //             .get_chunk_info(chunk_info_pos as usize)
    //             .map_err(|e| {
    //                 error!(
    //                     "load_chunks_on_demand: failed to get chunk info at {}",
    //                     chunk_info_pos
    //                 );
    //                 e
    //             })?;

    //         let offset = 0;
    //         let end = RAFS_DEFAULT_BLOCK_SIZE;
    //         let mut desc = RafsBioDesc::new();
    //         let blksize = RAFS_DEFAULT_BLOCK_SIZE;

    //         let blob = self
    //             .bootstrap_args
    //             .rafs
    //             .sb
    //             .inodes
    //             .get_blob_table()
    //             .get(chunk.blob_index())
    //             .map_err(|e| {
    //                 error!(
    //                     "load_chunks_on_demand: failed to get blob in blob table at index {}",
    //                     chunk.blob_index()
    //                 );
    //                 e
    //             })?;

    //         let ret =
    //             add_chunk_to_bio_desc(offset, end, chunk.clone(), &mut desc, blksize as u32, blob);
    //         trace!("add chunk block id: {}", chunk.block_id());
    //         if ret {
    //             let mut dummy_writer = DummyZcWriter {};
    //             let ret = self
    //                 .bootstrap_args
    //                 .rafs
    //                 .device
    //                 .read_to(&mut dummy_writer, desc)?;
    //             trace!("read device: {}", ret);
    //         } else {
    //             return Err(eio!());
    //         }

    //         chunk_vec_off += std::mem::size_of::<u64>() as u64;
    //         chunk_vec_len -= 1;
    //         if chunk_vec_len == 0 {
    //             break;
    //         }
    //     }
    //     Ok(())
    // }

    #[cfg(feature = "virtiofs")]
    fn readlinkat_proc_file(&self, pathname: &CStr) -> io::Result<PathBuf> {
        Self::readlinkat(self.proc.as_raw_fd(), pathname)
    }

    fn open_proc_file(&self, pathname: &CStr, flags: i32) -> io::Result<File> {
        Self::open_file(self.proc.as_raw_fd(), pathname, flags, 0)
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        let data = self.inode_map.get(inode)?;
        let pathname = CString::new(format!("self/fd/{}", data.get_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        // We don't really check `flags` because if the kernel can't handle poorly specified flags
        // then we have much bigger problems. Also, clear the `O_NOFOLLOW` flag if it is set since
        // we need to follow the `/proc/self/fd` symlink to get the file.
        self.open_proc_file(&pathname, (flags | libc::O_CLOEXEC) & (!libc::O_NOFOLLOW))
    }

    fn do_readdir(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> io::Result<usize>,
    ) -> io::Result<()> {
        if size == 0 {
            return Ok(());
        }

        let mut buf = Vec::<u8>::with_capacity(size as usize);
        let data = self.get_dirdata(handle, inode, libc::O_RDONLY)?;

        {
            // Since we are going to work with the kernel offset, we have to acquire the file lock
            // for both the `lseek64` and `getdents64` syscalls to ensure that no other thread
            // changes the kernel offset while we are using it.
            let (guard, dir) = data.get_file_mut();

            // Safe because this doesn't modify any memory and we check the return value.
            let res =
                unsafe { libc::lseek64(dir.as_raw_fd(), offset as libc::off64_t, libc::SEEK_SET) };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            // Safe because the kernel guarantees that it will only write to `buf` and we check the
            // return value.
            let res = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    dir.as_raw_fd(),
                    buf.as_mut_ptr() as *mut LinuxDirent64,
                    size as libc::c_int,
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            // Safe because we trust the value returned by kernel.
            unsafe { buf.set_len(res as usize) };

            // Explicitly drop the lock so that it's not held while we fill in the fuse buffer.
            mem::drop(guard);
        }

        let mut rem = &buf[..];
        let orig_rem_len = rem.len();
        while !rem.is_empty() {
            // We only use debug asserts here because these values are coming from the kernel and we
            // trust them implicitly.
            debug_assert!(
                rem.len() >= size_of::<LinuxDirent64>(),
                "fuse: not enough space left in `rem`"
            );

            let (front, back) = rem.split_at(size_of::<LinuxDirent64>());

            let dirent64 = LinuxDirent64::from_slice(front)
                .expect("fuse: unable to get LinuxDirent64 from slice");

            let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
            debug_assert!(
                namelen <= back.len(),
                "fuse: back is smaller than `namelen`"
            );

            let name = &back[..namelen];
            let res = if name.starts_with(CURRENT_DIR_CSTR) || name.starts_with(PARENT_DIR_CSTR) {
                // We don't want to report the "." and ".." entries. However, returning `Ok(0)` will
                // break the loop so return `Ok` with a non-zero value instead.
                Ok(1)
            } else {
                // The Sys_getdents64 in kernel will pad the name with '\0'
                // bytes up to 8-byte alignment, so @name may contain a few null
                // terminators.  This causes an extra lookup from fuse when
                // called by readdirplus, because kernel path walking only takes
                // name without null terminators, the dentry with more than 1
                // null terminators added by readdirplus doesn't satisfy the
                // path walking.
                let name = bytes_to_cstr(name)
                    .map_err(|e| {
                        error!("fuse: do_readdir: {:?}", e);
                        io::Error::from_raw_os_error(libc::EINVAL)
                    })?
                    .to_bytes();

                add_entry(DirEntry {
                    ino: dirent64.d_ino,
                    offset: dirent64.d_off as u64,
                    type_: u32::from(dirent64.d_ty),
                    name,
                })
            };

            debug_assert!(
                rem.len() >= dirent64.d_reclen as usize,
                "fuse: rem is smaller than `d_reclen`"
            );

            match res {
                Ok(0) => break,
                Ok(_) => rem = &rem[dirent64.d_reclen as usize..],
                // If there's an error, we can only signal it if we haven't
                // stored any entries yet - otherwise we'd end up with wrong
                // lookup counts for the entries that are already in the
                // buffer. So we return what we've collected until that point.
                Err(e) if rem.len() == orig_rem_len => return Err(e),
                Err(_) => return Ok(()),
            }
        }

        Ok(())
    }

    fn do_open(&self, inode: Inode, flags: u32) -> io::Result<(Option<Handle>, OpenOptions)> {
        let file = self.open_inode(inode, flags as i32)?;
        let data = HandleData::new(inode, file);
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);

        self.handle_map.insert(handle, data);

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(
                OpenOptions::DIRECT_IO,
                flags & (libc::O_DIRECTORY as u32) == 0,
            ),
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(libc::stat64, Duration)> {
        let data = self.inode_map.get(inode).map_err(|e| {
            error!("fuse: do_getattr ino {} Not find err {:?}", inode, e);
            e
        })?;

        let st = Self::stat(&data.file).map_err(|e| {
            error!(
                "fuse: do_getattr stat failed ino {} fd: {:?} err {:?}",
                inode,
                data.get_raw_fd(),
                e
            );
            e
        })?;

        Ok((st, self.cfg.attr_timeout))
    }

    fn do_unlink(&self, parent: Inode, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        let data = self.inode_map.get(parent)?;
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(data.get_raw_fd(), name.as_ptr(), flags) };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn get_dirdata(
        &self,
        handle: Handle,
        inode: Inode,
        flags: libc::c_int,
    ) -> io::Result<Arc<HandleData>> {
        let no_open = self.no_opendir.load(Ordering::Relaxed);
        if !no_open {
            self.handle_map.get(handle, inode)
        } else {
            let file = self.open_inode(inode, (flags | libc::O_DIRECTORY) as i32)?;
            Ok(Arc::new(HandleData::new(inode, file)))
        }
    }

    fn get_data(
        &self,
        handle: Handle,
        inode: Inode,
        flags: libc::c_int,
    ) -> io::Result<Arc<HandleData>> {
        let no_open = self.no_open.load(Ordering::Relaxed);
        if !no_open {
            self.handle_map.get(handle, inode)
        } else {
            let file = self.open_inode(inode, flags as i32)?;
            Ok(Arc::new(HandleData::new(inode, file)))
        }
    }
}

impl FileSystem for BlobFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        if self.cfg.do_import {
            self.import()?;
        }

        let mut opts = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        // !cfg.do_import means we are under vfs, in which case capable is already
        // negotiated and must be honored.
        if (!self.cfg.do_import || self.cfg.writeback)
            && capable.contains(FsOptions::WRITEBACK_CACHE)
        {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }
        if (!self.cfg.do_import || self.cfg.no_open)
            && capable.contains(FsOptions::ZERO_MESSAGE_OPEN)
        {
            opts |= FsOptions::ZERO_MESSAGE_OPEN;
            // We can't support FUSE_ATOMIC_O_TRUNC with no_open
            opts.remove(FsOptions::ATOMIC_O_TRUNC);
            self.no_open.store(true, Ordering::Relaxed);
        }
        if (!self.cfg.do_import || self.cfg.no_opendir)
            && capable.contains(FsOptions::ZERO_MESSAGE_OPENDIR)
        {
            opts |= FsOptions::ZERO_MESSAGE_OPENDIR;
            self.no_opendir.store(true, Ordering::Relaxed);
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.handle_map.clear();
        self.inode_map.clear();

        if let Err(e) = self.import() {
            error!("fuse: failed to destroy instance, {:?}", e);
        };
    }

    fn statfs(&self, _ctx: &Context, inode: Inode) -> io::Result<libc::statvfs64> {
        let data = self.inode_map.get(inode)?;
        let mut out = MaybeUninit::<libc::statvfs64>::zeroed();

        // Safe because this will only modify `out` and we check the return value.
        match unsafe { libc::fstatvfs64(data.get_raw_fd(), out.as_mut_ptr()) } {
            // Safe because the kernel guarantees that `out` has been initialized.
            0 => Ok(unsafe { out.assume_init() }),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn lookup(&self, _ctx: &Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
    }

    fn forget(&self, _ctx: &Context, inode: Inode, count: u64) {
        let mut inodes = self.inode_map.get_map_mut();

        Self::forget_one(&mut inodes, inode, count)
    }

    fn batch_forget(&self, _ctx: &Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inode_map.get_map_mut();

        for (inode, count) in requests {
            Self::forget_one(&mut inodes, inode, count)
        }
    }

    fn opendir(
        &self,
        _ctx: &Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if self.no_opendir.load(Ordering::Relaxed) {
            info!("fuse: opendir is not supported.");
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        } else {
            self.do_open(inode, flags | (libc::O_DIRECTORY as u32))
        }
    }

    fn releasedir(
        &self,
        _ctx: &Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let data = self.inode_map.get(parent)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::mkdirat(data.get_raw_fd(), name.as_ptr(), mode & !umask) };
        if res == 0 {
            self.do_lookup(parent, name)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn rmdir(&self, _ctx: &Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> io::Result<usize>,
    ) -> io::Result<()> {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn readdirplus(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> io::Result<usize>,
    ) -> io::Result<()> {
        self.do_readdir(inode, handle, size, offset, &mut |dir_entry| {
            // Safe because do_readdir() has ensured dir_entry.name is a
            // valid [u8] generated by CStr::to_bytes().
            let name = unsafe {
                CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
                    &dir_entry.name[0],
                    dir_entry.name.len() + 1,
                ))
            };
            let entry = self.do_lookup(inode, name)?;
            let ino = entry.inode;

            add_entry(dir_entry, entry).map(|r| {
                // true when size is not large enough to hold entry.
                if r == 0 {
                    // Release the refcount acquired by self.do_lookup().
                    let mut inodes = self.inode_map.get_map_mut();
                    Self::forget_one(&mut inodes, ino, 1);
                }
                r
            })
        })
    }

    fn open(
        &self,
        _ctx: &Context,
        inode: Inode,
        flags: u32,
        _fuse_flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if self.no_open.load(Ordering::Relaxed) {
            info!("fuse: open is not supported.");
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        } else {
            self.do_open(inode, flags)
        }
    }

    fn release(
        &self,
        _ctx: &Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if self.no_open.load(Ordering::Relaxed) {
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        } else {
            self.do_release(inode, handle)
        }
    }

    fn create(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &CStr,
        args: CreateIn,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let data = self.inode_map.get(parent)?;

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let file = Self::open_file(
            data.get_raw_fd(),
            name,
            args.flags as i32 | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            args.mode & !(args.umask & 0o777),
        )?;

        let entry = self.do_lookup(parent, name)?;

        let ret_handle = if !self.no_open.load(Ordering::Relaxed) {
            let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
            let data = HandleData::new(entry.inode, file);

            self.handle_map.insert(handle, data);
            Some(handle)
        } else {
            None
        };

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((entry, ret_handle, opts))
    }

    fn unlink(&self, _ctx: &Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, 0)
    }

    #[cfg(feature = "virtiofs")]
    fn setupmapping(
        &self,
        _ctx: &Context,
        inode: Inode,
        _handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        debug!(
            "blobfs: setupmapping ino {:?} foffset {} len {} flags {} moffset {}",
            inode, foffset, len, flags, moffset
        );

        self.load_chunks_on_demand(inode, foffset)?;

        let open_flags = if (flags & virtio_fs::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };

        let file = self.open_inode(inode, open_flags as i32)?;
        (*vu_req).map(foffset, moffset, len, flags, file.as_raw_fd())
    }

    #[cfg(feature = "virtiofs")]
    fn removemapping(
        &self,
        _ctx: &Context,
        _inode: Inode,
        requests: Vec<virtio_fs::RemovemappingOne>,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        (*vu_req).unmap(requests)
    }

    fn read(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        w: &mut dyn ZeroCopyWriter<S = ()>,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.get_data(handle, inode, libc::O_RDONLY)?;

        // Manually implement File::try_clone() by borrowing fd of data.file instead of dup().
        // It's safe because the `data` variable's lifetime spans the whole function,
        // so data.file won't be closed.
        let f = unsafe { File::from_raw_fd(data.get_handle_raw_fd()) };
        let mut f = ManuallyDrop::new(f);

        w.write_from(&mut *f, size as usize, offset)
    }

    fn write(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        r: &mut dyn ZeroCopyReader<S = ()>,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _flags: u32,
        _fuse_flags: u32,
    ) -> io::Result<usize> {
        let data = self.get_data(handle, inode, libc::O_RDWR)?;

        // Manually implement File::try_clone() by borrowing fd of data.file instead of dup().
        // It's safe because the `data` variable's lifetime spans the whole function,
        // so data.file won't be closed.
        let f = unsafe { File::from_raw_fd(data.get_handle_raw_fd()) };
        let mut f = ManuallyDrop::new(f);

        r.read_to(&mut *f, size as usize, offset)
    }

    fn getattr(
        &self,
        _ctx: &Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: &Context,
        inode: Inode,
        attr: libc::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let inode_data = self.inode_map.get(inode)?;

        enum Data {
            Handle(Arc<HandleData>, RawFd),
            ProcPath(CString),
        }

        let data = if self.no_open.load(Ordering::Relaxed) {
            let pathname = CString::new(format!("self/fd/{}", inode_data.get_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Data::ProcPath(pathname)
        } else {
            // If we have a handle then use it otherwise get a new fd from the inode.
            if let Some(handle) = handle {
                let hd = self.handle_map.get(handle, inode)?;
                let fd = hd.get_handle_raw_fd();
                Data::Handle(hd, fd)
            } else {
                let pathname = CString::new(format!("self/fd/{}", inode_data.get_raw_fd()))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Data::ProcPath(pathname)
            }
        };

        if valid.contains(SetattrValid::MODE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                match data {
                    Data::Handle(_, fd) => libc::fchmod(fd, attr.st_mode),
                    Data::ProcPath(ref p) => {
                        libc::fchmodat(self.proc.as_raw_fd(), p.as_ptr(), attr.st_mode, 0)
                    }
                }
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                ::std::u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                ::std::u32::MAX
            };

            // Safe because this is a constant value and a valid C string.
            let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

            // Safe because this doesn't modify any memory and we check the return value.
            let res = unsafe {
                libc::fchownat(
                    inode_data.get_raw_fd(),
                    empty.as_ptr(),
                    uid,
                    gid,
                    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::ftruncate(fd, attr.st_size) },
                _ => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    unsafe { libc::ftruncate(f.as_raw_fd(), attr.st_size) }
                }
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(_, fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
                Data::ProcPath(ref p) => unsafe {
                    libc::utimensat(self.proc.as_raw_fd(), p.as_ptr(), tvs.as_ptr(), 0)
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(inode)
    }

    fn rename(
        &self,
        _ctx: &Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let old_inode = self.inode_map.get(olddir)?;
        let new_inode = self.inode_map.get(newdir)?;

        // Safe because this doesn't modify any memory and we check the return value.
        // TODO: Switch to libc::renameat2 once https://github.com/rust-lang/libc/pull/1508 lands
        // and we have glibc 2.28.
        let res = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_inode.get_raw_fd(),
                oldname.as_ptr(),
                new_inode.get_raw_fd(),
                newname.as_ptr(),
                flags,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn mknod(
        &self,
        ctx: &Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let data = self.inode_map.get(parent)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::mknodat(
                data.get_raw_fd(),
                name.as_ptr(),
                (mode & !umask) as libc::mode_t,
                u64::from(rdev),
            )
        };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            self.do_lookup(parent, name)
        }
    }

    fn link(
        &self,
        _ctx: &Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let data = self.inode_map.get(inode)?;
        let new_inode = self.inode_map.get(newparent)?;

        // Safe because this is a constant value and a valid C string.
        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::linkat(
                data.get_raw_fd(),
                empty.as_ptr(),
                new_inode.get_raw_fd(),
                newname.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if res == 0 {
            self.do_lookup(newparent, newname)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn symlink(
        &self,
        ctx: &Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
    ) -> io::Result<Entry> {
        let (_uid, _gid) = set_creds(ctx.uid, ctx.gid)?;
        let data = self.inode_map.get(parent)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::symlinkat(linkname.as_ptr(), data.get_raw_fd(), name.as_ptr()) };
        if res == 0 {
            self.do_lookup(parent, name)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn readlink(&self, _ctx: &Context, inode: Inode) -> io::Result<Vec<u8>> {
        // Safe because this is a constant value and a valid C string.
        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
        let mut buf = Vec::<u8>::with_capacity(libc::PATH_MAX as usize);
        let data = self.inode_map.get(inode)?;

        // Safe because this will only modify the contents of `buf` and we check the return value.
        let res = unsafe {
            libc::readlinkat(
                data.get_raw_fd(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                libc::PATH_MAX as usize,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we trust the value returned by kernel.
        unsafe { buf.set_len(res as usize) };

        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        if self.no_open.load(Ordering::Relaxed) {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self.handle_map.get(handle, inode)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.get_handle_raw_fd());
            if newfd < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::close(newfd) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn fsync(
        &self,
        _ctx: &Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        let data = self.get_data(handle, inode, libc::O_RDONLY)?;
        let fd = data.get_handle_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            if datasync {
                libc::fdatasync(fd)
            } else {
                libc::fsync(fd)
            }
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fsyncdir(
        &self,
        ctx: &Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: &Context, inode: Inode, mask: u32) -> io::Result<()> {
        let data = self.inode_map.get(inode)?;
        let st = Self::stat(&data.file)?;
        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            // The file exists since we were able to call `stat(2)` on it.
            return Ok(());
        }

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o400 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o040 == 0)
            && st.st_mode & 0o004 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.st_uid != ctx.uid || st.st_mode & 0o200 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o020 == 0)
            && st.st_mode & 0o002 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.st_mode & 0o111 == 0)
            && (st.st_uid != ctx.uid || st.st_mode & 0o100 == 0)
            && (st.st_gid != ctx.gid || st.st_mode & 0o010 == 0)
            && st.st_mode & 0o001 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        Ok(())
    }

    fn setxattr(
        &self,
        _ctx: &Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self.inode_map.get(inode)?;
        let pathname = CString::new(format!("/proc/self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to use the {set,get,remove,list}xattr variants.
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::setxattr(
                pathname.as_ptr(),
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                flags as libc::c_int,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn getxattr(
        &self,
        _ctx: &Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self.inode_map.get(inode)?;
        let mut buf = Vec::<u8>::with_capacity(size as usize);
        let pathname = CString::new(format!("/proc/self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to use the {set,get,remove,list}xattr variants.
        // Safe because this will only modify the contents of `buf`.
        let res = unsafe {
            libc::getxattr(
                pathname.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size as libc::size_t,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            // Safe because we trust the value returned by kernel.
            unsafe { buf.set_len(res as usize) };
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: &Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self.inode_map.get(inode)?;
        let mut buf = Vec::<u8>::with_capacity(size as usize);
        let pathname = CString::new(format!("/proc/self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to use the {set,get,remove,list}xattr variants.
        // Safe because this will only modify the contents of `buf`.
        let res = unsafe {
            libc::listxattr(
                pathname.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                size as libc::size_t,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(ListxattrReply::Count(res as u32))
        } else {
            // Safe because we trust the value returned by kernel.
            unsafe { buf.set_len(res as usize) };
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: &Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let data = self.inode_map.get(inode)?;
        let pathname = CString::new(format!("/proc/self/fd/{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to use the {set,get,remove,list}xattr variants.
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::removexattr(pathname.as_ptr(), name.as_ptr()) };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fallocate(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        // Let the Arc<HandleData> in scope, otherwise fd may get invalid.
        let data = self.get_data(handle, inode, libc::O_RDWR)?;
        let fd = data.get_handle_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::fallocate64(
                fd,
                mode as libc::c_int,
                offset as libc::off64_t,
                length as libc::off64_t,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn lseek(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        // Let the Arc<HandleData> in scope, otherwise fd may get invalid.
        let data = self.handle_map.get(handle, inode)?;

        // Acquire the lock to get exclusive access, otherwise it may break do_readdir().
        let (_guard, file) = data.get_file_mut();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::lseek(
                file.as_raw_fd(),
                offset as libc::off64_t,
                whence as libc::c_int,
            )
        };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as u64)
        }
    }
}

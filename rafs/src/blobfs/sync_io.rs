// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use std::ffi::CStr;
use std::io;
use std::time::Duration;

use fuse_backend_rs::abi::fuse_abi::{CreateIn, FsOptions, OpenOptions, SetattrValid};
use fuse_backend_rs::abi::virtio_fs;
use fuse_backend_rs::api::filesystem::{
    Context, DirEntry, Entry, FileSystem, GetxattrReply, ListxattrReply, ZeroCopyReader,
    ZeroCopyWriter,
};
use fuse_backend_rs::transport::FsCacheReqHandler;
use nydus_api::eacces;
use nydus_utils::{round_down, round_up};

use super::*;
use crate::fs::Handle;
use crate::metadata::Inode;

const MAPPING_UNIT_SIZE: u64 = 0x200000;

impl BlobfsState {
    fn fetch_range_sync(&self, prefetches: &[BlobPrefetchRequest]) -> io::Result<()> {
        let rafs_handle = self.rafs_handle.read().unwrap();
        match rafs_handle.rafs.as_ref() {
            Some(rafs) => rafs.fetch_range_synchronous(prefetches),
            None => Err(einval!("blobfs: failed to initialize RAFS filesystem.")),
        }
    }
}

impl BlobFs {
    // prepare BlobPrefetchRequest and call device.prefetch().
    // Make sure prefetch doesn't use delay_persist as we need the data immediately.
    fn load_chunks_on_demand(&self, inode: Inode, offset: u64, len: u64) -> io::Result<()> {
        let (blob_id, size) = self.get_blob_id_and_size(inode)?;
        if size <= offset || offset.checked_add(len).is_none() {
            return Err(einval!(format!(
                "blobfs: blob_id {:?}, offset {:?} is larger than size {:?}",
                blob_id, offset, size
            )));
        }

        let end = std::cmp::min(offset + len, size);
        let len = end - offset;
        let req = BlobPrefetchRequest {
            blob_id,
            offset,
            len,
        };

        self.state.fetch_range_sync(&[req]).map_err(|e| {
            warn!("blobfs: failed to load data, {:?}", e);
            e
        })
    }
}

impl FileSystem for BlobFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.state.get_rafs_handle()?;
        self.pfs.init(capable)
    }

    fn destroy(&self) {
        self.pfs.destroy()
    }

    fn lookup(&self, _ctx: &Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.pfs.lookup(_ctx, parent, name)
    }

    fn forget(&self, _ctx: &Context, inode: Inode, count: u64) {
        self.pfs.forget(_ctx, inode, count)
    }

    fn batch_forget(&self, _ctx: &Context, requests: Vec<(Inode, u64)>) {
        self.pfs.batch_forget(_ctx, requests)
    }

    fn getattr(
        &self,
        _ctx: &Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.pfs.getattr(_ctx, inode, _handle)
    }

    fn setattr(
        &self,
        _ctx: &Context,
        _inode: Inode,
        _attr: libc::stat64,
        _handle: Option<Handle>,
        _valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        Err(eacces!("Setattr request is not allowed in blobfs"))
    }

    fn readlink(&self, _ctx: &Context, inode: Inode) -> io::Result<Vec<u8>> {
        self.pfs.readlink(_ctx, inode)
    }

    fn symlink(
        &self,
        _ctx: &Context,
        _linkname: &CStr,
        _parent: Inode,
        _name: &CStr,
    ) -> io::Result<Entry> {
        Err(eacces!("Symlink request is not allowed in blobfs"))
    }

    fn mknod(
        &self,
        _ctx: &Context,
        _parent: Inode,
        _name: &CStr,
        _mode: u32,
        _rdev: u32,
        _umask: u32,
    ) -> io::Result<Entry> {
        Err(eacces!("Mknod request is not allowed in blobfs"))
    }

    fn mkdir(
        &self,
        _ctx: &Context,
        _parent: Inode,
        _name: &CStr,
        _mode: u32,
        _umask: u32,
    ) -> io::Result<Entry> {
        Err(eacces!("Mkdir request is not allowed in blobfs"))
    }

    fn unlink(&self, _ctx: &Context, _parent: Inode, _name: &CStr) -> io::Result<()> {
        Err(eacces!("Unlink request is not allowed in blobfs"))
    }

    fn rmdir(&self, _ctx: &Context, _parent: Inode, _name: &CStr) -> io::Result<()> {
        Err(eacces!("Rmdir request is not allowed in blobfs"))
    }

    fn rename(
        &self,
        _ctx: &Context,
        _olddir: Inode,
        _oldname: &CStr,
        _newdir: Inode,
        _newname: &CStr,
        _flags: u32,
    ) -> io::Result<()> {
        Err(eacces!("Rename request is not allowed in blobfs"))
    }

    fn link(
        &self,
        _ctx: &Context,
        _inode: Inode,
        _newparent: Inode,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        Err(eacces!("Link request is not allowed in blobfs"))
    }

    fn open(
        &self,
        _ctx: &Context,
        inode: Inode,
        flags: u32,
        _fuse_flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.pfs.open(_ctx, inode, flags, _fuse_flags)
    }

    fn create(
        &self,
        _ctx: &Context,
        _parent: Inode,
        _name: &CStr,
        _args: CreateIn,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        Err(eacces!("Create request is not allowed in blobfs"))
    }

    fn read(
        &self,
        ctx: &Context,
        inode: Inode,
        handle: Handle,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.load_chunks_on_demand(inode, offset, size as u64)?;
        self.pfs
            .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
    }

    fn write(
        &self,
        _ctx: &Context,
        _inode: Inode,
        _handle: Handle,
        _r: &mut dyn ZeroCopyReader,
        _size: u32,
        _offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _flags: u32,
        _fuse_flags: u32,
    ) -> io::Result<usize> {
        Err(eacces!("Write request is not allowed in blobfs"))
    }

    fn flush(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        self.pfs.flush(_ctx, inode, handle, _lock_owner)
    }

    fn fsync(
        &self,
        _ctx: &Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.pfs.fsync(_ctx, inode, datasync, handle)
    }

    fn fallocate(
        &self,
        _ctx: &Context,
        _inode: Inode,
        _handle: Handle,
        _mode: u32,
        _offset: u64,
        _length: u64,
    ) -> io::Result<()> {
        Err(eacces!("Fallocate request is not allowed in blobfs"))
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
        self.pfs.release(
            _ctx,
            inode,
            _flags,
            handle,
            _flush,
            _flock_release,
            _lock_owner,
        )
    }

    fn statfs(&self, _ctx: &Context, inode: Inode) -> io::Result<libc::statvfs64> {
        self.pfs.statfs(_ctx, inode)
    }

    fn setxattr(
        &self,
        _ctx: &Context,
        _inode: Inode,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        Err(eacces!("Setxattr request is not allowed in blobfs"))
    }

    fn getxattr(
        &self,
        _ctx: &Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.pfs.getxattr(_ctx, inode, name, size)
    }

    fn listxattr(&self, _ctx: &Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        self.pfs.listxattr(_ctx, inode, size)
    }

    fn removexattr(&self, _ctx: &Context, _inode: Inode, _name: &CStr) -> io::Result<()> {
        Err(eacces!("Removexattr request is not allowed in blobfs"))
    }

    fn opendir(
        &self,
        _ctx: &Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.pfs.opendir(_ctx, inode, flags)
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
        self.pfs
            .readdir(_ctx, inode, handle, size, offset, add_entry)
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
        self.pfs
            .readdirplus(_ctx, inode, handle, size, offset, add_entry)
    }

    fn fsyncdir(
        &self,
        ctx: &Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.pfs.fsyncdir(ctx, inode, datasync, handle)
    }

    fn releasedir(
        &self,
        _ctx: &Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.pfs.releasedir(_ctx, inode, _flags, handle)
    }

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
        if (flags & virtio_fs::SetupmappingFlags::WRITE.bits()) != 0 {
            return Err(eacces!("blob file cannot write in dax"));
        }
        if foffset.checked_add(len).is_none() || foffset + len > u64::MAX - MAPPING_UNIT_SIZE {
            return Err(einval!(format!(
                "blobfs: invalid offset 0x{:x} and len 0x{:x}",
                foffset, len
            )));
        }

        let end = round_up(foffset + len, MAPPING_UNIT_SIZE);
        let offset = round_down(foffset, MAPPING_UNIT_SIZE);
        let len = end - offset;
        self.load_chunks_on_demand(inode, offset, len)?;

        self.pfs
            .setupmapping(_ctx, inode, _handle, foffset, len, flags, moffset, vu_req)
    }

    fn removemapping(
        &self,
        _ctx: &Context,
        _inode: Inode,
        requests: Vec<virtio_fs::RemovemappingOne>,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        self.pfs.removemapping(_ctx, _inode, requests, vu_req)
    }

    fn access(&self, ctx: &Context, inode: Inode, mask: u32) -> io::Result<()> {
        self.pfs.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        _ctx: &Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.pfs.lseek(_ctx, inode, handle, offset, whence)
    }
}

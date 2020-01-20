// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// A container image Registry Acceleration File System.

//! RAFS: a readonly FUSE file system designed for Cloud Native.

use std::any::Any;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::fmt;
use std::io::Result;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::*;
use fuse_rs::api::BackendFileSystem;
use nix::unistd::{getegid, geteuid};
use serde::Deserialize;
use std::time::SystemTime;

use crate::io_stats;
use crate::io_stats::StatsFop;
use crate::metadata::{Inode, RafsInode, RafsSuper};
use crate::storage::device;
use crate::storage::*;
use crate::*;

use nydus_utils::{eacces, ealready, enoent, eother};

/// Type of RAFS fuse handle.
pub type Handle = u64;

/// Rafs default attribute timeout value.
pub const RAFS_DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
/// Rafs default entry timeout value.
pub const RAFS_DEFAULT_ENTRY_TIMEOUT: u64 = RAFS_DEFAULT_ATTR_TIMEOUT;

const DOT: &str = ".";
const DOTDOT: &str = "..";

fn default_threads_count() -> usize {
    8
}

fn default_merging_size() -> usize {
    128 * 1024
}

#[derive(Clone, Default, Deserialize)]
pub struct FsPrefetchControl {
    #[serde(default)]
    enable: bool,
    #[serde(default = "default_threads_count")]
    threads_count: usize,
    #[serde(default = "default_merging_size")]
    merging_size: usize,
}

/// Rafs storage backend configuration information.
#[derive(Clone, Default, Deserialize)]
pub struct RafsConfig {
    pub device: factory::Config,
    pub mode: String,
    #[serde(default)]
    pub digest_validate: bool,
    #[serde(default)]
    pub iostats_files: bool,
    #[serde(default)]
    pub fs_prefetch: FsPrefetchControl,
    #[serde(default)]
    pub enable_xattr: bool,
    #[serde(default)]
    pub access_pattern: bool,
}

impl RafsConfig {
    pub fn new() -> RafsConfig {
        RafsConfig {
            ..Default::default()
        }
    }
}

impl fmt::Display for RafsConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "mode={} digest_validate={} iostats_files={}",
            self.mode, self.digest_validate, self.iostats_files
        )
    }
}

/// Main entrance of the RAFS readonly FUSE file system.
pub struct Rafs {
    device: device::RafsDevice,
    sb: RafsSuper,
    digest_validate: bool,
    fs_prefetch: bool,
    initialized: bool,
    xattr_enabled: bool,
    ios: Arc<io_stats::GlobalIOStats>,
    // static inode attributes
    i_uid: u32,
    i_gid: u32,
    i_time: u64,
}

impl Rafs {
    pub fn new(conf: RafsConfig, id: &str, r: &mut RafsIoReader) -> Result<Self> {
        let mut device_conf = conf.device.clone();
        device_conf.cache.cache_validate = conf.digest_validate;
        device_conf.cache.prefetch_worker.threads_count = conf.fs_prefetch.threads_count;
        device_conf.cache.prefetch_worker.merging_size = conf.fs_prefetch.merging_size;

        let mut sb = RafsSuper::new(&conf)?;
        sb.load(r)?;

        let rafs = Rafs {
            device: device::RafsDevice::new(
                device_conf,
                sb.meta.get_compressor(),
                sb.meta.get_digester(),
            )?,
            sb,
            initialized: false,
            ios: io_stats::new(id),
            digest_validate: conf.digest_validate,
            fs_prefetch: conf.fs_prefetch.enable,
            xattr_enabled: conf.enable_xattr,
            i_uid: geteuid().into(),
            i_gid: getegid().into(),
            i_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        rafs.ios.toggle_files_recording(conf.iostats_files);
        rafs.ios.toggle_access_pattern(conf.access_pattern);

        Ok(rafs)
    }

    /// update backend meta and blob file.
    pub fn update(&self, r: &mut RafsIoReader, conf: RafsConfig) -> Result<()> {
        info!("update");
        if !self.initialized {
            warn!("Rafs is not yet initialized");
            return Err(enoent!("Rafs is not yet initialized"));
        }

        // step 1: update sb.
        // No lock is needed thanks to ArcSwap.
        self.sb.update(r).map_err(|e| {
            error!("update failed due to {:?}", e);
            e
        })?;

        info!("update sb is successful");

        // step 2: update device (only localfs is supported)
        self.device.update(
            conf.device,
            self.sb.meta.get_compressor(),
            self.sb.meta.get_digester(),
        )?;
        info!("update device is successful");

        Ok(())
    }

    /// Import an rafs bootstrap to initialize the filesystem instance.
    pub fn import(
        &mut self,
        r: &mut RafsIoReader,
        prefetch_files: Option<Vec<&Path>>,
    ) -> Result<()> {
        if self.initialized {
            return Err(ealready!("rafs already mounted"));
        }

        self.device
            .init(&self.sb.meta, &self.sb.inodes.get_blobs())?;

        // Device should be ready before any prefetch.
        if self.fs_prefetch {
            let inodes = match prefetch_files {
                Some(files) => {
                    let mut inodes = Vec::<Inode>::new();
                    for f in files {
                        if let Ok(inode) = self.ino_from_path(f) {
                            inodes.push(inode);
                        } else {
                            continue;
                        }
                    }
                    Some(inodes)
                }
                None => None,
            };

            if let Ok(ref mut desc) = self.sb.prefetch_hint_files(r, inodes) {
                if self.device.prefetch(desc).is_err() {
                    eother!("Prefetch error");
                }
            }
        }

        self.initialized = true;
        info!("rafs imported");

        Ok(())
    }

    /// umount a previously mounted rafs virtual path
    pub fn destroy(&mut self) -> Result<()> {
        info! {"Destroy rafs"}

        if self.initialized {
            self.sb.destroy();
            self.device.close()?;
            self.initialized = false;
        }

        Ok(())
    }

    fn xattr_supported(&self) -> bool {
        self.xattr_enabled || self.sb.meta.has_xattr()
    }

    fn do_readdir<F>(&self, ino: Inode, size: u32, offset: u64, mut add_entry: F) -> Result<()>
    where
        F: FnMut(DirEntry) -> Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let parent = self.sb.get_inode(ino, self.digest_validate)?;
        if !parent.is_dir() {
            return Err(err_not_directory!());
        }

        let mut cur_offset = offset;
        // offset 0 and 1 is for "." and ".." respectively.
        if cur_offset == 0 {
            cur_offset += 1;
            add_entry(DirEntry {
                ino,
                offset: cur_offset,
                type_: 0,
                name: DOT.as_bytes(),
            })?;
        }
        if cur_offset == 1 {
            let parent = if ino == ROOT_ID {
                ROOT_ID
            } else {
                parent.parent()
            };
            cur_offset += 1;
            add_entry(DirEntry {
                ino: parent,
                offset: cur_offset,
                type_: 0,
                name: DOTDOT.as_bytes(),
            })?;
        }

        let mut idx = cur_offset - 2;
        while idx < parent.get_child_count() as u64 {
            let child = parent.get_child_by_index(idx)?;

            cur_offset += 1;
            match add_entry(DirEntry {
                ino: child.ino(),
                offset: cur_offset,
                type_: 0,
                name: child.name()?.as_bytes(),
            }) {
                Ok(0) => {
                    self.ios
                        .new_file_counter(child.ino(), |i| self.path_from_ino(i).unwrap());
                    break;
                }
                Ok(_) => {
                    idx += 1;
                    self.ios
                        .new_file_counter(child.ino(), |i| self.path_from_ino(i).unwrap())
                } // TODO: should we check `size` here?
                Err(r) => return Err(r),
            }
        }

        Ok(())
    }

    fn negative_entry(&self) -> Entry {
        Entry {
            attr: Attr {
                ..Default::default()
            }
            .into(),
            inode: 0,
            generation: 0,
            attr_timeout: self.sb.meta.attr_timeout,
            entry_timeout: self.sb.meta.entry_timeout,
        }
    }

    fn lookup_wrapped(&self, ino: u64, name: &CStr) -> Result<Entry> {
        let target = OsStr::from_bytes(name.to_bytes());
        let parent = self.sb.get_inode(ino, self.digest_validate)?;
        if !parent.is_dir() {
            return Err(err_not_directory!());
        }

        if target == DOT || (ino == ROOT_ID && target == DOTDOT) {
            let mut entry = self.get_inode_entry(parent);
            entry.inode = ino;
            Ok(entry)
        } else if target == DOTDOT {
            Ok(self
                .sb
                .get_inode(parent.parent(), self.digest_validate)
                .map(|i| self.get_inode_entry(i))
                .unwrap_or_else(|_| self.negative_entry()))
        } else {
            Ok(parent
                .get_child_by_name(target)
                .map(|i| {
                    self.ios
                        .new_file_counter(i.ino(), |i| self.path_from_ino(i).unwrap());
                    self.get_inode_entry(i)
                })
                .unwrap_or_else(|_| self.negative_entry()))
        }
    }

    fn get_inode_attr(&self, ino: u64) -> Result<Attr> {
        let inode = self.sb.get_inode(ino, false)?;
        let mut attr = inode.get_attr();
        // override uid/gid if there is no explicit inode uid/gid
        if !self.sb.meta.explicit_uidgid() {
            attr.uid = self.i_uid;
            attr.gid = self.i_gid;
        }
        // Rafs does not accommodate special files, so `rdev` can always be 0.
        attr.rdev = 0;
        attr.atime = self.i_time;
        attr.ctime = self.i_time;
        attr.mtime = self.i_time;

        Ok(attr)
    }

    fn get_inode_entry(&self, inode: Arc<dyn RafsInode>) -> Entry {
        let mut entry = inode.get_entry();
        // override uid/gid if there is no explicit inode uid/gid
        if !self.sb.meta.explicit_uidgid() {
            entry.attr.st_uid = self.i_uid;
            entry.attr.st_gid = self.i_gid;
        }

        // Rafs does not accommodate special files, so `rdev` can always be 0.
        entry.attr.st_rdev = 0u64;
        entry.attr.st_atime = self.i_time as i64;
        entry.attr.st_ctime = self.i_time as i64;
        entry.attr.st_mtime = self.i_time as i64;

        entry
    }

    fn path_from_ino(&self, ino: Inode) -> Result<PathBuf> {
        if ino == ROOT_ID {
            return Ok(self.sb.get_inode(ino, false)?.name()?.into());
        }

        let mut path = PathBuf::new();
        let mut cur_ino = ino;
        let mut inode;

        loop {
            inode = self.sb.get_inode(cur_ino, false)?;
            let e: PathBuf = inode.name()?.into();
            path = e.join(path);

            if inode.ino() == ROOT_ID {
                break;
            } else {
                cur_ino = inode.parent();
            }
        }

        Ok(path)
    }

    fn ino_from_path(&self, f: &Path) -> Result<u64> {
        if f == Path::new("/") {
            return Ok(ROOT_ID);
        }

        if !f.starts_with("/") {
            return Err(einval!());
        }

        let mut parent = self.sb.get_inode(ROOT_ID, self.digest_validate)?;

        let entries = f
            .components()
            .filter(|comp| *comp != Component::RootDir)
            .map(|comp| match comp {
                Component::Normal(name) => Some(name),
                Component::ParentDir => Some(OsStr::from_bytes(DOTDOT.as_bytes())),
                Component::CurDir => Some(OsStr::from_bytes(DOT.as_bytes())),
                _ => None,
            })
            .collect::<Vec<_>>();

        if entries.is_empty() {
            warn!("Path can't be parsed {:?}", f);
            return Err(enoent!());
        }

        for p in entries {
            if p.is_none() {
                error!("Illegal specified path {:?}", f);
                return Err(einval!());
            }

            // Safe because it already checks if p is None above.
            match parent.get_child_by_name(p.unwrap()) {
                Ok(p) => parent = p,
                Err(_) => {
                    warn!("File {:?} not in rafs", p.unwrap());
                    return Err(enoent!());
                }
            }
        }

        Ok(parent.ino())
    }
}

impl BackendFileSystem for Rafs {
    fn mount(&self) -> Result<(Entry, u64)> {
        let root_inode = self.sb.get_inode(ROOT_ID, self.digest_validate)?;
        self.ios
            .new_file_counter(root_inode.ino(), |i| self.path_from_ino(i).unwrap());
        let entry = self.get_inode_entry(root_inode);
        Ok((entry, self.sb.get_max_ino()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl FileSystem for Rafs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, _opts: FsOptions) -> Result<FsOptions> {
        Ok(
            // These fuse features are supported by rafs by default.
            FsOptions::ASYNC_READ
                | FsOptions::PARALLEL_DIROPS
                | FsOptions::BIG_WRITES
                | FsOptions::HANDLE_KILLPRIV
                | FsOptions::ASYNC_DIO
                | FsOptions::HAS_IOCTL_DIR
                | FsOptions::WRITEBACK_CACHE
                | FsOptions::ZERO_MESSAGE_OPEN
                | FsOptions::ATOMIC_O_TRUNC
                | FsOptions::CACHE_SYMLINKS
                | FsOptions::ZERO_MESSAGE_OPENDIR,
        )
    }

    fn destroy(&self) {}

    fn lookup(&self, _ctx: Context, ino: u64, name: &CStr) -> Result<Entry> {
        let start = self.ios.latency_start();
        let r = self.lookup_wrapped(ino, name);
        self.ios.file_stats_update(ino, StatsFop::Lookup, 0, &r);
        self.ios.latency_end(&start, StatsFop::Lookup);
        r
    }

    fn forget(&self, _ctx: Context, _inode: u64, _count: u64) {}

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count)
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: Option<u64>,
    ) -> Result<(libc::stat64, Duration)> {
        let attr = self.get_inode_attr(ino)?;
        let r = Ok((attr.into(), self.sb.meta.attr_timeout));
        self.ios.file_stats_update(ino, StatsFop::Stat, 0, &r);
        r
    }

    fn readlink(&self, _ctx: Context, ino: u64) -> Result<Vec<u8>> {
        let inode = self.sb.get_inode(ino, self.digest_validate)?;

        Ok(inode.get_symlink()?.as_bytes().to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> Result<usize> {
        let inode = self.sb.get_inode(ino, false)?;
        if offset >= inode.size() {
            return Ok(0);
        }
        let desc = inode.alloc_bio_desc(offset, size as usize)?;
        let start = self.ios.latency_start();
        let r = self.device.read_to(w, desc);
        self.ios
            .file_stats_update(ino, StatsFop::Read, size as usize, &r);
        self.ios.latency_end(&start, io_stats::StatsFop::Read);
        r
    }

    fn release(
        &self,
        _ctx: Context,
        _inode: u64,
        _flags: u32,
        _handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _inode: u64) -> Result<libc::statvfs64> {
        // Safe because we are zero-initializing a struct with only POD fields.
        let mut st: libc::statvfs64 = unsafe { std::mem::zeroed() };

        // This matches the behavior of libfuse as it returns these values if the
        // filesystem doesn't implement this method.
        st.f_namemax = 255;
        st.f_bsize = 512;
        st.f_fsid = self.sb.meta.magic as u64;
        st.f_files = self.sb.meta.inodes_count;

        Ok(st)
    }

    fn getxattr(&self, _ctx: Context, inode: u64, name: &CStr, size: u32) -> Result<GetxattrReply> {
        if !self.xattr_supported() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let name = OsStr::from_bytes(name.to_bytes());
        let inode = self.sb.get_inode(inode, false)?;

        let value = inode.get_xattr(name)?;
        match value {
            Some(value) => match size {
                0 => Ok(GetxattrReply::Count((value.len() + 1) as u32)),
                x if x < value.len() as u32 => Err(std::io::Error::from_raw_os_error(libc::ERANGE)),
                _ => Ok(GetxattrReply::Value(value)),
            },
            None => Err(std::io::Error::from_raw_os_error(libc::ENODATA)),
        }
    }

    fn listxattr(&self, _ctx: Context, inode: u64, size: u32) -> Result<ListxattrReply> {
        if !self.xattr_supported() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let inode = self.sb.get_inode(inode, false)?;

        let mut count = 0;
        let mut buf = Vec::new();

        for mut name in inode.get_xattrs()? {
            count += name.len() + 1;
            if size != 0 {
                buf.append(&mut name);
                buf.append(&mut vec![0u8; 1]);
            }
        }

        match size {
            0 => Ok(ListxattrReply::Count(count as u32)),
            x if x < count as u32 => Err(std::io::Error::from_raw_os_error(libc::ERANGE)),
            _ => Ok(ListxattrReply::Names(buf)),
        }
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        self.do_readdir(inode, size, offset, add_entry)
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        self.do_readdir(ino, size, offset, |dir_entry| {
            let inode = self.sb.get_inode(dir_entry.ino, self.digest_validate)?;
            add_entry(dir_entry, self.get_inode_entry(inode))
        })
    }

    fn releasedir(&self, _ctx: Context, _inode: u64, _flags: u32, _handle: u64) -> Result<()> {
        Ok(())
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> Result<()> {
        let st = self.get_inode_attr(ino)?;
        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            return Ok(());
        }

        if (mode & libc::R_OK) != 0
            && ctx.uid != 0
            && (st.uid != ctx.uid || st.mode & 0o400 == 0)
            && (st.gid != ctx.gid || st.mode & 0o040 == 0)
            && st.mode & 0o004 == 0
        {
            return Err(eacces!("permission denied"));
        }

        if (mode & libc::W_OK) != 0
            && ctx.uid != 0
            && (st.uid != ctx.uid || st.mode & 0o200 == 0)
            && (st.gid != ctx.gid || st.mode & 0o020 == 0)
            && st.mode & 0o002 == 0
        {
            return Err(eacces!("permission denied"));
        }

        // root can only execute something if it is executable by one of the owner, the group, or
        // everyone.
        if (mode & libc::X_OK) != 0
            && (ctx.uid != 0 || st.mode & 0o111 == 0)
            && (st.uid != ctx.uid || st.mode & 0o100 == 0)
            && (st.gid != ctx.gid || st.mode & 0o010 == 0)
            && st.mode & 0o001 == 0
        {
            return Err(eacces!("permission denied"));
        }

        Ok(())
    }
}

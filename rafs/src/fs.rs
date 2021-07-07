// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// A container image Registry Acceleration File System.

//! RAFS: a readonly FUSE file system designed for Cloud Native.

use std::any::Any;
use std::convert::TryFrom;
use std::ffi::{CStr, OsStr};
use std::fmt;
use std::io::Result;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

use nix::unistd::{getegid, geteuid};
use serde::Deserialize;

use fuse_rs::abi::linux_abi::Attr;
use fuse_rs::api::filesystem::*;
use fuse_rs::api::BackendFileSystem;

use crate::metadata::{
    layout::RAFS_ROOT_INODE, Inode, RafsInode, RafsSuper, RAFS_DEFAULT_BLOCK_SIZE,
};
use crate::*;
use nydus_utils::metrics::{self, FopRecorder, StatsFop::*};
use storage::device::BlobPrefetchControl;
use storage::*;
use storage::{cache::PrefetchWorker, device};

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

fn default_prefetch_all() -> bool {
    true
}

#[derive(Clone, Default, Deserialize)]
pub struct FsPrefetchControl {
    #[serde(default)]
    enable: bool,
    #[serde(default = "default_threads_count")]
    threads_count: usize,
    #[serde(default = "default_merging_size")]
    // In unit of Bytes
    merging_size: usize,
    #[serde(default)]
    // In unit of Bytes. It sets a limit to prefetch bandwidth usage in order to
    // reduce congestion with normal user IO.
    // bandwidth_rate == 0 -- prefetch bandwidth ratelimit disabled
    // bandwidth_rate > 0  -- prefetch bandwidth ratelimit enabled.
    //                        Please note that if the value is less than Rafs chunk size,
    //                        it will be raised to the chunk size.
    bandwidth_rate: u32,
    #[serde(default = "default_prefetch_all")]
    prefetch_all: bool,
}

/// Not everything can be safely exported from configuration.
/// We trim the unneeded info from here.
#[macro_export]
macro_rules! trim_backend_config {
    ($config:expr, $($i:expr),*) => {
        let mut _n :&mut serde_json::Value = &mut $config["device"]["backend"]["config"];
        if let serde_json::Value::Object(ref mut m) = _n {
            $(if m.contains_key($i) { m[$i].take();} else {()};)*
        }
    };
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
    #[serde(default)]
    pub latest_read_files: bool,
}

impl FromStr for RafsConfig {
    type Err = RafsError;

    fn from_str(s: &str) -> RafsResult<RafsConfig> {
        serde_json::from_str(s).map_err(RafsError::ParseConfig)
    }
}

impl RafsConfig {
    pub fn new() -> RafsConfig {
        RafsConfig {
            ..Default::default()
        }
    }

    pub fn from_file(path: &str) -> RafsResult<RafsConfig> {
        let file = File::open(path).map_err(RafsError::LoadConfig)?;
        serde_json::from_reader::<File, RafsConfig>(file).map_err(RafsError::ParseConfig)
    }
}

impl fmt::Display for RafsConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "mode={} digest_validate={} iostats_files={} latest_read_files={}",
            self.mode, self.digest_validate, self.iostats_files, self.latest_read_files
        )
    }
}

/// Main entrance of the RAFS readonly FUSE file system.
pub struct Rafs {
    id: String,
    device: device::RafsDevice,
    pub sb: Arc<RafsSuper>,
    digest_validate: bool,
    fs_prefetch: bool,
    prefetch_all: bool,
    initialized: bool,
    xattr_enabled: bool,
    ios: Arc<metrics::GlobalIOStats>,
    // static inode attributes
    i_uid: u32,
    i_gid: u32,
    i_time: u64,
}

impl TryFrom<&RafsConfig> for PrefetchWorker {
    type Error = RafsError;
    fn try_from(c: &RafsConfig) -> RafsResult<Self> {
        if c.fs_prefetch.merging_size as u64 > RAFS_DEFAULT_BLOCK_SIZE {
            return Err(RafsError::Configure(
                "Merging size can't exceed chunk size".to_string(),
            ));
        }

        Ok(PrefetchWorker {
            enable: c.fs_prefetch.enable,
            threads_count: c.fs_prefetch.threads_count,
            merging_size: c.fs_prefetch.merging_size,
            bandwidth_rate: c.fs_prefetch.bandwidth_rate,
        })
    }
}

impl Rafs {
    pub fn new(conf: RafsConfig, id: &str, r: &mut RafsIoReader) -> RafsResult<Self> {
        let mut device_conf = conf.device.clone();

        device_conf.cache.cache_validate = conf.digest_validate;
        device_conf.cache.prefetch_worker = TryFrom::try_from(&conf)?;

        let mut sb = RafsSuper::new(&conf).map_err(RafsError::FillSuperblock)?;
        sb.load(r).map_err(RafsError::FillSuperblock)?;

        let rafs = Rafs {
            id: id.to_string(),
            device: device::RafsDevice::new(
                device_conf,
                sb.meta.get_compressor(),
                sb.meta.get_digester(),
                id,
            )
            .map_err(RafsError::CreateDevice)?,
            sb: Arc::new(sb),
            initialized: false,
            ios: metrics::new(id),
            digest_validate: conf.digest_validate,
            fs_prefetch: conf.fs_prefetch.enable,
            prefetch_all: conf.fs_prefetch.prefetch_all,
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
        rafs.ios
            .toggle_latest_read_files_recording(conf.latest_read_files);

        Ok(rafs)
    }

    /// update backend meta and blob file.
    pub fn update(&self, r: &mut RafsIoReader, conf: RafsConfig) -> RafsResult<()> {
        info!("update");
        if !self.initialized {
            warn!("Rafs is not yet initialized");
            return Err(RafsError::Uninitialized);
        }

        // step 1: update sb.
        // No lock is needed thanks to ArcSwap.
        self.sb.update(r).map_err(|e| {
            error!("update failed due to {:?}", e);
            e
        })?;

        info!("update sb is successful");

        let mut device_conf = conf.device.clone();
        device_conf.cache.cache_validate = conf.digest_validate;
        device_conf.cache.prefetch_worker = TryFrom::try_from(&conf)?;

        // step 2: update device (only localfs is supported)
        self.device
            .update(
                device_conf,
                self.sb.meta.get_compressor(),
                self.sb.meta.get_digester(),
                self.id.as_str(),
            )
            .map_err(RafsError::SwapBackend)?;
        info!("update device is successful");

        Ok(())
    }

    /// Import an rafs bootstrap to initialize the filesystem instance.
    pub fn import(
        &mut self,
        r: RafsIoReader,
        prefetch_files: Option<Vec<PathBuf>>,
    ) -> RafsResult<()> {
        if self.initialized {
            return Err(RafsError::AlreadyMounted);
        }

        // Without too much layout concern, just prefetch a certain range from backend.
        let prefetch_vec = self
            .sb
            .inodes
            .get_blobs()
            .iter()
            .map(|b| BlobPrefetchControl {
                blob_id: b.blob_id.clone(),
                offset: b.readahead_offset,
                len: b.readahead_size,
            })
            .collect::<Vec<BlobPrefetchControl>>();

        self.device
            .init(&prefetch_vec)
            .map_err(RafsError::CreateDevice)?;

        // Device should be ready before any prefetch.
        if self.fs_prefetch {
            let sb = self.sb.clone();
            let device = self.device.clone();

            let prefetch_all = self.prefetch_all;

            let _ = std::thread::spawn(move || {
                let mut reader = r;
                let inodes = match prefetch_files {
                    Some(files) => {
                        let mut inodes = Vec::<Inode>::new();
                        for f in files {
                            if let Ok(inode) = sb.ino_from_path(f.as_path()) {
                                inodes.push(inode);
                            } else {
                                continue;
                            }
                        }
                        Some(inodes)
                    }
                    None => None,
                };

                // Prefetch procedure does not affect rafs mounting
                sb.prefetch_hint_files(&mut reader, inodes, &|mut desc| {
                    device.prefetch(&mut desc).unwrap_or_else(|e| {
                        warn!("Prefetch error, {:?}", e);
                        0
                    });
                })
                .unwrap_or_else(|e| {
                    info!("No file to be prefetched {:?}", e);
                });

                if prefetch_all {
                    let mut root = Vec::new();
                    root.push(RAFS_ROOT_INODE);
                    // Sleeping for 2 seconds is indeed a trick to prefetch the entire rootfs.
                    // FIXME: As nydus can't give different policies different priorities, this is a
                    // workaround. Remove the sleeping when IO priority mechanism is ready.
                    sleep(Duration::from_secs(2));
                    sb.prefetch_hint_files(&mut reader, Some(root), &|mut desc| {
                        device.prefetch(&mut desc).unwrap_or_else(|e| {
                            warn!("Prefetch error, {:?}", e);
                            0
                        });
                    })
                    .unwrap_or_else(|e| {
                        info!("No file to be prefetched {:?}", e);
                    })
                }

                // For now, we only have hinted prefetch. So stopping prefetch workers once
                // it's done is Okay. But if we involve more policies someday, we have to be
                // careful when to stop prefetch progresses.
                device
                    .stop_prefetch()
                    .unwrap_or_else(|_| error!("Failed in stopping prefetch workers"));
            });
        }

        self.initialized = true;
        Ok(())
    }

    /// umount a previously mounted rafs virtual path
    pub fn destroy(&mut self) -> Result<()> {
        info! {"Destroy rafs"}

        if self.initialized {
            Arc::get_mut(&mut self.sb)
                .expect("Superblock is no longer used")
                .destroy();
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
            return Err(enotdir!());
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
                name: child.name().as_bytes(),
            }) {
                Ok(0) => {
                    self.ios
                        .new_file_counter(child.ino(), |i| self.sb.path_from_ino(i).unwrap());
                    break;
                }
                Ok(_) => {
                    idx += 1;
                    self.ios
                        .new_file_counter(child.ino(), |i| self.sb.path_from_ino(i).unwrap())
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

    fn get_inode_attr(&self, ino: u64) -> Result<Attr> {
        let inode = self.sb.get_inode(ino, false)?;
        let mut attr = inode.get_attr();
        // override uid/gid if there is no explicit inode uid/gid
        if !self.sb.meta.explicit_uidgid() {
            attr.uid = self.i_uid;
            attr.gid = self.i_gid;
        }

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

        entry.attr.st_atime = self.i_time as i64;
        entry.attr.st_ctime = self.i_time as i64;
        entry.attr.st_mtime = self.i_time as i64;

        entry
    }
}

impl BackendFileSystem for Rafs {
    fn mount(&self) -> Result<(Entry, u64)> {
        let root_inode = self.sb.get_inode(ROOT_ID, self.digest_validate)?;
        self.ios
            .new_file_counter(root_inode.ino(), |i| self.sb.path_from_ino(i).unwrap());
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
        let mut rec = FopRecorder::settle(Lookup, ino, &self.ios);
        let target = OsStr::from_bytes(name.to_bytes());
        let parent = self.sb.get_inode(ino, self.digest_validate)?;
        if !parent.is_dir() {
            return Err(enotdir!());
        }

        rec.mark_success(0);
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
                        .new_file_counter(i.ino(), |i| self.sb.path_from_ino(i).unwrap());
                    self.get_inode_entry(i)
                })
                .unwrap_or_else(|_| self.negative_entry()))
        }
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
        let mut recorder = FopRecorder::settle(Getattr, ino, &self.ios);
        let attr = self.get_inode_attr(ino).map(|r| {
            recorder.mark_success(0);
            r
        })?;
        Ok((attr.into(), self.sb.meta.attr_timeout))
    }

    fn readlink(&self, _ctx: Context, ino: u64) -> Result<Vec<u8>> {
        let mut rec = FopRecorder::settle(Readlink, ino, &self.ios);
        let inode = self.sb.get_inode(ino, self.digest_validate)?;
        Ok(inode
            .get_symlink()
            .map(|r| {
                rec.mark_success(0);
                r
            })?
            .as_bytes()
            .to_vec())
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
        let mut recorder = FopRecorder::settle(Read, ino, &self.ios);
        let inode = self.sb.get_inode(ino, false)?;
        if offset >= inode.size() {
            recorder.mark_success(0);
            return Ok(0);
        }
        let desc = inode.alloc_bio_desc(offset, size as usize)?;
        let start = self.ios.latency_start();
        let r = self.device.read_to(w, desc).map(|r| {
            recorder.mark_success(r);
            r
        });
        self.ios.latency_end(&start, Read);
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
        let mut recorder = FopRecorder::settle(Getxattr, inode, &self.ios);

        if !self.xattr_supported() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let name = OsStr::from_bytes(name.to_bytes());
        let inode = self.sb.get_inode(inode, false)?;

        let value = inode.get_xattr(name)?;
        let r = match value {
            Some(value) => match size {
                0 => Ok(GetxattrReply::Count((value.len() + 1) as u32)),
                x if x < value.len() as u32 => Err(std::io::Error::from_raw_os_error(libc::ERANGE)),
                _ => Ok(GetxattrReply::Value(value)),
            },
            None => {
                // TODO: Hopefully, we can have a 'decorator' procedure macro in
                // the future to wrap this method thus to handle different reasonable
                // errors in a clean way.
                recorder.mark_success(0);
                Err(std::io::Error::from_raw_os_error(libc::ENODATA))
            }
        };

        r.map(|v| {
            recorder.mark_success(0);
            v
        })
    }

    fn listxattr(&self, _ctx: Context, inode: u64, size: u32) -> Result<ListxattrReply> {
        let mut rec = FopRecorder::settle(Listxattr, inode, &self.ios);
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

        rec.mark_success(0);

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
        let mut rec = FopRecorder::settle(Readdir, inode, &self.ios);
        self.do_readdir(inode, size, offset, add_entry).map(|r| {
            rec.mark_success(0);
            r
        })
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
        let mut rec = FopRecorder::settle(Readdirplus, ino, &self.ios);
        self.do_readdir(ino, size, offset, |dir_entry| {
            let inode = self.sb.get_inode(dir_entry.ino, self.digest_validate)?;
            add_entry(dir_entry, self.get_inode_entry(inode))
        })
        .map(|r| {
            rec.mark_success(0);
            r
        })
    }

    fn releasedir(&self, _ctx: Context, _inode: u64, _flags: u32, _handle: u64) -> Result<()> {
        Ok(())
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> Result<()> {
        let mut rec = FopRecorder::settle(Access, ino, &self.ios);
        let st = self.get_inode_attr(ino)?;
        let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);

        if mode == libc::F_OK {
            rec.mark_success(0);
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

        rec.mark_success(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_rafs_backend() -> Box<Rafs> {
        let config = r#"
        {
            "device": {
              "backend": {
                "type": "oss",
                "config": {
                  "endpoint": "test",
                  "access_key_id": "test",
                  "access_key_secret": "test",
                  "bucket_name": "antsys-nydus",
                  "object_prefix":"nydus_v2/",
                  "scheme": "http"
                }
              }
            },
            "mode": "direct",
            "digest_validate": false,
            "enable_xattr": true,
            "fs_prefetch": {
              "enable": true,
              "threads_count": 10,
              "merging_size": 131072,
              "bandwidth_rate": 10485760
            }
          }"#;
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/image_v2.boot");
        let mountpoint = "/mnt";
        let rafs_config = RafsConfig::from_str(config).unwrap();
        let bootstrapfile = source_path.to_str().unwrap();
        let mut bootstrap = RafsIoRead::from_file(bootstrapfile).unwrap();
        let mut rafs = Rafs::new(rafs_config, mountpoint, &mut bootstrap).unwrap();
        rafs.import(bootstrap, Some(vec![std::path::PathBuf::new()]))
            .unwrap();
        Box::new(rafs)
    }

    #[test]
    fn it_should_create_new_rafs_fs() {
        let rafs = new_rafs_backend();
        let attr = rafs.get_inode_attr(1).unwrap();
        assert_eq!(attr.ino, 1);
        assert_eq!(attr.blocks, 8);
        assert_eq!(attr.uid, 0);
    }

    #[test]
    fn it_should_access() {
        let rafs = new_rafs_backend();
        let ctx = Context {
            gid: 0,
            pid: 1,
            uid: 0,
        };
        if rafs.access(ctx, 1, 0).is_err() {
            panic!("failed to access inode 1");
        }
    }

    #[test]
    fn it_should_listxattr() {
        let rafs = new_rafs_backend();
        let ctx = Context {
            gid: 0,
            pid: 1,
            uid: 0,
        };
        match rafs.listxattr(ctx, 1, 0) {
            Ok(reply) => match reply {
                ListxattrReply::Count(c) => assert_eq!(c, 0),
                _ => panic!(),
            },
            Err(_) => panic!("failed to access inode 1"),
        }
    }

    #[test]
    fn it_should_get_statfs() {
        let rafs = new_rafs_backend();
        let ctx = Context {
            gid: 0,
            pid: 1,
            uid: 0,
        };
        match rafs.statfs(ctx, 1) {
            Ok(statfs) => {
                assert_eq!(statfs.f_files, 43082);
                assert_eq!(statfs.f_bsize, 512);
                assert_eq!(statfs.f_namemax, 255);
                assert_eq!(statfs.f_fsid, 1380009555);
                assert_eq!(statfs.f_ffree, 0);
            }
            Err(_) => panic!("failed to statfs"),
        }
    }

    #[test]
    fn it_should_enable_xattr() {
        let rafs = new_rafs_backend();
        assert_eq!(rafs.xattr_supported(), true);
    }

    #[test]
    fn it_should_lookup_entry() {
        let rafs = new_rafs_backend();
        let ctx = Context {
            gid: 0,
            pid: 1,
            uid: 0,
        };
        match rafs.lookup(ctx, 1, &std::ffi::CString::new("/etc").unwrap()) {
            Err(e) => {
                println!("{:?}", e);
                panic!("failed to lookup /etc from ino 1");
            }
            Ok(e) => {
                assert_eq!(e.inode, 0);
            }
        }
    }
}

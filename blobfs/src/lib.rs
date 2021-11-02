// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fuse blob passthrough file system, mirroring an existing FS hierarchy.
//!
//! This file system mirrors the existing file system hierarchy of the system, starting at the
//! root file system. This is implemented by just "passing through" all requests to the
//! corresponding underlying file system.
//!
//! The code is derived from the
//! [CrosVM](https://chromium.googlesource.com/chromiumos/platform/crosvm/) project,
//! with heavy modification/enhancements from Alibaba Cloud OS team.

#[macro_use]
extern crate log;

use std::any::Any;
use std::collections::{btree_map, BTreeMap};
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
#[cfg(feature = "virtiofs")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
#[cfg(feature = "virtiofs")]
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockWriteGuard};
use std::time::Duration;

use serde::Deserialize;
use vm_memory::ByteValued;

use fuse_backend_rs::{
    api::{filesystem::*, BackendFileSystem, VFS_MAX_INO},
    passthrough::CachePolicy,
    // transport::FileReadWriteVolatile,
};

#[cfg(feature = "virtiofs")]
use fuse_backend_rs::abi::virtio_fs;
#[cfg(feature = "virtiofs")]
use fuse_backend_rs::transport::FsCacheReqHandler;
// #[cfg(feature = "virtiofs")]
// use rafs::metadata::cached::CachedChunkInfo;
// #[cfg(feature = "virtiofs")]
// use rafs::metadata::layout::OndiskChunkInfo;

use nydus_error::{einval, eother};

use rafs::{
    fs::{Rafs, RafsConfig},
    RafsIoRead,
};

mod sync_io;

#[allow(dead_code)]
mod multikey;
use multikey::MultikeyBTreeMap;

const CURRENT_DIR_CSTR: &[u8] = b".\0";
const PARENT_DIR_CSTR: &[u8] = b"..\0";
const EMPTY_CSTR: &[u8] = b"\0";
const PROC_CSTR: &[u8] = b"/proc\0";

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Debug, Default)]
struct InodeAltKey {
    ino: libc::ino64_t,
    dev: libc::dev_t,
}

impl InodeAltKey {
    fn from_stat(st: &libc::stat64) -> Self {
        InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        }
    }
}

struct InodeData {
    inode: Inode,
    // Most of these aren't actually files but ¯\_(ツ)_/¯.
    file: File,
    refcount: AtomicU64,
}

impl InodeData {
    fn new(inode: Inode, file: File, refcount: u64) -> Self {
        InodeData {
            inode,
            file,
            refcount: AtomicU64::new(refcount),
        }
    }

    // When making use of the underlying RawFd, the caller must ensure that the Arc<InodeData>
    // object is within scope. Otherwise it may cause race window to access wrong target fd.
    // By introducing this method, we could explicitly audit all callers making use of the
    // underlying RawFd.
    fn get_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// Data structures to manage accessed inodes.
struct InodeMap {
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
}

impl InodeMap {
    fn new() -> Self {
        InodeMap {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
        }
    }

    fn clear(&self) {
        self.inodes.write().unwrap().clear();
    }

    fn get(&self, inode: Inode) -> io::Result<Arc<InodeData>> {
        self.inodes
            .read()
            .unwrap()
            .get(&inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)
    }

    fn get_alt(&self, altkey: &InodeAltKey) -> Option<Arc<InodeData>> {
        self.inodes.read().unwrap().get_alt(altkey).map(Arc::clone)
    }

    fn get_map_mut(
        &self,
    ) -> RwLockWriteGuard<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>> {
        self.inodes.write().unwrap()
    }

    fn insert(&self, inode: Inode, altkey: InodeAltKey, data: InodeData) {
        self.inodes
            .write()
            .unwrap()
            .insert(inode, altkey, Arc::new(data));
    }
}

struct HandleData {
    inode: Inode,
    file: File,
    lock: Mutex<()>,
}

impl HandleData {
    fn new(inode: Inode, file: File) -> Self {
        HandleData {
            inode,
            file,
            lock: Mutex::new(()),
        }
    }

    fn get_file_mut(&self) -> (MutexGuard<()>, &File) {
        (self.lock.lock().unwrap(), &self.file)
    }

    // When making use of the underlying RawFd, the caller must ensure that the Arc<HandleData>
    // object is within scope. Otherwise it may cause race window to access wrong target fd.
    // By introducing this method, we could explicitly audit all callers making use of the
    // underlying RawFd.
    fn get_handle_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

struct HandleMap {
    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
}

impl HandleMap {
    fn new() -> Self {
        HandleMap {
            handles: RwLock::new(BTreeMap::new()),
        }
    }

    fn clear(&self) {
        self.handles.write().unwrap().clear();
    }

    fn insert(&self, handle: Handle, data: HandleData) {
        self.handles.write().unwrap().insert(handle, Arc::new(data));
    }

    fn release(&self, handle: Handle, inode: Inode) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle) {
            if e.get().inode == inode {
                // We don't need to close the file here because that will happen automatically when
                // the last `Arc` is dropped.
                e.remove();
                return Ok(());
            }
        }

        Err(ebadf())
    }

    fn get(&self, handle: Handle, inode: Inode) -> io::Result<Arc<HandleData>> {
        self.handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .map(Arc::clone)
            .ok_or_else(ebadf)
    }
}

// #[derive(Clone)]
// struct BlobOffsetMapArg {
//     base: *const u8,
//     size: usize,
// }

// unsafe impl Sync for BlobOffsetMapArg {}
// unsafe impl Send for BlobOffsetMapArg {}

// struct BlobOffsetMap {
//     map: RwLock<BTreeMap<OsString, Arc<BlobOffsetMapArg>>>,
// }

// impl BlobOffsetMap {
//     fn new() -> Self {
//         BlobOffsetMap {
//             map: RwLock::new(BTreeMap::new()),
//         }
//     }

//     fn get(&self, blob: &OsString) -> io::Result<Arc<BlobOffsetMapArg>> {
//         self.map
//             .read()
//             .unwrap()
//             .get(blob)
//             .map(Arc::clone)
//             .ok_or_else(|| einval!())
//     }

//     fn insert(&self, blob: OsString, arg: Arc<BlobOffsetMapArg>) {
//         self.map.write().unwrap().insert(blob, arg);
//     }

//     fn clear(&self) {
//         let mut map = self.map.write().unwrap();
//         for (_, arg) in map.iter_mut() {
//             trace!("unmap offset map ptr");
//             unsafe { libc::munmap((*arg).base as *mut u8 as *mut libc::c_void, (*arg).size) };
//         }

//         map.clear();
//     }
// }

// struct DummyZcWriter {}

// impl io::Write for DummyZcWriter {
//     fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
//         Ok(0)
//     }

//     fn flush(&mut self) -> io::Result<()> {
//         Ok(())
//     }
// }

// impl ZeroCopyWriter for DummyZcWriter {
//     fn write_from(
//         &mut self,
//         f: &mut dyn FileReadWriteVolatile,
//         mut count: usize,
//         off: u64,
//     ) -> io::Result<usize> {
//         let mut buf = Vec::with_capacity(count);
//         count = f.read_vectored_at_volatile(
//             // Safe because we have made sure buf has at least count capacity above
//             unsafe { &[VolatileSlice::new(buf.as_mut_ptr(), count)] },
//             off,
//         )?;

//         trace!("dummy zc write count {} off {}", count, off);
//         Ok(count)
//     }
// }

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct LinuxDirent64 {
    d_ino: libc::ino64_t,
    d_off: libc::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}
unsafe impl ByteValued for LinuxDirent64 {}

/// Options that configure xxx
#[derive(Clone, Default, Deserialize)]
pub struct BlobOndemandConfig {
    /// The rafs config used to set up rafs device for the purpose of
    /// `on demand read`.
    pub rafs_conf: RafsConfig,

    /// THe path of bootstrap of an container image (for rafs in
    /// kernel).
    ///
    /// The default is ``.
    #[serde(default)]
    pub bootstrap_path: String,

    /// The path of blob cache directory.
    #[serde(default)]
    pub blob_cache_dir: String,
}

impl FromStr for BlobOndemandConfig {
    type Err = io::Error;

    fn from_str(s: &str) -> io::Result<BlobOndemandConfig> {
        serde_json::from_str(s).map_err(|e| einval!(e))
    }
}

/// Options that configure the behavior of the blobfs fuse file system.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// The path of the root directory.
    ///
    /// The default is `/`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// To be compatible with Vfs and PseudoFs, BlobFs needs to prepare
    /// root inode before accepting INIT request.
    ///
    /// The default value for this option is `true`.
    pub do_import: bool,

    /// Control whether no_open is allowed.
    ///
    /// The default value for this option is `false`.
    pub no_open: bool,

    /// Control whether no_opendir is allowed.
    ///
    /// The default value for this option is `false`.
    pub no_opendir: bool,

    /// This provides on demand config of blob management.
    pub blob_ondemand_cfg: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            xattr: false,
            do_import: true,
            no_open: false,
            no_opendir: false,
            blob_ondemand_cfg: Default::default(),
        }
    }
}

struct BootstrapArgs {
    rafs: Rafs,
    // bootstrap: String,
    blob_cache_dir: String,
}

// Safe to Send/Sync because the underlying data structures are readonly
unsafe impl Sync for BootstrapArgs {}
unsafe impl Send for BootstrapArgs {}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system.
///
/// To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct BlobFs {
    // File descriptors for various points in the file system tree. These fds are always opened with
    // the `O_PATH` option so they cannot be used for reading or writing any data. See the
    // documentation of the `O_PATH` flag in `open(2)` for more details on what one can and cannot
    // do with an fd opened with this flag.
    inode_map: InodeMap,
    next_inode: AtomicU64,

    // File descriptors for open files and directories. Unlike the fds in `inodes`, these _can_ be
    // used for reading and writing data.
    handle_map: HandleMap,
    next_handle: AtomicU64,

    // File descriptor pointing to the `/proc` directory. This is used to convert an fd from
    // `inodes` into one that can go into `handles`. This is accomplished by reading the
    // `self/fd/{}` symlink. We keep an open fd here in case the file system tree that we are meant
    // to be serving doesn't have access to `/proc`.
    proc: File,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,

    // Whether no_open is enabled.
    no_open: AtomicBool,

    // Whether no_opendir is enabled.
    no_opendir: AtomicBool,

    cfg: Config,

    bootstrap_args: BootstrapArgs,
}

impl BlobFs {
    /// Create a Blob file system instance.
    pub fn new(cfg: Config) -> io::Result<BlobFs> {
        // Safe because this is a constant value and a valid C string.
        let proc_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(PROC_CSTR) };
        let proc = Self::open_file(
            libc::AT_FDCWD,
            proc_cstr,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
        .map_err(|e| einval!(e))?;

        let bootstrap_args = Self::load_bootstrap(&cfg)?;
        Ok(BlobFs {
            inode_map: InodeMap::new(),
            next_inode: AtomicU64::new(ROOT_ID + 1),

            handle_map: HandleMap::new(),
            next_handle: AtomicU64::new(1),

            proc,

            writeback: AtomicBool::new(false),
            no_open: AtomicBool::new(false),
            no_opendir: AtomicBool::new(false),
            cfg,
            bootstrap_args,
        })
    }

    fn load_bootstrap(cfg: &Config) -> io::Result<BootstrapArgs> {
        let blob_ondemand_conf = BlobOndemandConfig::from_str(&cfg.blob_ondemand_cfg)?;
        // check if blob cache dir exists.
        let path = Path::new(blob_ondemand_conf.blob_cache_dir.as_str());
        if !path.exists() || blob_ondemand_conf.blob_cache_dir == String::default() {
            return Err(einval!("no valid blob cache dir"));
        }

        // mmap bootstrap into current process
        let path = Path::new(blob_ondemand_conf.bootstrap_path.as_str());
        if !path.exists() || blob_ondemand_conf.bootstrap_path == String::default() {
            return Err(einval!("no valid bootstrap"));
        }

        let mut rafs_conf = blob_ondemand_conf.rafs_conf.clone();
        // we must use direct mode to get mmap'd bootstrap.
        rafs_conf.mode = "direct".to_string();
        let mut bootstrap =
            <dyn RafsIoRead>::from_file(path.to_str().unwrap()).map_err(|e| eother!(e))?;
        let mut rafs = Rafs::new(rafs_conf, "blobfs", &mut bootstrap)
            .map_err(|e| eother!(format!("blobfs: new rafs failed {:?}", e)))?;
        rafs.import(bootstrap, None)
            .map_err(|e| eother!(format!("blobfs: rafs import failed {:?}", e)))?;

        Ok(BootstrapArgs {
            rafs,
            // bootstrap: blob_ondemand_conf.bootstrap_path.clone(),
            blob_cache_dir: blob_ondemand_conf.blob_cache_dir,
        })
    }

    /// Initialize the Blob file system.
    pub fn import(&self) -> io::Result<()> {
        let root = CString::new(self.cfg.root_dir.as_str()).expect("CString::new failed");
        // We use `O_PATH` because we just want this for traversing the directory tree
        // and not for actually reading the contents.
        let f = Self::open_file(
            libc::AT_FDCWD,
            &root,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;

        let st = Self::stat(&f)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        self.inode_map.insert(
            ROOT_ID,
            InodeAltKey::from_stat(&st),
            InodeData::new(ROOT_ID, f, 2),
        );

        Ok(())
    }

    /// Get the list of file descriptors which should be reserved across live upgrade.
    pub fn keep_fds(&self) -> Vec<RawFd> {
        vec![self.proc.as_raw_fd()]
    }

    fn stat(f: &File) -> io::Result<libc::stat64> {
        // Safe because this is a constant value and a valid C string.
        let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
        let mut st = MaybeUninit::<libc::stat64>::zeroed();

        // Safe because the kernel will only write data in `st` and we check the return value.
        let res = unsafe {
            libc::fstatat64(
                f.as_raw_fd(),
                pathname.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if res >= 0 {
            // Safe because the kernel guarantees that the struct is now fully initialized.
            Ok(unsafe { st.assume_init() })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(feature = "virtiofs")]
    fn readlinkat(dfd: i32, pathname: &CStr) -> io::Result<PathBuf> {
        let mut buf = Vec::with_capacity(256);

        loop {
            let buf_read = unsafe {
                libc::readlinkat(
                    dfd,
                    pathname.as_ptr(),
                    buf.as_mut_ptr() as *mut _,
                    buf.capacity(),
                )
            };
            if buf_read < 0 {
                return Err(io::Error::last_os_error());
            }

            unsafe {
                buf.set_len(buf_read as usize);
            }

            if buf_read as usize != buf.capacity() {
                buf.shrink_to_fit();

                return Ok(PathBuf::from(OsString::from_vec(buf)));
            }

            // Trigger the internal buffer resizing logic of `Vec` by requiring
            // more space than the current capacity. The length is guaranteed to be
            // the same as the capacity due to the if statement above.
            buf.reserve(1);
        }
    }

    fn open_file(dfd: i32, pathname: &CStr, flags: i32, mode: u32) -> io::Result<File> {
        let fd = if flags & libc::O_CREAT == libc::O_CREAT {
            unsafe { libc::openat(dfd, pathname.as_ptr(), flags, mode) }
        } else {
            unsafe { libc::openat(dfd, pathname.as_ptr(), flags) }
        };

        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let p = self.inode_map.get(parent)?;
        let f = Self::open_file(
            p.get_raw_fd(),
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let st = Self::stat(&f)?;
        let altkey = InodeAltKey::from_stat(&st);

        let mut found = None;
        'search: loop {
            match self.inode_map.get_alt(&altkey) {
                // No existing entry found
                None => break 'search,
                Some(data) => {
                    let curr = data.refcount.load(Ordering::Acquire);
                    // forgot_one() has just destroyed the entry, retry...
                    if curr == 0 {
                        continue 'search;
                    }

                    // Saturating add to avoid integer overflow, it's not realistic to saturate u64.
                    let new = curr.saturating_add(1);

                    // Synchronizes with the forgot_one()
                    if data
                        .refcount
                        .compare_exchange(curr, new, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        found = Some(data.inode);
                        break;
                    }
                }
            }
        }

        let inode = if let Some(v) = found {
            v
        } else {
            let mut inodes = self.inode_map.get_map_mut();

            // Lookup inode_map again after acquiring the inode_map lock, as there might be another
            // racing thread already added an inode with the same altkey while we're not holding
            // the lock. If so just use the newly added inode, otherwise the inode will be replaced
            // and results in EBADF.
            match inodes.get_alt(&altkey).map(Arc::clone) {
                Some(data) => {
                    trace!(
                        "fuse: do_lookup sees existing inode {} altkey {:?}",
                        data.inode,
                        altkey
                    );
                    data.refcount.fetch_add(1, Ordering::Relaxed);
                    data.inode
                }
                None => {
                    let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
                    if inode > VFS_MAX_INO {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("max inode number reached: {}", VFS_MAX_INO),
                        ));
                    }
                    trace!(
                        "fuse: do_lookup adds new inode {} altkey {:?}",
                        inode,
                        altkey
                    );
                    inodes.insert(inode, altkey, Arc::new(InodeData::new(inode, f, 1)));
                    inode
                }
            }
        };

        Ok(Entry {
            inode,
            generation: 0,
            attr: st,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    fn forget_one(
        inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
        inode: Inode,
        count: u64,
    ) {
        // ROOT_ID should not be forgotten, or we're not able to access to files any more.
        if inode == ROOT_ID {
            return;
        }

        if let Some(data) = inodes.get(&inode) {
            // Acquiring the write lock on the inode map prevents new lookups from incrementing the
            // refcount but there is the possibility that a previous lookup already acquired a
            // reference to the inode data and is in the process of updating the refcount so we need
            // to loop here until we can decrement successfully.
            loop {
                let curr = data.refcount.load(Ordering::Acquire);

                // Saturating sub because it doesn't make sense for a refcount to go below zero and
                // we don't want misbehaving clients to cause integer overflow.
                let new = curr.saturating_sub(count);

                trace!(
                    "fuse: forget inode {} refcount {}, count {}, new_count {}",
                    inode,
                    curr,
                    count,
                    new
                );

                // Synchronizes with the acquire load in `do_lookup`.
                if data
                    .refcount
                    .compare_exchange(curr, new, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    if new == 0 {
                        // We just removed the last refcount for this inode.
                        inodes.remove(&inode);
                    }
                    break;
                }
            }
        }
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        self.handle_map.release(handle, inode)
    }
}

impl BackendFileSystem for BlobFs {
    fn mount(&self) -> io::Result<(Entry, u64)> {
        let entry = self.do_lookup(ROOT_ID, &CString::new(".").unwrap())?;
        Ok((entry, VFS_MAX_INO))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

#[cfg(test)]
#[cfg(feature = "virtiofs")]
mod tests {
    use super::*;
    use nydus_app::setup_logging;

    struct DummyCacheReq {}

    impl FsCacheReqHandler for DummyCacheReq {
        fn map(
            &mut self,
            _foffset: u64,
            _moffset: u64,
            _len: u64,
            _flags: u64,
            _fd: RawFd,
        ) -> io::Result<()> {
            Ok(())
        }

        fn unmap(&mut self, _requests: Vec<virtio_fs::RemovemappingOne>) -> io::Result<()> {
            Ok(())
        }
    }

    // #[test]
    // #[cfg(feature = "virtiofs")]
    // fn test_blobfs_new() {
    //     setup_logging(None, log::LevelFilter::Trace).unwrap();
    //     let config = r#"
    //     {
    //         "device": {
    //           "backend": {
    //             "type": "localfs",
    //             "config": {
    //               "dir": "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1/test4k"
    //             }
    //           },
    //           "cache": {
    //             "type": "blobcache",
    //             "compressed": false,
    //             "config": {
    //               "work_dir": "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1/blobcache"
    //             }
    //           }
    //         },
    //         "mode": "direct",
    //         "digest_validate": true,
    //         "enable_xattr": false,
    //         "fs_prefetch": {
    //           "enable": false,
    //           "threads_count": 10,
    //           "merging_size": 131072,
    //           "bandwidth_rate": 10485760
    //         }
    //       }"#;
    //     //        let rafs_conf = RafsConfig::from_str(config).unwrap();

    //     let fs_cfg = Config {
    //         root_dir: "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1"
    //             .to_string(),
    //         bootstrap_path: "test4k/bootstrap-link".to_string(),
    //         //            blob_cache_dir: "blobcache".to_string(),
    //         do_import: false,
    //         no_open: true,
    //         rafs_conf: config.to_string(),
    //         ..Default::default()
    //     };

    //     assert!(BlobFs::new(fs_cfg).is_err());

    //     let fs_cfg = Config {
    //         root_dir: "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1"
    //             .to_string(),
    //         bootstrap_path: "test4k/bootstrap-link".to_string(),
    //         blob_cache_dir: "blobcache1".to_string(),
    //         do_import: false,
    //         no_open: true,
    //         rafs_conf: config.to_string(),
    //         ..Default::default()
    //     };

    //     assert!(BlobFs::new(fs_cfg).is_err());

    //     let fs_cfg = Config {
    //         root_dir: "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1"
    //             .to_string(),
    //         //            bootstrap_path: "test4k/bootstrap-link".to_string(),
    //         blob_cache_dir: "blobcache".to_string(),
    //         do_import: false,
    //         no_open: true,
    //         rafs_conf: config.to_string(),
    //         ..Default::default()
    //     };

    //     assert!(BlobFs::new(fs_cfg).is_err());

    //     let fs_cfg = Config {
    //         root_dir: "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1"
    //             .to_string(),
    //         bootstrap_path: "test4k/bootstrap-foo".to_string(),
    //         blob_cache_dir: "blobcache".to_string(),
    //         do_import: false,
    //         no_open: true,
    //         rafs_conf: config.to_string(),
    //         ..Default::default()
    //     };

    //     assert!(BlobFs::new(fs_cfg).is_err());

    //     let fs_cfg = Config {
    //         root_dir: "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1"
    //             .to_string(),
    //         bootstrap_path: "test4k/bootstrap-link".to_string(),
    //         blob_cache_dir: "blobcache".to_string(),
    //         do_import: false,
    //         no_open: true,
    //         rafs_conf: config.to_string(),
    //         ..Default::default()
    //     };

    //     assert!(BlobFs::new(fs_cfg).is_ok());
    // }

    #[test]
    fn test_blobfs_setupmapping() {
        setup_logging(None, log::LevelFilter::Trace).unwrap();
        let config = r#"
{
        "rafs_conf": {
            "device": {
              "backend": {
                "type": "localfs",
                "config": {
                  "blob_file": "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1/nydus-rs/myblob1/v6/blob-btrfs"
                }
              },
              "cache": {
                "type": "blobcache",
                "compressed": false,
                "config": {
                  "work_dir": "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1/blobcache"
                }
              }
            },
            "mode": "direct",
            "digest_validate": false,
            "enable_xattr": false,
            "fs_prefetch": {
              "enable": false,
              "threads_count": 10,
              "merging_size": 131072,
              "bandwidth_rate": 10485760
            }
          },
     "bootstrap_path": "nydus-rs/myblob1/v6/bootstrap-btrfs",
     "blob_cache_dir": "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1/blobcache"
}"#;
        //        let rafs_conf = RafsConfig::from_str(config).unwrap();

        let fs_cfg = Config {
            root_dir: "/home/b.liu/1_source/3_ali/virtiofs/qemu-my/build-kangaroo/share_dir1"
                .to_string(),
            do_import: false,
            no_open: true,
            blob_ondemand_cfg: config.to_string(),
            ..Default::default()
        };

        let fs = BlobFs::new(fs_cfg).unwrap();
        fs.import().unwrap();

        fs.mount().unwrap();

        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };

        // read bootstrap first, should return err as it's not in blobcache dir.
        // let bootstrap = CString::new("foo").unwrap();
        // let entry = fs.lookup(ctx, ROOT_ID, &bootstrap).unwrap();
        // let mut req = DummyCacheReq {};
        // fs.setupmapping(ctx, entry.inode, 0, 0, 4096, 0, 0, &mut req)
        //     .unwrap();

        // FIXME: use a real blob id under test4k.
        let blob_cache_dir = CString::new("blobcache").unwrap();
        let parent_entry = fs.lookup(&ctx, ROOT_ID, &blob_cache_dir).unwrap();

        let blob_id = CString::new("80da976ee69d68af6bb9170395f71b4ef1e235e815e2").unwrap();
        let entry = fs.lookup(&ctx, parent_entry.inode, &blob_id).unwrap();

        let foffset = 0;
        let len = 1 << 21;
        let mut req = DummyCacheReq {};
        fs.setupmapping(&ctx, entry.inode, 0, foffset, len, 0, 0, &mut req)
            .unwrap();

        // FIXME: release fs
        fs.destroy();
    }
}

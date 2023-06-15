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

use std::any::Any;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{create_dir_all, File};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use fuse_backend_rs::api::{filesystem::*, BackendFileSystem, VFS_MAX_INO};
use fuse_backend_rs::{passthrough::Config as PassthroughConfig, passthrough::PassthroughFs};
use nix::NixPath;
use nydus_api::{einval, ConfigV2};
use nydus_storage::device::BlobPrefetchRequest;
use serde::Deserialize;

use crate::fs::Rafs;
use crate::metadata::Inode;
use crate::RafsError;

mod sync_io;

const EMPTY_CSTR: &[u8] = b"\0";

/// Configuration information for blobfs instance.
#[derive(Clone, Default, Deserialize)]
pub struct BlobOndemandConfig {
    /// RAFS filesystem configuration to configure backend, cache and fuse.
    /// The rafs config used to set up rafs device for the purpose of `on demand read`.
    pub rafs_conf: ConfigV2,

    /// Meta blob file path for a RAFS filesystem.
    #[serde(default)]
    pub bootstrap_path: String,

    /// Blob cache directory path.
    #[serde(default)]
    pub blob_cache_dir: String,
}

impl FromStr for BlobOndemandConfig {
    type Err = io::Error;

    fn from_str(s: &str) -> io::Result<BlobOndemandConfig> {
        serde_json::from_str(s).map_err(|e| {
            einval!(format!(
                "blobfs: failed to load blobfs configuration, {}",
                e
            ))
        })
    }
}

/// Options that configure the behavior of the blobfs fuse file system.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Config {
    /// Blobfs config is embedded with passthrough config
    pub ps_config: PassthroughConfig,
    /// This provides on demand config of blob management.
    pub blob_ondemand_cfg: String,
}

struct RafsHandle {
    rafs: Option<Rafs>,
    thread: Option<thread::JoinHandle<Result<Rafs, RafsError>>>,
}

struct BlobfsState {
    #[allow(unused)]
    blob_cache_dir: String,
    rafs_handle: RwLock<RafsHandle>,
    inode_map: Mutex<HashMap<Inode, (u64, String)>>,
}

impl BlobfsState {
    fn get_rafs_handle(&self) -> io::Result<()> {
        let mut rafs_handle = self.rafs_handle.write().unwrap();

        if let Some(handle) = rafs_handle.thread.take() {
            match handle.join() {
                Ok(v) => match v {
                    Ok(rafs) => rafs_handle.rafs = Some(rafs),
                    Err(e) => {
                        return Err(eio!(format!(
                            "blobfs: failed to get RAFS filesystem handle, {}",
                            e
                        )))
                    }
                },
                Err(e) => {
                    return Err(eio!(format!(
                        "blobfs: failed to get RAFS filesystem handle, {:?}",
                        e
                    )))
                }
            }
        }

        if rafs_handle.rafs.is_none() {
            Err(eio!("blobfs: failed to get RAFS filesystem handle"))
        } else {
            Ok(())
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system.
///
/// To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct BlobFs {
    state: BlobfsState,
    pfs: PassthroughFs,
}

impl BlobFs {
    /// Create a Blob file system instance.
    pub fn new(cfg: Config) -> io::Result<BlobFs> {
        let bootstrap_args = Self::load_bootstrap(&cfg)?;
        let pfs = PassthroughFs::new(cfg.ps_config)?;

        Ok(BlobFs {
            pfs,
            state: bootstrap_args,
        })
    }

    /// Initialize the blobfs instance.
    pub fn import(&self) -> io::Result<()> {
        self.pfs.import()
    }

    fn ensure_path_exist(path: &Path) -> io::Result<()> {
        if path.is_empty() {
            return Err(einval!("blobfs: path is empty"));
        }
        if !path.exists() {
            create_dir_all(path).map_err(|e| {
                error!("blobfs: failed to create dir {}, {}", path.display(), e);
                e
            })?;
        }

        Ok(())
    }

    fn load_bootstrap(cfg: &Config) -> io::Result<BlobfsState> {
        let blob_ondemand_conf = BlobOndemandConfig::from_str(&cfg.blob_ondemand_cfg)?;
        if !blob_ondemand_conf.rafs_conf.validate() {
            return Err(einval!("blobfs: invlidate configuration for blobfs"));
        }
        let rafs_cfg = blob_ondemand_conf.rafs_conf.get_rafs_config()?;
        if rafs_cfg.mode != "direct" {
            return Err(einval!("blobfs: only 'direct' mode is supported"));
        }

        // check if blob cache dir exists.
        let path = Path::new(blob_ondemand_conf.blob_cache_dir.as_str());
        Self::ensure_path_exist(path)?;

        let path = Path::new(blob_ondemand_conf.bootstrap_path.as_str());
        if blob_ondemand_conf.bootstrap_path.is_empty() || !path.is_file() {
            return Err(einval!(format!(
                "blobfs: bootstrap file {} is invalid",
                path.display()
            )));
        }

        let bootstrap_path = blob_ondemand_conf.bootstrap_path.clone();
        let config = Arc::new(blob_ondemand_conf.rafs_conf.clone());

        trace!("blobfs: async create Rafs start!");
        let rafs_join_handle = std::thread::spawn(move || {
            let (mut rafs, reader) = Rafs::new(&config, "blobfs", Path::new(&bootstrap_path))?;
            rafs.import(reader, None)?;
            Ok(rafs)
        });

        let rafs_handle = RafsHandle {
            rafs: None,
            thread: Some(rafs_join_handle),
        };

        Ok(BlobfsState {
            blob_cache_dir: blob_ondemand_conf.blob_cache_dir.clone(),
            rafs_handle: RwLock::new(rafs_handle),
            inode_map: Mutex::new(HashMap::new()),
        })
    }

    fn get_blob_id_and_size(&self, inode: Inode) -> io::Result<(String, u64)> {
        let mut map = self.state.inode_map.lock().unwrap();
        match map.entry(inode) {
            std::collections::hash_map::Entry::Occupied(v) => {
                let (sz, blob_id) = v.get();
                Ok((blob_id.to_string(), *sz))
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                // locate blob file that the inode refers to
                let blob_id_full_path = self.pfs.readlinkat_proc_file(inode)?;
                let blob_file = Self::open_file(
                    libc::AT_FDCWD,
                    blob_id_full_path.as_path(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
                .map_err(|e| einval!(e))?;
                let st = Self::stat(&blob_file).map_err(|e| {
                    error!("get_blob_id_and_size: stat failed {:?}", e);
                    e
                })?;
                if st.st_size < 0 {
                    return Err(einval!(format!(
                        "load_chunks_on_demand: blob_id {:?}, size: {:?} is less than 0",
                        blob_id_full_path.display(),
                        st.st_size
                    )));
                }

                let blob_id = blob_id_full_path
                    .file_name()
                    .ok_or_else(|| einval!("blobfs: failed to find blob file"))?;
                let blob_id = blob_id
                    .to_os_string()
                    .into_string()
                    .map_err(|_e| einval!("blobfs: failed to get blob id from file name"))?;
                trace!("load_chunks_on_demand: blob_id {}", blob_id);
                entry.insert((st.st_size as u64, blob_id.clone()));

                Ok((blob_id, st.st_size as u64))
            }
        }
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

    fn open_file(dfd: i32, pathname: &Path, flags: i32, mode: u32) -> io::Result<File> {
        let pathname = CString::new(pathname.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
}

impl BackendFileSystem for BlobFs {
    fn mount(&self) -> io::Result<(Entry, u64)> {
        let ctx = &Context::default();
        let name = CString::new(".").unwrap();
        let entry = self.lookup(ctx, ROOT_ID, name.as_c_str())?;

        Ok((entry, VFS_MAX_INO))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::{RafsMode, RafsSuper};
    use crate::{RafsIoRead, RafsIoReader, RafsIoWrite, RafsIterator};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_rafs_io_writer() {
        let mut file = TempFile::new().unwrap().into_file();

        assert!(file.validate_alignment(2, 8).is_err());
        assert!(file.validate_alignment(7, 8).is_err());
        assert!(file.validate_alignment(9, 8).is_err());
        assert!(file.validate_alignment(8, 8).is_ok());

        file.write_all(&[0x0u8; 7]).unwrap();
        assert!(file.validate_alignment(8, 8).is_err());
        {
            let obj: &mut dyn RafsIoWrite = &mut file;
            obj.write_padding(1).unwrap();
        }
        assert!(file.validate_alignment(8, 8).is_ok());
        file.write_all(&[0x0u8; 1]).unwrap();
        assert!(file.validate_alignment(8, 8).is_err());

        let obj: &mut dyn RafsIoRead = &mut file;
        assert_eq!(obj.seek_to_offset(0).unwrap(), 0);
        assert_eq!(obj.seek_plus_offset(7).unwrap(), 7);
        assert_eq!(obj.seek_to_next_aligned(7, 8).unwrap(), 8);
        assert_eq!(obj.seek_plus_offset(7).unwrap(), 15);
    }

    #[test]
    fn test_rafs_iterator() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/bootstrap/rafs-v5.boot");
        let bootstrap = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&path)
            .unwrap();
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: false,
            ..Default::default()
        };
        rs.load(&mut (Box::new(bootstrap) as RafsIoReader)).unwrap();
        let iter = RafsIterator::new(&rs);

        let mut last = false;
        for (idx, (_node, path)) in iter.enumerate() {
            assert!(!last);
            if idx == 1 {
                assert_eq!(path, PathBuf::from("/bin"));
            } else if idx == 2 {
                assert_eq!(path, PathBuf::from("/boot"));
            } else if idx == 3 {
                assert_eq!(path, PathBuf::from("/dev"));
            } else if idx == 10 {
                assert_eq!(path, PathBuf::from("/etc/DIR_COLORS.256color"));
            } else if idx == 11 {
                assert_eq!(path, PathBuf::from("/etc/DIR_COLORS.lightbgcolor"));
            } else if path == PathBuf::from("/var/yp") {
                last = true;
            }
        }
        assert!(last);
    }
}

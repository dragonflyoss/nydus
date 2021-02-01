// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nix::sys::stat::{dev_t, makedev, mknod, Mode, SFlag};
use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result, Write};
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

use nydus_utils::exec;

const NYDUS_IMAGE: &str = "./target-fusedev/debug/nydus-image";

pub struct Builder<'a> {
    work_dir: &'a PathBuf,
    whiteout_spec: &'a str,
}

pub fn new<'a>(work_dir: &'a PathBuf, whiteout_spec: &'a str) -> Builder<'a> {
    Builder {
        work_dir,
        whiteout_spec,
    }
}

impl<'a> Builder<'a> {
    fn create_dir(&mut self, path: &PathBuf) -> Result<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    fn create_file(&mut self, path: &PathBuf, data: &[u8]) -> Result<()> {
        File::create(path)?.write_all(data)?;
        Ok(())
    }

    fn copy_file(&mut self, src: &PathBuf, dst: &PathBuf) -> Result<u64> {
        fs::copy(src, dst)
    }

    fn create_symlink(&mut self, src: &PathBuf, dst: &PathBuf) -> Result<()> {
        unix_fs::symlink(src, dst)?;
        Ok(())
    }

    fn create_hardlink(&mut self, src: &PathBuf, dst: &PathBuf) -> Result<()> {
        fs::hard_link(src, dst)?;
        Ok(())
    }

    fn create_large_file(&mut self, path: &PathBuf, size_in_mb: u8) -> Result<()> {
        let mut file = File::create(path)?;

        for i in 1..size_in_mb + 1 {
            // Write 1MB data
            file.write_all(&vec![i; 1024 * 1024])?;
        }

        Ok(())
    }

    fn create_whiteout_file(&mut self, path: &PathBuf) -> Result<()> {
        match self.whiteout_spec {
            "overlayfs" => {
                let dev: dev_t = makedev(0, 0);
                if let Err(nix::Error::Sys(errno)) = mknod(
                    path.to_str().unwrap(),
                    SFlag::S_IFCHR,
                    Mode::S_IRUSR | Mode::S_IWUSR,
                    dev,
                ) {
                    println!("mknod failed: {} {:?}", errno.desc(), path);
                    return Err(errno.into());
                }
            }
            "oci" => {
                let file_name = PathBuf::from(format!(
                    ".wh.{}",
                    path.file_name().unwrap().to_str().unwrap()
                ));
                self.create_file(&path.parent().unwrap().join(file_name), b"")?;
            }
            _ => {
                return Err(Error::new(ErrorKind::InvalidInput, "invalid whiteout spec"));
            }
        }

        Ok(())
    }

    fn create_opaque_entry(&mut self, path: &PathBuf) -> Result<()> {
        match self.whiteout_spec {
            "overlayfs" => {
                self.set_xattr(path, "trusted.overlay.opaque", "y".as_bytes())?;
            }
            "oci" => {
                self.create_file(&path.join(".wh..wh..opq"), b"")?;
            }
            _ => {
                return Err(Error::new(ErrorKind::InvalidInput, "invalid whiteout spec"));
            }
        }

        Ok(())
    }

    fn create_special_file(&mut self, path: &PathBuf, devtype: &str) -> Result<()> {
        let dev: dev_t = makedev(255, 0);
        let kind = match devtype {
            "char" => SFlag::S_IFCHR,
            "block" => SFlag::S_IFBLK,
            "fifo" => SFlag::S_IFIFO,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "invalid special file type",
                ))
            }
        };
        if let Err(nix::Error::Sys(errno)) = mknod(
            path.to_str().unwrap(),
            kind,
            Mode::S_IRUSR | Mode::S_IWUSR,
            dev,
        ) {
            println!("create_special_file failed: {} {:?}", errno.desc(), path);
            return Err(errno.into());
        }

        Ok(())
    }

    fn set_xattr(&mut self, path: &PathBuf, key: &str, value: &[u8]) -> Result<()> {
        xattr::set(path, key, value)?;
        Ok(())
    }

    pub fn make_lower(&mut self) -> Result<()> {
        let dir = self.work_dir.join("lower");
        self.create_dir(&dir)?;

        self.create_file(&dir.join("root-1"), b"lower:root-1")?;
        self.create_file(&dir.join("root-2"), b"lower:root-2")?;
        self.create_large_file(&dir.join("root-large"), 13)?;
        self.copy_file(&dir.join("root-large"), &dir.join("root-large-copy"))?;

        self.create_dir(&dir.join("sub"))?;
        self.create_file(&dir.join("sub/sub-1"), b"lower:sub-1")?;
        self.create_file(&dir.join("sub/sub-2"), b"lower:sub-2")?;
        self.create_hardlink(
            &dir.join("root-large"),
            &dir.join("sub/sub-root-large-hardlink"),
        )?;
        self.create_hardlink(
            &dir.join("root-large-copy"),
            &dir.join("sub/sub-root-large-copy-hardlink"),
        )?;
        self.create_hardlink(
            &dir.join("root-large-copy"),
            &dir.join("sub/sub-root-large-copy-hardlink-1"),
        )?;
        self.create_symlink(
            &Path::new("../root-large").to_path_buf(),
            &dir.join("sub/sub-root-large-symlink"),
        )?;

        self.create_dir(&dir.join("sub/some"))?;
        self.create_file(&dir.join("sub/some/some-1"), b"lower:some-1")?;

        self.create_dir(&dir.join("sub/more"))?;
        self.create_file(&dir.join("sub/more/more-1"), b"lower:more-1")?;
        self.create_dir(&dir.join("sub/more/more-sub"))?;
        self.create_file(
            &dir.join("sub/more/more-sub/more-sub-1"),
            b"lower:more-sub-1",
        )?;

        let long_name = &"test-😉-name.".repeat(100)[..255];
        self.create_file(&dir.join(long_name), b"lower:long-name")?;

        self.set_xattr(
            &dir.join("sub/sub-1"),
            "user.key-foo",
            "value-foo".as_bytes(),
        )?;

        self.set_xattr(
            &dir.join("sub/sub-1"),
            "user.key-bar",
            "value-bar".as_bytes(),
        )?;

        Ok(())
    }

    pub fn make_upper(&mut self) -> Result<()> {
        let dir = self.work_dir.join("upper");
        self.create_dir(&dir)?;

        self.create_whiteout_file(&dir.join("root-large"))?;
        self.create_whiteout_file(&dir.join("root-2"))?;

        self.create_dir(&dir.join("sub"))?;
        self.create_file(&dir.join("sub/sub-1"), b"upper:sub-1")?;
        self.create_whiteout_file(&dir.join("sub/some"))?;
        self.create_whiteout_file(&dir.join("sub/sub-2"))?;
        self.create_whiteout_file(&dir.join("sub/sub-root-large-copy-hardlink-1"))?;

        self.create_dir(&dir.join("sub/more"))?;
        self.create_file(&dir.join("sub/more/more-1"), b"upper:more-1")?;
        self.create_opaque_entry(&dir.join("sub/more"))?;
        self.create_dir(&dir.join("sub/more/more-sub"))?;
        self.create_file(
            &dir.join("sub/more/more-sub/more-sub-2"),
            b"upper:more-sub-2",
        )?;

        Ok(())
    }

    pub fn build_lower(&mut self, compressor: &str) -> Result<()> {
        let lower_dir = self.work_dir.join("lower");

        self.create_dir(&self.work_dir.join("blobs"))?;

        exec(
            format!(
                "{:?} create --bootstrap {:?} --backend-type localfs --backend-config '{{\"dir\": {:?}}}' --log-level info --compressor {} --whiteout-spec {} {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                lower_dir,
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }

    pub fn build_upper(&mut self, compressor: &str) -> Result<()> {
        let upper_dir = self.work_dir.join("upper").to_path_buf();

        exec(
            format!(
                "{:?} create --parent-bootstrap {:?} --bootstrap {:?} --backend-type localfs --backend-config '{{\"dir\": {:?}}}' --log-level info --compressor {} --whiteout-spec {} {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("bootstrap-overlay"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                upper_dir,
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }

    pub fn build_stargz_lower(&mut self) -> Result<()> {
        exec(
            format!(
                "{:?} create --source-type stargz_index --bootstrap {:?} --blob-id {} --log-level info {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-lower"),
                "lower.stargz",
                self.work_dir.join("stargz.index-lower.json"),
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }

    pub fn build_stargz_upper(&mut self) -> Result<()> {
        exec(
            format!(
                "{:?} create --source-type stargz_index --parent-bootstrap {:?} --bootstrap {:?} --blob-id {} --log-level info {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("bootstrap-overlay"),
                "upper.stargz",
                self.work_dir.join("stargz.index-upper.json"),
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }

    pub fn build_special_files(&mut self) -> Result<()> {
        let dir = self.work_dir.join("special_files");
        self.create_dir(&dir)?;
        self.create_dir(&self.work_dir.join("blobs"))?;

        self.create_special_file(&dir.join("block-file"), "block")?;
        self.create_special_file(&dir.join("char-file"), "char")?;
        self.create_special_file(&dir.join("fifo-file"), "fifo")?;
        self.create_file(&dir.join("normal-file"), b"")?;
        self.create_dir(&dir.join("dir"))?;

        exec(
            format!(
                "{:?} create --bootstrap {:?} --backend-type localfs --backend-config '{{\"dir\": {:?}}}' --log-level info --compressor {} --whiteout-spec {} {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-specialfiles"),
                self.work_dir.join("blobs"),
                "lz4_block",
                self.whiteout_spec,
                dir,
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }
}

// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{Result, Write};
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

use nydus_utils::exec;

const NYDUS_IMAGE: &str = "./target-fusedev/release/nydus-image";

pub struct Builder<'a> {
    work_dir: &'a PathBuf,
}

pub fn new<'a>(work_dir: &'a PathBuf) -> Builder<'a> {
    Builder { work_dir }
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

        self.create_large_file(&dir.join("root-large"), 13)?;
        self.create_file(&dir.join(".wh.root-large"), b"")?;
        self.create_file(&dir.join("root-2"), b"upper:root-2")?;
        self.create_file(&dir.join(".wh.root-2"), b"")?;

        self.create_dir(&dir.join("sub"))?;
        self.create_file(&dir.join("sub/sub-1"), b"upper:sub-1")?;
        self.create_file(&dir.join("sub/.wh.some"), b"")?;
        self.create_file(&dir.join("sub/.wh.sub-2"), b"")?;
        self.create_file(&dir.join("sub/.wh.sub-root-large-copy-hardlink-1"), b"")?;

        self.create_dir(&dir.join("sub/more"))?;
        self.create_file(&dir.join("sub/more/more-1"), b"upper:more-1")?;
        self.create_file(&dir.join("sub/more/.wh..wh..opq"), b"")?;
        self.create_dir(&dir.join("sub/more/more-sub"))?;
        self.create_file(
            &dir.join("sub/more/more-sub/more-sub-2"),
            b"upper:more-sub-2",
        )?;

        self.create_dir(&dir.join("sub/some"))?;
        self.create_dir(&dir.join("sub/some/some-sub"))?;
        self.create_file(
            &dir.join("sub/some/some-sub/some-sub-1"),
            b"upper:some-sub-1",
        )?;

        Ok(())
    }

    pub fn build_lower(&mut self, compressor: &str) -> Result<()> {
        let lower_dir = self.work_dir.join("lower");

        self.create_dir(&self.work_dir.join("blobs"))?;

        exec(
            format!(
                "{:?} create --bootstrap {:?} --backend-type localfs --backend-config '{{\"dir\": {:?}}}' --log-level info --compressor {} {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("blobs"),
                compressor,
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
                "{:?} create --parent-bootstrap {:?} --bootstrap {:?} --backend-type localfs --backend-config '{{\"dir\": {:?}}}' --log-level info --compressor {} {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("bootstrap-overlay"),
                self.work_dir.join("blobs"),
                compressor,
                upper_dir,
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }

    pub fn build_stargz_lower(&mut self, blob_id: &str, index_file: &str) -> Result<()> {
        let index_path = self.work_dir.join(index_file).to_path_buf();

        exec(
            format!(
                "{:?} create --source-type stargz_index --bootstrap {:?} --blob-id {} --log-level info {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-stargz-lower"),
                blob_id,
                index_path,
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }

    pub fn build_stargz_upper(&mut self, blob_id: &str, index_file: &str) -> Result<()> {
        let index_path = self.work_dir.join(index_file).to_path_buf();

        exec(
            format!(
                "{:?} create --source-type stargz_index --parent-bootstrap {:?} --bootstrap {:?} --blob-id {} --log-level info {:?}",
                NYDUS_IMAGE,
                self.work_dir.join("bootstrap-stargz-lower"),
                self.work_dir.join("bootstrap-stargz-overlay"),
                blob_id,
                index_path,
            )
            .as_str(),
            false,
        )?;

        Ok(())
    }
}

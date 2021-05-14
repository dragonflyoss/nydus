// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nix::sys::stat::{dev_t, makedev, mknod, Mode, SFlag};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

use nydus_utils::exec;

pub struct Builder<'a> {
    builder: String,
    work_dir: &'a PathBuf,
    whiteout_spec: &'a str,
}

pub fn new<'a>(work_dir: &'a PathBuf, whiteout_spec: &'a str) -> Builder<'a> {
    let builder = std::env::var("NYDUS_IMAGE").unwrap_or_else(|_| {
        String::from("./target-fusedev/x86_64-unknown-linux-musl/release/nydus-image")
    });
    Builder {
        builder,
        work_dir,
        whiteout_spec,
    }
}

impl<'a> Builder<'a> {
    fn create_dir(&mut self, path: &PathBuf) {
        fs::create_dir_all(path).unwrap();
    }

    fn create_file(&mut self, path: &PathBuf, data: &[u8]) {
        File::create(path).unwrap().write_all(data).unwrap();
    }

    fn copy_file(&mut self, src: &PathBuf, dst: &PathBuf) -> u64 {
        fs::copy(src, dst).unwrap()
    }

    fn create_symlink(&mut self, src: &PathBuf, dst: &PathBuf) {
        unix_fs::symlink(src, dst).unwrap();
    }

    fn create_hardlink(&mut self, src: &PathBuf, dst: &PathBuf) {
        fs::hard_link(src, dst).unwrap();
    }

    fn create_large_file(&mut self, path: &PathBuf, size_in_mb: u8) {
        let mut file = File::create(path).unwrap();

        for i in 1..size_in_mb + 1 {
            // Write 1MB data
            file.write_all(&[i; 1024 * 1024]).unwrap();
        }
    }

    fn create_whiteout_file(&mut self, path: &PathBuf) {
        match self.whiteout_spec {
            "overlayfs" => {
                let dev: dev_t = makedev(0, 0);
                mknod(
                    path.to_str().unwrap(),
                    SFlag::S_IFCHR,
                    Mode::S_IRUSR | Mode::S_IWUSR,
                    dev,
                )
                .expect("mknod failed");
            }
            "oci" => {
                let file_name = PathBuf::from(format!(
                    ".wh.{}",
                    path.file_name().unwrap().to_str().unwrap()
                ));
                self.create_file(&path.parent().unwrap().join(file_name), b"");
            }
            _ => {
                panic!("invalid whiteout spec");
            }
        }
    }

    fn create_opaque_entry(&mut self, path: &PathBuf) {
        match self.whiteout_spec {
            "overlayfs" => {
                self.set_xattr(path, "trusted.overlay.opaque", b"y");
            }
            "oci" => {
                self.create_file(&path.join(".wh..wh..opq"), b"");
            }
            _ => {
                panic!("invalid whiteout spec");
            }
        }
    }

    fn create_special_file(&mut self, path: &PathBuf, devtype: &str) {
        let dev: dev_t = makedev(255, 0);
        let kind = match devtype {
            "char" => SFlag::S_IFCHR,
            "block" => SFlag::S_IFBLK,
            "fifo" => SFlag::S_IFIFO,
            _ => {
                panic!("invalid special file type");
            }
        };
        mknod(
            path.to_str().unwrap(),
            kind,
            Mode::S_IRUSR | Mode::S_IWUSR,
            dev,
        )
        .expect("create_special_file failed");
    }

    fn set_xattr(&mut self, path: &PathBuf, key: &str, value: &[u8]) {
        xattr::set(path, key, value).unwrap();
    }

    pub fn make_lower(&mut self) {
        let dir = self.work_dir.join("lower");
        self.create_dir(&dir);

        self.create_file(&dir.join("root-1"), b"lower:root-1");
        self.create_file(&dir.join("root-2"), b"lower:root-2");
        self.create_large_file(&dir.join("root-large"), 13);
        self.copy_file(&dir.join("root-large"), &dir.join("root-large-copy"));

        self.create_dir(&dir.join("sub"));
        self.create_file(&dir.join("sub/sub-1"), b"lower:sub-1");
        self.create_file(&dir.join("sub/sub-2"), b"lower:sub-2");
        self.create_hardlink(
            &dir.join("root-large"),
            &dir.join("sub/sub-root-large-hardlink"),
        );
        self.create_hardlink(
            &dir.join("root-large-copy"),
            &dir.join("sub/sub-root-large-copy-hardlink"),
        );
        self.create_hardlink(
            &dir.join("root-large-copy"),
            &dir.join("sub/sub-root-large-copy-hardlink-1"),
        );
        self.create_symlink(
            &Path::new("../root-large").to_path_buf(),
            &dir.join("sub/sub-root-large-symlink"),
        );

        self.create_dir(&dir.join("sub/some"));
        self.create_file(&dir.join("sub/some/some-1"), b"lower:some-1");

        self.create_dir(&dir.join("sub/more"));
        self.create_file(&dir.join("sub/more/more-1"), b"lower:more-1");
        self.create_dir(&dir.join("sub/more/more-sub"));
        self.create_file(
            &dir.join("sub/more/more-sub/more-sub-1"),
            b"lower:more-sub-1",
        );

        let long_name = &"test-😉-name.".repeat(100)[..255];
        self.create_file(&dir.join(long_name), b"lower:long-name");

        self.set_xattr(&dir.join("sub/sub-1"), "user.key-foo", b"value-foo");

        self.set_xattr(&dir.join("sub/sub-1"), "user.key-bar", b"value-bar");
    }

    pub fn make_upper(&mut self) {
        let dir = self.work_dir.join("upper");
        self.create_dir(&dir);

        self.create_whiteout_file(&dir.join("root-large"));
        self.create_whiteout_file(&dir.join("root-2"));

        self.create_dir(&dir.join("sub"));
        self.create_file(&dir.join("sub/sub-1"), b"upper:sub-1");
        self.create_whiteout_file(&dir.join("sub/some"));
        self.create_whiteout_file(&dir.join("sub/sub-2"));
        self.create_whiteout_file(&dir.join("sub/sub-root-large-copy-hardlink-1"));

        self.create_dir(&dir.join("sub/more"));
        self.create_file(&dir.join("sub/more/more-1"), b"upper:more-1");
        self.create_opaque_entry(&dir.join("sub/more"));
        self.create_dir(&dir.join("sub/more/more-sub"));
        self.create_file(
            &dir.join("sub/more/more-sub/more-sub-2"),
            b"upper:more-sub-2",
        );
    }

    pub fn build_lower(&mut self, compressor: &str) {
        let lower_dir = self.work_dir.join("lower");

        self.create_dir(&self.work_dir.join("blobs"));

        exec(
            format!(
                "{:?} create --bootstrap {:?} --blob-dir {:?} --log-level info --compressor {} --whiteout-spec {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                lower_dir,
            )
            .as_str(),
            false,
        ).unwrap();
    }

    pub fn build_upper(&mut self, compressor: &str) {
        let upper_dir = self.work_dir.join("upper");

        exec(
            format!(
                "{:?} create --parent-bootstrap {:?} --bootstrap {:?} --blob-dir {:?} --log-level info --compressor {} --whiteout-spec {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("bootstrap-overlay"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                upper_dir,
            )
            .as_str(),
            false,
        ).unwrap();
    }

    pub fn build_stargz_lower(&mut self) {
        exec(
            format!(
                "{:?} create --source-type stargz_index --bootstrap {:?} --blob-id {} --log-level info {:?}",
                self.builder,
                self.work_dir.join("bootstrap-lower"),
                "lower.stargz",
                self.work_dir.join("stargz.index-lower.json"),
            )
            .as_str(),
            false,
        ).unwrap();
    }

    pub fn build_stargz_upper(&mut self) {
        exec(
            format!(
                "{:?} create --source-type stargz_index --parent-bootstrap {:?} --bootstrap {:?} --blob-id {} --log-level info {:?}",
                self.builder,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("bootstrap-overlay"),
                "upper.stargz",
                self.work_dir.join("stargz.index-upper.json"),
            )
            .as_str(),
            false,
        ).unwrap();
    }

    pub fn build_special_files(&mut self) {
        let dir = self.work_dir.join("special_files");
        self.create_dir(&dir);
        self.create_dir(&self.work_dir.join("blobs"));

        self.create_special_file(&dir.join("block-file"), "block");
        self.create_special_file(&dir.join("char-file"), "char");
        self.create_special_file(&dir.join("fifo-file"), "fifo");
        self.create_file(&dir.join("normal-file"), b"");
        self.create_dir(&dir.join("dir"));

        exec(
            format!(
                "{:?} create --bootstrap {:?} --backend-type localfs --backend-config '{{\"blob_file\": {:?}}}' --log-level info --compressor {} --whiteout-spec {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-specialfiles"),
                self.work_dir.join("smoke-localfs-blob"),
                "lz4_block",
                self.whiteout_spec,
                dir,
            )
            .as_str(),
            false,
        ).unwrap();
    }
}

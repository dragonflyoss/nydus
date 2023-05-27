// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

use nix::sys::stat::{dev_t, mknod, Mode, SFlag};
use tar::Header;

use nydus_utils::compact::makedev;
use nydus_utils::exec;

pub struct Builder<'a> {
    builder: String,
    work_dir: &'a Path,
    whiteout_spec: &'a str,
}

pub fn new<'a>(work_dir: &'a Path, whiteout_spec: &'a str) -> Builder<'a> {
    let builder = std::env::var("NYDUS_IMAGE")
        .unwrap_or_else(|_| String::from("./target/release/nydus-image"));
    Builder {
        builder,
        work_dir,
        whiteout_spec,
    }
}

impl<'a> Builder<'a> {
    fn create_dir(&mut self, path: &Path) {
        fs::create_dir_all(path).unwrap();
    }

    fn create_file(&mut self, path: &Path, data: &[u8]) {
        File::create(path).unwrap().write_all(data).unwrap();
    }

    fn copy_file(&mut self, src: &Path, dst: &Path) -> u64 {
        fs::copy(src, dst).unwrap()
    }

    fn create_symlink(&mut self, src: &Path, dst: &Path) {
        unix_fs::symlink(src, dst).unwrap();
    }

    fn create_hardlink(&mut self, src: &Path, dst: &Path) {
        fs::hard_link(src, dst).unwrap();
    }

    fn create_large_file(&mut self, path: &Path, size_in_mb: u8) {
        let mut file = File::create(path).unwrap();

        for i in 1..size_in_mb + 1 {
            // Write 1MB data
            file.write_all(&[i; 1024 * 1024]).unwrap();
        }
    }

    fn create_whiteout_file(&mut self, path: &Path) {
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

    fn create_opaque_entry(&mut self, path: &Path) {
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

    fn create_special_file(&mut self, path: &Path, devtype: &str) {
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

    fn set_xattr(&mut self, path: &Path, key: &str, value: &[u8]) {
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
            Path::new("../root-large"),
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

    pub fn build_inline_lower(&mut self, rafs_version: &str) {
        let lower_dir = self.work_dir.join("lower");

        exec(
            format!(
                "{:?} create --source-type directory --blob {:?} --log-level info  --fs-version {} --inline-bootstrap {:?}",
                self.builder,
                self.work_dir.join("inline.nydus"),
                rafs_version,
                lower_dir,
            )
            .as_str(),
            false,
            b""
        ).unwrap();
    }

    pub fn build_lower(&mut self, compressor: &str, rafs_version: &str) {
        let lower_dir = self.work_dir.join("lower");
        self.create_dir(&self.work_dir.join("blobs"));

        exec(
            format!(
                "{:?} create --parent-bootstrap {:?} --bootstrap {:?} --blob-dir {:?} --log-level info --compressor {} --whiteout-spec {} --fs-version {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-empty"),
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                rafs_version,
                lower_dir,
            )
            .as_str(),
            false,
            b""
        ).unwrap();
    }

    pub fn build_upper(&mut self, compressor: &str, rafs_version: &str) {
        let upper_dir = self.work_dir.join("upper");

        exec(
            format!(
                "{:?} create --parent-bootstrap {:?} --bootstrap {:?} --blob-dir {:?} --log-level info --compressor {} --whiteout-spec {} --fs-version {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-lower"),
                self.work_dir.join("bootstrap-overlay"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                rafs_version,
                upper_dir,
            )
            .as_str(),
            false,
            b"",
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
                "{:?} create --bootstrap {:?} --blob {:?} --log-level info --compressor {} --fs-version 5 --whiteout-spec {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-specialfiles"),
                self.work_dir.join("smoke-localfs-blob"),
                "lz4_block",
                self.whiteout_spec,
                dir,
            )
            .as_str(),
            false,
            b"",
        ).unwrap();
    }

    pub fn build_empty_dir_with_prefetch(&mut self, compressor: &str, rafs_version: &str) {
        let empty_dir = self.work_dir.join("empty-dir");
        self.create_dir(&empty_dir);
        self.create_dir(&self.work_dir.join("blobs"));
        exec(
            format!(
                "{:?} create --bootstrap {:?} --prefetch-policy fs --blob-dir {:?}  --log-level info --compressor {} --whiteout-spec {} --fs-version {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-empty-dir"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                rafs_version,
                empty_dir,
            )
            .as_str(),
            false,
            b"/",
        ).unwrap();
    }

    pub fn build_empty_file_with_prefetch(&mut self, compressor: &str, rafs_version: &str) {
        let empty_file_dir = self.work_dir.join("empty");
        self.create_dir(&empty_file_dir);
        self.create_dir(&self.work_dir.join("blobs"));
        self.create_file(&empty_file_dir.join("empty-file"), b"");
        exec(
            format!(
                "{:?} create --parent-bootstrap {:?} --bootstrap {:?} --prefetch-policy fs --blob-dir {:?}  --log-level info --compressor {} --whiteout-spec {} --fs-version {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap-empty-dir"),
                self.work_dir.join("bootstrap-empty"),
                self.work_dir.join("blobs"),
                compressor,
                self.whiteout_spec,
                rafs_version,
                empty_file_dir,
            )
            .as_str(),
            false,
            b"/",
        ).unwrap();
    }

    pub fn check_inline_layout(&self, rafs_version: &str) {
        let header_size = 512u64;

        let files = if rafs_version == "5" {
            vec!["image.boot", "image.blob"]
        } else {
            vec!["image.boot", "blob.meta", "image.blob"]
        };

        let mut f = File::open(self.work_dir.join("inline.nydus")).unwrap();
        let mut cur = f.metadata().unwrap().len();
        let mut idx = 0;
        loop {
            cur = f.seek(SeekFrom::Start(cur - header_size)).unwrap();
            let mut header = Header::new_old();
            let bs = header.as_mut_bytes();
            f.read_exact(bs).unwrap();
            assert_eq!(
                &header.path().unwrap().as_os_str().to_str().unwrap(),
                &files[idx]
            );
            cur -= header.size().unwrap();
            idx += 1;
            if cur == 0 {
                break;
            }
        }
    }

    pub fn unpack(&self, blob: &str, output: &str) {
        let cmd = format!(
            "{:?} unpack --bootstrap {:?} --blob {:?} --output {:?}",
            self.builder,
            self.work_dir.join("bootstrap"),
            self.work_dir.join(blob),
            self.work_dir.join(output)
        );

        exec(&cmd, false, b"").unwrap();
    }

    pub fn pack(&mut self, compressor: &str, rafs_version: &str) {
        self.create_dir(&self.work_dir.join("blobs"));

        exec(
            format!(
                "{:?} create --bootstrap {:?} --blob-dir {:?} --log-level info --compressor {} --whiteout-spec {} --fs-version {} {:?}",
                self.builder,
                self.work_dir.join("bootstrap"),
                self.work_dir.join("blobs"),
                compressor,
                "none", // Use "none" instead of "oci". Otherwise whiteout and opaque files are no longer exist in result.
                rafs_version,
                self.work_dir.join("compress"),
            )
            .as_str(),
            false,
            b""
        ).unwrap();
    }

    pub fn make_pack(&mut self) {
        let dir = self.work_dir.join("compress");
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
            Path::new("../root-large"),
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

        self.create_whiteout_file(&dir.join("sub/some"));
        self.create_opaque_entry(&dir.join("sub/more"));

        self.create_special_file(&dir.join("block-file"), "block");
        self.create_special_file(&dir.join("char-file"), "char");
        self.create_special_file(&dir.join("fifo-file"), "fifo");
    }
}

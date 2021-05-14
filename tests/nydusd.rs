// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread::*;
use std::time;

use nydus_utils::exec;
use rafs::metadata::RafsMode;

pub struct Nydusd {
    nydusd: String,
    work_dir: PathBuf,
    pub api_sock: PathBuf,
}

pub fn new(
    work_dir: &PathBuf,
    enable_cache: bool,
    cache_compressed: bool,
    rafs_mode: RafsMode,
    api_sock: PathBuf,
    digest_validate: bool,
) -> Nydusd {
    let cache_path = work_dir.join("cache");
    fs::create_dir_all(cache_path).unwrap();

    let cache = format!(
        r###"
        ,"cache": {{
            "type": "blobcache",
            "config": {{
                "compressed": {},
                "work_dir": {:?}
            }}
        }}
    "###,
        cache_compressed,
        work_dir.join("cache")
    );

    let config = format!(
        r###"
        {{
            "device": {{
                "backend": {{
                    "type": "localfs",
                    "config": {{
                        "dir": {:?},
                        "readahead": true
                    }}
                }}
                {}
            }},
            "mode": "{}",
            "digest_validate": {},
            "iostats_files": true
        }}
        "###,
        work_dir.join("blobs"),
        if enable_cache { cache } else { String::new() },
        rafs_mode,
        digest_validate,
    );

    fs::create_dir_all(work_dir.join("blobs")).unwrap();

    File::create(work_dir.join("config.json"))
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();

    let nydusd = std::env::var("NYDUSD").unwrap_or_else(|_| {
        String::from("./target-fusedev/x86_64-unknown-linux-musl/release/nydusd")
    });

    Nydusd {
        nydusd,
        work_dir: work_dir.to_path_buf(),
        api_sock,
    }
}

impl Nydusd {
    fn _start(&self, upgrade: bool, bootstrap_name: Option<&str>, mount_path: &str) {
        let work_dir = self.work_dir.clone();
        let api_sock = self.api_sock.clone();

        fs::create_dir_all(work_dir.join(mount_path)).unwrap();

        let upgrade_arg = if upgrade { "--upgrade" } else { "" };
        let bootstrap_name = if let Some(bootstrap_name) = bootstrap_name {
            format!("--bootstrap {:?}", work_dir.join(bootstrap_name))
        } else {
            String::new()
        };

        let _mount_path = mount_path.to_string();
        let nydusd = self.nydusd.clone();
        spawn(move || {
            exec(
                format!(
                    "{} {} --config {:?} --apisock {:?} --mountpoint {:?} {} --log-level info --id {:?} --supervisor {:?}",
                    nydusd,
                    upgrade_arg,
                    work_dir.join("config.json"),
                    work_dir.join(api_sock),
                    work_dir.join(_mount_path),
                    bootstrap_name,
                    work_dir.file_name().unwrap(),
                    work_dir.join("supervisor.sock"),
                )
                .as_str(),
                false
            ).unwrap();
        });

        sleep(time::Duration::from_secs(2));

        if !upgrade && !self.is_mounted(mount_path) {
            panic!("nydusd mount failed");
        }
    }

    pub fn start(&self, bootstrap_name: Option<&str>, mount_path: &str) {
        self._start(false, bootstrap_name, mount_path)
    }

    pub fn check(&self, expect_texture: &str, mount_path: &str) {
        let mount_path = self.work_dir.join(mount_path);

        let tree_ret = exec(format!("tree -a -J -v {:?}", mount_path).as_str(), true).unwrap();
        let md5_ret = exec(
            format!("find {:?} -type f -exec md5sum {{}} + | sort", mount_path).as_str(),
            true,
        )
        .unwrap();

        let ret = format!(
            "{}{}",
            tree_ret.replace(mount_path.to_str().unwrap(), ""),
            md5_ret.replace(mount_path.to_str().unwrap(), "")
        );

        let texture_file = format!("./tests/texture/{}", expect_texture);
        let mut texture = File::open(texture_file).expect("invalid texture file path");
        let mut expected = String::new();
        texture.read_to_string(&mut expected).unwrap();

        assert_eq!(ret.trim(), expected.trim());
    }

    pub fn is_mounted(&self, mount_path: &str) -> bool {
        let ret = exec("cat /proc/mounts", true).unwrap();
        for line in ret.split('\n') {
            if line.contains(self.work_dir.join(mount_path).to_str().unwrap()) {
                return true;
            }
        }
        false
    }

    pub fn umount(&self, mount_path: &str) {
        exec(
            format!("umount {:?}", self.work_dir.join(mount_path)).as_str(),
            false,
        )
        .unwrap();
    }
}

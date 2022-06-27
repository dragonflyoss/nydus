// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate log;

use std::env::var;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use nydus_app::setup_logging;
use nydus_utils::exec;
use vmm_sys_util::tempdir::TempDir;

mod builder;
mod nydusd;

const COMPAT_BOOTSTRAPS: [&str; 2] = [
    "blake3-lz4_block-non_repeatable",
    "sha256-nocompress-repeatable",
];

fn check_compatibility(
    work_dir: &Path,
    enable_cache: bool,
    bootstrap_name: &str,
    rafs_mode: &str,
    digest_validate: bool,
) {
    let nydusd = nydusd::new(
        work_dir,
        enable_cache,
        false,
        rafs_mode.parse().unwrap(),
        "api.sock".into(),
        digest_validate,
    );

    nydusd.start(Some(bootstrap_name), "mnt");
    let result_path = format!("repeatable/{}.result", bootstrap_name);
    nydusd.check(result_path.as_str(), "mnt");
    nydusd.umount("mnt");
}

fn test(
    compressor: &str,
    enable_cache: bool,
    cache_compressed: bool,
    rafs_mode: &str,
    whiteout_spec: &str,
    rafs_version: &str,
) {
    // std::thread::sleep(std::time::Duration::from_secs(1000));

    info!(
        "\n\n==================== testing run: compressor={} enable_cache={} cache_compressed={} rafs_mode={} whiteout_spec={} rafs_version={}",
        compressor, enable_cache, cache_compressed, rafs_mode, whiteout_spec, rafs_version,
    );

    // If the smoke test run in container based on overlayfs storage driver,
    // the test will failed because we can't call `mknod` to create char device file.
    // So please provide the env `TEST_WORKDIR_PREFIX` to specify a host path, allow
    // `mknod` to create char device file in the non-overlayfs filesystem.
    let tmp_dir_prefix =
        std::env::var("TEST_WORKDIR_PREFIX").expect("Please specify `TEST_WORKDIR_PREFIX` env");
    let tmp_dir = {
        let path = if tmp_dir_prefix.ends_with('/') {
            tmp_dir_prefix
        } else {
            format!("{}/", tmp_dir_prefix)
        };
        TempDir::new_with_prefix(path).unwrap()
    };
    let work_dir = tmp_dir.as_path().to_path_buf();
    let lower_texture = "directory/lower.result".to_string();
    let overlay_texture = "directory/overlay.result".to_string();
    let empty_texture = "directory/empty.result".to_string();
    let emptydir_texture = "directory/emptydir.result".to_string();

    let mut builder = builder::new(&work_dir, whiteout_spec);
    let rafsv6 = rafs_version == "6";
    {
        // Create & build empty dir rootfs
        builder.build_empty_dir_with_prefetch(compressor, rafs_version);
        // Mount empty rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse().unwrap(),
            "api.sock".into(),
            // FIXME: Currently no digest validation is implemented for rafs v6.
            !rafsv6,
        );
        nydusd.start(Some("bootstrap-empty-dir"), "mnt");
        nydusd.check(&emptydir_texture, "mnt");
        nydusd.umount("mnt");
    }

    {
        // Create & build empty file rootfs
        builder.build_empty_file_with_prefetch(compressor, rafs_version);
        // Mount empty rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse().unwrap(),
            "api.sock".into(),
            !rafsv6,
        );
        nydusd.start(Some("bootstrap-empty"), "mnt");
        nydusd.check(&empty_texture, "mnt");
        nydusd.umount("mnt");
    }

    {
        // Create & build lower rootfs
        builder.make_lower();
        builder.build_lower(compressor, rafs_version);

        // Mount lower rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse().unwrap(),
            "api.sock".into(),
            !rafsv6,
        );
        nydusd.start(Some("bootstrap-lower"), "mnt");
        nydusd.check(&lower_texture, "mnt");
        nydusd.umount("mnt");
    }

    // Mount upper rootfs and check
    {
        // Create & build upper rootfs based lower
        builder.make_upper();
        builder.build_upper(compressor, rafs_version);

        // Mount overlay rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse().unwrap(),
            "api.sock".into(),
            !rafsv6,
        );
        nydusd.start(Some("bootstrap-overlay"), "mnt");
        nydusd.check(&overlay_texture, "mnt");
        nydusd.umount("mnt");
    }

    // Test blob cache recovery if enable cache
    if enable_cache {
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse().unwrap(),
            "api.sock".into(),
            !rafsv6,
        );
        nydusd.start(Some("bootstrap-overlay"), "mnt");
        nydusd.check(&overlay_texture, "mnt");
        nydusd.umount("mnt");
    }
}

#[test]
fn integration_test_init() {
    setup_logging(None, log::LevelFilter::Trace).unwrap()
}

#[test]
fn integration_test_directory_1() {
    test("lz4_block", true, false, "direct", "oci", "5");
    test("lz4_block", true, false, "direct", "oci", "6")
}

#[test]
fn integration_test_directory_2() {
    test("lz4_block", false, false, "direct", "oci", "5")
}

#[test]
fn integration_test_directory_3() {
    test("gzip", false, false, "direct", "oci", "5")
}

#[test]
fn integration_test_directory_4() {
    test("none", true, false, "direct", "oci", "5");
    test("none", true, false, "direct", "oci", "6")
}

#[test]
fn integration_test_directory_5() {
    test("gzip", true, true, "cached", "oci", "5")
}

#[test]
fn integration_test_directory_6() {
    test("none", false, true, "cached", "oci", "5")
}

#[test]
fn integration_test_directory_7() {
    test("lz4_block", false, true, "cached", "oci", "5")
}

#[test]
fn integration_test_directory_8() {
    test("lz4_block", true, true, "cached", "oci", "5")
}

#[test]
fn integration_test_directory_9() {
    test("lz4_block", true, false, "direct", "overlayfs", "5");
    test("lz4_block", true, false, "direct", "overlayfs", "6")
}

#[test]
fn integration_test_compact() {
    info!("\n\n==================== testing run: compact test");

    let tmp_dir = TempDir::new().unwrap();
    let work_dir = tmp_dir.as_path().to_path_buf();
    let _ = exec(
        format!("cp -a tests/texture/repeatable/* {:?}", work_dir).as_str(),
        false,
        b"",
    );

    for mode in vec!["direct", "cached"].iter() {
        for bs in COMPAT_BOOTSTRAPS.iter() {
            check_compatibility(&work_dir, false, bs, mode, false);
            check_compatibility(&work_dir, false, bs, mode, true);
            check_compatibility(&work_dir, true, bs, mode, false);
            check_compatibility(&work_dir, true, bs, mode, true);
        }
    }
}

#[test]
fn integration_test_special_files() {
    info!("\n\n==================== testing run: special file test");
    let tmp_dir = TempDir::new().unwrap();
    let work_dir = tmp_dir.as_path().to_path_buf();

    let mut builder = builder::new(&work_dir, "oci");

    builder.build_special_files();

    for mode in &["direct", "cached"] {
        let nydusd = nydusd::new(
            &work_dir,
            true,
            true,
            mode.parse().unwrap(),
            "api.sock".into(),
            false,
        );
        nydusd.start(Some("bootstrap-specialfiles"), "mnt");
        nydusd.check("specialfiles/result", "mnt");
        nydusd.umount("mnt");
    }
}

fn test_stargz(rafs_version: &str) {
    info!("\n\n==================== testing run: stargz test");

    let tmp_dir = TempDir::new().unwrap();
    let work_dir = tmp_dir.as_path().to_path_buf();

    let _ = exec(
        format!("cp -a tests/texture/stargz/* {:?}", work_dir).as_str(),
        false,
        b"",
    )
    .unwrap();

    let empty_blob_id = "db30bb2870067ed3e0e73c7448d9f0b529169da8295b5b5155b417624d861d81";
    let lower_blob_id = "e81a6dbddf425e3082f158ff1d80f2adab1dde8dad0b8c4ca43c1bad339f4ec5";
    let upper_blob_id = "5aabe268d8139e952bfff14b2dd0f43fcfef4f2c38b63ea782486ce7268d4954";

    let mut builder = builder::new(&work_dir, "oci");

    builder.build_stargz_empty(rafs_version, empty_blob_id);
    builder.build_stargz_lower(rafs_version, lower_blob_id);
    builder.build_stargz_upper(rafs_version, upper_blob_id);

    // Merge assumes the bootstrap name as the hash of nydus blob.
    builder.merge(
        &work_dir.join("bootstrap-overlay"),
        vec![
            work_dir.join(empty_blob_id).to_str().unwrap(),
            work_dir.join(lower_blob_id).to_str().unwrap(),
            work_dir.join(upper_blob_id).to_str().unwrap(),
        ],
    );

    let nydusd = nydusd::new(
        &work_dir,
        true,
        true,
        "direct".parse().unwrap(),
        "api.sock".into(),
        false,
    );

    nydusd.start(Some("bootstrap-overlay"), "mnt");
    nydusd.check("directory/overlay.result", "mnt");
    nydusd.umount("mnt");
}

#[test]
fn integration_test_stargz() {
    test_stargz("5");
    test_stargz("6");
}

#[test]
fn integration_test_inline_directory() {
    test_inline("5");
    test_inline("6");
}

fn test_inline(rafs_version: &str) {
    info!("\n\n==================== testing run: stargz test");

    let tmp_dir = TempDir::new().unwrap();
    let work_dir = tmp_dir.as_path().to_path_buf();

    let mut builder = builder::new(&work_dir, "oci");
    builder.make_lower();
    builder.build_inline_lower(rafs_version);
    builder.check_inline_layout();
}

#[test]
fn integration_test_unpack() {
    let mut prefix =
        PathBuf::from(var("TEST_WORKDIR_PREFIX").expect("Please specify TEST_WORKDIR_PREFIX env"));

    // A trailing slash is required.
    prefix.push("");

    let wk_dir = TempDir::new_with_prefix(&prefix).unwrap();
    test_unpack(wk_dir.as_path(), "5");

    let wk_dir = TempDir::new_with_prefix(&prefix).unwrap();
    test_unpack(wk_dir.as_path(), "6");
}

fn test_unpack(work_dir: &Path, version: &str) {
    let mut builder = builder::new(work_dir, "oci");
    builder.make_pack();
    builder.pack("lz4_block", version);

    let mut blob_dir = fs::read_dir(work_dir.join("blobs")).unwrap();
    let blob_path = blob_dir.next().unwrap().unwrap().path();

    let tar_name = work_dir.join("oci.tar");
    builder.unpack(blob_path.to_str().unwrap(), tar_name.to_str().unwrap());

    let unpack_dir = work_dir.join("output");
    exec(&format!("mkdir {:?}", unpack_dir), false, b"").unwrap();
    exec(
        &format!("tar --xattrs -xf {:?} -C {:?}", tar_name, unpack_dir),
        false,
        b"",
    )
    .unwrap();

    let tree_ret = exec(&format!("tree -a -J -v {:?}", unpack_dir), true, b"").unwrap();
    let md5_ret = exec(
        &format!("find {:?} -type f -exec md5sum {{}} + | sort", unpack_dir),
        true,
        b"",
    )
    .unwrap();

    let ret = format!(
        "{}{}",
        tree_ret.replace(unpack_dir.to_str().unwrap(), ""),
        md5_ret.replace(unpack_dir.to_str().unwrap(), "")
    );

    let mut texture = File::open("./tests/texture/directory/unpack.result").unwrap();
    let mut expected = String::new();
    texture.read_to_string(&mut expected).unwrap();

    assert_eq!(ret.trim(), expected.trim());
}

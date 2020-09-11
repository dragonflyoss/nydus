// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::path::PathBuf;

#[macro_use]
extern crate log;
extern crate stderrlog;

use nydus_utils::{eother, exec};
use vmm_sys_util::tempdir::TempDir;

mod builder;
mod nydusd;

fn test(
    compressor: &str,
    enable_cache: bool,
    cache_compressed: bool,
    rafs_mode: &str,
) -> Result<()> {
    // std::thread::sleep(std::time::Duration::from_secs(1000));

    info!(
        "\n\n==================== testing run: compressor={} enable_cache={} cache_compressed={} rafs_mode={}",
        compressor, enable_cache, cache_compressed, rafs_mode
    );

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();

    let mut builder = builder::new(&work_dir);

    {
        // Create & build lower rootfs
        builder.make_lower()?;
        builder.build_lower(compressor)?;

        // Mount lower rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse()?,
            "bootstrap-lower".to_string(),
            true,
        )?;
        nydusd.start()?;
        nydusd.check("directory/lower.result")?;
        nydusd.stop();
    }

    // Mount upper rootfs and check
    {
        // Create & build upper rootfs based lower
        builder.make_upper()?;
        builder.build_upper(compressor)?;

        // Mount overlay rootfs and check
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse()?,
            "bootstrap-overlay".to_string(),
            true,
        )?;
        nydusd.start()?;
        nydusd.check("directory/overlay.result")?;
        nydusd.stop();
    }

    // Test blob cache recovery if enable cache
    if enable_cache {
        let nydusd = nydusd::new(
            &work_dir,
            enable_cache,
            cache_compressed,
            rafs_mode.parse()?,
            "bootstrap-overlay".to_string(),
            true,
        )?;
        nydusd.start()?;
        nydusd.check("directory/overlay.result")?;
        nydusd.stop();
    }

    Ok(())
}

#[test]
fn integration_test_init() -> Result<()> {
    stderrlog::new()
        .quiet(false)
        .timestamp(stderrlog::Timestamp::Second)
        .verbosity(log::LevelFilter::Trace as usize - 1)
        .init()
        .map_err(|e| eother!(e))
}

#[test]
fn integration_test_directory_1() -> Result<()> {
    test("lz4_block", true, false, "direct")
}

#[test]
fn integration_test_directory_2() -> Result<()> {
    test("lz4_block", false, false, "direct")
}

#[test]
fn integration_test_directory_3() -> Result<()> {
    test("gzip", false, false, "direct")
}

#[test]
fn integration_test_directory_4() -> Result<()> {
    test("none", true, false, "direct")
}

#[test]
fn integration_test_directory_5() -> Result<()> {
    test("gzip", true, true, "cached")
}

#[test]
fn integration_test_directory_6() -> Result<()> {
    test("none", false, true, "cached")
}

#[test]
fn integration_test_directory_7() -> Result<()> {
    test("lz4_block", false, true, "cached")
}

#[test]
fn integration_test_directory_8() -> Result<()> {
    test("lz4_block", true, true, "cached")
}

const COMPAT_BOOTSTRAPS: &'static [&'static str] = &[
    "blake3-lz4_block-non_repeatable",
    "sha256-nocompress-repeatable",
];

fn check_compact<'a>(work_dir: &'a PathBuf, bootstrap_name: &str, rafs_mode: &str) -> Result<()> {
    let nydusd = nydusd::new(
        work_dir,
        false,
        false,
        rafs_mode.parse()?,
        bootstrap_name.to_string(),
        true,
    )?;

    nydusd.start()?;
    let result_path = format!("repeatable/{}.result", bootstrap_name);
    nydusd.check(result_path.as_str())?;
    nydusd.stop();

    Ok(())
}

#[test]
fn integration_test_compact() -> Result<()> {
    info!("\n\n==================== testing run: compact test");

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();
    let _ = exec(
        format!("cp -a tests/texture/repeatable/* {:?}", work_dir).as_str(),
        false,
    )?;

    for mode in vec!["direct", "cached"].iter() {
        for bs in COMPAT_BOOTSTRAPS.iter() {
            check_compact(&work_dir, bs, mode)?;
        }
    }

    Ok(())
}

#[test]
fn integration_test_stargz() -> Result<()> {
    info!("\n\n==================== testing run: stargz test");

    let tmp_dir = TempDir::new().map_err(|e| eother!(e))?;
    let work_dir = tmp_dir.as_path().to_path_buf();

    let _ = exec(
        format!("cp -a tests/texture/stargz/* {:?}", work_dir).as_str(),
        false,
    )?;

    let mut builder = builder::new(&work_dir);

    builder.build_stargz_lower()?;
    builder.build_stargz_upper()?;

    let nydusd = nydusd::new(
        &work_dir,
        true,
        true,
        "direct".parse()?,
        "bootstrap-overlay".to_string(),
        false,
    )?;

    nydusd.start()?;
    nydusd.check("directory/overlay.result")?;
    nydusd.stop();

    Ok(())
}

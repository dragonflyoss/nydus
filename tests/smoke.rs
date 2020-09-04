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
    info!(
        "\n\n==================== testing run: enable_compress {} enable_cache {} rafs_mode {}",
        enable_compress, enable_cache, rafs_mode
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
        )?;
        nydusd.start()?;
        builder.mount_check("source/lower.result")?;
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
        )?;
        nydusd.start()?;
        builder.mount_check("source/overlay.result")?;
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
        )?;
        nydusd.start()?;
        builder.mount_check("source/overlay.result")?;
        nydusd.stop();
    }

    Ok(())
}

fn check_compact<'a>(work_dir: &'a PathBuf, bootstrap_name: &str, rafs_mode: &str) -> Result<()> {
    let nydusd = nydusd::new(
        work_dir,
        false,
        false,
        rafs_mode.parse()?,
        bootstrap_name.to_string(),
    )?;
    let mut builder = builder::new(&work_dir);

    nydusd.start()?;
    let result_path = format!("repeatable/{}.result", bootstrap_name);
    builder.mount_check(result_path.as_str())?;
    nydusd.stop();

    Ok(())
}

const COMPAT_BOOTSTRAPS: &'static [&'static str] = &[
    "blake3-lz4_block-non_repeatable",
    "sha256-nocompress-repeatable",
];

fn test_compact() -> Result<()> {
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
fn integration_run() -> Result<()> {
    stderrlog::new()
        .quiet(false)
        .timestamp(stderrlog::Timestamp::Second)
        .verbosity(log::LevelFilter::Trace as usize - 1)
        .init()
        .map_err(|e| eother!(e))
        .unwrap();

    test_compact()?;

    test("lz4_block", true, false, "direct")?;
    test("lz4_block", false, false, "direct")?;
    test("gzip", false, false, "direct")?;
    test("none", true, false, "direct")?;

    test("gzip", true, true, "cached")?;
    test("none", false, true, "cached")?;
    test("lz4_block", false, true, "cached")?;
    test("lz4_block", true, true, "cached")
}
